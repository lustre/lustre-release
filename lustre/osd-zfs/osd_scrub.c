// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Top-level entry points into osd module
 *
 * The OI scrub is used for rebuilding Object Index files when restores MDT from
 * file-level backup.
 *
 * The otable based iterator scans ZFS objects to feed up layer LFSCK.
 *
 * Author: Fan Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LFSCK

#include <linux/kthread.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_disk.h>
#include <dt_object.h>
#include <linux/xattr.h>
#include <lustre_scrub.h>
#include <obd_class.h>
#include <lustre_nodemap.h>
#include <sys/dsl_dataset.h>
#include <sys/zap_impl.h>
#include <sys/zap.h>
#include <sys/zap_leaf.h>

#include "osd_internal.h"

#define OSD_OTABLE_MAX_HASH		((1ULL << 48) - 1)
#define OTABLE_PREFETCH			256

static inline bool osd_scrub_has_window(struct osd_otable_it *it)
{
	return it->ooi_prefetched < OTABLE_PREFETCH;
}

/**
 * update/insert/delete the specified OI mapping (@fid @id) according to the ops
 *
 * \retval   1, changed nothing
 * \retval   0, changed successfully
 * \retval -ve, on error
 */
int osd_scrub_refresh_mapping(const struct lu_env *env,
			      struct osd_device *dev,
			      const struct lu_fid *fid,
			      uint64_t oid, enum dt_txn_op ops,
			      bool force, const char *name)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct zpl_direntry *zde = &info->oti_zde.lzd_reg;
	char *buf = info->oti_str;
	dmu_tx_t *tx = NULL;
	dnode_t *dn = NULL;
	uint64_t zapid;
	int rc;

	ENTRY;
	if (dev->od_scrub.os_file.sf_param & SP_DRYRUN && !force)
		GOTO(log, rc = 0);

	tx = dmu_tx_create(dev->od_os);
	if (!tx)
		GOTO(log, rc = -ENOMEM);

	zapid = osd_get_name_n_idx(env, dev, fid, buf,
				   sizeof(info->oti_str), &dn);
	osd_tx_hold_zap(tx, zapid, dn,
			ops == DTO_INDEX_INSERT ? TRUE : FALSE, NULL);
	rc = -dmu_tx_assign(tx, DMU_TX_WAIT);
	if (rc) {
		dmu_tx_abort(tx);
		GOTO(log, rc);
	}

	switch (ops) {
	case DTO_INDEX_UPDATE:
		zde->zde_pad = 0;
		zde->zde_dnode = oid;
		zde->zde_type = 0; /* The type in OI mapping is useless. */
		rc = -zap_update(dev->od_os, zapid, buf, 8, sizeof(*zde) / 8,
				 zde, tx);
		if (unlikely(rc == -ENOENT)) {
			/* Some unlink thread may removed the OI mapping. */
			rc = 1;
		}
		break;
	case DTO_INDEX_INSERT:
		zde->zde_pad = 0;
		zde->zde_dnode = oid;
		zde->zde_type = 0; /* The type in OI mapping is useless. */
		rc = osd_zap_add(dev, zapid, dn, buf, 8, sizeof(*zde) / 8,
				 zde, tx);
		if (unlikely(rc == -EEXIST))
			rc = 1;
		break;
	case DTO_INDEX_DELETE:
		rc = osd_zap_remove(dev, zapid, dn, buf, tx);
		if (rc == -ENOENT) {
			/* It is normal that the unlink thread has removed the
			 * OI mapping already.
			 */
			rc = 1;
		}
		break;
	default:
		LASSERTF(0, "Unexpected ops %d\n", ops);
		rc = -EINVAL;
		break;
	}

	dmu_tx_commit(tx);
	GOTO(log, rc);

log:
	CDEBUG(D_LFSCK, "%s: refresh OI map for scrub, op %d, force %s, "
	       DFID" => %llu (%s): rc = %d\n", osd_name(dev), ops,
	       force ? "yes" : "no", PFID(fid), oid, name ? name : "null", rc);

	return rc;
}

static int
osd_scrub_check_update(const struct lu_env *env, struct osd_device *dev,
		       const struct lu_fid *fid, uint64_t oid, int val)
{
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct scrub_file *sf = &scrub->os_file;
	struct osd_inconsistent_item *oii = NULL;
	nvlist_t *nvbuf = NULL;
	dnode_t *dn = NULL;
	uint64_t oid2;
	int ops = DTO_INDEX_UPDATE;
	int index;
	int rc;

	ENTRY;
	down_write(&scrub->os_rwsem);
	scrub->os_new_checked++;
	if (val < 0)
		GOTO(out, rc = val);

	if (scrub->os_in_prior)
		oii = list_first_entry(&scrub->os_inconsistent_items,
				       struct osd_inconsistent_item, oii_list);

	if (oid < sf->sf_pos_latest_start && !oii)
		GOTO(out, rc = 0);

	if (oii && oii->oii_insert) {
		ops = DTO_INDEX_INSERT;
		goto zget;
	}

	rc = osd_fid_lookup(env, dev, fid, &oid2);
	if (rc) {
		if (rc != -ENOENT)
			GOTO(out, rc);

		ops = DTO_INDEX_INSERT;

zget:
		rc = __osd_obj2dnode(dev->od_os, oid, &dn);
		if (rc) {
			/* Someone removed the object by race. */
			if (rc == -ENOENT || rc == -EEXIST)
				rc = 0;
			GOTO(out, rc);
		}

		spin_lock(&scrub->os_lock);
		scrub->os_full_speed = 1;
		spin_unlock(&scrub->os_lock);

		sf->sf_flags |= SF_INCONSISTENT;
	} else if (oid == oid2) {
		GOTO(out, rc = 0);
	} else {
		struct lustre_mdt_attrs *lma = NULL;
		int size;

		rc = __osd_xattr_load_by_oid(dev, oid2, &nvbuf);
		if (rc == -ENOENT || rc == -EEXIST || rc == -ENODATA)
			goto update;
		if (rc)
			GOTO(out, rc);

		rc = -nvlist_lookup_byte_array(nvbuf, XATTR_NAME_LMA,
					       (uchar_t **)&lma, &size);
		if (rc == -ENOENT || rc == -EEXIST || rc == -ENODATA)
			goto update;
		if (rc)
			GOTO(out, rc);

		lustre_lma_swab(lma);
		if (unlikely(lu_fid_eq(&lma->lma_self_fid, fid))) {
			rc = -EEXIST;
			CDEBUG(D_LFSCK,
			       "%s: the FID "DFID" is used by two objects: %llu and %llu (in OI): rc = %d\n",
			       osd_name(dev), PFID(fid), oid, oid2, rc);

			GOTO(out, rc);
		}

update:
		spin_lock(&scrub->os_lock);
		scrub->os_full_speed = 1;
		spin_unlock(&scrub->os_lock);
		sf->sf_flags |= SF_INCONSISTENT;
	}

	rc = osd_scrub_refresh_mapping(env, dev, fid, oid, ops, false, NULL);
	if (!rc) {
		if (scrub->os_in_prior)
			sf->sf_items_updated_prior++;
		else
			sf->sf_items_updated++;
	}

	GOTO(out, rc);

out:
	if (dev->od_is_ost) {
		sa_handle_t *hdl;
		uint64_t nlink, mode;

		rc = -sa_handle_get(dev->od_os, oid, NULL, SA_HDL_PRIVATE,
				    &hdl);
		if (rc)
			GOTO(cleanup, rc);

		rc = -sa_lookup(hdl, SA_ZPL_MODE(dev), &mode, sizeof(mode));
		if (rc || !S_ISREG(mode)) {
			sa_handle_destroy(hdl);
			GOTO(cleanup, rc);
		}

		rc = -sa_lookup(hdl, SA_ZPL_LINKS(dev), &nlink, sizeof(nlink));
		if (rc == 0 && nlink > 1)
			scrub->os_has_ml_file = 1;

		sa_handle_destroy(hdl);
	}

	if (!rc && scrub->os_ls_count > 0 && fid_is_local_storage(fid)) {
		index = 0;
		for (index = 0; index < scrub->os_ls_count; index++)
			if (scrub->os_ls_fids[index].f_seq == fid->f_seq)
				break;

		if (index < scrub->os_ls_count &&
		    scrub->os_ls_fids[index].f_oid < fid->f_oid)
			scrub->os_ls_fids[index].f_oid = fid->f_oid;
	}

cleanup:
	if (nvbuf)
		nvlist_free(nvbuf);

	if (rc < 0) {
		sf->sf_items_failed++;
		if (sf->sf_pos_first_inconsistent == 0 ||
		    sf->sf_pos_first_inconsistent > oid)
			sf->sf_pos_first_inconsistent = oid;
	} else {
		rc = 0;
	}

	/* There may be conflict unlink during the OI scrub,
	 * if happend, then remove the new added OI mapping.
	 */
	if (ops == DTO_INDEX_INSERT && dn && dn->dn_free_txg)
		osd_scrub_refresh_mapping(env, dev, fid, oid,
					  DTO_INDEX_DELETE, false, NULL);
	up_write(&scrub->os_rwsem);

	if (dn)
		osd_dnode_rele(dn);

	if (oii) {
		spin_lock(&scrub->os_lock);
		if (likely(!list_empty(&oii->oii_list)))
			list_del(&oii->oii_list);
		spin_unlock(&scrub->os_lock);
		OBD_FREE_PTR(oii);
	}

	RETURN(sf->sf_param & SP_FAILOUT ? rc : 0);
}

/* iteration engine */

static inline int
osd_scrub_wakeup(struct lustre_scrub *scrub, struct osd_otable_it *it)
{
	spin_lock(&scrub->os_lock);
	if (osd_scrub_has_window(it) ||
	    !list_empty(&scrub->os_inconsistent_items) ||
	    it->ooi_waiting || kthread_should_stop())
		scrub->os_waiting = 0;
	else
		scrub->os_waiting = 1;
	spin_unlock(&scrub->os_lock);

	return !scrub->os_waiting;
}

static int osd_scrub_next(const struct lu_env *env, struct osd_device *dev,
			  struct lu_fid *fid, uint64_t *oid)
{
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct osd_otable_it *it = dev->od_otable_it;
	struct lustre_mdt_attrs *lma = NULL;
	nvlist_t *nvbuf = NULL;
	int size = 0;
	int rc = 0;

	ENTRY;
	if (CFS_FAIL_CHECK(OBD_FAIL_OSD_SCRUB_DELAY) && cfs_fail_val > 0) {
		wait_var_event_timeout(
			scrub,
			!list_empty(&scrub->os_inconsistent_items) ||
			kthread_should_stop(),
			cfs_time_seconds(cfs_fail_val));

		if (kthread_should_stop())
			RETURN(SCRUB_NEXT_EXIT);
	}

	if (CFS_FAIL_CHECK(OBD_FAIL_OSD_SCRUB_CRASH)) {
		spin_lock(&scrub->os_lock);
		scrub->os_running = 0;
		spin_unlock(&scrub->os_lock);
		RETURN(SCRUB_NEXT_CRASH);
	}

	if (CFS_FAIL_CHECK(OBD_FAIL_OSD_SCRUB_FATAL))
		RETURN(SCRUB_NEXT_FATAL);

again:
	if (nvbuf) {
		nvlist_free(nvbuf);
		nvbuf = NULL;
		lma = NULL;
	}

	if (!list_empty(&scrub->os_inconsistent_items)) {
		spin_lock(&scrub->os_lock);
		if (likely(!list_empty(&scrub->os_inconsistent_items))) {
			struct osd_inconsistent_item *oii;

			oii = list_first_entry(&scrub->os_inconsistent_items,
					       struct osd_inconsistent_item,
					       oii_list);
			*fid = oii->oii_cache.oic_fid;
			*oid = oii->oii_cache.oic_dnode;
			scrub->os_in_prior = 1;
			spin_unlock(&scrub->os_lock);

			GOTO(out, rc = 0);
		}
		spin_unlock(&scrub->os_lock);
	}

	if (!scrub->os_full_speed && !osd_scrub_has_window(it))
		wait_var_event(scrub, osd_scrub_wakeup(scrub, it));

	if (kthread_should_stop())
		GOTO(out, rc = SCRUB_NEXT_EXIT);

	rc = -dmu_object_next(dev->od_os, &scrub->os_pos_current, B_FALSE, 0);
	if (rc)
		GOTO(out, rc = (rc == -ESRCH ? SCRUB_NEXT_BREAK : rc));

	rc = __osd_xattr_load_by_oid(dev, scrub->os_pos_current, &nvbuf);
	if (rc == -ENOENT || rc == -EEXIST || rc == -ENODATA)
		goto again;

	if (rc)
		GOTO(out, rc);

	LASSERT(nvbuf != NULL);
	rc = -nvlist_lookup_byte_array(nvbuf, XATTR_NAME_LMA,
				       (uchar_t **)&lma, &size);
	if (!rc) {
		lustre_lma_swab(lma);
		if (likely(!(lma->lma_compat & LMAC_NOT_IN_OI) &&
			   !(lma->lma_incompat & LMAI_AGENT))) {
			*fid = lma->lma_self_fid;
			*oid = scrub->os_pos_current;

			GOTO(out, rc = 0);
		}
	}

	if (!scrub->os_full_speed) {
		spin_lock(&scrub->os_lock);
		it->ooi_prefetched++;
		if (it->ooi_waiting) {
			it->ooi_waiting = 0;
			wake_up_var(scrub);
		}
		spin_unlock(&scrub->os_lock);
	}

	goto again;

out:
	if (nvbuf)
		nvlist_free(nvbuf);

	return rc;
}

static int osd_scrub_exec(const struct lu_env *env, struct osd_device *dev,
			  const struct lu_fid *fid, uint64_t oid, int rc)
{
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct osd_otable_it *it = dev->od_otable_it;

	rc = osd_scrub_check_update(env, dev, fid, oid, rc);
	if (!scrub->os_in_prior) {
		if (!scrub->os_full_speed) {
			spin_lock(&scrub->os_lock);
			it->ooi_prefetched++;
			if (it->ooi_waiting) {
				it->ooi_waiting = 0;
				wake_up_var(scrub);
			}
			spin_unlock(&scrub->os_lock);
		}
	} else {
		spin_lock(&scrub->os_lock);
		scrub->os_in_prior = 0;
		spin_unlock(&scrub->os_lock);
	}

	if (rc)
		return rc;

	rc = scrub_checkpoint(env, scrub);
	if (rc) {
		CDEBUG(D_LFSCK, "%s: fail to checkpoint, pos = %llu: rc = %d\n",
		       scrub->os_name, scrub->os_pos_current, rc);
		/* Continue, as long as the scrub itself can go ahead. */
	}

	return 0;
}

static int osd_scan_ml_file_main(const struct lu_env *env,
				 struct osd_device *dev);
static int osd_scan_O_main(const struct lu_env *env, struct osd_device *dev);
static int osd_scan_lastid_main(const struct lu_env *env,
				struct osd_device *dev);

static int osd_scrub_main(void *args)
{
	struct lu_env env;
	struct osd_device *dev = (struct osd_device *)args;
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct lu_fid *fid;
	uint64_t oid;
	int rc = 0, ret;

	ENTRY;
	rc = lu_env_init(&env, LCT_LOCAL | LCT_DT_THREAD);
	if (rc) {
		CDEBUG(D_LFSCK, "%s: OI scrub fail to init env: rc = %d\n",
		       scrub->os_name, rc);
		GOTO(noenv, rc);
	}

	rc = scrub_thread_prep(&env, scrub, dev->od_uuid, 1);
	if (rc) {
		CDEBUG(D_LFSCK, "%s: OI scrub fail to scrub prep: rc = %d\n",
		       scrub->os_name, rc);
		GOTO(out, rc);
	}

	if (!scrub->os_full_speed) {
		struct osd_otable_it *it = dev->od_otable_it;

		wait_var_event(scrub,
			       it->ooi_user_ready ||
			       kthread_should_stop());

		if (kthread_should_stop())
			GOTO(post, rc = 0);

		scrub->os_pos_current = it->ooi_pos;
	}

	CDEBUG(D_LFSCK, "%s: OI scrub start, flags = 0x%x, pos = %llu\n",
	       scrub->os_name, scrub->os_start_flags,
	       scrub->os_pos_current);

	scrub->os_ls_count = 0;
	scrub->os_ls_size = 4;
	OBD_ALLOC(scrub->os_ls_fids, scrub->os_ls_size * sizeof(struct lu_fid));
	if (scrub->os_ls_fids == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = osd_scan_O_main(&env, dev);
	if (rc)
		GOTO(out, rc);

	fid = &osd_oti_get(&env)->oti_fid;
	while (!rc && !kthread_should_stop()) {
		rc = osd_scrub_next(&env, dev, fid, &oid);
		switch (rc) {
		case SCRUB_NEXT_EXIT:
			GOTO(post, rc = 0);
		case SCRUB_NEXT_CRASH:
			spin_lock(&scrub->os_lock);
			scrub->os_running = 0;
			spin_unlock(&scrub->os_lock);
			GOTO(out, rc = -EINVAL);
		case SCRUB_NEXT_FATAL:
			GOTO(post, rc = -EINVAL);
		case SCRUB_NEXT_BREAK:
			GOTO(post, rc = 1);
		}

		rc = osd_scrub_exec(&env, dev, fid, oid, rc);
	}

	GOTO(post, rc);

post:
	if (scrub->os_has_ml_file) {
		ret = osd_scan_ml_file_main(&env, dev);
		if (ret != 0)
			rc = ret;
	}

	ret = osd_scan_lastid_main(&env, dev);
	if (ret != 0)
		rc = ret;

	rc = scrub_thread_post(&env, &dev->od_scrub, rc);
	CDEBUG(D_LFSCK, "%s: OI scrub: stop, pos = %llu: rc = %d\n",
	       scrub->os_name, scrub->os_pos_current, rc);

out:
	if (scrub->os_ls_fids) {
		OBD_FREE(scrub->os_ls_fids,
			 scrub->os_ls_size * sizeof(struct lu_fid));

		scrub->os_ls_size = 0;
		scrub->os_ls_count = 0;
		scrub->os_ls_fids = NULL;
	}

	while (!list_empty(&scrub->os_inconsistent_items)) {
		struct osd_inconsistent_item *oii;

		oii = list_first_entry(&scrub->os_inconsistent_items,
				       struct osd_inconsistent_item, oii_list);
		list_del_init(&oii->oii_list);
		OBD_FREE_PTR(oii);
	}

	lu_env_fini(&env);

noenv:
	spin_lock(&scrub->os_lock);
	scrub->os_running = 0;
	spin_unlock(&scrub->os_lock);
	if (xchg(&scrub->os_task, NULL) == NULL)
		/* scrub_stop is waiting, we need to synchronize */
		wait_var_event(scrub, kthread_should_stop());
	wake_up_var(scrub);
	return rc;
}

/* initial OI scrub */

struct osd_lf_map;

typedef int (*handle_dirent_t)(const struct lu_env *, struct osd_device *,
			       const char *, uint64_t, uint64_t,
			       enum osd_lf_flags, bool);
static int osd_ios_varfid_hd(const struct lu_env *, struct osd_device *,
			     const char *, uint64_t, uint64_t,
			     enum osd_lf_flags, bool);
static int osd_ios_uld_hd(const struct lu_env *, struct osd_device *,
			  const char *, uint64_t, uint64_t,
			  enum osd_lf_flags, bool);

typedef int (*scan_dir_t)(const struct lu_env *, struct osd_device *,
			  uint64_t, handle_dirent_t, enum osd_lf_flags);
static int osd_ios_general_sd(const struct lu_env *, struct osd_device *,
			      uint64_t, handle_dirent_t, enum osd_lf_flags);
static int osd_ios_ROOT_sd(const struct lu_env *, struct osd_device *,
			   uint64_t, handle_dirent_t, enum osd_lf_flags);

struct osd_lf_map {
	char			*olm_name;
	struct lu_fid		 olm_fid;
	enum osd_lf_flags	 olm_flags;
	scan_dir_t		 olm_scan_dir;
	handle_dirent_t		 olm_handle_dirent;
};

/* Add the new introduced local files in the list in the future. */
static const struct osd_lf_map osd_lf_maps[] = {
	/* CONFIGS */
	{
		.olm_name		= MOUNT_CONFIGS_DIR,
		.olm_fid		= {
			.f_seq	= FID_SEQ_LOCAL_FILE,
			.f_oid	= MGS_CONFIGS_OID,
		},
		.olm_flags		= OLF_SCAN_SUBITEMS,
		.olm_scan_dir		= osd_ios_general_sd,
		.olm_handle_dirent	= osd_ios_varfid_hd,
	},

	/* NIDTBL_VERSIONS */
	{
		.olm_name		= MGS_NIDTBL_DIR,
		.olm_flags		= OLF_SCAN_SUBITEMS,
		.olm_scan_dir		= osd_ios_general_sd,
		.olm_handle_dirent	= osd_ios_varfid_hd,
	},

	/* PENDING */
	{
		.olm_name		= MDT_ORPHAN_DIR,
	},

	/* ROOT */
	{
		.olm_name		= "ROOT",
		.olm_fid		= {
			.f_seq	= FID_SEQ_ROOT,
			.f_oid	= FID_OID_ROOT,
		},
		.olm_flags		= OLF_SCAN_SUBITEMS,
		.olm_scan_dir		= osd_ios_ROOT_sd,
	},

	/* fld */
	{
		.olm_name		= "fld",
		.olm_fid		= {
			.f_seq	= FID_SEQ_LOCAL_FILE,
			.f_oid	= FLD_INDEX_OID,
		},
	},

	/* changelog_catalog */
	{
		.olm_name		= CHANGELOG_CATALOG,
	},

	/* changelog_users */
	{
		.olm_name		= CHANGELOG_USERS,
	},

	/* quota_master */
	{
		.olm_name		= QMT_DIR,
		.olm_flags		= OLF_SCAN_SUBITEMS,
		.olm_scan_dir		= osd_ios_general_sd,
		.olm_handle_dirent	= osd_ios_varfid_hd,
	},

	/* quota_slave */
	{
		.olm_name		= QSD_DIR,
		.olm_flags		= OLF_SCAN_SUBITEMS,
		.olm_scan_dir		= osd_ios_general_sd,
		.olm_handle_dirent	= osd_ios_varfid_hd,
	},

	/* LFSCK */
	{
		.olm_name		= LFSCK_DIR,
		.olm_flags		= OLF_SCAN_SUBITEMS | OLF_NOT_BACKUP,
		.olm_scan_dir		= osd_ios_general_sd,
		.olm_handle_dirent	= osd_ios_varfid_hd,
	},

	/* lfsck_bookmark */
	{
		.olm_name		= LFSCK_BOOKMARK,
	},

	/* lfsck_layout */
	{
		.olm_name		= LFSCK_LAYOUT,
	},

	/* lfsck_namespace */
	{
		.olm_name		= LFSCK_NAMESPACE,
	},

	/* OSP update logs update_log{_dir} use f_seq = FID_SEQ_UPDATE_LOG{_DIR}
	 * and f_oid = index for their log files.  See lu_update_log{_dir}_fid()
	 * for more details.
	 */

	/* update_log */
	{
		.olm_name		= "update_log",
		.olm_fid		= {
			.f_seq	= FID_SEQ_UPDATE_LOG,
		},
		.olm_flags		= OLF_IDX_IN_FID,
	},

	/* update_log_dir */
	{
		.olm_name		= "update_log_dir",
		.olm_fid	= {
			.f_seq	= FID_SEQ_UPDATE_LOG_DIR,
		},
		.olm_flags		= OLF_SCAN_SUBITEMS | OLF_IDX_IN_FID,
		.olm_scan_dir		= osd_ios_general_sd,
		.olm_handle_dirent	= osd_ios_uld_hd,
	},

	/* hsm_actions */
	{
		.olm_name		= HSM_ACTIONS,
	},

	/* nodemap */
	{
		.olm_name		= LUSTRE_NODEMAP_NAME,
	},

	/* index_backup */
	{
		.olm_name		= INDEX_BACKUP_DIR,
		.olm_fid		= {
			.f_seq	= FID_SEQ_LOCAL_FILE,
			.f_oid	= INDEX_BACKUP_OID,
		},
		.olm_flags		= OLF_SCAN_SUBITEMS | OLF_NOT_BACKUP,
		.olm_scan_dir		= osd_ios_general_sd,
		.olm_handle_dirent	= osd_ios_varfid_hd,
	},

	{
		.olm_name		= NULL
	}
};

/* Add the new introduced files under .lustre/ in the list in the future. */
static const struct osd_lf_map osd_dl_maps[] = {
	/* .lustre/fid */
	{
		.olm_name		= "fid",
		.olm_fid		= {
			.f_seq	= FID_SEQ_DOT_LUSTRE,
			.f_oid	= FID_OID_DOT_LUSTRE_OBF,
		},
	},

	/* .lustre/lost+found */
	{
		.olm_name		= "lost+found",
		.olm_fid		= {
			.f_seq	= FID_SEQ_DOT_LUSTRE,
			.f_oid	= FID_OID_DOT_LUSTRE_LPF,
		},
	},

	{
		.olm_name		= NULL
	}
};

struct osd_ios_item {
	struct list_head	oii_list;
	uint64_t		oii_parent;
	enum osd_lf_flags	oii_flags;
	scan_dir_t		oii_scan_dir;
	handle_dirent_t		oii_handle_dirent;
};

static int osd_ios_new_item(struct osd_device *dev, uint64_t parent,
			    enum osd_lf_flags flags, scan_dir_t scan_dir,
			    handle_dirent_t handle_dirent)
{
	struct osd_ios_item *item;
	int rc = 0;

	OBD_ALLOC_PTR(item);
	if (!item) {
		rc = -ENOMEM;
		CWARN("%s: initial OI scrub failed to add item for %llu: rc = %d\n",
		      osd_name(dev), parent, rc);
		return rc;
	}

	INIT_LIST_HEAD(&item->oii_list);
	item->oii_parent = parent;
	item->oii_flags = flags;
	item->oii_scan_dir = scan_dir;
	item->oii_handle_dirent = handle_dirent;
	list_add_tail(&item->oii_list, &dev->od_ios_list);

	return rc;
}

static bool osd_index_need_recreate(const struct lu_env *env,
				    struct osd_device *dev, uint64_t oid)
{
	struct osd_thread_info *info = osd_oti_get(env);
	zap_attribute_t *za = &info->oti_za2;
	zap_cursor_t *zc = &info->oti_zc2;
	int rc;

	ENTRY;
	zap_cursor_init_serialized(zc, dev->od_os, oid, 0);
	rc = -zap_cursor_retrieve(zc, za);
	zap_cursor_fini(zc);
	if (rc && rc != -ENOENT)
		RETURN(true);

	RETURN(false);
}

static void osd_ios_index_register(const struct lu_env *env,
				   struct osd_device *osd,
				   const struct lu_fid *fid, uint64_t oid)
{
	struct osd_thread_info *info = osd_oti_get(env);
	zap_attribute_t *za = &info->oti_za2;
	zap_cursor_t *zc = &info->oti_zc2;
	struct zap_leaf_entry *le;
	dnode_t *dn = NULL;
	sa_handle_t *hdl;
	__u64 mode = 0;
	__u32 keysize = 0;
	__u32 recsize = 0;
	int rc;

	ENTRY;
	rc = __osd_obj2dnode(osd->od_os, oid, &dn);
	if (rc == -EEXIST || rc == -ENOENT)
		RETURN_EXIT;

	if (rc < 0)
		GOTO(log, rc);

	if (!osd_object_is_zap(dn))
		GOTO(log, rc = 1);

	rc = -sa_handle_get(osd->od_os, oid, NULL, SA_HDL_PRIVATE, &hdl);
	if (rc)
		GOTO(log, rc);

	rc = -sa_lookup(hdl, SA_ZPL_MODE(osd), &mode, sizeof(mode));
	sa_handle_destroy(hdl);
	if (rc)
		GOTO(log, rc);

	if (!S_ISREG(mode))
		GOTO(log, rc = 1);

	zap_cursor_init_serialized(zc, osd->od_os, oid, 0);
	rc = -zap_cursor_retrieve(zc, za);
	if (rc)
		/* Skip empty index object */
		GOTO(fini, rc = (rc == -ENOENT ? 1 : rc));

	if (zc->zc_zap->zap_ismicro ||
	    !(zap_f_phys(zc->zc_zap)->zap_flags & ZAP_FLAG_UINT64_KEY))
		GOTO(fini, rc = 1);

	le = ZAP_LEAF_ENTRY(zc->zc_leaf, 0);
	keysize = le->le_name_numints * 8;
	recsize = za->za_integer_length * za->za_num_integers;
	if (likely(keysize && recsize))
		rc = osd_index_register(osd, fid, keysize, recsize);

	GOTO(fini, rc);

fini:
	zap_cursor_fini(zc);

log:
	if (dn)
		osd_dnode_rele(dn);
	if (rc < 0)
		CWARN("%s: failed to register index "DFID" (%u/%u): rc = %d\n",
		      osd_name(osd), PFID(fid), keysize, recsize, rc);
	else if (!rc)
		CDEBUG(D_LFSCK, "%s: registered index "DFID" (%u/%u)\n",
		       osd_name(osd), PFID(fid), keysize, recsize);
}

static void osd_index_restore(const struct lu_env *env, struct osd_device *dev,
			      struct lustre_index_restore_unit *liru, void *buf,
			      int bufsize)
{
	struct luz_direntry *zde = &osd_oti_get(env)->oti_zde;
	struct lu_fid *tgt_fid = &liru->liru_cfid;
	struct lu_fid bak_fid;
	int rc;

	ENTRY;
	lustre_fid2lbx(buf, tgt_fid, bufsize);
	rc = -zap_lookup(dev->od_os, dev->od_index_backup_id, buf, 8,
			 sizeof(*zde) / 8, (void *)zde);
	if (rc)
		GOTO(log, rc);

	rc = osd_get_fid_by_oid(env, dev, zde->lzd_reg.zde_dnode, &bak_fid);
	if (rc)
		GOTO(log, rc);

	/* The OI mapping for index may be invalid, since it will be
	 * re-created, not update the OI mapping, just cache it in RAM.
	 */
	rc = osd_idc_find_and_init_with_oid(env, dev, tgt_fid,
					    liru->liru_clid);
	if (!rc)
		rc = lustre_index_restore(env, &dev->od_dt_dev,
				&liru->liru_pfid, tgt_fid, &bak_fid,
				liru->liru_name, &dev->od_index_backup_list,
				&dev->od_lock, buf, bufsize);
	GOTO(log, rc);

log:
	CDEBUG(D_WARNING, "%s: restore index '%s' with "DFID": rc = %d\n",
	       osd_name(dev), liru->liru_name, PFID(tgt_fid), rc);
}

/**
 * verify FID-in-LMA and OI entry for one object
 *
 * ios: Initial OI Scrub.
 */
static int osd_ios_scan_one(const struct lu_env *env, struct osd_device *dev,
			    const struct lu_fid *fid, uint64_t parent,
			    uint64_t oid, const char *name,
			    enum osd_lf_flags flags)
{
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct scrub_file *sf = &scrub->os_file;
	struct lustre_mdt_attrs *lma = NULL;
	nvlist_t *nvbuf = NULL;
	struct lu_fid tfid;
	uint64_t oid2 = 0;
	__u64 flag = 0;
	int size = 0;
	int op = 0;
	int rc;

	ENTRY;
	rc = __osd_xattr_load_by_oid(dev, oid, &nvbuf);
	if (unlikely(rc == -ENOENT || rc == -EEXIST))
		RETURN(0);

	if (rc && rc != -ENODATA) {
		CWARN("%s: initial OI scrub failed to get lma for %llu: rc = %d\n",
		      osd_name(dev), oid, rc);

		RETURN(rc);
	}

	if (!rc) {
		LASSERT(nvbuf != NULL);
		rc = -nvlist_lookup_byte_array(nvbuf, XATTR_NAME_LMA,
					       (uchar_t **)&lma, &size);
		if (rc || size == 0) {
			LASSERT(lma == NULL);
			rc = -ENODATA;
		} else {
			LASSERTF(lma != NULL, "corrupted LMA, size %d\n", size);
			lustre_lma_swab(lma);
			if (lma->lma_compat & LMAC_NOT_IN_OI) {
				nvlist_free(nvbuf);
				RETURN(0);
			}

			if (lma->lma_compat & LMAC_IDX_BACKUP &&
			    osd_index_need_recreate(env, dev, oid)) {
				if (parent == dev->od_root) {
					lu_local_obj_fid(&tfid,
							 OSD_FS_ROOT_OID);
				} else {
					rc = osd_get_fid_by_oid(env, dev,
								parent, &tfid);
					if (rc) {
						nvlist_free(nvbuf);
						RETURN(rc);
					}
				}

				rc = lustre_liru_new(
						&dev->od_index_restore_list,
						&tfid, &lma->lma_self_fid, oid,
						name, strlen(name));
				nvlist_free(nvbuf);
				RETURN(rc);
			}

			tfid = lma->lma_self_fid;
			if (!(flags & OLF_NOT_BACKUP))
				osd_ios_index_register(env, dev, &tfid, oid);
		}
		nvlist_free(nvbuf);
	}

	if (rc == -ENODATA) {
		if (!fid) {
			/* Skip the object without FID-in-LMA */
			CDEBUG(D_LFSCK, "%s: %llu has no FID-in-LMA, skip it\n",
			       osd_name(dev), oid);

			RETURN(0);
		}

		LASSERT(!fid_is_zero(fid));

		tfid = *fid;
		if (flags & OLF_IDX_IN_FID) {
			LASSERT(dev->od_index >= 0);

			tfid.f_oid = dev->od_index;
		}
	}

	rc = osd_fid_lookup(env, dev, &tfid, &oid2);
	if (rc) {
		if (rc != -ENOENT) {
			CWARN("%s: initial OI scrub failed to lookup fid for "DFID"=>%llu: rc = %d\n",
			      osd_name(dev), PFID(&tfid), oid, rc);
			RETURN(rc);
		}

		flag = SF_RECREATED;
		op = DTO_INDEX_INSERT;
	} else {
		if (oid == oid2)
			RETURN(0);

		flag = SF_INCONSISTENT;
		op = DTO_INDEX_UPDATE;
	}

	if (!(sf->sf_flags & flag)) {
		scrub_file_reset(scrub, dev->od_uuid, flag);
		rc = scrub_file_store(env, scrub);
		if (rc)
			RETURN(rc);
	}

	rc = osd_scrub_refresh_mapping(env, dev, &tfid, oid, op, true, name);

	RETURN(rc > 0 ? 0 : rc);
}

static int osd_ios_varfid_hd(const struct lu_env *env, struct osd_device *dev,
			     const char *name, uint64_t parent, uint64_t oid,
			     enum osd_lf_flags flags, bool is_dir)
{
	int rc;

	ENTRY;
	rc = osd_ios_scan_one(env, dev, NULL, parent, oid, name, 0);
	if (!rc && is_dir)
		rc = osd_ios_new_item(dev, oid, flags, osd_ios_general_sd,
				      osd_ios_varfid_hd);

	RETURN(rc);
}

static int osd_ios_uld_hd(const struct lu_env *env, struct osd_device *dev,
			  const char *name, uint64_t parent, uint64_t oid,
			  enum osd_lf_flags flags, bool is_dir)
{
	struct lu_fid tfid;
	int rc;

	ENTRY;
	/* skip any non-DFID format name */
	if (name[0] != '[')
		RETURN(0);

	/* skip the start '[' */
	sscanf(&name[1], SFID, RFID(&tfid));
	if (fid_is_sane(&tfid))
		rc = osd_ios_scan_one(env, dev, &tfid, parent, oid, name, 0);
	else
		rc = -EIO;

	RETURN(rc);
}

/*
 * General scanner for the directories execpt /ROOT during initial OI scrub.
 * It scans the name entries under the given directory one by one. For each
 * entry, verifies its OI mapping via the given @handle_dirent.
 */
static int osd_ios_general_sd(const struct lu_env *env, struct osd_device *dev,
			      uint64_t parent, handle_dirent_t handle_dirent,
			      enum osd_lf_flags flags)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct luz_direntry *zde = &info->oti_zde;
	zap_attribute_t *za = &info->oti_za;
	zap_cursor_t *zc = &info->oti_zc;
	int rc;

	ENTRY;
	zap_cursor_init_serialized(zc, dev->od_os, parent, 0);
	rc = -zap_cursor_retrieve(zc, za);
	if (rc == -ENOENT)
		zap_cursor_advance(zc);
	else if (rc)
		GOTO(log, rc);

	while (1) {
		rc = -zap_cursor_retrieve(zc, za);
		if (rc)
			GOTO(log, rc = (rc == -ENOENT ? 0 : rc));

		/* skip the entry started with '.' */
		if (likely(za->za_name[0] != '.')) {
			rc = osd_zap_lookup(dev, parent, NULL, za->za_name,
					za->za_integer_length,
					sizeof(*zde) / za->za_integer_length,
					(void *)zde);
			if (rc) {
				CWARN("%s: initial OI scrub failed to lookup %s under %llu: rc = %d\n",
				      osd_name(dev), za->za_name, parent, rc);
				continue;
			}

			rc = handle_dirent(env, dev, za->za_name, parent,
					zde->lzd_reg.zde_dnode, flags,
					S_ISDIR(DTTOIF(zde->lzd_reg.zde_type)) ?
					true : false);
			CDEBUG(D_LFSCK,
			       "%s: initial OI scrub handled %s under %llu: rc = %d\n",
			       osd_name(dev), za->za_name, parent, rc);
		}

		zap_cursor_advance(zc);
	}

log:
	if (rc)
		CWARN("%s: initial OI scrub failed to scan the directory %llu: rc = %d\n",
		      osd_name(dev), parent, rc);
	zap_cursor_fini(zc);

	return rc;
}

/*
 * The scanner for /ROOT directory. It is not all the items under /ROOT will
 * be scanned during the initial OI scrub, instead, only the .lustre and the
 * sub-items under .lustre will be handled.
 */
static int osd_ios_ROOT_sd(const struct lu_env *env, struct osd_device *dev,
			   uint64_t parent, handle_dirent_t handle_dirent,
			   enum osd_lf_flags flags)
{
	struct luz_direntry *zde = &osd_oti_get(env)->oti_zde;
	const struct osd_lf_map *map;
	uint64_t oid;
	int rc;
	int rc1 = 0;

	ENTRY;
	rc = osd_zap_lookup(dev, parent, NULL, dot_lustre_name, 8,
			    sizeof(*zde) / 8, (void *)zde);
	if (rc == -ENOENT) {
		/* The .lustre directory is lost. That is not fatal. It can
		 * be re-created in the subsequent MDT start processing.
		 */
		RETURN(0);
	}

	if (rc) {
		CWARN("%s: initial OI scrub failed to find .lustre: rc = %d\n",
		      osd_name(dev), rc);

		RETURN(rc);
	}

	oid = zde->lzd_reg.zde_dnode;
	rc = osd_ios_scan_one(env, dev, &LU_DOT_LUSTRE_FID, parent, oid,
			      dot_lustre_name, 0);
	if (rc)
		RETURN(rc);

	for (map = osd_dl_maps; map->olm_name; map++) {
		rc = osd_zap_lookup(dev, oid, NULL, map->olm_name, 8,
				    sizeof(*zde) / 8, (void *)zde);
		if (rc) {
			if (rc != -ENOENT)
				CWARN("%s: initial OI scrub failed to find the entry %s under .lustre: rc = %d\n",
				      osd_name(dev), map->olm_name, rc);
			else if (!fid_is_zero(&map->olm_fid))
				/* Try to remove the stale OI mapping. */
				osd_scrub_refresh_mapping(env, dev,
						&map->olm_fid, 0,
						DTO_INDEX_DELETE, true,
						map->olm_name);
			continue;
		}

		rc = osd_ios_scan_one(env, dev, &map->olm_fid, oid,
				      zde->lzd_reg.zde_dnode, map->olm_name,
				      map->olm_flags);
		if (rc)
			rc1 = rc;
	}

	RETURN(rc1);
}

static void osd_initial_OI_scrub(const struct lu_env *env,
				 struct osd_device *dev)
{
	struct luz_direntry *zde = &osd_oti_get(env)->oti_zde;
	const struct osd_lf_map *map;
	int rc;

	ENTRY;
	for (map = osd_lf_maps; map->olm_name; map++) {
		rc = osd_zap_lookup(dev, dev->od_root, NULL, map->olm_name, 8,
				    sizeof(*zde) / 8, (void *)zde);
		if (rc) {
			if (rc != -ENOENT)
				CWARN("%s: initial OI scrub failed to find the entry %s: rc = %d\n",
				      osd_name(dev), map->olm_name, rc);
			else if (!fid_is_zero(&map->olm_fid))
				/* Try to remove the stale OI mapping. */
				osd_scrub_refresh_mapping(env, dev,
						&map->olm_fid, 0,
						DTO_INDEX_DELETE, true,
						map->olm_name);
			continue;
		}

		rc = osd_ios_scan_one(env, dev, &map->olm_fid, dev->od_root,
				      zde->lzd_reg.zde_dnode, map->olm_name,
				      map->olm_flags);
		if (!rc && map->olm_flags & OLF_SCAN_SUBITEMS)
			osd_ios_new_item(dev, zde->lzd_reg.zde_dnode,
					 map->olm_flags, map->olm_scan_dir,
					 map->olm_handle_dirent);
	}

	while (!list_empty(&dev->od_ios_list)) {
		struct osd_ios_item *item;

		item = list_first_entry(&dev->od_ios_list,
					struct osd_ios_item, oii_list);
		list_del_init(&item->oii_list);
		item->oii_scan_dir(env, dev, item->oii_parent,
				   item->oii_handle_dirent, item->oii_flags);
		OBD_FREE_PTR(item);
	}

	if (!list_empty(&dev->od_index_restore_list)) {
		char *buf;

		OBD_ALLOC_LARGE(buf, INDEX_BACKUP_BUFSIZE);
		if (!buf)
			CERROR("%s: not enough RAM for rebuild index: rc = %d\n",
			       osd_name(dev), -ENOMEM);

		while (!list_empty(&dev->od_index_restore_list)) {
			struct lustre_index_restore_unit *liru;

			liru = list_first_entry(&dev->od_index_restore_list,
						struct lustre_index_restore_unit,
						liru_link);
			list_del(&liru->liru_link);
			if (buf)
				osd_index_restore(env, dev, liru, buf,
						  INDEX_BACKUP_BUFSIZE);
			OBD_FREE(liru, liru->liru_len);
		}

		if (buf)
			OBD_FREE_LARGE(buf, INDEX_BACKUP_BUFSIZE);
	}

	EXIT;
}

/* OI scrub start/stop */

int osd_scrub_start(const struct lu_env *env, struct osd_device *dev,
		    __u32 flags)
{
	int rc;

	ENTRY;
	if (dev->od_dt_dev.dd_rdonly)
		RETURN(-EROFS);

	/* od_otable_sem: prevent concurrent start/stop */
	down(&dev->od_otable_sem);
	rc = scrub_start(osd_scrub_main, &dev->od_scrub, dev, flags);
	up(&dev->od_otable_sem);

	RETURN(rc == -EALREADY ? 0 : rc);
}

void osd_scrub_stop(struct osd_device *dev)
{
	struct lustre_scrub *scrub = &dev->od_scrub;

	ENTRY;
	/* od_otable_sem: prevent concurrent start/stop */
	down(&dev->od_otable_sem);
	spin_lock(&scrub->os_lock);
	scrub->os_paused = 1;
	spin_unlock(&scrub->os_lock);
	scrub_stop(scrub);
	up(&dev->od_otable_sem);

	EXIT;
}

/* OI scrub setup/cleanup */

static const char osd_scrub_name[] = "OI_scrub";

int osd_scrub_setup(const struct lu_env *env, struct osd_device *dev,
		    time64_t interval, bool resetoi)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct scrub_file *sf = &scrub->os_file;
	struct lu_fid *fid = &info->oti_fid;
	struct dt_object *obj;
	uint64_t oid;
	int rc = 0;
	bool dirty = false;

	ENTRY;
	memcpy(dev->od_uuid.b,
	       &dsl_dataset_phys(dev->od_os->os_dsl_dataset)->ds_guid,
	       sizeof(dsl_dataset_phys(dev->od_os->os_dsl_dataset)->ds_guid));
	memset(&dev->od_scrub, 0, sizeof(struct lustre_scrub));
	init_rwsem(&scrub->os_rwsem);
	spin_lock_init(&scrub->os_lock);
	INIT_LIST_HEAD(&scrub->os_inconsistent_items);
	scrub->os_name = osd_name(dev);
	scrub->os_auto_scrub_interval = interval;

	/* 'What the @fid is' is not imporatant, because the object
	 * has no OI mapping, and only is visible inside the OSD.
	 */
	fid->f_seq = FID_SEQ_IGIF_MAX;
	if (dev->od_is_ost)
		fid->f_oid = ((1 << 31) | dev->od_index) + 1;
	else
		fid->f_oid = dev->od_index + 1;
	fid->f_ver = 0;
	rc = osd_obj_find_or_create(env, dev, dev->od_root,
				    osd_scrub_name, &oid, fid, false);
	if (rc)
		RETURN(rc);

	rc = osd_idc_find_and_init_with_oid(env, dev, fid, oid);
	if (rc)
		RETURN(rc);

	obj = lu2dt(lu_object_find_slice(env, osd2lu_dev(dev), fid, NULL));
	if (IS_ERR_OR_NULL(obj))
		RETURN(obj ? PTR_ERR(obj) : -ENOENT);

	obj->do_body_ops = &osd_body_scrub_ops;
	scrub->os_obj = obj;
	rc = scrub_file_load(env, scrub);
	if (rc == -ENOENT || rc == -EFAULT) {
		scrub_file_init(scrub, dev->od_uuid);
		dirty = true;
	} else if (rc < 0) {
		GOTO(cleanup_obj, rc);
	} else {
		if (!guid_equal(&sf->sf_uuid, &dev->od_uuid)) {
			CDEBUG(D_LFSCK,
			       "%s: UUID has been changed from %pU to %pU\n",
			       osd_name(dev), &sf->sf_uuid, &dev->od_uuid);
			scrub_file_reset(scrub, dev->od_uuid, SF_INCONSISTENT);
			dirty = true;
		} else if (sf->sf_status == SS_SCANNING) {
			sf->sf_status = SS_CRASHED;
			dirty = true;
		}

		if (unlikely((sf->sf_oi_count & (sf->sf_oi_count - 1)) != 0 ||
			     sf->sf_oi_count > OSD_OI_FID_NR_MAX)) {
			LCONSOLE_WARN("%s: invalid OI count %u, reset to %u\n",
				      osd_name(dev), sf->sf_oi_count,
				      osd_oi_count);
			sf->sf_oi_count = osd_oi_count;
			dirty = true;
		}
	}

	if (sf->sf_pos_last_checkpoint != 0)
		scrub->os_pos_current = sf->sf_pos_last_checkpoint + 1;
	else
		scrub->os_pos_current = 1;

	if (dirty) {
		rc = scrub_file_store(env, scrub);
		if (rc)
			GOTO(cleanup_obj, rc);
	}

	/* Initialize OI files. */
	rc = osd_oi_init(env, dev, resetoi);
	if (rc < 0)
		GOTO(cleanup_obj, rc);

	if (!dev->od_dt_dev.dd_rdonly)
		osd_initial_OI_scrub(env, dev);

	if (!dev->od_dt_dev.dd_rdonly &&
	    scrub->os_auto_scrub_interval != AS_NEVER &&
	    ((sf->sf_status == SS_PAUSED) ||
	     (sf->sf_status == SS_CRASHED &&
	      sf->sf_flags & (SF_RECREATED | SF_INCONSISTENT |
			      SF_UPGRADE | SF_AUTO)) ||
	     (sf->sf_status == SS_INIT &&
	      sf->sf_flags & (SF_RECREATED | SF_INCONSISTENT |
			      SF_UPGRADE))))
		rc = osd_scrub_start(env, dev, SS_AUTO_FULL);

	if (rc)
		GOTO(cleanup_oi, rc);

	RETURN(0);

cleanup_oi:
	osd_oi_fini(env, dev);
cleanup_obj:
	dt_object_put_nocache(env, scrub->os_obj);
	scrub->os_obj = NULL;

	return rc;
}

void osd_scrub_cleanup(const struct lu_env *env, struct osd_device *dev)
{
	struct lustre_scrub *scrub = &dev->od_scrub;

	LASSERT(!dev->od_otable_it);

	if (scrub->os_obj) {
		osd_scrub_stop(dev);
		dt_object_put_nocache(env, scrub->os_obj);
		scrub->os_obj = NULL;
	}

	if (dev->od_oi_table)
		osd_oi_fini(env, dev);
}

/* object table based iteration APIs */

static struct dt_it *osd_otable_it_init(const struct lu_env *env,
				       struct dt_object *dt, __u32 attr)
{
	enum dt_otable_it_flags flags = attr >> DT_OTABLE_IT_FLAGS_SHIFT;
	enum dt_otable_it_valid valid = attr & ~DT_OTABLE_IT_FLAGS_MASK;
	struct osd_device *dev = osd_dev(dt->do_lu.lo_dev);
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct osd_otable_it *it;
	__u32 start = 0;
	int rc;

	ENTRY;
	if (dev->od_dt_dev.dd_rdonly)
		RETURN(ERR_PTR(-EROFS));

	/* od_otable_sem: prevent concurrent init/fini */
	down(&dev->od_otable_sem);
	if (dev->od_otable_it)
		GOTO(out, it = ERR_PTR(-EALREADY));

	OBD_ALLOC_PTR(it);
	if (!it)
		GOTO(out, it = ERR_PTR(-ENOMEM));

	if (flags & DOIF_OUTUSED)
		it->ooi_used_outside = 1;

	if (flags & DOIF_RESET)
		start |= SS_RESET;

	if (valid & DOIV_ERROR_HANDLE) {
		if (flags & DOIF_FAILOUT)
			start |= SS_SET_FAILOUT;
		else
			start |= SS_CLEAR_FAILOUT;
	}

	if (valid & DOIV_DRYRUN) {
		if (flags & DOIF_DRYRUN)
			start |= SS_SET_DRYRUN;
		else
			start |= SS_CLEAR_DRYRUN;
	}

	/* XXX: dmu_object_next() does NOT find dnodes allocated
	 *	in the current non-committed txg, so we force txg
	 *	commit to find all existing dnodes ...
	 */
	txg_wait_synced(dmu_objset_pool(dev->od_os), 0ULL);

	dev->od_otable_it = it;
	it->ooi_dev = dev;
	rc = scrub_start(osd_scrub_main, scrub, dev, start & ~SS_AUTO_PARTIAL);
	if (rc == -EALREADY) {
		it->ooi_pos = 1;
	} else if (rc < 0) {
		dev->od_otable_it = NULL;
		OBD_FREE_PTR(it);
		it = ERR_PTR(rc);
	} else {
		it->ooi_pos = scrub->os_pos_current;
	}

	GOTO(out, it);

out:
	up(&dev->od_otable_sem);
	return (struct dt_it *)it;
}

static void osd_otable_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_otable_it *it = (struct osd_otable_it *)di;
	struct osd_device *dev = it->ooi_dev;

	/* od_otable_sem: prevent concurrent init/fini */
	down(&dev->od_otable_sem);
	scrub_stop(&dev->od_scrub);
	LASSERT(dev->od_otable_it == it);

	dev->od_otable_it = NULL;
	up(&dev->od_otable_sem);
	OBD_FREE_PTR(it);
}

static int osd_otable_it_get(const struct lu_env *env,
			     struct dt_it *di, const struct dt_key *key)
{
	return 0;
}

static void osd_otable_it_put(const struct lu_env *env, struct dt_it *di)
{
}

static void osd_otable_it_preload(const struct lu_env *env,
				  struct osd_otable_it *it)
{
	struct osd_device *dev = it->ooi_dev;
	int rc;

	/* can go negative on the very first access to the iterator
	 * or if some non-Lustre objects were found
	 */
	if (unlikely(it->ooi_prefetched < 0))
		it->ooi_prefetched = 0;

	if (it->ooi_prefetched >= (OTABLE_PREFETCH >> 1))
		return;

	if (it->ooi_prefetched_dnode == 0)
		it->ooi_prefetched_dnode = it->ooi_pos;

	while (it->ooi_prefetched < OTABLE_PREFETCH) {
		rc = -dmu_object_next(dev->od_os, &it->ooi_prefetched_dnode,
				      B_FALSE, 0);
		if (rc)
			break;

		dmu_prefetch(dev->od_os, it->ooi_prefetched_dnode,
				 0, 0, 0, ZIO_PRIORITY_ASYNC_READ);
		it->ooi_prefetched++;
	}
}

static inline int
osd_otable_it_wakeup(struct lustre_scrub *scrub, struct osd_otable_it *it)
{
	spin_lock(&scrub->os_lock);
	if (it->ooi_pos < scrub->os_pos_current || scrub->os_waiting ||
	    !scrub->os_running)
		it->ooi_waiting = 0;
	else
		it->ooi_waiting = 1;
	spin_unlock(&scrub->os_lock);

	return !it->ooi_waiting;
}

static int osd_otable_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_otable_it *it = (struct osd_otable_it *)di;
	struct osd_device *dev = it->ooi_dev;
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct lustre_mdt_attrs *lma = NULL;
	nvlist_t *nvbuf = NULL;
	int rc, size = 0;
	bool locked;

	ENTRY;
	LASSERT(it->ooi_user_ready);
	fid_zero(&it->ooi_fid);

	if (unlikely(it->ooi_all_cached))
		RETURN(1);

again:
	if (nvbuf) {
		nvlist_free(nvbuf);
		nvbuf = NULL;
		lma = NULL;
		size = 0;
	}

	if (it->ooi_pos >= scrub->os_pos_current)
		wait_var_event(scrub,
			       osd_otable_it_wakeup(scrub, it));

	if (!scrub->os_running && !it->ooi_used_outside)
		GOTO(out, rc = 1);

	rc = -dmu_object_next(dev->od_os, &it->ooi_pos, B_FALSE, 0);
	if (rc) {
		if (unlikely(rc == -ESRCH)) {
			it->ooi_all_cached = 1;
			rc = 1;
		}

		GOTO(out, rc);
	}

	rc = __osd_xattr_load_by_oid(dev, it->ooi_pos, &nvbuf);

	locked = false;
	if (!scrub->os_full_speed) {
		spin_lock(&scrub->os_lock);
		locked = true;
	}
	it->ooi_prefetched--;
	if (!scrub->os_full_speed) {
		if (scrub->os_waiting) {
			scrub->os_waiting = 0;
			wake_up_var(scrub);
		}
	}
	if (locked)
		spin_unlock(&scrub->os_lock);

	if (rc == -ENOENT || rc == -EEXIST || rc == -ENODATA)
		goto again;

	if (rc)
		GOTO(out, rc);

	LASSERT(nvbuf != NULL);
	rc = -nvlist_lookup_byte_array(nvbuf, XATTR_NAME_LMA,
				       (uchar_t **)&lma, &size);
	if (rc || size == 0)
		/* It is either non-Lustre object or OSD internal object,
		 * ignore it, go ahead
		 */
		goto again;

	LASSERTF(lma != NULL, "corrupted LMA, size %d\n", size);
	lustre_lma_swab(lma);
	if (unlikely(lma->lma_compat & LMAC_NOT_IN_OI ||
		     lma->lma_incompat & LMAI_AGENT))
		goto again;

	it->ooi_fid = lma->lma_self_fid;

	GOTO(out, rc = 0);

out:
	if (nvbuf)
		nvlist_free(nvbuf);

	if (!rc && scrub->os_full_speed)
		osd_otable_it_preload(env, it);

	return rc;
}

static struct dt_key *osd_otable_it_key(const struct lu_env *env,
					const struct dt_it *di)
{
	return NULL;
}

static int osd_otable_it_key_size(const struct lu_env *env,
				  const struct dt_it *di)
{
	return sizeof(__u64);
}

static int osd_otable_it_rec(const struct lu_env *env, const struct dt_it *di,
			     struct dt_rec *rec, __u32 attr)
{
	struct osd_otable_it *it  = (struct osd_otable_it *)di;
	struct lu_fid *fid = (struct lu_fid *)rec;

	*fid = it->ooi_fid;
	return 0;
}

static __u64 osd_otable_it_store(const struct lu_env *env,
				 const struct dt_it *di)
{
	struct osd_otable_it *it = (struct osd_otable_it *)di;

	return it->ooi_pos;
}

/**
 * Set the OSD layer iteration start position as the specified hash.
 */
static int osd_otable_it_load(const struct lu_env *env,
			      const struct dt_it *di, __u64 hash)
{
	struct osd_otable_it *it = (struct osd_otable_it *)di;
	struct osd_device *dev = it->ooi_dev;
	struct lustre_scrub *scrub = &dev->od_scrub;
	int rc;

	ENTRY;
	/* Forbid to set iteration position after iteration started. */
	if (it->ooi_user_ready)
		RETURN(-EPERM);

	if (hash > OSD_OTABLE_MAX_HASH)
		hash = OSD_OTABLE_MAX_HASH;

	/* The hash is the last checkpoint position, start from the next one. */
	it->ooi_pos = hash + 1;
	it->ooi_prefetched = 0;
	it->ooi_prefetched_dnode = 0;
	it->ooi_user_ready = 1;
	if (!scrub->os_full_speed)
		wake_up_var(scrub);

	/* Unplug OSD layer iteration by the first next() call. */
	rc = osd_otable_it_next(env, (struct dt_it *)it);

	RETURN(rc);
}

const struct dt_index_operations osd_otable_ops = {
	.dio_it = {
		.init     = osd_otable_it_init,
		.fini     = osd_otable_it_fini,
		.get      = osd_otable_it_get,
		.put	  = osd_otable_it_put,
		.next     = osd_otable_it_next,
		.key	  = osd_otable_it_key,
		.key_size = osd_otable_it_key_size,
		.rec      = osd_otable_it_rec,
		.store    = osd_otable_it_store,
		.load     = osd_otable_it_load,
	}
};

/* high priority inconsistent items list APIs */

int osd_oii_insert(const struct lu_env *env, struct osd_device *dev,
		   const struct lu_fid *fid, uint64_t oid, bool insert)
{
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct osd_inconsistent_item *oii;
	bool wakeup = false;

	ENTRY;
	osd_idc_find_and_init_with_oid(env, dev, fid, oid);
	OBD_ALLOC_PTR(oii);
	if (unlikely(!oii))
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&oii->oii_list);
	oii->oii_cache.oic_dev = dev;
	oii->oii_cache.oic_fid = *fid;
	oii->oii_cache.oic_dnode = oid;
	oii->oii_insert = insert;

	spin_lock(&scrub->os_lock);
	if (!scrub->os_running) {
		spin_unlock(&scrub->os_lock);
		OBD_FREE_PTR(oii);
		RETURN(-EAGAIN);
	}

	if (list_empty(&scrub->os_inconsistent_items))
		wakeup = true;
	list_add_tail(&oii->oii_list, &scrub->os_inconsistent_items);
	spin_unlock(&scrub->os_lock);

	if (wakeup)
		wake_up_var(scrub);

	RETURN(0);
}

int osd_oii_lookup(struct osd_device *dev, const struct lu_fid *fid,
		   uint64_t *oid)
{
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct osd_inconsistent_item *oii;
	int ret = -ENOENT;

	ENTRY;
	spin_lock(&scrub->os_lock);
	list_for_each_entry(oii, &scrub->os_inconsistent_items, oii_list) {
		if (lu_fid_eq(fid, &oii->oii_cache.oic_fid)) {
			*oid = oii->oii_cache.oic_dnode;
			ret = 0;
			break;
		}
	}
	spin_unlock(&scrub->os_lock);

	RETURN(ret);
}

typedef int (*scan_dir_helper_t)(const struct lu_env *env,
				 struct osd_device *dev, uint64_t dir_oid,
				 struct osd_zap_it *ozi);

static int osd_scan_dir(const struct lu_env *env, struct osd_device *dev,
			uint64_t id, scan_dir_helper_t cb)
{
	struct osd_zap_it *it;
	struct luz_direntry *zde;
	zap_attribute_t	*za;
	int rc;

	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(it, osd_zapit_cachep, GFP_NOFS);
	if (it == NULL)
		RETURN(-ENOMEM);

	rc = osd_zap_cursor_init(&it->ozi_zc, dev->od_os, id, 0);
	if (rc != 0)
		GOTO(out, rc);

	za = &it->ozi_za;
	zde = &it->ozi_zde;

#ifdef ZAP_MAXNAMELEN_NEW
	za->za_name_len = MAXNAMELEN;
#endif

	while (1) {
		rc = -zap_cursor_retrieve(it->ozi_zc, za);
		if (unlikely(rc)) {
			if (rc == -ENOENT)
				rc = 0;

			break;
		}

		if (name_is_dot_or_dotdot(za->za_name, strlen(za->za_name))) {
			zap_cursor_advance(it->ozi_zc);
			continue;
		}

		strncpy(it->ozi_name, za->za_name, sizeof(it->ozi_name));
		if (za->za_integer_length != 8) {
			rc = -EIO;
			break;
		}

		rc = osd_zap_lookup(dev, it->ozi_zc->zc_zapobj, NULL,
				    za->za_name, za->za_integer_length,
				    sizeof(*zde) / za->za_integer_length, zde);
		if (rc)
			break;

		rc = cb(env, dev, id, it);
		if (rc)
			break;

		zap_cursor_advance(it->ozi_zc);
	}
	osd_zap_cursor_fini(it->ozi_zc);

out:
	OBD_SLAB_FREE_PTR(it, osd_zapit_cachep);
	RETURN(rc);
}

static int osd_remove_ml_file(const struct lu_env *env, struct osd_device *dev,
			      uint64_t dir, uint64_t id, struct lu_fid *fid,
			      char *name)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct dt_object *dt;
	struct osd_object *obj = NULL;
	dmu_tx_t *tx;
	sa_handle_t *hdl;
	uint64_t nlink;
	int rc;

	rc = -sa_handle_get(dev->od_os, id, NULL, SA_HDL_PRIVATE, &hdl);
	if (rc)
		RETURN(rc);

	dt = lu2dt(lu_object_find_slice(env, osd2lu_dev(dev), fid, NULL));
	if (IS_ERR(dt))
		RETURN(PTR_ERR(dt));

	if (dt) {
		obj = osd_dt_obj(dt);
		down_read(&obj->oo_guard);
	}

	rc = -sa_lookup(hdl, SA_ZPL_LINKS(dev), &nlink, sizeof(nlink));
	if (rc)
		GOTO(out, rc);

	if (nlink <= 1) {
		rc = 0;
		CERROR("%s: multi-link file O/%s/%s/%s has nlink %llu: rc = %d\n",
		       osd_name(dev), info->oti_seq_name, info->oti_dir_name,
		       name, nlink, rc);
		GOTO(out, rc);
	}

	tx = dmu_tx_create(dev->od_os);
	if (!tx) {
		rc = -ENOMEM;
		CERROR("%s: fail to create tx to remove multi-link file!: rc = %d\n",
		       osd_name(dev), rc);
		GOTO(out, rc);
	}

	dmu_tx_hold_zap(tx, dir, FALSE, NULL);
	rc = -dmu_tx_assign(tx, DMU_TX_WAIT);
	if (rc)
		GOTO(abort, rc);

	nlink--;
	rc = -sa_update(hdl, SA_ZPL_LINKS(dev), &nlink, sizeof(nlink), tx);
	if (rc)
		GOTO(abort, rc);

	rc = -zap_remove(dev->od_os, dir, name, tx);
	if (rc)
		GOTO(abort, rc);

	dmu_tx_commit(tx);
	GOTO(out, rc);

abort:
	dmu_tx_abort(tx);

out:
	if (dt) {
		up_read(&obj->oo_guard);
		dt_object_put_nocache(env, dt);
	}

	sa_handle_destroy(hdl);
	RETURN(rc);
}

static int osd_scan_ml_file(const struct lu_env *env, struct osd_device *dev,
			    uint64_t dir_oid, struct osd_zap_it *ozi)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lu_fid *fid = &info->oti_fid;
	struct ost_id *ostid = &info->oti_ostid;
	char name[32];
	u64 seq;
	int rc = 0;

	ENTRY;

	rc = osd_get_fid_by_oid(env, dev, ozi->ozi_zde.lzd_reg.zde_dnode, fid);
	if (rc)
		RETURN(rc);

	seq = fid_seq(fid);
	fid_to_ostid(fid, ostid);

	snprintf(name, sizeof(name), (fid_seq_is_rsvd(seq) ||
				      fid_seq_is_mdt0(seq)) ? "%llu" : "%llx",
				      fid_seq_is_idif(seq) ? 0 : seq);
	if (strcmp(info->oti_seq_name, name) != 0)
		GOTO(fix, rc);

	snprintf(name, sizeof(name), "d%d",
		(int)ostid_id(ostid) % OSD_OST_MAP_SIZE);
	if (strcmp(info->oti_dir_name, name) != 0)
		GOTO(fix, rc);

	snprintf(name, sizeof(name), "%llu", ostid_id(ostid));
	if (strcmp(ozi->ozi_name, name) == 0)
		RETURN(0);

fix:
	CDEBUG(D_LFSCK, "%s: the file O/%s/%s/%s is corrupted\n",
	       osd_name(dev), info->oti_seq_name, info->oti_dir_name,
	       ozi->ozi_name);

	rc = osd_remove_ml_file(env, dev, dir_oid,
				ozi->ozi_zde.lzd_reg.zde_dnode, fid,
				ozi->ozi_name);
	RETURN(rc);
}

static int osd_scan_ml_file_dir(const struct lu_env *env,
				struct osd_device *dev, uint64_t dir_oid,
				struct osd_zap_it *ozi)
{
	struct osd_thread_info *info = osd_oti_get(env);

	if (!S_ISDIR(cpu_to_le16(DTTOIF(ozi->ozi_zde.lzd_reg.zde_type))))
		return 0;

	info->oti_dir_name = ozi->ozi_name;
	return osd_scan_dir(env, dev, ozi->ozi_zde.lzd_reg.zde_dnode,
			    osd_scan_ml_file);
}

static int osd_scan_ml_file_seq(const struct lu_env *env,
				struct osd_device *dev, uint64_t dir_oid,
				struct osd_zap_it *ozi)
{
	struct osd_thread_info *info = osd_oti_get(env);

	if (!S_ISDIR(cpu_to_le16(DTTOIF(ozi->ozi_zde.lzd_reg.zde_type))))
		return 0;

	info->oti_seq_name = ozi->ozi_name;
	return osd_scan_dir(env, dev, ozi->ozi_zde.lzd_reg.zde_dnode,
			    osd_scan_ml_file_dir);
}

static int osd_scan_ml_file_main(const struct lu_env *env,
				 struct osd_device *dev)
{
	return osd_scan_dir(env, dev, dev->od_O_id, osd_scan_ml_file_seq);
}

#define LASTID	"LAST_ID"

static int osd_create_lastid(const struct lu_env *env, struct osd_device *dev,
			     struct osd_zap_it *ozi, __u64 lastid_known)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lustre_mdt_attrs *lma = &info->oti_mdt_attrs;
	struct lu_attr *la = &info->oti_la;
	struct luz_direntry *zde = &info->oti_zde;
	uint64_t dir = ozi->ozi_zde.lzd_reg.zde_dnode;
	dmu_tx_t *tx = NULL;
	nvlist_t *nvbuf = NULL;
	dnode_t *dn = NULL;
	sa_handle_t *hdl;
	__u64 lastid;
	int num = sizeof(*zde) / 8;
	int rc = 0;

	ENTRY;

	tx = dmu_tx_create(dev->od_os);
	if (!tx)
		GOTO(out, rc = -ENOMEM);

	dmu_tx_hold_sa_create(tx, osd_find_dnsize(dev, OSD_BASE_EA_IN_BONUS));
	dmu_tx_hold_zap(tx, dir, FALSE, NULL);

	rc = -dmu_tx_assign(tx, DMU_TX_WAIT);
	if (rc)
		GOTO(abort, rc);

	memset(&zde->lzd_reg, 0, sizeof(zde->lzd_reg));
	zde->lzd_reg.zde_type = IFTODT(S_IFREG);
	zde->lzd_fid = lma->lma_self_fid;

	rc = -nvlist_alloc(&nvbuf, NV_UNIQUE_NAME, KM_SLEEP);
	if (rc)
		GOTO(abort, rc);

	lustre_lma_init(lma, &zde->lzd_fid, 0, 0);
	lustre_lma_swab(lma);
	rc = -nvlist_add_byte_array(nvbuf, XATTR_NAME_LMA, (uchar_t *)lma,
				    sizeof(*lma));
	if (rc)
		GOTO(abort, rc);

	la->la_valid = LA_TYPE | LA_MODE;
	la->la_mode = (DTTOIF(zde->lzd_reg.zde_type) & S_IFMT) | 0644;

	rc = __osd_object_create(env, dev, NULL, &zde->lzd_fid, &dn, tx, la);
	if (rc)
		GOTO(abort, rc);

	zde->lzd_reg.zde_dnode = dn->dn_object;
	rc = -sa_handle_get(dev->od_os, dn->dn_object, NULL,
			    SA_HDL_PRIVATE, &hdl);
	if (rc)
		GOTO(abort, rc);

	rc = __osd_attr_init(env, dev, NULL, hdl, tx, la, dir, nvbuf);
	if (rc)
		GOTO(abort, rc);

	sa_handle_destroy(hdl);
	hdl = NULL;

	dmu_tx_hold_write_by_dnode(tx, dn, 0, sizeof(lastid_known));

	lastid = cpu_to_le64(lastid_known);
#ifdef HAVE_DMU_WRITE_BY_DNODE_6ARGS
	dmu_write_by_dnode(dn, 0, sizeof(lastid), &lastid, tx, 0);
#else
	dmu_write_by_dnode(dn, 0, sizeof(lastid), &lastid, tx);
#endif

	rc = osd_zap_add(dev, dir, NULL, LASTID, strlen(LASTID), num,
			 (void *)zde, tx);
	if (rc)
		GOTO(abort, tx);

	dmu_tx_commit(tx);
	GOTO(out, rc);

abort:
	if (dn)
		dmu_object_free(dev->od_os, dn->dn_object, tx);

	dmu_tx_abort(tx);

out:
	if (hdl)
		sa_handle_destroy(hdl);
	if (dn)
		osd_dnode_rele(dn);
	if (nvbuf)
		nvlist_free(nvbuf);

	return rc;
}

static int osd_scan_lastid_dir(const struct lu_env *env,
			       struct osd_device *dev, uint64_t dir_oid,
			       struct osd_zap_it *ozi)
{
	struct osd_thread_info *info = osd_oti_get(env);

	ENTRY;

	if (!S_ISREG(cpu_to_le16(DTTOIF(ozi->ozi_zde.lzd_reg.zde_type))))
		RETURN(0);

	if (strcmp(ozi->ozi_name, LASTID) != 0) {
		CDEBUG(D_LFSCK, "%s: the file O/%s/%s is unexpected\n",
		       osd_name(dev), info->oti_seq_name, ozi->ozi_name);
		RETURN(0);
	}

	info->oti_lastid_oid = ozi->ozi_zde.lzd_reg.zde_dnode;
	RETURN(0);
}

static int osd_scan_lastid_seq(const struct lu_env *env,
			       struct osd_device *dev, uint64_t dir_oid,
			       struct osd_zap_it *ozi)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lustre_mdt_attrs *lma = &info->oti_mdt_attrs;
	struct lu_buf *lb = &info->oti_xattr_lbuf;
	struct lustre_scrub *scrub = &dev->od_scrub;
	dnode_t *dn = NULL;
	dmu_tx_t *tx = NULL;
	nvlist_t *nvbuf = NULL;
	sa_handle_t *hdl = NULL;
	uint64_t blocks;
	uint32_t blksize;
	uint32_t sz_lma;
	size_t size = 0;
	__u64 seq;
	__u64 lastid;
	__u64 lastid_known;
	bool need_update = false;
	int index;
	int rc;

	ENTRY;

	if (!S_ISDIR(cpu_to_le16(DTTOIF(ozi->ozi_zde.lzd_reg.zde_type))))
		RETURN(0);

	rc = kstrtoull(ozi->ozi_name, 16, &seq);
	if (rc)
		RETURN(rc);

	if (seq < 0x1F) {
		rc = kstrtoull(ozi->ozi_name, 10, &seq);
		if (rc)
			RETURN(rc);
	}

	if (!fid_seq_is_local_storage(seq))
		GOTO(out, rc = 0);

	info->oti_lastid_oid = 0;
	info->oti_seq_name = ozi->ozi_name;
	rc = osd_scan_dir(env, dev, ozi->ozi_zde.lzd_reg.zde_dnode,
			  osd_scan_lastid_dir);
	if (rc)
		GOTO(out, rc);

	for (index = 0; index < scrub->os_ls_count; index++)
		if (scrub->os_ls_fids[index].f_seq == seq)
			break;

	if (unlikely(index >= scrub->os_ls_count)) {
		CDEBUG(D_LFSCK,
		       "%s: can't find seq %llu, it's modified during scrub?\n",
		       osd_name(dev), seq);
		GOTO(out, rc = -ERANGE);
	}

	lastid_known = scrub->os_ls_fids[index].f_oid;

	if (info->oti_lastid_oid == 0) {
		lma->lma_self_fid.f_seq = seq;
		lma->lma_self_fid.f_oid = 0;
		lma->lma_self_fid.f_ver = 0;

		rc = osd_create_lastid(env, dev, ozi, lastid_known);
		GOTO(out, rc);
	}

	rc = __osd_obj2dnode(dev->od_os, info->oti_lastid_oid, &dn);
	if (rc)
		GOTO(out, rc);

	rc = -sa_handle_get(dev->od_os, dn->dn_object, NULL,
			    SA_HDL_PRIVATE, &hdl);
	if (rc)
		GOTO(out, rc);

	lastid = 0;
	sa_object_size(hdl, &blksize, &blocks);
	if (blocks > 0) {
		rc = osd_dmu_read(dev, dn, 0, sizeof(lastid), (char *) &lastid,
				  0);
		if (rc)
			GOTO(out, rc);

		lastid = le64_to_cpu(lastid);
		if (lastid <= lastid_known)
			need_update = true;
	} else {
		need_update = true;
	}

	rc = __osd_xattr_load(dev, hdl, &nvbuf);
	if (rc)
		GOTO(out, rc);

	rc = -nvlist_lookup_byte_array(nvbuf, XATTR_NAME_LMA, (uchar_t **) &lma,
				       &sz_lma);
	if (rc != 0 && rc != -ENOENT)
		GOTO(out, rc);

	if (rc == -ENOENT || lma->lma_self_fid.f_seq != seq ||
	    lma->lma_self_fid.f_oid != 0 || lma->lma_self_fid.f_ver != 0) {
		if (!rc) {
			rc = -nvlist_remove(nvbuf, XATTR_NAME_LMA,
					    DATA_TYPE_BYTE_ARRAY);
			if (rc)
				GOTO(out, rc);
		}

		need_update = true;
		lma->lma_self_fid.f_seq = seq;
		lma->lma_self_fid.f_oid = 0;
		lma->lma_self_fid.f_ver = 0;

		rc = -nvlist_add_byte_array(nvbuf, XATTR_NAME_LMA,
					    (uchar_t *) &lma, sizeof(lma));
		if (rc)
			GOTO(out, rc);
	}

	if (!need_update)
		GOTO(out, rc);

	if (scrub->os_file.sf_param & SP_DRYRUN)
		GOTO(out, rc = 0);

	tx = dmu_tx_create(dev->od_os);
	if (!tx)
		GOTO(out, rc = -ENOMEM);

	dmu_tx_hold_zap_by_dnode(tx, dn, TRUE, NULL);
	if (lastid < lastid_known)
		dmu_tx_hold_write_by_dnode(tx, dn, 0, sizeof(lastid));

	rc = -dmu_tx_assign(tx, DMU_TX_WAIT);
	if (rc)
		GOTO(abort, rc);

	rc = -nvlist_size(nvbuf, &size, NV_ENCODE_XDR);
	if (rc)
		GOTO(abort, rc);

	lu_buf_check_and_alloc(lb, size);
	if (lb->lb_buf == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = -nvlist_pack(nvbuf, (char **)&lb->lb_buf, &size, NV_ENCODE_XDR,
			  KM_SLEEP);
	if (rc)
		GOTO(abort, rc);

	rc = -sa_update(hdl, SA_ZPL_SIZE(dev), lb->lb_buf, size, tx);
	if (rc)
		GOTO(abort, rc);

	if (lastid < lastid_known) {
		lastid = cpu_to_le64(lastid_known);
#ifdef HAVE_DMU_WRITE_BY_DNODE_6ARGS
		dmu_write_by_dnode(dn, 0, sizeof(lastid),
				   (const char *) &lastid, tx, 0);
#else
		dmu_write_by_dnode(dn, 0, sizeof(lastid),
				   (const char *) &lastid, tx);
#endif
	}

	dmu_tx_commit(tx);
	GOTO(out, rc);

abort:
	dmu_tx_abort(tx);

out:
	if (hdl)
		sa_handle_destroy(hdl);

	if (dn)
		osd_dnode_rele(dn);

	RETURN(rc);
}

static int osd_scan_lastid_main(const struct lu_env *env,
				struct osd_device *dev)
{
	return osd_scan_dir(env, dev, dev->od_O_id, osd_scan_lastid_seq);
}

static int osd_scan_O_seq(const struct lu_env *env, struct osd_device *dev,
			  uint64_t dir_oid, struct osd_zap_it *ozi)
{
	struct lustre_scrub *scrub = &dev->od_scrub;
	struct lu_fid *fids;
	__u64 seq;
	int rc;

	ENTRY;

	if (!S_ISDIR(cpu_to_le16(DTTOIF(ozi->ozi_zde.lzd_reg.zde_type))))
		RETURN(0);

	rc = kstrtoull(ozi->ozi_name, 16, &seq);
	if (rc)
		RETURN(rc);

	if (seq < 0x1F) {
		rc = kstrtoull(ozi->ozi_name, 10, &seq);
		if (rc)
			RETURN(rc);
	}

	if (!fid_seq_is_local_storage(seq))
		GOTO(out, rc = 0);

	scrub->os_ls_count++;
	if (unlikely(scrub->os_ls_count > scrub->os_ls_size)) {
		OBD_ALLOC(fids,
			  sizeof(struct lu_fid) * (scrub->os_ls_size + 4));
		if (fids == NULL)
			GOTO(out, -ENOMEM);

		memcpy(fids, scrub->os_ls_fids,
		       sizeof(struct lu_fid) * scrub->os_ls_size);
		OBD_FREE(scrub->os_ls_fids,
			 sizeof(struct lu_fid) * scrub->os_ls_size);

		scrub->os_ls_size += 4;
		scrub->os_ls_fids = fids;
	}

	scrub->os_ls_fids[scrub->os_ls_count - 1].f_seq = seq;

out:
	RETURN(rc);
}

static int osd_scan_O_main(const struct lu_env *env, struct osd_device *dev)
{
	return osd_scan_dir(env, dev, dev->od_O_id, osd_scan_O_seq);
}

static int osd_seq_dir_helper(const struct lu_env *env,
			      struct osd_device *osd, uint64_t dir_oid,
			      struct osd_zap_it *ozi)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lu_fid *fid = &info->oti_fid;
	__u64 seq;
	int rc;

	if (!S_ISDIR(cpu_to_le16(DTTOIF(ozi->ozi_zde.lzd_reg.zde_type))))
		return 0;

	rc = kstrtoull(ozi->ozi_name, 16, &seq);
	if (!rc && seq >= FID_SEQ_NORMAL && seq > fid_seq(fid))
		fid->f_seq = seq;

	return 0;
}

int osd_last_seq_get(const struct lu_env *env, struct dt_device *dt,
		     __u64 *seq)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct osd_device *osd = osd_dt_dev(dt);
	struct lu_fid *fid = &info->oti_fid;
	int rc;

	ENTRY;

	if (!osd->od_is_ost)
		RETURN(-EINVAL);

	fid_zero(fid);
	rc = osd_scan_dir(env, osd, osd->od_O_id, osd_seq_dir_helper);
	if (!rc)
		*seq = fid_seq(fid);

	RETURN(rc);
}
