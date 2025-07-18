// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * NID table management for lustre.
 *
 * Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_MGS
#define D_MGS D_CONFIG

#include <linux/kthread.h>
#include <linux/pagemap.h>

#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>

#include "mgs_internal.h"

static time64_t ir_timeout;

static int nidtbl_is_sane(struct mgs_nidtbl *tbl)
{
	struct mgs_nidtbl_target *tgt;
	int version = 0;

	LASSERT(mutex_is_locked(&tbl->mn_lock));
	list_for_each_entry(tgt, &tbl->mn_targets, mnt_list) {
		if (!tgt->mnt_version)
			continue;

		if (version >= tgt->mnt_version)
			return 0;

		version = tgt->mnt_version;
	}
	return 1;
}

static unsigned int mgs_tgt_nid_count(struct mgs_nidtbl_target *tgt,
				      unsigned long netid)
{
	struct tnt_nidlist *tnl;
	void *xa_tnl;
	unsigned int nids_total = 0;

	if (netid == LNET_NET_ANY) {
		xa_for_each(&tgt->mnt_xa_nids, netid, xa_tnl) {
			tnl = xa_tnl;
			nids_total += tnl->tnl_count;
		}
	} else {
		/* only particular net */
		tnl = xa_load(&tgt->mnt_xa_nids, netid);
		if (tnl)
			nids_total += tnl->tnl_count;
	}
	return nids_total;
}

static int nidtbl_tnl2entry(struct mgs_nidtbl_entry *entry,
			    struct tnt_nidlist *tnl, unsigned int limit)
{
	unsigned int tail = limit - entry->mne_length;
	unsigned int count = tail / entry->mne_nid_size;
	int i, rc = 0;

	if (tnl->tnl_count > count) {
		CDEBUG(D_MGS,
		       "IR: only +%u NIDs (%u total) fits in unit size %u\n",
		       count, count + entry->mne_nid_count, limit);
		rc = -EOVERFLOW;
	} else {
		count = tnl->tnl_count;
	}

	for (i = 0; i < count; i++) {
		struct lnet_nid nid;
		int err;

		err = libcfs_strnid(&nid, tnl->tnl_nids[i]);
		if (err < 0) {
			CDEBUG(D_MGS, "IR: bad NID #%d in nidtbl: %s\n",
			       i, tnl->tnl_nids[i]);
			continue;
		}

		if (entry->mne_nid_type == 0) {
			if (!nid_is_nid4(&nid))
				continue;

			entry->u.nids[entry->mne_nid_count] =
						lnet_nid_to_nid4(&nid);
		} else {
			/* If the mgs_target_info NIDs are
			 * struct lnet_nid that have been
			 * expanded in size we still can
			 * use the nid if it fits in what
			 * the client supports.
			 */
			if (NID_BYTES(&nid) > entry->mne_nid_size)
				continue;
			entry->u.nidlist[entry->mne_nid_count] = nid;
		}
		entry->mne_nid_count++;
		entry->mne_length += entry->mne_nid_size;
	}

	return rc;
}

static int nidtbl_fill_entry(struct mgs_nidtbl_target *tgt,
			     struct mgs_nidtbl_entry *entry,
			     unsigned long netid, unsigned int limit)
{
	struct tnt_nidlist *tnl;
	void *xa_tnl;
	unsigned long xa_index;
	int rc = 0;

	/* fill in entry. */
	entry->mne_version = tgt->mnt_version;
	entry->mne_instance = tgt->mnt_instance;
	entry->mne_index = tgt->mnt_stripe_index;
	entry->mne_length = sizeof(*entry);
	entry->mne_type = tgt->mnt_type;
	entry->mne_nid_count = 0;

	if (netid == LNET_NET_ANY) {
		/* Without restrictions it gets all NIDs across all nets */
		xa_for_each(&tgt->mnt_xa_nids, xa_index, xa_tnl) {
			tnl = xa_tnl;
			CDEBUG(D_INFO, "IR: %u NIDs from NET #%lu\n",
			       tnl->tnl_count, xa_index);
			rc = nidtbl_tnl2entry(entry, tnl, limit);
			if (rc)
				break;
		}
	} else {
		xa_index = LNET_NETNUM(netid);
		/* only particular netid */
		tnl = xa_load(&tgt->mnt_xa_nids, xa_index);
		if (tnl) {
			CDEBUG(D_INFO, "IR: %u NIDs from NET #%lu\n",
			       tnl->tnl_count, xa_index);
			rc = nidtbl_tnl2entry(entry, tnl, limit);
		} else {
			CDEBUG(D_MGS, "IR: no NIDs for NET #%lu\n", xa_index);
		}
	}
	return rc;
}
/**
 * Fetch nidtbl entries whose version are not less than @version
 * nidtbl entries will be packed in @pages by @unit_size units - entries
 * shouldn't cross unit boundaries.
 */
static int mgs_nidtbl_read(struct obd_export *exp, struct mgs_nidtbl *tbl,
			   struct mgs_config_res *res, u8 nid_size,
			   struct page **pages, int nrpages,
			   int units_total, int unit_size)
{
	struct mgs_nidtbl_target *tgt;
	struct mgs_nidtbl_entry *entry;
	struct mgs_nidtbl_entry *last_in_unit = NULL;
	__u64 version = res->mcr_offset;
	unsigned long netid;
	unsigned int nid_count;
	bool nobuf = false;
	void *buf = NULL;
	void *kaddr = NULL;
	int bytes_in_unit = 0;
	int units_in_page = 0;
	int index = 0;
	int rc = 0;

	ENTRY;

	/* make sure unit_size is power 2 */
	LASSERT((unit_size & (unit_size - 1)) == 0);
	LASSERT(nrpages << PAGE_SHIFT >= units_total * unit_size);

	mutex_lock(&tbl->mn_lock);
	LASSERT(nidtbl_is_sane(tbl));

	/* no more entries ? */
	if (version > tbl->mn_version) {
		version = tbl->mn_version;
		goto out;
	}

	/*
	 * iterate over all targets to compose IR log entries.
	 */
	list_for_each_entry(tgt, &tbl->mn_targets, mnt_list) {
		int entry_len = sizeof(*entry);

		if (tgt->mnt_version < version)
			continue;

		/* Network filtering. Possibly can come from:
		 * - any server restriction policy NETs vs clients
		 * - any client supplied hints about its networks
		 * - network used by this request
		 * - etc.
		 */
		/* no filtering yet */
		netid = LNET_NET_ANY;
		nid_count = mgs_tgt_nid_count(tgt, netid);

		if (!nid_size)
			entry_len += nid_count * sizeof(lnet_nid_t);
		else
			entry_len += nid_count * nid_size;

		if (entry_len > unit_size) {
			CDEBUG(D_MGS,
			       "nidtbl: entry has %u NIDs, can't fit in %d\n",
			       nid_count, unit_size);
			/* return as many NIDs as can fit */
		}

		if (bytes_in_unit < entry_len) {
			if (units_total == 0) {
				nobuf = true;
				break;
			}

			/* check if we need to consume remaining bytes. */
			if (last_in_unit && bytes_in_unit) {
				last_in_unit->mne_length += bytes_in_unit;
				rc  += bytes_in_unit;
				buf += bytes_in_unit;
				last_in_unit = NULL;
			}
			LASSERT((rc & (unit_size - 1)) == 0);

			if (units_in_page == 0) {
				/* destroy previous map */
				if (kaddr) {
					kunmap_local(kaddr);
					kaddr = NULL;
				}
				/* allocate a new page */
				pages[index] = alloc_page(GFP_KERNEL);
				if (!pages[index]) {
					rc = -ENOMEM;
					break;
				}

				/* reassign buffer */
				buf = kaddr = kmap_local_page(pages[index]);
				++index;

				units_in_page = PAGE_SIZE / unit_size;
				LASSERT(units_in_page > 0);
			}

			/* allocate an unit */
			LASSERT(((long)buf & (unit_size - 1)) == 0);
			bytes_in_unit = unit_size;
			--units_in_page;
			--units_total;
		}

		/* fill in entry. */
		entry = (struct mgs_nidtbl_entry *)buf;
		if (nid_size) {
			entry->mne_nid_size = nid_size;
			entry->mne_nid_type = 1;
		} else {
			entry->mne_nid_size = sizeof(lnet_nid_t);
			entry->mne_nid_type = 0;
		}
		/* if no NIDs filled then emit error and continue
		 * with partial nidlist otherwise.
		 */
		nidtbl_fill_entry(tgt, entry, netid, bytes_in_unit);
		if (!entry->mne_nid_count) {
			rc = -EOVERFLOW;
			break;
		}
		entry_len = entry->mne_length;

		version = tgt->mnt_version;
		rc += entry_len;
		buf += entry_len;

		bytes_in_unit -= entry_len;
		last_in_unit = entry;

		CDEBUG(D_MGS, "fsname %s, entry size %d, pages %d/%d/%d/%d.\n",
		       tbl->mn_fsdb->fsdb_name, entry_len,
		       bytes_in_unit, index, nrpages, units_total);
	}
	if (kaddr)
		kunmap_local(kaddr);
out:
	LASSERT(version <= tbl->mn_version);
	res->mcr_size = tbl->mn_version;
	res->mcr_offset = nobuf ? version : tbl->mn_version;
	mutex_unlock(&tbl->mn_lock);

	CDEBUG(D_MGS, "Read IR logs %s return with %d, version %llu\n",
	       tbl->mn_fsdb->fsdb_name, rc, version);
	LASSERT(ergo(version == 1, rc <= 0)); /* get the log first time */

	RETURN(rc);
}

static int nidtbl_update_version(const struct lu_env *env,
				 struct mgs_device *mgs,
				 struct mgs_nidtbl *tbl)
{
	struct dt_object *fsdb;
	struct thandle *th;
	u64 version;
	struct lu_buf buf = {
			.lb_buf = &version,
			.lb_len = sizeof(version)
	};
	loff_t off = 0;
	int rc;

	ENTRY;

	if (mgs->mgs_bottom->dd_rdonly)
		RETURN(0);

	LASSERT(mutex_is_locked(&tbl->mn_lock));

	fsdb = local_file_find_or_create(env, mgs->mgs_los, mgs->mgs_nidtbl_dir,
					 tbl->mn_fsdb->fsdb_name,
					 S_IFREG | S_IRUGO | S_IWUSR);
	if (IS_ERR(fsdb))
		RETURN(PTR_ERR(fsdb));

	th = dt_trans_create(env, mgs->mgs_bottom);
	if (IS_ERR(th))
		GOTO(out_put, rc = PTR_ERR(th));

	th->th_sync = 1; /* update table synchronously */
	rc = dt_declare_record_write(env, fsdb, &buf, off, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, mgs->mgs_bottom, th);
	if (rc)
		GOTO(out, rc);

	version = cpu_to_le64(tbl->mn_version);
	rc = dt_record_write(env, fsdb, &buf, &off, th);

out:
	dt_trans_stop(env, mgs->mgs_bottom, th);
out_put:
	dt_object_put(env, fsdb);
	RETURN(rc);
}

#define MGS_NIDTBL_VERSION_INIT 2

static int nidtbl_read_version(const struct lu_env *env,
			       struct mgs_device *mgs, struct mgs_nidtbl *tbl,
			       u64 *version)
{
	struct dt_object *fsdb;
	struct lu_fid fid;
	u64 tmpver;
	struct lu_buf buf = {
		.lb_buf = &tmpver,
		.lb_len = sizeof(tmpver)
	};
	loff_t off = 0;
	int rc;

	ENTRY;

	LASSERT(mutex_is_locked(&tbl->mn_lock));

	LASSERT(mgs->mgs_nidtbl_dir);
	rc = dt_lookup_dir(env, mgs->mgs_nidtbl_dir, tbl->mn_fsdb->fsdb_name,
			   &fid);
	if (rc == -ENOENT) {
		*version = MGS_NIDTBL_VERSION_INIT;
		RETURN(0);
	} else if (rc < 0) {
		RETURN(rc);
	}

	fsdb = dt_locate_at(env, mgs->mgs_bottom, &fid,
			    &mgs->mgs_dt_dev.dd_lu_dev, NULL);
	if (IS_ERR(fsdb))
		RETURN(PTR_ERR(fsdb));

	rc = dt_read(env, fsdb, &buf, &off);
	if (rc == buf.lb_len) {
		*version = le64_to_cpu(tmpver);
		rc = 0;
	} else if (rc == 0) {
		*version = MGS_NIDTBL_VERSION_INIT;
	} else {
		CERROR("%s: read version file %s error %d\n",
		       mgs->mgs_obd->obd_name, tbl->mn_fsdb->fsdb_name, rc);
	}
	dt_object_put(env, fsdb);
	RETURN(rc);
}

/* Overwrite or append nidlist with new one */
static int mgs_tnl_update(struct mgs_nidtbl_target *tgt, unsigned long net,
			  struct mgs_target_info *mti, unsigned int mti_off,
			  unsigned int count)
{
	struct tnt_nidlist *tnl, *oldtnl;
	size_t newsize, oldsize = 0;
	unsigned int tnl_off = 0;
	int i, rc;

	if (net == LNET_NETNUM(LNET_NET_ANY))
		return 0;

	oldtnl = xa_load(&tgt->mnt_xa_nids, net);
	if (oldtnl) {
		oldsize = oldtnl->tnl_size;
		/* if version is the same then append case */
		if (oldtnl->tnl_version == tgt->mnt_version)
			tnl_off = oldtnl->tnl_count;
	}

	/* start with 4 slots as minumum */
	newsize = TNL_SIZE(max_t(unsigned int, tnl_off + count, 4));
	if (newsize > oldsize) {
		newsize = size_roundup_power2(newsize);
		OBD_ALLOC(tnl, newsize);
		if (!tnl) {
			rc = -ENOMEM;
			CERROR("%s: can't allocate nidlist, rc = %d\n",
			       mti->mti_svname, rc);
			return rc;
		}
		if (oldtnl && tnl_off) /* append case */
			memcpy(tnl, oldtnl, TNL_SIZE(oldtnl->tnl_count));
		tnl->tnl_size = newsize;
	} else {
		tnl = oldtnl;
	}

	CDEBUG(D_MGS, "nidtbl: %s %u NIDs to NET #%lu\n",
	       tnl_off ? "append" : "write", count, net);
	if (target_supports_large_nid(mti)) {
		memcpy(&tnl->tnl_nids[tnl_off], &mti->mti_nidlist[mti_off],
		       count * LNET_NIDSTR_SIZE);
	} else {
		for (i = 0; i < count; i++)
			libcfs_nid2str_r(mti->mti_nids[mti_off + i],
					 tnl->tnl_nids[tnl_off + i],
					 LNET_NIDSTR_SIZE);
	}
	tnl->tnl_count = tnl_off + count;
	tnl->tnl_version = tgt->mnt_version;

	if (tnl == oldtnl)
		return 0;

	oldtnl = xa_store(&tgt->mnt_xa_nids, net, tnl, GFP_KERNEL);
	rc = xa_err(oldtnl);
	if (rc) {
		CDEBUG(D_MGS, "nidtbl: can't store NET #%lu, rc = %d\n",
		       net, rc);
		/* free tnl and keep using oldtnl whatever it is */
		OBD_FREE(tnl, tnl->tnl_size);
	} else {
		OBD_FREE(oldtnl, oldtnl->tnl_size);
	}

	return rc;
}

static unsigned int mti_nidnet(struct mgs_target_info *mti, int i)
{
	struct lnet_nid nid;
	int rc;

	if (target_supports_large_nid(mti)) {
		rc = libcfs_strnid(&nid, mti->mti_nidlist[i]);
		if (rc)
			return LNET_NETNUM(LNET_NET_ANY);
	} else {
		lnet_nid4_to_nid(mti->mti_nids[i], &nid);
	}

	return LNET_NETNUM(LNET_NID_NET(&nid));
}

/**
 * parse incoming target info and update NID lists
 */
static int mgs_build_nidlists(struct mgs_nidtbl_target *tgt,
			      struct mgs_target_info *mti)
{
	unsigned long net;
	int i, rc = 0;

	/* Usually it is build on target on network basis, so assume that
	 * and search forward to find a sequence of nids at the same net
	 */
	i = 0;
	while (i < mti->mti_nid_count) {
		int cnt = 1;

		net = mti_nidnet(mti, i);
		while (i + cnt < mti->mti_nid_count &&
		       mti_nidnet(mti, i + cnt) == net)
			cnt++;
		rc = mgs_tnl_update(tgt, net, mti, i, cnt);
		if (rc)
			break;
		i += cnt;
	}
	return rc;
}

static int mgs_nidtbl_write(const struct lu_env *env, struct fs_db *fsdb,
			    struct mgs_target_info *mti)
{
	struct mgs_nidtbl *tbl;
	struct mgs_nidtbl_target *tgt;
	bool found = false;
	int type = mti->mti_flags & LDD_F_SV_TYPE_MASK;
	int rc = 0;

	ENTRY;
	type &= ~LDD_F_SV_TYPE_MGS;
	LASSERT(type != 0);

	tbl = &fsdb->fsdb_nidtbl;
	mutex_lock(&tbl->mn_lock);
	list_for_each_entry(tgt, &tbl->mn_targets, mnt_list) {
		if (type == tgt->mnt_type &&
		    mti->mti_stripe_index == tgt->mnt_stripe_index) {
			found = true;
			break;
		}
	}

	if (!found) {
		OBD_ALLOC_PTR(tgt);
		if (!tgt)
			GOTO(out, rc = -ENOMEM);

		INIT_LIST_HEAD(&tgt->mnt_list);
		tgt->mnt_fs = tbl;
		tgt->mnt_version = 0; /* 0 means invalid */
		tgt->mnt_type = type;

		tgt->mnt_stripe_index = mti->mti_stripe_index;
		xa_init(&tgt->mnt_xa_nids);
		++tbl->mn_nr_targets;
	}

	tgt->mnt_instance = mti->mti_instance;
	tgt->mnt_version = ++tbl->mn_version;

	list_move_tail(&tgt->mnt_list, &tbl->mn_targets);
	rc = mgs_build_nidlists(tgt, mti);
	if (rc)
		GOTO(out, rc);

	rc = nidtbl_update_version(env, fsdb->fsdb_mgs, tbl);
	EXIT;

out:
	mutex_unlock(&tbl->mn_lock);
	if (rc)
		CERROR("Write NID table version for file system %s error %d\n",
                       fsdb->fsdb_name, rc);
	return rc;
}

static void mgs_nidtbl_fini_fs(struct fs_db *fsdb)
{
	struct mgs_nidtbl *tbl = &fsdb->fsdb_nidtbl;
	LIST_HEAD(head);

	mutex_lock(&tbl->mn_lock);
	tbl->mn_nr_targets = 0;
	list_splice_init(&tbl->mn_targets, &head);
	mutex_unlock(&tbl->mn_lock);

	while (!list_empty(&head)) {
		struct mgs_nidtbl_target *tgt;
		unsigned long xa_index;
		void *xa_nids;

		tgt = list_first_entry(&head, struct mgs_nidtbl_target,
				       mnt_list);
		list_del(&tgt->mnt_list);
		xa_for_each(&tgt->mnt_xa_nids, xa_index, xa_nids) {
			struct tnt_nidlist *tnl = xa_nids;

			xa_erase(&tgt->mnt_xa_nids, xa_index);
			OBD_FREE(tnl, tnl->tnl_size);
		}

		xa_destroy(&tgt->mnt_xa_nids);
		OBD_FREE_PTR(tgt);
	}
}

static int mgs_nidtbl_init_fs(const struct lu_env *env, struct fs_db *fsdb)
{
	struct mgs_nidtbl *tbl = &fsdb->fsdb_nidtbl;
	int rc;

	INIT_LIST_HEAD(&tbl->mn_targets);
	mutex_init(&tbl->mn_lock);
	tbl->mn_nr_targets = 0;
	tbl->mn_fsdb = fsdb;
	mutex_lock(&tbl->mn_lock);
	rc = nidtbl_read_version(env, fsdb->fsdb_mgs, tbl, &tbl->mn_version);
	mutex_unlock(&tbl->mn_lock);
	if (rc < 0)
		CERROR("%s: IR: failed to read current version, rc = %d\n",
		       fsdb->fsdb_mgs->mgs_obd->obd_name, rc);
	else
		CDEBUG(D_MGS, "IR: current version is %llu\n",
		       tbl->mn_version);

	return rc;
}

/* --------- Imperative Recovery relies on nidtbl stuff ------- */
void mgs_ir_notify_complete(struct fs_db *fsdb)
{
	struct timespec64 ts;
	ktime_t delta;

	atomic_set(&fsdb->fsdb_notify_phase, 0);

	/* do statistic */
	fsdb->fsdb_notify_count++;
	delta = ktime_sub(ktime_get(), fsdb->fsdb_notify_start);
	fsdb->fsdb_notify_total = ktime_add(fsdb->fsdb_notify_total, delta);
	if (ktime_after(delta, fsdb->fsdb_notify_max))
		fsdb->fsdb_notify_max = delta;

	ts = ktime_to_timespec64(fsdb->fsdb_notify_max);
	CDEBUG(D_MGS, "Revoke recover lock of %s completed after %lld.%09lds\n",
	       fsdb->fsdb_name, (s64)ts.tv_sec, ts.tv_nsec);
}

static int mgs_ir_notify(void *arg)
{
	struct fs_db *fsdb = arg;
	struct ldlm_res_id resid;
	char name[sizeof(fsdb->fsdb_name) + 16];

	BUILD_BUG_ON(sizeof(name) >= 40); /* name is too large to be on stack */

	snprintf(name, sizeof(name) - 1, "mgs_%s_notify", fsdb->fsdb_name);
	complete(&fsdb->fsdb_notify_comp);
	set_user_nice(current, -2);
	mgc_fsname2resid(fsdb->fsdb_name, &resid, MGS_CFG_T_RECOVER);
	while (1) {
		wait_event_idle(fsdb->fsdb_notify_waitq,
				fsdb->fsdb_notify_stop ||
				atomic_read(&fsdb->fsdb_notify_phase));

		if (fsdb->fsdb_notify_stop)
			break;

		CDEBUG(D_MGS, "%s woken up, phase is %d\n",
		       name, atomic_read(&fsdb->fsdb_notify_phase));

		fsdb->fsdb_notify_start = ktime_get();
		mgs_revoke_lock(fsdb->fsdb_mgs, fsdb, MGS_CFG_T_RECOVER);
	}

	complete(&fsdb->fsdb_notify_comp);
	return 0;
}

int mgs_ir_init_fs(const struct lu_env *env, struct mgs_device *mgs,
		   struct fs_db *fsdb)
{
	struct task_struct *task;

	if (!ir_timeout)
		ir_timeout = (time64_t)OBD_IR_MGS_TIMEOUT;

	fsdb->fsdb_ir_state = IR_FULL;
	if (mgs->mgs_start_time + ir_timeout > ktime_get_real_seconds())
		fsdb->fsdb_ir_state = IR_STARTUP;
	fsdb->fsdb_nonir_clients = 0;
	/* start notify thread */
	fsdb->fsdb_mgs = mgs;
	task = kthread_run(mgs_ir_notify, fsdb,
			       "mgs_%s_notify", fsdb->fsdb_name);
	if (!IS_ERR(task))
		wait_for_completion(&fsdb->fsdb_notify_comp);
	else
		CERROR("Start notify thread error %ld\n", PTR_ERR(task));

	mgs_nidtbl_init_fs(env, fsdb);
	return 0;
}

void mgs_ir_fini_fs(struct mgs_device *mgs, struct fs_db *fsdb)
{
	if (test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags))
		return;

	mgs_fsc_cleanup_by_fsdb(fsdb);

	mgs_nidtbl_fini_fs(fsdb);

	LASSERT(list_empty(&fsdb->fsdb_clients));

	fsdb->fsdb_notify_stop = 1;
	wake_up(&fsdb->fsdb_notify_waitq);
	wait_for_completion(&fsdb->fsdb_notify_comp);
}

/* caller must have held fsdb_mutex */
static inline void ir_state_graduate(struct fs_db *fsdb)
{
	if (fsdb->fsdb_ir_state == IR_STARTUP) {
		if (ktime_get_real_seconds() >
		    fsdb->fsdb_mgs->mgs_start_time + ir_timeout) {
			fsdb->fsdb_ir_state = IR_FULL;
			if (fsdb->fsdb_nonir_clients)
				fsdb->fsdb_ir_state = IR_PARTIAL;
		}
	}
}

int mgs_ir_update(const struct lu_env *env, struct mgs_device *mgs,
		  struct mgs_target_info *mti)
{
	struct fs_db *fsdb;
	bool notify = true;
	int rc;

	if (mti->mti_instance == 0)
		return -EINVAL;

	rc = mgs_find_or_make_fsdb(env, mgs, mti->mti_fsname, &fsdb);
	if (rc)
		return rc;

	rc = mgs_nidtbl_write(env, fsdb, mti);
	if (rc)
		GOTO(out, rc);

	/* check ir state */
	mutex_lock(&fsdb->fsdb_mutex);
	ir_state_graduate(fsdb);
	switch (fsdb->fsdb_ir_state) {
	case IR_FULL:
		mti->mti_flags |= LDD_F_IR_CAPABLE;
		break;
	case IR_DISABLED:
		notify = false;
		fallthrough;
	case IR_STARTUP:
	case IR_PARTIAL:
		break;
	default:
		LBUG();
	}
	mutex_unlock(&fsdb->fsdb_mutex);

	LASSERT(ergo(mti->mti_flags & LDD_F_IR_CAPABLE, notify));
	if (notify) {
		CDEBUG(D_MGS, "Try to revoke recover lock of %s\n",
		       fsdb->fsdb_name);
		atomic_inc(&fsdb->fsdb_notify_phase);
		wake_up(&fsdb->fsdb_notify_waitq);
	}

out:
	mgs_put_fsdb(mgs, fsdb);
	return rc;
}

/* NID table can be cached by two entities: Clients and MDTs */
enum {
	IR_CLIENT  = 1,
	IR_MDT     = 2
};

static int delogname(char *logname, char *fsname, int *typ)
{
	char *ptr;
	int type;
	int len;

	ptr = strrchr(logname, '-');
	if (!ptr)
		return -EINVAL;

	/*
	 * decouple file system name. The llog name may be:
	 * - "prefix-fsname", prefix is "cliir" or "mdtir"
	 */
	if (strncmp(ptr, "-mdtir", 6) == 0)
		type = IR_MDT;
	else if (strncmp(ptr, "-cliir", 6) == 0)
		type = IR_CLIENT;
	else
		return -EINVAL;

	len = ptr - logname;
	if (len == 0)
		return -EINVAL;

	memcpy(fsname, logname, len);
	fsname[len] = 0;
	if (typ)
		*typ = type;
	return 0;
}

int mgs_get_ir_logs(struct ptlrpc_request *req)
{
	struct lu_env *env = req->rq_svc_thread->t_env;
	struct mgs_device *mgs = exp2mgs_dev(req->rq_export);
	struct fs_db *fsdb = NULL;
	struct mgs_config_body *body;
	struct mgs_config_res *res;
	struct ptlrpc_bulk_desc *desc;
	char fsname[16];
	long bufsize;
	int unit_size;
	int type;
	int rc = 0;
	int i;
	int bytes;
	int page_count;
	int nrpages;
	struct page **pages = NULL;

	ENTRY;

	body = req_capsule_client_get(&req->rq_pill, &RMF_MGS_CONFIG_BODY);
	if (!body)
		RETURN(-EINVAL);

	if (body->mcb_type != MGS_CFG_T_RECOVER)
		RETURN(-EINVAL);

	rc = delogname(body->mcb_name, fsname, &type);
	if (rc)
		RETURN(rc);

	bufsize = body->mcb_units << body->mcb_bits;
	nrpages = (bufsize + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (nrpages > PTLRPC_MAX_BRW_PAGES)
		RETURN(-EINVAL);

	rc = mgs_find_or_make_fsdb(env, mgs, fsname, &fsdb);
	if (rc)
		RETURN(rc);

	CDEBUG(D_MGS, "Reading IR log %s bufsize %ld.\n",
	       body->mcb_name, bufsize);

	OBD_ALLOC_PTR_ARRAY_LARGE(pages, nrpages);
	if (!pages)
		GOTO(out, rc = -ENOMEM);

	res = req_capsule_server_get(&req->rq_pill, &RMF_MGS_CONFIG_RES);
	if (!res)
		GOTO(out, rc = -EINVAL);

	res->mcr_offset = body->mcb_offset;
	unit_size = min_t(int, 1 << body->mcb_bits, PAGE_SIZE);
	bytes = mgs_nidtbl_read(req->rq_export, &fsdb->fsdb_nidtbl, res,
				body->mcb_rec_nid_size, pages, nrpages,
				bufsize / unit_size, unit_size);
	if (bytes < 0)
		GOTO(out, rc = bytes);

	/* start bulk transfer */
	page_count = (bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
	LASSERT(page_count <= nrpages);
	desc = ptlrpc_prep_bulk_exp(req, page_count, 1,
				    PTLRPC_BULK_PUT_SOURCE,
				    MGS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_pin_ops);
	if (!desc)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < page_count && bytes > 0; i++) {
		desc->bd_frag_ops->add_kiov_frag(desc, pages[i], 0,
						 min_t(int, bytes,
						      PAGE_SIZE));
		bytes -= PAGE_SIZE;
	}

	rc = target_bulk_io(req->rq_export, desc);
	ptlrpc_free_bulk(desc);

	GOTO(out, rc);

out:
	if (pages) {
		for (i = 0; i < nrpages; i++) {
			if (!pages[i])
				break;

			__free_page(pages[i]);
		}

		OBD_FREE_PTR_ARRAY_LARGE(pages, nrpages);
	}

	if (fsdb)
		mgs_put_fsdb(mgs, fsdb);

	return rc;
}

static int lprocfs_ir_set_state(struct fs_db *fsdb, const char *buf)
{
	const char *const strings[] = IR_STRINGS;
	int state = -1;
	int i;

	for (i = 0; i < ARRAY_SIZE(strings); i++) {
		if (strcmp(strings[i], buf) == 0) {
			state = i;
			break;
		}
	}
	if (state < 0)
		return -EINVAL;

	CDEBUG(D_MGS, "change fsr state of %s from %s to %s\n",
	       fsdb->fsdb_name, strings[fsdb->fsdb_ir_state], strings[state]);
	mutex_lock(&fsdb->fsdb_mutex);
	if (state == IR_FULL && fsdb->fsdb_nonir_clients)
		state = IR_PARTIAL;
	fsdb->fsdb_ir_state = state;
	mutex_unlock(&fsdb->fsdb_mutex);

	return 0;
}

static int lprocfs_ir_set_timeout(struct fs_db *fsdb, const char *buf)
{
	return -EINVAL;
}

static int lprocfs_ir_clear_stats(struct fs_db *fsdb, const char *buf)
{
	if (*buf)
		return -EINVAL;

	fsdb->fsdb_notify_total = ktime_set(0, 0);
	fsdb->fsdb_notify_max = ktime_set(0, 0);
	fsdb->fsdb_notify_count = 0;
	return 0;
}

static struct lproc_ir_cmd {
	char *name;
	int namelen;
	int (*handler)(struct fs_db *, const char *);
} ir_cmds[] = {
	{ "state=",   6, lprocfs_ir_set_state },
	{ "timeout=", 8, lprocfs_ir_set_timeout },
	{ "0",        1, lprocfs_ir_clear_stats }
};

int lprocfs_wr_ir_state(struct file *file, const char __user *buffer,
			size_t count, void *data)
{
	struct fs_db *fsdb = data;
	char *kbuf;
	char *ptr;
	int rc = 0;

	if (count == 0 || count >= PAGE_SIZE)
		return -EINVAL;

	OBD_ALLOC(kbuf, count + 1);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buffer, count)) {
		OBD_FREE(kbuf, count + 1);
		return -EFAULT;
	}

	kbuf[count] = 0; /* buffer is supposed to end with 0 */
	if (kbuf[count - 1] == '\n')
		kbuf[count - 1] = 0;
	ptr = kbuf;

	/* fsname=<file system name> must be the 1st entry */
	while (ptr) {
		char *tmpptr;
		int i;

		tmpptr = strchr(ptr, ';');
		if (tmpptr)
			*tmpptr++ = 0;

		rc = -EINVAL;
		for (i = 0; i < ARRAY_SIZE(ir_cmds); i++) {
			struct lproc_ir_cmd *cmd;
			int cmdlen;

			cmd    = &ir_cmds[i];
			cmdlen = cmd->namelen;
			if (strncmp(cmd->name, ptr, cmdlen) == 0) {
				ptr += cmdlen;
                                rc = cmd->handler(fsdb, ptr);
                                break;
			}
		}
		if (rc)
			break;

		ptr = tmpptr;
	}
	if (rc)
		CERROR("Unable to process command: %s(%d)\n", ptr, rc);
	OBD_FREE(kbuf, count + 1);
	return rc ?: count;
}

int lprocfs_rd_ir_state(struct seq_file *seq, void *data)
{
	struct fs_db *fsdb = data;
	struct mgs_nidtbl *tbl = &fsdb->fsdb_nidtbl;
	const char *const ir_strings[] = IR_STRINGS;
	struct timespec64 ts_max;
	struct timespec64 ts;

	/* mgs_live_seq_show() already holds fsdb_mutex. */
	ir_state_graduate(fsdb);

	seq_printf(seq, "\nimperative_recovery_state:\n");
	seq_printf(seq,
		   "    state: %s\n"
		   "    nonir_clients: %d\n"
		   "    nidtbl_version: %lld\n",
		   ir_strings[fsdb->fsdb_ir_state], fsdb->fsdb_nonir_clients,
		   tbl->mn_version);

	ts = ktime_to_timespec64(fsdb->fsdb_notify_total);
	ts_max = ktime_to_timespec64(fsdb->fsdb_notify_max);

	seq_printf(seq, "    notify_duration_total: %lld.%09ld\n"
			"    notify_duation_max: %lld.%09ld\n"
			"    notify_count: %u\n",
		   (s64)ts.tv_sec, ts.tv_nsec,
		   (s64)ts_max.tv_sec, ts_max.tv_nsec,
		   fsdb->fsdb_notify_count);

	return 0;
}

int lprocfs_ir_timeout_seq_show(struct seq_file *m, void *data)
{
	seq_printf(m, "%lld\n", ir_timeout);
	return 0;
}

ssize_t lprocfs_ir_timeout_seq_write(struct file *file,
				     const char __user *buffer,
				     size_t count, loff_t *off)
{
	return kstrtoll_from_user(buffer, count, 0, &ir_timeout);
}

/* --------------- Handle non IR support clients --------------- */
/* attach a lustre file system to an export */
int mgs_fsc_attach(const struct lu_env *env, struct obd_export *exp,
		   char *fsname)
{
	struct mgs_export_data *data = &exp->u.eu_mgs_data;
	struct mgs_device *mgs = exp2mgs_dev(exp);
	struct fs_db *fsdb = NULL;
	struct mgs_fsc *fsc = NULL;
	struct mgs_fsc *new_fsc = NULL;
	bool found = false;
	int rc;

	ENTRY;

	rc = mgs_find_or_make_fsdb(env, mgs, fsname, &fsdb);
	if (rc)
		RETURN(rc);

	/* allocate a new fsc in case we need it in spinlock. */
	OBD_ALLOC_PTR(new_fsc);
	if (!new_fsc)
		GOTO(out, rc = -ENOMEM);

	INIT_LIST_HEAD(&new_fsc->mfc_export_list);
	INIT_LIST_HEAD(&new_fsc->mfc_fsdb_list);
	new_fsc->mfc_fsdb       = fsdb;
	new_fsc->mfc_export     = class_export_get(exp);
	new_fsc->mfc_ir_capable = !!(exp_connect_flags(exp) &
				     OBD_CONNECT_IMP_RECOV);

	rc = -EEXIST;
	mutex_lock(&fsdb->fsdb_mutex);

	/* tend to find it in export list because this list is shorter. */
	spin_lock(&data->med_lock);
	list_for_each_entry(fsc, &data->med_clients, mfc_export_list) {
		if (strcmp(fsname, fsc->mfc_fsdb->fsdb_name) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		fsc = new_fsc;
		new_fsc = NULL;

		/* add it into export list. */
		list_add(&fsc->mfc_export_list, &data->med_clients);

		/* add into fsdb list. */
		list_add(&fsc->mfc_fsdb_list, &fsdb->fsdb_clients);
		if (!fsc->mfc_ir_capable) {
			++fsdb->fsdb_nonir_clients;
			if (fsdb->fsdb_ir_state == IR_FULL)
				fsdb->fsdb_ir_state = IR_PARTIAL;
		}
		rc = 0;
	}
	spin_unlock(&data->med_lock);
	mutex_unlock(&fsdb->fsdb_mutex);

	if (new_fsc) {
		class_export_put(new_fsc->mfc_export);
		OBD_FREE_PTR(new_fsc);
	}

out:
	mgs_put_fsdb(mgs, fsdb);
	RETURN(rc);
}

void mgs_fsc_cleanup(struct obd_export *exp)
{
	struct mgs_export_data *data = &exp->u.eu_mgs_data;
	struct mgs_fsc *fsc, *tmp;
	LIST_HEAD(head);

	spin_lock(&data->med_lock);
	list_splice_init(&data->med_clients, &head);
	spin_unlock(&data->med_lock);

	list_for_each_entry_safe(fsc, tmp, &head, mfc_export_list) {
		struct fs_db *fsdb = fsc->mfc_fsdb;

		LASSERT(fsc->mfc_export == exp);

		mutex_lock(&fsdb->fsdb_mutex);
		list_del_init(&fsc->mfc_fsdb_list);
		if (fsc->mfc_ir_capable == 0) {
			--fsdb->fsdb_nonir_clients;
			LASSERT(fsdb->fsdb_ir_state != IR_FULL);
			if (fsdb->fsdb_nonir_clients == 0 &&
			    fsdb->fsdb_ir_state == IR_PARTIAL)
				fsdb->fsdb_ir_state = IR_FULL;
		}
		mutex_unlock(&fsdb->fsdb_mutex);
		list_del_init(&fsc->mfc_export_list);
		class_export_put(fsc->mfc_export);
		OBD_FREE_PTR(fsc);
	}
}

/* must be called with fsdb->fsdb_mutex held */
void mgs_fsc_cleanup_by_fsdb(struct fs_db *fsdb)
{
	struct mgs_fsc *fsc, *tmp;

	list_for_each_entry_safe(fsc, tmp, &fsdb->fsdb_clients,
                                     mfc_fsdb_list) {
		struct mgs_export_data *data = &fsc->mfc_export->u.eu_mgs_data;

		LASSERT(fsdb == fsc->mfc_fsdb);
		list_del_init(&fsc->mfc_fsdb_list);

		spin_lock(&data->med_lock);
		list_del_init(&fsc->mfc_export_list);
		spin_unlock(&data->med_lock);
		class_export_put(fsc->mfc_export);
		OBD_FREE_PTR(fsc);
	}

	fsdb->fsdb_nonir_clients = 0;
	if (fsdb->fsdb_ir_state == IR_PARTIAL)
		fsdb->fsdb_ir_state = IR_FULL;
}
