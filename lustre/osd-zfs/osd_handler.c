/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, 2013, Intel Corporation.
 * Use is subject to license terms.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/osd_handler.c
 * Top-level entry points into osd module
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 * Author: Johann Lombardi <johann@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <lustre_ver.h>
#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lustre_param.h>
#include <md_object.h>

#include "osd_internal.h"

#include <sys/dnode.h>
#include <sys/dbuf.h>
#include <sys/spa.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa_impl.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_tx.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_prop.h>
#include <sys/sa_impl.h>
#include <sys/txg.h>

struct lu_context_key	osd_key;

static char *root_tag = "osd_mount, rootdb";

/* Slab for OSD object allocation */
struct kmem_cache *osd_object_kmem;

static struct lu_kmem_descr osd_caches[] = {
	{
		.ckd_cache = &osd_object_kmem,
		.ckd_name  = "zfs_osd_obj",
		.ckd_size  = sizeof(struct osd_object)
	},
	{
		.ckd_cache = NULL
	}
};

static void arc_prune_func(int64_t bytes, void *private)
{
	struct osd_device *od = private;
	struct lu_site    *site = &od->od_site;
	struct lu_env      env;
	int rc;

	rc = lu_env_init(&env, LCT_SHRINKER);
	if (rc) {
		CERROR("%s: can't initialize shrinker env: rc = %d\n",
		       od->od_svname, rc);
		return;
	}

	lu_site_purge(&env, site, (bytes >> 10));

	lu_env_fini(&env);
}

/*
 * Concurrency: doesn't access mutable data
 */
static int osd_root_get(const struct lu_env *env,
			struct dt_device *dev, struct lu_fid *f)
{
	lu_local_obj_fid(f, OSD_FS_ROOT_OID);
	return 0;
}

/*
 * OSD object methods.
 */

/*
 * Concurrency: shouldn't matter.
 */
static void osd_trans_commit_cb(void *cb_data, int error)
{
	struct osd_thandle	*oh = cb_data;
	struct thandle		*th = &oh->ot_super;
	struct osd_device	*osd = osd_dt_dev(th->th_dev);
	struct lu_device	*lud = &th->th_dev->dd_lu_dev;
	struct dt_txn_commit_cb	*dcb, *tmp;

	ENTRY;

	if (error) {
		if (error == ECANCELED)
			CWARN("%s: transaction @0x%p was aborted\n",
			      osd_dt_dev(th->th_dev)->od_svname, th);
		else
			CERROR("%s: transaction @0x%p commit error: rc = %d\n",
				osd_dt_dev(th->th_dev)->od_svname, th, error);
	}

	dt_txn_hook_commit(th);

	/* call per-transaction callbacks if any */
	cfs_list_for_each_entry_safe(dcb, tmp, &oh->ot_dcb_list, dcb_linkage)
		dcb->dcb_func(NULL, th, dcb, error);

	/* Unlike ldiskfs, zfs updates space accounting at commit time.
	 * As a consequence, op_end is called only now to inform the quota slave
	 * component that reserved quota space is now accounted in usage and
	 * should be released. Quota space won't be adjusted at this point since
	 * we can't provide a suitable environment. It will be performed
	 * asynchronously by a lquota thread. */
	qsd_op_end(NULL, osd->od_quota_slave, &oh->ot_quota_trans);

	lu_device_put(lud);
	th->th_dev = NULL;
	lu_context_exit(&th->th_ctx);
	lu_context_fini(&th->th_ctx);
	OBD_FREE_PTR(oh);

	EXIT;
}

static int osd_trans_cb_add(struct thandle *th, struct dt_txn_commit_cb *dcb)
{
	struct osd_thandle *oh;

	oh = container_of0(th, struct osd_thandle, ot_super);
	cfs_list_add(&dcb->dcb_linkage, &oh->ot_dcb_list);

	return 0;
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_trans_start(const struct lu_env *env, struct dt_device *d,
			   struct thandle *th)
{
	struct osd_thandle	*oh;
	int			rc;
	ENTRY;

	oh = container_of0(th, struct osd_thandle, ot_super);
	LASSERT(oh);
	LASSERT(oh->ot_tx);

	rc = dt_txn_hook_start(env, d, th);
	if (rc != 0)
		RETURN(rc);

	if (oh->ot_write_commit && OBD_FAIL_CHECK(OBD_FAIL_OST_MAPBLK_ENOSPC))
		/* Unlike ldiskfs, ZFS checks for available space and returns
		 * -ENOSPC when assigning txg */
		RETURN(-ENOSPC);

	rc = -dmu_tx_assign(oh->ot_tx, TXG_WAIT);
	if (unlikely(rc != 0)) {
		struct osd_device *osd = osd_dt_dev(d);
		/* dmu will call commit callback with error code during abort */
		if (!lu_device_is_md(&d->dd_lu_dev) && rc == -ENOSPC)
			CERROR("%s: failed to start transaction due to ENOSPC. "
			       "Metadata overhead is underestimated or "
			       "grant_ratio is too low.\n", osd->od_svname);
		else
			CERROR("%s: can't assign tx: rc = %d\n",
			       osd->od_svname, rc);
	} else {
		/* add commit callback */
		dmu_tx_callback_register(oh->ot_tx, osd_trans_commit_cb, oh);
		oh->ot_assigned = 1;
		lu_context_init(&th->th_ctx, th->th_tags);
		lu_context_enter(&th->th_ctx);
		lu_device_get(&d->dd_lu_dev);
	}

	RETURN(rc);
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_trans_stop(const struct lu_env *env, struct thandle *th)
{
	struct osd_device	*osd = osd_dt_dev(th->th_dev);
	struct osd_thandle	*oh;
	uint64_t		 txg;
	int			 rc;
	ENTRY;

	oh = container_of0(th, struct osd_thandle, ot_super);

	if (oh->ot_assigned == 0) {
		LASSERT(oh->ot_tx);
		dmu_tx_abort(oh->ot_tx);
		osd_object_sa_dirty_rele(oh);
		/* there won't be any commit, release reserved quota space now,
		 * if any */
		qsd_op_end(env, osd->od_quota_slave, &oh->ot_quota_trans);
		OBD_FREE_PTR(oh);
		RETURN(0);
	}

	/* When doing our own inode accounting, the ZAPs storing per-uid/gid
	 * usage are updated at operation execution time, so we should call
	 * qsd_op_end() straight away. Otherwise (for blk accounting maintained
	 * by ZFS and when #inode is estimated from #blks) accounting is updated
	 * at commit time and the call to qsd_op_end() must be delayed */
	if (oh->ot_quota_trans.lqt_id_cnt > 0 &&
			!oh->ot_quota_trans.lqt_ids[0].lqi_is_blk &&
			!osd->od_quota_iused_est)
		qsd_op_end(env, osd->od_quota_slave, &oh->ot_quota_trans);

	rc = dt_txn_hook_stop(env, th);
	if (rc != 0)
		CDEBUG(D_OTHER, "%s: transaction hook failed: rc = %d\n",
		       osd->od_svname, rc);

	LASSERT(oh->ot_tx);
	txg = oh->ot_tx->tx_txg;

	osd_object_sa_dirty_rele(oh);
	dmu_tx_commit(oh->ot_tx);

	if (th->th_sync)
		txg_wait_synced(dmu_objset_pool(osd->od_objset.os), txg);

	RETURN(rc);
}

static struct thandle *osd_trans_create(const struct lu_env *env,
					struct dt_device *dt)
{
	struct osd_device	*osd = osd_dt_dev(dt);
	struct osd_thandle	*oh;
	struct thandle		*th;
	dmu_tx_t		*tx;
	ENTRY;

	tx = dmu_tx_create(osd->od_objset.os);
	if (tx == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* alloc callback data */
	OBD_ALLOC_PTR(oh);
	if (oh == NULL) {
		dmu_tx_abort(tx);
		RETURN(ERR_PTR(-ENOMEM));
	}

	oh->ot_tx = tx;
	CFS_INIT_LIST_HEAD(&oh->ot_dcb_list);
	CFS_INIT_LIST_HEAD(&oh->ot_sa_list);
	sema_init(&oh->ot_sa_lock, 1);
	memset(&oh->ot_quota_trans, 0, sizeof(oh->ot_quota_trans));
	th = &oh->ot_super;
	th->th_dev = dt;
	th->th_result = 0;
	th->th_tags = LCT_TX_HANDLE;
	RETURN(th);
}

/*
 * Concurrency: shouldn't matter.
 */
int osd_statfs(const struct lu_env *env, struct dt_device *d,
	       struct obd_statfs *osfs)
{
	struct osd_device *osd = osd_dt_dev(d);
	int		   rc;
	ENTRY;

	rc = udmu_objset_statfs(&osd->od_objset, osfs);
	if (unlikely(rc))
		RETURN(rc);
	osfs->os_bavail -= min_t(obd_size,
				 OSD_GRANT_FOR_LOCAL_OIDS / osfs->os_bsize,
				 osfs->os_bavail);
	RETURN(0);
}

/*
 * Concurrency: doesn't access mutable data.
 */
static void osd_conf_get(const struct lu_env *env,
			 const struct dt_device *dev,
			 struct dt_device_param *param)
{
	struct osd_device *osd = osd_dt_dev(dev);

	/*
	 * XXX should be taken from not-yet-existing fs abstraction layer.
	 */
	param->ddp_max_name_len	= MAXNAMELEN;
	param->ddp_max_nlink	= 1 << 31; /* it's 8byte on a disk */
	param->ddp_block_shift	= 12; /* XXX */
	param->ddp_mount_type	= LDD_MT_ZFS;

	param->ddp_mntopts	= MNTOPT_USERXATTR;
	if (osd->od_posix_acl)
		param->ddp_mntopts |= MNTOPT_ACL;
	param->ddp_max_ea_size	= DXATTR_MAX_ENTRY_SIZE;

	/* for maxbytes, report same value as ZPL */
	param->ddp_maxbytes	= MAX_LFS_FILESIZE;

	/* Default reserved fraction of the available space that should be kept
	 * for error margin. Unfortunately, there are many factors that can
	 * impact the overhead with zfs, so let's be very cautious for now and
	 * reserve 20% of the available space which is not given out as grant.
	 * This tunable can be changed on a live system via procfs if needed. */
	param->ddp_grant_reserved = 20;

	/* inodes are dynamically allocated, so we report the per-inode space
	 * consumption to upper layers. This static value is not really accurate
	 * and we should use the same logic as in udmu_objset_statfs() to
	 * estimate the real size consumed by an object */
	param->ddp_inodespace = OSD_DNODE_EST_COUNT;
	/* per-fragment overhead to be used by the client code */
	param->ddp_grant_frag = udmu_blk_insert_cost();
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_sync(const struct lu_env *env, struct dt_device *d)
{
	struct osd_device  *osd = osd_dt_dev(d);
	CDEBUG(D_HA, "syncing OSD %s\n", LUSTRE_OSD_ZFS_NAME);
	txg_wait_synced(dmu_objset_pool(osd->od_objset.os), 0ULL);
	return 0;
}

static int osd_commit_async(const struct lu_env *env, struct dt_device *dev)
{
	struct osd_device *osd = osd_dt_dev(dev);
	tx_state_t	  *tx = &dmu_objset_pool(osd->od_objset.os)->dp_tx;
	uint64_t	   txg;

	mutex_enter(&tx->tx_sync_lock);
	txg = tx->tx_open_txg + 1;
	if (tx->tx_quiesce_txg_waiting < txg) {
		tx->tx_quiesce_txg_waiting = txg;
		cv_broadcast(&tx->tx_quiesce_more_cv);
	}
	mutex_exit(&tx->tx_sync_lock);

	return 0;
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_ro(const struct lu_env *env, struct dt_device *d)
{
	struct osd_device  *osd = osd_dt_dev(d);
	ENTRY;

	CERROR("%s: *** setting device %s read-only ***\n",
	       osd->od_svname, LUSTRE_OSD_ZFS_NAME);
	osd->od_rdonly = 1;
	spa_freeze(dmu_objset_spa(osd->od_objset.os));

	RETURN(0);
}

/*
 * Concurrency: serialization provided by callers.
 */
static int osd_init_capa_ctxt(const struct lu_env *env, struct dt_device *d,
			      int mode, unsigned long timeout, __u32 alg,
			      struct lustre_capa_key *keys)
{
	struct osd_device *dev = osd_dt_dev(d);
	ENTRY;

	dev->od_fl_capa = mode;
	dev->od_capa_timeout = timeout;
	dev->od_capa_alg = alg;
	dev->od_capa_keys = keys;

	RETURN(0);
}

static struct dt_device_operations osd_dt_ops = {
	.dt_root_get		= osd_root_get,
	.dt_statfs		= osd_statfs,
	.dt_trans_create	= osd_trans_create,
	.dt_trans_start		= osd_trans_start,
	.dt_trans_stop		= osd_trans_stop,
	.dt_trans_cb_add	= osd_trans_cb_add,
	.dt_conf_get		= osd_conf_get,
	.dt_sync		= osd_sync,
	.dt_commit_async	= osd_commit_async,
	.dt_ro			= osd_ro,
	.dt_init_capa_ctxt	= osd_init_capa_ctxt,
};

/*
 * DMU OSD device type methods
 */
static int osd_type_init(struct lu_device_type *t)
{
	LU_CONTEXT_KEY_INIT(&osd_key);
	return lu_context_key_register(&osd_key);
}

static void osd_type_fini(struct lu_device_type *t)
{
	lu_context_key_degister(&osd_key);
}

static void *osd_key_init(const struct lu_context *ctx,
			  struct lu_context_key *key)
{
	struct osd_thread_info *info;

	OBD_ALLOC_PTR(info);
	if (info != NULL)
		info->oti_env = container_of(ctx, struct lu_env, le_ctx);
	else
		info = ERR_PTR(-ENOMEM);
	return info;
}

static void osd_key_fini(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct osd_thread_info *info = data;

	OBD_FREE_PTR(info);
}

static void osd_key_exit(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct osd_thread_info *info = data;

	memset(info, 0, sizeof(*info));
}

struct lu_context_key osd_key = {
	.lct_tags = LCT_DT_THREAD | LCT_MD_THREAD | LCT_MG_THREAD | LCT_LOCAL,
	.lct_init = osd_key_init,
	.lct_fini = osd_key_fini,
	.lct_exit = osd_key_exit
};

static int osd_shutdown(const struct lu_env *env, struct osd_device *o)
{
	ENTRY;

	/* shutdown quota slave instance associated with the device */
	if (o->od_quota_slave != NULL) {
		qsd_fini(env, o->od_quota_slave);
		o->od_quota_slave = NULL;
	}

	RETURN(0);
}

static void osd_xattr_changed_cb(void *arg, uint64_t newval)
{
	struct osd_device *osd = arg;

	osd->od_xattr_in_sa = (newval == ZFS_XATTR_SA);
}

static int osd_mount(const struct lu_env *env,
		     struct osd_device *o, struct lustre_cfg *cfg)
{
	struct dsl_dataset	*ds;
	char			*dev  = lustre_cfg_string(cfg, 1);
	dmu_buf_t		*rootdb;
	dsl_pool_t		*dp;
	const char		*opts;
	int			 rc;
	ENTRY;

	if (o->od_objset.os != NULL)
		RETURN(0);

	if (strlen(dev) >= sizeof(o->od_mntdev))
		RETURN(-E2BIG);

	strcpy(o->od_mntdev, dev);
	strncpy(o->od_svname, lustre_cfg_string(cfg, 4),
		sizeof(o->od_svname) - 1);

	if (server_name_is_ost(o->od_svname))
		o->od_is_ost = 1;

	rc = -udmu_objset_open(o->od_mntdev, &o->od_objset);
	if (rc) {
		CERROR("can't open objset %s: %d\n", o->od_mntdev, rc);
		RETURN(rc);
	}

	ds = dmu_objset_ds(o->od_objset.os);
	dp = dmu_objset_pool(o->od_objset.os);
	LASSERT(ds);
	LASSERT(dp);
	dsl_pool_config_enter(dp, FTAG);
	rc = dsl_prop_register(ds, "xattr", osd_xattr_changed_cb, o);
	dsl_pool_config_exit(dp, FTAG);
	if (rc)
		CERROR("%s: cat not register xattr callback, ignore: %d\n",
		       o->od_svname, rc);

	rc = __osd_obj2dbuf(env, o->od_objset.os, o->od_objset.root,
				&rootdb, root_tag);
	if (rc) {
		CERROR("udmu_obj2dbuf() failed with error %d\n", rc);
		udmu_objset_close(&o->od_objset);
		RETURN(rc);
	}

	o->od_root = rootdb->db_object;
	sa_buf_rele(rootdb, root_tag);

	/* 1. initialize oi before any file create or file open */
	rc = osd_oi_init(env, o);
	if (rc)
		GOTO(err, rc);

	rc = lu_site_init(&o->od_site, osd2lu_dev(o));
	if (rc)
		GOTO(err, rc);
	o->od_site.ls_bottom_dev = osd2lu_dev(o);

	rc = lu_site_init_finish(&o->od_site);
	if (rc)
		GOTO(err, rc);

	rc = osd_convert_root_to_new_seq(env, o);
	if (rc)
		GOTO(err, rc);

	/* Use our own ZAP for inode accounting by default, this can be changed
	 * via procfs to estimate the inode usage from the block usage */
	o->od_quota_iused_est = 0;

	rc = osd_procfs_init(o, o->od_svname);
	if (rc)
		GOTO(err, rc);

	o->arc_prune_cb = arc_add_prune_callback(arc_prune_func, o);

	/* initialize quota slave instance */
	o->od_quota_slave = qsd_init(env, o->od_svname, &o->od_dt_dev,
				     o->od_proc_entry);
	if (IS_ERR(o->od_quota_slave)) {
		rc = PTR_ERR(o->od_quota_slave);
		o->od_quota_slave = NULL;
		GOTO(err, rc);
	}

	/* parse mount option "noacl", and enable ACL by default */
	opts = lustre_cfg_string(cfg, 3);
	if (opts == NULL || strstr(opts, "noacl") == NULL)
		o->od_posix_acl = 1;

err:
	RETURN(rc);
}

static void osd_umount(const struct lu_env *env, struct osd_device *o)
{
	ENTRY;

	if (cfs_atomic_read(&o->od_zerocopy_alloc))
		CERROR("%s: lost %d allocated page(s)\n", o->od_svname,
		       cfs_atomic_read(&o->od_zerocopy_alloc));
	if (cfs_atomic_read(&o->od_zerocopy_loan))
		CERROR("%s: lost %d loaned abuf(s)\n", o->od_svname,
		       cfs_atomic_read(&o->od_zerocopy_loan));
	if (cfs_atomic_read(&o->od_zerocopy_pin))
		CERROR("%s: lost %d pinned dbuf(s)\n", o->od_svname,
		       cfs_atomic_read(&o->od_zerocopy_pin));

	if (o->od_objset.os != NULL)
		udmu_objset_close(&o->od_objset);

	EXIT;
}

static int osd_device_init0(const struct lu_env *env,
			    struct osd_device *o,
			    struct lustre_cfg *cfg)
{
	struct lu_device	*l = osd2lu_dev(o);
	int			 rc;

	/* if the module was re-loaded, env can loose its keys */
	rc = lu_env_refill((struct lu_env *) env);
	if (rc)
		GOTO(out, rc);

	l->ld_ops = &osd_lu_ops;
	o->od_dt_dev.dd_ops = &osd_dt_ops;

	o->od_capa_hash = init_capa_hash();
	if (o->od_capa_hash == NULL)
		GOTO(out, rc = -ENOMEM);

out:
	RETURN(rc);
}

static struct lu_device *osd_device_fini(const struct lu_env *env,
					 struct lu_device *dev);

static struct lu_device *osd_device_alloc(const struct lu_env *env,
					  struct lu_device_type *type,
					  struct lustre_cfg *cfg)
{
	struct osd_device *dev;
	int		   rc;

	OBD_ALLOC_PTR(dev);
	if (dev == NULL)
		return ERR_PTR(-ENOMEM);

	rc = dt_device_init(&dev->od_dt_dev, type);
	if (rc == 0) {
		rc = osd_device_init0(env, dev, cfg);
		if (rc == 0) {
			rc = osd_mount(env, dev, cfg);
			if (rc)
				osd_device_fini(env, osd2lu_dev(dev));
		}
		if (rc)
			dt_device_fini(&dev->od_dt_dev);
	}

	if (unlikely(rc != 0))
		OBD_FREE_PTR(dev);

	return rc == 0 ? osd2lu_dev(dev) : ERR_PTR(rc);
}

static struct lu_device *osd_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct osd_device *o = osd_dev(d);
	ENTRY;

	cleanup_capa_hash(o->od_capa_hash);
	/* XXX: make osd top device in order to release reference */
	d->ld_site->ls_top_dev = d;
	lu_site_purge(env, d->ld_site, -1);
	if (!cfs_hash_is_empty(d->ld_site->ls_obj_hash)) {
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_ERROR, NULL);
		lu_site_print(env, d->ld_site, &msgdata, lu_cdebug_printer);
	}
	lu_site_fini(&o->od_site);
	dt_device_fini(&o->od_dt_dev);
	OBD_FREE_PTR(o);

	RETURN (NULL);
}

static struct lu_device *osd_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct osd_device *o = osd_dev(d);
	struct dsl_dataset *ds;
	int		   rc;
	ENTRY;


	osd_shutdown(env, o);
	osd_oi_fini(env, o);

	if (o->od_objset.os) {
		ds = dmu_objset_ds(o->od_objset.os);
		rc = dsl_prop_unregister(ds, "xattr", osd_xattr_changed_cb, o);
		if (rc)
			CERROR("%s: dsl_prop_unregister xattr error %d\n",
				o->od_svname, rc);
		arc_remove_prune_callback(o->arc_prune_cb);
		o->arc_prune_cb = NULL;
		osd_sync(env, lu2dt_dev(d));
		txg_wait_callbacks(spa_get_dsl(dmu_objset_spa(o->od_objset.os)));
	}

	rc = osd_procfs_fini(o);
	if (rc) {
		CERROR("proc fini error %d\n", rc);
		RETURN(ERR_PTR(rc));
	}

	if (o->od_objset.os)
		osd_umount(env, o);

	RETURN(NULL);
}

static int osd_device_init(const struct lu_env *env, struct lu_device *d,
                           const char *name, struct lu_device *next)
{
	return 0;
}

/*
 * To be removed, setup is performed by osd_device_{init,alloc} and
 * cleanup is performed by osd_device_{fini,free).
 */
static int osd_process_config(const struct lu_env *env,
			      struct lu_device *d, struct lustre_cfg *cfg)
{
	struct osd_device	*o = osd_dev(d);
	int			rc;
	ENTRY;

	switch(cfg->lcfg_command) {
	case LCFG_SETUP:
		rc = osd_mount(env, o, cfg);
		break;
	case LCFG_CLEANUP:
		rc = osd_shutdown(env, o);
		break;
	case LCFG_PARAM: {
		LASSERT(&o->od_dt_dev);
		rc = class_process_proc_param(PARAM_OSD, lprocfs_osd_obd_vars,
					      cfg, &o->od_dt_dev);
		if (rc > 0 || rc == -ENOSYS)
			rc = class_process_proc_param(PARAM_OST,
						      lprocfs_osd_obd_vars,
						      cfg, &o->od_dt_dev);
		break;
	}
	default:
		rc = -ENOTTY;
	}

	RETURN(rc);
}

static int osd_recovery_complete(const struct lu_env *env, struct lu_device *d)
{
	struct osd_device	*osd = osd_dev(d);
	int			 rc = 0;
	ENTRY;

	if (osd->od_quota_slave == NULL)
		RETURN(0);

	/* start qsd instance on recovery completion, this notifies the quota
	 * slave code that we are about to process new requests now */
	rc = qsd_start(env, osd->od_quota_slave);
	RETURN(rc);
}

/*
 * we use exports to track all osd users
 */
static int osd_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct osd_device    *osd = osd_dev(obd->obd_lu_dev);
	struct lustre_handle  conn;
	int                   rc;
	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", osd->od_connects);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	*exp = class_conn2export(&conn);

	spin_lock(&osd->od_objset.lock);
	osd->od_connects++;
	spin_unlock(&osd->od_objset.lock);

	RETURN(0);
}

/*
 * once last export (we don't count self-export) disappeared
 * osd can be released
 */
static int osd_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct osd_device *osd = osd_dev(obd->obd_lu_dev);
	int                rc, release = 0;
	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	spin_lock(&osd->od_objset.lock);
	osd->od_connects--;
	if (osd->od_connects == 0)
		release = 1;
	spin_unlock(&osd->od_objset.lock);

	rc = class_disconnect(exp); /* bz 9811 */

	if (rc == 0 && release)
		class_manual_cleanup(obd);
	RETURN(rc);
}

static int osd_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *dev)
{
	struct osd_device	*osd = osd_dev(dev);
	int			 rc = 0;
	ENTRY;

	if (osd->od_quota_slave != NULL)
		/* set up quota slave objects */
		rc = qsd_prepare(env, osd->od_quota_slave);

	RETURN(rc);
}

struct lu_device_operations osd_lu_ops = {
	.ldo_object_alloc	= osd_object_alloc,
	.ldo_process_config	= osd_process_config,
	.ldo_recovery_complete	= osd_recovery_complete,
	.ldo_prepare		= osd_prepare,
};

static void osd_type_start(struct lu_device_type *t)
{
}

static void osd_type_stop(struct lu_device_type *t)
{
}

static struct lu_device_type_operations osd_device_type_ops = {
	.ldto_init		= osd_type_init,
	.ldto_fini		= osd_type_fini,

	.ldto_start		= osd_type_start,
	.ldto_stop		= osd_type_stop,

	.ldto_device_alloc	= osd_device_alloc,
	.ldto_device_free	= osd_device_free,

	.ldto_device_init	= osd_device_init,
	.ldto_device_fini	= osd_device_fini
};

static struct lu_device_type osd_device_type = {
	.ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_OSD_ZFS_NAME,
	.ldt_ops      = &osd_device_type_ops,
	.ldt_ctx_tags = LCT_LOCAL
};


static struct obd_ops osd_obd_device_ops = {
	.o_owner       = THIS_MODULE,
	.o_connect	= osd_obd_connect,
	.o_disconnect	= osd_obd_disconnect
};

int __init osd_init(void)
{
	int rc;

	rc = osd_options_init();
	if (rc)
		return rc;

	rc = lu_kmem_init(osd_caches);
	if (rc)
		return rc;

	rc = class_register_type(&osd_obd_device_ops, NULL,
				 lprocfs_osd_module_vars,
				 LUSTRE_OSD_ZFS_NAME, &osd_device_type);
	if (rc)
		lu_kmem_fini(osd_caches);
	return rc;
}

void __exit osd_exit(void)
{
	class_unregister_type(LUSTRE_OSD_ZFS_NAME);
	lu_kmem_fini(osd_caches);
}

extern unsigned int osd_oi_count;
CFS_MODULE_PARM(osd_oi_count, "i", int, 0444,
		"Number of Object Index containers to be created, "
		"it's only valid for new filesystem.");

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Device ("LUSTRE_OSD_ZFS_NAME")");
MODULE_LICENSE("GPL");

cfs_module(osd, LUSTRE_VERSION_STRING, osd_init, osd_exit);
