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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
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
#include <uapi/linux/lustre_param.h>
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

/* Slab for OSD object allocation */
struct kmem_cache *osd_object_kmem;

/* Slab to allocate osd_zap_it */
struct kmem_cache *osd_zapit_cachep;

static struct lu_kmem_descr osd_caches[] = {
	{
		.ckd_cache = &osd_object_kmem,
		.ckd_name  = "zfs_osd_obj",
		.ckd_size  = sizeof(struct osd_object)
	},
	{
		.ckd_cache = &osd_zapit_cachep,
		.ckd_name  = "osd_zapit_cache",
		.ckd_size  = sizeof(struct osd_zap_it)
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

	LASSERT(site->ls_obj_hash);

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
	list_for_each_entry_safe(dcb, tmp, &oh->ot_dcb_list, dcb_linkage) {
		LASSERTF(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC,
			 "commit callback entry: magic=%x name='%s'\n",
			 dcb->dcb_magic, dcb->dcb_name);
		list_del_init(&dcb->dcb_linkage);
		dcb->dcb_func(NULL, th, dcb, error);
	}

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
	struct osd_thandle *oh = container_of0(th, struct osd_thandle,
					       ot_super);

	LASSERT(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC);
	LASSERT(&dcb->dcb_func != NULL);
	if (dcb->dcb_flags & DCB_TRANS_STOP)
		list_add(&dcb->dcb_linkage, &oh->ot_stop_dcb_list);
	else
		list_add(&dcb->dcb_linkage, &oh->ot_dcb_list);

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
			CERROR("%s: failed to start transaction due to ENOSPC"
			       "\n", osd->od_svname);
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

static void osd_unlinked_list_emptify(const struct lu_env *env,
				      struct osd_device *osd,
				      struct list_head *list, bool free)
{
	struct osd_object *obj;
	uint64_t	   oid;

	while (!list_empty(list)) {
		obj = list_entry(list->next,
				 struct osd_object, oo_unlinked_linkage);
		LASSERT(obj->oo_dn != NULL);
		oid = obj->oo_dn->dn_object;

		list_del_init(&obj->oo_unlinked_linkage);
		if (free)
			(void)osd_unlinked_object_free(env, osd, oid);
	}
}

static void osd_trans_stop_cb(struct osd_thandle *oth, int result)
{
	struct dt_txn_commit_cb	*dcb;
	struct dt_txn_commit_cb	*tmp;

	/* call per-transaction stop callbacks if any */
	list_for_each_entry_safe(dcb, tmp, &oth->ot_stop_dcb_list,
				 dcb_linkage) {
		LASSERTF(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC,
			 "commit callback entry: magic=%x name='%s'\n",
			 dcb->dcb_magic, dcb->dcb_name);
		list_del_init(&dcb->dcb_linkage);
		dcb->dcb_func(NULL, &oth->ot_super, dcb, result);
	}
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_trans_stop(const struct lu_env *env, struct dt_device *dt,
			  struct thandle *th)
{
	struct osd_device	*osd = osd_dt_dev(th->th_dev);
	bool			 sync = (th->th_sync != 0);
	struct osd_thandle	*oh;
	struct list_head	 unlinked;
	uint64_t		 txg;
	int			 rc;
	ENTRY;

	oh = container_of0(th, struct osd_thandle, ot_super);
	INIT_LIST_HEAD(&unlinked);
	list_splice_init(&oh->ot_unlinked_list, &unlinked);
	/* reset OI cache for safety */
	osd_oti_get(env)->oti_ins_cache_used = 0;

	if (oh->ot_assigned == 0) {
		LASSERT(oh->ot_tx);
		dmu_tx_abort(oh->ot_tx);
		osd_object_sa_dirty_rele(env, oh);
		osd_unlinked_list_emptify(env, osd, &unlinked, false);
		/* there won't be any commit, release reserved quota space now,
		 * if any */
		qsd_op_end(env, osd->od_quota_slave, &oh->ot_quota_trans);
		OBD_FREE_PTR(oh);
		RETURN(0);
	}

	rc = dt_txn_hook_stop(env, th);
	if (rc != 0)
		CDEBUG(D_OTHER, "%s: transaction hook failed: rc = %d\n",
		       osd->od_svname, rc);

	osd_trans_stop_cb(oh, rc);

	LASSERT(oh->ot_tx);
	txg = oh->ot_tx->tx_txg;

	osd_object_sa_dirty_rele(env, oh);
	/* XXX: Once dmu_tx_commit() called, oh/th could have been freed
	 * by osd_trans_commit_cb already. */
	dmu_tx_commit(oh->ot_tx);

	osd_unlinked_list_emptify(env, osd, &unlinked, true);

	if (sync)
		txg_wait_synced(dmu_objset_pool(osd->od_os), txg);

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

	if (dt->dd_rdonly) {
		CERROR("%s: someone try to start transaction under "
		       "readonly mode, should be disabled.\n",
		       osd_name(osd_dt_dev(dt)));
		dump_stack();
		RETURN(ERR_PTR(-EROFS));
	}

	tx = dmu_tx_create(osd->od_os);
	if (tx == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* alloc callback data */
	OBD_ALLOC_PTR(oh);
	if (oh == NULL) {
		dmu_tx_abort(tx);
		RETURN(ERR_PTR(-ENOMEM));
	}

	oh->ot_tx = tx;
	INIT_LIST_HEAD(&oh->ot_dcb_list);
	INIT_LIST_HEAD(&oh->ot_stop_dcb_list);
	INIT_LIST_HEAD(&oh->ot_unlinked_list);
	INIT_LIST_HEAD(&oh->ot_sa_list);
	memset(&oh->ot_quota_trans, 0, sizeof(oh->ot_quota_trans));
	th = &oh->ot_super;
	th->th_dev = dt;
	th->th_result = 0;
	th->th_tags = LCT_TX_HANDLE;
	RETURN(th);
}

/* Estimate the total number of objects from a number of blocks */
uint64_t osd_objs_count_estimate(uint64_t usedbytes, uint64_t usedobjs,
				 uint64_t nrblocks, uint64_t est_maxblockshift)
{
	uint64_t est_totobjs, est_usedblocks, est_usedobjs;

	/*
	 * If blocksize is below 64KB (e.g. MDT with recordsize=4096) then
	 * bump the free dnode estimate to assume blocks at least 64KB in
	 * case of a directory-heavy MDT (at 32KB/directory).
	 */
	if (est_maxblockshift < 16) {
		nrblocks >>= (16 - est_maxblockshift);
		est_maxblockshift = 16;
	}

	/*
	 * Estimate the total number of dnodes from the total blocks count
	 * and the space used per dnode.  Since we don't know the overhead
	 * associated with each dnode (xattrs, SAs, VDEV overhead, etc.)
	 * just using DNODE_SHIFT isn't going to give a good estimate.
	 * Instead, compute the current average space usage per dnode, with
	 * an upper and lower cap to avoid unrealistic estimates..
	 *
	 * In case there aren't many dnodes or blocks used yet, add a small
	 * correction factor (OSD_DNODE_EST_{COUNT,BLKSHIFT}).  This factor
	 * gradually disappears as the number of real dnodes grows.  It also
	 * avoids the need to check for divide-by-zero computing dn_per_block.
	 */
	CLASSERT(OSD_DNODE_MIN_BLKSHIFT > 0);
	CLASSERT(OSD_DNODE_EST_BLKSHIFT > 0);

	est_usedblocks = ((OSD_DNODE_EST_COUNT << OSD_DNODE_EST_BLKSHIFT) +
			  usedbytes) >> est_maxblockshift;
	est_usedobjs   = OSD_DNODE_EST_COUNT + usedobjs;

	if (est_usedobjs <= est_usedblocks) {
		/*
		 * Average space/dnode more than maximum block size, use max
		 * block size to estimate free dnodes from adjusted free blocks
		 * count.  OSTs typically use multiple blocks per dnode so this
		 * case applies.
		 */
		est_totobjs = nrblocks;

	} else if (est_usedobjs >= (est_usedblocks << OSD_DNODE_MIN_BLKSHIFT)) {
		/*
		 * Average space/dnode smaller than min dnode size (probably
		 * due to metadnode compression), use min dnode size to
		 * estimate object count.  MDTs may use only one block per node
		 * so this case applies.
		 */
		est_totobjs = nrblocks << OSD_DNODE_MIN_BLKSHIFT;

	} else {
		/*
		 * Between the extremes, use average space per existing dnode
		 * to compute the number of dnodes that will fit into nrblocks:
		 *
		 *    est_totobjs = nrblocks * (est_usedobjs / est_usedblocks)
		 *
		 * this may overflow 64 bits or become 0 if not handled well.
		 *
		 * We know nrblocks is below 2^(64 - blkbits) bits, and
		 * est_usedobjs is under 48 bits due to DN_MAX_OBJECT_SHIFT,
		 * which means that multiplying them may get as large as
		 * 2 ^ 96 for the minimum blocksize of 64KB allowed above.
		 *
		 * The ratio of dnodes per block (est_usedobjs / est_usedblocks)
		 * is under 2^(blkbits - DNODE_SHIFT) = blocksize / 512 due to
		 * the limit checks above, so we can safely compute this first.
		 * We care more about accuracy on the MDT (many dnodes/block)
		 * which is good because this is where truncation errors are
		 * smallest.  Since both nrblocks and dn_per_block are a
		 * function of blkbits, their product is at most:
		 *
		 *    2^(64 - blkbits) * 2^(blkbits - DNODE_SHIFT) = 2^(64 - 9)
		 *
		 * so we can safely use 7 bits to compute a fixed-point
		 * fraction and est_totobjs can still fit in 64 bits.
		 */
		unsigned dn_per_block = (est_usedobjs << 7) / est_usedblocks;

		est_totobjs = (nrblocks * dn_per_block) >> 7;
	}
	return est_totobjs;
}

static int osd_objset_statfs(struct osd_device *osd, struct obd_statfs *osfs)
{
	struct objset *os = osd->od_os;
	uint64_t usedbytes, availbytes, usedobjs, availobjs;
	uint64_t est_availobjs;
	uint64_t reserved;
	uint64_t bshift;

	dmu_objset_space(os, &usedbytes, &availbytes, &usedobjs, &availobjs);

	memset(osfs, 0, sizeof(*osfs));

	/* We're a zfs filesystem. */
	osfs->os_type = UBERBLOCK_MAGIC;

	/*
	 * ZFS allows multiple block sizes.  For statfs, Linux makes no
	 * proper distinction between bsize and frsize.  For calculations
	 * of free and used blocks incorrectly uses bsize instead of frsize,
	 * but bsize is also used as the optimal blocksize.  We return the
	 * largest possible block size as IO size for the optimum performance
	 * and scale the free and used blocks count appropriately.
	 */
	osfs->os_bsize = osd->od_max_blksz;
	bshift = fls64(osfs->os_bsize) - 1;

	osfs->os_blocks = (usedbytes + availbytes) >> bshift;
	osfs->os_bfree = availbytes >> bshift;
	osfs->os_bavail = osfs->os_bfree; /* no extra root reservation */

	/* Take replication (i.e. number of copies) into account */
	if (os->os_copies != 0)
		osfs->os_bavail /= os->os_copies;

	/*
	 * Reserve some space so we don't run into ENOSPC due to grants not
	 * accounting for metadata overhead in ZFS, and to avoid fragmentation.
	 * Rather than report this via os_bavail (which makes users unhappy if
	 * they can't fill the filesystem 100%), reduce os_blocks as well.
	 *
	 * Reserve 0.78% of total space, at least 16MB for small filesystems,
	 * for internal files to be created/unlinked when space is tight.
	 */
	CLASSERT(OSD_STATFS_RESERVED_SIZE > 0);
	reserved = OSD_STATFS_RESERVED_SIZE >> bshift;
	if (likely(osfs->os_blocks >= reserved << OSD_STATFS_RESERVED_SHIFT))
		reserved = osfs->os_blocks >> OSD_STATFS_RESERVED_SHIFT;

	osfs->os_blocks -= reserved;
	osfs->os_bfree  -= min(reserved, osfs->os_bfree);
	osfs->os_bavail -= min(reserved, osfs->os_bavail);

	/*
	 * The availobjs value returned from dmu_objset_space() is largely
	 * useless, since it reports the number of objects that might
	 * theoretically still fit into the dataset, independent of minor
	 * issues like how much space is actually available in the pool.
	 * Compute a better estimate in udmu_objs_count_estimate().
	 */
	est_availobjs = osd_objs_count_estimate(usedbytes, usedobjs,
						osfs->os_bfree, bshift);

	osfs->os_ffree = min(availobjs, est_availobjs);
	osfs->os_files = osfs->os_ffree + usedobjs;

	/* ZFS XXX: fill in backing dataset FSID/UUID
	   memcpy(osfs->os_fsid, .... );*/

	osfs->os_namelen = MAXNAMELEN;
	osfs->os_maxbytes = OBD_OBJECT_EOF;

	if (!spa_writeable(dmu_objset_spa(os)) ||
	    osd->od_dev_set_rdonly || osd->od_prop_rdonly)
		osfs->os_state |= OS_STATE_READONLY;

	return 0;
}

/*
 * Concurrency: shouldn't matter.
 */
int osd_statfs(const struct lu_env *env, struct dt_device *d,
	       struct obd_statfs *osfs)
{
	int		   rc;
	ENTRY;

	rc = osd_objset_statfs(osd_dt_dev(d), osfs);
	if (unlikely(rc != 0))
		RETURN(rc);

	osfs->os_bavail -= min_t(u64,
				 OSD_GRANT_FOR_LOCAL_OIDS / osfs->os_bsize,
				 osfs->os_bavail);
	RETURN(0);
}

static int osd_blk_insert_cost(struct osd_device *osd)
{
	int max_blockshift, nr_blkptrshift, bshift;

	/* max_blockshift is the log2 of the number of blocks needed to reach
	 * the maximum filesize (that's to say 2^64) */
	bshift = osd_spa_maxblockshift(dmu_objset_spa(osd->od_os));
	max_blockshift = DN_MAX_OFFSET_SHIFT - bshift;

	/* nr_blkptrshift is the log2 of the number of block pointers that can
	 * be stored in an indirect block */
	CLASSERT(DN_MAX_INDBLKSHIFT > SPA_BLKPTRSHIFT);
	nr_blkptrshift = DN_MAX_INDBLKSHIFT - SPA_BLKPTRSHIFT;

	/* max_blockshift / nr_blkptrshift is thus the maximum depth of the
	 * tree. We add +1 for rounding purpose.
	 * The tree depth times the indirect block size gives us the maximum
	 * cost of inserting a block in the tree */
	return (max_blockshift / nr_blkptrshift + 1) * (1<<DN_MAX_INDBLKSHIFT);
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
	param->ddp_symlink_max	= PATH_MAX;
	param->ddp_mount_type	= LDD_MT_ZFS;

	param->ddp_mntopts	= MNTOPT_USERXATTR;
	if (osd->od_posix_acl)
		param->ddp_mntopts |= MNTOPT_ACL;
	param->ddp_max_ea_size	= DXATTR_MAX_ENTRY_SIZE;

	/* for maxbytes, report same value as ZPL */
	param->ddp_maxbytes	= MAX_LFS_FILESIZE;

	/* inodes are dynamically allocated, so we report the per-inode space
	 * consumption to upper layers. This static value is not really accurate
	 * and we should use the same logic as in udmu_objset_statfs() to
	 * estimate the real size consumed by an object */
	param->ddp_inodespace = OSD_DNODE_EST_COUNT;
	/* Although ZFS isn't an extent-based filesystem, the metadata overhead
	 * (i.e. 7 levels of indirect blocks, see osd_blk_insert_cost()) should
	 * not be accounted for every single new block insertion.
	 * Instead, the maximum extent size is set to the number of blocks that
	 * can fit into a single contiguous indirect block. There would be some
	 * cases where this crosses indirect blocks, but it also won't have 7
	 * new levels of indirect blocks in that case either, so it will still
	 * have enough reserved space for the extra indirect block */
	param->ddp_max_extent_blks =
		(1 << (DN_MAX_INDBLKSHIFT - SPA_BLKPTRSHIFT));
	param->ddp_extent_tax = osd_blk_insert_cost(osd);
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_sync(const struct lu_env *env, struct dt_device *d)
{
	if (!d->dd_rdonly) {
		struct osd_device  *osd = osd_dt_dev(d);

		CDEBUG(D_CACHE, "syncing OSD %s\n", LUSTRE_OSD_ZFS_NAME);
		txg_wait_synced(dmu_objset_pool(osd->od_os), 0ULL);
		CDEBUG(D_CACHE, "synced OSD %s\n", LUSTRE_OSD_ZFS_NAME);
	}

	return 0;
}

static int osd_commit_async(const struct lu_env *env, struct dt_device *dev)
{
	struct osd_device *osd = osd_dt_dev(dev);
	tx_state_t	  *tx = &dmu_objset_pool(osd->od_os)->dp_tx;
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
	osd->od_dev_set_rdonly = 1;
	spa_freeze(dmu_objset_spa(osd->od_os));

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
	struct osd_idmap_cache *idc = info->oti_ins_cache;

	if (idc != NULL) {
		LASSERT(info->oti_ins_cache_size > 0);
		OBD_FREE(idc, sizeof(*idc) * info->oti_ins_cache_size);
		info->oti_ins_cache = NULL;
		info->oti_ins_cache_size = 0;
	}
	lu_buf_free(&info->oti_xattr_lbuf);
	OBD_FREE_PTR(info);
}

static void osd_key_exit(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
}

struct lu_context_key osd_key = {
	.lct_tags = LCT_DT_THREAD | LCT_MD_THREAD | LCT_MG_THREAD | LCT_LOCAL,
	.lct_init = osd_key_init,
	.lct_fini = osd_key_fini,
	.lct_exit = osd_key_exit
};

static void osd_fid_fini(const struct lu_env *env, struct osd_device *osd)
{
	if (osd->od_cl_seq == NULL)
		return;

	seq_client_fini(osd->od_cl_seq);
	OBD_FREE_PTR(osd->od_cl_seq);
	osd->od_cl_seq = NULL;
}

static int osd_shutdown(const struct lu_env *env, struct osd_device *o)
{
	ENTRY;

	/* shutdown quota slave instance associated with the device */
	if (o->od_quota_slave != NULL) {
		/* complete all in-flight callbacks */
		osd_sync(env, &o->od_dt_dev);
		txg_wait_callbacks(spa_get_dsl(dmu_objset_spa(o->od_os)));
		qsd_fini(env, o->od_quota_slave);
		o->od_quota_slave = NULL;
	}

	osd_fid_fini(env, o);

	RETURN(0);
}

static void osd_xattr_changed_cb(void *arg, uint64_t newval)
{
	struct osd_device *osd = arg;

	osd->od_xattr_in_sa = (newval == ZFS_XATTR_SA);
}

static void osd_recordsize_changed_cb(void *arg, uint64_t newval)
{
	struct osd_device *osd = arg;

	LASSERT(newval <= osd_spa_maxblocksize(dmu_objset_spa(osd->od_os)));
	LASSERT(newval >= SPA_MINBLOCKSIZE);
	LASSERT(ISP2(newval));

	osd->od_max_blksz = newval;
}

static void osd_readonly_changed_cb(void *arg, uint64_t newval)
{
	struct osd_device *osd = arg;

	osd->od_prop_rdonly = !!newval;
}

static void osd_dnodesize_changed_cb(void *arg, uint64_t newval)
{
	struct osd_device *osd = arg;

	osd->od_dnsize = newval;
}

/*
 * This function unregisters all registered callbacks.  It's harmless to
 * unregister callbacks that were never registered so it is used to safely
 * unwind a partially completed call to osd_objset_register_callbacks().
 */
static void osd_objset_unregister_callbacks(struct osd_device *o)
{
	struct dsl_dataset	*ds = dmu_objset_ds(o->od_os);

	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_XATTR),
				   osd_xattr_changed_cb, o);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_RECORDSIZE),
				   osd_recordsize_changed_cb, o);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_READONLY),
				   osd_readonly_changed_cb, o);
	(void) dsl_prop_unregister(ds, zfs_prop_to_name(ZFS_PROP_DNODESIZE),
				   osd_readonly_changed_cb, o);

	if (o->arc_prune_cb != NULL) {
		arc_remove_prune_callback(o->arc_prune_cb);
		o->arc_prune_cb = NULL;
	}
}

/*
 * Register the required callbacks to be notified when zfs properties
 * are modified using the 'zfs(8)' command line utility.
 */
static int osd_objset_register_callbacks(struct osd_device *o)
{
	struct dsl_dataset	*ds = dmu_objset_ds(o->od_os);
	dsl_pool_t		*dp = dmu_objset_pool(o->od_os);
	int			rc;

	LASSERT(ds);
	LASSERT(dp);

	dsl_pool_config_enter(dp, FTAG);
	rc = -dsl_prop_register(ds, zfs_prop_to_name(ZFS_PROP_XATTR),
				osd_xattr_changed_cb, o);
	if (rc)
		GOTO(err, rc);

	rc = -dsl_prop_register(ds, zfs_prop_to_name(ZFS_PROP_RECORDSIZE),
				osd_recordsize_changed_cb, o);
	if (rc)
		GOTO(err, rc);

	rc = -dsl_prop_register(ds, zfs_prop_to_name(ZFS_PROP_READONLY),
				osd_readonly_changed_cb, o);
	if (rc)
		GOTO(err, rc);

	rc = -dsl_prop_register(ds, zfs_prop_to_name(ZFS_PROP_DNODESIZE),
				osd_dnodesize_changed_cb, o);
	if (rc)
		GOTO(err, rc);

	o->arc_prune_cb = arc_add_prune_callback(arc_prune_func, o);
err:
	dsl_pool_config_exit(dp, FTAG);
	if (rc)
		osd_objset_unregister_callbacks(o);

	RETURN(rc);
}

static int osd_objset_open(struct osd_device *o)
{
	uint64_t	version = ZPL_VERSION;
	uint64_t	sa_obj, unlink_obj;
	int		rc;
	ENTRY;

	rc = -osd_dmu_objset_own(o->od_mntdev, DMU_OST_ZFS,
			     o->od_dt_dev.dd_rdonly ? B_TRUE : B_FALSE,
			     B_FALSE, o, &o->od_os);

	if (rc) {
		CERROR("%s: can't open %s\n", o->od_svname, o->od_mntdev);
		o->od_os = NULL;

		GOTO(out, rc);
	}

	/* Check ZFS version */
	rc = -zap_lookup(o->od_os, MASTER_NODE_OBJ,
			 ZPL_VERSION_STR, 8, 1, &version);
	if (rc) {
		CERROR("%s: Error looking up ZPL VERSION\n", o->od_mntdev);
		/*
		 * We can't return ENOENT because that would mean the objset
		 * didn't exist.
		 */
		GOTO(out, rc = -EIO);
	}

	rc = -zap_lookup(o->od_os, MASTER_NODE_OBJ,
			 ZFS_SA_ATTRS, 8, 1, &sa_obj);
	if (rc)
		GOTO(out, rc);

	rc = -sa_setup(o->od_os, sa_obj, zfs_attr_table,
		       ZPL_END, &o->z_attr_table);
	if (rc)
		GOTO(out, rc);

	rc = -zap_lookup(o->od_os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ,
			 8, 1, &o->od_rootid);
	if (rc) {
		CERROR("%s: lookup for root failed: rc = %d\n",
			o->od_svname, rc);
		GOTO(out, rc);
	}

	rc = -zap_lookup(o->od_os, MASTER_NODE_OBJ, ZFS_UNLINKED_SET,
			 8, 1, &unlink_obj);
	if (rc) {
		CERROR("%s: lookup for %s failed: rc = %d\n",
		       o->od_svname, ZFS_UNLINKED_SET, rc);
		GOTO(out, rc);
	}

	/* Check that user/group usage tracking is supported */
	if (!dmu_objset_userused_enabled(o->od_os) ||
	    DMU_USERUSED_DNODE(o->od_os)->dn_type != DMU_OT_USERGROUP_USED ||
	    DMU_GROUPUSED_DNODE(o->od_os)->dn_type != DMU_OT_USERGROUP_USED) {
		CERROR("%s: Space accounting not supported by this target, "
			"aborting\n", o->od_svname);
		GOTO(out, rc = -ENOTSUPP);
	}

	rc = __osd_obj2dnode(o->od_os, unlink_obj, &o->od_unlinked);
	if (rc) {
		CERROR("%s: can't get dnode for unlinked: rc = %d\n",
		       o->od_svname, rc);
		GOTO(out, rc);
	}

out:
	if (rc != 0 && o->od_os != NULL) {
		osd_dmu_objset_disown(o->od_os, B_FALSE, o);
		o->od_os = NULL;
	}

	RETURN(rc);
}

int osd_unlinked_object_free(const struct lu_env *env, struct osd_device *osd,
			 uint64_t oid)
{
	char *key = osd_oti_get(env)->oti_str;
	int	  rc;
	dmu_tx_t *tx;

	if (osd->od_dt_dev.dd_rdonly) {
		CERROR("%s: someone try to free objects under "
		       "readonly mode, should be disabled.\n", osd_name(osd));
		dump_stack();

		return -EROFS;
	}

	rc = -dmu_free_long_range(osd->od_os, oid, 0, DMU_OBJECT_END);
	if (rc != 0) {
		CWARN("%s: Cannot truncate %llu: rc = %d\n",
		      osd->od_svname, oid, rc);
		return rc;
	}

	tx = dmu_tx_create(osd->od_os);
	dmu_tx_hold_free(tx, oid, 0, DMU_OBJECT_END);
	osd_tx_hold_zap(tx, osd->od_unlinked->dn_object, osd->od_unlinked,
			FALSE, NULL);
	rc = -dmu_tx_assign(tx, TXG_WAIT);
	if (rc != 0) {
		CWARN("%s: Cannot assign tx for %llu: rc = %d\n",
		      osd->od_svname, oid, rc);
		goto failed;
	}

	snprintf(key, sizeof(osd_oti_get(env)->oti_str), "%llx", oid);
	rc = osd_zap_remove(osd, osd->od_unlinked->dn_object,
			    osd->od_unlinked, key, tx);
	if (rc != 0) {
		CWARN("%s: Cannot remove %llu from unlinked set: rc = %d\n",
		      osd->od_svname, oid, rc);
		goto failed;
	}

	rc = -dmu_object_free(osd->od_os, oid, tx);
	if (rc != 0) {
		CWARN("%s: Cannot free %llu: rc = %d\n",
		      osd->od_svname, oid, rc);
		goto failed;
	}
	dmu_tx_commit(tx);

	return 0;

failed:
	LASSERT(rc != 0);
	dmu_tx_abort(tx);

	return rc;
}

static void
osd_unlinked_drain(const struct lu_env *env, struct osd_device *osd)
{
	zap_cursor_t	 zc;
	zap_attribute_t	*za = &osd_oti_get(env)->oti_za;

	zap_cursor_init(&zc, osd->od_os, osd->od_unlinked->dn_object);

	while (zap_cursor_retrieve(&zc, za) == 0) {
		/* If cannot free the object, leave it in the unlinked set,
		 * until the OSD is mounted again when obd_unlinked_drain()
		 * will be called. */
		if (osd_unlinked_object_free(env, osd, za->za_first_integer))
			break;
		zap_cursor_advance(&zc);
	}

	zap_cursor_fini(&zc);
}

static int osd_mount(const struct lu_env *env,
		     struct osd_device *o, struct lustre_cfg *cfg)
{
	char			*mntdev = lustre_cfg_string(cfg, 1);
	char			*str	= lustre_cfg_string(cfg, 2);
	char			*svname = lustre_cfg_string(cfg, 4);
	dnode_t *rootdn;
	const char		*opts;
	int			 rc;
	ENTRY;

	if (o->od_os != NULL)
		RETURN(0);

	if (mntdev == NULL || svname == NULL)
		RETURN(-EINVAL);

	rc = strlcpy(o->od_mntdev, mntdev, sizeof(o->od_mntdev));
	if (rc >= sizeof(o->od_mntdev))
		RETURN(-E2BIG);

	rc = strlcpy(o->od_svname, svname, sizeof(o->od_svname));
	if (rc >= sizeof(o->od_svname))
		RETURN(-E2BIG);

	str = strstr(str, ":");
	if (str) {
		unsigned long flags;

		rc = kstrtoul(str + 1, 10, &flags);
		if (rc)
			RETURN(-EINVAL);

		if (flags & LMD_FLG_DEV_RDONLY) {
			o->od_dt_dev.dd_rdonly = 1;
			LCONSOLE_WARN("%s: set dev_rdonly on this device\n",
				      svname);
		}
	}

	if (server_name_is_ost(o->od_svname))
		o->od_is_ost = 1;

	rc = osd_objset_open(o);
	if (rc)
		RETURN(rc);

	o->od_xattr_in_sa = B_TRUE;
	o->od_max_blksz = osd_spa_maxblocksize(o->od_os->os_spa);

	rc = __osd_obj2dnode(o->od_os, o->od_rootid, &rootdn);
	if (rc)
		GOTO(err, rc);
	o->od_root = rootdn->dn_object;
	osd_dnode_rele(rootdn);

	rc = __osd_obj2dnode(o->od_os, DMU_USERUSED_OBJECT,
			     &o->od_userused_dn);
	if (rc)
		GOTO(err, rc);

	rc = __osd_obj2dnode(o->od_os, DMU_GROUPUSED_OBJECT,
			     &o->od_groupused_dn);
	if (rc)
		GOTO(err, rc);

#ifdef ZFS_PROJINHERIT
	if (dmu_objset_projectquota_enabled(o->od_os)) {
		rc = __osd_obj2dnode(o->od_os, DMU_PROJECTUSED_OBJECT,
				     &o->od_projectused_dn);
		if (rc && rc != -ENOENT)
			GOTO(err, rc);
	}
#endif

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

	rc = osd_objset_register_callbacks(o);
	if (rc)
		GOTO(err, rc);

	rc = osd_procfs_init(o, o->od_svname);
	if (rc)
		GOTO(err, rc);

	/* initialize quota slave instance */
	o->od_quota_slave = qsd_init(env, o->od_svname, &o->od_dt_dev,
				     o->od_proc_entry);
	if (IS_ERR(o->od_quota_slave)) {
		rc = PTR_ERR(o->od_quota_slave);
		o->od_quota_slave = NULL;
		GOTO(err, rc);
	}

#ifdef HAVE_DMU_USEROBJ_ACCOUNTING
	if (!osd_dmu_userobj_accounting_available(o))
		CWARN("%s: dnode accounting not enabled: "
		      "enable feature@userobj_accounting in pool\n",
		      o->od_mntdev);
#endif

	/* parse mount option "noacl", and enable ACL by default */
	opts = lustre_cfg_string(cfg, 3);
	if (opts == NULL || strstr(opts, "noacl") == NULL)
		o->od_posix_acl = 1;

	osd_unlinked_drain(env, o);
err:
	if (rc && o->od_os) {
		osd_dmu_objset_disown(o->od_os, B_FALSE, o);
		o->od_os = NULL;
	}

	RETURN(rc);
}

static void osd_umount(const struct lu_env *env, struct osd_device *o)
{
	ENTRY;

	if (atomic_read(&o->od_zerocopy_alloc))
		CERROR("%s: lost %d allocated page(s)\n", o->od_svname,
		       atomic_read(&o->od_zerocopy_alloc));
	if (atomic_read(&o->od_zerocopy_loan))
		CERROR("%s: lost %d loaned abuf(s)\n", o->od_svname,
		       atomic_read(&o->od_zerocopy_loan));
	if (atomic_read(&o->od_zerocopy_pin))
		CERROR("%s: lost %d pinned dbuf(s)\n", o->od_svname,
		       atomic_read(&o->od_zerocopy_pin));

	if (o->od_unlinked) {
		osd_dnode_rele(o->od_unlinked);
		o->od_unlinked = NULL;
	}
	if (o->od_userused_dn) {
		osd_dnode_rele(o->od_userused_dn);
		o->od_userused_dn = NULL;
	}
	if (o->od_groupused_dn) {
		osd_dnode_rele(o->od_groupused_dn);
		o->od_groupused_dn = NULL;
	}

#ifdef ZFS_PROJINHERIT
	if (o->od_projectused_dn) {
		osd_dnode_rele(o->od_projectused_dn);
		o->od_projectused_dn = NULL;
	}
#endif

	if (o->od_os != NULL) {
		if (!o->od_dt_dev.dd_rdonly)
			/* force a txg sync to get all commit callbacks */
			txg_wait_synced(dmu_objset_pool(o->od_os), 0ULL);

		/* close the object set */
		osd_dmu_objset_disown(o->od_os, B_FALSE, o);
		o->od_os = NULL;
	}

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

out:
	RETURN(rc);
}

static struct lu_device *osd_device_fini(const struct lu_env *env,
					 struct lu_device *dev);

static struct lu_device *osd_device_alloc(const struct lu_env *env,
					  struct lu_device_type *type,
					  struct lustre_cfg *cfg)
{
	struct osd_device	*dev;
	struct osd_seq_list	*osl;
	int			rc;

	OBD_ALLOC_PTR(dev);
	if (dev == NULL)
		return ERR_PTR(-ENOMEM);

	osl = &dev->od_seq_list;
	INIT_LIST_HEAD(&osl->osl_seq_list);
	rwlock_init(&osl->osl_seq_list_lock);
	sema_init(&osl->osl_seq_init_sem, 1);

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
	int		   rc;
	ENTRY;


	if (o->od_os) {
		osd_objset_unregister_callbacks(o);
		if (!o->od_dt_dev.dd_rdonly) {
			osd_sync(env, lu2dt_dev(d));
			txg_wait_callbacks(
					spa_get_dsl(dmu_objset_spa(o->od_os)));
		}
	}

	/* now with all the callbacks completed we can cleanup the remainings */
	osd_shutdown(env, o);
	osd_oi_fini(env, o);

	rc = osd_procfs_fini(o);
	if (rc) {
		CERROR("proc fini error %d\n", rc);
		RETURN(ERR_PTR(rc));
	}

	if (o->od_os)
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
		if (rc > 0 || rc == -ENOSYS) {
			rc = class_process_proc_param(PARAM_OST,
						      lprocfs_osd_obd_vars,
						      cfg, &o->od_dt_dev);
			if (rc > 0)
				rc = 0;
		}
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

	spin_lock(&obd->obd_dev_lock);
	osd->od_connects++;
	spin_unlock(&obd->obd_dev_lock);

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
	spin_lock(&obd->obd_dev_lock);
	osd->od_connects--;
	if (osd->od_connects == 0)
		release = 1;
	spin_unlock(&obd->obd_dev_lock);

	rc = class_disconnect(exp); /* bz 9811 */

	if (rc == 0 && release)
		class_manual_cleanup(obd);
	RETURN(rc);
}

static int osd_fid_init(const struct lu_env *env, struct osd_device *osd)
{
	struct seq_server_site	*ss = osd_seq_site(osd);
	int			rc;
	ENTRY;

	if (osd->od_is_ost || osd->od_cl_seq != NULL)
		RETURN(0);

	if (unlikely(ss == NULL))
		RETURN(-ENODEV);

	OBD_ALLOC_PTR(osd->od_cl_seq);
	if (osd->od_cl_seq == NULL)
		RETURN(-ENOMEM);

	rc = seq_client_init(osd->od_cl_seq, NULL, LUSTRE_SEQ_METADATA,
			     osd->od_svname, ss->ss_server_seq);

	if (rc != 0) {
		OBD_FREE_PTR(osd->od_cl_seq);
		osd->od_cl_seq = NULL;
	}

	RETURN(rc);
}

static int osd_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *dev)
{
	struct osd_device	*osd = osd_dev(dev);
	int			 rc = 0;
	ENTRY;

	if (osd->od_quota_slave != NULL) {
		/* set up quota slave objects */
		rc = qsd_prepare(env, osd->od_quota_slave);
		if (rc != 0)
			RETURN(rc);
	}

	rc = osd_fid_init(env, osd);

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

int osd_fid_alloc(const struct lu_env *env, struct obd_export *exp,
		  struct lu_fid *fid, struct md_op_data *op_data)
{
	struct osd_device *osd = osd_dev(exp->exp_obd->obd_lu_dev);

	return seq_client_alloc_fid(env, osd->od_cl_seq, fid);
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
	.o_disconnect	= osd_obd_disconnect,
	.o_fid_alloc	= osd_fid_alloc
};

static int __init osd_init(void)
{
	int rc;

	rc = osd_options_init();
	if (rc)
		return rc;

	rc = lu_kmem_init(osd_caches);
	if (rc)
		return rc;

	rc = class_register_type(&osd_obd_device_ops, NULL, true, NULL,
				 LUSTRE_OSD_ZFS_NAME, &osd_device_type);
	if (rc)
		lu_kmem_fini(osd_caches);
	return rc;
}

static void __exit osd_exit(void)
{
	class_unregister_type(LUSTRE_OSD_ZFS_NAME);
	lu_kmem_fini(osd_caches);
}

extern unsigned int osd_oi_count;
module_param(osd_oi_count, int, 0444);
MODULE_PARM_DESC(osd_oi_count, "Number of Object Index containers to be created, it's only valid for new filesystem.");

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Device ("LUSTRE_OSD_ZFS_NAME")");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(osd_init);
module_exit(osd_exit);
