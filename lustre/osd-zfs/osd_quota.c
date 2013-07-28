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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann@whamcloud.com>
 */

#include <lustre_quota.h>
#include <obd.h>
#include "osd_internal.h"

#include <sys/dnode.h>
#include <sys/spa.h>
#include <sys/zap.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_prop.h>
#include <sys/txg.h>

/*
 * the structure tracks per-ID change/state
 */
struct zfs_id_change {
	struct hlist_node	zic_hash;
	__u64			zic_id;
	atomic_t		zic_num;
};

/*
 * callback data for cfs_hash_for_each_safe()
 * used in txg commit and OSD cleanup path
 */
struct hash_cbdata {
	struct osd_device	*hcb_osd;
	uint64_t		 hcb_zapid;
	dmu_tx_t		*hcb_tx;
};

/**
 * Helper function to retrieve DMU object id from fid for accounting object
 */
static inline uint64_t osd_quota_fid2dmu(const struct lu_fid *fid)
{
	LASSERT(fid_is_acct(fid));
	if (fid_oid(fid) == ACCT_GROUP_OID)
		return DMU_GROUPUSED_OBJECT;
	return DMU_USERUSED_OBJECT;
}

/*
 * a note about locking:
 *  entries in per-OSD cache never go before umount,
 *  so there is no need in locking for lookups.
 *
 *  entries in per-txg deltas never go before txg is closed,
 *  there is no concurrency between removal/insertions.
 *
 * also, given all above, there is no need in reference counting.
 */
static struct zfs_id_change *osd_zfs_lookup_by_id(cfs_hash_t *hash, __u64 id)
{
	struct zfs_id_change	*za = NULL;
	struct hlist_node	*hnode;
	cfs_hash_bd_t		 bd;

	cfs_hash_bd_get(hash, &id, &bd);
	hnode = cfs_hash_bd_peek_locked(hash, &bd, &id);
	if (hnode != NULL)
		za = container_of0(hnode, struct zfs_id_change, zic_hash);

	return za;
}

static struct zfs_id_change *lookup_or_create_by_id(struct osd_device *osd,
						cfs_hash_t *hash, __u64 id)
{
	struct zfs_id_change	*za, *tmp;
	struct hlist_node	*hnode;
	cfs_hash_bd_t		 bd;

	za = osd_zfs_lookup_by_id(hash, id);
	if (likely(za != NULL))
		return za;

	OBD_ALLOC_PTR(za);
	if (unlikely(za == NULL))
		return NULL;

	za->zic_id = id;

	cfs_hash_bd_get(hash, &id, &bd);
	spin_lock(&osd->od_known_txg_lock);
	hnode = cfs_hash_bd_findadd_locked(hash, &bd, &id, &za->zic_hash, 1);
	LASSERT(hnode != NULL);
	tmp = container_of0(hnode, struct zfs_id_change, zic_hash);
	spin_unlock(&osd->od_known_txg_lock);

	if (tmp == za) {
		/*
		 * our structure got into the hash
		 */
	} else {
		/* somebody won the race, we wasted the cycles */
		OBD_FREE_PTR(za);
	}

	return tmp;
}

/*
 * used to maintain per-txg deltas
 */
static int osd_zfs_acct_id(const struct lu_env *env, cfs_hash_t *hash,
			   __u64 id, int delta, struct osd_thandle *oh)
{
	struct osd_device	*osd = osd_dt_dev(oh->ot_super.th_dev);
	struct zfs_id_change	*za;

	LASSERT(hash);
	LASSERT(oh->ot_tx);
	LASSERT(oh->ot_tx->tx_txg == osd->od_known_txg);
	LASSERT(osd->od_acct_delta != NULL);

	za = lookup_or_create_by_id(osd, hash, id);
	if (unlikely(za == NULL))
		return -ENOMEM;

	atomic_add(delta, &za->zic_num);

	return 0;
}

/*
 * this function is used to maintain current state for given ID:
 * at the beginning it initializes the cache from correspoding ZAP
 */
static void osd_zfs_acct_cache_init(const struct lu_env *env,
				    struct osd_device *osd,
				    cfs_hash_t *hash, __u64 oid,
				    __u64 id, int delta,
				    struct osd_thandle *oh)
{
	char			*buf  = osd_oti_get(env)->oti_buf;
	struct hlist_node	*hnode;
	cfs_hash_bd_t		 bd;
	struct zfs_id_change	*za, *tmp;
	__u64			 v;
	int			 rc;

	za = osd_zfs_lookup_by_id(hash, id);
	if (likely(za != NULL))
		goto apply;

	/*
	 * any concurrent thread is running in the same txg, so no on-disk
	 * accounting ZAP can be modified until this txg is closed
	 * thus all the concurrent threads must be getting the same value
	 * from that ZAP and we don't need to serialize lookups
	 */
	snprintf(buf, sizeof(osd_oti_get(env)->oti_buf), "%llx", id);
	/* XXX: we should be using zap_lookup_int_key(), but it consumes
	 *	20 bytes on the stack for buf .. */
	rc = -zap_lookup(osd->od_objset.os, oid, buf, sizeof(uint64_t), 1, &v);
	if (rc == -ENOENT) {
		v = 0;
	} else if (unlikely(rc != 0)) {
		CERROR("%s: can't access accounting zap %llu\n",
		       osd->od_svname, oid);
		return;
	}

	OBD_ALLOC_PTR(za);
	if (unlikely(za == NULL)) {
		CERROR("%s: can't allocate za\n", osd->od_svname);
		return;
	}

	za->zic_id = id;
	atomic_set(&za->zic_num, v);

	cfs_hash_bd_get(hash, &id, &bd);
	spin_lock(&osd->od_known_txg_lock);
	hnode = cfs_hash_bd_findadd_locked(hash, &bd, &id, &za->zic_hash, 1);
	LASSERT(hnode != NULL);
	tmp = container_of0(hnode, struct zfs_id_change, zic_hash);
	spin_unlock(&osd->od_known_txg_lock);

	if (tmp == za) {
		/* our structure got into the hash */
		if (rc == -ENOENT) {
			/* there was no entry in ZAP yet, we have
			 * to initialize with 0, so that accounting
			 * reports can find that and then find our
			 * cached value. */
			v = 0;
			rc = -zap_update(osd->od_objset.os, oid, buf,
					 sizeof(uint64_t), 1, &v, oh->ot_tx);
			if (unlikely(rc != 0))
				CERROR("%s: can't initialize: rc = %d\n",
				       osd->od_svname, rc);
		}
	} else {
		/* somebody won the race, we wasted the cycles */
		OBD_FREE_PTR(za);
		za = tmp;
	}

apply:
	LASSERT(za != NULL);
	atomic_add(delta, &za->zic_num);
}

static __u32 acct_hashfn(cfs_hash_t *hash_body, const void *key, unsigned mask)
{
	const __u64	*id = key;
	__u32		 result;

	result = (__u32) *id;
	return result % mask;
}

static void *acct_key(struct hlist_node *hnode)
{
	struct zfs_id_change	*ac;

	ac = hlist_entry(hnode, struct zfs_id_change, zic_hash);
	return &ac->zic_id;
}

static int acct_hashkey_keycmp(const void *key,
			       struct hlist_node *compared_hnode)
{
	struct zfs_id_change	*ac;
	const __u64		*id = key;

	ac = hlist_entry(compared_hnode, struct zfs_id_change, zic_hash);
	return *id == ac->zic_id;
}

static void *acct_hashobject(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct zfs_id_change, zic_hash);
}

static cfs_hash_ops_t acct_hash_operations = {
	.hs_hash        = acct_hashfn,
	.hs_key         = acct_key,
	.hs_keycmp      = acct_hashkey_keycmp,
	.hs_object      = acct_hashobject,
};

#define ACCT_HASH_OPS (CFS_HASH_NO_LOCK|CFS_HASH_NO_ITEMREF|CFS_HASH_ADD_TAIL)

int osd_zfs_acct_init(const struct lu_env *env, struct osd_device *o)
{
	int rc = 0;
	ENTRY;

	spin_lock_init(&o->od_known_txg_lock);

	/* global structure representing current state for given ID */
	o->od_acct_usr = cfs_hash_create("usr", 4, 4, 4, 0, 0, 0,
					 &acct_hash_operations,
					 ACCT_HASH_OPS);
	if (o->od_acct_usr == NULL)
		GOTO(out, rc = -ENOMEM);

	o->od_acct_grp = cfs_hash_create("grp", 4, 4, 4, 0, 0, 0,
					 &acct_hash_operations,
					 ACCT_HASH_OPS);
	if (o->od_acct_grp == NULL)
		GOTO(out, rc = -ENOMEM);

out:
	RETURN(rc);
}

static int osd_zfs_delete_item(cfs_hash_t *hs, cfs_hash_bd_t *bd,
			       struct hlist_node *node, void *data)
{
	struct hash_cbdata	*d = data;
	struct zfs_id_change	*za;
	__u64			 v;
	char			 buf[12];
	int			 rc;

	za = hlist_entry(node, struct zfs_id_change, zic_hash);

	/*
	 * XXX: should we try to fix accounting we failed to update before?
	 */
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 5, 70, 0)
	/*
	 * extra checks to ensure our cache matches on-disk state
	 */
	snprintf(buf, sizeof(buf), "%llx", za->zic_id);
	rc = -zap_lookup(d->hcb_osd->od_objset.os, d->hcb_zapid,
			 buf, sizeof(uint64_t), 1, &v);
	/* pairs with zero value are removed by ZAP automatically */
	if (rc == -ENOENT)
		v = 0;
	if (atomic_read(&za->zic_num) != v) {
		CERROR("%s: INVALID ACCOUNTING FOR %llu %d != %lld: rc = %d\n",
		       d->hcb_osd->od_svname, za->zic_id,
		       atomic_read(&za->zic_num), v, rc);
		/* XXX: to catch with automated testing */
		LBUG();
	}
#else
#warning "remove this additional check before release"
#endif

	cfs_hash_bd_del_locked(hs, bd, node);
	OBD_FREE_PTR(za);

	return 0;
}

void osd_zfs_acct_fini(const struct lu_env *env, struct osd_device *o)
{
	struct hash_cbdata	cbdata;

	cbdata.hcb_osd = o;

	/* release object accounting cache (owners) */
	cbdata.hcb_zapid = o->od_iusr_oid;

	if (o->od_acct_usr) {
		cfs_hash_for_each_safe(o->od_acct_usr, osd_zfs_delete_item,
				       &cbdata);
		cfs_hash_putref(o->od_acct_usr);
		o->od_acct_usr = NULL;
	}

	/* release object accounting cache (groups) */
	cbdata.hcb_zapid = o->od_igrp_oid;

	if (o->od_acct_grp) {
		cfs_hash_for_each_safe(o->od_acct_grp, osd_zfs_delete_item,
				       &cbdata);
		cfs_hash_putref(o->od_acct_grp);
		o->od_acct_grp = NULL;
	}
}

static int osd_zfs_commit_item(cfs_hash_t *hs, cfs_hash_bd_t *bd,
			       struct hlist_node *node, void *data)
{
	struct hash_cbdata	*d = data;
	struct osd_device	*osd = d->hcb_osd;
	struct zfs_id_change	*za;
	int			 rc;

	za = hlist_entry(node, struct zfs_id_change, zic_hash);

	rc = -zap_increment_int(osd->od_objset.os, d->hcb_zapid, za->zic_id,
				atomic_read(&za->zic_num), d->hcb_tx);
	if (unlikely(rc != 0))
		CERROR("%s: quota update for UID "LPU64" failed: rc = %d\n",
		       osd->od_svname, za->zic_id, rc);

	cfs_hash_bd_del_locked(hs, bd, node);
	OBD_FREE_PTR(za);

	return 0;
}

/*
 * this function is called as part of txg commit procedure,
 * no more normal changes are allowed to this txg.
 * we go over all the changes cached in per-txg structure
 * and apply them to actual ZAPs
 */
static void osd_zfs_acct_update(void *arg, void *arg2, dmu_tx_t *tx)
{
	struct osd_zfs_acct_txg	*zat = arg;
	struct osd_device	*osd = zat->zat_osd;
	struct hash_cbdata	 cbdata;

	cbdata.hcb_osd = osd;
	cbdata.hcb_tx = tx;

	CDEBUG(D_OTHER, "COMMIT %llu on %s\n", tx->tx_txg, osd->od_svname);

	/* apply changes related to the owners */
	cbdata.hcb_zapid = osd->od_iusr_oid;
	cfs_hash_for_each_safe(zat->zat_usr, osd_zfs_commit_item, &cbdata);

	/* apply changes related to the groups */
	cbdata.hcb_zapid = osd->od_igrp_oid;
	cfs_hash_for_each_safe(zat->zat_grp, osd_zfs_commit_item, &cbdata);

	cfs_hash_putref(zat->zat_usr);
	cfs_hash_putref(zat->zat_grp);

	OBD_FREE_PTR(zat);
}

static int osd_zfs_acct_check(void *arg1, void *arg2, dmu_tx_t *tx)
{
	/* check function isn't used currently */
	return 0;
}

/*
 * if any change to the object accounting is going to happen,
 * we create one structure per txg to track all the changes
 * and register special routine to be called as part of txg
 * commit procedure.
 */
int osd_zfs_acct_trans_start(const struct lu_env *env, struct osd_thandle *oh)
{
	struct osd_device	*osd = osd_dt_dev(oh->ot_super.th_dev);
	struct osd_zfs_acct_txg *ac = NULL;
	int			 rc = 0, add_work = 0;

	if (likely(oh->ot_tx->tx_txg == osd->od_known_txg)) {
		/* already created */
		return 0;
	}

	OBD_ALLOC_PTR(ac);
	if (unlikely(ac == NULL))
		return -ENOMEM;

	ac->zat_usr = cfs_hash_create("usr", 4, 4, 4, 0, 0, 0,
				      &acct_hash_operations,
				      ACCT_HASH_OPS);
	if (unlikely(ac->zat_usr == NULL)) {
		CERROR("%s: can't allocate hash for accounting\n",
			osd->od_svname);
		GOTO(out, rc = -ENOMEM);
	}

	ac->zat_grp = cfs_hash_create("grp", 4, 4, 4, 0, 0, 0,
				      &acct_hash_operations,
				      ACCT_HASH_OPS);
	if (unlikely(ac->zat_grp == NULL)) {
		CERROR("%s: can't allocate hash for accounting\n",
			osd->od_svname);
		GOTO(out, rc = -ENOMEM);
	}

	spin_lock(&osd->od_known_txg_lock);
	if (oh->ot_tx->tx_txg != osd->od_known_txg) {
		osd->od_acct_delta = ac;
		osd->od_known_txg = oh->ot_tx->tx_txg;
		add_work = 1;
	}
	spin_unlock(&osd->od_known_txg_lock);

	/* schedule a callback to be run in the context of txg
	 * once the latter is closed and syncing */
	if (add_work) {
		spa_t *spa = dmu_objset_spa(osd->od_objset.os);
		LASSERT(ac->zat_osd == NULL);
		ac->zat_osd = osd;
		dsl_sync_task_do_nowait(spa_get_dsl(spa),
					osd_zfs_acct_check,
					osd_zfs_acct_update,
					ac, NULL, 128, oh->ot_tx);

		/* no to be freed now */
		ac = NULL;
	}

out:
	if (ac != NULL) {
		/* another thread has installed new structure already */
		if (ac->zat_usr)
			cfs_hash_putref(ac->zat_usr);
		if (ac->zat_grp)
			cfs_hash_putref(ac->zat_grp);
		OBD_FREE_PTR(ac);
	}

	return rc;
}

void osd_zfs_acct_uid(const struct lu_env *env, struct osd_device *osd,
		      __u64 uid, int delta, struct osd_thandle *oh)
{
	int rc;

	/* add per-txg job to update accounting */
	rc = osd_zfs_acct_trans_start(env, oh);
	if (unlikely(rc != 0))
		return;

	/* maintain per-OSD cached value */
	osd_zfs_acct_cache_init(env, osd, osd->od_acct_usr,
				osd->od_iusr_oid, uid, delta, oh);

	/* maintain per-TXG delta */
	osd_zfs_acct_id(env, osd->od_acct_delta->zat_usr, uid, delta, oh);

}

void osd_zfs_acct_gid(const struct lu_env *env, struct osd_device *osd,
		      __u64 gid, int delta, struct osd_thandle *oh)
{
	int rc;

	/* add per-txg job to update accounting */
	rc = osd_zfs_acct_trans_start(env, oh);
	if (unlikely(rc != 0))
		return;

	/* maintain per-OSD cached value */
	osd_zfs_acct_cache_init(env, osd, osd->od_acct_grp,
				osd->od_igrp_oid, gid, delta, oh);

	/* maintain per-TXG delta */
	osd_zfs_acct_id(env, osd->od_acct_delta->zat_grp, gid, delta, oh);
}

/**
 * Space Accounting Management
 */

/**
 * Return space usage consumed by a given uid or gid.
 * Block usage is accurrate since it is maintained by DMU itself.
 * However, DMU does not provide inode accounting, so the #inodes in use
 * is estimated from the block usage and statfs information.
 *
 * \param env   - is the environment passed by the caller
 * \param dtobj - is the accounting object
 * \param dtrec - is the record to fill with space usage information
 * \param dtkey - is the id the of the user or group for which we would
 *                like to access disk usage.
 * \param capa - is the capability, not used.
 *
 * \retval +ve - success : exact match
 * \retval -ve - failure
 */
static int osd_acct_index_lookup(const struct lu_env *env,
				 struct dt_object *dtobj,
				 struct dt_rec *dtrec,
				 const struct dt_key *dtkey,
				 struct lustre_capa *capa)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	char			*buf  = info->oti_buf;
	struct lquota_acct_rec	*rec  = (struct lquota_acct_rec *)dtrec;
	struct osd_object	*obj = osd_dt_obj(dtobj);
	struct osd_device	*osd = osd_obj2dev(obj);
	uint64_t		 oid;
	struct zfs_id_change	*za = NULL;
	int			 rc;
	ENTRY;

	rec->bspace = rec->ispace = 0;

	/* convert the 64-bit uid/gid into a string */
	sprintf(buf, "%llx", *((__u64 *)dtkey));
	/* fetch DMU object ID (DMU_USERUSED_OBJECT/DMU_GROUPUSED_OBJECT) to be
	 * used */
	oid = osd_quota_fid2dmu(lu_object_fid(&dtobj->do_lu));

	/* disk usage (in bytes) is maintained by DMU.
	 * DMU_USERUSED_OBJECT/DMU_GROUPUSED_OBJECT are special objects which
	 * not associated with any dmu_but_t (see dnode_special_open()).
	 * As a consequence, we cannot use udmu_zap_lookup() here since it
	 * requires a valid oo_db. */
	rc = -zap_lookup(osd->od_objset.os, oid, buf, sizeof(uint64_t), 1,
			&rec->bspace);
	if (rc == -ENOENT)
		/* user/group has not created anything yet */
		CDEBUG(D_QUOTA, "%s: id %s not found in DMU accounting ZAP\n",
		       osd->od_svname, buf);
	else if (rc)
		RETURN(rc);

	if (osd->od_quota_iused_est) {
		if (rec->bspace != 0)
			/* estimate #inodes in use */
			rec->ispace = udmu_objset_user_iused(&osd->od_objset,
							     rec->bspace);
		RETURN(+1);
	}

	/* as for inode accounting, it is not maintained by DMU, so we just
	 * use our own ZAP to track inode usage */
	if (oid == DMU_USERUSED_OBJECT) {
		za = osd_zfs_lookup_by_id(osd->od_acct_usr,
					 *((__u64 *)dtkey));
	} else if (oid == DMU_GROUPUSED_OBJECT) {
		za = osd_zfs_lookup_by_id(osd->od_acct_grp,
					 *((__u64 *)dtkey));
	}
	if (za) {
		rec->ispace = atomic_read(&za->zic_num);
	} else {
		rc = -zap_lookup(osd->od_objset.os, obj->oo_db->db_object,
				buf, sizeof(uint64_t), 1, &rec->ispace);
	}

	if (rc == -ENOENT)
		/* user/group has not created any file yet */
		CDEBUG(D_QUOTA, "%s: id %s not found in accounting ZAP\n",
		       osd->od_svname, buf);
	else if (rc)
		RETURN(rc);

	RETURN(+1);
}

/**
 * Initialize osd Iterator for given osd index object.
 *
 * \param  dt    - osd index object
 * \param  attr  - not used
 * \param  capa  - BYPASS_CAPA
 */
static struct dt_it *osd_it_acct_init(const struct lu_env *env,
				      struct dt_object *dt,
				      __u32 attr,
				      struct lustre_capa *capa)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	struct osd_it_quota	*it;
	struct lu_object	*lo   = &dt->do_lu;
	struct osd_device	*osd  = osd_dev(lo->lo_dev);
	int			 rc;
	ENTRY;

	LASSERT(lu_object_exists(lo));

	if (info == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	it = &info->oti_it_quota;
	memset(it, 0, sizeof(*it));
	it->oiq_oid = osd_quota_fid2dmu(lu_object_fid(lo));

	if (it->oiq_oid == DMU_GROUPUSED_OBJECT)
		it->oiq_hash = osd->od_acct_grp;
	else if (it->oiq_oid == DMU_USERUSED_OBJECT)
		it->oiq_hash = osd->od_acct_usr;
	else
		LBUG();

	/* initialize zap cursor */
	rc = -udmu_zap_cursor_init(&it->oiq_zc, &osd->od_objset, it->oiq_oid,0);
	if (rc)
		RETURN(ERR_PTR(rc));

	/* take object reference */
	lu_object_get(lo);
	it->oiq_obj   = osd_dt_obj(dt);
	it->oiq_reset = 1;

	RETURN((struct dt_it *)it);
}

/**
 * Free given iterator.
 *
 * \param  di   - osd iterator
 */
static void osd_it_acct_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	ENTRY;
	udmu_zap_cursor_fini(it->oiq_zc);
	lu_object_put(env, &it->oiq_obj->oo_dt.do_lu);
	EXIT;
}

/**
 * Move on to the next valid entry.
 *
 * \param  di   - osd iterator
 *
 * \retval +ve  - iterator reached the end
 * \retval   0  - iterator has not reached the end yet
 * \retval -ve  - unexpected failure
 */
static int osd_it_acct_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	int			 rc;
	ENTRY;

	if (it->oiq_reset == 0)
		zap_cursor_advance(it->oiq_zc);
	it->oiq_reset = 0;
	rc = -udmu_zap_cursor_retrieve_key(env, it->oiq_zc, NULL, 32);
	if (rc == -ENOENT) /* reached the end */
		RETURN(+1);
	RETURN(rc);
}

/**
 * Return pointer to the key under iterator.
 *
 * \param  di   - osd iterator
 */
static struct dt_key *osd_it_acct_key(const struct lu_env *env,
				      const struct dt_it *di)
{
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	struct osd_thread_info	*info = osd_oti_get(env);
	char			*buf  = info->oti_buf;
	char			*p;
	int			 rc;
	ENTRY;

	it->oiq_reset = 0;
	rc = -udmu_zap_cursor_retrieve_key(env, it->oiq_zc, buf, 32);
	if (rc)
		RETURN(ERR_PTR(rc));
	it->oiq_id = simple_strtoull(buf, &p, 16);
	RETURN((struct dt_key *) &it->oiq_id);
}

/**
 * Return size of key under iterator (in bytes)
 *
 * \param  di   - osd iterator
 */
static int osd_it_acct_key_size(const struct lu_env *env,
				const struct dt_it *di)
{
	ENTRY;
	RETURN((int)sizeof(uint64_t));
}

/**
 * Return pointer to the record under iterator.
 *
 * \param  di    - osd iterator
 * \param  attr  - not used
 */
static int osd_it_acct_rec(const struct lu_env *env,
			   const struct dt_it *di,
			   struct dt_rec *dtrec, __u32 attr)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	char			*buf  = info->oti_buf;
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	struct lquota_acct_rec	*rec  = (struct lquota_acct_rec *)dtrec;
	struct osd_object	*obj = it->oiq_obj;
	struct osd_device	*osd = osd_obj2dev(obj);
	int			 bytes_read;
	struct zfs_id_change	*za;
	int			 rc;
	ENTRY;

	it->oiq_reset = 0;
	rec->ispace = rec->bspace = 0;

	/* retrieve block usage from the DMU accounting object */
	rc = -udmu_zap_cursor_retrieve_value(env, it->oiq_zc,
					     (char *)&rec->bspace,
					     sizeof(uint64_t), &bytes_read);
	if (rc)
		RETURN(rc);

	if (osd->od_quota_iused_est) {
		if (rec->bspace != 0)
			/* estimate #inodes in use */
			rec->ispace = udmu_objset_user_iused(&osd->od_objset,
							     rec->bspace);
		RETURN(0);
	}

	/* retrieve key associated with the current cursor */
	rc = -udmu_zap_cursor_retrieve_key(env, it->oiq_zc, buf, 32);
	if (rc)
		RETURN(rc);

	/* inode accounting is not maintained by DMU, so we use our own ZAP to
	 * track inode usage */
	za = osd_zfs_lookup_by_id(it->oiq_hash, it->oiq_id);
	if (za != NULL) {
		/* found in the cache */
		rec->ispace = atomic_read(&za->zic_num);
	} else {
		 rc = -zap_lookup(osd->od_objset.os,
				  it->oiq_obj->oo_db->db_object,
				  buf, sizeof(uint64_t), 1, &rec->ispace);
		 if (rc == -ENOENT) {
			/* user/group has not created any file yet */
			CDEBUG(D_QUOTA, "%s: id %s not found in ZAP\n",
			       osd->od_svname, buf);
			rc = 0;
		}
	}

	RETURN(rc);
}

/**
 * Returns cookie for current Iterator position.
 *
 * \param  di    - osd iterator
 */
static __u64 osd_it_acct_store(const struct lu_env *env,
			       const struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	ENTRY;
	it->oiq_reset = 0;
	RETURN(udmu_zap_cursor_serialize(it->oiq_zc));
}

/**
 * Restore iterator from cookie. if the \a hash isn't found,
 * restore the first valid record.
 *
 * \param  di    - osd iterator
 * \param  hash  - iterator location cookie
 *
 * \retval +ve  - di points to exact matched key
 * \retval  0   - di points to the first valid record
 * \retval -ve  - failure
 */
static int osd_it_acct_load(const struct lu_env *env,
			    const struct dt_it *di, __u64 hash)
{
	struct osd_it_quota	*it  = (struct osd_it_quota *)di;
	struct osd_device	*osd = osd_obj2dev(it->oiq_obj);
	zap_cursor_t		*zc;
	int			 rc;
	ENTRY;

	/* create new cursor pointing to the new hash */
	rc = -udmu_zap_cursor_init(&zc, &osd->od_objset, it->oiq_oid, hash);
	if (rc)
		RETURN(rc);
	udmu_zap_cursor_fini(it->oiq_zc);
	it->oiq_zc = zc;
	it->oiq_reset = 0;

	rc = -udmu_zap_cursor_retrieve_key(env, it->oiq_zc, NULL, 32);
	if (rc == 0)
		RETURN(+1);
	else if (rc == -ENOENT)
		RETURN(0);
	RETURN(rc);
}

/**
 * Move Iterator to record specified by \a key, if the \a key isn't found,
 * move to the first valid record.
 *
 * \param  di   - osd iterator
 * \param  key  - uid or gid
 *
 * \retval +ve  - di points to exact matched key
 * \retval 0    - di points to the first valid record
 * \retval -ve  - failure
 */
static int osd_it_acct_get(const struct lu_env *env, struct dt_it *di,
		const struct dt_key *key)
{
	ENTRY;

	/* XXX: like osd_zap_it_get(), API is currently broken */
	LASSERT(*((__u64 *)key) == 0);

	RETURN(osd_it_acct_load(env, di, 0));
}

/**
 * Release Iterator
 *
 * \param  di   - osd iterator
 */
static void osd_it_acct_put(const struct lu_env *env, struct dt_it *di)
{
}

/**
 * Index and Iterator operations for accounting objects
 */
const struct dt_index_operations osd_acct_index_ops = {
	.dio_lookup = osd_acct_index_lookup,
	.dio_it     = {
		.init		= osd_it_acct_init,
		.fini		= osd_it_acct_fini,
		.get		= osd_it_acct_get,
		.put		= osd_it_acct_put,
		.next		= osd_it_acct_next,
		.key		= osd_it_acct_key,
		.key_size	= osd_it_acct_key_size,
		.rec		= osd_it_acct_rec,
		.store		= osd_it_acct_store,
		.load		= osd_it_acct_load
	}
};

/**
 * Quota Enforcement Management
 */

/*
 * Wrapper for qsd_op_begin().
 *
 * \param env    - the environment passed by the caller
 * \param osd    - is the osd_device
 * \param uid    - user id of the inode
 * \param gid    - group id of the inode
 * \param space  - how many blocks/inodes will be consumed/released
 * \param oh     - osd transaction handle
 * \param is_blk - block quota or inode quota?
 * \param flags  - if the operation is write, return no user quota, no
 *                  group quota, or sync commit flags to the caller
 * \param force  - set to 1 when changes are performed by root user and thus
 *                  can't failed with EDQUOT
 *
 * \retval 0      - success
 * \retval -ve    - failure
 */
int osd_declare_quota(const struct lu_env *env, struct osd_device *osd,
		      qid_t uid, qid_t gid, long long space,
		      struct osd_thandle *oh, bool is_blk, int *flags,
		      bool force)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	struct lquota_id_info	*qi = &info->oti_qi;
	struct qsd_instance     *qsd = osd->od_quota_slave;
	int			 rcu, rcg; /* user & group rc */
	ENTRY;

	if (unlikely(qsd == NULL))
		/* quota slave instance hasn't been allocated yet */
		RETURN(0);

	/* let's start with user quota */
	qi->lqi_id.qid_uid = uid;
	qi->lqi_type       = USRQUOTA;
	qi->lqi_space      = space;
	qi->lqi_is_blk     = is_blk;
	rcu = qsd_op_begin(env, qsd, &oh->ot_quota_trans, qi, flags);

	if (force && (rcu == -EDQUOT || rcu == -EINPROGRESS))
		/* ignore EDQUOT & EINPROGRESS when changes are done by root */
		rcu = 0;

	/* For non-fatal error, we want to continue to get the noquota flags
	 * for group id. This is only for commit write, which has @flags passed
	 * in. See osd_declare_write_commit().
	 * When force is set to true, we also want to proceed with the gid */
	if (rcu && (rcu != -EDQUOT || flags == NULL))
		RETURN(rcu);

	/* and now group quota */
	qi->lqi_id.qid_gid = gid;
	qi->lqi_type       = GRPQUOTA;
	rcg = qsd_op_begin(env, qsd, &oh->ot_quota_trans, qi, flags);

	if (force && (rcg == -EDQUOT || rcg == -EINPROGRESS))
		/* as before, ignore EDQUOT & EINPROGRESS for root */
		rcg = 0;

	RETURN(rcu ? rcu : rcg);
}
