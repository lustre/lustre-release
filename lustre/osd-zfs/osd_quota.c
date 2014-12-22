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
 * Copyright (c) 2012, 2014, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann@whamcloud.com>
 */

#include <lustre_quota.h>
#include <obd.h>
#include "osd_internal.h"

/**
 * Helper function to retrieve DMU object id from fid for accounting object
 */
uint64_t osd_quota_fid2dmu(const struct lu_fid *fid)
{
	LASSERT(fid_is_acct(fid));
	if (fid_oid(fid) == ACCT_GROUP_OID)
		return DMU_GROUPUSED_OBJECT;
	return DMU_USERUSED_OBJECT;
}

/**
 * Helper function to estimate the number of inodes in use for a give uid/gid
 * from the block usage
 */
static uint64_t osd_objset_user_iused(struct osd_device *osd, uint64_t uidbytes)
{
	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	uint64_t uidobjs;

	/* get fresh statfs info */
	dmu_objset_space(osd->od_os, &refdbytes, &availbytes,
			 &usedobjs, &availobjs);

	/* estimate the number of objects based on the disk usage */
	uidobjs = osd_objs_count_estimate(refdbytes, usedobjs,
					  uidbytes >> SPA_MAXBLOCKSHIFT);
	if (uidbytes > 0)
		/* if we have at least 1 byte, we have at least one dnode ... */
		uidobjs = max_t(uint64_t, uidobjs, 1);

	return uidobjs;
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
	int			 rc;
	uint64_t		 oid;
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
	rc = -zap_lookup(osd->od_os, oid, buf, sizeof(uint64_t), 1,
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
			rec->ispace = osd_objset_user_iused(osd, rec->bspace);
		RETURN(+1);
	}

	/* as for inode accounting, it is not maintained by DMU, so we just
	 * use our own ZAP to track inode usage */
	rc = -zap_lookup(osd->od_os, obj->oo_db->db_object,
			 buf, sizeof(uint64_t), 1, &rec->ispace);
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

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	memset(it, 0, sizeof(*it));
	it->oiq_oid = osd_quota_fid2dmu(lu_object_fid(lo));

	/* initialize zap cursor */
	rc = osd_zap_cursor_init(&it->oiq_zc, osd->od_os, it->oiq_oid, 0);
	if (rc != 0) {
		OBD_FREE_PTR(it);
		RETURN(ERR_PTR(rc));
	}

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
	struct osd_it_quota	*it	= (struct osd_it_quota *)di;
	ENTRY;

	osd_zap_cursor_fini(it->oiq_zc);
	lu_object_put(env, &it->oiq_obj->oo_dt.do_lu);
	OBD_FREE_PTR(it);

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
	zap_attribute_t		*za = &osd_oti_get(env)->oti_za;
	int			 rc;
	ENTRY;

	if (it->oiq_reset == 0)
		zap_cursor_advance(it->oiq_zc);
	it->oiq_reset = 0;
	rc = -zap_cursor_retrieve(it->oiq_zc, za);
	if (rc == -ENOENT) /* reached the end */
		rc = 1;
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
	zap_attribute_t		*za = &osd_oti_get(env)->oti_za;
	int			 rc;
	ENTRY;

	it->oiq_reset = 0;
	rc = -zap_cursor_retrieve(it->oiq_zc, za);
	if (rc)
		RETURN(ERR_PTR(rc));
	rc = kstrtoull(za->za_name, 16, &it->oiq_id);

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

/*
 * zap_cursor_retrieve read from current record.
 * to read bytes we need to call zap_lookup explicitly.
 */
static int osd_zap_cursor_retrieve_value(const struct lu_env *env,
					 zap_cursor_t *zc,  char *buf,
					 int buf_size, int *bytes_read)
{
	zap_attribute_t *za = &osd_oti_get(env)->oti_za;
	int rc, actual_size;

	rc = -zap_cursor_retrieve(zc, za);
	if (unlikely(rc != 0))
		return -rc;

	if (unlikely(za->za_integer_length <= 0))
		return -ERANGE;

	actual_size = za->za_integer_length * za->za_num_integers;

	if (actual_size > buf_size) {
		actual_size = buf_size;
		buf_size = actual_size / za->za_integer_length;
	} else {
		buf_size = za->za_num_integers;
	}

	rc = -zap_lookup(zc->zc_objset, zc->zc_zapobj,
			 za->za_name, za->za_integer_length,
			 buf_size, buf);

	if (likely(rc == 0))
		*bytes_read = actual_size;

	return rc;
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
	zap_attribute_t		*za = &info->oti_za;
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	struct lquota_acct_rec	*rec  = (struct lquota_acct_rec *)dtrec;
	struct osd_object	*obj = it->oiq_obj;
	struct osd_device	*osd = osd_obj2dev(obj);
	int			 bytes_read;
	int			 rc;
	ENTRY;

	it->oiq_reset = 0;
	rec->ispace = rec->bspace = 0;

	/* retrieve block usage from the DMU accounting object */
	rc = osd_zap_cursor_retrieve_value(env, it->oiq_zc,
					   (char *)&rec->bspace,
					   sizeof(uint64_t), &bytes_read);
	if (rc)
		RETURN(rc);

	if (osd->od_quota_iused_est) {
		if (rec->bspace != 0)
			/* estimate #inodes in use */
			rec->ispace = osd_objset_user_iused(osd, rec->bspace);
		RETURN(0);
	}

	/* retrieve key associated with the current cursor */
	rc = -zap_cursor_retrieve(it->oiq_zc, za);
	if (unlikely(rc != 0))
		RETURN(rc);

	/* inode accounting is not maintained by DMU, so we use our own ZAP to
	 * track inode usage */
	rc = -zap_lookup(osd->od_os, it->oiq_obj->oo_db->db_object,
			 za->za_name, sizeof(uint64_t), 1, &rec->ispace);
	if (rc == -ENOENT)
		/* user/group has not created any file yet */
		CDEBUG(D_QUOTA, "%s: id %s not found in accounting ZAP\n",
		       osd->od_svname, za->za_name);
	else if (rc)
		RETURN(rc);

	RETURN(0);
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
	RETURN(osd_zap_cursor_serialize(it->oiq_zc));
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
	zap_attribute_t		*za = &osd_oti_get(env)->oti_za;
	zap_cursor_t		*zc;
	int			 rc;
	ENTRY;

	/* create new cursor pointing to the new hash */
	rc = osd_zap_cursor_init(&zc, osd->od_os, it->oiq_oid, hash);
	if (rc)
		RETURN(rc);
	osd_zap_cursor_fini(it->oiq_zc);
	it->oiq_zc = zc;
	it->oiq_reset = 0;

	rc = -zap_cursor_retrieve(it->oiq_zc, za);
	if (rc == 0)
		rc = 1;
	else if (rc == -ENOENT)
		rc = 0;

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
