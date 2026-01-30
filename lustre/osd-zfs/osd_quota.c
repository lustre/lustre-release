// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Johann Lombardi <johann@whamcloud.com>
 */

#include <dt_object.h>
#include <lustre_quota.h>
#include <obd.h>
#include "osd_internal.h"

/*
 * Helper function to estimate the number of inodes in use for the given
 * uid/gid/projid from the block usage
 */
static uint64_t osd_objset_user_iused(struct osd_device *osd, uint64_t uidbytes)
{
	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	uint64_t uidobjs, bshift;

	/* get fresh statfs info */
	dmu_objset_space(osd->od_os, &refdbytes, &availbytes,
			 &usedobjs, &availobjs);

	/* estimate the number of objects based on the disk usage */
	bshift = fls64(osd->od_max_blksz) - 1;
	uidobjs = osd_objs_count_estimate(refdbytes, usedobjs,
					  uidbytes >> bshift, bshift);
	if (uidbytes > 0)
		/* if we have at least 1 byte, we have at least one dnode ... */
		uidobjs = max_t(uint64_t, uidobjs, 1);

	return uidobjs;
}

/* Space Accounting Management */

/**
 * osd_acct_index_lookup() - Get space usage consumed by a given uid/gid/projid.
 * @env: is the environment passed by the caller
 * @dtobj: is the accounting object
 * @dtrec: is the record to fill with space usage information
 * @dtkey: is the id the of the user or group for which we would like to access
 *         disk usage.
 *
 * Return space usage consumed by a given uid or gid or projid.
 * Block usage is accurrate since it is maintained by DMU itself.
 * However, DMU does not provide inode accounting, so the #inodes in use
 * is estimated from the block usage and statfs information.
 *
 * Return:
 * * %positive success (exact match)
 * * %negative failure
 */
static int osd_acct_index_lookup(const struct lu_env *env,
				struct dt_object *dtobj,
				struct dt_rec *dtrec,
				const struct dt_key *dtkey)
{
	struct osd_thread_info *info = osd_oti_get(env);
	char *buf = info->oti_buf;
	struct lquota_acct_rec *rec = (struct lquota_acct_rec *)dtrec;
	struct osd_object *obj = osd_dt_obj(dtobj);
	struct osd_device *osd = osd_obj2dev(obj);
	dnode_t *dn = obj->oo_dn;
	size_t buflen = sizeof(info->oti_buf);
	int rc;

	ENTRY;
	rec->bspace = rec->ispace = 0;

	/* convert the 64-bit uid/gid/projid into a string */
	snprintf(buf, buflen, "%llx", *((__u64 *)dtkey));
	if (unlikely(!dn)) {
		CDEBUG(D_QUOTA, "%s: miss accounting obj for %s\n",
		       osd->od_svname, buf);

		RETURN(-ENOENT);
	}

	/* disk usage (in bytes) is maintained by DMU.
	 * DMU_USERUSED_OBJECT/DMU_GROUPUSED_OBJECT are special objects which
	 * not associated with any dmu_but_t (see dnode_special_open()).
	 */
	rc = osd_zap_lookup(osd, dn->dn_object, dn, buf, sizeof(uint64_t), 1,
			    &rec->bspace);
	if (rc == -ENOENT) {
		/* user/group/project has not created anything yet */
		CDEBUG(D_QUOTA, "%s: id %s not found in DMU accounting ZAP\n",
		       osd->od_svname, buf);
		/* -ENOENT is normal case, convert it as 1. */
		rc = 1;
	} else if (rc) {
		RETURN(rc);
	}

	if (!osd_dmu_userobj_accounting_available(osd)) {
		if (rec->bspace != 0)
			/* estimate #inodes in use */
			rec->ispace = osd_objset_user_iused(osd, rec->bspace);
		rc = 1;
	} else {
		snprintf(buf, buflen, DMU_OBJACCT_PREFIX "%llx",
			 *((__u64 *)dtkey));
		rc = osd_zap_lookup(osd, dn->dn_object, dn, buf,
				    sizeof(uint64_t), 1, &rec->ispace);
		if (rc == -ENOENT) {
			CDEBUG(D_QUOTA,
			       "%s: id %s not found dnode accounting\n",
			       osd->od_svname, buf);
			/* -ENOENT is normal case, convert it as 1. */
			rc = 1;
		} else if (rc == 0) {
			rc = 1;
		}
	}

	RETURN(rc);
}

/**
 * osd_it_acct_init() - Initialize osd Iterator for given osd index object.
 * @env: Lustre environment
 * @dt: osd index object
 * @attr: not used
 *
 * Return struct di_it on success or %negative on failure
 */
static struct dt_it *osd_it_acct_init(const struct lu_env *env,
				      struct dt_object *dt,
				      __u32 attr)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct osd_it_quota *it;
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	dnode_t *dn = obj->oo_dn;
	int rc;

	ENTRY;
	if (unlikely(!dn)) {
		CDEBUG(D_QUOTA, "%s: Not found in DMU accounting ZAP\n",
		       osd->od_svname);

		RETURN(ERR_PTR(-ENOENT));
	}

	if (info == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	memset(it, 0, sizeof(*it));
	it->oiq_oid = dn->dn_object;

	/* initialize zap cursor */
	rc = osd_zap_cursor_init(&it->oiq_zc, osd->od_os, it->oiq_oid, 0);
	if (rc != 0) {
		OBD_FREE_PTR(it);
		RETURN(ERR_PTR(rc));
	}

	/* take object reference */
	lu_object_get(&dt->do_lu);
	it->oiq_obj   = osd_dt_obj(dt);
	it->oiq_reset = 1;

	RETURN((struct dt_it *)it);
}

/*
 * osd_it_acct_fini() - Free given iterator.
 * @env: Lustre environment
 * @di: osd iterator
 */
static void osd_it_acct_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;

	ENTRY;
	osd_zap_cursor_fini(it->oiq_zc);
	osd_object_put(env, it->oiq_obj);
	OBD_FREE_PTR(it);

	EXIT;
}

/**
 * osd_zap_locate() - Locate the first entry that is for space accounting.
 * @it: Iterator for quota
 * @za: ZFS attributes located [out]
 *
 * Return:
 * * %0 on success (ZAP entry found)
 * * %-ENOENT (ZAP entry not found)
 * * %negative on other error
 */
static int osd_zap_locate(struct osd_it_quota *it, zap_attribute_t *za)
{
	int rc;

	ENTRY;
	while (1) {
		rc = -zap_cursor_retrieve(it->oiq_zc, za);
		if (rc)
			break;

		if (strncmp(za->za_name, DMU_OBJACCT_PREFIX,
			    DMU_OBJACCT_PREFIX_LEN))
			break;

		zap_cursor_advance(it->oiq_zc);
	}

	RETURN(rc);
}

/**
 * osd_it_acct_next() - Move on to the next valid entry.
 * @env: Lustre environment
 * @di: osd iterator
 *
 * Return:
 * * %positive iterator reached the end
 * * %0 iterator has not reached the end yet
 * * %negitive unexpected failure
 */
static int osd_it_acct_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	zap_attribute_t *za = &osd_oti_get(env)->oti_za;
	int rc;

	ENTRY;
	if (it->oiq_reset == 0)
		zap_cursor_advance(it->oiq_zc);
	it->oiq_reset = 0;

	rc = osd_zap_locate(it, za);
	RETURN(rc == -ENOENT ? 1 : rc);
}

/**
 * osd_it_acct_key() - Get pointer to the key under iterator.
 * @env: Lustre environment
 * @di: osd iterator
 *
 * Return pointer to the key under iterator.
 */
static struct dt_key *osd_it_acct_key(const struct lu_env *env,
				      const struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	zap_attribute_t *za = &osd_oti_get(env)->oti_za;
	int rc;

	ENTRY;
	it->oiq_reset = 0;
	rc = osd_zap_locate(it, za);
	if (rc)
		RETURN(ERR_PTR(rc));

	rc = kstrtoull(za->za_name, 16, &it->oiq_id);
	if (rc)
		CERROR("couldn't parse name %s: rc = %d\n", za->za_name, rc);

	RETURN((struct dt_key *) &it->oiq_id);
}

/**
 * osd_it_acct_key_size() - Get size of key under iterator (in bytes)
 * @env: Lustre environment
 * @di: osd iterator
 *
 * Returns size of key
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
					 struct osd_it_quota *it,
					 char *buf, int buf_size,
					 int *bytes_read)
{
	const struct lu_fid *fid = lu_object_fid(&it->oiq_obj->oo_dt.do_lu);
	zap_attribute_t *za = &osd_oti_get(env)->oti_za;
	zap_cursor_t *zc = it->oiq_zc;
	struct osd_device *osd = osd_obj2dev(it->oiq_obj);
	uint64_t acct_obj;
	int rc, actual_size;

	rc = -zap_cursor_retrieve(zc, za);
	if (unlikely(rc != 0))
		return rc;

	if (unlikely(za->za_integer_length <= 0))
		return -ERANGE;

	actual_size = za->za_integer_length * za->za_num_integers;

	if (actual_size > buf_size) {
		actual_size = buf_size;
		buf_size = actual_size / za->za_integer_length;
	} else {
		buf_size = za->za_num_integers;
	}

	/* use correct special ID to request bytes used */
	if (fid_oid(fid) == ACCT_USER_OID)
		acct_obj = DMU_USERUSED_OBJECT;
	else if (fid_oid(fid) == ACCT_GROUP_OID)
		acct_obj = DMU_GROUPUSED_OBJECT;
	else
		acct_obj = DMU_PROJECTUSED_OBJECT;

	rc = osd_zap_lookup(osd, acct_obj, NULL, za->za_name,
			    za->za_integer_length, buf_size, buf);
	if (likely(rc == 0))
		*bytes_read = actual_size;

	return rc;
}

/**
 * osd_it_acct_rec() - Return pointer to the record under iterator.
 * @env: Lustre environment
 * @di: osd iterator
 * @dtrec: record fill with accounting information [out]
 * @attr: Unused
 *
 * * Return:
 * * %0 on success
 * * %negative on failure
 */
static int osd_it_acct_rec(const struct lu_env *env,
			   const struct dt_it *di,
			   struct dt_rec *dtrec, __u32 attr)
{
	struct osd_thread_info *info = osd_oti_get(env);
	zap_attribute_t *za = &info->oti_za;
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	struct lquota_acct_rec *rec = (struct lquota_acct_rec *)dtrec;
	struct osd_object *obj = it->oiq_obj;
	struct osd_device *osd = osd_obj2dev(obj);
	int bytes_read;
	int rc;

	ENTRY;
	it->oiq_reset = 0;
	rec->ispace = rec->bspace = 0;

	/* retrieve block usage from the DMU accounting object */
	rc = osd_zap_cursor_retrieve_value(env, it, (char *)&rec->bspace,
					   sizeof(uint64_t), &bytes_read);
	if (rc)
		RETURN(rc);

	if (!osd_dmu_userobj_accounting_available(osd)) {
		if (rec->bspace != 0)
			/* estimate #inodes in use */
			rec->ispace = osd_objset_user_iused(osd, rec->bspace);
		RETURN(0);
	}

	/* retrieve key associated with the current cursor */
	rc = -zap_cursor_retrieve(it->oiq_zc, za);
	if (unlikely(rc != 0))
		RETURN(rc);

	/* inode accounting is maintained by DMU since 0.7.0 */
	strncpy(info->oti_buf, DMU_OBJACCT_PREFIX,
		DMU_OBJACCT_PREFIX_LEN);
	strscpy(info->oti_buf + DMU_OBJACCT_PREFIX_LEN, za->za_name,
		sizeof(info->oti_buf) - DMU_OBJACCT_PREFIX_LEN);
	rc = osd_zap_lookup(osd, it->oiq_obj->oo_dn->dn_object,
			    it->oiq_obj->oo_dn, info->oti_buf, sizeof(uint64_t),
			    1, &rec->ispace);
	if (rc == -ENOENT)
		/* user/group has not created any file yet */
		CDEBUG(D_QUOTA, "%s: id %s not found in accounting ZAP\n",
		       osd->od_svname, info->oti_buf);
	else if (rc)
		RETURN(rc);

	RETURN(0);
}

/**
 * osd_it_acct_store() - Returns cookie for current Iterator position.
 * @env: Lustre environment
 * @di: osd iterator
 *
 * Returns cookie/hash representing iterator state
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
 * osd_it_acct_load() - Restore iterator from cookie
 * @env: Lustre environment
 * @di: osd iterator
 * @hash: iterator location cookie
 *
 * Restore iterator from cookie. if the @hash isn't found,
 * restore the first valid record.
 *
 * Return:
 * * %positive @di points to exact matched key
 * * %0 @di points to the first valid record
 * * %negative on failure
 */
static int osd_it_acct_load(const struct lu_env *env,
			    const struct dt_it *di, __u64 hash)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	struct osd_device *osd = osd_obj2dev(it->oiq_obj);
	zap_attribute_t *za = &osd_oti_get(env)->oti_za;
	zap_cursor_t *zc;
	int rc;

	ENTRY;
	/* create new cursor pointing to the new hash */
	rc = osd_zap_cursor_init(&zc, osd->od_os, it->oiq_oid, hash);
	if (rc)
		RETURN(rc);
	osd_zap_cursor_fini(it->oiq_zc);
	it->oiq_zc = zc;
	it->oiq_reset = 0;

	rc = osd_zap_locate(it, za);
	if (rc == 0)
		rc = 1;
	else if (rc == -ENOENT)
		rc = 0;
	RETURN(rc);
}

/**
 * osd_it_acct_get() - Move Iterator to record specified by @key, if the @key
 *                     isn't found, move to the first valid record.
 * @env: Lustre environment
 * @di: osd iterator
 * @key: uid or gid or projid
 *
 * Return:
 * * %positive @di points to exact matched key
 * * %0 @di points to the first valid record
 * * %negative on failure
 */
static int osd_it_acct_get(const struct lu_env *env, struct dt_it *di,
		const struct dt_key *key)
{
	ENTRY;

	/* XXX: like osd_zap_it_get(), API is currently broken */
	LASSERT(*((__u64 *)key) == 0);

	RETURN(osd_it_acct_load(env, di, 0));
}

/*
 * osd_id_acct_put() - Release Iterator
 * @env: Lustre environment
 * @di: osd iterator
 */
static void osd_it_acct_put(const struct lu_env *env, struct dt_it *di)
{
}

/* Index and Iterator operations for accounting objects */
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

/* Quota Enforcement Management */

/**
 * osd_declare_quota() - Wrapper for qsd_op_begin().
 * @env: the environment passed by the caller
 * @osd: is the osd_device
 * @uid: user id of the inode
 * @gid: group id of the inode
 * @projid: project id of the inode
 * @space: how many blocks/inodes will be consumed/released
 * @oh: osd transaction handle
 * @local_flags: if the operation is write, return no user quota, no group
 *               quota, or sync commit flags to the caller
 * @osd_qid_declare_flags: indicate this is a inode/block accounting and whether
 *                         changes are performed by root user
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int osd_declare_quota(const struct lu_env *env, struct osd_device *osd,
		      qid_t uid, qid_t gid, qid_t projid, long long space,
		      struct osd_thandle *oh,
		      enum osd_quota_local_flags *local_flags,
		      enum osd_qid_declare_flags osd_qid_declare_flags)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lquota_id_info *qi = &info->oti_qi;
	struct qsd_instance *qsd = NULL;
	int rcu, rcg, rcp = 0; /* user & group & project rc */
	struct thandle *th = &oh->ot_super;
	enum osd_quota_local_flags tmp_flags;
	bool force = !!(osd_qid_declare_flags & OSD_QID_FORCE) ||
			th->th_ignore_quota;

	ENTRY;
	/* very fast path for special files like llog */
	if (uid == 0 && gid == 0 && projid == 0)
		return 0;

	if (osd_qid_declare_flags & OSD_QID_INODE)
		qsd = osd->od_quota_slave_md;
	else if (osd_qid_declare_flags & OSD_QID_BLK)
		qsd = osd->od_quota_slave_dt;
	else
		RETURN(0);

	if (unlikely(qsd == NULL))
		/* quota slave instance hasn't been allocated yet */
		RETURN(0);

	/* let's start with user quota */
	qi->lqi_id.qid_uid = uid;
	qi->lqi_type       = USRQUOTA;
	qi->lqi_space      = space;
	qi->lqi_is_blk     = !!(osd_qid_declare_flags & OSD_QID_BLK);
	rcu = qsd_op_begin(env, qsd, &oh->ot_quota_trans, qi, local_flags);
	if (force && (rcu == -EDQUOT || rcu == -EINPROGRESS))
		/* ignore EDQUOT & EINPROGRESS when changes are done by root */
		rcu = 0;

	/* For non-fatal error, we want to continue to get the noquota flags
	 * for group id. This is only for commit write, which has @flags passed
	 * in. See osd_declare_write_commit().
	 * When force is set to true, we also want to proceed with the gid
	 */
	if (rcu && (rcu != -EDQUOT || local_flags == NULL))
		RETURN(rcu);

	/* and now group quota */
	qi->lqi_id.qid_gid = gid;
	qi->lqi_type       = GRPQUOTA;
	rcg = qsd_op_begin(env, qsd, &oh->ot_quota_trans, qi, local_flags);
	if (force && (rcg == -EDQUOT || rcg == -EINPROGRESS))
		/* as before, ignore EDQUOT & EINPROGRESS for root */
		rcg = 0;

#ifdef ZFS_PROJINHERIT
	if (rcg && (rcg != -EDQUOT || local_flags == NULL))
		RETURN(rcg);

	/* for project quota */
	if (osd->od_projectused_dn) {
		qi->lqi_id.qid_projid = projid;
		qi->lqi_ignore_root_proj_quota = th->th_ignore_root_proj_quota;
		qi->lqi_type = PRJQUOTA;

		tmp_flags = 0;
		if (local_flags)
			tmp_flags = *local_flags;
		rcp = qsd_op_begin(env, qsd, &oh->ot_quota_trans, qi,
				   &tmp_flags);
		if (tmp_flags & QUOTA_FL_ROOT_PRJQUOTA &&
		    !(osd_qid_declare_flags & OSD_QID_IGNORE_ROOT_PRJ))
			/* Currently, th_ignore_quota is only set for inode
			 * quota in mdd_trans_create if the user has
			 * CAP_SYS_RESOURCE, then it should be ignored if
			 * root_prj_enable is set.
			 */
			force = 0;
		if (local_flags)
			*local_flags = tmp_flags;
		if (force && (rcp == -EDQUOT || rcp == -EINPROGRESS))
			rcp = 0;
	}
#endif

	RETURN(rcu ? rcu : (rcg ? rcg : rcp));
}
