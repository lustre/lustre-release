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
 * Copyright (c) 2012, 2013, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann@whamcloud.com>
 * Author: Niu    Yawei    <niu@whamcloud.com>
 */

#include <lustre_quota.h>
#include "osd_internal.h"

/**
 * Helpers function to find out the quota type (USRQUOTA/GRPQUOTA) of a
 * given object
 */
static inline int fid2type(const struct lu_fid *fid)
{
	LASSERT(fid_is_acct(fid));
	if (fid_oid(fid) == ACCT_GROUP_OID)
		return GRPQUOTA;
	return USRQUOTA;
}

static inline int obj2type(struct dt_object *obj)
{
	return fid2type(lu_object_fid(&obj->do_lu));
}

/**
 * Space Accounting Management
 */

/**
 * Look up an accounting object based on its fid.
 *
 * \param info - is the osd thread info passed by the caller
 * \param osd  - is the osd device
 * \param fid  - is the fid of the accounting object we want to look up
 * \param id   - is the osd_inode_id struct to fill with the inode number of
 *               the quota file if the lookup is successful
 */
int osd_acct_obj_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id)
{
	struct super_block *sb = osd_sb(osd);
        unsigned long qf_inums[2] = {
		le32_to_cpu(LDISKFS_SB(sb)->s_es->s_usr_quota_inum),
		le32_to_cpu(LDISKFS_SB(sb)->s_es->s_grp_quota_inum)
	};

	ENTRY;
	LASSERT(fid_is_acct(fid));

	if (!LDISKFS_HAS_RO_COMPAT_FEATURE(sb,
					   LDISKFS_FEATURE_RO_COMPAT_QUOTA))
		RETURN(-ENOENT);

	id->oii_gen = OSD_OII_NOGEN;
	id->oii_ino = qf_inums[fid2type(fid)];
	if (!ldiskfs_valid_inum(sb, id->oii_ino))
		RETURN(-ENOENT);
	RETURN(0);
}

/**
 * Return space usage (#blocks & #inodes) consumed by a given uid or gid.
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
#ifdef HAVE_DQUOT_FS_DISK_QUOTA
	struct fs_disk_quota	*dqblk = &info->oti_fdq;
#else
	struct if_dqblk		*dqblk = &info->oti_dqblk;
#endif
	struct super_block	*sb = osd_sb(osd_obj2dev(osd_dt_obj(dtobj)));
	struct lquota_acct_rec	*rec = (struct lquota_acct_rec *)dtrec;
	__u64			 id = *((__u64 *)dtkey);
	int			 rc;
#ifdef HAVE_DQUOT_KQID
	struct kqid		qid;
#endif

	ENTRY;

	memset((void *)dqblk, 0, sizeof(struct obd_dqblk));
#ifdef HAVE_DQUOT_KQID
	qid = make_kqid(&init_user_ns, obj2type(dtobj), id);
	rc = sb->s_qcop->get_dqblk(sb, qid, dqblk);
#else
	rc = sb->s_qcop->get_dqblk(sb, obj2type(dtobj), (qid_t) id, dqblk);
#endif
	if (rc)
		RETURN(rc);
#ifdef HAVE_DQUOT_FS_DISK_QUOTA
	rec->bspace = dqblk->d_bcount;
	rec->ispace = dqblk->d_icount;
#else
	rec->bspace = dqblk->dqb_curspace;
	rec->ispace = dqblk->dqb_curinodes;
#endif
	RETURN(+1);
}

#define QUOTA_IT_READ_ERROR(it, rc)                                    \
	CERROR("%s: Error while trying to read quota information, "    \
	       "failed with %d\n",                                     \
	       osd_dev(it->oiq_obj->oo_dt.do_lu.lo_dev)->od_svname, rc); \

/**
 * Initialize osd Iterator for given osd index object.
 *
 * \param  dt    - osd index object
 * \param  attr  - not used
 * \param  capa  - BYPASS_CAPA
 */
static struct dt_it *osd_it_acct_init(const struct lu_env *env,
				      struct dt_object *dt,
				      __u32 attr, struct lustre_capa *capa)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	struct osd_it_quota	*it;
	struct lu_object	*lo = &dt->do_lu;
	struct osd_object	*obj = osd_dt_obj(dt);

	ENTRY;

	LASSERT(lu_object_exists(lo));

	if (info == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	it = &info->oti_it_quota;
	memset(it, 0, sizeof(*it));
	lu_object_get(lo);
	it->oiq_obj = obj;
	CFS_INIT_LIST_HEAD(&it->oiq_list);

	/* LUSTRE_DQTREEOFF is the initial offset where the tree can be found */
	it->oiq_blk[0] = LUSTRE_DQTREEOFF;

	/* NB: we don't need to store the tree depth since it is always
	 * equal to LUSTRE_DQTREEDEPTH - 1 (root has depth = 0) for a leaf
	 * block. */
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
	struct osd_quota_leaf *leaf, *tmp;
	ENTRY;

	lu_object_put(env, &it->oiq_obj->oo_dt.do_lu);

	cfs_list_for_each_entry_safe(leaf, tmp, &it->oiq_list, oql_link) {
		cfs_list_del_init(&leaf->oql_link);
		OBD_FREE_PTR(leaf);
	}
	EXIT;
}

/**
 * Move Iterator to record specified by \a key, if the \a key isn't found,
 * move to the first valid record.
 *
 * \param  di   - osd iterator
 * \param  key  - uid or gid
 *
 * \retval +ve  - di points to the first valid record
 * \retval  +1  - di points to exact matched key
 * \retval -ve  - failure
 */
static int osd_it_acct_get(const struct lu_env *env, struct dt_it *di,
			   const struct dt_key *key)
{
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	const struct lu_fid	*fid =
				lu_object_fid(&it->oiq_obj->oo_dt.do_lu);
	int			 type = fid2type(fid);
	qid_t			 dqid = *(qid_t *)key;
	loff_t			 offset;
	int			 rc;

	ENTRY;

	offset = find_tree_dqentry(env, it->oiq_obj, type, dqid,
				   LUSTRE_DQTREEOFF, 0, it);
	if (offset > 0) { /* Found */
		RETURN(+1);
	} else if (offset < 0) { /* Error */
		QUOTA_IT_READ_ERROR(it, (int)offset);
		RETURN((int)offset);
	}

	/* The @key is not found, move to the first valid entry */
	rc = walk_tree_dqentry(env, it->oiq_obj, type, it->oiq_blk[0], 0,
			       0, it);
	if (rc == 0)
		rc = 1;
	else if (rc > 0)
		rc = -ENOENT;

	RETURN(rc);
}

/**
 * Release Iterator
 *
 * \param  di   - osd iterator
 */
static void osd_it_acct_put(const struct lu_env *env, struct dt_it *di)
{
	return;
}

static int osd_it_add_processed(struct osd_it_quota *it, int depth)
{
	struct osd_quota_leaf *leaf;

	OBD_ALLOC_PTR(leaf);
	if (leaf == NULL)
		RETURN(-ENOMEM);
	CFS_INIT_LIST_HEAD(&leaf->oql_link);
	leaf->oql_blk = it->oiq_blk[depth];
	cfs_list_add_tail(&leaf->oql_link, &it->oiq_list);
	RETURN(0);
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
	const struct lu_fid	*fid =
				lu_object_fid(&it->oiq_obj->oo_dt.do_lu);
	int			 type = fid2type(fid);
	int			 depth, rc;
	uint			 index;

	ENTRY;

	/* Let's first check if there are any remaining valid entry in the
	 * current leaf block. Start with the next entry after the current one.
	 */
	depth = LUSTRE_DQTREEDEPTH;
	index = it->oiq_index[depth];
	if (++index < LUSTRE_DQSTRINBLK) {
		/* Search for the next valid entry from current index */
		rc = walk_block_dqentry(env, it->oiq_obj, type,
					it->oiq_blk[depth], index, it);
		if (rc < 0) {
			QUOTA_IT_READ_ERROR(it, rc);
			RETURN(rc);
		} else if (rc == 0) {
			/* Found on entry, @it is already updated to the
			 * new position in walk_block_dqentry(). */
			RETURN(0);
		} else {
			rc = osd_it_add_processed(it, depth);
			if (rc)
				RETURN(rc);
		}
	} else {
		rc = osd_it_add_processed(it, depth);
		if (rc)
			RETURN(rc);
	}
	rc = 1;

	/* We have consumed all the entries of the current leaf block, move on
	 * to the next one. */
	depth--;

	/* We keep searching as long as walk_tree_dqentry() returns +1
	 * (= no valid entry found). */
	for (; depth >= 0 && rc > 0; depth--) {
		index = it->oiq_index[depth];
		if (++index > 0xff)
			continue;
		rc = walk_tree_dqentry(env, it->oiq_obj, type,
				       it->oiq_blk[depth], depth, index, it);
	}

	if (rc < 0)
		QUOTA_IT_READ_ERROR(it, rc);
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
	struct osd_it_quota *it = (struct osd_it_quota *)di;

	ENTRY;
	RETURN((struct dt_key *)&it->oiq_id);
}

/**
 * Return size of key under iterator (in bytes)
 *
 * \param  di   - osd iterator
 */
static int osd_it_acct_key_size(const struct lu_env *env,
				const struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;

	ENTRY;
	RETURN((int)sizeof(it->oiq_id));
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
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	const struct dt_key	*key = osd_it_acct_key(env, di);
	int			 rc;

	ENTRY;

	rc = osd_acct_index_lookup(env, &it->oiq_obj->oo_dt, dtrec, key,
				   BYPASS_CAPA);
	RETURN(rc > 0 ? 0 : rc);
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
	RETURN(it->oiq_id);
}

/**
 * Restore iterator from cookie. if the \a hash isn't found,
 * restore the first valid record.
 *
 * \param  di    - osd iterator
 * \param  hash  - iterator location cookie
 *
 * \retval +ve   - di points to the first valid record
 * \retval  +1   - di points to exact matched hash
 * \retval -ve   - failure
 */
static int osd_it_acct_load(const struct lu_env *env,
			    const struct dt_it *di, __u64 hash)
{
	ENTRY;
	RETURN(osd_it_acct_get(env, (struct dt_it *)di,
			       (const struct dt_key *)&hash));
}

/**
 * Index and Iterator operations for accounting objects
 */
const struct dt_index_operations osd_acct_index_ops = {
	.dio_lookup	= osd_acct_index_lookup,
	.dio_it		= {
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

static inline void osd_quota_swab(char *ptr, size_t size)
{
	int offset;

	LASSERT((size & (sizeof(__u64) - 1)) == 0);

	for (offset = 0; offset < size; offset += sizeof(__u64))
	     __swab64s((__u64 *)(ptr + offset));
}

const struct dt_rec *osd_quota_pack(struct osd_object *obj,
				    const struct dt_rec *rec,
				    union lquota_rec *quota_rec)
{
#ifdef __BIG_ENDIAN
	struct iam_descr        *descr;

	LASSERT(obj->oo_dir != NULL);
	descr = obj->oo_dir->od_container.ic_descr;

	memcpy(quota_rec, rec, descr->id_rec_size);

	osd_quota_swab((char *)quota_rec, descr->id_rec_size);
	return (const struct dt_rec *)quota_rec;
#else
	return rec;
#endif
}

void osd_quota_unpack(struct osd_object *obj, const struct dt_rec *rec)
{
#ifdef __BIG_ENDIAN
	struct iam_descr *descr;

	LASSERT(obj->oo_dir != NULL);
	descr = obj->oo_dir->od_container.ic_descr;

	osd_quota_swab((char *)rec, descr->id_rec_size);
#else
	return;
#endif
}

static inline int osd_qid_type(struct osd_thandle *oh, int i)
{
	return (oh->ot_id_type & (1 << i)) ? GRPQUOTA : USRQUOTA;
}

static inline void osd_qid_set_type(struct osd_thandle *oh, int i, int type)
{
	oh->ot_id_type |= ((type == GRPQUOTA) ? (1 << i) : 0);
}

/**
 * Reserve journal credits for quota files update first, then call
 * ->op_begin() to perform quota enforcement.
 *
 * \param  env     - the environment passed by the caller
 * \param  oh      - osd transaction handle
 * \param  qi      - quota id & space required for this operation
 * \param  obj     - osd object, could be NULL when it's under create
 * \param  enforce - whether to perform quota enforcement
 * \param  flags   - if the operation is write, return no user quota, no
 *                  group quota, or sync commit flags to the caller
 *
 * \retval 0       - success
 * \retval -ve     - failure
 */
int osd_declare_qid(const struct lu_env *env, struct osd_thandle *oh,
		    struct lquota_id_info *qi, struct osd_object *obj,
		    bool enforce, int *flags)
{
	struct osd_thread_info  *info = osd_oti_get(env);
	struct osd_device       *dev = info->oti_dev;
	struct qsd_instance     *qsd = dev->od_quota_slave;
	struct inode		*inode = NULL;
	int                      i, rc = 0;
	bool                     found = false;
	ENTRY;

	LASSERT(oh != NULL);
	LASSERTF(oh->ot_id_cnt <= OSD_MAX_UGID_CNT, "count=%d\n",
		 oh->ot_id_cnt);

	for (i = 0; i < oh->ot_id_cnt; i++) {
		if (oh->ot_id_array[i] == qi->lqi_id.qid_uid &&
		    osd_qid_type(oh, i) == qi->lqi_type) {
			found = true;
			break;
		}
	}

	if (!found) {
		/* we need to account for credits for this new ID */
		if (i >= OSD_MAX_UGID_CNT) {
			CERROR("Too many(%d) trans qids!\n", i + 1);
			RETURN(-EOVERFLOW);
		}

		if (obj != NULL)
			inode = obj->oo_inode;
		osd_trans_declare_op(env, oh, OSD_OT_QUOTA,
				     (qi->lqi_id.qid_uid == 0 ||
				      (inode != NULL &&
				       inode->i_dquot[qi->lqi_type] != NULL)) ?
				     1: LDISKFS_QUOTA_INIT_BLOCKS(osd_sb(dev)));

		oh->ot_id_array[i] = qi->lqi_id.qid_uid;
		osd_qid_set_type(oh, i, qi->lqi_type);
		oh->ot_id_cnt++;
	}

	if (unlikely(qsd == NULL))
		/* quota slave instance hasn't been allocated yet */
		RETURN(0);

	/* check quota */
	if (enforce)
		rc = qsd_op_begin(env, qsd, oh->ot_quota_trans, qi, flags);
	RETURN(rc);
}

/**
 * Wrapper for osd_declare_qid()
 *
 * \param  env    - the environment passed by the caller
 * \param  uid    - user id of the inode
 * \param  gid    - group id of the inode
 * \param  space  - how many blocks/inodes will be consumed/released
 * \param  oh     - osd transaction handle
 * \param  obj    - osd object, could be NULL when it's under create
 * \param  is_blk - block quota or inode quota?
 * \param  flags  - if the operation is write, return no user quota, no
 *                  group quota, or sync commit flags to the caller
 * \param force   - set to 1 when changes are performed by root user and thus
 *                  can't failed with EDQUOT
 *
 * \retval 0      - success
 * \retval -ve    - failure
 */
int osd_declare_inode_qid(const struct lu_env *env, qid_t uid, qid_t gid,
			  long long space, struct osd_thandle *oh,
			  struct osd_object *obj, bool is_blk, int *flags,
			  bool force)
{
	struct osd_thread_info  *info = osd_oti_get(env);
	struct lquota_id_info   *qi = &info->oti_qi;
	int                      rcu, rcg; /* user & group rc */
	ENTRY;

	/* let's start with user quota */
	qi->lqi_id.qid_uid = uid;
	qi->lqi_type       = USRQUOTA;
	qi->lqi_space      = space;
	qi->lqi_is_blk     = is_blk;
	rcu = osd_declare_qid(env, oh, qi, obj, true, flags);

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
	rcg = osd_declare_qid(env, oh, qi, obj, true, flags);

	if (force && (rcg == -EDQUOT || rcg == -EINPROGRESS))
		/* as before, ignore EDQUOT & EINPROGRESS for root */
		rcg = 0;

	RETURN(rcu ? rcu : rcg);
}

/* Following code is used to migrate old admin quota files (in Linux quota
 * file v2 format) into the new quota global indexes (in IAM format). */

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2,7,50,0)

/* copied from osd_it_acct_get(), only changed the 'type' to -1 */
static int osd_it_admin_get(const struct lu_env *env, struct dt_it *di,
			    const struct dt_key *key)
{
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	int			 type = -1;
	qid_t			 dqid = *(qid_t *)key;
	loff_t			 offset;
	int			 rc;
	ENTRY;

	offset = find_tree_dqentry(env, it->oiq_obj, type, dqid,
				   LUSTRE_DQTREEOFF, 0, it);
	if (offset > 0) { /* Found */
		RETURN(+1);
	} else if (offset < 0) { /* Error */
		QUOTA_IT_READ_ERROR(it, (int)offset);
		RETURN((int)offset);
	}

	/* The @key is not found, move to the first valid entry */
	rc = walk_tree_dqentry(env, it->oiq_obj, type, it->oiq_blk[0], 0,
			       0, it);
	if (rc > 0)
		/* no valid entry found */
		rc = -ENOENT;
	RETURN(rc);
}

static int osd_it_admin_load(const struct lu_env *env,
			     const struct dt_it *di, __u64 hash)
{
	int rc;
	ENTRY;

	rc = osd_it_admin_get(env, (struct dt_it *)di,
			      (const struct dt_key *)&hash);
	RETURN(rc);
}

static int osd_it_admin_rec(const struct lu_env *env,
			    const struct dt_it *di,
			    struct dt_rec *dtrec, __u32 attr)
{
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	struct lu_buf		 buf;
	loff_t			 pos;
	int			 rc;
	struct lustre_disk_dqblk_v2 *dqblk =
		(struct lustre_disk_dqblk_v2 *)dtrec;
	ENTRY;

	buf.lb_buf = dqblk;
	buf.lb_len = sizeof(*dqblk);

	pos = it->oiq_offset;
	rc = dt_record_read(env, &it->oiq_obj->oo_dt, &buf, &pos);
	RETURN(rc);
}

/* copied from osd_it_acct_next(), only changed the 'type' to -1 */
static int osd_it_admin_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it_quota	*it = (struct osd_it_quota *)di;
	int			 type = -1;
	int			 depth, rc;
	uint			 index;
	ENTRY;

	/* Let's first check if there are any remaining valid entry in the
	 * current leaf block. Start with the next entry after the current one.
	 */
	depth = LUSTRE_DQTREEDEPTH;
	index = it->oiq_index[depth];
	if (++index < LUSTRE_DQSTRINBLK) {
		/* Search for the next valid entry from current index */
		rc = walk_block_dqentry(env, it->oiq_obj, type,
					it->oiq_blk[depth], index, it);
		if (rc < 0) {
			QUOTA_IT_READ_ERROR(it, rc);
			RETURN(rc);
		} else if (rc == 0) {
			/* Found on entry, @it is already updated to the
			 * new position in walk_block_dqentry(). */
			RETURN(0);
		} else {
			rc = osd_it_add_processed(it, depth);
			if (rc)
				RETURN(rc);
		}
	} else {
		rc = osd_it_add_processed(it, depth);
		if (rc)
			RETURN(rc);
	}
	rc = 1;

	/* We have consumed all the entries of the current leaf block, move on
	 * to the next one. */
	depth--;

	/* We keep searching as long as walk_tree_dqentry() returns +1
	 * (= no valid entry found). */
	for (; depth >= 0 && rc > 0; depth--) {
		index = it->oiq_index[depth];
		if (++index > 0xff)
			continue;
		rc = walk_tree_dqentry(env, it->oiq_obj, type,
				       it->oiq_blk[depth], depth, index, it);
	}

	if (rc < 0)
		QUOTA_IT_READ_ERROR(it, rc);
	RETURN(rc);
}

const struct dt_index_operations osd_admin_index_ops = {
	.dio_lookup	= osd_acct_index_lookup,
	.dio_it		= {
		.init     = osd_it_acct_init,
		.fini     = osd_it_acct_fini,
		.get      = osd_it_admin_get,
		.put      = osd_it_acct_put,
		.next     = osd_it_admin_next,
		.key      = osd_it_acct_key,
		.key_size = osd_it_acct_key_size,
		.rec      = osd_it_admin_rec,
		.store    = osd_it_acct_store,
		.load     = osd_it_admin_load
	}
};

static int convert_quota_file(const struct lu_env *env,
			      struct dt_object *old, struct dt_object *new,
			      bool isblk)
{
	const struct dt_it_ops	*iops = &old->do_index_ops->dio_it;
	struct osd_object	*obj;
	struct lu_buf		 buf;
	struct dt_it		*it;
	struct dt_key		*key;
	__u32			 grace;
	struct lquota_glb_rec	*glb_rec = NULL;
	loff_t			 pos;
	int			 rc;
	struct lustre_disk_dqblk_v2	*dqblk = NULL;
	struct lustre_disk_dqinfo	*dqinfo = NULL;
	ENTRY;

	obj = osd_dt_obj(old);
	LASSERT(obj->oo_inode);

	if (i_size_read(obj->oo_inode) == 0)
		RETURN(0);

	/* allocate buffers */
	OBD_ALLOC_PTR(dqinfo);
	if (dqinfo == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC_PTR(glb_rec);
	if (glb_rec == NULL)
		GOTO(out, rc = -ENOMEM);

	OBD_ALLOC_PTR(dqblk);
	if (dqblk == NULL)
		GOTO(out, rc = -ENOMEM);

	/* convert the old igrace/bgrace */
	buf.lb_buf = dqinfo;
	buf.lb_len = sizeof(*dqinfo);
	pos = LUSTRE_DQINFOOFF;

	rc = dt_record_read(env, old, &buf, &pos);
	if (rc)
		GOTO(out, rc);

	/* keep it in little endian */
	grace = isblk ? dqinfo->dqi_bgrace : dqinfo->dqi_igrace;
	if (grace != 0) {
		glb_rec->qbr_time = grace;
		rc = lquota_disk_write_glb(env, new, 0, glb_rec);
		if (rc)
			GOTO(out, rc);
		glb_rec->qbr_time = 0;
	}

	/* iterate the old admin file, insert each record into the
	 * new index file. */
	it = iops->init(env, old, 0, BYPASS_CAPA);
	if (IS_ERR(it))
		GOTO(out, rc = PTR_ERR(it));

	rc = iops->load(env, it, 0);
	if (rc == -ENOENT)
		GOTO(out_it, rc = 0);
	else if (rc < 0)
		GOTO(out_it, rc);

	do {
		key = iops->key(env, it);
		if (IS_ERR(key))
			GOTO(out_it, rc = PTR_ERR(key));

		/* skip the root user/group */
		if (*((__u64 *)key) == 0)
			goto next;

		rc = iops->rec(env, it, (struct dt_rec *)dqblk, 0);
		if (rc)
			GOTO(out_it, rc);

		/* keep the value in little endian */
		glb_rec->qbr_hardlimit = isblk ? dqblk->dqb_bhardlimit :
						 dqblk->dqb_ihardlimit;
		glb_rec->qbr_softlimit = isblk ? dqblk->dqb_bsoftlimit :
						 dqblk->dqb_isoftlimit;

		rc = lquota_disk_write_glb(env, new, *((__u64 *)key), glb_rec);
		if (rc)
			GOTO(out_it, rc);
next:
		rc = iops->next(env, it);
	} while (rc == 0);

	/* reach the end */
	if (rc > 0)
		rc = 0;

out_it:
	iops->put(env, it);
	iops->fini(env, it);
out:
	if (dqblk != NULL)
		OBD_FREE_PTR(dqblk);
	if (glb_rec != NULL)
		OBD_FREE_PTR(glb_rec);
	if (dqinfo != NULL)
		OBD_FREE_PTR(dqinfo);
	return rc;
}

/* Nobdy else can access the global index now, it's safe to truncate and
 * reinitialize it */
static int truncate_quota_index(const struct lu_env *env, struct dt_object *dt,
				const struct dt_index_features *feat)
{
	struct osd_device	*osd = osd_obj2dev(osd_dt_obj(dt));
	struct thandle		*th;
	struct lu_attr		*attr;
	struct osd_thandle	*oth;
	struct inode		*inode;
	int			 rc;
	struct iam_container	*bag = &(osd_dt_obj(dt))->oo_dir->od_container;
	ENTRY;

	LASSERT(bag->ic_root_bh != NULL);
	iam_container_fini(bag);

	LASSERT(fid_seq(lu_object_fid(&dt->do_lu)) == FID_SEQ_QUOTA_GLB);

	OBD_ALLOC_PTR(attr);
	if (attr == NULL)
		RETURN(-ENOMEM);

	attr->la_size = 0;
	attr->la_valid = LA_SIZE;

	th = dt_trans_create(env, &osd->od_dt_dev);
	if (IS_ERR(th)) {
		OBD_FREE_PTR(attr);
		RETURN(PTR_ERR(th));
	}

	rc = dt_declare_punch(env, dt, 0, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_declare_attr_set(env, dt, attr, th);
	if (rc)
		GOTO(out, rc);

	inode = osd_dt_obj(dt)->oo_inode;
	LASSERT(inode);

	/* iam_lfix_create() writes two blocks at the beginning */
	rc = dt_declare_record_write(env, dt, inode->i_sb->s_blocksize * 2,
				     0, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, &osd->od_dt_dev, th);
	if (rc)
		GOTO(out, rc);

	dt_write_lock(env, dt, 0);
	rc = dt_punch(env, dt, 0, OBD_OBJECT_EOF, th, BYPASS_CAPA);
	if (rc)
		GOTO(out_lock, rc);

	rc = dt_attr_set(env, dt, attr, th, BYPASS_CAPA);
	if (rc)
		GOTO(out_lock, rc);

	oth = container_of(th, struct osd_thandle, ot_super);

	if (feat->dif_flags & DT_IND_VARKEY)
		rc = iam_lvar_create(osd_dt_obj(dt)->oo_inode,
				     feat->dif_keysize_max,
				     feat->dif_ptrsize,
				     feat->dif_recsize_max, oth->ot_handle);
	else
		rc = iam_lfix_create(osd_dt_obj(dt)->oo_inode,
				     feat->dif_keysize_max,
				     feat->dif_ptrsize,
				     feat->dif_recsize_max, oth->ot_handle);
out_lock:
	dt_write_unlock(env, dt);
out:
	dt_trans_stop(env, &osd->od_dt_dev, th);
	OBD_FREE_PTR(attr);

	if (rc == 0) {
		rc  = iam_container_setup(bag);
		if (rc != 0)
			iam_container_fini(bag);
	}
	RETURN(rc);
}

static int set_quota_index_version(const struct lu_env *env,
				   struct dt_object *dt,
				   dt_obj_version_t version)
{
	struct osd_device	*osd = osd_obj2dev(osd_dt_obj(dt));
	struct thandle		*th;
	int			 rc;
	ENTRY;

	th = dt_trans_create(env, &osd->od_dt_dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_version_set(env, dt, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, &osd->od_dt_dev, th);
	if (rc)
		GOTO(out, rc);

	th->th_sync = 1;
	dt_version_set(env, dt, version, th);
out:
	dt_trans_stop(env, &osd->od_dt_dev, th);
	RETURN(rc);
}

int osd_quota_migration(const struct lu_env *env, struct dt_object *dt,
			const struct dt_index_features *feat)
{
	struct osd_thread_info	*oti = osd_oti_get(env);
	struct osd_device	*osd = osd_obj2dev(osd_dt_obj(dt));
	struct dt_object	*root, *parent = NULL, *admin = NULL;
	dt_obj_version_t	 version;
	char			*fname;
	bool			 isblk = false, converted = false;
	int			 rc;
	ENTRY;

	/* not newly created global index */
	version = dt_version_get(env, dt);
	if (version != 0)
		RETURN(0);

	/* locate root */
	rc = dt_root_get(env, &osd->od_dt_dev, &oti->oti_fid);
	if (rc) {
		CERROR("%s: Can't get root FID, rc:%d\n", osd->od_svname, rc);
		RETURN(rc);
	}

	root = dt_locate(env, &osd->od_dt_dev, &oti->oti_fid);
	if (IS_ERR(root)) {
		CERROR("%s: Failed to locate root "DFID", rc:%ld\n",
		       osd->od_svname, PFID(&oti->oti_fid), PTR_ERR(root));
		RETURN(PTR_ERR(root));
	}

	/* locate /OBJECTS */
	rc = dt_lookup_dir(env, root, OBJECTS, &oti->oti_fid);
	if (rc == -ENOENT) {
		GOTO(out, rc = 0);
	} else if (rc) {
		CERROR("%s: Failed to lookup %s, rc:%d\n",
		       osd->od_svname, OBJECTS, rc);
		GOTO(out, rc);
	}

	parent = dt_locate(env, &osd->od_dt_dev, &oti->oti_fid);
	if (IS_ERR(parent)) {
		CERROR("%s: Failed to locate %s "DFID", rc:%ld\n",
		       osd->od_svname, OBJECTS, PFID(&oti->oti_fid),
		       PTR_ERR(parent));
		GOTO(out, rc = PTR_ERR(parent));
	}

	/* locate quota admin file */
	if (feat == &dt_quota_iusr_features) {
		fname = ADMIN_USR;
		isblk = false;
	} else if (feat == &dt_quota_busr_features) {
		fname = ADMIN_USR;
		isblk = true;
	} else if (feat == &dt_quota_igrp_features) {
		fname = ADMIN_GRP;
		isblk = false;
	} else {
		fname = ADMIN_GRP;
		isblk = true;
	}

	rc = dt_lookup_dir(env, parent, fname, &oti->oti_fid);
	if (rc == -ENOENT) {
		GOTO(out, rc = 0);
	} else if (rc) {
		CERROR("%s: Failed to lookup %s, rc:%d\n",
		       osd->od_svname, fname, rc);
		GOTO(out, rc);
	}

	admin = dt_locate(env, &osd->od_dt_dev, &oti->oti_fid);
	if (IS_ERR(admin)) {
		CERROR("%s: Failed to locate %s "DFID", rc:%d\n",
		       osd->od_svname, fname, PFID(&oti->oti_fid), rc);
		GOTO(out, rc = PTR_ERR(admin));
	}

	if (!dt_object_exists(admin)) {
		CERROR("%s: Old admin file %s doesn't exist, but is still "
		       " referenced in parent directory.\n",
		       osd->od_svname, fname);
		GOTO(out, rc = -ENOENT);
	}

	/* truncate the new quota index file in case of any leftovers
	 * from last failed migration */
	rc = truncate_quota_index(env, dt, feat);
	if (rc) {
		CERROR("%s: Failed to truncate the quota index "DFID", rc:%d\n",
		       osd->od_svname, PFID(lu_object_fid(&dt->do_lu)), rc);
		GOTO(out, rc);
	}

	/* set up indexing operations for the admin file */
	admin->do_index_ops = &osd_admin_index_ops;

	LCONSOLE_INFO("%s: Migrate %s quota from old admin quota file(%s) to "
		      "new IAM quota index("DFID").\n", osd->od_svname,
		      isblk ? "block" : "inode", fname,
		      PFID(lu_object_fid(&dt->do_lu)));

	/* iterate the admin quota file, and insert each record into
	 * the new index file */
	rc = convert_quota_file(env, admin, dt, isblk);
	if (rc)
		CERROR("%s: Migrate old admin quota file(%s) failed, rc:%d\n",
		       osd->od_svname, fname, rc);
	converted = true;
out:
	/* if no migration happen, we need to set the default grace time. */
	if (!converted && rc == 0) {
		struct lquota_glb_rec *rec = &oti->oti_quota_rec.lqr_glb_rec;

		rec->qbr_hardlimit = 0;
		rec->qbr_softlimit = 0;
		rec->qbr_granted = 0;
		rec->qbr_time = isblk ? MAX_DQ_TIME : MAX_IQ_TIME;

		rc = lquota_disk_write_glb(env, dt, 0, rec);
		if (rc)
			CERROR("%s: Failed to set default grace time for "
			       "index("DFID"), rc:%d\n", osd->od_svname,
			       PFID(lu_object_fid(&dt->do_lu)), rc);
	}

	/* bump index version to 1 (or 2 if migration happened), so the
	 * migration will be skipped next time. */
	if (rc == 0) {
		rc = set_quota_index_version(env , dt, converted ? 2 : 1);
		if (rc)
			CERROR("%s: Failed to set quota index("DFID") "
			       "version, rc:%d\n", osd->od_svname,
			       PFID(lu_object_fid(&dt->do_lu)), rc);
	}

	if (admin && !IS_ERR(admin))
		lu_object_put(env, &admin->do_lu);
	if (parent && !IS_ERR(parent))
		lu_object_put(env, &parent->do_lu);
	lu_object_put(env, &root->do_lu);

	RETURN(rc);
}
#else
#warning "remove old quota compatibility code"
#endif
