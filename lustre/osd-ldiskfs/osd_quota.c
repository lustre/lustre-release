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
 * Copyright (c) 2012, 2015, Intel Corporation.
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
	switch (fid_oid(fid)) {
	case ACCT_USER_OID:
		return USRQUOTA;
	case ACCT_GROUP_OID:
		return GRPQUOTA;
	case ACCT_PROJECT_OID:
		return PRJQUOTA;
	}

	LASSERTF(0, "invalid fid for quota type: %u", fid_oid(fid));
	return USRQUOTA;
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

	ENTRY;
	LASSERT(fid_is_acct(fid));

	if (!LDISKFS_HAS_RO_COMPAT_FEATURE(sb,
					   LDISKFS_FEATURE_RO_COMPAT_QUOTA))
		RETURN(-ENOENT);

	id->oii_gen = OSD_OII_NOGEN;
	switch (fid2type(fid)) {
	case USRQUOTA:
		id->oii_ino =
			le32_to_cpu(LDISKFS_SB(sb)->s_es->s_usr_quota_inum);
		break;
	case GRPQUOTA:
		id->oii_ino =
			le32_to_cpu(LDISKFS_SB(sb)->s_es->s_grp_quota_inum);
		break;
	case PRJQUOTA:
 #ifdef HAVE_PROJECT_QUOTA
		if (LDISKFS_HAS_RO_COMPAT_FEATURE(sb,
					LDISKFS_FEATURE_RO_COMPAT_PROJECT))
			id->oii_ino =
				le32_to_cpu(LDISKFS_SB(sb)->s_es->s_prj_quota_inum);
		else
 #endif
			RETURN(-ENOENT);
		break;
	}
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
 * \param dtkey - is the id of the user or group for which we would
 *                like to access disk usage.
 *
 * \retval +ve - success : exact match
 * \retval -ve - failure
 */
static int osd_acct_index_lookup(const struct lu_env *env,
				 struct dt_object *dtobj,
				 struct dt_rec *dtrec,
				 const struct dt_key *dtkey)
{
	struct osd_thread_info	*info = osd_oti_get(env);
#if defined(HAVE_DQUOT_QC_DQBLK)
	struct qc_dqblk		*dqblk = &info->oti_qdq;
#elif defined(HAVE_DQUOT_FS_DISK_QUOTA)
	struct fs_disk_quota	*dqblk = &info->oti_fdq;
#else
	struct if_dqblk		*dqblk = &info->oti_dqblk;
#endif
	struct super_block	*sb = osd_sb(osd_obj2dev(osd_dt_obj(dtobj)));
	struct lquota_acct_rec	*rec = (struct lquota_acct_rec *)dtrec;
	__u64			 id = *((__u64 *)dtkey);
	int			 rc;
#ifdef HAVE_DQUOT_KQID
	struct kqid		 qid;
#endif
	int type;

	ENTRY;

	type = fid2type(lu_object_fid(&dtobj->do_lu));
	memset(dqblk, 0, sizeof(*dqblk));
#ifdef HAVE_DQUOT_KQID
	qid = make_kqid(&init_user_ns, type, id);
	rc = sb->s_qcop->get_dqblk(sb, qid, dqblk);
#else
	rc = sb->s_qcop->get_dqblk(sb, type, (qid_t) id, dqblk);
#endif
	if (rc)
		RETURN(rc);
#if defined(HAVE_DQUOT_QC_DQBLK)
	rec->bspace = dqblk->d_space;
	rec->ispace = dqblk->d_ino_count;
#elif defined(HAVE_DQUOT_FS_DISK_QUOTA)
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
 */
static struct dt_it *osd_it_acct_init(const struct lu_env *env,
				      struct dt_object *dt,
				      __u32 attr)
{
	struct osd_it_quota	*it;
	struct lu_object	*lo = &dt->do_lu;
	struct osd_object	*obj = osd_dt_obj(dt);

	ENTRY;

	LASSERT(lu_object_exists(lo));

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	lu_object_get(lo);
	it->oiq_obj = obj;
	INIT_LIST_HEAD(&it->oiq_list);

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

	osd_object_put(env, it->oiq_obj);

	list_for_each_entry_safe(leaf, tmp, &it->oiq_list, oql_link) {
		list_del_init(&leaf->oql_link);
		OBD_FREE_PTR(leaf);
	}

	OBD_FREE_PTR(it);

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
	int			 type;
	qid_t			 dqid = *(qid_t *)key;
	loff_t			 offset;
	int			 rc;

	ENTRY;
	type = fid2type(fid);

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
	INIT_LIST_HEAD(&leaf->oql_link);
	leaf->oql_blk = it->oiq_blk[depth];
	list_add_tail(&leaf->oql_link, &it->oiq_list);
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
	int			 type;
	int			 depth, rc;
	uint			 index;

	ENTRY;

	type = fid2type(fid);

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

	rc = osd_acct_index_lookup(env, &it->oiq_obj->oo_dt, dtrec, key);
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
	return oh->ot_id_types[i];
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
 *                   group quota, or sync commit flags to the caller
 *
 * \retval 0       - success
 * \retval -ve     - failure
 */
int osd_declare_qid(const struct lu_env *env, struct osd_thandle *oh,
		    struct lquota_id_info *qi, struct osd_object *obj,
		    bool enforce, int *flags)
{
	struct osd_device       *dev;
	struct qsd_instance     *qsd;
	struct inode		*inode = NULL;
	int                      i, rc = 0, crd;
	bool                     found = false;
	ENTRY;

	LASSERT(oh != NULL);
	LASSERTF(oh->ot_id_cnt <= OSD_MAX_UGID_CNT, "count=%d\n",
		 oh->ot_id_cnt);

	dev = osd_dt_dev(oh->ot_super.th_dev);
	LASSERT(dev != NULL);

	qsd = dev->od_quota_slave;

	for (i = 0; i < oh->ot_id_cnt; i++) {
		if (oh->ot_id_array[i] == qi->lqi_id.qid_uid &&
		    oh->ot_id_types[i] == qi->lqi_type) {
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

		/* root ID entry should be always present in the quota file */
		if (qi->lqi_id.qid_uid == 0) {
			crd = 1;
		} else {
			/* used space for this ID could be dropped to zero,
			 * reserve extra credits for removing ID entry from
			 * the quota file */
			if (qi->lqi_space < 0)
				crd = LDISKFS_QUOTA_DEL_BLOCKS(osd_sb(dev));
			/* reserve credits for adding ID entry to the quota
			 * file if the i_dquot isn't initialized yet. */
			else if (inode == NULL ||
#ifdef HAVE_EXT4_INFO_DQUOT
				 LDISKFS_I(inode)->i_dquot[qi->lqi_type] == NULL)
#else
				 inode->i_dquot[qi->lqi_type] == NULL)
#endif
				crd = LDISKFS_QUOTA_INIT_BLOCKS(osd_sb(dev));
			else
				crd = 1;
		}

		osd_trans_declare_op(env, oh, OSD_OT_QUOTA, crd);

		oh->ot_id_array[i] = qi->lqi_id.qid_uid;
		oh->ot_id_types[i] = qi->lqi_type;
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
 * \param  flags  - if the operation is write, return no user quota, no
 *                  group quota, or sync commit flags to the caller
 * \param osd_qid_flags - indicate this is a inode/block accounting
 *			and whether changes are performed by root user
 *
 * \retval 0      - success
 * \retval -ve    - failure
 */
int osd_declare_inode_qid(const struct lu_env *env, qid_t uid, qid_t gid,
			  __u32 projid, long long space, struct osd_thandle *oh,
			  struct osd_object *obj, int *flags,
			  enum osd_qid_declare_flags osd_qid_declare_flags)
{
	struct osd_thread_info  *info = osd_oti_get(env);
	struct lquota_id_info   *qi = &info->oti_qi;
	int rcu, rcg, rcp = 0; /* user & group & project rc */
	bool force = !!(osd_qid_declare_flags & OSD_QID_FORCE);
	ENTRY;

	/* let's start with user quota */
	qi->lqi_id.qid_uid = uid;
	qi->lqi_type       = USRQUOTA;
	qi->lqi_space      = space;
	qi->lqi_is_blk     = !!(osd_qid_declare_flags & OSD_QID_BLK);
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

#ifdef HAVE_PROJECT_QUOTA
	if (rcg && (rcg != -EDQUOT || flags == NULL))
		RETURN(rcg);

	/* and now project quota */
	qi->lqi_id.qid_projid = projid;
	qi->lqi_type = PRJQUOTA;
	rcp = osd_declare_qid(env, oh, qi, obj, true, flags);

	if (force && (rcp == -EDQUOT || rcp == -EINPROGRESS))
		/* as before, ignore EDQUOT & EINPROGRESS for root */
		rcp = 0;
#endif

	RETURN(rcu ? rcu : (rcg ? rcg : rcp));
}
