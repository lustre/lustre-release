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
 * Author: Niu    Yawei    <niu@whamcloud.com>
 */

#include <lquota.h>
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

	ENTRY;
	LASSERT(fid_is_acct(fid));

	if (!LDISKFS_HAS_RO_COMPAT_FEATURE(sb,
					   LDISKFS_FEATURE_RO_COMPAT_QUOTA))
		RETURN(-ENOENT);

	id->oii_gen = OSD_OII_NOGEN;
	id->oii_ino = LDISKFS_SB(sb)->s_qf_inums[fid2type(fid)];
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
	struct if_dqblk		*dqblk = &info->oti_dqblk;
	struct super_block	*sb = osd_sb(osd_obj2dev(osd_dt_obj(dtobj)));
	struct acct_rec		*rec = (struct acct_rec *)dtrec;
	__u64			 id = *((__u64 *)dtkey);
	int			 rc;

	ENTRY;

	memset((void *)dqblk, 0, sizeof(struct obd_dqblk));
	rc = sb->s_qcop->get_dqblk(sb, obj2type(dtobj), (qid_t) id, dqblk);
	if (rc)
		RETURN(rc);
	rec->bspace = dqblk->dqb_curspace;
	rec->ispace = dqblk->dqb_curinodes;
	RETURN(+1);
}

#define QUOTA_IT_READ_ERROR(it, rc)                                    \
	CERROR("%s: Error while trying to read quota information, "    \
	       "failed with %d\n",                                     \
	       it->oiq_obj->oo_dt.do_lu.lo_dev->ld_obd->obd_name, rc); \

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

	ENTRY;
	lu_object_put(env, &it->oiq_obj->oo_dt.do_lu);
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
	depth = LUSTRE_DQTREEDEPTH - 1;
	index = GETIDINDEX(it->oiq_id, depth);
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
		}
	}
	rc = 1;

	/* We have consumed all the entries of the current leaf block, move on
	 * to the next one. */
	depth--;

	/* We keep searching as long as walk_tree_dqentry() returns +1
	 * (= no valid entry found). */
	for (; depth >= 0 && rc > 0; depth--) {
		index = GETIDINDEX(it->oiq_id, depth);
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

