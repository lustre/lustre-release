/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * lustre/lfsck/lfsck_striped_dir.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

/*
 * About the verification for striped directory. Some rules and assumptions:
 *
 * 1) lmv_magic: The magic may be wrong. But it is almost impossible (1/2^32
 *    probability) that a master LMV EA claims as a slave LMV EA by wrong,
 *    so we can ignore such race case and the reverse case.
 *
 * 2) lmv_master_mdt_index: The master index can be self-verified by compared
 *    with the MDT index directly. The slave stripe index can be verified by
 *    compared with the file name. Although both the name entry and the LMV EA
 *    can be wrong, it is almost impossible that they hit the same bad data
 *    So if they match each other, then trust them. Similarly, for the shard,
 *    it stores index in both slave LMV EA and in linkEA, if the two copies
 *    match, then trust them.
 *
 * 3) lmv_hash_type: The valid hash type should be LMV_HASH_TYPE_ALL_CHARS or
 *    LMV_HASH_TYPE_FNV_1A_64. If the LFSCK instance on some slave finds that
 *    the name hash against the hash function does not match the MDT, then it
 *    will change the master LMV EA hash type as LMV_HASH_TYPE_UNKNOWN. With
 *    such hash type, the whole striped directory still can be accessed via
 *    lookup/readdir, and also support unlink, but cannot add new name entry.
 *
 * 3.1) If the master hash type is one of the valid values, then trust the
 *	master LMV EA. Because:
 *
 * 3.1.1) The master hash type is visible to the client and used by the client.
 *
 * 3.1.2) For a given name, different hash types may map the name entry to the
 *	  same MDT. So simply checking one name entry or some name entries may
 *	  cannot verify whether the hash type is correct or not.
 *
 * 3.1.3) Different shards can claim different hash types, it is not easy to
 *	  distinguish which ones are correct. Even though the master is wrong,
 *	  as the LFSCK processing, some LFSCK instance on other MDT may finds
 *	  unmatched name hash, then it will change the master hash type to
 *	  LMV_HASH_TYPE_UNKNOWN as described above. The worst case is euqal
 *	  to the case without the LFSCK.
 *
 * 3.2) If the master hash type is invalid, nor LMV_HASH_TYPE_UNKNOWN, then
 *	trust the first shard with valid hash type (ALL_CHARS or FNV_1A_64).
 *	If the shard is also worng, means there are double failures, then as
 *	the LFSCK processing, other LFSCK instances on the other MDTs may
 *	find unmatched name hash, and then, the master hash type will be
 *	changed to LMV_HASH_TYPE_UNKNOWN as described in the 3).
 *
 * 3.3) If the master hash type is LMV_HASH_TYPE_UNKNOWN, then it is possible
 *	that some other LFSCK instance on other MDT found bad name hash, then
 *	changed the master hash type to LMV_HASH_TYPE_UNKNOWN as described in
 *	the 3). But it also maybe because of data corruption in master LMV EA.
 *	To make such two cases to be distinguishable, when the LFSCK changes
 *	the master hash type to LMV_HASH_TYPE_UNKNOWN, it will mark in the
 *	master LMV EA (new lmv flags LMV_HASH_FLAG_BAD_TYPE). Then subsequent
 *	LFSCK checking can distinguish them: for former case, turst the master
 *	LMV EA with nothing to be done; otherwise, trust the first shard with
 *	valid hash type (ALL_CHARS or FNV_1A_64) as the 3.2) does.
 *
 * 4) lmv_stripe_count: For a shard of a striped directory, if its index has
 *    been verified as the 2), then the stripe count must be larger than its
 *    index. For the master object, by scanning each shard's index, the LFSCK
 *    can know the highest index, and the stripe count must be larger than the
 *    known highest index. If the stipe count in the LMV EA matches above two
 *    rules, then it is may be trustable. If both the master claimed stripe
 *    count and the slave claimed stripe count match each own rule, but they
 *    are not the same, then trust the master. Because the stripe count in
 *    the master LMV EA is visible to client and used to distribute the name
 *    entry to some shard, but the slave LMV EA is only used for verification
 *    and invisible to client.
 *
 * 5) If the master LMV EA is lost, then there are two possible cases:
 *
 * 5.1) The slave claims slave LMV EA by wrong, means that the parent was not
 *	a striped directory, but its sub-directory has a wrong slave LMV EA.
 *	It is very very race case, similar as the 1), can be ignored.
 *
 * 5.2) The parent directory is a striped directory, but the master LMV EA
 *	is lost or crashed. Then the LFSCK needs to re-generate the master
 *	LMV EA: the lmv_master_mdt_index is from the MDT device index; the
 *	lmv_hash_type is from the first valid shard; the lmv_stripe_count
 *	will be calculated via scanning all the shards.
 *
 * 5.2.1) Before re-generating the master LMV EA, the LFSCK needs to check
 *	  whether someone has created some file(s) under the master object
 *	  after the master LMV EA disappear. If yes, the LFSCK will cannot
 *	  re-generate the master LMV EA, otherwise, such new created files
 *	  will be invisible to client. Under such case, the LFSCK will mark
 *	  the master object as read only (without master LMV EA). Then all
 *	  things under the master MDT-object, including those new created
 *	  files and the shards themselves, will be visibile to client. And
 *	  then the administrator can handle the bad striped directory with
 *	  more human knowledge.
 *
 * 5.2.2) If someone created some special sub-directory under the master
 *	  MDT-object with the same naming rule as shard name $FID:$index,
 *	  as to the LFSCK cannot detect it before re-generating the master
 *	  LMV EA, then such sub-directory itself will be invisible after
 *	  the LFSCK re-generating the master LMV EA. The sub-items under
 *	  such sub-directory are still visible to client. As the LFSCK
 *	  processing, if such sub-directory cause some conflict with other
 *	  normal shard, such as the index conflict, then the LFSCK will
 *	  remove the master LMV EA and change the master MDT-object to
 *	  read-only mode as the 5.2.1). But if there is no conflict, the
 *	  LFSCK will regard such sub-directory as a striped shard that
 *	  lost its slave LMV EA, and will re-generate slave LMV EA for it.
 *
 * 5.2.3) Anytime, if the LFSCK found some shards name/index conflict,
 *	  and cannot make the distinguish which one is right, then it
 *	  will remove the master LMV EA and change the MDT-object to
 *	  read-only mode as the 5.2.2).
 */

#define DEBUG_SUBSYSTEM S_LFSCK

#include <lustre/lustre_idl.h>
#include <lu_object.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_lmv.h>
#include <lustre/lustre_user.h>

#include "lfsck_internal.h"

void lfsck_lmv_put(const struct lu_env *env, struct lfsck_lmv *llmv)
{
	if (llmv != NULL && atomic_dec_and_test(&llmv->ll_ref)) {
		if (llmv->ll_lslr != NULL)
			OBD_FREE_LARGE(llmv->ll_lslr,
				sizeof(struct lfsck_slave_lmv_rec) *
				llmv->ll_stripes_allocated);

		OBD_FREE_PTR(llmv);
	}
}

static inline bool lfsck_is_valid_slave_lmv(struct lmv_mds_md_v1 *lmv)
{
	return lmv->lmv_stripe_count >= 1 &&
	       lmv->lmv_stripe_count <= LFSCK_LMV_MAX_STRIPES &&
	       lmv->lmv_stripe_count > lmv->lmv_master_mdt_index &&
	       lmv_is_known_hash_type(lmv->lmv_hash_type);
}

int lfsck_read_stripe_lmv(const struct lu_env *env, struct dt_object *obj,
			  struct lmv_mds_md_v1 *lmv)
{
	struct dt_object *bottom;
	int		  rc;

	/* Currently, we only store the LMV header on disk. It is the LOD's
	 * duty to iterate the master MDT-object's directory to compose the
	 * integrated LMV EA. But here, we only want to load the LMV header,
	 * so we need to bypass LOD to avoid unnecessary iteration in LOD. */
	bottom = lu2dt(container_of0(obj->do_lu.lo_header->loh_layers.prev,
				     struct lu_object, lo_linkage));
	if (unlikely(bottom == NULL))
		return -ENOENT;

	dt_read_lock(env, bottom, 0);
	rc = dt_xattr_get(env, bottom, lfsck_buf_get(env, lmv, sizeof(*lmv)),
			  XATTR_NAME_LMV, BYPASS_CAPA);
	dt_read_unlock(env, bottom);
	if (rc != sizeof(*lmv))
		return rc > 0 ? -EINVAL : rc;

	lfsck_lmv_header_le_to_cpu(lmv, lmv);
	if ((lmv->lmv_magic == LMV_MAGIC &&
	     !(lmv->lmv_hash_type & LMV_HASH_FLAG_MIGRATION)) ||
	    (lmv->lmv_magic == LMV_MAGIC_STRIPE &&
	     !(lmv->lmv_hash_type & LMV_HASH_FLAG_DEAD)))
		return 0;

	return -ENODATA;
}

/**
 * Parse the shard's index from the given shard name.
 *
 * The valid shard name/type should be:
 * 1) The type must be S_IFDIR
 * 2) The name should be $FID:$index
 * 3) the index should within valid range.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] name	the shard name
 * \param[in] namelen	the name length
 * \param[in] type	the entry's type
 * \param[in] fid	the entry's FID
 *
 * \retval		zero or positive number for the index from the name
 * \retval		negative error number on failure
 */
int lfsck_shard_name_to_index(const struct lu_env *env, const char *name,
			      int namelen, __u16 type, const struct lu_fid *fid)
{
	char	*name2	= lfsck_env_info(env)->lti_tmpbuf2;
	int	 len;
	int	 idx	= 0;

	if (!S_ISDIR(type))
		return -ENOTDIR;

	LASSERT(name != name2);

	len = snprintf(name2, sizeof(lfsck_env_info(env)->lti_tmpbuf2),
		       DFID":", PFID(fid));
	if (namelen < len + 1 || memcmp(name, name2, len) != 0)
		return -EINVAL;

	do {
		if (!isdigit(name[len]))
			return -EINVAL;

		idx = idx * 10 + name[len++] - '0';
	} while (len < namelen);

	if (idx >= LFSCK_LMV_MAX_STRIPES)
		return -EINVAL;

	return idx;
}

bool lfsck_is_valid_slave_name_entry(const struct lu_env *env,
				     struct lfsck_lmv *llmv,
				     const char *name, int namelen)
{
	struct lmv_mds_md_v1	*lmv;
	int			 idx;

	if (llmv == NULL || !llmv->ll_lmv_slave || !llmv->ll_lmv_verified)
		return true;

	lmv = &llmv->ll_lmv;
	idx = lmv_name_to_stripe_index(lmv->lmv_hash_type,
				       lmv->lmv_stripe_count,
				       name, namelen);
	if (unlikely(idx != lmv->lmv_master_mdt_index))
		return false;

	return true;
}

/**
 * Check whether the given name is a valid entry under the @parent.
 *
 * If the @parent is a striped directory then the @child should one
 * shard of the striped directory, its name should be $FID:$index.
 *
 * If the @parent is a shard of a striped directory, then the name hash
 * should match the MDT, otherwise it is invalid.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] parent	the parent directory
 * \param[in] child	the child object to be checked
 * \param[in] cname	the name for the @child in the parent directory
 *
 * \retval		positive number for invalid name entry
 * \retval		0 if the name is valid or uncertain
 * \retval		negative error number on failure
 */
int lfsck_namespace_check_name(const struct lu_env *env,
			       struct dt_object *parent,
			       struct dt_object *child,
			       const struct lu_name *cname)
{
	struct lmv_mds_md_v1	*lmv = &lfsck_env_info(env)->lti_lmv;
	int			 idx;
	int			 rc;

	rc = lfsck_read_stripe_lmv(env, parent, lmv);
	if (rc != 0)
		RETURN(rc == -ENODATA ? 0 : rc);

	if (lmv->lmv_magic == LMV_MAGIC_STRIPE) {
		if (!lfsck_is_valid_slave_lmv(lmv))
			return 0;

		idx = lmv_name_to_stripe_index(lmv->lmv_hash_type,
					       lmv->lmv_stripe_count,
					       cname->ln_name,
					       cname->ln_namelen);
		if (unlikely(idx != lmv->lmv_master_mdt_index))
			return 1;
	} else if (lfsck_shard_name_to_index(env, cname->ln_name,
			cname->ln_namelen, lfsck_object_type(child),
			lfsck_dto2fid(child)) < 0) {
		return 1;
	}

	return 0;
}

/**
 * Update the object's LMV EA with the given @lmv.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the object which LMV EA will be updated
 * \param[in] lmv	pointer to buffer holding the new LMV EA
 * \param[in] locked	whether the caller has held ldlm lock on the @obj or not
 *
 * \retval		positive number for nothing to be done
 * \retval		zero if updated successfully
 * \retval		negative error number on failure
 */
int lfsck_namespace_update_lmv(const struct lu_env *env,
			       struct lfsck_component *com,
			       struct dt_object *obj,
			       struct lmv_mds_md_v1 *lmv, bool locked)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lmv_mds_md_v1		*lmv4	= &info->lti_lmv4;
	struct lu_buf			*buf	= &info->lti_buf;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck_obj2dt_dev(obj);
	struct thandle			*th	= NULL;
	struct lustre_handle		 lh	= { 0 };
	int				 rc	= 0;
	int				 rc1	= 0;
	ENTRY;

	LASSERT(lmv4 != lmv);

	lfsck_lmv_header_cpu_to_le(lmv4, lmv);
	lfsck_buf_init(buf, lmv4, sizeof(*lmv4));

	if (!locked) {
		rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
				      MDS_INODELOCK_UPDATE |
				      MDS_INODELOCK_XATTR, LCK_EX);
		if (rc != 0)
			GOTO(log, rc);
	}

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	/* For remote updating LMV EA, there will be further LFSCK action on
	 * remote MDT after the updating, so update the LMV EA synchronously. */
	if (dt_object_remote(obj))
		th->th_sync = 1;

	rc = dt_declare_xattr_set(env, obj, buf, XATTR_NAME_LMV, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	if (unlikely(lfsck_is_dead_obj(obj)))
		GOTO(unlock, rc = 1);

	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(unlock, rc = 0);

	rc = dt_xattr_set(env, obj, buf, XATTR_NAME_LMV, 0, th, BYPASS_CAPA);

	GOTO(unlock, rc);

unlock:
	dt_write_unlock(env, obj);

stop:
	rc1 = dt_trans_stop(env, dev, th);
	if (rc == 0)
		rc = rc1;

log:
	lfsck_ibits_unlock(&lh, LCK_EX);
	CDEBUG(D_LFSCK, "%s: namespace LFSCK updated the %s LMV EA "
	       "for the object "DFID": rc = %d\n",
	       lfsck_lfsck2name(lfsck),
	       lmv->lmv_magic == LMV_MAGIC ? "master" : "slave",
	       PFID(lfsck_dto2fid(obj)), rc);

	return rc;
}

/**
 * Set master LMV EA for the specified striped directory.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] dir	pointer to the object on which the LMV EA will be set
 * \param[in] lmv	pointer to the buffer holding the new LMV EA
 * \param[in] cfid	the shard's FID used for verification
 * \param[in] cidx	the shard's index used for verification
 * \param[in] flags	to indicate which element(s) in the LMV EA will be set
 *
 * \retval		positive number if nothing to be done
 * \retval		zero for succeed
 * \retval		negative error number on failure
 */
static int lfsck_namespace_set_lmv_master(const struct lu_env *env,
					  struct lfsck_component *com,
					  struct dt_object *dir,
					  struct lmv_mds_md_v1 *lmv,
					  const struct lu_fid *cfid,
					  __u32 cidx, __u32 flags)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lmv_mds_md_v1		*lmv3	= &info->lti_lmv3;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_object		*obj;
	struct lustre_handle		 lh	= { 0 };
	int				 pidx	= -1;
	int				 rc	= 0;
	ENTRY;

	/* Find the bottom object to bypass LOD when set LMV EA. */
	obj = lu2dt(container_of0(dir->do_lu.lo_header->loh_layers.prev,
				  struct lu_object, lo_linkage));
	if (unlikely(obj == NULL))
		RETURN(-ENOENT);

	if (dt_object_remote(obj)) {
		struct lu_seq_range	*range	= &info->lti_range;
		struct seq_server_site	*ss	=
			lu_site2seq(lfsck->li_bottom->dd_lu_dev.ld_site);

		fld_range_set_mdt(range);
		rc = fld_server_lookup(env, ss->ss_server_fld,
				       fid_seq(lfsck_dto2fid(obj)), range);
		if (rc != 0)
			GOTO(log, rc);

		pidx = range->lsr_index;
	} else {
		pidx = lfsck_dev_idx(lfsck->li_bottom);
	}

	/* XXX: it will be improved with subsequent patches landed. */

	rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
			      MDS_INODELOCK_UPDATE | MDS_INODELOCK_XATTR,
			      LCK_EX);
	if (rc != 0)
		GOTO(log, rc);

	rc = lfsck_read_stripe_lmv(env, obj, lmv3);
	if (rc != 0)
		GOTO(log, rc);

	lmv3->lmv_hash_type = lmv->lmv_hash_type;
	lmv3->lmv_magic = LMV_MAGIC;
	lmv3->lmv_master_mdt_index = pidx;

	rc = lfsck_namespace_update_lmv(env, com, obj, lmv3, true);

	GOTO(log, rc);

log:
	lfsck_ibits_unlock(&lh, LCK_EX);
	CDEBUG(D_LFSCK, "%s: namespace LFSCK set master LMV EA for the object "
	       DFID" on the %s MDT %d, flags %x: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(obj)),
	       dt_object_remote(obj) ? "remote" : "local", pidx, flags, rc);

	if (rc <= 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
	}

	return rc;
}

/**
 * Repair the bad name hash.
 *
 * If the name hash of some name entry under the striped directory does not
 * match the shard of the striped directory, then the LFSCK will repair the
 * inconsistency. Ideally, the LFSCK should migrate the name entry from the
 * current MDT to the right MDT (another one), but before the async commit
 * finished, the LFSCK will change the striped directory's hash type as
 * LMV_HASH_TYPE_UNKNOWN and mark the lmv flags as LMV_HASH_FLAG_BAD_TYPE.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] shard	pointer to the shard of the striped directory that
 *			contains the bad name entry
 * \param[in] llmv	pointer to lfsck LMV EA structure
 * \param[in] name	the name of the bad name hash
 *
 * \retval		positive number if nothing to be done
 * \retval		zero for succeed
 * \retval		negative error number on failure
 */
int lfsck_namespace_repair_bad_name_hash(const struct lu_env *env,
					 struct lfsck_component *com,
					 struct dt_object *shard,
					 struct lfsck_lmv *llmv,
					 const char *name)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_fid			*pfid	= &info->lti_fid3;
	struct lmv_mds_md_v1		*lmv2	= &info->lti_lmv2;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_object		*parent	= NULL;
	int				 rc	= 0;
	ENTRY;

	rc = dt_lookup(env, shard, (struct dt_rec *)pfid,
		       (const struct dt_key *)dotdot, BYPASS_CAPA);
	if (rc != 0 || !fid_is_sane(pfid))
		GOTO(log, rc);

	parent = lfsck_object_find_bottom(env, lfsck, pfid);
	if (IS_ERR(parent))
		GOTO(log, rc = PTR_ERR(parent));

	*lmv2 = llmv->ll_lmv;
	lmv2->lmv_hash_type = LMV_HASH_TYPE_UNKNOWN | LMV_HASH_FLAG_BAD_TYPE;
	rc = lfsck_namespace_set_lmv_master(env, com, parent, lmv2,
					    lfsck_dto2fid(shard),
					    llmv->ll_lmv.lmv_master_mdt_index,
					    LEF_SET_LMV_HASH);

	GOTO(log, rc);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant found bad name hash "
	       "on the MDT %x, parent "DFID", name %s, shard_%x "DFID
	       ": rc = %d\n",
	       lfsck_lfsck2name(lfsck), lfsck_dev_idx(lfsck->li_bottom),
	       PFID(pfid), name, llmv->ll_lmv.lmv_master_mdt_index,
	       PFID(lfsck_dto2fid(shard)), rc);

	if (parent != NULL && !IS_ERR(parent))
		lfsck_object_put(env, parent);

	return rc;
}

/**
 * Verify the slave object's (of striped directory) LMV EA.
 *
 * For the slave object of a striped directory, before traversing the shard
 * the LFSCK will verify whether its slave LMV EA matches its parent's master
 * LMV EA or not.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the object which LMV EA will be checked
 * \param[in] llmv	pointer to buffer holding the slave LMV EA
 *
 * \retval		zero for succeed
 * \retval		negative error number on failure
 */
int lfsck_namespace_verify_stripe_slave(const struct lu_env *env,
					struct lfsck_component *com,
					struct dt_object *obj,
					struct lfsck_lmv *llmv)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	char				*name	= info->lti_key;
	char				*name2;
	struct lu_fid			*pfid	= &info->lti_fid3;
	struct lu_fid			*tfid	= &info->lti_fid4;
	const struct lu_fid		*cfid	= lfsck_dto2fid(obj);
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lmv_mds_md_v1		*clmv	= &llmv->ll_lmv;
	struct lmv_mds_md_v1		*plmv	= &info->lti_lmv;
	struct dt_object		*parent	= NULL;
	int				 rc	= 0;
	ENTRY;

	if (!lfsck_is_valid_slave_lmv(clmv)) {
		rc = lfsck_namespace_trace_update(env, com, cfid,
					LNTF_UNCERTAIN_LMV, true);

		GOTO(out, rc);
	}

	rc = dt_lookup(env, obj, (struct dt_rec *)pfid,
		       (const struct dt_key *)dotdot, BYPASS_CAPA);
	if (rc != 0 || !fid_is_sane(pfid)) {
		rc = lfsck_namespace_trace_update(env, com, cfid,
					LNTF_UNCERTAIN_LMV, true);

		GOTO(out, rc);
	}

	parent = lfsck_object_find(env, lfsck, pfid);
	if (IS_ERR(parent)) {
		rc = lfsck_namespace_trace_update(env, com, cfid,
					LNTF_UNCERTAIN_LMV, true);

		GOTO(out, rc);
	}

	rc = lfsck_read_stripe_lmv(env, parent, plmv);
	if (rc != 0) {
		int rc1;

		/* If the parent has no LMV EA, then it maybe because:
		 * 1) The parent lost the LMV EA.
		 * 2) The child claims a wrong (slave) LMV EA. */

		/* XXX: to be improved. */
		rc = 0;

		rc1 = lfsck_namespace_trace_update(env, com, cfid,
						   LNTF_UNCERTAIN_LMV, true);

		GOTO(out, rc = (rc < 0 ? rc : rc1));
	}

	/* Unmatched magic or stripe count. */
	if (unlikely(plmv->lmv_magic != LMV_MAGIC ||
		     plmv->lmv_stripe_count != clmv->lmv_stripe_count)) {
		rc = lfsck_namespace_trace_update(env, com, cfid,
						  LNTF_UNCERTAIN_LMV, true);

		GOTO(out, rc);
	}

	/* If the master hash type has been set as LMV_HASH_TYPE_UNKNOWN,
	 * then the slave hash type is not important. */
	if ((plmv->lmv_hash_type & LMV_HASH_TYPE_MASK) ==
	    LMV_HASH_TYPE_UNKNOWN &&
	    plmv->lmv_hash_type & LMV_HASH_FLAG_BAD_TYPE)
		GOTO(out, rc = 0);

	/* Unmatched hash type. */
	if (unlikely((plmv->lmv_hash_type & LMV_HASH_TYPE_MASK) !=
		     (clmv->lmv_hash_type & LMV_HASH_TYPE_MASK))) {
		rc = lfsck_namespace_trace_update(env, com, cfid,
						  LNTF_UNCERTAIN_LMV, true);

		GOTO(out, rc);
	}

	snprintf(info->lti_tmpbuf2, sizeof(info->lti_tmpbuf2), DFID":%u",
		 PFID(cfid), clmv->lmv_master_mdt_index);
	name2 = info->lti_tmpbuf2;

	rc = lfsck_links_get_first(env, obj, name, tfid);
	if (rc == 0 && strcmp(name, name2) == 0 && lu_fid_eq(pfid, tfid)) {
		llmv->ll_lmv_verified = 1;

		GOTO(out, rc);
	}

	rc = dt_lookup(env, parent, (struct dt_rec *)tfid,
		       (const struct dt_key *)name2, BYPASS_CAPA);
	if (rc != 0 || !lu_fid_eq(cfid, tfid))
		rc = lfsck_namespace_trace_update(env, com, cfid,
						  LNTF_UNCERTAIN_LMV, true);
	else
		llmv->ll_lmv_verified = 1;

	GOTO(out, rc);

out:
	if (parent != NULL && !IS_ERR(parent))
		lfsck_object_put(env, parent);

	return rc;
}

/**
 * Double scan the striped directory or the shard.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] lnr	pointer to the namespace request that contains the
 *			striped directory or the shard
 *
 * \retval		zero for succeed
 * \retval		negative error number on failure
 */
int lfsck_namespace_striped_dir_rescan(const struct lu_env *env,
				       struct lfsck_component *com,
				       struct lfsck_namespace_req *lnr)
{
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct lfsck_lmv		*llmv	= lnr->lnr_lmv;
	struct dt_object		*dir	= lnr->lnr_obj;
	ENTRY;

	/* XXX: it will be improved with subsequent patches landed. */

	if (llmv->ll_lmv_slave && llmv->ll_lmv_verified) {
		ns->ln_striped_shards_scanned++;
		lfsck_namespace_trace_update(env, com,
					lfsck_dto2fid(dir),
					LNTF_UNCERTAIN_LMV |
					LNTF_RECHECK_NAME_HASH, false);
	}

	RETURN(0);
}
