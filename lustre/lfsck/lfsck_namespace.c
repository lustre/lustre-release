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
 * Copyright (c) 2013, 2017, Intel Corporation.
 */
/*
 * lustre/lfsck/lfsck_namespace.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LFSCK

#include <lu_object.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>

#include "lfsck_internal.h"

#define LFSCK_NAMESPACE_MAGIC_V1	0xA0629D03
#define LFSCK_NAMESPACE_MAGIC_V2	0xA0621A0B
#define LFSCK_NAMESPACE_MAGIC_V3	0xA06249FF

/* For Lustre-2.x (x <= 6), the namespace LFSCK used LFSCK_NAMESPACE_MAGIC_V1
 * as the trace file magic. When downgrade to such old release, the old LFSCK
 * will not recognize the new LFSCK_NAMESPACE_MAGIC_V2 in the new trace file,
 * then it will reset the whole LFSCK, and will not cause start failure. The
 * similar case will happen when upgrade from such old release. */
#define LFSCK_NAMESPACE_MAGIC		LFSCK_NAMESPACE_MAGIC_V3

enum lfsck_nameentry_check {
	LFSCK_NAMEENTRY_DEAD		= 1, /* The object has been unlinked. */
	LFSCK_NAMEENTRY_REMOVED		= 2, /* The entry has been removed. */
	LFSCK_NAMEENTRY_RECREATED	= 3, /* The entry has been recreated. */
};

static struct lfsck_namespace_req *
lfsck_namespace_assistant_req_init(struct lfsck_instance *lfsck,
				   struct lfsck_assistant_object *lso,
				   struct lu_dirent *ent, __u16 type)
{
	struct lfsck_namespace_req *lnr;
	int			    size;

	size = sizeof(*lnr) + (ent->lde_namelen & ~3) + 4;
	OBD_ALLOC(lnr, size);
	if (lnr == NULL)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&lnr->lnr_lar.lar_list);
	lnr->lnr_lar.lar_parent = lfsck_assistant_object_get(lso);
	lnr->lnr_lmv = lfsck_lmv_get(lfsck->li_lmv);
	lnr->lnr_fid = ent->lde_fid;
	lnr->lnr_dir_cookie = ent->lde_hash;
	lnr->lnr_attr = ent->lde_attrs;
	lnr->lnr_size = size;
	lnr->lnr_type = type;
	lnr->lnr_namelen = ent->lde_namelen;
	memcpy(lnr->lnr_name, ent->lde_name, ent->lde_namelen);

	return lnr;
}

static void lfsck_namespace_assistant_req_fini(const struct lu_env *env,
					       struct lfsck_assistant_req *lar)
{
	struct lfsck_namespace_req *lnr =
		container_of(lar, struct lfsck_namespace_req, lnr_lar);

	if (lnr->lnr_lmv != NULL)
		lfsck_lmv_put(env, lnr->lnr_lmv);

	lfsck_assistant_object_put(env, lar->lar_parent);
	OBD_FREE(lnr, lnr->lnr_size);
}

static void lfsck_namespace_le_to_cpu(struct lfsck_namespace *dst,
				      struct lfsck_namespace *src)
{
	dst->ln_magic = le32_to_cpu(src->ln_magic);
	dst->ln_status = le32_to_cpu(src->ln_status);
	dst->ln_flags = le32_to_cpu(src->ln_flags);
	dst->ln_success_count = le32_to_cpu(src->ln_success_count);
	dst->ln_run_time_phase1 = le64_to_cpu(src->ln_run_time_phase1);
	dst->ln_run_time_phase2 = le64_to_cpu(src->ln_run_time_phase2);
	dst->ln_time_last_complete = le64_to_cpu(src->ln_time_last_complete);
	dst->ln_time_latest_start = le64_to_cpu(src->ln_time_latest_start);
	dst->ln_time_last_checkpoint =
				le64_to_cpu(src->ln_time_last_checkpoint);
	lfsck_position_le_to_cpu(&dst->ln_pos_latest_start,
				 &src->ln_pos_latest_start);
	lfsck_position_le_to_cpu(&dst->ln_pos_last_checkpoint,
				 &src->ln_pos_last_checkpoint);
	lfsck_position_le_to_cpu(&dst->ln_pos_first_inconsistent,
				 &src->ln_pos_first_inconsistent);
	dst->ln_items_checked = le64_to_cpu(src->ln_items_checked);
	dst->ln_items_repaired = le64_to_cpu(src->ln_items_repaired);
	dst->ln_items_failed = le64_to_cpu(src->ln_items_failed);
	dst->ln_dirs_checked = le64_to_cpu(src->ln_dirs_checked);
	dst->ln_objs_checked_phase2 = le64_to_cpu(src->ln_objs_checked_phase2);
	dst->ln_objs_repaired_phase2 =
				le64_to_cpu(src->ln_objs_repaired_phase2);
	dst->ln_objs_failed_phase2 = le64_to_cpu(src->ln_objs_failed_phase2);
	dst->ln_objs_nlink_repaired = le64_to_cpu(src->ln_objs_nlink_repaired);
	fid_le_to_cpu(&dst->ln_fid_latest_scanned_phase2,
		      &src->ln_fid_latest_scanned_phase2);
	dst->ln_dirent_repaired = le64_to_cpu(src->ln_dirent_repaired);
	dst->ln_linkea_repaired = le64_to_cpu(src->ln_linkea_repaired);
	dst->ln_mul_linked_checked = le64_to_cpu(src->ln_mul_linked_checked);
	dst->ln_mul_linked_repaired = le64_to_cpu(src->ln_mul_linked_repaired);
	dst->ln_unknown_inconsistency =
				le64_to_cpu(src->ln_unknown_inconsistency);
	dst->ln_unmatched_pairs_repaired =
				le64_to_cpu(src->ln_unmatched_pairs_repaired);
	dst->ln_dangling_repaired = le64_to_cpu(src->ln_dangling_repaired);
	dst->ln_mul_ref_repaired = le64_to_cpu(src->ln_mul_ref_repaired);
	dst->ln_bad_type_repaired = le64_to_cpu(src->ln_bad_type_repaired);
	dst->ln_lost_dirent_repaired =
				le64_to_cpu(src->ln_lost_dirent_repaired);
	dst->ln_striped_dirs_scanned =
				le64_to_cpu(src->ln_striped_dirs_scanned);
	dst->ln_striped_dirs_repaired =
				le64_to_cpu(src->ln_striped_dirs_repaired);
	dst->ln_striped_dirs_failed =
				le64_to_cpu(src->ln_striped_dirs_failed);
	dst->ln_striped_dirs_disabled =
				le64_to_cpu(src->ln_striped_dirs_disabled);
	dst->ln_striped_dirs_skipped =
				le64_to_cpu(src->ln_striped_dirs_skipped);
	dst->ln_striped_shards_scanned =
				le64_to_cpu(src->ln_striped_shards_scanned);
	dst->ln_striped_shards_repaired =
				le64_to_cpu(src->ln_striped_shards_repaired);
	dst->ln_striped_shards_failed =
				le64_to_cpu(src->ln_striped_shards_failed);
	dst->ln_striped_shards_skipped =
				le64_to_cpu(src->ln_striped_shards_skipped);
	dst->ln_name_hash_repaired = le64_to_cpu(src->ln_name_hash_repaired);
	dst->ln_local_lpf_scanned = le64_to_cpu(src->ln_local_lpf_scanned);
	dst->ln_local_lpf_moved = le64_to_cpu(src->ln_local_lpf_moved);
	dst->ln_local_lpf_skipped = le64_to_cpu(src->ln_local_lpf_skipped);
	dst->ln_local_lpf_failed = le64_to_cpu(src->ln_local_lpf_failed);
	dst->ln_bitmap_size = le32_to_cpu(src->ln_bitmap_size);
	dst->ln_time_latest_reset = le64_to_cpu(src->ln_time_latest_reset);
	dst->ln_linkea_overflow_cleared =
				le64_to_cpu(src->ln_linkea_overflow_cleared);
	dst->ln_agent_entries_repaired =
				le64_to_cpu(src->ln_agent_entries_repaired);
}

static void lfsck_namespace_cpu_to_le(struct lfsck_namespace *dst,
				      struct lfsck_namespace *src)
{
	dst->ln_magic = cpu_to_le32(src->ln_magic);
	dst->ln_status = cpu_to_le32(src->ln_status);
	dst->ln_flags = cpu_to_le32(src->ln_flags);
	dst->ln_success_count = cpu_to_le32(src->ln_success_count);
	dst->ln_run_time_phase1 = cpu_to_le64(src->ln_run_time_phase1);
	dst->ln_run_time_phase2 = cpu_to_le64(src->ln_run_time_phase2);
	dst->ln_time_last_complete = cpu_to_le64(src->ln_time_last_complete);
	dst->ln_time_latest_start = cpu_to_le64(src->ln_time_latest_start);
	dst->ln_time_last_checkpoint =
				cpu_to_le64(src->ln_time_last_checkpoint);
	lfsck_position_cpu_to_le(&dst->ln_pos_latest_start,
				 &src->ln_pos_latest_start);
	lfsck_position_cpu_to_le(&dst->ln_pos_last_checkpoint,
				 &src->ln_pos_last_checkpoint);
	lfsck_position_cpu_to_le(&dst->ln_pos_first_inconsistent,
				 &src->ln_pos_first_inconsistent);
	dst->ln_items_checked = cpu_to_le64(src->ln_items_checked);
	dst->ln_items_repaired = cpu_to_le64(src->ln_items_repaired);
	dst->ln_items_failed = cpu_to_le64(src->ln_items_failed);
	dst->ln_dirs_checked = cpu_to_le64(src->ln_dirs_checked);
	dst->ln_objs_checked_phase2 = cpu_to_le64(src->ln_objs_checked_phase2);
	dst->ln_objs_repaired_phase2 =
				cpu_to_le64(src->ln_objs_repaired_phase2);
	dst->ln_objs_failed_phase2 = cpu_to_le64(src->ln_objs_failed_phase2);
	dst->ln_objs_nlink_repaired = cpu_to_le64(src->ln_objs_nlink_repaired);
	fid_cpu_to_le(&dst->ln_fid_latest_scanned_phase2,
		      &src->ln_fid_latest_scanned_phase2);
	dst->ln_dirent_repaired = cpu_to_le64(src->ln_dirent_repaired);
	dst->ln_linkea_repaired = cpu_to_le64(src->ln_linkea_repaired);
	dst->ln_mul_linked_checked = cpu_to_le64(src->ln_mul_linked_checked);
	dst->ln_mul_linked_repaired = cpu_to_le64(src->ln_mul_linked_repaired);
	dst->ln_unknown_inconsistency =
				cpu_to_le64(src->ln_unknown_inconsistency);
	dst->ln_unmatched_pairs_repaired =
				cpu_to_le64(src->ln_unmatched_pairs_repaired);
	dst->ln_dangling_repaired = cpu_to_le64(src->ln_dangling_repaired);
	dst->ln_mul_ref_repaired = cpu_to_le64(src->ln_mul_ref_repaired);
	dst->ln_bad_type_repaired = cpu_to_le64(src->ln_bad_type_repaired);
	dst->ln_lost_dirent_repaired =
				cpu_to_le64(src->ln_lost_dirent_repaired);
	dst->ln_striped_dirs_scanned =
				cpu_to_le64(src->ln_striped_dirs_scanned);
	dst->ln_striped_dirs_repaired =
				cpu_to_le64(src->ln_striped_dirs_repaired);
	dst->ln_striped_dirs_failed =
				cpu_to_le64(src->ln_striped_dirs_failed);
	dst->ln_striped_dirs_disabled =
				cpu_to_le64(src->ln_striped_dirs_disabled);
	dst->ln_striped_dirs_skipped =
				cpu_to_le64(src->ln_striped_dirs_skipped);
	dst->ln_striped_shards_scanned =
				cpu_to_le64(src->ln_striped_shards_scanned);
	dst->ln_striped_shards_repaired =
				cpu_to_le64(src->ln_striped_shards_repaired);
	dst->ln_striped_shards_failed =
				cpu_to_le64(src->ln_striped_shards_failed);
	dst->ln_striped_shards_skipped =
				cpu_to_le64(src->ln_striped_shards_skipped);
	dst->ln_name_hash_repaired = cpu_to_le64(src->ln_name_hash_repaired);
	dst->ln_local_lpf_scanned = cpu_to_le64(src->ln_local_lpf_scanned);
	dst->ln_local_lpf_moved = cpu_to_le64(src->ln_local_lpf_moved);
	dst->ln_local_lpf_skipped = cpu_to_le64(src->ln_local_lpf_skipped);
	dst->ln_local_lpf_failed = cpu_to_le64(src->ln_local_lpf_failed);
	dst->ln_bitmap_size = cpu_to_le32(src->ln_bitmap_size);
	dst->ln_time_latest_reset = cpu_to_le64(src->ln_time_latest_reset);
	dst->ln_linkea_overflow_cleared =
				cpu_to_le64(src->ln_linkea_overflow_cleared);
	dst->ln_agent_entries_repaired =
				cpu_to_le64(src->ln_agent_entries_repaired);
}

static void lfsck_namespace_record_failure(const struct lu_env *env,
					   struct lfsck_instance *lfsck,
					   struct lfsck_namespace *ns)
{
	struct lfsck_position pos;

	ns->ln_items_failed++;
	lfsck_pos_fill(env, lfsck, &pos, false);
	if (lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent) ||
	    lfsck_pos_is_eq(&pos, &ns->ln_pos_first_inconsistent) < 0) {
		ns->ln_pos_first_inconsistent = pos;

		CDEBUG(D_LFSCK, "%s: namespace LFSCK hit first non-repaired "
		       "inconsistency at the pos [%llu, "DFID", %#llx]\n",
		       lfsck_lfsck2name(lfsck),
		       ns->ln_pos_first_inconsistent.lp_oit_cookie,
		       PFID(&ns->ln_pos_first_inconsistent.lp_dir_parent),
		       ns->ln_pos_first_inconsistent.lp_dir_cookie);
	}
}

/**
 * Load the MDT bitmap from the lfsck_namespace trace file.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 *
 * \retval		0 for success
 * \retval		negative error number on failure or data corruption
 */
static int lfsck_namespace_load_bitmap(const struct lu_env *env,
				       struct lfsck_component *com)
{
	struct dt_object		*obj	= com->lc_obj;
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct cfs_bitmap			*bitmap = lad->lad_bitmap;
	ssize_t				 size;
	__u32				 nbits;
	int				 rc;
	ENTRY;

	if (com->lc_lfsck->li_mdt_descs.ltd_tgts_bitmap->size >
	    ns->ln_bitmap_size)
		nbits = com->lc_lfsck->li_mdt_descs.ltd_tgts_bitmap->size;
	else
		nbits = ns->ln_bitmap_size;

	if (unlikely(nbits < BITS_PER_LONG))
		nbits = BITS_PER_LONG;

	if (nbits > bitmap->size) {
		__u32 new_bits = bitmap->size;
		struct cfs_bitmap *new_bitmap;

		while (new_bits < nbits)
			new_bits <<= 1;

		new_bitmap = CFS_ALLOCATE_BITMAP(new_bits);
		if (new_bitmap == NULL)
			RETURN(-ENOMEM);

		lad->lad_bitmap = new_bitmap;
		CFS_FREE_BITMAP(bitmap);
		bitmap = new_bitmap;
	}

	if (ns->ln_bitmap_size == 0) {
		clear_bit(LAD_INCOMPLETE, &lad->lad_flags);
		CFS_RESET_BITMAP(bitmap);

		RETURN(0);
	}

	size = (ns->ln_bitmap_size + 7) >> 3;
	rc = dt_xattr_get(env, obj,
			  lfsck_buf_get(env, bitmap->data, size),
			  XATTR_NAME_LFSCK_BITMAP);
	if (rc != size)
		RETURN(rc >= 0 ? -EINVAL : rc);

	if (cfs_bitmap_check_empty(bitmap))
		clear_bit(LAD_INCOMPLETE, &lad->lad_flags);
	else
		set_bit(LAD_INCOMPLETE, &lad->lad_flags);

	RETURN(0);
}

/**
 * Load namespace LFSCK statistics information from the trace file.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_namespace_load(const struct lu_env *env,
				struct lfsck_component *com)
{
	int len = com->lc_file_size;
	int rc;

	rc = dt_xattr_get(env, com->lc_obj,
			  lfsck_buf_get(env, com->lc_file_disk, len),
			  XATTR_NAME_LFSCK_NAMESPACE);
	if (rc == len) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		lfsck_namespace_le_to_cpu(ns,
				(struct lfsck_namespace *)com->lc_file_disk);
		if (ns->ln_magic != LFSCK_NAMESPACE_MAGIC) {
			CDEBUG(D_LFSCK, "%s: invalid lfsck_namespace magic "
			       "%#x != %#x\n", lfsck_lfsck2name(com->lc_lfsck),
			       ns->ln_magic, LFSCK_NAMESPACE_MAGIC);
			rc = -ESTALE;
		} else {
			rc = 0;
		}
	} else if (rc != -ENODATA) {
		CDEBUG(D_LFSCK, "%s: fail to load lfsck_namespace, "
		       "expected = %d: rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck), len, rc);
		if (rc >= 0)
			rc = -ESTALE;
	}

	return rc;
}

static int lfsck_namespace_store(const struct lu_env *env,
				 struct lfsck_component *com)
{
	struct dt_object		*obj	= com->lc_obj;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct dt_device		*dev	= lfsck_obj2dev(obj);
	struct cfs_bitmap		*bitmap	= NULL;
	struct thandle			*handle;
	__u32				 nbits	= 0;
	int				 len    = com->lc_file_size;
	int				 rc;
	ENTRY;

	if (lad != NULL) {
		bitmap = lad->lad_bitmap;
		nbits = bitmap->size;

		LASSERT(nbits > 0);
		LASSERTF((nbits & 7) == 0, "Invalid nbits %u\n", nbits);
	}

	ns->ln_bitmap_size = nbits;
	lfsck_namespace_cpu_to_le((struct lfsck_namespace *)com->lc_file_disk,
				  ns);
	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		GOTO(log, rc = PTR_ERR(handle));

	rc = dt_declare_xattr_set(env, obj,
				  lfsck_buf_get(env, com->lc_file_disk, len),
				  XATTR_NAME_LFSCK_NAMESPACE, 0, handle);
	if (rc != 0)
		GOTO(out, rc);

	if (bitmap != NULL) {
		rc = dt_declare_xattr_set(env, obj,
				lfsck_buf_get(env, bitmap->data, nbits >> 3),
				XATTR_NAME_LFSCK_BITMAP, 0, handle);
		if (rc != 0)
			GOTO(out, rc);
	}

	rc = dt_trans_start_local(env, dev, handle);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_xattr_set(env, obj,
			  lfsck_buf_get(env, com->lc_file_disk, len),
			  XATTR_NAME_LFSCK_NAMESPACE, 0, handle);
	if (rc == 0 && bitmap != NULL)
		rc = dt_xattr_set(env, obj,
				  lfsck_buf_get(env, bitmap->data, nbits >> 3),
				  XATTR_NAME_LFSCK_BITMAP, 0, handle);

	GOTO(out, rc);

out:
	dt_trans_stop(env, dev, handle);

log:
	if (rc != 0)
		CDEBUG(D_LFSCK, "%s: fail to store lfsck_namespace: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);
	return rc;
}

static int lfsck_namespace_init(const struct lu_env *env,
				struct lfsck_component *com)
{
	struct lfsck_namespace *ns = com->lc_file_ram;
	int rc;

	memset(ns, 0, sizeof(*ns));
	ns->ln_magic = LFSCK_NAMESPACE_MAGIC;
	ns->ln_status = LS_INIT;
	ns->ln_time_latest_reset = ktime_get_real_seconds();
	down_write(&com->lc_sem);
	rc = lfsck_namespace_store(env, com);
	if (rc == 0)
		rc = lfsck_load_sub_trace_files(env, com,
			&dt_lfsck_namespace_features, LFSCK_NAMESPACE, true);
	up_write(&com->lc_sem);

	return rc;
}

/**
 * Update the namespace LFSCK trace file for the given @fid
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] fid	the fid which flags to be updated in the lfsck
 *			trace file
 * \param[in] add	true if add new flags, otherwise remove flags
 *
 * \retval		0 for success or nothing to be done
 * \retval		negative error number on failure
 */
int lfsck_namespace_trace_update(const struct lu_env *env,
				 struct lfsck_component *com,
				 const struct lu_fid *fid,
				 const __u8 flags, bool add)
{
	struct lfsck_instance	*lfsck  = com->lc_lfsck;
	struct dt_object	*obj;
	struct lu_fid		*key    = &lfsck_env_info(env)->lti_fid3;
	struct dt_device	*dev;
	struct thandle		*th	= NULL;
	int			 idx;
	int			 rc	= 0;
	__u8			 old	= 0;
	__u8			 new	= 0;
	ENTRY;

	LASSERT(flags != 0);

	if (unlikely(!fid_is_sane(fid)))
		RETURN(0);

	idx = lfsck_sub_trace_file_fid2idx(fid);
	mutex_lock(&com->lc_sub_trace_objs[idx].lsto_mutex);
	obj = com->lc_sub_trace_objs[idx].lsto_obj;
	if (unlikely(obj == NULL)) {
		mutex_unlock(&com->lc_sub_trace_objs[idx].lsto_mutex);
		RETURN(0);
	}

	lfsck_object_get(obj);
	dev = lfsck_obj2dev(obj);
	fid_cpu_to_be(key, fid);
	rc = dt_lookup(env, obj, (struct dt_rec *)&old,
		       (const struct dt_key *)key);
	if (rc == -ENOENT) {
		if (!add)
			GOTO(unlock, rc = 0);

		old = 0;
		new = flags;
	} else if (rc == 0) {
		if (add) {
			if ((old & flags) == flags)
				GOTO(unlock, rc = 0);

			new = old | flags;
		} else {
			if ((old & flags) == 0)
				GOTO(unlock, rc = 0);

			new = old & ~flags;
		}
	} else {
		GOTO(log, rc);
	}

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	if (old != 0) {
		rc = dt_declare_delete(env, obj,
				       (const struct dt_key *)key, th);
		if (rc != 0)
			GOTO(log, rc);
	}

	if (new != 0) {
		rc = dt_declare_insert(env, obj,
				       (const struct dt_rec *)&new,
				       (const struct dt_key *)key, th);
		if (rc != 0)
			GOTO(log, rc);
	}

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(log, rc);

	if (old != 0) {
		rc = dt_delete(env, obj, (const struct dt_key *)key, th);
		if (rc != 0)
			GOTO(log, rc);
	}

	if (new != 0) {
		rc = dt_insert(env, obj, (const struct dt_rec *)&new,
			       (const struct dt_key *)key, th);
		if (rc != 0)
			GOTO(log, rc);
	}

	GOTO(log, rc);

log:
	if (th != NULL && !IS_ERR(th))
		dt_trans_stop(env, dev, th);

	CDEBUG(D_LFSCK, "%s: namespace LFSCK %s flags for "DFID" in the "
	       "trace file, flags %x, old %x, new %x: rc = %d\n",
	       lfsck_lfsck2name(lfsck), add ? "add" : "del", PFID(fid),
	       (__u32)flags, (__u32)old, (__u32)new, rc);

unlock:
	mutex_unlock(&com->lc_sub_trace_objs[idx].lsto_mutex);
	lfsck_object_put(env, obj);

	return rc;
}

int lfsck_namespace_check_exist(const struct lu_env *env,
				struct dt_object *dir,
				struct dt_object *obj, const char *name)
{
	struct lu_fid	 *fid = &lfsck_env_info(env)->lti_fid;
	int		  rc;
	ENTRY;

	if (unlikely(lfsck_is_dead_obj(obj)))
		RETURN(LFSCK_NAMEENTRY_DEAD);

	rc = dt_lookup_dir(env, dir, name, fid);
	if (rc == -ENOENT)
		RETURN(LFSCK_NAMEENTRY_REMOVED);

	if (rc < 0)
		RETURN(rc);

	if (!lu_fid_eq(fid, lfsck_dto2fid(obj)))
		RETURN(LFSCK_NAMEENTRY_RECREATED);

	RETURN(0);
}

static int lfsck_declare_namespace_exec_dir(const struct lu_env *env,
					    struct dt_object *obj,
					    struct thandle *handle)
{
	int rc;

	/* For remote updating LINKEA, there may be further LFSCK action
	 * on remote MDT after the updating, so update the LINKEA ASAP. */
	if (dt_object_remote(obj))
		handle->th_sync = 1;

	/* For destroying all invalid linkEA entries. */
	rc = dt_declare_xattr_del(env, obj, XATTR_NAME_LINK, handle);
	if (rc == 0)
		/* For insert new linkEA entry. */
		rc = dt_declare_xattr_set(env, obj,
			lfsck_buf_get_const(env, NULL, MAX_LINKEA_SIZE),
			XATTR_NAME_LINK, 0, handle);
	return rc;
}

int __lfsck_links_read(const struct lu_env *env, struct dt_object *obj,
		       struct linkea_data *ldata, bool with_rec)
{
	int rc;

	if (ldata->ld_buf->lb_buf == NULL)
		return -ENOMEM;

	if (!dt_object_exists(obj))
		return -ENOENT;

	rc = dt_xattr_get(env, obj, ldata->ld_buf, XATTR_NAME_LINK);
	if (rc == -ERANGE) {
		/* Buf was too small, figure out what we need. */
		rc = dt_xattr_get(env, obj, &LU_BUF_NULL, XATTR_NAME_LINK);
		if (unlikely(rc == 0))
			return -ENODATA;

		if (rc < 0)
			return rc;

		lu_buf_realloc(ldata->ld_buf, rc);
		if (ldata->ld_buf->lb_buf == NULL)
			return -ENOMEM;

		rc = dt_xattr_get(env, obj, ldata->ld_buf, XATTR_NAME_LINK);
	}

	if (unlikely(rc == 0))
		return -ENODATA;

	if (rc > 0) {
		if (with_rec)
			rc = linkea_init_with_rec(ldata);
		else
			rc = linkea_init(ldata);
	}

	return rc;
}

/**
 * Remove linkEA for the given object.
 *
 * The caller should take the ldlm lock before the calling.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the dt_object to be handled
 *
 * \retval		0 for repaired cases
 * \retval		negative error number on failure
 */
static int lfsck_namespace_links_remove(const struct lu_env *env,
					struct lfsck_component *com,
					struct dt_object *obj)
{
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck_obj2dev(obj);
	struct thandle			*th	= NULL;
	int				 rc	= 0;
	ENTRY;

	LASSERT(dt_object_remote(obj) == 0);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	rc = dt_declare_xattr_del(env, obj, XATTR_NAME_LINK, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	if (unlikely(lfsck_is_dead_obj(obj)))
		GOTO(unlock, rc = -ENOENT);

	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(unlock, rc = 0);

	rc = dt_xattr_del(env, obj, XATTR_NAME_LINK, th);

	GOTO(unlock, rc);

unlock:
	dt_write_unlock(env, obj);

stop:
	dt_trans_stop(env, dev, th);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK remove invalid linkEA "
	       "for the object "DFID": rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(obj)), rc);

	if (rc == 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
	}

	return rc;
}

static int lfsck_links_write(const struct lu_env *env, struct dt_object *obj,
			     struct linkea_data *ldata, struct thandle *handle)
{
	struct lu_buf buf;
	int rc;

	lfsck_buf_init(&buf, ldata->ld_buf->lb_buf, ldata->ld_leh->leh_len);

again:
	rc = dt_xattr_set(env, obj, &buf, XATTR_NAME_LINK, 0, handle);
	if (unlikely(rc == -ENOSPC)) {
		rc = linkea_overflow_shrink(ldata);
		if (likely(rc > 0)) {
			buf.lb_len = rc;
			goto again;
		}
	}

	return rc;
}

static inline bool linkea_reclen_is_valid(const struct linkea_data *ldata)
{
	if (ldata->ld_reclen <= 0)
		return false;

	if ((char *)ldata->ld_lee + ldata->ld_reclen >
	    (char *)ldata->ld_leh + ldata->ld_leh->leh_len)
		return false;

	return true;
}

static inline bool linkea_entry_is_valid(const struct linkea_data *ldata,
					 const struct lu_name *cname,
					 const struct lu_fid *pfid)
{
	if (!linkea_reclen_is_valid(ldata))
		return false;

	if (cname->ln_namelen <= 0 || cname->ln_namelen > NAME_MAX)
		return false;

	if (!fid_is_sane(pfid))
		return false;

	return true;
}

static int lfsck_namespace_unpack_linkea_entry(struct linkea_data *ldata,
					       struct lu_name *cname,
					       struct lu_fid *pfid,
					       char *buf, const int buflen)
{
	linkea_entry_unpack(ldata->ld_lee, &ldata->ld_reclen, cname, pfid);
	if (unlikely(!linkea_entry_is_valid(ldata, cname, pfid)))
		return -EINVAL;

	/* To guarantee the 'name' is terminated with '0'. */
	memcpy(buf, cname->ln_name, cname->ln_namelen);
	buf[cname->ln_namelen] = 0;
	cname->ln_name = buf;

	return 0;
}

static void lfsck_linkea_del_buf(struct linkea_data *ldata,
				 const struct lu_name *lname)
{
	LASSERT(ldata->ld_leh != NULL && ldata->ld_lee != NULL);

	/* If current record is corrupted, all the subsequent
	 * records will be dropped. */
	if (unlikely(!linkea_reclen_is_valid(ldata))) {
		void *ptr = ldata->ld_lee;

		ldata->ld_leh->leh_len = sizeof(struct link_ea_header);
		ldata->ld_leh->leh_reccount = 0;
		linkea_first_entry(ldata);
		while (ldata->ld_lee != NULL &&
		       (char *)ldata->ld_lee < (char *)ptr) {
			int reclen = (ldata->ld_lee->lee_reclen[0] << 8) |
				     ldata->ld_lee->lee_reclen[1];

			ldata->ld_leh->leh_len += reclen;
			ldata->ld_leh->leh_reccount++;
			ldata->ld_lee = (struct link_ea_entry *)
					((char *)ldata->ld_lee + reclen);
		}

		ldata->ld_lee = NULL;
	} else {
		linkea_del_buf(ldata, lname);
	}
}

static int lfsck_namespace_filter_linkea_entry(struct linkea_data *ldata,
					       struct lu_name *cname,
					       struct lu_fid *pfid,
					       bool remove)
{
	struct link_ea_entry	*oldlee;
	int			 oldlen;
	int			 repeated = 0;

	oldlee = ldata->ld_lee;
	oldlen = ldata->ld_reclen;
	linkea_next_entry(ldata);
	while (ldata->ld_lee != NULL) {
		ldata->ld_reclen = (ldata->ld_lee->lee_reclen[0] << 8) |
				   ldata->ld_lee->lee_reclen[1];
		if (unlikely(!linkea_reclen_is_valid(ldata))) {
			lfsck_linkea_del_buf(ldata, NULL);
			LASSERT(ldata->ld_lee == NULL);
		} else if (unlikely(ldata->ld_reclen == oldlen &&
			     memcmp(ldata->ld_lee, oldlee, oldlen) == 0)) {
			repeated++;
			if (!remove)
				break;

			lfsck_linkea_del_buf(ldata, cname);
		} else {
			linkea_next_entry(ldata);
		}
	}
	ldata->ld_lee = oldlee;
	ldata->ld_reclen = oldlen;

	return repeated;
}

/**
 * Insert orphan into .lustre/lost+found/MDTxxxx/ locally.
 *
 * Add the specified orphan MDT-object to the .lustre/lost+found/MDTxxxx/
 * with the given type to generate the name, the detailed rules for name
 * have been described as following.
 *
 * The function also generates the linkEA corresponding to the name entry
 * under the .lustre/lost+found/MDTxxxx/ for the orphan MDT-object.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] orphan	pointer to the orphan MDT-object
 * \param[in] infix	additional information for the orphan name, such as
 *			the FID for original
 * \param[in] type	the type for describing why the orphan MDT-object is
 *			created. The rules are as following:
 *
 *  type "D":		The MDT-object is a directory, it may knows its parent
 *			but because there is no valid linkEA, the LFSCK cannot
 *			know where to put it back to the namespace.
 *  type "O":		The MDT-object has no linkEA, and there is no name
 *			entry that references the MDT-object.
 *
 *  type "S":		The orphan MDT-object is a shard of a striped directory
 *
 * \see lfsck_layout_recreate_parent() for more types.
 *
 * The orphan name will be like:
 * ${FID}-${infix}-${type}-${conflict_version}
 *
 * \param[out] count	if some others inserted some linkEA entries by race,
 *			then return the linkEA entries count.
 *
 * \retval		positive number for repaired cases
 * \retval		0 if needs to repair nothing
 * \retval		negative error number on failure
 */
static int lfsck_namespace_insert_orphan(const struct lu_env *env,
					 struct lfsck_component *com,
					 struct dt_object *orphan,
					 const char *infix, const char *type,
					 int *count)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_name			*cname	= &info->lti_name;
	struct dt_insert_rec		*rec	= &info->lti_dt_rec;
	struct lu_attr			*la	= &info->lti_la2;
	const struct lu_fid		*cfid	= lfsck_dto2fid(orphan);
	const struct lu_fid		*pfid;
	struct lu_fid			 tfid;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck_obj2dev(orphan);
	struct dt_object		*parent;
	struct thandle			*th	= NULL;
	struct lfsck_lock_handle	*pllh	= &info->lti_llh;
	struct lustre_handle		 clh	= { 0 };
	struct linkea_data		 ldata2	= { NULL };
	struct lu_buf			 linkea_buf;
	int				 namelen;
	int				 idx	= 0;
	int				 rc	= 0;
	bool				 exist	= false;
	ENTRY;

	cname->ln_name = NULL;
	if (unlikely(lfsck->li_lpf_obj == NULL))
		GOTO(log, rc = -ENXIO);

	parent = lfsck->li_lpf_obj;
	pfid = lfsck_dto2fid(parent);

again:
	do {
		namelen = snprintf(info->lti_key, NAME_MAX, DFID"%s-%s-%d",
				   PFID(cfid), infix, type, idx++);
		rc = dt_lookup_dir(env, parent, info->lti_key, &tfid);
		if (rc != 0 && rc != -ENOENT)
			GOTO(log, rc);

		if (unlikely(rc == 0 && lu_fid_eq(cfid, &tfid)))
			exist = true;
	} while (rc == 0 && !exist);

	rc = lfsck_lock(env, lfsck, parent, info->lti_key, pllh,
			MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		GOTO(log, rc);

	/* Re-check whether the name conflict with othrs after taken
	 * the ldlm lock. */
	rc = dt_lookup_dir(env, parent, info->lti_key, &tfid);
	if (rc == 0) {
		if (!lu_fid_eq(cfid, &tfid)) {
			exist = false;
			lfsck_unlock(pllh);
			goto again;
		}

		exist = true;
	} else if (rc != -ENOENT) {
		GOTO(log, rc);
	} else {
		exist = false;
	}

	cname->ln_name = info->lti_key;
	cname->ln_namelen = namelen;
	rc = linkea_links_new(&ldata2, &info->lti_linkea_buf2,
			      cname, pfid);
	if (rc != 0)
		GOTO(log, rc);

	rc = lfsck_ibits_lock(env, lfsck, orphan, &clh,
			      MDS_INODELOCK_UPDATE | MDS_INODELOCK_LOOKUP |
			      MDS_INODELOCK_XATTR, LCK_EX);
	if (rc != 0)
		GOTO(log, rc);

	lfsck_buf_init(&linkea_buf, ldata2.ld_buf->lb_buf,
		       ldata2.ld_leh->leh_len);
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	if (S_ISDIR(lfsck_object_type(orphan))) {
		rc = dt_declare_delete(env, orphan,
				       (const struct dt_key *)dotdot, th);
		if (rc != 0)
			GOTO(stop, rc);

		rec->rec_type = S_IFDIR;
		rec->rec_fid = pfid;
		rc = dt_declare_insert(env, orphan, (const struct dt_rec *)rec,
				       (const struct dt_key *)dotdot, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	rc = dt_declare_xattr_set(env, orphan, &linkea_buf,
				  XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (!exist) {
		rec->rec_type = lfsck_object_type(orphan) & S_IFMT;
		rec->rec_fid = cfid;
		rc = dt_declare_insert(env, parent, (const struct dt_rec *)rec,
				       (const struct dt_key *)cname->ln_name,
				       th);
		if (rc != 0)
			GOTO(stop, rc);

		if (S_ISDIR(rec->rec_type)) {
			rc = dt_declare_ref_add(env, parent, th);
			if (rc != 0)
				GOTO(stop, rc);
		}
	}

	memset(la, 0, sizeof(*la));
	la->la_ctime = ktime_get_real_seconds();
	la->la_valid = LA_CTIME;
	rc = dt_declare_attr_set(env, orphan, la, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, orphan, 0);
	rc = lfsck_links_read2_with_rec(env, orphan, &ldata2);
	if (likely(rc == -ENODATA || rc == -EINVAL)) {
		if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
			GOTO(unlock, rc = 1);

		if (S_ISDIR(lfsck_object_type(orphan))) {
			rc = dt_delete(env, orphan,
				       (const struct dt_key *)dotdot, th);
			if (rc != 0)
				GOTO(unlock, rc);

			rec->rec_type = S_IFDIR;
			rec->rec_fid = pfid;
			rc = dt_insert(env, orphan, (const struct dt_rec *)rec,
				       (const struct dt_key *)dotdot, th);
			if (rc != 0)
				GOTO(unlock, rc);
		}

		rc = dt_xattr_set(env, orphan, &linkea_buf, XATTR_NAME_LINK, 0,
				  th);
	} else {
		if (rc == 0 && count != NULL)
			*count = ldata2.ld_leh->leh_reccount;

		GOTO(unlock, rc);
	}
	dt_write_unlock(env, orphan);

	if (rc == 0 && !exist) {
		rec->rec_type = lfsck_object_type(orphan) & S_IFMT;
		rec->rec_fid = cfid;
		rc = dt_insert(env, parent, (const struct dt_rec *)rec,
			       (const struct dt_key *)cname->ln_name, th);
		if (rc == 0 && S_ISDIR(rec->rec_type)) {
			dt_write_lock(env, parent, 0);
			rc = dt_ref_add(env, parent, th);
			dt_write_unlock(env, parent);
		}
	}

	if (rc == 0)
		rc = dt_attr_set(env, orphan, la, th);

	GOTO(stop, rc = (rc == 0 ? 1 : rc));

unlock:
	dt_write_unlock(env, orphan);

stop:
	dt_trans_stop(env, dev, th);

log:
	lfsck_ibits_unlock(&clh, LCK_EX);
	lfsck_unlock(pllh);
	CDEBUG(D_LFSCK, "%s: namespace LFSCK insert orphan for the "
	       "object "DFID", name = %s: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(cfid),
	       cname->ln_name != NULL ? cname->ln_name : "<NULL>", rc);

	if (rc != 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
	}

	return rc;
}

static int lfsck_lmv_set(const struct lu_env *env,
			 struct lfsck_instance *lfsck,
			 struct dt_object *obj,
			 struct lmv_mds_md_v1 *lmv)
{
	struct dt_device *dev = lfsck->li_next;
	struct thandle *th = NULL;
	struct lu_buf buf = { lmv, sizeof(*lmv) };
	int rc;

	ENTRY;

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_xattr_set(env, obj, &buf, XATTR_NAME_LMV, 0, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_xattr_set(env, obj, &buf, XATTR_NAME_LMV, 0, th);
	if (rc)
		GOTO(stop, rc);

	EXIT;
stop:
	dt_trans_stop(env, dev, th);

	return rc;
}

static int lfsck_lmv_delete(const struct lu_env *env,
			    struct lfsck_instance *lfsck,
			    struct dt_object *obj)
{
	struct dt_device *dev = lfsck->li_next;
	struct thandle *th = NULL;
	int rc;

	ENTRY;

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_xattr_del(env, obj, XATTR_NAME_LMV, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_xattr_del(env, obj, XATTR_NAME_LMV, th);
	if (rc)
		GOTO(stop, rc);

	EXIT;
stop:
	dt_trans_stop(env, dev, th);

	return rc;
}

static inline int lfsck_object_is_shard(const struct lu_env *env,
					struct lfsck_instance *lfsck,
					struct dt_object *obj,
					const struct lu_name *lname)
{
	struct lfsck_thread_info *info = lfsck_env_info(env);
	struct lmv_mds_md_v1 *lmv = &info->lti_lmv;
	int rc;

	rc = lfsck_shard_name_to_index(env, lname->ln_name, lname->ln_namelen,
				       lfsck_object_type(obj),
				       lfsck_dto2fid(obj));
	if (rc < 0)
		return 0;

	rc = lfsck_read_stripe_lmv(env, lfsck, obj, lmv);
	if (rc == -ENODATA)
		return 0;

	if (!rc && lmv->lmv_magic == LMV_MAGIC_STRIPE)
		return 1;

	return rc;
}

/**
 * Add the specified name entry back to namespace.
 *
 * If there is a linkEA entry that back references a name entry under
 * some parent directory, but such parent directory does not have the
 * claimed name entry. On the other hand, the linkEA entries count is
 * not larger than the MDT-object's hard link count. Under such case,
 * it is quite possible that the name entry is lost. Then the LFSCK
 * should add the name entry back to the namespace.
 *
 * If \a child is shard, which means \a parent is a striped directory,
 * if \a parent has LMV, we need to delete it before insertion because
 * now parent's striping is broken and can't be parsed correctly.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] parent	pointer to the directory under which the name entry
 *			will be inserted into
 * \param[in] child	pointer to the object referenced by the name entry
 *			that to be inserted into the parent
 * \param[in] lname	the name for the child in the parent directory
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_insert_normal(const struct lu_env *env,
					 struct lfsck_component *com,
					 struct dt_object *parent,
					 struct dt_object *child,
					 const struct lu_name *lname)
{
	struct lfsck_thread_info *info = lfsck_env_info(env);
	struct lu_attr *la = &info->lti_la;
	struct dt_insert_rec *rec = &info->lti_dt_rec;
	struct lfsck_instance *lfsck = com->lc_lfsck;
	/* The child and its name may be on different MDTs. */
	const struct lu_fid *pfid = lfsck_dto2fid(parent);
	const struct lu_fid *cfid = lfsck_dto2fid(child);
	struct dt_device *dev = lfsck->li_next;
	struct thandle *th = NULL;
	struct lfsck_lock_handle *llh = &info->lti_llh;
	struct lmv_mds_md_v1 *lmv = &info->lti_lmv;
	struct lu_buf buf = { lmv, sizeof(*lmv) };
	/* whether parent's LMV is deleted before insertion */
	bool parent_lmv_deleted = false;
	/* whether parent's LMV is missing */
	bool parent_lmv_lost = false;
	int rc = 0;

	ENTRY;

	/* @parent/@child may be based on lfsck->li_bottom,
	 * but here we need the object based on the lfsck->li_next. */

	parent = lfsck_object_locate(dev, parent);
	if (IS_ERR(parent))
		GOTO(log, rc = PTR_ERR(parent));

	child = lfsck_object_locate(dev, child);
	if (IS_ERR(child))
		GOTO(log, rc = PTR_ERR(child));

	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(log, rc = 1);

	rc = lfsck_lock(env, lfsck, parent, lname->ln_name, llh,
			MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE |
			MDS_INODELOCK_XATTR, LCK_EX);
	if (rc)
		GOTO(log, rc);

	rc = lfsck_object_is_shard(env, lfsck, child, lname);
	if (rc < 0)
		GOTO(unlock, rc);

	if (rc == 1) {
		rc = lfsck_read_stripe_lmv(env, lfsck, parent, lmv);
		if (!rc) {
			/*
			 * To add a shard, we need to convert parent to a
			 * plain directory by deleting its LMV, and after
			 * insertion set it back.
			 */
			rc = lfsck_lmv_delete(env, lfsck, parent);
			if (rc)
				GOTO(unlock, rc);
			parent_lmv_deleted = true;
			lmv->lmv_layout_version++;
			lfsck_lmv_header_cpu_to_le(lmv, lmv);
		} else if (rc == -ENODATA) {
			struct lu_seq_range *range = &info->lti_range;
			struct seq_server_site *ss = lfsck_dev_site(lfsck);

			rc = lfsck_read_stripe_lmv(env, lfsck, child, lmv);
			if (rc)
				GOTO(unlock, rc);

			fld_range_set_mdt(range);
			rc = fld_server_lookup(env, ss->ss_server_fld,
				       fid_seq(lfsck_dto2fid(parent)), range);
			if (rc)
				GOTO(unlock, rc);

			parent_lmv_lost = true;
			lmv->lmv_magic = LMV_MAGIC;
			lmv->lmv_master_mdt_index = range->lsr_index;
			lmv->lmv_layout_version++;
			lfsck_lmv_header_cpu_to_le(lmv, lmv);
		} else {
			GOTO(unlock, rc);
		}
	}

	if (unlikely(!dt_try_as_dir(env, parent)))
		GOTO(unlock, rc = -ENOTDIR);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rec->rec_type = lfsck_object_type(child) & S_IFMT;
	rec->rec_fid = cfid;
	rc = dt_declare_insert(env, parent, (const struct dt_rec *)rec,
			       (const struct dt_key *)lname->ln_name, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (S_ISDIR(rec->rec_type)) {
		rc = dt_declare_ref_add(env, parent, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	if (parent_lmv_lost) {
		rc = dt_declare_xattr_set(env, parent, &buf, XATTR_NAME_LMV,
					  0, th);
		if (rc)
			GOTO(stop, rc);
	}

	la->la_ctime = ktime_get_real_seconds();
	la->la_valid = LA_CTIME;
	rc = dt_declare_attr_set(env, parent, la, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_attr_set(env, child, la, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_insert(env, parent, (const struct dt_rec *)rec,
		       (const struct dt_key *)lname->ln_name, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (S_ISDIR(rec->rec_type)) {
		dt_write_lock(env, parent, 0);
		rc = dt_ref_add(env, parent, th);
		dt_write_unlock(env, parent);
		if (rc != 0)
			GOTO(stop, rc);
	}

	if (parent_lmv_lost) {
		rc = dt_xattr_set(env, parent, &buf, XATTR_NAME_LMV, 0, th);
		if (rc)
			GOTO(stop, rc);
	}

	rc = dt_attr_set(env, parent, la, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_attr_set(env, child, la, th);

	GOTO(stop, rc = (rc == 0 ? 1 : rc));

stop:
	dt_trans_stop(env, dev, th);

unlock:
	if (parent_lmv_deleted)
		lfsck_lmv_set(env, lfsck, parent, lmv);

	lfsck_unlock(llh);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK insert object "DFID" with "
	       "the name %s and type %o to the parent "DFID": rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(cfid), lname->ln_name,
	       lfsck_object_type(child) & S_IFMT, PFID(pfid), rc);

	if (rc != 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
		if (rc > 0)
			ns->ln_lost_dirent_repaired++;
	}

	return rc;
}

/**
 * Create the specified orphan directory.
 *
 * For the case that the parent MDT-object stored in some MDT-object's
 * linkEA entry is lost, the LFSCK will re-create the parent object as
 * an orphan and insert it into .lustre/lost+found/MDTxxxx/ directory
 * with the name ${FID}-P-${conflict_version}.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] orphan	pointer to the orphan MDT-object to be created
 * \param[in] lmv	pointer to master LMV EA that will be set to the orphan
 *
 * \retval		positive number for repaired cases
 * \retval		negative error number on failure
 */
static int lfsck_namespace_create_orphan_dir(const struct lu_env *env,
					     struct lfsck_component *com,
					     struct dt_object *orphan,
					     struct lmv_mds_md_v1 *lmv)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_attr			*la	= &info->lti_la;
	struct dt_allocation_hint	*hint	= &info->lti_hint;
	struct dt_object_format		*dof	= &info->lti_dof;
	struct lu_name			*cname	= &info->lti_name2;
	struct dt_insert_rec		*rec	= &info->lti_dt_rec;
	struct lmv_mds_md_v1		*lmv2	= &info->lti_lmv2;
	const struct lu_fid		*cfid	= lfsck_dto2fid(orphan);
	struct lu_fid			 tfid;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct dt_device		*dev	= lfsck_obj2dev(orphan);
	struct dt_object		*parent	= NULL;
	struct thandle			*th	= NULL;
	struct lfsck_lock_handle	*llh    = &info->lti_llh;
	struct linkea_data		 ldata	= { NULL };
	struct lu_buf			 linkea_buf;
	struct lu_buf			 lmv_buf;
	char				 name[32];
	int				 namelen;
	int				 idx	= 0;
	int				 rc	= 0;
	int				 rc1	= 0;
	ENTRY;

	LASSERT(!dt_object_exists(orphan));

	cname->ln_name = NULL;
	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(log, rc = 1);

	if (dt_object_remote(orphan)) {
		LASSERT(lfsck->li_lpf_root_obj != NULL);

		idx = lfsck_find_mdt_idx_by_fid(env, lfsck, cfid);
		if (idx < 0)
			GOTO(log, rc = idx);

		snprintf(name, 8, "MDT%04x", idx);
		rc = dt_lookup_dir(env, lfsck->li_lpf_root_obj, name, &tfid);
		if (rc != 0)
			GOTO(log, rc = (rc == -ENOENT ? -ENXIO : rc));

		parent = lfsck_object_find_bottom(env, lfsck, &tfid);
		if (IS_ERR(parent))
			GOTO(log, rc = PTR_ERR(parent));

		if (unlikely(!dt_try_as_dir(env, parent)))
			GOTO(log, rc = -ENOTDIR);
	} else {
		if (unlikely(lfsck->li_lpf_obj == NULL))
			GOTO(log, rc = -ENXIO);

		parent = lfsck->li_lpf_obj;
	}

	dev = lfsck_find_dev_by_fid(env, lfsck, cfid);
	if (IS_ERR(dev))
		GOTO(log, rc = PTR_ERR(dev));

	idx = 0;

again:
	do {
		namelen = snprintf(name, 31, DFID"-P-%d",
				   PFID(cfid), idx++);
		rc = dt_lookup_dir(env, parent, name, &tfid);
		if (rc != 0 && rc != -ENOENT)
			GOTO(log, rc);
	} while (rc == 0);

	rc = lfsck_lock(env, lfsck, parent, name, llh,
			MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		GOTO(log, rc);

	/* Re-check whether the name conflict with othrs after taken
	 * the ldlm lock. */
	rc = dt_lookup_dir(env, parent, name, &tfid);
	if (unlikely(rc == 0)) {
		lfsck_unlock(llh);
		goto again;
	}

	if (rc != -ENOENT)
		GOTO(unlock1, rc);

	cname->ln_name = name;
	cname->ln_namelen = namelen;

	memset(la, 0, sizeof(*la));
	la->la_mode = S_IFDIR | 0700;
	la->la_valid = LA_TYPE | LA_MODE | LA_UID | LA_GID |
		       LA_ATIME | LA_MTIME | LA_CTIME;

	orphan->do_ops->do_ah_init(env, hint, parent, orphan,
				   la->la_mode & S_IFMT);

	memset(dof, 0, sizeof(*dof));
	dof->dof_type = dt_mode_to_dft(S_IFDIR);

	rc = linkea_links_new(&ldata, &info->lti_linkea_buf2,
			      cname, lfsck_dto2fid(parent));
	if (rc != 0)
		GOTO(unlock1, rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock1, rc = PTR_ERR(th));

	/* Sync the remote transaction to guarantee that the subsequent
	 * lock against the @orphan can find the @orphan in time. */
	if (dt_object_remote(orphan))
		th->th_sync = 1;

	rc = dt_declare_create(env, orphan, la, hint, dof, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (unlikely(!dt_try_as_dir(env, orphan)))
		GOTO(stop, rc = -ENOTDIR);

	rc = dt_declare_ref_add(env, orphan, th);
	if (rc != 0)
		GOTO(stop, rc);

	rec->rec_type = S_IFDIR;
	rec->rec_fid = cfid;
	rc = dt_declare_insert(env, orphan, (const struct dt_rec *)rec,
			       (const struct dt_key *)dot, th);
	if (rc != 0)
		GOTO(stop, rc);

	rec->rec_fid = lfsck_dto2fid(parent);
	rc = dt_declare_insert(env, orphan, (const struct dt_rec *)rec,
			       (const struct dt_key *)dotdot, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (lmv != NULL) {
		lmv->lmv_magic = LMV_MAGIC;
		lmv->lmv_master_mdt_index = lfsck_dev_idx(lfsck);
		lfsck_lmv_header_cpu_to_le(lmv2, lmv);
		lfsck_buf_init(&lmv_buf, lmv2, sizeof(*lmv2));
		rc = dt_declare_xattr_set(env, orphan, &lmv_buf, XATTR_NAME_LMV,
					  0, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	lfsck_buf_init(&linkea_buf, ldata.ld_buf->lb_buf,
		       ldata.ld_leh->leh_len);
	rc = dt_declare_xattr_set(env, orphan, &linkea_buf,
				  XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	rec->rec_fid = cfid;
	rc = dt_declare_insert(env, parent, (const struct dt_rec *)rec,
			       (const struct dt_key *)name, th);
	if (rc == 0)
		rc = dt_declare_ref_add(env, parent, th);

	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, orphan, 0);
	rc = dt_create(env, orphan, la, hint, dof, th);
	if (rc != 0)
		GOTO(unlock2, rc);

	rc = dt_ref_add(env, orphan, th);
	if (rc != 0)
		GOTO(unlock2, rc);

	rec->rec_fid = cfid;
	rc = dt_insert(env, orphan, (const struct dt_rec *)rec,
		       (const struct dt_key *)dot, th);
	if (rc != 0)
		GOTO(unlock2, rc);

	rec->rec_fid = lfsck_dto2fid(parent);
	rc = dt_insert(env, orphan, (const struct dt_rec *)rec,
		       (const struct dt_key *)dotdot, th);
	if (rc != 0)
		GOTO(unlock2, rc);

	if (lmv != NULL) {
		rc = dt_xattr_set(env, orphan, &lmv_buf, XATTR_NAME_LMV, 0, th);
		if (rc != 0)
			GOTO(unlock2, rc);
	}

	rc = dt_xattr_set(env, orphan, &linkea_buf,
			  XATTR_NAME_LINK, 0, th);
	dt_write_unlock(env, orphan);
	if (rc != 0)
		GOTO(stop, rc);

	rec->rec_fid = cfid;
	rc = dt_insert(env, parent, (const struct dt_rec *)rec,
		       (const struct dt_key *)name, th);
	if (rc == 0) {
		dt_write_lock(env, parent, 0);
		rc = dt_ref_add(env, parent, th);
		dt_write_unlock(env, parent);
	}

	GOTO(stop, rc = (rc == 0 ? 1 : rc));

unlock2:
	dt_write_unlock(env, orphan);

stop:
	rc1 = dt_trans_stop(env, dev, th);
	if (rc1 != 0 && rc > 0)
		rc = rc1;

unlock1:
	lfsck_unlock(llh);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK create orphan dir for "
	       "the object "DFID", name = %s: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(cfid),
	       cname->ln_name != NULL ? cname->ln_name : "<NULL>", rc);

	if (parent != NULL && !IS_ERR(parent) && parent != lfsck->li_lpf_obj)
		lfsck_object_put(env, parent);

	if (rc != 0)
		ns->ln_flags |= LF_INCONSISTENT;

	return rc;
}

/**
 * Remove the specified entry from the linkEA.
 *
 * Locate the linkEA entry with the given @cname and @pfid, then
 * remove this entry or the other entries those are repeated with
 * this entry.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the dt_object to be handled
 * \param[in,out]ldata  pointer to the buffer that holds the linkEA
 * \param[in] cname	the name for the child in the parent directory
 * \param[in] pfid	the parent directory's FID for the linkEA
 * \param[in] next	if true, then remove the first found linkEA
 *			entry, and move the ldata->ld_lee to next entry
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_shrink_linkea(const struct lu_env *env,
					 struct lfsck_component *com,
					 struct dt_object *obj,
					 struct linkea_data *ldata,
					 struct lu_name *cname,
					 struct lu_fid *pfid,
					 bool next)
{
	struct lfsck_instance		*lfsck	   = com->lc_lfsck;
	struct dt_device		*dev	   = lfsck_obj2dev(obj);
	struct lfsck_bookmark		*bk	   = &lfsck->li_bookmark_ram;
	struct thandle			*th	   = NULL;
	struct lustre_handle		 lh	   = { 0 };
	struct linkea_data		 ldata_new = { NULL };
	struct lu_buf			 linkea_buf;
	int				 buflen    = 0;
	int				 rc	   = 0;
	ENTRY;

	rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
			      MDS_INODELOCK_UPDATE | MDS_INODELOCK_XATTR,
			      LCK_EX);
	if (rc != 0)
		GOTO(log, rc);

	if (next)
		lfsck_linkea_del_buf(ldata, cname);
	else
		lfsck_namespace_filter_linkea_entry(ldata, cname, pfid,
						    true);
	if (ldata->ld_leh->leh_reccount > 0 ||
	    unlikely(ldata->ld_leh->leh_overflow_time)) {
		lfsck_buf_init(&linkea_buf, ldata->ld_buf->lb_buf,
			       ldata->ld_leh->leh_len);
		buflen = linkea_buf.lb_len;
	}

again:
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock1, rc = PTR_ERR(th));

	if (buflen != 0)
		rc = dt_declare_xattr_set(env, obj, &linkea_buf,
					  XATTR_NAME_LINK, 0, th);
	else
		rc = dt_declare_xattr_del(env, obj, XATTR_NAME_LINK, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	if (unlikely(lfsck_is_dead_obj(obj)))
		GOTO(unlock2, rc = -ENOENT);

	rc = lfsck_links_read2_with_rec(env, obj, &ldata_new);
	if (rc)
		GOTO(unlock2, rc = (rc == -ENODATA ? 0 : rc));

	/* The specified linkEA entry has been removed by race. */
	rc = linkea_links_find(&ldata_new, cname, pfid);
	if (rc != 0)
		GOTO(unlock2, rc = 0);

	if (bk->lb_param & LPF_DRYRUN)
		GOTO(unlock2, rc = 1);

	if (next)
		lfsck_linkea_del_buf(&ldata_new, cname);
	else
		lfsck_namespace_filter_linkea_entry(&ldata_new, cname, pfid,
						    true);

	/*
	 * linkea may change because it doesn't take lock in the first read, if
	 * it becomes larger, restart from beginning.
	 */
	if ((ldata_new.ld_leh->leh_reccount > 0 ||
	     unlikely(ldata_new.ld_leh->leh_overflow_time)) &&
	    buflen < ldata_new.ld_leh->leh_len) {
		dt_write_unlock(env, obj);
		dt_trans_stop(env, dev, th);
		lfsck_buf_init(&linkea_buf, ldata_new.ld_buf->lb_buf,
			       ldata_new.ld_leh->leh_len);
		buflen = linkea_buf.lb_len;
		goto again;
	}

	if (buflen)
		rc = lfsck_links_write(env, obj, &ldata_new, th);
	else
		rc = dt_xattr_del(env, obj, XATTR_NAME_LINK, th);

	GOTO(unlock2, rc = (rc == 0 ? 1 : rc));

unlock2:
	dt_write_unlock(env, obj);

stop:
	dt_trans_stop(env, dev, th);

unlock1:
	lfsck_ibits_unlock(&lh, LCK_EX);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK remove %s linkEA entry "
	       "for the object: "DFID", parent "DFID", name %.*s\n",
	       lfsck_lfsck2name(lfsck), next ? "invalid" : "redundant",
	       PFID(lfsck_dto2fid(obj)), PFID(pfid), cname->ln_namelen,
	       cname->ln_name);

	if (rc != 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
	}

	return rc;
}

/**
 * Conditionally remove the specified entry from the linkEA.
 *
 * Take the parent lock firstly, then check whether the specified
 * name entry exists or not: if yes, do nothing; otherwise, call
 * lfsck_namespace_shrink_linkea() to remove the linkea entry.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] parent	pointer to the parent directory
 * \param[in] child	pointer to the child object that holds the linkEA
 * \param[in,out]ldata  pointer to the buffer that holds the linkEA
 * \param[in] cname	the name for the child in the parent directory
 * \param[in] pfid	the parent directory's FID for the linkEA
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_shrink_linkea_cond(const struct lu_env *env,
					      struct lfsck_component *com,
					      struct dt_object *parent,
					      struct dt_object *child,
					      struct linkea_data *ldata,
					      struct lu_name *cname,
					      struct lu_fid *pfid)
{
	struct lfsck_thread_info *info	= lfsck_env_info(env);
	struct lu_fid		 *cfid	= &info->lti_fid3;
	struct lfsck_lock_handle *llh	= &info->lti_llh;
	int			  rc;
	ENTRY;

	rc = lfsck_lock(env, com->lc_lfsck, parent, cname->ln_name, llh,
			MDS_INODELOCK_UPDATE, LCK_PR);
	if (rc != 0)
		RETURN(rc);

	dt_read_lock(env, parent, 0);
	if (unlikely(lfsck_is_dead_obj(parent))) {
		dt_read_unlock(env, parent);
		lfsck_unlock(llh);
		rc = lfsck_namespace_shrink_linkea(env, com, child, ldata,
						   cname, pfid, true);

		RETURN(rc);
	}

	rc = dt_lookup(env, parent, (struct dt_rec *)cfid,
		       (const struct dt_key *)cname->ln_name);
	dt_read_unlock(env, parent);

	/* It is safe to release the ldlm lock, because when the logic come
	 * here, we have got all the needed information above whether the
	 * linkEA entry is valid or not. It is not important that others
	 * may add new linkEA entry after the ldlm lock released. If other
	 * has removed the specified linkEA entry by race, then it is OK,
	 * because the subsequent lfsck_namespace_shrink_linkea() can handle
	 * such case. */
	lfsck_unlock(llh);
	if (rc == -ENOENT) {
		rc = lfsck_namespace_shrink_linkea(env, com, child, ldata,
						   cname, pfid, true);

		RETURN(rc);
	}

	if (rc != 0)
		RETURN(rc);

	/* The LFSCK just found some internal status of cross-MDTs
	 * create operation. That is normal. */
	if (lu_fid_eq(cfid, lfsck_dto2fid(child))) {
		linkea_next_entry(ldata);

		RETURN(0);
	}

	rc = lfsck_namespace_shrink_linkea(env, com, child, ldata, cname,
					   pfid, true);

	RETURN(rc);
}

/**
 * Conditionally replace name entry in the parent.
 *
 * As required, the LFSCK may re-create the lost MDT-object for dangling
 * name entry, but such repairing may be wrong because of bad FID in the
 * name entry. As the LFSCK processing, the real MDT-object may be found,
 * then the LFSCK should check whether the former re-created MDT-object
 * has been modified or not, if not, then destroy it and update the name
 * entry in the parent to reference the real MDT-object.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] parent	pointer to the parent directory
 * \param[in] child	pointer to the MDT-object that may be the real
 *			MDT-object corresponding to the name entry in parent
 * \param[in] cfid	the current FID in the name entry
 * \param[in] cname	contains the name of the child in the parent directory
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_replace_cond(const struct lu_env *env,
					struct lfsck_component *com,
					struct dt_object *parent,
					struct dt_object *child,
					const struct lu_fid *cfid,
					const struct lu_name *cname)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_attr			*la	= &info->lti_la;
	struct dt_insert_rec		*rec	= &info->lti_dt_rec;
	struct lu_fid			 tfid;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	/* The child and its name may be on different MDTs. */
	struct dt_device		*dev	= lfsck->li_next;
	const char			*name	= cname->ln_name;
	const struct lu_fid		*pfid	= lfsck_dto2fid(parent);
	struct dt_object		*cobj	= NULL;
	struct lfsck_lock_handle	*pllh	= &info->lti_llh;
	struct lustre_handle		 clh	= { 0 };
	struct linkea_data		 ldata	= { NULL };
	struct thandle			*th	= NULL;
	bool				 exist	= true;
	int				 rc	= 0;
	ENTRY;

	/* @parent/@child may be based on lfsck->li_bottom,
	 * but here we need the object based on the lfsck->li_next. */

	parent = lfsck_object_locate(dev, parent);
	if (IS_ERR(parent))
		GOTO(log, rc = PTR_ERR(parent));

	if (unlikely(!dt_try_as_dir(env, parent)))
		GOTO(log, rc = -ENOTDIR);

	rc = lfsck_lock(env, lfsck, parent, name, pllh,
			MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		GOTO(log, rc);

	if (!fid_is_sane(cfid)) {
		exist = false;
		goto replace;
	}

	cobj = lfsck_object_find_by_dev(env, dev, cfid);
	if (IS_ERR(cobj)) {
		rc = PTR_ERR(cobj);
		if (rc == -ENOENT) {
			exist = false;
			goto replace;
		}

		GOTO(log, rc);
	}

	if (!dt_object_exists(cobj)) {
		exist = false;
		goto replace;
	}

	rc = dt_lookup_dir(env, parent, name, &tfid);
	if (rc == -ENOENT) {
		exist = false;
		goto replace;
	}

	if (rc != 0)
		GOTO(log, rc);

	/* Someone changed the name entry, cannot replace it. */
	if (!lu_fid_eq(cfid, &tfid))
		GOTO(log, rc = 0);

	/* lock the object to be destroyed. */
	rc = lfsck_ibits_lock(env, lfsck, cobj, &clh,
			      MDS_INODELOCK_UPDATE |
			      MDS_INODELOCK_UPDATE | MDS_INODELOCK_XATTR,
			      LCK_EX);
	if (rc != 0)
		GOTO(log, rc);

	if (unlikely(lfsck_is_dead_obj(cobj))) {
		exist = false;
		goto replace;
	}

	rc = dt_attr_get(env, cobj, la);
	if (rc != 0)
		GOTO(log, rc);

	/* The object has been modified by other(s), or it is not created by
	 * LFSCK, the two cases are indistinguishable. So cannot replace it. */
	if (la->la_ctime != 0)
		GOTO(log, rc);

	if (S_ISREG(la->la_mode)) {
		rc = dt_xattr_get(env, cobj, &LU_BUF_NULL, XATTR_NAME_LOV);
		/* If someone has created related OST-object(s),
		 * then keep it. */
		if ((rc > 0) || (rc < 0 && rc != -ENODATA))
			GOTO(log, rc = (rc > 0 ? 0 : rc));
	}

replace:
	dt_read_lock(env, child, 0);
	rc = lfsck_links_read2_with_rec(env, child, &ldata);
	dt_read_unlock(env, child);

	/* Someone changed the child, no need to replace. */
	if (rc == -ENODATA)
		GOTO(log, rc = 0);

	if (rc != 0)
		GOTO(log, rc);

	rc = linkea_links_find(&ldata, cname, pfid);
	/* Someone moved the child, no need to replace. */
	if (rc != 0)
		GOTO(log, rc = 0);

	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(log, rc = 1);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	if (exist) {
		rc = dt_declare_destroy(env, cobj, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	rc = dt_declare_delete(env, parent, (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rec->rec_type = S_IFDIR;
	rec->rec_fid = lfsck_dto2fid(child);
	rc = dt_declare_insert(env, parent, (const struct dt_rec *)rec,
			       (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (exist) {
		rc = dt_destroy(env, cobj, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	/* The old name entry maybe not exist. */
	rc = dt_delete(env, parent, (const struct dt_key *)name, th);
	if (rc != 0 && rc != -ENOENT)
		GOTO(stop, rc);

	rc = dt_insert(env, parent, (const struct dt_rec *)rec,
		       (const struct dt_key *)name, th);

	GOTO(stop, rc = (rc == 0 ? 1 : rc));

stop:
	dt_trans_stop(env, dev, th);

log:
	lfsck_ibits_unlock(&clh, LCK_EX);
	lfsck_unlock(pllh);

	if (cobj != NULL && !IS_ERR(cobj))
		lfsck_object_put(env, cobj);

	CDEBUG(D_LFSCK, "%s: namespace LFSCK conditionally destroy the "
	       "object "DFID" because of conflict with the object "DFID
	       " under the parent "DFID" with name %s: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(cfid),
	       PFID(lfsck_dto2fid(child)), PFID(pfid), name, rc);

	return rc;
}

/**
 * Overwrite the linkEA for the object with the given ldata.
 *
 * The caller should take the ldlm lock before the calling.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the dt_object to be handled
 * \param[in] ldata	pointer to the new linkEA data
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
int lfsck_namespace_rebuild_linkea(const struct lu_env *env,
				   struct lfsck_component *com,
				   struct dt_object *obj,
				   struct linkea_data *ldata)
{
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck_obj2dev(obj);
	struct thandle			*th	= NULL;
	struct lu_buf			 linkea_buf;
	int				 rc	= 0;
	ENTRY;

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	lfsck_buf_init(&linkea_buf, ldata->ld_buf->lb_buf,
		       ldata->ld_leh->leh_len);
	rc = dt_declare_xattr_set(env, obj, &linkea_buf,
				  XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	if (unlikely(lfsck_is_dead_obj(obj)))
		GOTO(unlock, rc = 0);

	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(unlock, rc = 1);

	rc = dt_xattr_set(env, obj, &linkea_buf,
			  XATTR_NAME_LINK, 0, th);

	GOTO(unlock, rc = (rc == 0 ? 1 : rc));

unlock:
	dt_write_unlock(env, obj);

stop:
	dt_trans_stop(env, dev, th);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK rebuild linkEA for the "
	       "object "DFID": rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(obj)), rc);

	if (rc != 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
	}

	return rc;
}

/**
 * Repair invalid name entry.
 *
 * If the name entry contains invalid information, such as bad file type
 * or (and) corrupted object FID, then either remove the name entry or
 * udpate the name entry with the given (right) information.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] parent	pointer to the parent directory
 * \param[in] child	pointer to the object referenced by the name entry
 * \param[in] name	the old name of the child under the parent directory
 * \param[in] name2	the new name of the child under the parent directory
 * \param[in] type	the type claimed by the name entry
 * \param[in] update	update the name entry if true; otherwise, remove it
 * \param[in] dec	decrease the parent nlink count if true
 *
 * \retval		positive number for repaired successfully
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
int lfsck_namespace_repair_dirent(const struct lu_env *env,
				  struct lfsck_component *com,
				  struct dt_object *parent,
				  struct dt_object *child,
				  const char *name, const char *name2,
				  __u16 type, bool update, bool dec)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct dt_insert_rec		*rec	= &info->lti_dt_rec;
	const struct lu_fid		*pfid	= lfsck_dto2fid(parent);
	struct lu_fid			cfid	= {0};
	struct lu_fid			 tfid;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck->li_next;
	struct thandle			*th	= NULL;
	struct lfsck_lock_handle        *llh    = &info->lti_llh;
	struct lustre_handle		 lh	= { 0 };
	int				 rc	= 0;
	ENTRY;

	if (child)
		cfid = *lfsck_dto2fid(child);
	parent = lfsck_object_locate(dev, parent);
	if (IS_ERR(parent))
		GOTO(log, rc = PTR_ERR(parent));

	if (unlikely(!dt_try_as_dir(env, parent)))
		GOTO(log, rc = -ENOTDIR);

	if (!update || strcmp(name, name2) == 0)
		rc = lfsck_lock(env, lfsck, parent, name, llh,
				MDS_INODELOCK_UPDATE, LCK_PW);
	else
		rc = lfsck_ibits_lock(env, lfsck, parent, &lh,
				      MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		GOTO(log, rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock1, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, parent, (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (update) {
		rec->rec_type = lfsck_object_type(child) & S_IFMT;
		LASSERT(!fid_is_zero(&cfid));
		rec->rec_fid = &cfid;
		rc = dt_declare_insert(env, parent,
				       (const struct dt_rec *)rec,
				       (const struct dt_key *)name2, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	if (dec && S_ISDIR(type)) {
		rc = dt_declare_ref_del(env, parent, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);


	dt_write_lock(env, parent, 0);
	rc = dt_lookup_dir(env, dt_object_child(parent), name, &tfid);
	/* Someone has removed the bad name entry by race. */
	if (rc == -ENOENT)
		GOTO(unlock2, rc = 0);

	if (rc != 0)
		GOTO(unlock2, rc);

	/* Someone has removed the bad name entry and reused it for other
	 * object by race. */
	if (!lu_fid_eq(&tfid, &cfid))
		GOTO(unlock2, rc = 0);

	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(unlock2, rc = 1);

	rc = dt_delete(env, parent, (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(unlock2, rc);

	if (update) {
		rc = dt_insert(env, parent,
			       (const struct dt_rec *)rec,
			       (const struct dt_key *)name2, th);
		if (rc != 0)
			GOTO(unlock2, rc);
	}

	if (dec && S_ISDIR(type)) {
		rc = dt_ref_del(env, parent, th);
		if (rc != 0)
			GOTO(unlock2, rc);
	}

	GOTO(unlock2, rc = (rc == 0 ? 1 : rc));

unlock2:
	dt_write_unlock(env, parent);

stop:
	dt_trans_stop(env, dev, th);

	/* We are not sure whether the child will become orphan or not.
	 * Record it in the LFSCK trace file for further checking in
	 * the second-stage scanning. */
	if (!update && !dec && child && rc == 0)
		lfsck_namespace_trace_update(env, com, &cfid,
					     LNTF_CHECK_LINKEA, true);

unlock1:
	/* It is harmless even if unlock the unused lock_handle */
	lfsck_ibits_unlock(&lh, LCK_PW);
	lfsck_unlock(llh);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant found bad name "
	       "entry for: parent "DFID", child "DFID", name %s, type "
	       "in name entry %o, type claimed by child %o. repair it "
	       "by %s with new name2 %s: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(pfid), PFID(&cfid),
	       name, type, update ? lfsck_object_type(child) : 0,
	       update ? "updating" : "removing", name2, rc);

	if (rc != 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
	}

	return rc;
}

/**
 * Update the ".." name entry for the given object.
 *
 * The object's ".." is corrupted, this function will update the ".." name
 * entry with the given pfid, and the linkEA with the given ldata.
 *
 * The caller should take the ldlm lock before the calling.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the dt_object to be handled
 * \param[in] pfid	the new fid for the object's ".." name entry
 * \param[in] cname	the name for the @obj in the parent directory
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_repair_unmatched_pairs(const struct lu_env *env,
						  struct lfsck_component *com,
						  struct dt_object *obj,
						  const struct lu_fid *pfid,
						  struct lu_name *cname)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct dt_insert_rec		*rec	= &info->lti_dt_rec;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck_obj2dev(obj);
	struct thandle			*th	= NULL;
	struct linkea_data		 ldata	= { NULL };
	struct lu_buf			 linkea_buf;
	int				 rc	= 0;
	ENTRY;

	LASSERT(!dt_object_remote(obj));
	LASSERT(S_ISDIR(lfsck_object_type(obj)));

	rc = linkea_links_new(&ldata, &info->lti_big_buf, cname, pfid);
	if (rc != 0)
		GOTO(log, rc);

	lfsck_buf_init(&linkea_buf, ldata.ld_buf->lb_buf,
		       ldata.ld_leh->leh_len);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, obj, (const struct dt_key *)dotdot, th);
	if (rc != 0)
		GOTO(stop, rc);

	rec->rec_type = S_IFDIR;
	rec->rec_fid = pfid;
	rc = dt_declare_insert(env, obj, (const struct dt_rec *)rec,
			       (const struct dt_key *)dotdot, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_xattr_set(env, obj, &linkea_buf,
				  XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	if (unlikely(lfsck_is_dead_obj(obj)))
		GOTO(unlock, rc = 0);

	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(unlock, rc = 1);

	/* The old ".." name entry maybe not exist. */
	dt_delete(env, obj, (const struct dt_key *)dotdot, th);

	rc = dt_insert(env, obj, (const struct dt_rec *)rec,
		       (const struct dt_key *)dotdot, th);
	if (rc != 0)
		GOTO(unlock, rc);

	rc = lfsck_links_write(env, obj, &ldata, th);

	GOTO(unlock, rc = (rc == 0 ? 1 : rc));

unlock:
	dt_write_unlock(env, obj);

stop:
	dt_trans_stop(env, dev, th);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK rebuild dotdot name entry for "
	       "the object "DFID", new parent "DFID": rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(obj)),
	       PFID(pfid), rc);

	if (rc != 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
	}

	return rc;
}

/**
 * Handle orphan @obj during Double Scan Directory.
 *
 * Remove the @obj's current (invalid) linkEA entries, and insert
 * it in the directory .lustre/lost+found/MDTxxxx/ with the name:
 * ${FID}-${PFID}-D-${conflict_version}
 *
 * The caller should take the ldlm lock before the calling.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the orphan object to be handled
 * \param[in] pfid	the new fid for the object's ".." name entry
 * \param[in,out] lh	ldlm lock handler for the given @obj
 * \param[out] type	to tell the caller what the inconsistency is
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int
lfsck_namespace_dsd_orphan(const struct lu_env *env,
			   struct lfsck_component *com,
			   struct dt_object *obj,
			   const struct lu_fid *pfid,
			   struct lustre_handle *lh,
			   enum lfsck_namespace_inconsistency_type *type)
{
	struct lfsck_thread_info *info = lfsck_env_info(env);
	struct lfsck_namespace	 *ns   = com->lc_file_ram;
	int			  rc;
	ENTRY;

	/* Remove the unrecognized linkEA. */
	rc = lfsck_namespace_links_remove(env, com, obj);
	lfsck_ibits_unlock(lh, LCK_EX);
	if (rc < 0 && rc != -ENODATA)
		RETURN(rc);

	*type = LNIT_MUL_REF;

	/* If the LFSCK is marked as LF_INCOMPLETE, then means some MDT has
	 * ever tried to verify some remote MDT-object that resides on this
	 * MDT, but this MDT failed to respond such request. So means there
	 * may be some remote name entry on other MDT that references this
	 * object with another name, so we cannot know whether this linkEA
	 * is valid or not. So keep it there and maybe resolved when next
	 * LFSCK run. */
	if (ns->ln_flags & LF_INCOMPLETE)
		RETURN(0);

	/* The unique linkEA is invalid, even if the ".." name entry may be
	 * valid, we still cannot know via which name entry this directory
	 * will be referenced. Then handle it as pure orphan. */
	snprintf(info->lti_tmpbuf, sizeof(info->lti_tmpbuf),
		 "-"DFID, PFID(pfid));
	rc = lfsck_namespace_insert_orphan(env, com, obj,
					   info->lti_tmpbuf, "D", NULL);

	RETURN(rc);
}

/**
 * Double Scan Directory object for single linkEA entry case.
 *
 * The given @child has unique linkEA entry. If the linkEA entry is valid,
 * then check whether the name is in the namespace or not, if not, add the
 * missing name entry back to namespace. If the linkEA entry is invalid,
 * then remove it and insert the @child in the .lustre/lost+found/MDTxxxx/
 * as an orphan.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] child	pointer to the directory to be double scanned
 * \param[in] pfid	the FID corresponding to the ".." entry
 * \param[in] ldata	pointer to the linkEA data for the given @child
 * \param[in,out] lh	ldlm lock handler for the given @child
 * \param[out] type	to tell the caller what the inconsistency is
 * \param[in] retry	if found inconsistency, but the caller does not hold
 *			ldlm lock on the @child, then set @retry as true
 * \param[in] unknown	set if does not know how to repair the inconsistency
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int
lfsck_namespace_dsd_single(const struct lu_env *env,
			   struct lfsck_component *com,
			   struct dt_object *child,
			   const struct lu_fid *pfid,
			   struct linkea_data *ldata,
			   struct lustre_handle *lh,
			   enum lfsck_namespace_inconsistency_type *type,
			   bool *retry, bool *unknown)
{
	struct lfsck_thread_info *info		= lfsck_env_info(env);
	struct lu_name		 *cname		= &info->lti_name;
	const struct lu_fid	 *cfid		= lfsck_dto2fid(child);
	struct lu_fid		  tfid;
	struct lfsck_namespace	 *ns		= com->lc_file_ram;
	struct lfsck_instance	 *lfsck		= com->lc_lfsck;
	struct dt_object	 *parent	= NULL;
	struct lmv_mds_md_v1	 *lmv;
	int			  rc		= 0;
	ENTRY;

	rc = lfsck_namespace_unpack_linkea_entry(ldata, cname, &tfid,
						 info->lti_key,
						 sizeof(info->lti_key));
	/* The unique linkEA entry with bad parent will be handled as orphan. */
	if (rc != 0) {
		if (!lustre_handle_is_used(lh) && retry != NULL)
			*retry = true;
		else
			rc = lfsck_namespace_dsd_orphan(env, com, child,
							pfid, lh, type);

		GOTO(out, rc);
	}

	parent = lfsck_object_find_bottom(env, lfsck, &tfid);
	if (IS_ERR(parent))
		GOTO(out, rc = PTR_ERR(parent));

	/* We trust the unique linkEA entry in spite of whether it matches the
	 * ".." name entry or not. Because even if the linkEA entry is wrong
	 * and the ".." name entry is right, we still cannot know via which
	 * name entry the child will be referenced, since all known entries
	 * have been verified during the first-stage scanning. */
	if (!dt_object_exists(parent)) {
		/* If the LFSCK is marked as LF_INCOMPLETE, then means some MDT
		 * has ever tried to verify some remote MDT-object that resides
		 * on this MDT, but this MDT failed to respond such request. So
		 * means there may be some remote name entry on other MDT that
		 * references this object with another name, so we cannot know
		 * whether this linkEA is valid or not. So keep it there and
		 * maybe resolved when next LFSCK run. */
		if (ns->ln_flags & LF_INCOMPLETE)
			GOTO(out, rc = 0);

		if (!lustre_handle_is_used(lh) && retry != NULL) {
			*retry = true;

			GOTO(out, rc = 0);
		}

		lfsck_ibits_unlock(lh, LCK_EX);

lost_parent:
		lmv = &info->lti_lmv;
		rc = lfsck_read_stripe_lmv(env, lfsck, child, lmv);
		if (rc != 0 && rc != -ENODATA)
			GOTO(out, rc);

		if (rc == -ENODATA || lmv->lmv_magic != LMV_MAGIC_STRIPE) {
			lmv = NULL;
		} else if (lfsck_shard_name_to_index(env,
					cname->ln_name, cname->ln_namelen,
					S_IFDIR, cfid) < 0) {
			/* It is an invalid name entry, we
			 * cannot trust the parent also. */
			rc = lfsck_namespace_shrink_linkea(env, com, child,
						ldata, cname, &tfid, true);
			if (rc < 0)
				GOTO(out, rc);

			snprintf(info->lti_tmpbuf, sizeof(info->lti_tmpbuf),
				 "-"DFID, PFID(pfid));
			rc = lfsck_namespace_insert_orphan(env, com, child,
						info->lti_tmpbuf, "S", NULL);

			GOTO(out, rc);
		}

		/* Create the lost parent as an orphan. */
		rc = lfsck_namespace_create_orphan_dir(env, com, parent, lmv);
		if (rc >= 0) {
			/* Add the missing name entry to the parent. */
			rc = lfsck_namespace_insert_normal(env, com, parent,
							   child, cname);
			if (unlikely(rc == -EEXIST)) {
				/* Unfortunately, someone reused the name
				 * under the parent by race. So we have
				 * to remove the linkEA entry from
				 * current child object. It means that the
				 * LFSCK cannot recover the system
				 * totally back to its original status,
				 * but it is necessary to make the
				 * current system to be consistent. */
				rc = lfsck_namespace_shrink_linkea(env,
						com, child, ldata,
						cname, &tfid, true);
				if (rc >= 0) {
					snprintf(info->lti_tmpbuf,
						 sizeof(info->lti_tmpbuf),
						 "-"DFID, PFID(pfid));
					rc = lfsck_namespace_insert_orphan(env,
						com, child, info->lti_tmpbuf,
						"D", NULL);
				}
			}
		}

		GOTO(out, rc);
	} /* !dt_object_exists(parent) */

	/* The unique linkEA entry with bad parent will be handled as orphan. */
	if (unlikely(!dt_try_as_dir(env, parent))) {
		if (!lustre_handle_is_used(lh) && retry != NULL)
			*retry = true;
		else
			rc = lfsck_namespace_dsd_orphan(env, com, child,
							pfid, lh, type);

		GOTO(out, rc);
	}

	rc = dt_lookup_dir(env, parent, cname->ln_name, &tfid);
	if (rc == -ENOENT) {
		/* If the LFSCK is marked as LF_INCOMPLETE, then means some MDT
		 * has ever tried to verify some remote MDT-object that resides
		 * on this MDT, but this MDT failed to respond such request. So
		 * means there may be some remote name entry on other MDT that
		 * references this object with another name, so we cannot know
		 * whether this linkEA is valid or not. So keep it there and
		 * maybe resolved when next LFSCK run. */
		if (ns->ln_flags & LF_INCOMPLETE)
			GOTO(out, rc = 0);

		if (!lustre_handle_is_used(lh) && retry != NULL) {
			*retry = true;

			GOTO(out, rc = 0);
		}

		lfsck_ibits_unlock(lh, LCK_EX);
		rc = lfsck_namespace_check_name(env, lfsck, parent, child,
						cname);
		if (rc == -ENOENT)
			goto lost_parent;

		if (rc < 0)
			GOTO(out, rc);

		/* It is an invalid name entry, drop it. */
		if (unlikely(rc > 0)) {
			rc = lfsck_namespace_shrink_linkea(env, com, child,
						ldata, cname, &tfid, true);
			if (rc >= 0) {
				snprintf(info->lti_tmpbuf,
					 sizeof(info->lti_tmpbuf),
					 "-"DFID, PFID(pfid));
				rc = lfsck_namespace_insert_orphan(env, com,
					child, info->lti_tmpbuf, "D", NULL);
			}

			GOTO(out, rc);
		}

		/* Add the missing name entry back to the namespace. */
		rc = lfsck_namespace_insert_normal(env, com, parent, child,
						   cname);
		if (unlikely(rc == -ESTALE))
			/* It may happen when the remote object has been
			 * removed, but the local MDT is not aware of that. */
			goto lost_parent;

		if (unlikely(rc == -EEXIST)) {
			/* Unfortunately, someone reused the name under the
			 * parent by race. So we have to remove the linkEA
			 * entry from current child object. It means that the
			 * LFSCK cannot recover the system totally back to
			 * its original status, but it is necessary to make
			 * the current system to be consistent.
			 *
			 * It also may be because of the LFSCK found some
			 * internal status of create operation. Under such
			 * case, nothing to be done. */
			rc = lfsck_namespace_shrink_linkea_cond(env, com,
					parent, child, ldata, cname, &tfid);
			if (rc >= 0) {
				snprintf(info->lti_tmpbuf,
					 sizeof(info->lti_tmpbuf),
					 "-"DFID, PFID(pfid));
				rc = lfsck_namespace_insert_orphan(env, com,
					child, info->lti_tmpbuf, "D", NULL);
			}
		}

		GOTO(out, rc);
	} /* rc == -ENOENT */

	if (rc != 0)
		GOTO(out, rc);

	if (!lu_fid_eq(&tfid, cfid)) {
		if (!lustre_handle_is_used(lh) && retry != NULL) {
			*retry = true;

			GOTO(out, rc = 0);
		}

		lfsck_ibits_unlock(lh, LCK_EX);
		/* The name entry references another MDT-object that
		 * may be created by the LFSCK for repairing dangling
		 * name entry. Try to replace it. */
		rc = lfsck_namespace_replace_cond(env, com, parent, child,
						  &tfid, cname);
		if (rc == 0)
			rc = lfsck_namespace_dsd_orphan(env, com, child,
							pfid, lh, type);

		GOTO(out, rc);
	}

	/* Zero FID may because the remote directroy object has invalid linkEA,
	 * or lost linkEA. Under such case, the LFSCK on this MDT does not know
	 * how to repair the inconsistency, but the namespace LFSCK on the MDT
	 * where its name entry resides may has more information (name, FID) to
	 * repair such inconsistency. So here, keep the inconsistency to avoid
	 * some imporper repairing. */
	if (fid_is_zero(pfid)) {
		if (unknown)
			*unknown = true;

		GOTO(out, rc = 0);
	}

	/* The ".." name entry is wrong, update it. */
	if (!lu_fid_eq(pfid, lfsck_dto2fid(parent))) {
		if (!lustre_handle_is_used(lh) && retry != NULL) {
			*retry = true;

			GOTO(out, rc = 0);
		}

		*type = LNIT_UNMATCHED_PAIRS;
		rc = lfsck_namespace_repair_unmatched_pairs(env, com, child,
						lfsck_dto2fid(parent), cname);
	}

	GOTO(out, rc);

out:
	if (parent != NULL && !IS_ERR(parent))
		lfsck_object_put(env, parent);

	return rc;
}

/**
 * Double Scan Directory object for multiple linkEA entries case.
 *
 * The given @child has multiple linkEA entries. There is at most one linkEA
 * entry will be valid, all the others will be removed. Firstly, the function
 * will try to find out the linkEA entry for which the name entry exists under
 * the given parent (@pfid). If there is no linkEA entry that matches the given
 * ".." name entry, then tries to find out the first linkEA entry that both the
 * parent and the name entry exist to rebuild a new ".." name entry.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] child	pointer to the directory to be double scanned
 * \param[in] pfid	the FID corresponding to the ".." entry
 * \param[in] ldata	pointer to the linkEA data for the given @child
 * \param[in,out] lh	ldlm lock handler for the given @child
 * \param[out] type	to tell the caller what the inconsistency is
 * \param[in] lpf	true if the ".." entry is under lost+found/MDTxxxx/
 * \param[in] unknown	set if does not know how to repair the inconsistency
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int
lfsck_namespace_dsd_multiple(const struct lu_env *env,
			     struct lfsck_component *com,
			     struct dt_object *child,
			     const struct lu_fid *pfid,
			     struct linkea_data *ldata,
			     struct lustre_handle *lh,
			     enum lfsck_namespace_inconsistency_type *type,
			     bool lpf, bool *unknown)
{
	struct lfsck_thread_info *info		= lfsck_env_info(env);
	struct lu_name		 *cname		= &info->lti_name;
	const struct lu_fid	 *cfid		= lfsck_dto2fid(child);
	struct lu_fid		 *pfid2		= &info->lti_fid3;
	struct lu_fid		  tfid;
	struct lfsck_namespace	 *ns		= com->lc_file_ram;
	struct lfsck_instance	 *lfsck		= com->lc_lfsck;
	struct lfsck_bookmark	 *bk		= &lfsck->li_bookmark_ram;
	struct dt_object	 *parent	= NULL;
	struct linkea_data	  ldata_new	= { NULL };
	int			  dirent_count	= 0;
	int			  rc		= 0;
	bool			  once		= true;
	ENTRY;

again:
	while (ldata->ld_lee != NULL) {
		rc = lfsck_namespace_unpack_linkea_entry(ldata, cname, &tfid,
							 info->lti_key,
							 sizeof(info->lti_key));
		/* Drop invalid linkEA entry. */
		if (rc != 0) {
			lfsck_linkea_del_buf(ldata, cname);
			continue;
		}

		/* Drop repeated linkEA entries. */
		lfsck_namespace_filter_linkea_entry(ldata, cname, &tfid, true);

		/* If current dotdot is the .lustre/lost+found/MDTxxxx/,
		 * then it is possible that: the directry object has ever
		 * been lost, but its name entry was there. In the former
		 * LFSCK run, during the first-stage scanning, the LFSCK
		 * found the dangling name entry, but it did not recreate
		 * the lost object, and when moved to the second-stage
		 * scanning, some children objects of the lost directory
		 * object were found, then the LFSCK recreated such lost
		 * directory object as an orphan.
		 *
		 * When the LFSCK runs again, if the dangling name is still
		 * there, the LFSCK should move the orphan directory object
		 * back to the normal namespace. */
		if (!lpf && !fid_is_zero(pfid) &&
		    !lu_fid_eq(pfid, &tfid) && once) {
			linkea_next_entry(ldata);
			continue;
		}

		parent = lfsck_object_find_bottom(env, lfsck, &tfid);
		if (IS_ERR(parent)) {
			rc = PTR_ERR(parent);
			/* if @pfid doesn't have a valid OI mapping, it will
			 * trigger OI scrub, and -ENONET is is returned if it's
			 * remote, -EINPROGRESS if local.
			 */
			if ((rc == -ENOENT || rc == -EINPROGRESS) &&
			    ldata->ld_leh->leh_reccount > 1) {
				lfsck_linkea_del_buf(ldata, cname);
				continue;
			}

			RETURN(rc);
		}

		if (!dt_object_exists(parent)) {
			lfsck_object_put(env, parent);
			if (ldata->ld_leh->leh_reccount > 1) {
				/* If it is NOT the last linkEA entry, then
				 * there is still other chance to make the
				 * child to be visible via other parent, then
				 * remove this linkEA entry. */
				lfsck_linkea_del_buf(ldata, cname);
				continue;
			}

			break;
		}

		/* The linkEA entry with bad parent will be removed. */
		if (unlikely(!dt_try_as_dir(env, parent))) {
			lfsck_object_put(env, parent);
			lfsck_linkea_del_buf(ldata, cname);
			continue;
		}

		rc = dt_lookup_dir(env, parent, cname->ln_name, &tfid);
		*pfid2 = *lfsck_dto2fid(parent);
		if (rc == -ENOENT) {
			lfsck_object_put(env, parent);
			linkea_next_entry(ldata);
			continue;
		}

		if (rc != 0) {
			lfsck_object_put(env, parent);

			RETURN(rc);
		}

		if (lu_fid_eq(&tfid, cfid)) {
			lfsck_object_put(env, parent);
			/* If the parent (that is declared via linkEA entry)
			 * directory contains the specified child, but such
			 * parent does not match the dotdot name entry, then
			 * trust the linkEA. */
			if (!fid_is_zero(pfid) && !lu_fid_eq(pfid, pfid2)) {
				*type = LNIT_UNMATCHED_PAIRS;
				rc = lfsck_namespace_repair_unmatched_pairs(env,
						com, child, pfid2, cname);

				RETURN(rc);
			}

rebuild:
			/* It is the most common case that we find the
			 * name entry corresponding to the linkEA entry
			 * that matches the ".." name entry. */
			rc = linkea_links_new(&ldata_new, &info->lti_big_buf,
					      cname, pfid2);
			if (rc != 0)
				RETURN(rc);

			rc = lfsck_namespace_rebuild_linkea(env, com, child,
							    &ldata_new);
			if (rc < 0)
				RETURN(rc);

			lfsck_linkea_del_buf(ldata, cname);
			linkea_first_entry(ldata);
			/* There may be some invalid dangling name entries under
			 * other parent directories, remove all of them. */
			while (ldata->ld_lee != NULL) {
				rc = lfsck_namespace_unpack_linkea_entry(ldata,
						cname, &tfid, info->lti_key,
						sizeof(info->lti_key));
				if (rc != 0)
					goto next;

				parent = lfsck_object_find_bottom(env, lfsck,
								  &tfid);
				if (IS_ERR(parent)) {
					rc = PTR_ERR(parent);
					if (rc != -ENOENT &&
					    bk->lb_param & LPF_FAILOUT)
						RETURN(rc);

					goto next;
				}

				if (!dt_object_exists(parent)) {
					lfsck_object_put(env, parent);
					goto next;
				}

				rc = lfsck_namespace_repair_dirent(env, com,
					parent, child, cname->ln_name,
					cname->ln_name, S_IFDIR, false, true);
				lfsck_object_put(env, parent);
				if (rc < 0) {
					if (bk->lb_param & LPF_FAILOUT)
						RETURN(rc);

					goto next;
				}

				dirent_count += rc;

next:
				lfsck_linkea_del_buf(ldata, cname);
			}

			ns->ln_dirent_repaired += dirent_count;

			RETURN(rc);
		} /* lu_fid_eq(&tfid, lfsck_dto2fid(child)) */

		lfsck_ibits_unlock(lh, LCK_EX);
		/* The name entry references another MDT-object that may be
		 * created by the LFSCK for repairing dangling name entry.
		 * Try to replace it. */
		rc = lfsck_namespace_replace_cond(env, com, parent, child,
						  &tfid, cname);
		lfsck_object_put(env, parent);
		if (rc < 0)
			RETURN(rc);

		if (rc > 0)
			goto rebuild;

		lfsck_linkea_del_buf(ldata, cname);
	} /* while (ldata->ld_lee != NULL) */

	/* If there is still linkEA overflow, return. */
	if (unlikely(ldata->ld_leh->leh_overflow_time))
		RETURN(0);

	linkea_first_entry(ldata);
	if (ldata->ld_leh->leh_reccount == 1) {
		rc = lfsck_namespace_dsd_single(env, com, child, pfid, ldata,
						lh, type, NULL, unknown);

		RETURN(rc);
	}

	/* All linkEA entries are invalid and removed, then handle the @child
	 * as an orphan.*/
	if (ldata->ld_leh->leh_reccount == 0) {
		rc = lfsck_namespace_dsd_orphan(env, com, child, pfid, lh,
						type);

		RETURN(rc);
	}

	/* If the dangling name entry for the orphan directory object has
	 * been remvoed, then just check whether the directory object is
	 * still under the .lustre/lost+found/MDTxxxx/ or not. */
	if (lpf) {
		lpf = false;
		goto again;
	}

	/* There is no linkEA entry that matches the ".." name entry. Find
	 * the first linkEA entry that both parent and name entry exist to
	 * rebuild a new ".." name entry. */
	if (once) {
		once = false;
		goto again;
	}

	RETURN(rc);
}

/**
 * Repair the object's nlink attribute.
 *
 * If all the known name entries have been verified, then the object's hard
 * link attribute should match the object's linkEA entries count unless the
 * object's has too many hard link to be recorded in the linkEA. Such cases
 * should have been marked in the LFSCK trace file. Otherwise, trust the
 * linkEA to update the object's nlink attribute.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the dt_object to be handled
 * \param[in,out] la	pointer to buffer to object's attribute before
 *			and after the repairing
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_repair_nlink(const struct lu_env *env,
					struct lfsck_component *com,
					struct dt_object *obj,
					struct lu_attr *la)
{
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck_obj2dev(obj);
	const struct lu_fid		*cfid	= lfsck_dto2fid(obj);
	struct thandle			*th	= NULL;
	struct linkea_data		 ldata	= { NULL };
	struct lustre_handle		 lh	= { 0 };
	__u32				 old	= la->la_nlink;
	int				 rc	= 0;
	ENTRY;

	LASSERT(!dt_object_remote(obj));

	rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
			      MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		GOTO(log, rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	la->la_valid = LA_NLINK;
	rc = dt_declare_attr_set(env, obj, la, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	/* If the LFSCK is marked as LF_INCOMPLETE, then means some MDT has
	 * ever tried to verify some remote MDT-object that resides on this
	 * MDT, but this MDT failed to respond such request. So means there
	 * may be some remote name entry on other MDT that references this
	 * object with another name, so we cannot know whether this linkEA
	 * is valid or not. So keep it there and maybe resolved when next
	 * LFSCK run. */
	if (ns->ln_flags & LF_INCOMPLETE)
		GOTO(unlock, rc = 0);

	rc = dt_attr_get(env, obj, la);
	if (rc != 0)
		GOTO(unlock, rc = (rc == -ENOENT ? 0 : rc));

	rc = lfsck_links_read2_with_rec(env, obj, &ldata);
	if (rc)
		GOTO(unlock, rc = (rc == -ENODATA ? 0 : rc));

	/* XXX: Currently, we only update the nlink attribute if the known
	 *	linkEA entries is larger than the nlink attribute. That is
	 *	safe action. */
	if (la->la_nlink >= ldata.ld_leh->leh_reccount ||
	    unlikely(la->la_nlink == 0 ||
		     ldata.ld_leh->leh_overflow_time))
		GOTO(unlock, rc = 0);

	la->la_nlink = ldata.ld_leh->leh_reccount;
	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(unlock, rc = 1);

	rc = dt_attr_set(env, obj, la, th);

	GOTO(unlock, rc = (rc == 0 ? 1 : rc));

unlock:
	dt_write_unlock(env, obj);

stop:
	dt_trans_stop(env, dev, th);

log:
	lfsck_ibits_unlock(&lh, LCK_PW);
	CDEBUG(D_LFSCK, "%s: namespace LFSCK repaired the object "DFID"'s "
	       "nlink count from %u to %u: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(cfid), old, la->la_nlink, rc);

	if (rc != 0)
		ns->ln_flags |= LF_INCONSISTENT;

	return rc;
}

/**
 * Double scan the directory object for namespace LFSCK.
 *
 * This function will verify the <parent, child> pairs in the namespace tree:
 * the parent references the child via some name entry that should be in the
 * child's linkEA entry, the child should back references the parent via its
 * ".." name entry.
 *
 * The LFSCK will scan every linkEA entry in turn until find out the first
 * matched pairs. If found, then all other linkEA entries will be dropped.
 * If all the linkEA entries cannot match the ".." name entry, then there
 * are serveral possible cases:
 *
 * 1) If there is only one linkEA entry, then trust it as long as the PFID
 *    in the linkEA entry is valid.
 *
 * 2) If there are multiple linkEA entries, then try to find the linkEA
 *    that matches the ".." name entry. If found, then all other entries
 *    are invalid; otherwise, it is quite possible that the ".." name entry
 *    is corrupted. Under such case, the LFSCK will rebuild the ".." name
 *    entry according to the first valid linkEA entry (both the parent and
 *    the name entry should exist).
 *
 * 3) If the directory object has no (valid) linkEA entry, then the
 *    directory object will be handled as pure orphan and inserted
 *    in the .lustre/lost+found/MDTxxxx/ with the name:
 *    ${self_FID}-${PFID}-D-${conflict_version}
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] child	pointer to the directory object to be handled
 * \param[in] flags	to indicate the specical checking on the @child
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_double_scan_dir(const struct lu_env *env,
					   struct lfsck_component *com,
					   struct dt_object *child, __u8 flags)
{
	struct lfsck_thread_info *info		= lfsck_env_info(env);
	const struct lu_fid	 *cfid		= lfsck_dto2fid(child);
	struct lu_fid		 *pfid		= &info->lti_fid2;
	struct lfsck_namespace	 *ns		= com->lc_file_ram;
	struct lfsck_instance	 *lfsck		= com->lc_lfsck;
	struct lustre_handle	  lh		= { 0 };
	struct linkea_data	  ldata		= { NULL };
	bool			  unknown	= false;
	bool			  lpf		= false;
	bool			  retry		= false;
	enum lfsck_namespace_inconsistency_type type = LNIT_BAD_LINKEA;
	int			  rc		= 0;
	ENTRY;

	LASSERT(!dt_object_remote(child));

	if (flags & LNTF_UNCERTAIN_LMV) {
		if (flags & LNTF_RECHECK_NAME_HASH) {
			rc = lfsck_namespace_scan_shard(env, com, child);
			if (rc < 0)
				RETURN(rc);

			ns->ln_striped_shards_scanned++;
		} else {
			ns->ln_striped_shards_skipped++;
		}
	}

	flags &= ~(LNTF_RECHECK_NAME_HASH | LNTF_UNCERTAIN_LMV);
	if (flags == 0)
		RETURN(0);

	if (flags & (LNTF_CHECK_LINKEA | LNTF_CHECK_PARENT) &&
	    !(lfsck->li_bookmark_ram.lb_param & LPF_ALL_TGT)) {
		CDEBUG(D_LFSCK,
		       "%s: some MDT(s) maybe NOT take part in the the namespace LFSCK, then the LFSCK cannot guarantee all the name entries have been verified in first-stage scanning. So have to skip orphan related handling for the directory object "DFID" with remote name entry\n",
		       lfsck_lfsck2name(lfsck), PFID(cfid));

		RETURN(0);
	}

	if (unlikely(!dt_try_as_dir(env, child)))
		GOTO(out, rc = -ENOTDIR);

	/* We only take ldlm lock on the @child when required. When the
	 * logic comes here for the first time, it is always false. */
	if (0) {

lock:
		rc = lfsck_ibits_lock(env, lfsck, child, &lh,
				      MDS_INODELOCK_UPDATE |
				      MDS_INODELOCK_XATTR, LCK_EX);
		if (rc != 0)
			GOTO(out, rc);
	}

	dt_read_lock(env, child, 0);
	if (unlikely(lfsck_is_dead_obj(child))) {
		dt_read_unlock(env, child);

		GOTO(out, rc = 0);
	}

	rc = dt_lookup_dir(env, child, dotdot, pfid);
	if (rc != 0) {
		if (rc != -ENOENT && rc != -ENODATA && rc != -EINVAL) {
			dt_read_unlock(env, child);

			GOTO(out, rc);
		}

		if (!lustre_handle_is_used(&lh)) {
			dt_read_unlock(env, child);
			goto lock;
		}

		fid_zero(pfid);
	} else if (lfsck->li_lpf_obj != NULL &&
		   lu_fid_eq(pfid, lfsck_dto2fid(lfsck->li_lpf_obj))) {
		lpf = true;
	} else if (unlikely(!fid_is_sane(pfid))) {
		fid_zero(pfid);
	}

	rc = lfsck_links_read(env, child, &ldata);
	dt_read_unlock(env, child);
	if (rc != 0) {
		if (rc != -ENODATA && rc != -EINVAL)
			GOTO(out, rc);

		if (!lustre_handle_is_used(&lh))
			goto lock;

		if (rc == -EINVAL && !fid_is_zero(pfid)) {
			/* Remove the corrupted linkEA. */
			rc = lfsck_namespace_links_remove(env, com, child);
			if (rc == 0)
				/* Here, because of the crashed linkEA, we
				 * cannot know whether there is some parent
				 * that references the child directory via
				 * some name entry or not. So keep it there,
				 * when the LFSCK run next time, if there is
				 * some parent that references this object,
				 * then the LFSCK can rebuild the linkEA;
				 * otherwise, this object will be handled
				 * as orphan as above. */
				unknown = true;
		} else {
			/* 1. If we have neither ".." nor linkEA,
			 *    then it is an orphan.
			 *
			 * 2. If we only have the ".." name entry,
			 *    but no parent references this child
			 *    directory, then handle it as orphan. */
			lfsck_ibits_unlock(&lh, LCK_EX);
			type = LNIT_MUL_REF;

			/* If the LFSCK is marked as LF_INCOMPLETE,
			 * then means some MDT has ever tried to
			 * verify some remote MDT-object that resides
			 * on this MDT, but this MDT failed to respond
			 * such request. So means there may be some
			 * remote name entry on other MDT that
			 * references this object with another name,
			 * so we cannot know whether this linkEA is
			 * valid or not. So keep it there and maybe
			 * resolved when next LFSCK run. */
			if (ns->ln_flags & LF_INCOMPLETE)
				GOTO(out, rc = 0);

			snprintf(info->lti_tmpbuf, sizeof(info->lti_tmpbuf),
				 "-"DFID, PFID(pfid));
			rc = lfsck_namespace_insert_orphan(env, com, child,
						info->lti_tmpbuf, "D", NULL);
		}

		GOTO(out, rc);
	} /* rc != 0 */

	linkea_first_entry(&ldata);
	/* This is the most common case: the object has unique linkEA entry. */
	if (ldata.ld_leh->leh_reccount == 1) {
		rc = lfsck_namespace_dsd_single(env, com, child, pfid, &ldata,
						&lh, &type, &retry, &unknown);
		if (retry) {
			LASSERT(!lustre_handle_is_used(&lh));

			retry = false;
			goto lock;
		}

		GOTO(out, rc);
	}

	if (!lustre_handle_is_used(&lh))
		goto lock;

	if (unlikely(ldata.ld_leh->leh_reccount == 0)) {
		rc = lfsck_namespace_dsd_orphan(env, com, child, pfid, &lh,
						&type);

		GOTO(out, rc);
	}

	/* When we come here, the cases usually like that:
	 * 1) The directory object has a corrupted linkEA entry. During the
	 *    first-stage scanning, the LFSCK cannot know such corruption,
	 *    then it appends the right linkEA entry according to the found
	 *    name entry after the bad one.
	 *
	 * 2) The directory object has a right linkEA entry. During the
	 *    first-stage scanning, the LFSCK finds some bad name entry,
	 *    but the LFSCK cannot aware that at that time, then it adds
	 *    the bad linkEA entry for further processing. */
	rc = lfsck_namespace_dsd_multiple(env, com, child, pfid, &ldata,
					  &lh, &type, lpf, &unknown);

	GOTO(out, rc);

out:
	lfsck_ibits_unlock(&lh, LCK_EX);
	if (rc > 0) {
		switch (type) {
		case LNIT_BAD_LINKEA:
			ns->ln_linkea_repaired++;
			break;
		case LNIT_UNMATCHED_PAIRS:
			ns->ln_unmatched_pairs_repaired++;
			break;
		case LNIT_MUL_REF:
			ns->ln_mul_ref_repaired++;
			break;
		default:
			break;
		}
	}

	if (unknown)
		ns->ln_unknown_inconsistency++;

	return rc;
}

static inline bool
lfsck_namespace_linkea_stale_overflow(struct linkea_data *ldata,
				      struct lfsck_namespace *ns)
{
	/* Both the leh_overflow_time and ln_time_latest_reset are
	 * local time based, so need NOT to care about clock drift
	 * among the servers. */
	return ldata->ld_leh->leh_overflow_time &&
	       ldata->ld_leh->leh_overflow_time < ns->ln_time_latest_reset;
}

/**
 * Clear the object's linkEA overflow timestamp.
 *
 * If the MDT-object has too many hard links as to the linkEA cannot hold
 * all of them, then overflow timestamp will be set in the linkEA header.
 * If some hard links are removed after that, then it is possible to hold
 * other missed linkEA entries. If the namespace LFSCK have added all the
 * related linkEA entries, then it will remove the overflow timestamp.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] ldata	pointer to the linkEA data for the given @obj
 * \param[in] obj	pointer to the dt_object to be handled
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_linkea_clear_overflow(const struct lu_env *env,
						 struct lfsck_component *com,
						 struct linkea_data *ldata,
						 struct dt_object *obj)
{
	struct lfsck_namespace *ns = com->lc_file_ram;
	struct lfsck_instance *lfsck = com->lc_lfsck;
	struct dt_device *dev = lfsck_obj2dev(obj);
	struct thandle *th = NULL;
	struct lustre_handle lh = { 0 };
	struct lu_buf linkea_buf;
	int rc = 0;
	ENTRY;

	LASSERT(!dt_object_remote(obj));

	rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
			      MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		GOTO(log, rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	rc = dt_declare_xattr_set(env, obj,
			lfsck_buf_get_const(env, NULL, MAX_LINKEA_SIZE),
			XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	rc = lfsck_links_read(env, obj, ldata);
	if (rc != 0)
		GOTO(unlock, rc);

	if (unlikely(!lfsck_namespace_linkea_stale_overflow(ldata, ns)))
		GOTO(unlock, rc = 0);

	ldata->ld_leh->leh_overflow_time = 0;
	if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
		GOTO(unlock, rc = 1);

	/* If all known entries are in the linkEA, then the 'leh_reccount'
	 * should NOT be zero. */
	LASSERT(ldata->ld_leh->leh_reccount > 0);

	lfsck_buf_init(&linkea_buf, ldata->ld_buf->lb_buf,
		       ldata->ld_leh->leh_len);
	rc = dt_xattr_set(env, obj, &linkea_buf, XATTR_NAME_LINK, 0, th);
	if (unlikely(rc == -ENOSPC))
		rc = 0;
	else if (!rc)
		rc = 1;

	GOTO(unlock, rc);

unlock:
	dt_write_unlock(env, obj);

stop:
	dt_trans_stop(env, dev, th);

log:
	lfsck_ibits_unlock(&lh, LCK_PW);
	CDEBUG(D_LFSCK, "%s: clear linkea overflow timestamp for the object "
	       DFID": rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(obj)), rc);

	return rc;
}

/**
 * Verify the object's agent entry.
 *
 * If the object claims to have agent entry but the linkEA does not contain
 * remote parent, then remove the agent entry. Otherwise, if the object has
 * no agent entry but its linkEA contains remote parent, then will generate
 * agent entry for it.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] obj	pointer to the dt_object to be handled
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_check_agent_entry(const struct lu_env *env,
					     struct lfsck_component *com,
					     struct dt_object *obj)
{
	struct linkea_data ldata = { NULL };
	struct lfsck_thread_info *info = lfsck_env_info(env);
	struct lfsck_namespace *ns = com->lc_file_ram;
	struct lfsck_instance *lfsck = com->lc_lfsck;
	struct lu_fid *pfid = &info->lti_fid2;
	struct lu_name *cname = &info->lti_name;
	struct lu_seq_range *range = &info->lti_range;
	struct seq_server_site *ss = lfsck_dev_site(lfsck);
	__u32 idx = lfsck_dev_idx(lfsck);
	int rc;
	bool remote = false;
	ENTRY;

	if (!(lfsck->li_bookmark_ram.lb_param & LPF_ALL_TGT))
		RETURN(0);

	rc = lfsck_links_read_with_rec(env, obj, &ldata);
	if (rc == -ENOENT || rc == -ENODATA)
		RETURN(0);

	if (rc && rc != -EINVAL)
		GOTO(out, rc);

	/* We check the agent entry again after verifying the linkEA
	 * successfully. So invalid linkEA should be dryrun mode. */
	if (rc == -EINVAL || unlikely(!ldata.ld_leh->leh_reccount))
		RETURN(0);

	linkea_first_entry(&ldata);
	while (ldata.ld_lee != NULL && !remote) {
		linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen,
				    cname, pfid);
		if (!linkea_entry_is_valid(&ldata, cname, pfid))
			GOTO(out, rc = 0);

		fld_range_set_mdt(range);
		rc = fld_server_lookup(env, ss->ss_server_fld,
				       fid_seq(pfid), range);
		if (rc)
			GOTO(out, rc = (rc == -ENOENT ? 0 : rc));

		if (range->lsr_index != idx)
			remote = true;
		else
			linkea_next_entry(&ldata);
	}

	if ((lu_object_has_agent_entry(&obj->do_lu) && !remote) ||
	    (!lu_object_has_agent_entry(&obj->do_lu) && remote)) {
		struct dt_device *dev = lfsck_obj2dev(obj);
		struct linkea_data ldata2 = { NULL };
		struct lustre_handle lh	= { 0 };
		struct lu_buf linkea_buf;
		struct thandle *handle;

		if (lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN)
			GOTO(out, rc = 1);

		rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
				      MDS_INODELOCK_UPDATE |
				      MDS_INODELOCK_XATTR, LCK_EX);
		if (rc)
			GOTO(out, rc);

		handle = dt_trans_create(env, dev);
		if (IS_ERR(handle))
			GOTO(unlock, rc = PTR_ERR(handle));

		lfsck_buf_init(&linkea_buf, ldata.ld_buf->lb_buf,
			       ldata.ld_leh->leh_len);
		rc = dt_declare_xattr_set(env, obj, &linkea_buf,
				XATTR_NAME_LINK, LU_XATTR_REPLACE, handle);
		if (rc)
			GOTO(stop, rc);

		rc = dt_trans_start_local(env, dev, handle);
		if (rc)
			GOTO(stop, rc);

		dt_write_lock(env, obj, 0);
		rc = lfsck_links_read2_with_rec(env, obj, &ldata2);
		if (rc) {
			if (rc == -ENOENT || rc == -ENODATA)
				rc = 0;
			GOTO(unlock2, rc);
		}

		/* If someone changed linkEA by race, then the agent
		 * entry will be updated by lower layer automatically. */
		if (ldata.ld_leh->leh_len != ldata2.ld_leh->leh_len ||
		    memcmp(ldata.ld_buf->lb_buf, ldata2.ld_buf->lb_buf,
			   ldata.ld_leh->leh_len) != 0)
			GOTO(unlock2, rc = 0);

		rc = dt_xattr_set(env, obj, &linkea_buf, XATTR_NAME_LINK,
				  LU_XATTR_REPLACE, handle);
		if (!rc)
			rc = 1;

		GOTO(unlock2, rc);

unlock2:
		dt_write_unlock(env, obj);
stop:
		dt_trans_stop(env, dev, handle);
unlock:
		lfsck_ibits_unlock(&lh, LCK_EX);
	}

	GOTO(out, rc);

out:
	if (rc > 0)
		ns->ln_agent_entries_repaired++;
	if (rc)
		CDEBUG(D_LFSCK, "%s: repair agent entry for "DFID": rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(obj)), rc);
	return rc;
}

/**
 * Double scan the MDT-object for namespace LFSCK.
 *
 * If the MDT-object contains invalid or repeated linkEA entries, then drop
 * those entries from the linkEA; if the linkEA becomes empty or the object
 * has no linkEA, then it is an orphan and will be added into the directory
 * .lustre/lost+found/MDTxxxx/; if the remote parent is lost, then recreate
 * the remote parent; if the name entry corresponding to some linkEA entry
 * is lost, then add the name entry back to the namespace.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] child	pointer to the dt_object to be handled
 * \param[in] flags	some hints to indicate how the @child should be handled
 *
 * \retval		positive number for repaired cases
 * \retval		0 if nothing to be repaired
 * \retval		negative error number on failure
 */
static int lfsck_namespace_double_scan_one(const struct lu_env *env,
					   struct lfsck_component *com,
					   struct dt_object *child, __u8 flags)
{
	struct lfsck_thread_info *info	   = lfsck_env_info(env);
	struct lu_attr		 *la	   = &info->lti_la;
	struct lu_name		 *cname	   = &info->lti_name;
	struct lu_fid		 *pfid	   = &info->lti_fid;
	struct lu_fid		 *cfid	   = &info->lti_fid2;
	struct lfsck_instance	 *lfsck	   = com->lc_lfsck;
	struct lfsck_namespace	 *ns	   = com->lc_file_ram;
	struct dt_object	 *parent   = NULL;
	struct linkea_data	  ldata	   = { NULL };
	bool			  repaired = false;
	int			  count	   = 0;
	int			  rc;
	ENTRY;

	dt_read_lock(env, child, 0);
	if (unlikely(lfsck_is_dead_obj(child))) {
		dt_read_unlock(env, child);

		RETURN(0);
	}

	if (S_ISDIR(lfsck_object_type(child))) {
		dt_read_unlock(env, child);
		rc = lfsck_namespace_double_scan_dir(env, com, child, flags);
		if (!rc && flags & LNTF_CHECK_AGENT_ENTRY)
			rc = lfsck_namespace_check_agent_entry(env, com, child);

		RETURN(rc);
	}

	rc = lfsck_links_read(env, child, &ldata);
	dt_read_unlock(env, child);

	if (rc == -EINVAL) {
		struct lustre_handle lh	= { 0 };

		rc = lfsck_ibits_lock(env, com->lc_lfsck, child, &lh,
				      MDS_INODELOCK_UPDATE |
				      MDS_INODELOCK_XATTR, LCK_EX);
		if (rc == 0) {
			rc = lfsck_namespace_links_remove(env, com, child);
			lfsck_ibits_unlock(&lh, LCK_EX);
		}

		GOTO(out, rc);
	}

	if (rc != 0)
		GOTO(out, rc);

	if (!(ns->ln_flags & LF_INCOMPLETE) &&
	    unlikely(lfsck_namespace_linkea_stale_overflow(&ldata, ns))) {
		rc = lfsck_namespace_linkea_clear_overflow(env, com, &ldata,
							   child);
		if (rc < 0)
			GOTO(out, rc);

		if (rc > 0)
			ns->ln_linkea_overflow_cleared++;
	}

	linkea_first_entry(&ldata);
	while (ldata.ld_lee != NULL) {
		rc = lfsck_namespace_unpack_linkea_entry(&ldata, cname, pfid,
							 info->lti_key,
							 sizeof(info->lti_key));
		/* Invalid PFID in the linkEA entry. */
		if (rc != 0) {
			rc = lfsck_namespace_shrink_linkea(env, com, child,
						&ldata, cname, pfid, true);
			if (rc < 0)
				GOTO(out, rc);

			if (rc > 0)
				repaired = true;

			continue;
		}

		rc = lfsck_namespace_filter_linkea_entry(&ldata, cname, pfid,
							 false);
		/* Found repeated linkEA entries */
		if (rc > 0) {
			rc = lfsck_namespace_shrink_linkea(env, com, child,
						&ldata, cname, pfid, false);
			if (rc < 0)
				GOTO(out, rc);

			if (rc == 0)
				continue;

			repaired = true;

			/* fall through */
		}

		parent = lfsck_object_find_bottom(env, lfsck, pfid);
		if (IS_ERR(parent)) {
			rc = PTR_ERR(parent);
			/* if @pfid doesn't have a valid OI mapping, it will
			 * trigger OI scrub, and -ENONET is is returned if it's
			 * remote, -EINPROGRESS if local.
			 */
			if ((rc == -ENOENT || rc == -EINPROGRESS) &&
			    ldata.ld_leh->leh_reccount > 1)
				rc = lfsck_namespace_shrink_linkea(env, com,
					child, &ldata, cname, pfid, true);
			GOTO(out, rc);
		}

		if (!dt_object_exists(parent)) {

lost_parent:
			if (ldata.ld_leh->leh_reccount > 1) {
				/* If it is NOT the last linkEA entry, then
				 * there is still other chance to make the
				 * child to be visible via other parent, then
				 * remove this linkEA entry. */
				rc = lfsck_namespace_shrink_linkea(env, com,
					child, &ldata, cname, pfid, true);
			} else {
				/* If the LFSCK is marked as LF_INCOMPLETE,
				 * then means some MDT has ever tried to
				 * verify some remote MDT-object that resides
				 * on this MDT, but this MDT failed to respond
				 * such request. So means there may be some
				 * remote name entry on other MDT that
				 * references this object with another name,
				 * so we cannot know whether this linkEA is
				 * valid or not. So keep it there and maybe
				 * resolved when next LFSCK run. */
				if (ns->ln_flags & LF_INCOMPLETE) {
					lfsck_object_put(env, parent);

					GOTO(out, rc = 0);
				}

				/* Create the lost parent as an orphan. */
				rc = lfsck_namespace_create_orphan_dir(env, com,
								parent, NULL);
				if (rc < 0) {
					lfsck_object_put(env, parent);

					GOTO(out, rc);
				}

				if (rc > 0)
					repaired = true;

				/* Add the missing name entry to the parent. */
				rc = lfsck_namespace_insert_normal(env, com,
							parent, child, cname);
				if (unlikely(rc == -EEXIST))
					/* Unfortunately, someone reused the
					 * name under the parent by race. So we
					 * have to remove the linkEA entry from
					 * current child object. It means that
					 * the LFSCK cannot recover the system
					 * totally back to its original status,
					 * but it is necessary to make the
					 * current system to be consistent. */
					rc = lfsck_namespace_shrink_linkea(env,
							com, child, &ldata,
							cname, pfid, true);
				else
					linkea_next_entry(&ldata);
			}

			lfsck_object_put(env, parent);
			if (rc < 0)
				GOTO(out, rc);

			if (rc > 0)
				repaired = true;

			continue;
		} /* !dt_object_exists(parent) */

		/* The linkEA entry with bad parent will be removed. */
		if (unlikely(!dt_try_as_dir(env, parent))) {
			lfsck_object_put(env, parent);
			rc = lfsck_namespace_shrink_linkea(env, com, child,
						&ldata, cname, pfid, true);
			if (rc < 0)
				GOTO(out, rc);

			if (rc > 0)
				repaired = true;

			continue;
		}

		rc = dt_lookup_dir(env, parent, cname->ln_name, cfid);
		if (rc != 0 && rc != -ENOENT) {
			lfsck_object_put(env, parent);

			GOTO(out, rc);
		}

		if (rc == 0) {
			if (lu_fid_eq(cfid, lfsck_dto2fid(child))) {
				/* It is the most common case that we
				 * find the name entry corresponding
				 * to the linkEA entry. */
				lfsck_object_put(env, parent);
				linkea_next_entry(&ldata);
			} else {
				/* The name entry references another
				 * MDT-object that may be created by
				 * the LFSCK for repairing dangling
				 * name entry. Try to replace it. */
				rc = lfsck_namespace_replace_cond(env, com,
						parent, child, cfid, cname);
				lfsck_object_put(env, parent);
				if (rc < 0)
					GOTO(out, rc);

				if (rc > 0) {
					repaired = true;
					linkea_next_entry(&ldata);
				} else {
					rc = lfsck_namespace_shrink_linkea(env,
							com, child, &ldata,
							cname, pfid, true);
					if (rc < 0)
						GOTO(out, rc);

					if (rc > 0)
						repaired = true;
				}
			}

			continue;
		}

		/* The following handles -ENOENT case */

		rc = dt_attr_get(env, child, la);
		if (rc != 0)
			GOTO(out, rc);

		/* If there is no name entry in the parent dir and the object
		 * link count is fewer than the linkea entries count, then the
		 * linkea entry should be removed. */
		if (ldata.ld_leh->leh_reccount > la->la_nlink) {
			rc = lfsck_namespace_shrink_linkea_cond(env, com,
					parent, child, &ldata, cname, pfid);
			lfsck_object_put(env, parent);
			if (rc < 0)
				GOTO(out, rc);

			if (rc > 0)
				repaired = true;

			continue;
		}

		/* If the LFSCK is marked as LF_INCOMPLETE, then means some
		 * MDT has ever tried to verify some remote MDT-object that
		 * resides on this MDT, but this MDT failed to respond such
		 * request. So means there may be some remote name entry on
		 * other MDT that references this object with another name,
		 * so we cannot know whether this linkEA is valid or not.
		 * So keep it there and maybe resolved when next LFSCK run. */
		if (ns->ln_flags & LF_INCOMPLETE) {
			lfsck_object_put(env, parent);

			GOTO(out, rc = 0);
		}

		rc = lfsck_namespace_check_name(env, lfsck, parent, child,
						cname);
		if (rc == -ENOENT)
			goto lost_parent;

		if (rc < 0) {
			lfsck_object_put(env, parent);

			GOTO(out, rc);
		}

		/* It is an invalid name entry, drop it. */
		if (unlikely(rc > 0)) {
			lfsck_object_put(env, parent);
			rc = lfsck_namespace_shrink_linkea(env, com, child,
						&ldata, cname, pfid, true);
			if (rc < 0)
				GOTO(out, rc);

			if (rc > 0)
				repaired = true;

			continue;
		}

		/* Add the missing name entry back to the namespace. */
		rc = lfsck_namespace_insert_normal(env, com, parent, child,
						   cname);
		if (unlikely(rc == -ESTALE))
			/* It may happen when the remote object has been
			 * removed, but the local MDT is not aware of that. */
			goto lost_parent;

		if (unlikely(rc == -EEXIST))
			/* Unfortunately, someone reused the name under the
			 * parent by race. So we have to remove the linkEA
			 * entry from current child object. It means that the
			 * LFSCK cannot recover the system totally back to
			 * its original status, but it is necessary to make
			 * the current system to be consistent.
			 *
			 * It also may be because of the LFSCK found some
			 * internal status of create operation. Under such
			 * case, nothing to be done. */
			rc = lfsck_namespace_shrink_linkea_cond(env, com,
					parent, child, &ldata, cname, pfid);
		else
			linkea_next_entry(&ldata);

		lfsck_object_put(env, parent);
		if (rc < 0)
			GOTO(out, rc);

		if (rc > 0)
			repaired = true;
	}

	GOTO(out, rc = 0);

out:
	if (rc < 0 && rc != -ENODATA)
		return rc;

	if (rc == 0 && ldata.ld_leh != NULL)
		count = ldata.ld_leh->leh_reccount;

	if (count == 0) {
		/* If the LFSCK is marked as LF_INCOMPLETE, then means some
		 * MDT has ever tried to verify some remote MDT-object that
		 * resides on this MDT, but this MDT failed to respond such
		 * request. So means there may be some remote name entry on
		 * other MDT that references this object with another name,
		 * so we cannot know whether this linkEA is valid or not.
		 * So keep it there and maybe resolved when next LFSCK run. */
		if (!(ns->ln_flags & LF_INCOMPLETE) &&
		    (ldata.ld_leh == NULL ||
		     !ldata.ld_leh->leh_overflow_time)) {
			/* If the child becomes orphan, then insert it into
			 * the global .lustre/lost+found/MDTxxxx directory. */
			rc = lfsck_namespace_insert_orphan(env, com, child,
							   "", "O", &count);
			if (rc < 0)
				return rc;

			if (rc > 0) {
				ns->ln_mul_ref_repaired++;
				repaired = true;
			}
		}
	} else {
		rc = dt_attr_get(env, child, la);
		if (rc != 0)
			return rc;

		if (la->la_nlink != 0 && la->la_nlink != count) {
			if (unlikely(!S_ISREG(lfsck_object_type(child)) &&
				     !S_ISLNK(lfsck_object_type(child)))) {
				CDEBUG(D_LFSCK, "%s: namespace LFSCK finds "
				       "the object "DFID"'s nlink count %d "
				       "does not match linkEA count %d, "
				       "type %o, skip it.\n",
				       lfsck_lfsck2name(lfsck),
				       PFID(lfsck_dto2fid(child)),
				       la->la_nlink, count,
				       lfsck_object_type(child));
			} else if (la->la_nlink < count &&
				   likely(!ldata.ld_leh->leh_overflow_time)) {
				rc = lfsck_namespace_repair_nlink(env, com,
								  child, la);
				if (rc > 0) {
					ns->ln_objs_nlink_repaired++;
					rc = 0;
				}
			}
		}
	}

	if (repaired) {
		if (la->la_nlink > 1)
			ns->ln_mul_linked_repaired++;

		if (rc == 0)
			rc = 1;
	}

	if (!rc && flags & LNTF_CHECK_AGENT_ENTRY)
		rc = lfsck_namespace_check_agent_entry(env, com, child);

	return rc;
}

static void lfsck_namespace_dump_statistics(struct seq_file *m,
					    struct lfsck_namespace *ns,
					    __u64 checked_phase1,
					    __u64 checked_phase2,
					    time64_t time_phase1,
					    time64_t time_phase2, bool dryrun)
{
	const char *postfix = dryrun ? "inconsistent" : "repaired";

	seq_printf(m, "checked_phase1: %llu\n"
		   "checked_phase2: %llu\n"
		   "%s_phase1: %llu\n"
		   "%s_phase2: %llu\n"
		   "failed_phase1: %llu\n"
		   "failed_phase2: %llu\n"
		   "directories: %llu\n"
		   "dirent_%s: %llu\n"
		   "linkea_%s: %llu\n"
		   "nlinks_%s: %llu\n"
		   "multiple_linked_checked: %llu\n"
		   "multiple_linked_%s: %llu\n"
		   "unknown_inconsistency: %llu\n"
		   "unmatched_pairs_%s: %llu\n"
		   "dangling_%s: %llu\n"
		   "multiple_referenced_%s: %llu\n"
		   "bad_file_type_%s: %llu\n"
		   "lost_dirent_%s: %llu\n"
		   "local_lost_found_scanned: %llu\n"
		   "local_lost_found_moved: %llu\n"
		   "local_lost_found_skipped: %llu\n"
		   "local_lost_found_failed: %llu\n"
		   "striped_dirs_scanned: %llu\n"
		   "striped_dirs_%s: %llu\n"
		   "striped_dirs_failed: %llu\n"
		   "striped_dirs_disabled: %llu\n"
		   "striped_dirs_skipped: %llu\n"
		   "striped_shards_scanned: %llu\n"
		   "striped_shards_%s: %llu\n"
		   "striped_shards_failed: %llu\n"
		   "striped_shards_skipped: %llu\n"
		   "name_hash_%s: %llu\n"
		   "linkea_overflow_%s: %llu\n"
		   "agent_entries_%s: %llu\n"
		   "success_count: %u\n"
		   "run_time_phase1: %lld seconds\n"
		   "run_time_phase2: %lld seconds\n",
		   checked_phase1,
		   checked_phase2,
		   dryrun ? "inconsistent" : "updated",
		   ns->ln_items_repaired,
		   dryrun ? "inconsistent" : "updated",
		   ns->ln_objs_repaired_phase2,
		   ns->ln_items_failed,
		   ns->ln_objs_failed_phase2,
		   ns->ln_dirs_checked,
		   postfix, ns->ln_dirent_repaired,
		   postfix, ns->ln_linkea_repaired,
		   postfix, ns->ln_objs_nlink_repaired,
		   ns->ln_mul_linked_checked,
		   postfix, ns->ln_mul_linked_repaired,
		   ns->ln_unknown_inconsistency,
		   postfix, ns->ln_unmatched_pairs_repaired,
		   postfix, ns->ln_dangling_repaired,
		   postfix, ns->ln_mul_ref_repaired,
		   postfix, ns->ln_bad_type_repaired,
		   postfix, ns->ln_lost_dirent_repaired,
		   ns->ln_local_lpf_scanned,
		   ns->ln_local_lpf_moved,
		   ns->ln_local_lpf_skipped,
		   ns->ln_local_lpf_failed,
		   ns->ln_striped_dirs_scanned,
		   postfix, ns->ln_striped_dirs_repaired,
		   ns->ln_striped_dirs_failed,
		   ns->ln_striped_dirs_disabled,
		   ns->ln_striped_dirs_skipped,
		   ns->ln_striped_shards_scanned,
		   postfix, ns->ln_striped_shards_repaired,
		   ns->ln_striped_shards_failed,
		   ns->ln_striped_shards_skipped,
		   postfix, ns->ln_name_hash_repaired,
		   dryrun ? "inconsistent" : "cleared",
		   ns->ln_linkea_overflow_cleared,
		   postfix, ns->ln_agent_entries_repaired,
		   ns->ln_success_count,
		   time_phase1,
		   time_phase2);
}

static void lfsck_namespace_release_lmv(const struct lu_env *env,
					struct lfsck_component *com)
{
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_namespace		*ns	= com->lc_file_ram;

	while (!list_empty(&lfsck->li_list_lmv)) {
		struct lfsck_lmv_unit	*llu;
		struct lfsck_lmv	*llmv;

		llu = list_entry(lfsck->li_list_lmv.next,
				 struct lfsck_lmv_unit, llu_link);
		llmv = &llu->llu_lmv;

		LASSERTF(atomic_read(&llmv->ll_ref) == 1,
			 "still in using: %u\n",
			 atomic_read(&llmv->ll_ref));

		ns->ln_striped_dirs_skipped++;
		lfsck_lmv_put(env, llmv);
	}
}

static int lfsck_namespace_check_for_double_scan(const struct lu_env *env,
						 struct lfsck_component *com,
						 struct dt_object *obj)
{
	struct lu_attr *la = &lfsck_env_info(env)->lti_la;
	int		rc;

	rc = dt_attr_get(env, obj, la);
	if (rc != 0)
		return rc;

	/* zero-linkEA object may be orphan, but it also maybe because
	 * of upgrading. Currently, we cannot record it for double scan.
	 * Because it may cause the LFSCK trace file to be too large. */

	/* "la_ctime" == 1 means that it has ever been removed from
	 * backend /lost+found directory but not been added back to
	 * the normal namespace yet. */

	if ((S_ISREG(lfsck_object_type(obj)) && la->la_nlink > 1) ||
	    unlikely(la->la_ctime == 1))
		rc = lfsck_namespace_trace_update(env, com, lfsck_dto2fid(obj),
						  LNTF_CHECK_LINKEA, true);

	return rc;
}

/* namespace APIs */

static int lfsck_namespace_reset(const struct lu_env *env,
				 struct lfsck_component *com, bool init)
{
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct dt_object		*root;
	int				 rc;
	ENTRY;

	root = dt_locate(env, lfsck->li_bottom, &lfsck->li_local_root_fid);
	if (IS_ERR(root))
		GOTO(log, rc = PTR_ERR(root));

	if (unlikely(!dt_try_as_dir(env, root)))
		GOTO(put, rc = -ENOTDIR);

	down_write(&com->lc_sem);
	if (init) {
		memset(ns, 0, sizeof(*ns));
	} else {
		__u32 count = ns->ln_success_count;
		time64_t last_time = ns->ln_time_last_complete;

		memset(ns, 0, sizeof(*ns));
		ns->ln_success_count = count;
		ns->ln_time_last_complete = last_time;
	}
	ns->ln_magic = LFSCK_NAMESPACE_MAGIC;
	ns->ln_status = LS_INIT;
	ns->ln_time_latest_reset = ktime_get_real_seconds();

	rc = lfsck_load_one_trace_file(env, com, root, &com->lc_obj,
				       &dt_lfsck_namespace_features,
				       LFSCK_NAMESPACE, true);
	if (rc)
		GOTO(out, rc);

	rc = lfsck_load_sub_trace_files(env, com, &dt_lfsck_namespace_features,
					LFSCK_NAMESPACE, true);
	if (rc != 0)
		GOTO(out, rc);

	clear_bit(LAD_INCOMPLETE, &lad->lad_flags);
	CFS_RESET_BITMAP(lad->lad_bitmap);

	rc = lfsck_namespace_store(env, com);

	GOTO(out, rc);

out:
	up_write(&com->lc_sem);

put:
	lfsck_object_put(env, root);
log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK reset: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);
	return rc;
}

static void
lfsck_namespace_fail(const struct lu_env *env, struct lfsck_component *com,
		     bool new_checked)
{
	struct lfsck_namespace *ns = com->lc_file_ram;

	down_write(&com->lc_sem);
	if (new_checked)
		com->lc_new_checked++;
	lfsck_namespace_record_failure(env, com->lc_lfsck, ns);
	up_write(&com->lc_sem);
}

static void lfsck_namespace_close_dir(const struct lu_env *env,
				      struct lfsck_component *com)
{
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_assistant_object	*lso	= NULL;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_lmv		*llmv	= lfsck->li_lmv;
	struct lfsck_namespace_req	*lnr;
	struct lu_attr *la = &lfsck_env_info(env)->lti_la2;
	__u32 size = sizeof(*lnr) + LFSCK_TMPBUF_LEN;
	int rc;
	bool wakeup = false;
	ENTRY;

	if (llmv == NULL)
		RETURN_EXIT;

	rc = dt_attr_get(env, lfsck->li_obj_dir, la);
	if (rc)
		RETURN_EXIT;

	OBD_ALLOC(lnr, size);
	if (lnr == NULL) {
		ns->ln_striped_dirs_skipped++;

		RETURN_EXIT;
	}

	lso = lfsck_assistant_object_init(env, lfsck_dto2fid(lfsck->li_obj_dir),
			la, lfsck->li_pos_current.lp_oit_cookie, true);
	if (IS_ERR(lso)) {
		OBD_FREE(lnr, size);
		ns->ln_striped_dirs_skipped++;

		RETURN_EXIT;
	}

	/* Generate a dummy request to indicate that all shards' name entry
	 * in this striped directory has been scanned for the first time. */
	INIT_LIST_HEAD(&lnr->lnr_lar.lar_list);
	lnr->lnr_lar.lar_parent = lso;
	lnr->lnr_lmv = lfsck_lmv_get(llmv);
	lnr->lnr_fid = *lfsck_dto2fid(lfsck->li_obj_dir);
	lnr->lnr_dir_cookie = MDS_DIR_END_OFF;
	lnr->lnr_size = size;
	lnr->lnr_type = lso->lso_attr.la_mode;

	spin_lock(&lad->lad_lock);
	if (lad->lad_assistant_status < 0 ||
	    unlikely(!thread_is_running(&lfsck->li_thread) ||
		     !thread_is_running(&lad->lad_thread))) {
		spin_unlock(&lad->lad_lock);
		lfsck_namespace_assistant_req_fini(env, &lnr->lnr_lar);
		ns->ln_striped_dirs_skipped++;

		RETURN_EXIT;
	}

	list_add_tail(&lnr->lnr_lar.lar_list, &lad->lad_req_list);
	if (lad->lad_prefetched == 0)
		wakeup = true;

	lad->lad_prefetched++;
	spin_unlock(&lad->lad_lock);
	if (wakeup)
		wake_up(&lad->lad_thread.t_ctl_waitq);

	EXIT;
}

static int lfsck_namespace_open_dir(const struct lu_env *env,
				    struct lfsck_component *com)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_namespace	*ns	= com->lc_file_ram;
	struct lfsck_lmv	*llmv	= lfsck->li_lmv;
	int			 rc	= 0;
	ENTRY;

	if (llmv == NULL)
		RETURN(0);

	if (llmv->ll_lmv_master) {
		struct lmv_mds_md_v1 *lmv = &llmv->ll_lmv;

		if (lmv->lmv_master_mdt_index != lfsck_dev_idx(lfsck)) {
			lmv->lmv_master_mdt_index =
				lfsck_dev_idx(lfsck);
			ns->ln_flags |= LF_INCONSISTENT;
			llmv->ll_lmv_updated = 1;
		}
	} else {
		rc = lfsck_namespace_verify_stripe_slave(env, com,
					lfsck->li_obj_dir, llmv);
	}

	RETURN(rc > 0 ? 0 : rc);
}

static int lfsck_namespace_checkpoint(const struct lu_env *env,
				      struct lfsck_component *com, bool init)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_namespace	*ns    = com->lc_file_ram;
	int			 rc;

	if (!init) {
		rc = lfsck_checkpoint_generic(env, com);
		if (rc != 0)
			goto log;
	}

	down_write(&com->lc_sem);
	if (init) {
		ns->ln_pos_latest_start = lfsck->li_pos_checkpoint;
	} else {
		ns->ln_pos_last_checkpoint = lfsck->li_pos_checkpoint;
		ns->ln_run_time_phase1 += ktime_get_seconds() -
					  lfsck->li_time_last_checkpoint;
		ns->ln_time_last_checkpoint = ktime_get_real_seconds();
		ns->ln_items_checked += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_namespace_store(env, com);
	up_write(&com->lc_sem);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK checkpoint at the pos [%llu"
	       ", "DFID", %#llx], status = %d: rc = %d\n",
	       lfsck_lfsck2name(lfsck), lfsck->li_pos_current.lp_oit_cookie,
	       PFID(&lfsck->li_pos_current.lp_dir_parent),
	       lfsck->li_pos_current.lp_dir_cookie, ns->ln_status, rc);

	return rc > 0 ? 0 : rc;
}

static int lfsck_namespace_prep(const struct lu_env *env,
				struct lfsck_component *com,
				struct lfsck_start_param *lsp)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_namespace	*ns	= com->lc_file_ram;
	struct lfsck_position	*pos	= &com->lc_pos_start;
	int			 rc;

	rc = lfsck_namespace_load_bitmap(env, com);
	if (rc != 0 || ns->ln_status == LS_COMPLETED) {
		rc = lfsck_namespace_reset(env, com, false);
		if (rc == 0)
			rc = lfsck_set_param(env, lfsck, lsp->lsp_start, true);

		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: namespace LFSCK prep failed: "
			       "rc = %d\n", lfsck_lfsck2name(lfsck), rc);

			return rc;
		}
	}

	down_write(&com->lc_sem);
	ns->ln_time_latest_start = ktime_get_real_seconds();
	spin_lock(&lfsck->li_lock);

	if (ns->ln_flags & LF_SCANNED_ONCE) {
		if (!lfsck->li_drop_dryrun ||
		    lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent)) {
			ns->ln_status = LS_SCANNING_PHASE2;
			list_move_tail(&com->lc_link,
				       &lfsck->li_list_double_scan);
			if (!list_empty(&com->lc_link_dir))
				list_del_init(&com->lc_link_dir);
			lfsck_pos_set_zero(pos);
		} else {
			ns->ln_status = LS_SCANNING_PHASE1;
			ns->ln_run_time_phase1 = 0;
			ns->ln_run_time_phase2 = 0;
			ns->ln_items_checked = 0;
			ns->ln_items_repaired = 0;
			ns->ln_items_failed = 0;
			ns->ln_dirs_checked = 0;
			ns->ln_objs_checked_phase2 = 0;
			ns->ln_objs_repaired_phase2 = 0;
			ns->ln_objs_failed_phase2 = 0;
			ns->ln_objs_nlink_repaired = 0;
			ns->ln_dirent_repaired = 0;
			ns->ln_linkea_repaired = 0;
			ns->ln_mul_linked_checked = 0;
			ns->ln_mul_linked_repaired = 0;
			ns->ln_unknown_inconsistency = 0;
			ns->ln_unmatched_pairs_repaired = 0;
			ns->ln_dangling_repaired = 0;
			ns->ln_mul_ref_repaired = 0;
			ns->ln_bad_type_repaired = 0;
			ns->ln_lost_dirent_repaired = 0;
			ns->ln_striped_dirs_scanned = 0;
			ns->ln_striped_dirs_repaired = 0;
			ns->ln_striped_dirs_failed = 0;
			ns->ln_striped_dirs_disabled = 0;
			ns->ln_striped_dirs_skipped = 0;
			ns->ln_striped_shards_scanned = 0;
			ns->ln_striped_shards_repaired = 0;
			ns->ln_striped_shards_failed = 0;
			ns->ln_striped_shards_skipped = 0;
			ns->ln_name_hash_repaired = 0;
			fid_zero(&ns->ln_fid_latest_scanned_phase2);
			if (list_empty(&com->lc_link_dir))
				list_add_tail(&com->lc_link_dir,
					      &lfsck->li_list_dir);
			*pos = ns->ln_pos_first_inconsistent;
		}
	} else {
		ns->ln_status = LS_SCANNING_PHASE1;
		if (list_empty(&com->lc_link_dir))
			list_add_tail(&com->lc_link_dir,
				      &lfsck->li_list_dir);
		if (!lfsck->li_drop_dryrun ||
		    lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent)) {
			*pos = ns->ln_pos_last_checkpoint;
			pos->lp_oit_cookie++;
		} else {
			*pos = ns->ln_pos_first_inconsistent;
		}
	}

	spin_unlock(&lfsck->li_lock);
	up_write(&com->lc_sem);

	rc = lfsck_start_assistant(env, com, lsp);

	CDEBUG(D_LFSCK, "%s: namespace LFSCK prep done, start pos [%llu, "
	       DFID", %#llx]: rc = %d\n",
	       lfsck_lfsck2name(lfsck), pos->lp_oit_cookie,
	       PFID(&pos->lp_dir_parent), pos->lp_dir_cookie, rc);

	return rc;
}

static int lfsck_namespace_exec_oit(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct dt_object *obj)
{
	struct lfsck_thread_info *info = lfsck_env_info(env);
	struct lfsck_namespace *ns = com->lc_file_ram;
	struct lfsck_instance *lfsck = com->lc_lfsck;
	const struct lu_fid *fid = lfsck_dto2fid(obj);
	struct lu_fid *pfid = &info->lti_fid2;
	struct lu_name *cname = &info->lti_name;
	struct lu_seq_range *range = &info->lti_range;
	struct seq_server_site *ss = lfsck_dev_site(lfsck);
	struct linkea_data ldata = { NULL };
	__u32 idx = lfsck_dev_idx(lfsck);
	struct lu_attr la = { .la_valid = 0 };
	bool remote = false;
	int rc;
	ENTRY;

	rc = dt_attr_get(env, obj, &la);
	if (unlikely(rc || (la.la_valid & LA_FLAGS &&
			    la.la_flags & LUSTRE_ORPHAN_FL))) {
		CDEBUG(D_INFO,
		       "%s: skip orphan "DFID", %llx/%x: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(fid),
		       la.la_valid, la.la_flags, rc);

		return rc;
	}

	rc = lfsck_links_read(env, obj, &ldata);
	if (rc == -ENOENT)
		GOTO(out, rc = 0);

	/* -EINVAL means crashed linkEA, should be verified. */
	if (rc == -EINVAL) {
		rc = lfsck_namespace_trace_update(env, com, fid,
						  LNTF_CHECK_LINKEA, true);
		if (rc == 0) {
			struct lustre_handle lh	= { 0 };

			rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
					      MDS_INODELOCK_UPDATE |
					      MDS_INODELOCK_XATTR, LCK_EX);
			if (rc == 0) {
				rc = lfsck_namespace_links_remove(env, com,
								  obj);
				lfsck_ibits_unlock(&lh, LCK_EX);
			}
		}

		GOTO(out, rc = (rc == -ENOENT ? 0 : rc));
	}

	if (rc && rc != -ENODATA)
		GOTO(out, rc);

	if (rc == -ENODATA || unlikely(!ldata.ld_leh->leh_reccount)) {
		rc = lfsck_namespace_check_for_double_scan(env, com, obj);

		GOTO(out, rc);
	}

	linkea_first_entry(&ldata);
	while (ldata.ld_lee != NULL) {
		linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen,
				    cname, pfid);
		if (!fid_is_sane(pfid)) {
			rc = lfsck_namespace_trace_update(env, com, fid,
						  LNTF_CHECK_PARENT, true);
		} else if (!linkea_entry_is_valid(&ldata, cname, pfid)) {
			GOTO(out, rc);
		} else {
			fld_range_set_mdt(range);
			rc = fld_server_lookup(env, ss->ss_server_fld,
					       fid_seq(pfid), range);
			if ((rc == -ENOENT) ||
			    (!rc && range->lsr_index != idx)) {
				remote = true;
				break;
			}
		}
		if (rc)
			GOTO(out, rc);

		linkea_next_entry(&ldata);
	}

	if ((lu_object_has_agent_entry(&obj->do_lu) && !remote) ||
	    (!lu_object_has_agent_entry(&obj->do_lu) && remote)) {
		rc = lfsck_namespace_trace_update(env, com, fid,
						  LNTF_CHECK_AGENT_ENTRY, true);
		if (rc)
			GOTO(out, rc);
	}

	/* Record multiple-linked object. */
	if (ldata.ld_leh->leh_reccount > 1) {
		rc = lfsck_namespace_trace_update(env, com, fid,
						  LNTF_CHECK_LINKEA, true);

		GOTO(out, rc);
	}

	if (remote)
		rc = lfsck_namespace_trace_update(env, com, fid,
						  LNTF_CHECK_LINKEA, true);
	else
		rc = lfsck_namespace_check_for_double_scan(env, com, obj);

	GOTO(out, rc);

out:
	down_write(&com->lc_sem);
	if (S_ISDIR(lfsck_object_type(obj)))
		ns->ln_dirs_checked++;
	if (rc != 0)
		lfsck_namespace_record_failure(env, com->lc_lfsck, ns);
	up_write(&com->lc_sem);

	return rc;
}

static int lfsck_namespace_exec_dir(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct lfsck_assistant_object *lso,
				    struct lu_dirent *ent, __u16 type)
{
	struct lfsck_assistant_data	*lad	 = com->lc_data;
	struct lfsck_instance		*lfsck	 = com->lc_lfsck;
	struct lfsck_namespace_req	*lnr;
	struct lfsck_bookmark		*bk	 = &lfsck->li_bookmark_ram;
	struct ptlrpc_thread		*mthread = &lfsck->li_thread;
	struct ptlrpc_thread		*athread = &lad->lad_thread;
	bool				 wakeup	 = false;

	wait_event_idle(mthread->t_ctl_waitq,
			lad->lad_prefetched < bk->lb_async_windows ||
			!thread_is_running(mthread) ||
			!thread_is_running(athread));

	if (unlikely(!thread_is_running(mthread) ||
		     !thread_is_running(athread)))
		return 0;

	if (unlikely(lfsck_is_dead_obj(lfsck->li_obj_dir)))
		return 0;

	lnr = lfsck_namespace_assistant_req_init(com->lc_lfsck, lso, ent, type);
	if (IS_ERR(lnr)) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		lfsck_namespace_record_failure(env, com->lc_lfsck, ns);
		return PTR_ERR(lnr);
	}

	spin_lock(&lad->lad_lock);
	if (lad->lad_assistant_status < 0 ||
	    unlikely(!thread_is_running(mthread) ||
		     !thread_is_running(athread))) {
		spin_unlock(&lad->lad_lock);
		lfsck_namespace_assistant_req_fini(env, &lnr->lnr_lar);
		return lad->lad_assistant_status;
	}

	list_add_tail(&lnr->lnr_lar.lar_list, &lad->lad_req_list);
	if (lad->lad_prefetched == 0)
		wakeup = true;

	lad->lad_prefetched++;
	spin_unlock(&lad->lad_lock);
	if (wakeup)
		wake_up(&lad->lad_thread.t_ctl_waitq);

	down_write(&com->lc_sem);
	com->lc_new_checked++;
	up_write(&com->lc_sem);

	return 0;
}

static int lfsck_namespace_post(const struct lu_env *env,
				struct lfsck_component *com,
				int result, bool init)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_namespace	*ns    = com->lc_file_ram;
	int			 rc;
	ENTRY;

	lfsck_post_generic(env, com, &result);

	down_write(&com->lc_sem);
	lfsck_namespace_release_lmv(env, com);

	spin_lock(&lfsck->li_lock);
	if (!init)
		ns->ln_pos_last_checkpoint = lfsck->li_pos_checkpoint;
	if (result > 0) {
		ns->ln_status = LS_SCANNING_PHASE2;
		ns->ln_flags |= LF_SCANNED_ONCE;
		ns->ln_flags &= ~LF_UPGRADE;
		list_del_init(&com->lc_link_dir);
		list_move_tail(&com->lc_link, &lfsck->li_list_double_scan);
	} else if (result == 0) {
		if (lfsck->li_status != 0)
			ns->ln_status = lfsck->li_status;
		else
			ns->ln_status = LS_STOPPED;
		if (ns->ln_status != LS_PAUSED) {
			list_del_init(&com->lc_link_dir);
			list_move_tail(&com->lc_link, &lfsck->li_list_idle);
		}
	} else {
		ns->ln_status = LS_FAILED;
		list_del_init(&com->lc_link_dir);
		list_move_tail(&com->lc_link, &lfsck->li_list_idle);
	}
	spin_unlock(&lfsck->li_lock);

	if (!init) {
		ns->ln_run_time_phase1 += ktime_get_seconds() -
					  lfsck->li_time_last_checkpoint;
		ns->ln_time_last_checkpoint = ktime_get_real_seconds();
		ns->ln_items_checked += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_namespace_store(env, com);
	up_write(&com->lc_sem);

	CDEBUG(D_LFSCK, "%s: namespace LFSCK post done: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);

	RETURN(rc);
}

static void
lfsck_namespace_dump(const struct lu_env *env, struct lfsck_component *com,
		     struct seq_file *m)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_bookmark	*bk    = &lfsck->li_bookmark_ram;
	struct lfsck_namespace	*ns    = com->lc_file_ram;

	down_read(&com->lc_sem);
	seq_printf(m, "name: lfsck_namespace\n"
		   "magic: %#x\n"
		   "version: %d\n"
		   "status: %s\n",
		   ns->ln_magic,
		   bk->lb_version,
		   lfsck_status2name(ns->ln_status));

	lfsck_bits_dump(m, ns->ln_flags, lfsck_flags_names, "flags");

	lfsck_bits_dump(m, bk->lb_param, lfsck_param_names, "param");

	lfsck_time_dump(m, ns->ln_time_last_complete, "last_completed");

	lfsck_time_dump(m, ns->ln_time_latest_start, "latest_start");

	lfsck_time_dump(m, ns->ln_time_last_checkpoint, "last_checkpoint");

	lfsck_pos_dump(m, &ns->ln_pos_latest_start, "latest_start_position");

	lfsck_pos_dump(m, &ns->ln_pos_last_checkpoint,
		       "last_checkpoint_position");

	lfsck_pos_dump(m, &ns->ln_pos_first_inconsistent,
		       "first_failure_position");

	if (ns->ln_status == LS_SCANNING_PHASE1) {
		struct lfsck_position pos;
		time64_t duration = ktime_get_seconds() -
				    lfsck->li_time_last_checkpoint;
		u64 checked = ns->ln_items_checked + com->lc_new_checked;
		u64 speed = checked;
		u64 new_checked = com->lc_new_checked;
		time64_t rtime = ns->ln_run_time_phase1 + duration;

		if (duration != 0)
			new_checked = div64_s64(new_checked, duration);

		if (rtime != 0)
			speed = div64_s64(speed, rtime);

		lfsck_namespace_dump_statistics(m, ns, checked, 0, rtime, 0,
						bk->lb_param & LPF_DRYRUN);
		seq_printf(m, "average_speed_phase1: %llu items/sec\n"
			   "average_speed_phase2: N/A\n"
			   "average_speed_total: %llu items/sec\n"
			   "real_time_speed_phase1: %llu items/sec\n"
			   "real_time_speed_phase2: N/A\n",
			   speed,
			   speed,
			   new_checked);

		if (likely(lfsck->li_di_oit)) {
			const struct dt_it_ops *iops =
				&lfsck->li_obj_oit->do_index_ops->dio_it;

			/* The low layer otable-based iteration position may NOT
			 * exactly match the namespace-based directory traversal
			 * cookie. Generally, it is not a serious issue. But the
			 * caller should NOT make assumption on that. */
			pos.lp_oit_cookie = iops->store(env, lfsck->li_di_oit);
			if (!lfsck->li_current_oit_processed)
				pos.lp_oit_cookie--;

			spin_lock(&lfsck->li_lock);
			if (lfsck->li_di_dir) {
				pos.lp_dir_cookie = lfsck->li_cookie_dir;
				if (pos.lp_dir_cookie >= MDS_DIR_END_OFF) {
					fid_zero(&pos.lp_dir_parent);
					pos.lp_dir_cookie = 0;
				} else {
					pos.lp_dir_parent =
					*lfsck_dto2fid(lfsck->li_obj_dir);
				}
			} else {
				fid_zero(&pos.lp_dir_parent);
				pos.lp_dir_cookie = 0;
			}
			spin_unlock(&lfsck->li_lock);
		} else {
			pos = ns->ln_pos_last_checkpoint;
		}

		lfsck_pos_dump(m, &pos, "current_position");
	} else if (ns->ln_status == LS_SCANNING_PHASE2) {
		time64_t duration = ktime_get_seconds() -
				    com->lc_time_last_checkpoint;
		__u64 checked = ns->ln_objs_checked_phase2 +
				com->lc_new_checked;
		__u64 speed1 = ns->ln_items_checked;
		__u64 speed2 = checked;
		__u64 speed0 = speed1 + speed2;
		__u64 new_checked = com->lc_new_checked;
		time64_t rtime = ns->ln_run_time_phase2 + duration;
		time64_t time0 = ns->ln_run_time_phase1 + rtime;

		if (duration != 0)
			new_checked = div64_s64(new_checked, duration);

		if (ns->ln_run_time_phase1 != 0)
			speed1 = div64_s64(speed1, ns->ln_run_time_phase1);
		else if (ns->ln_items_checked != 0)
			time0++;

		if (rtime != 0)
			speed2 = div64_s64(speed2, rtime);
		else if (checked != 0)
			time0++;

		if (time0 != 0)
			speed0 = div64_s64(speed0, time0);

		lfsck_namespace_dump_statistics(m, ns, ns->ln_items_checked,
						checked,
						ns->ln_run_time_phase1, rtime,
						bk->lb_param & LPF_DRYRUN);
		seq_printf(m, "average_speed_phase1: %llu items/sec\n"
			   "average_speed_phase2: %llu objs/sec\n"
			   "average_speed_total: %llu items/sec\n"
			   "real_time_speed_phase1: N/A\n"
			   "real_time_speed_phase2: %llu objs/sec\n"
			   "current_position: "DFID"\n",
			   speed1,
			   speed2,
			   speed0,
			   new_checked,
			   PFID(&ns->ln_fid_latest_scanned_phase2));
	} else {
		__u64 speed1 = ns->ln_items_checked;
		__u64 speed2 = ns->ln_objs_checked_phase2;
		__u64 speed0 = speed1 + speed2;
		time64_t time0 = ns->ln_run_time_phase1 + ns->ln_run_time_phase2;

		if (ns->ln_run_time_phase1 != 0)
			speed1 = div64_s64(speed1, ns->ln_run_time_phase1);
		else if (ns->ln_items_checked != 0)
			time0++;

		if (ns->ln_run_time_phase2 != 0)
			speed2 = div64_s64(speed2, ns->ln_run_time_phase2);
		else if (ns->ln_objs_checked_phase2 != 0)
			time0++;

		if (time0 != 0)
			speed0 = div64_s64(speed0, time0);

		lfsck_namespace_dump_statistics(m, ns, ns->ln_items_checked,
						ns->ln_objs_checked_phase2,
						ns->ln_run_time_phase1,
						ns->ln_run_time_phase2,
						bk->lb_param & LPF_DRYRUN);
		seq_printf(m, "average_speed_phase1: %llu items/sec\n"
			   "average_speed_phase2: %llu objs/sec\n"
			   "average_speed_total: %llu items/sec\n"
			   "real_time_speed_phase1: N/A\n"
			   "real_time_speed_phase2: N/A\n"
			   "current_position: N/A\n",
			   speed1,
			   speed2,
			   speed0);
	}

	up_read(&com->lc_sem);
}

static int lfsck_namespace_double_scan(const struct lu_env *env,
				       struct lfsck_component *com)
{
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_tgt_descs		*ltds	= &com->lc_lfsck->li_mdt_descs;
	struct lfsck_tgt_desc		*ltd;
	struct lfsck_tgt_desc		*next;
	int				 rc;

	rc = lfsck_double_scan_generic(env, com, ns->ln_status);
	if (thread_is_stopped(&lad->lad_thread)) {
		LASSERT(list_empty(&lad->lad_req_list));
		LASSERT(list_empty(&lad->lad_mdt_phase1_list));

		spin_lock(&ltds->ltd_lock);
		list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase2_list,
					 ltd_namespace_phase_list) {
			list_del_init(&ltd->ltd_namespace_phase_list);
		}
		spin_unlock(&ltds->ltd_lock);
	}

	return rc;
}

static void lfsck_namespace_data_release(const struct lu_env *env,
					 struct lfsck_component *com)
{
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_tgt_descs		*ltds	= &com->lc_lfsck->li_mdt_descs;
	struct lfsck_tgt_desc		*ltd;
	struct lfsck_tgt_desc		*next;

	LASSERT(lad != NULL);
	LASSERT(thread_is_init(&lad->lad_thread) ||
		thread_is_stopped(&lad->lad_thread));
	LASSERT(list_empty(&lad->lad_req_list));

	com->lc_data = NULL;
	lfsck_namespace_release_lmv(env, com);

	spin_lock(&ltds->ltd_lock);
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase1_list,
				 ltd_namespace_phase_list) {
		list_del_init(&ltd->ltd_namespace_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase2_list,
				 ltd_namespace_phase_list) {
		list_del_init(&ltd->ltd_namespace_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_list,
				 ltd_namespace_list) {
		list_del_init(&ltd->ltd_namespace_list);
	}
	spin_unlock(&ltds->ltd_lock);

	if (likely(lad->lad_bitmap != NULL))
		CFS_FREE_BITMAP(lad->lad_bitmap);

	OBD_FREE_PTR(lad);
}

static void lfsck_namespace_quit(const struct lu_env *env,
				 struct lfsck_component *com)
{
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_tgt_descs		*ltds	= &com->lc_lfsck->li_mdt_descs;
	struct lfsck_tgt_desc		*ltd;
	struct lfsck_tgt_desc		*next;

	LASSERT(lad != NULL);

	lfsck_quit_generic(env, com);

	LASSERT(thread_is_init(&lad->lad_thread) ||
		thread_is_stopped(&lad->lad_thread));
	LASSERT(list_empty(&lad->lad_req_list));

	lfsck_namespace_release_lmv(env, com);

	spin_lock(&ltds->ltd_lock);
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase1_list,
				 ltd_namespace_phase_list) {
		list_del_init(&ltd->ltd_namespace_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase2_list,
				 ltd_namespace_phase_list) {
		list_del_init(&ltd->ltd_namespace_phase_list);
	}
	spin_unlock(&ltds->ltd_lock);
}

static int lfsck_namespace_in_notify(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct lfsck_request *lr)
{
	struct lfsck_instance *lfsck = com->lc_lfsck;
	struct lfsck_namespace *ns = com->lc_file_ram;
	struct lfsck_assistant_data *lad = com->lc_data;
	struct lfsck_tgt_descs *ltds = &lfsck->li_mdt_descs;
	struct lfsck_tgt_desc *ltd;
	int rc = 0;
	bool fail = false;
	ENTRY;

	switch (lr->lr_event) {
	case LE_SET_LMV_MASTER: {
		struct dt_object	*obj;

		obj = lfsck_object_find_bottom(env, lfsck, &lr->lr_fid);
		if (IS_ERR(obj))
			RETURN(PTR_ERR(obj));

		if (likely(dt_object_exists(obj)))
			rc = lfsck_namespace_notify_lmv_master_local(env, com,
								     obj);

		lfsck_object_put(env, obj);

		RETURN(rc > 0 ? 0 : rc);
	}
	case LE_SET_LMV_SLAVE: {
		if (!(lr->lr_flags & LEF_RECHECK_NAME_HASH))
			ns->ln_striped_shards_repaired++;

		rc = lfsck_namespace_trace_update(env, com, &lr->lr_fid,
						  LNTF_RECHECK_NAME_HASH, true);

		RETURN(rc > 0 ? 0 : rc);
	}
	case LE_PHASE1_DONE:
	case LE_PHASE2_DONE:
	case LE_PEER_EXIT:
		break;
	default:
		RETURN(-EINVAL);
	}

	CDEBUG(D_LFSCK, "%s: namespace LFSCK handles notify %u from MDT %x, "
	       "status %d, flags %x\n", lfsck_lfsck2name(lfsck), lr->lr_event,
	       lr->lr_index, lr->lr_status, lr->lr_flags2);

	spin_lock(&ltds->ltd_lock);
	ltd = lfsck_ltd2tgt(ltds, lr->lr_index);
	if (ltd == NULL) {
		spin_unlock(&ltds->ltd_lock);

		RETURN(-ENXIO);
	}

	list_del_init(&ltd->ltd_namespace_phase_list);
	switch (lr->lr_event) {
	case LE_PHASE1_DONE:
		if (lr->lr_status <= 0) {
			ltd->ltd_namespace_done = 1;
			list_del_init(&ltd->ltd_namespace_list);
			CDEBUG(D_LFSCK, "%s: MDT %x failed/stopped at "
			       "phase1 for namespace LFSCK: rc = %d.\n",
			       lfsck_lfsck2name(lfsck),
			       ltd->ltd_index, lr->lr_status);
			ns->ln_flags |= LF_INCOMPLETE;
			fail = true;
			break;
		}

		if (lr->lr_flags2 & LF_INCOMPLETE)
			ns->ln_flags |= LF_INCOMPLETE;

		if (list_empty(&ltd->ltd_namespace_list))
			list_add_tail(&ltd->ltd_namespace_list,
				      &lad->lad_mdt_list);
		list_add_tail(&ltd->ltd_namespace_phase_list,
			      &lad->lad_mdt_phase2_list);
		break;
	case LE_PHASE2_DONE:
		ltd->ltd_namespace_done = 1;
		list_del_init(&ltd->ltd_namespace_list);
		break;
	case LE_PEER_EXIT:
		fail = true;
		ltd->ltd_namespace_done = 1;
		list_del_init(&ltd->ltd_namespace_list);
		if (!(lfsck->li_bookmark_ram.lb_param & LPF_FAILOUT)) {
			CDEBUG(D_LFSCK,
			       "%s: the peer MDT %x exit namespace LFSCK\n",
			       lfsck_lfsck2name(lfsck), ltd->ltd_index);
			ns->ln_flags |= LF_INCOMPLETE;
		}
		break;
	default:
		break;
	}
	spin_unlock(&ltds->ltd_lock);

	if (fail && lfsck->li_bookmark_ram.lb_param & LPF_FAILOUT) {
		struct lfsck_stop *stop = &lfsck_env_info(env)->lti_stop;

		memset(stop, 0, sizeof(*stop));
		stop->ls_status = lr->lr_status;
		stop->ls_flags = lr->lr_param & ~LPF_BROADCAST;
		lfsck_stop(env, lfsck->li_bottom, stop);
	} else if (lfsck_phase2_next_ready(lad)) {
		wake_up(&lad->lad_thread.t_ctl_waitq);
	}

	RETURN(0);
}

static void lfsck_namespace_repaired(struct lfsck_namespace *ns, __u64 *count)
{
	*count += ns->ln_objs_nlink_repaired;
	*count += ns->ln_dirent_repaired;
	*count += ns->ln_linkea_repaired;
	*count += ns->ln_mul_linked_repaired;
	*count += ns->ln_unmatched_pairs_repaired;
	*count += ns->ln_dangling_repaired;
	*count += ns->ln_mul_ref_repaired;
	*count += ns->ln_bad_type_repaired;
	*count += ns->ln_lost_dirent_repaired;
	*count += ns->ln_striped_dirs_disabled;
	*count += ns->ln_striped_dirs_repaired;
	*count += ns->ln_striped_shards_repaired;
	*count += ns->ln_name_hash_repaired;
	*count += ns->ln_local_lpf_moved;
}

static int lfsck_namespace_query_all(const struct lu_env *env,
				     struct lfsck_component *com,
				     __u32 *mdts_count, __u64 *repaired)
{
	struct lfsck_namespace *ns = com->lc_file_ram;
	struct lfsck_tgt_descs *ltds = &com->lc_lfsck->li_mdt_descs;
	struct lfsck_tgt_desc *ltd;
	int idx;
	int rc;
	ENTRY;

	rc = lfsck_query_all(env, com);
	if (rc != 0)
		RETURN(rc);

	down_read(&ltds->ltd_rw_sem);
	cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
		ltd = lfsck_ltd2tgt(ltds, idx);
		LASSERT(ltd != NULL);

		mdts_count[ltd->ltd_namespace_status]++;
		*repaired += ltd->ltd_namespace_repaired;
	}
	up_read(&ltds->ltd_rw_sem);

	down_read(&com->lc_sem);
	mdts_count[ns->ln_status]++;
	lfsck_namespace_repaired(ns, repaired);
	up_read(&com->lc_sem);

	RETURN(0);
}

static int lfsck_namespace_query(const struct lu_env *env,
				 struct lfsck_component *com,
				 struct lfsck_request *req,
				 struct lfsck_reply *rep,
				 struct lfsck_query *que, int idx)
{
	struct lfsck_namespace *ns = com->lc_file_ram;
	int rc = 0;

	if (que != NULL) {
		LASSERT(com->lc_lfsck->li_master);

		rc = lfsck_namespace_query_all(env, com,
					       que->lu_mdts_count[idx],
					       &que->lu_repaired[idx]);
	} else {
		down_read(&com->lc_sem);
		rep->lr_status = ns->ln_status;
		if (req->lr_flags & LEF_QUERY_ALL)
			lfsck_namespace_repaired(ns, &rep->lr_repaired);
		up_read(&com->lc_sem);
	}

	return rc;
}

static const struct lfsck_operations lfsck_namespace_ops = {
	.lfsck_reset		= lfsck_namespace_reset,
	.lfsck_fail		= lfsck_namespace_fail,
	.lfsck_close_dir	= lfsck_namespace_close_dir,
	.lfsck_open_dir		= lfsck_namespace_open_dir,
	.lfsck_checkpoint	= lfsck_namespace_checkpoint,
	.lfsck_prep		= lfsck_namespace_prep,
	.lfsck_exec_oit		= lfsck_namespace_exec_oit,
	.lfsck_exec_dir		= lfsck_namespace_exec_dir,
	.lfsck_post		= lfsck_namespace_post,
	.lfsck_dump		= lfsck_namespace_dump,
	.lfsck_double_scan	= lfsck_namespace_double_scan,
	.lfsck_data_release	= lfsck_namespace_data_release,
	.lfsck_quit		= lfsck_namespace_quit,
	.lfsck_in_notify	= lfsck_namespace_in_notify,
	.lfsck_query		= lfsck_namespace_query,
};

/**
 * Repair dangling name entry.
 *
 * For the name entry with dangling reference, we need to repare the
 * inconsistency according to the LFSCK sponsor's requirement:
 *
 * 1) Keep the inconsistency there and report the inconsistency case,
 *    then give the chance to the application to find related issues,
 *    and the users can make the decision about how to handle it with
 *    more human knownledge. (by default)
 *
 * 2) Re-create the missing MDT-object with the FID information.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] parent	pointer to the dir object that contains the dangling
 *			name entry
 * \param[in] child	pointer to the object corresponding to the dangling
 *			name entry
 * \param[in] lnr	pointer to the namespace request that contains the
 *			name's name, parent object, parent's LMV, and ect.
 *
 * \retval		positive number if no need to repair
 * \retval		zero for repaired successfully
 * \retval		negative error number on failure
 */
int lfsck_namespace_repair_dangling(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct dt_object *parent,
				    struct dt_object *child,
				    struct lfsck_namespace_req *lnr)
{
	struct lfsck_thread_info *info = lfsck_env_info(env);
	struct lu_attr *la = &info->lti_la;
	struct dt_allocation_hint *hint = &info->lti_hint;
	struct dt_object_format *dof = &info->lti_dof;
	struct dt_insert_rec *rec = &info->lti_dt_rec;
	struct lmv_mds_md_v1 *lmv2 = &info->lti_lmv2;
	const struct lu_name *cname;
	const struct lu_fid *pfid = lfsck_dto2fid(parent);
	const struct lu_fid *cfid = lfsck_dto2fid(child);
	struct linkea_data ldata = { NULL };
	struct lfsck_lock_handle *llh = &info->lti_llh;
	struct lustre_handle rlh = { 0 };
	struct lustre_handle clh = { 0 };
	struct lu_buf linkea_buf;
	struct lu_buf lmv_buf;
	struct lfsck_instance *lfsck = com->lc_lfsck;
	struct lfsck_bookmark *bk = &lfsck->li_bookmark_ram;
	struct dt_device *dev = lfsck->li_next;
	struct thandle *th = NULL;
	int rc = 0;
	__u16 type = lnr->lnr_type;
	bool create;
	ENTRY;

	cname = lfsck_name_get_const(env, lnr->lnr_name, lnr->lnr_namelen);
	if (bk->lb_param & LPF_CREATE_MDTOBJ)
		create = true;
	else
		create = false;

	if (!create || bk->lb_param & LPF_DRYRUN)
		GOTO(log, rc = 0);

	/* We may need to create the sub-objects of the @child via LOD,
	 * so make the modification based on lfsck->li_next. */

	parent = lfsck_object_locate(dev, parent);
	if (IS_ERR(parent))
		GOTO(log, rc = PTR_ERR(parent));

	if (unlikely(!dt_try_as_dir(env, parent)))
		GOTO(log, rc = -ENOTDIR);

	child = lfsck_object_locate(dev, child);
	if (IS_ERR(child))
		GOTO(log, rc = PTR_ERR(child));

	rc = linkea_links_new(&ldata, &info->lti_linkea_buf2,
			      cname, pfid);
	if (rc != 0)
		GOTO(log, rc);

	rc = lfsck_lock(env, lfsck, parent, lnr->lnr_name, llh,
			MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		GOTO(log, rc);

	rc = lfsck_namespace_check_exist(env, parent, child, lnr->lnr_name);
	if (rc != 0)
		GOTO(log, rc);

	if (dt_object_remote(child)) {
		rc = lfsck_remote_lookup_lock(env, lfsck, parent, child, &rlh,
					      LCK_EX);
		if (rc != 0)
			GOTO(log, rc);
	}

	rc = lfsck_ibits_lock(env, lfsck, child, &clh,
			      MDS_INODELOCK_UPDATE | MDS_INODELOCK_LOOKUP |
			      MDS_INODELOCK_XATTR, LCK_EX);
	if (rc != 0)
		GOTO(unlock_remote_lookup, rc);

	/* Set the ctime as zero, then others can know it is created for
	 * repairing dangling name entry by LFSCK. And if the LFSCK made
	 * wrong decision and the real MDT-object has been found later,
	 * then the LFSCK has chance to fix the incosistency properly. */
	memset(la, 0, sizeof(*la));
	if (S_ISDIR(type))
		la->la_mode = (type & S_IFMT) | 0700;
	else
		la->la_mode = (type & S_IFMT) | 0600;
	la->la_valid = LA_TYPE | LA_MODE | LA_CTIME;

	/*
	 * if it's directory, skip do_ah_init() to create a plain directory
	 * because it may have shards already, which will be inserted back
	 * later, besides, it may be remote, and creating stripe directory
	 * remotely is not supported.
	 */
	if (S_ISREG(type))
		child->do_ops->do_ah_init(env, hint,  parent, child, type);
	else if (S_ISDIR(type))
		child->do_ops->do_ah_init(env, hint,  NULL, child, type);

	memset(dof, 0, sizeof(*dof));
	dof->dof_type = dt_mode_to_dft(type);
	/* If the target is a regular file, then the LFSCK will only create
	 * the MDT-object without stripes (dof->dof_reg.striped = 0). related
	 * OST-objects will be created when write open. */

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock_child, rc = PTR_ERR(th));

	/* 1a. create child. */
	rc = dt_declare_create(env, child, la, hint, dof, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (S_ISDIR(type)) {
		if (unlikely(!dt_try_as_dir(env, child)))
			GOTO(stop, rc = -ENOTDIR);

		/* 2a. increase child nlink */
		rc = dt_declare_ref_add(env, child, th);
		if (rc != 0)
			GOTO(stop, rc);

		/* 3a. insert dot into child dir */
		rec->rec_type = S_IFDIR;
		rec->rec_fid = cfid;
		rc = dt_declare_insert(env, child,
				       (const struct dt_rec *)rec,
				       (const struct dt_key *)dot, th);
		if (rc != 0)
			GOTO(stop, rc);

		/* 4a. insert dotdot into child dir */
		rec->rec_fid = pfid;
		rc = dt_declare_insert(env, child,
				       (const struct dt_rec *)rec,
				       (const struct dt_key *)dotdot, th);
		if (rc != 0)
			GOTO(stop, rc);

		/* 5a. generate slave LMV EA. */
		if (lnr->lnr_lmv != NULL && lnr->lnr_lmv->ll_lmv_master) {
			int idx;

			idx = lfsck_shard_name_to_index(env,
					lnr->lnr_name, lnr->lnr_namelen,
					type, cfid);
			if (unlikely(idx < 0))
				GOTO(stop, rc = idx);

			*lmv2 = lnr->lnr_lmv->ll_lmv;
			lmv2->lmv_magic = LMV_MAGIC_STRIPE;
			lmv2->lmv_master_mdt_index = idx;

			lfsck_lmv_header_cpu_to_le(lmv2, lmv2);
			lfsck_buf_init(&lmv_buf, lmv2, sizeof(*lmv2));
			rc = dt_declare_xattr_set(env, child, &lmv_buf,
						  XATTR_NAME_LMV, 0, th);
			if (rc != 0)
				GOTO(stop, rc);
		}
	}

	/* 6a. insert linkEA for child */
	lfsck_buf_init(&linkea_buf, ldata.ld_buf->lb_buf,
		       ldata.ld_leh->leh_len);
	rc = dt_declare_xattr_set(env, child, &linkea_buf,
				  XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 7a. if child is remote, delete and insert to generate local agent */
	if (dt_object_remote(child)) {
		rc = dt_declare_delete(env, parent,
				       (const struct dt_key *)lnr->lnr_name,
				       th);
		if (rc)
			GOTO(stop, rc);

		rc = dt_declare_insert(env, parent, (const struct dt_rec *)rec,
				       (const struct dt_key *)lnr->lnr_name,
				       th);
		if (rc)
			GOTO(stop, rc);
	}

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc = (rc == -EEXIST ? 1 : rc));

	dt_write_lock(env, child, 0);
	/* 1b. create child */
	rc = dt_create(env, child, la, hint, dof, th);
	if (rc != 0)
		GOTO(unlock, rc = (rc == -EEXIST ? 1 : rc));

	if (S_ISDIR(type)) {
		/* 2b. increase child nlink */
		rc = dt_ref_add(env, child, th);
		if (rc != 0)
			GOTO(unlock, rc);

		/* 3b. insert dot into child dir */
		rec->rec_type = S_IFDIR;
		rec->rec_fid = cfid;
		rc = dt_insert(env, child, (const struct dt_rec *)rec,
			       (const struct dt_key *)dot, th);
		if (rc != 0)
			GOTO(unlock, rc);

		/* 4b. insert dotdot into child dir */
		rec->rec_fid = pfid;
		rc = dt_insert(env, child, (const struct dt_rec *)rec,
			       (const struct dt_key *)dotdot, th);
		if (rc != 0)
			GOTO(unlock, rc);

		/* 5b. generate slave LMV EA. */
		if (lnr->lnr_lmv != NULL && lnr->lnr_lmv->ll_lmv_master) {
			rc = dt_xattr_set(env, child, &lmv_buf, XATTR_NAME_LMV,
					  0, th);
			if (rc != 0)
				GOTO(unlock, rc);
		}
	}

	/* 6b. insert linkEA for child. */
	rc = dt_xattr_set(env, child, &linkea_buf,
			  XATTR_NAME_LINK, 0, th);
	if (rc)
		GOTO(unlock, rc);

	/* 7b. if child is remote, delete and insert to generate local agent */
	if (dt_object_remote(child)) {
		rc = dt_delete(env, parent,
			       (const struct dt_key *)lnr->lnr_name, th);
		if (rc)
			GOTO(unlock, rc);

		rec->rec_type = type;
		rec->rec_fid = cfid;
		rc = dt_insert(env, parent, (const struct dt_rec *)rec,
			       (const struct dt_key *)lnr->lnr_name, th);
		if (rc)
			GOTO(unlock, rc);
	}

	GOTO(unlock, rc);

unlock:
	dt_write_unlock(env, child);

stop:
	dt_trans_stop(env, dev, th);

unlock_child:
	lfsck_ibits_unlock(&clh, LCK_EX);
unlock_remote_lookup:
	if (dt_object_remote(child))
		lfsck_ibits_unlock(&rlh, LCK_EX);
log:
	lfsck_unlock(llh);
	CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant found dangling "
	       "reference for: parent "DFID", child "DFID", type %u, "
	       "name %s. %s: rc = %d\n", lfsck_lfsck2name(lfsck),
	       PFID(pfid), PFID(cfid), type, cname->ln_name,
	       create ? "Create the lost MDT-object as required" :
			"Keep the MDT-object there by default", rc);

	if (rc <= 0) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		ns->ln_flags |= LF_INCONSISTENT;
	}

	return rc;
}

static int lfsck_namespace_assistant_handler_p1(const struct lu_env *env,
						struct lfsck_component *com,
						struct lfsck_assistant_req *lar)
{
	struct lfsck_thread_info   *info     = lfsck_env_info(env);
	struct lu_attr		   *la	     = &info->lti_la;
	struct lfsck_instance	   *lfsck    = com->lc_lfsck;
	struct lfsck_bookmark	   *bk	     = &lfsck->li_bookmark_ram;
	struct lfsck_namespace	   *ns	     = com->lc_file_ram;
	struct lfsck_assistant_data *lad     = com->lc_data;
	struct linkea_data	    ldata    = { NULL };
	const struct lu_name	   *cname;
	struct thandle		   *handle   = NULL;
	struct lfsck_namespace_req *lnr      =
		container_of(lar, struct lfsck_namespace_req, lnr_lar);
	struct dt_object	   *dir      = NULL;
	struct dt_object	   *obj      = NULL;
	struct lfsck_assistant_object *lso   = lar->lar_parent;
	const struct lu_fid	   *pfid     = &lso->lso_fid;
	struct dt_device	   *dev      = NULL;
	struct lustre_handle	    lh       = { 0 };
	bool			    repaired = false;
	bool			    dtlocked = false;
	bool			    remove = false;
	bool			    newdata = false;
	bool			    log      = false;
	bool			    bad_hash = false;
	bool			    bad_linkea = false;
	int			    idx      = 0;
	int			    count    = 0;
	int			    rc	     = 0;
	enum lfsck_namespace_inconsistency_type type = LNIT_NONE;
	ENTRY;

	if (lso->lso_dead)
		RETURN(0);

	la->la_nlink = 0;
	if (lnr->lnr_attr & LUDA_UPGRADE) {
		ns->ln_flags |= LF_UPGRADE;
		ns->ln_dirent_repaired++;
		repaired = true;
	} else if (lnr->lnr_attr & LUDA_REPAIR) {
		ns->ln_flags |= LF_INCONSISTENT;
		ns->ln_dirent_repaired++;
		repaired = true;
	}

	if (unlikely(fid_is_zero(&lnr->lnr_fid) &&
		     strcmp(lnr->lnr_name, dotdot) == 0)) {
		rc = lfsck_namespace_trace_update(env, com, pfid,
						LNTF_CHECK_PARENT, true);

		GOTO(out, rc);
	}

	if (unlikely(!fid_is_sane(&lnr->lnr_fid))) {
		CDEBUG(D_LFSCK, "%s: dir scan find invalid FID "DFID
		       " for the name entry %.*s under "DFID"\n",
		       lfsck_lfsck2name(lfsck), PFID(&lnr->lnr_fid),
		       lnr->lnr_namelen, lnr->lnr_name, PFID(pfid));

		if (strcmp(lnr->lnr_name, dotdot) != 0)
			/* invalid FID means bad name entry, remove it. */
			type = LNIT_BAD_DIRENT;
		else
			/* If the parent FID is invalid, we cannot remove
			 * the ".." entry directly. */
			rc = lfsck_namespace_trace_update(env, com, pfid,
						LNTF_CHECK_PARENT, true);

		GOTO(out, rc);
	}

	if (unlikely(lnr->lnr_dir_cookie == MDS_DIR_END_OFF)) {
		rc = lfsck_namespace_striped_dir_rescan(env, com, lnr);

		RETURN(rc);
	}

	if (fid_seq_is_dot(fid_seq(&lnr->lnr_fid)))
		GOTO(out, rc = 0);

	if (lnr->lnr_lmv != NULL && lnr->lnr_lmv->ll_lmv_master) {
		rc = lfsck_namespace_handle_striped_master(env, com, lnr);

		RETURN(rc);
	}

	idx = lfsck_find_mdt_idx_by_fid(env, lfsck, &lnr->lnr_fid);
	if (idx < 0)
		GOTO(out, rc = idx);

	if (idx == lfsck_dev_idx(lfsck)) {
		if (unlikely(strcmp(lnr->lnr_name, dotdot) == 0))
			GOTO(out, rc = 0);

		dev = lfsck->li_bottom;
	} else {
		struct lfsck_tgt_desc *ltd;

		/* Usually, some local filesystem consistency verification
		 * tools can guarantee the local namespace tree consistenct.
		 * So the LFSCK will only verify the remote directory. */
		if (unlikely(strcmp(lnr->lnr_name, dotdot) == 0)) {
			rc = lfsck_namespace_trace_update(env, com, pfid,
						LNTF_CHECK_PARENT, true);

			GOTO(out, rc);
		}

		ltd = lfsck_ltd2tgt(&lfsck->li_mdt_descs, idx);
		if (unlikely(ltd == NULL)) {
			CDEBUG(D_LFSCK, "%s: cannot talk with MDT %x which "
			       "did not join the namespace LFSCK\n",
			       lfsck_lfsck2name(lfsck), idx);
			lfsck_lad_set_bitmap(env, com, idx);

			GOTO(out, rc = -ENODEV);
		}

		dev = ltd->ltd_tgt;
	}

	obj = lfsck_object_find_by_dev(env, dev, &lnr->lnr_fid);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	cname = lfsck_name_get_const(env, lnr->lnr_name, lnr->lnr_namelen);
	if (dt_object_exists(obj) == 0) {

dangling:
		if (dir == NULL) {
			dir = lfsck_assistant_object_load(env, lfsck, lso);
			if (IS_ERR(dir)) {
				rc = PTR_ERR(dir);

				GOTO(trace, rc == -ENOENT ? 0 : rc);
			}
		}

		rc = lfsck_namespace_check_exist(env, dir, obj, lnr->lnr_name);
		if (rc == 0) {
			if (!lfsck_is_valid_slave_name_entry(env, lnr->lnr_lmv,
					lnr->lnr_name, lnr->lnr_namelen)) {
				type = LNIT_BAD_DIRENT;

				GOTO(out, rc);
			}

			type = LNIT_DANGLING;
			rc = lfsck_namespace_repair_dangling(env, com, dir,
							     obj, lnr);
			if (rc == 0)
				repaired = true;
		}

		GOTO(out, rc);
	}

	if (!(bk->lb_param & LPF_DRYRUN) && lad->lad_advance_lock) {

again:
		rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
				      MDS_INODELOCK_UPDATE |
				      MDS_INODELOCK_XATTR, LCK_EX);
		if (rc != 0)
			GOTO(out, rc);

		handle = dt_trans_create(env, dev);
		if (IS_ERR(handle))
			GOTO(out, rc = PTR_ERR(handle));

		rc = lfsck_declare_namespace_exec_dir(env, obj, handle);
		if (rc != 0)
			GOTO(stop, rc);

		rc = dt_trans_start_local(env, dev, handle);
		if (rc != 0)
			GOTO(stop, rc);

		dt_write_lock(env, obj, 0);
		dtlocked = true;
	}

	rc = lfsck_links_read(env, obj, &ldata);
	if (unlikely(rc == -ENOENT)) {
		if (handle != NULL) {
			dt_write_unlock(env, obj);
			dtlocked = false;

			dt_trans_stop(env, dev, handle);
			handle = NULL;

			lfsck_ibits_unlock(&lh, LCK_EX);
		}

		/* It may happen when the remote object has been removed,
		 * but the local MDT is not aware of that. */
		goto dangling;
	} else if (rc == 0) {
		count = ldata.ld_leh->leh_reccount;
		rc = linkea_links_find(&ldata, cname, pfid);
		if ((rc == 0) &&
		    (count == 1 || !S_ISDIR(lfsck_object_type(obj)))) {
			if ((lfsck_object_type(obj) & S_IFMT) !=
			    lnr->lnr_type) {
				ns->ln_flags |= LF_INCONSISTENT;
				type = LNIT_BAD_TYPE;
			}

			goto stop;
		}

		/* If the name entry hash does not match the slave striped
		 * directory, and the name entry does not match also, then
		 * it is quite possible that name entry is corrupted. */
		if (!lfsck_is_valid_slave_name_entry(env, lnr->lnr_lmv,
					lnr->lnr_name, lnr->lnr_namelen)) {
			ns->ln_flags |= LF_INCONSISTENT;
			type = LNIT_BAD_DIRENT;

			GOTO(stop, rc = 0);
		}

		/* If the file type stored in the name entry does not match
		 * the file type claimed by the object, and the object does
		 * not recognize the name entry, then it is quite possible
		 * that the name entry is corrupted. */
		if ((lfsck_object_type(obj) & S_IFMT) != lnr->lnr_type) {
			ns->ln_flags |= LF_INCONSISTENT;
			type = LNIT_BAD_DIRENT;

			GOTO(stop, rc = 0);
		}

		/* For sub-dir object, we cannot make sure whether the sub-dir
		 * back references the parent via ".." name entry correctly or
		 * not in the LFSCK first-stage scanning. It may be that the
		 * (remote) sub-dir ".." name entry has no parent FID after
		 * file-level backup/restore and its linkEA may be wrong.
		 * So under such case, we should replace the linkEA according
		 * to current name entry. But this needs to be done during the
		 * LFSCK second-stage scanning. The LFSCK will record the name
		 * entry for further possible using. */
		remove = false;
		newdata = false;
		goto nodata;
	} else if (unlikely(rc == -EINVAL)) {
		if ((lfsck_object_type(obj) & S_IFMT) != lnr->lnr_type)
			type = LNIT_BAD_TYPE;

		count = 1;
		/* The magic crashed, we are not sure whether there are more
		 * corrupt data in the linkea, so remove all linkea entries. */
		remove = true;
		newdata = true;
		goto nodata;
	} else if (rc == -ENODATA) {
		if ((lfsck_object_type(obj) & S_IFMT) != lnr->lnr_type)
			type = LNIT_BAD_TYPE;

		count = 1;
		remove = false;
		newdata = true;

nodata:
		if (bk->lb_param & LPF_DRYRUN) {
			if (rc == -ENODATA)
				ns->ln_flags |= LF_UPGRADE;
			else
				ns->ln_flags |= LF_INCONSISTENT;
			ns->ln_linkea_repaired++;
			repaired = true;
			log = true;
			goto stop;
		}

		if (!lustre_handle_is_used(&lh)) {
			remove = false;
			newdata = false;
			type = LNIT_NONE;

			goto again;
		}

		LASSERT(handle != NULL);

		if (dir == NULL) {
			dir = lfsck_assistant_object_load(env, lfsck, lso);
			if (IS_ERR(dir)) {
				rc = PTR_ERR(dir);

				GOTO(stop, rc == -ENOENT ? 0 : rc);
			}
		}

		rc = lfsck_namespace_check_exist(env, dir, obj, lnr->lnr_name);
		if (rc != 0)
			GOTO(stop, rc);

		bad_linkea = true;
		if (!remove && newdata)
			ns->ln_flags |= LF_UPGRADE;
		else if (remove || !(ns->ln_flags & LF_UPGRADE))
			ns->ln_flags |= LF_INCONSISTENT;

		if (remove) {
			LASSERT(newdata);

			rc = dt_xattr_del(env, obj, XATTR_NAME_LINK, handle);
			if (rc != 0 && rc != -ENOENT && rc != -ENODATA)
				GOTO(stop, rc);
		}

		if (newdata) {
			rc = linkea_data_new(&ldata,
					&lfsck_env_info(env)->lti_linkea_buf);
			if (rc != 0)
				GOTO(stop, rc);
		}

		rc = linkea_add_buf(&ldata, cname, pfid);
		if (rc == 0)
			rc = lfsck_links_write(env, obj, &ldata, handle);
		if (rc != 0)
			GOTO(stop, rc);

		count = ldata.ld_leh->leh_reccount;
		if (!S_ISDIR(lfsck_object_type(obj)) ||
		    !dt_object_remote(obj)) {
			ns->ln_linkea_repaired++;
			repaired = true;
			log = true;
		}
	} else {
		GOTO(stop, rc);
	}

stop:
	if (dtlocked)
		dt_write_unlock(env, obj);

	if (handle != NULL && !IS_ERR(handle))
		dt_trans_stop(env, dev, handle);

out:
	lfsck_ibits_unlock(&lh, LCK_EX);

	if (!name_is_dot_or_dotdot(lnr->lnr_name, lnr->lnr_namelen) &&
	    !lfsck_is_valid_slave_name_entry(env, lnr->lnr_lmv,
					     lnr->lnr_name, lnr->lnr_namelen) &&
	    type != LNIT_BAD_DIRENT) {
		ns->ln_flags |= LF_INCONSISTENT;

		log = false;
		if (dir == NULL) {
			dir = lfsck_assistant_object_load(env, lfsck, lso);
			if (IS_ERR(dir)) {
				rc = PTR_ERR(dir);

				GOTO(trace, rc == -ENOENT ? 0 : rc);
			}
		}

		rc = lfsck_namespace_repair_bad_name_hash(env, com, dir,
						lnr->lnr_lmv, lnr->lnr_name);
		if (rc == 0)
			bad_hash = true;
	}

	if (rc >= 0) {
		if (type != LNIT_NONE && dir == NULL) {
			dir = lfsck_assistant_object_load(env, lfsck, lso);
			if (IS_ERR(dir)) {
				rc = PTR_ERR(dir);

				GOTO(trace, rc == -ENOENT ? 0 : rc);
			}
		}

		switch (type) {
		case LNIT_BAD_TYPE:
			log = false;
			rc = lfsck_namespace_repair_dirent(env, com, dir,
					obj, lnr->lnr_name, lnr->lnr_name,
					lnr->lnr_type, true, false);
			if (rc > 0)
				repaired = true;
			break;
		case LNIT_BAD_DIRENT:
			log = false;
			/* XXX: This is a bad dirent, we do not know whether
			 *	the original name entry reference a regular
			 *	file or a directory, then keep the parent's
			 *	nlink count unchanged here. */
			rc = lfsck_namespace_repair_dirent(env, com, dir,
					obj, lnr->lnr_name, lnr->lnr_name,
					lnr->lnr_type, false, false);
			if (rc > 0)
				repaired = true;
			break;
		default:
			break;
		}

		if (obj != NULL && count == 1 &&
		    S_ISREG(lfsck_object_type(obj)))
			dt_attr_get(env, obj, la);

		/* if new linkea entry is added, the old entry may be stale,
		 * check it in phase 2. Sigh, linkea check can only be done
		 * locally.
		 */
		if (bad_linkea && !remove && !newdata &&
		    !dt_object_remote(obj) && count > 1)
			rc = lfsck_namespace_trace_update(env, com,
							  &lnr->lnr_fid,
							  LNTF_CHECK_LINKEA,
							  true);
	}

trace:
	down_write(&com->lc_sem);
	if (rc < 0) {
		CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant fail to handle "
		       "the entry: "DFID", parent "DFID", name %.*s: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(&lnr->lnr_fid), PFID(pfid),
		       lnr->lnr_namelen, lnr->lnr_name, rc);

		lfsck_namespace_record_failure(env, lfsck, ns);
		if ((rc == -ENOTCONN || rc == -ESHUTDOWN || rc == -EREMCHG ||
		     rc == -ETIMEDOUT || rc == -EHOSTDOWN ||
		     rc == -EHOSTUNREACH || rc == -EINPROGRESS) &&
		    dev != NULL && dev != lfsck->li_bottom)
			lfsck_lad_set_bitmap(env, com, idx);

		if (!(bk->lb_param & LPF_FAILOUT))
			rc = 0;
	} else {
		if (repaired) {
			ns->ln_items_repaired++;
			if (log)
				CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant "
				       "repaired the entry: "DFID", parent "DFID
				       ", name %.*s, type %d\n",
				       lfsck_lfsck2name(lfsck),
				       PFID(&lnr->lnr_fid), PFID(pfid),
				       lnr->lnr_namelen, lnr->lnr_name, type);

			switch (type) {
			case LNIT_DANGLING:
				ns->ln_dangling_repaired++;
				break;
			case LNIT_BAD_TYPE:
				ns->ln_bad_type_repaired++;
				break;
			case LNIT_BAD_DIRENT:
				ns->ln_dirent_repaired++;
				break;
			default:
				break;
			}

			if (bk->lb_param & LPF_DRYRUN &&
			    lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent))
				lfsck_pos_fill(env, lfsck,
					       &ns->ln_pos_first_inconsistent,
					       false);
		}

		if (bad_hash) {
			ns->ln_name_hash_repaired++;

			/* Not count repeatedly. */
			if (!repaired) {
				ns->ln_items_repaired++;
				if (log)
					CDEBUG(D_LFSCK, "%s: namespace LFSCK "
					       "assistant repaired the entry: "
					       DFID", parent "DFID
					       ", name %.*s\n",
					       lfsck_lfsck2name(lfsck),
					       PFID(&lnr->lnr_fid), PFID(pfid),
					       lnr->lnr_namelen, lnr->lnr_name);
			}

			if (bk->lb_param & LPF_DRYRUN &&
			    lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent))
				lfsck_pos_fill(env, lfsck,
					       &ns->ln_pos_first_inconsistent,
					       false);
		}

		rc = 0;
	}

	if (count > 1 || la->la_nlink > 1)
		ns->ln_mul_linked_checked++;

	up_write(&com->lc_sem);

	if (obj != NULL && !IS_ERR(obj))
		lfsck_object_put(env, obj);

	if (dir != NULL && !IS_ERR(dir))
		lfsck_object_put(env, dir);

	lad->lad_advance_lock = bad_linkea;

	return rc;
}

/**
 * Handle one orphan under the backend /lost+found directory
 *
 * Insert the orphan FID into the namespace LFSCK trace file for further
 * processing (via the subsequent namespace LFSCK second-stage scanning).
 * At the same time, remove the orphan name entry from backend /lost+found
 * directory. There is an interval between the orphan name entry removed
 * from the backend /lost+found directory and the orphan FID in the LFSCK
 * trace file handled. In such interval, the LFSCK can be reset, then
 * all the FIDs recorded in the namespace LFSCK trace file will be dropped.
 * To guarantee that the orphans can be found when LFSCK run next time
 * without e2fsck again, when remove the orphan name entry, the LFSCK
 * will set the orphan's ctime attribute as 1. Since normal applications
 * cannot change the object's ctime attribute as 1. Then when LFSCK run
 * next time, it can record the object (that ctime is 1) in the namespace
 * LFSCK trace file during the first-stage scanning.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] parent	pointer to the object for the backend /lost+found
 * \param[in] ent	pointer to the name entry for the target under the
 *			backend /lost+found
 *
 * \retval		positive for repaired
 * \retval		0 if needs to repair nothing
 * \retval		negative error number on failure
 */
static int lfsck_namespace_scan_local_lpf_one(const struct lu_env *env,
					      struct lfsck_component *com,
					      struct dt_object *parent,
					      struct lu_dirent *ent)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_fid			*key	= &info->lti_fid;
	struct lu_attr			*la	= &info->lti_la;
	struct lfsck_instance		*lfsck  = com->lc_lfsck;
	struct dt_object		*obj;
	struct dt_device		*dev	= lfsck->li_bottom;
	struct dt_object		*child	= NULL;
	struct thandle			*th	= NULL;
	int				 idx;
	int				 rc	= 0;
	__u8				 flags	= 0;
	bool				 exist	= false;
	ENTRY;

	child = lfsck_object_find_by_dev(env, dev, &ent->lde_fid);
	if (IS_ERR(child))
		RETURN(PTR_ERR(child));

	LASSERT(dt_object_exists(child));
	LASSERT(!dt_object_remote(child));

	idx = lfsck_sub_trace_file_fid2idx(&ent->lde_fid);
	obj = com->lc_sub_trace_objs[idx].lsto_obj;
	fid_cpu_to_be(key, &ent->lde_fid);
	rc = dt_lookup(env, obj, (struct dt_rec *)&flags,
		       (const struct dt_key *)key);
	if (rc == 0) {
		exist = true;
		flags |= LNTF_CHECK_ORPHAN;
	} else if (rc == -ENOENT) {
		flags = LNTF_CHECK_ORPHAN;
	} else {
		GOTO(out, rc);
	}

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	/* a1. remove name entry from backend /lost+found */
	rc = dt_declare_delete(env, parent,
			       (const struct dt_key *)ent->lde_name, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (S_ISDIR(lfsck_object_type(child))) {
		/* a2. decrease parent's nlink */
		rc = dt_declare_ref_del(env, parent, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	if (exist) {
		/* a3. remove child's FID from the LFSCK trace file. */
		rc = dt_declare_delete(env, obj,
				       (const struct dt_key *)key, th);
		if (rc != 0)
			GOTO(stop, rc);
	} else {
		/* a4. set child's ctime as 1 */
		memset(la, 0, sizeof(*la));
		la->la_ctime = 1;
		la->la_valid = LA_CTIME;
		rc = dt_declare_attr_set(env, child, la, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	/* a5. insert child's FID into the LFSCK trace file. */
	rc = dt_declare_insert(env, obj, (const struct dt_rec *)&flags,
			       (const struct dt_key *)key, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* b1. remove name entry from backend /lost+found */
	rc = dt_delete(env, parent, (const struct dt_key *)ent->lde_name, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (S_ISDIR(lfsck_object_type(child))) {
		/* b2. decrease parent's nlink */
		dt_write_lock(env, parent, 0);
		rc = dt_ref_del(env, parent, th);
		dt_write_unlock(env, parent);
		if (rc != 0)
			GOTO(stop, rc);
	}

	if (exist) {
		/* a3. remove child's FID from the LFSCK trace file. */
		rc = dt_delete(env, obj, (const struct dt_key *)key, th);
		if (rc != 0)
			GOTO(stop, rc);
	} else {
		/* b4. set child's ctime as 1 */
		rc = dt_attr_set(env, child, la, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	/* b5. insert child's FID into the LFSCK trace file. */
	rc = dt_insert(env, obj, (const struct dt_rec *)&flags,
		       (const struct dt_key *)key, th);

	GOTO(stop, rc = (rc == 0 ? 1 : rc));

stop:
	dt_trans_stop(env, dev, th);

out:
	lfsck_object_put(env, child);

	return rc;
}

/**
 * Handle orphans under the backend /lost+found directory
 *
 * Some backend checker, such as e2fsck for ldiskfs may find some orphans
 * and put them under the backend /lost+found directory that is invisible
 * to client. The LFSCK will scan such directory, for the original client
 * visible orphans, add their fids into the namespace LFSCK trace file,
 * then the subsenquent namespace LFSCK second-stage scanning can handle
 * them as other objects to be double scanned: either move back to normal
 * namespace, or to the global visible orphan directory:
 * /ROOT/.lustre/lost+found/MDTxxxx/
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 */
static void lfsck_namespace_scan_local_lpf(const struct lu_env *env,
					   struct lfsck_component *com)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_dirent		*ent	=
					(struct lu_dirent *)info->lti_key;
	struct lu_seq_range		*range	= &info->lti_range;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct ptlrpc_thread		*thread = &lfsck->li_thread;
	struct lfsck_bookmark		*bk	= &lfsck->li_bookmark_ram;
	struct lfsck_namespace		*ns	= com->lc_file_ram;
	struct dt_object		*parent;
	const struct dt_it_ops		*iops;
	struct dt_it			*di;
	struct seq_server_site		*ss	= lfsck_dev_site(lfsck);
	__u64				 cookie;
	__u32				 idx	= lfsck_dev_idx(lfsck);
	int				 rc	= 0;
	__u16				 type;
	ENTRY;

	parent = lfsck_object_find_by_dev(env, lfsck->li_bottom,
					  &LU_BACKEND_LPF_FID);
	if (IS_ERR(parent)) {
		CERROR("%s: fail to find backend /lost+found: rc = %ld\n",
		       lfsck_lfsck2name(lfsck), PTR_ERR(parent));
		RETURN_EXIT;
	}

	/* It is normal that the /lost+found does not exist for ZFS backend. */
	if (!dt_object_exists(parent))
		GOTO(out, rc = 0);

	if (unlikely(!dt_try_as_dir(env, parent)))
		GOTO(out, rc = -ENOTDIR);

	CDEBUG(D_LFSCK, "%s: start to scan backend /lost+found\n",
	       lfsck_lfsck2name(lfsck));

	com->lc_new_scanned = 0;
	iops = &parent->do_index_ops->dio_it;
	di = iops->init(env, parent, LUDA_64BITHASH | LUDA_TYPE);
	if (IS_ERR(di))
		GOTO(out, rc = PTR_ERR(di));

	rc = iops->load(env, di, 0);
	if (rc == 0)
		rc = iops->next(env, di);
	else if (rc > 0)
		rc = 0;

	while (rc == 0) {
		if (CFS_FAIL_TIMEOUT(OBD_FAIL_LFSCK_DELAY3, cfs_fail_val) &&
		    unlikely(!thread_is_running(thread)))
			break;

		rc = iops->rec(env, di, (struct dt_rec *)ent,
			       LUDA_64BITHASH | LUDA_TYPE);
		if (rc == 0)
			rc = lfsck_unpack_ent(ent, &cookie, &type);

		if (unlikely(rc != 0)) {
			CDEBUG(D_LFSCK, "%s: fail to iterate backend "
			       "/lost+found: rc = %d\n",
			       lfsck_lfsck2name(lfsck), rc);

			goto skip;
		}

		/* skip dot and dotdot entries */
		if (name_is_dot_or_dotdot(ent->lde_name, ent->lde_namelen))
			goto next;

		if (!fid_seq_in_fldb(fid_seq(&ent->lde_fid)))
			goto skip;

		if (fid_is_norm(&ent->lde_fid)) {
			fld_range_set_mdt(range);
			rc = fld_local_lookup(env, ss->ss_server_fld,
					      fid_seq(&ent->lde_fid), range);
			if (rc != 0)
				goto skip;
		} else if (idx != 0) {
			/* If the returned FID is IGIF, then there are three
			 * possible cases:
			 *
			 * 1) The object is upgraded from old Lustre-1.8 with
			 *    IGIF assigned to such object.
			 * 2) The object is a backend local object and is
			 *    invisible to client.
			 * 3) The object lost its LMV EA, and since there is
			 *    no FID-in-dirent for the orphan in the backend
			 *    /lost+found directory, then the low layer will
			 *    return IGIF for such object.
			 *
			 * For MDTx (x != 0), it is either case 2) or case 3),
			 * but from the LFSCK view, they are indistinguishable.
			 * To be safe, the LFSCK will keep it there and report
			 * some message, then the adminstrator can handle that
			 * furtherly.
			 *
			 * For MDT0, it is more possible the case 1). The LFSCK
			 * will handle the orphan as an upgraded object. */
			CDEBUG(D_LFSCK, "%s: the orphan %.*s with IGIF "DFID
			       "in the backend /lost+found on the MDT %04x, "
			       "to be safe, skip it.\n",
			       lfsck_lfsck2name(lfsck), ent->lde_namelen,
			       ent->lde_name, PFID(&ent->lde_fid), idx);
			goto skip;
		}

		rc = lfsck_namespace_scan_local_lpf_one(env, com, parent, ent);

skip:
		down_write(&com->lc_sem);
		com->lc_new_scanned++;
		ns->ln_local_lpf_scanned++;
		if (rc > 0)
			ns->ln_local_lpf_moved++;
		else if (rc == 0)
			ns->ln_local_lpf_skipped++;
		else
			ns->ln_local_lpf_failed++;
		up_write(&com->lc_sem);

		if (rc < 0 && bk->lb_param & LPF_FAILOUT)
			break;

next:
		lfsck_control_speed_by_self(com);
		if (unlikely(!thread_is_running(thread))) {
			rc = 0;
			break;
		}

		rc = iops->next(env, di);
	}

	iops->put(env, di);
	iops->fini(env, di);

	EXIT;

out:
	CDEBUG(D_LFSCK, "%s: stop to scan backend /lost+found: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);

	lfsck_object_put(env, parent);
}

/**
 * Rescan the striped directory after the master LMV EA reset.
 *
 * Sometimes, the master LMV EA of the striped directory maybe lost, so when
 * the namespace LFSCK engine scan the striped directory for the first time,
 * it will be regarded as a normal directory. As the LFSCK processing, some
 * other LFSCK instance on other MDT will find the shard of this striped dir,
 * and find that the master MDT-object of the striped directory lost its LMV
 * EA, then such remote LFSCK instance will regenerate the master LMV EA and
 * notify the LFSCK instance on this MDT to rescan the striped directory.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] llu	the lfsck_lmv_unit that contains the striped directory
 *			to be rescanned.
 *
 * \retval		positive number for success
 * \retval		0 for LFSCK stopped/paused
 * \retval		negative error number on failure
 */
static int lfsck_namespace_rescan_striped_dir(const struct lu_env *env,
					      struct lfsck_component *com,
					      struct lfsck_lmv_unit *llu)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct dt_object		*dir;
	const struct dt_it_ops		*iops;
	struct dt_it			*di;
	struct lu_dirent		*ent	=
			(struct lu_dirent *)info->lti_key;
	struct lfsck_bookmark		*bk	= &lfsck->li_bookmark_ram;
	struct ptlrpc_thread		*thread = &lfsck->li_thread;
	struct lfsck_assistant_object	*lso	= NULL;
	struct lfsck_namespace_req	*lnr;
	struct lfsck_assistant_req	*lar;
	int				 rc;
	__u16				 type;
	ENTRY;

	LASSERT(list_empty(&lad->lad_req_list));

	lfsck->li_lmv = &llu->llu_lmv;
	lfsck->li_obj_dir = lfsck_object_get(llu->llu_obj);
	rc = lfsck_open_dir(env, lfsck, 0);
	if (rc != 0)
		RETURN(rc);

	dir = lfsck->li_obj_dir;
	di = lfsck->li_di_dir;
	iops = &dir->do_index_ops->dio_it;
	do {
		rc = iops->rec(env, di, (struct dt_rec *)ent,
			       lfsck->li_args_dir);
		if (rc == 0)
			rc = lfsck_unpack_ent(ent, &lfsck->li_cookie_dir,
					      &type);

		if (rc != 0) {
			if (bk->lb_param & LPF_FAILOUT)
				GOTO(out, rc);

			goto next;
		}

		if (name_is_dot_or_dotdot(ent->lde_name, ent->lde_namelen))
			goto next;

		if (lso == NULL) {
			lso = lfsck_assistant_object_init(env,
				lfsck_dto2fid(dir), NULL,
				lfsck->li_pos_current.lp_oit_cookie, true);
			if (IS_ERR(lso)) {
				if (bk->lb_param & LPF_FAILOUT)
					GOTO(out, rc = PTR_ERR(lso));

				lso = NULL;
				goto next;
			}
		}

		lnr = lfsck_namespace_assistant_req_init(lfsck, lso, ent, type);
		if (IS_ERR(lnr)) {
			if (bk->lb_param & LPF_FAILOUT)
				GOTO(out, rc = PTR_ERR(lnr));

			goto next;
		}

		lar = &lnr->lnr_lar;
		rc = lfsck_namespace_assistant_handler_p1(env, com, lar);
		lfsck_namespace_assistant_req_fini(env, lar);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(out, rc);

		if (unlikely(!thread_is_running(thread)))
			GOTO(out, rc = 0);

next:
		rc = iops->next(env, di);
	} while (rc == 0);

out:
	if (lso != NULL && !IS_ERR(lso))
		lfsck_assistant_object_put(env, lso);

	lfsck_close_dir(env, lfsck, rc);
	if (rc <= 0)
		RETURN(rc);

	/* The close_dir() may insert a dummy lnr in the lad->lad_req_list. */
	if (list_empty(&lad->lad_req_list))
		RETURN(1);

	spin_lock(&lad->lad_lock);
	lar = list_entry(lad->lad_req_list.next, struct lfsck_assistant_req,
			  lar_list);
	list_del_init(&lar->lar_list);
	spin_unlock(&lad->lad_lock);

	rc = lfsck_namespace_assistant_handler_p1(env, com, lar);
	lfsck_namespace_assistant_req_fini(env, lar);

	RETURN(rc == 0 ? 1 : rc);
}

static int
lfsck_namespace_double_scan_one_trace_file(const struct lu_env *env,
					   struct lfsck_component *com,
					   struct dt_object *obj, bool first)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct ptlrpc_thread	*thread = &lfsck->li_thread;
	struct lfsck_bookmark	*bk	= &lfsck->li_bookmark_ram;
	struct lfsck_namespace	*ns	= com->lc_file_ram;
	const struct dt_it_ops	*iops	= &obj->do_index_ops->dio_it;
	struct dt_object	*target;
	struct dt_it		*di;
	struct dt_key		*key;
	struct lu_fid		 fid;
	int			 rc;
	__u8			 flags	= 0;
	ENTRY;

	di = iops->init(env, obj, 0);
	if (IS_ERR(di))
		RETURN(PTR_ERR(di));

	if (first)
		fid_cpu_to_be(&fid, &ns->ln_fid_latest_scanned_phase2);
	else
		fid_zero(&fid);
	rc = iops->get(env, di, (const struct dt_key *)&fid);
	if (rc < 0)
		GOTO(fini, rc);

	if (first) {
		/* The start one either has been processed or does not exist,
		 * skip it. */
		rc = iops->next(env, di);
		if (rc != 0)
			GOTO(put, rc);
	}

	do {
		if (CFS_FAIL_TIMEOUT(OBD_FAIL_LFSCK_DELAY3, cfs_fail_val) &&
		    unlikely(!thread_is_running(thread)))
			GOTO(put, rc = 0);

		key = iops->key(env, di);
		if (IS_ERR(key)) {
			rc = PTR_ERR(key);
			if (rc == -ENOENT)
				GOTO(put, rc = 1);

			goto checkpoint;
		}

		fid_be_to_cpu(&fid, (const struct lu_fid *)key);
		if (!fid_is_sane(&fid)) {
			rc = 0;
			goto checkpoint;
		}

		target = lfsck_object_find_bottom(env, lfsck, &fid);
		if (IS_ERR(target)) {
			rc = PTR_ERR(target);
			goto checkpoint;
		}

		if (dt_object_exists(target)) {
			rc = iops->rec(env, di, (struct dt_rec *)&flags, 0);
			if (rc == 0) {
				rc = lfsck_namespace_double_scan_one(env, com,
								target, flags);
				if (rc == -ENOENT)
					rc = 0;
			}
		}

		lfsck_object_put(env, target);

checkpoint:
		down_write(&com->lc_sem);
		com->lc_new_checked++;
		com->lc_new_scanned++;
		if (rc >= 0)
			ns->ln_fid_latest_scanned_phase2 = fid;

		if (rc > 0)
			ns->ln_objs_repaired_phase2++;
		else if (rc < 0)
			ns->ln_objs_failed_phase2++;
		up_write(&com->lc_sem);

		if (rc < 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(put, rc);

		if (unlikely(com->lc_time_next_checkpoint <=
			     ktime_get_seconds()) &&
		    com->lc_new_checked != 0) {
			down_write(&com->lc_sem);
			ns->ln_run_time_phase2 += ktime_get_seconds() -
						  com->lc_time_last_checkpoint;
			ns->ln_time_last_checkpoint = ktime_get_real_seconds();
			ns->ln_objs_checked_phase2 += com->lc_new_checked;
			com->lc_new_checked = 0;
			lfsck_namespace_store(env, com);
			up_write(&com->lc_sem);

			com->lc_time_last_checkpoint = ktime_get_seconds();
			com->lc_time_next_checkpoint =
				com->lc_time_last_checkpoint +
				LFSCK_CHECKPOINT_INTERVAL;
		}

		lfsck_control_speed_by_self(com);
		if (unlikely(!thread_is_running(thread)))
			GOTO(put, rc = 0);

		rc = iops->next(env, di);
	} while (rc == 0);

	GOTO(put, rc);

put:
	iops->put(env, di);

fini:
	iops->fini(env, di);

	return rc;
}

static int lfsck_namespace_assistant_handler_p2(const struct lu_env *env,
						struct lfsck_component *com)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_namespace	*ns	= com->lc_file_ram;
	int			 rc;
	int			 i;
	ENTRY;

	while (!list_empty(&lfsck->li_list_lmv)) {
		struct lfsck_lmv_unit *llu;

		spin_lock(&lfsck->li_lock);
		llu = list_entry(lfsck->li_list_lmv.next,
				 struct lfsck_lmv_unit, llu_link);
		list_del_init(&llu->llu_link);
		spin_unlock(&lfsck->li_lock);

		rc = lfsck_namespace_rescan_striped_dir(env, com, llu);
		if (rc <= 0)
			RETURN(rc);
	}

	CDEBUG(D_LFSCK, "%s: namespace LFSCK phase2 scan start\n",
	       lfsck_lfsck2name(lfsck));

	lfsck_namespace_scan_local_lpf(env, com);

	com->lc_new_checked = 0;
	com->lc_new_scanned = 0;
	com->lc_time_last_checkpoint = ktime_get_seconds();
	com->lc_time_next_checkpoint = com->lc_time_last_checkpoint +
				       LFSCK_CHECKPOINT_INTERVAL;

	i = lfsck_sub_trace_file_fid2idx(&ns->ln_fid_latest_scanned_phase2);
	rc = lfsck_namespace_double_scan_one_trace_file(env, com,
				com->lc_sub_trace_objs[i].lsto_obj, true);
	while (rc > 0 && ++i < LFSCK_STF_COUNT)
		rc = lfsck_namespace_double_scan_one_trace_file(env, com,
				com->lc_sub_trace_objs[i].lsto_obj, false);

	CDEBUG(D_LFSCK, "%s: namespace LFSCK phase2 scan stop at the No. %d "
	       "trace file: rc = %d\n", lfsck_lfsck2name(lfsck), i, rc);

	RETURN(rc);
}

static void lfsck_namespace_assistant_fill_pos(const struct lu_env *env,
					       struct lfsck_component *com,
					       struct lfsck_position *pos)
{
	struct lfsck_assistant_data	*lad = com->lc_data;
	struct lfsck_namespace_req	*lnr;

	if (((struct lfsck_namespace *)(com->lc_file_ram))->ln_status !=
	    LS_SCANNING_PHASE1)
		return;

	if (list_empty(&lad->lad_req_list))
		return;

	lnr = list_entry(lad->lad_req_list.next,
			 struct lfsck_namespace_req,
			 lnr_lar.lar_list);
	pos->lp_oit_cookie = lnr->lnr_lar.lar_parent->lso_oit_cookie;
	pos->lp_dir_cookie = lnr->lnr_dir_cookie - 1;
	pos->lp_dir_parent = lnr->lnr_lar.lar_parent->lso_fid;
}

static int lfsck_namespace_double_scan_result(const struct lu_env *env,
					      struct lfsck_component *com,
					      int rc)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_namespace	*ns	= com->lc_file_ram;

	down_write(&com->lc_sem);
	ns->ln_run_time_phase2 += ktime_get_seconds() -
				  com->lc_time_last_checkpoint;
	ns->ln_time_last_checkpoint = ktime_get_real_seconds();
	ns->ln_objs_checked_phase2 += com->lc_new_checked;
	com->lc_new_checked = 0;

	if (rc > 0) {
		if (ns->ln_flags & LF_INCOMPLETE)
			ns->ln_status = LS_PARTIAL;
		else
			ns->ln_status = LS_COMPLETED;
		ns->ln_flags &= ~LF_SCANNED_ONCE;
		if (!(lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN))
			ns->ln_flags &= ~LF_INCONSISTENT;
		ns->ln_time_last_complete = ns->ln_time_last_checkpoint;
		ns->ln_success_count++;
	} else if (rc == 0) {
		if (lfsck->li_status != 0)
			ns->ln_status = lfsck->li_status;
		else
			ns->ln_status = LS_STOPPED;
	} else {
		ns->ln_status = LS_FAILED;
	}

	rc = lfsck_namespace_store(env, com);
	up_write(&com->lc_sem);

	return rc;
}

static int
lfsck_namespace_assistant_sync_failures_interpret(const struct lu_env *env,
						  struct ptlrpc_request *req,
						  void *args, int rc)
{
	if (rc == 0) {
		struct lfsck_async_interpret_args *laia = args;
		struct lfsck_tgt_desc		  *ltd	= laia->laia_ltd;

		ltd->ltd_synced_failures = 1;
	}

	return 0;
}

/**
 * Notify remote LFSCK instances about former failures.
 *
 * The local LFSCK instance has recorded which MDTs have ever failed to respond
 * some LFSCK verification requests (maybe because of network issues or the MDT
 * itself trouble). During the respond gap the MDT may missed some name entries
 * verification, then the MDT cannot know whether related MDT-objects have been
 * referenced by related name entries or not, then in the second-stage scanning,
 * these MDT-objects will be regarded as orphan, if the MDT-object contains bad
 * linkEA for back reference, then it will misguide the LFSCK to generate wrong
 * name entry for repairing the orphan.
 *
 * To avoid above trouble, when layout LFSCK finishes the first-stage scanning,
 * it will scan the bitmap for the ever failed MDTs, and notify them that they
 * have ever missed some name entries verification and should skip the handling
 * for orphan MDT-objects.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] lr	pointer to the lfsck request
 */
static void lfsck_namespace_assistant_sync_failures(const struct lu_env *env,
						    struct lfsck_component *com,
						    struct lfsck_request *lr)
{
	struct lfsck_async_interpret_args *laia  =
				&lfsck_env_info(env)->lti_laia2;
	struct lfsck_assistant_data	  *lad   = com->lc_data;
	struct lfsck_namespace		  *ns    = com->lc_file_ram;
	struct lfsck_instance		  *lfsck = com->lc_lfsck;
	struct lfsck_tgt_descs		  *ltds  = &lfsck->li_mdt_descs;
	struct lfsck_tgt_desc		  *ltd;
	struct ptlrpc_request_set	  *set;
	__u32				   idx;
	int				   rc    = 0;
	ENTRY;

	if (!test_bit(LAD_INCOMPLETE, &lad->lad_flags))
		RETURN_EXIT;

	set = ptlrpc_prep_set();
	if (set == NULL)
		GOTO(out, rc = -ENOMEM);

	lr->lr_flags2 = ns->ln_flags | LF_INCOMPLETE;
	memset(laia, 0, sizeof(*laia));
	lad->lad_touch_gen++;

	down_read(&ltds->ltd_rw_sem);
	cfs_foreach_bit(lad->lad_bitmap, idx) {
		ltd = lfsck_ltd2tgt(ltds, idx);
		if (unlikely(!ltd))
			continue;

		laia->laia_ltd = ltd;
		rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
			lfsck_namespace_assistant_sync_failures_interpret,
			laia, LFSCK_NOTIFY);
		if (rc != 0)
			CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant fail "
			       "to sync failure with MDT %x: rc = %d\n",
			       lfsck_lfsck2name(lfsck), ltd->ltd_index, rc);
	}
	up_read(&ltds->ltd_rw_sem);

	rc = ptlrpc_set_wait(env, set);
	ptlrpc_set_destroy(set);

	GOTO(out, rc);

out:
	if (rc != 0)
		CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant fail "
		       "to sync failure with MDTs, and related MDTs "
		       "may handle orphan improperly: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);

	EXIT;
}

const struct lfsck_assistant_operations lfsck_namespace_assistant_ops = {
	.la_handler_p1		= lfsck_namespace_assistant_handler_p1,
	.la_handler_p2		= lfsck_namespace_assistant_handler_p2,
	.la_fill_pos		= lfsck_namespace_assistant_fill_pos,
	.la_double_scan_result	= lfsck_namespace_double_scan_result,
	.la_req_fini		= lfsck_namespace_assistant_req_fini,
	.la_sync_failures	= lfsck_namespace_assistant_sync_failures,
};

/**
 * Verify the specified linkEA entry for the given directory object.
 * If the object has no such linkEA entry or it has more other linkEA
 * entries, then re-generate the linkEA with the given information.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] obj	pointer to the dt_object to be handled
 * \param[in] cname	the name for the child in the parent directory
 * \param[in] pfid	the parent directory's FID for the linkEA
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_verify_linkea(const struct lu_env *env, struct dt_object *obj,
			const struct lu_name *cname, const struct lu_fid *pfid)
{
	struct dt_device	*dev	= lfsck_obj2dev(obj);
	struct linkea_data	 ldata	= { NULL };
	struct lu_buf		 linkea_buf;
	struct thandle		*th;
	int			 rc;
	int			 fl	= LU_XATTR_CREATE;
	bool			 dirty	= false;
	ENTRY;

	LASSERT(S_ISDIR(lfsck_object_type(obj)));

	rc = lfsck_links_read_with_rec(env, obj, &ldata);
	if (rc == -ENODATA) {
		dirty = true;
	} else if (rc == 0) {
		fl = LU_XATTR_REPLACE;
		if (ldata.ld_leh->leh_reccount != 1) {
			dirty = true;
		} else {
			rc = linkea_links_find(&ldata, cname, pfid);
			if (rc != 0)
				dirty = true;
		}
	}

	if (!dirty)
		RETURN(rc);

	rc = linkea_links_new(&ldata, &lfsck_env_info(env)->lti_linkea_buf,
			      cname, pfid);
	if (rc != 0)
		RETURN(rc);

	lfsck_buf_init(&linkea_buf, ldata.ld_buf->lb_buf,
		       ldata.ld_leh->leh_len);
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_xattr_set(env, obj, &linkea_buf,
				  XATTR_NAME_LINK, fl, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	rc = dt_xattr_set(env, obj, &linkea_buf,
			  XATTR_NAME_LINK, fl, th);
	dt_write_unlock(env, obj);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);
	return rc;
}

/**
 * Get the name and parent directory's FID from the first linkEA entry.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] obj	pointer to the object which get linkEA from
 * \param[out] name	pointer to the buffer to hold the name
 *			in the first linkEA entry
 * \param[out] pfid	pointer to the buffer to hold the parent
 *			directory's FID in the first linkEA entry
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_links_get_first(const struct lu_env *env, struct dt_object *obj,
			  char *name, struct lu_fid *pfid)
{
	struct lu_name		 *cname = &lfsck_env_info(env)->lti_name;
	struct linkea_data	  ldata = { NULL };
	int			  rc;

	rc = lfsck_links_read_with_rec(env, obj, &ldata);
	if (rc)
		return rc;

	linkea_first_entry(&ldata);
	linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen, cname, pfid);
	if (!linkea_entry_is_valid(&ldata, cname, pfid))
		return -EINVAL;

	/* To guarantee the 'name' is terminated with '0'. */
	memcpy(name, cname->ln_name, cname->ln_namelen);
	name[cname->ln_namelen] = 0;

	return 0;
}

/**
 * Update the object's name entry with the given FID.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 * \param[in] dir	pointer to the directory that holds
 *			the name entry
 * \param[in] name	the name for the entry to be updated
 * \param[in] fid	the new FID for the name entry referenced
 * \param[in] type	the type for the name entry to be updated
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_update_name_entry(const struct lu_env *env,
			    struct lfsck_instance *lfsck,
			    struct dt_object *dir, const char *name,
			    const struct lu_fid *fid, __u32 type)
{
	struct lfsck_thread_info *info	 = lfsck_env_info(env);
	struct dt_insert_rec	 *rec	 = &info->lti_dt_rec;
	struct lfsck_lock_handle *llh	 = &info->lti_llh;
	struct dt_device	 *dev	 = lfsck_obj2dev(dir);
	struct thandle		 *th;
	int			  rc;
	bool			  exists = true;
	ENTRY;

	rc = lfsck_lock(env, lfsck, dir, name, llh,
			MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		RETURN(rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, dir, (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rec->rec_type = type;
	rec->rec_fid = fid;
	rc = dt_declare_insert(env, dir, (const struct dt_rec *)rec,
			       (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_ref_add(env, dir, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_delete(env, dir, (const struct dt_key *)name, th);
	if (rc == -ENOENT) {
		exists = false;
		rc = 0;
	}

	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_insert(env, dir, (const struct dt_rec *)rec,
		       (const struct dt_key *)name, th);
	if (rc == 0 && S_ISDIR(type) && !exists) {
		dt_write_lock(env, dir, 0);
		rc = dt_ref_add(env, dir, th);
		dt_write_unlock(env, dir);
	}

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);

unlock:
	lfsck_unlock(llh);
	CDEBUG(D_LFSCK, "%s: update name entry "DFID"/%s with the FID "DFID
	       " and the type %o: rc = %d\n", lfsck_lfsck2name(lfsck),
	       PFID(lfsck_dto2fid(dir)), name, PFID(fid), type, rc);

	return rc;
}

int lfsck_namespace_setup(const struct lu_env *env,
			  struct lfsck_instance *lfsck)
{
	struct lfsck_component	*com;
	struct lfsck_namespace	*ns;
	struct dt_object	*root = NULL;
	struct dt_object	*obj;
	int			 i;
	int			 rc;
	ENTRY;

	LASSERT(lfsck->li_master);

	OBD_ALLOC_PTR(com);
	if (com == NULL)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&com->lc_link);
	INIT_LIST_HEAD(&com->lc_link_dir);
	init_rwsem(&com->lc_sem);
	atomic_set(&com->lc_ref, 1);
	com->lc_lfsck = lfsck;
	com->lc_type = LFSCK_TYPE_NAMESPACE;
	com->lc_ops = &lfsck_namespace_ops;
	com->lc_data = lfsck_assistant_data_init(
			&lfsck_namespace_assistant_ops,
			LFSCK_NAMESPACE);
	if (com->lc_data == NULL)
		GOTO(out, rc = -ENOMEM);

	com->lc_file_size = sizeof(struct lfsck_namespace);
	OBD_ALLOC(com->lc_file_ram, com->lc_file_size);
	if (com->lc_file_ram == NULL)
		GOTO(out, rc = -ENOMEM);

	OBD_ALLOC(com->lc_file_disk, com->lc_file_size);
	if (com->lc_file_disk == NULL)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < LFSCK_STF_COUNT; i++)
		mutex_init(&com->lc_sub_trace_objs[i].lsto_mutex);

	root = dt_locate(env, lfsck->li_bottom, &lfsck->li_local_root_fid);
	if (IS_ERR(root))
		GOTO(out, rc = PTR_ERR(root));

	if (unlikely(!dt_try_as_dir(env, root)))
		GOTO(out, rc = -ENOTDIR);

	obj = local_index_find_or_create(env, lfsck->li_los, root,
					 LFSCK_NAMESPACE,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 &dt_lfsck_namespace_features);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	com->lc_obj = obj;
	rc = lfsck_namespace_load(env, com);
	if (rc == -ENODATA) {
		rc = lfsck_namespace_init(env, com);
	} else if (rc < 0) {
		rc = lfsck_namespace_reset(env, com, true);
	} else {
		rc = lfsck_load_sub_trace_files(env, com,
			&dt_lfsck_namespace_features, LFSCK_NAMESPACE, false);
		if (rc)
			rc = lfsck_namespace_reset(env, com, true);
	}
	if (rc != 0)
		GOTO(out, rc);

	ns = com->lc_file_ram;
	switch (ns->ln_status) {
	case LS_INIT:
	case LS_COMPLETED:
	case LS_FAILED:
	case LS_STOPPED:
		spin_lock(&lfsck->li_lock);
		list_add_tail(&com->lc_link, &lfsck->li_list_idle);
		spin_unlock(&lfsck->li_lock);
		break;
	default:
		CERROR("%s: unknown lfsck_namespace status %d\n",
		       lfsck_lfsck2name(lfsck), ns->ln_status);
		/* fall through */
	case LS_SCANNING_PHASE1:
	case LS_SCANNING_PHASE2:
		/* No need to store the status to disk right now.
		 * If the system crashed before the status stored,
		 * it will be loaded back when next time. */
		ns->ln_status = LS_CRASHED;
		/* fall through */
	case LS_PAUSED:
	case LS_CRASHED:
		spin_lock(&lfsck->li_lock);
		list_add_tail(&com->lc_link, &lfsck->li_list_scan);
		list_add_tail(&com->lc_link_dir, &lfsck->li_list_dir);
		spin_unlock(&lfsck->li_lock);
		break;
	}

	GOTO(out, rc = 0);

out:
	if (root != NULL && !IS_ERR(root))
		lfsck_object_put(env, root);
	if (rc != 0) {
		lfsck_component_cleanup(env, com);
		CERROR("%s: fail to init namespace LFSCK component: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);
	}
	return rc;
}
