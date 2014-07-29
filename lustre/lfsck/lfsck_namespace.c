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
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * lustre/lfsck/lfsck_namespace.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LFSCK

#include <lustre/lustre_idl.h>
#include <lu_object.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre/lustre_user.h>

#include "lfsck_internal.h"

#define LFSCK_NAMESPACE_MAGIC	0xA0629D03

enum lfsck_nameentry_check {
	LFSCK_NAMEENTRY_DEAD		= 1, /* The object has been unlinked. */
	LFSCK_NAMEENTRY_REMOVED		= 2, /* The entry has been removed. */
	LFSCK_NAMEENTRY_RECREATED	= 3, /* The entry has been recreated. */
};

static const char lfsck_namespace_name[] = "lfsck_namespace";

struct lfsck_namespace_req {
	struct lfsck_assistant_req	 lnr_lar;
	struct dt_object		*lnr_obj;
	struct lu_fid			 lnr_fid;
	__u64				 lnr_oit_cookie;
	__u64				 lnr_dir_cookie;
	__u32				 lnr_attr;
	__u32				 lnr_size;
	__u16				 lnr_type;
	__u16				 lnr_namelen;
	char				 lnr_name[0];
};

static struct lfsck_namespace_req *
lfsck_namespace_assistant_req_init(struct lfsck_instance *lfsck,
				   struct lu_dirent *ent, __u16 type)
{
	struct lfsck_namespace_req *lnr;
	int			    size;

	size = sizeof(*lnr) + (ent->lde_namelen & ~3) + 4;
	OBD_ALLOC(lnr, size);
	if (lnr == NULL)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&lnr->lnr_lar.lar_list);
	lu_object_get(&lfsck->li_obj_dir->do_lu);
	lnr->lnr_obj = lfsck->li_obj_dir;
	lnr->lnr_fid = ent->lde_fid;
	lnr->lnr_oit_cookie = lfsck->li_pos_current.lp_oit_cookie;
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
			container_of0(lar, struct lfsck_namespace_req, lnr_lar);

	lu_object_put(env, &lnr->lnr_obj->do_lu);
	OBD_FREE(lnr, lnr->lnr_size);
}

static void lfsck_namespace_le_to_cpu(struct lfsck_namespace *dst,
				      struct lfsck_namespace *src)
{
	dst->ln_magic = le32_to_cpu(src->ln_magic);
	dst->ln_status = le32_to_cpu(src->ln_status);
	dst->ln_flags = le32_to_cpu(src->ln_flags);
	dst->ln_success_count = le32_to_cpu(src->ln_success_count);
	dst->ln_run_time_phase1 = le32_to_cpu(src->ln_run_time_phase1);
	dst->ln_run_time_phase2 = le32_to_cpu(src->ln_run_time_phase2);
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
	dst->ln_mlinked_checked = le64_to_cpu(src->ln_mlinked_checked);
	dst->ln_objs_checked_phase2 = le64_to_cpu(src->ln_objs_checked_phase2);
	dst->ln_objs_repaired_phase2 =
				le64_to_cpu(src->ln_objs_repaired_phase2);
	dst->ln_objs_failed_phase2 = le64_to_cpu(src->ln_objs_failed_phase2);
	dst->ln_objs_nlink_repaired = le64_to_cpu(src->ln_objs_nlink_repaired);
	dst->ln_objs_lost_found = le64_to_cpu(src->ln_objs_lost_found);
	fid_le_to_cpu(&dst->ln_fid_latest_scanned_phase2,
		      &src->ln_fid_latest_scanned_phase2);
	dst->ln_dirent_repaired = le64_to_cpu(src->ln_dirent_repaired);
	dst->ln_linkea_repaired = le64_to_cpu(src->ln_linkea_repaired);
}

static void lfsck_namespace_cpu_to_le(struct lfsck_namespace *dst,
				      struct lfsck_namespace *src)
{
	dst->ln_magic = cpu_to_le32(src->ln_magic);
	dst->ln_status = cpu_to_le32(src->ln_status);
	dst->ln_flags = cpu_to_le32(src->ln_flags);
	dst->ln_success_count = cpu_to_le32(src->ln_success_count);
	dst->ln_run_time_phase1 = cpu_to_le32(src->ln_run_time_phase1);
	dst->ln_run_time_phase2 = cpu_to_le32(src->ln_run_time_phase2);
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
	dst->ln_mlinked_checked = cpu_to_le64(src->ln_mlinked_checked);
	dst->ln_objs_checked_phase2 = cpu_to_le64(src->ln_objs_checked_phase2);
	dst->ln_objs_repaired_phase2 =
				cpu_to_le64(src->ln_objs_repaired_phase2);
	dst->ln_objs_failed_phase2 = cpu_to_le64(src->ln_objs_failed_phase2);
	dst->ln_objs_nlink_repaired = cpu_to_le64(src->ln_objs_nlink_repaired);
	dst->ln_objs_lost_found = cpu_to_le64(src->ln_objs_lost_found);
	fid_cpu_to_le(&dst->ln_fid_latest_scanned_phase2,
		      &src->ln_fid_latest_scanned_phase2);
	dst->ln_dirent_repaired = cpu_to_le64(src->ln_dirent_repaired);
	dst->ln_linkea_repaired = cpu_to_le64(src->ln_linkea_repaired);
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
		       "inconsistency at the pos ["LPU64", "DFID", "LPX64"]\n",
		       lfsck_lfsck2name(lfsck),
		       ns->ln_pos_first_inconsistent.lp_oit_cookie,
		       PFID(&ns->ln_pos_first_inconsistent.lp_dir_parent),
		       ns->ln_pos_first_inconsistent.lp_dir_cookie);
	}
}

/**
 * \retval +ve: the lfsck_namespace is broken, the caller should reset it.
 * \retval 0: succeed.
 * \retval -ve: failed cases.
 */
static int lfsck_namespace_load(const struct lu_env *env,
				struct lfsck_component *com)
{
	int len = com->lc_file_size;
	int rc;

	rc = dt_xattr_get(env, com->lc_obj,
			  lfsck_buf_get(env, com->lc_file_disk, len),
			  XATTR_NAME_LFSCK_NAMESPACE, BYPASS_CAPA);
	if (rc == len) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		lfsck_namespace_le_to_cpu(ns,
				(struct lfsck_namespace *)com->lc_file_disk);
		if (ns->ln_magic != LFSCK_NAMESPACE_MAGIC) {
			CDEBUG(D_LFSCK, "%s: invalid lfsck_namespace magic "
			       "%#x != %#x\n", lfsck_lfsck2name(com->lc_lfsck),
			       ns->ln_magic, LFSCK_NAMESPACE_MAGIC);
			rc = 1;
		} else {
			rc = 0;
		}
	} else if (rc != -ENODATA) {
		CDEBUG(D_LFSCK, "%s: fail to load lfsck_namespace, "
		       "expected = %d: rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck), len, rc);
		if (rc >= 0)
			rc = 1;
	}
	return rc;
}

static int lfsck_namespace_store(const struct lu_env *env,
				 struct lfsck_component *com, bool init)
{
	struct dt_object	*obj    = com->lc_obj;
	struct lfsck_instance	*lfsck  = com->lc_lfsck;
	struct thandle		*handle;
	int			 len    = com->lc_file_size;
	int			 rc;
	ENTRY;

	lfsck_namespace_cpu_to_le((struct lfsck_namespace *)com->lc_file_disk,
				  (struct lfsck_namespace *)com->lc_file_ram);
	handle = dt_trans_create(env, lfsck->li_bottom);
	if (IS_ERR(handle))
		GOTO(log, rc = PTR_ERR(handle));

	rc = dt_declare_xattr_set(env, obj,
				  lfsck_buf_get(env, com->lc_file_disk, len),
				  XATTR_NAME_LFSCK_NAMESPACE, 0, handle);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, lfsck->li_bottom, handle);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_xattr_set(env, obj,
			  lfsck_buf_get(env, com->lc_file_disk, len),
			  XATTR_NAME_LFSCK_NAMESPACE,
			  init ? LU_XATTR_CREATE : LU_XATTR_REPLACE,
			  handle, BYPASS_CAPA);

	GOTO(out, rc);

out:
	dt_trans_stop(env, lfsck->li_bottom, handle);

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
	down_write(&com->lc_sem);
	rc = lfsck_namespace_store(env, com, true);
	up_write(&com->lc_sem);
	return rc;
}

static int lfsck_namespace_lookup(const struct lu_env *env,
				  struct lfsck_component *com,
				  const struct lu_fid *fid, __u8 *flags)
{
	struct lu_fid *key = &lfsck_env_info(env)->lti_fid;
	int	       rc;

	fid_cpu_to_be(key, fid);
	rc = dt_lookup(env, com->lc_obj, (struct dt_rec *)flags,
		       (const struct dt_key *)key, BYPASS_CAPA);
	return rc;
}

static int lfsck_namespace_delete(const struct lu_env *env,
				  struct lfsck_component *com,
				  const struct lu_fid *fid)
{
	struct lfsck_instance	*lfsck  = com->lc_lfsck;
	struct lu_fid		*key    = &lfsck_env_info(env)->lti_fid;
	struct thandle		*handle;
	struct dt_object	*obj    = com->lc_obj;
	int			 rc;
	ENTRY;

	handle = dt_trans_create(env, lfsck->li_bottom);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = dt_declare_delete(env, obj, (const struct dt_key *)fid, handle);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, lfsck->li_bottom, handle);
	if (rc != 0)
		GOTO(out, rc);

	fid_cpu_to_be(key, fid);
	rc = dt_delete(env, obj, (const struct dt_key *)key, handle,
		       BYPASS_CAPA);

	GOTO(out, rc);

out:
	dt_trans_stop(env, lfsck->li_bottom, handle);
	return rc;
}

static int lfsck_namespace_update(const struct lu_env *env,
				  struct lfsck_component *com,
				  const struct lu_fid *fid,
				  __u8 flags, bool force)
{
	struct lfsck_instance	*lfsck  = com->lc_lfsck;
	struct lu_fid		*key    = &lfsck_env_info(env)->lti_fid;
	struct thandle		*handle;
	struct dt_object	*obj    = com->lc_obj;
	int			 rc;
	bool			 exist  = false;
	__u8			 tf;
	ENTRY;

	rc = lfsck_namespace_lookup(env, com, fid, &tf);
	if (rc != 0 && rc != -ENOENT)
		RETURN(rc);

	if (rc == 0) {
		if (!force || flags == tf)
			RETURN(0);

		exist = true;
		handle = dt_trans_create(env, lfsck->li_bottom);
		if (IS_ERR(handle))
			RETURN(PTR_ERR(handle));

		rc = dt_declare_delete(env, obj, (const struct dt_key *)fid,
				       handle);
		if (rc != 0)
			GOTO(out, rc);
	} else {
		handle = dt_trans_create(env, lfsck->li_bottom);
		if (IS_ERR(handle))
			RETURN(PTR_ERR(handle));
	}

	rc = dt_declare_insert(env, obj, (const struct dt_rec *)&flags,
			       (const struct dt_key *)fid, handle);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, lfsck->li_bottom, handle);
	if (rc != 0)
		GOTO(out, rc);

	fid_cpu_to_be(key, fid);
	if (exist) {
		rc = dt_delete(env, obj, (const struct dt_key *)key, handle,
			       BYPASS_CAPA);
		if (rc != 0)
			GOTO(out, rc);
	}

	rc = dt_insert(env, obj, (const struct dt_rec *)&flags,
		       (const struct dt_key *)key, handle, BYPASS_CAPA, 1);

	GOTO(out, rc);

out:
	dt_trans_stop(env, lfsck->li_bottom, handle);
	return rc;
}

static int lfsck_namespace_check_exist(const struct lu_env *env,
				       struct dt_object *dir,
				       struct dt_object *obj, const char *name)
{
	struct lu_fid	 *fid = &lfsck_env_info(env)->lti_fid;
	int		  rc;
	ENTRY;

	if (unlikely(lfsck_is_dead_obj(obj)))
		RETURN(LFSCK_NAMEENTRY_DEAD);

	rc = dt_lookup(env, dir, (struct dt_rec *)fid,
		       (const struct dt_key *)name, BYPASS_CAPA);
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

	/* For destroying all invalid linkEA entries. */
	rc = dt_declare_xattr_del(env, obj, XATTR_NAME_LINK, handle);
	if (rc != 0)
		return rc;

	/* For insert new linkEA entry. */
	rc = dt_declare_xattr_set(env, obj,
			lfsck_buf_get_const(env, NULL, DEFAULT_LINKEA_SIZE),
			XATTR_NAME_LINK, 0, handle);
	return rc;
}

static int lfsck_links_read(const struct lu_env *env, struct dt_object *obj,
			    struct linkea_data *ldata)
{
	int rc;

	ldata->ld_buf =
		lu_buf_check_and_alloc(&lfsck_env_info(env)->lti_linkea_buf,
				       PAGE_CACHE_SIZE);
	if (ldata->ld_buf->lb_buf == NULL)
		return -ENOMEM;

	if (!dt_object_exists(obj))
		return -ENODATA;

	rc = dt_xattr_get(env, obj, ldata->ld_buf, XATTR_NAME_LINK, BYPASS_CAPA);
	if (rc == -ERANGE) {
		/* Buf was too small, figure out what we need. */
		lu_buf_free(ldata->ld_buf);
		rc = dt_xattr_get(env, obj, ldata->ld_buf, XATTR_NAME_LINK,
				  BYPASS_CAPA);
		if (rc < 0)
			return rc;

		ldata->ld_buf = lu_buf_check_and_alloc(ldata->ld_buf, rc);
		if (ldata->ld_buf->lb_buf == NULL)
			return -ENOMEM;

		rc = dt_xattr_get(env, obj, ldata->ld_buf, XATTR_NAME_LINK,
				  BYPASS_CAPA);
	}
	if (rc < 0)
		return rc;

	linkea_init(ldata);

	return 0;
}

static int lfsck_links_write(const struct lu_env *env, struct dt_object *obj,
			     struct linkea_data *ldata, struct thandle *handle)
{
	const struct lu_buf *buf = lfsck_buf_get_const(env,
						       ldata->ld_buf->lb_buf,
						       ldata->ld_leh->leh_len);

	return dt_xattr_set(env, obj, buf, XATTR_NAME_LINK, 0, handle,
			    BYPASS_CAPA);
}

/**
 * \retval ve: removed entries
 */
static int lfsck_linkea_entry_unpack(struct lfsck_instance *lfsck,
				     struct linkea_data *ldata,
				     struct lu_name *cname,
				     struct lu_fid *pfid)
{
	struct link_ea_entry	*oldlee;
	int			 oldlen;
	int			 removed = 0;

	linkea_entry_unpack(ldata->ld_lee, &ldata->ld_reclen, cname, pfid);
	oldlee = ldata->ld_lee;
	oldlen = ldata->ld_reclen;
	linkea_next_entry(ldata);
	while (ldata->ld_lee != NULL) {
		ldata->ld_reclen = (ldata->ld_lee->lee_reclen[0] << 8) |
				   ldata->ld_lee->lee_reclen[1];
		if (unlikely(ldata->ld_reclen == oldlen &&
			     memcmp(ldata->ld_lee, oldlee, oldlen) == 0)) {
			linkea_del_buf(ldata, cname);
			removed++;
		} else {
			linkea_next_entry(ldata);
		}
	}
	ldata->ld_lee = oldlee;
	ldata->ld_reclen = oldlen;
	return removed;
}

/**
 * \retval +ve	repaired
 * \retval 0	no need to repair
 * \retval -ve	error cases
 */
static int lfsck_namespace_double_scan_one(const struct lu_env *env,
					   struct lfsck_component *com,
					   struct dt_object *child, __u8 flags)
{
	struct lfsck_thread_info *info	  = lfsck_env_info(env);
	struct lu_attr		 *la	  = &info->lti_la;
	struct lu_name		 *cname	  = &info->lti_name;
	struct lu_fid		 *pfid	  = &info->lti_fid;
	struct lu_fid		 *cfid	  = &info->lti_fid2;
	struct lfsck_instance	*lfsck	  = com->lc_lfsck;
	struct lfsck_bookmark	*bk	  = &lfsck->li_bookmark_ram;
	struct lfsck_namespace	*ns	  = com->lc_file_ram;
	struct linkea_data	 ldata	  = { 0 };
	struct thandle		*handle   = NULL;
	bool			 locked   = false;
	bool			 update	  = false;
	int			 rc;
	ENTRY;

	if (com->lc_journal) {

again:
		LASSERT(!locked);

		update = false;
		com->lc_journal = 1;
		handle = dt_trans_create(env, lfsck->li_next);
		if (IS_ERR(handle))
			RETURN(rc = PTR_ERR(handle));

		rc = dt_declare_xattr_set(env, child,
			lfsck_buf_get_const(env, NULL, DEFAULT_LINKEA_SIZE),
			XATTR_NAME_LINK, 0, handle);
		if (rc != 0)
			GOTO(stop, rc);

		rc = dt_trans_start(env, lfsck->li_next, handle);
		if (rc != 0)
			GOTO(stop, rc);

		dt_write_lock(env, child, MOR_TGT_CHILD);
		locked = true;
	}

	if (unlikely(lfsck_is_dead_obj(child)))
		GOTO(stop, rc = 0);

	rc = dt_attr_get(env, child, la, BYPASS_CAPA);
	if (rc == 0)
		rc = lfsck_links_read(env, child, &ldata);
	if (rc != 0) {
		if ((bk->lb_param & LPF_DRYRUN) &&
		    (rc == -EINVAL || rc == -ENODATA))
			rc = 1;

		GOTO(stop, rc);
	}

	linkea_first_entry(&ldata);
	while (ldata.ld_lee != NULL) {
		struct dt_object *parent = NULL;

		rc = lfsck_linkea_entry_unpack(lfsck, &ldata, cname, pfid);
		if (rc > 0)
			update = true;

		if (!fid_is_sane(pfid))
			goto shrink;

		parent = lfsck_object_find(env, lfsck, pfid);
		if (IS_ERR(parent))
			GOTO(stop, rc = PTR_ERR(parent));

		if (!dt_object_exists(parent))
			goto shrink;

		/* XXX: Currently, skip remote object, the consistency for
		 *	remote object will be processed in LFSCK phase III. */
		if (dt_object_remote(parent)) {
			lfsck_object_put(env, parent);
			linkea_next_entry(&ldata);
			continue;
		}

		if (unlikely(!dt_try_as_dir(env, parent)))
			goto shrink;

		/* To guarantee the 'name' is terminated with '0'. */
		memcpy(info->lti_key, cname->ln_name, cname->ln_namelen);
		info->lti_key[cname->ln_namelen] = 0;
		cname->ln_name = info->lti_key;
		rc = dt_lookup(env, parent, (struct dt_rec *)cfid,
			       (const struct dt_key *)cname->ln_name,
			       BYPASS_CAPA);
		if (rc != 0 && rc != -ENOENT) {
			lfsck_object_put(env, parent);
			GOTO(stop, rc);
		}

		if (rc == 0) {
			if (lu_fid_eq(cfid, lfsck_dto2fid(child))) {
				lfsck_object_put(env, parent);
				linkea_next_entry(&ldata);
				continue;
			}

			goto shrink;
		}

		/* If there is no name entry in the parent dir and the object
		 * link count is less than the linkea entries count, then the
		 * linkea entry should be removed. */
		if (ldata.ld_leh->leh_reccount > la->la_nlink)
			goto shrink;

		/* XXX: For the case of there is a linkea entry, but without
		 *	name entry pointing to the object and its hard links
		 *	count is not less than the object name entries count,
		 *	then seems we should add the 'missed' name entry back
		 *	to namespace, but before LFSCK phase III finished, we
		 *	do not know whether the object has some inconsistency
		 *	on other MDTs. So now, do NOT add the name entry back
		 *	to the namespace, but keep the linkEA entry. LU-2914 */
		lfsck_object_put(env, parent);
		linkea_next_entry(&ldata);
		continue;

shrink:
		if (parent != NULL)
			lfsck_object_put(env, parent);
		if (bk->lb_param & LPF_DRYRUN)
			RETURN(1);

		CDEBUG(D_LFSCK, "%s: namespace LFSCK remove invalid linkEA "
		      "for the object: "DFID", parent "DFID", name %.*s\n",
		      lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(child)),
		      PFID(pfid), cname->ln_namelen, cname->ln_name);

		linkea_del_buf(&ldata, cname);
		update = true;
	}

	if (update) {
		if (!com->lc_journal) {
			com->lc_journal = 1;
			goto again;
		}

		rc = lfsck_links_write(env, child, &ldata, handle);
	}

	GOTO(stop, rc);

stop:
	if (locked) {
	/* XXX: For the case linkea entries count does not match the object hard
	 *	links count, we cannot update the later one simply. Before LFSCK
	 *	phase III finished, we cannot know whether there are some remote
	 *	name entries to be repaired or not. LU-2914 */
		if (rc == 0 && !lfsck_is_dead_obj(child) &&
		    ldata.ld_leh != NULL &&
		    ldata.ld_leh->leh_reccount != la->la_nlink)
			CDEBUG(D_LFSCK, "%s: the object "DFID" linkEA entry "
			       "count %u may not match its hardlink count %u\n",
			       lfsck_lfsck2name(lfsck), PFID(cfid),
			       ldata.ld_leh->leh_reccount, la->la_nlink);

		dt_write_unlock(env, child);
	}

	if (handle != NULL)
		dt_trans_stop(env, lfsck->li_next, handle);

	if (rc == 0 && update) {
		ns->ln_objs_nlink_repaired++;
		rc = 1;
	}

	return rc;
}

/* namespace APIs */

static int lfsck_namespace_reset(const struct lu_env *env,
				 struct lfsck_component *com, bool init)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_namespace	*ns    = com->lc_file_ram;
	struct dt_object	*root;
	struct dt_object	*dto;
	int			 rc;
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
		__u64 last_time = ns->ln_time_last_complete;

		memset(ns, 0, sizeof(*ns));
		ns->ln_success_count = count;
		ns->ln_time_last_complete = last_time;
	}
	ns->ln_magic = LFSCK_NAMESPACE_MAGIC;
	ns->ln_status = LS_INIT;

	rc = local_object_unlink(env, lfsck->li_bottom, root,
				 lfsck_namespace_name);
	if (rc != 0)
		GOTO(out, rc);

	lfsck_object_put(env, com->lc_obj);
	com->lc_obj = NULL;
	dto = local_index_find_or_create(env, lfsck->li_los, root,
					 lfsck_namespace_name,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 &dt_lfsck_features);
	if (IS_ERR(dto))
		GOTO(out, rc = PTR_ERR(dto));

	com->lc_obj = dto;
	rc = dto->do_ops->do_index_try(env, dto, &dt_lfsck_features);
	if (rc != 0)
		GOTO(out, rc);

	rc = lfsck_namespace_store(env, com, true);

	GOTO(out, rc);

out:
	up_write(&com->lc_sem);

put:
	lu_object_put(env, &root->do_lu);
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
		ns->ln_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
		ns->ln_time_last_checkpoint = cfs_time_current_sec();
		ns->ln_items_checked += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_namespace_store(env, com, false);
	up_write(&com->lc_sem);

log:
	CDEBUG(D_LFSCK, "%s: namespace LFSCK checkpoint at the pos ["LPU64
	       ", "DFID", "LPX64"]: rc = %d\n", lfsck_lfsck2name(lfsck),
	       lfsck->li_pos_current.lp_oit_cookie,
	       PFID(&lfsck->li_pos_current.lp_dir_parent),
	       lfsck->li_pos_current.lp_dir_cookie, rc);

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

	if (ns->ln_status == LS_COMPLETED) {
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
	ns->ln_time_latest_start = cfs_time_current_sec();
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
			ns->ln_mlinked_checked = 0;
			ns->ln_objs_checked_phase2 = 0;
			ns->ln_objs_repaired_phase2 = 0;
			ns->ln_objs_failed_phase2 = 0;
			ns->ln_objs_nlink_repaired = 0;
			ns->ln_objs_lost_found = 0;
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

	CDEBUG(D_LFSCK, "%s: namespace LFSCK prep done, start pos ["LPU64", "
	       DFID", "LPX64"]: rc = %d\n",
	       lfsck_lfsck2name(lfsck), pos->lp_oit_cookie,
	       PFID(&pos->lp_dir_parent), pos->lp_dir_cookie, rc);

	return rc;
}

static int lfsck_namespace_exec_oit(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct dt_object *obj)
{
	down_write(&com->lc_sem);
	com->lc_new_checked++;
	if (S_ISDIR(lfsck_object_type(obj)))
		((struct lfsck_namespace *)com->lc_file_ram)->ln_dirs_checked++;
	up_write(&com->lc_sem);
	return 0;
}

static int lfsck_namespace_exec_dir(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct lu_dirent *ent, __u16 type)
{
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_namespace_req	*lnr;
	bool				 wakeup	= false;

	lnr = lfsck_namespace_assistant_req_init(com->lc_lfsck, ent, type);
	if (IS_ERR(lnr)) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		lfsck_namespace_record_failure(env, com->lc_lfsck, ns);
		return PTR_ERR(lnr);
	}

	spin_lock(&lad->lad_lock);
	if (lad->lad_assistant_status < 0) {
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
		wake_up_all(&lad->lad_thread.t_ctl_waitq);

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
		ns->ln_status = lfsck->li_status;
		if (ns->ln_status == 0)
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
		ns->ln_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
		ns->ln_time_last_checkpoint = cfs_time_current_sec();
		ns->ln_items_checked += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_namespace_store(env, com, false);
	up_write(&com->lc_sem);

	CDEBUG(D_LFSCK, "%s: namespace LFSCK post done: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);

	RETURN(rc);
}

static int
lfsck_namespace_dump(const struct lu_env *env, struct lfsck_component *com,
		     struct seq_file *m)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_bookmark	*bk    = &lfsck->li_bookmark_ram;
	struct lfsck_namespace	*ns    = com->lc_file_ram;
	int			 rc;

	down_read(&com->lc_sem);
	seq_printf(m, "name: lfsck_namespace\n"
		   "magic: %#x\n"
		   "version: %d\n"
		   "status: %s\n",
		   ns->ln_magic,
		   bk->lb_version,
		   lfsck_status2names(ns->ln_status));

	rc = lfsck_bits_dump(m, ns->ln_flags, lfsck_flags_names, "flags");
	if (rc < 0)
		goto out;

	rc = lfsck_bits_dump(m, bk->lb_param, lfsck_param_names, "param");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(m, ns->ln_time_last_complete,
			     "time_since_last_completed");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(m, ns->ln_time_latest_start,
			     "time_since_latest_start");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(m, ns->ln_time_last_checkpoint,
			     "time_since_last_checkpoint");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(m, &ns->ln_pos_latest_start,
			    "latest_start_position");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(m, &ns->ln_pos_last_checkpoint,
			    "last_checkpoint_position");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(m, &ns->ln_pos_first_inconsistent,
			    "first_failure_position");
	if (rc < 0)
		goto out;

	if (ns->ln_status == LS_SCANNING_PHASE1) {
		struct lfsck_position pos;
		const struct dt_it_ops *iops;
		cfs_duration_t duration = cfs_time_current() -
					  lfsck->li_time_last_checkpoint;
		__u64 checked = ns->ln_items_checked + com->lc_new_checked;
		__u64 speed = checked;
		__u64 new_checked = com->lc_new_checked * HZ;
		__u32 rtime = ns->ln_run_time_phase1 +
			      cfs_duration_sec(duration + HALF_SEC);

		if (duration != 0)
			do_div(new_checked, duration);
		if (rtime != 0)
			do_div(speed, rtime);
		seq_printf(m, "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "directories: "LPU64"\n"
			      "multi_linked_files: "LPU64"\n"
			      "dirent_repaired: "LPU64"\n"
			      "linkea_repaired: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: N/A\n"
			      "real_time_speed_phase1: "LPU64" items/sec\n"
			      "real_time_speed_phase2: N/A\n",
			      checked,
			      ns->ln_objs_checked_phase2,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_dirent_repaired,
			      ns->ln_linkea_repaired,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      rtime,
			      ns->ln_run_time_phase2,
			      speed,
			      new_checked);

		LASSERT(lfsck->li_di_oit != NULL);

		iops = &lfsck->li_obj_oit->do_index_ops->dio_it;

		/* The low layer otable-based iteration position may NOT
		 * exactly match the namespace-based directory traversal
		 * cookie. Generally, it is not a serious issue. But the
		 * caller should NOT make assumption on that. */
		pos.lp_oit_cookie = iops->store(env, lfsck->li_di_oit);
		if (!lfsck->li_current_oit_processed)
			pos.lp_oit_cookie--;

		spin_lock(&lfsck->li_lock);
		if (lfsck->li_di_dir != NULL) {
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
		lfsck_pos_dump(m, &pos, "current_position");
	} else if (ns->ln_status == LS_SCANNING_PHASE2) {
		cfs_duration_t duration = cfs_time_current() -
					  lfsck->li_time_last_checkpoint;
		__u64 checked = ns->ln_objs_checked_phase2 +
				com->lc_new_checked;
		__u64 speed1 = ns->ln_items_checked;
		__u64 speed2 = checked;
		__u64 new_checked = com->lc_new_checked * HZ;
		__u32 rtime = ns->ln_run_time_phase2 +
			      cfs_duration_sec(duration + HALF_SEC);

		if (duration != 0)
			do_div(new_checked, duration);
		if (ns->ln_run_time_phase1 != 0)
			do_div(speed1, ns->ln_run_time_phase1);
		if (rtime != 0)
			do_div(speed2, rtime);
		seq_printf(m, "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "directories: "LPU64"\n"
			      "multi_linked_files: "LPU64"\n"
			      "dirent_repaired: "LPU64"\n"
			      "linkea_repaired: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: "LPU64" objs/sec\n"
			      "real_time_speed_phase1: N/A\n"
			      "real_time_speed_phase2: "LPU64" objs/sec\n"
			      "current_position: "DFID"\n",
			      ns->ln_items_checked,
			      checked,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_dirent_repaired,
			      ns->ln_linkea_repaired,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      ns->ln_run_time_phase1,
			      rtime,
			      speed1,
			      speed2,
			      new_checked,
			      PFID(&ns->ln_fid_latest_scanned_phase2));
	} else {
		__u64 speed1 = ns->ln_items_checked;
		__u64 speed2 = ns->ln_objs_checked_phase2;

		if (ns->ln_run_time_phase1 != 0)
			do_div(speed1, ns->ln_run_time_phase1);
		if (ns->ln_run_time_phase2 != 0)
			do_div(speed2, ns->ln_run_time_phase2);
		seq_printf(m, "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "directories: "LPU64"\n"
			      "multi_linked_files: "LPU64"\n"
			      "dirent_repaired: "LPU64"\n"
			      "linkea_repaired: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: "LPU64" objs/sec\n"
			      "real_time_speed_phase1: N/A\n"
			      "real_time_speed_phase2: N/A\n"
			      "current_position: N/A\n",
			      ns->ln_items_checked,
			      ns->ln_objs_checked_phase2,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_dirent_repaired,
			      ns->ln_linkea_repaired,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      ns->ln_run_time_phase1,
			      ns->ln_run_time_phase2,
			      speed1,
			      speed2);
	}
out:
	up_read(&com->lc_sem);
	return 0;
}

static int lfsck_namespace_double_scan(const struct lu_env *env,
				       struct lfsck_component *com)
{
	struct lfsck_namespace *ns = com->lc_file_ram;

	return lfsck_double_scan_generic(env, com, ns->ln_status);
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

	CFS_FREE_BITMAP(lad->lad_bitmap);

	OBD_FREE_PTR(lad);
}

static int lfsck_namespace_in_notify(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct lfsck_request *lr)
{
	struct lfsck_instance		*lfsck = com->lc_lfsck;
	struct lfsck_namespace		*ns    = com->lc_file_ram;
	struct lfsck_assistant_data	*lad   = com->lc_data;
	struct lfsck_tgt_descs		*ltds  = &lfsck->li_mdt_descs;
	struct lfsck_tgt_desc		*ltd;
	bool				 fail  = false;
	ENTRY;

	if (lr->lr_event != LE_PHASE1_DONE &&
	    lr->lr_event != LE_PHASE2_DONE &&
	    lr->lr_event != LE_PEER_EXIT)
		RETURN(-EINVAL);

	CDEBUG(D_LFSCK, "%s: namespace LFSCK handles notify %u from MDT %x, "
	       "status %d\n", lfsck_lfsck2name(lfsck), lr->lr_event,
	       lr->lr_index, lr->lr_status);

	spin_lock(&ltds->ltd_lock);
	ltd = LTD_TGT(ltds, lr->lr_index);
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
		wake_up_all(&lad->lad_thread.t_ctl_waitq);
	}

	RETURN(0);
}

static int lfsck_namespace_query(const struct lu_env *env,
				 struct lfsck_component *com)
{
	struct lfsck_namespace *ns = com->lc_file_ram;

	return ns->ln_status;
}

static struct lfsck_operations lfsck_namespace_ops = {
	.lfsck_reset		= lfsck_namespace_reset,
	.lfsck_fail		= lfsck_namespace_fail,
	.lfsck_checkpoint	= lfsck_namespace_checkpoint,
	.lfsck_prep		= lfsck_namespace_prep,
	.lfsck_exec_oit		= lfsck_namespace_exec_oit,
	.lfsck_exec_dir		= lfsck_namespace_exec_dir,
	.lfsck_post		= lfsck_namespace_post,
	.lfsck_dump		= lfsck_namespace_dump,
	.lfsck_double_scan	= lfsck_namespace_double_scan,
	.lfsck_data_release	= lfsck_namespace_data_release,
	.lfsck_quit		= lfsck_quit_generic,
	.lfsck_in_notify	= lfsck_namespace_in_notify,
	.lfsck_query		= lfsck_namespace_query,
};

static int lfsck_namespace_assistant_handler_p1(const struct lu_env *env,
						struct lfsck_component *com,
						struct lfsck_assistant_req *lar)
{
	struct lfsck_thread_info   *info     = lfsck_env_info(env);
	struct lu_attr		   *la	     = &info->lti_la;
	struct lfsck_instance	   *lfsck    = com->lc_lfsck;
	struct lfsck_bookmark	   *bk	     = &lfsck->li_bookmark_ram;
	struct lfsck_namespace	   *ns	     = com->lc_file_ram;
	struct linkea_data	    ldata    = { 0 };
	const struct lu_name	   *cname;
	struct thandle		   *handle   = NULL;
	struct lfsck_namespace_req *lnr      =
			container_of0(lar, struct lfsck_namespace_req, lnr_lar);
	struct dt_object	   *dir      = lnr->lnr_obj;
	struct dt_object	   *obj      = NULL;
	const struct lu_fid	   *pfid     = lfsck_dto2fid(dir);
	bool			    repaired = false;
	bool			    locked   = false;
	bool			    remove;
	bool			    newdata;
	bool			    log      = false;
	int			    count    = 0;
	int			    rc;
	ENTRY;

	if (lnr->lnr_attr & LUDA_UPGRADE) {
		ns->ln_flags |= LF_UPGRADE;
		ns->ln_dirent_repaired++;
		repaired = true;
	} else if (lnr->lnr_attr & LUDA_REPAIR) {
		ns->ln_flags |= LF_INCONSISTENT;
		ns->ln_dirent_repaired++;
		repaired = true;
	}

	if (lnr->lnr_name[0] == '.' &&
	    (lnr->lnr_namelen == 1 ||
	     (lnr->lnr_namelen == 2 && lnr->lnr_name[1] == '.') ||
	     fid_seq_is_dot(fid_seq(&lnr->lnr_fid))))
		GOTO(out, rc = 0);

	obj = lfsck_object_find(env, lfsck, &lnr->lnr_fid);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	if (dt_object_exists(obj) == 0) {
		rc = lfsck_namespace_check_exist(env, dir, obj, lnr->lnr_name);
		if (rc != 0)
			GOTO(out, rc);

		/* XXX: dangling name entry, will handle it in other patch. */
		GOTO(out, rc);
	}

	cname = lfsck_name_get_const(env, lnr->lnr_name, lnr->lnr_namelen);
	if (!(bk->lb_param & LPF_DRYRUN) &&
	    (com->lc_journal || repaired)) {

again:
		LASSERT(!locked);

		com->lc_journal = 1;
		handle = dt_trans_create(env, lfsck->li_next);
		if (IS_ERR(handle))
			GOTO(out, rc = PTR_ERR(handle));

		rc = lfsck_declare_namespace_exec_dir(env, obj, handle);
		if (rc != 0)
			GOTO(stop, rc);

		rc = dt_trans_start(env, lfsck->li_next, handle);
		if (rc != 0)
			GOTO(stop, rc);

		dt_write_lock(env, obj, MOR_TGT_CHILD);
		locked = true;
	}

	rc = lfsck_namespace_check_exist(env, dir, obj, lnr->lnr_name);
	if (rc != 0)
		GOTO(stop, rc);

	rc = lfsck_links_read(env, obj, &ldata);
	if (rc == 0) {
		count = ldata.ld_leh->leh_reccount;
		rc = linkea_links_find(&ldata, cname, pfid);
		if ((rc == 0) &&
		    (count == 1 || !S_ISDIR(lfsck_object_type(obj))))
			goto record;

		ns->ln_flags |= LF_INCONSISTENT;
		/* For dir, if there are more than one linkea entries, or the
		 * linkea entry does not match the name entry, then remove all
		 * and add the correct one. */
		if (S_ISDIR(lfsck_object_type(obj))) {
			remove = true;
			newdata = true;
		} else {
			remove = false;
			newdata = false;
		}
		goto nodata;
	} else if (unlikely(rc == -EINVAL)) {
		count = 1;
		ns->ln_flags |= LF_INCONSISTENT;
		/* The magic crashed, we are not sure whether there are more
		 * corrupt data in the linkea, so remove all linkea entries. */
		remove = true;
		newdata = true;
		goto nodata;
	} else if (rc == -ENODATA) {
		count = 1;
		ns->ln_flags |= LF_UPGRADE;
		remove = false;
		newdata = true;

nodata:
		if (bk->lb_param & LPF_DRYRUN) {
			ns->ln_linkea_repaired++;
			repaired = true;
			log = true;
			goto record;
		}

		if (!com->lc_journal)
			goto again;

		if (remove) {
			LASSERT(newdata);

			rc = dt_xattr_del(env, obj, XATTR_NAME_LINK, handle,
					  BYPASS_CAPA);
			if (rc != 0)
				GOTO(stop, rc);
		}

		if (newdata) {
			rc = linkea_data_new(&ldata,
					&lfsck_env_info(env)->lti_linkea_buf);
			if (rc != 0)
				GOTO(stop, rc);
		}

		rc = linkea_add_buf(&ldata, cname, pfid);
		if (rc != 0)
			GOTO(stop, rc);

		rc = lfsck_links_write(env, obj, &ldata, handle);
		if (rc != 0)
			GOTO(stop, rc);

		count = ldata.ld_leh->leh_reccount;
		ns->ln_linkea_repaired++;
		repaired = true;
		log = true;
	} else {
		GOTO(stop, rc);
	}

record:
	LASSERT(count > 0);

	rc = dt_attr_get(env, obj, la, BYPASS_CAPA);
	if (rc != 0)
		GOTO(stop, rc);

	if ((count == 1) &&
	    (la->la_nlink == 1 || S_ISDIR(lfsck_object_type(obj))))
		/* Usually, it is for single linked object or dir, do nothing.*/
		GOTO(stop, rc);

	/* Following modification will be in another transaction.  */
	if (handle != NULL) {
		LASSERT(dt_write_locked(env, obj));

		dt_write_unlock(env, obj);
		locked = false;

		dt_trans_stop(env, lfsck->li_next, handle);
		handle = NULL;
	}

	ns->ln_mlinked_checked++;
	rc = lfsck_namespace_update(env, com, &lnr->lnr_fid,
			count != la->la_nlink ? LLF_UNMATCH_NLINKS : 0, false);

	GOTO(out, rc);

stop:
	if (locked)
		dt_write_unlock(env, obj);

	if (handle != NULL)
		dt_trans_stop(env, lfsck->li_next, handle);

out:
	down_write(&com->lc_sem);
	if (rc < 0) {
		CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant fail to handle "
		       "the entry: "DFID", parent "DFID", name %.*s: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(&lnr->lnr_fid),
		       PFID(lfsck_dto2fid(lnr->lnr_obj)),
		       lnr->lnr_namelen, lnr->lnr_name, rc);

		lfsck_namespace_record_failure(env, lfsck, ns);
		if (!(bk->lb_param & LPF_FAILOUT))
			rc = 0;
	} else {
		if (log)
			CDEBUG(D_LFSCK, "%s: namespace LFSCK assistant "
			       "repaired the entry: "DFID", parent "DFID
			       ", name %.*s\n", lfsck_lfsck2name(lfsck),
			       PFID(&lnr->lnr_fid),
			       PFID(lfsck_dto2fid(lnr->lnr_obj)),
			       lnr->lnr_namelen, lnr->lnr_name);

		if (repaired) {
			ns->ln_items_repaired++;
			if (bk->lb_param & LPF_DRYRUN &&
			    lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent))
				lfsck_pos_fill(env, lfsck,
					       &ns->ln_pos_first_inconsistent,
					       false);
		} else {
			com->lc_journal = 0;
		}
		rc = 0;
	}
	up_write(&com->lc_sem);

	if (obj != NULL && !IS_ERR(obj))
		lfsck_object_put(env, obj);
	return rc;
}

static int lfsck_namespace_assistant_handler_p2(const struct lu_env *env,
						struct lfsck_component *com)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct ptlrpc_thread	*thread = &lfsck->li_thread;
	struct lfsck_bookmark	*bk	= &lfsck->li_bookmark_ram;
	struct lfsck_namespace	*ns	= com->lc_file_ram;
	struct dt_object	*obj	= com->lc_obj;
	const struct dt_it_ops	*iops	= &obj->do_index_ops->dio_it;
	struct dt_object	*target;
	struct dt_it		*di;
	struct dt_key		*key;
	struct lu_fid		 fid;
	int			 rc;
	__u8			 flags = 0;
	ENTRY;

	CDEBUG(D_LFSCK, "%s: namespace LFSCK phase2 scan start\n",
	       lfsck_lfsck2name(lfsck));

	com->lc_new_checked = 0;
	com->lc_new_scanned = 0;
	com->lc_time_last_checkpoint = cfs_time_current();
	com->lc_time_next_checkpoint = com->lc_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);

	di = iops->init(env, obj, 0, BYPASS_CAPA);
	if (IS_ERR(di))
		RETURN(PTR_ERR(di));

	fid_cpu_to_be(&fid, &ns->ln_fid_latest_scanned_phase2);
	rc = iops->get(env, di, (const struct dt_key *)&fid);
	if (rc < 0)
		GOTO(fini, rc);

	/* Skip the start one, which either has been processed or non-exist. */
	rc = iops->next(env, di);
	if (rc != 0)
		GOTO(put, rc);

	do {
		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DELAY3) &&
		    cfs_fail_val > 0) {
			struct l_wait_info lwi;

			lwi = LWI_TIMEOUT(cfs_time_seconds(cfs_fail_val),
					  NULL, NULL);
			l_wait_event(thread->t_ctl_waitq,
				     !thread_is_running(thread),
				     &lwi);
		}

		key = iops->key(env, di);
		fid_be_to_cpu(&fid, (const struct lu_fid *)key);
		target = lfsck_object_find(env, lfsck, &fid);
		down_write(&com->lc_sem);
		if (IS_ERR(target)) {
			rc = PTR_ERR(target);
			goto checkpoint;
		}

		/* XXX: Currently, skip remote object, the consistency for
		 *	remote object will be processed in LFSCK phase III. */
		if (dt_object_exists(target) && !dt_object_remote(target)) {
			rc = iops->rec(env, di, (struct dt_rec *)&flags, 0);
			if (rc == 0)
				rc = lfsck_namespace_double_scan_one(env, com,
								target, flags);
		}

		lfsck_object_put(env, target);

checkpoint:
		com->lc_new_checked++;
		com->lc_new_scanned++;
		ns->ln_fid_latest_scanned_phase2 = fid;
		if (rc > 0)
			ns->ln_objs_repaired_phase2++;
		else if (rc < 0)
			ns->ln_objs_failed_phase2++;
		up_write(&com->lc_sem);

		if ((rc == 0) || ((rc > 0) && !(bk->lb_param & LPF_DRYRUN))) {
			lfsck_namespace_delete(env, com, &fid);
		} else if (rc < 0) {
			flags |= LLF_REPAIR_FAILED;
			lfsck_namespace_update(env, com, &fid, flags, true);
		}

		if (rc < 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(put, rc);

		if (unlikely(cfs_time_beforeq(com->lc_time_next_checkpoint,
					      cfs_time_current())) &&
		    com->lc_new_checked != 0) {
			down_write(&com->lc_sem);
			ns->ln_run_time_phase2 +=
				cfs_duration_sec(cfs_time_current() +
				HALF_SEC - com->lc_time_last_checkpoint);
			ns->ln_time_last_checkpoint = cfs_time_current_sec();
			ns->ln_objs_checked_phase2 += com->lc_new_checked;
			com->lc_new_checked = 0;
			rc = lfsck_namespace_store(env, com, false);
			up_write(&com->lc_sem);
			if (rc != 0)
				GOTO(put, rc);

			com->lc_time_last_checkpoint = cfs_time_current();
			com->lc_time_next_checkpoint =
				com->lc_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);
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

static void lfsck_namespace_assistant_fill_pos(const struct lu_env *env,
					       struct lfsck_component *com,
					       struct lfsck_position *pos)
{
	struct lfsck_assistant_data	*lad = com->lc_data;
	struct lfsck_namespace_req	*lnr;

	if (list_empty(&lad->lad_req_list))
		return;

	lnr = list_entry(lad->lad_req_list.next,
			 struct lfsck_namespace_req,
			 lnr_lar.lar_list);
	pos->lp_oit_cookie = lnr->lnr_oit_cookie;
	pos->lp_dir_cookie = lnr->lnr_dir_cookie - 1;
	pos->lp_dir_parent = *lfsck_dto2fid(lnr->lnr_obj);
}

static int lfsck_namespace_double_scan_result(const struct lu_env *env,
					      struct lfsck_component *com,
					      int rc)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_namespace	*ns	= com->lc_file_ram;

	down_write(&com->lc_sem);
	ns->ln_run_time_phase2 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
	ns->ln_time_last_checkpoint = cfs_time_current_sec();
	ns->ln_objs_checked_phase2 += com->lc_new_checked;
	com->lc_new_checked = 0;

	if (rc > 0) {
		com->lc_journal = 0;
		if (ns->ln_flags & LF_INCOMPLETE)
			ns->ln_status = LS_PARTIAL;
		else
			ns->ln_status = LS_COMPLETED;
		if (!(lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN))
			ns->ln_flags &= ~(LF_SCANNED_ONCE | LF_INCONSISTENT);
		ns->ln_time_last_complete = ns->ln_time_last_checkpoint;
		ns->ln_success_count++;
	} else if (rc == 0) {
		ns->ln_status = lfsck->li_status;
		if (ns->ln_status == 0)
			ns->ln_status = LS_STOPPED;
	} else {
		ns->ln_status = LS_FAILED;
	}

	rc = lfsck_namespace_store(env, com, false);
	up_write(&com->lc_sem);

	return rc;
}

static void lfsck_namespace_assistant_sync_failures(const struct lu_env *env,
						    struct lfsck_component *com,
						    struct lfsck_request *lr)
{
	/* XXX: TBD */
}

struct lfsck_assistant_operations lfsck_namespace_assistant_ops = {
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
 * \param[in] dev	pointer to the dt_device
 * \param[in] obj	pointer to the dt_object to be handled
 * \param[in] cname	the name for the child in the parent directory
 * \param[in] pfid	the parent directory's FID for the linkEA
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_verify_linkea(const struct lu_env *env, struct dt_device *dev,
			struct dt_object *obj, const struct lu_name *cname,
			const struct lu_fid *pfid)
{
	struct linkea_data	 ldata	= { 0 };
	struct lu_buf		 linkea_buf;
	struct thandle		*th;
	int			 rc;
	int			 fl	= LU_XATTR_CREATE;
	bool			 dirty	= false;
	ENTRY;

	LASSERT(S_ISDIR(lfsck_object_type(obj)));

	rc = lfsck_links_read(env, obj, &ldata);
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

	rc = linkea_data_new(&ldata, &lfsck_env_info(env)->lti_linkea_buf);
	if (rc != 0)
		RETURN(rc);

	rc = linkea_add_buf(&ldata, cname, pfid);
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
		GOTO(stop, rc = PTR_ERR(th));

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	rc = dt_xattr_set(env, obj, &linkea_buf,
			  XATTR_NAME_LINK, fl, th, BYPASS_CAPA);
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
	struct linkea_data	  ldata = { 0 };
	int			  rc;

	rc = lfsck_links_read(env, obj, &ldata);
	if (rc != 0)
		return rc;

	linkea_first_entry(&ldata);
	if (ldata.ld_lee == NULL)
		return -ENODATA;

	linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen, cname, pfid);
	/* To guarantee the 'name' is terminated with '0'. */
	memcpy(name, cname->ln_name, cname->ln_namelen);
	name[cname->ln_namelen] = 0;

	return 0;
}

/**
 * Remove the name entry from the parent directory.
 *
 * No need to care about the object referenced by the name entry,
 * either the name entry is invalid or redundant, or the referenced
 * object has been processed has been or will be handled by others.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 * \param[in] parent	pointer to the lost+found object
 * \param[in] name	the name for the name entry to be removed
 * \param[in] type	the type for the name entry to be removed
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_remove_name_entry(const struct lu_env *env,
			    struct lfsck_instance *lfsck,
			    struct dt_object *parent,
			    const char *name, __u32 type)
{
	struct dt_device	*dev	= lfsck->li_next;
	struct thandle		*th;
	struct lustre_handle	 lh	= { 0 };
	int			 rc;
	ENTRY;

	rc = lfsck_ibits_lock(env, lfsck, parent, &lh,
			      MDS_INODELOCK_UPDATE, LCK_EX);
	if (rc != 0)
		RETURN(rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, parent, (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	if (S_ISDIR(type)) {
		rc = dt_declare_ref_del(env, parent, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	rc = dt_trans_start(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_delete(env, parent, (const struct dt_key *)name, th,
		       BYPASS_CAPA);
	if (rc != 0)
		GOTO(stop, rc);

	if (S_ISDIR(type)) {
		dt_write_lock(env, parent, 0);
		rc = dt_ref_del(env, parent, th);
		dt_write_unlock(env, parent);
	}

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);

unlock:
	lfsck_ibits_unlock(&lh, LCK_EX);

	CDEBUG(D_LFSCK, "%s: remove name entry "DFID"/%s "
	       "with type %o: rc = %d\n", lfsck_lfsck2name(lfsck),
	       PFID(lfsck_dto2fid(parent)), name, type, rc);

	return rc;
}

/**
 * Update the object's name entry with the given FID.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 * \param[in] parent	pointer to the parent directory that holds
 *			the name entry
 * \param[in] name	the name for the entry to be updated
 * \param[in] pfid	the new PFID for the name entry
 * \param[in] type	the type for the name entry to be updated
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_update_name_entry(const struct lu_env *env,
			    struct lfsck_instance *lfsck,
			    struct dt_object *parent, const char *name,
			    const struct lu_fid *pfid, __u32 type)
{
	struct dt_insert_rec	*rec	= &lfsck_env_info(env)->lti_dt_rec;
	struct dt_device	*dev	= lfsck->li_next;
	struct lustre_handle	 lh	= { 0 };
	struct thandle		*th;
	int			 rc;
	bool			 exists = true;
	ENTRY;

	rc = lfsck_ibits_lock(env, lfsck, parent, &lh,
			      MDS_INODELOCK_UPDATE, LCK_EX);
	if (rc != 0)
		RETURN(rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, parent, (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rec->rec_type = type;
	rec->rec_fid = pfid;
	rc = dt_declare_insert(env, parent, (const struct dt_rec *)rec,
			       (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_ref_add(env, parent, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_delete(env, parent, (const struct dt_key *)name, th,
		       BYPASS_CAPA);
	if (rc == -ENOENT) {
		exists = false;
		rc = 0;
	}

	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_insert(env, parent, (const struct dt_rec *)rec,
		       (const struct dt_key *)name, th, BYPASS_CAPA, 1);
	if (rc == 0 && S_ISDIR(type) && !exists) {
		dt_write_lock(env, parent, 0);
		rc = dt_ref_add(env, parent, th);
		dt_write_unlock(env, parent);
	}

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);

unlock:
	lfsck_ibits_unlock(&lh, LCK_EX);

	CDEBUG(D_LFSCK, "%s: update name entry "DFID"/%s with the FID "DFID
	       " and the type %o: rc = %d\n", lfsck_lfsck2name(lfsck),
	       PFID(lfsck_dto2fid(parent)), name, PFID(pfid), type, rc);

	return rc;
}

int lfsck_namespace_setup(const struct lu_env *env,
			  struct lfsck_instance *lfsck)
{
	struct lfsck_component	*com;
	struct lfsck_namespace	*ns;
	struct dt_object	*root = NULL;
	struct dt_object	*obj;
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
			"lfsck_namespace");
	if (com->lc_data == NULL)
		GOTO(out, rc = -ENOMEM);

	com->lc_file_size = sizeof(struct lfsck_namespace);
	OBD_ALLOC(com->lc_file_ram, com->lc_file_size);
	if (com->lc_file_ram == NULL)
		GOTO(out, rc = -ENOMEM);

	OBD_ALLOC(com->lc_file_disk, com->lc_file_size);
	if (com->lc_file_disk == NULL)
		GOTO(out, rc = -ENOMEM);

	root = dt_locate(env, lfsck->li_bottom, &lfsck->li_local_root_fid);
	if (IS_ERR(root))
		GOTO(out, rc = PTR_ERR(root));

	if (unlikely(!dt_try_as_dir(env, root)))
		GOTO(out, rc = -ENOTDIR);

	obj = local_index_find_or_create(env, lfsck->li_los, root,
					 lfsck_namespace_name,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 &dt_lfsck_features);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	com->lc_obj = obj;
	rc = obj->do_ops->do_index_try(env, obj, &dt_lfsck_features);
	if (rc != 0)
		GOTO(out, rc);

	rc = lfsck_namespace_load(env, com);
	if (rc > 0)
		rc = lfsck_namespace_reset(env, com, true);
	else if (rc == -ENODATA)
		rc = lfsck_namespace_init(env, com);
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
		lu_object_put(env, &root->do_lu);
	if (rc != 0) {
		lfsck_component_cleanup(env, com);
		CERROR("%s: fail to init namespace LFSCK component: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);
	}
	return rc;
}
