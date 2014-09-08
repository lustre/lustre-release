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
#include <lustre_linkea.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre/lustre_user.h>

#include "lfsck_internal.h"

#define LFSCK_NAMESPACE_MAGIC	0xA0629D03

static const char lfsck_namespace_name[] = "lfsck_namespace";

static void lfsck_namespace_le_to_cpu(struct lfsck_namespace *des,
				      struct lfsck_namespace *src)
{
	des->ln_magic = le32_to_cpu(src->ln_magic);
	des->ln_status = le32_to_cpu(src->ln_status);
	des->ln_flags = le32_to_cpu(src->ln_flags);
	des->ln_success_count = le32_to_cpu(src->ln_success_count);
	des->ln_run_time_phase1 = le32_to_cpu(src->ln_run_time_phase1);
	des->ln_run_time_phase2 = le32_to_cpu(src->ln_run_time_phase2);
	des->ln_time_last_complete = le64_to_cpu(src->ln_time_last_complete);
	des->ln_time_latest_start = le64_to_cpu(src->ln_time_latest_start);
	des->ln_time_last_checkpoint =
				le64_to_cpu(src->ln_time_last_checkpoint);
	lfsck_position_le_to_cpu(&des->ln_pos_latest_start,
				 &src->ln_pos_latest_start);
	lfsck_position_le_to_cpu(&des->ln_pos_last_checkpoint,
				 &src->ln_pos_last_checkpoint);
	lfsck_position_le_to_cpu(&des->ln_pos_first_inconsistent,
				 &src->ln_pos_first_inconsistent);
	des->ln_items_checked = le64_to_cpu(src->ln_items_checked);
	des->ln_items_repaired = le64_to_cpu(src->ln_items_repaired);
	des->ln_items_failed = le64_to_cpu(src->ln_items_failed);
	des->ln_dirs_checked = le64_to_cpu(src->ln_dirs_checked);
	des->ln_mlinked_checked = le64_to_cpu(src->ln_mlinked_checked);
	des->ln_objs_checked_phase2 = le64_to_cpu(src->ln_objs_checked_phase2);
	des->ln_objs_repaired_phase2 =
				le64_to_cpu(src->ln_objs_repaired_phase2);
	des->ln_objs_failed_phase2 = le64_to_cpu(src->ln_objs_failed_phase2);
	des->ln_objs_nlink_repaired = le64_to_cpu(src->ln_objs_nlink_repaired);
	des->ln_objs_lost_found = le64_to_cpu(src->ln_objs_lost_found);
	fid_le_to_cpu(&des->ln_fid_latest_scanned_phase2,
		      &src->ln_fid_latest_scanned_phase2);
}

static void lfsck_namespace_cpu_to_le(struct lfsck_namespace *des,
				      struct lfsck_namespace *src)
{
	des->ln_magic = cpu_to_le32(src->ln_magic);
	des->ln_status = cpu_to_le32(src->ln_status);
	des->ln_flags = cpu_to_le32(src->ln_flags);
	des->ln_success_count = cpu_to_le32(src->ln_success_count);
	des->ln_run_time_phase1 = cpu_to_le32(src->ln_run_time_phase1);
	des->ln_run_time_phase2 = cpu_to_le32(src->ln_run_time_phase2);
	des->ln_time_last_complete = cpu_to_le64(src->ln_time_last_complete);
	des->ln_time_latest_start = cpu_to_le64(src->ln_time_latest_start);
	des->ln_time_last_checkpoint =
				cpu_to_le64(src->ln_time_last_checkpoint);
	lfsck_position_cpu_to_le(&des->ln_pos_latest_start,
				 &src->ln_pos_latest_start);
	lfsck_position_cpu_to_le(&des->ln_pos_last_checkpoint,
				 &src->ln_pos_last_checkpoint);
	lfsck_position_cpu_to_le(&des->ln_pos_first_inconsistent,
				 &src->ln_pos_first_inconsistent);
	des->ln_items_checked = cpu_to_le64(src->ln_items_checked);
	des->ln_items_repaired = cpu_to_le64(src->ln_items_repaired);
	des->ln_items_failed = cpu_to_le64(src->ln_items_failed);
	des->ln_dirs_checked = cpu_to_le64(src->ln_dirs_checked);
	des->ln_mlinked_checked = cpu_to_le64(src->ln_mlinked_checked);
	des->ln_objs_checked_phase2 = cpu_to_le64(src->ln_objs_checked_phase2);
	des->ln_objs_repaired_phase2 =
				cpu_to_le64(src->ln_objs_repaired_phase2);
	des->ln_objs_failed_phase2 = cpu_to_le64(src->ln_objs_failed_phase2);
	des->ln_objs_nlink_repaired = cpu_to_le64(src->ln_objs_nlink_repaired);
	des->ln_objs_lost_found = cpu_to_le64(src->ln_objs_lost_found);
	fid_cpu_to_le(&des->ln_fid_latest_scanned_phase2,
		      &src->ln_fid_latest_scanned_phase2);
}

/**
 * Load namespace LFSCK statistics information from the trace file.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 *
 * \retval		0 for success
 * \retval		negative error number on failure or absence the
 *			namespace LFSCK trace file
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
			CWARN("%.16s: invalid lfsck_namespace magic "
			      "0x%x != 0x%x\n",
			      lfsck_lfsck2name(com->lc_lfsck),
			      ns->ln_magic, LFSCK_NAMESPACE_MAGIC);
			rc = -ESTALE;
		} else {
			rc = 0;
		}
	} else {
		if (rc != -ENODATA)
			CERROR("%.16s: fail to load lfsck_namespace, "
			       "expected = %d, rc = %d\n",
			       lfsck_lfsck2name(com->lc_lfsck), len, rc);
		else if (rc > 0)
			rc = -ESTALE;
	}

	return rc;
}

static int lfsck_namespace_store(const struct lu_env *env,
				 struct lfsck_component *com)
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
	if (IS_ERR(handle)) {
		rc = PTR_ERR(handle);
		CERROR("%.16s: fail to create trans for storing "
		       "lfsck_namespace: %d\n,", lfsck_lfsck2name(lfsck), rc);
		RETURN(rc);
	}

	rc = dt_declare_xattr_set(env, obj,
				  lfsck_buf_get(env, com->lc_file_disk, len),
				  XATTR_NAME_LFSCK_NAMESPACE, 0, handle);
	if (rc != 0) {
		CERROR("%.16s: fail to declare trans for storing "
		       "lfsck_namespace: %d\n,", lfsck_lfsck2name(lfsck), rc);
		GOTO(out, rc);
	}

	rc = dt_trans_start_local(env, lfsck->li_bottom, handle);
	if (rc != 0) {
		CERROR("%.16s: fail to start trans for storing "
		       "lfsck_namespace: %d\n,", lfsck_lfsck2name(lfsck), rc);
		GOTO(out, rc);
	}

	rc = dt_xattr_set(env, obj,
			  lfsck_buf_get(env, com->lc_file_disk, len),
			  XATTR_NAME_LFSCK_NAMESPACE, 0,
			  handle, BYPASS_CAPA);
	if (rc != 0)
		CERROR("%.16s: fail to store lfsck_namespace, len = %d, "
		       "rc = %d\n", lfsck_lfsck2name(lfsck), len, rc);

	GOTO(out, rc);

out:
	dt_trans_stop(env, lfsck->li_bottom, handle);
	return rc;
}

static int lfsck_namespace_init(const struct lu_env *env,
				struct lfsck_component *com)
{
	struct lfsck_namespace *ns = (struct lfsck_namespace *)com->lc_file_ram;
	int rc;

	memset(ns, 0, sizeof(*ns));
	ns->ln_magic = LFSCK_NAMESPACE_MAGIC;
	ns->ln_status = LS_INIT;
	down_write(&com->lc_sem);
	rc = lfsck_namespace_store(env, com);
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
		if (rc != 0) {
			CERROR("%s: fail to insert "DFID", rc = %d\n",
			       lfsck_lfsck2name(com->lc_lfsck), PFID(fid), rc);
			GOTO(out, rc);
		}
	}

	rc = dt_insert(env, obj, (const struct dt_rec *)&flags,
		       (const struct dt_key *)key, handle, BYPASS_CAPA, 1);

	GOTO(out, rc);

out:
	dt_trans_stop(env, lfsck->li_bottom, handle);
	return rc;
}

static int lfsck_namespace_check_exist(const struct lu_env *env,
				       struct lfsck_instance *lfsck,
				       struct dt_object *obj, const char *name)
{
	struct dt_object *dir = lfsck->li_obj_dir;
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
	struct lfsck_namespace	*ns	  =
				(struct lfsck_namespace *)com->lc_file_ram;
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
		if (parent == NULL)
			goto shrink;
		else if (IS_ERR(parent))
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

		CDEBUG(D_LFSCK, "Remove linkEA: "DFID"[%.*s], "DFID"\n",
		       PFID(lfsck_dto2fid(child)), cname->ln_namelen, cname->ln_name,
		       PFID(pfid));
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
			CWARN("%.16s: the object "DFID" linkEA entry count %u "
			      "may not match its hardlink count %u\n",
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
	struct lfsck_namespace	*ns    =
				(struct lfsck_namespace *)com->lc_file_ram;
	struct dt_object	*root;
	struct dt_object	*dto;
	int			 rc;
	ENTRY;

	root = dt_locate(env, lfsck->li_bottom, &lfsck->li_local_root_fid);
	if (IS_ERR(root))
		RETURN(PTR_ERR(root));

	dt_try_as_dir(env, root);

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

	rc = lfsck_namespace_store(env, com);

	GOTO(out, rc);

out:
	up_write(&com->lc_sem);
	lu_object_put(env, &root->do_lu);
	return rc;
}

static void
lfsck_namespace_fail(const struct lu_env *env, struct lfsck_component *com,
		     bool new_checked)
{
	struct lfsck_namespace *ns = (struct lfsck_namespace *)com->lc_file_ram;

	down_write(&com->lc_sem);
	if (new_checked)
		com->lc_new_checked++;
	ns->ln_items_failed++;
	if (lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent))
		lfsck_pos_fill(env, com->lc_lfsck,
			       &ns->ln_pos_first_inconsistent, false);
	up_write(&com->lc_sem);
}

static int lfsck_namespace_checkpoint(const struct lu_env *env,
				      struct lfsck_component *com, bool init)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_namespace	*ns    =
				(struct lfsck_namespace *)com->lc_file_ram;
	int			 rc;

	if (com->lc_new_checked == 0 && !init)
		return 0;

	down_write(&com->lc_sem);

	if (init) {
		ns->ln_pos_latest_start = lfsck->li_pos_current;
	} else {
		ns->ln_pos_last_checkpoint = lfsck->li_pos_current;
		ns->ln_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
		ns->ln_time_last_checkpoint = cfs_time_current_sec();
		ns->ln_items_checked += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_namespace_store(env, com);

	up_write(&com->lc_sem);
	return rc;
}

static int lfsck_namespace_prep(const struct lu_env *env,
				struct lfsck_component *com)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_namespace	*ns	=
				(struct lfsck_namespace *)com->lc_file_ram;
	struct lfsck_position	*pos	= &com->lc_pos_start;

	if (ns->ln_status == LS_COMPLETED) {
		int rc;

		rc = lfsck_namespace_reset(env, com, false);
		if (rc != 0)
			return rc;
	}

	down_write(&com->lc_sem);

	ns->ln_time_latest_start = cfs_time_current_sec();

	spin_lock(&lfsck->li_lock);
	if (ns->ln_flags & LF_SCANNED_ONCE) {
		if (!lfsck->li_drop_dryrun ||
		    lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent)) {
			ns->ln_status = LS_SCANNING_PHASE2;
			cfs_list_del_init(&com->lc_link);
			cfs_list_add_tail(&com->lc_link,
					  &lfsck->li_list_double_scan);
			if (!cfs_list_empty(&com->lc_link_dir))
				cfs_list_del_init(&com->lc_link_dir);
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
			if (cfs_list_empty(&com->lc_link_dir))
				cfs_list_add_tail(&com->lc_link_dir,
						  &lfsck->li_list_dir);
			*pos = ns->ln_pos_first_inconsistent;
		}
	} else {
		ns->ln_status = LS_SCANNING_PHASE1;
		if (cfs_list_empty(&com->lc_link_dir))
			cfs_list_add_tail(&com->lc_link_dir,
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
	return 0;
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
				    struct dt_object *obj,
				    struct lu_dirent *ent)
{
	struct lfsck_thread_info   *info     = lfsck_env_info(env);
	struct lu_attr		   *la	     = &info->lti_la;
	struct lfsck_instance	   *lfsck    = com->lc_lfsck;
	struct lfsck_bookmark	   *bk	     = &lfsck->li_bookmark_ram;
	struct lfsck_namespace	   *ns	     =
				(struct lfsck_namespace *)com->lc_file_ram;
	struct linkea_data	    ldata    = { 0 };
	const struct lu_fid	   *pfid     =
				lu_object_fid(&lfsck->li_obj_dir->do_lu);
	const struct lu_fid	   *cfid     = lfsck_dto2fid(obj);
	const struct lu_name	   *cname;
	struct thandle		   *handle   = NULL;
	bool			    repaired = false;
	bool			    locked   = false;
	bool			    remove;
	bool			    newdata;
	int			    count    = 0;
	int			    rc;
	ENTRY;

	cname = lfsck_name_get_const(env, ent->lde_name, ent->lde_namelen);
	down_write(&com->lc_sem);
	com->lc_new_checked++;

	if (ent->lde_attrs & LUDA_UPGRADE) {
		ns->ln_flags |= LF_UPGRADE;
		repaired = true;
	} else if (ent->lde_attrs & LUDA_REPAIR) {
		ns->ln_flags |= LF_INCONSISTENT;
		repaired = true;
	}

	if (ent->lde_name[0] == '.' &&
	    (ent->lde_namelen == 1 ||
	     (ent->lde_namelen == 2 && ent->lde_name[1] == '.') ||
	     fid_is_dot_lustre(&ent->lde_fid)))
		GOTO(out, rc = 0);

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

	rc = lfsck_namespace_check_exist(env, lfsck, obj, ent->lde_name);
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
			repaired = true;
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
		repaired = true;
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
	rc = lfsck_namespace_update(env, com, cfid,
			count != la->la_nlink ? LLF_UNMATCH_NLINKS : 0, false);

	GOTO(out, rc);

stop:
	if (locked)
		dt_write_unlock(env, obj);

	if (handle != NULL)
		dt_trans_stop(env, lfsck->li_next, handle);

out:
	if (rc < 0) {
		ns->ln_items_failed++;
		if (lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent))
			lfsck_pos_fill(env, lfsck,
				       &ns->ln_pos_first_inconsistent, false);
		if (!(bk->lb_param & LPF_FAILOUT))
			rc = 0;
	} else {
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
	return rc;
}

static int lfsck_namespace_post(const struct lu_env *env,
				struct lfsck_component *com,
				int result, bool init)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_namespace	*ns    =
				(struct lfsck_namespace *)com->lc_file_ram;
	int			 rc;

	down_write(&com->lc_sem);

	spin_lock(&lfsck->li_lock);
	if (!init)
		ns->ln_pos_last_checkpoint = lfsck->li_pos_current;
	if (result > 0) {
		ns->ln_status = LS_SCANNING_PHASE2;
		ns->ln_flags |= LF_SCANNED_ONCE;
		ns->ln_flags &= ~LF_UPGRADE;
		cfs_list_del_init(&com->lc_link);
		cfs_list_del_init(&com->lc_link_dir);
		cfs_list_add_tail(&com->lc_link, &lfsck->li_list_double_scan);
	} else if (result == 0) {
		if (lfsck->li_paused) {
			ns->ln_status = LS_PAUSED;
		} else {
			ns->ln_status = LS_STOPPED;
			cfs_list_del_init(&com->lc_link);
			cfs_list_del_init(&com->lc_link_dir);
			cfs_list_add_tail(&com->lc_link, &lfsck->li_list_idle);
		}
	} else {
		ns->ln_status = LS_FAILED;
		cfs_list_del_init(&com->lc_link);
		cfs_list_del_init(&com->lc_link_dir);
		cfs_list_add_tail(&com->lc_link, &lfsck->li_list_idle);
	}
	spin_unlock(&lfsck->li_lock);

	if (!init) {
		ns->ln_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
		ns->ln_time_last_checkpoint = cfs_time_current_sec();
		ns->ln_items_checked += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_namespace_store(env, com);

	up_write(&com->lc_sem);
	return rc;
}

static int
lfsck_namespace_dump(const struct lu_env *env, struct lfsck_component *com,
		     char *buf, int len)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_bookmark	*bk    = &lfsck->li_bookmark_ram;
	struct lfsck_namespace	*ns    =
				(struct lfsck_namespace *)com->lc_file_ram;
	int			 save  = len;
	int			 ret   = -ENOSPC;
	int			 rc;

	down_read(&com->lc_sem);
	rc = snprintf(buf, len,
		      "name: lfsck_namespace\n"
		      "magic: 0x%x\n"
		      "version: %d\n"
		      "status: %s\n",
		      ns->ln_magic,
		      bk->lb_version,
		      lfsck_status_names[ns->ln_status]);
	if (rc <= 0)
		goto out;

	buf += rc;
	len -= rc;
	rc = lfsck_bits_dump(&buf, &len, ns->ln_flags, lfsck_flags_names,
			     "flags");
	if (rc < 0)
		goto out;

	rc = lfsck_bits_dump(&buf, &len, bk->lb_param, lfsck_param_names,
			     "param");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, ns->ln_time_last_complete,
			     "time_since_last_completed");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, ns->ln_time_latest_start,
			     "time_since_latest_start");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, ns->ln_time_last_checkpoint,
			     "time_since_last_checkpoint");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(&buf, &len, &ns->ln_pos_latest_start,
			    "latest_start_position");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(&buf, &len, &ns->ln_pos_last_checkpoint,
			    "last_checkpoint_position");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(&buf, &len, &ns->ln_pos_first_inconsistent,
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
		rc = snprintf(buf, len,
			      "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "dirs: "LPU64"\n"
			      "M-linked: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: N/A\n"
			      "real-time_speed_phase1: "LPU64" items/sec\n"
			      "real-time_speed_phase2: N/A\n",
			      checked,
			      ns->ln_objs_checked_phase2,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      rtime,
			      ns->ln_run_time_phase2,
			      speed,
			      new_checked);
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;

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
				*lu_object_fid(&lfsck->li_obj_dir->do_lu);
			}
		} else {
			fid_zero(&pos.lp_dir_parent);
			pos.lp_dir_cookie = 0;
		}
		spin_unlock(&lfsck->li_lock);
		rc = lfsck_pos_dump(&buf, &len, &pos, "current_position");
		if (rc <= 0)
			goto out;
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
		rc = snprintf(buf, len,
			      "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "dirs: "LPU64"\n"
			      "M-linked: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: "LPU64" objs/sec\n"
			      "real-time_speed_phase1: N/A\n"
			      "real-time_speed_phase2: "LPU64" objs/sec\n"
			      "current_position: "DFID"\n",
			      ns->ln_items_checked,
			      checked,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      ns->ln_run_time_phase1,
			      rtime,
			      speed1,
			      speed2,
			      new_checked,
			      PFID(&ns->ln_fid_latest_scanned_phase2));
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;
	} else {
		__u64 speed1 = ns->ln_items_checked;
		__u64 speed2 = ns->ln_objs_checked_phase2;

		if (ns->ln_run_time_phase1 != 0)
			do_div(speed1, ns->ln_run_time_phase1);
		if (ns->ln_run_time_phase2 != 0)
			do_div(speed2, ns->ln_run_time_phase2);
		rc = snprintf(buf, len,
			      "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "dirs: "LPU64"\n"
			      "M-linked: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: "LPU64" objs/sec\n"
			      "real-time_speed_phase1: N/A\n"
			      "real-time_speed_phase2: N/A\n"
			      "current_position: N/A\n",
			      ns->ln_items_checked,
			      ns->ln_objs_checked_phase2,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      ns->ln_run_time_phase1,
			      ns->ln_run_time_phase2,
			      speed1,
			      speed2);
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;
	}
	ret = save - len;

out:
	up_read(&com->lc_sem);
	return ret;
}

static int lfsck_namespace_double_scan(const struct lu_env *env,
				       struct lfsck_component *com)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct ptlrpc_thread	*thread = &lfsck->li_thread;
	struct lfsck_bookmark	*bk	= &lfsck->li_bookmark_ram;
	struct lfsck_namespace	*ns	=
				(struct lfsck_namespace *)com->lc_file_ram;
	struct dt_object	*obj	= com->lc_obj;
	const struct dt_it_ops	*iops	= &obj->do_index_ops->dio_it;
	struct dt_object	*target;
	struct dt_it		*di;
	struct dt_key		*key;
	struct lu_fid		 fid;
	int			 rc;
	__u8			 flags = 0;
	ENTRY;

	lfsck->li_new_scanned = 0;
	lfsck->li_time_last_checkpoint = cfs_time_current();
	lfsck->li_time_next_checkpoint = lfsck->li_time_last_checkpoint +
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

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_DOUBLESCAN))
		GOTO(put, rc = 0);

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
		if (target == NULL) {
			rc = 0;
			goto checkpoint;
		} else if (IS_ERR(target)) {
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
		lfsck->li_new_scanned++;
		com->lc_new_checked++;
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

		if (unlikely(cfs_time_beforeq(lfsck->li_time_next_checkpoint,
					      cfs_time_current())) &&
		    com->lc_new_checked != 0) {
			down_write(&com->lc_sem);
			ns->ln_run_time_phase2 +=
				cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
			ns->ln_time_last_checkpoint = cfs_time_current_sec();
			ns->ln_objs_checked_phase2 += com->lc_new_checked;
			com->lc_new_checked = 0;
			rc = lfsck_namespace_store(env, com);
			up_write(&com->lc_sem);
			if (rc != 0)
				GOTO(put, rc);

			lfsck->li_time_last_checkpoint = cfs_time_current();
			lfsck->li_time_next_checkpoint =
				lfsck->li_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);
		}

		lfsck_control_speed(lfsck);
		if (unlikely(!thread_is_running(thread)))
			GOTO(put, rc = 0);

		rc = iops->next(env, di);
	} while (rc == 0);

	GOTO(put, rc);

put:
	iops->put(env, di);

fini:
	iops->fini(env, di);
	down_write(&com->lc_sem);

	ns->ln_run_time_phase2 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
	ns->ln_time_last_checkpoint = cfs_time_current_sec();
	ns->ln_objs_checked_phase2 += com->lc_new_checked;
	com->lc_new_checked = 0;

	if (rc > 0) {
		com->lc_journal = 0;
		ns->ln_status = LS_COMPLETED;
		if (!(bk->lb_param & LPF_DRYRUN))
			ns->ln_flags &=
			~(LF_SCANNED_ONCE | LF_INCONSISTENT | LF_UPGRADE);
		ns->ln_time_last_complete = ns->ln_time_last_checkpoint;
		ns->ln_success_count++;
	} else if (rc == 0) {
		if (lfsck->li_paused)
			ns->ln_status = LS_PAUSED;
		else
			ns->ln_status = LS_STOPPED;
	} else {
		ns->ln_status = LS_FAILED;
	}

	if (ns->ln_status != LS_PAUSED) {
		spin_lock(&lfsck->li_lock);
		cfs_list_del_init(&com->lc_link);
		cfs_list_add_tail(&com->lc_link, &lfsck->li_list_idle);
		spin_unlock(&lfsck->li_lock);
	}

	rc = lfsck_namespace_store(env, com);

	up_write(&com->lc_sem);
	return rc;
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
};

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

	CFS_INIT_LIST_HEAD(&com->lc_link);
	CFS_INIT_LIST_HEAD(&com->lc_link_dir);
	init_rwsem(&com->lc_sem);
	atomic_set(&com->lc_ref, 1);
	com->lc_lfsck = lfsck;
	com->lc_type = LT_NAMESPACE;
	com->lc_ops = &lfsck_namespace_ops;
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

	dt_try_as_dir(env, root);
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
	if (rc == -ENODATA)
		rc = lfsck_namespace_init(env, com);
	else if (rc < 0)
		rc = lfsck_namespace_reset(env, com, true);
	if (rc != 0)
		GOTO(out, rc);

	ns = (struct lfsck_namespace *)com->lc_file_ram;
	switch (ns->ln_status) {
	case LS_INIT:
	case LS_COMPLETED:
	case LS_FAILED:
	case LS_STOPPED:
		cfs_list_add_tail(&com->lc_link, &lfsck->li_list_idle);
		break;
	default:
		CERROR("%s: unknown lfsck_namespace status: %u\n",
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
		cfs_list_add_tail(&com->lc_link, &lfsck->li_list_scan);
		cfs_list_add_tail(&com->lc_link_dir, &lfsck->li_list_dir);
		break;
	}

	GOTO(out, rc = 0);

out:
	if (root != NULL && !IS_ERR(root))
		lu_object_put(env, &root->do_lu);
	if (rc != 0)
		lfsck_component_cleanup(env, com);
	return rc;
}
