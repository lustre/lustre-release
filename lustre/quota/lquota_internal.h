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
 * Copyright (c) 2012 Whamcloud, Inc.
 * Use is subject to license terms.
 */

#include <obd.h>
#include <lquota.h>

#ifndef _LQUOTA_INTERNAL_H
#define _LQUOTA_INTERNAL_H

#define QTYPE_NAME(qtype) ((qtype) == USRQUOTA ? "usr" : "grp")

#define QIF_IFLAGS (QIF_INODES | QIF_ITIME | QIF_ILIMITS)
#define QIF_BFLAGS (QIF_SPACE | QIF_BTIME | QIF_BLIMITS)

/* The biggest filename are the one used for slave index which are in the form
 * of 0x%x-%s,glb_fid.f_oid,slv_uuid, that's to say:
 * 2(0x) + 8(f_oid) + 1(-) + 40(UUID_MAX) which means 51 chars + '\0' */
#define LQUOTA_NAME_MAX 52

/* reserved OID in FID_SEQ_QUOTA for local objects */
enum lquota_local_oid {
	LQUOTA_USR_OID		= 1UL, /* slave index copy for user quota */
	LQUOTA_GRP_OID		= 2UL, /* slave index copy for group quota */
	/* all OIDs after this are allocated dynamically by the QMT */
	LQUOTA_GENERATED_OID	= 4096UL,
};

/* Common data shared by quota-level handlers. This is allocated per-thread to
 * reduce stack consumption */
struct lquota_thread_info {
	union  lquota_rec	qti_rec;
	struct lu_buf		qti_lb;
	struct lu_attr		qti_attr;
	struct dt_object_format	qti_dof;
	struct lustre_mdt_attrs	qti_lma;
	struct lu_fid		qti_fid;
	char			qti_buf[LQUOTA_NAME_MAX];
};

#define qti_glb_rec	qti_rec.lqr_glb_rec
#define qti_acct_rec	qti_rec.lqr_acct_rec
#define qti_slv_rec	qti_rec.lqr_slv_rec

#define LQUOTA_BUMP_VER	0x1
#define LQUOTA_SET_VER	0x2

extern struct lu_context_key lquota_thread_key;

/* extract lquota_threa_info context from environment */
static inline
struct lquota_thread_info *lquota_info(const struct lu_env *env)
{
	struct lquota_thread_info	*info;

	info = lu_context_key_get(&env->le_ctx, &lquota_thread_key);
	if (info == NULL) {
		lu_env_refill((struct lu_env *)env);
		info = lu_context_key_get(&env->le_ctx, &lquota_thread_key);
	}
	LASSERT(info);
	return info;
}

/* lquota_lib.c */
struct dt_object *acct_obj_lookup(const struct lu_env *, struct dt_device *,
				  int);
void lquota_generate_fid(struct lu_fid *, int, int, int);
int lquota_extract_fid(struct lu_fid *, int *, int *, int *);
const struct dt_index_features *glb_idx_feature(struct lu_fid *);

/* lquota_disk.c */
struct dt_object *lquota_disk_dir_find_create(const struct lu_env *,
					      struct dt_device *,
					      struct dt_object *, const char *);
struct dt_object *lquota_disk_glb_find_create(const struct lu_env *,
					      struct dt_device *,
					      struct dt_object *,
					      struct lu_fid *, bool);
struct dt_object *lquota_disk_slv_find_create(const struct lu_env *,
					      struct dt_device *,
					      struct dt_object *,
					      struct lu_fid *,
					      struct obd_uuid *, bool);
typedef int (*lquota_disk_slv_cb_t) (const struct lu_env *, struct lu_fid *,
				     char *, struct lu_fid *, void *);
int lquota_disk_for_each_slv(const struct lu_env *, struct dt_object *,
			     struct lu_fid *, lquota_disk_slv_cb_t, void *);
struct dt_object *lquota_disk_slv_find(const struct lu_env *,
				       struct dt_device *, struct dt_object *,
				       struct lu_fid *, struct obd_uuid *);
int lquota_disk_read(const struct lu_env *, struct dt_object *,
		     union lquota_id *, struct dt_rec *);
int lquota_disk_declare_write(const struct lu_env *, struct thandle *,
			      struct dt_object *, union lquota_id *);
int lquota_disk_write(const struct lu_env *, struct thandle *,
		      struct dt_object *, union lquota_id *, struct dt_rec *,
		      __u32, __u64 *);
int lquota_disk_update_ver(const struct lu_env *, struct dt_device *,
			   struct dt_object *, __u64);

/* lproc_quota.c */
extern struct file_operations lprocfs_quota_seq_fops;

/* quota_interface.c
 * old quota module initialization routines, to be removed */
int init_lustre_quota(void);
void exit_lustre_quota(void);

#endif /* _LQUOTA_INTERNAL_H */
