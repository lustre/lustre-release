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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _OFD_INTERNAL_H
#define _OFD_INTERNAL_H

#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>
#include <lustre_fid.h>
#include <lustre_capa.h>

#define OFD_INIT_OBJID	0
#define OFD_ROCOMPAT_SUPP (0)
#define OFD_INCOMPAT_SUPP (OBD_INCOMPAT_GROUPS | OBD_INCOMPAT_OST | \
			   OBD_INCOMPAT_COMMON_LR)
#define OFD_MAX_GROUPS	256

/* per-client-per-object persistent state (LRU) */
struct ofd_mod_data {
	cfs_list_t	fmd_list;        /* linked to fed_mod_list */
	struct lu_fid	fmd_fid;         /* FID being written to */
	__u64		fmd_mactime_xid; /* xid highest {m,a,c}time setattr */
	cfs_time_t	fmd_expire;      /* time when the fmd should expire */
	int		fmd_refcount;    /* reference counter - list holds 1 */
};

#define OFD_FMD_MAX_NUM_DEFAULT 128
#define OFD_FMD_MAX_AGE_DEFAULT ((obd_timeout + 10) * CFS_HZ)

enum {
	LPROC_OFD_READ_BYTES = 0,
	LPROC_OFD_WRITE_BYTES = 1,
	LPROC_OFD_LAST,
};

struct ofd_device {
	struct dt_device	 ofd_dt_dev;
	struct dt_device	*ofd_osd;
	struct dt_device_param	 ofd_dt_conf;
	/* DLM name-space for meta-data locks maintained by this server */
	struct ldlm_namespace	*ofd_namespace;

	/* last_rcvd file */
	struct lu_target	 ofd_lut;
	struct dt_object	*ofd_last_group_file;
	struct dt_object	*ofd_health_check_file;

	int			 ofd_subdir_count;

	int			 ofd_max_group;
	obd_id			 ofd_last_objids[OFD_MAX_GROUPS];
	cfs_mutex_t		 ofd_create_locks[OFD_MAX_GROUPS];
	struct dt_object	*ofd_lastid_obj[OFD_MAX_GROUPS];
	cfs_spinlock_t		 ofd_objid_lock;

	/* ofd mod data: ofd_device wide values */
	int			 ofd_fmd_max_num; /* per ofd ofd_mod_data */
	cfs_duration_t		 ofd_fmd_max_age; /* time to fmd expiry */

	cfs_spinlock_t		 ofd_flags_lock;
	unsigned long		 ofd_raid_degraded:1,
				 /* sync journal on writes */
				 ofd_syncjournal:1,
				 /* sync on lock cancel */
				 ofd_sync_lock_cancel:2;

	struct lu_site		 ofd_site;
};

static inline struct ofd_device *ofd_dev(struct lu_device *d)
{
	return container_of0(d, struct ofd_device, ofd_dt_dev.dd_lu_dev);
}

static inline struct obd_device *ofd_obd(struct ofd_device *ofd)
{
	return ofd->ofd_dt_dev.dd_lu_dev.ld_obd;
}

static inline struct ofd_device *ofd_exp(struct obd_export *exp)
{
	return ofd_dev(exp->exp_obd->obd_lu_dev);
}

static inline char *ofd_name(struct ofd_device *ofd)
{
	return ofd->ofd_dt_dev.dd_lu_dev.ld_obd->obd_name;
}

struct ofd_object {
	struct lu_object_header ofo_header;
	struct dt_object	ofo_obj;
};

static inline struct ofd_object *ofd_obj(struct lu_object *o)
{
	return container_of0(o, struct ofd_object, ofo_obj.do_lu);
}

/*
 * Common data shared by obdofd-level handlers. This is allocated per-thread
 * to reduce stack consumption.
 */
struct ofd_thread_info {
	const struct lu_env		*fti_env;

	struct obd_export		*fti_exp;
	struct lu_fid			 fti_fid;
	struct lu_attr			 fti_attr;
	union {
		char			 name[64]; /* for ofd_init0() */
		struct obd_statfs	 osfs;    /* for obdofd_statfs() */
	} fti_u;

	struct dt_object_format		 fti_dof;
	struct lu_buf			 fti_buf;
	loff_t				 fti_off;
};

extern void target_recovery_fini(struct obd_device *obd);
extern void target_recovery_init(struct lu_target *lut, svc_handler_t handler);

/* ofd_capa.c */
int ofd_update_capa_key(struct ofd_device *ofd, struct lustre_capa_key *key);
int ofd_auth_capa(struct obd_export *exp, struct lu_fid *fid, obd_seq seq,
		  struct lustre_capa *capa, __u64 opc);
void ofd_free_capa_keys(struct ofd_device *ofd);

/* ofd_dev.c */
extern struct lu_context_key ofd_thread_key;

/* ofd_obd.c */
extern struct obd_ops ofd_obd_ops;

/* ofd_fs.c */
obd_id ofd_last_id(struct ofd_device *ofd, obd_seq seq);
int ofd_group_load(const struct lu_env *env, struct ofd_device *ofd, int);
int ofd_fs_setup(const struct lu_env *env, struct ofd_device *ofd,
		 struct obd_device *obd);
void ofd_fs_cleanup(const struct lu_env *env, struct ofd_device *ofd);

/* lproc_ofd.c */
void lprocfs_ofd_init_vars(struct lprocfs_static_vars *lvars);
int lproc_ofd_attach_seqstat(struct obd_device *dev);
extern struct file_operations ofd_per_nid_stats_fops;

/* ofd_fmd.c */
int ofd_fmd_init(void);
void ofd_fmd_exit(void);
struct ofd_mod_data *ofd_fmd_find(struct obd_export *exp,
				  struct lu_fid *fid);
struct ofd_mod_data *ofd_fmd_get(struct obd_export *exp,
				 struct lu_fid *fid);
void ofd_fmd_put(struct obd_export *exp, struct ofd_mod_data *fmd);
void ofd_fmd_expire(struct obd_export *exp);
void ofd_fmd_cleanup(struct obd_export *exp);
#ifdef DO_FMD_DROP
void ofd_fmd_drop(struct obd_export *exp, struct lu_fid *fid);
#else
#define ofd_fmd_drop(exp, fid) do {} while (0)
#endif

static inline struct ofd_thread_info * ofd_info(const struct lu_env *env)
{
	struct ofd_thread_info *info;

	info = lu_context_key_get(&env->le_ctx, &ofd_thread_key);
	LASSERT(info);
	LASSERT(info->fti_env);
	LASSERT(info->fti_env == env);
	return info;
}

static inline struct ofd_thread_info * ofd_info_init(const struct lu_env *env,
						     struct obd_export *exp)
{
	struct ofd_thread_info *info;

	info = lu_context_key_get(&env->le_ctx, &ofd_thread_key);
	LASSERT(info);
	LASSERT(info->fti_exp == NULL);
	LASSERT(info->fti_env == NULL);

	info->fti_env = env;
	info->fti_exp = exp;
	return info;
}

/* sync on lock cancel is useless when we force a journal flush,
 * and if we enable async journal commit, we should also turn on
 * sync on lock cancel if it is not enabled already. */
static inline void ofd_slc_set(struct ofd_device *ofd)
{
	if (ofd->ofd_syncjournal == 1)
		ofd->ofd_sync_lock_cancel = NEVER_SYNC_ON_CANCEL;
	else if (ofd->ofd_sync_lock_cancel == NEVER_SYNC_ON_CANCEL)
		ofd->ofd_sync_lock_cancel = ALWAYS_SYNC_ON_CANCEL;
}

#endif /* _OFD_INTERNAL_H */
