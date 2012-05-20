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

#define OFD_INIT_OBJID	0
#define OFD_ROCOMPAT_SUPP (0)
#define OFD_INCOMPAT_SUPP (OBD_INCOMPAT_GROUPS | OBD_INCOMPAT_OST | \
			   OBD_INCOMPAT_COMMON_LR)
#define OFD_MAX_GROUPS	256

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
	const struct lu_env	*fti_env;

	struct obd_export	*fti_exp;
	struct lu_fid		 fti_fid;
	struct lu_attr		 fti_attr;
	union {
		char		 name[64]; /* for ofd_init0() */
	} fti_u;

	struct dt_object_format	 fti_dof;
	struct lu_buf		 fti_buf;
	loff_t			 fti_off;
};

static inline int ofd_export_stats_init(struct ofd_device *ofd,
					struct obd_export *exp, void *data)
{
	return 0;
}

extern void target_recovery_fini(struct obd_device *obd);
extern void target_recovery_init(struct lu_target *lut, svc_handler_t handler);

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

#endif /* _OFD_INTERNAL_H */
