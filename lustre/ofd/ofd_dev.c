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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 * Author: Johann Lombardi <johann@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <obd_class.h>
#include <lustre_param.h>

#include "ofd_internal.h"

/* Slab for OFD object allocation */
static cfs_mem_cache_t *ofd_object_kmem;

static struct lu_kmem_descr ofd_caches[] = {
	{
		.ckd_cache = &ofd_object_kmem,
		.ckd_name  = "ofd_obj",
		.ckd_size  = sizeof(struct ofd_object)
	},
	{
		.ckd_cache = NULL
	}
};

/* used by MGS to process specific configurations */
static int ofd_process_config(const struct lu_env *env, struct lu_device *d,
			      struct lustre_cfg *cfg)
{
	int rc = 0;

	ENTRY;

	switch (cfg->lcfg_command) {
	case LCFG_PARAM: {
		struct lprocfs_static_vars lvars;

		lprocfs_ofd_init_vars(&lvars);
		rc = class_process_proc_param(PARAM_OST, lvars.obd_vars, cfg,
					      d->ld_obd);
		break;
	}
	case LCFG_SPTLRPC_CONF: {
		rc = -ENOTSUPP;
		break;
	}
	default:
		break;
	}
	RETURN(rc);
}

struct lu_object_operations ofd_obj_ops = {
};

static struct lu_object *ofd_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *hdr,
					  struct lu_device *d)
{
	struct ofd_object *of;

	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(of, ofd_object_kmem, CFS_ALLOC_IO);
	if (of != NULL) {
		struct lu_object	*o;
		struct lu_object_header *h;

		o = &of->ofo_obj.do_lu;
		h = &of->ofo_header;
		lu_object_header_init(h);
		lu_object_init(o, h, d);
		lu_object_add_top(h, o);
		o->lo_ops = &ofd_obj_ops;
		RETURN(o);
	} else {
		RETURN(NULL);
	}
}

static int ofd_start(const struct lu_env *env, struct lu_device *parent,
		     struct lu_device *dev)
{
	struct obd_device *obd = dev->ld_obd;
	int		   rc = 0;

	ENTRY;

	LASSERT(obd->obd_no_conn);
	cfs_spin_lock(&obd->obd_dev_lock);
	obd->obd_no_conn = 0;
	cfs_spin_unlock(&obd->obd_dev_lock);

	RETURN(rc);
}

static int ofd_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	int		   rc = 0;

	ENTRY;

	RETURN(rc);
}

static struct lu_device_operations ofd_lu_ops = {
	.ldo_object_alloc	= ofd_object_alloc,
	.ldo_process_config	= ofd_process_config,
	.ldo_prepare		= ofd_start,
	.ldo_recovery_complete	= ofd_recovery_complete,
};

static int ofd_init0(const struct lu_env *env, struct ofd_device *m,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	const char		*dev = lustre_cfg_string(cfg, 0);
	struct obd_device	*obd;
	int			 rc;

	ENTRY;

	obd = class_name2obd(dev);
	if (obd == NULL) {
		CERROR("Cannot find obd with name %s\n", dev);
		RETURN(-ENODEV);
	}

	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0)
		RETURN(rc);

	obd->u.obt.obt_magic = OBT_MAGIC;

	m->ofd_dt_dev.dd_lu_dev.ld_ops = &ofd_lu_ops;
	m->ofd_dt_dev.dd_lu_dev.ld_obd = obd;
	/* set this lu_device to obd, because error handling need it */
	obd->obd_lu_dev = &m->ofd_dt_dev.dd_lu_dev;

	/* No connection accepted until configurations will finish */
	obd->obd_no_conn = 1;
	obd->obd_replayable = 1;
	if (cfg->lcfg_bufcount > 4 && LUSTRE_CFG_BUFLEN(cfg, 4) > 0) {
		char *str = lustre_cfg_string(cfg, 4);

		if (strchr(str, 'n')) {
			CWARN("%s: recovery disabled\n", obd->obd_name);
			obd->obd_replayable = 0;
		}
	}

	RETURN(0);
}

static void ofd_fini(const struct lu_env *env, struct ofd_device *m)
{
	struct obd_device *obd = ofd_obd(m);
	struct lu_device  *d = &m->ofd_dt_dev.dd_lu_dev;

	obd_exports_barrier(obd);
	obd_zombie_barrier();

	LASSERT(cfs_atomic_read(&d->ld_ref) == 0);
	EXIT;
}

static struct lu_device* ofd_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	ENTRY;
	ofd_fini(env, ofd_dev(d));
	RETURN(NULL);
}

static struct lu_device *ofd_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct ofd_device *m = ofd_dev(d);

	dt_device_fini(&m->ofd_dt_dev);
	OBD_FREE_PTR(m);
	RETURN(NULL);
}

static struct lu_device *ofd_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct ofd_device *m;
	struct lu_device  *l;
	int		   rc;

	OBD_ALLOC_PTR(m);
	if (m == NULL)
		return ERR_PTR(-ENOMEM);

	l = &m->ofd_dt_dev.dd_lu_dev;
	dt_device_init(&m->ofd_dt_dev, t);
	rc = ofd_init0(env, m, t, cfg);
	if (rc != 0) {
		ofd_device_free(env, l);
		l = ERR_PTR(rc);
	}

	return l;
}

/* thread context key constructor/destructor */
LU_KEY_INIT_FINI(ofd, struct ofd_thread_info);

static void ofd_key_exit(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct ofd_thread_info *info = data;

	info->fti_env = NULL;
}

struct lu_context_key ofd_thread_key = {
	.lct_tags = LCT_DT_THREAD,
	.lct_init = ofd_key_init,
	.lct_fini = ofd_key_fini,
	.lct_exit = ofd_key_exit
};

/* type constructor/destructor: mdt_type_init, mdt_type_fini */
LU_TYPE_INIT_FINI(ofd, &ofd_thread_key);

static struct lu_device_type_operations ofd_device_type_ops = {
	.ldto_init		= ofd_type_init,
	.ldto_fini		= ofd_type_fini,

	.ldto_start		= ofd_type_start,
	.ldto_stop		= ofd_type_stop,

	.ldto_device_alloc	= ofd_device_alloc,
	.ldto_device_free	= ofd_device_free,
	.ldto_device_fini	= ofd_device_fini
};

static struct lu_device_type ofd_device_type = {
	.ldt_tags	= LU_DEVICE_DT,
	.ldt_name	= LUSTRE_OST_NAME,
	.ldt_ops	= &ofd_device_type_ops,
	.ldt_ctx_tags	= LCT_DT_THREAD
};

int __init ofd_init(void)
{
	struct lprocfs_static_vars	lvars;
	int				rc;

	rc = lu_kmem_init(ofd_caches);
	if (rc)
		return rc;

	lprocfs_ofd_init_vars(&lvars);

	rc = class_register_type(&ofd_obd_ops, NULL, lvars.module_vars,
				 LUSTRE_OST_NAME, &ofd_device_type);
	return rc;
}

void __exit ofd_exit(void)
{
	class_unregister_type(LUSTRE_OST_NAME);
	lu_kmem_fini(ofd_caches);
}

MODULE_AUTHOR("Whamcloud, Inc. <http://www.whamcloud.com/>");
MODULE_DESCRIPTION("Lustre Object Filtering Device");
MODULE_LICENSE("GPL");

module_init(ofd_init);
module_exit(ofd_exit);
