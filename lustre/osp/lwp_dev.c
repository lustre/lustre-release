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
 * Copyright (c) 2013, Intel Corporation.
 * Use is subject to license terms.
 *
 * lustre/osp/lwp_dev.c
 *
 * Light Weight Proxy, which is just for managing the connection established
 * from OSTs/MDTs to MDT0.
 *
 * Author: <di.wang@intel.com>
 * Author: <yawei.niu@intel.com>
 */
#define DEBUG_SUBSYSTEM S_OST

#include <obd_class.h>
#include <lustre_param.h>
#include <lustre_log.h>
#include <libcfs/libcfs_string.h>

struct lwp_device {
	struct lu_device	lpd_dev;
	struct obd_device	*lpd_obd;
	struct obd_uuid		lpd_cluuid;
	struct obd_export	*lpd_exp;
	int			lpd_connects;
};

static inline struct lwp_device *lu2lwp_dev(struct lu_device *d)
{
	return container_of0(d, struct lwp_device, lpd_dev);
}

static inline struct lu_device *lwp2lu_dev(struct lwp_device *d)
{
	return &d->lpd_dev;
}

static int lwp_setup(const struct lu_env *env, struct lwp_device *lwp,
		     char *nidstring)
{
	struct lustre_cfg_bufs	*bufs = NULL;
	struct lustre_cfg	*lcfg = NULL;
	char			*lwp_name = lwp->lpd_obd->obd_name;
	char			*server_uuid = NULL;
	char			*ptr;
	class_uuid_t		 uuid;
	struct obd_import	*imp;
	int			 len = strlen(lwp_name);
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(bufs);
	if (bufs == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC(server_uuid, len);
	if (server_uuid == NULL)
		GOTO(out, rc = -ENOMEM);

	snprintf(server_uuid, len, "-%s-", LUSTRE_LWP_NAME);
	ptr = cfs_strrstr(lwp_name, server_uuid);
	if (ptr == NULL) {
		CERROR("%s: failed to get server_uuid from lwp_name: rc = %d\n",
		       lwp_name, -EINVAL);
		GOTO(out, rc = -EINVAL);
	}

	strncpy(server_uuid, lwp_name, ptr - lwp_name);
	server_uuid[ptr - lwp_name] = '\0';
	strncat(server_uuid, "_UUID", len - 1);
	lustre_cfg_bufs_reset(bufs, lwp_name);
	lustre_cfg_bufs_set_string(bufs, 1, server_uuid);
	lustre_cfg_bufs_set_string(bufs, 2, nidstring);
	lcfg = lustre_cfg_new(LCFG_SETUP, bufs);
	if (lcfg == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = client_obd_setup(lwp->lpd_obd, lcfg);
	if (rc != 0) {
		CERROR("%s: client obd setup error: rc = %d\n",
		       lwp->lpd_obd->obd_name, rc);
		GOTO(out, rc);
	}

	imp = lwp->lpd_obd->u.cli.cl_import;
	rc = ptlrpc_init_import(imp);
	if (rc)
		GOTO(out, rc);

	ll_generate_random_uuid(uuid);
	class_uuid_unparse(uuid, &lwp->lpd_cluuid);
out:
	if (bufs != NULL)
		OBD_FREE_PTR(bufs);
	if (server_uuid != NULL)
		OBD_FREE(server_uuid, len);
	if (lcfg != NULL)
		lustre_cfg_free(lcfg);
	if (rc)
		client_obd_cleanup(lwp->lpd_obd);

	RETURN(rc);
}

static int lwp_disconnect(struct lwp_device *d)
{
	struct obd_import *imp;
	int rc = 0;

	imp = d->lpd_obd->u.cli.cl_import;

	/* Mark import deactivated now, so we don't try to reconnect if any
	 * of the cleanup RPCs fails (e.g. ldlm cancel, etc).  We don't
	 * fully deactivate the import, or that would drop all requests. */
	LASSERT(imp != NULL);
	spin_lock(&imp->imp_lock);
	imp->imp_deactive = 1;
	spin_unlock(&imp->imp_lock);

	ptlrpc_deactivate_import(imp);

	/* Some non-replayable imports (MDS's OSCs) are pinged, so just
	 * delete it regardless.  (It's safe to delete an import that was
	 * never added.) */
	ptlrpc_pinger_del_import(imp);
	rc = ptlrpc_disconnect_import(imp, 0);
	if (rc != 0)
		CWARN("%s: can't disconnect: rc = %d\n",
		      d->lpd_obd->obd_name, rc);

	ptlrpc_invalidate_import(imp);

	RETURN(rc);
}

static int lwp_process_config(const struct lu_env *env,
			      struct lu_device *dev, struct lustre_cfg *lcfg)
{
	struct lwp_device		*d = lu2lwp_dev(dev);
	int				 rc;
	ENTRY;

	switch (lcfg->lcfg_command) {
	case LCFG_PRE_CLEANUP:
	case LCFG_CLEANUP:
		rc = lwp_disconnect(d);
		break;
	case LCFG_PARAM:
		rc = -ENOSYS;
		break;
	default:
		CERROR("%s: unknown command %u\n",
		       (char *)lustre_cfg_string(lcfg, 0), lcfg->lcfg_command);
		rc = 0;
		break;
	}

	RETURN(rc);
}

const struct lu_device_operations lwp_lu_ops = {
	.ldo_process_config	= lwp_process_config,
};

static struct lprocfs_vars lprocfs_lwp_module_vars[] = {
	{ "num_refs",		lprocfs_rd_numrefs, 0, 0 },
	{ 0 }
};

static struct lprocfs_vars lprocfs_lwp_obd_vars[] = {
	{ 0 }
};

void lprocfs_lwp_init_vars(struct lprocfs_static_vars *lvars)
{
	lvars->module_vars = lprocfs_lwp_module_vars;
	lvars->obd_vars = lprocfs_lwp_obd_vars;
}

int lwp_init0(const struct lu_env *env, struct lwp_device *lwp,
	      struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	struct lprocfs_static_vars lvars = { 0 };
	int			   rc;
	ENTRY;

	lwp->lpd_obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (lwp->lpd_obd == NULL) {
		CERROR("Cannot find obd with name %s\n",
		       lustre_cfg_string(cfg, 0));
		RETURN(-ENODEV);
	}

	lwp->lpd_dev.ld_ops = &lwp_lu_ops;
	lwp->lpd_obd->obd_lu_dev = &lwp->lpd_dev;

	rc = ptlrpcd_addref();
	if (rc) {
		CERROR("%s: ptlrpcd addref error: rc =%d\n",
		       lwp->lpd_obd->obd_name, rc);
		RETURN(rc);
	}

	rc = lwp_setup(env, lwp, lustre_cfg_string(cfg, 1));
	if (rc) {
		CERROR("%s: setup lwp failed. %d\n",
		       lwp->lpd_obd->obd_name, rc);
		ptlrpcd_decref();
		RETURN(rc);
	}

	lprocfs_lwp_init_vars(&lvars);
	if (lprocfs_obd_setup(lwp->lpd_obd, lvars.obd_vars) == 0)
		ptlrpc_lprocfs_register_obd(lwp->lpd_obd);

	RETURN(0);
}

static struct lu_device *lwp_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct lwp_device *m = lu2lwp_dev(lu);
	ENTRY;

	if (atomic_read(&lu->ld_ref) && lu->ld_site) {
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_ERROR, NULL);
		lu_site_print(env, lu->ld_site, &msgdata, lu_cdebug_printer);
	}
	lu_device_fini(&m->lpd_dev);
	OBD_FREE_PTR(m);
	RETURN(NULL);
}

static struct lu_device *lwp_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *lcfg)
{
	struct lwp_device *lwp;
	struct lu_device  *l;

	OBD_ALLOC_PTR(lwp);
	if (lwp == NULL) {
		l = ERR_PTR(-ENOMEM);
	} else {
		int rc;

		l = lwp2lu_dev(lwp);
		lu_device_init(&lwp->lpd_dev, t);
		rc = lwp_init0(env, lwp, t, lcfg);
		if (rc != 0) {
			lwp_device_free(env, l);
			l = ERR_PTR(rc);
		}
	}
	return l;
}


static struct lu_device *lwp_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct lwp_device *m = lu2lwp_dev(d);
	struct obd_import *imp;
	int                rc;
	ENTRY;

	if (m->lpd_exp != NULL)
		class_disconnect(m->lpd_exp);

	imp = m->lpd_obd->u.cli.cl_import;

	if (imp->imp_rq_pool) {
		ptlrpc_free_rq_pool(imp->imp_rq_pool);
		imp->imp_rq_pool = NULL;
	}

	LASSERT(m->lpd_obd);
	ptlrpc_lprocfs_unregister_obd(m->lpd_obd);
	lprocfs_obd_cleanup(m->lpd_obd);

	rc = client_obd_cleanup(m->lpd_obd);
	LASSERTF(rc == 0, "error %d\n", rc);

	ptlrpcd_decref();

	RETURN(NULL);
}

static struct lu_device_type_operations lwp_device_type_ops = {
	.ldto_device_alloc   = lwp_device_alloc,
	.ldto_device_free    = lwp_device_free,
	.ldto_device_fini    = lwp_device_fini
};

struct lu_device_type lwp_device_type = {
	.ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_LWP_NAME,
	.ldt_ops      = &lwp_device_type_ops,
	.ldt_ctx_tags = LCT_MD_THREAD
};

static int lwp_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct lwp_device       *lwp = lu2lwp_dev(obd->obd_lu_dev);
	struct client_obd	*cli = &lwp->lpd_obd->u.cli;
	struct obd_import       *imp = cli->cl_import;
	struct obd_connect_data *ocd;
	struct lustre_handle     conn;
	int                      rc;

	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", lwp->lpd_connects);

	*exp = NULL;
	down_write(&cli->cl_sem);
	rc = class_connect(&conn, obd, cluuid);
	if (rc != 0)
		GOTO(out_sem, rc);

	*exp = class_conn2export(&conn);
	lwp->lpd_exp = *exp;

	/* Why should there ever be more than 1 connect? */
	lwp->lpd_connects++;
	LASSERT(lwp->lpd_connects == 1);

	imp->imp_dlm_handle = conn;
	rc = ptlrpc_init_import(imp);
	if (rc != 0)
		GOTO(out_dis, rc);

	LASSERT(data != NULL);
	ocd = &imp->imp_connect_data;
	*ocd = *data;

	LASSERT(ocd->ocd_connect_flags & OBD_CONNECT_LIGHTWEIGHT);

	ocd->ocd_version = LUSTRE_VERSION_CODE;
	imp->imp_connect_flags_orig = ocd->ocd_connect_flags;

	rc = ptlrpc_connect_import(imp);
	if (rc != 0) {
		CERROR("%s: can't connect obd: rc = %d\n", obd->obd_name, rc);
		GOTO(out_dis, rc);
	}

	ptlrpc_pinger_add_import(imp);

	GOTO(out_dis, rc = 0);

out_dis:
	if (rc != 0) {
		class_disconnect(*exp);
		*exp = NULL;
		lwp->lpd_exp = NULL;
	}

out_sem:
	up_write(&cli->cl_sem);

	return rc;
}

static int lwp_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct lwp_device *lwp = lu2lwp_dev(obd->obd_lu_dev);
	int                rc;
	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	LASSERT(lwp->lpd_connects == 1);
	lwp->lpd_connects--;

	rc = class_disconnect(exp);
	if (rc)
		CERROR("%s: class disconnect error: rc = %d\n",
		       obd->obd_name, rc);

	RETURN(rc);
}

static int lwp_import_event(struct obd_device *obd, struct obd_import *imp,
			    enum obd_import_event event)
{
	switch (event) {
	case IMP_EVENT_DISCON:
	case IMP_EVENT_INACTIVE:
	case IMP_EVENT_ACTIVE:
		break;
	case IMP_EVENT_INVALIDATE:
		if (obd->obd_namespace == NULL)
			break;
		ldlm_namespace_cleanup(obd->obd_namespace, LDLM_FL_LOCAL_ONLY);
		break;
	case IMP_EVENT_OCD:
		break;
	default:
		CERROR("%s: unsupported import event: %#x\n",
		       obd->obd_name, event);
	}
	return 0;
}

struct obd_ops lwp_obd_device_ops = {
	.o_owner	= THIS_MODULE,
	.o_add_conn	= client_import_add_conn,
	.o_del_conn	= client_import_del_conn,
	.o_connect	= lwp_obd_connect,
	.o_disconnect	= lwp_obd_disconnect,
	.o_import_event	= lwp_import_event,
};
