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
 * Copyright (c) 2013, 2017, Intel Corporation.
 * Use is subject to license terms.
 *
 * lustre/osp/lwp_dev.c
 *
 * This file provides code related to the Light Weight Proxy (LWP) managing
 * the connections established from OST to MDT, and MDT to MDT0.
 *
 * A LWP connection is used to send quota and FLD query requests. It's not
 * recoverable, which means target server doesn't have an on-disk record in
 * the last_rcvd file to remember the connection. Once LWP reconnect after
 * server reboot, server will always regard it as a new connection.
 *
 * Author: <di.wang@intel.com>
 * Author: <yawei.niu@intel.com>
 */
#define DEBUG_SUBSYSTEM S_OST

#include <obd_class.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_log.h>
#include <linux/kthread.h>

#include "osp_internal.h"

struct lwp_device {
	struct lu_device	lpd_dev;
	struct obd_device      *lpd_obd;   /* corresponding OBD device */
	struct obd_export      *lpd_exp;   /* export of LWP */
	struct task_struct     *lpd_notify_task; /* notify thread */
	int			lpd_connects; /* use count, 0 or 1 */
};

static inline struct lwp_device *lu2lwp_dev(struct lu_device *d)
{
	return container_of_safe(d, struct lwp_device, lpd_dev);
}

static inline struct lu_device *lwp2lu_dev(struct lwp_device *d)
{
	return &d->lpd_dev;
}

/**
 * Setup LWP device.
 *
 * \param[in] env	environment passed by caller
 * \param[in] lwp	LWP device to be setup
 * \param[in] nidstring	remote target NID
 *
 * \retval		0 on success
 * \retval		negative number on error
 */
static int lwp_setup(const struct lu_env *env, struct lwp_device *lwp,
		     char *nidstring)
{
	struct lustre_cfg_bufs	*bufs = NULL;
	struct lustre_cfg	*lcfg = NULL;
	char			*lwp_name = lwp->lpd_obd->obd_name;
	char			*server_uuid = NULL;
	char			*ptr;
	int			 uuid_len = -1;
	struct obd_import	*imp;
	int			 len = strlen(lwp_name) + 1;
	int			 rc;
	const char		*lwp_marker = "-" LUSTRE_LWP_NAME "-";
	ENTRY;

	lwp->lpd_notify_task = NULL;

	OBD_ALLOC_PTR(bufs);
	if (bufs == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC(server_uuid, len);
	if (server_uuid == NULL)
		GOTO(out, rc = -ENOMEM);

	ptr = lwp_name;
	while (ptr && (ptr = strstr(ptr+1, lwp_marker)) != NULL)
		uuid_len = ptr - lwp_name;

	if (uuid_len < 0) {
		CERROR("%s: failed to get server_uuid from lwp_name: rc = %d\n",
		       lwp_name, -EINVAL);
		GOTO(out, rc = -EINVAL);
	}

	strncpy(server_uuid, lwp_name, uuid_len);
	strlcat(server_uuid, "_UUID", len);
	lustre_cfg_bufs_reset(bufs, lwp_name);
	lustre_cfg_bufs_set_string(bufs, 1, server_uuid);
	lustre_cfg_bufs_set_string(bufs, 2, nidstring);
	OBD_ALLOC(lcfg, lustre_cfg_len(bufs->lcfg_bufcount, bufs->lcfg_buflen));
	if (!lcfg)
		GOTO(out, rc = -ENOMEM);
	lustre_cfg_init(lcfg, LCFG_SETUP, bufs);

	rc = client_obd_setup(lwp->lpd_obd, lcfg);
	if (rc != 0) {
		CERROR("%s: client obd setup error: rc = %d\n",
		       lwp->lpd_obd->obd_name, rc);
		GOTO(out, rc);
	}

	imp = lwp->lpd_obd->u.cli.cl_import;
	rc = ptlrpc_init_import(imp);
out:
	if (bufs != NULL)
		OBD_FREE_PTR(bufs);
	if (server_uuid != NULL)
		OBD_FREE(server_uuid, len);
	if (lcfg)
		OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount,
					      lcfg->lcfg_buflens));
	if (rc)
		client_obd_cleanup(lwp->lpd_obd);

	RETURN(rc);
}

/**
 * Disconnect the import from LWP.
 *
 * \param[in] d		LWP device to be disconnected
 *
 * \retval		0 on success
 * \retval		negative number on error
 */
static int lwp_disconnect(struct lwp_device *d)
{
	struct obd_import *imp;
	int rc = 0;

	imp = d->lpd_obd->u.cli.cl_import;

	/*
	 * Mark import deactivated now, so we don't try to reconnect if any
	 * of the cleanup RPCs fails (e.g. ldlm cancel, etc).  We don't
	 * fully deactivate the import because that would cause all requests
	 * to be dropped.
	 */
	LASSERT(imp != NULL);
	spin_lock(&imp->imp_lock);
	imp->imp_deactive = 1;
	spin_unlock(&imp->imp_lock);

	ptlrpc_deactivate_import(imp);

	/*
	 * Some non-replayable imports (MDS's OSCs) are pinged, so just
	 * delete it regardless.  (It's safe to delete an import that was
	 * never added.)
	 */
	ptlrpc_pinger_del_import(imp);
	rc = ptlrpc_disconnect_import(imp, 0);
	if (rc != 0)
		CWARN("%s: can't disconnect: rc = %d\n",
		      d->lpd_obd->obd_name, rc);

	ptlrpc_invalidate_import(imp);

	RETURN(rc);
}

/**
 * Implementation of lu_device_operations::ldo_process_config.
 *
 * Process a Lustre configuration request.
 *
 * \param[in] env	environment passed by caller
 * \param[in] dev	device to be processed
 * \param[in] lcfg	lustre_cfg, LCFG_PRE_CLEANUP or LCFG_CLEANUP
 *
 * \retval		0 on success
 * \retval		negative number on error
 */
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

static const struct lu_device_operations lwp_lu_ops = {
	.ldo_process_config	= lwp_process_config,
};

/**
 * Initialize LWP device.
 *
 * \param[in] env	environment passed by caller
 * \param[in] lwp	device to be initialized
 * \param[in] ldt	not used
 * \param[in] cfg	lustre_cfg contains remote target uuid
 *
 * \retval		0 on success
 * \retval		-ENODEV if the device name cannot be found
 * \retval		negative numbers on other errors
 */
static int lwp_init0(const struct lu_env *env, struct lwp_device *lwp,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
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

	rc = lprocfs_obd_setup(lwp->lpd_obd, true);
	if (rc) {
		CERROR("%s: lprocfs_obd_setup failed. %d\n",
		       lwp->lpd_obd->obd_name, rc);
		ptlrpcd_decref();
		RETURN(rc);
	}

	rc = lwp_setup(env, lwp, lustre_cfg_string(cfg, 1));
	if (rc) {
		CERROR("%s: setup lwp failed. %d\n",
		       lwp->lpd_obd->obd_name, rc);
		lprocfs_obd_cleanup(lwp->lpd_obd);
		ptlrpcd_decref();
		RETURN(rc);
	}

	rc = sptlrpc_lprocfs_cliobd_attach(lwp->lpd_obd);
	if (rc) {
		CERROR("%s: sptlrpc_lprocfs_cliobd_attached failed. %d\n",
		       lwp->lpd_obd->obd_name, rc);
		ptlrpcd_decref();
		RETURN(rc);
	}

	ptlrpc_lprocfs_register_obd(lwp->lpd_obd);

	RETURN(0);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_free.
 *
 * Free a LWP device.
 *
 * \param[in] env	environment passed by caller
 * \param[in] lu	device to be freed
 *
 * \retval		NULL to indicate that this is the bottom device
 *			of the stack and there are no more devices
 *			below this one to be cleaned up.
 */
static struct lu_device *lwp_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct lwp_device *m = lu2lwp_dev(lu);
	ENTRY;

	lu_site_print(env, lu->ld_site, &lu->ld_ref, D_ERROR,
		      lu_cdebug_printer);
	lu_device_fini(&m->lpd_dev);
	OBD_FREE_PTR(m);
	RETURN(NULL);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_alloc.
 *
 * Allocate a LWP device.
 *
 * \param[in] env	environment passed by caller
 * \param[in] ldt	device type whose name is LUSTRE_LWP_NAME
 * \param[in] lcfg	lustre_cfg contains remote target UUID
 *
 * \retval		pointer of allocated LWP device on success
 * \retval		ERR_PTR(errno) on error
 */
static struct lu_device *lwp_device_alloc(const struct lu_env *env,
					  struct lu_device_type *ldt,
					  struct lustre_cfg *lcfg)
{
	struct lwp_device *lwp;
	struct lu_device  *ludev;

	OBD_ALLOC_PTR(lwp);
	if (lwp == NULL) {
		ludev = ERR_PTR(-ENOMEM);
	} else {
		int rc;

		ludev = lwp2lu_dev(lwp);
		lu_device_init(&lwp->lpd_dev, ldt);
		rc = lwp_init0(env, lwp, ldt, lcfg);
		if (rc != 0) {
			lwp_device_free(env, ludev);
			ludev = ERR_PTR(rc);
		}
	}
	return ludev;
}


/**
 * Implementation of lu_device_type_operations::ltdo_device_fini.
 *
 * Finalize LWP device.
 *
 * \param[in] env	environment passed by caller
 * \param[in] ludev	device to be finalized
 *
 * \retval		NULL on success
 */
static struct lu_device *lwp_device_fini(const struct lu_env *env,
					 struct lu_device *ludev)
{
	struct lwp_device	*m = lu2lwp_dev(ludev);
	struct task_struct	*task = NULL;
	int			 rc;
	ENTRY;

	task = xchg(&m->lpd_notify_task, NULL);
	if (task) {
		kthread_stop(task);
		class_export_put(m->lpd_exp);
	}

	if (m->lpd_exp != NULL)
		class_disconnect(m->lpd_exp);

	LASSERT(m->lpd_obd);
	rc = client_obd_cleanup(m->lpd_obd);
	LASSERTF(rc == 0, "error %d\n", rc);

	ptlrpc_lprocfs_unregister_obd(m->lpd_obd);

	ptlrpcd_decref();

	RETURN(NULL);
}

static const struct lu_device_type_operations lwp_device_type_ops = {
	.ldto_device_alloc	= lwp_device_alloc,
	.ldto_device_free	= lwp_device_free,
	.ldto_device_fini	= lwp_device_fini
};

struct lu_device_type lwp_device_type = {
	.ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_LWP_NAME,
	.ldt_ops      = &lwp_device_type_ops,
	.ldt_ctx_tags = LCT_MD_THREAD
};

static int lwp_notify_main(void *args)
{
	struct obd_export	*exp = (struct obd_export *)args;
	struct lwp_device	*lwp;

	LASSERT(exp != NULL);

	lwp = lu2lwp_dev(exp->exp_obd->obd_lu_dev);

	lustre_notify_lwp_list(exp);

	if (xchg(&lwp->lpd_notify_task, NULL) == NULL)
		/* lwp_device_fini() is waiting for me
		 * Note that the wakeup comes direct from
		 * kthread_stop, not from wake_up_var().
		 * lwp_device_fini() will call class_export_put().
		 */
		wait_var_event(lwp, kthread_should_stop());
	else
		class_export_put(exp);

	return 0;
}

/*
 * Some notify callbacks may cause deadlock in failover
 * scenario, so we have to start thread to run callbacks
 * asynchronously. See LU-6273.
 */
static void lwp_notify_users(struct obd_export *exp)
{
	struct lwp_device	*lwp;
	struct task_struct	*task;
	char			 name[MTI_NAME_MAXLEN];

	LASSERT(exp != NULL);
	lwp = lu2lwp_dev(exp->exp_obd->obd_lu_dev);

	snprintf(name, MTI_NAME_MAXLEN, "lwp_notify_%s",
		 exp->exp_obd->obd_name);

	/* Notify happens only on LWP setup, so there shouldn't
	 * be notify thread running */
	if (lwp->lpd_notify_task) {
		CERROR("LWP notify thread: %s wasn't stopped\n", name);
		return;
	}

	task = kthread_create(lwp_notify_main, exp, name);
	if (IS_ERR(task)) {
		CERROR("Failed to start LWP notify thread:%s. %lu\n",
		       name, PTR_ERR(task));
	} else {
		lwp->lpd_notify_task = task;
		class_export_get(exp);
		wake_up_process(task);
	}
}

/**
 * Implementation of OBD device operations obd_ops::o_connect.
 *
 * Create export for LWP, and connect to target server.
 *
 * \param[in] env	the environment passed by caller
 * \param[out] exp	export for the connection to be established
 * \param[in] obd	OBD device to perform the connect on
 * \param[in] cluuid	UUID of the OBD device
 * \param[in] data	connect data containing compatibility flags
 * \param[in] localdata	not used
 *
 * \retval		0 on success
 * \retval		negative number on error
 */
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
	imp->imp_connect_flags2_orig = ocd->ocd_connect_flags2;

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

	if (rc == 0)
		lwp_notify_users(*exp);

	return rc;
}

/**
 * Implementation of OBD device operations obd_ops::o_disconnect.
 *
 * Release export for the LWP. Only disconnect the underlying layers
 * on the final disconnect.
 *
 * \param[in] exp	the export to perform disconnect on
 *
 * \retval		0 on success
 * \retval		negative number on error
 */
static int lwp_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct lwp_device *lwp = lu2lwp_dev(obd->obd_lu_dev);
	int                rc;
	ENTRY;

	LASSERT(lwp->lpd_connects == 1);
	lwp->lpd_connects--;

	rc = class_disconnect(exp);
	if (rc)
		CERROR("%s: class disconnect error: rc = %d\n",
		       obd->obd_name, rc);

	RETURN(rc);
}

/**
 * Handle import events for the LWP device.
 *
 * \param[in] obd	OBD device associated with the import
 * \param[in] imp	the import which event happened on
 * \param[in] event	event type
 *
 * \retval		0 on success
 * \retval		negative number on error
 */
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

static int lwp_set_info_async(const struct lu_env *env,
			      struct obd_export *exp,
			      u32 keylen, void *key,
			      u32 vallen, void *val,
			      struct ptlrpc_request_set *set)
{
	ENTRY;

	if (KEY_IS(KEY_SPTLRPC_CONF)) {
		sptlrpc_conf_client_adapt(exp->exp_obd);
		RETURN(0);
	}

	CERROR("Unknown key %s\n", (char *)key);
	RETURN(-EINVAL);
}

const struct obd_ops lwp_obd_device_ops = {
	.o_owner	= THIS_MODULE,
	.o_add_conn	= client_import_add_conn,
	.o_del_conn	= client_import_del_conn,
	.o_connect	= lwp_obd_connect,
	.o_disconnect	= lwp_obd_disconnect,
	.o_import_event	= lwp_import_event,
	.o_set_info_async   = lwp_set_info_async,
};
