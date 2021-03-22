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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osp/osp_dev.c
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 * Author: Di Wang <di.wang@intel.com>
 */
/*
 * The Object Storage Proxy (OSP) module provides an implementation of
 * the DT API for remote MDTs and OSTs. Every local OSP device (or
 * object) is a proxy for a remote OSD device (or object). Thus OSP
 * converts DT operations into RPCs, which are sent to the OUT service
 * on a remote target, converted back to DT operations, and
 * executed. Of course there are many ways in which this description
 * is inaccurate but it's a good enough mental model. OSP is used by
 * the MDT stack in several ways:
 *
 * - OSP devices allocate FIDs for the stripe sub-objects of a striped
 *   file or directory.
 *
 * - OSP objects represent the remote MDT and OST objects that are
 *   the stripes of a striped object.
 *
 * - OSP devices log, send, and track synchronous operations (setattr
 *   and unlink) to remote targets.
 *
 * - OSP objects are the bottom slice of the compound LU object
 *   representing a remote MDT object: MDT/MDD/LOD/OSP.
 *
 * - OSP objects are used by LFSCK to represent remote OST objects
 *   during the verification of MDT-OST consistency.
 *
 * - OSP devices batch idempotent requests (declare_attr_get() and
 *   declare_xattr_get()) to the remote target and cache their results.
 *
 * In addition the OSP layer implements a subset of the OBD device API
 * to support being a client of a remote target, connecting to other
 * layers, and FID allocation.
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/kthread.h>

#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_log.h>
#include <lustre_obdo.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <obd_class.h>

#include "osp_internal.h"

/* Slab for OSP object allocation */
struct kmem_cache *osp_object_kmem;

static struct lu_kmem_descr osp_caches[] = {
	{
		.ckd_cache = &osp_object_kmem,
		.ckd_name  = "osp_obj",
		.ckd_size  = sizeof(struct osp_object)
	},
	{
		.ckd_cache = NULL
	}
};

/**
 * Implementation of lu_device_operations::ldo_object_alloc
 *
 * Allocates an OSP object in memory, whose FID is on the remote target.
 *
 * \param[in] env	execution environment
 * \param[in] hdr	The header of the object stack. If it is NULL, it
 *                      means the object is not built from top device, i.e.
 *                      it is a sub-stripe object of striped directory or
 *                      an OST object.
 * \param[in] d		OSP device
 *
 * \retval object	object being created if the creation succeed.
 * \retval NULL		NULL if the creation failed.
 */
static struct lu_object *osp_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *hdr,
					  struct lu_device *d)
{
	struct lu_object_header	*h = NULL;
	struct osp_object	*o;
	struct lu_object	*l;

	OBD_SLAB_ALLOC_PTR_GFP(o, osp_object_kmem, GFP_NOFS);
	if (o != NULL) {
		l = &o->opo_obj.do_lu;

		/* If hdr is NULL, it means the object is not built
		 * from the top dev(MDT/OST), usually it happens when
		 * building striped object, like data object on MDT or
		 * striped object for directory */
		if (hdr == NULL) {
			h = &o->opo_header;
			lu_object_header_init(h);
			dt_object_init(&o->opo_obj, h, d);
			lu_object_add_top(h, l);
		} else {
			dt_object_init(&o->opo_obj, h, d);
		}

		l->lo_ops = &osp_lu_obj_ops;

		return l;
	} else {
		return NULL;
	}
}

/**
 * Find or create the local object
 *
 * Finds or creates the local file referenced by \a reg_id and return the
 * attributes of the local file.
 *
 * \param[in] env	execution environment
 * \param[in] osp	OSP device
 * \param[out] attr	attributes of the object
 * \param[in] reg_id	the local object ID of the file. It will be used
 *                      to compose a local FID{FID_SEQ_LOCAL_FILE, reg_id, 0}
 *                      to identify the object.
 *
 * \retval object		object(dt_object) found or created
 * \retval ERR_PTR(errno)	ERR_PTR(errno) if not get the object.
 */
static struct dt_object
*osp_find_or_create_local_file(const struct lu_env *env, struct osp_device *osp,
			       struct lu_attr *attr, __u32 reg_id)
{
	struct osp_thread_info *osi = osp_env_info(env);
	struct dt_object_format dof = { 0 };
	struct dt_object       *dto;
	int		     rc;
	ENTRY;

	lu_local_obj_fid(&osi->osi_fid, reg_id);
	attr->la_valid = LA_MODE;
	attr->la_mode = S_IFREG | 0644;
	dof.dof_type = DFT_REGULAR;
	/* Find or create the local object by osi_fid. */
	dto = dt_find_or_create(env, osp->opd_storage, &osi->osi_fid,
				&dof, attr);
	if (IS_ERR(dto))
		RETURN(dto);

	/* Get attributes of the local object. */
	rc = dt_attr_get(env, dto, attr);
	if (rc) {
		CERROR("%s: can't be initialized: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		dt_object_put(env, dto);
		RETURN(ERR_PTR(rc));
	}
	RETURN(dto);
}

/**
 * Write data buffer to a local file object.
 *
 * \param[in] env	execution environment
 * \param[in] osp	OSP device
 * \param[in] dt_obj	object written to
 * \param[in] buf	buffer containing byte array and length
 * \param[in] offset	write offset in the object in bytes
 *
 * \retval 0		0 if write succeed
 * \retval -EFAULT	-EFAULT if only part of buffer is written.
 * \retval negative		other negative errno if write failed.
 */
static int osp_write_local_file(const struct lu_env *env,
				struct osp_device *osp,
				struct dt_object *dt_obj,
				struct lu_buf *buf,
				loff_t offset)
{
	struct thandle *th;
	int rc;

	if (osp->opd_storage->dd_rdonly)
		RETURN(0);

	th = dt_trans_create(env, osp->opd_storage);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_record_write(env, dt_obj, buf, offset, th);
	if (rc)
		GOTO(out, rc);
	rc = dt_trans_start_local(env, osp->opd_storage, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_record_write(env, dt_obj, buf, &offset, th);
out:
	dt_trans_stop(env, osp->opd_storage, th);
	RETURN(rc);
}

/**
 * Initialize last ID object.
 *
 * This function initializes the LAST_ID file, which stores the current last
 * used id of data objects. The MDT will use the last used id and the last_seq
 * (\see osp_init_last_seq()) to synchronize the precreate object cache with
 * OSTs.
 *
 * \param[in] env	execution environment
 * \param[in] osp	OSP device
 *
 * \retval 0		0 if initialization succeed
 * \retval negative	negative errno if initialization failed
 */
static int osp_init_last_objid(const struct lu_env *env, struct osp_device *osp)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct lu_fid		*fid = &osp->opd_last_used_fid;
	struct dt_object	*dto;
	int			rc = -EFAULT;
	ENTRY;

	dto = osp_find_or_create_local_file(env, osp, &osi->osi_attr,
					    MDD_LOV_OBJ_OID);
	if (IS_ERR(dto))
		RETURN(PTR_ERR(dto));

	osp_objid_buf_prep(&osi->osi_lb, &osi->osi_off, &osp->opd_last_id,
			   osp->opd_index);

	/* object will be released in device cleanup path */
	if (osi->osi_attr.la_size >= (osi->osi_off + osi->osi_lb.lb_len)) {
		rc = dt_record_read(env, dto, &osi->osi_lb, &osi->osi_off);
		if (rc != 0 && rc != -EFAULT)
			GOTO(out, rc);
		/* In case of idif bits 32-48 go to f_seq
		 * (see osp_init_last_seq). So don't care
		 * about u64->u32 convertion. */
		fid->f_oid = osp->opd_last_id;
	}

	if (rc == -EFAULT) { /* fresh LAST_ID */
		osp->opd_last_id = 0;
		fid->f_oid = 0;
		rc = osp_write_local_file(env, osp, dto, &osi->osi_lb,
					  osi->osi_off);
		if (rc != 0)
			GOTO(out, rc);
	}
	osp->opd_last_used_oid_file = dto;
	RETURN(0);
out:
	/* object will be released in device cleanup path */
	CERROR("%s: can't initialize lov_objid: rc = %d\n",
	       osp->opd_obd->obd_name, rc);
	dt_object_put(env, dto);
	osp->opd_last_used_oid_file = NULL;
	RETURN(rc);
}

/**
 * Initialize last sequence object.
 *
 * This function initializes the LAST_SEQ file in the local OSD, which stores
 * the current last used sequence of data objects. The MDT will use the last
 * sequence and last id (\see osp_init_last_objid()) to synchronize the
 * precreate object cache with OSTs.
 *
 * \param[in] env	execution environment
 * \param[in] osp	OSP device
 *
 * \retval 0		0 if initialization succeed
 * \retval negative	negative errno if initialization failed
 */
static int osp_init_last_seq(const struct lu_env *env, struct osp_device *osp)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct lu_fid		*fid = &osp->opd_last_used_fid;
	struct dt_object	*dto;
	int			rc = -EFAULT;
	ENTRY;

	dto = osp_find_or_create_local_file(env, osp, &osi->osi_attr,
					    MDD_LOV_OBJ_OSEQ);
	if (IS_ERR(dto))
		RETURN(PTR_ERR(dto));

	osp_objseq_buf_prep(&osi->osi_lb, &osi->osi_off, &fid->f_seq,
			   osp->opd_index);

	/* object will be released in device cleanup path */
	if (osi->osi_attr.la_size >= (osi->osi_off + osi->osi_lb.lb_len)) {
		rc = dt_record_read(env, dto, &osi->osi_lb, &osi->osi_off);
		if (rc != 0 && rc != -EFAULT)
			GOTO(out, rc);
		if (fid_is_idif(fid))
			fid->f_seq = fid_idif_seq(osp->opd_last_id,
						  osp->opd_index);
	}

	if (rc == -EFAULT) { /* fresh OSP */
		fid->f_seq = 0;
		rc = osp_write_local_file(env, osp, dto, &osi->osi_lb,
					  osi->osi_off);
		if (rc != 0)
			GOTO(out, rc);
	}
	osp->opd_last_used_seq_file = dto;
	RETURN(0);
out:
	/* object will be released in device cleanup path */
	CERROR("%s: can't initialize lov_seq: rc = %d\n",
	       osp->opd_obd->obd_name, rc);
	dt_object_put(env, dto);
	osp->opd_last_used_seq_file = NULL;
	RETURN(rc);
}

/**
 * Initialize last OID and sequence object.
 *
 * If the MDT is just upgraded to 2.4 from the lower version, where the
 * LAST_SEQ file does not exist, the file will be created and IDIF sequence
 * will be written into the file.
 *
 * \param[in] env	execution environment
 * \param[in] osp	OSP device
 *
 * \retval 0		0 if initialization succeed
 * \retval negative	negative error if initialization failed
 */
static int osp_last_used_init(const struct lu_env *env, struct osp_device *osp)
{
	struct osp_thread_info *osi = osp_env_info(env);
	int		     rc;
	ENTRY;

	fid_zero(&osp->opd_last_used_fid);
	rc = osp_init_last_objid(env, osp);
	if (rc < 0) {
		CERROR("%s: Can not get ids %d from old objid!\n",
		       osp->opd_obd->obd_name, rc);
		RETURN(rc);
	}

	rc = osp_init_last_seq(env, osp);
	if (rc < 0) {
		CERROR("%s: Can not get sequence %d from old objseq!\n",
		       osp->opd_obd->obd_name, rc);
		GOTO(out, rc);
	}

	if (fid_oid(&osp->opd_last_used_fid) != 0 &&
	    fid_seq(&osp->opd_last_used_fid) == 0) {
		/* Just upgrade from the old version,
		 * set the seq to be IDIF */
		osp->opd_last_used_fid.f_seq =
		   fid_idif_seq(fid_oid(&osp->opd_last_used_fid),
				osp->opd_index);
		osp_objseq_buf_prep(&osi->osi_lb, &osi->osi_off,
				    &osp->opd_last_used_fid.f_seq,
				    osp->opd_index);
		rc = osp_write_local_file(env, osp, osp->opd_last_used_seq_file,
					  &osi->osi_lb, osi->osi_off);
		if (rc) {
			CERROR("%s : Can not write seq file: rc = %d\n",
			       osp->opd_obd->obd_name, rc);
			GOTO(out, rc);
		}
	}

	if (!fid_is_zero(&osp->opd_last_used_fid) &&
		 !fid_is_sane(&osp->opd_last_used_fid)) {
		CERROR("%s: Got invalid FID "DFID"\n", osp->opd_obd->obd_name,
			PFID(&osp->opd_last_used_fid));
		GOTO(out, rc = -EINVAL);
	}

	osp_fid_to_obdid(&osp->opd_last_used_fid, &osp->opd_last_id);
	CDEBUG(D_INFO, "%s: Init last used fid "DFID"\n",
	       osp->opd_obd->obd_name, PFID(&osp->opd_last_used_fid));
out:
	if (rc != 0) {
		if (osp->opd_last_used_oid_file != NULL) {
			dt_object_put(env, osp->opd_last_used_oid_file);
			osp->opd_last_used_oid_file = NULL;
		}
		if (osp->opd_last_used_seq_file != NULL) {
			dt_object_put(env, osp->opd_last_used_seq_file);
			osp->opd_last_used_seq_file = NULL;
		}
	}

	RETURN(rc);
}

/**
 * Release the last sequence and OID file objects in OSP device.
 *
 * \param[in] env	execution environment
 * \param[in] osp	OSP device
 */
static void osp_last_used_fini(const struct lu_env *env, struct osp_device *osp)
{
	/* release last_used file */
	if (osp->opd_last_used_oid_file != NULL) {
		dt_object_put(env, osp->opd_last_used_oid_file);
		osp->opd_last_used_oid_file = NULL;
	}

	if (osp->opd_last_used_seq_file != NULL) {
		dt_object_put(env, osp->opd_last_used_seq_file);
		osp->opd_last_used_seq_file = NULL;
	}
}

/**
 * Disconnects the connection between OSP and its correspondent MDT or OST, and
 * the import will be marked as inactive. It will only be called during OSP
 * cleanup process.
 *
 * \param[in] d		OSP device being disconnected
 *
 * \retval 0		0 if disconnection succeed
 * \retval negative	negative errno if disconnection failed
 */
static int osp_disconnect(struct osp_device *d)
{
	struct obd_device *obd = d->opd_obd;
	struct obd_import *imp;
	int rc = 0;

	imp = obd->u.cli.cl_import;

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
	(void)ptlrpc_pinger_del_import(imp);

	rc = ptlrpc_disconnect_import(imp, 0);
	if (rc != 0)
		CERROR("%s: can't disconnect: rc = %d\n", obd->obd_name, rc);

	ptlrpc_invalidate_import(imp);

	RETURN(rc);
}

/**
 * Initialize the osp_update structure in OSP device
 *
 * Allocate osp update structure and start update thread.
 *
 * \param[in] osp	OSP device
 *
 * \retval		0 if initialization succeeds.
 * \retval		negative errno if initialization fails.
 */
static int osp_update_init(struct osp_device *osp)
{
	struct task_struct *task;
	int rc;

	ENTRY;

	LASSERT(osp->opd_connect_mdt);

	if (osp->opd_storage->dd_rdonly)
		RETURN(0);

	OBD_ALLOC_PTR(osp->opd_update);
	if (osp->opd_update == NULL)
		RETURN(-ENOMEM);

	init_waitqueue_head(&osp->opd_update->ou_waitq);
	spin_lock_init(&osp->opd_update->ou_lock);
	INIT_LIST_HEAD(&osp->opd_update->ou_list);
	osp->opd_update->ou_rpc_version = 1;
	osp->opd_update->ou_version = 1;
	osp->opd_update->ou_generation = 0;

	rc = lu_env_init(&osp->opd_update->ou_env,
			 osp->opd_dt_dev.dd_lu_dev.ld_type->ldt_ctx_tags);
	if (rc < 0) {
		CERROR("%s: init env error: rc = %d\n", osp->opd_obd->obd_name,
		       rc);
		OBD_FREE_PTR(osp->opd_update);
		osp->opd_update = NULL;
		RETURN(rc);
	}
	/* start thread handling sending updates to the remote MDT */
	task = kthread_create(osp_send_update_thread, osp,
			      "osp_up%u-%u", osp->opd_index, osp->opd_group);
	if (IS_ERR(task)) {
		int rc = PTR_ERR(task);

		lu_env_fini(&osp->opd_update->ou_env);
		OBD_FREE_PTR(osp->opd_update);
		osp->opd_update = NULL;
		CERROR("%s: can't start precreate thread: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		RETURN(rc);
	}

	osp->opd_update->ou_update_task = task;
	wake_up_process(task);

	RETURN(0);
}

/**
 * Finialize osp_update structure in OSP device
 *
 * Stop the OSP update sending thread, then delete the left
 * osp thandle in the sending list.
 *
 * \param [in] osp	OSP device.
 */
static void osp_update_fini(const struct lu_env *env, struct osp_device *osp)
{
	struct osp_update_request *our;
	struct osp_update_request *tmp;
	struct osp_updates *ou = osp->opd_update;

	if (ou == NULL)
		return;

	kthread_stop(ou->ou_update_task);
	lu_env_fini(&ou->ou_env);

	/* Remove the left osp thandle from the list */
	spin_lock(&ou->ou_lock);
	list_for_each_entry_safe(our, tmp, &ou->ou_list,
				 our_list) {
		list_del_init(&our->our_list);
		LASSERT(our->our_th != NULL);
		osp_trans_callback(env, our->our_th, -EIO);
		/* our will be destroyed in osp_thandle_put() */
		osp_thandle_put(env, our->our_th);
	}
	spin_unlock(&ou->ou_lock);

	OBD_FREE_PTR(ou);
	osp->opd_update = NULL;
}

/**
 * Cleanup OSP, which includes disconnect import, cleanup unlink log, stop
 * precreate threads etc.
 *
 * \param[in] env	execution environment.
 * \param[in] d		OSP device being disconnected.
 *
 * \retval 0		0 if cleanup succeed
 * \retval negative	negative errno if cleanup failed
 */
static int osp_shutdown(const struct lu_env *env, struct osp_device *d)
{
	int			 rc = 0;
	ENTRY;

	LASSERT(env);

	rc = osp_disconnect(d);

	osp_statfs_fini(d);

	if (!d->opd_connect_mdt) {
		/* stop sync thread */
		osp_sync_fini(d);

		/* stop precreate thread */
		osp_precreate_fini(d);

		/* release last_used file */
		osp_last_used_fini(env, d);
	}

	obd_fid_fini(d->opd_obd);

	RETURN(rc);
}

/**
 * Implementation of osp_lu_ops::ldo_process_config
 *
 * This function processes config log records in OSP layer. It is usually
 * called from the top layer of MDT stack, and goes through the stack by calling
 * ldo_process_config of next layer.
 *
 * \param[in] env	execution environment
 * \param[in] dev	lu_device of OSP
 * \param[in] lcfg	config log
 *
 * \retval 0		0 if the config log record is executed correctly.
 * \retval negative	negative errno if the record execution fails.
 */
static int osp_process_config(const struct lu_env *env,
			      struct lu_device *dev, struct lustre_cfg *lcfg)
{
	struct osp_device *d = lu2osp_dev(dev);
	struct dt_device *dt = lu2dt_dev(dev);
	struct obd_device *obd = d->opd_obd;
	ssize_t count;
	int rc;

	ENTRY;

	switch (lcfg->lcfg_command) {
	case LCFG_PRE_CLEANUP:
		rc = osp_disconnect(d);
		osp_update_fini(env, d);
		if (obd->obd_namespace != NULL)
			ldlm_namespace_free_prior(obd->obd_namespace, NULL, 1);
		break;
	case LCFG_CLEANUP:
		lu_dev_del_linkage(dev->ld_site, dev);
		rc = osp_shutdown(env, d);
		break;
	case LCFG_PARAM:
		count = class_modify_config(lcfg, d->opd_connect_mdt ?
						  PARAM_OSP : PARAM_OSC,
					    &dt->dd_kobj);
		if (count < 0) {
			/* class_modify_config() haven't found matching
			 * parameter and returned an error so that layer(s)
			 * below could use that. But OSP is the bottom, so
			 * just ignore it
			 */
			CERROR("%s: unknown param %s\n",
			       (char *)lustre_cfg_string(lcfg, 0),
			       (char *)lustre_cfg_string(lcfg, 1));
		}
		rc = 0;
		break;
	default:
		CERROR("%s: unknown command %u\n",
		       (char *)lustre_cfg_string(lcfg, 0), lcfg->lcfg_command);
		rc = 0;
		break;
	}

	RETURN(rc);
}

/**
 * Implementation of osp_lu_ops::ldo_recovery_complete
 *
 * This function is called after recovery is finished, and OSP layer
 * will wake up precreate thread here.
 *
 * \param[in] env	execution environment
 * \param[in] dev	lu_device of OSP
 *
 * \retval 0		0 unconditionally
 */
static int osp_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	struct osp_device	*osp = lu2osp_dev(dev);

	ENTRY;
	osp->opd_recovery_completed = 1;

	if (!osp->opd_connect_mdt && osp->opd_pre != NULL)
		wake_up(&osp->opd_pre_waitq);

	RETURN(0);
}

/**
 * Implementation of lu_device_operations::ldo_fid_alloc() for OSP
 *
 * Allocate FID from remote MDT.
 *
 * see include/lu_object.h for the details.
 */
static int osp_fid_alloc(const struct lu_env *env, struct lu_device *d,
			 struct lu_fid *fid, struct lu_object *parent,
			 const struct lu_name *name)
{
	struct osp_device *osp = lu2osp_dev(d);
	struct client_obd *cli = &osp->opd_obd->u.cli;
	struct lu_client_seq *seq = cli->cl_seq;
	int rc;

	ENTRY;

	/* Sigh, fid client is not ready yet */
	if (!osp->opd_obd->u.cli.cl_seq)
		RETURN(-ENOTCONN);

	if (!osp->opd_obd->u.cli.cl_seq->lcs_exp)
		RETURN(-ENOTCONN);

	rc = seq_client_alloc_fid(env, seq, fid);

	RETURN(rc);
}

const struct lu_device_operations osp_lu_ops = {
	.ldo_object_alloc	= osp_object_alloc,
	.ldo_process_config	= osp_process_config,
	.ldo_recovery_complete	= osp_recovery_complete,
	.ldo_fid_alloc		= osp_fid_alloc,
};

/**
 * Implementation of dt_device_operations::dt_statfs
 *
 * This function provides statfs status (for precreation) from
 * corresponding OST. Note: this function only retrieves the status
 * from the OSP device, and the real statfs RPC happens inside
 * precreate thread (\see osp_statfs_update). Note: OSP for MDT does
 * not need to retrieve statfs data for now.
 *
 * \param[in] env	execution environment.
 * \param[in] dev	dt_device of OSP.
 * \param[out] sfs	holds the retrieved statfs data.
 *
 * \retval 0		0 statfs data was retrieved successfully or
 *                      retrieval was not needed
 * \retval negative	negative errno if get statfs failed.
 */
static int osp_statfs(const struct lu_env *env, struct dt_device *dev,
		      struct obd_statfs *sfs, struct obd_statfs_info *info)
{
	struct osp_device *d = dt2osp_dev(dev);
	struct obd_import *imp = d->opd_obd->u.cli.cl_import;

	ENTRY;

	if (imp->imp_state == LUSTRE_IMP_CLOSED)
		RETURN(-ESHUTDOWN);

	if (unlikely(d->opd_imp_active == 0))
		RETURN(-ENOTCONN);

	/* return recently updated data */
	*sfs = d->opd_statfs;
	if (info) {
		info->os_reserved_mb_low = d->opd_reserved_mb_low;
		info->os_reserved_mb_high = d->opd_reserved_mb_high;
	}

	if (d->opd_pre == NULL)
		RETURN(0);

	CDEBUG(D_OTHER, "%s: %llu blocks, %llu free, %llu avail, "
	       "%u bsize, %u reserved mb low, %u reserved mb high, "
	       "%llu files, %llu free files\n", d->opd_obd->obd_name,
	       sfs->os_blocks, sfs->os_bfree, sfs->os_bavail, sfs->os_bsize,
	       d->opd_reserved_mb_low, d->opd_reserved_mb_high,
	       sfs->os_files, sfs->os_ffree);


	if (info && !info->os_enable_pre)
		RETURN(0);

	/*
	 * The layer above osp (usually lod) can use f_precreated to
	 * estimate how many objects are available for immediate usage.
	 */
	spin_lock(&d->opd_pre_lock);
	sfs->os_fprecreated = osp_fid_diff(&d->opd_pre_last_created_fid,
					   &d->opd_pre_used_fid);
	sfs->os_fprecreated -= d->opd_pre_reserved;
	LASSERTF(sfs->os_fprecreated <= OST_MAX_PRECREATE * 2,
		 "last_created "DFID", next_fid "DFID", reserved %llu\n",
		 PFID(&d->opd_pre_last_created_fid), PFID(&d->opd_pre_used_fid),
		 d->opd_pre_reserved);
	spin_unlock(&d->opd_pre_lock);
	RETURN(0);
}

/**
 * Implementation of dt_device_operations::dt_sync
 *
 * This function synchronizes the OSP cache to the remote target. It wakes
 * up unlink log threads and sends out unlink records to the remote OST.
 *
 * \param[in] env	execution environment
 * \param[in] dev	dt_device of OSP
 *
 * \retval 0		0 if synchronization succeeds
 * \retval negative	negative errno if synchronization fails
 */
static int osp_sync(const struct lu_env *env, struct dt_device *dev)
{
	struct osp_device *d = dt2osp_dev(dev);
	time64_t start = ktime_get_seconds();
	int recs, rc = 0;
	u64 old;

	ENTRY;

	/* No Sync between MDTs yet. */
	if (d->opd_connect_mdt)
		RETURN(0);

	recs = atomic_read(&d->opd_sync_changes);
	old = atomic64_read(&d->opd_sync_processed_recs);

	osp_sync_force(env, dt2osp_dev(dev));

	if (unlikely(d->opd_imp_active == 0))
		RETURN(-ENOTCONN);

	down_write(&d->opd_async_updates_rwsem);

	CDEBUG(D_OTHER, "%s: async updates %d\n", d->opd_obd->obd_name,
	       atomic_read(&d->opd_async_updates_count));

	/* make sure the connection is fine */
	rc = wait_event_idle_timeout(
		d->opd_sync_barrier_waitq,
		atomic_read(&d->opd_async_updates_count) == 0,
		cfs_time_seconds(obd_timeout));
	if (rc > 0)
		rc = 0;
	else if (rc == 0)
		rc = -ETIMEDOUT;

	up_write(&d->opd_async_updates_rwsem);
	if (rc != 0)
		GOTO(out, rc);

	CDEBUG(D_CACHE, "%s: processed %llu\n", d->opd_obd->obd_name,
	       (unsigned long long)atomic64_read(&d->opd_sync_processed_recs));

	while (atomic64_read(&d->opd_sync_processed_recs) < old + recs) {
		__u64 last = atomic64_read(&d->opd_sync_processed_recs);
		/* make sure the connection is fine */
		wait_event_idle_timeout(
			d->opd_sync_barrier_waitq,
			atomic64_read(&d->opd_sync_processed_recs)
			     >= old + recs,
			cfs_time_seconds(obd_timeout));

		if (atomic64_read(&d->opd_sync_processed_recs) >= old + recs)
			break;

		if (atomic64_read(&d->opd_sync_processed_recs) != last) {
			/* some progress have been made,
			 * keep trying... */
			continue;
		}

		/* no changes and expired, something is wrong */
		GOTO(out, rc = -ETIMEDOUT);
	}

	/* block new processing (barrier>0 - few callers are possible */
	atomic_inc(&d->opd_sync_barrier);

	CDEBUG(D_CACHE, "%s: %u in flight\n", d->opd_obd->obd_name,
	       atomic_read(&d->opd_sync_rpcs_in_flight));

	/* wait till all-in-flight are replied, so executed by the target */
	/* XXX: this is used by LFSCK at the moment, which doesn't require
	 *	all the changes to be committed, but in general it'd be
	 *	better to wait till commit */
	while (atomic_read(&d->opd_sync_rpcs_in_flight) > 0) {
		old = atomic_read(&d->opd_sync_rpcs_in_flight);

		wait_event_idle_timeout(
			d->opd_sync_barrier_waitq,
			atomic_read(&d->opd_sync_rpcs_in_flight) == 0,
			cfs_time_seconds(obd_timeout));

		if (atomic_read(&d->opd_sync_rpcs_in_flight) == 0)
			break;

		if (atomic_read(&d->opd_sync_rpcs_in_flight) != old) {
			/* some progress have been made */
			continue;
		}

		/* no changes and expired, something is wrong */
		GOTO(out, rc = -ETIMEDOUT);
	}

out:
	/* resume normal processing (barrier=0) */
	atomic_dec(&d->opd_sync_barrier);
	osp_sync_check_for_work(d);

	CDEBUG(D_CACHE, "%s: done in %lld: rc = %d\n", d->opd_obd->obd_name,
	       ktime_get_seconds() - start, rc);

	RETURN(rc);
}

static const struct dt_device_operations osp_dt_ops = {
	.dt_statfs	 = osp_statfs,
	.dt_sync	 = osp_sync,
	.dt_trans_create = osp_trans_create,
	.dt_trans_start  = osp_trans_start,
	.dt_trans_stop   = osp_trans_stop,
	.dt_trans_cb_add   = osp_trans_cb_add,
};

/**
 * Connect OSP to local OSD.
 *
 * Locate the local OSD referenced by \a nextdev and connect to it. Sometimes,
 * OSP needs to access the local OSD to store some information. For example,
 * during precreate, it needs to update last used OID and sequence file
 * (LAST_SEQ) in local OSD.
 *
 * \param[in] env	execution environment
 * \param[in] osp	OSP device
 * \param[in] nextdev	the name of local OSD
 *
 * \retval 0		0 connection succeeded
 * \retval negative	negative errno connection failed
 */
static int osp_connect_to_osd(const struct lu_env *env, struct osp_device *osp,
			      const char *nextdev)
{
	struct obd_connect_data	*data = NULL;
	struct obd_device	*obd;
	int			 rc;

	ENTRY;

	LASSERT(osp->opd_storage_exp == NULL);

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		RETURN(-ENOMEM);

	obd = class_name2obd(nextdev);
	if (obd == NULL) {
		CERROR("%s: can't locate next device: %s\n",
		       osp->opd_obd->obd_name, nextdev);
		GOTO(out, rc = -ENOTCONN);
	}

	rc = obd_connect(env, &osp->opd_storage_exp, obd, &obd->obd_uuid, data,
			 NULL);
	if (rc) {
		CERROR("%s: cannot connect to next dev %s: rc = %d\n",
		       osp->opd_obd->obd_name, nextdev, rc);
		GOTO(out, rc);
	}

	osp->opd_dt_dev.dd_lu_dev.ld_site =
		osp->opd_storage_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(osp->opd_dt_dev.dd_lu_dev.ld_site);
	osp->opd_storage = lu2dt_dev(osp->opd_storage_exp->exp_obd->obd_lu_dev);

out:
	OBD_FREE_PTR(data);
	RETURN(rc);
}

/**
 * Determine if the lock needs to be cancelled
 *
 * Determine if the unused lock should be cancelled before replay, see
 * (ldlm_cancel_no_wait_policy()). Currently, only inode bits lock exists
 * between MDTs.
 *
 * \param[in] lock	lock to be checked.
 *
 * \retval		1 if the lock needs to be cancelled before replay.
 * \retval		0 if the lock does not need to be cancelled before
 *                      replay.
 */
static int osp_cancel_weight(struct ldlm_lock *lock)
{
	if (lock->l_resource->lr_type != LDLM_IBITS)
		RETURN(0);

	RETURN(1);
}

/**
 * Initialize OSP device according to the parameters in the configuration
 * log \a cfg.
 *
 * Reconstruct the local device name from the configuration profile, and
 * initialize necessary threads and structures according to the OSP type
 * (MDT or OST).
 *
 * Since there is no record in the MDT configuration for the local disk
 * device, we have to extract this from elsewhere in the profile.
 * The only information we get at setup is from the OSC records:
 * setup 0:{fsname}-OSTxxxx-osc[-MDTxxxx] 1:lustre-OST0000_UUID 2:NID
 *
 * Note: configs generated by Lustre 1.8 are missing the -MDTxxxx part,
 * so, we need to reconstruct the name of the underlying OSD from this:
 * {fsname}-{svname}-osd, for example "lustre-MDT0000-osd".
 *
 * \param[in] env	execution environment
 * \param[in] osp	OSP device
 * \param[in] ldt	lu device type of OSP
 * \param[in] cfg	configuration log
 *
 * \retval 0		0 if OSP initialization succeeded.
 * \retval negative	negative errno if OSP initialization failed.
 */
static int osp_init0(const struct lu_env *env, struct osp_device *osp,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	struct obd_device	*obd;
	struct obd_import	*imp;
	char *src, *tgt, *osdname = NULL;
	const char *mdt;
	int			rc;
	u32 idx;

	ENTRY;

	mutex_init(&osp->opd_async_requests_mutex);
	INIT_LIST_HEAD(&osp->opd_async_updates);
	init_rwsem(&osp->opd_async_updates_rwsem);
	atomic_set(&osp->opd_async_updates_count, 0);

	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (obd == NULL) {
		CERROR("Cannot find obd with name %s\n",
		       lustre_cfg_string(cfg, 0));
		RETURN(-ENODEV);
	}
	osp->opd_obd = obd;

	src = lustre_cfg_string(cfg, 0);
	if (src == NULL)
		RETURN(-EINVAL);

	tgt = strrchr(src, '-');
	if (tgt == NULL) {
		CERROR("%s: invalid target name %s: rc = %d\n",
		       osp->opd_obd->obd_name, lustre_cfg_string(cfg, 0),
		       -EINVAL);
		RETURN(-EINVAL);
	}

	if (strncmp(tgt, "-osc", 4) == 0) {
		/* Old OSC name fsname-OSTXXXX-osc */
		for (tgt--; tgt > src && *tgt != '-'; tgt--)
			;
		if (tgt == src) {
			CERROR("%s: invalid target name %s: rc = %d\n",
			       osp->opd_obd->obd_name,
			       lustre_cfg_string(cfg, 0), -EINVAL);
			RETURN(-EINVAL);
		}

		if (strncmp(tgt, "-OST", 4) != 0) {
			CERROR("%s: invalid target name %s: rc = %d\n",
			       osp->opd_obd->obd_name,
			       lustre_cfg_string(cfg, 0), -EINVAL);
			RETURN(-EINVAL);
		}

		rc = target_name2index(tgt + 1, &idx, &mdt);
		if (rc < 0 || rc & LDD_F_SV_ALL || mdt[0] != '-') {
			CERROR("%s: invalid OST index in '%s': rc = %d\n",
			       osp->opd_obd->obd_name, src, -EINVAL);
			RETURN(-EINVAL);
		}
		osp->opd_index = idx;
		osp->opd_group = 0;
		idx = tgt - src;
	} else {
		/* New OSC name fsname-OSTXXXX-osc-MDTXXXX */
		if (strncmp(tgt, "-MDT", 4) != 0 &&
		    strncmp(tgt, "-OST", 4) != 0) {
			CERROR("%s: invalid target name %s: rc = %d\n",
			       osp->opd_obd->obd_name,
			       lustre_cfg_string(cfg, 0), -EINVAL);
			RETURN(-EINVAL);
		}

		rc = target_name2index(tgt + 1, &idx, &mdt);
		if (rc < 0 || rc & LDD_F_SV_ALL || *mdt != '\0') {
			CERROR("%s: invalid OST index in '%s': rc = %d\n",
			       osp->opd_obd->obd_name, src, -EINVAL);
			RETURN(-EINVAL);
		}

		/* Get MDT index from the name and set it to opd_group,
		 * which will be used by OSP to connect with OST */
		osp->opd_group = idx;
		if (tgt - src <= 12) {
			CERROR("%s: invalid mdt index from %s: rc =%d\n",
			       osp->opd_obd->obd_name,
			       lustre_cfg_string(cfg, 0), -EINVAL);
			RETURN(-EINVAL);
		}

		if (strncmp(tgt - 12, "-MDT", 4) == 0)
			osp->opd_connect_mdt = 1;

		rc = target_name2index(tgt - 11, &idx, &mdt);
		if (rc < 0 || rc & LDD_F_SV_ALL || mdt[0] != '-') {
			CERROR("%s: invalid OST index in '%s': rc =%d\n",
			       osp->opd_obd->obd_name, src, -EINVAL);
			RETURN(-EINVAL);
		}

		osp->opd_index = idx;
		idx = tgt - src - 12;
	}
	/* check the fsname length, and after this everything else will fit */
	if (idx > MTI_NAME_MAXLEN) {
		CERROR("%s: fsname too long in '%s': rc = %d\n",
		       osp->opd_obd->obd_name, src, -EINVAL);
		RETURN(-EINVAL);
	}

	OBD_ALLOC(osdname, MAX_OBD_NAME);
	if (osdname == NULL)
		RETURN(-ENOMEM);

	memcpy(osdname, src, idx); /* copy just the fsname part */
	osdname[idx] = '\0';

	mdt = strstr(mdt, "-MDT");
	if (mdt == NULL) /* 1.8 configs don't have "-MDT0000" at the end */
		strcat(osdname, "-MDT0000");
	else
		strcat(osdname, mdt);
	strcat(osdname, "-osd");
	CDEBUG(D_HA, "%s: connect to %s (%s)\n", obd->obd_name, osdname, src);

	osp_init_rpc_lock(osp);

	osp->opd_dt_dev.dd_lu_dev.ld_ops = &osp_lu_ops;
	osp->opd_dt_dev.dd_ops = &osp_dt_ops;

	obd->obd_lu_dev = &osp->opd_dt_dev.dd_lu_dev;

	rc = osp_connect_to_osd(env, osp, osdname);
	if (rc)
		GOTO(out_fini, rc);

	rc = ptlrpcd_addref();
	if (rc)
		GOTO(out_disconnect, rc);

	rc = client_obd_setup(obd, cfg);
	if (rc) {
		CERROR("%s: can't setup obd: rc = %d\n", osp->opd_obd->obd_name,
		       rc);
		GOTO(out_ref, rc);
	}

	osp_tunables_init(osp);

	rc = obd_fid_init(osp->opd_obd, NULL, osp->opd_connect_mdt ?
			  LUSTRE_SEQ_METADATA : LUSTRE_SEQ_DATA);
	if (rc) {
		CERROR("%s: fid init error: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		GOTO(out_proc, rc);
	}

	if (!osp->opd_connect_mdt) {
		/* Initialize last id from the storage - will be
		 * used in orphan cleanup. */
		if (!osp->opd_storage->dd_rdonly) {
			rc = osp_last_used_init(env, osp);
			if (rc)
				GOTO(out_fid, rc);
		}

		/* Initialize precreation thread, it handles new
		 * connections as well. */
		rc = osp_init_precreate(osp);
		if (rc)
			GOTO(out_last_used, rc);

		/*
		 * Initialize synhronization mechanism taking
		 * care of propogating changes to OST in near
		 * transactional manner.
		 */
		rc = osp_sync_init(env, osp);
		if (rc < 0)
			GOTO(out_precreat, rc);
	} else {
		osp->opd_got_disconnected = 1;
		rc = osp_update_init(osp);
		if (rc != 0)
			GOTO(out_fid, rc);
	}

	rc = osp_init_statfs(osp);
	if (rc)
		GOTO(out_precreat, rc);

	ns_register_cancel(obd->obd_namespace, osp_cancel_weight);

	/*
	 * Initiate connect to OST
	 */
	imp = obd->u.cli.cl_import;

	rc = ptlrpc_init_import(imp);
	if (rc)
		GOTO(out, rc);
	if (osdname)
		OBD_FREE(osdname, MAX_OBD_NAME);
	RETURN(0);

out:
	if (!osp->opd_connect_mdt)
		/* stop sync thread */
		osp_sync_fini(osp);
out_precreat:
	/* stop precreate thread */
	if (!osp->opd_connect_mdt)
		osp_precreate_fini(osp);
	else
		osp_update_fini(env, osp);
out_last_used:
	if (!osp->opd_connect_mdt)
		osp_last_used_fini(env, osp);
out_fid:
	obd_fid_fini(osp->opd_obd);
out_proc:
	osp_tunables_fini(osp);
	client_obd_cleanup(obd);
out_ref:
	ptlrpcd_decref();
out_disconnect:
	obd_disconnect(osp->opd_storage_exp);
out_fini:
	if (osdname)
		OBD_FREE(osdname, MAX_OBD_NAME);
	RETURN(rc);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_free
 *
 * Free the OSP device in memory.  No return value is needed for now,
 * so always return NULL to comply with the interface.
 *
 * \param[in] env	execution environment
 * \param[in] lu	lu_device of OSP
 *
 * \retval NULL		NULL unconditionally
 */
static struct lu_device *osp_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct osp_device *osp = lu2osp_dev(lu);

	lu_site_print(env, lu->ld_site, &lu->ld_ref, D_ERROR,
		      lu_cdebug_printer);
	dt_device_fini(&osp->opd_dt_dev);
	OBD_FREE_PTR(osp);

	return NULL;
}

/**
 * Implementation of lu_device_type_operations::ldto_device_alloc
 *
 * This function allocates and initializes OSP device in memory according to
 * the config log.
 *
 * \param[in] env	execution environment
 * \param[in] type	device type of OSP
 * \param[in] lcfg	config log
 *
 * \retval pointer		the pointer of allocated OSP if succeed.
 * \retval ERR_PTR(errno)	ERR_PTR(errno) if failed.
 */
static struct lu_device *osp_device_alloc(const struct lu_env *env,
					  struct lu_device_type *type,
					  struct lustre_cfg *lcfg)
{
	struct osp_device *osp;
	struct lu_device  *ld;

	OBD_ALLOC_PTR(osp);
	if (osp == NULL) {
		ld = ERR_PTR(-ENOMEM);
	} else {
		int rc;

		ld = osp2lu_dev(osp);
		dt_device_init(&osp->opd_dt_dev, type);
		rc = osp_init0(env, osp, type, lcfg);
		if (rc != 0) {
			osp_device_free(env, ld);
			ld = ERR_PTR(rc);
		}
	}
	return ld;
}

/**
 * Implementation of lu_device_type_operations::ldto_device_fini
 *
 * This function cleans up the OSP device, i.e. release and free those
 * attached items in osp_device.
 *
 * \param[in] env	execution environment
 * \param[in] ld	lu_device of OSP
 *
 * \retval NULL			NULL if cleanup succeeded.
 * \retval ERR_PTR(errno)	ERR_PTR(errno) if cleanup failed.
 */
static struct lu_device *osp_device_fini(const struct lu_env *env,
					 struct lu_device *ld)
{
	struct osp_device *osp = lu2osp_dev(ld);
	int                rc;

	ENTRY;

	if (osp->opd_async_requests != NULL) {
		osp_update_request_destroy(env, osp->opd_async_requests);
		osp->opd_async_requests = NULL;
	}

	if (osp->opd_storage_exp) {
		/* wait for the commit callbacks to complete */
		wait_event(osp->opd_sync_waitq,
			  atomic_read(&osp->opd_commits_registered) == 0);
		obd_disconnect(osp->opd_storage_exp);
	}

	LASSERT(osp->opd_obd);

	rc = client_obd_cleanup(osp->opd_obd);
	if (rc != 0) {
		ptlrpcd_decref();
		RETURN(ERR_PTR(rc));
	}

	osp_tunables_fini(osp);

	ptlrpcd_decref();

	RETURN(NULL);
}

/**
 * Implementation of obd_ops::o_reconnect
 *
 * This function is empty and does not need to do anything for now.
 */
static int osp_reconnect(const struct lu_env *env,
			 struct obd_export *exp, struct obd_device *obd,
			 struct obd_uuid *cluuid,
			 struct obd_connect_data *data,
			 void *localdata)
{
	return 0;
}

/*
 * Implementation of obd_ops::o_connect
 *
 * Connect OSP to the remote target (MDT or OST). Allocate the
 * export and return it to the LOD, which calls this function
 * for each OSP to connect it to the remote target. This function
 * is currently only called once per OSP.
 *
 * \param[in] env	execution environment
 * \param[out] exp	export connected to OSP
 * \param[in] obd	OSP device
 * \param[in] cluuid	OSP device client uuid
 * \param[in] data	connect_data to be used to connect to the remote
 *                      target
 * \param[in] localdata necessary for the API interface, but not used in
 *                      this function
 *
 * \retval 0		0 if the connection succeeded.
 * \retval negative	negative errno if the connection failed.
 */
static int osp_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct osp_device       *osp = lu2osp_dev(obd->obd_lu_dev);
	struct obd_connect_data *ocd;
	struct obd_import       *imp;
	struct lustre_handle     conn;
	int                      rc;

	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", osp->opd_connects);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	*exp = class_conn2export(&conn);
	/* Why should there ever be more than 1 connect? */
	osp->opd_connects++;
	LASSERT(osp->opd_connects == 1);

	osp->opd_exp = *exp;

	imp = osp->opd_obd->u.cli.cl_import;
	imp->imp_dlm_handle = conn;

	LASSERT(data != NULL);
	LASSERT(data->ocd_connect_flags & OBD_CONNECT_INDEX);
	ocd = &imp->imp_connect_data;
	*ocd = *data;

	imp->imp_connect_flags_orig = ocd->ocd_connect_flags;
	imp->imp_connect_flags2_orig = ocd->ocd_connect_flags2;

	ocd->ocd_version = LUSTRE_VERSION_CODE;
	ocd->ocd_index = data->ocd_index;

	rc = ptlrpc_connect_import(imp);
	if (rc) {
		CERROR("%s: can't connect obd: rc = %d\n", obd->obd_name, rc);
		GOTO(out, rc);
	} else {
		osp->opd_obd->u.cli.cl_seq->lcs_exp =
				class_export_get(osp->opd_exp);
	}

	ptlrpc_pinger_add_import(imp);
out:
	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_disconnect
 *
 * Disconnect the export for the OSP.  This is called by LOD to release the
 * OSP during cleanup (\see lod_del_device()). The OSP will be released after
 * the export is released.
 *
 * \param[in] exp	export to be disconnected.
 *
 * \retval 0		0 if disconnection succeed
 * \retval negative	negative errno if disconnection failed
 */
static int osp_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);
	int                rc;
	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	LASSERT(osp->opd_connects == 1);
	osp->opd_connects--;

	rc = class_disconnect(exp);
	if (rc) {
		CERROR("%s: class disconnect error: rc = %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	/* destroy the device */
	class_manual_cleanup(obd);

	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_statfs
 *
 * Send a RPC to the remote target to get statfs status. This is only used
 * in lprocfs helpers by obd_statfs.
 *
 * \param[in] env	execution environment
 * \param[in] exp	connection state from this OSP to the parent (LOD)
 *                      device
 * \param[out] osfs	hold the statfs result
 * \param[in] unused    Not used in this function for now
 * \param[in] flags	flags to indicate how OSP will issue the RPC
 *
 * \retval 0		0 if statfs succeeded.
 * \retval negative	negative errno if statfs failed.
 */
static int osp_obd_statfs(const struct lu_env *env, struct obd_export *exp,
			  struct obd_statfs *osfs, time64_t unused, __u32 flags)
{
	struct obd_statfs	*msfs;
	struct ptlrpc_request	*req;
	struct obd_import	*imp = NULL, *imp0;
	int			 rc;

	ENTRY;

	/* Since the request might also come from lprocfs, so we need
	 * sync this with client_disconnect_export Bug15684
	 */
	with_imp_locked(exp->exp_obd, imp0, rc)
		imp = class_import_get(imp0);
	if (rc)
		RETURN(rc);

	req = ptlrpc_request_alloc(imp, &RQF_OST_STATFS);

	class_import_put(imp);

	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_STATFS);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}
	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OST_CREATE_PORTAL;
	ptlrpc_at_set_req_timeout(req);

	if (flags & OBD_STATFS_NODELAY) {
		/* procfs requests not want stat in wait for avoid deadlock */
		req->rq_no_resend = 1;
		req->rq_no_delay = 1;
	}

	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out, rc);

	msfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);
	if (msfs == NULL)
		GOTO(out, rc = -EPROTO);

	*osfs = *msfs;

	EXIT;
out:
	ptlrpc_req_finished(req);
	return rc;
}

/**
 * Implementation of obd_ops::o_import_event
 *
 * This function is called when some related import event happens. It will
 * mark the necessary flags according to the event and notify the necessary
 * threads (mainly precreate thread).
 *
 * \param[in] obd	OSP OBD device
 * \param[in] imp	import attached from OSP to remote (OST/MDT) service
 * \param[in] event	event related to remote service (IMP_EVENT_*)
 *
 * \retval 0		0 if the event handling succeeded.
 * \retval negative	negative errno if the event handling failed.
 */
static int osp_import_event(struct obd_device *obd, struct obd_import *imp,
			    enum obd_import_event event)
{
	struct osp_device *d = lu2osp_dev(obd->obd_lu_dev);
	int rc;

	switch (event) {
	case IMP_EVENT_DISCON:
		d->opd_got_disconnected = 1;
		d->opd_imp_connected = 0;
		if (d->opd_connect_mdt)
			break;

		if (d->opd_pre != NULL) {
			osp_pre_update_status(d, -ENODEV);
			wake_up(&d->opd_pre_waitq);
		}

		CDEBUG(D_HA, "got disconnected\n");
		break;
	case IMP_EVENT_INACTIVE:
		d->opd_imp_active = 0;
		d->opd_imp_connected = 0;
		d->opd_obd->obd_inactive = 1;
		if (d->opd_connect_mdt)
			break;
		if (d->opd_pre != NULL) {
			/* Import is invalid, we can`t get stripes so
			 * wakeup waiters */
			rc = imp->imp_deactive ? -ESHUTDOWN : -ENODEV;
			osp_pre_update_status(d, rc);
			wake_up(&d->opd_pre_waitq);
		}

		CDEBUG(D_HA, "got inactive\n");
		break;
	case IMP_EVENT_ACTIVE:
		d->opd_imp_active = 1;

		d->opd_new_connection = 1;
		d->opd_imp_connected = 1;
		d->opd_imp_seen_connected = 1;
		d->opd_obd->obd_inactive = 0;
		wake_up(&d->opd_pre_waitq);
		if (d->opd_connect_mdt)
			break;

		osp_sync_check_for_work(d);
		CDEBUG(D_HA, "got connected\n");
		break;
	case IMP_EVENT_INVALIDATE:
		if (d->opd_connect_mdt)
			osp_invalidate_request(d);

		if (obd->obd_namespace == NULL)
			break;
		ldlm_namespace_cleanup(obd->obd_namespace, LDLM_FL_LOCAL_ONLY);
		break;
	case IMP_EVENT_OCD:
	case IMP_EVENT_DEACTIVATE:
	case IMP_EVENT_ACTIVATE:
		break;
	default:
		CERROR("%s: unsupported import event: %#x\n",
		       obd->obd_name, event);
	}
	return 0;
}

/**
 * Implementation of obd_ops: o_iocontrol
 *
 * This function is the ioctl handler for OSP. Note: lctl will access the OSP
 * directly by ioctl, instead of through the MDS stack.
 *
 * param[in] cmd	ioctl command.
 * param[in] exp	export of this OSP.
 * param[in] len	data length of \a karg.
 * param[in] karg	input argument which is packed as
 *                      obd_ioctl_data
 * param[out] uarg	pointer to userspace buffer (must access by
 *                      copy_to_user()).
 *
 * \retval 0		0 if the ioctl handling succeeded.
 * \retval negative	negative errno if the ioctl handling failed.
 */
static int osp_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
			 void *karg, void __user *uarg)
{
	struct obd_device	*obd = exp->exp_obd;
	struct osp_device	*d;
	struct obd_ioctl_data	*data = karg;
	int			 rc = 0;

	ENTRY;

	LASSERT(obd->obd_lu_dev);
	d = lu2osp_dev(obd->obd_lu_dev);
	LASSERT(d->opd_dt_dev.dd_ops == &osp_dt_ops);

	if (!try_module_get(THIS_MODULE)) {
		CERROR("%s: cannot get module '%s'\n", obd->obd_name,
		       module_name(THIS_MODULE));
		return -EINVAL;
	}

	switch (cmd) {
	case OBD_IOC_CLIENT_RECOVER:
		rc = ptlrpc_recover_import(obd->u.cli.cl_import,
					   data->ioc_inlbuf1, 0);
		if (rc > 0)
			rc = 0;
		break;
	case IOC_OSC_SET_ACTIVE:
		rc = ptlrpc_set_import_active(obd->u.cli.cl_import,
					      data->ioc_offset);
		break;
	default:
		CERROR("%s: unrecognized ioctl %#x by %s\n", obd->obd_name,
		       cmd, current->comm);
		rc = -ENOTTY;
	}
	module_put(THIS_MODULE);
	return rc;
}


/**
 * Implementation of obd_ops::o_get_info
 *
 * Retrieve information by key. Retrieval starts from the top layer
 * (MDT) of the MDS stack and traverses the stack by calling the
 * obd_get_info() method of the next sub-layer.
 *
 * \param[in] env	execution environment
 * \param[in] exp	export of this OSP
 * \param[in] keylen	length of \a key
 * \param[in] key	the key
 * \param[out] vallen	length of \a val
 * \param[out] val	holds the value returned by the key
 *
 * \retval 0		0 if getting information succeeded.
 * \retval negative	negative errno if getting information failed.
 */
static int osp_obd_get_info(const struct lu_env *env, struct obd_export *exp,
			    __u32 keylen, void *key, __u32 *vallen, void *val)
{
	int rc = -EINVAL;

	if (KEY_IS(KEY_OSP_CONNECTED)) {
		struct obd_device	*obd = exp->exp_obd;
		struct osp_device	*osp;

		if (!obd->obd_set_up || obd->obd_stopping)
			RETURN(-EAGAIN);

		osp = lu2osp_dev(obd->obd_lu_dev);
		LASSERT(osp);
		/*
		 * 1.8/2.0 behaviour is that OST being connected once at least
		 * is considered "healthy". and one "healthy" OST is enough to
		 * allow lustre clients to connect to MDS
		 */
		RETURN(!osp->opd_imp_seen_connected);
	}

	RETURN(rc);
}

static int osp_obd_set_info_async(const struct lu_env *env,
				  struct obd_export *exp,
				  u32 keylen, void *key,
				  u32 vallen, void *val,
				  struct ptlrpc_request_set *set)
{
	struct obd_device	*obd = exp->exp_obd;
	struct obd_import	*imp = obd->u.cli.cl_import;
	struct osp_device	*osp;
	struct ptlrpc_request	*req;
	char			*tmp;
	int			 rc;

	if (KEY_IS(KEY_SPTLRPC_CONF)) {
		sptlrpc_conf_client_adapt(exp->exp_obd);
		RETURN(0);
	}

	LASSERT(set != NULL);
	if (!obd->obd_set_up || obd->obd_stopping)
		RETURN(-EAGAIN);
	osp = lu2osp_dev(obd->obd_lu_dev);

	req = ptlrpc_request_alloc(imp, &RQF_OBD_SET_INFO);
	if (req == NULL)
		RETURN(-ENOMEM);

	req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_KEY,
			     RCL_CLIENT, keylen);
	req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_VAL,
			     RCL_CLIENT, vallen);
	if (osp->opd_connect_mdt)
		rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, MDS_SET_INFO);
	else
		rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SET_INFO);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
	memcpy(tmp, key, keylen);
	tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_VAL);
	memcpy(tmp, val, vallen);

	ptlrpc_request_set_replen(req);
	ptlrpc_set_add_req(set, req);
	ptlrpc_check_set(NULL, set);

	RETURN(0);
}

/* context key constructor/destructor: mdt_key_init, mdt_key_fini */
LU_KEY_INIT_FINI(osp, struct osp_thread_info);
static void osp_key_exit(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct osp_thread_info *info = data;

	info->osi_attr.la_valid = 0;
}

struct lu_context_key osp_thread_key = {
	.lct_tags = LCT_MD_THREAD,
	.lct_init = osp_key_init,
	.lct_fini = osp_key_fini,
	.lct_exit = osp_key_exit
};

/* context key constructor/destructor: mdt_txn_key_init, mdt_txn_key_fini */
LU_KEY_INIT_FINI(osp_txn, struct osp_txn_info);

struct lu_context_key osp_txn_key = {
	.lct_tags = LCT_OSP_THREAD,
	.lct_init = osp_txn_key_init,
	.lct_fini = osp_txn_key_fini
};
LU_TYPE_INIT_FINI(osp, &osp_thread_key, &osp_txn_key);

static const struct lu_device_type_operations osp_device_type_ops = {
	.ldto_init           = osp_type_init,
	.ldto_fini           = osp_type_fini,

	.ldto_start          = osp_type_start,
	.ldto_stop           = osp_type_stop,

	.ldto_device_alloc   = osp_device_alloc,
	.ldto_device_free    = osp_device_free,

	.ldto_device_fini    = osp_device_fini
};

static struct lu_device_type osp_device_type = {
	.ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_OSP_NAME,
	.ldt_ops      = &osp_device_type_ops,
	.ldt_ctx_tags = LCT_MD_THREAD | LCT_DT_THREAD,
};

static const struct obd_ops osp_obd_device_ops = {
	.o_owner	= THIS_MODULE,
	.o_add_conn	= client_import_add_conn,
	.o_del_conn	= client_import_del_conn,
	.o_reconnect	= osp_reconnect,
	.o_connect	= osp_obd_connect,
	.o_disconnect	= osp_obd_disconnect,
	.o_get_info     = osp_obd_get_info,
	.o_set_info_async = osp_obd_set_info_async,
	.o_import_event	= osp_import_event,
	.o_iocontrol	= osp_iocontrol,
	.o_statfs	= osp_obd_statfs,
	.o_fid_init	= client_fid_init,
	.o_fid_fini	= client_fid_fini,
};

/**
 * Initialize OSP module.
 *
 * Register device types OSP and Light Weight Proxy (LWP) (\see lwp_dev.c)
 * in obd_types (\see class_obd.c).  Initialize procfs for the
 * the OSP device.  Note: OSP was called OSC before Lustre 2.4,
 * so for compatibility it still uses the name "osc" in procfs.
 * This is called at module load time.
 *
 * \retval 0		0 if initialization succeeds.
 * \retval negative	negative errno if initialization failed.
 */
static int __init osp_init(void)
{
	struct obd_type *sym;
	int rc;

	rc = lu_kmem_init(osp_caches);
	if (rc)
		return rc;

	rc = class_register_type(&osp_obd_device_ops, NULL, false,
				 LUSTRE_OSP_NAME, &osp_device_type);
	if (rc != 0) {
		lu_kmem_fini(osp_caches);
		return rc;
	}

	rc = class_register_type(&lwp_obd_device_ops, NULL, false,
				 LUSTRE_LWP_NAME, &lwp_device_type);
	if (rc != 0) {
		class_unregister_type(LUSTRE_OSP_NAME);
		lu_kmem_fini(osp_caches);
		return rc;
	}

	/* create "osc" entry for compatibility purposes */
	sym = class_add_symlinks(LUSTRE_OSC_NAME, true);
	if (IS_ERR(sym)) {
		rc = PTR_ERR(sym);
		/* does real "osc" already exist ? */
		if (rc == -EEXIST)
			rc = 0;
	}

	return rc;
}

/**
 * Finalize OSP module.
 *
 * This callback is called when kernel unloads OSP module from memory, and
 * it will deregister OSP and LWP device type from obd_types (\see class_obd.c).
 */
static void __exit osp_exit(void)
{
	struct obd_type *sym = class_search_type(LUSTRE_OSC_NAME);

	/* if this was never fully initialized by the osc layer
	 * then we are responsible for freeing this obd_type
	 */
	if (sym) {
		/* final put if we manage this obd type */
		if (sym->typ_sym_filter)
			kobject_put(&sym->typ_kobj);
		/* put reference taken by class_search_type */
		kobject_put(&sym->typ_kobj);
	}

	class_unregister_type(LUSTRE_LWP_NAME);
	class_unregister_type(LUSTRE_OSP_NAME);
	lu_kmem_fini(osp_caches);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre OSD Storage Proxy ("LUSTRE_OSP_NAME")");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(osp_init);
module_exit(osp_exit);
