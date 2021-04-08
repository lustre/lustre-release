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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ofd/ofd_dev.c
 *
 * This file contains OSD API methods for OBD Filter Device (OFD),
 * request handlers and supplemental functions to set OFD up and clean it up.
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mike Pershin <mike.pershin@intel.com>
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 */
/*
 * The OBD Filter Device (OFD) module belongs to the Object Storage
 * Server stack and connects the RPC oriented Unified Target (TGT)
 * layer (see lustre/include/lu_target.h) to the storage oriented OSD
 * layer (see Documentation/osd-api.txt).
 *
 *     TGT
 *      |      DT and OBD APIs
 *     OFD
 *      |      DT API
 *     OSD
 *
 * OFD implements the LU and OBD device APIs and is responsible for:
 *
 * - Handling client requests (create, destroy, bulk IO, setattr,
 *   get_info, set_info, statfs) for the objects belonging to the OST
 *   (together with TGT).
 *
 * - Providing grant space management which allows clients to reserve
 *   disk space for data writeback. OFD tracks grants on global and
 *   per client levels.
 *
 * - Handling object precreation requests from MDTs.
 *
 * - Operating the LDLM service that allows clients to maintain object
 *   data cache coherence.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <obd_class.h>
#include <obd_cksum.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_fid.h>
#include <lustre_lfsck.h>
#include <lustre_dlm.h>
#include <lustre_quota.h>
#include <lustre_nodemap.h>
#include <lustre_log.h>
#include <linux/falloc.h>

#include "ofd_internal.h"

/* Slab for OFD object allocation */
static struct kmem_cache *ofd_object_kmem;
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

/**
 * Connect OFD to the next device in the stack.
 *
 * This function is used for device stack configuration and links OFD
 * device with bottom OSD device.
 *
 * \param[in]  env	execution environment
 * \param[in]  m	OFD device
 * \param[in]  next	name of next device in the stack
 * \param[out] exp	export to return
 *
 * \retval		0 and export in \a exp if successful
 * \retval		negative value on error
 */
static int ofd_connect_to_next(const struct lu_env *env, struct ofd_device *m,
			       const char *next, struct obd_export **exp)
{
	struct obd_connect_data *data = NULL;
	struct obd_device	*obd;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		GOTO(out, rc = -ENOMEM);

	obd = class_name2obd(next);
	if (obd == NULL) {
		CERROR("%s: can't locate next device: %s\n",
		       ofd_name(m), next);
		GOTO(out, rc = -ENOTCONN);
	}

	data->ocd_connect_flags = OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;

	rc = obd_connect(NULL, exp, obd, &obd->obd_uuid, data, NULL);
	if (rc) {
		CERROR("%s: cannot connect to next dev %s: rc = %d\n",
		       ofd_name(m), next, rc);
		GOTO(out, rc);
	}

	m->ofd_dt_dev.dd_lu_dev.ld_site =
		m->ofd_osd_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(m->ofd_dt_dev.dd_lu_dev.ld_site);
	m->ofd_osd = lu2dt_dev(m->ofd_osd_exp->exp_obd->obd_lu_dev);
	m->ofd_dt_dev.dd_lu_dev.ld_site->ls_top_dev = &m->ofd_dt_dev.dd_lu_dev;

out:
	if (data)
		OBD_FREE_PTR(data);
	RETURN(rc);
}

/**
 * Initialize stack of devices.
 *
 * This function initializes OFD-OSD device stack to serve OST requests
 *
 * \param[in] env	execution environment
 * \param[in] m		OFD device
 * \param[in] cfg	Lustre config for this server
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_stack_init(const struct lu_env *env,
			  struct ofd_device *m, struct lustre_cfg *cfg,
			  u32 *lmd_flags)
{
	const char		*dev = lustre_cfg_string(cfg, 0);
	struct lu_device	*d;
	struct ofd_thread_info	*info = ofd_info(env);
	struct lustre_mount_info *lmi;
	struct lustre_mount_data *lmd;
	int			 rc;
	char			*osdname;

	ENTRY;

	lmi = server_get_mount(dev);
	if (lmi == NULL) {
		CERROR("Cannot get mount info for %s!\n", dev);
		RETURN(-ENODEV);
	}

	lmd = s2lsi(lmi->lmi_sb)->lsi_lmd;
	if (lmd) {
		if (lmd->lmd_flags & LMD_FLG_SKIP_LFSCK)
			m->ofd_skip_lfsck = 1;
		if (lmd->lmd_flags & LMD_FLG_NO_PRECREATE)
			m->ofd_no_precreate = 1;
		*lmd_flags = lmd->lmd_flags;
	}

	/* find bottom osd */
	OBD_ALLOC(osdname, MTI_NAME_MAXLEN);
	if (osdname == NULL)
		RETURN(-ENOMEM);

	snprintf(osdname, MTI_NAME_MAXLEN, "%s-osd", dev);
	rc = ofd_connect_to_next(env, m, osdname, &m->ofd_osd_exp);
	OBD_FREE(osdname, MTI_NAME_MAXLEN);
	if (rc)
		RETURN(rc);

	d = m->ofd_osd_exp->exp_obd->obd_lu_dev;
	LASSERT(d);
	m->ofd_osd = lu2dt_dev(d);

	snprintf(info->fti_u.name, sizeof(info->fti_u.name),
		 "%s-osd", lustre_cfg_string(cfg, 0));

	RETURN(rc);
}

/**
 * Finalize the device stack OFD-OSD.
 *
 * This function cleans OFD-OSD device stack and
 * disconnects OFD from the OSD.
 *
 * \param[in] env	execution environment
 * \param[in] m		OFD device
 * \param[in] top	top device of stack
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static void ofd_stack_fini(const struct lu_env *env, struct ofd_device *m,
			   struct lu_device *top)
{
	struct obd_device	*obd = ofd_obd(m);
	struct lustre_cfg_bufs	 bufs;
	struct lustre_cfg	*lcfg;
	char			 flags[3] = "";

	ENTRY;

	lu_site_purge(env, top->ld_site, ~0);
	/* process cleanup, pass mdt obd name to get obd umount flags */
	lustre_cfg_bufs_reset(&bufs, obd->obd_name);
	if (obd->obd_force)
		strcat(flags, "F");
	if (obd->obd_fail)
		strcat(flags, "A");
	lustre_cfg_bufs_set_string(&bufs, 1, flags);
	OBD_ALLOC(lcfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (!lcfg)
		RETURN_EXIT;
	lustre_cfg_init(lcfg, LCFG_CLEANUP, &bufs);

	LASSERT(top);
	top->ld_ops->ldo_process_config(env, top, lcfg);
	OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens));

	if (m->ofd_los != NULL) {
		local_oid_storage_fini(env, m->ofd_los);
		m->ofd_los = NULL;
	}

	lu_site_purge(env, top->ld_site, ~0);
	lu_site_print(env, top->ld_site, &top->ld_site->ls_obj_hash.nelems,
		      D_OTHER, lu_cdebug_printer);
	LASSERT(m->ofd_osd_exp);
	obd_disconnect(m->ofd_osd_exp);

	EXIT;
}

static void ofd_stack_pre_fini(const struct lu_env *env, struct ofd_device *m,
			       struct lu_device *top)
{
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg;
	ENTRY;

	LASSERT(top);

	lustre_cfg_bufs_reset(&bufs, ofd_name(m));
	lustre_cfg_bufs_set_string(&bufs, 1, NULL);
	OBD_ALLOC(lcfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (!lcfg) {
		CERROR("%s: failed to trigger LCFG_PRE_CLEANUP\n", ofd_name(m));
	} else {
		lustre_cfg_init(lcfg, LCFG_PRE_CLEANUP, &bufs);
		top->ld_ops->ldo_process_config(env, top, lcfg);
		OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount,
					      lcfg->lcfg_buflens));
	}

	EXIT;
}

/* For interoperability, see mdt_interop_param[]. */
static struct cfg_interop_param ofd_interop_param[] = {
	{ "ost.quota_type",	NULL },
	{ NULL }
};

/**
 * Check if parameters are symlinks to the OSD.
 *
 * Some parameters were moved from ofd to osd and only their
 * symlinks were kept in ofd by LU-3106. They are:
 * -writehthrough_cache_enable
 * -readcache_max_filesize
 * -read_cache_enable
 * -brw_stats
 *
 * Since they are not included by the static lprocfs var list, a pre-check
 * is added for them to avoid "unknown param" errors. If they are matched
 * in this check, they will be passed to the OSD directly.
 *
 * \param[in] param	parameters to check
 *
 * \retval		true if param is symlink to OSD param
 *			false otherwise
 */
static bool match_symlink_param(char *param)
{
	char *sval;
	int paramlen;

	if (class_match_param(param, PARAM_OST, &param) == 0) {
		sval = strchr(param, '=');
		if (sval != NULL) {
			paramlen = sval - param;
			if (strncmp(param, "brw_stats", paramlen) == 0)
				return true;
		}
	}

	return false;
}

/**
 * Process various configuration parameters.
 *
 * This function is used by MGS to process specific configurations and
 * pass them through to the next device in server stack, i.e. the OSD.
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of OFD
 * \param[in] cfg	parameters to process
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_process_config(const struct lu_env *env, struct lu_device *d,
			      struct lustre_cfg *cfg)
{
	struct ofd_device	*m = ofd_dev(d);
	struct dt_device	*dt_next = m->ofd_osd;
	struct lu_device	*next = &dt_next->dd_lu_dev;
	int			 rc;

	ENTRY;

	switch (cfg->lcfg_command) {
	case LCFG_PARAM: {
		/* For interoperability */
		struct cfg_interop_param *ptr = NULL;
		struct lustre_cfg *old_cfg = NULL;
		char *param = NULL;
		ssize_t count;

		param = lustre_cfg_string(cfg, 1);
		if (param == NULL) {
			CERROR("param is empty\n");
			rc = -EINVAL;
			break;
		}

		ptr = class_find_old_param(param, ofd_interop_param);
		if (ptr != NULL) {
			if (ptr->new_param == NULL) {
				rc = 0;
				CWARN("For interoperability, skip this %s."
				      " It is obsolete.\n", ptr->old_param);
				break;
			}

			CWARN("Found old param %s, changed it to %s.\n",
			      ptr->old_param, ptr->new_param);

			old_cfg = cfg;
			cfg = lustre_cfg_rename(old_cfg, ptr->new_param);
			if (IS_ERR(cfg)) {
				rc = PTR_ERR(cfg);
				break;
			}
		}

		if (match_symlink_param(param)) {
			rc = next->ld_ops->ldo_process_config(env, next, cfg);
			break;
		}

		count = class_modify_config(cfg, PARAM_OST,
					    &d->ld_obd->obd_kset.kobj);
		if (count > 0) {
			rc = 0;
			break;
		}
		CDEBUG(D_CONFIG, "pass param %s down the stack.\n",
		       param);
		/* we don't understand; pass it on */
		rc = next->ld_ops->ldo_process_config(env, next, cfg);
		break;
	}
	case LCFG_SPTLRPC_CONF: {
		rc = -ENOTSUPP;
		break;
	}
	default:
		/* others are passed further */
		rc = next->ld_ops->ldo_process_config(env, next, cfg);
		break;
	}
	RETURN(rc);
}

/**
 * Implementation of lu_object_operations::loo_object_init for OFD
 *
 * Allocate just the next object (OSD) in stack.
 *
 * \param[in] env	execution environment
 * \param[in] o		lu_object of OFD object
 * \param[in] conf	additional configuration parameters, not used here
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_object_init(const struct lu_env *env, struct lu_object *o,
			   const struct lu_object_conf *conf)
{
	struct ofd_device	*d = ofd_dev(o->lo_dev);
	struct lu_device	*under;
	struct lu_object	*below;
	int			 rc = 0;

	ENTRY;

	CDEBUG(D_INFO, "object init, fid = "DFID"\n",
	       PFID(lu_object_fid(o)));

	under = &d->ofd_osd->dd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
	if (below != NULL)
		lu_object_add(o, below);
	else
		rc = -ENOMEM;

	RETURN(rc);
}

static void ofd_object_free_rcu(struct rcu_head *head)
{
	struct ofd_object *of = container_of(head, struct ofd_object,
					     ofo_header.loh_rcu);

	kmem_cache_free(ofd_object_kmem, of);
}

/**
 * Implementation of lu_object_operations::loo_object_free.
 *
 * Finish OFD object lifecycle and free its memory.
 *
 * \param[in] env	execution environment
 * \param[in] o		LU object of OFD object
 */
static void ofd_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct ofd_object	*of = ofd_obj(o);
	struct lu_object_header	*h;

	ENTRY;

	h = o->lo_header;
	CDEBUG(D_INFO, "object free, fid = "DFID"\n",
	       PFID(lu_object_fid(o)));

	lu_object_fini(o);
	lu_object_header_fini(h);
	OBD_FREE_PRE(of, sizeof(*of), "slab-freed");
	call_rcu(&of->ofo_header.loh_rcu, ofd_object_free_rcu);
	EXIT;
}

/**
 * Implementation of lu_object_operations::loo_object_print.
 *
 * Print OFD part of compound OFD-OSD object. See lu_object_print() and
 * LU_OBJECT_DEBUG() for more details about the compound object printing.
 *
 * \param[in] env	execution environment
 * \param[in] cookie	opaque data passed to the printer function
 * \param[in] p		printer function to use
 * \param[in] o		LU object of OFD object
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *o)
{
	return (*p)(env, cookie, LUSTRE_OST_NAME"-object@%p", o);
}

static const struct lu_object_operations ofd_obj_ops = {
	.loo_object_init	= ofd_object_init,
	.loo_object_free	= ofd_object_free,
	.loo_object_print	= ofd_object_print
};

/**
 * Implementation of lu_device_operations::lod_object_alloc.
 *
 * This function allocates OFD part of compound OFD-OSD object and
 * initializes its header, because OFD is the top device in stack
 *
 * \param[in] env	execution environment
 * \param[in] hdr	object header, NULL for OFD
 * \param[in] d		lu_device
 *
 * \retval		allocated object if successful
 * \retval		NULL value on failed allocation
 */
static struct lu_object *ofd_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *hdr,
					  struct lu_device *d)
{
	struct ofd_object *of;

	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(of, ofd_object_kmem, GFP_NOFS);
	if (of != NULL) {
		struct lu_object	*o;
		struct lu_object_header *h;

		o = &of->ofo_obj.do_lu;
		h = &of->ofo_header;
		lu_object_header_init(h);
		lu_object_init(o, h, d);
		lu_object_add_top(h, o);
		o->lo_ops = &ofd_obj_ops;
		range_lock_tree_init(&of->ofo_write_tree);
		RETURN(o);
	} else {
		RETURN(NULL);
	}
}

/**
 * Return the result of LFSCK run to the OFD.
 *
 * Notify OFD about result of LFSCK run. That may block the new object
 * creation until problem is fixed by LFSCK.
 *
 * \param[in] env	execution environment
 * \param[in] data	pointer to the OFD device
 * \param[in] event	LFSCK event type
 *
 * \retval		0 if successful
 * \retval		negative value on unknown event
 */
static int ofd_lfsck_out_notify(const struct lu_env *env, void *data,
				enum lfsck_events event)
{
	struct ofd_device *ofd = data;
	struct obd_device *obd = ofd_obd(ofd);

	switch (event) {
	case LE_LASTID_REBUILDING:
		CWARN("%s: Found crashed LAST_ID, deny creating new OST-object "
		      "on the device until the LAST_ID rebuilt successfully.\n",
		      obd->obd_name);
		down_write(&ofd->ofd_lastid_rwsem);
		ofd->ofd_lastid_rebuilding = 1;
		up_write(&ofd->ofd_lastid_rwsem);
		break;
	case LE_LASTID_REBUILT: {
		down_write(&ofd->ofd_lastid_rwsem);
		ofd_seqs_free(env, ofd);
		ofd->ofd_lastid_rebuilding = 0;
		ofd->ofd_lastid_gen++;
		up_write(&ofd->ofd_lastid_rwsem);
		CWARN("%s: Rebuilt crashed LAST_ID files successfully.\n",
		      obd->obd_name);
		break;
	}
	default:
		CERROR("%s: unknown lfsck event: rc = %d\n",
		       ofd_name(ofd), event);
		return -EINVAL;
	}

	return 0;
}

/**
 * Implementation of lu_device_operations::ldo_prepare.
 *
 * This method is called after layer has been initialized and before it starts
 * serving user requests. In OFD it starts lfsk check routines and initializes
 * recovery.
 *
 * \param[in] env	execution environment
 * \param[in] pdev	higher device in stack, NULL for OFD
 * \param[in] dev	lu_device of OFD device
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *dev)
{
	struct ofd_thread_info		*info;
	struct ofd_device		*ofd = ofd_dev(dev);
	struct obd_device		*obd = ofd_obd(ofd);
	struct lu_device		*next = &ofd->ofd_osd->dd_lu_dev;
	int				 rc;

	ENTRY;

	info = ofd_info_init(env, NULL);
	if (info == NULL)
		RETURN(-EFAULT);

	/* initialize lower device */
	rc = next->ld_ops->ldo_prepare(env, dev, next);
	if (rc != 0)
		RETURN(rc);

	rc = lfsck_register(env, ofd->ofd_osd, ofd->ofd_osd, obd,
			    ofd_lfsck_out_notify, ofd, false);
	if (rc != 0) {
		CERROR("%s: failed to initialize lfsck: rc = %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	rc = lfsck_register_namespace(env, ofd->ofd_osd, ofd->ofd_namespace);
	/* The LFSCK instance is registered just now, so it must be there when
	 * register the namespace to such instance. */
	LASSERTF(rc == 0, "register namespace failed: rc = %d\n", rc);

	target_recovery_init(&ofd->ofd_lut, tgt_request_handle);
	OBD_FAIL_TIMEOUT_ORSET(OBD_FAIL_OST_PREPARE_DELAY, OBD_FAIL_ONCE,
			       (OBD_TIMEOUT_DEFAULT + 1) / 4);
	LASSERT(obd->obd_no_conn);
	spin_lock(&obd->obd_dev_lock);
	obd->obd_no_conn = 0;
	spin_unlock(&obd->obd_dev_lock);

	if (obd->obd_recovering == 0)
		ofd_postrecov(env, ofd);

	RETURN(rc);
}

/**
 * Implementation of lu_device_operations::ldo_recovery_complete.
 *
 * This method notifies all layers about 'recovery complete' event. That means
 * device is in full state and consistent. An OFD calculates available grant
 * space upon this event.
 *
 * \param[in] env	execution environment
 * \param[in] dev	lu_device of OFD device
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	struct ofd_thread_info	*oti = ofd_info(env);
	struct ofd_device	*ofd = ofd_dev(dev);
	struct lu_device	*next = &ofd->ofd_osd->dd_lu_dev;
	int			 rc = 0;

	ENTRY;

	/*
	 * Grant space for object precreation on the self export.
	 * The initial reserved space (i.e. 10MB for zfs and 280KB for ldiskfs)
	 * is enough to create 10k objects. More space is then acquired for
	 * precreation in tgt_grant_create().
	 */
	memset(&oti->fti_ocd, 0, sizeof(oti->fti_ocd));
	oti->fti_ocd.ocd_grant = OST_MAX_PRECREATE / 2;
	oti->fti_ocd.ocd_grant *= ofd->ofd_lut.lut_dt_conf.ddp_inodespace;
	oti->fti_ocd.ocd_connect_flags = OBD_CONNECT_GRANT |
					 OBD_CONNECT_GRANT_PARAM;
	tgt_grant_connect(env, dev->ld_obd->obd_self_export, &oti->fti_ocd,
			  true);
	rc = next->ld_ops->ldo_recovery_complete(env, next);
	RETURN(rc);
}

/**
 * lu_device_operations matrix for OFD device.
 */
static const struct lu_device_operations ofd_lu_ops = {
	.ldo_object_alloc	= ofd_object_alloc,
	.ldo_process_config	= ofd_process_config,
	.ldo_recovery_complete	= ofd_recovery_complete,
	.ldo_prepare		= ofd_prepare,
};

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 14, 53, 0)
/**
 * Expose OSD statistics to OFD layer.
 *
 * The osd interfaces to the backend file system exposes useful data
 * such as brw_stats and read or write cache states. This same data
 * needs to be exposed into the obdfilter (ofd) layer to maintain
 * backwards compatibility. This function creates the symlinks in the
 * proc layer to enable this.
 *
 * \param[in] ofd	OFD device
 */
static void ofd_procfs_add_brw_stats_symlink(struct ofd_device *ofd)
{
	struct obd_device *obd = ofd_obd(ofd);
	struct obd_device *osd_obd = ofd->ofd_osd_exp->exp_obd;
	struct kobj_type *osd_type;
	int i;

	osd_type = get_ktype(&ofd->ofd_osd->dd_kobj);
	for (i = 0; osd_type->default_attrs[i]; i++) {
		if (strcmp(osd_type->default_attrs[i]->name,
			   "read_cache_enable") == 0) {
			ofd->ofd_read_cache_enable =
				osd_type->default_attrs[i];
		}

		if (strcmp(osd_type->default_attrs[i]->name,
			   "readcache_max_filesize") == 0) {
			ofd->ofd_read_cache_max_filesize =
				osd_type->default_attrs[i];
		}

		if (strcmp(osd_type->default_attrs[i]->name,
			   "writethrough_cache_enable") == 0) {
			ofd->ofd_write_cache_enable =
				osd_type->default_attrs[i];
		}
	}

	if (obd->obd_proc_entry == NULL)
		return;

	lprocfs_add_symlink("brw_stats", obd->obd_proc_entry,
			    "../../%s/%s/brw_stats",
			    osd_obd->obd_type->typ_name, obd->obd_name);
}
#endif

/**
 * Cleanup all procfs entries in OFD.
 *
 * \param[in] ofd	OFD device
 */
static void ofd_procfs_fini(struct ofd_device *ofd)
{
	struct obd_device *obd = ofd_obd(ofd);

	tgt_tunables_fini(&ofd->ofd_lut);
	lprocfs_free_per_client_stats(obd);
	lprocfs_obd_cleanup(obd);
	lprocfs_free_obd_stats(obd);
	lprocfs_job_stats_fini(obd);
}

/**
 * Stop SEQ/FID server on OFD.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_fid_fini(const struct lu_env *env, struct ofd_device *ofd)
{
	return seq_site_fini(env, &ofd->ofd_seq_site);
}

/**
 * Start SEQ/FID server on OFD.
 *
 * The SEQ/FID server on OFD is needed to allocate FIDs for new objects.
 * It also connects to the master server to get own FID sequence (SEQ) range
 * to this particular OFD. Typically that happens when the OST is first
 * formatted or in the rare case that it exhausts the local sequence range.
 *
 * The sequence range is allocated out to the MDTs for OST object allocations,
 * and not directly to the clients.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_fid_init(const struct lu_env *env, struct ofd_device *ofd)
{
	struct seq_server_site *ss = &ofd->ofd_seq_site;
	struct lu_device *lu = &ofd->ofd_dt_dev.dd_lu_dev;
	char *obd_name = ofd_name(ofd);
	char *name = NULL;
	int len = strlen(obd_name) + 7;
	int rc = 0;

	ss = &ofd->ofd_seq_site;
	lu->ld_site->ld_seq_site = ss;
	ss->ss_lu = lu->ld_site;
	ss->ss_node_id = ofd->ofd_lut.lut_lsd.lsd_osd_index;

	OBD_ALLOC(name, len);
	if (name == NULL)
		return -ENOMEM;

	OBD_ALLOC_PTR(ss->ss_server_seq);
	if (ss->ss_server_seq == NULL)
		GOTO(out_name, rc = -ENOMEM);

	rc = seq_server_init(env, ss->ss_server_seq, ofd->ofd_osd, obd_name,
			     LUSTRE_SEQ_SERVER, ss);
	if (rc) {
		CERROR("%s: seq server init error: rc = %d\n", obd_name, rc);
		GOTO(out_server, rc);
	}
	ss->ss_server_seq->lss_space.lsr_index = ss->ss_node_id;

	OBD_ALLOC_PTR(ss->ss_client_seq);
	if (ss->ss_client_seq == NULL)
		GOTO(out_server, rc = -ENOMEM);

	snprintf(name, len, "%s-super", obd_name);
	seq_client_init(ss->ss_client_seq, NULL, LUSTRE_SEQ_DATA,
			name, NULL);

	rc = seq_server_set_cli(env, ss->ss_server_seq, ss->ss_client_seq);

	if (rc) {
		seq_client_fini(ss->ss_client_seq);
		OBD_FREE_PTR(ss->ss_client_seq);
		ss->ss_client_seq = NULL;
out_server:
		seq_server_fini(ss->ss_server_seq, env);
		OBD_FREE_PTR(ss->ss_server_seq);
		ss->ss_server_seq = NULL;
	}
out_name:
	OBD_FREE(name, len);

	return rc;
}

/**
 * OFD request handler for OST_SET_INFO RPC.
 *
 * This is OFD-specific part of request handling
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_set_info_hdl(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct ost_body		*body = NULL, *repbody;
	void			*key, *val = NULL;
	int			 keylen, vallen, rc = 0;
	bool			 is_grant_shrink;
	ktime_t			 kstart = ktime_get();

	ENTRY;

	key = req_capsule_client_get(tsi->tsi_pill, &RMF_SETINFO_KEY);
	if (key == NULL) {
		DEBUG_REQ(D_HA, req, "no set_info key");
		RETURN(err_serious(-EFAULT));
	}
	keylen = req_capsule_get_size(tsi->tsi_pill, &RMF_SETINFO_KEY,
				      RCL_CLIENT);

	val = req_capsule_client_get(tsi->tsi_pill, &RMF_SETINFO_VAL);
	if (val == NULL) {
		DEBUG_REQ(D_HA, req, "no set_info val");
		RETURN(err_serious(-EFAULT));
	}
	vallen = req_capsule_get_size(tsi->tsi_pill, &RMF_SETINFO_VAL,
				      RCL_CLIENT);

	is_grant_shrink = KEY_IS(KEY_GRANT_SHRINK);
	if (is_grant_shrink)
		/* In this case the value is actually an RMF_OST_BODY, so we
		 * transmutate the type of this PTLRPC */
		req_capsule_extend(tsi->tsi_pill, &RQF_OST_SET_GRANT_INFO);

	rc = req_capsule_server_pack(tsi->tsi_pill);
	if (rc < 0)
		RETURN(rc);

	if (is_grant_shrink) {
		body = req_capsule_client_get(tsi->tsi_pill, &RMF_OST_BODY);

		repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
		*repbody = *body;

		/** handle grant shrink, similar to a read request */
		tgt_grant_prepare_read(tsi->tsi_env, tsi->tsi_exp,
				       &repbody->oa);
	} else if (KEY_IS(KEY_EVICT_BY_NID)) {
		if (vallen > 0)
			obd_export_evict_by_nid(tsi->tsi_exp->exp_obd, val);
		rc = 0;
	} else {
		CERROR("%s: Unsupported key %s\n",
		       tgt_name(tsi->tsi_tgt), (char *)key);
		rc = -EOPNOTSUPP;
	}
	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_SET_INFO,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));

	RETURN(rc);
}

/**
 * Get FIEMAP (FIle Extent MAPping) for object with the given FID.
 *
 * This function returns a list of extents which describes how a file's
 * blocks are laid out on the disk.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of object
 * \param[in] fiemap	fiemap structure to fill with data
 *
 * \retval		0 if \a fiemap is filled with data successfully
 * \retval		negative value on error
 */
int ofd_fiemap_get(const struct lu_env *env, struct ofd_device *ofd,
		   struct lu_fid *fid, struct fiemap *fiemap)
{
	struct ofd_object	*fo;
	int			 rc;

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo)) {
		CERROR("%s: error finding object "DFID"\n",
		       ofd_name(ofd), PFID(fid));
		return PTR_ERR(fo);
	}

	ofd_read_lock(env, fo);
	if (ofd_object_exists(fo))
		rc = dt_fiemap_get(env, ofd_object_child(fo), fiemap);
	else
		rc = -ENOENT;
	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	return rc;
}


static int ofd_lock_unlock_region(const struct lu_env *env,
				  struct ldlm_namespace *ns,
				  struct ldlm_res_id *res_id,
				  unsigned long long begin,
				  unsigned long long end)
{
	__u64			 flags = 0;
	int			 rc;
	struct lustre_handle     lh = { 0 };

	LASSERT(begin <= end);

	rc = tgt_extent_lock(env, ns, res_id, begin, end, &lh, LCK_PR, &flags);
	if (rc != 0)
		return rc;

	CDEBUG(D_OTHER, "ost lock [%llu,%llu], lh=%p\n", begin, end, &lh);
	tgt_data_unlock(&lh, LCK_PR);

	return 0;
}

/**
 * Lock the sparse areas of given resource.
 *
 * The locking of sparse areas will cause dirty data to be flushed back from
 * clients. This is used when getting the FIEMAP of an object to make sure
 * there is no unaccounted cached data on clients.
 *
 * This function goes through \a fiemap list of extents and locks only sparse
 * areas between extents.
 *
 * \param[in] ns	LDLM namespace
 * \param[in] res_id	resource ID
 * \param[in] fiemap	file extents mapping on disk
 * \param[in] locked	list head of regions list
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int lock_zero_regions(const struct lu_env *env,
			     struct ldlm_namespace *ns,
			     struct ldlm_res_id *res_id,
			     struct fiemap *fiemap)
{
	__u64 begin = fiemap->fm_start;
	unsigned int i;
	int rc = 0;
	struct fiemap_extent *fiemap_start = fiemap->fm_extents;

	ENTRY;

	CDEBUG(D_OTHER, "extents count %u\n", fiemap->fm_mapped_extents);
	for (i = 0; i < fiemap->fm_mapped_extents; i++) {
		if (fiemap_start[i].fe_logical > begin) {
			CDEBUG(D_OTHER, "ost lock [%llu,%llu]\n",
			       begin, fiemap_start[i].fe_logical);
			rc = ofd_lock_unlock_region(env, ns, res_id, begin,
						    fiemap_start[i].fe_logical);
			if (rc)
				RETURN(rc);
		}

		begin = fiemap_start[i].fe_logical + fiemap_start[i].fe_length;
	}

	if (begin < (fiemap->fm_start + fiemap->fm_length)) {
		CDEBUG(D_OTHER, "ost lock [%llu,%llu]\n",
		       begin, fiemap->fm_start + fiemap->fm_length);
		rc = ofd_lock_unlock_region(env, ns, res_id, begin,
				fiemap->fm_start + fiemap->fm_length);
	}

	RETURN(rc);
}


/**
 * OFD request handler for OST_GET_INFO RPC.
 *
 * This is OFD-specific part of request handling. The OFD-specific keys are:
 * - KEY_LAST_ID (obsolete)
 * - KEY_FIEMAP
 * - KEY_LAST_FID
 *
 * This function reads needed data from storage and fills reply with it.
 *
 * Note: the KEY_LAST_ID is obsolete, replaced by KEY_LAST_FID on newer MDTs,
 * and is kept for compatibility.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_get_info_hdl(struct tgt_session_info *tsi)
{
	struct obd_export		*exp = tsi->tsi_exp;
	struct ofd_device		*ofd = ofd_exp(exp);
	struct ofd_thread_info		*fti = tsi2ofd_info(tsi);
	void				*key;
	int				 keylen;
	int				 replylen, rc = 0;
	ktime_t				 kstart = ktime_get();

	ENTRY;

	/* this common part for get_info rpc */
	key = req_capsule_client_get(tsi->tsi_pill, &RMF_GETINFO_KEY);
	if (key == NULL) {
		DEBUG_REQ(D_HA, tgt_ses_req(tsi), "no get_info key");
		RETURN(err_serious(-EPROTO));
	}
	keylen = req_capsule_get_size(tsi->tsi_pill, &RMF_GETINFO_KEY,
				      RCL_CLIENT);

	if (KEY_IS(KEY_LAST_ID)) {
		u64		*last_id;
		struct ofd_seq	*oseq;

		req_capsule_extend(tsi->tsi_pill, &RQF_OST_GET_INFO_LAST_ID);
		rc = req_capsule_server_pack(tsi->tsi_pill);
		if (rc)
			RETURN(err_serious(rc));

		last_id = req_capsule_server_get(tsi->tsi_pill, &RMF_OBD_ID);

		oseq = ofd_seq_load(tsi->tsi_env, ofd,
				    (u64)exp->exp_filter_data.fed_group);
		if (IS_ERR(oseq))
			rc = -EFAULT;
		else
			*last_id = ofd_seq_last_oid(oseq);
		ofd_seq_put(tsi->tsi_env, oseq);
	} else if (KEY_IS(KEY_FIEMAP)) {
		struct ll_fiemap_info_key	*fm_key;
		struct fiemap			*fiemap;
		struct lu_fid			*fid;

		req_capsule_extend(tsi->tsi_pill, &RQF_OST_GET_INFO_FIEMAP);

		fm_key = req_capsule_client_get(tsi->tsi_pill, &RMF_FIEMAP_KEY);
		rc = tgt_validate_obdo(tsi, &fm_key->lfik_oa);
		if (rc)
			RETURN(err_serious(rc));

		fid = &fm_key->lfik_oa.o_oi.oi_fid;

		CDEBUG(D_INODE, "get FIEMAP of object "DFID"\n", PFID(fid));

		replylen = fiemap_count_to_size(
					fm_key->lfik_fiemap.fm_extent_count);
		req_capsule_set_size(tsi->tsi_pill, &RMF_FIEMAP_VAL,
				     RCL_SERVER, replylen);

		rc = req_capsule_server_pack(tsi->tsi_pill);
		if (rc)
			RETURN(err_serious(rc));

		fiemap = req_capsule_server_get(tsi->tsi_pill, &RMF_FIEMAP_VAL);
		if (fiemap == NULL)
			RETURN(-ENOMEM);

		*fiemap = fm_key->lfik_fiemap;
		rc = ofd_fiemap_get(tsi->tsi_env, ofd, fid, fiemap);

		/* LU-3219: Lock the sparse areas to make sure dirty
		 * flushed back from client, then call fiemap again. */
		if (fm_key->lfik_oa.o_valid & OBD_MD_FLFLAGS &&
		    fm_key->lfik_oa.o_flags & OBD_FL_SRVLOCK) {
			ost_fid_build_resid(fid, &fti->fti_resid);
			rc = lock_zero_regions(tsi->tsi_env, ofd->ofd_namespace,
					       &fti->fti_resid, fiemap);
			if (rc == 0)
				rc = ofd_fiemap_get(tsi->tsi_env, ofd, fid,
						    fiemap);
		}
	} else if (KEY_IS(KEY_LAST_FID)) {
		struct ofd_device	*ofd = ofd_exp(exp);
		struct ofd_seq		*oseq;
		struct lu_fid		*fid;
		int			 rc;

		req_capsule_extend(tsi->tsi_pill, &RQF_OST_GET_INFO_LAST_FID);
		rc = req_capsule_server_pack(tsi->tsi_pill);
		if (rc)
			RETURN(err_serious(rc));

		fid = req_capsule_client_get(tsi->tsi_pill, &RMF_FID);
		if (fid == NULL)
			RETURN(err_serious(-EPROTO));

		fid_le_to_cpu(&fti->fti_ostid.oi_fid, fid);

		fid = req_capsule_server_get(tsi->tsi_pill, &RMF_FID);
		if (fid == NULL)
			RETURN(-ENOMEM);

		oseq = ofd_seq_load(tsi->tsi_env, ofd,
				    ostid_seq(&fti->fti_ostid));
		if (IS_ERR(oseq))
			RETURN(PTR_ERR(oseq));

		rc = ostid_to_fid(fid, &oseq->os_oi,
				  ofd->ofd_lut.lut_lsd.lsd_osd_index);
		if (rc != 0)
			GOTO(out_put, rc);

		CDEBUG(D_HA, "%s: LAST FID is "DFID"\n", ofd_name(ofd),
		       PFID(fid));
out_put:
		ofd_seq_put(tsi->tsi_env, oseq);
	} else {
		CERROR("%s: not supported key %s\n", tgt_name(tsi->tsi_tgt),
		       (char *)key);
		rc = -EOPNOTSUPP;
	}
	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_GET_INFO,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));

	RETURN(rc);
}

/**
 * OFD request handler for OST_GETATTR RPC.
 *
 * This is OFD-specific part of request handling. It finds the OFD object
 * by its FID, gets attributes from storage and packs result to the reply.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_getattr_hdl(struct tgt_session_info *tsi)
{
	struct ofd_thread_info	*fti = tsi2ofd_info(tsi);
	struct ofd_device	*ofd = ofd_exp(tsi->tsi_exp);
	struct ost_body		*repbody;
	struct lustre_handle	 lh = { 0 };
	struct ofd_object	*fo;
	__u64			 flags = 0;
	enum ldlm_mode		 lock_mode = LCK_PR;
	ktime_t			 kstart = ktime_get();
	bool			 srvlock;
	int			 rc;
	ENTRY;

	LASSERT(tsi->tsi_ost_body != NULL);

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(-ENOMEM);

	repbody->oa.o_oi = tsi->tsi_ost_body->oa.o_oi;
	repbody->oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

	srvlock = tsi->tsi_ost_body->oa.o_valid & OBD_MD_FLFLAGS &&
		  tsi->tsi_ost_body->oa.o_flags & OBD_FL_SRVLOCK;

	if (srvlock) {
		if (unlikely(tsi->tsi_ost_body->oa.o_flags & OBD_FL_FLUSH))
			lock_mode = LCK_PW;

		rc = tgt_extent_lock(tsi->tsi_env,
				     tsi->tsi_tgt->lut_obd->obd_namespace,
				     &tsi->tsi_resid, 0, OBD_OBJECT_EOF, &lh,
				     lock_mode, &flags);
		if (rc != 0)
			RETURN(rc);
	}

	fo = ofd_object_find_exists(tsi->tsi_env, ofd, &tsi->tsi_fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	rc = ofd_attr_get(tsi->tsi_env, fo, &fti->fti_attr);
	if (rc == 0) {
		__u64	 curr_version;

		obdo_from_la(&repbody->oa, &fti->fti_attr,
			     OFD_VALID_FLAGS | LA_UID | LA_GID | LA_PROJID);

		/* Store object version in reply */
		curr_version = dt_version_get(tsi->tsi_env,
					      ofd_object_child(fo));
		if ((__s64)curr_version != -EOPNOTSUPP) {
			repbody->oa.o_valid |= OBD_MD_FLDATAVERSION;
			repbody->oa.o_data_version = curr_version;
		}

		if (fo->ofo_ff.ff_layout_version > 0) {
			repbody->oa.o_valid |= OBD_MD_LAYOUT_VERSION;
			repbody->oa.o_layout_version =
			     fo->ofo_ff.ff_layout_version + fo->ofo_ff.ff_range;

			CDEBUG(D_INODE, DFID": get layout version: %u\n",
			       PFID(&tsi->tsi_fid),
			       repbody->oa.o_layout_version);
		}
	}

	ofd_object_put(tsi->tsi_env, fo);
out:
	if (srvlock)
		tgt_data_unlock(&lh, lock_mode);

	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_GETATTR,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));

	repbody->oa.o_valid |= OBD_MD_FLFLAGS;
	repbody->oa.o_flags = OBD_FL_FLUSH;

	RETURN(rc);
}

/**
 * OFD request handler for OST_SETATTR RPC.
 *
 * This is OFD-specific part of request handling. It finds the OFD object
 * by its FID, sets attributes from request and packs result to the reply.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_setattr_hdl(struct tgt_session_info *tsi)
{
	struct ofd_thread_info	*fti = tsi2ofd_info(tsi);
	struct ofd_device	*ofd = ofd_exp(tsi->tsi_exp);
	struct ost_body		*body = tsi->tsi_ost_body;
	struct ost_body		*repbody;
	struct ldlm_resource	*res;
	struct ofd_object	*fo;
	ktime_t			 kstart = ktime_get();
	int			 rc = 0;

	ENTRY;

	LASSERT(body != NULL);

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(-ENOMEM);

	repbody->oa.o_oi = body->oa.o_oi;
	repbody->oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

	/* This would be very bad - accidentally truncating a file when
	 * changing the time or similar - bug 12203. */
	if (body->oa.o_valid & OBD_MD_FLSIZE &&
	    body->oa.o_size != OBD_OBJECT_EOF) {
		static char mdsinum[48];

		if (body->oa.o_valid & OBD_MD_FLFID)
			snprintf(mdsinum, sizeof(mdsinum) - 1,
				 "of parent "DFID, body->oa.o_parent_seq,
				 body->oa.o_parent_oid, 0);
		else
			mdsinum[0] = '\0';

		CERROR("%s: setattr from %s is trying to truncate object "DFID
		       " %s\n", ofd_name(ofd), obd_export_nid2str(tsi->tsi_exp),
		       PFID(&tsi->tsi_fid), mdsinum);
		RETURN(-EPERM);
	}

	fo = ofd_object_find_exists(tsi->tsi_env, ofd, &tsi->tsi_fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	la_from_obdo(&fti->fti_attr, &body->oa, body->oa.o_valid);
	fti->fti_attr.la_valid &= ~LA_TYPE;

	/* setting objects attributes (including owner/group) */
	rc = ofd_attr_set(tsi->tsi_env, fo, &fti->fti_attr, &body->oa);
	if (rc != 0)
		GOTO(out_put, rc);

	obdo_from_la(&repbody->oa, &fti->fti_attr,
		     OFD_VALID_FLAGS | LA_UID | LA_GID | LA_PROJID);

	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_SETATTR,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));
	EXIT;
out_put:
	ofd_object_put(tsi->tsi_env, fo);
out:
	if (rc == 0) {
		/* we do not call this before to avoid lu_object_find() in
		 *  ->lvbo_update() holding another reference on the object.
		 * otherwise concurrent destroy can make the object unavailable
		 * for 2nd lu_object_find() waiting for the first reference
		 * to go... deadlock! */
		res = ldlm_resource_get(ofd->ofd_namespace, NULL,
					&tsi->tsi_resid, LDLM_EXTENT, 0);
		if (!IS_ERR(res)) {
			ldlm_res_lvbo_update(res, NULL, 0);
			ldlm_resource_putref(res);
		}
	}
	return rc;
}

/**
 * Destroy OST orphans.
 *
 * This is part of OST_CREATE RPC handling. If there is flag OBD_FL_DELORPHAN
 * set then we must destroy possible orphaned objects.
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export
 * \param[in] ofd	OFD device
 * \param[in] oa	obdo structure for reply
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_orphans_destroy(const struct lu_env *env,
			       struct obd_export *exp,
			       struct ofd_device *ofd, struct obdo *oa)
{
	struct ofd_thread_info	*info	= ofd_info(env);
	struct lu_fid		*fid	= &info->fti_fid;
	struct ost_id		*oi	= &oa->o_oi;
	struct ofd_seq		*oseq;
	u64			 seq	= ostid_seq(oi);
	u64			 end_id = ostid_id(oi);
	u64			 last;
	u64			 oid;
	int			 skip_orphan;
	int			 rc	= 0;

	ENTRY;

	oseq = ofd_seq_get(ofd, seq);
	if (oseq == NULL) {
		CERROR("%s: Can not find seq for "DOSTID"\n",
		       ofd_name(ofd), POSTID(oi));
		RETURN(-EINVAL);
	}

	*fid = oi->oi_fid;
	last = ofd_seq_last_oid(oseq);
	oid = last;

	LASSERT(exp != NULL);
	skip_orphan = !!(exp_connect_flags(exp) & OBD_CONNECT_SKIP_ORPHAN);

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_NODESTROY))
		goto done;

	LCONSOLE(D_INFO, "%s: deleting orphan objects from "DOSTID
		 " to "DOSTID"\n", ofd_name(ofd), seq, end_id + 1, seq, last);

	while (oid > end_id) {
		rc = fid_set_id(fid, oid);
		if (unlikely(rc != 0))
			GOTO(out_put, rc);

		rc = ofd_destroy_by_fid(env, ofd, fid, 1);
		if (rc != 0 && rc != -ENOENT && rc != -ESTALE &&
		    likely(rc != -EREMCHG && rc != -EINPROGRESS))
			/* this is pretty fatal... */
			CEMERG("%s: error destroying precreated id "
			       DFID": rc = %d\n",
			       ofd_name(ofd), PFID(fid), rc);

		oid--;
		if (!skip_orphan) {
			ofd_seq_last_oid_set(oseq, oid);
			/* update last_id on disk periodically so that if we
			 * restart * we don't need to re-scan all of the just
			 * deleted objects. */
			if ((oid & 511) == 0)
				ofd_seq_last_oid_write(env, ofd, oseq);
		}
	}

	CDEBUG(D_HA, "%s: after destroy: set last_id to "DOSTID"\n",
	       ofd_name(ofd), seq, oid);

done:
	if (!skip_orphan) {
		ofd_seq_last_oid_set(oseq, oid);
		rc = ofd_seq_last_oid_write(env, ofd, oseq);
	} else {
		/* don't reuse orphan object, return last used objid */
		rc = ostid_set_id(oi, last);
	}

	GOTO(out_put, rc);

out_put:
	ofd_seq_put(env, oseq);
	return rc;
}

/**
 * OFD request handler for OST_CREATE RPC.
 *
 * This is OFD-specific part of request handling. Its main purpose is to
 * create new data objects on OST, but it also used to destroy orphans.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_create_hdl(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct ost_body		*repbody;
	const struct obdo	*oa = &tsi->tsi_ost_body->oa;
	struct obdo		*rep_oa;
	struct obd_export	*exp = tsi->tsi_exp;
	struct ofd_device	*ofd = ofd_exp(exp);
	u64			 seq = ostid_seq(&oa->o_oi);
	u64			 oid = ostid_id(&oa->o_oi);
	struct ofd_seq		*oseq;
	int			 sync_trans = 0;
	long			 granted = 0;
	ktime_t			 kstart = ktime_get();
	s64			 diff;
	int			 rc = 0;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_EROFS))
		RETURN(-EROFS);

	if (ofd->ofd_no_precreate)
		return -EPERM;

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(-ENOMEM);

	down_read(&ofd->ofd_lastid_rwsem);
	/* Currently, for safe, we do not distinguish which LAST_ID is broken,
	 * we may do that in the future.
	 * Return -ENOSPC until the LAST_ID rebuilt. */
	if (unlikely(ofd->ofd_lastid_rebuilding))
		GOTO(out_sem, rc = -ENOSPC);

	rep_oa = &repbody->oa;
	rep_oa->o_oi = oa->o_oi;

	LASSERT(oa->o_valid & OBD_MD_FLGROUP);

	CDEBUG(D_INFO, "ofd_create("DOSTID")\n", POSTID(&oa->o_oi));

	oseq = ofd_seq_load(tsi->tsi_env, ofd, seq);
	if (IS_ERR(oseq)) {
		CERROR("%s: Can't find FID Sequence %#llx: rc = %ld\n",
		       ofd_name(ofd), seq, PTR_ERR(oseq));
		GOTO(out_sem, rc = -EINVAL);
	}

	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_RECREATE_OBJS)) {
		if (!ofd_obd(ofd)->obd_recovering ||
		    oid > ofd_seq_last_oid(oseq)) {
			CERROR("%s: recreate objid "DOSTID" > last id %llu"
			       "\n", ofd_name(ofd), POSTID(&oa->o_oi),
			       ofd_seq_last_oid(oseq));
			GOTO(out_nolock, rc = -EINVAL);
		}
		/* Do nothing here, we re-create objects during recovery
		 * upon write replay, see ofd_preprw_write() */
		GOTO(out_nolock, rc = 0);
	}
	/* former ofd_handle_precreate */
	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_DELORPHAN)) {
		exp->exp_filter_data.fed_lastid_gen = ofd->ofd_lastid_gen;

		/* destroy orphans */
		if (lustre_msg_get_conn_cnt(tgt_ses_req(tsi)->rq_reqmsg) <
		    exp->exp_conn_cnt) {
			CERROR("%s: dropping old orphan cleanup request\n",
			       ofd_name(ofd));
			GOTO(out_nolock, rc = 0);
		}
		/* This causes inflight precreates to abort and drop lock */
		oseq->os_destroys_in_progress = 1;
		mutex_lock(&oseq->os_create_lock);
		if (!oseq->os_destroys_in_progress) {
			CDEBUG(D_HA,
			       "%s:[%llu] destroys_in_progress already cleared\n",
			       ofd_name(ofd), seq);
			rc = ostid_set_id(&rep_oa->o_oi,
					  ofd_seq_last_oid(oseq));
			GOTO(out, rc);
		}
		diff = oid - ofd_seq_last_oid(oseq);
		CDEBUG(D_HA, "ofd_last_id() = %llu -> diff = %lld\n",
		       ofd_seq_last_oid(oseq), diff);
		if (-diff > OST_MAX_PRECREATE) {
			LCONSOLE(D_INFO, "%s: too large difference between MDS "
				 "LAST_ID "DFID" (%llu) and OST LAST_ID "DFID" "
				 "(%llu), trust the OST\n",
				 ofd_name(ofd), PFID(&oa->o_oi.oi_fid), oid,
				 PFID(&oseq->os_oi.oi_fid),
				 ofd_seq_last_oid(oseq));

			/* Let MDS know that we are so far ahead. */
			rc = ostid_set_id(&rep_oa->o_oi,
					  ofd_seq_last_oid(oseq) + 1);
		} else if (diff < 0) {
			rc = ofd_orphans_destroy(tsi->tsi_env, exp,
						 ofd, rep_oa);
			oseq->os_destroys_in_progress = 0;
		} else {
			/* XXX: Used by MDS for the first time! */
			oseq->os_destroys_in_progress = 0;
		}
	} else {
		if (unlikely(exp->exp_filter_data.fed_lastid_gen !=
			     ofd->ofd_lastid_gen)) {
			/* Keep the export ref so we can send the reply. */
			ofd_obd_disconnect(class_export_get(exp));
			GOTO(out_nolock, rc = -ENOTCONN);
		}

		mutex_lock(&oseq->os_create_lock);
		if (lustre_msg_get_conn_cnt(tgt_ses_req(tsi)->rq_reqmsg) <
		    exp->exp_conn_cnt) {
			CERROR("%s: dropping old precreate request\n",
			       ofd_name(ofd));
			GOTO(out, rc = 0);
		}
		/* only precreate if seq is 0, IDIF or normal and also o_id
		 * must be specfied */
		if ((!fid_seq_is_mdt(seq) && !fid_seq_is_norm(seq) &&
		     !fid_seq_is_idif(seq)) || oid == 0) {
			diff = 1; /* shouldn't we create this right now? */
		} else {
			diff = oid - ofd_seq_last_oid(oseq);
			/* Do sync create if the seq is about to used up */
			if (fid_seq_is_idif(seq) || fid_seq_is_mdt0(seq)) {
				if (unlikely(oid >= IDIF_MAX_OID - 1))
					sync_trans = 1;
			} else if (fid_seq_is_norm(seq)) {
				if (unlikely(oid >=
					     LUSTRE_DATA_SEQ_MAX_WIDTH - 1))
					sync_trans = 1;
			} else {
				CERROR("%s : invalid o_seq "DOSTID"\n",
				       ofd_name(ofd), POSTID(&oa->o_oi));
				GOTO(out, rc = -EINVAL);
			}

			if (diff < 0) {
				/* LU-5648 */
				CERROR("%s: invalid precreate request for "
				       DOSTID", last_id %llu. "
				       "Likely MDS last_id corruption\n",
				       ofd_name(ofd), POSTID(&oa->o_oi),
				       ofd_seq_last_oid(oseq));
				GOTO(out, rc = -EINVAL);
			}
		}
	}
	if (diff > 0) {
		time64_t enough_time = ktime_get_seconds() + DISK_TIMEOUT;
		u64 next_id;
		int created = 0;
		int count;
		int rc2;

		if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
		    !(oa->o_flags & OBD_FL_DELORPHAN)) {
			/* don't enforce grant during orphan recovery */
			granted = tgt_grant_create(tsi->tsi_env,
						ofd_obd(ofd)->obd_self_export,
						&diff);
			if (granted < 0) {
				rc = granted;
				granted = 0;
				CDEBUG(D_HA, "%s: failed to acquire grant "
				       "space for precreate (%lld): rc = %d\n",
				       ofd_name(ofd), diff, rc);
				diff = 0;
			}
		}

		/* This can happen if a new OST is formatted and installed
		 * in place of an old one at the same index.  Instead of
		 * precreating potentially millions of deleted old objects
		 * (possibly filling the OST), only precreate the last batch.
		 * LFSCK will eventually clean up any orphans. LU-14 */
		if (diff > 5 * OST_MAX_PRECREATE) {
			/* Message below is checked in conf-sanity test_122b */
			LCONSOLE_WARN("%s: precreate FID "DOSTID" is over %lld higher than LAST_ID "DOSTID", only precreating the last %u objects. OST replaced or reformatted?\n",
				      ofd_name(ofd), POSTID(&oa->o_oi), diff,
				      POSTID(&oseq->os_oi),
				      OST_MAX_PRECREATE / 2);
			diff = OST_MAX_PRECREATE / 2;
			ofd_seq_last_oid_set(oseq, ostid_id(&oa->o_oi) - diff);
		}

		while (diff > 0) {
			next_id = ofd_seq_last_oid(oseq) + 1;
			count = ofd_precreate_batch(ofd, (int)diff);

			CDEBUG(D_HA, "%s: reserve %d objects in group %#llx"
			       " at %llu\n", ofd_name(ofd),
			       count, seq, next_id);

			if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)
			    && ktime_get_seconds() > enough_time) {
				CDEBUG(D_HA, "%s: Slow creates, %d/%lld objects"
				      " created at a rate of %d/s\n",
				      ofd_name(ofd), created, diff + created,
				      created / DISK_TIMEOUT);
				break;
			}

			rc = ofd_precreate_objects(tsi->tsi_env, ofd, next_id,
						   oseq, count, sync_trans);
			if (rc > 0) {
				created += rc;
				diff -= rc;
			} else if (rc < 0) {
				break;
			}
		}

		if (diff > 0 &&
		    lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)
			LCONSOLE_WARN("%s: can't create the same count of"
				      " objects when replaying the request"
				      " (diff is %lld). see LU-4621\n",
				      ofd_name(ofd), diff);

		if (created > 0)
			/* some objects got created, we can return
			 * them, even if last creation failed */
			rc = 0;
		else
			CERROR("%s: unable to precreate: rc = %d\n",
			       ofd_name(ofd), rc);

		if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
		    !(oa->o_flags & OBD_FL_DELORPHAN)) {
			tgt_grant_commit(ofd_obd(ofd)->obd_self_export,
					 granted, rc);
			granted = 0;
		}

		rc2 = ostid_set_id(&rep_oa->o_oi, ofd_seq_last_oid(oseq));
		rc = rc ? : rc2;
	}
	EXIT;
	ofd_counter_incr(exp, LPROC_OFD_STATS_CREATE,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));
	if (unlikely(!oseq->os_last_id_synced))
		oseq->os_last_id_synced = 1;
out:
	mutex_unlock(&oseq->os_create_lock);
out_nolock:
	if (rc == 0)
		rep_oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP;
	ofd_seq_put(tsi->tsi_env, oseq);

out_sem:
	up_read(&ofd->ofd_lastid_rwsem);
	return rc;
}

/**
 * OFD request handler for OST_DESTROY RPC.
 *
 * This is OFD-specific part of request handling. It destroys data objects
 * related to destroyed object on MDT.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_destroy_hdl(struct tgt_session_info *tsi)
{
	const struct ost_body	*body = tsi->tsi_ost_body;
	struct ost_body		*repbody;
	struct ofd_device	*ofd = ofd_exp(tsi->tsi_exp);
	struct ofd_thread_info	*fti = tsi2ofd_info(tsi);
	struct lu_fid		*fid = &fti->fti_fid;
	ktime_t			 kstart = ktime_get();
	u64			 oid;
	u32			 count;
	int			 rc = 0;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_EROFS))
		RETURN(-EROFS);

	/* This is old case for clients before Lustre 2.4 */
	/* If there's a DLM request, cancel the locks mentioned in it */
	if (req_capsule_field_present(tsi->tsi_pill, &RMF_DLM_REQ,
				      RCL_CLIENT)) {
		struct ldlm_request *dlm;

		dlm = req_capsule_client_get(tsi->tsi_pill, &RMF_DLM_REQ);
		if (dlm == NULL)
			RETURN(-EFAULT);
		ldlm_request_cancel(tgt_ses_req(tsi), dlm, 0, LATF_SKIP);
	}

	*fid = body->oa.o_oi.oi_fid;
	oid = ostid_id(&body->oa.o_oi);
	LASSERT(oid != 0);

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);

	/* check that o_misc makes sense */
	if (body->oa.o_valid & OBD_MD_FLOBJCOUNT)
		count = body->oa.o_misc;
	else
		count = 1; /* default case - single destroy */

	CDEBUG(D_HA, "%s: Destroy object "DOSTID" count %d\n", ofd_name(ofd),
	       POSTID(&body->oa.o_oi), count);

	while (count > 0) {
		int lrc;

		lrc = ofd_destroy_by_fid(tsi->tsi_env, ofd, fid, 0);
		if (lrc == -ENOENT) {
			CDEBUG(D_INODE,
			       "%s: destroying non-existent object "DFID"\n",
			       ofd_name(ofd), PFID(fid));
			/* rewrite rc with -ENOENT only if it is 0 */
			if (rc == 0)
				rc = lrc;
		} else if (lrc != 0) {
			CERROR("%s: error destroying object "DFID": %d\n",
			       ofd_name(ofd), PFID(fid), lrc);
			rc = lrc;
		}

		count--;
		oid++;
		lrc = fid_set_id(fid, oid);
		if (unlikely(lrc != 0 && count > 0))
			GOTO(out, rc = lrc);
	}

	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_DESTROY,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));

	GOTO(out, rc);

out:
	fid_to_ostid(fid, &repbody->oa.o_oi);
	return rc;
}

/**
 * OFD request handler for OST_STATFS RPC.
 *
 * This function gets statfs data from storage as part of request
 * processing.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_statfs_hdl(struct tgt_session_info *tsi)
{
	ktime_t			 kstart = ktime_get();
	struct obd_statfs	*osfs;
	int			 rc;

	ENTRY;

	OBD_FAIL_TIMEOUT(OBD_FAIL_OST_STATFS_DELAY, 10);

	osfs = req_capsule_server_get(tsi->tsi_pill, &RMF_OBD_STATFS);

	rc = ofd_statfs(tsi->tsi_env, tsi->tsi_exp, osfs,
			ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS, 0);
	if (rc != 0)
		CERROR("%s: statfs failed: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_STATFS_EINPROGRESS))
		rc = -EINPROGRESS;

	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_STATFS,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));

	RETURN(rc);
}

/**
 * OFD request handler for OST_SYNC RPC.
 *
 * Sync object data or all filesystem data to the disk and pack the
 * result in reply.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_sync_hdl(struct tgt_session_info *tsi)
{
	struct ost_body		*body = tsi->tsi_ost_body;
	struct ost_body		*repbody;
	struct ofd_thread_info	*fti = tsi2ofd_info(tsi);
	struct ofd_device	*ofd = ofd_exp(tsi->tsi_exp);
	struct ofd_object	*fo = NULL;
	ktime_t			 kstart = ktime_get();
	int			 rc = 0;

	ENTRY;

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);

	/* if no objid is specified, it means "sync whole filesystem" */
	if (!fid_is_zero(&tsi->tsi_fid)) {
		fo = ofd_object_find_exists(tsi->tsi_env, ofd, &tsi->tsi_fid);
		if (IS_ERR(fo))
			RETURN(PTR_ERR(fo));
	}

	rc = tgt_sync(tsi->tsi_env, tsi->tsi_tgt,
		      fo != NULL ? ofd_object_child(fo) : NULL,
		      repbody->oa.o_size, repbody->oa.o_blocks);
	if (rc)
		GOTO(put, rc);

	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_SYNC,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));
	if (fo == NULL)
		RETURN(0);

	repbody->oa.o_oi = body->oa.o_oi;
	repbody->oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

	rc = ofd_attr_get(tsi->tsi_env, fo, &fti->fti_attr);
	if (rc == 0)
		obdo_from_la(&repbody->oa, &fti->fti_attr,
			     OFD_VALID_FLAGS);
	else
		/* don't return rc from getattr */
		rc = 0;
	EXIT;
put:
	if (fo != NULL)
		ofd_object_put(tsi->tsi_env, fo);
	return rc;
}

/**
 * OFD request handler for OST_FALLOCATE RPC.
 *
 * This is part of request processing. Validate request fields,
 * preallocate the given OFD object and pack reply.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_fallocate_hdl(struct tgt_session_info *tsi)
{
	struct obdo *oa = &tsi->tsi_ost_body->oa;
	struct ost_body *repbody;
	struct ofd_thread_info *info = tsi2ofd_info(tsi);
	struct ldlm_namespace *ns = tsi->tsi_tgt->lut_obd->obd_namespace;
	struct ldlm_resource *res;
	struct ofd_object *fo;
	__u64 flags = 0;
	struct lustre_handle lh = { 0, };
	int rc, mode;
	__u64 start, end;
	bool srvlock;
	ktime_t kstart = ktime_get();

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(err_serious(-ENOMEM));

	/*
	 * fallocate start and end are passed in o_size, o_blocks
	 * on the wire.
	 */
	if ((oa->o_valid & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS)) !=
	    (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))
		RETURN(err_serious(-EPROTO));

	start = oa->o_size;
	end = oa->o_blocks;
	mode = oa->o_falloc_mode;
	/*
	 * mode == 0 (which is standard prealloc) and PUNCH is supported
	 * Rest of mode options are not supported yet.
	 */
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		RETURN(-EOPNOTSUPP);

	/* PUNCH_HOLE mode should always be accompanied with KEEP_SIZE flag
	 * Check that and add the missing flag for such invalid call with
	 * warning.
	 */
	if (mode & FALLOC_FL_PUNCH_HOLE && !(mode & FALLOC_FL_KEEP_SIZE)) {
		CWARN("%s: PUNCH mode misses KEEP_SIZE flag, setting it\n",
		      tsi->tsi_tgt->lut_obd->obd_name);
		mode |= FALLOC_FL_KEEP_SIZE;
	}

	repbody->oa.o_oi = oa->o_oi;
	repbody->oa.o_valid = OBD_MD_FLID;

	srvlock = oa->o_valid & OBD_MD_FLFLAGS &&
		  oa->o_flags & OBD_FL_SRVLOCK;

	if (srvlock) {
		rc = tgt_extent_lock(tsi->tsi_env, ns, &tsi->tsi_resid,
				     start, end, &lh, LCK_PW, &flags);
		if (rc != 0)
			RETURN(rc);
	}

	fo = ofd_object_find_exists(tsi->tsi_env, ofd_exp(tsi->tsi_exp),
				    &tsi->tsi_fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	la_from_obdo(&info->fti_attr, oa,
		     OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME);

	rc = ofd_object_fallocate(tsi->tsi_env, fo, start, end, mode,
				 &info->fti_attr, oa);
	if (rc)
		GOTO(out_put, rc);

	rc = ofd_attr_get(tsi->tsi_env, fo, &info->fti_attr);
	if (rc == 0)
		obdo_from_la(&repbody->oa, &info->fti_attr,
			     OFD_VALID_FLAGS);
	else
		rc = 0;

	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_PREALLOC,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));

	EXIT;
out_put:
	ofd_object_put(tsi->tsi_env, fo);
out:
	if (srvlock)
		tgt_data_unlock(&lh, LCK_PW);
	if (rc == 0) {
		res = ldlm_resource_get(ns, NULL, &tsi->tsi_resid,
					LDLM_EXTENT, 0);
		if (!IS_ERR(res)) {
			struct ost_lvb *res_lvb;

			ldlm_res_lvbo_update(res, NULL, 0);
			res_lvb = res->lr_lvb_data;
			/* Blocks */
			repbody->oa.o_valid |= OBD_MD_FLBLOCKS;
			repbody->oa.o_blocks = res_lvb->lvb_blocks;
			/* Size */
			repbody->oa.o_valid |= OBD_MD_FLSIZE;
			repbody->oa.o_size = res_lvb->lvb_size;

			ldlm_resource_putref(res);
		}
	}

	RETURN(rc);
}

/**
 * OFD request handler for OST_PUNCH RPC.
 *
 * This is part of request processing. Validate request fields,
 * punch (truncate) the given OFD object and pack reply.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_punch_hdl(struct tgt_session_info *tsi)
{
	const struct obdo	*oa = &tsi->tsi_ost_body->oa;
	struct ost_body		*repbody;
	struct ofd_thread_info	*info = tsi2ofd_info(tsi);
	struct ldlm_namespace	*ns = tsi->tsi_tgt->lut_obd->obd_namespace;
	struct ldlm_resource	*res;
	struct ofd_object	*fo;
	__u64			 flags = 0;
	struct lustre_handle	 lh = { 0, };
	__u64			 start, end;
	bool			 srvlock;
	ktime_t			 kstart = ktime_get();
	int			 rc;

	ENTRY;

	OBD_FAIL_TIMEOUT(OBD_FAIL_OST_PAUSE_PUNCH, cfs_fail_val);

	/* check that we do support OBD_CONNECT_TRUNCLOCK. */
	BUILD_BUG_ON(!(OST_CONNECT_SUPPORTED & OBD_CONNECT_TRUNCLOCK));

	if ((oa->o_valid & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS)) !=
	    (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))
		RETURN(err_serious(-EPROTO));

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(err_serious(-ENOMEM));

	/* punch start,end are passed in o_size,o_blocks throught wire */
	start = oa->o_size;
	end = oa->o_blocks;

	if (end != OBD_OBJECT_EOF) /* Only truncate is supported */
		RETURN(-EPROTO);

	/* standard truncate optimization: if file body is completely
	 * destroyed, don't send data back to the server. */
	if (start == 0)
		flags |= LDLM_FL_AST_DISCARD_DATA;

	repbody->oa.o_oi = oa->o_oi;
	repbody->oa.o_valid = OBD_MD_FLID;

	srvlock = oa->o_valid & OBD_MD_FLFLAGS &&
		  oa->o_flags & OBD_FL_SRVLOCK;

	if (srvlock) {
		rc = tgt_extent_lock(tsi->tsi_env, ns, &tsi->tsi_resid, start,
				     end, &lh, LCK_PW, &flags);
		if (rc != 0)
			RETURN(rc);
	}

	CDEBUG(D_INODE, "calling punch for object "DFID", valid = %#llx"
	       ", start = %lld, end = %lld\n", PFID(&tsi->tsi_fid),
	       oa->o_valid, start, end);

	fo = ofd_object_find_exists(tsi->tsi_env, ofd_exp(tsi->tsi_exp),
				    &tsi->tsi_fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	la_from_obdo(&info->fti_attr, oa,
		     OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME);
	info->fti_attr.la_size = start;
	info->fti_attr.la_valid |= LA_SIZE;

	rc = ofd_object_punch(tsi->tsi_env, fo, start, end, &info->fti_attr,
			      (struct obdo *)oa);
	if (rc)
		GOTO(out_put, rc);

	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_PUNCH,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));
	EXIT;
out_put:
	ofd_object_put(tsi->tsi_env, fo);
out:
	if (srvlock)
		tgt_data_unlock(&lh, LCK_PW);
	if (rc == 0) {
		/* we do not call this before to avoid lu_object_find() in
		 *  ->lvbo_update() holding another reference on the object.
		 * otherwise concurrent destroy can make the object unavailable
		 * for 2nd lu_object_find() waiting for the first reference
		 * to go... deadlock! */
		res = ldlm_resource_get(ns, NULL, &tsi->tsi_resid,
				        LDLM_EXTENT, 0);
		if (!IS_ERR(res)) {
			struct ost_lvb *res_lvb;

			ldlm_res_lvbo_update(res, NULL, 0);
			res_lvb = res->lr_lvb_data;
			repbody->oa.o_valid |= OBD_MD_FLBLOCKS;
			repbody->oa.o_blocks = res_lvb->lvb_blocks;
			ldlm_resource_putref(res);
		}
	}
	return rc;
}

static int ofd_ladvise_prefetch(const struct lu_env *env,
				struct ofd_object *fo,
				struct niobuf_local *lnb,
				__u64 start, __u64 end, enum dt_bufs_type dbt)
{
	struct ofd_thread_info *info = ofd_info(env);
	pgoff_t start_index, end_index, pages;
	struct niobuf_remote rnb;
	unsigned long nr_local;
	int rc = 0;

	if (end <= start)
		RETURN(-EINVAL);

	ofd_read_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(out_unlock, rc = -ENOENT);

	rc = ofd_attr_get(env, fo, &info->fti_attr);
	if (rc)
		GOTO(out_unlock, rc);

	if (end > info->fti_attr.la_size)
		end = info->fti_attr.la_size;

	if (end <= start)
		GOTO(out_unlock, rc);

	/* We need page aligned offset and length */
	start_index = start >> PAGE_SHIFT;
	end_index = (end - 1) >> PAGE_SHIFT;
	pages = end_index - start_index + 1;
	while (pages > 0) {
		nr_local = pages <= PTLRPC_MAX_BRW_PAGES ? pages :
			PTLRPC_MAX_BRW_PAGES;
		rnb.rnb_offset = start_index << PAGE_SHIFT;
		rnb.rnb_len = nr_local << PAGE_SHIFT;
		rc = dt_bufs_get(env, ofd_object_child(fo), &rnb, lnb,
				 PTLRPC_MAX_BRW_PAGES, dbt);
		if (unlikely(rc < 0))
			break;
		nr_local = rc;
		rc = dt_read_prep(env, ofd_object_child(fo), lnb, nr_local);
		dt_bufs_put(env, ofd_object_child(fo), lnb, nr_local);
		if (unlikely(rc))
			break;
		start_index += nr_local;
		pages -= nr_local;
	}

out_unlock:
	ofd_read_unlock(env, fo);
	RETURN(rc);
}

/**
 * OFD request handler for OST_LADVISE RPC.
 *
 * Tune cache or perfetch policies according to advices.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative errno on error
 */
static int ofd_ladvise_hdl(struct tgt_session_info *tsi)
{
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	struct obd_export *exp = tsi->tsi_exp;
	struct ofd_device *ofd = ofd_exp(exp);
	struct ost_body *body, *repbody;
	struct ofd_thread_info *info;
	struct ofd_object *fo;
	struct ptlrpc_thread *svc_thread = req->rq_svc_thread;
	const struct lu_env *env = svc_thread->t_env;
	struct tgt_thread_big_cache *tbc = svc_thread->t_data;
	enum dt_bufs_type dbt = DT_BUFS_TYPE_READAHEAD;
	struct lu_ladvise *ladvise;
	int num_advise;
	struct ladvise_hdr *ladvise_hdr;
	struct obd_ioobj ioo;
	struct lustre_handle lockh = { 0 };
	__u64 flags = 0;
	int i;
	struct dt_object *dob;
	__u64 start;
	__u64 end;
	int rc = 0;
	ENTRY;

	CFS_FAIL_TIMEOUT(OBD_FAIL_OST_LADVISE_PAUSE, cfs_fail_val);
	body = tsi->tsi_ost_body;

	if ((body->oa.o_valid & OBD_MD_FLID) != OBD_MD_FLID)
		RETURN(err_serious(-EPROTO));

	ladvise_hdr = req_capsule_client_get(tsi->tsi_pill,
					     &RMF_OST_LADVISE_HDR);
	if (ladvise_hdr == NULL)
		RETURN(err_serious(-EPROTO));

	if (ladvise_hdr->lah_magic != LADVISE_MAGIC ||
	    ladvise_hdr->lah_count < 1)
		RETURN(err_serious(-EPROTO));

	if ((ladvise_hdr->lah_flags & (~LF_MASK)) != 0)
		RETURN(err_serious(-EPROTO));

	ladvise = req_capsule_client_get(tsi->tsi_pill, &RMF_OST_LADVISE);
	if (ladvise == NULL)
		RETURN(err_serious(-EPROTO));

	num_advise = req_capsule_get_size(&req->rq_pill,
					  &RMF_OST_LADVISE, RCL_CLIENT) /
					  sizeof(*ladvise);
	if (num_advise < ladvise_hdr->lah_count)
		RETURN(err_serious(-EPROTO));

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	repbody->oa = body->oa;

	info = ofd_info_init(env, exp);

	rc = ostid_to_fid(&info->fti_fid, &body->oa.o_oi,
			  ofd->ofd_lut.lut_lsd.lsd_osd_index);
	if (rc != 0)
		RETURN(rc);

	fo = ofd_object_find(env, ofd, &info->fti_fid);
	if (IS_ERR(fo)) {
		rc = PTR_ERR(fo);
		RETURN(rc);
	}
	LASSERT(fo != NULL);
	dob = ofd_object_child(fo);

	if (ptlrpc_connection_is_local(exp->exp_connection))
		dbt |= DT_BUFS_TYPE_LOCAL;

	for (i = 0; i < num_advise; i++, ladvise++) {
		start = ladvise->lla_start;
		end = ladvise->lla_end;
		if (end <= start) {
			rc = err_serious(-EPROTO);
			break;
		}

		/* Handle different advice types */
		switch (ladvise->lla_advice) {
		default:
			rc = -ENOTSUPP;
			break;
		case LU_LADVISE_WILLREAD:
			if (tbc == NULL)
				RETURN(-ENOMEM);

			ioo.ioo_oid = body->oa.o_oi;
			ioo.ioo_bufcnt = 1;
			rc = tgt_extent_lock(env, exp->exp_obd->obd_namespace,
					     &tsi->tsi_resid, start, end - 1,
					     &lockh, LCK_PR, &flags);
			if (rc != 0)
				break;

			req->rq_status = ofd_ladvise_prefetch(env, fo,
							      tbc->local,
							      start, end, dbt);
			tgt_data_unlock(&lockh, LCK_PR);
			break;
		case LU_LADVISE_DONTNEED:
			rc = dt_ladvise(env, dob, ladvise->lla_start,
					ladvise->lla_end, LU_LADVISE_DONTNEED);
			break;
		}
		if (rc != 0)
			break;
	}

	ofd_object_put(env, fo);
	req->rq_status = rc;
	RETURN(rc);
}

/**
 * OFD request handler for OST_QUOTACTL RPC.
 *
 * This is part of request processing to validate incoming request fields,
 * get the requested data from OSD and pack reply.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_quotactl(struct tgt_session_info *tsi)
{
	struct obd_quotactl *oqctl, *repoqc;
	struct lu_nodemap *nodemap;
	ktime_t kstart = ktime_get();
	int id;
	int rc;

	ENTRY;

	oqctl = req_capsule_client_get(tsi->tsi_pill, &RMF_OBD_QUOTACTL);
	if (oqctl == NULL)
		RETURN(err_serious(-EPROTO));

	repoqc = req_capsule_server_get(tsi->tsi_pill, &RMF_OBD_QUOTACTL);
	if (repoqc == NULL)
		RETURN(err_serious(-ENOMEM));

	*repoqc = *oqctl;

	nodemap = nodemap_get_from_exp(tsi->tsi_exp);
	if (IS_ERR(nodemap))
		RETURN(PTR_ERR(nodemap));

	id = repoqc->qc_id;
	if (oqctl->qc_type == USRQUOTA)
		id = nodemap_map_id(nodemap, NODEMAP_UID,
				    NODEMAP_CLIENT_TO_FS,
				    repoqc->qc_id);
	else if (oqctl->qc_type == GRPQUOTA)
		id = nodemap_map_id(nodemap, NODEMAP_GID,
				    NODEMAP_CLIENT_TO_FS,
				    repoqc->qc_id);

	nodemap_putref(nodemap);

	if (repoqc->qc_id != id)
		swap(repoqc->qc_id, id);

	rc = lquotactl_slv(tsi->tsi_env, tsi->tsi_tgt->lut_bottom, repoqc);

	ofd_counter_incr(tsi->tsi_exp, LPROC_OFD_STATS_QUOTACTL,
			 tsi->tsi_jobid, ktime_us_delta(ktime_get(), kstart));

	if (repoqc->qc_id != id)
		swap(repoqc->qc_id, id);

	RETURN(rc);
}

/**
 * Prolong lock timeout for the given extent.
 *
 * This function finds all locks related with incoming request and
 * prolongs their timeout.
 *
 * If a client is holding a lock for a long time while it sends
 * read or write RPCs to the OST for the object under this lock,
 * then we don't want the OST to evict the client. Otherwise,
 * if the network or disk is very busy then the client may not
 * be able to make any progress to clear out dirty pages under
 * the lock and the application will fail.
 *
 * Every time a Bulk Read/Write (BRW) request arrives for the object
 * covered by the lock, extend the timeout on that lock. The RPC should
 * contain a lock handle for the lock it is using, but this
 * isn't handled correctly by all client versions, and the
 * request may cover multiple locks.
 *
 * \param[in] tsi	target session environment for this request
 * \param[in] data	struct of data to prolong locks
 *
 */
static void ofd_prolong_extent_locks(struct tgt_session_info *tsi,
				    struct ldlm_prolong_args *data)
{
	struct obdo		*oa  = &tsi->tsi_ost_body->oa;
	struct ldlm_lock	*lock;

	ENTRY;

	data->lpa_timeout = prolong_timeout(tgt_ses_req(tsi));
	data->lpa_export = tsi->tsi_exp;
	data->lpa_resid = tsi->tsi_resid;

	CDEBUG(D_RPCTRACE, "Prolong locks for req %p with x%llu"
	       " ext(%llu->%llu)\n", tgt_ses_req(tsi),
	       tgt_ses_req(tsi)->rq_xid, data->lpa_extent.start,
	       data->lpa_extent.end);

	if (oa->o_valid & OBD_MD_FLHANDLE) {
		/* mostly a request should be covered by only one lock, try
		 * fast path. */
		lock = ldlm_handle2lock(&oa->o_handle);
		if (lock != NULL) {
			/* Fast path to check if the lock covers the whole IO
			 * region exclusively. */
			if (ldlm_extent_contain(&lock->l_policy_data.l_extent,
						&data->lpa_extent)) {
				/* bingo */
				LASSERT(lock->l_export == data->lpa_export);
				ldlm_lock_prolong_one(lock, data);
				LDLM_LOCK_PUT(lock);
				if (data->lpa_locks_cnt > 0)
					RETURN_EXIT;
				/* The lock was destroyed probably lets try
				 * resource tree. */
			} else {
				lock->l_last_used = ktime_get();
				LDLM_LOCK_PUT(lock);
			}
		}
	}

	ldlm_resource_prolong(data);
	EXIT;
}

/**
 * Implementation of ptlrpc_hpreq_ops::hpreq_lock_match for OFD RW requests.
 *
 * Determine if \a lock and the lock from request \a req are equivalent
 * by comparing their resource names, modes, and extents.
 *
 * It is used to give priority to read and write RPCs being done
 * under this lock so that the client can drop the contended
 * lock more quickly and let other clients use it. This improves
 * overall performance in the case where the first client gets a
 * very large lock extent that prevents other clients from
 * submitting their writes.
 *
 * \param[in] req	ptlrpc_request being processed
 * \param[in] lock	contended lock to match
 *
 * \retval		1 if lock is matched
 * \retval		0 otherwise
 */
static int ofd_rw_hpreq_lock_match(struct ptlrpc_request *req,
				   struct ldlm_lock *lock)
{
	struct niobuf_remote *rnb;
	struct obd_ioobj *ioo;
	enum ldlm_mode  mode;
	struct ldlm_extent ext;
	__u32 opc = lustre_msg_get_opc(req->rq_reqmsg);

	ENTRY;

	ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
	LASSERT(ioo != NULL);

	rnb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
	LASSERT(rnb != NULL);

	ext.start = rnb->rnb_offset;
	rnb += ioo->ioo_bufcnt - 1;
	ext.end = rnb->rnb_offset + rnb->rnb_len - 1;

	LASSERT(lock->l_resource != NULL);
	if (!ostid_res_name_eq(&ioo->ioo_oid, &lock->l_resource->lr_name))
		RETURN(0);

	/* a bulk write can only hold a reference on a PW extent lock
	 * or GROUP lock.
	 */
	mode = LCK_PW | LCK_GROUP;
	if (opc == OST_READ)
		/* whereas a bulk read can be protected by either a PR or PW
		 * extent lock */
		mode |= LCK_PR;

	if (!(lock->l_granted_mode & mode))
		RETURN(0);

	RETURN(ldlm_extent_overlap(&lock->l_policy_data.l_extent, &ext));
}

/**
 * Implementation of ptlrpc_hpreq_ops::hpreq_lock_check for OFD RW requests.
 *
 * Check for whether the given PTLRPC request (\a req) is blocking
 * an LDLM lock cancel. Also checks whether the request is covered by an LDLM
 * lock.
 *
 * \param[in] req	the incoming request
 *
 * \retval		1 if \a req is blocking an LDLM lock cancel
 * \retval		0 if it is not
 * \retval		-ESTALE if lock is not found
 */
static int ofd_rw_hpreq_check(struct ptlrpc_request *req)
{
	struct tgt_session_info	*tsi;
	struct obd_ioobj	*ioo;
	struct niobuf_remote	*rnb;
	int opc;
	struct ldlm_prolong_args pa = { 0 };

	ENTRY;

	/* Don't use tgt_ses_info() to get session info, because lock_match()
	 * can be called while request has no processing thread yet. */
	tsi = lu_context_key_get(&req->rq_session, &tgt_session_key);

	/*
	 * Use LASSERT below because malformed RPCs should have
	 * been filtered out in tgt_hpreq_handler().
	 */
	opc = lustre_msg_get_opc(req->rq_reqmsg);
	LASSERT(opc == OST_READ || opc == OST_WRITE);

	ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
	LASSERT(ioo != NULL);

	rnb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
	LASSERT(rnb != NULL);
	LASSERT(!(rnb->rnb_flags & OBD_BRW_SRVLOCK));

	pa.lpa_mode = LCK_PW | LCK_GROUP;
	if (opc == OST_READ)
		pa.lpa_mode |= LCK_PR;

	pa.lpa_extent.start = rnb->rnb_offset;
	rnb += ioo->ioo_bufcnt - 1;
	pa.lpa_extent.end = rnb->rnb_offset + rnb->rnb_len - 1;

	DEBUG_REQ(D_RPCTRACE, req,
		  "%s %s: refresh rw locks for "DFID" (%llu->%llu)",
		  tgt_name(tsi->tsi_tgt), current->comm, PFID(&tsi->tsi_fid),
		  pa.lpa_extent.start, pa.lpa_extent.end);

	ofd_prolong_extent_locks(tsi, &pa);

	CDEBUG(D_DLMTRACE, "%s: refreshed %u locks timeout for req %p\n",
	       tgt_name(tsi->tsi_tgt), pa.lpa_blocks_cnt, req);

	if (pa.lpa_blocks_cnt > 0)
		RETURN(1);

	RETURN(pa.lpa_locks_cnt > 0 ? 0 : -ESTALE);
}

/**
 * Implementation of ptlrpc_hpreq_ops::hpreq_lock_fini for OFD RW requests.
 *
 * Called after the request has been handled. It refreshes lock timeout again
 * so that client has more time to send lock cancel RPC.
 *
 * \param[in] req	request which is being processed.
 */
static void ofd_rw_hpreq_fini(struct ptlrpc_request *req)
{
	ofd_rw_hpreq_check(req);
}

/**
 * Implementation of ptlrpc_hpreq_ops::hpreq_lock_match for OST_PUNCH request.
 *
 * This function checks if the given lock is the same by its resname, mode
 * and extent as one taken from the request.
 * It is used to give priority to punch/truncate RPCs that might lead to
 * the fastest release of that lock when a lock is contended.
 *
 * \param[in] req	ptlrpc_request being processed
 * \param[in] lock	contended lock to match
 *
 * \retval		1 if lock is matched
 * \retval		0 otherwise
 */
static int ofd_punch_hpreq_lock_match(struct ptlrpc_request *req,
				      struct ldlm_lock *lock)
{
	struct tgt_session_info	*tsi;
	struct obdo		*oa;
	struct ldlm_extent	 ext;

	ENTRY;

	/* Don't use tgt_ses_info() to get session info, because lock_match()
	 * can be called while request has no processing thread yet. */
	tsi = lu_context_key_get(&req->rq_session, &tgt_session_key);

	/*
	 * Use LASSERT below because malformed RPCs should have
	 * been filtered out in tgt_hpreq_handler().
	 */
	LASSERT(tsi->tsi_ost_body != NULL);
	if (tsi->tsi_ost_body->oa.o_valid & OBD_MD_FLHANDLE &&
	    tsi->tsi_ost_body->oa.o_handle.cookie == lock->l_handle.h_cookie)
		RETURN(1);

	oa = &tsi->tsi_ost_body->oa;
	ext.start = oa->o_size;
	ext.end   = oa->o_blocks;

	LASSERT(lock->l_resource != NULL);
	if (!ostid_res_name_eq(&oa->o_oi, &lock->l_resource->lr_name))
		RETURN(0);

	if (!(lock->l_granted_mode & (LCK_PW | LCK_GROUP)))
		RETURN(0);

	RETURN(ldlm_extent_overlap(&lock->l_policy_data.l_extent, &ext));
}

/**
 * Implementation of ptlrpc_hpreq_ops::hpreq_lock_check for OST_PUNCH request.
 *
 * High-priority queue request check for whether the given punch request
 * (\a req) is blocking an LDLM lock cancel. Also checks whether the request is
 * covered by an LDLM lock.
 *

 *
 * \param[in] req	the incoming request
 *
 * \retval		1 if \a req is blocking an LDLM lock cancel
 * \retval		0 if it is not
 * \retval		-ESTALE if lock is not found
 */
static int ofd_punch_hpreq_check(struct ptlrpc_request *req)
{
	struct tgt_session_info	*tsi;
	struct obdo		*oa;
	struct ldlm_prolong_args pa = { 0 };

	ENTRY;

	/* Don't use tgt_ses_info() to get session info, because lock_match()
	 * can be called while request has no processing thread yet. */
	tsi = lu_context_key_get(&req->rq_session, &tgt_session_key);
	LASSERT(tsi != NULL);
	oa = &tsi->tsi_ost_body->oa;

	LASSERT(!(oa->o_valid & OBD_MD_FLFLAGS &&
		  oa->o_flags & OBD_FL_SRVLOCK));

	pa.lpa_mode = LCK_PW | LCK_GROUP;
	pa.lpa_extent.start = oa->o_size;
	pa.lpa_extent.end   = oa->o_blocks;

	CDEBUG(D_DLMTRACE,
	       "%s: refresh locks: %llu/%llu (%llu->%llu)\n",
	       tgt_name(tsi->tsi_tgt), tsi->tsi_resid.name[0],
	       tsi->tsi_resid.name[1], pa.lpa_extent.start, pa.lpa_extent.end);

	ofd_prolong_extent_locks(tsi, &pa);

	CDEBUG(D_DLMTRACE, "%s: refreshed %u locks timeout for req %p.\n",
	       tgt_name(tsi->tsi_tgt), pa.lpa_blocks_cnt, req);

	if (pa.lpa_blocks_cnt > 0)
		RETURN(1);

	RETURN(pa.lpa_locks_cnt > 0 ? 0 : -ESTALE);
}

/**
 * Implementation of ptlrpc_hpreq_ops::hpreq_lock_fini for OST_PUNCH request.
 *
 * Called after the request has been handled. It refreshes lock timeout again
 * so that client has more time to send lock cancel RPC.
 *
 * \param[in] req	request which is being processed.
 */
static void ofd_punch_hpreq_fini(struct ptlrpc_request *req)
{
	ofd_punch_hpreq_check(req);
}

static struct ptlrpc_hpreq_ops ofd_hpreq_rw = {
	.hpreq_lock_match	= ofd_rw_hpreq_lock_match,
	.hpreq_check		= ofd_rw_hpreq_check,
	.hpreq_fini		= ofd_rw_hpreq_fini
};

static struct ptlrpc_hpreq_ops ofd_hpreq_punch = {
	.hpreq_lock_match	= ofd_punch_hpreq_lock_match,
	.hpreq_check		= ofd_punch_hpreq_check,
	.hpreq_fini		= ofd_punch_hpreq_fini
};

/**
 * Assign high priority operations to an IO request.
 *
 * Check if the incoming request is a candidate for
 * high-priority processing. If it is, assign it a high
 * priority operations table.
 *
 * \param[in] tsi	target session environment for this request
 */
static void ofd_hp_brw(struct tgt_session_info *tsi)
{
	struct niobuf_remote	*rnb;
	struct obd_ioobj	*ioo;

	ENTRY;

	ioo = req_capsule_client_get(tsi->tsi_pill, &RMF_OBD_IOOBJ);
	LASSERT(ioo != NULL); /* must exist after request preprocessing */
	if (ioo->ioo_bufcnt > 0) {
		rnb = req_capsule_client_get(tsi->tsi_pill, &RMF_NIOBUF_REMOTE);
		LASSERT(rnb != NULL); /* must exist after request preprocessing */

		/* no high priority if server lock is needed */
		if (rnb->rnb_flags & OBD_BRW_SRVLOCK ||
		    (lustre_msg_get_flags(tgt_ses_req(tsi)->rq_reqmsg)
		     & MSG_REPLAY))
			return;
	}
	tgt_ses_req(tsi)->rq_ops = &ofd_hpreq_rw;
}

/**
 * Assign high priority operations to an punch request.
 *
 * Check if the incoming request is a candidate for
 * high-priority processing. If it is, assign it a high
 * priority operations table.
 *
 * \param[in] tsi	target session environment for this request
 */
static void ofd_hp_punch(struct tgt_session_info *tsi)
{
	LASSERT(tsi->tsi_ost_body != NULL); /* must exists if we are here */
	/* no high-priority if server lock is needed */
	if ((tsi->tsi_ost_body->oa.o_valid & OBD_MD_FLFLAGS &&
	     tsi->tsi_ost_body->oa.o_flags & OBD_FL_SRVLOCK) ||
	    tgt_conn_flags(tsi) & OBD_CONNECT_MDS ||
	    lustre_msg_get_flags(tgt_ses_req(tsi)->rq_reqmsg) & MSG_REPLAY)
		return;
	tgt_ses_req(tsi)->rq_ops = &ofd_hpreq_punch;
}

#define OBD_FAIL_OST_READ_NET	OBD_FAIL_OST_BRW_NET
#define OBD_FAIL_OST_WRITE_NET	OBD_FAIL_OST_BRW_NET
#define OST_BRW_READ	OST_READ
#define OST_BRW_WRITE	OST_WRITE

/**
 * Table of OFD-specific request handlers
 *
 * This table contains all opcodes accepted by OFD and
 * specifies handlers for them. The tgt_request_handler()
 * uses such table from each target to process incoming
 * requests.
 */
static struct tgt_handler ofd_tgt_handlers[] = {
TGT_RPC_HANDLER(OST_FIRST_OPC,
		0,			OST_CONNECT,	tgt_connect,
		&RQF_CONNECT, LUSTRE_OBD_VERSION),
TGT_RPC_HANDLER(OST_FIRST_OPC,
		0,			OST_DISCONNECT,	tgt_disconnect,
		&RQF_OST_DISCONNECT, LUSTRE_OBD_VERSION),
TGT_RPC_HANDLER(OST_FIRST_OPC,
		0,			OST_SET_INFO,	ofd_set_info_hdl,
		&RQF_OBD_SET_INFO, LUSTRE_OST_VERSION),
TGT_OST_HDL(0,				OST_GET_INFO,	ofd_get_info_hdl),
TGT_OST_HDL(HAS_BODY | HAS_REPLY,	OST_GETATTR,	ofd_getattr_hdl),
TGT_OST_HDL(HAS_BODY | HAS_REPLY | IS_MUTABLE,
					OST_SETATTR,	ofd_setattr_hdl),
TGT_OST_HDL(HAS_REPLY | IS_MUTABLE,
					OST_CREATE,	ofd_create_hdl),
TGT_OST_HDL(HAS_REPLY | IS_MUTABLE,
					OST_DESTROY,	ofd_destroy_hdl),
TGT_OST_HDL(HAS_REPLY,	OST_STATFS,	ofd_statfs_hdl),
TGT_OST_HDL_HP(HAS_BODY | HAS_REPLY,	OST_BRW_READ,	tgt_brw_read,
							ofd_hp_brw),
/* don't set CORPUS flag for brw_write because -ENOENT may be valid case */
TGT_OST_HDL_HP(HAS_BODY | IS_MUTABLE,	OST_BRW_WRITE,	tgt_brw_write,
							ofd_hp_brw),
TGT_OST_HDL_HP(HAS_BODY | HAS_REPLY | IS_MUTABLE,
					OST_PUNCH,	ofd_punch_hdl,
							ofd_hp_punch),
TGT_OST_HDL(HAS_BODY | HAS_REPLY,	OST_SYNC,	ofd_sync_hdl),
TGT_OST_HDL(HAS_REPLY,	OST_QUOTACTL,	ofd_quotactl),
TGT_OST_HDL(HAS_BODY | HAS_REPLY, OST_LADVISE,	ofd_ladvise_hdl),
TGT_OST_HDL(HAS_BODY | HAS_REPLY | IS_MUTABLE, OST_FALLOCATE, ofd_fallocate_hdl),
TGT_OST_HDL(HAS_BODY | HAS_REPLY, OST_SEEK, tgt_lseek),
};

static struct tgt_opc_slice ofd_common_slice[] = {
	{
		.tos_opc_start	= OST_FIRST_OPC,
		.tos_opc_end	= OST_LAST_OPC,
		.tos_hs		= ofd_tgt_handlers
	},
	{
		.tos_opc_start	= OBD_FIRST_OPC,
		.tos_opc_end	= OBD_LAST_OPC,
		.tos_hs		= tgt_obd_handlers
	},
	{
		.tos_opc_start	= LDLM_FIRST_OPC,
		.tos_opc_end	= LDLM_LAST_OPC,
		.tos_hs		= tgt_dlm_handlers
	},
	{
		.tos_opc_start	= OUT_UPDATE_FIRST_OPC,
		.tos_opc_end	= OUT_UPDATE_LAST_OPC,
		.tos_hs		= tgt_out_handlers
	},
	{
		.tos_opc_start	= SEQ_FIRST_OPC,
		.tos_opc_end	= SEQ_LAST_OPC,
		.tos_hs		= seq_handlers
	},
	{
		.tos_opc_start	= LFSCK_FIRST_OPC,
		.tos_opc_end	= LFSCK_LAST_OPC,
		.tos_hs		= tgt_lfsck_handlers
	},
	{
		.tos_opc_start  = SEC_FIRST_OPC,
		.tos_opc_end    = SEC_LAST_OPC,
		.tos_hs         = tgt_sec_ctx_handlers
	},
	{
		.tos_hs		= NULL
	}
};

/* context key constructor/destructor: ofd_key_init(), ofd_key_fini() */
LU_KEY_INIT_FINI(ofd, struct ofd_thread_info);

/**
 * Implementation of lu_context_key::lct_key_exit.
 *
 * Optional method called on lu_context_exit() for all allocated
 * keys.
 * It is used in OFD to sanitize context values which may be re-used
 * during another request processing by the same thread.
 *
 * \param[in] ctx	execution context
 * \param[in] key	context key
 * \param[in] data	ofd_thread_info
 */
static void ofd_key_exit(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct ofd_thread_info *info = data;

	info->fti_env = NULL;
	info->fti_exp = NULL;

	info->fti_xid = 0;
	info->fti_pre_version = 0;

	memset(&info->fti_attr, 0, sizeof info->fti_attr);
}

struct lu_context_key ofd_thread_key = {
	.lct_tags = LCT_DT_THREAD,
	.lct_init = ofd_key_init,
	.lct_fini = ofd_key_fini,
	.lct_exit = ofd_key_exit
};

/**
 * Initialize OFD device according to parameters in the config log \a cfg.
 *
 * This is the main starting point of OFD initialization. It fills all OFD
 * parameters with their initial values and calls other initializing functions
 * to set up all OFD subsystems.
 *
 * \param[in] env	execution environment
 * \param[in] m		OFD device
 * \param[in] ldt	LU device type of OFD
 * \param[in] cfg	configuration log
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_init0(const struct lu_env *env, struct ofd_device *m,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	const char *dev = lustre_cfg_string(cfg, 0);
	struct ofd_thread_info *info = NULL;
	struct obd_device *obd;
	struct tg_grants_data *tgd = &m->ofd_lut.lut_tgd;
	struct lu_fid fid;
	struct nm_config_file *nodemap_config;
	struct obd_device_target *obt;
	u32 lmd_flags = 0;
	int rc;

	ENTRY;

	obd = class_name2obd(dev);
	if (obd == NULL) {
		CERROR("Cannot find obd with name %s\n", dev);
		RETURN(-ENODEV);
	}

	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0)
		RETURN(rc);

	obt = &obd->u.obt;
	obt->obt_magic = OBT_MAGIC;

	spin_lock_init(&m->ofd_flags_lock);
	m->ofd_raid_degraded = 0;
	m->ofd_sync_journal = 0;
	ofd_slc_set(m);
	m->ofd_soft_sync_limit = OFD_SOFT_SYNC_LIMIT_DEFAULT;

	m->ofd_seq_count = 0;
	INIT_LIST_HEAD(&m->ofd_inconsistency_list);
	spin_lock_init(&m->ofd_inconsistency_lock);

	m->ofd_access_log_mask = -1; /* Log all accesses if enabled. */

	spin_lock_init(&m->ofd_batch_lock);
	init_rwsem(&m->ofd_lastid_rwsem);

	m->ofd_dt_dev.dd_lu_dev.ld_ops = &ofd_lu_ops;
	m->ofd_dt_dev.dd_lu_dev.ld_obd = obd;
	/* set this lu_device to obd, because error handling need it */
	obd->obd_lu_dev = &m->ofd_dt_dev.dd_lu_dev;

	/* No connection accepted until configurations will finish */
	spin_lock(&obd->obd_dev_lock);
	obd->obd_no_conn = 1;
	spin_unlock(&obd->obd_dev_lock);
	obd->obd_replayable = 1;
	if (cfg->lcfg_bufcount > 4 && LUSTRE_CFG_BUFLEN(cfg, 4) > 0) {
		char *str = lustre_cfg_string(cfg, 4);

		if (strchr(str, 'n')) {
			CWARN("%s: recovery disabled\n", obd->obd_name);
			obd->obd_replayable = 0;
		}
	}

	info = ofd_info_init(env, NULL);
	if (info == NULL)
		RETURN(-EFAULT);

	rc = ofd_stack_init(env, m, cfg, &lmd_flags);
	if (rc) {
		CERROR("%s: can't init device stack, rc %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 14, 53, 0)
	ofd_procfs_add_brw_stats_symlink(m);
#endif

	snprintf(info->fti_u.name, sizeof(info->fti_u.name), "%s-%s",
		 "filter"/*LUSTRE_OST_NAME*/, obd->obd_uuid.uuid);
	m->ofd_namespace = ldlm_namespace_new(obd, info->fti_u.name,
					      LDLM_NAMESPACE_SERVER,
					      LDLM_NAMESPACE_GREEDY,
					      LDLM_NS_TYPE_OST);
	if (IS_ERR(m->ofd_namespace)) {
		rc = PTR_ERR(m->ofd_namespace);
		CERROR("%s: unable to create server namespace: rc = %d\n",
		       obd->obd_name, rc);
		m->ofd_namespace = NULL;
		GOTO(err_fini_stack, rc);
	}
	/* set obd_namespace for compatibility with old code */
	obd->obd_namespace = m->ofd_namespace;
	ldlm_register_intent(m->ofd_namespace, ofd_intent_policy);
	m->ofd_namespace->ns_lvbo = &ofd_lvbo;
	m->ofd_namespace->ns_lvbp = m;

	ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
			   "filter_ldlm_cb_client", &obd->obd_ldlm_client);

	rc = tgt_init(env, &m->ofd_lut, obd, m->ofd_osd, ofd_common_slice,
		      OBD_FAIL_OST_ALL_REQUEST_NET,
		      OBD_FAIL_OST_ALL_REPLY_NET);
	if (rc)
		GOTO(err_free_ns, rc);

	if (lmd_flags & LMD_FLG_SKIP_LFSCK)
		m->ofd_skip_lfsck = 1;
	if (lmd_flags & LMD_FLG_LOCAL_RECOV)
		m->ofd_lut.lut_local_recovery = 1;

	rc = ofd_tunables_init(m);
	if (rc)
		GOTO(err_fini_lut, rc);

	tgd->tgd_reserved_pcnt = 0;

	m->ofd_brw_size = m->ofd_lut.lut_dt_conf.ddp_brw_size;
	m->ofd_precreate_batch = OFD_PRECREATE_BATCH_DEFAULT;
	if (tgd->tgd_osfs.os_bsize * tgd->tgd_osfs.os_blocks <
	    OFD_PRECREATE_SMALL_FS)
		m->ofd_precreate_batch = OFD_PRECREATE_BATCH_SMALL;
	m->ofd_atime_diff = OFD_DEF_ATIME_DIFF;

	rc = ofd_fs_setup(env, m, obd);
	if (rc)
		GOTO(err_fini_proc, rc);

	fid.f_seq = FID_SEQ_LOCAL_NAME;
	fid.f_oid = 1;
	fid.f_ver = 0;
	rc = local_oid_storage_init(env, m->ofd_osd, &fid,
				    &m->ofd_los);
	if (rc != 0)
		GOTO(err_fini_fs, rc);

	nodemap_config = nm_config_file_register_tgt(env, m->ofd_osd,
						     m->ofd_los);
	if (IS_ERR(nodemap_config)) {
		rc = PTR_ERR(nodemap_config);
		if (rc != -EROFS)
			GOTO(err_fini_los, rc);
	} else {
		obt->obt_nodemap_config_file = nodemap_config;
	}

	rc = ofd_start_inconsistency_verification_thread(m);
	if (rc != 0)
		GOTO(err_fini_nm, rc);

	tgt_adapt_sptlrpc_conf(&m->ofd_lut);

	RETURN(0);

err_fini_nm:
	nm_config_file_deregister_tgt(env, obt->obt_nodemap_config_file);
	obt->obt_nodemap_config_file = NULL;
err_fini_los:
	local_oid_storage_fini(env, m->ofd_los);
	m->ofd_los = NULL;
err_fini_fs:
	ofd_fs_cleanup(env, m);
err_fini_proc:
	ofd_procfs_fini(m);
err_fini_lut:
	tgt_fini(env, &m->ofd_lut);
err_free_ns:
	ldlm_namespace_free(m->ofd_namespace, NULL, obd->obd_force);
	obd->obd_namespace = m->ofd_namespace = NULL;
err_fini_stack:
	ofd_stack_fini(env, m, &m->ofd_osd->dd_lu_dev);
	return rc;
}

/**
 * Stop the OFD device
 *
 * This function stops the OFD device and all its subsystems.
 * This is the end of OFD lifecycle.
 *
 * \param[in] env	execution environment
 * \param[in] m		OFD device
 */
static void ofd_fini(const struct lu_env *env, struct ofd_device *m)
{
	struct obd_device	*obd = ofd_obd(m);
	struct lu_device	*d   = &m->ofd_dt_dev.dd_lu_dev;
	struct lfsck_stop	 stop;

	stop.ls_status = LS_PAUSED;
	stop.ls_flags = 0;
	lfsck_stop(env, m->ofd_osd, &stop);
	ofd_stack_pre_fini(env, m, &m->ofd_dt_dev.dd_lu_dev);
	target_recovery_fini(obd);
	if (m->ofd_namespace != NULL)
		ldlm_namespace_free_prior(m->ofd_namespace, NULL,
					  d->ld_obd->obd_force);

	obd_exports_barrier(obd);
	obd_zombie_barrier();

	ofd_procfs_fini(m);
	tgt_fini(env, &m->ofd_lut);
	ofd_stop_inconsistency_verification_thread(m);
	lfsck_degister(env, m->ofd_osd);
	ofd_fs_cleanup(env, m);
	nm_config_file_deregister_tgt(env, obd->u.obt.obt_nodemap_config_file);
	obd->u.obt.obt_nodemap_config_file = NULL;

	if (m->ofd_namespace != NULL) {
		ldlm_namespace_free_post(m->ofd_namespace);
		d->ld_obd->obd_namespace = m->ofd_namespace = NULL;
	}

	ofd_access_log_delete(m->ofd_access_log);
	m->ofd_access_log = NULL;

	ofd_stack_fini(env, m, &m->ofd_dt_dev.dd_lu_dev);

	LASSERT(atomic_read(&d->ld_ref) == 0);
	server_put_mount(obd->obd_name, true);
	EXIT;
}

/**
 * Implementation of lu_device_type_operations::ldto_device_fini.
 *
 * Finalize device. Dual to ofd_device_init(). It is called from
 * obd_precleanup() and stops the current device.
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of OFD
 *
 * \retval		NULL
 */
static struct lu_device *ofd_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	ENTRY;
	ofd_fini(env, ofd_dev(d));
	RETURN(NULL);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_free.
 *
 * Free OFD device. Dual to ofd_device_alloc().
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of OFD
 *
 * \retval		NULL
 */
static struct lu_device *ofd_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct ofd_device *m = ofd_dev(d);

	dt_device_fini(&m->ofd_dt_dev);
	OBD_FREE_PTR(m);
	RETURN(NULL);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_alloc.
 *
 * This function allocates the new OFD device. It is called from
 * obd_setup() if OBD device had lu_device_type defined.
 *
 * \param[in] env	execution environment
 * \param[in] t		lu_device_type of OFD device
 * \param[in] cfg	configuration log
 *
 * \retval		pointer to the lu_device of just allocated OFD
 * \retval		ERR_PTR of return value on error
 */
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

/* type constructor/destructor: ofd_type_init(), ofd_type_fini() */
LU_TYPE_INIT_FINI(ofd, &ofd_thread_key);

static const struct lu_device_type_operations ofd_device_type_ops = {
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

/**
 * Initialize OFD module.
 *
 * This function is called upon module loading. It registers OFD device type
 * and prepares all in-memory structures used by all OFD devices.
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int __init ofd_init(void)
{
	int rc;

	rc = lu_kmem_init(ofd_caches);
	if (rc)
		return rc;

	rc = ofd_access_log_module_init();
	if (rc)
		goto out_caches;

	rc = class_register_type(&ofd_obd_ops, NULL, true,
				 LUSTRE_OST_NAME, &ofd_device_type);
	if (rc)
		goto out_ofd_access_log;

	return 0;

out_ofd_access_log:
	ofd_access_log_module_exit();
out_caches:
	lu_kmem_fini(ofd_caches);

	return rc;
}

/**
 * Stop OFD module.
 *
 * This function is called upon OFD module unloading.
 * It frees all related structures and unregisters OFD device type.
 */
static void __exit ofd_exit(void)
{
	class_unregister_type(LUSTRE_OST_NAME);
	ofd_access_log_module_exit();
	lu_kmem_fini(ofd_caches);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Filtering Device");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(ofd_init);
module_exit(ofd_exit);
