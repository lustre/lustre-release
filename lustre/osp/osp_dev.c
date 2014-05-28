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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osp/osp_dev.c
 *
 * Lustre OST Proxy Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 * Author: Di Wang <di.wang@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <lustre_param.h>
#include <lustre_log.h>
#include <lustre_mdc.h>

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

struct lu_object *osp_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *d)
{
	struct lu_object_header	*h = NULL;
	struct osp_object	*o;
	struct lu_object	*l;

	OBD_SLAB_ALLOC_PTR_GFP(o, osp_object_kmem, GFP_NOFS);
	if (o != NULL) {
		l = &o->opo_obj.do_lu;

		/* For data object, OSP obj would always be the top
		 * object, i.e. hdr is always NULL, see lu_object_alloc.
		 * But for metadata object, we always build the object
		 * stack from MDT. i.e. mdt_object will be the top object
		 * i.e.  hdr != NULL */
		if (hdr == NULL) {
			/* object for OST */
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

static struct dt_object
*osp_find_or_create(const struct lu_env *env, struct osp_device *osp,
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
	dto = dt_find_or_create(env, osp->opd_storage, &osi->osi_fid,
				&dof, attr);
	if (IS_ERR(dto))
		RETURN(dto);

	rc = dt_attr_get(env, dto, attr, NULL);
	if (rc) {
		CERROR("%s: can't be initialized: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		lu_object_put(env, &dto->do_lu);
		RETURN(ERR_PTR(rc));
	}
	RETURN(dto);
}

static int osp_write_local_file(const struct lu_env *env,
				struct osp_device *osp,
				struct dt_object *dt_obj,
				struct lu_buf *buf,
				loff_t offset)
{
	struct thandle *th;
	int rc;

	th = dt_trans_create(env, osp->opd_storage);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_record_write(env, dt_obj, buf->lb_len, offset, th);
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

static int osp_init_last_objid(const struct lu_env *env, struct osp_device *osp)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct lu_fid		*fid = &osp->opd_last_used_fid;
	struct dt_object	*dto;
	int			rc;
	ENTRY;

	dto = osp_find_or_create(env, osp, &osi->osi_attr, MDD_LOV_OBJ_OID);
	if (IS_ERR(dto))
		RETURN(PTR_ERR(dto));
	/* object will be released in device cleanup path */
	if (osi->osi_attr.la_size >=
	    sizeof(osi->osi_id) * (osp->opd_index + 1)) {
		osp_objid_buf_prep(&osi->osi_lb, &osi->osi_off, &fid->f_oid,
				   osp->opd_index);
		rc = dt_record_read(env, dto, &osi->osi_lb, &osi->osi_off);
		if (rc != 0)
			GOTO(out, rc);
	} else {
		fid->f_oid = 0;
		osp_objid_buf_prep(&osi->osi_lb, &osi->osi_off, &fid->f_oid,
				   osp->opd_index);
		rc = osp_write_local_file(env, osp, dto, &osi->osi_lb,
					  osi->osi_off);
	}
	osp->opd_last_used_oid_file = dto;
	RETURN(0);
out:
	/* object will be released in device cleanup path */
	CERROR("%s: can't initialize lov_objid: rc = %d\n",
	       osp->opd_obd->obd_name, rc);
	lu_object_put(env, &dto->do_lu);
	osp->opd_last_used_oid_file = NULL;
	RETURN(rc);
}

static int osp_init_last_seq(const struct lu_env *env, struct osp_device *osp)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct lu_fid		*fid = &osp->opd_last_used_fid;
	struct dt_object	*dto;
	int			rc;
	ENTRY;

	dto = osp_find_or_create(env, osp, &osi->osi_attr, MDD_LOV_OBJ_OSEQ);
	if (IS_ERR(dto))
		RETURN(PTR_ERR(dto));

	/* object will be released in device cleanup path */
	if (osi->osi_attr.la_size >=
	    sizeof(osi->osi_id) * (osp->opd_index + 1)) {
		osp_objseq_buf_prep(&osi->osi_lb, &osi->osi_off, &fid->f_seq,
				   osp->opd_index);
		rc = dt_record_read(env, dto, &osi->osi_lb, &osi->osi_off);
		if (rc != 0)
			GOTO(out, rc);
	} else {
		fid->f_seq = 0;
		osp_objseq_buf_prep(&osi->osi_lb, &osi->osi_off, &fid->f_seq,
				    osp->opd_index);
		rc = osp_write_local_file(env, osp, dto, &osi->osi_lb,
					  osi->osi_off);
	}
	osp->opd_last_used_seq_file = dto;
	RETURN(0);
out:
	/* object will be released in device cleanup path */
	CERROR("%s: can't initialize lov_seq: rc = %d\n",
	       osp->opd_obd->obd_name, rc);
	lu_object_put(env, &dto->do_lu);
	osp->opd_last_used_seq_file = NULL;
	RETURN(rc);
}

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
		CERROR("%s: Can not get ids %d from old objid!\n",
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

	CDEBUG(D_INFO, "%s: Init last used fid "DFID"\n",
	       osp->opd_obd->obd_name, PFID(&osp->opd_last_used_fid));
out:
	if (rc != 0) {
		if (osp->opd_last_used_oid_file != NULL) {
			lu_object_put(env, &osp->opd_last_used_oid_file->do_lu);
			osp->opd_last_used_oid_file = NULL;
		}
		if (osp->opd_last_used_seq_file != NULL) {
			lu_object_put(env, &osp->opd_last_used_seq_file->do_lu);
			osp->opd_last_used_seq_file = NULL;
		}
	}

	RETURN(rc);
}

static void osp_last_used_fini(const struct lu_env *env, struct osp_device *d)
{
	/* release last_used file */
	if (d->opd_last_used_oid_file != NULL) {
		lu_object_put(env, &d->opd_last_used_oid_file->do_lu);
		d->opd_last_used_oid_file = NULL;
	}

	if (d->opd_last_used_seq_file != NULL) {
		lu_object_put(env, &d->opd_last_used_seq_file->do_lu);
		d->opd_last_used_seq_file = NULL;
	}
}

static int osp_disconnect(struct osp_device *d)
{
	struct obd_import *imp;
	int rc = 0;

	imp = d->opd_obd->u.cli.cl_import;

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
	if (rc == -ETIMEDOUT || rc == -ENOTCONN || rc == -ESHUTDOWN)
		rc = 0;
	if (rc)
		CERROR("%s: can't disconnect: rc = %d\n",
		       d->opd_obd->obd_name, rc);

	ptlrpc_invalidate_import(imp);

	RETURN(rc);
}

static int osp_shutdown(const struct lu_env *env, struct osp_device *d)
{
	int			 rc = 0;
	ENTRY;

	LASSERT(env);

	rc = osp_disconnect(d);

	if (!d->opd_connect_mdt) {
		/* stop precreate thread */
		osp_precreate_fini(d);

		/* stop sync thread */
		osp_sync_fini(d);

		/* release last_used file */
		osp_last_used_fini(env, d);
	}

	obd_fid_fini(d->opd_obd);

	RETURN(rc);
}

static int osp_process_config(const struct lu_env *env,
			      struct lu_device *dev, struct lustre_cfg *lcfg)
{
	struct osp_device		*d = lu2osp_dev(dev);
	struct lprocfs_static_vars	 lvars = { 0 };
	int				 rc;

	ENTRY;

	switch (lcfg->lcfg_command) {
	case LCFG_PRE_CLEANUP:
		rc = osp_disconnect(d);
		break;
	case LCFG_CLEANUP:
		lu_dev_del_linkage(dev->ld_site, dev);
		rc = osp_shutdown(env, d);
		break;
	case LCFG_PARAM:
		lprocfs_osp_init_vars(&lvars);

		LASSERT(d->opd_obd);
		rc = class_process_proc_param(PARAM_OSC, lvars.obd_vars,
					      lcfg, d->opd_obd);
		if (rc > 0)
			rc = 0;
		if (rc == -ENOSYS) {
			/* class_process_proc_param() haven't found matching
			 * parameter and returned ENOSYS so that layer(s)
			 * below could use that. But OSP is the bottom, so
			 * just ignore it */
			CERROR("%s: unknown param %s\n",
			       (char *)lustre_cfg_string(lcfg, 0),
			       (char *)lustre_cfg_string(lcfg, 1));
			rc = 0;
		}
		break;
	default:
		CERROR("%s: unknown command %u\n",
		       (char *)lustre_cfg_string(lcfg, 0), lcfg->lcfg_command);
		rc = 0;
		break;
	}

	RETURN(rc);
}

static int osp_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	struct osp_device	*osp = lu2osp_dev(dev);
	int			 rc = 0;

	ENTRY;
	osp->opd_recovery_completed = 1;
	if (!osp->opd_connect_mdt)
		wake_up(&osp->opd_pre_waitq);
	RETURN(rc);
}

const struct lu_device_operations osp_lu_ops = {
	.ldo_object_alloc	= osp_object_alloc,
	.ldo_process_config	= osp_process_config,
	.ldo_recovery_complete	= osp_recovery_complete,
};

/**
 * provides with statfs from corresponded OST
 *
 */
static int osp_statfs(const struct lu_env *env, struct dt_device *dev,
		      struct obd_statfs *sfs)
{
	struct osp_device *d = dt2osp_dev(dev);

	ENTRY;

	if (unlikely(d->opd_imp_active == 0))
		RETURN(-ENOTCONN);

	/* return recently updated data */
	*sfs = d->opd_statfs;

	/*
	 * layer above osp (usually lod) can use ffree to estimate
	 * how many objects are available for immediate creation
	 */

	spin_lock(&d->opd_pre_lock);
	LASSERTF(fid_seq(&d->opd_pre_last_created_fid) ==
		 fid_seq(&d->opd_pre_used_fid),
		 "last_created "DFID", next_fid "DFID"\n",
		 PFID(&d->opd_pre_last_created_fid),
		 PFID(&d->opd_pre_used_fid));
	sfs->os_fprecreated = fid_oid(&d->opd_pre_last_created_fid) -
			      fid_oid(&d->opd_pre_used_fid);
	sfs->os_fprecreated -= d->opd_pre_reserved;
	spin_unlock(&d->opd_pre_lock);

	LASSERT(sfs->os_fprecreated <= OST_MAX_PRECREATE * 2);

	CDEBUG(D_OTHER, "%s: "LPU64" blocks, "LPU64" free, "LPU64" avail, "
	       LPU64" files, "LPU64" free files\n", d->opd_obd->obd_name,
	       sfs->os_blocks, sfs->os_bfree, sfs->os_bavail,
	       sfs->os_files, sfs->os_ffree);
	RETURN(0);
}

static int osp_sync(const struct lu_env *env, struct dt_device *dev)
{
	ENTRY;

	/*
	 * XXX: wake up sync thread, command it to start flushing asap?
	 */

	RETURN(0);
}

const struct dt_device_operations osp_dt_ops = {
	.dt_statfs	= osp_statfs,
	.dt_sync	= osp_sync,
	.dt_trans_start = osp_trans_start,
	.dt_trans_stop  = osp_trans_stop,
};

static int osp_connect_to_osd(const struct lu_env *env, struct osp_device *m,
			      const char *nextdev)
{
	struct obd_connect_data	*data = NULL;
	struct obd_device	*obd;
	int			 rc;

	ENTRY;

	LASSERT(m->opd_storage_exp == NULL);

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		RETURN(-ENOMEM);

	obd = class_name2obd(nextdev);
	if (obd == NULL) {
		CERROR("%s: can't locate next device: %s\n",
		       m->opd_obd->obd_name, nextdev);
		GOTO(out, rc = -ENOTCONN);
	}

	rc = obd_connect(env, &m->opd_storage_exp, obd, &obd->obd_uuid, data,
			 NULL);
	if (rc) {
		CERROR("%s: cannot connect to next dev %s: rc = %d\n",
		       m->opd_obd->obd_name, nextdev, rc);
		GOTO(out, rc);
	}

	m->opd_dt_dev.dd_lu_dev.ld_site =
		m->opd_storage_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(m->opd_dt_dev.dd_lu_dev.ld_site);
	m->opd_storage = lu2dt_dev(m->opd_storage_exp->exp_obd->obd_lu_dev);

out:
	OBD_FREE_PTR(data);
	RETURN(rc);
}

static int osp_init0(const struct lu_env *env, struct osp_device *m,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	struct obd_device	*obd;
	struct obd_import	*imp;
	class_uuid_t		uuid;
	char			*src, *tgt, *mdt, *osdname = NULL;
	int			rc;
	long                    idx;

	ENTRY;

	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (obd == NULL) {
		CERROR("Cannot find obd with name %s\n",
		       lustre_cfg_string(cfg, 0));
		RETURN(-ENODEV);
	}
	m->opd_obd = obd;

	/* There is no record in the MDT configuration for the local disk
	 * device, so we have to extract this from elsewhere in the profile.
	 * The only information we get at setup is from the OSC records:
	 * setup 0:{fsname}-OSTxxxx-osc[-MDTxxxx] 1:lustre-OST0000_UUID 2:NID
	 * Note that 1.8 generated configs are missing the -MDTxxxx part.
	 * We need to reconstruct the name of the underlying OSD from this:
	 * {fsname}-{svname}-osd, for example "lustre-MDT0000-osd".  We
	 * also need to determine the OST index from this - will be used
	 * to calculate the offset in shared lov_objids file later */

	src = lustre_cfg_string(cfg, 0);
	if (src == NULL)
		RETURN(-EINVAL);

	tgt = strrchr(src, '-');
	if (tgt == NULL) {
		CERROR("%s: invalid target name %s\n",
		       m->opd_obd->obd_name, lustre_cfg_string(cfg, 0));
		RETURN(-EINVAL);
	}

	if (strncmp(tgt, "-osc", 4) == 0) {
		/* Old OSC name fsname-OSTXXXX-osc */
		for (tgt--; tgt > src && *tgt != '-'; tgt--)
			;
		if (tgt == src) {
			CERROR("%s: invalid target name %s\n",
			       m->opd_obd->obd_name, lustre_cfg_string(cfg, 0));
			RETURN(-EINVAL);
		}

		if (strncmp(tgt, "-OST", 4) != 0) {
			CERROR("%s: invalid target name %s\n",
			       m->opd_obd->obd_name, lustre_cfg_string(cfg, 0));
			RETURN(-EINVAL);
		}

		idx = simple_strtol(tgt + 4, &mdt, 16);
		if (mdt[0] != '-' || idx > INT_MAX || idx < 0) {
			CERROR("%s: invalid OST index in '%s'\n",
			       m->opd_obd->obd_name, src);
			RETURN(-EINVAL);
		}
		m->opd_index = idx;
		m->opd_group = 0;
		idx = tgt - src;
	} else {
		/* New OSC name fsname-OSTXXXX-osc-MDTXXXX */
		if (strncmp(tgt, "-MDT", 4) != 0 &&
		    strncmp(tgt, "-OST", 4) != 0) {
			CERROR("%s: invalid target name %s\n",
			       m->opd_obd->obd_name, lustre_cfg_string(cfg, 0));
			RETURN(-EINVAL);
		}

		idx = simple_strtol(tgt + 4, &mdt, 16);
		if (*mdt != '\0' || idx > INT_MAX || idx < 0) {
			CERROR("%s: invalid OST index in '%s'\n",
			       m->opd_obd->obd_name, src);
			RETURN(-EINVAL);
		}

		/* Get MDT index from the name and set it to opd_group,
		 * which will be used by OSP to connect with OST */
		m->opd_group = idx;
		if (tgt - src <= 12) {
			CERROR("%s: invalid mdt index retrieve from %s\n",
			       m->opd_obd->obd_name, lustre_cfg_string(cfg, 0));
			RETURN(-EINVAL);
		}

		if (strncmp(tgt - 12, "-MDT", 4) == 0)
			m->opd_connect_mdt = 1;

		idx = simple_strtol(tgt - 8, &mdt, 16);
		if (mdt[0] != '-' || idx > INT_MAX || idx < 0) {
			CERROR("%s: invalid OST index in '%s'\n",
			       m->opd_obd->obd_name, src);
			RETURN(-EINVAL);
		}

		m->opd_index = idx;
		idx = tgt - src - 12;
	}
	/* check the fsname length, and after this everything else will fit */
	if (idx > MTI_NAME_MAXLEN) {
		CERROR("%s: fsname too long in '%s'\n",
		       m->opd_obd->obd_name, src);
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

	if (m->opd_connect_mdt) {
		struct client_obd *cli = &m->opd_obd->u.cli;

		OBD_ALLOC(cli->cl_rpc_lock, sizeof(*cli->cl_rpc_lock));
		if (!cli->cl_rpc_lock)
			GOTO(out_fini, rc = -ENOMEM);
		osp_init_rpc_lock(cli->cl_rpc_lock);
	}

	m->opd_dt_dev.dd_lu_dev.ld_ops = &osp_lu_ops;
	m->opd_dt_dev.dd_ops = &osp_dt_ops;
	obd->obd_lu_dev = &m->opd_dt_dev.dd_lu_dev;

	rc = osp_connect_to_osd(env, m, osdname);
	if (rc)
		GOTO(out_fini, rc);

	rc = ptlrpcd_addref();
	if (rc)
		GOTO(out_disconnect, rc);

	rc = client_obd_setup(obd, cfg);
	if (rc) {
		CERROR("%s: can't setup obd: %d\n", m->opd_obd->obd_name, rc);
		GOTO(out_ref, rc);
	}

	osp_lprocfs_init(m);

	if (!m->opd_connect_mdt) {
		/* Initialize last id from the storage - will be
		 * used in orphan cleanup. */
		rc = osp_last_used_init(env, m);
		if (rc)
			GOTO(out_proc, rc);

		rc = obd_fid_init(m->opd_obd, NULL, LUSTRE_SEQ_DATA);
		if (rc) {
			CERROR("%s: fid init error: rc = %d\n",
			       m->opd_obd->obd_name, rc);
			GOTO(out_last_used, rc);
		}

		/* Initialize precreation thread, it handles new
		 * connections as well. */
		rc = osp_init_precreate(m);
		if (rc)
			GOTO(out_last_used, rc);
		/*
		 * Initialize synhronization mechanism taking
		 * care of propogating changes to OST in near
		 * transactional manner.
		 */
		rc = osp_sync_init(env, m);
		if (rc)
			GOTO(out_precreat, rc);

	}
	/*
	 * Initiate connect to OST
	 */
	ll_generate_random_uuid(uuid);
	class_uuid_unparse(uuid, &m->opd_cluuid);

	imp = obd->u.cli.cl_import;

	rc = ptlrpc_init_import(imp);
	if (rc)
		GOTO(out, rc);
	if (osdname)
		OBD_FREE(osdname, MAX_OBD_NAME);
	RETURN(0);

out:
	if (!m->opd_connect_mdt)
		/* stop sync thread */
		osp_sync_fini(m);
out_precreat:
	/* stop precreate thread */
	if (!m->opd_connect_mdt)
		osp_precreate_fini(m);
out_last_used:
	if (!m->opd_connect_mdt)
		osp_last_used_fini(env, m);
out_proc:
	ptlrpc_lprocfs_unregister_obd(obd);
	lprocfs_obd_cleanup(obd);
	obd_cleanup_client_import(obd);
	if (m->opd_symlink)
		lprocfs_remove(&m->opd_symlink);
	client_obd_cleanup(obd);
out_ref:
	ptlrpcd_decref();
out_disconnect:
	if (m->opd_connect_mdt) {
		struct client_obd *cli = &m->opd_obd->u.cli;
		if (cli->cl_rpc_lock != NULL) {
			OBD_FREE_PTR(cli->cl_rpc_lock);
			cli->cl_rpc_lock = NULL;
		}
	}
	obd_disconnect(m->opd_storage_exp);
out_fini:
	if (osdname)
		OBD_FREE(osdname, MAX_OBD_NAME);
	RETURN(rc);
}

static struct lu_device *osp_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct osp_device *m = lu2osp_dev(lu);

	ENTRY;

	if (cfs_atomic_read(&lu->ld_ref) && lu->ld_site) {
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_ERROR, NULL);
		lu_site_print(env, lu->ld_site, &msgdata, lu_cdebug_printer);
	}
	dt_device_fini(&m->opd_dt_dev);
	OBD_FREE_PTR(m);
	RETURN(NULL);
}

static struct lu_device *osp_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *lcfg)
{
	struct osp_device *m;
	struct lu_device  *l;

	OBD_ALLOC_PTR(m);
	if (m == NULL) {
		l = ERR_PTR(-ENOMEM);
	} else {
		int rc;

		l = osp2lu_dev(m);
		dt_device_init(&m->opd_dt_dev, t);
		rc = osp_init0(env, m, t, lcfg);
		if (rc != 0) {
			osp_device_free(env, l);
			l = ERR_PTR(rc);
		}
	}
	return l;
}

static struct lu_device *osp_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct osp_device *m = lu2osp_dev(d);
	struct obd_import *imp;
	int                rc;

	ENTRY;

	if (m->opd_storage_exp)
		obd_disconnect(m->opd_storage_exp);

	imp = m->opd_obd->u.cli.cl_import;

	if (imp->imp_rq_pool) {
		ptlrpc_free_rq_pool(imp->imp_rq_pool);
		imp->imp_rq_pool = NULL;
	}

	obd_cleanup_client_import(m->opd_obd);

	if (m->opd_symlink)
		lprocfs_remove(&m->opd_symlink);

	LASSERT(m->opd_obd);
	ptlrpc_lprocfs_unregister_obd(m->opd_obd);
	lprocfs_obd_cleanup(m->opd_obd);

	if (m->opd_connect_mdt) {
		struct client_obd *cli = &m->opd_obd->u.cli;
		if (cli->cl_rpc_lock != NULL) {
			OBD_FREE_PTR(cli->cl_rpc_lock);
			cli->cl_rpc_lock = NULL;
		}
	}

	rc = client_obd_cleanup(m->opd_obd);
	LASSERTF(rc == 0, "error %d\n", rc);

	ptlrpcd_decref();

	RETURN(NULL);
}

static int osp_reconnect(const struct lu_env *env,
			 struct obd_export *exp, struct obd_device *obd,
			 struct obd_uuid *cluuid,
			 struct obd_connect_data *data,
			 void *localdata)
{
	return 0;
}

static void osp_prepare_fid_client(struct osp_device *osp)
{
	LASSERT(osp->opd_obd->u.cli.cl_seq != NULL);
	if (osp->opd_obd->u.cli.cl_seq->lcs_exp != NULL)
		return;

	LASSERT(osp->opd_exp != NULL);
	osp->opd_obd->u.cli.cl_seq->lcs_exp =
				class_export_get(osp->opd_exp);
}

/*
 * we use exports to track all LOD users
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

	ocd->ocd_version = LUSTRE_VERSION_CODE;
	ocd->ocd_index = data->ocd_index;
	imp->imp_connect_flags_orig = ocd->ocd_connect_flags;

	rc = ptlrpc_connect_import(imp);
	if (rc) {
		CERROR("%s: can't connect obd: rc = %d\n", obd->obd_name, rc);
		GOTO(out, rc);
	}

	ptlrpc_pinger_add_import(imp);

	if (osp->opd_connect_mdt && data->ocd_index == 0) {
		/* set seq controller export for MDC0 if exists */
		struct seq_server_site *ss;

		ss = lu_site2seq(osp2lu_dev(osp)->ld_site);
		ss->ss_control_exp = class_export_get(*exp);
		ss->ss_server_fld->lsf_control_exp = *exp;
	}
out:
	RETURN(rc);
}

/*
 * once last export (we don't count self-export) disappeared
 * osp can be released
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

/*
 * lprocfs helpers still use OBD API, let's keep obd_statfs() support
 */
static int osp_obd_statfs(const struct lu_env *env, struct obd_export *exp,
			  struct obd_statfs *osfs, __u64 max_age, __u32 flags)
{
	struct obd_statfs	*msfs;
	struct ptlrpc_request	*req;
	struct obd_import	*imp = NULL;
	int			 rc;

	ENTRY;

	/* Since the request might also come from lprocfs, so we need
	 * sync this with client_disconnect_export Bug15684 */
	down_read(&exp->exp_obd->u.cli.cl_sem);
	if (exp->exp_obd->u.cli.cl_import)
		imp = class_import_get(exp->exp_obd->u.cli.cl_import);
	up_read(&exp->exp_obd->u.cli.cl_sem);
	if (!imp)
		RETURN(-ENODEV);

	/* We could possibly pass max_age in the request (as an absolute
	 * timestamp or a "seconds.usec ago") so the target can avoid doing
	 * extra calls into the filesystem if that isn't necessary (e.g.
	 * during mount that would help a bit).  Having relative timestamps
	 * is not so great if request processing is slow, while absolute
	 * timestamps are not ideal because they need time synchronization. */
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

static int osp_import_event(struct obd_device *obd, struct obd_import *imp,
			    enum obd_import_event event)
{
	struct osp_device *d = lu2osp_dev(obd->obd_lu_dev);

	switch (event) {
	case IMP_EVENT_DISCON:
		d->opd_got_disconnected = 1;
		d->opd_imp_connected = 0;
		if (d->opd_connect_mdt)
			break;
		osp_pre_update_status(d, -ENODEV);
		wake_up(&d->opd_pre_waitq);
		CDEBUG(D_HA, "got disconnected\n");
		break;
	case IMP_EVENT_INACTIVE:
		d->opd_imp_active = 0;
		if (d->opd_connect_mdt)
			break;
		osp_pre_update_status(d, -ENODEV);
		wake_up(&d->opd_pre_waitq);
		CDEBUG(D_HA, "got inactive\n");
		break;
	case IMP_EVENT_ACTIVE:
		d->opd_imp_active = 1;

		if (d->opd_got_disconnected)
			d->opd_new_connection = 1;
		d->opd_imp_connected = 1;
		d->opd_imp_seen_connected = 1;
		if (d->opd_connect_mdt)
			break;

		osp_prepare_fid_client(d);

		wake_up(&d->opd_pre_waitq);
		__osp_sync_check_for_work(d);
		CDEBUG(D_HA, "got connected\n");
		break;
	case IMP_EVENT_INVALIDATE:
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

static int osp_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
			 void *karg, void *uarg)
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
		CERROR("%s: can't get module. Is it alive?", obd->obd_name);
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
	case OBD_IOC_PING_TARGET:
		rc = ptlrpc_obd_ping(obd);
		break;
	default:
		CERROR("%s: unrecognized ioctl %#x by %s\n", obd->obd_name,
		       cmd, current_comm());
		rc = -ENOTTY;
	}
	module_put(THIS_MODULE);
	return rc;
}

static int osp_obd_get_info(const struct lu_env *env, struct obd_export *exp,
			    __u32 keylen, void *key, __u32 *vallen, void *val,
			    struct lov_stripe_md *lsm)
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

static struct lu_device_type_operations osp_device_type_ops = {
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
	.ldt_ctx_tags = LCT_MD_THREAD
};

static struct obd_ops osp_obd_device_ops = {
	.o_owner	= THIS_MODULE,
	.o_add_conn	= client_import_add_conn,
	.o_del_conn	= client_import_del_conn,
	.o_reconnect	= osp_reconnect,
	.o_connect	= osp_obd_connect,
	.o_disconnect	= osp_obd_disconnect,
	.o_get_info     = osp_obd_get_info,
	.o_import_event	= osp_import_event,
	.o_iocontrol	= osp_iocontrol,
	.o_statfs	= osp_obd_statfs,
	.o_fid_init	= client_fid_init,
	.o_fid_fini	= client_fid_fini,
};

struct llog_operations osp_mds_ost_orig_logops;

static int __init osp_mod_init(void)
{
	struct lprocfs_static_vars	 lvars;
	cfs_proc_dir_entry_t		*osc_proc_dir;
	int				 rc;

	rc = lu_kmem_init(osp_caches);
	if (rc)
		return rc;

	lprocfs_osp_init_vars(&lvars);

	rc = class_register_type(&osp_obd_device_ops, NULL, lvars.module_vars,
				 LUSTRE_OSP_NAME, &osp_device_type);

	/* create "osc" entry in procfs for compatibility purposes */
	if (rc != 0) {
		lu_kmem_fini(osp_caches);
		return rc;
	}

	lprocfs_lwp_init_vars(&lvars);

	rc = class_register_type(&lwp_obd_device_ops, NULL, lvars.module_vars,
				 LUSTRE_LWP_NAME, &lwp_device_type);
	if (rc != 0) {
		class_unregister_type(LUSTRE_OSP_NAME);
		lu_kmem_fini(osp_caches);
		return rc;
	}

	/* Note: add_rec/delcare_add_rec will be only used by catalogs */
	osp_mds_ost_orig_logops = llog_osd_ops;
	osp_mds_ost_orig_logops.lop_add = llog_cat_add_rec;
	osp_mds_ost_orig_logops.lop_declare_add = llog_cat_declare_add_rec;

	osc_proc_dir = lprocfs_srch(proc_lustre_root, "osc");
	if (osc_proc_dir == NULL) {
		osc_proc_dir = lprocfs_register("osc", proc_lustre_root, NULL,
						NULL);
		if (IS_ERR(osc_proc_dir))
			CERROR("osp: can't create compat entry \"osc\": %d\n",
			       (int) PTR_ERR(osc_proc_dir));
	}
	return rc;
}

static void __exit osp_mod_exit(void)
{
	lprocfs_try_remove_proc_entry("osc", proc_lustre_root);

	class_unregister_type(LUSTRE_LWP_NAME);
	class_unregister_type(LUSTRE_OSP_NAME);
	lu_kmem_fini(osp_caches);
}

MODULE_AUTHOR("Intel, Inc. <http://www.intel.com/>");
MODULE_DESCRIPTION("Lustre OST Proxy Device ("LUSTRE_OSP_NAME")");
MODULE_LICENSE("GPL");

cfs_module(osp, LUSTRE_VERSION_STRING, osp_mod_init, osp_mod_exit);
