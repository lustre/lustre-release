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
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lod/lod_dev.c
 *
 * Lustre Logical Object Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <lustre_param.h>

#include "lod_internal.h"

/**
 * Lookup MDT/OST index \a tgt by FID \a fid.
 *
 * \param lod LOD to be lookup at.
 * \param fid FID of object to find MDT/OST.
 * \param tgt MDT/OST index to return.
 * \param flags indidcate the FID is on MDS or OST.
 **/
int lod_fld_lookup(const struct lu_env *env, struct lod_device *lod,
		   const struct lu_fid *fid, __u32 *tgt, int flags)
{
	struct lu_seq_range	range;
	struct lu_server_fld	*server_fld;
	int rc = 0;
	ENTRY;

	LASSERTF(fid_is_sane(fid), "Invalid FID "DFID"\n", PFID(fid));
	if (fid_is_idif(fid)) {
		*tgt = fid_idif_ost_idx(fid);
		RETURN(rc);
	}

	if (!lod->lod_initialized || !fid_is_norm(fid)) {
		LASSERT(lu_site2seq(lod2lu_dev(lod)->ld_site) != NULL);
		*tgt = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
		RETURN(rc);
	}

	server_fld = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_server_fld;
	range.lsr_flags = flags;
	rc = fld_server_lookup(env, server_fld, fid_seq(fid), &range);
	if (rc) {
		CERROR("%s: Can't find tgt by seq "LPX64", rc %d\n",
		       lod2obd(lod)->obd_name, fid_seq(fid), rc);
		RETURN(rc);
	}

	*tgt = range.lsr_index;

	CDEBUG(D_INFO, "LOD: got tgt %x for sequence: "
	       LPX64"\n", *tgt, fid_seq(fid));

	RETURN(rc);
}

extern struct lu_object_operations lod_lu_obj_ops;
extern struct dt_object_operations lod_obj_ops;

/* Slab for OSD object allocation */
cfs_mem_cache_t *lod_object_kmem;

static struct lu_kmem_descr lod_caches[] = {
	{
		.ckd_cache = &lod_object_kmem,
		.ckd_name  = "lod_obj",
		.ckd_size  = sizeof(struct lod_object)
	},
	{
		.ckd_cache = NULL
	}
};

static struct lu_device *lod_device_fini(const struct lu_env *env,
					 struct lu_device *d);

struct lu_object *lod_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *dev)
{
	struct lu_object  *lu_obj;
	struct lod_object *lo;

	OBD_SLAB_ALLOC_PTR_GFP(lo, lod_object_kmem, CFS_ALLOC_IO);
	if (lo == NULL)
		return NULL;

	lu_obj = lod2lu_obj(lo);
	dt_object_init(&lo->ldo_obj, NULL, dev);
	lo->ldo_obj.do_ops = &lod_obj_ops;
	lu_obj->lo_ops = &lod_lu_obj_ops;

	return lu_obj;
}

static int lod_process_config(const struct lu_env *env,
			      struct lu_device *dev,
			      struct lustre_cfg *lcfg)
{
	struct lod_device *lod = lu2lod_dev(dev);
	struct lu_device  *next = &lod->lod_child->dd_lu_dev;
	char		  *arg1;
	int		   rc, i;
	ENTRY;

	switch(lcfg->lcfg_command) {

	case LCFG_LOV_DEL_OBD:
	case LCFG_LOV_ADD_INA:
	case LCFG_LOV_ADD_OBD: {
		__u32 index;
		int gen;
		/* lov_modify_tgts add  0:lov_mdsA  1:osp  2:0  3:1 */
		arg1 = lustre_cfg_string(lcfg, 1);

		if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1)
			GOTO(out, rc = -EINVAL);
		if (sscanf(lustre_cfg_buf(lcfg, 3), "%d", &gen) != 1)
			GOTO(out, rc = -EINVAL);

		if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD)
			rc = lod_add_device(env, lod, arg1, index, gen, 1);
		else if (lcfg->lcfg_command == LCFG_LOV_ADD_INA)
			rc = lod_add_device(env, lod, arg1, index, gen, 0);
		else
			rc = lod_del_device(env, lod, arg1, index, gen);

		break;
	}

	case LCFG_PARAM: {
		struct lprocfs_static_vars  v = { 0 };
		struct obd_device	  *obd = lod2obd(lod);

		lprocfs_lod_init_vars(&v);

		rc = class_process_proc_param(PARAM_LOV, v.obd_vars, lcfg, obd);
		if (rc > 0)
			rc = 0;
		GOTO(out, rc);
	 }

	case LCFG_CLEANUP:
		lu_dev_del_linkage(dev->ld_site, dev);
		lod_getref(lod);
		lod_foreach_ost(lod, i) {
			struct lod_ost_desc *ost;
			ost = OST_TGT(lod, i);
			LASSERT(ost && ost->ltd_ost);
			next = &ost->ltd_ost->dd_lu_dev;
			rc = next->ld_ops->ldo_process_config(env, next, lcfg);
			if (rc)
				CERROR("%s: can't process %u: %d\n",
				       lod2obd(lod)->obd_name,
				       lcfg->lcfg_command, rc);
		}
		lod_putref(lod);

		/*
		 * do cleanup on underlying storage only when
		 * all OSPs are cleaned up, as they use that OSD as well
		 */
		next = &lod->lod_child->dd_lu_dev;
		rc = next->ld_ops->ldo_process_config(env, next, lcfg);
		if (rc)
			CERROR("%s: can't process %u: %d\n",
			       lod2obd(lod)->obd_name, lcfg->lcfg_command, rc);

		rc = obd_disconnect(lod->lod_child_exp);
		if (rc)
			CERROR("error in disconnect from storage: %d\n", rc);
		break;

	default:
	       CERROR("%s: unknown command %u\n", lod2obd(lod)->obd_name,
		      lcfg->lcfg_command);
	       rc = -EINVAL;
	       break;
	}

out:
	RETURN(rc);
}

static int lod_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	struct lod_device   *lod = lu2lod_dev(dev);
	struct lu_device    *next = &lod->lod_child->dd_lu_dev;
	struct lod_ost_desc *ost;
	int		     i, rc;
	ENTRY;

	LASSERT(lod->lod_recovery_completed == 0);
	lod->lod_recovery_completed = 1;

	rc = next->ld_ops->ldo_recovery_complete(env, next);

	lod_getref(lod);
	lod_foreach_ost(lod, i) {
		ost = OST_TGT(lod, i);
		LASSERT(ost && ost->ltd_ost);
		next = &ost->ltd_ost->dd_lu_dev;
		rc = next->ld_ops->ldo_recovery_complete(env, next);
		if (rc)
			CERROR("%s: can't complete recovery on #%d: %d\n",
			       lod2obd(lod)->obd_name, i, rc);
	}
	lod_putref(lod);

	RETURN(rc);
}

static int lod_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *cdev)
{
	struct lod_device   *lod = lu2lod_dev(cdev);
	struct lu_device    *next = &lod->lod_child->dd_lu_dev;
	int		     rc;
	ENTRY;

	rc = next->ld_ops->ldo_prepare(env, pdev, next);
	if (rc != 0) {
		CERROR("%s: prepare bottom error: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		RETURN(rc);
	}

	lod->lod_initialized = 1;

	RETURN(rc);
}

const struct lu_device_operations lod_lu_ops = {
	.ldo_object_alloc	= lod_object_alloc,
	.ldo_process_config	= lod_process_config,
	.ldo_recovery_complete	= lod_recovery_complete,
	.ldo_prepare		= lod_prepare,
};

static int lod_root_get(const struct lu_env *env,
			struct dt_device *dev, struct lu_fid *f)
{
	return dt_root_get(env, dt2lod_dev(dev)->lod_child, f);
}

static int lod_statfs(const struct lu_env *env,
		      struct dt_device *dev, struct obd_statfs *sfs)
{
	return dt_statfs(env, dt2lod_dev(dev)->lod_child, sfs);
}

static struct thandle *lod_trans_create(const struct lu_env *env,
					struct dt_device *dev)
{
	return dt_trans_create(env, dt2lod_dev(dev)->lod_child);
}

static int lod_trans_start(const struct lu_env *env, struct dt_device *dev,
			   struct thandle *th)
{
	return dt_trans_start(env, dt2lod_dev(dev)->lod_child, th);
}

static int lod_trans_stop(const struct lu_env *env, struct thandle *th)
{
	/* XXX: we don't know next device, will be fixed with DNE */
	return dt_trans_stop(env, th->th_dev, th);
}

static void lod_conf_get(const struct lu_env *env,
			 const struct dt_device *dev,
			 struct dt_device_param *param)
{
	dt_conf_get(env, dt2lod_dev((struct dt_device *)dev)->lod_child, param);
}

static int lod_sync(const struct lu_env *env, struct dt_device *dev)
{
	struct lod_device   *lod = dt2lod_dev(dev);
	struct lod_ost_desc *ost;
	int                  rc = 0, i;
	ENTRY;

	lod_getref(lod);
	lod_foreach_ost(lod, i) {
		ost = OST_TGT(lod, i);
		LASSERT(ost && ost->ltd_ost);
		rc = dt_sync(env, ost->ltd_ost);
		if (rc) {
			CERROR("%s: can't sync %u: %d\n",
			       lod2obd(lod)->obd_name, i, rc);
			break;
		}
	}
	lod_putref(lod);
	if (rc == 0)
		rc = dt_sync(env, lod->lod_child);

	RETURN(rc);
}

static int lod_ro(const struct lu_env *env, struct dt_device *dev)
{
	return dt_ro(env, dt2lod_dev(dev)->lod_child);
}

static int lod_commit_async(const struct lu_env *env, struct dt_device *dev)
{
	return dt_commit_async(env, dt2lod_dev(dev)->lod_child);
}

static int lod_init_capa_ctxt(const struct lu_env *env, struct dt_device *dev,
			      int mode, unsigned long timeout,
			      __u32 alg, struct lustre_capa_key *keys)
{
	struct dt_device *next = dt2lod_dev(dev)->lod_child;
	return dt_init_capa_ctxt(env, next, mode, timeout, alg, keys);
}

static const struct dt_device_operations lod_dt_ops = {
	.dt_root_get         = lod_root_get,
	.dt_statfs           = lod_statfs,
	.dt_trans_create     = lod_trans_create,
	.dt_trans_start      = lod_trans_start,
	.dt_trans_stop       = lod_trans_stop,
	.dt_conf_get         = lod_conf_get,
	.dt_sync             = lod_sync,
	.dt_ro               = lod_ro,
	.dt_commit_async     = lod_commit_async,
	.dt_init_capa_ctxt   = lod_init_capa_ctxt,
};

static int lod_connect_to_osd(const struct lu_env *env, struct lod_device *lod,
			      struct lustre_cfg *cfg)
{
	struct obd_connect_data *data = NULL;
	struct obd_device	*obd;
	char			*nextdev = NULL, *p, *s;
	int			 rc, len = 0;
	ENTRY;

	LASSERT(cfg);
	LASSERT(lod->lod_child_exp == NULL);

	/* compatibility hack: we still use old config logs
	 * which specify LOV, but we need to learn underlying
	 * OSD device, which is supposed to be:
	 *  <fsname>-MDTxxxx-osd
	 *
	 * 2.x MGS generates lines like the following:
	 *   #03 (176)lov_setup 0:lustre-MDT0000-mdtlov  1:(struct lov_desc)
	 * 1.8 MGS generates lines like the following:
	 *   #03 (168)lov_setup 0:lustre-mdtlov  1:(struct lov_desc)
	 *
	 * we use "-MDT" to differentiate 2.x from 1.8 */

	if ((p = lustre_cfg_string(cfg, 0)) && strstr(p, "-mdtlov")) {
		len = strlen(p) + 1;
		OBD_ALLOC(nextdev, len);
		if (nextdev == NULL)
			GOTO(out, rc = -ENOMEM);

		strcpy(nextdev, p);
		s = strstr(nextdev, "-mdtlov");
		if (unlikely(s == NULL)) {
			CERROR("unable to parse device name %s\n",
			       lustre_cfg_string(cfg, 0));
			GOTO(out, rc = -EINVAL);
		}

		if (strstr(nextdev, "-MDT")) {
			/* 2.x config */
			strcpy(s, "-osd");
		} else {
			/* 1.8 config */
			strcpy(s, "-MDT0000-osd");
		}
	} else {
		CERROR("unable to parse device name %s\n",
		       lustre_cfg_string(cfg, 0));
		GOTO(out, rc = -EINVAL);
	}

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		GOTO(out, rc = -ENOMEM);

	obd = class_name2obd(nextdev);
	if (obd == NULL) {
		CERROR("can not locate next device: %s\n", nextdev);
		GOTO(out, rc = -ENOTCONN);
	}

	data->ocd_connect_flags = OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;

	rc = obd_connect(env, &lod->lod_child_exp, obd, &obd->obd_uuid,
			 data, NULL);
	if (rc) {
		CERROR("cannot connect to next dev %s (%d)\n", nextdev, rc);
		GOTO(out, rc);
	}

	lod->lod_dt_dev.dd_lu_dev.ld_site =
		lod->lod_child_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(lod->lod_dt_dev.dd_lu_dev.ld_site);
	lod->lod_child = lu2dt_dev(lod->lod_child_exp->exp_obd->obd_lu_dev);

out:
	if (data)
		OBD_FREE_PTR(data);
	if (nextdev)
		OBD_FREE(nextdev, len);
	RETURN(rc);
}

static int lod_init0(const struct lu_env *env, struct lod_device *lod,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	struct dt_device_param ddp;
	struct obd_device     *obd;
	int		       rc;
	ENTRY;

	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (obd == NULL) {
		CERROR("Cannot find obd with name %s\n",
		       lustre_cfg_string(cfg, 0));
		RETURN(-ENODEV);
	}

	obd->obd_lu_dev = &lod->lod_dt_dev.dd_lu_dev;
	lod->lod_dt_dev.dd_lu_dev.ld_obd = obd;
	lod->lod_dt_dev.dd_lu_dev.ld_ops = &lod_lu_ops;
	lod->lod_dt_dev.dd_ops = &lod_dt_ops;

	rc = lod_connect_to_osd(env, lod, cfg);
	if (rc)
		RETURN(rc);

	dt_conf_get(env, &lod->lod_dt_dev, &ddp);
	lod->lod_osd_max_easize = ddp.ddp_max_ea_size;

	/* setup obd to be used with old lov code */
	rc = lod_pools_init(lod, cfg);
	if (rc)
		GOTO(out_disconnect, rc);

	rc = lod_procfs_init(lod);
	if (rc)
		GOTO(out_pools, rc);

	mutex_init(&lod->lod_mutex);
	init_rwsem(&lod->lod_rw_sem);
	spin_lock_init(&lod->lod_desc_lock);

	RETURN(0);

out_pools:
	lod_pools_fini(lod);
out_disconnect:
	obd_disconnect(lod->lod_child_exp);
	RETURN(rc);
}

static struct lu_device *lod_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct lod_device *lod = lu2lod_dev(lu);
	struct lu_device  *next = &lod->lod_child->dd_lu_dev;
	ENTRY;

	LASSERT(cfs_atomic_read(&lu->ld_ref) == 0);
	dt_device_fini(&lod->lod_dt_dev);
	OBD_FREE_PTR(lod);
	RETURN(next);
}

static struct lu_device *lod_device_alloc(const struct lu_env *env,
					  struct lu_device_type *type,
					  struct lustre_cfg *lcfg)
{
	struct lod_device *lod;
	struct lu_device  *lu_dev;

	OBD_ALLOC_PTR(lod);
	if (lod == NULL) {
		lu_dev = ERR_PTR(-ENOMEM);
	} else {
		int rc;

		lu_dev = lod2lu_dev(lod);
		dt_device_init(&lod->lod_dt_dev, type);
		rc = lod_init0(env, lod, type, lcfg);
		if (rc != 0) {
			lod_device_free(env, lu_dev);
			lu_dev = ERR_PTR(rc);
		}
	}

	return lu_dev;
}

static struct lu_device *lod_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct lod_device *lod = lu2lod_dev(d);
	ENTRY;

	lod_pools_fini(lod);

	lod_procfs_fini(lod);

	RETURN(NULL);
}

/*
 * we use exports to track all LOD users
 */
static int lod_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct lod_device    *lod = lu2lod_dev(obd->obd_lu_dev);
	struct lustre_handle  conn;
	int                   rc;
	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", lod->lod_connects);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	*exp = class_conn2export(&conn);

	mutex_lock(&lod->lod_mutex);
	lod->lod_connects++;
	/* at the moment we expect the only user */
	LASSERT(lod->lod_connects == 1);
	mutex_unlock(&lod->lod_mutex);

	RETURN(0);
}

/*
 * once last export (we don't count self-export) disappeared
 * lod can be released
 */
static int lod_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	int                rc, release = 0;
	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	mutex_lock(&lod->lod_mutex);
	lod->lod_connects--;
	if (lod->lod_connects != 0) {
		/* why should there be more than 1 connect? */
		mutex_unlock(&lod->lod_mutex);
		CERROR("%s: disconnect #%d\n", exp->exp_obd->obd_name,
		       lod->lod_connects);
		goto out;
	}
	mutex_unlock(&lod->lod_mutex);

	/* the last user of lod has gone, let's release the device */
	release = 1;

out:
	rc = class_disconnect(exp); /* bz 9811 */

	if (rc == 0 && release)
		class_manual_cleanup(obd);
	RETURN(rc);
}

LU_KEY_INIT(lod, struct lod_thread_info);

static void lod_key_fini(const struct lu_context *ctx,
		struct lu_context_key *key, void *data)
{
	struct lod_thread_info *info = data;
	/* allocated in lod_get_lov_ea
	 * XXX: this is overload, a tread may have such store but used only
	 * once. Probably better would be pool of such stores per LOD.
	 */
	if (info->lti_ea_store) {
		OBD_FREE_LARGE(info->lti_ea_store, info->lti_ea_store_size);
		info->lti_ea_store = NULL;
		info->lti_ea_store_size = 0;
	}
	OBD_FREE_PTR(info);
}

/* context key: lod_thread_key */
LU_CONTEXT_KEY_DEFINE(lod, LCT_MD_THREAD);

LU_TYPE_INIT_FINI(lod, &lod_thread_key);

static struct lu_device_type_operations lod_device_type_ops = {
	.ldto_init           = lod_type_init,
	.ldto_fini           = lod_type_fini,

	.ldto_start          = lod_type_start,
	.ldto_stop           = lod_type_stop,

	.ldto_device_alloc   = lod_device_alloc,
	.ldto_device_free    = lod_device_free,

	.ldto_device_fini    = lod_device_fini
};

static struct lu_device_type lod_device_type = {
	.ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_LOD_NAME,
	.ldt_ops      = &lod_device_type_ops,
	.ldt_ctx_tags = LCT_MD_THREAD,
};

static int lod_obd_health_check(const struct lu_env *env,
		struct obd_device *obd)
{
	struct lod_device   *d = lu2lod_dev(obd->obd_lu_dev);
	struct lod_ost_desc *ost;
	int                  i, rc = 1;
	ENTRY;

	LASSERT(d);
	lod_getref(d);
	lod_foreach_ost(d, i) {
		ost = OST_TGT(d, i);
		LASSERT(ost && ost->ltd_ost);
		rc = obd_health_check(env, ost->ltd_exp->exp_obd);
		/* one healthy device is enough */
		if (rc == 0)
			break;
	}
	lod_putref(d);
	RETURN(rc);
}

static struct obd_ops lod_obd_device_ops = {
	.o_owner        = THIS_MODULE,
	.o_connect      = lod_obd_connect,
	.o_disconnect   = lod_obd_disconnect,
	.o_health_check = lod_obd_health_check,
	.o_pool_new     = lod_pool_new,
	.o_pool_rem     = lod_pool_remove,
	.o_pool_add     = lod_pool_add,
	.o_pool_del     = lod_pool_del,
};

static int __init lod_mod_init(void)
{
	struct lprocfs_static_vars  lvars = { 0 };
	cfs_proc_dir_entry_t       *lov_proc_dir;
	int			    rc;

	rc = lu_kmem_init(lod_caches);
	if (rc)
		return rc;

	lprocfs_lod_init_vars(&lvars);

	rc = class_register_type(&lod_obd_device_ops, NULL, lvars.module_vars,
				 LUSTRE_LOD_NAME, &lod_device_type);
	if (rc) {
		lu_kmem_fini(lod_caches);
		return rc;
	}

	/* create "lov" entry in procfs for compatibility purposes */
	lov_proc_dir = lprocfs_srch(proc_lustre_root, "lov");
	if (lov_proc_dir == NULL) {
		lov_proc_dir = lprocfs_register("lov", proc_lustre_root,
						NULL, NULL);
		if (IS_ERR(lov_proc_dir))
			CERROR("lod: can't create compat entry \"lov\": %d\n",
			       (int)PTR_ERR(lov_proc_dir));
	}

	return rc;
}

static void __exit lod_mod_exit(void)
{

	lprocfs_try_remove_proc_entry("lov", proc_lustre_root);

	class_unregister_type(LUSTRE_LOD_NAME);
	lu_kmem_fini(lod_caches);
}

MODULE_AUTHOR("Whamcloud, Inc. <http://www.whamcloud.com/>");
MODULE_DESCRIPTION("Lustre Logical Object Device ("LUSTRE_LOD_NAME")");
MODULE_LICENSE("GPL");

module_init(lod_mod_init);
module_exit(lod_mod_exit);

