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
 * Copyright (c) 2012, 2013, Intel Corporation.
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
/**
 * The Logical Object Device (LOD) layer manages access to striped
 * objects (both regular files and directories). It implements the DT
 * device and object APIs and is responsible for creating, storing,
 * and loading striping information as an extended attribute of the
 * underlying OSD object. LOD is the server side analog of the LOV and
 * LMV layers on the client side.
 *
 * Metadata LU object stack (layers of the same compound LU object,
 * all have the same FID):
 *
 *        MDT
 *         |      MD API
 *        MDD
 *         |      DT API
 *        LOD
 *       /   \    DT API
 *     OSD   OSP
 *
 * During LOD object initialization the localness or remoteness of the
 * object FID dictates the choice between OSD and OSP.
 *
 * An LOD object (file or directory) with N stripes (each has a
 * different FID):
 *
 *          LOD
 *           |
 *   +---+---+---+...+
 *   |   |   |   |   |
 *   S0  S1  S2  S3  S(N-1)  OS[DP] objects, seen as DT objects by LOD
 *
 * When upper layers must access an object's stripes (which are
 * themselves OST or MDT LU objects) LOD finds these objects by their
 * FIDs and stores them as an array of DT object pointers on the
 * object. Declarations and operations on LOD objects are received by
 * LOD (as DT object operations) and performed on the underlying
 * OS[DP] object and (as needed) on the stripes. From the perspective
 * of LOD, a stripe-less file (created by mknod() or open with
 * O_LOV_DELAY_CREATE) is an object which does not yet have stripes,
 * while a non-striped directory (created by mkdir()) is an object
 * which will never have stripes.
 *
 * The LOD layer also implements a small subset of the OBD device API
 * to support MDT stack initialization and finalization (an MDD device
 * connects and disconnects itself to and from the underlying LOD
 * device), and pool management. In turn LOD uses the OBD device API
 * to connect it self to the underlying OSD, and to connect itself to
 * OSP devices representing the MDTs and OSTs that bear the stripes of
 * its objects.
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <lustre_param.h>
#include <lustre_update.h>

#include "lod_internal.h"

/*
 * Lookup target by FID.
 *
 * Lookup MDT/OST target index by FID. Type of the target can be
 * specific or any.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] lod		lod device
 * \param[in] fid		FID
 * \param[out] tgt		result target index
 * \param[in] type		expected type of the target:
 *				LU_SEQ_RANGE_{MDT,OST,ANY}
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
int lod_fld_lookup(const struct lu_env *env, struct lod_device *lod,
		   const struct lu_fid *fid, __u32 *tgt, int *type)
{
	struct lu_seq_range	range = { 0 };
	struct lu_server_fld	*server_fld;
	int rc = 0;
	ENTRY;

	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID"\n", lod2obd(lod)->obd_name,
		       PFID(fid));
		RETURN(-EIO);
	}

	if (fid_is_idif(fid)) {
		*tgt = fid_idif_ost_idx(fid);
		*type = LU_SEQ_RANGE_OST;
		RETURN(rc);
	}

	if (!lod->lod_initialized || (!fid_seq_in_fldb(fid_seq(fid)))) {
		LASSERT(lu_site2seq(lod2lu_dev(lod)->ld_site) != NULL);

		*tgt = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
		*type = LU_SEQ_RANGE_MDT;
		RETURN(rc);
	}

	server_fld = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_server_fld;
	fld_range_set_type(&range, *type);
	rc = fld_server_lookup(env, server_fld, fid_seq(fid), &range);
	if (rc)
		RETURN(rc);

	*tgt = range.lsr_index;
	*type = range.lsr_flags;

	CDEBUG(D_INFO, "LOD: got tgt %x for sequence: "
	       LPX64"\n", *tgt, fid_seq(fid));

	RETURN(rc);
}

extern struct lu_object_operations lod_lu_obj_ops;
extern struct dt_object_operations lod_obj_ops;

/* Slab for OSD object allocation */
struct kmem_cache *lod_object_kmem;

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

/**
 * Implementation of lu_device_operations::ldo_object_alloc() for LOD
 *
 * Allocates and initializes LOD's slice in the given object.
 *
 * see include/lu_object.h for the details.
 */
struct lu_object *lod_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *dev)
{
	struct lod_object	*lod_obj;
	struct lu_object	*lu_obj;
	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(lod_obj, lod_object_kmem, GFP_NOFS);
	if (lod_obj == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	lu_obj = lod2lu_obj(lod_obj);
	dt_object_init(&lod_obj->ldo_obj, NULL, dev);
	lod_obj->ldo_obj.do_ops = &lod_obj_ops;
	lu_obj->lo_ops = &lod_lu_obj_ops;

	RETURN(lu_obj);
}

/**
 * Cleanup table of target's descriptors.
 *
 * The function goes through all the targets in the given table
 * and apply given configuration command on to the targets.
 * Used to cleanup the targets at unmount.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] lod		lod device
 * \param[in] ltd		target's table to go through
 * \param[in] lcfg		configuration command to apply
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
static int lod_cleanup_desc_tgts(const struct lu_env *env,
				 struct lod_device *lod,
				 struct lod_tgt_descs *ltd,
				 struct lustre_cfg *lcfg)
{
	struct lu_device  *next;
	int rc = 0;
	unsigned int i;

	lod_getref(ltd);
	if (ltd->ltd_tgts_size <= 0) {
		lod_putref(lod, ltd);
		return 0;
	}
	cfs_foreach_bit(ltd->ltd_tgt_bitmap, i) {
		struct lod_tgt_desc *tgt;
		int rc1;

		tgt = LTD_TGT(ltd, i);
		LASSERT(tgt && tgt->ltd_tgt);
		next = &tgt->ltd_tgt->dd_lu_dev;
		rc1 = next->ld_ops->ldo_process_config(env, next, lcfg);
		if (rc1) {
			CERROR("%s: error cleaning up LOD index %u: cmd %#x"
			       ": rc = %d\n", lod2obd(lod)->obd_name, i,
			       lcfg->lcfg_command, rc1);
			rc = rc1;
		}
	}
	lod_putref(lod, ltd);
	return rc;
}

/**
 * Extract MDT target index from a device name.
 *
 * a helper function to extract index from the given device name
 * like "fsname-MDTxxxx-mdtlov"
 *
 * \param[in] lodname	device name
 * \param[out] index	extracted index
 *
 * \retval 0		on success
 * \retval -EINVAL	if the name is invalid
 */
static int lodname2mdt_index(char *lodname, long *index)
{
	char *ptr, *tmp;

	ptr = strrchr(lodname, '-');
	if (ptr == NULL) {
		CERROR("invalid MDT index in '%s'\n", lodname);
		return -EINVAL;
	}

	if (strncmp(ptr, "-mdtlov", 7) != 0) {
		CERROR("invalid MDT index in '%s'\n", lodname);
		return -EINVAL;
	}

	if ((unsigned long)ptr - (unsigned long)lodname <= 8) {
		CERROR("invalid MDT index in '%s'\n", lodname);
		return -EINVAL;
	}

	if (strncmp(ptr - 8, "-MDT", 4) != 0) {
		CERROR("invalid MDT index in '%s'\n", lodname);
		return -EINVAL;
	}

	*index = simple_strtol(ptr - 4, &tmp, 16);
	if (*tmp != '-' || *index > INT_MAX || *index < 0) {
		CERROR("invalid MDT index in '%s'\n", lodname);
		return -EINVAL;
	}
	return 0;
}

/**
 * Implementation of lu_device_operations::ldo_process_config() for LOD
 *
 * The method is called by the configuration subsystem during setup,
 * cleanup and when the configuration changes. The method processes
 * few specific commands like adding/removing the targets, changing
 * the runtime parameters.

 * \param[in] env		LU environment provided by the caller
 * \param[in] dev		lod device
 * \param[in] lcfg		configuration command to apply
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 *
 * The examples are below.
 *
 * Add osc config log:
 * marker  20 (flags=0x01, v2.2.49.56) lustre-OST0001  'add osc'
 * add_uuid  nid=192.168.122.162@tcp(0x20000c0a87aa2)  0:  1:nidxxx
 * attach    0:lustre-OST0001-osc-MDT0001  1:osc  2:lustre-MDT0001-mdtlov_UUID
 * setup     0:lustre-OST0001-osc-MDT0001  1:lustre-OST0001_UUID  2:nid
 * lov_modify_tgts add 0:lustre-MDT0001-mdtlov  1:lustre-OST0001_UUID  2:1  3:1
 * marker  20 (flags=0x02, v2.2.49.56) lustre-OST0001  'add osc'
 *
 * Add mdc config log:
 * marker  10 (flags=0x01, v2.2.49.56) lustre-MDT0000  'add osp'
 * add_uuid  nid=192.168.122.162@tcp(0x20000c0a87aa2)  0:  1:nid
 * attach 0:lustre-MDT0000-osp-MDT0001  1:osp  2:lustre-MDT0001-mdtlov_UUID
 * setup     0:lustre-MDT0000-osp-MDT0001  1:lustre-MDT0000_UUID  2:nid
 * modify_mdc_tgts add 0:lustre-MDT0001  1:lustre-MDT0000_UUID  2:0  3:1
 * marker  10 (flags=0x02, v2.2.49.56) lustre-MDT0000_UUID  'add osp'
 */
static int lod_process_config(const struct lu_env *env,
			      struct lu_device *dev,
			      struct lustre_cfg *lcfg)
{
	struct lod_device *lod = lu2lod_dev(dev);
	struct lu_device  *next = &lod->lod_child->dd_lu_dev;
	char		  *arg1;
	int		   rc = 0;
	ENTRY;

	switch(lcfg->lcfg_command) {
	case LCFG_LOV_DEL_OBD:
	case LCFG_LOV_ADD_INA:
	case LCFG_LOV_ADD_OBD:
	case LCFG_ADD_MDC: {
		__u32 index;
		__u32 mdt_index;
		int gen;
		/* lov_modify_tgts add  0:lov_mdsA  1:osp  2:0  3:1
		 * modify_mdc_tgts add  0:lustre-MDT0001
		 *		      1:lustre-MDT0001-mdc0002
		 *		      2:2  3:1*/
		arg1 = lustre_cfg_string(lcfg, 1);

		if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1)
			GOTO(out, rc = -EINVAL);
		if (sscanf(lustre_cfg_buf(lcfg, 3), "%d", &gen) != 1)
			GOTO(out, rc = -EINVAL);

		if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD) {
			char *mdt;
			mdt = strstr(lustre_cfg_string(lcfg, 0), "-MDT");
			/* 1.8 configs don't have "-MDT0000" at the end */
			if (mdt == NULL) {
				mdt_index = 0;
			} else {
				long long_index;
				rc = lodname2mdt_index(
					lustre_cfg_string(lcfg, 0),
					&long_index);
				if (rc != 0)
					GOTO(out, rc);
				mdt_index = long_index;
			}
			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_OSC_NAME, 1);
		} else if (lcfg->lcfg_command == LCFG_ADD_MDC) {
			mdt_index = index;
			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_MDC_NAME, 1);
		} else if (lcfg->lcfg_command == LCFG_LOV_ADD_INA) {
			/*FIXME: Add mdt_index for LCFG_LOV_ADD_INA*/
			mdt_index = 0;
			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_OSC_NAME, 0);
		} else {
			rc = lod_del_device(env, lod,
					    &lod->lod_ost_descs,
					    arg1, index, gen, true);
		}

		break;
	}

	case LCFG_PARAM: {
		struct obd_device *obd = lod2obd(lod);

		rc = class_process_proc_param(PARAM_LOV, obd->obd_vars,
					      lcfg, obd);
		if (rc > 0)
			rc = 0;
		GOTO(out, rc);
	}
	case LCFG_CLEANUP:
	case LCFG_PRE_CLEANUP: {
		lu_dev_del_linkage(dev->ld_site, dev);
		lod_cleanup_desc_tgts(env, lod, &lod->lod_mdt_descs, lcfg);
		lod_cleanup_desc_tgts(env, lod, &lod->lod_ost_descs, lcfg);
		if (lcfg->lcfg_command == LCFG_PRE_CLEANUP)
			break;
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
	}
	default:
	       CERROR("%s: unknown command %u\n", lod2obd(lod)->obd_name,
		      lcfg->lcfg_command);
	       rc = -EINVAL;
	       break;
	}

out:
	RETURN(rc);
}

/**
 * Implementation of lu_device_operations::ldo_recovery_complete() for LOD
 *
 * The method is called once the recovery is complete. This implementation
 * distributes the notification to all the known targets.
 *
 * see include/lu_object.h for the details
 */
static int lod_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	struct lod_device   *lod = lu2lod_dev(dev);
	struct lu_device    *next = &lod->lod_child->dd_lu_dev;
	unsigned int	     i;
	int		     rc;
	ENTRY;

	LASSERT(lod->lod_recovery_completed == 0);
	lod->lod_recovery_completed = 1;

	rc = next->ld_ops->ldo_recovery_complete(env, next);

	lod_getref(&lod->lod_ost_descs);
	if (lod->lod_osts_size > 0) {
		cfs_foreach_bit(lod->lod_ost_bitmap, i) {
			struct lod_tgt_desc *tgt;
			tgt = OST_TGT(lod, i);
			LASSERT(tgt && tgt->ltd_tgt);
			next = &tgt->ltd_ost->dd_lu_dev;
			rc = next->ld_ops->ldo_recovery_complete(env, next);
			if (rc)
				CERROR("%s: can't complete recovery on #%d:"
					"%d\n", lod2obd(lod)->obd_name, i, rc);
		}
	}
	lod_putref(lod, &lod->lod_ost_descs);
	RETURN(rc);
}

/**
 * Implementation of lu_device_operations::ldo_prepare() for LOD
 *
 * see include/lu_object.h for the details.
 */
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

/**
 * Implementation of dt_device_operations::dt_root_get() for LOD
 *
 * see include/dt_object.h for the details.
 */
static int lod_root_get(const struct lu_env *env,
			struct dt_device *dev, struct lu_fid *f)
{
	return dt_root_get(env, dt2lod_dev(dev)->lod_child, f);
}

/**
 * Implementation of dt_device_operations::dt_statfs() for LOD
 *
 * see include/dt_object.h for the details.
 */
static int lod_statfs(const struct lu_env *env,
		      struct dt_device *dev, struct obd_statfs *sfs)
{
	return dt_statfs(env, dt2lod_dev(dev)->lod_child, sfs);
}

/**
 * Implementation of dt_device_operations::dt_trans_create() for LOD
 *
 * Creates a transaction using local (to this node) OSD.
 *
 * see include/dt_object.h for the details.
 */
static struct thandle *lod_trans_create(const struct lu_env *env,
					struct dt_device *dev)
{
	struct thandle *th;

	th = dt_trans_create(env, dt2lod_dev(dev)->lod_child);
	if (IS_ERR(th))
		return th;

	return th;
}

/**
 * Implementation of dt_device_operations::dt_trans_start() for LOD
 *
 * Starts the set of local transactions using the targets involved
 * in declare phase. Initial support for the distributed transactions.
 *
 * see include/dt_object.h for the details.
 */
static int lod_trans_start(const struct lu_env *env, struct dt_device *dev,
			   struct thandle *th)
{
	struct lod_device *lod = dt2lod_dev((struct dt_device *) dev);
	int rc = 0;

	if (unlikely(th->th_update != NULL)) {
		struct thandle_update *tu = th->th_update;
		struct dt_update_request *update;

		list_for_each_entry(update, &tu->tu_remote_update_list,
				    dur_list) {
			LASSERT(update->dur_dt != NULL);
			rc = dt_trans_start(env, update->dur_dt, th);
			if (rc != 0)
				return rc;
		}
	}
	return dt_trans_start(env, lod->lod_child, th);
}

/**
 * Implementation of dt_device_operations::dt_trans_stop() for LOD
 *
 * Stops the set of local transactions using the targets involved
 * in declare phase. Initial support for the distributed transactions.
 *
 * see include/dt_object.h for the details.
 */
static int lod_trans_stop(const struct lu_env *env, struct dt_device *dt,
			  struct thandle *th)
{
	struct thandle_update		*tu = th->th_update;
	struct dt_update_request	*update;
	struct dt_update_request	*tmp;
	int				rc2 = 0;
	int				rc;
	ENTRY;

	rc = dt_trans_stop(env, th->th_dev, th);
	if (likely(tu == NULL))
		RETURN(rc);

	list_for_each_entry_safe(update, tmp,
				 &tu->tu_remote_update_list,
				 dur_list) {
		/* update will be freed inside dt_trans_stop */
		rc2 = dt_trans_stop(env, update->dur_dt, th);
		if (unlikely(rc2 != 0 && rc == 0))
			rc = rc2;
	}

	RETURN(rc);
}

/**
 * Implementation of dt_device_operations::dt_conf_get() for LOD
 *
 * Currently returns the configuration provided by the local OSD.
 *
 * see include/dt_object.h for the details.
 */
static void lod_conf_get(const struct lu_env *env,
			 const struct dt_device *dev,
			 struct dt_device_param *param)
{
	dt_conf_get(env, dt2lod_dev((struct dt_device *)dev)->lod_child, param);
}

/**
 * Implementation of dt_device_operations::dt_sync() for LOD
 *
 * Syncs all known OST targets. Very very expensive and used
 * rarely by LFSCK now. Should not be used in general.
 *
 * see include/dt_object.h for the details.
 */
static int lod_sync(const struct lu_env *env, struct dt_device *dev)
{
	struct lod_device   *lod = dt2lod_dev(dev);
	struct lod_ost_desc *ost;
	unsigned int         i;
	int                  rc = 0;
	ENTRY;

	lod_getref(&lod->lod_ost_descs);
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
	lod_putref(lod, &lod->lod_ost_descs);
	if (rc == 0)
		rc = dt_sync(env, lod->lod_child);

	RETURN(rc);
}

/**
 * Implementation of dt_device_operations::dt_ro() for LOD
 *
 * Turns local OSD read-only, used for the testing only.
 *
 * see include/dt_object.h for the details.
 */
static int lod_ro(const struct lu_env *env, struct dt_device *dev)
{
	return dt_ro(env, dt2lod_dev(dev)->lod_child);
}

/**
 * Implementation of dt_device_operations::dt_commit_async() for LOD
 *
 * Asks local OSD to commit sooner.
 *
 * see include/dt_object.h for the details.
 */
static int lod_commit_async(const struct lu_env *env, struct dt_device *dev)
{
	return dt_commit_async(env, dt2lod_dev(dev)->lod_child);
}

/**
 * Not used
 */
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

/**
 * Connect to a local OSD.
 *
 * Used to connect to the local OSD at mount. OSD name is taken from the
 * configuration command passed. This connection is used to identify LU
 * site and pin the OSD from early removal.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] lod		lod device
 * \param[in] cfg		configuration command to apply
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
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

/**
 * Allocate and initialize target table.
 *
 * A helper function to initialize the target table and allocate
 * a bitmap of the available targets.
 *
 * \param[in] ltd		target's table to initialize
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
static int lod_tgt_desc_init(struct lod_tgt_descs *ltd)
{
	mutex_init(&ltd->ltd_mutex);
	init_rwsem(&ltd->ltd_rw_sem);

	/* the OST array and bitmap are allocated/grown dynamically as OSTs are
	 * added to the LOD, see lod_add_device() */
	ltd->ltd_tgt_bitmap = CFS_ALLOCATE_BITMAP(32);
	if (ltd->ltd_tgt_bitmap == NULL)
		RETURN(-ENOMEM);

	ltd->ltd_tgts_size  = 32;
	ltd->ltd_tgtnr      = 0;

	ltd->ltd_death_row = 0;
	ltd->ltd_refcount  = 0;
	return 0;
}

/**
 * Initialize LOD device at setup.
 *
 * Initializes the given LOD device using the original configuration command.
 * The function initiates a connection to the local OSD and initializes few
 * internal structures like pools, target tables, etc.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] lod		lod device
 * \param[in] ldt		not used
 * \param[in] cfg		configuration command
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
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

	spin_lock_init(&lod->lod_desc_lock);
	spin_lock_init(&lod->lod_connects_lock);
	lod_tgt_desc_init(&lod->lod_mdt_descs);
	lod_tgt_desc_init(&lod->lod_ost_descs);

	RETURN(0);

out_pools:
	lod_pools_fini(lod);
out_disconnect:
	obd_disconnect(lod->lod_child_exp);
	RETURN(rc);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_free() for LOD
 *
 * Releases the memory allocated for LOD device.
 *
 * see include/lu_object.h for the details.
 */
static struct lu_device *lod_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct lod_device *lod = lu2lod_dev(lu);
	struct lu_device  *next = &lod->lod_child->dd_lu_dev;
	ENTRY;

	LASSERT(atomic_read(&lu->ld_ref) == 0);
	dt_device_fini(&lod->lod_dt_dev);
	OBD_FREE_PTR(lod);
	RETURN(next);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_alloc() for LOD
 *
 * Allocates LOD device and calls the helpers to initialize it.
 *
 * see include/lu_object.h for the details.
 */
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

/**
 * Implementation of lu_device_type_operations::ldto_device_fini() for LOD
 *
 * Releases the internal resources used by LOD device.
 *
 * see include/lu_object.h for the details.
 */
static struct lu_device *lod_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct lod_device *lod = lu2lod_dev(d);
	int		   rc;
	ENTRY;

	lod_pools_fini(lod);

	lod_procfs_fini(lod);

	rc = lod_fini_tgt(env, lod, &lod->lod_ost_descs, true);
	if (rc)
		CERROR("%s:can not fini ost descs %d\n",
			lod2obd(lod)->obd_name, rc);

	rc = lod_fini_tgt(env, lod, &lod->lod_mdt_descs, false);
	if (rc)
		CERROR("%s:can not fini mdt descs %d\n",
			lod2obd(lod)->obd_name, rc);

	RETURN(NULL);
}

/**
 * Implementation of obd_ops::o_connect() for LOD
 *
 * Used to track all the users of this specific LOD device,
 * so the device stays up until the last user disconnected.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[out] exp		export the caller will be using to access LOD
 * \param[in] obd		OBD device representing LOD device
 * \param[in] cluuid		unique identifier of the caller
 * \param[in] data		not used
 * \param[in] localdata		not used
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
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

	spin_lock(&lod->lod_connects_lock);
	lod->lod_connects++;
	/* at the moment we expect the only user */
	LASSERT(lod->lod_connects == 1);
	spin_unlock(&lod->lod_connects_lock);

	RETURN(0);
}

/**
 *
 * Implementation of obd_ops::o_disconnect() for LOD
 *
 * When the caller doesn't need to use this LOD instance, it calls
 * obd_disconnect() and LOD releases corresponding export/reference count.
 * Once all the users gone, LOD device is released.
 *
 * \param[in] exp		export provided to the caller in obd_connect()
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
static int lod_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	int                rc, release = 0;
	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	spin_lock(&lod->lod_connects_lock);
	lod->lod_connects--;
	if (lod->lod_connects != 0) {
		/* why should there be more than 1 connect? */
		spin_unlock(&lod->lod_connects_lock);
		CERROR("%s: disconnect #%d\n", exp->exp_obd->obd_name,
		       lod->lod_connects);
		goto out;
	}
	spin_unlock(&lod->lod_connects_lock);

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
	lu_buf_free(&info->lti_linkea_buf);
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

/**
 * Implementation of obd_ops::o_get_info() for LOD
 *
 * Currently, there is only one supported key: KEY_OSP_CONNECTED , to provide
 * the caller binary status whether LOD has seen connection to any OST target.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] exp		export of the caller
 * \param[in] keylen		len of the key
 * \param[in] key		the key
 * \param[in] vallen		not used
 * \param[in] val		not used
 * \param[in] lsm		not used
 *
 * \retval			0 if a connection was seen
 * \retval			-EAGAIN if LOD isn't running yet or no
 *				connection has been seen yet
 * \retval			-EINVAL if not supported key is requested
 **/
static int lod_obd_get_info(const struct lu_env *env, struct obd_export *exp,
			    __u32 keylen, void *key, __u32 *vallen, void *val,
			    struct lov_stripe_md *lsm)
{
	int rc = -EINVAL;

	if (KEY_IS(KEY_OSP_CONNECTED)) {
		struct obd_device	*obd = exp->exp_obd;
		struct lod_device	*d;
		struct lod_ost_desc	*ost;
		unsigned int		i;
		int			rc = 1;

		if (!obd->obd_set_up || obd->obd_stopping)
			RETURN(-EAGAIN);

		d = lu2lod_dev(obd->obd_lu_dev);
		lod_getref(&d->lod_ost_descs);
		lod_foreach_ost(d, i) {
			ost = OST_TGT(d, i);
			LASSERT(ost && ost->ltd_ost);

			rc = obd_get_info(env, ost->ltd_exp, keylen, key,
					  vallen, val, lsm);
			/* one healthy device is enough */
			if (rc == 0)
				break;
		}
		lod_putref(d, &d->lod_ost_descs);
		RETURN(rc);
	}

	RETURN(rc);
}

static struct obd_ops lod_obd_device_ops = {
	.o_owner        = THIS_MODULE,
	.o_connect      = lod_obd_connect,
	.o_disconnect   = lod_obd_disconnect,
	.o_get_info     = lod_obd_get_info,
	.o_pool_new     = lod_pool_new,
	.o_pool_rem     = lod_pool_remove,
	.o_pool_add     = lod_pool_add,
	.o_pool_del     = lod_pool_del,
};

static int __init lod_mod_init(void)
{
	struct obd_type	*type;
	int rc;

	rc = lu_kmem_init(lod_caches);
	if (rc)
		return rc;

	rc = class_register_type(&lod_obd_device_ops, NULL, true, NULL,
				 LUSTRE_LOD_NAME, &lod_device_type);
	if (rc) {
		lu_kmem_fini(lod_caches);
		return rc;
	}

	/* create "lov" entry in procfs for compatibility purposes */
	type = class_search_type(LUSTRE_LOV_NAME);
	if (type != NULL && type->typ_procroot != NULL)
		return rc;

	type = class_search_type(LUSTRE_LOD_NAME);
	type->typ_procsym = lprocfs_seq_register("lov", proc_lustre_root,
						 NULL, NULL);
	if (IS_ERR(type->typ_procsym)) {
		CERROR("lod: can't create compat entry \"lov\": %d\n",
		       (int)PTR_ERR(type->typ_procsym));
		type->typ_procsym = NULL;
	}
	return rc;
}

static void __exit lod_mod_exit(void)
{
	class_unregister_type(LUSTRE_LOD_NAME);
	lu_kmem_fini(lod_caches);
}

MODULE_AUTHOR("Whamcloud, Inc. <http://www.whamcloud.com/>");
MODULE_DESCRIPTION("Lustre Logical Object Device ("LUSTRE_LOD_NAME")");
MODULE_LICENSE("GPL");

module_init(lod_mod_init);
module_exit(lod_mod_exit);

