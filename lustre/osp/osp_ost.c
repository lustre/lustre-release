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
 * Copyright (c) 2012 Intel, Inc.
 * Use is subject to license terms.
 *
 * lustre/osp/osp_ost.c
 *
 * OSP on OST for communicating with MDT0
 *
 * Author: <di.wang@whamcloud.com>
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OST

#include <obd_class.h>
#include <lustre_param.h>
#include <lustre_log.h>

#include "osp_internal.h"

static int osp_name2fsname(char *ospname, char *fsname)
{
	char *ptr;

	LASSERT(ospname != NULL);
	LASSERT(fsname != NULL);
	if (!is_osp_on_ost(ospname))
		return -EINVAL;

	sprintf(fsname, "-%s-", LUSTRE_OSP_NAME);

	ptr = strstr(ospname, fsname);
	if (ptr) {
		strncpy(fsname, ospname, ptr - ospname);
		fsname[ptr - ospname] = '\0';
	}
	return 0;
}

static int osp_setup_for_ost(const struct lu_env *env, struct osp_device *osp,
                             char *nidstring)
{
	struct lustre_cfg_bufs	*bufs = NULL;
	struct lustre_cfg	*lcfg = NULL;
	char			*ospname = osp->opd_obd->obd_name;
	char			*fsname = NULL;
	char			*server_uuid = NULL;
	class_uuid_t		 uuid;
	struct obd_import	*imp;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(bufs);
	if (bufs == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC(fsname, strlen(ospname));
	if (fsname == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = osp_name2fsname(ospname, fsname);
	if (rc) {
		CERROR("%s: name change error: rc %d\n", ospname, rc);
		GOTO(out, rc);
	}

	OBD_ALLOC(server_uuid, strlen(fsname) + 15);
	if (server_uuid == NULL)
		GOTO(out, rc = -ENOMEM);

	sprintf(server_uuid, "%s-MDT0000_UUID", fsname);
	lustre_cfg_bufs_reset(bufs, ospname);
	lustre_cfg_bufs_set_string(bufs, 1, server_uuid);
	lustre_cfg_bufs_set_string(bufs, 2, nidstring);
	lcfg = lustre_cfg_new(LCFG_SETUP, bufs);
	if (lcfg == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = client_obd_setup(osp->opd_obd, lcfg);
	if (rc != 0) {
		CERROR("%s: client obd setup error: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		GOTO(out, rc);
	}

	imp = osp->opd_obd->u.cli.cl_import;
	rc = ptlrpc_init_import(imp);
	if (rc)
		GOTO(out, rc);

	ll_generate_random_uuid(uuid);
	class_uuid_unparse(uuid, &osp->opd_cluuid);
out:
	if (bufs != NULL)
		OBD_FREE_PTR(bufs);
	if (server_uuid != NULL)
		OBD_FREE(server_uuid, strlen(fsname) + 15);
	if (fsname != NULL)
		OBD_FREE(fsname, strlen(ospname));
	if (lcfg != NULL)
		lustre_cfg_free(lcfg);
	if (rc)
		client_obd_cleanup(osp->opd_obd);
	RETURN(rc);
}

int osp_fini_for_ost(struct osp_device *osp)
{
	if (osp->opd_exp != NULL)
		class_disconnect(osp->opd_exp);
	return 0;
}

int osp_init_for_ost(const struct lu_env *env, struct osp_device *osp,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	struct lprocfs_static_vars lvars = { 0 };
	int			   rc;
	ENTRY;

	osp->opd_obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (osp->opd_obd == NULL) {
		CERROR("Cannot find obd with name %s\n",
		       lustre_cfg_string(cfg, 0));
		RETURN(-ENODEV);
	}

	osp->opd_dt_dev.dd_lu_dev.ld_ops = &osp_lu_ops;
	osp->opd_dt_dev.dd_ops = &osp_dt_ops;
	osp->opd_obd->obd_lu_dev = &osp->opd_dt_dev.dd_lu_dev;

	rc = ptlrpcd_addref();
	if (rc) {
		CERROR("%s: ptlrpcd addref error: rc =%d\n",
		       osp->opd_obd->obd_name, rc);
		RETURN(rc);
	}

	rc = osp_setup_for_ost(env, osp, lustre_cfg_string(cfg, 1));
	if (rc) {
		CERROR("%s: osp_setup_for_ost error: rc =%d\n",
		       osp->opd_obd->obd_name, rc);
		ptlrpcd_decref();
		RETURN(rc);
	}

	lprocfs_osp_init_vars(&lvars);
	if (lprocfs_obd_setup(osp->opd_obd, lvars.obd_vars) == 0)
		ptlrpc_lprocfs_register_obd(osp->opd_obd);

	RETURN(0);
}
