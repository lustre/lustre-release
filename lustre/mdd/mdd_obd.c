/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_lov.c
 *  Lustre Metadata Server (mdd) OBD  
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: wangdi <wangdi@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <obd_lov.h>
#include <lprocfs_status.h>

#include <lu_object.h>
#include <md_object.h>
#include <dt_object.h>
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"

/*The obd is created for using llog in mdd layer*/
int mdd_new_obd(struct mdd_device *mdd)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg      *lcfg;
        struct obd_device      *obd; 
        int rc;
        ENTRY;
        
        lustre_cfg_bufs_reset(&bufs, MDD_OBD_NAME);
        lustre_cfg_bufs_set_string(&bufs, 1, MDD_OBD_TYPE);
        lustre_cfg_bufs_set_string(&bufs, 2, MDD_OBD_UUID);
        lustre_cfg_bufs_set_string(&bufs, 3, MDD_OBD_UUID);

        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
        if (!lcfg)
                RETURN(-ENOMEM);
        
        rc = class_attach(lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);
       
        obd = class_name2obd(MDD_OBD_NAME);
        if (!obd) {
                CERROR("can not find obd %s \n", MDD_OBD_NAME);
                LBUG();
        }
        
        rc = class_setup(obd, lcfg);
        if (rc)
                GOTO(class_detach, rc);
        
        mdd->mdd_md_dev.md_lu_dev.ld_obd = obd;
class_detach:
        if (rc)
                class_detach(obd, lcfg);
lcfg_cleanup:
        lustre_cfg_free(lcfg);
        RETURN(rc);
}

int mdd_cleanup_obd(struct mdd_device *mdd)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg      *lcfg;
        struct obd_device      *obd; 
        int rc;
        ENTRY;
        
        obd = mdd->mdd_md_dev.md_lu_dev.ld_obd;
        LASSERT(obd);
        lustre_cfg_bufs_reset(&bufs, MDD_OBD_NAME);
        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
       
        if (!lcfg)
                RETURN(-ENOMEM);

        rc = class_cleanup(obd, lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);
        
        rc = class_detach(obd, lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);
        mdd->mdd_md_dev.md_lu_dev.ld_obd = NULL;
lcfg_cleanup:
        lustre_cfg_free(lcfg);
        RETURN(rc);
}
