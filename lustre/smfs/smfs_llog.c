/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/smfs_llog.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/lvfs.h>

#include "smfs_internal.h"
int smfs_llog_setup(struct dentry **logs, struct dentry **objects)
{
        struct dentry *dentry = NULL;
        int rc = 0;
        ENTRY;

        /* create OBJECTS and LOGS for writing logs */
        dentry = simple_mkdir(current->fs->pwd, "LOGS", 0777, 1);
        if (IS_ERR(dentry)) {
                CERROR("cannot create LOGS directory: rc = %d\n",
                       (int)PTR_ERR(dentry));
                RETURN(rc);
        }
        *logs = dentry;
        
        dentry = simple_mkdir(current->fs->pwd, "OBJECTS", 0777, 1);
        if (IS_ERR(dentry)) {
                CERROR("cannot create OBJECTS directory: rc = %d\n",
                       (int)PTR_ERR(dentry));
                RETURN(rc);
        }
        *objects = dentry;
        
        RETURN(rc);
}

int smfs_llog_cleanup(struct smfs_super_info *smb)
{
        ENTRY;

        /*
        if (SMFS_CACHE_HOOK(S2SMI(sb)))
                rc = cache_space_hook_cleanup();

        if (SMFS_DO_REC(S2SMI(sb))) {
                rc2 = llog_catalog_cleanup(ctxt);
                OBD_FREE(ctxt, sizeof(*ctxt));
                if (!rc)
                        rc = rc2;
        }
        */
        if (smb->smsi_logs_dir) {
                l_dput(smb->smsi_logs_dir);
                smb->smsi_logs_dir = NULL;
        }
        if (smb->smsi_objects_dir) {
                l_dput(smb->smsi_objects_dir);
                smb->smsi_objects_dir = NULL;
        }
        RETURN(0);
}

int smfs_llog_add_rec(struct smfs_super_info *smb, void *data, int data_size)
{
        struct llog_rec_hdr rec;
        int rc = 0;
        
        ENTRY;
        rec.lrh_len = size_round(data_size);
        rec.lrh_type = SMFS_UPDATE_REC;

        rc = llog_catalog_add(smb->smsi_kml_log, &rec, data, NULL, 0, NULL, NULL, NULL);
        if (rc != 1) {
                CERROR("error adding kml rec: %d\n", rc);
                RETURN(-EINVAL);
        }
        RETURN(0);
}

