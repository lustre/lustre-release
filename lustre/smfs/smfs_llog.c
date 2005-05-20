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
int smfs_llog_setup(struct super_block *sb, struct vfsmount *mnt)
{
        struct dentry *dentry = NULL;
        int rc = 0;

        /* create OBJECTS and LOGS for writing logs */
        ENTRY;

        LASSERT(mnt);

        //push_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        dentry = simple_mkdir(current->fs->pwd, "LOGS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create LOGS directory: rc = %d\n", rc);
                rc = -EINVAL;
                goto exit;
        }

        S2SMI(sb)->smsi_logs_dir = dentry;
        //SMFS_SET(I2SMI(dentry->d_inode)->smi_flags, SMFS_PLG_ALL);
        
        dentry = simple_mkdir(current->fs->pwd, "OBJECTS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create OBJECTS directory: rc = %d\n", rc);
                rc = -EINVAL;
                goto exit;
        }

        S2SMI(sb)->smsi_objects_dir = dentry;
        //SMFS_SET(I2SMI(dentry->d_inode)->smi_flags, SMFS_PLG_ALL);

        /* write log will not write to KML, cleanup kml flags */
        //SMFS_CLEAN_INODE_REC(S2SMI(sb)->smsi_objects_dir->d_inode);
        //SMFS_CLEAN_INODE_REC(S2SMI(sb)->smsi_logs_dir->d_inode);

        /* log create does not call cache hooks, cleanup hook flags */
        //SMFS_CLEAN_INODE_CACHE_HOOK(S2SMI(sb)->smsi_objects_dir->d_inode);
        //SMFS_CLEAN_INODE_CACHE_HOOK(S2SMI(sb)->smsi_logs_dir->d_inode);

        
        /*if (SMFS_CACHE_HOOK(S2SMI(sb))) {
                rc2 = cache_space_hook_setup(sb);
                if (!rc && rc2)
                        rc = rc2;
        }*/
exit:
        //pop_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        RETURN(rc);
}

int smfs_llog_cleanup(struct super_block *sb)
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
        if (S2SMI(sb)->smsi_logs_dir) {
                l_dput(S2SMI(sb)->smsi_logs_dir);
                S2SMI(sb)->smsi_logs_dir = NULL;
        }
        if (S2SMI(sb)->smsi_objects_dir) {
                l_dput(S2SMI(sb)->smsi_objects_dir);
                S2SMI(sb)->smsi_objects_dir = NULL;
        }
        RETURN(0);
}

int smfs_llog_add_rec(struct smfs_super_info *sinfo, void *data, int data_size)
{
        struct llog_rec_hdr rec;
        int rc = 0;

        rec.lrh_len = size_round(data_size);
        rec.lrh_type = SMFS_UPDATE_REC;

        rc = llog_add(sinfo->smsi_kml_log, &rec, data, NULL, 0, NULL, NULL, NULL);
        if (rc != 1) {
                CERROR("error adding kml rec: %d\n", rc);
                RETURN(-EINVAL);
        }
        RETURN(0);
}

