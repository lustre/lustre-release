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

static int smfs_llog_process_rec_cb(struct llog_handle *handle,
                                    struct llog_rec_hdr *rec, void *data)
{
        char   *rec_buf ;
        struct smfs_proc_args *args = (struct smfs_proc_args *)data;
        struct lvfs_run_ctxt saved;
        int    rc = 0;

        if (!(le32_to_cpu(handle->lgh_hdr->llh_flags) & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        if (le32_to_cpu(rec->lrh_type) == LLOG_GEN_REC) {
                struct llog_cookie cookie;

                cookie.lgc_lgl = handle->lgh_id;
                cookie.lgc_index = le32_to_cpu(rec->lrh_index);

                llog_cancel(handle->lgh_ctxt, 1, &cookie, 0, NULL);
                RETURN(LLOG_PROC_BREAK);
        }

        if (le32_to_cpu(rec->lrh_type) != SMFS_UPDATE_REC)
                RETURN(-EINVAL);

        rec_buf = (char*) (rec + 1);

        if (!S2SMI(args->sr_sb)->smsi_ctxt)
                GOTO(exit, rc = -ENODEV);

        push_ctxt(&saved, S2SMI(args->sr_sb)->smsi_ctxt, NULL);
#if 0
        /*FIXME later should first unpack the rec,
         * then call lvfs_reint or lvfs_undo
         * kml rec format has changed lvfs_reint lvfs_undo should
         * be rewrite FIXME later*/
        if (SMFS_DO_REINT_REC(args->sr_flags))
                rc = lvfs_reint(args->sr_sb, rec_buf);
        else
                rc = lvfs_undo(args->sr_sb, rec_buf);
#endif
        if (!rc && !SMFS_DO_REC_ALL(args->sr_flags)) {
                args->sr_count --;
                if (args->sr_count == 0)
                        rc = LLOG_PROC_BREAK;
        }
        pop_ctxt(&saved, S2SMI(args->sr_sb)->smsi_ctxt, NULL);
exit:
        RETURN(rc);
}

int smfs_llog_setup(struct super_block *sb, struct vfsmount *mnt)
{
        struct llog_ctxt **ctxt = &(S2SMI(sb)->smsi_rec_log);
        struct lvfs_run_ctxt saved;
        struct dentry *dentry;
        int rc = 0, rc2;

        /* create OBJECTS and LOGS for writing logs */
        ENTRY;

        LASSERT(mnt);

        push_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        dentry = simple_mkdir(current->fs->pwd, "LOGS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create LOGS directory: rc = %d\n", rc);
                GOTO(exit, rc = -EINVAL);
        }

        S2SMI(sb)->smsi_logs_dir = dentry;
        dentry = simple_mkdir(current->fs->pwd, "OBJECTS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create OBJECTS directory: rc = %d\n", rc);
                GOTO(exit, rc = -EINVAL);
        }

        S2SMI(sb)->smsi_objects_dir = dentry;

        /* write log will not write to KML, cleanup kml flags */
        SMFS_CLEAN_INODE_REC(S2SMI(sb)->smsi_objects_dir->d_inode);
        SMFS_CLEAN_INODE_REC(S2SMI(sb)->smsi_logs_dir->d_inode);

        /* log create does not call cache hooks, cleanup hook flags */
        SMFS_CLEAN_INODE_CACHE_HOOK(S2SMI(sb)->smsi_objects_dir->d_inode);
        SMFS_CLEAN_INODE_CACHE_HOOK(S2SMI(sb)->smsi_logs_dir->d_inode);

        if (SMFS_DO_REC(S2SMI(sb))) {
                rc = llog_catalog_setup(ctxt, KML_LOG_NAME, S2SMI(sb)->smsi_exp,
                                        S2SMI(sb)->smsi_ctxt, S2SMI(sb)->sm_fsfilt,
                                        S2SMI(sb)->smsi_logs_dir,
                                        S2SMI(sb)->smsi_objects_dir);
                (*ctxt)->llog_proc_cb = smfs_llog_process_rec_cb;
        }

        if (SMFS_CACHE_HOOK(S2SMI(sb))) {
                rc2 = cache_space_hook_setup(sb);
                if (!rc && rc2)
                        rc = rc2;
        }
exit:
        pop_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        RETURN(rc);
}

int smfs_llog_cleanup(struct super_block *sb)
{
        struct llog_ctxt *ctxt = S2SMI(sb)->smsi_rec_log;
        int rc = 0, rc2;
        ENTRY;

        if (SMFS_CACHE_HOOK(S2SMI(sb)))
                rc = cache_space_hook_cleanup();

        if (SMFS_DO_REC(S2SMI(sb))) {
                rc2 = llog_catalog_cleanup(ctxt);
                OBD_FREE(ctxt, sizeof(*ctxt));
                if (!rc)
                        rc = rc2;
        }

        if (S2SMI(sb)->smsi_logs_dir) {
                l_dput(S2SMI(sb)->smsi_logs_dir);
                S2SMI(sb)->smsi_logs_dir = NULL;
        }
        if (S2SMI(sb)->smsi_objects_dir) {
                l_dput(S2SMI(sb)->smsi_objects_dir);
                S2SMI(sb)->smsi_objects_dir = NULL;
        }
        RETURN(rc);
}

int smfs_llog_add_rec(struct smfs_super_info *sinfo, void *data, int data_size)
{
        struct llog_rec_hdr rec;
        int rc = 0;

        rec.lrh_len = size_round(data_size);
        rec.lrh_type = SMFS_UPDATE_REC;

        rc = llog_add(sinfo->smsi_rec_log, &rec, data, NULL, 0, NULL, NULL, NULL);
        if (rc != 1) {
                CERROR("error adding kml rec: %d\n", rc);
                RETURN(-EINVAL);
        }
        RETURN(0);
}
