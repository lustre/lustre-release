/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
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
 *
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include "smfs_internal.h"

/*FIXME there should be more conditions in this check*/
int smfs_do_rec(struct inode *inode)
{
        struct super_block *sb = inode->i_sb;
        struct smfs_super_info *smfs_info = S2SMI(sb);

        if (SMFS_DO_REC(smfs_info) && SMFS_INIT_REC(smfs_info) &&
            SMFS_DO_INODE_REC(inode))
                return 1;
        return 0;
}

int smfs_rec_init(struct super_block *sb)
{
        struct smfs_super_info *smfs_info = S2SMI(sb);
        int rc = 0;

        SMFS_SET_REC(smfs_info);

        RETURN(rc);
}

int smfs_rec_cleanup(struct super_block *sb)
{
        int rc = 0;

        SMFS_CLEAN_REC(S2SMI(sb));
        RETURN(rc);
}

void reint_rec_free(struct reint_record *reint_rec)
{
        if (reint_rec) {
                if (reint_rec->rec_data1)
                        OBD_FREE(reint_rec->rec_data1,
                                 reint_rec->rec1_size + 1);
                if (reint_rec->rec_data2)
                        OBD_FREE(reint_rec->rec_data2,
                                 reint_rec->rec2_size + 1);

                OBD_FREE(reint_rec, sizeof(struct reint_record));
        }
}

static inline void copy_inode_attr(struct iattr *iattr, struct inode *inode)
{
        iattr->ia_mode = inode->i_mode;
        iattr->ia_uid  = inode->i_uid;
        iattr->ia_gid  = inode->i_gid;
        iattr->ia_atime = inode->i_atime;
        iattr->ia_ctime = inode->i_ctime;
        iattr->ia_mtime = inode->i_mtime;
        iattr->ia_size = inode->i_size;
}

void smfs_rec_pack(struct update_record *rec, struct inode *dst,
                   void *data, int op)
{
        rec->ur_fsuid = current->fsuid;
        rec->ur_fsgid = current->fsgid;
        rec->ur_rdev = dst->i_rdev;
        rec->ur_opcode = op;
        copy_inode_attr(&rec->ur_iattr, dst);
        if (data) {
                switch (op) {
                case REINT_CREATE:
                case REINT_LINK:
                case REINT_UNLINK:
                case REINT_RENAME: {
                        struct inode *dir = (struct inode *)data;
                        copy_inode_attr(&rec->ur_pattr, dir);
                        break;
                }
                case REINT_SETATTR: {
                        struct iattr *attr = (struct iattr *)data;
                        memcpy(&rec->ur_pattr, attr, sizeof(struct iattr));
                        break;
                }
                }
        }
}

static inline void unpack_attr(struct reint_record *r_rec,
                               struct update_record *u_rec)
{
        memcpy(&r_rec->u_rec, u_rec, sizeof(struct update_record));
}

static inline int unpack_rec_data(char **p_buffer, int *size,
                                  char *in_data, char *args_data)
{
        int args_len = 0;
        int rc = 0;
        ENTRY;

        if (args_data)
                args_len = strlen(args_data);

        *size = *((int*)(in_data));
        rc = *size + sizeof(int);

        OBD_ALLOC(*p_buffer, *size + args_len + 1);
        if (!*p_buffer)
                RETURN(-ENOMEM);
        /*First copy reint dir */
        if (args_data)
                memcpy(*p_buffer, args_data, args_len);

        /*then copy the node name */
        memcpy(*p_buffer + args_len,
                      (in_data + sizeof(int)), *size);

        *size += args_len;

        RETURN(rc);
}

int smfs_rec_unpack(struct smfs_proc_args *args, struct reint_record *r_rec,
                    char *rec_buf)
{
        struct update_record *u_rec = (struct update_record *)rec_buf;
        int rc = 0, length = 0;
        ENTRY;
        /*FIXME wangdi, there unpack are so smiliar that
          *we will put it together later*/

        if (SMFS_DO_WRITE_KML(args->sr_flags))
                SET_REC_WRITE_KML_FLAGS(r_rec->u_rec.ur_flags, SMFS_WRITE_KML);
        unpack_attr(r_rec, u_rec);
        length += sizeof(struct update_record);
        rc = unpack_rec_data(&r_rec->rec_data1, &r_rec->rec1_size,
                             (rec_buf + length), args->sr_data);
        switch (u_rec->ur_opcode) {
        case REINT_OPEN:
        case REINT_CLOSE:
                /*record src path which will be passed to reint and undo*/
                rc = unpack_rec_data(&r_rec->rec_data2, &r_rec->rec2_size,
                                     (rec_buf + length), NULL);
                break;
        case REINT_LINK:
        case REINT_RENAME:
        case REINT_SETATTR:
        case REINT_UNLINK:
        case REINT_CREATE:
        case REINT_WRITE: {
                length += rc;
                if (length < u_rec->ur_len) {
                        char *pre_name;
                        if (u_rec->ur_opcode == REINT_CREATE ||
                            u_rec->ur_opcode == REINT_WRITE ||
                            (u_rec->ur_opcode == REINT_UNLINK &&
                             SMFS_DO_DEC_LINK(r_rec->u_rec.ur_flags)))
                                pre_name = NULL;
                        else
                                pre_name = args->sr_data;

                        rc = unpack_rec_data(&r_rec->rec_data2,
                                             &r_rec->rec2_size,
                                             (rec_buf + length), pre_name);
                }
                break;
        }
        }
        if (rc > 0)
                rc = 0;

        RETURN(rc);
}

int smfs_start_rec(struct super_block *sb)
{
        struct dentry *dentry;
        struct lvfs_run_ctxt saved;
        int rc = 0;
        ENTRY;

        if (SMFS_INIT_REC(S2SMI(sb)) ||
            (!SMFS_DO_REC(S2SMI(sb)) && !SMFS_CACHE_HOOK(S2SMI(sb))))
                RETURN(rc);

        rc = smfs_llog_setup(sb);
        if (rc)
                RETURN(rc);

        push_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        dentry = simple_mkdir(current->fs->pwd, "DELETE", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create LOGS directory: rc = %d\n", rc);
                GOTO(err_exit, rc = -EINVAL);
        }
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (list_empty(&dentry->d_hash))
                d_rehash(dentry);
#else
        /* FIXME-WANGDI: here should be be something. */
#endif

        if (!rc)
                SMFS_SET_INIT_REC(S2SMI(sb));
        S2SMI(sb)->smsi_delete_dir = dentry;
exit:
        pop_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        RETURN(rc);
err_exit:
        if (S2SMI(sb)->smsi_ctxt)
                OBD_FREE(S2SMI(sb)->smsi_ctxt, sizeof(struct lvfs_run_ctxt));
        goto exit;
}

int smfs_stop_rec(struct super_block *sb)
{
        int rc = 0;
        ENTRY;

        if (!SMFS_INIT_REC(S2SMI(sb)) ||
            (!SMFS_DO_REC(S2SMI(sb)) && !SMFS_CACHE_HOOK(S2SMI(sb))))
                RETURN(rc);

        rc = smfs_llog_cleanup(sb);

        SMFS_CLEAN_INIT_REC(S2SMI(sb));

        if (S2SMI(sb)->smsi_delete_dir) {
                l_dput(S2SMI(sb)->smsi_delete_dir);
                S2SMI(sb)->smsi_delete_dir = NULL;
        }
        RETURN(rc);
}

int smfs_process_rec(struct super_block *sb, int count, char *dir, int flags)
{
        struct llog_ctxt *ctxt;
        struct llog_handle *loghandle;
        struct smfs_proc_args args;
        int rc = 0;
        ENTRY;

        if (!SMFS_INIT_REC(S2SMI(sb))) {
                CWARN("Did not start up rec server \n");
                RETURN(rc);
        }

        memset(&args, 0, sizeof(struct smfs_proc_args));
        args.sr_sb = sb;
        args.sr_count = count;
        args.sr_data = dir;
        args.sr_flags = flags ;
        ctxt = S2SMI(sb)->smsi_rec_log;
        loghandle = ctxt->loc_handle;

        if (count == 0) {
                if (SMFS_DO_REINT_REC(flags)) {
                        struct llog_gen_rec *lgr;

                        /*For reint rec, we need insert
                          *a gen rec to identify the end
                          *of the rec.*/
                        OBD_ALLOC(lgr, sizeof(*lgr));
                        if (!lgr)
                                RETURN(-ENOMEM);
                        lgr->lgr_hdr.lrh_len = lgr->lgr_tail.lrt_len =
                                sizeof(*lgr);
                        lgr->lgr_hdr.lrh_type = LLOG_GEN_REC;
                        lgr->lgr_gen = ctxt->loc_gen;
                        rc = llog_add(ctxt, &lgr->lgr_hdr, NULL, NULL, 1, NULL);
                        OBD_FREE(lgr, sizeof(*lgr));
                        if (rc != 1)
                                RETURN(rc);
                }
        } else {
                SET_REC_COUNT_FLAGS(args.sr_flags, SMFS_REC_ALL);
        }
        if (loghandle) {
                if (SMFS_DO_REINT_REC(flags))
                        rc = llog_cat_process(loghandle, ctxt->loc_proc_cb,
                                              (void *)&args);
                else
                        rc = llog_cat_reverse_process(loghandle,
                                                      ctxt->loc_proc_cb,
                                                      (void *)&args);
                if (rc == LLOG_PROC_BREAK)
                        rc = 0;
        }
        RETURN(rc);
}
