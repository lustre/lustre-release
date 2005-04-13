/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/kml.c
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
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

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

#define KML_BUF_REC_INIT(buffer, pbuf, len)     \
do {                                            \
        pbuf = buffer + sizeof(int);            \
        len -= sizeof(int);                     \
} while (0)
        
#define KML_BUF_REC_END(buffer, length, pbuf)   \
do {                                            \
        int len = length;                       \
        memcpy(buffer, &len, sizeof(len));      \
        length += sizeof(int);                  \
        pbuf = buffer + length;                 \
} while (0)


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

static smfs_pack_rec_func smfs_get_rec_pack_type(struct super_block *sb)
{
        int idx = 0;
        struct smfs_super_info *smsi = S2SMI(sb);

        idx = GET_REC_PACK_TYPE_INDEX(smsi->smsi_flags);
        return smsi->smsi_pack_rec[idx];
}

static inline void
copy_inode_attr(struct iattr *iattr, struct inode *inode)
{
        iattr->ia_mode = inode->i_mode;
        iattr->ia_uid  = inode->i_uid;
        iattr->ia_gid  = inode->i_gid;
        iattr->ia_atime = inode->i_atime;
        iattr->ia_ctime = inode->i_ctime;
        iattr->ia_mtime = inode->i_mtime;
        iattr->ia_size = inode->i_size;
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

        /* first copy reint dir. */
        if (args_data)
                memcpy(*p_buffer, args_data, args_len);

        /* then copy the node name. */
        memcpy(*p_buffer + args_len,
                      (in_data + sizeof(int)), *size);

        *size += args_len;

        RETURN(rc);
}

int smfs_rec_unpack(struct smfs_proc_args *args, char *record, 
                    char **pbuf, int *opcode)
{
        int offset = *(int *)(record);
        char *tmp = record + offset + sizeof(int);

        *opcode = *(int *)tmp;
        *pbuf = tmp + sizeof(*opcode);
        return 0;
}
EXPORT_SYMBOL(smfs_rec_unpack);

int smfs_write_extents(struct inode *dir, struct dentry *dentry,
                       unsigned long from, unsigned long num)
{
        return smfs_post_rec_write(dir, dentry, &from, &num);
}
EXPORT_SYMBOL(smfs_write_extents);

int smfs_rec_setattr(struct inode *dir, struct dentry *dentry,
                     struct iattr *attr)
{
        return smfs_post_rec_setattr(dir, dentry, attr, NULL);
}
EXPORT_SYMBOL(smfs_rec_setattr);

int smfs_rec_md(struct inode *inode, void *lmm, int lmm_size)
{
        char *set_lmm = NULL;
        int  rc = 0;
        ENTRY;

        if (!SMFS_DO_REC(S2SMI(inode->i_sb)))
                RETURN(0);

        if (lmm) {
                OBD_ALLOC(set_lmm, lmm_size + sizeof(lmm_size));
                if (!set_lmm)
                        RETURN(-ENOMEM);
                memcpy(set_lmm, &lmm_size, sizeof(lmm_size));
                memcpy(set_lmm + sizeof(lmm_size), lmm, lmm_size);
                rc = smfs_post_rec_setattr(inode, NULL, NULL, set_lmm);
                if (rc) {
                        CERROR("Error: Record md for inode %lu rc=%d\n",
                                inode->i_ino, rc);
                }
        }
        if (set_lmm)
                OBD_FREE(set_lmm, lmm_size + sizeof(lmm_size));
        RETURN(rc);
}
EXPORT_SYMBOL(smfs_rec_md);

int smfs_rec_precreate(struct dentry *dentry, int *num, struct obdo *oa)
{
       return smfs_post_rec_create(dentry->d_inode, dentry, num, oa);
}
EXPORT_SYMBOL(smfs_rec_precreate);

int smfs_process_rec(struct super_block *sb,
                     int count, char *dir, int flags)
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
        ctxt = S2SMI(sb)->smsi_kml_log;
        loghandle = ctxt->loc_handle;

        if (count == 0) {
                if (SMFS_DO_REINT_REC(flags)) {
                        struct llog_gen_rec *lgr;

                        /* for reint rec, we need insert a gen rec to identify
                         * the end of the rec.*/
                        OBD_ALLOC(lgr, sizeof(*lgr));
                        if (!lgr)
                                RETURN(-ENOMEM);
                        lgr->lgr_hdr.lrh_len = lgr->lgr_tail.lrt_len = sizeof(*lgr);
                        lgr->lgr_hdr.lrh_type = LLOG_GEN_REC;
                        lgr->lgr_gen = ctxt->loc_gen;
                        rc = llog_add(ctxt, &lgr->lgr_hdr, NULL, NULL, 1,
                                      NULL, NULL, NULL);
                        OBD_FREE(lgr, sizeof(*lgr));
                        if (rc != 1)
                                RETURN(rc);
                }
        } else {
                SET_REC_COUNT_FLAGS(args.sr_flags, SMFS_REC_ALL);
        }
        if (loghandle) {
                if (SMFS_DO_REINT_REC(flags))
                        rc = llog_cat_process(loghandle, ctxt->llog_proc_cb,
                                              (void *)&args);
                else
                        rc = llog_cat_reverse_process(loghandle,
                                                      ctxt->llog_proc_cb,
                                                      (void *)&args);
                if (rc == LLOG_PROC_BREAK)
                        rc = 0;
        }
        RETURN(rc);
}

/*smfs_path is gotten from intermezzo*/
static char* smfs_path(struct dentry *dentry, struct dentry *root, char *buffer,
                       int buflen)
{
        char * end = buffer + buflen;
        char * name = buffer;
        char * buf_end = buffer + buflen;
        char * retval;

        *--end = '\0';
        buflen--;
        /* Get '/' right */
        retval = end-1;
        *retval = '/';

        for (;;) {
                struct dentry * parent;
                int namelen;

                if (dentry == root)
                        break;
                parent = dentry->d_parent;
                if (dentry == parent)
                        break;
                namelen = dentry->d_name.len;
                buflen -= namelen + 1;
                if (buflen < 0)
                        break;
                end -= namelen;
                memcpy(end, dentry->d_name.name, namelen);
                *--end = '/';
                retval = end;
                dentry = parent;
        }
        
        while (end != buf_end) 
                *name++ = *end++;
        *name = '\0'; 
        return retval;
}

static int smfs_log_path(struct super_block *sb, 
                         struct dentry *dentry, 
                         char   *buffer,
                         int    buffer_len)
{
        struct dentry *root=sb->s_root;
        char *p_name = buffer + sizeof(int);
        char *name = NULL;
        int namelen = 0;
        ENTRY;

        if (dentry) {
                name = smfs_path(dentry, root, p_name, buffer_len - sizeof(int));
                namelen = cpu_to_le32(strlen(p_name));
                memcpy(buffer, &namelen, sizeof(int));        
        }
        namelen += sizeof(int);
        RETURN(namelen);
}

static inline int log_it(char *buffer, void *data, int length)
{
        memcpy(buffer, &length, sizeof(int));
        memcpy(buffer + sizeof(int), data, length);
        return (sizeof(int) + length);                 
}

static int smfs_pack_rec (char *buffer, struct dentry *dentry, 
                          struct inode *dir, void *data1, 
                          void *data2, int op)
{ 
        smfs_pack_rec_func pack_func;        

        pack_func = smfs_get_rec_pack_type(dir->i_sb);
        if (!pack_func)
                return 0;
        return pack_func(buffer, dentry, dir, data1, data2, op);
}

int smfs_post_rec_create(struct inode *dir, struct dentry *dentry,
                         void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        char   *buffer = NULL, *pbuf;
        int rc = 0, length = 0, buf_len = 0;
        ENTRY;
        
        sinfo = S2SMI(dentry->d_inode->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);
        
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);        

        buf_len = PAGE_SIZE;
        KML_BUF_REC_INIT(buffer, pbuf, buf_len);
        rc = smfs_log_path(dir->i_sb, dentry, pbuf, buf_len);
        if (rc < 0)
                GOTO(exit, rc);
        length = rc;
        KML_BUF_REC_END(buffer, length, pbuf);   
       
        rc = smfs_pack_rec(pbuf, dentry, dir, 
                           data1, data2, REINT_CREATE);
        if (rc <= 0)
                GOTO(exit, rc);
        else
                length += rc;
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        
        RETURN(rc);
}

static int smfs_post_rec_link(struct inode *dir, struct dentry *dentry, 
                              void *data1, void *data2)
{
        struct dentry *new_dentry = (struct dentry *)data1;
        int rc = 0, length = 0, buf_len = 0;
        char *buffer = NULL, *pbuf = NULL;
        struct smfs_super_info *sinfo;
        ENTRY;
        
        sinfo = S2SMI(dir->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        
        buf_len = PAGE_SIZE;
        KML_BUF_REC_INIT(buffer, pbuf, buf_len);
        
        rc = smfs_log_path(dir->i_sb, dentry, pbuf, buf_len);
        if (rc < 0)
                GOTO(exit, rc);
        
        length = rc;
        KML_BUF_REC_END(buffer, length, pbuf);  
        
        rc = smfs_pack_rec(pbuf, dentry, dir, dentry, 
                           new_dentry, REINT_LINK);
        if (rc <= 0)
                GOTO(exit, rc);
        
        length += rc;
        rc = smfs_llog_add_rec(sinfo, (void *)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        
        RETURN(rc);
}

static int smfs_post_rec_unlink(struct inode *dir, struct dentry *dentry,
                                void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        int mode = *((int*)data1);
        char   *buffer = NULL, *pbuf = NULL;
        int  length = 0, rc = 0, buf_len = 0;
        ENTRY;
         
        sinfo = S2SMI(dentry->d_inode->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);
        
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);        
      
        buf_len = PAGE_SIZE;
        KML_BUF_REC_INIT(buffer, pbuf, buf_len);        
        rc = smfs_log_path(dir->i_sb, dentry, pbuf, buf_len);
        if (rc < 0)
                GOTO(exit, rc);

        length = rc;
        KML_BUF_REC_END(buffer, length, pbuf);
        rc = smfs_pack_rec(pbuf, dentry, dir, 
                           &mode, NULL, REINT_UNLINK);
        if (rc <= 0)
                GOTO(exit, rc);
        else
                length += rc;         
        
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        
        RETURN(rc);
}

static int smfs_post_rec_rename(struct inode *dir, struct dentry *dentry, 
                                void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        struct inode *new_dir = (struct inode *)data1;
        struct dentry *new_dentry = (struct dentry *)data2;
        char *buffer = NULL, *pbuf = NULL;
        int rc = 0, length = 0, buf_len = 0;
        ENTRY;
        
        sinfo = S2SMI(dir->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);

        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        
        buf_len = PAGE_SIZE;
        KML_BUF_REC_INIT(buffer, pbuf, buf_len);        
        rc = smfs_log_path(dir->i_sb, dentry, pbuf, buf_len);
        if (rc < 0)
                GOTO(exit, rc);

        pbuf += rc; 
        length += rc;
        buf_len -= rc;
        
        /* record new_dentry path. */
        rc = smfs_log_path(dir->i_sb, new_dentry, pbuf, buf_len);
        if (rc < 0)
                GOTO(exit, rc);

        length += rc;
        KML_BUF_REC_END(buffer, length, pbuf);
               
        rc = smfs_pack_rec(pbuf, dentry, dir, 
                           new_dir, new_dentry, REINT_RENAME);
        if (rc <= 0) 
                GOTO(exit, rc);
        length += rc;
        
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);
        RETURN(rc);
}

static int smfs_insert_extents_ea(struct inode *inode, size_t from, loff_t num)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        int rc = 0;
        ENTRY;
        
        if (SMFS_INODE_OVER_WRITE(inode))
                RETURN(rc);
        
        rc = fsfilt->fs_insert_extents_ea(inode, OFF2BLKS(from, inode), 
                                          SIZE2BLKS(num, inode));        
        RETURN(rc);
}

static int smfs_remove_extents_ea(struct inode *inode, size_t from, loff_t num)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        int rc = 0;
        ENTRY;
        
        rc = fsfilt->fs_remove_extents_ea(inode, OFF2BLKS(from, inode), 
                                          SIZE2BLKS(num, inode));        
        
        RETURN(rc);
}

static int smfs_remove_all_extents_ea(struct inode *inode)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        int rc = 0;
        ENTRY;
        
        rc = fsfilt->fs_remove_extents_ea(inode, 0, 0xffffffff);        
        RETURN(rc);
}
static int  smfs_init_extents_ea(struct inode *inode)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        int rc = 0;
        ENTRY;
        
        rc = fsfilt->fs_init_extents_ea(inode);        
        
        RETURN(rc);
}
static int smfs_set_dirty_flags(struct inode *inode, int flags)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        void   *handle;
        int    rc = 0;
        ENTRY;

        if (SMFS_INODE_OVER_WRITE(inode))
                RETURN(rc);
        /*FIXME later, the blocks needed in journal here will be recalculated*/
         handle = smfs_trans_start(inode, FSFILT_OP_SETATTR, NULL);
        if (IS_ERR(handle)) {
                CERROR("smfs_set_dirty_flag:no space for transaction\n");
                RETURN(-ENOSPC);
        }
        if ((!SMFS_INODE_DIRTY_WRITE(inode) && (!SMFS_INODE_OVER_WRITE(inode))) || 
             ((flags == SMFS_OVER_WRITE) && (SMFS_INODE_DIRTY_WRITE(inode)))) {        
                rc = fsfilt->fs_set_xattr(inode, handle, REINT_EXTENTS_FLAGS,
                                            &flags, sizeof(int));
                if (rc)
                        GOTO(out, rc);
        }
        if (flags == SMFS_OVER_WRITE)
                SMFS_SET_INODE_OVER_WRITE(inode);
        else
                SMFS_SET_INODE_DIRTY_WRITE(inode);
out:
        smfs_trans_commit(inode, handle, 0);
        RETURN(rc);
}

int smfs_post_rec_setattr(struct inode *inode, struct dentry *dentry, 
                          void  *data1, void  *data2)
{        
        struct smfs_super_info *sinfo;
        struct iattr *attr = (struct iattr *)data1;
        char   *buffer = NULL, *pbuf;
        int rc = 0, length = 0, buf_len = 0;
        ENTRY;

        sinfo = S2SMI(inode->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);
        
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);        

        buf_len = PAGE_SIZE;
        KML_BUF_REC_INIT(buffer, pbuf, buf_len);        
        rc = smfs_log_path(inode->i_sb, dentry, pbuf, buf_len);
        if (rc < 0)
                GOTO(exit, rc);
        
        length = rc;
        KML_BUF_REC_END(buffer, length, pbuf);
        
        rc = smfs_pack_rec(pbuf, dentry, inode, 
                           data1, data2, REINT_SETATTR);
        if (rc <= 0) 
                GOTO(exit, rc);
        else
                length += rc;

        rc = smfs_llog_add_rec(sinfo, (void*)buffer, length); 
        if (!rc) {
                if (attr && attr->ia_valid & ATTR_SIZE) {
                        smfs_remove_extents_ea(inode, attr->ia_size,
                                               0xffffffff);                                
                        if (attr->ia_size == 0)
                                smfs_set_dirty_flags(inode, SMFS_OVER_WRITE);
                        else
                                smfs_set_dirty_flags(inode, SMFS_DIRTY_WRITE);
                }
        }
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        RETURN(rc);
}
 
static int all_blocks_present_ea(struct inode *inode)
{
        int rc = 0;
        ENTRY;
        RETURN(rc);        
}

int smfs_post_rec_write(struct inode *dir, struct dentry *dentry, void *data1, 
                        void *data2)
{
        struct smfs_super_info *sinfo;
        char   *buffer = NULL, *pbuf;
        int rc = 0, length = 0, buf_len = 0;
        ENTRY;
        
        if (!SMFS_INODE_OVER_WRITE(dentry->d_inode) && 
            !SMFS_INODE_DIRTY_WRITE(dentry->d_inode)) {
                sinfo = S2SMI(dentry->d_inode->i_sb);
                if (!sinfo)
                        RETURN(-EINVAL);
                
                OBD_ALLOC(buffer, PAGE_SIZE);
                if (!buffer)
                        GOTO(exit, rc = -ENOMEM);        
                
                buf_len = PAGE_SIZE;
                KML_BUF_REC_INIT(buffer, pbuf, buf_len);        
                rc = smfs_log_path(dir->i_sb, dentry, pbuf, buf_len);
                
                if (rc < 0)
                        GOTO(exit, rc);
                pbuf += rc;
                memcpy(buffer, &rc, sizeof(int));        
                length = rc + sizeof(int);
                        
                rc = smfs_pack_rec(pbuf, dentry, dir, 
                                   data1, data2, REINT_WRITE);
                if (rc <= 0) 
                        GOTO(exit, rc);
                else
                        length += rc;
 
                rc = smfs_llog_add_rec(sinfo, (void*)buffer, length);
                if (rc)
                        GOTO(exit, rc);
                rc = smfs_init_extents_ea(dentry->d_inode);
                if (rc)
                        GOTO(exit, rc);
        } 
        if (dentry->d_inode->i_size == 0) {
                smfs_set_dirty_flags(dentry->d_inode, SMFS_OVER_WRITE);        
        } else {
                /*insert extent EA*/
                loff_t off = *((loff_t*)data1);        
                size_t count = *((size_t*)data2);
                
                rc = smfs_insert_extents_ea(dentry->d_inode, off, count);        
                if (rc < 0)  
                        GOTO(exit, rc);        
                if (all_blocks_present_ea(dentry->d_inode)){
                        smfs_set_dirty_flags(dentry->d_inode, SMFS_OVER_WRITE);        
                        smfs_remove_all_extents_ea(dentry->d_inode);
                } else {
                        smfs_set_dirty_flags(dentry->d_inode, SMFS_DIRTY_WRITE);        
                }
        }
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);
        RETURN(rc);
}

/* new plugin API */
struct kml_priv {
        struct dentry * kml_llog_dir;
};

static int kml_create(struct inode * inode, void *arg) 
{
        struct hook_msg * msg = arg;
        return smfs_post_rec_create(inode, msg->dentry, NULL, NULL);
}

static int kml_link(struct inode * inode, void *arg) 
{
        struct hook_link_msg * msg = arg;
        return smfs_post_rec_link(inode, msg->dentry, msg->new_dentry, NULL);
}

static int kml_unlink(struct inode * inode, void *arg) 
{
        struct hook_unlink_msg * msg = arg;
        return smfs_post_rec_unlink(inode, msg->dentry, &msg->mode, NULL);
}

static int kml_symlink(struct inode * inode, void *arg) 
{
        struct hook_symlink_msg * msg = arg;
        return smfs_post_rec_create(inode, msg->dentry, &msg->tgt_len,
                                    msg->symname);
}

static int kml_rename(struct inode * inode, void *arg) 
{
        struct hook_rename_msg * msg = arg;
        return smfs_post_rec_rename(inode, msg->dentry, msg->new_dir,
                                    msg->new_dentry);
}

static int kml_setattr(struct inode * inode, void *arg) 
{
        struct hook_setattr_msg * msg = arg;
        return smfs_post_rec_setattr(inode, msg->dentry, msg->attr, NULL);
}

static int kml_write(struct inode * inode, void *arg) 
{
        struct hook_write_msg * msg = arg;
        return smfs_post_rec_write(inode, msg->dentry, &msg->count, &msg->pos);
}

typedef int (*post_kml_op)(struct inode * inode, void *msg);
static post_kml_op smfs_kml_post[HOOK_MAX] = {
        [HOOK_CREATE]  kml_create,
        [HOOK_LOOKUP]  NULL,
        [HOOK_LINK]    kml_link,
        [HOOK_UNLINK]  kml_unlink,
        [HOOK_SYMLINK] kml_symlink,
        [HOOK_MKDIR]   kml_create,
        [HOOK_RMDIR]   kml_unlink,
        [HOOK_MKNOD]   kml_create,
        [HOOK_RENAME]  kml_rename,
        [HOOK_SETATTR] kml_setattr,
        [HOOK_WRITE]   kml_write,
        [HOOK_READDIR] NULL,
};

static int smfs_kml_post_op(int code, struct inode * inode,
                            void * msg, int ret, void * priv)
{
        int rc = 0;
        
        ENTRY;
        CDEBUG(D_INODE,"KML: inode %lu, code: %u\n", inode->i_ino, code);
        //KML don't handle failed ops
        if (ret)
                RETURN(0);
        
        if (smfs_kml_post[code]) {
                rc = smfs_kml_post[code](inode, msg);
        }
                
        RETURN(rc);
}

/* Helpers */
static int smfs_exit_kml(struct super_block *sb, void * arg, struct kml_priv * priv)
{
        ENTRY;

        smfs_deregister_plugin(sb, SMFS_PLG_KML);
                
        EXIT;
        return 0;
}

static int smfs_trans_kml (struct super_block *sb, void *arg,
                           struct kml_priv * priv)
{
        int size;
        
        ENTRY;
        
        size = 20;//LDISKFS_INDEX_EXTRA_TRANS_BLOCKS+LDISKFS_DATA_TRANS_BLOCKS;
        
        RETURN(size);
}

static int smfs_start_kml(struct super_block *sb, void *arg,
                          struct kml_priv * kml_p)
{
        int rc = 0;
        struct smfs_super_info * smb = S2SMI(sb);
        struct llog_ctxt **ctxt = &smb->smsi_kml_log;

        ENTRY;
        //is plugin already activated
        if (SMFS_IS(smb->plg_flags, SMFS_PLG_KML))
                RETURN(0);
        
        //this will do OBD_ALLOC() for ctxt
        rc = llog_catalog_setup(ctxt, KML_LOG_NAME, smb->smsi_exp,
                                smb->smsi_ctxt, smb->sm_fsfilt,
                                smb->smsi_logs_dir,
                                smb->smsi_objects_dir);
        
        if (rc) {
                CERROR("Failed to initialize kml log list catalog %d\n", rc);
                RETURN(rc);
        }
        
        (*ctxt)->llog_proc_cb = smfs_llog_process_rec_cb;

        SMFS_SET(smb->plg_flags, SMFS_PLG_KML);

        RETURN(0);
}

int smfs_stop_kml(struct super_block *sb, void *arg,
                  struct kml_priv * kml_p)
{
        struct smfs_super_info * smb = S2SMI(sb);
        struct llog_ctxt *ctxt = smb->smsi_kml_log;
        ENTRY;

        if (!SMFS_IS(smb->plg_flags, SMFS_PLG_KML))
                RETURN(0);

        SMFS_CLEAR(smb->plg_flags, SMFS_PLG_KML);

        llog_catalog_cleanup(ctxt);
        OBD_FREE(ctxt, sizeof(*ctxt));
        
        RETURN(0);
}

typedef int (*kml_helper)(struct super_block * sb, void *msg, struct kml_priv *);
static kml_helper smfs_kml_helpers[PLG_HELPER_MAX] = {
        [PLG_EXIT]       smfs_exit_kml,
        [PLG_START]      smfs_start_kml,
        [PLG_STOP]       smfs_stop_kml,
        [PLG_TRANS_SIZE] smfs_trans_kml,
        [PLG_TEST_INODE] NULL,
        [PLG_SET_INODE]  NULL,
};

static int smfs_kml_help_op(int code, struct super_block * sb,
                            void * arg, void * priv)
{
        int rc = 0;
        ENTRY;
        if (smfs_kml_helpers[code])
                rc = smfs_kml_helpers[code](sb, arg, (struct kml_priv *) priv);
        RETURN(rc);
}

int smfs_init_kml(struct super_block *sb)
{
        int rc = 0;
        struct smfs_super_info *smb = S2SMI(sb);
        struct smfs_plugin plg = {
                .plg_type = SMFS_PLG_KML,
                .plg_pre_op = NULL,
                .plg_post_op = &smfs_kml_post_op,
                .plg_helper = &smfs_kml_help_op,
                .plg_private = NULL,
        };
        
        ENTRY;

        rc = ost_rec_pack_init(smb);
        if (rc)
                return rc;
        
        rc = mds_rec_pack_init(smb);
        if (rc)
                return rc;

        rc = smfs_register_plugin(sb, &plg);
        
        RETURN(rc);
}


