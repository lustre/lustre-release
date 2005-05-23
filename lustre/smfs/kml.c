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

#if 0
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
#endif

int smfs_rec_unpack(struct smfs_proc_args *args, char *record, 
                    char **pbuf, int *opcode)
{
        //int offset = *(int *)(record);
        //char *tmp = record + offset + sizeof(int);

        *opcode = *(int *)record;
        *pbuf = record + sizeof(*opcode);
        return 0;
}
EXPORT_SYMBOL(smfs_rec_unpack); /* cmobd/cm_reint.c */

int smfs_write_extents(struct inode *dir, struct dentry *dentry,
                       unsigned long from, unsigned long num)
{
        return 0;//smfs_post_rec_write(dir, dentry, &from, &num);
}
#if 0
int smfs_rec_precreate(struct dentry *dentry, int *num, struct obdo *oa)
{
       return smfs_post_rec_create(dentry->d_inode, dentry, num, oa);
}

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
#endif

#if 0
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
         handle = smfs_trans_start(inode, FSFILT_OP_SETATTR);
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

static int all_blocks_present_ea(struct inode *inode)
{
        int rc = 0;
        ENTRY;
        RETURN(rc);        
}
#endif

/* new plugin API */
#if 0
static int kml_pack_path (char **buf, struct dentry * dentry)
{
        char *pbuf;
        int length = 0, rc = 0;
        
        OBD_ALLOC(*buf, PAGE_SIZE);
        if (*buf == NULL)
                return -ENOMEM;        

        length = PAGE_SIZE;
        KML_BUF_REC_INIT(*buf, pbuf, length);
        rc = smfs_log_path(dentry->d_sb, dentry, pbuf, length);
        if (rc < 0) {
                return rc;
        }
        
        length = rc;
        KML_BUF_REC_END(*buf, length, pbuf);  
        
        return length;
}
#endif
static int kml_create(struct inode * inode, void *arg, struct kml_priv * priv) 
{
        struct hook_msg * msg = arg;
        //return smfs_post_rec_create(inode, msg->dentry, NULL, NULL);
        struct smfs_super_info *smb = S2SMI(inode->i_sb);
        char   *buffer = NULL;
        int rc = 0, length = 0;
        ENTRY;
        
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (buffer == NULL)
                return -ENOMEM;    
        
        /*
        rc = kml_pack_path(&buffer, msg->dentry);
        if (rc < 0)
                goto exit;
        
        length = rc;
        pbuf = buffer + length;
        */        
        rc = priv->pack_fn(REINT_CREATE, buffer, msg->dentry, inode,
                           NULL, NULL);
        if (rc <= 0)
                GOTO(exit, rc);
        
        length += rc;
        rc = smfs_llog_add_rec(smb, (void*)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        
        RETURN(rc);
}

static int kml_link(struct inode * inode, void *arg, struct kml_priv * priv) 
{
        struct hook_link_msg * msg = arg;
        int rc = 0, length = 0, buf_len = 0;
        char *buffer = NULL, *pbuf = NULL;
        struct smfs_super_info *smb;
        ENTRY;
        
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        
        rc = priv->pack_fn(REINT_LINK, buffer, msg->dentry, inode, 
                           msg->dentry, msg->new_dentry);
        if (rc <= 0)
                GOTO(exit, rc);
        
        length += rc;
        rc = smfs_llog_add_rec(S2SMI(inode->i_sb), (void *)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        
        RETURN(rc);
}

static int kml_unlink(struct inode * inode, void *arg, struct kml_priv * priv) 
{
        struct hook_unlink_msg * msg = arg;
        char   *buffer = NULL;
        int  length = 0, rc = 0;
        ENTRY;
         
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);        
      
        rc = priv->pack_fn(REINT_UNLINK, buffer, msg->dentry, inode, 
                           &msg->mode, NULL);
        if (rc <= 0)
                GOTO(exit, rc);
        
        length += rc;         
        rc = smfs_llog_add_rec(S2SMI(inode->i_sb), (void*)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        
        RETURN(rc);
}

static int kml_symlink(struct inode * inode, void *arg, struct kml_priv * priv) 
{
        struct hook_symlink_msg * msg = arg;
        struct smfs_super_info *smb = S2SMI(inode->i_sb);
        char   *buffer = NULL, *pbuf;
        int rc = 0, length = 0;
        ENTRY;
        
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);        

        rc = priv->pack_fn(REINT_CREATE, buffer, msg->dentry, inode,
                           msg->symname, &msg->tgt_len);
        if (rc <= 0)
                GOTO(exit, rc);
        
        length += rc;
        rc = smfs_llog_add_rec(smb, (void*)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        
        RETURN(rc);
}

static int kml_rename(struct inode * inode, void *arg, struct kml_priv * priv) 
{
        struct hook_rename_msg * msg = arg;
        char *buffer = NULL, *pbuf = NULL;
        int rc = 0, length = 0, buf_len = 0;
        ENTRY;
        
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        
        rc = priv->pack_fn(REINT_RENAME, buffer, msg->dentry, inode, 
                           msg->new_dir, msg->new_dentry);
        if (rc <= 0) 
                GOTO(exit, rc);
        length += rc;
        
        rc = smfs_llog_add_rec(S2SMI(inode->i_sb), (void*)buffer, length); 
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);
        RETURN(rc);
}

static int kml_setattr(struct inode * inode, void *arg, struct kml_priv * priv) 
{
        struct hook_setattr_msg * msg = arg;
        char   *buffer = NULL, *pbuf;
        int rc = 0, length = 0, buf_len = 0;
        ENTRY;

        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);        

        rc = priv->pack_fn(REINT_SETATTR, buffer, msg->dentry, inode, 
                           msg->attr, NULL);
        if (rc <= 0) 
                GOTO(exit, rc);
        
        length += rc;
        rc = smfs_llog_add_rec(S2SMI(inode->i_sb), (void*)buffer, length); 
        /*
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
        */
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE);        
        RETURN(rc);
}
/*
static int kml_write(struct inode * inode, void *arg, struct kml_priv * priv) 
{
        struct hook_write_msg * msg = arg;
        //return smfs_post_rec_write(inode, msg->dentry, &msg->count, &msg->pos);
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
                //insert extent EA
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
*/

typedef int (*post_kml_op)(struct inode * inode, void *msg, struct kml_priv * priv);
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
        [HOOK_WRITE]   NULL,
        [HOOK_READDIR] NULL,
};

static int smfs_kml_post_op(int code, struct inode * inode,
                            void * msg, int ret, void * priv)
{
        int rc = 0;
        
        ENTRY;
                
        //KML don't handle failed ops
        if (ret)
                RETURN(0);
        
        if (smfs_kml_post[code]) {
                CDEBUG(D_INODE,"KML: inode %lu, code: %u\n", inode->i_ino, code);
                rc = smfs_kml_post[code](inode, msg, priv);
        }
                
        RETURN(rc);
}

/* Helpers */
static int smfs_exit_kml(struct super_block *sb, void * arg, struct kml_priv * priv)
{
        ENTRY;

        smfs_deregister_plugin(sb, SMFS_PLG_KML);
        OBD_FREE(priv, sizeof(*priv));
        
        EXIT;
        return 0;
}

static int smfs_trans_kml (struct super_block *sb, void *arg,
                           struct kml_priv * priv)
{
        int size;
        
        //TODO: pass fs opcode and see if kml can participate or not
        //one record in log per operation
        size = 1;
        
        return size;
}

extern int mds_rec_pack(int, char*, struct dentry*, struct inode*, void*, void*);

static int smfs_start_kml(struct super_block *sb, void *arg,
                          struct kml_priv * kml_p)
{
        int rc = 0;
        struct smfs_super_info * smb = S2SMI(sb);
        struct llog_ctxt **ctxt = &smb->smsi_kml_log;
        struct obd_device *obd = arg;

        ENTRY;
        //is plugin already activated
        if (SMFS_IS(smb->plg_flags, SMFS_PLG_KML))
                RETURN(0);
        
        if (obd && obd->obd_type && obd->obd_type->typ_name) {
                if (strcmp(obd->obd_type->typ_name, "mds"))
                        RETURN(0);                
        }
        
        kml_p->pack_fn = mds_rec_pack;
        
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
        
        if (smfs_kml_helpers[code])
                rc = smfs_kml_helpers[code](sb, arg, (struct kml_priv *) priv);
        return rc;
}

int smfs_init_kml(struct super_block *sb)
{
        int rc = 0;
        struct kml_priv * priv = NULL;
        struct smfs_plugin plg = {
                .plg_type = SMFS_PLG_KML,
                .plg_pre_op = NULL,
                .plg_post_op = &smfs_kml_post_op,
                .plg_helper = &smfs_kml_help_op,
                .plg_private = NULL,
        };
        
        ENTRY;

        OBD_ALLOC(priv, sizeof(*priv));
        if (!priv) {
                RETURN(-ENOMEM);
        }

        plg.plg_private = priv;
        /*
        rc = ost_rec_pack_init(smb);
        if (rc)
                return rc;
        
        rc = mds_rec_pack_init(smb);
        if (rc)
                return rc;
        */
        rc = smfs_register_plugin(sb, &plg);
        
        RETURN(rc);
}


