/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/journal.c
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

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/lvfs.h>
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

void *smfs_trans_start(struct inode *inode, int op, void *desc_private)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;

        CDEBUG(D_INFO, "trans start %p\n", fsfilt->fs_start);

        SMFS_TRANS_OP(inode, op);

        /* There are some problem here. fs_start in fsfilt is used by lustre
         * the journal blocks of write rec are not counted in FIXME later */
        if (fsfilt->fs_start)
                return fsfilt->fs_start(inode, op, desc_private, 0);
        return NULL;
}

void smfs_trans_commit(struct inode *inode, void *handle, int force_sync)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;

        CDEBUG(D_INFO, "trans commit %p\n", fsfilt->fs_commit);

        if (fsfilt->fs_commit)
                fsfilt->fs_commit(inode, handle, force_sync);
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
        int rc;

        pack_func = smfs_get_rec_pack_type(dir->i_sb);
        if (!pack_func) {
                return (0);
        }
        rc = pack_func(buffer, dentry, dir, data1, data2, op);
        return rc;
}

static int smfs_post_rec_create(struct inode *dir, 
                                struct dentry *dentry,
                                 void   *data1,
                                void   *data2)
{
        struct smfs_super_info *sinfo;
        char   *buffer = NULL, *pbuf;
        int rc = 0, length = 0, buf_len = 0;
        
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

static int smfs_post_rec_link(struct inode *dir, 
                              struct dentry *dentry,
                               void   *data1,
                              void   *data2)
{
        struct smfs_super_info *sinfo;
        struct dentry *old_dentry = (struct dentry *)data1;
        char *buffer = NULL, *pbuf = NULL;
        int rc = 0, length = 0, buf_len = 0;
        
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
        
        rc = smfs_pack_rec(pbuf, dentry, dir, dentry->d_parent, 
                           old_dentry->d_parent, REINT_LINK);
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

static int smfs_post_rec_unlink(struct inode *dir, struct dentry *dentry,
                                void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        int mode = *((int*)data1);
        char   *buffer = NULL, *pbuf = NULL;
        int  length = 0, rc = 0, buf_len = 0;
         
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

static int smfs_post_rec_rename(struct inode *dir, 
                                 struct dentry *dentry,
                                 void   *data1,
                                void   *data2)
{
        struct smfs_super_info *sinfo;
        struct inode *new_dir = (struct inode *)data1;
        struct dentry *new_dentry = (struct dentry *)data2;
        char *buffer = NULL, *pbuf = NULL;
        int rc = 0, length = 0, buf_len = 0;
        
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
        /*record new_dentry path*/        
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
        
        rc = fsfilt->fs_remove_extents_ea(inode, OFF2BLKS(from, inode), 
                                          SIZE2BLKS(num, inode));        
        
        RETURN(rc);
}

static int smfs_remove_all_extents_ea(struct inode *inode)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        int rc = 0;
        
        rc = fsfilt->fs_remove_extents_ea(inode, 0, 0xffffffff);        
        RETURN(rc);
}
static int  smfs_init_extents_ea(struct inode *inode)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        int rc = 0;
        
        rc = fsfilt->fs_init_extents_ea(inode);        
        
        RETURN(rc);
}
static int smfs_set_dirty_flags(struct inode *inode, int flags)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        void   *handle;
        int    rc = 0;

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
        
        RETURN(rc);        
}
int smfs_post_rec_write(struct inode *dir, struct dentry *dentry,
                        void   *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        char   *buffer = NULL, *pbuf;
        int rc = 0, length = 0, buf_len = 0;
        
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

typedef int (*post_kml_rec)(struct inode *dir, struct dentry *dentry,
                            void *data1, void *data2);

static post_kml_rec smfs_kml_post[REINT_MAX + 1] = {
        [REINT_SETATTR] smfs_post_rec_setattr,
        [REINT_CREATE]  smfs_post_rec_create,
        [REINT_LINK]    smfs_post_rec_link,
        [REINT_UNLINK]  smfs_post_rec_unlink,
        [REINT_RENAME]  smfs_post_rec_rename,
        [REINT_WRITE]   smfs_post_rec_write,
};

int smfs_post_kml_rec(struct inode *dir, struct dentry *dst_dentry,
                      void *data1, void *data2, int op)
{
        return smfs_kml_post[op](dir, dst_dentry, data1, data2);
}
