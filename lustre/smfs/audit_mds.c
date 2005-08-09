/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/audit_mds.c
 *  Lustre filesystem audit part for MDS
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
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/lustre_audit.h>
#include "smfs_internal.h"

static inline int audit_fill_id_rec (char **pbuf, struct inode * inode)
{
        struct fsfilt_operations *fsfilt = I2FOPS(inode);
        struct audit_id_record * rec = (void*)(*pbuf);
        int len = sizeof(*rec);
        struct lustre_fid fid;
        int rc = 0;
        
        rec->au_num = inode->i_ino;
        rec->au_type = (S_IFMT & inode->i_mode);
        rec->au_gen = inode->i_generation;
        
        //fid & mdsnum
        rc = fsfilt->fs_get_md(I2CI(inode), &fid, sizeof(fid), EA_SID);
        if (rc > 0) {
                rec->au_fid = fid.lf_id;
                rec->au_mds = fid.lf_group;
        }
        
        *pbuf += len;
        return len;
}

int static audit_mds_create_rec(struct inode * parent, void * arg,
                                struct audit_priv * priv, char * buffer,
                                __u32 * type)
{
        struct hook_msg * msg = arg;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec); 
        struct inode * inode = msg->dentry->d_inode;
        int len = sizeof(*rec);

        rec->opcode = AUDIT_CREATE;
        if (priv->result == 0) { //successfull operation
                len += audit_fill_id_rec(&pbuf, inode);
                *type = SMFS_AUDIT_GEN_REC;
        }
        else { //failed operation
                len += audit_fill_id_rec(&pbuf, parent);
                len += audit_fill_name_rec(&pbuf, msg->dentry->d_name.name,
                                           msg->dentry->d_name.len);
                
                *type = SMFS_AUDIT_NAME_REC;
        }
        return len;
}

int static audit_mds_link_rec(struct inode * parent, void * arg, 
                              struct audit_priv * priv, char * buffer,
                              __u32 *type)
{
        struct hook_link_msg * msg = arg;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        struct inode * inode = msg->dentry->d_inode;
        int len = sizeof(*rec);

        rec->opcode = AUDIT_LINK;
        
        /* these things will be needed always */
        len += audit_fill_id_rec(&pbuf, inode);
        len += audit_fill_id_rec(&pbuf, parent);
        len += audit_fill_name_rec(&pbuf, msg->dentry->d_name.name,
                                   msg->dentry->d_name.len);
        *type = SMFS_AUDIT_NAME_REC;
        
        return len;
}

int static audit_mds_unlink_rec(struct inode * parent, void * arg,
                                struct audit_priv * priv, char * buffer,
                                __u32 *type)
{
        struct hook_unlink_msg * msg = arg;
        struct inode * inode = msg->dentry->d_inode;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        int len = sizeof(*rec);
              
        rec->opcode = AUDIT_UNLINK;
        
        
        len += audit_fill_id_rec(&pbuf, inode);
        len += audit_fill_id_rec(&pbuf, parent);
        if (priv->result == 0) {
                len += audit_fill_name_rec(&pbuf, msg->dentry->d_name.name,
                                   msg->dentry->d_name.len);
                *type = SMFS_AUDIT_NAME_REC;
        } else {
                //in case of failure name shouldn't be saved
                *type = SMFS_AUDIT_GEN_REC;
        }
        
        return len;
}

int static audit_mds_rename_rec(struct inode * parent, void * arg, 
                                struct audit_priv * priv, char * buffer,
                                __u32 *type)
{
        struct hook_rename_msg * msg = arg;
        struct inode * inode = msg->dentry->d_inode;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        int len = sizeof(*rec);
        
        rec->opcode = AUDIT_RENAME;
        
        len += audit_fill_id_rec(&pbuf, inode);
        if (priv->result == 0) {
                len += audit_fill_id_rec(&pbuf, msg->old_dir);
                len += audit_fill_name_rec(&pbuf, msg->dentry->d_name.name,
                                           msg->dentry->d_name.len);
        } else { 
                len += audit_fill_id_rec(&pbuf, msg->new_dir);
                len += audit_fill_name_rec(&pbuf, msg->new_dentry->d_name.name,
                                           msg->new_dentry->d_name.len);
        }
        
        *type = SMFS_AUDIT_NAME_REC;
                
        return len;

}

int static audit_mds_setattr_rec(struct inode * inode, void * arg, 
                              struct audit_priv * priv, char * buffer,
                              __u32 *type)
{
        //struct hook_attr_msg * msg = arg;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        int len = sizeof(*rec);
        
        rec->opcode = AUDIT_SETATTR;
        len += audit_fill_id_rec(&pbuf, inode);
        *type = SMFS_AUDIT_GEN_REC;
                
        return len;
}

int static audit_mds_readlink_rec(struct inode * inode, void * arg, 
                                  struct audit_priv * priv, char * buffer,
                                  __u32 *type)
{
        //struct hook_symlink_msg * msg = arg;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        int len = sizeof(*rec);
        
        rec->opcode = AUDIT_READLINK;
        len += audit_fill_id_rec(&pbuf, inode);
        *type = SMFS_AUDIT_GEN_REC;
                
        return len;
}

int static audit_mds_readdir_rec(struct inode * inode, void * arg, 
                                 struct audit_priv * priv, char * buffer,
                                 __u32 *type)
{
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        int len = sizeof(*rec);
        
        rec->opcode = AUDIT_READDIR;
        len += audit_fill_id_rec(&pbuf, inode);
        *type = SMFS_AUDIT_GEN_REC;
                
        return len;
}

/* for special records from failed auth and open/stat*/
int audit_mds_special_rec(struct inode * inode, void * arg,
                          struct audit_priv * priv, char *buffer,
                          __u32 * type)
{
        struct audit_info * info = arg;
        struct audit_msg * msg = &info->m;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        int len = sizeof(*rec);
                
        //rewrite some fields
        rec->opcode = msg->code;
        rec->result = msg->result;
        rec->uid = msg->uid;
        rec->gid = msg->gid;
        rec->nid = msg->nid;
        
        len += audit_rec_from_id(&pbuf, &msg->id);
        switch (rec->opcode)
        {
                case AUDIT_OPEN:
                case AUDIT_CREATE:
                        if (info->name && info->namelen > 0) { 
                                len += audit_fill_name_rec(&pbuf,
                                                           info->name,
                                                           info->namelen);
                                *type = SMFS_AUDIT_NAME_REC;
                                break;
                        }
                default:
                        *type = SMFS_AUDIT_GEN_REC;
        }
        
        return len;
}

static audit_get_op audit_mds_record[HOOK_MAX] = {
        [HOOK_CREATE]     audit_mds_create_rec,
        [HOOK_LINK]       audit_mds_link_rec,
        [HOOK_UNLINK]     audit_mds_unlink_rec,
        [HOOK_SYMLINK]    audit_mds_create_rec,
        [HOOK_READLINK]   audit_mds_readlink_rec,
        [HOOK_MKDIR]      audit_mds_create_rec,
        [HOOK_RMDIR]      audit_mds_unlink_rec,
        [HOOK_MKNOD]      audit_mds_create_rec,
        [HOOK_RENAME]     audit_mds_rename_rec,
        [HOOK_SETATTR]    audit_mds_setattr_rec,
        [HOOK_F_SETATTR]  audit_mds_setattr_rec,
        [HOOK_SPECIAL]    audit_mds_special_rec,
        [HOOK_READDIR]    audit_mds_readdir_rec,
};

int audit_mds_setup(struct obd_device * obd, struct super_block *sb,
                    struct audit_priv *priv) 
{
        int rc;
        struct smfs_super_info * smb = S2SMI(sb);
        struct llog_ctxt **ctxt = &priv->audit_ctxt;
        
        //this will do OBD_ALLOC() for ctxt
        rc = llog_catalog_setup(ctxt, AUDIT_MDS_NAME, smb->smsi_exp,
                                smb->smsi_ctxt, smb->sm_fsfilt,
                                smb->smsi_logs_dir, smb->smsi_objects_dir);

        /* export audit llog ctxt */
        if (*ctxt) {
                (*ctxt)->loc_idx = LLOG_AUDIT_ORIG_CTXT;
                (*ctxt)->loc_obd = obd;
                (*ctxt)->loc_llogs = &obd->obd_llogs;
                (*ctxt)->loc_llogs->llog_ctxt[LLOG_AUDIT_ORIG_CTXT] = *ctxt;
        }
        priv->audit_get_record = &audit_mds_record;
        return 0;
}
