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

static int audit_ost_get_id(struct inode * inode, struct lustre_id * id) 
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;
        
        ENTRY;
        if(fsfilt->fs_get_md(inode, id, sizeof(*id), EA_SID) <= 0)
                RETURN(-ENODATA);

        RETURN(0);        
}
#if 0
static int audit_ost_create_rec(struct inode * parent, void * arg,
                                struct audit_priv * priv, char * buffer,
                                __u32 * type)
{
        struct hook_msg * msg = arg;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec); 
        struct inode * inode = msg->dentry->d_inode;
        struct lustre_id id;
        int len = sizeof(*rec);

        if (audit_ost_get_id(inode, &id) < 0) 
                CERROR("Cannot get lustre id from object EA\n");

        rec->opcode = AUDIT_CREATE;
        len += audit_rec_from_id(&pbuf, &id);
        *type = SMFS_AUDIT_GEN_REC;
        return len;
}

static int audit_ost_unlink_rec(struct inode * parent, void * arg,
                                struct audit_priv * priv, char * buffer,
                                __u32 *type)
{
        struct hook_unlink_msg * msg = arg;
        struct inode * inode = msg->dentry->d_inode;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        int len = sizeof(*rec);
        struct lustre_id id;
        
        if (audit_ost_get_id(inode, &id) < 0) 
                CERROR("Cannot get lustre id from object EA\n");

        rec->opcode = AUDIT_UNLINK;
        len += audit_rec_from_id(&pbuf, &id);
        //len += audit_fill_id_rec(&pbuf, parent);
        *type = SMFS_AUDIT_GEN_REC;
        
        return len;        
}

int static audit_ost_setattr_rec(struct inode * inode, void * arg, 
                                 struct audit_priv * priv, char * buffer,
                                 __u32 *type)
{
        //struct hook_attr_msg * msg = arg;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec);
        int len = sizeof(*rec);
        struct lustre_id id;
        
        if (audit_ost_get_id(inode, &id) < 0) 
                CERROR("Cannot get lustre id from object EA\n");

        rec->opcode = AUDIT_SETATTR;
        len += audit_rec_from_id(&pbuf, &id);
        *type = SMFS_AUDIT_GEN_REC;
                
        return len;
}
#endif
int static audit_ost_rw_rec(struct inode * inode, void * arg, 
                            struct audit_priv * priv, char * buffer,
                            __u32 * type)
{
        struct hook_rw_msg * msg = arg;
        struct audit_record * rec = (void*)buffer;
        char * pbuf = buffer + sizeof(*rec); 
        int len = sizeof(*rec);
        struct lustre_id id;

        if (audit_ost_get_id(inode, &id) < 0) 
                CERROR("Cannot get lustre id from object EA\n");

        rec->opcode = msg->write ? AUDIT_WRITE : AUDIT_READ;
        len += audit_rec_from_id(&pbuf, &id);
        *type = SMFS_AUDIT_GEN_REC;
        
        return len;
}

static audit_get_op audit_ost_record[HOOK_MAX] = {
        [HOOK_SI_READ]      audit_ost_rw_rec,
        [HOOK_SI_WRITE]     audit_ost_rw_rec,
        [HOOK_READ]         audit_ost_rw_rec,
        [HOOK_WRITE]        audit_ost_rw_rec,
        [HOOK_CREATE]       NULL, /* audit_ost_create_rec, */
        [HOOK_UNLINK]       NULL, //audit_ost_unlink_rec,
        [HOOK_SETATTR]      NULL, //audit_ost_setattr_rec,
        [HOOK_F_SETATTR]    NULL, //audit_ost_setattr_rec
};

int audit_ost_setup(struct obd_device * obd, struct super_block *sb,
                    struct audit_priv *priv) 
{
        int rc;
        struct smfs_super_info * smb = S2SMI(sb);
        struct llog_ctxt **ctxt = &priv->audit_ctxt;
        
        //this will do OBD_ALLOC() for ctxt
        rc = llog_catalog_setup(ctxt, AUDIT_OST_NAME, smb->smsi_exp,
                                smb->smsi_ctxt, smb->sm_fsfilt,
                                smb->smsi_logs_dir, smb->smsi_objects_dir);
        
        /* export audit llog ctxt */
        if (*ctxt) {
                (*ctxt)->loc_idx = LLOG_AUDIT_ORIG_CTXT;
                (*ctxt)->loc_obd = obd;
                (*ctxt)->loc_llogs = &obd->obd_llogs;
                (*ctxt)->loc_llogs->llog_ctxt[LLOG_AUDIT_ORIG_CTXT] = *ctxt;
        }
        
        priv->audit_get_record = audit_ost_record;
        return 0;
}
