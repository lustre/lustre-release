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
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/lustre_audit.h>
#include <linux/lustre_log.h>
#include "smfs_internal.h"

static audit_op hook2audit(hook_op hook)
{
        audit_op opcode = AUDIT_UNKNOWN;

        switch (hook) 
        {
                case HOOK_CREATE:
                case HOOK_SYMLINK:
                case HOOK_MKDIR:
                case HOOK_MKNOD:
                        return AUDIT_CREATE;
                        
                case HOOK_LINK:
                        return AUDIT_LINK;
                                                
                case HOOK_RMDIR:
                case HOOK_UNLINK:
                        return AUDIT_UNLINK;
                        
                case HOOK_READLINK:
                        return AUDIT_READLINK;
                        
                case HOOK_RENAME:
                        return AUDIT_RENAME;
                        
                case HOOK_SETATTR:
                case HOOK_F_SETATTR:
                        return AUDIT_SETATTR;
                        
                case HOOK_SI_WRITE:
                case HOOK_WRITE:
                        return AUDIT_WRITE;
                        
                case HOOK_SI_READ:
                case HOOK_READ:
                        return AUDIT_READ;

                case HOOK_READDIR:
                        return AUDIT_READDIR;

                default:
                        break;
        }
        
        return opcode;
}

struct inode * get_inode_from_hook(hook_op hook, void * msg) 
{
        struct inode * inode;
        
        switch (hook)
        {
                case HOOK_LINK:
                {
                        struct hook_link_msg * m = msg;
                        inode = m->dentry->d_inode;
                        break;
                }
                case HOOK_UNLINK:
                case HOOK_RMDIR:
                {
                        struct hook_unlink_msg * m = msg;
                        inode = m->dentry->d_inode;
                        break;
                }
                case HOOK_READLINK:
                {
                        struct hook_symlink_msg * m = msg;
                        inode = m->dentry->d_inode;
                        break;
                }        
                case HOOK_RENAME:
                {
                        struct hook_rename_msg * m = msg;
                        inode = m->dentry->d_inode;
                        break;
                }        
                default:
                        inode = NULL;
        }

        return inode;
}

static inline int smfs_get_inode_audit(struct inode *inode, __u64 *mask)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_cache_fsfilt;
        struct smfs_inode_info * smi = I2SMI(inode);
        int rc = 0;
        
        /* omit __iopen__ dir */
        if (inode->i_ino == SMFS_IOPEN_INO) {
                *mask = AUDIT_OFF;
                RETURN(-ENOENT);
        }
        if (smi->au_info.au_valid)
                *mask = smi->au_info.au_mask;
        else {
                rc = fsfilt->fs_get_xattr(I2CI(inode), AUDIT_ATTR_EA,
                                          mask, sizeof(*mask));
                if (rc <= 0)
                        *mask = AUDIT_OFF;
                smi->au_info.au_valid = 1;
                smi->au_info.au_mask = *mask;
        }
        RETURN(0);
}

/* is called also from fsfilt_smfs_get_info */
int smfs_get_audit(struct super_block * sb, struct inode * parent,
                   struct inode * inode,  __u64 * mask)
{
        struct smfs_super_info * smb = S2SMI(sb);
        struct obd_device * obd = smb->smsi_exp->exp_obd;
        struct audit_priv * priv = NULL;
        
        ENTRY;
        
        if (!SMFS_IS(smb->plg_flags, SMFS_PLG_AUDIT))
                RETURN(-EINVAL);
        
        priv = smfs_get_plg_priv(S2SMI(sb), SMFS_PLG_AUDIT);
              
        if (!priv)
                RETURN(-ENOENT);
        
        if (IS_AUDIT(priv->a_mask)) {
                /* no audit for directories on OSS */
                if (inode && S_ISDIR(inode->i_mode) &&
                    !strcmp(obd->obd_type->typ_name, OBD_FILTER_DEVICENAME))
                        RETURN(-EINVAL);
                (*mask) = priv->a_mask;
                RETURN(0);
        }
        
        /* get inode audit EA */
        if (parent) {
                smfs_get_inode_audit(parent, mask);
                /* check if parent has audit */
                if (IS_AUDIT(*mask))
                        RETURN(0);
        }
        
        if (inode) {
                smfs_get_inode_audit(inode, mask);
                if (IS_AUDIT(*mask))
                        RETURN(0);
        }

        RETURN(-ENODATA);
}

int smfs_audit_check(struct inode * parent, hook_op hook, int ret,
                     struct audit_priv * priv, void * msg)
{
        audit_op code;
        struct inode * inode = NULL;
        __u64 mask = 0;
        int rc = 0;
        
        ENTRY;

        if (hook == HOOK_SPECIAL) { 
                struct audit_info * info = msg;
                code = info->m.code;
                inode = info->child;
        }
        else {
                inode = get_inode_from_hook(hook, msg);
                code = hook2audit(hook);
        }
        
        rc = smfs_get_audit(parent->i_sb, parent, inode, &mask);
        
        if (rc < 0)
                RETURN(0);

        //should only failures be audited?
        if (ret >= 0 && IS_AUDIT_OP(mask, AUDIT_FAIL))
                RETURN(0); 

        //check audit mask
        RETURN(IS_AUDIT_OP(mask, code));
}

static int smfs_set_fs_audit (struct super_block * sb, __u64 *mask)
{
        struct smfs_super_info * smb = S2SMI(sb);
        struct fsfilt_operations * fsfilt = smb->sm_fsfilt;
        int rc = 0;
        loff_t off = 0;
        struct file * f = NULL;
        struct audit_priv *priv;
        struct lvfs_run_ctxt * ctxt, saved;
        ENTRY;
        
        ctxt = &smb->smsi_exp->exp_obd->obd_lvfs_ctxt;
        
        priv = smfs_get_plg_priv(smb, SMFS_PLG_AUDIT);
        if(!priv) {
                CERROR("Audit is not initialized, use mountoptions 'audit'\n");
                RETURN(-EINVAL);
        }
        
        push_ctxt(&saved, ctxt, NULL);

        f = filp_open(AUDIT_ATTR_FILE, O_RDWR|O_CREAT, 0600);
        if (IS_ERR(f)) {
                CERROR("cannot get audit_setting file\n");
                rc = -EINVAL;
                goto exit;
        }
                
        rc = fsfilt->fs_write_record(f, mask, sizeof(*mask), &off, 1);
        if (rc) {
                CERROR("error writting audit setting: rc = %d\n", rc);
                goto exit;
        }
        
        priv->a_mask = (*mask);
        
exit:
        if (f)
                filp_close(f, 0);

        pop_ctxt(&saved, ctxt, NULL);

        RETURN (rc);
}

//set audit attributes for directory/file
int smfs_set_audit(struct super_block * sb, struct inode * inode,
                   __u64 * mask)
{
        void * handle = NULL;
        struct fsfilt_operations * fsfilt = S2SMI(sb)->sm_fsfilt;
        struct smfs_inode_info *smi = NULL;
        int rc = 0;
        
        ENTRY;
        
        if (IS_AUDIT_OP((*mask), AUDIT_FS))
                return smfs_set_fs_audit(sb, mask);

        LASSERT(inode);
        smi = I2SMI(inode);
        /* save audit EA in inode_info */
        if (rc >= 0) {
                smi->au_info.au_mask = *mask;
                smi->au_info.au_valid = 1;
        }
        
        handle = fsfilt->fs_start(inode, FSFILT_OP_SETATTR, NULL, 0);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));
        
        if (fsfilt->fs_set_xattr)
                rc = fsfilt->fs_set_xattr(inode, handle, AUDIT_ATTR_EA,
                                          mask, sizeof(*mask));
        fsfilt->fs_commit(inode->i_sb, inode, handle, 1);
        RETURN(rc);
                                
}

static int smfs_audit_post_op(hook_op code, struct inode * inode, void * msg,
                              int ret, void * arg)
{
        int rc = 0, len;
        char * buffer = NULL;
        struct audit_record * rec = NULL;
        struct llog_rec_hdr * llh;
        struct timeval cur_time;
        struct audit_priv * priv = arg;
        audit_get_op * handler = priv->audit_get_record;

        //check that we are in lustre ctxt
        if (!SMFS_IS(I2SMI(inode)->smi_flags, SMFS_PLG_AUDIT))
                return 0;
        
        if (!handler || !handler[code])
                return 0;
        
        if (smfs_audit_check(inode, code, ret, priv, msg) == 0)
                return 0;

        ENTRY;
        
        do_gettimeofday(&cur_time);

        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                RETURN(-ENOMEM);
        
        llh = (void*)buffer;
        //fill common fields
        rec = (void*)(buffer + sizeof(*llh));
               
        rec->result = ret;
        rec->uid = current->uid;
        rec->gid = current->gid;
        rec->nid = current->user->nid;
        rec->time = cur_time.tv_sec * USEC_PER_SEC + cur_time.tv_usec;
        
        len = handler[code](inode, msg, priv, (char*)rec,
                                           &llh->lrh_type);
        
        LASSERT(llh->lrh_type == SMFS_AUDIT_GEN_REC ||
                llh->lrh_type == SMFS_AUDIT_NAME_REC);

        llh->lrh_len = size_round(len);

        rc = llog_cat_add_rec(priv->audit_ctxt->loc_handle, llh, NULL,
                              (void*)rec, NULL, NULL); 
        if (rc != 0) {
                CERROR("Error adding audit record: %d\n", rc);
                rc= -EINVAL;
        } else {
                audit_notify(priv->audit_ctxt->loc_handle, priv->au_id2name);
        }
        
        OBD_FREE(buffer, PAGE_SIZE);
        
        RETURN(rc);
}

/* Helpers */
static int smfs_trans_audit (struct super_block *sb, void *arg,
                           struct audit_priv * priv)
{
        int size = 1; //one record in log per operation.

        return size;
}

extern int mds_alloc_inode_ids(struct obd_device *, struct inode *,
                        void *, struct lustre_id *, struct lustre_id *);

static int smfs_start_audit(struct super_block *sb, void *arg,
                          struct audit_priv * audit_p)
{
        struct smfs_super_info * smb = S2SMI(sb);
        struct fsfilt_operations * fsfilt = smb->sm_fsfilt;
        struct obd_device *obd = arg;
        struct file * f;
        int rc = 0;

        ENTRY;

        //is plugin already activated
        if (SMFS_IS(smb->plg_flags, SMFS_PLG_AUDIT))
                RETURN(0);
        
        rc = audit_start_transferd();
        if (rc) {
                CERROR("can't start audit transfer daemon. rc:%d\n", rc);
                RETURN(rc);
        }
        
        if (obd && obd->obd_type && obd->obd_type->typ_name) {
                if (!strcmp(obd->obd_type->typ_name, "mds")) {
                        CDEBUG(D_INODE, "Setup MDS audit handler\n");
                        audit_mds_setup(obd, sb, audit_p);
                }
                else if (!strcmp(obd->obd_type->typ_name, "obdfilter")) {
                        CDEBUG(D_INODE, "Setup OST audit handler\n");
                        audit_ost_setup(obd, sb, audit_p);
                }
                else {
                        CDEBUG(D_INODE, "Unknown obd type %s\n",
                               obd->obd_type->typ_name);       
                        RETURN(0);
                }
        }
        //read fs audit settings if any
	audit_p->a_mask = AUDIT_OFF;

        f = filp_open(AUDIT_ATTR_FILE, O_RDONLY, 0644);
        if (!IS_ERR(f)) {
                loff_t off = 0;
                rc = fsfilt->fs_read_record(f, &audit_p->a_mask, 
                                        sizeof(audit_p->a_mask), &off);
                if (rc) {
                        CERROR("error reading audit setting: rc = %d\n", rc);
                }
                filp_close(f, 0);
        }
        
        SMFS_SET(smb->plg_flags, SMFS_PLG_AUDIT);

        RETURN(0);
}

int smfs_stop_audit(struct super_block *sb, void *arg,
                  struct audit_priv * audit_p)
{
        struct smfs_super_info * smb = S2SMI(sb);
        struct llog_ctxt *ctxt = audit_p->audit_ctxt;
        ENTRY;

        if (!SMFS_IS(smb->plg_flags, SMFS_PLG_AUDIT))
                RETURN(0);

        audit_stop_transferd();

        SMFS_CLEAR(smb->plg_flags, SMFS_PLG_AUDIT);

        if (ctxt->loc_llogs)
                ctxt->loc_llogs->llog_ctxt[LLOG_AUDIT_ORIG_CTXT] = NULL;

        llog_catalog_cleanup(ctxt);
        OBD_FREE(ctxt, sizeof(*ctxt));
        audit_p->audit_ctxt = NULL;
        
        RETURN(0);
}

int smfs_audit_set_info(struct super_block *sb, void *arg,
                        struct audit_priv *priv) {
        struct plg_info_msg * msg = arg;
        if (KEY_IS(msg->key, "id2name")) {
                priv->au_id2name = msg->val;
        }
                         
        return 0;
}

typedef int (*audit_helper)(struct super_block * sb, void *msg, struct audit_priv *);
static audit_helper smfs_audit_helpers[PLG_HELPER_MAX] = {
        [PLG_START]      smfs_start_audit,
        [PLG_STOP]       smfs_stop_audit,
        [PLG_TRANS_SIZE] smfs_trans_audit,
        [PLG_TEST_INODE] NULL,
        [PLG_SET_INODE]  NULL,
        [PLG_SET_INFO]   smfs_audit_set_info,
};

static int smfs_audit_help_op(int code, struct super_block * sb,
                            void * arg, void * priv)
{
        int rc = 0;
        
        if (smfs_audit_helpers[code])
                rc = smfs_audit_helpers[code](sb, arg, (struct audit_priv *) priv);
        return rc;
}

static int smfs_exit_audit(struct super_block *sb, 
                           void * arg)
{
        struct audit_priv * priv = arg;
        struct smfs_plugin * plg;
        ENTRY;

        plg = smfs_deregister_plugin(sb, SMFS_PLG_AUDIT);
        if (plg)
                OBD_FREE(plg, sizeof(*plg));
        else
                CERROR("Cannot find AUDIT plugin while unregistering\n");
        
        if (priv)
                OBD_FREE(priv, sizeof(*priv));
        
        RETURN(0);
}

int smfs_init_audit(struct super_block *sb)
{
        int rc = 0;
        struct audit_priv * priv = NULL;
        struct smfs_plugin * plg = NULL;

        ENTRY;
        
        OBD_ALLOC(plg, sizeof(*plg));
        if (!plg) {
                rc = -ENOMEM;
                goto exit;
        }
        
        plg->plg_type = SMFS_PLG_AUDIT;
        plg->plg_post_op = &smfs_audit_post_op;
        plg->plg_helper = &smfs_audit_help_op;
        plg->plg_exit = &smfs_exit_audit;

        OBD_ALLOC(priv, sizeof(*priv));
        if (!priv) {
                rc = -ENOMEM;
                goto exit;
        }

        plg->plg_private = priv;
        rc = smfs_register_plugin(sb, plg);
        if (!rc)
                RETURN(0);
exit:
        if (priv)
                OBD_FREE(priv, sizeof(*priv));
        
        if (plg)
                OBD_FREE(plg, sizeof(*plg));

        RETURN(rc);

}

int audit_client_log(struct super_block * sb, struct audit_msg * msg)
{
        struct smfs_super_info * smb = S2SMI(sb);
        char *buffer = NULL, *pbuf = NULL;
        struct audit_record * rec = NULL;
        struct llog_rec_hdr * llh;
        struct llog_handle * ll_handle = NULL;
        int len = 0, rc = 0;
        struct timeval cur_time;
        //char name[32];
        struct audit_priv * priv;
        
        ENTRY;
        
        do_gettimeofday(&cur_time);
        
        priv = smfs_get_plg_priv(smb, SMFS_PLG_AUDIT);
        if (!priv)
                RETURN(-EINVAL);
        
        ll_handle = priv->audit_ctxt->loc_handle;
        
        OBD_ALLOC(buffer, PAGE_SIZE);
        if (!buffer)
                RETURN(-ENOMEM);
        
        llh = (void*)buffer;
        llh->lrh_type = SMFS_AUDIT_GEN_REC;

        //fill common fields
        rec = (void*)buffer + sizeof(*llh);
        rec->opcode = msg->code;
        rec->result = msg->result;
        rec->uid = msg->uid;
        rec->gid = msg->gid;
        rec->nid = msg->nid;
        rec->time = cur_time.tv_sec * USEC_PER_SEC + cur_time.tv_usec;
        len = sizeof(*rec);
        pbuf = (char*)rec + len;

        CDEBUG(D_VFSTRACE, "AUDITLOG:"DLID4"\n", OLID4(&msg->id));
        /* check id is valid */
        LASSERT(id_ino(&msg->id));
        LASSERT(id_fid(&msg->id));
        //LASSERT(id_type(&msg->id) & S_IFMT);

        switch (msg->code) {
                case AUDIT_READ:    
                case AUDIT_WRITE:
                case AUDIT_MMAP:
                case AUDIT_OPEN:
                case AUDIT_STAT:
                        len += audit_rec_from_id(&pbuf, &msg->id);
                        break;
                default:
                        CERROR("Unknown code %i in audit_msg\n", msg->code);
        }
        
        llh->lrh_len = size_round(len);

        rc = llog_cat_add_rec(ll_handle, llh, NULL, (void*)rec, NULL, NULL);
        if (rc != 0) {
                CERROR("Error adding audit client record: %d\n", rc);
                rc= -EINVAL;
        } else {
                audit_notify(ll_handle, priv->au_id2name);
        }
        
        OBD_FREE(buffer, PAGE_SIZE);
        return rc;
}

