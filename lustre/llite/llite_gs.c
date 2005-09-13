/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004, 2005 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/kmod.h>
#include <linux/posix_acl.h>
#include <linux/xattr_acl.h>

#include <linux/lustre_acl.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_gs.h>
#include "llite_internal.h"

int ll_gs_intent_init(struct lookup_intent *it)
{
        struct lustre_intent_data *lustre_data;
        
        LASSERT(it->d.fs_data != NULL); 
        lustre_data = (struct lustre_intent_data *)it->d.fs_data;
        /*set lustre key size when there is gss server 
         *or other configuration*/ 
        lustre_data->it_key = NULL;
        lustre_data->it_key_size = 0;
        RETURN(0);
}

static int ll_get_acl_key(struct inode *inode, struct posix_acl **acl,
                          struct lustre_key **lkey) 
{
        struct lookup_intent it = { .it_op = IT_GETATTR };
        struct dentry de = { .d_inode = inode };
        struct ll_sb_info *sbi;
        struct lustre_id id;
        struct ptlrpc_request *req = NULL;
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc = 0;
        ENTRY;

        sbi = ll_i2sbi(inode);
        ll_inode2id(&id, inode);

        if (ll_intent_alloc(&it))
                RETURN(-EACCES);

        rc = md_intent_lock(sbi->ll_md_exp, &id, NULL, 0, NULL, 0, &id,
                            &it, 0, &req, ll_mdc_blocking_ast);
        if (rc < 0) {
                ll_intent_free(&it);
                GOTO(out, rc);
        }

        rc = revalidate_it_finish(req, 1, &it, &de);
        if (rc) {
                ll_intent_release(&it);
                GOTO(out, rc);
        }

        ll_lookup_finish_locks(&it, &de);
        ll_intent_free(&it);

        spin_lock(&lli->lli_lock);
        *acl = posix_acl_dup(lli->lli_posix_acl);
        *lkey =  lustre_key_get(lli->lli_key_info);
        spin_unlock(&lli->lli_lock);
        EXIT;
out:
        if (req)
                ptlrpc_req_finished(req);        
        return rc;
}

static int ll_init_key_perm(struct key_perm *kperm, struct posix_acl *acl, 
                            __u32 uid, __u32 gid, int mode) 
{
        ENTRY;
        if (acl) {
                kperm->kp_acl_count = acl->a_count;
                memcpy(kperm->kp_acls, acl->a_entries, 
                       acl->a_count * sizeof(struct posix_acl_entry));
        }
        kperm->kp_mode = mode;
        kperm->kp_uid = uid;
        kperm->kp_gid = gid;
        RETURN(0);
}

static int ll_init_key_context(struct key_context *pkc, __u32 uid, 
                                __u32 gid, struct crypto_key *ck, 
                                struct posix_acl *acl,  int mode, 
                                int command, int valid)
{
        struct key_perm *kperm;
        ENTRY;

        pkc->kc_command = command;
        pkc->kc_valid = valid;

        if (ck)
                memcpy(&pkc->kc_ck, ck, sizeof(*ck));

        kperm = &pkc->kc_perm;      
 
        ll_init_key_perm(kperm, acl, uid, gid, mode);  
        RETURN(0);
}
static int ll_get_default_acl(struct inode *inode, struct posix_acl **acl, 
                              mode_t mode) 
{
        int rc = 0, buf_size, ea_size;
        char *buf = NULL;
        ENTRY;

        if (!S_ISDIR(inode->i_mode))
                RETURN(0);
 
        buf_size = xattr_acl_size(LL_ACL_MAX_ENTRIES);
        OBD_ALLOC(buf, buf_size);
        if (!buf)
                RETURN(-ENOMEM);

        ea_size = ll_getxattr_internal(inode, XATTR_NAME_ACL_DEFAULT, 
                                       buf, buf_size, OBD_MD_FLXATTR);
        if (ea_size <= 0) {
                if (ea_size < 0 && ea_size != -ENODATA)
                        CERROR("get default acl of ino %lu error rc %d \n",
                                inode->i_ino, ea_size);
                GOTO(out, rc = 0);       
        }
        *acl = posix_acl_from_xattr(buf, ea_size);
        if (IS_ERR(*acl)) {
                rc = PTR_ERR(*acl);
                CERROR("convert xattr to acl failed: %d\n", rc);
                GOTO(out, rc);
        } else if (*acl) {
                rc = posix_acl_valid(*acl);
                if (rc) {
                        CERROR("acl valid error: %d\n", rc);
                        posix_acl_release(*acl);
                        GOTO(out, rc);
                }
        }
        
        rc = posix_acl_create_masq(*acl, &mode);
        EXIT;
out:
        if (buf) 
                OBD_FREE(buf, buf_size);
        return rc;
}

int ll_gks_create_key(struct inode *dir, mode_t mode, void **key, 
                      int* key_size)
{
        struct obd_export *gs_exp = ll_i2gsexp(dir);
        struct key_context *kcontext = NULL;
        struct posix_acl *default_acl = NULL;       
        struct key_parms kparms;
        int rc = 0;  
        ENTRY;
 
        OBD_ALLOC(kcontext, sizeof(struct key_context));
        if (!kcontext)
                GOTO(out, rc = -ENOMEM);

        rc = ll_get_default_acl(dir, &default_acl, mode);
        if (rc)
                GOTO(out, rc);       
 
        ll_init_key_context(kcontext, current->fsuid, current->fsgid, 
                            NULL, default_acl, mode, GKS_GET_KEY, 0);
       
        kparms.context = kcontext;
        kparms.context_size = sizeof(struct key_context);
        kparms.perm = NULL;
       
        *key_size = sizeof(struct crypto_key);
        OBD_ALLOC(*key, *key_size);
        if (!*key)
                GOTO(out, rc = -ENOMEM);
 
        /* GET an encrypt key from GS server */
        rc = obd_get_info(gs_exp, sizeof(struct key_parms), (void *)&kparms,
                          key_size, *key);
        if (rc) {
                CERROR("get key error rc %d \n", rc);
                GOTO(out, rc);
        }
        CDEBUG(D_INFO, "Get enkey %s MAC %s from exp %p \n", 
               (char*)((struct crypto_key *)(*key))->ck_key, 
               (char*)((struct crypto_key *)(*key))->ck_mac, 
               gs_exp);
        EXIT;
out:
        if (kcontext)
                OBD_FREE(kcontext, sizeof(struct key_context));
        if (default_acl)
                posix_acl_release(default_acl);
        return rc;

}
 
int ll_gks_init_it(struct inode *parent, struct lookup_intent *it)
{
        struct obd_export *gs_exp = ll_i2gsexp(parent);
        struct lustre_intent_data *lustre_data;
        mode_t mode = (it->it_create_mode | S_IFREG) & (~current->fs->umask);
        void *key = NULL;
        int key_size = 0, rc = 0;
        ENTRY;
 
        if (!gs_exp || !it)
                RETURN(rc);

        ll_gs_intent_init(it);
        if (!(it->it_flags & O_CREAT)) 
                RETURN(rc);

        LASSERT(it->d.fs_data != NULL); 
        lustre_data = (struct lustre_intent_data *)it->d.fs_data;
          
        if (lustre_data->it_key) {
                LASSERT(lustre_data->it_key_size == 
                         sizeof(struct crypto_key));
                OBD_FREE(lustre_data->it_key, sizeof(struct crypto_key));
        }

        rc = ll_gks_create_key(parent, mode, &key, &key_size); 
        if (rc)
                GOTO(out, rc);

        lustre_data->it_key = key; 
        lustre_data->it_key_size = key_size;
        EXIT;
out:
        if (rc) {
                if (key && key_size)
                        OBD_FREE(key, key_size);
        }
        return rc; 
}

int ll_gks_decrypt_key(struct inode *inode, struct lookup_intent *it)
{
        struct obd_export *gs_exp = ll_i2gsexp(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        struct key_context *kcontext = NULL;
        struct key_perm *kperm = NULL;
        struct key_parms kparms;
        struct lustre_key *lkey =  NULL;
        struct crypto_key *ckey = NULL;
        struct posix_acl *acl = NULL;
        __u32 flags = 0; 
        int rc = 0, ck_size = 0, kcontext_size = 0, acl_count;
        
        ENTRY;
 
        if (!gs_exp)
                RETURN(rc);
       
        rc = ll_get_acl_key(inode, &acl, &lkey);
        if (rc)
                GOTO(out, rc);       
        if (!lkey || IS_DECRYPTED(lkey->lk_flags))
                GOTO(out, rc = 0);
       
        acl_count = acl ? acl->a_count : 0;  
        kcontext_size = crypto_kcontext_size(acl_count); 
        OBD_ALLOC(kcontext, kcontext_size);
        if (!kcontext)
                GOTO(out, rc = -ENOMEM);
        
        flags = mds_pack_open_flags(it->it_flags); 

        spin_lock(&lli->lli_lock); 
        ll_init_key_context(kcontext, inode->i_uid, inode->i_gid, &lkey->lk_ck, 
                            acl, inode->i_mode, GKS_DECRYPT_KEY, flags);
       
        spin_unlock(&lli->lli_lock); 
        
        OBD_ALLOC(kperm, sizeof(struct key_perm));
        if (!kperm)
                GOTO(out, rc = -ENOMEM);
            
        ll_init_key_perm(kperm, NULL, current->uid, current->gid, 0);
    
        kparms.context = kcontext;
        kparms.context_size = kcontext_size;
        kparms.perm = kperm;       
        kparms.perm_size = sizeof(struct key_perm); 

        ck_size = sizeof(*ckey);
        OBD_ALLOC(ckey, ck_size);
        if (!ckey)
                GOTO(out, rc = -ENOMEM);
 
        /*GET an encrypt key from GS server*/
        rc = obd_get_info(gs_exp, sizeof(struct key_parms), (void *)&kparms,
                          &ck_size, ckey);
        if (rc) {
                CERROR("decrypt key error rc %d \n", rc);
                GOTO(out, rc);
        }
        CDEBUG(D_INFO, "decrypt key %s MAC %s from exp %p \n", 
               ckey->ck_mac, ckey->ck_mac, gs_exp);        
      
        /*copy the decrypt key from kcontext to the lustre key*/
        
        spin_lock(&lli->lli_lock); 
        memcpy(&lkey->lk_dk, ckey->ck_key, KEY_SIZE);
        SET_DECRYPTED(lkey->lk_flags);
        spin_unlock(&lli->lli_lock);
        EXIT;
out:
        if (acl)
                posix_acl_release(acl);
        if (lkey)
                lustre_key_release(lkey); 
        if (kperm)
                OBD_FREE(kperm, sizeof(struct key_perm));
        if (kcontext)
                OBD_FREE(kcontext, kcontext_size);
        if (ckey)
                OBD_FREE(ckey, ck_size);
        return rc; 
}

static void get_real_parameters(struct inode *inode, struct iattr *iattr,
                                struct posix_acl *new_acl, mode_t *mode,   
                                __u32 *uid, __u32 *gid)
{ 
        LASSERT(iattr);

        if (iattr->ia_valid & ATTR_MODE) {
                *mode = iattr->ia_mode;
        } else {
                *mode = inode->i_mode;
                if (new_acl) {
                        posix_acl_equiv_mode(new_acl, mode);
                        CDEBUG(D_INFO, "get new mode %d \n", *mode);
                } 
        }

        if (iattr->ia_valid & ATTR_UID)
                *uid = iattr->ia_uid;
        else 
                *uid = inode->i_uid;

        if (iattr->ia_valid & ATTR_GID)
                *gid = iattr->ia_gid;
        else
                *gid = inode->i_gid;
}

int ll_gks_get_mac(struct inode *inode, struct iattr *iattr, void *value, 
                   int size, void **key, int *key_size)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_export *gs_exp = ll_i2gsexp(inode);
        struct key_context *kcontext = NULL;
        struct key_perm *kperm = NULL;
        struct key_parms kparms;
        struct lustre_key *lkey =  NULL;
        struct crypto_key *ckey = NULL;
        struct posix_acl *acl = NULL, *new_acl = NULL; 
        int rc = 0,  kperm_size = 0, kcontext_size = 0; 
        mode_t mac_mode;
        __u32 uid, gid;
        int acl_count = 0;
        
        ENTRY;
 
        if (!gs_exp)
                RETURN(rc);
       
        rc = ll_get_acl_key(inode, &acl, &lkey);
        if (rc)
                GOTO(out, rc);       
        if (!lkey)
                RETURN(rc);
        
        acl_count = acl ? acl->a_count : 0;  
        kcontext_size = crypto_kcontext_size(acl_count); 
        OBD_ALLOC(kcontext, kcontext_size);
        if (!kcontext)
                GOTO(out, rc = -ENOMEM);
        spin_lock(&lli->lli_lock);
        ll_init_key_context(kcontext, inode->i_uid, inode->i_gid, &lkey->lk_ck, 
                            acl, inode->i_mode, GKS_GET_MAC, iattr->ia_valid);
        spin_unlock(&lli->lli_lock);
        if (value) {
                new_acl = posix_acl_from_xattr(value, size); 
                if (IS_ERR(new_acl)) {
                        rc = PTR_ERR(new_acl);
                        CERROR("convert from xattr to acl error: %d",rc);
                        new_acl = NULL;
                        GOTO(out, rc);
                } else if (new_acl) {
                        rc = posix_acl_valid(new_acl);
                        if (rc) {
                                CERROR("acl valid error: %d", rc);
                                GOTO(out, rc);
                        }
                }
        } else {
                new_acl = acl;
        }
        acl_count = new_acl ? new_acl->a_count : 0;  
        kperm_size = crypto_kperm_size(acl_count);
        OBD_ALLOC(kperm, kperm_size);
        if (!kperm)
                GOTO(out, rc = -ENOMEM);
                
        get_real_parameters(inode, iattr, new_acl, &mac_mode, &uid, &gid);
        ll_init_key_perm(kperm, new_acl, uid, gid, mac_mode);
        kparms.context = kcontext;
        kparms.context_size = kcontext_size;
        kparms.perm = kperm;       
        kparms.perm_size = kperm_size; 

        *key_size = sizeof(struct crypto_key);
        OBD_ALLOC(ckey, sizeof(struct crypto_key));
        if (!ckey)
                GOTO(out, rc = -ENOMEM);
        /*GET an encrypt key from GS server*/
        rc = obd_get_info(gs_exp, sizeof(struct key_parms), (void *)&kparms,
                          key_size, ckey);
        if (rc) {
                CERROR("decrypt key error rc %d \n", rc);
                *key_size = 0;
                GOTO(out, rc);
        }
        *key = ckey;
        iattr->ia_valid |= ATTR_MAC;
out:
        if (acl)
                posix_acl_release(acl);
        if (new_acl)
                posix_acl_release(new_acl);
        if (lkey)
                lustre_key_release(lkey); 
        if (kperm)
                OBD_FREE(kperm, kperm_size);
        if (kcontext)
                OBD_FREE(kcontext, kcontext_size);
        RETURN(rc); 
}

static int ll_crypt_permission_check(struct lustre_key *lkey,
                                     int flags)
{
        ENTRY;
        if (!IS_DECRYPTED(lkey->lk_flags)) 
                RETURN(-EFAULT);
        if (flags == ENCRYPT_DATA && !IS_ENABLE_ENCRYPT(lkey->lk_flags)) 
                RETURN(-EFAULT);
        if (flags == DECRYPT_DATA && !IS_ENABLE_DECRYPT(lkey->lk_flags)) 
                RETURN(-EFAULT);
        RETURN(0);
}
/*key function for calculate the key for countermode method*/
static int ll_crypt_cb(struct page *page, __u64 offset, __u64 count,
                       int flags)
{
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_key *lkey = ll_i2info(inode)->lli_key_info;
        unsigned char *ptr;
        char *key_ptr;
        int index = page->index;
        __u8 data_key = 0; 
        int i, rc = 0;
        ENTRY;

        if (!lkey)
                RETURN(0);
        spin_lock(&lli->lli_lock);
        rc = ll_crypt_permission_check(lkey, flags);
        if (rc) {
                spin_unlock(&lli->lli_lock);
                RETURN(rc);
        }
        
        key_ptr = &lkey->lk_dk[0];
        for (i=0; i < KEY_SIZE; i++) 
                data_key += *key_ptr++; 
        spin_unlock(&lli->lli_lock);
        data_key += index;

        CDEBUG(D_INFO, "data_key is %d \n", data_key);
        if (data_key == 0) {
                CDEBUG(D_INFO, "data_key is 0, inc 1 \n");
                data_key ++; 
        }
        LASSERT((__u8)data_key != 0);
        /*encrypt the data*/
        ptr = (char *)kmap(page);
        key_ptr = ptr;
        ptr += offset & (PAGE_SIZE - 1); 
        //CDEBUG(D_INFO, "ptr is %s \n", ptr);
        for (i = 0; i < count; i++) 
                *ptr++ ^= (__u8)data_key; 
        //CDEBUG(D_INFO, "encrypted ptr is %s \n", key_ptr);
        kunmap(page);
        
        RETURN(rc); 
} 

int ll_gs_init_inode_key(struct inode *inode, void  *mkey)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct crypto_key *key = (struct crypto_key*)mkey;
        struct lustre_key *lkey = NULL;
        ENTRY;        

        if (!key)
                RETURN(0);
        
        if (lli->lli_key_info == NULL) {
                OBD_ALLOC(lkey, sizeof(struct lustre_key));
                if (!lkey)
                        RETURN(-ENOMEM); 
                memcpy(&lkey->lk_ck, key, sizeof(*key));
                atomic_set(&lkey->lk_refcount, 1);
                SET_UNDECRYPTED(lkey->lk_flags); 
                ENABLE_ENCRYPT(lkey->lk_flags);  
                ENABLE_DECRYPT(lkey->lk_flags); 
                spin_lock(&lli->lli_lock);
                lli->lli_key_info = lkey; 
                spin_unlock(&lli->lli_lock);
                CDEBUG(D_INFO, "set key %s mac %s in inode %lu \n", 
                       lli->lli_key_info->lk_ck.ck_key, 
                       lli->lli_key_info->lk_ck.ck_mac, 
                       inode->i_ino);
        } else {
                lkey = lustre_key_get(lli->lli_key_info);
                LASSERTF(!memcmp(lkey->lk_ck.ck_key, key->ck_key, KEY_SIZE), 
                         "old key %s != new key %s\n", lkey->lk_ck.ck_key, 
                         key->ck_key);
                spin_lock(&lli->lli_lock);
                if (memcmp(lkey->lk_ck.ck_mac, key->ck_mac, MAC_SIZE)){
                        CDEBUG(D_INFO, "reset mac %s to %s ino %ld \n",
                               lkey->lk_ck.ck_mac, key->ck_mac, inode->i_ino);
                        memcpy(lkey->lk_ck.ck_mac, key->ck_mac, MAC_SIZE);
                        SET_UNDECRYPTED(lkey->lk_flags); 
                }
                spin_unlock(&lli->lli_lock);
                lustre_key_release(lkey);
        }
        RETURN(0);
}

static int ll_gs_destroy_key(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
       
        spin_lock(&lli->lli_lock);
        if (lli->lli_key_info) {
                LASSERTF(atomic_read(&lli->lli_key_info->lk_refcount) == 1, 
                         "lk_refcount %d != 1 when destory\n", 
                         atomic_read(&lli->lli_key_info->lk_refcount));
                lustre_key_release(lli->lli_key_info);
                lli->lli_key_info = NULL;
        }
        spin_unlock(&lli->lli_lock);
        RETURN(0);
}

struct crypto_helper_ops ll_cgs_ops = { 
       .init_it_key     = ll_gks_init_it,
       .create_key      = ll_gks_create_key,
       .init_inode_key  = ll_gs_init_inode_key, 
       .get_mac         = ll_gks_get_mac,
       .decrypt_key     = ll_gks_decrypt_key, 
       .destroy_key     = ll_gs_destroy_key,
};

int ll_mks_create_key(struct inode *inode, struct lookup_intent *it)
{
        struct lustre_intent_data *lustre_data;
        struct crypto_key         *crypto_key;
        int    rc = 0;       
        ENTRY;
       
        LASSERT(it->d.fs_data != NULL); 
        lustre_data = (struct lustre_intent_data *)it->d.fs_data;
       
        if (lustre_data->it_key)
                OBD_FREE(lustre_data->it_key, sizeof(struct crypto_key));

        OBD_ALLOC(crypto_key, sizeof(struct crypto_key));
        if (!crypto_key)
                RETURN(-ENOMEM);
       
        crypto_key->ck_type = MKS_TYPE;
        lustre_data->it_key = crypto_key; 
        lustre_data->it_key_size = sizeof(struct crypto_key); 
        RETURN(rc);
}

int ll_mks_init_it(struct inode *parent, struct lookup_intent *it)
{
        int rc = 0;
        ENTRY;
 
        if (!it)
                RETURN(0);

        ll_gs_intent_init(it);
        if (it->it_op & IT_CREAT) {
                ll_mks_create_key(parent, it);
        }
        RETURN(rc); 
}

int ll_mks_decrypt_key(struct inode *inode, struct lookup_intent *it)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_key *lkey =  NULL;
        struct posix_acl *acl = NULL;
        int rc = 0;
        ENTRY;
 
        rc = ll_get_acl_key(inode, &acl, &lkey);
        if (rc || !lkey)
                GOTO(out, rc);      
        spin_lock(&lli->lli_lock); 
        SET_DECRYPTED(lkey->lk_flags); 
        memcpy(&lkey->lk_dk, lkey->lk_ck.ck_key, KEY_SIZE);
        spin_unlock(&lli->lli_lock);
        EXIT;
out:
        if (acl)
                posix_acl_release(acl);
        if (lkey)
                lustre_key_release(lkey); 
        return rc;
}

struct crypto_helper_ops ll_cmd_ops = { 
       .init_it_key     = ll_mks_init_it,
       .init_inode_key  = ll_gs_init_inode_key, 
       .decrypt_key     = ll_mks_decrypt_key,
       .destroy_key     = ll_gs_destroy_key,
};


static int ll_register_cops(struct ll_crypto_info *llci, char *type,
                            struct crypto_helper_ops *cops)
{
        struct list_head *list = &llci->ll_cops_list;
        struct crypto_ops_item *opi = NULL, *tmp;
        char   *opi_name = NULL;        
        int rc = 0;
        ENTRY;
        
        list_for_each_entry(tmp, list, clist) {
                if (!strcmp(type, tmp->ctype)) {
                        CWARN("%s is already registered\n", type);
                        RETURN(-EEXIST);
                }
        }
        
        OBD_ALLOC(opi, sizeof(*opi));
        if (!opi)
                RETURN(-ENOMEM);
       
        OBD_ALLOC(opi_name, strlen(type) + 1);
        if (!opi_name) {
                OBD_FREE(opi, sizeof(*opi));
                RETURN(-ENOMEM);
        }
       
        memcpy(opi_name, type, strlen(type));

        opi->ctype = opi_name;
        opi->cops = cops;
  
        list_add_tail(&opi->clist, list);
        RETURN(rc);
}

static int ll_init_sb_crypto(struct super_block *sb)
{
        struct ll_crypto_info *llci = NULL;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(llci, sizeof(*llci));
        if (!llci)
                RETURN(-ENOMEM);

        INIT_LIST_HEAD(&llci->ll_cops_list);
        
        ll_register_cops(llci, "gks", &ll_cgs_ops);
        ll_register_cops(llci, "mks", &ll_cmd_ops);

        ll_s2sbi(sb)->ll_crypto_info = llci;

        RETURN(rc);
}         

static int ll_unregister_cops(struct ll_crypto_info *llci)
{
        struct list_head *list = &llci->ll_cops_list;
        struct crypto_ops_item *tmp, *item;
        ENTRY;

        list_for_each_entry_safe(item, tmp, list, clist) {       
                list_del_init(&item->clist);       
                OBD_FREE(item->ctype, strlen(item->ctype) + 1);
                OBD_FREE(item, sizeof(*item));
        }
        RETURN(0);
}

int lustre_destroy_crypto(struct super_block *sb)
{
        struct ll_crypto_info *llci = ll_s2crpi(sb);
        ENTRY;       

        if (!llci)
                RETURN(0);

        if (llci->ll_gt_exp)
                obd_disconnect(llci->ll_gt_exp, 0);
 
        ll_unregister_cops(llci);
        OBD_FREE(llci, sizeof(*llci)); 
        RETURN(0);
}

int lustre_init_crypto(struct super_block *sb, char *gkc, 
                       struct obd_connect_data *data,
                       int async)
{
        struct obd_device *obd = NULL;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct lustre_handle gt_conn;
        int rc = 0;
        ENTRY;

        rc = ll_init_sb_crypto(sb);
        if (rc)
                RETURN(rc);

        if (!gkc || !strcmp(gkc, "null")) {
                CDEBUG(D_INFO, "No gks Server\n"); 
                RETURN(rc);
        }
        
        obd = class_name2obd(gkc);
        if (!obd) {
                CERROR("GSC %s: not setup or attached\n", gkc);
                GOTO(out, rc = -EINVAL);
        }
        
        obd_set_info(obd->obd_self_export, strlen("async"), "async",
                     sizeof(async), &async);
        
        rc = obd_connect(&gt_conn, obd, &sbi->ll_sb_uuid, data,
                          OBD_OPT_REAL_CLIENT);
        if (rc) {
                CERROR("cannot connect to %s: rc = %d\n", gkc, rc);
                GOTO(out, rc);
        }
        ll_s2crpi(sb)->ll_gt_exp = class_conn2export(&gt_conn);
        EXIT;
out:
        if (rc)
                lustre_destroy_crypto(sb); 
        return rc;
}
struct crypto_helper_ops *
ll_gks_find_ops(struct ll_crypto_info *llc_info, char *type)
{
        struct list_head *list = &llc_info->ll_cops_list;
        struct crypto_ops_item *tmp;
        ENTRY;

        list_for_each_entry(tmp, list, clist) {
                if (!strcmp(type, tmp->ctype)) {
                        EXIT;
                        return (tmp->cops);            
                }
        }
        CERROR("can not find crypto api %s \n", type);
        RETURN(NULL);
}

int ll_set_sb_gksinfo(struct super_block *sb, char *type)
{
        struct ll_crypto_info *llci = ll_s2crpi(sb);
        struct obd_export *md_exp = ll_s2mdexp(sb);
        struct obd_export *dt_exp = ll_s2dtexp(sb);
        struct crypto_helper_ops *ops;
        int rc = 0;
        ENTRY;
        
        /*try to find the helper ops according to the type*/
        ops = ll_gks_find_ops(llci, type);
        if (!ops) {
                CERROR("can not find the crypto ops by type %s \n", type);
                RETURN(-EINVAL);
        }
        llci->ll_cops = ops;
        /*set crypto type */
        rc = obd_set_info(md_exp, strlen("crypto_type"), "crypto_type",
                          strlen(type), type);

        /*set crypt call back func*/

        rc = obd_set_info(dt_exp, strlen("crypto_cb"), "crypto_cb",
                          sizeof(crypt_cb_t), &ll_crypt_cb);
  
        RETURN(rc);
}

