/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/quotaops.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>

#include "llite_internal.h"

/* should NOT be called with the dcache lock, see fs/dcache.c */
static void ll_release(struct dentry *de)
{
        struct ll_dentry_data *lld = ll_d2d(de);
        ENTRY;

        LASSERT(lld->lld_cwd_count == 0);
        LASSERT(lld->lld_mnt_count == 0);
        OBD_FREE(de->d_fsdata, sizeof(struct ll_dentry_data));

        EXIT;
}

void ll_set_dd(struct dentry *de)
{
        ENTRY;
        LASSERT(de != NULL);

        lock_kernel();
        if (de->d_fsdata == NULL) {
                OBD_ALLOC(de->d_fsdata, sizeof(struct ll_dentry_data));
        }
        unlock_kernel();

        EXIT;
}

void ll_intent_release(struct lookup_intent *it)
{
        struct lustre_handle *handle;
        ENTRY;

        if (it->it_op && it->it_lock_mode) {
                handle = (struct lustre_handle *)it->it_lock_handle;
                CDEBUG(D_DLMTRACE, "releasing lock with cookie "LPX64
                       " from it %p\n",
                       handle->cookie, it);
                ldlm_lock_decref(handle, it->it_lock_mode);

                /* intent_release may be called multiple times, from
                   this thread and we don't want to double-decref this
                   lock (see bug 494) */
                it->it_lock_mode = 0;
        }
        it->it_magic = 0;
        it->it_op_release = 0;
        EXIT;
}

void ll_unhash_aliases(struct inode *inode)
{
        struct dentry *dentry = NULL;
        struct list_head *tmp;
        struct ll_sb_info *sbi;
        ENTRY;

        if (inode == NULL) {
                CERROR("unexpected NULL inode, tell phil\n");
                return;
        }

        sbi = ll_i2sbi(inode);

        CDEBUG(D_INODE, "marking dentries for ino %lx/%x invalid\n",
               inode->i_ino, inode->i_generation);

        spin_lock(&dcache_lock);
        list_for_each(tmp, &inode->i_dentry) {
                dentry = list_entry(tmp, struct dentry, d_alias);

                list_del_init(&dentry->d_hash);
                dentry->d_flags |= DCACHE_LUSTRE_INVALID;
                list_add(&dentry->d_hash, &sbi->ll_orphan_dentry_list);
        }

        spin_unlock(&dcache_lock);
        EXIT;
}

extern struct dentry *ll_find_alias(struct inode *, struct dentry *);

static int revalidate_it_finish(struct ptlrpc_request *request,
                              struct inode *parent, struct dentry **de,
                              struct lookup_intent *it, int offset, obd_id ino)
{
        struct ll_sb_info     *sbi = ll_i2sbi(parent);
        struct lustre_md      md;
        int                    rc = 0;
        ENTRY;

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return */

        if (it_disposition(it, DISP_LOOKUP_NEG))
                RETURN(-ENOENT);

        /* ll_intent_lock was successful, now prepare the lustre_md) */
        rc = mdc_req2lustre_md(request, offset, &sbi->ll_osc_conn, &md);
        if (rc)
                RETURN(rc);

        ll_update_inode((*de)->d_inode, md.body, md.lsm);

        if (md.lsm != NULL && ll_i2info((*de)->d_inode)->lli_smd != md.lsm)
                obd_free_memmd (&sbi->ll_osc_conn, &md.lsm);

        CDEBUG(D_DLMTRACE, "setting l_data to inode %p (%lu/%u)\n",
               (*de)->d_inode, (*de)->d_inode->i_ino,
               (*de)->d_inode->i_generation);
        ldlm_lock_set_data((struct lustre_handle *)it->it_lock_handle,
                           (*de)->d_inode);
        RETURN(rc);
}

int ll_have_md_lock(struct dentry *de)
{
        struct ll_sb_info *sbi = ll_s2sbi(de->d_sb);
        struct lustre_handle lockh;
        struct ldlm_res_id res_id = { .name = {0} };
        struct obd_device *obddev;
        int flags;
        ENTRY;

        if (!de->d_inode)
               RETURN(0);

        obddev = class_conn2obd(&sbi->ll_mdc_conn);
        res_id.name[0] = de->d_inode->i_ino;
        res_id.name[1] = de->d_inode->i_generation;

        CDEBUG(D_INFO, "trying to match res "LPU64"\n", res_id.name[0]);

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_MATCH_DATA;
        if (ldlm_lock_match(obddev->obd_namespace, flags, &res_id, LDLM_PLAIN,
                            NULL, 0, LCK_PR, de->d_inode, &lockh)) {
                ldlm_lock_decref(&lockh, LCK_PR);
                RETURN(1);
        }

        if (ldlm_lock_match(obddev->obd_namespace, flags, &res_id, LDLM_PLAIN,
                            NULL, 0, LCK_PW, de->d_inode, &lockh)) {
                ldlm_lock_decref(&lockh, LCK_PW);
                RETURN(1);
        }
        RETURN(0);
}

int ll_revalidate_it(struct dentry *de, int flags, struct lookup_intent *it)
{
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,intent=%s\n", de->d_name.name,
               LL_IT2STR(it));

        /* Cached negative dentries are unsafe for now - look them up again */
        if (de->d_inode == NULL)
                RETURN(0);

        /* 
         * never execute intents for mount points
         * - attrs will be fixed up in ll_revalidate_inode
         */
        if (d_mountpoint(de))
                RETURN(1);

        if (it)
                it->it_op_release = ll_intent_release;

        if (it == NULL || it->it_op == IT_GETATTR) {
                /* We could just return 1 immediately, but since we should only
                 * be called in revalidate2 if we already have a lock, let's
                 * verify that. */
                struct inode *inode = de->d_inode;
                struct ll_sb_info *sbi = ll_i2sbi(inode);
                struct obd_device *obddev = class_conn2obd(&sbi->ll_mdc_conn);
                struct ldlm_res_id res_id =
                        { .name = {inode->i_ino, (__u64)inode->i_generation} };
                struct lustre_handle lockh;
                int flags;
                flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_MATCH_DATA;
                rc = ldlm_lock_match(obddev->obd_namespace, flags, &res_id,
                                     LDLM_PLAIN, NULL, 0, LCK_PR, inode,
                                     &lockh);
                if (rc) {
                        de->d_flags &= ~DCACHE_LUSTRE_INVALID;
                        if (it && it->it_op == IT_GETATTR) {
                                memcpy(it->it_lock_handle, &lockh,
                                       sizeof(lockh));
                                it->it_lock_mode = LCK_PR;
                        } else {
                                ldlm_lock_decref(&lockh, LCK_PR);
                        }
                        RETURN(1);
                }
                rc = ldlm_lock_match(obddev->obd_namespace, flags, &res_id,
                                     LDLM_PLAIN, NULL, 0, LCK_PW, inode,
                                     &lockh);
                if (rc) {
                        de->d_flags &= ~DCACHE_LUSTRE_INVALID;
                        if (it && it->it_op == IT_GETATTR) {
                                memcpy(it->it_lock_handle, &lockh,
                                       sizeof(lockh));
                                it->it_lock_mode = LCK_PW;
                        } else {
                                ldlm_lock_decref(&lockh, LCK_PW);
                        }
                        RETURN(1);
                }
                if (S_ISDIR(de->d_inode->i_mode))
                        ll_invalidate_inode_pages(de->d_inode);
                ll_unhash_aliases(de->d_inode);
                RETURN(0);
        }

        rc = ll_intent_lock(de->d_parent->d_inode, &de, it, flags,
                            revalidate_it_finish);
        if (rc < 0) {
                if (rc != -ESTALE) {
                        CERROR("ll_intent_lock: rc %d : it->it_status %d\n", rc,
                               it->it_status);
                }
                ll_unhash_aliases(de->d_inode);
                RETURN(0);
        }
        /* unfortunately ll_intent_lock may cause a callback and revoke our
           dentry */
        spin_lock(&dcache_lock);
        hlist_del_init(&de->d_hash);
        __d_rehash(de, 0);
        spin_unlock(&dcache_lock);

        RETURN(1);
}

static void ll_pin(struct dentry *de, struct vfsmount *mnt, int flag)
{
        struct inode *inode= de->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_dentry_data *ldd = ll_d2d(de);
        struct obd_client_handle *handle;
        int rc = 0;
        ENTRY;
        LASSERT(ldd);

        lock_kernel();
        /* Strictly speaking this introduces an additional race: the
         * increments should wait until the rpc has returned.
         * However, given that at present the function is void, this
         * issue is moot. */
        if (flag == 1 && (++ldd->lld_mnt_count) > 1) {
                unlock_kernel();
                EXIT;
                return;
        }

        if (flag == 0 && (++ldd->lld_cwd_count) > 1) {
                unlock_kernel();
                EXIT;
                return;
        }
        unlock_kernel();

        handle = (flag) ? &ldd->lld_mnt_och : &ldd->lld_cwd_och;
        rc = obd_pin(&sbi->ll_mdc_conn, inode->i_ino, inode->i_generation,
                     inode->i_mode & S_IFMT, handle, flag);

        if (rc) {
                lock_kernel();
                memset(handle, 0, sizeof(*handle));
                if (flag == 0)
                        ldd->lld_cwd_count--;
                else
                        ldd->lld_mnt_count--;
                unlock_kernel();
        }

        EXIT;
        return;
}

static void ll_unpin(struct dentry *de, struct vfsmount *mnt, int flag)
{
        struct ll_sb_info *sbi = ll_i2sbi(de->d_inode);
        struct ll_dentry_data *ldd = ll_d2d(de);
        struct obd_client_handle handle;
        int count, rc = 0;
        ENTRY;
        LASSERT(ldd);

        lock_kernel();
        /* Strictly speaking this introduces an additional race: the
         * increments should wait until the rpc has returned.
         * However, given that at present the function is void, this
         * issue is moot. */
        handle = (flag) ? ldd->lld_mnt_och : ldd->lld_cwd_och;
        if (handle.och_magic != OBD_CLIENT_HANDLE_MAGIC) {
                /* the "pin" failed */
                unlock_kernel();
                EXIT;
                return;
        }

        if (flag)
                count = --ldd->lld_mnt_count;
        else
                count = --ldd->lld_cwd_count;
        unlock_kernel();

        if (count != 0) {
                EXIT;
                return;
        }

        rc = obd_unpin(&sbi->ll_mdc_conn, &handle, flag);
        EXIT;
        return;
}

struct dentry_operations ll_d_ops = {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        .d_revalidate_nd = ll_revalidate_nd,
#else
        .d_revalidate_it = ll_revalidate_it,
#endif
        .d_release = ll_release,
#if 0
        .d_pin = ll_pin,
        .d_unpin = ll_unpin,
#endif
};
