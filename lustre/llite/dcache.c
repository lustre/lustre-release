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

/* should NOT be called with the dcache lock, see fs/dcache.c */
void ll_release(struct dentry *de)
{
        ENTRY;
        OBD_FREE(de->d_fsdata, sizeof(struct ll_dentry_data));
        EXIT;
}

int ll_delete(struct dentry *de)
{
        if (de->d_it != 0) {
                CERROR("%s put dentry %p+%p with d_it %p\n", current->comm,
                       de, de->d_fsdata, de->d_it);
                LBUG();
        }
        return 0;
}

void ll_set_dd(struct dentry *de)
{
        ENTRY;
        LASSERT(de != NULL);

        lock_kernel();

        if (de->d_fsdata == NULL) {
                OBD_ALLOC(de->d_fsdata, sizeof(struct ll_dentry_data));
                sema_init(&ll_d2d(de)->lld_it_sem, 1);
        }

        unlock_kernel();

        EXIT;
}

void ll_intent_release(struct dentry *de, struct lookup_intent *it)
{
        struct lustre_handle *handle;
        ENTRY;

        if (it->it_lock_mode) {
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

        if (!de->d_it || it->it_op == IT_RELEASED_MAGIC) {
                EXIT;
                return;
        }

        if (de->d_it == it)
                LL_GET_INTENT(de, it);
        else
                CDEBUG(D_INODE, "STRANGE intent release: %p %p\n",
                       de->d_it, it);

        EXIT;
}

extern struct dentry *ll_find_alias(struct inode *, struct dentry *);

static int revalidate2_finish(int flag, struct ptlrpc_request *request,
                              struct inode *parent, struct dentry **de,
                              struct lookup_intent *it, int offset, obd_id ino)
{
        struct ll_sb_info     *sbi = ll_i2sbi(parent);
        struct mds_body       *body;
        struct lov_stripe_md  *lsm = NULL;
        struct lov_mds_md     *lmm;
        int                    lmmsize;
        int                    rc = 0;
        ENTRY;

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return */

        if ((flag & LL_LOOKUP_NEGATIVE) != 0)
                GOTO (out, rc = -ENOENT);

        /* We only get called if the mdc_enqueue() called from
         * ll_intent_lock() was successful.  Therefore the mds_body is
         * present and correct, and the eadata is present (but still
         * opaque, so only obd_unpackmd() can check the size) */
        body = lustre_msg_buf(request->rq_repmsg, offset, sizeof (*body));
        LASSERT (body != NULL);
        LASSERT_REPSWABBED (request, offset);

        if (body->valid & OBD_MD_FLEASIZE) {
                /* Only bother with this if inodes's LSM not set? */

                if (body->eadatasize == 0) {
                        CERROR ("OBD_MD_FLEASIZE set, but eadatasize 0\n");
                        GOTO (out, rc = -EPROTO);
                }
                lmmsize = body->eadatasize;
                lmm = lustre_msg_buf (request->rq_repmsg, offset + 1, lmmsize);
                LASSERT (lmm != NULL);
                LASSERT_REPSWABBED (request, offset + 1);

                rc = obd_unpackmd (&sbi->ll_osc_conn,
                                   &lsm, lmm, lmmsize);
                if (rc < 0) {
                        CERROR ("Error %d unpacking eadata\n", rc);
                        LBUG();
                        /* XXX don't know if I should do this... */
                        GOTO (out, rc);
                        /* or skip the ll_update_inode but still do
                         * mdc_lock_set_inode() */
                }
                LASSERT (rc >= sizeof (*lsm));
                rc = 0;
        }

        ll_update_inode((*de)->d_inode, body, lsm);

        if (lsm != NULL &&
            ll_i2info((*de)->d_inode)->lli_smd != lsm)
                obd_free_memmd (&sbi->ll_osc_conn, &lsm);

        ll_mdc_lock_set_inode((struct lustre_handle *)it->it_lock_handle,
                              (*de)->d_inode);
 out:
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

int ll_revalidate2(struct dentry *de, int flags, struct lookup_intent *it)
{
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,intent=%s\n", de->d_name.name,
               LL_IT2STR(it));

        /* We don't want to cache negative dentries, so return 0 immediately.
         * We believe that this is safe, that negative dentries cannot be
         * pinned by someone else */
        if (de->d_inode == NULL) {
                CDEBUG(D_INODE, "negative dentry: ret 0 to force lookup2\n");
                RETURN(0);
        }

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
                                LL_SAVE_INTENT(de, it);
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
                                LL_SAVE_INTENT(de, it);
                        } else {
                                ldlm_lock_decref(&lockh, LCK_PW);
                        }
                        RETURN(1);
                }
                if (S_ISDIR(de->d_inode->i_mode))
                        ll_invalidate_inode_pages(de->d_inode);
                d_unhash_aliases(de->d_inode);
                RETURN(0);
        }

        rc = ll_intent_lock(de->d_parent->d_inode, &de, it, revalidate2_finish);
        if (rc < 0) {
                if (rc != -ESTALE) {
                        CERROR("ll_intent_lock: rc %d : it->it_status %d\n", rc,
                               it->it_status);
                }
                RETURN(0);
        }
        /* unfortunately ll_intent_lock may cause a callback and revoke our
           dentry */
        spin_lock(&dcache_lock);
        list_del_init(&de->d_hash);
        __d_rehash(de, 0);
        spin_unlock(&dcache_lock);

        RETURN(1);
}

struct dentry_operations ll_d_ops = {
        .d_revalidate2 = ll_revalidate2,
        .d_intent_release = ll_intent_release,
        .d_release = ll_release,
        .d_delete = ll_delete,
};
