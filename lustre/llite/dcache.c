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

#include <obd_support.h>
#include <lustre_lite.h>
#include <lustre/lustre_idl.h>
#include <lustre_dlm.h>
#include <lustre_mdc.h>
#include <lustre_ver.h>

#include "llite_internal.h"

/* should NOT be called with the dcache lock, see fs/dcache.c */
static void ll_release(struct dentry *de)
{
        struct ll_dentry_data *lld;
        ENTRY;
        LASSERT(de != NULL);
        lld = ll_d2d(de);
        if (lld == NULL) { /* NFS copies the de->d_op methods (bug 4655) */
                EXIT;
                return;
        }
        LASSERT(lld->lld_cwd_count == 0);
        LASSERT(lld->lld_mnt_count == 0);
        OBD_FREE(de->d_fsdata, sizeof(*lld));

        EXIT;
}

/* Compare if two dentries are the same.  Don't match if the existing dentry
 * is marked DCACHE_LUSTRE_INVALID.  Returns 1 if different, 0 if the same.
 *
 * This avoids a race where ll_lookup_it() instantiates a dentry, but we get
 * an AST before calling d_revalidate_it().  The dentry still exists (marked
 * INVALID) so d_lookup() matches it, but we have no lock on it (so
 * lock_match() fails) and we spin around real_lookup(). */
int ll_dcompare(struct dentry *parent, struct qstr *d_name, struct qstr *name)
{
        struct dentry *dchild;
        ENTRY;

        if (d_name->len != name->len)
                RETURN(1);

        if (memcmp(d_name->name, name->name, name->len))
                RETURN(1);

        /* XXX: d_name must be in-dentry structure */
        dchild = container_of(d_name, struct dentry, d_name); /* ugh */
        if (dchild->d_flags & DCACHE_LUSTRE_INVALID) {
                CDEBUG(D_DENTRY,"INVALID dentry %p not matched, was bug 3784\n",
                       dchild);
                RETURN(1);
        }

        RETURN(0);
}

/* should NOT be called with the dcache lock, see fs/dcache.c */
static int ll_ddelete(struct dentry *de)
{
        ENTRY;
        LASSERT(de);
        CDEBUG(D_DENTRY, "%s dentry %.*s (%p, parent %p, inode %p) %s%s\n",
               (de->d_flags & DCACHE_LUSTRE_INVALID ? "deleting" : "keeping"),
               de->d_name.len, de->d_name.name, de, de->d_parent, de->d_inode,
               d_unhashed(de) ? "" : "hashed,",
               list_empty(&de->d_subdirs) ? "" : "subdirs");
        RETURN(0);
}

void ll_set_dd(struct dentry *de)
{
        ENTRY;
        LASSERT(de != NULL);

        CDEBUG(D_DENTRY, "ldd on dentry %.*s (%p) parent %p inode %p refc %d\n",
               de->d_name.len, de->d_name.name, de, de->d_parent, de->d_inode,
               atomic_read(&de->d_count));
        lock_kernel();
        if (de->d_fsdata == NULL) {
                OBD_ALLOC(de->d_fsdata, sizeof(struct ll_dentry_data));
        }
        unlock_kernel();

        EXIT;
}

void ll_intent_drop_lock(struct lookup_intent *it)
{
        struct lustre_handle *handle;

        if (it->it_op && it->d.lustre.it_lock_mode) {
                handle = (struct lustre_handle *)&it->d.lustre.it_lock_handle;
                CDEBUG(D_DLMTRACE, "releasing lock with cookie "LPX64
                       " from it %p\n", handle->cookie, it);
                ldlm_lock_decref(handle, it->d.lustre.it_lock_mode);

                /* bug 494: intent_release may be called multiple times, from
                 * this thread and we don't want to double-decref this lock */
                it->d.lustre.it_lock_mode = 0;
        }
}

void ll_intent_release(struct lookup_intent *it)
{
        ENTRY;

        CDEBUG(D_INFO, "intent %p released\n", it);
        ll_intent_drop_lock(it);
        it->it_magic = 0;
        it->it_op_release = 0;
        it->d.lustre.it_disposition = 0;
        it->d.lustre.it_data = NULL;
        EXIT;
}

/* Drop dentry if it is not used already, unhash otherwise.
   Should be called with dcache lock held!
   Returns: 1 if dentry was dropped, 0 if unhashed. */
int ll_drop_dentry(struct dentry *dentry)
{
        lock_dentry(dentry);
                CDEBUG(D_DENTRY, "dentry in drop %.*s (%p) parent %p "
                       "inode %p flags %d\n", dentry->d_name.len,
                       dentry->d_name.name, dentry, dentry->d_parent,
                       dentry->d_inode, dentry->d_flags);

        if (atomic_read(&dentry->d_count) == 0) {
                CDEBUG(D_DENTRY, "deleting dentry %.*s (%p) parent %p "
                       "inode %p\n", dentry->d_name.len,
                       dentry->d_name.name, dentry, dentry->d_parent,
                       dentry->d_inode);
                dget_locked(dentry);
                __d_drop(dentry);
                unlock_dentry(dentry);
                spin_unlock(&dcache_lock);
                dput(dentry);
                spin_lock(&dcache_lock);
                return 1;
        }

#ifdef LUSTRE_KERNEL_VERSION
        if (!(dentry->d_flags & DCACHE_LUSTRE_INVALID)) {
#else
        if (!d_unhashed(dentry)) {
                struct inode *inode = dentry->d_inode;
#endif
                CDEBUG(D_DENTRY, "unhashing dentry %.*s (%p) parent %p "
                       "inode %p refc %d\n", dentry->d_name.len,
                       dentry->d_name.name, dentry, dentry->d_parent,
                       dentry->d_inode, atomic_read(&dentry->d_count));
                /* actually we don't unhash the dentry, rather just
                 * mark it inaccessible for to __d_lookup(). otherwise
                 * sys_getcwd() could return -ENOENT -bzzz */
#ifdef LUSTRE_KERNEL_VERSION
                dentry->d_flags |= DCACHE_LUSTRE_INVALID;
#else
                if (!inode || !S_ISDIR(inode->i_mode))
                        __d_drop(dentry);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                __d_drop(dentry);
                if (inode) {
                        /* Put positive dentries to orphan list */
                        hlist_add_head(&dentry->d_hash,
                                       &ll_i2sbi(inode)->ll_orphan_dentry_list);
                }
#endif
        }
        unlock_dentry(dentry);
        return 0;
}

void ll_unhash_aliases(struct inode *inode)
{
        struct list_head *tmp, *head;
        ENTRY;

        if (inode == NULL) {
                CERROR("unexpected NULL inode, tell phil\n");
                return;
        }

        CDEBUG(D_INODE, "marking dentries for 111 ino %lu/%u(%p) invalid\n",
               inode->i_ino, inode->i_generation, inode);

        head = &inode->i_dentry;
        spin_lock(&dcache_lock);
restart:
        tmp = head;
        while ((tmp = tmp->next) != head) {
                struct dentry *dentry = list_entry(tmp, struct dentry, d_alias);

                CDEBUG(D_DENTRY, "dentry in drop %.*s (%p) parent %p "
                       "inode %p flags %d\n", dentry->d_name.len,
                       dentry->d_name.name, dentry, dentry->d_parent,
                       dentry->d_inode, dentry->d_flags);

                if (dentry->d_name.len == 1 && dentry->d_name.name[0] == '/') {
                        CERROR("called on root (?) dentry=%p, inode=%p "
                               "ino=%lu\n", dentry, inode, inode->i_ino);
                        lustre_dump_dentry(dentry, 1);
                        libcfs_debug_dumpstack(NULL);
                } else if (d_mountpoint(dentry)) {
                        /* For mountpoints we skip removal of the dentry
                           which happens solely because we have a lock on it
                           obtained when this dentry was not a mountpoint yet */
                        CDEBUG(D_DENTRY, "Skippind mountpoint dentry removal "
                                         "%.*s (%p) parent %p\n",
                                          dentry->d_name.len,
                                          dentry->d_name.name,
                                          dentry, dentry->d_parent);

                        continue;
                }
                
                if (ll_drop_dentry(dentry))
                          goto restart;
        }
        spin_unlock(&dcache_lock);
        EXIT;
}

int ll_revalidate_it_finish(struct ptlrpc_request *request,
                            int offset, struct lookup_intent *it,
                            struct dentry *de)
{
        int rc = 0;
        ENTRY;

        if (!request)
                RETURN(0);

        if (it_disposition(it, DISP_LOOKUP_NEG)) {
                /*Sometimes, revalidate_it might also create node in MDS,
                 *So we need check whether it is really created, if not,
                 *just return the -ENOENT, if it is, return -ESTALE anyway.
                 *which is original done in mdc_intent_lock, 
                 *but no chance for new fid allocation in client. 
                 */
                if (it_disposition(it, DISP_OPEN_CREATE) && 
                    !it_open_error(DISP_OPEN_CREATE, it)) {
                         /*These 2 req finished is for balancing 2 add ref
                          *in mdc_intent_lock, since there are no create_node
                          *and file_open following revalidate_it*/
                         it_set_disposition(it, DISP_ENQ_COMPLETE);
                         if (it_disposition(it, DISP_OPEN_CREATE) &&
                            !it_open_error(DISP_OPEN_CREATE, it))
                                ptlrpc_req_finished(request); 
                         if (it_disposition(it, DISP_OPEN_OPEN) &&
                            !it_open_error(DISP_OPEN_OPEN, it))
                                ptlrpc_req_finished(request); 
                        
                         RETURN(-ESTALE);
                }
                RETURN(-ENOENT);
        }

        rc = ll_prep_inode(&de->d_inode,
                           request, offset, NULL);

        RETURN(rc);
}

void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry)
{
        LASSERT(it != NULL);
        LASSERT(dentry != NULL);

        if (it->d.lustre.it_lock_mode && dentry->d_inode != NULL) {
                struct inode *inode = dentry->d_inode;
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);

                CDEBUG(D_DLMTRACE, "setting l_data to inode %p (%lu/%u)\n",
                       inode, inode->i_ino, inode->i_generation);
                md_set_lock_data(sbi->ll_md_exp, &it->d.lustre.it_lock_handle,
                                 inode);
        }

        /* drop lookup or getattr locks immediately */
        if (it->it_op & (IT_LOOKUP | IT_GETATTR)) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                /* on 2.6 there are situation when several lookups and
                 * revalidations may be requested during single operation.
                 * therefore, we don't release intent here -bzzz */
                ll_intent_drop_lock(it);
#else
                ll_intent_release(it);
#endif
        }
}

void ll_frob_intent(struct lookup_intent **itp, struct lookup_intent *deft)
{
        struct lookup_intent *it = *itp;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        if (it) {
                LASSERTF(it->it_magic == INTENT_MAGIC, 
                         "%p has bad intent magic: %x\n",
                         it, it->it_magic);
        }
#endif

        if (!it || it->it_op == IT_GETXATTR)
                it = *itp = deft;

        it->it_op_release = ll_intent_release;
}

int ll_revalidate_it(struct dentry *de, int lookup_flags,
                     struct lookup_intent *it)
{
        int rc;
        struct it_cb_data icbd;
        struct md_op_data *op_data;
        struct ptlrpc_request *req = NULL;
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        struct obd_export *exp;
        struct inode *parent;

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,intent=%s\n", de->d_name.name,
               LL_IT2STR(it));

        /* Cached negative dentries are unsafe for now - look them up again */
        if (de->d_inode == NULL)
                RETURN(0);

        exp = ll_i2mdexp(de->d_inode);
        icbd.icbd_parent = de->d_parent->d_inode;
        icbd.icbd_childp = &de;

        /* Never execute intents for mount points.
         * Attributes will be fixed up in ll_inode_revalidate_it */
        if (d_mountpoint(de))
                RETURN(1);

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDC_REVALIDATE_PAUSE, 5);
        ll_frob_intent(&it, &lookup_it);
        LASSERT(it);

        parent = de->d_parent->d_inode;

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        if (it->it_op & IT_CREAT) {
                struct lu_placement_hint hint = { .ph_pname = NULL,
                                          .ph_pfid = ll_inode2fid(parent),
                                          .ph_cname = &de->d_name,
                                          .ph_opc = LUSTRE_OPC_CREATE };

                ll_prepare_md_op_data(op_data, parent, NULL,
                                      de->d_name.name, de->d_name.len, 0);
                rc = ll_fid_md_alloc(ll_i2sbi(parent), &op_data->fid2, 
                                     &hint);
                if (rc) {
                        CERROR("can't allocate new fid, rc %d\n", rc);
                        LBUG();
                }
        } else {
                ll_prepare_md_op_data(op_data, parent, de->d_inode,
                                      de->d_name.name, de->d_name.len, 0);
        }

        rc = md_intent_lock(exp, op_data, NULL, 0, it, lookup_flags,
                            &req, ll_md_blocking_ast, 0);

        OBD_FREE_PTR(op_data);
        /* If req is NULL, then md_intent_lock only tried to do a lock match;
         * if all was well, it will return 1 if it found locks, 0 otherwise. */
        if (req == NULL && rc >= 0) {
                GOTO(out, rc);
        }

        if (rc < 0) {
                if (rc != -ESTALE) {
                        CDEBUG(D_INFO, "ll_intent_lock: rc %d : it->it_status "
                               "%d\n", rc, it->d.lustre.it_status);
                }
                GOTO(out, rc = 0);
        }

        rc = ll_revalidate_it_finish(req, 1, it, de);
        if (rc != 0) {
                if (rc != -ESTALE && rc != -ENOENT)
                        ll_intent_release(it);
                GOTO(out, rc = 0);
        }
        if ((it->it_op & IT_OPEN) && de->d_inode && 
            !S_ISREG(de->d_inode->i_mode) && 
            !S_ISDIR(de->d_inode->i_mode)) {
                ll_release_openhandle(de, it);
        }
        rc = 1;

        /* unfortunately ll_intent_lock may cause a callback and revoke our
         * dentry */
        spin_lock(&dcache_lock);
        lock_dentry(de);
        __d_drop(de);
        unlock_dentry(de);
        __d_rehash(de, 0);
        spin_unlock(&dcache_lock);

 out:
        /* We do not free request as it may be reused during following lookup
          (see comment in mdc/mdc_locks.c::mdc_intent_lock()), request will
           be freed in ll_lookup_it or in ll_intent_release. But if
           request was not completed, we need to free it. (bug 5154) */
        if (req != NULL && !it_disposition(it, DISP_ENQ_COMPLETE))
                ptlrpc_req_finished(req);
        if (rc == 0) {
                ll_unhash_aliases(de->d_inode);
                /* done in ll_unhash_aliases()
                dentry->d_flags |= DCACHE_LUSTRE_INVALID; */
        } else {
                CDEBUG(D_DENTRY, "revalidated dentry %.*s (%p) parent %p "
                               "inode %p refc %d\n", de->d_name.len,
                               de->d_name.name, de, de->d_parent, de->d_inode,
                               atomic_read(&de->d_count));
                ll_lookup_finish_locks(it, de);
                lock_dentry(de);
                de->d_flags &= ~DCACHE_LUSTRE_INVALID;
                unlock_dentry(de);
        }
        RETURN(rc);
}

/*static*/ void ll_pin(struct dentry *de, struct vfsmount *mnt, int flag)
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
        rc = obd_pin(sbi->ll_md_exp, &ll_i2info(inode)->lli_fid,
                     handle, flag);

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

/*static*/ void ll_unpin(struct dentry *de, struct vfsmount *mnt, int flag)
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

        rc = obd_unpin(sbi->ll_md_exp, &handle, flag);
        EXIT;
        return;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int ll_revalidate_nd(struct dentry *dentry, struct nameidata *nd)
{
        int rc;
        ENTRY;

        if (nd && nd->flags & LOOKUP_LAST && !(nd->flags & LOOKUP_LINK_NOTLAST))
                rc = ll_revalidate_it(dentry, nd->flags, &nd->intent);
        else
                rc = ll_revalidate_it(dentry, 0, NULL);

        RETURN(rc);
}
#endif

struct dentry_operations ll_d_ops = {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        .d_revalidate = ll_revalidate_nd,
#else
        .d_revalidate_it = ll_revalidate_it,
#endif
        .d_release = ll_release,
        .d_delete = ll_ddelete,
        .d_compare = ll_dcompare,
#if 0
        .d_pin = ll_pin,
        .d_unpin = ll_unpin,
#endif
};
