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
#ifndef LUSTRE_KERNEL_VERSION
        if (lld->lld_it) {
                ll_intent_release(lld->lld_it);
                OBD_FREE(lld->lld_it, sizeof(*lld->lld_it));
        }
#endif
        LASSERT(lld->lld_cwd_count == 0);
        LASSERT(lld->lld_mnt_count == 0);
        OBD_FREE(de->d_fsdata, sizeof(*lld));

        EXIT;
}

#ifdef LUSTRE_KERNEL_VERSION
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
#endif

/* should NOT be called with the dcache lock, see fs/dcache.c */
static int ll_ddelete(struct dentry *de)
{
        ENTRY;
        LASSERT(de);
#ifndef DCACHE_LUSTRE_INVALID
#define DCACHE_LUSTRE_INVALID 0
#endif

        CDEBUG(D_DENTRY, "%s dentry %.*s (%p, parent %p, inode %p) %s%s\n",
               (de->d_flags & DCACHE_LUSTRE_INVALID ? "deleting" : "keeping"),
               de->d_name.len, de->d_name.name, de, de->d_parent, de->d_inode,
               d_unhashed(de) ? "" : "hashed,",
               list_empty(&de->d_subdirs) ? "" : "subdirs");
#if DCACHE_LUSTRE_INVALID == 0
#undef DCACHE_LUSTRE_INVALID
#endif

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
#ifdef LUSTRE_KERNEL_VERSION
        it->it_magic = 0;
        it->it_op_release = 0;
#endif
        /* We are still holding extra reference on a request, need to free it */
        if (it_disposition(it, DISP_ENQ_OPEN_REF)) /* open req for llfile_open*/
                ptlrpc_req_finished(it->d.lustre.it_data);
        if (it_disposition(it, DISP_ENQ_CREATE_REF)) /* create rec */
                ptlrpc_req_finished(it->d.lustre.it_data);
        if (it_disposition(it, DISP_ENQ_COMPLETE)) /* saved req from revalidate
                                                    * to lookup */
                ptlrpc_req_finished(it->d.lustre.it_data);

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

                /* 
                 * XXX: Try to drop negative not directory dentries to check if
                 * this is source of OOM on clients on big numbers of created
                 * files.  --umka
                 */
                if (!dentry->d_inode || !S_ISDIR(dentry->d_inode->i_mode))
                        __d_drop(dentry);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                __d_drop(dentry);
                if (dentry->d_inode) {
                        /* Put positive dentries to orphan list */
                        list_add(&dentry->d_hash,
                                 &ll_i2sbi(dentry->d_inode)->ll_orphan_dentry_list);
                }
#endif
#else
                if (!dentry->d_inode || !S_ISDIR(dentry->d_inode->i_mode))
                        __d_drop(dentry);
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

        if (it_disposition(it, DISP_LOOKUP_NEG)) 
                RETURN(-ENOENT);

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
        if (it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR) {
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
#if defined(LUSTRE_KERNEL_VERSION)&&(LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        if (it) {
                LASSERTF(it->it_magic == INTENT_MAGIC, 
                         "%p has bad intent magic: %x\n",
                         it, it->it_magic);
        }
#endif

        if (!it || it->it_op == IT_GETXATTR)
                it = *itp = deft;

#ifdef LUSTRE_KERNEL_VERSION
        it->it_op_release = ll_intent_release;
#endif
}

int ll_revalidate_it(struct dentry *de, int lookup_flags,
                     struct lookup_intent *it)
{
        int rc;
        struct md_op_data *op_data;
        struct ptlrpc_request *req = NULL;
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        struct obd_export *exp;
        struct inode *parent;

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,intent=%s\n", de->d_name.name,
               LL_IT2STR(it));

        if (de->d_inode == NULL) {
                /* We can only use negative dentries if this is stat or lookup,
                   for opens and stuff we do need to query server. */
                /* If there is IT_CREAT in intent op set, then we must throw
                   away this negative dentry and actually do the request to
                   kernel to create whatever needs to be created (if possible)*/
                if (it && (it->it_op & IT_CREAT))
                        RETURN(0);

#ifdef LUSTRE_KERNEL_VERSION
                if (de->d_flags & DCACHE_LUSTRE_INVALID)
                        RETURN(0);
#endif

                rc = ll_have_md_lock(de->d_parent->d_inode, 
                                     MDS_INODELOCK_UPDATE);
        
                RETURN(rc);
        }

        exp = ll_i2mdexp(de->d_inode);

        /* Never execute intents for mount points.
         * Attributes will be fixed up in ll_inode_revalidate_it */
        if (d_mountpoint(de))
                RETURN(1);

        /* Root of the lustre tree. Always valid.
         * Attributes will be fixed up in ll_inode_revalidate_it */
        if (de->d_name.name[0] == '/' && de->d_name.len == 1)
                RETURN(1);

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDC_REVALIDATE_PAUSE, 5);
        ll_frob_intent(&it, &lookup_it);
        LASSERT(it);

        parent = de->d_parent->d_inode;

        if (it->it_op & IT_CREAT) {
                /* 
                 * Allocate new fid for case of create or open(O_CREAT). In both
                 * cases it->it_op will contain IT_CREAT. In case of
                 * open(O_CREAT) agains existing file, fid allocating is not
                 * needed, but this is not known until server returns
                 * anything. Well, in this case new allocated fid is lost. But
                 * this is not big deal, we have 64bit fids. --umka
                 */
                struct lu_placement_hint hint = { .ph_pname = NULL,
                                                  .ph_pfid = ll_inode2fid(parent),
                                                  .ph_cname = &de->d_name,
                                                  .ph_opc = LUSTRE_OPC_CREATE };

                op_data = ll_prep_md_op_data(NULL, parent, NULL,
                                            de->d_name.name, de->d_name.len, 0);
                if (op_data == NULL)
                        RETURN(-ENOMEM);
                rc = ll_fid_md_alloc(ll_i2sbi(parent), &op_data->op_fid2, &hint);
                if (rc) {
                        ll_finish_md_op_data(op_data);
                        RETURN(rc);
                }
        } else {
                op_data = ll_prep_md_op_data(NULL, parent, de->d_inode,
                                             de->d_name.name, de->d_name.len, 0);
                if (op_data == NULL)
                        RETURN(-ENOMEM);
        }

        if ((it->it_op == IT_OPEN) && de->d_inode) {
                struct inode *inode = de->d_inode;
                struct ll_inode_info *lli = ll_i2info(inode);
                struct obd_client_handle **och_p;
                __u64 *och_usecount;
                
                /*
                 * We used to check for MDS_INODELOCK_OPEN here, but in fact
                 * just having LOOKUP lock is enough to justify inode is the
                 * same. And if inode is the same and we have suitable
                 * openhandle, then there is no point in doing another OPEN RPC
                 * just to throw away newly received openhandle.  There are no
                 * security implications too, if file owner or access mode is
                 * change, LOOKUP lock is revoked.
                 */

                it->it_create_mode &= ~current->fs->umask;

                if (it->it_flags & FMODE_WRITE) {
                        och_p = &lli->lli_mds_write_och;
                        och_usecount = &lli->lli_open_fd_write_count;
                } else if (it->it_flags & FMODE_EXEC) {
                        och_p = &lli->lli_mds_exec_och;
                        och_usecount = &lli->lli_open_fd_exec_count;
                } else {
                        och_p = &lli->lli_mds_read_och;
                        och_usecount = &lli->lli_open_fd_read_count;
                }
                /* Check for the proper lock. */
                if (!ll_have_md_lock(inode, MDS_INODELOCK_LOOKUP))
                        goto do_lock;
                down(&lli->lli_och_sem);
                if (*och_p) { /* Everything is open already, do nothing */
                        /*(*och_usecount)++;  Do not let them steal our open
                          handle from under us */
                        /* XXX The code above was my original idea, but in case
                           we have the handle, but we cannot use it due to later
                           checks (e.g. O_CREAT|O_EXCL flags set), nobody
                           would decrement counter increased here. So we just
                           hope the lock won't be invalidated in between. But
                           if it would be, we'll reopen the open request to
                           MDS later during file open path */
                        up(&lli->lli_och_sem);
                        ll_finish_md_op_data(op_data);
                        RETURN(1);
                } else {
                        up(&lli->lli_och_sem);
                }
        }

do_lock:
        it->it_flags |= O_CHECK_STALE;
        rc = md_intent_lock(exp, op_data, NULL, 0, it, lookup_flags,
                            &req, ll_md_blocking_ast, 0);
        it->it_flags &= ~O_CHECK_STALE;
        
        ll_finish_md_op_data(op_data);
        /* If req is NULL, then md_intent_lock only tried to do a lock match;
         * if all was well, it will return 1 if it found locks, 0 otherwise. */
        if (req == NULL && rc >= 0) {
                if (!rc)
                        goto do_lookup;
                GOTO(out, rc);
        }

        if (rc < 0) {
                if (rc != -ESTALE) {
                        CDEBUG(D_INFO, "ll_intent_lock: rc %d : it->it_status "
                               "%d\n", rc, it->d.lustre.it_status);
                }
                GOTO(out, rc = 0);
        }

revalidate_finish:
        rc = ll_revalidate_it_finish(req, DLM_REPLY_REC_OFF, it, de);
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
         * (see comment in mdc/mdc_locks.c::mdc_intent_lock()), request will
         * be freed in ll_lookup_it or in ll_intent_release. But if
         * request was not completed, we need to free it. (bug 5154, 9903) */
        if (req != NULL && !it_disposition(it, DISP_ENQ_COMPLETE))
                ptlrpc_req_finished(req);
        if (rc == 0) {
#ifdef LUSTRE_KERNEL_VERSION
                ll_unhash_aliases(de->d_inode);
                /* done in ll_unhash_aliases()
                   dentry->d_flags |= DCACHE_LUSTRE_INVALID; */
#else
                /* We do not want d_invalidate to kill all child dentries too */
                d_drop(de);
#endif
        } else {
                CDEBUG(D_DENTRY, "revalidated dentry %.*s (%p) parent %p "
                       "inode %p refc %d\n", de->d_name.len,
                       de->d_name.name, de, de->d_parent, de->d_inode,
                       atomic_read(&de->d_count));
                ll_lookup_finish_locks(it, de);
#ifdef LUSTRE_KERNEL_VERSION
                lock_dentry(de);
                de->d_flags &= ~DCACHE_LUSTRE_INVALID;
                unlock_dentry(de);
#endif
        }
        RETURN(rc);
        
        /*
         * This part is here to combat evil-evil race in real_lookup on 2.6
         * kernels.  The race details are: We enter do_lookup() looking for some
         * name, there is nothing in dcache for this name yet and d_lookup()
         * returns NULL.  We proceed to real_lookup(), and while we do this,
         * another process does open on the same file we looking up (most simple
         * reproducer), open succeeds and the dentry is added. Now back to
         * us. In real_lookup() we do d_lookup() again and suddenly find the
         * dentry, so we call d_revalidate on it, but there is no lock, so
         * without this code we would return 0, but unpatched real_lookup just
         * returns -ENOENT in such a case instead of retrying the lookup. Once
         * this is dealt with in real_lookup(), all of this ugly mess can go and
         * we can just check locks in ->d_revalidate without doing any RPCs
         * ever.
         */
do_lookup:
        if (it != &lookup_it) {
                ll_lookup_finish_locks(it, de);
                it = &lookup_it;
        }
        
        /* do real lookup here */
        op_data = ll_prep_md_op_data(NULL, parent, NULL,
                                     de->d_name.name, de->d_name.len, 0);
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        if (it->it_op & IT_CREAT) {
                /* 
                 * Allocate new fid for case of create or open with O_CREAT. In
                 * both cases it->it_op will contain IT_CREAT.
                 */
                struct lu_placement_hint hint = { .ph_pname = NULL,
                                                  .ph_pfid = ll_inode2fid(parent),
                                                  .ph_cname = &de->d_name,
                                                  .ph_opc = LUSTRE_OPC_CREATE };

                rc = ll_fid_md_alloc(ll_i2sbi(parent), &op_data->op_fid2, &hint);
                if (rc) {
                        ll_finish_md_op_data(op_data);
                        RETURN(rc);
                }
        }
        
        rc = md_intent_lock(exp, op_data, NULL, 0,  it, 0, &req,
                            ll_md_blocking_ast, 0);
        if (rc >= 0) {
                struct mdt_body *mdt_body = lustre_msg_buf(req->rq_repmsg,
                                                           DLM_REPLY_REC_OFF,
                                                           sizeof(*mdt_body));
                /* see if we got same inode, if not - return error */
                if (lu_fid_eq(&op_data->op_fid2, &mdt_body->fid1)) {
                        ll_finish_md_op_data(op_data);
                        op_data = NULL;
                        goto revalidate_finish;
                }
                ll_intent_release(it);
        }
        ll_finish_md_op_data(op_data);
        GOTO(out, rc = 0);
}

/*static*/ void ll_pin(struct dentry *de, struct vfsmount *mnt, int flag)
{
        struct inode *inode= de->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_dentry_data *ldd = ll_d2d(de);
        struct obd_client_handle *handle;
        struct obd_capa *oc;
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
        oc = ll_mdscapa_get(inode);
        rc = obd_pin(sbi->ll_md_exp, ll_inode2fid(inode), oc, handle, flag);
        capa_put(oc);
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
#ifdef LUSTRE_KERNEL_VERSION
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
#else
int ll_revalidate_nd(struct dentry *dentry, struct nameidata *nd)
{
        int rc;
        ENTRY;

        if (nd && !(nd->flags & (LOOKUP_CONTINUE|LOOKUP_PARENT))) {
                struct lookup_intent *it;
                it = ll_convert_intent(&nd->intent.open, nd->flags);
                if (IS_ERR(it))
                        RETURN(0);
                if (it->it_op == (IT_OPEN|IT_CREAT))
                        if (nd->intent.open.flags & O_EXCL) {
                                CDEBUG(D_VFSTRACE, "create O_EXCL, returning 0\n");
                                rc = 0;
                                goto out_it;
                        }

                rc = ll_revalidate_it(dentry, nd->flags, it);

                if (rc && (nd->flags & LOOKUP_OPEN) &&
                    it_disposition(it, DISP_OPEN_OPEN)) {/*Open*/
#ifdef HAVE_FILE_IN_STRUCT_INTENT
// XXX Code duplication with ll_lookup_nd
                        if (S_ISFIFO(dentry->d_inode->i_mode)) {
                                // We cannot call open here as it would
                                // deadlock.
                                ptlrpc_req_finished(
                                               (struct ptlrpc_request *)
                                                  it->d.lustre.it_data);
                        } else {
                                struct file *filp;

                                nd->intent.open.file->private_data = it;
                                filp = lookup_instantiate_filp(nd, dentry,NULL);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
/* 2.6.1[456] have a bug in open_namei() that forgets to check
 * nd->intent.open.file for error, so we need to return it as lookup's result
 * instead */
                                if (IS_ERR(filp))
                                        rc = 0;
#endif
                        }
#else
                        ll_release_openhandle(dentry, it);
#endif /* HAVE_FILE_IN_STRUCT_INTENT */
                }
                if (!rc && (nd->flags & LOOKUP_CREATE) &&
                    it_disposition(it, DISP_OPEN_CREATE)) {
                        /* We created something but we may only return
                         * negative dentry here, so save request in dentry,
                         * if lookup will be called later on, it will
                         * pick the request, otherwise it would be freed
                         * with dentry */
                        ll_d2d(dentry)->lld_it = it;
                        it = NULL; /* avoid freeing */
                }
                        
out_it:
                if (it) {
                        ll_intent_release(it);
                        OBD_FREE(it, sizeof(*it));
                }
        } else {
                rc = ll_revalidate_it(dentry, 0, NULL);
        }

        RETURN(rc);
}
#endif
#endif

struct dentry_operations ll_d_ops = {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        .d_revalidate = ll_revalidate_nd,
#else
        .d_revalidate_it = ll_revalidate_it,
#endif
        .d_release = ll_release,
        .d_delete = ll_ddelete,
#ifdef LUSTRE_KERNEL_VERSION
        .d_compare = ll_dcompare,
#endif
#if 0
        .d_pin = ll_pin,
        .d_unpin = ll_unpin,
#endif
};
