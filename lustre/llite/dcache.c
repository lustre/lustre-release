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
#include <linux/lustre_version.h>
#include "llite_internal.h"

/* should NOT be called with the dcache lock, see fs/dcache.c */
static void ll_release(struct dentry *de)
{
        struct ll_dentry_data *lld;
        ENTRY;
        LASSERT(de != NULL);

        CDEBUG(D_DENTRY, "releasing dentry %p\n", de);

        lld = ll_d2d(de);
        if (lld) { /* Root dentry does not have ll_dentry_data */
                LASSERT(lld->lld_cwd_count == 0);
                LASSERT(lld->lld_mnt_count == 0);
                OBD_FREE(de->d_fsdata, sizeof(struct ll_dentry_data));
        }

        EXIT;
}

/* Compare if two dentries are the same.  Don't match if the existing dentry
 * is marked DCACHE_LUSTRE_INVALID.  Returns 1 if different, 0 if the same.
 *
 * This avoids a race where ll_lookup_it() instantiates a dentry, but we get
 * an AST before calling d_revalidate_it().  The dentry still exists (marked
 * INVALID) so d_lookup() matches it, but we have no lock on it (so
 * lock_match() fails) and we spin around real_lookup(). */
static int ll_dcompare(struct dentry *parent, struct qstr *d_name,
                       struct qstr *name){
        struct dentry *dchild;
        ENTRY;

        if (d_name->len != name->len)
                RETURN(1);

        if (memcmp(d_name->name, name->name, name->len))
                RETURN(1);

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
        CDEBUG(D_DENTRY, "%s dentry %*s (%p, parent %p, inode %p) %s%s\n",
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
        struct lustre_intent_data *itdata = LUSTRE_IT(it);

        if (it->it_op && itdata && itdata->it_lock_mode) {
                handle = (struct lustre_handle *)&itdata->it_lock_handle;
                CDEBUG(D_DLMTRACE, "releasing lock with cookie "LPX64
                       " from it %p\n", handle->cookie, it);
                ldlm_lock_decref(handle, itdata->it_lock_mode);

                /* bug 494: intent_release may be called multiple times, from
                 * this thread and we don't want to double-decref this lock */
                itdata->it_lock_mode = 0;
        }
}

void ll_intent_release(struct lookup_intent *it)
{
        ENTRY;

        ll_intent_drop_lock(it);
        it->it_magic = 0;
        it->it_op_release = 0;
        ll_intent_free(it);
        EXIT;
}

void ll_unhash_aliases(struct inode *inode)
{
        struct list_head *tmp, *head;
        struct ll_sb_info *sbi;
        ENTRY;

        if (inode == NULL) {
                CERROR("unexpected NULL inode, tell phil\n");
                EXIT;
                return;
        }

        CDEBUG(D_INODE, "marking dentries for ino %lu/%u(%p) invalid\n",
               inode->i_ino, inode->i_generation, inode);

        sbi = ll_i2sbi(inode);
        head = &inode->i_dentry;
restart:
        spin_lock(&dcache_lock);
        tmp = head;
        while ((tmp = tmp->next) != head) {
                struct dentry *dentry = list_entry(tmp, struct dentry, d_alias);
                if (atomic_read(&dentry->d_count) == 0) {
                        CDEBUG(D_DENTRY, "deleting dentry %.*s (%p) parent %p "
                               "inode %p\n", dentry->d_name.len,
                               dentry->d_name.name, dentry, dentry->d_parent,
                               dentry->d_inode);
                        dget_locked(dentry);
                        __d_drop(dentry);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                        INIT_HLIST_NODE(&dentry->d_hash);
#endif
                        spin_unlock(&dcache_lock);
                        dput(dentry);
                        goto restart;
                } else if (!(dentry->d_flags & DCACHE_LUSTRE_INVALID)) {
                        CDEBUG(D_DENTRY, "unhashing dentry %.*s (%p) parent %p "
                               "inode %p refc %d\n", dentry->d_name.len,
                               dentry->d_name.name, dentry, dentry->d_parent,
                               dentry->d_inode, atomic_read(&dentry->d_count));
                        hlist_del_init(&dentry->d_hash);
                        dentry->d_flags |= DCACHE_LUSTRE_INVALID;
                        hlist_add_head(&dentry->d_hash,
                                       &sbi->ll_orphan_dentry_list);
                }
        }
        spin_unlock(&dcache_lock);
        EXIT;
}

extern struct dentry *ll_find_alias(struct inode *, struct dentry *);

int revalidate_it_finish(struct ptlrpc_request *request, int offset, 
                         struct lookup_intent *it, struct dentry *de)
{
        struct ll_sb_info *sbi;
        int rc = 0;
        ENTRY;

        if (!request)
                RETURN(0);

        if (it_disposition(it, DISP_LOOKUP_NEG))
                RETURN(-ENOENT);

        sbi = ll_i2sbi(de->d_inode);
        rc = ll_prep_inode(sbi->ll_dt_exp, sbi->ll_md_exp,
                           &de->d_inode, request, offset, NULL);

        RETURN(rc);
}

void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry)
{
        LASSERT(it != NULL);
        LASSERT(dentry != NULL);

        if (LUSTRE_IT(it)->it_lock_mode && dentry->d_inode != NULL) {
                struct inode *inode = dentry->d_inode;
                CDEBUG(D_DLMTRACE, "setting l_data to inode %p (%lu/%u)\n",
                       inode, inode->i_ino, inode->i_generation);
                mdc_set_lock_data(NULL, &LUSTRE_IT(it)->it_lock_handle, inode);
        }

        /* drop lookup or getattr locks immediately */
        if (it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR ||
            it->it_op == IT_CHDIR) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                /*
                 * on 2.6 there are situations when several lookups and
                 * revalidations may be requested during single operation.
                 * Therefore, we don't release intent here -bzzz
                 */
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
                LASSERTF(it->it_magic == INTENT_MAGIC, "bad intent magic: %x\n",
                         it->it_magic);
        }
#endif

        if (!it || it->it_op == IT_GETXATTR)
                it = *itp = deft;

        if (it->d.fs_data)
                return;

        if (ll_intent_alloc(it)) {
                CERROR("Failed to allocate memory for lustre specific intent "
                       "data\n");
                /* XXX: we cannot return status just yet */
                LBUG();
        }
}

int ll_intent_alloc(struct lookup_intent *it)
{
        if (it->d.fs_data) {
                CERROR("Intent alloc on already allocated intent\n");
                return 0;
        }
        OBD_SLAB_ALLOC(it->d.fs_data, ll_intent_slab, SLAB_KERNEL,
                       sizeof(struct lustre_intent_data));
        if (!it->d.fs_data) {
                CERROR("Failed to allocate memory for lustre specific intent "
                       "data\n");
                return -ENOMEM;
        }

        it->it_op_release = ll_intent_release;
        return 0;
}

void ll_intent_free(struct lookup_intent *it)
{
        if (it->d.fs_data) {
                struct lustre_intent_data *lustre_data = 
                        (struct lustre_intent_data *)it->d.fs_data;
                if (lustre_data->it_key) {
                        OBD_FREE(lustre_data->it_key, 
                                 lustre_data->it_key_size);
                        lustre_data->it_key = NULL;
                        lustre_data->it_key_size = 0;
                }
                OBD_SLAB_FREE(it->d.fs_data, ll_intent_slab,
                              sizeof(struct lustre_intent_data));
                it->d.fs_data = NULL;
        }
}

static inline int 
ll_special_name(struct dentry *de)
{
	if (de->d_name.name[0] == '.') switch (de->d_name.len) {
		case 2:
			if (de->d_name.name[1] == '.')
				return 1;
		case 1:
			return 1;
		default:
			return 0;
	}
	return 0;
}

int ll_revalidate_it(struct dentry *de, int flags, struct nameidata *nd,
                     struct lookup_intent *it)
{
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        struct ptlrpc_request *req = NULL;
        int gns_it, gns_flags, rc = 0;
        struct obd_export *exp;
        struct it_cb_data icbd;
        struct lustre_id pid;
        struct lustre_id cid;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s (%p), intent=%s\n", de->d_name.name,
               de, LL_IT2STR(it));

        /* Cached negative dentries are unsafe for now - look them up again */
        if (de->d_inode == NULL)
                RETURN(0);

        /*
         * root of the tree is always valid, attributes would be fixed in
         * ll_inode_revalidate_it()
         */
        if (de->d_sb->s_root == de)
                RETURN(1);

        CDEBUG(D_INODE, "revalidate 0x%p: %*s -> %lu/%lu\n",
               de, de->d_name.len, de->d_name.name,
               (unsigned long) de->d_inode->i_ino,
               (unsigned long) de->d_inode->i_generation);

        exp = ll_i2mdexp(de->d_inode);
        ll_inode2id(&pid, de->d_parent->d_inode);
        ll_inode2id(&cid, de->d_inode);
        LASSERT(id_fid(&cid) != 0);

        icbd.icbd_parent = de->d_parent->d_inode;
        icbd.icbd_childp = &de;

        /*
         * never execute intents for mount points. Attributes will be fixed up
         * in ll_inode_revalidate_it().
         */
        if (d_mountpoint(de))
                RETURN(1);

        if (nd != NULL)
                nd->mnt->mnt_last_used = jiffies;

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDC_REVALIDATE_PAUSE, 5);
        gns_it = nd ? nd->intent.open.it_op : IT_OPEN;
        gns_flags = nd ? nd->flags : LOOKUP_CONTINUE;

        if (it && it->it_op == IT_GETATTR)
                it = NULL; /* will use it_lookup */
        else if (it && (it->it_op == IT_OPEN) && de->d_inode) {
                /* open lock stuff */
                struct inode *inode = de->d_inode;
                struct ll_inode_info *lli = ll_i2info(inode);
                struct obd_client_handle **och_p;
                __u64 *och_usecount;
                struct obd_device *obddev;
                struct lustre_handle lockh;
                int flags = LDLM_FL_BLOCK_GRANTED;
                ldlm_policy_data_t policy = {.l_inodebits = {MDS_INODELOCK_OPEN}};
                struct ldlm_res_id file_res_id = {.name = {id_fid(&lli->lli_id), 
							   id_group(&lli->lli_id)}};
                int lockmode;

                if (it->it_flags & FMODE_WRITE) {
                        och_p = &lli->lli_mds_write_och;
                        och_usecount = &lli->lli_open_fd_write_count;
                        lockmode = LCK_CW;
                } else if (it->it_flags & FMODE_EXEC) {
                        och_p = &lli->lli_mds_exec_och;
                        och_usecount = &lli->lli_open_fd_exec_count;
                        lockmode = LCK_PR;
                } else {
                        och_p = &lli->lli_mds_read_och;
                        och_usecount = &lli->lli_open_fd_read_count;
                        lockmode = LCK_CR;
                }

                /* Check for the proper lock */
                obddev = md_get_real_obd(exp, &lli->lli_id);
                if (!ldlm_lock_match(obddev->obd_namespace, flags, &file_res_id,
                                     LDLM_IBITS, &policy, lockmode, &lockh))
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
                        if (ll_intent_alloc(it))
                                LBUG();
                        memcpy(&LUSTRE_IT(it)->it_lock_handle, &lockh,
                               sizeof(lockh));
                        LUSTRE_IT(it)->it_lock_mode = lockmode;

                        /* 
                         * we do not check here for possible GNS dentry as if
                         * file is opened on it, it is mounted already and we do
                         * not need do anything. --umka
                         */
                        RETURN(1);
                } else {
                        /* Hm, interesting. Lock is present, but no open
                           handle? */
                        up(&lli->lli_och_sem);
                        ldlm_lock_decref(&lockh, lockmode);
                }
        }

do_lock:
        ll_frob_intent(&it, &lookup_it);
        LASSERT(it != NULL);
        
        rc = ll_crypto_init_it_key(de->d_inode, it);
        if (rc)
                GOTO(out, rc);
        
        rc = md_intent_lock(exp, &pid, (char *)de->d_name.name, de->d_name.len,
                            NULL, 0, &cid, it, flags, &req, ll_mdc_blocking_ast);
        /* If req is NULL, then md_intent_lock() only tried to do a lock match;
         * if all was well, it will return 1 if it found locks, 0 otherwise. */
        if (req == NULL && rc >= 0) {
                if (!rc)
                        goto do_lookup;
                GOTO(out, rc);
        }

        if (rc < 0) {
                if (rc != -ESTALE) {
                        CDEBUG(D_INFO, "ll_intent_lock(): rc %d : it->it_status "
                               "%d\n", rc, LUSTRE_IT(it)->it_status);
                }
                GOTO(out, rc = 0);
        }
revalidate_finish:
        rc = revalidate_it_finish(req, 1, it, de);
        if (rc != 0) {
                ll_intent_release(it);
                GOTO(out, rc = 0);
        }
        rc = 1;

        /* unfortunately ll_intent_lock may cause a callback and revoke our
           dentry */
        spin_lock(&dcache_lock);
        hlist_del_init(&de->d_hash);
        __d_rehash(de);
        spin_unlock(&dcache_lock);

        GOTO(out, rc);
out:
        /* If we had succesful it lookup on mds, but it happened to be negative,
           we do not free request as it will be reused during lookup (see
           comment in mdc/mdc_locks.c::mdc_intent_lock(). But if
           request was not completed, we need to free it. (bug 5154) */
        if (req != NULL && (rc == 1 || !it_disposition(it, DISP_ENQ_COMPLETE))) {
                ptlrpc_req_finished(req);
                req = NULL;
        }

        if (rc == 0) {
                if (it == &lookup_it)
                        ll_intent_release(it);

                ll_unhash_aliases(de->d_inode);
                RETURN(0);
        }

        /* 
         * if we found that this is possible GNS mount and dentry is still valid
         * and may be used by system, we drop the lock and return 0, that means
         * that re-lookup is needed. Such a way we cause real mounting only in
         * lookup control path, which is always made with parent's i_sem taken.
         * --umka
         */
        if (nd && atomic_read(&ll_i2sbi(de->d_inode)->ll_gns_enabled) &&
            (de->d_inode->i_mode & S_ISUID) && S_ISDIR(de->d_inode->i_mode) &&
            (gns_flags & LOOKUP_CONTINUE || (gns_it & (IT_CHDIR | IT_OPEN)))) {
                /* 
                 * special "." and ".." has to be always revalidated because
                 * they never should be passed to lookup()
                 */
                if (!ll_special_name(de)) {
                        CDEBUG(D_DENTRY, "possible GNS dentry %*s %p found, "
                               "causing mounting\n", (int)de->d_name.len,
                               de->d_name.name, de);
                        
                        LASSERT(req == NULL);
                        if (it == &lookup_it) {
                                ll_intent_release(it);
                        } else {
                                ll_intent_drop_lock(it);
                        }
                        ll_unhash_aliases(de->d_inode);
                        RETURN(0);
                }
        }

        CDEBUG(D_DENTRY, "revalidated dentry %*s (%p) parent %p "
               "inode %p refc %d\n", de->d_name.len,
               de->d_name.name, de, de->d_parent, de->d_inode,
               atomic_read(&de->d_count));

        if (it == &lookup_it)
                ll_intent_release(it);
        else
                ll_lookup_finish_locks(it, de);

        de->d_flags &= ~DCACHE_LUSTRE_INVALID;
        return rc;

do_lookup:
        if (it != &lookup_it) {
                ll_lookup_finish_locks(it, de);
                it = &lookup_it;
                if (ll_intent_alloc(it))
                        LBUG();
        }
        rc = ll_crypto_init_it_key(de->d_inode, it);
        if (rc)
               GOTO(out, rc); 
        rc = md_intent_lock(exp, &pid, (char *)de->d_name.name, de->d_name.len,
                            NULL, 0, NULL, it, 0, &req, ll_mdc_blocking_ast);
        if (rc >= 0) {
                struct mds_body *mds_body = lustre_msg_buf(req->rq_repmsg, 1,
                                                           sizeof(*mds_body));

                /* see if we got same inode, if not - return error */
                if (id_equal_stc(&cid, &mds_body->id1))
                        goto revalidate_finish;
        }

        GOTO(out, rc = 0);
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
        rc = obd_pin(sbi->ll_md_exp, inode->i_ino, inode->i_generation,
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
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int ll_revalidate_nd(struct dentry *dentry, struct nameidata *nd)
{
        int rc;
        ENTRY;

        if (nd && nd->flags & LOOKUP_LAST && !(nd->flags & LOOKUP_LINK_NOTLAST))
                rc = ll_revalidate_it(dentry, nd->flags, nd, &nd->intent.open);
        else
                rc = ll_revalidate_it(dentry, 0, nd, NULL);

        RETURN(rc);
}
#endif

#if 0
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static void ll_dentry_iput(struct dentry *dentry, struct inode *inode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_id parent, child;

        LASSERT(dentry->d_parent && dentry->d_parent->d_inode);
        ll_inode2id(&parent, dentry->d_parent->d_inode);
        ll_inode2id(&child, inode);
        md_change_cbdata_name(sbi->ll_md_exp, &parent,
                              (char *)dentry->d_name.name, 
                              dentry->d_name.len, &child, 
                              null_if_equal, inode);
        iput(inode);
}
#else
static void ll_dentry_iput(struct dentry *dentry, struct inode *inode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_id parent, child;

        if (dentry->d_parent != dentry) {
                /* Do not do this for root of the tree */
                LASSERT(dentry->d_parent && dentry->d_parent->d_inode);
                ll_inode2id(&parent, dentry->d_parent->d_inode);
                ll_inode2id(&child, inode);
                md_change_cbdata_name(sbi->ll_md_exp, &parent,
                                      (char *)dentry->d_name.name,
                                      dentry->d_name.len, &child,
                                      null_if_equal, inode);
        }
        iput(inode);

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
#if 0
        .d_iput = ll_dentry_iput,
#endif
        .d_delete = ll_ddelete,
        .d_compare = ll_dcompare,
#if 0
        .d_pin = ll_pin,
        .d_unpin = ll_unpin,
#endif
};
