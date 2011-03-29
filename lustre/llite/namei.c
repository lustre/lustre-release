/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_fid.h>
#include <lustre_lite.h>
#include <lustre_dlm.h>
#include <lustre_ver.h>
#include <lustre_mdc.h>
#include "llite_internal.h"

/*
 * Check if we have something mounted at the named dchild.
 * In such a case there would always be dentry present.
 */
static int ll_d_mountpoint(struct dentry *dparent, struct dentry *dchild,
                           struct qstr *name)
{
        int mounted = 0;

        if (unlikely(dchild)) {
                mounted = d_mountpoint(dchild);
        } else if (dparent) {
                dchild = d_lookup(dparent, name);
                if (dchild) {
                        mounted = d_mountpoint(dchild);
                        dput(dchild);
                }
        }
        return mounted;
}

int ll_unlock(__u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}


/* called from iget5_locked->find_inode() under inode_lock spinlock */
static int ll_test_inode(struct inode *inode, void *opaque)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lustre_md     *md = opaque;

        if (unlikely(!(md->body->valid & OBD_MD_FLID))) {
                CERROR("MDS body missing FID\n");
                return 0;
        }

        if (!lu_fid_eq(&lli->lli_fid, &md->body->fid1))
                return 0;

        return 1;
}

static int ll_set_inode(struct inode *inode, void *opaque)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct mdt_body *body = ((struct lustre_md *)opaque)->body;

        if (unlikely(!(body->valid & OBD_MD_FLID))) {
                CERROR("MDS body missing FID\n");
                return -EINVAL;
        }

        lli->lli_fid = body->fid1;
        return 0;
}


/*
 * Get an inode by inode number (already instantiated by the intent lookup).
 * Returns inode or NULL
 */
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *md)
{
        struct inode         *inode;
        ENTRY;

        LASSERT(hash != 0);
        inode = iget5_locked(sb, hash, ll_test_inode, ll_set_inode, md);

        if (inode) {
                if (inode->i_state & I_NEW) {
                        int rc;

                        ll_read_inode2(inode, md);
                        rc = cl_inode_init(inode, md);
                        if (rc != 0) {
                                md->lsm = NULL;
                                make_bad_inode(inode);
                                unlock_new_inode(inode);
                                iput(inode);
                                inode = ERR_PTR(rc);
                        } else
                                unlock_new_inode(inode);
                } else if (!(inode->i_state & (I_FREEING | I_CLEAR)))
                                ll_update_inode(inode, md);
                CDEBUG(D_VFSTRACE, "got inode: %p for "DFID"\n",
                       inode, PFID(&md->body->fid1));
        }
        RETURN(inode);
}

static void ll_drop_negative_dentry(struct inode *dir)
{
        struct dentry *dentry, *tmp_alias, *tmp_subdir;

        cfs_spin_lock(&ll_lookup_lock);
        spin_lock(&dcache_lock);
restart:
        list_for_each_entry_safe(dentry, tmp_alias,
                                 &dir->i_dentry,d_alias) {
                if (!list_empty(&dentry->d_subdirs)) {
                        struct dentry *child;
                        list_for_each_entry_safe(child, tmp_subdir,
                                                 &dentry->d_subdirs,
                                                 d_child) {
                                /* XXX Print some debug here? */
                                if (!child->d_inode)
                                /* Negative dentry. If we were
                                   dropping dcache lock, go
                                   throught the list again */
                                        if (ll_drop_dentry(child))
                                                goto restart;
                        }
                }
        }
        spin_unlock(&dcache_lock);
        cfs_spin_unlock(&ll_lookup_lock);
}


int ll_md_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                       void *data, int flag)
{
        int rc;
        struct lustre_handle lockh;
        ENTRY;

        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0) {
                        CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
                        RETURN(rc);
                }
                break;
        case LDLM_CB_CANCELING: {
                struct inode *inode = ll_inode_from_lock(lock);
                struct ll_inode_info *lli;
                __u64 bits = lock->l_policy_data.l_inodebits.bits;
                struct lu_fid *fid;
                ldlm_mode_t mode = lock->l_req_mode;

                /* Invalidate all dentries associated with this inode */
                if (inode == NULL)
                        break;

                LASSERT(lock->l_flags & LDLM_FL_CANCELING);
                /* For OPEN locks we differentiate between lock modes - CR, CW. PR - bug 22891 */
                if ((bits & MDS_INODELOCK_LOOKUP) &&
                    ll_have_md_lock(inode, MDS_INODELOCK_LOOKUP, LCK_MINMODE))
                        bits &= ~MDS_INODELOCK_LOOKUP;
                if ((bits & MDS_INODELOCK_UPDATE) &&
                    ll_have_md_lock(inode, MDS_INODELOCK_UPDATE, LCK_MINMODE))
                        bits &= ~MDS_INODELOCK_UPDATE;
                if ((bits & MDS_INODELOCK_OPEN) &&
                    ll_have_md_lock(inode, MDS_INODELOCK_OPEN, mode))
                        bits &= ~MDS_INODELOCK_OPEN;

                fid = ll_inode2fid(inode);
                if (lock->l_resource->lr_name.name[0] != fid_seq(fid) ||
                    lock->l_resource->lr_name.name[1] != fid_oid(fid) ||
                    lock->l_resource->lr_name.name[2] != fid_ver(fid)) {
                        LDLM_ERROR(lock, "data mismatch with object "
                                   DFID" (%p)", PFID(fid), inode);
                }

                if (bits & MDS_INODELOCK_OPEN) {
                        int flags = 0;
                        switch (lock->l_req_mode) {
                        case LCK_CW:
                                flags = FMODE_WRITE;
                                break;
                        case LCK_PR:
                                flags = FMODE_EXEC;
                                break;
                        case LCK_CR:
                                flags = FMODE_READ;
                                break;
                        default:
                                CERROR("Unexpected lock mode for OPEN lock "
                                       "%d, inode %ld\n", lock->l_req_mode,
                                       inode->i_ino);
                        }
                        ll_md_real_close(inode, flags);
                }

                lli = ll_i2info(inode);
                if (bits & MDS_INODELOCK_UPDATE)
                        lli->lli_flags &= ~LLIF_MDS_SIZE_LOCK;

                if (S_ISDIR(inode->i_mode) &&
                     (bits & MDS_INODELOCK_UPDATE)) {
                        CDEBUG(D_INODE, "invalidating inode %lu\n",
                               inode->i_ino);
                        truncate_inode_pages(inode->i_mapping, 0);
                        ll_drop_negative_dentry(inode);
                }

                if (inode->i_sb->s_root &&
                    inode != inode->i_sb->s_root->d_inode &&
                    (bits & MDS_INODELOCK_LOOKUP))
                        ll_unhash_aliases(inode);
                iput(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

__u32 ll_i2suppgid(struct inode *i)
{
        if (cfs_curproc_is_in_groups(i->i_gid))
                return (__u32)i->i_gid;
        else
                return (__u32)(-1);
}

/* Pack the required supplementary groups into the supplied groups array.
 * If we don't need to use the groups from the target inode(s) then we
 * instead pack one or more groups from the user's supplementary group
 * array in case it might be useful.  Not needed if doing an MDS-side upcall. */
void ll_i2gids(__u32 *suppgids, struct inode *i1, struct inode *i2)
{
#if 0
        int i;
#endif

        LASSERT(i1 != NULL);
        LASSERT(suppgids != NULL);

        suppgids[0] = ll_i2suppgid(i1);

        if (i2)
                suppgids[1] = ll_i2suppgid(i2);
                else
                        suppgids[1] = -1;

#if 0
        for (i = 0; i < current_ngroups; i++) {
                if (suppgids[0] == -1) {
                        if (current_groups[i] != suppgids[1])
                                suppgids[0] = current_groups[i];
                        continue;
                }
                if (suppgids[1] == -1) {
                        if (current_groups[i] != suppgids[0])
                                suppgids[1] = current_groups[i];
                        continue;
                }
                break;
        }
#endif
}

static void ll_d_add(struct dentry *de, struct inode *inode)
{
        CDEBUG(D_DENTRY, "adding inode %p to dentry %p\n", inode, de);
        /* d_instantiate */
        if (!list_empty(&de->d_alias)) {
                spin_unlock(&dcache_lock);
                CERROR("dentry %.*s %p alias next %p, prev %p\n",
                       de->d_name.len, de->d_name.name, de,
                       de->d_alias.next, de->d_alias.prev);
                LBUG();
        }
        if (inode)
                list_add(&de->d_alias, &inode->i_dentry);
        de->d_inode = inode;

        /* d_rehash */
        if (!d_unhashed(de)) {
                spin_unlock(&dcache_lock);
                CERROR("dentry %.*s %p hash next %p\n",
                       de->d_name.len, de->d_name.name, de, de->d_hash.next);
                LBUG();
        }
        d_rehash_cond(de, 0);
}

/* Search "inode"'s alias list for a dentry that has the same name and parent
 * as de.  If found, return it.  If not found, return de.
 * Lustre can't use d_add_unique because don't unhash aliases for directory
 * in ll_revalidate_it.  After revaliadate inode will be have hashed aliases
 * and it triggers BUG_ON in d_instantiate_unique (bug #10954).
 */
static struct dentry *ll_find_alias(struct inode *inode, struct dentry *de)
{
        struct list_head *tmp;
        struct dentry *dentry;
        struct dentry *last_discon = NULL;

        cfs_spin_lock(&ll_lookup_lock);
        spin_lock(&dcache_lock);
        list_for_each(tmp, &inode->i_dentry) {
                dentry = list_entry(tmp, struct dentry, d_alias);

                /* We are called here with 'de' already on the aliases list. */
                if (unlikely(dentry == de)) {
                        CERROR("whoops\n");
                        continue;
                }

                if (dentry->d_flags & DCACHE_DISCONNECTED) {
                        LASSERT(last_discon == NULL);
                        last_discon = dentry;
                        continue;
                }

                if (dentry->d_parent != de->d_parent)
                        continue;

                if (dentry->d_name.hash != de->d_name.hash)
                        continue;

                if (dentry->d_name.len != de->d_name.len)
                        continue;

                if (memcmp(dentry->d_name.name, de->d_name.name,
                           de->d_name.len) != 0)
                        continue;

                dget_locked(dentry);
                lock_dentry(dentry);
                __d_drop(dentry);
                unlock_dentry(dentry);
                ll_dops_init(dentry, 0);
                d_rehash_cond(dentry, 0); /* avoid taking dcache_lock inside */
                spin_unlock(&dcache_lock);
                cfs_spin_unlock(&ll_lookup_lock);
                iput(inode);
                CDEBUG(D_DENTRY, "alias dentry %.*s (%p) parent %p inode %p "
                       "refc %d\n", de->d_name.len, de->d_name.name, de,
                       de->d_parent, de->d_inode, atomic_read(&de->d_count));
                return dentry;
        }

        if (last_discon) {
                CDEBUG(D_DENTRY, "Reuse disconnected dentry %p inode %p "
                        "refc %d\n", last_discon, last_discon->d_inode,
                        atomic_read(&last_discon->d_count));
                dget_locked(last_discon);
                lock_dentry(last_discon);
                last_discon->d_flags |= DCACHE_LUSTRE_INVALID;
                unlock_dentry(last_discon);
                spin_unlock(&dcache_lock);
                cfs_spin_unlock(&ll_lookup_lock);
                ll_dops_init(last_discon, 1);
                d_rehash(de);
                d_move(last_discon, de);
                iput(inode);
                return last_discon;
        }
        lock_dentry(de);
        de->d_flags |= DCACHE_LUSTRE_INVALID;
        unlock_dentry(de);
        ll_d_add(de, inode);

        spin_unlock(&dcache_lock);
        cfs_spin_unlock(&ll_lookup_lock);

        return de;
}

int ll_lookup_it_finish(struct ptlrpc_request *request,
                        struct lookup_intent *it, void *data)
{
        struct it_cb_data *icbd = data;
        struct dentry **de = icbd->icbd_childp;
        struct inode *parent = icbd->icbd_parent;
        struct ll_sb_info *sbi = ll_i2sbi(parent);
        struct inode *inode = NULL;
        int rc;
        ENTRY;

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return */
        if (!it_disposition(it, DISP_LOOKUP_NEG)) {
                struct dentry *save = *de;
                __u32 bits;

                rc = ll_prep_inode(&inode, request, (*de)->d_sb);
                if (rc)
                        RETURN(rc);

                CDEBUG(D_DLMTRACE, "setting l_data to inode %p (%lu/%u)\n",
                       inode, inode->i_ino, inode->i_generation);
                md_set_lock_data(sbi->ll_md_exp,
                                 &it->d.lustre.it_lock_handle, inode, &bits);

                /* We used to query real size from OSTs here, but actually
                   this is not needed. For stat() calls size would be updated
                   from subsequent do_revalidate()->ll_inode_revalidate_it() in
                   2.4 and
                   vfs_getattr_it->ll_getattr()->ll_inode_revalidate_it() in 2.6
                   Everybody else who needs correct file size would call
                   cl_glimpse_size or some equivalent themselves anyway.
                   Also see bug 7198. */
                ll_dops_init(*de, 1);
                *de = ll_find_alias(inode, *de);
                if (*de != save) {
                        struct ll_dentry_data *lld = ll_d2d(*de);

                        /* just make sure the ll_dentry_data is ready */
                        if (unlikely(lld == NULL))
                                ll_dops_init(*de, 1);
                }
                /* we have lookup look - unhide dentry */
                if (bits & MDS_INODELOCK_LOOKUP) {
                        lock_dentry(*de);
                        (*de)->d_flags &= ~DCACHE_LUSTRE_INVALID;
                        unlock_dentry(*de);
                }
        } else {
                ll_dops_init(*de, 1);
                /* Check that parent has UPDATE lock. If there is none, we
                   cannot afford to hash this dentry (done by ll_d_add) as it
                   might get picked up later when UPDATE lock will appear */
                if (ll_have_md_lock(parent, MDS_INODELOCK_UPDATE, LCK_MINMODE)) {
                        spin_lock(&dcache_lock);
                        ll_d_add(*de, NULL);
                        spin_unlock(&dcache_lock);
                } else {
                        /* negative lookup - and don't have update lock to
                         * parent */
                        lock_dentry(*de);
                        (*de)->d_flags |= DCACHE_LUSTRE_INVALID;
                        unlock_dentry(*de);

                        (*de)->d_inode = NULL;
                        /* We do not want to hash the dentry if don`t have a
                         * lock, but if this dentry is later used in d_move,
                         * we'd hit uninitialised list head d_hash, so we just
                         * do this to init d_hash field but leave dentry
                         * unhashed. (bug 10796). */
                        d_rehash(*de);
                        d_drop(*de);
                }
        }

        RETURN(0);
}

static struct dentry *ll_lookup_it(struct inode *parent, struct dentry *dentry,
                                   struct lookup_intent *it, int lookup_flags)
{
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        struct dentry *save = dentry, *retval;
        struct ptlrpc_request *req = NULL;
        struct md_op_data *op_data;
        struct it_cb_data icbd;
        __u32 opc;
        int rc, first = 0;
        ENTRY;

        if (dentry->d_name.len > ll_i2sbi(parent)->ll_namelen)
                RETURN(ERR_PTR(-ENAMETOOLONG));

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.len, dentry->d_name.name, parent->i_ino,
               parent->i_generation, parent, LL_IT2STR(it));

        if (d_mountpoint(dentry))
                CERROR("Tell Peter, lookup on mtpt, it %s\n", LL_IT2STR(it));

        ll_frob_intent(&it, &lookup_it);

        /* As do_lookup is called before follow_mount, root dentry may be left
         * not valid, revalidate it here. */
        if (parent->i_sb->s_root && (parent->i_sb->s_root->d_inode == parent) &&
            (it->it_op & (IT_OPEN | IT_CREAT))) {
                rc = ll_inode_revalidate_it(parent->i_sb->s_root, it,
                                            MDS_INODELOCK_LOOKUP);
                if (rc)
                        RETURN(ERR_PTR(rc));
        }

        if (it->it_op == IT_GETATTR) {
                first = ll_statahead_enter(parent, &dentry, 1);
                if (first >= 0) {
                        ll_statahead_exit(parent, dentry, first);
                        if (first == 1)
                                RETURN(retval = dentry);
                }
        }

        icbd.icbd_childp = &dentry;
        icbd.icbd_parent = parent;

        if (it->it_op & IT_CREAT ||
            (it->it_op & IT_OPEN && it->it_create_mode & O_CREAT))
                opc = LUSTRE_OPC_CREATE;
        else
                opc = LUSTRE_OPC_ANY;

        op_data = ll_prep_md_op_data(NULL, parent, NULL, dentry->d_name.name,
                                     dentry->d_name.len, lookup_flags, opc,
                                     NULL);
        if (IS_ERR(op_data))
                RETURN((void *)op_data);

        it->it_create_mode &= ~cfs_curproc_umask();

        rc = md_intent_lock(ll_i2mdexp(parent), op_data, NULL, 0, it,
                            lookup_flags, &req, ll_md_blocking_ast, 0);
        ll_finish_md_op_data(op_data);
        if (rc < 0)
                GOTO(out, retval = ERR_PTR(rc));

        rc = ll_lookup_it_finish(req, it, &icbd);
        if (rc != 0) {
                ll_intent_release(it);
                GOTO(out, retval = ERR_PTR(rc));
        }

        if (first == -EEXIST)
                ll_statahead_mark(parent, dentry);

        if ((it->it_op & IT_OPEN) && dentry->d_inode &&
            !S_ISREG(dentry->d_inode->i_mode) &&
            !S_ISDIR(dentry->d_inode->i_mode)) {
                ll_release_openhandle(dentry, it);
        }
        ll_lookup_finish_locks(it, dentry);

        if (dentry == save)
                GOTO(out, retval = NULL);
        else
                GOTO(out, retval = dentry);
 out:
        if (req)
                ptlrpc_req_finished(req);
        return retval;
}

struct lookup_intent *ll_convert_intent(struct open_intent *oit,
                                        int lookup_flags)
{
        struct lookup_intent *it;

        OBD_ALLOC(it, sizeof(*it));
        if (!it)
                return ERR_PTR(-ENOMEM);

        if (lookup_flags & LOOKUP_OPEN) {
                it->it_op = IT_OPEN;
                if (lookup_flags & LOOKUP_CREATE)
                        it->it_op |= IT_CREAT;
                it->it_create_mode = oit->create_mode;
                it->it_flags = oit->flags;
        } else {
                it->it_op = IT_GETATTR;
        }

#ifndef HAVE_FILE_IN_STRUCT_INTENT
                /* Since there is no way to pass our intent to ll_file_open,
                 * just check the file is there. Actual open will be done
                 * in ll_file_open */
                if (it->it_op & IT_OPEN)
                        it->it_op = IT_LOOKUP;
#endif

        return it;
}

static struct dentry *ll_lookup_nd(struct inode *parent, struct dentry *dentry,
                                   struct nameidata *nd)
{
        struct dentry *de;
        ENTRY;

        if (nd && !(nd->flags & (LOOKUP_CONTINUE|LOOKUP_PARENT))) {
                struct lookup_intent *it;

#if defined(HAVE_FILE_IN_STRUCT_INTENT) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
                /* Did we came here from failed revalidate just to propagate
                 * its error? */
                if (nd->flags & LOOKUP_OPEN)
                        if (IS_ERR(nd->intent.open.file))
                                RETURN((struct dentry *)nd->intent.open.file);
#endif
                if (ll_d2d(dentry) && ll_d2d(dentry)->lld_it) {
                        it = ll_d2d(dentry)->lld_it;
                        ll_d2d(dentry)->lld_it = NULL;
                } else {
                        if ((nd->flags & LOOKUP_CREATE ) && !(nd->flags & LOOKUP_OPEN)) {
                                /* We are sure this is new dentry, so we need to create
                                   our private data and set the dentry ops */ 
                                ll_dops_init(dentry, 1);
                                RETURN(NULL);
                        }
                        it = ll_convert_intent(&nd->intent.open, nd->flags);
                        if (IS_ERR(it))
                                RETURN((struct dentry *)it);
                }

                de = ll_lookup_it(parent, dentry, it, nd->flags);
                if (de)
                        dentry = de;
                if ((nd->flags & LOOKUP_OPEN) && !IS_ERR(dentry)) { /* Open */
                        if (dentry->d_inode &&
                            it_disposition(it, DISP_OPEN_OPEN)) { /* nocreate */
#ifdef HAVE_FILE_IN_STRUCT_INTENT
                                if (S_ISFIFO(dentry->d_inode->i_mode)) {
                                        // We cannot call open here as it would
                                        // deadlock.
                                        ptlrpc_req_finished(
                                                       (struct ptlrpc_request *)
                                                          it->d.lustre.it_data);
                                } else {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
/* 2.6.1[456] have a bug in open_namei() that forgets to check
 * nd->intent.open.file for error, so we need to return it as lookup's result
 * instead */
                                        struct file *filp;
                                        nd->intent.open.file->private_data = it;
                                        filp =lookup_instantiate_filp(nd,dentry,
                                                                      NULL);
                                        if (IS_ERR(filp)) {
                                                if (de)
                                                        dput(de);
                                                de = (struct dentry *) filp;
                                        }
#else
                                        nd->intent.open.file->private_data = it;
                                        (void)lookup_instantiate_filp(nd,dentry,
                                                                      NULL);
#endif

                                }
#else /* HAVE_FILE_IN_STRUCT_INTENT */
                                /* Release open handle as we have no way to
                                 * pass it to ll_file_open */
                                ll_release_openhandle(dentry, it);
#endif /* HAVE_FILE_IN_STRUCT_INTENT */
                        } else if (it_disposition(it, DISP_OPEN_CREATE)) {
                                // XXX This can only reliably work on assumption
                                // that there are NO hashed negative dentries.
                                ll_d2d(dentry)->lld_it = it;
                                it = NULL; /* Will be freed in ll_create_nd */
                                /* We absolutely depend on ll_create_nd to be
                                 * called to not leak this intent and possible
                                 * data attached to it */
                        }
                }

                if (it) {
                        ll_intent_release(it);
                        OBD_FREE(it, sizeof(*it));
                }
        } else {
                de = ll_lookup_it(parent, dentry, NULL, 0);
        }

        RETURN(de);
}

/* We depend on "mode" being set with the proper file type/umask by now */
static struct inode *ll_create_node(struct inode *dir, const char *name,
                                    int namelen, const void *data, int datalen,
                                    int mode, __u64 extra,
                                    struct lookup_intent *it)
{
        struct inode *inode = NULL;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int rc;
        ENTRY;

        LASSERT(it && it->d.lustre.it_disposition);

        LASSERT(it_disposition(it, DISP_ENQ_CREATE_REF));
        request = it->d.lustre.it_data;
        it_clear_disposition(it, DISP_ENQ_CREATE_REF);
        rc = ll_prep_inode(&inode, request, dir->i_sb);
        if (rc)
                GOTO(out, inode = ERR_PTR(rc));

        LASSERT(list_empty(&inode->i_dentry));

        /* We asked for a lock on the directory, but were granted a
         * lock on the inode.  Since we finally have an inode pointer,
         * stuff it in the lock. */
        CDEBUG(D_DLMTRACE, "setting l_ast_data to inode %p (%lu/%u)\n",
               inode, inode->i_ino, inode->i_generation);
        md_set_lock_data(sbi->ll_md_exp,
                         &it->d.lustre.it_lock_handle, inode, NULL);
        EXIT;
 out:
        ptlrpc_req_finished(request);
        return inode;
}

/*
 * By the time this is called, we already have created the directory cache
 * entry for the new file, but it is so far negative - it has no inode.
 *
 * We defer creating the OBD object(s) until open, to keep the intent and
 * non-intent code paths similar, and also because we do not have the MDS
 * inode number before calling ll_create_node() (which is needed for LOV),
 * so we would need to do yet another RPC to the MDS to store the LOV EA
 * data on the MDS.  If needed, we would pass the PACKED lmm as data and
 * lmm_size in datalen (the MDS still has code which will handle that).
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int ll_create_it(struct inode *dir, struct dentry *dentry, int mode,
                        struct lookup_intent *it)
{
        struct inode *inode;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.len, dentry->d_name.name, dir->i_ino,
               dir->i_generation, dir, LL_IT2STR(it));

        rc = it_open_error(DISP_OPEN_CREATE, it);
        if (rc)
                RETURN(rc);

        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, 0, it);
        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

        d_instantiate(dentry, inode);
        /* Negative dentry may be unhashed if parent does not have UPDATE lock,
         * but some callers, e.g. do_coredump, expect dentry to be hashed after
         * successful create. Hash it here. */
        spin_lock(&dcache_lock);
        if (d_unhashed(dentry))
                d_rehash_cond(dentry, 0);
        spin_unlock(&dcache_lock);
        RETURN(0);
}

static void ll_update_times(struct ptlrpc_request *request,
                            struct inode *inode)
{
        struct mdt_body *body = req_capsule_server_get(&request->rq_pill,
                                                       &RMF_MDT_BODY);

        LASSERT(body);
        if (body->valid & OBD_MD_FLMTIME &&
            body->mtime > LTIME_S(inode->i_mtime)) {
                CDEBUG(D_INODE, "setting ino %lu mtime from %lu to "LPU64"\n",
                       inode->i_ino, LTIME_S(inode->i_mtime), body->mtime);
                LTIME_S(inode->i_mtime) = body->mtime;
        }
        if (body->valid & OBD_MD_FLCTIME &&
            body->ctime > LTIME_S(inode->i_ctime))
                LTIME_S(inode->i_ctime) = body->ctime;
}

static int ll_new_node(struct inode *dir, struct qstr *name,
                       const char *tgt, int mode, int rdev,
                       struct dentry *dchild, __u32 opc)
{
        struct ptlrpc_request *request = NULL;
        struct md_op_data *op_data;
        struct inode *inode = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int tgt_len = 0;
        int err;

        ENTRY;
        if (unlikely(tgt != NULL))
                tgt_len = strlen(tgt) + 1;

        op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name,
                                     name->len, 0, opc, NULL);
        if (IS_ERR(op_data))
                GOTO(err_exit, err = PTR_ERR(op_data));

        err = md_create(sbi->ll_md_exp, op_data, tgt, tgt_len, mode,
                        cfs_curproc_fsuid(), cfs_curproc_fsgid(),
                        cfs_curproc_cap_pack(), rdev, &request);
        ll_finish_md_op_data(op_data);
        if (err)
                GOTO(err_exit, err);

        ll_update_times(request, dir);

        if (dchild) {
                err = ll_prep_inode(&inode, request, dchild->d_sb);
                if (err)
                     GOTO(err_exit, err);

                d_drop(dchild);
                d_instantiate(dchild, inode);
        }
        EXIT;
err_exit:
        ptlrpc_req_finished(request);

        return err;
}

static int ll_mknod_generic(struct inode *dir, struct qstr *name, int mode,
                            unsigned rdev, struct dentry *dchild)
{
        int err;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p) mode %o dev %x\n",
               name->len, name->name, dir->i_ino, dir->i_generation, dir,
               mode, rdev);

        mode &= ~cfs_curproc_umask();

        switch (mode & S_IFMT) {
        case 0:
                mode |= S_IFREG; /* for mode = 0 case, fallthrough */
        case S_IFREG:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                err = ll_new_node(dir, name, NULL, mode, rdev, dchild,
                                  LUSTRE_OPC_MKNOD);
                break;
        case S_IFDIR:
                err = -EPERM;
                break;
        default:
                err = -EINVAL;
        }
        RETURN(err);
}

static int ll_create_nd(struct inode *dir, struct dentry *dentry,
                        int mode, struct nameidata *nd)
{
        struct lookup_intent *it = ll_d2d(dentry)->lld_it;
        int rc;

        if (!it)
                return ll_mknod_generic(dir, &dentry->d_name, mode, 0, dentry);

        ll_d2d(dentry)->lld_it = NULL;

        /* Was there an error? Propagate it! */
        if (it->d.lustre.it_status) {
                rc = it->d.lustre.it_status;
                goto out;
        }

        rc = ll_create_it(dir, dentry, mode, it);
#ifdef HAVE_FILE_IN_STRUCT_INTENT
        if (nd && (nd->flags & LOOKUP_OPEN) && dentry->d_inode) { /* Open */
                nd->intent.open.file->private_data = it;
                lookup_instantiate_filp(nd, dentry, NULL);
        }
#else
        ll_release_openhandle(dentry,it);
#endif

out:
        ll_intent_release(it);
        OBD_FREE(it, sizeof(*it));

        return rc;
}

static int ll_symlink_generic(struct inode *dir, struct qstr *name,
                              const char *tgt, struct dentry *dchild)
{
        int err;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p),target=%.*s\n",
               name->len, name->name, dir->i_ino, dir->i_generation,
               dir, 3000, tgt);

        err = ll_new_node(dir, name, (char *)tgt, S_IFLNK | S_IRWXUGO,
                          0, dchild, LUSTRE_OPC_SYMLINK);
        RETURN(err);
}

static int ll_link_generic(struct inode *src,  struct inode *dir,
                           struct qstr *name, struct dentry *dchild)
{
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct ptlrpc_request *request = NULL;
        struct md_op_data *op_data;
        int err;

        ENTRY;
        CDEBUG(D_VFSTRACE,
               "VFS Op: inode=%lu/%u(%p), dir=%lu/%u(%p), target=%.*s\n",
               src->i_ino, src->i_generation, src, dir->i_ino,
               dir->i_generation, dir, name->len, name->name);

        op_data = ll_prep_md_op_data(NULL, src, dir, name->name, name->len,
                                     0, LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        err = md_link(sbi->ll_md_exp, op_data, &request);
        ll_finish_md_op_data(op_data);
        if (err)
                GOTO(out, err);
        if (dchild)
                d_drop(dchild);

        ll_update_times(request, dir);
        EXIT;
out:
        ptlrpc_req_finished(request);
        RETURN(err);
}

static int ll_mkdir_generic(struct inode *dir, struct qstr *name,
                            int mode, struct dentry *dchild)

{
        int err;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p)\n",
               name->len, name->name, dir->i_ino, dir->i_generation, dir);

        mode = (mode & (S_IRWXUGO|S_ISVTX) & ~cfs_curproc_umask()) | S_IFDIR;
        err = ll_new_node(dir, name, NULL, mode, 0, dchild, LUSTRE_OPC_MKDIR);

        RETURN(err);
}

/* Try to find the child dentry by its name.
   If found, put the result fid into @fid. */
static void ll_get_child_fid(struct inode * dir, struct qstr *name,
                             struct lu_fid *fid)
{
        struct dentry *parent, *child;

        parent = list_entry(dir->i_dentry.next, struct dentry, d_alias);
        child = d_lookup(parent, name);
        if (child) {
                if (child->d_inode)
                        *fid = *ll_inode2fid(child->d_inode);
                dput(child);
        }
}

static int ll_rmdir_generic(struct inode *dir, struct dentry *dparent,
                            struct dentry *dchild, struct qstr *name)
{
        struct ptlrpc_request *request = NULL;
        struct md_op_data *op_data;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p)\n",
               name->len, name->name, dir->i_ino, dir->i_generation, dir);

        if (unlikely(ll_d_mountpoint(dparent, dchild, name)))
                RETURN(-EBUSY);

        op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name, name->len,
                                     S_IFDIR, LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        ll_get_child_fid(dir, name, &op_data->op_fid3);
        rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
        ll_finish_md_op_data(op_data);
        if (rc == 0)
                ll_update_times(request, dir);
        ptlrpc_req_finished(request);
        RETURN(rc);
}

int ll_objects_destroy(struct ptlrpc_request *request, struct inode *dir)
{
        struct mdt_body *body;
        struct lov_mds_md *eadata;
        struct lov_stripe_md *lsm = NULL;
        struct obd_trans_info oti = { 0 };
        struct obdo *oa;
        struct obd_capa *oc = NULL;
        int rc;
        ENTRY;

        /* req is swabbed so this is safe */
        body = req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY);
        if (!(body->valid & OBD_MD_FLEASIZE))
                RETURN(0);

        if (body->eadatasize == 0) {
                CERROR("OBD_MD_FLEASIZE set but eadatasize zero\n");
                GOTO(out, rc = -EPROTO);
        }

        /* The MDS sent back the EA because we unlinked the last reference
         * to this file. Use this EA to unlink the objects on the OST.
         * It's opaque so we don't swab here; we leave it to obd_unpackmd() to
         * check it is complete and sensible. */
        eadata = req_capsule_server_sized_get(&request->rq_pill, &RMF_MDT_MD,
                                              body->eadatasize);
        LASSERT(eadata != NULL);

        rc = obd_unpackmd(ll_i2dtexp(dir), &lsm, eadata, body->eadatasize);
        if (rc < 0) {
                CERROR("obd_unpackmd: %d\n", rc);
                GOTO(out, rc);
        }
        LASSERT(rc >= sizeof(*lsm));

        OBDO_ALLOC(oa);
        if (oa == NULL)
                GOTO(out_free_memmd, rc = -ENOMEM);

        oa->o_id = lsm->lsm_object_id;
        oa->o_seq = lsm->lsm_object_seq;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLGROUP;

        if (body->valid & OBD_MD_FLCOOKIE) {
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies =
                        req_capsule_server_sized_get(&request->rq_pill,
                                                     &RMF_LOGCOOKIES,
                                                   sizeof(struct llog_cookie) *
                                                     lsm->lsm_stripe_count);
                if (oti.oti_logcookies == NULL) {
                        oa->o_valid &= ~OBD_MD_FLCOOKIE;
                        body->valid &= ~OBD_MD_FLCOOKIE;
                }
        }

        if (body->valid & OBD_MD_FLOSSCAPA) {
                rc = md_unpack_capa(ll_i2mdexp(dir), request, &RMF_CAPA2, &oc);
                if (rc)
                        GOTO(out_free_memmd, rc);
        }

        rc = obd_destroy(ll_i2dtexp(dir), oa, lsm, &oti, ll_i2mdexp(dir), oc);
        capa_put(oc);
        OBDO_FREE(oa);
        if (rc)
                CERROR("obd destroy objid "LPX64" error %d\n",
                       lsm->lsm_object_id, rc);
 out_free_memmd:
        obd_free_memmd(ll_i2dtexp(dir), &lsm);
 out:
        return rc;
}

/* ll_unlink_generic() doesn't update the inode with the new link count.
 * Instead, ll_ddelete() and ll_d_iput() will update it based upon if there
 * is any lock existing. They will recycle dentries and inodes based upon locks
 * too. b=20433 */
static int ll_unlink_generic(struct inode *dir, struct dentry *dparent,
                             struct dentry *dchild, struct qstr *name)
{
        struct ptlrpc_request *request = NULL;
        struct md_op_data *op_data;
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p)\n",
               name->len, name->name, dir->i_ino, dir->i_generation, dir);

        /*
         * XXX: unlink bind mountpoint maybe call to here,
         * just check it as vfs_unlink does.
         */
        if (unlikely(ll_d_mountpoint(dparent, dchild, name)))
                RETURN(-EBUSY);

        op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name,
                                     name->len, 0, LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        ll_get_child_fid(dir, name, &op_data->op_fid3);
        rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
        ll_finish_md_op_data(op_data);
        if (rc)
                GOTO(out, rc);

        ll_update_times(request, dir);

        rc = ll_objects_destroy(request, dir);
 out:
        ptlrpc_req_finished(request);
        RETURN(rc);
}

static int ll_rename_generic(struct inode *src, struct dentry *src_dparent,
                             struct dentry *src_dchild, struct qstr *src_name,
                             struct inode *tgt, struct dentry *tgt_dparent,
                             struct dentry *tgt_dchild, struct qstr *tgt_name)
{
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(src);
        struct md_op_data *op_data;
        int err;
        ENTRY;
        CDEBUG(D_VFSTRACE,"VFS Op:oldname=%.*s,src_dir=%lu/%u(%p),newname=%.*s,"
               "tgt_dir=%lu/%u(%p)\n", src_name->len, src_name->name,
               src->i_ino, src->i_generation, src, tgt_name->len,
               tgt_name->name, tgt->i_ino, tgt->i_generation, tgt);

        if (unlikely(ll_d_mountpoint(src_dparent, src_dchild, src_name) ||
            ll_d_mountpoint(tgt_dparent, tgt_dchild, tgt_name)))
                RETURN(-EBUSY);

        op_data = ll_prep_md_op_data(NULL, src, tgt, NULL, 0, 0,
                                     LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        ll_get_child_fid(src, src_name, &op_data->op_fid3);
        ll_get_child_fid(tgt, tgt_name, &op_data->op_fid4);
        err = md_rename(sbi->ll_md_exp, op_data,
                        src_name->name, src_name->len,
                        tgt_name->name, tgt_name->len, &request);
        ll_finish_md_op_data(op_data);
        if (!err) {
                ll_update_times(request, src);
                ll_update_times(request, tgt);
                err = ll_objects_destroy(request, src);
        }

        ptlrpc_req_finished(request);

        RETURN(err);
}

static int ll_mknod(struct inode *dir, struct dentry *dchild, int mode,
                    ll_dev_t rdev)
{
        return ll_mknod_generic(dir, &dchild->d_name, mode,
                                old_encode_dev(rdev), dchild);
}

static int ll_unlink(struct inode * dir, struct dentry *dentry)
{
        return ll_unlink_generic(dir, NULL, dentry, &dentry->d_name);
}
static int ll_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
        return ll_mkdir_generic(dir, &dentry->d_name, mode, dentry);
}
static int ll_rmdir(struct inode *dir, struct dentry *dentry)
{
        return ll_rmdir_generic(dir, NULL, dentry, &dentry->d_name);
}
static int ll_symlink(struct inode *dir, struct dentry *dentry,
                      const char *oldname)
{
        return ll_symlink_generic(dir, &dentry->d_name, oldname, dentry);
}
static int ll_link(struct dentry *old_dentry, struct inode *dir,
                   struct dentry *new_dentry)
{
        return ll_link_generic(old_dentry->d_inode, dir, &new_dentry->d_name,
                               new_dentry);
}
static int ll_rename(struct inode *old_dir, struct dentry *old_dentry,
                     struct inode *new_dir, struct dentry *new_dentry)
{
        int err;
        err = ll_rename_generic(old_dir, NULL,
                                 old_dentry, &old_dentry->d_name,
                                 new_dir, NULL, new_dentry,
                                 &new_dentry->d_name);
        if (!err) {
#ifndef HAVE_FS_RENAME_DOES_D_MOVE
                if (!S_ISDIR(old_dentry->d_inode->i_mode))
#endif
                        d_move(old_dentry, new_dentry);
        }
        return err;
}

struct inode_operations ll_dir_inode_operations = {
        .mknod              = ll_mknod,
        .lookup             = ll_lookup_nd,
        .create             = ll_create_nd,
        /* We need all these non-raw things for NFSD, to not patch it. */
        .unlink             = ll_unlink,
        .mkdir              = ll_mkdir,
        .rmdir              = ll_rmdir,
        .symlink            = ll_symlink,
        .link               = ll_link,
        .rename             = ll_rename,
        .setattr            = ll_setattr,
        .getattr            = ll_getattr,
        .permission         = ll_inode_permission,
        .setxattr           = ll_setxattr,
        .getxattr           = ll_getxattr,
        .listxattr          = ll_listxattr,
        .removexattr        = ll_removexattr,
};

struct inode_operations ll_special_inode_operations = {
        .setattr        = ll_setattr,
        .getattr        = ll_getattr,
        .permission     = ll_inode_permission,
        .setxattr       = ll_setxattr,
        .getxattr       = ll_getxattr,
        .listxattr      = ll_listxattr,
        .removexattr    = ll_removexattr,
};
