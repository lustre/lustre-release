/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
 *
 *  derived in small part from linux/fs/ext2/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *  Directory entry file type support and forward compatibility hooks
 *      for B-tree directories by Theodore Ts'o (tytso@mit.edu), 1998
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_version.h>
#include "llite_internal.h"

/* methods */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int ll_test_inode(struct inode *inode, unsigned long ino, void *opaque)
#else
static int ll_test_inode(struct inode *inode, void *opaque)
#endif
{
        static int last_ino, last_gen, last_count;
        struct lustre_md *md = opaque;

        if (!(md->body->valid & (OBD_MD_FLGENER | OBD_MD_FLID))) {
                CERROR("MDS body missing inum or generation\n");
                return 0;
        }

        if (last_ino == id_ino(&md->body->id1) &&
            last_gen == id_gen(&md->body->id1) &&
            last_count < 500) {
                last_count++;
        } else {
                if (last_count > 1)
                        CDEBUG(D_VFSTRACE, "compared %u/%u %u times\n",
                               last_ino, last_gen, last_count);
                last_count = 0;
                last_ino = id_ino(&md->body->id1);
                last_gen = id_gen(&md->body->id1);
                CDEBUG(D_VFSTRACE,
                       "comparing inode %p ino "DLID4" to body "DLID4"\n",
                       inode, OLID4(&ll_i2info(inode)->lli_id),
                       OLID4(&md->body->id1));
        }

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        if (inode->i_ino != id_ino(&md->body->id1))
                return 0;
#endif
        if (inode->i_generation != id_gen(&md->body->id1))
                return 0;

        if (id_group(&ll_i2info(inode)->lli_id) != id_group(&md->body->id1))
                return 0;
        
        /* apply the attributes in 'opaque' to this inode. */
        ll_update_inode(inode, md);
        return 1;
}

extern struct dentry_operations ll_d_ops;

int ll_unlock(__u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

/*
 * get an inode by inode number (already instantiated by the intent lookup).
 * Returns inode or NULL.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
int ll_set_inode(struct inode *inode, void *opaque)
{
        ll_read_inode2(inode, opaque);
        return 0;
}

struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *md)
{
        struct inode *inode;

        LASSERT(hash != 0);
        inode = iget5_locked(sb, hash, ll_test_inode, ll_set_inode, md);

        if (inode) {
                if (inode->i_state & I_NEW)
                        unlock_new_inode(inode);
                CDEBUG(D_VFSTRACE, "inode: %lu/%u(%p)\n", inode->i_ino,
                       inode->i_generation, inode);
        }

        return inode;
}
#else
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *md)
{
        struct inode *inode;
        LASSERT(hash != 0);
        inode = iget4(sb, hash, ll_test_inode, md);
        if (inode)
                CDEBUG(D_VFSTRACE, "inode: %lu/%u(%p)\n", inode->i_ino,
                       inode->i_generation, inode);
        return inode;
}
#endif

int ll_mdc_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
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
                struct ll_inode_info *li = ll_i2info(inode);
                __u64 bits = lock->l_policy_data.l_inodebits.bits;

                /* For lookup locks: Invalidate all dentries associated with
                   this inode, for UPDATE locks - invalidate directory pages */
                if (inode == NULL)
                        break;

                if (bits & MDS_INODELOCK_UPDATE)
                        clear_bit(LLI_F_HAVE_MDS_SIZE_LOCK,
                                  &(ll_i2info(inode)->lli_flags));


                if (lock->l_resource->lr_name.name[0] != id_fid(&li->lli_id) ||
                    lock->l_resource->lr_name.name[1] != id_group(&li->lli_id)) {
                        LDLM_ERROR(lock, "data mismatch with object %lu/%lu",
                                   (unsigned long)id_fid(&li->lli_id),
                                   (unsigned long)id_group(&li->lli_id));
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
                        ll_md_real_close(ll_i2mdexp(inode), inode, flags);
                }

                if (bits & MDS_INODELOCK_UPDATE)
                        clear_bit(LLI_F_HAVE_MDS_SIZE_LOCK,
                                  &(ll_i2info(inode)->lli_flags));


                /* If lookup lock is cancelled, we just drop the dentry and
                   this will cause us to reget data from MDS when we'd want to
                   access this dentry/inode again. If this is lock on
                   other parts of inode that is cancelled, we do not need to do
                   much (but need to discard data from readdir, if any), since
                   abscence of lock will cause ll_revalidate_it (called from
                   stat() and similar functions) to renew the data anyway */
                if (S_ISDIR(inode->i_mode) &&
                    (bits & MDS_INODELOCK_UPDATE)) {
                        CDEBUG(D_INODE, "invalidating inode %lu/%u(%p)\n",
                               inode->i_ino, inode->i_generation, inode);
                        truncate_inode_pages(inode->i_mapping, 0);
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

int ll_mdc_cancel_unused(struct lustre_handle *conn, struct inode *inode,
                         int flags, void *opaque)
{
        struct ll_inode_info *li = ll_i2info(inode);
        struct ldlm_res_id res_id =
                { .name = {id_fid(&li->lli_id), id_group(&li->lli_id)} };
        struct obd_device *obddev = class_conn2obd(conn);
        ENTRY;
        
        RETURN(ldlm_cli_cancel_unused(obddev->obd_namespace, &res_id, flags,
                                      opaque));
}

/* Search "inode"'s alias list for a dentry that has the same name and parent as
 * de.  If found, return it.  If not found, return de. */
struct dentry *ll_find_alias(struct inode *inode, struct dentry *de)
{
        struct list_head *tmp;

        spin_lock(&dcache_lock);
        list_for_each(tmp, &inode->i_dentry) {
                struct dentry *dentry = list_entry(tmp, struct dentry, d_alias);

                /* We are called here with 'de' already on the aliases list. */
                if (dentry == de) {
                        CERROR("whoops\n");
                        continue;
                }

                if (dentry->d_parent != de->d_parent)
                        continue;

                if (dentry->d_name.len != de->d_name.len)
                        continue;

                if (memcmp(dentry->d_name.name, de->d_name.name,
                           de->d_name.len) != 0)
                        continue;

                if (!list_empty(&dentry->d_lru))
                        list_del_init(&dentry->d_lru);

                hlist_del_init(&dentry->d_hash);
                __d_rehash(dentry); /* avoid taking dcache_lock inside */
                spin_unlock(&dcache_lock);
                atomic_inc(&dentry->d_count);
                iput(inode);
                dentry->d_flags &= ~DCACHE_LUSTRE_INVALID;
                CDEBUG(D_DENTRY, "alias dentry %*s (%p) parent %p inode %p "
                       "refc %d\n", de->d_name.len, de->d_name.name, de,
                       de->d_parent, de->d_inode, atomic_read(&de->d_count));
                return dentry;
        }

        spin_unlock(&dcache_lock);

        return de;
}

static int lookup_it_finish(struct ptlrpc_request *request, int offset,
                            struct lookup_intent *it, void *data)
{
        struct it_cb_data *icbd = data;
        struct dentry **de = icbd->icbd_childp;
        struct inode *parent = icbd->icbd_parent;
        struct ll_sb_info *sbi = ll_i2sbi(parent);
        struct dentry *dentry = *de, *saved = *de;
        struct inode *inode = NULL;
        int rc;

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return */
        if (!it_disposition(it, DISP_LOOKUP_NEG)) {
                ENTRY;

                rc = ll_prep_inode(sbi->ll_dt_exp, sbi->ll_md_exp,
                                   &inode, request, offset, dentry->d_sb);
                if (rc)
                        RETURN(rc);

                CDEBUG(D_DLMTRACE, "setting l_data to inode %p (%lu/%u)\n",
                       inode, inode->i_ino, inode->i_generation);
                
                mdc_set_lock_data(NULL, &LUSTRE_IT(it)->it_lock_handle, inode);
                
                /* If this is a stat, get the authoritative file size */
                if (it->it_op == IT_GETATTR && S_ISREG(inode->i_mode) &&
                    ll_i2info(inode)->lli_smd != NULL) {
                        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                        ldlm_error_t rc;

                        LASSERT(lsm->lsm_object_id != 0);

                        /* bug 2334: drop MDS lock before acquiring OST lock */
                        ll_intent_drop_lock(it);

                        rc = ll_glimpse_size(inode);
                        if (rc) {
                                iput(inode);
                                RETURN(rc);
                        }
                }

                dentry = *de = ll_find_alias(inode, dentry);
        } else {
                ENTRY;
        }

        dentry->d_op = &ll_d_ops;
        ll_set_dd(dentry);

        if (dentry == saved)
                d_add(dentry, inode);

        RETURN(0);
}

static struct dentry *ll_lookup_it(struct inode *parent, struct dentry *dentry,
                                   struct nameidata *nd, int flags)
{
        struct dentry *save = dentry, *retval;
        struct lookup_intent *it = flags ? &nd->intent.open : NULL;
        struct lustre_id pid;
        struct it_cb_data icbd;
        struct ptlrpc_request *req = NULL;
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        int rc, orig_it;
        ENTRY;

        if (dentry->d_name.len > EXT3_NAME_LEN)
                RETURN(ERR_PTR(-ENAMETOOLONG));

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.len, dentry->d_name.name, parent->i_ino,
               parent->i_generation, parent, LL_IT2STR(it));

        if (d_mountpoint(dentry))
                CERROR("Tell Peter, lookup on mtpt, it %s\n", LL_IT2STR(it));

        if (nd != NULL)
                nd->mnt->mnt_last_used = jiffies;

        orig_it = it ? it->it_op : IT_OPEN;
        ll_frob_intent(&it, &lookup_it);

        icbd.icbd_childp = &dentry;
        icbd.icbd_parent = parent;
        ll_inode2id(&pid, parent);

        rc = md_intent_lock(ll_i2mdexp(parent), &pid,
                            dentry->d_name.name, dentry->d_name.len, NULL, 0,
                            NULL, it, flags, &req, ll_mdc_blocking_ast);
        if (rc < 0)
                GOTO(out, retval = ERR_PTR(rc));

        rc = lookup_it_finish(req, 1, it, &icbd);
        if (rc != 0) {
                ll_intent_release(it);
                GOTO(out, retval = ERR_PTR(rc));
        }

        ll_lookup_finish_locks(it, dentry);

        if (nd &&
            dentry->d_inode != NULL && dentry->d_inode->i_mode & S_ISUID &&
            S_ISDIR(dentry->d_inode->i_mode) &&
            ((flags & LOOKUP_CONTINUE) || (orig_it & (IT_CHDIR | IT_OPEN))))
        {
                rc = ll_gns_mount_object(dentry, nd->mnt);
                if (rc == -ERESTARTSYS) {
                        /* 
                         * making system to restart syscall as currently GNS is
                         * in mounting progress.
                         */
                        GOTO(out, retval = ERR_PTR(rc));
                }
        }
        
        if (dentry == save)
                GOTO(out, retval = NULL);
        else
                GOTO(out, retval = dentry);
 out:
        if (req)
                ptlrpc_req_finished(req);
        if (it == &lookup_it)
                ll_intent_release(it);
        if (dentry->d_inode)
                CDEBUG(D_INODE, "lookup 0x%p in %lu/%lu: %*s -> %lu/%lu\n",
                       dentry,
                       (unsigned long) parent->i_ino,
                       (unsigned long) parent->i_generation,
                       dentry->d_name.len, dentry->d_name.name,
                       (unsigned long) dentry->d_inode->i_ino,
                       (unsigned long) dentry->d_inode->i_generation);
        else
                CDEBUG(D_INODE, "lookup 0x%p in %lu/%lu: %*s -> ??\n",
                       dentry,
                       (unsigned long) parent->i_ino,
                       (unsigned long) parent->i_generation,
                       dentry->d_name.len, dentry->d_name.name);
        return retval;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static struct dentry *ll_lookup_nd(struct inode *parent, struct dentry *dentry,
                                   struct nameidata *nd)
{
        struct dentry *de;
        ENTRY;

        if (nd && nd->flags & LOOKUP_LAST && !(nd->flags & LOOKUP_LINK_NOTLAST))
                de = ll_lookup_it(parent, dentry, nd, nd->flags);
        else
                de = ll_lookup_it(parent, dentry, nd, 0);

        RETURN(de);
}
#endif

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


        LASSERT(it && LUSTRE_IT(it)->it_disposition);
  
        request = LUSTRE_IT(it)->it_data;
        rc = ll_prep_inode(sbi->ll_dt_exp, sbi->ll_md_exp,
                           &inode, request, 1, dir->i_sb);
        if (rc)
                GOTO(out, inode = ERR_PTR(rc));

        LASSERT(list_empty(&inode->i_dentry));

        /* We asked for a lock on the directory, but were granted a
         * lock on the inode.  Since we finally have an inode pointer,
         * stuff it in the lock. */
        CDEBUG(D_DLMTRACE, "setting l_ast_data to inode %p (%lu/%u)\n",
               inode, inode->i_ino, inode->i_generation);
        mdc_set_lock_data(NULL, &LUSTRE_IT(it)->it_lock_handle, inode);
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
        struct ptlrpc_request *request = LUSTRE_IT(it)->it_data;
        struct obd_export *md_exp = ll_i2mdexp(dir); 
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.len, dentry->d_name.name, dir->i_ino,
               dir->i_generation, dir, LL_IT2STR(it));

        rc = it_open_error(DISP_OPEN_CREATE, it);
        if (rc)
                RETURN(rc);

        mdc_store_inode_generation(md_exp, request, MDS_REQ_INTENT_REC_OFF, 1);
        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, 0, it);
        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

        d_instantiate(dentry, inode);
        RETURN(0);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int ll_create_nd(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd)
{
        return ll_create_it(dir, dentry, mode, &nd->intent.open);
}
#endif

static void ll_update_times(struct ptlrpc_request *request, int offset,
                            struct inode *inode)
{
        struct mds_body *body = lustre_msg_buf(request->rq_repmsg, offset,
                                               sizeof(*body));
        LASSERT(body);

        if (body->valid & OBD_MD_FLMTIME &&
            body->mtime > LTIME_S(inode->i_mtime)) {
                CDEBUG(D_INODE, "setting ino %lu mtime from %lu to %u\n",
                       inode->i_ino, LTIME_S(inode->i_mtime), body->mtime);
                LTIME_S(inode->i_mtime) = body->mtime;
        }
        if (body->valid & OBD_MD_FLCTIME &&
            body->ctime > LTIME_S(inode->i_ctime))
                LTIME_S(inode->i_ctime) = body->ctime;
}

static int ll_mknod_raw(struct nameidata *nd, int mode, dev_t rdev)
{
        struct ptlrpc_request *request = NULL;
        struct inode *dir = nd->dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data *op_data;
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p)\n",
               nd->last.len, nd->last.name, dir->i_ino, dir->i_generation, dir);

        mode &= ~current->fs->umask;

        switch (mode & S_IFMT) {
        case 0:
        case S_IFREG:
                mode |= S_IFREG; /* for mode = 0 case, fallthrough */
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                OBD_ALLOC(op_data, sizeof(*op_data));
                if (op_data == NULL)
                        RETURN(-ENOMEM);
                ll_prepare_mdc_data(op_data, dir, NULL, nd->last.name, 
				    nd->last.len, 0);
                err = md_create(sbi->ll_md_exp, op_data, NULL, 0, mode,
                                current->fsuid, current->fsgid, rdev,
                                &request);
                OBD_FREE(op_data, sizeof(*op_data));
                if (err == 0)
                        ll_update_times(request, 0, dir);
                ptlrpc_req_finished(request);
                break;
        case S_IFDIR:
                err = -EPERM;
                break;
        default:
                err = -EINVAL;
        }
        RETURN(err);
}

static int ll_mknod(struct inode *dir, struct dentry *dchild,
                    int mode, ll_dev_t rdev)
{
        struct ptlrpc_request *request = NULL;
        struct inode *inode = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data *op_data;
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p)\n",
               dchild->d_name.len, dchild->d_name.name,
               dir->i_ino, dir->i_generation, dir);

        mode &= ~current->fs->umask;

        switch (mode & S_IFMT) {
        case 0:
        case S_IFREG:
                mode |= S_IFREG; /* for mode = 0 case, fallthrough */
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                OBD_ALLOC(op_data, sizeof(*op_data));
                if (op_data == NULL)
                        RETURN(-ENOMEM);
                ll_prepare_mdc_data(op_data, dir, NULL, dchild->d_name.name, 
				    dchild->d_name.len, 0);
                err = md_create(sbi->ll_md_exp, op_data, NULL, 0, mode,
                                current->fsuid, current->fsgid, rdev,
                                &request);
                OBD_FREE(op_data, sizeof(*op_data));
                if (err)
                        GOTO(out_err, err);

                ll_update_times(request, 0, dir);
                err = ll_prep_inode(sbi->ll_dt_exp, sbi->ll_md_exp,
                                    &inode, request, 0, dchild->d_sb);
                if (err)
                        GOTO(out_err, err);
                break;
        case S_IFDIR:
                RETURN(-EPERM);
                break;
        default:
                RETURN(-EINVAL);
        }

        d_instantiate(dchild, inode);
        EXIT;
 out_err:
        ptlrpc_req_finished(request);
        return err;
}

static int ll_symlink_raw(struct nameidata *nd, const char *tgt)
{
        struct inode *dir = nd->dentry->d_inode;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        const char *name = nd->last.name;
        struct mdc_op_data *op_data;
        int len = nd->last.len;
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%*s,dir=%lu/%u(%p),target=%s\n",
               nd->last.len, nd->last.name, dir->i_ino, dir->i_generation,
               dir, tgt);

        if (dir->i_nlink >= EXT3_LINK_MAX)
                RETURN(err);

        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        ll_prepare_mdc_data(op_data, dir, NULL, name, len, 0);
        LASSERT(tgt);
        err = md_create(sbi->ll_md_exp, op_data,
                        tgt, strlen(tgt) + 1, S_IFLNK | S_IRWXUGO,
                        current->fsuid, current->fsgid, 0, &request);
        OBD_FREE(op_data, sizeof(*op_data));
        if (err == 0)
                ll_update_times(request, 0, dir);
        
        ptlrpc_req_finished(request);
        RETURN(err);
}

static int ll_link_raw(struct nameidata *srcnd, struct nameidata *tgtnd)
{
        struct inode *src = srcnd->dentry->d_inode;
        struct inode *dir = tgtnd->dentry->d_inode;
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data *op_data;
        int err;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        ENTRY;

        CDEBUG(D_VFSTRACE,
               "VFS Op: inode=%lu/%u(%p), dir=%lu/%u(%p), target=%.*s\n",
               src->i_ino, src->i_generation, src, dir->i_ino,
               dir->i_generation, dir, tgtnd->last.len, tgtnd->last.name);

        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        ll_prepare_mdc_data(op_data, src, dir, tgtnd->last.name, 
                            tgtnd->last.len, 0);
        err = md_link(sbi->ll_md_exp, op_data, &request);
        OBD_FREE(op_data, sizeof(*op_data));
        if (err == 0)
                ll_update_times(request, 0, dir);
        ptlrpc_req_finished(request);
        RETURN(err);
}


static int ll_mkdir_raw(struct nameidata *nd, int mode)
{
        struct inode *dir = nd->dentry->d_inode;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data *op_data;
        int err = -EMLINK;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p)\n",
               nd->last.len, nd->last.name, dir->i_ino, dir->i_generation, dir);

        mode = (mode & (S_IRWXUGO|S_ISVTX) & ~current->fs->umask) | S_IFDIR;
        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        ll_prepare_mdc_data(op_data, dir, NULL, nd->last.name, 
                            nd->last.len, 0);
        err = md_create(sbi->ll_md_exp, op_data, NULL, 0, mode,
                        current->fsuid, current->fsgid, 0, &request);
        OBD_FREE(op_data, sizeof(*op_data));
        if (err == 0)
                ll_update_times(request, 0, dir);
        ptlrpc_req_finished(request);
        RETURN(err);
}

static int ll_rmdir_raw(struct nameidata *nd)
{
        struct inode *dir = nd->dentry->d_inode;
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data *op_data;
        int rc;

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p)\n",
               nd->last.len, nd->last.name, dir->i_ino, dir->i_generation, dir);

        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        ll_prepare_mdc_data(op_data, dir, NULL, nd->last.name, 
                            nd->last.len, S_IFDIR);
        rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
        OBD_FREE(op_data, sizeof(*op_data));
        if (rc == 0)
                ll_update_times(request, 0, dir);
        ptlrpc_req_finished(request);
        RETURN(rc);
}

int ll_objects_destroy(struct ptlrpc_request *request,
                       struct inode *dir, int offset)
{
        struct mds_body *body;
        struct lov_mds_md *eadata;
        struct lov_stripe_md *lsm = NULL;
        struct obd_trans_info oti = { 0 };
        struct obdo *oa;
        int rc;
        ENTRY;

        /* req is swabbed so this is safe */
        body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*body));

        if (!(body->valid & OBD_MD_FLEASIZE))
                RETURN(0);

        if (body->eadatasize == 0) {
                CERROR("OBD_MD_FLEASIZE set but eadatasize zero\n");
                GOTO(out, rc = -EPROTO);
        }

        /*
         * the MDS sent back the EA because we unlinked the last reference to
         * this file. Use this EA to unlink the objects on the OST. It's opaque
         * so we don't swab here; we leave it to obd_unpackmd() to check it is
         * complete and sensible.
         */
        eadata = lustre_swab_repbuf(request, 1, body->eadatasize, NULL);
        LASSERT(eadata != NULL);
        if (eadata == NULL) {
                CERROR("Can't unpack MDS EA data\n");
                GOTO(out, rc = -EPROTO);
        }

        rc = obd_unpackmd(ll_i2dtexp(dir), &lsm, eadata, body->eadatasize);
        if (rc < 0) {
                CERROR("obd_unpackmd: %d\n", rc);
                GOTO(out, rc);
        }
        LASSERT(rc >= sizeof(*lsm));

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out_free_memmd, rc = -ENOMEM);

        oa->o_id = lsm->lsm_object_id;
        oa->o_gr = lsm->lsm_object_gr;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLGROUP;

        if (body->valid & OBD_MD_FLCOOKIE) {
                int length = sizeof(struct llog_cookie) *
                                lsm->lsm_stripe_count;
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies =
                        lustre_msg_buf(request->rq_repmsg, 2, length);
                if (oti.oti_logcookies == NULL) {
                        oa->o_valid &= ~OBD_MD_FLCOOKIE;
                        body->valid &= ~OBD_MD_FLCOOKIE;
                } else {
                        /* copy llog cookies to request to replay unlink
                         * so that the same llog file and records as those created
                         * during fail can be re-created while doing replay 
                         */
                        if (offset >= 0)
                                memcpy(lustre_msg_buf(request->rq_reqmsg, offset, 0),
                                       oti.oti_logcookies, length);
                }
        }

        rc = obd_destroy(ll_i2dtexp(dir), oa, lsm, &oti);
        obdo_free(oa);
        if (rc)
                CERROR("obd destroy objid "LPX64" error %d\n",
                       lsm->lsm_object_id, rc);
        EXIT;
 out_free_memmd:
        obd_free_memmd(ll_i2dtexp(dir), &lsm);
 out:
        return rc;
}

static int ll_unlink_raw(struct nameidata *nd)
{
        struct inode *dir = nd->dentry->d_inode;
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data *op_data;
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%lu/%u(%p)\n",
               nd->last.len, nd->last.name, dir->i_ino, dir->i_generation, dir);

        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        ll_prepare_mdc_data(op_data, dir, NULL, nd->last.name, nd->last.len, 0);
        rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
        OBD_FREE(op_data, sizeof(*op_data));
        if (rc)
                GOTO(out, rc);
        ll_update_times(request, 0, dir);
        
        rc = ll_objects_destroy(request, dir, 2);
        EXIT;
out:
        ptlrpc_req_finished(request);
        return rc;
}

static int ll_rename_raw(struct nameidata *srcnd, struct nameidata *tgtnd)
{
        struct inode *src = srcnd->dentry->d_inode;
        struct inode *tgt = tgtnd->dentry->d_inode;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(src);
        struct mdc_op_data *op_data;
        int err;
        ENTRY;
        
        CDEBUG(D_VFSTRACE,"VFS Op:oldname=%.*s,src_dir=%lu/%u(%p),newname=%.*s,"
               "tgt_dir=%lu/%u(%p)\n", srcnd->last.len, srcnd->last.name,
               src->i_ino, src->i_generation, src, tgtnd->last.len,
               tgtnd->last.name, tgt->i_ino, tgt->i_generation, tgt);

        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        ll_prepare_mdc_data(op_data, src, tgt, NULL, 0, 0);
        err = md_rename(sbi->ll_md_exp, op_data, srcnd->last.name, 
                        srcnd->last.len, tgtnd->last.name, tgtnd->last.len, 
                        &request);
        OBD_FREE(op_data, sizeof(*op_data));
        if (!err) {
                ll_update_times(request, 0, src);
                ll_update_times(request, 0, tgt);
                err = ll_objects_destroy(request, src, 3);
        }

        ptlrpc_req_finished(request);
        RETURN(err);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
#define LLITE_IT_RAWOPS (IT_MKNOD|IT_MKDIR|IT_SYMLINK|IT_LINK|IT_UNLINK|IT_RMDIR|IT_RENAME)
static int ll_rawop_from_intent(struct nameidata *nd)
{
        int error = 0;

        if (!nd || !(nd->intent.open.op & LLITE_IT_RAWOPS))
                return 0;

        switch (nd->intent.open.op) {
        case IT_MKNOD:
                error = ll_mknod_raw(nd, nd->intent.open.create_mode,
                                     nd->intent.open.create.dev);
                break;
        case IT_MKDIR:
                error = ll_mkdir_raw(nd, nd->intent.open.create_mode);
                break;
        case IT_RMDIR:
                error = ll_rmdir_raw(nd);
                break;
        case IT_UNLINK:
                error = ll_unlink_raw(nd);
                break;
        case IT_SYMLINK:
                LASSERT(nd->intent.open.create.link);
                error = ll_symlink_raw(nd, nd->intent.open.create.link);
                break;
        case IT_LINK:
                error = ll_link_raw(nd->intent.open.create.source_nd, nd);
                break;
        case IT_RENAME:
                LASSERT(nd->intent.open.create.source_nd);
                error = ll_rename_raw(nd->intent.open.create.source_nd, nd);
                break;
        default:
                LBUG();
        }
        if (error != -EOPNOTSUPP)
                nd->intent.open.flags |= IT_STATUS_RAW;

        return error;
}
#endif

struct inode_operations ll_dir_inode_operations = {
        .mknod              = ll_mknod,
        .setattr            = ll_setattr,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        .create_it          = ll_create_it,
        .lookup_it          = ll_lookup_it,
        .revalidate_it      = ll_inode_revalidate_it,
#else
        .lookup             = ll_lookup_nd,
        .create             = ll_create_nd,
        .getattr            = ll_getattr,
        .endparentlookup    = ll_rawop_from_intent,
#endif
        .setxattr           = ll_setxattr,
        .getxattr           = ll_getxattr,
        .listxattr          = ll_listxattr,
        .removexattr        = ll_removexattr,
        .permission         = ll_inode_permission,
};
