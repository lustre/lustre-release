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

/* from dcache.c */
extern void ll_set_dd(struct dentry *de);

/* from super.c */
extern void ll_change_inode(struct inode *inode);
extern int ll_setattr(struct dentry *de, struct iattr *attr);

/* from dir.c */
extern int ll_add_link (struct dentry *dentry, struct inode *inode);
obd_id ll_inode_by_name(struct inode * dir, struct dentry *dentry, int *typ);
int ext2_make_empty(struct inode *inode, struct inode *parent);
struct ext2_dir_entry_2 * ext2_find_entry (struct inode * dir,
                   struct dentry *dentry, struct page ** res_page);
int ext2_delete_entry (struct ext2_dir_entry_2 * dir, struct page * page );
int ext2_empty_dir (struct inode * inode);
struct ext2_dir_entry_2 * ext2_dotdot (struct inode *dir, struct page **p);
void ext2_set_link(struct inode *dir, struct ext2_dir_entry_2 *de,
                   struct page *page, struct inode *inode);

/*
 * Couple of helper functions - make the code slightly cleaner.
 */
static inline void ext2_inc_count(struct inode *inode)
{
        inode->i_nlink++;
}

/* postpone the disk update until the inode really goes away */
static inline void ext2_dec_count(struct inode *inode)
{
        inode->i_nlink--;
}
static inline int ext2_add_nondir(struct dentry *dentry, struct inode *inode)
{
        int err;
        err = ll_add_link(dentry, inode);
        if (!err) {
                d_instantiate(dentry, inode);
                return 0;
        }
        ext2_dec_count(inode);
        iput(inode);
        return err;
}

/* methods */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int ll_find_inode(struct inode *inode, unsigned long ino, void *opaque)
#else
static int ll_test_inode(struct inode *inode, void *opaque)
#endif
{
        struct ll_read_inode2_cookie *lic = opaque;
        struct mds_body *body = lic->lic_body;

        if (!(lic->lic_body->valid & (OBD_MD_FLGENER | OBD_MD_FLID)))
                CERROR("invalid generation\n");
        CDEBUG(D_VFSTRACE, "comparing inode %p ino %lu/%u to body %lu/%u\n",
               inode, inode->i_ino, inode->i_generation, ino,
               lic->lic_body->generation);

        if (inode->i_generation != lic->lic_body->generation)
                return 0;

        /* Apply the attributes in 'opaque' to this inode */
        ll_update_inode(inode, body, lic->lic_lsm);
        return 1;
}

extern struct dentry_operations ll_d_ops;

int ll_unlock(__u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

/* Get an inode by inode number (already instantiated by the intent lookup).
 * Returns inode or NULL
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
extern int ll_read_inode2(struct inode *inode, void *opaque);
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct ll_read_inode2_cookie *lic)
{
        struct inode *inode;

        LASSERT(hash != 0);
        inode = iget5_locked(sb, hash, ll_test_inode, ll_read_inode2, lic);
        if (inode == NULL)
                return NULL;              /* removed ERR_PTR(-ENOMEM) -eeb */

        if (inode->i_state & I_NEW)
                unlock_new_inode(inode);

        // XXX Coda always fills inodes, should Lustre?
        return inode;
}
#else
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct ll_read_inode2_cookie *lic)
{
        struct inode *inode;
        LASSERT(hash != 0);
        inode = iget4(sb, hash, ll_find_inode, lic);
        CDEBUG(D_VFSTRACE, "inode: %lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);
        return inode;
}
#endif

static int ll_intent_to_lock_mode(struct lookup_intent *it)
{
        /* CREAT needs to be tested before open (both could be set) */
        if (it->it_op & IT_CREAT)
                return LCK_PW;
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_LOOKUP))
                return LCK_PR;

        LBUG();
        RETURN(-EINVAL);
}

int ll_it_open_error(int phase, struct lookup_intent *it)
{
        if (it->it_disposition & IT_OPEN_OPEN) {
                if (phase == IT_OPEN_OPEN)
                        return it->it_status;
                else
                        return 0;
        }

        if (it->it_disposition & IT_OPEN_CREATE) {
                if (phase == IT_OPEN_CREATE)
                        return it->it_status;
                else
                        return 0;
        }

        if (it->it_disposition & IT_OPEN_LOOKUP) {
                if (phase == IT_OPEN_LOOKUP)
                        return it->it_status;
                else
                        return 0;
        }
        LBUG();
        return 0;
}

int ll_mdc_blocking_ast(struct ldlm_lock *lock,
                        struct ldlm_lock_desc *desc,
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
                /* Invalidate all dentries associated with this inode */
                struct inode *inode = lock->l_data;
                LASSERT(inode != NULL);

                if (S_ISDIR(inode->i_mode)) {
                        CDEBUG(D_INODE, "invalidating inode %lu\n",
                               inode->i_ino);

                        ll_invalidate_inode_pages(inode);
                }

#warning FIXME: we should probably free this inode if there are no aliases
                if (inode->i_sb->s_root &&
                    inode != inode->i_sb->s_root->d_inode)
                        d_unhash_aliases(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

void ll_mdc_lock_set_inode(struct lustre_handle *lockh, struct inode *inode)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        ENTRY;

        LASSERT(lock != NULL);
        lock->l_data = inode;
        LDLM_LOCK_PUT(lock);
        EXIT;
}

int ll_mdc_cancel_unused(struct lustre_handle *conn, struct inode *inode,
                         int flags, void *opaque)
{
        struct ldlm_res_id res_id =
                { .name = {inode->i_ino, inode->i_generation} };
        struct obd_device *obddev = class_conn2obd(conn);
        ENTRY;
        RETURN(ldlm_cli_cancel_unused(obddev->obd_namespace, &res_id, flags,
                                      opaque));
}

void ll_prepare_mdc_op_data(struct mdc_op_data *data,
                            struct inode *i1,
                            struct inode *i2,
                            const char *name,
                            int namelen,
                            int mode)
{
        LASSERT(i1);

        data->ino1 = i1->i_ino;
        data->gen1 = i1->i_generation;
        data->typ1 = i1->i_mode & S_IFMT;
        data->gid1 = i1->i_gid;

        if (i2) {
                data->ino2 = i2->i_ino;
                data->gen2 = i2->i_generation;
                data->typ2 = i2->i_mode & S_IFMT;
                data->gid2 = i2->i_gid;
        } else {
                data->ino2 = 0;
        }

        data->name = name;
        data->namelen = namelen;
        data->mode = mode;
}

#define IT_ENQ_COMPLETE (1<<16)

int ll_intent_lock(struct inode *parent, struct dentry **de,
                   struct lookup_intent *it, intent_finish_cb intent_finish)
{
        struct dentry *dentry = *de;
        struct inode *inode = dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(parent);
        struct lustre_handle lockh;
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        struct ptlrpc_request *request = NULL;
        int rc = 0, offset, flag = 0;
        obd_id ino = 0;
        ENTRY;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        if (it && it->it_op == 0)
                *it = lookup_it;
#endif
        if (it == NULL)
                it = &lookup_it;

        CDEBUG(D_DLMTRACE, "name: %*s, intent: %s\n", dentry->d_name.len,
               dentry->d_name.name, ldlm_it2str(it->it_op));

        if (dentry->d_name.len > EXT2_NAME_LEN)
                RETURN(-ENAMETOOLONG);

        if (!(it->it_disposition & IT_ENQ_COMPLETE)) {
                struct mdc_op_data op_data;

                ll_prepare_mdc_op_data(&op_data, parent, dentry->d_inode,
                                       dentry->d_name.name, dentry->d_name.len,
                                       0);

                rc = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_PLAIN, it,
                                 ll_intent_to_lock_mode(it), &op_data,
                                 &lockh, NULL, 0, ldlm_completion_ast,
                                 ll_mdc_blocking_ast, parent);
                if (rc < 0)
                        RETURN(rc);
                memcpy(it->it_lock_handle, &lockh, sizeof(lockh));
        }

        request = (struct ptlrpc_request *)it->it_data;

        /* non-zero it_disposition indicates that the server performed the
         * intent on our behalf. */
        if (it->it_disposition) {
                struct mds_body *mds_body;
                int mode;

                /* This long block is all about fixing up the local
                 * state so that it is correct as of the moment
                 * _before_ the operation was applied; that way, the
                 * VFS will think that everything is normal and call
                 * Lustre's regular FS function.
                 *
                 * If we're performing a creation, that means that unless the
                 * creation failed with EEXIST, we should fake up a negative
                 * dentry.  Likewise for the target of a hard link.
                 *
                 * For everything else, we want to lookup to succeed. */

                /* One additional note: if CREATE/MKDIR/etc succeeded,
                 * we add an extra reference to the request because we
                 * need to keep it around until ll_create gets called.
                 * For anything else which results in
                 * LL_LOOKUP_POSITIVE, we can do the iget()
                 * immediately with the contents of the reply (in the
                 * intent_finish callback).  In the create case,
                 * however, we need to wait until ll_create_node to do
                 * the iget() or the VFS will abort with -EEXISTS.
                 */

                offset = 1;
                mds_body = lustre_msg_buf(request->rq_repmsg, offset,
                                          sizeof(*mds_body));
                LASSERT (mds_body != NULL);           /* mdc_enqueue checked */
                LASSERT_REPSWABBED (request, offset); /* mdc_enqueue swabbed */

                ino = mds_body->fid1.id;
                mode = mds_body->mode;

                /*We were called from revalidate2: did we find the same inode?*/
                if (inode && (ino != inode->i_ino ||
                    mds_body->fid1.generation != inode->i_generation)) {
                        it->it_disposition |= IT_ENQ_COMPLETE;
                        RETURN(-ESTALE);
                }

                /* If we're doing an IT_OPEN which did not result in an actual
                 * successful open, then we need to remove the bit which saves
                 * this request for unconditional replay. */
                if (it->it_op & IT_OPEN &&
                    (!(it->it_disposition & IT_OPEN_OPEN) ||
                     it->it_status != 0)) {
                        unsigned long flags;

                        spin_lock_irqsave (&request->rq_lock, flags);
                        request->rq_replay = 0;
                        spin_unlock_irqrestore (&request->rq_lock, flags);
                }

                if (it->it_op & IT_CREAT) {
                        mdc_store_inode_generation(request, 2, 1);
                        /* The server will return to us, in it_disposition, an
                         * indication of exactly what it_status refers to.
                         *
                         * If IT_OPEN_OPEN is set, then it_status refers to the
                         * open() call, otherwise if IT_OPEN_CREATE is set, then
                         * it status is the creation failure mode.  In either
                         * case, one of IT_OPEN_NEG or IT_OPEN_POS will be set,
                         * indicating whether the child lookup was successful.
                         *
                         * Else, if IT_OPEN_LOOKUP then it_status is the rc
                         * of the child lookup.
                         *
                         * Finally, if none of the bits are set, then the
                         * failure occurred while looking up the parent. */
                        rc = ll_it_open_error(IT_OPEN_LOOKUP, it);
                        if (rc)
                                GOTO(drop_req, rc);

                        if (it->it_disposition & IT_OPEN_CREATE)
                                ptlrpc_request_addref(request);
                        if (it->it_disposition & IT_OPEN_OPEN)
                                ptlrpc_request_addref(request);

                        if (it->it_disposition & IT_OPEN_NEG)
                                flag = LL_LOOKUP_NEGATIVE;
                        else
                                flag = LL_LOOKUP_POSITIVE;
                } else if (it->it_op == IT_OPEN) {
                        LASSERT(!(it->it_disposition & IT_OPEN_CREATE));

                        rc = ll_it_open_error(IT_OPEN_LOOKUP, it);
                        if (rc)
                                GOTO(drop_req, rc);

                        if (it->it_disposition & IT_OPEN_OPEN)
                                ptlrpc_request_addref(request);

                        if (it->it_disposition & IT_OPEN_NEG)
                                flag = LL_LOOKUP_NEGATIVE;
                        else
                                flag = LL_LOOKUP_POSITIVE;
                } else if (it->it_op & (IT_GETATTR | IT_LOOKUP)) {
                        /* For check ops, we want the lookup to succeed */
                        it->it_data = NULL;
                        if (it->it_status)
                                flag = LL_LOOKUP_NEGATIVE;
                        else
                                flag = LL_LOOKUP_POSITIVE;
                } else
                        LBUG();
        } else {
                struct ll_fid fid;
                obd_flag valid;
                int eadatalen;
                int mode;

                LBUG(); /* For the moment, no non-intent locks */

                /* it_disposition == 0 indicates that it just did a simple lock
                 * request, for which we are very thankful.  move along with
                 * the local lookup then. */

                //memcpy(&lli->lli_intent_lock_handle, &lockh, sizeof(lockh));
                offset = 0;

                ino = ll_inode_by_name(parent, dentry, &mode);
                if (!ino) {
                        CERROR("inode %*s not found by name\n",
                               dentry->d_name.len, dentry->d_name.name);
                        GOTO(drop_lock, rc = -ENOENT);
                }

                valid = OBD_MD_FLNOTOBD;

                if (S_ISREG(mode)) {
                        eadatalen = obd_size_diskmd(&sbi->ll_osc_conn, NULL),
                        valid |= OBD_MD_FLEASIZE;
                } else {
                        eadatalen = 0;
                        valid |= OBD_MD_FLBLOCKS;
                }

                fid.id = ino;
                fid.generation = 0;
                fid.f_type = mode;
                rc = mdc_getattr(&sbi->ll_mdc_conn, &fid, valid,
                                 eadatalen, &request);
                if (rc) {
                        CERROR("failure %d inode "LPX64"\n", rc, ino);
                        GOTO(drop_lock, rc = -abs(rc));
                }
        }

        LASSERT (request != NULL);

        if (intent_finish != NULL) {
                rc = intent_finish(flag, request, parent, de, it, offset, ino);
                dentry = *de; /* intent_finish may change *de */
                inode = dentry->d_inode;
                if (rc != 0)
                        GOTO(drop_lock, rc);
        }
        ptlrpc_req_finished(request);

        /* This places the intent in the dentry so that the vfs_xxx
         * operation can lay its hands on it; but that is not always
         * needed...  (we need to save it in the GETATTR case for the
         * benefit of ll_inode_revalidate -phil) */
        /* Ignore trying to save the intent for "special" inodes as
         * they have special semantics that can cause deadlocks on
         * the intent semaphore. -mmex */
        if ((!inode || S_ISDIR(inode->i_mode) || S_ISREG(inode->i_mode) ||
             S_ISLNK(inode->i_mode)) && (it->it_op & (IT_OPEN | IT_GETATTR)))
                LL_SAVE_INTENT(dentry, it);
        else
                CDEBUG(D_DENTRY,
                       "D_IT dentry %p fsdata %p intent: %s status %d\n",
                       dentry, ll_d2d(dentry), ldlm_it2str(it->it_op),
                       it->it_status);

        if (it->it_op == IT_LOOKUP)
                ll_intent_release(dentry, it);

        RETURN(rc);

 drop_lock:
        ll_intent_release(dentry, it);
 drop_req:
        ptlrpc_req_finished(request);
        RETURN(rc);
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

                list_del_init(&dentry->d_hash);
                __d_rehash(dentry, 0); /* avoid taking dcache_lock inside */
                spin_unlock(&dcache_lock);
                atomic_inc(&dentry->d_count);
                iput(inode);
                dentry->d_flags &= ~DCACHE_LUSTRE_INVALID;
                return dentry;
        }

        spin_unlock(&dcache_lock);

        return de;
}

static int
lookup2_finish(int flag, struct ptlrpc_request *request,
               struct inode *parent, struct dentry **de,
               struct lookup_intent *it, int offset, obd_id ino)
{
        struct ll_sb_info *sbi = ll_i2sbi(parent);
        struct dentry *dentry = *de, *saved = *de;
        struct inode *inode = NULL;
        struct ll_read_inode2_cookie lic = {.lic_body = NULL, .lic_lsm = NULL};

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return */

        if (!(flag & LL_LOOKUP_NEGATIVE)) {
                ENTRY;

                /* We only get called if the mdc_enqueue() called from
                 * ll_intent_lock() was successful.  Therefore the mds_body
                 * is present and correct, and the eadata is present if
                 * body->eadatasize != 0 (but still opaque, so only
                 * obd_unpackmd() can check the size) */
                lic.lic_body = lustre_msg_buf(request->rq_repmsg, offset,
                                              sizeof (*lic.lic_body));
                LASSERT(lic.lic_body != NULL);
                LASSERT_REPSWABBED(request, offset);

                if (S_ISREG(lic.lic_body->mode) &&
                    (lic.lic_body->valid & OBD_MD_FLEASIZE)) {
                        struct lov_mds_md    *lmm;
                        int                   lmm_size;
                        int                   rc;

                        lmm_size = lic.lic_body->eadatasize;
                        if (lmm_size == 0) {
                                CERROR("OBD_MD_FLEASIZE set but "
                                       "eadatasize 0\n");
                                RETURN(-EPROTO);
                        }
                        lmm = lustre_msg_buf(request->rq_repmsg, offset + 1,
                                             lmm_size);
                        LASSERT(lmm != NULL);
                        LASSERT_REPSWABBED(request, offset + 1);

                        rc = obd_unpackmd(&sbi->ll_osc_conn,
                                          &lic.lic_lsm, lmm, lmm_size);
                        if (rc < 0) {
                                CERROR("Error %d unpacking eadata\n", rc);
                                RETURN(rc);
                        }
                        LASSERT(rc >= sizeof(*lic.lic_lsm));
                }

                /* Both ENOMEM and an RPC timeout are possible in ll_iget; which
                 * to pick?  A more generic EIO?  -phik */
                inode = ll_iget(dentry->d_sb, ino, &lic);
                if (!inode) {
                        /* free the lsm if we allocated one above */
                        if (lic.lic_lsm != NULL)
                                obd_free_memmd(&sbi->ll_osc_conn, &lic.lic_lsm);
                        RETURN(-ENOMEM);
                } else if (lic.lic_lsm != NULL &&
                           ll_i2info(inode)->lli_smd != lic.lic_lsm) {
                        obd_free_memmd(&sbi->ll_osc_conn, &lic.lic_lsm);
                }

                /* If this is a stat, get the authoritative file size */
                if (it->it_op == IT_GETATTR && S_ISREG(inode->i_mode) &&
                    ll_i2info(inode)->lli_smd != NULL) {
                        struct ldlm_extent extent = {0, OBD_OBJECT_EOF};
                        struct lustre_handle lockh = {0};
                        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                        ldlm_error_t rc;

                        LASSERT(lsm->lsm_object_id != 0);

                        rc = ll_extent_lock(NULL, inode, lsm, LCK_PR, &extent,
                                            &lockh);
                        if (rc != ELDLM_OK) {
                                iput(inode);
                                RETURN(-EIO);
                        }
                        ll_extent_unlock(NULL, inode, lsm, LCK_PR, &lockh);
                }

                dentry = *de = ll_find_alias(inode, dentry);

                /* We asked for a lock on the directory, and may have been
                 * granted a lock on the inode.  Just in case, fixup the data
                 * pointer. */
                ll_mdc_lock_set_inode((struct lustre_handle*)it->it_lock_handle,
                                      inode);
        } else {
                ENTRY;
        }

        dentry->d_op = &ll_d_ops;
        ll_set_dd(dentry);

        if (dentry == saved)
                d_add(dentry, inode);

        RETURN(0);
}

static struct dentry *ll_lookup2(struct inode *parent, struct dentry *dentry,
                                 struct lookup_intent *it)
{
        struct dentry *save = dentry, *retval;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, parent->i_ino, parent->i_generation,
               parent, LL_IT2STR(it));

        rc = ll_intent_lock(parent, &dentry, it, lookup2_finish);
        if (rc < 0) {
                CDEBUG(D_INFO, "ll_intent_lock: %d\n", rc);
                GOTO(out, retval = ERR_PTR(rc));
        }

        if (dentry == save)
                GOTO(out, retval = NULL);
        else
                GOTO(out, retval = dentry);
 out:
        return retval;
}

/* We depend on "mode" being set with the proper file type/umask by now */
static struct inode *ll_create_node(struct inode *dir, const char *name,
                                    int namelen, const void *data, int datalen,
                                    int mode, __u64 extra,
                                    struct lookup_intent *it)
{
        struct inode *inode;
        struct ptlrpc_request *request = NULL;
        struct mds_body *body;
        time_t time = LTIME_S(CURRENT_TIME);
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct ll_read_inode2_cookie lic;
        ENTRY;

        if (it && it->it_disposition) {
                ll_invalidate_inode_pages(dir);
                request = it->it_data;
                body = lustre_msg_buf(request->rq_repmsg, 1, sizeof (*body));
                LASSERT (body != NULL);         /* checked already */
                LASSERT_REPSWABBED (request, 1); /* swabbed already */
        } else {
                struct mdc_op_data op_data;
                int gid = current->fsgid;
                int rc;

                if (dir->i_mode & S_ISGID) {
                        gid = dir->i_gid;
                        if (S_ISDIR(mode))
                                mode |= S_ISGID;
                }

                ll_prepare_mdc_op_data(&op_data, dir, NULL, name, namelen, 0);
                rc = mdc_create(&sbi->ll_mdc_conn, &op_data,
                                data, datalen, mode, current->fsuid, gid,
                                time, extra, &request);
                if (rc) {
                        inode = ERR_PTR(rc);
                        GOTO(out, rc);
                }
                body = lustre_swab_repbuf(request, 0, sizeof (*body),
                                          lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't unpack mds_body\n");
                        GOTO (out, inode = ERR_PTR(-EPROTO));
                }
        }

        lic.lic_body = body;
        lic.lic_lsm = NULL;

        inode = ll_iget(dir->i_sb, body->ino, &lic);
        if (!inode || is_bad_inode(inode)) {
                /* XXX might need iput() for bad inode */
                int rc = -EIO;
                CERROR("new_inode -fatal: rc %d\n", rc);
                LBUG();
                GOTO(out, rc);
        }

        if (!list_empty(&inode->i_dentry)) {
                CERROR("new_inode -fatal: inode %d, ct %d lnk %d\n",
                       body->ino, atomic_read(&inode->i_count),
                       inode->i_nlink);
                iput(inode);
                LBUG();
                inode = ERR_PTR(-EIO);
                GOTO(out, -EIO);
        }

        if (it && it->it_disposition) {
                /* We asked for a lock on the directory, but were
                 * granted a lock on the inode.  Since we finally have
                 * an inode pointer, stuff it in the lock. */
                ll_mdc_lock_set_inode((struct lustre_handle*)it->it_lock_handle,
                                      inode);
        }

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return inode;
}

static int ll_mdc_unlink(struct inode *dir, struct inode *child, __u32 mode,
                         const char *name, int len)
{
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mds_body *body;
        struct lov_mds_md *eadata;
        struct lov_stripe_md *lsm = NULL;
        struct lustre_handle lockh;
        struct lookup_intent it = { .it_op = IT_UNLINK };
        struct obdo *oa;
        int err;
        struct mdc_op_data op_data;
        ENTRY;

        ll_prepare_mdc_op_data(&op_data, dir, child, name, len, mode);

        err = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_PLAIN, &it, LCK_EX,
                         &op_data, &lockh, NULL, 0,
                         ldlm_completion_ast, ll_mdc_blocking_ast,
                         dir);
        request = (struct ptlrpc_request *)it.it_data;
        if (err < 0)
                GOTO(out, err);
        if (it.it_status)
                GOTO(out, err = it.it_status);
        err = 0;

        body = lustre_msg_buf (request->rq_repmsg, 1, sizeof (*body));
        LASSERT (body != NULL);                 /* checked by mdc_enqueue() */
        LASSERT_REPSWABBED (request, 1);        /* swabbed by mdc_enqueue() */

        if (!(body->valid & OBD_MD_FLEASIZE))
                GOTO(out, 0);

        if (body->eadatasize == 0) {
                CERROR ("OBD_MD_FLEASIZE set but eadatasize zero\n");
                GOTO (out, err = -EPROTO);
        }

        /* The MDS sent back the EA because we unlinked the last reference
         * to this file. Use this EA to unlink the objects on the OST.
         * Note that mdc_enqueue() has already checked there _is_ some EA
         * data, but this data is opaque to both mdc_enqueue() and the MDS.
         * We have to leave it to obd_unpackmd() to check it is complete
         * and sensible. */
        eadata = lustre_msg_buf (request->rq_repmsg, 2, body->eadatasize);
        LASSERT (eadata != NULL);
        LASSERT_REPSWABBED (request, 2);

        err = obd_unpackmd(ll_i2obdconn(dir), &lsm, eadata,
                           body->eadatasize);
        if (err < 0) {
                CERROR("obd_unpackmd: %d\n", err);
                GOTO (out_unlock, err);
        }
        LASSERT (err >= sizeof (*lsm));

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out_free_memmd, err = -ENOMEM);

        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE;

        err = obd_destroy(ll_i2obdconn(dir), oa, lsm, NULL);
        obdo_free(oa);
        if (err)
                CERROR("obd destroy objid 0x"LPX64" error %d\n",
                       lsm->lsm_object_id, err);
 out_free_memmd:
        obd_free_memmd(ll_i2obdconn(dir), &lsm);
 out_unlock:
        ldlm_lock_decref_and_cancel(&lockh, LCK_EX);
 out:
        ptlrpc_req_finished(request);
        return err;
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
static int ll_create(struct inode *dir, struct dentry *dentry, int mode)
{
        struct lookup_intent *it;
        struct inode *inode;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, dir->i_ino, dir->i_generation, dir,
               LL_IT2STR(dentry->d_it));

        it = dentry->d_it;

        rc = ll_it_open_error(IT_OPEN_CREATE, it);
        if (rc) {
                LL_GET_INTENT(dentry, it);
                ptlrpc_req_finished(it->it_data);
                RETURN(rc);
        }

        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, 0, it);

        if (IS_ERR(inode)) {
                LL_GET_INTENT(dentry, it);
                RETURN(PTR_ERR(inode));
        }

        /* no directory data updates when intents rule */
        if (it && it->it_disposition) {
                d_instantiate(dentry, inode);
                RETURN(0);
        }

        rc = ext2_add_nondir(dentry, inode);
        RETURN(rc);
}

static int ll_mknod2(struct inode *dir, const char *name, int len, int mode,
                     int rdev)
{
        struct ptlrpc_request *request = NULL;
        time_t time = LTIME_S(CURRENT_TIME);
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p)\n",
               name, dir->i_ino, dir->i_generation, dir);

        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        mode &= ~current->fs->umask;

        switch (mode & S_IFMT) {
        case 0: case S_IFREG:
                mode |= S_IFREG; /* for mode = 0 case, fallthrough */
        case S_IFCHR: case S_IFBLK:
        case S_IFIFO: case S_IFSOCK:
                ll_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
                err = mdc_create(&sbi->ll_mdc_conn, &op_data, NULL, 0, mode,
                                 current->fsuid, current->fsgid, time,
                                 rdev, &request);
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

static int ll_mknod(struct inode *dir, struct dentry *dentry, int mode,
                    int rdev)
{
        struct lookup_intent *it;
        struct inode *inode;
        int rc = 0;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, dir->i_ino, dir->i_generation, dir,
               LL_IT2STR(dentry->d_it));

        LL_GET_INTENT(dentry, it);

        if ((mode & S_IFMT) == 0)
                mode |= S_IFREG;
        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, rdev, it);

        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

        /* no directory data updates when intents rule */
        if (it && it->it_disposition)
                d_instantiate(dentry, inode);
        else
                rc = ext2_add_nondir(dentry, inode);

        return rc;
}

static int ll_symlink2(struct inode *dir, const char *name, int len,
                       const char *tgt)
{
        struct ptlrpc_request *request = NULL;
        time_t time = LTIME_S(CURRENT_TIME);
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),target=%s\n",
               name, dir->i_ino, dir->i_generation, dir, tgt);

        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        ll_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
        err = mdc_create(&sbi->ll_mdc_conn, &op_data,
                         tgt, strlen(tgt) + 1, S_IFLNK | S_IRWXUGO,
                         current->fsuid, current->fsgid, time, 0, &request);
        ptlrpc_req_finished(request);
        RETURN(err);
}

static int ll_symlink(struct inode *dir, struct dentry *dentry,
                      const char *symname)
{
        struct lookup_intent *it;
        unsigned l = strlen(symname) + 1;
        struct inode *inode;
        struct ll_inode_info *lli;
        int err = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, dir->i_ino, dir->i_generation, dir,
               LL_IT2STR(dentry->d_it));

        LL_GET_INTENT(dentry, it);

        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               symname, l, S_IFLNK | S_IRWXUGO, 0, it);
        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

        lli = ll_i2info(inode);

        OBD_ALLOC(lli->lli_symlink_name, l);
        /* this _could_ be a non-fatal error, since the symlink is already
         * stored on the MDS by this point, and we can re-get it in readlink.
         */
        if (!lli->lli_symlink_name)
                RETURN(-ENOMEM);

        memcpy(lli->lli_symlink_name, symname, l);
        inode->i_size = l - 1;

        /* no directory data updates when intents rule */
        if (it && it->it_disposition)
                d_instantiate(dentry, inode);
        else
                err = ext2_add_nondir(dentry, inode);

        RETURN(err);
}

static int ll_link2(struct inode *src, struct inode *dir,
                    const char *name, int len)
{
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data op_data;
        int err;
        struct ll_sb_info *sbi = ll_i2sbi(dir);

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),dir=%lu/%u(%p),target=%s\n",
               src->i_ino, src->i_generation, src,
               dir->i_ino, dir->i_generation, dir, name);

        ll_prepare_mdc_op_data(&op_data, src, dir, name, len, 0);
        err = mdc_link(&sbi->ll_mdc_conn, &op_data, &request);
        ptlrpc_req_finished(request);

        RETURN(err);
}

static int ll_link(struct dentry *old_dentry, struct inode * dir,
                   struct dentry *dentry)
{
        struct lookup_intent *it;
        struct inode *inode = old_dentry->d_inode;
        int rc;
        CDEBUG(D_VFSTRACE,
               "VFS Op:inode=%lu/%u(%p),dir=%lu/%u(%p),target=%s,intent=%s\n",
               inode->i_ino, inode->i_generation, inode, dir->i_ino,
               dir->i_generation, dir, dentry->d_name.name,
               LL_IT2STR(dentry->d_it));

        LL_GET_INTENT(dentry, it);

        if (it && it->it_disposition) {
                if (it->it_status)
                        RETURN(it->it_status);
                LTIME_S(inode->i_ctime) = LTIME_S(CURRENT_TIME);
                ext2_inc_count(inode);
                atomic_inc(&inode->i_count);
                d_instantiate(dentry, inode);
                ll_invalidate_inode_pages(dir);
                RETURN(0);
        }

        if (S_ISDIR(inode->i_mode))
                return -EPERM;

        if (inode->i_nlink >= EXT2_LINK_MAX)
                return -EMLINK;

        rc = ll_link2(old_dentry->d_inode, dir,
                      dentry->d_name.name, dentry->d_name.len);
        if (rc)
                RETURN(rc);

        LTIME_S(inode->i_ctime) = LTIME_S(CURRENT_TIME);
        ext2_inc_count(inode);
        atomic_inc(&inode->i_count);

        return ext2_add_nondir(dentry, inode);
}

static int ll_mkdir2(struct inode *dir, const char *name, int len, int mode)
{
        struct ptlrpc_request *request = NULL;
        time_t time = LTIME_S(CURRENT_TIME);
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p)\n",
               name, dir->i_ino, dir->i_generation, dir);

        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        mode = (mode & (S_IRWXUGO|S_ISVTX) & ~current->fs->umask) | S_IFDIR;
        ll_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
        err = mdc_create(&sbi->ll_mdc_conn, &op_data, NULL, 0, mode,
                         current->fsuid, current->fsgid,
                         time, 0, &request);
        ptlrpc_req_finished(request);
        RETURN(err);
}


static int ll_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
        struct lookup_intent *it;
        struct inode * inode;
        int err = -EMLINK;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, dir->i_ino, dir->i_generation, dir,
               LL_IT2STR(dentry->d_it));

        LL_GET_INTENT(dentry, it);

        if (dir->i_nlink >= EXT2_LINK_MAX)
                goto out;

        ext2_inc_count(dir);
        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, S_IFDIR | mode, 0, it);
        err = PTR_ERR(inode);
        if (IS_ERR(inode))
                goto out_dir;

        err = ext2_make_empty(inode, dir);
        if (err)
                goto out_fail;

        /* no directory data updates when intents rule */
        if (!it || !it->it_disposition) {
                /* XXX FIXME This code needs re-checked for non-intents */
                ext2_inc_count(inode);
                err = ll_add_link(dentry, inode);
                if (err)
                        goto out_fail;
        }

        d_instantiate(dentry, inode);
out:
        EXIT;
        return err;

out_fail:
        ext2_dec_count(inode);
        ext2_dec_count(inode);
        iput(inode);
        EXIT;
out_dir:
        ext2_dec_count(dir);
        EXIT;
        goto out;
}

static int ll_rmdir2(struct inode *dir, const char *name, int len)
{
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p)\n",
               name, dir->i_ino, dir->i_generation, dir);

        rc = ll_mdc_unlink(dir, NULL, S_IFDIR, name, len);
        RETURN(rc);
}

static int ll_unlink2(struct inode *dir, const char *name, int len)
{
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p)\n",
               name, dir->i_ino, dir->i_generation, dir);

        rc = ll_mdc_unlink(dir, NULL, S_IFREG, name, len);
        RETURN(rc);
}

static int ll_common_unlink(struct inode *dir, struct dentry *dentry,
                            struct lookup_intent *it, __u32 mode)
{
        struct inode *inode = dentry->d_inode;
        struct ext2_dir_entry_2 * de;
        struct page * page;
        int rc = 0;
        ENTRY;

        if (it && it->it_disposition) {
                rc = it->it_status;
                ll_invalidate_inode_pages(dir);
                if (rc)
                        GOTO(out, rc);
                GOTO(out_dec, 0);
        }

        de = ext2_find_entry(dir, dentry, &page);
        if (!de)
                GOTO(out, rc = -ENOENT);
        rc = ll_mdc_unlink(dir, dentry->d_inode, mode,
                           dentry->d_name.name, dentry->d_name.len);
        if (rc)
                GOTO(out, rc);

        rc = ext2_delete_entry(de, page);
        if (rc)
                GOTO(out, rc);

        /* AED: not sure if needed - directory lock revocation should do it
         * in the case where the client has cached it for non-intent ops.
         */
        ll_invalidate_inode_pages(dir);

        inode->i_ctime = dir->i_ctime;
        EXIT;
out_dec:
        ext2_dec_count(inode);
out:
        return rc;
}

static int ll_unlink(struct inode *dir, struct dentry *dentry)
{
        struct lookup_intent * it;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, dir->i_ino, dir->i_generation, dir,
               LL_IT2STR(dentry->d_it));

        LL_GET_INTENT(dentry, it);

        RETURN(ll_common_unlink(dir, dentry, it, S_IFREG));
}

static int ll_rmdir(struct inode *dir, struct dentry *dentry)
{
        struct inode * inode = dentry->d_inode;
        struct lookup_intent *it;
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, dir->i_ino, dir->i_generation, dir,
               LL_IT2STR(dentry->d_it));

        LL_GET_INTENT(dentry, it);

        if ((!it || !it->it_disposition) && !ext2_empty_dir(inode))
                RETURN(-ENOTEMPTY);

        rc = ll_common_unlink(dir, dentry, it, S_IFDIR);
        if (!rc) {
                inode->i_size = 0;
                ext2_dec_count(inode);
                ext2_dec_count(dir);
        }

        RETURN(rc);
}

static int ll_rename2(struct inode *src, struct inode *tgt,
                      const char *oldname, int oldlen,
                      const char *newname, int newlen)
{
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(src);
        struct mdc_op_data op_data;
        int err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:oldname=%s,src_dir=%lu/%u(%p),newname=%s,"
               "tgt_dir=%lu/%u(%p)\n", oldname, src->i_ino, src->i_generation,
               src, newname, tgt->i_ino, tgt->i_generation, tgt);

        ll_prepare_mdc_op_data(&op_data, src, tgt, NULL, 0, 0);
        err = mdc_rename(&sbi->ll_mdc_conn, &op_data,
                         oldname, oldlen, newname, newlen, &request);
        ptlrpc_req_finished(request);

        RETURN(err);
}



static int ll_rename(struct inode * old_dir, struct dentry * old_dentry,
                     struct inode * new_dir, struct dentry * new_dentry)
{
        struct lookup_intent *it;
        struct inode * old_inode = old_dentry->d_inode;
        struct inode * tgt_inode = new_dentry->d_inode;
        struct page * dir_page = NULL;
        struct ext2_dir_entry_2 * dir_de = NULL;
        struct ext2_dir_entry_2 * old_de;
        struct page * old_page;
        int err;
        CDEBUG(D_VFSTRACE, "VFS Op:oldname=%s,src_dir=%lu/%u(%p),newname=%s,"
               "tgt_dir=%lu/%u(%p),intent=%s\n",
               old_dentry->d_name.name, old_dir->i_ino, old_dir->i_generation,
               old_dir, new_dentry->d_name.name, new_dir->i_ino,
               new_dir->i_generation, new_dir, LL_IT2STR(new_dentry->d_it));

        LL_GET_INTENT(new_dentry, it);

        if (it && it->it_disposition) {
                if (tgt_inode) {
                        tgt_inode->i_ctime = CURRENT_TIME;
                        tgt_inode->i_nlink--;
                }
                ll_invalidate_inode_pages(old_dir);
                ll_invalidate_inode_pages(new_dir);
                GOTO(out, err = it->it_status);
        }

        err = ll_rename2(old_dir, new_dir,
                         old_dentry->d_name.name, old_dentry->d_name.len,
                         new_dentry->d_name.name, new_dentry->d_name.len);
        if (err)
                goto out;

        old_de = ext2_find_entry (old_dir, old_dentry, &old_page);
        if (!old_de)
                goto out;

        if (S_ISDIR(old_inode->i_mode)) {
                err = -EIO;
                dir_de = ext2_dotdot(old_inode, &dir_page);
                if (!dir_de)
                        goto out_old;
        }

        if (tgt_inode) {
                struct page *new_page;
                struct ext2_dir_entry_2 *new_de;

                err = -ENOTEMPTY;
                if (dir_de && !ext2_empty_dir (tgt_inode))
                        goto out_dir;

                err = -ENOENT;
                new_de = ext2_find_entry (new_dir, new_dentry, &new_page);
                if (!new_de)
                        goto out_dir;
                ext2_inc_count(old_inode);
                ext2_set_link(new_dir, new_de, new_page, old_inode);
                tgt_inode->i_ctime = CURRENT_TIME;
                if (dir_de)
                        tgt_inode->i_nlink--;
                ext2_dec_count(tgt_inode);
        } else {
                if (dir_de) {
                        err = -EMLINK;
                        if (new_dir->i_nlink >= EXT2_LINK_MAX)
                                goto out_dir;
                }
                ext2_inc_count(old_inode);
                err = ll_add_link(new_dentry, old_inode);
                if (err) {
                        ext2_dec_count(old_inode);
                        goto out_dir;
                }
                if (dir_de)
                        ext2_inc_count(new_dir);
        }

        ext2_delete_entry (old_de, old_page);
        ext2_dec_count(old_inode);

        if (dir_de) {
                ext2_set_link(old_inode, dir_de, dir_page, new_dir);
                ext2_dec_count(old_dir);
        }
        return 0;

out_dir:
        if (dir_de) {
                kunmap(dir_page);
                page_cache_release(dir_page);
        }
out_old:
        kunmap(old_page);
        page_cache_release(old_page);
out:
        return err;
}

extern int ll_inode_revalidate(struct dentry *dentry);
struct inode_operations ll_dir_inode_operations = {
        create:          ll_create,
        lookup2:         ll_lookup2,
        link:            ll_link,
        link2:           ll_link2,
        unlink:          ll_unlink,
        unlink2:         ll_unlink2,
        symlink:         ll_symlink,
        symlink2:        ll_symlink2,
        mkdir:           ll_mkdir,
        mkdir2:          ll_mkdir2,
        rmdir:           ll_rmdir,
        rmdir2:          ll_rmdir2,
        mknod:           ll_mknod,
        mknod2:          ll_mknod2,
        rename:          ll_rename,
        rename2:         ll_rename2,
        setattr:         ll_setattr,
        setattr_raw:     ll_setattr_raw,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        revalidate:      ll_inode_revalidate,
#endif
};
