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

        if (inode->i_generation != lic->lic_body->generation)
                return 0;

        /* Apply the attributes in 'opaque' to this inode */
        ll_update_inode(inode, body, lic->lic_lmm);

        return 1;
}

extern struct dentry_operations ll_d_ops;

int ll_unlock(__u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
extern int ll_read_inode2(struct inode *inode, void *opaque);
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct ll_read_inode2_cookie *lic)
{
        struct inode *inode;

        LASSERT(hash != 0);
        inode = iget5_locked(sb, hash, ll_test_inode, ll_read_inode2, lic);

        if (!inode)
                return ERR_PTR(-ENOMEM);

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

#define IT_ENQ_COMPLETE (1<<16)

int ll_intent_lock(struct inode *parent, struct dentry **de,
                   struct lookup_intent *it, intent_finish_cb intent_finish)
{
        struct dentry *dentry = *de;
        struct ll_sb_info *sbi = ll_i2sbi(parent);
        struct lustre_handle lockh;
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        struct ptlrpc_request *request = NULL;
        char *data = NULL;
        int rc = 0, datalen = 0, offset, flag = 0;
        obd_id ino = 0;
        ENTRY;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        if (it && it->it_op == 0)
                *it = lookup_it;
#endif
        if (it == NULL)
                it = &lookup_it;

        CDEBUG(D_INFO, "name: %*s, intent: %s\n", dentry->d_name.len,
               dentry->d_name.name, ldlm_it2str(it->it_op));

        if (dentry->d_name.len > EXT2_NAME_LEN)
                RETURN(-ENAMETOOLONG);

        if (!(it->it_disposition & IT_ENQ_COMPLETE)) {
                rc = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_PLAIN, it,
                                 ll_intent_to_lock_mode(it), parent, dentry,
                                 &lockh, data, datalen, parent,
                                 sizeof(*parent));
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
                mds_body = lustre_msg_buf(request->rq_repmsg, offset);
                ino = mds_body->fid1.id;
                mode = mds_body->mode;

                /*We were called from revalidate2: did we find the same inode?*/
                if ((*de)->d_inode &&
                    (ino != (*de)->d_inode->i_ino || 
                   mds_body->fid1.generation != (*de)->d_inode->i_generation)) {
                        it->it_disposition |= IT_ENQ_COMPLETE;
                        RETURN(-ESTALE);
                }

                /* If we're doing an IT_OPEN which did not result in an actual
                 * successful open, then we need to remove the bit which saves
                 * this request for unconditional replay. */
                if (it->it_op & IT_OPEN &&
                    (!(it->it_disposition & IT_OPEN_OPEN) ||
                     it->it_status != 0))
                        request->rq_flags &= ~PTL_RPC_FL_REPLAY;

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
                obd_flag valid;
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
                        datalen = obd_size_wiremd(&sbi->ll_osc_conn, NULL),
                        valid |= OBD_MD_FLEASIZE;
                } else {
                        valid |= OBD_MD_FLBLOCKS;
                }

                rc = mdc_getattr(&sbi->ll_mdc_conn, ino, mode, valid,
                                 datalen, &request);
                if (rc) {
                        CERROR("failure %d inode "LPX64"\n", rc, ino);
                        GOTO(drop_req, rc = -abs(rc));
                }
        }

        if (intent_finish != NULL) {
                rc = intent_finish(flag, request, de, it, offset, ino);
                dentry = *de; /* intent_finish may change *de */
        } else {
                ptlrpc_req_finished(request);
        }

        /* This places the intent in the dentry so that the vfs_xxx
         * operation can lay its hands on it; but that is not always
         * needed...  (we need to save it in the GETATTR case for the
         * benefit of ll_inode_revalidate -phil) */
        if (it->it_op & (IT_OPEN | IT_GETATTR))
                LL_SAVE_INTENT(dentry, it);
        else
                CDEBUG(D_DENTRY,
                       "D_IT dentry %p fsdata %p intent: %s status %d\n",
                       dentry, ll_d2d(dentry), ldlm_it2str(it->it_op),
                       it->it_status);

        if (it->it_op == IT_LOOKUP)
                ll_intent_release(dentry, it);

        RETURN(rc);

 drop_req:
        ptlrpc_req_finished(request);
 drop_lock:
#warning FIXME: must release lock here
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
lookup2_finish(int flag, struct ptlrpc_request *request, struct dentry **de,
               struct lookup_intent *it, int offset, obd_id ino)
{
        struct dentry *dentry = *de, *saved = *de;
        struct inode *inode = NULL;
        struct ll_read_inode2_cookie lic = {.lic_body = NULL, .lic_lmm = NULL};

        if (!(flag & LL_LOOKUP_NEGATIVE)) {
                ENTRY;
                lic.lic_body = lustre_msg_buf(request->rq_repmsg, offset);

                if (S_ISREG(lic.lic_body->mode) &&
                    lic.lic_body->valid & OBD_MD_FLEASIZE) {
                        LASSERT(request->rq_repmsg->bufcount > offset);
                        lic.lic_lmm = lustre_msg_buf(request->rq_repmsg,
                                                     offset + 1);
                } else {
                        lic.lic_lmm = NULL;
                }

                /* No rpc's happen during iget4, -ENOMEM's are possible */
                inode = ll_iget(dentry->d_sb, ino, &lic);
                if (!inode) {
                        /* XXX make sure that request is freed in this case;
                         * I think it is, but double-check refcounts. -phil */
                        RETURN(-ENOMEM);
                }

                dentry = *de = ll_find_alias(inode, dentry);

                /* We asked for a lock on the directory, and may have been
                 * granted a lock on the inode.  Just in case, fixup the data
                 * pointer. */
                mdc_lock_set_inode((struct lustre_handle *)it->it_lock_handle,
                                   inode);
        } else {
                ENTRY;
        }

        ptlrpc_req_finished(request);

        dentry->d_op = &ll_d_ops;
        ll_set_dd(dentry);

        if (dentry == saved)
                d_add(dentry, inode);

        RETURN(0);
}

static struct dentry *ll_lookup2(struct inode *parent, struct dentry *dentry,
                                 struct lookup_intent *it)
{
        struct dentry *save = dentry;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        rc = ll_intent_lock(parent, &dentry, it, lookup2_finish);
        if (rc < 0) {
                CDEBUG(D_INFO, "ll_intent_lock: %d\n", rc);
                RETURN(ERR_PTR(rc));
        }

        if (dentry == save)
                RETURN(NULL);
        else
                RETURN(dentry);
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
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        time_t time = CURRENT_TIME.tv_sec;
#else
        time_t time = CURRENT_TIME;
#endif
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct ll_read_inode2_cookie lic = { .lic_lmm = NULL, };
        ENTRY;

        if (it && it->it_disposition) {
                ll_invalidate_inode_pages(dir);
                request = it->it_data;
                body = lustre_msg_buf(request->rq_repmsg, 1);
        } else {
                int gid = current->fsgid;
                int rc;

                if (dir->i_mode & S_ISGID) {
                        gid = dir->i_gid;
                        if (S_ISDIR(mode))
                                mode |= S_ISGID;
                }

                rc = mdc_create(&sbi->ll_mdc_conn, dir, name, namelen,
                                data, datalen, mode, current->fsuid, gid,
                                time, extra, &request);
                if (rc) {
                        inode = ERR_PTR(rc);
                        GOTO(out, rc);
                }
                body = lustre_msg_buf(request->rq_repmsg, 0);
        }

        lic.lic_body = body;

        inode = ll_iget(dir->i_sb, body->ino, &lic);
        if (IS_ERR(inode)) {
                int rc = PTR_ERR(inode);
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
                mdc_lock_set_inode((struct lustre_handle *)it->it_lock_handle,
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
        struct lov_stripe_md *lsm = NULL;
        struct lustre_handle lockh;
        struct lookup_intent it = { .it_op = IT_UNLINK };
        struct obdo *oa;
        int err;
        struct mdc_unlink_data data;
        ENTRY;

        data.unl_dir = dir;
        data.unl_de = child;
        data.unl_mode = mode;
        data.unl_name = name;
        data.unl_len = len;

        err = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_PLAIN, &it, LCK_EX, dir,
                         NULL, &lockh, NULL, 0, &data, sizeof(data));
        request = (struct ptlrpc_request *)it.it_data;
        if (err < 0)
                GOTO(out, err);
        if (it.it_status)
                GOTO(out, err = it.it_status);
        err = 0;

        body = lustre_msg_buf(request->rq_repmsg, 1);
        LASSERT(body != NULL);
        if (!(body->valid & OBD_MD_FLEASIZE))
                GOTO(out, 0);

        /* The MDS sent back the EA because we unlinked the last reference
         * to this file.  Use this EA to unlink the objects on the OST */
        err = obd_unpackmd(ll_i2obdconn(dir), &lsm,
                           lustre_msg_buf(request->rq_repmsg, 2));
        if (err < 0)
                CERROR("obd_unpackmd: %d\n", err);

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out_unlock, err = -ENOMEM);

        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE;

        err = obd_destroy(ll_i2obdconn(dir), oa, lsm, NULL);
        obdo_free(oa);
        if (err)
                CERROR("obd destroy objid 0x"LPX64" error %d\n",
                       lsm->lsm_object_id, err);

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

        CDEBUG(D_VFSTRACE, "VFS Op\n");
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
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        time_t time = CURRENT_TIME.tv_sec;
#else
        time_t time = CURRENT_TIME;
#endif
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        mode &= ~current->fs->umask;

        switch (mode & S_IFMT) {
        case 0: case S_IFREG:
                mode |= S_IFREG; /* for mode = 0 case, fallthrough */
        case S_IFCHR: case S_IFBLK:
        case S_IFIFO: case S_IFSOCK:
                err = mdc_create(&sbi->ll_mdc_conn, dir, name, len, NULL, 0,
                                 mode, current->fsuid, current->fsgid, time,
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

        CDEBUG(D_VFSTRACE, "VFS Op\n");
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
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        time_t time = CURRENT_TIME.tv_sec;
#else
        time_t time = CURRENT_TIME;
#endif
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        err = mdc_create(&sbi->ll_mdc_conn, dir, name, len,
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

        CDEBUG(D_VFSTRACE, "VFS Op\n");
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
        int err;
        struct ll_sb_info *sbi = ll_i2sbi(dir);

        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        err = mdc_link(&sbi->ll_mdc_conn, src, dir, name, len, &request);
        ptlrpc_req_finished(request);

        RETURN(err);
}

static int ll_link(struct dentry *old_dentry, struct inode * dir,
                   struct dentry *dentry)
{
        struct lookup_intent *it;
        struct inode *inode = old_dentry->d_inode;
        int rc;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        LL_GET_INTENT(dentry, it);

        if (it && it->it_disposition) {
                if (it->it_status)
                        RETURN(it->it_status);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                inode->i_ctime.tv_sec = CURRENT_TIME.tv_sec;
#else
                inode->i_ctime = CURRENT_TIME;
#endif
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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                inode->i_ctime.tv_sec = CURRENT_TIME.tv_sec;
#else
                inode->i_ctime = CURRENT_TIME;
#endif
        ext2_inc_count(inode);
        atomic_inc(&inode->i_count);

        return ext2_add_nondir(dentry, inode);
}

static int ll_mkdir2(struct inode *dir, const char *name, int len, int mode)
{
        struct ptlrpc_request *request = NULL;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        time_t time = CURRENT_TIME.tv_sec;
#else
        time_t time = CURRENT_TIME;
#endif
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        mode = (mode & (S_IRWXUGO|S_ISVTX) & ~current->fs->umask) | S_IFDIR;
        err = mdc_create(&sbi->ll_mdc_conn, dir, name, len, NULL, 0,
                         mode, current->fsuid, current->fsgid,
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

        CDEBUG(D_VFSTRACE, "VFS Op\n");
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

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        rc = ll_mdc_unlink(dir, NULL, S_IFDIR, name, len);
        RETURN(rc);
}

static int ll_unlink2(struct inode *dir, const char *name, int len)
{
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op\n");
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

        CDEBUG(D_VFSTRACE, "VFS Op\n");
        LL_GET_INTENT(dentry, it);

        RETURN(ll_common_unlink(dir, dentry, it, S_IFREG));
}

static int ll_rmdir(struct inode *dir, struct dentry *dentry)
{
        struct inode * inode = dentry->d_inode;
        struct lookup_intent *it;
        int rc;
        ENTRY;
        
        CDEBUG(D_VFSTRACE, "VFS Op\n");
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
        int err;
        ENTRY;
        
        CDEBUG(D_VFSTRACE, "VFS Op\n");
        err = mdc_rename(&sbi->ll_mdc_conn, src, tgt,
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

        CDEBUG(D_VFSTRACE, "VFS Op\n");
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
