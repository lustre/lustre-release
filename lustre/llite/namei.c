/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/ext2/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *  Directory entry file type support and forward compatibility hooks
 *      for B-tree directories by Theodore Ts'o (tytso@mit.edu), 1998
 *
 *  Changes for use in OBDFS
 *  Copyright (c) 1999, Seagate Technology Inc.
 *  Copyright (C) 2001, Cluster File Systems, Inc.
 *                       Rewritten based on recent ext2 page cache use.
 *
 */

#include <linux/fs.h>
#include <linux/locks.h>
#include <linux/quotaops.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_dlm.h>
#include <linux/obd_lov.h>

extern struct address_space_operations ll_aops;

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
static int ll_find_inode(struct inode *inode, unsigned long ino, void *opaque)
{
        struct ll_read_inode2_cookie *lic = opaque;
        struct mds_body *body = lic->lic_body;

        if (inode->i_generation != lic->lic_body->generation)
                return 0;

        /* Apply the attributes in 'opaque' to this inode */
        ll_update_inode(inode, body);

        return 1;
}

extern struct dentry_operations ll_d_ops;

int ll_lock(struct inode *dir, struct dentry *dentry,
            struct lookup_intent *it, struct lustre_handle *lockh)
{
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        char *tgt = NULL;
        int tgtlen = 0;
        int err, lock_mode;

        if ((it->it_op & (IT_CREAT | IT_MKDIR | IT_SETATTR | IT_MKNOD)))
                lock_mode = LCK_PW;
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_UNLINK |
                              IT_RMDIR | IT_RENAME | IT_RENAME2 | IT_READLINK|
                              IT_LINK | IT_LINK2))
                lock_mode = LCK_PR;
        else if (it->it_op & IT_SYMLINK) {
                lock_mode = LCK_PW;
                tgt = it->it_data;
                tgtlen = strlen(tgt);
                it->it_data = NULL;
        } else if (it->it_op & IT_LOOKUP)
                lock_mode = LCK_PR;
        else {
                LBUG();
                RETURN(-EINVAL);
        }

        err = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_MDSINTENT, it, lock_mode,
                          dir, dentry, lockh, tgt, tgtlen, dir, sizeof(*dir));

        RETURN(err);
}

int ll_unlock(__u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

static struct dentry *ll_lookup2(struct inode *dir, struct dentry *dentry,
                                 struct lookup_intent *it)
{
        struct ptlrpc_request *request = NULL;
        struct inode * inode = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct ll_read_inode2_cookie lic;
        struct lustre_handle lockh;
        struct lookup_intent lookup_it = { IT_LOOKUP };
        int err, offset;
        obd_id ino = 0;

        ENTRY;

        /* CHECK_MOUNT_EPOCH(dir); */
        if (ll_i2info(dir)->lli_mount_epoch != ll_i2sbi(dir)->ll_mount_epoch)
                RETURN(ERR_PTR(-EIO));

        if (it == NULL) {
                it = &lookup_it;
                dentry->d_it = it;
        }

        CDEBUG(D_INFO, "name: %*s, intent: %s\n", dentry->d_name.len,
               dentry->d_name.name, ldlm_it2str(it->it_op));

        if (dentry->d_name.len > EXT2_NAME_LEN)
                RETURN(ERR_PTR(-ENAMETOOLONG));

        err = ll_lock(dir, dentry, it, &lockh);
        if (err < 0)
                RETURN(ERR_PTR(err));
        memcpy(it->it_lock_handle, &lockh, sizeof(lockh));

        request = (struct ptlrpc_request *)it->it_data;
        if (it->it_disposition) {
                int mode, symlen = 0;
                obd_flag valid;

                offset = 1;
                lic.lic_body = lustre_msg_buf(request->rq_repmsg, offset);
                ino = lic.lic_body->fid1.id;
                mode = lic.lic_body->mode;
                if (it->it_op & (IT_CREAT | IT_MKDIR | IT_SYMLINK | IT_MKNOD)) {
                        /* For create ops, we want the lookup to be negative,
                         * unless the create failed in a way that indicates
                         * that the file is already there */
                        if (it->it_status != -EEXIST)
                                GOTO(negative, NULL);
                } else if (it->it_op & (IT_GETATTR | IT_SETATTR | IT_LOOKUP)) {
                        /* For check ops, we want the lookup to succeed */
                        it->it_data = NULL;
                        if (it->it_status)
                                GOTO(neg_req, NULL);
                } else if (it->it_op & (IT_RENAME | IT_LINK)) {
                        /* For rename, we want the lookup to succeed */
                        if (it->it_status) {
                                it->it_data = NULL;
                                GOTO(neg_req, NULL);
                        }
                        it->it_data = dentry;
                } else if (it->it_op & (IT_UNLINK | IT_RMDIR)) {
                        /* For remove ops, we want the lookup to succeed unless
                         * the file truly doesn't exist */
                        it->it_data = NULL;
                        if (it->it_status == -ENOENT)
                                GOTO(neg_req, NULL);
                        goto iget;
                } else if (it->it_op == IT_OPEN) {
                        it->it_data = NULL;
                        if (it->it_status && it->it_status != -EEXIST)
                                GOTO(neg_req, NULL);
                } else if (it->it_op & (IT_RENAME2|IT_LINK2)) {
                        struct mds_body *body =
                                lustre_msg_buf(request->rq_repmsg, offset);
                        it->it_data = NULL;
                        /* For rename2, this means the lookup is negative */
                        /* For link2 also */
                        if (body->valid == 0)
                                GOTO(neg_req, NULL);
                        goto iget;
                }

                /* Do a getattr now that we have the lock */
                valid = OBD_MD_FLNOTOBD | OBD_MD_FLEASIZE;
                if (it->it_op == IT_READLINK) {
                        valid |= OBD_MD_LINKNAME;
                        symlen = lic.lic_body->size;
                }
                ptlrpc_req_finished(request);
                request = NULL;
                err = mdc_getattr(&sbi->ll_mdc_conn, ino, mode,
                                  valid, symlen, &request);
                if (err) {
                        CERROR("failure %d inode %Ld\n", err, (long long)ino);
                        GOTO(drop_req, err = -abs(err));
                }
                offset = 0;
        } else {
                struct ll_inode_info *lli = ll_i2info(dir);
                int mode;

                memcpy(&lli->lli_intent_lock_handle, &lockh, sizeof(lockh));
                offset = 0;

                ino = ll_inode_by_name(dir, dentry, &mode);
                if (!ino) {
                        CERROR("inode %*s not found by name\n",
                               dentry->d_name.len, dentry->d_name.name);
                        GOTO(drop_lock, err = -ENOENT);
                }

                err = mdc_getattr(&sbi->ll_mdc_conn, ino, mode,
                                  OBD_MD_FLNOTOBD|OBD_MD_FLEASIZE, 0, &request);
                if (err) {
                        CERROR("failure %d inode %Ld\n", err, (long long)ino);
                        GOTO(drop_req, err = -abs(err));
                }
        }

 iget:
        lic.lic_body = lustre_msg_buf(request->rq_repmsg, offset);
        if (S_ISREG(lic.lic_body->mode) &&
            lic.lic_body->valid & OBD_MD_FLEASIZE) {
                LASSERT(request->rq_repmsg->bufcount > offset);
                lic.lic_lmm = lustre_msg_buf(request->rq_repmsg, offset + 1);
        } else
                lic.lic_lmm = NULL;

        /* No rpc's happen during iget4, -ENOMEM's are possible */
        LASSERT(ino != 0);
        inode = iget4(dir->i_sb, ino, ll_find_inode, &lic);

        if (!inode) {
                ptlrpc_free_req(request);
                ll_intent_release(dentry);
                RETURN(ERR_PTR(-ENOMEM));
        }

        EXIT;
 neg_req:
        ptlrpc_req_finished(request);
 negative:
        dentry->d_op = &ll_d_ops;
        d_add(dentry, inode);

        if (ll_d2d(dentry) == NULL)
                ll_set_dd(dentry);
        // down(&ll_d2d(dentry)->lld_it_sem);
        // dentry->d_it = it;        

        if (it->it_op == IT_LOOKUP)
                ll_intent_release(dentry);

        return NULL;

 drop_req:
        ptlrpc_free_req(request);
 drop_lock:
#warning FIXME: must release lock here
        return ERR_PTR(err);
}

static struct inode *ll_create_node(struct inode *dir, const char *name,
                                    int namelen, const char *tgt, int tgtlen,
                                    int mode, __u64 extra,
                                    struct lookup_intent *it,
                                    struct lov_stripe_md *lsm)
{
        struct inode *inode;
        struct ptlrpc_request *request = NULL;
        struct mds_body *body;
        int rc;
        time_t time = CURRENT_TIME;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int gid = current->fsgid;
        struct ll_read_inode2_cookie lic;
        struct lov_mds_md *lmm = NULL;
        int mds_md_size = 0;

        ENTRY;

        if (dir->i_mode & S_ISGID) {
                gid = dir->i_gid;
                if (S_ISDIR(mode))
                        mode |= S_ISGID;
        }

        if (!it || !it->it_disposition) {
                rc = mdc_create(&sbi->ll_mdc_conn, dir, name, namelen, tgt,
                                 tgtlen, mode, current->fsuid,
                                 gid, time, extra, lsm, &request);
                if (rc) {
                        inode = ERR_PTR(rc);
                        GOTO(out, rc);
                }
                body = lustre_msg_buf(request->rq_repmsg, 0);
                if (lsm != NULL) {
                        mds_md_size = ll_mds_easize(dir->i_sb);
                        OBD_ALLOC(lmm, mds_md_size);
                        lov_packmd(lmm, lsm);
                        lic.lic_lmm = lmm;
                } else
                        lic.lic_lmm = NULL;

        } else {
                invalidate_inode_pages(dir);
                request = it->it_data;
                body = lustre_msg_buf(request->rq_repmsg, 1);
                lic.lic_lmm = NULL;
        }

        body->valid = OBD_MD_FLNOTOBD;

        body->nlink = 1;
        body->atime = body->ctime = body->mtime = time;
        body->uid = current->fsuid;
        body->gid = gid;
        body->mode = mode;

        lic.lic_body = body;

        inode = iget4(dir->i_sb, body->ino, ll_find_inode, &lic);
        if (IS_ERR(inode)) {
                rc = PTR_ERR(inode);
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

        EXIT;
 out:
        if (lmm)
                OBD_FREE(lmm, mds_md_size);
        ptlrpc_req_finished(request);
        return inode;
}

static int ll_mdc_unlink(struct inode *dir, struct inode *child, __u32 mode,
                         const char *name, int len)
{
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int err;

        ENTRY;

        err = mdc_unlink(&sbi->ll_mdc_conn, dir, child, mode, name, len,
                         &request);
        ptlrpc_req_finished(request);

        RETURN(err);
}

int ll_mdc_link(struct dentry *src, struct inode *dir,
                const char *name, int len)
{
        struct ptlrpc_request *request = NULL;
        int err;
        struct ll_sb_info *sbi = ll_i2sbi(dir);

        ENTRY;

        err = mdc_link(&sbi->ll_mdc_conn, src, dir, name,
                       len, &request);
        ptlrpc_req_finished(request);

        RETURN(err);
}

int ll_mdc_rename(struct inode *src, struct inode *tgt,
                  struct dentry *old, struct dentry *new)
{
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(src);
        int err;

        ENTRY;

        err = mdc_rename(&sbi->ll_mdc_conn, src, tgt,
                         old->d_name.name, old->d_name.len,
                         new->d_name.name, new->d_name.len, &request);
        ptlrpc_req_finished(request);

        RETURN(err);
}

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */

static int ll_create(struct inode * dir, struct dentry * dentry, int mode)
{
        int err, rc = 0;
        struct obdo *oa = NULL;
        struct inode *inode;
        struct lov_stripe_md *lsm = NULL;
        struct ll_inode_info *lli = NULL;
        ENTRY;

        CHECK_MOUNT_EPOCH(dir);

        if (dentry->d_it->it_disposition == 0) {
                int gid = current->fsgid;

                if (dir->i_mode & S_ISGID)
                        gid = dir->i_gid;

                oa = obdo_alloc();
                if (!oa)
                        RETURN(-ENOMEM);

                oa->o_mode = S_IFREG | 0600;
                /* FIXME: we set the UID/GID fields to 0 for now, because it
                 *        fixes a bug on the BA OSTs.  We should really set
                 *        them properly, and this needs to be revisited when
                 *        we do proper credentials checking on the OST, and
                 *        set the attributes on the OST in ll_inode_setattr().
                oa->o_uid = current->fsuid;
                oa->o_gid = gid;
                 */
                oa->o_uid = 0;
                oa->o_gid = 0;
                oa->o_valid = OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLUID |
                        OBD_MD_FLGID;
                rc = obd_create(ll_i2obdconn(dir), oa, &lsm);
                CDEBUG(D_DENTRY, "name %s mode %o o_id "LPX64": rc = %d\n",
                       dentry->d_name.name, mode, oa->o_id, rc);
                if (rc)
                        GOTO(out_free, rc);
        }

        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, 0, dentry->d_it, lsm);

        if (IS_ERR(inode)) {
                rc = PTR_ERR(inode);
                CERROR("error creating MDS object for id "LPX64": rc = %d\n",
                       oa->o_id, rc);
                GOTO(out_destroy, rc);
        }

        if (dentry->d_it->it_disposition) {
                lli = ll_i2info(inode);
                memcpy(&lli->lli_intent_lock_handle,
                       dentry->d_it->it_lock_handle,
                       sizeof(struct lustre_handle));
                d_instantiate(dentry, inode);
        } else {
                /* no directory data updates when intents rule */
                rc = ext2_add_nondir(dentry, inode);
        }

out_free:
        obdo_free(oa);
        RETURN(rc);

out_destroy:
        if (lsm) {
                if (!oa)
                        oa = obdo_alloc();
                if (!oa)
                        RETURN(-ENOMEM);

                oa->o_easize = ll_mds_easize(inode->i_sb);
                oa->o_valid |= OBD_MD_FLEASIZE;
                err = obd_destroy(ll_i2obdconn(dir), oa, lsm);
                if (err)
                        CERROR("error uncreating objid "LPX64": err %d\n",
                               oa->o_id, err);
        }

        goto out_free;
}

static int ll_mknod(struct inode *dir, struct dentry *dentry, int mode,
                    int rdev)
{
        struct inode *inode;
        int err = 0;

        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, rdev, dentry->d_it, NULL);

        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

        /* no directory data updates when intents rule */
        if (dentry->d_it && dentry->d_it->it_disposition)
                d_instantiate(dentry, inode);
        else
                err = ext2_add_nondir(dentry, inode);

        return err;
}

static int ll_symlink(struct inode *dir, struct dentry *dentry,
                      const char *symname)
{
        unsigned l = strlen(symname);
        struct inode *inode;
        struct ll_inode_info *lli;
        int err = 0;
        ENTRY;

        CHECK_MOUNT_EPOCH(dir);

        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               symname, l, S_IFLNK | S_IRWXUGO, 0,
                               dentry->d_it, NULL);
        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

        lli = ll_i2info(inode);

        OBD_ALLOC(lli->lli_symlink_name, l + 1);
        /* this _could_ be a non-fatal error, since the symlink is already
         * stored on the MDS by this point, and we can re-get it in readlink.
         */
        if (!lli->lli_symlink_name)
                RETURN(-ENOMEM);

        memcpy(lli->lli_symlink_name, symname, l + 1);
        inode->i_size = l;

        /* no directory data updates when intents rule */
        if (dentry->d_it && dentry->d_it->it_disposition)
                d_instantiate(dentry, inode);
        else
                err = ext2_add_nondir(dentry, inode);

        RETURN(err);
}

static int ll_link(struct dentry *old_dentry, struct inode * dir,
                   struct dentry *dentry)
{
        int err;
        struct inode *inode = old_dentry->d_inode;

        if (dentry->d_it && dentry->d_it->it_disposition) { 
                int err = dentry->d_it->it_status;
                if (err) 
                        RETURN(err);
                inode->i_ctime = CURRENT_TIME;
                ext2_inc_count(inode);
                atomic_inc(&inode->i_count);
                d_instantiate(dentry, inode);
                invalidate_inode_pages(dir);
                RETURN(err);
        }

        if (S_ISDIR(inode->i_mode))
                return -EPERM;

        if (inode->i_nlink >= EXT2_LINK_MAX)
                return -EMLINK;

        err = ll_mdc_link(old_dentry, dir,
                          dentry->d_name.name, dentry->d_name.len);
        if (err)
                RETURN(err);

        inode->i_ctime = CURRENT_TIME;
        ext2_inc_count(inode);
        atomic_inc(&inode->i_count);

        return ext2_add_nondir(dentry, inode);
}

static int ll_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
        struct inode * inode;
        int err = -EMLINK;
        ENTRY;

        if (dir->i_nlink >= EXT2_LINK_MAX)
                goto out;

        ext2_inc_count(dir);

        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, S_IFDIR | mode, 0, dentry->d_it, NULL);
        err = PTR_ERR(inode);
        if (IS_ERR(inode))
                goto out_dir;

        ext2_inc_count(inode);

        err = ext2_make_empty(inode, dir);
        if (err)
                goto out_fail;

        /* no directory data updates when intents rule */
        if (dentry->d_it->it_disposition == 0) {
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

static int ll_common_unlink(struct inode *dir, struct dentry *dentry,
                            __u32 mode)
{
        struct inode * inode = dentry->d_inode;
#if 0
        struct ext2_dir_entry_2 * de;
        struct page * page;
#endif
        int err = -ENOENT;

        if (dentry->d_it && dentry->d_it->it_disposition) {
                err = dentry->d_it->it_status;
                invalidate_inode_pages(dir);
                GOTO(out, err);
        }

#if 0
        de = ext2_find_entry(dir, dentry, &page);
        if (!de)
                goto out;
#endif
        err = ll_mdc_unlink(dir, dentry->d_inode, mode,
                            dentry->d_name.name, dentry->d_name.len);
        if (err)
                goto out;

#if 0
        err = ext2_delete_entry(de, page);
        if (err)
                goto out;
#endif
        invalidate_inode_pages(dir);

        inode->i_ctime = dir->i_ctime;
out:
        ext2_dec_count(inode);
        return err;
}

static int ll_unlink(struct inode *dir, struct dentry *dentry)
{
        return ll_common_unlink(dir, dentry, S_IFREG);
}

static int ll_rmdir(struct inode *dir, struct dentry *dentry)
{
        struct inode * inode = dentry->d_inode;
        int err = 0;
        ENTRY;

        if (!dentry->d_it || dentry->d_it->it_disposition == 0) {
                if (!ext2_empty_dir(inode))
                        RETURN(-ENOTEMPTY);
                err = ll_common_unlink(dir, dentry, S_IFDIR);
        } else
                err = dentry->d_it->it_status;
        if (err)
                RETURN(err);
        inode->i_size = 0;
        ext2_dec_count(inode);
        ext2_dec_count(dir);
        RETURN(err);
}

static int ll_rename(struct inode * old_dir, struct dentry * old_dentry,
                     struct inode * new_dir, struct dentry * new_dentry)
{
        struct inode * old_inode = old_dentry->d_inode;
        struct inode * tgt_inode = new_dentry->d_inode;
        struct page * dir_page = NULL;
        struct ext2_dir_entry_2 * dir_de = NULL;
        struct ext2_dir_entry_2 * old_de;
        struct page * old_page;
        int err = -ENOENT;

        if (new_dentry->d_it && new_dentry->d_it->it_disposition) { 
		if (tgt_inode) {
			tgt_inode->i_ctime = CURRENT_TIME;
			tgt_inode->i_nlink--;
		}
                invalidate_inode_pages(old_dir);
                invalidate_inode_pages(new_dir);
                GOTO(out, err = new_dentry->d_it->it_status);
        }

        err = ll_mdc_rename(old_dir, new_dir, old_dentry, new_dentry);
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

struct inode_operations ll_dir_inode_operations = {
        create:         ll_create,
        lookup2:        ll_lookup2,
        link:           ll_link,
        unlink:         ll_unlink,
        symlink:        ll_symlink,
        mkdir:          ll_mkdir,
        rmdir:          ll_rmdir,
        mknod:          ll_mknod,
        rename:         ll_rename,
        setattr:        ll_setattr
};
