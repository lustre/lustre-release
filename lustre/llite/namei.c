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
        struct mds_body *body = (struct mds_body *)opaque;

        if (inode->i_generation != body->generation)
                return 0;

        return 1;
}

extern struct dentry_operations ll_d_ops;

int ll_lock(struct inode *dir, struct dentry *dentry,
            struct lookup_intent *it, struct lustre_handle *lockh)
{
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int err, lock_mode;

        if ((it->it_op & (IT_CREAT | IT_MKDIR | IT_SYMLINK | IT_SETATTR |
                          IT_MKNOD)))
                lock_mode = LCK_PW;
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_UNLINK |
                              IT_RMDIR | IT_RENAME | IT_RENAME2))
                lock_mode = LCK_PR;
        else if (it->it_op & IT_LOOKUP)
                lock_mode = LCK_CR;
        else {
                LBUG();
                RETURN(-1);
        }

        err = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_MDSINTENT, it, lock_mode, dir,
                          dentry, lockh, 0, NULL, 0, dir, sizeof(*dir));

        RETURN(err);
}

int ll_unlock(__u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

static struct dentry *ll_lookup2(struct inode * dir, struct dentry *dentry,
                                 struct lookup_intent *it)
{
        struct ptlrpc_request *request = NULL;
        struct inode * inode = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct ll_inode_md md;
        struct lustre_handle lockh;
        int err, type, offset;
        struct lookup_intent lookup_it = { IT_LOOKUP };
        obd_id ino;

        ENTRY;

        if (it == NULL) {
                it = &lookup_it;
                dentry->d_it = it;
        }

        CDEBUG(D_INFO, "name: %*s, intent op: %d\n", dentry->d_name.len,
               dentry->d_name.name, it->it_op);

        if (dentry->d_name.len > EXT2_NAME_LEN)
                RETURN(ERR_PTR(-ENAMETOOLONG));

        err = ll_lock(dir, dentry, it, &lockh);
        if (err < 0) {
                /* FIXME: Mike LBUG() can disappear the moment that 
                 *   ll_lock has sane interrupt behavior 
                 */
                LBUG();
                RETURN(ERR_PTR(err));
        }
        memcpy(it->it_lock_handle, &lockh, sizeof(lockh));

        if ((it->it_op & (IT_CREAT | IT_MKDIR | IT_SYMLINK | IT_MKNOD)) &&
            it->it_disposition && !it->it_status)
                GOTO(negative, NULL);

        if ((it->it_op & (IT_RENAME | IT_GETATTR | IT_UNLINK | IT_RMDIR |
                          IT_SETATTR | IT_LOOKUP)) && 
            it->it_disposition && it->it_status)
                GOTO(negative, NULL);

        request = (struct ptlrpc_request *)it->it_data;
        if (!it->it_disposition) {
                struct ll_inode_info *lli = ll_i2info(dir);
                memcpy(&lli->lli_intent_lock_handle, &lockh, sizeof(lockh));

                ino = ll_inode_by_name(dir, dentry, &type);
#warning FIXME: handle negative inode case (see old ll_lookup)

                err = mdc_getattr(&sbi->ll_mdc_conn, ino, type,
                                  OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
                if (err) {
                        CERROR("failure %d inode %Ld\n", err, (long long)ino);
                        ptlrpc_free_req(request);
                        RETURN(ERR_PTR(-abs(err)));
                }
                offset = 0;
        } else if (it->it_op == IT_RENAME2) {
                inode = ((struct dentry *)(it->it_data))->d_inode;
                GOTO(out_req, NULL); 
        } else {
                offset = 1;
        }

        md.body = lustre_msg_buf(request->rq_repmsg, offset);
        if (S_ISREG(md.body->mode)) {
                if (request->rq_repmsg->bufcount < offset + 1)
                        LBUG();
                md.md = lustre_msg_buf(request->rq_repmsg, offset + 1);
        } else
                md.md = NULL;

        /* No rpc's happen during iget4, -ENOMEM's are possible */
        inode = iget4(dir->i_sb, ino, ll_find_inode, &md);
        if (it->it_op & IT_RENAME)
                it->it_data = dentry;

 out_req:
        ptlrpc_free_req(request);
        if (!inode || IS_ERR(inode)) { 
                ll_intent_release(dentry); 
                RETURN(ERR_PTR(-ENOMEM));
        }
        EXIT;
 negative:
        dentry->d_op = &ll_d_ops;
        d_add(dentry, inode);
        if (it->it_op == IT_LOOKUP)
                ll_intent_release(dentry);

        return NULL;
}

static struct inode *ll_create_node(struct inode *dir, const char *name,
                                    int namelen, const char *tgt, int tgtlen,
                                    int mode, __u64 extra,
                                    struct lookup_intent *it,
                                    struct lov_stripe_md *smd)
{
        struct inode *inode;
        struct ptlrpc_request *request = NULL;
        struct mds_body *body;
        int rc;
        time_t time = CURRENT_TIME;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int gid = current->fsgid;
        struct ll_inode_md md;

        ENTRY;

        if (dir->i_mode & S_ISGID) {
                gid = dir->i_gid;
                if (S_ISDIR(mode))
                        mode |= S_ISGID;
        }

        if (!it->it_disposition) {
                rc = mdc_create(&sbi->ll_mdc_conn, dir, name, namelen, tgt,
                                 tgtlen, mode, current->fsuid,
                                 gid, time, extra, smd, &request);
                if (rc) {
                        inode = ERR_PTR(rc);
                        GOTO(out, rc);
                }
                body = lustre_msg_buf(request->rq_repmsg, 0);
                md.md = smd;
        } else {
                request = it->it_data;
                body = lustre_msg_buf(request->rq_repmsg, 1);
                md.md = NULL;
        }

        body->valid = OBD_MD_FLNOTOBD;

        body->nlink = 1;
        body->atime = body->ctime = body->mtime = time;
        body->uid = current->fsuid;
        body->gid = gid;
        body->mode = mode;

        md.body = body;

        inode = iget4(dir->i_sb, body->ino, ll_find_inode, &md);
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
        ptlrpc_free_req(request);
        return inode;
}

int ll_mdc_unlink(struct inode *dir, struct inode *child,
                  const char *name, int len)
{
        struct ptlrpc_request *request = NULL;
        int err;
        struct ll_sb_info *sbi = ll_i2sbi(dir);

        ENTRY;

        err = mdc_unlink(&sbi->ll_mdc_conn, dir, child,
                         name, len, &request);
        ptlrpc_free_req(request);

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
        ptlrpc_free_req(request);

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
        ptlrpc_free_req(request);

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
        struct obdo oa;
        struct inode *inode;
        struct lov_stripe_md *smd;
        struct ll_inode_info *ii;

        if (dentry->d_it->it_disposition == 0) {
                memset(&oa, 0, sizeof(oa));
                oa.o_valid = OBD_MD_FLMODE;
                oa.o_mode = S_IFREG | 0600;
                rc = obd_create(ll_i2obdconn(dir), &oa, &smd);
                if (rc)
                        RETURN(rc);
        }

        CDEBUG(D_DENTRY, "name %s mode %o o_id %lld\n",
               dentry->d_name.name, mode, (unsigned long long)oa.o_id);
        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, 0, dentry->d_it, smd);

        if (IS_ERR(inode)) {
                rc = PTR_ERR(inode);
                CERROR("error creating MDS object for id %Ld: rc = %d\n",
                       (unsigned long long)oa.o_id, rc);
                GOTO(out_destroy, rc);
        }

        if (dentry->d_it->it_disposition) {
                struct ll_inode_info *ii = ll_i2info(inode);
                ii->lli_flags |= OBD_FL_CREATEONOPEN;
                memcpy(&ii->lli_intent_lock_handle,
                       dentry->d_it->it_lock_handle,
                       sizeof(struct lustre_handle));
        }

        /* no directory data updates when intents rule */
        if (dentry->d_it->it_disposition == 0)
                rc = ext2_add_nondir(dentry, inode);
        else
                d_instantiate(dentry, inode);
        RETURN(rc);

out_destroy:
        oa.o_easize = ii->lli_smd->lmd_size;
        err = obd_destroy(ll_i2obdconn(dir), &oa, ii->lli_smd);
        if (err)
                CERROR("error destroying object %Ld in error path: err = %d\n",
                       (unsigned long long)oa.o_id, err);
        return rc;
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
        if (dentry->d_it->it_disposition == 0)
                err = ext2_add_nondir(dentry, inode);
        else
                d_instantiate(dentry, inode);

        return err;
}

static int ll_symlink(struct inode *dir, struct dentry *dentry,
                      const char *symname)
{
        unsigned l = strlen(symname);
        struct inode *inode;
        struct ll_inode_info *oinfo;

        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               symname, l, S_IFLNK | S_IRWXUGO, 0,
                               dentry->d_it, NULL);
        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

        oinfo = ll_i2info(inode);

        OBD_ALLOC(oinfo->lli_symlink_name, l + 1);
        memcpy(oinfo->lli_symlink_name, symname, l + 1);
        inode->i_size = l;

        ext2_inc_count(inode);
        atomic_inc(&inode->i_count);

        return ext2_add_nondir(dentry, inode);
}

static int ll_link(struct dentry *old_dentry, struct inode * dir,
                   struct dentry *dentry)
{
        int err;
        struct inode *inode = old_dentry->d_inode;

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

        inode = ll_create_node (dir, dentry->d_name.name,
                                dentry->d_name.len, NULL, 0,
                                S_IFDIR | mode, 0, dentry->d_it, NULL);
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

static int ll_unlink(struct inode * dir, struct dentry *dentry)
{
        struct inode * inode = dentry->d_inode;
        struct ext2_dir_entry_2 * de;
        struct page * page;
        int err = -ENOENT;

        if (dentry->d_it && dentry->d_it->it_disposition) {
                inode->i_nlink = 0;
                GOTO(out, err = dentry->d_it->it_status);
        }

        de = ext2_find_entry (dir, dentry, &page);
        if (!de)
                goto out;

        err = ll_mdc_unlink(dir, dentry->d_inode,
                            dentry->d_name.name, dentry->d_name.len);
        if (err)
                goto out;

        err = ext2_delete_entry (de, page);
        if (err)
                goto out;

        inode->i_ctime = dir->i_ctime;
        ext2_dec_count(inode);
out:
        return err;
}

static int ll_rmdir(struct inode * dir, struct dentry *dentry)
{
        struct inode * inode = dentry->d_inode;
        int err = 0;
        int intent_did = dentry->d_it && dentry->d_it->it_disposition;

        if (!intent_did) {
                if (!ext2_empty_dir(inode))
                LBUG();

                err = ll_unlink(dir, dentry);
                if (err)
                        RETURN(err);
        } else
                err = dentry->d_it->it_status;
        inode->i_size = 0;
        ext2_dec_count(inode);
        ext2_dec_count(dir);
        RETURN(err);
}

static int ll_rename(struct inode * old_dir, struct dentry * old_dentry,
                     struct inode * new_dir, struct dentry * new_dentry)
{
        struct inode * old_inode = old_dentry->d_inode;
        struct inode * new_inode = new_dentry->d_inode;
        struct page * dir_page = NULL;
        struct ext2_dir_entry_2 * dir_de = NULL;
        struct page * old_page;
        struct ext2_dir_entry_2 * old_de;
        int err = -ENOENT;

        if (new_dentry->d_it && new_dentry->d_it->it_disposition)
                GOTO(out, err = new_dentry->d_it->it_status);

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

        if (new_inode) {
                struct page *new_page;
                struct ext2_dir_entry_2 *new_de;

                err = -ENOTEMPTY;
                if (dir_de && !ext2_empty_dir (new_inode))
                        goto out_dir;

                err = -ENOENT;
                new_de = ext2_find_entry (new_dir, new_dentry, &new_page);
                if (!new_de)
                        goto out_dir;
                ext2_inc_count(old_inode);
                ext2_set_link(new_dir, new_de, new_page, old_inode);
                new_inode->i_ctime = CURRENT_TIME;
                if (dir_de)
                        new_inode->i_nlink--;
                ext2_dec_count(new_inode);
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
