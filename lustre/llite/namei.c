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
ino_t ll_inode_by_name(struct inode * dir, struct dentry *dentry, int *typ);
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
        int err;

        if ((it->it_op & (IT_CREAT | IT_MKDIR | IT_SYMLINK | IT_SETATTR |
                          IT_MKNOD)) )
                err = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_MDSINTENT,
                                  it, LCK_PW, dir, dentry, lockh, 0, NULL, 0,
                                  dir, sizeof(*dir));
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_UNLINK))
                err = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_MDSINTENT,
                                  it, LCK_PR, dir, dentry, lockh, 0, NULL, 0,
                                  dir, sizeof(*dir));
        else {
                LBUG();
                RETURN(-1);
        }

        RETURN(err);
}

int ll_unlock(__u32 mode, struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        ENTRY;

        lock = lustre_handle2object(lockh);
        ldlm_lock_decref(lock, mode);

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
        ino_t ino;

        ENTRY;

        CDEBUG(D_INFO, "name: %*s, intent op: %d\n", dentry->d_name.len,
               dentry->d_name.name, it->it_op);

        if (dentry->d_name.len > EXT2_NAME_LEN)
                RETURN(ERR_PTR(-ENAMETOOLONG));

        err = ll_lock(dir, dentry, it, &lockh);
        memcpy(it->it_lock_handle, &lockh, sizeof(lockh));

        if ( (it->it_op & (IT_CREAT | IT_MKDIR | IT_SYMLINK | IT_MKNOD)) &&
             it->it_disposition && !it->it_status)
                GOTO(negative, NULL);

        if ( (it->it_op & (IT_GETATTR | IT_UNLINK)) &&
             it->it_disposition && it->it_status)
                GOTO(negative, NULL);

        if (!it->it_disposition) {
                struct ll_inode_info *lli = ll_i2info(dir);
                memcpy(&lli->lli_intent_lock_handle, &lockh, sizeof(lockh));

                ino = ll_inode_by_name(dir, dentry, &type);

                err = mdc_getattr(&sbi->ll_mdc_conn, ino, type,
                                  OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
                if (err) {
                        CERROR("failure %d inode %ld\n", err, (long)ino);
                        ptlrpc_free_req(request);
                        RETURN(ERR_PTR(-abs(err)));
                }
                offset = 0;
        } else if (it->it_op == IT_UNLINK) { 
                struct obdo *obdo;
                request = (struct ptlrpc_request *)it->it_data;
                obdo = lustre_msg_buf(request->rq_repmsg, 1);
                inode = new_inode(dir->i_sb);
                ll_i2info(inode)->lli_obdo = obdo_alloc();

                /* XXX fix mem allocation error */
                memcpy(ll_i2info(inode)->lli_obdo, obdo, sizeof(*obdo));

                if (!inode) 
                        GOTO(out_req, -ENOMEM);
                inode->i_mode= S_IFREG;
                inode->i_nlink = 1;
                GOTO(out_req, 0);
        } else {
                struct mds_body *body;

                offset = 1;
                request = (struct ptlrpc_request *)it->it_data;
                body = lustre_msg_buf(request->rq_repmsg, 1);
                type = body->mode;
                ino = body->fid1.id;
        }

        if (S_ISREG(type)) {
                if (request->rq_repmsg->bufcount < offset + 2 ||
                    request->rq_repmsg->buflens[offset + 1] !=
                    sizeof(struct obdo))
                        LBUG();

                md.obdo = lustre_msg_buf(request->rq_repmsg, offset + 1);
        } else
                md.obdo = NULL;

        md.body = lustre_msg_buf(request->rq_repmsg, offset);

        inode = iget4(dir->i_sb, ino, ll_find_inode, &md);

        if (it->it_op & IT_RENAME)
                it->it_data = dentry;

 out_req:
        ptlrpc_free_req(request);
        if (!inode)
                RETURN(ERR_PTR(-ENOMEM));

        EXIT;
 negative:
        dentry->d_op = &ll_d_ops;
        d_add(dentry, inode);
        return NULL;
}

static struct inode *ll_create_node(struct inode *dir, const char *name,
                                    int namelen, const char *tgt, int tgtlen,
                                    int mode, __u64 extra,
                                    struct lookup_intent *it, struct obdo *obdo)
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
                                 gid, time, extra, obdo, &request);
                if (rc) {
                        inode = ERR_PTR(rc);
                        GOTO(out, rc);
                }
                body = lustre_msg_buf(request->rq_repmsg, 0);
                md.obdo = obdo;
        } else {
                request = it->it_data;
                body = lustre_msg_buf(request->rq_repmsg, 1);
                md.obdo = NULL;
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

        if (dentry->d_it->it_disposition == 0) {
                memset(&oa, 0, sizeof(oa));
                oa.o_valid = OBD_MD_FLMODE;
                oa.o_mode = S_IFREG | 0600;
                rc = obd_create(ll_i2obdconn(dir), &oa);
                if (rc)
                        RETURN(rc);
        }

        mode = mode | S_IFREG;
        CDEBUG(D_DENTRY, "name %s mode %o o_id %lld\n",
               dentry->d_name.name, mode, (unsigned long long)oa.o_id);
        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, 0, dentry->d_it, &oa);

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
        err = obd_destroy(ll_i2obdconn(dir), &oa);
        if (err)
                CERROR("error destroying object %Ld in error path: err = %d\n",
                       (unsigned long long)oa.o_id, err);
        return rc;
}

static int ll_mknod(struct inode *dir, struct dentry *dentry, int mode,
                    int rdev)
{
        struct inode * inode = ll_create_node(dir, dentry->d_name.name,
                                              dentry->d_name.len, NULL, 0,
                                              mode, rdev, NULL, NULL);
        int err = PTR_ERR(inode);
        if (!IS_ERR(inode))
                err = ext2_add_nondir(dentry, inode);
        return err;
}

static int ll_symlink(struct inode *dir, struct dentry *dentry,
                      const char *symname)
{
        int err = -ENAMETOOLONG;
        unsigned l = strlen(symname);
        struct inode * inode;
        struct ll_inode_info *oinfo;

        if (l > LL_INLINESZ)
                return err;

        inode = ll_create_node(dir, dentry->d_name.name,
                               dentry->d_name.len, symname, l,
                               S_IFLNK | S_IRWXUGO, 0, dentry->d_it, NULL);
        err = PTR_ERR(inode);
        if (IS_ERR(inode))
                return err;

        oinfo = ll_i2info(inode);

        memcpy(oinfo->lli_inline, symname, l);
        inode->i_size = l-1;

        err = ext2_add_nondir(dentry, inode);

        if (err) {
                ext2_dec_count(inode);
                iput (inode);
        }
        return err;
}

static int ll_link(struct dentry * old_dentry, struct inode * dir,
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
        if (err) {
                EXIT;
                return err;
        }

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

        inode->i_nlink = 1;
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
                GOTO(out, err=0);
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
        err = 0;
out:
        return err;
}

static int ll_rmdir(struct inode * dir, struct dentry *dentry)
{
        struct inode * inode = dentry->d_inode;
        int err = -ENOTEMPTY;

        if (ext2_empty_dir(inode)) {
                err = ll_unlink(dir, dentry);
                if (!err) {
                        inode->i_size = 0;
                        ext2_dec_count(inode);
                        ext2_dec_count(dir);
                }
        }
        return err;
}

static int ll_rename (struct inode * old_dir, struct dentry * old_dentry,
                      struct inode * new_dir, struct dentry * new_dentry )
{
        struct inode * old_inode = old_dentry->d_inode;
        struct inode * new_inode = new_dentry->d_inode;
        struct page * dir_page = NULL;
        struct ext2_dir_entry_2 * dir_de = NULL;
        struct page * old_page;
        struct ext2_dir_entry_2 * old_de;
        int err = -ENOENT;

        if (new_dentry->d_it) {
                struct ptlrpc_request *req = new_dentry->d_it->it_data;
                err = req->rq_status;
                goto out;
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
