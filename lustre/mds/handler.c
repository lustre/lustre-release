/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/handler.c
 *  Lustre Metadata Server (mds) request handler
 *
 *  Copyright (c) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/obd_class.h>

extern int mds_get_lovtgts(struct obd_device *obd, int tgt_count,
                           uuid_t *uuidarray);
extern int mds_get_lovdesc(struct obd_device *obd, struct lov_desc *desc);
extern int mds_update_last_rcvd(struct mds_obd *mds, void *handle,
                                struct ptlrpc_request *req);
static int mds_cleanup(struct obd_device * obddev);

inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mds;
}

static int mds_bulk_timeout(void *data)
{
        struct ptlrpc_bulk_desc *desc = data;
        
        ENTRY;
        CERROR("(not yet) starting recovery of client %p\n", desc->b_client);
        RETURN(1);
}

/* Assumes caller has already pushed into the kernel filesystem context */
static int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                        __u64 offset)
{
        int rc = 0;
        struct mds_obd *mds = mds_req2mds(req);
        struct ptlrpc_bulk_desc *desc;
        struct ptlrpc_bulk_page *bulk;
        struct l_wait_info lwi;
        char *buf;
        ENTRY;

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        bulk = ptlrpc_prep_bulk_page(desc);
        if (bulk == NULL)
                GOTO(cleanup_bulk, rc = -ENOMEM);

        OBD_ALLOC(buf, PAGE_SIZE);
        if (buf == NULL)
                GOTO(cleanup_bulk, rc = -ENOMEM);

        rc = mds_fs_readpage(mds, file, buf, PAGE_SIZE, (loff_t *)&offset);

        if (rc != PAGE_SIZE)
                GOTO(cleanup_buf, rc = -EIO);

        bulk->b_xid = req->rq_xid;
        bulk->b_buf = buf;
        bulk->b_buflen = PAGE_SIZE;
        desc->b_portal = MDS_BULK_PORTAL;

        rc = ptlrpc_send_bulk(desc);
        if (rc)
                GOTO(cleanup_buf, rc);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
                CERROR("obd_fail_loc=%x, fail operation rc=%d\n",
                       OBD_FAIL_MDS_SENDPAGE, rc);
                ptlrpc_abort_bulk(desc);
                GOTO(cleanup_buf, rc);
        }

        lwi = LWI_TIMEOUT(obd_timeout * HZ, mds_bulk_timeout, desc);
        rc = l_wait_event(desc->b_waitq, desc->b_flags & PTL_BULK_FL_SENT, &lwi);
        if (rc) {
                if (rc != -ETIMEDOUT)
                        LBUG();
                GOTO(cleanup_buf, rc);
        }

        EXIT;
 cleanup_buf:
        OBD_FREE(buf, PAGE_SIZE);
 cleanup_bulk:
        ptlrpc_free_bulk(desc);
 out:
        return rc;
}

/*
 * Look up a named entry in a directory, and get an LDLM lock on it.
 * 'dir' is a inode for which an LDLM lock has already been taken.
 *
 * If we do not need an exclusive or write lock on this entry (e.g.
 * a read lock for attribute lookup only) then we do not hold the
 * directory on return.  It is up to the caller to know what type
 * of lock it is getting, and clean up appropriately.
 */
struct dentry *mds_name2locked_dentry(struct obd_device *obd,
                                      struct dentry *dir, struct vfsmount **mnt,
                                      char *name, int namelen, int lock_mode,
                                      struct lustre_handle *lockh,
                                      int dir_lock_mode)
{
        struct dentry *dchild;
        int flags, rc;
        __u64 res_id[3] = {0};
        ENTRY;

        down(&dir->d_inode->i_sem);
        dchild = lookup_one_len(name, dir, namelen);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                up(&dir->d_inode->i_sem);
                LBUG();
                RETURN(dchild);
        }
        if (dir_lock_mode != LCK_EX && dir_lock_mode != LCK_PW) {
                up(&dir->d_inode->i_sem);
                ldlm_lock_decref(lockh, dir_lock_mode);
        }

        if (lock_mode == 0 || !dchild->d_inode)
                RETURN(dchild);

        res_id[0] = dchild->d_inode->i_ino;
        rc = ldlm_match_or_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                   res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                   &flags, ldlm_completion_ast,
                                   mds_blocking_ast, NULL, 0, lockh);
        if (rc != ELDLM_OK) {
                l_dput(dchild);
                up(&dir->d_inode->i_sem);
                RETURN(ERR_PTR(-ENOLCK)); /* XXX translate ldlm code */
        }

        RETURN(dchild);
}

struct dentry *mds_fid2locked_dentry(struct obd_device *obd, struct ll_fid *fid,
                                     struct vfsmount **mnt, int lock_mode,
                                     struct lustre_handle *lockh)
{
        struct mds_obd *mds = &obd->u.mds;
        struct dentry *de = mds_fid2dentry(mds, fid, mnt), *retval = de;
        int flags, rc;
        __u64 res_id[3] = {0};
        ENTRY;

        if (IS_ERR(de))
                RETURN(de);

        res_id[0] = de->d_inode->i_ino;
        rc = ldlm_match_or_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                   res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                   &flags, ldlm_completion_ast,
                                   mds_blocking_ast, NULL, 0, lockh);
        if (rc != ELDLM_OK) {
                l_dput(de);
                retval = ERR_PTR(-ENOLCK); /* XXX translate ldlm code */
        }

        RETURN(retval);
}

/* Look up an entry by inode number. */
struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid,
                              struct vfsmount **mnt)
{
        /* stolen from NFS */
        struct super_block *sb = mds->mds_sb;
        unsigned long ino = fid->id;
        __u32 generation = fid->generation;
        struct inode *inode;
        struct list_head *lp;
        struct dentry *result;

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));

        inode = iget(sb, ino);
        if (inode == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        CDEBUG(D_DENTRY, "--> mds_fid2dentry: sb %p\n", inode->i_sb);

        if (is_bad_inode(inode) ||
            (generation && inode->i_generation != generation)) {
                /* we didn't find the right inode.. */
                CERROR("bad inode %lu, link: %d ct: %d or version  %u/%u\n",
                       inode->i_ino, inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       generation);
                LBUG();
                iput(inode);
                RETURN(ERR_PTR(-ESTALE));
        }

        /* now to find a dentry. If possible, get a well-connected one */
        if (mnt)
                *mnt = mds->mds_vfsmnt;
        spin_lock(&dcache_lock);
        list_for_each(lp, &inode->i_dentry) {
                result = list_entry(lp, struct dentry, d_alias);
                if (!(result->d_flags & DCACHE_NFSD_DISCONNECTED)) {
                        dget_locked(result);
                        result->d_vfs_flags |= DCACHE_REFERENCED;
                        spin_unlock(&dcache_lock);
                        iput(inode);
                        if (mnt)
                                mntget(*mnt);
                        return result;
                }
        }
        spin_unlock(&dcache_lock);
        result = d_alloc_root(inode);
        if (result == NULL) {
                iput(inode);
                return ERR_PTR(-ENOMEM);
        }
        if (mnt)
                mntget(*mnt);
        result->d_flags |= DCACHE_NFSD_DISCONNECTED;
        return result;
}

/* Establish a connection to the MDS.
 *
 * This will set up an export structure for the client to hold state data
 * about that client, like open files, the last operation number it did
 * on the server, etc.
 */
static int mds_connect(struct lustre_handle *conn, struct obd_device *obd,
                       char *cluuid)
{
        struct obd_export *exp;
        struct mds_client_data *mcd;
        struct list_head *p;
        int rc;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        MOD_INC_USE_COUNT;

        list_for_each(p, &obd->obd_exports) {
                exp = list_entry(p, struct obd_export, exp_chain);
                mcd = exp->exp_mds_data.med_mcd;
                if (!memcmp(cluuid, mcd->mcd_uuid, sizeof(mcd->mcd_uuid))) {
                        CDEBUG(D_INFO, "existing export for UUID '%s' at %p\n",
                               cluuid, exp);
                        LASSERT(exp->exp_obd == obd);

                        exp->exp_rconnh.addr = conn->addr;
                        exp->exp_rconnh.cookie = conn->cookie;
                        conn->addr = (__u64) (unsigned long)exp;
                        conn->cookie = exp->exp_cookie;
                        CDEBUG(D_IOCTL,"connect: addr %Lx cookie %Lx\n",
                               (long long)conn->addr, (long long)conn->cookie);
                        RETURN(0);
                }
        }
        rc = class_connect(conn, obd, cluuid);
        if (rc)
                GOTO(out_dec, rc);
        exp = class_conn2export(conn);
        LASSERT(exp);

        OBD_ALLOC(mcd, sizeof(*mcd));
        if (!mcd) {
                CERROR("mds: out of memory for client data\n");
                GOTO(out_export, rc = -ENOMEM);
        }
        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        exp->exp_mds_data.med_mcd = mcd;
        rc = mds_client_add(&exp->exp_mds_data, -1);
        if (rc)
                GOTO(out_mdc, rc);

        RETURN(0);

out_mdc:
        OBD_FREE(mcd, sizeof(*mcd));
out_export:
        class_disconnect(conn);
out_dec:
        MOD_DEC_USE_COUNT;

        return rc;
}

static int mds_disconnect(struct lustre_handle *conn)
{
        struct obd_export *exp;
        int rc;

        exp = class_conn2export(conn);
        if (!exp)
                RETURN(-EINVAL);

        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

static int mds_getstatus(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK)) {
                CERROR("mds: out of memory for message: size=%d\n", size);
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_unpack_body(body);

        /* Anything we need to do here with the client's trans no or so? */
        body = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&body->fid1, &mds->mds_rootfid, sizeof(body->fid1));

        LASSERT(med->med_mcd);

        /* mcd_last_xid is is stored in little endian on the disk and
           mds_pack_rep_body converts it to network order */
        req->rq_repmsg->last_xid = le32_to_cpu(med->med_mcd->mcd_last_xid);
        mds_pack_rep_body(req);
        RETURN(0);
}

static int mds_getlovinfo(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_status_req *streq;
        struct lov_desc *desc;
        int tgt_count;
        int rc, size[2] = {sizeof(*desc)};
        ENTRY;

        streq = lustre_msg_buf(req->rq_reqmsg, 0);
        streq->flags = NTOH__u32(streq->flags);
        streq->repbuf = NTOH__u32(streq->repbuf);
        size[1] = streq->repbuf;

        rc = lustre_pack_msg(2, size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("mds: out of memory for message: size=%d\n", size[1]);
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        desc = lustre_msg_buf(req->rq_repmsg, 0);
        rc = mds_get_lovdesc(req->rq_obd, desc);
        if (rc != 0 ) {
                CERROR("mds_get_lovdesc error %d", rc);
                req->rq_status = rc;
                RETURN(0);
        }

        tgt_count = NTOH__u32(desc->ld_tgt_count);
        if (tgt_count * sizeof(uuid_t) > streq->repbuf) {
                CERROR("too many targets, enlarge client buffers\n");
                req->rq_status = -ENOSPC;
                RETURN(0);
        }

        mds->mds_max_mdsize = sizeof(struct lov_mds_md) + 
                tgt_count * sizeof(struct lov_object_id);
        rc = mds_get_lovtgts(req->rq_obd, tgt_count,
                             lustre_msg_buf(req->rq_repmsg, 1));
        if (rc) {
                CERROR("get_lovtgts error %d\n", rc);
                req->rq_status = rc;
                RETURN(0);
        }
        RETURN(0);
}

int mds_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                     void *data, __u32 data_len)
{
        int do_ast;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        if (do_ast) {
                struct lustre_handle lockh;
                int rc;

                LDLM_DEBUG(lock, "already unused, calling ldlm_cli_cancel");
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0)
                        CERROR("ldlm_cli_cancel: %d\n", rc);
        } else
                LDLM_DEBUG(lock, "Lock still has references, will be"
                           "cancelled later");
        RETURN(0);
}

static int mds_getattr_internal(struct mds_obd *mds, struct dentry *dentry,
                                struct ptlrpc_request *req,
                                int request_off, int reply_off)
{
        struct mds_body *request_body, *body;
        struct inode *inode = dentry->d_inode;
        int rc;
        ENTRY;

        if (inode == NULL)
                RETURN(-ENOENT);

        /* Did the client request the link name? */
        request_body = lustre_msg_buf(req->rq_reqmsg, request_off);
        body = lustre_msg_buf(req->rq_repmsg, reply_off);
        if ((body->valid & OBD_MD_LINKNAME) && S_ISLNK(inode->i_mode)) {
                char *tmp = lustre_msg_buf(req->rq_repmsg, reply_off + 1);

                rc = inode->i_op->readlink(dentry, tmp, req->rq_repmsg->
                                           buflens[reply_off + 1]);
                if (rc < 0) {
                        CERROR("readlink failed: %d\n", rc);
                        RETURN(rc);
                }

                body->valid |= OBD_MD_LINKNAME;
        }

        mds_pack_inode2fid(&body->fid1, inode);
        mds_pack_inode2body(body, inode);
        if (S_ISREG(inode->i_mode)) {
                struct lov_mds_md *md;

                md = lustre_msg_buf(req->rq_repmsg, reply_off + 1);
                md->lmd_easize = mds->mds_max_mdsize;
                rc = mds_fs_get_md(mds, inode, md);

                if (rc < 0) {
                        if (rc == -ENODATA)
                                RETURN(0);
                        CERROR("mds_fs_get_md failed: %d\n", rc);
                        RETURN(rc);
                }
                body->valid |= OBD_MD_FLEASIZE;
        }
        RETURN(0);
}

static int mds_getattr_name(int offset, struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_run_ctxt saved;
        struct mds_body *body;
        struct dentry *de = NULL, *dchild = NULL;
        struct inode *dir;
        struct lustre_handle lockh;
        char *name;
        int namelen, flags, lock_mode, rc = 0, old_offset = offset;
        __u64 res_id[3] = {0, 0, 0};
        ENTRY;

        LASSERT(!strcmp(req->rq_export->exp_obd->obd_type->typ_name, "mds"));

        if (req->rq_reqmsg->bufcount <= offset + 1) {
                LBUG();
                GOTO(out_pre_de, rc = -EINVAL);
        }

        body = lustre_msg_buf(req->rq_reqmsg, offset);
        name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        namelen = req->rq_reqmsg->buflens[offset + 1];
        /* requests were at offset 2, replies go back at 1 */
        if (offset)
                offset = 1;

        push_ctxt(&saved, &mds->mds_ctxt);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                LBUG();
                GOTO(out_pre_de, rc = -ESTALE);
        }

        dir = de->d_inode;
        CDEBUG(D_INODE, "parent ino %ld, name %*s\n", dir->i_ino,namelen,name);

        lock_mode = (req->rq_reqmsg->opc == MDS_REINT) ? LCK_CW : LCK_PW;
        res_id[0] = dir->i_ino;

        rc = ldlm_lock_match(obd->obd_namespace, res_id, LDLM_PLAIN,
                             NULL, 0, lock_mode, &lockh);
        if (rc == 0) {
                LDLM_DEBUG_NOLOCK("enqueue res %Lu", res_id[0]);
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL, 0, &lockh);
                if (rc != ELDLM_OK) {
                        CERROR("lock enqueue: err: %d\n", rc);
                        GOTO(out_create_de, rc = -EIO);
                }
        }
        ldlm_lock_dump((void *)(unsigned long)lockh.addr);

        down(&dir->i_sem);
        dchild = lookup_one_len(name, de, namelen - 1);
        if (IS_ERR(dchild)) {
                CDEBUG(D_INODE, "child lookup error %ld\n", PTR_ERR(dchild));
                up(&dir->i_sem);
                LBUG();
                GOTO(out_create_dchild, rc = -ESTALE);
        }

        rc = mds_getattr_internal(mds, dchild, req, old_offset, offset);

        EXIT;
out_create_dchild:
        l_dput(dchild);
        up(&dir->i_sem);
        ldlm_lock_decref(&lockh, lock_mode);
out_create_de:
        l_dput(de);
out_pre_de:
        req->rq_status = rc;
        pop_ctxt(&saved);
        return 0;
}

static int mds_getattr(int offset, struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_run_ctxt saved;
        struct dentry *de;
        struct inode *inode;
        struct mds_body *body;
        int rc = 0, size[2] = {sizeof(*body)}, bufcount = 1;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, offset);
        push_ctxt(&saved, &mds->mds_ctxt);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                req->rq_status = -ENOENT;
                GOTO(out_pop, rc = -ENOENT);
        }

        inode = de->d_inode;
        if (S_ISREG(body->fid1.f_type)) {
                bufcount = 2;
                size[1] = mds->mds_max_mdsize;
        } else if (body->valid & OBD_MD_LINKNAME) {
                bufcount = 2;
                size[1] = inode->i_size;
        }

        rc = lustre_pack_msg(bufcount, size, NULL, &req->rq_replen,
                             &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("out of memory or FAIL_MDS_GETATTR_PACK\n");
                req->rq_status = rc;
                GOTO(out, rc = 0);
        }

        req->rq_status = mds_getattr_internal(mds, de, req, offset, 0);

out:
        l_dput(de);
out_pop:
        pop_ctxt(&saved);
        RETURN(rc);
}

static int mds_statfs(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_statfs *osfs;
        struct statfs sfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                             &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR("mds: statfs lustre_pack_msg failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        rc = vfs_statfs(mds->mds_sb, &sfs);
        if (rc) {
                CERROR("mds: statfs failed: rc %d\n", rc);
                GOTO(out, rc);
        }
        osfs = lustre_msg_buf(req->rq_repmsg, 0);
        memset(osfs, 0, size);
        obd_statfs_pack(osfs, &sfs);

out:
        req->rq_status = rc;
        RETURN(0);
}

static int mds_open(struct ptlrpc_request *req)
{
        struct dentry *de;
        struct mds_body *body;
        struct file *file;
        struct vfsmount *mnt;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_export_data *med;
        __u32 flags;
        struct list_head *tmp;
        struct mds_file_data *mfd;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
                CERROR("mds: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        /* was this animal open already? */
        /* XXX we should only check on re-open, or do a refcount... */
        med = &req->rq_export->exp_mds_data;
        list_for_each(tmp, &med->med_open_head) {
                struct mds_file_data *fd;
                fd = list_entry(tmp, struct mds_file_data, mfd_list);
                if (body->extra == fd->mfd_clientfd &&
                    body->fid1.id == fd->mfd_file->f_dentry->d_inode->i_ino) {
                        CERROR("Re opening %Ld\n", body->fid1.id);
                        RETURN(0);
                }
        }

        OBD_ALLOC(mfd, sizeof(*mfd));
        if (!mfd) {
                CERROR("mds: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        de = mds_fid2dentry(mds, &body->fid1, &mnt);
        if (IS_ERR(de)) {
                req->rq_status = -ENOENT;
                RETURN(0);
        }

        /* check if this inode has seen a delayed object creation */
        if (req->rq_reqmsg->bufcount > 1) {
                void *handle;
                struct lov_mds_md *md;
                struct inode *inode = de->d_inode;
                int rc;

                md = lustre_msg_buf(req->rq_reqmsg, 1);

                handle = mds_fs_start(mds, de->d_inode, MDS_FSOP_SETATTR);
                if (!handle) {
                        req->rq_status = -ENOMEM;
                        RETURN(0);
                }

                /* XXX error handling */
                rc = mds_fs_set_md(mds, inode, handle, md);
                if (!rc) {
                        struct obd_run_ctxt saved;
                        push_ctxt(&saved, &mds->mds_ctxt);
                        rc = mds_update_last_rcvd(mds, handle, req);
                        pop_ctxt(&saved);
                } else {
                        req->rq_status = rc;
                        RETURN(0);
                }
                /* FIXME: need to return last_rcvd, last_committed */

                /* FIXME: keep rc intact */
                rc = mds_fs_commit(mds, de->d_inode, handle);
                if (rc) {
                        req->rq_status = rc;
                        RETURN(0);
                }
        }

        flags = body->flags;
        file = dentry_open(de, mnt, flags & ~O_DIRECT);
        if (!file || IS_ERR(file)) {
                req->rq_status = -EINVAL;
                OBD_FREE(mfd, sizeof(*mfd));
                RETURN(0);
        }

        file->private_data = mfd;
        mfd->mfd_file = file;
        mfd->mfd_clientfd = body->extra;
        list_add(&mfd->mfd_list, &med->med_open_head);

        body = lustre_msg_buf(req->rq_repmsg, 0);
        /* FIXME: need to have cookies involved here */
        body->extra = (__u64) (unsigned long)file;
        RETURN(0);
}

static int mds_close(struct ptlrpc_request *req)
{
        struct dentry *de;
        struct mds_body *body;
        struct file *file;
        struct mds_obd *mds = mds_req2mds(req);
        struct vfsmount *mnt;
        struct mds_file_data *mfd;
        int rc;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK)) {
                CERROR("mds: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        de = mds_fid2dentry(mds, &body->fid1, &mnt);
        if (IS_ERR(de)) {
                req->rq_status = -ENOENT;
                RETURN(0);
        }

        /* FIXME: need to have cookies involved here */
        file = (struct file *)(unsigned long)body->extra;
        if (!file->f_dentry)
                LBUG();
        mfd = (struct mds_file_data *)file->private_data;
        list_del(&mfd->mfd_list);
        OBD_FREE(mfd, sizeof(*mfd));

        req->rq_status = filp_close(file, 0);
        l_dput(de);
        mntput(mnt);

        RETURN(0);
}

static int mds_readpage(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct vfsmount *mnt;
        struct dentry *de;
        struct file *file;
        struct mds_body *body;
        struct obd_run_ctxt saved;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK)) {
                CERROR("mds: out of memory\n");
                GOTO(out, rc = -ENOMEM);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        push_ctxt(&saved, &mds->mds_ctxt);
        de = mds_fid2dentry(mds, &body->fid1, &mnt);
        if (IS_ERR(de))
                GOTO(out_pop, rc = PTR_ERR(de));

        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

        file = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE);
        /* note: in case of an error, dentry_open puts dentry */
        if (IS_ERR(file))
                GOTO(out_pop, rc = PTR_ERR(file));

        /* to make this asynchronous make sure that the handling function
           doesn't send a reply when this function completes. Instead a
           callback function would send the reply */
        rc = mds_sendpage(req, file, body->size);

        filp_close(file, 0);
out_pop:
        pop_ctxt(&saved);
out:
        req->rq_status = rc;
        RETURN(0);
}

int mds_reint(int offset, struct ptlrpc_request *req)
{
        int rc;
        struct mds_update_record rec;

        rc = mds_update_unpack(req, offset, &rec);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK)) {
                CERROR("invalid record\n");
                req->rq_status = -EINVAL;
                RETURN(0);
        }
        /* rc will be used to interrupt a for loop over multiple records */
        rc = mds_reint_rec(&rec, offset, req);
        return rc;
}

int mds_handle(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_HANDLE_UNPACK)) {
                CERROR("lustre_mds: Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->type != PTL_RPC_MSG_REQUEST) {
                CERROR("lustre_mds: wrong packet type sent %d\n",
                       req->rq_reqmsg->type);
                GOTO(out, rc = -EINVAL);
        }

        if (req->rq_reqmsg->opc != MDS_CONNECT && req->rq_export == NULL)
                GOTO(out, rc = -ENOTCONN);

        if (strcmp(req->rq_obd->obd_type->typ_name, "mds") != 0)
                GOTO(out, rc = -EINVAL);

        switch (req->rq_reqmsg->opc) {
        case MDS_CONNECT:
                CDEBUG(D_INODE, "connect\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CONNECT_NET, 0);
                rc = target_handle_connect(req);
                break;

        case MDS_DISCONNECT:
                CDEBUG(D_INODE, "disconnect\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                goto out;

        case MDS_GETSTATUS:
                CDEBUG(D_INODE, "getstatus\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETSTATUS_NET, 0);
                rc = mds_getstatus(req);
                break;

        case MDS_GETLOVINFO:
                CDEBUG(D_INODE, "getlovinfo\n");
                rc = mds_getlovinfo(req);
                break;

        case MDS_GETATTR:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_NET, 0);
                rc = mds_getattr(0, req);
                break;

        case MDS_STATFS:
                CDEBUG(D_INODE, "statfs\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_STATFS_NET, 0);
                rc = mds_statfs(req);
                break;

        case MDS_READPAGE:
                CDEBUG(D_INODE, "readpage\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_READPAGE_NET, 0);
                rc = mds_readpage(req);

                if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE))
                        return 0;
                break;

        case MDS_REINT: {
                int size = sizeof(struct mds_body);
                CDEBUG(D_INODE, "reint\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET, 0);

                rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        req->rq_status = rc;
                        break;
                }
                rc = mds_reint(0, req);
                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET_REP, 0);
                break;
                }

        case MDS_OPEN:
                CDEBUG(D_INODE, "open\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_OPEN_NET, 0);
                rc = mds_open(req);
                break;

        case MDS_CLOSE:
                CDEBUG(D_INODE, "close\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CLOSE_NET, 0);
                rc = mds_close(req);
                break;

        case LDLM_ENQUEUE:
                CDEBUG(D_INODE, "enqueue\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = ldlm_handle_enqueue(req);
                if (rc)
                        break;
                RETURN(0);

        case LDLM_CONVERT:
                CDEBUG(D_INODE, "convert\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CONVERT, 0);
                rc = ldlm_handle_convert(req);
                if (rc)
                        break;
                RETURN(0);

        case LDLM_CANCEL:
                CDEBUG(D_INODE, "cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CANCEL, 0);
                rc = ldlm_handle_cancel(req);
                if (rc)
                        break;
                RETURN(0);
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "callback\n");
                CERROR("callbacks should not happen on MDS\n");
                LBUG();
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;
        default:
                rc = ptlrpc_error(req->rq_svc, req);
                RETURN(rc);
        }

        EXIT;

        if (!rc) {
                struct mds_obd *mds = mds_req2mds(req);
                req->rq_repmsg->last_xid = HTON__u64(mds->mds_last_rcvd);
                req->rq_repmsg->last_committed =
                        HTON__u64(mds->mds_last_committed);
                CDEBUG(D_INFO, "last_rcvd %Lu, last_committed %Lu, xid %d\n",
                       (unsigned long long)mds->mds_last_rcvd,
                       (unsigned long long)mds->mds_last_committed,
                       cpu_to_le32(req->rq_xid));
        }
 out:
        /* Still not 100% sure whether we should reply with the server
         * last_rcvd or that of this client.  I'm not sure it even makes
         * a difference on a per-client basis, because last_rcvd is global
         * and we are not supposed to allow transactions while in recovery.
         */
        if (rc) {
                CERROR("mds: processing error %d\n", rc);
                ptlrpc_error(req->rq_svc, req);
        } else {
                CDEBUG(D_NET, "sending reply\n");
                ptlrpc_reply(req->rq_svc, req);
        }
        return 0;
}

/* Update the server data on disk.  This stores the new mount_count and
 * also the last_rcvd value to disk.  If we don't have a clean shutdown,
 * then the server last_rcvd value may be less than that of the clients.
 * This will alert us that we may need to do client recovery.
 *
 * Assumes we are already in the server filesystem context.
 */
static
int mds_update_server_data(struct mds_obd *mds)
{
        struct mds_server_data *msd = mds->mds_server_data;
        struct file *filp = mds->mds_rcvd_filp;
        loff_t off = 0;
        int rc;

        msd->msd_last_rcvd = cpu_to_le64(mds->mds_last_rcvd);
        msd->msd_mount_count = cpu_to_le64(mds->mds_mount_count);

        CDEBUG(D_SUPER, "MDS mount_count is %Lu, last_rcvd is %Lu\n",
               (unsigned long long)mds->mds_mount_count,
               (unsigned long long)mds->mds_last_rcvd);
        rc = lustre_fwrite(filp, (char *)msd, sizeof(*msd), &off);
        if (rc != sizeof(*msd)) {
                CERROR("error writing MDS server data: rc = %d\n", rc);
                if (rc > 0)
                        RETURN(-EIO);
                RETURN(rc);
        }
        rc = fsync_dev(filp->f_dentry->d_inode->i_rdev);
        if (rc)
                CERROR("error flushing MDS server data: rc = %d\n", rc);

        return 0;
}

/* Do recovery actions for the MDS */
static int mds_recover(struct obd_device *obddev)
{
        struct mds_obd *mds = &obddev->u.mds;
        struct obd_run_ctxt saved;
        int rc;

        /* This happens at the end when recovery is complete */
        ++mds->mds_mount_count;
        push_ctxt(&saved, &mds->mds_ctxt);
        rc = mds_update_server_data(mds);
        pop_ctxt(&saved);

        return rc;
}

#define MDS_NUM_THREADS 8
/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        int i;
        struct obd_ioctl_data* data = buf;
        struct mds_obd *mds = &obddev->u.mds;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;

        MOD_INC_USE_COUNT;
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2)
                GOTO(err_dec, rc = -EINVAL);

        mds->mds_fstype = strdup(data->ioc_inlbuf2);

        mnt = do_kern_mount(mds->mds_fstype, 0, data->ioc_inlbuf1, NULL);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(err_kfree, rc);
        }

        mds->mds_sb = mnt->mnt_root->d_inode->i_sb;
        if (!mds->mds_sb)
                GOTO(err_put, rc = -ENODEV);

        mds->mds_max_mdsize = sizeof(struct lov_mds_md);
        rc = mds_fs_setup(obddev, mnt);
        if (rc) {
                CERROR("MDS filesystem method init failed: rc = %d\n", rc);
                GOTO(err_put, rc);
        }

        mds->mds_service = ptlrpc_init_svc(64 * 1024, MDS_REQUEST_PORTAL,
                                           MDC_REPLY_PORTAL, "self",mds_handle, 
                                           "mds");
        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                GOTO(err_fs, rc = -EINVAL);
        }

        obddev->obd_namespace =
                ldlm_namespace_new("mds_server", LDLM_NAMESPACE_SERVER);
        if (obddev->obd_namespace == NULL) {
                mds_cleanup(obddev);
                GOTO(err_svc, rc = -ENOMEM);
        }

        for (i = 0; i < MDS_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "lustre_MDS_%02d", i);
                rc = ptlrpc_start_thread(obddev, mds->mds_service, name);
                if (rc) {
                        CERROR("cannot start MDS thread #%d: rc %d\n", i, rc);
                        GOTO(err_thread, rc);
                }
        }

        rc = mds_recover(obddev);
        if (rc)
                GOTO(err_thread, rc);
        
        mds_destroy_export = mds_client_free;

        RETURN(0);

err_thread:
        ptlrpc_stop_all_threads(mds->mds_service);
err_svc:
        ptlrpc_unregister_service(mds->mds_service);
err_fs:
        mds_fs_cleanup(obddev);
err_put:
        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        lock_kernel();
err_kfree:
        kfree(mds->mds_fstype);
err_dec:
        MOD_DEC_USE_COUNT;
        return rc;
}

static int mds_cleanup(struct obd_device *obddev)
{
        struct super_block *sb;
        struct mds_obd *mds = &obddev->u.mds;
        struct obd_run_ctxt saved;
        ENTRY;

        ptlrpc_stop_all_threads(mds->mds_service);
        ptlrpc_unregister_service(mds->mds_service);

        sb = mds->mds_sb;
        if (!mds->mds_sb)
                RETURN(0);

        push_ctxt(&saved, &mds->mds_ctxt);
        mds_update_server_data(mds);

        if (mds->mds_rcvd_filp) {
                int rc = filp_close(mds->mds_rcvd_filp, 0);
                mds->mds_rcvd_filp = NULL;

                if (rc)
                        CERROR("last_rcvd file won't close, rc=%d\n", rc);
        }
        pop_ctxt(&saved);

        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        kfree(mds->mds_fstype);

        ldlm_namespace_free(obddev->obd_namespace);

        lock_kernel();
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        mds_fs_cleanup(obddev);

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

static int ldlm_intent_policy(struct ldlm_lock *lock, void *req_cookie,
                              ldlm_mode_t mode, void *data)
{
        struct ptlrpc_request *req = req_cookie;
        int rc = 0;
        ENTRY;

        if (!req_cookie)
                RETURN(0);

        if (req->rq_reqmsg->bufcount > 1) {
                /* an intent needs to be considered */
                struct ldlm_intent *it = lustre_msg_buf(req->rq_reqmsg, 1);
                struct mds_obd *mds= &req->rq_export->exp_obd->u.mds;
                struct mds_body *mds_rep;
                struct ldlm_reply *rep;
                __u64 new_resid[3] = {0, 0, 0}, old_res;
                int rc, size[3] = {sizeof(struct ldlm_reply),
                                                  sizeof(struct mds_body),
                                                  mds->mds_max_mdsize};

                it->opc = NTOH__u64(it->opc);

                LDLM_DEBUG(lock, "intent policy, opc: %s",
                           ldlm_it2str(it->opc));

                rc = lustre_pack_msg(3, size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        rc = req->rq_status = -ENOMEM;
                        RETURN(rc);
                }

                rep = lustre_msg_buf(req->rq_repmsg, 0);
                rep->lock_policy_res1 = 1;

                /* execute policy */
                switch ((long)it->opc) {
                case IT_CREAT|IT_OPEN:
                        rc = mds_reint(2, req);
                        if (rc || (req->rq_status != 0 &&
                                   req->rq_status != -EEXIST)) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_CREAT:
                case IT_LINK:
                case IT_MKDIR:
                case IT_MKNOD:
                case IT_RENAME2:
                case IT_RMDIR:
                case IT_SYMLINK:
                case IT_UNLINK:
                        rc = mds_reint(2, req);
                        if (rc || (req->rq_status != 0 &&
                                   req->rq_status != -EISDIR &&
                                   req->rq_status != -ENOTDIR)) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_GETATTR:
                case IT_LOOKUP:
                case IT_OPEN:
                case IT_READDIR:
                case IT_READLINK:
                case IT_RENAME:
                case IT_SETATTR:
                        rc = mds_getattr_name(2, req);
                        /* FIXME: we need to sit down and decide on who should
                         * set req->rq_status, who should return negative and
                         * positive return values, and what they all mean. */
                        if (rc || req->rq_status != 0) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_READDIR|IT_OPEN:
                        LBUG();
                        break;
                default:
                        CERROR("Unhandled intent\n");
                        LBUG();
                }

                if (it->opc == IT_UNLINK || it->opc == IT_RMDIR ||
                    it->opc == IT_RENAME || it->opc == IT_RENAME2)
                        RETURN(ELDLM_LOCK_ABORTED);

                rep->lock_policy_res2 = req->rq_status;
                mds_rep = lustre_msg_buf(req->rq_repmsg, 1);

                /* If the client is about to open a file that doesn't have an MD
                 * stripe record, it's going to need a write lock. */
                if (it->opc & IT_OPEN) {
                        struct lov_mds_md *md =
                                lustre_msg_buf(req->rq_repmsg, 2);
                        if (md->lmd_easize == 0) {
                                LDLM_DEBUG(lock, "open with no EA; returning PW"
                                           " lock");
                                lock->l_req_mode = LCK_PW;
                        }
                }

                /* Give the client a lock on the child object, instead of the
                 * parent that it requested. */
                new_resid[0] = NTOH__u32(mds_rep->ino);
                if (new_resid[0] == 0)
                        LBUG();
                old_res = lock->l_resource->lr_name[0];

                ldlm_lock_change_resource(lock, new_resid);
                if (lock->l_resource == NULL) {
                        LBUG();
                        RETURN(-ENOMEM);
                }
                LDLM_DEBUG(lock, "intent policy, old res %ld",
                           (long)old_res);
                RETURN(ELDLM_LOCK_CHANGED);
        } else {
                int size = sizeof(struct ldlm_reply);
                rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        LBUG();
                        RETURN(-ENOMEM);
                }
        }
        RETURN(rc);
}


extern int mds_iocontrol(long cmd, struct lustre_handle *conn,
                         int len, void *karg, void *uarg);

/* use obd ops to offer management infrastructure */
static struct obd_ops mds_obd_ops = {
        o_connect:     mds_connect,
        o_disconnect:  mds_disconnect,
        o_setup:       mds_setup,
        o_cleanup:     mds_cleanup,
        o_iocontrol:   mds_iocontrol
};

static int __init mds_init(void)
{
        class_register_type(&mds_obd_ops, LUSTRE_MDS_NAME);
        ldlm_register_intent(ldlm_intent_policy);
        return 0;
}

static void __exit mds_exit(void)
{
        ldlm_unregister_intent();
        class_unregister_type(LUSTRE_MDS_NAME);
}

MODULE_AUTHOR("Cluster File Systems <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS) v0.01");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
