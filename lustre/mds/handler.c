/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/handler.c
 *
 *  Lustre Metadata Server (mds) request handler
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com> &
 *     Andreas Dilger <braam@clusterfs.com>
 *
 *  This server is single threaded at present (but can easily be multi threaded)
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
extern int mds_get_lovtgts(struct obd_device *obd, uuid_t *uuidarray);
extern int mds_get_lovdesc(struct obd_device *obd, struct lov_desc *desc);
extern int mds_update_last_rcvd(struct mds_obd *mds, void *handle,
                                struct ptlrpc_request *req);
static int mds_cleanup(struct obd_device * obddev);

inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req)
{
        return &req->rq_export->export_obd->u.mds;
}

/* Assumes caller has already pushed into the kernel filesystem context */
static int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                        __u64 offset)
{
        int rc = 0;
        struct mds_obd *mds = mds_req2mds(req); 
        struct ptlrpc_bulk_desc *desc;
        struct ptlrpc_bulk_page *bulk;
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

        wait_event_interruptible(desc->b_waitq, ptlrpc_check_bulk_sent(desc));
        if (desc->b_flags & PTL_RPC_FL_INTR)
                GOTO(cleanup_buf, rc = -EINTR);

        EXIT;
 cleanup_buf:
        OBD_FREE(buf, PAGE_SIZE);
 cleanup_bulk:
        ptlrpc_free_bulk(desc);
 out:
        return rc;
}

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

        /* now to find a dentry.
         * If possible, get a well-connected one
         */
        if (mnt)
                *mnt = mds->mds_vfsmnt;
        spin_lock(&dcache_lock);
        for (lp = inode->i_dentry.next; lp != &inode->i_dentry ; lp=lp->next) {
                result = list_entry(lp,struct dentry, d_alias);
                if (! (result->d_flags & DCACHE_NFSD_DISCONNECTED)) {
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

static int mds_connect(struct lustre_handle *conn, struct obd_device *obd)
{
        int rc;

        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd);

        if (rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

static int mds_disconnect(struct lustre_handle *conn)
{
        int rc;

        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

/* FIXME: the error cases need fixing to avoid leaks */
static int mds_getstatus(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        struct mds_client_info *mci;
        struct mds_client_data *mcd;
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

        mci = mds_uuid_to_mci(mds, ptlrpc_req_to_uuid(req));
        if (!mci) {
                /* We don't have any old connection data for this client */
                int rc;

                CDEBUG(D_INFO, "allocating new client data for UUID '%s'",
                       ptlrpc_req_to_uuid(req));

                OBD_ALLOC(mcd, sizeof(*mcd));
                if (!mcd) {
                        CERROR("mds: out of memory for client data\n");
                        req->rq_status = -ENOMEM;
                        RETURN(0);
                }
                memcpy(mcd->mcd_uuid, ptlrpc_req_to_uuid(req),
                       sizeof(mcd->mcd_uuid));
                rc = mds_client_add(mds, mcd, -1);
                if (rc) {
                        req->rq_status = rc;
                        RETURN(0);
                }
        } else {
                /* We have old connection data for this client... */
                mcd = mci->mci_mcd;
                CDEBUG(D_INFO, "found existing data for UUID '%s' at #%d\n",
                       mcd->mcd_uuid, mci->mci_off);
        }
        /* mcd_last_xid is is stored in little endian on the disk and
           mds_pack_rep_body converts it to network order */
        body->last_xid = le32_to_cpu(mcd->mcd_last_xid);
        mds_pack_rep_body(req);
        RETURN(0);
}

static int mds_lovinfo(struct ptlrpc_request *req)
{
        struct mds_status_req *streq;
        struct lov_desc *desc; 
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
                CERROR("get_lovdesc error %d", rc);
                req->rq_status = rc;
                RETURN(0);
        }

        if (desc->ld_tgt_count * sizeof(uuid_t) > streq->repbuf) { 
                CERROR("too many targets, enlarge client buffers\n");
                req->rq_status = -ENOSPC;
                RETURN(0);
        }

        rc = mds_get_lovtgts(req->rq_obd, lustre_msg_buf(req->rq_repmsg, 1));
        if (rc) { 
                CERROR("get_lovtgts error %d", rc);
                req->rq_status = rc;
                RETURN(0);
        }
        RETURN(0);
}

int mds_lock_callback(struct lustre_handle *lockh, struct ldlm_lock_desc *desc,
                      void *data, int data_len, struct ptlrpc_request **reqp)
{
        ENTRY;

        if (desc == NULL) {
                /* Completion AST.  Do nothing */
                RETURN(0);
        }

        if (ldlm_cli_cancel(lockh, NULL) < 0)
                LBUG();
        RETURN(0);
}

static int mds_getattr_name(int offset, struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_run_ctxt saved;
        struct mds_body *body;
        struct dentry *de = NULL, *dchild = NULL;
        struct inode *dir;
        struct lustre_handle lockh;
        char *name;
        int namelen, flags, lock_mode, rc = 0;
        __u64 res_id[3] = {0, 0, 0};
        ENTRY;

        if (strcmp(req->rq_export->export_obd->obd_type->typ_name, "mds") != 0)
                LBUG();

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
        CDEBUG(D_INODE, "parent ino %ld\n", dir->i_ino);

        lock_mode = (req->rq_reqmsg->opc == MDS_REINT) ? LCK_CW : LCK_PW;
        res_id[0] = dir->i_ino;

        rc = ldlm_lock_match(mds->mds_local_namespace, res_id, LDLM_PLAIN,
                             NULL, 0, lock_mode, &lockh);
        if (rc == 0) {
                LDLM_DEBUG_NOLOCK("enqueue res %Lu", res_id[0]);
                rc = ldlm_cli_enqueue(mds->mds_ldlm_client, mds->mds_ldlm_conn,
                                      (struct lustre_handle *)&mds->mds_connh, 
                                      NULL, mds->mds_local_namespace, NULL,
                                      res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                      &flags, (void *)mds_lock_callback,
                                      NULL, 0, &lockh);
                if (rc != ELDLM_OK) {
                        CERROR("lock enqueue: err: %d\n", rc);
                        GOTO(out_create_de, rc = -EIO);
                }
        }
        ldlm_lock_dump((void *)(unsigned long)lockh.addr);

        down(&dir->i_sem);
        dchild = lookup_one_len(name, de, namelen - 1);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                up(&dir->i_sem);
                LBUG();
                GOTO(out_create_dchild, rc = -ESTALE);
        }

        if (dchild->d_inode) {
                struct mds_body *body;
                struct obdo *obdo;
                struct inode *inode = dchild->d_inode;
                CERROR("child exists (dir %ld, name %s, ino %ld)\n",
                       dir->i_ino, name, dchild->d_inode->i_ino);

                body = lustre_msg_buf(req->rq_repmsg, offset);
                mds_pack_inode2fid(&body->fid1, inode);
                mds_pack_inode2body(body, inode);
                if (S_ISREG(inode->i_mode)) {
                        obdo = lustre_msg_buf(req->rq_repmsg, offset + 1);
                        mds_fs_get_obdo(mds, inode, obdo);
                }
                /* now a normal case for intent locking */
                rc = 0;
        } else {
                rc = -ENOENT;
        }

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
        int rc, size[2] = {sizeof(*body)}, bufcount = 1;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, offset);
        push_ctxt(&saved, &mds->mds_ctxt);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                GOTO(out_pop, rc = -ENOENT);
        }

        inode = de->d_inode;
        if (S_ISREG(body->fid1.f_type)) {
                bufcount = 2;
                size[1] = sizeof(struct obdo);
        } else if (body->valid & OBD_MD_LINKNAME) {
                bufcount = 2;
                size[1] = inode->i_size;
        }

        rc = lustre_pack_msg(bufcount, size, NULL, &req->rq_replen,
                             &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("mds: out of memory\n");
                GOTO(out, rc);
        }

        if (body->valid & OBD_MD_LINKNAME) {
                char *tmp = lustre_msg_buf(req->rq_repmsg, 1);

                rc = inode->i_op->readlink(de, tmp, size[1]);

                if (rc < 0) {
                        CERROR("readlink failed: %d\n", rc);
                        GOTO(out, rc);
                }
        }

        body = lustre_msg_buf(req->rq_repmsg, 0);
        body->ino = inode->i_ino;
        body->generation = inode->i_generation;
        body->atime = inode->i_atime;
        body->ctime = inode->i_ctime;
        body->mtime = inode->i_mtime;
        body->uid = inode->i_uid;
        body->gid = inode->i_gid;
        body->size = inode->i_size;
        body->mode = inode->i_mode;
        body->nlink = inode->i_nlink;
        body->valid = ~0; /* FIXME: should be more selective */

        if (S_ISREG(inode->i_mode)) {
                rc = mds_fs_get_obdo(mds, inode,
                                     lustre_msg_buf(req->rq_repmsg, 1));
                if (rc < 0) {
                        CERROR("mds_fs_get_obdo failed: %d\n", rc);
                        GOTO(out, rc);
                }
        }
out:
        l_dput(de);
out_pop:
        pop_ctxt(&saved);
        req->rq_status = rc;
        RETURN(0);
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
        struct mds_client_info *mci;
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

        mci = mds_uuid_to_mci(mds, ptlrpc_req_to_uuid(req));
        if (!mci) {
                CERROR("mds: no mci!\n");
                req->rq_status = -ENOTCONN;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        /* was this animal open already? */
        /* XXX we should only check on re-open, or do a refcount... */
        list_for_each(tmp, &mci->mci_open_head) {
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
                struct inode *inode = de->d_inode;
                //struct iattr iattr;
                struct obdo *obdo;
                int rc;

                obdo = lustre_msg_buf(req->rq_reqmsg, 1);
                //iattr.ia_valid = ATTR_MODE;
                //iattr.ia_mode = inode->i_mode;

                handle = mds_fs_start(mds, de->d_inode, MDS_FSOP_SETATTR);
                if (!handle) {
                        req->rq_status = -ENOMEM;
                        RETURN(0);
                }

                /* XXX error handling */
                rc = mds_fs_set_obdo(mds, inode, handle, obdo);
                //                rc = mds_fs_setattr(mds, de, handle, &iattr);
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
        list_add(&mfd->mfd_list, &mci->mci_open_head);

        body = lustre_msg_buf(req->rq_repmsg, 0);
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

        if (req->rq_reqmsg->opc != MDS_CONNECT &&
            req->rq_export == NULL)
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

        case MDS_LOVINFO:
                CDEBUG(D_INODE, "lovinfo\n");
                rc = mds_lovinfo(req);
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
                        rc = req->rq_status = -ENOMEM;
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

        default:
                rc = ptlrpc_error(req->rq_svc, req);
                RETURN(rc);
        }

        EXIT;

        if (!rc) { 
                struct mds_obd *mds = mds_req2mds(req);
                req->rq_repmsg->last_rcvd = HTON__u64(mds->mds_last_rcvd);
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
 */
static
int mds_update_server_data(struct mds_obd *mds)
{
        struct obd_run_ctxt saved;
        struct mds_server_data *msd = mds->mds_server_data;
        struct file *filp = mds->mds_rcvd_filp;
        loff_t off = 0;
        int rc;

        msd->msd_last_rcvd = cpu_to_le64(mds->mds_last_rcvd);
        msd->msd_mount_count = cpu_to_le64(mds->mds_mount_count);

        CDEBUG(D_SUPER, "MDS mount_count is %Lu, last_rcvd is %Lu\n",
               (unsigned long long)mds->mds_mount_count,
               (unsigned long long)mds->mds_last_rcvd);
        push_ctxt(&saved, &mds->mds_ctxt);
        rc = lustre_fwrite(filp, (char *)msd, sizeof(*msd), &off);
        if (rc != sizeof(*msd)) {
                CERROR("error writing MDS server data: rc = %d\n", rc);
                if (rc > 0)
                        RETURN(-EIO);
                RETURN(rc);
        }
        rc = fsync_dev(filp->f_dentry->d_inode->i_rdev);
        pop_ctxt(&saved);
        if (rc)
                CERROR("error flushing MDS server data: rc = %d\n", rc);

        return 0;
}

/* Do recovery actions for the MDS */
static int mds_recover(struct obd_device *obddev)
{
        struct mds_obd *mds = &obddev->u.mds;
        int rc;

        /* This happens at the end when recovery is complete */
        ++mds->mds_mount_count;
        rc = mds_update_server_data(mds);

        return rc;
}


/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct obd_export *export;
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

        rc = mds_fs_setup(mds, mnt);
        if (rc) {
                CERROR("MDS filesystem method init failed: rc = %d\n", rc);
                GOTO(err_put, rc);
        }

        mds->mds_service = ptlrpc_init_svc(64 * 1024, MDS_REQUEST_PORTAL,
                                           MDC_REPLY_PORTAL, "self",mds_handle);
        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                GOTO(err_fs, rc = -EINVAL);
        }

        rc = ptlrpc_start_thread(obddev, mds->mds_service, "lustre_mds");
        if (rc) {
                CERROR("cannot start thread: rc = %d\n", rc);
                GOTO(err_svc, rc);
        }

        rc = -ENOENT;
        mds->mds_ldlm_conn = ptlrpc_uuid_to_connection("self");
        if (!mds->mds_ldlm_conn) {
                mds_cleanup(obddev);
                GOTO(err_thread, rc);
        }

        obddev->obd_namespace =
                ldlm_namespace_new("mds_server", LDLM_NAMESPACE_SERVER);
        if (obddev->obd_namespace == NULL) {
                LBUG();
                mds_cleanup(obddev);
                GOTO(err_thread, rc);
        }

        mds->mds_local_namespace =
                ldlm_namespace_new("mds_client", LDLM_NAMESPACE_CLIENT);
        if (mds->mds_local_namespace == NULL) {
                LBUG();
                mds_cleanup(obddev);
                GOTO(err_thread, rc);
        }

        OBD_ALLOC(mds->mds_ldlm_client, sizeof(*mds->mds_ldlm_client));
        if (mds->mds_ldlm_client == NULL) {
                LBUG();
                mds_cleanup(obddev);
                GOTO(err_thread, rc);
        }
        ptlrpc_init_client(NULL, NULL, LDLM_REQUEST_PORTAL, LDLM_REPLY_PORTAL,
                           mds->mds_ldlm_client);
        mds->mds_ldlm_client->cli_target_devno = obddev->obd_minor;
        mds->mds_ldlm_client->cli_name = "mds ldlm";

        rc = mds_recover(obddev);
        if (rc)
                GOTO(err_thread, rc);

        rc = class_connect(&mds->mds_connh, obddev);
        if (rc)
                GOTO(err_thread, rc);
        export = class_conn2export(&mds->mds_connh);
        if (!export)
                LBUG();
        export->export_connection = mds->mds_ldlm_conn;

        RETURN(0);

        

err_thread:
        ptlrpc_stop_all_threads(mds->mds_service);
err_svc:
        ptlrpc_unregister_service(mds->mds_service);
err_fs:
        mds_fs_cleanup(mds);
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

static int mds_cleanup(struct obd_device * obddev)
{
        struct super_block *sb;
        struct mds_obd *mds = &obddev->u.mds;

        ENTRY;
        class_disconnect(&mds->mds_connh);


        if ( !list_empty(&obddev->obd_exports) ) {
                CERROR("still has exports!\n");
                RETURN(-EBUSY);
        }

        ptlrpc_stop_all_threads(mds->mds_service);
        ptlrpc_unregister_service(mds->mds_service);

        sb = mds->mds_sb;
        if (!mds->mds_sb)
                RETURN(0);

        mds_update_server_data(mds);

        if (mds->mds_rcvd_filp) {
                int rc = filp_close(mds->mds_rcvd_filp, 0);
                mds->mds_rcvd_filp = NULL;

                if (rc)
                        CERROR("last_rcvd file won't close, rc=%d\n", rc);
        }

        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        kfree(mds->mds_fstype);

        ldlm_namespace_free(mds->mds_local_namespace);
        ldlm_namespace_free(obddev->obd_namespace);

        if (mds->mds_ldlm_conn != NULL)
                ptlrpc_put_connection(mds->mds_ldlm_conn);

        OBD_FREE(mds->mds_ldlm_client, sizeof(*mds->mds_ldlm_client));

        lock_kernel();
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        mds_fs_cleanup(mds);

        MOD_DEC_USE_COUNT;
        RETURN(0);
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
        inter_module_register("mds_reint", THIS_MODULE, &mds_reint);
        inter_module_register("mds_getattr_name", THIS_MODULE,
                              &mds_getattr_name);
        class_register_type(&mds_obd_ops, LUSTRE_MDS_NAME);
        return 0;
}

static void __exit mds_exit(void)
{
        inter_module_unregister("mds_reint");
        inter_module_unregister("mds_getattr_name");
        class_unregister_type(LUSTRE_MDS_NAME);
}

MODULE_AUTHOR("Cluster File Systems <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS) v0.01");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
