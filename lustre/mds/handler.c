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
 *  by Peter Braam <braam@clusterfs.com>
 *
 *  This server is single threaded at present (but can easily be multi threaded)
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>

static int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                        __u64 offset)
{
        int rc = 0;
        mm_segment_t oldfs = get_fs();
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

        set_fs(KERNEL_DS);
        rc = mds_fs_readpage(&req->rq_obd->u.mds, file, buf, PAGE_SIZE,
                             (loff_t *)&offset);
        set_fs(oldfs);

        if (rc != PAGE_SIZE)
                GOTO(cleanup_buf, rc = -EIO);

        bulk->b_xid = req->rq_reqmsg->xid;
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

static
int mds_connect(struct ptlrpc_request *req)
{
        struct mds_body *body;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        struct mds_client_info *mci;
        struct mds_client_data *mcd;
        int rc, size = sizeof(*body);
        ENTRY;

        CDEBUG(D_INFO, "MDS connect from UUID '%s'\n", ptlrpc_req_to_uuid(req));
        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_CONNECT_PACK)) {
                CERROR("mds: out of memory for message: size=%d\n", size);
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_unpack_req_body(req);
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

static int mds_getattr(struct ptlrpc_request *req)
{
        struct dentry *de;
        struct inode *inode;
        struct mds_body *body;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        int rc, size[2] = {sizeof(*body)}, bufcount = 1;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                req->rq_status = -ENOENT;
                RETURN(0);
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
                req->rq_status = -ENOMEM;
                GOTO(out, 0);
        }

        if (body->valid & OBD_MD_LINKNAME) {
                char *tmp = lustre_msg_buf(req->rq_repmsg, 1);
                mm_segment_t oldfs;

                oldfs = get_fs();
                set_fs(KERNEL_DS);
                rc = inode->i_op->readlink(de, tmp, size[1]);
                set_fs(oldfs);

                if (rc < 0) {
                        req->rq_status = rc;
                        CERROR("readlink failed: %d\n", rc);
                        GOTO(out, 0);
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
                        req->rq_status = rc;
                        CERROR("mds_fs_get_objid failed: %d\n", rc);
                        GOTO(out, 0);
                }
        }
 out:
        l_dput(de);
        RETURN(0);
}

static
int mds_open(struct ptlrpc_request *req)
{
        struct mds_obd *mds = &req->rq_obd->u.mds;
        struct dentry *de;
        struct mds_body *body;
        struct file *file;
        struct vfsmount *mnt;
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

static
int mds_close(struct ptlrpc_request *req)
{
        struct dentry *de;
        struct mds_body *body;
        struct file *file;
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
        de = mds_fid2dentry(&req->rq_obd->u.mds, &body->fid1, &mnt);
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

int mds_readpage(struct ptlrpc_request *req)
{
        struct vfsmount *mnt;
        struct dentry *de;
        struct file *file;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK)) {
                CERROR("mds: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        de = mds_fid2dentry(&req->rq_obd->u.mds, &body->fid1, &mnt);
        if (IS_ERR(de)) {
                req->rq_status = PTR_ERR(de);
                RETURN(0);
        }

        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

        file = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE);
        /* note: in case of an error, dentry_open puts dentry */
        if (IS_ERR(file)) {
                req->rq_status = PTR_ERR(file);
                RETURN(0);
        }

        /* to make this asynchronous make sure that the handling function
           doesn't send a reply when this function completes. Instead a
           callback function would send the reply */
        rc = mds_sendpage(req, file, body->size);

        filp_close(file, 0);
        req->rq_status = rc;
        RETURN(0);
}

int mds_reint(struct ptlrpc_request *req)
{
        int rc;
        struct mds_update_record rec;

        rc = mds_update_unpack(req, &rec);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK)) {
                CERROR("invalid record\n");
                req->rq_status = -EINVAL;
                RETURN(0);
        }
        /* rc will be used to interrupt a for loop over multiple records */
        rc = mds_reint_rec(&rec, req);
        return 0;
}

int mds_handle(struct obd_device *dev, struct ptlrpc_service *svc,
               struct ptlrpc_request *req)
{
        struct mds_obd *mds = &req->rq_obd->u.mds;
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

        switch (req->rq_reqmsg->opc) {
        case MDS_CONNECT:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CONNECT_NET, 0);
                rc = mds_connect(req);
                break;

        case MDS_GETATTR:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_NET, 0);
                rc = mds_getattr(req);
                break;

        case MDS_READPAGE:
                CDEBUG(D_INODE, "readpage\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_READPAGE_NET, 0);
                rc = mds_readpage(req);

                if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE))
                        return 0;
                break;

        case MDS_REINT:
                CDEBUG(D_INODE, "reint\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET, 0);
                rc = mds_reint(req);
                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET_REP, 0);
                break;

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
                rc = ptlrpc_error(svc, req);
                RETURN(rc);
        }

        EXIT;
out:
        /* Still not 100% sure whether we should reply with the server
         * last_rcvd or that of this client.  I'm not sure it even makes
         * a difference on a per-client basis, because last_rcvd is global
         * and we are not supposed to allow transactions while in recovery.
         */
        req->rq_repmsg->last_rcvd = HTON__u64(mds->mds_last_rcvd);
        req->rq_repmsg->last_committed = HTON__u64(mds->mds_last_committed);
        CDEBUG(D_INFO, "last_rcvd %Lu, last_committed %Lu, xid %d\n",
               (unsigned long long)mds->mds_last_rcvd,
               (unsigned long long)mds->mds_last_committed, 
               cpu_to_le32(req->rq_reqmsg->xid));
        if (rc) {
                ptlrpc_error(svc, req);
        } else {
                CDEBUG(D_NET, "sending reply\n");
                ptlrpc_reply(svc, req);
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

        mds->mds_service = ptlrpc_init_svc(128 * 1024,
                                           MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,                                           "self", mds_handle);
        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                GOTO(err_fs, rc = -EINVAL);
        }

        rc = ptlrpc_start_thread(obddev, mds->mds_service, "lustre_mds");
        if (rc) {
                CERROR("cannot start thread: rc = %d\n", rc);
                GOTO(err_svc, rc);
        }

        rc = mds_recover(obddev);
        if (rc)
                GOTO(err_thread, rc);

        RETURN(0);

err_thread:
        ptlrpc_stop_all_threads(mds->mds_service);
err_svc:
        rpc_unregister_service(mds->mds_service);
        OBD_FREE(mds->mds_service, sizeof(*mds->mds_service));
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

        if ( !list_empty(&obddev->obd_gen_clients) ) {
                CERROR("still has clients!\n");
                RETURN(-EBUSY);
        }

        ptlrpc_stop_all_threads(mds->mds_service);
        rpc_unregister_service(mds->mds_service);
        if (!list_empty(&mds->mds_service->srv_reqs)) {
                // XXX reply with errors and clean up
                CERROR("Request list not empty!\n");
        }
        OBD_FREE(mds->mds_service, sizeof(*mds->mds_service));

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
        lock_kernel();
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        mds_fs_cleanup(mds);

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

/* use obd ops to offer management infrastructure */
static struct obd_ops mds_obd_ops = {
        o_setup:       mds_setup,
        o_cleanup:     mds_cleanup,
};

static int __init mds_init(void)
{
        obd_register_type(&mds_obd_ops, LUSTRE_MDS_NAME);
        return 0;
}

static void __exit mds_exit(void)
{
        obd_unregister_type(LUSTRE_MDS_NAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS) v0.01");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
