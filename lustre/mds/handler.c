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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/lustre_mds.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>

int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                 __u64 offset, struct niobuf *dst)
{
        int rc = 0;
        mm_segment_t oldfs = get_fs();
        struct ptlrpc_bulk_desc *bulk;
        char *buf;

        bulk = ptlrpc_prep_bulk(req->rq_connection);
        if (bulk == NULL) {
                rc = -ENOMEM;
                GOTO(out, rc);
        }

        bulk->b_xid = req->rq_reqmsg->xid;

        OBD_ALLOC(buf, PAGE_SIZE);
        if (!buf) {
                rc = -ENOMEM;
                GOTO(cleanup_bulk, rc);
        }

        set_fs(KERNEL_DS);
        rc = mds_fs_readpage(&req->rq_obd->u.mds, file, buf, PAGE_SIZE,
                             (loff_t *)&offset);
        set_fs(oldfs);

        if (rc != PAGE_SIZE) {
                rc = -EIO;
                GOTO(cleanup_buf, rc);
        }

        bulk->b_buf = buf;
        bulk->b_buflen = PAGE_SIZE;

        rc = ptlrpc_send_bulk(bulk, MDS_BULK_PORTAL);
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
                CERROR("obd_fail_loc=%x, fail operation rc=%d\n",
                       OBD_FAIL_MDS_SENDPAGE, rc);
                PtlMDUnlink(bulk->b_md_h);
                GOTO(cleanup_buf, rc);
        }
        wait_event_interruptible(bulk->b_waitq,
                                 ptlrpc_check_bulk_sent(bulk));

        if (bulk->b_flags & PTL_RPC_FL_INTR) {
                rc = -EINTR;
                GOTO(cleanup_buf, rc);
        }

        EXIT;
 cleanup_buf:
        OBD_FREE(buf, PAGE_SIZE);
 cleanup_bulk:
        ptlrpc_free_bulk(bulk);
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
                return ERR_PTR(-ESTALE);

        inode = iget(sb, ino);
        if (inode == NULL)
                return ERR_PTR(-ENOMEM);

        CDEBUG(D_DENTRY, "--> mds_fid2dentry: sb %p\n", inode->i_sb);

        if (is_bad_inode(inode) ||
            (generation && inode->i_generation != generation)) {
                /* we didn't find the right inode.. */
                CERROR("bad inode %lu, link: %d ct: %d or version  %u/%u\n",
                        inode->i_ino,
                        inode->i_nlink, atomic_read(&inode->i_count),
                        inode->i_generation,
                        generation);
                LBUG();
                iput(inode);
                return ERR_PTR(-ESTALE);
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

int mds_connect(struct ptlrpc_request *req)
{
        struct mds_body *body;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_CONNECT_PACK)) {
                CERROR("mds: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_unpack_req_body(req); 
        /* Anything we need to do here with the client's trans no or so? */

        body = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&body->fid1, &mds->mds_rootfid  , sizeof(body->fid1)); 
        mds_pack_rep_body(req);
        RETURN(0);
}

int mds_getattr(struct ptlrpc_request *req)
{
        struct dentry *de;
        struct inode *inode;
        struct mds_body *body;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("mds: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                req->rq_status = -ENOENT;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_repmsg, 0);
        inode = de->d_inode;
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
        body->valid = ~0;
        mds_fs_get_objid(mds, inode, &body->objid);
        l_dput(de);
        RETURN(0);
}

int mds_open(struct ptlrpc_request *req)
{
        struct dentry *de;
        struct mds_body *body;
        struct file *file;
        struct vfsmount *mnt;
        __u32 flags;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
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
        flags = body->flags;
        file = dentry_open(de, mnt, flags);
        if (!file || IS_ERR(file)) {
                req->rq_status = -EINVAL;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_repmsg, 0);
        body->objid = (__u64) (unsigned long)file;
        RETURN(0);
}

int mds_close(struct ptlrpc_request *req)
{
        struct dentry *de;
        struct mds_body *body;
        struct file *file;
        struct vfsmount *mnt;
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

        file = (struct file *)(unsigned long)body->objid;
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
        struct niobuf *niobuf;
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

        niobuf = lustre_msg_buf(req->rq_reqmsg, 1);
        if (!niobuf) {
                req->rq_status = -EINVAL;
                LBUG();
                RETURN(0);
        }

        /* to make this asynchronous make sure that the handling function
           doesn't send a reply when this function completes. Instead a
           callback function would send the reply */
        rc = mds_sendpage(req, file, body->size, niobuf);

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
        if (rc) {
                ptlrpc_error(svc, req);
        } else {
                CDEBUG(D_NET, "sending reply\n");
                ptlrpc_reply(svc, req);
        }

        return 0;
}

static int mds_prep(struct obd_device *obddev)
{
        struct obd_run_ctxt saved;
        struct mds_obd *mds = &obddev->u.mds;
        struct super_operations *s_ops;
        struct file *f;
        loff_t off = 0;
        __u64 mount_count;
        int rc;

        mds->mds_service = ptlrpc_init_svc(128 * 1024,
                                           MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                                           "self", mds_handle);

        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                RETURN(-EINVAL);
        }

        rc = ptlrpc_start_thread(obddev, mds->mds_service, "lustre_mds");
        if (rc) {
                CERROR("cannot start thread\n");
                GOTO(err_svc, rc);
        }

        push_ctxt(&saved, &mds->mds_ctxt);
        rc = simple_mkdir(current->fs->pwd, "ROOT", 0700);
        if (rc && rc != -EEXIST) {
                CERROR("cannot create ROOT directory\n");
                GOTO(err_svc, rc);
        }
        f = filp_open("ROOT", O_RDONLY, 0); 
        if (!f || IS_ERR(f)) { 
                CERROR("cannot open ROOT\n"); 
                LBUG();
        }
        
        mds->mds_rootfid.id = f->f_dentry->d_inode->i_ino;
        mds->mds_rootfid.generation = f->f_dentry->d_inode->i_generation;
        mds->mds_rootfid.f_type = S_IFDIR;

        rc = filp_close(f, 0);
        if (rc) { 
                CERROR("cannot close ROOT\n"); 
                LBUG();
        }

        rc = simple_mkdir(current->fs->pwd, "FH", 0700);
        if (rc && rc != -EEXIST) {
                CERROR("cannot create FH directory\n");
                GOTO(err_svc, rc);
        }

        f = filp_open("mount_count", O_RDWR | O_CREAT, 0644);
        if (IS_ERR(f)) {
                CERROR("cannot open/create mount_count file, rc = %ld\n",
                       PTR_ERR(f));
                GOTO(err_svc, rc = PTR_ERR(f));
        }
        rc = lustre_fread(f, (char *)&mount_count, sizeof(mount_count), &off);
        if (rc == 0) {
                CERROR("empty MDS mount_count, new MDS?\n");
                /* XXX maybe this should just be a random number? */
                mds->mds_mount_count = 0;
        } else if (rc != sizeof(mount_count)) {
                CERROR("error reading mount_count: rc = %d\n", rc);
                /* XXX maybe this should just be a random number? */
                mds->mds_mount_count = 0;
        } else {
                mds->mds_mount_count = le64_to_cpu(mount_count);
        }

        mds->mds_mount_count++;
        CDEBUG(D_SUPER, "MDS mount_count is %Ld\n",
               (unsigned long long)mds->mds_mount_count);
        off = 0;
        mount_count = cpu_to_le64(mds->mds_mount_count);
        rc = lustre_fwrite(f, (char *)&mount_count, sizeof(mount_count), &off);
        if (rc != sizeof(mount_count))
                CERROR("error writing mount_count: rc = %d\n", rc);
        rc = filp_close(f, 0);
        if (rc)
                CERROR("error closing mount_count: rc = %d\n", rc);

        f = filp_open("last_rcvd", O_RDWR | O_CREAT, 0644);
        if (IS_ERR(f)) {
                CERROR("cannot open/create last_rcvd file\n");
                GOTO(err_svc, rc = PTR_ERR(f));
        }
        mds->mds_last_rcvd = f;
        pop_ctxt(&saved);

        /*
         * Replace the client filesystem delete_inode method with our own,
         * so that we can clear the object ID before the inode is deleted.
         * The fs_delete_inode method will call cl_delete_inode for us.
         *
         * We need to do this for the MDS superblock only, hence we install
         * a modified copy of the original superblock method table.
         *
         * We still assume that there is only a single MDS client filesystem
         * type, as we don't have access to the mds struct in * delete_inode.
         */
        OBD_ALLOC(s_ops, sizeof(*s_ops));
        memcpy(s_ops, mds->mds_sb->s_op, sizeof(*s_ops));
        mds->mds_fsops->cl_delete_inode = s_ops->delete_inode;
        s_ops->delete_inode = mds->mds_fsops->fs_delete_inode;
        mds->mds_sb->s_op = s_ops;

        RETURN(0);

err_svc:
        rpc_unregister_service(mds->mds_service);
        OBD_FREE(mds->mds_service, sizeof(*mds->mds_service));

        return rc;
}

/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct mds_obd *mds = &obddev->u.mds;
        struct vfsmount *mnt;
        int err = 0;
        ENTRY;

#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2)
                RETURN(-EINVAL);

        mds->mds_fstype = strdup(data->ioc_inlbuf2);

        if (!strcmp(mds->mds_fstype, "ext3"))
                mds->mds_fsops = &mds_ext3_fs_ops;
        else if (!strcmp(mds->mds_fstype, "ext2"))
                mds->mds_fsops = &mds_ext2_fs_ops;
        else {
                CERROR("unsupported MDS filesystem type %s\n", mds->mds_fstype);
                GOTO(err_kfree, (err = -EPERM));
        }

        MOD_INC_USE_COUNT;
        mnt = do_kern_mount(mds->mds_fstype, 0, data->ioc_inlbuf1, NULL);
        if (IS_ERR(mnt)) {
                CERROR("do_kern_mount failed: %d\n", err);
                GOTO(err_dec, err = PTR_ERR(mnt));
        }

        mds->mds_sb = mnt->mnt_root->d_inode->i_sb;
        if (!mds->mds_sb)
                GOTO(err_put, (err = -ENODEV));

        mds->mds_vfsmnt = mnt;
        mds->mds_ctxt.pwdmnt = mnt;
        mds->mds_ctxt.pwd = mnt->mnt_root;
        mds->mds_ctxt.fs = KERNEL_DS;

        err = mds_prep(obddev);
        if (err)
                GOTO(err_put, err);

        RETURN(0);

err_put:
        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        lock_kernel();
err_dec:
        MOD_DEC_USE_COUNT;
err_kfree:
        kfree(mds->mds_fstype);
        return err;
}

static int mds_cleanup(struct obd_device * obddev)
{
        struct super_operations *s_ops = NULL;
        struct super_block *sb;
        struct mds_obd *mds = &obddev->u.mds;

        ENTRY;

        if ( !list_empty(&obddev->obd_gen_clients) ) {
                CERROR("still has clients!\n");
                RETURN(-EBUSY);
        }

        ptlrpc_stop_thread(mds->mds_service);
        rpc_unregister_service(mds->mds_service);
        if (!list_empty(&mds->mds_service->srv_reqs)) {
                // XXX reply with errors and clean up
                CERROR("Request list not empty!\n");
        }
        OBD_FREE(mds->mds_service, sizeof(*mds->mds_service));

        sb = mds->mds_sb;
        if (!mds->mds_sb)
                RETURN(0);

        if (mds->mds_last_rcvd) {
                int rc = filp_close(mds->mds_last_rcvd, 0);
                mds->mds_last_rcvd = NULL;

                if (rc)
                        CERROR("last_rcvd file won't close, rc=%d\n", rc);
        }
        s_ops = sb->s_op;

        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        kfree(mds->mds_fstype);
        lock_kernel();
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        OBD_FREE(s_ops, sizeof(*s_ops));

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
