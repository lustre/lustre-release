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

int mds_sendpage(struct ptlrpc_request *req, struct file *file, __u64 offset)
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
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
                CERROR("obd_fail_loc=%x, fail operation rc=%d\n",
                       OBD_FAIL_MDS_SENDPAGE, rc);
                ptlrpc_abort_bulk(desc);
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

#define MDS_MAX_CLIENTS 1024
#define MDS_MAX_CLIENT_WORDS (MDS_MAX_CLIENTS / sizeof(unsigned long))

static unsigned long last_rcvd_slots[MDS_MAX_CLIENT_WORDS];

/* Add client data to the MDS.  The in-memory storage will be a hash at some
 * point.  We use a bitmap to locate a free space in the last_rcvd file if
 * cl_off is -1 (i.e. a new client).  Otherwise, we have just read the data
 * from the last_rcvd file and we know its offset.
 */
int mds_client_add(struct mds_obd *mds, struct mds_client_data *mcd, int cl_off)
{
        struct mds_client_info *mci;

        OBD_ALLOC(mci, sizeof(*mci));
        if (!mci) {
                CERROR("no memory for MDS client info\n");
                RETURN(-ENOMEM);
        }
        INIT_LIST_HEAD(&mci->mci_open_head);

        CDEBUG(D_INFO, "client at offset %d with UUID '%s' added\n",
               cl_off, mcd->mcd_uuid);

        if (cl_off == -1) {
                unsigned long *word;
                int bit;

        repeat:
                word = last_rcvd_slots;
                while(*word == ~0UL)
                        ++word;
                if (word - last_rcvd_slots >= MDS_MAX_CLIENT_WORDS) {
                        CERROR("no room in client MDS bitmap - fix code\n");
                        return -ENOMEM;
                }
                bit = ffz(*word);
                if (test_and_set_bit(bit, word)) {
                        CERROR("found bit %d set for word %d - fix code\n",
                               bit, word - last_rcvd_slots);
                        goto repeat;
                }
                cl_off = word - last_rcvd_slots + bit;
        } else {
                if (test_and_set_bit(cl_off, last_rcvd_slots)) {
                        CERROR("bit %d already set in bitmap - bad bad\n",
                               cl_off);
                        LBUG();
                }
        }

        mci->mci_mcd = mcd;
        mci->mci_off = cl_off;

        /* For now we just put the clients in a list, not a hashed list */
        list_add_tail(&mci->mci_list, &mds->mds_client_info);

        mds->mds_client_count++;

        return 0;
}

void mds_client_del(struct mds_obd *mds, struct mds_client_info *mci)
{
        unsigned long *word;
        int bit;

        word = last_rcvd_slots + mci->mci_off / sizeof(unsigned long);
        bit = mci->mci_off % sizeof(unsigned long);

        if (!test_and_clear_bit(bit, word)) {
                CERROR("bit %d already clear in word %d - bad bad\n",
                       bit, word - last_rcvd_slots);
                LBUG();
        }

        --mds->mds_client_count;
        list_del(&mci->mci_list);
        OBD_FREE(mci->mci_mcd, sizeof(*mci->mci_mcd));
        OBD_FREE(mci, sizeof (*mci));
}

int mds_client_free_all(struct mds_obd *mds)
{
        struct list_head *p, *n;

        list_for_each_safe(p, n, &mds->mds_client_info) {
                struct mds_client_info *mci;

                mci = list_entry(p, struct mds_client_info, mci_list);
                mds_client_del(mds, mci);
        }

        return 0;
}

int mds_server_free_data(struct mds_obd *mds)
{
        OBD_FREE(mds->mds_server_data, sizeof(*mds->mds_server_data));
        mds->mds_server_data = NULL;

        return 0;
}

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

int mds_getattr(struct ptlrpc_request *req)
{
        struct dentry *de;
        struct inode *inode;
        struct mds_body *body;
        struct mds_obd *mds = &req->rq_obd->u.mds;
        int rc, size[2] = {sizeof(*body)}, count = 1;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                req->rq_status = -ENOENT;
                RETURN(0);
        }
        inode = de->d_inode;
        if (body->valid & OBD_MD_LINKNAME) {
                count = 2;
                size[1] = inode->i_size;
        }

        rc = lustre_pack_msg(count, size, NULL, &req->rq_replen,
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
                        CERROR("readlink failed: %d\n", req->rq_status);
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
        body->valid = ~0;
        mds_fs_get_objid(mds, inode, &body->objid);
 out:
        l_dput(de);
        RETURN(0);
}

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
                if (body->objid == fd->mfd_clientfd && 
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
        file = dentry_open(de, mnt, flags);
        if (!file || IS_ERR(file)) {
                req->rq_status = -EINVAL;
                OBD_FREE(mfd, sizeof(*mfd));
                RETURN(0);
        }

        file->private_data = mfd;
        mfd->mfd_file = file;
        mfd->mfd_clientfd = body->objid;
        list_add(&mfd->mfd_list, &mci->mci_open_head); 

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

        file = (struct file *)(unsigned long)body->objid;
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

/* This will be a hash table at some point. */
int mds_init_client_data(struct mds_obd *mds)
{
        INIT_LIST_HEAD(&mds->mds_client_info);
        return 0;
}

#define LAST_RCVD "last_rcvd"

int mds_read_last_rcvd(struct mds_obd *mds, struct file *f)
{
        struct mds_server_data *msd;
        struct mds_client_data *mcd = NULL;
        loff_t fsize = f->f_dentry->d_inode->i_size;
        loff_t off = 0;
        int cl_off;
        __u64 last_rcvd = 0;
        __u64 last_mount;
        int rc = 0;

        OBD_ALLOC(msd, sizeof(*msd));
        if (!msd)
                RETURN(-ENOMEM);
        rc = lustre_fread(f, (char *)msd, sizeof(*msd), &off);

        mds->mds_server_data = msd;
        if (rc == 0) {
                CERROR("empty MDS %s, new MDS?\n", LAST_RCVD);
                RETURN(0);
        } else if (rc != sizeof(*msd)) {
                CERROR("error reading MDS %s: rc = %d\n", LAST_RCVD, rc);
                if (rc > 0) {
                        rc = -EIO;
                }
                GOTO(err_msd, rc);
        }

        /*
         * When we do a clean MDS shutdown, we save the last_rcvd into
         * the header.  If we find clients with higher last_rcvd values
         * then those clients may need recovery done.
         */
        last_rcvd = le64_to_cpu(msd->msd_last_rcvd);
        mds->mds_last_rcvd = last_rcvd;
        CDEBUG(D_INODE, "got %Lu for server last_rcvd value\n",
               (unsigned long long)last_rcvd);

        last_mount = le64_to_cpu(msd->msd_mount_count);
        mds->mds_mount_count = last_mount;
        CDEBUG(D_INODE, "got %Lu for server last_mount value\n",
               (unsigned long long)last_mount);

        for (off = MDS_LR_CLIENT, cl_off = 0, rc = sizeof(*mcd);
             off <= fsize - sizeof(*mcd) && rc == sizeof(*mcd);
             off = MDS_LR_CLIENT + ++cl_off * MDS_LR_SIZE) {
                if (!mcd)
                        OBD_ALLOC(mcd, sizeof(*mcd));
                if (!mcd)
                        GOTO(err_msd, rc = -ENOMEM);

                rc = lustre_fread(f, (char *)mcd, sizeof(*mcd), &off);
                if (rc != sizeof(*mcd)) {
                        CERROR("error reading MDS %s offset %d: rc = %d\n",
                               LAST_RCVD, cl_off, rc);
                        if (rc > 0)
                                rc = -EIO;
                        break;
                }

                last_rcvd = le64_to_cpu(mcd->mcd_last_rcvd);
                last_mount = le64_to_cpu(mcd->mcd_mount_count);

                if (last_rcvd &&
                    last_mount - mcd->mcd_mount_count < MDS_MOUNT_RECOV) {
                        rc = mds_client_add(mds, mcd, cl_off);
                        if (rc) {
                                rc = 0;
                                break;
                        }
                        mcd = NULL;
                } else {
                        CDEBUG(D_INFO,
                               "client at offset %d with UUID '%s' ignored\n",
                               cl_off, mcd->mcd_uuid);
                }

                if (last_rcvd > mds->mds_last_rcvd) {
                        CDEBUG(D_OTHER,
                               "client at offset %d has last_rcvd = %Lu\n",
                               cl_off, (unsigned long long)last_rcvd);
                        mds->mds_last_rcvd = last_rcvd;
                }
        }
        CDEBUG(D_INODE, "got %Lu for highest last_rcvd value, %d clients\n",
               (unsigned long long)mds->mds_last_rcvd, mds->mds_client_count);

        /* After recovery, there can be no local uncommitted transactions */
        mds->mds_last_committed = mds->mds_last_rcvd;

        return 0;

err_msd:
        mds_server_free_data(mds);
        return rc;
}

static int mds_prep(struct obd_device *obddev)
{
        struct obd_run_ctxt saved;
        struct mds_obd *mds = &obddev->u.mds;
        struct super_operations *s_ops;
        struct dentry *dentry;
        struct file *f;
        int rc;

        push_ctxt(&saved, &mds->mds_ctxt);
        dentry = simple_mkdir(current->fs->pwd, "ROOT", 0700);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create ROOT directory: rc = %d\n", rc);
                GOTO(err_pop, rc);
        }
        /* XXX probably want to hold on to this later... */
        dput(dentry);
        f = filp_open("ROOT", O_RDONLY, 0);
        if (IS_ERR(f)) {
                rc = PTR_ERR(f);
                CERROR("cannot open ROOT: rc = %d\n", rc);
                LBUG();
                GOTO(err_pop, rc);
        }

        mds->mds_rootfid.id = f->f_dentry->d_inode->i_ino;
        mds->mds_rootfid.generation = f->f_dentry->d_inode->i_generation;
        mds->mds_rootfid.f_type = S_IFDIR;

        rc = filp_close(f, 0);
        if (rc) {
                CERROR("cannot close ROOT: rc = %d\n", rc);
                LBUG();
        }

        dentry = simple_mkdir(current->fs->pwd, "FH", 0700);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create FH directory: rc = %d\n", rc);
                GOTO(err_pop, rc);
        }
        /* XXX probably want to hold on to this later... */
        dput(dentry);

        rc = mds_init_client_data(mds);
        if (rc)
                GOTO(err_pop, rc);

        f = filp_open(LAST_RCVD, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(f)) {
                rc = PTR_ERR(f);
                CERROR("cannot open/create %s file: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_pop, rc = PTR_ERR(f));
        }
        if (!S_ISREG(f->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LAST_RCVD,
                       f->f_dentry->d_inode->i_mode);
                GOTO(err_pop, rc = -ENOENT);
        }

        rc = mds_fs_journal_data(mds, f);
        if (rc) {
                CERROR("cannot journal data on %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_filp, rc);
        }

        rc = mds_read_last_rcvd(mds, f);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_client, rc);
        }
        mds->mds_rcvd_filp = f;
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
         * type, as we don't have access to the mds struct in delete_inode
         * and store the client delete_inode method in a global table.  This
         * will only become a problem when multiple MDSs are running on a
         * single host with different client filesystems.
         */
        OBD_ALLOC(s_ops, sizeof(*s_ops));
        if (!s_ops)
                GOTO(err_filp, rc = -ENOMEM);

        memcpy(s_ops, mds->mds_sb->s_op, sizeof(*s_ops));
        mds->mds_fsops->cl_delete_inode = s_ops->delete_inode;
        s_ops->delete_inode = mds->mds_fsops->fs_delete_inode;
        mds->mds_sb->s_op = s_ops;

        mds->mds_service = ptlrpc_init_svc(128 * 1024,
                                           MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                                           "self", mds_handle);

        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                GOTO(err_filp, rc = -EINVAL);
        }

        rc = ptlrpc_start_thread(obddev, mds->mds_service, "lustre_mds");
        if (rc) {
                CERROR("cannot start thread: rc = %d\n", rc);
                GOTO(err_svc, rc);
        }

        RETURN(0);

err_svc:
        rpc_unregister_service(mds->mds_service);
        OBD_FREE(mds->mds_service, sizeof(*mds->mds_service));
err_client:
        mds_client_free_all(mds);
err_filp:
        if (filp_close(f, 0))
                CERROR("can't close %s after error\n", LAST_RCVD);
err_pop:
        pop_ctxt(&saved);

        return rc;
}

/* Update the server data on disk.  This stores the new mount_count and
 * also the last_rcvd value to disk.  If we don't have a clean shutdown,
 * then the server last_rcvd value may be less than that of the clients.
 * This will alert us that we may need to do client recovery.
 */
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

static int mds_cleanup(struct obd_device *obddev);

/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct mds_obd *mds = &obddev->u.mds;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;

#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2)
                RETURN(-EINVAL);

        mds->mds_fstype = strdup(data->ioc_inlbuf2);

        if (!strcmp(mds->mds_fstype, "extN"))
                mds->mds_fsops = &mds_extN_fs_ops;
        else if (!strcmp(mds->mds_fstype, "ext3"))
                mds->mds_fsops = &mds_ext3_fs_ops;
        else if (!strcmp(mds->mds_fstype, "ext2"))
                mds->mds_fsops = &mds_ext2_fs_ops;
        else {
                CERROR("unsupported MDS filesystem type %s\n", mds->mds_fstype);
                GOTO(err_kfree, rc = -EPERM);
        }

        MOD_INC_USE_COUNT;
        mnt = do_kern_mount(mds->mds_fstype, 0, data->ioc_inlbuf1, NULL);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(err_dec, rc);
        }

        mds->mds_sb = mnt->mnt_root->d_inode->i_sb;
        if (!mds->mds_sb)
                GOTO(err_put, rc = -ENODEV);

        mds->mds_vfsmnt = mnt;
        mds->mds_ctxt.pwdmnt = mnt;
        mds->mds_ctxt.pwd = mnt->mnt_root;
        mds->mds_ctxt.fs = KERNEL_DS;

        rc = mds_prep(obddev);
        if (rc)
                GOTO(err_put, rc);

        rc = mds_recover(obddev);
        if (rc) {
                mds_cleanup(obddev);
                RETURN(rc);
        }

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
        return rc;
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

        mds_client_free_all(mds);
        mds_update_server_data(mds);
        mds_server_free_data(mds);

        if (mds->mds_rcvd_filp) {
                int rc = filp_close(mds->mds_rcvd_filp, 0);
                mds->mds_rcvd_filp = NULL;

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
