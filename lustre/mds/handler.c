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
 *  This server is single threaded at present (but can easily be multi threaded). 
 * 
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/ext2_fs.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/obd_support.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_net.h>
#include <linux/obd_class.h>

// XXX for testing
static struct mds_obd *MDS;

// XXX make this networked!  
static int mds_queue_req(struct ptlrpc_request *req)
{
	struct ptlrpc_request *srv_req;
	
	if (!MDS) { 
		EXIT;
		return -1;
	}

	OBD_ALLOC(srv_req, sizeof(*srv_req));
	if (!srv_req) { 
		EXIT;
		return -ENOMEM;
	}

        CDEBUG(0, "---> MDS at %d %p, incoming req %p, srv_req %p\n",
	       __LINE__, MDS, req, srv_req);

	memset(srv_req, 0, sizeof(*req)); 

	/* move the request buffer */
	srv_req->rq_reqbuf = req->rq_reqbuf;
	srv_req->rq_reqlen = req->rq_reqlen;
	srv_req->rq_obd = MDS;

	/* remember where it came from */
	srv_req->rq_reply_handle = req;

	list_add(&srv_req->rq_list, &MDS->mds_reqs); 
	wake_up(&MDS->mds_waitq);
	return 0;
}

int mds_sendpage(struct ptlrpc_request *req, struct file *file, 
                 __u64 offset, struct niobuf *dst)
{
	int rc; 
	mm_segment_t oldfs = get_fs();

	if (req->rq_peer.peer_nid == 0) {
		/* dst->addr is a user address, but in a different task! */
		set_fs(KERNEL_DS); 
		rc = generic_file_read(file, (char *)(long)dst->addr, 
				       PAGE_SIZE, &offset); 
		set_fs(oldfs);

		if (rc != PAGE_SIZE) 
			return -EIO;
	} else {
		char *buf;

		OBD_ALLOC(buf, PAGE_SIZE);
		if (!buf)
			return -ENOMEM;

		set_fs(KERNEL_DS); 
		rc = generic_file_read(file, buf, PAGE_SIZE, &offset); 
		set_fs(oldfs);

		if (rc != PAGE_SIZE) {
                        OBD_FREE(buf, PAGE_SIZE);
			return -EIO;
                }

		req->rq_bulkbuf = buf;
		req->rq_bulklen = PAGE_SIZE;
		rc = ptl_send_buf(req, &req->rq_peer, MDS_BULK_PORTAL, 0);
		init_waitqueue_head(&req->rq_wait_for_bulk);
		sleep_on(&req->rq_wait_for_bulk);
                OBD_FREE(buf, PAGE_SIZE);
		req->rq_bulklen = 0; /* FIXME: eek. */
	}

	return 0;
}

int mds_reply(struct ptlrpc_request *req)
{
	struct ptlrpc_request *clnt_req = req->rq_reply_handle;

	ENTRY;
	
	if (req->rq_obd->mds_service != NULL) {
		/* This is a request that came from the network via portals. */

		/* FIXME: we need to increment the count of handled events */
		ptl_send_buf(req, &req->rq_peer, MDS_REPLY_PORTAL, 0);
	} else {
		/* This is a local request that came from another thread. */

		/* move the reply to the client */ 
		clnt_req->rq_replen = req->rq_replen;
		clnt_req->rq_repbuf = req->rq_repbuf;
		req->rq_repbuf = NULL;
		req->rq_replen = 0;

		/* free the request buffer */
		OBD_FREE(req->rq_reqbuf, req->rq_reqlen);
		req->rq_reqbuf = NULL;

		/* wake up the client */ 
		wake_up_interruptible(&clnt_req->rq_wait_for_rep); 
	}

	EXIT;
	return 0;
}

int mds_error(struct ptlrpc_request *req)
{
	struct ptlrep_hdr *hdr;

	ENTRY;

	OBD_ALLOC(hdr, sizeof(*hdr));
	if (!hdr) { 
		EXIT;
		return -ENOMEM;
	}

	memset(hdr, 0, sizeof(*hdr));
	
	hdr->seqno = req->rq_reqhdr->seqno;
	hdr->status = req->rq_status; 
	hdr->type = MDS_TYPE_ERR;

	req->rq_repbuf = (char *)hdr;
	req->rq_replen = sizeof(*hdr); 

	EXIT;
	return mds_reply(req);
}

struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid,
                              struct vfsmount **mnt)
{
	/* stolen from NFS */ 
	struct super_block *sb = mds->mds_sb; 
	unsigned long ino = fid->id;
	//__u32 generation = fid->generation;
	__u32 generation = 0;
	struct inode *inode;
	struct list_head *lp;
	struct dentry *result;

	if (ino == 0)
		return ERR_PTR(-ESTALE);

	inode = iget(sb, ino);
	if (inode == NULL)
		return ERR_PTR(-ENOMEM);

	CDEBUG(D_DENTRY, "--> mds_fid2dentry: sb %p\n", inode->i_sb); 

	if (is_bad_inode(inode)
	    || (generation && inode->i_generation != generation)
		) {
		/* we didn't find the right inode.. */
		CERROR("bad inode %lu, link: %d ct: %d or version  %u/%u\n",
			inode->i_ino,
			inode->i_nlink, atomic_read(&inode->i_count),
			inode->i_generation,
			generation);
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

static inline void mds_get_objid(struct inode *inode, __u64 *id)
{
	memcpy(id, &inode->u.ext2_i.i_data, sizeof(*id));
}

int mds_getattr(struct ptlrpc_request *req)
{
	struct dentry *de;
	struct inode *inode;
	struct mds_rep *rep;
	int rc;
	
	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.mds, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		CERROR("mds: out of memory\n");
		req->rq_status = -ENOMEM;
		return 0;
	}

	req->rq_rephdr->seqno = req->rq_reqhdr->seqno;
	rep = req->rq_rep.mds;

	de = mds_fid2dentry(req->rq_obd, &req->rq_req.mds->fid1, NULL);
	if (IS_ERR(de)) { 
		EXIT;
		req->rq_rephdr->status = -ENOENT;
		return 0;
	}

	inode = de->d_inode;
	rep->ino = inode->i_ino;
	rep->atime = inode->i_atime;
	rep->ctime = inode->i_ctime;
	rep->mtime = inode->i_mtime;
	rep->uid = inode->i_uid;
	rep->gid = inode->i_gid;
	rep->size = inode->i_size;
	rep->mode = inode->i_mode;
	rep->nlink = inode->i_nlink;
	rep->valid = ~0;
	mds_get_objid(inode, &rep->objid);
	dput(de); 
	return 0;
}

int mds_readpage(struct ptlrpc_request *req)
{
	struct vfsmount *mnt;
	struct dentry *de;
	struct file *file; 
	struct niobuf *niobuf; 
	struct mds_rep *rep;
	int rc;
	
	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.mds, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		CERROR("mds: out of memory\n");
		req->rq_status = -ENOMEM;
		return 0;
	}

	req->rq_rephdr->seqno = req->rq_reqhdr->seqno;
	rep = req->rq_rep.mds;

	de = mds_fid2dentry(req->rq_obd, &req->rq_req.mds->fid1, &mnt);
	if (IS_ERR(de)) { 
		EXIT;
		req->rq_rephdr->status = PTR_ERR(de); 
		return 0;
	}

        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

	file = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE); 
	/* note: in case of an error, dentry_open puts dentry */
	if (IS_ERR(file)) { 
		EXIT;
		req->rq_rephdr->status = PTR_ERR(file);
		return 0;
	}

	niobuf = mds_req_tgt(req->rq_req.mds);

	/* to make this asynchronous make sure that the handling function 
	   doesn't send a reply when this function completes. Instead a 
	   callback function would send the reply */ 
	rc = mds_sendpage(req, file, req->rq_req.mds->size, niobuf); 

	filp_close(file, 0);
	req->rq_rephdr->status = rc;
	EXIT;
	return 0;
}

int mds_reint(struct ptlrpc_request *req)
{
	int rc;
	char *buf = mds_req_tgt(req->rq_req.mds);
	int len = req->rq_req.mds->tgtlen;
	struct mds_update_record rec;
	
	rc = mds_update_unpack(buf, len, &rec);
	if (rc) { 
		CERROR("invalid record\n");
		req->rq_status = -EINVAL;
		return 0;
	}
	/* rc will be used to interrupt a for loop over multiple records */
	rc = mds_reint_rec(&rec, req); 
	return 0; 
}

//int mds_handle(struct mds_conn *conn, int len, char *buf)
int mds_handle(struct ptlrpc_request *req)
{
	int rc;
	struct ptlreq_hdr *hdr;

	ENTRY;

	hdr = (struct ptlreq_hdr *)req->rq_reqbuf;

	if (NTOH__u32(hdr->type) != MDS_TYPE_REQ) {
		CERROR("lustre_mds: wrong packet type sent %d\n",
		       NTOH__u32(hdr->type));
		rc = -EINVAL;
		goto out;
	}

	rc = mds_unpack_req(req->rq_reqbuf, req->rq_reqlen, 
			    &req->rq_reqhdr, &req->rq_req.mds);
	if (rc) { 
		CERROR("lustre_mds: Invalid request\n");
		EXIT; 
		goto out;
	}

	switch (req->rq_reqhdr->opc) { 

	case MDS_GETATTR:
		CDEBUG(D_INODE, "getattr\n");
		rc = mds_getattr(req);
		break;

	case MDS_READPAGE:
		CDEBUG(D_INODE, "readpage\n");
		rc = mds_readpage(req);
		break;

	case MDS_REINT:
		CDEBUG(D_INODE, "reint\n");
		rc = mds_reint(req);
		break;

	default:
		return mds_error(req);
	}

out:
	if (rc) { 
		CERROR("no header\n");
		return 0;
	}

	if( req->rq_status) { 
		mds_error(req);
	} else { 
		CDEBUG(D_INODE, "sending reply\n"); 
		mds_reply(req); 
	}

	return 0;
}


static void mds_timer_run(unsigned long __data)
{
	struct task_struct * p = (struct task_struct *) __data;

	wake_up_process(p);
}

int mds_main(void *arg)
{
	struct mds_obd *mds = (struct mds_obd *) arg;
	struct timer_list timer;
        DECLARE_WAITQUEUE(wait, current);

	lock_kernel();
	daemonize();
	spin_lock_irq(&current->sigmask_lock);
	sigfillset(&current->blocked);
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);

	sprintf(current->comm, "lustre_mds");

	/* Set up an interval timer which can be used to trigger a
           wakeup after the interval expires */
	init_timer(&timer);
	timer.data = (unsigned long) current;
	timer.function = mds_timer_run;
	mds->mds_timer = &timer;

	/* Record that the  thread is running */
	mds->mds_thread = current;
	wake_up(&mds->mds_done_waitq); 

	/* And now, wait forever for commit wakeup events. */
	while (1) {
		int rc;

		if (mds->mds_flags & MDS_UNMOUNT)
			break;

		wake_up(&mds->mds_done_waitq);
		interruptible_sleep_on(&mds->mds_waitq);
		CDEBUG(D_INODE, "mds_wakes pick up req here and continue\n"); 

		if (mds->mds_service != NULL) {
			ptl_event_t ev;
                        struct ptlrpc_request request;
                        struct ptlrpc_service *service;


                        CDEBUG(D_IOCTL, "-- sleeping\n");
                        add_wait_queue(&mds->mds_waitq, &wait);
                        while (1) {
				rc = PtlEQGet(mds->mds_service->srv_eq_h, &ev);
                                if (rc == PTL_OK || rc == PTL_EQ_DROPPED)
                                        break;

                                set_current_state(TASK_INTERRUPTIBLE);

                                /* if this process really wants to die,
                                 * let it go */
                                if (sigismember(&(current->pending.signal),
                                                SIGKILL) ||
                                    sigismember(&(current->pending.signal),
                                                SIGINT))
                                        break;

                                schedule();
                        }
                        remove_wait_queue(&mds->mds_waitq, &wait);
                        set_current_state(TASK_RUNNING);
                        CDEBUG(D_IOCTL, "-- done\n");

                        if (rc == PTL_EQ_EMPTY) {
                                /* We broke out because of a signal */
                                EXIT;
                                return -EINTR;
                        }

                        service = (struct ptlrpc_service *)ev.mem_desc.user_ptr;	

                        /* FIXME: If we move to an event-driven model,
                         * we should put the request on the stack of
                         * mds_handle instead. */
                        memset(&request, 0, sizeof(request));
                        request.rq_reqbuf = ev.mem_desc.start + ev.offset;
                        request.rq_reqlen = ev.mem_desc.length;
                        request.rq_obd = MDS;
                        request.rq_xid = ev.match_bits;

                        request.rq_peer.peer_nid = ev.initiator.nid;
                        /* FIXME: this NI should be the incoming NI.
                         * We don't know how to find that from here. */
                        request.rq_peer.peer_ni =
                                mds->mds_service->srv_self.peer_ni;
                        rc = mds_handle(&request);

                        /* Inform the rpc layer the event has been handled */ 
                        ptl_received_rpc(service);
		} else {
			struct ptlrpc_request *request;

                        CDEBUG(D_IOCTL, "-- sleeping\n");
                        add_wait_queue(&mds->mds_waitq, &wait);
                        while (1) {
                                spin_lock(&mds->mds_lock);
                                if (!list_empty(&mds->mds_reqs))
                                        break;

                                set_current_state(TASK_INTERRUPTIBLE);

                                /* if this process really wants to die,
                                 * let it go */
                                if (sigismember(&(current->pending.signal),
                                                SIGKILL) ||
                                    sigismember(&(current->pending.signal),
                                                SIGINT))
                                        break;

                                spin_unlock(&mds->mds_lock);

                                schedule();
                        }
                        remove_wait_queue(&mds->mds_waitq, &wait);
                        set_current_state(TASK_RUNNING);
                        CDEBUG(D_IOCTL, "-- done\n");

			if (list_empty(&mds->mds_reqs)) {
				CDEBUG(D_INODE, "woke because of signal\n");
                                spin_unlock(&mds->mds_lock);
			} else {
				request = list_entry(mds->mds_reqs.next,
						     struct ptlrpc_request,
						     rq_list);
				list_del(&request->rq_list);
                                spin_unlock(&mds->mds_lock);
				rc = mds_handle(request);
			}
		}
	}

	del_timer_sync(mds->mds_timer);

	/* XXX maintain a list of all managed devices: cleanup here */

	mds->mds_thread = NULL;
	wake_up(&mds->mds_done_waitq);
	CERROR("lustre_mds: exiting\n");
	return 0;
}

static void mds_stop_srv_thread(struct mds_obd *mds)
{
	mds->mds_flags |= MDS_UNMOUNT;

	while (mds->mds_thread) {
		wake_up(&mds->mds_waitq);
		sleep_on(&mds->mds_done_waitq);
	}
}

static void mds_start_srv_thread(struct mds_obd *mds)
{
	init_waitqueue_head(&mds->mds_waitq);
	init_waitqueue_head(&mds->mds_done_waitq);
	kernel_thread(mds_main, (void *)mds, 
		      CLONE_VM | CLONE_FS | CLONE_FILES);
	while (!mds->mds_thread) 
		sleep_on(&mds->mds_done_waitq);
}

/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct obd_ioctl_data* data = buf;
	struct mds_obd *mds = &obddev->u.mds;
	struct vfsmount *mnt;
	struct lustre_peer peer;
	int err; 
        ENTRY;


	mnt = do_kern_mount(data->ioc_inlbuf2, 0, data->ioc_inlbuf1, NULL); 
	err = PTR_ERR(mnt);
	if (IS_ERR(mnt)) { 
		EXIT;
		return err;
	}

	mds->mds_sb = mnt->mnt_root->d_inode->i_sb;
	if (!obddev->u.mds.mds_sb) {
		EXIT;
		return -ENODEV;
	}

	mds->mds_vfsmnt = mnt;
	obddev->u.mds.mds_fstype = strdup(data->ioc_inlbuf2);

	mds->mds_ctxt.pwdmnt = mnt;
	mds->mds_ctxt.pwd = mnt->mnt_root;
	mds->mds_ctxt.fs = KERNEL_DS;
	mds->mds_remote_nid = 0;

	INIT_LIST_HEAD(&mds->mds_reqs);
	mds->mds_thread = NULL;
	mds->mds_flags = 0;
	mds->mds_interval = 3 * HZ;
	MDS = mds;

	spin_lock_init(&obddev->u.mds.mds_lock);

	err = kportal_uuid_to_peer("self", &peer);
	if (err == 0) {
		OBD_ALLOC(mds->mds_service, sizeof(*mds->mds_service));
		if (mds->mds_service == NULL)
			return -ENOMEM;
		mds->mds_service->srv_buf_size = 64 * 1024;
		//mds->mds_service->srv_buf_size = 1024;
		mds->mds_service->srv_portal = MDS_REQUEST_PORTAL;
		memcpy(&mds->mds_service->srv_self, &peer, sizeof(peer));
		mds->mds_service->srv_wait_queue = &mds->mds_waitq;

		rpc_register_service(mds->mds_service, "self");
	}

	mds_start_srv_thread(mds);

        MOD_INC_USE_COUNT;
        EXIT; 
        return 0;
} 

static int mds_cleanup(struct obd_device * obddev)
{
        struct super_block *sb;
	struct mds_obd *mds = &obddev->u.mds;

        ENTRY;

        if ( !(obddev->obd_flags & OBD_SET_UP) ) {
                EXIT;
                return 0;
        }

        if ( !list_empty(&obddev->obd_gen_clients) ) {
                CERROR("still has clients!\n");
                EXIT;
                return -EBUSY;
        }

	MDS = NULL;
	mds_stop_srv_thread(mds);
        rpc_unregister_service(mds->mds_service);
        OBD_FREE(mds->mds_service, sizeof(*mds->mds_service));

        sb = mds->mds_sb;
        if (!mds->mds_sb){
                EXIT;
                return 0;
        }

	if (!list_empty(&mds->mds_reqs)) {
		// XXX reply with errors and clean up
		CDEBUG(D_INODE, "Request list not empty!\n");
	}

	unlock_kernel();
	mntput(mds->mds_vfsmnt); 
        mds->mds_sb = 0;
	kfree(mds->mds_fstype);
	lock_kernel();

        MOD_DEC_USE_COUNT;
        EXIT;
        return 0;
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


// for testing (maybe this stays)
EXPORT_SYMBOL(mds_queue_req);

module_init(mds_init);
module_exit(mds_exit);
