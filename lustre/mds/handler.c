/*
 *  linux/mds/handler.c
 *  
 *  Lustre Metadata Server (mds) request handler
 * 
 *  Copyright (C) 2001  Cluster File Systems, Inc.
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
#include <linux/obd_support.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>

// for testing
static struct mds_obd *MDS;

// XXX make this networked!  
static int mds_queue_req(struct mds_request *req)
{
	struct mds_request *srv_req;
	
	if (!MDS) { 
		EXIT;
		return -1;
	}

	srv_req = kmalloc(sizeof(*srv_req), GFP_KERNEL);
	if (!srv_req) { 
		EXIT;
		return -ENOMEM;
	}

	printk("---> MDS at %d %p, incoming req %p, srv_req %p\n", 
	       __LINE__, MDS, req, srv_req);

	memset(srv_req, 0, sizeof(*req)); 

	/* move the request buffer */
	srv_req->rq_reqbuf = req->rq_reqbuf;
	srv_req->rq_reqlen    = req->rq_reqlen;
	srv_req->rq_obd = MDS;

	/* remember where it came from */
	srv_req->rq_reply_handle = req;

	list_add(&srv_req->rq_list, &MDS->mds_reqs); 
	wake_up(&MDS->mds_waitq);
	return 0;
}

/* XXX replace with networking code */
int mds_reply(struct mds_request *req)
{
	struct mds_request *clnt_req = req->rq_reply_handle;

	ENTRY;

	/* free the request buffer */
	kfree(req->rq_reqbuf);
	req->rq_reqbuf = NULL; 
	
	/* move the reply to the client */ 
	clnt_req->rq_replen = req->rq_replen;
	clnt_req->rq_repbuf = req->rq_repbuf;
	req->rq_repbuf = NULL;
	req->rq_replen = 0;

	/* wake up the client */ 
	wake_up_interruptible(&clnt_req->rq_wait_for_rep); 
	EXIT;
	return 0;
}

int mds_error(struct mds_request *req)
{
	struct mds_rep_hdr *hdr;

	ENTRY;
	hdr = kmalloc(sizeof(*hdr), GFP_KERNEL);
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



static struct dentry *mds_fid2dentry(struct mds_obd *mds, struct lustre_fid *fid)
{
	struct dentry *de;
	struct inode *inode;

	inode = iget(mds->mds_sb, fid->id);
	if (!inode) { 
		EXIT;
	}

	de = d_alloc_root(inode);
	if (!de) { 
		iput(inode);
		EXIT;
		return NULL;
	}

	de->d_inode = inode;
	return de;
}

int mds_getattr(struct mds_request *req)
{
	struct dentry *de = mds_fid2dentry(req->rq_obd, &req->rq_req->fid1);
	struct inode *inode;
	struct mds_rep *rep;
	int rc;
	
	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		printk("mds: out of memory\n");
		req->rq_status = -ENOMEM;
		return -ENOMEM;
	}

	req->rq_rephdr->seqno = req->rq_reqhdr->seqno;
	rep = req->rq_rep;

	if (!de) { 
		EXIT;
		req->rq_rephdr->status = -ENOENT;
		return 0;
	}

	inode = de->d_inode;
	rep->atime = inode->i_atime;
	rep->ctime = inode->i_ctime;
	rep->mtime = inode->i_mtime;
	rep->uid = inode->i_uid;
	rep->gid = inode->i_gid;
	rep->size = inode->i_size;
	rep->mode = inode->i_mode;
	rep->valid = ~0;

	dput(de); 
	return 0;
}


//int mds_handle(struct mds_conn *conn, int len, char *buf)
int mds_handle(struct mds_request *req)
{
	int rc;
	struct mds_req_hdr *hdr;

	ENTRY;

	hdr = (struct mds_req_hdr *)req->rq_reqbuf;

	if (NTOH__u32(hdr->type) != MDS_TYPE_REQ) {
		printk("lustre_mds: wrong packet type sent %d\n",
		       NTOH__u32(hdr->type));
		rc = -EINVAL;
		goto out;
	}

	rc = mds_unpack_req(req->rq_reqbuf, req->rq_reqlen, 
			    &req->rq_reqhdr, &req->rq_req);
	if (rc) { 
		printk("lustre_mds: Invalid request\n");
		EXIT; 
		goto out;
	}

	switch (req->rq_reqhdr->opc) { 

	case MDS_GETATTR:
		CDEBUG(D_INODE, "getattr\n");
		rc = mds_getattr(req);
		break;

	case MDS_OPEN:
		return mds_getattr(req);

	case MDS_SETATTR:
		return mds_getattr(req);

	case MDS_CREATE:
		return mds_getattr(req);

	case MDS_MKDIR:
		return mds_getattr(req);

	case MDS_RMDIR:
		return mds_getattr(req);

	case MDS_SYMLINK:
		return mds_getattr(req);
 
	case MDS_LINK:
		return mds_getattr(req);
  
	case MDS_MKNOD:
		return mds_getattr(req);

	case MDS_UNLINK:
		return mds_getattr(req);

	case MDS_RENAME:
		return mds_getattr(req);

	default:
		return mds_error(req);
	}

out:
	if (rc) { 
		printk("mds: processing error %d\n", rc);
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

	printk(KERN_INFO "lustre_mds starting.  Commit interval %d seconds\n",
			mds->mds_interval / HZ);

	/* XXX maintain a list of all managed devices: insert here */

	/* And now, wait forever for commit wakeup events. */
	while (1) {
		struct mds_request *request;
		int rc; 

		if (mds->mds_flags & MDS_UNMOUNT)
			break;


		wake_up(&mds->mds_done_waitq);
		interruptible_sleep_on(&mds->mds_waitq);

		CDEBUG(D_INODE, "lustre_mds wakes\n");
		CDEBUG(D_INODE, "pick up req here and continue\n"); 

		if (list_empty(&mds->mds_reqs)) { 
			CDEBUG(D_INODE, "woke because of timer\n"); 
		} else { 
			request = list_entry(mds->mds_reqs.next, 
					     struct mds_request, rq_list);
			list_del(&request->rq_list);
			rc = mds_handle(request); 
		}
	}

	del_timer_sync(mds->mds_timer);

	/* XXX maintain a list of all managed devices: cleanup here */

	mds->mds_thread = NULL;
	wake_up(&mds->mds_done_waitq);
	printk("lustre_mds: exiting\n");
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
	int err; 
        ENTRY;
	
	mnt = do_kern_mount(data->ioc_inlbuf2, 0, 
			    data->ioc_inlbuf1, NULL); 
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

	INIT_LIST_HEAD(&mds->mds_reqs);
	mds->mds_thread = NULL;
	mds->mds_flags = 0;
	mds->mds_interval = 3 * HZ;
	mds->mds_vfsmnt = mnt;
	obddev->u.mds.mds_fstype = strdup(data->ioc_inlbuf2);

	mds->mds_ctxt.pwdmnt = mnt;
	mds->mds_ctxt.pwd = mnt->mnt_root;
	mds->mds_ctxt.fs = KERNEL_DS;
	MDS = mds;

	spin_lock_init(&obddev->u.mds.fo_lock);

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
                printk(KERN_WARNING __FUNCTION__ ": still has clients!\n");
                EXIT;
                return -EBUSY;
        }

	MDS = NULL;
	mds_stop_srv_thread(mds);
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
