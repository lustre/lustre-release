/*
 *  ost/ost_handler.c
 *  Storage Target Handling functions
 *  
 *  Lustre Object Server Module (OST)
 * 
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com>
 * 
 *  This server is single threaded at present (but can easily be multi
 *  threaded). For testing and management it is treated as an
 *  obd_device, although it does not export a full OBD method table
 *  (the requests are coming in over the wire, so object target
 *  modules do not have a full method table.)
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
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>

// for testing
static int ost_queue_req(struct obd_device *obddev, struct ptlrpc_request *req)
{
	struct ptlrpc_request *srv_req; 
	struct ost_obd *ost = &obddev->u.ost;
	
	if (!ost) { 
		EXIT;
		return -1;
	}

	srv_req = kmalloc(sizeof(*srv_req), GFP_KERNEL); 
	if (!srv_req) { 
		EXIT;
		return -ENOMEM;
	}

	printk("---> OST at %d %p, incoming req %p, srv_req %p\n", 
	       __LINE__, ost, req, srv_req);

	memset(srv_req, 0, sizeof(*req)); 

	/* move the request buffer */
	srv_req->rq_reqbuf = req->rq_reqbuf;
	srv_req->rq_reqlen    = req->rq_reqlen;
	srv_req->rq_ost = ost;

	/* remember where it came from */
	srv_req->rq_reply_handle = req;

	list_add(&srv_req->rq_list, &ost->ost_reqs); 
	wake_up(&ost->ost_waitq);
	return 0;
}

int ost_reply(struct obd_device *obddev, struct ptlrpc_request *req)
{
	struct ptlrpc_request *clnt_req = req->rq_reply_handle;

	ENTRY;

	if (req->rq_ost->ost_service != NULL) {
		/* This is a request that came from the network via portals. */

		/* FIXME: we need to increment the count of handled events */
		ptl_send_buf(req, &req->rq_peer, OST_REPLY_PORTAL, 0);
	} else {
		/* This is a local request that came from another thread. */

		/* move the reply to the client */ 
		clnt_req->rq_replen = req->rq_replen;
		clnt_req->rq_repbuf = req->rq_repbuf;
		req->rq_repbuf = NULL;
		req->rq_replen = 0;

		/* free the request buffer */
		kfree(req->rq_reqbuf);
		req->rq_reqbuf = NULL;

		/* wake up the client */ 
		wake_up_interruptible(&clnt_req->rq_wait_for_rep); 
	}

	EXIT;
	return 0;
}

int ost_error(struct obd_device *obddev, struct ptlrpc_request *req)
{
	struct ptlrep_hdr *hdr;

	ENTRY;

	hdr = kmalloc(sizeof(*hdr), GFP_KERNEL);
	if (!hdr) { 
		EXIT;
		return -ENOMEM;
	}

	memset(hdr, 0, sizeof(*hdr));
	
	hdr->seqno = req->rq_reqhdr->seqno;
	hdr->status = req->rq_status; 
	hdr->type = OST_TYPE_ERR;

	req->rq_repbuf = (char *)hdr;
	req->rq_replen = sizeof(*hdr); 

	EXIT;
	return ost_reply(obddev, req);
}

static int ost_destroy(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		printk("ost_destroy: cannot pack reply\n"); 
		return rc;
	}

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_destroy
		(&conn, &req->rq_req.ost->oa); 

	EXIT;
	return 0;
}

static int ost_getattr(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	printk("ost getattr entered\n"); 
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		printk("ost_getattr: cannot pack reply\n"); 
		return rc;
	}
	req->rq_rep.ost->oa.o_id = req->rq_req.ost->oa.o_id;
	req->rq_rep.ost->oa.o_valid = req->rq_req.ost->oa.o_valid;

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_getattr
		(&conn, &req->rq_rep.ost->oa); 

	EXIT;
	return 0;
}

static int ost_create(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		printk("ost_create: cannot pack reply\n"); 
		return rc;
	}

	memcpy(&req->rq_rep.ost->oa, &req->rq_req.ost->oa, sizeof(req->rq_req.ost->oa));

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_create
		(&conn, &req->rq_rep.ost->oa); 

	EXIT;
	return 0;
}


static int ost_setattr(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		printk("ost_setattr: cannot pack reply\n"); 
		return rc;
	}

	memcpy(&req->rq_rep.ost->oa, &req->rq_req.ost->oa,
	       sizeof(req->rq_req.ost->oa));

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_setattr
		(&conn, &req->rq_rep.ost->oa); 

	EXIT;
	return 0;
}

static int ost_connect(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		printk("ost_setattr: cannot pack reply\n"); 
		return rc;
	}

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_connect(&conn);

	printk("ost_connect: rep buffer %p, id %d\n", req->rq_repbuf, 
	       conn.oc_id);
	req->rq_rep.ost->connid = conn.oc_id;
	EXIT;
	return 0;
}


static int ost_disconnect(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_dev = ost->ost_tgt;
	conn.oc_id = req->rq_req.ost->connid;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		printk("ost_setattr: cannot pack reply\n"); 
		return rc;
	}

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_disconnect(&conn);

	EXIT;
	return 0;
}

static int ost_get_info(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;
	int vallen;
	void *val;
	char *ptr; 

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	ptr = ost_req_buf1(req->rq_req.ost);
	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_get_info
		(&conn, req->rq_req.ost->buflen1, ptr, &vallen, &val); 

	rc = ost_pack_rep(val, vallen, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		printk("ost_setattr: cannot pack reply\n"); 
		return rc;
	}

	EXIT;
	return 0;
}


#if 0
static struct page * ext2_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_cache_page(mapping, n,
				(filler_t*)mapping->a_ops->readpage, NULL);
	if (!IS_ERR(page)) {
		wait_on_page(page);
		kmap(page);
		if (!Page_Uptodate(page))
			goto fail;
		if (!PageChecked(page))
			ext2_check_page(page);
		if (PageError(page))
			goto fail;
	}
	return page;

fail:
	ext2_put_page(page);
	return ERR_PTR(-EIO);
}

static inline void ext2_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

/* Releases the page */
void ext2_set_link(struct inode *dir, struct ext2_dir_entry_2 *de,
			struct page *page, struct inode *inode)
{
	unsigned from = (char *) de - (char *) page_address(page);
	unsigned to = from + le16_to_cpu(de->rec_len);
	int err;

	lock_page(page);
	err = page->mapping->a_ops->prepare_write(NULL, page, from, to);
	if (err)
		BUG();
	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type (de, inode);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	err = ext2_commit_chunk(page, from, to);
	UnlockPage(page);
	ext2_put_page(page);
}

static int ext2_commit_chunk(struct page *page, unsigned from, unsigned to)
{
	struct inode *dir = page->mapping->host;
	int err = 0;
	dir->i_version = ++event;
	SetPageUptodate(page);
	set_page_clean(page);

	//page->mapping->a_ops->commit_write(NULL, page, from, to);
	//if (IS_SYNC(dir))
	//	err = waitfor_one_page(page);
	return err;
}

#endif

int ost_prepw(struct ost_obd *obddev, struct ptlrpc_request *req)
{
#if 0
	struct obd_conn conn; 
	int rc;
	int i, j, n;
	int objcount;
	void *tmp;
	struct niobuf **nb;
	struct obd_ioo **ioo;

	ENTRY;
	
	tmp1 = ost_req_buf1(req);
	tmp2 = ost_req_buf2(req);
	objcount = req->buflen1 / sizeof(**ioo); 

	n = 0;
	for (i=0 ; i<objcount ; i++) { 
		obd_unpack_ioo

	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		printk("ost_create: cannot pack reply\n"); 
		return rc;
	}

	memcpy(&req->rq_rep.ost->oa, &req->rq_req.ost->oa, sizeof(req->rq_req.ost->oa));

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_create
		(&conn, &req->rq_rep.ost->oa); 

	EXIT;
	return 0;
#endif
	return -ENOTSUPP;

}


int ost_handle(struct obd_device *obddev, struct ptlrpc_request *req)
{
	int rc;
	struct ost_obd *ost = &obddev->u.ost;
	struct ptlreq_hdr *hdr;

	ENTRY;
	printk("ost_handle: req at %p\n", req); 

	hdr = (struct ptlreq_hdr *)req->rq_reqbuf;
	if (NTOH__u32(hdr->type) != OST_TYPE_REQ) {
		printk("lustre_ost: wrong packet type sent %d\n",
		       NTOH__u32(hdr->type));
		rc = -EINVAL;
		goto out;
	}

	rc = ost_unpack_req(req->rq_reqbuf, req->rq_reqlen, 
			    &req->rq_reqhdr, &req->rq_req.ost);
	if (rc) { 
		printk("lustre_ost: Invalid request\n");
		EXIT; 
		goto out;
	}

	switch (req->rq_reqhdr->opc) { 

	case OST_CONNECT:
		CDEBUG(D_INODE, "connect\n");
		printk("----> connect \n"); 
		rc = ost_connect(ost, req);
		break;
	case OST_DISCONNECT:
		CDEBUG(D_INODE, "disconnect\n");
		rc = ost_disconnect(ost, req);
		break;
	case OST_GET_INFO:
		CDEBUG(D_INODE, "get_info\n");
		rc = ost_get_info(ost, req);
		break;
	case OST_CREATE:
		CDEBUG(D_INODE, "create\n");
		rc = ost_create(ost, req);
		break;
	case OST_DESTROY:
		CDEBUG(D_INODE, "destroy\n");
		rc = ost_destroy(ost, req);
		break;
	case OST_GETATTR:
		CDEBUG(D_INODE, "getattr\n");
		rc = ost_getattr(ost, req);
		break;
	case OST_SETATTR:
		CDEBUG(D_INODE, "setattr\n");
		rc = ost_setattr(ost, req);
		break;
	case OST_PREPW:
		CDEBUG(D_INODE, "prepw\n");
		rc = ost_prepw(ost, req);
		break;
	default:
		req->rq_status = -ENOTSUPP;
		return ost_error(obddev, req);
	}

out:
	req->rq_status = rc;
	if (rc) { 
		printk("ost: processing error %d\n", rc);
		ost_error(obddev, req);
	} else { 
		CDEBUG(D_INODE, "sending reply\n"); 
		ost_reply(obddev, req); 
	}

	return 0;
}

int ost_main(void *arg)
{
	struct obd_device *obddev = (struct obd_device *) arg;
	struct ost_obd *ost = &obddev->u.ost;
	ENTRY;
	printk("---> %d\n", __LINE__);


	lock_kernel();
	printk("---> %d\n", __LINE__);
	daemonize();
	printk("---> %d\n", __LINE__);
	spin_lock_irq(&current->sigmask_lock);
	printk("---> %d\n", __LINE__);
	sigfillset(&current->blocked);
	printk("---> %d\n", __LINE__);
	recalc_sigpending(current);
	printk("---> %d\n", __LINE__);
	spin_unlock_irq(&current->sigmask_lock);
	printk("---> %d\n", __LINE__);

	printk("---> %d\n", __LINE__);
	sprintf(current->comm, "lustre_ost");
	printk("---> %d\n", __LINE__);

	/* Record that the  thread is running */
	ost->ost_thread = current;
	printk("---> %d\n", __LINE__);
	wake_up(&ost->ost_done_waitq); 
	printk("---> %d\n", __LINE__);

	/* XXX maintain a list of all managed devices: insert here */

	/* And now, wait forever for commit wakeup events. */
	while (1) {
		int rc; 

		if (ost->ost_flags & OST_EXIT)
			break;

		wake_up(&ost->ost_done_waitq);
		interruptible_sleep_on(&ost->ost_waitq);

		CDEBUG(D_INODE, "lustre_ost wakes\n");
		CDEBUG(D_INODE, "pick up req here and continue\n"); 


		if (ost->ost_service != NULL) {
			ptl_event_t ev;

			while (1) {
				struct ptlrpc_request request;

				rc = PtlEQGet(ost->ost_service->srv_eq_h, &ev);
				if (rc != PTL_OK && rc != PTL_EQ_DROPPED)
					break;
				/* FIXME: If we move to an event-driven model,
				 * we should put the request on the stack of
				 * mds_handle instead. */
				memset(&request, 0, sizeof(request));
				request.rq_reqbuf = ev.mem_desc.start +
					ev.offset;
				request.rq_reqlen = ev.mem_desc.length;
				request.rq_ost = ost;
				request.rq_xid = ev.match_bits;

				request.rq_peer.peer_nid = ev.initiator.nid;
				/* FIXME: this NI should be the incoming NI.
				 * We don't know how to find that from here. */
				request.rq_peer.peer_ni =
					ost->ost_service->srv_self.peer_ni;
				rc = ost_handle(obddev, &request);
			}
		} else {
			struct ptlrpc_request *request;

			if (list_empty(&ost->ost_reqs)) { 
				CDEBUG(D_INODE, "woke because of timer\n"); 
			} else { 
				request = list_entry(ost->ost_reqs.next,
						     struct ptlrpc_request,
						     rq_list);
				list_del(&request->rq_list);
				rc = ost_handle(obddev, request); 
			}
		}
	}

	/* XXX maintain a list of all managed devices: cleanup here */

	ost->ost_thread = NULL;
	wake_up(&ost->ost_done_waitq);
	printk("lustre_ost: exiting\n");
	return 0;
}

static void ost_stop_srv_thread(struct ost_obd *ost)
{
	ost->ost_flags |= OST_EXIT;

	while (ost->ost_thread) {
		wake_up(&ost->ost_waitq);
		sleep_on(&ost->ost_done_waitq);
	}
}

static void ost_start_srv_thread(struct obd_device *obd)
{
	struct ost_obd *ost = &obd->u.ost;
	ENTRY;

	init_waitqueue_head(&ost->ost_waitq);
	printk("---> %d\n", __LINE__);
	init_waitqueue_head(&ost->ost_done_waitq);
	printk("---> %d\n", __LINE__);
	kernel_thread(ost_main, (void *)obd, 
		      CLONE_VM | CLONE_FS | CLONE_FILES);
	printk("---> %d\n", __LINE__);
	while (!ost->ost_thread) 
		sleep_on(&ost->ost_done_waitq);
	printk("---> %d\n", __LINE__);
	EXIT;
}

/* mount the file system (secretly) */
static int ost_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct obd_ioctl_data* data = buf;
	struct ost_obd *ost = &obddev->u.ost;
	struct obd_device *tgt;
	struct lustre_peer peer;
	int err; 
        ENTRY;

	if (data->ioc_dev  < 0 || data->ioc_dev > MAX_OBD_DEVICES) { 
		EXIT;
		return -ENODEV;
	}

        tgt = &obd_dev[data->ioc_dev];
	ost->ost_tgt = tgt;
        if ( ! (tgt->obd_flags & OBD_ATTACHED) || 
             ! (tgt->obd_flags & OBD_SET_UP) ){
                printk("device not attached or not set up (%d)\n", 
                       data->ioc_dev);
                EXIT;
		return -EINVAL;
        } 

	ost->ost_conn.oc_dev = tgt;
	err = tgt->obd_type->typ_ops->o_connect(&ost->ost_conn);
	if (err) { 
		printk("lustre ost: fail to connect to device %d\n", 
		       data->ioc_dev); 
		return -EINVAL;
	}

	INIT_LIST_HEAD(&ost->ost_reqs);
	ost->ost_thread = NULL;
	ost->ost_flags = 0;

	spin_lock_init(&obddev->u.ost.ost_lock);

	err = kportal_uuid_to_peer("self", &peer);
	if (err == 0) {
		ost->ost_service = kmalloc(sizeof(*ost->ost_service),
					   GFP_KERNEL);
		if (ost->ost_service == NULL)
			return -ENOMEM;
		ost->ost_service->srv_buf_size = 64 * 1024;
		ost->ost_service->srv_portal = OST_REQUEST_PORTAL;
		memcpy(&ost->ost_service->srv_self, &peer, sizeof(peer));
		ost->ost_service->srv_wait_queue = &ost->ost_waitq;

		rpc_register_service(ost->ost_service, "self");
	}

	ost_start_srv_thread(obddev);

        MOD_INC_USE_COUNT;
        EXIT; 
        return 0;
} 

static int ost_cleanup(struct obd_device * obddev)
{
	struct ost_obd *ost = &obddev->u.ost;
	struct obd_device *tgt;
	int err;

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

	rpc_unregister_service(ost->ost_service);

	ost_stop_srv_thread(ost);

	if (!list_empty(&ost->ost_reqs)) {
		// XXX reply with errors and clean up
		CDEBUG(D_INODE, "Request list not empty!\n");
	}

	tgt = ost->ost_tgt;
	err = tgt->obd_type->typ_ops->o_disconnect(&ost->ost_conn);
	if (err) { 
		printk("lustre ost: fail to disconnect device\n");
		return -EINVAL;
	}
	

        MOD_DEC_USE_COUNT;
        EXIT;
        return 0;
}

/* use obd ops to offer management infrastructure */
static struct obd_ops ost_obd_ops = {
        o_setup:       ost_setup,
        o_cleanup:     ost_cleanup,
};

static int __init ost_init(void)
{
        obd_register_type(&ost_obd_ops, LUSTRE_OST_NAME);
	return 0;
}

static void __exit ost_exit(void)
{
	obd_unregister_type(LUSTRE_OST_NAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

// for testing (maybe this stays)
EXPORT_SYMBOL(ost_queue_req);

module_init(ost_init);
module_exit(ost_exit);
