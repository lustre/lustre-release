/*
 *  linux/mds/handler.c
 *  
 *  Lustre Object Server Module (OST)
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
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>


// for testing
static struct ost_obd *OST;

// for testing
static int ost_queue_req(struct ost_request *req)
{
	
	if (!OST) { 
		EXIT;
		return -1;
	}

	list_add(&req->rq_list, &OST->ost_reqs); 
	init_waitqueue_head(&req->rq_wait_for_ost_rep);
	req->rq_obd = OST;
	wake_up(&OST->ost_waitq);
	printk("-- sleeping\n");
	interruptible_sleep_on(&req->rq_wait_for_ost_rep);
	printk("-- done\n");
	return 0;
}

int ost_reply(struct ost_request *req)
{
	ENTRY;
	kfree(req->rq_reqbuf);
	req->rq_reqbuf = NULL; 
	wake_up_interruptible(&req->rq_wait_for_ost_rep); 
	EXIT;
	return 0;
}

int ost_error(struct ost_request *req)
{
	struct ost_rep_hdr *hdr;

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

	EXIT;
	return ost_reply(req);
}

static int ost_destroy(struct ost_obd *ost, struct ost_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep,
			  &req->rq_reqlen, &req->rq_reqbuf); 
	if (rc) { 
		printk("ost_destroy: cannot pack reply\n"); 
		return rc;
	}

	req->rq_rep->result =ost->ost_tgt->obd_type->typ_ops->o_destroy
		(&conn, &req->rq_req->oa); 

	EXIT;
	return 0;
}

static int ost_getattr(struct ost_obd *ost, struct ost_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep,
			  &req->rq_reqlen, &req->rq_reqbuf); 
	if (rc) { 
		printk("ost_getattr: cannot pack reply\n"); 
		return rc;
	}
	req->rq_rep->oa.o_id = req->rq_req->oa.o_id;

	req->rq_rep->result =ost->ost_tgt->obd_type->typ_ops->o_getattr
		(&conn, &req->rq_rep->oa); 

	EXIT;
	return 0;
}

static int ost_create(struct ost_obd *ost, struct ost_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep,
			  &req->rq_reqlen, &req->rq_reqbuf); 
	if (rc) { 
		printk("ost_create: cannot pack reply\n"); 
		return rc;
	}

	memcpy(&req->rq_rep->oa, &req->rq_req->oa, sizeof(req->rq_req->oa));

	req->rq_rep->result =ost->ost_tgt->obd_type->typ_ops->o_create
		(&conn, &req->rq_rep->oa); 

	EXIT;
	return 0;
}


static int ost_setattr(struct ost_obd *ost, struct ost_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep,
			  &req->rq_reqlen, &req->rq_reqbuf); 
	if (rc) { 
		printk("ost_setattr: cannot pack reply\n"); 
		return rc;
	}

	memcpy(&req->rq_rep->oa, &req->rq_req->oa, sizeof(req->rq_req->oa));

	req->rq_rep->result =ost->ost_tgt->obd_type->typ_ops->o_setattr
		(&conn, &req->rq_rep->oa); 

	EXIT;
	return 0;
}


//int ost_handle(struct ost_conn *conn, int len, char *buf)
int ost_handle(struct ost_obd *ost, struct ost_request *req)
{
	int rc;
	struct ost_req_hdr *hdr;

	ENTRY;

	hdr = (struct ost_req_hdr *)req->rq_reqbuf;

	if (NTOH__u32(hdr->type) != OST_TYPE_REQ) {
		printk("lustre_ost: wrong packet type sent %d\n",
		       NTOH__u32(hdr->type));
		rc = -EINVAL;
		goto out;
	}

	rc = ost_unpack_req(req->rq_reqbuf, req->rq_reqlen, 
			    &req->rq_reqhdr, &req->rq_req);
	if (rc) { 
		printk("lustre_ost: Invalid request\n");
		EXIT; 
		goto out;
	}

	switch (req->rq_reqhdr->opc) { 

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

	default:
		return ost_error(req);
	}

out:
	if (rc) { 
		printk("ost: processing error %d\n", rc);
		ost_error(req);
	} else { 
		CDEBUG(D_INODE, "sending reply\n"); 
		ost_reply(req); 
	}

	return 0;
}

int ost_main(void *arg)
{
	struct ost_obd *ost = (struct ost_obd *) arg;

	lock_kernel();
	daemonize();
	spin_lock_irq(&current->sigmask_lock);
	sigfillset(&current->blocked);
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);

	sprintf(current->comm, "lustre_ost");

	/* Record that the  thread is running */
	ost->ost_thread = current;
	wake_up(&ost->ost_done_waitq); 

	/* XXX maintain a list of all managed devices: insert here */

	/* And now, wait forever for commit wakeup events. */
	while (1) {
		struct ost_request *request;
		int rc; 

		if (ost->ost_flags & OST_EXIT)
			break;


		wake_up(&ost->ost_done_waitq);
		interruptible_sleep_on(&ost->ost_waitq);

		CDEBUG(D_INODE, "lustre_ost wakes\n");
		CDEBUG(D_INODE, "pick up req here and continue\n"); 

		if (list_empty(&ost->ost_reqs)) { 
			CDEBUG(D_INODE, "woke because of timer\n"); 
		} else { 
			request = list_entry(ost->ost_reqs.next, 
					     struct ost_request, rq_list);
			list_del(&request->rq_list);
			rc = ost_handle(ost, request); 
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

static void ost_start_srv_thread(struct ost_obd *ost)
{
	init_waitqueue_head(&ost->ost_waitq);
	init_waitqueue_head(&ost->ost_done_waitq);
	kernel_thread(ost_main, (void *)ost, 
		      CLONE_VM | CLONE_FS | CLONE_FILES);
	while (!ost->ost_thread) 
		sleep_on(&ost->ost_done_waitq);
}

/* mount the file system (secretly) */
static int ost_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct obd_ioctl_data* data = buf;
	struct ost_obd *ost = &obddev->u.ost;
	struct obd_device *tgt;
	int err; 
        ENTRY;

	if (data->ioc_dev  < 0 || data->ioc_dev > MAX_OBD_DEVICES) { 
		EXIT;
		return -ENODEV;
	}

        tgt = &obd_dev[data->ioc_dev];
	
        if ( ! (tgt->obd_flags & OBD_ATTACHED) || 
             ! (tgt->obd_flags & OBD_SET_UP) ){
                printk("device not attached or not set up (%d)\n", 
                       data->ioc_dev);
                EXIT;
		return -EINVAL;
        } 

	err = tgt->obd_type->typ_ops->o_connect(&ost->ost_conn);
	if (err) { 
		printk("lustre ost: fail to connect to device %d\n", 
		       data->ioc_dev); 
		return -EINVAL;
	}

	INIT_LIST_HEAD(&ost->ost_reqs);
	ost->ost_thread = NULL;
	ost->ost_flags = 0;
	OST = ost;

	spin_lock_init(&obddev->u.ost.fo_lock);

	ost_start_srv_thread(ost);

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

	OST = NULL;
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
