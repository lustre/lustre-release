/*
 * Copryright (C) 2001 Cluster File Systems, Inc.
 *
 */

#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>

extern int ost_queue_req(struct obd_device *, struct ost_request *);

struct ost_request *osc_prep_req(int size, int opcode)
{
	struct ost_request *request;
	int rc;
	ENTRY; 

	request = (struct ost_request *)kmalloc(sizeof(*request), GFP_KERNEL); 
	if (!request) { 
		printk("osc_prep_req: request allocation out of memory\n");
		return NULL;
	}

	rc = ost_pack_req(NULL, 0, NULL, 0, 
			  &request->rq_reqhdr, &request->rq_req, 
			  &request->rq_reqlen, &request->rq_reqbuf);
	if (rc) { 
		printk("llight request: cannot pack request %d\n", rc); 
		return NULL;
	}
	request->rq_reqhdr->opc = opcode;

	EXIT;
	return request;
}

extern int osc_queue_wait(struct obd_conn *conn, struct ost_request *req)
{
	struct obd_device *client = conn->oc_dev;
	struct obd_device *target = client->u.osc.osc_tgt;
	int rc;

	ENTRY;
	/* set the connection id */
	req->rq_req->connid = conn->oc_id;

	CDEBUG(D_INODE, "tgt at %p, conn id %d, opcode %d request at: %p\n", 
	       &conn->oc_dev->u.osc.osc_tgt->u.ost, 
	       conn->oc_id, req->rq_reqhdr->opc, req);

	/* XXX fix the race here (wait_for_event?)*/
	/* hand the packet over to the server */
	rc =  ost_queue_req(target, req); 
	if (rc) { 
		printk("osc_queue_wait: error %d, opcode %d\n", rc, 
		       req->rq_reqhdr->opc); 
		return -rc;
	}

	/* wait for the reply */
	init_waitqueue_head(&req->rq_wait_for_rep);
	interruptible_sleep_on(&req->rq_wait_for_rep);

	ost_unpack_rep(req->rq_repbuf, req->rq_replen, &req->rq_rephdr, 
		       &req->rq_rep); 
	printk("-->osc_queue_wait: buf %p len %d status %d\n", 
	       req->rq_repbuf, req->rq_replen, req->rq_rephdr->status); 

	EXIT;
	return req->rq_rephdr->status;
}

void osc_free_req(struct ost_request *request)
{
	if (request->rq_repbuf)
		kfree(request->rq_repbuf);
	kfree(request);
}


int osc_connect(struct obd_conn *conn)
{
	struct ost_request *request;
	int rc; 
	ENTRY;
	
	request = osc_prep_req(sizeof(*request), OST_CONNECT);
	if (!request) { 
		printk("osc_connect: cannot pack req!\n"); 
		return -ENOMEM;
	}

	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}
      
	CDEBUG(D_INODE, "received connid %d\n", request->rq_rep->connid); 

	conn->oc_id = request->rq_rep->connid;
 out:
	osc_free_req(request);
	EXIT;
	return rc;
}

int osc_disconnect(struct obd_conn *conn)
{
	struct ost_request *request;
	int rc; 
	ENTRY;
	
	request = osc_prep_req(sizeof(*request), OST_DISCONNECT);
	if (!request) { 
		printk("osc_connect: cannot pack req!\n"); 
		return -ENOMEM;
	}

	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}
 out:
	osc_free_req(request);
	EXIT;
	return rc;
}


int osc_getattr(struct obd_conn *conn, struct obdo *oa)
{
	struct ost_request *request;
	int rc; 

	request = osc_prep_req(sizeof(*request), OST_GETATTR);
	if (!request) { 
		printk("osc_connect: cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req->oa, oa, sizeof(*oa));
	request->rq_req->oa.o_valid = ~0;
	
	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}

	CDEBUG(D_INODE, "mode: %o\n", request->rq_rep->oa.o_mode); 
	if (oa) { 
		memcpy(oa, &request->rq_rep->oa, sizeof(*oa));
	}

 out:
	osc_free_req(request);
	return 0;
}

int osc_create(struct obd_conn *conn, struct obdo *oa)
{
	struct ost_request *request;
	int rc; 

	if (!oa) { 
		printk(__FUNCTION__ ": oa NULL\n"); 
	}
	request = osc_prep_req(sizeof(*request), OST_CREATE);
	if (!request) { 
		printk("osc_connect: cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req->oa, oa, sizeof(*oa));
	request->rq_req->oa.o_valid = ~0;
	
	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}
	memcpy(oa, &request->rq_rep->oa, sizeof(*oa));

 out:
	osc_free_req(request);
	return 0;
}


/* mount the file system (secretly) */
static int osc_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct obd_ioctl_data* data = buf;
	struct osc_obd *osc = &obddev->u.osc;
        ENTRY;

	if (data->ioc_dev  < 0 || data->ioc_dev > MAX_OBD_DEVICES) { 
		EXIT;
		return -ENODEV;
	}

        osc->osc_tgt = &obd_dev[data->ioc_dev];
	printk("OSC: tgt %d ost at %p\n", data->ioc_dev, &osc->osc_tgt->u.ost); 
        if ( ! (osc->osc_tgt->obd_flags & OBD_ATTACHED) || 
             ! (osc->osc_tgt->obd_flags & OBD_SET_UP) ){
                printk("device not attached or not set up (%d)\n", 
                       data->ioc_dev);
                EXIT;
		return -EINVAL;
        } 

        MOD_INC_USE_COUNT;
        EXIT; 
        return 0;
} 


static int osc_cleanup(struct obd_device * obddev)
{
        ENTRY;

        if ( !(obddev->obd_flags & OBD_SET_UP) ) {
                EXIT;
                return 0;
        }

        MOD_DEC_USE_COUNT;
        EXIT;
        return 0;
}


struct obd_ops osc_obd_ops = { 
	o_setup:   osc_setup,
	o_cleanup: osc_cleanup, 
	o_create: osc_create,
	o_getattr: osc_getattr,
	o_connect: osc_connect,
	o_disconnect: osc_disconnect
};

static int __init osc_init(void)
{
        obd_register_type(&osc_obd_ops, LUSTRE_OSC_NAME);
	return 0;
}

static void __exit osc_exit(void)
{
	obd_unregister_type(LUSTRE_OSC_NAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC) v1.0");
MODULE_LICENSE("GPL"); 

module_init(osc_init);
module_exit(osc_exit);

