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

extern int ost_queue_req(struct obd_device *, struct ptlrpc_request *);

struct ptlrpc_request *ost_prep_req(int opcode, int buflen1, char *buf1, 
				 int buflen2, char *buf2)
{
	struct ptlrpc_request *request;
	int rc;
	ENTRY; 

	request = (struct ptlrpc_request *)kmalloc(sizeof(*request), GFP_KERNEL); 
	if (!request) { 
		printk("osc_prep_req: request allocation out of memory\n");
		return NULL;
	}

	rc = ost_pack_req(buf1, buflen1,  buf2, buflen2,
			  &request->rq_reqhdr, &request->rq_req.ost, 
			  &request->rq_reqlen, &request->rq_reqbuf);
	if (rc) { 
		printk("llight request: cannot pack request %d\n", rc); 
		return NULL;
	}
	request->rq_reqhdr->opc = opcode;

	EXIT;
	return request;
}

extern int osc_queue_wait(struct obd_conn *conn, struct ptlrpc_request *req)
{
	struct obd_device *client = conn->oc_dev;
	struct obd_device *target = client->u.osc.osc_tgt;
	int rc;

	ENTRY;
	/* set the connection id */
	req->rq_req.ost->connid = conn->oc_id;

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
		       &req->rq_rep.ost); 
	printk("-->osc_queue_wait: buf %p len %d status %d\n", 
	       req->rq_repbuf, req->rq_replen, req->rq_rephdr->status); 

	EXIT;
	return req->rq_rephdr->status;
}

void osc_free_req(struct ptlrpc_request *request)
{
	if (request->rq_repbuf)
		kfree(request->rq_repbuf);
	kfree(request);
}


int osc_connect(struct obd_conn *conn)
{
	struct ptlrpc_request *request;
	int rc; 
	ENTRY;
	
	request = ost_prep_req(OST_CONNECT, 0, NULL, 0, NULL);
	if (!request) { 
		printk("osc_connect: cannot pack req!\n"); 
		return -ENOMEM;
	}

	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}
      
	CDEBUG(D_INODE, "received connid %d\n", request->rq_rep.ost->connid); 

	conn->oc_id = request->rq_rep.ost->connid;
 out:
	osc_free_req(request);
	EXIT;
	return rc;
}

int osc_disconnect(struct obd_conn *conn)
{
	struct ptlrpc_request *request;
	int rc; 
	ENTRY;
	
	request = ost_prep_req(OST_DISCONNECT, 0, NULL, 0, NULL);
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
	struct ptlrpc_request *request;
	int rc; 

	request = ost_prep_req(OST_GETATTR, 0, NULL, 0, NULL);
	if (!request) { 
		printk("osc_connect: cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_req.ost->oa.o_valid = ~0;
	
	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}

	CDEBUG(D_INODE, "mode: %o\n", request->rq_rep.ost->oa.o_mode); 
	if (oa) { 
		memcpy(oa, &request->rq_rep.ost->oa, sizeof(*oa));
	}

 out:
	osc_free_req(request);
	return 0;
}

int osc_create(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	int rc; 

	if (!oa) { 
		printk(__FUNCTION__ ": oa NULL\n"); 
	}
	request = ost_prep_req(OST_CREATE, 0, NULL, 0, NULL);
	if (!request) { 
		printk("osc_connect: cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_req.ost->oa.o_valid = ~0;
	
	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}
	memcpy(oa, &request->rq_rep.ost->oa, sizeof(*oa));

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

void osc_sendpage(struct niobuf *dst, struct niobuf *src)
{
	memcpy((char *)(unsigned long)dst->addr,  
	       (char *)(unsigned long)src->addr, 
	       src->len);
	return;
}


int osc_brw(int rw, struct obd_conn *conn, obd_count num_oa,
	      struct obdo **oa, obd_count *oa_bufs, struct page **buf,
	      obd_size *count, obd_off *offset, obd_flag *flags)
{
	struct ptlrpc_request *request;
	int rc; 
	struct obd_ioobj ioo;
	struct niobuf src;
	int size1, size2 = 0; 
	void *ptr1, *ptr2;
	int i, j, n;

	size1 = num_oa * sizeof(ioo); 
	for (i = 0; i < num_oa; i++) { 
		size2 += oa_bufs[i] * sizeof(src);
	}

	request = ost_prep_req(OST_PREPW, size1, NULL, size2, NULL);
	if (!request) { 
		printk("osc_connect: cannot pack req!\n"); 
		return -ENOMEM;
	}

	n = 0;
	ptr1 = ost_req_buf1(request->rq_req.ost);
	ptr2 = ost_req_buf2(request->rq_req.ost);
	for (i=0; i < num_oa; i++) { 
		ost_pack_ioo(&ptr1, oa[i], oa_bufs[i]); 
		for (j = 0 ; j < oa_bufs[i] ; j++) { 
			ost_pack_niobuf(&ptr2, kmap(buf[n]), offset[n],
					count[n], flags[n]); 
			n++;
		}
	}

	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}

	ptr2 = ost_rep_buf2(request->rq_rep.ost); 
	if (request->rq_rep.ost->buflen2 != n * sizeof(struct niobuf)) { 
		printk(__FUNCTION__ ": buffer length wrong\n"); 
		goto out;
	}

	for (i=0; i < num_oa; i++) { 
		for (j = 0 ; j < oa_bufs[i] ; j++) { 
			struct niobuf *dst;
			src.addr = (__u64)(unsigned long)buf[n];
			src.len = count[n];
			ost_unpack_niobuf(&ptr2, &dst);
			osc_sendpage(dst, &src);
			n++;
		}
	}
	//ost_complete_brw(rep); 

 out:
	if (request->rq_rephdr)
		kfree(request->rq_rephdr);
	n = 0;
	for (i=0; i < num_oa; i++) { 
		for (j = 0 ; j < oa_bufs[i] ; j++) { 
			kunmap(buf[n]);
			n++;
		}
	}

	osc_free_req(request);
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

