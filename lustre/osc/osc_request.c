/* 
 * Copryright (C) 2001 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  Author Peter Braam <braam@clusterfs.com>
 * 
 *  This server is single threaded at present (but can easily be multi
 *  threaded). For testing and management it is treated as an
 *  obd_device, although it does not export a full OBD method table
 *  (the requests are coming in over the wire, so object target
 *  modules do not have a full method table.)
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
#include <asm/segment.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_OSC

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>

extern int ost_queue_req(struct obd_device *, struct ptlrpc_request *);

/* FIXME: this belongs in some sort of service struct */
static int osc_xid = 1;

struct ptlrpc_request *ost_prep_req(int opcode, int buflen1, char *buf1, 
				 int buflen2, char *buf2)
{
	struct ptlrpc_request *request;
	int rc;
	ENTRY; 

	OBD_ALLOC(request, sizeof(*request));
	if (!request) { 
		CERROR("request allocation out of memory\n");
		return NULL;
	}

	memset(request, 0, sizeof(*request));
	request->rq_xid = osc_xid++;

	rc = ost_pack_req(buf1, buflen1,  buf2, buflen2,
			  &request->rq_reqhdr, &request->rq_req.ost, 
			  &request->rq_reqlen, &request->rq_reqbuf);
	if (rc) { 
		CERROR("llight request: cannot pack request %d\n", rc); 
		return NULL;
	}
	request->rq_reqhdr->opc = opcode;

	EXIT;
	return request;
}

/* XXX: unify with mdc_queue_wait */
extern int osc_queue_wait(struct obd_conn *conn, struct ptlrpc_request *req)
{
	struct obd_device *client = conn->oc_dev;
	struct lustre_peer *peer = &conn->oc_dev->u.osc.osc_peer;
	int rc;

	ENTRY;

	/* set the connection id */
	req->rq_req.ost->connid = conn->oc_id;

	/* XXX fix the race here (wait_for_event?)*/
	if (peer == NULL) {
		/* Local delivery */
		CDEBUG(D_INODE, "\n");
		rc = ost_queue_req(client, req); 
	} else {
		/* Remote delivery via portals. */
		req->rq_req_portal = OST_REQUEST_PORTAL;
		req->rq_reply_portal = OST_REPLY_PORTAL;
		rc = ptl_send_rpc(req, peer);
	}
	if (rc) { 
		CERROR("error %d, opcode %d\n", rc, req->rq_reqhdr->opc); 
		return -rc;
	}

	CDEBUG(D_INODE, "tgt at %p, conn id %d, opcode %d request at: %p\n", 
	       &conn->oc_dev->u.osc.osc_tgt->u.ost, 
	       conn->oc_id, req->rq_reqhdr->opc, req);

	/* wait for the reply */
	init_waitqueue_head(&req->rq_wait_for_rep);
	CDEBUG(D_INODE, "-- sleeping\n");
	interruptible_sleep_on(&req->rq_wait_for_rep);
	CDEBUG(D_INODE, "-- done\n");

	rc = ost_unpack_rep(req->rq_repbuf, req->rq_replen, &req->rq_rephdr, 
			    &req->rq_rep.ost); 
	if (rc) {
		CERROR("mds_unpack_rep failed: %d\n", rc);
		return rc;
	}

	if ( req->rq_rephdr->status == 0 )
		CDEBUG(D_INODE, "buf %p len %d status %d\n", 
		       req->rq_repbuf, req->rq_replen, 
		       req->rq_rephdr->status); 

	EXIT;
	return 0;
}

static void osc_free_req(struct ptlrpc_request *request)
{
	OBD_FREE(request, sizeof(*request));
}

static int osc_connect(struct obd_conn *conn)
{
	struct ptlrpc_request *request;
	int rc; 
	ENTRY;
	
	request = ost_prep_req(OST_CONNECT, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}

	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);

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

static int osc_disconnect(struct obd_conn *conn)
{
	struct ptlrpc_request *request;
	int rc; 
	ENTRY;
	
	request = ost_prep_req(OST_DISCONNECT, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}

	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);

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


static int osc_getattr(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	int rc; 

	request = ost_prep_req(OST_GETATTR, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_req.ost->oa.o_valid = ~0;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
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

static int osc_setattr(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	int rc; 

	request = ost_prep_req(OST_SETATTR, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}

 out:
	osc_free_req(request);
	return 0;
}

static int osc_create(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	int rc; 

	if (!oa) { 
		CERROR("oa NULL\n"); 
	}
	request = ost_prep_req(OST_CREATE, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_req.ost->oa.o_valid = ~0;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
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

static int osc_destroy(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	int rc; 

	if (!oa) { 
		CERROR("oa NULL\n"); 
	}
	request = ost_prep_req(OST_DESTROY, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_req.ost->oa.o_valid = ~0;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
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

	if (data->ioc_dev >= 0 && data->ioc_dev < MAX_OBD_DEVICES) {
		/* This is a local connection */
		osc->osc_tgt = &obd_dev[data->ioc_dev];

		CERROR("OSC: tgt %d ost at %p\n", data->ioc_dev,
		       &osc->osc_tgt->u.ost);
		if ( ! (osc->osc_tgt->obd_flags & OBD_ATTACHED) || 
		     ! (osc->osc_tgt->obd_flags & OBD_SET_UP) ){
			CERROR("device not attached or not set up (%d)\n", 
			       data->ioc_dev);
			EXIT;
			return -EINVAL;
		}
	} else {
		int err;
		/* This is a remote connection using Portals */

		/* XXX: this should become something like ioc_inlbuf1 */
		err = kportal_uuid_to_peer("ost", &osc->osc_peer);
		if (err != 0) {
			CERROR("Cannot find 'ost' peer.\n");
			EXIT;
			return -EINVAL;
		}
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

	request = ost_prep_req(OST_BRW, size1, NULL, size2, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}

	n = 0;
	request->rq_req.ost->cmd = rw;
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

	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep) + size2;

	rc = osc_queue_wait(conn, request);
	if (rc) { 
		EXIT;
		goto out;
	}

#if 0
	ptr2 = ost_rep_buf2(request->rq_rep.ost); 
	if (request->rq_rep.ost->buflen2 != n * sizeof(struct niobuf)) { 
		CERROR("buffer length wrong\n"); 
		goto out;
	}

	if (rw == OBD_BRW_READ)
		goto out;

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
#endif

 out:
	if (request->rq_rephdr)
		OBD_FREE(request->rq_rephdr, request->rq_replen);
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
        MOD_DEC_USE_COUNT;
        return 0;
}

struct obd_ops osc_obd_ops = { 
	o_setup:   osc_setup,
	o_cleanup: osc_cleanup, 
	o_create: osc_create,
	o_destroy: osc_destroy,
	o_getattr: osc_getattr,
	o_setattr: osc_setattr,
	o_connect: osc_connect,
	o_disconnect: osc_disconnect,
	o_brw: osc_brw
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

