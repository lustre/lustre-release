/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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

struct ptlrpc_client *osc_con2cl(struct obd_conn *conn)
{
	struct osc_obd *osc = &conn->oc_dev->u.osc;
	return &osc->osc_peer;

}

static int osc_connect(struct obd_conn *conn)
{
	struct ptlrpc_request *request;
	struct ptlrpc_client *peer = osc_con2cl(conn);
	int rc; 
	ENTRY;
	
	request = ptlrpc_prep_req(peer, OST_CONNECT, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}

	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);

	rc = ptlrpc_queue_wait(peer, request);
	if (rc) { 
		EXIT;
		goto out;
	}
      
	CDEBUG(D_INODE, "received connid %d\n", request->rq_rep.ost->connid); 

	conn->oc_id = request->rq_rep.ost->connid;
 out:
	ptlrpc_free_req(request);
	EXIT;
	return rc;
}

static int osc_disconnect(struct obd_conn *conn)
{
	struct ptlrpc_request *request;
	struct ptlrpc_client *peer = osc_con2cl(conn);
	int rc; 
	ENTRY;
	
	request = ptlrpc_prep_req(peer, OST_DISCONNECT, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	request->rq_req.ost->connid = conn->oc_id;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);

	rc = ptlrpc_queue_wait(peer, request);
	if (rc) { 
		EXIT;
		goto out;
	}
 out:
	ptlrpc_free_req(request);
	EXIT;
	return rc;
}


static int osc_getattr(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	struct ptlrpc_client *peer = osc_con2cl(conn);
	int rc; 

	request = ptlrpc_prep_req(peer, OST_GETATTR, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_req.ost->oa.o_valid = ~0;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
	rc = ptlrpc_queue_wait(peer, request);
	if (rc) { 
		EXIT;
		goto out;
	}

	CDEBUG(D_INODE, "mode: %o\n", request->rq_rep.ost->oa.o_mode); 
	if (oa) { 
		memcpy(oa, &request->rq_rep.ost->oa, sizeof(*oa));
	}

 out:
	ptlrpc_free_req(request);
	return 0;
}

static int osc_setattr(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	struct ptlrpc_client *peer = osc_con2cl(conn);
	int rc; 

	request = ptlrpc_prep_req(peer, OST_SETATTR, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
	rc = ptlrpc_queue_wait(peer, request);
	if (rc) { 
		EXIT;
		goto out;
	}

 out:
	ptlrpc_free_req(request);
	return 0;
}

static int osc_create(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	struct ptlrpc_client *peer = osc_con2cl(conn);
	int rc; 

	if (!oa) { 
		CERROR("oa NULL\n"); 
	}
	request = ptlrpc_prep_req(peer, OST_CREATE, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
        request->rq_req.ost->connid = conn->oc_id;
	request->rq_req.ost->oa.o_valid = ~0;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
	rc = ptlrpc_queue_wait(peer, request);
	if (rc) { 
		EXIT;
		goto out;
	}
	memcpy(oa, &request->rq_rep.ost->oa, sizeof(*oa));

 out:
	ptlrpc_free_req(request);
	return 0;
}

static int osc_punch(struct obd_conn *conn, struct obdo *oa, obd_size count,
                     obd_off offset)
{
	struct ptlrpc_request *request;
	struct ptlrpc_client *peer = osc_con2cl(conn);
	int rc; 

	if (!oa) { 
		CERROR("oa NULL\n"); 
	}
	request = ptlrpc_prep_req(peer, OST_PUNCH, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_req.ost->oa.o_valid = ~0;
	request->rq_req.ost->oa.o_size = offset;
	request->rq_req.ost->oa.o_blocks = count;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
	rc = ptlrpc_queue_wait(peer, request);
	if (rc) { 
		EXIT;
		goto out;
	}
	memcpy(oa, &request->rq_rep.ost->oa, sizeof(*oa));

 out:
	ptlrpc_free_req(request);
	return 0;
}

static int osc_destroy(struct obd_conn *conn, struct obdo *oa)
{
	struct ptlrpc_request *request;
	struct ptlrpc_client *peer = osc_con2cl(conn);
	int rc; 

	if (!oa) { 
		CERROR("oa NULL\n"); 
	}
	request = ptlrpc_prep_req(peer, OST_DESTROY, 0, NULL, 0, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
	
	memcpy(&request->rq_req.ost->oa, oa, sizeof(*oa));
	request->rq_req.ost->oa.o_valid = ~0;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
	
	rc = ptlrpc_queue_wait(peer, request);
	if (rc) { 
		EXIT;
		goto out;
	}
	memcpy(oa, &request->rq_rep.ost->oa, sizeof(*oa));

 out:
	ptlrpc_free_req(request);
	return 0;
}

int osc_sendpage(struct obd_conn *conn, struct ptlrpc_request *req,
                 struct niobuf *dst, struct niobuf *src)
{
        struct ptlrpc_client *cl = osc_con2cl(conn);

        if (cl->cli_obd) {
                /* local sendpage */
                memcpy((char *)(unsigned long)dst->addr,
                       (char *)(unsigned long)src->addr, src->len);
        } else {
                struct ptlrpc_bulk_desc *bulk;
                int rc;

                bulk = ptlrpc_prep_bulk(&cl->cli_server);
                if (bulk == NULL)
                        return -ENOMEM;

                bulk->b_buf = (void *)(unsigned long)src->addr;
                bulk->b_buflen = src->len;
                bulk->b_xid = dst->xid;
		rc = ptlrpc_send_bulk(bulk, OSC_BULK_PORTAL);
                if (rc != 0) {
                        CERROR("send_bulk failed: %d\n", rc);
                        BUG();
                        return rc;
                }
                wait_event_interruptible(bulk->b_waitq,
                                         ptlrpc_check_bulk_sent(bulk));

                if (bulk->b_flags == PTL_RPC_INTR) {
                        EXIT;
                        /* FIXME: hey hey, we leak here. */
                        return -EINTR;
                }

                OBD_FREE(bulk, sizeof(*bulk));
        }

        return 0;
}

int osc_brw_read(struct obd_conn *conn, obd_count num_oa, struct obdo **oa,
                 obd_count *oa_bufs, struct page **buf, obd_size *count,
                 obd_off *offset, obd_flag *flags)
{
	struct ptlrpc_client *cl = osc_con2cl(conn);
        struct ptlrpc_request *request;
        int pages;
	int rc; 
	struct obd_ioobj ioo;
	struct niobuf src;
	int size1, size2 = 0; 
	void *ptr1, *ptr2;
	int i, j, n;
        struct ptlrpc_bulk_desc **bulk;

	size1 = num_oa * sizeof(ioo); 
        pages = 0;
        for (i = 0; i < num_oa; i++)
                pages += oa_bufs[i];
        size2 = pages * sizeof(src);

	request = ptlrpc_prep_req(cl, OST_BRW, size1, NULL, size2, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
        request->rq_req.ost->cmd = OBD_BRW_READ;

        OBD_ALLOC(bulk, pages * sizeof(struct ptlrpc_bulk_desc *));
        if (bulk == NULL) {
                CERROR("cannot alloc bulk desc vector\n");
                return -ENOMEM;
        }
        memset(bulk, 0, pages * sizeof(struct ptlrpc_bulk_desc *));

        n = 0;
        ptr1 = ost_req_buf1(request->rq_req.ost);
        ptr2 = ost_req_buf2(request->rq_req.ost);
        for (i = 0; i < num_oa; i++) {
                ost_pack_ioo(&ptr1, oa[i], oa_bufs[i]); 
                for (j = 0; j < oa_bufs[i]; j++) {
                        bulk[n] = ptlrpc_prep_bulk(&cl->cli_server);
                        if (bulk[n] == NULL) {
                                CERROR("cannot alloc bulk desc\n");
                                rc = -ENOMEM;
                                goto out;
                        }

                        spin_lock(&cl->cli_lock);
                        bulk[n]->b_xid = cl->cli_xid++;
                        spin_unlock(&cl->cli_lock);
                        bulk[n]->b_buf = kmap(buf[n]);
                        bulk[n]->b_buflen = PAGE_SIZE;
                        bulk[n]->b_portal = OST_BULK_PORTAL;
                        ost_pack_niobuf(&ptr2, bulk[n]->b_buf, offset[n],
                                        count[n], flags[n], bulk[n]->b_xid);

                        rc = ptlrpc_register_bulk(bulk[n]);
                        if (rc)
                                goto out;
                        n++;
                }
        }

        request->rq_replen = sizeof(struct ptlrep_hdr) + sizeof(struct ost_rep);
        rc = ptlrpc_queue_wait(cl, request);

 out:
        /* FIXME: if we've called ptlrpc_wait_bulk but rc != 0, we need to
         * abort those bulk listeners. */

        n = 0;
        for (i = 0; i < num_oa; i++) {
                for (j = 0; j < oa_bufs[i]; j++) {
                        if (bulk[n] == NULL)
                                continue;
                        kunmap(buf[n]);
                        OBD_FREE(bulk[n], sizeof(struct ptlrpc_bulk_desc));
                        n++;
                }
        }

        OBD_FREE(bulk, pages * sizeof(struct ptlrpc_bulk_desc *));
        ptlrpc_free_req(request);
        return rc;
}

int osc_brw_write(struct obd_conn *conn, obd_count num_oa, struct obdo **oa,
                  obd_count *oa_bufs, struct page **buf, obd_size *count,
                  obd_off *offset, obd_flag *flags)
{
	struct ptlrpc_client *cl = osc_con2cl(conn);
        struct ptlrpc_request *request;
	struct obd_ioobj ioo;
	struct niobuf *src;
	int pages, rc, i, j, n, size1, size2 = 0; 
	void *ptr1, *ptr2;

	size1 = num_oa * sizeof(ioo); 
        pages = 0;
        for (i = 0; i < num_oa; i++)
                pages += oa_bufs[i];
        size2 = pages * sizeof(*src);

        OBD_ALLOC(src, size2);
        if (!src) { 
                CERROR("no src memory\n");
                return -ENOMEM;
        }
        memset((char *)src, 0, size2);

	request = ptlrpc_prep_req(cl, OST_BRW, size1, NULL, size2, NULL);
	if (!request) { 
		CERROR("cannot pack req!\n"); 
		return -ENOMEM;
	}
        request->rq_req.ost->cmd = OBD_BRW_WRITE;

	n = 0;
	ptr1 = ost_req_buf1(request->rq_req.ost);
	ptr2 = ost_req_buf2(request->rq_req.ost);
        for (i = 0; i < num_oa; i++) {
		ost_pack_ioo(&ptr1, oa[i], oa_bufs[i]); 
                for (j = 0; j < oa_bufs[i]; j++) {
                        ost_pack_niobuf(&ptr2, kmap(buf[n]), offset[n],
                                        count[n], flags[n], 0);
			n++;
		}
	}
        memcpy((char *)src, (char *)ost_req_buf2(request->rq_req.ost), size2); 

	request->rq_replen = sizeof(struct ptlrep_hdr) +
                sizeof(struct ost_rep) + pages * sizeof(struct niobuf);
	rc = ptlrpc_queue_wait(cl, request);
	if (rc) { 
		EXIT;
		goto out;
	}

        ptr2 = ost_rep_buf2(request->rq_rep.ost);
        if (request->rq_rep.ost->buflen2 != n * sizeof(struct niobuf)) {
                CERROR("buffer length wrong (%d vs. %d)\n",
                       request->rq_rep.ost->buflen2, n * sizeof(struct niobuf));
                EXIT;
                goto out;
        }

        n = 0;
        for (i = 0; i < num_oa; i++) {
                for (j = 0; j < oa_bufs[i]; j++) {
			struct niobuf *dst;
			ost_unpack_niobuf(&ptr2, &dst);
			osc_sendpage(conn, request, dst, &src[n]);
			n++;
		}
	}
        OBD_FREE(src, size2);
 out:
	n = 0;
        for (i = 0; i < num_oa; i++) {
                for (j = 0; j < oa_bufs[i]; j++) {
			kunmap(buf[n]);
			n++;
		}
	}

	ptlrpc_free_req(request);
	return 0;
}

int osc_brw(int rw, struct obd_conn *conn, obd_count num_oa,
	      struct obdo **oa, obd_count *oa_bufs, struct page **buf,
	      obd_size *count, obd_off *offset, obd_flag *flags)
{
        if (rw == OBD_BRW_READ) {
                return osc_brw_read(conn, num_oa, oa, oa_bufs, buf, count,
                                    offset, flags);
        } else {
                return osc_brw_write(conn, num_oa, oa, oa_bufs, buf, count,
                                     offset, flags);
        }
}

/* mount the file system (secretly) */
static int osc_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct osc_obd *osc = &obddev->u.osc;
	struct obd_ioctl_data *data = (struct obd_ioctl_data *)buf;
	int rc;
	int dev = data->ioc_dev;
        ENTRY;

	rc = ptlrpc_connect_client(dev, "ost", 
				   OST_REQUEST_PORTAL, 
				   OSC_REPLY_PORTAL,    
				   ost_pack_req, 
				   ost_unpack_rep,
				   &osc->osc_peer); 

        MOD_INC_USE_COUNT;
        EXIT;
        return rc;
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
	o_brw: osc_brw,
	o_punch: osc_punch
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
