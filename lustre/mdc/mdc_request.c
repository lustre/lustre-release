/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include <linux/module.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>

#define REQUEST_MINOR 244

extern int mds_queue_req(struct ptlrpc_request *);

/* FIXME: this belongs in some sort of service struct */
static int mdc_xid = 0;

struct ptlrpc_request *mds_prep_req(int opcode, int namelen, char *name,
                                    int tgtlen, char *tgt)
{
	struct ptlrpc_request *request;
	int rc;
	ENTRY; 

	OBD_ALLOC(request, sizeof(*request));
	if (!request) { 
		printk("mds_prep_req: request allocation out of memory\n");
		return NULL;
	}

	memset(request, 0, sizeof(*request));
	request->rq_xid = mdc_xid++;

	rc = mds_pack_req(name, namelen, tgt, tgtlen,
			  &request->rq_reqhdr, &(request->rq_req.mds),
			  &request->rq_reqlen, &request->rq_reqbuf);
	if (rc) { 
		printk("llight request: cannot pack request %d\n", rc); 
		return NULL;
	}
        CDEBUG(0, "--> mds_prep_req: len %d, req %p, tgtlen %d\n", 
	       request->rq_reqlen, request->rq_req.mds, 
	       request->rq_req.mds->tgtlen);
	request->rq_reqhdr->opc = opcode;

	EXIT;
	return request;
}

static int mds_queue_wait(struct ptlrpc_request *req, struct lustre_peer *peer)
{
	int rc;

	/* XXX fix the race here (wait_for_event?)*/
	if (peer == NULL) {
		/* Local delivery */
                ENTRY;
		rc = mds_queue_req(req); 
	} else {
		/* Remote delivery via portals. */
		req->rq_req_portal = MDS_REQUEST_PORTAL;
		req->rq_reply_portal = MDS_REPLY_PORTAL;
		rc = ptl_send_rpc(req, peer);
	}
	if (rc) { 
		printk(__FUNCTION__ ": error %d, opcode %d\n", rc, 
		       req->rq_reqhdr->opc); 
		return -rc;
	}

	init_waitqueue_head(&req->rq_wait_for_rep);
        CDEBUG(0, "-- sleeping\n");
	interruptible_sleep_on(&req->rq_wait_for_rep);
        CDEBUG(0, "-- done\n");

	rc = mds_unpack_rep(req->rq_repbuf, req->rq_replen, &req->rq_rephdr, 
			    &req->rq_rep.mds);
	if (rc) {
		printk(__FUNCTION__ ": mds_unpack_rep failed: %d\n", rc);
		return rc;
	}

	if ( req->rq_rephdr->status == 0 )
                CDEBUG(0, "--> buf %p len %d status %d\n",
		       req->rq_repbuf, req->rq_replen, 
		       req->rq_rephdr->status); 

	EXIT;
	return 0;
}

void mdc_free_req(struct ptlrpc_request *request)
{
	OBD_FREE(request, sizeof(*request));
}

int mdc_getattr(struct lustre_peer *peer, ino_t ino, int type, int valid, 
		struct mds_rep  **rep, struct ptlrep_hdr **hdr)
{
	struct ptlrpc_request *request;
	int rc; 

	request = mds_prep_req(MDS_GETATTR, 0, NULL, 0, NULL); 
	if (!request) { 
		printk("llight request: cannot pack\n");
		return -ENOMEM;
	}

	ll_ino2fid(&request->rq_req.mds->fid1, ino, 0, type);

	request->rq_req.mds->valid = valid;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rc = mds_queue_wait(request, peer);
	if (rc) { 
		printk("llight request: error in handling %d\n", rc); 
		goto out;
	}

        CDEBUG(0, "mode: %o\n", request->rq_rep.mds->mode);

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

 out: 
	mdc_free_req(request);
	return rc;
}

int mdc_readpage(struct lustre_peer *peer, ino_t ino, int type, __u64 offset,
		 char *addr, struct mds_rep  **rep, struct ptlrep_hdr **hdr)
{
	struct ptlrpc_request *request;
	struct niobuf niobuf;
	int rc; 

	niobuf.addr = (__u64) (long) addr;

        CDEBUG(D_INODE, "inode: %ld\n", ino);

	request = mds_prep_req(MDS_READPAGE, 0, NULL,
			       sizeof(struct niobuf), (char *)&niobuf);
	if (!request) { 
		printk("mdc request: cannot pack\n");
		return -ENOMEM;
	}

	request->rq_req.mds->fid1.id = ino;
	request->rq_req.mds->fid1.f_type = type;
	request->rq_req.mds->size = offset;
	request->rq_req.mds->tgtlen = sizeof(niobuf); 

	request->rq_bulk_portal = MDS_BULK_PORTAL;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rc = mds_queue_wait(request, peer);
	if (rc) { 
		printk("mdc request: error in handling %d\n", rc); 
		goto out;
	}

        CDEBUG(0, "mode: %o\n", request->rq_rep.mds->mode);

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

 out: 
	mdc_free_req(request);
	return rc;
}

int mdc_reint(struct lustre_peer *peer, struct ptlrpc_request *request)
{
	int rc; 

	rc = mds_queue_wait(request, peer);
	if (rc) { 
		printk("mdc request: error in handling %d\n", rc); 
	}

	return rc;
}


static int request_ioctl(struct inode *inode, struct file *file, 
                         unsigned int cmd, unsigned long arg)
{
	int err;
	struct lustre_peer peer, *peer_ptr = NULL;

	ENTRY;

	if (MINOR(inode->i_rdev) != REQUEST_MINOR) {
		EXIT;
		return -EINVAL;
	}

	if ( _IOC_TYPE(cmd) != IOC_REQUEST_TYPE || 
             _IOC_NR(cmd) < IOC_REQUEST_MIN_NR  || 
             _IOC_NR(cmd) > IOC_REQUEST_MAX_NR ) {
                CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
                                _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
                EXIT;
                return -EINVAL;
        }

	err = kportal_uuid_to_peer("mds", &peer);
	if (err == 0)
		peer_ptr = &peer;
	
	switch (cmd) {
	case IOC_REQUEST_GETATTR: { 
		struct ptlrep_hdr *hdr = NULL;
		printk("-- getting attr for ino 2\n"); 
		err = mdc_getattr(peer_ptr, 2, S_IFDIR, ~0, NULL, &hdr);
		if (hdr) {
                        /* FIXME: there must be a better way to get the size */
			OBD_FREE(hdr, sizeof(struct ptlrep_hdr) +
                                 sizeof(struct mds_rep));
                }
		printk("-- done err %d\n", err);
		break;
	}

	case IOC_REQUEST_READPAGE: { 
		struct ptlrep_hdr *hdr = NULL;
		char *buf;
		OBD_ALLOC(buf, PAGE_SIZE);
		if (!buf) { 
			err = -ENOMEM;
			break;
		}
		printk("-- readpage 0 for ino 2\n"); 
		err = mdc_readpage(peer_ptr, 2, S_IFDIR, 0, buf, NULL, &hdr);
		printk("-- done err %d\n", err);
		if (!err) { 
			printk("-- status: %d\n", hdr->status); 
			err = hdr->status;
                        if (hdr)
                                OBD_FREE(hdr, sizeof(struct ptlrep_hdr) +
                                         sizeof(struct mds_rep));
		}
		OBD_FREE(buf, PAGE_SIZE);
		break;
	}

	case IOC_REQUEST_SETATTR: { 
		struct inode inode;
		struct ptlrep_hdr *hdr;
		struct iattr iattr; 

		inode.i_ino = 2;
		iattr.ia_mode = 040777;
		iattr.ia_atime = 0;
		iattr.ia_valid = ATTR_MODE | ATTR_ATIME;

		err = mdc_setattr(peer_ptr, &inode, &iattr, NULL, &hdr);
		printk("-- done err %d\n", err);
		if (!err) { 
			printk("-- status: %d\n", hdr->status); 
			err = hdr->status;
		} else {
                        OBD_FREE(hdr, sizeof(struct ptlrep_hdr) +
                                 sizeof(struct mds_rep));
		}
		break;
	}

	case IOC_REQUEST_CREATE: { 
		struct inode inode;
		struct ptlrep_hdr *hdr;
		struct iattr iattr; 

		inode.i_ino = 2;
		iattr.ia_mode = 040777;
		iattr.ia_atime = 0;
		iattr.ia_valid = ATTR_MODE | ATTR_ATIME;

		err = mdc_create(peer_ptr, &inode, 
				 "foofile", strlen("foofile"), 
				 NULL, 0, 0100707, 47114711, 
				 11, 47, 0, NULL, &hdr);
		printk("-- done err %d\n", err);
		if (!err) { 
			printk("-- status: %d\n", hdr->status); 
			err = hdr->status;
		}
                OBD_FREE(hdr, sizeof(struct ptlrep_hdr) +
                         sizeof(struct mds_rep));
		break;
	}

	default:		
		err = -EINVAL;
		EXIT;
		break;
	}
	EXIT;
	return err;
}


static struct file_operations requestdev_fops = {
	ioctl: request_ioctl,
};


static struct miscdevice request_dev = {
	REQUEST_MINOR,
	"request",
	&requestdev_fops
};


static int __init ptlrpc_request_init(void)
{
	misc_register(&request_dev);
        return 0 ;
}


static void __exit ptlrpc_request_exit(void)
{
	misc_deregister(&request_dev);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre MDS Request Tester v1.0");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mdc_create); 
EXPORT_SYMBOL(mdc_unlink); 
EXPORT_SYMBOL(mdc_rename); 
EXPORT_SYMBOL(mdc_link); 
EXPORT_SYMBOL(mdc_getattr); 
EXPORT_SYMBOL(mdc_readpage); 
EXPORT_SYMBOL(mdc_setattr); 

module_init(ptlrpc_request_init);
module_exit(ptlrpc_request_exit);
