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
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>

#define REQUEST_MINOR 244

extern int mds_queue_req(struct ptlrpc_request *);


int mdc_getattr(struct ptlrpc_client *cl, ino_t ino, int type, int valid, 
		struct mds_rep  **rep, struct ptlrep_hdr **hdr)
{
	struct ptlrpc_request *request;
	int rc; 

	request = ptlrpc_prep_req(cl, MDS_GETATTR, 0, NULL, 0, NULL); 
	if (!request) { 
		CERROR("llight request: cannot pack\n");
		return -ENOMEM;
	}

	ll_ino2fid(&request->rq_req.mds->fid1, ino, 0, type);

	request->rq_req.mds->valid = valid;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rc = ptlrpc_queue_wait(cl, request);
	if (rc) { 
		CERROR("llight request: error in handling %d\n", rc); 
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
	ptlrpc_free_req(request);
	return rc;
}

int mdc_open(struct ptlrpc_client *cl, ino_t ino, int type, int flags,
                __u64 *fh, struct mds_rep  **rep, struct ptlrep_hdr **hdr)
{
	struct ptlrpc_request *request;
	int rc; 

	request = ptlrpc_prep_req(cl, MDS_OPEN, 0, NULL, 0, NULL); 
	if (!request) { 
		CERROR("llight request: cannot pack\n");
		return -ENOMEM;
	}

	ll_ino2fid(&request->rq_req.mds->fid1, ino, 0, type);
        request->rq_req.mds->flags = flags;
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rc = ptlrpc_queue_wait(cl, request);
	if (rc) { 
		CERROR("llight request: error in handling %d\n", rc); 
		goto out;
	}

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}
        *fh = request->rq_rep.mds->objid; 

 out: 
	ptlrpc_free_req(request);
	return rc;
}


int mdc_close(struct ptlrpc_client *cl, ino_t ino, int type, __u64 fh, 
		struct mds_rep  **rep, struct ptlrep_hdr **hdr)
{
	struct ptlrpc_request *request;
	int rc; 

	request = ptlrpc_prep_req(cl, MDS_CLOSE, 0, NULL, 0, NULL); 
	if (!request) { 
		CERROR("llight request: cannot pack\n");
		return -ENOMEM;
	}

	ll_ino2fid(&request->rq_req.mds->fid1, ino, 0, type);
        request->rq_req.mds->objid = fh; 
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rc = ptlrpc_queue_wait(cl, request);
	if (rc) { 
		CERROR("llight request: error in handling %d\n", rc); 
		goto out;
	}

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

 out: 
	ptlrpc_free_req(request);
	return rc;
}

int mdc_readpage(struct ptlrpc_client *cl, ino_t ino, int type, __u64 offset,
		 char *addr, struct mds_rep  **rep, struct ptlrep_hdr **hdr)
{
	struct ptlrpc_request *request;
        struct ptlrpc_bulk_desc *bulk;
	struct niobuf niobuf;
	int rc; 

	niobuf.addr = (__u64) (long) addr;

        CDEBUG(D_INODE, "inode: %ld\n", ino);

        bulk = ptlrpc_prep_bulk(&cl->cli_server);
        if (bulk == NULL) {
                CERROR("%s: cannot init bulk desc\n", __FUNCTION__);
                return -ENOMEM;
        }

	request = ptlrpc_prep_req(cl, MDS_READPAGE, 0, NULL,
                                  sizeof(struct niobuf), (char *)&niobuf);
	if (!request) { 
                OBD_FREE(bulk, sizeof(*bulk));
		CERROR("%s: cannot pack\n", __FUNCTION__);
		return -ENOMEM;
	}

        bulk->b_buflen = PAGE_SIZE;
        bulk->b_buf = (void *)(long)niobuf.addr;
	bulk->b_portal = MDS_BULK_PORTAL;
        bulk->b_xid = request->rq_xid;

        rc = ptlrpc_register_bulk(bulk);
        if (rc) {
                CERROR("%s: couldn't setup bulk sink: error %d.\n",
                       __FUNCTION__, rc);
                goto out;
        }

	request->rq_req.mds->fid1.id = ino;
	request->rq_req.mds->fid1.f_type = type;
	request->rq_req.mds->size = offset;
	request->rq_req.mds->tgtlen = sizeof(niobuf); 
	request->rq_replen = sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rc = ptlrpc_queue_wait(cl, request);
	if (rc) { 
		CERROR("mdc request: error in handling %d\n", rc); 
		goto out;
	}

        CDEBUG(D_INODE, "mode: %o\n", request->rq_rep.mds->mode);

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

 out:
	ptlrpc_free_req(request);
        OBD_FREE(bulk, sizeof(*bulk));
	return rc;
}

int mdc_reint(struct ptlrpc_client *cl, struct ptlrpc_request *request)
{
	int rc; 

	rc = ptlrpc_queue_wait(cl, request);
	if (rc) { 
		CERROR("mdc request: error in handling %d\n", rc); 
	}

	return rc;
}

static int request_ioctl(struct inode *inode, struct file *file, 
                         unsigned int cmd, unsigned long arg)
{
	int err;
	struct ptlrpc_client cl;

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

        /* XXX complete this to get debugging working again */
        err = -1;
	if (err) {
                CERROR("cannot create client"); 
                return -EINVAL;
        }
	
	switch (cmd) {
	case IOC_REQUEST_GETATTR: { 
		struct ptlrep_hdr *hdr = NULL;
		CERROR("-- getting attr for ino 2\n"); 
		err = mdc_getattr(&cl, 2, S_IFDIR, ~0, NULL, &hdr);
		if (hdr) {
                        /* FIXME: there must be a better way to get the size */
			OBD_FREE(hdr, sizeof(struct ptlrep_hdr) +
                                 sizeof(struct mds_rep));
                }
		CERROR("-- done err %d\n", err);
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
		CERROR("-- readpage 0 for ino 2\n"); 
		err = mdc_readpage(&cl, 2, S_IFDIR, 0, buf, NULL, &hdr);
		CERROR("-- done err %d\n", err);
		if (!err) { 
			CERROR("-- status: %d\n", hdr->status); 
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

		err = mdc_setattr(&cl, &inode, &iattr, NULL, &hdr);
		CERROR("-- done err %d\n", err);
		if (!err) { 
			CERROR("-- status: %d\n", hdr->status); 
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

		err = mdc_create(&cl, &inode, 
				 "foofile", strlen("foofile"), 
				 NULL, 0, 0100707, 47114711, 
				 11, 47, 0, NULL, &hdr);
		CERROR("-- done err %d\n", err);
		if (!err) { 
			CERROR("-- status: %d\n", hdr->status); 
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
