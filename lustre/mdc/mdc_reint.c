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

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>

extern int mdc_reint(struct lustre_peer *peer, struct ptlrpc_request *request);
extern struct ptlrpc_request *mds_prep_req(int opcode, int namelen, char *name,
                                           int tgtlen, char *tgt);

int mdc_setattr(struct lustre_peer *peer, 
		struct inode *inode, struct iattr *iattr,
		struct mds_rep **rep, struct ptlrep_hdr **hdr)
{
	int rc; 
	struct ptlrpc_request *request;
	struct mds_rec_setattr *rec;

	request = mds_prep_req(MDS_REINT, 0, NULL, sizeof(*rec), NULL);
	if (!request) { 
		printk("mdc request: cannot pack\n");
		return -ENOMEM;
	}

	rec = mds_req_tgt(request->rq_req.mds);
	mds_setattr_pack(rec, inode, iattr); 
	request->rq_req.mds->opcode = HTON__u32(REINT_SETATTR);
	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rc = mdc_reint(peer, request);
	if (rc)
		return rc;

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

	return 0;
}

int mdc_create(struct lustre_peer *peer, 
	       struct inode *dir, const char *name, int namelen, 
	       const char *tgt, int tgtlen, 
	       int mode, __u64 id, __u32 uid, __u32 gid, __u64 time, 
		struct mds_rep **rep, struct ptlrep_hdr **hdr)
{
	int rc; 
	struct ptlrpc_request *request;
	struct mds_rec_create *rec;

	request = mds_prep_req(MDS_REINT, 0, NULL, 
			       sizeof(*rec) + size_round0(namelen) + 
			       size_round0(tgtlen), NULL);
	if (!request) { 
		printk("mdc_create: cannot pack\n");
		return -ENOMEM;
	}

	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rec = mds_req_tgt(request->rq_req.mds);
	mds_create_pack(rec, dir, name, namelen, mode, id, uid, gid, time, 
			tgt, tgtlen); 

	rc = mdc_reint(peer, request);

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

        OBD_FREE(request, sizeof(*request));
	return rc;
}

int mdc_unlink(struct lustre_peer *peer, 
	       struct inode *dir, const char *name, int namelen, 
		struct mds_rep **rep, struct ptlrep_hdr **hdr)
{
	int rc; 
	struct ptlrpc_request *request;
	struct mds_rec_unlink *rec;

	request = mds_prep_req(MDS_REINT, 0, NULL, 
			       sizeof(*rec) + size_round0(namelen), NULL);
	if (!request) { 
		printk("mdc_unlink: cannot pack\n");
		return -ENOMEM;
	}

	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rec = mds_req_tgt(request->rq_req.mds);
	mds_unlink_pack(rec, dir, name, namelen);

	rc = mdc_reint(peer, request);

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

        OBD_FREE(request, sizeof(*request));
	return rc;
}

int mdc_link(struct lustre_peer *peer, struct dentry *src, 
	     struct inode *dir, const char *name, int namelen, 
		struct mds_rep **rep, struct ptlrep_hdr **hdr)
{
	int rc; 
	struct ptlrpc_request *request;
	struct mds_rec_link *rec;

	request = mds_prep_req(MDS_REINT, 0, NULL, 
			       sizeof(*rec) + size_round0(namelen), NULL);
	if (!request) { 
		printk("mdc_link: cannot pack\n");
		return -ENOMEM;
	}

	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rec = mds_req_tgt(request->rq_req.mds);
	mds_link_pack(rec, src->d_inode, dir, name, namelen);

	rc = mdc_reint(peer, request);

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

        OBD_FREE(request, sizeof(*request));
	return rc;
}

int mdc_rename(struct lustre_peer *peer, struct inode *src, 
	       struct inode *tgt, const char *old, int oldlen, 
	       const char *new, int newlen, 
	       struct mds_rep **rep, struct ptlrep_hdr **hdr)
{
	int rc; 
	struct ptlrpc_request *request;
	struct mds_rec_rename *rec;

	request = mds_prep_req(MDS_REINT, 0, NULL, 
			       sizeof(*rec) + size_round0(oldlen)
			       + size_round0(newlen), NULL);
	if (!request) { 
		printk("mdc_link: cannot pack\n");
		return -ENOMEM;
	}

	request->rq_replen = 
		sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

	rec = mds_req_tgt(request->rq_req.mds);
	mds_rename_pack(rec, src, tgt, old, oldlen, new, newlen);

	rc = mdc_reint(peer, request);

	if (rep) { 
		*rep = request->rq_rep.mds;
	}
	if (hdr) { 
		*hdr = request->rq_rephdr;
	}

        OBD_FREE(request, sizeof(*request));
	return rc;
}
