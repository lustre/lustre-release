/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/obd_class.h>
#include <linux/lustre_mds.h>

static int mdc_reint(struct ptlrpc_client *cl, struct ptlrpc_request *request)
{
        int rc; 

        rc = ptlrpc_queue_wait(cl, request);
        if (rc)
                CERROR("error in handling %d\n", rc); 

        return rc;
}

int mdc_setattr(struct ptlrpc_client *peer, 
                struct inode *inode, struct iattr *iattr,
                struct ptlrpc_request **request)
{
        int rc; 
        struct mds_rec_setattr *rec;
        ENTRY;

        *request = ptlrpc_prep_req(peer, MDS_REINT, 0, NULL,
                                   sizeof(*rec), NULL);
        if (!(*request)) { 
                CERROR("cannot pack\n");
                EXIT;
                return -ENOMEM;
        }

        rec = mds_req_tgt((*request)->rq_req.mds);
        mds_setattr_pack(rec, inode, iattr); 
        (*request)->rq_req.mds->opcode = HTON__u32(REINT_SETATTR);
        (*request)->rq_replen = 
                sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rc = mdc_reint(peer, *request);

        EXIT;
        return rc;
}

int mdc_create(struct ptlrpc_client *peer, 
               struct inode *dir, const char *name, int namelen, 
               const char *tgt, int tgtlen, 
               int mode, __u64 id, __u32 uid, __u32 gid, __u64 time, 
               struct ptlrpc_request **request)
{
        int rc; 
        struct mds_rec_create *rec;
        ENTRY;

        (*request) = ptlrpc_prep_req(peer, MDS_REINT, 0, NULL, 
                               sizeof(*rec) + size_round0(namelen) + 
                               size_round0(tgtlen), NULL);
        if (!(*request)) { 
                CERROR("cannot pack\n");
                return -ENOMEM;
        }

        (*request)->rq_replen = 
                sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rec = mds_req_tgt((*request)->rq_req.mds);
        mds_create_pack(rec, dir, name, namelen, mode, id, uid, gid, time, 
                        tgt, tgtlen); 

        rc = mdc_reint(peer, (*request));

        EXIT;
        return rc;
}

int mdc_unlink(struct ptlrpc_client *peer,  struct inode *dir,
               struct inode *child, const char *name, int namelen, 
               struct ptlrpc_request **request)
{
        int rc; 
        struct mds_rec_unlink *rec;

        (*request) = ptlrpc_prep_req(peer, MDS_REINT, 0, NULL, 
                                     sizeof(*rec) + size_round0(namelen), NULL);
        if (!(*request)) { 
                CERROR("cannot pack\n");
                return -ENOMEM;
        }

        (*request)->rq_replen = 
                sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rec = mds_req_tgt((*request)->rq_req.mds);
        mds_unlink_pack(rec, dir, child, name, namelen);

        rc = mdc_reint(peer, (*request));

        EXIT;
        return rc;
}

int mdc_link(struct ptlrpc_client *peer, struct dentry *src, 
             struct inode *dir, const char *name, int namelen, 
             struct ptlrpc_request **request)
{
        int rc; 
        struct mds_rec_link *rec;
        ENTRY;

        (*request) = ptlrpc_prep_req(peer, MDS_REINT, 0, NULL, 
                               sizeof(*rec) + size_round0(namelen), NULL);
        if (!(*request)) { 
                CERROR("cannot pack\n");
                return -ENOMEM;
        }

        (*request)->rq_replen = 
                sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rec = mds_req_tgt((*request)->rq_req.mds);
        mds_link_pack(rec, src->d_inode, dir, name, namelen);

        rc = mdc_reint(peer, (*request));
        EXIT;
        return rc;
}

int mdc_rename(struct ptlrpc_client *peer, struct inode *src, 
               struct inode *tgt, const char *old, int oldlen, 
               const char *new, int newlen, 
               struct ptlrpc_request **request)
{
        int rc; 
        struct mds_rec_rename *rec;
        ENTRY;

        (*request) = ptlrpc_prep_req(peer, MDS_REINT, 0, NULL, 
                               sizeof(*rec) + size_round0(oldlen)
                               + size_round0(newlen), NULL);
        if (!(*request)) { 
                CERROR("cannot pack\n");
                return -ENOMEM;
        }

        (*request)->rq_replen = 
                sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rec = mds_req_tgt((*request)->rq_req.mds);
        mds_rename_pack(rec, src, tgt, old, oldlen, new, newlen);

        rc = mdc_reint(peer, (*request));

        EXIT;
        return rc;
}
