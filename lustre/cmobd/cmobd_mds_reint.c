/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
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
 */

#define DEBUG_SUBSYSTEM S_CMOBD

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_smfs.h>
#include "cmobd_internal.h"

/* If mdc_setattr is called with an 'iattr', then it is a normal RPC that
 * should take the normal semaphore and go to the normal portal.
 *
 * If it is called with iattr->ia_valid & ATTR_FROM_OPEN, then it is a
 * magic open-path setattr that should take the setattr semaphore and
 * go to the setattr portal. */
int cmobd_setattr_reint(struct obd_device *obd, struct ptlrpc_request *req)
{
        struct mds_rec_setattr *rec;
        int    size[1], rc = 0; 
        
        ENTRY;

        rec = (struct mds_rec_setattr *)lustre_msg_buf(req->rq_reqmsg, 0, 0);
        if (!rec) 
                RETURN (-EINVAL);
        if (rec->sa_valid & ATTR_FROM_OPEN) 
                req->rq_request_portal = MDS_SETATTR_PORTAL; //XXX FIXME bug 249

        if (rec->sa_valid & (ATTR_MTIME | ATTR_CTIME)) 
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu\n",
                       ((time_t)rec->sa_mtime), 
                       ((time_t)rec->sa_ctime));
        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(req, NULL, LUSTRE_IMP_FULL);
        
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int cmobd_create_reint(struct obd_device *obd, struct ptlrpc_request *req)
{
        int rc = 0, level, size[1];
        ENTRY;

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        level = LUSTRE_IMP_FULL;
 resend:
        rc = mdc_reint(req, NULL, level);
        /* Resend if we were told to. */
        if (rc == -ERESTARTSYS) {
                level = LUSTRE_IMP_RECOVER;
                goto resend;
        }

        if (!rc)
                mdc_store_inode_generation(NULL, req, 0, 0);

        RETURN(rc);
}

int cmobd_unlink_reint(struct obd_device *obd, struct ptlrpc_request *req)
{
        int rc = 0, size[3];
        ENTRY;
        
        size[0] = sizeof(struct mds_body);
        size[1] = obd->u.cli.cl_max_mds_easize;
        size[2] = obd->u.cli.cl_max_mds_cookiesize;
        req->rq_replen = lustre_msg_size(3, size);

        rc = mdc_reint(req,  NULL, LUSTRE_IMP_FULL);
        if (rc == -ERESTARTSYS)
                rc = 0;
        RETURN(rc);
}

int cmobd_link_reint(struct obd_device *obd, struct ptlrpc_request *req)
{
        int rc = 0, size[1];
        ENTRY;

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(req, NULL, LUSTRE_IMP_FULL);
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int cmobd_rename_reint(struct obd_device *obd, struct ptlrpc_request *req)
{
        int rc = 0, size[2];
        ENTRY;

        size[0] = sizeof(struct mds_body);
        size[1] = obd->u.cli.cl_max_mds_easize;
        req->rq_replen = lustre_msg_size(2, size);

        rc = mdc_reint(req,  NULL, LUSTRE_IMP_FULL);
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

typedef int (*cmobd_reint_mds_rec)(struct obd_device*,
                                   struct ptlrpc_request *req);

static cmobd_reint_mds_rec cmobd_mds_reint[REINT_MAX + 1] = {
        [REINT_SETATTR] cmobd_setattr_reint,
        [REINT_CREATE] cmobd_create_reint,
        [REINT_LINK] cmobd_link_reint,
        [REINT_UNLINK] cmobd_unlink_reint,
        [REINT_RENAME] cmobd_rename_reint,
};

int cmobd_reint_mds(struct obd_device *obd, void* record)
{
        struct cache_manager_obd *cmobd = &obd->u.cmobd;
        struct ptlrpc_request *req; 
        struct lustre_msg *msg; 
        struct mds_kml_pack_info *mkpi;
        __u32  opcode; 
        int    rc = 0;
        mkpi = (struct mds_kml_pack_info *)record; 
       
        req = ptlrpc_prep_req(class_exp2cliimp(cmobd->cm_master_exp), 
                              LUSTRE_MDS_VERSION, MDS_REINT,
                              mkpi->mpi_bufcount, mkpi->mpi_size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);
        record += sizeof(*mkpi);
        msg = (struct lustre_msg *)record;
        opcode = (__u32)*(int*)lustre_msg_buf(msg, 0, 0); 
        if (opcode > REINT_MAX || opcode <= 0) {
                CERROR("Unrecorgnized reint opcode %u in cmobd mds reint\n",
                        opcode);
                GOTO(out, rc=-EINVAL);
        }
        
        memcpy(req->rq_reqmsg, record, mkpi->mpi_total_size);
        /*flags and opc will be rewrite, so reset here 
         *FIXME maybe should set some flags in reint process*/  

        req->rq_reqmsg->opc = MDS_REINT;
        req->rq_reqmsg->flags = 0;

        rc = cmobd_mds_reint[opcode](cmobd->cm_master_obd, req);
out:
        ptlrpc_req_finished(req);
        return rc;
} 

