/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mdt/mdt_lib.c
 *  Lustre Metadata Target (mdt) request unpacking helper.
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *   Author: Huang Hua <huanghua@clusterfs.com>
 *
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */


#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"


/* unpacking */
static int mdt_setattr_unpack(struct mdt_thread_info *info,
                              struct ptlrpc_request *req, 
                              int offset)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_create_unpack(struct mdt_thread_info *info,
                             struct ptlrpc_request *req, 
                             int offset)
{
        struct mdt_rec_create *rec;
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        ENTRY;

        rec = lustre_swab_reqbuf(req, offset, sizeof (*rec),
                                 lustre_swab_mdt_rec_create);
        if (rec == NULL)
                RETURN(-EFAULT);

        rr->rr_fid1 = &rec->cr_fid1;
        rr->rr_fid2 = &rec->cr_fid2;
        attr->la_mode = rec->cr_mode;

        rr->rr_name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);

        RETURN(0);
}

static int mdt_link_unpack(struct mdt_thread_info *info,
                           struct ptlrpc_request *req, 
                           int offset)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_unlink_unpack(struct mdt_thread_info *info,
                             struct ptlrpc_request *req, 
                             int offset)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_rename_unpack(struct mdt_thread_info *info,
                             struct ptlrpc_request *req, 
                             int offset)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_open_unpack(struct mdt_thread_info *info,
                           struct ptlrpc_request *req, 
                           int offset)
{
        struct mdt_rec_create *rec;
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        ENTRY;

        rec = lustre_swab_reqbuf(req, offset, sizeof (*rec),
                                 lustre_swab_mdt_rec_create);
        if (rec == NULL)
                RETURN(-EFAULT);

        rr->rr_fid1   = &rec->cr_fid1;
        rr->rr_fid2   = &rec->cr_fid2;
        attr->la_mode = rec->cr_mode;
        rr->rr_flags  = rec->cr_flags;

        rr->rr_name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (rr->rr_name == NULL)
                RETURN (-EFAULT);

        RETURN(0);
}

typedef int (*reint_unpacker)(struct mdt_thread_info *info,
                              struct ptlrpc_request *req, 
                              int offset);

static reint_unpacker mdt_reint_unpackers[REINT_MAX] = {
        [REINT_SETATTR]  = mdt_setattr_unpack,
        [REINT_CREATE] = mdt_create_unpack,
        [REINT_LINK] = mdt_link_unpack,
        [REINT_UNLINK] = mdt_unlink_unpack,
        [REINT_RENAME] = mdt_rename_unpack,
        [REINT_OPEN] = mdt_open_unpack
};

int mdt_reint_unpack(struct mdt_thread_info *info,
                     struct ptlrpc_request *req, 
                     int offset)
{
        mdt_reint_t opcode;
        mdt_reint_t *opcodep;
        int rc;
        ENTRY;

        /* NB don't lustre_swab_reqbuf() here.  We're just taking a peek
         * and we want to leave it to the specific unpacker once we've
         * identified the message type */
        opcodep = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*opcodep));
        if (opcodep == NULL)
                RETURN(-EFAULT);

        opcode = *opcodep;
        if (lustre_msg_swabbed(req->rq_reqmsg))
                __swab32s (&opcode);

        if (opcode >= REINT_MAX || mdt_reint_unpackers[opcode] == NULL) {
                CERROR("Unexpected opcode %d\n", opcode);
                RETURN(-EFAULT);
        }
        info->mti_rr.rr_opcode = opcode;
        rc = mdt_reint_unpackers[opcode](info, req, offset);

        RETURN(rc);
}
