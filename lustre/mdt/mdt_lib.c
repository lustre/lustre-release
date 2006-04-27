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
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *r = &info->mti_rr;
        struct mdt_rec_setattr *rec;
        ENTRY;

        rec = lustre_swab_reqbuf(req, offset, sizeof(*rec),
                                 lustre_swab_mdt_rec_setattr);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->rr_uc.luc_fsuid = rec->sa_fsuid;
        r->rr_uc.luc_fsgid = rec->sa_fsgid;
        r->rr_uc.luc_cap = rec->sa_cap;
        r->rr_uc.luc_suppgid1 = rec->sa_suppgid;
        r->rr_uc.luc_suppgid2 = -1;
        r->rr_fid1 = &rec->sa_fid;
/*FIXME        attr->la_valid = rec->sa_valid; */
        attr->la_mode = rec->sa_mode;
        attr->la_uid = rec->sa_uid;
        attr->la_gid = rec->sa_gid;
        attr->la_size = rec->sa_size;
        attr->la_atime = rec->sa_atime;
        attr->la_mtime = rec->sa_mtime;
        attr->la_ctime = rec->sa_ctime;
/*FIXME        attr->la_attr_flags = rec->sa_attr_flags;*/

        LASSERT_REQSWAB (req, offset + 1);
        if (req->rq_reqmsg->bufcount > offset + 1) {
                r->rr_eadata = lustre_msg_buf (req->rq_reqmsg,
                                               offset + 1, 0);
                if (r->rr_eadata == NULL)
                        RETURN(-EFAULT);
                r->rr_eadatalen = req->rq_reqmsg->buflens[offset + 1];
        }

        if (req->rq_reqmsg->bufcount > offset + 2) {
                r->rr_logcookies = lustre_msg_buf(req->rq_reqmsg, offset + 2,0);
                if (r->rr_logcookies == NULL)
                        RETURN(-EFAULT);

                r->rr_cookielen = req->rq_reqmsg->buflens[offset + 2];
        }

        RETURN(0);
}

static int mdt_create_unpack(struct mdt_thread_info *info,
                             struct ptlrpc_request *req, 
                             int offset)
{
        struct mdt_rec_create *rec;
        struct mdt_reint_record *r = &info->mti_rr;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_create);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->rr_uc.luc_fsuid = rec->cr_fsuid;
        r->rr_uc.luc_fsgid = rec->cr_fsgid;
        r->rr_uc.luc_cap = rec->cr_cap;
        r->rr_uc.luc_suppgid1 = rec->cr_suppgid;
        r->rr_uc.luc_suppgid2 = -1;
        r->rr_fid1 = &rec->cr_fid;
        r->rr_fid2 = &rec->cr_replayfid;
        r->rr_mode = rec->cr_mode;
        r->rr_rdev = rec->cr_rdev;
        r->rr_time = rec->cr_time;
        r->rr_flags = rec->cr_flags;

        LASSERT_REQSWAB (req, offset + 1);
        r->rr_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->rr_name == NULL)
                RETURN(-EFAULT);
        r->rr_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        if (req->rq_reqmsg->bufcount > offset + 2) {
                /* NB for now, we only seem to pass NULL terminated symlink
                 * target strings here.  If this ever changes, we'll have
                 * to stop checking for a buffer filled completely with a
                 * NULL terminated string here, and make the callers check
                 * depending on what they expect.  We should probably stash
                 * it in r->rr_eadata in that case, so it's obvious... -eeb
                 */
                r->rr_tgt = lustre_msg_string(req->rq_reqmsg, offset + 2, 0);
                if (r->rr_tgt == NULL)
                        RETURN(-EFAULT);
                r->rr_tgtlen = req->rq_reqmsg->buflens[offset + 2];
        }
        RETURN(0);
}

static int mdt_link_unpack(struct mdt_thread_info *info,
                           struct ptlrpc_request *req, 
                           int offset)
{
        struct mdt_rec_link *rec;
        struct mdt_reint_record *r = &info->mti_rr;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_link);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->rr_uc.luc_fsuid = rec->lk_fsuid;
        r->rr_uc.luc_fsgid = rec->lk_fsgid;
        r->rr_uc.luc_cap = rec->lk_cap;
        r->rr_uc.luc_suppgid1 = rec->lk_suppgid1;
        r->rr_uc.luc_suppgid2 = rec->lk_suppgid2;
        r->rr_fid1 = &rec->lk_fid1;
        r->rr_fid2 = &rec->lk_fid2;
        r->rr_time = rec->lk_time;

        LASSERT_REQSWAB (req, offset + 1);
        r->rr_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->rr_name == NULL)
                RETURN(-EFAULT);
        r->rr_namelen = req->rq_reqmsg->buflens[offset + 1];
        RETURN(0);
}

static int mdt_unlink_unpack(struct mdt_thread_info *info,
                             struct ptlrpc_request *req, 
                             int offset)
{
        struct mdt_rec_unlink *rec;
        struct mdt_reint_record *r = &info->mti_rr;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_unlink);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->rr_uc.luc_fsuid = rec->ul_fsuid;
        r->rr_uc.luc_fsgid = rec->ul_fsgid;
        r->rr_uc.luc_cap = rec->ul_cap;
        r->rr_uc.luc_suppgid1 = rec->ul_suppgid;
        r->rr_uc.luc_suppgid2 = -1;
        r->rr_mode = rec->ul_mode;
        r->rr_fid1 = &rec->ul_fid1;
        r->rr_fid2 = &rec->ul_fid2;
        r->rr_time = rec->ul_time;

        LASSERT_REQSWAB (req, offset + 1);
        r->rr_name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (r->rr_name == NULL)
                RETURN(-EFAULT);
        r->rr_namelen = req->rq_reqmsg->buflens[offset + 1];
        RETURN(0);
}

static int mdt_rename_unpack(struct mdt_thread_info *info,
                             struct ptlrpc_request *req, 
                             int offset)
{
        struct mdt_rec_rename *rec;
        struct mdt_reint_record *r = &info->mti_rr;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_rename);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->rr_uc.luc_fsuid = rec->rn_fsuid;
        r->rr_uc.luc_fsgid = rec->rn_fsgid;
        r->rr_uc.luc_cap = rec->rn_cap;
        r->rr_uc.luc_suppgid1 = rec->rn_suppgid1;
        r->rr_uc.luc_suppgid2 = rec->rn_suppgid2;
        r->rr_fid1 = &rec->rn_fid1;
        r->rr_fid2 = &rec->rn_fid2;
        r->rr_time = rec->rn_time;

        LASSERT_REQSWAB (req, offset + 1);
        r->rr_name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (r->rr_name == NULL)
                RETURN(-EFAULT);
        r->rr_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        r->rr_tgt = lustre_msg_string(req->rq_reqmsg, offset + 2, 0);
        if (r->rr_tgt == NULL)
                RETURN(-EFAULT);
        r->rr_tgtlen = req->rq_reqmsg->buflens[offset + 2];
        RETURN(0);
}

static int mdt_open_unpack(struct mdt_thread_info *info,
                           struct ptlrpc_request *req, 
                           int offset)
{
        struct mdt_rec_create *rec;
        struct mdt_reint_record *r = &info->mti_rr;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_create);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->rr_uc.luc_fsuid = rec->cr_fsuid;
        r->rr_uc.luc_fsgid = rec->cr_fsgid;
        r->rr_uc.luc_cap = rec->cr_cap;
        r->rr_uc.luc_suppgid1 = rec->cr_suppgid;
        r->rr_uc.luc_suppgid2 = -1;
        r->rr_fid1 = &rec->cr_fid;
        r->rr_fid2 = &rec->cr_replayfid;
        r->rr_mode = rec->cr_mode;
        r->rr_rdev = rec->cr_rdev;
        r->rr_time = rec->cr_time;
        r->rr_flags = rec->cr_flags;

        LASSERT_REQSWAB (req, offset + 1);
        r->rr_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->rr_name == NULL)
                RETURN(-EFAULT);
        r->rr_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        if (req->rq_reqmsg->bufcount > offset + 2) {
                r->rr_eadata = lustre_msg_buf(req->rq_reqmsg, offset + 2, 0);
                if (r->rr_eadata == NULL)
                        RETURN(-EFAULT);
                r->rr_eadatalen = req->rq_reqmsg->buflens[offset + 2];
        }
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
        opcodep = lustre_msg_buf (req->rq_reqmsg, offset, sizeof (*opcodep));
        if (opcodep == NULL)
                RETURN(-EFAULT);

        opcode = *opcodep;
        if (lustre_msg_swabbed (req->rq_reqmsg))
                __swab32s (&opcode);

        if (opcode >= REINT_MAX || mdt_reint_unpackers[opcode] == NULL) {
                CERROR("Unexpected opcode %d\n", opcode);
                RETURN(-EFAULT);
        }

        info->mti_rr.rr_opcode = opcode;
        rc = mdt_reint_unpackers[opcode](info, req, offset);

        RETURN(rc);
}
