/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <linux/lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <linux/obd_support.h>
/* struct ptlrpc_request */
#include <linux/lustre_net.h>
/* struct obd_export */
#include <linux/lustre_export.h>
/* struct obd_device */
#include <linux/obd.h>
/* lu2dt_dev() */
#include <linux/dt_object.h>


#include "../mds/mds_internal.h"
#include "mdt_internal.h"


/* unpacking */
static int mdt_setattr_unpack(struct ptlrpc_request *req, int offset,
                              struct mdt_reint_record *r)
{
        struct iattr *attr = &r->ur_iattr;
        struct mdt_rec_setattr *rec;
        ENTRY;

        rec = lustre_swab_reqbuf(req, offset, sizeof(*rec),
                                 lustre_swab_mdt_rec_setattr);
        if (rec == NULL)
                RETURN (-EFAULT);

        r->ur_uc.luc_fsuid = rec->sa_fsuid;
        r->ur_uc.luc_fsgid = rec->sa_fsgid;
        r->ur_uc.luc_cap = rec->sa_cap;
        r->ur_uc.luc_suppgid1 = rec->sa_suppgid;
        r->ur_uc.luc_suppgid2 = -1;
        r->ur_fid1 = &rec->sa_fid;
        attr->ia_valid = rec->sa_valid;
        attr->ia_mode = rec->sa_mode;
        attr->ia_uid = rec->sa_uid;
        attr->ia_gid = rec->sa_gid;
        attr->ia_size = rec->sa_size;
        LTIME_S(attr->ia_atime) = rec->sa_atime;
        LTIME_S(attr->ia_mtime) = rec->sa_mtime;
        LTIME_S(attr->ia_ctime) = rec->sa_ctime;
        attr->ia_attr_flags = rec->sa_attr_flags;

        LASSERT_REQSWAB (req, offset + 1);
        if (req->rq_reqmsg->bufcount > offset + 1) {
                r->ur_eadata = lustre_msg_buf (req->rq_reqmsg,
                                               offset + 1, 0);
                if (r->ur_eadata == NULL)
                        RETURN (-EFAULT);
                r->ur_eadatalen = req->rq_reqmsg->buflens[offset + 1];
        }

        if (req->rq_reqmsg->bufcount > offset + 2) {
                r->ur_logcookies = lustre_msg_buf(req->rq_reqmsg, offset + 2,0);
                if (r->ur_eadata == NULL)
                        RETURN (-EFAULT);

                r->ur_cookielen = req->rq_reqmsg->buflens[offset + 2];
        }

        RETURN(0);
}

static int mdt_create_unpack(struct ptlrpc_request *req, int offset,
                             struct mdt_reint_record *r)
{
        struct mdt_rec_create *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_create);
        if (rec == NULL)
                RETURN (-EFAULT);

        r->ur_uc.luc_fsuid = rec->cr_fsuid;
        r->ur_uc.luc_fsgid = rec->cr_fsgid;
        r->ur_uc.luc_cap = rec->cr_cap;
        r->ur_uc.luc_suppgid1 = rec->cr_suppgid;
        r->ur_uc.luc_suppgid2 = -1;
        r->ur_fid1 = &rec->cr_fid;
        r->ur_fid2 = &rec->cr_replayfid;
        r->ur_mode = rec->cr_mode;
        r->ur_rdev = rec->cr_rdev;
        r->ur_time = rec->cr_time;
        r->ur_flags = rec->cr_flags;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN (-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        if (req->rq_reqmsg->bufcount > offset + 2) {
                /* NB for now, we only seem to pass NULL terminated symlink
                 * target strings here.  If this ever changes, we'll have
                 * to stop checking for a buffer filled completely with a
                 * NULL terminated string here, and make the callers check
                 * depending on what they expect.  We should probably stash
                 * it in r->ur_eadata in that case, so it's obvious... -eeb
                 */
                r->ur_tgt = lustre_msg_string(req->rq_reqmsg, offset + 2, 0);
                if (r->ur_tgt == NULL)
                        RETURN (-EFAULT);
                r->ur_tgtlen = req->rq_reqmsg->buflens[offset + 2];
        }
        RETURN(0);
}

static int mdt_link_unpack(struct ptlrpc_request *req, int offset,
                           struct mdt_reint_record *r)
{
        struct mdt_rec_link *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_link);
        if (rec == NULL)
                RETURN (-EFAULT);

        r->ur_uc.luc_fsuid = rec->lk_fsuid;
        r->ur_uc.luc_fsgid = rec->lk_fsgid;
        r->ur_uc.luc_cap = rec->lk_cap;
        r->ur_uc.luc_suppgid1 = rec->lk_suppgid1;
        r->ur_uc.luc_suppgid2 = rec->lk_suppgid2;
        r->ur_fid1 = &rec->lk_fid1;
        r->ur_fid2 = &rec->lk_fid2;
        r->ur_time = rec->lk_time;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN (-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];
        RETURN(0);
}

static int mdt_unlink_unpack(struct ptlrpc_request *req, int offset,
                             struct mdt_reint_record *r)
{
        struct mdt_rec_unlink *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_unlink);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->ur_uc.luc_fsuid = rec->ul_fsuid;
        r->ur_uc.luc_fsgid = rec->ul_fsgid;
        r->ur_uc.luc_cap = rec->ul_cap;
        r->ur_uc.luc_suppgid1 = rec->ul_suppgid;
        r->ur_uc.luc_suppgid2 = -1;
        r->ur_mode = rec->ul_mode;
        r->ur_fid1 = &rec->ul_fid1;
        r->ur_fid2 = &rec->ul_fid2;
        r->ur_time = rec->ul_time;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN(-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];
        RETURN(0);
}

static int mdt_rename_unpack(struct ptlrpc_request *req, int offset,
                             struct mdt_reint_record *r)
{
        struct mdt_rec_rename *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_rename);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->ur_uc.luc_fsuid = rec->rn_fsuid;
        r->ur_uc.luc_fsgid = rec->rn_fsgid;
        r->ur_uc.luc_cap = rec->rn_cap;
        r->ur_uc.luc_suppgid1 = rec->rn_suppgid1;
        r->ur_uc.luc_suppgid2 = rec->rn_suppgid2;
        r->ur_fid1 = &rec->rn_fid1;
        r->ur_fid2 = &rec->rn_fid2;
        r->ur_time = rec->rn_time;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN(-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        r->ur_tgt = lustre_msg_string(req->rq_reqmsg, offset + 2, 0);
        if (r->ur_tgt == NULL)
                RETURN(-EFAULT);
        r->ur_tgtlen = req->rq_reqmsg->buflens[offset + 2];
        RETURN(0);
}

static int mdt_open_unpack(struct ptlrpc_request *req, int offset,
                           struct mdt_reint_record *r)
{
        struct mdt_rec_create *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mdt_rec_create);
        if (rec == NULL)
                RETURN (-EFAULT);

        r->ur_uc.luc_fsuid = rec->cr_fsuid;
        r->ur_uc.luc_fsgid = rec->cr_fsgid;
        r->ur_uc.luc_cap = rec->cr_cap;
        r->ur_uc.luc_suppgid1 = rec->cr_suppgid;
        r->ur_uc.luc_suppgid2 = -1;
        r->ur_fid1 = &rec->cr_fid;
        r->ur_fid2 = &rec->cr_replayfid;
        r->ur_mode = rec->cr_mode;
        r->ur_rdev = rec->cr_rdev;
        r->ur_time = rec->cr_time;
        r->ur_flags = rec->cr_flags;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN (-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        if (req->rq_reqmsg->bufcount > offset + 2) {
                r->ur_eadata = lustre_msg_buf(req->rq_reqmsg, offset + 2, 0);
                if (r->ur_eadata == NULL)
                        RETURN (-EFAULT);
                r->ur_eadatalen = req->rq_reqmsg->buflens[offset + 2];
        }
        RETURN(0);
}

typedef int (*reint_unpacker)(struct ptlrpc_request *req, int offset,
                               struct mdt_reint_record *r);

static reint_unpacker mdt_reint_unpackers[REINT_MAX] = {
        [REINT_SETATTR] mdt_setattr_unpack,
        [REINT_CREATE] mdt_create_unpack,
        [REINT_LINK] mdt_link_unpack,
        [REINT_UNLINK] mdt_unlink_unpack,
        [REINT_RENAME] mdt_rename_unpack,
        [REINT_OPEN] mdt_open_unpack,
};

int mdt_reint_unpack(struct mdt_thread_info *info, struct ptlrpc_request *req, int offset,
                      struct mdt_reint_record *rec)
{
        mdt_reint_t opcode, *opcodep;
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

        rec->ur_opcode = opcode;
        rc = mdt_reint_unpackers[opcode](req, offset, rec);

        RETURN(rc);
}
