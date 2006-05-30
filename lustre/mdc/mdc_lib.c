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

#define DEBUG_SUBSYSTEM S_MDC
#ifndef __KERNEL__
# include <fcntl.h>
# include <liblustre.h>
#endif
#include <lustre/lustre_idl.h>
#include <lustre_net.h>
#include "mdc_internal.h"

#ifndef __KERNEL__
/* some liblustre hackings here */
#ifndef O_DIRECTORY
#define O_DIRECTORY     0
#endif
#endif

void mdc_readdir_pack(struct ptlrpc_request *req, int offset, __u64 pg_off,
                      __u32 size, struct ll_fid *fid)
{
        struct mds_body *b;

        b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));
        b->fsuid = current->fsuid;
        b->fsgid = current->fsgid;
        b->capability = current->cap_effective;
        b->fid1 = *fid;
        b->size = pg_off;                       /* !! */
        b->suppgid = -1;
        b->nlink = size;                        /* !! */
}

static void mdc_pack_body(struct mds_body *b)
{
        LASSERT (b != NULL);

        b->fsuid = current->fsuid;
        b->fsgid = current->fsgid;
        b->capability = current->cap_effective;
}

void mdc_pack_req_body(struct ptlrpc_request *req, int offset,
                       __u64 valid, struct ll_fid *fid, int ea_size, int flags)
{
        struct mds_body *b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));

        if (fid)
                b->fid1 = *fid;
        b->valid = valid;
        b->eadatasize = ea_size;
        b->flags = flags;
        mdc_pack_body(b);
}

/* packing of MDS records */
void mdc_create_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *op_data, const void *data, int datalen,
                     __u32 mode, __u32 uid, __u32 gid, __u32 cap_effective,
                     __u64 rdev)
{
        struct mds_rec_create *rec;
        char *tmp;
        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        rec->cr_opcode = REINT_CREATE;
        rec->cr_fsuid = uid;
        rec->cr_fsgid = gid;
        rec->cr_cap = cap_effective;
        rec->cr_fid = op_data->fid1;
        memset(&rec->cr_replayfid, 0, sizeof(rec->cr_replayfid));
        rec->cr_mode = mode;
        rec->cr_rdev = rdev;
        rec->cr_time = op_data->mod_time;
        rec->cr_suppgid = op_data->suppgids[0];

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1, op_data->namelen + 1);
        LOGL0(op_data->name, op_data->namelen, tmp);

        if (data) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, datalen);
                memcpy (tmp, data, datalen);
        }
}

static __u32 mds_pack_open_flags(__u32 flags)
{
        return
                (flags & (FMODE_READ | FMODE_WRITE |
                          MDS_OPEN_DELAY_CREATE | MDS_OPEN_HAS_EA |
                          MDS_OPEN_HAS_OBJS | MDS_OPEN_OWNEROVERRIDE |
                          MDS_OPEN_LOCK)) |
                ((flags & O_CREAT) ? MDS_OPEN_CREAT : 0) |
                ((flags & O_EXCL) ? MDS_OPEN_EXCL : 0) |
                ((flags & O_TRUNC) ? MDS_OPEN_TRUNC : 0) |
                ((flags & O_APPEND) ? MDS_OPEN_APPEND : 0) |
                ((flags & O_SYNC) ? MDS_OPEN_SYNC : 0) |
                ((flags & O_DIRECTORY) ? MDS_OPEN_DIRECTORY : 0) |
                ((flags & O_JOIN_FILE) ? MDS_OPEN_JOIN_FILE : 0) |
#ifdef FMODE_EXEC
                ((flags & FMODE_EXEC) ? MDS_FMODE_EXEC : 0) |
#endif
                0;
}

/* packing of MDS records */
void mdc_join_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *op_data, __u64 head_size)
{
        struct mds_rec_join *rec;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*rec));
        LASSERT(rec != NULL);
        rec->jr_fid = op_data->fid2;
        rec->jr_headsize = head_size;
}

void mdc_open_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *op_data, __u32 mode, __u64 rdev,
                   __u32 flags, const void *lmm, int lmmlen)
{
        struct mds_rec_create *rec;
        char *tmp;
        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        /* XXX do something about time, uid, gid */
        rec->cr_opcode = REINT_OPEN;
        rec->cr_fsuid = current->fsuid;
        rec->cr_fsgid = current->fsgid;
        rec->cr_cap = current->cap_effective;
        rec->cr_fid = op_data->fid1;
        memset(&rec->cr_replayfid, 0, sizeof(rec->cr_replayfid));
        rec->cr_mode = mode;
        rec->cr_flags = mds_pack_open_flags(flags);
        rec->cr_rdev = rdev;
        rec->cr_time = op_data->mod_time;
        rec->cr_suppgid = op_data->suppgids[0];

        if (op_data->name) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1,
                                     op_data->namelen + 1);
                LOGL0(op_data->name, op_data->namelen, tmp);
        }

        if (lmm) {
                rec->cr_flags |= MDS_OPEN_HAS_EA;
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, lmmlen);
                memcpy (tmp, lmm, lmmlen);
        }
}

void mdc_setattr_pack(struct ptlrpc_request *req, int offset,
                      struct mdc_op_data *data, struct iattr *iattr, void *ea,
                      int ealen, void *ea2, int ea2len)
{
        struct mds_rec_setattr *rec = lustre_msg_buf(req->rq_reqmsg, offset,
                                                     sizeof(*rec));
        rec->sa_opcode = REINT_SETATTR;
        rec->sa_fsuid = current->fsuid;
        rec->sa_fsgid = current->fsgid;
        rec->sa_cap = current->cap_effective;
        rec->sa_fid = data->fid1;
        rec->sa_suppgid = -1;

        if (iattr) {
                rec->sa_valid = iattr->ia_valid;
                rec->sa_mode = iattr->ia_mode;
                rec->sa_uid = iattr->ia_uid;
                rec->sa_gid = iattr->ia_gid;
                rec->sa_size = iattr->ia_size;
                rec->sa_atime = LTIME_S(iattr->ia_atime);
                rec->sa_mtime = LTIME_S(iattr->ia_mtime);
                rec->sa_ctime = LTIME_S(iattr->ia_ctime);
                rec->sa_attr_flags =
                               ((struct ll_iattr_struct *)iattr)->ia_attr_flags;

                if ((iattr->ia_valid & ATTR_GID) && in_group_p(iattr->ia_gid))
                        rec->sa_suppgid = iattr->ia_gid;
                else
                        rec->sa_suppgid = data->suppgids[0];
        }

        if (ealen == 0)
                return;

        memcpy(lustre_msg_buf(req->rq_reqmsg, offset + 1, ealen), ea, ealen);

        if (ea2len == 0)
                return;

        memcpy(lustre_msg_buf(req->rq_reqmsg, offset + 2, ea2len), ea2, ea2len);
}

void mdc_unlink_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *data)
{
        struct mds_rec_unlink *rec;
        char *tmp;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));
        LASSERT (rec != NULL);

        rec->ul_opcode = REINT_UNLINK;
        rec->ul_fsuid = current->fsuid;
        rec->ul_fsgid = current->fsgid;
        rec->ul_cap = current->cap_effective;
        rec->ul_mode = data->create_mode;
        rec->ul_suppgid = data->suppgids[0];
        rec->ul_fid1 = data->fid1;
        rec->ul_fid2 = data->fid2;
        rec->ul_time = data->mod_time;

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1, data->namelen + 1);
        LASSERT (tmp != NULL);
        LOGL0(data->name, data->namelen, tmp);
}

void mdc_link_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *data)
{
        struct mds_rec_link *rec;
        char *tmp;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        rec->lk_opcode = REINT_LINK;
        rec->lk_fsuid = current->fsuid;
        rec->lk_fsgid = current->fsgid;
        rec->lk_cap = current->cap_effective;
        rec->lk_suppgid1 = data->suppgids[0];
        rec->lk_suppgid2 = data->suppgids[1];
        rec->lk_fid1 = data->fid1;
        rec->lk_fid2 = data->fid2;
        rec->lk_time = data->mod_time;

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1, data->namelen + 1);
        LOGL0(data->name, data->namelen, tmp);
}

void mdc_rename_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *data,
                     const char *old, int oldlen, const char *new, int newlen)
{
        struct mds_rec_rename *rec;
        char *tmp;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        /* XXX do something about time, uid, gid */
        rec->rn_opcode = REINT_RENAME;
        rec->rn_fsuid = current->fsuid;
        rec->rn_fsgid = current->fsgid;
        rec->rn_cap = current->cap_effective;
        rec->rn_suppgid1 = data->suppgids[0];
        rec->rn_suppgid2 = data->suppgids[1];
        rec->rn_fid1 = data->fid1;
        rec->rn_fid2 = data->fid2;
        rec->rn_time = data->mod_time;

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1, oldlen + 1);
        LOGL0(old, oldlen, tmp);

        if (new) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, newlen + 1);
                LOGL0(new, newlen, tmp);
        }
}

void mdc_getattr_pack(struct ptlrpc_request *req, int offset, int valid,
                      int flags, struct mdc_op_data *data)
{
        struct mds_body *b;
        b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));

        b->fsuid = current->fsuid;
        b->fsgid = current->fsgid;
        b->capability = current->cap_effective;
        b->valid = valid;
        b->flags = flags | MDS_BFLAG_EXT_FLAGS;
        b->suppgid = data->suppgids[0];

        b->fid1 = data->fid1;
        b->fid2 = data->fid2;
        if (data->name) {
                char *tmp;
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1,
                                     data->namelen + 1);
                LOGL0(data->name, data->namelen, tmp);
        }
}

void mdc_close_pack(struct ptlrpc_request *req, int offset, struct obdo *oa,
                    int valid, struct obd_client_handle *och)
{
        struct mds_body *body;

        body = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*body));

        mdc_pack_fid(&body->fid1, oa->o_id, 0, oa->o_mode);
        memcpy(&body->handle, &och->och_fh, sizeof(body->handle));
        if (oa->o_valid & OBD_MD_FLATIME) {
                body->atime = oa->o_atime;
                body->valid |= OBD_MD_FLATIME;
        }
        if (oa->o_valid & OBD_MD_FLMTIME) {
                body->mtime = oa->o_mtime;
                body->valid |= OBD_MD_FLMTIME;
        }
        if (oa->o_valid & OBD_MD_FLCTIME) {
                body->ctime = oa->o_ctime;
                body->valid |= OBD_MD_FLCTIME;
        }
        if (oa->o_valid & OBD_MD_FLSIZE) {
                body->size = oa->o_size;
                body->valid |= OBD_MD_FLSIZE;
        }
        if (oa->o_valid & OBD_MD_FLBLOCKS) {
                body->blocks = oa->o_blocks;
                body->valid |= OBD_MD_FLBLOCKS;
        }
        if (oa->o_valid & OBD_MD_FLFLAGS) {
                body->flags = oa->o_flags;
                body->valid |= OBD_MD_FLFLAGS;
        }
}
