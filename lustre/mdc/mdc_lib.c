/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
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

#define DEBUG_SUBSYSTEM S_MDS
#ifndef __KERNEL__
# include <fcntl.h>
# include <liblustre.h>
#endif
#include <linux/lustre_idl.h>
#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include "mdc_internal.h"

#ifndef __KERNEL__
/* some liblustre hackings here */
#ifndef O_DIRECTORY
#define O_DIRECTORY     0
#endif
#endif

void mdc_readdir_pack(struct ptlrpc_request *req, __u64 offset, __u32 size,
                      struct ll_fid *mdc_fid)
{
        struct mds_body *b;

        b = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*b));
        b->fsuid = current->fsuid;
        b->fsgid = current->fsgid;
        b->capability = current->cap_effective;
        b->fid1 = *mdc_fid;
        b->size = offset;                       /* !! */
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

void mdc_pack_req_body(struct ptlrpc_request *req)
{
        struct mds_body *b = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*b));
        mdc_pack_body(b);
}

/* packing of MDS records */
void mdc_create_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *op_data, __u32 mode, __u64 rdev,
                     const void *data, int datalen)
{
        struct mds_rec_create *rec;
        char *tmp;
        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        rec->cr_opcode = REINT_CREATE;
        rec->cr_fsuid = current->fsuid;
        rec->cr_fsgid = current->fsgid;
        rec->cr_cap = current->cap_effective;
        rec->cr_fid = op_data->fid1;
        memset(&rec->cr_replayfid, 0, sizeof(rec->cr_replayfid));
        rec->cr_mode = mode;
        rec->cr_rdev = rdev;
        rec->cr_time = op_data->mod_time;
        rec->cr_suppgid = op_data->ctxt.gid1;

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
                (flags & (FMODE_READ | FMODE_WRITE | FMODE_EXEC |
                          MDS_OPEN_DELAY_CREATE | MDS_OPEN_HAS_EA |
                          MDS_OPEN_HAS_OBJS)) |
                ((flags & O_CREAT) ? MDS_OPEN_CREAT : 0) |
                ((flags & O_EXCL) ? MDS_OPEN_EXCL : 0) |
                ((flags & O_TRUNC) ? MDS_OPEN_TRUNC : 0) |
                ((flags & O_APPEND) ? MDS_OPEN_APPEND : 0) |
                ((flags & O_SYNC) ? MDS_OPEN_SYNC : 0) |
                ((flags & O_DIRECTORY) ? MDS_OPEN_DIRECTORY : 0) |
                0;
}

/* packing of MDS records */
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
        if (op_data != NULL)
                rec->cr_fid = op_data->fid1;
        memset(&rec->cr_replayfid, 0, sizeof(rec->cr_replayfid));
        rec->cr_mode = mode;
        rec->cr_flags = mds_pack_open_flags(flags);
        rec->cr_rdev = rdev;
        rec->cr_time = op_data->mod_time;
        rec->cr_suppgid = op_data->ctxt.gid1;

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

void mdc_setattr_pack(struct ptlrpc_request *req, struct mdc_op_data *data,
                      struct iattr *iattr, void *ea, int ealen,
                      void *ea2, int ea2len)
{
        struct mds_rec_setattr *rec = lustre_msg_buf(req->rq_reqmsg, 0,
                                                     sizeof (*rec));
        rec->sa_opcode = REINT_SETATTR;
        rec->sa_fsuid = current->fsuid;
        rec->sa_fsgid = current->fsgid;
        rec->sa_cap = current->cap_effective;
        rec->sa_fid = data->fid1;

        if (iattr) {
                rec->sa_valid = iattr->ia_valid;
                rec->sa_mode = iattr->ia_mode;
                rec->sa_uid = iattr->ia_uid;
                rec->sa_gid = iattr->ia_gid;
                rec->sa_size = iattr->ia_size;
                rec->sa_atime = LTIME_S(iattr->ia_atime);
                rec->sa_mtime = LTIME_S(iattr->ia_mtime);
                rec->sa_ctime = LTIME_S(iattr->ia_ctime);
                rec->sa_attr_flags = iattr->ia_attr_flags;
                if ((iattr->ia_valid & ATTR_GID) && in_group_p(iattr->ia_gid))
                        rec->sa_suppgid = iattr->ia_gid;
                else if ((iattr->ia_valid & ATTR_MODE) &&
                         in_group_p(iattr->ia_gid))
                        rec->sa_suppgid = data->ctxt.gid1;
                else if ((iattr->ia_valid & (ATTR_MTIME|ATTR_CTIME)) &&
                         data->ctxt.gid1 != -1)
                        rec->sa_suppgid = data->ctxt.gid1;
        }

        if (ealen == 0)
                return;

        memcpy(lustre_msg_buf(req->rq_reqmsg, 1, ealen), ea, ealen);

        if (ea2len == 0)
                return;

        memcpy(lustre_msg_buf(req->rq_reqmsg, 2, ea2len), ea2, ea2len);
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
        rec->ul_suppgid = data->ctxt.gid1;
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
        rec->lk_suppgid1 = data->ctxt.gid1;
        rec->lk_suppgid2 = data->ctxt.gid2;
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
        if (in_group_p(data->ctxt.gid1))
                rec->rn_suppgid1 = data->ctxt.gid1;
        else
                rec->rn_suppgid1 = -1;
        if (in_group_p(data->ctxt.gid2))
                rec->rn_suppgid2 = data->ctxt.gid2;
        else
                rec->rn_suppgid2 = -1;
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

void mdc_getattr_pack(struct ptlrpc_request *req, int valid, int offset,
                      int flags, struct mdc_op_data *data)
{
        struct mds_body *b;
        b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*b));

        b->fsuid = current->fsuid;
        b->fsgid = current->fsgid;
        b->capability = current->cap_effective;
        b->valid = valid;
        b->flags = flags;
        b->suppgid = data->ctxt.gid1;

        b->fid1 = data->fid1;
        if (data->name) {
                char *tmp;
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1,
                                     data->namelen + 1);
                LOGL0(data->name, data->namelen, tmp);
        }
}

