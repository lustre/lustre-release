/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_MDC
#ifndef __KERNEL__
# include <fcntl.h>
# include <liblustre.h>
#endif
#include <lustre_net.h>
#include <lustre/lustre_idl.h>
#include "mdc_internal.h"

#ifndef __KERNEL__
/* some liblustre hackings here */
#ifndef O_DIRECTORY
#define O_DIRECTORY     0
#endif
#endif

static void mdc_readdir_pack_18(struct ptlrpc_request *req, int offset,
                                __u64 pg_off, __u32 size, struct ll_fid *fid)
{
        struct mds_body *b;
        ENTRY;

        CLASSERT(sizeof(struct ll_fid)   == sizeof(struct lu_fid));
        CLASSERT(sizeof(struct mds_body) <= sizeof(struct mdt_body));
        CLASSERT((int)offsetof(struct mds_body, max_cookiesize) == 
                 (int)offsetof(struct mdt_body, max_cookiesize));


        b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));
        b->fsuid = cfs_curproc_fsuid();
        b->fsgid = cfs_curproc_fsgid();
        b->capability = cfs_curproc_cap_pack();
        b->fid1 = *fid;
        b->size = pg_off;                       /* !! */
        b->suppgid = -1;
        b->nlink = size;                        /* !! */
        EXIT;
}

static void mdc_readdir_pack_20(struct ptlrpc_request *req, int offset,
                                __u64 pg_off, __u32 size, struct ll_fid *fid)
{
        struct mdt_body *b;
        ENTRY;

        b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));
        b->fsuid = cfs_curproc_fsuid();
        b->fsgid = cfs_curproc_fsgid();
        b->capability = cfs_curproc_cap_pack();

        if (fid) {
                b->fid1 = *((struct lu_fid*)fid);
                b->valid |= OBD_MD_FLID;
        }
        b->size = pg_off;                       /* !! */
        b->suppgid = -1;
        b->nlink = size;                        /* !! */
        b->mode = LUDA_FID | LUDA_TYPE;
        EXIT;
}

void mdc_readdir_pack(struct ptlrpc_request *req, int offset,
                      __u64 pg_off, __u32 size, struct ll_fid *fid)
{
        if (mdc_req_is_2_0_server(req))
                mdc_readdir_pack_20(req, offset, pg_off, size, fid);
        else
                mdc_readdir_pack_18(req, offset, pg_off, size, fid);
}

static void mdc_pack_req_body_18(struct ptlrpc_request *req, int offset,
                                 __u64 valid, struct ll_fid *fid, int ea_size,
                                 int flags)
{
        struct mds_body *b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));
        ENTRY;
        LASSERT (b != NULL);

        if (fid)
                b->fid1 = *fid;
        b->valid = valid;
        b->eadatasize = ea_size;
        b->flags = flags;
        b->fsuid = cfs_curproc_fsuid();
        b->fsgid = cfs_curproc_fsgid();
        b->capability = cfs_curproc_cap_pack();
        EXIT;
}

static void mdc_pack_req_body_20(struct ptlrpc_request *req, int offset,
                                 __u64 valid, struct ll_fid *fid, int ea_size,
                                 int flags)
{
        struct mdt_body *b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));
        ENTRY;
        LASSERT (b != NULL);

        b->valid      = valid;
        b->eadatasize = ea_size;
        b->flags      = flags;
        if (fid) {
                b->fid1 = *((struct lu_fid*)fid);
                b->valid |= OBD_MD_FLID;
        }

        b->fsuid = cfs_curproc_fsuid();
        b->fsgid = cfs_curproc_fsgid();
        b->capability = cfs_curproc_cap_pack();
        EXIT;
}

void mdc_pack_req_body(struct ptlrpc_request *req, int offset,
                       __u64 valid, struct ll_fid *fid, int ea_size,
                       int flags)
{
        if (mdc_req_is_2_0_server(req))
                mdc_pack_req_body_20(req, offset, valid, fid, ea_size, flags);
        else
                mdc_pack_req_body_18(req, offset, valid, fid, ea_size, flags);
}

/* packing of MDS records */
static void mdc_create_pack_18(struct ptlrpc_request *req, int offset,
                               struct mdc_op_data *op_data, const void *data,
                               int datalen, __u32 mode, __u32 uid, __u32 gid,
                               cfs_cap_t cap_effective, __u64 rdev)
{
        struct mds_rec_create *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        rec->cr_opcode  = REINT_CREATE;
        rec->cr_fsuid   = uid;
        rec->cr_fsgid   = gid;
        rec->cr_cap     = cap_effective;
        rec->cr_fid     = op_data->fid1;
        memset(&rec->cr_replayfid, 0, sizeof(rec->cr_replayfid));
        rec->cr_mode    = mode;
        rec->cr_rdev    = rdev;
        rec->cr_time    = op_data->mod_time;
        rec->cr_suppgid = op_data->suppgids[0];

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1, op_data->namelen + 1);
        LOGL0(op_data->name, op_data->namelen, tmp);

        if (data) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, datalen);
                memcpy (tmp, data, datalen);
        }
        EXIT;
}

static void mdc_create_pack_20(struct ptlrpc_request *req, int offset,
                               struct mdc_op_data *op_data, const void *data,
                               int datalen, __u32 mode, __u32 uid, __u32 gid,
                               cfs_cap_t cap_effective, __u64 rdev)
{
        struct mdt_rec_create *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        rec->cr_opcode   = REINT_CREATE;
        rec->cr_fsuid    = uid;
        rec->cr_fsgid    = gid;
        rec->cr_cap      = cap_effective;
        memcpy(&rec->cr_fid1, &op_data->fid1, sizeof(op_data->fid1));
        memcpy(&rec->cr_fid2, &op_data->fid2, sizeof(op_data->fid2));
        rec->cr_mode     = mode;
        rec->cr_rdev     = rdev;
        rec->cr_time     = op_data->mod_time;
        rec->cr_suppgid1 = op_data->suppgids[0];

        /* offset + 1  == capa */
        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, op_data->namelen + 1);
        LOGL0(op_data->name, op_data->namelen, tmp);

        if (data) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 3, datalen);
                memcpy(tmp, data, datalen);
        }
        EXIT;
}

void mdc_create_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *op_data, const void *data,
                     int datalen, __u32 mode, __u32 uid, __u32 gid,
                     cfs_cap_t cap_effective, __u64 rdev)
{
        if (mdc_req_is_2_0_server(req))
                mdc_create_pack_20(req, offset, op_data, data, datalen,
                                   mode, uid, gid, cap_effective, rdev);
        else
                mdc_create_pack_18(req, offset, op_data, data, datalen,
                                   mode, uid, gid, cap_effective, rdev);
}

static __u32 mds_pack_open_flags(__u32 flags, __u32 mode)
{
        __u32 cr_flags = (flags & (FMODE_READ | FMODE_WRITE |
                                   MDS_OPEN_DELAY_CREATE | MDS_OPEN_HAS_OBJS |
                                   MDS_OPEN_OWNEROVERRIDE | MDS_OPEN_LOCK));
        if (flags & O_CREAT)
                cr_flags |= MDS_OPEN_CREAT;
        if (flags & O_EXCL)
                cr_flags |= MDS_OPEN_EXCL;
        if (flags & O_TRUNC)
                cr_flags |= MDS_OPEN_TRUNC;
        if (flags & O_APPEND)
                cr_flags |= MDS_OPEN_APPEND;
        if (flags & O_SYNC)
                cr_flags |= MDS_OPEN_SYNC;
        if (flags & O_DIRECTORY)
                cr_flags |= MDS_OPEN_DIRECTORY;
        if (mode  & M_JOIN_FILE)
                cr_flags |= MDS_OPEN_JOIN_FILE;
#ifdef FMODE_EXEC
        if (flags & FMODE_EXEC)
                cr_flags |= MDS_FMODE_EXEC;
#endif
        return cr_flags;
}

/* packing of MDS records */
static void mdc_join_pack_18(struct ptlrpc_request *req, int offset,
                             struct mdc_op_data *op_data, __u64 head_size)
{
        struct mds_rec_join *rec;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*rec));
        LASSERT(rec != NULL);
        rec->jr_fid = op_data->fid2;
        rec->jr_headsize = head_size;
        EXIT;
}

static void mdc_join_pack_20(struct ptlrpc_request *req, int offset,
                             struct mdc_op_data *op_data, __u64 head_size)
{
        struct mdt_rec_join *rec;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*rec));
        LASSERT(rec != NULL);
        memcpy(&rec->jr_fid, &op_data->fid2, sizeof(op_data->fid2));
        rec->jr_headsize = head_size;
        EXIT;
}

void mdc_join_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *op_data, __u64 head_size)
{
        if (mdc_req_is_2_0_server(req))
                mdc_join_pack_20(req, offset, op_data, head_size);
        else
                mdc_join_pack_18(req, offset, op_data, head_size);
}

static void mdc_open_pack_18(struct ptlrpc_request *req, int offset,
                            struct mdc_op_data *op_data, __u32 mode, __u64 rdev,
                             __u32 flags, const void *lmm, int lmmlen)
{
        struct mds_rec_create *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        /* XXX do something about time, uid, gid */
        rec->cr_opcode  = REINT_OPEN;
        rec->cr_fsuid   = cfs_curproc_fsuid();
        rec->cr_fsgid   = cfs_curproc_fsgid();
        rec->cr_cap     = cfs_curproc_cap_pack();
        rec->cr_fid     = op_data->fid1;
        memset(&rec->cr_replayfid, 0, sizeof(rec->cr_replayfid));
        rec->cr_mode    = mode;
        rec->cr_flags   = mds_pack_open_flags(flags, mode);
        rec->cr_rdev    = rdev;
        rec->cr_time    = op_data->mod_time;
        rec->cr_suppgid = op_data->suppgids[0];

        if (op_data->name) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1,
                                     op_data->namelen + 1);
                LOGL0(op_data->name, op_data->namelen, tmp);
        }

        if (lmm) {
                rec->cr_flags |= MDS_OPEN_HAS_EA;
#ifndef __KERNEL__
                /*XXX a hack for liblustre to set EA (LL_IOC_LOV_SETSTRIPE) */
                rec->cr_replayfid = op_data->fid2;
#endif
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, lmmlen);
                memcpy (tmp, lmm, lmmlen);
        }
        EXIT;
}

static void mdc_open_pack_20(struct ptlrpc_request *req, int offset,
                            struct mdc_op_data *op_data, __u32 mode, __u64 rdev,
                             __u32 flags, const void *lmm, int lmmlen)
{
        struct mdt_rec_create *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        /* XXX do something about time, uid, gid */
        rec->cr_opcode = REINT_OPEN;
        rec->cr_fsuid  = cfs_curproc_fsuid();
        rec->cr_fsgid  = cfs_curproc_fsgid();
        rec->cr_cap    = cfs_curproc_cap_pack();
        memcpy(&rec->cr_fid1, &op_data->fid1, sizeof(op_data->fid1));
        memcpy(&rec->cr_fid2, &op_data->fid2, sizeof(op_data->fid2));
        rec->cr_mode   = mode;
        rec->cr_flags  = mds_pack_open_flags(flags, mode);
        rec->cr_rdev   = rdev;
        rec->cr_time   = op_data->mod_time;
        rec->cr_suppgid1 = op_data->suppgids[0];
        rec->cr_suppgid2 = op_data->suppgids[1];

        if (op_data->name) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 3,
                                     op_data->namelen + 1);
                CDEBUG(D_INFO, "offset=%d, src=%p(%d):%s, dst=%p\n",
                        offset, op_data->name, op_data->namelen,
                        op_data->name, tmp);
                LASSERT(tmp);
                LOGL0(op_data->name, op_data->namelen, tmp);
        }

        if (lmm) {
                rec->cr_flags |= MDS_OPEN_HAS_EA;
#ifndef __KERNEL__
                /*XXX a hack for liblustre to set EA (LL_IOC_LOV_SETSTRIPE) */
                memcpy(&rec->cr_fid2, &op_data->fid2, sizeof(op_data->fid2));
#endif
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 4, lmmlen);
                memcpy(tmp, lmm, lmmlen);
        }
        EXIT;
}

void mdc_open_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *op_data, __u32 mode, __u64 rdev,
                   __u32 flags, const void *lmm, int lmmlen)
{
        if (mdc_req_is_2_0_server(req))
                mdc_open_pack_20(req, offset, op_data, mode, rdev,
                                 flags, lmm, lmmlen);
        else
                mdc_open_pack_18(req, offset, op_data, mode, rdev,
                                 flags, lmm, lmmlen);

}

static inline __u64 attr_pack(unsigned int ia_valid) {
        __u64 sa_valid = 0;

        if (ia_valid & ATTR_MODE)
                sa_valid |= MDS_ATTR_MODE;
        if (ia_valid & ATTR_UID)
                sa_valid |= MDS_ATTR_UID;
        if (ia_valid & ATTR_GID)
                sa_valid |= MDS_ATTR_GID;
        if (ia_valid & ATTR_SIZE)
                sa_valid |= MDS_ATTR_SIZE;
        if (ia_valid & ATTR_ATIME)
                sa_valid |= MDS_ATTR_ATIME;
        if (ia_valid & ATTR_MTIME)
                sa_valid |= MDS_ATTR_MTIME;
        if (ia_valid & ATTR_CTIME)
                sa_valid |= MDS_ATTR_CTIME;
        if (ia_valid & ATTR_ATIME_SET)
                sa_valid |= MDS_ATTR_ATIME_SET;
        if (ia_valid & ATTR_MTIME_SET)
                sa_valid |= MDS_ATTR_MTIME_SET;
        if (ia_valid & ATTR_FORCE)
                sa_valid |= MDS_ATTR_FORCE;
        if (ia_valid & ATTR_ATTR_FLAG)
                sa_valid |= MDS_ATTR_ATTR_FLAG;
        if (ia_valid & ATTR_KILL_SUID)
                sa_valid |=  MDS_ATTR_KILL_SUID;
        if (ia_valid & ATTR_KILL_SGID)
                sa_valid |= MDS_ATTR_KILL_SGID;
        if (ia_valid & ATTR_CTIME_SET)
                sa_valid |= MDS_ATTR_CTIME_SET;
        if (ia_valid & ATTR_FROM_OPEN)
                sa_valid |= MDS_ATTR_FROM_OPEN;
        if (ia_valid & MDS_OPEN_OWNEROVERRIDE)
                /* NFSD hack (see bug 5781) */
                sa_valid |= MDS_OPEN_OWNEROVERRIDE;
        return sa_valid;
}

void mdc_setattr_pack_18(struct ptlrpc_request *req, int offset,
                         struct mdc_op_data *data, struct iattr *iattr, void *ea,
                         int ealen, void *ea2, int ea2len)
{
        struct lov_user_md     *lum = NULL;
        struct mds_rec_setattr *rec = lustre_msg_buf(req->rq_reqmsg, offset,
                                                     sizeof(*rec));
        ENTRY;

        rec->sa_opcode = REINT_SETATTR;
        rec->sa_fsuid = cfs_curproc_fsuid();
        rec->sa_fsgid = cfs_curproc_fsgid();
        rec->sa_cap = cfs_curproc_cap_pack();
        rec->sa_fid = data->fid1;
        rec->sa_suppgid = -1;

        if (iattr) {
                rec->sa_valid = attr_pack(iattr->ia_valid);
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

        if (ealen == 0) {
                EXIT;
                return;
        }

        lum = lustre_msg_buf(req->rq_reqmsg, offset + 1, ealen);
        if (ea == NULL) { /* Remove LOV EA */
                lum->lmm_magic = LOV_USER_MAGIC_V1;
                lum->lmm_stripe_size = 0;
                lum->lmm_stripe_count = 0;
                lum->lmm_stripe_offset = (typeof(lum->lmm_stripe_offset))(-1);
        } else {
                memcpy(lum, ea, ealen);
        }

        if (ea2len == 0) {
                EXIT;
                return;
        }
        memcpy(lustre_msg_buf(req->rq_reqmsg, offset + 2, ea2len), ea2, ea2len);

        EXIT;
}

static void mdc_setattr_pack_20(struct ptlrpc_request *req, int offset,
                                struct mdc_op_data *data, struct iattr *iattr,
                                void *ea, int ealen, void *ea2, int ea2len)
{
        struct mdt_rec_setattr *rec = lustre_msg_buf(req->rq_reqmsg, offset,
                                                     sizeof(*rec));
        struct lov_user_md     *lum = NULL;
        ENTRY;

        rec->sa_opcode  = REINT_SETATTR;
        rec->sa_fsuid   = cfs_curproc_fsuid();
        rec->sa_fsgid   = cfs_curproc_fsgid();
        rec->sa_cap     = cfs_curproc_cap_pack();
        memcpy(&rec->sa_fid, &data->fid1, sizeof(data->fid1));
        rec->sa_suppgid = -1;

        if (iattr) {
                rec->sa_valid   = attr_pack(iattr->ia_valid);
                rec->sa_mode    = iattr->ia_mode;
                rec->sa_uid     = iattr->ia_uid;
                rec->sa_gid     = iattr->ia_gid;
                rec->sa_size    = iattr->ia_size;
//              rec->sa_blocks  = iattr->ia_blocks;
                rec->sa_atime   = LTIME_S(iattr->ia_atime);
                rec->sa_mtime   = LTIME_S(iattr->ia_mtime);
                rec->sa_ctime   = LTIME_S(iattr->ia_ctime);
                rec->sa_attr_flags = 
                        ((struct ll_iattr_struct *)iattr)->ia_attr_flags;
                if ((iattr->ia_valid & ATTR_GID) && in_group_p(iattr->ia_gid))
                        rec->sa_suppgid = iattr->ia_gid;
                else
                        rec->sa_suppgid = data->suppgids[0];
        }
        if (ealen == 0) {
                EXIT;
                return;
        }
        lum = lustre_msg_buf(req->rq_reqmsg, offset + 3, ealen);
        if (ea == NULL) { /* Remove LOV EA */
                lum->lmm_magic = LOV_USER_MAGIC_V1;
                lum->lmm_stripe_size = 0;
                lum->lmm_stripe_count = 0;
                lum->lmm_stripe_offset = (typeof(lum->lmm_stripe_offset))(-1);
        } else {
                memcpy(lum, ea, ealen);
        }

        if (ea2len == 0) {
                EXIT;
                return;
        }
        memcpy(lustre_msg_buf(req->rq_reqmsg, offset + 4, ea2len), ea2, ea2len);
        EXIT;
}

void mdc_setattr_pack(struct ptlrpc_request *req, int offset,
                      struct mdc_op_data *data, struct iattr *iattr,
                      void *ea, int ealen, void *ea2, int ea2len)
{
        if (mdc_req_is_2_0_server(req))
                mdc_setattr_pack_20(req, offset, data, iattr,
                                    ea, ealen, ea2, ea2len);
        else
                mdc_setattr_pack_18(req, offset, data, iattr,
                                    ea, ealen, ea2, ea2len);
}

static void mdc_unlink_pack_18(struct ptlrpc_request *req, int offset,
                               struct mdc_op_data *data)
{
        struct mds_rec_unlink *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));
        LASSERT (rec != NULL);

        rec->ul_opcode = REINT_UNLINK;
        rec->ul_fsuid = cfs_curproc_fsuid();
        rec->ul_fsgid = cfs_curproc_fsgid();
        rec->ul_cap = cfs_curproc_cap_pack();
        rec->ul_mode = data->create_mode;
        rec->ul_suppgid = data->suppgids[0];
        rec->ul_fid1 = data->fid1;
        rec->ul_fid2 = data->fid2;
        rec->ul_time = data->mod_time;

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1, data->namelen + 1);
        LASSERT (tmp != NULL);
        LOGL0(data->name, data->namelen, tmp);
        EXIT;
}

static void mdc_unlink_pack_20(struct ptlrpc_request *req, int offset,
                               struct mdc_op_data *data)
{
        struct mdt_rec_unlink *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));
        LASSERT (rec != NULL);

        rec->ul_opcode  = REINT_UNLINK;
        rec->ul_fsuid   = cfs_curproc_fsuid();
        rec->ul_fsgid   = cfs_curproc_fsgid();
        rec->ul_cap     = cfs_curproc_cap_pack();
        rec->ul_mode    = data->create_mode;
        rec->ul_suppgid1= data->suppgids[0];
        memcpy(&rec->ul_fid1, &data->fid1, sizeof(data->fid1));
        memcpy(&rec->ul_fid2, &data->fid2, sizeof(data->fid2));
        rec->ul_time    = data->mod_time;

        /* NULL capa is skipped. */

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, data->namelen + 1);
        LASSERT (tmp != NULL);
        LOGL0(data->name, data->namelen, tmp);
        EXIT;
}

void mdc_unlink_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *data)
{
        if (mdc_req_is_2_0_server(req))
                mdc_unlink_pack_20(req, offset, data);
        else
                mdc_unlink_pack_18(req, offset, data);
}
static void mdc_link_pack_18(struct ptlrpc_request *req, int offset,
                             struct mdc_op_data *data)
{
        struct mds_rec_link *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        rec->lk_opcode = REINT_LINK;
        rec->lk_fsuid = cfs_curproc_fsuid();
        rec->lk_fsgid = cfs_curproc_fsgid();
        rec->lk_cap = cfs_curproc_cap_pack();
        rec->lk_suppgid1 = data->suppgids[0];
        rec->lk_suppgid2 = data->suppgids[1];
        rec->lk_fid1 = data->fid1;
        rec->lk_fid2 = data->fid2;
        rec->lk_time = data->mod_time;

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1, data->namelen + 1);
        LOGL0(data->name, data->namelen, tmp);
        EXIT;
}

static void mdc_link_pack_20(struct ptlrpc_request *req, int offset,
                             struct mdc_op_data *data)
{
        struct mdt_rec_link *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        rec->lk_opcode   = REINT_LINK;
        rec->lk_fsuid    = cfs_curproc_fsuid();
        rec->lk_fsgid    = cfs_curproc_fsgid();
        rec->lk_cap      = cfs_curproc_cap_pack();
        rec->lk_suppgid1 = data->suppgids[0];
        rec->lk_suppgid2 = data->suppgids[1];
        memcpy(&rec->lk_fid1, &data->fid1, sizeof(data->fid1));
        memcpy(&rec->lk_fid2, &data->fid2, sizeof(data->fid2));
        rec->lk_time     = data->mod_time;


        /* capa @ offset + 1; */
        /* capa @ offset + 2; */

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 3, data->namelen + 1);
        LOGL0(data->name, data->namelen, tmp);
        EXIT;
}

void mdc_link_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *data)
{
        if (mdc_req_is_2_0_server(req))
                mdc_link_pack_20(req, offset, data);
        else
                mdc_link_pack_18(req, offset, data);
}

static void mdc_rename_pack_18(struct ptlrpc_request *req, int offset,
                               struct mdc_op_data *data, const char *old, 
                               int oldlen, const char *new, int newlen)
{
        struct mds_rec_rename *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        /* XXX do something about time, uid, gid */
        rec->rn_opcode = REINT_RENAME;
        rec->rn_fsuid = cfs_curproc_fsuid();
        rec->rn_fsgid = cfs_curproc_fsgid();
        rec->rn_cap = cfs_curproc_cap_pack();
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
        EXIT;
}

static void mdc_rename_pack_20(struct ptlrpc_request *req, int offset,
                               struct mdc_op_data *data, const char *old,
                               int oldlen, const char *new, int newlen)
{
        struct mdt_rec_rename *rec;
        char *tmp;
        ENTRY;

        rec = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*rec));

        /* XXX do something about time, uid, gid */
        rec->rn_opcode   = REINT_RENAME;
        rec->rn_fsuid    = cfs_curproc_fsuid();
        rec->rn_fsgid    = cfs_curproc_fsgid();
        rec->rn_cap      = cfs_curproc_cap_pack();
        rec->rn_suppgid1 = data->suppgids[0];
        rec->rn_suppgid2 = data->suppgids[1];
        memcpy(&rec->rn_fid1, &data->fid1, sizeof(data->fid1));
        memcpy(&rec->rn_fid2, &data->fid2, sizeof(data->fid2));
        rec->rn_time     = data->mod_time;
        rec->rn_mode     = data->create_mode;


        /* skip capa @ offset + 1 */
        /* skip capa @ offset + 2 */

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 3, oldlen + 1);
        LOGL0(old, oldlen, tmp);

        if (new) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 4, newlen + 1);
                LOGL0(new, newlen, tmp);
        }
        EXIT;
}

void mdc_rename_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *data, const char *old,
                     int oldlen, const char *new, int newlen)
{
        if (mdc_req_is_2_0_server(req))
                mdc_rename_pack_20(req, offset, data, old, oldlen, new, newlen);
        else
                mdc_rename_pack_18(req, offset, data, old, oldlen, new, newlen);
}

static void mdc_getattr_pack_18(struct ptlrpc_request *req, int offset,
                                __u64 valid, int flags,
                                struct mdc_op_data *data)
{
        struct mds_body *b;
        ENTRY;

        b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));

        b->fsuid = cfs_curproc_fsuid();
        b->fsgid = cfs_curproc_fsgid();
        b->capability = cfs_curproc_cap_pack();
        b->valid = valid;
        b->flags = flags | MDS_BFLAG_EXT_FLAGS;
        /* skip MDS_BFLAG_EXT_FLAGS to verify the "client < 1.4.7" case 
         * refer to bug 12848.
         */
        if (OBD_FAIL_CHECK(OBD_FAIL_MDC_OLD_EXT_FLAGS))
                b->flags &= ~MDS_BFLAG_EXT_FLAGS;
        b->suppgid = data->suppgids[0];

        b->fid1 = data->fid1;
        b->fid2 = data->fid2;
        if (data->name) {
                char *tmp;
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1,
                                     data->namelen + 1);
                memcpy(tmp, data->name, data->namelen);
                data->name = tmp;
        }
        EXIT;
}

static void mdc_getattr_pack_20(struct ptlrpc_request *req, int offset,
                                __u64 valid, int flags,
                                struct mdc_op_data *data, int ea_size)
{
        struct mdt_body *b;
        ENTRY;

        b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*b));

        b->fsuid = cfs_curproc_fsuid();
        b->fsgid = cfs_curproc_fsgid();
        b->capability = cfs_curproc_cap_pack();
        b->valid = valid;
        b->eadatasize = ea_size;
        b->flags = flags | MDS_BFLAG_EXT_FLAGS;
        b->suppgid = data->suppgids[0];

        memcpy(&b->fid1, &data->fid1, sizeof(data->fid1));
        memcpy(&b->fid2, &data->fid2, sizeof(data->fid2));
        b->valid |= OBD_MD_FLID;
        if (data->name) {
                char *tmp;
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2,
                                     data->namelen + 1);
                LASSERT(tmp);
                LOGL0(data->name, data->namelen, tmp);
        }
        EXIT;
}

void mdc_getattr_pack(struct ptlrpc_request *req, int offset,
                      __u64 valid, int flags,
                      struct mdc_op_data *data, int ea_size)
{
        if (mdc_req_is_2_0_server(req))
                mdc_getattr_pack_20(req, offset, valid, flags, data, ea_size);
        else
                mdc_getattr_pack_18(req, offset, valid, flags, data);
}
static void mdc_close_pack_18(struct ptlrpc_request *req, int offset,
                              struct mdc_op_data *data,
                              struct obdo *oa, __u64 valid,
                              struct obd_client_handle *och)
{
        struct mds_body *body;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*body));

        body->fid1 = data->fid1;
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
        EXIT;
}

static void mdc_close_pack_20(struct ptlrpc_request *req, int offset,
                              struct mdc_op_data *data,
                              struct obdo *oa, __u64 valid,
                              struct obd_client_handle *och)
{
        struct mdt_epoch *epoch;
        struct mdt_rec_setattr *rec;
        ENTRY;

        epoch = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*epoch));
        rec = lustre_msg_buf(req->rq_reqmsg, offset + 1, sizeof(*rec));

        rec->sa_opcode  = REINT_SETATTR;
        rec->sa_fsuid   = cfs_curproc_fsuid();
        rec->sa_fsgid   = cfs_curproc_fsgid();
        rec->sa_cap     = cfs_curproc_cap_pack();
        rec->sa_suppgid = -1;

        memcpy(&rec->sa_fid, &data->fid1, sizeof(data->fid1));

        if (oa->o_valid & OBD_MD_FLATIME) {
                rec->sa_atime = oa->o_atime;
                rec->sa_valid |= MDS_ATTR_ATIME;
        }
        if (oa->o_valid & OBD_MD_FLMTIME) {
                rec->sa_mtime = oa->o_mtime;
                rec->sa_valid |= MDS_ATTR_MTIME;
        }
        if (oa->o_valid & OBD_MD_FLCTIME) {
                rec->sa_ctime = oa->o_ctime;
                rec->sa_valid |= MDS_ATTR_CTIME;
        }
        if (oa->o_valid & OBD_MD_FLSIZE) {
                rec->sa_size = oa->o_size;
                rec->sa_valid |= MDS_ATTR_SIZE;
        }
        if (oa->o_valid & OBD_MD_FLBLOCKS) {
                rec->sa_blocks = oa->o_blocks;
                rec->sa_valid |= MDS_ATTR_BLOCKS;
        }
        if (oa->o_valid & OBD_MD_FLFLAGS) {
                rec->sa_attr_flags = oa->o_flags;
                rec->sa_valid |= MDS_ATTR_ATTR_FLAG;
        }

        epoch->handle = och->och_fh;
        epoch->ioepoch = 0;
        epoch->flags = 0;

        EXIT;
}


void mdc_close_pack(struct ptlrpc_request *req, int offset,
                    struct mdc_op_data *data,
                    struct obdo *oa, __u64 valid,
                    struct obd_client_handle *och)
{
        if (mdc_req_is_2_0_server(req))
                mdc_close_pack_20(req, offset, data, oa, valid, och);
        else
                mdc_close_pack_18(req, offset, data, oa, valid, och);
}
struct mdc_cache_waiter {
        struct list_head        mcw_entry;
        wait_queue_head_t       mcw_waitq;
};

static int mdc_req_avail(struct client_obd *cli, struct mdc_cache_waiter *mcw)
{
        int rc;
        ENTRY;
        spin_lock(&cli->cl_loi_list_lock);
        rc = list_empty(&mcw->mcw_entry);
        spin_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
};

/* We record requests in flight in cli->cl_r_in_flight here.
 * There is only one write rpc possible in mdc anyway. If this to change
 * in the future - the code may need to be revisited. */
int mdc_enter_request(struct client_obd *cli)
{
        int rc = 0;
        struct mdc_cache_waiter mcw;
        struct l_wait_info lwi = LWI_INTR(LWI_ON_SIGNAL_NOOP, NULL);

        spin_lock(&cli->cl_loi_list_lock);
        if (cli->cl_r_in_flight >= cli->cl_max_rpcs_in_flight) {
                list_add_tail(&mcw.mcw_entry, &cli->cl_cache_waiters);
                init_waitqueue_head(&mcw.mcw_waitq);
                spin_unlock(&cli->cl_loi_list_lock);
                rc = l_wait_event(mcw.mcw_waitq, mdc_req_avail(cli, &mcw),
                                  &lwi);
                if (rc) {
                        spin_lock(&cli->cl_loi_list_lock);
                        if (list_empty(&mcw.mcw_entry))
                                cli->cl_r_in_flight--;
                        list_del_init(&mcw.mcw_entry);
                        spin_unlock(&cli->cl_loi_list_lock);
                }
        } else {
                cli->cl_r_in_flight++;
                spin_unlock(&cli->cl_loi_list_lock);
        }
        return rc;
}

void mdc_exit_request(struct client_obd *cli)
{
        struct list_head *l, *tmp;
        struct mdc_cache_waiter *mcw;

        spin_lock(&cli->cl_loi_list_lock);
        cli->cl_r_in_flight--;

        list_for_each_safe(l, tmp, &cli->cl_cache_waiters) {
                if (cli->cl_r_in_flight >= cli->cl_max_rpcs_in_flight) {
                        /* No free request slots anymore */
                        break;
                }

                mcw = list_entry(l, struct mdc_cache_waiter, mcw_entry);
                list_del_init(&mcw->mcw_entry);
                cli->cl_r_in_flight++;
                wake_up(&mcw->mcw_waitq);
        }
        /* Empty waiting list? Decrease reqs in-flight number */

        spin_unlock(&cli->cl_loi_list_lock);
}
