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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
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
        __u32 cr_flags = (flags & (FMODE_READ | FMODE_WRITE |
                                   MDS_OPEN_DELAY_CREATE | MDS_OPEN_HAS_EA |
                                   MDS_OPEN_HAS_OBJS | MDS_OPEN_OWNEROVERRIDE |
                                   MDS_OPEN_LOCK));
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
        if (flags & O_JOIN_FILE)
                cr_flags |= MDS_OPEN_JOIN_FILE;
#ifdef FMODE_EXEC
        if (flags & FMODE_EXEC)
                cr_flags |= MDS_FMODE_EXEC;
#endif
        return cr_flags;
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
#ifndef __KERNEL__
                /*XXX a hack for liblustre to set EA (LL_IOC_LOV_SETSTRIPE) */
                rec->cr_replayfid = op_data->fid2;
#endif
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, lmmlen);
                memcpy (tmp, lmm, lmmlen);
        }
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

void mdc_getattr_pack(struct ptlrpc_request *req, int offset, __u64 valid,
                      int flags, struct mdc_op_data *data)
{
        struct mds_body *b;
        b = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*b));

        b->fsuid = current->fsuid;
        b->fsgid = current->fsgid;
        b->capability = current->cap_effective;
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
}

void mdc_close_pack(struct ptlrpc_request *req, int offset, struct obdo *oa,
                    __u64 valid, struct obd_client_handle *och)
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
void mdc_enter_request(struct client_obd *cli)
{
        struct mdc_cache_waiter mcw;
        struct l_wait_info lwi = { 0 };

        spin_lock(&cli->cl_loi_list_lock);
        if (cli->cl_r_in_flight >= cli->cl_max_rpcs_in_flight) {
                list_add_tail(&mcw.mcw_entry, &cli->cl_cache_waiters);
                init_waitqueue_head(&mcw.mcw_waitq);
                spin_unlock(&cli->cl_loi_list_lock);
                l_wait_event(mcw.mcw_waitq, mdc_req_avail(cli, &mcw), &lwi);
        } else {
                cli->cl_r_in_flight++;
                spin_unlock(&cli->cl_loi_list_lock);
        }
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
