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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
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

void mdc_readdir_pack(struct ptlrpc_request *req, int req_offset,
                      __u64 offset, __u32 size, struct lustre_id *mdc_id)
{
        struct mds_body *b;

        b = lustre_msg_buf(req->rq_reqmsg, req_offset, sizeof (*b));
        b->id1 = *mdc_id;
        b->size = offset;                       /* !! */
        b->nlink = size;                        /* !! */
}

/* packing of MDS records */
void mdc_open_pack(struct lustre_msg *msg, int offset,
                   struct mdc_op_data *op_data, __u32 mode,
                   __u64 rdev, __u32 flags, const void *lmm,
                   int lmmlen, void *key, int keylen)
{
        struct mds_rec_create *rec;
        char *tmp;
        
        rec = lustre_msg_buf(msg, offset, sizeof (*rec));

        /* XXX do something about time, uid, gid */
        rec->cr_opcode = REINT_OPEN;
        if (op_data != NULL)
                rec->cr_id = op_data->id1;
        memset(&rec->cr_replayid, 0, sizeof(rec->cr_replayid));
        rec->cr_flags = mds_pack_open_flags(flags) | op_data->flags ;
        rec->cr_time = op_data->mod_time;
        rec->cr_mode = mode;
        rec->cr_rdev = rdev;

        if (op_data->name) {
                tmp = lustre_msg_buf(msg, offset + 1,
                                     op_data->namelen + 1);
                LOGL0(op_data->name, op_data->namelen, tmp);
        }

        if (lmm) {
                rec->cr_flags |= MDS_OPEN_HAS_EA;
                tmp = lustre_msg_buf(msg, offset + 2, lmmlen);
                memcpy (tmp, lmm, lmmlen);
        }
        if (key) {
                rec->cr_flags |= MDS_OPEN_HAS_KEY;
                tmp = lustre_msg_buf(msg, offset + 3, keylen);
                memcpy(tmp, key, keylen); 
        }
}

void mdc_getattr_pack(struct lustre_msg *msg, int offset,
                      __u64 valid, int flags, struct mdc_op_data *data)
{
        struct mds_body *b;
        b = lustre_msg_buf(msg, offset, sizeof (*b));

        b->valid = valid;
        b->flags = flags;

        b->id1 = data->id1;
        b->id2 = data->id2;
        if (data->name) {
                char *tmp;
                tmp = lustre_msg_buf(msg, offset + 1,
                                     data->namelen + 1);
                LOGL0(data->name, data->namelen, tmp);
        }
}

void mdc_close_pack(struct ptlrpc_request *req, int offset,
                    struct mdc_op_data *op_data,
                    struct obd_client_handle *och)
{
        obd_valid valid = op_data->valid;
        struct mds_body *body;

        body = lustre_msg_buf(req->rq_reqmsg, offset,
                              sizeof(*body));
        body->id1 = op_data->id1;

        memcpy(&body->handle, &och->och_fh, sizeof(body->handle));
        if (valid & OBD_MD_FLATIME) {
                body->atime = op_data->atime;
                body->valid |= OBD_MD_FLATIME;
        }
        if (valid & OBD_MD_FLMTIME) {
                body->mtime = op_data->mtime;
                body->valid |= OBD_MD_FLMTIME;
        }
        if (valid & OBD_MD_FLCTIME) {
                body->ctime = op_data->ctime;
                body->valid |= OBD_MD_FLCTIME;
        }
        if (valid & OBD_MD_FLSIZE) {
                body->size = op_data->size;
                body->valid |= OBD_MD_FLSIZE;
        }
        if (valid & OBD_MD_FLBLOCKS) {
                body->blocks = op_data->blocks;
                body->valid |= OBD_MD_FLBLOCKS;
        }
        if (valid & OBD_MD_FLFLAGS) {
                body->flags = op_data->flags;
                body->valid |= OBD_MD_FLFLAGS;
        }
        if (valid & OBD_MD_FLEPOCH) {
                body->io_epoch = op_data->io_epoch;
                body->valid |= OBD_MD_FLEPOCH;
        }
}

/* 
 * these methods needed for saying higher levels that MDC does not pack/unpack
 * any EAs. This is needed to have real abstraction and do not try to recognize
 * what OBD type is to avoid calling these methods on it, as they may not be
 * implemented.
 *
 * Sometimes pack/unpack calls happen to MDC too. This is for instance default
 * striping info for directories and our goal here is to skip them with no
 * errors or any complains.
 */
int mdc_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
               struct lov_stripe_md *lsm)
{
        ENTRY;
        RETURN(0);
}

int mdc_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm, int lmm_size)
{
        ENTRY;
        RETURN(0);
}

