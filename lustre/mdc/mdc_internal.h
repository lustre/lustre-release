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
#ifndef MDC_INTERNAL_H
#define MDC_INTERNAL_H

int mdc_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
               struct lov_stripe_md *lsm);

int mdc_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm, int lmm_size);

void mdc_getattr_pack(struct lustre_msg *msg, int offset,
                      __u64 valid, int flags,
                      struct mdc_op_data *op_data);

void mdc_open_pack(struct lustre_msg *msg, int offset,
                   struct mdc_op_data *op_data, __u32 mode,
                   __u64 rdev, __u32 flags, const void *lmm,
                   int lmmlen, void *key, int keylen);

void mdc_close_pack(struct ptlrpc_request *req, int offset,
                    struct mdc_op_data *op_data,
                    struct obd_client_handle *och);

void mdc_readdir_pack(struct ptlrpc_request *req, int req_offset,
                      __u64 offset, __u32 size, struct lustre_id *mdc_id);

struct mdc_open_data {
        struct obd_client_handle *mod_och;
        struct ptlrpc_request    *mod_open_req;
        struct ptlrpc_request    *mod_close_req;
};

struct mdc_rpc_lock {
        struct semaphore rpcl_sem;
        struct lookup_intent *rpcl_it;
};

static inline void mdc_init_rpc_lock(struct mdc_rpc_lock *lck)
{
        sema_init(&lck->rpcl_sem, 1);
        lck->rpcl_it = NULL;
}

static inline void mdc_get_rpc_lock(struct mdc_rpc_lock *lck, 
                                    struct lookup_intent *it)
{
        ENTRY;
        down(&lck->rpcl_sem);
        if (it) { 
                lck->rpcl_it = it;
        }
}

static inline void mdc_put_rpc_lock(struct mdc_rpc_lock *lck, 
                                    struct lookup_intent *it)
{
        EXIT;
        if (it == NULL) {
                LASSERT(it == lck->rpcl_it);
                up(&lck->rpcl_sem);
                return;
        }
        if (it) {
                LASSERT(it == lck->rpcl_it);
                lck->rpcl_it = NULL;
                up(&lck->rpcl_sem);
        }
}

#endif /* MDC_INTERNAL_H */
