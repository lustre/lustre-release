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

#ifndef _MDC_INTERNAL_H
#define _MDC_INTERNAL_H

#include <lustre_mdc.h>

void mdc_pack_req_body(struct ptlrpc_request *req, int offset,
                       __u64 valid, struct lu_fid *fid, int ea_size, int flags);
void mdc_pack_rep_body(struct ptlrpc_request *);
void mdc_readdir_pack(struct ptlrpc_request *req, int pos, __u64 offset,
		      __u32 size, struct lu_fid *fid);
void mdc_getattr_pack(struct ptlrpc_request *req, int offset, int valid,
                      int flags, struct md_op_data *data);
void mdc_setattr_pack(struct ptlrpc_request *req, int offset,
                      struct md_op_data *op_data,
                      struct iattr *iattr, void *ea, int ealen,
                      void *ea2, int ea2len);
void mdc_create_pack(struct ptlrpc_request *req, int offset,
                     struct md_op_data *op_data, const void *data, int datalen,
		     __u32 mode, __u32 uid, __u32 gid, __u32 cap_effective,
		     __u64 rdev);
void mdc_open_pack(struct ptlrpc_request *req, int offset,
                   struct md_op_data *op_data, __u32 mode, __u64 rdev,
                   __u32 flags, const void *data, int datalen);
void mdc_join_pack(struct ptlrpc_request *req, int offset, 
                   struct md_op_data *op_data, __u64 head_size);
void mdc_unlink_pack(struct ptlrpc_request *req, int offset,
                     struct md_op_data *op_data);
void mdc_link_pack(struct ptlrpc_request *req, int offset,
                   struct md_op_data *op_data);
void mdc_rename_pack(struct ptlrpc_request *req, int offset,
                     struct md_op_data *op_data,
                     const char *old, int oldlen, const char *new, int newlen);
void mdc_close_pack(struct ptlrpc_request *req, int offset, struct md_op_data *op_data,
		    int valid, struct obd_client_handle *och);
void mdc_exit_request(struct client_obd *cli);
void mdc_enter_request(struct client_obd *cli);

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
        if (!it || (it->it_op != IT_GETATTR && it->it_op != IT_LOOKUP)) {
                down(&lck->rpcl_sem);
                LASSERT(lck->rpcl_it == NULL);
                lck->rpcl_it = it;
        }
}

static inline void mdc_put_rpc_lock(struct mdc_rpc_lock *lck,
                                    struct lookup_intent *it)
{
        if (!it || (it->it_op != IT_GETATTR && it->it_op != IT_LOOKUP)) {
                LASSERT(it == lck->rpcl_it);
                lck->rpcl_it = NULL;
                up(&lck->rpcl_sem);
        }
        EXIT;
}

/* Quota stuff */
extern quota_interface_t *quota_interface;

/* mdc/mdc_locks.c */
int mdc_set_lock_data(struct obd_export *exp,
                      __u64 *lockh, void *data);

int mdc_change_cbdata(struct obd_export *exp, struct lu_fid *fid,
                      ldlm_iterator_t it, void *data);
int mdc_intent_lock(struct obd_export *exp,
                    struct md_op_data *,
                    void *lmm, int lmmsize,
                    struct lookup_intent *, int,
                    struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking, int extra_lock_flags);
int mdc_enqueue(struct obd_export *exp,
                int lock_type,
                struct lookup_intent *it,
                int lock_mode,
                struct md_op_data *op_data,
                struct lustre_handle *lockh,
                void *lmm,
                int lmmlen,
                ldlm_completion_callback cb_completion,
                ldlm_blocking_callback cb_blocking,
                void *cb_data, int extra_lock_flags);

/* mdc/mdc_request.c */
int mdc_init_ea_size(struct obd_export *exp, int easize, int def_easzie,
                     int cookiesize);

int mdc_getstatus(struct obd_export *exp, struct lu_fid *rootfid);
int mdc_getattr(struct obd_export *exp, struct lu_fid *fid,
                obd_valid valid, int ea_size,
                struct ptlrpc_request **request);
int mdc_getattr_name(struct obd_export *exp, struct lu_fid *fid,
                     const char *filename, int namelen, obd_valid valid,
                     int ea_size, struct ptlrpc_request **request);
int mdc_setattr(struct obd_export *exp, struct md_op_data *op_data,
                struct iattr *iattr, void *ea, int ealen, void *ea2, int ea2len,
                struct ptlrpc_request **request);
int mdc_setxattr(struct obd_export *exp, struct lu_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, int flags,
                 struct ptlrpc_request **request);
int mdc_getxattr(struct obd_export *exp, struct lu_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, int flags, struct ptlrpc_request **request);
int mdc_open(struct obd_export *exp, obd_id ino, int type, int flags,
             struct lov_mds_md *lmm, int lmm_size, struct lustre_handle *fh,
             struct ptlrpc_request **);

struct obd_client_handle;

int mdc_get_lustre_md(struct obd_export *md_exp, struct ptlrpc_request *req,
                      int offset, struct obd_export *dt_exp, struct lustre_md *md);

int mdc_free_lustre_md(struct obd_export *exp, struct lustre_md *md);

int mdc_set_open_replay_data(struct obd_export *exp,
                             struct obd_client_handle *och,
                             struct ptlrpc_request *open_req);

int mdc_clear_open_replay_data(struct obd_export *exp,
                               struct obd_client_handle *och);

int mdc_close(struct obd_export *, struct md_op_data *,
              struct obd_client_handle *, struct ptlrpc_request **);

int mdc_readpage(struct obd_export *exp, struct lu_fid *fid,
                 __u64 offset,  struct page *, struct ptlrpc_request **);

int mdc_create(struct obd_export *exp, struct md_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid,
               __u32 gid, __u32 cap_effective, __u64 rdev,
               struct ptlrpc_request **request);

int mdc_unlink(struct obd_export *exp, struct md_op_data *op_data,
               struct ptlrpc_request **request);

int mdc_link(struct obd_export *exp, struct md_op_data *op_data,
             struct ptlrpc_request **);

int mdc_rename(struct obd_export *exp, struct md_op_data *op_data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request);

int mdc_sync(struct obd_export *exp, struct lu_fid *fid,
             struct ptlrpc_request **);

int mdc_lock_match(struct obd_export *exp, int flags,
                   struct lu_fid *fid, ldlm_type_t type,
                   ldlm_policy_data_t *policy, ldlm_mode_t mode,
                   struct lustre_handle *lockh);

int mdc_cancel_unused(struct obd_export *exp, struct lu_fid *fid,
                      int flags, void *opaque);

int mdc_done_writing(struct obd_export *exp, struct md_op_data *op_data);

#endif
