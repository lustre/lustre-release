/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mdt/mdt_internal.h
 *  Lustre Metadata Target (mdt) request handler
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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

#ifndef _MDT_INTERNAL_H
#define _MDT_INTERNAL_H

#if defined(__KERNEL__)

/*
 * struct ptlrpc_client
 */
#include <lustre_net.h>
#include <obd.h>
/*
 * struct obd_connect_data
 * struct lustre_handle
 */
#include <lustre/lustre_idl.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <lustre_req_layout.h>

struct mdt_device {
        /* super-class */
        struct md_device           mdt_md_dev;
        struct ptlrpc_service     *mdt_service;
        /* DLM name-space for meta-data locks maintained by this server */
        struct ldlm_namespace     *mdt_namespace;
        /* ptlrpc handle for MDS->client connections (for lock ASTs). */
        struct ptlrpc_client       mdt_ldlm_client;
        /* underlying device */
        struct md_device          *mdt_child;
        /*
         * Device flags, taken from enum mdt_flags. No locking (so far) is
         * necessary.
         */
        unsigned long              mdt_flags;

        /* Seq management related stuff */
        struct lu_seq_mgr         *mdt_seq_mgr;

        struct dt_device          *mdt_bottom;
        /*
         * Options bit-fields.
         */
        struct {
                signed int         mo_user_xattr :1;
                signed int         mo_acl        :1;
        } mdt_opts;
};

static inline struct md_device_operations *mdt_child_ops(struct mdt_device * m)
{
        LASSERT(m->mdt_child);
        return m->mdt_child->md_ops;
}

enum mdt_flags {
        /*
         * This mdt works with legacy clients with different resource name
         * encoding (pre-fid, etc.).
         */
        MDT_CL_COMPAT_RESNAME = 1 << 0,
};

struct mdt_object {
        struct lu_object_header mot_header;
        struct md_object        mot_obj;
};

static inline struct md_object *mdt_object_child(struct mdt_object *o)
{
        return lu2md(lu_object_next(&o->mot_obj.mo_lu));
}

struct mdt_lock_handle {
        struct lustre_handle    mlh_lh;
        ldlm_mode_t             mlh_mode;
};

void mdt_lock_handle_init(struct mdt_lock_handle *lh);
void mdt_lock_handle_fini(struct mdt_lock_handle *lh);

int md_device_init(struct md_device *md, struct lu_device_type *t);
void md_device_fini(struct md_device *md);

enum {
        MDT_REP_BUF_NR_MAX = 8
};

enum {
        MDT_LH_PARENT,
        MDT_LH_CHILD,
        MDT_LH_NR
};

struct mdt_reint_record {
        mdt_reint_t          rr_opcode;
        const struct lu_fid *rr_fid1;
        struct lu_fid       *rr_fid2;
        const char          *rr_name;
        const char          *rr_tgt;
        __u32                rr_flags;
};

struct mdt_reint_reply {
        struct mdt_body    *mrr_body;
        struct lov_mds_md  *mrr_md;
        struct llog_cookie *mrr_cookie;
};

/*
 * Common data shared by mdt-level handlers. This is allocated per-thread to
 * reduce stack consumption.
 */
struct mdt_thread_info {
        const struct lu_context   *mti_ctxt;
        struct mdt_device         *mti_mdt;
        /*
         * number of buffers in reply message.
         */
        int                        mti_rep_buf_nr;
        /*
         * sizes of reply buffers.
         */
        int                        mti_rep_buf_size[MDT_REP_BUF_NR_MAX];
        /*
         * Body for "habeo corpus" operations.
         */
        const struct mdt_body     *mti_body;
        /*
         * Lock request for "habeo clavis" operations.
         */
        const struct ldlm_request *mti_dlm_req;
        /*
         * Host object. This is released at the end of mdt_handler().
         */
        struct mdt_object         *mti_object;
        /*
         * Object attributes.
         */
        struct lu_attr             mti_attr;
        /*
         * reint record. Containing information for reint operations.
         */
        struct mdt_reint_record    mti_rr;
        /*
         * Additional fail id that can be set by handler. Passed to
         * target_send_reply().
         */
        int                        mti_fail_id;
        /*
         * A couple of lock handles.
         */
        struct mdt_lock_handle     mti_lh[MDT_LH_NR];
        /*
         * for req-layout interface.
         */
        struct req_capsule         mti_pill;
        /*
         * buffer for mdt_statfs().
         *
         * XXX this is probably huge overkill, because statfs is not that
         * frequent.
         */
        struct kstatfs             mti_sfs;
        struct mdt_reint_reply     mti_reint_rep;
};

int fid_lock(struct ldlm_namespace *, const struct lu_fid *,
             struct lustre_handle *, ldlm_mode_t,
             ldlm_policy_data_t *);

void fid_unlock(struct ldlm_namespace *, const struct lu_fid *,
                struct lustre_handle *, ldlm_mode_t);

struct mdt_object *mdt_object_find(const struct lu_context *,
                                   struct mdt_device *, const struct lu_fid *);
void mdt_object_put(const struct lu_context *ctxt, struct mdt_object *);

int mdt_object_lock(struct ldlm_namespace *, struct mdt_object *,
                    struct mdt_lock_handle *, __u64);

void mdt_object_unlock(struct ldlm_namespace *, struct mdt_object *,
                       struct mdt_lock_handle *);

struct mdt_object *mdt_object_find_lock(const struct lu_context *,
                                        struct mdt_device *,
                                        const struct lu_fid *,
                                        struct mdt_lock_handle *, __u64);

int mdt_reint_unpack(struct mdt_thread_info *info, __u32 op);
int mdt_reint_rec(struct mdt_thread_info *);
void mdt_pack_attr2body(struct mdt_body *b, struct lu_attr *attr);
const struct lu_fid *mdt_object_fid(struct mdt_object *o);
struct ptlrpc_request *mdt_info_req  (struct mdt_thread_info *info);

#endif /* __KERNEL__ */
#endif /* _MDT_H */
