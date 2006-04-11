/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/handler.c
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
#include <linux/lustre_net.h>
#include <linux/obd.h>
/*
 * struct obd_connect_data
 * struct lustre_handle
 */
#include <linux/lustre_idl.h>

#include <linux/md_object.h>

struct ptlrpc_service_conf {
        int psc_nbufs;
        int psc_bufsize;
        int psc_max_req_size;
        int psc_max_reply_size;
        int psc_req_portal;
        int psc_rep_portal;
        int psc_watchdog_timeout; /* in ms */
        int psc_num_threads;
};

struct mdt_device {
        /* super-class */
        struct md_device           mdt_md_dev;
        struct ptlrpc_service     *mdt_service;
        struct ptlrpc_service_conf mdt_service_conf;
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

struct mdd_object {
        struct md_object  mod_obj;
};

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

/*
 * Common data shared by mdt-level handlers. This is allocated per-thread to
 * reduce stack consumption.
 */
struct mdt_thread_info {
        struct mdt_device     *mti_mdt;
        /*
         * number of buffers in reply message.
         */
        int                    mti_rep_buf_nr;
        /*
         * sizes of reply buffers.
         */
        int                    mti_rep_buf_size[MDT_REP_BUF_NR_MAX];
        /*
         * Body for "habeo corpus" operations.
         */
        struct mdt_body       *mti_body;
        /*
         * Lock request for "habeo clavis" operations.
         */
        struct ldlm_request   *mti_dlm_req;
        /*
         * Host object. This is released at the end of mdt_handler().
         */
        struct mdt_object     *mti_object;
        /*
         * Additional fail id that can be set by handler. Passed to
         * target_send_reply().
         */
        int                    mti_fail_id;
        /*
         * A couple of lock handles.
         */
        struct mdt_lock_handle mti_lh[MDT_LH_NR];

};

int fid_lock(struct ldlm_namespace *, const struct lu_fid *,
             struct lustre_handle *, ldlm_mode_t, ldlm_policy_data_t *);

void fid_unlock(struct ldlm_namespace *, const struct lu_fid *,
                struct lustre_handle *, ldlm_mode_t);

#endif /* __KERNEL__ */
#endif /* _MDT_H */
