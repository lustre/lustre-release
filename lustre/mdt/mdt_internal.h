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
 *   Author: Huang Hua <huanghua@clusterfs.com>
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
#include <dt_object.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <lustre_req_layout.h>
/* LR_CLIENT_SIZE, etc. */
#include <lustre_disk.h>


/* Data stored per client in the last_rcvd file.  In le32 order. */
struct mdt_client_data {
        __u8  mcd_uuid[40];     /* client UUID */
        __u64 mcd_last_transno; /* last completed transaction ID */
        __u64 mcd_last_xid;     /* xid for the last transaction */
        __u32 mcd_last_result;  /* result from last RPC */
        __u32 mcd_last_data;    /* per-op data (disposition for open &c.) */
        __u8  mcd_padding[LR_CLIENT_SIZE - 64];
};

/* copied from lr_server_data.
 * mds data stored at the head of last_rcvd file. In le32 order. */
struct mdt_server_data {
        __u8  msd_uuid[40];        /* server UUID */
        __u64 msd_unused;          /* was fsd_last_objid - don't use for now */
        __u64 msd_last_transno;    /* last completed transaction ID */
        __u64 msd_mount_count;     /* incarnation number */
        __u32 msd_feature_compat;  /* compatible feature flags */
        __u32 msd_feature_rocompat;/* read-only compatible feature flags */
        __u32 msd_feature_incompat;/* incompatible feature flags */
        __u32 msd_server_size;     /* size of server data area */
        __u32 msd_client_start;    /* start of per-client data area */
        __u16 msd_client_size;     /* size of per-client data area */
        __u16 msd_subdir_count;    /* number of subdirectories for objects */
        __u64 msd_catalog_oid;     /* recovery catalog object id */
        __u32 msd_catalog_ogen;    /* recovery catalog inode generation */
        __u8  msd_peeruuid[40];    /* UUID of MDS associated with this OST */
        __u32 msd_ost_index;       /* index number of OST in LOV */
        __u32 msd_mdt_index;       /* index number of MDT in LMV */
        __u8  msd_padding[LR_SERVER_SIZE - 148];
};

struct mdt_object;
/* file data for open files on MDS */
struct mdt_file_data {
        struct portals_handle mfd_handle; /* must be first */
        struct list_head      mfd_list;   /* protected by med_open_lock */
        __u64                 mfd_xid;    /* xid of the open request */
        int                   mfd_mode;   /* open mode provided by client */
        struct mdt_object    *mfd_object; /* point to opened object */
};

struct mdt_device {
        /* super-class */
        struct md_device           mdt_md_dev;
        struct ptlrpc_service     *mdt_service;
        struct ptlrpc_service     *mdt_readpage_service;
        /* DLM name-space for meta-data locks maintained by this server */
        struct ldlm_namespace     *mdt_namespace;
        /* ptlrpc handle for MDS->client connections (for lock ASTs). */
        struct ptlrpc_client      *mdt_ldlm_client;
        /* underlying device */
        struct md_device          *mdt_child;
        struct dt_device          *mdt_bottom;
        /*
         * Options bit-fields.
         */
        struct {
                signed int         mo_user_xattr :1;
                signed int         mo_acl        :1;
                signed int         mo_compat_resname:1;
        } mdt_opts;
        /* Transaction related stuff here */
        spinlock_t                 mdt_transno_lock;
        __u64                      mdt_last_transno;
        __u64                      mdt_last_committed;
        /* transaction callbacks */
        struct dt_txn_callback     mdt_txn_cb;
        /* last_rcvd file */
        struct dt_object          *mdt_last_rcvd;

        /* these values should be updated from lov if necessary.
         * or should be placed somewhere else. */
        int                        mdt_max_mdsize;
        int                        mdt_max_cookiesize;
        __u64                      mdt_mount_count;

        struct mdt_server_data     mdt_msd;
        unsigned long              mdt_client_bitmap[(LR_MAX_CLIENTS >> 3) / sizeof(long)];
};

/*XXX copied from mds_internal.h */
#define MDT_SERVICE_WATCHDOG_TIMEOUT (obd_timeout * 1000)
#define MDT_ROCOMPAT_SUPP       (OBD_ROCOMPAT_LOVOBJID)
#define MDT_INCOMPAT_SUPP       (OBD_INCOMPAT_MDT | OBD_INCOMPAT_COMMON_LR)

struct mdt_object {
        struct lu_object_header mot_header;
        struct md_object        mot_obj;
};

struct mdt_lock_handle {
        struct lustre_handle    mlh_lh;
        ldlm_mode_t             mlh_mode;
};

enum {
        MDT_REP_BUF_NR_MAX = 8
};

enum {
        MDT_LH_PARENT,
        MDT_LH_CHILD,
        MDT_LH_OLD,
        MDT_LH_NEW,
        MDT_LH_NR
};

struct mdt_reint_record {
        mdt_reint_t          rr_opcode;
        const struct lu_fid *rr_fid1;
        const struct lu_fid *rr_fid2;
        const char          *rr_name;
        const char          *rr_tgt;
        int                  rr_eadatalen;
        const void          *rr_eadata;
        int                  rr_logcookielen;
        const struct llog_cookie  *rr_logcookies;

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
        struct md_attr             mti_attr;
        /*
         * reint record. contains information for reint operations.
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

        /* temporary stuff used by thread */
        struct lu_fid              mti_tmp_fid1;
        struct lu_fid              mti_tmp_fid2;
        ldlm_policy_data_t         mti_policy;
        struct ldlm_res_id         mti_res_id;
        union {
                struct obd_uuid    uuid;
                char               ns_name[48];
        } mti_u;
        /* transaction number of current request */
        __u64                      mti_transno;
};
/*
 * Info allocated per-transaction.
 */
struct mdt_txn_info {
        __u64  txi_transno;
};

static inline struct md_device_operations *mdt_child_ops(struct mdt_device * m)
{
        LASSERT(m->mdt_child);
        return m->mdt_child->md_ops;
}

static inline struct md_object *mdt_object_child(struct mdt_object *o)
{
        return lu2md(lu_object_next(&o->mot_obj.mo_lu));
}

static inline struct ptlrpc_request *mdt_info_req(struct mdt_thread_info *info)
{
         return info->mti_pill.rc_req;
}

static inline void mdt_object_get(const struct lu_context *ctxt,
                                  struct mdt_object *o)
{
        lu_object_get(&o->mot_obj.mo_lu);
}

static inline void mdt_object_put(const struct lu_context *ctxt,
                                  struct mdt_object *o)
{
        lu_object_put(ctxt, &o->mot_obj.mo_lu);
}

static inline const struct lu_fid *mdt_object_fid(struct mdt_object *o)
{
        return lu_object_fid(&o->mot_obj.mo_lu);
}

int mdt_object_lock(struct mdt_thread_info *,
                    struct mdt_object *,
                    struct mdt_lock_handle *,
                    __u64);

void mdt_object_unlock(struct mdt_thread_info *,
                       struct mdt_object *,
                       struct mdt_lock_handle *,
                       int decref);

struct mdt_object *mdt_object_find(const struct lu_context *,
                                   struct mdt_device *,
                                   const struct lu_fid *);
struct mdt_object *mdt_object_find_lock(struct mdt_thread_info *,
                                        const struct lu_fid *,
                                        struct mdt_lock_handle *,
                                        __u64);
void mdt_object_unlock_put(struct mdt_thread_info *,
                           struct mdt_object *,
                           struct mdt_lock_handle *,
                           int decref);

int mdt_reint_unpack(struct mdt_thread_info *info, __u32 op);
int mdt_reint_rec(struct mdt_thread_info *);
void mdt_pack_attr2body(struct mdt_body *b, struct lu_attr *attr,
                        const struct lu_fid *fid);

int mdt_getxattr(struct mdt_thread_info *info);
int mdt_setxattr(struct mdt_thread_info *info);

void mdt_lock_handle_init(struct mdt_lock_handle *lh);
void mdt_lock_handle_fini(struct mdt_lock_handle *lh);


int mdt_object_exists(const struct lu_context *ctx,
                      const struct lu_object *o);

int mdt_fs_setup(const struct lu_context *ctxt,
                 struct mdt_device *mdt);

void mdt_fs_cleanup(const struct lu_context *ctxt,
                    struct mdt_device *mdt);

int mdt_client_free(const struct lu_context *ctxt,
                    struct mdt_device *mdt,
                    struct mdt_export_data *med);

int mdt_update_server_data(const struct lu_context *ctxt,
                           struct mdt_device *mdt,
                           int sync);

int mdt_client_add(const struct lu_context *ctxt,
                   struct mdt_device *mdt,
                   struct mdt_export_data *med,
                   int cl_idx);

int mdt_pin(struct mdt_thread_info* info);

int mdt_lock_new_child(struct mdt_thread_info *info,
                       struct mdt_object *o,
                       struct mdt_lock_handle *child_lockh);

int mdt_reint_open(struct mdt_thread_info *info);

int mdt_mfd_close(const struct lu_context *ctxt,
                  struct mdt_file_data *mfd);

int mdt_close(struct mdt_thread_info *info);

int mdt_done_writing(struct mdt_thread_info *info);
int mdt_handle_last_unlink(struct mdt_thread_info *, struct mdt_object *,
                           const struct req_format *);


/* debug issues helper starts here*/
#define MDT_FAIL_CHECK(id)                                              \
({                                                                      \
        if (OBD_FAIL_CHECK(id))                                         \
                CERROR(LUSTRE_MDT0_NAME": " #id " test failed\n");      \
        OBD_FAIL_CHECK(id);                                             \
})

#endif /* __KERNEL__ */
#endif /* _MDT_H */
