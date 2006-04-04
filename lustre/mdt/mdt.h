/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _MDT_H
#define _MDT_H

#if defined(__KERNEL__)

/*
 * struct ptlrpc_client
 */
#include <linux/lustre_net.h>
/*
 * struct obd_connect_data
 * struct lustre_handle
 */
#include <linux/lustre_idl.h>

#include <linux/lu_object.h>

struct md_device_operations;

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

struct md_object;

struct md_device {
        struct lu_device             md_lu_dev;
        struct md_device_operations *md_ops;
};

struct md_device_operations {
        int (*mdo_root_get)(struct md_device *m, struct lu_fid *f);
        int (*mdo_mkdir)(struct md_object *o, const char *name,
                         struct md_object *child);
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
};

struct md_object {
        struct lu_object mo_lu;
};

static inline int lu_device_is_md(struct lu_device *d)
{
        return d->ld_type->ldt_tags & LU_DEVICE_MD;
}

static inline struct md_object *lu2md(struct lu_object *o)
{
        LASSERT(lu_device_is_md(o->lo_dev));
        return container_of(o, struct md_object, mo_lu);
}

static inline struct md_device *md_device_get(struct md_object *o)
{
        LASSERT(lu_device_is_md(o->mo_lu.lo_dev));
        return container_of(o->mo_lu.lo_dev, struct md_device, md_lu_dev);
}

struct mdt_object {
        struct lu_object_header mot_header;
        struct md_object        mot_obj;
};

struct mdt_lock_handle {
        struct lustre_handle    mlh_lh;
        ldlm_mode_t             mlh_mode;
};

void mdt_lock_handle_init(struct mdt_lock_handle *lh);
void mdt_lock_handle_fini(struct mdt_lock_handle *lh);

struct mdd_object {
        struct md_object  mod_obj;
};

struct osd_object {
        struct lu_object  oo_lu;
        struct dentry    *oo_dentry;
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
        struct mds_body       *mti_body;
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

int fid_lock(const struct lu_fid *, struct lustre_handle *, ldlm_mode_t);
void fid_unlock(const struct lu_fid *, struct lustre_handle *, ldlm_mode_t);

#endif /* __KERNEL__ */
#endif /* _MDT_H */
