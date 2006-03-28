/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _MDT_H
#define _MDT_H

#if defined(__KERNEL__)

#include <linux/lu_object.h>

#define LUSTRE_MDT0_NAME "mdt0"

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

struct md_device {
	struct lu_device             md_lu_dev;
	struct md_device_operations *md_ops;
};

struct md_device_operations {
        int (*mdo_root_get)(struct md_device *m, struct lfid *f);
};

struct mdt_device {
        /* super-class */
        struct md_device           mdt_md_dev;
        struct ptlrpc_service     *mdt_service;
        struct ptlrpc_service_conf mdt_service_conf;
        /* DLM name-space for meta-data locks maintained by this server */
        struct ldlm_namespace     *mdt_namespace;
        /* DLM handle for MDS->client connections (for lock ASTs). */
        struct ldlm_client         mdt_ldlm_client;
        /* underlying device */
        struct md_device          *mdt_mdd;
};

/*
 * Meta-data stacking.
 */

struct md_object;
struct md_device;

struct md_object {
	struct lu_object mo_lu;
};

static inline struct md_object *lu2md(struct lu_object *o)
{
	return container_of(o, struct md_object, mo_lu);
}

static inline struct md_device *md_device_get(struct md_object *o)
{
	return container_of(o->mo_lu.lo_dev, struct md_device, md_lu);
}

struct mdt_object {
	struct lu_object_header mot_header;
	struct md_object        mot_obj;
};

struct mdd_object {
	struct md_object  mod_obj;
};

struct osd_object {
	struct lu_object  oo_lu;
	struct dentry    *oo_dentry;
};

int md_device_init(struct md_device *md);
void md_device_fini(struct md_device *md);

#endif /* __KERNEL__ */
#endif /* _MDT_H */
