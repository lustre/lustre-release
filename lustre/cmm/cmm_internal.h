/*
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/cmm/cmm_internal.h
 *
 * Lustre Cluster Metadata Manager (cmm)
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */
/**
 * \defgroup cmm cmm
 * Cluster Metadata Manager.
 * Implementation of md interface to provide operation between MDS-es.
 *
 * CMM has two set of md methods, one is for local operation which uses MDD,
 * second is for remote operations to call different MDS.
 * When object is allocated then proper set of methods are set for it. *
 * @{
 */
#ifndef _CMM_INTERNAL_H
#define _CMM_INTERNAL_H

#if defined(__KERNEL__)

#include <obd.h>
#include <lustre_fld.h>
#include <md_object.h>
#include <lustre_acl.h>

/**
 * md_device extention for CMM layer.
 */
struct cmm_device {
        /** md_device instance */
        struct md_device        cmm_md_dev;
        /** device flags, taken from enum cmm_flags */
        __u32                   cmm_flags;
        /** underlaying device in MDS stack, usually MDD */
        struct md_device       *cmm_child;
        /** FLD client to talk to FLD */
        struct lu_client_fld   *cmm_fld;
        /** Number of this MDS server in cluster */
        mdsno_t                 cmm_local_num;
        /** Total number of other MDS */
        __u32                   cmm_tgt_count;
        /** linked list of all remove MDS clients */
        cfs_list_t              cmm_targets;
        /** lock for cmm_device::cmm_targets operations */
        cfs_spinlock_t          cmm_tgt_guard;
        /** /proc entry with CMM data */
        cfs_proc_dir_entry_t   *cmm_proc_entry;
        /** CMM statistic */
        struct lprocfs_stats   *cmm_stats;
};

/**
 * CMM flags
 */
enum cmm_flags {
        /** Device initialization complete. */
        CMM_INITIALIZED = 1 << 0
};

/**
 * Wrapper for md_device::md_ops of underlaying device cmm_child.
 */
static inline const struct md_device_operations *
cmm_child_ops(struct cmm_device *d)
{
        return d->cmm_child->md_ops;
}

/** Wrapper to get cmm_device by contained md_device */
static inline struct cmm_device *md2cmm_dev(struct md_device *m)
{
        return container_of0(m, struct cmm_device, cmm_md_dev);
}

/** Wrapper to get cmm_device by contained lu_device */
static inline struct cmm_device *lu2cmm_dev(struct lu_device *d)
{
        return container_of0(d, struct cmm_device, cmm_md_dev.md_lu_dev);
}

/** Wrapper to get lu_device from cmm_device */
static inline struct lu_device *cmm2lu_dev(struct cmm_device *d)
{
        return (&d->cmm_md_dev.md_lu_dev);
}

#ifdef HAVE_SPLIT_SUPPORT
/**
 * \ingroup split
 * States of split operation.
 */
enum cmm_split_state {
        CMM_SPLIT_UNKNOWN,
        CMM_SPLIT_NONE,
        CMM_SPLIT_NEEDED,
        CMM_SPLIT_DONE,
        CMM_SPLIT_DENIED
};
#endif

/** CMM container for md_object. */
struct cmm_object {
        struct md_object cmo_obj;
};

/**
 * \defgroup cml cml
 * CMM local operations.
 * @{
 */
/**
 * Local CMM object.
 */
struct cml_object {
        /** cmm_object instance. */
        struct cmm_object    cmm_obj;
#ifdef HAVE_SPLIT_SUPPORT
        /** split state of object (for dirs only) */
        enum cmm_split_state clo_split;
#endif
};
/** @} */

/**
 * \defgroup cmr cmr
 * CMM remote operations.
 * @{
 */
/**
 * Remote CMM object.
 */
struct cmr_object {
        /** cmm_object instance */
        struct cmm_object cmm_obj;
        /** mds number where object is placed */
        mdsno_t           cmo_num;
};
/** @} */

enum {
        CMM_SPLIT_PAGE_COUNT = 1
};

/**
 * CMM thread info.
 * This is storage for all variables used in CMM functions and it is needed as
 * stack replacement.
 */
struct cmm_thread_info {
        struct md_attr        cmi_ma;
        struct lu_buf         cmi_buf;
        struct lu_fid         cmi_fid; /* used for le/cpu conversions */
        struct lu_rdpg        cmi_rdpg;
        /** pointers to pages for readpage. */
        struct page          *cmi_pages[CMM_SPLIT_PAGE_COUNT];
        struct md_op_spec     cmi_spec;
        struct lmv_stripe_md  cmi_lmv;
        char                  cmi_xattr_buf[LUSTRE_POSIX_ACL_MAX_SIZE];
        /** Ops object filename */
        struct lu_name        cti_name;
};

/**
 * Wrapper to get cmm_device from cmm_object.
 */
static inline struct cmm_device *cmm_obj2dev(struct cmm_object *c)
{
        return (md2cmm_dev(md_obj2dev(&c->cmo_obj)));
}

/**
 * Get cmm_device from related lu_device.
 */
static inline struct cmm_object *lu2cmm_obj(struct lu_object *o)
{
        //LASSERT(lu_device_is_cmm(o->lo_dev));
        return container_of0(o, struct cmm_object, cmo_obj.mo_lu);
}

/**
 * Get cmm object from corresponding md_object.
 */
static inline struct cmm_object *md2cmm_obj(struct md_object *o)
{
        return container_of0(o, struct cmm_object, cmo_obj);
}

/**
 * Get next lower-layer md_object from current cmm_object.
 */
static inline struct md_object *cmm2child_obj(struct cmm_object *o)
{
        return (o ? lu2md(lu_object_next(&o->cmo_obj.mo_lu)) : NULL);
}

/**
 * Extract lu_fid from corresponding cmm_object.
 */
static inline struct lu_fid* cmm2fid(struct cmm_object *obj)
{
       return &(obj->cmo_obj.mo_lu.lo_header->loh_fid);
}

struct cmm_thread_info *cmm_env_info(const struct lu_env *env);
struct lu_object *cmm_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *);
/**
 * \addtogroup cml
 * @{
 */
/** Get cml_object from lu_object. */
static inline struct cml_object *lu2cml_obj(struct lu_object *o)
{
        return container_of0(o, struct cml_object, cmm_obj.cmo_obj.mo_lu);
}
/** Get cml_object from md_object. */
static inline struct cml_object *md2cml_obj(struct md_object *mo)
{
        return container_of0(mo, struct cml_object, cmm_obj.cmo_obj);
}
/** Get cml_object from cmm_object */
static inline struct cml_object *cmm2cml_obj(struct cmm_object *co)
{
        return container_of0(co, struct cml_object, cmm_obj);
}
/** @} */

int cmm_upcall(const struct lu_env *env, struct md_device *md,
               enum md_upcall_event ev, void *data);

#ifdef HAVE_SPLIT_SUPPORT
/**
 * \defgroup split split
 * @{
 */

#define CMM_MD_SIZE(stripes)  (sizeof(struct lmv_stripe_md) +  \
                               (stripes) * sizeof(struct lu_fid))

/** Get and initialize lu_bug from cmm_thread_info. */
static inline struct lu_buf *cmm_buf_get(const struct lu_env *env,
                                         void *area, ssize_t len)
{
        struct lu_buf *buf;

        buf = &cmm_env_info(env)->cmi_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

int cmm_split_check(const struct lu_env *env, struct md_object *mp,
                    const char *name);
int cmm_split_expect(const struct lu_env *env, struct md_object *mo,
                     struct md_attr *ma, int *split);
int cmm_split_dir(const struct lu_env *env, struct md_object *mo);
int cmm_split_access(const struct lu_env *env, struct md_object *mo,
                     mdl_mode_t lm);
/** @} */
#endif

int cmm_fld_lookup(struct cmm_device *cm, const struct lu_fid *fid,
                   mdsno_t *mds, const struct lu_env *env);

int cmm_procfs_init(struct cmm_device *cmm, const char *name);
int cmm_procfs_fini(struct cmm_device *cmm);

void cmm_lprocfs_time_start(const struct lu_env *env);
void cmm_lprocfs_time_end(const struct lu_env *env, struct cmm_device *cmm,
                          int idx);
/**
 * CMM counters.
 */
enum {
        LPROC_CMM_SPLIT_CHECK,
        LPROC_CMM_SPLIT,
        LPROC_CMM_LOOKUP,
        LPROC_CMM_CREATE,
        LPROC_CMM_NR
};

#endif /* __KERNEL__ */
#endif /* _CMM_INTERNAL_H */
/** @} */
