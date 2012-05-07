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
 * lustre/cmm/mdc_internal.h
 *
 * Lustre Cluster Metadata Manager (cmm), MDC device
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */

#ifndef _CMM_MDC_INTERNAL_H
#define _CMM_MDC_INTERNAL_H

#if defined(__KERNEL__)

#include <lustre_net.h>
#include <obd.h>
#include <md_object.h>
/**
 * \addtogroup cmm
 * @{
 */
/**
 * \defgroup cmm_mdc cmm_mdc
 *
 * This is mdc wrapper device to work with old MDC obd-based devices.
 * @{
 */
/**
 * MDC client description.
 */
struct mdc_cli_desc {
        /** uuid of remote MDT to connect */
        struct obd_uuid          cl_srv_uuid;
        /** mdc uuid */
        struct obd_uuid          cl_cli_uuid;
        /** export of mdc obd */
        struct obd_export        *cl_exp;
};

/**
 * MDC device.
 */
struct mdc_device {
        /** md_device instance for MDC */
        struct md_device        mc_md_dev;
        /** other MD servers in cluster */
        cfs_list_t              mc_linkage;
        /** number of current device */
        mdsno_t                 mc_num;
        /** mdc client description */
        struct mdc_cli_desc     mc_desc;
        /** Protects ??*/
        cfs_semaphore_t         mc_fid_sem;
};

/**
 * mdc thread info. Local storage for varios data.
 */
struct mdc_thread_info {
        /** Storage for md_op_data */
        struct md_op_data       mci_opdata;
        /** Storage for ptlrpc request */
        struct ptlrpc_request  *mci_req;
};

/** mdc object. */
struct mdc_object {
        /** md_object instance for mdc_object */
        struct md_object        mco_obj;
};

/** Get lu_device from mdc_device. */
static inline struct lu_device *mdc2lu_dev(struct mdc_device *mc)
{
        return (&mc->mc_md_dev.md_lu_dev);
}

/** Get mdc_device from md_device. */
static inline struct mdc_device *md2mdc_dev(struct md_device *md)
{
        return container_of0(md, struct mdc_device, mc_md_dev);
}

/** Get mdc_device from mdc_object. */
static inline struct mdc_device *mdc_obj2dev(struct mdc_object *mco)
{
        return (md2mdc_dev(md_obj2dev(&mco->mco_obj)));
}

/** Get mdc_object from lu_object. */
static inline struct mdc_object *lu2mdc_obj(struct lu_object *lo)
{
        return container_of0(lo, struct mdc_object, mco_obj.mo_lu);
}

/** Get mdc_object from md_object. */
static inline struct mdc_object *md2mdc_obj(struct md_object *mo)
{
        return container_of0(mo, struct mdc_object, mco_obj);
}

/** Get mdc_device from lu_device. */
static inline struct mdc_device *lu2mdc_dev(struct lu_device *ld)
{
        return container_of0(ld, struct mdc_device, mc_md_dev.md_lu_dev);
}

struct lu_object *mdc_object_alloc(const struct lu_env *,
                                   const struct lu_object_header *,
                                   struct lu_device *);

void cmm_mdc_init_ea_size(const struct lu_env *env, struct mdc_device *mc,
                      int max_mdsize, int max_cookiesize);
#ifdef HAVE_SPLIT_SUPPORT
int mdc_send_page(struct cmm_device *cmm, const struct lu_env *env,
                  struct md_object *mo, struct page *page, __u32 end);
#endif
/** @} */
/** @} */
#endif /* __KERNEL__ */
#endif /* _CMM_MDC_INTERNAL_H */
