/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_internal.h
 *  Lustre Cluster Metadata Manager (cmm),
 *  MDC device
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Mike Pershin <tappro@clusterfs.com>
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

#ifndef _CMM_MDC_INTERNAL_H
#define _CMM_MDC_INTERNAL_H

#if defined(__KERNEL__)

#include <lustre_net.h>
#include <obd.h>
#include <md_object.h>

struct mdc_cli_desc {
        struct lustre_handle     cl_conn;
        /* uuid of remote MDT to connect */
        struct obd_uuid          cl_srv_uuid;
        /* mdc uuid */
        struct obd_uuid          cl_cli_uuid;
        /* export of mdc obd */
        struct obd_export        *cl_exp;
};

struct mdc_device {
        struct md_device        mc_md_dev;
        /* other MD servers in cluster */
        struct list_head        mc_linkage;
        mdsno_t                 mc_num;
        struct mdc_cli_desc     mc_desc;
        struct semaphore        mc_fid_sem;
};

struct mdc_thread_info {
        struct md_op_data       mci_opdata;
        struct ptlrpc_request  *mci_req;
};

struct mdc_object {
	struct md_object        mco_obj;
};

static inline struct lu_device *mdc2lu_dev(struct mdc_device *mc)
{
	return (&mc->mc_md_dev.md_lu_dev);
}

static inline struct mdc_device *md2mdc_dev(struct md_device *md)
{
        return container_of0(md, struct mdc_device, mc_md_dev);
}

static inline struct mdc_device *mdc_obj2dev(struct mdc_object *mco)
{
	return (md2mdc_dev(md_obj2dev(&mco->mco_obj)));
}

static inline struct mdc_object *lu2mdc_obj(struct lu_object *lo)
{
	return container_of0(lo, struct mdc_object, mco_obj.mo_lu);
}

static inline struct mdc_object *md2mdc_obj(struct md_object *mo)
{
	return container_of0(mo, struct mdc_object, mco_obj);
}

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

#endif /* __KERNEL__ */
#endif /* _CMM_MDC_INTERNAL_H */
