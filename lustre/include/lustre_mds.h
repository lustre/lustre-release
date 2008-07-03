/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_MDS_H
#define _LUSTRE_MDS_H

#include <lustre_handles.h>
#include <libcfs/libcfs.h>
#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_dlm.h>
#include <lustre_log.h>
#include <lustre_export.h>

#if defined(__linux__)
#include <linux/lustre_mds.h>
#elif defined(__APPLE__)
#include <darwin/lustre_mds.h>
#elif defined(__WINNT__)
#include <winnt/lustre_mds.h>
#else
#error Unsupported operating system.
#endif

struct mds_group_info {
        struct obd_uuid *uuid;
        int group;
};

/* mds/mds_reint.c */
int mds_lov_write_objids(struct obd_device *obd);
void mds_lov_update_objids(struct obd_device *obd, struct lov_mds_md *lmm);


#define MDS_LOV_MD_NAME "trusted.lov"
#define MDS_LMV_MD_NAME "trusted.lmv"
#define MDD_OBD_NAME    "mdd_obd"
#define MDD_OBD_UUID    "mdd_obd_uuid"
#define MDD_OBD_TYPE    "mds"

static inline int md_should_create(__u32 flags)
{
       return !(flags & MDS_OPEN_DELAY_CREATE ||
               !(flags & FMODE_WRITE));
}

#endif
