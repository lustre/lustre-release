/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mdt/mdt_lib.c
 *  Lustre Metadata Target (mdt) request unpacking helper.
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *   Author: Huang Hua <huanghua@clusterfs.com>
 *
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


#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"


/* unpacking */
static int mdt_setattr_unpack(struct mdt_thread_info *info)
{
#ifdef MDT_CODE
        struct mdt_rec_setattr *rec;
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule *pill = &info->mti_pill;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_SETATTR);

        if (rec == NULL)
                RETURN (-EFAULT);

        rr->rr_fid1 = &rec->sa_fid;
        attr->la_valid = rec->sa_valid;
        attr->la_mode  = rec->sa_mode;
        attr->la_uid   = rec->sa_uid;
        attr->la_gid   = rec->sa_gid;
        attr->la_size  = rec->sa_size;
        attr->la_flags = rec->sa_attr_flags;
        attr->la_ctime = rec->sa_ctime;
        attr->la_atime = rec->sa_atime;
        attr->la_mtime = rec->sa_mtime;

        if (req_capsule_field_present(pill, &RMF_EADATA)) {
                rr->rr_eadata = req_capsule_client_get(pill, &RMF_EADATA);
                rr->rr_eadatalen = req_capsule_get_size(pill, 
                                                        &RMF_EADATA,
                                                        RCL_CLIENT);
        }
        if (req_capsule_field_present(pill, &RMF_LOGCOOKIES)) {
                rr->rr_logcookies = req_capsule_client_get(pill, 
                                                           &RMF_LOGCOOKIES);
                rr->rr_logcookielen = req_capsule_get_size(pill, 
                                                           &RMF_LOGCOOKIES,
                                                           RCL_CLIENT);
        }

        RETURN(0);
#endif
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_create_unpack(struct mdt_thread_info *info)
{
        struct mdt_rec_create *rec;
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule *pill = &info->mti_pill;
        int result = 0;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_CREATE);
        if (rec != NULL) {
                rr->rr_fid1 = &rec->cr_fid1;
                rr->rr_fid2 = &rec->cr_fid2;
                attr->la_mode = rec->cr_mode;
                rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
#ifdef MDT_CODE
                attr->la_rdev  = rec->cr_rdev;
                attr->la_uid   = rec->cr_fsuid;
                attr->la_gid   = rec->cr_fsgid;
                attr->la_flags = rec->cr_flags;
                attr->la_ctime = rec->cr_time;
                if (req_capsule_field_present(pill, &RMF_SYMTGT))
                        rr->rr_tgt  = req_capsule_client_get(pill, &RMF_SYMTGT);
#endif
        } else
                result = -EFAULT;
        RETURN(result);
}

static int mdt_link_unpack(struct mdt_thread_info *info)
{
#ifdef MDT_CODE
        struct mdt_rec_link *rec;
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule *pill = &info->mti_pill;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_LINK);
        if (rec == NULL)
                RETURN (-EFAULT);

        attr->la_uid = rec->lk_fsuid;
        attr->la_gid = rec->lk_fsgid;
        rr->rr_fid1 = &rec->lk_fid1;
        rr->rr_fid2 = &rec->lk_fid2;
        attr->la_ctime = rec->lk_time;

        rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
        if (rr->rr_name == NULL)
                RETURN (-EFAULT);
        RETURN(0);
#endif
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_unlink_unpack(struct mdt_thread_info *info)
{
#ifdef MDT_CODE
        struct mdt_rec_unlink *rec;
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule *pill = &info->mti_pill;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_UNLINK);
        if (rec == NULL)
                RETURN (-EFAULT);

        attr->la_uid = rec->ul_fsuid;
        attr->la_gid = rec->ul_fsgid;
        rr->rr_fid1 = &rec->ul_fid1;
        rr->rr_fid2 = &rec->ul_fid2;
        attr->la_ctime = rec->ul_time;
        attr->la_mode  = rec->ul_mode;

        rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
        if (rr->rr_name == NULL)
                RETURN (-EFAULT);
        RETURN(0);
#endif
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_rename_unpack(struct mdt_thread_info *info)
{
#ifdef MDT_CODE
        struct mdt_rec_rename *rec;
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule *pill = &info->mti_pill;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_RENAME);
        if (rec == NULL)
                RETURN (-EFAULT);

        attr->la_uid = rec->rn_fsuid;
        attr->la_gid = rec->rn_fsgid;
        rr->rr_fid1 = &rec->rn_fid1;
        rr->rr_fid2 = &rec->rn_fid2;
        attr->la_ctime = rec->rn_time;

        rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
        if (rr->rr_name == NULL)
                RETURN (-EFAULT);
        rr->rr_tgt = req_capsule_client_get(pill, &RMF_SYMTGT);
        if (rr->rr_tgt == NULL)
                RETURN (-EFAULT);
        RETURN(0);
#endif
 
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_open_unpack(struct mdt_thread_info *info)
{
        struct mdt_rec_create   *rec;
        struct lu_attr          *attr = &info->mti_attr;
        struct req_capsule      *pill = &info->mti_pill;
        struct mdt_reint_record *rr   = &info->mti_rr;
        int result;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_CREATE);
        if (rec != NULL) {
                rr->rr_fid1   = &rec->cr_fid1;
                rr->rr_fid2   = &rec->cr_fid2;
                attr->la_mode = rec->cr_mode;
                attr->la_flags  = rec->cr_flags;

                rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (rr->rr_name == NULL)
                        result = -EFAULT;
                else
                        result = 0;
        } else
                result = -EFAULT;

        RETURN(result);
}

typedef int (*reint_unpacker)(struct mdt_thread_info *info);

static reint_unpacker mdt_reint_unpackers[REINT_MAX] = {
        [REINT_SETATTR]  = mdt_setattr_unpack,
        [REINT_CREATE]   = mdt_create_unpack,
        [REINT_LINK]     = mdt_link_unpack,
        [REINT_UNLINK]   = mdt_unlink_unpack,
        [REINT_RENAME]   = mdt_rename_unpack,
        [REINT_OPEN]     = mdt_open_unpack
};

int mdt_reint_unpack(struct mdt_thread_info *info, __u32 op)
{
        int rc;

        ENTRY;

        if (op < REINT_MAX && mdt_reint_unpackers[op] != NULL) {
                info->mti_rr.rr_opcode = op;
                rc = mdt_reint_unpackers[op](info);
        } else {
                CERROR("Unexpected opcode %d\n", op);
                rc = -EFAULT;
        }
        RETURN(rc);
}
