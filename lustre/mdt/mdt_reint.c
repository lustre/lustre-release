/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdt/mdt_reint.c
 *  Lustre Metadata Server (mds) reintegration routines
 *
 *  Copyright (C) 2002-2005 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <linux/lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <linux/obd_support.h>
/* struct ptlrpc_request */
#include <linux/lustre_net.h>
/* struct obd_export */
#include <linux/lustre_export.h>
/* struct obd_device */
#include <linux/obd.h>
/* lu2dt_dev() */
#include <linux/dt_object.h>


#include "../mds/mds_internal.h"
#include "mdt_internal.h"


/* object operations */
static int mdt_md_mkdir(struct mdt_thread_info *info,
                        struct mdt_reint_record *rec)
{
        struct mdt_device      *mdt= info->mti_mdt;
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;

        int result;

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_PW;

        parent = mdt_object_find_lock(info->mti_ctxt,
                                 mdt, rec->ur_fid1, lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                return PTR_ERR(parent);

        child = mdt_object_find(info->mti_ctxt, mdt, rec->ur_fid2);
        if (!IS_ERR(child)) {
                struct md_object *next = mdt_object_child(parent);

                result = next->mo_ops->moo_mkdir(info->mti_ctxt, next, rec->ur_name,
                                                 mdt_object_child(child));
                mdt_object_put(info->mti_ctxt, child);
        } else
                result = PTR_ERR(child);
        mdt_object_unlock(mdt->mdt_namespace, parent, lh);
        mdt_object_put(info->mti_ctxt, parent);
        return result;
}


static int mdt_reint_setattr(struct mdt_thread_info *info,
                             struct mdt_reint_record *rec, int offset,
                             struct ptlrpc_request *req,
                             struct lustre_handle *lh)
{
        ENTRY;
        RETURN (-EOPNOTSUPP);
}


static int mdt_reint_create(struct mdt_thread_info *info,
                            struct mdt_reint_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lh)
{
        int rc = 0, type = rec->ur_mode & S_IFMT;
        
        ENTRY;

        switch (type) {
        case S_IFREG:{
                RETURN (rc = -EOPNOTSUPP);
                break;
        }
        case S_IFDIR:{
                rc = mdt_md_mkdir(info, rec);
                break;
        }
        case S_IFLNK:{
                RETURN (rc = -EOPNOTSUPP);
                break;
        }
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:{
                RETURN (rc = -EOPNOTSUPP);
                break;
        }
        default:
                CERROR("bad file type %o creating %s\n", type, rec->ur_name);
        }
        RETURN (rc);
}


static int mdt_reint_unlink(struct mdt_thread_info *info,
                            struct mdt_reint_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lh)
{
        ENTRY;
        RETURN (-EOPNOTSUPP);
}

static int mdt_reint_link(struct mdt_thread_info *info,
                          struct mdt_reint_record *rec, int offset,
                          struct ptlrpc_request *req,
                          struct lustre_handle *lh)
{
        ENTRY;
        RETURN (-EOPNOTSUPP);
}


static int mdt_reint_rename(struct mdt_thread_info *info,
                            struct mdt_reint_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lockh)
{
        ENTRY;
        RETURN (-EOPNOTSUPP);
}

static int mdt_reint_open(struct mdt_thread_info *info,
                            struct mdt_reint_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lockh)
{
        ENTRY;
        RETURN (-EOPNOTSUPP);
}


typedef int (*mdt_reinter)(struct mdt_thread_info *info,
                           struct mdt_reint_record *, int offset,
                           struct ptlrpc_request *, struct lustre_handle *);

static mdt_reinter reinters[REINT_MAX] = {
        [REINT_SETATTR] mdt_reint_setattr,
        [REINT_CREATE] mdt_reint_create,
        [REINT_LINK] mdt_reint_link,
        [REINT_UNLINK] mdt_reint_unlink,
        [REINT_RENAME] mdt_reint_rename,
        [REINT_OPEN] mdt_reint_open
};

int mdt_reint_rec(struct mdt_thread_info *info, struct mdt_reint_record *rec, 
                  int offset, struct ptlrpc_request *req, 
                  struct lustre_handle *lockh)
{
        int rc;
        ENTRY;
        /* checked by unpacker */
        LASSERT(rec->ur_opcode < REINT_MAX && reinters[rec->ur_opcode] != NULL);

        rc = reinters[rec->ur_opcode] (info, rec, offset, req, lockh);

        RETURN(rc);
}
