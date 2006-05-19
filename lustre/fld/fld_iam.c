/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  fld/fld.c
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: WangDi <wangdi@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/jbd.h>

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <dt_object.h>
#include <md_object.h>
#include <lustre_mdc.h>
#include <lustre_fid.h>
#include <linux/lustre_iam.h>
#include "fld_internal.h"

struct iam_descr fld_param = {
        .id_key_size = sizeof ((struct lu_fid *)0)->f_seq,
        .id_ptr_size = 4, /* 32 bit block numbers for now */
        .id_rec_size = sizeof(mdsno_t),
        .id_node_gap = 0, /* no gaps in index nodes */
        .id_root_gap = 0,

#if 0
        .id_root_ptr   = iam_root_ptr, /* returns 0: root is always at the
                                        * beginning of the file (as it
                                        * htree) */
        .id_node_read  = iam_node_read,
        .id_node_check = iam_node_check,
        .id_node_init  = iam_node_init,
        .id_keycmp     = iam_keycmp,
#endif
};

int fld_handle_insert(struct lu_context *ctx, struct fld *fld,
                      fidseq_t seq_num, mdsno_t mdsno)
{
        /*
         * XXX Use ->dio_index_insert() from struct dt_index_operations. The
         * same below.
         */
#if 0
        return fld->fld_dt->dd_ops->dt_iam_insert(&lctx, fld->fld_dt,
                                                  fld->fld_info->fi_container,
                                                  &seq_num, fld_param.id_key_size,
                                                  &mdsno, fld_param.id_rec_size);
#else
        return 0;
#endif
}

int fld_handle_delete(struct lu_context *ctx, struct fld *fld,
                      fidseq_t seq_num, mdsno_t mds_num)
{
#if 0
        return fld->fld_dt->dd_ops->dt_iam_delete(&lctx, fld->fld_dt,
                                                  fld->fld_info->fi_container,
                                                  &seq_num, fld_param.id_key_size,
                                                  &mds_num, fld_param.id_rec_size);
#else
        return 0;
#endif
}

int fld_handle_lookup(struct lu_context *ctx,
                      struct fld *fld, fidseq_t seq_num, mdsno_t *mds_num)
{
#if 0
        int size;

        size = fld_param.id_rec_size;
        return fld->fld_dt->dd_ops->dt_iam_lookup(&lctx, fld->fld_dt,
                                                  fld->fld_info->fi_container,
                                                  &seq_num, fld_param.id_key_size,
                                                  mds_num, &size);
#else
        return 0;
#endif
}

int fld_info_init(struct fld_info *fld_info)
{
        struct file *fld_file;
        int rc;
        ENTRY;

        fld_file = filp_open("/dev/null", O_RDWR, S_IRWXU);
        /* sanity and security checks... */
        OBD_ALLOC(fld_info->fi_container, sizeof(struct iam_container));
        if (!fld_info->fi_container)
                RETURN(-ENOMEM);

        rc = iam_container_init(fld_info->fi_container, &fld_param,
                                fld_file->f_dentry->d_inode);
        RETURN(rc);
}

void fld_info_fini(struct fld_info *fld_info)
{
        iam_container_fini(fld_info->fi_container);
        OBD_FREE(fld_info->fi_container, sizeof(struct iam_container));
        OBD_FREE_PTR(fld_info);
}
