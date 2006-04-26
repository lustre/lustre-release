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

#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/lustre_ver.h>
#include <linux/obd_support.h>
#include <linux/lprocfs_status.h>
#include <linux/jbd.h>

#include <linux/dt_object.h>
#include <linux/md_object.h>
#include <linux/lustre_mdc.h>
#include <linux/lustre_fid.h>
/* XXX doesn't exist yet #include <linux/lustre_iam.h> */
#include "fld_internal.h"

#if 1
int fld_handle_insert(struct fld_info *fld_info,
                      fidseq_t seq_num, mdsno_t mdsno)
{
        return 0;
}

int fld_handle_delete(struct fld_info *fld_info,
                      fidseq_t seq_num, mdsno_t mds_num)
{
        return 0;
}

int fld_handle_lookup(struct fld_info *fld_info,
                      fidseq_t seq_num, mdsno_t *mds_num)
{
        return 0;
}

int fld_info_init(struct fld_info *fld_info)
{
        return 0;
}

void fld_info_fini(struct fld_info *fld_info)
{
}

#else
struct iam_key;
struct iam_rec;

struct fld_info fld_info;

int fld_handle_insert(struct fld_info *fld_info, fidseq_t seq_num, mdsno_t mdsno)
{
        handle_t *handle = NULL;
        return iam_insert(handle, &fld_info->fi_container,
                          (struct iam_key *)&seq_num, (struct iam_rec *)&mdsno);
}

int fld_handle_delete(struct fld_info *fld_info, fidseq_t seq_num, mdsno_t mds_num)
{
        handle_t *handle = NULL;
        return iam_delete(handle, &fld_info->fi_container,
                          (struct iam_key *)&seq_num);
}

int fld_handle_lookup(struct fld_info *fld_info, fidseq_t seq_num, mdsno_t *mds_num)
{
        mdsno_t mdsno;
        int result;

        result = iam_lookup(&fld_info->fi_container, (struct iam_key *)&seq_num,
                            (struct iam_rec *)&mdsno);
        if (result == 0)
                return -ENOENT;
        else if (result > 0)
                return mdsno;
        else
                return result;
}

static u32 fld_root_ptr(struct iam_container *c)
{
        return 0;
}
static int fld_node_check(struct iam_path *path, struct iam_frame *frame)
{
        return 0;
}
static int fld_node_init(struct iam_container *c, struct buffer_head *bh,
                           int root)
{
        return 0;
}
static int fld_keycmp(struct iam_container *c,
                        struct iam_key *k1, struct iam_key *k2)
{
        return key_cmp(le64_to_cpu(*(__u64 *)k1), le64_to_cpu(*(__u64 *)k2));
}
static int fld_node_read(struct iam_container *c, iam_ptr_t ptr,
                           handle_t *h, struct buffer_head **bh)
{
        return 0;
}


static struct iam_descr fld_param = {
        .id_key_size = sizeof ((struct lu_fid *)0)->f_seq,
        .id_ptr_size = 4, /* 32 bit block numbers for now */
        .id_rec_size = sizeof(mdsno_t),
        .id_node_gap = 0, /* no gaps in index nodes */
        .id_root_gap = 0,

        .id_root_ptr   = fld_root_ptr, /* returns 0: root is always at the
                                        * beginning of the file (as it
                                        * htree) */
        .id_node_read  = fld_node_read,
        .id_node_check = fld_node_check,
        .id_node_init  = fld_node_init,
        .id_keycmp     = fld_keycmp
};

int fld_info_init(struct fld_info *fld_info)
{
        struct file *fld_file;

        fld_file = filp_open("/fld", O_RDWR, S_IRWXU);
        /* sanity and security checks... */
        return iam_container_init(&fld_info->fi_container, &fld_param,
                                  fld_file->f_dentry->d_inode);
}

void fld_info_fini(struct fld_info *fld_info)
{
        iam_container_fini(&fld_info->fi_container);
        OBD_FREE_PTR(fld_info);
}


#endif
