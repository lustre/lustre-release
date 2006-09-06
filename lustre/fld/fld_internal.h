/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  fld/fld_internal.h
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
 *           Tom WangDi <wangdi@clusterfs.com>
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
#ifndef _FLD_INTERNAL_H
#define _FLD_INTERNAL_H

#include <lustre/lustre_idl.h>
#include <dt_object.h>

#include <libcfs/list.h>
#include <libcfs/kp30.h>

#include <linux/types.h>
#include <lustre_req_layout.h>
#include <lustre_fld.h>

enum fld_op {
        FLD_CREATE = 0,
        FLD_DELETE = 1,
        FLD_LOOKUP = 2
};

enum {
        FLD_HTABLE_SIZE = 256
};

extern struct lu_fld_hash fld_hash[];

#ifdef __KERNEL__
#define FLD_SERVICE_WATCHDOG_TIMEOUT (obd_timeout * 1000)
struct fld_thread_info {
        struct req_capsule fti_pill;
        int                fti_rep_buf_size[4];
        __u64              fti_key;
        __u64              fti_rec;
};

int fld_index_init(struct lu_server_fld *fld,
                   const struct lu_context *ctx,
                   struct dt_device *dt);

void fld_index_fini(struct lu_server_fld *fld,
                    const struct lu_context *ctx);

int fld_index_create(struct lu_server_fld *fld,
                     const struct lu_context *ctx,
                     seqno_t seq, mdsno_t mds);

int fld_index_delete(struct lu_server_fld *fld,
                     const struct lu_context *ctx,
                     seqno_t seq);

int fld_index_lookup(struct lu_server_fld *fld,
                     const struct lu_context *ctx,
                     seqno_t seq, mdsno_t *mds);

#ifdef LPROCFS
extern struct lprocfs_vars fld_server_proc_list[];
extern struct lprocfs_vars fld_client_proc_list[];
#endif

#endif

static inline const char *
fld_target_name(struct lu_fld_target *tar)
{
        if (tar->ft_srv != NULL)
                return tar->ft_srv->lsf_name;

        return tar->ft_exp->exp_client_uuid.uuid;
}

#endif
