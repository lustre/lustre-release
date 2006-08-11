/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  fid/fid_internal.h
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
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
#ifndef _FID_INTERNAL_H
#define _FID_INTERNAL_H

#include <lustre/lustre_idl.h>
#include <dt_object.h>

#include <libcfs/list.h>
#include <libcfs/kp30.h>

#include <linux/types.h>

#define SEQ_SERVICE_WATCHDOG_TIMEOUT (obd_timeout * 1000)

#ifdef __KERNEL__
struct seq_store_record {
        struct lu_range ssr_space;
        struct lu_range ssr_super;
};

struct seq_thread_info {
        struct txn_param        sti_txn;
        struct req_capsule      sti_pill;
        struct seq_store_record sti_record;
        int                     sti_rep_buf_size[2];
};

extern struct lu_context_key seq_thread_key;

int seq_store_init(struct lu_server_seq *seq,
                   const struct lu_context *ctx,
                   struct dt_device *dt);

void seq_store_fini(struct lu_server_seq *seq,
                    const struct lu_context *ctx);

int seq_store_write(struct lu_server_seq *seq,
                    const struct lu_context *ctx);

int seq_store_read(struct lu_server_seq *seq,
                   const struct lu_context *ctx);

#ifdef LPROCFS
extern struct lprocfs_vars seq_server_proc_list[];
extern struct lprocfs_vars seq_client_proc_list[];
#endif

#endif

#endif
