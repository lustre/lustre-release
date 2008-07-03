/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  fid/fid_internal.h
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
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
#ifndef __FID_INTERNAL_H
#define __FID_INTERNAL_H

#include <lustre/lustre_idl.h>
#include <dt_object.h>

#include <libcfs/libcfs.h>

#include <linux/types.h>

#ifdef __KERNEL__
struct seq_thread_info {
        struct req_capsule     *sti_pill;
        struct txn_param        sti_txn;
        struct lu_range         sti_space;
        struct lu_buf           sti_buf;
};

extern struct lu_context_key seq_thread_key;

/* Functions used internally in module. */
int seq_client_alloc_super(struct lu_client_seq *seq,
                           const struct lu_env *env);

int seq_client_replay_super(struct lu_client_seq *seq,
                            struct lu_range *range,
                            const struct lu_env *env);

/* Store API functions. */
int seq_store_init(struct lu_server_seq *seq,
                   const struct lu_env *env,
                   struct dt_device *dt);

void seq_store_fini(struct lu_server_seq *seq,
                    const struct lu_env *env);

int seq_store_write(struct lu_server_seq *seq,
                    const struct lu_env *env);

int seq_store_read(struct lu_server_seq *seq,
                   const struct lu_env *env);

#ifdef LPROCFS
extern struct lprocfs_vars seq_server_proc_list[];
extern struct lprocfs_vars seq_client_proc_list[];
#endif

#endif

extern cfs_proc_dir_entry_t *seq_type_proc_dir;

#endif /* __FID_INTERNAL_H */
