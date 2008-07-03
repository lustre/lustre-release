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
#ifndef __FLD_INTERNAL_H
#define __FLD_INTERNAL_H

#include <lustre/lustre_idl.h>
#include <dt_object.h>

#include <libcfs/libcfs.h>

#include <linux/types.h>
#include <lustre_req_layout.h>
#include <lustre_fld.h>

enum fld_op {
        FLD_CREATE = 0,
        FLD_DELETE = 1,
        FLD_LOOKUP = 2
};

enum {
        /* 4M of FLD cache will not hurt client a lot. */
        FLD_SERVER_CACHE_SIZE      = (4 * 0x100000),

        /* 1M of FLD cache will not hurt client a lot. */
        FLD_CLIENT_CACHE_SIZE      = (1 * 0x100000)
};

enum {
        /* Cache threshold is 10 percent of size. */
        FLD_SERVER_CACHE_THRESHOLD = 10,

        /* Cache threshold is 10 percent of size. */
        FLD_CLIENT_CACHE_THRESHOLD = 10
};

enum {
        /*
         * One page is used for hashtable. That is sizeof(struct hlist_head) *
         * 1024.
         */
        FLD_CLIENT_HTABLE_SIZE     = (1024 * 1),

        /* 
         * Here 4 pages are used for hashtable of server cache. This is is
         * because cache it self is 4 times bugger.
         */
        FLD_SERVER_HTABLE_SIZE     = (1024 * 4)
};

extern struct lu_fld_hash fld_hash[];

#ifdef __KERNEL__
struct fld_thread_info {
        struct req_capsule *fti_pill;
        __u64               fti_key;
        __u64               fti_rec;
        __u32               fti_flags;
};

int fld_index_init(struct lu_server_fld *fld,
                   const struct lu_env *env,
                   struct dt_device *dt);

void fld_index_fini(struct lu_server_fld *fld,
                    const struct lu_env *env);

int fld_index_create(struct lu_server_fld *fld,
                     const struct lu_env *env,
                     seqno_t seq, mdsno_t mds);

int fld_index_delete(struct lu_server_fld *fld,
                     const struct lu_env *env,
                     seqno_t seq);

int fld_index_lookup(struct lu_server_fld *fld,
                     const struct lu_env *env,
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

        return (const char *)tar->ft_exp->exp_obd->obd_name;
}

extern cfs_proc_dir_entry_t *fld_type_proc_dir;

#endif /* __FLD_INTERNAL_H */
