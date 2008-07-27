/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/fld/fld_internal.h
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 * Author: Tom WangDi <wangdi@clusterfs.com>
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
