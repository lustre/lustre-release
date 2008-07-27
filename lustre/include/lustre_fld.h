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
 */

#ifndef __LINUX_FLD_H
#define __LINUX_FLD_H

#include <lustre/lustre_idl.h>
#include <lustre_mdt.h>
#include <dt_object.h>

#include <libcfs/libcfs.h>

struct lu_client_fld;
struct lu_server_fld;

struct fld_stats {
        __u64   fst_count;
        __u64   fst_cache;
        __u64   fst_inflight;
};

/*
 * FLD (Fid Location Database) interface.
 */
enum {
        LUSTRE_CLI_FLD_HASH_DHT = 0,
        LUSTRE_CLI_FLD_HASH_RRB
};

struct lu_server_fld;

struct lu_fld_target {
        struct list_head         ft_chain;
        struct obd_export       *ft_exp;
        struct lu_server_fld    *ft_srv;
        __u64                    ft_idx;
};

typedef int
(*fld_hash_func_t) (struct lu_client_fld *, __u64);

typedef struct lu_fld_target *
(*fld_scan_func_t) (struct lu_client_fld *, __u64);

struct lu_fld_hash {
        const char              *fh_name;
        fld_hash_func_t          fh_hash_func;
        fld_scan_func_t          fh_scan_func;
};

struct fld_cache_entry {
        struct hlist_node        fce_list;
        struct list_head         fce_lru;
        mdsno_t                  fce_mds;
        seqno_t                  fce_seq;
        cfs_waitq_t              fce_waitq;
        __u32                    fce_inflight:1,
                                 fce_invalid:1;
};

struct fld_cache {
        /*
         * Cache guard, protects fci_hash mostly because others immutable after
         * init is finished.
         */
        spinlock_t               fci_lock;

        /* Cache shrink threshold */
        int                      fci_threshold;

        /* Prefered number of cached entries */
        int                      fci_cache_size;

        /* Current number of cached entries. Protected by @fci_lock */
        int                      fci_cache_count;

        /* Hash table size (number of collision lists) */
        int                      fci_hash_size;

        /* Hash table mask */
        int                      fci_hash_mask;

        /* Hash table for all collision lists */
        struct hlist_head       *fci_hash_table;

        /* Lru list */
        struct list_head         fci_lru;

        /* Cache statistics. */
        struct fld_stats         fci_stat;
        
        /* Cache name used for debug and messages. */
        char                     fci_name[80];
};

struct lu_server_fld {
        /* Fld dir proc entry. */
        cfs_proc_dir_entry_t    *lsf_proc_dir;

        /* /fld file object device */
        struct dt_object        *lsf_obj;

        /* Client FLD cache. */
        struct fld_cache        *lsf_cache;

        /* Protect index modifications */
        struct semaphore         lsf_sem;

        /* Fld service name in form "fld-srv-lustre-MDTXXX" */
        char                     lsf_name[80];
};

enum {
        LUSTRE_FLD_INIT = 1 << 0,
        LUSTRE_FLD_RUN  = 1 << 1
};

struct lu_client_fld {
        /* Client side proc entry. */
        cfs_proc_dir_entry_t    *lcf_proc_dir;

        /* List of exports client FLD knows about. */
        struct list_head         lcf_targets;

        /* Current hash to be used to chose an export. */
        struct lu_fld_hash      *lcf_hash;

        /* Exports count. */
        int                      lcf_count;

        /* Lock protecting exports list and fld_hash. */
        spinlock_t               lcf_lock;

        /* Client FLD cache. */
        struct fld_cache        *lcf_cache;

        /* Client fld proc entry name. */
        char                     lcf_name[80];

        const struct lu_context *lcf_ctx;
        
        int                      lcf_flags;
};

int fld_query(struct com_thread_info *info);

/* Server methods */
int fld_server_init(struct lu_server_fld *fld,
                    struct dt_device *dt,
                    const char *prefix,
                    const struct lu_env *env);

void fld_server_fini(struct lu_server_fld *fld,
                     const struct lu_env *env);

int fld_server_create(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq, mdsno_t mds);

int fld_server_delete(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq);

int fld_server_lookup(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq, mdsno_t *mds);

/* Client methods */
int fld_client_init(struct lu_client_fld *fld,
                    const char *prefix, int hash);

void fld_client_fini(struct lu_client_fld *fld);

void fld_client_flush(struct lu_client_fld *fld);

int fld_client_lookup(struct lu_client_fld *fld,
                      seqno_t seq, mdsno_t *mds,
                      const struct lu_env *env);

int fld_client_create(struct lu_client_fld *fld,
                      seqno_t seq, mdsno_t mds,
                      const struct lu_env *env);

int fld_client_delete(struct lu_client_fld *fld,
                      seqno_t seq,
                      const struct lu_env *env);

int fld_client_add_target(struct lu_client_fld *fld,
                          struct lu_fld_target *tar);

int fld_client_del_target(struct lu_client_fld *fld,
                          __u64 idx);

/* Cache methods */
struct fld_cache *fld_cache_init(const char *name,
                                 int hash_size,
                                 int cache_size,
                                 int cache_threshold);

void fld_cache_fini(struct fld_cache *cache);

void fld_cache_flush(struct fld_cache *cache);

int fld_cache_insert(struct fld_cache *cache,
                     seqno_t seq, mdsno_t mds);

int fld_cache_insert_inflight(struct fld_cache *cache,
                              seqno_t seq);

void fld_cache_delete(struct fld_cache *cache,
                      seqno_t seq);

int
fld_cache_lookup(struct fld_cache *cache,
                 seqno_t seq, mdsno_t *mds);

#endif
