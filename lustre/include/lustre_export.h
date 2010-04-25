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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
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

#ifndef __EXPORT_H
#define __EXPORT_H

/** \defgroup export export
 *
 * @{
 */

#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>
#include <lustre_dlm.h>

struct mds_client_data;
struct mdt_client_data;
struct mds_idmap_table;
struct mdt_idmap_table;

struct tg_export_data {
        /** Protects led_lcd below */
        cfs_semaphore_t         ted_lcd_lock;
        /** Per-client data for each export */
        struct lsd_client_data *ted_lcd;
        /** Offset of record in last_rcvd file */
        loff_t                  ted_lr_off;
        /** Client index in last_rcvd file */
        int                     ted_lr_idx;
};

struct mdt_export_data {
        struct tg_export_data   med_ted;
        cfs_list_t              med_open_head;
        cfs_spinlock_t          med_open_lock; /* lock med_open_head, mfd_list*/
        __u64                   med_ibits_known;
        cfs_semaphore_t         med_idmap_sem;
        struct lustre_idmap_table *med_idmap;
};

struct osc_creator {
        cfs_spinlock_t          oscc_lock;
        cfs_list_t              oscc_wait_create_list;
        struct obd_device      *oscc_obd;
        obd_id                  oscc_last_id;//last available pre-created object
        obd_id                  oscc_next_id;// what object id to give out next
        int                     oscc_grow_count;
        /**
         * Limit oscc_grow_count value, can be changed via proc fs
         */
        int                     oscc_max_grow_count;
        struct obdo             oscc_oa;
        int                     oscc_flags;
        cfs_waitq_t             oscc_waitq; /* creating procs wait on this */
};

struct ec_export_data { /* echo client */
        cfs_list_t eced_locks;
};

/* In-memory access to client data from OST struct */
struct filter_export_data {
        struct tg_export_data      fed_ted;
        cfs_spinlock_t             fed_lock;     /**< protects fed_mod_list */
        long                       fed_dirty;    /* in bytes */
        long                       fed_grant;    /* in bytes */
        cfs_list_t                 fed_mod_list; /* files being modified */
        int                        fed_mod_count;/* items in fed_writing list */
        long                       fed_pending;  /* bytes just being written */
        __u32                      fed_group;
};

typedef struct nid_stat {
        lnet_nid_t               nid;
        cfs_hlist_node_t         nid_hash;
        cfs_list_t               nid_list;
        struct obd_device       *nid_obd;
        struct proc_dir_entry   *nid_proc;
        struct lprocfs_stats    *nid_stats;
        struct lprocfs_stats    *nid_ldlm_stats;
        struct brw_stats        *nid_brw_stats;
        cfs_atomic_t             nid_exp_ref_count; /* for obd_nid_stats_hash
                                                           exp_nid_stats */
}nid_stat_t;

#define nidstat_getref(nidstat)                                                \
do {                                                                           \
        cfs_atomic_inc(&(nidstat)->nid_exp_ref_count);                         \
} while(0)

#define nidstat_putref(nidstat)                                                \
do {                                                                           \
        cfs_atomic_dec(&(nidstat)->nid_exp_ref_count);                         \
        LASSERTF(cfs_atomic_read(&(nidstat)->nid_exp_ref_count) >= 0,          \
                 "stat %p nid_exp_ref_count < 0\n", nidstat);                  \
} while(0)

enum obd_option {
        OBD_OPT_FORCE =         0x0001,
        OBD_OPT_FAILOVER =      0x0002,
        OBD_OPT_ABORT_RECOV =   0x0004,
};

struct obd_export {
        struct portals_handle     exp_handle;
        cfs_atomic_t              exp_refcount;
        /**
         * Set of counters below is to track where export references are
         * kept. The exp_rpc_count is used for reconnect handling also,
         * the cb_count and locks_count are for debug purposes only for now.
         * The sum of them should be less than exp_refcount by 3
         */
        cfs_atomic_t              exp_rpc_count; /* RPC references */
        cfs_atomic_t              exp_cb_count; /* Commit callback references */
        cfs_atomic_t              exp_locks_count; /** Lock references */
#if LUSTRE_TRACKS_LOCK_EXP_REFS
        cfs_list_t                exp_locks_list;
        cfs_spinlock_t            exp_locks_list_guard;
#endif
        cfs_atomic_t              exp_replay_count;
        struct obd_uuid           exp_client_uuid;
        cfs_list_t                exp_obd_chain;
        cfs_hlist_node_t          exp_uuid_hash; /* uuid-export hash*/
        cfs_hlist_node_t          exp_nid_hash; /* nid-export hash */
        /* exp_obd_chain_timed fo ping evictor, protected by obd_dev_lock */
        cfs_list_t                exp_obd_chain_timed;
        struct obd_device        *exp_obd;
        struct obd_import        *exp_imp_reverse; /* to make RPCs backwards */
        struct nid_stat          *exp_nid_stats;
        struct lprocfs_stats     *exp_md_stats;
        struct ptlrpc_connection *exp_connection;
        __u32                     exp_conn_cnt;
        cfs_hash_t               *exp_lock_hash; /* existing lock hash */
        cfs_spinlock_t            exp_lock_hash_lock;
        cfs_list_t                exp_outstanding_replies;
        cfs_list_t                exp_uncommitted_replies;
        cfs_spinlock_t            exp_uncommitted_replies_lock;
        __u64                     exp_last_committed;
        cfs_time_t                exp_last_request_time;
        cfs_list_t                exp_req_replay_queue;
        cfs_spinlock_t            exp_lock; /* protects flags int below */
        /* ^ protects exp_outstanding_replies too */
        __u64                     exp_connect_flags;
        enum obd_option           exp_flags;
        unsigned long             exp_failed:1,
                                  exp_in_recovery:1,
                                  exp_disconnected:1,
                                  exp_connecting:1,
                                  /** VBR: export missed recovery */
                                  exp_delayed:1,
                                  /** VBR: failed version checking */
                                  exp_vbr_failed:1,
                                  exp_req_replay_needed:1,
                                  exp_lock_replay_needed:1,
                                  exp_need_sync:1,
                                  exp_flvr_changed:1,
                                  exp_flvr_adapt:1,
                                  exp_libclient:1, /* liblustre client? */
                                  /* client timed out and tried to reconnect,
                                   * but couldn't because of active rpcs */
                                  exp_abort_active_req:1;
        cfs_list_t                exp_queued_rpc;  /* RPC to be handled */
        /* also protected by exp_lock */
        enum lustre_sec_part      exp_sp_peer;
        struct sptlrpc_flavor     exp_flvr;             /* current */
        struct sptlrpc_flavor     exp_flvr_old[2];      /* about-to-expire */
        cfs_time_t                exp_flvr_expire[2];   /* seconds */

        union {
                struct tg_export_data     eu_target_data;
                struct mdt_export_data    eu_mdt_data;
                struct filter_export_data eu_filter_data;
                struct ec_export_data     eu_ec_data;
        } u;
};

#define exp_target_data u.eu_target_data
#define exp_mdt_data    u.eu_mdt_data
#define exp_filter_data u.eu_filter_data
#define exp_ec_data     u.eu_ec_data

static inline int exp_expired(struct obd_export *exp, cfs_duration_t age)
{
        LASSERT(exp->exp_delayed);
        return cfs_time_before(cfs_time_add(exp->exp_last_request_time, age),
                               cfs_time_current_sec());
}

static inline int exp_connect_cancelset(struct obd_export *exp)
{
        LASSERT(exp != NULL);
        return !!(exp->exp_connect_flags & OBD_CONNECT_CANCELSET);
}

static inline int exp_connect_lru_resize(struct obd_export *exp)
{
        LASSERT(exp != NULL);
        return !!(exp->exp_connect_flags & OBD_CONNECT_LRU_RESIZE);
}

static inline int exp_connect_rmtclient(struct obd_export *exp)
{
        LASSERT(exp != NULL);
        return !!(exp->exp_connect_flags & OBD_CONNECT_RMT_CLIENT);
}

static inline int client_is_remote(struct obd_export *exp)
{
        struct obd_import *imp = class_exp2cliimp(exp);

        return !!(imp->imp_connect_data.ocd_connect_flags &
                  OBD_CONNECT_RMT_CLIENT);
}

static inline int exp_connect_vbr(struct obd_export *exp)
{
        LASSERT(exp != NULL);
        LASSERT(exp->exp_connection);
        return !!(exp->exp_connect_flags & OBD_CONNECT_VBR);
}

static inline int exp_connect_som(struct obd_export *exp)
{
        LASSERT(exp != NULL);
        return !!(exp->exp_connect_flags & OBD_CONNECT_SOM);
}

static inline int imp_connect_lru_resize(struct obd_import *imp)
{
        struct obd_connect_data *ocd;

        LASSERT(imp != NULL);
        ocd = &imp->imp_connect_data;
        return !!(ocd->ocd_connect_flags & OBD_CONNECT_LRU_RESIZE);
}

extern struct obd_export *class_conn2export(struct lustre_handle *conn);
extern struct obd_device *class_conn2obd(struct lustre_handle *conn);

/** @} export */

#endif /* __EXPORT_H */
