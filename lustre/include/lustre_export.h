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

#include <lustre/lustre_idl.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>
#include <class_hash.h>

struct lu_export_data {
        struct semaphore        led_lcd_lock; /**< protect led_lcd */
        struct lsd_client_data *led_lcd;      /**< client data */
        loff_t                  led_lr_off;   /**< offset in last_rcvd */
        int                     led_lr_idx;   /**< client index */
};

struct mds_export_data {
        struct lu_export_data   med_led;
        struct list_head        med_open_head;
        spinlock_t              med_open_lock; /* lock med_open_head, mfd_list*/
        __u64                   med_ibits_known;
};

#define med_lcd_lock    med_led.led_lcd_lock
#define med_lcd         med_led.led_lcd
#define med_lr_off      med_led.led_lr_off
#define med_lr_idx      med_led.led_lr_idx

struct osc_creator {
        spinlock_t              oscc_lock;
        struct list_head        oscc_list;
        struct obd_device       *oscc_obd;
        obd_id                  oscc_last_id;//last available pre-created object
        obd_id                  oscc_next_id;// what object id to give out next
        int                     oscc_grow_count;
        int                     oscc_max_grow_count;
        struct obdo             oscc_oa;
        int                     oscc_flags;
        cfs_waitq_t             oscc_waitq; /* creating procs wait on this */
};

struct ec_export_data { /* echo client */
        struct list_head eced_locks;
};

/* In-memory access to client data from OST struct */
struct filter_export_data {
        struct lu_export_data      fed_led;
        spinlock_t                 fed_lock;      /**< protects fed_mod_list */
        long                       fed_dirty;    /* in bytes */
        long                       fed_grant;    /* in bytes */
        struct list_head           fed_mod_list; /* files being modified */
        int                        fed_mod_count;/* items in fed_writing list */
        long                       fed_pending;  /* bytes just being written */
        struct brw_stats           fed_brw_stats;
};

#define fed_lcd_lock    fed_led.led_lcd_lock
#define fed_lcd         fed_led.led_lcd
#define fed_lr_off      fed_led.led_lr_off
#define fed_lr_idx      fed_led.led_lr_idx

typedef struct nid_stat_uuid {
        struct list_head ns_uuid_list;
        struct obd_uuid  ns_uuid;
} nid_stat_uuid_t;

typedef struct nid_stat {
        lnet_nid_t               nid;
        struct hlist_node        nid_hash;
        struct list_head         nid_list;
        struct list_head         nid_uuid_list;
        struct obd_device       *nid_obd;
        struct proc_dir_entry   *nid_proc;
        struct lprocfs_stats    *nid_stats;
        struct brw_stats        *nid_brw_stats;
        struct lprocfs_stats    *nid_ldlm_stats;
        int                      nid_exp_ref_count;
} nid_stat_t;

struct obd_export {
        struct portals_handle     exp_handle;
        atomic_t                  exp_refcount;
        atomic_t                  exp_rpc_count;
        struct obd_uuid           exp_client_uuid;
        lnet_nid_t                exp_client_nid;
        struct list_head          exp_obd_chain;
        struct hlist_node         exp_uuid_hash; /* uuid-export hash*/
        struct hlist_node         exp_nid_hash; /* nid-export hash */
        /* exp_obd_chain_timed fo ping evictor, protected by obd_dev_lock */
        struct list_head          exp_obd_chain_timed;
        struct obd_device        *exp_obd;
        struct obd_import        *exp_imp_reverse; /* to make RPCs backwards */
        struct nid_stat          *exp_nid_stats;
        struct lprocfs_stats     *exp_ops_stats;
        struct ptlrpc_connection *exp_connection;
        __u32                     exp_conn_cnt;
        lustre_hash_t            *exp_lock_hash; /* existing lock hash */
        spinlock_t                exp_lock_hash_lock;
        struct list_head          exp_outstanding_replies;
        struct list_head          exp_uncommitted_replies;
        spinlock_t                exp_uncommitted_replies_lock;
        time_t                    exp_last_request_time;
        struct list_head          exp_req_replay_queue;
        spinlock_t                exp_lock; /* protects flags int below */
        /* ^ protects exp_outstanding_replies too */
        __u64                     exp_connect_flags;
        int                       exp_flags;
        unsigned long             exp_failed:1,
                                  exp_in_recovery:1,
                                  exp_disconnected:1,
                                  exp_connecting:1,
                                  /* VBR: export missed recovery */
                                  exp_delayed:1,
                                  /* VBR: failed version checking */
                                  exp_vbr_failed:1,
                                  exp_replay_needed:1,
                                  exp_need_sync:1, /* needs sync from connect */
                                  exp_libclient:1; /* liblustre client? */
        /* VBR: per-export last committed */
        __u64                     exp_last_committed;
        union {
                struct lu_export_data     eu_target_data;
                struct mds_export_data    eu_mds_data;
                struct filter_export_data eu_filter_data;
                struct ec_export_data     eu_ec_data;
        } u;
};

#define exp_target_data u.eu_target_data
#define exp_mds_data    u.eu_mds_data
#define exp_filter_data u.eu_filter_data
#define exp_ec_data     u.eu_ec_data

static inline int exp_expired(struct obd_export *exp, __u32 age)
{
        LASSERT(exp->exp_delayed);
        return cfs_time_before(exp->exp_last_request_time + age,
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

static inline int exp_connect_vbr(struct obd_export *exp)
{
        LASSERT(exp != NULL);
        LASSERT(exp->exp_connection);
        return !!(exp->exp_connect_flags & OBD_CONNECT_VBR);
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

#endif /* __EXPORT_H */
