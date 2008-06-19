/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef __EXPORT_H
#define __EXPORT_H

#include <lustre/lustre_idl.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct mds_client_data;
struct mdt_client_data;
struct mds_idmap_table;
struct mdt_idmap_table;

struct mdt_export_data {
        struct list_head        med_open_head;
        spinlock_t              med_open_lock; /* lock med_open_head, mfd_list*/
        struct semaphore        med_lcd_lock;
        struct lsd_client_data *med_lcd;
        __u64                   med_ibits_known;
        loff_t                  med_lr_off;
        int                     med_lr_idx;
        unsigned int            med_rmtclient:1; /* remote client? */
        struct semaphore           med_idmap_sem;
        struct lustre_idmap_table *med_idmap;
};

struct osc_creator {
        spinlock_t              oscc_lock;
        struct list_head        oscc_list;
        struct obd_device       *oscc_obd;
        obd_id                  oscc_last_id;//last available pre-created object
        obd_id                  oscc_next_id;// what object id to give out next
        int                     oscc_grow_count;
        struct obdo             oscc_oa;
        int                     oscc_flags;
        cfs_waitq_t             oscc_waitq; /* creating procs wait on this */
};

struct ldlm_export_data {
        struct list_head       led_held_locks; /* protected by led_lock */
        spinlock_t             led_lock;
};

struct ec_export_data { /* echo client */
        struct list_head eced_locks;
};

/* In-memory access to client data from OST struct */
struct filter_export_data {
        spinlock_t                 fed_lock;      /* protects fed_open_head */
        struct lsd_client_data    *fed_lcd;
        loff_t                     fed_lr_off;
        int                        fed_lr_idx;
        long                       fed_dirty;    /* in bytes */
        long                       fed_grant;    /* in bytes */
        struct list_head           fed_mod_list; /* files being modified */
        int                        fed_mod_count;/* items in fed_writing list */
        long                       fed_pending;  /* bytes just being written */
        __u32                      fed_group;
        struct brw_stats           fed_brw_stats;
};

typedef struct nid_stat {
        lnet_nid_t               nid;
        struct hlist_node        nid_hash;
        struct list_head         nid_list;
        struct obd_device       *nid_obd;
        struct proc_dir_entry   *nid_proc;
        struct lprocfs_stats    *nid_stats;
        struct brw_stats        *nid_brw_stats;
        int                      nid_exp_ref_count;
}nid_stat_t;

struct obd_export {
        struct portals_handle     exp_handle;
        atomic_t                  exp_refcount;
        atomic_t                  exp_rpc_count;
        struct obd_uuid           exp_client_uuid;
        struct list_head          exp_obd_chain;
        struct hlist_node         exp_uuid_hash; /* uuid-export hash*/
        struct hlist_node         exp_nid_hash; /* nid-export hash */
        /* exp_obd_chain_timed fo ping evictor, protected by obd_dev_lock */
        struct list_head          exp_obd_chain_timed;
        struct obd_device        *exp_obd;
        struct obd_import        *exp_imp_reverse; /* to make RPCs backwards */
        struct nid_stat          *exp_nid_stats;
        struct lprocfs_stats     *exp_md_stats;
        struct lprocfs_stats     *exp_ldlm_stats;
        struct ptlrpc_connection *exp_connection;
        __u32                     exp_conn_cnt;
        struct ldlm_export_data   exp_ldlm_data;
        struct list_head          exp_outstanding_replies;
        time_t                    exp_last_request_time;
        spinlock_t                exp_lock; /* protects flags int below */
        /* ^ protects exp_outstanding_replies too */
        __u64                     exp_connect_flags;
        int                       exp_flags;
        unsigned long             exp_failed:1,
                                  exp_in_recovery:1,
                                  exp_disconnected:1,
                                  exp_connecting:1,
                                  exp_req_replay_needed:1,
                                  exp_lock_replay_needed:1,
                                  exp_need_sync:1,
                                  exp_flvr_changed:1,
                                  exp_flvr_adapt:1,
                                  exp_libclient:1; /* liblustre client? */
        /* also protected by exp_lock */
        enum lustre_sec_part      exp_sp_peer;
        struct sptlrpc_flavor     exp_flvr;             /* current */
        struct sptlrpc_flavor     exp_flvr_old[2];      /* about-to-expire */
        cfs_time_t                exp_flvr_expire[2];   /* seconds */

        union {
                struct mdt_export_data    eu_mdt_data;
                struct filter_export_data eu_filter_data;
                struct ec_export_data     eu_ec_data;
        } u;
};

#define exp_mdt_data    u.eu_mdt_data
#define exp_filter_data u.eu_filter_data
#define exp_ec_data     u.eu_ec_data

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
