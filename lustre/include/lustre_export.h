/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef __EXPORT_H
#define __EXPORT_H

#include <lustre/lustre_idl.h>
#include <lustre_dlm.h>

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct mds_client_data;
struct mdt_client_data;

struct mds_export_data {
        struct list_head        med_open_head;
        spinlock_t              med_open_lock; /* lock med_open_head, mfd_list*/
        struct mds_client_data *med_mcd;
        __u64                   med_ibits_known;
        loff_t                  med_lr_off;
        int                     med_lr_idx;
};

struct mdt_export_data {
        struct list_head        med_open_head;
        spinlock_t              med_open_lock; /* lock med_open_head, mfd_list*/
        struct semaphore        med_mcd_lock; 
        struct mdt_client_data *med_mcd;
        __u64                   med_ibits_known;
        loff_t                  med_lr_off;
        int                     med_lr_idx;
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
        struct list_head       led_held_locks; /* protected by namespace lock */
        spinlock_t             led_lock;
};

struct ec_export_data { /* echo client */
        struct list_head eced_locks;
};

/* In-memory access to client data from OST struct */
struct filter_client_data;
struct filter_export_data {
        spinlock_t                 fed_lock;      /* protects fed_open_head */
        struct filter_client_data *fed_fcd;
        loff_t                     fed_lr_off;
        int                        fed_lr_idx;
        long                       fed_dirty;    /* in bytes */
        long                       fed_grant;    /* in bytes */
        struct list_head           fed_mod_list; /* files being modified */
        int                        fed_mod_count;/* items in fed_writing list */
        long                       fed_pending;  /* bytes just being written */
};

struct obd_export {
        struct portals_handle     exp_handle;
        atomic_t                  exp_refcount;
        struct obd_uuid           exp_client_uuid;
        struct list_head          exp_obd_chain;
        /* exp_obd_chain_timed fo ping evictor, protected by obd_dev_lock */
        struct list_head          exp_obd_chain_timed;
        struct obd_device        *exp_obd;
        struct obd_import        *exp_imp_reverse; /* to make RPCs backwards */
        struct ptlrpc_connection *exp_connection;
        __u32                     exp_conn_cnt;
        struct ldlm_export_data   exp_ldlm_data;
        struct list_head          exp_outstanding_replies;
        time_t                    exp_last_request_time;
        spinlock_t                exp_lock; /* protects flags int below */
        /* ^ protects exp_outstanding_replies too */
        __u64                     exp_connect_flags;
        int                       exp_flags;
        unsigned int              exp_failed:1,
                                  exp_disconnected:1,
                                  exp_connecting:1,
                                  exp_replay_needed:1,
                                  exp_libclient:1; /* liblustre client? */
        union {
                struct mds_export_data    eu_mds_data;
                struct mdt_export_data    eu_mdt_data;
                struct filter_export_data eu_filter_data;
                struct ec_export_data     eu_ec_data;
        } u;
};

#define exp_mds_data    u.eu_mds_data
#define exp_mdt_data    u.eu_mdt_data
#define exp_lov_data    u.eu_lov_data
#define exp_filter_data u.eu_filter_data
#define exp_ec_data     u.eu_ec_data

extern struct obd_export *class_conn2export(struct lustre_handle *conn);
extern struct obd_device *class_conn2obd(struct lustre_handle *conn);

#endif /* __EXPORT_H */
