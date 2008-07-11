/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef __IMPORT_H
#define __IMPORT_H

#include <lustre_handles.h>
#include <lustre/lustre_idl.h>


/* Adaptive Timeout stuff */
#define D_ADAPTTO D_OTHER
#define AT_BINS 4                  /* "bin" means "N seconds of history" */
#define AT_FLG_NOHIST 0x1          /* use last reported value only */

struct adaptive_timeout {
        time_t       at_binstart;         /* bin start time */
        unsigned int at_hist[AT_BINS];    /* timeout history bins */
        unsigned int at_flags;
        unsigned int at_current;          /* current timeout value */
        unsigned int at_worst_ever;       /* worst-ever timeout value */
        time_t       at_worst_time;       /* worst-ever timeout timestamp */
        spinlock_t   at_lock;
};

enum lustre_imp_state {
        LUSTRE_IMP_CLOSED     = 1,
        LUSTRE_IMP_NEW        = 2,
        LUSTRE_IMP_DISCON     = 3,
        LUSTRE_IMP_CONNECTING = 4,
        LUSTRE_IMP_REPLAY     = 5,
        LUSTRE_IMP_REPLAY_LOCKS = 6,
        LUSTRE_IMP_REPLAY_WAIT  = 7,
        LUSTRE_IMP_RECOVER    = 8,
        LUSTRE_IMP_FULL       = 9,
        LUSTRE_IMP_EVICTED    = 10,
};

static inline char * ptlrpc_import_state_name(enum lustre_imp_state state)
{
        static char* import_state_names[] = {
                "<UNKNOWN>", "CLOSED",  "NEW", "DISCONN",
                "CONNECTING", "REPLAY", "REPLAY_LOCKS", "REPLAY_WAIT",
                "RECOVER", "FULL", "EVICTED",
        };

        LASSERT (state <= LUSTRE_IMP_EVICTED);
        return import_state_names[state];
}

enum obd_import_event {
        IMP_EVENT_DISCON     = 0x808001,
        IMP_EVENT_INACTIVE   = 0x808002,
        IMP_EVENT_INVALIDATE = 0x808003,
        IMP_EVENT_ACTIVE     = 0x808004,
        IMP_EVENT_OCD        = 0x808005,
};

struct obd_import_conn {
        struct list_head          oic_item;
        struct ptlrpc_connection *oic_conn;
        struct obd_uuid           oic_uuid;
        __u64                     oic_last_attempt; /* jiffies, 64-bit */
};

#define IMP_AT_MAX_PORTALS 8
struct imp_at {
        int                     iat_portal[IMP_AT_MAX_PORTALS];
        struct adaptive_timeout iat_net_latency;
        struct adaptive_timeout iat_service_estimate[IMP_AT_MAX_PORTALS];
};

struct obd_import {
        struct portals_handle     imp_handle;
        atomic_t                  imp_refcount;
        struct lustre_handle      imp_dlm_handle; /* client's ldlm export */
        struct ptlrpc_connection *imp_connection;
        struct ptlrpc_client     *imp_client;
        struct list_head          imp_pinger_chain;
        struct list_head          imp_zombie_chain; /* queue for destruction */

        /* Lists of requests that are retained for replay, waiting for a reply,
         * or waiting for recovery to complete, respectively.
         */
        struct list_head          imp_replay_list;
        struct list_head          imp_sending_list;
        struct list_head          imp_delayed_list;

        struct obd_device        *imp_obd;
        cfs_waitq_t               imp_recovery_waitq;

        atomic_t                  imp_inflight;
        atomic_t                  imp_replay_inflight;
        atomic_t                  imp_inval_count;
        enum lustre_imp_state     imp_state;
        int                       imp_generation;
        __u32                     imp_conn_cnt;
        int                       imp_last_generation_checked;
        __u64                     imp_last_replay_transno;
        __u64                     imp_peer_committed_transno;
        __u64                     imp_last_transno_checked;
        struct lustre_handle      imp_remote_handle;
        cfs_time_t                imp_next_ping;   /* jiffies */
        __u64                     imp_last_success_conn;   /* jiffies, 64-bit */

        /* all available obd_import_conn linked here */
        struct list_head          imp_conn_list;
        struct obd_import_conn   *imp_conn_current;

        /* Protects flags, level, generation, conn_cnt, *_list */
        spinlock_t                imp_lock;

        /* flags */
        unsigned long             imp_invalid:1,          /* evicted */
                                  imp_deactive:1,         /* administratively disabled */
                                  imp_replayable:1,       /* try to recover the import */
                                  imp_dlm_fake:1,         /* don't run recovery (timeout instead) */
                                  imp_server_timeout:1,   /* use 1/2 timeout on MDS' OSCs */
                                  imp_initial_recov:1,    /* retry the initial connection */  
                                  imp_initial_recov_bk:1, /* turn off init_recov after trying all failover nids */
                                  imp_force_verify:1,     /* force an immidiate ping */
                                  imp_pingable:1,         /* pingable */
                                  imp_resend_replay:1,    /* resend for replay */
                                  imp_recon_bk:1,         /* turn off reconnect if all failovers fail */
                                  imp_last_recon:1;       /* internally used by above */
        __u32                     imp_connect_op;
        struct obd_connect_data   imp_connect_data;
        __u64                     imp_connect_flags_orig;

        __u32                     imp_msg_magic;
        __u32                     imp_msghdr_flags;       /* adjusted based on server capability */

        struct ptlrpc_request_pool *imp_rq_pool;          /* emergency request pool */

        struct imp_at             imp_at;                 /* adaptive timeout data */
        time_t                    imp_last_reply_time;    /* for health check */
};

/* import.c */
static inline void at_init(struct adaptive_timeout *at, int val, int flags) {
        memset(at, 0, sizeof(*at));
        at->at_current = val;
        at->at_worst_ever = val;
        at->at_worst_time = cfs_time_current_sec();
        at->at_flags = flags;
        spin_lock_init(&at->at_lock);
}
static inline int at_get(struct adaptive_timeout *at) {
        return at->at_current;
}
int at_add(struct adaptive_timeout *at, unsigned int val);
int import_at_get_index(struct obd_import *imp, int portal);
extern unsigned int at_max;
#define AT_OFF (at_max == 0)

/* genops.c */
struct obd_export;
extern struct obd_import *class_exp2cliimp(struct obd_export *);
extern struct obd_import *class_conn2cliimp(struct lustre_handle *);

#endif /* __IMPORT_H */
