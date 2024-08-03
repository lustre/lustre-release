/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __IMPORT_H
#define __IMPORT_H

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <libcfs/libcfs.h>
#include <uapi/linux/lustre/lustre_idl.h>

/**
 * Adaptive Timeout stuff
 *
 * @{
 */
#define D_ADAPTTO D_OTHER
#define AT_BINS 4                  /* "bin" means "N seconds of history" */
#define AT_FLG_NOHIST 0x1          /* use last reported value only */

struct adaptive_timeout {
	time64_t	at_binstart;         /* bin start time */
	unsigned int	at_hist[AT_BINS];    /* timeout history bins */
	unsigned int	at_flags;
	timeout_t	at_current_timeout;	/* current timeout value */
	timeout_t	at_worst_timeout_ever;	/* worst-ever timeout delta
						 * value
						 */
	time64_t	at_worst_timestamp;	/* worst-ever timeout
						 * timestamp
						 */
	spinlock_t	at_lock;
};

enum lustre_at_flags {
	LATF_SKIP	= 0x0,
	LATF_STATS	= 0x1,
};

struct ptlrpc_at_array {
	struct list_head *paa_reqs_array; /** array to hold requests */
        __u32             paa_size;       /** the size of array */
        __u32             paa_count;      /** the total count of reqs */
	time64_t	  paa_deadline;	  /** the earliest deadline of reqs */
        __u32            *paa_reqs_count; /** the count of reqs in each entry */
};

#define IMP_AT_MAX_PORTALS 8
struct imp_at {
	int			iat_portal[IMP_AT_MAX_PORTALS];
	struct adaptive_timeout	iat_net_latency;
	struct adaptive_timeout	iat_service_estimate[IMP_AT_MAX_PORTALS];
};


/** @} */

/** Possible import states */
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
	LUSTRE_IMP_IDLE	      = 11,
	LUSTRE_IMP_LAST
};

/** Returns test string representation of numeric import state \a state */
static inline const char *ptlrpc_import_state_name(enum lustre_imp_state state)
{
	static const char * const import_state_names[] = {
		"<UNKNOWN>", "CLOSED",  "NEW", "DISCONN",
		"CONNECTING", "REPLAY", "REPLAY_LOCKS", "REPLAY_WAIT",
		"RECOVER", "FULL", "EVICTED", "IDLE",
	};

	LASSERT(state < LUSTRE_IMP_LAST);
	return import_state_names[state];
}

/**
 * List of import event types
 */
enum obd_import_event {
        IMP_EVENT_DISCON     = 0x808001,
        IMP_EVENT_INACTIVE   = 0x808002,
        IMP_EVENT_INVALIDATE = 0x808003,
        IMP_EVENT_ACTIVE     = 0x808004,
        IMP_EVENT_OCD        = 0x808005,
        IMP_EVENT_DEACTIVATE = 0x808006,
        IMP_EVENT_ACTIVATE   = 0x808007,
};

/**
 * Definition of import connection structure
 */
struct obd_import_conn {
	/** Item for linking connections together */
	struct list_head	  oic_item;
	/** Pointer to actual PortalRPC connection */
        struct ptlrpc_connection *oic_conn;
        /** uuid of remote side */
        struct obd_uuid           oic_uuid;
        /**
	 * Time (64 bit seconds) of last connection attempt on this connection
         */
	time64_t		  oic_last_attempt;
	unsigned int		  oic_attempts;
	unsigned int		  oic_replied;
	bool			  oic_uptodate;
};

/* state history */
#define IMP_STATE_HIST_LEN 16
struct import_state_hist {
	enum lustre_imp_state	ish_state;
	time64_t		ish_time;
};

/**
 * Defintion of PortalRPC import structure.
 * Imports are representing client-side view to remote target.
 */
struct obd_import {
	/** Reference counter */
	refcount_t		  imp_refcount;
	struct lustre_handle      imp_dlm_handle; /* client's ldlm export */
	/** Currently active connection */
	struct ptlrpc_connection *imp_connection;
        /** PortalRPC client structure for this import */
        struct ptlrpc_client     *imp_client;
	/** List element for linking into pinger chain */
	struct list_head	  imp_pinger_chain;
	/** work struct for destruction of import */
	struct work_struct	  imp_zombie_work;

        /**
         * Lists of requests that are retained for replay, waiting for a reply,
         * or waiting for recovery to complete, respectively.
         * @{
         */
	struct list_head	imp_replay_list;
	struct list_head	imp_sending_list;
	struct list_head	imp_delayed_list;
        /** @} */

	/**
	 * List of requests that are retained for committed open replay. Once
	 * open is committed, open replay request will be moved from the
	 * imp_replay_list into the imp_committed_list.
	 * The imp_replay_cursor is for accelerating searching during replay.
	 * @{
	 */
	struct list_head	imp_committed_list;
	struct list_head	*imp_replay_cursor;
	/** @} */

	/** List of not replied requests */
	struct list_head	imp_unreplied_list;
	/** XID below which we know all replies have been received */
	__u64			imp_known_replied_xid;
	/** highest XID for which we have received a reply */
	__u64			imp_highest_replied_xid;

	/** obd device for this import */
	struct obd_device	*imp_obd;

        /**
         * some seciruty-related fields
         * @{
         */
	struct ptlrpc_sec        *imp_sec;
	rwlock_t		  imp_sec_lock;
	time64_t		imp_sec_expire;
	pid_t			  imp_sec_refpid;
        /** @} */

	/** Wait queue for those who need to wait for recovery completion */
	wait_queue_head_t         imp_recovery_waitq;

	/** Number of requests allocated */
	atomic_t                  imp_reqs;
	/** Number of requests currently in-flight */
	atomic_t                  imp_inflight;
	/** Number of requests currently unregistering */
	atomic_t                  imp_unregistering;
	/** Number of replay requests inflight */
	atomic_t                  imp_replay_inflight;
	/** In-flight replays rate control */
	wait_queue_head_t	  imp_replay_waitq;

	/** Number of currently happening import invalidations */
	atomic_t                  imp_inval_count;
	/** Numbner of request timeouts */
	atomic_t                  imp_timeouts;
	/** Current import state */
        enum lustre_imp_state     imp_state;
	/** Last replay state */
	enum lustre_imp_state     imp_replay_state;
        /** History of import states */
        struct import_state_hist  imp_state_hist[IMP_STATE_HIST_LEN];
        int                       imp_state_hist_idx;
        /** Current import generation. Incremented on every reconnect */
        int                       imp_generation;
	/** Idle connection initiated at this generation */
	int			  imp_initiated_at;
        /** Incremented every time we send reconnection request */
        __u32                     imp_conn_cnt;
       /**
        * \see ptlrpc_free_committed remembers imp_generation value here
        * after a check to save on unnecessary replay list iterations
        */
        int                       imp_last_generation_checked;
        /** Last tranno we replayed */
        __u64                     imp_last_replay_transno;
        /** Last transno committed on remote side */
        __u64                     imp_peer_committed_transno;
        /**
         * \see ptlrpc_free_committed remembers last_transno since its last
         * check here and if last_transno did not change since last run of
         * ptlrpc_free_committed and import generation is the same, we can
         * skip looking for requests to remove from replay list as optimisation
         */
        __u64                     imp_last_transno_checked;
        /**
         * Remote export handle. This is how remote side knows what export
         * we are talking to. Filled from response to connect request
         */
        struct lustre_handle      imp_remote_handle;
        /** When to perform next ping. time in jiffies. */
	time64_t		imp_next_ping;
	/** When we last successfully connected. time in 64bit jiffies */
	time64_t		imp_last_success_conn;

        /** List of all possible connection for import. */
	struct list_head	imp_conn_list;
        /**
         * Current connection. \a imp_connection is imp_conn_current->oic_conn
         */
        struct obd_import_conn   *imp_conn_current;

        /** Protects flags, level, generation, conn_cnt, *_list */
	spinlock_t		  imp_lock;

	/**
	 * A "sentinel" value used to check if there are other threads
	 * waiting on the imp_lock.
	 */
	atomic_t                  imp_waiting;

	/* flags */
	unsigned long		  imp_invalid:1,    /* evicted */
				  /* administratively disabled */
				  imp_deactive:1,
				  /* try to recover the import */
				  imp_replayable:1,
				  /* don't run recovery (timeout instead) */
				  imp_dlm_fake:1,
				  /* use 1/2 timeout on MDS' OSCs */
				  imp_server_timeout:1,
				  /* VBR: imp in delayed recovery */
				  imp_delayed_recovery:1,
				  /* recovery by versions was failed */
				  imp_vbr_failed:1,
				  /* force an immidiate ping */
				  imp_force_verify:1,
				  /* force a scheduled ping */
				  imp_force_next_verify:1,
				  /* pingable */
				  imp_pingable:1,
				  /* resend for replay */
				  imp_resend_replay:1,
				  /* disable normal recovery, for test only. */
				  imp_no_pinger_recover:1,
				  /* import must be reconnected instead of
				   * chouse new connection */
				  imp_force_reconnect:1,
				  /* import has tried to connect with server */
				  imp_connect_tried:1,
				  /* connected but not FULL yet */
				  imp_connected:1,
				  /* grant shrink disabled */
				  imp_grant_shrink_disabled:1,
				  /* to supress LCONSOLE() at conn.restore */
				  imp_was_idle:1,
				  imp_no_cached_data:1;
	u32			  imp_connect_op;
	u32			  imp_idle_timeout;
	u32			  imp_idle_debug;
	struct obd_connect_data	  imp_connect_data;
	__u64			  imp_connect_flags_orig;
	__u64			  imp_connect_flags2_orig;
	int			  imp_connect_error;

	enum lustre_msg_magic	imp_msg_magic;
				/* adjusted based on server capability */
	enum lustre_msghdr	imp_msghdr_flags;

				/* adaptive timeout data */
	struct imp_at		imp_at;
	time64_t		imp_last_reply_time;	/* for health check */
	time64_t		imp_setup_time;
	__u32			imp_conn_restricted_net;
};

/* import.c : adaptive timeout handling.
 *
 * Lustre tracks how long RPCs take to complete. This information is reported
 * back to clients who utilize the information to estimate the time needed
 * for future requests and set appropriate RPC timeouts. Minimum and maximum
 * service times can be configured via the at_min and at_max kernel module
 * parameters, respectively.
 *
 * Since this information is transmitted between nodes the timeouts are in
 * seconds not jiffies which can vary from node to node. To avoid confusion
 * the timeout is handled in timeout_t (s32) instead of time64_t or
 * long (jiffies).
 */
static inline timeout_t at_est2timeout(timeout_t timeout)
{
	/* add an arbitrary minimum: 125% +5 sec */
	return timeout + (timeout >> 2) + 5;
}

static inline timeout_t at_timeout2est(timeout_t timeout)
{
	/* restore estimate value from timeout: e=4/5(t-5) */
	LASSERT(timeout > 0);
	return max((timeout << 2) / 5, 5) - 4;
}

static inline void at_reset_nolock(struct adaptive_timeout *at,
				   timeout_t timeout)
{
	at->at_current_timeout = timeout;
	at->at_worst_timeout_ever = timeout;
	at->at_worst_timestamp = ktime_get_real_seconds();
}

static inline void at_reset(struct adaptive_timeout *at, timeout_t timeout)
{
	spin_lock(&at->at_lock);
	at_reset_nolock(at, timeout);
	spin_unlock(&at->at_lock);
}

static inline void at_init(struct adaptive_timeout *at, timeout_t timeout,
			   int flags)
{
	memset(at, 0, sizeof(*at));
	spin_lock_init(&at->at_lock);
	at->at_flags = flags;
	at_reset(at, timeout);
}

static inline void at_reinit(struct adaptive_timeout *at, timeout_t timeout,
			     int flags)
{
	spin_lock(&at->at_lock);
	at->at_binstart = 0;
	memset(at->at_hist, 0, sizeof(at->at_hist));
	at->at_flags = flags;
	at_reset_nolock(at, timeout);
	spin_unlock(&at->at_lock);
}

timeout_t obd_at_measure(struct obd_device *obd, struct adaptive_timeout *at,
			    timeout_t timeout);

int import_at_get_index(struct obd_import *imp, int portal);

/* genops.c */
struct obd_export;
extern struct obd_import *class_exp2cliimp(struct obd_export *);

/** @} import */

#endif /* __IMPORT_H */

/** @} obd_import */
