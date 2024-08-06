// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 */

#ifndef __SELFTEST_SELFTEST_H__
#define __SELFTEST_SELFTEST_H__

#define LNET_ONLY

#include <libcfs/libcfs.h>
#include <lnet/api.h>
#include <lnet/lib-lnet.h>
#include <lnet/lib-types.h>
#include <uapi/linux/lnet/lnetst.h>
#include <linux/refcount.h>

#include "rpc.h"
#include "timer.h"

#ifndef MADE_WITHOUT_COMPROMISE
#define MADE_WITHOUT_COMPROMISE
#endif

/* enum lnet_selftest_session_attrs   - LNet selftest session Netlink
 *					attributes
 *
 *  @LNET_SELFTEST_SESSION_UNSPEC:	unspecified attribute to catch errors
 *  @LNET_SELFTEST_SESSION_PAD:		padding for 64-bit attributes, ignore
 *
 *  @LENT_SELFTEST_SESSION_HDR:		Netlink group this data is for
 *					(NLA_NUL_STRING)
 *  @LNET_SELFTEST_SESSION_NAME:	name of this session (NLA_STRING)
 *  @LNET_SELFTEST_SESSION_KEY:		key used to represent the session
 *					(NLA_U32)
 *  @LNET_SELFTEST_SESSION_TIMESTAMP:	timestamp when the session was created
 *					(NLA_S64)
 *  @LNET_SELFTEST_SESSION_NID:		NID of the node selftest ran on
 *					(NLA_STRING)
 *  @LNET_SELFTEST_SESSION_NODE_COUNT:	Number of nodes in use (NLA_U16)
 */
enum lnet_selftest_session_attrs {
	LNET_SELFTEST_SESSION_UNSPEC = 0,
	LNET_SELFTEST_SESSION_PAD = LNET_SELFTEST_SESSION_UNSPEC,

	LNET_SELFTEST_SESSION_HDR,
	LNET_SELFTEST_SESSION_NAME,
	LNET_SELFTEST_SESSION_KEY,
	LNET_SELFTEST_SESSION_TIMESTAMP,
	LNET_SELFTEST_SESSION_NID,
	LNET_SELFTEST_SESSION_NODE_COUNT,

	__LNET_SELFTEST_SESSION_MAX_PLUS_ONE,
};

#define LNET_SELFTEST_SESSION_MAX	(__LNET_SELFTEST_SESSION_MAX_PLUS_ONE - 1)

/* enum lnet_selftest_group_attrs     - LNet selftest group Netlink attributes
 *
 *  @LNET_SELFTEST_GROUP_ATTR_UNSPEC:	unspecified attribute to catch errors
 *
 *  @LENT_SELFTEST_GROUP_ATTR_HDR:	Netlink group this data is for
 *					(NLA_NUL_STRING)
 *  @LNET_SELFTEST_GROUP_ATTR_NAME:	name of this group (NLA_STRING)
 *  @LNET_SELFTEST_GROUP_ATTR_NODELIST:	List of nodes belonging to the group
 *					(NLA_NESTED)
 */
enum lnet_selftest_group_attrs {
	LNET_SELFTEST_GROUP_ATTR_UNSPEC = 0,

	LNET_SELFTEST_GROUP_ATTR_HDR,
	LNET_SELFTEST_GROUP_ATTR_NAME,
	LNET_SELFTEST_GROUP_ATTR_NODELIST,

	__LNET_SELFTEST_GROUP_MAX_PLUS_ONE,
};

#define LNET_SELFTEST_GROUP_MAX		(__LNET_SELFTEST_GROUP_MAX_PLUS_ONE - 1)

/* enum lnet_selftest_group_nodelist_prop_attrs	      - Netlink attributes for
 *							the properties of the
 *							nodes that belong to a
 *							group
 *
 *  @LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_UNSPEC:	unspecified attribute
 *							to catch errors
 *
 *  @LENT_SELFTEST_GROUP_NODELIST_PROP_ATTR_NID:	Nodes's NID (NLA_STRING)
 *  @LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_STATUS:	Status of the node
 *							(NLA_STRING)
 */
enum lnet_selftest_group_nodelist_prop_attrs {
	LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_UNSPEC = 0,

	LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_NID,
	LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_STATUS,
	__LNET_SELFTEST_GROUP_NODELIST_PROP_MAX_PLUS_ONE,
};

#define LNET_SELFTEST_GROUP_NODELIST_PROP_MAX	(__LNET_SELFTEST_GROUP_NODELIST_PROP_MAX_PLUS_ONE - 1)

enum lsr_swi_state {
	SWI_STATE_DONE = 0,
	SWI_STATE_NEWBORN,
	SWI_STATE_REPLY_SUBMITTED,
	SWI_STATE_REPLY_SENT,
	SWI_STATE_REQUEST_SUBMITTED,
	SWI_STATE_REQUEST_SENT,
	SWI_STATE_REPLY_RECEIVED,
	SWI_STATE_BULK_STARTED,
	SWI_STATE_RUNNING,
	SWI_STATE_PAUSE,
};

/* forward refs */
struct srpc_service;
struct srpc_service_cd;
struct sfw_test_unit;
struct sfw_test_instance;

/* services below SRPC_FRAMEWORK_SERVICE_MAX_ID are framework
 * services, e.g. create/modify session.
 */
#define SRPC_SERVICE_DEBUG              0
#define SRPC_SERVICE_MAKE_SESSION       1
#define SRPC_SERVICE_REMOVE_SESSION     2
#define SRPC_SERVICE_BATCH              3
#define SRPC_SERVICE_TEST               4
#define SRPC_SERVICE_QUERY_STAT         5
#define SRPC_SERVICE_JOIN               6
#define SRPC_FRAMEWORK_SERVICE_MAX_ID   10
/* other services start from SRPC_FRAMEWORK_SERVICE_MAX_ID+1 */
#define SRPC_SERVICE_BRW                11
#define SRPC_SERVICE_PING               12
#define SRPC_SERVICE_MAX_ID             12

#define SRPC_REQUEST_PORTAL             50
/* a lazy portal for framework RPC requests */
#define SRPC_FRAMEWORK_REQUEST_PORTAL   51
/* all reply/bulk RDMAs go to this portal */
#define SRPC_RDMA_PORTAL                52

static inline enum srpc_msg_type
srpc_service2request(int service)
{
	switch (service) {
	default:
		LBUG();
	case SRPC_SERVICE_DEBUG:
		return SRPC_MSG_DEBUG_REQST;

	case SRPC_SERVICE_MAKE_SESSION:
		return SRPC_MSG_MKSN_REQST;

	case SRPC_SERVICE_REMOVE_SESSION:
		return SRPC_MSG_RMSN_REQST;

	case SRPC_SERVICE_BATCH:
		return SRPC_MSG_BATCH_REQST;

	case SRPC_SERVICE_TEST:
		return SRPC_MSG_TEST_REQST;

	case SRPC_SERVICE_QUERY_STAT:
		return SRPC_MSG_STAT_REQST;

	case SRPC_SERVICE_BRW:
		return SRPC_MSG_BRW_REQST;

	case SRPC_SERVICE_PING:
		return SRPC_MSG_PING_REQST;

	case SRPC_SERVICE_JOIN:
		return SRPC_MSG_JOIN_REQST;
	}
}

static inline enum srpc_msg_type
srpc_service2reply(int service)
{
	return srpc_service2request(service) + 1;
}

enum srpc_event_type {
	SRPC_BULK_REQ_RCVD   = 1, /* passive bulk request(PUT sink/GET source) received */
	SRPC_BULK_PUT_SENT   = 2, /* active bulk PUT sent (source) */
	SRPC_BULK_GET_RPLD   = 3, /* active bulk GET replied (sink) */
	SRPC_REPLY_RCVD      = 4, /* incoming reply received */
	SRPC_REPLY_SENT      = 5, /* outgoing reply sent */
	SRPC_REQUEST_RCVD    = 6, /* incoming request received */
	SRPC_REQUEST_SENT    = 7, /* outgoing request sent */
};

/* RPC event */
struct srpc_event {
	enum srpc_event_type	ev_type;   /* what's up */
	enum lnet_event_kind	ev_lnet;   /* LNet event type */
	int               ev_fired;  /* LNet event fired? */
	int               ev_status; /* LNet event status */
	void             *ev_data;   /* owning server/client RPC */
};

/* bulk descriptor */
struct srpc_bulk {
	int			bk_len;  /* len of bulk data */
	struct lnet_handle_md	bk_mdh;
	int			bk_sink; /* sink/source */
	int			bk_alloc; /* # allocated iov */
	int			bk_niov; /* # iov in bk_iovs */
	struct bio_vec		bk_iovs[];
};

/* message buffer descriptor */
struct srpc_buffer {
	struct list_head	buf_list; /* chain on srpc_service::*_msgq */
	struct srpc_msg		buf_msg;
	struct lnet_handle_md	buf_mdh;
	lnet_nid_t		buf_self;
	struct lnet_process_id	buf_peer;
};

struct swi_workitem;
typedef void (*swi_action_t)(struct swi_workitem *);

struct swi_workitem {
	struct workqueue_struct	*swi_wq;
	struct work_struct	swi_work;
	swi_action_t		swi_action;
	enum lsr_swi_state	swi_state;
};

/* server-side state of a RPC */
struct srpc_server_rpc {
	/* chain on srpc_service::*_rpcq */
	struct list_head	srpc_list;
	struct srpc_service_cd *srpc_scd;
	struct swi_workitem	srpc_wi;
	struct srpc_event	srpc_ev;	/* bulk/reply event */
	lnet_nid_t		srpc_self;
	struct lnet_process_id	srpc_peer;
	struct srpc_msg		srpc_replymsg;
	struct lnet_handle_md	srpc_replymdh;
	struct srpc_buffer     *srpc_reqstbuf;
	struct srpc_bulk       *srpc_bulk;

	unsigned int	srpc_aborted; /* being given up */
	int		srpc_status;
	void		(*srpc_done)(struct srpc_server_rpc *);
};

/* client-side state of a RPC */
struct srpc_client_rpc {
	struct list_head	crpc_list;	/* chain on user's lists */
	spinlock_t		crpc_lock;	/* serialize */
	int			crpc_service;
	atomic_t		crpc_refcount;
	/* # seconds to wait for reply */
	int			crpc_timeout;
	struct stt_timer	crpc_timer;
	struct swi_workitem	crpc_wi;
	struct lnet_process_id	crpc_dest;

	void               (*crpc_done)(struct srpc_client_rpc *);
	void               (*crpc_fini)(struct srpc_client_rpc *);
	int                  crpc_status;    /* completion status */
	void                *crpc_priv;      /* caller data */

	/* state flags */
	unsigned int         crpc_aborted:1; /* being given up */
	unsigned int         crpc_closed:1;  /* completed */

	/* RPC events */
	struct srpc_event	crpc_bulkev;	/* bulk event */
	struct srpc_event	crpc_reqstev;	/* request event */
	struct srpc_event	crpc_replyev;	/* reply event */

	/* bulk, request(reqst), and reply exchanged on wire */
	struct srpc_msg		crpc_reqstmsg;
	struct srpc_msg		crpc_replymsg;
	struct lnet_handle_md	crpc_reqstmdh;
	struct lnet_handle_md	crpc_replymdh;
	struct srpc_bulk	crpc_bulk;
};

#define srpc_client_rpc_size(rpc)                                       \
offsetof(struct srpc_client_rpc, crpc_bulk.bk_iovs[(rpc)->crpc_bulk.bk_niov])

#define srpc_client_rpc_addref(rpc)                                     \
do {                                                                    \
	CDEBUG(D_NET, "RPC[%p] -> %s (%d)++\n",                         \
	       (rpc), libcfs_id2str((rpc)->crpc_dest),                  \
	       atomic_read(&(rpc)->crpc_refcount));                     \
	LASSERT(atomic_read(&(rpc)->crpc_refcount) > 0);                \
	atomic_inc(&(rpc)->crpc_refcount);                              \
} while (0)

#define srpc_client_rpc_decref(rpc)                                     \
do {                                                                    \
	CDEBUG(D_NET, "RPC[%p] -> %s (%d)--\n",                         \
	       (rpc), libcfs_id2str((rpc)->crpc_dest),                  \
	       atomic_read(&(rpc)->crpc_refcount));                     \
	LASSERT(atomic_read(&(rpc)->crpc_refcount) > 0);                \
	if (atomic_dec_and_test(&(rpc)->crpc_refcount))                 \
		srpc_destroy_client_rpc(rpc);                           \
} while (0)

#define srpc_event_pending(rpc)   ((rpc)->crpc_bulkev.ev_fired == 0 ||  \
				   (rpc)->crpc_reqstev.ev_fired == 0 || \
				   (rpc)->crpc_replyev.ev_fired == 0)

/* CPU partition data of srpc service */
struct srpc_service_cd {
	/** serialize */
	spinlock_t		scd_lock;
	/** backref to service */
	struct srpc_service	*scd_svc;
	/** event buffer */
	struct srpc_event	scd_ev;
	/** free RPC descriptors */
	struct list_head	scd_rpc_free;
	/** in-flight RPCs */
	struct list_head	scd_rpc_active;
	/** workitem for posting buffer */
	struct swi_workitem	scd_buf_wi;
	/** CPT id */
	int			scd_cpt;
	/** error code for scd_buf_wi */
	int			scd_buf_err;
	/** timestamp for scd_buf_err */
	time64_t		scd_buf_err_stamp;
	/** total # request buffers */
	int			scd_buf_total;
	/** # posted request buffers */
	int			scd_buf_nposted;
	/** in progress of buffer posting */
	int			scd_buf_posting;
	/** allocate more buffers if scd_buf_nposted < scd_buf_low */
	int			scd_buf_low;
	/** increase/decrease some buffers */
	int			scd_buf_adjust;
	/** posted message buffers */
	struct list_head	scd_buf_posted;
	/** blocked for RPC descriptor */
	struct list_head	scd_buf_blocked;
};

/* number of server workitems (mini-thread) for testing service */
#define SFW_TEST_WI_MIN		256
#define SFW_TEST_WI_MAX		2048
/* extra buffers for tolerating buggy peers, or unbalanced number
 * of peers between partitions  */
#define SFW_TEST_WI_EXTRA	64

/* number of server workitems (mini-thread) for framework service */
#define SFW_FRWK_WI_MIN		16
#define SFW_FRWK_WI_MAX		256

struct srpc_service {
	int			sv_id;		/* service id */
	const char		*sv_name;	/* human readable name */
	int			sv_wi_total;	/* total server workitems */
	int			sv_shuttingdown;
	int			sv_ncpts;
	/* percpt data for srpc_service */
	struct srpc_service_cd	**sv_cpt_data;
	/* Service callbacks:
	 * - sv_handler: process incoming RPC request
	 * - sv_bulk_ready: notify bulk data
	 */
	int              (*sv_handler)(struct srpc_server_rpc *);
	int              (*sv_bulk_ready)(struct srpc_server_rpc *, int);

	/** Service side srpc constructor/destructor.
	 *  used for the bulk preallocation as usual.
	 */
	int              (*sv_srpc_init)(struct srpc_server_rpc *, int);
	void             (*sv_srpc_fini)(struct srpc_server_rpc *);
};

struct lst_session_id {
	s64			ses_stamp;	/* time stamp in milliseconds */
	struct lnet_nid		ses_nid;	/* nid of console node */
};						/*** session id (large addr) */

extern struct lst_session_id LST_INVALID_SID;

struct sfw_session {
	/* chain on fw_zombie_sessions */
	struct list_head	sn_list;
	struct lst_session_id	sn_id;		/* unique identifier */
	/* # seconds' inactivity to expire */
	unsigned int		sn_timeout;
	int			sn_timer_active;
	unsigned int		sn_features;
	struct stt_timer	sn_timer;
	struct list_head	sn_batches;	/* list of batches */
	char			sn_name[LST_NAME_SIZE];
	refcount_t		sn_refcount;
	atomic_t		sn_brw_errors;
	atomic_t		sn_ping_errors;
	ktime_t			sn_started;
};

static inline int sfw_sid_equal(struct lst_sid sid0,
				struct lst_session_id sid1)
{
	struct lnet_nid ses_nid;

	lnet_nid4_to_nid(sid0.ses_nid, &ses_nid);

	return ((sid0.ses_stamp == sid1.ses_stamp) &&
		nid_same(&ses_nid, &sid1.ses_nid));
}

struct sfw_batch {
	struct list_head	bat_list;	/* chain on sn_batches */
	struct lst_bid		bat_id;		/* batch id */
	int			bat_error;	/* error code of batch */
	struct sfw_session	*bat_session;	/* batch's session */
	atomic_t		bat_nactive;	/* # of active tests */
	struct list_head	bat_tests;	/* test instances */
};

struct sfw_test_client_ops {
	int  (*tso_init)(struct sfw_test_instance *tsi); /* intailize test client */
	void (*tso_fini)(struct sfw_test_instance *tsi); /* finalize test client */
	int  (*tso_prep_rpc)(struct sfw_test_unit *tsu,
			     struct lnet_process_id dest,
			     struct srpc_client_rpc **rpc); /* prep a tests rpc */
	void (*tso_done_rpc)(struct sfw_test_unit *tsu,
			     struct srpc_client_rpc *rpc);  /* done a test rpc */
};

struct sfw_test_instance {
	struct list_head	tsi_list; /* chain on batch */
	int			tsi_service; /* test type */
	struct sfw_batch	*tsi_batch; /* batch */
	struct sfw_test_client_ops	*tsi_ops; /* test client operations */

	/* public parameter for all test units */
	unsigned int		tsi_is_client:1;     /* is test client */
	unsigned int		tsi_stoptsu_onerr:1; /* stop tsu on error */
	int                     tsi_concur;          /* concurrency */
	int                     tsi_loop;            /* loop count */

	/* status of test instance */
	spinlock_t		tsi_lock;	/* serialize */
	unsigned int		tsi_stopping:1;	/* test is stopping */
	atomic_t		tsi_nactive;	/* # of active test unit */
	struct list_head	tsi_units;	/* test units */
	struct list_head	tsi_free_rpcs;	/* free rpcs */
	struct list_head	tsi_active_rpcs;/* active rpcs */

	union {
		struct test_ping_req	ping;	  /* ping parameter */
		struct test_bulk_req	bulk_v0;  /* bulk parameter */
		struct test_bulk_req_v1	bulk_v1;  /* bulk v1 parameter */
	} tsi_u;
};

/* XXX: trailing (PAGE_SIZE % sizeof(struct lnet_process_id)) bytes at
 * the end of pages are not used */
#define SFW_MAX_CONCUR     LST_MAX_CONCUR
#define SFW_ID_PER_PAGE    (PAGE_SIZE / sizeof(struct lnet_process_id_packed))
#define SFW_MAX_NDESTS     (LNET_MAX_IOV * SFW_ID_PER_PAGE)
#define sfw_id_pages(n)    (((n) + SFW_ID_PER_PAGE - 1) / SFW_ID_PER_PAGE)

struct sfw_test_unit {
	struct list_head	tsu_list;	/* chain on lst_test_instance */
	struct lnet_process_id	tsu_dest;	/* id of dest node */
	int			tsu_loop;	/* loop count of the test */
	struct sfw_test_instance *tsu_instance;	/* pointer to test instance */
	void			*tsu_private;	/* private data */
	struct swi_workitem	 tsu_worker;	/* workitem of the test unit */
};

struct sfw_test_case {
	struct list_head		tsc_list; /* chain on fw_tests */
	struct srpc_service		*tsc_srv_service; /* test service */
	struct sfw_test_client_ops	*tsc_cli_ops; /* ops of test client */
};

struct srpc_client_rpc *
sfw_create_rpc(struct lnet_process_id peer, int service,
	       unsigned int features, int nbulkiov, int bulklen,
	       void (*done)(struct srpc_client_rpc *), void *priv);
int sfw_create_test_rpc(struct sfw_test_unit *tsu,
			struct lnet_process_id peer, unsigned int features,
			int nblk, int blklen, struct srpc_client_rpc **rpc);
void sfw_abort_rpc(struct srpc_client_rpc *rpc);
void sfw_post_rpc(struct srpc_client_rpc *rpc);
void sfw_client_rpc_done(struct srpc_client_rpc *rpc);
void sfw_unpack_message(struct srpc_msg *msg);
void sfw_add_bulk_page(struct srpc_bulk *bk, struct page *pg, int i);
int sfw_alloc_pages(struct srpc_server_rpc *rpc, int cpt, int len,
		    int sink);
int sfw_make_session(struct srpc_mksn_reqst *request,
		     struct srpc_mksn_reply *reply);

struct srpc_client_rpc *
srpc_create_client_rpc(struct lnet_process_id peer, int service,
		       int nbulkiov, int bulklen,
		       void (*rpc_done)(struct srpc_client_rpc *),
		       void (*rpc_fini)(struct srpc_client_rpc *), void *priv);
void srpc_post_rpc(struct srpc_client_rpc *rpc);
void srpc_abort_rpc(struct srpc_client_rpc *rpc, int why);
void srpc_free_bulk(struct srpc_bulk *bk);

struct srpc_bulk *srpc_alloc_bulk(int cpt, unsigned int bulk_len);
void srpc_init_bulk(struct srpc_bulk *bk, unsigned int off,
		    unsigned int bulk_len, int sink);

void srpc_send_rpc(struct swi_workitem *wi);
int srpc_send_reply(struct srpc_server_rpc *rpc);
int srpc_add_service(struct srpc_service *sv);
int srpc_remove_service(struct srpc_service *sv);
void srpc_shutdown_service(struct srpc_service *sv);
void srpc_abort_service(struct srpc_service *sv);
int srpc_finish_service(struct srpc_service *sv);
int srpc_service_add_buffers(struct srpc_service *sv, int nbuffer);
void srpc_service_remove_buffers(struct srpc_service *sv, int nbuffer);
void srpc_get_counters(struct srpc_counters *cnt);

extern struct workqueue_struct *lst_serial_wq;
extern struct workqueue_struct **lst_test_wq;

static inline int
srpc_serv_is_framework(struct srpc_service *svc)
{
	return svc->sv_id < SRPC_FRAMEWORK_SERVICE_MAX_ID;
}

static void
swi_wi_action(struct work_struct *wi)
{
	struct swi_workitem *swi;

	swi = container_of(wi, struct swi_workitem, swi_work);
	swi->swi_action(swi);
}

static inline void
swi_init_workitem(struct swi_workitem *swi,
		  swi_action_t action, struct workqueue_struct *wq)
{
	swi->swi_wq = wq;
	swi->swi_action = action;
	swi->swi_state  = SWI_STATE_NEWBORN;
	INIT_WORK(&swi->swi_work, swi_wi_action);
}

static inline void
swi_schedule_workitem(struct swi_workitem *wi)
{
	queue_work(wi->swi_wq, &wi->swi_work);
}

static inline int
swi_cancel_workitem(struct swi_workitem *swi)
{
	swi->swi_state = SWI_STATE_DONE;
	return cancel_work_sync(&swi->swi_work);
}

int sfw_startup(void);
int srpc_startup(void);
void sfw_shutdown(void);
void srpc_shutdown(void);

static inline void
srpc_destroy_client_rpc(struct srpc_client_rpc *rpc)
{
	LASSERT(rpc != NULL);
	LASSERT(!srpc_event_pending(rpc));
	LASSERT(atomic_read(&rpc->crpc_refcount) == 0);

	if (rpc->crpc_fini == NULL)
		LIBCFS_FREE(rpc, srpc_client_rpc_size(rpc));
	else
		(*rpc->crpc_fini) (rpc);
}

static inline void
srpc_init_client_rpc(struct srpc_client_rpc *rpc, struct lnet_process_id peer,
		     int service, int nbulkiov, int bulklen,
		     void (*rpc_done)(struct srpc_client_rpc *),
		     void (*rpc_fini)(struct srpc_client_rpc *), void *priv)
{
	LASSERT(nbulkiov <= LNET_MAX_IOV);

	memset(rpc, 0, offsetof(struct srpc_client_rpc,
				crpc_bulk.bk_iovs[nbulkiov]));

	INIT_LIST_HEAD(&rpc->crpc_list);
	swi_init_workitem(&rpc->crpc_wi, srpc_send_rpc,
			  lst_test_wq[lnet_cpt_of_nid(peer.nid, NULL)]);
	spin_lock_init(&rpc->crpc_lock);
	atomic_set(&rpc->crpc_refcount, 1); /* 1 ref for caller */

	rpc->crpc_dest         = peer;
	rpc->crpc_priv         = priv;
	rpc->crpc_service      = service;
	rpc->crpc_bulk.bk_len  = bulklen;
	rpc->crpc_bulk.bk_niov = nbulkiov;
	rpc->crpc_done         = rpc_done;
	rpc->crpc_fini         = rpc_fini;
	LNetInvalidateMDHandle(&rpc->crpc_reqstmdh);
	LNetInvalidateMDHandle(&rpc->crpc_replymdh);
	LNetInvalidateMDHandle(&rpc->crpc_bulk.bk_mdh);

	/* no event is expected at this point */
	rpc->crpc_bulkev.ev_fired  =
	rpc->crpc_reqstev.ev_fired =
	rpc->crpc_replyev.ev_fired = 1;

	rpc->crpc_reqstmsg.msg_magic   = SRPC_MSG_MAGIC;
	rpc->crpc_reqstmsg.msg_version = SRPC_MSG_VERSION;
	rpc->crpc_reqstmsg.msg_type    = srpc_service2request(service);
}

static inline const char *
swi_state2str(int state)
{
#define STATE2STR(x) case x: return #x
	switch (state) {
	default:
		LBUG();
	STATE2STR(SWI_STATE_NEWBORN);
	STATE2STR(SWI_STATE_REPLY_SUBMITTED);
	STATE2STR(SWI_STATE_REPLY_SENT);
	STATE2STR(SWI_STATE_REQUEST_SUBMITTED);
	STATE2STR(SWI_STATE_REQUEST_SENT);
	STATE2STR(SWI_STATE_REPLY_RECEIVED);
	STATE2STR(SWI_STATE_BULK_STARTED);
	STATE2STR(SWI_STATE_DONE);
	}
#undef STATE2STR
}

#define lst_wait_until(cond, lock, fmt, ...)				\
do {									\
	int __I = 2;							\
	while (!(cond)) {						\
		CDEBUG(is_power_of_2(++__I) ? D_WARNING : D_NET,	\
		       fmt, ## __VA_ARGS__);				\
		spin_unlock(&(lock));					\
									\
		schedule_timeout_uninterruptible(			\
			cfs_time_seconds(1) / 10);			\
									\
		spin_lock(&(lock));					\
	}								\
} while (0)

static inline void
srpc_wait_service_shutdown(struct srpc_service *sv)
{
	int i = 2;

	LASSERT(sv->sv_shuttingdown);

	while (srpc_finish_service(sv) == 0) {
		i++;
		CDEBUG(((i & -i) == i) ? D_WARNING : D_NET,
		       "Waiting for %s service to shutdown...\n",
		       sv->sv_name);
		schedule_timeout_uninterruptible(cfs_time_seconds(1) / 10);
	}
}

extern struct sfw_test_client_ops ping_test_client;
extern struct srpc_service ping_test_service;
void ping_init_test_client(void);
void ping_init_test_service(void);

extern struct sfw_test_client_ops brw_test_client;
extern struct srpc_service brw_test_service;
void brw_init_test_service(void);

#endif /* __SELFTEST_SELFTEST_H__ */
