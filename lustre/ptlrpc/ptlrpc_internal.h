/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

/* Intramodule declarations for ptlrpc. */

#ifndef PTLRPC_INTERNAL_H
#define PTLRPC_INTERNAL_H

#include "../ldlm/ldlm_internal.h"
#include "heap.h"

#include <linux/sched.h>
#ifdef HAVE_SCHED_SHOW_TASK
#include <linux/sched/debug.h>
#endif

struct ldlm_namespace;
struct obd_import;
struct ldlm_res_id;
struct ptlrpc_request_set;
extern int test_req_buffer_pressure;
extern struct list_head ptlrpc_all_services;
extern struct mutex ptlrpc_all_services_mutex;
extern struct ptlrpc_nrs_pol_conf nrs_conf_fifo;
extern struct ptlrpc_nrs_pol_conf nrs_conf_delay;

#ifdef HAVE_SERVER_SUPPORT
extern struct ptlrpc_nrs_pol_conf nrs_conf_crrn;
extern struct ptlrpc_nrs_pol_conf nrs_conf_orr;
extern struct ptlrpc_nrs_pol_conf nrs_conf_trr;
extern struct ptlrpc_nrs_pol_conf nrs_conf_tbf;
#endif /* HAVE_SERVER_SUPPORT */

/**
 * \addtogoup nrs
 * @{
 */
extern struct nrs_core nrs_core;

extern struct mutex ptlrpcd_mutex;
extern struct mutex pinger_mutex;

extern lnet_handler_t ptlrpc_handler;
extern struct percpu_ref ptlrpc_pending;

#ifndef HAVE_SCHED_SHOW_TASK
#define sched_show_task(task)		libcfs_debug_dumpstack((task))
#endif

/* ptlrpcd.c */
int ptlrpcd_start(struct ptlrpcd_ctl *pc);

/* client.c */
void ptlrpc_at_adj_net_latency(struct ptlrpc_request *req,
			       timeout_t service_timeout);
struct ptlrpc_bulk_desc *ptlrpc_new_bulk(unsigned npages, unsigned max_brw,
					 enum ptlrpc_bulk_op_type type,
					 unsigned portal,
					 const struct ptlrpc_bulk_frag_ops
						*ops);
int ptlrpc_request_cache_init(void);
void ptlrpc_request_cache_fini(void);
struct ptlrpc_request *ptlrpc_request_cache_alloc(gfp_t flags);
void ptlrpc_request_cache_free(struct ptlrpc_request *req);
void ptlrpc_init_xid(void);
void ptlrpc_set_add_new_req(struct ptlrpcd_ctl *pc,
			    struct ptlrpc_request *req);
void ptlrpc_expired_set(struct ptlrpc_request_set *set);
time64_t ptlrpc_set_next_timeout(struct ptlrpc_request_set *);
void ptlrpc_resend_req(struct ptlrpc_request *request);
void ptlrpc_set_mbits(struct ptlrpc_request *req);
void ptlrpc_assign_next_xid_nolock(struct ptlrpc_request *req);
__u64 ptlrpc_known_replied_xid(struct obd_import *imp);
void ptlrpc_add_unreplied(struct ptlrpc_request *req);
void ptlrpc_reqset_free(struct kref *kerf);

/* events.c */
int ptlrpc_init_portals(void);
void ptlrpc_exit_portals(void);

void ptlrpc_request_handle_notconn(struct ptlrpc_request *);
void lustre_assert_wire_constants(void);
bool ptlrpc_import_in_recovery(struct obd_import *imp);
bool ptlrpc_import_in_recovery_disconnect(struct obd_import *imp, bool d);
int ptlrpc_set_import_discon(struct obd_import *imp, __u32 conn_cnt,
			     bool invalid);
void ptlrpc_handle_failed_import(struct obd_import *imp);
int ptlrpc_replay_next(struct obd_import *imp, int *inflight);

int lustre_unpack_req_ptlrpc_body(struct ptlrpc_request *req, int offset);
int lustre_unpack_rep_ptlrpc_body(struct ptlrpc_request *req, int offset);

int ptlrpc_sysfs_register_service(struct kset *parent,
				  struct ptlrpc_service *svc);
void ptlrpc_sysfs_unregister_service(struct ptlrpc_service *svc);

void ptlrpc_ldebugfs_register_service(struct dentry *debugfs_entry,
				      char *param,
				      struct ptlrpc_service *svc);
void ptlrpc_lprocfs_unregister_service(struct ptlrpc_service *svc);
void ptlrpc_lprocfs_rpc_sent(struct ptlrpc_request *req, long amount);
void ptlrpc_lprocfs_do_request_stat (struct ptlrpc_request *req,
                                     long q_usec, long work_usec);

/* NRS */

/**
 * NRS core object.
 *
 * Holds NRS core fields.
 */
struct nrs_core {
	/**
	 * Protects nrs_core::nrs_policies, serializes external policy
	 * registration/unregistration, and NRS core lprocfs operations.
	 */
	struct mutex nrs_mutex;
	/**
	 * List of all policy descriptors registered with NRS core; protected
	 * by nrs_core::nrs_mutex.
	 */
	struct list_head nrs_policies;
};

int ptlrpc_service_nrs_setup(struct ptlrpc_service *svc);
void ptlrpc_service_nrs_cleanup(struct ptlrpc_service *svc);

void ptlrpc_nrs_req_initialize(struct ptlrpc_service_part *svcpt,
			       struct ptlrpc_request *req, bool hp);
void ptlrpc_nrs_req_finalize(struct ptlrpc_request *req);
void ptlrpc_nrs_req_stop_nolock(struct ptlrpc_request *req);
void ptlrpc_nrs_req_add(struct ptlrpc_service_part *svcpt,
			struct ptlrpc_request *req, bool hp);

struct ptlrpc_request *
ptlrpc_nrs_req_get_nolock0(struct ptlrpc_service_part *svcpt, bool hp,
			   bool peek, bool force);

static inline struct ptlrpc_request *
ptlrpc_nrs_req_get_nolock(struct ptlrpc_service_part *svcpt, bool hp,
			  bool force)
{
	return ptlrpc_nrs_req_get_nolock0(svcpt, hp, false, force);
}

static inline struct ptlrpc_request *
ptlrpc_nrs_req_peek_nolock(struct ptlrpc_service_part *svcpt, bool hp)
{
	return ptlrpc_nrs_req_get_nolock0(svcpt, hp, true, true);
}

void ptlrpc_nrs_req_del_nolock(struct ptlrpc_request *req);
bool ptlrpc_nrs_req_pending_nolock(struct ptlrpc_service_part *svcpt, bool hp);
bool ptlrpc_nrs_req_throttling_nolock(struct ptlrpc_service_part *svcpt,
				      bool hp);

int ptlrpc_nrs_policy_control(const struct ptlrpc_service *svc,
			      enum ptlrpc_nrs_queue_type queue, char *name,
			      enum ptlrpc_nrs_ctl opc, bool single, void *arg);

int ptlrpc_nrs_init(void);
void ptlrpc_nrs_fini(void);

static inline bool nrs_svcpt_has_hp(const struct ptlrpc_service_part *svcpt)
{
	return svcpt->scp_nrs_hp != NULL;
}

static inline bool nrs_svc_has_hp(const struct ptlrpc_service *svc)
{
	/**
	 * If the first service partition has an HP NRS head, all service
	 * partitions will.
	 */
	return nrs_svcpt_has_hp(svc->srv_parts[0]);
}

static inline
struct ptlrpc_nrs *nrs_svcpt2nrs(struct ptlrpc_service_part *svcpt, bool hp)
{
	LASSERT(ergo(hp, nrs_svcpt_has_hp(svcpt)));
	return hp ? svcpt->scp_nrs_hp : &svcpt->scp_nrs_reg;
}

static inline int nrs_pol2cptid(const struct ptlrpc_nrs_policy *policy)
{
	return policy->pol_nrs->nrs_svcpt->scp_cpt;
}

static inline
struct ptlrpc_service *nrs_pol2svc(struct ptlrpc_nrs_policy *policy)
{
	return policy->pol_nrs->nrs_svcpt->scp_service;
}

static inline
struct ptlrpc_service_part *nrs_pol2svcpt(struct ptlrpc_nrs_policy *policy)
{
	return policy->pol_nrs->nrs_svcpt;
}

static inline
struct cfs_cpt_table *nrs_pol2cptab(struct ptlrpc_nrs_policy *policy)
{
	return nrs_pol2svc(policy)->srv_cptable;
}

static inline struct ptlrpc_nrs_resource *
nrs_request_resource(struct ptlrpc_nrs_request *nrq)
{
	LASSERT(nrq->nr_initialized);
	LASSERT(!nrq->nr_finalized);

	return nrq->nr_res_ptrs[nrq->nr_res_idx];
}

static inline
struct ptlrpc_nrs_policy *nrs_request_policy(struct ptlrpc_nrs_request *nrq)
{
	return nrs_request_resource(nrq)->res_policy;
}

#define NRS_LPROCFS_QUANTUM_NAME_REG	"reg_quantum:"
#define NRS_LPROCFS_QUANTUM_NAME_HP	"hp_quantum:"

/**
 * the maximum size of nrs_crrn_client::cc_quantum and nrs_orr_data::od_quantum.
 */
#define LPROCFS_NRS_QUANTUM_MAX		65535

/**
 * Max valid command string is the size of the labels, plus "65535" twice, plus
 * a separating space character.
 */
#define LPROCFS_NRS_WR_QUANTUM_MAX_CMD					       \
 sizeof(NRS_LPROCFS_QUANTUM_NAME_REG __stringify(LPROCFS_NRS_QUANTUM_MAX) " "  \
        NRS_LPROCFS_QUANTUM_NAME_HP __stringify(LPROCFS_NRS_QUANTUM_MAX))

/* recovd_thread.c */

int ptlrpc_expire_one_request(struct ptlrpc_request *req, int async_unlink);

/* pers.c */
void ptlrpc_fill_bulk_md(struct lnet_md *md, struct ptlrpc_bulk_desc *desc,
			 int mdcnt);

/* pack_generic.c */
struct ptlrpc_reply_state *
lustre_get_emerg_rs(struct ptlrpc_service_part *svcpt);
void lustre_put_emerg_rs(struct ptlrpc_reply_state *rs);
void lustre_msg_early_size_init(void); /* just for init */

/* pinger.c */
int ptlrpc_start_pinger(void);
int ptlrpc_stop_pinger(void);
void ptlrpc_pinger_sending_on_import(struct obd_import *imp);
void ptlrpc_pinger_commit_expected(struct obd_import *imp);
void ptlrpc_pinger_wake_up(void);
int ping_evictor_wake(struct obd_export *exp);

/* sec_null.c */
int  sptlrpc_null_init(void);
void sptlrpc_null_fini(void);

/* sec_plain.c */
int  sptlrpc_plain_init(void);
void sptlrpc_plain_fini(void);

/* lproc_ptlrpc.c */
int  ptlrpc_lproc_init(void);
void ptlrpc_lproc_fini(void);

/* sec_lproc.c */
int  sptlrpc_lproc_init(void);
void sptlrpc_lproc_fini(void);

/* sec_gc.c */
int sptlrpc_gc_init(void);
void sptlrpc_gc_fini(void);

/* sec_config.c */
void sptlrpc_conf_choose_flavor(enum lustre_sec_part from,
				enum lustre_sec_part to,
				struct obd_uuid *target,
				struct lnet_nid *nid,
				struct sptlrpc_flavor *sf);
int  sptlrpc_conf_init(void);
void sptlrpc_conf_fini(void);

/* sec.c */
int  sptlrpc_init(void);
void sptlrpc_fini(void);

/* layout.c */
__u32 __req_capsule_offset(const struct req_capsule *pill,
			   const struct req_msg_field *field,
			   enum req_location loc);

static inline bool ptlrpc_recoverable_error(int rc)
{
	return (rc == -ENOTCONN || rc == -ENODEV);
}

#ifdef HAVE_SERVER_SUPPORT
int tgt_mod_init(void);
void tgt_mod_exit(void);
int nodemap_mod_init(void);
void nodemap_mod_exit(void);
#endif /* HAVE_SERVER_SUPPORT */

/** initialise ptlrpc common fields */
static inline void ptlrpc_req_comm_init(struct ptlrpc_request *req)
{
	spin_lock_init(&req->rq_lock);
	spin_lock_init(&req->rq_early_free_lock);
	atomic_set(&req->rq_refcount, 1);
	INIT_LIST_HEAD(&req->rq_list);
	INIT_LIST_HEAD(&req->rq_replay_list);
}

/** initialise client side ptlrpc request */
static inline void ptlrpc_cli_req_init(struct ptlrpc_request *req)
{
	struct ptlrpc_cli_req *cr = &req->rq_cli;

	ptlrpc_req_comm_init(req);

	req->rq_receiving_reply = 0;
	req->rq_req_unlinked = req->rq_reply_unlinked = 1;
	req->rq_replied = 0;

	INIT_LIST_HEAD(&cr->cr_set_chain);
	INIT_LIST_HEAD(&cr->cr_ctx_chain);
	INIT_LIST_HEAD(&cr->cr_unreplied_list);
	init_waitqueue_head(&cr->cr_reply_waitq);
	init_waitqueue_head(&cr->cr_set_waitq);
}

/** initialise server side ptlrpc request */
static inline void ptlrpc_srv_req_init(struct ptlrpc_request *req)
{
	struct ptlrpc_srv_req *sr = &req->rq_srv;

	ptlrpc_req_comm_init(req);
	req->rq_srv_req = 1;
	INIT_LIST_HEAD(&sr->sr_exp_list);
	INIT_LIST_HEAD(&sr->sr_timed_list);
	INIT_LIST_HEAD(&sr->sr_hist_list);
}

static inline bool ptlrpc_req_is_connect(struct ptlrpc_request *req)
{
	if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CONNECT ||
	    lustre_msg_get_opc(req->rq_reqmsg) == OST_CONNECT ||
	    lustre_msg_get_opc(req->rq_reqmsg) == MGS_CONNECT)
		return true;
	else
		return false;
}

static inline bool ptlrpc_req_is_disconnect(struct ptlrpc_request *req)
{
	if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_DISCONNECT ||
	    lustre_msg_get_opc(req->rq_reqmsg) == OST_DISCONNECT ||
	    lustre_msg_get_opc(req->rq_reqmsg) == MGS_DISCONNECT)
		return true;
	else
		return false;
}

static inline void do_pack_body(struct ptlrpc_request *req)
{
	struct mdt_body *b = req_capsule_client_get(&req->rq_pill,
						    &RMF_MDT_BODY);

	if (b == NULL)
		return;

	b->mbo_valid = 0;
	b->mbo_eadatasize = 0;
	b->mbo_flags = 0;
	b->mbo_suppgid = -1;
	b->mbo_uid = from_kuid(&init_user_ns, current_uid());
	b->mbo_gid = from_kgid(&init_user_ns, current_gid());
	b->mbo_fsuid = from_kuid(&init_user_ns, current_fsuid());
	b->mbo_fsgid = from_kgid(&init_user_ns, current_fsgid());
	b->mbo_capability = ll_capability_u32(current_cap());
}

#endif /* PTLRPC_INTERNAL_H */
