// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/fs_struct.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lu_object.h>
#include <uapi/linux/lnet/lnet-types.h>
#include "ptlrpc_internal.h"
#include <linux/delay.h>

/* The following are visible and mutable through /sys/module/ptlrpc */
int test_req_buffer_pressure = 0;
module_param(test_req_buffer_pressure, int, 0444);
MODULE_PARM_DESC(test_req_buffer_pressure, "set non-zero to put pressure on request buffer pools");
module_param(at_min, int, 0644);
MODULE_PARM_DESC(at_min, "Adaptive timeout minimum (sec)");
module_param(at_max, int, 0644);
MODULE_PARM_DESC(at_max, "Adaptive timeout maximum (sec)");
module_param(at_history, int, 0644);
MODULE_PARM_DESC(at_history,
		 "Adaptive timeouts remember the slowest event that took place within this period (sec)");
module_param(at_unhealthy_factor, int, 0644);
MODULE_PARM_DESC(at_unhealthy_factor,
		 "Multiple of at_max when delayed RPCs considered unhealthy");
module_param(at_early_margin, int, 0644);
MODULE_PARM_DESC(at_early_margin, "How soon before an RPC deadline to send an early reply");
module_param(at_extra, int, 0644);
MODULE_PARM_DESC(at_extra, "How much extra time to give with each early reply");

/* forward ref */
static int ptlrpc_server_post_idle_rqbds(struct ptlrpc_service_part *svcpt);
static void ptlrpc_server_hpreq_fini(struct ptlrpc_request *req);
static void ptlrpc_at_remove_timed(struct ptlrpc_request *req);
static int ptlrpc_start_threads(struct ptlrpc_service *svc);
static int ptlrpc_start_thread(struct ptlrpc_service_part *svcpt, int wait);

/* Holds a list of all PTLRPC services */
LIST_HEAD(ptlrpc_all_services);
/* Used to protect the @ptlrpc_all_services list */
struct mutex ptlrpc_all_services_mutex;

static struct ptlrpc_request_buffer_desc *
ptlrpc_alloc_rqbd(struct ptlrpc_service_part *svcpt)
{
	struct ptlrpc_service		  *svc = svcpt->scp_service;
	struct ptlrpc_request_buffer_desc *rqbd;

	OBD_CPT_ALLOC_PTR(rqbd, svc->srv_cptable, svcpt->scp_cpt);
	if (rqbd == NULL)
		return NULL;

	rqbd->rqbd_svcpt = svcpt;
	rqbd->rqbd_refcount = 0;
	rqbd->rqbd_cbid.cbid_fn = request_in_callback;
	rqbd->rqbd_cbid.cbid_arg = rqbd;
	INIT_LIST_HEAD(&rqbd->rqbd_reqs);
	OBD_CPT_ALLOC_LARGE(rqbd->rqbd_buffer, svc->srv_cptable,
			    svcpt->scp_cpt, svc->srv_buf_size);
	if (rqbd->rqbd_buffer == NULL) {
		OBD_FREE_PTR(rqbd);
		return NULL;
	}

	spin_lock(&svcpt->scp_lock);
	list_add(&rqbd->rqbd_list, &svcpt->scp_rqbd_idle);
	svcpt->scp_nrqbds_total++;
	spin_unlock(&svcpt->scp_lock);

	return rqbd;
}

static void ptlrpc_free_rqbd(struct ptlrpc_request_buffer_desc *rqbd)
{
	struct ptlrpc_service_part *svcpt = rqbd->rqbd_svcpt;

	LASSERT(rqbd->rqbd_refcount == 0);
	LASSERT(list_empty(&rqbd->rqbd_reqs));

	OBD_FREE_LARGE(rqbd->rqbd_buffer, svcpt->scp_service->srv_buf_size);
	OBD_FREE_PTR(rqbd);
}

static int ptlrpc_grow_req_bufs(struct ptlrpc_service_part *svcpt, int post)
{
	struct ptlrpc_service *svc = svcpt->scp_service;
	struct ptlrpc_request_buffer_desc *rqbd;
	int rc = 0;
	int i;

	if (svcpt->scp_rqbd_allocating)
		goto try_post;

	spin_lock(&svcpt->scp_lock);
	/* check again with lock */
	if (svcpt->scp_rqbd_allocating) {
		/* NB: we might allow more than one thread in the future */
		LASSERT(svcpt->scp_rqbd_allocating == 1);
		spin_unlock(&svcpt->scp_lock);
		goto try_post;
	}

	svcpt->scp_rqbd_allocating++;
	spin_unlock(&svcpt->scp_lock);


	for (i = 0; i < svc->srv_nbuf_per_group; i++) {
		/*
		 * NB: another thread might have recycled enough rqbds, we
		 * need to make sure it wouldn't over-allocate, see LU-1212.
		 */
		if (svcpt->scp_nrqbds_posted >= svc->srv_nbuf_per_group ||
		    (svc->srv_nrqbds_max != 0 &&
		     svcpt->scp_nrqbds_total > svc->srv_nrqbds_max))
			break;

		rqbd = ptlrpc_alloc_rqbd(svcpt);

		if (rqbd == NULL) {
			CERROR("%s: Can't allocate request buffer\n",
			       svc->srv_name);
			rc = -ENOMEM;
			break;
		}
	}

	spin_lock(&svcpt->scp_lock);

	LASSERT(svcpt->scp_rqbd_allocating == 1);
	svcpt->scp_rqbd_allocating--;

	spin_unlock(&svcpt->scp_lock);

	CDEBUG(D_RPCTRACE,
	       "%s: allocate %d new %d-byte reqbufs (%d/%d left), rc = %d\n",
	       svc->srv_name, i, svc->srv_buf_size, svcpt->scp_nrqbds_posted,
	       svcpt->scp_nrqbds_total, rc);

 try_post:
	if (post && rc == 0)
		rc = ptlrpc_server_post_idle_rqbds(svcpt);

	return rc;
}

/**
 * ptlrpc_save_lock() - Part of Rep-Ack(Reply Acknowledgement) logic
 * @req: pointer to struct ptlrpc_request
 * @lock: pointer to lustre_handle (to be saved)
 * @no_ack: if True, server will not wait for client ack. (incl difficult reqs)
 *
 * Puts(saves) a lock and its mode into reply state assotiated to request reply
 */
void ptlrpc_save_lock(struct ptlrpc_request *req, struct lustre_handle *lock,
		      bool no_ack)
{
	struct ptlrpc_reply_state *rs = req->rq_reply_state;
	int idx;

	LASSERT(rs != NULL);
	CDEBUG(D_RPCTRACE, "nlocks %d\n", rs->rs_nlocks);
	LASSERT(rs->rs_nlocks < RS_MAX_LOCKS);

	idx = rs->rs_nlocks++;
	rs->rs_locks[idx] = *lock;
	rs->rs_difficult = 1;
	rs->rs_no_ack = no_ack;
}
EXPORT_SYMBOL(ptlrpc_save_lock);


struct ptlrpc_hr_partition;

struct ptlrpc_hr_thread {
	int				hrt_id;		/* thread ID */
	spinlock_t			hrt_lock;
	wait_queue_head_t		hrt_waitq;
	struct list_head		hrt_queue;
	struct ptlrpc_hr_partition	*hrt_partition;
};

struct ptlrpc_hr_partition {
	/* # of started threads */
	atomic_t			hrp_nstarted;
	/* # of stopped threads */
	atomic_t			hrp_nstopped;
	/* cpu partition id */
	int				hrp_cpt;
	/* round-robin rotor for choosing thread */
	int				hrp_rotor;
	/* total number of threads on this partition */
	int				hrp_nthrs;
	/* threads table */
	struct ptlrpc_hr_thread		*hrp_thrs;
};

#define HRT_RUNNING 0
#define HRT_STOPPING 1

struct ptlrpc_hr_service {
	/* CPU partition table, it's just cfs_cpt_tab for now */
	struct cfs_cpt_table		*hr_cpt_table;
	/** controller sleep waitq */
	wait_queue_head_t		hr_waitq;
	unsigned int			hr_stopping;
	/** roundrobin rotor for non-affinity service */
	unsigned int			hr_rotor;
	/* partition data */
	struct ptlrpc_hr_partition	**hr_partitions;
};

struct rs_batch {
	struct list_head			rsb_replies;
	unsigned int			rsb_n_replies;
	struct ptlrpc_service_part	*rsb_svcpt;
};

/** reply handling service. */
static struct ptlrpc_hr_service		ptlrpc_hr;

/* maximum mumber of replies scheduled in one batch */
#define MAX_SCHEDULED 256

/* Initialize a reply batch. */
static void rs_batch_init(struct rs_batch *b)
{
	memset(b, 0, sizeof(*b));
	INIT_LIST_HEAD(&b->rsb_replies);
}

/* Choose an hr thread to dispatch requests to. */
static
struct ptlrpc_hr_thread *ptlrpc_hr_select(struct ptlrpc_service_part *svcpt)
{
	struct ptlrpc_hr_partition	*hrp;
	unsigned int			rotor;

	if (svcpt->scp_cpt >= 0 &&
	    svcpt->scp_service->srv_cptable == ptlrpc_hr.hr_cpt_table) {
		/* directly match partition */
		hrp = ptlrpc_hr.hr_partitions[svcpt->scp_cpt];

	} else {
		rotor = ptlrpc_hr.hr_rotor++;
		rotor %= cfs_cpt_number(ptlrpc_hr.hr_cpt_table);

		hrp = ptlrpc_hr.hr_partitions[rotor];
	}

	rotor = hrp->hrp_rotor++;
	return &hrp->hrp_thrs[rotor % hrp->hrp_nthrs];
}

/* Dispatch all replies accumulated in the batch to one from
 * dedicated reply handling threads.
 */
static void rs_batch_dispatch(struct rs_batch *b)
{
	if (b->rsb_n_replies != 0) {
		struct ptlrpc_hr_thread	*hrt;

		hrt = ptlrpc_hr_select(b->rsb_svcpt);

		spin_lock(&hrt->hrt_lock);
		list_splice_init(&b->rsb_replies, &hrt->hrt_queue);
		spin_unlock(&hrt->hrt_lock);

		wake_up(&hrt->hrt_waitq);
		b->rsb_n_replies = 0;
	}
}

/**
 * rs_batch_add() - Add a reply to a batch.
 * @b: pointer to struct rs_batch where @rs will be added
 * @rs: pointer to ptlrpc_reply_state to be added to @b
 *
 * Add one reply object to a batch, schedule batched replies if overload.
 */
static void rs_batch_add(struct rs_batch *b, struct ptlrpc_reply_state *rs)
{
	struct ptlrpc_service_part *svcpt = rs->rs_svcpt;

	if (svcpt != b->rsb_svcpt || b->rsb_n_replies >= MAX_SCHEDULED) {
		if (b->rsb_svcpt != NULL) {
			rs_batch_dispatch(b);
			spin_unlock(&b->rsb_svcpt->scp_rep_lock);
		}
		spin_lock(&svcpt->scp_rep_lock);
		b->rsb_svcpt = svcpt;
	}
	spin_lock(&rs->rs_lock);
	rs->rs_scheduled_ever = 1;
	if (rs->rs_scheduled == 0) {
		list_move(&rs->rs_list, &b->rsb_replies);
		rs->rs_scheduled = 1;
		b->rsb_n_replies++;
	}
	rs->rs_committed = 1;
	spin_unlock(&rs->rs_lock);
}

/* Reply batch finalization. Dispatch remaining replies from the batch
 * and release remaining spinlock.
 */
static void rs_batch_fini(struct rs_batch *b)
{
	if (b->rsb_svcpt != NULL) {
		rs_batch_dispatch(b);
		spin_unlock(&b->rsb_svcpt->scp_rep_lock);
	}
}

#define DECLARE_RS_BATCH(b)     struct rs_batch b


/* Put reply state into a queue for processing because we received
 * ACK from the client
 */
void ptlrpc_dispatch_difficult_reply(struct ptlrpc_reply_state *rs)
{
	struct ptlrpc_hr_thread *hrt;

	ENTRY;

	LASSERT(list_empty(&rs->rs_list));

	hrt = ptlrpc_hr_select(rs->rs_svcpt);

	spin_lock(&hrt->hrt_lock);
	list_add_tail(&rs->rs_list, &hrt->hrt_queue);
	spin_unlock(&hrt->hrt_lock);

	wake_up(&hrt->hrt_waitq);
	EXIT;
}

void ptlrpc_schedule_difficult_reply(struct ptlrpc_reply_state *rs)
{
	ENTRY;

	assert_spin_locked(&rs->rs_svcpt->scp_rep_lock);
	assert_spin_locked(&rs->rs_lock);
	LASSERT(rs->rs_difficult);
	rs->rs_scheduled_ever = 1;  /* flag any notification attempt */

	if (rs->rs_scheduled) {     /* being set up or already notified */
		EXIT;
		return;
	}

	rs->rs_scheduled = 1;
	list_del_init(&rs->rs_list);
	ptlrpc_dispatch_difficult_reply(rs);
	EXIT;
}
EXPORT_SYMBOL(ptlrpc_schedule_difficult_reply);

void ptlrpc_commit_replies(struct obd_export *exp)
{
	struct ptlrpc_reply_state *rs, *nxt;
	DECLARE_RS_BATCH(batch);

	ENTRY;

	rs_batch_init(&batch);
	/*
	 * Find any replies that have been committed and get their service
	 * to attend to complete them.
	 */

	/* CAVEAT EMPTOR: spinlock ordering!!! */
	spin_lock(&exp->exp_uncommitted_replies_lock);
	list_for_each_entry_safe(rs, nxt, &exp->exp_uncommitted_replies,
				 rs_obd_list) {
		LASSERT(rs->rs_difficult);
		/* VBR: per-export last_committed */
		LASSERT(rs->rs_export);
		if (rs->rs_transno <= exp->exp_last_committed) {
			list_del_init(&rs->rs_obd_list);
			rs_batch_add(&batch, rs);
		}
	}
	spin_unlock(&exp->exp_uncommitted_replies_lock);
	rs_batch_fini(&batch);
	EXIT;
}

static int ptlrpc_server_post_idle_rqbds(struct ptlrpc_service_part *svcpt)
{
	struct ptlrpc_request_buffer_desc *rqbd;
	int rc;
	int posted = 0;

	for (;;) {
		spin_lock(&svcpt->scp_lock);

		if (list_empty(&svcpt->scp_rqbd_idle)) {
			spin_unlock(&svcpt->scp_lock);
			return posted;
		}

		rqbd = list_first_entry(&svcpt->scp_rqbd_idle,
					struct ptlrpc_request_buffer_desc,
					rqbd_list);

		/* assume we will post successfully */
		svcpt->scp_nrqbds_posted++;
		list_move(&rqbd->rqbd_list, &svcpt->scp_rqbd_posted);

		spin_unlock(&svcpt->scp_lock);

		rc = ptlrpc_register_rqbd(rqbd);
		if (rc != 0)
			break;

		posted = 1;
	}

	spin_lock(&svcpt->scp_lock);

	svcpt->scp_nrqbds_posted--;
	list_move_tail(&rqbd->rqbd_list, &svcpt->scp_rqbd_idle);

	/*
	 * Don't complain if no request buffers are posted right now; LNET
	 * won't drop requests because we set the portal lazy!
	 */

	spin_unlock(&svcpt->scp_lock);

	return -1;
}

static void ptlrpc_at_timer(cfs_timer_cb_arg_t data)
{
	struct ptlrpc_service_part *svcpt;

	svcpt = cfs_from_timer(svcpt, data, scp_at_timer);

	svcpt->scp_at_check = 1;
	svcpt->scp_at_checktime = ktime_get();
	wake_up(&svcpt->scp_waitq);
}

static void ptlrpc_server_nthreads_check(struct ptlrpc_service *svc,
					 struct ptlrpc_service_conf *conf)
{
	struct ptlrpc_service_thr_conf *tc = &conf->psc_thr;
	unsigned int init;
	unsigned int total;
	unsigned int nthrs;
	int weight;

	/*
	 * Common code for estimating & validating threads number.
	 * CPT affinity service could have percpt thread-pool instead
	 * of a global thread-pool, which means user might not always
	 * get the threads number they give it in conf::tc_nthrs_user
	 * even they did set. It's because we need to validate threads
	 * number for each CPT to guarantee each pool will have enough
	 * threads to keep the service healthy.
	 */
	init = PTLRPC_NTHRS_INIT + (svc->srv_ops.so_hpreq_handler != NULL);
	init = max_t(int, init, tc->tc_nthrs_init);

	/*
	 * NB: please see comments in lustre_lnet.h for definition
	 * details of these members
	 */
	LASSERT(tc->tc_nthrs_max != 0);

	if (tc->tc_nthrs_user != 0) {
		/*
		 * In case there is a reason to test a service with many
		 * threads, we give a less strict check here, it can
		 * be up to 8 * nthrs_max
		 */
		total = min(tc->tc_nthrs_max * 8, tc->tc_nthrs_user);
		nthrs = total / svc->srv_ncpts;
		init  = max(init, nthrs);
		goto out;
	}

	total = tc->tc_nthrs_max;
	if (tc->tc_nthrs_base == 0) {
		/*
		 * don't care about base threads number per partition,
		 * this is most for non-affinity service
		 */
		nthrs = total / svc->srv_ncpts;
		goto out;
	}

	nthrs = tc->tc_nthrs_base;
	if (svc->srv_ncpts == 1) {
		int	i;

		/*
		 * NB: Increase the base number if it's single partition
		 * and total number of cores/HTs is larger or equal to 4.
		 * result will always < 2 * nthrs_base
		 */
		weight = cfs_cpt_weight(svc->srv_cptable, CFS_CPT_ANY);
		for (i = 1; (weight >> (i + 1)) != 0 && /* >= 4 cores/HTs */
			    (tc->tc_nthrs_base >> i) != 0; i++)
			nthrs += tc->tc_nthrs_base >> i;
	}

	if (tc->tc_thr_factor != 0) {
		int	  factor = tc->tc_thr_factor;
		const int fade = 4;

		/*
		 * User wants to increase number of threads with for
		 * each CPU core/HT, most likely the factor is larger than
		 * one thread/core because service threads are supposed to
		 * be blocked by lock or wait for IO.
		 */
		/*
		 * Amdahl's law says that adding processors wouldn't give
		 * a linear increasing of parallelism, so it's nonsense to
		 * have too many threads no matter how many cores/HTs
		 * there are.
		 */
		preempt_disable();
		if (cpumask_weight
		    (topology_sibling_cpumask(smp_processor_id())) > 1) {
			/* weight is # of HTs */
			/* depress thread factor for hyper-thread */
			factor = factor - (factor >> 1) + (factor >> 3);
		}
		preempt_enable();

		weight = cfs_cpt_weight(svc->srv_cptable, 0);

		for (; factor > 0 && weight > 0; factor--, weight -= fade)
			nthrs += min(weight, fade) * factor;
	}

	if (nthrs * svc->srv_ncpts > tc->tc_nthrs_max) {
		nthrs = max(tc->tc_nthrs_base,
			    tc->tc_nthrs_max / svc->srv_ncpts);
	}
 out:
	nthrs = max(nthrs, tc->tc_nthrs_init);
	svc->srv_nthrs_cpt_limit = nthrs;
	svc->srv_nthrs_cpt_init = init;

	if (nthrs * svc->srv_ncpts > tc->tc_nthrs_max) {
		CDEBUG(D_OTHER,
		       "%s: This service may have more threads (%d) than the given soft limit (%d)\n",
		       svc->srv_name, nthrs * svc->srv_ncpts,
		       tc->tc_nthrs_max);
	}
}

/**
 * ptlrpc_service_part_init() - Initialize percpt data for a service
 * @svc: pointer to ptlrpc_service struct
 * @svcpt: pltrpc_service_part which is to get intialize
 * @cpt: CPU ID @svcpt will be tied to
 *
 * Returns:
 * * %0 on success
 * * %negative on failure
 */
static int ptlrpc_service_part_init(struct ptlrpc_service *svc,
				    struct ptlrpc_service_part *svcpt, int cpt)
{
	struct ptlrpc_at_array *array;
	int size;
	int index;
	int rc;

	svcpt->scp_cpt = cpt;
	INIT_LIST_HEAD(&svcpt->scp_threads);

	/* rqbd and incoming request queue */
	spin_lock_init(&svcpt->scp_lock);
	mutex_init(&svcpt->scp_mutex);
	INIT_LIST_HEAD(&svcpt->scp_rqbd_idle);
	INIT_LIST_HEAD(&svcpt->scp_rqbd_posted);
	INIT_LIST_HEAD(&svcpt->scp_req_incoming);
	init_waitqueue_head(&svcpt->scp_waitq);
	/* history request & rqbd list */
	INIT_LIST_HEAD(&svcpt->scp_hist_reqs);
	INIT_LIST_HEAD(&svcpt->scp_hist_rqbds);

	/* acitve requests and hp requests */
	spin_lock_init(&svcpt->scp_req_lock);

	/* reply states */
	spin_lock_init(&svcpt->scp_rep_lock);
	INIT_LIST_HEAD(&svcpt->scp_rep_active);
	INIT_LIST_HEAD(&svcpt->scp_rep_idle);
	init_waitqueue_head(&svcpt->scp_rep_waitq);
	atomic_set(&svcpt->scp_nreps_difficult, 0);

	/* adaptive timeout */
	spin_lock_init(&svcpt->scp_at_lock);
	array = &svcpt->scp_at_array;

	size = at_est2timeout(obd_get_at_max(NULL));
	array->paa_size     = size;
	array->paa_count    = 0;
	array->paa_deadline = -1;

	/* allocate memory for scp_at_array (ptlrpc_at_array) */
	OBD_CPT_ALLOC(array->paa_reqs_array,
		      svc->srv_cptable, cpt, sizeof(struct list_head) * size);
	if (array->paa_reqs_array == NULL)
		return -ENOMEM;

	for (index = 0; index < size; index++)
		INIT_LIST_HEAD(&array->paa_reqs_array[index]);

	OBD_CPT_ALLOC(array->paa_reqs_count,
		      svc->srv_cptable, cpt, sizeof(__u32) * size);
	if (array->paa_reqs_count == NULL)
		goto failed;

	cfs_timer_setup(&svcpt->scp_at_timer, ptlrpc_at_timer,
			(unsigned long)svcpt, 0);

	/*
	 * At SOW, service time should be quick; 10s seems generous. If client
	 * timeout is less than this, we'll be sending an early reply.
	 */
	at_init(&svcpt->scp_at_estimate, 10, 0);

	/* assign this before call ptlrpc_grow_req_bufs */
	svcpt->scp_service = svc;
	/* Now allocate the request buffers, but don't post them now */
	rc = ptlrpc_grow_req_bufs(svcpt, 0);
	/*
	 * We shouldn't be under memory pressure at startup, so
	 * fail if we can't allocate all our buffers at this time.
	 */
	if (rc != 0)
		goto failed;

	return 0;

 failed:
	if (array->paa_reqs_count != NULL) {
		OBD_FREE_PTR_ARRAY(array->paa_reqs_count, size);
		array->paa_reqs_count = NULL;
	}

	if (array->paa_reqs_array != NULL) {
		OBD_FREE_PTR_ARRAY(array->paa_reqs_array, array->paa_size);
		array->paa_reqs_array = NULL;
	}

	return -ENOMEM;
}

/**
 * ptlrpc_register_service() - Initialize service on a given portal (LNET)
 * @conf: pointer to ptlrpc_service_conf (configuration)
 * @parent: Parent directory under sysfs
 * @debugfs_entry: Parent directoy under debugfs
 *
 * This includes starting serving threads, allocating and posting rqbds and
 * so on.
 *
 * Return pointer to ptlrpc_service on Success else ERR_PTR on failure
 */
struct ptlrpc_service *ptlrpc_register_service(struct ptlrpc_service_conf *conf,
					       struct kset *parent,
					       struct dentry *debugfs_entry)
{
	struct ptlrpc_service_cpt_conf *cconf = &conf->psc_cpt;
	struct ptlrpc_service *service;
	struct ptlrpc_service_part *svcpt;
	struct cfs_cpt_table *cptable;
	char param[MAX_OBD_NAME * 4];
	u32 *cpts = NULL;
	int ncpts;
	int cpt;
	int rc;
	int i;

	ENTRY;

	LASSERT(conf->psc_buf.bc_nbufs > 0);
	LASSERT(conf->psc_buf.bc_buf_size >=
		conf->psc_buf.bc_req_max_size + SPTLRPC_MAX_PAYLOAD);
	LASSERT(conf->psc_thr.tc_ctx_tags != 0);

	cptable = cconf->cc_cptable;
	if (cptable == NULL)
		cptable = cfs_cpt_tab;

	if (conf->psc_thr.tc_cpu_bind > 1) {
		CERROR("%s: Invalid cpu bind value %d, only 1 or 0 allowed\n",
		       conf->psc_name, conf->psc_thr.tc_cpu_bind);
		RETURN(ERR_PTR(-EINVAL));
	}

	if (!cconf->cc_affinity) {
		ncpts = 1;
	} else {
		ncpts = cfs_cpt_number(cptable);
		if (cconf->cc_pattern != NULL) {
			struct cfs_expr_list	*el;

			rc = cfs_expr_list_parse(cconf->cc_pattern,
						 strlen(cconf->cc_pattern),
						 0, ncpts - 1, &el);
			if (rc != 0) {
				CERROR("%s: invalid CPT pattern string: %s\n",
				       conf->psc_name, cconf->cc_pattern);
				RETURN(ERR_PTR(-EINVAL));
			}

			rc = cfs_expr_list_values(el, ncpts, &cpts);
			cfs_expr_list_free(el);
			if (rc <= 0) {
				CERROR("%s: failed to parse CPT array %s: %d\n",
				       conf->psc_name, cconf->cc_pattern, rc);
				RETURN(ERR_PTR(rc < 0 ? rc : -EINVAL));
			}
			ncpts = rc;
		}
	}

	OBD_ALLOC(service, offsetof(struct ptlrpc_service, srv_parts[ncpts]));
	if (service == NULL) {
		if (cpts != NULL)
			cfs_expr_list_values_free(cpts, ncpts);
		RETURN(ERR_PTR(-ENOMEM));
	}

	service->srv_cptable		= cptable;
	service->srv_cpts		= cpts;
	service->srv_ncpts		= ncpts;
	service->srv_cpt_bind		= conf->psc_thr.tc_cpu_bind;

	service->srv_cpt_bits = 0; /* it's zero already, easy to read... */
	while ((1 << service->srv_cpt_bits) < cfs_cpt_number(cptable))
		service->srv_cpt_bits++;

	/* public members */
	spin_lock_init(&service->srv_lock);
	service->srv_name		= conf->psc_name;
	service->srv_watchdog_factor	= conf->psc_watchdog_factor;
	INIT_LIST_HEAD(&service->srv_list); /* for safty of cleanup */

	/* buffer configuration */
	service->srv_nbuf_per_group	= test_req_buffer_pressure ?
					  1 : conf->psc_buf.bc_nbufs;
	/* do not limit max number of rqbds by default */
	service->srv_nrqbds_max		= 0;

	service->srv_max_req_size	= conf->psc_buf.bc_req_max_size +
					  SPTLRPC_MAX_PAYLOAD;
	service->srv_buf_size		= conf->psc_buf.bc_buf_size;
	service->srv_rep_portal		= conf->psc_buf.bc_rep_portal;
	service->srv_req_portal		= conf->psc_buf.bc_req_portal;

	/* With slab/alloc_pages buffer size will be rounded up to 2^n */
	if (service->srv_buf_size & (service->srv_buf_size - 1)) {
		int round = size_roundup_power2(service->srv_buf_size);

		service->srv_buf_size = round;
	}

	/* Increase max reply size to next power of two */
	service->srv_max_reply_size = 1;
	while (service->srv_max_reply_size <
	       conf->psc_buf.bc_rep_max_size + SPTLRPC_MAX_PAYLOAD)
		service->srv_max_reply_size <<= 1;

	service->srv_thread_name	= conf->psc_thr.tc_thr_name;
	service->srv_ctx_tags		= conf->psc_thr.tc_ctx_tags;
	service->srv_hpreq_ratio	= PTLRPC_SVC_HP_RATIO;
	service->srv_ops		= conf->psc_ops;

	for (i = 0; i < ncpts; i++) {
		if (!cconf->cc_affinity)
			cpt = CFS_CPT_ANY;
		else
			cpt = cpts != NULL ? cpts[i] : i;

		OBD_CPT_ALLOC(svcpt, cptable, cpt, sizeof(*svcpt));
		if (svcpt == NULL)
			GOTO(failed, rc = -ENOMEM);

		service->srv_parts[i] = svcpt;
		rc = ptlrpc_service_part_init(service, svcpt, cpt);
		if (rc != 0)
			GOTO(failed, rc);
	}

	ptlrpc_server_nthreads_check(service, conf);

	rc = LNetSetLazyPortal(service->srv_req_portal);
	LASSERT(rc == 0);

	mutex_lock(&ptlrpc_all_services_mutex);
	list_add(&service->srv_list, &ptlrpc_all_services);
	mutex_unlock(&ptlrpc_all_services_mutex);

	if (parent) {
		char *path, *tmp;

		rc = ptlrpc_sysfs_register_service(parent, service);
		if (rc)
			GOTO(failed, rc);

		path = kobject_get_path(&parent->kobj, GFP_KERNEL);
		if (path) {
			tmp = path + strlen("/fs/lustre/");
			scnprintf(param, sizeof(param), "%s.%s.stats",
				  tmp, service->srv_name);
			tmp = param;
			while ((tmp = strchr(tmp, '/')) != NULL)
				*tmp = '.';
		}
	}

	ptlrpc_ldebugfs_register_service(debugfs_entry, param, service);

	rc = ptlrpc_service_nrs_setup(service);
	if (rc != 0)
		GOTO(failed, rc);

	CDEBUG(D_NET, "%s: Started, listening on portal %d\n",
	       service->srv_name, service->srv_req_portal);

	rc = ptlrpc_start_threads(service);
	if (rc != 0) {
		CERROR("Failed to start threads for service %s: %d\n",
		       service->srv_name, rc);
		GOTO(failed, rc);
	}

	RETURN(service);
failed:
	ptlrpc_unregister_service(service);
	RETURN(ERR_PTR(rc));
}
EXPORT_SYMBOL(ptlrpc_register_service);

/**
 * ptlrpc_server_free_request() - free the request
 * @req: ptlrpc request
 *
 * Actually free the request, must be called without holding svc_lock.
 * note it's caller's responsibility to unlink req->rq_list.
 */
static void ptlrpc_server_free_request(struct ptlrpc_request *req)
{
	LASSERT(atomic_read(&req->rq_refcount) == 0);
	LASSERT(list_empty(&req->rq_timed_list));

	/*
	 * DEBUG_REQ() assumes the reply state of a request with a valid
	 * ref will not be destroyed until that reference is dropped.
	 */
	ptlrpc_req_drop_rs(req);

	sptlrpc_svc_ctx_decref(req);

	if (req != &req->rq_rqbd->rqbd_req) {
		/*
		 * NB request buffers use an embedded
		 * req if the incoming req unlinked the
		 * MD; this isn't one of them!
		 */
		ptlrpc_request_cache_free(req);
	}
}

/**
 * ptlrpc_server_drop_request() - drop a reference count of the request
 * @req: pltrpc request
 *
 * drop a reference count of the request. if it reaches 0, we either
 * put it into history list, or free it immediately.
 */
void ptlrpc_server_drop_request(struct ptlrpc_request *req)
{
	struct ptlrpc_request_buffer_desc *rqbd = req->rq_rqbd;
	struct ptlrpc_service_part	  *svcpt = rqbd->rqbd_svcpt;
	struct ptlrpc_service		  *svc = svcpt->scp_service;
	int				   refcount;

	if (!atomic_dec_and_test(&req->rq_refcount))
		return;

	if (req->rq_session.lc_state == LCS_ENTERED) {
		lu_context_exit(&req->rq_session);
		lu_context_fini(&req->rq_session);
	}

	if (req->rq_at_linked) {
		spin_lock(&svcpt->scp_at_lock);
		/*
		 * recheck with lock, in case it's unlinked by
		 * ptlrpc_at_check_timed()
		 */
		if (likely(req->rq_at_linked))
			ptlrpc_at_remove_timed(req);
		spin_unlock(&svcpt->scp_at_lock);
	}

	LASSERT(list_empty(&req->rq_timed_list));

	/* finalize request */
	if (req->rq_export) {
		class_export_put(req->rq_export);
		req->rq_export = NULL;
	}

	spin_lock(&svcpt->scp_lock);

	list_add(&req->rq_list, &rqbd->rqbd_reqs);

	refcount = --(rqbd->rqbd_refcount);
	if (refcount == 0) {
		/* request buffer is now idle: add to history */
		list_move_tail(&rqbd->rqbd_list, &svcpt->scp_hist_rqbds);
		svcpt->scp_hist_nrqbds++;

		/*
		 * cull some history?
		 * I expect only about 1 or 2 rqbds need to be recycled here
		 */
		while (svcpt->scp_hist_nrqbds > svc->srv_hist_nrqbds_cpt_max) {
			rqbd = list_first_entry(&svcpt->scp_hist_rqbds,
						struct ptlrpc_request_buffer_desc,
						rqbd_list);

			list_del(&rqbd->rqbd_list);
			svcpt->scp_hist_nrqbds--;

			/*
			 * remove rqbd's reqs from svc's req history while
			 * I've got the service lock
			 */
			list_for_each_entry(req, &rqbd->rqbd_reqs, rq_list) {
				/* Track the highest culled req seq */
				if (req->rq_history_seq >
				    svcpt->scp_hist_seq_culled) {
					svcpt->scp_hist_seq_culled =
						req->rq_history_seq;
				}
				list_del(&req->rq_history_list);
			}

			spin_unlock(&svcpt->scp_lock);

			while ((req = list_first_entry_or_null(
					&rqbd->rqbd_reqs,
					struct ptlrpc_request, rq_list))) {
				list_del(&req->rq_list);
				ptlrpc_server_free_request(req);
			}

			spin_lock(&svcpt->scp_lock);
			/*
			 * now all reqs including the embedded req has been
			 * disposed, schedule request buffer for re-use
			 * or free it to drain some in excess.
			 */
			LASSERT(atomic_read(&rqbd->rqbd_req.rq_refcount) == 0);
			if (svcpt->scp_nrqbds_posted >=
			    svc->srv_nbuf_per_group ||
			    (svc->srv_nrqbds_max != 0 &&
			     svcpt->scp_nrqbds_total > svc->srv_nrqbds_max) ||
			    test_req_buffer_pressure) {
				/* like in ptlrpc_free_rqbd() */
				svcpt->scp_nrqbds_total--;
				OBD_FREE_LARGE(rqbd->rqbd_buffer,
					       svc->srv_buf_size);
				OBD_FREE_PTR(rqbd);
			} else {
				list_add_tail(&rqbd->rqbd_list,
					      &svcpt->scp_rqbd_idle);
			}
		}

		spin_unlock(&svcpt->scp_lock);
	} else if (req->rq_reply_state && req->rq_reply_state->rs_prealloc) {
		/* If we are low on memory, we are not interested in history */
		list_del(&req->rq_list);
		list_del_init(&req->rq_history_list);

		/* Track the highest culled req seq */
		if (req->rq_history_seq > svcpt->scp_hist_seq_culled)
			svcpt->scp_hist_seq_culled = req->rq_history_seq;

		spin_unlock(&svcpt->scp_lock);

		ptlrpc_server_free_request(req);
	} else {
		spin_unlock(&svcpt->scp_lock);
	}
}

static void ptlrpc_add_exp_list_nolock(struct ptlrpc_request *req,
				       struct obd_export *export, bool hp)
{
	__u16 tag = lustre_msg_get_tag(req->rq_reqmsg);

	if (hp)
		list_add(&req->rq_exp_list, &export->exp_hp_rpcs);
	else
		list_add(&req->rq_exp_list, &export->exp_reg_rpcs);
	if (tag && export->exp_used_slots)
		set_bit(tag - 1, export->exp_used_slots);
}

void ptlrpc_del_exp_list(struct ptlrpc_request *req)
{
	__u16 tag = 0;

	if (unlikely(!req->rq_export))
		return;
	if (likely(req->rq_reqmsg))
		tag = lustre_msg_get_tag(req->rq_reqmsg);

	spin_lock(&req->rq_export->exp_rpc_lock);
	list_del_init(&req->rq_exp_list);
	if (tag && !req->rq_obsolete && req->rq_export->exp_used_slots)
		clear_bit(tag - 1, req->rq_export->exp_used_slots);
	spin_unlock(&req->rq_export->exp_rpc_lock);
}

/**
 * ptlrpc_request_change_export() - Change request export
 * @req: ptlrpc request export to be changed
 * @export: new export @req is changed to
 *
 * Change request export and move hp request from old export to new
 */
void ptlrpc_request_change_export(struct ptlrpc_request *req,
				  struct obd_export *export)
{
	if (req->rq_export != NULL) {
		LASSERT(!list_empty(&req->rq_exp_list));
		/* remove rq_exp_list from last export */
		ptlrpc_del_exp_list(req);
		/* export has one reference already, so it's safe to
		 * add req to export queue here and get another
		 * reference for request later
		 */
		spin_lock(&export->exp_rpc_lock);
		ptlrpc_add_exp_list_nolock(req, export, req->rq_ops != NULL);
		spin_unlock(&export->exp_rpc_lock);

		class_export_rpc_dec(req->rq_export);
		class_export_put(req->rq_export);
	}

	/* request takes one export refcount */
	req->rq_export = class_export_get(export);
	class_export_rpc_inc(export);
}

/* to finish a request: stop sending more early replies, and release
 * the request.
 */
static void ptlrpc_server_finish_request(struct ptlrpc_service_part *svcpt,
					 struct ptlrpc_request *req)
{
	ptlrpc_server_hpreq_fini(req);

	ptlrpc_server_drop_request(req);
}

/* to finish an active request: stop sending more early replies, and release
 * the request. should be called after we finished handling the request.
 */
static void ptlrpc_server_finish_active_request(
					struct ptlrpc_service_part *svcpt,
					struct ptlrpc_request *req)
{
	spin_lock(&svcpt->scp_req_lock);
	ptlrpc_nrs_req_stop_nolock(req);
	svcpt->scp_nreqs_active--;
	if (req->rq_hp)
		svcpt->scp_nhreqs_active--;
	spin_unlock(&svcpt->scp_req_lock);

	ptlrpc_nrs_req_finalize(req);

	if (req->rq_export != NULL)
		class_export_rpc_dec(req->rq_export);

	ptlrpc_server_finish_request(svcpt, req);
}

/**
 * ptlrpc_export_timeout() - Calcuate an export eviction timeout
 * @obd: export to calucalte the timout of
 * @at: AT of RPC service time to calculate timeout for
 * @netl: network AT
 * @rpc_left_time: left service time for the current RPC 0 if not applicable
 * @pinger: if the caller is ping evictor or ldlm
 *
 * Calculate an export eviction timeout.
 * Used for both cases, lock prolong timeout and ping evictor timeout.
 *
 * Whereas a problem client may be still alive trying hard to reconnect and to
 * resend its RPCs, we should not consider the worst ever case, consisting of
 * a chain of failures on each step. Let this timeout survive a recovery of
 * just 1 failure:
 * - an RPC timeout;
 * - a re-connect success;
 *
 * For lock prolong timeout, we are in the middle of the process -
 * BL AST is sent, CANCEL is ahead - it is still 1 reply for the current RPC
 * and at least 1 another RPC (which will trigger another refresh if it will be
 * not CANCEL) - but more accurate than ldlm_bl_timeout as the timeout is taken
 * from the RPC (i.e. the view of the client on the current AT) is taken into
 * account.
 *
 * Return timeout in seconds to wait for the next client's RPC
 */
static timeout_t ptlrpc_export_timeout(struct obd_device *obd,
				       struct adaptive_timeout *at,
				       timeout_t netl,
				       timeout_t rpc_left_time,
				       bool pinger)
{
	timeout_t timeout, at_timeout, req_timeout;

	if (obd_at_off(obd))
		return obd_timeout / 2;

	LASSERT(at != NULL);
	at_timeout = at_est2timeout(obd_at_get(obd, at)) + netl;

	if (pinger) {
		/* There might be a delay till the next RPC. In fact it is two
		 * PING_INTERVALs due to ptlrpc_pinger_main logic.
		 * In addition, the ping itself may time out, but no resend will
		 * be needed, export is updated on re-connect */
		timeout = 2 * PING_INTERVAL + at_timeout;
	} else {
		/* For the lock prolong, we have an RPC in hand, which may still
		 * get its reply lost. Thus, it may be either this one or the
		 * next client's RPC times out, take the max.
		 * Considering the current RPC, take just the left time. */
		req_timeout = max(rpc_left_time + (netl >> 1), at_timeout);
		/* Adding the RPC resend time */
		timeout = req_timeout + at_timeout;
	}

	/* Adding the re-connect time */
	timeout += INITIAL_CONNECT_TIMEOUT + netl;

	/* Let's be a bit more conservative than client */
	return max(timeout + (timeout >> 4),
		   (timeout_t)obd_get_ldlm_enqueue_min(obd));
}

/**
 * ptlrpc_export_prolong_timeout() - Used for lock prolog timeout
 * @req: ptlrpc request
 * @recovery: True if this is recovery
 *
 * Used for lock prolog timeout, calculates a timeout for CANCEL to come.
 * Also used for recovery, calculates a timeout for a next recovery RPC to come.
 * In this case, there is an RPC, in hand. Thus, a particular svcpt AT is used.
 *
 * The reverse import network AT is used as an estimate for the client side one.
 *
 * Returns timeout value (seconds)
 */
timeout_t ptlrpc_export_prolong_timeout(struct ptlrpc_request *req,
					bool recovery)
{
	timeout_t netl;

	if (recovery)
		netl = lustre_msg_get_service_timeout(req->rq_reqmsg);
	else
		netl = obd_at_get(req->rq_export->exp_obd,
				  &req->rq_export->exp_imp_reverse->
				  imp_at.iat_net_latency);

	return ptlrpc_export_timeout(req->rq_export->exp_obd,
				     &req->rq_rqbd->rqbd_svcpt->scp_at_estimate,
				     netl, req->rq_deadline -
				     ktime_get_real_seconds(), false);
}

/*
 * Used for ping evictor, calculates a timeout for any next RPC to come.
 * As there are different portals and the AT stats is separated for them,
 * just the last RPC AT is used here.
 *
 * The reverse import network AT is used as an estimate for the client side one.
 */
static timeout_t ptlrpc_export_pinger_timeout(struct ptlrpc_request *req)
{
	struct obd_import *revimp = req->rq_export->exp_imp_reverse;
	timeout_t netl = obd_at_get(req->rq_export->exp_obd,
				    &revimp->imp_at.iat_net_latency);

	return ptlrpc_export_timeout(req->rq_export->exp_obd,
				     &req->rq_rqbd->rqbd_svcpt->scp_at_estimate,
				     netl, 0, true);
}

/*
 * In this case the net was down and just came back, when the 1st timeout has
 * been already expired, clients just keep sending re-connects, switching
 * between different connections, thus what is to be covered:
 * - a previous reconnect to not yet recovered network, times out;
 * - the second reconnect to the failover pair, ENODEV;
 * - the third reconnect succeeds;
 */
static timeout_t ptlrpc_export_extra_timeout(struct obd_export *exp)
{
	timeout_t netl, tout;

	/* As this is not the 1st re-connection failure, the client might
	 * have net latency get extended to the max - CONNECTION_SWITCH_MAX */
	netl = obd_at_get(exp->exp_obd,
			  &exp->exp_imp_reverse->imp_at.iat_net_latency);
	tout = 3 * (INITIAL_CONNECT_TIMEOUT +
		    max((timeout_t)CONNECTION_SWITCH_MAX, netl));

	/* Let's be a bit more conservative than client */
	return tout + (tout >> 4);
}

/*
 * This function makes sure dead exports are evicted in a timely manner.
 * This function is only called when some export receives a message (i.e.,
 * the network is up.)
 */
void ptlrpc_update_export_timer(struct ptlrpc_request *req)
{
	struct obd_export *oldest_exp, *newest_exp, *exp;
	time64_t current_time, timeout;
	bool evict = false;
	void *data;
	int rc;
	ENTRY;

	LASSERT(req != NULL);
	LASSERT(req->rq_export != NULL);

	exp = req->rq_export;
	current_time = ktime_get_real_seconds();

	rc = obd_export_timed_init(exp, &data);
	if (rc)
		/* will be updated next time */
		RETURN_EXIT;

	/*
	 * exports may get disconnected from the chain even though the
	 * export has references, so we must keep the spin lock while
	 * manipulating the lists
	 */
	spin_lock(&exp->exp_obd->obd_dev_lock);
	if (list_empty(&exp->exp_timed_chain)) {
		/* this one is not timed */
		spin_unlock(&exp->exp_obd->obd_dev_lock);
		GOTO(err, 0);
	}

	exp->exp_last_request_time = current_time;

	timeout = ptlrpc_export_pinger_timeout(req);

	/* Do not pay attention on 1sec or smaller renewals. */
	if (exp->exp_deadline + 1 >= current_time + timeout) {
		spin_unlock(&exp->exp_obd->obd_dev_lock);
		GOTO(err, 0);
	}

	newest_exp = obd_export_timed_get(exp->exp_obd, true);
	obd_export_timed_del(exp);
	exp->exp_deadline = current_time + timeout;
	obd_export_timed_add(exp, &data);

	if (test_bit(OBDF_RECOVERING, exp->exp_obd->obd_flags)) {
		/* be nice to everyone during recovery */
		spin_unlock(&exp->exp_obd->obd_dev_lock);
		GOTO(err, 0);
	}
	oldest_exp = obd_export_timed_get(exp->exp_obd, false);

	/* Check if the oldest entry is expired. */
	if (exp->exp_obd->obd_eviction_timer == 0) {
		if (current_time > oldest_exp->exp_deadline) {
			timeout = newest_exp->exp_last_request_time +
				((newest_exp->exp_deadline -
				  newest_exp->exp_last_request_time) >> 1);
			if (current_time < timeout) {
				/* If import is active - evict stale clients */
				evict = true;
			} else {
				/*
				 * We need a second timer, in case the net was
				 * down and it just came back.
				 */
				exp->exp_obd->obd_eviction_timer =
					ktime_get_real_seconds() +
					ptlrpc_export_extra_timeout(oldest_exp);
				CDEBUG(D_HA, "%s: Think about evicting %s "
				       "from %lld deadline at %lld\n",
				       exp->exp_obd->obd_name,
				       obd_export_nid2str(oldest_exp),
				       oldest_exp->exp_deadline,
				       exp->exp_obd->obd_eviction_timer);
			}
		}
	}
	spin_unlock(&exp->exp_obd->obd_dev_lock);

	if (evict) {
		/* Evict stale clients */
		ping_evictor_wake(exp);
	} else {
		if (ktime_get_real_seconds() >
		    exp->exp_obd->obd_eviction_timer) {
			/*
			 * The evictor won't evict anyone who we've heard from
			 * recently, so we don't have to check before we start
			 * it.
			 */
			if (!ping_evictor_wake(exp))
				exp->exp_obd->obd_eviction_timer = 0;
		}
	}

	EXIT;
err:
	obd_export_timed_fini(exp, &data);
}

/**
 * ptlrpc_check_req() - Sanity check request @req.
 * @req: ptlrpc request
 *
 * Return 0 if all is ok, error code otherwise.
 */
static int ptlrpc_check_req(struct ptlrpc_request *req)
{
	struct obd_device *obd = req->rq_export->exp_obd;
	int rc = 0;

	if (unlikely(lustre_msg_get_conn_cnt(req->rq_reqmsg) <
		     req->rq_export->exp_conn_cnt)) {
		DEBUG_REQ(D_RPCTRACE, req,
			  "DROPPING req from old connection %d < %d",
			  lustre_msg_get_conn_cnt(req->rq_reqmsg),
			  req->rq_export->exp_conn_cnt);
		return -EEXIST;
	}
	if (unlikely(obd == NULL || obd->obd_fail)) {
		/*
		 * Failing over, don't handle any more reqs,
		 * send error response instead.
		 */
		CDEBUG(D_RPCTRACE, "Dropping req %p for failed obd %s\n",
			req, (obd != NULL) ? obd->obd_name : "unknown");
		rc = -ENODEV;
	} else if (lustre_msg_get_flags(req->rq_reqmsg) &
		   (MSG_REPLAY | MSG_REQ_REPLAY_DONE) &&
		   !test_bit(OBDF_RECOVERING, obd->obd_flags)) {
		DEBUG_REQ(D_ERROR, req,
			  "Invalid replay without recovery");
		class_fail_export(req->rq_export);
		rc = -ENODEV;
	} else if (lustre_msg_get_transno(req->rq_reqmsg) != 0 &&
		   !test_bit(OBDF_RECOVERING, obd->obd_flags)) {
		DEBUG_REQ(D_ERROR, req,
			  "Invalid req with transno %llu without recovery",
			  lustre_msg_get_transno(req->rq_reqmsg));
		class_fail_export(req->rq_export);
		rc = -ENODEV;
	}

	if (unlikely(rc < 0)) {
		req->rq_status = rc;
		ptlrpc_error(req);
	}
	return rc;
}

static void ptlrpc_at_set_timer(struct ptlrpc_service_part *svcpt)
{
	struct ptlrpc_at_array *array = &svcpt->scp_at_array;
	time64_t next;

	if (array->paa_count == 0) {
		timer_delete(&svcpt->scp_at_timer);
		return;
	}

	/* Set timer for closest deadline */
	next = array->paa_deadline - ktime_get_real_seconds() -
	       at_early_margin;
	if (next <= 0) {
		ptlrpc_at_timer(cfs_timer_cb_arg(svcpt, scp_at_timer));
	} else {
		mod_timer(&svcpt->scp_at_timer,
			  jiffies + nsecs_to_jiffies(next * NSEC_PER_SEC));
		CDEBUG(D_INFO, "armed %s at %+llds\n",
		       svcpt->scp_service->srv_name, next);
	}
}

/* Add rpc to early reply check list */
static int ptlrpc_at_add_timed(struct ptlrpc_request *req)
{
	struct ptlrpc_service_part *svcpt = req->rq_rqbd->rqbd_svcpt;
	struct ptlrpc_at_array *array = &svcpt->scp_at_array;
	struct ptlrpc_request *rq = NULL;
	__u32 index;
	struct obd_device *obd = NULL;

	if (req->rq_export)
		obd = req->rq_export->exp_obd;

	if (obd_at_off(obd))
		return(0);

	if (req->rq_no_reply)
		return 0;

	if ((lustre_msghdr_get_flags(req->rq_reqmsg) & MSGHDR_AT_SUPPORT) == 0)
		return(-ENOSYS);

	spin_lock(&svcpt->scp_at_lock);
	LASSERT(list_empty(&req->rq_timed_list));

	div_u64_rem(req->rq_deadline, array->paa_size, &index);
	if (array->paa_reqs_count[index] > 0) {
		/*
		 * latest rpcs will have the latest deadlines in the list,
		 * so search backward.
		 */
		list_for_each_entry_reverse(rq, &array->paa_reqs_array[index],
					    rq_timed_list) {
			if (req->rq_deadline >= rq->rq_deadline) {
				list_add(&req->rq_timed_list,
					 &rq->rq_timed_list);
				break;
			}
		}
	}

	/* Add the request at the head of the list */
	if (list_empty(&req->rq_timed_list))
		list_add(&req->rq_timed_list, &array->paa_reqs_array[index]);

	spin_lock(&req->rq_lock);
	req->rq_at_linked = 1;
	spin_unlock(&req->rq_lock);
	req->rq_at_index = index;
	array->paa_reqs_count[index]++;
	array->paa_count++;
	if (array->paa_count == 1 || array->paa_deadline > req->rq_deadline) {
		array->paa_deadline = req->rq_deadline;
		ptlrpc_at_set_timer(svcpt);
	}
	spin_unlock(&svcpt->scp_at_lock);

	return 0;
}

static void ptlrpc_at_remove_timed(struct ptlrpc_request *req)
{
	struct ptlrpc_at_array *array;

	array = &req->rq_rqbd->rqbd_svcpt->scp_at_array;

	/* NB: must call with hold svcpt::scp_at_lock */
	LASSERT(!list_empty(&req->rq_timed_list));
	list_del_init(&req->rq_timed_list);

	spin_lock(&req->rq_lock);
	req->rq_at_linked = 0;
	spin_unlock(&req->rq_lock);

	array->paa_reqs_count[req->rq_at_index]--;
	array->paa_count--;
}

/* Attempt to extend the request deadline by sending an early reply to the
 * client.
 */
static int ptlrpc_at_send_early_reply(struct ptlrpc_request *req)
{
	struct ptlrpc_service_part *svcpt = req->rq_rqbd->rqbd_svcpt;
	struct ptlrpc_request *reqcopy;
	struct lustre_msg *reqmsg;
	timeout_t olddl = req->rq_deadline - ktime_get_real_seconds();
	time64_t newdl;
	int rc;
	struct obd_device *obd = NULL;

	ENTRY;

	if (req->rq_export)
		obd = req->rq_export->exp_obd;

	if (CFS_FAIL_CHECK(OBD_FAIL_TGT_REPLAY_RECONNECT) ||
	    CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_ENQ_RESEND)) {
		/* don't send early reply */
		RETURN(1);
	}

	/*
	 * deadline is when the client expects us to reply, margin is the
	 * difference between clients' and servers' expectations
	 */
	DEBUG_REQ(D_ADAPTTO, req,
		  "%ssending early reply (deadline %+ds, margin %+ds) for %d+%d",
		  obd_at_off(obd) ? "AT off - not " : "",
		  olddl, olddl - obd_at_get(obd, &svcpt->scp_at_estimate),
		  obd_at_get(obd, &svcpt->scp_at_estimate), at_extra);

	if (obd_at_off(obd))
		RETURN(0);

	if (olddl < 0) {
		/* below message is checked in replay-ost-single.sh test_9 */
		DEBUG_REQ(D_WARNING, req,
			  "Already past deadline (%+ds), not sending early reply. Consider increasing at_early_margin (%d)?",
			  olddl, at_early_margin);

		/* Return an error so we're not re-added to the timed list. */
		RETURN(-ETIMEDOUT);
	}

	if ((lustre_msghdr_get_flags(req->rq_reqmsg) &
	     MSGHDR_AT_SUPPORT) == 0) {
		DEBUG_REQ(D_INFO, req,
			  "Wanted to ask client for more time, but no AT support");
		RETURN(-ENOSYS);
	}

	if (req->rq_export &&
	    lustre_msg_get_flags(req->rq_reqmsg) &
	    (MSG_REPLAY | MSG_REQ_REPLAY_DONE | MSG_LOCK_REPLAY_DONE)) {
		struct obd_device *obd_exp = req->rq_export->exp_obd;

		/*
		 * During recovery, we don't want to send too many early
		 * replies, but on the other hand we want to make sure the
		 * client has enough time to resend if the rpc is lost. So
		 * during the recovery period send at least 4 early replies,
		 * spacing them every at_extra if we can. at_estimate should
		 * always equal this fixed value during recovery.
		 */

		/*
		 * Don't account request processing time into AT history
		 * during recovery, it is not service time we need but
		 * includes also waiting time for recovering clients
		 */
		newdl = min_t(time64_t, at_extra,
			      obd_exp->obd_recovery_timeout / 4) +
			ktime_get_real_seconds();
	} else {
		/*
		 * We want to extend the request deadline by at_extra seconds,
		 * so we set our service estimate to reflect how much time has
		 * passed since this request arrived plus an additional
		 * at_extra seconds. The client will calculate the new deadline
		 * based on this service estimate (plus some additional time to
		 * account for network latency). See ptlrpc_at_recv_early_reply
		 */
		obd_at_measure(obd, &svcpt->scp_at_estimate, at_extra +
			    ktime_get_real_seconds() -
			    req->rq_arrival_time.tv_sec);
		newdl = req->rq_arrival_time.tv_sec +
			obd_at_get(obd, &svcpt->scp_at_estimate);
	}

	/*
	 * Check to see if we've actually increased the deadline -
	 * we may be past adaptive_max
	 */
	if (req->rq_deadline >= newdl) {
		DEBUG_REQ(D_WARNING, req,
			  "Could not add any time (%d/%lld), not sending early reply",
			  olddl, newdl - ktime_get_real_seconds());
		RETURN(-ETIMEDOUT);
	}

	reqcopy = ptlrpc_request_cache_alloc(GFP_NOFS);
	if (reqcopy == NULL)
		RETURN(-ENOMEM);
	OBD_ALLOC_LARGE(reqmsg, req->rq_reqlen);
	if (!reqmsg)
		GOTO(out_free, rc = -ENOMEM);

	*reqcopy = *req;
	spin_lock_init(&reqcopy->rq_early_free_lock);
	reqcopy->rq_reply_state = NULL;
	reqcopy->rq_rep_swab_mask = 0;
	reqcopy->rq_pack_bulk = 0;
	reqcopy->rq_pack_udesc = 0;
	reqcopy->rq_packed_final = 0;
	sptlrpc_svc_ctx_addref(reqcopy);
	/* We only need the reqmsg for the magic */
	reqcopy->rq_reqmsg = reqmsg;
	memcpy(reqmsg, req->rq_reqmsg, req->rq_reqlen);

	/*
	 * tgt_brw_read() and tgt_brw_write() may have decided not to reply.
	 * Without this check, we would fail the rq_no_reply assertion in
	 * ptlrpc_send_reply().
	 */
	if (reqcopy->rq_no_reply)
		GOTO(out, rc = -ETIMEDOUT);

	LASSERT(atomic_read(&req->rq_refcount));
	/* if it is last refcount then early reply isn't needed */
	if (atomic_read(&req->rq_refcount) == 1) {
		DEBUG_REQ(D_ADAPTTO, reqcopy,
			  "Normal reply already sent, abort early reply");
		GOTO(out, rc = -EINVAL);
	}

	/* Connection ref */
	reqcopy->rq_export = class_conn2export(
			lustre_msg_get_handle(reqcopy->rq_reqmsg));
	if (reqcopy->rq_export == NULL)
		GOTO(out, rc = -ENODEV);
	INIT_LIST_HEAD(&reqcopy->rq_exp_list);

	/* RPC ref */
	class_export_rpc_inc(reqcopy->rq_export);
	if (reqcopy->rq_export->exp_obd &&
	    reqcopy->rq_export->exp_obd->obd_fail)
		GOTO(out_put, rc = -ENODEV);

	rc = lustre_pack_reply_flags(reqcopy, 1, NULL, NULL, LPRFL_EARLY_REPLY);
	if (rc)
		GOTO(out_put, rc);

	rc = ptlrpc_send_reply(reqcopy, PTLRPC_REPLY_EARLY);

	if (!rc) {
		/* Adjust our own deadline to what we told the client */
		req->rq_deadline = newdl;
		req->rq_early_count++; /* number sent, server side */
	} else {
		DEBUG_REQ(D_ERROR, req, "Early reply send failed: rc = %d", rc);
	}

	/*
	 * Free the (early) reply state from lustre_pack_reply.
	 * (ptlrpc_send_reply takes it's own rs ref, so this is safe here)
	 */
	ptlrpc_req_drop_rs(reqcopy);

out_put:
	class_export_rpc_dec(reqcopy->rq_export);
	class_export_put(reqcopy->rq_export);
out:
	sptlrpc_svc_ctx_decref(reqcopy);
	OBD_FREE_LARGE(reqmsg, req->rq_reqlen);
out_free:
	ptlrpc_request_cache_free(reqcopy);
	RETURN(rc);
}

/*
 * Send early replies to everybody expiring within at_early_margin
 * asking for at_extra time
 */
static int ptlrpc_at_check_timed(struct ptlrpc_service_part *svcpt)
{
	struct ptlrpc_at_array *array = &svcpt->scp_at_array;
	struct ptlrpc_request *rq, *n;
	LIST_HEAD(work_list);
	__u32 index, count;
	time64_t deadline;
	time64_t now = ktime_get_real_seconds();
	s64 delay_ms;
	int first, counter = 0;

	ENTRY;
	spin_lock(&svcpt->scp_at_lock);
	if (svcpt->scp_at_check == 0) {
		spin_unlock(&svcpt->scp_at_lock);
		RETURN(0);
	}
	delay_ms = ktime_ms_delta(ktime_get(), svcpt->scp_at_checktime);
	svcpt->scp_at_check = 0;

	if (array->paa_count == 0) {
		spin_unlock(&svcpt->scp_at_lock);
		RETURN(0);
	}

	/* The timer went off, but maybe the nearest rpc already completed. */
	first = array->paa_deadline - now;
	if (first > at_early_margin) {
		/* We've still got plenty of time.  Reset the timer. */
		ptlrpc_at_set_timer(svcpt);
		spin_unlock(&svcpt->scp_at_lock);
		RETURN(0);
	}

	/*
	 * We're close to a timeout, and we don't know how much longer the
	 * server will take. Send early replies to everyone expiring soon.
	 */
	deadline = -1;
	div_u64_rem(array->paa_deadline, array->paa_size, &index);
	count = array->paa_count;
	while (count > 0) {
		count -= array->paa_reqs_count[index];
		list_for_each_entry_safe(rq, n,
					 &array->paa_reqs_array[index],
					 rq_timed_list) {
			if (rq->rq_deadline > now + at_early_margin) {
				/* update the earliest deadline */
				if (deadline == -1 ||
				    rq->rq_deadline < deadline)
					deadline = rq->rq_deadline;
				break;
			}

			/**
			 * ptlrpc_server_drop_request() may drop
			 * refcount to 0 already. Let's check this and
			 * don't add entry to work_list
			 */
			if (likely(atomic_inc_not_zero(&rq->rq_refcount))) {
				ptlrpc_at_remove_timed(rq);
				list_add(&rq->rq_timed_list, &work_list);
			} else {
				ptlrpc_at_remove_timed(rq);
			}

			counter++;
		}

		if (++index >= array->paa_size)
			index = 0;
	}
	array->paa_deadline = deadline;
	/* we have a new earliest deadline, restart the timer */
	ptlrpc_at_set_timer(svcpt);

	spin_unlock(&svcpt->scp_at_lock);

	CDEBUG(D_ADAPTTO,
	       "timeout in %+ds, asking for %d secs on %d early replies\n",
	       first, at_extra, counter);
	if (first < 0) {
		/*
		 * We're already past request deadlines before we even get a
		 * chance to send early replies
		 */
		timeout_t atg = obd_at_get((struct obd_device *)NULL,
					   &svcpt->scp_at_estimate);
		LCONSOLE_WARN("'%s' is processing requests too slowly, client may timeout. Late by %ds, missed %d early replies (reqs waiting=%d active=%d, at_estimate=%d, delay=%lldms)\n",
			      svcpt->scp_service->srv_name, -first, counter,
			      svcpt->scp_nreqs_incoming,
			      svcpt->scp_nreqs_active,
			      atg,
			      delay_ms);
	}

	/*
	 * we took additional refcount so entries can't be deleted from list, no
	 * locking is needed
	 */
	while ((rq = list_first_entry_or_null(&work_list,
					      struct ptlrpc_request,
					      rq_timed_list)) != NULL) {
		list_del_init(&rq->rq_timed_list);

		if (ptlrpc_at_send_early_reply(rq) == 0)
			ptlrpc_at_add_timed(rq);

		ptlrpc_server_drop_request(rq);
	}

	RETURN(1); /* return "did_something" for liblustre */
}

/*
 * Check if we are already handling earlier incarnation of this request.
 * Called under &req->rq_export->exp_rpc_lock locked
 */
static struct ptlrpc_request*
ptlrpc_server_check_resend_in_progress(struct ptlrpc_request *req)
{
	struct ptlrpc_request *tmp = NULL;

	if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT))
		return NULL;

	/*
	 * This list should not be longer than max_requests in
	 * flights on the client, so it is not all that long.
	 * Also we only hit this codepath in case of a resent
	 * request which makes it even more rarely hit
	 */
	list_for_each_entry(tmp, &req->rq_export->exp_reg_rpcs,
				rq_exp_list) {
		/* Found duplicate one */
		if (tmp->rq_xid == req->rq_xid)
			goto found;
	}
	list_for_each_entry(tmp, &req->rq_export->exp_hp_rpcs,
				rq_exp_list) {
		/* Found duplicate one */
		if (tmp->rq_xid == req->rq_xid)
			goto found;
	}
	return NULL;

found:
	return tmp;
}

#ifdef HAVE_SERVER_SUPPORT
static void ptlrpc_server_mark_obsolete(struct ptlrpc_request *req)
{
	spin_lock(&req->rq_lock);
	req->rq_obsolete = 1;
	spin_unlock(&req->rq_lock);
}

static void
ptlrpc_server_mark_in_progress_obsolete(struct ptlrpc_request *req)
{
	struct ptlrpc_request	*tmp = NULL;
	__u16			tag;

	if (!tgt_is_increasing_xid_client(req->rq_export) ||
	    req->rq_export->exp_used_slots == NULL)
		return;

	tag = lustre_msg_get_tag(req->rq_reqmsg);
	if (tag == 0)
		return;

	if (!test_bit(tag - 1, req->rq_export->exp_used_slots))
		return;

	/* This list should not be longer than max_requests in
	 * flights on the client, so it is not all that long.
	 * Also we only hit this codepath in case of a resent
	 * request which makes it even more rarely hit */
	list_for_each_entry(tmp, &req->rq_export->exp_reg_rpcs, rq_exp_list) {
		if (tag == lustre_msg_get_tag(tmp->rq_reqmsg) &&
		    req->rq_xid > tmp->rq_xid)
			ptlrpc_server_mark_obsolete(tmp);

	}
	list_for_each_entry(tmp, &req->rq_export->exp_hp_rpcs, rq_exp_list) {
		if (tag == lustre_msg_get_tag(tmp->rq_reqmsg) &&
		    req->rq_xid > tmp->rq_xid)
			ptlrpc_server_mark_obsolete(tmp);
	}
}
#endif

/**
 * ptlrpc_server_hpreq_init() - Check request can be assigned with high priority
 * @svcpt: the PTLRPC service partition
 * @req: ptlrpc thread
 *
 * Return:
 * * %<0 error occurred
 * * %0 normal RPC request
 * * %1 high priority request
 */
static int ptlrpc_server_hpreq_init(struct ptlrpc_service_part *svcpt,
				    struct ptlrpc_request *req)
{
	int rc = 0;

	ENTRY;
	if (svcpt->scp_service->srv_ops.so_hpreq_handler != NULL) {
		rc = svcpt->scp_service->srv_ops.so_hpreq_handler(req);
		if (rc < 0)
			RETURN(rc);

		LASSERT(rc == 0);
	}

	if (req->rq_export != NULL && req->rq_ops != NULL) {
		/*
		 * Perform request specific check. We should do this
		 * check before the request is added into exp_hp_rpcs
		 * list otherwise it may hit swab race at LU-1044.
		 */
		if (req->rq_ops->hpreq_check != NULL) {
			rc = req->rq_ops->hpreq_check(req);
			if (rc == -ESTALE) {
				req->rq_status = rc;
				ptlrpc_error(req);
			}
			/*
			 * can only return error,
			 * 0 for normal request,
			 * or 1 for high priority request
			 */
			LASSERT(rc <= 1);
		}
	}

	RETURN(rc);
}

/* Remove the request from the export list. */
static void ptlrpc_server_hpreq_fini(struct ptlrpc_request *req)
{
	ENTRY;
	if (req->rq_export) {
		/*
		 * refresh lock timeout again so that client has more
		 * room to send lock cancel RPC.
		 */
		if (req->rq_ops && req->rq_ops->hpreq_fini)
			req->rq_ops->hpreq_fini(req);

		ptlrpc_del_exp_list(req);
	}
	EXIT;
}

static int ptlrpc_hpreq_check(struct ptlrpc_request *req)
{
	return 1;
}

static struct ptlrpc_hpreq_ops ptlrpc_hpreq_common = {
	.hpreq_check       = ptlrpc_hpreq_check,
};

/* Hi-Priority RPC check by RPC operation code. */
int ptlrpc_hpreq_handler(struct ptlrpc_request *req)
{
	int opc = lustre_msg_get_opc(req->rq_reqmsg);

	/*
	 * Check for export to let only reconnects for not yet evicted
	 * export to become a HP rpc.
	 */
	if ((req->rq_export != NULL) &&
	    (opc == OBD_PING || opc == MDS_CONNECT || opc == OST_CONNECT))
		req->rq_ops = &ptlrpc_hpreq_common;

	return 0;
}
EXPORT_SYMBOL(ptlrpc_hpreq_handler);

static int ptlrpc_server_request_add(struct ptlrpc_service_part *svcpt,
				     struct ptlrpc_request *req)
{
	int rc;
	bool hp;
	struct ptlrpc_request *orig = NULL;
	int opc;

	ENTRY;

	rc = ptlrpc_server_hpreq_init(svcpt, req);
	if (rc < 0)
		RETURN(rc);

	hp = rc > 0;
	ptlrpc_nrs_req_initialize(svcpt, req, hp);

	opc = lustre_msg_get_opc(req->rq_reqmsg);

	while (req->rq_export != NULL) {
		struct obd_export *exp = req->rq_export;

		/*
		 * do search for duplicated xid and the adding to the list
		 * atomically
		 */
		spin_lock_bh(&exp->exp_rpc_lock);

		/* Cancels are unbounded unlimited requests, they are also
		 * stateless, so we don't really want to search for duplicates
		 * as that can take a really long time (under spinlock at that.
		 * There might be other requests like this and we might want to
		 * make this code a bit more generic, but this should plug
		 * the most obious hole for now */
		if (opc != LDLM_CANCEL) {
#ifdef HAVE_SERVER_SUPPORT
			ptlrpc_server_mark_in_progress_obsolete(req);
#endif
			orig = ptlrpc_server_check_resend_in_progress(req);
			if (orig && CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_RESEND_RACE)) {
				spin_unlock_bh(&exp->exp_rpc_lock);

				CFS_RACE(OBD_FAIL_PTLRPC_RESEND_RACE);
				msleep(4 * MSEC_PER_SEC);
				continue;
			}
		}

		if (orig && likely(atomic_inc_not_zero(&orig->rq_refcount))) {
			bool linked;

			spin_unlock_bh(&exp->exp_rpc_lock);

			DEBUG_REQ(D_HA, req,
				  "Found duplicate req in processing");
			DEBUG_REQ(D_HA, orig, "Request being processed");

			/*
			 * When the client resend request and the server has
			 * the previous copy of it, we need to update deadlines,
			 * to be sure that the client and the server have equal
			 *  request deadlines.
			 */

			spin_lock(&orig->rq_rqbd->rqbd_svcpt->scp_at_lock);
			linked = orig->rq_at_linked;
			if (likely(linked))
				ptlrpc_at_remove_timed(orig);
			spin_unlock(&orig->rq_rqbd->rqbd_svcpt->scp_at_lock);
			orig->rq_deadline = req->rq_deadline;
			orig->rq_rep_mbits = req->rq_rep_mbits;
			if (likely(linked))
				ptlrpc_at_add_timed(orig);
			ptlrpc_server_drop_request(orig);
			ptlrpc_nrs_req_finalize(req);

			/* don't mark slot unused for resend in progress */
			spin_lock(&req->rq_lock);
			req->rq_obsolete = 1;
			spin_unlock(&req->rq_lock);

			RETURN(-EBUSY);
		}

		ptlrpc_add_exp_list_nolock(req, exp, hp || req->rq_ops != NULL);

		spin_unlock_bh(&exp->exp_rpc_lock);
		break;
	}

	/*
	 * the current thread is not the processing thread for this request
	 * since that, but request is in exp_hp_list and can be find there.
	 * Remove all relations between request and old thread.
	 */
	req->rq_svc_thread->t_env->le_ses = NULL;
	req->rq_svc_thread = NULL;
	req->rq_session.lc_thread = NULL;

	ptlrpc_nrs_req_add(svcpt, req, hp);

	RETURN(0);
}

/*
 * Allow to handle high priority request
 * User can call it w/o any lock but need to hold
 * ptlrpc_service_part::scp_req_lock to get reliable result
 */
static bool ptlrpc_server_allow_high(struct ptlrpc_service_part *svcpt,
				     bool force)
{
	int running = svcpt->scp_nthrs_running;

	if (!nrs_svcpt_has_hp(svcpt))
		return false;

	if (force)
		return true;

	if (ptlrpc_nrs_req_throttling_nolock(svcpt, true))
		return false;

	if (unlikely(svcpt->scp_service->srv_req_portal == MDS_REQUEST_PORTAL &&
		     CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CANCEL_RESEND))) {
		/* leave just 1 thread for normal RPCs */
		running = PTLRPC_NTHRS_INIT;
		if (svcpt->scp_service->srv_ops.so_hpreq_handler != NULL)
			running += 1;
	}

	if (svcpt->scp_nreqs_active >= running - 1)
		return false;

	if (svcpt->scp_nhreqs_active == 0)
		return true;

	return !ptlrpc_nrs_req_pending_nolock(svcpt, false) ||
	       svcpt->scp_hreq_count < svcpt->scp_service->srv_hpreq_ratio;
}

static bool ptlrpc_server_high_pending(struct ptlrpc_service_part *svcpt,
				       bool force)
{
	return ptlrpc_server_allow_high(svcpt, force) &&
	       ptlrpc_nrs_req_pending_nolock(svcpt, true);
}

/*
 * Only allow normal priority requests on a service that has a high-priority
 * queue if forced (i.e. cleanup), if there are other high priority requests
 * already being processed (i.e. those threads can service more high-priority
 * requests), or if there are enough idle threads that a later thread can do
 * a high priority request.
 * User can call it w/o any lock but need to hold
 * ptlrpc_service_part::scp_req_lock to get reliable result
 */
static bool ptlrpc_server_allow_normal(struct ptlrpc_service_part *svcpt,
				       bool force)
{
	int running = svcpt->scp_nthrs_running;

	if (unlikely(svcpt->scp_service->srv_req_portal == MDS_REQUEST_PORTAL &&
		     CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CANCEL_RESEND))) {
		/* leave just 1 thread for normal RPCs */
		running = PTLRPC_NTHRS_INIT;
		if (svcpt->scp_service->srv_ops.so_hpreq_handler != NULL)
			running += 1;
	}

	if (force)
		return true;

	if (ptlrpc_nrs_req_throttling_nolock(svcpt, false))
		return false;

	if (svcpt->scp_nreqs_active < running - 2)
		return true;

	if (svcpt->scp_nreqs_active >= running - 1)
		return false;

	return svcpt->scp_nhreqs_active > 0 || !nrs_svcpt_has_hp(svcpt);
}

static bool ptlrpc_server_normal_pending(struct ptlrpc_service_part *svcpt,
					 bool force)
{
	return ptlrpc_server_allow_normal(svcpt, force) &&
	       ptlrpc_nrs_req_pending_nolock(svcpt, false);
}

/*
 * Returns true if there are requests available in incoming
 * request queue for processing and it is allowed to fetch them.
 * User can call it w/o any lock but need to hold ptlrpc_service::scp_req_lock
 * to get reliable result
 * see @ptlrpc_server_allow_normal
 * see @ptlrpc_server_allow high
 */
static inline
bool ptlrpc_server_request_pending(struct ptlrpc_service_part *svcpt,
				   bool force)
{
	return ptlrpc_server_high_pending(svcpt, force) ||
	       ptlrpc_server_normal_pending(svcpt, force);
}

/**
 * ptlrpc_server_request_get() - Fetch a request for processing from queue of
 * unprocessed requests.
 * @svcpt: the PTLRPC service partition
 * @force: If true Fetch the request regardless (even if it is stuck)
 *
 * Favors high-priority requests.
 *
 * Returns a pointer to fetched request else NULL
 */
static struct ptlrpc_request *
ptlrpc_server_request_get(struct ptlrpc_service_part *svcpt, bool force)
{
	struct ptlrpc_request *req = NULL;

	ENTRY;

	spin_lock(&svcpt->scp_req_lock);

	if (ptlrpc_server_high_pending(svcpt, force)) {
		req = ptlrpc_nrs_req_get_nolock(svcpt, true, force);
		if (req != NULL) {
			svcpt->scp_hreq_count++;
			goto got_request;
		}
	}

	if (ptlrpc_server_normal_pending(svcpt, force)) {
		req = ptlrpc_nrs_req_get_nolock(svcpt, false, force);
		if (req != NULL) {
			svcpt->scp_hreq_count = 0;
			goto got_request;
		}
	}

	spin_unlock(&svcpt->scp_req_lock);
	RETURN(NULL);

got_request:
	svcpt->scp_last_request = ktime_get_real_seconds();
	svcpt->scp_nreqs_active++;
	if (req->rq_hp)
		svcpt->scp_nhreqs_active++;

	spin_unlock(&svcpt->scp_req_lock);

	if (likely(req->rq_export))
		class_export_rpc_inc(req->rq_export);

	RETURN(req);
}

/**
 * ptlrpc_server_handle_req_in() - Handle freshly incoming reqs
 * @svcpt: the PTLRPC service partition
 * @thread: ptlrpc thread
 *
 * Handle freshly incoming reqs, add to timed early reply list, pass on to
 * regular request queue. All incoming requests pass through here before getting
 * into @ptlrpc_server_handle_req later on.
 *
 * Return:
 * * %0 Request was processed
 * * %1 Request not processed or no request available
 */
static int ptlrpc_server_handle_req_in(struct ptlrpc_service_part *svcpt,
				       struct ptlrpc_thread *thread)
{
	struct ptlrpc_service *svc = svcpt->scp_service;
	struct ptlrpc_request *req;
	__u32 deadline;
	__u32 opc;
	int rc;

	ENTRY;

	spin_lock(&svcpt->scp_lock);
	if (list_empty(&svcpt->scp_req_incoming)) {
		spin_unlock(&svcpt->scp_lock);
		RETURN(0);
	}

	req = list_first_entry(&svcpt->scp_req_incoming,
			       struct ptlrpc_request, rq_list);
	list_del_init(&req->rq_list);
	svcpt->scp_nreqs_incoming--;
	/*
	 * Consider this still a "queued" request as far as stats are
	 * concerned
	 */
	spin_unlock(&svcpt->scp_lock);

	/* go through security check/transform */
	CDEBUG(D_RPCTRACE, "unwrap req x%llu\n", req->rq_xid);
	rc = sptlrpc_svc_unwrap_request(req);
	switch (rc) {
	case SECSVC_OK:
		break;
	case SECSVC_COMPLETE:
		target_send_reply(req, 0, OBD_FAIL_MDS_ALL_REPLY_NET);
		goto err_req;
	case SECSVC_DROP:
		goto err_req;
	default:
		LBUG();
	}

	/*
	 * for null-flavored rpc, msg has been unpacked by sptlrpc, although
	 * redo it wouldn't be harmful.
	 */
	if (SPTLRPC_FLVR_POLICY(req->rq_flvr.sf_rpc) != SPTLRPC_POLICY_NULL) {
		rc = ptlrpc_unpack_req_msg(req, req->rq_reqlen);
		if (rc != 0) {
			CERROR("error unpacking request: ptl %d from %s x%llu\n",
			       svc->srv_req_portal, libcfs_idstr(&req->rq_peer),
			       req->rq_xid);
			goto err_req;
		}
	}

	rc = lustre_unpack_req_ptlrpc_body(req, MSG_PTLRPC_BODY_OFF);
	if (rc) {
		CERROR("error unpacking ptlrpc body: ptl %d from %s x %llu\n",
		       svc->srv_req_portal, libcfs_idstr(&req->rq_peer),
		       req->rq_xid);
		goto err_req;
	}

	opc = lustre_msg_get_opc(req->rq_reqmsg);
	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_DROP_REQ_OPC) &&
	    opc == cfs_fail_val) {
		CERROR("drop incoming rpc opc %u, x%llu\n",
		       cfs_fail_val, req->rq_xid);
		goto err_req;
	}

	rc = -EINVAL;
	if (lustre_msg_get_type(req->rq_reqmsg) != PTL_RPC_MSG_REQUEST) {
		CERROR("wrong packet type received (type=%u) from %s\n",
		       lustre_msg_get_type(req->rq_reqmsg),
		       libcfs_idstr(&req->rq_peer));
		goto err_req;
	}

	switch (opc) {
	case MDS_WRITEPAGE:
	case OST_WRITE:
	case OUT_UPDATE:
		req->rq_bulk_write = 1;
		break;
	case MDS_READPAGE:
	case OST_READ:
	case MGS_CONFIG_READ:
		req->rq_bulk_read = 1;
		break;
	}

	CDEBUG(D_RPCTRACE, "got req x%llu\n", req->rq_xid);

	req->rq_export = class_conn2export(
		lustre_msg_get_handle(req->rq_reqmsg));
	if (req->rq_export) {
		rc = ptlrpc_check_req(req);
		if (rc == 0) {
			rc = sptlrpc_target_export_check(req->rq_export, req);
			if (rc)
				DEBUG_REQ(D_ERROR, req,
					  "DROPPING req with illegal security flavor");
		}

		if (rc)
			goto err_req;

		ptlrpc_update_export_timer(req);
	}

	/* req_in handling should/must be fast */
	if (ktime_get_real_seconds() - req->rq_arrival_time.tv_sec > 5)
		DEBUG_REQ(D_WARNING, req, "Slow req_in handling %llds",
			  ktime_get_real_seconds() -
			  req->rq_arrival_time.tv_sec);

	/* Set rpc server deadline and add it to the timed list */
	deadline = (lustre_msghdr_get_flags(req->rq_reqmsg) &
		    MSGHDR_AT_SUPPORT) ?
		    /* The max time the client expects us to take */
		    lustre_msg_get_timeout(req->rq_reqmsg) : obd_timeout;

	req->rq_deadline = req->rq_arrival_time.tv_sec + deadline;
	if (unlikely(deadline == 0)) {
		DEBUG_REQ(D_ERROR, req, "Dropping request with 0 timeout");
		goto err_req;
	}

	/* Skip early reply */
	if (CFS_FAIL_PRECHECK(OBD_FAIL_MDS_RESEND))
		req->rq_deadline += obd_timeout;

	req->rq_svc_thread = thread;
	if (thread != NULL) {
		/*
		 * initialize request session, it is needed for request
		 * processing by target
		 */
		rc = lu_context_init(&req->rq_session, LCT_SERVER_SESSION |
						       LCT_NOREF);
		if (rc) {
			CERROR("%s: failure to initialize session: rc = %d\n",
			       thread->t_name, rc);
			goto err_req;
		}
		req->rq_session.lc_thread = thread;
		lu_context_enter(&req->rq_session);
		thread->t_env->le_ses = &req->rq_session;
	}


	if (unlikely(CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_ENQ_RESEND) &&
		     (opc == LDLM_ENQUEUE) &&
		     (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT)))
		CFS_FAIL_TIMEOUT(OBD_FAIL_PTLRPC_ENQ_RESEND, 6);

	ptlrpc_at_add_timed(req);

	if (opc != OST_CONNECT && opc != MDS_CONNECT &&
	    opc != MGS_CONNECT && req->rq_export != NULL) {
		if (exp_connect_flags2(req->rq_export) & OBD_CONNECT2_REP_MBITS)
			req->rq_rep_mbits = lustre_msg_get_mbits(req->rq_reqmsg);
	}

	/* Move it over to the request processing queue */
	rc = ptlrpc_server_request_add(svcpt, req);
	if (rc)
		GOTO(err_req, rc);

	wake_up(&svcpt->scp_waitq);
	RETURN(1);

err_req:
	CDEBUG(D_RPCTRACE, "finish req x%llu\n", req->rq_xid);
	ptlrpc_server_finish_request(svcpt, req);

	RETURN(1);
}

/**
 * ptlrpc_server_handle_request() - Main incoming request handling logic
 * @svcpt: pointer to struct ptlrpc_service_part
 * @thread: pointer to struct ptlrpc_thread(actual handling done by this thread)
 *
 * Calls handler function from service to do actual processing.
 *
 * Return:
 * * %1 request is processed
 * * %0 no request processed or request not available
 */
static int ptlrpc_server_handle_request(struct ptlrpc_service_part *svcpt,
					struct ptlrpc_thread *thread)
{
	struct ptlrpc_service *svc = svcpt->scp_service;
	struct ptlrpc_request *request;
	ktime_t work_start;
	ktime_t work_end;
	ktime_t arrived;
	s64 timediff_usecs;
	s64 arrived_usecs;
	__u32 op;
	int fail_opc = 0;
	struct obd_device *obd = NULL;

	ENTRY;

	request = ptlrpc_server_request_get(svcpt, false);
	if (request == NULL)
		RETURN(0);

	if (request->rq_export)
		obd = request->rq_export->exp_obd;

	op = lustre_msg_get_opc(request->rq_reqmsg);

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_HPREQ_NOTIMEOUT))
		fail_opc = OBD_FAIL_PTLRPC_HPREQ_NOTIMEOUT;
	else if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_HPREQ_TIMEOUT))
		fail_opc = OBD_FAIL_PTLRPC_HPREQ_TIMEOUT;

	if (unlikely(fail_opc)) {
		if (request->rq_export && request->rq_ops)
			CFS_FAIL_TIMEOUT(fail_opc, 4);
	}

	ptlrpc_rqphase_move(request, RQ_PHASE_INTERPRET);

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_DUMP_LOG))
		libcfs_debug_dumplog();

	work_start = ktime_get_real();
	arrived = timespec64_to_ktime(request->rq_arrival_time);
	timediff_usecs = ktime_us_delta(work_start, arrived);
	if (unlikely(timediff_usecs < 0))
		timediff_usecs = 1;
	if (likely(svc->srv_stats != NULL)) {
		lprocfs_counter_add(svc->srv_stats, PTLRPC_REQWAIT_CNTR,
				    timediff_usecs);
		lprocfs_counter_add(svc->srv_stats, PTLRPC_REQQDEPTH_CNTR,
				    svcpt->scp_nreqs_incoming);
		lprocfs_counter_add(svc->srv_stats, PTLRPC_REQACTIVE_CNTR,
				    svcpt->scp_nreqs_active);
		lprocfs_counter_add(svc->srv_stats, PTLRPC_TIMEOUT,
				    obd_at_get(obd, &svcpt->scp_at_estimate));
	}

	if (likely(request->rq_export)) {
		if (unlikely(ptlrpc_check_req(request)))
			goto put_conn;

		ptlrpc_update_export_timer(request);
	}

	/*
	 * Discard requests queued for longer than the deadline.
	 * The deadline is increased if we send an early reply.
	 */
	if (op != LDLM_CANCEL &&
	    ktime_get_real_seconds() > request->rq_deadline) {
		DEBUG_REQ(D_ERROR, request,
			  "Dropping timed-out request from %s: deadline %lld/%llds ago",
			  libcfs_idstr(&request->rq_peer),
			  request->rq_deadline -
			  request->rq_arrival_time.tv_sec,
			  ktime_get_real_seconds() - request->rq_deadline);
		goto put_conn;
	}

	CDEBUG(D_RPCTRACE,
	       "Handling RPC req@%p pname:cluuid+ref:pid:xid:nid:opc:job %s:%s+%d:%d:x%llu:%s:%d:%s\n",
	       request, current->comm,
	       (request->rq_export ?
		(char *)request->rq_export->exp_client_uuid.uuid : "0"),
	       (request->rq_export ?
		refcount_read(&request->rq_export->exp_handle.h_ref) : -99),
	       lustre_msg_get_status(request->rq_reqmsg), request->rq_xid,
	       libcfs_idstr(&request->rq_peer), op,
	       lustre_msg_get_jobid(request->rq_reqmsg) ?: "");

	if (CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_PAUSE_REQ)) {
		if (op != OBD_PING && op != OST_STATFS &&
		    op != MDS_STATFS && op != OST_CREATE &&
		    op != OST_DISCONNECT) {
			DEBUG_REQ(D_ERROR, request, "HIT");
			CFS_FAIL_TIMEOUT_MS(OBD_FAIL_PTLRPC_PAUSE_REQ, cfs_fail_val);
		}
	}

	CDEBUG(D_NET, "got req %llu\n", request->rq_xid);

	/* re-assign request and sesson thread to the current one */
	request->rq_svc_thread = thread;
	if (thread != NULL) {
		LASSERT(request->rq_session.lc_thread == NULL);
		request->rq_session.lc_thread = thread;
		thread->t_env->le_ses = &request->rq_session;
	}
	svc->srv_ops.so_req_handler(request);

	ptlrpc_rqphase_move(request, RQ_PHASE_COMPLETE);

put_conn:
	if (unlikely(ktime_get_real_seconds() > request->rq_deadline)) {
		DEBUG_REQ(D_WARNING, request,
			  "Request took longer than estimated (%lld/%llds); client may timeout",
			  request->rq_deadline -
			  request->rq_arrival_time.tv_sec,
			  ktime_get_real_seconds() - request->rq_deadline);
	}

	work_end = ktime_get_real();
	timediff_usecs = ktime_us_delta(work_end, work_start);
	if (unlikely(timediff_usecs < 0))
		timediff_usecs = 1;
	arrived_usecs = ktime_us_delta(work_end, arrived);
	if (unlikely(arrived_usecs < 0))
		arrived_usecs = 1;
	CDEBUG(D_RPCTRACE,
	       "Handled RPC req@%p pname:cluuid+ref:pid:xid:nid:opc:job %s:%s+%d:%d:x%llu:%s:%d:%s Request processed in %lldus (%lldus total) trans %llu rc %d/%d\n",
	       request, current->comm,
	       (request->rq_export ?
	       (char *)request->rq_export->exp_client_uuid.uuid : "0"),
	       (request->rq_export ?
		refcount_read(&request->rq_export->exp_handle.h_ref) : -99),
	       lustre_msg_get_status(request->rq_reqmsg),
	       request->rq_xid,
	       libcfs_idstr(&request->rq_peer), op,
	       lustre_msg_get_jobid(request->rq_reqmsg) ?: "",
	       timediff_usecs,
	       arrived_usecs,
	       (request->rq_repmsg ?
	       lustre_msg_get_transno(request->rq_repmsg) :
	       request->rq_transno),
	       request->rq_status,
	       (request->rq_repmsg ?
	       lustre_msg_get_status(request->rq_repmsg) : -999));
	if (likely(svc->srv_stats != NULL && request->rq_reqmsg != NULL)) {
		int opc = opcode_offset(op);

		if (opc > 0 && !(op == LDLM_ENQUEUE || op == MDS_REINT)) {
			LASSERT(opc < LUSTRE_MAX_OPCODES);
			lprocfs_counter_add(svc->srv_stats,
					    opc + EXTRA_MAX_OPCODES,
					    timediff_usecs);
		}
	}
	if (unlikely(request->rq_early_count)) {
		DEBUG_REQ(D_ADAPTTO, request,
			  "sent %d early replies before finishing in %llds",
			  request->rq_early_count,
			  div_u64(arrived_usecs, USEC_PER_SEC));
	}
	if (unlikely(request->rq_pause_after_reply)) {
		DEBUG_REQ(D_WARNING, request, "pause req after reply");
		schedule_timeout_uninterruptible(cfs_time_seconds(3));
		DEBUG_REQ(D_WARNING, request, "continue");
	}

	ptlrpc_server_finish_active_request(svcpt, request);

	RETURN(1);
}

/* An internal function to process a single reply state object. */
static int ptlrpc_handle_rs(struct ptlrpc_reply_state *rs)
{
	struct ptlrpc_service_part *svcpt = rs->rs_svcpt;
	struct ptlrpc_service *svc = svcpt->scp_service;
	struct obd_export *exp;
	int nlocks;
	int been_handled;

	ENTRY;

	exp = rs->rs_export;

	LASSERT(rs->rs_difficult);
	LASSERT(rs->rs_scheduled);
	LASSERT(list_empty(&rs->rs_list));

	/*
	 * The disk commit callback holds exp_uncommitted_replies_lock while it
	 * iterates over newly committed replies, removing them from
	 * exp_uncommitted_replies.  It then drops this lock and schedules the
	 * replies it found for handling here.
	 *
	 * We can avoid contention for exp_uncommitted_replies_lock between the
	 * HRT threads and further commit callbacks by checking rs_committed
	 * which is set in the commit callback while it holds both
	 * rs_lock and exp_uncommitted_reples.
	 *
	 * If we see rs_committed clear, the commit callback _may_ not have
	 * handled this reply yet and we race with it to grab
	 * exp_uncommitted_replies_lock before removing the reply from
	 * exp_uncommitted_replies.  Note that if we lose the race and the
	 * reply has already been removed, list_del_init() is a noop.
	 *
	 * If we see rs_committed set, we know the commit callback is handling,
	 * or has handled this reply since store reordering might allow us to
	 * see rs_committed set out of sequence.  But since this is done
	 * holding rs_lock, we can be sure it has all completed once we hold
	 * rs_lock, which we do right next.
	 */
	if (!rs->rs_committed) {
		spin_lock(&exp->exp_uncommitted_replies_lock);
		list_del_init(&rs->rs_obd_list);
		spin_unlock(&exp->exp_uncommitted_replies_lock);
	}

	spin_lock(&exp->exp_lock);
	/* Noop if removed already */
	list_del_init(&rs->rs_exp_list);
	spin_unlock(&exp->exp_lock);

	spin_lock(&rs->rs_lock);

	been_handled = rs->rs_handled;
	rs->rs_handled = 1;

	nlocks = rs->rs_nlocks; /* atomic "steal", but */
	rs->rs_nlocks = 0; /* locks still on rs_locks! */

	if (nlocks == 0 && !been_handled) {
		/*
		 * If we see this, we should already have seen the warning
		 * in mds_steal_ack_locks()
		 */
		CDEBUG(D_HA,
		       "All locks stolen from rs %p x%lld.t%lld o%d NID %s\n",
		       rs, rs->rs_xid, rs->rs_transno, rs->rs_opc,
		       libcfs_nidstr(&exp->exp_connection->c_peer.nid));
	}

	if ((rs->rs_sent && !rs->rs_unlinked) || nlocks > 0) {
		spin_unlock(&rs->rs_lock);

		/* We can unlink if the LNET_EVENT_SEND has occurred.
		 * If rs_unlinked is set then MD is already unlinked and no
		 * need to do so here.
		 */
		if ((rs->rs_sent && !rs->rs_unlinked)) {
			LNetMDUnlink(rs->rs_md_h);
			/* Ignore return code; we're racing with completion */
		}

		while (nlocks-- > 0)
			ldlm_lock_decref(&rs->rs_locks[nlocks], LCK_TXN);

		spin_lock(&rs->rs_lock);
	}

	rs->rs_scheduled = 0;

	if (rs->rs_unlinked) {
		/* Off the net */
		spin_unlock(&rs->rs_lock);

		class_export_put(exp);
		rs->rs_export = NULL;
		kref_put(&rs->rs_refcount, lustre_free_reply_state);
		if (atomic_dec_and_test(&svcpt->scp_nreps_difficult) &&
		    svc->srv_is_stopping)
			wake_up_all(&svcpt->scp_waitq);
		RETURN(1);
	}

	/* still on the net; callback will schedule */
	spin_unlock(&rs->rs_lock);
	RETURN(1);
}


static void ptlrpc_check_rqbd_pool(struct ptlrpc_service_part *svcpt)
{
	int avail = svcpt->scp_nrqbds_posted;
	int low_water = test_req_buffer_pressure ? 0 :
			svcpt->scp_service->srv_nbuf_per_group / 2;

	/* NB I'm not locking; just looking. */

	/*
	 * CAVEAT EMPTOR: We might be allocating buffers here because we've
	 * allowed the request history to grow out of control.  We could put a
	 * sanity check on that here and cull some history if we need the
	 * space.
	 */

	if (avail <= low_water)
		ptlrpc_grow_req_bufs(svcpt, 1);

	if (svcpt->scp_service->srv_stats) {
		lprocfs_counter_add(svcpt->scp_service->srv_stats,
				    PTLRPC_REQBUF_AVAIL_CNTR, avail);
	}
}

static inline int ptlrpc_threads_enough(struct ptlrpc_service_part *svcpt)
{
	return svcpt->scp_nreqs_active <
	       svcpt->scp_nthrs_running - 1 -
	       (svcpt->scp_service->srv_ops.so_hpreq_handler != NULL);
}

/**
 * ptlrpc_threads_increasable() - allowed to create more threads
 * @svcpt: the PTLRPC service partition to increase thread
 *
 * user can call it w/o any lock but need to hold
 * ptlrpc_service_part::scp_lock to get reliable result
 *
 * Return:
 * * %0 if it can be increased
 * * %1 if it cannot be increased
 */
static inline int ptlrpc_threads_increasable(struct ptlrpc_service_part *svcpt)
{
	return svcpt->scp_nthrs_running +
	       svcpt->scp_nthrs_starting <
	       svcpt->scp_service->srv_nthrs_cpt_limit;
}

/* too many requests and allowed to create more threads */
static inline int ptlrpc_threads_need_create(struct ptlrpc_service_part *svcpt)
{
	return !ptlrpc_threads_enough(svcpt) &&
		ptlrpc_threads_increasable(svcpt);
}

static inline int ptlrpc_thread_stopping(struct ptlrpc_thread *thread)
{
	return thread_is_stopping(thread) ||
	       thread->t_svcpt->scp_service->srv_is_stopping;
}

/* stop the highest numbered thread if there are too many threads running */
static inline bool ptlrpc_thread_should_stop(struct ptlrpc_thread *thread)
{
	struct ptlrpc_service_part *svcpt = thread->t_svcpt;

	return thread->t_id >= svcpt->scp_service->srv_nthrs_cpt_limit &&
		thread->t_id == svcpt->scp_thr_nextid - 1;
}

static void ptlrpc_stop_thread(struct ptlrpc_thread *thread)
{
	CDEBUG(D_INFO, "Stopping thread %s #%u\n",
	       thread->t_svcpt->scp_service->srv_thread_name, thread->t_id);
	thread_add_flags(thread, SVC_STOPPING);
}

static inline void ptlrpc_thread_stop(struct ptlrpc_thread *thread)
{
	struct ptlrpc_service_part *svcpt = thread->t_svcpt;

	spin_lock(&svcpt->scp_lock);
	if (ptlrpc_thread_should_stop(thread)) {
		ptlrpc_stop_thread(thread);
		svcpt->scp_thr_nextid--;
	}
	spin_unlock(&svcpt->scp_lock);
}

static inline int ptlrpc_rqbd_pending(struct ptlrpc_service_part *svcpt)
{
	return !list_empty(&svcpt->scp_rqbd_idle) &&
	       svcpt->scp_rqbd_timeout == 0;
}

static inline int
ptlrpc_at_check(struct ptlrpc_service_part *svcpt)
{
	return svcpt->scp_at_check;
}

/*
 * If a thread runs too long or spends to much time on a single request,
 * we want to know about it, so we set up a delayed work item as a watchdog.
 * If it fires, we display a stack trace of the delayed thread,
 * providing we aren't rate-limited
 *
 * Watchdog stack traces are limited to 3 per 'libcfs_watchdog_ratelimit'
 * seconds
 */
static struct ratelimit_state watchdog_limit;

static void ptlrpc_watchdog_fire(struct work_struct *work)
{
	struct ptlrpc_thread *thread = container_of(work, struct ptlrpc_thread,
						    t_watchdog.work);
	u64 ms_elapsed = ktime_ms_delta(ktime_get(), thread->t_touched);
	u32 ms_frac = do_div(ms_elapsed, MSEC_PER_SEC);

	thread->t_flags |= SVC_WATCHDOG;

	/* ___ratelimit() returns true if the action is NOT ratelimited */
	if (__ratelimit(&watchdog_limit)) {
		/* below message is checked in sanity-quota.sh test_6,18 */
		/* below message is checked in recovery-small test 10a. */
		LCONSOLE_WARN("%s: service thread pid %u was inactive for %llu.%03u seconds. The thread might be hung, or it might only be slow and will resume later. Dumping the stack trace for debugging purposes:\n",
			      thread->t_task->comm, thread->t_task->pid,
			      ms_elapsed, ms_frac);

		sched_show_task(thread->t_task);
	} else {
		LCONSOLE_WARN("%s: service thread pid %u was inactive for %llu.%03u seconds. Watchdog stack traces are limited to 3 per %u seconds, skipping this one.\n",
			      thread->t_task->comm, thread->t_task->pid,
			      ms_elapsed, ms_frac, libcfs_watchdog_ratelimit);
	}
}

void ptlrpc_watchdog_init(struct delayed_work *work, timeout_t timeout)
{
	struct ptlrpc_thread *thread = container_of(&work->work,
						    struct ptlrpc_thread,
						    t_watchdog.work);

	thread->t_touched = ktime_get();
	INIT_DELAYED_WORK(work, ptlrpc_watchdog_fire);
	schedule_delayed_work(work, cfs_time_seconds(timeout));
}

static void ptlrpc_watchdog_update(struct delayed_work *work, const char *msg)
{
	struct ptlrpc_thread *thread = container_of(&work->work,
						    struct ptlrpc_thread,
						    t_watchdog.work);
	ktime_t now = ktime_get();

	if (unlikely(thread->t_flags & SVC_WATCHDOG)) {
		u64 ms_elapsed = ktime_ms_delta(now, thread->t_touched);
		u32 ms_frac = do_div(ms_elapsed, MSEC_PER_SEC);

		/* Don't ratelimit this message, since it is already limited
		 * by the watchdog (obd_timeout) and it is important to know
		 * if/when a service thread has revived after being hung.
		 * below message is checked in recovery-small test 10a.
		 */
		LCONSOLE(D_WARNING,
			 "%s: service thread pid %u %s after %llu.%03us. This likely indicates the system was overloaded (too many service threads, or not enough hardware resources).\n",
			 thread->t_task->comm, thread->t_pid, msg,
			 ms_elapsed, ms_frac);
		thread->t_flags &= ~SVC_WATCHDOG;
	}

	thread->t_touched = now;
}

void ptlrpc_watchdog_touch(struct delayed_work *work, timeout_t timeout)
{
	ptlrpc_watchdog_update(work, "resumed");
	mod_delayed_work(system_wq, work, cfs_time_seconds(timeout));
}

void ptlrpc_watchdog_disable(struct delayed_work *work)
{
	ptlrpc_watchdog_update(work, "completed");
	cancel_delayed_work_sync(work);
}

void ptlrpc_watchdog_delete(struct delayed_work *work)
{
	ptlrpc_watchdog_update(work, "stopped");
	cancel_delayed_work_sync(work);
}

/**
 * ptlrpc_server_request_incoming() - check incoming queue for requests which
 * is waiting for processing
 * @svcpt: pointer to struct ptlrpc_service_part
 *
 * user can call it w/o any lock but need to hold
 * ptlrpc_service_part::scp_lock to get reliable result
 *
 * Returns:
 * * %1 if incoming requests waiting to be processed
 * * %0 if incoming request queue is empty
 */
static inline int
ptlrpc_server_request_incoming(struct ptlrpc_service_part *svcpt)
{
	return !list_empty(&svcpt->scp_req_incoming);
}

static __attribute__((__noinline__)) int
ptlrpc_wait_event(struct ptlrpc_service_part *svcpt,
		  struct ptlrpc_thread *thread)
{
	ptlrpc_watchdog_disable(&thread->t_watchdog);

	cond_resched();

	if (svcpt->scp_rqbd_timeout == 0)
		/* Don't exit while there are replies to be handled */
		wait_event_idle_exclusive_lifo(
			svcpt->scp_waitq,
			ptlrpc_thread_stopping(thread) ||
			ptlrpc_server_request_incoming(svcpt) ||
			ptlrpc_server_request_pending(svcpt, false) ||
			ptlrpc_rqbd_pending(svcpt) ||
			ptlrpc_at_check(svcpt));
	else if (wait_event_idle_exclusive_lifo_timeout(
			 svcpt->scp_waitq,
			 ptlrpc_thread_stopping(thread) ||
			 ptlrpc_server_request_incoming(svcpt) ||
			 ptlrpc_server_request_pending(svcpt, false) ||
			 ptlrpc_rqbd_pending(svcpt) ||
			 ptlrpc_at_check(svcpt),
			 svcpt->scp_rqbd_timeout) == 0)
		svcpt->scp_rqbd_timeout = 0;

	if (ptlrpc_thread_stopping(thread))
		return -EINTR;

	ptlrpc_watchdog_touch(&thread->t_watchdog,
			      ptlrpc_server_get_timeout(svcpt));
	return 0;
}

/**
 * ptlrpc_main() - Main thread body for service threads.
 * @arg: pointer to a struct ptlrpc_thread
 *
 * Waits in a loop waiting for new requests to process to appear.
 * Every time an incoming requests is added to its queue, a waitq
 * is woken up and one of the threads will handle it.
 *
 * Returns 0 on success or error code on failure
 */
static int ptlrpc_main(void *arg)
{
	struct ptlrpc_thread *thread = (struct ptlrpc_thread *)arg;
	struct ptlrpc_service_part *svcpt = thread->t_svcpt;
	struct ptlrpc_service *svc = svcpt->scp_service;
	struct ptlrpc_reply_state *rs;
	struct group_info *ginfo = NULL;
	struct lu_env *env;
	int counter = 0, rc = 0;

	ENTRY;
	unshare_fs_struct();

	thread->t_task = current;
	thread->t_pid = current->pid;

	if (svc->srv_cpt_bind) {
		rc = cfs_cpt_bind(svc->srv_cptable, svcpt->scp_cpt);
		if (rc != 0) {
			CWARN("%s: failed to bind %s on CPT %d\n",
			      svc->srv_name, thread->t_name, svcpt->scp_cpt);
		}
	}

	ginfo = groups_alloc(0);
	if (!ginfo)
		GOTO(out, rc = -ENOMEM);

	set_current_groups(ginfo);
	put_group_info(ginfo);

	if (svc->srv_ops.so_thr_init != NULL) {
		rc = svc->srv_ops.so_thr_init(thread);
		if (rc)
			GOTO(out, rc);
	}

	OBD_ALLOC_PTR(env);
	if (env == NULL)
		GOTO(out_srv_fini, rc = -ENOMEM);
	rc = lu_env_add(env);
	if (rc)
		GOTO(out_env, rc);

	rc = lu_context_init(&env->le_ctx,
			     svc->srv_ctx_tags|LCT_REMEMBER|LCT_NOREF);
	if (rc)
		GOTO(out_env_remove, rc);

	thread->t_env = env;
	env->le_ctx.lc_thread = thread;
	env->le_ctx.lc_cookie = 0x6;

	while (!list_empty(&svcpt->scp_rqbd_idle)) {
		rc = ptlrpc_server_post_idle_rqbds(svcpt);
		if (rc >= 0)
			continue;

		CERROR("Failed to post rqbd for %s on CPT %d: %d\n",
			svc->srv_name, svcpt->scp_cpt, rc);
		GOTO(out_ctx_fini, rc);
	}

	/* Alloc reply state structure for this one */
	OBD_ALLOC_LARGE(rs, svc->srv_max_reply_size);
	if (!rs)
		GOTO(out_ctx_fini, rc = -ENOMEM);

	spin_lock(&svcpt->scp_lock);

	LASSERT(thread_is_starting(thread));
	thread_clear_flags(thread, SVC_STARTING);

	LASSERT(svcpt->scp_nthrs_starting == 1);
	svcpt->scp_nthrs_starting--;

	/*
	 * SVC_STOPPING may already be set here if someone else is trying
	 * to stop the service while this new thread has been dynamically
	 * forked. We still set SVC_RUNNING to let our creator know that
	 * we are now running, however we will exit as soon as possible
	 */
	thread_add_flags(thread, SVC_RUNNING);
	svcpt->scp_nthrs_running++;
	spin_unlock(&svcpt->scp_lock);

	/* wake up our creator in case he's still waiting. */
	wake_up(&thread->t_ctl_waitq);

	ptlrpc_watchdog_init(&thread->t_watchdog,
			     ptlrpc_server_get_timeout(svcpt));

	spin_lock(&svcpt->scp_rep_lock);
	list_add(&rs->rs_list, &svcpt->scp_rep_idle);
	wake_up(&svcpt->scp_rep_waitq);
	spin_unlock(&svcpt->scp_rep_lock);

	CDEBUG(D_NET, "service thread %d (#%d) started\n", thread->t_id,
	       svcpt->scp_nthrs_running);

	/* XXX maintain a list of all managed devices: insert here */
	while (!ptlrpc_thread_stopping(thread)) {

		if (ptlrpc_wait_event(svcpt, thread))
			break;

		ptlrpc_check_rqbd_pool(svcpt);

		if (ptlrpc_threads_need_create(svcpt)) {
			/* Ignore return code - we tried... */
			ptlrpc_start_thread(svcpt, 0);
		}

		/* reset le_ses to initial state */
		env->le_ses = NULL;
		/* Refill the context before execution to make sure
		 * all thread keys are allocated */
		lu_env_refill(env);
		/* Process all incoming reqs before handling any */
		if (ptlrpc_server_request_incoming(svcpt)) {
			lu_context_enter(&env->le_ctx);
			ptlrpc_server_handle_req_in(svcpt, thread);
			lu_context_exit(&env->le_ctx);

			/* but limit ourselves in case of flood */
			if (counter++ < 100)
				continue;
			counter = 0;
		}

		if (ptlrpc_at_check(svcpt))
			ptlrpc_at_check_timed(svcpt);

		if (ptlrpc_server_request_pending(svcpt, false)) {
			lu_context_enter(&env->le_ctx);
			ptlrpc_server_handle_request(svcpt, thread);
			lu_context_exit(&env->le_ctx);
		}

		if (ptlrpc_rqbd_pending(svcpt) &&
		    ptlrpc_server_post_idle_rqbds(svcpt) < 0) {
			/*
			 * I just failed to repost request buffers.
			 * Wait for a timeout (unless something else
			 * happens) before I try again
			 */
			svcpt->scp_rqbd_timeout = cfs_time_seconds(1) / 10;
			CDEBUG(D_RPCTRACE, "Posted buffers: %d\n",
			       svcpt->scp_nrqbds_posted);
		}

		/*
		 * If the number of threads has been tuned downward and this
		 * thread should be stopped, then stop in reverse order so the
		 * the threads always have contiguous thread index values.
		 */
		if (unlikely(ptlrpc_thread_should_stop(thread)))
			ptlrpc_thread_stop(thread);
	}

	ptlrpc_watchdog_delete(&thread->t_watchdog);

out_ctx_fini:
	lu_context_fini(&env->le_ctx);
out_env_remove:
	lu_env_remove(env);
out_env:
	OBD_FREE_PTR(env);
out_srv_fini:
	/* deconstruct service thread state created by ptlrpc_start_thread() */
	if (svc->srv_ops.so_thr_done != NULL)
		svc->srv_ops.so_thr_done(thread);
out:
	CDEBUG(D_RPCTRACE, "%s: service thread [%p:%u] %d exiting: rc = %d\n",
	       thread->t_name, thread, thread->t_pid, thread->t_id, rc);
	spin_lock(&svcpt->scp_lock);
	if (thread_test_and_clear_flags(thread, SVC_STARTING))
		svcpt->scp_nthrs_starting--;

	if (thread_test_and_clear_flags(thread, SVC_RUNNING)) {
		/* must know immediately */
		svcpt->scp_nthrs_running--;
	}

	thread->t_id = rc;
	thread_add_flags(thread, SVC_STOPPED);

	wake_up(&thread->t_ctl_waitq);
	spin_unlock(&svcpt->scp_lock);

	return rc;
}

static int hrt_dont_sleep(struct ptlrpc_hr_thread *hrt,
			  struct list_head *replies)
{
	int result;

	spin_lock(&hrt->hrt_lock);

	list_splice_init(&hrt->hrt_queue, replies);
	result = ptlrpc_hr.hr_stopping || !list_empty(replies);

	spin_unlock(&hrt->hrt_lock);
	return result;
}

/**
 * ptlrpc_hr_main() - Main body of "handle reply" function.
 * @arg: Pointer to struct 'ptlrpc_hr_thread'
 *
 * It processes acked reply states
 *
 * Returns:
 * * %0 on success
 * * %ERRNO on failure
 */
static int ptlrpc_hr_main(void *arg)
{
	struct ptlrpc_hr_thread *hrt = (struct ptlrpc_hr_thread *)arg;
	struct ptlrpc_hr_partition *hrp = hrt->hrt_partition;
	LIST_HEAD(replies);
	struct lu_env *env;
	int rc;

	unshare_fs_struct();
	OBD_ALLOC_PTR(env);
	if (env == NULL)
		RETURN(-ENOMEM);

	rc = cfs_cpt_bind(ptlrpc_hr.hr_cpt_table, hrp->hrp_cpt);
	if (rc != 0) {
		char threadname[20];

		snprintf(threadname, sizeof(threadname), "ptlrpc_hr%02d_%03d",
			 hrp->hrp_cpt, hrt->hrt_id);
		CWARN("Failed to bind %s on CPT %d of CPT table %p: rc = %d\n",
		      threadname, hrp->hrp_cpt, ptlrpc_hr.hr_cpt_table, rc);
	}

	rc = lu_context_init(&env->le_ctx, LCT_MD_THREAD | LCT_DT_THREAD |
			     LCT_REMEMBER | LCT_NOREF);
	if (rc)
		GOTO(out_env, rc);

	rc = lu_env_add(env);
	if (rc)
		GOTO(out_ctx_fini, rc);

	atomic_inc(&hrp->hrp_nstarted);
	wake_up(&ptlrpc_hr.hr_waitq);

	while (!ptlrpc_hr.hr_stopping) {
		wait_event_idle(hrt->hrt_waitq, hrt_dont_sleep(hrt, &replies));

		while (!list_empty(&replies)) {
			struct ptlrpc_reply_state *rs;

			rs = list_entry(replies.prev,
					struct ptlrpc_reply_state,
					rs_list);
			list_del_init(&rs->rs_list);
			/* refill keys if needed */
			lu_env_refill(env);
			lu_context_enter(&env->le_ctx);
			ptlrpc_handle_rs(rs);
			lu_context_exit(&env->le_ctx);
		}
	}

	atomic_inc(&hrp->hrp_nstopped);
	wake_up(&ptlrpc_hr.hr_waitq);

	lu_env_remove(env);
out_ctx_fini:
	lu_context_fini(&env->le_ctx);
out_env:
	OBD_FREE_PTR(env);
	return 0;
}

static void ptlrpc_stop_hr_threads(void)
{
	struct ptlrpc_hr_partition *hrp;
	int i;
	int j;

	ptlrpc_hr.hr_stopping = 1;

	cfs_percpt_for_each(hrp, i, ptlrpc_hr.hr_partitions) {
		if (hrp->hrp_thrs == NULL)
			continue; /* uninitialized */
		for (j = 0; j < hrp->hrp_nthrs; j++)
			wake_up(&hrp->hrp_thrs[j].hrt_waitq);
	}

	cfs_percpt_for_each(hrp, i, ptlrpc_hr.hr_partitions) {
		if (hrp->hrp_thrs == NULL)
			continue; /* uninitialized */
		wait_event(ptlrpc_hr.hr_waitq,
			       atomic_read(&hrp->hrp_nstopped) ==
			       atomic_read(&hrp->hrp_nstarted));
	}
}

static int ptlrpc_start_hr_threads(void)
{
	struct ptlrpc_hr_partition *hrp;
	int i;
	int j;

	ENTRY;

	cfs_percpt_for_each(hrp, i, ptlrpc_hr.hr_partitions) {
		int	rc = 0;

		for (j = 0; j < hrp->hrp_nthrs; j++) {
			struct ptlrpc_hr_thread *hrt = &hrp->hrp_thrs[j];
			struct task_struct *task;

			task = kthread_run(ptlrpc_hr_main,
					   &hrp->hrp_thrs[j],
					   "ptlrpc_hr%02d_%03d",
					   hrp->hrp_cpt,
					   hrt->hrt_id);
			if (IS_ERR(task)) {
				rc = PTR_ERR(task);
				break;
			}
		}

		wait_event(ptlrpc_hr.hr_waitq,
			   atomic_read(&hrp->hrp_nstarted) == j);

		if (rc < 0) {
			CERROR("cannot start reply handler thread %d:%d: rc = %d\n",
			       i, j, rc);
			ptlrpc_stop_hr_threads();
			RETURN(rc);
		}
	}

	RETURN(0);
}

static void ptlrpc_svcpt_stop_threads(struct ptlrpc_service_part *svcpt)
{
	struct ptlrpc_thread *thread;
	LIST_HEAD(zombie);

	ENTRY;

	CDEBUG(D_INFO, "Stopping threads for service %s\n",
	       svcpt->scp_service->srv_name);

	spin_lock(&svcpt->scp_lock);
	/* let the thread know that we would like it to stop asap */
	list_for_each_entry(thread, &svcpt->scp_threads, t_link)
		ptlrpc_stop_thread(thread);

	wake_up_all(&svcpt->scp_waitq);

	while ((thread = list_first_entry_or_null(&svcpt->scp_threads,
						  struct ptlrpc_thread,
						  t_link)) != NULL) {
		if (thread_is_stopped(thread)) {
			list_move(&thread->t_link, &zombie);
			continue;
		}
		spin_unlock(&svcpt->scp_lock);

		CDEBUG(D_INFO, "waiting for stopping-thread %s #%u\n",
		       svcpt->scp_service->srv_thread_name, thread->t_id);
		wait_event_idle(thread->t_ctl_waitq,
				thread_is_stopped(thread));

		spin_lock(&svcpt->scp_lock);
	}

	spin_unlock(&svcpt->scp_lock);

	while ((thread = list_first_entry_or_null(&zombie,
						  struct ptlrpc_thread,
						  t_link)) != NULL) {
		list_del(&thread->t_link);
		OBD_FREE_PTR(thread);
	}
	EXIT;
}

/* Stops all threads of a particular service @svc */
static void ptlrpc_stop_all_threads(struct ptlrpc_service *svc)
{
	struct ptlrpc_service_part *svcpt;
	int i;

	ENTRY;

	ptlrpc_service_for_each_part(svcpt, i, svc) {
		if (svcpt->scp_service != NULL)
			ptlrpc_svcpt_stop_threads(svcpt);
	}

	EXIT;
}

static int ptlrpc_start_threads(struct ptlrpc_service *svc)
{
	int rc = 0;
	int i;
	int j;

	ENTRY;

	/* We require 2 threads min, see note in ptlrpc_server_handle_request */
	LASSERT(svc->srv_nthrs_cpt_init >= PTLRPC_NTHRS_INIT);

	for (i = 0; i < svc->srv_ncpts; i++) {
		for (j = 0; j < svc->srv_nthrs_cpt_init; j++) {
			rc = ptlrpc_start_thread(svc->srv_parts[i], 1);
			if (rc == 0)
				continue;

			if (rc != -EMFILE)
				goto failed;
			/* We have enough threads, don't start more. b=15759 */
			break;
		}
	}

	RETURN(0);
 failed:
	CERROR("cannot start %s thread #%d_%d: rc %d\n",
	       svc->srv_thread_name, i, j, rc);
	ptlrpc_stop_all_threads(svc);
	RETURN(rc);
}

static int ptlrpc_start_thread(struct ptlrpc_service_part *svcpt, int wait)
{
	struct ptlrpc_thread *thread;
	struct ptlrpc_service *svc;
	struct task_struct *task;
	int rc;

	ENTRY;

	LASSERT(svcpt != NULL);

	svc = svcpt->scp_service;

	CDEBUG(D_RPCTRACE, "%s[%d] started %d min %d max %d\n",
	       svc->srv_name, svcpt->scp_cpt, svcpt->scp_nthrs_running,
	       svc->srv_nthrs_cpt_init, svc->srv_nthrs_cpt_limit);

 again:
	if (unlikely(svc->srv_is_stopping))
		RETURN(-ESRCH);

	if (!ptlrpc_threads_increasable(svcpt) ||
	    (CFS_FAIL_CHECK(OBD_FAIL_TGT_TOOMANY_THREADS) &&
	     svcpt->scp_nthrs_running == svc->srv_nthrs_cpt_init - 1))
		RETURN(-EMFILE);

	OBD_CPT_ALLOC_PTR(thread, svc->srv_cptable, svcpt->scp_cpt);
	if (thread == NULL)
		RETURN(-ENOMEM);
	init_waitqueue_head(&thread->t_ctl_waitq);

	spin_lock(&svcpt->scp_lock);
	if (!ptlrpc_threads_increasable(svcpt)) {
		spin_unlock(&svcpt->scp_lock);
		OBD_FREE_PTR(thread);
		RETURN(-EMFILE);
	}

	if (svcpt->scp_nthrs_starting != 0) {
		/*
		 * serialize starting because some modules (obdfilter)
		 * might require unique and contiguous t_id
		 */
		LASSERT(svcpt->scp_nthrs_starting == 1);
		spin_unlock(&svcpt->scp_lock);
		OBD_FREE_PTR(thread);
		if (wait) {
			CDEBUG(D_INFO, "Waiting for creating thread %s #%d\n",
			       svc->srv_thread_name, svcpt->scp_thr_nextid);
			schedule();
			goto again;
		}

		CDEBUG(D_INFO, "Creating thread %s #%d race, retry later\n",
		       svc->srv_thread_name, svcpt->scp_thr_nextid);
		RETURN(-EAGAIN);
	}

	svcpt->scp_nthrs_starting++;
	thread->t_id = svcpt->scp_thr_nextid++;
	thread_add_flags(thread, SVC_STARTING);
	thread->t_svcpt = svcpt;

	list_add(&thread->t_link, &svcpt->scp_threads);
	spin_unlock(&svcpt->scp_lock);

	if (svcpt->scp_cpt >= 0) {
		snprintf(thread->t_name, PTLRPC_THR_NAME_LEN, "%s%02d_%03d",
			 svc->srv_thread_name, svcpt->scp_cpt, thread->t_id);
	} else {
		snprintf(thread->t_name, PTLRPC_THR_NAME_LEN, "%s_%04d",
			 svc->srv_thread_name, thread->t_id);
	}

	CDEBUG(D_RPCTRACE, "starting thread '%s'\n", thread->t_name);
	task = kthread_run(ptlrpc_main, thread, "%s", thread->t_name);
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("cannot start thread '%s': rc = %d\n",
		       thread->t_name, rc);
		spin_lock(&svcpt->scp_lock);
		--svcpt->scp_nthrs_starting;
		if (thread_is_stopping(thread)) {
			/* thread now handled by ptlrpc_svcpt_stop_threads() */
			thread_add_flags(thread, SVC_STOPPED);
			wake_up(&thread->t_ctl_waitq);
			spin_unlock(&svcpt->scp_lock);
		} else {
			list_del(&thread->t_link);
			spin_unlock(&svcpt->scp_lock);
			OBD_FREE_PTR(thread);
		}
		RETURN(rc);
	}

	if (!wait)
		RETURN(0);

	wait_event_idle(thread->t_ctl_waitq,
			thread_is_running(thread) || thread_is_stopped(thread));

	rc = thread_is_stopped(thread) ? thread->t_id : 0;
	RETURN(rc);
}

int ptlrpc_hr_init(void)
{
	struct ptlrpc_hr_partition *hrp;
	struct ptlrpc_hr_thread *hrt;
	int rc;
	int cpt;
	int i;
	int weight;

	ENTRY;

	memset(&ptlrpc_hr, 0, sizeof(ptlrpc_hr));
	ptlrpc_hr.hr_cpt_table = cfs_cpt_tab;

	ptlrpc_hr.hr_partitions = cfs_percpt_alloc(ptlrpc_hr.hr_cpt_table,
						   sizeof(*hrp));
	if (ptlrpc_hr.hr_partitions == NULL)
		RETURN(-ENOMEM);

	ratelimit_state_init(&watchdog_limit,
			     cfs_time_seconds(libcfs_watchdog_ratelimit), 3);

	init_waitqueue_head(&ptlrpc_hr.hr_waitq);

	preempt_disable();
	weight = cpumask_weight(topology_sibling_cpumask(smp_processor_id()));
	preempt_enable();

	cfs_percpt_for_each(hrp, cpt, ptlrpc_hr.hr_partitions) {
		hrp->hrp_cpt = cpt;

		atomic_set(&hrp->hrp_nstarted, 0);
		atomic_set(&hrp->hrp_nstopped, 0);

		hrp->hrp_nthrs = cfs_cpt_weight(ptlrpc_hr.hr_cpt_table, cpt);
		hrp->hrp_nthrs /= weight;
		if (hrp->hrp_nthrs == 0)
			hrp->hrp_nthrs = 1;

		OBD_CPT_ALLOC(hrp->hrp_thrs, ptlrpc_hr.hr_cpt_table, cpt,
			      hrp->hrp_nthrs * sizeof(*hrt));
		if (hrp->hrp_thrs == NULL)
			GOTO(out, rc = -ENOMEM);

		for (i = 0; i < hrp->hrp_nthrs; i++) {
			hrt = &hrp->hrp_thrs[i];

			hrt->hrt_id = i;
			hrt->hrt_partition = hrp;
			init_waitqueue_head(&hrt->hrt_waitq);
			spin_lock_init(&hrt->hrt_lock);
			INIT_LIST_HEAD(&hrt->hrt_queue);
		}
	}

	rc = ptlrpc_start_hr_threads();
out:
	if (rc != 0)
		ptlrpc_hr_fini();
	RETURN(rc);
}

void ptlrpc_hr_fini(void)
{
	struct ptlrpc_hr_partition *hrp;
	int cpt;

	if (ptlrpc_hr.hr_partitions == NULL)
		return;

	ptlrpc_stop_hr_threads();

	cfs_percpt_for_each(hrp, cpt, ptlrpc_hr.hr_partitions) {
		if (hrp->hrp_thrs)
			OBD_FREE_PTR_ARRAY(hrp->hrp_thrs, hrp->hrp_nthrs);
	}

	cfs_percpt_free(ptlrpc_hr.hr_partitions);
	ptlrpc_hr.hr_partitions = NULL;
}


/* Wait until all already scheduled replies are processed */
static void ptlrpc_wait_replies(struct ptlrpc_service_part *svcpt)
{
	while (1) {
		if (wait_event_idle_timeout(
			svcpt->scp_waitq,
			atomic_read(&svcpt->scp_nreps_difficult) == 0,
			cfs_time_seconds(10)) > 0)
			break;
		CWARN("Unexpectedly long timeout %s %p\n",
		      svcpt->scp_service->srv_name, svcpt->scp_service);
	}
}

static void
ptlrpc_service_del_atimer(struct ptlrpc_service *svc)
{
	struct ptlrpc_service_part *svcpt;
	int i;

	/* early disarm AT timer... */
	ptlrpc_service_for_each_part(svcpt, i, svc) {
		if (svcpt->scp_service != NULL)
			timer_delete(&svcpt->scp_at_timer);
	}
}

static void
ptlrpc_service_unlink_rqbd(struct ptlrpc_service *svc)
{
	struct ptlrpc_service_part *svcpt;
	struct ptlrpc_request_buffer_desc *rqbd;
	int rc;
	int i;

	/*
	 * All history will be culled when the next request buffer is
	 * freed in ptlrpc_service_purge_all()
	 */
	svc->srv_hist_nrqbds_cpt_max = 0;

	rc = LNetClearLazyPortal(svc->srv_req_portal);
	LASSERT(rc == 0);

	ptlrpc_service_for_each_part(svcpt, i, svc) {
		if (svcpt->scp_service == NULL)
			break;

		/*
		 * Unlink all the request buffers.  This forces a 'final'
		 * event with its 'unlink' flag set for each posted rqbd
		 */
		list_for_each_entry(rqbd, &svcpt->scp_rqbd_posted,
					rqbd_list) {
			rc = LNetMDUnlink(rqbd->rqbd_md_h);
			LASSERT(rc == 0 || rc == -ENOENT);
		}
	}

	ptlrpc_service_for_each_part(svcpt, i, svc) {
		if (svcpt->scp_service == NULL)
			break;

		/*
		 * Wait for the network to release any buffers
		 * it's currently filling
		 */
		spin_lock(&svcpt->scp_lock);
		while (svcpt->scp_nrqbds_posted != 0) {
			int seconds = PTLRPC_REQ_LONG_UNLINK;

			spin_unlock(&svcpt->scp_lock);
			/*
			 * Network access will complete in finite time but
			 * the HUGE timeout lets us CWARN for visibility
			 * of sluggish NALs
			 */
			while (seconds > 0 &&
			       wait_event_idle_timeout(
				       svcpt->scp_waitq,
				       svcpt->scp_nrqbds_posted == 0,
				       cfs_time_seconds(1)) == 0)
				seconds -= 1;
			if (seconds == 0) {
				CWARN("Service %s waiting for request buffers\n",
				      svcpt->scp_service->srv_name);
			}
			spin_lock(&svcpt->scp_lock);
		}
		spin_unlock(&svcpt->scp_lock);
	}
}

static void
ptlrpc_service_purge_all(struct ptlrpc_service *svc)
{
	struct ptlrpc_service_part *svcpt;
	struct ptlrpc_request_buffer_desc *rqbd;
	struct ptlrpc_request *req;
	struct ptlrpc_reply_state *rs;
	int i;

	ptlrpc_service_for_each_part(svcpt, i, svc) {
		if (svcpt->scp_service == NULL)
			break;

		spin_lock(&svcpt->scp_rep_lock);
		while ((rs = list_first_entry_or_null(&svcpt->scp_rep_active,
						      struct ptlrpc_reply_state,
						      rs_list)) != NULL) {
			spin_lock(&rs->rs_lock);
			ptlrpc_schedule_difficult_reply(rs);
			spin_unlock(&rs->rs_lock);
		}
		spin_unlock(&svcpt->scp_rep_lock);

		/*
		 * purge the request queue.  NB No new replies (rqbds
		 * all unlinked) and no service threads, so I'm the only
		 * thread noodling the request queue now
		 */
		while ((req = list_first_entry_or_null(&svcpt->scp_req_incoming,
						       struct ptlrpc_request,
						       rq_list)) != NULL) {
			list_del(&req->rq_list);
			svcpt->scp_nreqs_incoming--;
			ptlrpc_server_finish_request(svcpt, req);
		}

		while (ptlrpc_server_request_pending(svcpt, true)) {
			req = ptlrpc_server_request_get(svcpt, true);
			LASSERT(req);
			ptlrpc_server_finish_active_request(svcpt, req);
		}

		/*
		 * The portal may be shared by several services (eg:OUT_PORTAL).
		 * So the request could be referenced by other target. So we
		 * have to wait the ptlrpc_server_drop_request invoked.
		 *
		 * TODO: move the req_buffer as global rather than per service.
		 */
		spin_lock(&svcpt->scp_lock);
		while (!list_empty(&svcpt->scp_rqbd_posted)) {
			spin_unlock(&svcpt->scp_lock);
			wait_event_idle_timeout(svcpt->scp_waitq,
				list_empty(&svcpt->scp_rqbd_posted),
				cfs_time_seconds(1));
			spin_lock(&svcpt->scp_lock);
		}
		spin_unlock(&svcpt->scp_lock);

		LASSERT(svcpt->scp_nreqs_incoming == 0);
		LASSERT(svcpt->scp_nreqs_active == 0);
		/*
		 * history should have been culled by
		 * ptlrpc_server_finish_request
		 */
		LASSERT(svcpt->scp_hist_nrqbds == 0);

		/*
		 * Now free all the request buffers since nothing
		 * references them any more...
		 */
		spin_lock(&svcpt->scp_lock);
		while ((rqbd = list_first_entry_or_null(&svcpt->scp_rqbd_idle,
							struct ptlrpc_request_buffer_desc,
							rqbd_list)) != NULL) {
			list_del(&rqbd->rqbd_list);
			svcpt->scp_nrqbds_total--;
			spin_unlock(&svcpt->scp_lock);

			ptlrpc_free_rqbd(rqbd);
			spin_lock(&svcpt->scp_lock);
		}
		spin_unlock(&svcpt->scp_lock);

		ptlrpc_wait_replies(svcpt);

		while ((rs = list_first_entry_or_null(&svcpt->scp_rep_idle,
						      struct ptlrpc_reply_state,
						      rs_list)) != NULL) {
			list_del(&rs->rs_list);
			OBD_FREE_LARGE(rs, svc->srv_max_reply_size);
		}
	}
}

static void
ptlrpc_service_free(struct ptlrpc_service *svc)
{
	struct ptlrpc_service_part	*svcpt;
	struct ptlrpc_at_array		*array;
	int				i;

	ptlrpc_service_for_each_part(svcpt, i, svc) {
		if (svcpt->scp_service == NULL)
			break;

		/* In case somebody rearmed this in the meantime */
		timer_delete(&svcpt->scp_at_timer);
		array = &svcpt->scp_at_array;

		if (array->paa_reqs_array != NULL) {
			OBD_FREE_PTR_ARRAY(array->paa_reqs_array,
					   array->paa_size);
			array->paa_reqs_array = NULL;
		}

		if (array->paa_reqs_count != NULL) {
			OBD_FREE_PTR_ARRAY(array->paa_reqs_count,
					   array->paa_size);
			array->paa_reqs_count = NULL;
		}
	}

	ptlrpc_service_for_each_part(svcpt, i, svc)
		OBD_FREE_PTR(svcpt);

	if (svc->srv_cpts != NULL)
		cfs_expr_list_values_free(svc->srv_cpts, svc->srv_ncpts);

	OBD_FREE(svc, offsetof(struct ptlrpc_service,
			       srv_parts[svc->srv_ncpts]));
}

int ptlrpc_unregister_service(struct ptlrpc_service *service)
{
	ENTRY;

	CDEBUG(D_NET, "%s: tearing down\n", service->srv_name);

	service->srv_is_stopping = 1;

	mutex_lock(&ptlrpc_all_services_mutex);
	list_del_init(&service->srv_list);
	mutex_unlock(&ptlrpc_all_services_mutex);

	ptlrpc_service_del_atimer(service);
	ptlrpc_stop_all_threads(service);

	ptlrpc_service_unlink_rqbd(service);
	ptlrpc_service_purge_all(service);
	ptlrpc_service_nrs_cleanup(service);

	ptlrpc_lprocfs_unregister_service(service);
	ptlrpc_sysfs_unregister_service(service);

	ptlrpc_service_free(service);

	RETURN(0);
}
EXPORT_SYMBOL(ptlrpc_unregister_service);

/**
 * ptlrpc_svcpt_health_check() - checks the health of a PTLRPC service
 * @svcpt: PTLRPC service partition structure to be cecked for health
 *
 * Check whether requests have been waiting in the queue for an excessive
 * time without being processed.  Individual requests may wait in the queue
 * for some time due to NRS policies, overloaded storage, etc. but the queue
 * itself should continue to process some requests on a regular basis.
 *
 * We'll use this health check to govern whether a node needs to be shot,
 * so it's intentionally non-aggressive.
 *
 * Returns:
 * * %0 if the service is healthy.
 * * %negative if the service is not healthy.
 */
static int ptlrpc_svcpt_health_check(struct ptlrpc_service_part *svcpt)
{
	struct ptlrpc_request *request = NULL;
	struct obd_device *obd = NULL;
	time64_t right_now;
	time64_t req_waited;
	time64_t svc_waited;
	bool recovering;
	unsigned int max;

	/* quick check without locking to handle the most common case */
	right_now = ktime_get_real_seconds();
	if (likely(right_now - svcpt->scp_last_request < obd_get_at_max(NULL)))
		return 0;

	spin_lock(&svcpt->scp_req_lock);
	if (ptlrpc_server_high_pending(svcpt, true))
		request = ptlrpc_nrs_req_peek_nolock(svcpt, true);
	else if (ptlrpc_server_normal_pending(svcpt, true))
		request = ptlrpc_nrs_req_peek_nolock(svcpt, false);

	/* if no waiting requests, service idle time is irrelevant */
	if (request == NULL) {
		spin_unlock(&svcpt->scp_req_lock);
		return 0;
	}

	if (request->rq_export)
		obd = request->rq_export->exp_obd;

	req_waited = right_now - request->rq_arrival_time.tv_sec;
	svc_waited = right_now - svcpt->scp_last_request;
	recovering = obd ? test_bit(OBDF_RECOVERING, obd->obd_flags) : false;
	spin_unlock(&svcpt->scp_req_lock);

	max = obd_get_at_max(obd);
	if (min(req_waited, svc_waited) > max && !recovering) {
		bool unhealthy = false;

		/* if at_unhealthy_factor = 0 then disable unhealthy status but
		 * at least print a warning if requests are stuck for a while
		 */
		if (obd_get_at_unhealthy_factor(obd) &&
		    svc_waited > max * obd_get_at_unhealthy_factor(obd)) {
			/* check if other CPTs in svc also unhealthy? */
			unhealthy = true;
		}

		CDEBUG_LIMIT(unhealthy ? D_ERROR : D_WARNING,
			     "%s: %s - request waiting %llus, service %llus\n",
			     obd ? obd->obd_name : svcpt->scp_service->srv_name,
			     unhealthy ? "unhealthy" : "notice",
			     req_waited, svc_waited);
		if (unhealthy)
			return -1;
	}

	return 0;
}

int
ptlrpc_service_health_check(struct ptlrpc_service *svc)
{
	struct ptlrpc_service_part	*svcpt;
	int				i;

	if (svc == NULL)
		return 0;

	ptlrpc_service_for_each_part(svcpt, i, svc) {
		int rc = ptlrpc_svcpt_health_check(svcpt);

		if (rc != 0)
			return rc;
	}
	return 0;
}
EXPORT_SYMBOL(ptlrpc_service_health_check);

int
ptlrpc_server_get_timeout(struct ptlrpc_service_part *svcpt)
{
	int at = 0;

	if (!obd_at_off(NULL))
		at = obd_at_get(NULL, &svcpt->scp_at_estimate);

	return svcpt->scp_service->srv_watchdog_factor *
	       max_t(int, at, obd_timeout);
}
