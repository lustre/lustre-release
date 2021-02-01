/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Cray Inc. All Rights Reserved.
 *
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * lustre/ptlrpc/nrs_delay.c
 *
 * Network Request Scheduler (NRS) Delay policy
 *
 * This policy will delay request handling for some configurable amount of
 * time.
 *
 * Author: Chris Horn <hornc@cray.com>
 */
/**
 * \addtogoup nrs
 * @{
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/random.h>

#include <obd_support.h>
#include <obd_class.h>
#include "ptlrpc_internal.h"

/**
 * \name delay
 *
 * The delay policy schedules RPCs so that they are only processed after some
 * configurable amount of time (in seconds) has passed.
 *
 * The defaults were chosen arbitrarily.
 *
 * @{
 */

#define NRS_POL_NAME_DELAY	"delay"

/* Default minimum delay in seconds. */
#define NRS_DELAY_MIN_DEFAULT	5
/* Default maximum delay, in seconds. */
#define NRS_DELAY_MAX_DEFAULT	300
/* Default percentage of delayed RPCs. */
#define NRS_DELAY_PCT_DEFAULT	100

/**
 * Binary heap predicate.
 *
 * Elements are sorted according to the start time assigned to the requests
 * upon enqueue. An element with an earlier start time is "less than" an
 * element with a later start time.
 *
 * \retval 0 start_time(e1) > start_time(e2)
 * \retval 1 start_time(e1) <= start_time(e2)
 */
static int delay_req_compare(struct binheap_node *e1,
			     struct binheap_node *e2)
{
	struct ptlrpc_nrs_request *nrq1;
	struct ptlrpc_nrs_request *nrq2;

	nrq1 = container_of(e1, struct ptlrpc_nrs_request, nr_node);
	nrq2 = container_of(e2, struct ptlrpc_nrs_request, nr_node);

	return nrq1->nr_u.delay.req_start_time <=
	       nrq2->nr_u.delay.req_start_time;
}

static struct binheap_ops nrs_delay_heap_ops = {
	.hop_enter	= NULL,
	.hop_exit	= NULL,
	.hop_compare	= delay_req_compare,
};

/**
 * Is called before the policy transitions into
 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STARTED; allocates and initializes
 * the delay-specific private data structure.
 *
 * \param[in] policy The policy to start
 * \param[in] Generic char buffer; unused in this policy
 *
 * \retval -ENOMEM OOM error
 * \retval  0	   success
 *
 * \see nrs_policy_register()
 * \see nrs_policy_ctl()
 */
static int nrs_delay_start(struct ptlrpc_nrs_policy *policy, char *arg)
{
	struct nrs_delay_data *delay_data;

	ENTRY;

	OBD_CPT_ALLOC_PTR(delay_data, nrs_pol2cptab(policy),
			  nrs_pol2cptid(policy));
	if (delay_data == NULL)
		RETURN(-ENOMEM);

	delay_data->delay_binheap = binheap_create(&nrs_delay_heap_ops,
						       CBH_FLAG_ATOMIC_GROW,
						       4096, NULL,
						       nrs_pol2cptab(policy),
						       nrs_pol2cptid(policy));

	if (delay_data->delay_binheap == NULL) {
		OBD_FREE_PTR(delay_data);
		RETURN(-ENOMEM);
	}

	delay_data->min_delay = NRS_DELAY_MIN_DEFAULT;
	delay_data->max_delay = NRS_DELAY_MAX_DEFAULT;
	delay_data->delay_pct = NRS_DELAY_PCT_DEFAULT;

	policy->pol_private = delay_data;

	RETURN(0);
}

/**
 * Is called before the policy transitions into
 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED; deallocates the delay-specific
 * private data structure.
 *
 * \param[in] policy The policy to stop
 *
 * \see nrs_policy_stop0()
 */
static void nrs_delay_stop(struct ptlrpc_nrs_policy *policy)
{
	struct nrs_delay_data *delay_data = policy->pol_private;

	LASSERT(delay_data != NULL);
	LASSERT(delay_data->delay_binheap != NULL);
	LASSERT(binheap_is_empty(delay_data->delay_binheap));

	binheap_destroy(delay_data->delay_binheap);

	OBD_FREE_PTR(delay_data);
}

/**
 * Is called for obtaining a delay policy resource.
 *
 * \param[in]  policy	  The policy on which the request is being asked for
 * \param[in]  nrq	  The request for which resources are being taken
 * \param[in]  parent	  Parent resource, unused in this policy
 * \param[out] resp	  Resources references are placed in this array
 * \param[in]  moving_req Signifies limited caller context; unused in this
 *			  policy
 *
 * \retval 1 The delay policy only has a one-level resource hierarchy
 *
 * \see nrs_resource_get_safe()
 */
static int nrs_delay_res_get(struct ptlrpc_nrs_policy *policy,
			     struct ptlrpc_nrs_request *nrq,
			     const struct ptlrpc_nrs_resource *parent,
			     struct ptlrpc_nrs_resource **resp, bool moving_req)
{
	/**
	 * Just return the resource embedded inside nrs_delay_data, and end this
	 * resource hierarchy reference request.
	 */
	*resp = &((struct nrs_delay_data *)policy->pol_private)->delay_res;
	return 1;
}

/**
 * Called when getting a request from the delay policy for handling, or just
 * peeking; removes the request from the policy when it is to be handled.
 * Requests are only removed from this policy when their start time has
 * passed.
 *
 * \param[in] policy The policy
 * \param[in] peek   When set, signifies that we just want to examine the
 *		     request, and not handle it, so the request is not removed
 *		     from the policy.
 * \param[in] force  Force the policy to return a request
 *
 * \retval The request to be handled
 * \retval NULL no request available
 *
 * \see ptlrpc_nrs_req_get_nolock()
 * \see nrs_request_get()
 */
static
struct ptlrpc_nrs_request *nrs_delay_req_get(struct ptlrpc_nrs_policy *policy,
					     bool peek, bool force)
{
	struct nrs_delay_data *delay_data = policy->pol_private;
	struct binheap_node *node;
	struct ptlrpc_nrs_request *nrq;

	node = binheap_root(delay_data->delay_binheap);
	nrq = unlikely(node == NULL) ? NULL :
	      container_of(node, struct ptlrpc_nrs_request, nr_node);

	if (likely(nrq != NULL)) {
		if (!force &&
		    ktime_get_real_seconds() < nrq->nr_u.delay.req_start_time)
			nrq = NULL;
		else if (likely(!peek))
			binheap_remove(delay_data->delay_binheap,
					   &nrq->nr_node);
	}

	return nrq;
}

/**
 * Adds request \a nrq to a delay \a policy instance's set of queued requests
 *
 * A percentage (delay_pct) of incoming requests are delayed by this policy.
 * If selected for delay a request start time is calculated. A start time
 * is the current time plus a random offset in the range [min_delay, max_delay]
 * The start time is recorded in the request, and is then used by
 * delay_req_compare() to maintain a set of requests ordered by their start
 * times.
 *
 * \param[in] policy The policy
 * \param[in] nrq    The request to add
 *
 * \retval 0 request added
 * \retval 1 request not added
 *
 */
static int nrs_delay_req_add(struct ptlrpc_nrs_policy *policy,
			     struct ptlrpc_nrs_request *nrq)
{
	struct nrs_delay_data *delay_data = policy->pol_private;

	if (delay_data->delay_pct == 0 || /* Not delaying anything */
	    (delay_data->delay_pct != 100 &&
	     delay_data->delay_pct < prandom_u32_max(100)))
		return 1;

	nrq->nr_u.delay.req_start_time = ktime_get_real_seconds() +
					 prandom_u32_max(delay_data->max_delay - delay_data->min_delay + 1) +
					 delay_data->min_delay;

	return binheap_insert(delay_data->delay_binheap, &nrq->nr_node);
}

/**
 * Removes request \a nrq from \a policy's list of queued requests.
 *
 * \param[in] policy The policy
 * \param[in] nrq    The request to remove
 */
static void nrs_delay_req_del(struct ptlrpc_nrs_policy *policy,
			      struct ptlrpc_nrs_request *nrq)
{
	struct nrs_delay_data *delay_data = policy->pol_private;

	binheap_remove(delay_data->delay_binheap, &nrq->nr_node);
}

/**
 * Prints a debug statement right before the request \a nrq stops being
 * handled.
 *
 * \param[in] policy The policy handling the request
 * \param[in] nrq    The request being handled
 *
 * \see ptlrpc_server_finish_request()
 * \see ptlrpc_nrs_req_stop_nolock()
 */
static void nrs_delay_req_stop(struct ptlrpc_nrs_policy *policy,
			       struct ptlrpc_nrs_request *nrq)
{
	struct ptlrpc_request *req = container_of(nrq, struct ptlrpc_request,
						  rq_nrq);

	DEBUG_REQ(D_RPCTRACE, req,
		  "NRS: finished delayed request from %s after %llds",
		  libcfs_id2str(req->rq_peer),
		  (s64)(nrq->nr_u.delay.req_start_time -
			req->rq_srv.sr_arrival_time.tv_sec));
}

/**
 * Performs ctl functions specific to delay policy instances; similar to ioctl
 *
 * \param[in]     policy the policy instance
 * \param[in]     opc    the opcode
 * \param[in,out] arg    used for passing parameters and information
 *
 * \pre assert_spin_locked(&policy->pol_nrs->->nrs_lock)
 * \post assert_spin_locked(&policy->pol_nrs->->nrs_lock)
 *
 * \retval 0   operation carried out successfully
 * \retval -ve error
 */
static int nrs_delay_ctl(struct ptlrpc_nrs_policy *policy,
			 enum ptlrpc_nrs_ctl opc, void *arg)
{
	struct nrs_delay_data *delay_data = policy->pol_private;
	__u32 *val = (__u32 *)arg;

	assert_spin_locked(&policy->pol_nrs->nrs_lock);

	switch ((enum nrs_ctl_delay)opc) {
	default:
		RETURN(-EINVAL);

	case NRS_CTL_DELAY_RD_MIN:
		*val = delay_data->min_delay;
		break;

	case NRS_CTL_DELAY_WR_MIN:
		if (*val > delay_data->max_delay)
			RETURN(-EINVAL);

		delay_data->min_delay = *val;
		break;

	case NRS_CTL_DELAY_RD_MAX:
		*val = delay_data->max_delay;
		break;

	case NRS_CTL_DELAY_WR_MAX:
		if (*val < delay_data->min_delay)
			RETURN(-EINVAL);

		delay_data->max_delay = *val;
		break;

	case NRS_CTL_DELAY_RD_PCT:
		*val = delay_data->delay_pct;
		break;

	case NRS_CTL_DELAY_WR_PCT:
		if (*val < 0 || *val > 100)
			RETURN(-EINVAL);

		delay_data->delay_pct = *val;
		break;
	}
	RETURN(0);
}

/**
 * debugfs interface
 */

/* nrs_delay_min and nrs_delay_max are bounded by these values */
#define LPROCFS_NRS_DELAY_LOWER_BOUND		0
#define LPROCFS_NRS_DELAY_UPPER_BOUND		65535

#define LPROCFS_NRS_DELAY_MIN_NAME		"delay_min:"
#define LPROCFS_NRS_DELAY_MIN_NAME_REG		"reg_delay_min:"
#define LPROCFS_NRS_DELAY_MIN_NAME_HP		"hp_delay_min:"

/**
 * Max size of the nrs_delay_min seq_write buffer. Needs to be large enough
 * to hold the string: "reg_min_delay:65535 hp_min_delay:65535"
 */
#define LPROCFS_NRS_DELAY_MIN_SIZE					       \
	sizeof(LPROCFS_NRS_DELAY_MIN_NAME_REG				       \
	       __stringify(LPROCFS_NRS_DELAY_UPPER_BOUND)		       \
	       " " LPROCFS_NRS_DELAY_MIN_NAME_HP			       \
	       __stringify(LPROCFS_NRS_DELAY_UPPER_BOUND))

#define LPROCFS_NRS_DELAY_MAX_NAME		"delay_max:"
#define LPROCFS_NRS_DELAY_MAX_NAME_REG		"reg_delay_max:"
#define LPROCFS_NRS_DELAY_MAX_NAME_HP		"hp_delay_max:"

/**
 * Similar to LPROCFS_NRS_DELAY_MIN_SIZE above, but for the nrs_delay_max
 * variable.
 */
#define LPROCFS_NRS_DELAY_MAX_SIZE					       \
	sizeof(LPROCFS_NRS_DELAY_MAX_NAME_REG				       \
	       __stringify(LPROCFS_NRS_DELAY_UPPER_BOUND)		       \
	       " " LPROCFS_NRS_DELAY_MAX_NAME_HP			       \
	       __stringify(LPROCFS_NRS_DELAY_UPPER_BOUND))

#define LPROCFS_NRS_DELAY_PCT_MIN_VAL		0
#define LPROCFS_NRS_DELAY_PCT_MAX_VAL		100
#define LPROCFS_NRS_DELAY_PCT_NAME		"delay_pct:"
#define LPROCFS_NRS_DELAY_PCT_NAME_REG		"reg_delay_pct:"
#define LPROCFS_NRS_DELAY_PCT_NAME_HP		"hp_delay_pct:"

/**
 * Similar to LPROCFS_NRS_DELAY_MIN_SIZE above, but for the nrs_delay_pct
 * variable.
 */
#define LPROCFS_NRS_DELAY_PCT_SIZE					       \
	sizeof(LPROCFS_NRS_DELAY_PCT_NAME_REG				       \
	       __stringify(LPROCFS_NRS_DELAY_PCT_MAX_VAL)		       \
	       " " LPROCFS_NRS_DELAY_PCT_NAME_HP			       \
	       __stringify(LPROCFS_NRS_DELAY_PCT_MAX_VAL))

/**
 * Helper for delay's seq_write functions.
 */
static ssize_t
lprocfs_nrs_delay_seq_write_common(const char __user *buffer,
				   unsigned int bufsize, size_t count,
				   const char *var_name, unsigned int min_val,
				   unsigned int max_val,
				   struct ptlrpc_service *svc, char *pol_name,
				   enum ptlrpc_nrs_ctl opc, bool single)
{
	enum ptlrpc_nrs_queue_type queue = 0;
	char *kernbuf;
	char *val_str;
	long unsigned int val_reg;
	long unsigned int val_hp;
	size_t count_copy;
	int rc = 0;
	char *tmp = NULL;
	int tmpsize = 0;

	if (count > bufsize - 1)
		return -EINVAL;

	OBD_ALLOC(kernbuf, bufsize);
	if (kernbuf == NULL)
		return -ENOMEM;

	if (copy_from_user(kernbuf, buffer, count))
		GOTO(free_kernbuf, rc = -EFAULT);

	tmpsize = strlen("reg_") + strlen(var_name) + 1;
	OBD_ALLOC(tmp, tmpsize);
	if (tmp == NULL)
		GOTO(free_tmp, rc = -ENOMEM);

	/* look for "reg_<var_name>" in kernbuf */
	snprintf(tmp, tmpsize, "reg_%s", var_name);
	count_copy = count;
	val_str = lprocfs_find_named_value(kernbuf, tmp, &count_copy);
	if (val_str != kernbuf) {
		rc = kstrtoul(val_str, 10, &val_reg);
		if (rc != 0)
			GOTO(free_tmp, rc = -EINVAL);
		queue |= PTLRPC_NRS_QUEUE_REG;
	}

	/* look for "hp_<var_name>" in kernbuf */
	snprintf(tmp, tmpsize, "hp_%s", var_name);
	count_copy = count;
	val_str = lprocfs_find_named_value(kernbuf, tmp, &count_copy);
	if (val_str != kernbuf) {
		if (!nrs_svc_has_hp(svc))
			GOTO(free_tmp, rc = -ENODEV);

		rc = kstrtoul(val_str, 10, &val_hp);
		if (rc != 0)
			GOTO(free_tmp, rc = -EINVAL);
		queue |= PTLRPC_NRS_QUEUE_HP;
	}

	if (queue == 0) {
		if (!isdigit(kernbuf[0]))
			GOTO(free_tmp, rc = -EINVAL);

		rc = kstrtoul(kernbuf, 10, &val_reg);
		if (rc != 0)
			GOTO(free_tmp, rc = -EINVAL);

		queue = PTLRPC_NRS_QUEUE_REG;

		if (nrs_svc_has_hp(svc)) {
			queue |= PTLRPC_NRS_QUEUE_HP;
			val_hp = val_reg;
		}
	}

	if (queue & PTLRPC_NRS_QUEUE_REG) {
		if (val_reg > max_val || val_reg < min_val)
			GOTO(free_tmp, rc = -EINVAL);

		rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
					       pol_name, opc, single, &val_reg);
		if ((rc < 0 && rc != -ENODEV) ||
		    (rc == -ENODEV && queue == PTLRPC_NRS_QUEUE_REG))
			GOTO(free_tmp, rc);
	}

	if (queue & PTLRPC_NRS_QUEUE_HP) {
		int rc2 = 0;
		if (val_hp > max_val || val_hp < min_val)
			GOTO(free_tmp, rc = -EINVAL);

		rc2 = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
						pol_name, opc, single, &val_hp);
		if ((rc2 < 0 && rc2 != -ENODEV) ||
		    (rc2 == -ENODEV && queue == PTLRPC_NRS_QUEUE_HP))
			GOTO(free_tmp, rc = rc2);
	}

	/* If we've reached here then we want to return count */
	rc = count;

free_tmp:
	OBD_FREE(tmp, tmpsize);
free_kernbuf:
	OBD_FREE(kernbuf, bufsize);

	return rc;
}

/**
 * Retrieves the value of the minimum delay for delay policy instances on both
 * the regular and high-priority NRS head of a service, as long as a policy
 * instance is not in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state;
 */
static int
ptlrpc_lprocfs_nrs_delay_min_seq_show(struct seq_file *m, void *data)
{
	struct ptlrpc_service *svc = m->private;
	unsigned int min_delay;
	int rc;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
				       NRS_POL_NAME_DELAY,
				       NRS_CTL_DELAY_RD_MIN,
				       true, &min_delay);

	if (rc == 0)
		seq_printf(m, LPROCFS_NRS_DELAY_MIN_NAME_REG"%-5d\n",
			   min_delay);
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in
		 * the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	else if (rc != -ENODEV)
		return rc;

	if (!nrs_svc_has_hp(svc))
		return 0;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
				       NRS_POL_NAME_DELAY,
				       NRS_CTL_DELAY_RD_MIN,
				       true, &min_delay);
	if (rc == 0)
		seq_printf(m, LPROCFS_NRS_DELAY_MIN_NAME_HP"%-5d\n",
			   min_delay);
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in
		 * the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	else if (rc == -ENODEV)
		rc = 0;

	return rc;
}

/**
 * Sets the value of the minimum request delay for delay policy instances of a
 * service. The user can set the minimum request delay for the regular or high
 * priority NRS head individually by specifying each value, or both together in
 * a single invocation.
 *
 * For example:
 *
 * lctl set_param *.*.*.nrs_delay_min=reg_delay_min:5, to set the regular
 * request minimum delay on all PtlRPC services to 5 seconds
 *
 * lctl set_param *.*.*.nrs_delay_min=hp_delay_min:2, to set the high-priority
 * request minimum delay on all PtlRPC services to 2 seconds, and
 *
 * lctl set_param *.*.ost_io.nrs_delay_min=8, to set both the regular and
 * high priority request minimum delay of the ost_io service to 8 seconds.
 */
static ssize_t
ptlrpc_lprocfs_nrs_delay_min_seq_write(struct file *file,
				       const char __user *buffer, size_t count,
				       loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct ptlrpc_service *svc = m->private;

	return lprocfs_nrs_delay_seq_write_common(buffer,
						  LPROCFS_NRS_DELAY_MIN_SIZE,
						  count,
						  LPROCFS_NRS_DELAY_MIN_NAME,
						  LPROCFS_NRS_DELAY_LOWER_BOUND,
						  LPROCFS_NRS_DELAY_UPPER_BOUND,
						  svc, NRS_POL_NAME_DELAY,
						  NRS_CTL_DELAY_WR_MIN, false);
}
LDEBUGFS_SEQ_FOPS(ptlrpc_lprocfs_nrs_delay_min);

/**
 * Retrieves the value of the maximum delay for delay policy instances on both
 * the regular and high-priority NRS head of a service, as long as a policy
 * instance is not in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state;
 */
static int
ptlrpc_lprocfs_nrs_delay_max_seq_show(struct seq_file *m, void *data)
{
	struct ptlrpc_service *svc = m->private;
	unsigned int max_delay;
	int rc;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
				       NRS_POL_NAME_DELAY,
				       NRS_CTL_DELAY_RD_MAX,
				       true, &max_delay);

	if (rc == 0)
		seq_printf(m, LPROCFS_NRS_DELAY_MAX_NAME_REG"%-5d\n",
			   max_delay);
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in
		 * the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	else if (rc != -ENODEV)
		return rc;

	if (!nrs_svc_has_hp(svc))
		return 0;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
				       NRS_POL_NAME_DELAY,
				       NRS_CTL_DELAY_RD_MAX,
				       true, &max_delay);
	if (rc == 0)
		seq_printf(m, LPROCFS_NRS_DELAY_MAX_NAME_HP"%-5d\n",
			   max_delay);
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in
		 * the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	else if (rc == -ENODEV)
		rc = 0;

	return rc;
}

/**
 * Sets the value of the maximum request delay for delay policy instances of a
 * service. The user can set the maximum request delay for the regular or high
 * priority NRS head individually by specifying each value, or both together in
 * a single invocation.
 *
 * For example:
 *
 * lctl set_param *.*.*.nrs_delay_max=reg_delay_max:20, to set the regular
 * request maximum delay on all PtlRPC services to 20 seconds
 *
 * lctl set_param *.*.*.nrs_delay_max=hp_delay_max:10, to set the high-priority
 * request maximum delay on all PtlRPC services to 10 seconds, and
 *
 * lctl set_param *.*.ost_io.nrs_delay_max=35, to set both the regular and
 * high priority request maximum delay of the ost_io service to 35 seconds.
 */
static ssize_t
ptlrpc_lprocfs_nrs_delay_max_seq_write(struct file *file,
				       const char __user *buffer, size_t count,
				       loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct ptlrpc_service *svc = m->private;

	return lprocfs_nrs_delay_seq_write_common(buffer,
						  LPROCFS_NRS_DELAY_MAX_SIZE,
						  count,
						  LPROCFS_NRS_DELAY_MAX_NAME,
						  LPROCFS_NRS_DELAY_LOWER_BOUND,
						  LPROCFS_NRS_DELAY_UPPER_BOUND,
						  svc, NRS_POL_NAME_DELAY,
						  NRS_CTL_DELAY_WR_MAX, false);
}
LDEBUGFS_SEQ_FOPS(ptlrpc_lprocfs_nrs_delay_max);

/**
 * Retrieves the value of the percentage of requests which should be delayed
 * for delay policy instances on both the regular and high-priority NRS head
 * of a service, as long as a policy instance is not in the
 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state;
 */
static int
ptlrpc_lprocfs_nrs_delay_pct_seq_show(struct seq_file *m, void *data)
{
	struct ptlrpc_service *svc = m->private;
	unsigned int delay_pct;
	int rc;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
				       NRS_POL_NAME_DELAY,
				       NRS_CTL_DELAY_RD_PCT,
				       true, &delay_pct);

	if (rc == 0)
		seq_printf(m, LPROCFS_NRS_DELAY_PCT_NAME_REG"%-3d\n",
			   delay_pct);
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in
		 * the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	else if (rc != -ENODEV)
		return rc;

	if (!nrs_svc_has_hp(svc))
		return 0;

	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
				       NRS_POL_NAME_DELAY,
				       NRS_CTL_DELAY_RD_PCT,
				       true, &delay_pct);
	if (rc == 0)
		seq_printf(m, LPROCFS_NRS_DELAY_PCT_NAME_HP"%-3d\n",
			   delay_pct);
		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in
		 * the ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	else if (rc == -ENODEV)
		rc = 0;

	return rc;
}

/**
 * Sets the value of the percentage of requests to be delayed for delay policy
 * instances of a service. The user can set the percentage for the regular or
 * high-priority NRS head individually by specifying each value, or both
 * together in a single invocation.
 *
 * For example:
 *
 * lctl set_param *.*.*.nrs_delay_pct=reg_delay_pct:5, to delay 5 percent of
 * regular requests on all PtlRPC services
 *
 * lctl set_param *.*.*.nrs_delay_pct=hp_delay_pct:2, to delay 2 percent of
 * high-priority requests on all PtlRPC services, and
 *
 * lctl set_param *.*.ost_io.nrs_delay_pct=8, to delay 8 percent of both
 * regular and high-priority requests of the ost_io service.
 */
static ssize_t
ptlrpc_lprocfs_nrs_delay_pct_seq_write(struct file *file,
				       const char __user *buffer, size_t count,
				       loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct ptlrpc_service *svc = m->private;

	return lprocfs_nrs_delay_seq_write_common(buffer,
						  LPROCFS_NRS_DELAY_PCT_SIZE,
						  count,
						  LPROCFS_NRS_DELAY_PCT_NAME,
						  LPROCFS_NRS_DELAY_PCT_MIN_VAL,
						  LPROCFS_NRS_DELAY_PCT_MAX_VAL,
						  svc, NRS_POL_NAME_DELAY,
						  NRS_CTL_DELAY_WR_PCT, false);
}

LDEBUGFS_SEQ_FOPS(ptlrpc_lprocfs_nrs_delay_pct);

static int nrs_delay_lprocfs_init(struct ptlrpc_service *svc)
{
	struct ldebugfs_vars nrs_delay_lprocfs_vars[] = {
		{ .name		= "nrs_delay_min",
		  .fops		= &ptlrpc_lprocfs_nrs_delay_min_fops,
		  .data		= svc },
		{ .name		= "nrs_delay_max",
		  .fops		= &ptlrpc_lprocfs_nrs_delay_max_fops,
		  .data		= svc },
		{ .name		= "nrs_delay_pct",
		  .fops		= &ptlrpc_lprocfs_nrs_delay_pct_fops,
		  .data		= svc },
		{ NULL }
	};

	if (!svc->srv_debugfs_entry)
		return 0;

	ldebugfs_add_vars(svc->srv_debugfs_entry, nrs_delay_lprocfs_vars, NULL);

	return 0;
}

/**
 * Delay policy operations
 */
static const struct ptlrpc_nrs_pol_ops nrs_delay_ops = {
	.op_policy_start	= nrs_delay_start,
	.op_policy_stop		= nrs_delay_stop,
	.op_policy_ctl		= nrs_delay_ctl,
	.op_res_get		= nrs_delay_res_get,
	.op_req_get		= nrs_delay_req_get,
	.op_req_enqueue		= nrs_delay_req_add,
	.op_req_dequeue		= nrs_delay_req_del,
	.op_req_stop		= nrs_delay_req_stop,
	.op_lprocfs_init	= nrs_delay_lprocfs_init,
};

/**
 * Delay policy configuration
 */
struct ptlrpc_nrs_pol_conf nrs_conf_delay = {
	.nc_name		= NRS_POL_NAME_DELAY,
	.nc_ops			= &nrs_delay_ops,
	.nc_compat		= nrs_policy_compat_all,
};

/** @} delay */

/** @} nrs */
