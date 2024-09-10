// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/ */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/ctype.h>
#include <linux/generic-radix-tree.h>
#include <linux/log2.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/signal.h>
#endif
#include <net/genetlink.h>

#include <libcfs/linux/linux-net.h>
#include <lnet/udsp.h>
#include <lnet/lib-lnet.h>

#define D_LNI D_CONSOLE

/*
 * initialize ln_api_mutex statically, since it needs to be used in
 * discovery_set callback. That module parameter callback can be called
 * before module init completes. The mutex needs to be ready for use then.
 */
struct lnet the_lnet = {
	.ln_api_mutex = __MUTEX_INITIALIZER(the_lnet.ln_api_mutex),
};		/* THE state of the network */
EXPORT_SYMBOL(the_lnet);

static char *ip2nets = "";
module_param(ip2nets, charp, 0444);
MODULE_PARM_DESC(ip2nets, "LNET network <- IP table");

static char *networks = "";
module_param(networks, charp, 0444);
MODULE_PARM_DESC(networks, "local networks");

static char *routes = "";
module_param(routes, charp, 0444);
MODULE_PARM_DESC(routes, "routes to non-local networks");

static int rnet_htable_size = LNET_REMOTE_NETS_HASH_DEFAULT;
module_param(rnet_htable_size, int, 0444);
MODULE_PARM_DESC(rnet_htable_size, "size of remote network hash table");

static int use_tcp_bonding;
module_param(use_tcp_bonding, int, 0444);
MODULE_PARM_DESC(use_tcp_bonding,
		 "use_tcp_bonding parameter has been removed");

unsigned int lnet_numa_range = 0;
module_param(lnet_numa_range, uint, 0444);
MODULE_PARM_DESC(lnet_numa_range,
		"NUMA range to consider during Multi-Rail selection");

/*
 * lnet_health_sensitivity determines by how much we decrement the health
 * value on sending error. The value defaults to 100, which means health
 * interface health is decremented by 100 points every failure.
 */
unsigned int lnet_health_sensitivity = 100;
static int sensitivity_set(const char *val, cfs_kernel_param_arg_t *kp);
#ifdef HAVE_KERNEL_PARAM_OPS
static struct kernel_param_ops param_ops_health_sensitivity = {
	.set = sensitivity_set,
	.get = param_get_int,
};
#define param_check_health_sensitivity(name, p) \
		__param_check(name, p, int)
module_param(lnet_health_sensitivity, health_sensitivity, S_IRUGO|S_IWUSR);
#else
module_param_call(lnet_health_sensitivity, sensitivity_set, param_get_int,
		  &lnet_health_sensitivity, S_IRUGO|S_IWUSR);
#endif
MODULE_PARM_DESC(lnet_health_sensitivity,
		"Value to decrement the health value by on error");

/*
 * lnet_recovery_interval determines how often we should perform recovery
 * on unhealthy interfaces.
 */
unsigned int lnet_recovery_interval = 1;
static int recovery_interval_set(const char *val, cfs_kernel_param_arg_t *kp);
#ifdef HAVE_KERNEL_PARAM_OPS
static struct kernel_param_ops param_ops_recovery_interval = {
	.set = recovery_interval_set,
	.get = param_get_int,
};
#define param_check_recovery_interval(name, p) \
		__param_check(name, p, int)
module_param(lnet_recovery_interval, recovery_interval, S_IRUGO|S_IWUSR);
#else
module_param_call(lnet_recovery_interval, recovery_interval_set, param_get_int,
		  &lnet_recovery_interval, S_IRUGO|S_IWUSR);
#endif
MODULE_PARM_DESC(lnet_recovery_interval,
		"DEPRECATED - Interval to recover unhealthy interfaces in seconds");

unsigned int lnet_recovery_limit;
module_param(lnet_recovery_limit, uint, 0644);
MODULE_PARM_DESC(lnet_recovery_limit,
		 "How long to attempt recovery of unhealthy peer interfaces in seconds. Set to 0 to allow indefinite recovery");

unsigned int lnet_max_recovery_ping_interval = 900;
unsigned int lnet_max_recovery_ping_count = 9;
static int max_recovery_ping_interval_set(const char *val,
					  cfs_kernel_param_arg_t *kp);

#define param_check_max_recovery_ping_interval(name, p) \
		__param_check(name, p, int)

#ifdef HAVE_KERNEL_PARAM_OPS
static struct kernel_param_ops param_ops_max_recovery_ping_interval = {
	.set = max_recovery_ping_interval_set,
	.get = param_get_int,
};
module_param(lnet_max_recovery_ping_interval, max_recovery_ping_interval, 0644);
#else
module_param_call(lnet_max_recovery_ping_interval, max_recovery_ping_interval,
		  param_get_int, &lnet_max_recovery_ping_interval, 0644);
#endif
MODULE_PARM_DESC(lnet_max_recovery_ping_interval,
		 "The max interval between LNet recovery pings, in seconds");

static int lnet_interfaces_max = LNET_INTERFACES_MAX_DEFAULT;
static int intf_max_set(const char *val, cfs_kernel_param_arg_t *kp);

static struct kernel_param_ops param_ops_interfaces_max = {
	.set = intf_max_set,
	.get = param_get_int,
};

#define param_check_interfaces_max(name, p) \
		__param_check(name, p, int)

#ifdef HAVE_KERNEL_PARAM_OPS
module_param(lnet_interfaces_max, interfaces_max, 0644);
#else
module_param_call(lnet_interfaces_max, intf_max_set, param_get_int,
		  &param_ops_interfaces_max, 0644);
#endif
MODULE_PARM_DESC(lnet_interfaces_max,
		"Maximum number of interfaces in a node.");

unsigned lnet_peer_discovery_disabled = 0;
static int discovery_set(const char *val, cfs_kernel_param_arg_t *kp);

static struct kernel_param_ops param_ops_discovery_disabled = {
	.set = discovery_set,
	.get = param_get_int,
};

#define param_check_discovery_disabled(name, p) \
		__param_check(name, p, int)
#ifdef HAVE_KERNEL_PARAM_OPS
module_param(lnet_peer_discovery_disabled, discovery_disabled, 0644);
#else
module_param_call(lnet_peer_discovery_disabled, discovery_set, param_get_int,
		  &param_ops_discovery_disabled, 0644);
#endif
MODULE_PARM_DESC(lnet_peer_discovery_disabled,
		"Set to 1 to disable peer discovery on this node.");

unsigned int lnet_drop_asym_route;
static int drop_asym_route_set(const char *val, cfs_kernel_param_arg_t *kp);

static struct kernel_param_ops param_ops_drop_asym_route = {
	.set = drop_asym_route_set,
	.get = param_get_int,
};

#define param_check_drop_asym_route(name, p)	\
	__param_check(name, p, int)
#ifdef HAVE_KERNEL_PARAM_OPS
module_param(lnet_drop_asym_route, drop_asym_route, 0644);
#else
module_param_call(lnet_drop_asym_route, drop_asym_route_set, param_get_int,
		  &param_ops_drop_asym_route, 0644);
#endif
MODULE_PARM_DESC(lnet_drop_asym_route,
		 "Set to 1 to drop asymmetrical route messages.");

#define LNET_TRANSACTION_TIMEOUT_DEFAULT 150
unsigned int lnet_transaction_timeout = LNET_TRANSACTION_TIMEOUT_DEFAULT;
static int transaction_to_set(const char *val, cfs_kernel_param_arg_t *kp);
#ifdef HAVE_KERNEL_PARAM_OPS
static struct kernel_param_ops param_ops_transaction_timeout = {
	.set = transaction_to_set,
	.get = param_get_int,
};

#define param_check_transaction_timeout(name, p) \
		__param_check(name, p, int)
module_param(lnet_transaction_timeout, transaction_timeout, S_IRUGO|S_IWUSR);
#else
module_param_call(lnet_transaction_timeout, transaction_to_set, param_get_int,
		  &lnet_transaction_timeout, S_IRUGO|S_IWUSR);
#endif
MODULE_PARM_DESC(lnet_transaction_timeout,
		"Maximum number of seconds to wait for a peer response.");

#define LNET_RETRY_COUNT_DEFAULT 2
unsigned int lnet_retry_count = LNET_RETRY_COUNT_DEFAULT;
static int retry_count_set(const char *val, cfs_kernel_param_arg_t *kp);
#ifdef HAVE_KERNEL_PARAM_OPS
static struct kernel_param_ops param_ops_retry_count = {
	.set = retry_count_set,
	.get = param_get_int,
};

#define param_check_retry_count(name, p) \
		__param_check(name, p, int)
module_param(lnet_retry_count, retry_count, S_IRUGO|S_IWUSR);
#else
module_param_call(lnet_retry_count, retry_count_set, param_get_int,
		  &lnet_retry_count, S_IRUGO|S_IWUSR);
#endif
MODULE_PARM_DESC(lnet_retry_count,
		 "Maximum number of times to retry transmitting a message");

unsigned int lnet_response_tracking = 3;
static int response_tracking_set(const char *val, cfs_kernel_param_arg_t *kp);

#ifdef HAVE_KERNEL_PARAM_OPS
static struct kernel_param_ops param_ops_response_tracking = {
	.set = response_tracking_set,
	.get = param_get_int,
};

#define param_check_response_tracking(name, p)  \
	__param_check(name, p, int)
module_param(lnet_response_tracking, response_tracking, 0644);
#else
module_param_call(lnet_response_tracking, response_tracking_set, param_get_int,
		  &lnet_response_tracking, 0644);
#endif
MODULE_PARM_DESC(lnet_response_tracking,
		 "(0|1|2|3) LNet Internal Only|GET Reply only|PUT ACK only|Full Tracking (default)");

int lock_prim_nid = 1;
module_param(lock_prim_nid, int, 0444);
MODULE_PARM_DESC(lock_prim_nid,
		 "Whether nid passed down by Lustre is locked as primary");

#define LNET_LND_TIMEOUT_DEFAULT ((LNET_TRANSACTION_TIMEOUT_DEFAULT - 1) / \
				  (LNET_RETRY_COUNT_DEFAULT + 1))
unsigned int lnet_lnd_timeout = LNET_LND_TIMEOUT_DEFAULT;
static void lnet_set_lnd_timeout(void)
{
	lnet_lnd_timeout = max((lnet_transaction_timeout - 1) /
			       (lnet_retry_count + 1), 1U);
}

/*
 * This sequence number keeps track of how many times DLC was used to
 * update the local NIs. It is incremented when a NI is added or
 * removed and checked when sending a message to determine if there is
 * a need to re-run the selection algorithm. See lnet_select_pathway()
 * for more details on its usage.
 */
static atomic_t lnet_dlc_seq_no = ATOMIC_INIT(0);

struct lnet_fail_ping {
	struct lnet_processid		lfp_id;
	int				lfp_errno;
	char				lfp_msg[256];
};

struct lnet_genl_ping_list {
	unsigned int			lgpl_index;
	unsigned int			lgpl_list_count;
	unsigned int			lgpl_failed_count;
	signed long			lgpl_timeout;
	struct lnet_nid			lgpl_src_nid;
	GENRADIX(struct lnet_fail_ping)	lgpl_failed;
	GENRADIX(struct lnet_processid)	lgpl_list;
};

static int lnet_ping(struct lnet_processid *id, struct lnet_nid *src_nid,
		     signed long timeout, struct lnet_genl_ping_list *plist,
		     int n_ids);

static int lnet_discover(struct lnet_processid *id, u32 force,
			 struct lnet_genl_ping_list *dlists);

static int
sensitivity_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned *sensitivity = (unsigned *)kp->arg;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_health_sensitivity'\n");
		return rc;
	}

	/*
	 * The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (value > LNET_MAX_HEALTH_VALUE) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		CERROR("Invalid health value. Maximum: %d value = %lu\n",
		       LNET_MAX_HEALTH_VALUE, value);
		return -EINVAL;
	}

	if (*sensitivity != 0 && value == 0 && lnet_retry_count != 0) {
		lnet_retry_count = 0;
		lnet_set_lnd_timeout();
	}

	*sensitivity = value;

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
recovery_interval_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	CWARN("'lnet_recovery_interval' has been deprecated\n");

	return 0;
}

static int
max_recovery_ping_interval_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_max_recovery_ping_interval'\n");
		return rc;
	}

	if (!value) {
		CERROR("Invalid max ping timeout. Must be strictly positive\n");
		return -EINVAL;
	}

	/* The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);
	lnet_max_recovery_ping_interval = value;
	lnet_max_recovery_ping_count = 0;
	value >>= 1;
	while (value) {
		lnet_max_recovery_ping_count++;
		value >>= 1;
	}
	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
discovery_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned *discovery_off = (unsigned *)kp->arg;
	unsigned long value;
	struct lnet_ping_buffer *pbuf;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_peer_discovery_disabled'\n");
		return rc;
	}

	value = (value) ? 1 : 0;

	/*
	 * The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (value == *discovery_off) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	/*
	 * We still want to set the discovery value even when LNet is not
	 * running. This is the case when LNet is being loaded and we want
	 * the module parameters to take effect. Otherwise if we're
	 * changing the value dynamically, we want to set it after
	 * updating the peers
	 */
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		*discovery_off = value;
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	/* tell peers that discovery setting has changed */
	lnet_net_lock(LNET_LOCK_EX);
	pbuf = the_lnet.ln_ping_target;
	if (value)
		pbuf->pb_info.pi_features &= ~LNET_PING_FEAT_DISCOVERY;
	else
		pbuf->pb_info.pi_features |= LNET_PING_FEAT_DISCOVERY;
	lnet_net_unlock(LNET_LOCK_EX);

	/* only send a push when we're turning off discovery */
	if (*discovery_off <= 0 && value > 0)
		lnet_push_update_to_peers(1);
	*discovery_off = value;

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
drop_asym_route_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned int *drop_asym_route = (unsigned int *)kp->arg;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for "
		       "'lnet_drop_asym_route'\n");
		return rc;
	}

	/*
	 * The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (value == *drop_asym_route) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	*drop_asym_route = value;

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
transaction_to_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned *transaction_to = (unsigned *)kp->arg;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_transaction_timeout'\n");
		return rc;
	}

	/*
	 * The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (value <= lnet_retry_count || value == 0) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		CERROR("Invalid value for lnet_transaction_timeout (%lu). "
		       "Has to be greater than lnet_retry_count (%u)\n",
		       value, lnet_retry_count);
		return -EINVAL;
	}

	if (value == *transaction_to) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	*transaction_to = value;
	/* Update the lnet_lnd_timeout now that we've modified the
	 * transaction timeout
	 */
	lnet_set_lnd_timeout();

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
retry_count_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned *retry_count = (unsigned *)kp->arg;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_retry_count'\n");
		return rc;
	}

	/*
	 * The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (lnet_health_sensitivity == 0 && value > 0) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		CERROR("Can not set lnet_retry_count when health feature is turned off\n");
		return -EINVAL;
	}

	if (value > lnet_transaction_timeout) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		CERROR("Invalid value for lnet_retry_count (%lu). "
		       "Has to be smaller than lnet_transaction_timeout (%u)\n",
		       value, lnet_transaction_timeout);
		return -EINVAL;
	}

	*retry_count = value;

	/* Update the lnet_lnd_timeout now that we've modified the
	 * retry count
	 */
	lnet_set_lnd_timeout();

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
intf_max_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int value, rc;

	rc = kstrtoint(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_interfaces_max'\n");
		return rc;
	}

	if (value < LNET_INTERFACES_MIN) {
		CWARN("max interfaces provided are too small, setting to %d\n",
		      LNET_INTERFACES_MAX_DEFAULT);
		value = LNET_INTERFACES_MAX_DEFAULT;
	}

	*(int *)kp->arg = value;

	return 0;
}

static int
response_tracking_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned long new_value;

	rc = kstrtoul(val, 0, &new_value);
	if (rc) {
		CERROR("Invalid value for 'lnet_response_tracking'\n");
		return -EINVAL;
	}

	if (new_value < 0 || new_value > 3) {
		CWARN("Invalid value (%lu) for 'lnet_response_tracking'\n",
		      new_value);
		return -EINVAL;
	}

	lnet_response_tracking = new_value;

	return 0;
}

static const char *
lnet_get_routes(void)
{
	return routes;
}

static const char *
lnet_get_networks(void)
{
	const char *nets;
	int rc;

	if (*networks != 0 && *ip2nets != 0) {
		LCONSOLE_ERROR("Please specify EITHER 'networks' or 'ip2nets' but not both at once\n");
		return NULL;
	}

	if (*ip2nets != 0) {
		rc = lnet_parse_ip2nets(&nets, ip2nets);
		return (rc == 0) ? nets : NULL;
	}

	if (*networks != 0)
		return networks;

	return "tcp";
}

static void
lnet_init_locks(void)
{
	spin_lock_init(&the_lnet.ln_eq_wait_lock);
	spin_lock_init(&the_lnet.ln_msg_resend_lock);
	init_completion(&the_lnet.ln_mt_wait_complete);
	mutex_init(&the_lnet.ln_lnd_mutex);
}

struct kmem_cache *lnet_mes_cachep;	   /* MEs kmem_cache */
struct kmem_cache *lnet_small_mds_cachep;  /* <= LNET_SMALL_MD_SIZE bytes
					    *  MDs kmem_cache */
struct kmem_cache *lnet_udsp_cachep;	   /* udsp cache */
struct kmem_cache *lnet_rspt_cachep;	   /* response tracker cache */
struct kmem_cache *lnet_msg_cachep;

static int
lnet_slab_setup(void)
{
	/* create specific kmem_cache for MEs and small MDs (i.e., originally
	 * allocated in <size-xxx> kmem_cache).
	 */
	lnet_mes_cachep = kmem_cache_create("lnet_MEs", sizeof(struct lnet_me),
					    0, 0, NULL);
	if (!lnet_mes_cachep)
		return -ENOMEM;

	lnet_small_mds_cachep = kmem_cache_create("lnet_small_MDs",
						  LNET_SMALL_MD_SIZE, 0, 0,
						  NULL);
	if (!lnet_small_mds_cachep)
		return -ENOMEM;

	lnet_udsp_cachep = kmem_cache_create("lnet_udsp",
					     sizeof(struct lnet_udsp),
					     0, 0, NULL);
	if (!lnet_udsp_cachep)
		return -ENOMEM;

	lnet_rspt_cachep = kmem_cache_create("lnet_rspt", sizeof(struct lnet_rsp_tracker),
					    0, 0, NULL);
	if (!lnet_rspt_cachep)
		return -ENOMEM;

	lnet_msg_cachep = kmem_cache_create("lnet_msg", sizeof(struct lnet_msg),
					    0, 0, NULL);
	if (!lnet_msg_cachep)
		return -ENOMEM;

	return 0;
}

static void
lnet_slab_cleanup(void)
{
	if (lnet_msg_cachep) {
		kmem_cache_destroy(lnet_msg_cachep);
		lnet_msg_cachep = NULL;
	}

	if (lnet_rspt_cachep) {
		kmem_cache_destroy(lnet_rspt_cachep);
		lnet_rspt_cachep = NULL;
	}

	if (lnet_udsp_cachep) {
		kmem_cache_destroy(lnet_udsp_cachep);
		lnet_udsp_cachep = NULL;
	}

	if (lnet_small_mds_cachep) {
		kmem_cache_destroy(lnet_small_mds_cachep);
		lnet_small_mds_cachep = NULL;
	}

	if (lnet_mes_cachep) {
		kmem_cache_destroy(lnet_mes_cachep);
		lnet_mes_cachep = NULL;
	}
}

static int
lnet_create_remote_nets_table(void)
{
	int		  i;
	struct list_head *hash;

	LASSERT(the_lnet.ln_remote_nets_hash == NULL);
	LASSERT(the_lnet.ln_remote_nets_hbits > 0);
	CFS_ALLOC_PTR_ARRAY(hash, LNET_REMOTE_NETS_HASH_SIZE);
	if (hash == NULL) {
		CERROR("Failed to create remote nets hash table\n");
		return -ENOMEM;
	}

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++)
		INIT_LIST_HEAD(&hash[i]);
	the_lnet.ln_remote_nets_hash = hash;
	return 0;
}

static void
lnet_destroy_remote_nets_table(void)
{
	int i;

	if (the_lnet.ln_remote_nets_hash == NULL)
		return;

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++)
		LASSERT(list_empty(&the_lnet.ln_remote_nets_hash[i]));

	CFS_FREE_PTR_ARRAY(the_lnet.ln_remote_nets_hash,
			   LNET_REMOTE_NETS_HASH_SIZE);
	the_lnet.ln_remote_nets_hash = NULL;
}

static void
lnet_destroy_locks(void)
{
	if (the_lnet.ln_res_lock != NULL) {
		cfs_percpt_lock_free(the_lnet.ln_res_lock);
		the_lnet.ln_res_lock = NULL;
	}

	if (the_lnet.ln_net_lock != NULL) {
		cfs_percpt_lock_free(the_lnet.ln_net_lock);
		the_lnet.ln_net_lock = NULL;
	}
}

static int
lnet_create_locks(void)
{
	lnet_init_locks();

	the_lnet.ln_res_lock = cfs_percpt_lock_alloc(lnet_cpt_table());
	if (the_lnet.ln_res_lock == NULL)
		goto failed;

	the_lnet.ln_net_lock = cfs_percpt_lock_alloc(lnet_cpt_table());
	if (the_lnet.ln_net_lock == NULL)
		goto failed;

	return 0;

 failed:
	lnet_destroy_locks();
	return -ENOMEM;
}

static void lnet_assert_wire_constants(void)
{
	/* Wire protocol assertions generated by 'wirecheck'
	 * running on Linux robert.bartonsoftware.com 2.6.8-1.521
	 * #1 Mon Aug 16 09:01:18 EDT 2004 i686 athlon i386 GNU/Linux
	 * with gcc version 3.3.3 20040412 (Red Hat Linux 3.3.3-7)
	 */

	/* Constants... */
	BUILD_BUG_ON(LNET_PROTO_TCP_MAGIC != 0xeebc0ded);
	BUILD_BUG_ON(LNET_PROTO_TCP_VERSION_MAJOR != 1);
	BUILD_BUG_ON(LNET_PROTO_TCP_VERSION_MINOR != 0);
	BUILD_BUG_ON(LNET_MSG_ACK != 0);
	BUILD_BUG_ON(LNET_MSG_PUT != 1);
	BUILD_BUG_ON(LNET_MSG_GET != 2);
	BUILD_BUG_ON(LNET_MSG_REPLY != 3);
	BUILD_BUG_ON(LNET_MSG_HELLO != 4);

	BUILD_BUG_ON((int)sizeof(lnet_nid_t) != 8);
	BUILD_BUG_ON((int)sizeof(lnet_pid_t) != 4);

	/* Checks for struct lnet_nid */
	BUILD_BUG_ON((int)sizeof(struct lnet_nid) != 20);
	BUILD_BUG_ON((int)offsetof(struct lnet_nid, nid_size) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_nid *)0)->nid_size) != 1);
	BUILD_BUG_ON((int)offsetof(struct lnet_nid, nid_type) != 1);
	BUILD_BUG_ON((int)sizeof(((struct lnet_nid *)0)->nid_type) != 1);
	BUILD_BUG_ON((int)offsetof(struct lnet_nid, nid_num) != 2);
	BUILD_BUG_ON((int)sizeof(((struct lnet_nid *)0)->nid_num) != 2);
	BUILD_BUG_ON((int)offsetof(struct lnet_nid, nid_addr) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_nid *)0)->nid_addr) != 16);

	/* Checks for struct lnet_process_id_packed */
	BUILD_BUG_ON((int)sizeof(struct lnet_process_id_packed) != 12);
	BUILD_BUG_ON((int)offsetof(struct lnet_process_id_packed, nid) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_process_id_packed *)0)->nid) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_process_id_packed, pid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_process_id_packed *)0)->pid) != 4);

	/* Checks for struct lnet_handle_wire */
	BUILD_BUG_ON((int)sizeof(struct lnet_handle_wire) != 16);
	BUILD_BUG_ON((int)offsetof(struct lnet_handle_wire,
				   wh_interface_cookie) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_handle_wire *)0)->wh_interface_cookie) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_handle_wire,
				   wh_object_cookie) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_handle_wire *)0)->wh_object_cookie) != 8);

	/* Checks for lnet_magicversion */
	BUILD_BUG_ON((int)sizeof(struct lnet_magicversion) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_magicversion, magic) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_magicversion *)0)->magic) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_magicversion, version_major) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_magicversion *)0)->version_major) != 2);
	BUILD_BUG_ON((int)offsetof(struct lnet_magicversion,
				   version_minor) != 6);
	BUILD_BUG_ON((int)sizeof(((struct lnet_magicversion *)0)->version_minor) != 2);

	/* Checks for _lnet_hdr_nid4 */
	BUILD_BUG_ON((int)sizeof(struct _lnet_hdr_nid4) != 72);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, dest_nid) != 0);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->dest_nid) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, src_nid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->src_nid) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, dest_pid) != 16);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->dest_pid) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, src_pid) != 20);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->src_pid) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, type) != 24);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->type) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, payload_length) != 28);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->payload_length) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg) != 40);

	/* Ack */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.ack.dst_wmd) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.ack.dst_wmd) != 16);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.ack.match_bits) != 48);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.ack.match_bits) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.ack.mlength) != 56);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.ack.mlength) != 4);

	/* Put */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.ack_wmd) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.ack_wmd) != 16);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.match_bits) != 48);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.match_bits) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.hdr_data) != 56);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.hdr_data) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.ptl_index) != 64);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.ptl_index) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.offset) != 68);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.offset) != 4);

	/* Get */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.return_wmd) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.return_wmd) != 16);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.match_bits) != 48);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.match_bits) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.ptl_index) != 56);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.ptl_index) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.src_offset) != 60);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.src_offset) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.sink_length) != 64);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.sink_length) != 4);

	/* Reply */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.reply.dst_wmd) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.reply.dst_wmd) != 16);

	/* Hello */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.hello.incarnation) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.hello.incarnation) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.hello.type) != 40);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.hello.type) != 4);

	/* Checks for struct lnet_ni_status and related constants */
	BUILD_BUG_ON(LNET_NI_STATUS_INVALID != 0x00000000);
	BUILD_BUG_ON(LNET_NI_STATUS_UP != 0x15aac0de);
	BUILD_BUG_ON(LNET_NI_STATUS_DOWN != 0xdeadface);

	/* Checks for struct lnet_ni_status */
	BUILD_BUG_ON((int)sizeof(struct lnet_ni_status) != 16);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_status, ns_nid) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_status *)0)->ns_nid) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_status, ns_status) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_status *)0)->ns_status) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_status, ns_msg_size) != 12);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_status *)0)->ns_msg_size) != 4);

	/* Checks for struct lnet_ni_large_status */
	BUILD_BUG_ON((int)sizeof(struct lnet_ni_large_status) != 24);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_large_status, ns_status) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_large_status *)0)->ns_status) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_large_status, ns_nid) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_large_status *)0)->ns_nid) != 20);

	/* Checks for struct lnet_ping_info and related constants */
	BUILD_BUG_ON(LNET_PROTO_PING_MAGIC != 0x70696E67);
	BUILD_BUG_ON(LNET_PING_FEAT_INVAL != 0);
	BUILD_BUG_ON(LNET_PING_FEAT_BASE != 1);
	BUILD_BUG_ON(LNET_PING_FEAT_NI_STATUS != 2);
	BUILD_BUG_ON(LNET_PING_FEAT_RTE_DISABLED != 4);
	BUILD_BUG_ON(LNET_PING_FEAT_MULTI_RAIL != 8);
	BUILD_BUG_ON(LNET_PING_FEAT_DISCOVERY != 16);
	BUILD_BUG_ON(LNET_PING_FEAT_LARGE_ADDR != 32);
	BUILD_BUG_ON(LNET_PING_FEAT_PRIMARY_LARGE != 64);
	BUILD_BUG_ON(LNET_PING_FEAT_BITS != 127);

	/* Checks for struct lnet_ping_info */
	BUILD_BUG_ON((int)sizeof(struct lnet_ping_info) != 16);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_magic) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_magic) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_features) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_features) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_pid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_pid) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_nnis) != 12);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_nnis) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_ni) != 16);
	BUILD_BUG_ON(offsetof(struct lnet_ping_info, pi_ni) != sizeof(struct lnet_ping_info));

	/* Acceptor connection request */
	BUILD_BUG_ON(LNET_PROTO_ACCEPTOR_VERSION != 1);

	/* Checks for struct lnet_acceptor_connreq */
	BUILD_BUG_ON((int)sizeof(struct lnet_acceptor_connreq) != 16);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq, acr_magic) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq *)0)->acr_magic) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq, acr_version) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq *)0)->acr_version) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq, acr_nid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq *)0)->acr_nid) != 8);

	/* Checks for struct lnet_acceptor_connreq_v2 */
	BUILD_BUG_ON((int)sizeof(struct lnet_acceptor_connreq_v2) != 28);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq_v2, acr_magic) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq_v2 *)0)->acr_magic) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq_v2, acr_version) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq_v2 *)0)->acr_version) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq_v2, acr_nid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq_v2 *)0)->acr_nid) != 20);

	/* Checks for struct lnet_counters_common */
	BUILD_BUG_ON((int)sizeof(struct lnet_counters_common) != 60);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_msgs_alloc) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_msgs_alloc) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_msgs_max) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_msgs_max) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_errors) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_errors) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_send_count) != 12);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_send_count) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_recv_count) != 16);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_recv_count) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_route_count) != 20);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_route_count) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_drop_count) != 24);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_drop_count) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_send_length) != 28);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_send_length) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_recv_length) != 36);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_recv_length) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_route_length) != 44);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_route_length) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_drop_length) != 52);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_drop_length) != 8);
}

static const struct lnet_lnd *lnet_find_lnd_by_type(__u32 type)
{
	const struct lnet_lnd *lnd;

	/* holding lnd mutex */
	if (type >= NUM_LNDS)
		return NULL;
	lnd = the_lnet.ln_lnds[type];
	LASSERT(!lnd || lnd->lnd_type == type);

	return lnd;
}

unsigned int
lnet_get_lnd_timeout(void)
{
	return lnet_lnd_timeout;
}
EXPORT_SYMBOL(lnet_get_lnd_timeout);

void
lnet_register_lnd(const struct lnet_lnd *lnd)
{
	mutex_lock(&the_lnet.ln_lnd_mutex);

	LASSERT(libcfs_isknown_lnd(lnd->lnd_type));
	LASSERT(lnet_find_lnd_by_type(lnd->lnd_type) == NULL);

	the_lnet.ln_lnds[lnd->lnd_type] = lnd;

	CDEBUG(D_NET, "%s LND registered\n", libcfs_lnd2str(lnd->lnd_type));

	mutex_unlock(&the_lnet.ln_lnd_mutex);
}
EXPORT_SYMBOL(lnet_register_lnd);

void
lnet_unregister_lnd(const struct lnet_lnd *lnd)
{
	mutex_lock(&the_lnet.ln_lnd_mutex);

	LASSERT(lnet_find_lnd_by_type(lnd->lnd_type) == lnd);

	the_lnet.ln_lnds[lnd->lnd_type] = NULL;
	CDEBUG(D_NET, "%s LND unregistered\n", libcfs_lnd2str(lnd->lnd_type));

	mutex_unlock(&the_lnet.ln_lnd_mutex);
}
EXPORT_SYMBOL(lnet_unregister_lnd);

static void
lnet_counters_get_common_locked(struct lnet_counters_common *common)
{
	struct lnet_counters *ctr;
	int i;

	/* FIXME !!! Their is no assert_lnet_net_locked() to ensure this
	 * actually called under the protection of the lnet_net_lock.
	 */
	memset(common, 0, sizeof(*common));

	cfs_percpt_for_each(ctr, i, the_lnet.ln_counters) {
		common->lcc_msgs_max     += ctr->lct_common.lcc_msgs_max;
		common->lcc_msgs_alloc   += ctr->lct_common.lcc_msgs_alloc;
		common->lcc_errors       += ctr->lct_common.lcc_errors;
		common->lcc_send_count   += ctr->lct_common.lcc_send_count;
		common->lcc_recv_count   += ctr->lct_common.lcc_recv_count;
		common->lcc_route_count  += ctr->lct_common.lcc_route_count;
		common->lcc_drop_count   += ctr->lct_common.lcc_drop_count;
		common->lcc_send_length  += ctr->lct_common.lcc_send_length;
		common->lcc_recv_length  += ctr->lct_common.lcc_recv_length;
		common->lcc_route_length += ctr->lct_common.lcc_route_length;
		common->lcc_drop_length  += ctr->lct_common.lcc_drop_length;
	}
}

void
lnet_counters_get_common(struct lnet_counters_common *common)
{
	lnet_net_lock(LNET_LOCK_EX);
	lnet_counters_get_common_locked(common);
	lnet_net_unlock(LNET_LOCK_EX);
}
EXPORT_SYMBOL(lnet_counters_get_common);

int
lnet_counters_get(struct lnet_counters *counters)
{
	struct lnet_counters *ctr;
	struct lnet_counters_health *health = &counters->lct_health;
	int i, rc = 0;

	memset(counters, 0, sizeof(*counters));

	lnet_net_lock(LNET_LOCK_EX);

	if (the_lnet.ln_state != LNET_STATE_RUNNING)
		GOTO(out_unlock, rc = -ENODEV);

	lnet_counters_get_common_locked(&counters->lct_common);

	cfs_percpt_for_each(ctr, i, the_lnet.ln_counters) {
		health->lch_rst_alloc    += ctr->lct_health.lch_rst_alloc;
		health->lch_resend_count += ctr->lct_health.lch_resend_count;
		health->lch_response_timeout_count +=
				ctr->lct_health.lch_response_timeout_count;
		health->lch_local_interrupt_count +=
				ctr->lct_health.lch_local_interrupt_count;
		health->lch_local_dropped_count +=
				ctr->lct_health.lch_local_dropped_count;
		health->lch_local_aborted_count +=
				ctr->lct_health.lch_local_aborted_count;
		health->lch_local_no_route_count +=
				ctr->lct_health.lch_local_no_route_count;
		health->lch_local_timeout_count +=
				ctr->lct_health.lch_local_timeout_count;
		health->lch_local_error_count +=
				ctr->lct_health.lch_local_error_count;
		health->lch_remote_dropped_count +=
				ctr->lct_health.lch_remote_dropped_count;
		health->lch_remote_error_count +=
				ctr->lct_health.lch_remote_error_count;
		health->lch_remote_timeout_count +=
				ctr->lct_health.lch_remote_timeout_count;
		health->lch_network_timeout_count +=
				ctr->lct_health.lch_network_timeout_count;
	}
out_unlock:
	lnet_net_unlock(LNET_LOCK_EX);
	return rc;
}
EXPORT_SYMBOL(lnet_counters_get);

void
lnet_counters_reset(void)
{
	struct lnet_counters *counters;
	int		i;

	lnet_net_lock(LNET_LOCK_EX);

	if (the_lnet.ln_state != LNET_STATE_RUNNING)
		goto avoid_reset;

	cfs_percpt_for_each(counters, i, the_lnet.ln_counters)
		memset(counters, 0, sizeof(struct lnet_counters));
avoid_reset:
	lnet_net_unlock(LNET_LOCK_EX);
}

static char *
lnet_res_type2str(int type)
{
	switch (type) {
	default:
		LBUG();
	case LNET_COOKIE_TYPE_MD:
		return "MD";
	case LNET_COOKIE_TYPE_ME:
		return "ME";
	case LNET_COOKIE_TYPE_EQ:
		return "EQ";
	}
}

static void
lnet_res_container_cleanup(struct lnet_res_container *rec)
{
	int	count = 0;

	if (rec->rec_type == 0) /* not set yet, it's uninitialized */
		return;

	while (!list_empty(&rec->rec_active)) {
		struct list_head *e = rec->rec_active.next;

		list_del_init(e);
		if (rec->rec_type == LNET_COOKIE_TYPE_MD) {
			lnet_md_free(list_entry(e, struct lnet_libmd, md_list));

		} else { /* NB: Active MEs should be attached on portals */
			LBUG();
		}
		count++;
	}

	if (count > 0) {
		/* Found alive MD/ME/EQ, user really should unlink/free
		 * all of them before finalize LNet, but if someone didn't,
		 * we have to recycle garbage for him */
		CERROR("%d active elements on exit of %s container\n",
		       count, lnet_res_type2str(rec->rec_type));
	}

	if (rec->rec_lh_hash != NULL) {
		CFS_FREE_PTR_ARRAY(rec->rec_lh_hash, LNET_LH_HASH_SIZE);
		rec->rec_lh_hash = NULL;
	}

	rec->rec_type = 0; /* mark it as finalized */
}

static int
lnet_res_container_setup(struct lnet_res_container *rec, int cpt, int type)
{
	int	rc = 0;
	int	i;

	LASSERT(rec->rec_type == 0);

	rec->rec_type = type;
	INIT_LIST_HEAD(&rec->rec_active);

	rec->rec_lh_cookie = (cpt << LNET_COOKIE_TYPE_BITS) | type;

	/* Arbitrary choice of hash table size */
	LIBCFS_CPT_ALLOC(rec->rec_lh_hash, lnet_cpt_table(), cpt,
			 LNET_LH_HASH_SIZE * sizeof(rec->rec_lh_hash[0]));
	if (rec->rec_lh_hash == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < LNET_LH_HASH_SIZE; i++)
		INIT_LIST_HEAD(&rec->rec_lh_hash[i]);

	return 0;

out:
	CERROR("Failed to setup %s resource container\n",
	       lnet_res_type2str(type));
	lnet_res_container_cleanup(rec);
	return rc;
}

static void
lnet_res_containers_destroy(struct lnet_res_container **recs)
{
	struct lnet_res_container	*rec;
	int				i;

	cfs_percpt_for_each(rec, i, recs)
		lnet_res_container_cleanup(rec);

	cfs_percpt_free(recs);
}

static struct lnet_res_container **
lnet_res_containers_create(int type)
{
	struct lnet_res_container	**recs;
	struct lnet_res_container	*rec;
	int				rc;
	int				i;

	recs = cfs_percpt_alloc(lnet_cpt_table(), sizeof(*rec));
	if (recs == NULL) {
		CERROR("Failed to allocate %s resource containers\n",
		       lnet_res_type2str(type));
		return NULL;
	}

	cfs_percpt_for_each(rec, i, recs) {
		rc = lnet_res_container_setup(rec, i, type);
		if (rc != 0) {
			lnet_res_containers_destroy(recs);
			return NULL;
		}
	}

	return recs;
}

struct lnet_libhandle *
lnet_res_lh_lookup(struct lnet_res_container *rec, __u64 cookie)
{
	/* ALWAYS called with lnet_res_lock held */
	struct list_head	*head;
	struct lnet_libhandle	*lh;
	unsigned int		hash;

	if ((cookie & LNET_COOKIE_MASK) != rec->rec_type)
		return NULL;

	hash = cookie >> (LNET_COOKIE_TYPE_BITS + LNET_CPT_BITS);
	head = &rec->rec_lh_hash[hash & LNET_LH_HASH_MASK];

	list_for_each_entry(lh, head, lh_hash_chain) {
		if (lh->lh_cookie == cookie)
			return lh;
	}

	return NULL;
}

void
lnet_res_lh_initialize(struct lnet_res_container *rec,
		       struct lnet_libhandle *lh)
{
	/* ALWAYS called with lnet_res_lock held */
	unsigned int	ibits = LNET_COOKIE_TYPE_BITS + LNET_CPT_BITS;
	unsigned int	hash;

	lh->lh_cookie = rec->rec_lh_cookie;
	rec->rec_lh_cookie += 1 << ibits;

	hash = (lh->lh_cookie >> ibits) & LNET_LH_HASH_MASK;

	list_add(&lh->lh_hash_chain, &rec->rec_lh_hash[hash]);
}

struct list_head **
lnet_create_array_of_queues(void)
{
	struct list_head **qs;
	struct list_head *q;
	int i;

	qs = cfs_percpt_alloc(lnet_cpt_table(),
			      sizeof(struct list_head));
	if (!qs) {
		CERROR("Failed to allocate queues\n");
		return NULL;
	}

	cfs_percpt_for_each(q, i, qs)
		INIT_LIST_HEAD(q);

	return qs;
}

static int lnet_unprepare(void);

static int
lnet_prepare(lnet_pid_t requested_pid)
{
	/* Prepare to bring up the network */
	struct lnet_res_container **recs;
	int			  rc = 0;

	if (requested_pid == LNET_PID_ANY) {
		/* Don't instantiate LNET just for me */
		return -ENETDOWN;
	}

	LASSERT(the_lnet.ln_refcount == 0);

	the_lnet.ln_routing = 0;

	LASSERT((requested_pid & LNET_PID_USERFLAG) == 0);
	the_lnet.ln_pid = requested_pid;

	INIT_LIST_HEAD(&the_lnet.ln_test_peers);
	INIT_LIST_HEAD(&the_lnet.ln_remote_peer_ni_list);
	INIT_LIST_HEAD(&the_lnet.ln_nets);
	INIT_LIST_HEAD(&the_lnet.ln_routers);
	INIT_LIST_HEAD(&the_lnet.ln_drop_rules);
	INIT_LIST_HEAD(&the_lnet.ln_delay_rules);
	INIT_LIST_HEAD(&the_lnet.ln_dc_request);
	INIT_LIST_HEAD(&the_lnet.ln_dc_working);
	INIT_LIST_HEAD(&the_lnet.ln_dc_expired);
	INIT_LIST_HEAD(&the_lnet.ln_mt_localNIRecovq);
	INIT_LIST_HEAD(&the_lnet.ln_mt_peerNIRecovq);
	INIT_LIST_HEAD(&the_lnet.ln_udsp_list);
	init_waitqueue_head(&the_lnet.ln_dc_waitq);
	the_lnet.ln_mt_handler = NULL;
	init_completion(&the_lnet.ln_started);
	atomic_set(&the_lnet.ln_late_msg_count, 0);
	atomic64_set(&the_lnet.ln_late_msg_nsecs, 0);

	rc = lnet_slab_setup();
	if (rc != 0)
		goto failed;

	rc = lnet_create_remote_nets_table();
	if (rc != 0)
		goto failed;

	/*
	 * NB the interface cookie in wire handles guards against delayed
	 * replies and ACKs appearing valid after reboot.
	 */
	the_lnet.ln_interface_cookie = ktime_get_real_ns();

	the_lnet.ln_counters = cfs_percpt_alloc(lnet_cpt_table(),
						sizeof(struct lnet_counters));
	if (the_lnet.ln_counters == NULL) {
		CERROR("Failed to allocate counters for LNet\n");
		rc = -ENOMEM;
		goto failed;
	}

	rc = lnet_peer_tables_create();
	if (rc != 0)
		goto failed;

	rc = lnet_msg_containers_create();
	if (rc != 0)
		goto failed;

	rc = lnet_res_container_setup(&the_lnet.ln_eq_container, 0,
				      LNET_COOKIE_TYPE_EQ);
	if (rc != 0)
		goto failed;

	recs = lnet_res_containers_create(LNET_COOKIE_TYPE_MD);
	if (recs == NULL) {
		rc = -ENOMEM;
		goto failed;
	}

	the_lnet.ln_md_containers = recs;

	rc = lnet_portals_create();
	if (rc != 0) {
		CERROR("Failed to create portals for LNet: %d\n", rc);
		goto failed;
	}

	the_lnet.ln_mt_zombie_rstqs = lnet_create_array_of_queues();
	if (!the_lnet.ln_mt_zombie_rstqs) {
		rc = -ENOMEM;
		goto failed;
	}

	return 0;

 failed:
	lnet_unprepare();
	return rc;
}

static int
lnet_unprepare(void)
{
	/* NB no LNET_LOCK since this is the last reference.  All LND instances
	 * have shut down already, so it is safe to unlink and free all
	 * descriptors, even those that appear committed to a network op (eg MD
	 * with non-zero pending count)
	 */
	lnet_fail_nid(&LNET_ANY_NID, 0);

	LASSERT(the_lnet.ln_refcount == 0);
	LASSERT(list_empty(&the_lnet.ln_test_peers));
	LASSERT(list_empty(&the_lnet.ln_nets));

	if (the_lnet.ln_mt_zombie_rstqs) {
		lnet_clean_zombie_rstqs();
		the_lnet.ln_mt_zombie_rstqs = NULL;
	}

	lnet_assert_handler_unused(the_lnet.ln_mt_handler);
	the_lnet.ln_mt_handler = NULL;

	lnet_portals_destroy();

	if (the_lnet.ln_md_containers != NULL) {
		lnet_res_containers_destroy(the_lnet.ln_md_containers);
		the_lnet.ln_md_containers = NULL;
	}

	lnet_res_container_cleanup(&the_lnet.ln_eq_container);

	lnet_msg_containers_destroy();
	lnet_peer_uninit();
	lnet_rtrpools_free(0);

	if (the_lnet.ln_counters != NULL) {
		cfs_percpt_free(the_lnet.ln_counters);
		the_lnet.ln_counters = NULL;
	}
	lnet_destroy_remote_nets_table();
	lnet_udsp_destroy(true);
	lnet_slab_cleanup();

	return 0;
}

struct lnet_ni  *
lnet_net2ni_locked(__u32 net_id, int cpt)
{
	struct lnet_ni	 *ni;
	struct lnet_net	 *net;

	LASSERT(cpt != LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		if (net->net_id == net_id) {
			ni = list_first_entry(&net->net_ni_list, struct lnet_ni,
					      ni_netlist);
			return ni;
		}
	}

	return NULL;
}

struct lnet_ni *
lnet_net2ni_addref(__u32 net)
{
	struct lnet_ni *ni;

	lnet_net_lock(0);
	ni = lnet_net2ni_locked(net, 0);
	if (ni)
		lnet_ni_addref_locked(ni, 0);
	lnet_net_unlock(0);

	return ni;
}
EXPORT_SYMBOL(lnet_net2ni_addref);

struct lnet_net *
lnet_get_net_locked(__u32 net_id)
{
	struct lnet_net	 *net;

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		if (net->net_id == net_id)
			return net;
	}

	return NULL;
}

void
lnet_net_clr_pref_rtrs(struct lnet_net *net)
{
	struct list_head zombies;
	struct lnet_nid_list *ne;
	struct lnet_nid_list *tmp;

	INIT_LIST_HEAD(&zombies);

	lnet_net_lock(LNET_LOCK_EX);
	list_splice_init(&net->net_rtr_pref_nids, &zombies);
	lnet_net_unlock(LNET_LOCK_EX);

	list_for_each_entry_safe(ne, tmp, &zombies, nl_list) {
		list_del_init(&ne->nl_list);
		LIBCFS_FREE(ne, sizeof(*ne));
	}
}

int
lnet_net_add_pref_rtr(struct lnet_net *net,
		      struct lnet_nid *gw_nid)
__must_hold(&the_lnet.ln_api_mutex)
{
	struct lnet_nid_list *ne;

	/* This function is called with api_mutex held. When the api_mutex
	 * is held the list can not be modified, as it is only modified as
	 * a result of applying a UDSP and that happens under api_mutex
	 * lock.
	 */
	list_for_each_entry(ne, &net->net_rtr_pref_nids, nl_list) {
		if (nid_same(&ne->nl_nid, gw_nid))
			return -EEXIST;
	}

	LIBCFS_ALLOC(ne, sizeof(*ne));
	if (!ne)
		return -ENOMEM;

	ne->nl_nid = *gw_nid;

	/* Lock the cpt to protect against addition and checks in the
	 * selection algorithm
	 */
	lnet_net_lock(LNET_LOCK_EX);
	list_add(&ne->nl_list, &net->net_rtr_pref_nids);
	lnet_net_unlock(LNET_LOCK_EX);

	return 0;
}

static unsigned int
lnet_nid4_cpt_hash(lnet_nid_t nid, unsigned int number)
{
	__u64 key = nid;
	__u16 lnd = LNET_NETTYP(LNET_NIDNET(nid));
	unsigned int cpt;

	if (lnd == KFILND || lnd == GNILND) {
		cpt = hash_long(key, LNET_CPT_BITS);

		/* NB: The number of CPTs needn't be a power of 2 */
		if (cpt >= number)
			cpt = (key + cpt + (cpt >> 1)) % number;
	} else {
		__u64 pair_bits = 0x0001000100010001LLU;
		__u64 mask = pair_bits * 0xFF;
		__u64 pair_sum;
		/* For ipv4 NIDs, use (sum-by-multiplication of nid bytes) mod
		 * (number of CPTs) to match nid to a CPT.
		 */
		pair_sum = (key & mask) + ((key >> 8) & mask);
		pair_sum = (pair_sum * pair_bits) >> 48;
		cpt = (unsigned int)(pair_sum) % number;
	}

	CDEBUG(D_NET, "Match nid %s to cpt %u\n",
	       libcfs_nid2str(nid), cpt);

	return cpt;
}

unsigned int
lnet_nid_cpt_hash(struct lnet_nid *nid, unsigned int number)
{
	unsigned int val;
	u32 h = 0;
	int i;

	LASSERT(number >= 1 && number <= LNET_CPT_NUMBER);

	if (number == 1)
		return 0;

	if (nid_is_nid4(nid))
		return lnet_nid4_cpt_hash(lnet_nid_to_nid4(nid), number);

	for (i = 0; i < 4; i++)
		h = cfs_hash_32(nid->nid_addr[i]^h, 32);
	val = cfs_hash_32(LNET_NID_NET(nid) ^ h, LNET_CPT_BITS);
	if (val < number)
		return val;
	return (unsigned int)(h + val + (val >> 1)) % number;
}

int
lnet_cpt_of_nid_locked(struct lnet_nid *nid, struct lnet_ni *ni)
{
	struct lnet_net *net;

	/* must called with hold of lnet_net_lock */
	if (LNET_CPT_NUMBER == 1)
		return 0; /* the only one */

	/*
	 * If NI is provided then use the CPT identified in the NI cpt
	 * list if one exists. If one doesn't exist, then that NI is
	 * associated with all CPTs and it follows that the net it belongs
	 * to is implicitly associated with all CPTs, so just hash the nid
	 * and return that.
	 */
	if (ni != NULL) {
		if (ni->ni_cpts != NULL)
			return ni->ni_cpts[lnet_nid_cpt_hash(nid,
							     ni->ni_ncpts)];
		else
			return lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);
	}

	/* no NI provided so look at the net */
	net = lnet_get_net_locked(LNET_NID_NET(nid));

	if (net != NULL && net->net_cpts != NULL) {
		return net->net_cpts[lnet_nid_cpt_hash(nid, net->net_ncpts)];
	}

	return lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);
}

int
lnet_nid2cpt(struct lnet_nid *nid, struct lnet_ni *ni)
{
	int	cpt;
	int	cpt2;

	if (LNET_CPT_NUMBER == 1)
		return 0; /* the only one */

	cpt = lnet_net_lock_current();

	cpt2 = lnet_cpt_of_nid_locked(nid, ni);

	lnet_net_unlock(cpt);

	return cpt2;
}
EXPORT_SYMBOL(lnet_nid2cpt);

int
lnet_cpt_of_nid(lnet_nid_t nid4, struct lnet_ni *ni)
{
	struct lnet_nid nid;

	if (LNET_CPT_NUMBER == 1)
		return 0; /* the only one */

	lnet_nid4_to_nid(nid4, &nid);
	return lnet_nid2cpt(&nid, ni);
}
EXPORT_SYMBOL(lnet_cpt_of_nid);

int
lnet_islocalnet_locked(__u32 net_id)
{
	struct lnet_net *net;
	bool local;

	net = lnet_get_net_locked(net_id);

	local = net != NULL;

	return local;
}

int
lnet_islocalnet(__u32 net_id)
{
	int cpt;
	bool local;

	cpt = lnet_net_lock_current();

	local = lnet_islocalnet_locked(net_id);

	lnet_net_unlock(cpt);

	return local;
}

struct lnet_ni  *
lnet_nid_to_ni_locked(struct lnet_nid *nid, int cpt)
{
	struct lnet_net  *net;
	struct lnet_ni *ni;

	LASSERT(cpt != LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (nid_same(&ni->ni_nid, nid))
				return ni;
		}
	}

	return NULL;
}

struct lnet_ni *
lnet_nid_to_ni_addref(struct lnet_nid *nid)
{
	struct lnet_ni *ni;

	lnet_net_lock(0);
	ni = lnet_nid_to_ni_locked(nid, 0);
	if (ni)
		lnet_ni_addref_locked(ni, 0);
	lnet_net_unlock(0);

	return ni;
}
EXPORT_SYMBOL(lnet_nid_to_ni_addref);

int
lnet_islocalnid(struct lnet_nid *nid)
{
	struct lnet_ni	*ni;
	int		cpt;

	cpt = lnet_net_lock_current();
	ni = lnet_nid_to_ni_locked(nid, cpt);
	lnet_net_unlock(cpt);

	return ni != NULL;
}

int
lnet_count_acceptor_nets(void)
{
	/* Return the # of NIs that need the acceptor. */
	int		 count = 0;
	struct lnet_net  *net;
	int		 cpt;

	cpt = lnet_net_lock_current();
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		/* all socklnd type networks should have the acceptor
		 * thread started */
		if (net->net_lnd->lnd_accept != NULL)
			count++;
	}

	lnet_net_unlock(cpt);

	return count;
}

struct lnet_ping_buffer *
lnet_ping_buffer_alloc(int nbytes, gfp_t gfp)
{
	struct lnet_ping_buffer *pbuf;

	LIBCFS_ALLOC_GFP(pbuf, LNET_PING_BUFFER_SIZE(nbytes), gfp);
	if (pbuf) {
		pbuf->pb_nbytes = nbytes;	/* sizeof of pb_info */
		pbuf->pb_needs_post = false;
		atomic_set(&pbuf->pb_refcnt, 1);
	}

	return pbuf;
}

void
lnet_ping_buffer_free(struct lnet_ping_buffer *pbuf)
{
	LASSERT(atomic_read(&pbuf->pb_refcnt) == 0);
	LIBCFS_FREE(pbuf, LNET_PING_BUFFER_SIZE(pbuf->pb_nbytes));
}

static struct lnet_ping_buffer *
lnet_ping_target_create(int nbytes)
{
	struct lnet_ping_buffer *pbuf;

	pbuf = lnet_ping_buffer_alloc(nbytes, GFP_NOFS);
	if (pbuf == NULL) {
		CERROR("Can't allocate ping source [%d]\n", nbytes);
		return NULL;
	}

	pbuf->pb_info.pi_nnis = 0;
	pbuf->pb_info.pi_pid = the_lnet.ln_pid;
	pbuf->pb_info.pi_magic = LNET_PROTO_PING_MAGIC;
	pbuf->pb_info.pi_features =
		LNET_PING_FEAT_NI_STATUS | LNET_PING_FEAT_MULTI_RAIL;

	return pbuf;
}

static inline int
lnet_get_net_ni_bytes_locked(struct lnet_net *net)
{
	struct lnet_ni *ni;
	int bytes = 0;

	list_for_each_entry(ni, &net->net_ni_list, ni_netlist)
		bytes += lnet_ping_sts_size(&ni->ni_nid);

	return bytes;
}

static inline int
lnet_get_ni_bytes(void)
{
	struct lnet_ni *ni;
	struct lnet_net *net;
	int bytes = 0;

	lnet_net_lock(0);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist)
			bytes += lnet_ping_sts_size(&ni->ni_nid);
	}

	lnet_net_unlock(0);

	return bytes;
}

void
lnet_swap_pinginfo(struct lnet_ping_buffer *pbuf)
{
	struct lnet_ni_large_status *lstat, *lend;
	struct lnet_ni_status *stat, *end;
	int nnis;
	int i;

	__swab32s(&pbuf->pb_info.pi_magic);
	__swab32s(&pbuf->pb_info.pi_features);
	__swab32s(&pbuf->pb_info.pi_pid);
	__swab32s(&pbuf->pb_info.pi_nnis);
	nnis = pbuf->pb_info.pi_nnis;
	stat = &pbuf->pb_info.pi_ni[0];
	end = (void *)&pbuf->pb_info + pbuf->pb_nbytes;
	for (i = 0; i < nnis && stat + 1 <= end; i++, stat++) {
		__swab64s(&stat->ns_nid);
		__swab32s(&stat->ns_status);
		if (i == 0)
			/* Might be total size */
			__swab32s(&stat->ns_msg_size);
	}
	if (!(pbuf->pb_info.pi_features & LNET_PING_FEAT_LARGE_ADDR))
		return;

	lstat = (struct lnet_ni_large_status *)stat;
	lend = (void *)end;
	while (lstat + 1 <= lend) {
		__swab32s(&lstat->ns_status);
		/* struct lnet_nid never needs to be swabed */
		lstat = lnet_ping_sts_next(lstat);
	}
}

int
lnet_ping_info_validate(struct lnet_ping_info *pinfo)
{
	if (!pinfo)
		return -EINVAL;
	if (pinfo->pi_magic != LNET_PROTO_PING_MAGIC)
		return -EPROTO;
	if (!(pinfo->pi_features & LNET_PING_FEAT_NI_STATUS))
		return -EPROTO;
	/* Loopback is guaranteed to be present */
	if (pinfo->pi_nnis < 1 || pinfo->pi_nnis > lnet_interfaces_max)
		return -ERANGE;
	if (LNET_PING_INFO_LONI(pinfo) != LNET_NID_LO_0)
		return -EPROTO;
	return 0;
}

static void
lnet_ping_target_destroy(void)
{
	struct lnet_net *net;
	struct lnet_ni	*ni;

	lnet_net_lock(LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			lnet_ni_lock(ni);
			ni->ni_status = NULL;
			lnet_ni_unlock(ni);
		}
	}

	lnet_ping_buffer_decref(the_lnet.ln_ping_target);
	the_lnet.ln_ping_target = NULL;

	lnet_net_unlock(LNET_LOCK_EX);
}

static void
lnet_ping_target_event_handler(struct lnet_event *event)
{
	struct lnet_ping_buffer *pbuf = event->md_user_ptr;

	if (event->unlinked)
		lnet_ping_buffer_decref(pbuf);
}

static int
lnet_ping_target_setup(struct lnet_ping_buffer **ppbuf,
		       struct lnet_handle_md *ping_mdh,
		       int ni_bytes, bool set_eq)
{
	struct lnet_processid id = {
		.nid = LNET_ANY_NID,
		.pid = LNET_PID_ANY
	};
	struct lnet_me *me;
	struct lnet_md md = { NULL };
	int rc;

	if (set_eq)
		the_lnet.ln_ping_target_handler =
			lnet_ping_target_event_handler;

	*ppbuf = lnet_ping_target_create(ni_bytes);
	if (*ppbuf == NULL) {
		rc = -ENOMEM;
		goto fail_free_eq;
	}

	/* Ping target ME/MD */
	me = LNetMEAttach(LNET_RESERVED_PORTAL, &id,
			  LNET_PROTO_PING_MATCHBITS, 0,
			  LNET_UNLINK, LNET_INS_AFTER);
	if (IS_ERR(me)) {
		rc = PTR_ERR(me);
		CERROR("Can't create ping target ME: %d\n", rc);
		goto fail_decref_ping_buffer;
	}

	/* initialize md content */
	md.start     = &(*ppbuf)->pb_info;
	md.length    = (*ppbuf)->pb_nbytes;
	md.threshold = LNET_MD_THRESH_INF;
	md.max_size  = 0;
	md.options   = LNET_MD_OP_GET | LNET_MD_TRUNCATE |
		       LNET_MD_MANAGE_REMOTE;
	md.handler   = the_lnet.ln_ping_target_handler;
	md.user_ptr  = *ppbuf;

	rc = LNetMDAttach(me, &md, LNET_RETAIN, ping_mdh);
	if (rc != 0) {
		CERROR("Can't attach ping target MD: %d\n", rc);
		goto fail_decref_ping_buffer;
	}
	lnet_ping_buffer_addref(*ppbuf);

	return 0;

fail_decref_ping_buffer:
	LASSERT(atomic_read(&(*ppbuf)->pb_refcnt) == 1);
	lnet_ping_buffer_decref(*ppbuf);
	*ppbuf = NULL;
fail_free_eq:
	return rc;
}

static void
lnet_ping_md_unlink(struct lnet_ping_buffer *pbuf,
		    struct lnet_handle_md *ping_mdh)
{
	LNetMDUnlink(*ping_mdh);
	LNetInvalidateMDHandle(ping_mdh);

	/* NB the MD could be busy; this just starts the unlink */
	wait_var_event_warning(&pbuf->pb_refcnt,
			       atomic_read(&pbuf->pb_refcnt) <= 1,
			       "Still waiting for ping data MD to unlink\n");
}

static void
lnet_ping_target_install_locked(struct lnet_ping_buffer *pbuf)
{
	struct lnet_ni *ni;
	struct lnet_net	*net;
	struct lnet_ni_status *ns, *end;
	struct lnet_ni_large_status *lns, *lend;
	int rc;

	pbuf->pb_info.pi_nnis = 0;
	ns = &pbuf->pb_info.pi_ni[0];
	end = (void *)&pbuf->pb_info + pbuf->pb_nbytes;
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (!nid_is_nid4(&ni->ni_nid)) {
				if (ns == &pbuf->pb_info.pi_ni[1]) {
					/* This is primary, and it is long */
					pbuf->pb_info.pi_features |=
						LNET_PING_FEAT_PRIMARY_LARGE;
				}
				continue;
			}
			LASSERT(ns + 1 <= end);
			ns->ns_nid = lnet_nid_to_nid4(&ni->ni_nid);

			lnet_ni_lock(ni);
			ns->ns_status = lnet_ni_get_status_locked(ni);
			ni->ni_status = &ns->ns_status;
			lnet_ni_unlock(ni);

			pbuf->pb_info.pi_nnis++;
			ns++;
		}
	}

	lns = (void *)ns;
	lend = (void *)end;
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (nid_is_nid4(&ni->ni_nid))
				continue;
			LASSERT(lns + 1 <= lend);

			lns->ns_nid = ni->ni_nid;

			lnet_ni_lock(ni);
			lns->ns_status = lnet_ni_get_status_locked(ni);
			ni->ni_status = &lns->ns_status;
			lnet_ni_unlock(ni);

			lns = lnet_ping_sts_next(lns);
		}
	}
	if ((void *)lns > (void *)ns) {
		/* Record total info size */
		pbuf->pb_info.pi_ni[0].ns_msg_size =
			(void *)lns - (void *)&pbuf->pb_info;
		pbuf->pb_info.pi_features |= LNET_PING_FEAT_LARGE_ADDR;
	}

	/* We (ab)use the ns_status of the loopback interface to
	 * transmit the sequence number. The first interface listed
	 * must be the loopback interface.
	 */
	rc = lnet_ping_info_validate(&pbuf->pb_info);
	if (rc) {
		LCONSOLE_EMERG("Invalid ping target: %d\n", rc);
		LBUG();
	}
	LNET_PING_BUFFER_SEQNO(pbuf) =
		atomic_inc_return(&the_lnet.ln_ping_target_seqno);
}

static void
lnet_ping_target_update(struct lnet_ping_buffer *pbuf,
			struct lnet_handle_md ping_mdh)
__must_hold(&the_lnet.ln_api_mutex)
{
	struct lnet_ping_buffer *old_pbuf = NULL;
	struct lnet_handle_md old_ping_md;

	/* switch the NIs to point to the new ping info created */
	lnet_net_lock(LNET_LOCK_EX);

	if (!the_lnet.ln_routing)
		pbuf->pb_info.pi_features |= LNET_PING_FEAT_RTE_DISABLED;
	if (!lnet_peer_discovery_disabled)
		pbuf->pb_info.pi_features |= LNET_PING_FEAT_DISCOVERY;

	/* Ensure only known feature bits have been set. */
	LASSERT(pbuf->pb_info.pi_features & LNET_PING_FEAT_BITS);
	LASSERT(!(pbuf->pb_info.pi_features & ~LNET_PING_FEAT_BITS));

	lnet_ping_target_install_locked(pbuf);

	if (the_lnet.ln_ping_target) {
		old_pbuf = the_lnet.ln_ping_target;
		old_ping_md = the_lnet.ln_ping_target_md;
	}
	the_lnet.ln_ping_target_md = ping_mdh;
	the_lnet.ln_ping_target = pbuf;

	lnet_net_unlock(LNET_LOCK_EX);

	if (old_pbuf) {
		/* unlink and free the old ping info.
		 * There may be outstanding traffic on this MD, and
		 * ln_api_mutex may be required to finalize that
		 * traffic. Release ln_api_mutex while we wait for
		 * refs on this ping buffer to drop
		 */
		mutex_unlock(&the_lnet.ln_api_mutex);
		lnet_ping_md_unlink(old_pbuf, &old_ping_md);
		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_ping_buffer_decref(old_pbuf);
	}

	lnet_push_update_to_peers(0);
}

static void
lnet_ping_target_fini(void)
{
	lnet_ping_md_unlink(the_lnet.ln_ping_target,
			    &the_lnet.ln_ping_target_md);

	lnet_assert_handler_unused(the_lnet.ln_ping_target_handler);
	lnet_ping_target_destroy();
}

/* Resize the push target. */
int lnet_push_target_resize(void)
{
	struct lnet_handle_md mdh;
	struct lnet_handle_md old_mdh;
	struct lnet_ping_buffer *pbuf;
	struct lnet_ping_buffer *old_pbuf;
	int nbytes;
	int rc;

again:
	nbytes = the_lnet.ln_push_target_nbytes;
	if (nbytes <= 0) {
		CDEBUG(D_NET, "Invalid nbytes %d\n", nbytes);
		return -EINVAL;
	}

	/* NB: lnet_ping_buffer_alloc() sets pbuf refcount to 1. That ref is
	 * dropped when we need to resize again (see "old_pbuf" below) or when
	 * LNet is shutdown (see lnet_push_target_fini())
	 */
	pbuf = lnet_ping_buffer_alloc(nbytes, GFP_NOFS);
	if (!pbuf) {
		CDEBUG(D_NET, "Can't allocate pbuf for nbytes %d\n", nbytes);
		return -ENOMEM;
	}

	rc = lnet_push_target_post(pbuf, &mdh);
	if (rc) {
		CDEBUG(D_NET, "Failed to post push target: %d\n", rc);
		lnet_ping_buffer_decref(pbuf);
		return rc;
	}

	lnet_net_lock(LNET_LOCK_EX);
	old_pbuf = the_lnet.ln_push_target;
	old_mdh = the_lnet.ln_push_target_md;
	the_lnet.ln_push_target = pbuf;
	the_lnet.ln_push_target_md = mdh;
	lnet_net_unlock(LNET_LOCK_EX);

	if (old_pbuf) {
		LNetMDUnlink(old_mdh);
		/* Drop ref set by lnet_ping_buffer_alloc() */
		lnet_ping_buffer_decref(old_pbuf);
	}

	/* Received another push or reply that requires a larger buffer */
	if (nbytes < the_lnet.ln_push_target_nbytes)
		goto again;

	CDEBUG(D_NET, "nbytes %d success\n", nbytes);
	return 0;
}

int lnet_push_target_post(struct lnet_ping_buffer *pbuf,
			  struct lnet_handle_md *mdhp)
{
	struct lnet_processid id = { LNET_ANY_NID, LNET_PID_ANY };
	struct lnet_md md = { NULL };
	struct lnet_me *me;
	int rc;

	me = LNetMEAttach(LNET_RESERVED_PORTAL, &id,
			  LNET_PROTO_PING_MATCHBITS, 0,
			  LNET_UNLINK, LNET_INS_AFTER);
	if (IS_ERR(me)) {
		rc = PTR_ERR(me);
		CERROR("Can't create push target ME: %d\n", rc);
		return rc;
	}

	pbuf->pb_needs_post = false;

	/* This reference is dropped by lnet_push_target_event_handler() */
	lnet_ping_buffer_addref(pbuf);

	/* initialize md content */
	md.start     = &pbuf->pb_info;
	md.length    = pbuf->pb_nbytes;
	md.threshold = 1;
	md.max_size  = 0;
	md.options   = LNET_MD_OP_PUT | LNET_MD_TRUNCATE;
	md.user_ptr  = pbuf;
	md.handler   = the_lnet.ln_push_target_handler;

	rc = LNetMDAttach(me, &md, LNET_UNLINK, mdhp);
	if (rc) {
		CERROR("Can't attach push MD: %d\n", rc);
		lnet_ping_buffer_decref(pbuf);
		pbuf->pb_needs_post = true;
		return rc;
	}

	CDEBUG(D_NET, "posted push target %p\n", pbuf);

	return 0;
}

static void lnet_push_target_event_handler(struct lnet_event *ev)
{
	struct lnet_ping_buffer *pbuf = ev->md_user_ptr;

	CDEBUG(D_NET, "type %d status %d unlinked %d\n", ev->type, ev->status,
	       ev->unlinked);

	if (pbuf->pb_info.pi_magic == __swab32(LNET_PROTO_PING_MAGIC))
		lnet_swap_pinginfo(pbuf);

	if (ev->type == LNET_EVENT_UNLINK) {
		/* Drop ref added by lnet_push_target_post() */
		lnet_ping_buffer_decref(pbuf);
		return;
	}

	lnet_peer_push_event(ev);
	if (ev->unlinked)
		/* Drop ref added by lnet_push_target_post */
		lnet_ping_buffer_decref(pbuf);
}

/* Initialize the push target. */
static int lnet_push_target_init(void)
{
	int rc;

	if (the_lnet.ln_push_target)
		return -EALREADY;

	the_lnet.ln_push_target_handler =
		lnet_push_target_event_handler;

	rc = LNetSetLazyPortal(LNET_RESERVED_PORTAL);
	LASSERT(rc == 0);

	/* Start at the required minimum, we'll enlarge if required. */
	the_lnet.ln_push_target_nbytes = LNET_PING_INFO_MIN_SIZE;

	rc = lnet_push_target_resize();
	if (rc) {
		LNetClearLazyPortal(LNET_RESERVED_PORTAL);
		the_lnet.ln_push_target_handler = NULL;
	}

	return rc;
}

/* Clean up the push target. */
static void lnet_push_target_fini(void)
{
	if (!the_lnet.ln_push_target)
		return;

	/* Unlink and invalidate to prevent new references. */
	LNetMDUnlink(the_lnet.ln_push_target_md);
	LNetInvalidateMDHandle(&the_lnet.ln_push_target_md);

	/* Wait for the unlink to complete. */
	wait_var_event_warning(&the_lnet.ln_push_target->pb_refcnt,
			       atomic_read(&the_lnet.ln_push_target->pb_refcnt) <= 1,
			       "Still waiting for ping data MD to unlink\n");

	/* Drop ref set by lnet_ping_buffer_alloc() */
	lnet_ping_buffer_decref(the_lnet.ln_push_target);
	the_lnet.ln_push_target = NULL;
	the_lnet.ln_push_target_nbytes = 0;

	LNetClearLazyPortal(LNET_RESERVED_PORTAL);
	lnet_assert_handler_unused(the_lnet.ln_push_target_handler);
	the_lnet.ln_push_target_handler = NULL;
}

static int
lnet_ni_tq_credits(struct lnet_ni *ni)
{
	int	credits;

	LASSERT(ni->ni_ncpts >= 1);

	if (ni->ni_ncpts == 1)
		return ni->ni_net->net_tunables.lct_max_tx_credits;

	credits = ni->ni_net->net_tunables.lct_max_tx_credits / ni->ni_ncpts;
	credits = max(credits, 8 * ni->ni_net->net_tunables.lct_peer_tx_credits);
	credits = min(credits, ni->ni_net->net_tunables.lct_max_tx_credits);

	return credits;
}

static void
lnet_ni_unlink_locked(struct lnet_ni *ni)
{
	/* move it to zombie list and nobody can find it anymore */
	LASSERT(!list_empty(&ni->ni_netlist));
	list_move(&ni->ni_netlist, &ni->ni_net->net_ni_zombie);
	lnet_ni_decref_locked(ni, 0);
}

static void
lnet_clear_zombies_nis_locked(struct lnet_net *net)
{
	int		i;
	int		islo;
	struct lnet_ni	*ni;
	struct list_head *zombie_list = &net->net_ni_zombie;

	/*
	 * Now wait for the NIs I just nuked to show up on the zombie
	 * list and shut them down in guaranteed thread context
	 */
	i = 2;
	while ((ni = list_first_entry_or_null(zombie_list,
					      struct lnet_ni,
					      ni_netlist)) != NULL) {
		int *ref;
		int j;

		list_del_init(&ni->ni_netlist);
		/* the ni should be in deleting state. If it's not it's
		 * a bug */
		LASSERT(ni->ni_state == LNET_NI_STATE_DELETING);
		cfs_percpt_for_each(ref, j, ni->ni_refs) {
			if (*ref == 0)
				continue;
			/* still busy, add it back to zombie list */
			list_add(&ni->ni_netlist, zombie_list);
			break;
		}

		if (!list_empty(&ni->ni_netlist)) {
			/* Unlock mutex while waiting to allow other
			 * threads to read the LNet state and fall through
			 * to avoid deadlock
			 */
			lnet_net_unlock(LNET_LOCK_EX);
			mutex_unlock(&the_lnet.ln_api_mutex);

			++i;
			if ((i & (-i)) == i) {
				CDEBUG(D_WARNING,
				       "Waiting for zombie LNI %s\n",
				       libcfs_nidstr(&ni->ni_nid));
			}
			schedule_timeout_uninterruptible(cfs_time_seconds(1));

			mutex_lock(&the_lnet.ln_api_mutex);
			lnet_net_lock(LNET_LOCK_EX);
			continue;
		}

		lnet_net_unlock(LNET_LOCK_EX);

		islo = ni->ni_net->net_lnd->lnd_type == LOLND;

		LASSERT(!in_interrupt());
		/* Holding the LND mutex makes it safe for lnd_shutdown
		 * to call module_put(). Module unload cannot finish
		 * until lnet_unregister_lnd() completes, and that
		 * requires the LND mutex.
		 */
		mutex_unlock(&the_lnet.ln_api_mutex);
		mutex_lock(&the_lnet.ln_lnd_mutex);
		(net->net_lnd->lnd_shutdown)(ni);
		mutex_unlock(&the_lnet.ln_lnd_mutex);
		mutex_lock(&the_lnet.ln_api_mutex);

		if (!islo)
			CDEBUG(D_LNI, "Removed LNI %s\n",
			      libcfs_nidstr(&ni->ni_nid));

		lnet_ni_free(ni);
		i = 2;
		lnet_net_lock(LNET_LOCK_EX);
	}
}

/* shutdown down the NI and release refcount */
static void
lnet_shutdown_lndni(struct lnet_ni *ni)
{
	int i;
	struct lnet_net *net = ni->ni_net;

	lnet_net_lock(LNET_LOCK_EX);
	lnet_ni_lock(ni);
	ni->ni_state = LNET_NI_STATE_DELETING;
	lnet_ni_unlock(ni);
	lnet_ni_unlink_locked(ni);
	lnet_incr_dlc_seq();
	lnet_net_unlock(LNET_LOCK_EX);

	/* clear messages for this NI on the lazy portal */
	for (i = 0; i < the_lnet.ln_nportals; i++)
		lnet_clear_lazy_portal(ni, i, "Shutting down NI");

	lnet_net_lock(LNET_LOCK_EX);
	lnet_clear_zombies_nis_locked(net);
	lnet_net_unlock(LNET_LOCK_EX);
}

static void
lnet_shutdown_lndnet(struct lnet_net *net)
{
	struct lnet_ni *ni;

	lnet_net_lock(LNET_LOCK_EX);

	list_del_init(&net->net_list);

	while ((ni = list_first_entry_or_null(&net->net_ni_list,
					      struct lnet_ni,
					      ni_netlist)) != NULL) {
		lnet_net_unlock(LNET_LOCK_EX);
		lnet_shutdown_lndni(ni);
		lnet_net_lock(LNET_LOCK_EX);
	}

	lnet_net_unlock(LNET_LOCK_EX);

	/* Do peer table cleanup for this net */
	lnet_peer_tables_cleanup(net);

	lnet_net_free(net);
}

static void
lnet_shutdown_lndnets(void)
{
	struct lnet_net *net;
	LIST_HEAD(resend);
	struct lnet_msg *msg, *tmp;

	/* NB called holding the global mutex */

	/* All quiet on the API front */
	LASSERT(the_lnet.ln_state == LNET_STATE_RUNNING ||
		the_lnet.ln_state == LNET_STATE_STOPPING);
	LASSERT(the_lnet.ln_refcount == 0);

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_state = LNET_STATE_STOPPING;

	/*
	 * move the nets to the zombie list to avoid them being
	 * picked up for new work. LONET is also included in the
	 * Nets that will be moved to the zombie list
	 */
	list_splice_init(&the_lnet.ln_nets, &the_lnet.ln_net_zombie);

	/* Drop the cached loopback Net. */
	if (the_lnet.ln_loni != NULL) {
		lnet_ni_decref_locked(the_lnet.ln_loni, 0);
		the_lnet.ln_loni = NULL;
	}
	lnet_net_unlock(LNET_LOCK_EX);

	/* iterate through the net zombie list and delete each net */
	while ((net = list_first_entry_or_null(&the_lnet.ln_net_zombie,
					       struct lnet_net,
					       net_list)) != NULL)
		lnet_shutdown_lndnet(net);

	spin_lock(&the_lnet.ln_msg_resend_lock);
	list_splice(&the_lnet.ln_msg_resend, &resend);
	spin_unlock(&the_lnet.ln_msg_resend_lock);

	list_for_each_entry_safe(msg, tmp, &resend, msg_list) {
		list_del_init(&msg->msg_list);
		msg->msg_no_resend = true;
		lnet_finalize(msg, -ECANCELED);
	}

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_state = LNET_STATE_SHUTDOWN;
	lnet_net_unlock(LNET_LOCK_EX);
}

static int
lnet_startup_lndni(struct lnet_ni *ni, struct lnet_lnd_tunables *tun)
{
	int			rc = -EINVAL;
	struct lnet_tx_queue	*tq;
	int			i;
	struct lnet_net		*net = ni->ni_net;

	mutex_lock(&the_lnet.ln_lnd_mutex);

	if (tun) {
		memcpy(&ni->ni_lnd_tunables, tun, sizeof(*tun));
		ni->ni_lnd_tunables_set = true;
	}

	rc = (net->net_lnd->lnd_startup)(ni);

	mutex_unlock(&the_lnet.ln_lnd_mutex);

	if (rc != 0) {
		LCONSOLE_ERROR("Error %d starting up LNI %s\n",
			       rc, libcfs_lnd2str(net->net_lnd->lnd_type));
		goto failed0;
	}

	lnet_net_lock(0);
	if (lnet_nid_to_ni_locked(&ni->ni_nid, 0)) {
		lnet_ni_addref_locked(ni, 0);
		lnet_net_unlock(0);
		return -EEXIST;
	}
	lnet_net_unlock(0);

	/* We keep a reference on the loopback net through the loopback NI */
	if (net->net_lnd->lnd_type == LOLND) {
		lnet_ni_addref(ni);
		LASSERT(the_lnet.ln_loni == NULL);
		the_lnet.ln_loni = ni;
		ni->ni_net->net_tunables.lct_peer_tx_credits = 0;
		ni->ni_net->net_tunables.lct_peer_rtr_credits = 0;
		ni->ni_net->net_tunables.lct_max_tx_credits = 0;
		ni->ni_net->net_tunables.lct_peer_timeout = 0;
		return 0;
	}

	if (ni->ni_net->net_tunables.lct_peer_tx_credits == 0 ||
	    ni->ni_net->net_tunables.lct_max_tx_credits == 0) {
		LCONSOLE_ERROR("LNI %s has no %scredits\n",
			       libcfs_lnd2str(net->net_lnd->lnd_type),
			       ni->ni_net->net_tunables.lct_peer_tx_credits == 0 ?
			       "" : "per-peer ");
		/* shutdown the NI since if we get here then it must've already
		 * been started
		 */
		lnet_shutdown_lndni(ni);
		return -EINVAL;
	}

	cfs_percpt_for_each(tq, i, ni->ni_tx_queues) {
		tq->tq_credits_min =
		tq->tq_credits_max =
		tq->tq_credits = lnet_ni_tq_credits(ni);
	}

	atomic_set(&ni->ni_tx_credits,
		   lnet_ni_tq_credits(ni) * ni->ni_ncpts);
	atomic_set(&ni->ni_healthv, LNET_MAX_HEALTH_VALUE);

	/* Nodes with small feet have little entropy. The NID for this
	 * node gives the most entropy in the low bits.
	 */
	add_device_randomness(&ni->ni_nid, sizeof(ni->ni_nid));

	CDEBUG(D_LNI, "Added LNI %s [%d/%d/%d/%d]\n",
		libcfs_nidstr(&ni->ni_nid),
		ni->ni_net->net_tunables.lct_peer_tx_credits,
		lnet_ni_tq_credits(ni) * LNET_CPT_NUMBER,
		ni->ni_net->net_tunables.lct_peer_rtr_credits,
		ni->ni_net->net_tunables.lct_peer_timeout);

	return 0;
failed0:
	lnet_ni_free(ni);
	return rc;
}

static const struct lnet_lnd *lnet_load_lnd(u32 lnd_type)
{
	const struct lnet_lnd *lnd;
	int rc = 0;

	mutex_lock(&the_lnet.ln_lnd_mutex);
	lnd = lnet_find_lnd_by_type(lnd_type);
	if (!lnd) {
		mutex_unlock(&the_lnet.ln_lnd_mutex);
		rc = request_module("%s", libcfs_lnd2modname(lnd_type));
		mutex_lock(&the_lnet.ln_lnd_mutex);

		lnd = lnet_find_lnd_by_type(lnd_type);
		if (!lnd) {
			mutex_unlock(&the_lnet.ln_lnd_mutex);
			CERROR("Can't load LND %s, module %s, rc=%d\n",
			libcfs_lnd2str(lnd_type),
			libcfs_lnd2modname(lnd_type), rc);
#ifndef HAVE_MODULE_LOADING_SUPPORT
			LCONSOLE_ERROR("Your kernel must be compiled with kernel module loading support.");
#endif
			return ERR_PTR(-EINVAL);
		}
	}
	mutex_unlock(&the_lnet.ln_lnd_mutex);

	return lnd;
}

static int
lnet_startup_lndnet(struct lnet_net *net, struct lnet_lnd_tunables *tun)
{
	struct lnet_ni *ni;
	struct lnet_net *net_l = NULL;
	LIST_HEAD(local_ni_list);
	int rc;
	int ni_count = 0;
	__u32 lnd_type;
	const struct lnet_lnd  *lnd;
	int peer_timeout =
		net->net_tunables.lct_peer_timeout;
	int maxtxcredits =
		net->net_tunables.lct_max_tx_credits;
	int peerrtrcredits =
		net->net_tunables.lct_peer_rtr_credits;

	/*
	 * make sure that this net is unique. If it isn't then
	 * we are adding interfaces to an already existing network, and
	 * 'net' is just a convenient way to pass in the list.
	 * if it is unique we need to find the LND and load it if
	 * necessary.
	 */
	if (lnet_net_unique(net->net_id, &the_lnet.ln_nets, &net_l)) {
		lnd_type = LNET_NETTYP(net->net_id);

		lnd = lnet_load_lnd(lnd_type);
		if (IS_ERR(lnd)) {
			rc = PTR_ERR(lnd);
			goto failed0;
		}

		mutex_lock(&the_lnet.ln_lnd_mutex);
		net->net_lnd = lnd;
		mutex_unlock(&the_lnet.ln_lnd_mutex);

		net_l = net;
	}

	/*
	 * net_l: if the network being added is unique then net_l
	 *        will point to that network
	 *        if the network being added is not unique then
	 *        net_l points to the existing network.
	 *
	 * When we enter the loop below, we'll pick NIs off he
	 * network beign added and start them up, then add them to
	 * a local ni list. Once we've successfully started all
	 * the NIs then we join the local NI list (of started up
	 * networks) with the net_l->net_ni_list, which should
	 * point to the correct network to add the new ni list to
	 *
	 * If any of the new NIs fail to start up, then we want to
	 * iterate through the local ni list, which should include
	 * any NIs which were successfully started up, and shut
	 * them down.
	 *
	 * After than we want to delete the network being added,
	 * to avoid a memory leak.
	 */
	while ((ni = list_first_entry_or_null(&net->net_ni_added,
					      struct lnet_ni,
					      ni_netlist)) != NULL) {
		list_del_init(&ni->ni_netlist);

		/* make sure that the the NI we're about to start
		 * up is actually unique. if it's not fail. */

		if (ni->ni_interface &&
		    !lnet_ni_unique_net(&net_l->net_ni_list,
					ni->ni_interface)) {
			rc = -EEXIST;
			goto failed1;
		}

		/* adjust the pointer the parent network, just in case it
		 * the net is a duplicate */
		ni->ni_net = net_l;

		rc = lnet_startup_lndni(ni, tun);

		if (rc == -EEXIST)
			list_add_tail(&ni->ni_netlist, &local_ni_list);

		if (rc != 0)
			goto failed1;

		lnet_ni_addref(ni);
		list_add_tail(&ni->ni_netlist, &local_ni_list);

		ni_count++;
	}

	lnet_net_lock(LNET_LOCK_EX);
	list_splice_tail(&local_ni_list, &net_l->net_ni_list);
	lnet_incr_dlc_seq();

	list_for_each_entry(ni, &net_l->net_ni_list, ni_netlist) {
		if (!ni)
			break;
		lnet_ni_lock(ni);
		ni->ni_state = LNET_NI_STATE_ACTIVE;
		lnet_ni_unlock(ni);
	}
	lnet_net_unlock(LNET_LOCK_EX);

	/* if the network is not unique then we don't want to keep
	 * it around after we're done. Free it. Otherwise add that
	 * net to the global the_lnet.ln_nets */
	if (net_l != net && net_l != NULL) {
		/*
		 * TODO - note. currently the tunables can not be updated
		 * once added
		 */
		lnet_net_free(net);
	} else {
		/*
		 * restore tunables after it has been overwitten by the
		 * lnd
		 */
		if (peer_timeout != -1)
			net->net_tunables.lct_peer_timeout = peer_timeout;
		if (maxtxcredits != -1)
			net->net_tunables.lct_max_tx_credits = maxtxcredits;
		if (peerrtrcredits != -1)
			net->net_tunables.lct_peer_rtr_credits = peerrtrcredits;

		lnet_net_lock(LNET_LOCK_EX);
		list_add_tail(&net->net_list, &the_lnet.ln_nets);
		lnet_net_unlock(LNET_LOCK_EX);
	}

	return ni_count;

failed1:
	/*
	 * shutdown the new NIs that are being started up
	 * free the NET being started
	 */
	while ((ni = list_first_entry_or_null(&local_ni_list,
					      struct lnet_ni,
					      ni_netlist)) != NULL)
		lnet_shutdown_lndni(ni);

failed0:
	lnet_net_free(net);

	return rc;
}

static int
lnet_startup_lndnets(struct list_head *netlist)
{
	struct lnet_net		*net;
	int			rc;
	int			ni_count = 0;

	/*
	 * Change to running state before bringing up the LNDs. This
	 * allows lnet_shutdown_lndnets() to assert that we've passed
	 * through here.
	 */
	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_state = LNET_STATE_RUNNING;
	lnet_net_unlock(LNET_LOCK_EX);

	while ((net = list_first_entry_or_null(netlist,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);

		rc = lnet_startup_lndnet(net, NULL);

		if (rc < 0)
			goto failed;

		ni_count += rc;
	}

	return ni_count;
failed:
	lnet_shutdown_lndnets();

	return rc;
}

static int lnet_genl_parse_list(struct sk_buff *msg,
				const struct ln_key_list *data[], u16 idx)
{
	const struct ln_key_list *list = data[idx];
	const struct ln_key_props *props;
	struct nlattr *node;
	u16 count;

	if (!list)
		return 0;

	if (!list->lkl_maxattr)
		return -ERANGE;

	props = list->lkl_list;
	if (!props)
		return -EINVAL;

	node = nla_nest_start(msg, LN_SCALAR_ATTR_LIST);
	if (!node)
		return -ENOBUFS;

	for (count = 1; count <= list->lkl_maxattr; count++) {
		struct nlattr *key = nla_nest_start(msg, count);

		if (!key)
			return -EMSGSIZE;

		if (count == 1)
			nla_put_u16(msg, LN_SCALAR_ATTR_LIST_SIZE,
				    list->lkl_maxattr);

		nla_put_u16(msg, LN_SCALAR_ATTR_INDEX, count);
		if (props[count].lkp_value)
			nla_put_string(msg, LN_SCALAR_ATTR_VALUE,
				       props[count].lkp_value);
		if (props[count].lkp_key_format)
			nla_put_u16(msg, LN_SCALAR_ATTR_KEY_FORMAT,
				    props[count].lkp_key_format);
		nla_put_u16(msg, LN_SCALAR_ATTR_NLA_TYPE,
			    props[count].lkp_data_type);
		if (props[count].lkp_data_type == NLA_NESTED) {
			int rc;

			rc = lnet_genl_parse_list(msg, data, ++idx);
			if (rc < 0)
				return rc;
			idx = rc;
		}

		nla_nest_end(msg, key);
	}

	nla_nest_end(msg, node);
	return idx;
}

int lnet_genl_send_scalar_list(struct sk_buff *msg, u32 portid, u32 seq,
			       const struct genl_family *family, int flags,
			       u8 cmd, const struct ln_key_list *data[])
{
	int rc = 0;
	void *hdr;

	if (!data[0])
		return -EINVAL;

	hdr = genlmsg_put(msg, portid, seq, family, flags, cmd);
	if (!hdr)
		GOTO(canceled, rc = -EMSGSIZE);

	rc = lnet_genl_parse_list(msg, data, 0);
	if (rc < 0)
		GOTO(canceled, rc);

	genlmsg_end(msg, hdr);
canceled:
	if (rc < 0)
		genlmsg_cancel(msg, hdr);
	return rc > 0 ? 0 : rc;
}
EXPORT_SYMBOL(lnet_genl_send_scalar_list);

static int
nla_extract_val(struct nlattr **attr, int *rem,
		enum lnet_nl_scalar_attrs attr_type,
		void *ret, int ret_size,
		struct netlink_ext_ack *extack)
{
	int rc = -EINVAL;

	ENTRY;
	*attr = nla_next(*attr, rem);
	if (nla_type(*attr) != attr_type) {
		CDEBUG(D_NET, "nla_type %d expect %d\n", nla_type(*attr),
		       attr_type);
		NL_SET_ERR_MSG(extack, "Invalid type for attribute");
		RETURN(rc);
	}

	switch (attr_type) {
	case LN_SCALAR_ATTR_VALUE:
		rc = nla_strscpy(ret, *attr, ret_size);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack,
				       "Failed to extract value from string attribute");
		} else {
			rc = 0;
		}
		break;
	case LN_SCALAR_ATTR_INT_VALUE:
		if (ret_size == sizeof(u64)) {
			*(u64 *)ret = nla_get_s64(*attr);
			rc = 0;
		}
		break;
	default:
		NL_SET_ERR_MSG(extack, "Unrecognized attribute type");
		ret = NULL;
		break;
	}
	RETURN(rc);
}

static int
nla_strnid(struct nlattr **attr, struct lnet_nid *nid, int *rem,
	   struct netlink_ext_ack *extack)
{
	char nidstr[LNET_NIDSTR_SIZE];
	int rc;

	ENTRY;
	rc = nla_extract_val(attr, rem, LN_SCALAR_ATTR_VALUE,
			     nidstr, sizeof(nidstr), extack);
	if (rc < 0) {
		NL_SET_ERR_MSG(extack, "failed to copy nidstring attribute");
		RETURN(rc);
	}

	rc = libcfs_strnid(nid, strim(nidstr));
	if (rc < 0) {
		CDEBUG(D_NET, "Invalid nidstr \"%s\"\n", nidstr);
		NL_SET_ERR_MSG(extack, "failed to convert nidstring to NID");
		RETURN(rc);
	}

	CDEBUG(D_NET, "%s -> %s\n", nidstr, libcfs_nidstr(nid));

	RETURN(0);
}

static struct genl_family lnet_family;

/**
 * Initialize LNet library.
 *
 * Automatically called at module loading time. Caller has to call
 * lnet_lib_exit() after a call to lnet_lib_init(), if and only if the
 * latter returned 0. It must be called exactly once.
 *
 * \retval 0 on success
 * \retval -ve on failures.
 */
int lnet_lib_init(void)
{
	int rc;

	lnet_assert_wire_constants();

	/* refer to global cfs_cpt_table for now */
	the_lnet.ln_cpt_table = cfs_cpt_tab;
	the_lnet.ln_cpt_number = cfs_cpt_number(cfs_cpt_tab);

	LASSERT(the_lnet.ln_cpt_number > 0);
	if (the_lnet.ln_cpt_number > LNET_CPT_MAX) {
		/* we are under risk of consuming all lh_cookie */
		CERROR("Can't have %d CPTs for LNet (max allowed is %d), "
		       "please change setting of CPT-table and retry\n",
		       the_lnet.ln_cpt_number, LNET_CPT_MAX);
		return -E2BIG;
	}

	while ((1 << the_lnet.ln_cpt_bits) < the_lnet.ln_cpt_number)
		the_lnet.ln_cpt_bits++;

	rc = lnet_create_locks();
	if (rc != 0) {
		CERROR("Can't create LNet global locks: %d\n", rc);
		return rc;
	}

	rc = genl_register_family(&lnet_family);
	if (rc != 0) {
		lnet_destroy_locks();
		CERROR("Can't register LNet netlink family: %d\n", rc);
		return rc;
	}

	the_lnet.ln_refcount = 0;
	INIT_LIST_HEAD(&the_lnet.ln_net_zombie);
	INIT_LIST_HEAD(&the_lnet.ln_msg_resend);

	/* The hash table size is the number of bits it takes to express the set
	 * ln_num_routes, minus 1 (better to under estimate than over so we
	 * don't waste memory). */
	if (rnet_htable_size <= 0)
		rnet_htable_size = LNET_REMOTE_NETS_HASH_DEFAULT;
	else if (rnet_htable_size > LNET_REMOTE_NETS_HASH_MAX)
		rnet_htable_size = LNET_REMOTE_NETS_HASH_MAX;
	the_lnet.ln_remote_nets_hbits = max_t(int, 1,
					   order_base_2(rnet_htable_size) - 1);

	/* All LNDs apart from the LOLND are in separate modules.  They
	 * register themselves when their module loads, and unregister
	 * themselves when their module is unloaded. */
	lnet_register_lnd(&the_lolnd);
	return 0;
}

/**
 * Finalize LNet library.
 *
 * \pre lnet_lib_init() called with success.
 * \pre All LNet users called LNetNIFini() for matching LNetNIInit() calls.
 *
 * As this happens at module-unload, all lnds must already be unloaded,
 * so they must already be unregistered.
 */
void lnet_lib_exit(void)
{
	int i;

	LASSERT(the_lnet.ln_refcount == 0);
	lnet_unregister_lnd(&the_lolnd);
	for (i = 0; i < NUM_LNDS; i++)
		LASSERT(!the_lnet.ln_lnds[i]);
	lnet_destroy_locks();
	genl_unregister_family(&lnet_family);
}

/**
 * Set LNet PID and start LNet interfaces, routing, and forwarding.
 *
 * Users must call this function at least once before any other functions.
 * For each successful call there must be a corresponding call to
 * LNetNIFini(). For subsequent calls to LNetNIInit(), \a requested_pid is
 * ignored.
 *
 * The PID used by LNet may be different from the one requested.
 * See LNetGetId().
 *
 * \param requested_pid PID requested by the caller.
 *
 * \return >= 0 on success, and < 0 error code on failures.
 */
int
LNetNIInit(lnet_pid_t requested_pid)
{
	int im_a_router = 0;
	int rc;
	int ni_bytes;
	struct lnet_ping_buffer	*pbuf;
	struct lnet_handle_md ping_mdh;
	LIST_HEAD(net_head);
	struct lnet_net	*net;

	mutex_lock(&the_lnet.ln_api_mutex);

	CDEBUG(D_OTHER, "refs %d\n", the_lnet.ln_refcount);

	if (the_lnet.ln_state == LNET_STATE_STOPPING) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ESHUTDOWN;
	}

	if (the_lnet.ln_refcount > 0) {
		rc = the_lnet.ln_refcount++;
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	rc = lnet_prepare(requested_pid);
	if (rc != 0) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	/* create a network for Loopback network */
	net = lnet_net_alloc(LNET_MKNET(LOLND, 0), &net_head);
	if (net == NULL) {
		rc = -ENOMEM;
		goto err_empty_list;
	}

	/* Add in the loopback NI */
	if (lnet_ni_alloc(net, NULL, NULL) == NULL) {
		rc = -ENOMEM;
		goto err_empty_list;
	}

	if (use_tcp_bonding)
		CWARN("use_tcp_bonding has been removed. Use Multi-Rail and Dynamic Discovery instead, see LU-13641\n");

	/* If LNet is being initialized via DLC it is possible
	 * that the user requests not to load module parameters (ones which
	 * are supported by DLC) on initialization.  Therefore, make sure not
	 * to load networks, routes and forwarding from module parameters
	 * in this case.  On cleanup in case of failure only clean up
	 * routes if it has been loaded */
	if (!the_lnet.ln_nis_from_mod_params) {
		rc = lnet_parse_networks(&net_head, lnet_get_networks());
		if (rc < 0)
			goto err_empty_list;
	}

	rc = lnet_startup_lndnets(&net_head);
	if (rc < 0)
		goto err_empty_list;

	if (!the_lnet.ln_nis_from_mod_params) {
		rc = lnet_parse_routes(lnet_get_routes(), &im_a_router);
		if (rc != 0)
			goto err_shutdown_lndnis;

		rc = lnet_rtrpools_alloc(im_a_router);
		if (rc != 0)
			goto err_destroy_routes;
	}

	rc = lnet_acceptor_start();
	if (rc != 0)
		goto err_destroy_routes;

	the_lnet.ln_refcount = 1;
	/* Now I may use my own API functions... */

	ni_bytes = LNET_PING_INFO_HDR_SIZE;
	list_for_each_entry(net, &the_lnet.ln_nets, net_list)
		ni_bytes += lnet_get_net_ni_bytes_locked(net);

	rc = lnet_ping_target_setup(&pbuf, &ping_mdh, ni_bytes, true);
	if (rc != 0)
		goto err_acceptor_stop;

	lnet_ping_target_update(pbuf, ping_mdh);

	the_lnet.ln_mt_handler = lnet_mt_event_handler;

	rc = lnet_push_target_init();
	if (rc != 0)
		goto err_stop_ping;

	rc = lnet_monitor_thr_start();
	if (rc != 0)
		goto err_destroy_push_target;

	rc = lnet_peer_discovery_start();
	if (rc != 0)
		goto err_stop_monitor_thr;

	lnet_fault_init();
	lnet_router_debugfs_init();

	mutex_unlock(&the_lnet.ln_api_mutex);

	complete_all(&the_lnet.ln_started);

	/* wait for all routers to start */
	lnet_wait_router_start();

	return 0;

err_stop_monitor_thr:
	lnet_monitor_thr_stop();
err_destroy_push_target:
	lnet_push_target_fini();
err_stop_ping:
	lnet_ping_target_fini();
err_acceptor_stop:
	the_lnet.ln_refcount = 0;
	lnet_acceptor_stop();
err_destroy_routes:
	if (!the_lnet.ln_nis_from_mod_params)
		lnet_destroy_routes();
err_shutdown_lndnis:
	lnet_shutdown_lndnets();
err_empty_list:
	lnet_unprepare();
	LASSERT(rc < 0);
	mutex_unlock(&the_lnet.ln_api_mutex);
	while ((net = list_first_entry_or_null(&net_head,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);
		lnet_net_free(net);
	}
	return rc;
}
EXPORT_SYMBOL(LNetNIInit);

/**
 * Stop LNet interfaces, routing, and forwarding.
 *
 * Users must call this function once for each successful call to LNetNIInit().
 * Once the LNetNIFini() operation has been started, the results of pending
 * API operations are undefined.
 *
 * \return always 0 for current implementation.
 */
int
LNetNIFini(void)
{
	mutex_lock(&the_lnet.ln_api_mutex);

	LASSERT(the_lnet.ln_refcount > 0);

	if (the_lnet.ln_refcount != 1) {
		the_lnet.ln_refcount--;
	} else {
		lnet_handler_t dc_handler = the_lnet.ln_dc_handler;
		LASSERT(!the_lnet.ln_niinit_self);

		lnet_net_lock(LNET_LOCK_EX);
		the_lnet.ln_state = LNET_STATE_STOPPING;
		lnet_net_unlock(LNET_LOCK_EX);

		lnet_fault_fini();

		lnet_router_debugfs_fini();
		lnet_peer_discovery_stop();
		lnet_monitor_thr_stop();
		lnet_assert_handler_unused(dc_handler);
		lnet_push_target_fini();
		lnet_ping_target_fini();

		/* Teardown fns that use my own API functions BEFORE here */
		the_lnet.ln_refcount = 0;

		lnet_acceptor_stop();
		lnet_destroy_routes();
		lnet_shutdown_lndnets();
		lnet_unprepare();
	}

	mutex_unlock(&the_lnet.ln_api_mutex);
	return 0;
}
EXPORT_SYMBOL(LNetNIFini);

/**
 * Grabs the ni data from the ni structure and fills the out
 * parameters
 *
 * \param[in] ni network	interface structure
 * \param[out] cfg_ni		NI config information
 * \param[out] tun		network and LND tunables
 */
static void
lnet_fill_ni_info(struct lnet_ni *ni, struct lnet_ioctl_config_ni *cfg_ni,
		   struct lnet_ioctl_config_lnd_tunables *tun,
		   struct lnet_ioctl_element_stats *stats,
		   __u32 tun_size)
{
	size_t min_size = 0;
	int i;

	if (!ni || !cfg_ni || !tun || !nid_is_nid4(&ni->ni_nid))
		return;

	if (ni->ni_interface != NULL) {
		strncpy(cfg_ni->lic_ni_intf,
			ni->ni_interface,
			sizeof(cfg_ni->lic_ni_intf));
	}

	cfg_ni->lic_nid = lnet_nid_to_nid4(&ni->ni_nid);
	cfg_ni->lic_status = lnet_ni_get_status_locked(ni);
	cfg_ni->lic_dev_cpt = ni->ni_dev_cpt;

	memcpy(&tun->lt_cmn, &ni->ni_net->net_tunables, sizeof(tun->lt_cmn));

	if (stats) {
		stats->iel_send_count = lnet_sum_stats(&ni->ni_stats,
						       LNET_STATS_TYPE_SEND);
		stats->iel_recv_count = lnet_sum_stats(&ni->ni_stats,
						       LNET_STATS_TYPE_RECV);
		stats->iel_drop_count = lnet_sum_stats(&ni->ni_stats,
						       LNET_STATS_TYPE_DROP);
	}

	/*
	 * tun->lt_tun will always be present, but in order to be
	 * backwards compatible, we need to deal with the cases when
	 * tun->lt_tun is smaller than what the kernel has, because it
	 * comes from an older version of a userspace program, then we'll
	 * need to copy as much information as we have available space.
	 */
	min_size = tun_size - sizeof(tun->lt_cmn);
	memcpy(&tun->lt_tun, &ni->ni_lnd_tunables, min_size);

	/* copy over the cpts */
	if (ni->ni_ncpts == LNET_CPT_NUMBER &&
	    ni->ni_cpts == NULL)  {
		for (i = 0; i < ni->ni_ncpts; i++)
			cfg_ni->lic_cpts[i] = i;
	} else {
		for (i = 0;
		     ni->ni_cpts != NULL && i < ni->ni_ncpts &&
		     i < LNET_MAX_SHOW_NUM_CPT;
		     i++)
			cfg_ni->lic_cpts[i] = ni->ni_cpts[i];
	}
	cfg_ni->lic_ncpts = ni->ni_ncpts;
}

/**
 * NOTE: This is a legacy function left in the code to be backwards
 * compatible with older userspace programs. It should eventually be
 * removed.
 *
 * Grabs the ni data from the ni structure and fills the out
 * parameters
 *
 * \param[in] ni network	interface structure
 * \param[out] config		config information
 */
static void
lnet_fill_ni_info_legacy(struct lnet_ni *ni,
			 struct lnet_ioctl_config_data *config)
{
	struct lnet_ioctl_net_config *net_config;
	struct lnet_ioctl_config_lnd_tunables *lnd_cfg = NULL;
	size_t min_size, tunable_size = 0;
	int i;

	if (!ni || !config || !nid_is_nid4(&ni->ni_nid))
		return;

	net_config = (struct lnet_ioctl_net_config *) config->cfg_bulk;
	if (!net_config)
		return;

	if (!ni->ni_interface)
		return;

	strncpy(net_config->ni_interface,
		ni->ni_interface,
		sizeof(net_config->ni_interface));

	config->cfg_nid = lnet_nid_to_nid4(&ni->ni_nid);
	config->cfg_config_u.cfg_net.net_peer_timeout =
		ni->ni_net->net_tunables.lct_peer_timeout;
	config->cfg_config_u.cfg_net.net_max_tx_credits =
		ni->ni_net->net_tunables.lct_max_tx_credits;
	config->cfg_config_u.cfg_net.net_peer_tx_credits =
		ni->ni_net->net_tunables.lct_peer_tx_credits;
	config->cfg_config_u.cfg_net.net_peer_rtr_credits =
		ni->ni_net->net_tunables.lct_peer_rtr_credits;

	net_config->ni_status = lnet_ni_get_status_locked(ni);

	if (ni->ni_cpts) {
		int num_cpts = min(ni->ni_ncpts, LNET_MAX_SHOW_NUM_CPT);

		for (i = 0; i < num_cpts; i++)
			net_config->ni_cpts[i] = ni->ni_cpts[i];

		config->cfg_ncpts = num_cpts;
	}

	/*
	 * See if user land tools sent in a newer and larger version
	 * of struct lnet_tunables than what the kernel uses.
	 */
	min_size = sizeof(*config) + sizeof(*net_config);

	if (config->cfg_hdr.ioc_len > min_size)
		tunable_size = config->cfg_hdr.ioc_len - min_size;

	/* Don't copy too much data to user space */
	min_size = min(tunable_size, sizeof(ni->ni_lnd_tunables));
	lnd_cfg = (struct lnet_ioctl_config_lnd_tunables *)net_config->cfg_bulk;

	if (lnd_cfg && min_size) {
		memcpy(&lnd_cfg->lt_tun, &ni->ni_lnd_tunables, min_size);
		config->cfg_config_u.cfg_net.net_interface_count = 1;

		/* Tell user land that kernel side has less data */
		if (tunable_size > sizeof(ni->ni_lnd_tunables)) {
			min_size = tunable_size - sizeof(ni->ni_lnd_tunables);
			config->cfg_hdr.ioc_len -= min_size;
		}
	}
}

struct lnet_ni *
lnet_get_ni_idx_locked(int idx)
{
	struct lnet_ni		*ni;
	struct lnet_net		*net;

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (idx-- == 0)
				return ni;
		}
	}

	return NULL;
}

int lnet_get_net_healthv_locked(struct lnet_net *net)
{
	struct lnet_ni *ni;
	int best_healthv = 0;
	int healthv, ni_fatal;

	list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
		healthv = atomic_read(&ni->ni_healthv);
		ni_fatal = atomic_read(&ni->ni_fatal_error_on);
		if (!ni_fatal && healthv > best_healthv)
			best_healthv = healthv;
	}

	return best_healthv;
}

struct lnet_ni *
lnet_get_next_ni_locked(struct lnet_net *mynet, struct lnet_ni *prev)
{
	struct lnet_ni		*ni;
	struct lnet_net		*net = mynet;

	/*
	 * It is possible that the net has been cleaned out while there is
	 * a message being sent. This function accessed the net without
	 * checking if the list is empty
	 */
	if (!prev) {
		if (!net)
			net = list_first_entry(&the_lnet.ln_nets,
					       struct lnet_net,
					       net_list);
		if (list_empty(&net->net_ni_list))
			return NULL;
		ni = list_first_entry(&net->net_ni_list, struct lnet_ni,
				      ni_netlist);

		return ni;
	}

	if (prev->ni_netlist.next == &prev->ni_net->net_ni_list) {
		/* if you reached the end of the ni list and the net is
		 * specified, then there are no more nis in that net */
		if (net != NULL)
			return NULL;

		/* we reached the end of this net ni list. move to the
		 * next net */
		if (prev->ni_net->net_list.next == &the_lnet.ln_nets)
			/* no more nets and no more NIs. */
			return NULL;

		/* get the next net */
		net = list_first_entry(&prev->ni_net->net_list, struct lnet_net,
				       net_list);
		if (list_empty(&net->net_ni_list))
			return NULL;
		/* get the ni on it */
		ni = list_first_entry(&net->net_ni_list, struct lnet_ni,
				      ni_netlist);

		return ni;
	}

	if (list_empty(&prev->ni_netlist))
		return NULL;

	/* there are more nis left */
	ni = list_first_entry(&prev->ni_netlist, struct lnet_ni, ni_netlist);

	return ni;
}

static int
lnet_get_net_config(struct lnet_ioctl_config_data *config)
{
	struct lnet_ni *ni;
	int cpt;
	int rc = -ENOENT;
	int idx = config->cfg_count;

	cpt = lnet_net_lock_current();

	ni = lnet_get_ni_idx_locked(idx);

	if (ni != NULL) {
		rc = 0;
		lnet_ni_lock(ni);
		lnet_fill_ni_info_legacy(ni, config);
		lnet_ni_unlock(ni);
	}

	lnet_net_unlock(cpt);
	return rc;
}

static int
lnet_get_ni_config(struct lnet_ioctl_config_ni *cfg_ni,
		   struct lnet_ioctl_config_lnd_tunables *tun,
		   struct lnet_ioctl_element_stats *stats,
		   __u32 tun_size)
{
	struct lnet_ni		*ni;
	int			cpt;
	int			rc = -ENOENT;

	if (!cfg_ni || !tun || !stats)
		return -EINVAL;

	cpt = lnet_net_lock_current();

	ni = lnet_get_ni_idx_locked(cfg_ni->lic_idx);

	if (ni) {
		rc = 0;
		lnet_ni_lock(ni);
		lnet_fill_ni_info(ni, cfg_ni, tun, stats, tun_size);
		lnet_ni_unlock(ni);
	}

	lnet_net_unlock(cpt);
	return rc;
}

static int lnet_get_ni_stats(struct lnet_ioctl_element_msg_stats *msg_stats)
{
	struct lnet_ni *ni;
	int rc = -ENOENT;

	if (!msg_stats)
		return -EINVAL;

	ni = lnet_get_ni_idx_locked(msg_stats->im_idx);

	if (ni) {
		lnet_usr_translate_stats(msg_stats, &ni->ni_stats);
		rc = 0;
	}

	return rc;
}

static int lnet_add_net_common(struct lnet_net *net,
			       struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct lnet_handle_md ping_mdh;
	struct lnet_ping_buffer *pbuf;
	struct lnet_remotenet *rnet;
	struct lnet_ni *ni;
	u32 net_id;
	int rc;

	lnet_net_lock(LNET_LOCK_EX);
	rnet = lnet_find_rnet_locked(net->net_id);
	lnet_net_unlock(LNET_LOCK_EX);
	/*
	 * make sure that the net added doesn't invalidate the current
	 * configuration LNet is keeping
	 */
	if (rnet) {
		CERROR("Adding net %s will invalidate routing configuration\n",
		       libcfs_net2str(net->net_id));
		lnet_net_free(net);
		return -EUSERS;
	}

	if (tun)
		memcpy(&net->net_tunables,
		       &tun->lt_cmn, sizeof(net->net_tunables));
	else
		memset(&net->net_tunables, -1, sizeof(net->net_tunables));

	net_id = net->net_id;

	rc = lnet_startup_lndnet(net,
				 (tun) ? &tun->lt_tun : NULL);
	if (rc < 0)
		return rc;

	/* make sure you calculate the correct number of slots in the ping
	 * buffer. Since the ping info is a flattened list of all the NIs,
	 * we should allocate enough slots to accomodate the number of NIs
	 * which will be added.
	 */
	rc = lnet_ping_target_setup(&pbuf, &ping_mdh,
				    LNET_PING_INFO_HDR_SIZE +
				    lnet_get_ni_bytes(),
				    false);
	if (rc < 0) {
		lnet_shutdown_lndnet(net);
		return rc;
	}

	lnet_net_lock(LNET_LOCK_EX);
	net = lnet_get_net_locked(net_id);
	LASSERT(net);

	/* apply the UDSPs */
	rc = lnet_udsp_apply_policies_on_net(net);
	if (rc)
		CERROR("Failed to apply UDSPs on local net %s\n",
		       libcfs_net2str(net->net_id));

	/* At this point we lost track of which NI was just added, so we
	 * just re-apply the policies on all of the NIs on this net
	 */
	list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
		rc = lnet_udsp_apply_policies_on_ni(ni);
		if (rc)
			CERROR("Failed to apply UDSPs on ni %s\n",
			       libcfs_nidstr(&ni->ni_nid));
	}
	lnet_net_unlock(LNET_LOCK_EX);

	/*
	 * Start the acceptor thread if this is the first network
	 * being added that requires the thread.
	 */
	if (net->net_lnd->lnd_accept) {
		rc = lnet_acceptor_start();
		if (rc < 0) {
			/* shutdown the net that we just started */
			CERROR("Failed to start up acceptor thread\n");
			lnet_shutdown_lndnet(net);
			goto failed;
		}
	}

	lnet_net_lock(LNET_LOCK_EX);
	lnet_peer_net_added(net);
	lnet_net_unlock(LNET_LOCK_EX);

	lnet_ping_target_update(pbuf, ping_mdh);

	return 0;

failed:
	lnet_ping_md_unlink(pbuf, &ping_mdh);
	lnet_ping_buffer_decref(pbuf);
	return rc;
}

static void
lnet_set_tune_defaults(struct lnet_ioctl_config_lnd_tunables *tun)
{
	if (tun) {
		if (tun->lt_cmn.lct_peer_timeout < 0)
			tun->lt_cmn.lct_peer_timeout = DEFAULT_PEER_TIMEOUT;
		if (!tun->lt_cmn.lct_peer_tx_credits)
			tun->lt_cmn.lct_peer_tx_credits = DEFAULT_PEER_CREDITS;
		if (!tun->lt_cmn.lct_max_tx_credits)
			tun->lt_cmn.lct_max_tx_credits = DEFAULT_CREDITS;
	}
}

static int lnet_handle_legacy_ip2nets(char *ip2nets,
				      struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct lnet_net *net;
	const char *nets;
	int rc;
	LIST_HEAD(net_head);

	rc = lnet_parse_ip2nets(&nets, ip2nets);
	if (rc < 0)
		return rc;

	rc = lnet_parse_networks(&net_head, nets);
	if (rc < 0)
		return rc;

	lnet_set_tune_defaults(tun);

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto out;
	}

	while ((net = list_first_entry_or_null(&net_head,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);
		rc = lnet_add_net_common(net, tun);
		if (rc < 0)
			goto out;
	}

out:
	mutex_unlock(&the_lnet.ln_api_mutex);

	while ((net = list_first_entry_or_null(&net_head,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);
		lnet_net_free(net);
	}
	return rc;
}

int lnet_dyn_add_ni(struct lnet_ioctl_config_ni *conf, u32 net_id,
		    struct lnet_nid *nid,
		    struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct lnet_net *net;
	struct lnet_ni *ni;
	int rc, i;
	u32 lnd_type;

	/* handle legacy ip2nets from DLC */
	if (conf->lic_legacy_ip2nets[0] != '\0')
		return lnet_handle_legacy_ip2nets(conf->lic_legacy_ip2nets,
						  tun);

	lnd_type = LNET_NETTYP(net_id);

	if (!libcfs_isknown_lnd(lnd_type)) {
		CERROR("No valid net and lnd information provided\n");
		return -ENOENT;
	}

	net = lnet_net_alloc(net_id, NULL);
	if (!net)
		return -ENOMEM;

	for (i = 0; i < conf->lic_ncpts; i++) {
		if (conf->lic_cpts[i] >= LNET_CPT_NUMBER) {
			lnet_net_free(net);
			return -ERANGE;
		}
	}

	ni = lnet_ni_alloc_w_cpt_array(net, nid, conf->lic_cpts,
				       conf->lic_ncpts, conf->lic_ni_intf);
	if (!ni) {
		lnet_net_free(net);
		return -ENOMEM;
	}

	lnet_set_tune_defaults(tun);

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		lnet_net_free(net);
		rc = -ESHUTDOWN;
	} else {
		rc = lnet_add_net_common(net, tun);
	}

	mutex_unlock(&the_lnet.ln_api_mutex);

	/* If NI already exist delete this new unused copy */
	if (rc == -EEXIST)
		lnet_ni_free(ni);

	return rc;
}

int lnet_dyn_del_ni(struct lnet_nid *nid)
{
	struct lnet_net *net;
	struct lnet_ni *ni;
	u32 net_id = LNET_NID_NET(nid);
	struct lnet_ping_buffer *pbuf;
	struct lnet_handle_md ping_mdh;
	int net_bytes, rc;
	bool net_empty;

	/* don't allow userspace to shutdown the LOLND */
	if (LNET_NETTYP(net_id) == LOLND)
		return -EINVAL;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto unlock_api_mutex;
	}

	lnet_net_lock(0);

	net = lnet_get_net_locked(net_id);
	if (!net) {
		CERROR("net %s not found\n",
		       libcfs_net2str(net_id));
		rc = -ENOENT;
		goto unlock_net;
	}

	if (!nid_addr_is_set(nid)) {
		/* remove the entire net */
		net_bytes = lnet_get_net_ni_bytes_locked(net);

		lnet_net_unlock(0);

		/* create and link a new ping info, before removing the old one */
		rc = lnet_ping_target_setup(&pbuf, &ping_mdh,
					    LNET_PING_INFO_HDR_SIZE +
					    lnet_get_ni_bytes() - net_bytes,
					    false);
		if (rc != 0)
			goto unlock_api_mutex;

		lnet_shutdown_lndnet(net);

		lnet_acceptor_stop();

		lnet_ping_target_update(pbuf, ping_mdh);

		goto unlock_api_mutex;
	}

	ni = lnet_nid_to_ni_locked(nid, 0);
	if (!ni) {
		CERROR("nid %s not found\n", libcfs_nidstr(nid));
		rc = -ENOENT;
		goto unlock_net;
	}

	net_bytes = lnet_get_net_ni_bytes_locked(net);
	net_empty = list_is_singular(&net->net_ni_list);

	lnet_net_unlock(0);

	/* create and link a new ping info, before removing the old one */
	rc = lnet_ping_target_setup(&pbuf, &ping_mdh,
				    (LNET_PING_INFO_HDR_SIZE +
				     lnet_get_ni_bytes() -
				     lnet_ping_sts_size(&ni->ni_nid)),
				    false);
	if (rc != 0)
		goto unlock_api_mutex;

	lnet_shutdown_lndni(ni);

	lnet_acceptor_stop();

	lnet_ping_target_update(pbuf, ping_mdh);

	/* check if the net is empty and remove it if it is */
	if (net_empty)
		lnet_shutdown_lndnet(net);

	goto unlock_api_mutex;

unlock_net:
	lnet_net_unlock(0);
unlock_api_mutex:
	mutex_unlock(&the_lnet.ln_api_mutex);

	return rc;
}

/*
 * lnet_dyn_add_net and lnet_dyn_del_net are now deprecated.
 * They are only expected to be called for unique networks.
 * That can be as a result of older DLC library
 * calls. Multi-Rail DLC and beyond no longer uses these APIs.
 */
int
lnet_dyn_add_net(struct lnet_ioctl_config_data *conf)
{
	struct lnet_net *net;
	LIST_HEAD(net_head);
	int rc;
	struct lnet_ioctl_config_lnd_tunables tun;
	const char *nets = conf->cfg_config_u.cfg_net.net_intf;

	/* Create a net/ni structures for the network string */
	rc = lnet_parse_networks(&net_head, nets);
	if (rc <= 0)
		return rc == 0 ? -EINVAL : rc;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto out_unlock_clean;
	}

	if (rc > 1) {
		rc = -EINVAL; /* only add one network per call */
		goto out_unlock_clean;
	}

	net = list_first_entry(&net_head, struct lnet_net, net_list);
	list_del_init(&net->net_list);

	LASSERT(lnet_net_unique(net->net_id, &the_lnet.ln_nets, NULL));

	memset(&tun, 0, sizeof(tun));

	tun.lt_cmn.lct_peer_timeout =
	  (!conf->cfg_config_u.cfg_net.net_peer_timeout) ? DEFAULT_PEER_TIMEOUT :
		conf->cfg_config_u.cfg_net.net_peer_timeout;
	tun.lt_cmn.lct_peer_tx_credits =
	  (!conf->cfg_config_u.cfg_net.net_peer_tx_credits) ? DEFAULT_PEER_CREDITS :
		conf->cfg_config_u.cfg_net.net_peer_tx_credits;
	tun.lt_cmn.lct_peer_rtr_credits =
	  conf->cfg_config_u.cfg_net.net_peer_rtr_credits;
	tun.lt_cmn.lct_max_tx_credits =
	  (!conf->cfg_config_u.cfg_net.net_max_tx_credits) ? DEFAULT_CREDITS :
		conf->cfg_config_u.cfg_net.net_max_tx_credits;

	rc = lnet_add_net_common(net, &tun);

out_unlock_clean:
	mutex_unlock(&the_lnet.ln_api_mutex);
	/* net_head list is empty in success case */
	while ((net = list_first_entry_or_null(&net_head,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);
		lnet_net_free(net);
	}
	return rc;
}

int
lnet_dyn_del_net(u32 net_id)
{
	struct lnet_net *net;
	struct lnet_ping_buffer *pbuf;
	struct lnet_handle_md ping_mdh;
	int net_ni_bytes, rc;

	/* don't allow userspace to shutdown the LOLND */
	if (LNET_NETTYP(net_id) == LOLND)
		return -EINVAL;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto out;
	}

	lnet_net_lock(0);

	net = lnet_get_net_locked(net_id);
	if (net == NULL) {
		lnet_net_unlock(0);
		rc = -EINVAL;
		goto out;
	}

	net_ni_bytes = lnet_get_net_ni_bytes_locked(net);

	lnet_net_unlock(0);

	/* create and link a new ping info, before removing the old one */
	rc = lnet_ping_target_setup(&pbuf, &ping_mdh,
				    LNET_PING_INFO_HDR_SIZE +
				    lnet_get_ni_bytes() - net_ni_bytes,
				    false);
	if (rc != 0)
		goto out;

	lnet_shutdown_lndnet(net);

	lnet_acceptor_stop();

	lnet_ping_target_update(pbuf, ping_mdh);

out:
	mutex_unlock(&the_lnet.ln_api_mutex);

	return rc;
}

void lnet_mark_ping_buffer_for_update(void)
{
	if (the_lnet.ln_routing)
		return;

	atomic_set(&the_lnet.ln_update_ping_buf, 1);
	complete(&the_lnet.ln_mt_wait_complete);
}
EXPORT_SYMBOL(lnet_mark_ping_buffer_for_update);

static void lnet_update_ping_buffer(struct work_struct *work)
{
	struct lnet_ping_buffer *pbuf;
	struct lnet_handle_md ping_mdh;

	mutex_lock(&the_lnet.ln_api_mutex);

	atomic_set(&the_lnet.ln_pb_update_ready, 1);

	if ((the_lnet.ln_state == LNET_STATE_RUNNING) &&
	    !lnet_ping_target_setup(&pbuf, &ping_mdh,
				    LNET_PING_INFO_HDR_SIZE +
				    lnet_get_ni_bytes(),
				    false))
		lnet_ping_target_update(pbuf, ping_mdh);

	mutex_unlock(&the_lnet.ln_api_mutex);
}

void lnet_queue_ping_buffer_update(void)
{
	/* don't queue pb update if it is not needed */
	if (atomic_dec_if_positive(&the_lnet.ln_update_ping_buf) < 0)
		return;

	/* don't queue pb update if already queued and not processed */
	if (atomic_dec_if_positive(&the_lnet.ln_pb_update_ready) < 0)
		return;

	INIT_WORK(&the_lnet.ln_pb_update_work, lnet_update_ping_buffer);
	queue_work(the_lnet.ln_pb_update_wq, &the_lnet.ln_pb_update_work);
}

void lnet_incr_dlc_seq(void)
{
	atomic_inc(&lnet_dlc_seq_no);
}

__u32 lnet_get_dlc_seq_locked(void)
{
	return atomic_read(&lnet_dlc_seq_no);
}

static void
lnet_ni_set_healthv(struct lnet_nid *nid, int value)
{
	bool all = nid_same(nid, &LNET_ANY_NID);
	struct lnet_net *net;
	struct lnet_ni *ni;

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (!all && !nid_same(&ni->ni_nid, nid))
				continue;

			atomic_set(&ni->ni_healthv, value);
			if (list_empty(&ni->ni_recovery) &&
			    value < LNET_MAX_HEALTH_VALUE) {
				CERROR("manually adding local NI %s to recovery\n",
				       libcfs_nidstr(&ni->ni_nid));
				list_add_tail(&ni->ni_recovery,
					      &the_lnet.ln_mt_localNIRecovq);
				lnet_ni_addref_locked(ni, 0);
			}
			if (!all) {
				lnet_net_unlock(LNET_LOCK_EX);
				return;
			}
		}
	}
	lnet_net_unlock(LNET_LOCK_EX);
}

static void
lnet_ni_set_conns_per_peer(lnet_nid_t nid, int value, bool all)
{
	struct lnet_net *net;
	struct lnet_ni *ni;

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (lnet_nid_to_nid4(&ni->ni_nid) != nid && !all)
				continue;
			if (LNET_NETTYP(net->net_id) == SOCKLND)
				ni->ni_lnd_tunables.lnd_tun_u.lnd_sock.lnd_conns_per_peer = value;
			else if (LNET_NETTYP(net->net_id) == O2IBLND)
				ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib.lnd_conns_per_peer = value;
			if (!all) {
				lnet_net_unlock(LNET_LOCK_EX);
				return;
			}
		}
	}
	lnet_net_unlock(LNET_LOCK_EX);
}

static int
lnet_get_local_ni_hstats(struct lnet_ioctl_local_ni_hstats *stats)
{
	int cpt, rc = 0;
	struct lnet_ni *ni;
	struct lnet_nid nid;

	lnet_nid4_to_nid(stats->hlni_nid, &nid);
	cpt = lnet_net_lock_current();
	ni = lnet_nid_to_ni_locked(&nid, cpt);
	if (!ni) {
		rc = -ENOENT;
		goto unlock;
	}

	stats->hlni_local_interrupt = atomic_read(&ni->ni_hstats.hlt_local_interrupt);
	stats->hlni_local_dropped = atomic_read(&ni->ni_hstats.hlt_local_dropped);
	stats->hlni_local_aborted = atomic_read(&ni->ni_hstats.hlt_local_aborted);
	stats->hlni_local_no_route = atomic_read(&ni->ni_hstats.hlt_local_no_route);
	stats->hlni_local_timeout = atomic_read(&ni->ni_hstats.hlt_local_timeout);
	stats->hlni_local_error = atomic_read(&ni->ni_hstats.hlt_local_error);
	stats->hlni_fatal_error = atomic_read(&ni->ni_fatal_error_on);
	stats->hlni_health_value = atomic_read(&ni->ni_healthv);
	stats->hlni_ping_count = ni->ni_ping_count;
	stats->hlni_next_ping = ni->ni_next_ping;

unlock:
	lnet_net_unlock(cpt);

	return rc;
}

static int
lnet_get_local_ni_recovery_list(struct lnet_ioctl_recovery_list *list)
{
	struct lnet_ni *ni;
	int i = 0;

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(ni, &the_lnet.ln_mt_localNIRecovq, ni_recovery) {
		if (!nid_is_nid4(&ni->ni_nid))
			continue;
		list->rlst_nid_array[i] = lnet_nid_to_nid4(&ni->ni_nid);
		i++;
		if (i >= LNET_MAX_SHOW_NUM_NID)
			break;
	}
	lnet_net_unlock(LNET_LOCK_EX);
	list->rlst_num_nids = i;

	return 0;
}

static int
lnet_get_peer_ni_recovery_list(struct lnet_ioctl_recovery_list *list)
{
	struct lnet_peer_ni *lpni;
	int i = 0;

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(lpni, &the_lnet.ln_mt_peerNIRecovq, lpni_recovery) {
		list->rlst_nid_array[i] = lnet_nid_to_nid4(&lpni->lpni_nid);
		i++;
		if (i >= LNET_MAX_SHOW_NUM_NID)
			break;
	}
	lnet_net_unlock(LNET_LOCK_EX);
	list->rlst_num_nids = i;

	return 0;
}

/**
 * LNet ioctl handler.
 *
 */
int
LNetCtl(unsigned int cmd, void *arg)
{
	struct libcfs_ioctl_data *data = arg;
	struct lnet_ioctl_config_data *config;
	struct lnet_ni		 *ni;
	struct lnet_nid		  nid;
	int			  rc;

	BUILD_BUG_ON(sizeof(struct lnet_ioctl_net_config) +
		     sizeof(struct lnet_ioctl_config_data) > LIBCFS_IOC_DATA_MAX);

	switch (cmd) {
	case IOC_LIBCFS_GET_NI: {
		struct lnet_processid id = {};

		rc = LNetGetId(data->ioc_count, &id, false);
		data->ioc_nid = lnet_nid_to_nid4(&id.nid);
		return rc;
	}
	case IOC_LIBCFS_FAIL_NID:
		lnet_nid4_to_nid(data->ioc_nid, &nid);
		return lnet_fail_nid(&nid, data->ioc_count);

	case IOC_LIBCFS_ADD_ROUTE: {
		/* default router sensitivity to 1 */
		unsigned int sensitivity = 1;
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		if (config->cfg_config_u.cfg_route.rtr_sensitivity) {
			sensitivity =
			  config->cfg_config_u.cfg_route.rtr_sensitivity;
		}

		lnet_nid4_to_nid(config->cfg_nid, &nid);
		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_add_route(config->cfg_net,
				    config->cfg_config_u.cfg_route.rtr_hop,
				    &nid,
				    config->cfg_config_u.cfg_route.
					rtr_priority, sensitivity);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_DEL_ROUTE:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		lnet_nid4_to_nid(config->cfg_nid, &nid);
		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_del_route(config->cfg_net, &nid);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;

	case IOC_LIBCFS_GET_ROUTE:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_route(config->cfg_count,
				    &config->cfg_net,
				    &config->cfg_config_u.cfg_route.rtr_hop,
				    &config->cfg_nid,
				    &config->cfg_config_u.cfg_route.rtr_flags,
				    &config->cfg_config_u.cfg_route.
					rtr_priority,
				    &config->cfg_config_u.cfg_route.
					rtr_sensitivity);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;

	case IOC_LIBCFS_GET_LOCAL_NI: {
		struct lnet_ioctl_config_ni *cfg_ni;
		struct lnet_ioctl_config_lnd_tunables *tun = NULL;
		struct lnet_ioctl_element_stats *stats;
		__u32 tun_size;

		cfg_ni = arg;

		/* get the tunables if they are available */
		if (cfg_ni->lic_cfg_hdr.ioc_len <
		    sizeof(*cfg_ni) + sizeof(*stats) + sizeof(*tun))
			return -EINVAL;

		stats = (struct lnet_ioctl_element_stats *)
			cfg_ni->lic_bulk;
		tun = (struct lnet_ioctl_config_lnd_tunables *)
				(cfg_ni->lic_bulk + sizeof(*stats));

		tun_size = cfg_ni->lic_cfg_hdr.ioc_len - sizeof(*cfg_ni) -
			sizeof(*stats);

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_ni_config(cfg_ni, tun, stats, tun_size);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_LOCAL_NI_MSG_STATS: {
		struct lnet_ioctl_element_msg_stats *msg_stats = arg;
		int cpt;

		if (msg_stats->im_hdr.ioc_len != sizeof(*msg_stats))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);

		cpt = lnet_net_lock_current();
		rc = lnet_get_ni_stats(msg_stats);
		lnet_net_unlock(cpt);

		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_NET: {
		size_t total = sizeof(*config) +
			       sizeof(struct lnet_ioctl_net_config);
		config = arg;

		if (config->cfg_hdr.ioc_len < total)
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_net_config(config);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_LNET_STATS:
	{
		struct lnet_ioctl_lnet_stats *lnet_stats = arg;

		if (lnet_stats->st_hdr.ioc_len < sizeof(*lnet_stats))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_counters_get(&lnet_stats->st_cntrs);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_RESET_LNET_STATS:
	{
		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_counters_reset();
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	case IOC_LIBCFS_CONFIG_RTR:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		if (config->cfg_config_u.cfg_buffers.buf_enable) {
			rc = lnet_rtrpools_enable();
			mutex_unlock(&the_lnet.ln_api_mutex);
			return rc;
		}
		lnet_rtrpools_disable();
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;

	case IOC_LIBCFS_ADD_BUF:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_rtrpools_adjust(config->cfg_config_u.cfg_buffers.
						buf_tiny,
					  config->cfg_config_u.cfg_buffers.
						buf_small,
					  config->cfg_config_u.cfg_buffers.
						buf_large);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;

	case IOC_LIBCFS_SET_NUMA_RANGE: {
		struct lnet_ioctl_set_value *numa;
		numa = arg;
		if (numa->sv_hdr.ioc_len != sizeof(*numa))
			return -EINVAL;
		lnet_net_lock(LNET_LOCK_EX);
		lnet_numa_range = numa->sv_value;
		lnet_net_unlock(LNET_LOCK_EX);
		return 0;
	}

	case IOC_LIBCFS_GET_NUMA_RANGE: {
		struct lnet_ioctl_set_value *numa;
		numa = arg;
		if (numa->sv_hdr.ioc_len != sizeof(*numa))
			return -EINVAL;
		numa->sv_value = lnet_numa_range;
		return 0;
	}

	case IOC_LIBCFS_GET_BUF: {
		struct lnet_ioctl_pool_cfg *pool_cfg;
		size_t total = sizeof(*config) + sizeof(*pool_cfg);

		config = arg;

		if (config->cfg_hdr.ioc_len < total)
			return -EINVAL;

		pool_cfg = (struct lnet_ioctl_pool_cfg *)config->cfg_bulk;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_rtr_pool_cfg(config->cfg_count, pool_cfg);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_LOCAL_HSTATS: {
		struct lnet_ioctl_local_ni_hstats *stats = arg;

		if (stats->hlni_hdr.ioc_len < sizeof(*stats))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_local_ni_hstats(stats);
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_RECOVERY_QUEUE: {
		struct lnet_ioctl_recovery_list *list = arg;
		if (list->rlst_hdr.ioc_len < sizeof(*list))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		if (list->rlst_type == LNET_HEALTH_TYPE_LOCAL_NI)
			rc = lnet_get_local_ni_recovery_list(list);
		else
			rc = lnet_get_peer_ni_recovery_list(list);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_ADD_PEER_NI: {
		struct lnet_ioctl_peer_cfg *cfg = arg;
		struct lnet_nid prim_nid;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_nid4_to_nid(cfg->prcfg_prim_nid, &prim_nid);
		lnet_nid4_to_nid(cfg->prcfg_cfg_nid, &nid);
		rc = lnet_user_add_peer_ni(&prim_nid, &nid, cfg->prcfg_mr,
					   cfg->prcfg_count == 1);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_DEL_PEER_NI: {
		struct lnet_ioctl_peer_cfg *cfg = arg;
		struct lnet_nid prim_nid;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_nid4_to_nid(cfg->prcfg_prim_nid, &prim_nid);
		lnet_nid4_to_nid(cfg->prcfg_cfg_nid, &nid);
		rc = lnet_del_peer_ni(&prim_nid,
				      &nid,
				      cfg->prcfg_count);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_PEER_INFO: {
		struct lnet_ioctl_peer *peer_info = arg;

		if (peer_info->pr_hdr.ioc_len < sizeof(*peer_info))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_peer_ni_info(
		   peer_info->pr_count,
		   &peer_info->pr_nid,
		   peer_info->pr_lnd_u.pr_peer_credits.cr_aliveness,
		   &peer_info->pr_lnd_u.pr_peer_credits.cr_ncpt,
		   &peer_info->pr_lnd_u.pr_peer_credits.cr_refcount,
		   &peer_info->pr_lnd_u.pr_peer_credits.cr_ni_peer_tx_credits,
		   &peer_info->pr_lnd_u.pr_peer_credits.cr_peer_tx_credits,
		   &peer_info->pr_lnd_u.pr_peer_credits.cr_peer_rtr_credits,
		   &peer_info->pr_lnd_u.pr_peer_credits.cr_peer_min_tx_credits,
		   &peer_info->pr_lnd_u.pr_peer_credits.cr_peer_tx_qnob);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_PEER_NI: {
		struct lnet_ioctl_peer_cfg *cfg = arg;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_peer_info(cfg,
					(void __user *)cfg->prcfg_bulk);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_PEER_LIST: {
		struct lnet_ioctl_peer_cfg *cfg = arg;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_peer_list(&cfg->prcfg_count, &cfg->prcfg_size,
				(struct lnet_process_id __user *)cfg->prcfg_bulk);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_SET_HEALHV: {
		struct lnet_ioctl_reset_health_cfg *cfg = arg;
		int value;

		if (cfg->rh_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;
		if (cfg->rh_value < 0 ||
		    cfg->rh_value > LNET_MAX_HEALTH_VALUE)
			value = LNET_MAX_HEALTH_VALUE;
		else
			value = cfg->rh_value;
		CDEBUG(D_NET, "Manually setting healthv to %d for %s:%s. all = %d\n",
		       value, (cfg->rh_type == LNET_HEALTH_TYPE_LOCAL_NI) ?
		       "local" : "peer", libcfs_nid2str(cfg->rh_nid), cfg->rh_all);
		lnet_nid4_to_nid(cfg->rh_nid, &nid);
		mutex_lock(&the_lnet.ln_api_mutex);
		if (cfg->rh_type == LNET_HEALTH_TYPE_LOCAL_NI) {
			if (cfg->rh_all)
				nid = LNET_ANY_NID;
			lnet_ni_set_healthv(&nid, value);
		} else {
			lnet_peer_ni_set_healthv(&nid, value, cfg->rh_all);
		}
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	case IOC_LIBCFS_SET_PEER: {
		struct lnet_ioctl_peer_cfg *cfg = arg;
		struct lnet_peer *lp;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_nid4_to_nid(cfg->prcfg_prim_nid, &nid);
		lp = lnet_find_peer(&nid);
		if (!lp) {
			mutex_unlock(&the_lnet.ln_api_mutex);
			return -ENOENT;
		}
		spin_lock(&lp->lp_lock);
		lp->lp_state = cfg->prcfg_state;
		spin_unlock(&lp->lp_lock);
		lnet_peer_decref_locked(lp);
		mutex_unlock(&the_lnet.ln_api_mutex);
		CDEBUG(D_NET, "Set peer %s state to %u\n",
		       libcfs_nid2str(cfg->prcfg_prim_nid), cfg->prcfg_state);
		return 0;
	}

	case IOC_LIBCFS_SET_CONNS_PER_PEER: {
		struct lnet_ioctl_reset_conns_per_peer_cfg *cfg = arg;
		int value;

		if (cfg->rcpp_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;
		if (cfg->rcpp_value < 0)
			value = 1;
		else
			value = cfg->rcpp_value;
		CDEBUG(D_NET,
		       "Setting conns_per_peer to %d for %s. all = %d\n",
		       value, libcfs_nid2str(cfg->rcpp_nid), cfg->rcpp_all);
		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_ni_set_conns_per_peer(cfg->rcpp_nid, value, cfg->rcpp_all);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	case IOC_LIBCFS_NOTIFY_ROUTER: {
		/* Convert the user-supplied real time to monotonic.
		 * NB: "when" is always in the past
		 */
		time64_t when = ktime_get_seconds() -
				(ktime_get_real_seconds() - data->ioc_u64[0]);

		lnet_nid4_to_nid(data->ioc_nid, &nid);
		return lnet_notify(NULL, &nid, data->ioc_flags, false, when);
	}

	case IOC_LIBCFS_LNET_DIST:
		lnet_nid4_to_nid(data->ioc_nid, &nid);
		rc = LNetDist(&nid, &nid, &data->ioc_u32[1]);
		if (rc < 0 && rc != -EHOSTUNREACH)
			return rc;

		data->ioc_nid = lnet_nid_to_nid4(&nid);
		data->ioc_u32[0] = rc;
		return 0;

	case IOC_LIBCFS_TESTPROTOCOMPAT:
		the_lnet.ln_testprotocompat = data->ioc_flags;
		return 0;

	case IOC_LIBCFS_LNET_FAULT:
		return lnet_fault_ctl(data->ioc_flags, data);

	case IOC_LIBCFS_PING_PEER: {
		struct lnet_ioctl_ping_data *ping = arg;
		struct lnet_process_id __user *ids = ping->ping_buf;
		struct lnet_nid src_nid = LNET_ANY_NID;
		struct lnet_genl_ping_list plist;
		struct lnet_processid id;
		struct lnet_peer *lp;
		signed long timeout;
		int count, i;

		/* Check if the supplied ping data supports source nid
		 * NB: This check is sufficient if lnet_ioctl_ping_data has
		 * additional fields added, but if they are re-ordered or
		 * fields removed then this will break. It is expected that
		 * these ioctls will be replaced with netlink implementation, so
		 * it is probably not worth coming up with a more robust version
		 * compatibility scheme.
		 */
		if (ping->ping_hdr.ioc_len >= sizeof(struct lnet_ioctl_ping_data))
			lnet_nid4_to_nid(ping->ping_src, &src_nid);

		/* If timeout is negative then set default of 3 minutes */
		if (((s32)ping->op_param) <= 0 ||
		    ping->op_param > (DEFAULT_PEER_TIMEOUT * MSEC_PER_SEC))
			timeout = cfs_time_seconds(DEFAULT_PEER_TIMEOUT);
		else
			timeout = nsecs_to_jiffies(ping->op_param * NSEC_PER_MSEC);

		id.pid = ping->ping_id.pid;
		lnet_nid4_to_nid(ping->ping_id.nid, &id.nid);
		rc = lnet_ping(&id, &src_nid, timeout, &plist,
			       ping->ping_count);
		if (rc < 0)
			goto report_ping_err;
		count = rc;
		rc = 0;

		for (i = 0; i < count; i++) {
			struct lnet_processid *result;
			struct lnet_process_id tmpid;

			result = genradix_ptr(&plist.lgpl_list, i);
			memset(&tmpid, 0, sizeof(tmpid));
			tmpid.pid = result->pid;
			tmpid.nid = lnet_nid_to_nid4(&result->nid);
			if (copy_to_user(&ids[i], &tmpid, sizeof(tmpid))) {
				rc = -EFAULT;
				goto report_ping_err;
			}
		}

		mutex_lock(&the_lnet.ln_api_mutex);
		lp = lnet_find_peer(&id.nid);
		if (lp) {
			ping->ping_id.nid =
				lnet_nid_to_nid4(&lp->lp_primary_nid);
			ping->mr_info = lnet_peer_is_multi_rail(lp);
			lnet_peer_decref_locked(lp);
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		ping->ping_count = count;
report_ping_err:
		genradix_free(&plist.lgpl_list);
		return rc;
	}

	case IOC_LIBCFS_DISCOVER: {
		struct lnet_ioctl_ping_data *discover = arg;
		struct lnet_process_id __user *ids;
		struct lnet_genl_ping_list dlists;
		struct lnet_processid id;
		struct lnet_peer *lp;
		int count, i;

		if (discover->ping_count <= 0)
			return -EINVAL;

		genradix_init(&dlists.lgpl_list);
		/* If the user buffer has more space than the lnet_interfaces_max,
		 * then only fill it up to lnet_interfaces_max.
		 */
		if (discover->ping_count > lnet_interfaces_max)
			discover->ping_count = lnet_interfaces_max;

		id.pid = discover->ping_id.pid;
		lnet_nid4_to_nid(discover->ping_id.nid, &id.nid);
		rc = lnet_discover(&id, discover->op_param, &dlists);
		if (rc < 0)
			goto report_discover_err;
		count = rc;

		ids = discover->ping_buf;
		for (i = 0; i < count; i++) {
			struct lnet_processid *result;
			struct lnet_process_id tmpid;

			result = genradix_ptr(&dlists.lgpl_list, i);
			memset(&tmpid, 0, sizeof(tmpid));
			tmpid.pid = result->pid;
			tmpid.nid = lnet_nid_to_nid4(&result->nid);
			if (copy_to_user(&ids[i], &tmpid, sizeof(tmpid))) {
				rc = -EFAULT;
				goto report_discover_err;
			}

			if (i >= discover->ping_count)
				break;
		}
		rc = 0;

		mutex_lock(&the_lnet.ln_api_mutex);
		lp = lnet_find_peer(&id.nid);
		if (lp) {
			discover->ping_id.nid =
				lnet_nid_to_nid4(&lp->lp_primary_nid);
			discover->mr_info = lnet_peer_is_multi_rail(lp);
			lnet_peer_decref_locked(lp);
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		discover->ping_count = count;
report_discover_err:
		genradix_free(&dlists.lgpl_list);
		return rc;
	}

	case IOC_LIBCFS_ADD_UDSP: {
		struct lnet_ioctl_udsp *ioc_udsp = arg;
		__u32 bulk_size = ioc_udsp->iou_hdr.ioc_len;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_udsp_demarshal_add(arg, bulk_size);
		if (!rc) {
			rc = lnet_udsp_apply_policies(NULL, false);
			CDEBUG(D_NET, "policy application returned %d\n", rc);
			rc = 0;
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_DEL_UDSP: {
		struct lnet_ioctl_udsp *ioc_udsp = arg;
		int idx = ioc_udsp->iou_idx;

		if (ioc_udsp->iou_hdr.ioc_len < sizeof(*ioc_udsp))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_udsp_del_policy(idx);
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_UDSP_SIZE: {
		struct lnet_ioctl_udsp *ioc_udsp = arg;
		struct lnet_udsp *udsp;

		if (ioc_udsp->iou_hdr.ioc_len < sizeof(*ioc_udsp))
			return -EINVAL;

		rc = 0;

		mutex_lock(&the_lnet.ln_api_mutex);
		udsp = lnet_udsp_get_policy(ioc_udsp->iou_idx);
		if (!udsp) {
			rc = -ENOENT;
		} else {
			/* coming in iou_idx will hold the idx of the udsp
			 * to get the size of. going out the iou_idx will
			 * hold the size of the UDSP found at the passed
			 * in index.
			 */
			ioc_udsp->iou_idx = lnet_get_udsp_size(udsp);
			if (ioc_udsp->iou_idx < 0)
				rc = -EINVAL;
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_UDSP: {
		struct lnet_ioctl_udsp *ioc_udsp = arg;
		struct lnet_udsp *udsp;

		if (ioc_udsp->iou_hdr.ioc_len < sizeof(*ioc_udsp))
			return -EINVAL;

		rc = 0;

		mutex_lock(&the_lnet.ln_api_mutex);
		udsp = lnet_udsp_get_policy(ioc_udsp->iou_idx);
		if (!udsp)
			rc = -ENOENT;
		else
			rc = lnet_udsp_marshal(udsp, ioc_udsp);
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_CONST_UDSP_INFO: {
		struct lnet_ioctl_construct_udsp_info *info = arg;

		if (info->cud_hdr.ioc_len < sizeof(*info))
			return -EINVAL;

		CDEBUG(D_NET, "GET_UDSP_INFO for %s\n",
		       libcfs_nid2str(info->cud_nid));

		lnet_nid4_to_nid(info->cud_nid, &nid);
		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_net_lock(0);
		lnet_udsp_get_construct_info(info, &nid);
		lnet_net_unlock(0);
		mutex_unlock(&the_lnet.ln_api_mutex);

		return 0;
	}

	default:
		ni = lnet_net2ni_addref(data->ioc_net);
		if (ni == NULL)
			return -EINVAL;

		if (ni->ni_net->net_lnd->lnd_ctl == NULL)
			rc = -EINVAL;
		else
			rc = ni->ni_net->net_lnd->lnd_ctl(ni, cmd, arg);

		lnet_ni_decref(ni);
		return rc <= 0 ? rc : 0;
	}
	/* not reached */
}
EXPORT_SYMBOL(LNetCtl);

static int lnet_net_conf_cmd(struct sk_buff *skb, struct genl_info *info)
{
	int rc = 0;

	if (info->nlhdr->nlmsg_flags & NLM_F_CREATE) {
		/* NLM_F_EXCL means ignore module parameters */
		if (info->nlhdr->nlmsg_flags & NLM_F_EXCL)
			the_lnet.ln_nis_from_mod_params = true;

		if (info->nlhdr->nlmsg_flags & NLM_F_APPEND)
			the_lnet.ln_nis_use_large_nids = true;

		rc = lnet_configure(NULL);
		switch (rc) {
		case -ENETDOWN:
			GENL_SET_ERR_MSG(info,
					 "Network is down");
			break;
		case -ENODEV:
			GENL_SET_ERR_MSG(info,
					 "LNET is currently not loaded");
			break;
		case -EBUSY:
			GENL_SET_ERR_MSG(info, "LNET busy");
			break;
		default:
			break;
		}
	} else {
		rc = lnet_unconfigure();
	}

	return rc;
};

struct lnet_nid_cpt {
	struct lnet_nid lnc_nid;
	unsigned int lnc_cpt;
};

struct lnet_genl_nid_cpt_list {
	unsigned int lgncl_index;
	unsigned int lgncl_list_count;
	GENRADIX(struct lnet_nid_cpt) lgncl_lnc_list;
};

static inline struct lnet_genl_nid_cpt_list *
lnet_cpt_of_nid_dump_ctx(struct netlink_callback *cb)
{
	return (struct lnet_genl_nid_cpt_list *)cb->args[0];
}

static int lnet_cpt_of_nid_show_done(struct netlink_callback *cb)
{
	struct lnet_genl_nid_cpt_list *lgncl;

	lgncl = lnet_cpt_of_nid_dump_ctx(cb);

	if (lgncl) {
		genradix_free(&lgncl->lgncl_lnc_list);
		LIBCFS_FREE(lgncl, sizeof(*lgncl));
		cb->args[0] = 0;
	}

	return 0;
}

static int lnet_cpt_of_nid_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	struct lnet_genl_nid_cpt_list *lgncl;
	int msg_len = genlmsg_len(gnlh);
	struct nlattr *params, *top;
	int rem, rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		NL_SET_ERR_MSG(extack, "Network is down");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENETDOWN;
	}

	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		NL_SET_ERR_MSG(extack, "Missing NID argument(s)");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENOENT;
	}

	LIBCFS_ALLOC(lgncl, sizeof(*lgncl));
	if (!lgncl) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENOMEM;
	}

	genradix_init(&lgncl->lgncl_lnc_list);
	lgncl->lgncl_list_count = 0;
	cb->args[0] = (long)lgncl;

	params = genlmsg_data(gnlh);
	nla_for_each_attr(top, params, msg_len, rem) {
		struct nlattr *nids;
		int rem2;

		switch (nla_type(top)) {
		case LN_SCALAR_ATTR_LIST:
			nla_for_each_nested(nids, top, rem2) {
				char nidstr[LNET_NIDSTR_SIZE + 1];
				struct lnet_nid_cpt *lnc;

				if (nla_type(nids) != LN_SCALAR_ATTR_VALUE)
					continue;

				memset(nidstr, 0, sizeof(nidstr));
				rc = nla_strscpy(nidstr, nids, sizeof(nidstr));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "failed to get NID");
					GOTO(report_err, rc);
				}

				lnc = genradix_ptr_alloc(&lgncl->lgncl_lnc_list,
						      lgncl->lgncl_list_count++,
						      GFP_KERNEL);
				if (!lnc) {
					NL_SET_ERR_MSG(extack,
						      "failed to allocate NID");
					GOTO(report_err, rc = -ENOMEM);
				}

				rc = libcfs_strnid(&lnc->lnc_nid,
						   strim(nidstr));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack, "invalid NID");
					GOTO(report_err, rc);
				}
				rc = 0;
				CDEBUG(D_NET, "nid: %s\n",
				       libcfs_nidstr(&lnc->lnc_nid));
			}
			fallthrough;
		default:
			break;
		}
	}
report_err:
	mutex_unlock(&the_lnet.ln_api_mutex);

	if (rc < 0)
		lnet_cpt_of_nid_show_done(cb);

	return rc;
}

static const struct ln_key_list cpt_of_nid_props_list = {
	.lkl_maxattr			= LNET_CPT_OF_NID_ATTR_MAX,
	.lkl_list			= {
		[LNET_CPT_OF_NID_ATTR_HDR]	= {
			.lkp_value		= "cpt-of-nid",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_CPT_OF_NID_ATTR_NID]	= {
			.lkp_value		= "nid",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_CPT_OF_NID_ATTR_CPT]	= {
			.lkp_value		= "cpt",
			.lkp_data_type		= NLA_U32,
		},
	},
};

static int lnet_cpt_of_nid_show_dump(struct sk_buff *msg,
				     struct netlink_callback *cb)
{
	struct lnet_genl_nid_cpt_list *lgncl;
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx;
	int rc = 0;
	bool need_hdr = true;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		NL_SET_ERR_MSG(extack, "Network is down");
		GOTO(send_error, rc = -ENETDOWN);
	}

	lgncl = lnet_cpt_of_nid_dump_ctx(cb);
	idx = lgncl->lgncl_index;

	if (!lgncl->lgncl_index) {
		const struct ln_key_list *all[] = {
			&cpt_of_nid_props_list, NULL, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq, &lnet_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_CMD_CPT_OF_NID, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_error, rc);
		}
	}

	while (idx < lgncl->lgncl_list_count) {
		struct lnet_nid_cpt *lnc;
		void *hdr;
		int cpt;

		lnc = genradix_ptr(&lgncl->lgncl_lnc_list, idx++);

		cpt = lnet_nid_cpt_hash(&lnc->lnc_nid, LNET_CPT_NUMBER);

		CDEBUG(D_NET, "nid: %s cpt: %d\n", libcfs_nidstr(&lnc->lnc_nid), cpt);
		hdr = genlmsg_put(msg, portid, seq, &lnet_family,
				  NLM_F_MULTI, LNET_CMD_CPT_OF_NID);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			genlmsg_cancel(msg, hdr);
			GOTO(send_error, rc = -EMSGSIZE);
		}

		if (need_hdr) {
			nla_put_string(msg, LNET_CPT_OF_NID_ATTR_HDR, "");
			need_hdr = false;
		}

		nla_put_string(msg, LNET_CPT_OF_NID_ATTR_NID,
			       libcfs_nidstr(&lnc->lnc_nid));
		nla_put_u32(msg, LNET_CPT_OF_NID_ATTR_CPT, cpt);

		genlmsg_end(msg, hdr);
	}

	genradix_free(&lgncl->lgncl_lnc_list);
	rc = 0;
	lgncl->lgncl_index = idx;

send_error:
	mutex_unlock(&the_lnet.ln_api_mutex);

	return lnet_nl_send_error(cb->skb, portid, seq, rc);
}

#ifndef HAVE_NETLINK_CALLBACK_START
static int lnet_old_cpt_of_nid_show_dump(struct sk_buff *msg,
					 struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lnet_cpt_of_nid_show_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lnet_cpt_of_nid_show_dump(msg, cb);
}
#endif

/* This is the keys for the UDSP info which is used by many
 * Netlink commands.
 */
static const struct ln_key_list udsp_info_list = {
	.lkl_maxattr			= LNET_UDSP_INFO_ATTR_MAX,
	.lkl_list			= {
		[LNET_UDSP_INFO_ATTR_NET_PRIORITY]		= {
			.lkp_value	= "net priority",
			.lkp_data_type	= NLA_S32
		},
		[LNET_UDSP_INFO_ATTR_NID_PRIORITY]		= {
			.lkp_value	= "nid priority",
			.lkp_data_type	= NLA_S32
		},
		[LNET_UDSP_INFO_ATTR_PREF_RTR_NIDS_LIST]	= {
			.lkp_value	= "Preferred gateway NIDs",
			.lkp_key_format	= LNKF_MAPPING,
			.lkp_data_type	= NLA_NESTED,
		},
		[LNET_UDSP_INFO_ATTR_PREF_NIDS_LIST]		= {
			.lkp_value	= "Preferred source NIDs",
			.lkp_key_format	= LNKF_MAPPING,
			.lkp_data_type	= NLA_NESTED,
		},
	},
};

static const struct ln_key_list udsp_info_pref_nids_list = {
	.lkl_maxattr			= LNET_UDSP_INFO_PREF_NIDS_ATTR_MAX,
	.lkl_list			= {
		[LNET_UDSP_INFO_PREF_NIDS_ATTR_INDEX]		= {
			.lkp_value	= "NID-0",
			.lkp_data_type	= NLA_NUL_STRING,
		},
		[LNET_UDSP_INFO_PREF_NIDS_ATTR_NID]		= {
			.lkp_value	= "0@lo",
			.lkp_data_type  = NLA_STRING,
		},
	},
};

static int lnet_udsp_info_send(struct sk_buff *msg, int attr,
			       struct lnet_nid *nid, bool remote)
{
	struct lnet_ioctl_construct_udsp_info *udsp;
	struct nlattr *udsp_attr, *udsp_info;
	struct nlattr *udsp_list_attr;
	struct nlattr *udsp_list_info;
	int i;

	CFS_ALLOC_PTR(udsp);
	if (!udsp)
		return -ENOMEM;

	udsp->cud_peer = remote;
	lnet_udsp_get_construct_info(udsp, nid);

	udsp_info = nla_nest_start(msg, attr);
	udsp_attr = nla_nest_start(msg, 0);
	nla_put_s32(msg, LNET_UDSP_INFO_ATTR_NET_PRIORITY,
		    udsp->cud_net_priority);
	nla_put_s32(msg, LNET_UDSP_INFO_ATTR_NID_PRIORITY,
		    udsp->cud_nid_priority);

	if (udsp->cud_pref_rtr_nid[0] == 0)
		goto skip_list;

	udsp_list_info = nla_nest_start(msg,
					LNET_UDSP_INFO_ATTR_PREF_RTR_NIDS_LIST);
	for (i = 0; i < LNET_MAX_SHOW_NUM_NID; i++) {
		char tmp[8]; /* NID-"3 number"\0 */

		if (udsp->cud_pref_rtr_nid[i] == 0)
			break;

		udsp_list_attr = nla_nest_start(msg, i);
		snprintf(tmp, sizeof(tmp), "NID-%d", i);
		nla_put_string(msg, LNET_UDSP_INFO_PREF_NIDS_ATTR_INDEX,
			       tmp);
		nla_put_string(msg, LNET_UDSP_INFO_PREF_NIDS_ATTR_NID,
			       libcfs_nid2str(udsp->cud_pref_rtr_nid[i]));
		nla_nest_end(msg, udsp_list_attr);
	}
	nla_nest_end(msg, udsp_list_info);
skip_list:
	nla_nest_end(msg, udsp_attr);
	nla_nest_end(msg, udsp_info);
	LIBCFS_FREE(udsp, sizeof(*udsp));

	return 0;
}

/* LNet NI handling */
static const struct ln_key_list net_props_list = {
	.lkl_maxattr			= LNET_NET_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_ATTR_HDR]		= {
			.lkp_value		= "net",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_NET_ATTR_TYPE]		= {
			.lkp_value		= "net type",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_NET_ATTR_LOCAL]           = {
			.lkp_value		= "local NI(s)",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
	},
};

static struct ln_key_list local_ni_list = {
	.lkl_maxattr			= LNET_NET_LOCAL_NI_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_LOCAL_NI_ATTR_NID]		= {
			.lkp_value		= "nid",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_NET_LOCAL_NI_ATTR_STATUS]		= {
			.lkp_value		= "status",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_NET_LOCAL_NI_ATTR_INTERFACE]	= {
			.lkp_value		= "interfaces",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
		[LNET_NET_LOCAL_NI_ATTR_STATS]		= {
			.lkp_value		= "statistics",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
		[LNET_NET_LOCAL_NI_ATTR_UDSP_INFO]	= {
			.lkp_value		= "udsp info",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
		[LNET_NET_LOCAL_NI_ATTR_SEND_STATS]	= {
			.lkp_value		= "sent_stats",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
		[LNET_NET_LOCAL_NI_ATTR_RECV_STATS]	= {
			.lkp_value		= "received_stats",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
		[LNET_NET_LOCAL_NI_ATTR_DROPPED_STATS]	= {
			.lkp_value		= "dropped_stats",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED

		},
		[LNET_NET_LOCAL_NI_ATTR_HEALTH_STATS]	= {
			.lkp_value		= "health stats",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
		[LNET_NET_LOCAL_NI_ATTR_TUNABLES]	= {
			.lkp_value		= "tunables",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
		[LNET_NET_LOCAL_NI_ATTR_LND_TUNABLES]	= {
			.lkp_value		= "lnd tunables",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
		[LNET_NET_LOCAL_NI_DEV_CPT]		= {
			.lkp_value		= "dev cpt",
			.lkp_data_type		= NLA_S32,
		},
		[LNET_NET_LOCAL_NI_CPTS]		= {
			.lkp_value		= "CPT",
			.lkp_data_type		= NLA_STRING,
		},
	},
};

static const struct ln_key_list local_ni_interfaces_list = {
	.lkl_maxattr			= LNET_NET_LOCAL_NI_INTF_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_LOCAL_NI_INTF_ATTR_TYPE] = {
			.lkp_value	= "0",
			.lkp_data_type	= NLA_STRING
		},
	},
};

static const struct ln_key_list local_ni_stats_list = {
	.lkl_maxattr			= LNET_NET_LOCAL_NI_STATS_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_LOCAL_NI_STATS_ATTR_SEND_COUNT]	= {
			.lkp_value	= "send_count",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_STATS_ATTR_RECV_COUNT]	= {
			.lkp_value	= "recv_count",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_STATS_ATTR_DROP_COUNT]	= {
			.lkp_value	= "drop_count",
			.lkp_data_type	= NLA_U32
		},
	},
};

static const struct ln_key_list local_ni_msg_stats_list = {
	.lkl_maxattr			= LNET_NET_LOCAL_NI_MSG_STATS_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_LOCAL_NI_MSG_STATS_ATTR_PUT_COUNT]	= {
			.lkp_value	= "put",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_MSG_STATS_ATTR_GET_COUNT]	= {
			.lkp_value	= "get",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_MSG_STATS_ATTR_REPLY_COUNT]	= {
			.lkp_value	= "reply",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_MSG_STATS_ATTR_ACK_COUNT]	= {
			.lkp_value	= "ack",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_MSG_STATS_ATTR_HELLO_COUNT]	= {
			.lkp_value	= "hello",
			.lkp_data_type	= NLA_U32
		},
	},
};

static const struct ln_key_list local_ni_health_stats_list = {
	.lkl_maxattr			= LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_FATAL_ERRORS] = {
			.lkp_value	= "fatal_error",
			.lkp_data_type	= NLA_S32
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_LEVEL] = {
			.lkp_value	= "health value",
			.lkp_data_type	= NLA_S32
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_INTERRUPTS] = {
			.lkp_value	= "interrupts",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_DROPPED] = {
			.lkp_value	= "dropped",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_ABORTED] = {
			.lkp_value	= "aborted",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_NO_ROUTE] = {
			.lkp_value	= "no route",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_TIMEOUTS] = {
			.lkp_value	= "timeouts",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_ERROR] = {
			.lkp_value	= "error",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_PING_COUNT] = {
			.lkp_value	= "ping_count",
			.lkp_data_type	= NLA_U32,
		},
		[LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_NEXT_PING] = {
			.lkp_value	= "next_ping",
			.lkp_data_type	= NLA_U64
		},
	},
};

static const struct ln_key_list local_ni_tunables_list = {
	.lkl_maxattr			= LNET_NET_LOCAL_NI_TUNABLES_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_TIMEOUT]	= {
			.lkp_value	= "peer_timeout",
			.lkp_data_type	= NLA_S32
		},
		[LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_CREDITS]	= {
			.lkp_value	= "peer_credits",
			.lkp_data_type	= NLA_S32
		},
		[LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_BUFFER_CREDITS] = {
			.lkp_value	= "peer_buffer_credits",
			.lkp_data_type	= NLA_S32
		},
		[LNET_NET_LOCAL_NI_TUNABLES_ATTR_CREDITS] = {
			.lkp_value	= "credits",
			.lkp_data_type	= NLA_S32
		},
	},
};

/* Use an index since the traversal is across LNet nets and ni collections */
struct lnet_genl_net_list {
	unsigned int	lngl_net_id;
	unsigned int	lngl_idx;
};

static inline struct lnet_genl_net_list *
lnet_net_dump_ctx(struct netlink_callback *cb)
{
	return (struct lnet_genl_net_list *)cb->args[0];
}

static int lnet_net_show_done(struct netlink_callback *cb)
{
	struct lnet_genl_net_list *nlist = lnet_net_dump_ctx(cb);

	if (nlist) {
		LIBCFS_FREE(nlist, sizeof(*nlist));
		cb->args[0] = 0;
	}

	return 0;
}

/* LNet net ->start() handler for GET requests */
static int lnet_net_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	struct lnet_genl_net_list *nlist;
	int msg_len = genlmsg_len(gnlh);
	struct nlattr *params, *top;
	int rem, rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (the_lnet.ln_refcount == 0) {
		NL_SET_ERR_MSG(extack, "LNet stack down");
		return -ENETDOWN;
	}

	LIBCFS_ALLOC(nlist, sizeof(*nlist));
	if (!nlist)
		return -ENOMEM;

	nlist->lngl_net_id = LNET_NET_ANY;
	nlist->lngl_idx = 0;
	cb->args[0] = (long)nlist;

	cb->min_dump_alloc = U16_MAX;
	if (!msg_len)
		return 0;

	params = genlmsg_data(gnlh);
	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		NL_SET_ERR_MSG(extack, "invalid configuration");
		return -EINVAL;
	}

	nla_for_each_nested(top, params, rem) {
		struct nlattr *net;
		int rem2;

		nla_for_each_nested(net, top, rem2) {
			char filter[LNET_NIDSTR_SIZE];

			if (nla_type(net) != LN_SCALAR_ATTR_VALUE ||
			    nla_strcmp(net, "net type") != 0)
				continue;

			net = nla_next(net, &rem2);
			if (nla_type(net) != LN_SCALAR_ATTR_VALUE) {
				NL_SET_ERR_MSG(extack, "invalid config param");
				GOTO(report_err, rc = -EINVAL);
			}

			rc = nla_strscpy(filter, net, sizeof(filter));
			if (rc < 0) {
				NL_SET_ERR_MSG(extack, "failed to get param");
				GOTO(report_err, rc);
			}
			rc = 0;

			nlist->lngl_net_id = libcfs_str2net(filter);
			if (nlist->lngl_net_id == LNET_NET_ANY) {
				NL_SET_ERR_MSG(extack, "cannot parse net");
				GOTO(report_err, rc = -ENOENT);
			}
		}
	}
report_err:
	if (rc < 0)
		lnet_net_show_done(cb);

	return rc;
}

static const struct ln_key_list net_update_props_list = {
	.lkl_maxattr			= LNET_NET_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_ATTR_HDR]		= {
			.lkp_value		= "",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_NET_ATTR_TYPE]		= {
			.lkp_value		= "net type",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_NET_ATTR_LOCAL]           = {
			.lkp_value		= "local NI(s)",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
	},
};

static int lnet_net_show_dump(struct sk_buff *msg,
			      struct netlink_callback *cb)
{
	struct lnet_genl_net_list *nlist = lnet_net_dump_ctx(cb);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
	int portid = NETLINK_CB(cb->skb).portid;
	bool found = false, started = false;
	const struct lnet_lnd *lnd = NULL;
	int idx = nlist->lngl_idx, rc = 0;
	int seq = cb->nlh->nlmsg_seq;
	struct lnet_net *net;
	void *hdr = NULL;
	bool export_backup = cb->nlh->nlmsg_flags & NLM_F_DUMP_FILTERED;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	lnet_net_lock(LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		struct nlattr *local_ni, *ni_attr;
		bool send_lnd_keys = false;
		struct lnet_ni *ni;
		int dev = 0;

		if (nlist->lngl_net_id != LNET_NET_ANY &&
		    nlist->lngl_net_id != net->net_id)
			continue;

		if (export_backup && LNET_NETTYP(net->net_id) == LOLND)
			continue;

		if (gnlh->version && LNET_NETTYP(net->net_id) != LOLND) {
			if (!net->net_lnd) {
				NL_SET_ERR_MSG(extack,
					       "LND not setup for NI");
				GOTO(net_unlock, rc = -ENODEV);
			}
			if (net->net_lnd != lnd) {
				send_lnd_keys = true;
				lnd = net->net_lnd;
			}
		}

		/* We need to resend the key table every time the base LND
		 * changed.
		 */
		if (!idx || send_lnd_keys) {
			const struct ln_key_list *all[] = {
				&net_props_list, &local_ni_list,
				&local_ni_interfaces_list,
				&local_ni_stats_list,
				&udsp_info_list,
				&udsp_info_pref_nids_list,
				&udsp_info_pref_nids_list,
				&local_ni_msg_stats_list,
				&local_ni_msg_stats_list,
				&local_ni_msg_stats_list,
				&local_ni_health_stats_list,
				&local_ni_tunables_list,
				NULL, /* lnd tunables */
				NULL
			};
			int flags = NLM_F_CREATE | NLM_F_MULTI;

			if (lnd) {
				all[ARRAY_SIZE(all) - 2] = lnd->lnd_keys;
				if (idx) {
					all[0] = &net_update_props_list;
					flags |= NLM_F_REPLACE;
				}
			}

			rc = lnet_genl_send_scalar_list(msg, portid, seq,
							&lnet_family, flags,
							LNET_CMD_NETS, all);
			if (rc < 0) {
				NL_SET_ERR_MSG(extack, "failed to send key table");
				GOTO(net_unlock, rc);
			}
			started = true;
		}

		hdr = genlmsg_put(msg, portid, seq, &lnet_family,
				  NLM_F_MULTI, LNET_CMD_NETS);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			GOTO(net_unlock, rc = -EMSGSIZE);
		}

		if (started) {
			nla_put_string(msg, LNET_NET_ATTR_HDR, "");
			started = false;
		}

		nla_put_string(msg, LNET_NET_ATTR_TYPE,
			       libcfs_net2str(net->net_id));

		local_ni = nla_nest_start(msg, LNET_NET_ATTR_LOCAL);
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			char *status = "up";

			if (idx++ < nlist->lngl_idx)
				continue;

			ni_attr = nla_nest_start(msg, dev++);
			found = true;
			lnet_ni_lock(ni);
			if (!export_backup) {
				nla_put_string(msg, LNET_NET_LOCAL_NI_ATTR_NID,
					       libcfs_nidstr(&ni->ni_nid));
				if (!nid_is_lo0(&ni->ni_nid) &&
				    lnet_ni_get_status_locked(ni) != LNET_NI_STATUS_UP)
					status = "down";
				nla_put_string(msg, LNET_NET_LOCAL_NI_ATTR_STATUS,
					       status);
			}

			if (!nid_is_lo0(&ni->ni_nid) && ni->ni_interface) {
				struct nlattr *intf_nest, *intf_attr;

				intf_nest = nla_nest_start(msg,
							   LNET_NET_LOCAL_NI_ATTR_INTERFACE);
				intf_attr = nla_nest_start(msg, 0);
				nla_put_string(msg,
					       LNET_NET_LOCAL_NI_INTF_ATTR_TYPE,
					       ni->ni_interface);
				nla_nest_end(msg, intf_attr);
				nla_nest_end(msg, intf_nest);
			}

			if (gnlh->version) {
				char cpts[LNET_MAX_SHOW_NUM_CPT * 4 + 4], *cpt;
				struct lnet_ioctl_element_msg_stats msg_stats;
				struct lnet_ioctl_element_stats stats;
				size_t buf_len = sizeof(cpts), len;
				struct nlattr *health_attr, *health_stats;
				struct nlattr *send_attr, *send_stats;
				struct nlattr *recv_attr, *recv_stats;
				struct nlattr *drop_attr, *drop_stats;
				struct nlattr *stats_attr, *ni_stats;
				struct nlattr *tun_attr, *ni_tun;
				int j;

				if (export_backup) {
					lnet_ni_unlock(ni);
					goto skip_msg_stats;
				}

				stats.iel_send_count = lnet_sum_stats(&ni->ni_stats,
								      LNET_STATS_TYPE_SEND);
				stats.iel_recv_count = lnet_sum_stats(&ni->ni_stats,
								      LNET_STATS_TYPE_RECV);
				stats.iel_drop_count = lnet_sum_stats(&ni->ni_stats,
								      LNET_STATS_TYPE_DROP);
				lnet_ni_unlock(ni);

				stats_attr = nla_nest_start(msg, LNET_NET_LOCAL_NI_ATTR_STATS);
				ni_stats = nla_nest_start(msg, 0);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_STATS_ATTR_SEND_COUNT,
					    stats.iel_send_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_STATS_ATTR_RECV_COUNT,
					    stats.iel_recv_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_STATS_ATTR_DROP_COUNT,
					    stats.iel_drop_count);
				nla_nest_end(msg, ni_stats);
				nla_nest_end(msg, stats_attr);

				if (gnlh->version < 4)
					goto skip_udsp;

				/* UDSP info */
				rc = lnet_udsp_info_send(msg, LNET_NET_LOCAL_NI_ATTR_UDSP_INFO,
							 &ni->ni_nid, false);
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "Failed to get udsp info");
					genlmsg_cancel(msg, hdr);
					GOTO(net_unlock, rc = -ENOMEM);
				}
skip_udsp:
				if (gnlh->version < 2)
					goto skip_msg_stats;

				msg_stats.im_idx = idx - 1;
				rc = lnet_get_ni_stats(&msg_stats);
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "failed to get msg stats");
					genlmsg_cancel(msg, hdr);
					GOTO(net_unlock, rc = -ENOMEM);
				}

				send_stats = nla_nest_start(msg, LNET_NET_LOCAL_NI_ATTR_SEND_STATS);
				send_attr = nla_nest_start(msg, 0);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_GET_COUNT,
					    msg_stats.im_send_stats.ico_get_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_PUT_COUNT,
					    msg_stats.im_send_stats.ico_put_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_REPLY_COUNT,
					    msg_stats.im_send_stats.ico_reply_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_ACK_COUNT,
					    msg_stats.im_send_stats.ico_ack_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_HELLO_COUNT,
					    msg_stats.im_send_stats.ico_hello_count);
				nla_nest_end(msg, send_attr);
				nla_nest_end(msg, send_stats);

				recv_stats = nla_nest_start(msg, LNET_NET_LOCAL_NI_ATTR_RECV_STATS);
				recv_attr = nla_nest_start(msg, 0);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_GET_COUNT,
					    msg_stats.im_recv_stats.ico_get_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_PUT_COUNT,
					    msg_stats.im_recv_stats.ico_put_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_REPLY_COUNT,
					    msg_stats.im_recv_stats.ico_reply_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_ACK_COUNT,
					    msg_stats.im_recv_stats.ico_ack_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_HELLO_COUNT,
					    msg_stats.im_recv_stats.ico_hello_count);
				nla_nest_end(msg, recv_attr);
				nla_nest_end(msg, recv_stats);

				drop_stats = nla_nest_start(msg,
							    LNET_NET_LOCAL_NI_ATTR_DROPPED_STATS);
				drop_attr = nla_nest_start(msg, 0);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_GET_COUNT,
					    msg_stats.im_drop_stats.ico_get_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_PUT_COUNT,
					    msg_stats.im_drop_stats.ico_put_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_REPLY_COUNT,
					    msg_stats.im_drop_stats.ico_reply_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_ACK_COUNT,
					    msg_stats.im_drop_stats.ico_ack_count);
				nla_put_u32(msg, LNET_NET_LOCAL_NI_MSG_STATS_ATTR_HELLO_COUNT,
					    msg_stats.im_drop_stats.ico_hello_count);
				nla_nest_end(msg, drop_attr);
				nla_nest_end(msg, drop_stats);

				/* health stats */
				health_stats = nla_nest_start(msg,
							      LNET_NET_LOCAL_NI_ATTR_HEALTH_STATS);
				health_attr = nla_nest_start(msg, 0);
				nla_put_s32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_FATAL_ERRORS,
					    atomic_read(&ni->ni_fatal_error_on));
				nla_put_s32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_LEVEL,
					    atomic_read(&ni->ni_healthv));
				nla_put_u32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_INTERRUPTS,
					    atomic_read(&ni->ni_hstats.hlt_local_interrupt));
				nla_put_u32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_DROPPED,
					    atomic_read(&ni->ni_hstats.hlt_local_dropped));
				nla_put_u32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_ABORTED,
					    atomic_read(&ni->ni_hstats.hlt_local_aborted));
				nla_put_u32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_NO_ROUTE,
					    atomic_read(&ni->ni_hstats.hlt_local_no_route));
				nla_put_u32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_TIMEOUTS,
					    atomic_read(&ni->ni_hstats.hlt_local_timeout));
				nla_put_u32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_ERROR,
					    atomic_read(&ni->ni_hstats.hlt_local_error));
				nla_put_u32(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_PING_COUNT,
					    ni->ni_ping_count);
				nla_put_u64_64bit(msg, LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_NEXT_PING,
						  ni->ni_next_ping,
						  LNET_NET_LOCAL_NI_HEALTH_STATS_ATTR_PAD);
				nla_nest_end(msg, health_attr);
				nla_nest_end(msg, health_stats);
skip_msg_stats:
				/* Report net tunables */
				tun_attr = nla_nest_start(msg, LNET_NET_LOCAL_NI_ATTR_TUNABLES);
				ni_tun = nla_nest_start(msg, 0);
				nla_put_s32(msg, LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_TIMEOUT,
					    ni->ni_net->net_tunables.lct_peer_timeout);
				nla_put_s32(msg, LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_CREDITS,
					    ni->ni_net->net_tunables.lct_peer_tx_credits);
				nla_put_s32(msg, LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_BUFFER_CREDITS,
					    ni->ni_net->net_tunables.lct_peer_rtr_credits);
				nla_put_s32(msg, LNET_NET_LOCAL_NI_TUNABLES_ATTR_CREDITS,
					    ni->ni_net->net_tunables.lct_max_tx_credits);
				nla_nest_end(msg, ni_tun);

				nla_nest_end(msg, tun_attr);

				if (lnd && lnd->lnd_nl_get && lnd->lnd_keys) {
					struct nlattr *lnd_tun_attr, *lnd_ni_tun;

					lnd_tun_attr = nla_nest_start(msg,
								      LNET_NET_LOCAL_NI_ATTR_LND_TUNABLES);
					lnd_ni_tun = nla_nest_start(msg, 0);
					rc = lnd->lnd_nl_get(LNET_CMD_NETS, msg,
							     LNET_NET_LOCAL_NI_ATTR_LND_TUNABLES,
							     ni);
					if (rc < 0) {
						NL_SET_ERR_MSG(extack,
							       "failed to get lnd tunables");
						genlmsg_cancel(msg, hdr);
						GOTO(net_unlock, rc);
					}
					nla_nest_end(msg, lnd_ni_tun);
					nla_nest_end(msg, lnd_tun_attr);
				}

				if (!export_backup)
					nla_put_s32(msg, LNET_NET_LOCAL_NI_DEV_CPT,
						    ni->ni_dev_cpt);

				/* Report cpts. We could send this as a nested list
				 * of integers but older versions of the tools
				 * except a string. The new versions can handle
				 * both formats so in the future we can change
				 * this to a nested list.
				 */
				len = snprintf(cpts, buf_len, "\"[");
				cpt = cpts + len;
				buf_len -= len;

				if (ni->ni_ncpts == LNET_CPT_NUMBER && !ni->ni_cpts)  {
					for (j = 0; j < ni->ni_ncpts; j++) {
						len = snprintf(cpt, buf_len, "%d,", j);
						buf_len -= len;
						cpt += len;
					}
				} else {
					for (j = 0;
					     ni->ni_cpts && j < ni->ni_ncpts &&
					     j < LNET_MAX_SHOW_NUM_CPT; j++) {
						len = snprintf(cpt, buf_len, "%d,",
							       ni->ni_cpts[j]);
						buf_len -= len;
						cpt += len;
					}
				}
				snprintf(cpt - 1, sizeof(cpts), "]\"");

				nla_put_string(msg, LNET_NET_LOCAL_NI_CPTS, cpts);
			} else {
				lnet_ni_unlock(ni);
			}
			nla_nest_end(msg, ni_attr);
		}
		nla_nest_end(msg, local_ni);

		genlmsg_end(msg, hdr);
	}

	if (!export_backup && !found) {
		struct nlmsghdr *nlh = nlmsg_hdr(msg);

		nlmsg_cancel(msg, nlh);
		NL_SET_ERR_MSG(extack, "Network is down");
		rc = -ESRCH;
	}
	nlist->lngl_idx = idx;
net_unlock:
	lnet_net_unlock(LNET_LOCK_EX);

	return lnet_nl_send_error(cb->skb, portid, seq, rc);
}

#ifndef HAVE_NETLINK_CALLBACK_START
static int lnet_old_net_show_dump(struct sk_buff *msg,
				   struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lnet_net_show_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lnet_net_show_dump(msg, cb);
}
#endif

static int lnet_genl_parse_tunables(struct nlattr *settings,
				    struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct nlattr *param;
	int rem, rc = 0;

	nla_for_each_nested(param, settings, rem) {
		int type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_UNSPEC;
		s64 num;

		if (nla_type(param) != LN_SCALAR_ATTR_VALUE)
			continue;

		if (nla_strcmp(param, "peer_timeout") == 0)
			type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_TIMEOUT;
		else if (nla_strcmp(param, "peer_credits") == 0)
			type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_CREDITS;
		else if (nla_strcmp(param, "peer_buffer_credits") == 0)
			type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_BUFFER_CREDITS;
		else if (nla_strcmp(param, "credits") == 0)
			type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_CREDITS;

		param = nla_next(param, &rem);
		if (nla_type(param) != LN_SCALAR_ATTR_INT_VALUE)
			return -EINVAL;

		num = nla_get_s64(param);
		switch (type) {
		case LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_TIMEOUT:
			if (num >= 0)
				tun->lt_cmn.lct_peer_timeout = num;
			break;
		case LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_CREDITS:
			if (num > 0)
				tun->lt_cmn.lct_peer_tx_credits = num;
			break;
		case LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_BUFFER_CREDITS:
			if (num > 0)
				tun->lt_cmn.lct_peer_rtr_credits = num;
			break;
		case LNET_NET_LOCAL_NI_TUNABLES_ATTR_CREDITS:
			if (num > 0)
				tun->lt_cmn.lct_max_tx_credits = num;
			break;
		default:
			rc = -EINVAL;
			break;
		}
	}
	return rc;
}

static int lnet_genl_parse_lnd_tunables(struct nlattr *settings,
					struct lnet_lnd_tunables *tun,
					const struct lnet_lnd *lnd)
{
	const struct ln_key_list *list = lnd->lnd_keys;
	struct nlattr *param;
	int rem, rc = 0;
	int i = 1;

	/* silently ignore these setting if the LND driver doesn't
	 * support any LND tunables
	 */
	if (!list || !lnd->lnd_nl_set || !list->lkl_maxattr)
		return 0;

	nla_for_each_nested(param, settings, rem) {
		if (nla_type(param) != LN_SCALAR_ATTR_VALUE)
			continue;

		for (i = 1; i <= list->lkl_maxattr; i++) {
			if (!list->lkl_list[i].lkp_value ||
			    nla_strcmp(param, list->lkl_list[i].lkp_value) != 0)
				continue;

			param = nla_next(param, &rem);
			rc = lnd->lnd_nl_set(LNET_CMD_NETS, param, i, tun);
			if (rc < 0)
				return rc;
		}
	}

	return rc;
}

static inline void
lnet_genl_init_tunables(const struct lnet_lnd *lnd,
			struct lnet_ioctl_config_lnd_tunables *tun)
{
	const struct ln_key_list *list = lnd ? lnd->lnd_keys : NULL;
	int i;

	tun->lt_cmn.lct_peer_timeout = -1;
	tun->lt_cmn.lct_peer_tx_credits = -1;
	tun->lt_cmn.lct_peer_rtr_credits = -1;
	tun->lt_cmn.lct_max_tx_credits = -1;

	if (!list || !lnd->lnd_nl_set || !list->lkl_maxattr)
		return;

	/* init lnd tunables with default values */
	for (i = 1; i <= list->lkl_maxattr; i++)
		lnd->lnd_nl_set(LNET_CMD_NETS, NULL, i, &tun->lt_tun);
}

static int
lnet_genl_parse_local_ni(struct nlattr *entry, struct genl_info *info,
			 int net_id, struct lnet_ioctl_config_ni *conf,
			 bool *ni_list)
{
	struct lnet_ioctl_config_lnd_tunables *tun;
	struct lnet_nid nid = LNET_ANY_NID;
	const struct lnet_lnd *lnd = NULL;
	struct nlattr *settings;
	int healthv = -1;
	int rem3, rc = 0;

	if (net_id != LNET_NET_ANY) {
		lnd = lnet_load_lnd(LNET_NETTYP(net_id));
		if (IS_ERR(lnd)) {
			GENL_SET_ERR_MSG(info, "LND type not supported");
			RETURN(PTR_ERR(lnd));
		}
	}

	LIBCFS_ALLOC(tun, sizeof(struct lnet_ioctl_config_lnd_tunables));
	if (!tun) {
		GENL_SET_ERR_MSG(info, "cannot allocate memory for tunables");
		GOTO(out, rc = -ENOMEM);
	}

	/* Use LND defaults */
	lnet_genl_init_tunables(lnd, tun);
	conf->lic_ncpts = 0;

	nla_for_each_nested(settings, entry, rem3) {
		if (nla_type(settings) != LN_SCALAR_ATTR_VALUE)
			continue;

		if (nla_strcmp(settings, "interfaces") == 0) {
			struct nlattr *intf;
			int rem4;

			settings = nla_next(settings, &rem3);
			if (nla_type(settings) !=
			    LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "invalid interfaces");
				GOTO(out, rc = -EINVAL);
			}

			nla_for_each_nested(intf, settings, rem4) {
				intf = nla_next(intf, &rem4);
				if (nla_type(intf) !=
				    LN_SCALAR_ATTR_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "cannot parse interface");
					GOTO(out, rc = -EINVAL);
				}

				rc = nla_strscpy(conf->lic_ni_intf, intf,
						 sizeof(conf->lic_ni_intf));
				if (rc < 0) {
					GENL_SET_ERR_MSG(info,
							 "failed to parse interfaces");
					GOTO(out, rc);
				}
			}
			*ni_list = true;
		} else if (nla_strcmp(settings, "nid") == 0 &&
			   net_id != LNET_NET_ANY) {
			char nidstr[LNET_NIDSTR_SIZE];

			settings = nla_next(settings, &rem3);
			if (nla_type(settings) != LN_SCALAR_ATTR_VALUE) {
				GENL_SET_ERR_MSG(info, "cannot parse NID");
				GOTO(out, rc = -EINVAL);
			}

			rc = nla_strscpy(nidstr, settings, sizeof(nidstr));
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "failed to parse NID");
				GOTO(out, rc);
			}

			CDEBUG(D_NET, "Requested NID %s\n", nidstr);
			rc = libcfs_strnid(&nid, strim(nidstr));
			if (rc < 0) {
				GENL_SET_ERR_MSG(info, "unsupported NID");
				GOTO(out, rc);
			}

			if (!(info->nlhdr->nlmsg_flags & NLM_F_REPLACE) &&
			     nid_same(&nid, &LNET_ANY_NID)) {
				GENL_SET_ERR_MSG(info, "any NID not supported");
				GOTO(out, rc = -EINVAL);
			}
			*ni_list = true;
		} else if (nla_strcmp(settings, "health stats") == 0 &&
			   info->nlhdr->nlmsg_flags & NLM_F_REPLACE) {
			struct nlattr *health;
			int rem4;

			settings = nla_next(settings, &rem3);
			if (nla_type(settings) != LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "cannot parse health stats");
				GOTO(out, rc = -EINVAL);
			}

			nla_for_each_nested(health, settings, rem4) {
				if (nla_type(health) != LN_SCALAR_ATTR_VALUE ||
				    nla_strcmp(health, "health value") != 0) {
					GENL_SET_ERR_MSG(info,
							 "wrong health config format");
					GOTO(out, rc = -EINVAL);
				}

				health = nla_next(health, &rem4);
				if (nla_type(health) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "invalid health config format");
					GOTO(out, rc = -EINVAL);
				}

				healthv = nla_get_s64(health);
				clamp_t(s64, healthv, 0, LNET_MAX_HEALTH_VALUE);
			}
		} else if (nla_strcmp(settings, "tunables") == 0) {
			settings = nla_next(settings, &rem3);
			if (nla_type(settings) !=
			    LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "invalid tunables");
				GOTO(out, rc = -EINVAL);
			}

			rc = lnet_genl_parse_tunables(settings, tun);
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "failed to parse tunables");
				GOTO(out, rc);
			}
		} else if ((nla_strcmp(settings, "lnd tunables") == 0)) {
			settings = nla_next(settings, &rem3);
			if (nla_type(settings) !=
			    LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "lnd tunables should be list\n");
				GOTO(out, rc = -EINVAL);
			}

			if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE &&
			    net_id == LNET_NET_ANY) {
				struct lnet_net *net;

				lnet_net_lock(LNET_LOCK_EX);
				list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
					struct lnet_ni *ni;

					if (!net->net_lnd)
						continue;

					list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
						if (!nid_same(&nid, &LNET_ANY_NID) &&
						    !nid_same(&nid, &ni->ni_nid))
							continue;

						rc = lnet_genl_parse_lnd_tunables(settings,
										  &ni->ni_lnd_tunables,
										  net->net_lnd);
						if (rc < 0) {
							GENL_SET_ERR_MSG(info,
									 "failed to parse lnd tunables");
							lnet_net_unlock(LNET_LOCK_EX);
							GOTO(out, rc);
						}
					}
				}
				lnet_net_unlock(LNET_LOCK_EX);
			} else {
				lnd = lnet_load_lnd(LNET_NETTYP(net_id));
				if (IS_ERR(lnd)) {
					GENL_SET_ERR_MSG(info,
							 "LND type not supported");
					GOTO(out, rc = PTR_ERR(lnd));
				}

				rc = lnet_genl_parse_lnd_tunables(settings,
								  &tun->lt_tun, lnd);
				if (rc < 0) {
					GENL_SET_ERR_MSG(info,
							 "failed to parse lnd tunables");
					GOTO(out, rc);
				}
			}
		} else if (nla_strcmp(settings, "CPT") == 0) {
			struct nlattr *cpt;
			int rem4;

			settings = nla_next(settings, &rem3);
			if (nla_type(settings) != LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "CPT should be list");
				GOTO(out, rc = -EINVAL);
			}

			nla_for_each_nested(cpt, settings, rem4) {
				s64 core;

				if (nla_type(cpt) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "invalid CPT config");
					GOTO(out, rc = -EINVAL);
				}

				core = nla_get_s64(cpt);
				if (core >= LNET_CPT_NUMBER) {
					GENL_SET_ERR_MSG(info,
							 "invalid CPT value");
					GOTO(out, rc = -ERANGE);
				}

				conf->lic_cpts[conf->lic_ncpts] = core;
				conf->lic_ncpts++;
			}
		}
	}

	if (info->nlhdr->nlmsg_flags & NLM_F_CREATE) {
		if (nid_same(&nid, &LNET_ANY_NID) &&
		    !strlen(conf->lic_ni_intf)) {
			GENL_SET_ERR_MSG(info,
					 "interface / NID is missing");
			GOTO(out, rc);
		}

		rc = lnet_dyn_add_ni(conf, net_id, &nid, tun);
		switch (rc) {
		case -ENOENT:
			GENL_SET_ERR_MSG(info,
					 "cannot parse net");
			break;
		case -ERANGE:
			GENL_SET_ERR_MSG(info,
					 "invalid CPT set");
			break;
		default:
			GENL_SET_ERR_MSG(info,
					 "cannot add LNet NI");
		case 0:
			break;
		}
	} else if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE && healthv != -1) {
		lnet_ni_set_healthv(&nid, healthv);
		rc = 0;
	} else if (!(info->nlhdr->nlmsg_flags & (NLM_F_CREATE | NLM_F_REPLACE))) {
		struct lnet_ni *ni;

		/* delete case */
		rc = -ENODEV;
		if (!strlen(conf->lic_ni_intf) &&
		    nid_same(&nid, &LNET_ANY_NID)) {
			GENL_SET_ERR_MSG(info,
					 "interface / NID is missing");
			GOTO(out, rc);
		}

		if (nid_same(&nid, &LNET_ANY_NID)) {
			struct lnet_net *net;
			bool found = false;

			lnet_net_lock(LNET_LOCK_EX);
			net = lnet_get_net_locked(net_id);
			if (!net) {
				GENL_SET_ERR_MSG(info,
						 "LNet net doesn't exist");
				lnet_net_unlock(LNET_LOCK_EX);
				GOTO(out, rc);
			}

			list_for_each_entry(ni, &net->net_ni_list,
					    ni_netlist) {
				if (!ni->ni_interface ||
				    strcmp(ni->ni_interface,
					  conf->lic_ni_intf) != 0)
					continue;

				found = true;
				lnet_net_unlock(LNET_LOCK_EX);
				rc = lnet_dyn_del_ni(&ni->ni_nid);
				break;
			}

			if (rc < 0 && !found) { /* will be -ENODEV */
				GENL_SET_ERR_MSG(info,
						 "interface invalid for deleting LNet NI");
				lnet_net_unlock(LNET_LOCK_EX);
			}
		} else {
			rc = lnet_dyn_del_ni(&nid);
		}

		if (rc < 0) {
			GENL_SET_ERR_MSG(info,
					 "cannot del LNet NI");
			GOTO(out, rc);
		}
	}
out:
	LIBCFS_FREE(tun, sizeof(struct lnet_ioctl_config_lnd_tunables));

	return rc;
}

static int lnet_net_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *params = genlmsg_data(gnlh);
	int msg_len, rem, rc = 0;
	struct nlattr *attr;

	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		GENL_SET_ERR_MSG(info, "no configuration");
		return -ENOMSG;
	}

	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		GENL_SET_ERR_MSG(info, "invalid configuration");
		return -EINVAL;
	}

	nla_for_each_nested(attr, params, rem) {
		bool ni_list = false, ipnets = false;
		struct lnet_ioctl_config_ni conf;
		u32 net_id = LNET_NET_ANY;
		struct nlattr *entry;
		int rem2;

		if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
			continue;

		nla_for_each_nested(entry, attr, rem2) {
			switch (nla_type(entry)) {
			case LN_SCALAR_ATTR_VALUE: {
				ssize_t len;

				memset(&conf, 0, sizeof(conf));
				if (nla_strcmp(entry, "ip2net") == 0) {
					entry = nla_next(entry, &rem2);
					if (nla_type(entry) !=
					    LN_SCALAR_ATTR_VALUE) {
						GENL_SET_ERR_MSG(info,
								 "ip2net has invalid key");
						GOTO(out, rc = -EINVAL);
					}

					len = nla_strscpy(conf.lic_legacy_ip2nets,
							  entry,
							  sizeof(conf.lic_legacy_ip2nets));
					if (len < 0) {
						GENL_SET_ERR_MSG(info,
								 "ip2net key string is invalid");
						GOTO(out, rc = len);
					}
					ni_list = true;
					ipnets = true;
				} else if (nla_strcmp(entry, "net type") == 0) {
					char tmp[LNET_NIDSTR_SIZE];

					entry = nla_next(entry, &rem2);
					if (nla_type(entry) !=
					    LN_SCALAR_ATTR_VALUE) {
						GENL_SET_ERR_MSG(info,
								 "net type has invalid key");
						GOTO(out, rc = -EINVAL);
					}

					len = nla_strscpy(tmp, entry,
							  sizeof(tmp));
					if (len < 0) {
						GENL_SET_ERR_MSG(info,
								 "net type key string is invalid");
						GOTO(out, rc = len);
					}

					net_id = libcfs_str2net(tmp);
					if (!net_id) {
						GENL_SET_ERR_MSG(info,
								 "cannot parse net");
						GOTO(out, rc = -ENODEV);
					}
					if (LNET_NETTYP(net_id) == LOLND) {
						GENL_SET_ERR_MSG(info,
								 "setting @lo not allowed");
						GOTO(out, rc = -ENODEV);
					}
					conf.lic_legacy_ip2nets[0] = '\0';
					conf.lic_ni_intf[0] = '\0';
					ni_list = false;
				}
				if (rc < 0)
					GOTO(out, rc);
				break;
			}
			case LN_SCALAR_ATTR_LIST: {
				struct nlattr *interface;
				int rem3;

				ipnets = false;
				nla_for_each_nested(interface, entry, rem3) {
					rc = lnet_genl_parse_local_ni(interface, info,
								      net_id, &conf,
								      &ni_list);
					if (rc < 0)
						GOTO(out, rc);
				}
				break;
			}
			/* it is possible a newer version of the user land send
			 * values older kernels doesn't handle. So silently
			 * ignore these values
			 */
			default:
				break;
			}
		}

		/* Handle case of just sent NET with no list of NIDs */
		if (!(info->nlhdr->nlmsg_flags & (NLM_F_CREATE | NLM_F_REPLACE)) &&
		    !ni_list) {
			rc = lnet_dyn_del_net(net_id);
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "cannot del network");
			}
		} else if ((info->nlhdr->nlmsg_flags & NLM_F_CREATE) &&
			   ipnets && ni_list) {
			rc = lnet_handle_legacy_ip2nets(conf.lic_legacy_ip2nets,
							NULL);
			if (rc < 0)
				GENL_SET_ERR_MSG(info,
						 "cannot setup ip2nets");
		}
	}
out:
	return rc;
}

/* Called with ln_api_mutex */
static int lnet_parse_peer_nis(struct nlattr *rlist, struct genl_info *info,
			       struct lnet_nid *pnid, bool mr,
			       bool *create_some)
{
	struct lnet_nid snid = LNET_ANY_NID;
	struct nlattr *props;
	int rem, rc = 0;
	s64 num = -1;

	nla_for_each_nested(props, rlist, rem) {
		if (nla_type(props) != LN_SCALAR_ATTR_VALUE)
			continue;

		if (nla_strcmp(props, "nid") == 0) {
			char nidstr[LNET_NIDSTR_SIZE];

			props = nla_next(props, &rem);
			if (nla_type(props) != LN_SCALAR_ATTR_VALUE) {
				GENL_SET_ERR_MSG(info,
						 "invalid secondary NID");
				GOTO(report_err, rc = -EINVAL);
			}

			rc = nla_strscpy(nidstr, props, sizeof(nidstr));
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "failed to get secondary NID");
				GOTO(report_err, rc);
			}

			rc = libcfs_strnid(&snid, strim(nidstr));
			if (rc < 0) {
				GENL_SET_ERR_MSG(info, "unsupported secondary NID");
				GOTO(report_err, rc);
			}

			if (LNET_NID_IS_ANY(&snid) || nid_same(&snid, pnid))
				*create_some = false;
		} else if (nla_strcmp(props, "health stats") == 0) {
			struct nlattr *health;
			int rem2;

			props = nla_next(props, &rem);
			if (nla_type(props) !=
			      LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "invalid health configuration");
				GOTO(report_err, rc = -EINVAL);
			}

			nla_for_each_nested(health, props, rem2) {
				if (nla_type(health) != LN_SCALAR_ATTR_VALUE ||
				    nla_strcmp(health, "health value") != 0) {
					GENL_SET_ERR_MSG(info,
							 "wrong health config format");
					GOTO(report_err, rc = -EINVAL);
				}

				health = nla_next(health, &rem2);
				if (nla_type(health) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "invalid health config format");
					GOTO(report_err, rc = -EINVAL);
				}

				num = nla_get_s64(health);
				clamp_t(s64, num, 0, LNET_MAX_HEALTH_VALUE);
			}
		}
	}

	if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE && num != -1) {
		lnet_peer_ni_set_healthv(pnid, num, !*create_some);
	} else if (info->nlhdr->nlmsg_flags & NLM_F_CREATE) {
		bool lock_prim = info->nlhdr->nlmsg_flags & NLM_F_EXCL;

		rc = lnet_user_add_peer_ni(pnid, &snid, mr, lock_prim);
		if (rc < 0)
			GENL_SET_ERR_MSG(info,
					 "failed to add peer");
	} else if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE) && *create_some) {
		bool force = info->nlhdr->nlmsg_flags & NLM_F_EXCL;

		rc = lnet_del_peer_ni(pnid, &snid, force);
		if (rc < 0)
			GENL_SET_ERR_MSG(info,
					 "failed to del peer");
	}
report_err:
	return rc;
}

static int lnet_peer_ni_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *params = genlmsg_data(gnlh);
	int msg_len, rem, rc = 0;
	struct lnet_nid pnid;
	struct nlattr *attr;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		GENL_SET_ERR_MSG(info, "Network is down");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENETDOWN;
	}

	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		GENL_SET_ERR_MSG(info, "no configuration");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENOMSG;
	}

	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		GENL_SET_ERR_MSG(info, "invalid configuration");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -EINVAL;
	}

	nla_for_each_nested(attr, params, rem) {
		bool parse_peer_nis = false;
		struct nlattr *pnid_prop;
		int rem2;

		if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
			continue;

		pnid = LNET_ANY_NID;
		nla_for_each_nested(pnid_prop, attr, rem2) {
			bool mr = true;

			if (nla_type(pnid_prop) != LN_SCALAR_ATTR_VALUE)
				continue;

			if (nla_strcmp(pnid_prop, "primary nid") == 0) {
				char nidstr[LNET_NIDSTR_SIZE];

				pnid_prop = nla_next(pnid_prop, &rem2);
				if (nla_type(pnid_prop) !=
				    LN_SCALAR_ATTR_VALUE) {
					GENL_SET_ERR_MSG(info,
							  "invalid primary NID type");
					GOTO(report_err, rc = -EINVAL);
				}

				rc = nla_strscpy(nidstr, pnid_prop,
						 sizeof(nidstr));
				if (rc < 0) {
					GENL_SET_ERR_MSG(info,
							 "failed to get primary NID");
					GOTO(report_err, rc);
				}

				rc = libcfs_strnid(&pnid, strim(nidstr));
				if (rc < 0) {
					GENL_SET_ERR_MSG(info,
							 "unsupported primary NID");
					GOTO(report_err, rc);
				}

				/* we must create primary NID for peer ni
				 * creation
				 */
				if (info->nlhdr->nlmsg_flags & NLM_F_CREATE) {
					bool lock_prim;

					lock_prim = info->nlhdr->nlmsg_flags & NLM_F_EXCL;
					rc = lnet_user_add_peer_ni(&pnid,
								   &LNET_ANY_NID,
								   true, lock_prim);
					if (rc < 0) {
						GENL_SET_ERR_MSG(info,
								 "failed to add primary peer");
						GOTO(report_err, rc);
					}
				}
			} else if (nla_strcmp(pnid_prop, "Multi-Rail") == 0) {
				pnid_prop = nla_next(pnid_prop, &rem2);
				if (nla_type(pnid_prop) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							  "invalid MR flag param");
					GOTO(report_err, rc = -EINVAL);
				}

				if (nla_get_s64(pnid_prop) == 0)
					mr = false;
			} else if (nla_strcmp(pnid_prop, "peer state") == 0) {
				struct lnet_peer_ni *lpni;
				struct lnet_peer *lp;

				pnid_prop = nla_next(pnid_prop, &rem2);
				if (nla_type(pnid_prop) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							  "invalid peer state param");
					GOTO(report_err, rc = -EINVAL);
				}

				lpni = lnet_peer_ni_find_locked(&pnid);
				if (!lpni) {
					GENL_SET_ERR_MSG(info,
							  "invalid peer state param");
					GOTO(report_err, rc = -ENOENT);
				}
				lnet_peer_ni_decref_locked(lpni);
				lp = lpni->lpni_peer_net->lpn_peer;
				lp->lp_state = nla_get_s64(pnid_prop);
			} else if (nla_strcmp(pnid_prop, "peer ni") == 0) {
				struct nlattr *rlist;
				int rem3;

				if (!(info->nlhdr->nlmsg_flags & NLM_F_REPLACE) &&
				    LNET_NID_IS_ANY(&pnid)) {
					GENL_SET_ERR_MSG(info,
							 "missing required primary NID");
					GOTO(report_err, rc);
				}

				pnid_prop = nla_next(pnid_prop, &rem2);
				if (nla_type(pnid_prop) !=
				    LN_SCALAR_ATTR_LIST) {
					GENL_SET_ERR_MSG(info,
							  "invalid NIDs list");
					GOTO(report_err, rc = -EINVAL);
				}

				parse_peer_nis = true;
				nla_for_each_nested(rlist, pnid_prop, rem3) {
					rc = lnet_parse_peer_nis(rlist, info,
								 &pnid, mr,
								 &parse_peer_nis);
					if (rc < 0)
						GOTO(report_err, rc);
				}
			}
		}

		/* If we have remote peer ni's we already add /del peers */
		if (parse_peer_nis)
			continue;

		if (LNET_NID_IS_ANY(&pnid)) {
			GENL_SET_ERR_MSG(info, "missing primary NID");
			GOTO(report_err, rc);
		}

		if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE)) {
			bool force = info->nlhdr->nlmsg_flags & NLM_F_EXCL;

			rc = lnet_del_peer_ni(&pnid, &LNET_ANY_NID,
					      force);
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "failed to del primary peer");
				GOTO(report_err, rc);
			}
		}
	}
report_err:
	/* If we failed on creation and encounter a latter error then
	 * delete the primary nid.
	 */
	if (rc < 0 && info->nlhdr->nlmsg_flags & NLM_F_CREATE &&
	    !LNET_NID_IS_ANY(&pnid))
		lnet_del_peer_ni(&pnid, &LNET_ANY_NID,
				 info->nlhdr->nlmsg_flags & NLM_F_EXCL);
	mutex_unlock(&the_lnet.ln_api_mutex);

	return rc;
}

/** LNet route handling */

/* We can't use struct lnet_ioctl_config_data since it lacks
 * support for large NIDS
 */
struct lnet_route_properties {
	struct lnet_nid		lrp_gateway;
	u32			lrp_net;
	s32			lrp_hop;
	u32			lrp_flags;
	u32			lrp_priority;
	u32			lrp_sensitivity;
};

struct lnet_genl_route_list {
	unsigned int				lgrl_index;
	unsigned int				lgrl_count;
	GENRADIX(struct lnet_route_properties)	lgrl_list;
};

static inline struct lnet_genl_route_list *
lnet_route_dump_ctx(struct netlink_callback *cb)
{
	return (struct lnet_genl_route_list *)cb->args[0];
}

static int lnet_route_show_done(struct netlink_callback *cb)
{
	struct lnet_genl_route_list *rlist = lnet_route_dump_ctx(cb);

	if (rlist) {
		genradix_free(&rlist->lgrl_list);
		CFS_FREE_PTR(rlist);
	}
	cb->args[0] = 0;

	return 0;
}

static int lnet_scan_route(struct lnet_genl_route_list *rlist,
		    struct lnet_route_properties *settings)
{
	struct lnet_remotenet *rnet;
	struct list_head *rn_list;
	struct lnet_route *route;
	int cpt, i, rc = 0;

	cpt = lnet_net_lock_current();

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++) {
		rn_list = &the_lnet.ln_remote_nets_hash[i];
		list_for_each_entry(rnet, rn_list, lrn_list) {
			if (settings->lrp_net != LNET_NET_ANY &&
			    settings->lrp_net != rnet->lrn_net)
				continue;

			list_for_each_entry(route, &rnet->lrn_routes,
					    lr_list) {
				struct lnet_route_properties *prop;

				if (!LNET_NID_IS_ANY(&settings->lrp_gateway) &&
				    !nid_same(&settings->lrp_gateway,
					      &route->lr_nid)) {
					continue;
				}

				if (settings->lrp_hop != -1 &&
				    settings->lrp_hop != route->lr_hops)
					continue;

				if (settings->lrp_priority != -1 &&
				    settings->lrp_priority != route->lr_priority)
					continue;

				if (settings->lrp_sensitivity != -1 &&
				    settings->lrp_sensitivity !=
				    route->lr_gateway->lp_health_sensitivity)
					continue;

				prop = genradix_ptr_alloc(&rlist->lgrl_list,
							  rlist->lgrl_count++,
							  GFP_ATOMIC);
				if (!prop)
					GOTO(failed_alloc, rc = -ENOMEM);

				prop->lrp_net = rnet->lrn_net;
				prop->lrp_gateway = route->lr_nid;
				prop->lrp_hop = route->lr_hops;
				prop->lrp_priority = route->lr_priority;
				prop->lrp_sensitivity =
					route->lr_gateway->lp_health_sensitivity;
				if (lnet_is_route_alive(route))
					prop->lrp_flags |= LNET_RT_ALIVE;
				else
					prop->lrp_flags &= ~LNET_RT_ALIVE;
				if (route->lr_single_hop)
					prop->lrp_flags &= ~LNET_RT_MULTI_HOP;
				else
					prop->lrp_flags |= LNET_RT_MULTI_HOP;
			}
		}
	}

failed_alloc:
	lnet_net_unlock(cpt);
	return rc;
}

/* Size of the message send by lnet_genl_send_scalar_list().
 * Length is from genlmsg_len() on the msg created.
 */
#define ROUTER_MSG_MIN_SIZE		284
/* For 'value' packet it contains
 *	net		LNET_NIDSTR_SIZE
 *	gateway		LNET_NIDSTR_SIZE
 *	hop		u32
 *	priority	u32
 *	health sensit.. u32
 *	state		"down" largest string (5)
 *	type		"single-hop" largest string (10)
 */
#define ROUTER_MSG_VALUES_SIZE		(LNET_NIDSTR_SIZE * 2 + 27)

/* LNet route ->start() handler for GET requests */
static int lnet_route_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	unsigned long len = ROUTER_MSG_MIN_SIZE;
	struct lnet_genl_route_list *rlist;
	int msg_len = genlmsg_len(gnlh);
	int rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (the_lnet.ln_refcount == 0 ||
	    the_lnet.ln_state != LNET_STATE_RUNNING) {
		NL_SET_ERR_MSG(extack, "Network is down");
		return -ENETDOWN;
	}

	CFS_ALLOC_PTR(rlist);
	if (!rlist) {
		NL_SET_ERR_MSG(extack, "No memory for route list");
		return -ENOMEM;
	}

	genradix_init(&rlist->lgrl_list);
	rlist->lgrl_count = 0;
	rlist->lgrl_index = 0;
	cb->args[0] = (long)rlist;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (!msg_len) {
		struct lnet_route_properties tmp = {
			.lrp_gateway		= LNET_ANY_NID,
			.lrp_net		= LNET_NET_ANY,
			.lrp_hop		= -1,
			.lrp_priority		= -1,
			.lrp_sensitivity	= -1,
		};

		rc = lnet_scan_route(rlist, &tmp);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack,
				       "failed to allocate router data");
			GOTO(report_err, rc);
		}
	} else {
		struct nlattr *params = genlmsg_data(gnlh);
		struct nlattr *attr;
		int rem;

		nla_for_each_nested(attr, params, rem) {
			struct lnet_route_properties tmp = {
				.lrp_gateway		= LNET_ANY_NID,
				.lrp_net		= LNET_NET_ANY,
				.lrp_hop		= -1,
				.lrp_priority		= -1,
				.lrp_sensitivity	= -1,
			};
			struct nlattr *route;
			int rem2;

			if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
				continue;

			nla_for_each_nested(route, attr, rem2) {
				if (nla_type(route) != LN_SCALAR_ATTR_VALUE)
					continue;

				if (nla_strcmp(route, "net") == 0) {
					char nw[LNET_NIDSTR_SIZE];

					route = nla_next(route, &rem2);
					if (nla_type(route) !=
					    LN_SCALAR_ATTR_VALUE) {
						NL_SET_ERR_MSG(extack,
							       "invalid net param");
						GOTO(report_err, rc = -EINVAL);
					}

					rc = nla_strscpy(nw, route, sizeof(nw));
					if (rc < 0) {
						NL_SET_ERR_MSG(extack,
							       "failed to get route param");
						GOTO(report_err, rc);
					}
					rc = 0;
					tmp.lrp_net = libcfs_str2net(strim(nw));
				} else if (nla_strcmp(route, "gateway") == 0) {
					char gw[LNET_NIDSTR_SIZE];

					route = nla_next(route, &rem2);
					if (nla_type(route) !=
					    LN_SCALAR_ATTR_VALUE) {
						NL_SET_ERR_MSG(extack,
							       "invalid gateway param");
						GOTO(report_err, rc = -EINVAL);
					}

					rc = nla_strscpy(gw, route, sizeof(gw));
					if (rc < 0) {
						NL_SET_ERR_MSG(extack,
							       "failed to get route param");
						GOTO(report_err, rc);
					}

					rc = libcfs_strnid(&tmp.lrp_gateway, strim(gw));
					if (rc < 0) {
						NL_SET_ERR_MSG(extack,
							       "cannot parse gateway");
						GOTO(report_err, rc = -ENODEV);
					}
					rc = 0;
				} else if (nla_strcmp(route, "hop") == 0) {
					route = nla_next(route, &rem2);
					if (nla_type(route) !=
					    LN_SCALAR_ATTR_INT_VALUE) {
						NL_SET_ERR_MSG(extack,
							       "invalid hop param");
						GOTO(report_err, rc = -EINVAL);
					}

					tmp.lrp_hop = nla_get_s64(route);
					if (tmp.lrp_hop != -1)
						clamp_t(s32, tmp.lrp_hop, 1, 127);
				} else if (nla_strcmp(route, "priority") == 0) {
					route = nla_next(route, &rem2);
					if (nla_type(route) !=
					    LN_SCALAR_ATTR_INT_VALUE) {
						NL_SET_ERR_MSG(extack,
							       "invalid priority param");
						GOTO(report_err, rc = -EINVAL);
					}

					tmp.lrp_priority = nla_get_s64(route);
				}
			}

			rc = lnet_scan_route(rlist, &tmp);
			if (rc < 0) {
				NL_SET_ERR_MSG(extack,
					       "failed to allocate router data");
				GOTO(report_err, rc);
			}
		}
	}

	len += ROUTER_MSG_VALUES_SIZE * rlist->lgrl_count;
	if (len > BIT(sizeof(cb->min_dump_alloc) << 3)) {
		NL_SET_ERR_MSG(extack, "Netlink msg is too large");
		rc = -EMSGSIZE;
	} else {
		cb->min_dump_alloc = len;
	}
report_err:
	mutex_unlock(&the_lnet.ln_api_mutex);

	if (rc < 0)
		lnet_route_show_done(cb);

	return rc;
}

static const struct ln_key_list route_props_list = {
	.lkl_maxattr			= LNET_ROUTE_ATTR_MAX,
	.lkl_list			= {
		[LNET_ROUTE_ATTR_HDR]			= {
			.lkp_value			= "route",
			.lkp_key_format			= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type			= NLA_NUL_STRING,
		},
		[LNET_ROUTE_ATTR_NET]			= {
			.lkp_value			= "net",
			.lkp_data_type			= NLA_STRING
		},
		[LNET_ROUTE_ATTR_GATEWAY]		= {
			.lkp_value			= "gateway",
			.lkp_data_type			= NLA_STRING
		},
		[LNET_ROUTE_ATTR_HOP]			= {
			.lkp_value			= "hop",
			.lkp_data_type			= NLA_S32
		},
		[LNET_ROUTE_ATTR_PRIORITY]		= {
			.lkp_value			= "priority",
			.lkp_data_type			= NLA_U32
		},
		[LNET_ROUTE_ATTR_HEALTH_SENSITIVITY]	= {
			.lkp_value			= "health_sensitivity",
			.lkp_data_type			= NLA_U32
		},
		[LNET_ROUTE_ATTR_STATE]	= {
			.lkp_value			= "state",
			.lkp_data_type			= NLA_STRING,
		},
		[LNET_ROUTE_ATTR_TYPE]	= {
			.lkp_value			= "type",
			.lkp_data_type			= NLA_STRING,
		},
	},
};


static int lnet_route_show_dump(struct sk_buff *msg,
				struct netlink_callback *cb)
{
	struct lnet_genl_route_list *rlist = lnet_route_dump_ctx(cb);
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx = rlist->lgrl_index;
	int msg_len = genlmsg_len(gnlh);
	int rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (!rlist->lgrl_count) {
		NL_SET_ERR_MSG(extack, "No routes found");
		GOTO(send_error, rc = msg_len ? -ENOENT : 0);
	}

	if (!idx) {
		const struct ln_key_list *all[] = {
			&route_props_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lnet_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_CMD_ROUTES, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_error, rc);
		}
	}

	while (idx < rlist->lgrl_count) {
		struct lnet_route_properties *prop;
		void *hdr;

		prop = genradix_ptr(&rlist->lgrl_list, idx++);

		hdr = genlmsg_put(msg, portid, seq, &lnet_family,
				  NLM_F_MULTI, LNET_CMD_ROUTES);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			genlmsg_cancel(msg, hdr);
			GOTO(send_error, rc = -EMSGSIZE);
		}

		if (idx == 1)
			nla_put_string(msg, LNET_ROUTE_ATTR_HDR, "");

		nla_put_string(msg, LNET_ROUTE_ATTR_NET,
			       libcfs_net2str(prop->lrp_net));
		nla_put_string(msg, LNET_ROUTE_ATTR_GATEWAY,
			       libcfs_nidstr(&prop->lrp_gateway));
		if (gnlh->version) {
			nla_put_s32(msg, LNET_ROUTE_ATTR_HOP, prop->lrp_hop);
			nla_put_u32(msg, LNET_ROUTE_ATTR_PRIORITY, prop->lrp_priority);
			nla_put_u32(msg, LNET_ROUTE_ATTR_HEALTH_SENSITIVITY,
				    prop->lrp_sensitivity);

			if (!(cb->nlh->nlmsg_flags & NLM_F_DUMP_FILTERED)) {
				nla_put_string(msg, LNET_ROUTE_ATTR_STATE,
					       prop->lrp_flags & LNET_RT_ALIVE ?
					       "up" : "down");
				nla_put_string(msg, LNET_ROUTE_ATTR_TYPE,
					       prop->lrp_flags & LNET_RT_MULTI_HOP ?
					       "multi-hop" : "single-hop");
			}
		}
		genlmsg_end(msg, hdr);
	}
	rlist->lgrl_index = idx;
send_error:
	return lnet_nl_send_error(cb->skb, portid, seq, rc);
};

#ifndef HAVE_NETLINK_CALLBACK_START
static int lnet_old_route_show_dump(struct sk_buff *msg,
				    struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lnet_route_show_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lnet_route_show_dump(msg, cb);
}
#endif /* !HAVE_NETLINK_CALLBACK_START */

/** LNet peer handling */
struct lnet_genl_processid_list {
	unsigned int			lgpl_index;
	unsigned int			lgpl_count;
	GENRADIX(struct lnet_processid)	lgpl_list;
};

static inline struct lnet_genl_processid_list *
lnet_peer_dump_ctx(struct netlink_callback *cb)
{
	return (struct lnet_genl_processid_list *)cb->args[0];
}

static int lnet_peer_ni_show_done(struct netlink_callback *cb)
{
	struct lnet_genl_processid_list *plist = lnet_peer_dump_ctx(cb);

	if (plist) {
		genradix_free(&plist->lgpl_list);
		CFS_FREE_PTR(plist);
	}
	cb->args[0] = 0;

	return 0;
}

/* LNet peer ->start() handler for GET requests */
static int lnet_peer_ni_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	struct lnet_genl_processid_list *plist;
	int msg_len = genlmsg_len(gnlh);
	int rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		NL_SET_ERR_MSG(extack, "Network is down");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENETDOWN;
	}

	CFS_ALLOC_PTR(plist);
	if (!plist) {
		NL_SET_ERR_MSG(extack, "No memory for peer list");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENOMEM;
	}

	genradix_init(&plist->lgpl_list);
	plist->lgpl_count = 0;
	plist->lgpl_index = 0;
	cb->args[0] = (long)plist;

	if (!msg_len) {
		struct lnet_peer_table *ptable;
		int cpt;

		cfs_percpt_for_each(ptable, cpt, the_lnet.ln_peer_tables) {
			struct lnet_peer *lp;

			list_for_each_entry(lp, &ptable->pt_peer_list,
					    lp_peer_list) {
				struct lnet_processid *lpi;

				lpi = genradix_ptr_alloc(&plist->lgpl_list,
							 plist->lgpl_count++,
							 GFP_KERNEL);
				if (!lpi) {
					NL_SET_ERR_MSG(extack,
						      "failed to allocate NID");
					GOTO(report_err, rc = -ENOMEM);
				}

				lpi->pid = LNET_PID_LUSTRE;
				lpi->nid = lp->lp_primary_nid;
			}
		}
	} else {
		struct nlattr *params = genlmsg_data(gnlh);
		struct nlattr *attr;
		int rem;

		nla_for_each_nested(attr, params, rem) {
			struct nlattr *nid;
			int rem2;

			if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
				continue;

			nla_for_each_nested(nid, attr, rem2) {
				char addr[LNET_NIDSTR_SIZE];
				struct lnet_processid *id;

				if (nla_type(nid) != LN_SCALAR_ATTR_VALUE ||
				    nla_strcmp(nid, "primary nid") != 0)
					continue;

				nid = nla_next(nid, &rem2);
				if (nla_type(nid) != LN_SCALAR_ATTR_VALUE) {
					NL_SET_ERR_MSG(extack,
						       "invalid primary nid param");
					GOTO(report_err, rc = -EINVAL);
				}

				rc = nla_strscpy(addr, nid, sizeof(addr));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "failed to get primary nid param");
					GOTO(report_err, rc);
				}

				id = genradix_ptr_alloc(&plist->lgpl_list,
							plist->lgpl_count++,
							GFP_KERNEL);
				if (!id) {
					NL_SET_ERR_MSG(extack, "failed to allocate NID");
					GOTO(report_err, rc = -ENOMEM);
				}

				rc = libcfs_strid(id, strim(addr));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack, "invalid NID");
					GOTO(report_err, rc);
				}
				rc = 0;
			}
		}
	}
report_err:
	mutex_unlock(&the_lnet.ln_api_mutex);

	if (rc < 0)
		lnet_peer_ni_show_done(cb);

	return rc;
}

static const struct ln_key_list lnet_peer_ni_keys = {
	.lkl_maxattr			= LNET_PEER_NI_ATTR_MAX,
	.lkl_list			= {
		[LNET_PEER_NI_ATTR_HDR]  = {
			.lkp_value		= "peer",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_PEER_NI_ATTR_PRIMARY_NID] = {
			.lkp_value		= "primary nid",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_PEER_NI_ATTR_MULTIRAIL]	= {
			.lkp_value              = "Multi-Rail",
			.lkp_data_type          = NLA_FLAG
		},
		[LNET_PEER_NI_ATTR_STATE]	= {
			.lkp_value		= "peer state",
			.lkp_data_type		= NLA_U32
		},
		[LNET_PEER_NI_ATTR_PEER_NI_LIST] = {
			.lkp_value              = "peer ni",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type          = NLA_NESTED,
		},
	},
};

static const struct ln_key_list lnet_peer_ni_list = {
	.lkl_maxattr			= LNET_PEER_NI_LIST_ATTR_MAX,
	.lkl_list			= {
		[LNET_PEER_NI_LIST_ATTR_NID]		= {
			.lkp_value			= "nid",
			.lkp_data_type			= NLA_STRING,
		},
		[LNET_PEER_NI_LIST_ATTR_UDSP_INFO]	= {
			.lkp_value			= "udsp info",
			.lkp_key_format			= LNKF_MAPPING,
			.lkp_data_type			= NLA_NESTED,
		},
		[LNET_PEER_NI_LIST_ATTR_STATE]		= {
			.lkp_value			= "state",
			.lkp_data_type			= NLA_STRING,
		},
		[LNET_PEER_NI_LIST_ATTR_MAX_TX_CREDITS]	= {
			.lkp_value			= "max_ni_tx_credits",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_ATTR_CUR_TX_CREDITS]	= {
			.lkp_value			= "available_tx_credits",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_ATTR_MIN_TX_CREDITS]	= {
			.lkp_value			= "min_tx_credits",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_ATTR_QUEUE_BUF_COUNT] = {
			.lkp_value			= "tx_q_num_of_buf",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_ATTR_CUR_RTR_CREDITS] = {
			.lkp_value			= "available_rtr_credits",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_ATTR_MIN_RTR_CREDITS] = {
			.lkp_value			= "min_rtr_credits",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_ATTR_REFCOUNT]	= {
			.lkp_value			= "refcount",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_ATTR_STATS_COUNT]	= {
			.lkp_value			= "statistics",
			.lkp_key_format			= LNKF_MAPPING,
			.lkp_data_type			= NLA_NESTED
		},
		[LNET_PEER_NI_LIST_ATTR_SENT_STATS]	= {
			.lkp_value			= "sent_stats",
			.lkp_key_format			= LNKF_MAPPING,
			.lkp_data_type			= NLA_NESTED
		},
		[LNET_PEER_NI_LIST_ATTR_RECV_STATS]	= {
			.lkp_value			= "received_stats",
			.lkp_key_format			= LNKF_MAPPING,
			.lkp_data_type			= NLA_NESTED
		},
		[LNET_PEER_NI_LIST_ATTR_DROP_STATS]	= {
			.lkp_value			= "dropped_stats",
			.lkp_key_format			= LNKF_MAPPING,
			.lkp_data_type			= NLA_NESTED
		},
		[LNET_PEER_NI_LIST_ATTR_HEALTH_STATS]	= {
			.lkp_value			= "health stats",
			.lkp_key_format			= LNKF_MAPPING,
			.lkp_data_type			= NLA_NESTED
		},
	},
};

static const struct ln_key_list lnet_peer_ni_list_stats_count = {
	.lkl_maxattr			= LNET_PEER_NI_LIST_STATS_COUNT_ATTR_MAX,
	.lkl_list			= {
		[LNET_PEER_NI_LIST_STATS_COUNT_ATTR_SEND_COUNT]	= {
			.lkp_value				= "send_count",
			.lkp_data_type				= NLA_U32,
		},
		[LNET_PEER_NI_LIST_STATS_COUNT_ATTR_RECV_COUNT]	= {
			.lkp_value				= "recv_count",
			.lkp_data_type				= NLA_U32,
		},
		[LNET_PEER_NI_LIST_STATS_COUNT_ATTR_DROP_COUNT]	= {
			.lkp_value				= "drop_count",
			.lkp_data_type				= NLA_U32,
		},
	},
};

static const struct ln_key_list lnet_peer_ni_list_stats = {
	.lkl_maxattr			= LNET_PEER_NI_LIST_STATS_ATTR_MAX,
	.lkl_list			= {
		[LNET_PEER_NI_LIST_STATS_ATTR_PUT]	= {
			.lkp_value			= "put",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_STATS_ATTR_GET]	= {
			.lkp_value			= "get",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_STATS_ATTR_REPLY]	= {
			.lkp_value			= "reply",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_STATS_ATTR_ACK]	= {
			.lkp_value			= "ack",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_STATS_ATTR_HELLO]	= {
			.lkp_value			= "hello",
			.lkp_data_type			= NLA_U32,
		},
	},
};

static const struct ln_key_list lnet_peer_ni_list_health = {
	.lkl_maxattr			= LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_MAX,
	.lkl_list			= {
		[LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_VALUE]	= {
			.lkp_value			= "health value",
			.lkp_data_type			= NLA_S32,
		},
		[LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_DROPPED]	= {
			.lkp_value			= "dropped",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_TIMEOUT]	= {
			.lkp_value			= "timeout",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_ERROR]	= {
			.lkp_value			= "error",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_NETWORK_TIMEOUT] = {
			.lkp_value			= "network timeout",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_PING_COUNT] = {
			.lkp_value			= "ping_count",
			.lkp_data_type			= NLA_U32,
		},
		[LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_NEXT_PING]	= {
			.lkp_value			= "next_ping",
			.lkp_data_type			= NLA_S64,
		},
	},
};

static int lnet_peer_ni_show_dump(struct sk_buff *msg,
				  struct netlink_callback *cb)
{
	struct lnet_genl_processid_list *plist = lnet_peer_dump_ctx(cb);
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx = plist->lgpl_index;
	int msg_len = genlmsg_len(gnlh);
	int rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (!plist->lgpl_count) {
		NL_SET_ERR_MSG(extack, "No peers found");
		GOTO(send_error, rc = msg_len ? -ENOENT : 0);
	}

	if (!idx) {
		const struct ln_key_list *all[] = {
			&lnet_peer_ni_keys, &lnet_peer_ni_list,
			&udsp_info_list, &udsp_info_pref_nids_list,
			&udsp_info_pref_nids_list,
			&lnet_peer_ni_list_stats_count,
			&lnet_peer_ni_list_stats, /* send_stats */
			&lnet_peer_ni_list_stats, /* recv_stats */
			&lnet_peer_ni_list_stats, /* drop stats */
			&lnet_peer_ni_list_health,
			NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lnet_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_CMD_PEERS, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_error, rc);
		}
	}

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		NL_SET_ERR_MSG(extack, "Network is down");
		GOTO(unlock_api_mutex, rc = -ENETDOWN);
	}

	while (idx < plist->lgpl_count) {
		struct lnet_processid *id;
		struct lnet_peer_ni *lpni = NULL;
		struct nlattr *nid_list;
		struct lnet_peer *lp;
		int count = 1;
		void *hdr;

		id = genradix_ptr(&plist->lgpl_list, idx++);
		if (nid_is_lo0(&id->nid))
			continue;

		hdr = genlmsg_put(msg, portid, seq, &lnet_family,
				  NLM_F_MULTI, LNET_CMD_PEERS);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			genlmsg_cancel(msg, hdr);
			GOTO(unlock_api_mutex, rc = -EMSGSIZE);
		}

		lp = lnet_find_peer(&id->nid);
		if (!lp) {
			NL_SET_ERR_MSG(extack, "cannot find peer");
			GOTO(unlock_api_mutex, rc = -ENOENT);
		}

		if (idx == 1)
			nla_put_string(msg, LNET_PEER_NI_ATTR_HDR, "");

		nla_put_string(msg, LNET_PEER_NI_ATTR_PRIMARY_NID,
			       libcfs_nidstr(&lp->lp_primary_nid));
		if (lnet_peer_is_multi_rail(lp))
			nla_put_flag(msg, LNET_PEER_NI_ATTR_MULTIRAIL);

		if (gnlh->version >= 3)
			nla_put_u32(msg, LNET_PEER_NI_ATTR_STATE, lp->lp_state);

		nid_list = nla_nest_start(msg, LNET_PEER_NI_ATTR_PEER_NI_LIST);
		while ((lpni = lnet_get_next_peer_ni_locked(lp, NULL, lpni)) != NULL) {
			struct nlattr *peer_nid = nla_nest_start(msg, count++);

			nla_put_string(msg, LNET_PEER_NI_LIST_ATTR_NID,
				       libcfs_nidstr(&lpni->lpni_nid));

			if (gnlh->version >= 4) {
				rc = lnet_udsp_info_send(msg,
							 LNET_PEER_NI_LIST_ATTR_UDSP_INFO,
							 &lpni->lpni_nid, true);
				if (rc < 0) {
					lnet_peer_decref_locked(lp);
					NL_SET_ERR_MSG(extack,
						       "failed to get UDSP info");
					GOTO(unlock_api_mutex, rc);
				}
			}

			if (cb->nlh->nlmsg_flags & NLM_F_DUMP_FILTERED)
				goto skip_state;

			if (lnet_isrouter(lpni) ||
			    lnet_peer_aliveness_enabled(lpni)) {
				nla_put_string(msg, LNET_PEER_NI_LIST_ATTR_STATE,
					       lnet_is_peer_ni_alive(lpni) ?
					       "up" : "down");
			} else {
				nla_put_string(msg, LNET_PEER_NI_LIST_ATTR_STATE,
					       "NA");
			}
skip_state:
			if (gnlh->version) {
				struct lnet_ioctl_element_msg_stats lpni_msg_stats;
				struct nlattr *send_stats_list, *send_stats;
				struct nlattr *recv_stats_list, *recv_stats;
				struct nlattr *drop_stats_list, *drop_stats;
				struct nlattr *health_list, *health_stats;
				struct lnet_ioctl_element_stats stats;
				struct nlattr *stats_attr, *ni_stats;

				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_ATTR_MAX_TX_CREDITS,
					    lpni->lpni_net ?
						lpni->lpni_net->net_tunables.lct_peer_tx_credits : 0);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_ATTR_CUR_TX_CREDITS,
					    lpni->lpni_txcredits);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_ATTR_MIN_TX_CREDITS,
					    lpni->lpni_mintxcredits);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_ATTR_QUEUE_BUF_COUNT,
					    lpni->lpni_txqnob);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_ATTR_CUR_RTR_CREDITS,
					    lpni->lpni_rtrcredits);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_ATTR_MIN_RTR_CREDITS,
					    lpni->lpni_minrtrcredits);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_ATTR_REFCOUNT,
					    kref_read(&lpni->lpni_kref));

				memset(&stats, 0, sizeof(stats));
				stats.iel_send_count = lnet_sum_stats(&lpni->lpni_stats,
								      LNET_STATS_TYPE_SEND);
				stats.iel_recv_count = lnet_sum_stats(&lpni->lpni_stats,
								      LNET_STATS_TYPE_RECV);
				stats.iel_drop_count = lnet_sum_stats(&lpni->lpni_stats,
								      LNET_STATS_TYPE_DROP);

				stats_attr = nla_nest_start(msg,
							    LNET_PEER_NI_LIST_ATTR_STATS_COUNT);
				ni_stats = nla_nest_start(msg, 0);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_COUNT_ATTR_SEND_COUNT,
					    stats.iel_send_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_COUNT_ATTR_RECV_COUNT,
					    stats.iel_recv_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_COUNT_ATTR_DROP_COUNT,
					    stats.iel_drop_count);
				nla_nest_end(msg, ni_stats);
				nla_nest_end(msg, stats_attr);

				if (gnlh->version < 2)
					goto skip_msg_stats;

				lnet_usr_translate_stats(&lpni_msg_stats, &lpni->lpni_stats);

				send_stats_list = nla_nest_start(msg,
								 LNET_PEER_NI_LIST_ATTR_SENT_STATS);
				send_stats = nla_nest_start(msg, 0);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_PUT,
					    lpni_msg_stats.im_send_stats.ico_put_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_GET,
					    lpni_msg_stats.im_send_stats.ico_get_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_REPLY,
					    lpni_msg_stats.im_send_stats.ico_reply_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_ACK,
					    lpni_msg_stats.im_send_stats.ico_ack_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_HELLO,
					    lpni_msg_stats.im_send_stats.ico_hello_count);
				nla_nest_end(msg, send_stats);
				nla_nest_end(msg, send_stats_list);

				recv_stats_list = nla_nest_start(msg,
								 LNET_PEER_NI_LIST_ATTR_RECV_STATS);
				recv_stats = nla_nest_start(msg, 0);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_PUT,
					    lpni_msg_stats.im_recv_stats.ico_put_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_GET,
					    lpni_msg_stats.im_recv_stats.ico_get_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_REPLY,
					    lpni_msg_stats.im_recv_stats.ico_reply_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_ACK,
					    lpni_msg_stats.im_recv_stats.ico_ack_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_HELLO,
					    lpni_msg_stats.im_recv_stats.ico_hello_count);
				nla_nest_end(msg, recv_stats);
				nla_nest_end(msg, recv_stats_list);

				drop_stats_list = nla_nest_start(msg,
								 LNET_PEER_NI_LIST_ATTR_DROP_STATS);
				drop_stats = nla_nest_start(msg, 0);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_PUT,
					    lpni_msg_stats.im_drop_stats.ico_put_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_GET,
					    lpni_msg_stats.im_drop_stats.ico_get_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_REPLY,
					    lpni_msg_stats.im_drop_stats.ico_reply_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_ACK,
					    lpni_msg_stats.im_drop_stats.ico_ack_count);
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_STATS_ATTR_HELLO,
					    lpni_msg_stats.im_drop_stats.ico_hello_count);
				nla_nest_end(msg, drop_stats);
				nla_nest_end(msg, drop_stats_list);

				health_list = nla_nest_start(msg,
							     LNET_PEER_NI_LIST_ATTR_HEALTH_STATS);
				health_stats = nla_nest_start(msg, 0);
				nla_put_s32(msg,
					    LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_VALUE,
					    atomic_read(&lpni->lpni_healthv));
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_DROPPED,
					    atomic_read(&lpni->lpni_hstats.hlt_remote_dropped));
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_TIMEOUT,
					    atomic_read(&lpni->lpni_hstats.hlt_remote_timeout));
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_ERROR,
					    atomic_read(&lpni->lpni_hstats.hlt_remote_error));
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_NETWORK_TIMEOUT,
					    atomic_read(&lpni->lpni_hstats.hlt_network_timeout));
				nla_put_u32(msg,
					    LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_PING_COUNT,
					    lpni->lpni_ping_count);
				nla_put_s64(msg,
					    LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_NEXT_PING,
					    lpni->lpni_next_ping,
					    LNET_PEER_NI_LIST_HEALTH_STATS_ATTR_PAD);
				nla_nest_end(msg, health_stats);
				nla_nest_end(msg, health_list);
			}
skip_msg_stats:
			nla_nest_end(msg, peer_nid);
		}
		nla_nest_end(msg, nid_list);

		genlmsg_end(msg, hdr);
		lnet_peer_decref_locked(lp);
	}
	plist->lgpl_index = idx;
unlock_api_mutex:
	mutex_unlock(&the_lnet.ln_api_mutex);
send_error:
	return lnet_nl_send_error(cb->skb, portid, seq, rc);
};

#ifndef HAVE_NETLINK_CALLBACK_START
static int lnet_old_peer_ni_show_dump(struct sk_buff *msg,
				      struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lnet_peer_ni_show_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lnet_peer_ni_show_dump(msg, cb);
}
#endif

static int lnet_route_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *params = genlmsg_data(gnlh);
	int msg_len, rem, rc = 0;
	struct nlattr *attr;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		GENL_SET_ERR_MSG(info, "Network is down");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENETDOWN;
	}

	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		GENL_SET_ERR_MSG(info, "no configuration");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENOMSG;
	}

	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		GENL_SET_ERR_MSG(info, "invalid configuration");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -EINVAL;
	}

	nla_for_each_nested(attr, params, rem) {
		u32 net_id = LNET_NET_ANY, hops = LNET_UNDEFINED_HOPS;
		u32 priority = 0, sensitivity = 1;
		struct lnet_nid gw_nid = LNET_ANY_NID;
		struct nlattr *route_prop;
		bool alive = true;
		s64 when = 0;
		int rem2;

		if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
			continue;

		nla_for_each_nested(route_prop, attr, rem2) {
			char tmp[LNET_NIDSTR_SIZE];
			ssize_t len;
			s64 num;

			if (nla_type(route_prop) != LN_SCALAR_ATTR_VALUE)
				continue;

			if (nla_strcmp(route_prop, "net") == 0) {
				route_prop = nla_next(route_prop, &rem2);
				if (nla_type(route_prop) !=
				    LN_SCALAR_ATTR_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "net is invalid key");
					GOTO(report_err, rc = -EINVAL);
				}

				len = nla_strscpy(tmp, route_prop, sizeof(tmp));
				if (len < 0) {
					GENL_SET_ERR_MSG(info,
							 "net key string is invalid");
					GOTO(report_err, rc = len);
				}

				net_id = libcfs_str2net(tmp);
				if (!net_id) {
					GENL_SET_ERR_MSG(info,
							 "cannot parse remote net");
					GOTO(report_err, rc = -ENODEV);
				}

				if (LNET_NETTYP(net_id) == LOLND) {
					GENL_SET_ERR_MSG(info,
							 "setting @lo not allowed");
					GOTO(report_err, rc = -EACCES);
				}

				if (net_id == LNET_NET_ANY) {
					GENL_SET_ERR_MSG(info,
							 "setting LNET_NET_ANY not allowed");
					GOTO(report_err, rc = -ENXIO);
				}
			} else if (nla_strcmp(route_prop, "gateway") == 0) {
				route_prop = nla_next(route_prop, &rem2);
				if (nla_type(route_prop) !=
				    LN_SCALAR_ATTR_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "gateway is invalid key");
					GOTO(report_err, rc = -EINVAL);
				}

				len = nla_strscpy(tmp, route_prop, sizeof(tmp));
				if (len < 0) {
					GENL_SET_ERR_MSG(info,
							 "gateway string is invalid");
					GOTO(report_err, rc = len);
				}

				rc = libcfs_strnid(&gw_nid, strim(tmp));
				if (rc < 0) {
					GENL_SET_ERR_MSG(info,
							 "cannot parse gateway");
					GOTO(report_err, rc = -ENODEV);
				}
			} else if (nla_strcmp(route_prop, "state") == 0) {
				route_prop = nla_next(route_prop, &rem2);
				if (nla_type(route_prop) !=
				    LN_SCALAR_ATTR_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "state is invalid key");
					GOTO(report_err, rc = -EINVAL);
				}

				if (nla_strcmp(route_prop, "down") == 0) {
					alive = false;
				} else if (nla_strcmp(route_prop, "up") == 0) {
					alive = true;
				} else {
					GENL_SET_ERR_MSG(info,
							 "status string bad value");
					GOTO(report_err, rc = -EINVAL);
				}
			} else if (nla_strcmp(route_prop, "notify_time") == 0) {
				route_prop = nla_next(route_prop, &rem2);
				if (nla_type(route_prop) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "notify_time is invalid key");
					GOTO(report_err, rc = -EINVAL);
				}

				when = nla_get_s64(route_prop);
				if (ktime_get_real_seconds() < when) {
					GENL_SET_ERR_MSG(info,
							 "notify_time is in the future");
					GOTO(report_err, rc = -EINVAL);
				}
			} else if (nla_strcmp(route_prop, "hop") == 0) {
				route_prop = nla_next(route_prop, &rem2);
				if (nla_type(route_prop) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "hop has invalid key");
					GOTO(report_err, rc = -EINVAL);
				}

				hops = nla_get_s64(route_prop);
				if ((hops < 1 || hops > 255) && hops != -1) {
					GENL_SET_ERR_MSG(info,
							 "invalid hop count must be between 1 and 255");
					GOTO(report_err, rc = -EINVAL);
				}
			} else if (nla_strcmp(route_prop, "priority") == 0) {
				route_prop = nla_next(route_prop, &rem2);
				if (nla_type(route_prop) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "priority has invalid key");
					GOTO(report_err, rc = -EINVAL);
				}

				num = nla_get_s64(route_prop);
				if (num < 0) {
					GENL_SET_ERR_MSG(info,
							 "invalid priority, must not be negative");
					GOTO(report_err, rc = -EINVAL);
				}
				priority = num;
			} else if (nla_strcmp(route_prop,
					      "health_sensitivity") == 0) {
				route_prop = nla_next(route_prop, &rem2);
				if (nla_type(route_prop) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "sensitivity has invalid key");
					GOTO(report_err, rc = -EINVAL);
				}

				num = nla_get_s64(route_prop);
				if (num < 1) {
					GENL_SET_ERR_MSG(info,
							 "invalid health sensitivity, must be 1 or greater");
					GOTO(report_err, rc = -EINVAL);
				}
				sensitivity = num;
			}
		}

		if (net_id == LNET_NET_ANY) {
			GENL_SET_ERR_MSG(info,
					 "missing mandatory parameter: network");
			GOTO(report_err, rc = -ENODEV);
		}

		if (LNET_NID_IS_ANY(&gw_nid)) {
			GENL_SET_ERR_MSG(info,
					 "missing mandatory parameter: gateway");
			GOTO(report_err, rc = -ENODEV);
		}

		if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE) {
			/* Convert the user-supplied real time to monotonic.
			 * NB: "when" is always in the past
			 */
			when = ktime_get_seconds() -
				(ktime_get_real_seconds() - when);

			mutex_unlock(&the_lnet.ln_api_mutex);
			rc = lnet_notify(NULL, &gw_nid, alive, false, when);
			mutex_lock(&the_lnet.ln_api_mutex);
			if (rc < 0)
				GOTO(report_err, rc);
			else if (the_lnet.ln_state != LNET_STATE_RUNNING)
				GOTO(report_err, rc = -ENETDOWN);
		} else if (info->nlhdr->nlmsg_flags & NLM_F_CREATE) {
			rc = lnet_add_route(net_id, hops, &gw_nid, priority,
					    sensitivity);
			if (rc < 0) {
				switch (rc) {
				case -EINVAL:
					GENL_SET_ERR_MSG(info,
							 "invalid settings for route creation");
					break;
				case -EHOSTUNREACH:
					GENL_SET_ERR_MSG(info,
							 "No interface configured on the same net as gateway");
					break;
				case -ESHUTDOWN:
					GENL_SET_ERR_MSG(info,
							 "Network is down");
					break;
				case -EEXIST:
					GENL_SET_ERR_MSG(info,
							 "Route already exists or the specified network is local");
					break;
				default:
					GENL_SET_ERR_MSG(info,
							 "failed to create route");
					break;
				}
				GOTO(report_err, rc);
			}
		} else if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE)) {
			rc = lnet_del_route(net_id, &gw_nid);
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "failed to delete route");
				GOTO(report_err, rc);
			}
		}
	}
report_err:
	mutex_unlock(&the_lnet.ln_api_mutex);

	return rc;
}

static inline struct lnet_genl_ping_list *
lnet_ping_dump_ctx(struct netlink_callback *cb)
{
	return (struct lnet_genl_ping_list *)cb->args[0];
}

static int lnet_ping_show_done(struct netlink_callback *cb)
{
	struct lnet_genl_ping_list *plist = lnet_ping_dump_ctx(cb);

	if (plist) {
		genradix_free(&plist->lgpl_failed);
		genradix_free(&plist->lgpl_list);
		LIBCFS_FREE(plist, sizeof(*plist));
		cb->args[0] = 0;
	}

	return 0;
}

/* LNet ping ->start() handler for GET requests */
static int lnet_ping_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	struct lnet_genl_ping_list *plist;
	int msg_len = genlmsg_len(gnlh);
	struct nlattr *params, *top;
	int rem, rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (the_lnet.ln_refcount == 0) {
		NL_SET_ERR_MSG(extack, "Network is down");
		return -ENETDOWN;
	}

	if (!msg_len) {
		NL_SET_ERR_MSG(extack, "Ping needs NID targets");
		return -ENOENT;
	}

	LIBCFS_ALLOC(plist, sizeof(*plist));
	if (!plist) {
		NL_SET_ERR_MSG(extack, "failed to setup ping list");
		return -ENOMEM;
	}
	genradix_init(&plist->lgpl_list);
	plist->lgpl_timeout = cfs_time_seconds(DEFAULT_PEER_TIMEOUT);
	plist->lgpl_src_nid = LNET_ANY_NID;
	plist->lgpl_index = 0;
	plist->lgpl_list_count = 0;
	cb->args[0] = (long)plist;

	params = genlmsg_data(gnlh);
	nla_for_each_attr(top, params, msg_len, rem) {
		struct nlattr *nids;
		int rem2;

		switch (nla_type(top)) {
		case LN_SCALAR_ATTR_VALUE:
			if (nla_strcmp(top, "timeout") == 0) {
				s64 timeout;

				top = nla_next(top, &rem);
				if (nla_type(top) != LN_SCALAR_ATTR_INT_VALUE) {
					NL_SET_ERR_MSG(extack,
						       "invalid timeout param");
					GOTO(report_err, rc = -EINVAL);
				}

				/* If timeout is negative then set default of
				 * 3 minutes
				 */
				timeout = nla_get_s64(top);
				if (timeout > 0 &&
				    timeout < (DEFAULT_PEER_TIMEOUT * MSEC_PER_SEC))
					plist->lgpl_timeout =
						nsecs_to_jiffies(timeout * NSEC_PER_MSEC);
			} else if (nla_strcmp(top, "source") == 0) {
				char nidstr[LNET_NIDSTR_SIZE + 1];

				top = nla_next(top, &rem);
				if (nla_type(top) != LN_SCALAR_ATTR_VALUE) {
					NL_SET_ERR_MSG(extack,
						       "invalid source param");
					GOTO(report_err, rc = -EINVAL);
				}

				rc = nla_strscpy(nidstr, top, sizeof(nidstr));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "failed to parse source nid");
					GOTO(report_err, rc);
				}

				rc = libcfs_strnid(&plist->lgpl_src_nid,
						   strim(nidstr));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "invalid source nid");
					GOTO(report_err, rc);
				}
				rc = 0;
			}
			break;
		case LN_SCALAR_ATTR_LIST:
			nla_for_each_nested(nids, top, rem2) {
				char nid[LNET_NIDSTR_SIZE + 1];
				struct lnet_processid *id;

				if (nla_type(nids) != LN_SCALAR_ATTR_VALUE)
					continue;

				memset(nid, 0, sizeof(nid));
				rc = nla_strscpy(nid, nids, sizeof(nid));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "failed to get NID");
					GOTO(report_err, rc);
				}

				id = genradix_ptr_alloc(&plist->lgpl_list,
							plist->lgpl_list_count++,
							GFP_KERNEL);
				if (!id) {
					NL_SET_ERR_MSG(extack,
						       "failed to allocate NID");
					GOTO(report_err, rc = -ENOMEM);
				}

				rc = libcfs_strid(id, strim(nid));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack, "cannot parse NID");
					GOTO(report_err, rc);
				}
				rc = 0;
			}
			fallthrough;
		default:
			break;
		}
	}
report_err:
	if (rc < 0)
		lnet_ping_show_done(cb);

	return rc;
}

static const struct ln_key_list ping_err_props_list = {
	.lkl_maxattr			= LNET_ERR_ATTR_MAX,
	.lkl_list			= {
		[LNET_ERR_ATTR_HDR]		= {
			.lkp_value		= "manage",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_ERR_ATTR_TYPE]		= {
			.lkp_value		= "ping",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_ERR_ATTR_ERRNO]		= {
			.lkp_value		= "errno",
			.lkp_data_type		= NLA_S16,
		},
		[LNET_ERR_ATTR_DESCR]		= {
			.lkp_value		= "descr",
			.lkp_data_type		= NLA_STRING,
		},
	},
};

static const struct ln_key_list ping_props_list = {
	.lkl_maxattr			= LNET_PING_ATTR_MAX,
	.lkl_list			= {
		[LNET_PING_ATTR_HDR]            = {
			.lkp_value              = "ping",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_PING_ATTR_PRIMARY_NID]	= {
			.lkp_value		= "primary nid",
			.lkp_data_type          = NLA_STRING
		},
		[LNET_PING_ATTR_ERRNO]		= {
			.lkp_value		= "errno",
			.lkp_data_type		= NLA_S16
		},
		[LNET_PING_ATTR_MULTIRAIL]	= {
			.lkp_value              = "Multi-Rail",
			.lkp_data_type          = NLA_FLAG
		},
		[LNET_PING_ATTR_PEER_NI_LIST]	= {
			.lkp_value		= "peer_ni",
			.lkp_key_format         = LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type          = NLA_NESTED
		},
	},
};

static const struct ln_key_list ping_peer_ni_list = {
	.lkl_maxattr			= LNET_PING_PEER_NI_ATTR_MAX,
	.lkl_list                       = {
		[LNET_PING_PEER_NI_ATTR_NID]	= {
			.lkp_value		= "nid",
			.lkp_data_type		= NLA_STRING
		},
	},
};

static int lnet_ping_show_dump(struct sk_buff *msg,
			       struct netlink_callback *cb)
{
	struct lnet_genl_ping_list *plist = lnet_ping_dump_ctx(cb);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx = plist->lgpl_index;
	int rc = 0, i = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (!plist->lgpl_index) {
		const struct ln_key_list *all[] = {
			&ping_props_list, &ping_peer_ni_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lnet_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_CMD_PING, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_error, rc);
		}

		genradix_init(&plist->lgpl_failed);
	}

	while (idx < plist->lgpl_list_count) {
		struct lnet_nid primary_nid = LNET_ANY_NID;
		struct lnet_genl_ping_list peers;
		struct lnet_processid *id;
		struct nlattr *nid_list;
		struct lnet_peer *lp;
		bool mr_flag = false;
		unsigned int count;
		void *hdr = NULL;

		id = genradix_ptr(&plist->lgpl_list, idx++);

		rc = lnet_ping(id, &plist->lgpl_src_nid, plist->lgpl_timeout,
			       &peers, lnet_interfaces_max);
		if (rc < 0) {
			struct lnet_fail_ping *fail;

			fail = genradix_ptr_alloc(&plist->lgpl_failed,
						  plist->lgpl_failed_count++,
						  GFP_KERNEL);
			if (!fail) {
				NL_SET_ERR_MSG(extack,
					       "failed to allocate failed NID");
				GOTO(send_error, rc);
			}
			memset(fail->lfp_msg, '\0', sizeof(fail->lfp_msg));
			snprintf(fail->lfp_msg, sizeof(fail->lfp_msg),
				 "failed to ping %s",
				 libcfs_nidstr(&id->nid));
			fail->lfp_id = *id;
			fail->lfp_errno = rc;
			goto cant_reach;
		}

		mutex_lock(&the_lnet.ln_api_mutex);
		lp = lnet_find_peer(&id->nid);
		if (lp) {
			primary_nid = lp->lp_primary_nid;
			mr_flag = lnet_peer_is_multi_rail(lp);
			lnet_peer_decref_locked(lp);
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		hdr = genlmsg_put(msg, portid, seq, &lnet_family,
				  NLM_F_MULTI, LNET_CMD_PING);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			genlmsg_cancel(msg, hdr);
			GOTO(send_error, rc = -EMSGSIZE);
		}

		if (i++ == 0)
			nla_put_string(msg, LNET_PING_ATTR_HDR, "");

		nla_put_string(msg, LNET_PING_ATTR_PRIMARY_NID,
			       libcfs_nidstr(&primary_nid));
		if (mr_flag)
			nla_put_flag(msg, LNET_PING_ATTR_MULTIRAIL);

		nid_list = nla_nest_start(msg, LNET_PING_ATTR_PEER_NI_LIST);
		for (count = 0; count < rc; count++) {
			struct lnet_processid *result;
			struct nlattr *nid_attr;
			char *idstr;

			result = genradix_ptr(&peers.lgpl_list, count);
			if (nid_is_lo0(&result->nid))
				continue;

			nid_attr = nla_nest_start(msg, count + 1);
			if (id->pid == LNET_PID_LUSTRE)
				idstr = libcfs_nidstr(&result->nid);
			else
				idstr = libcfs_idstr(result);
			nla_put_string(msg, LNET_PING_PEER_NI_ATTR_NID, idstr);
			nla_nest_end(msg, nid_attr);
		}
		nla_nest_end(msg, nid_list);
		genlmsg_end(msg, hdr);
cant_reach:
		genradix_free(&peers.lgpl_list);
	}

	if (plist->lgpl_failed_count) {
		int flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_MULTI;
		const struct ln_key_list *fail[] = {
			&ping_err_props_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq, &lnet_family,
						flags, LNET_CMD_PING, fail);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack,
				       "failed to send new key table");
			GOTO(send_error, rc);
		}

		for (i = 0; i < plist->lgpl_failed_count; i++) {
			struct lnet_fail_ping *fail;
			void *hdr;

			fail = genradix_ptr(&plist->lgpl_failed, i);

			hdr = genlmsg_put(msg, portid, seq, &lnet_family,
					  NLM_F_MULTI, LNET_CMD_PING);
			if (!hdr) {
				NL_SET_ERR_MSG(extack,
					       "failed to send failed values");
				genlmsg_cancel(msg, hdr);
				GOTO(send_error, rc = -EMSGSIZE);
			}

			if (i == 0)
				nla_put_string(msg, LNET_ERR_ATTR_HDR, "");

			nla_put_string(msg, LNET_ERR_ATTR_TYPE, "\n");
			nla_put_s16(msg, LNET_ERR_ATTR_ERRNO,
				    fail->lfp_errno);
			nla_put_string(msg, LNET_ERR_ATTR_DESCR,
				       fail->lfp_msg);
			genlmsg_end(msg, hdr);
		}
	}
	genradix_free(&plist->lgpl_list);
	rc = 0; /* don't treat it as an error */

	plist->lgpl_index = idx;
send_error:
	return lnet_nl_send_error(cb->skb, portid, seq, rc);
}

#ifndef HAVE_NETLINK_CALLBACK_START
static int lnet_old_ping_show_dump(struct sk_buff *msg,
				   struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lnet_ping_show_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lnet_ping_show_dump(msg, cb);
}
#endif

static const struct ln_key_list discover_err_props_list = {
	.lkl_maxattr			= LNET_ERR_ATTR_MAX,
	.lkl_list			= {
		[LNET_ERR_ATTR_HDR]		= {
			.lkp_value		= "manage",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_ERR_ATTR_TYPE]		= {
			.lkp_value		= "discover",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_ERR_ATTR_ERRNO]		= {
			.lkp_value		= "errno",
			.lkp_data_type		= NLA_S16,
		},
		[LNET_ERR_ATTR_DESCR]		= {
			.lkp_value		= "descr",
			.lkp_data_type		= NLA_STRING,
		},
	},
};

static const struct ln_key_list discover_props_list = {
	.lkl_maxattr			= LNET_PING_ATTR_MAX,
	.lkl_list			= {
		[LNET_PING_ATTR_HDR]            = {
			.lkp_value              = "discover",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_PING_ATTR_PRIMARY_NID]	= {
			.lkp_value		= "primary nid",
			.lkp_data_type          = NLA_STRING
		},
		[LNET_PING_ATTR_ERRNO]		= {
			.lkp_value		= "errno",
			.lkp_data_type		= NLA_S16
		},
		[LNET_PING_ATTR_MULTIRAIL]	= {
			.lkp_value              = "Multi-Rail",
			.lkp_data_type          = NLA_FLAG
		},
		[LNET_PING_ATTR_PEER_NI_LIST]	= {
			.lkp_value		= "peer_ni",
			.lkp_key_format         = LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type          = NLA_NESTED
		},
	},
};

static int lnet_ping_cmd(struct sk_buff *skb, struct genl_info *info)
{
	const struct ln_key_list *all[] = {
		&discover_props_list, &ping_peer_ni_list, NULL
	};
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *params = genlmsg_data(gnlh);
	struct lnet_genl_ping_list dlists;
	int msg_len, rem, rc = 0, i;
	bool clear_hdr = false;
	struct sk_buff *reply;
	struct nlattr *attr;
	void *hdr = NULL;

	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		GENL_SET_ERR_MSG(info, "no configuration");
		return -ENOMSG;
	}

	if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE)) {
		GENL_SET_ERR_MSG(info, "only NLM_F_CREATE setting is allowed");
		return -EINVAL;
	}

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!reply) {
		GENL_SET_ERR_MSG(info,
				 "fail to allocate reply");
		return -ENOMEM;
	}

	genradix_init(&dlists.lgpl_failed);
	dlists.lgpl_failed_count = 0;
	genradix_init(&dlists.lgpl_list);
	dlists.lgpl_list_count = 0;

	rc = lnet_genl_send_scalar_list(reply, info->snd_portid,
					info->snd_seq, &lnet_family,
					NLM_F_CREATE | NLM_F_MULTI,
					LNET_CMD_PING, all);
	if (rc < 0) {
		GENL_SET_ERR_MSG(info,
				 "failed to send key table");
		GOTO(report_err, rc);
	}

	nla_for_each_attr(attr, params, msg_len, rem) {
		struct nlattr *nids;
		int rem2;

		/* We only care about the NID list to discover with */
		if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
			continue;

		nla_for_each_nested(nids, attr, rem2) {
			char nid[LNET_NIDSTR_SIZE + 1];
			struct lnet_processid id;
			struct nlattr *nid_list;
			struct lnet_peer *lp;
			ssize_t len;

			if (nla_type(nids) != LN_SCALAR_ATTR_VALUE)
				continue;

			memset(nid, 0, sizeof(nid));
			rc = nla_strscpy(nid, nids, sizeof(nid));
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "failed to get NID");
				GOTO(report_err, rc);
			}

			len = libcfs_strid(&id, strim(nid));
			if (len < 0) {
				struct lnet_fail_ping *fail;

				fail = genradix_ptr_alloc(&dlists.lgpl_failed,
							  dlists.lgpl_failed_count++,
							  GFP_KERNEL);
				if (!fail) {
					GENL_SET_ERR_MSG(info,
							 "failed to allocate improper NID");
					GOTO(report_err, rc = -ENOMEM);
				}
				memset(fail->lfp_msg, '\0', sizeof(fail->lfp_msg));
				snprintf(fail->lfp_msg, sizeof(fail->lfp_msg),
					 "cannot parse NID '%s'", strim(nid));
				fail->lfp_id = id;
				fail->lfp_errno = len;
				continue;
			}

			if (LNET_NID_IS_ANY(&id.nid))
				continue;

			rc = lnet_discover(&id,
					   info->nlhdr->nlmsg_flags & NLM_F_EXCL,
					   &dlists);
			if (rc < 0) {
				struct lnet_fail_ping *fail;

				fail = genradix_ptr_alloc(&dlists.lgpl_failed,
							  dlists.lgpl_failed_count++,
							  GFP_KERNEL);
				if (!fail) {
					GENL_SET_ERR_MSG(info,
							 "failed to allocate failed NID");
					GOTO(report_err, rc = -ENOMEM);
				}
				memset(fail->lfp_msg, '\0', sizeof(fail->lfp_msg));
				snprintf(fail->lfp_msg, sizeof(fail->lfp_msg),
					 "failed to discover %s",
					 libcfs_nidstr(&id.nid));
				fail->lfp_id = id;
				fail->lfp_errno = rc;
				continue;
			}

			/* create the genetlink message header */
			hdr = genlmsg_put(reply, info->snd_portid, info->snd_seq,
					  &lnet_family, NLM_F_MULTI, LNET_CMD_PING);
			if (!hdr) {
				GENL_SET_ERR_MSG(info,
						 "failed to allocate hdr");
				GOTO(report_err, rc = -ENOMEM);
			}

			if (!clear_hdr) {
				nla_put_string(reply, LNET_PING_ATTR_HDR, "");
				clear_hdr = true;
			}

			lp = lnet_find_peer(&id.nid);
			if (lp) {
				nla_put_string(reply, LNET_PING_ATTR_PRIMARY_NID,
					       libcfs_nidstr(&lp->lp_primary_nid));
				if (lnet_peer_is_multi_rail(lp))
					nla_put_flag(reply, LNET_PING_ATTR_MULTIRAIL);
				lnet_peer_decref_locked(lp);
			}

			nid_list = nla_nest_start(reply, LNET_PING_ATTR_PEER_NI_LIST);
			for (i = 0; i < dlists.lgpl_list_count; i++) {
				struct lnet_processid *found;
				struct nlattr *nid_attr;
				char *idstr;

				found = genradix_ptr(&dlists.lgpl_list, i);
				if (nid_is_lo0(&found->nid))
					continue;

				nid_attr = nla_nest_start(reply, i + 1);
				if (id.pid == LNET_PID_LUSTRE)
					idstr = libcfs_nidstr(&found->nid);
				else
					idstr = libcfs_idstr(found);
				nla_put_string(reply, LNET_PING_PEER_NI_ATTR_NID, idstr);
				nla_nest_end(reply, nid_attr);
			}
			nla_nest_end(reply, nid_list);

			genlmsg_end(reply, hdr);
		}
	}

	if (dlists.lgpl_failed_count) {
		int flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_MULTI;
		const struct ln_key_list *fail[] = {
			&discover_err_props_list, NULL
		};

		rc = lnet_genl_send_scalar_list(reply, info->snd_portid,
						info->snd_seq, &lnet_family,
						flags, LNET_CMD_PING, fail);
		if (rc < 0) {
			GENL_SET_ERR_MSG(info,
					 "failed to send new key table");
			GOTO(report_err, rc);
		}

		for (i = 0; i < dlists.lgpl_failed_count; i++) {
			struct lnet_fail_ping *fail;

			hdr = genlmsg_put(reply, info->snd_portid, info->snd_seq,
					  &lnet_family, NLM_F_MULTI, LNET_CMD_PING);
			if (!hdr) {
				GENL_SET_ERR_MSG(info,
						 "failed to send failed values");
				GOTO(report_err, rc = -ENOMSG);
			}

			fail = genradix_ptr(&dlists.lgpl_failed, i);
			if (i == 0)
				nla_put_string(reply, LNET_ERR_ATTR_HDR, "");

			nla_put_string(reply, LNET_ERR_ATTR_TYPE, "\n");
			nla_put_s16(reply, LNET_ERR_ATTR_ERRNO,
				    fail->lfp_errno);
			nla_put_string(reply, LNET_ERR_ATTR_DESCR,
				       fail->lfp_msg);
			genlmsg_end(reply, hdr);
		}
	}

	nlh = nlmsg_put(reply, info->snd_portid, info->snd_seq, NLMSG_DONE, 0,
			NLM_F_MULTI);
	if (!nlh) {
		genlmsg_cancel(reply, hdr);
		GENL_SET_ERR_MSG(info,
				 "failed to finish message");
		GOTO(report_err, rc = -EMSGSIZE);
	}

report_err:
	genradix_free(&dlists.lgpl_failed);
	genradix_free(&dlists.lgpl_list);

	if (rc < 0) {
		genlmsg_cancel(reply, hdr);
		nlmsg_free(reply);
	} else {
		rc = genlmsg_reply(reply, info);
	}

	return rc;
}

#define lnet_peer_dist_show_done	lnet_peer_ni_show_done

static int lnet_peer_dist_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	struct lnet_genl_processid_list *plist;
	int msg_len = genlmsg_len(gnlh);
	struct nlattr *params, *top;
	int rem, rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		NL_SET_ERR_MSG(extack, "Network is down");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENETDOWN;
	}

	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		NL_SET_ERR_MSG(extack, "Missing NID argument(s)");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENOENT;
	}

	CFS_ALLOC_PTR(plist);
	if (!plist) {
		NL_SET_ERR_MSG(extack, "No memory for peer NID list");
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ENOMEM;
	}

	genradix_init(&plist->lgpl_list);
	plist->lgpl_count = 0;
	plist->lgpl_index = 0;
	cb->args[0] = (long)plist;

	params = genlmsg_data(gnlh);
	nla_for_each_attr(top, params, msg_len, rem) {
		struct nlattr *nids;
		int rem2;

		if (nla_type(top) != LN_SCALAR_ATTR_LIST)
			continue;

		nla_for_each_nested(nids, top, rem2) {
			char nidstr[LNET_NIDSTR_SIZE + 1];
			struct lnet_processid *id;

			if (nla_type(nids) != LN_SCALAR_ATTR_VALUE)
				continue;

			memset(nidstr, 0, sizeof(nidstr));
			rc = nla_strscpy(nidstr, nids, sizeof(nidstr));
			if (rc < 0) {
				NL_SET_ERR_MSG(extack,
					       "failed to get NID");
				GOTO(report_err, rc);
			}

			id = genradix_ptr_alloc(&plist->lgpl_list,
						plist->lgpl_count++,
						GFP_KERNEL);
			if (!id) {
				NL_SET_ERR_MSG(extack, "failed to allocate NID");
				GOTO(report_err, rc = -ENOMEM);
			}

			rc = libcfs_strid(id, strim(nidstr));
			if (rc < 0) {
				NL_SET_ERR_MSG(extack, "invalid NID");
				GOTO(report_err, rc);
			}
			rc = 0;
		}
	}
report_err:
	mutex_unlock(&the_lnet.ln_api_mutex);

	if (rc < 0)
		lnet_peer_dist_show_done(cb);

	return rc;
}

static const struct ln_key_list peer_dist_props_list = {
	.lkl_maxattr			= LNET_PEER_DIST_ATTR_MAX,
	.lkl_list			= {
		[LNET_PEER_DIST_ATTR_HDR]	= {
			.lkp_value		= "peer",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_PEER_DIST_ATTR_NID]	= {
			.lkp_value		= "nid",
			.lkp_data_type          = NLA_STRING
		},
		[LNET_PEER_DIST_ATTR_DIST]	= {
			.lkp_value		= "distance",
			.lkp_data_type		= NLA_U32
		},
		[LNET_PEER_DIST_ATTR_ORDER]	= {
			.lkp_value		= "order",
			.lkp_data_type		= NLA_U32
		},
	},
};

static int lnet_peer_dist_show_dump(struct sk_buff *msg,
				    struct netlink_callback *cb)
{
	struct lnet_genl_processid_list *plist = lnet_peer_dump_ctx(cb);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx = plist->lgpl_index;
	int rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (!idx) {
		const struct ln_key_list *all[] = {
			&peer_dist_props_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lnet_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_CMD_PEER_DIST, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_error, rc);
		}
	}

	while (idx < plist->lgpl_count) {
		struct lnet_processid *id;
		void *hdr;
		u32 order;
		int dist;

		id = genradix_ptr(&plist->lgpl_list, idx++);
		if (nid_is_lo0(&id->nid))
			continue;

		dist = LNetDist(&id->nid, &id->nid, &order);
		if (dist < 0) {
			if (dist == -EHOSTUNREACH)
				continue;

			rc = dist;
			return rc;
		}

		hdr = genlmsg_put(msg, portid, seq, &lnet_family,
				  NLM_F_MULTI, LNET_CMD_PEER_DIST);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			genlmsg_cancel(msg, hdr);
			GOTO(send_error, rc = -EMSGSIZE);
		}

		if (idx == 1)
			nla_put_string(msg, LNET_PEER_DIST_ATTR_HDR, "");

		nla_put_string(msg, LNET_PEER_DIST_ATTR_NID,
			       libcfs_nidstr(&id->nid));
		nla_put_u32(msg, LNET_PEER_DIST_ATTR_DIST, dist);
		nla_put_u32(msg, LNET_PEER_DIST_ATTR_ORDER, order);

		genlmsg_end(msg, hdr);
	}

	plist->lgpl_index = idx;
send_error:
	return lnet_nl_send_error(cb->skb, portid, seq, rc);
}

#ifndef HAVE_NETLINK_CALLBACK_START
static int lnet_old_peer_dist_show_dump(struct sk_buff *msg,
					struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lnet_peer_dist_show_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lnet_peer_dist_show_dump(msg, cb);
}
#endif

static int lnet_peer_fail_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *params = genlmsg_data(gnlh);
	struct netlink_ext_ack *extack = NULL;
	int msg_len, rem, rc = 0;
	struct nlattr *attr;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = info->extack;
#endif
	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		GENL_SET_ERR_MSG(info, "no configuration");
		return -ENOMSG;
	}

	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		GENL_SET_ERR_MSG(info, "invalid configuration");
		return -EINVAL;
	}

	nla_for_each_nested(attr, params, rem) {
		s64 threshold = LNET_MD_THRESH_INF;
		struct lnet_nid pnid = {};
		struct nlattr *peer;
		int rem2;

		if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
			continue;

		nla_for_each_nested(peer, attr, rem2) {
			if (nla_type(peer) != LN_SCALAR_ATTR_VALUE)
				continue;

			if (nla_strcmp(peer, "nid") == 0) {
				char nidstr[LNET_NIDSTR_SIZE];

				rc = nla_extract_val(&peer, &rem2,
						     LN_SCALAR_ATTR_VALUE,
						     nidstr, sizeof(nidstr),
						     extack);
				if (rc < 0)
					GOTO(report_err, rc);

				rc = libcfs_strnid(&pnid, strim(nidstr));
				if (rc < 0) {
					GENL_SET_ERR_MSG(info,
							 "invalid peer NID");
					GOTO(report_err, rc);
				}
				rc = 0;
			} else if (nla_strcmp(peer, "threshold") == 0) {
				rc = nla_extract_val(&peer, &rem2,
						     LN_SCALAR_ATTR_INT_VALUE,
						     &threshold, sizeof(threshold),
						     extack);
				if (rc < 0) {
					GOTO(report_err, rc);
				}
			}
		}

		if (!nid_addr_is_set(&pnid)) {
			GENL_SET_ERR_MSG(info, "peer NID missing");
			GOTO(report_err, rc);
		}

		rc = lnet_fail_nid(&pnid, threshold);
		if (rc < 0) {
			GENL_SET_ERR_MSG(info,
					 "could not set threshoold for peer NID");
			GOTO(report_err, rc);
		}
	}
report_err:
	return rc;
}

struct lnet_genl_debug_recovery_list {
	unsigned int			lgdrl_index;
	unsigned int			lgdrl_count;
	unsigned int			lgdrl_len;
	struct ln_key_list		*lgdrl_keys;
	enum lnet_health_type		lgdrl_type;
	GENRADIX(struct lnet_nid)	lgdrl_nids;
};

static inline struct lnet_genl_debug_recovery_list *
lnet_debug_recovery_dump_ctx(struct netlink_callback *cb)
{
	return (struct lnet_genl_debug_recovery_list *)cb->args[0];
}

static int lnet_debug_recovery_show_done(struct netlink_callback *cb)
{
	struct lnet_genl_debug_recovery_list *drlist;

	ENTRY;
	drlist = lnet_debug_recovery_dump_ctx(cb);
	if (drlist) {
		if (drlist->lgdrl_keys) {
			int i;

			for (i = 1; i < drlist->lgdrl_count; i++) {
				int idx = i + LNET_DBG_RECOV_ATTR_MAX;
				struct ln_key_props *props;

				props = &drlist->lgdrl_keys->lkl_list[idx];
				kfree(props->lkp_value);
			}
			LIBCFS_FREE(drlist->lgdrl_keys,
				    drlist->lgdrl_len);
		}
		genradix_free(&drlist->lgdrl_nids);
		CFS_FREE_PTR(drlist);
	}

	cb->args[0] = 0;

	RETURN(0);
}

static int lnet_debug_recovery_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
	struct netlink_ext_ack *extack = NULL;
	struct nlattr *params;
	struct nlattr *entry;
	struct lnet_genl_debug_recovery_list *drlist;
	enum lnet_health_type type = -1;
	struct lnet_nid *nid;
	int rem, rc = 0;
	int msg_len;

	ENTRY;
#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		NL_SET_ERR_MSG(extack, "No configuration");
		RETURN(-ENOMSG);
	}

	params = genlmsg_data(gnlh);
	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		NL_SET_ERR_MSG(extack, "invalid configuration");
		RETURN(-EINVAL);
	}

	nla_for_each_attr(entry, params, msg_len, rem) {
		s64 tmp;

		if (nla_type(entry) != LN_SCALAR_ATTR_VALUE ||
		    nla_strcmp(entry, "queue_type") != 0)
			continue;

		rc = nla_extract_val(&entry, &rem, LN_SCALAR_ATTR_INT_VALUE,
				     (void *)&tmp, sizeof(tmp),
				     extack);
		if (rc < 0)
			GOTO(report_error, rc);
		type = tmp;
	}
	CDEBUG(D_NET, "Got queue_type: %d\n", type);

	CFS_ALLOC_PTR(drlist);
	if (!drlist) {
		NL_SET_ERR_MSG(extack, "No memory for recovery list");
		RETURN(-ENOMEM);
	}

	genradix_init(&drlist->lgdrl_nids);
	drlist->lgdrl_index = 0;
	drlist->lgdrl_count = 0;
	drlist->lgdrl_type = type;
	cb->args[0] = (long)drlist;

	rc = -ENOENT;
	lnet_net_lock(LNET_LOCK_EX);
	if (type == LNET_HEALTH_TYPE_LOCAL_NI) {
		struct lnet_ni *ni;

		list_for_each_entry(ni, &the_lnet.ln_mt_localNIRecovq,
				    ni_recovery) {
			CDEBUG(D_NET, "nid: %s\n", libcfs_nidstr(&ni->ni_nid));
			nid = genradix_ptr_alloc(&drlist->lgdrl_nids,
						 drlist->lgdrl_count++,
						 GFP_ATOMIC);
			if (!nid)
				GOTO(report_error_unlock, rc = -ENOMEM);

			*nid = ni->ni_nid;
			rc = 0;
		}
	} else if (type == LNET_HEALTH_TYPE_PEER_NI) {
		struct lnet_peer_ni *lpni;

		list_for_each_entry(lpni, &the_lnet.ln_mt_peerNIRecovq,
				    lpni_recovery) {
			CDEBUG(D_NET, "nid: %s\n",
			       libcfs_nidstr(&lpni->lpni_nid));
			nid = genradix_ptr_alloc(&drlist->lgdrl_nids,
						 drlist->lgdrl_count++,
						 GFP_ATOMIC);
			if (!nid)
				GOTO(report_error_unlock, rc = -ENOMEM);

			*nid = lpni->lpni_nid;
			rc = 0;
		}
	}
report_error_unlock:
	lnet_net_unlock(LNET_LOCK_EX);
report_error:
	if (rc < 0)
		lnet_debug_recovery_show_done(cb);

	RETURN(rc);
}

static const struct ln_key_list debug_recovery_attr_list = {
	.lkl_maxattr			= LNET_DBG_RECOV_ATTR_MAX,
	.lkl_list			= {
		[LNET_DBG_RECOV_ATTR_HDR]	= {
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_DBG_RECOV_ATTR_NID]	= {
			.lkp_value		= "nid-0",
			.lkp_data_type		= NLA_STRING,
		},
	},
};

static int lnet_debug_recovery_show_dump(struct sk_buff *msg,
					 struct netlink_callback *cb)
{
	struct lnet_genl_debug_recovery_list *drlist;
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int rc = 0;
	void *hdr;
	int idx;

	ENTRY;
#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	drlist = lnet_debug_recovery_dump_ctx(cb);
	if (!drlist->lgdrl_count) {
		NL_SET_ERR_MSG(extack, "No NIDs in recovery");
		GOTO(send_error, rc = -ENOENT);
	}

	idx = drlist->lgdrl_index;
	if (!idx) {
		unsigned int count = debug_recovery_attr_list.lkl_maxattr;
		const struct ln_key_list *all[] = { NULL, NULL };
		size_t len = sizeof(struct ln_key_list);
		struct ln_key_list *keys;
		int i;

		count += drlist->lgdrl_count - 1;
		len += sizeof(struct ln_key_props) * count;
		LIBCFS_ALLOC(keys, len);
		if (!keys) {
			NL_SET_ERR_MSG(extack,
				       "key list allocation failure");
			GOTO(send_error, rc = -ENOMEM);
		}
		/* Set initial values */
		*keys = debug_recovery_attr_list;
		if (drlist->lgdrl_type == LNET_HEALTH_TYPE_LOCAL_NI) {
			keys->lkl_list[LNET_DBG_RECOV_ATTR_HDR].lkp_value =
				"Local NI recovery";
		} else {
			keys->lkl_list[LNET_DBG_RECOV_ATTR_HDR].lkp_value =
				"Peer NI recovery";
		}
		keys->lkl_maxattr = count;

		for (i = 1; i < drlist->lgdrl_count; i++) {
			keys->lkl_list[LNET_DBG_RECOV_ATTR_MAX + i].lkp_data_type =
				NLA_STRING;
			keys->lkl_list[LNET_DBG_RECOV_ATTR_MAX + i].lkp_value =
				kasprintf(GFP_ATOMIC, "nid-%u", i);
		}
		/* memory cleaned up is done in lnet_debug_recovery_show_done */
		drlist->lgdrl_keys = keys;
		drlist->lgdrl_len = len;

		all[0] = keys;
		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lnet_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_CMD_DBG_RECOV, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_error, rc);
		}
	}

	hdr = genlmsg_put(msg, portid, seq, &lnet_family,
			  NLM_F_MULTI, LNET_CMD_DBG_RECOV);
	if (!hdr) {
		NL_SET_ERR_MSG(extack, "failed to send values");
		genlmsg_cancel(msg, hdr);
		GOTO(send_error, rc = -EMSGSIZE);
	}

	while (idx < drlist->lgdrl_count) {
		struct lnet_nid *nid;

		if (idx == 1)
			nla_put_string(msg, LNET_DBG_RECOV_ATTR_HDR, "");

		nid = genradix_ptr(&drlist->lgdrl_nids, idx++);
		CDEBUG(D_NET, "nid: %s\n", libcfs_nidstr(nid));
		nla_put_string(msg, LNET_DBG_RECOV_ATTR_NID + idx - 1,
			       libcfs_nidstr(nid));
	}
	genlmsg_end(msg, hdr);

	drlist->lgdrl_index = idx;
send_error:
	RETURN(lnet_nl_send_error(cb->skb, portid, seq, rc));
}

#ifndef HAVE_NETLINK_CALLBACK_START
static int lnet_old_debug_recovery_show_dump(struct sk_buff *msg,
					     struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lnet_debug_recovery_show_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lnet_debug_recovery_show_dump(msg, cb);
}
#endif

static inline struct lnet_genl_fault_rule_list *
lnet_fault_dump_ctx(struct netlink_callback *cb)
{
	return (struct lnet_genl_fault_rule_list *)cb->args[0];
}

static int lnet_fault_show_done(struct netlink_callback *cb)
{
	struct lnet_genl_fault_rule_list *rlist = lnet_fault_dump_ctx(cb);

	ENTRY;
	if (rlist) {
		genradix_free(&rlist->lgfrl_list);
		CFS_FREE_PTR(rlist);
	}
	cb->args[0] = 0;

	RETURN(0);
}

static int lnet_fault_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
	struct netlink_ext_ack *extack = NULL;
	struct nlattr *params = genlmsg_data(gnlh);
	struct lnet_genl_fault_rule_list *rlist;
	int msg_len, rem, rc = 0;
	struct nlattr *entry;
	s64 opc = 0;

	ENTRY;
#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		NL_SET_ERR_MSG(extack, "no configuration");
		RETURN(-ENOMSG);
	}

	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		NL_SET_ERR_MSG(extack, "invalid configuration");
		RETURN(-EINVAL);
	}

	nla_for_each_attr(entry, params, msg_len, rem) {
		if (nla_type(entry) != LN_SCALAR_ATTR_VALUE)
			continue;

		if (nla_strcmp(entry, "rule_type") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     (void *)&opc, sizeof(opc), extack);
			if (rc < 0)
				GOTO(report_error, rc);
		}
	}

	CDEBUG(D_NET, "Got opc %lld\n", opc);

	if (opc != LNET_CTL_DROP_LIST && opc != LNET_CTL_DELAY_LIST) {
		NL_SET_ERR_MSG(extack, "invalid operation");
		GOTO(report_error, rc = -EINVAL);
	}

	CFS_ALLOC_PTR(rlist);
	if (!rlist) {
		NL_SET_ERR_MSG(extack, "No memory for rule list");
		RETURN(-ENOMEM);
	}

	genradix_init(&rlist->lgfrl_list);
	rlist->lgfrl_count = 0;
	rlist->lgfrl_index = 0;
	rlist->lgfrl_opc = opc;
	cb->args[0] = (long)rlist;

	rc = -ENOENT;
	if (opc == LNET_CTL_DROP_LIST)
		rc = lnet_drop_rule_collect(rlist);
	else if (opc == LNET_CTL_DELAY_LIST)
		rc = lnet_delay_rule_collect(rlist);
report_error:
	if (rc < 0)
		lnet_fault_show_done(cb);

	RETURN(rc);
}

static const struct ln_key_list fault_attr_list = {
	.lkl_maxattr			= LNET_FAULT_ATTR_MAX,
	.lkl_list			= {
		[LNET_FAULT_ATTR_HDR]		= {
			.lkp_value		= "fault",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_FAULT_ATTR_FA_TYPE]	= {
			.lkp_value		= "rule_type",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_FAULT_ATTR_FA_SRC]	= {
			.lkp_value		= "fa_src",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_FAULT_ATTR_FA_DST]	= {
			.lkp_value		= "fa_dst",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_FAULT_ATTR_FA_PTL_MASK]	= {
			.lkp_value		= "fa_ptl_mask",
			.lkp_data_type		= NLA_U64
		},
		[LNET_FAULT_ATTR_FA_MSG_MASK]	= {
			.lkp_value		= "fa_msg_mask",
			.lkp_data_type		= NLA_U32
		},
		[LNET_FAULT_ATTR_DA_RATE]	= {
			.lkp_value		= "da_rate",
			.lkp_data_type		= NLA_U32
		},
		[LNET_FAULT_ATTR_DA_INTERVAL]	= {
			.lkp_value		= "da_interval",
			.lkp_data_type		= NLA_U32
		},
		[LNET_FAULT_ATTR_DS_DROPPED]	= {
			.lkp_value		= "ds_dropped",
			.lkp_data_type		= NLA_U64
		},
		[LNET_FAULT_ATTR_LA_RATE]	= {
			.lkp_value		= "la_rate",
			.lkp_data_type		= NLA_U32
		},
		[LNET_FAULT_ATTR_LA_INTERVAL]	= {
			.lkp_value		= "la_interval",
			.lkp_data_type		= NLA_U32
		},
		[LNET_FAULT_ATTR_LA_LATENCY]	= {
			.lkp_value		= "la_latency",
			.lkp_data_type		= NLA_U32
		},
		[LNET_FAULT_ATTR_LS_DELAYED]	= {
			.lkp_value		= "ls_delayed",
			.lkp_data_type		= NLA_U64
		},
		[LNET_FAULT_ATTR_FS_COUNT]	= {
			.lkp_value		= "fs_count",
			.lkp_data_type		= NLA_U64
		},
		[LNET_FAULT_ATTR_FS_PUT]	= {
			.lkp_value		= "fs_put",
			.lkp_data_type		= NLA_U64
		},
		[LNET_FAULT_ATTR_FS_ACK]	= {
			.lkp_value		= "fs_ack",
			.lkp_data_type		= NLA_U64
		},
		[LNET_FAULT_ATTR_FS_GET]	= {
			.lkp_value		= "fs_get",
			.lkp_data_type		= NLA_U64
		},
		[LNET_FAULT_ATTR_FS_REPLY]	= {
			.lkp_value		= "fs_reply",
			.lkp_data_type		= NLA_U64
		},
	},
};

static int lnet_fault_show_dump(struct sk_buff *msg,
				struct netlink_callback *cb)
{
	struct lnet_genl_fault_rule_list *rlist = lnet_fault_dump_ctx(cb);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx, rc = 0;
	u32 opc;

	ENTRY;
#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (!rlist->lgfrl_count) {
		NL_SET_ERR_MSG(extack, "No routes found");
		GOTO(send_error, rc = -ENOENT);
	}

	idx = rlist->lgfrl_index;
	if (!idx) {
		const struct ln_key_list *all[] = {
			&fault_attr_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lnet_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_CMD_FAULT, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_error, rc);
		}
	}
	opc = rlist->lgfrl_opc;

	while (idx < rlist->lgfrl_count) {
		struct lnet_rule_properties *prop;
		void *hdr;

		prop = genradix_ptr(&rlist->lgfrl_list, idx++);

		hdr = genlmsg_put(msg, portid, seq, &lnet_family,
				  NLM_F_MULTI, LNET_CMD_FAULT);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			genlmsg_cancel(msg, hdr);
			GOTO(send_error, rc = -EMSGSIZE);
		}

		if (idx == 1)
			nla_put_string(msg, LNET_FAULT_ATTR_HDR, "");

		nla_put_string(msg, LNET_FAULT_ATTR_FA_TYPE,
			       opc == LNET_CTL_DROP_LIST ? "drop" : "delay");

		nla_put_string(msg, LNET_FAULT_ATTR_FA_SRC,
			       libcfs_nidstr(&prop->attr.fa_src));
		nla_put_string(msg, LNET_FAULT_ATTR_FA_DST,
			       libcfs_nidstr(&prop->attr.fa_dst));

		nla_put_u64_64bit(msg, LNET_FAULT_ATTR_FA_PTL_MASK,
				  prop->attr.fa_ptl_mask,
				  LNET_FAULT_ATTR_PAD);
		nla_put_u32(msg, LNET_FAULT_ATTR_FA_MSG_MASK,
			    prop->attr.fa_msg_mask);

		if (opc == LNET_CTL_DROP_LIST) {
			nla_put_u32(msg, LNET_FAULT_ATTR_DA_RATE,
				    prop->attr.u.drop.da_rate);
			nla_put_u32(msg, LNET_FAULT_ATTR_DA_INTERVAL,
				    prop->attr.u.drop.da_interval);
			nla_put_u64_64bit(msg, LNET_FAULT_ATTR_DS_DROPPED,
					  prop->stat.u.drop.ds_dropped,
					  LNET_FAULT_ATTR_PAD);
		} else if (opc == LNET_CTL_DELAY_LIST) {
			nla_put_u32(msg, LNET_FAULT_ATTR_LA_RATE,
				    prop->attr.u.delay.la_rate);
			nla_put_u32(msg, LNET_FAULT_ATTR_LA_INTERVAL,
				    prop->attr.u.delay.la_interval);
			nla_put_u32(msg, LNET_FAULT_ATTR_LA_LATENCY,
				    prop->attr.u.delay.la_latency);
			nla_put_u64_64bit(msg, LNET_FAULT_ATTR_LS_DELAYED,
					  prop->stat.u.delay.ls_delayed,
					  LNET_FAULT_ATTR_PAD);
		}
		nla_put_u64_64bit(msg, LNET_FAULT_ATTR_FS_COUNT,
				  prop->stat.fs_count,
				  LNET_FAULT_ATTR_PAD);
		nla_put_u64_64bit(msg, LNET_FAULT_ATTR_FS_PUT,
				  prop->stat.fs_put,
				  LNET_FAULT_ATTR_PAD);
		nla_put_u64_64bit(msg, LNET_FAULT_ATTR_FS_ACK,
				  prop->stat.fs_ack,
				  LNET_FAULT_ATTR_PAD);
		nla_put_u64_64bit(msg, LNET_FAULT_ATTR_FS_GET,
				  prop->stat.fs_get,
				  LNET_FAULT_ATTR_PAD);
		nla_put_u64_64bit(msg, LNET_FAULT_ATTR_FS_REPLY,
				  prop->stat.fs_reply,
				  LNET_FAULT_ATTR_PAD);
		genlmsg_end(msg, hdr);
	}
	rlist->lgfrl_index = idx;
send_error:
	return lnet_nl_send_error(cb->skb, portid, seq, rc);
}

#ifndef HAVE_NETLINK_CALLBACK_START
int lnet_old_fault_show_dump(struct sk_buff *msg, struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lnet_fault_show_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lnet_fault_show_dump(msg, cb);
}
#endif

static int lnet_fault_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *params = genlmsg_data(gnlh);
	struct netlink_ext_ack *extack = NULL;
	struct lnet_fault_large_attr fattr;
	int msg_len, rem, rc = 0;
	struct nlattr *entry;
	s64 opc = 0;

	ENTRY;
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	extack = info->extack;
#endif
	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		GENL_SET_ERR_MSG(info, "no configuration");
		RETURN(-ENOMSG);
	}

	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		GENL_SET_ERR_MSG(info, "invalid configuration");
		RETURN(-EINVAL);
	}

	fattr.fa_src = LNET_ANY_NID;
	fattr.fa_dst = LNET_ANY_NID;

	nla_for_each_attr(entry, params, msg_len, rem) {
		u64 tmp;

		CDEBUG(D_NET, "attr type: %d\n", nla_type(entry));
		if (nla_type(entry) != LN_SCALAR_ATTR_VALUE)
			continue;

		if (nla_strcmp(entry, "rule_type") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &opc, sizeof(opc), extack);
			if (rc < 0)
				GOTO(report_error, rc);
		} else if (nla_strcmp(entry, "fa_src") == 0) {
			rc = nla_strnid(&entry, &fattr.fa_src, &rem, extack);
			if (rc < 0)
				GOTO(report_error, rc);
		} else if (nla_strcmp(entry, "fa_dst") == 0) {
			rc = nla_strnid(&entry, &fattr.fa_dst, &rem, extack);
			if (rc < 0)
				GOTO(report_error, rc);
		} else if (nla_strcmp(entry, "fa_local_nid") == 0) {
			rc = nla_strnid(&entry, &fattr.fa_local_nid, &rem,
					extack);
			if (rc < 0)
				GOTO(report_error, rc);
		} else if (nla_strcmp(entry, "fa_ptl_mask") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.fa_ptl_mask = tmp;
		} else if (nla_strcmp(entry, "fa_msg_mask") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.fa_msg_mask = tmp;
		} else if (nla_strcmp(entry, "da_rate") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.u.drop.da_rate = tmp;
		} else if (nla_strcmp(entry, "da_interval") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.u.drop.da_interval = tmp;
		} else if (nla_strcmp(entry, "da_health_error_mask") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.u.drop.da_health_error_mask = tmp;
		} else if (nla_strcmp(entry, "da_random") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.u.drop.da_random = !!tmp;
		} else if (nla_strcmp(entry, "da_drop_all") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.u.drop.da_drop_all = !!tmp;
		} else if (nla_strcmp(entry, "la_rate") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.u.delay.la_rate = tmp;
		} else if (nla_strcmp(entry, "la_interval") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.u.delay.la_interval = tmp;
		} else if (nla_strcmp(entry, "la_latency") == 0) {
			rc = nla_extract_val(&entry, &rem,
					     LN_SCALAR_ATTR_INT_VALUE,
					     &tmp, sizeof(tmp), extack);
			if (rc < 0)
				GOTO(report_error, rc);

			fattr.u.delay.la_latency = tmp;
		}
	}

	if (info->nlhdr->nlmsg_flags & NLM_F_CREATE) {
		if (opc == LNET_CTL_DROP_ADD)
			rc = lnet_drop_rule_add(&fattr);
		else
			rc = lnet_delay_rule_add(&fattr);
	} else if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE) {
		if (opc == LNET_CTL_DROP_RESET)
			lnet_drop_rule_reset();
		else
			lnet_delay_rule_reset();
	} else if (!(info->nlhdr->nlmsg_flags & (NLM_F_CREATE | NLM_F_REPLACE))) {
		if (opc == LNET_CTL_DROP_DEL)
			rc = lnet_drop_rule_del(&fattr.fa_src, &fattr.fa_dst);
		else
			rc = lnet_delay_rule_del(&fattr.fa_src, &fattr.fa_dst,
						 false);
		if (rc == 0)
			rc = -ENOENT;
		else
			rc = 0;
	}
report_error:
	RETURN(rc);
}

static const struct genl_multicast_group lnet_mcast_grps[] = {
	{ .name	=	"ip2net",	},
	{ .name =	"net",		},
	{ .name =	"peer",		},
	{ .name	=	"route",	},
	{ .name	=	"ping",		},
	{ .name =	"discover",	},
	{ .name =	"cpt-of-nid",	},
	{ .name =	"dbg-recov",	},
	{ .name =	"fault",	},
};

static const struct genl_ops lnet_genl_ops[] = {
	{
		.cmd		= LNET_CMD_CONFIGURE,
		.flags		= GENL_ADMIN_PERM,
		.doit		= lnet_net_conf_cmd,
	},
	{
		.cmd		= LNET_CMD_NETS,
		.flags		= GENL_ADMIN_PERM,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lnet_net_show_start,
		.dumpit		= lnet_net_show_dump,
#else
		.dumpit		= lnet_old_net_show_dump,
#endif
		.done		= lnet_net_show_done,
		.doit		= lnet_net_cmd,
	},
	{
		.cmd		= LNET_CMD_PEERS,
		.flags		= GENL_ADMIN_PERM,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lnet_peer_ni_show_start,
		.dumpit		= lnet_peer_ni_show_dump,
#else
		.dumpit		= lnet_old_peer_ni_show_dump,
#endif
		.done		= lnet_peer_ni_show_done,
		.doit		= lnet_peer_ni_cmd,
	},
	{
		.cmd		= LNET_CMD_ROUTES,
		.flags		= GENL_ADMIN_PERM,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lnet_route_show_start,
		.dumpit		= lnet_route_show_dump,
#else
		.dumpit		= lnet_old_route_show_dump,
#endif
		.done		= lnet_route_show_done,
		.doit		= lnet_route_cmd,
	},
	{
		.cmd		= LNET_CMD_PING,
		.flags		= GENL_ADMIN_PERM,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lnet_ping_show_start,
		.dumpit		= lnet_ping_show_dump,
#else
		.dumpit		= lnet_old_ping_show_dump,
#endif
		.done		= lnet_ping_show_done,
		.doit		= lnet_ping_cmd,
	},
	{
		.cmd		= LNET_CMD_CPT_OF_NID,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lnet_cpt_of_nid_show_start,
		.dumpit		= lnet_cpt_of_nid_show_dump,
#else
		.dumpit		= lnet_old_cpt_of_nid_show_dump,
#endif
		.done		= lnet_cpt_of_nid_show_done,
	},
	{
		.cmd		= LNET_CMD_PEER_DIST,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lnet_peer_dist_show_start,
		.dumpit		= lnet_peer_dist_show_dump,
#else
		.dumpit		= lnet_old_peer_dist_show_dump,
#endif
		.done		= lnet_peer_dist_show_done,
	},
	{
		.cmd		= LNET_CMD_PEER_FAIL,
		.flags		= GENL_ADMIN_PERM,
		.doit		= lnet_peer_fail_cmd,
	},
	{
		.cmd		= LNET_CMD_DBG_RECOV,
		.flags		= GENL_ADMIN_PERM,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lnet_debug_recovery_show_start,
		.dumpit		= lnet_debug_recovery_show_dump,
#else
		.dumpit		= lnet_old_debug_recovery_show_dump,
#endif
		.done		= lnet_debug_recovery_show_done,
	},
	{
		.cmd		= LNET_CMD_FAULT,
		.flags		= GENL_ADMIN_PERM,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lnet_fault_show_start,
		.dumpit		= lnet_fault_show_dump,
#else
		.dumpit		= lnet_old_fault_show_dump,
#endif
		.done		= lnet_fault_show_done,
		.doit		= lnet_fault_cmd,
	},
};

static struct genl_family lnet_family = {
	.name		= LNET_GENL_NAME,
	.version	= LNET_GENL_VERSION,
	.module		= THIS_MODULE,
	.parallel_ops	= true,
	.netnsok	= true,
	.ops		= lnet_genl_ops,
	.n_ops		= ARRAY_SIZE(lnet_genl_ops),
	.mcgrps		= lnet_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(lnet_mcast_grps),
#ifdef GENL_FAMILY_HAS_RESV_START_OP
	.resv_start_op	= __LNET_CMD_MAX_PLUS_ONE,
#endif
};

void LNetDebugPeer(struct lnet_processid *id)
{
	lnet_debug_peer(&id->nid);
}
EXPORT_SYMBOL(LNetDebugPeer);

/**
 * Determine if the specified peer \a nid is on the local node.
 *
 * \param nid	peer nid to check
 *
 * \retval true		If peer NID is on the local node.
 * \retval false	If peer NID is not on the local node.
 */
bool LNetIsPeerLocal(struct lnet_nid *nid)
{
	struct lnet_net *net;
	struct lnet_ni *ni;
	int cpt;

	cpt = lnet_net_lock_current();
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (nid_same(&ni->ni_nid, nid)) {
				lnet_net_unlock(cpt);
				return true;
			}
		}
	}
	lnet_net_unlock(cpt);

	return false;
}
EXPORT_SYMBOL(LNetIsPeerLocal);

/**
 * Retrieve the struct lnet_process_id ID of LNet interface at \a index.
 * Note that all interfaces share a same PID, as requested by LNetNIInit().
 *
 * @index	Index of the interface to look up.
 * @id		On successful return, this location will hold the
 *		struct lnet_process_id ID of the interface.
 * @large_nids	Report large NIDs if this is true.
 *
 * RETURN	0 If an interface exists at \a index.
 *		-ENOENT If no interface has been found.
 */
int
LNetGetId(unsigned int index, struct lnet_processid *id, bool large_nids)
{
	struct lnet_ni	 *ni;
	struct lnet_net  *net;
	int		  cpt;
	int		  rc = -ENOENT;

	LASSERT(the_lnet.ln_refcount > 0);

	cpt = lnet_net_lock_current();

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (!large_nids && !nid_is_nid4(&ni->ni_nid))
				continue;

			if (index-- != 0)
				continue;

			id->nid = ni->ni_nid;
			id->pid = the_lnet.ln_pid;
			rc = 0;
			break;
		}
	}

	lnet_net_unlock(cpt);
	return rc;
}
EXPORT_SYMBOL(LNetGetId);

struct ping_data {
	int rc;
	int replied;
	int pd_unlinked;
	struct lnet_handle_md mdh;
	struct completion completion;
};

static void
lnet_ping_event_handler(struct lnet_event *event)
{
	struct ping_data *pd = event->md_user_ptr;

	CDEBUG(D_NET, "ping event (%d %d)%s\n",
	       event->type, event->status,
	       event->unlinked ? " unlinked" : "");

	if (event->status) {
		if (!pd->rc)
			pd->rc = event->status;
	} else if (event->type == LNET_EVENT_REPLY) {
		pd->replied = 1;
		pd->rc = event->mlength;
	}

	if (event->unlinked)
		pd->pd_unlinked = 1;

	if (event->unlinked ||
	    (event->type == LNET_EVENT_SEND && event->status))
		complete(&pd->completion);
}

/* Max buffer we allow to be sent. Larger values will cause IB failures */
#define LNET_PING_BUFFER_MAX	3960

static int lnet_ping(struct lnet_processid *id, struct lnet_nid *src_nid,
		     signed long timeout, struct lnet_genl_ping_list *plist,
		     int n_ids)
{
	int id_bytes = sizeof(struct lnet_ni_status); /* For 0@lo */
	struct lnet_md md = { NULL };
	struct ping_data pd = { 0 };
	struct lnet_ping_buffer *pbuf;
	struct lnet_processid pid;
	struct lnet_ping_iter pi;
	int i = 0;
	u32 *st;
	int nob;
	int rc;
	int rc2;

	genradix_init(&plist->lgpl_list);

	/* n_ids limit is arbitrary */
	if (n_ids <= 0 || LNET_NID_IS_ANY(&id->nid))
		return -EINVAL;

	/* if the user buffer has more space than the lnet_interfaces_max
	 * then only fill it up to lnet_interfaces_max
	 */
	if (n_ids > lnet_interfaces_max)
		n_ids = lnet_interfaces_max;

	if (id->pid == LNET_PID_ANY)
		id->pid = LNET_PID_LUSTRE;

	/* Allocate maximum possible NID size */
	id_bytes += lnet_ping_sts_size(&LNET_ANY_NID) * n_ids;
	if (id_bytes > LNET_PING_BUFFER_MAX)
		id_bytes = LNET_PING_BUFFER_MAX;

	pbuf = lnet_ping_buffer_alloc(id_bytes, GFP_NOFS);
	if (!pbuf)
		return -ENOMEM;

	/* initialize md content */
	md.start     = &pbuf->pb_info;
	md.length    = id_bytes;
	md.threshold = 2; /* GET/REPLY */
	md.max_size  = 0;
	md.options   = LNET_MD_TRUNCATE;
	md.user_ptr  = &pd;
	md.handler   = lnet_ping_event_handler;

	init_completion(&pd.completion);

	rc = LNetMDBind(&md, LNET_UNLINK, &pd.mdh);
	if (rc != 0) {
		CERROR("Can't bind MD: %d\n", rc);
		goto fail_ping_buffer_decref;
	}

	rc = LNetGet(src_nid, pd.mdh, id, LNET_RESERVED_PORTAL,
		     LNET_PROTO_PING_MATCHBITS, 0, false);
	if (rc != 0) {
		/* Don't CERROR; this could be deliberate! */
		rc2 = LNetMDUnlink(pd.mdh);
		LASSERT(rc2 == 0);

		/* NB must wait for the UNLINK event below... */
	}

	/* Ensure completion in finite time... */
	wait_for_completion_timeout(&pd.completion, timeout);
	if (!pd.pd_unlinked) {
		LNetMDUnlink(pd.mdh);
		wait_for_completion(&pd.completion);
	}

	if (!pd.replied) {
		rc = pd.rc ?: -EIO;
		goto fail_ping_buffer_decref;
	}

	nob = pd.rc;
	LASSERT(nob >= 0 && nob <= id_bytes);

	rc = -EPROTO;		/* if I can't parse... */

	if (nob < LNET_PING_INFO_HDR_SIZE) {
		CERROR("%s: ping info too short %d\n",
		       libcfs_idstr(id), nob);
		goto fail_ping_buffer_decref;
	}

	if (pbuf->pb_info.pi_magic == __swab32(LNET_PROTO_PING_MAGIC)) {
		lnet_swap_pinginfo(pbuf);
	} else if (pbuf->pb_info.pi_magic != LNET_PROTO_PING_MAGIC) {
		CERROR("%s: Unexpected magic %08x\n",
		       libcfs_idstr(id), pbuf->pb_info.pi_magic);
		goto fail_ping_buffer_decref;
	}

	if ((pbuf->pb_info.pi_features & LNET_PING_FEAT_NI_STATUS) == 0) {
		CERROR("%s: ping w/o NI status: 0x%x\n",
		       libcfs_idstr(id), pbuf->pb_info.pi_features);
		goto fail_ping_buffer_decref;
	}

	/* Test if smaller than lnet_pinginfo with just one pi_ni status info.
	 * That one might contain size when large nids are used.
	 */
	if (nob < offsetof(struct lnet_ping_info, pi_ni[1])) {
		CERROR("%s: Short reply %d(%lu min)\n",
		       libcfs_idstr(id), nob,
		       offsetof(struct lnet_ping_info, pi_ni[1]));
		goto fail_ping_buffer_decref;
	}

	if (ping_info_count_entries(pbuf) < n_ids) {
		n_ids = ping_info_count_entries(pbuf);
		id_bytes = lnet_ping_info_size(&pbuf->pb_info);
	}

	if (nob < id_bytes) {
		CERROR("%s: Short reply %d(%d expected)\n",
		       libcfs_idstr(id), nob, id_bytes);
		goto fail_ping_buffer_decref;
	}

	for (st = ping_iter_first(&pi, pbuf, &pid.nid);
	     st;
	     st = ping_iter_next(&pi, &pid.nid)) {
		id = genradix_ptr_alloc(&plist->lgpl_list, i++, GFP_KERNEL);
		if (!id) {
			rc = -ENOMEM;
			goto fail_ping_buffer_decref;
		}

		id->pid = pbuf->pb_info.pi_pid;
		id->nid = pid.nid;
	}
	rc = i;
fail_ping_buffer_decref:
	lnet_ping_buffer_decref(pbuf);
	return rc;
}

static int
lnet_discover(struct lnet_processid *pid, u32 force,
	      struct lnet_genl_ping_list *dlist)
{
	struct lnet_peer_ni *lpni;
	struct lnet_peer_ni *p;
	struct lnet_peer *lp;
	int cpt;
	int rc;

	if (LNET_NID_IS_ANY(&pid->nid))
		return -EINVAL;

	if (pid->pid == LNET_PID_ANY)
		pid->pid = LNET_PID_LUSTRE;

	cpt = lnet_net_lock_current();
	lpni = lnet_peerni_by_nid_locked(&pid->nid, NULL, cpt);
	if (IS_ERR(lpni)) {
		rc = PTR_ERR(lpni);
		goto out;
	}

	/*
	 * Clearing the NIDS_UPTODATE flag ensures the peer will
	 * be discovered, provided discovery has not been disabled.
	 */
	lp = lpni->lpni_peer_net->lpn_peer;
	spin_lock(&lp->lp_lock);
	lp->lp_state &= ~LNET_PEER_NIDS_UPTODATE;
	/* If the force flag is set, force a PING and PUSH as well. */
	if (force)
		lp->lp_state |= LNET_PEER_FORCE_PING | LNET_PEER_FORCE_PUSH;
	spin_unlock(&lp->lp_lock);
	rc = lnet_discover_peer_locked(lpni, cpt, true);
	if (rc)
		goto out_decref;

	/* The lpni (or lp) for this NID may have changed and our ref is
	 * the only thing keeping the old one around. Release the ref
	 * and lookup the lpni again
	 */
	lnet_peer_ni_decref_locked(lpni);
	lpni = lnet_peer_ni_find_locked(&pid->nid);
	if (!lpni) {
		rc = -ENOENT;
		goto out;
	}
	lp = lpni->lpni_peer_net->lpn_peer;

	dlist->lgpl_list_count = 0;
	p = NULL;
	while ((p = lnet_get_next_peer_ni_locked(lp, NULL, p)) != NULL) {
		struct lnet_processid *id;

		id = genradix_ptr_alloc(&dlist->lgpl_list,
					dlist->lgpl_list_count++, GFP_ATOMIC);
		if (!id) {
			rc = -ENOMEM;
			goto out_decref;
		}
		id->pid = pid->pid;
		id->nid = p->lpni_nid;
	}
	rc = dlist->lgpl_list_count;

out_decref:
	lnet_peer_ni_decref_locked(lpni);
out:
	lnet_net_unlock(cpt);

	return rc;
}

/**
 * Retrieve peer discovery status.
 *
 * \retval 1 if lnet_peer_discovery_disabled is 0
 * \retval 0 if lnet_peer_discovery_disabled is 1
 */
int
LNetGetPeerDiscoveryStatus(void)
{
	return !lnet_peer_discovery_disabled;
}
EXPORT_SYMBOL(LNetGetPeerDiscoveryStatus);
