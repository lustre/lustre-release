/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (C) 2013 DataDirect Networks, Inc.
 *
 * Copyright (c) 2014, 2016, Intel Corporation.
 */
/*
 * lustre/ptlrpc/nrs_tbf.c
 *
 * Network Request Scheduler (NRS) Token Bucket Filter(TBF) policy
 *
 */

/**
 * \addtogoup nrs
 * @{
 */

#define DEBUG_SUBSYSTEM S_RPC
#include <obd_support.h>
#include <obd_class.h>
#include <libcfs/libcfs.h>
#include <lustre_req_layout.h>
#include "ptlrpc_internal.h"

/**
 * \name tbf
 *
 * Token Bucket Filter over client NIDs
 *
 * @{
 */

#define NRS_POL_NAME_TBF	"tbf"

static int tbf_jobid_cache_size = 8192;
module_param(tbf_jobid_cache_size, int, 0644);
MODULE_PARM_DESC(tbf_jobid_cache_size, "The size of jobid cache");

static int tbf_rate = 10000;
module_param(tbf_rate, int, 0644);
MODULE_PARM_DESC(tbf_rate, "Default rate limit in RPCs/s");

static int tbf_depth = 3;
module_param(tbf_depth, int, 0644);
MODULE_PARM_DESC(tbf_depth, "How many tokens that a client can save up");

static enum hrtimer_restart nrs_tbf_timer_cb(struct hrtimer *timer)
{
	struct nrs_tbf_head *head = container_of(timer, struct nrs_tbf_head,
						 th_timer);
	struct ptlrpc_nrs   *nrs = head->th_res.res_policy->pol_nrs;
	struct ptlrpc_service_part *svcpt = nrs->nrs_svcpt;

	nrs->nrs_throttling = 0;
	wake_up(&svcpt->scp_waitq);

	return HRTIMER_NORESTART;
}

#define NRS_TBF_DEFAULT_RULE "default"

static void nrs_tbf_rule_fini(struct nrs_tbf_rule *rule)
{
	LASSERT(atomic_read(&rule->tr_ref) == 0);
	LASSERT(list_empty(&rule->tr_cli_list));
	LASSERT(list_empty(&rule->tr_linkage));

	rule->tr_head->th_ops->o_rule_fini(rule);
	OBD_FREE_PTR(rule);
}

/**
 * Decreases the rule's usage reference count, and stops the rule in case it
 * was already stopping and have no more outstanding usage references (which
 * indicates it has no more queued or started requests, and can be safely
 * stopped).
 */
static void nrs_tbf_rule_put(struct nrs_tbf_rule *rule)
{
	if (atomic_dec_and_test(&rule->tr_ref))
		nrs_tbf_rule_fini(rule);
}

/**
 * Increases the rule's usage reference count.
 */
static inline void nrs_tbf_rule_get(struct nrs_tbf_rule *rule)
{
	atomic_inc(&rule->tr_ref);
}

static void
nrs_tbf_cli_rule_put(struct nrs_tbf_client *cli)
{
	LASSERT(!list_empty(&cli->tc_linkage));
	LASSERT(cli->tc_rule);
	spin_lock(&cli->tc_rule->tr_rule_lock);
	list_del_init(&cli->tc_linkage);
	spin_unlock(&cli->tc_rule->tr_rule_lock);
	nrs_tbf_rule_put(cli->tc_rule);
	cli->tc_rule = NULL;
}

static void
nrs_tbf_cli_reset_value(struct nrs_tbf_head *head,
			struct nrs_tbf_client *cli)

{
	struct nrs_tbf_rule *rule = cli->tc_rule;

	cli->tc_rpc_rate = rule->tr_rpc_rate;
	cli->tc_nsecs = rule->tr_nsecs_per_rpc;
	cli->tc_depth = rule->tr_depth;
	cli->tc_ntoken = rule->tr_depth;
	cli->tc_check_time = ktime_to_ns(ktime_get());
	cli->tc_rule_sequence = atomic_read(&head->th_rule_sequence);
	cli->tc_rule_generation = rule->tr_generation;

	if (cli->tc_in_heap)
		binheap_relocate(head->th_binheap,
				 &cli->tc_node);
}

static void
nrs_tbf_cli_reset(struct nrs_tbf_head *head,
		  struct nrs_tbf_rule *rule,
		  struct nrs_tbf_client *cli)
{
	spin_lock(&cli->tc_rule_lock);
	if (cli->tc_rule != NULL && !list_empty(&cli->tc_linkage)) {
		LASSERT(rule != cli->tc_rule);
		nrs_tbf_cli_rule_put(cli);
	}
	LASSERT(cli->tc_rule == NULL);
	LASSERT(list_empty(&cli->tc_linkage));
	/* Rule's ref is added before called */
	cli->tc_rule = rule;
	spin_lock(&rule->tr_rule_lock);
	list_add_tail(&cli->tc_linkage, &rule->tr_cli_list);
	spin_unlock(&rule->tr_rule_lock);
	spin_unlock(&cli->tc_rule_lock);
	nrs_tbf_cli_reset_value(head, cli);
}

static int
nrs_tbf_rule_dump(struct nrs_tbf_rule *rule, struct seq_file *m)
{
	return rule->tr_head->th_ops->o_rule_dump(rule, m);
}

static int
nrs_tbf_rule_dump_all(struct nrs_tbf_head *head, struct seq_file *m)
{
	struct nrs_tbf_rule *rule;
	int rc = 0;

	LASSERT(head != NULL);
	spin_lock(&head->th_rule_lock);
	/* List the rules from newest to oldest */
	list_for_each_entry(rule, &head->th_list, tr_linkage) {
		LASSERT((rule->tr_flags & NTRS_STOPPING) == 0);
		rc = nrs_tbf_rule_dump(rule, m);
		if (rc) {
			rc = -ENOSPC;
			break;
		}
	}
	spin_unlock(&head->th_rule_lock);

	return rc;
}

static struct nrs_tbf_rule *
nrs_tbf_rule_find_nolock(struct nrs_tbf_head *head,
			 const char *name)
{
	struct nrs_tbf_rule *rule;

	LASSERT(head != NULL);
	list_for_each_entry(rule, &head->th_list, tr_linkage) {
		LASSERT((rule->tr_flags & NTRS_STOPPING) == 0);
		if (strcmp(rule->tr_name, name) == 0) {
			nrs_tbf_rule_get(rule);
			return rule;
		}
	}
	return NULL;
}

static struct nrs_tbf_rule *
nrs_tbf_rule_find(struct nrs_tbf_head *head,
		  const char *name)
{
	struct nrs_tbf_rule *rule;

	LASSERT(head != NULL);
	spin_lock(&head->th_rule_lock);
	rule = nrs_tbf_rule_find_nolock(head, name);
	spin_unlock(&head->th_rule_lock);
	return rule;
}

static struct nrs_tbf_rule *
nrs_tbf_rule_match(struct nrs_tbf_head *head,
		   struct nrs_tbf_client *cli)
{
	struct nrs_tbf_rule *rule = NULL;
	struct nrs_tbf_rule *tmp_rule;

	spin_lock(&head->th_rule_lock);
	/* Match the newest rule in the list */
	list_for_each_entry(tmp_rule, &head->th_list, tr_linkage) {
		LASSERT((tmp_rule->tr_flags & NTRS_STOPPING) == 0);
		if (head->th_ops->o_rule_match(tmp_rule, cli)) {
			rule = tmp_rule;
			break;
		}
	}

	if (rule == NULL)
		rule = head->th_rule;

	nrs_tbf_rule_get(rule);
	spin_unlock(&head->th_rule_lock);
	return rule;
}

static void
nrs_tbf_cli_init(struct nrs_tbf_head *head,
		 struct nrs_tbf_client *cli,
		 struct ptlrpc_request *req)
{
	struct nrs_tbf_rule *rule;

	memset(cli, 0, sizeof(*cli));
	cli->tc_in_heap = false;
	head->th_ops->o_cli_init(cli, req);
	INIT_LIST_HEAD(&cli->tc_list);
	INIT_LIST_HEAD(&cli->tc_linkage);
	spin_lock_init(&cli->tc_rule_lock);
	atomic_set(&cli->tc_ref, 1);
	rule = nrs_tbf_rule_match(head, cli);
	nrs_tbf_cli_reset(head, rule, cli);
}

static void
nrs_tbf_cli_fini(struct nrs_tbf_client *cli)
{
	LASSERT(list_empty(&cli->tc_list));
	LASSERT(!cli->tc_in_heap);
	LASSERT(atomic_read(&cli->tc_ref) == 0);
	spin_lock(&cli->tc_rule_lock);
	nrs_tbf_cli_rule_put(cli);
	spin_unlock(&cli->tc_rule_lock);
	OBD_FREE_PTR(cli);
}

static int
nrs_tbf_rule_start(struct ptlrpc_nrs_policy *policy,
		   struct nrs_tbf_head *head,
		   struct nrs_tbf_cmd *start)
{
	struct nrs_tbf_rule	*rule;
	struct nrs_tbf_rule	*tmp_rule;
	struct nrs_tbf_rule	*next_rule;
	char			*next_name = start->u.tc_start.ts_next_name;
	int			 rc;

	rule = nrs_tbf_rule_find(head, start->tc_name);
	if (rule) {
		nrs_tbf_rule_put(rule);
		return -EEXIST;
	}

	OBD_CPT_ALLOC_PTR(rule, nrs_pol2cptab(policy), nrs_pol2cptid(policy));
	if (rule == NULL)
		return -ENOMEM;

	memcpy(rule->tr_name, start->tc_name, strlen(start->tc_name));
	rule->tr_rpc_rate = start->u.tc_start.ts_rpc_rate;
	rule->tr_flags = start->u.tc_start.ts_rule_flags;
	rule->tr_nsecs_per_rpc = NSEC_PER_SEC / rule->tr_rpc_rate;
	rule->tr_depth = tbf_depth;
	atomic_set(&rule->tr_ref, 1);
	INIT_LIST_HEAD(&rule->tr_cli_list);
	INIT_LIST_HEAD(&rule->tr_nids);
	INIT_LIST_HEAD(&rule->tr_linkage);
	spin_lock_init(&rule->tr_rule_lock);
	rule->tr_head = head;

	rc = head->th_ops->o_rule_init(policy, rule, start);
	if (rc) {
		OBD_FREE_PTR(rule);
		return rc;
	}

	/* Add as the newest rule */
	spin_lock(&head->th_rule_lock);
	tmp_rule = nrs_tbf_rule_find_nolock(head, start->tc_name);
	if (tmp_rule) {
		spin_unlock(&head->th_rule_lock);
		nrs_tbf_rule_put(tmp_rule);
		nrs_tbf_rule_put(rule);
		return -EEXIST;
	}

	if (next_name) {
		next_rule = nrs_tbf_rule_find_nolock(head, next_name);
		if (!next_rule) {
			spin_unlock(&head->th_rule_lock);
			nrs_tbf_rule_put(rule);
			return -ENOENT;
		}

		list_add(&rule->tr_linkage, next_rule->tr_linkage.prev);
		nrs_tbf_rule_put(next_rule);
	} else {
		/* Add on the top of the rule list */
		list_add(&rule->tr_linkage, &head->th_list);
	}
	spin_unlock(&head->th_rule_lock);
	atomic_inc(&head->th_rule_sequence);
	if (start->u.tc_start.ts_rule_flags & NTRS_DEFAULT) {
		rule->tr_flags |= NTRS_DEFAULT;
		LASSERT(head->th_rule == NULL);
		head->th_rule = rule;
	}

	CDEBUG(D_RPCTRACE, "TBF starts rule@%p rate %u gen %llu\n",
	       rule, rule->tr_rpc_rate, rule->tr_generation);

	return 0;
}

/**
 * Change the rank of a rule in the rule list
 *
 * The matched rule will be moved to the position right before another
 * given rule.
 *
 * \param[in] policy	the policy instance
 * \param[in] head	the TBF policy instance
 * \param[in] name	the rule name to be moved
 * \param[in] next_name	the rule name before which the matched rule will be
 *			moved
 *
 */
static int
nrs_tbf_rule_change_rank(struct ptlrpc_nrs_policy *policy,
			 struct nrs_tbf_head *head,
			 char *name,
			 char *next_name)
{
	struct nrs_tbf_rule	*rule = NULL;
	struct nrs_tbf_rule	*next_rule = NULL;
	int			 rc = 0;

	LASSERT(head != NULL);

	spin_lock(&head->th_rule_lock);
	rule = nrs_tbf_rule_find_nolock(head, name);
	if (!rule)
		GOTO(out, rc = -ENOENT);

	if (strcmp(name, next_name) == 0)
		GOTO(out_put, rc);

	next_rule = nrs_tbf_rule_find_nolock(head, next_name);
	if (!next_rule)
		GOTO(out_put, rc = -ENOENT);

	list_move(&rule->tr_linkage, next_rule->tr_linkage.prev);
	nrs_tbf_rule_put(next_rule);
out_put:
	nrs_tbf_rule_put(rule);
out:
	spin_unlock(&head->th_rule_lock);
	return rc;
}

static int
nrs_tbf_rule_change_rate(struct ptlrpc_nrs_policy *policy,
			 struct nrs_tbf_head *head,
			 char *name,
			 __u64 rate)
{
	struct nrs_tbf_rule *rule;

	assert_spin_locked(&policy->pol_nrs->nrs_lock);

	rule = nrs_tbf_rule_find(head, name);
	if (rule == NULL)
		return -ENOENT;

	rule->tr_rpc_rate = rate;
	rule->tr_nsecs_per_rpc = NSEC_PER_SEC / rule->tr_rpc_rate;
	rule->tr_generation++;
	nrs_tbf_rule_put(rule);

	return 0;
}

static int
nrs_tbf_rule_change(struct ptlrpc_nrs_policy *policy,
		    struct nrs_tbf_head *head,
		    struct nrs_tbf_cmd *change)
{
	__u64	 rate = change->u.tc_change.tc_rpc_rate;
	char	*next_name = change->u.tc_change.tc_next_name;
	int	 rc;

	if (rate != 0) {
		rc = nrs_tbf_rule_change_rate(policy, head, change->tc_name,
					      rate);
		if (rc)
			return rc;
	}

	if (next_name) {
		rc = nrs_tbf_rule_change_rank(policy, head, change->tc_name,
					      next_name);
		if (rc)
			return rc;
	}

	return 0;
}

static int
nrs_tbf_rule_stop(struct ptlrpc_nrs_policy *policy,
		  struct nrs_tbf_head *head,
		  struct nrs_tbf_cmd *stop)
{
	struct nrs_tbf_rule *rule;

	assert_spin_locked(&policy->pol_nrs->nrs_lock);

	if (strcmp(stop->tc_name, NRS_TBF_DEFAULT_RULE) == 0)
		return -EPERM;

	rule = nrs_tbf_rule_find(head, stop->tc_name);
	if (rule == NULL)
		return -ENOENT;

	list_del_init(&rule->tr_linkage);
	rule->tr_flags |= NTRS_STOPPING;
	nrs_tbf_rule_put(rule);
	nrs_tbf_rule_put(rule);

	return 0;
}

static int
nrs_tbf_command(struct ptlrpc_nrs_policy *policy,
		struct nrs_tbf_head *head,
		struct nrs_tbf_cmd *cmd)
{
	int rc;

	assert_spin_locked(&policy->pol_nrs->nrs_lock);

	switch (cmd->tc_cmd) {
	case NRS_CTL_TBF_START_RULE:
		if (cmd->u.tc_start.ts_valid_type != head->th_type_flag)
			return -EINVAL;

		spin_unlock(&policy->pol_nrs->nrs_lock);
		rc = nrs_tbf_rule_start(policy, head, cmd);
		spin_lock(&policy->pol_nrs->nrs_lock);
		return rc;
	case NRS_CTL_TBF_CHANGE_RULE:
		rc = nrs_tbf_rule_change(policy, head, cmd);
		return rc;
	case NRS_CTL_TBF_STOP_RULE:
		rc = nrs_tbf_rule_stop(policy, head, cmd);
		/* Take it as a success, if not exists at all */
		return rc == -ENOENT ? 0 : rc;
	default:
		return -EFAULT;
	}
}

/**
 * Binary heap predicate.
 *
 * \param[in] e1 the first binheap node to compare
 * \param[in] e2 the second binheap node to compare
 *
 * \retval 0 e1 > e2
 * \retval 1 e1 < e2
 */
static int
tbf_cli_compare(struct binheap_node *e1, struct binheap_node *e2)
{
	struct nrs_tbf_client *cli1;
	struct nrs_tbf_client *cli2;

	cli1 = container_of(e1, struct nrs_tbf_client, tc_node);
	cli2 = container_of(e2, struct nrs_tbf_client, tc_node);

	if (cli1->tc_deadline < cli2->tc_deadline)
		return 1;
	else if (cli1->tc_deadline > cli2->tc_deadline)
		return 0;

	if (cli1->tc_check_time < cli2->tc_check_time)
		return 1;
	else if (cli1->tc_check_time > cli2->tc_check_time)
		return 0;

	/* Maybe need more comparasion, e.g. request number in the rules */
	return 1;
}

/**
 * TBF binary heap operations
 */
static struct binheap_ops nrs_tbf_heap_ops = {
	.hop_enter	= NULL,
	.hop_exit	= NULL,
	.hop_compare	= tbf_cli_compare,
};

static unsigned nrs_tbf_jobid_hop_hash(struct cfs_hash *hs, const void *key,
				  unsigned mask)
{
	return cfs_hash_djb2_hash(key, strlen(key), mask);
}

static int nrs_tbf_jobid_hop_keycmp(const void *key, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	return (strcmp(cli->tc_jobid, key) == 0);
}

static void *nrs_tbf_jobid_hop_key(struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	return cli->tc_jobid;
}

static void *nrs_tbf_hop_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct nrs_tbf_client, tc_hnode);
}

static void nrs_tbf_jobid_hop_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	atomic_inc(&cli->tc_ref);
}

static void nrs_tbf_jobid_hop_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	atomic_dec(&cli->tc_ref);
}

static void
nrs_tbf_jobid_hop_exit(struct cfs_hash *hs, struct hlist_node *hnode)

{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	LASSERT(atomic_read(&cli->tc_ref) == 0);
	nrs_tbf_cli_fini(cli);
}

static struct cfs_hash_ops nrs_tbf_jobid_hash_ops = {
	.hs_hash	= nrs_tbf_jobid_hop_hash,
	.hs_keycmp	= nrs_tbf_jobid_hop_keycmp,
	.hs_key		= nrs_tbf_jobid_hop_key,
	.hs_object	= nrs_tbf_hop_object,
	.hs_get		= nrs_tbf_jobid_hop_get,
	.hs_put		= nrs_tbf_jobid_hop_put,
	.hs_put_locked	= nrs_tbf_jobid_hop_put,
	.hs_exit	= nrs_tbf_jobid_hop_exit,
};

#define NRS_TBF_JOBID_HASH_FLAGS (CFS_HASH_SPIN_BKTLOCK | \
				  CFS_HASH_NO_ITEMREF | \
				  CFS_HASH_DEPTH)

static struct nrs_tbf_client *
nrs_tbf_jobid_hash_lookup(struct cfs_hash *hs,
			  struct cfs_hash_bd *bd,
			  const char *jobid)
{
	struct hlist_node *hnode;
	struct nrs_tbf_client *cli;

	hnode = cfs_hash_bd_lookup_locked(hs, bd, (void *)jobid);
	if (hnode == NULL)
		return NULL;

	cli = container_of(hnode, struct nrs_tbf_client, tc_hnode);
	if (!list_empty(&cli->tc_lru))
		list_del_init(&cli->tc_lru);
	return cli;
}

#define NRS_TBF_JOBID_NULL ""

static struct nrs_tbf_client *
nrs_tbf_jobid_cli_find(struct nrs_tbf_head *head,
		       struct ptlrpc_request *req)
{
	const char		*jobid;
	struct nrs_tbf_client	*cli;
	struct cfs_hash		*hs = head->th_cli_hash;
	struct cfs_hash_bd		 bd;

	jobid = lustre_msg_get_jobid(req->rq_reqmsg);
	if (jobid == NULL)
		jobid = NRS_TBF_JOBID_NULL;
	cfs_hash_bd_get_and_lock(hs, (void *)jobid, &bd, 1);
	cli = nrs_tbf_jobid_hash_lookup(hs, &bd, jobid);
	cfs_hash_bd_unlock(hs, &bd, 1);

	return cli;
}

static struct nrs_tbf_client *
nrs_tbf_jobid_cli_findadd(struct nrs_tbf_head *head,
			  struct nrs_tbf_client *cli)
{
	const char		*jobid;
	struct nrs_tbf_client	*ret;
	struct cfs_hash		*hs = head->th_cli_hash;
	struct cfs_hash_bd		 bd;

	jobid = cli->tc_jobid;
	cfs_hash_bd_get_and_lock(hs, (void *)jobid, &bd, 1);
	ret = nrs_tbf_jobid_hash_lookup(hs, &bd, jobid);
	if (ret == NULL) {
		cfs_hash_bd_add_locked(hs, &bd, &cli->tc_hnode);
		ret = cli;
	}
	cfs_hash_bd_unlock(hs, &bd, 1);

	return ret;
}

static void
nrs_tbf_jobid_cli_put(struct nrs_tbf_head *head,
		      struct nrs_tbf_client *cli)
{
	struct cfs_hash_bd		 bd;
	struct cfs_hash		*hs = head->th_cli_hash;
	struct nrs_tbf_bucket	*bkt;
	int			 hw;
	LIST_HEAD(zombies);

	cfs_hash_bd_get(hs, &cli->tc_jobid, &bd);
	bkt = cfs_hash_bd_extra_get(hs, &bd);
	if (!cfs_hash_bd_dec_and_lock(hs, &bd, &cli->tc_ref))
		return;
	LASSERT(list_empty(&cli->tc_lru));
	list_add_tail(&cli->tc_lru, &bkt->ntb_lru);

	/*
	 * Check and purge the LRU, there is at least one client in the LRU.
	 */
	hw = tbf_jobid_cache_size >>
	     (hs->hs_cur_bits - hs->hs_bkt_bits);
	while (cfs_hash_bd_count_get(&bd) > hw) {
		if (unlikely(list_empty(&bkt->ntb_lru)))
			break;
		cli = list_entry(bkt->ntb_lru.next,
				     struct nrs_tbf_client,
				     tc_lru);
		LASSERT(atomic_read(&cli->tc_ref) == 0);
		cfs_hash_bd_del_locked(hs, &bd, &cli->tc_hnode);
		list_move(&cli->tc_lru, &zombies);
	}
	cfs_hash_bd_unlock(head->th_cli_hash, &bd, 1);

	while (!list_empty(&zombies)) {
		cli = container_of(zombies.next,
				   struct nrs_tbf_client, tc_lru);
		list_del_init(&cli->tc_lru);
		nrs_tbf_cli_fini(cli);
	}
}

static void
nrs_tbf_jobid_cli_init(struct nrs_tbf_client *cli,
		       struct ptlrpc_request *req)
{
	char *jobid = lustre_msg_get_jobid(req->rq_reqmsg);

	if (jobid == NULL)
		jobid = NRS_TBF_JOBID_NULL;
	LASSERT(strlen(jobid) < LUSTRE_JOBID_SIZE);
	INIT_LIST_HEAD(&cli->tc_lru);
	memcpy(cli->tc_jobid, jobid, strlen(jobid));
}

static int nrs_tbf_jobid_hash_order(void)
{
	int bits;

	for (bits = 1; (1 << bits) < tbf_jobid_cache_size; ++bits)
		;

	return bits;
}

#define NRS_TBF_JOBID_BKT_BITS 10

static int
nrs_tbf_jobid_startup(struct ptlrpc_nrs_policy *policy,
		      struct nrs_tbf_head *head)
{
	struct nrs_tbf_cmd	 start;
	struct nrs_tbf_bucket	*bkt;
	int			 bits;
	int			 i;
	int			 rc;
	struct cfs_hash_bd	 bd;

	bits = nrs_tbf_jobid_hash_order();
	if (bits < NRS_TBF_JOBID_BKT_BITS)
		bits = NRS_TBF_JOBID_BKT_BITS;
	head->th_cli_hash = cfs_hash_create("nrs_tbf_hash",
					    bits,
					    bits,
					    NRS_TBF_JOBID_BKT_BITS,
					    sizeof(*bkt),
					    0,
					    0,
					    &nrs_tbf_jobid_hash_ops,
					    NRS_TBF_JOBID_HASH_FLAGS);
	if (head->th_cli_hash == NULL)
		return -ENOMEM;

	cfs_hash_for_each_bucket(head->th_cli_hash, &bd, i) {
		bkt = cfs_hash_bd_extra_get(head->th_cli_hash, &bd);
		INIT_LIST_HEAD(&bkt->ntb_lru);
	}

	memset(&start, 0, sizeof(start));
	start.u.tc_start.ts_jobids_str = "*";

	start.u.tc_start.ts_rpc_rate = tbf_rate;
	start.u.tc_start.ts_rule_flags = NTRS_DEFAULT;
	start.tc_name = NRS_TBF_DEFAULT_RULE;
	INIT_LIST_HEAD(&start.u.tc_start.ts_jobids);
	rc = nrs_tbf_rule_start(policy, head, &start);
	if (rc) {
		cfs_hash_putref(head->th_cli_hash);
		head->th_cli_hash = NULL;
	}

	return rc;
}

/**
 * Frees jobid of \a list.
 *
 */
static void
nrs_tbf_jobid_list_free(struct list_head *jobid_list)
{
	struct nrs_tbf_jobid *jobid, *n;

	list_for_each_entry_safe(jobid, n, jobid_list, tj_linkage) {
		OBD_FREE(jobid->tj_id, strlen(jobid->tj_id) + 1);
		list_del(&jobid->tj_linkage);
		OBD_FREE_PTR(jobid);
	}
}

static int
nrs_tbf_jobid_list_add(struct cfs_lstr *id, struct list_head *jobid_list)
{
	struct nrs_tbf_jobid *jobid;
	char *ptr;

	OBD_ALLOC_PTR(jobid);
	if (jobid == NULL)
		return -ENOMEM;

	OBD_ALLOC(jobid->tj_id, id->ls_len + 1);
	if (jobid->tj_id == NULL) {
		OBD_FREE_PTR(jobid);
		return -ENOMEM;
	}

	memcpy(jobid->tj_id, id->ls_str, id->ls_len);
	ptr = lprocfs_strnstr(id->ls_str, "*", id->ls_len);
	if (ptr == NULL)
		jobid->tj_match_flag = NRS_TBF_MATCH_FULL;
	else
		jobid->tj_match_flag = NRS_TBF_MATCH_WILDCARD;

	list_add_tail(&jobid->tj_linkage, jobid_list);
	return 0;
}

static bool
cfs_match_wildcard(const char *pattern, const char *content)
{
	if (*pattern == '\0' && *content == '\0')
		return true;

	if (*pattern == '*' && *(pattern + 1) != '\0' && *content == '\0')
		return false;

	while (*pattern == *content) {
		pattern++;
		content++;
		if (*pattern == '\0' && *content == '\0')
			return true;

		if (*pattern == '*' && *(pattern + 1) != '\0' &&
		    *content == '\0')
			return false;
	}

	if (*pattern == '*')
		return (cfs_match_wildcard(pattern + 1, content) ||
			cfs_match_wildcard(pattern, content + 1));

	return false;
}

static inline bool
nrs_tbf_jobid_match(const struct nrs_tbf_jobid *jobid, const char *id)
{
	if (jobid->tj_match_flag == NRS_TBF_MATCH_FULL)
		return strcmp(jobid->tj_id, id) == 0;

	if (jobid->tj_match_flag == NRS_TBF_MATCH_WILDCARD)
		return cfs_match_wildcard(jobid->tj_id, id);

	return false;
}

static int
nrs_tbf_jobid_list_match(struct list_head *jobid_list, char *id)
{
	struct nrs_tbf_jobid *jobid;

	list_for_each_entry(jobid, jobid_list, tj_linkage) {
		if (nrs_tbf_jobid_match(jobid, id))
			return 1;
	}
	return 0;
}

static int
nrs_tbf_jobid_list_parse(char *str, int len, struct list_head *jobid_list)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;
	ENTRY;

	src.ls_str = str;
	src.ls_len = len;
	INIT_LIST_HEAD(jobid_list);
	while (src.ls_str) {
		rc = cfs_gettok(&src, ' ', &res);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = nrs_tbf_jobid_list_add(&res, jobid_list);
		if (rc)
			break;
	}
	if (rc)
		nrs_tbf_jobid_list_free(jobid_list);
	RETURN(rc);
}

static void nrs_tbf_jobid_cmd_fini(struct nrs_tbf_cmd *cmd)
{
	if (!list_empty(&cmd->u.tc_start.ts_jobids))
		nrs_tbf_jobid_list_free(&cmd->u.tc_start.ts_jobids);
	if (cmd->u.tc_start.ts_jobids_str)
		OBD_FREE(cmd->u.tc_start.ts_jobids_str,
			 strlen(cmd->u.tc_start.ts_jobids_str) + 1);
}

static int nrs_tbf_check_id_value(struct cfs_lstr *src, char *key)
{
	struct cfs_lstr res;
	int keylen = strlen(key);
	int rc;

	rc = cfs_gettok(src, '=', &res);
	if (rc == 0 || res.ls_len != keylen ||
	    strncmp(res.ls_str, key, keylen) != 0 ||
	    src->ls_len <= 2 || src->ls_str[0] != '{' ||
	    src->ls_str[src->ls_len - 1] != '}')
		return -EINVAL;

	/* Skip '{' and '}' */
	src->ls_str++;
	src->ls_len -= 2;
	return 0;
}

static int nrs_tbf_jobid_parse(struct nrs_tbf_cmd *cmd, char *id)
{
	struct cfs_lstr src;
	int rc;

	src.ls_str = id;
	src.ls_len = strlen(id);
	rc = nrs_tbf_check_id_value(&src, "jobid");
	if (rc)
		return rc;

	OBD_ALLOC(cmd->u.tc_start.ts_jobids_str, src.ls_len + 1);
	if (cmd->u.tc_start.ts_jobids_str == NULL)
		return -ENOMEM;

	memcpy(cmd->u.tc_start.ts_jobids_str, src.ls_str, src.ls_len);

	/* parse jobid list */
	rc = nrs_tbf_jobid_list_parse(cmd->u.tc_start.ts_jobids_str,
				      strlen(cmd->u.tc_start.ts_jobids_str),
				      &cmd->u.tc_start.ts_jobids);
	if (rc)
		nrs_tbf_jobid_cmd_fini(cmd);

	return rc;
}

static int nrs_tbf_jobid_rule_init(struct ptlrpc_nrs_policy *policy,
				   struct nrs_tbf_rule *rule,
				   struct nrs_tbf_cmd *start)
{
	int rc = 0;

	LASSERT(start->u.tc_start.ts_jobids_str);
	OBD_ALLOC(rule->tr_jobids_str,
		  strlen(start->u.tc_start.ts_jobids_str) + 1);
	if (rule->tr_jobids_str == NULL)
		return -ENOMEM;

	memcpy(rule->tr_jobids_str,
	       start->u.tc_start.ts_jobids_str,
	       strlen(start->u.tc_start.ts_jobids_str));

	INIT_LIST_HEAD(&rule->tr_jobids);
	if (!list_empty(&start->u.tc_start.ts_jobids)) {
		rc = nrs_tbf_jobid_list_parse(rule->tr_jobids_str,
					      strlen(rule->tr_jobids_str),
					      &rule->tr_jobids);
		if (rc)
			CERROR("jobids {%s} illegal\n", rule->tr_jobids_str);
	}
	if (rc)
		OBD_FREE(rule->tr_jobids_str,
			 strlen(start->u.tc_start.ts_jobids_str) + 1);
	return rc;
}

static int
nrs_tbf_jobid_rule_dump(struct nrs_tbf_rule *rule, struct seq_file *m)
{
	seq_printf(m, "%s {%s} %u, ref %d\n", rule->tr_name,
		   rule->tr_jobids_str, rule->tr_rpc_rate,
		   atomic_read(&rule->tr_ref) - 1);
	return 0;
}

static int
nrs_tbf_jobid_rule_match(struct nrs_tbf_rule *rule,
			 struct nrs_tbf_client *cli)
{
	return nrs_tbf_jobid_list_match(&rule->tr_jobids, cli->tc_jobid);
}

static void nrs_tbf_jobid_rule_fini(struct nrs_tbf_rule *rule)
{
	if (!list_empty(&rule->tr_jobids))
		nrs_tbf_jobid_list_free(&rule->tr_jobids);
	LASSERT(rule->tr_jobids_str != NULL);
	OBD_FREE(rule->tr_jobids_str, strlen(rule->tr_jobids_str) + 1);
}

static struct nrs_tbf_ops nrs_tbf_jobid_ops = {
	.o_name = NRS_TBF_TYPE_JOBID,
	.o_startup = nrs_tbf_jobid_startup,
	.o_cli_find = nrs_tbf_jobid_cli_find,
	.o_cli_findadd = nrs_tbf_jobid_cli_findadd,
	.o_cli_put = nrs_tbf_jobid_cli_put,
	.o_cli_init = nrs_tbf_jobid_cli_init,
	.o_rule_init = nrs_tbf_jobid_rule_init,
	.o_rule_dump = nrs_tbf_jobid_rule_dump,
	.o_rule_match = nrs_tbf_jobid_rule_match,
	.o_rule_fini = nrs_tbf_jobid_rule_fini,
};

/**
 * libcfs_hash operations for nrs_tbf_net::cn_cli_hash
 *
 * This uses ptlrpc_request::rq_peer.nid as its key, in order to hash
 * nrs_tbf_client objects.
 */
#define NRS_TBF_NID_BKT_BITS	8
#define NRS_TBF_NID_BITS	16

static unsigned nrs_tbf_nid_hop_hash(struct cfs_hash *hs, const void *key,
				  unsigned mask)
{
	return cfs_hash_djb2_hash(key, sizeof(lnet_nid_t), mask);
}

static int nrs_tbf_nid_hop_keycmp(const void *key, struct hlist_node *hnode)
{
	lnet_nid_t	      *nid = (lnet_nid_t *)key;
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	return *nid == cli->tc_nid;
}

static void *nrs_tbf_nid_hop_key(struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	return &cli->tc_nid;
}

static void nrs_tbf_nid_hop_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	atomic_inc(&cli->tc_ref);
}

static void nrs_tbf_nid_hop_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	atomic_dec(&cli->tc_ref);
}

static void nrs_tbf_nid_hop_exit(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						     struct nrs_tbf_client,
						     tc_hnode);

	LASSERTF(atomic_read(&cli->tc_ref) == 0,
		 "Busy TBF object from client with NID %s, with %d refs\n",
		 libcfs_nid2str(cli->tc_nid), atomic_read(&cli->tc_ref));

	nrs_tbf_cli_fini(cli);
}

static struct cfs_hash_ops nrs_tbf_nid_hash_ops = {
	.hs_hash	= nrs_tbf_nid_hop_hash,
	.hs_keycmp	= nrs_tbf_nid_hop_keycmp,
	.hs_key		= nrs_tbf_nid_hop_key,
	.hs_object	= nrs_tbf_hop_object,
	.hs_get		= nrs_tbf_nid_hop_get,
	.hs_put		= nrs_tbf_nid_hop_put,
	.hs_put_locked	= nrs_tbf_nid_hop_put,
	.hs_exit	= nrs_tbf_nid_hop_exit,
};

static struct nrs_tbf_client *
nrs_tbf_nid_cli_find(struct nrs_tbf_head *head,
		     struct ptlrpc_request *req)
{
	return cfs_hash_lookup(head->th_cli_hash, &req->rq_peer.nid);
}

static struct nrs_tbf_client *
nrs_tbf_nid_cli_findadd(struct nrs_tbf_head *head,
			struct nrs_tbf_client *cli)
{
	return cfs_hash_findadd_unique(head->th_cli_hash, &cli->tc_nid,
				       &cli->tc_hnode);
}

static void
nrs_tbf_nid_cli_put(struct nrs_tbf_head *head,
		      struct nrs_tbf_client *cli)
{
	cfs_hash_put(head->th_cli_hash, &cli->tc_hnode);
}

static int
nrs_tbf_nid_startup(struct ptlrpc_nrs_policy *policy,
		    struct nrs_tbf_head *head)
{
	struct nrs_tbf_cmd	start;
	int rc;

	head->th_cli_hash = cfs_hash_create("nrs_tbf_hash",
					    NRS_TBF_NID_BITS,
					    NRS_TBF_NID_BITS,
					    NRS_TBF_NID_BKT_BITS, 0,
					    CFS_HASH_MIN_THETA,
					    CFS_HASH_MAX_THETA,
					    &nrs_tbf_nid_hash_ops,
					    CFS_HASH_RW_BKTLOCK);
	if (head->th_cli_hash == NULL)
		return -ENOMEM;

	memset(&start, 0, sizeof(start));
	start.u.tc_start.ts_nids_str = "*";

	start.u.tc_start.ts_rpc_rate = tbf_rate;
	start.u.tc_start.ts_rule_flags = NTRS_DEFAULT;
	start.tc_name = NRS_TBF_DEFAULT_RULE;
	INIT_LIST_HEAD(&start.u.tc_start.ts_nids);
	rc = nrs_tbf_rule_start(policy, head, &start);
	if (rc) {
		cfs_hash_putref(head->th_cli_hash);
		head->th_cli_hash = NULL;
	}

	return rc;
}

static void
nrs_tbf_nid_cli_init(struct nrs_tbf_client *cli,
			     struct ptlrpc_request *req)
{
	cli->tc_nid = req->rq_peer.nid;
}

static int nrs_tbf_nid_rule_init(struct ptlrpc_nrs_policy *policy,
				 struct nrs_tbf_rule *rule,
				 struct nrs_tbf_cmd *start)
{
	LASSERT(start->u.tc_start.ts_nids_str);
	OBD_ALLOC(rule->tr_nids_str,
		  strlen(start->u.tc_start.ts_nids_str) + 1);
	if (rule->tr_nids_str == NULL)
		return -ENOMEM;

	memcpy(rule->tr_nids_str,
	       start->u.tc_start.ts_nids_str,
	       strlen(start->u.tc_start.ts_nids_str));

	INIT_LIST_HEAD(&rule->tr_nids);
	if (!list_empty(&start->u.tc_start.ts_nids)) {
		if (cfs_parse_nidlist(rule->tr_nids_str,
				      strlen(rule->tr_nids_str),
				      &rule->tr_nids) <= 0) {
			CERROR("nids {%s} illegal\n",
			       rule->tr_nids_str);
			OBD_FREE(rule->tr_nids_str,
				 strlen(start->u.tc_start.ts_nids_str) + 1);
			return -EINVAL;
		}
	}
	return 0;
}

static int
nrs_tbf_nid_rule_dump(struct nrs_tbf_rule *rule, struct seq_file *m)
{
	seq_printf(m, "%s {%s} %u, ref %d\n", rule->tr_name,
		   rule->tr_nids_str, rule->tr_rpc_rate,
		   atomic_read(&rule->tr_ref) - 1);
	return 0;
}

static int
nrs_tbf_nid_rule_match(struct nrs_tbf_rule *rule,
		       struct nrs_tbf_client *cli)
{
	return cfs_match_nid(cli->tc_nid, &rule->tr_nids);
}

static void nrs_tbf_nid_rule_fini(struct nrs_tbf_rule *rule)
{
	if (!list_empty(&rule->tr_nids))
		cfs_free_nidlist(&rule->tr_nids);
	LASSERT(rule->tr_nids_str != NULL);
	OBD_FREE(rule->tr_nids_str, strlen(rule->tr_nids_str) + 1);
}

static void nrs_tbf_nid_cmd_fini(struct nrs_tbf_cmd *cmd)
{
	if (!list_empty(&cmd->u.tc_start.ts_nids))
		cfs_free_nidlist(&cmd->u.tc_start.ts_nids);
	if (cmd->u.tc_start.ts_nids_str)
		OBD_FREE(cmd->u.tc_start.ts_nids_str,
			 strlen(cmd->u.tc_start.ts_nids_str) + 1);
}

static int nrs_tbf_nid_parse(struct nrs_tbf_cmd *cmd, char *id)
{
	struct cfs_lstr src;
	int rc;

	src.ls_str = id;
	src.ls_len = strlen(id);
	rc = nrs_tbf_check_id_value(&src, "nid");
	if (rc)
		return rc;

	OBD_ALLOC(cmd->u.tc_start.ts_nids_str, src.ls_len + 1);
	if (cmd->u.tc_start.ts_nids_str == NULL)
		return -ENOMEM;

	memcpy(cmd->u.tc_start.ts_nids_str, src.ls_str, src.ls_len);

	/* parse NID list */
	if (cfs_parse_nidlist(cmd->u.tc_start.ts_nids_str,
			      strlen(cmd->u.tc_start.ts_nids_str),
			      &cmd->u.tc_start.ts_nids) <= 0) {
		nrs_tbf_nid_cmd_fini(cmd);
		return -EINVAL;
	}

	return 0;
}

static struct nrs_tbf_ops nrs_tbf_nid_ops = {
	.o_name = NRS_TBF_TYPE_NID,
	.o_startup = nrs_tbf_nid_startup,
	.o_cli_find = nrs_tbf_nid_cli_find,
	.o_cli_findadd = nrs_tbf_nid_cli_findadd,
	.o_cli_put = nrs_tbf_nid_cli_put,
	.o_cli_init = nrs_tbf_nid_cli_init,
	.o_rule_init = nrs_tbf_nid_rule_init,
	.o_rule_dump = nrs_tbf_nid_rule_dump,
	.o_rule_match = nrs_tbf_nid_rule_match,
	.o_rule_fini = nrs_tbf_nid_rule_fini,
};

static unsigned nrs_tbf_hop_hash(struct cfs_hash *hs, const void *key,
				 unsigned mask)
{
	return cfs_hash_djb2_hash(key, strlen(key), mask);
}

static int nrs_tbf_hop_keycmp(const void *key, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	return (strcmp(cli->tc_key, key) == 0);
}

static void *nrs_tbf_hop_key(struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);
	return cli->tc_key;
}

static void nrs_tbf_hop_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	atomic_inc(&cli->tc_ref);
}

static void nrs_tbf_hop_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	atomic_dec(&cli->tc_ref);
}

static void nrs_tbf_hop_exit(struct cfs_hash *hs, struct hlist_node *hnode)

{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	LASSERT(atomic_read(&cli->tc_ref) == 0);
	nrs_tbf_cli_fini(cli);
}

static struct cfs_hash_ops nrs_tbf_hash_ops = {
	.hs_hash	= nrs_tbf_hop_hash,
	.hs_keycmp      = nrs_tbf_hop_keycmp,
	.hs_key		= nrs_tbf_hop_key,
	.hs_object	= nrs_tbf_hop_object,
	.hs_get		= nrs_tbf_hop_get,
	.hs_put		= nrs_tbf_hop_put,
	.hs_put_locked	= nrs_tbf_hop_put,
	.hs_exit	= nrs_tbf_hop_exit,
};

#define NRS_TBF_GENERIC_BKT_BITS	10
#define NRS_TBF_GENERIC_HASH_FLAGS	(CFS_HASH_SPIN_BKTLOCK | \
					CFS_HASH_NO_ITEMREF | \
					CFS_HASH_DEPTH)

static int
nrs_tbf_startup(struct ptlrpc_nrs_policy *policy, struct nrs_tbf_head *head)
{
	struct nrs_tbf_cmd	 start;
	struct nrs_tbf_bucket	*bkt;
	int			 bits;
	int			 i;
	int			 rc;
	struct cfs_hash_bd	 bd;

	bits = nrs_tbf_jobid_hash_order();
	if (bits < NRS_TBF_GENERIC_BKT_BITS)
		bits = NRS_TBF_GENERIC_BKT_BITS;
	head->th_cli_hash = cfs_hash_create("nrs_tbf_hash",
					    bits, bits,
					    NRS_TBF_GENERIC_BKT_BITS,
					    sizeof(*bkt), 0, 0,
					    &nrs_tbf_hash_ops,
					    NRS_TBF_GENERIC_HASH_FLAGS);
	if (head->th_cli_hash == NULL)
		return -ENOMEM;

	cfs_hash_for_each_bucket(head->th_cli_hash, &bd, i) {
		bkt = cfs_hash_bd_extra_get(head->th_cli_hash, &bd);
		INIT_LIST_HEAD(&bkt->ntb_lru);
	}

	memset(&start, 0, sizeof(start));
	start.u.tc_start.ts_conds_str = "*";

	start.u.tc_start.ts_rpc_rate = tbf_rate;
	start.u.tc_start.ts_rule_flags = NTRS_DEFAULT;
	start.tc_name = NRS_TBF_DEFAULT_RULE;
	INIT_LIST_HEAD(&start.u.tc_start.ts_conds);
	rc = nrs_tbf_rule_start(policy, head, &start);
	if (rc)
		cfs_hash_putref(head->th_cli_hash);

	return rc;
}

static struct nrs_tbf_client *
nrs_tbf_cli_hash_lookup(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			const char *key)
{
	struct hlist_node *hnode;
	struct nrs_tbf_client *cli;

	hnode = cfs_hash_bd_lookup_locked(hs, bd, (void *)key);
	if (hnode == NULL)
		return NULL;

	cli = container_of(hnode, struct nrs_tbf_client, tc_hnode);
	if (!list_empty(&cli->tc_lru))
		list_del_init(&cli->tc_lru);
	return cli;
}

/**
 * ONLY opcode presented in this function will be checked in
 * nrs_tbf_id_cli_set(). That means, we can add or remove an
 * opcode to enable or disable requests handled in nrs_tbf
 */
static struct req_format *req_fmt(__u32 opcode)
{
	switch (opcode) {
	case OST_GETATTR:
		return &RQF_OST_GETATTR;
	case OST_SETATTR:
		return &RQF_OST_SETATTR;
	case OST_READ:
		return &RQF_OST_BRW_READ;
	case OST_WRITE:
		return &RQF_OST_BRW_WRITE;
	/* FIXME: OST_CREATE and OST_DESTROY comes from MDS
	 * in most case. Should they be removed? */
	case OST_CREATE:
		return &RQF_OST_CREATE;
	case OST_DESTROY:
		return &RQF_OST_DESTROY;
	case OST_PUNCH:
		return &RQF_OST_PUNCH;
	case OST_SYNC:
		return &RQF_OST_SYNC;
	case OST_LADVISE:
		return &RQF_OST_LADVISE;
	case MDS_GETATTR:
		return &RQF_MDS_GETATTR;
	case MDS_GETATTR_NAME:
		return &RQF_MDS_GETATTR_NAME;
	/* close is skipped to avoid LDLM cancel slowness */
#if 0
	case MDS_CLOSE:
		return &RQF_MDS_CLOSE;
#endif
	case MDS_REINT:
		return &RQF_MDS_REINT;
	case MDS_READPAGE:
		return &RQF_MDS_READPAGE;
	case MDS_GET_ROOT:
		return &RQF_MDS_GET_ROOT;
	case MDS_STATFS:
		return &RQF_MDS_STATFS;
	case MDS_SYNC:
		return &RQF_MDS_SYNC;
	case MDS_QUOTACTL:
		return &RQF_MDS_QUOTACTL;
	case MDS_GETXATTR:
		return &RQF_MDS_GETXATTR;
	case MDS_GET_INFO:
		return &RQF_MDS_GET_INFO;
	/* HSM op is skipped */
#if 0 
	case MDS_HSM_STATE_GET:
		return &RQF_MDS_HSM_STATE_GET;
	case MDS_HSM_STATE_SET:
		return &RQF_MDS_HSM_STATE_SET;
	case MDS_HSM_ACTION:
		return &RQF_MDS_HSM_ACTION;
	case MDS_HSM_CT_REGISTER:
		return &RQF_MDS_HSM_CT_REGISTER;
	case MDS_HSM_CT_UNREGISTER:
		return &RQF_MDS_HSM_CT_UNREGISTER;
#endif
	case MDS_SWAP_LAYOUTS:
		return &RQF_MDS_SWAP_LAYOUTS;
	case LDLM_ENQUEUE:
		return &RQF_LDLM_ENQUEUE;
	default:
		return NULL;
	}
}

static struct req_format *intent_req_fmt(__u32 it_opc)
{
	if (it_opc & (IT_OPEN | IT_CREAT))
		return &RQF_LDLM_INTENT_OPEN;
	else if (it_opc & (IT_GETATTR | IT_LOOKUP))
		return &RQF_LDLM_INTENT_GETATTR;
	else if (it_opc & IT_GETXATTR)
		return &RQF_LDLM_INTENT_GETXATTR;
	else if (it_opc & (IT_GLIMPSE | IT_BRW))
		return &RQF_LDLM_INTENT;
	else
		return NULL;
}

static int ost_tbf_id_cli_set(struct ptlrpc_request *req,
			      struct tbf_id *id)
{
	struct ost_body *body;

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	if (body != NULL) {
		id->ti_uid = body->oa.o_uid;
		id->ti_gid = body->oa.o_gid;
		return 0;
	}

	return -EINVAL;
}

static void unpack_ugid_from_mdt_body(struct ptlrpc_request *req,
				      struct tbf_id *id)
{
	struct mdt_body *b = req_capsule_client_get(&req->rq_pill,
						    &RMF_MDT_BODY);
	LASSERT(b != NULL);

	/* TODO: nodemaping feature converts {ug}id from individual
	 * clients to the actual ones of the file system. Some work
	 * may be needed to fix this. */
	id->ti_uid = b->mbo_uid;
	id->ti_gid = b->mbo_gid;
}

static void unpack_ugid_from_mdt_rec_reint(struct ptlrpc_request *req,
					   struct tbf_id *id)
{
	struct mdt_rec_reint *rec;

	rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);
	LASSERT(rec != NULL);

	/* use the fs{ug}id as {ug}id of the process */
	id->ti_uid = rec->rr_fsuid;
	id->ti_gid = rec->rr_fsgid;
}

static int mdt_tbf_id_cli_set(struct ptlrpc_request *req,
			      struct tbf_id *id)
{
	u32 opc = lustre_msg_get_opc(req->rq_reqmsg);
	int rc = 0;

	switch (opc) {
	case MDS_GETATTR:
	case MDS_GETATTR_NAME:
	case MDS_GET_ROOT:
	case MDS_READPAGE:
	case MDS_SYNC:
	case MDS_GETXATTR:
	case MDS_HSM_STATE_GET ... MDS_SWAP_LAYOUTS:
		unpack_ugid_from_mdt_body(req, id);
		break;
	case MDS_CLOSE:
	case MDS_REINT:
		unpack_ugid_from_mdt_rec_reint(req, id);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

static int ldlm_tbf_id_cli_set(struct ptlrpc_request *req,
			      struct tbf_id *id)
{
	struct ldlm_intent *lit;
	struct req_format *fmt;

	if (req->rq_reqmsg->lm_bufcount <= DLM_INTENT_IT_OFF)
		return -EINVAL;

	req_capsule_extend(&req->rq_pill, &RQF_LDLM_INTENT_BASIC);
	lit = req_capsule_client_get(&req->rq_pill, &RMF_LDLM_INTENT);
	if (lit == NULL)
		return -EINVAL;

	fmt = intent_req_fmt(lit->opc);
	if (fmt == NULL)
		return -EINVAL;

	req_capsule_extend(&req->rq_pill, fmt);

	if (lit->opc & (IT_GETXATTR | IT_GETATTR | IT_LOOKUP))
		unpack_ugid_from_mdt_body(req, id);
	else if (lit->opc & (IT_OPEN | IT_OPEN | IT_GLIMPSE | IT_BRW))
		unpack_ugid_from_mdt_rec_reint(req, id);
	else
		return -EINVAL;
	return 0;
}

static int nrs_tbf_id_cli_set(struct ptlrpc_request *req, struct tbf_id *id,
			      enum nrs_tbf_flag ti_type)
{
	u32 opc = lustre_msg_get_opc(req->rq_reqmsg);
	struct req_format *fmt = req_fmt(opc);
	bool fmt_unset = false;
	int rc;

	memset(id, 0, sizeof(struct tbf_id));
	id->ti_type = ti_type;

	if (fmt == NULL)
		return -EINVAL;
	req_capsule_init(&req->rq_pill, req, RCL_SERVER);
	if (req->rq_pill.rc_fmt == NULL) {
		req_capsule_set(&req->rq_pill, fmt);
		fmt_unset = true;
	}

	if (opc < OST_LAST_OPC)
		rc = ost_tbf_id_cli_set(req, id);
	else if (opc >= MDS_FIRST_OPC && opc < MDS_LAST_OPC)
		rc = mdt_tbf_id_cli_set(req, id);
	else if (opc == LDLM_ENQUEUE)
		rc = ldlm_tbf_id_cli_set(req, id);
	else
		rc = -EINVAL;

	/* restore it to the initialized state */
	if (fmt_unset)
		req->rq_pill.rc_fmt = NULL;
	return rc;
}

static inline void nrs_tbf_cli_gen_key(struct nrs_tbf_client *cli,
				       struct ptlrpc_request *req,
				       char *keystr, size_t keystr_sz)
{
	const char *jobid;
	u32 opc = lustre_msg_get_opc(req->rq_reqmsg);
	struct tbf_id id;

	nrs_tbf_id_cli_set(req, &id, NRS_TBF_FLAG_UID | NRS_TBF_FLAG_GID);
	jobid = lustre_msg_get_jobid(req->rq_reqmsg);
	if (jobid == NULL)
		jobid = NRS_TBF_JOBID_NULL;

	snprintf(keystr, keystr_sz, "%s_%s_%d_%u_%u", jobid,
		 libcfs_nid2str(req->rq_peer.nid), opc, id.ti_uid,
		 id.ti_gid);

	if (cli) {
		INIT_LIST_HEAD(&cli->tc_lru);
		strlcpy(cli->tc_key, keystr, sizeof(cli->tc_key));
		strlcpy(cli->tc_jobid, jobid, sizeof(cli->tc_jobid));
		cli->tc_nid = req->rq_peer.nid;
		cli->tc_opcode = opc;
		cli->tc_id = id;
	}
}

static struct nrs_tbf_client *
nrs_tbf_cli_find(struct nrs_tbf_head *head, struct ptlrpc_request *req)
{
	struct nrs_tbf_client *cli;
	struct cfs_hash *hs = head->th_cli_hash;
	struct cfs_hash_bd bd;
	char keystr[NRS_TBF_KEY_LEN];

	nrs_tbf_cli_gen_key(NULL, req, keystr, sizeof(keystr));
	cfs_hash_bd_get_and_lock(hs, (void *)keystr, &bd, 1);
	cli = nrs_tbf_cli_hash_lookup(hs, &bd, keystr);
	cfs_hash_bd_unlock(hs, &bd, 1);

	return cli;
}

static struct nrs_tbf_client *
nrs_tbf_cli_findadd(struct nrs_tbf_head *head,
		    struct nrs_tbf_client *cli)
{
	const char		*key;
	struct nrs_tbf_client	*ret;
	struct cfs_hash		*hs = head->th_cli_hash;
	struct cfs_hash_bd	 bd;

	key = cli->tc_key;
	cfs_hash_bd_get_and_lock(hs, (void *)key, &bd, 1);
	ret = nrs_tbf_cli_hash_lookup(hs, &bd, key);
	if (ret == NULL) {
		cfs_hash_bd_add_locked(hs, &bd, &cli->tc_hnode);
		ret = cli;
	}
	cfs_hash_bd_unlock(hs, &bd, 1);

	return ret;
}

static void
nrs_tbf_cli_put(struct nrs_tbf_head *head, struct nrs_tbf_client *cli)
{
	struct cfs_hash_bd	 bd;
	struct cfs_hash		*hs = head->th_cli_hash;
	struct nrs_tbf_bucket	*bkt;
	int			 hw;
	LIST_HEAD(zombies);

	cfs_hash_bd_get(hs, &cli->tc_key, &bd);
	bkt = cfs_hash_bd_extra_get(hs, &bd);
	if (!cfs_hash_bd_dec_and_lock(hs, &bd, &cli->tc_ref))
		return;
	LASSERT(list_empty(&cli->tc_lru));
	list_add_tail(&cli->tc_lru, &bkt->ntb_lru);

	/**
	 * Check and purge the LRU, there is at least one client in the LRU.
	 */
	hw = tbf_jobid_cache_size >> (hs->hs_cur_bits - hs->hs_bkt_bits);
	while (cfs_hash_bd_count_get(&bd) > hw) {
		if (unlikely(list_empty(&bkt->ntb_lru)))
			break;
		cli = list_entry(bkt->ntb_lru.next,
				 struct nrs_tbf_client,
				 tc_lru);
		LASSERT(atomic_read(&cli->tc_ref) == 0);
		cfs_hash_bd_del_locked(hs, &bd, &cli->tc_hnode);
		list_move(&cli->tc_lru, &zombies);
	}
	cfs_hash_bd_unlock(head->th_cli_hash, &bd, 1);

	while (!list_empty(&zombies)) {
		cli = container_of(zombies.next,
				   struct nrs_tbf_client, tc_lru);
		list_del_init(&cli->tc_lru);
		nrs_tbf_cli_fini(cli);
	}
}

static void
nrs_tbf_generic_cli_init(struct nrs_tbf_client *cli,
			 struct ptlrpc_request *req)
{
	char keystr[NRS_TBF_KEY_LEN];

	nrs_tbf_cli_gen_key(cli, req, keystr, sizeof(keystr));
}

static void
nrs_tbf_id_list_free(struct list_head *uid_list)
{
	struct nrs_tbf_id *nti_id, *n;

	list_for_each_entry_safe(nti_id, n, uid_list, nti_linkage) {
		list_del_init(&nti_id->nti_linkage);
		OBD_FREE_PTR(nti_id);
	}
}

static void
nrs_tbf_expression_free(struct nrs_tbf_expression *expr)
{
	LASSERT(expr->te_field >= NRS_TBF_FIELD_NID &&
		expr->te_field < NRS_TBF_FIELD_MAX);
	switch (expr->te_field) {
	case NRS_TBF_FIELD_NID:
		cfs_free_nidlist(&expr->te_cond);
		break;
	case NRS_TBF_FIELD_JOBID:
		nrs_tbf_jobid_list_free(&expr->te_cond);
		break;
	case NRS_TBF_FIELD_OPCODE:
		CFS_FREE_BITMAP(expr->te_opcodes);
		break;
	case NRS_TBF_FIELD_UID:
	case NRS_TBF_FIELD_GID:
		nrs_tbf_id_list_free(&expr->te_cond);
		break;
	default:
		LBUG();
	}
	OBD_FREE_PTR(expr);
}

static void
nrs_tbf_conjunction_free(struct nrs_tbf_conjunction *conjunction)
{
	struct nrs_tbf_expression *expression;
	struct nrs_tbf_expression *n;

	LASSERT(list_empty(&conjunction->tc_linkage));
	list_for_each_entry_safe(expression, n,
				 &conjunction->tc_expressions,
				 te_linkage) {
		list_del_init(&expression->te_linkage);
		nrs_tbf_expression_free(expression);
	}
	OBD_FREE_PTR(conjunction);
}

static void
nrs_tbf_conds_free(struct list_head *cond_list)
{
	struct nrs_tbf_conjunction *conjunction;
	struct nrs_tbf_conjunction *n;

	list_for_each_entry_safe(conjunction, n, cond_list, tc_linkage) {
		list_del_init(&conjunction->tc_linkage);
		nrs_tbf_conjunction_free(conjunction);
	}
}

static void
nrs_tbf_generic_cmd_fini(struct nrs_tbf_cmd *cmd)
{
	if (!list_empty(&cmd->u.tc_start.ts_conds))
		nrs_tbf_conds_free(&cmd->u.tc_start.ts_conds);
	if (cmd->u.tc_start.ts_conds_str)
		OBD_FREE(cmd->u.tc_start.ts_conds_str,
			 strlen(cmd->u.tc_start.ts_conds_str) + 1);
}

#define NRS_TBF_DISJUNCTION_DELIM	(',')
#define NRS_TBF_CONJUNCTION_DELIM	('&')
#define NRS_TBF_EXPRESSION_DELIM	('=')

static inline bool
nrs_tbf_check_field(struct cfs_lstr *field, char *str)
{
	int len = strlen(str);

	return (field->ls_len == len &&
		strncmp(field->ls_str, str, len) == 0);
}

static int
nrs_tbf_opcode_list_parse(char *str, int len, struct cfs_bitmap **bitmaptr);
static int
nrs_tbf_id_list_parse(char *str, int len, struct list_head *id_list,
		      enum nrs_tbf_flag tif);

static int
nrs_tbf_expression_parse(struct cfs_lstr *src, struct list_head *cond_list)
{
	struct nrs_tbf_expression *expr;
	struct cfs_lstr field;
	int rc = 0;

	OBD_ALLOC_PTR(expr);
	if (expr == NULL)
		return -ENOMEM;

	rc = cfs_gettok(src, NRS_TBF_EXPRESSION_DELIM, &field);
	if (rc == 0 || src->ls_len <= 2 || src->ls_str[0] != '{' ||
	    src->ls_str[src->ls_len - 1] != '}')
		GOTO(out, rc = -EINVAL);

	/* Skip '{' and '}' */
	src->ls_str++;
	src->ls_len -= 2;

	if (nrs_tbf_check_field(&field, "nid")) {
		if (cfs_parse_nidlist(src->ls_str,
				      src->ls_len,
				      &expr->te_cond) <= 0)
			GOTO(out, rc = -EINVAL);
		expr->te_field = NRS_TBF_FIELD_NID;
	} else if (nrs_tbf_check_field(&field, "jobid")) {
		if (nrs_tbf_jobid_list_parse(src->ls_str,
					     src->ls_len,
					     &expr->te_cond) < 0)
			GOTO(out, rc = -EINVAL);
		expr->te_field = NRS_TBF_FIELD_JOBID;
	} else if (nrs_tbf_check_field(&field, "opcode")) {
		if (nrs_tbf_opcode_list_parse(src->ls_str,
					      src->ls_len,
					      &expr->te_opcodes) < 0)
			GOTO(out, rc = -EINVAL);
		expr->te_field = NRS_TBF_FIELD_OPCODE;
	} else if (nrs_tbf_check_field(&field, "uid")) {
		if (nrs_tbf_id_list_parse(src->ls_str,
					  src->ls_len,
					  &expr->te_cond,
					  NRS_TBF_FLAG_UID) < 0)
			GOTO(out, rc = -EINVAL);
		expr->te_field = NRS_TBF_FIELD_UID;
	} else if (nrs_tbf_check_field(&field, "gid")) {
		if (nrs_tbf_id_list_parse(src->ls_str,
					  src->ls_len,
					  &expr->te_cond,
					  NRS_TBF_FLAG_GID) < 0)
			GOTO(out, rc = -EINVAL);
		expr->te_field = NRS_TBF_FIELD_GID;
	} else {
		GOTO(out, rc = -EINVAL);
	}

	list_add_tail(&expr->te_linkage, cond_list);
	return 0;
out:
	OBD_FREE_PTR(expr);
	return rc;
}

static int
nrs_tbf_conjunction_parse(struct cfs_lstr *src, struct list_head *cond_list)
{
	struct nrs_tbf_conjunction *conjunction;
	struct cfs_lstr expr;
	int rc = 0;

	OBD_ALLOC_PTR(conjunction);
	if (conjunction == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&conjunction->tc_expressions);
	list_add_tail(&conjunction->tc_linkage, cond_list);

	while (src->ls_str) {
		rc = cfs_gettok(src, NRS_TBF_CONJUNCTION_DELIM, &expr);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = nrs_tbf_expression_parse(&expr,
					      &conjunction->tc_expressions);
		if (rc)
			break;
	}
	return rc;
}

static int
nrs_tbf_conds_parse(char *str, int len, struct list_head *cond_list)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;

	src.ls_str = str;
	src.ls_len = len;
	INIT_LIST_HEAD(cond_list);
	while (src.ls_str) {
		rc = cfs_gettok(&src, NRS_TBF_DISJUNCTION_DELIM, &res);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = nrs_tbf_conjunction_parse(&res, cond_list);
		if (rc)
			break;
	}
	return rc;
}

static int
nrs_tbf_generic_parse(struct nrs_tbf_cmd *cmd, const char *id)
{
	int rc;

	OBD_ALLOC(cmd->u.tc_start.ts_conds_str, strlen(id) + 1);
	if (cmd->u.tc_start.ts_conds_str == NULL)
		return -ENOMEM;

	memcpy(cmd->u.tc_start.ts_conds_str, id, strlen(id));

	/* Parse hybird NID and JOBID conditions */
	rc = nrs_tbf_conds_parse(cmd->u.tc_start.ts_conds_str,
				 strlen(cmd->u.tc_start.ts_conds_str),
				 &cmd->u.tc_start.ts_conds);
	if (rc)
		nrs_tbf_generic_cmd_fini(cmd);

	return rc;
}

static int
nrs_tbf_id_list_match(struct list_head *id_list, struct tbf_id id);

static int
nrs_tbf_expression_match(struct nrs_tbf_expression *expr,
			 struct nrs_tbf_rule *rule,
			 struct nrs_tbf_client *cli)
{
	switch (expr->te_field) {
	case NRS_TBF_FIELD_NID:
		return cfs_match_nid(cli->tc_nid, &expr->te_cond);
	case NRS_TBF_FIELD_JOBID:
		return nrs_tbf_jobid_list_match(&expr->te_cond, cli->tc_jobid);
	case NRS_TBF_FIELD_OPCODE:
		return cfs_bitmap_check(expr->te_opcodes, cli->tc_opcode);
	case NRS_TBF_FIELD_UID:
	case NRS_TBF_FIELD_GID:
		return nrs_tbf_id_list_match(&expr->te_cond, cli->tc_id);
	default:
		return 0;
	}
}

static int
nrs_tbf_conjunction_match(struct nrs_tbf_conjunction *conjunction,
			  struct nrs_tbf_rule *rule,
			  struct nrs_tbf_client *cli)
{
	struct nrs_tbf_expression *expr;
	int matched;

	list_for_each_entry(expr, &conjunction->tc_expressions, te_linkage) {
		matched = nrs_tbf_expression_match(expr, rule, cli);
		if (!matched)
			return 0;
	}

	return 1;
}

static int
nrs_tbf_cond_match(struct nrs_tbf_rule *rule, struct nrs_tbf_client *cli)
{
	struct nrs_tbf_conjunction *conjunction;
	int matched;

	list_for_each_entry(conjunction, &rule->tr_conds, tc_linkage) {
		matched = nrs_tbf_conjunction_match(conjunction, rule, cli);
		if (matched)
			return 1;
	}

	return 0;
}

static void
nrs_tbf_generic_rule_fini(struct nrs_tbf_rule *rule)
{
	if (!list_empty(&rule->tr_conds))
		nrs_tbf_conds_free(&rule->tr_conds);
	LASSERT(rule->tr_conds_str != NULL);
	OBD_FREE(rule->tr_conds_str, strlen(rule->tr_conds_str) + 1);
}

static int
nrs_tbf_rule_init(struct ptlrpc_nrs_policy *policy,
		  struct nrs_tbf_rule *rule, struct nrs_tbf_cmd *start)
{
	int rc = 0;

	LASSERT(start->u.tc_start.ts_conds_str);
	OBD_ALLOC(rule->tr_conds_str,
		  strlen(start->u.tc_start.ts_conds_str) + 1);
	if (rule->tr_conds_str == NULL)
		return -ENOMEM;

	memcpy(rule->tr_conds_str,
	       start->u.tc_start.ts_conds_str,
	       strlen(start->u.tc_start.ts_conds_str));

	INIT_LIST_HEAD(&rule->tr_conds);
	if (!list_empty(&start->u.tc_start.ts_conds)) {
		rc = nrs_tbf_conds_parse(rule->tr_conds_str,
					 strlen(rule->tr_conds_str),
					 &rule->tr_conds);
	}
	if (rc)
		nrs_tbf_generic_rule_fini(rule);

	return rc;
}

static int
nrs_tbf_generic_rule_dump(struct nrs_tbf_rule *rule, struct seq_file *m)
{
	seq_printf(m, "%s %s %u, ref %d\n", rule->tr_name,
		   rule->tr_conds_str, rule->tr_rpc_rate,
		   atomic_read(&rule->tr_ref) - 1);
	return 0;
}

static int
nrs_tbf_generic_rule_match(struct nrs_tbf_rule *rule,
			   struct nrs_tbf_client *cli)
{
	return nrs_tbf_cond_match(rule, cli);
}

static struct nrs_tbf_ops nrs_tbf_generic_ops = {
	.o_name = NRS_TBF_TYPE_GENERIC,
	.o_startup = nrs_tbf_startup,
	.o_cli_find = nrs_tbf_cli_find,
	.o_cli_findadd = nrs_tbf_cli_findadd,
	.o_cli_put = nrs_tbf_cli_put,
	.o_cli_init = nrs_tbf_generic_cli_init,
	.o_rule_init = nrs_tbf_rule_init,
	.o_rule_dump = nrs_tbf_generic_rule_dump,
	.o_rule_match = nrs_tbf_generic_rule_match,
	.o_rule_fini = nrs_tbf_generic_rule_fini,
};

static void nrs_tbf_opcode_rule_fini(struct nrs_tbf_rule *rule)
{
	if (rule->tr_opcodes != NULL)
		CFS_FREE_BITMAP(rule->tr_opcodes);

	LASSERT(rule->tr_opcodes_str != NULL);
	OBD_FREE(rule->tr_opcodes_str, strlen(rule->tr_opcodes_str) + 1);
}

static unsigned nrs_tbf_opcode_hop_hash(struct cfs_hash *hs, const void *key,
					unsigned mask)
{
	return cfs_hash_djb2_hash(key, sizeof(__u32), mask);
}

static int nrs_tbf_opcode_hop_keycmp(const void *key, struct hlist_node *hnode)
{
	const __u32	*opc = key;
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	return *opc == cli->tc_opcode;
}

static void *nrs_tbf_opcode_hop_key(struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	return &cli->tc_opcode;
}

static void nrs_tbf_opcode_hop_get(struct cfs_hash *hs,
				   struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	atomic_inc(&cli->tc_ref);
}

static void nrs_tbf_opcode_hop_put(struct cfs_hash *hs,
				   struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	atomic_dec(&cli->tc_ref);
}

static void nrs_tbf_opcode_hop_exit(struct cfs_hash *hs,
				    struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	LASSERTF(atomic_read(&cli->tc_ref) == 0,
		 "Busy TBF object from client with opcode %s, with %d refs\n",
		 ll_opcode2str(cli->tc_opcode),
		 atomic_read(&cli->tc_ref));

	nrs_tbf_cli_fini(cli);
}
static struct cfs_hash_ops nrs_tbf_opcode_hash_ops = {
	.hs_hash	= nrs_tbf_opcode_hop_hash,
	.hs_keycmp	= nrs_tbf_opcode_hop_keycmp,
	.hs_key		= nrs_tbf_opcode_hop_key,
	.hs_object	= nrs_tbf_hop_object,
	.hs_get		= nrs_tbf_opcode_hop_get,
	.hs_put		= nrs_tbf_opcode_hop_put,
	.hs_put_locked	= nrs_tbf_opcode_hop_put,
	.hs_exit	= nrs_tbf_opcode_hop_exit,
};

static int
nrs_tbf_opcode_startup(struct ptlrpc_nrs_policy *policy,
		    struct nrs_tbf_head *head)
{
	struct nrs_tbf_cmd	start = { 0 };
	int rc;

	head->th_cli_hash = cfs_hash_create("nrs_tbf_hash",
					    NRS_TBF_NID_BITS,
					    NRS_TBF_NID_BITS,
					    NRS_TBF_NID_BKT_BITS, 0,
					    CFS_HASH_MIN_THETA,
					    CFS_HASH_MAX_THETA,
					    &nrs_tbf_opcode_hash_ops,
					    CFS_HASH_RW_BKTLOCK);
	if (head->th_cli_hash == NULL)
		return -ENOMEM;

	start.u.tc_start.ts_opcodes_str = "*";

	start.u.tc_start.ts_rpc_rate = tbf_rate;
	start.u.tc_start.ts_rule_flags = NTRS_DEFAULT;
	start.tc_name = NRS_TBF_DEFAULT_RULE;
	rc = nrs_tbf_rule_start(policy, head, &start);

	return rc;
}

static struct nrs_tbf_client *
nrs_tbf_opcode_cli_find(struct nrs_tbf_head *head,
			struct ptlrpc_request *req)
{
	__u32 opc;

	opc = lustre_msg_get_opc(req->rq_reqmsg);
	return cfs_hash_lookup(head->th_cli_hash, &opc);
}

static struct nrs_tbf_client *
nrs_tbf_opcode_cli_findadd(struct nrs_tbf_head *head,
			   struct nrs_tbf_client *cli)
{
	return cfs_hash_findadd_unique(head->th_cli_hash, &cli->tc_opcode,
				       &cli->tc_hnode);
}

static void
nrs_tbf_opcode_cli_init(struct nrs_tbf_client *cli,
			struct ptlrpc_request *req)
{
	cli->tc_opcode = lustre_msg_get_opc(req->rq_reqmsg);
}

#define MAX_OPCODE_LEN	32
static int
nrs_tbf_opcode_set_bit(const struct cfs_lstr *id, struct cfs_bitmap *opcodes)
{
	int	op = 0;
	char	opcode_str[MAX_OPCODE_LEN];

	if (id->ls_len + 1 > MAX_OPCODE_LEN)
		return -EINVAL;

	memcpy(opcode_str, id->ls_str, id->ls_len);
	opcode_str[id->ls_len] = '\0';

	op = ll_str2opcode(opcode_str);
	if (op < 0)
		return -EINVAL;

	cfs_bitmap_set(opcodes, op);
	return 0;
}

static int
nrs_tbf_opcode_list_parse(char *str, int len, struct cfs_bitmap **bitmaptr)
{
	struct cfs_bitmap *opcodes;
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;
	ENTRY;

	opcodes = CFS_ALLOCATE_BITMAP(LUSTRE_MAX_OPCODES);
	if (opcodes == NULL)
		return -ENOMEM;

	src.ls_str = str;
	src.ls_len = len;
	while (src.ls_str) {
		rc = cfs_gettok(&src, ' ', &res);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = nrs_tbf_opcode_set_bit(&res, opcodes);
		if (rc)
			break;
	}

	if (rc == 0 && bitmaptr)
		*bitmaptr = opcodes;
	else
		CFS_FREE_BITMAP(opcodes);

	RETURN(rc);
}

static void nrs_tbf_opcode_cmd_fini(struct nrs_tbf_cmd *cmd)
{
	if (cmd->u.tc_start.ts_opcodes_str)
		OBD_FREE(cmd->u.tc_start.ts_opcodes_str,
			 strlen(cmd->u.tc_start.ts_opcodes_str) + 1);

}

static int nrs_tbf_opcode_parse(struct nrs_tbf_cmd *cmd, char *id)
{
	struct cfs_lstr src;
	int rc;

	src.ls_str = id;
	src.ls_len = strlen(id);
	rc = nrs_tbf_check_id_value(&src, "opcode");
	if (rc)
		return rc;

	OBD_ALLOC(cmd->u.tc_start.ts_opcodes_str, src.ls_len + 1);
	if (cmd->u.tc_start.ts_opcodes_str == NULL)
		return -ENOMEM;

	memcpy(cmd->u.tc_start.ts_opcodes_str, src.ls_str, src.ls_len);

	/* parse opcode list */
	rc = nrs_tbf_opcode_list_parse(cmd->u.tc_start.ts_opcodes_str,
				       strlen(cmd->u.tc_start.ts_opcodes_str),
				       NULL);
	if (rc)
		nrs_tbf_opcode_cmd_fini(cmd);

	return rc;
}

static int
nrs_tbf_opcode_rule_match(struct nrs_tbf_rule *rule,
			  struct nrs_tbf_client *cli)
{
	if (rule->tr_opcodes == NULL)
		return 0;

	return cfs_bitmap_check(rule->tr_opcodes, cli->tc_opcode);
}

static int nrs_tbf_opcode_rule_init(struct ptlrpc_nrs_policy *policy,
				    struct nrs_tbf_rule *rule,
				    struct nrs_tbf_cmd *start)
{
	int rc = 0;

	LASSERT(start->u.tc_start.ts_opcodes_str != NULL);
	OBD_ALLOC(rule->tr_opcodes_str,
		  strlen(start->u.tc_start.ts_opcodes_str) + 1);
	if (rule->tr_opcodes_str == NULL)
		return -ENOMEM;

	strncpy(rule->tr_opcodes_str, start->u.tc_start.ts_opcodes_str,
		strlen(start->u.tc_start.ts_opcodes_str) + 1);

	/* Default rule '*' */
	if (strcmp(start->u.tc_start.ts_opcodes_str, "*") == 0)
		return 0;

	rc = nrs_tbf_opcode_list_parse(rule->tr_opcodes_str,
				       strlen(rule->tr_opcodes_str),
				       &rule->tr_opcodes);
	if (rc)
		OBD_FREE(rule->tr_opcodes_str,
			 strlen(start->u.tc_start.ts_opcodes_str) + 1);

	return rc;
}

static int
nrs_tbf_opcode_rule_dump(struct nrs_tbf_rule *rule, struct seq_file *m)
{
	seq_printf(m, "%s {%s} %u, ref %d\n", rule->tr_name,
		   rule->tr_opcodes_str, rule->tr_rpc_rate,
		   atomic_read(&rule->tr_ref) - 1);
	return 0;
}


struct nrs_tbf_ops nrs_tbf_opcode_ops = {
	.o_name = NRS_TBF_TYPE_OPCODE,
	.o_startup = nrs_tbf_opcode_startup,
	.o_cli_find = nrs_tbf_opcode_cli_find,
	.o_cli_findadd = nrs_tbf_opcode_cli_findadd,
	.o_cli_put = nrs_tbf_nid_cli_put,
	.o_cli_init = nrs_tbf_opcode_cli_init,
	.o_rule_init = nrs_tbf_opcode_rule_init,
	.o_rule_dump = nrs_tbf_opcode_rule_dump,
	.o_rule_match = nrs_tbf_opcode_rule_match,
	.o_rule_fini = nrs_tbf_opcode_rule_fini,
};

static unsigned nrs_tbf_id_hop_hash(struct cfs_hash *hs, const void *key,
				    unsigned mask)
{
	return cfs_hash_djb2_hash(key, sizeof(struct tbf_id), mask);
}

static int nrs_tbf_id_hop_keycmp(const void *key, struct hlist_node *hnode)
{
	const struct tbf_id *opc = key;
	enum nrs_tbf_flag ntf;
	struct nrs_tbf_client *cli = hlist_entry(hnode, struct nrs_tbf_client,
						 tc_hnode);
	ntf = opc->ti_type & cli->tc_id.ti_type;
	if ((ntf & NRS_TBF_FLAG_UID) && opc->ti_uid != cli->tc_id.ti_uid)
		return 0;

	if ((ntf & NRS_TBF_FLAG_GID) && opc->ti_gid != cli->tc_id.ti_gid)
		return 0;

	return 1;
}

static void *nrs_tbf_id_hop_key(struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);
	return &cli->tc_id;
}

static void nrs_tbf_id_hop_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	atomic_inc(&cli->tc_ref);
}

static void nrs_tbf_id_hop_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	atomic_dec(&cli->tc_ref);
}

static void
nrs_tbf_id_hop_exit(struct cfs_hash *hs, struct hlist_node *hnode)

{
	struct nrs_tbf_client *cli = hlist_entry(hnode,
						 struct nrs_tbf_client,
						 tc_hnode);

	LASSERT(atomic_read(&cli->tc_ref) == 0);
	nrs_tbf_cli_fini(cli);
}

static struct cfs_hash_ops nrs_tbf_id_hash_ops = {
	.hs_hash	= nrs_tbf_id_hop_hash,
	.hs_keycmp	= nrs_tbf_id_hop_keycmp,
	.hs_key		= nrs_tbf_id_hop_key,
	.hs_object	= nrs_tbf_hop_object,
	.hs_get		= nrs_tbf_id_hop_get,
	.hs_put		= nrs_tbf_id_hop_put,
	.hs_put_locked	= nrs_tbf_id_hop_put,
	.hs_exit	= nrs_tbf_id_hop_exit,
};

static int
nrs_tbf_id_startup(struct ptlrpc_nrs_policy *policy,
		   struct nrs_tbf_head *head)
{
	struct nrs_tbf_cmd start;
	int rc;

	head->th_cli_hash = cfs_hash_create("nrs_tbf_id_hash",
					    NRS_TBF_NID_BITS,
					    NRS_TBF_NID_BITS,
					    NRS_TBF_NID_BKT_BITS, 0,
					    CFS_HASH_MIN_THETA,
					    CFS_HASH_MAX_THETA,
					    &nrs_tbf_id_hash_ops,
					    CFS_HASH_RW_BKTLOCK);
	if (head->th_cli_hash == NULL)
		return -ENOMEM;

	memset(&start, 0, sizeof(start));
	start.u.tc_start.ts_ids_str = "*";
	start.u.tc_start.ts_rpc_rate = tbf_rate;
	start.u.tc_start.ts_rule_flags = NTRS_DEFAULT;
	start.tc_name = NRS_TBF_DEFAULT_RULE;
	INIT_LIST_HEAD(&start.u.tc_start.ts_ids);
	rc = nrs_tbf_rule_start(policy, head, &start);
	if (rc) {
		cfs_hash_putref(head->th_cli_hash);
		head->th_cli_hash = NULL;
	}

	return rc;
}

static struct nrs_tbf_client *
nrs_tbf_id_cli_find(struct nrs_tbf_head *head,
		    struct ptlrpc_request *req)
{
	struct tbf_id id;

	LASSERT(head->th_type_flag == NRS_TBF_FLAG_UID ||
		head->th_type_flag == NRS_TBF_FLAG_GID);

	nrs_tbf_id_cli_set(req, &id, head->th_type_flag);
	return cfs_hash_lookup(head->th_cli_hash, &id);
}

static struct nrs_tbf_client *
nrs_tbf_id_cli_findadd(struct nrs_tbf_head *head,
		       struct nrs_tbf_client *cli)
{
	return cfs_hash_findadd_unique(head->th_cli_hash, &cli->tc_id,
				       &cli->tc_hnode);
}

static void
nrs_tbf_uid_cli_init(struct nrs_tbf_client *cli,
		     struct ptlrpc_request *req)
{
	nrs_tbf_id_cli_set(req, &cli->tc_id, NRS_TBF_FLAG_UID);
}

static void
nrs_tbf_gid_cli_init(struct nrs_tbf_client *cli,
		     struct ptlrpc_request *req)
{
	nrs_tbf_id_cli_set(req, &cli->tc_id, NRS_TBF_FLAG_GID);
}

static int
nrs_tbf_id_list_match(struct list_head *id_list, struct tbf_id id)
{
	struct nrs_tbf_id *nti_id;
	enum nrs_tbf_flag flag;

	list_for_each_entry(nti_id, id_list, nti_linkage) {
		flag = id.ti_type & nti_id->nti_id.ti_type;
		if (!flag)
			continue;

		if ((flag & NRS_TBF_FLAG_UID) &&
		    (id.ti_uid != nti_id->nti_id.ti_uid))
			continue;

		if ((flag & NRS_TBF_FLAG_GID) &&
		    (id.ti_gid != nti_id->nti_id.ti_gid))
			continue;

		return 1;
	}
	return 0;
}

static int
nrs_tbf_id_rule_match(struct nrs_tbf_rule *rule,
		      struct nrs_tbf_client *cli)
{
	return nrs_tbf_id_list_match(&rule->tr_ids, cli->tc_id);
}

static void nrs_tbf_id_cmd_fini(struct nrs_tbf_cmd *cmd)
{
	nrs_tbf_id_list_free(&cmd->u.tc_start.ts_ids);

	if (cmd->u.tc_start.ts_ids_str)
		OBD_FREE(cmd->u.tc_start.ts_ids_str,
			 strlen(cmd->u.tc_start.ts_ids_str) + 1);
}

static int
nrs_tbf_id_list_parse(char *str, int len, struct list_head *id_list,
		      enum nrs_tbf_flag tif)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;
	struct tbf_id id = { 0 };
	ENTRY;

	if (tif != NRS_TBF_FLAG_UID && tif != NRS_TBF_FLAG_GID)
		RETURN(-EINVAL);

	src.ls_str = str;
	src.ls_len = len;
	INIT_LIST_HEAD(id_list);
	while (src.ls_str) {
		struct nrs_tbf_id *nti_id;

		if (cfs_gettok(&src, ' ', &res) == 0)
			GOTO(out, rc = -EINVAL);

		id.ti_type = tif;
		if (tif == NRS_TBF_FLAG_UID) {
			if (!cfs_str2num_check(res.ls_str, res.ls_len,
					       &id.ti_uid, 0, (u32)~0U))
				GOTO(out, rc = -EINVAL);
		} else {
			if (!cfs_str2num_check(res.ls_str, res.ls_len,
					       &id.ti_gid, 0, (u32)~0U))
				GOTO(out, rc = -EINVAL);
		}

		OBD_ALLOC_PTR(nti_id);
		if (nti_id == NULL)
			GOTO(out, rc = -ENOMEM);

		nti_id->nti_id = id;
		list_add_tail(&nti_id->nti_linkage, id_list);
	}
out:
	if (rc)
		nrs_tbf_id_list_free(id_list);
	RETURN(rc);
}

static int nrs_tbf_ug_id_parse(struct nrs_tbf_cmd *cmd, char *id)
{
	struct cfs_lstr src;
	int rc;
	enum nrs_tbf_flag tif;

	tif = cmd->u.tc_start.ts_valid_type;

	src.ls_str = id;
	src.ls_len = strlen(id);

	rc = nrs_tbf_check_id_value(&src,
				    tif == NRS_TBF_FLAG_UID ? "uid" : "gid");
	if (rc)
		return rc;

	OBD_ALLOC(cmd->u.tc_start.ts_ids_str, src.ls_len + 1);
	if (cmd->u.tc_start.ts_ids_str == NULL)
		return -ENOMEM;

	strlcpy(cmd->u.tc_start.ts_ids_str, src.ls_str, src.ls_len + 1);

	rc = nrs_tbf_id_list_parse(cmd->u.tc_start.ts_ids_str,
				   strlen(cmd->u.tc_start.ts_ids_str),
				   &cmd->u.tc_start.ts_ids, tif);
	if (rc)
		nrs_tbf_id_cmd_fini(cmd);

	return rc;
}

static int
nrs_tbf_id_rule_init(struct ptlrpc_nrs_policy *policy,
		     struct nrs_tbf_rule *rule,
		     struct nrs_tbf_cmd *start)
{
	struct nrs_tbf_head *head = rule->tr_head;
	int rc = 0;
	enum nrs_tbf_flag tif = head->th_type_flag;
	int ids_len = strlen(start->u.tc_start.ts_ids_str) + 1;

	LASSERT(start->u.tc_start.ts_ids_str);
	INIT_LIST_HEAD(&rule->tr_ids);

	OBD_ALLOC(rule->tr_ids_str, ids_len);
	if (rule->tr_ids_str == NULL)
		return -ENOMEM;

	strlcpy(rule->tr_ids_str, start->u.tc_start.ts_ids_str,
		ids_len);

	if (!list_empty(&start->u.tc_start.ts_ids)) {
		rc = nrs_tbf_id_list_parse(rule->tr_ids_str,
					   strlen(rule->tr_ids_str),
					   &rule->tr_ids, tif);
		if (rc)
			CERROR("%ss {%s} illegal\n",
			       tif == NRS_TBF_FLAG_UID ? "uid" : "gid",
			       rule->tr_ids_str);
	}
	if (rc) {
		OBD_FREE(rule->tr_ids_str, ids_len);
		rule->tr_ids_str = NULL;
	}
	return rc;
}

static int
nrs_tbf_id_rule_dump(struct nrs_tbf_rule *rule, struct seq_file *m)
{
	seq_printf(m, "%s {%s} %u, ref %d\n", rule->tr_name,
		   rule->tr_ids_str, rule->tr_rpc_rate,
		   atomic_read(&rule->tr_ref) - 1);
	return 0;
}

static void nrs_tbf_id_rule_fini(struct nrs_tbf_rule *rule)
{
	nrs_tbf_id_list_free(&rule->tr_ids);
	if (rule->tr_ids_str != NULL)
		OBD_FREE(rule->tr_ids_str, strlen(rule->tr_ids_str) + 1);
}

struct nrs_tbf_ops nrs_tbf_uid_ops = {
	.o_name = NRS_TBF_TYPE_UID,
	.o_startup = nrs_tbf_id_startup,
	.o_cli_find = nrs_tbf_id_cli_find,
	.o_cli_findadd = nrs_tbf_id_cli_findadd,
	.o_cli_put = nrs_tbf_nid_cli_put,
	.o_cli_init = nrs_tbf_uid_cli_init,
	.o_rule_init = nrs_tbf_id_rule_init,
	.o_rule_dump = nrs_tbf_id_rule_dump,
	.o_rule_match = nrs_tbf_id_rule_match,
	.o_rule_fini = nrs_tbf_id_rule_fini,
};

struct nrs_tbf_ops nrs_tbf_gid_ops = {
	.o_name = NRS_TBF_TYPE_GID,
	.o_startup = nrs_tbf_id_startup,
	.o_cli_find = nrs_tbf_id_cli_find,
	.o_cli_findadd = nrs_tbf_id_cli_findadd,
	.o_cli_put = nrs_tbf_nid_cli_put,
	.o_cli_init = nrs_tbf_gid_cli_init,
	.o_rule_init = nrs_tbf_id_rule_init,
	.o_rule_dump = nrs_tbf_id_rule_dump,
	.o_rule_match = nrs_tbf_id_rule_match,
	.o_rule_fini = nrs_tbf_id_rule_fini,
};

static struct nrs_tbf_type nrs_tbf_types[] = {
	{
		.ntt_name = NRS_TBF_TYPE_JOBID,
		.ntt_flag = NRS_TBF_FLAG_JOBID,
		.ntt_ops = &nrs_tbf_jobid_ops,
	},
	{
		.ntt_name = NRS_TBF_TYPE_NID,
		.ntt_flag = NRS_TBF_FLAG_NID,
		.ntt_ops = &nrs_tbf_nid_ops,
	},
	{
		.ntt_name = NRS_TBF_TYPE_OPCODE,
		.ntt_flag = NRS_TBF_FLAG_OPCODE,
		.ntt_ops = &nrs_tbf_opcode_ops,
	},
	{
		.ntt_name = NRS_TBF_TYPE_GENERIC,
		.ntt_flag = NRS_TBF_FLAG_GENERIC,
		.ntt_ops = &nrs_tbf_generic_ops,
	},
	{
		.ntt_name = NRS_TBF_TYPE_UID,
		.ntt_flag = NRS_TBF_FLAG_UID,
		.ntt_ops = &nrs_tbf_uid_ops,
	},
	{
		.ntt_name = NRS_TBF_TYPE_GID,
		.ntt_flag = NRS_TBF_FLAG_GID,
		.ntt_ops = &nrs_tbf_gid_ops,
	},
};

/**
 * Is called before the policy transitions into
 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STARTED; allocates and initializes a
 * policy-specific private data structure.
 *
 * \param[in] policy The policy to start
 *
 * \retval -ENOMEM OOM error
 * \retval  0	   success
 *
 * \see nrs_policy_register()
 * \see nrs_policy_ctl()
 */
static int nrs_tbf_start(struct ptlrpc_nrs_policy *policy, char *arg)
{
	struct nrs_tbf_head	*head;
	struct nrs_tbf_ops	*ops;
	__u32			 type;
	char			*name;
	int found = 0;
	int i;
	int rc = 0;

	if (arg == NULL)
		name = NRS_TBF_TYPE_GENERIC;
	else if (strlen(arg) < NRS_TBF_TYPE_MAX_LEN)
		name = arg;
	else
		GOTO(out, rc = -EINVAL);

	for (i = 0; i < ARRAY_SIZE(nrs_tbf_types); i++) {
		if (strcmp(name, nrs_tbf_types[i].ntt_name) == 0) {
			ops = nrs_tbf_types[i].ntt_ops;
			type = nrs_tbf_types[i].ntt_flag;
			found = 1;
			break;
		}
	}
	if (found == 0)
		GOTO(out, rc = -ENOTSUPP);

	OBD_CPT_ALLOC_PTR(head, nrs_pol2cptab(policy), nrs_pol2cptid(policy));
	if (head == NULL)
		GOTO(out, rc = -ENOMEM);

	memcpy(head->th_type, name, strlen(name));
	head->th_type[strlen(name)] = '\0';
	head->th_ops = ops;
	head->th_type_flag = type;

	head->th_binheap = binheap_create(&nrs_tbf_heap_ops,
					  CBH_FLAG_ATOMIC_GROW, 4096, NULL,
					  nrs_pol2cptab(policy),
					  nrs_pol2cptid(policy));
	if (head->th_binheap == NULL)
		GOTO(out_free_head, rc = -ENOMEM);

	atomic_set(&head->th_rule_sequence, 0);
	spin_lock_init(&head->th_rule_lock);
	INIT_LIST_HEAD(&head->th_list);
	hrtimer_init(&head->th_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	head->th_timer.function = nrs_tbf_timer_cb;
	rc = head->th_ops->o_startup(policy, head);
	if (rc)
		GOTO(out_free_heap, rc);

	policy->pol_private = head;
	return 0;
out_free_heap:
	binheap_destroy(head->th_binheap);
out_free_head:
	OBD_FREE_PTR(head);
out:
	return rc;
}

/**
 * Is called before the policy transitions into
 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED; deallocates the policy-specific
 * private data structure.
 *
 * \param[in] policy The policy to stop
 *
 * \see nrs_policy_stop0()
 */
static void nrs_tbf_stop(struct ptlrpc_nrs_policy *policy)
{
	struct nrs_tbf_head *head = policy->pol_private;
	struct ptlrpc_nrs *nrs = policy->pol_nrs;
	struct nrs_tbf_rule *rule, *n;

	LASSERT(head != NULL);
	LASSERT(head->th_cli_hash != NULL);
	hrtimer_cancel(&head->th_timer);
	/* Should cleanup hash first before free rules */
	cfs_hash_putref(head->th_cli_hash);
	list_for_each_entry_safe(rule, n, &head->th_list, tr_linkage) {
		list_del_init(&rule->tr_linkage);
		nrs_tbf_rule_put(rule);
	}
	LASSERT(list_empty(&head->th_list));
	LASSERT(head->th_binheap != NULL);
	LASSERT(binheap_is_empty(head->th_binheap));
	binheap_destroy(head->th_binheap);
	OBD_FREE_PTR(head);
	nrs->nrs_throttling = 0;
	wake_up(&policy->pol_nrs->nrs_svcpt->scp_waitq);
}

/**
 * Performs a policy-specific ctl function on TBF policy instances; similar
 * to ioctl.
 *
 * \param[in]	  policy the policy instance
 * \param[in]	  opc	 the opcode
 * \param[in,out] arg	 used for passing parameters and information
 *
 * \pre assert_spin_locked(&policy->pol_nrs->->nrs_lock)
 * \post assert_spin_locked(&policy->pol_nrs->->nrs_lock)
 *
 * \retval 0   operation carried out successfully
 * \retval -ve error
 */
static int nrs_tbf_ctl(struct ptlrpc_nrs_policy *policy,
		       enum ptlrpc_nrs_ctl opc,
		       void *arg)
{
	int rc = 0;
	ENTRY;

	assert_spin_locked(&policy->pol_nrs->nrs_lock);

	switch ((enum nrs_ctl_tbf)opc) {
	default:
		RETURN(-EINVAL);

	/**
	 * Read RPC rate size of a policy instance.
	 */
	case NRS_CTL_TBF_RD_RULE: {
		struct nrs_tbf_head *head = policy->pol_private;
		struct seq_file *m = arg;
		struct ptlrpc_service_part *svcpt;

		svcpt = policy->pol_nrs->nrs_svcpt;
		seq_printf(m, "CPT %d:\n", svcpt->scp_cpt);

		rc = nrs_tbf_rule_dump_all(head, m);
		}
		break;

	/**
	 * Write RPC rate of a policy instance.
	 */
	case NRS_CTL_TBF_WR_RULE: {
		struct nrs_tbf_head *head = policy->pol_private;
		struct nrs_tbf_cmd *cmd;

		cmd = (struct nrs_tbf_cmd *)arg;
		rc = nrs_tbf_command(policy,
				     head,
				     cmd);
		}
		break;
	/**
	 * Read the TBF policy type of a policy instance.
	 */
	case NRS_CTL_TBF_RD_TYPE_FLAG: {
		struct nrs_tbf_head *head = policy->pol_private;

		*(__u32 *)arg = head->th_type_flag;
		}
		break;
	}

	RETURN(rc);
}

/**
 * Is called for obtaining a TBF policy resource.
 *
 * \param[in]  policy	  The policy on which the request is being asked for
 * \param[in]  nrq	  The request for which resources are being taken
 * \param[in]  parent	  Parent resource, unused in this policy
 * \param[out] resp	  Resources references are placed in this array
 * \param[in]  moving_req Signifies limited caller context; unused in this
 *			  policy
 *
 *
 * \see nrs_resource_get_safe()
 */
static int nrs_tbf_res_get(struct ptlrpc_nrs_policy *policy,
			   struct ptlrpc_nrs_request *nrq,
			   const struct ptlrpc_nrs_resource *parent,
			   struct ptlrpc_nrs_resource **resp,
			   bool moving_req)
{
	struct nrs_tbf_head   *head;
	struct nrs_tbf_client *cli;
	struct nrs_tbf_client *tmp;
	struct ptlrpc_request *req;

	if (parent == NULL) {
		*resp = &((struct nrs_tbf_head *)policy->pol_private)->th_res;
		return 0;
	}

	head = container_of(parent, struct nrs_tbf_head, th_res);
	req = container_of(nrq, struct ptlrpc_request, rq_nrq);
	cli = head->th_ops->o_cli_find(head, req);
	if (cli != NULL) {
		spin_lock(&policy->pol_nrs->nrs_svcpt->scp_req_lock);
		LASSERT(cli->tc_rule);
		if (cli->tc_rule_sequence !=
		    atomic_read(&head->th_rule_sequence) ||
		    cli->tc_rule->tr_flags & NTRS_STOPPING) {
			struct nrs_tbf_rule *rule;

			CDEBUG(D_RPCTRACE,
			       "TBF class@%p rate %u sequence %d, "
			       "rule flags %d, head sequence %d\n",
			       cli, cli->tc_rpc_rate,
			       cli->tc_rule_sequence,
			       cli->tc_rule->tr_flags,
			       atomic_read(&head->th_rule_sequence));
			rule = nrs_tbf_rule_match(head, cli);
			if (rule != cli->tc_rule) {
				nrs_tbf_cli_reset(head, rule, cli);
			} else {
				if (cli->tc_rule_generation != rule->tr_generation)
					nrs_tbf_cli_reset_value(head, cli);
				nrs_tbf_rule_put(rule);
			}
		} else if (cli->tc_rule_generation !=
			   cli->tc_rule->tr_generation) {
			nrs_tbf_cli_reset_value(head, cli);
		}
		spin_unlock(&policy->pol_nrs->nrs_svcpt->scp_req_lock);
		goto out;
	}

	OBD_CPT_ALLOC_GFP(cli, nrs_pol2cptab(policy), nrs_pol2cptid(policy),
			  sizeof(*cli), moving_req ? GFP_ATOMIC : __GFP_IO);
	if (cli == NULL)
		return -ENOMEM;

	nrs_tbf_cli_init(head, cli, req);
	tmp = head->th_ops->o_cli_findadd(head, cli);
	if (tmp != cli) {
		atomic_dec(&cli->tc_ref);
		nrs_tbf_cli_fini(cli);
		cli = tmp;
	}
out:
	*resp = &cli->tc_res;

	return 1;
}

/**
 * Called when releasing references to the resource hierachy obtained for a
 * request for scheduling using the TBF policy.
 *
 * \param[in] policy   the policy the resource belongs to
 * \param[in] res      the resource to be released
 */
static void nrs_tbf_res_put(struct ptlrpc_nrs_policy *policy,
			    const struct ptlrpc_nrs_resource *res)
{
	struct nrs_tbf_head   *head;
	struct nrs_tbf_client *cli;

	/**
	 * Do nothing for freeing parent, nrs_tbf_net resources
	 */
	if (res->res_parent == NULL)
		return;

	cli = container_of(res, struct nrs_tbf_client, tc_res);
	head = container_of(res->res_parent, struct nrs_tbf_head, th_res);

	head->th_ops->o_cli_put(head, cli);
}

/**
 * Called when getting a request from the TBF policy for handling, or just
 * peeking; removes the request from the policy when it is to be handled.
 *
 * \param[in] policy The policy
 * \param[in] peek   When set, signifies that we just want to examine the
 *		     request, and not handle it, so the request is not removed
 *		     from the policy.
 * \param[in] force  Force the policy to return a request; unused in this
 *		     policy
 *
 * \retval The request to be handled; this is the next request in the TBF
 *	   rule
 *
 * \see ptlrpc_nrs_req_get_nolock()
 * \see nrs_request_get()
 */
static
struct ptlrpc_nrs_request *nrs_tbf_req_get(struct ptlrpc_nrs_policy *policy,
					   bool peek, bool force)
{
	struct nrs_tbf_head	  *head = policy->pol_private;
	struct ptlrpc_nrs_request *nrq = NULL;
	struct nrs_tbf_client     *cli;
	struct binheap_node	  *node;

	assert_spin_locked(&policy->pol_nrs->nrs_svcpt->scp_req_lock);

	if (!peek && policy->pol_nrs->nrs_throttling)
		return NULL;

	node = binheap_root(head->th_binheap);
	if (unlikely(node == NULL))
		return NULL;

	cli = container_of(node, struct nrs_tbf_client, tc_node);
	LASSERT(cli->tc_in_heap);
	if (peek) {
		nrq = list_entry(cli->tc_list.next,
				     struct ptlrpc_nrs_request,
				     nr_u.tbf.tr_list);
	} else {
		struct nrs_tbf_rule *rule = cli->tc_rule;
		__u64 now = ktime_to_ns(ktime_get());
		__u64 passed;
		__u64 ntoken;
		__u64 deadline;
		__u64 old_resid = 0;

		deadline = cli->tc_check_time +
			  cli->tc_nsecs;
		LASSERT(now >= cli->tc_check_time);
		passed = now - cli->tc_check_time;
		ntoken = passed * cli->tc_rpc_rate;
		do_div(ntoken, NSEC_PER_SEC);

		ntoken += cli->tc_ntoken;
		if (rule->tr_flags & NTRS_REALTIME) {
			LASSERT(cli->tc_nsecs_resid < cli->tc_nsecs);
			old_resid = cli->tc_nsecs_resid;
			cli->tc_nsecs_resid += passed % cli->tc_nsecs;
			if (cli->tc_nsecs_resid > cli->tc_nsecs) {
				ntoken++;
				cli->tc_nsecs_resid -= cli->tc_nsecs;
			}
		} else if (ntoken > cli->tc_depth)
			ntoken = cli->tc_depth;

		if (ntoken > 0) {
			struct ptlrpc_request *req;
			nrq = list_entry(cli->tc_list.next,
					     struct ptlrpc_nrs_request,
					     nr_u.tbf.tr_list);
			req = container_of(nrq,
					   struct ptlrpc_request,
					   rq_nrq);
			ntoken--;
			cli->tc_ntoken = ntoken;
			cli->tc_check_time = now;
			list_del_init(&nrq->nr_u.tbf.tr_list);
			if (list_empty(&cli->tc_list)) {
				binheap_remove(head->th_binheap,
					       &cli->tc_node);
				cli->tc_in_heap = false;
			} else {
				if (!(rule->tr_flags & NTRS_REALTIME))
					cli->tc_deadline = now + cli->tc_nsecs;
				binheap_relocate(head->th_binheap,
						 &cli->tc_node);
			}
			CDEBUG(D_RPCTRACE,
			       "TBF dequeues: class@%p rate %u gen %llu "
			       "token %llu, rule@%p rate %u gen %llu\n",
			       cli, cli->tc_rpc_rate,
			       cli->tc_rule_generation, cli->tc_ntoken,
			       cli->tc_rule, cli->tc_rule->tr_rpc_rate,
			       cli->tc_rule->tr_generation);
		} else {
			ktime_t time;

			if (rule->tr_flags & NTRS_REALTIME) {
				cli->tc_deadline = deadline;
				cli->tc_nsecs_resid = old_resid;
				binheap_relocate(head->th_binheap,
						 &cli->tc_node);
				if (node != binheap_root(head->th_binheap))
					return nrs_tbf_req_get(policy,
							       peek, force);
			}
			policy->pol_nrs->nrs_throttling = 1;
			head->th_deadline = deadline;
			time = ktime_set(0, 0);
			time = ktime_add_ns(time, deadline);
			hrtimer_start(&head->th_timer, time, HRTIMER_MODE_ABS);
		}
	}

	return nrq;
}

/**
 * Adds request \a nrq to \a policy's list of queued requests
 *
 * \param[in] policy The policy
 * \param[in] nrq    The request to add
 *
 * \retval 0 success; nrs_request_enqueue() assumes this function will always
 *		      succeed
 */
static int nrs_tbf_req_add(struct ptlrpc_nrs_policy *policy,
			   struct ptlrpc_nrs_request *nrq)
{
	struct nrs_tbf_head   *head;
	struct nrs_tbf_client *cli;
	int		       rc = 0;

	assert_spin_locked(&policy->pol_nrs->nrs_svcpt->scp_req_lock);

	cli = container_of(nrs_request_resource(nrq),
			   struct nrs_tbf_client, tc_res);
	head = container_of(nrs_request_resource(nrq)->res_parent,
			    struct nrs_tbf_head, th_res);
	if (list_empty(&cli->tc_list)) {
		LASSERT(!cli->tc_in_heap);
		cli->tc_deadline = cli->tc_check_time + cli->tc_nsecs;
		rc = binheap_insert(head->th_binheap, &cli->tc_node);
		if (rc == 0) {
			cli->tc_in_heap = true;
			nrq->nr_u.tbf.tr_sequence = head->th_sequence++;
			list_add_tail(&nrq->nr_u.tbf.tr_list,
					  &cli->tc_list);
			if (policy->pol_nrs->nrs_throttling) {
				__u64 deadline = cli->tc_deadline;
				if ((head->th_deadline > deadline) &&
				    (hrtimer_try_to_cancel(&head->th_timer)
				     >= 0)) {
					ktime_t time;
					head->th_deadline = deadline;
					time = ktime_set(0, 0);
					time = ktime_add_ns(time, deadline);
					hrtimer_start(&head->th_timer, time,
						      HRTIMER_MODE_ABS);
				}
			}
		}
	} else {
		LASSERT(cli->tc_in_heap);
		nrq->nr_u.tbf.tr_sequence = head->th_sequence++;
		list_add_tail(&nrq->nr_u.tbf.tr_list,
				  &cli->tc_list);
	}

	if (rc == 0)
		CDEBUG(D_RPCTRACE,
		       "TBF enqueues: class@%p rate %u gen %llu "
		       "token %llu, rule@%p rate %u gen %llu\n",
		       cli, cli->tc_rpc_rate,
		       cli->tc_rule_generation, cli->tc_ntoken,
		       cli->tc_rule, cli->tc_rule->tr_rpc_rate,
		       cli->tc_rule->tr_generation);

	return rc;
}

/**
 * Removes request \a nrq from \a policy's list of queued requests.
 *
 * \param[in] policy The policy
 * \param[in] nrq    The request to remove
 */
static void nrs_tbf_req_del(struct ptlrpc_nrs_policy *policy,
			     struct ptlrpc_nrs_request *nrq)
{
	struct nrs_tbf_head   *head;
	struct nrs_tbf_client *cli;

	assert_spin_locked(&policy->pol_nrs->nrs_svcpt->scp_req_lock);

	cli = container_of(nrs_request_resource(nrq),
			   struct nrs_tbf_client, tc_res);
	head = container_of(nrs_request_resource(nrq)->res_parent,
			    struct nrs_tbf_head, th_res);

	LASSERT(!list_empty(&nrq->nr_u.tbf.tr_list));
	list_del_init(&nrq->nr_u.tbf.tr_list);
	if (list_empty(&cli->tc_list)) {
		binheap_remove(head->th_binheap,
			       &cli->tc_node);
		cli->tc_in_heap = false;
	} else {
		binheap_relocate(head->th_binheap,
				 &cli->tc_node);
	}
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
static void nrs_tbf_req_stop(struct ptlrpc_nrs_policy *policy,
			      struct ptlrpc_nrs_request *nrq)
{
	struct ptlrpc_request *req = container_of(nrq, struct ptlrpc_request,
						  rq_nrq);

	assert_spin_locked(&policy->pol_nrs->nrs_svcpt->scp_req_lock);

	CDEBUG(D_RPCTRACE, "NRS stop %s request from %s, seq: %llu\n",
	       policy->pol_desc->pd_name, libcfs_id2str(req->rq_peer),
	       nrq->nr_u.tbf.tr_sequence);
}

/**
 * debugfs interface
 */

/**
 * The maximum RPC rate.
 */
#define LPROCFS_NRS_RATE_MAX		65535

static int
ptlrpc_lprocfs_nrs_tbf_rule_seq_show(struct seq_file *m, void *data)
{
	struct ptlrpc_service	    *svc = m->private;
	int			     rc;

	seq_printf(m, "regular_requests:\n");
	/**
	 * Perform two separate calls to this as only one of the NRS heads'
	 * policies may be in the ptlrpc_nrs_pol_state::NRS_POL_STATE_STARTED or
	 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPING state.
	 */
	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_REG,
				       NRS_POL_NAME_TBF,
				       NRS_CTL_TBF_RD_RULE,
				       false, m);
	if (rc == 0) {
		/**
		 * -ENOSPC means buf in the parameter m is overflow, return 0
		 * here to let upper layer function seq_read alloc a larger
		 * memory area and do this process again.
		 */
	} else if (rc == -ENOSPC) {
		return 0;

		/**
		 * Ignore -ENODEV as the regular NRS head's policy may be in the
		 * ptlrpc_nrs_pol_state::NRS_POL_STATE_STOPPED state.
		 */
	} else if (rc != -ENODEV) {
		return rc;
	}

	if (!nrs_svc_has_hp(svc))
		goto no_hp;

	seq_printf(m, "high_priority_requests:\n");
	rc = ptlrpc_nrs_policy_control(svc, PTLRPC_NRS_QUEUE_HP,
				       NRS_POL_NAME_TBF,
				       NRS_CTL_TBF_RD_RULE,
				       false, m);
	if (rc == 0) {
		/**
		 * -ENOSPC means buf in the parameter m is overflow, return 0
		 * here to let upper layer function seq_read alloc a larger
		 * memory area and do this process again.
		 */
	} else if (rc == -ENOSPC) {
		return 0;
	}

no_hp:

	return rc;
}

static int nrs_tbf_id_parse(struct nrs_tbf_cmd *cmd, char *token)
{
	int rc;
	ENTRY;

	switch (cmd->u.tc_start.ts_valid_type) {
	case NRS_TBF_FLAG_JOBID:
		rc = nrs_tbf_jobid_parse(cmd, token);
		break;
	case NRS_TBF_FLAG_NID:
		rc = nrs_tbf_nid_parse(cmd, token);
		break;
	case NRS_TBF_FLAG_OPCODE:
		rc = nrs_tbf_opcode_parse(cmd, token);
		break;
	case NRS_TBF_FLAG_GENERIC:
		rc = nrs_tbf_generic_parse(cmd, token);
		break;
	case NRS_TBF_FLAG_UID:
	case NRS_TBF_FLAG_GID:
		rc = nrs_tbf_ug_id_parse(cmd, token);
		break;
	default:
		RETURN(-EINVAL);
	}

	RETURN(rc);
}

static void nrs_tbf_cmd_fini(struct nrs_tbf_cmd *cmd)
{
	if (cmd->tc_cmd == NRS_CTL_TBF_START_RULE) {
		switch (cmd->u.tc_start.ts_valid_type) {
		case NRS_TBF_FLAG_JOBID:
			nrs_tbf_jobid_cmd_fini(cmd);
			break;
		case NRS_TBF_FLAG_NID:
			nrs_tbf_nid_cmd_fini(cmd);
			break;
		case NRS_TBF_FLAG_OPCODE:
			nrs_tbf_opcode_cmd_fini(cmd);
			break;
		case NRS_TBF_FLAG_GENERIC:
			nrs_tbf_generic_cmd_fini(cmd);
			break;
		case NRS_TBF_FLAG_UID:
		case NRS_TBF_FLAG_GID:
			nrs_tbf_id_cmd_fini(cmd);
			break;
		default:
			CWARN("unknown NRS_TBF_FLAGS:0x%x\n",
			      cmd->u.tc_start.ts_valid_type);
		}
	}
}

static bool name_is_valid(const char *name)
{
	int i;

	for (i = 0; i < strlen(name); i++) {
		if ((!isalnum(name[i])) &&
		    (name[i] != '_'))
			return false;
	}
	return true;
}

static int
nrs_tbf_parse_value_pair(struct nrs_tbf_cmd *cmd, char *buffer)
{
	char	*key;
	char	*val;
	int	 rc;
	__u64	 rate;

	val = buffer;
	key = strsep(&val, "=");
	if (val == NULL || strlen(val) == 0)
		return -EINVAL;

	/* Key of the value pair */
	if (strcmp(key, "rate") == 0) {
		rc = kstrtoull(val, 10, &rate);
		if (rc)
			return rc;

		if (rate <= 0 || rate >= LPROCFS_NRS_RATE_MAX)
			return -EINVAL;

		if (cmd->tc_cmd == NRS_CTL_TBF_START_RULE)
			cmd->u.tc_start.ts_rpc_rate = rate;
		else if (cmd->tc_cmd == NRS_CTL_TBF_CHANGE_RULE)
			cmd->u.tc_change.tc_rpc_rate = rate;
		else
			return -EINVAL;
	}  else if (strcmp(key, "rank") == 0) {
		if (!name_is_valid(val))
			return -EINVAL;

		if (cmd->tc_cmd == NRS_CTL_TBF_START_RULE)
			cmd->u.tc_start.ts_next_name = val;
		else if (cmd->tc_cmd == NRS_CTL_TBF_CHANGE_RULE)
			cmd->u.tc_change.tc_next_name = val;
		else
			return -EINVAL;
	} else if (strcmp(key, "realtime") == 0) {
		unsigned long realtime;

		rc = kstrtoul(val, 10, &realtime);
		if (rc)
			return rc;

		if (realtime > 0)
			cmd->u.tc_start.ts_rule_flags |= NTRS_REALTIME;
	} else {
		return -EINVAL;
	}
	return 0;
}

static int
nrs_tbf_parse_value_pairs(struct nrs_tbf_cmd *cmd, char *buffer)
{
	char	*val;
	char	*token;
	int	 rc;

	val = buffer;
	while (val != NULL && strlen(val) != 0) {
		token = strsep(&val, " ");
		rc = nrs_tbf_parse_value_pair(cmd, token);
		if (rc)
			return rc;
	}

	switch (cmd->tc_cmd) {
	case NRS_CTL_TBF_START_RULE:
		if (cmd->u.tc_start.ts_rpc_rate == 0)
			cmd->u.tc_start.ts_rpc_rate = tbf_rate;
		break;
	case NRS_CTL_TBF_CHANGE_RULE:
		if (cmd->u.tc_change.tc_rpc_rate == 0 &&
		    cmd->u.tc_change.tc_next_name == NULL)
			return -EINVAL;
		break;
	case NRS_CTL_TBF_STOP_RULE:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static struct nrs_tbf_cmd *
nrs_tbf_parse_cmd(char *buffer, unsigned long count, __u32 type_flag)
{
	static struct nrs_tbf_cmd	*cmd;
	char				*token;
	char				*val;
	int				 rc = 0;

	OBD_ALLOC_PTR(cmd);
	if (cmd == NULL)
		GOTO(out, rc = -ENOMEM);
	memset(cmd, 0, sizeof(*cmd));

	val = buffer;
	token = strsep(&val, " ");
	if (val == NULL || strlen(val) == 0)
		GOTO(out_free_cmd, rc = -EINVAL);

	/* Type of the command */
	if (strcmp(token, "start") == 0) {
		cmd->tc_cmd = NRS_CTL_TBF_START_RULE;
		cmd->u.tc_start.ts_valid_type = type_flag;
	} else if (strcmp(token, "stop") == 0)
		cmd->tc_cmd = NRS_CTL_TBF_STOP_RULE;
	else if (strcmp(token, "change") == 0)
		cmd->tc_cmd = NRS_CTL_TBF_CHANGE_RULE;
	else
		GOTO(out_free_cmd, rc = -EINVAL);

	/* Name of the rule */
	token = strsep(&val, " ");
	if ((val == NULL && cmd->tc_cmd != NRS_CTL_TBF_STOP_RULE) ||
	    !name_is_valid(token))
		GOTO(out_free_cmd, rc = -EINVAL);
	cmd->tc_name = token;

	if (cmd->tc_cmd == NRS_CTL_TBF_START_RULE) {
		/* List of ID */
		LASSERT(val);
		token = val;
		val = strrchr(token, '}');
		if (!val)
			GOTO(out_free_cmd, rc = -EINVAL);

		/* Skip '}' */
		val++;
		if (*val == '\0') {
			val = NULL;
		} else if (*val == ' ') {
			*val = '\0';
			val++;
		} else
			GOTO(out_free_cmd, rc = -EINVAL);

		rc = nrs_tbf_id_parse(cmd, token);
		if (rc)
			GOTO(out_free_cmd, rc);
	}

	rc = nrs_tbf_parse_value_pairs(cmd, val);
	if (rc)
		GOTO(out_cmd_fini, rc = -EINVAL);
	goto out;
out_cmd_fini:
	nrs_tbf_cmd_fini(cmd);
out_free_cmd:
	OBD_FREE_PTR(cmd);
out:
	if (rc)
		cmd = ERR_PTR(rc);
	return cmd;
}

/**
 * Get the TBF policy type (nid, jobid, etc) preset by
 * proc entry 'nrs_policies' for command buffer parsing.
 *
 * \param[in] svc the PTLRPC service
 * \param[in] queue the NRS queue type
 *
 * \retval the preset TBF policy type flag
 */
static __u32
nrs_tbf_type_flag(struct ptlrpc_service *svc, enum ptlrpc_nrs_queue_type queue)
{
	__u32	type;
	int	rc;

	rc = ptlrpc_nrs_policy_control(svc, queue,
				       NRS_POL_NAME_TBF,
				       NRS_CTL_TBF_RD_TYPE_FLAG,
				       true, &type);
	if (rc != 0)
		type = NRS_TBF_FLAG_INVALID;

	return type;
}

#define LPROCFS_WR_NRS_TBF_MAX_CMD (4096)
static ssize_t
ptlrpc_lprocfs_nrs_tbf_rule_seq_write(struct file *file,
				      const char __user *buffer,
				      size_t count, loff_t *off)
{
	struct seq_file		  *m = file->private_data;
	struct ptlrpc_service	  *svc = m->private;
	char			  *kernbuf;
	char			  *val;
	int			   rc;
	static struct nrs_tbf_cmd *cmd;
	enum ptlrpc_nrs_queue_type queue = PTLRPC_NRS_QUEUE_BOTH;
	unsigned long		   length;
	char			  *token;

	OBD_ALLOC(kernbuf, LPROCFS_WR_NRS_TBF_MAX_CMD);
	if (kernbuf == NULL)
		GOTO(out, rc = -ENOMEM);

	if (count > LPROCFS_WR_NRS_TBF_MAX_CMD - 1)
		GOTO(out_free_kernbuff, rc = -EINVAL);

	if (copy_from_user(kernbuf, buffer, count))
		GOTO(out_free_kernbuff, rc = -EFAULT);

	val = kernbuf;
	token = strsep(&val, " ");
	if (val == NULL)
		GOTO(out_free_kernbuff, rc = -EINVAL);

	if (strcmp(token, "reg") == 0) {
		queue = PTLRPC_NRS_QUEUE_REG;
	} else if (strcmp(token, "hp") == 0) {
		queue = PTLRPC_NRS_QUEUE_HP;
	} else {
		kernbuf[strlen(token)] = ' ';
		val = kernbuf;
	}
	length = strlen(val);

	if (length == 0)
		GOTO(out_free_kernbuff, rc = -EINVAL);

	if (queue == PTLRPC_NRS_QUEUE_HP && !nrs_svc_has_hp(svc))
		GOTO(out_free_kernbuff, rc = -ENODEV);
	else if (queue == PTLRPC_NRS_QUEUE_BOTH && !nrs_svc_has_hp(svc))
		queue = PTLRPC_NRS_QUEUE_REG;

	cmd = nrs_tbf_parse_cmd(val, length, nrs_tbf_type_flag(svc, queue));
	if (IS_ERR(cmd))
		GOTO(out_free_kernbuff, rc = PTR_ERR(cmd));

	/**
	 * Serialize NRS core lprocfs operations with policy registration/
	 * unregistration.
	 */
	mutex_lock(&nrs_core.nrs_mutex);
	rc = ptlrpc_nrs_policy_control(svc, queue,
				       NRS_POL_NAME_TBF,
				       NRS_CTL_TBF_WR_RULE,
				       false, cmd);
	mutex_unlock(&nrs_core.nrs_mutex);

	nrs_tbf_cmd_fini(cmd);
	OBD_FREE_PTR(cmd);
out_free_kernbuff:
	OBD_FREE(kernbuf, LPROCFS_WR_NRS_TBF_MAX_CMD);
out:
	return rc ? rc : count;
}

LDEBUGFS_SEQ_FOPS(ptlrpc_lprocfs_nrs_tbf_rule);

/**
 * Initializes a TBF policy's lprocfs interface for service \a svc
 *
 * \param[in] svc the service
 *
 * \retval 0	success
 * \retval != 0	error
 */
static int nrs_tbf_lprocfs_init(struct ptlrpc_service *svc)
{
	struct ldebugfs_vars nrs_tbf_lprocfs_vars[] = {
		{ .name		= "nrs_tbf_rule",
		  .fops		= &ptlrpc_lprocfs_nrs_tbf_rule_fops,
		  .data = svc },
		{ NULL }
	};

	if (!svc->srv_debugfs_entry)
		return 0;

	ldebugfs_add_vars(svc->srv_debugfs_entry, nrs_tbf_lprocfs_vars, NULL);

	return 0;
}

/**
 * TBF policy operations
 */
static const struct ptlrpc_nrs_pol_ops nrs_tbf_ops = {
	.op_policy_start	= nrs_tbf_start,
	.op_policy_stop		= nrs_tbf_stop,
	.op_policy_ctl		= nrs_tbf_ctl,
	.op_res_get		= nrs_tbf_res_get,
	.op_res_put		= nrs_tbf_res_put,
	.op_req_get		= nrs_tbf_req_get,
	.op_req_enqueue		= nrs_tbf_req_add,
	.op_req_dequeue		= nrs_tbf_req_del,
	.op_req_stop		= nrs_tbf_req_stop,
	.op_lprocfs_init	= nrs_tbf_lprocfs_init,
};

/**
 * TBF policy configuration
 */
struct ptlrpc_nrs_pol_conf nrs_conf_tbf = {
	.nc_name		= NRS_POL_NAME_TBF,
	.nc_ops			= &nrs_tbf_ops,
	.nc_compat		= nrs_policy_compat_all,
};

/** @} tbf */

/** @} nrs */
