// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2014, 2017, Intel Corporation. */

/* This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre network fault simulation
 *
 * Author: liang.zhen@intel.com
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/random.h>
#include <lnet/lib-lnet.h>
#include <uapi/linux/lnet/lnetctl.h>

#define LNET_MSG_MASK		(LNET_PUT_BIT | LNET_ACK_BIT | \
				 LNET_GET_BIT | LNET_REPLY_BIT)

struct lnet_drop_rule {
	/** link chain on the_lnet.ln_drop_rules */
	struct list_head		dr_link;
	/** attributes of this rule */
	struct lnet_fault_large_attr	dr_attr;
	/** lock to protect \a dr_drop_at and \a dr_stat */
	spinlock_t			dr_lock;
	/**
	 * the message sequence to drop, which means message is dropped when
	 * dr_stat.drs_count == dr_drop_at
	 */
	unsigned long			dr_drop_at;
	/**
	 * seconds to drop the next message, it's exclusive with dr_drop_at
	 */
	time64_t			dr_drop_time;
	/** baseline to caculate dr_drop_time */
	time64_t			dr_time_base;
	/** statistic of dropped messages */
	struct lnet_fault_stat		dr_stat;
};

static void
lnet_fault_attr_to_attr4(struct lnet_fault_large_attr *attr,
			 struct lnet_fault_attr *attr4)
{
	if (!attr)
		return;

	attr4->fa_src = lnet_nid_to_nid4(&attr->fa_src);
	attr4->fa_dst = lnet_nid_to_nid4(&attr->fa_dst);
	attr4->fa_local_nid = lnet_nid_to_nid4(&attr->fa_local_nid);
	attr4->fa_ptl_mask = attr->fa_ptl_mask;
	attr4->fa_msg_mask = attr->fa_msg_mask;

	memcpy(&attr4->u, &attr->u, sizeof(attr4->u));
}

static void
lnet_fault_attr4_to_attr(struct lnet_fault_attr *attr4,
			 struct lnet_fault_large_attr *attr)
{
	if (!attr4)
		return;

	if (attr4->fa_src)
		lnet_nid4_to_nid(attr4->fa_src, &attr->fa_src);
	else
		attr->fa_src = LNET_ANY_NID;

	if (attr4->fa_dst)
		lnet_nid4_to_nid(attr4->fa_dst, &attr->fa_dst);
	else
		attr->fa_dst = LNET_ANY_NID;

	if (attr4->fa_local_nid)
		lnet_nid4_to_nid(attr4->fa_local_nid, &attr->fa_local_nid);
	else
		attr->fa_local_nid = LNET_ANY_NID;

	attr->fa_ptl_mask = attr4->fa_ptl_mask;
	attr->fa_msg_mask = attr4->fa_msg_mask;

	memcpy(&attr->u, &attr4->u, sizeof(attr->u));
}

static bool
lnet_fault_nid_match(struct lnet_nid *nid, struct lnet_nid *msg_nid)
{
	if (LNET_NID_IS_ANY(nid))
		return true;
	if (!msg_nid)
		return false;
	if (nid_same(msg_nid, nid))
		return true;

	if (LNET_NID_NET(nid) != LNET_NID_NET(msg_nid))
		return false;

	/* 255.255.255.255@net is wildcard for all addresses in a network */
	return __be32_to_cpu(nid->nid_addr[0]) == LNET_NIDADDR(LNET_NID_ANY);
}

static bool
lnet_fault_attr_match(struct lnet_fault_large_attr *attr,
		      struct lnet_nid *src,
		      struct lnet_nid *local_nid,
		      struct lnet_nid *dst,
		      unsigned int type, unsigned int portal)
{
	if (!lnet_fault_nid_match(&attr->fa_src, src) ||
	    !lnet_fault_nid_match(&attr->fa_dst, dst) ||
	    !lnet_fault_nid_match(&attr->fa_local_nid, local_nid))
		return false;

	if (!(attr->fa_msg_mask & BIT(type)))
		return false;

	/* NB: ACK and REPLY have no portal, but they should have been
	 * rejected by message mask */
	if (attr->fa_ptl_mask != 0 && /* has portal filter */
	    !(attr->fa_ptl_mask & (1ULL << portal)))
		return false;

	return true;
}

static int
lnet_fault_attr_validate(struct lnet_fault_large_attr *attr)
{
	if (attr->fa_msg_mask == 0)
		attr->fa_msg_mask = LNET_MSG_MASK; /* all message types */

	if (attr->fa_ptl_mask == 0) /* no portal filter */
		return 0;

	/* NB: only PUT and GET can be filtered if portal filter has been set */
	attr->fa_msg_mask &= LNET_GET_BIT | LNET_PUT_BIT;
	if (attr->fa_msg_mask == 0) {
		CDEBUG(D_NET, "can't find valid message type bits %x\n",
		       attr->fa_msg_mask);
		return -EINVAL;
	}
	return 0;
}

static void
lnet_fault_stat_inc(struct lnet_fault_stat *stat, unsigned int type)
{
	/* NB: fs_counter is NOT updated by this function */
	switch (type) {
	case LNET_MSG_PUT:
		stat->fs_put++;
		return;
	case LNET_MSG_ACK:
		stat->fs_ack++;
		return;
	case LNET_MSG_GET:
		stat->fs_get++;
		return;
	case LNET_MSG_REPLY:
		stat->fs_reply++;
		return;
	}
}

/**
 * LNet message drop simulation
 */

/**
 * Add a new drop rule to LNet
 * There is no check for duplicated drop rule, all rules will be checked for
 * incoming message.
 */
int lnet_drop_rule_add(struct lnet_fault_large_attr *attr)
{
	struct lnet_drop_rule *rule;
	ENTRY;

	if (!((attr->u.drop.da_rate == 0) ^ (attr->u.drop.da_interval == 0))) {
		CDEBUG(D_NET,
		       "Invalid drop rule specifies rate and interval %d/%d\n",
		       attr->u.drop.da_rate, attr->u.drop.da_interval);
		RETURN(-EINVAL);
	}

	if (lnet_fault_attr_validate(attr) != 0)
		RETURN(-EINVAL);

	CFS_ALLOC_PTR(rule);
	if (rule == NULL)
		RETURN(-ENOMEM);

	spin_lock_init(&rule->dr_lock);

	rule->dr_attr = *attr;
	if (attr->u.drop.da_interval != 0) {
		rule->dr_time_base = ktime_get_seconds() + attr->u.drop.da_interval;
		rule->dr_drop_time = ktime_get_seconds() +
				     get_random_u32_below(attr->u.drop.da_interval);
	} else {
		rule->dr_drop_at = get_random_u32_below(attr->u.drop.da_rate);
	}

	lnet_net_lock(LNET_LOCK_EX);
	list_add(&rule->dr_link, &the_lnet.ln_drop_rules);
	lnet_net_unlock(LNET_LOCK_EX);

	CDEBUG(D_NET, "Added drop rule: src %s, dst %s, rate %d, interval %d\n",
	       libcfs_nidstr(&attr->fa_src), libcfs_nidstr(&attr->fa_dst),
	       attr->u.drop.da_rate, attr->u.drop.da_interval);
	RETURN(0);
}

/**
 * Remove matched drop rules from lnet, all rules that can match \a src and
 * \a dst will be removed.
 * If \a src is zero, then all rules have \a dst as destination will be remove
 * If \a dst is zero, then all rules have \a src as source will be removed
 * If both of them are zero, all rules will be removed
 */
int lnet_drop_rule_del(struct lnet_nid *src, struct lnet_nid *dst)
{
	struct lnet_drop_rule *rule;
	struct lnet_drop_rule *tmp;
	LIST_HEAD(zombies);
	int n = 0;
	ENTRY;

	CDEBUG(D_NET, "src %s dst %s\n", libcfs_nidstr(src),
	       libcfs_nidstr(dst));
	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry_safe(rule, tmp, &the_lnet.ln_drop_rules, dr_link) {
		if (!(LNET_NID_IS_ANY(src) || nid_same(&rule->dr_attr.fa_src, src)))
			continue;

		if (!(LNET_NID_IS_ANY(dst) || nid_same(&rule->dr_attr.fa_dst, dst)))
			continue;

		list_move(&rule->dr_link, &zombies);
	}
	lnet_net_unlock(LNET_LOCK_EX);

	list_for_each_entry_safe(rule, tmp, &zombies, dr_link) {
		CDEBUG(D_NET, "Remove drop rule: src %s->dst: %s (1/%d, %d)\n",
		       libcfs_nidstr(&rule->dr_attr.fa_src),
		       libcfs_nidstr(&rule->dr_attr.fa_dst),
		       rule->dr_attr.u.drop.da_rate,
		       rule->dr_attr.u.drop.da_interval);

		list_del(&rule->dr_link);
		CFS_FREE_PTR(rule);
		n++;
	}

	RETURN(n);
}

/**
 * List drop rule at position of \a pos
 */
static int
lnet_drop_rule_list(int pos, struct lnet_fault_large_attr *attr,
		    struct lnet_fault_stat *stat)
{
	struct lnet_drop_rule *rule;
	int		       cpt;
	int		       i = 0;
	int		       rc = -ENOENT;
	ENTRY;

	cpt = lnet_net_lock_current();
	list_for_each_entry(rule, &the_lnet.ln_drop_rules, dr_link) {
		if (i++ < pos)
			continue;

		spin_lock(&rule->dr_lock);
		*attr = rule->dr_attr;
		*stat = rule->dr_stat;
		spin_unlock(&rule->dr_lock);
		rc = 0;
		break;
	}

	lnet_net_unlock(cpt);
	RETURN(rc);
}

int lnet_drop_rule_collect(struct lnet_genl_fault_rule_list *rlist)
{
	struct lnet_drop_rule *rule;
	int cpt, rc = 0;

	ENTRY;
	cpt = lnet_net_lock_current();
	list_for_each_entry(rule, &the_lnet.ln_drop_rules, dr_link) {
		struct lnet_rule_properties *prop;

		prop = genradix_ptr_alloc(&rlist->lgfrl_list,
					  rlist->lgfrl_count++,
					  GFP_KERNEL);
		if (!prop) {
			rc = -ENOMEM;
			break;
		}
		spin_lock(&rule->dr_lock);
		prop->attr = rule->dr_attr;
		prop->stat = rule->dr_stat;
		spin_unlock(&rule->dr_lock);
	}

	lnet_net_unlock(cpt);
	RETURN(rc);
}

/**
 * reset counters for all drop rules
 */
void lnet_drop_rule_reset(void)
{
	struct lnet_drop_rule *rule;
	int		       cpt;
	ENTRY;

	cpt = lnet_net_lock_current();

	list_for_each_entry(rule, &the_lnet.ln_drop_rules, dr_link) {
		struct lnet_fault_large_attr *attr = &rule->dr_attr;

		spin_lock(&rule->dr_lock);

		memset(&rule->dr_stat, 0, sizeof(rule->dr_stat));
		if (attr->u.drop.da_rate != 0) {
			rule->dr_drop_at = get_random_u32_below(attr->u.drop.da_rate);
		} else {
			rule->dr_drop_time = ktime_get_seconds() +
					     get_random_u32_below(attr->u.drop.da_interval);
			rule->dr_time_base = ktime_get_seconds() + attr->u.drop.da_interval;
		}
		spin_unlock(&rule->dr_lock);
	}

	lnet_net_unlock(cpt);
	EXIT;
}

static void
lnet_fault_match_health(enum lnet_msg_hstatus *hstatus, __u32 mask)
{
	int choice;
	int delta;
	int best_delta;
	int i;

	/* assign a random failure */
	choice = get_random_u32_below(LNET_MSG_STATUS_END - LNET_MSG_STATUS_OK);
	if (choice == 0)
		choice++;

	if (mask == HSTATUS_RANDOM) {
		*hstatus = choice;
		return;
	}

	if (mask & BIT(choice)) {
		*hstatus = choice;
		return;
	}

	/* round to the closest ON bit */
	i = HSTATUS_END;
	best_delta = HSTATUS_END;
	while (i > 0) {
		if (mask & BIT(i)) {
			delta = choice - i;
			if (delta < 0)
				delta *= -1;
			if (delta < best_delta) {
				best_delta = delta;
				choice = i;
			}
		}
		i--;
	}

	*hstatus = choice;
}

/**
 * check source/destination NID, portal, message type and drop rate,
 * decide whether should drop this message or not
 */
static bool
drop_rule_match(struct lnet_drop_rule *rule,
		struct lnet_nid *src,
		struct lnet_nid *local_nid,
		struct lnet_nid *dst,
		unsigned int type, unsigned int portal,
		enum lnet_msg_hstatus *hstatus)
{
	struct lnet_fault_large_attr *attr = &rule->dr_attr;
	bool drop;

	if (!lnet_fault_attr_match(attr, src, local_nid, dst, type, portal))
		return false;

	if (attr->u.drop.da_drop_all) {
		CDEBUG(D_NET, "set to drop all messages\n");
		drop = true;
		goto drop_matched;
	}

	/*
	 * if we're trying to match a health status error but it hasn't
	 * been set in the rule, then don't match
	 */
	if ((hstatus && !attr->u.drop.da_health_error_mask) ||
	    (!hstatus && attr->u.drop.da_health_error_mask))
		return false;

	/* match this rule, check drop rate now */
	spin_lock(&rule->dr_lock);
	if (attr->u.drop.da_random) {
		int value = get_random_u32_below(attr->u.drop.da_interval);
		if (value >= (attr->u.drop.da_interval / 2))
			drop = true;
		else
			drop = false;
	} else if (rule->dr_drop_time != 0) { /* time based drop */
		time64_t now = ktime_get_seconds();

		rule->dr_stat.fs_count++;
		drop = now >= rule->dr_drop_time;
		if (drop) {
			if (now > rule->dr_time_base)
				rule->dr_time_base = now;

			rule->dr_drop_time = rule->dr_time_base +
					     get_random_u32_below(attr->u.drop.da_interval);
			rule->dr_time_base += attr->u.drop.da_interval;

			CDEBUG(D_NET, "Drop Rule %s->%s: next drop : %lld\n",
			       libcfs_nidstr(&attr->fa_src),
			       libcfs_nidstr(&attr->fa_dst),
			       rule->dr_drop_time);
		}

	} else { /* rate based drop */
		__u64 count;

		drop = rule->dr_stat.fs_count++ == rule->dr_drop_at;
		count = rule->dr_stat.fs_count;
		if (do_div(count, attr->u.drop.da_rate) == 0) {
			rule->dr_drop_at = rule->dr_stat.fs_count +
					   get_random_u32_below(attr->u.drop.da_rate);
			CDEBUG(D_NET, "Drop Rule %s->%s: next drop: %lu\n",
			       libcfs_nidstr(&attr->fa_src),
			       libcfs_nidstr(&attr->fa_dst), rule->dr_drop_at);
		}
	}

drop_matched:

	if (drop) { /* drop this message, update counters */
		if (hstatus)
			lnet_fault_match_health(hstatus,
				attr->u.drop.da_health_error_mask);
		lnet_fault_stat_inc(&rule->dr_stat, type);
		rule->dr_stat.u.drop.ds_dropped++;
	}

	spin_unlock(&rule->dr_lock);
	return drop;
}

/**
 * Check if message from \a src to \a dst can match any existed drop rule
 */
bool
lnet_drop_rule_match(struct lnet_hdr *hdr,
		     struct lnet_nid *local_nid,
		     enum lnet_msg_hstatus *hstatus)
{
	unsigned int typ = hdr->type;
	struct lnet_drop_rule *rule;
	unsigned int ptl = -1;
	bool drop = false;
	int cpt;

	/* NB: if Portal is specified, then only PUT and GET will be
	 * filtered by drop rule */
	if (typ == LNET_MSG_PUT)
		ptl = le32_to_cpu(hdr->msg.put.ptl_index);
	else if (typ == LNET_MSG_GET)
		ptl = le32_to_cpu(hdr->msg.get.ptl_index);

	cpt = lnet_net_lock_current();
	list_for_each_entry(rule, &the_lnet.ln_drop_rules, dr_link) {
		drop = drop_rule_match(rule, &hdr->src_nid, local_nid,
				       &hdr->dest_nid, typ, ptl,
				       hstatus);
		if (drop)
			break;
	}
	lnet_net_unlock(cpt);

	return drop;
}

/**
 * LNet Delay Simulation
 */
/** timestamp (second) to send delayed message */
#define msg_delay_send		 msg_ev.hdr_data

struct lnet_delay_rule {
	/** link chain on the_lnet.ln_delay_rules */
	struct list_head		dl_link;
	/** link chain on delay_dd.dd_sched_rules */
	struct list_head		dl_sched_link;
	/** attributes of this rule */
	struct lnet_fault_large_attr	dl_attr;
	/** lock to protect \a below members */
	spinlock_t			dl_lock;
	/** refcount of delay rule */
	struct kref		dl_refcount;
	/**
	 * the message sequence to delay, which means message is delayed when
	 * dl_stat.fs_count == dl_delay_at
	 */
	unsigned long			dl_delay_at;
	/**
	 * seconds to delay the next message, it's exclusive with dl_delay_at
	 */
	time64_t			dl_delay_time;
	/** baseline to caculate dl_delay_time */
	time64_t			dl_time_base;
	/** seconds until we send the next delayed message */
	time64_t			dl_msg_send;
	/** delayed message list */
	struct list_head		dl_msg_list;
	/** statistic of delayed messages */
	struct lnet_fault_stat		dl_stat;
	/** timer to wakeup delay_daemon */
	struct timer_list		dl_timer;
};

struct delay_daemon_data {
	/** serialise rule add/remove */
	struct mutex		dd_mutex;
	/** protect rules on \a dd_sched_rules */
	spinlock_t		dd_lock;
	/** scheduled delay rules (by timer) */
	struct list_head	dd_sched_rules;
	/** deamon thread sleeps at here */
	wait_queue_head_t	dd_waitq;
	/** controler (lctl command) wait at here */
	wait_queue_head_t	dd_ctl_waitq;
	/** deamon is running */
	unsigned int		dd_running;
	/** deamon stopped */
	unsigned int		dd_stopped;
};

static struct delay_daemon_data	delay_dd;

static void
delay_rule_free(struct kref *kref)
{
	struct lnet_delay_rule *rule = container_of(kref,
						    struct lnet_delay_rule,
						    dl_refcount);

	LASSERT(list_empty(&rule->dl_sched_link));
	LASSERT(list_empty(&rule->dl_msg_list));
	LASSERT(list_empty(&rule->dl_link));
	CFS_FREE_PTR(rule);
}

/**
 * check source/destination NID, portal, message type and delay rate,
 * decide whether should delay this message or not
 */
static bool
delay_rule_match(struct lnet_delay_rule *rule, struct lnet_nid *src,
		 struct lnet_nid *dst, unsigned int type, unsigned int portal,
		 struct lnet_msg *msg)
{
	struct lnet_fault_large_attr *attr = &rule->dl_attr;
	bool delay;
	time64_t now = ktime_get_seconds();

	if (!lnet_fault_attr_match(attr, src, NULL,
				   dst, type, portal))
		return false;

	/* match this rule, check delay rate now */
	spin_lock(&rule->dl_lock);
	if (rule->dl_delay_time != 0) { /* time based delay */
		rule->dl_stat.fs_count++;
		delay = now >= rule->dl_delay_time;
		if (delay) {
			if (now > rule->dl_time_base)
				rule->dl_time_base = now;

			rule->dl_delay_time = rule->dl_time_base +
					      get_random_u32_below(attr->u.delay.la_interval);
			rule->dl_time_base += attr->u.delay.la_interval;

			CDEBUG(D_NET, "Delay Rule %s->%s: next delay : %lld\n",
			       libcfs_nidstr(&attr->fa_src),
			       libcfs_nidstr(&attr->fa_dst),
			       rule->dl_delay_time);
		}

	} else { /* rate based delay */
		__u64 count;

		delay = rule->dl_stat.fs_count++ == rule->dl_delay_at;
		/* generate the next random rate sequence */
		count = rule->dl_stat.fs_count;
		if (do_div(count, attr->u.delay.la_rate) == 0) {
			rule->dl_delay_at = rule->dl_stat.fs_count +
					    get_random_u32_below(attr->u.delay.la_rate);
			CDEBUG(D_NET, "Delay Rule %s->%s: next delay: %lu\n",
			       libcfs_nidstr(&attr->fa_src),
			       libcfs_nidstr(&attr->fa_dst), rule->dl_delay_at);
		}
	}

	if (!delay) {
		spin_unlock(&rule->dl_lock);
		return false;
	}

	/* delay this message, update counters */
	lnet_fault_stat_inc(&rule->dl_stat, type);
	rule->dl_stat.u.delay.ls_delayed++;

	list_add_tail(&msg->msg_list, &rule->dl_msg_list);
	msg->msg_delay_send = now + attr->u.delay.la_latency;
	if (rule->dl_msg_send == -1) {
		rule->dl_msg_send = msg->msg_delay_send;
		mod_timer(&rule->dl_timer,
			  jiffies + cfs_time_seconds(attr->u.delay.la_latency));
	}

	spin_unlock(&rule->dl_lock);
	return true;
}

/**
 * check if \a msg can match any Delay Rule, receiving of this message
 * will be delayed if there is a match.
 */
bool
lnet_delay_rule_match_locked(struct lnet_hdr *hdr, struct lnet_msg *msg)
{
	struct lnet_delay_rule	*rule;
	unsigned int		 typ = hdr->type;
	unsigned int		 ptl = -1;

	/* NB: called with hold of lnet_net_lock */

	/* NB: if Portal is specified, then only PUT and GET will be
	 * filtered by delay rule */
	if (typ == LNET_MSG_PUT)
		ptl = le32_to_cpu(hdr->msg.put.ptl_index);
	else if (typ == LNET_MSG_GET)
		ptl = le32_to_cpu(hdr->msg.get.ptl_index);

	list_for_each_entry(rule, &the_lnet.ln_delay_rules, dl_link) {
		if (delay_rule_match(rule, &hdr->src_nid, &hdr->dest_nid,
				     typ, ptl, msg))
			return true;
	}

	return false;
}

/** check out delayed messages for send */
static void
delayed_msg_check(struct lnet_delay_rule *rule, bool all,
		  struct list_head *msg_list)
{
	struct lnet_msg *msg;
	struct lnet_msg *tmp;
	time64_t now = ktime_get_seconds();

	if (!all && rule->dl_msg_send > now)
		return;

	spin_lock(&rule->dl_lock);
	list_for_each_entry_safe(msg, tmp, &rule->dl_msg_list, msg_list) {
		if (!all && msg->msg_delay_send > now)
			break;

		msg->msg_delay_send = 0;
		list_move_tail(&msg->msg_list, msg_list);
	}

	if (list_empty(&rule->dl_msg_list)) {
		timer_delete(&rule->dl_timer);
		rule->dl_msg_send = -1;

	} else if (!list_empty(msg_list)) {
		/* dequeued some timedout messages, update timer for the
		 * next delayed message on rule */
		msg = list_first_entry(&rule->dl_msg_list,
				       struct lnet_msg, msg_list);
		rule->dl_msg_send = msg->msg_delay_send;
		mod_timer(&rule->dl_timer,
			  jiffies +
			  cfs_time_seconds(msg->msg_delay_send - now));
	}
	spin_unlock(&rule->dl_lock);
}

static void
delayed_msg_process(struct list_head *msg_list, bool drop)
{
	struct lnet_msg	*msg;

	while ((msg = list_first_entry_or_null(msg_list, struct lnet_msg,
					       msg_list)) != NULL) {
		struct lnet_ni *ni;
		int		cpt;
		int		rc;

		if (msg->msg_sending) {
			/* Delayed send */
			list_del_init(&msg->msg_list);
			ni = msg->msg_txni;
			CDEBUG(D_NET, "TRACE: msg %p %s -> %s : %s\n", msg,
			       libcfs_nidstr(&ni->ni_nid),
			       libcfs_nidstr(&msg->msg_txpeer->lpni_nid),
			       lnet_msgtyp2str(msg->msg_type));
			lnet_ni_send(ni, msg);
			continue;
		}

		/* Delayed receive */
		LASSERT(msg->msg_rxpeer != NULL);
		LASSERT(msg->msg_rxni != NULL);

		ni = msg->msg_rxni;
		cpt = msg->msg_rx_cpt;

		list_del_init(&msg->msg_list);
		if (drop) {
			rc = -ECANCELED;

		} else if (!msg->msg_routing) {
			rc = lnet_parse_local(ni, msg);
			if (rc == 0)
				continue;

		} else {
			lnet_net_lock(cpt);
			rc = lnet_parse_forward_locked(ni, msg);
			lnet_net_unlock(cpt);

			switch (rc) {
			case LNET_CREDIT_OK:
				lnet_ni_recv(ni, msg->msg_private, msg, 0,
					     0, msg->msg_len, msg->msg_len);
				fallthrough;
			case LNET_CREDIT_WAIT:
				continue;
			default: /* failures */
				break;
			}
		}

		lnet_drop_message(ni, cpt, msg->msg_private, msg->msg_len,
				  msg->msg_type);
		lnet_finalize(msg, rc);
	}
}

/**
 * Process delayed messages for scheduled rules
 * This function can either be called by delay_rule_daemon, or by lnet_finalise
 */
void
lnet_delay_rule_check(void)
{
	struct lnet_delay_rule *rule;
	LIST_HEAD(msgs);

	while (1) {
		if (list_empty(&delay_dd.dd_sched_rules))
			break;

		spin_lock_bh(&delay_dd.dd_lock);
		if (list_empty(&delay_dd.dd_sched_rules)) {
			spin_unlock_bh(&delay_dd.dd_lock);
			break;
		}

		rule = list_first_entry(&delay_dd.dd_sched_rules,
					struct lnet_delay_rule, dl_sched_link);
		list_del_init(&rule->dl_sched_link);
		spin_unlock_bh(&delay_dd.dd_lock);

		delayed_msg_check(rule, false, &msgs);
		/* -1 for delay_dd.dd_sched_rules */
		kref_put(&rule->dl_refcount, delay_rule_free);
	}

	if (!list_empty(&msgs))
		delayed_msg_process(&msgs, false);
}

/** deamon thread to handle delayed messages */
static int
lnet_delay_rule_daemon(void *arg)
{
	delay_dd.dd_running = 1;
	wake_up(&delay_dd.dd_ctl_waitq);

	while (delay_dd.dd_running) {
		wait_event_interruptible(delay_dd.dd_waitq,
					 !delay_dd.dd_running ||
					 !list_empty(&delay_dd.dd_sched_rules));
		lnet_delay_rule_check();
	}

	/* in case more rules have been enqueued after my last check */
	lnet_delay_rule_check();
	delay_dd.dd_stopped = 1;
	wake_up(&delay_dd.dd_ctl_waitq);

	return 0;
}

static void
delay_timer_cb(cfs_timer_cb_arg_t data)
{
	struct lnet_delay_rule *rule = cfs_from_timer(rule, data, dl_timer);

	spin_lock_bh(&delay_dd.dd_lock);
	if (list_empty(&rule->dl_sched_link) && delay_dd.dd_running) {
		kref_get(&rule->dl_refcount);
		list_add_tail(&rule->dl_sched_link, &delay_dd.dd_sched_rules);
		wake_up(&delay_dd.dd_waitq);
	}
	spin_unlock_bh(&delay_dd.dd_lock);
}

/**
 * Add a new delay rule to LNet
 * There is no check for duplicated delay rule, all rules will be checked for
 * incoming message.
 */
int
lnet_delay_rule_add(struct lnet_fault_large_attr *attr)
{
	struct lnet_delay_rule *rule;
	int rc = 0;
	ENTRY;

	if (!((attr->u.delay.la_rate == 0) ^
	      (attr->u.delay.la_interval == 0))) {
		CDEBUG(D_NET,
		       "please provide either delay rate or delay interval, "
		       "but not both at the same time %d/%d\n",
		       attr->u.delay.la_rate, attr->u.delay.la_interval);
		RETURN(-EINVAL);
	}

	if (attr->u.delay.la_latency == 0) {
		CDEBUG(D_NET, "delay latency cannot be zero\n");
		RETURN(-EINVAL);
	}

	if (lnet_fault_attr_validate(attr) != 0)
		RETURN(-EINVAL);

	CFS_ALLOC_PTR(rule);
	if (rule == NULL)
		RETURN(-ENOMEM);

	mutex_lock(&delay_dd.dd_mutex);
	if (!delay_dd.dd_running) {
		struct task_struct *task;

		/* NB: although LND threads will process delayed message
		 * in lnet_finalize, but there is no guarantee that LND
		 * threads will be waken up if no other message needs to
		 * be handled.
		 * Only one daemon thread, performance is not the concern
		 * of this simualation module.
		 */
		task = kthread_run(lnet_delay_rule_daemon, NULL, "lnet_dd");
		if (IS_ERR(task)) {
			rc = PTR_ERR(task);
			GOTO(failed, rc);
		}
		wait_event(delay_dd.dd_ctl_waitq, delay_dd.dd_running);
	}

	cfs_timer_setup(&rule->dl_timer, delay_timer_cb,
			(unsigned long)rule, 0);

	spin_lock_init(&rule->dl_lock);
	INIT_LIST_HEAD(&rule->dl_msg_list);
	INIT_LIST_HEAD(&rule->dl_sched_link);

	rule->dl_attr = *attr;
	if (attr->u.delay.la_interval != 0) {
		rule->dl_time_base = ktime_get_seconds() +
				     attr->u.delay.la_interval;
		rule->dl_delay_time = ktime_get_seconds() +
				      get_random_u32_below(attr->u.delay.la_interval);
	} else {
		rule->dl_delay_at = get_random_u32_below(attr->u.delay.la_rate);
	}

	rule->dl_msg_send = -1;

	lnet_net_lock(LNET_LOCK_EX);
	kref_init(&rule->dl_refcount);
	list_add(&rule->dl_link, &the_lnet.ln_delay_rules);
	lnet_net_unlock(LNET_LOCK_EX);

	CDEBUG(D_NET, "Added delay rule: src %s, dst %s, rate %d\n",
	       libcfs_nidstr(&attr->fa_src), libcfs_nidstr(&attr->fa_dst),
	       attr->u.delay.la_rate);

	mutex_unlock(&delay_dd.dd_mutex);
	RETURN(0);
 failed:
	mutex_unlock(&delay_dd.dd_mutex);
	CFS_FREE_PTR(rule);
	return rc;
}

/**
 * Remove matched Delay Rules from lnet, if \a shutdown is true or both \a src
 * and \a dst are zero, all rules will be removed, otherwise only matched rules
 * will be removed.
 * If \a src is zero, then all rules have \a dst as destination will be remove
 * If \a dst is zero, then all rules have \a src as source will be removed
 *
 * When a delay rule is removed, all delayed messages of this rule will be
 * processed immediately.
 */
int
lnet_delay_rule_del(struct lnet_nid *src, struct lnet_nid *dst, bool shutdown)
{
	struct lnet_delay_rule *rule;
	struct lnet_delay_rule *tmp;
	LIST_HEAD(rule_list);
	LIST_HEAD(msg_list);
	int n = 0;
	bool cleanup;
	ENTRY;

	mutex_lock(&delay_dd.dd_mutex);
	lnet_net_lock(LNET_LOCK_EX);

	list_for_each_entry_safe(rule, tmp, &the_lnet.ln_delay_rules, dl_link) {
		CDEBUG(D_NET, "src %s dst %s fa_src %s fa_dst %s\n",
		       libcfs_nidstr(src), libcfs_nidstr(dst),
		       libcfs_nidstr(&rule->dl_attr.fa_src),
		       libcfs_nidstr(&rule->dl_attr.fa_dst));
		if (!(LNET_NID_IS_ANY(src) || nid_same(&rule->dl_attr.fa_src, src)))
			continue;

		if (!(LNET_NID_IS_ANY(dst) || nid_same(&rule->dl_attr.fa_dst, dst)))
			continue;

		CDEBUG(D_NET, "Remove delay rule: src %s->dst: %s (1/%d, %d)\n",
		       libcfs_nidstr(&rule->dl_attr.fa_src),
		       libcfs_nidstr(&rule->dl_attr.fa_dst),
		       rule->dl_attr.u.delay.la_rate,
		       rule->dl_attr.u.delay.la_interval);
		/* refcount is taken over by rule_list */
		list_move(&rule->dl_link, &rule_list);
	}

	/* check if we need to shutdown delay_daemon */
	cleanup = list_empty(&the_lnet.ln_delay_rules) &&
		  !list_empty(&rule_list);
	lnet_net_unlock(LNET_LOCK_EX);

	list_for_each_entry_safe(rule, tmp, &rule_list, dl_link) {
		list_del_init(&rule->dl_link);

		timer_delete_sync(&rule->dl_timer);
		delayed_msg_check(rule, true, &msg_list);
		/* -1 for the_lnet.ln_delay_rules */
		kref_put(&rule->dl_refcount, delay_rule_free);
		n++;
	}

	if (cleanup) { /* no more delay rule, shutdown delay_daemon */
		LASSERT(delay_dd.dd_running);
		delay_dd.dd_running = 0;
		wake_up(&delay_dd.dd_waitq);

		while (!delay_dd.dd_stopped)
			wait_event(delay_dd.dd_ctl_waitq, delay_dd.dd_stopped);
	}
	mutex_unlock(&delay_dd.dd_mutex);

	if (!list_empty(&msg_list))
		delayed_msg_process(&msg_list, shutdown);

	RETURN(n);
}

/**
 * List Delay Rule at position of \a pos
 */
int
lnet_delay_rule_list(int pos, struct lnet_fault_large_attr *attr,
		    struct lnet_fault_stat *stat)
{
	struct lnet_delay_rule *rule;
	int			cpt;
	int			i = 0;
	int			rc = -ENOENT;
	ENTRY;

	cpt = lnet_net_lock_current();
	list_for_each_entry(rule, &the_lnet.ln_delay_rules, dl_link) {
		if (i++ < pos)
			continue;

		spin_lock(&rule->dl_lock);
		*attr = rule->dl_attr;
		*stat = rule->dl_stat;
		spin_unlock(&rule->dl_lock);
		rc = 0;
		break;
	}

	lnet_net_unlock(cpt);
	RETURN(rc);
}

int lnet_delay_rule_collect(struct lnet_genl_fault_rule_list *rlist)
{
	struct lnet_delay_rule *rule;
	int cpt, rc = 0;

	ENTRY;
	cpt = lnet_net_lock_current();
	list_for_each_entry(rule, &the_lnet.ln_delay_rules, dl_link) {
		struct lnet_rule_properties *prop;

		prop = genradix_ptr_alloc(&rlist->lgfrl_list,
					  rlist->lgfrl_count++,
					  GFP_KERNEL);
		if (!prop) {
			rc = -ENOMEM;
			break;
		}
		spin_lock(&rule->dl_lock);
		prop->attr = rule->dl_attr;
		prop->stat = rule->dl_stat;
		spin_unlock(&rule->dl_lock);
	}

	lnet_net_unlock(cpt);
	RETURN(rc);
}

/**
 * reset counters for all Delay Rules
 */
void
lnet_delay_rule_reset(void)
{
	struct lnet_delay_rule *rule;
	int			cpt;
	ENTRY;

	cpt = lnet_net_lock_current();

	list_for_each_entry(rule, &the_lnet.ln_delay_rules, dl_link) {
		struct lnet_fault_large_attr *attr = &rule->dl_attr;

		spin_lock(&rule->dl_lock);

		memset(&rule->dl_stat, 0, sizeof(rule->dl_stat));
		if (attr->u.delay.la_rate != 0) {
			rule->dl_delay_at = get_random_u32_below(attr->u.delay.la_rate);
		} else {
			rule->dl_delay_time = ktime_get_seconds() +
					      get_random_u32_below(attr->u.delay.la_interval);
			rule->dl_time_base = ktime_get_seconds() +
					     attr->u.delay.la_interval;
		}
		spin_unlock(&rule->dl_lock);
	}

	lnet_net_unlock(cpt);
	EXIT;
}

int
lnet_fault_ctl(int opc, struct libcfs_ioctl_data *data)
{
	struct lnet_fault_attr *attr4;
	struct lnet_fault_stat *stat;
	struct lnet_fault_large_attr attr = { { 0 } };
	int rc;

	attr4 = (struct lnet_fault_attr *)data->ioc_inlbuf1;

	lnet_fault_attr4_to_attr(attr4, &attr);

	switch (opc) {
	default:
		return -EINVAL;

	case LNET_CTL_DROP_ADD:
		if (!attr4)
			return -EINVAL;

		return lnet_drop_rule_add(&attr);

	case LNET_CTL_DROP_DEL:
		if (!attr4)
			return -EINVAL;

		data->ioc_count = lnet_drop_rule_del(&attr.fa_src,
						     &attr.fa_dst);
		return 0;

	case LNET_CTL_DROP_RESET:
		lnet_drop_rule_reset();
		return 0;

	case LNET_CTL_DROP_LIST:
		stat = (struct lnet_fault_stat *)data->ioc_inlbuf2;
		if (!attr4 || !stat)
			return -EINVAL;

		rc = lnet_drop_rule_list(data->ioc_count, &attr, stat);
		lnet_fault_attr_to_attr4(&attr, attr4);
		return rc;

	case LNET_CTL_DELAY_ADD:
		if (!attr4)
			return -EINVAL;

		return lnet_delay_rule_add(&attr);

	case LNET_CTL_DELAY_DEL:
		if (!attr4)
			return -EINVAL;

		data->ioc_count = lnet_delay_rule_del(&attr.fa_src,
						      &attr.fa_dst, false);
		return 0;

	case LNET_CTL_DELAY_RESET:
		lnet_delay_rule_reset();
		return 0;

	case LNET_CTL_DELAY_LIST:
		stat = (struct lnet_fault_stat *)data->ioc_inlbuf2;
		if (!attr4 || !stat)
			return -EINVAL;

		rc = lnet_delay_rule_list(data->ioc_count, &attr, stat);
		lnet_fault_attr_to_attr4(&attr, attr4);
		return rc;
	}
}

int
lnet_fault_init(void)
{
	BUILD_BUG_ON(LNET_PUT_BIT != BIT(LNET_MSG_PUT));
	BUILD_BUG_ON(LNET_ACK_BIT != BIT(LNET_MSG_ACK));
	BUILD_BUG_ON(LNET_GET_BIT != BIT(LNET_MSG_GET));
	BUILD_BUG_ON(LNET_REPLY_BIT != BIT(LNET_MSG_REPLY));

	mutex_init(&delay_dd.dd_mutex);
	spin_lock_init(&delay_dd.dd_lock);
	init_waitqueue_head(&delay_dd.dd_waitq);
	init_waitqueue_head(&delay_dd.dd_ctl_waitq);
	INIT_LIST_HEAD(&delay_dd.dd_sched_rules);

	return 0;
}

void
lnet_fault_fini(void)
{
	lnet_drop_rule_del(NULL, NULL);
	lnet_delay_rule_del(NULL, NULL, true);

	LASSERT(list_empty(&the_lnet.ln_drop_rules));
	LASSERT(list_empty(&the_lnet.ln_delay_rules));
	LASSERT(list_empty(&delay_dd.dd_sched_rules));
}
