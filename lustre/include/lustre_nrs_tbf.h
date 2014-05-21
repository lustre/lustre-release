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
 */
/*
 *
 * Network Request Scheduler (NRS) Token Bucket Filter(TBF) policy
 *
 */

#ifndef _LUSTRE_NRS_TBF_H
#define _LUSTRE_NRS_TBF_H
#include <lustre_net.h>

/* \name tbf
 *
 * TBF policy
 *
 * @{
 */

struct nrs_tbf_head;
struct nrs_tbf_cmd;

struct nrs_tbf_jobid {
	char		*tj_id;
	cfs_list_t	 tj_linkage;
};

struct nrs_tbf_client {
	/** Resource object for policy instance. */
	struct ptlrpc_nrs_resource	 tc_res;
	/** Node in the hash table. */
	cfs_hlist_node_t		 tc_hnode;
	/** NID of the client. */
	lnet_nid_t			 tc_nid;
	/** Jobid of the client. */
	char				 tc_jobid[JOBSTATS_JOBID_SIZE];
	/** Reference number of the client. */
	atomic_t			 tc_ref;
	/** Likage to rule. */
	cfs_list_t		         tc_linkage;
	/** Pointer to rule. */
	struct nrs_tbf_rule		*tc_rule;
	/** Generation of the rule matched. */
	__u64				 tc_rule_generation;
	/** Limit of RPC rate. */
	__u64				 tc_rpc_rate;
	/** Time to wait for next token. */
	__u64				 tc_nsecs;
	/** RPC token number. */
	__u64				 tc_ntoken;
	/** Token bucket depth. */
	__u64				 tc_depth;
	/** Time check-point. */
	__u64				 tc_check_time;
	/** List of queued requests. */
	cfs_list_t			 tc_list;
	/** Node in binary heap. */
	cfs_binheap_node_t		 tc_node;
	/** Whether the client is in heap. */
	bool				 tc_in_heap;
	/** Sequence of the newest rule. */
	__u32				 tc_rule_sequence;
	/**
	 * Linkage into LRU list. Protected bucket lock of
	 * nrs_tbf_head::th_cli_hash.
	 */
	cfs_list_t			 tc_lru;
};

#define MAX_TBF_NAME (16)

#define NTRS_STOPPING	0x0000001
#define NTRS_DEFAULT	0x0000002

struct nrs_tbf_rule {
	/** Name of the rule. */
	char				 tr_name[MAX_TBF_NAME];
	/** Head belongs to. */
	struct nrs_tbf_head		*tr_head;
	/** Likage to head. */
	cfs_list_t			 tr_linkage;
	/** Nid list of the rule. */
	cfs_list_t			 tr_nids;
	/** Nid list string of the rule.*/
	char				*tr_nids_str;
	/** Jobid list of the rule. */
	cfs_list_t			 tr_jobids;
	/** Jobid list string of the rule.*/
	char				*tr_jobids_str;
	/** RPC/s limit. */
	__u64				 tr_rpc_rate;
	/** Time to wait for next token. */
	__u64				 tr_nsecs;
	/** Token bucket depth. */
	__u64				 tr_depth;
	/** List of client. */
	cfs_list_t			 tr_cli_list;
	/** Flags of the rule. */
	__u32				 tr_flags;
	/** Usage Reference count taken on the rule. */
	atomic_t			 tr_ref;
	/** Generation of the rule. */
	__u64				 tr_generation;
};

struct nrs_tbf_ops {
	char *o_name;
	int (*o_startup)(struct ptlrpc_nrs_policy *, struct nrs_tbf_head *);
	struct nrs_tbf_client *(*o_cli_find)(struct nrs_tbf_head *,
					     struct ptlrpc_request *);
	struct nrs_tbf_client *(*o_cli_findadd)(struct nrs_tbf_head *,
						struct nrs_tbf_client *);
	void (*o_cli_put)(struct nrs_tbf_head *, struct nrs_tbf_client *);
	void (*o_cli_init)(struct nrs_tbf_client *, struct ptlrpc_request *);
	int (*o_rule_init)(struct ptlrpc_nrs_policy *,
			   struct nrs_tbf_rule *,
			   struct nrs_tbf_cmd *);
	int (*o_rule_dump)(struct nrs_tbf_rule *, struct seq_file *);
	int (*o_rule_match)(struct nrs_tbf_rule *,
			    struct nrs_tbf_client *);
	void (*o_rule_fini)(struct nrs_tbf_rule *);
};

#define NRS_TBF_TYPE_JOBID	"jobid"
#define NRS_TBF_TYPE_NID	"nid"
#define NRS_TBF_TYPE_MAX_LEN	20
#define NRS_TBF_FLAG_JOBID	0x0000001
#define NRS_TBF_FLAG_NID	0x0000002

struct nrs_tbf_bucket {
	/**
	 * LRU list, updated on each access to client. Protected by
	 * bucket lock of nrs_tbf_head::th_cli_hash.
	 */
	cfs_list_t	ntb_lru;
};

/**
 * Private data structure for the TBF policy
 */
struct nrs_tbf_head {
	/**
	 * Resource object for policy instance.
	 */
	struct ptlrpc_nrs_resource	 th_res;
	/**
	 * List of rules.
	 */
	cfs_list_t			 th_list;
	/**
	 * Lock to protect the list of rules.
	 */
	spinlock_t			 th_rule_lock;
	/**
	 * Generation of rules.
	 */
	atomic_t			 th_rule_sequence;
	/**
	 * Default rule.
	 */
	struct nrs_tbf_rule		*th_rule;
	/**
	 * Timer for next token.
	 */
#if defined(__KERNEL__) && defined(__linux__)
	struct hrtimer			 th_timer;
#endif
	/**
	 * Deadline of the timer.
	 */
	__u64				 th_deadline;
	/**
	 * Sequence of requests.
	 */
	__u64				 th_sequence;
	/**
	 * Heap of queues.
	 */
	cfs_binheap_t			*th_binheap;
	/**
	 * Hash of clients.
	 */
	cfs_hash_t			*th_cli_hash;
	/**
	 * Type of TBF policy.
	 */
	char				 th_type[NRS_TBF_TYPE_MAX_LEN + 1];
	/**
	 * Rule operations.
	 */
	struct nrs_tbf_ops		*th_ops;
	/**
	 * Flag of type.
	 */
	__u32				 th_type_flag;
	/**
	 * Index of bucket on hash table while purging.
	 */
	int				 th_purge_start;
};

enum nrs_tbf_cmd_type {
	NRS_CTL_TBF_START_RULE = 0,
	NRS_CTL_TBF_STOP_RULE,
	NRS_CTL_TBF_CHANGE_RATE,
};

struct nrs_tbf_cmd {
	enum nrs_tbf_cmd_type	 tc_cmd;
	char			*tc_name;
	__u64			 tc_rpc_rate;
	cfs_list_t		 tc_nids;
	char			*tc_nids_str;
	cfs_list_t		 tc_jobids;
	char			*tc_jobids_str;
	__u32			 tc_valid_types;
	__u32			 tc_rule_flags;
};

struct nrs_tbf_req {
	/**
	 * Linkage to queue.
	 */
	cfs_list_t		tr_list;
	/**
	 * Sequence of the request.
	 */
	__u64			tr_sequence;
};

/**
 * TBF policy operations.
 */
enum nrs_ctl_tbf {
	/**
	 * Read the the data of a TBF policy.
	 */
	NRS_CTL_TBF_RD_RULE = PTLRPC_NRS_CTL_1ST_POL_SPEC,
	/**
	 * Write the the data of a TBF policy.
	 */
	NRS_CTL_TBF_WR_RULE,
};

/** @} tbf */
#endif
