/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/include/lnet/lib-lnet.h
 *
 * Top level include for library side routines
 */

#ifndef __LNET_LIB_LNET_H__
#define __LNET_LIB_LNET_H__

/* LNET has 0xeXXX */
#define CFS_FAIL_PTLRPC_OST_BULK_CB2	0xe000

#include <linux/netdevice.h>

#include <libcfs/libcfs.h>
#include <lnet/api.h>
#include <lnet/lib-types.h>
#include <uapi/linux/lnet/lnet-dlc.h>
#include <uapi/linux/lnet/lnet-types.h>
#include <uapi/linux/lnet/lnetctl.h>
#include <uapi/linux/lnet/nidstr.h>

extern struct lnet the_lnet;			/* THE network */

#if (BITS_PER_LONG == 32)
/* 2 CPTs, allowing more CPTs might make us under memory pressure */
# define LNET_CPT_MAX_BITS     1

#else /* 64-bit system */
/*
 * 256 CPTs for thousands of CPUs, allowing more CPTs might make us
 * under risk of consuming all lh_cookie.
 */
# define LNET_CPT_MAX_BITS     8
#endif /* BITS_PER_LONG == 32 */

/* max allowed CPT number */
#define LNET_CPT_MAX		(1 << LNET_CPT_MAX_BITS)

#define LNET_CPT_NUMBER		(the_lnet.ln_cpt_number)
#define LNET_CPT_BITS		(the_lnet.ln_cpt_bits)
#define LNET_CPT_MASK		((1ULL << LNET_CPT_BITS) - 1)

/** exclusive lock */
#define LNET_LOCK_EX		CFS_PERCPT_LOCK_EX

/* default timeout and credits */
#define DEFAULT_PEER_TIMEOUT    180
#define DEFAULT_PEER_CREDITS    8
#define DEFAULT_CREDITS         256

#ifdef HAVE_KERN_SOCK_GETNAME_2ARGS
#define lnet_kernel_getpeername(sock, addr, addrlen) \
		kernel_getpeername(sock, addr)
#define lnet_kernel_getsockname(sock, addr, addrlen) \
		kernel_getsockname(sock, addr)
#else
#define lnet_kernel_getpeername(sock, addr, addrlen) \
		kernel_getpeername(sock, addr, addrlen)
#define lnet_kernel_getsockname(sock, addr, addrlen) \
		kernel_getsockname(sock, addr, addrlen)
#endif

/*
 * kernel 5.3: commit ef11db3310e272d3d8dbe8739e0770820dd20e52
 * kernel 4.18.0-193.el8:
 * added in_dev_for_each_ifa_rtnl and in_dev_for_each_ifa_rcu
 * and removed for_ifa and endfor_ifa.
 * Use the _rntl variant as the current locking is rtnl.
 */
#ifdef HAVE_IN_DEV_FOR_EACH_IFA_RTNL
#define DECLARE_CONST_IN_IFADDR(ifa)		const struct in_ifaddr *ifa
#define endfor_ifa(in_dev)
#else
#define DECLARE_CONST_IN_IFADDR(ifa)
#define in_dev_for_each_ifa_rtnl(ifa, in_dev)	for_ifa((in_dev))
#define in_dev_for_each_ifa_rcu(ifa, in_dev)	for_ifa((in_dev))
#endif

int choose_ipv4_src(__u32 *ret,
		    int interface, __u32 dst_ipaddr, struct net *ns);

bool lnet_is_route_alive(struct lnet_route *route);
bool lnet_is_gateway_alive(struct lnet_peer *gw);

static inline int lnet_is_wire_handle_none(struct lnet_handle_wire *wh)
{
	return (wh->wh_interface_cookie == LNET_WIRE_HANDLE_COOKIE_NONE &&
		wh->wh_object_cookie == LNET_WIRE_HANDLE_COOKIE_NONE);
}

static inline int lnet_md_exhausted(struct lnet_libmd *md)
{
	return (md->md_threshold == 0 ||
		((md->md_options & LNET_MD_MAX_SIZE) != 0 &&
		 md->md_offset + md->md_max_size > md->md_length));
}

static inline int lnet_md_unlinkable(struct lnet_libmd *md)
{
	/* Should unlink md when its refcount is 0 and either:
	 *  - md has been flagged for deletion (by auto unlink or LNetM[DE]Unlink,
	 *    in the latter case md may not be exhausted).
	 *  - auto unlink is on and md is exhausted.
	 */
	if (md->md_refcount != 0)
		return 0;

	if ((md->md_flags & LNET_MD_FLAG_ZOMBIE) != 0)
		return 1;

	return ((md->md_flags & LNET_MD_FLAG_AUTO_UNLINK) != 0 &&
		lnet_md_exhausted(md));
}

#define lnet_cpt_table()	(the_lnet.ln_cpt_table)
#define lnet_cpt_current()	cfs_cpt_current(the_lnet.ln_cpt_table, 1)

static inline int
lnet_cpt_of_cookie(__u64 cookie)
{
	unsigned int cpt = (cookie >> LNET_COOKIE_TYPE_BITS) & LNET_CPT_MASK;

	/* LNET_CPT_NUMBER doesn't have to be power2, which means we can
	 * get illegal cpt from it's invalid cookie */
	return cpt < LNET_CPT_NUMBER ? cpt : cpt % LNET_CPT_NUMBER;
}

static inline void
lnet_res_lock(int cpt)
{
	cfs_percpt_lock(the_lnet.ln_res_lock, cpt);
}

static inline void
lnet_res_unlock(int cpt)
{
	cfs_percpt_unlock(the_lnet.ln_res_lock, cpt);
}

static inline int
lnet_res_lock_current(void)
{
	int cpt = lnet_cpt_current();

	lnet_res_lock(cpt);
	return cpt;
}

static inline void
lnet_net_lock(int cpt)
{
	cfs_percpt_lock(the_lnet.ln_net_lock, cpt);
}

static inline void
lnet_net_unlock(int cpt)
{
	cfs_percpt_unlock(the_lnet.ln_net_lock, cpt);
}

static inline int
lnet_net_lock_current(void)
{
	int cpt = lnet_cpt_current();

	lnet_net_lock(cpt);
	return cpt;
}

#define LNET_LOCK()		lnet_net_lock(LNET_LOCK_EX)
#define LNET_UNLOCK()		lnet_net_unlock(LNET_LOCK_EX)

#define lnet_ptl_lock(ptl)	spin_lock(&(ptl)->ptl_lock)
#define lnet_ptl_unlock(ptl)	spin_unlock(&(ptl)->ptl_lock)
#define lnet_ni_lock(ni)	spin_lock(&(ni)->ni_lock)
#define lnet_ni_unlock(ni)	spin_unlock(&(ni)->ni_lock)

#define MAX_PORTALS	64

#define LNET_SMALL_MD_SIZE   offsetof(struct lnet_libmd, md_kiov[1])
extern struct kmem_cache *lnet_mes_cachep;	 /* MEs kmem_cache */
extern struct kmem_cache *lnet_small_mds_cachep; /* <= LNET_SMALL_MD_SIZE bytes
						  * MDs kmem_cache */
extern struct kmem_cache *lnet_udsp_cachep;
extern struct kmem_cache *lnet_rspt_cachep;
extern struct kmem_cache *lnet_msg_cachep;

static inline bool
lnet_ni_set_status_locked(struct lnet_ni *ni, __u32 status)
__must_hold(&ni->ni_lock)
{
	bool update = false;

	if (ni->ni_status && ni->ni_status->ns_status != status) {
		CDEBUG(D_NET, "ni %s status changed from %#x to %#x\n",
		       libcfs_nid2str(ni->ni_nid),
		       ni->ni_status->ns_status, status);
		ni->ni_status->ns_status = status;
		update = true;
	}

	return update;
}

static inline bool
lnet_ni_set_status(struct lnet_ni *ni, __u32 status)
{
	bool update;

	lnet_ni_lock(ni);
	update = lnet_ni_set_status_locked(ni, status);
	lnet_ni_unlock(ni);

	return update;
}

static inline void lnet_md_wait_handling(struct lnet_libmd *md, int cpt)
{
	wait_queue_head_t *wq = __var_waitqueue(md);
#ifdef HAVE_WAIT_QUEUE_ENTRY
	struct wait_bit_queue_entry entry;
	wait_queue_entry_t *wqe = &entry.wq_entry;
#else
	struct wait_bit_queue entry;
	wait_queue_entry_t *wqe = &entry.wait;
#endif
	init_wait_var_entry(&entry, md, 0);
	prepare_to_wait_event(wq, wqe, TASK_IDLE);
	if (md->md_flags & LNET_MD_FLAG_HANDLING) {
		/* Race with unlocked call to ->md_handler.
		 * It is safe to drop the res_lock here as the
		 * caller has only just claimed it.
		 */
		lnet_res_unlock(cpt);
		schedule();
		/* Cannot check md now, it might be freed.  Caller
		 * must reclaim reference and check.
		 */
		lnet_res_lock(cpt);
	}
	finish_wait(wq, wqe);
}

static inline void
lnet_md_free(struct lnet_libmd *md)
{
	unsigned int  size;

	LASSERTF(md->md_rspt_ptr == NULL, "md %p rsp %p\n", md, md->md_rspt_ptr);

	size = offsetof(struct lnet_libmd, md_kiov[md->md_niov]);

	if (size <= LNET_SMALL_MD_SIZE) {
		CDEBUG(D_MALLOC, "slab-freed 'md' at %p.\n", md);
		kmem_cache_free(lnet_small_mds_cachep, md);
	} else {
		LIBCFS_FREE(md, size);
	}
}

struct lnet_libhandle *lnet_res_lh_lookup(struct lnet_res_container *rec,
				     __u64 cookie);
void lnet_res_lh_initialize(struct lnet_res_container *rec,
			    struct lnet_libhandle *lh);
static inline void
lnet_res_lh_invalidate(struct lnet_libhandle *lh)
{
	/* ALWAYS called with resource lock held */
	/* NB: cookie is still useful, don't reset it */
	list_del(&lh->lh_hash_chain);
}

static inline void
lnet_md2handle(struct lnet_handle_md *handle, struct lnet_libmd *md)
{
	handle->cookie = md->md_lh.lh_cookie;
}

static inline struct lnet_libmd *
lnet_handle2md(struct lnet_handle_md *handle)
{
	/* ALWAYS called with resource lock held */
	struct lnet_libhandle *lh;
	int		 cpt;

	cpt = lnet_cpt_of_cookie(handle->cookie);
	lh = lnet_res_lh_lookup(the_lnet.ln_md_containers[cpt],
				handle->cookie);
	if (lh == NULL)
		return NULL;

	return lh_entry(lh, struct lnet_libmd, md_lh);
}

static inline struct lnet_libmd *
lnet_wire_handle2md(struct lnet_handle_wire *wh)
{
	/* ALWAYS called with resource lock held */
	struct lnet_libhandle *lh;
	int		 cpt;

	if (wh->wh_interface_cookie != the_lnet.ln_interface_cookie)
		return NULL;

	cpt = lnet_cpt_of_cookie(wh->wh_object_cookie);
	lh = lnet_res_lh_lookup(the_lnet.ln_md_containers[cpt],
				wh->wh_object_cookie);
	if (lh == NULL)
		return NULL;

	return lh_entry(lh, struct lnet_libmd, md_lh);
}

static inline void
lnet_peer_net_addref_locked(struct lnet_peer_net *lpn)
{
	atomic_inc(&lpn->lpn_refcount);
}

extern void lnet_destroy_peer_net_locked(struct lnet_peer_net *lpn);

static inline void
lnet_peer_net_decref_locked(struct lnet_peer_net *lpn)
{
	if (atomic_dec_and_test(&lpn->lpn_refcount))
		lnet_destroy_peer_net_locked(lpn);
}

static inline void
lnet_peer_addref_locked(struct lnet_peer *lp)
{
	atomic_inc(&lp->lp_refcount);
}

extern void lnet_destroy_peer_locked(struct lnet_peer *lp);

static inline void
lnet_peer_decref_locked(struct lnet_peer *lp)
{
	if (atomic_dec_and_test(&lp->lp_refcount))
		lnet_destroy_peer_locked(lp);
}

static inline void
lnet_peer_ni_addref_locked(struct lnet_peer_ni *lp)
{
	kref_get(&lp->lpni_kref);
}

extern void lnet_destroy_peer_ni_locked(struct kref *ref);

static inline void
lnet_peer_ni_decref_locked(struct lnet_peer_ni *lp)
{
	kref_put(&lp->lpni_kref, lnet_destroy_peer_ni_locked);
}

static inline int
lnet_isrouter(struct lnet_peer_ni *lpni)
{
	return lpni->lpni_peer_net->lpn_peer->lp_rtr_refcount != 0;
}

static inline void
lnet_ni_addref_locked(struct lnet_ni *ni, int cpt)
{
	LASSERT(cpt >= 0 && cpt < LNET_CPT_NUMBER);
	LASSERT(*ni->ni_refs[cpt] >= 0);

	(*ni->ni_refs[cpt])++;
}

static inline void
lnet_ni_addref(struct lnet_ni *ni)
{
	lnet_net_lock(0);
	lnet_ni_addref_locked(ni, 0);
	lnet_net_unlock(0);
}

static inline void
lnet_ni_decref_locked(struct lnet_ni *ni, int cpt)
{
	LASSERT(cpt >= 0 && cpt < LNET_CPT_NUMBER);
	LASSERT(*ni->ni_refs[cpt] > 0);

	(*ni->ni_refs[cpt])--;
}

static inline void
lnet_ni_decref(struct lnet_ni *ni)
{
	lnet_net_lock(0);
	lnet_ni_decref_locked(ni, 0);
	lnet_net_unlock(0);
}

static inline struct lnet_msg *
lnet_msg_alloc(void)
{
	struct lnet_msg *msg;

	msg = kmem_cache_zalloc(lnet_msg_cachep, GFP_NOFS);

	return (msg);
}

static inline void
lnet_msg_free(struct lnet_msg *msg)
{
	LASSERT(!msg->msg_onactivelist);
	kmem_cache_free(lnet_msg_cachep, msg);
}

static inline struct lnet_rsp_tracker *
lnet_rspt_alloc(int cpt)
{
	struct lnet_rsp_tracker *rspt;

	rspt = kmem_cache_zalloc(lnet_rspt_cachep, GFP_NOFS);
	if (rspt) {
		lnet_net_lock(cpt);
		the_lnet.ln_counters[cpt]->lct_health.lch_rst_alloc++;
		lnet_net_unlock(cpt);
	}
	CDEBUG(D_MALLOC, "rspt alloc %p\n", rspt);
	return rspt;
}

static inline void
lnet_rspt_free(struct lnet_rsp_tracker *rspt, int cpt)
{
	CDEBUG(D_MALLOC, "rspt free %p\n", rspt);

	kmem_cache_free(lnet_rspt_cachep, rspt);
	lnet_net_lock(cpt);
	the_lnet.ln_counters[cpt]->lct_health.lch_rst_alloc--;
	lnet_net_unlock(cpt);
}

void lnet_ni_free(struct lnet_ni *ni);
void lnet_net_free(struct lnet_net *net);

struct lnet_net *
lnet_net_alloc(__u32 net_type, struct list_head *netlist);

struct lnet_ni *
lnet_ni_alloc(struct lnet_net *net, struct cfs_expr_list *el,
	      char *iface);
struct lnet_ni *
lnet_ni_alloc_w_cpt_array(struct lnet_net *net, __u32 *cpts, __u32 ncpts,
			  char *iface);

static inline int
lnet_nid2peerhash(lnet_nid_t nid)
{
	return hash_long(nid, LNET_PEER_HASH_BITS);
}

static inline struct list_head *
lnet_net2rnethash(__u32 net)
{
	return &the_lnet.ln_remote_nets_hash[(LNET_NETNUM(net) +
		LNET_NETTYP(net)) &
		((1U << the_lnet.ln_remote_nets_hbits) - 1)];
}

extern const struct lnet_lnd the_lolnd;
extern int avoid_asym_router_failure;

extern unsigned int lnet_nid_cpt_hash(lnet_nid_t nid, unsigned int number);
extern int lnet_cpt_of_nid_locked(lnet_nid_t nid, struct lnet_ni *ni);
extern int lnet_cpt_of_nid(lnet_nid_t nid, struct lnet_ni *ni);
extern struct lnet_ni *lnet_nid2ni_locked(lnet_nid_t nid, int cpt);
extern struct lnet_ni *lnet_nid2ni_addref(lnet_nid_t nid);
extern struct lnet_ni *lnet_net2ni_locked(__u32 net, int cpt);
extern struct lnet_ni *lnet_net2ni_addref(__u32 net);
struct lnet_net *lnet_get_net_locked(__u32 net_id);

int lnet_lib_init(void);
void lnet_lib_exit(void);

extern unsigned int lnet_response_tracking;
extern unsigned lnet_transaction_timeout;
extern unsigned lnet_retry_count;
extern unsigned int lnet_lnd_timeout;
extern unsigned int lnet_numa_range;
extern unsigned int lnet_health_sensitivity;
extern unsigned int lnet_recovery_interval;
extern unsigned int lnet_recovery_limit;
extern unsigned int lnet_peer_discovery_disabled;
extern unsigned int lnet_drop_asym_route;
extern unsigned int router_sensitivity_percentage;
extern int alive_router_check_interval;
extern int live_router_check_interval;
extern int dead_router_check_interval;
extern int portal_rotor;

void lnet_mt_event_handler(struct lnet_event *event);

int lnet_notify(struct lnet_ni *ni, lnet_nid_t peer, bool alive, bool reset,
		time64_t when);
void lnet_notify_locked(struct lnet_peer_ni *lp, int notifylnd, int alive,
			time64_t when);
int lnet_add_route(__u32 net, __u32 hops, lnet_nid_t gateway_nid,
		   __u32 priority, __u32 sensitivity);
int lnet_del_route(__u32 net, lnet_nid_t gw_nid);
void lnet_move_route(struct lnet_route *route, struct lnet_peer *lp,
		     struct list_head *rt_list);
void lnet_destroy_routes(void);
int lnet_get_route(int idx, __u32 *net, __u32 *hops,
		   lnet_nid_t *gateway, __u32 *alive, __u32 *priority,
		   __u32 *sensitivity);
int lnet_get_rtr_pool_cfg(int idx, struct lnet_ioctl_pool_cfg *pool_cfg);
struct lnet_ni *lnet_get_next_ni_locked(struct lnet_net *mynet,
					struct lnet_ni *prev);
struct lnet_ni *lnet_get_ni_idx_locked(int idx);
int lnet_get_net_healthv_locked(struct lnet_net *net);

extern int libcfs_ioctl_getdata(struct libcfs_ioctl_hdr **hdr_pp,
				struct libcfs_ioctl_hdr __user *uparam);
extern int lnet_get_peer_list(__u32 *countp, __u32 *sizep,
			      struct lnet_process_id __user *ids);
extern void lnet_peer_ni_set_healthv(lnet_nid_t nid, int value, bool all);
extern void lnet_peer_ni_add_to_recoveryq_locked(struct lnet_peer_ni *lpni,
						 struct list_head *queue,
						 time64_t now);
extern int lnet_peer_add_pref_nid(struct lnet_peer_ni *lpni, lnet_nid_t nid);
extern void lnet_peer_clr_pref_nids(struct lnet_peer_ni *lpni);
extern int lnet_peer_del_pref_nid(struct lnet_peer_ni *lpni, lnet_nid_t nid);
void lnet_peer_ni_set_selection_priority(struct lnet_peer_ni *lpni,
					 __u32 priority);
extern void lnet_ni_add_to_recoveryq_locked(struct lnet_ni *ni,
					    struct list_head *queue,
					    time64_t now);

void lnet_router_debugfs_init(void);
void lnet_router_debugfs_fini(void);
int  lnet_rtrpools_alloc(int im_a_router);
void lnet_destroy_rtrbuf(struct lnet_rtrbuf *rb, int npages);
int  lnet_rtrpools_adjust(int tiny, int small, int large);
int lnet_rtrpools_enable(void);
void lnet_rtrpools_disable(void);
void lnet_rtrpools_free(int keep_pools);
void lnet_rtr_transfer_to_peer(struct lnet_peer *src,
			       struct lnet_peer *target);
struct lnet_remotenet *lnet_find_rnet_locked(__u32 net);
int lnet_dyn_add_net(struct lnet_ioctl_config_data *conf);
int lnet_dyn_del_net(__u32 net);
int lnet_dyn_add_ni(struct lnet_ioctl_config_ni *conf);
int lnet_dyn_del_ni(struct lnet_ioctl_config_ni *conf);
int lnet_clear_lazy_portal(struct lnet_ni *ni, int portal, char *reason);
struct lnet_net *lnet_get_net_locked(__u32 net_id);
void lnet_net_clr_pref_rtrs(struct lnet_net *net);
int lnet_net_add_pref_rtr(struct lnet_net *net, lnet_nid_t gw_nid);

int lnet_islocalnid(lnet_nid_t nid);
int lnet_islocalnet(__u32 net);
int lnet_islocalnet_locked(__u32 net);

void lnet_msg_attach_md(struct lnet_msg *msg, struct lnet_libmd *md,
			unsigned int offset, unsigned int mlen);
void lnet_build_unlink_event(struct lnet_libmd *md, struct lnet_event *ev);
void lnet_build_msg_event(struct lnet_msg *msg, enum lnet_event_kind ev_type);
void lnet_msg_commit(struct lnet_msg *msg, int cpt);
void lnet_msg_decommit(struct lnet_msg *msg, int cpt, int status);

void lnet_prep_send(struct lnet_msg *msg, int type,
		    struct lnet_process_id target, unsigned int offset,
		    unsigned int len);
int lnet_send(lnet_nid_t nid, struct lnet_msg *msg, lnet_nid_t rtr_nid);
int lnet_send_ping(lnet_nid_t dest_nid, struct lnet_handle_md *mdh, int nnis,
		   void *user_ptr, lnet_handler_t handler, bool recovery);
void lnet_return_tx_credits_locked(struct lnet_msg *msg);
void lnet_return_rx_credits_locked(struct lnet_msg *msg);
void lnet_schedule_blocked_locked(struct lnet_rtrbufpool *rbp);
void lnet_drop_routed_msgs_locked(struct list_head *list, int cpt);

struct list_head **lnet_create_array_of_queues(void);

/* portals functions */
/* portals attributes */
static inline int
lnet_ptl_is_lazy(struct lnet_portal *ptl)
{
	return !!(ptl->ptl_options & LNET_PTL_LAZY);
}

static inline int
lnet_ptl_is_unique(struct lnet_portal *ptl)
{
	return !!(ptl->ptl_options & LNET_PTL_MATCH_UNIQUE);
}

static inline int
lnet_ptl_is_wildcard(struct lnet_portal *ptl)
{
	return !!(ptl->ptl_options & LNET_PTL_MATCH_WILDCARD);
}

static inline void
lnet_ptl_setopt(struct lnet_portal *ptl, int opt)
{
	ptl->ptl_options |= opt;
}

static inline void
lnet_ptl_unsetopt(struct lnet_portal *ptl, int opt)
{
	ptl->ptl_options &= ~opt;
}

/* match-table functions */
struct list_head *lnet_mt_match_head(struct lnet_match_table *mtable,
			       struct lnet_process_id id, __u64 mbits);
struct lnet_match_table *lnet_mt_of_attach(unsigned int index,
					   struct lnet_process_id id,
					   __u64 mbits, __u64 ignore_bits,
					   enum lnet_ins_pos pos);
int lnet_mt_match_md(struct lnet_match_table *mtable,
		     struct lnet_match_info *info, struct lnet_msg *msg);

/* portals match/attach functions */
void lnet_ptl_attach_md(struct lnet_me *me, struct lnet_libmd *md,
			struct list_head *matches, struct list_head *drops);
void lnet_ptl_detach_md(struct lnet_me *me, struct lnet_libmd *md);
int lnet_ptl_match_md(struct lnet_match_info *info, struct lnet_msg *msg);

/* initialized and finalize portals */
int lnet_portals_create(void);
void lnet_portals_destroy(void);

/* message functions */
int lnet_parse(struct lnet_ni *ni, struct lnet_hdr *hdr,
	       lnet_nid_t fromnid, void *private, int rdma_req);
int lnet_parse_local(struct lnet_ni *ni, struct lnet_msg *msg);
int lnet_parse_forward_locked(struct lnet_ni *ni, struct lnet_msg *msg);

void lnet_recv(struct lnet_ni *ni, void *private, struct lnet_msg *msg,
	       int delayed, unsigned int offset, unsigned int mlen,
	       unsigned int rlen);
void lnet_ni_recv(struct lnet_ni *ni, void *private, struct lnet_msg *msg,
		  int delayed, unsigned int offset,
		  unsigned int mlen, unsigned int rlen);
void lnet_ni_send(struct lnet_ni *ni, struct lnet_msg *msg);

struct lnet_msg *lnet_create_reply_msg(struct lnet_ni *ni,
				       struct lnet_msg *get_msg);
void lnet_set_reply_msg_len(struct lnet_ni *ni, struct lnet_msg *msg,
			    unsigned int len);
void lnet_detach_rsp_tracker(struct lnet_libmd *md, int cpt);
void lnet_clean_zombie_rstqs(void);

bool lnet_md_discarded(struct lnet_libmd *md);
void lnet_finalize(struct lnet_msg *msg, int rc);
bool lnet_send_error_simulation(struct lnet_msg *msg,
				enum lnet_msg_hstatus *hstatus);
void lnet_handle_remote_failure_locked(struct lnet_peer_ni *lpni);

void lnet_drop_message(struct lnet_ni *ni, int cpt, void *private,
		       unsigned int nob, __u32 msg_type);
void lnet_drop_delayed_msg_list(struct list_head *head, char *reason);
void lnet_recv_delayed_msg_list(struct list_head *head);

int lnet_msg_container_setup(struct lnet_msg_container *container, int cpt);
void lnet_msg_container_cleanup(struct lnet_msg_container *container);
void lnet_msg_containers_destroy(void);
int lnet_msg_containers_create(void);

char *lnet_health_error2str(enum lnet_msg_hstatus hstatus);
char *lnet_msgtyp2str(int type);
int lnet_fail_nid(lnet_nid_t nid, unsigned int threshold);

/** \addtogroup lnet_fault_simulation @{ */

int lnet_fault_ctl(int cmd, struct libcfs_ioctl_data *data);
int lnet_fault_init(void);
void lnet_fault_fini(void);

bool lnet_drop_rule_match(struct lnet_hdr *hdr, lnet_nid_t local_nid,
			  enum lnet_msg_hstatus *hstatus);

int lnet_delay_rule_add(struct lnet_fault_attr *attr);
int lnet_delay_rule_del(lnet_nid_t src, lnet_nid_t dst, bool shutdown);
int lnet_delay_rule_list(int pos, struct lnet_fault_attr *attr,
			 struct lnet_fault_stat *stat);
void lnet_delay_rule_reset(void);
void lnet_delay_rule_check(void);
bool lnet_delay_rule_match_locked(struct lnet_hdr *hdr, struct lnet_msg *msg);

/** @} lnet_fault_simulation */

void lnet_counters_get_common(struct lnet_counters_common *common);
int lnet_counters_get(struct lnet_counters *counters);
void lnet_counters_reset(void);
static inline void
lnet_ni_set_sel_priority_locked(struct lnet_ni *ni, __u32 priority)
{
	ni->ni_sel_priority = priority;
}

static inline void
lnet_net_set_sel_priority_locked(struct lnet_net *net, __u32 priority)
{
	net->net_sel_priority = priority;
}

unsigned int lnet_iov_nob(unsigned int niov, struct kvec *iov);
unsigned int lnet_kiov_nob(unsigned int niov, struct bio_vec *iov);
int lnet_extract_kiov(int dst_niov, struct bio_vec *dst,
		      int src_niov, struct bio_vec *src,
		      unsigned int offset, unsigned int len);

void lnet_copy_iov2iov(unsigned int ndiov, struct kvec *diov,
		       unsigned int doffset,
		       unsigned int nsiov, struct kvec *siov,
		       unsigned int soffset, unsigned int nob);
void lnet_copy_kiov2iov(unsigned int niov, struct kvec *iov,
			unsigned int iovoffset,
			unsigned int nkiov, struct bio_vec *kiov,
			unsigned int kiovoffset, unsigned int nob);
void lnet_copy_iov2kiov(unsigned int nkiov, struct bio_vec *kiov,
			unsigned int kiovoffset,
			unsigned int niov, struct kvec *iov,
			unsigned int iovoffset, unsigned int nob);
void lnet_copy_kiov2kiov(unsigned int ndkiov, struct bio_vec *dkiov,
			 unsigned int doffset,
			 unsigned int nskiov, struct bio_vec *skiov,
			 unsigned int soffset, unsigned int nob);

static inline void
lnet_copy_kiov2flat(int dlen, void *dest, unsigned int doffset,
		    unsigned int nsiov, struct bio_vec *skiov,
		    unsigned int soffset, unsigned int nob)
{
	struct kvec diov = { .iov_base = dest, .iov_len = dlen };

	lnet_copy_kiov2iov(1, &diov, doffset,
			   nsiov, skiov, soffset, nob);
}

static inline void
lnet_copy_flat2kiov(unsigned int ndiov, struct bio_vec *dkiov,
		    unsigned int doffset, int slen, void *src,
		    unsigned int soffset, unsigned int nob)
{
	struct kvec siov = { .iov_base = src, .iov_len = slen };
	lnet_copy_iov2kiov(ndiov, dkiov, doffset,
			   1, &siov, soffset, nob);
}

void lnet_me_unlink(struct lnet_me *me);

void lnet_md_unlink(struct lnet_libmd *md);
void lnet_md_deconstruct(struct lnet_libmd *lmd, struct lnet_event *ev);
struct page *lnet_kvaddr_to_page(unsigned long vaddr);
int lnet_cpt_of_md(struct lnet_libmd *md, unsigned int offset);

unsigned int lnet_get_lnd_timeout(void);
void lnet_register_lnd(const struct lnet_lnd *lnd);
void lnet_unregister_lnd(const struct lnet_lnd *lnd);

struct socket *lnet_connect(lnet_nid_t peer_nid, int interface,
			    struct sockaddr *peeraddr, struct net *ns);
void lnet_connect_console_error(int rc, lnet_nid_t peer_nid,
				struct sockaddr *sa);
int lnet_count_acceptor_nets(void);
int lnet_acceptor_timeout(void);
int lnet_acceptor_port(void);
int lnet_acceptor_start(void);
void lnet_acceptor_stop(void);

struct lnet_inetdev {
	u32	li_cpt;
	u32	li_flags;
	u32	li_ipaddr;
	u32	li_netmask;
	char	li_name[IFNAMSIZ];
};

int lnet_inet_enumerate(struct lnet_inetdev **dev_list, struct net *ns);
void lnet_sock_setbuf(struct socket *socket, int txbufsize, int rxbufsize);
void lnet_sock_getbuf(struct socket *socket, int *txbufsize, int *rxbufsize);
int lnet_sock_getaddr(struct socket *socket, bool remote,
		      struct sockaddr_storage *peer);
int lnet_sock_write(struct socket *sock, void *buffer, int nob, int timeout);
int lnet_sock_read(struct socket *sock, void *buffer, int nob, int timeout);

struct socket *lnet_sock_listen(int port, int backlog,
				struct net *ns);
struct socket *lnet_sock_connect(int interface, int local_port,
				 struct sockaddr *peeraddr,
				 struct net *ns);

int lnet_peers_start_down(void);
int lnet_peer_buffer_credits(struct lnet_net *net);
void lnet_consolidate_routes_locked(struct lnet_peer *orig_lp,
				    struct lnet_peer *new_lp);
void lnet_router_discovery_complete(struct lnet_peer *lp);
void lnet_router_discovery_ping_reply(struct lnet_peer *lp);

int lnet_monitor_thr_start(void);
void lnet_monitor_thr_stop(void);

bool lnet_router_checker_active(void);
void lnet_check_routers(void);
void lnet_wait_router_start(void);
void lnet_swap_pinginfo(struct lnet_ping_buffer *pbuf);

int lnet_ping_info_validate(struct lnet_ping_info *pinfo);
struct lnet_ping_buffer *lnet_ping_buffer_alloc(int nnis, gfp_t gfp);
void lnet_ping_buffer_free(struct lnet_ping_buffer *pbuf);

static inline void lnet_ping_buffer_addref(struct lnet_ping_buffer *pbuf)
{
	atomic_inc(&pbuf->pb_refcnt);
}

static inline void lnet_ping_buffer_decref(struct lnet_ping_buffer *pbuf)
{
	if (atomic_dec_and_test(&pbuf->pb_refcnt)) {
		wake_up_var(&pbuf->pb_refcnt);
		lnet_ping_buffer_free(pbuf);
	}
}

static inline int lnet_push_target_resize_needed(void)
{
	return the_lnet.ln_push_target->pb_nnis < the_lnet.ln_push_target_nnis;
}

int lnet_push_target_resize(void);
int lnet_push_target_post(struct lnet_ping_buffer *pbuf,
			  struct lnet_handle_md *mdh);
void lnet_peer_push_event(struct lnet_event *ev);

int lnet_parse_ip2nets(const char **networksp, const char *ip2nets);
int lnet_parse_routes(const char *route_str, int *im_a_router);
int lnet_parse_networks(struct list_head *nilist, const char *networks);
bool lnet_net_unique(__u32 net_id, struct list_head *nilist,
		     struct lnet_net **net);
bool lnet_ni_unique_net(struct list_head *nilist, char *iface);
void lnet_incr_dlc_seq(void);
__u32 lnet_get_dlc_seq_locked(void);
int lnet_get_net_count(void);
extern unsigned int lnet_current_net_count;

struct lnet_peer_net *lnet_get_next_peer_net_locked(struct lnet_peer *lp,
						    __u32 prev_lpn_id);
struct lnet_peer_ni *lnet_get_next_peer_ni_locked(struct lnet_peer *peer,
						  struct lnet_peer_net *peer_net,
						  struct lnet_peer_ni *prev);
struct lnet_peer_ni *lnet_nid2peerni_locked(lnet_nid_t nid, lnet_nid_t pref,
					int cpt);
struct lnet_peer_ni *lnet_nid2peerni_ex(lnet_nid_t nid, int cpt);
struct lnet_peer_ni *lnet_peer_get_ni_locked(struct lnet_peer *lp,
					     lnet_nid_t nid);
struct lnet_peer_ni *lnet_find_peer_ni_locked(lnet_nid_t nid);
struct lnet_peer *lnet_find_peer(lnet_nid_t nid);
void lnet_peer_net_added(struct lnet_net *net);
lnet_nid_t lnet_peer_primary_nid_locked(lnet_nid_t nid);
int lnet_discover_peer_locked(struct lnet_peer_ni *lpni, int cpt, bool block);
void lnet_peer_queue_message(struct lnet_peer *lp, struct lnet_msg *msg);
int lnet_peer_discovery_start(void);
void lnet_peer_discovery_stop(void);
void lnet_push_update_to_peers(int force);
void lnet_peer_tables_cleanup(struct lnet_net *net);
void lnet_peer_uninit(void);
int lnet_peer_tables_create(void);
void lnet_debug_peer(lnet_nid_t nid);
struct lnet_peer_net *lnet_peer_get_net_locked(struct lnet_peer *peer,
					       __u32 net_id);
bool lnet_peer_is_pref_nid_locked(struct lnet_peer_ni *lpni, lnet_nid_t nid);
int lnet_peer_add_pref_nid(struct lnet_peer_ni *lpni, lnet_nid_t nid);
void lnet_peer_clr_pref_nids(struct lnet_peer_ni *lpni);
bool lnet_peer_is_pref_rtr_locked(struct lnet_peer_ni *lpni, lnet_nid_t gw_nid);
void lnet_peer_clr_pref_rtrs(struct lnet_peer_ni *lpni);
int lnet_peer_add_pref_rtr(struct lnet_peer_ni *lpni, lnet_nid_t nid);
int lnet_peer_ni_set_non_mr_pref_nid(struct lnet_peer_ni *lpni, lnet_nid_t nid);
int lnet_add_peer_ni(lnet_nid_t key_nid, lnet_nid_t nid, bool mr);
int lnet_del_peer_ni(lnet_nid_t key_nid, lnet_nid_t nid);
int lnet_get_peer_info(struct lnet_ioctl_peer_cfg *cfg, void __user *bulk);
int lnet_get_peer_ni_info(__u32 peer_index, __u64 *nid,
			  char alivness[LNET_MAX_STR_LEN],
			  __u32 *cpt_iter, __u32 *refcount,
			  __u32 *ni_peer_tx_credits, __u32 *peer_tx_credits,
			  __u32 *peer_rtr_credits, __u32 *peer_min_rtr_credtis,
			  __u32 *peer_tx_qnob);
int lnet_get_peer_ni_hstats(struct lnet_ioctl_peer_ni_hstats *stats);

static inline void
lnet_peer_net_set_sel_priority_locked(struct lnet_peer_net *lpn, __u32 priority)
{
	lpn->lpn_sel_priority = priority;
}


static inline struct lnet_peer_net *
lnet_find_peer_net_locked(struct lnet_peer *peer, __u32 net_id)
{
	struct lnet_peer_net *peer_net;

	list_for_each_entry(peer_net, &peer->lp_peer_nets, lpn_peer_nets) {
		if (peer_net->lpn_net_id == net_id)
			return peer_net;
	}

	return NULL;
}

static inline bool
lnet_peer_is_multi_rail(struct lnet_peer *lp)
{
	if (lp->lp_state & LNET_PEER_MULTI_RAIL)
		return true;
	return false;
}

static inline bool
lnet_peer_ni_is_configured(struct lnet_peer_ni *lpni)
{
	if (lpni->lpni_peer_net->lpn_peer->lp_state & LNET_PEER_CONFIGURED)
		return true;
	return false;
}

static inline bool
lnet_peer_ni_is_primary(struct lnet_peer_ni *lpni)
{
	return lpni->lpni_nid == lpni->lpni_peer_net->lpn_peer->lp_primary_nid;
}

bool lnet_peer_is_uptodate(struct lnet_peer *lp);
bool lnet_peer_is_uptodate_locked(struct lnet_peer *lp);
bool lnet_is_discovery_disabled(struct lnet_peer *lp);
bool lnet_is_discovery_disabled_locked(struct lnet_peer *lp);
bool lnet_peer_gw_discovery(struct lnet_peer *lp);

static inline bool
lnet_peer_needs_push(struct lnet_peer *lp)
{
	if (!(lp->lp_state & LNET_PEER_MULTI_RAIL))
		return false;
	if (lp->lp_state & LNET_PEER_MARK_DELETED)
		return false;
	if (lp->lp_state & LNET_PEER_FORCE_PUSH)
		return true;
	if (lp->lp_state & LNET_PEER_NO_DISCOVERY)
		return false;
	/* if discovery is not enabled then no need to push */
	if (lnet_peer_discovery_disabled)
		return false;
	if (lp->lp_node_seqno < atomic_read(&the_lnet.ln_ping_target_seqno))
		return true;
	return false;
}

#define LNET_RECOVERY_INTERVAL_MAX 900
static inline unsigned int
lnet_get_next_recovery_ping(unsigned int ping_count, time64_t now)
{
	unsigned int interval;

	/* 2^9 = 512, 2^10 = 1024 */
	if (ping_count > 9)
		interval = LNET_RECOVERY_INTERVAL_MAX;
	else
		interval = 1 << ping_count;

	return now + interval;
}

static inline void
lnet_peer_ni_set_next_ping(struct lnet_peer_ni *lpni, time64_t now)
{
	lpni->lpni_next_ping =
		lnet_get_next_recovery_ping(lpni->lpni_ping_count, now);
}

static inline void
lnet_ni_set_next_ping(struct lnet_ni *ni, time64_t now)
{
	ni->ni_next_ping = lnet_get_next_recovery_ping(ni->ni_ping_count, now);
}

/*
 * A peer NI is alive if it satisfies the following two conditions:
 *  1. peer NI health >= LNET_MAX_HEALTH_VALUE * router_sensitivity_percentage
 *  2. the cached NI status received when we discover the peer is UP
 */
static inline bool
lnet_is_peer_ni_alive(struct lnet_peer_ni *lpni)
{
	bool halive = false;

	halive = (atomic_read(&lpni->lpni_healthv) >=
		 (LNET_MAX_HEALTH_VALUE * router_sensitivity_percentage / 100));

	return halive && lpni->lpni_ns_status == LNET_NI_STATUS_UP;
}

static inline void
lnet_update_peer_net_healthv(struct lnet_peer_ni *lpni)
{
	struct lnet_peer_net *lpn;
	int best_healthv = 0;

	lpn = lpni->lpni_peer_net;

	list_for_each_entry(lpni, &lpn->lpn_peer_nis, lpni_peer_nis) {
		int lpni_healthv = atomic_read(&lpni->lpni_healthv);
		if (best_healthv < lpni_healthv)
			best_healthv = lpni_healthv;
	}

	lpn->lpn_healthv = best_healthv;
}

static inline void
lnet_set_lpni_healthv_locked(struct lnet_peer_ni *lpni, int value)
{
	if (atomic_read(&lpni->lpni_healthv) == value)
		return;
	atomic_set(&lpni->lpni_healthv, value);
	lnet_update_peer_net_healthv(lpni);
}

static inline bool
lnet_atomic_add_unless_max(atomic_t *v, int a, int u)
{
	int c = atomic_read(v);
	bool mod = false;
	int old;
	int m;

	if (c == u)
		return mod;

	for (;;) {
		if (c + a >= u)
			m = u;
		else
			m = c + a;
		old = atomic_cmpxchg(v, c, m);

		if (old == u)
			break;

		if (old == c) {
			mod = true;
			break;
		}
		c = old;
	}

	return mod;
}

static inline void
lnet_inc_lpni_healthv_locked(struct lnet_peer_ni *lpni, int value)
{
	/* only adjust the net health if the lpni health value changed */
	if (lnet_atomic_add_unless_max(&lpni->lpni_healthv, value,
				       LNET_MAX_HEALTH_VALUE))
		lnet_update_peer_net_healthv(lpni);
}

static inline void
lnet_inc_healthv(atomic_t *healthv, int value)
{
	lnet_atomic_add_unless_max(healthv, value, LNET_MAX_HEALTH_VALUE);
}

static inline int
lnet_get_list_len(struct list_head *list)
{
	struct list_head *l;
	int count = 0;

	list_for_each(l, list)
		count++;

	return count;
}

void lnet_incr_stats(struct lnet_element_stats *stats,
		     enum lnet_msg_type msg_type,
		     enum lnet_stats_type stats_type);

__u32 lnet_sum_stats(struct lnet_element_stats *stats,
		     enum lnet_stats_type stats_type);

void lnet_usr_translate_stats(struct lnet_ioctl_element_msg_stats *msg_stats,
			      struct lnet_element_stats *stats);

static inline void
lnet_set_route_aliveness(struct lnet_route *route, bool alive)
{
	bool old = atomic_xchg(&route->lr_alive, alive);

	if (old != alive)
		CERROR("route to %s through %s has gone from %s to %s\n",
		       libcfs_net2str(route->lr_net),
		       libcfs_nid2str(route->lr_gateway->lp_primary_nid),
		       old ? "up" : "down",
		       alive ? "up" : "down");
}
#endif
