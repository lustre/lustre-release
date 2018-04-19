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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <linux/log2.h>
#include <linux/ktime.h>

#include <lnet/lib-lnet.h>

#define D_LNI D_CONSOLE

struct lnet the_lnet;		/* THE state of the network */
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

static int use_tcp_bonding = false;
module_param(use_tcp_bonding, int, 0444);
MODULE_PARM_DESC(use_tcp_bonding,
		 "Set to 1 to use socklnd bonding. 0 to use Multi-Rail");

unsigned int lnet_numa_range = 0;
module_param(lnet_numa_range, uint, 0444);
MODULE_PARM_DESC(lnet_numa_range,
		"NUMA range to consider during Multi-Rail selection");

/*
 * This sequence number keeps track of how many times DLC was used to
 * update the local NIs. It is incremented when a NI is added or
 * removed and checked when sending a message to determine if there is
 * a need to re-run the selection algorithm. See lnet_select_pathway()
 * for more details on its usage.
 */
static atomic_t lnet_dlc_seq_no = ATOMIC_INIT(0);

static int lnet_ping(struct lnet_process_id id, signed long timeout,
		     struct lnet_process_id __user *ids, int n_ids);

static char *
lnet_get_routes(void)
{
	return routes;
}

static char *
lnet_get_networks(void)
{
	char   *nets;
	int	rc;

	if (*networks != 0 && *ip2nets != 0) {
		LCONSOLE_ERROR_MSG(0x101, "Please specify EITHER 'networks' or "
				   "'ip2nets' but not both at once\n");
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
	init_waitqueue_head(&the_lnet.ln_eq_waitq);
	init_waitqueue_head(&the_lnet.ln_rc_waitq);
	mutex_init(&the_lnet.ln_lnd_mutex);
	mutex_init(&the_lnet.ln_api_mutex);
}

static void
lnet_fini_locks(void)
{
}

struct kmem_cache *lnet_mes_cachep;	   /* MEs kmem_cache */
struct kmem_cache *lnet_small_mds_cachep;  /* <= LNET_SMALL_MD_SIZE bytes
					    *  MDs kmem_cache */

static int
lnet_descriptor_setup(void)
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

	return 0;
}

static void
lnet_descriptor_cleanup(void)
{

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
	LIBCFS_ALLOC(hash, LNET_REMOTE_NETS_HASH_SIZE * sizeof(*hash));
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

	LIBCFS_FREE(the_lnet.ln_remote_nets_hash,
		    LNET_REMOTE_NETS_HASH_SIZE *
		    sizeof(the_lnet.ln_remote_nets_hash[0]));
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

	lnet_fini_locks();
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
	 * with gcc version 3.3.3 20040412 (Red Hat Linux 3.3.3-7) */

	/* Constants... */
	CLASSERT(LNET_PROTO_TCP_MAGIC == 0xeebc0ded);
	CLASSERT(LNET_PROTO_TCP_VERSION_MAJOR == 1);
	CLASSERT(LNET_PROTO_TCP_VERSION_MINOR == 0);
	CLASSERT(LNET_MSG_ACK == 0);
	CLASSERT(LNET_MSG_PUT == 1);
	CLASSERT(LNET_MSG_GET == 2);
	CLASSERT(LNET_MSG_REPLY == 3);
	CLASSERT(LNET_MSG_HELLO == 4);

	/* Checks for struct lnet_handle_wire */
	CLASSERT((int)sizeof(struct lnet_handle_wire) == 16);
	CLASSERT((int)offsetof(struct lnet_handle_wire, wh_interface_cookie) == 0);
	CLASSERT((int)sizeof(((struct lnet_handle_wire *)0)->wh_interface_cookie) == 8);
	CLASSERT((int)offsetof(struct lnet_handle_wire, wh_object_cookie) == 8);
	CLASSERT((int)sizeof(((struct lnet_handle_wire *)0)->wh_object_cookie) == 8);

	/* Checks for struct struct lnet_magicversion */
	CLASSERT((int)sizeof(struct lnet_magicversion) == 8);
	CLASSERT((int)offsetof(struct lnet_magicversion, magic) == 0);
	CLASSERT((int)sizeof(((struct lnet_magicversion *)0)->magic) == 4);
	CLASSERT((int)offsetof(struct lnet_magicversion, version_major) == 4);
	CLASSERT((int)sizeof(((struct lnet_magicversion *)0)->version_major) == 2);
	CLASSERT((int)offsetof(struct lnet_magicversion, version_minor) == 6);
	CLASSERT((int)sizeof(((struct lnet_magicversion *)0)->version_minor) == 2);

	/* Checks for struct struct lnet_hdr */
	CLASSERT((int)sizeof(struct lnet_hdr) == 72);
	CLASSERT((int)offsetof(struct lnet_hdr, dest_nid) == 0);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->dest_nid) == 8);
	CLASSERT((int)offsetof(struct lnet_hdr, src_nid) == 8);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->src_nid) == 8);
	CLASSERT((int)offsetof(struct lnet_hdr, dest_pid) == 16);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->dest_pid) == 4);
	CLASSERT((int)offsetof(struct lnet_hdr, src_pid) == 20);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->src_pid) == 4);
	CLASSERT((int)offsetof(struct lnet_hdr, type) == 24);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->type) == 4);
	CLASSERT((int)offsetof(struct lnet_hdr, payload_length) == 28);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->payload_length) == 4);
	CLASSERT((int)offsetof(struct lnet_hdr, msg) == 32);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg) == 40);

	/* Ack */
	CLASSERT((int)offsetof(struct lnet_hdr, msg.ack.dst_wmd) == 32);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.ack.dst_wmd) == 16);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.ack.match_bits) == 48);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.ack.match_bits) == 8);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.ack.mlength) == 56);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.ack.mlength) == 4);

	/* Put */
	CLASSERT((int)offsetof(struct lnet_hdr, msg.put.ack_wmd) == 32);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.put.ack_wmd) == 16);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.put.match_bits) == 48);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.put.match_bits) == 8);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.put.hdr_data) == 56);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.put.hdr_data) == 8);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.put.ptl_index) == 64);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.put.ptl_index) == 4);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.put.offset) == 68);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.put.offset) == 4);

	/* Get */
	CLASSERT((int)offsetof(struct lnet_hdr, msg.get.return_wmd) == 32);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.get.return_wmd) == 16);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.get.match_bits) == 48);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.get.match_bits) == 8);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.get.ptl_index) == 56);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.get.ptl_index) == 4);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.get.src_offset) == 60);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.get.src_offset) == 4);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.get.sink_length) == 64);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.get.sink_length) == 4);

	/* Reply */
	CLASSERT((int)offsetof(struct lnet_hdr, msg.reply.dst_wmd) == 32);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.reply.dst_wmd) == 16);

	/* Hello */
	CLASSERT((int)offsetof(struct lnet_hdr, msg.hello.incarnation) == 32);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.hello.incarnation) == 8);
	CLASSERT((int)offsetof(struct lnet_hdr, msg.hello.type) == 40);
	CLASSERT((int)sizeof(((struct lnet_hdr *)0)->msg.hello.type) == 4);
}

static struct lnet_lnd *lnet_find_lnd_by_type(__u32 type)
{
	struct lnet_lnd *lnd;
	struct list_head *tmp;

	/* holding lnd mutex */
	list_for_each(tmp, &the_lnet.ln_lnds) {
		lnd = list_entry(tmp, struct lnet_lnd, lnd_list);

		if (lnd->lnd_type == type)
			return lnd;
	}
	return NULL;
}

void
lnet_register_lnd(struct lnet_lnd *lnd)
{
	mutex_lock(&the_lnet.ln_lnd_mutex);

	LASSERT(libcfs_isknown_lnd(lnd->lnd_type));
	LASSERT(lnet_find_lnd_by_type(lnd->lnd_type) == NULL);

	list_add_tail(&lnd->lnd_list, &the_lnet.ln_lnds);
	lnd->lnd_refcount = 0;

	CDEBUG(D_NET, "%s LND registered\n", libcfs_lnd2str(lnd->lnd_type));

	mutex_unlock(&the_lnet.ln_lnd_mutex);
}
EXPORT_SYMBOL(lnet_register_lnd);

void
lnet_unregister_lnd(struct lnet_lnd *lnd)
{
	mutex_lock(&the_lnet.ln_lnd_mutex);

	LASSERT(lnet_find_lnd_by_type(lnd->lnd_type) == lnd);
	LASSERT(lnd->lnd_refcount == 0);

	list_del(&lnd->lnd_list);
	CDEBUG(D_NET, "%s LND unregistered\n", libcfs_lnd2str(lnd->lnd_type));

	mutex_unlock(&the_lnet.ln_lnd_mutex);
}
EXPORT_SYMBOL(lnet_unregister_lnd);

void
lnet_counters_get(struct lnet_counters *counters)
{
	struct lnet_counters *ctr;
	int		i;

	memset(counters, 0, sizeof(*counters));

	lnet_net_lock(LNET_LOCK_EX);

	cfs_percpt_for_each(ctr, i, the_lnet.ln_counters) {
		counters->msgs_max     += ctr->msgs_max;
		counters->msgs_alloc   += ctr->msgs_alloc;
		counters->errors       += ctr->errors;
		counters->send_count   += ctr->send_count;
		counters->recv_count   += ctr->recv_count;
		counters->route_count  += ctr->route_count;
		counters->drop_count   += ctr->drop_count;
		counters->send_length  += ctr->send_length;
		counters->recv_length  += ctr->recv_length;
		counters->route_length += ctr->route_length;
		counters->drop_length  += ctr->drop_length;

	}
	lnet_net_unlock(LNET_LOCK_EX);
}
EXPORT_SYMBOL(lnet_counters_get);

void
lnet_counters_reset(void)
{
	struct lnet_counters *counters;
	int		i;

	lnet_net_lock(LNET_LOCK_EX);

	cfs_percpt_for_each(counters, i, the_lnet.ln_counters)
		memset(counters, 0, sizeof(struct lnet_counters));

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
		if (rec->rec_type == LNET_COOKIE_TYPE_EQ) {
			lnet_eq_free(list_entry(e, struct lnet_eq, eq_list));

		} else if (rec->rec_type == LNET_COOKIE_TYPE_MD) {
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
		LIBCFS_FREE(rec->rec_lh_hash,
			    LNET_LH_HASH_SIZE * sizeof(rec->rec_lh_hash[0]));
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
	INIT_LIST_HEAD(&the_lnet.ln_peers);
	INIT_LIST_HEAD(&the_lnet.ln_remote_peer_ni_list);
	INIT_LIST_HEAD(&the_lnet.ln_nets);
	INIT_LIST_HEAD(&the_lnet.ln_routers);
	INIT_LIST_HEAD(&the_lnet.ln_drop_rules);
	INIT_LIST_HEAD(&the_lnet.ln_delay_rules);

	rc = lnet_descriptor_setup();
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

	recs = lnet_res_containers_create(LNET_COOKIE_TYPE_ME);
	if (recs == NULL) {
		rc = -ENOMEM;
		goto failed;
	}

	the_lnet.ln_me_containers = recs;

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

	return 0;

 failed:
	lnet_unprepare();
	return rc;
}

static int
lnet_unprepare (void)
{
	/* NB no LNET_LOCK since this is the last reference.  All LND instances
	 * have shut down already, so it is safe to unlink and free all
	 * descriptors, even those that appear committed to a network op (eg MD
	 * with non-zero pending count) */

	lnet_fail_nid(LNET_NID_ANY, 0);

	LASSERT(the_lnet.ln_refcount == 0);
	LASSERT(list_empty(&the_lnet.ln_test_peers));
	LASSERT(list_empty(&the_lnet.ln_nets));

	lnet_portals_destroy();

	if (the_lnet.ln_md_containers != NULL) {
		lnet_res_containers_destroy(the_lnet.ln_md_containers);
		the_lnet.ln_md_containers = NULL;
	}

	if (the_lnet.ln_me_containers != NULL) {
		lnet_res_containers_destroy(the_lnet.ln_me_containers);
		the_lnet.ln_me_containers = NULL;
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
	lnet_descriptor_cleanup();

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
			ni = list_entry(net->net_ni_list.next, struct lnet_ni,
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

unsigned int
lnet_nid_cpt_hash(lnet_nid_t nid, unsigned int number)
{
	__u64		key = nid;
	unsigned int	val;

	LASSERT(number >= 1 && number <= LNET_CPT_NUMBER);

	if (number == 1)
		return 0;

	val = hash_long(key, LNET_CPT_BITS);
	/* NB: LNET_CP_NUMBER doesn't have to be PO2 */
	if (val < number)
		return val;

	return (unsigned int)(key + val + (val >> 1)) % number;
}

int
lnet_cpt_of_nid_locked(lnet_nid_t nid, struct lnet_ni *ni)
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
	net = lnet_get_net_locked(LNET_NIDNET(nid));

	if (net != NULL && net->net_cpts != NULL) {
		return net->net_cpts[lnet_nid_cpt_hash(nid, net->net_ncpts)];
	}

	return lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);
}

int
lnet_cpt_of_nid(lnet_nid_t nid, struct lnet_ni *ni)
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
EXPORT_SYMBOL(lnet_cpt_of_nid);

int
lnet_islocalnet(__u32 net_id)
{
	struct lnet_net *net;
	int		cpt;
	bool		local;

	cpt = lnet_net_lock_current();

	net = lnet_get_net_locked(net_id);

	local = net != NULL;

	lnet_net_unlock(cpt);

	return local;
}

bool
lnet_is_ni_healthy_locked(struct lnet_ni *ni)
{
	if (ni->ni_state == LNET_NI_STATE_ACTIVE ||
	    ni->ni_state == LNET_NI_STATE_DEGRADED)
		return true;

	return false;
}

struct lnet_ni  *
lnet_nid2ni_locked(lnet_nid_t nid, int cpt)
{
	struct lnet_net  *net;
	struct lnet_ni	 *ni;

	LASSERT(cpt != LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (ni->ni_nid == nid)
				return ni;
		}
	}

	return NULL;
}

struct lnet_ni *
lnet_nid2ni_addref(lnet_nid_t nid)
{
	struct lnet_ni *ni;

	lnet_net_lock(0);
	ni = lnet_nid2ni_locked(nid, 0);
	if (ni)
		lnet_ni_addref_locked(ni, 0);
	lnet_net_unlock(0);

	return ni;
}
EXPORT_SYMBOL(lnet_nid2ni_addref);

int
lnet_islocalnid(lnet_nid_t nid)
{
	struct lnet_ni	*ni;
	int		cpt;

	cpt = lnet_net_lock_current();
	ni = lnet_nid2ni_locked(nid, cpt);
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

static struct lnet_ping_info *
lnet_ping_info_create(int num_ni)
{
	struct lnet_ping_info *ping_info;
	unsigned int	 infosz;

	infosz = offsetof(struct lnet_ping_info, pi_ni[num_ni]);
	LIBCFS_ALLOC(ping_info, infosz);
	if (ping_info == NULL) {
		CERROR("Can't allocate ping info[%d]\n", num_ni);
		return NULL;
	}

	ping_info->pi_nnis = num_ni;
	ping_info->pi_pid = the_lnet.ln_pid;
	ping_info->pi_magic = LNET_PROTO_PING_MAGIC;
	ping_info->pi_features = LNET_PING_FEAT_NI_STATUS;

	return ping_info;
}

static inline int
lnet_get_net_ni_count_locked(struct lnet_net *net)
{
	struct lnet_ni	*ni;
	int		count = 0;

	list_for_each_entry(ni, &net->net_ni_list, ni_netlist)
		count++;

	return count;
}

static inline int
lnet_get_net_ni_count_pre(struct lnet_net *net)
{
	struct lnet_ni	*ni;
	int		count = 0;

	list_for_each_entry(ni, &net->net_ni_added, ni_netlist)
		count++;

	return count;
}

static inline int
lnet_get_ni_count(void)
{
	struct lnet_ni	*ni;
	struct lnet_net *net;
	int		count = 0;

	lnet_net_lock(0);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist)
			count++;
	}

	lnet_net_unlock(0);

	return count;
}

static inline void
lnet_ping_info_free(struct lnet_ping_info *pinfo)
{
	LIBCFS_FREE(pinfo,
		    offsetof(struct lnet_ping_info,
			     pi_ni[pinfo->pi_nnis]));
}

static void
lnet_ping_info_destroy(void)
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

	lnet_ping_info_free(the_lnet.ln_ping_info);
	the_lnet.ln_ping_info = NULL;

	lnet_net_unlock(LNET_LOCK_EX);
}

static void
lnet_ping_event_handler(struct lnet_event *event)
{
	struct lnet_ping_info *pinfo = event->md.user_ptr;

	if (event->unlinked)
		pinfo->pi_features = LNET_PING_FEAT_INVAL;
}

static int
lnet_ping_info_setup(struct lnet_ping_info **ppinfo,
		     struct lnet_handle_md *md_handle,
		     int ni_count, bool set_eq)
{
	struct lnet_process_id id = {
		.nid = LNET_NID_ANY,
		.pid = LNET_PID_ANY
	};
	struct lnet_handle_me me_handle;
	struct lnet_md md = { NULL };
	int rc, rc2;

	if (set_eq) {
		rc = LNetEQAlloc(0, lnet_ping_event_handler,
				 &the_lnet.ln_ping_target_eq);
		if (rc != 0) {
			CERROR("Can't allocate ping EQ: %d\n", rc);
			return rc;
		}
	}

	*ppinfo = lnet_ping_info_create(ni_count);
	if (*ppinfo == NULL) {
		rc = -ENOMEM;
		goto failed_0;
	}

	rc = LNetMEAttach(LNET_RESERVED_PORTAL, id,
			  LNET_PROTO_PING_MATCHBITS, 0,
			  LNET_UNLINK, LNET_INS_AFTER,
			  &me_handle);
	if (rc != 0) {
		CERROR("Can't create ping ME: %d\n", rc);
		goto failed_1;
	}

	/* initialize md content */
	md.start     = *ppinfo;
	md.length    = offsetof(struct lnet_ping_info,
				pi_ni[(*ppinfo)->pi_nnis]);
	md.threshold = LNET_MD_THRESH_INF;
	md.max_size  = 0;
	md.options   = LNET_MD_OP_GET | LNET_MD_TRUNCATE |
		       LNET_MD_MANAGE_REMOTE;
	md.user_ptr  = NULL;
	md.eq_handle = the_lnet.ln_ping_target_eq;
	md.user_ptr = *ppinfo;

	rc = LNetMDAttach(me_handle, md, LNET_RETAIN, md_handle);
	if (rc != 0) {
		CERROR("Can't attach ping MD: %d\n", rc);
		goto failed_2;
	}

	return 0;

failed_2:
	rc2 = LNetMEUnlink(me_handle);
	LASSERT(rc2 == 0);
failed_1:
	lnet_ping_info_free(*ppinfo);
	*ppinfo = NULL;
failed_0:
	if (set_eq)
		LNetEQFree(the_lnet.ln_ping_target_eq);
	return rc;
}

static void
lnet_ping_md_unlink(struct lnet_ping_info *pinfo, struct lnet_handle_md *md_handle)
{
	sigset_t	blocked = cfs_block_allsigs();

	LNetMDUnlink(*md_handle);
	LNetInvalidateMDHandle(md_handle);

	/* NB md could be busy; this just starts the unlink */
	while (pinfo->pi_features != LNET_PING_FEAT_INVAL) {
		CDEBUG(D_NET, "Still waiting for ping MD to unlink\n");
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1));
	}

	cfs_restore_sigs(blocked);
}

static void
lnet_ping_info_install_locked(struct lnet_ping_info *ping_info)
{
	int			i;
	struct lnet_ni		*ni;
	struct lnet_net		*net;
	struct lnet_ni_status *ns;

	i = 0;
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			LASSERT(i < ping_info->pi_nnis);

			ns = &ping_info->pi_ni[i];

			ns->ns_nid = ni->ni_nid;

			lnet_ni_lock(ni);
			ns->ns_status = (ni->ni_status != NULL) ?
					ni->ni_status->ns_status :
						LNET_NI_STATUS_UP;
			ni->ni_status = ns;
			lnet_ni_unlock(ni);

			i++;
		}

	}
}

static void
lnet_ping_target_update(struct lnet_ping_info *pinfo,
			struct lnet_handle_md md_handle)
{
	struct lnet_ping_info *old_pinfo = NULL;
	struct lnet_handle_md old_md;

	/* switch the NIs to point to the new ping info created */
	lnet_net_lock(LNET_LOCK_EX);

	if (!the_lnet.ln_routing)
		pinfo->pi_features |= LNET_PING_FEAT_RTE_DISABLED;
	lnet_ping_info_install_locked(pinfo);

	if (the_lnet.ln_ping_info != NULL) {
		old_pinfo = the_lnet.ln_ping_info;
		old_md = the_lnet.ln_ping_target_md;
	}
	the_lnet.ln_ping_target_md = md_handle;
	the_lnet.ln_ping_info = pinfo;

	lnet_net_unlock(LNET_LOCK_EX);

	if (old_pinfo != NULL) {
		/* unlink the old ping info */
		lnet_ping_md_unlink(old_pinfo, &old_md);
		lnet_ping_info_free(old_pinfo);
	}
}

static void
lnet_ping_target_fini(void)
{
	int		rc;

	lnet_ping_md_unlink(the_lnet.ln_ping_info,
			    &the_lnet.ln_ping_target_md);

	rc = LNetEQFree(the_lnet.ln_ping_target_eq);
	LASSERT(rc == 0);

	lnet_ping_info_destroy();
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
	if (!list_empty(&ni->ni_cptlist)) {
		list_del_init(&ni->ni_cptlist);
		lnet_ni_decref_locked(ni, 0);
	}

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
	while (!list_empty(zombie_list)) {
		int	*ref;
		int	j;

		ni = list_entry(zombie_list->next,
				struct lnet_ni, ni_netlist);
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
			lnet_net_unlock(LNET_LOCK_EX);
			++i;
			if ((i & (-i)) == i) {
				CDEBUG(D_WARNING,
				       "Waiting for zombie LNI %s\n",
				       libcfs_nid2str(ni->ni_nid));
			}
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(cfs_time_seconds(1));
			lnet_net_lock(LNET_LOCK_EX);
			continue;
		}

		lnet_net_unlock(LNET_LOCK_EX);

		islo = ni->ni_net->net_lnd->lnd_type == LOLND;

		LASSERT(!in_interrupt());
		(net->net_lnd->lnd_shutdown)(ni);

		if (!islo)
			CDEBUG(D_LNI, "Removed LNI %s\n",
			      libcfs_nid2str(ni->ni_nid));

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
	ni->ni_state = LNET_NI_STATE_DELETING;
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

	net->net_state = LNET_NET_STATE_DELETING;

	list_del_init(&net->net_list);

	while (!list_empty(&net->net_ni_list)) {
		ni = list_entry(net->net_ni_list.next,
				struct lnet_ni, ni_netlist);
		lnet_net_unlock(LNET_LOCK_EX);
		lnet_shutdown_lndni(ni);
		lnet_net_lock(LNET_LOCK_EX);
	}

	lnet_net_unlock(LNET_LOCK_EX);

	/* Do peer table cleanup for this net */
	lnet_peer_tables_cleanup(net);

	lnet_net_lock(LNET_LOCK_EX);
	/*
	 * decrement ref count on lnd only when the entire network goes
	 * away
	 */
	net->net_lnd->lnd_refcount--;

	lnet_net_unlock(LNET_LOCK_EX);

	lnet_net_free(net);
}

static void
lnet_shutdown_lndnets(void)
{
	struct lnet_net *net;

	/* NB called holding the global mutex */

	/* All quiet on the API front */
	LASSERT(the_lnet.ln_state == LNET_STATE_RUNNING);
	LASSERT(the_lnet.ln_refcount == 0);

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_state = LNET_STATE_STOPPING;

	while (!list_empty(&the_lnet.ln_nets)) {
		/*
		 * move the nets to the zombie list to avoid them being
		 * picked up for new work. LONET is also included in the
		 * Nets that will be moved to the zombie list
		 */
		net = list_entry(the_lnet.ln_nets.next,
				 struct lnet_net, net_list);
		list_move(&net->net_list, &the_lnet.ln_net_zombie);
	}

	/* Drop the cached loopback Net. */
	if (the_lnet.ln_loni != NULL) {
		lnet_ni_decref_locked(the_lnet.ln_loni, 0);
		the_lnet.ln_loni = NULL;
	}
	lnet_net_unlock(LNET_LOCK_EX);

	/* iterate through the net zombie list and delete each net */
	while (!list_empty(&the_lnet.ln_net_zombie)) {
		net = list_entry(the_lnet.ln_net_zombie.next,
				 struct lnet_net, net_list);
		lnet_shutdown_lndnet(net);
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
		LCONSOLE_ERROR_MSG(0x105, "Error %d starting up LNI %s\n",
				   rc, libcfs_lnd2str(net->net_lnd->lnd_type));
		lnet_net_lock(LNET_LOCK_EX);
		net->net_lnd->lnd_refcount--;
		lnet_net_unlock(LNET_LOCK_EX);
		goto failed0;
	}

	ni->ni_state = LNET_NI_STATE_ACTIVE;

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
		LCONSOLE_ERROR_MSG(0x107, "LNI %s has no %scredits\n",
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

	CDEBUG(D_LNI, "Added LNI %s [%d/%d/%d/%d]\n",
		libcfs_nid2str(ni->ni_nid),
		ni->ni_net->net_tunables.lct_peer_tx_credits,
		lnet_ni_tq_credits(ni) * LNET_CPT_NUMBER,
		ni->ni_net->net_tunables.lct_peer_rtr_credits,
		ni->ni_net->net_tunables.lct_peer_timeout);

	return 0;
failed0:
	lnet_ni_free(ni);
	return rc;
}

static int
lnet_startup_lndnet(struct lnet_net *net, struct lnet_lnd_tunables *tun)
{
	struct lnet_ni *ni;
	struct lnet_net	*net_l = NULL;
	struct list_head	local_ni_list;
	int			rc;
	int			ni_count = 0;
	__u32			lnd_type;
	struct lnet_lnd *lnd;
	int			peer_timeout =
		net->net_tunables.lct_peer_timeout;
	int			maxtxcredits =
		net->net_tunables.lct_max_tx_credits;
	int			peerrtrcredits =
		net->net_tunables.lct_peer_rtr_credits;

	INIT_LIST_HEAD(&local_ni_list);

	/*
	 * make sure that this net is unique. If it isn't then
	 * we are adding interfaces to an already existing network, and
	 * 'net' is just a convenient way to pass in the list.
	 * if it is unique we need to find the LND and load it if
	 * necessary.
	 */
	if (lnet_net_unique(net->net_id, &the_lnet.ln_nets, &net_l)) {
		lnd_type = LNET_NETTYP(net->net_id);

		LASSERT(libcfs_isknown_lnd(lnd_type));

		mutex_lock(&the_lnet.ln_lnd_mutex);
		lnd = lnet_find_lnd_by_type(lnd_type);

		if (lnd == NULL) {
			mutex_unlock(&the_lnet.ln_lnd_mutex);
			rc = request_module("%s", libcfs_lnd2modname(lnd_type));
			mutex_lock(&the_lnet.ln_lnd_mutex);

			lnd = lnet_find_lnd_by_type(lnd_type);
			if (lnd == NULL) {
				mutex_unlock(&the_lnet.ln_lnd_mutex);
				CERROR("Can't load LND %s, module %s, rc=%d\n",
				libcfs_lnd2str(lnd_type),
				libcfs_lnd2modname(lnd_type), rc);
#ifndef HAVE_MODULE_LOADING_SUPPORT
				LCONSOLE_ERROR_MSG(0x104, "Your kernel must be "
						"compiled with kernel module "
						"loading support.");
#endif
				rc = -EINVAL;
				goto failed0;
			}
		}

		lnet_net_lock(LNET_LOCK_EX);
		lnd->lnd_refcount++;
		lnet_net_unlock(LNET_LOCK_EX);

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

	/*
	 * When a network uses TCP bonding then all its interfaces
	 * must be specified when the network is first defined: the
	 * TCP bonding code doesn't allow for interfaces to be added
	 * or removed.
	 */
	if (net_l != net && net_l != NULL && use_tcp_bonding &&
	    LNET_NETTYP(net_l->net_id) == SOCKLND) {
		rc = -EINVAL;
		goto failed0;
	}

	while (!list_empty(&net->net_ni_added)) {
		ni = list_entry(net->net_ni_added.next, struct lnet_ni,
				ni_netlist);
		list_del_init(&ni->ni_netlist);

		/* make sure that the the NI we're about to start
		 * up is actually unique. if it's not fail. */
		if (!lnet_ni_unique_net(&net_l->net_ni_list,
					ni->ni_interfaces[0])) {
			rc = -EINVAL;
			goto failed1;
		}

		/* adjust the pointer the parent network, just in case it
		 * the net is a duplicate */
		ni->ni_net = net_l;

		rc = lnet_startup_lndni(ni, tun);

		LASSERT(ni->ni_net->net_tunables.lct_peer_timeout <= 0 ||
			ni->ni_net->net_lnd->lnd_query != NULL);

		if (rc < 0)
			goto failed1;

		lnet_ni_addref(ni);
		list_add_tail(&ni->ni_netlist, &local_ni_list);

		ni_count++;
	}

	lnet_net_lock(LNET_LOCK_EX);
	list_splice_tail(&local_ni_list, &net_l->net_ni_list);
	lnet_incr_dlc_seq();
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
		net->net_state = LNET_NET_STATE_ACTIVE;
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
	while (!list_empty(&local_ni_list)) {
		ni = list_entry(local_ni_list.next, struct lnet_ni,
				ni_netlist);

		lnet_shutdown_lndni(ni);
	}

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

	while (!list_empty(netlist)) {
		net = list_entry(netlist->next, struct lnet_net, net_list);
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

	memset(&the_lnet, 0, sizeof(the_lnet));

	/* refer to global cfs_cpt_table for now */
	the_lnet.ln_cpt_table	= cfs_cpt_table;
	the_lnet.ln_cpt_number	= cfs_cpt_number(cfs_cpt_table);

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

	the_lnet.ln_refcount = 0;
	LNetInvalidateEQHandle(&the_lnet.ln_rc_eqh);
	INIT_LIST_HEAD(&the_lnet.ln_lnds);
	INIT_LIST_HEAD(&the_lnet.ln_net_zombie);
	INIT_LIST_HEAD(&the_lnet.ln_rcd_zombie);
	INIT_LIST_HEAD(&the_lnet.ln_rcd_deathrow);

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
 */
void lnet_lib_exit(void)
{
	LASSERT(the_lnet.ln_refcount == 0);

	while (!list_empty(&the_lnet.ln_lnds))
		lnet_unregister_lnd(list_entry(the_lnet.ln_lnds.next,
					       struct lnet_lnd, lnd_list));
	lnet_destroy_locks();
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
	int			im_a_router = 0;
	int			rc;
	int			ni_count;
	struct lnet_ping_info	*pinfo;
	struct lnet_handle_md	md_handle;
	struct list_head	net_head;
	struct lnet_net		*net;

	INIT_LIST_HEAD(&net_head);

	mutex_lock(&the_lnet.ln_api_mutex);

	CDEBUG(D_OTHER, "refs %d\n", the_lnet.ln_refcount);

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

	/* If LNet is being initialized via DLC it is possible
	 * that the user requests not to load module parameters (ones which
	 * are supported by DLC) on initialization.  Therefore, make sure not
	 * to load networks, routes and forwarding from module parameters
	 * in this case.  On cleanup in case of failure only clean up
	 * routes if it has been loaded */
	if (!the_lnet.ln_nis_from_mod_params) {
		rc = lnet_parse_networks(&net_head, lnet_get_networks(),
					 use_tcp_bonding);
		if (rc < 0)
			goto err_empty_list;
	}

	ni_count = lnet_startup_lndnets(&net_head);
	if (ni_count < 0) {
		rc = ni_count;
		goto err_empty_list;
	}

	if (!the_lnet.ln_nis_from_mod_params) {
		rc = lnet_parse_routes(lnet_get_routes(), &im_a_router);
		if (rc != 0)
			goto err_shutdown_lndnis;

		rc = lnet_check_routes();
		if (rc != 0)
			goto err_destroy_routes;

		rc = lnet_rtrpools_alloc(im_a_router);
		if (rc != 0)
			goto err_destroy_routes;
	}

	rc = lnet_acceptor_start();
	if (rc != 0)
		goto err_destroy_routes;

	the_lnet.ln_refcount = 1;
	/* Now I may use my own API functions... */

	rc = lnet_ping_info_setup(&pinfo, &md_handle, ni_count, true);
	if (rc != 0)
		goto err_acceptor_stop;

	lnet_ping_target_update(pinfo, md_handle);

	rc = lnet_router_checker_start();
	if (rc != 0)
		goto err_stop_ping;

	lnet_fault_init();
	lnet_proc_init();

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;

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
	while (!list_empty(&net_head)) {
		struct lnet_net *net;

		net = list_entry(net_head.next, struct lnet_net, net_list);
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
LNetNIFini()
{
	mutex_lock(&the_lnet.ln_api_mutex);

	LASSERT(the_lnet.ln_refcount > 0);

	if (the_lnet.ln_refcount != 1) {
		the_lnet.ln_refcount--;
	} else {
		LASSERT(!the_lnet.ln_niinit_self);

		lnet_fault_fini();

		lnet_proc_fini();
		lnet_router_checker_stop();
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

	if (!ni || !cfg_ni || !tun)
		return;

	if (ni->ni_interfaces[0] != NULL) {
		for (i = 0; i < ARRAY_SIZE(ni->ni_interfaces); i++) {
			if (ni->ni_interfaces[i] != NULL) {
				strncpy(cfg_ni->lic_ni_intf[i],
					ni->ni_interfaces[i],
					sizeof(cfg_ni->lic_ni_intf[i]));
			}
		}
	}

	cfg_ni->lic_nid = ni->ni_nid;
	cfg_ni->lic_status = ni->ni_status->ns_status;
	cfg_ni->lic_tcp_bonding = use_tcp_bonding;
	cfg_ni->lic_dev_cpt = ni->ni_dev_cpt;

	memcpy(&tun->lt_cmn, &ni->ni_net->net_tunables, sizeof(tun->lt_cmn));

	if (stats) {
		stats->iel_send_count = atomic_read(&ni->ni_stats.send_count);
		stats->iel_recv_count = atomic_read(&ni->ni_stats.recv_count);
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

	if (!ni || !config)
		return;

	net_config = (struct lnet_ioctl_net_config *) config->cfg_bulk;
	if (!net_config)
		return;

	BUILD_BUG_ON(ARRAY_SIZE(ni->ni_interfaces) !=
		     ARRAY_SIZE(net_config->ni_interfaces));

	for (i = 0; i < ARRAY_SIZE(ni->ni_interfaces); i++) {
		if (!ni->ni_interfaces[i])
			break;

		strncpy(net_config->ni_interfaces[i],
			ni->ni_interfaces[i],
			sizeof(net_config->ni_interfaces[i]));
	}

	config->cfg_nid = ni->ni_nid;
	config->cfg_config_u.cfg_net.net_peer_timeout =
		ni->ni_net->net_tunables.lct_peer_timeout;
	config->cfg_config_u.cfg_net.net_max_tx_credits =
		ni->ni_net->net_tunables.lct_max_tx_credits;
	config->cfg_config_u.cfg_net.net_peer_tx_credits =
		ni->ni_net->net_tunables.lct_peer_tx_credits;
	config->cfg_config_u.cfg_net.net_peer_rtr_credits =
		ni->ni_net->net_tunables.lct_peer_rtr_credits;

	net_config->ni_status = ni->ni_status->ns_status;

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

struct lnet_ni *
lnet_get_next_ni_locked(struct lnet_net *mynet, struct lnet_ni *prev)
{
	struct lnet_ni		*ni;
	struct lnet_net		*net = mynet;

	if (prev == NULL) {
		if (net == NULL)
			net = list_entry(the_lnet.ln_nets.next, struct lnet_net,
					net_list);
		ni = list_entry(net->net_ni_list.next, struct lnet_ni,
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
		net = list_entry(prev->ni_net->net_list.next, struct lnet_net,
				 net_list);
		/* get the ni on it */
		ni = list_entry(net->net_ni_list.next, struct lnet_ni,
				ni_netlist);

		return ni;
	}

	/* there are more nis left */
	ni = list_entry(prev->ni_netlist.next, struct lnet_ni, ni_netlist);

	return ni;
}

int
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

int
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

static int lnet_add_net_common(struct lnet_net *net,
			       struct lnet_ioctl_config_lnd_tunables *tun)
{
	__u32			net_id;
	struct lnet_ping_info	*pinfo;
	struct lnet_handle_md	md_handle;
	int			rc;
	struct lnet_remotenet *rnet;
	int			net_ni_count;
	int			num_acceptor_nets;

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

	/*
	 * make sure you calculate the correct number of slots in the ping
	 * info. Since the ping info is a flattened list of all the NIs,
	 * we should allocate enough slots to accomodate the number of NIs
	 * which will be added.
	 *
	 * since ni hasn't been configured yet, use
	 * lnet_get_net_ni_count_pre() which checks the net_ni_added list
	 */
	net_ni_count = lnet_get_net_ni_count_pre(net);

	rc = lnet_ping_info_setup(&pinfo, &md_handle,
				  net_ni_count + lnet_get_ni_count(),
				  false);
	if (rc < 0) {
		lnet_net_free(net);
		return rc;
	}

	if (tun)
		memcpy(&net->net_tunables,
		       &tun->lt_cmn, sizeof(net->net_tunables));
	else
		memset(&net->net_tunables, -1, sizeof(net->net_tunables));

	/*
	 * before starting this network get a count of the current TCP
	 * networks which require the acceptor thread running. If that
	 * count is == 0 before we start up this network, then we'd want to
	 * start up the acceptor thread after starting up this network
	 */
	num_acceptor_nets = lnet_count_acceptor_nets();

	net_id = net->net_id;

	rc = lnet_startup_lndnet(net,
				 (tun) ? &tun->lt_tun : NULL);
	if (rc < 0)
		goto failed;

	lnet_net_lock(LNET_LOCK_EX);
	net = lnet_get_net_locked(net_id);
	lnet_net_unlock(LNET_LOCK_EX);

	LASSERT(net);

	/*
	 * Start the acceptor thread if this is the first network
	 * being added that requires the thread.
	 */
	if (net->net_lnd->lnd_accept && num_acceptor_nets == 0) {
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

	lnet_ping_target_update(pinfo, md_handle);

	return 0;

failed:
	lnet_ping_md_unlink(pinfo, &md_handle);
	lnet_ping_info_free(pinfo);
	return rc;
}

static int lnet_handle_legacy_ip2nets(char *ip2nets,
				      struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct lnet_net *net;
	char *nets;
	int rc;
	struct list_head net_head;

	INIT_LIST_HEAD(&net_head);

	rc = lnet_parse_ip2nets(&nets, ip2nets);
	if (rc < 0)
		return rc;

	rc = lnet_parse_networks(&net_head, nets, use_tcp_bonding);
	if (rc < 0)
		return rc;

	mutex_lock(&the_lnet.ln_api_mutex);
	while (!list_empty(&net_head)) {
		net = list_entry(net_head.next, struct lnet_net, net_list);
		list_del_init(&net->net_list);
		rc = lnet_add_net_common(net, tun);
		if (rc < 0)
			goto out;
	}

out:
	mutex_unlock(&the_lnet.ln_api_mutex);

	while (!list_empty(&net_head)) {
		net = list_entry(net_head.next, struct lnet_net, net_list);
		list_del_init(&net->net_list);
		lnet_net_free(net);
	}
	return rc;
}

int lnet_dyn_add_ni(struct lnet_ioctl_config_ni *conf)
{
	struct lnet_net *net;
	struct lnet_ni *ni;
	struct lnet_ioctl_config_lnd_tunables *tun = NULL;
	int rc, i;
	__u32 net_id;

	/* get the tunables if they are available */
	if (conf->lic_cfg_hdr.ioc_len >=
	    sizeof(*conf) + sizeof(*tun))
		tun = (struct lnet_ioctl_config_lnd_tunables *)
			conf->lic_bulk;

	/* handle legacy ip2nets from DLC */
	if (conf->lic_legacy_ip2nets[0] != '\0')
		return lnet_handle_legacy_ip2nets(conf->lic_legacy_ip2nets,
						  tun);

	net_id = LNET_NIDNET(conf->lic_nid);

	net = lnet_net_alloc(net_id, NULL);
	if (!net)
		return -ENOMEM;

	for (i = 0; i < conf->lic_ncpts; i++) {
		if (conf->lic_cpts[i] >= LNET_CPT_NUMBER)
			return -EINVAL;
	}

	ni = lnet_ni_alloc_w_cpt_array(net, conf->lic_cpts, conf->lic_ncpts,
				       conf->lic_ni_intf[0]);
	if (!ni)
		return -ENOMEM;

	mutex_lock(&the_lnet.ln_api_mutex);

	rc = lnet_add_net_common(net, tun);

	mutex_unlock(&the_lnet.ln_api_mutex);

	return rc;
}

int lnet_dyn_del_ni(struct lnet_ioctl_config_ni *conf)
{
	struct lnet_net	 *net;
	struct lnet_ni *ni;
	__u32 net_id = LNET_NIDNET(conf->lic_nid);
	struct lnet_ping_info *pinfo;
	struct lnet_handle_md md_handle;
	int		  rc;
	int		  net_count;
	__u32		  addr;

	/* don't allow userspace to shutdown the LOLND */
	if (LNET_NETTYP(net_id) == LOLND)
		return -EINVAL;

	mutex_lock(&the_lnet.ln_api_mutex);

	lnet_net_lock(0);

	net = lnet_get_net_locked(net_id);
	if (!net) {
		CERROR("net %s not found\n",
		       libcfs_net2str(net_id));
		rc = -ENOENT;
		goto net_unlock;
	}

	addr = LNET_NIDADDR(conf->lic_nid);
	if (addr == 0) {
		/* remove the entire net */
		net_count = lnet_get_net_ni_count_locked(net);

		lnet_net_unlock(0);

		/* create and link a new ping info, before removing the old one */
		rc = lnet_ping_info_setup(&pinfo, &md_handle,
					lnet_get_ni_count() - net_count,
					false);
		if (rc != 0)
			goto out;

		lnet_shutdown_lndnet(net);

		if (lnet_count_acceptor_nets() == 0)
			lnet_acceptor_stop();

		lnet_ping_target_update(pinfo, md_handle);

		goto out;
	}

	ni = lnet_nid2ni_locked(conf->lic_nid, 0);
	if (!ni) {
		CERROR("nid %s not found \n",
		       libcfs_nid2str(conf->lic_nid));
		rc = -ENOENT;
		goto net_unlock;
	}

	net_count = lnet_get_net_ni_count_locked(net);

	lnet_net_unlock(0);

	/* create and link a new ping info, before removing the old one */
	rc = lnet_ping_info_setup(&pinfo, &md_handle,
				  lnet_get_ni_count() - 1, false);
	if (rc != 0)
		goto out;

	lnet_shutdown_lndni(ni);

	if (lnet_count_acceptor_nets() == 0)
		lnet_acceptor_stop();

	lnet_ping_target_update(pinfo, md_handle);

	/* check if the net is empty and remove it if it is */
	if (net_count == 1)
		lnet_shutdown_lndnet(net);

	goto out;

net_unlock:
	lnet_net_unlock(0);
out:
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
	struct lnet_net		*net;
	struct list_head	net_head;
	int			rc;
	struct lnet_ioctl_config_lnd_tunables tun;
	char *nets = conf->cfg_config_u.cfg_net.net_intf;

	INIT_LIST_HEAD(&net_head);

	/* Create a net/ni structures for the network string */
	rc = lnet_parse_networks(&net_head, nets, use_tcp_bonding);
	if (rc <= 0)
		return rc == 0 ? -EINVAL : rc;

	mutex_lock(&the_lnet.ln_api_mutex);

	if (rc > 1) {
		rc = -EINVAL; /* only add one network per call */
		goto out_unlock_clean;
	}

	net = list_entry(net_head.next, struct lnet_net, net_list);
	list_del_init(&net->net_list);

	LASSERT(lnet_net_unique(net->net_id, &the_lnet.ln_nets, NULL));

	memset(&tun, 0, sizeof(tun));

	tun.lt_cmn.lct_peer_timeout =
	  conf->cfg_config_u.cfg_net.net_peer_timeout;
	tun.lt_cmn.lct_peer_tx_credits =
	  conf->cfg_config_u.cfg_net.net_peer_tx_credits;
	tun.lt_cmn.lct_peer_rtr_credits =
	  conf->cfg_config_u.cfg_net.net_peer_rtr_credits;
	tun.lt_cmn.lct_max_tx_credits =
	  conf->cfg_config_u.cfg_net.net_max_tx_credits;

	rc = lnet_add_net_common(net, &tun);

out_unlock_clean:
	mutex_unlock(&the_lnet.ln_api_mutex);
	while (!list_empty(&net_head)) {
		/* net_head list is empty in success case */
		net = list_entry(net_head.next, struct lnet_net, net_list);
		list_del_init(&net->net_list);
		lnet_net_free(net);
	}
	return rc;
}

int
lnet_dyn_del_net(__u32 net_id)
{
	struct lnet_net	 *net;
	struct lnet_ping_info *pinfo;
	struct lnet_handle_md md_handle;
	int		  rc;
	int		  net_ni_count;

	/* don't allow userspace to shutdown the LOLND */
	if (LNET_NETTYP(net_id) == LOLND)
		return -EINVAL;

	mutex_lock(&the_lnet.ln_api_mutex);

	lnet_net_lock(0);

	net = lnet_get_net_locked(net_id);
	if (net == NULL) {
		rc = -EINVAL;
		goto out;
	}

	net_ni_count = lnet_get_net_ni_count_locked(net);

	lnet_net_unlock(0);

	/* create and link a new ping info, before removing the old one */
	rc = lnet_ping_info_setup(&pinfo, &md_handle,
				  lnet_get_ni_count() - net_ni_count, false);
	if (rc != 0)
		goto out;

	lnet_shutdown_lndnet(net);

	if (lnet_count_acceptor_nets() == 0)
		lnet_acceptor_stop();

	lnet_ping_target_update(pinfo, md_handle);

out:
	mutex_unlock(&the_lnet.ln_api_mutex);

	return rc;
}

void lnet_incr_dlc_seq(void)
{
	atomic_inc(&lnet_dlc_seq_no);
}

__u32 lnet_get_dlc_seq_locked(void)
{
	return atomic_read(&lnet_dlc_seq_no);
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
	struct lnet_process_id	  id = {0};
	struct lnet_ni		 *ni;
	int			  rc;

	BUILD_BUG_ON(sizeof(struct lnet_ioctl_net_config) +
		     sizeof(struct lnet_ioctl_config_data) > LIBCFS_IOC_DATA_MAX);

	switch (cmd) {
	case IOC_LIBCFS_GET_NI:
		rc = LNetGetId(data->ioc_count, &id);
		data->ioc_nid = id.nid;
		return rc;

	case IOC_LIBCFS_FAIL_NID:
		return lnet_fail_nid(data->ioc_nid, data->ioc_count);

	case IOC_LIBCFS_ADD_ROUTE:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_add_route(config->cfg_net,
				    config->cfg_config_u.cfg_route.rtr_hop,
				    config->cfg_nid,
				    config->cfg_config_u.cfg_route.
					rtr_priority);
		if (rc == 0) {
			rc = lnet_check_routes();
			if (rc != 0)
				lnet_del_route(config->cfg_net,
					       config->cfg_nid);
		}
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;

	case IOC_LIBCFS_DEL_ROUTE:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_del_route(config->cfg_net, config->cfg_nid);
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
					rtr_priority);
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
		    sizeof(*cfg_ni) + sizeof(*stats)+ sizeof(*tun))
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
		lnet_counters_get(&lnet_stats->st_cntrs);
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
		struct lnet_ioctl_numa_range *numa;
		numa = arg;
		if (numa->nr_hdr.ioc_len != sizeof(*numa))
			return -EINVAL;
		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_numa_range = numa->nr_range;
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	case IOC_LIBCFS_GET_NUMA_RANGE: {
		struct lnet_ioctl_numa_range *numa;
		numa = arg;
		if (numa->nr_hdr.ioc_len != sizeof(*numa))
			return -EINVAL;
		numa->nr_range = lnet_numa_range;
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

	case IOC_LIBCFS_ADD_PEER_NI: {
		struct lnet_ioctl_peer_cfg *cfg = arg;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_add_peer_ni_to_peer(cfg->prcfg_prim_nid,
					      cfg->prcfg_cfg_nid,
					      cfg->prcfg_mr);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_DEL_PEER_NI: {
		struct lnet_ioctl_peer_cfg *cfg = arg;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_del_peer_ni_from_peer(cfg->prcfg_prim_nid,
						cfg->prcfg_cfg_nid);
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
		struct lnet_peer_ni_credit_info __user *lpni_cri;
		struct lnet_ioctl_element_stats __user *lpni_stats;
		size_t usr_size = sizeof(*lpni_cri) + sizeof(*lpni_stats);

		if ((cfg->prcfg_hdr.ioc_len != sizeof(*cfg)) ||
		    (cfg->prcfg_size != usr_size))
			return -EINVAL;

		lpni_cri = cfg->prcfg_bulk;
		lpni_stats = cfg->prcfg_bulk + sizeof(*lpni_cri);

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_peer_info(cfg->prcfg_count, &cfg->prcfg_prim_nid,
					&cfg->prcfg_cfg_nid, &cfg->prcfg_mr,
					lpni_cri, lpni_stats);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_NOTIFY_ROUTER:
		return lnet_notify(NULL, data->ioc_nid, data->ioc_flags,
				  cfs_time_current() -
				  cfs_time_seconds(cfs_time_current_sec() -
						   (time_t)data->ioc_u64[0]));

	case IOC_LIBCFS_LNET_DIST:
		rc = LNetDist(data->ioc_nid, &data->ioc_nid, &data->ioc_u32[1]);
		if (rc < 0 && rc != -EHOSTUNREACH)
			return rc;

		data->ioc_u32[0] = rc;
		return 0;

	case IOC_LIBCFS_TESTPROTOCOMPAT:
		lnet_net_lock(LNET_LOCK_EX);
		the_lnet.ln_testprotocompat = data->ioc_flags;
		lnet_net_unlock(LNET_LOCK_EX);
		return 0;

	case IOC_LIBCFS_LNET_FAULT:
		return lnet_fault_ctl(data->ioc_flags, data);

	case IOC_LIBCFS_PING: {
		signed long timeout;

		id.nid = data->ioc_nid;
		id.pid = data->ioc_u32[0];

		/* Don't block longer than 2 minutes */
		if (data->ioc_u32[1] > 120 * MSEC_PER_SEC)
			return -EINVAL;

		/* If timestamp is negative then disable timeout */
		if ((s32)data->ioc_u32[1] < 0)
			timeout = MAX_SCHEDULE_TIMEOUT;
		else
			timeout = msecs_to_jiffies(data->ioc_u32[1]);

		rc = lnet_ping(id, timeout, data->ioc_pbuf1,
			       data->ioc_plen1 / sizeof(struct lnet_process_id));
		if (rc < 0)
			return rc;
		data->ioc_count = rc;
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
		return rc;
	}
	/* not reached */
}
EXPORT_SYMBOL(LNetCtl);

void LNetDebugPeer(struct lnet_process_id id)
{
	lnet_debug_peer(id.nid);
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
bool LNetIsPeerLocal(lnet_nid_t nid)
{
	struct lnet_net *net;
	struct lnet_ni *ni;
	int cpt;

	cpt = lnet_net_lock_current();
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (ni->ni_nid == nid) {
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
 * \param index Index of the interface to look up.
 * \param id On successful return, this location will hold the
 * struct lnet_process_id ID of the interface.
 *
 * \retval 0 If an interface exists at \a index.
 * \retval -ENOENT If no interface has been found.
 */
int
LNetGetId(unsigned int index, struct lnet_process_id *id)
{
	struct lnet_ni	 *ni;
	struct lnet_net  *net;
	int		  cpt;
	int		  rc = -ENOENT;

	LASSERT(the_lnet.ln_refcount > 0);

	cpt = lnet_net_lock_current();

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
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

static int lnet_ping(struct lnet_process_id id, signed long timeout,
		     struct lnet_process_id __user *ids, int n_ids)
{
	struct lnet_handle_eq eqh;
	struct lnet_handle_md mdh;
	struct lnet_event event;
	struct lnet_md md = { NULL };
	int		     which;
	int		     unlinked = 0;
	int		     replied = 0;
	const signed long a_long_time = msecs_to_jiffies(60 * MSEC_PER_SEC);
	int		     infosz;
	struct lnet_ping_info *info;
	struct lnet_process_id tmpid;
	int		     i;
	int		     nob;
	int		     rc;
	int		     rc2;
	sigset_t	 blocked;

	infosz = offsetof(struct lnet_ping_info, pi_ni[n_ids]);

	/* n_ids limit is arbitrary */
	if (n_ids <= 0 || n_ids > 20 || id.nid == LNET_NID_ANY)
		return -EINVAL;

	if (id.pid == LNET_PID_ANY)
		id.pid = LNET_PID_LUSTRE;

	LIBCFS_ALLOC(info, infosz);
	if (info == NULL)
		return -ENOMEM;

	/* NB 2 events max (including any unlink event) */
	rc = LNetEQAlloc(2, LNET_EQ_HANDLER_NONE, &eqh);
	if (rc != 0) {
		CERROR("Can't allocate EQ: %d\n", rc);
		goto out_0;
	}

	/* initialize md content */
	md.start     = info;
	md.length    = infosz;
	md.threshold = 2; /*GET/REPLY*/
	md.max_size  = 0;
	md.options   = LNET_MD_TRUNCATE;
	md.user_ptr  = NULL;
	md.eq_handle = eqh;

	rc = LNetMDBind(md, LNET_UNLINK, &mdh);
	if (rc != 0) {
		CERROR("Can't bind MD: %d\n", rc);
		goto out_1;
	}

	rc = LNetGet(LNET_NID_ANY, mdh, id,
		     LNET_RESERVED_PORTAL,
		     LNET_PROTO_PING_MATCHBITS, 0);

	if (rc != 0) {
		/* Don't CERROR; this could be deliberate! */

		rc2 = LNetMDUnlink(mdh);
		LASSERT(rc2 == 0);

		/* NB must wait for the UNLINK event below... */
		unlinked = 1;
		timeout = a_long_time;
	}

	do {
		/* MUST block for unlink to complete */
		if (unlinked)
			blocked = cfs_block_allsigs();

		rc2 = LNetEQPoll(&eqh, 1, timeout, &event, &which);

		if (unlinked)
			cfs_restore_sigs(blocked);

		CDEBUG(D_NET, "poll %d(%d %d)%s\n", rc2,
		       (rc2 <= 0) ? -1 : event.type,
		       (rc2 <= 0) ? -1 : event.status,
		       (rc2 > 0 && event.unlinked) ? " unlinked" : "");

		LASSERT(rc2 != -EOVERFLOW);	/* can't miss anything */

		if (rc2 <= 0 || event.status != 0) {
			/* timeout or error */
			if (!replied && rc == 0)
				rc = (rc2 < 0) ? rc2 :
				     (rc2 == 0) ? -ETIMEDOUT :
				     event.status;

			if (!unlinked) {
				/* Ensure completion in finite time... */
				LNetMDUnlink(mdh);
				/* No assertion (racing with network) */
				unlinked = 1;
				timeout = a_long_time;
			} else if (rc2 == 0) {
				/* timed out waiting for unlink */
				CWARN("ping %s: late network completion\n",
				      libcfs_id2str(id));
			}
		} else if (event.type == LNET_EVENT_REPLY) {
			replied = 1;
			rc = event.mlength;
		}

	} while (rc2 <= 0 || !event.unlinked);

	if (!replied) {
		if (rc >= 0)
			CWARN("%s: Unexpected rc >= 0 but no reply!\n",
			      libcfs_id2str(id));
		rc = -EIO;
		goto out_1;
	}

	nob = rc;
	LASSERT(nob >= 0 && nob <= infosz);

	rc = -EPROTO;				/* if I can't parse... */

	if (nob < 8) {
		/* can't check magic/version */
		CERROR("%s: ping info too short %d\n",
		       libcfs_id2str(id), nob);
		goto out_1;
	}

	if (info->pi_magic == __swab32(LNET_PROTO_PING_MAGIC)) {
		lnet_swap_pinginfo(info);
	} else if (info->pi_magic != LNET_PROTO_PING_MAGIC) {
		CERROR("%s: Unexpected magic %08x\n",
		       libcfs_id2str(id), info->pi_magic);
		goto out_1;
	}

	if ((info->pi_features & LNET_PING_FEAT_NI_STATUS) == 0) {
		CERROR("%s: ping w/o NI status: 0x%x\n",
		       libcfs_id2str(id), info->pi_features);
		goto out_1;
	}

	if (nob < offsetof(struct lnet_ping_info, pi_ni[0])) {
		CERROR("%s: Short reply %d(%d min)\n", libcfs_id2str(id),
		       nob, (int)offsetof(struct lnet_ping_info, pi_ni[0]));
		goto out_1;
	}

	if (info->pi_nnis < n_ids)
		n_ids = info->pi_nnis;

	if (nob < offsetof(struct lnet_ping_info, pi_ni[n_ids])) {
		CERROR("%s: Short reply %d(%d expected)\n", libcfs_id2str(id),
		       nob, (int)offsetof(struct lnet_ping_info, pi_ni[n_ids]));
		goto out_1;
	}

	rc = -EFAULT;				/* If I SEGV... */

	memset(&tmpid, 0, sizeof(tmpid));
	for (i = 0; i < n_ids; i++) {
		tmpid.pid = info->pi_pid;
		tmpid.nid = info->pi_ni[i].ns_nid;
		if (copy_to_user(&ids[i], &tmpid, sizeof(tmpid)))
			goto out_1;
	}
	rc = info->pi_nnis;

 out_1:
	rc2 = LNetEQFree(eqh);
	if (rc2 != 0)
		CERROR("rc2 %d\n", rc2);
	LASSERT(rc2 == 0);

 out_0:
	LIBCFS_FREE(info, infosz);
	return rc;
}
