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
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/lnet/lib-move.c
 *
 * Data movement routines
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/pagemap.h>

#include <lnet/lib-lnet.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>

static int local_nid_dist_zero = 1;
module_param(local_nid_dist_zero, int, 0444);
MODULE_PARM_DESC(local_nid_dist_zero, "Reserved");

struct lnet_send_data {
	struct lnet_ni *sd_best_ni;
	struct lnet_peer_ni *sd_best_lpni;
	struct lnet_peer_ni *sd_final_dst_lpni;
	struct lnet_peer *sd_peer;
	struct lnet_peer *sd_gw_peer;
	struct lnet_peer_ni *sd_gw_lpni;
	struct lnet_peer_net *sd_peer_net;
	struct lnet_msg *sd_msg;
	lnet_nid_t sd_dst_nid;
	lnet_nid_t sd_src_nid;
	lnet_nid_t sd_rtr_nid;
	int sd_cpt;
	int sd_md_cpt;
	__u32 sd_send_case;
};

static inline struct lnet_comm_count *
get_stats_counts(struct lnet_element_stats *stats,
		 enum lnet_stats_type stats_type)
{
	switch (stats_type) {
	case LNET_STATS_TYPE_SEND:
		return &stats->el_send_stats;
	case LNET_STATS_TYPE_RECV:
		return &stats->el_recv_stats;
	case LNET_STATS_TYPE_DROP:
		return &stats->el_drop_stats;
	default:
		CERROR("Unknown stats type\n");
	}

	return NULL;
}

void lnet_incr_stats(struct lnet_element_stats *stats,
		     enum lnet_msg_type msg_type,
		     enum lnet_stats_type stats_type)
{
	struct lnet_comm_count *counts = get_stats_counts(stats, stats_type);
	if (!counts)
		return;

	switch (msg_type) {
	case LNET_MSG_ACK:
		atomic_inc(&counts->co_ack_count);
		break;
	case LNET_MSG_PUT:
		atomic_inc(&counts->co_put_count);
		break;
	case LNET_MSG_GET:
		atomic_inc(&counts->co_get_count);
		break;
	case LNET_MSG_REPLY:
		atomic_inc(&counts->co_reply_count);
		break;
	case LNET_MSG_HELLO:
		atomic_inc(&counts->co_hello_count);
		break;
	default:
		CERROR("There is a BUG in the code. Unknown message type\n");
		break;
	}
}

__u32 lnet_sum_stats(struct lnet_element_stats *stats,
		     enum lnet_stats_type stats_type)
{
	struct lnet_comm_count *counts = get_stats_counts(stats, stats_type);
	if (!counts)
		return 0;

	return (atomic_read(&counts->co_ack_count) +
		atomic_read(&counts->co_put_count) +
		atomic_read(&counts->co_get_count) +
		atomic_read(&counts->co_reply_count) +
		atomic_read(&counts->co_hello_count));
}

static inline void assign_stats(struct lnet_ioctl_comm_count *msg_stats,
				struct lnet_comm_count *counts)
{
	msg_stats->ico_get_count = atomic_read(&counts->co_get_count);
	msg_stats->ico_put_count = atomic_read(&counts->co_put_count);
	msg_stats->ico_reply_count = atomic_read(&counts->co_reply_count);
	msg_stats->ico_ack_count = atomic_read(&counts->co_ack_count);
	msg_stats->ico_hello_count = atomic_read(&counts->co_hello_count);
}

void lnet_usr_translate_stats(struct lnet_ioctl_element_msg_stats *msg_stats,
			      struct lnet_element_stats *stats)
{
	struct lnet_comm_count *counts;

	LASSERT(msg_stats);
	LASSERT(stats);

	counts = get_stats_counts(stats, LNET_STATS_TYPE_SEND);
	if (!counts)
		return;
	assign_stats(&msg_stats->im_send_stats, counts);

	counts = get_stats_counts(stats, LNET_STATS_TYPE_RECV);
	if (!counts)
		return;
	assign_stats(&msg_stats->im_recv_stats, counts);

	counts = get_stats_counts(stats, LNET_STATS_TYPE_DROP);
	if (!counts)
		return;
	assign_stats(&msg_stats->im_drop_stats, counts);
}

int
lnet_fail_nid(lnet_nid_t nid, unsigned int threshold)
{
	struct lnet_test_peer *tp;
	struct list_head *el;
	struct list_head *next;
	struct list_head  cull;

	/* NB: use lnet_net_lock(0) to serialize operations on test peers */
	if (threshold != 0) {
		/* Adding a new entry */
		LIBCFS_ALLOC(tp, sizeof(*tp));
		if (tp == NULL)
			return -ENOMEM;

		tp->tp_nid = nid;
		tp->tp_threshold = threshold;

		lnet_net_lock(0);
		list_add_tail(&tp->tp_list, &the_lnet.ln_test_peers);
		lnet_net_unlock(0);
		return 0;
	}

	/* removing entries */
	INIT_LIST_HEAD(&cull);

	lnet_net_lock(0);

	list_for_each_safe(el, next, &the_lnet.ln_test_peers) {
		tp = list_entry(el, struct lnet_test_peer, tp_list);

		if (tp->tp_threshold == 0 ||	/* needs culling anyway */
		    nid == LNET_NID_ANY ||	/* removing all entries */
		    tp->tp_nid == nid) {	/* matched this one */
			list_del(&tp->tp_list);
			list_add(&tp->tp_list, &cull);
		}
	}

	lnet_net_unlock(0);

	while (!list_empty(&cull)) {
		tp = list_entry(cull.next, struct lnet_test_peer, tp_list);

		list_del(&tp->tp_list);
		LIBCFS_FREE(tp, sizeof(*tp));
	}
	return 0;
}

static int
fail_peer (lnet_nid_t nid, int outgoing)
{
	struct lnet_test_peer *tp;
	struct list_head *el;
	struct list_head *next;
	struct list_head  cull;
	int		  fail = 0;

	INIT_LIST_HEAD(&cull);

	/* NB: use lnet_net_lock(0) to serialize operations on test peers */
	lnet_net_lock(0);

	list_for_each_safe(el, next, &the_lnet.ln_test_peers) {
		tp = list_entry(el, struct lnet_test_peer, tp_list);

		if (tp->tp_threshold == 0) {
			/* zombie entry */
			if (outgoing) {
				/* only cull zombies on outgoing tests,
				 * since we may be at interrupt priority on
				 * incoming messages. */
				list_del(&tp->tp_list);
				list_add(&tp->tp_list, &cull);
			}
			continue;
		}

		if (tp->tp_nid == LNET_NID_ANY ||	/* fail every peer */
		    nid == tp->tp_nid) {		/* fail this peer */
			fail = 1;

			if (tp->tp_threshold != LNET_MD_THRESH_INF) {
				tp->tp_threshold--;
				if (outgoing &&
				    tp->tp_threshold == 0) {
					/* see above */
					list_del(&tp->tp_list);
					list_add(&tp->tp_list, &cull);
				}
			}
			break;
		}
	}

	lnet_net_unlock(0);

	while (!list_empty(&cull)) {
		tp = list_entry(cull.next, struct lnet_test_peer, tp_list);
		list_del(&tp->tp_list);

		LIBCFS_FREE(tp, sizeof(*tp));
	}

	return fail;
}

unsigned int
lnet_iov_nob(unsigned int niov, struct kvec *iov)
{
	unsigned int nob = 0;

	LASSERT(niov == 0 || iov != NULL);
	while (niov-- > 0)
		nob += (iov++)->iov_len;

	return (nob);
}
EXPORT_SYMBOL(lnet_iov_nob);

void
lnet_copy_iov2iov(unsigned int ndiov, struct kvec *diov, unsigned int doffset,
		  unsigned int nsiov, struct kvec *siov, unsigned int soffset,
		  unsigned int nob)
{
	/* NB diov, siov are READ-ONLY */
	unsigned int  this_nob;

	if (nob == 0)
		return;

	/* skip complete frags before 'doffset' */
	LASSERT(ndiov > 0);
	while (doffset >= diov->iov_len) {
		doffset -= diov->iov_len;
		diov++;
		ndiov--;
		LASSERT(ndiov > 0);
	}

	/* skip complete frags before 'soffset' */
	LASSERT(nsiov > 0);
	while (soffset >= siov->iov_len) {
		soffset -= siov->iov_len;
		siov++;
		nsiov--;
		LASSERT(nsiov > 0);
	}

	do {
		LASSERT(ndiov > 0);
		LASSERT(nsiov > 0);
		this_nob = MIN(diov->iov_len - doffset,
			       siov->iov_len - soffset);
		this_nob = MIN(this_nob, nob);

		memcpy((char *)diov->iov_base + doffset,
		       (char *)siov->iov_base + soffset, this_nob);
		nob -= this_nob;

		if (diov->iov_len > doffset + this_nob) {
			doffset += this_nob;
		} else {
			diov++;
			ndiov--;
			doffset = 0;
		}

		if (siov->iov_len > soffset + this_nob) {
			soffset += this_nob;
		} else {
			siov++;
			nsiov--;
			soffset = 0;
		}
	} while (nob > 0);
}
EXPORT_SYMBOL(lnet_copy_iov2iov);

int
lnet_extract_iov(int dst_niov, struct kvec *dst,
		 int src_niov, struct kvec *src,
		 unsigned int offset, unsigned int len)
{
	/* Initialise 'dst' to the subset of 'src' starting at 'offset',
	 * for exactly 'len' bytes, and return the number of entries.
	 * NB not destructive to 'src' */
	unsigned int	frag_len;
	unsigned int	niov;

	if (len == 0)				/* no data => */
		return (0);			/* no frags */

	LASSERT(src_niov > 0);
	while (offset >= src->iov_len) {      /* skip initial frags */
		offset -= src->iov_len;
		src_niov--;
		src++;
		LASSERT(src_niov > 0);
	}

	niov = 1;
	for (;;) {
		LASSERT(src_niov > 0);
		LASSERT((int)niov <= dst_niov);

		frag_len = src->iov_len - offset;
		dst->iov_base = ((char *)src->iov_base) + offset;

		if (len <= frag_len) {
			dst->iov_len = len;
			return (niov);
		}

		dst->iov_len = frag_len;

		len -= frag_len;
		dst++;
		src++;
		niov++;
		src_niov--;
		offset = 0;
	}
}
EXPORT_SYMBOL(lnet_extract_iov);


unsigned int
lnet_kiov_nob(unsigned int niov, lnet_kiov_t *kiov)
{
	unsigned int  nob = 0;

	LASSERT(niov == 0 || kiov != NULL);
	while (niov-- > 0)
		nob += (kiov++)->kiov_len;

	return (nob);
}
EXPORT_SYMBOL(lnet_kiov_nob);

void
lnet_copy_kiov2kiov(unsigned int ndiov, lnet_kiov_t *diov, unsigned int doffset,
		    unsigned int nsiov, lnet_kiov_t *siov, unsigned int soffset,
		    unsigned int nob)
{
	/* NB diov, siov are READ-ONLY */
	unsigned int	this_nob;
	char	       *daddr = NULL;
	char	       *saddr = NULL;

	if (nob == 0)
		return;

	LASSERT (!in_interrupt ());

	LASSERT (ndiov > 0);
	while (doffset >= diov->kiov_len) {
		doffset -= diov->kiov_len;
		diov++;
		ndiov--;
		LASSERT(ndiov > 0);
	}

	LASSERT(nsiov > 0);
	while (soffset >= siov->kiov_len) {
		soffset -= siov->kiov_len;
		siov++;
		nsiov--;
		LASSERT(nsiov > 0);
	}

	do {
		LASSERT(ndiov > 0);
		LASSERT(nsiov > 0);
		this_nob = MIN(diov->kiov_len - doffset,
			       siov->kiov_len - soffset);
		this_nob = MIN(this_nob, nob);

		if (daddr == NULL)
			daddr = ((char *)kmap(diov->kiov_page)) +
				diov->kiov_offset + doffset;
		if (saddr == NULL)
			saddr = ((char *)kmap(siov->kiov_page)) +
				siov->kiov_offset + soffset;

		/* Vanishing risk of kmap deadlock when mapping 2 pages.
		 * However in practice at least one of the kiovs will be mapped
		 * kernel pages and the map/unmap will be NOOPs */

		memcpy (daddr, saddr, this_nob);
		nob -= this_nob;

		if (diov->kiov_len > doffset + this_nob) {
			daddr += this_nob;
			doffset += this_nob;
		} else {
			kunmap(diov->kiov_page);
			daddr = NULL;
			diov++;
			ndiov--;
			doffset = 0;
		}

		if (siov->kiov_len > soffset + this_nob) {
			saddr += this_nob;
			soffset += this_nob;
		} else {
			kunmap(siov->kiov_page);
			saddr = NULL;
			siov++;
			nsiov--;
			soffset = 0;
		}
	} while (nob > 0);

	if (daddr != NULL)
		kunmap(diov->kiov_page);
	if (saddr != NULL)
		kunmap(siov->kiov_page);
}
EXPORT_SYMBOL(lnet_copy_kiov2kiov);

void
lnet_copy_kiov2iov (unsigned int niov, struct kvec *iov, unsigned int iovoffset,
		    unsigned int nkiov, lnet_kiov_t *kiov, unsigned int kiovoffset,
		    unsigned int nob)
{
	/* NB iov, kiov are READ-ONLY */
	unsigned int	this_nob;
	char	       *addr = NULL;

	if (nob == 0)
		return;

	LASSERT (!in_interrupt ());

	LASSERT (niov > 0);
	while (iovoffset >= iov->iov_len) {
		iovoffset -= iov->iov_len;
		iov++;
		niov--;
		LASSERT(niov > 0);
	}

	LASSERT(nkiov > 0);
	while (kiovoffset >= kiov->kiov_len) {
		kiovoffset -= kiov->kiov_len;
		kiov++;
		nkiov--;
		LASSERT(nkiov > 0);
	}

	do {
		LASSERT(niov > 0);
		LASSERT(nkiov > 0);
		this_nob = MIN(iov->iov_len - iovoffset,
			       kiov->kiov_len - kiovoffset);
		this_nob = MIN(this_nob, nob);

		if (addr == NULL)
			addr = ((char *)kmap(kiov->kiov_page)) +
				kiov->kiov_offset + kiovoffset;

		memcpy((char *)iov->iov_base + iovoffset, addr, this_nob);
		nob -= this_nob;

		if (iov->iov_len > iovoffset + this_nob) {
			iovoffset += this_nob;
		} else {
			iov++;
			niov--;
			iovoffset = 0;
		}

		if (kiov->kiov_len > kiovoffset + this_nob) {
			addr += this_nob;
			kiovoffset += this_nob;
		} else {
			kunmap(kiov->kiov_page);
			addr = NULL;
			kiov++;
			nkiov--;
			kiovoffset = 0;
		}

	} while (nob > 0);

	if (addr != NULL)
		kunmap(kiov->kiov_page);
}
EXPORT_SYMBOL(lnet_copy_kiov2iov);

void
lnet_copy_iov2kiov(unsigned int nkiov, lnet_kiov_t *kiov, unsigned int kiovoffset,
		   unsigned int niov, struct kvec *iov, unsigned int iovoffset,
		   unsigned int nob)
{
	/* NB kiov, iov are READ-ONLY */
	unsigned int	this_nob;
	char	       *addr = NULL;

	if (nob == 0)
		return;

	LASSERT (!in_interrupt ());

	LASSERT (nkiov > 0);
	while (kiovoffset >= kiov->kiov_len) {
		kiovoffset -= kiov->kiov_len;
		kiov++;
		nkiov--;
		LASSERT(nkiov > 0);
	}

	LASSERT(niov > 0);
	while (iovoffset >= iov->iov_len) {
		iovoffset -= iov->iov_len;
		iov++;
		niov--;
		LASSERT(niov > 0);
	}

	do {
		LASSERT(nkiov > 0);
		LASSERT(niov > 0);
		this_nob = MIN(kiov->kiov_len - kiovoffset,
			       iov->iov_len - iovoffset);
		this_nob = MIN(this_nob, nob);

		if (addr == NULL)
			addr = ((char *)kmap(kiov->kiov_page)) +
				kiov->kiov_offset + kiovoffset;

		memcpy (addr, (char *)iov->iov_base + iovoffset, this_nob);
		nob -= this_nob;

		if (kiov->kiov_len > kiovoffset + this_nob) {
			addr += this_nob;
			kiovoffset += this_nob;
		} else {
			kunmap(kiov->kiov_page);
			addr = NULL;
			kiov++;
			nkiov--;
			kiovoffset = 0;
		}

		if (iov->iov_len > iovoffset + this_nob) {
			iovoffset += this_nob;
		} else {
			iov++;
			niov--;
			iovoffset = 0;
		}
	} while (nob > 0);

	if (addr != NULL)
		kunmap(kiov->kiov_page);
}
EXPORT_SYMBOL(lnet_copy_iov2kiov);

int
lnet_extract_kiov(int dst_niov, lnet_kiov_t *dst,
		  int src_niov, lnet_kiov_t *src,
		  unsigned int offset, unsigned int len)
{
	/* Initialise 'dst' to the subset of 'src' starting at 'offset',
	 * for exactly 'len' bytes, and return the number of entries.
	 * NB not destructive to 'src' */
	unsigned int	frag_len;
	unsigned int	niov;

	if (len == 0)				/* no data => */
		return (0);			/* no frags */

	LASSERT(src_niov > 0);
	while (offset >= src->kiov_len) {      /* skip initial frags */
		offset -= src->kiov_len;
		src_niov--;
		src++;
		LASSERT(src_niov > 0);
	}

	niov = 1;
	for (;;) {
		LASSERT(src_niov > 0);
		LASSERT((int)niov <= dst_niov);

		frag_len = src->kiov_len - offset;
		dst->kiov_page = src->kiov_page;
		dst->kiov_offset = src->kiov_offset + offset;

		if (len <= frag_len) {
			dst->kiov_len = len;
			LASSERT(dst->kiov_offset + dst->kiov_len <= PAGE_SIZE);
			return niov;
		}

		dst->kiov_len = frag_len;
		LASSERT(dst->kiov_offset + dst->kiov_len <= PAGE_SIZE);

		len -= frag_len;
		dst++;
		src++;
		niov++;
		src_niov--;
		offset = 0;
	}
}
EXPORT_SYMBOL(lnet_extract_kiov);

void
lnet_ni_recv(struct lnet_ni *ni, void *private, struct lnet_msg *msg,
	     int delayed, unsigned int offset, unsigned int mlen,
	     unsigned int rlen)
{
	unsigned int  niov = 0;
	struct kvec *iov = NULL;
	lnet_kiov_t  *kiov = NULL;
	int	      rc;

	LASSERT (!in_interrupt ());
	LASSERT (mlen == 0 || msg != NULL);

	if (msg != NULL) {
		LASSERT(msg->msg_receiving);
		LASSERT(!msg->msg_sending);
		LASSERT(rlen == msg->msg_len);
		LASSERT(mlen <= msg->msg_len);
		LASSERT(msg->msg_offset == offset);
		LASSERT(msg->msg_wanted == mlen);

		msg->msg_receiving = 0;

		if (mlen != 0) {
			niov = msg->msg_niov;
			iov  = msg->msg_iov;
			kiov = msg->msg_kiov;

			LASSERT (niov > 0);
			LASSERT ((iov == NULL) != (kiov == NULL));
		}
	}

	rc = (ni->ni_net->net_lnd->lnd_recv)(ni, private, msg, delayed,
					     niov, iov, kiov, offset, mlen,
					     rlen);
	if (rc < 0)
		lnet_finalize(msg, rc);
}

static void
lnet_setpayloadbuffer(struct lnet_msg *msg)
{
	struct lnet_libmd *md = msg->msg_md;

	LASSERT(msg->msg_len > 0);
	LASSERT(!msg->msg_routing);
	LASSERT(md != NULL);
	LASSERT(msg->msg_niov == 0);
	LASSERT(msg->msg_iov == NULL);
	LASSERT(msg->msg_kiov == NULL);

	msg->msg_niov = md->md_niov;
	if ((md->md_options & LNET_MD_KIOV) != 0)
		msg->msg_kiov = md->md_iov.kiov;
	else
		msg->msg_iov = md->md_iov.iov;
}

void
lnet_prep_send(struct lnet_msg *msg, int type, struct lnet_process_id target,
	       unsigned int offset, unsigned int len)
{
	msg->msg_type = type;
	msg->msg_target = target;
	msg->msg_len = len;
	msg->msg_offset = offset;

	if (len != 0)
		lnet_setpayloadbuffer(msg);

	memset (&msg->msg_hdr, 0, sizeof (msg->msg_hdr));
	msg->msg_hdr.type           = cpu_to_le32(type);
	/* dest_nid will be overwritten by lnet_select_pathway() */
	msg->msg_hdr.dest_nid       = cpu_to_le64(target.nid);
	msg->msg_hdr.dest_pid       = cpu_to_le32(target.pid);
	/* src_nid will be set later */
	msg->msg_hdr.src_pid        = cpu_to_le32(the_lnet.ln_pid);
	msg->msg_hdr.payload_length = cpu_to_le32(len);
}

void
lnet_ni_send(struct lnet_ni *ni, struct lnet_msg *msg)
{
	void *priv = msg->msg_private;
	int rc;

	LASSERT(!in_interrupt());
	LASSERT(ni->ni_nid == LNET_NID_LO_0 ||
		(msg->msg_txcredit && msg->msg_peertxcredit));

	rc = (ni->ni_net->net_lnd->lnd_send)(ni, priv, msg);
	if (rc < 0) {
		msg->msg_no_resend = true;
		lnet_finalize(msg, rc);
	}
}

static int
lnet_ni_eager_recv(struct lnet_ni *ni, struct lnet_msg *msg)
{
	int	rc;

	LASSERT(!msg->msg_sending);
	LASSERT(msg->msg_receiving);
	LASSERT(!msg->msg_rx_ready_delay);
	LASSERT(ni->ni_net->net_lnd->lnd_eager_recv != NULL);

	msg->msg_rx_ready_delay = 1;
	rc = (ni->ni_net->net_lnd->lnd_eager_recv)(ni, msg->msg_private, msg,
						  &msg->msg_private);
	if (rc != 0) {
		CERROR("recv from %s / send to %s aborted: "
		       "eager_recv failed %d\n",
		       libcfs_nid2str(msg->msg_rxpeer->lpni_nid),
		       libcfs_id2str(msg->msg_target), rc);
		LASSERT(rc < 0); /* required by my callers */
	}

	return rc;
}

/*
 * This function can be called from two paths:
 *	1. when sending a message
 *	2. when decommiting a message (lnet_msg_decommit_tx())
 * In both these cases the peer_ni should have it's reference count
 * acquired by the caller and therefore it is safe to drop the spin
 * lock before calling lnd_query()
 */
static void
lnet_ni_query_locked(struct lnet_ni *ni, struct lnet_peer_ni *lp)
{
	time64_t last_alive = 0;
	int cpt = lnet_cpt_of_nid_locked(lp->lpni_nid, ni);

	LASSERT(lnet_peer_aliveness_enabled(lp));
	LASSERT(ni->ni_net->net_lnd->lnd_query != NULL);

	lnet_net_unlock(cpt);
	(ni->ni_net->net_lnd->lnd_query)(ni, lp->lpni_nid, &last_alive);
	lnet_net_lock(cpt);

	lp->lpni_last_query = ktime_get_seconds();

	if (last_alive != 0) /* NI has updated timestamp */
		lp->lpni_last_alive = last_alive;
}

/* NB: always called with lnet_net_lock held */
static inline int
lnet_peer_is_alive(struct lnet_peer_ni *lp, time64_t now)
{
	int alive;
	time64_t deadline;

	LASSERT (lnet_peer_aliveness_enabled(lp));

	/*
	 * Trust lnet_notify() if it has more recent aliveness news, but
	 * ignore the initial assumed death (see lnet_peers_start_down()).
	 */
	spin_lock(&lp->lpni_lock);
	if (!lp->lpni_alive && lp->lpni_alive_count > 0 &&
	    lp->lpni_timestamp >= lp->lpni_last_alive) {
		spin_unlock(&lp->lpni_lock);
		return 0;
	}

	deadline = lp->lpni_last_alive +
		   lp->lpni_net->net_tunables.lct_peer_timeout;
	alive = deadline > now;

	/*
	 * Update obsolete lp_alive except for routers assumed to be dead
	 * initially, because router checker would update aliveness in this
	 * case, and moreover lpni_last_alive at peer creation is assumed.
	 */
	if (alive && !lp->lpni_alive &&
	    !(lnet_isrouter(lp) && lp->lpni_alive_count == 0)) {
		spin_unlock(&lp->lpni_lock);
		lnet_notify_locked(lp, 0, 1, lp->lpni_last_alive);
	} else {
		spin_unlock(&lp->lpni_lock);
	}

	return alive;
}


/* NB: returns 1 when alive, 0 when dead, negative when error;
 *     may drop the lnet_net_lock */
static int
lnet_peer_alive_locked(struct lnet_ni *ni, struct lnet_peer_ni *lp,
		       struct lnet_msg *msg)
{
	time64_t now = ktime_get_seconds();

	if (!lnet_peer_aliveness_enabled(lp))
		return -ENODEV;

	if (lnet_peer_is_alive(lp, now))
		return 1;

	/*
	 * If we're resending a message, let's attempt to send it even if
	 * the peer is down to fulfill our resend quota on the message
	 */
	if (msg->msg_retry_count > 0)
		return 1;

	/*
	 * Peer appears dead, but we should avoid frequent NI queries (at
	 * most once per lnet_queryinterval seconds).
	 */
	if (lp->lpni_last_query != 0) {
		static const int lnet_queryinterval = 1;
		time64_t next_query;

		next_query = lp->lpni_last_query + lnet_queryinterval;

		if (now < next_query) {
			if (lp->lpni_alive)
				CWARN("Unexpected aliveness of peer %s: "
				      "%lld < %lld (%d/%d)\n",
				      libcfs_nid2str(lp->lpni_nid),
				      now, next_query,
				      lnet_queryinterval,
				      lp->lpni_net->net_tunables.lct_peer_timeout);
			return 0;
		}
	}

	/* query NI for latest aliveness news */
	lnet_ni_query_locked(ni, lp);

	if (lnet_peer_is_alive(lp, now))
		return 1;

	lnet_notify_locked(lp, 0, 0, lp->lpni_last_alive);
	return 0;
}

/**
 * \param msg The message to be sent.
 * \param do_send True if lnet_ni_send() should be called in this function.
 *	  lnet_send() is going to lnet_net_unlock immediately after this, so
 *	  it sets do_send FALSE and I don't do the unlock/send/lock bit.
 *
 * \retval LNET_CREDIT_OK If \a msg sent or OK to send.
 * \retval LNET_CREDIT_WAIT If \a msg blocked for credit.
 * \retval -EHOSTUNREACH If the next hop of the message appears dead.
 * \retval -ECANCELED If the MD of the message has been unlinked.
 */
static int
lnet_post_send_locked(struct lnet_msg *msg, int do_send)
{
	struct lnet_peer_ni	*lp = msg->msg_txpeer;
	struct lnet_ni		*ni = msg->msg_txni;
	int			cpt = msg->msg_tx_cpt;
	struct lnet_tx_queue	*tq = ni->ni_tx_queues[cpt];

	/* non-lnet_send() callers have checked before */
	LASSERT(!do_send || msg->msg_tx_delayed);
	LASSERT(!msg->msg_receiving);
	LASSERT(msg->msg_tx_committed);
	/* can't get here if we're sending to the loopback interface */
	LASSERT(lp->lpni_nid != the_lnet.ln_loni->ni_nid);

	/* NB 'lp' is always the next hop */
	if ((msg->msg_target.pid & LNET_PID_USERFLAG) == 0 &&
	    lnet_peer_alive_locked(ni, lp, msg) == 0) {
		the_lnet.ln_counters[cpt]->lct_common.lcc_drop_count++;
		the_lnet.ln_counters[cpt]->lct_common.lcc_drop_length +=
			msg->msg_len;
		lnet_net_unlock(cpt);
		if (msg->msg_txpeer)
			lnet_incr_stats(&msg->msg_txpeer->lpni_stats,
					msg->msg_type,
					LNET_STATS_TYPE_DROP);
		if (msg->msg_txni)
			lnet_incr_stats(&msg->msg_txni->ni_stats,
					msg->msg_type,
					LNET_STATS_TYPE_DROP);

		CNETERR("Dropping message for %s: peer not alive\n",
			libcfs_id2str(msg->msg_target));
		msg->msg_health_status = LNET_MSG_STATUS_REMOTE_DROPPED;
		if (do_send)
			lnet_finalize(msg, -EHOSTUNREACH);

		lnet_net_lock(cpt);
		return -EHOSTUNREACH;
	}

	if (msg->msg_md != NULL &&
	    (msg->msg_md->md_flags & LNET_MD_FLAG_ABORTED) != 0) {
		lnet_net_unlock(cpt);

		CNETERR("Aborting message for %s: LNetM[DE]Unlink() already "
			"called on the MD/ME.\n",
			libcfs_id2str(msg->msg_target));
		if (do_send) {
			msg->msg_no_resend = true;
			CDEBUG(D_NET, "msg %p to %s canceled and will not be resent\n",
			       msg, libcfs_id2str(msg->msg_target));
			lnet_finalize(msg, -ECANCELED);
		}

		lnet_net_lock(cpt);
		return -ECANCELED;
	}

	if (!msg->msg_peertxcredit) {
		spin_lock(&lp->lpni_lock);
		LASSERT((lp->lpni_txcredits < 0) ==
			!list_empty(&lp->lpni_txq));

		msg->msg_peertxcredit = 1;
		lp->lpni_txqnob += msg->msg_len + sizeof(struct lnet_hdr);
		lp->lpni_txcredits--;

		if (lp->lpni_txcredits < lp->lpni_mintxcredits)
			lp->lpni_mintxcredits = lp->lpni_txcredits;

		if (lp->lpni_txcredits < 0) {
			msg->msg_tx_delayed = 1;
			list_add_tail(&msg->msg_list, &lp->lpni_txq);
			spin_unlock(&lp->lpni_lock);
			return LNET_CREDIT_WAIT;
		}
		spin_unlock(&lp->lpni_lock);
	}

	if (!msg->msg_txcredit) {
		LASSERT((tq->tq_credits < 0) ==
			!list_empty(&tq->tq_delayed));

		msg->msg_txcredit = 1;
		tq->tq_credits--;
		atomic_dec(&ni->ni_tx_credits);

		if (tq->tq_credits < tq->tq_credits_min)
			tq->tq_credits_min = tq->tq_credits;

		if (tq->tq_credits < 0) {
			msg->msg_tx_delayed = 1;
			list_add_tail(&msg->msg_list, &tq->tq_delayed);
			return LNET_CREDIT_WAIT;
		}
	}

	if (unlikely(!list_empty(&the_lnet.ln_delay_rules)) &&
	    lnet_delay_rule_match_locked(&msg->msg_hdr, msg)) {
		msg->msg_tx_delayed = 1;
		return LNET_CREDIT_WAIT;
	}

	/* unset the tx_delay flag as we're going to send it now */
	msg->msg_tx_delayed = 0;

	if (do_send) {
		lnet_net_unlock(cpt);
		lnet_ni_send(ni, msg);
		lnet_net_lock(cpt);
	}
	return LNET_CREDIT_OK;
}


static struct lnet_rtrbufpool *
lnet_msg2bufpool(struct lnet_msg *msg)
{
	struct lnet_rtrbufpool	*rbp;
	int			cpt;

	LASSERT(msg->msg_rx_committed);

	cpt = msg->msg_rx_cpt;
	rbp = &the_lnet.ln_rtrpools[cpt][0];

	LASSERT(msg->msg_len <= LNET_MTU);
	while (msg->msg_len > (unsigned int)rbp->rbp_npages * PAGE_SIZE) {
		rbp++;
		LASSERT(rbp < &the_lnet.ln_rtrpools[cpt][LNET_NRBPOOLS]);
	}

	return rbp;
}

static int
lnet_post_routed_recv_locked(struct lnet_msg *msg, int do_recv)
{
	/* lnet_parse is going to lnet_net_unlock immediately after this, so it
	 * sets do_recv FALSE and I don't do the unlock/send/lock bit.
	 * I return LNET_CREDIT_WAIT if msg blocked and LNET_CREDIT_OK if
	 * received or OK to receive */
	struct lnet_peer_ni *lp = msg->msg_rxpeer;
	struct lnet_rtrbufpool *rbp;
	struct lnet_rtrbuf *rb;

	LASSERT (msg->msg_iov == NULL);
	LASSERT (msg->msg_kiov == NULL);
	LASSERT (msg->msg_niov == 0);
	LASSERT (msg->msg_routing);
	LASSERT (msg->msg_receiving);
	LASSERT (!msg->msg_sending);

	/* non-lnet_parse callers only receive delayed messages */
	LASSERT(!do_recv || msg->msg_rx_delayed);

	if (!msg->msg_peerrtrcredit) {
		spin_lock(&lp->lpni_lock);
		LASSERT((lp->lpni_rtrcredits < 0) ==
			!list_empty(&lp->lpni_rtrq));

		msg->msg_peerrtrcredit = 1;
		lp->lpni_rtrcredits--;
		if (lp->lpni_rtrcredits < lp->lpni_minrtrcredits)
			lp->lpni_minrtrcredits = lp->lpni_rtrcredits;

		if (lp->lpni_rtrcredits < 0) {
			/* must have checked eager_recv before here */
			LASSERT(msg->msg_rx_ready_delay);
			msg->msg_rx_delayed = 1;
			list_add_tail(&msg->msg_list, &lp->lpni_rtrq);
			spin_unlock(&lp->lpni_lock);
			return LNET_CREDIT_WAIT;
		}
		spin_unlock(&lp->lpni_lock);
	}

	rbp = lnet_msg2bufpool(msg);

	if (!msg->msg_rtrcredit) {
		msg->msg_rtrcredit = 1;
		rbp->rbp_credits--;
		if (rbp->rbp_credits < rbp->rbp_mincredits)
			rbp->rbp_mincredits = rbp->rbp_credits;

		if (rbp->rbp_credits < 0) {
			/* must have checked eager_recv before here */
			LASSERT(msg->msg_rx_ready_delay);
			msg->msg_rx_delayed = 1;
			list_add_tail(&msg->msg_list, &rbp->rbp_msgs);
			return LNET_CREDIT_WAIT;
		}
	}

	LASSERT(!list_empty(&rbp->rbp_bufs));
	rb = list_entry(rbp->rbp_bufs.next, struct lnet_rtrbuf, rb_list);
	list_del(&rb->rb_list);

	msg->msg_niov = rbp->rbp_npages;
	msg->msg_kiov = &rb->rb_kiov[0];

	/* unset the msg-rx_delayed flag since we're receiving the message */
	msg->msg_rx_delayed = 0;

	if (do_recv) {
		int cpt = msg->msg_rx_cpt;

		lnet_net_unlock(cpt);
		lnet_ni_recv(msg->msg_rxni, msg->msg_private, msg, 1,
			     0, msg->msg_len, msg->msg_len);
		lnet_net_lock(cpt);
	}
	return LNET_CREDIT_OK;
}

void
lnet_return_tx_credits_locked(struct lnet_msg *msg)
{
	struct lnet_peer_ni	*txpeer = msg->msg_txpeer;
	struct lnet_ni		*txni = msg->msg_txni;
	struct lnet_msg		*msg2;

	if (msg->msg_txcredit) {
		struct lnet_ni	     *ni = msg->msg_txni;
		struct lnet_tx_queue *tq = ni->ni_tx_queues[msg->msg_tx_cpt];

		/* give back NI txcredits */
		msg->msg_txcredit = 0;

		LASSERT((tq->tq_credits < 0) ==
			!list_empty(&tq->tq_delayed));

		tq->tq_credits++;
		atomic_inc(&ni->ni_tx_credits);
		if (tq->tq_credits <= 0) {
			msg2 = list_entry(tq->tq_delayed.next,
					  struct lnet_msg, msg_list);
			list_del(&msg2->msg_list);

			LASSERT(msg2->msg_txni == ni);
			LASSERT(msg2->msg_tx_delayed);
			LASSERT(msg2->msg_tx_cpt == msg->msg_tx_cpt);

			(void) lnet_post_send_locked(msg2, 1);
		}
	}

	if (msg->msg_peertxcredit) {
		/* give back peer txcredits */
		msg->msg_peertxcredit = 0;

		spin_lock(&txpeer->lpni_lock);
		LASSERT((txpeer->lpni_txcredits < 0) ==
			!list_empty(&txpeer->lpni_txq));

		txpeer->lpni_txqnob -= msg->msg_len + sizeof(struct lnet_hdr);
		LASSERT(txpeer->lpni_txqnob >= 0);

		txpeer->lpni_txcredits++;
		if (txpeer->lpni_txcredits <= 0) {
			int msg2_cpt;

			msg2 = list_entry(txpeer->lpni_txq.next,
					      struct lnet_msg, msg_list);
			list_del(&msg2->msg_list);
			spin_unlock(&txpeer->lpni_lock);

			LASSERT(msg2->msg_txpeer == txpeer);
			LASSERT(msg2->msg_tx_delayed);

			msg2_cpt = msg2->msg_tx_cpt;

			/*
			 * The msg_cpt can be different from the msg2_cpt
			 * so we need to make sure we lock the correct cpt
			 * for msg2.
			 * Once we call lnet_post_send_locked() it is no
			 * longer safe to access msg2, since it could've
			 * been freed by lnet_finalize(), but we still
			 * need to relock the correct cpt, so we cache the
			 * msg2_cpt for the purpose of the check that
			 * follows the call to lnet_pose_send_locked().
			 */
			if (msg2_cpt != msg->msg_tx_cpt) {
				lnet_net_unlock(msg->msg_tx_cpt);
				lnet_net_lock(msg2_cpt);
			}
                        (void) lnet_post_send_locked(msg2, 1);
			if (msg2_cpt != msg->msg_tx_cpt) {
				lnet_net_unlock(msg2_cpt);
				lnet_net_lock(msg->msg_tx_cpt);
			}
                } else {
			spin_unlock(&txpeer->lpni_lock);
		}
        }

	if (txni != NULL) {
		msg->msg_txni = NULL;
		lnet_ni_decref_locked(txni, msg->msg_tx_cpt);
	}

	if (txpeer != NULL) {
		msg->msg_txpeer = NULL;
		lnet_peer_ni_decref_locked(txpeer);
	}
}

void
lnet_schedule_blocked_locked(struct lnet_rtrbufpool *rbp)
{
	struct lnet_msg	*msg;

	if (list_empty(&rbp->rbp_msgs))
		return;
	msg = list_entry(rbp->rbp_msgs.next,
			 struct lnet_msg, msg_list);
	list_del(&msg->msg_list);

	(void)lnet_post_routed_recv_locked(msg, 1);
}

void
lnet_drop_routed_msgs_locked(struct list_head *list, int cpt)
{
	struct lnet_msg *msg;
	struct lnet_msg *tmp;

	lnet_net_unlock(cpt);

	list_for_each_entry_safe(msg, tmp, list, msg_list) {
		lnet_ni_recv(msg->msg_rxni, msg->msg_private, NULL,
			     0, 0, 0, msg->msg_hdr.payload_length);
		list_del_init(&msg->msg_list);
		msg->msg_no_resend = true;
		msg->msg_health_status = LNET_MSG_STATUS_REMOTE_ERROR;
		lnet_finalize(msg, -ECANCELED);
	}

	lnet_net_lock(cpt);
}

void
lnet_return_rx_credits_locked(struct lnet_msg *msg)
{
	struct lnet_peer_ni *rxpeer = msg->msg_rxpeer;
	struct lnet_ni *rxni = msg->msg_rxni;
	struct lnet_msg	*msg2;

	if (msg->msg_rtrcredit) {
		/* give back global router credits */
		struct lnet_rtrbuf *rb;
		struct lnet_rtrbufpool *rbp;

		/* NB If a msg ever blocks for a buffer in rbp_msgs, it stays
		 * there until it gets one allocated, or aborts the wait
		 * itself */
		LASSERT(msg->msg_kiov != NULL);

		rb = list_entry(msg->msg_kiov, struct lnet_rtrbuf, rb_kiov[0]);
		rbp = rb->rb_pool;

		msg->msg_kiov = NULL;
		msg->msg_rtrcredit = 0;

		LASSERT(rbp == lnet_msg2bufpool(msg));

		LASSERT((rbp->rbp_credits > 0) ==
			!list_empty(&rbp->rbp_bufs));

		/* If routing is now turned off, we just drop this buffer and
		 * don't bother trying to return credits.  */
		if (!the_lnet.ln_routing) {
			lnet_destroy_rtrbuf(rb, rbp->rbp_npages);
			goto routing_off;
		}

		/* It is possible that a user has lowered the desired number of
		 * buffers in this pool.  Make sure we never put back
		 * more buffers than the stated number. */
		if (unlikely(rbp->rbp_credits >= rbp->rbp_req_nbuffers)) {
			/* Discard this buffer so we don't have too
			 * many. */
			lnet_destroy_rtrbuf(rb, rbp->rbp_npages);
			rbp->rbp_nbuffers--;
		} else {
			list_add(&rb->rb_list, &rbp->rbp_bufs);
			rbp->rbp_credits++;
			if (rbp->rbp_credits <= 0)
				lnet_schedule_blocked_locked(rbp);
		}
	}

routing_off:
	if (msg->msg_peerrtrcredit) {
		/* give back peer router credits */
		msg->msg_peerrtrcredit = 0;

		spin_lock(&rxpeer->lpni_lock);
		LASSERT((rxpeer->lpni_rtrcredits < 0) ==
			!list_empty(&rxpeer->lpni_rtrq));

		rxpeer->lpni_rtrcredits++;

		/* drop all messages which are queued to be routed on that
		 * peer. */
		if (!the_lnet.ln_routing) {
			struct list_head drop;
			INIT_LIST_HEAD(&drop);
			list_splice_init(&rxpeer->lpni_rtrq, &drop);
			spin_unlock(&rxpeer->lpni_lock);
			lnet_drop_routed_msgs_locked(&drop, msg->msg_rx_cpt);
		} else if (rxpeer->lpni_rtrcredits <= 0) {
			msg2 = list_entry(rxpeer->lpni_rtrq.next,
					  struct lnet_msg, msg_list);
			list_del(&msg2->msg_list);
			spin_unlock(&rxpeer->lpni_lock);
			(void) lnet_post_routed_recv_locked(msg2, 1);
		} else {
			spin_unlock(&rxpeer->lpni_lock);
		}
	}
	if (rxni != NULL) {
		msg->msg_rxni = NULL;
		lnet_ni_decref_locked(rxni, msg->msg_rx_cpt);
	}
	if (rxpeer != NULL) {
		msg->msg_rxpeer = NULL;
		lnet_peer_ni_decref_locked(rxpeer);
	}
}

static int
lnet_compare_peers(struct lnet_peer_ni *p1, struct lnet_peer_ni *p2)
{
	if (p1->lpni_txqnob < p2->lpni_txqnob)
		return 1;

	if (p1->lpni_txqnob > p2->lpni_txqnob)
		return -1;

	if (p1->lpni_txcredits > p2->lpni_txcredits)
		return 1;

	if (p1->lpni_txcredits < p2->lpni_txcredits)
		return -1;

	return 0;
}

static int
lnet_compare_routes(struct lnet_route *r1, struct lnet_route *r2)
{
	struct lnet_peer_ni *p1 = r1->lr_gateway;
	struct lnet_peer_ni *p2 = r2->lr_gateway;
	int r1_hops = (r1->lr_hops == LNET_UNDEFINED_HOPS) ? 1 : r1->lr_hops;
	int r2_hops = (r2->lr_hops == LNET_UNDEFINED_HOPS) ? 1 : r2->lr_hops;
	int rc;

	if (r1->lr_priority < r2->lr_priority)
		return 1;

	if (r1->lr_priority > r2->lr_priority)
		return -1;

	if (r1_hops < r2_hops)
		return 1;

	if (r1_hops > r2_hops)
		return -1;

	rc = lnet_compare_peers(p1, p2);
	if (rc)
		return rc;

	if (r1->lr_seq - r2->lr_seq <= 0)
		return 1;

	return -1;
}

static struct lnet_peer_ni *
lnet_find_route_locked(struct lnet_net *net, __u32 remote_net,
		       lnet_nid_t rtr_nid)
{
	struct lnet_remotenet	*rnet;
	struct lnet_route		*route;
	struct lnet_route		*best_route;
	struct lnet_route		*last_route;
	struct lnet_peer_ni	*lpni_best;
	struct lnet_peer_ni	*lp;
	int			rc;

	/* If @rtr_nid is not LNET_NID_ANY, return the gateway with
	 * rtr_nid nid, otherwise find the best gateway I can use */

	rnet = lnet_find_rnet_locked(remote_net);
	if (rnet == NULL)
		return NULL;

	lpni_best = NULL;
	best_route = last_route = NULL;
	list_for_each_entry(route, &rnet->lrn_routes, lr_list) {
		lp = route->lr_gateway;

		if (!lnet_is_route_alive(route))
			continue;

		if (net != NULL && lp->lpni_net != net)
			continue;

		if (lp->lpni_nid == rtr_nid) /* it's pre-determined router */
			return lp;

		if (lpni_best == NULL) {
			best_route = last_route = route;
			lpni_best = lp;
			continue;
		}

		/* no protection on below fields, but it's harmless */
		if (last_route->lr_seq - route->lr_seq < 0)
			last_route = route;

		rc = lnet_compare_routes(route, best_route);
		if (rc < 0)
			continue;

		best_route = route;
		lpni_best = lp;
	}

	/* set sequence number on the best router to the latest sequence + 1
	 * so we can round-robin all routers, it's race and inaccurate but
	 * harmless and functional  */
	if (best_route != NULL)
		best_route->lr_seq = last_route->lr_seq + 1;
	return lpni_best;
}

static struct lnet_ni *
lnet_get_best_ni(struct lnet_net *local_net, struct lnet_ni *best_ni,
		 struct lnet_peer *peer, struct lnet_peer_net *peer_net,
		 int md_cpt)
{
	struct lnet_ni *ni = NULL;
	unsigned int shortest_distance;
	int best_credits;
	int best_healthv;

	/*
	 * If there is no peer_ni that we can send to on this network,
	 * then there is no point in looking for a new best_ni here.
	*/
	if (!lnet_get_next_peer_ni_locked(peer, peer_net, NULL))
		return best_ni;

	if (best_ni == NULL) {
		shortest_distance = UINT_MAX;
		best_credits = INT_MIN;
		best_healthv = 0;
	} else {
		shortest_distance = cfs_cpt_distance(lnet_cpt_table(), md_cpt,
						     best_ni->ni_dev_cpt);
		best_credits = atomic_read(&best_ni->ni_tx_credits);
		best_healthv = atomic_read(&best_ni->ni_healthv);
	}

	while ((ni = lnet_get_next_ni_locked(local_net, ni))) {
		unsigned int distance;
		int ni_credits;
		int ni_healthv;
		int ni_fatal;

		ni_credits = atomic_read(&ni->ni_tx_credits);
		ni_healthv = atomic_read(&ni->ni_healthv);
		ni_fatal = atomic_read(&ni->ni_fatal_error_on);

		/*
		 * calculate the distance from the CPT on which
		 * the message memory is allocated to the CPT of
		 * the NI's physical device
		 */
		distance = cfs_cpt_distance(lnet_cpt_table(),
					    md_cpt,
					    ni->ni_dev_cpt);

		CDEBUG(D_NET, "compare ni %s [c:%d, d:%d, s:%d] with best_ni %s [c:%d, d:%d, s:%d]\n",
		       libcfs_nid2str(ni->ni_nid), ni_credits, distance,
		       ni->ni_seq, (best_ni) ? libcfs_nid2str(best_ni->ni_nid)
			: "not seleced", best_credits, shortest_distance,
			(best_ni) ? best_ni->ni_seq : 0);

		/*
		 * All distances smaller than the NUMA range
		 * are treated equally.
		 */
		if (distance < lnet_numa_range)
			distance = lnet_numa_range;

		/*
		 * Select on health, shorter distance, available
		 * credits, then round-robin.
		 */
		if (ni_fatal) {
			continue;
		} else if (ni_healthv < best_healthv) {
			continue;
		} else if (ni_healthv > best_healthv) {
			best_healthv = ni_healthv;
			/*
			 * If we're going to prefer this ni because it's
			 * the healthiest, then we should set the
			 * shortest_distance in the algorithm in case
			 * there are multiple NIs with the same health but
			 * different distances.
			 */
			if (distance < shortest_distance)
				shortest_distance = distance;
		} else if (distance > shortest_distance) {
			continue;
		} else if (distance < shortest_distance) {
			shortest_distance = distance;
		} else if (ni_credits < best_credits) {
			continue;
		} else if (ni_credits == best_credits) {
			if (best_ni && best_ni->ni_seq <= ni->ni_seq)
				continue;
		}
		best_ni = ni;
		best_credits = ni_credits;
	}

	CDEBUG(D_NET, "selected best_ni %s\n",
	       (best_ni) ? libcfs_nid2str(best_ni->ni_nid) : "no selection");

	return best_ni;
}

/*
 * Traffic to the LNET_RESERVED_PORTAL may not trigger peer discovery,
 * because such traffic is required to perform discovery. We therefore
 * exclude all GET and PUT on that portal. We also exclude all ACK and
 * REPLY traffic, but that is because the portal is not tracked in the
 * message structure for these message types. We could restrict this
 * further by also checking for LNET_PROTO_PING_MATCHBITS.
 */
static bool
lnet_msg_discovery(struct lnet_msg *msg)
{
	if (msg->msg_type == LNET_MSG_PUT) {
		if (msg->msg_hdr.msg.put.ptl_index != LNET_RESERVED_PORTAL)
			return true;
	} else if (msg->msg_type == LNET_MSG_GET) {
		if (msg->msg_hdr.msg.get.ptl_index != LNET_RESERVED_PORTAL)
			return true;
	}
	return false;
}

#define SRC_SPEC	0x0001
#define SRC_ANY		0x0002
#define LOCAL_DST	0x0004
#define REMOTE_DST	0x0008
#define MR_DST		0x0010
#define NMR_DST		0x0020
#define SND_RESP	0x0040

/* The following to defines are used for return codes */
#define REPEAT_SEND	0x1000
#define PASS_THROUGH	0x2000

/* The different cases lnet_select pathway needs to handle */
#define SRC_SPEC_LOCAL_MR_DST	(SRC_SPEC | LOCAL_DST | MR_DST)
#define SRC_SPEC_ROUTER_MR_DST	(SRC_SPEC | REMOTE_DST | MR_DST)
#define SRC_SPEC_LOCAL_NMR_DST	(SRC_SPEC | LOCAL_DST | NMR_DST)
#define SRC_SPEC_ROUTER_NMR_DST	(SRC_SPEC | REMOTE_DST | NMR_DST)
#define SRC_ANY_LOCAL_MR_DST	(SRC_ANY | LOCAL_DST | MR_DST)
#define SRC_ANY_ROUTER_MR_DST	(SRC_ANY | REMOTE_DST | MR_DST)
#define SRC_ANY_LOCAL_NMR_DST	(SRC_ANY | LOCAL_DST | NMR_DST)
#define SRC_ANY_ROUTER_NMR_DST	(SRC_ANY | REMOTE_DST | NMR_DST)

static int
lnet_handle_lo_send(struct lnet_send_data *sd)
{
	struct lnet_msg *msg = sd->sd_msg;
	int cpt = sd->sd_cpt;

	/* No send credit hassles with LOLND */
	lnet_ni_addref_locked(the_lnet.ln_loni, cpt);
	msg->msg_hdr.dest_nid = cpu_to_le64(the_lnet.ln_loni->ni_nid);
	if (!msg->msg_routing)
		msg->msg_hdr.src_nid =
			cpu_to_le64(the_lnet.ln_loni->ni_nid);
	msg->msg_target.nid = the_lnet.ln_loni->ni_nid;
	lnet_msg_commit(msg, cpt);
	msg->msg_txni = the_lnet.ln_loni;

	return LNET_CREDIT_OK;
}

static int
lnet_handle_send(struct lnet_send_data *sd)
{
	struct lnet_ni *best_ni = sd->sd_best_ni;
	struct lnet_peer_ni *best_lpni = sd->sd_best_lpni;
	struct lnet_peer_ni *final_dst_lpni = sd->sd_final_dst_lpni;
	struct lnet_msg *msg = sd->sd_msg;
	int cpt2;
	__u32 send_case = sd->sd_send_case;
	int rc;
	__u32 routing = send_case & REMOTE_DST;
	 struct lnet_rsp_tracker *rspt;

	/*
	 * Increment sequence number of the selected peer so that we
	 * pick the next one in Round Robin.
	 */
	best_lpni->lpni_seq++;

	/*
	 * grab a reference on the peer_ni so it sticks around even if
	 * we need to drop and relock the lnet_net_lock below.
	 */
	lnet_peer_ni_addref_locked(best_lpni);

	/*
	 * Use lnet_cpt_of_nid() to determine the CPT used to commit the
	 * message. This ensures that we get a CPT that is correct for
	 * the NI when the NI has been restricted to a subset of all CPTs.
	 * If the selected CPT differs from the one currently locked, we
	 * must unlock and relock the lnet_net_lock(), and then check whether
	 * the configuration has changed. We don't have a hold on the best_ni
	 * yet, and it may have vanished.
	 */
	cpt2 = lnet_cpt_of_nid_locked(best_lpni->lpni_nid, best_ni);
	if (sd->sd_cpt != cpt2) {
		__u32 seq = lnet_get_dlc_seq_locked();
		lnet_net_unlock(sd->sd_cpt);
		sd->sd_cpt = cpt2;
		lnet_net_lock(sd->sd_cpt);
		if (seq != lnet_get_dlc_seq_locked()) {
			lnet_peer_ni_decref_locked(best_lpni);
			return REPEAT_SEND;
		}
	}

	/*
	 * store the best_lpni in the message right away to avoid having
	 * to do the same operation under different conditions
	 */
	msg->msg_txpeer = best_lpni;
	msg->msg_txni = best_ni;

	/*
	 * grab a reference for the best_ni since now it's in use in this
	 * send. The reference will be dropped in lnet_finalize()
	 */
	lnet_ni_addref_locked(msg->msg_txni, sd->sd_cpt);

	/*
	 * Always set the target.nid to the best peer picked. Either the
	 * NID will be one of the peer NIDs selected, or the same NID as
	 * what was originally set in the target or it will be the NID of
	 * a router if this message should be routed
	 */
	msg->msg_target.nid = msg->msg_txpeer->lpni_nid;

	/*
	 * lnet_msg_commit assigns the correct cpt to the message, which
	 * is used to decrement the correct refcount on the ni when it's
	 * time to return the credits
	 */
	lnet_msg_commit(msg, sd->sd_cpt);

	/*
	 * If we are routing the message then we keep the src_nid that was
	 * set by the originator. If we are not routing then we are the
	 * originator and set it here.
	 */
	if (!msg->msg_routing)
		msg->msg_hdr.src_nid = cpu_to_le64(msg->msg_txni->ni_nid);

	if (routing) {
		msg->msg_target_is_router = 1;
		msg->msg_target.pid = LNET_PID_LUSTRE;
		/*
		 * since we're routing we want to ensure that the
		 * msg_hdr.dest_nid is set to the final destination. When
		 * the router receives this message it knows how to route
		 * it.
		 *
		 * final_dst_lpni is set at the beginning of the
		 * lnet_select_pathway() function and is never changed.
		 * It's safe to use it here.
		 */
		msg->msg_hdr.dest_nid = cpu_to_le64(final_dst_lpni->lpni_nid);
	} else {
		/*
		 * if we're not routing set the dest_nid to the best peer
		 * ni NID that we picked earlier in the algorithm.
		 */
		msg->msg_hdr.dest_nid = cpu_to_le64(msg->msg_txpeer->lpni_nid);
	}

	/*
	 * if we have response tracker block update it with the next hop
	 * nid
	 */
	if (msg->msg_md) {
		rspt = msg->msg_md->md_rspt_ptr;
		if (rspt) {
			rspt->rspt_next_hop_nid = msg->msg_txpeer->lpni_nid;
			CDEBUG(D_NET, "rspt_next_hop_nid = %s\n",
			       libcfs_nid2str(rspt->rspt_next_hop_nid));
		}
	}

	rc = lnet_post_send_locked(msg, 0);

	if (!rc)
		CDEBUG(D_NET, "TRACE: %s(%s:%s) -> %s(%s:%s) : %s try# %d\n",
		       libcfs_nid2str(msg->msg_hdr.src_nid),
		       libcfs_nid2str(msg->msg_txni->ni_nid),
		       libcfs_nid2str(sd->sd_src_nid),
		       libcfs_nid2str(msg->msg_hdr.dest_nid),
		       libcfs_nid2str(sd->sd_dst_nid),
		       libcfs_nid2str(msg->msg_txpeer->lpni_nid),
		       lnet_msgtyp2str(msg->msg_type), msg->msg_retry_count);

	return rc;
}

static struct lnet_peer_ni *
lnet_select_peer_ni(struct lnet_send_data *sd, struct lnet_peer *peer,
		    struct lnet_peer_net *peer_net)
{
	/*
	 * Look at the peer NIs for the destination peer that connect
	 * to the chosen net. If a peer_ni is preferred when using the
	 * best_ni to communicate, we use that one. If there is no
	 * preferred peer_ni, or there are multiple preferred peer_ni,
	 * the available transmit credits are used. If the transmit
	 * credits are equal, we round-robin over the peer_ni.
	 */
	struct lnet_peer_ni *lpni = NULL;
	struct lnet_peer_ni *best_lpni = NULL;
	struct lnet_ni *best_ni = sd->sd_best_ni;
	lnet_nid_t dst_nid = sd->sd_dst_nid;
	int best_lpni_credits = INT_MIN;
	bool preferred = false;
	bool ni_is_pref;
	int best_lpni_healthv = 0;
	int lpni_healthv;

	while ((lpni = lnet_get_next_peer_ni_locked(peer, peer_net, lpni))) {
		/*
		 * if the best_ni we've chosen aleady has this lpni
		 * preferred, then let's use it
		 */
		ni_is_pref = lnet_peer_is_pref_nid_locked(lpni,
							  best_ni->ni_nid);

		lpni_healthv = atomic_read(&lpni->lpni_healthv);

		CDEBUG(D_NET, "%s ni_is_pref = %d\n",
		       libcfs_nid2str(best_ni->ni_nid), ni_is_pref);

		if (best_lpni)
			CDEBUG(D_NET, "%s c:[%d, %d], s:[%d, %d]\n",
				libcfs_nid2str(lpni->lpni_nid),
				lpni->lpni_txcredits, best_lpni_credits,
				lpni->lpni_seq, best_lpni->lpni_seq);

		/* pick the healthiest peer ni */
		if (lpni_healthv < best_lpni_healthv) {
			continue;
		} else if (lpni_healthv > best_lpni_healthv) {
			best_lpni_healthv = lpni_healthv;
		/* if this is a preferred peer use it */
		} else if (!preferred && ni_is_pref) {
			preferred = true;
		} else if (preferred && !ni_is_pref) {
			/*
			 * this is not the preferred peer so let's ignore
			 * it.
			 */
			continue;
		} else if (lpni->lpni_txcredits < best_lpni_credits) {
			/*
			 * We already have a peer that has more credits
			 * available than this one. No need to consider
			 * this peer further.
			 */
			continue;
		} else if (lpni->lpni_txcredits == best_lpni_credits) {
			/*
			 * The best peer found so far and the current peer
			 * have the same number of available credits let's
			 * make sure to select between them using Round
			 * Robin
			 */
			if (best_lpni) {
				if (best_lpni->lpni_seq <= lpni->lpni_seq)
					continue;
			}
		}

		best_lpni = lpni;
		best_lpni_credits = lpni->lpni_txcredits;
	}

	/* if we still can't find a peer ni then we can't reach it */
	if (!best_lpni) {
		__u32 net_id = (peer_net) ? peer_net->lpn_net_id :
			LNET_NIDNET(dst_nid);
		CDEBUG(D_NET, "no peer_ni found on peer net %s\n",
				libcfs_net2str(net_id));
		return NULL;
	}

	CDEBUG(D_NET, "sd_best_lpni = %s\n",
	       libcfs_nid2str(best_lpni->lpni_nid));

	return best_lpni;
}

/*
 * Prerequisite: the best_ni should already be set in the sd
 */
static inline struct lnet_peer_ni *
lnet_find_best_lpni_on_net(struct lnet_send_data *sd, struct lnet_peer *peer,
			   __u32 net_id)
{
	struct lnet_peer_net *peer_net;

	/*
	 * The gateway is Multi-Rail capable so now we must select the
	 * proper peer_ni
	 */
	peer_net = lnet_peer_get_net_locked(peer, net_id);

	if (!peer_net) {
		CERROR("gateway peer %s has no NI on net %s\n",
		       libcfs_nid2str(peer->lp_primary_nid),
		       libcfs_net2str(net_id));
		return NULL;
	}

	return lnet_select_peer_ni(sd, peer, peer_net);
}

static inline void
lnet_set_non_mr_pref_nid(struct lnet_send_data *sd)
{
	if (sd->sd_send_case & NMR_DST &&
	    sd->sd_msg->msg_type != LNET_MSG_REPLY &&
	    sd->sd_msg->msg_type != LNET_MSG_ACK &&
	    sd->sd_best_lpni->lpni_pref_nnids == 0) {
		CDEBUG(D_NET, "Setting preferred local NID %s on NMR peer %s\n",
		       libcfs_nid2str(sd->sd_best_ni->ni_nid),
		       libcfs_nid2str(sd->sd_best_lpni->lpni_nid));
		lnet_peer_ni_set_non_mr_pref_nid(sd->sd_best_lpni,
						 sd->sd_best_ni->ni_nid);
	}
}

/*
 * Source Specified
 * Local Destination
 * non-mr peer
 *
 * use the source and destination NIDs as the pathway
 */
static int
lnet_handle_spec_local_nmr_dst(struct lnet_send_data *sd)
{
	/* the destination lpni is set before we get here. */

	/* find local NI */
	sd->sd_best_ni = lnet_nid2ni_locked(sd->sd_src_nid, sd->sd_cpt);
	if (!sd->sd_best_ni) {
		CERROR("Can't send to %s: src %s is not a "
		       "local nid\n", libcfs_nid2str(sd->sd_dst_nid),
				libcfs_nid2str(sd->sd_src_nid));
		return -EINVAL;
	}

	/*
	 * the preferred NID will only be set for NMR peers
	 */
	lnet_set_non_mr_pref_nid(sd);

	return lnet_handle_send(sd);
}

/*
 * Source Specified
 * Local Destination
 * MR Peer
 *
 * Don't run the selection algorithm on the peer NIs. By specifying the
 * local NID, we're also saying that we should always use the destination NID
 * provided. This handles the case where we should be using the same
 * destination NID for the all the messages which belong to the same RPC
 * request.
 */
static int
lnet_handle_spec_local_mr_dst(struct lnet_send_data *sd)
{
	sd->sd_best_ni = lnet_nid2ni_locked(sd->sd_src_nid, sd->sd_cpt);
	if (!sd->sd_best_ni) {
		CERROR("Can't send to %s: src %s is not a "
		       "local nid\n", libcfs_nid2str(sd->sd_dst_nid),
				libcfs_nid2str(sd->sd_src_nid));
		return -EINVAL;
	}

	if (sd->sd_best_lpni &&
	    sd->sd_best_lpni->lpni_nid == the_lnet.ln_loni->ni_nid)
		return lnet_handle_lo_send(sd);
	else if (sd->sd_best_lpni)
		return lnet_handle_send(sd);

	CERROR("can't send to %s. no NI on %s\n",
	       libcfs_nid2str(sd->sd_dst_nid),
	       libcfs_net2str(sd->sd_best_ni->ni_net->net_id));

	return -EHOSTUNREACH;
}

struct lnet_ni *
lnet_find_best_ni_on_spec_net(struct lnet_ni *cur_best_ni,
			      struct lnet_peer *peer,
			      struct lnet_peer_net *peer_net,
			      int cpt,
			      bool incr_seq)
{
	struct lnet_net *local_net;
	struct lnet_ni *best_ni;

	local_net = lnet_get_net_locked(peer_net->lpn_net_id);
	if (!local_net)
		return NULL;

	/*
	 * Iterate through the NIs in this local Net and select
	 * the NI to send from. The selection is determined by
	 * these 3 criterion in the following priority:
	 *	1. NUMA
	 *	2. NI available credits
	 *	3. Round Robin
	 */
	best_ni = lnet_get_best_ni(local_net, cur_best_ni,
				   peer, peer_net, cpt);

	if (incr_seq && best_ni)
		best_ni->ni_seq++;

	return best_ni;
}

static int
lnet_handle_find_routed_path(struct lnet_send_data *sd,
			     lnet_nid_t dst_nid,
			     struct lnet_peer_ni **gw_lpni,
			     struct lnet_peer **gw_peer)
{
	struct lnet_peer_ni *gw;
	lnet_nid_t src_nid = sd->sd_src_nid;

	gw = lnet_find_route_locked(NULL, LNET_NIDNET(dst_nid),
				    sd->sd_rtr_nid);
	if (!gw) {
		CERROR("no route to %s from %s\n",
		       libcfs_nid2str(dst_nid), libcfs_nid2str(src_nid));
		return -EHOSTUNREACH;
	}

	/* get the peer of the gw_ni */
	LASSERT(gw->lpni_peer_net);
	LASSERT(gw->lpni_peer_net->lpn_peer);

	*gw_peer = gw->lpni_peer_net->lpn_peer;

	if (!sd->sd_best_ni)
		sd->sd_best_ni = lnet_find_best_ni_on_spec_net(NULL, *gw_peer,
					gw->lpni_peer_net,
					sd->sd_md_cpt,
					true);

	if (!sd->sd_best_ni) {
		CERROR("Internal Error. Expected local ni on %s "
		       "but non found :%s\n",
		       libcfs_net2str(gw->lpni_peer_net->lpn_net_id),
		       libcfs_nid2str(sd->sd_src_nid));
		return -EFAULT;
	}

	/*
	 * if gw is MR let's find its best peer_ni
	 */
	if (lnet_peer_is_multi_rail(*gw_peer)) {
		gw = lnet_find_best_lpni_on_net(sd, *gw_peer,
						sd->sd_best_ni->ni_net->net_id);
		/*
		 * We've already verified that the gw has an NI on that
		 * desired net, but we're not finding it. Something is
		 * wrong.
		 */
		if (!gw) {
			CERROR("Internal Error. Route expected to %s from %s\n",
				libcfs_nid2str(dst_nid),
				libcfs_nid2str(src_nid));
			return -EFAULT;
		}
	}

	*gw_lpni = gw;

	return 0;
}

/*
 * Handle two cases:
 *
 * Case 1:
 *  Source specified
 *  Remote destination
 *  Non-MR destination
 *
 * Case 2:
 *  Source specified
 *  Remote destination
 *  MR destination
 *
 * The handling of these two cases is similar. Even though the destination
 * can be MR or non-MR, we'll deal directly with the router.
 */
static int
lnet_handle_spec_router_dst(struct lnet_send_data *sd)
{
	int rc;
	struct lnet_peer_ni *gw_lpni = NULL;
	struct lnet_peer *gw_peer = NULL;

	/* find local NI */
	sd->sd_best_ni = lnet_nid2ni_locked(sd->sd_src_nid, sd->sd_cpt);
	if (!sd->sd_best_ni) {
		CERROR("Can't send to %s: src %s is not a "
		       "local nid\n", libcfs_nid2str(sd->sd_dst_nid),
				libcfs_nid2str(sd->sd_src_nid));
		return -EINVAL;
	}

	rc = lnet_handle_find_routed_path(sd, sd->sd_dst_nid, &gw_lpni,
				     &gw_peer);
	if (rc < 0)
		return rc;

	if (sd->sd_send_case & NMR_DST)
		/*
		* since the final destination is non-MR let's set its preferred
		* NID before we send
		*/
		lnet_set_non_mr_pref_nid(sd);

	/*
	 * We're going to send to the gw found so let's set its
	 * info
	 */
	sd->sd_peer = gw_peer;
	sd->sd_best_lpni = gw_lpni;

	return lnet_handle_send(sd);
}

struct lnet_ni *
lnet_find_best_ni_on_local_net(struct lnet_peer *peer, int md_cpt)
{
	struct lnet_peer_net *peer_net = NULL;
	struct lnet_ni *best_ni = NULL;

	/*
	 * The peer can have multiple interfaces, some of them can be on
	 * the local network and others on a routed network. We should
	 * prefer the local network. However if the local network is not
	 * available then we need to try the routed network
	 */

	/* go through all the peer nets and find the best_ni */
	list_for_each_entry(peer_net, &peer->lp_peer_nets, lpn_peer_nets) {
		/*
		 * The peer's list of nets can contain non-local nets. We
		 * want to only examine the local ones.
		 */
		if (!lnet_get_net_locked(peer_net->lpn_net_id))
			continue;
		best_ni = lnet_find_best_ni_on_spec_net(best_ni, peer,
						   peer_net, md_cpt, false);
	}

	if (best_ni)
		/* increment sequence number so we can round robin */
		best_ni->ni_seq++;

	return best_ni;
}

static struct lnet_ni *
lnet_find_existing_preferred_best_ni(struct lnet_send_data *sd)
{
	struct lnet_ni *best_ni = NULL;
	struct lnet_peer_net *peer_net;
	struct lnet_peer *peer = sd->sd_peer;
	struct lnet_peer_ni *best_lpni = sd->sd_best_lpni;
	struct lnet_peer_ni *lpni;
	int cpt = sd->sd_cpt;

	/*
	 * We must use a consistent source address when sending to a
	 * non-MR peer. However, a non-MR peer can have multiple NIDs
	 * on multiple networks, and we may even need to talk to this
	 * peer on multiple networks -- certain types of
	 * load-balancing configuration do this.
	 *
	 * So we need to pick the NI the peer prefers for this
	 * particular network.
	 */

	/* Get the target peer_ni */
	peer_net = lnet_peer_get_net_locked(peer,
			LNET_NIDNET(best_lpni->lpni_nid));
	LASSERT(peer_net != NULL);
	list_for_each_entry(lpni, &peer_net->lpn_peer_nis,
				lpni_peer_nis) {
		if (lpni->lpni_pref_nnids == 0)
			continue;
		LASSERT(lpni->lpni_pref_nnids == 1);
		best_ni = lnet_nid2ni_locked(
				lpni->lpni_pref.nid, cpt);
		break;
	}

	return best_ni;
}

/* Prerequisite: sd->sd_peer and sd->sd_best_lpni should be set */
static int
lnet_select_preferred_best_ni(struct lnet_send_data *sd)
{
	struct lnet_ni *best_ni = NULL;
	struct lnet_peer_ni *best_lpni = sd->sd_best_lpni;

	/*
	 * We must use a consistent source address when sending to a
	 * non-MR peer. However, a non-MR peer can have multiple NIDs
	 * on multiple networks, and we may even need to talk to this
	 * peer on multiple networks -- certain types of
	 * load-balancing configuration do this.
	 *
	 * So we need to pick the NI the peer prefers for this
	 * particular network.
	 */

	best_ni = lnet_find_existing_preferred_best_ni(sd);

	/* if best_ni is still not set just pick one */
	if (!best_ni) {
		best_ni =
		  lnet_find_best_ni_on_spec_net(NULL, sd->sd_peer,
						sd->sd_best_lpni->lpni_peer_net,
						sd->sd_md_cpt, true);
		/* If there is no best_ni we don't have a route */
		if (!best_ni) {
			CERROR("no path to %s from net %s\n",
				libcfs_nid2str(best_lpni->lpni_nid),
				libcfs_net2str(best_lpni->lpni_net->net_id));
			return -EHOSTUNREACH;
		}
	}

	sd->sd_best_ni = best_ni;

	/* Set preferred NI if necessary. */
	lnet_set_non_mr_pref_nid(sd);

	return 0;
}


/*
 * Source not specified
 * Local destination
 * Non-MR Peer
 *
 * always use the same source NID for NMR peers
 * If we've talked to that peer before then we already have a preferred
 * source NI associated with it. Otherwise, we select a preferred local NI
 * and store it in the peer
 */
static int
lnet_handle_any_local_nmr_dst(struct lnet_send_data *sd)
{
	int rc;

	/* sd->sd_best_lpni is already set to the final destination */

	/*
	 * At this point we should've created the peer ni and peer. If we
	 * can't find it, then something went wrong. Instead of assert
	 * output a relevant message and fail the send
	 */
	if (!sd->sd_best_lpni) {
		CERROR("Internal fault. Unable to send msg %s to %s. "
		       "NID not known\n",
		       lnet_msgtyp2str(sd->sd_msg->msg_type),
		       libcfs_nid2str(sd->sd_dst_nid));
		return -EFAULT;
	}

	rc = lnet_select_preferred_best_ni(sd);
	if (!rc)
		rc = lnet_handle_send(sd);

	return rc;
}

static int
lnet_handle_any_mr_dsta(struct lnet_send_data *sd)
{
	/*
	 * NOTE we've already handled the remote peer case. So we only
	 * need to worry about the local case here.
	 *
	 * if we're sending a response, ACK or reply, we need to send it
	 * to the destination NID given to us. At this point we already
	 * have the peer_ni we're suppose to send to, so just find the
	 * best_ni on the peer net and use that. Since we're sending to an
	 * MR peer then we can just run the selection algorithm on our
	 * local NIs and pick the best one.
	 */
	if (sd->sd_send_case & SND_RESP) {
		sd->sd_best_ni =
		  lnet_find_best_ni_on_spec_net(NULL, sd->sd_peer,
						sd->sd_best_lpni->lpni_peer_net,
						sd->sd_md_cpt, true);

		if (!sd->sd_best_ni) {
			/*
			 * We're not going to deal with not able to send
			 * a response to the provided final destination
			 */
			CERROR("Can't send response to %s. "
			       "No local NI available\n",
				libcfs_nid2str(sd->sd_dst_nid));
			return -EHOSTUNREACH;
		}

		return lnet_handle_send(sd);
	}

	/*
	 * If we get here that means we're sending a fresh request, PUT or
	 * GET, so we need to run our standard selection algorithm.
	 * First find the best local interface that's on any of the peer's
	 * networks.
	 */
	sd->sd_best_ni = lnet_find_best_ni_on_local_net(sd->sd_peer,
							sd->sd_md_cpt);
	if (sd->sd_best_ni) {
		sd->sd_best_lpni =
		  lnet_find_best_lpni_on_net(sd, sd->sd_peer,
					     sd->sd_best_ni->ni_net->net_id);

		/*
		 * if we're successful in selecting a peer_ni on the local
		 * network, then send to it. Otherwise fall through and
		 * try and see if we can reach it over another routed
		 * network
		 */
		if (sd->sd_best_lpni &&
		    sd->sd_best_lpni->lpni_nid == the_lnet.ln_loni->ni_nid) {
			/*
			 * in case we initially started with a routed
			 * destination, let's reset to local
			 */
			sd->sd_send_case &= ~REMOTE_DST;
			sd->sd_send_case |= LOCAL_DST;
			return lnet_handle_lo_send(sd);
		} else if (sd->sd_best_lpni) {
			/*
			 * in case we initially started with a routed
			 * destination, let's reset to local
			 */
			sd->sd_send_case &= ~REMOTE_DST;
			sd->sd_send_case |= LOCAL_DST;
			return lnet_handle_send(sd);
		}

		CERROR("Internal Error. Expected to have a best_lpni: "
		       "%s -> %s\n",
		       libcfs_nid2str(sd->sd_src_nid),
		       libcfs_nid2str(sd->sd_dst_nid));

		return -EFAULT;
	}

	/*
	 * Peer doesn't have a local network. Let's see if there is
	 * a remote network we can reach it on.
	 */
	return PASS_THROUGH;
}

/*
 * Case 1:
 *	Source NID not specified
 *	Local destination
 *	MR peer
 *
 * Case 2:
 *	Source NID not speified
 *	Remote destination
 *	MR peer
 *
 * In both of these cases if we're sending a response, ACK or REPLY, then
 * we need to send to the destination NID provided.
 *
 * In the remote case let's deal with MR routers.
 *
 */

static int
lnet_handle_any_mr_dst(struct lnet_send_data *sd)
{
	int rc = 0;
	struct lnet_peer *gw_peer = NULL;
	struct lnet_peer_ni *gw_lpni = NULL;

	/*
	 * handle sending a response to a remote peer here so we don't
	 * have to worry about it if we hit lnet_handle_any_mr_dsta()
	 */
	if (sd->sd_send_case & REMOTE_DST &&
	    sd->sd_send_case & SND_RESP) {
		struct lnet_peer_ni *gw;
		struct lnet_peer *gw_peer;

		rc = lnet_handle_find_routed_path(sd, sd->sd_dst_nid, &gw,
						  &gw_peer);
		if (rc < 0) {
			CERROR("Can't send response to %s. "
			       "No route available\n",
				libcfs_nid2str(sd->sd_dst_nid));
			return -EHOSTUNREACH;
		}

		sd->sd_best_lpni = gw;
		sd->sd_peer = gw_peer;

		return lnet_handle_send(sd);
	}

	/*
	 * Even though the NID for the peer might not be on a local network,
	 * since the peer is MR there could be other interfaces on the
	 * local network. In that case we'd still like to prefer the local
	 * network over the routed network. If we're unable to do that
	 * then we select the best router among the different routed networks,
	 * and if the router is MR then we can deal with it as such.
	 */
	rc = lnet_handle_any_mr_dsta(sd);
	if (rc != PASS_THROUGH)
		return rc;

	/*
	 * TODO; One possible enhancement is to run the selection
	 * algorithm on the peer. However for remote peers the credits are
	 * not decremented, so we'll be basically going over the peer NIs
	 * in round robin. An MR router will run the selection algorithm
	 * on the next-hop interfaces.
	 */
	rc = lnet_handle_find_routed_path(sd, sd->sd_dst_nid, &gw_lpni,
					  &gw_peer);
	if (rc < 0)
		return rc;

	sd->sd_send_case &= ~LOCAL_DST;
	sd->sd_send_case |= REMOTE_DST;

	sd->sd_peer = gw_peer;
	sd->sd_best_lpni = gw_lpni;

	return lnet_handle_send(sd);
}

/*
 * Source not specified
 * Remote destination
 * Non-MR peer
 *
 * Must send to the specified peer NID using the same source NID that
 * we've used before. If it's the first time to talk to that peer then
 * find the source NI and assign it as preferred to that peer
 */
static int
lnet_handle_any_router_nmr_dst(struct lnet_send_data *sd)
{
	int rc;
	struct lnet_peer_ni *gw_lpni = NULL;
	struct lnet_peer *gw_peer = NULL;

	/*
	 * Let's set if we have a preferred NI to talk to this NMR peer
	 */
	sd->sd_best_ni = lnet_find_existing_preferred_best_ni(sd);

	/*
	 * find the router and that'll find the best NI if we didn't find
	 * it already.
	 */
	rc = lnet_handle_find_routed_path(sd, sd->sd_dst_nid, &gw_lpni,
					  &gw_peer);
	if (rc < 0)
		return rc;

	/*
	 * set the best_ni we've chosen as the preferred one for
	 * this peer
	 */
	lnet_set_non_mr_pref_nid(sd);

	/* we'll be sending to the gw */
	sd->sd_best_lpni = gw_lpni;
	sd->sd_peer = gw_peer;

	return lnet_handle_send(sd);
}

static int
lnet_handle_send_case_locked(struct lnet_send_data *sd)
{
	/*
	 * turn off the SND_RESP bit.
	 * It will be checked in the case handling
	 */
	__u32 send_case = sd->sd_send_case &= ~SND_RESP ;

	CDEBUG(D_NET, "Source %s%s to %s %s %s destination\n",
		(send_case & SRC_SPEC) ? "Specified: " : "ANY",
		(send_case & SRC_SPEC) ? libcfs_nid2str(sd->sd_src_nid) : "",
		(send_case & MR_DST) ? "MR: " : "NMR: ",
		libcfs_nid2str(sd->sd_dst_nid),
		(send_case & LOCAL_DST) ? "local" : "routed");

	switch (send_case) {
	/*
	 * For all cases where the source is specified, we should always
	 * use the destination NID, whether it's an MR destination or not,
	 * since we're continuing a series of related messages for the
	 * same RPC
	 */
	case SRC_SPEC_LOCAL_NMR_DST:
		return lnet_handle_spec_local_nmr_dst(sd);
	case SRC_SPEC_LOCAL_MR_DST:
		return lnet_handle_spec_local_mr_dst(sd);
	case SRC_SPEC_ROUTER_NMR_DST:
	case SRC_SPEC_ROUTER_MR_DST:
		return lnet_handle_spec_router_dst(sd);
	case SRC_ANY_LOCAL_NMR_DST:
		return lnet_handle_any_local_nmr_dst(sd);
	case SRC_ANY_LOCAL_MR_DST:
	case SRC_ANY_ROUTER_MR_DST:
		return lnet_handle_any_mr_dst(sd);
	case SRC_ANY_ROUTER_NMR_DST:
		return lnet_handle_any_router_nmr_dst(sd);
	default:
		CERROR("Unknown send case\n");
		return -1;
	}
}

static int
lnet_select_pathway(lnet_nid_t src_nid, lnet_nid_t dst_nid,
		    struct lnet_msg *msg, lnet_nid_t rtr_nid)
{
	struct lnet_peer_ni *lpni;
	struct lnet_peer *peer;
	struct lnet_send_data send_data;
	int cpt, rc;
	int md_cpt;
	__u32 send_case = 0;

	memset(&send_data, 0, sizeof(send_data));

	/*
	 * get an initial CPT to use for locking. The idea here is not to
	 * serialize the calls to select_pathway, so that as many
	 * operations can run concurrently as possible. To do that we use
	 * the CPT where this call is being executed. Later on when we
	 * determine the CPT to use in lnet_message_commit, we switch the
	 * lock and check if there was any configuration change.  If none,
	 * then we proceed, if there is, then we restart the operation.
	 */
	cpt = lnet_net_lock_current();

	md_cpt = lnet_cpt_of_md(msg->msg_md, msg->msg_offset);
	if (md_cpt == CFS_CPT_ANY)
		md_cpt = cpt;

again:

	/*
	 * If we're being asked to send to the loopback interface, there
	 * is no need to go through any selection. We can just shortcut
	 * the entire process and send over lolnd
	 */
	send_data.sd_msg = msg;
	send_data.sd_cpt = cpt;
	if (dst_nid == LNET_NID_LO_0) {
		rc = lnet_handle_lo_send(&send_data);
		lnet_net_unlock(cpt);
		return rc;
	}

	/*
	 * find an existing peer_ni, or create one and mark it as having been
	 * created due to network traffic. This call will create the
	 * peer->peer_net->peer_ni tree.
	 */
	lpni = lnet_nid2peerni_locked(dst_nid, LNET_NID_ANY, cpt);
	if (IS_ERR(lpni)) {
		lnet_net_unlock(cpt);
		return PTR_ERR(lpni);
	}

	/*
	 * Cache the original src_nid. If we need to resend the message
	 * then we'll need to know whether the src_nid was originally
	 * specified for this message. If it was originally specified,
	 * then we need to keep using the same src_nid since it's
	 * continuing the same sequence of messages.
	 */
	msg->msg_src_nid_param = src_nid;

	/*
	 * If necessary, perform discovery on the peer that owns this peer_ni.
	 * Note, this can result in the ownership of this peer_ni changing
	 * to another peer object.
	 */
	peer = lpni->lpni_peer_net->lpn_peer;
	if (lnet_msg_discovery(msg) && !lnet_peer_is_uptodate(peer)) {
		lnet_nid_t primary_nid;
		rc = lnet_discover_peer_locked(lpni, cpt, false);
		if (rc) {
			lnet_peer_ni_decref_locked(lpni);
			lnet_net_unlock(cpt);
			return rc;
		}
		/* The peer may have changed. */
		peer = lpni->lpni_peer_net->lpn_peer;
		spin_lock(&peer->lp_lock);
		if (!lnet_peer_is_uptodate_locked(peer)) {
			/* queue message and return */
			msg->msg_rtr_nid_param = rtr_nid;
			msg->msg_sending = 0;
			list_add_tail(&msg->msg_list, &peer->lp_dc_pendq);
			lnet_peer_ni_decref_locked(lpni);
			primary_nid = peer->lp_primary_nid;
			spin_unlock(&peer->lp_lock);
			lnet_net_unlock(cpt);

			CDEBUG(D_NET, "%s pending discovery\n",
			       libcfs_nid2str(primary_nid));

			return LNET_DC_WAIT;
		}
		spin_unlock(&peer->lp_lock);
	}
	lnet_peer_ni_decref_locked(lpni);

	/*
	 * Identify the different send cases
	 */
	if (src_nid == LNET_NID_ANY)
		send_case |= SRC_ANY;
	else
		send_case |= SRC_SPEC;

	if (lnet_get_net_locked(LNET_NIDNET(dst_nid)))
		send_case |= LOCAL_DST;
	else
		send_case |= REMOTE_DST;

	/*
	 * if this is a non-MR peer or if we're recovering a peer ni then
	 * let's consider this an NMR case so we can hit the destination
	 * NID.
	 */
	if (!lnet_peer_is_multi_rail(peer) || msg->msg_recovery)
		send_case |= NMR_DST;
	else
		send_case |= MR_DST;

	if (msg->msg_type == LNET_MSG_REPLY ||
	    msg->msg_type == LNET_MSG_ACK)
		send_case |= SND_RESP;

	/* assign parameters to the send_data */
	send_data.sd_rtr_nid = rtr_nid;
	send_data.sd_src_nid = src_nid;
	send_data.sd_dst_nid = dst_nid;
	send_data.sd_best_lpni = lpni;
	/*
	 * keep a pointer to the final destination in case we're going to
	 * route, so we'll need to access it later
	 */
	send_data.sd_final_dst_lpni = lpni;
	send_data.sd_peer = peer;
	send_data.sd_md_cpt = md_cpt;
	send_data.sd_send_case = send_case;

	rc = lnet_handle_send_case_locked(&send_data);

	/*
	 * Update the local cpt since send_data.sd_cpt might've been
	 * updated as a result of calling lnet_handle_send_case_locked().
	 */
	cpt = send_data.sd_cpt;

	if (rc == REPEAT_SEND)
		goto again;

	lnet_net_unlock(cpt);

	return rc;
}

int
lnet_send(lnet_nid_t src_nid, struct lnet_msg *msg, lnet_nid_t rtr_nid)
{
	lnet_nid_t		dst_nid = msg->msg_target.nid;
	int			rc;

	/*
	 * NB: rtr_nid is set to LNET_NID_ANY for all current use-cases,
	 * but we might want to use pre-determined router for ACK/REPLY
	 * in the future
	 */
	/* NB: ni != NULL == interface pre-determined (ACK/REPLY) */
	LASSERT(msg->msg_txpeer == NULL);
	LASSERT(msg->msg_txni == NULL);
	LASSERT(!msg->msg_sending);
	LASSERT(!msg->msg_target_is_router);
	LASSERT(!msg->msg_receiving);

	msg->msg_sending = 1;

	LASSERT(!msg->msg_tx_committed);

	rc = lnet_select_pathway(src_nid, dst_nid, msg, rtr_nid);
	if (rc < 0)
		return rc;

	if (rc == LNET_CREDIT_OK)
		lnet_ni_send(msg->msg_txni, msg);

	/* rc == LNET_CREDIT_OK or LNET_CREDIT_WAIT or LNET_DC_WAIT */
	return 0;
}

enum lnet_mt_event_type {
	MT_TYPE_LOCAL_NI = 0,
	MT_TYPE_PEER_NI
};

struct lnet_mt_event_info {
	enum lnet_mt_event_type mt_type;
	lnet_nid_t mt_nid;
};

/* called with res_lock held */
void
lnet_detach_rsp_tracker(struct lnet_libmd *md, int cpt)
{
	struct lnet_rsp_tracker *rspt;

	/*
	 * msg has a refcount on the MD so the MD is not going away.
	 * The rspt queue for the cpt is protected by
	 * the lnet_net_lock(cpt). cpt is the cpt of the MD cookie.
	 */
	if (!md->md_rspt_ptr)
		return;

	rspt = md->md_rspt_ptr;

	/* debug code */
	LASSERT(rspt->rspt_cpt == cpt);

	md->md_rspt_ptr = NULL;

	if (LNetMDHandleIsInvalid(rspt->rspt_mdh)) {
		/*
		 * The monitor thread has invalidated this handle because the
		 * response timed out, but it failed to lookup the MD. That
		 * means this response tracker is on the zombie list. We can
		 * safely remove it under the resource lock (held by caller) and
		 * free the response tracker block.
		 */
		list_del(&rspt->rspt_on_list);
		lnet_rspt_free(rspt, cpt);
	} else {
		/*
		 * invalidate the handle to indicate that a response has been
		 * received, which will then lead the monitor thread to clean up
		 * the rspt block.
		 */
		LNetInvalidateMDHandle(&rspt->rspt_mdh);
	}
}

void
lnet_clean_zombie_rstqs(void)
{
	struct lnet_rsp_tracker *rspt, *tmp;
	int i;

	cfs_cpt_for_each(i, lnet_cpt_table()) {
		list_for_each_entry_safe(rspt, tmp,
					 the_lnet.ln_mt_zombie_rstqs[i],
					 rspt_on_list) {
			list_del(&rspt->rspt_on_list);
			lnet_rspt_free(rspt, i);
		}
	}

	cfs_percpt_free(the_lnet.ln_mt_zombie_rstqs);
}

static void
lnet_finalize_expired_responses(void)
{
	struct lnet_libmd *md;
	struct list_head local_queue;
	struct lnet_rsp_tracker *rspt, *tmp;
	ktime_t now;
	int i;

	if (the_lnet.ln_mt_rstq == NULL)
		return;

	cfs_cpt_for_each(i, lnet_cpt_table()) {
		INIT_LIST_HEAD(&local_queue);

		lnet_net_lock(i);
		if (!the_lnet.ln_mt_rstq[i]) {
			lnet_net_unlock(i);
			continue;
		}
		list_splice_init(the_lnet.ln_mt_rstq[i], &local_queue);
		lnet_net_unlock(i);

		now = ktime_get();

		list_for_each_entry_safe(rspt, tmp, &local_queue, rspt_on_list) {
			/*
			 * The rspt mdh will be invalidated when a response
			 * is received or whenever we want to discard the
			 * block the monitor thread will walk the queue
			 * and clean up any rsts with an invalid mdh.
			 * The monitor thread will walk the queue until
			 * the first unexpired rspt block. This means that
			 * some rspt blocks which received their
			 * corresponding responses will linger in the
			 * queue until they are cleaned up eventually.
			 */
			lnet_res_lock(i);
			if (LNetMDHandleIsInvalid(rspt->rspt_mdh)) {
				lnet_res_unlock(i);
				list_del(&rspt->rspt_on_list);
				lnet_rspt_free(rspt, i);
				continue;
			}

			if (ktime_compare(now, rspt->rspt_deadline) >= 0 ||
			    the_lnet.ln_mt_state == LNET_MT_STATE_SHUTDOWN) {
				struct lnet_peer_ni *lpni;
				lnet_nid_t nid;

				md = lnet_handle2md(&rspt->rspt_mdh);
				if (!md) {
					/* MD has been queued for unlink, but
					 * rspt hasn't been detached (Note we've
					 * checked above that the rspt_mdh is
					 * valid). Since we cannot lookup the MD
					 * we're unable to detach the rspt
					 * ourselves. Thus, move the rspt to the
					 * zombie list where we'll wait for
					 * either:
					 *   1. The remaining operations on the
					 *   MD to complete. In this case the
					 *   final operation will result in
					 *   lnet_msg_detach_md()->
					 *   lnet_detach_rsp_tracker() where
					 *   we will clean up this response
					 *   tracker.
					 *   2. LNet to shutdown. In this case
					 *   we'll wait until after all LND Nets
					 *   have shutdown and then we can
					 *   safely free any remaining response
					 *   tracker blocks on the zombie list.
					 * Note: We need to hold the resource
					 * lock when adding to the zombie list
					 * because we may have concurrent access
					 * with lnet_detach_rsp_tracker().
					 */
					LNetInvalidateMDHandle(&rspt->rspt_mdh);
					list_move(&rspt->rspt_on_list,
						  the_lnet.ln_mt_zombie_rstqs[i]);
					lnet_res_unlock(i);
					continue;
				}
				LASSERT(md->md_rspt_ptr == rspt);
				md->md_rspt_ptr = NULL;
				lnet_res_unlock(i);

				LNetMDUnlink(rspt->rspt_mdh);

				nid = rspt->rspt_next_hop_nid;

				list_del(&rspt->rspt_on_list);
				lnet_rspt_free(rspt, i);

				/* If we're shutting down we just want to clean
				 * up the rspt blocks
				 */
				if (the_lnet.ln_mt_state == LNET_MT_STATE_SHUTDOWN)
					continue;

				lnet_net_lock(i);
				the_lnet.ln_counters[i]->lct_health.lch_response_timeout_count++;
				lnet_net_unlock(i);

				CDEBUG(D_NET,
				       "Response timeout: md = %p: nid = %s\n",
				       md, libcfs_nid2str(nid));

				/*
				 * If there is a timeout on the response
				 * from the next hop decrement its health
				 * value so that we don't use it
				 */
				lnet_net_lock(0);
				lpni = lnet_find_peer_ni_locked(nid);
				if (lpni) {
					lnet_handle_remote_failure_locked(lpni);
					lnet_peer_ni_decref_locked(lpni);
				}
				lnet_net_unlock(0);
			} else {
				lnet_res_unlock(i);
				break;
			}
		}

		if (!list_empty(&local_queue)) {
			lnet_net_lock(i);
			list_splice(&local_queue, the_lnet.ln_mt_rstq[i]);
			lnet_net_unlock(i);
		}
	}
}

static void
lnet_resend_pending_msgs_locked(struct list_head *resendq, int cpt)
{
	struct lnet_msg *msg;

	while (!list_empty(resendq)) {
		struct lnet_peer_ni *lpni;

		msg = list_entry(resendq->next, struct lnet_msg,
				 msg_list);

		list_del_init(&msg->msg_list);

		lpni = lnet_find_peer_ni_locked(msg->msg_hdr.dest_nid);
		if (!lpni) {
			lnet_net_unlock(cpt);
			CERROR("Expected that a peer is already created for %s\n",
			       libcfs_nid2str(msg->msg_hdr.dest_nid));
			msg->msg_no_resend = true;
			lnet_finalize(msg, -EFAULT);
			lnet_net_lock(cpt);
		} else {
			struct lnet_peer *peer;
			int rc;
			lnet_nid_t src_nid = LNET_NID_ANY;

			/*
			 * if this message is not being routed and the
			 * peer is non-MR then we must use the same
			 * src_nid that was used in the original send.
			 * Otherwise if we're routing the message (IE
			 * we're a router) then we can use any of our
			 * local interfaces. It doesn't matter to the
			 * final destination.
			 */
			peer = lpni->lpni_peer_net->lpn_peer;
			if (!msg->msg_routing &&
			    !lnet_peer_is_multi_rail(peer))
				src_nid = le64_to_cpu(msg->msg_hdr.src_nid);

			/*
			 * If we originally specified a src NID, then we
			 * must attempt to reuse it in the resend as well.
			 */
			if (msg->msg_src_nid_param != LNET_NID_ANY)
				src_nid = msg->msg_src_nid_param;
			lnet_peer_ni_decref_locked(lpni);

			lnet_net_unlock(cpt);
			CDEBUG(D_NET, "resending %s->%s: %s recovery %d try# %d\n",
			       libcfs_nid2str(src_nid),
			       libcfs_id2str(msg->msg_target),
			       lnet_msgtyp2str(msg->msg_type),
			       msg->msg_recovery,
			       msg->msg_retry_count);
			rc = lnet_send(src_nid, msg, LNET_NID_ANY);
			if (rc) {
				CERROR("Error sending %s to %s: %d\n",
				       lnet_msgtyp2str(msg->msg_type),
				       libcfs_id2str(msg->msg_target), rc);
				msg->msg_no_resend = true;
				lnet_finalize(msg, rc);
			}
			lnet_net_lock(cpt);
			if (!rc)
				the_lnet.ln_counters[cpt]->lct_health.lch_resend_count++;
		}
	}
}

static void
lnet_resend_pending_msgs(void)
{
	int i;

	cfs_cpt_for_each(i, lnet_cpt_table()) {
		lnet_net_lock(i);
		lnet_resend_pending_msgs_locked(the_lnet.ln_mt_resendqs[i], i);
		lnet_net_unlock(i);
	}
}

/* called with cpt and ni_lock held */
static void
lnet_unlink_ni_recovery_mdh_locked(struct lnet_ni *ni, int cpt, bool force)
{
	struct lnet_handle_md recovery_mdh;

	LNetInvalidateMDHandle(&recovery_mdh);

	if (ni->ni_recovery_state & LNET_NI_RECOVERY_PENDING ||
	    force) {
		recovery_mdh = ni->ni_ping_mdh;
		LNetInvalidateMDHandle(&ni->ni_ping_mdh);
	}
	lnet_ni_unlock(ni);
	lnet_net_unlock(cpt);
	if (!LNetMDHandleIsInvalid(recovery_mdh))
		LNetMDUnlink(recovery_mdh);
	lnet_net_lock(cpt);
	lnet_ni_lock(ni);
}

static void
lnet_recover_local_nis(void)
{
	struct lnet_mt_event_info *ev_info;
	struct list_head processed_list;
	struct list_head local_queue;
	struct lnet_handle_md mdh;
	struct lnet_ni *tmp;
	struct lnet_ni *ni;
	lnet_nid_t nid;
	int healthv;
	int rc;

	INIT_LIST_HEAD(&local_queue);
	INIT_LIST_HEAD(&processed_list);

	/*
	 * splice the recovery queue on a local queue. We will iterate
	 * through the local queue and update it as needed. Once we're
	 * done with the traversal, we'll splice the local queue back on
	 * the head of the ln_mt_localNIRecovq. Any newly added local NIs
	 * will be traversed in the next iteration.
	 */
	lnet_net_lock(0);
	list_splice_init(&the_lnet.ln_mt_localNIRecovq,
			 &local_queue);
	lnet_net_unlock(0);

	list_for_each_entry_safe(ni, tmp, &local_queue, ni_recovery) {
		/*
		 * if an NI is being deleted or it is now healthy, there
		 * is no need to keep it around in the recovery queue.
		 * The monitor thread is the only thread responsible for
		 * removing the NI from the recovery queue.
		 * Multiple threads can be adding NIs to the recovery
		 * queue.
		 */
		healthv = atomic_read(&ni->ni_healthv);

		lnet_net_lock(0);
		lnet_ni_lock(ni);
		if (ni->ni_state != LNET_NI_STATE_ACTIVE ||
		    healthv == LNET_MAX_HEALTH_VALUE) {
			list_del_init(&ni->ni_recovery);
			lnet_unlink_ni_recovery_mdh_locked(ni, 0, false);
			lnet_ni_unlock(ni);
			lnet_ni_decref_locked(ni, 0);
			lnet_net_unlock(0);
			continue;
		}

		/*
		 * if the local NI failed recovery we must unlink the md.
		 * But we want to keep the local_ni on the recovery queue
		 * so we can continue the attempts to recover it.
		 */
		if (ni->ni_recovery_state & LNET_NI_RECOVERY_FAILED) {
			lnet_unlink_ni_recovery_mdh_locked(ni, 0, true);
			ni->ni_recovery_state &= ~LNET_NI_RECOVERY_FAILED;
		}

		lnet_ni_unlock(ni);
		lnet_net_unlock(0);


		CDEBUG(D_NET, "attempting to recover local ni: %s\n",
		       libcfs_nid2str(ni->ni_nid));

		lnet_ni_lock(ni);
		if (!(ni->ni_recovery_state & LNET_NI_RECOVERY_PENDING)) {
			ni->ni_recovery_state |= LNET_NI_RECOVERY_PENDING;
			lnet_ni_unlock(ni);

			LIBCFS_ALLOC(ev_info, sizeof(*ev_info));
			if (!ev_info) {
				CERROR("out of memory. Can't recover %s\n",
				       libcfs_nid2str(ni->ni_nid));
				lnet_ni_lock(ni);
				ni->ni_recovery_state &=
				  ~LNET_NI_RECOVERY_PENDING;
				lnet_ni_unlock(ni);
				continue;
			}

			mdh = ni->ni_ping_mdh;
			/*
			 * Invalidate the ni mdh in case it's deleted.
			 * We'll unlink the mdh in this case below.
			 */
			LNetInvalidateMDHandle(&ni->ni_ping_mdh);
			nid = ni->ni_nid;

			/*
			 * remove the NI from the local queue and drop the
			 * reference count to it while we're recovering
			 * it. The reason for that, is that the NI could
			 * be deleted, and the way the code is structured
			 * is if we don't drop the NI, then the deletion
			 * code will enter a loop waiting for the
			 * reference count to be removed while holding the
			 * ln_mutex_lock(). When we look up the peer to
			 * send to in lnet_select_pathway() we will try to
			 * lock the ln_mutex_lock() as well, leading to
			 * a deadlock. By dropping the refcount and
			 * removing it from the list, we allow for the NI
			 * to be removed, then we use the cached NID to
			 * look it up again. If it's gone, then we just
			 * continue examining the rest of the queue.
			 */
			lnet_net_lock(0);
			list_del_init(&ni->ni_recovery);
			lnet_ni_decref_locked(ni, 0);
			lnet_net_unlock(0);

			ev_info->mt_type = MT_TYPE_LOCAL_NI;
			ev_info->mt_nid = nid;
			rc = lnet_send_ping(nid, &mdh, LNET_INTERFACES_MIN,
					    ev_info, the_lnet.ln_mt_eqh, true);
			/* lookup the nid again */
			lnet_net_lock(0);
			ni = lnet_nid2ni_locked(nid, 0);
			if (!ni) {
				/*
				 * the NI has been deleted when we dropped
				 * the ref count
				 */
				lnet_net_unlock(0);
				LNetMDUnlink(mdh);
				continue;
			}
			/*
			 * Same note as in lnet_recover_peer_nis(). When
			 * we're sending the ping, the NI is free to be
			 * deleted or manipulated. By this point it
			 * could've been added back on the recovery queue,
			 * and a refcount taken on it.
			 * So we can't just add it blindly again or we'll
			 * corrupt the queue. We must check under lock if
			 * it's not on any list and if not then add it
			 * to the processed list, which will eventually be
			 * spliced back on to the recovery queue.
			 */
			ni->ni_ping_mdh = mdh;
			if (list_empty(&ni->ni_recovery)) {
				list_add_tail(&ni->ni_recovery, &processed_list);
				lnet_ni_addref_locked(ni, 0);
			}
			lnet_net_unlock(0);

			lnet_ni_lock(ni);
			if (rc)
				ni->ni_recovery_state &= ~LNET_NI_RECOVERY_PENDING;
		}
		lnet_ni_unlock(ni);
	}

	/*
	 * put back the remaining NIs on the ln_mt_localNIRecovq to be
	 * reexamined in the next iteration.
	 */
	list_splice_init(&processed_list, &local_queue);
	lnet_net_lock(0);
	list_splice(&local_queue, &the_lnet.ln_mt_localNIRecovq);
	lnet_net_unlock(0);
}

static int
lnet_resendqs_create(void)
{
	struct list_head **resendqs;
	resendqs = lnet_create_array_of_queues();

	if (!resendqs)
		return -ENOMEM;

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_mt_resendqs = resendqs;
	lnet_net_unlock(LNET_LOCK_EX);

	return 0;
}

static void
lnet_clean_local_ni_recoveryq(void)
{
	struct lnet_ni *ni;

	/* This is only called when the monitor thread has stopped */
	lnet_net_lock(0);

	while (!list_empty(&the_lnet.ln_mt_localNIRecovq)) {
		ni = list_entry(the_lnet.ln_mt_localNIRecovq.next,
				struct lnet_ni, ni_recovery);
		list_del_init(&ni->ni_recovery);
		lnet_ni_lock(ni);
		lnet_unlink_ni_recovery_mdh_locked(ni, 0, true);
		lnet_ni_unlock(ni);
		lnet_ni_decref_locked(ni, 0);
	}

	lnet_net_unlock(0);
}

static void
lnet_unlink_lpni_recovery_mdh_locked(struct lnet_peer_ni *lpni, int cpt,
				     bool force)
{
	struct lnet_handle_md recovery_mdh;

	LNetInvalidateMDHandle(&recovery_mdh);

	if (lpni->lpni_state & LNET_PEER_NI_RECOVERY_PENDING || force) {
		recovery_mdh = lpni->lpni_recovery_ping_mdh;
		LNetInvalidateMDHandle(&lpni->lpni_recovery_ping_mdh);
	}
	spin_unlock(&lpni->lpni_lock);
	lnet_net_unlock(cpt);
	if (!LNetMDHandleIsInvalid(recovery_mdh))
		LNetMDUnlink(recovery_mdh);
	lnet_net_lock(cpt);
	spin_lock(&lpni->lpni_lock);
}

static void
lnet_clean_peer_ni_recoveryq(void)
{
	struct lnet_peer_ni *lpni, *tmp;

	lnet_net_lock(LNET_LOCK_EX);

	list_for_each_entry_safe(lpni, tmp, &the_lnet.ln_mt_peerNIRecovq,
				 lpni_recovery) {
		list_del_init(&lpni->lpni_recovery);
		spin_lock(&lpni->lpni_lock);
		lnet_unlink_lpni_recovery_mdh_locked(lpni, LNET_LOCK_EX, true);
		spin_unlock(&lpni->lpni_lock);
		lnet_peer_ni_decref_locked(lpni);
	}

	lnet_net_unlock(LNET_LOCK_EX);
}

static void
lnet_clean_resendqs(void)
{
	struct lnet_msg *msg, *tmp;
	struct list_head msgs;
	int i;

	INIT_LIST_HEAD(&msgs);

	cfs_cpt_for_each(i, lnet_cpt_table()) {
		lnet_net_lock(i);
		list_splice_init(the_lnet.ln_mt_resendqs[i], &msgs);
		lnet_net_unlock(i);
		list_for_each_entry_safe(msg, tmp, &msgs, msg_list) {
			list_del_init(&msg->msg_list);
			msg->msg_no_resend = true;
			lnet_finalize(msg, -ESHUTDOWN);
		}
	}

	cfs_percpt_free(the_lnet.ln_mt_resendqs);
}

static void
lnet_recover_peer_nis(void)
{
	struct lnet_mt_event_info *ev_info;
	struct list_head processed_list;
	struct list_head local_queue;
	struct lnet_handle_md mdh;
	struct lnet_peer_ni *lpni;
	struct lnet_peer_ni *tmp;
	lnet_nid_t nid;
	int healthv;
	int rc;

	INIT_LIST_HEAD(&local_queue);
	INIT_LIST_HEAD(&processed_list);

	/*
	 * Always use cpt 0 for locking across all interactions with
	 * ln_mt_peerNIRecovq
	 */
	lnet_net_lock(0);
	list_splice_init(&the_lnet.ln_mt_peerNIRecovq,
			 &local_queue);
	lnet_net_unlock(0);

	list_for_each_entry_safe(lpni, tmp, &local_queue,
				 lpni_recovery) {
		/*
		 * The same protection strategy is used here as is in the
		 * local recovery case.
		 */
		lnet_net_lock(0);
		healthv = atomic_read(&lpni->lpni_healthv);
		spin_lock(&lpni->lpni_lock);
		if (lpni->lpni_state & LNET_PEER_NI_DELETING ||
		    healthv == LNET_MAX_HEALTH_VALUE) {
			list_del_init(&lpni->lpni_recovery);
			lnet_unlink_lpni_recovery_mdh_locked(lpni, 0, false);
			spin_unlock(&lpni->lpni_lock);
			lnet_peer_ni_decref_locked(lpni);
			lnet_net_unlock(0);
			continue;
		}

		/*
		 * If the peer NI has failed recovery we must unlink the
		 * md. But we want to keep the peer ni on the recovery
		 * queue so we can try to continue recovering it
		 */
		if (lpni->lpni_state & LNET_PEER_NI_RECOVERY_FAILED) {
			lnet_unlink_lpni_recovery_mdh_locked(lpni, 0, true);
			lpni->lpni_state &= ~LNET_PEER_NI_RECOVERY_FAILED;
		}

		spin_unlock(&lpni->lpni_lock);
		lnet_net_unlock(0);

		/*
		 * NOTE: we're racing with peer deletion from user space.
		 * It's possible that a peer is deleted after we check its
		 * state. In this case the recovery can create a new peer
		 */
		spin_lock(&lpni->lpni_lock);
		if (!(lpni->lpni_state & LNET_PEER_NI_RECOVERY_PENDING) &&
		    !(lpni->lpni_state & LNET_PEER_NI_DELETING)) {
			lpni->lpni_state |= LNET_PEER_NI_RECOVERY_PENDING;
			spin_unlock(&lpni->lpni_lock);

			LIBCFS_ALLOC(ev_info, sizeof(*ev_info));
			if (!ev_info) {
				CERROR("out of memory. Can't recover %s\n",
				       libcfs_nid2str(lpni->lpni_nid));
				spin_lock(&lpni->lpni_lock);
				lpni->lpni_state &= ~LNET_PEER_NI_RECOVERY_PENDING;
				spin_unlock(&lpni->lpni_lock);
				continue;
			}

			/* look at the comments in lnet_recover_local_nis() */
			mdh = lpni->lpni_recovery_ping_mdh;
			LNetInvalidateMDHandle(&lpni->lpni_recovery_ping_mdh);
			nid = lpni->lpni_nid;
			lnet_net_lock(0);
			list_del_init(&lpni->lpni_recovery);
			lnet_peer_ni_decref_locked(lpni);
			lnet_net_unlock(0);

			ev_info->mt_type = MT_TYPE_PEER_NI;
			ev_info->mt_nid = nid;
			rc = lnet_send_ping(nid, &mdh, LNET_INTERFACES_MIN,
					    ev_info, the_lnet.ln_mt_eqh, true);
			lnet_net_lock(0);
			/*
			 * lnet_find_peer_ni_locked() grabs a refcount for
			 * us. No need to take it explicitly.
			 */
			lpni = lnet_find_peer_ni_locked(nid);
			if (!lpni) {
				lnet_net_unlock(0);
				LNetMDUnlink(mdh);
				continue;
			}

			lpni->lpni_recovery_ping_mdh = mdh;
			/*
			 * While we're unlocked the lpni could've been
			 * readded on the recovery queue. In this case we
			 * don't need to add it to the local queue, since
			 * it's already on there and the thread that added
			 * it would've incremented the refcount on the
			 * peer, which means we need to decref the refcount
			 * that was implicitly grabbed by find_peer_ni_locked.
			 * Otherwise, if the lpni is still not on
			 * the recovery queue, then we'll add it to the
			 * processed list.
			 */
			if (list_empty(&lpni->lpni_recovery))
				list_add_tail(&lpni->lpni_recovery, &processed_list);
			else
				lnet_peer_ni_decref_locked(lpni);
			lnet_net_unlock(0);

			spin_lock(&lpni->lpni_lock);
			if (rc)
				lpni->lpni_state &= ~LNET_PEER_NI_RECOVERY_PENDING;
		}
		spin_unlock(&lpni->lpni_lock);
	}

	list_splice_init(&processed_list, &local_queue);
	lnet_net_lock(0);
	list_splice(&local_queue, &the_lnet.ln_mt_peerNIRecovq);
	lnet_net_unlock(0);
}

static int
lnet_monitor_thread(void *arg)
{
	time64_t recovery_timeout = 0;
	time64_t rsp_timeout = 0;
	int interval;
	time64_t now;

	/*
	 * The monitor thread takes care of the following:
	 *  1. Checks the aliveness of routers
	 *  2. Checks if there are messages on the resend queue to resend
	 *     them.
	 *  3. Check if there are any NIs on the local recovery queue and
	 *     pings them
	 *  4. Checks if there are any NIs on the remote recovery queue
	 *     and pings them.
	 */
	cfs_block_allsigs();

	while (the_lnet.ln_mt_state == LNET_MT_STATE_RUNNING) {
		now = ktime_get_real_seconds();

		if (lnet_router_checker_active())
			lnet_check_routers();

		lnet_resend_pending_msgs();

		if (now >= rsp_timeout) {
			lnet_finalize_expired_responses();
			rsp_timeout = now + (lnet_transaction_timeout / 2);
		}

		if (now >= recovery_timeout) {
			lnet_recover_local_nis();
			lnet_recover_peer_nis();
			recovery_timeout = now + lnet_recovery_interval;
		}

		/*
		 * TODO do we need to check if we should sleep without
		 * timeout?  Technically, an active system will always
		 * have messages in flight so this check will always
		 * evaluate to false. And on an idle system do we care
		 * if we wake up every 1 second? Although, we've seen
		 * cases where we get a complaint that an idle thread
		 * is waking up unnecessarily.
		 */
		interval = min(lnet_recovery_interval,
			       lnet_transaction_timeout / 2);
		wait_event_interruptible_timeout(the_lnet.ln_mt_waitq,
						false,
						cfs_time_seconds(interval));
	}

	/* clean up the router checker */
	lnet_prune_rc_data(1);

	/* Shutting down */
	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_mt_state = LNET_MT_STATE_SHUTDOWN;
	lnet_net_unlock(LNET_LOCK_EX);

	/* signal that the monitor thread is exiting */
	up(&the_lnet.ln_mt_signal);

	return 0;
}

/*
 * lnet_send_ping
 * Sends a ping.
 * Returns == 0 if success
 * Returns > 0 if LNetMDBind or prior fails
 * Returns < 0 if LNetGet fails
 */
int
lnet_send_ping(lnet_nid_t dest_nid,
	       struct lnet_handle_md *mdh, int nnis,
	       void *user_data, struct lnet_handle_eq eqh, bool recovery)
{
	struct lnet_md md = { NULL };
	struct lnet_process_id id;
	struct lnet_ping_buffer *pbuf;
	int rc;

	if (dest_nid == LNET_NID_ANY) {
		rc = -EHOSTUNREACH;
		goto fail_error;
	}

	pbuf = lnet_ping_buffer_alloc(nnis, GFP_NOFS);
	if (!pbuf) {
		rc = ENOMEM;
		goto fail_error;
	}

	/* initialize md content */
	md.start     = &pbuf->pb_info;
	md.length    = LNET_PING_INFO_SIZE(nnis);
	md.threshold = 2; /* GET/REPLY */
	md.max_size  = 0;
	md.options   = LNET_MD_TRUNCATE;
	md.user_ptr  = user_data;
	md.eq_handle = eqh;

	rc = LNetMDBind(md, LNET_UNLINK, mdh);
	if (rc) {
		lnet_ping_buffer_decref(pbuf);
		CERROR("Can't bind MD: %d\n", rc);
		rc = -rc; /* change the rc to positive */
		goto fail_error;
	}
	id.pid = LNET_PID_LUSTRE;
	id.nid = dest_nid;

	rc = LNetGet(LNET_NID_ANY, *mdh, id,
		     LNET_RESERVED_PORTAL,
		     LNET_PROTO_PING_MATCHBITS, 0, recovery);

	if (rc)
		goto fail_unlink_md;

	return 0;

fail_unlink_md:
	LNetMDUnlink(*mdh);
	LNetInvalidateMDHandle(mdh);
fail_error:
	return rc;
}

static void
lnet_handle_recovery_reply(struct lnet_mt_event_info *ev_info,
			   int status, bool unlink_event)
{
	lnet_nid_t nid = ev_info->mt_nid;

	if (ev_info->mt_type == MT_TYPE_LOCAL_NI) {
		struct lnet_ni *ni;

		lnet_net_lock(0);
		ni = lnet_nid2ni_locked(nid, 0);
		if (!ni) {
			lnet_net_unlock(0);
			return;
		}
		lnet_ni_lock(ni);
		ni->ni_recovery_state &= ~LNET_NI_RECOVERY_PENDING;
		if (status)
			ni->ni_recovery_state |= LNET_NI_RECOVERY_FAILED;
		lnet_ni_unlock(ni);
		lnet_net_unlock(0);

		if (status != 0) {
			CERROR("local NI (%s) recovery failed with %d\n",
			       libcfs_nid2str(nid), status);
			return;
		}
		/*
		 * need to increment healthv for the ni here, because in
		 * the lnet_finalize() path we don't have access to this
		 * NI. And in order to get access to it, we'll need to
		 * carry forward too much information.
		 * In the peer case, it'll naturally be incremented
		 */
		if (!unlink_event)
			lnet_inc_healthv(&ni->ni_healthv);
	} else {
		struct lnet_peer_ni *lpni;
		int cpt;

		cpt = lnet_net_lock_current();
		lpni = lnet_find_peer_ni_locked(nid);
		if (!lpni) {
			lnet_net_unlock(cpt);
			return;
		}
		spin_lock(&lpni->lpni_lock);
		lpni->lpni_state &= ~LNET_PEER_NI_RECOVERY_PENDING;
		if (status)
			lpni->lpni_state |= LNET_PEER_NI_RECOVERY_FAILED;
		spin_unlock(&lpni->lpni_lock);
		lnet_peer_ni_decref_locked(lpni);
		lnet_net_unlock(cpt);

		if (status != 0)
			CERROR("peer NI (%s) recovery failed with %d\n",
			       libcfs_nid2str(nid), status);
	}
}

void
lnet_mt_event_handler(struct lnet_event *event)
{
	struct lnet_mt_event_info *ev_info = event->md.user_ptr;
	struct lnet_ping_buffer *pbuf;

	/* TODO: remove assert */
	LASSERT(event->type == LNET_EVENT_REPLY ||
		event->type == LNET_EVENT_SEND ||
		event->type == LNET_EVENT_UNLINK);

	CDEBUG(D_NET, "Received event: %d status: %d\n", event->type,
	       event->status);

	switch (event->type) {
	case LNET_EVENT_UNLINK:
		CDEBUG(D_NET, "%s recovery ping unlinked\n",
		       libcfs_nid2str(ev_info->mt_nid));
	case LNET_EVENT_REPLY:
		lnet_handle_recovery_reply(ev_info, event->status,
					   event->type == LNET_EVENT_UNLINK);
		break;
	case LNET_EVENT_SEND:
		CDEBUG(D_NET, "%s recovery message sent %s:%d\n",
			       libcfs_nid2str(ev_info->mt_nid),
			       (event->status) ? "unsuccessfully" :
			       "successfully", event->status);
		break;
	default:
		CERROR("Unexpected event: %d\n", event->type);
		break;
	}
	if (event->unlinked) {
		LIBCFS_FREE(ev_info, sizeof(*ev_info));
		pbuf = LNET_PING_INFO_TO_BUFFER(event->md.start);
		lnet_ping_buffer_decref(pbuf);
	}
}

static int
lnet_rsp_tracker_create(void)
{
	struct list_head **rstqs;
	rstqs = lnet_create_array_of_queues();

	if (!rstqs)
		return -ENOMEM;

	the_lnet.ln_mt_rstq = rstqs;

	return 0;
}

static void
lnet_rsp_tracker_clean(void)
{
	lnet_finalize_expired_responses();

	cfs_percpt_free(the_lnet.ln_mt_rstq);
	the_lnet.ln_mt_rstq = NULL;
}

int lnet_monitor_thr_start(void)
{
	int rc = 0;
	struct task_struct *task;

	if (the_lnet.ln_mt_state != LNET_MT_STATE_SHUTDOWN)
		return -EALREADY;

	rc = lnet_resendqs_create();
	if (rc)
		return rc;

	rc = lnet_rsp_tracker_create();
	if (rc)
		goto clean_queues;

	/* Pre monitor thread start processing */
	rc = lnet_router_pre_mt_start();
	if (rc)
		goto free_mem;

	sema_init(&the_lnet.ln_mt_signal, 0);

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_mt_state = LNET_MT_STATE_RUNNING;
	lnet_net_unlock(LNET_LOCK_EX);
	task = kthread_run(lnet_monitor_thread, NULL, "monitor_thread");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("Can't start monitor thread: %d\n", rc);
		goto clean_thread;
	}

	/* post monitor thread start processing */
	lnet_router_post_mt_start();

	return 0;

clean_thread:
	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_mt_state = LNET_MT_STATE_STOPPING;
	lnet_net_unlock(LNET_LOCK_EX);
	/* block until event callback signals exit */
	down(&the_lnet.ln_mt_signal);
	/* clean up */
	lnet_router_cleanup();
free_mem:
	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_mt_state = LNET_MT_STATE_SHUTDOWN;
	lnet_net_unlock(LNET_LOCK_EX);
	lnet_rsp_tracker_clean();
	lnet_clean_local_ni_recoveryq();
	lnet_clean_peer_ni_recoveryq();
	lnet_clean_resendqs();
	LNetInvalidateEQHandle(&the_lnet.ln_mt_eqh);
	return rc;
clean_queues:
	lnet_rsp_tracker_clean();
	lnet_clean_local_ni_recoveryq();
	lnet_clean_peer_ni_recoveryq();
	lnet_clean_resendqs();
	return rc;
}

void lnet_monitor_thr_stop(void)
{
	if (the_lnet.ln_mt_state == LNET_MT_STATE_SHUTDOWN)
		return;

	LASSERT(the_lnet.ln_mt_state == LNET_MT_STATE_RUNNING);
	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_mt_state = LNET_MT_STATE_STOPPING;
	lnet_net_unlock(LNET_LOCK_EX);

	/* tell the monitor thread that we're shutting down */
	wake_up(&the_lnet.ln_mt_waitq);

	/* block until monitor thread signals that it's done */
	down(&the_lnet.ln_mt_signal);
	LASSERT(the_lnet.ln_mt_state == LNET_MT_STATE_SHUTDOWN);

	/* perform cleanup tasks */
	lnet_router_cleanup();
	lnet_rsp_tracker_clean();
	lnet_clean_local_ni_recoveryq();
	lnet_clean_peer_ni_recoveryq();
	lnet_clean_resendqs();

	return;
}

void
lnet_drop_message(struct lnet_ni *ni, int cpt, void *private, unsigned int nob,
		  __u32 msg_type)
{
	lnet_net_lock(cpt);
	lnet_incr_stats(&ni->ni_stats, msg_type, LNET_STATS_TYPE_DROP);
	the_lnet.ln_counters[cpt]->lct_common.lcc_drop_count++;
	the_lnet.ln_counters[cpt]->lct_common.lcc_drop_length += nob;
	lnet_net_unlock(cpt);

	lnet_ni_recv(ni, private, NULL, 0, 0, 0, nob);
}

static void
lnet_recv_put(struct lnet_ni *ni, struct lnet_msg *msg)
{
	struct lnet_hdr	*hdr = &msg->msg_hdr;

	if (msg->msg_wanted != 0)
		lnet_setpayloadbuffer(msg);

	lnet_build_msg_event(msg, LNET_EVENT_PUT);

	/* Must I ACK?	If so I'll grab the ack_wmd out of the header and put
	 * it back into the ACK during lnet_finalize() */
	msg->msg_ack = (!lnet_is_wire_handle_none(&hdr->msg.put.ack_wmd) &&
			(msg->msg_md->md_options & LNET_MD_ACK_DISABLE) == 0);

	lnet_ni_recv(ni, msg->msg_private, msg, msg->msg_rx_delayed,
		     msg->msg_offset, msg->msg_wanted, hdr->payload_length);
}

static int
lnet_parse_put(struct lnet_ni *ni, struct lnet_msg *msg)
{
	struct lnet_hdr		*hdr = &msg->msg_hdr;
	struct lnet_match_info	info;
	int			rc;
	bool			ready_delay;

	/* Convert put fields to host byte order */
	hdr->msg.put.match_bits	= le64_to_cpu(hdr->msg.put.match_bits);
	hdr->msg.put.ptl_index	= le32_to_cpu(hdr->msg.put.ptl_index);
	hdr->msg.put.offset	= le32_to_cpu(hdr->msg.put.offset);

	/* Primary peer NID. */
	info.mi_id.nid	= msg->msg_initiator;
	info.mi_id.pid	= hdr->src_pid;
	info.mi_opc	= LNET_MD_OP_PUT;
	info.mi_portal	= hdr->msg.put.ptl_index;
	info.mi_rlength	= hdr->payload_length;
	info.mi_roffset	= hdr->msg.put.offset;
	info.mi_mbits	= hdr->msg.put.match_bits;
	info.mi_cpt	= lnet_cpt_of_nid(msg->msg_rxpeer->lpni_nid, ni);

	msg->msg_rx_ready_delay = ni->ni_net->net_lnd->lnd_eager_recv == NULL;
	ready_delay = msg->msg_rx_ready_delay;

 again:
	rc = lnet_ptl_match_md(&info, msg);
	switch (rc) {
	default:
		LBUG();

	case LNET_MATCHMD_OK:
		lnet_recv_put(ni, msg);
		return 0;

	case LNET_MATCHMD_NONE:
		if (ready_delay)
			/* no eager_recv or has already called it, should
			 * have been attached on delayed list */
			return 0;

		rc = lnet_ni_eager_recv(ni, msg);
		if (rc == 0) {
			ready_delay = true;
			goto again;
		}
		/* fall through */

	case LNET_MATCHMD_DROP:
		CNETERR("Dropping PUT from %s portal %d match %llu"
			" offset %d length %d: %d\n",
			libcfs_id2str(info.mi_id), info.mi_portal,
			info.mi_mbits, info.mi_roffset, info.mi_rlength, rc);

		return -ENOENT;	/* -ve: OK but no match */
	}
}

static int
lnet_parse_get(struct lnet_ni *ni, struct lnet_msg *msg, int rdma_get)
{
	struct lnet_match_info info;
	struct lnet_hdr *hdr = &msg->msg_hdr;
	struct lnet_process_id source_id;
	struct lnet_handle_wire	reply_wmd;
	int rc;

	/* Convert get fields to host byte order */
	hdr->msg.get.match_bits	  = le64_to_cpu(hdr->msg.get.match_bits);
	hdr->msg.get.ptl_index	  = le32_to_cpu(hdr->msg.get.ptl_index);
	hdr->msg.get.sink_length  = le32_to_cpu(hdr->msg.get.sink_length);
	hdr->msg.get.src_offset	  = le32_to_cpu(hdr->msg.get.src_offset);

	source_id.nid = hdr->src_nid;
	source_id.pid = hdr->src_pid;
	/* Primary peer NID */
	info.mi_id.nid	= msg->msg_initiator;
	info.mi_id.pid	= hdr->src_pid;
	info.mi_opc	= LNET_MD_OP_GET;
	info.mi_portal	= hdr->msg.get.ptl_index;
	info.mi_rlength	= hdr->msg.get.sink_length;
	info.mi_roffset	= hdr->msg.get.src_offset;
	info.mi_mbits	= hdr->msg.get.match_bits;
	info.mi_cpt	= lnet_cpt_of_nid(msg->msg_rxpeer->lpni_nid, ni);

	rc = lnet_ptl_match_md(&info, msg);
	if (rc == LNET_MATCHMD_DROP) {
		CNETERR("Dropping GET from %s portal %d match %llu"
			" offset %d length %d\n",
			libcfs_id2str(info.mi_id), info.mi_portal,
			info.mi_mbits, info.mi_roffset, info.mi_rlength);
		return -ENOENT;	/* -ve: OK but no match */
	}

	LASSERT(rc == LNET_MATCHMD_OK);

	lnet_build_msg_event(msg, LNET_EVENT_GET);

	reply_wmd = hdr->msg.get.return_wmd;

	lnet_prep_send(msg, LNET_MSG_REPLY, source_id,
		       msg->msg_offset, msg->msg_wanted);

	msg->msg_hdr.msg.reply.dst_wmd = reply_wmd;

	if (rdma_get) {
		/* The LND completes the REPLY from her recv procedure */
		lnet_ni_recv(ni, msg->msg_private, msg, 0,
			     msg->msg_offset, msg->msg_len, msg->msg_len);
		return 0;
	}

	lnet_ni_recv(ni, msg->msg_private, NULL, 0, 0, 0, 0);
	msg->msg_receiving = 0;

	rc = lnet_send(ni->ni_nid, msg, LNET_NID_ANY);
	if (rc < 0) {
		/* didn't get as far as lnet_ni_send() */
		CERROR("%s: Unable to send REPLY for GET from %s: %d\n",
		       libcfs_nid2str(ni->ni_nid),
		       libcfs_id2str(info.mi_id), rc);

		lnet_finalize(msg, rc);
	}

	return 0;
}

static int
lnet_parse_reply(struct lnet_ni *ni, struct lnet_msg *msg)
{
	void *private = msg->msg_private;
	struct lnet_hdr *hdr = &msg->msg_hdr;
	struct lnet_process_id src = {0};
	struct lnet_libmd *md;
	int rlength;
	int mlength;
	int cpt;

	cpt = lnet_cpt_of_cookie(hdr->msg.reply.dst_wmd.wh_object_cookie);
	lnet_res_lock(cpt);

	src.nid = hdr->src_nid;
	src.pid = hdr->src_pid;

	/* NB handles only looked up by creator (no flips) */
	md = lnet_wire_handle2md(&hdr->msg.reply.dst_wmd);
	if (md == NULL || md->md_threshold == 0 || md->md_me != NULL) {
		CNETERR("%s: Dropping REPLY from %s for %s "
			"MD %#llx.%#llx\n",
			libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
			(md == NULL) ? "invalid" : "inactive",
			hdr->msg.reply.dst_wmd.wh_interface_cookie,
			hdr->msg.reply.dst_wmd.wh_object_cookie);
		if (md != NULL && md->md_me != NULL)
			CERROR("REPLY MD also attached to portal %d\n",
			       md->md_me->me_portal);

		lnet_res_unlock(cpt);
		return -ENOENT;	/* -ve: OK but no match */
	}

	LASSERT(md->md_offset == 0);

	rlength = hdr->payload_length;
	mlength = MIN(rlength, (int)md->md_length);

	if (mlength < rlength &&
	    (md->md_options & LNET_MD_TRUNCATE) == 0) {
		CNETERR("%s: Dropping REPLY from %s length %d "
			"for MD %#llx would overflow (%d)\n",
			libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
			rlength, hdr->msg.reply.dst_wmd.wh_object_cookie,
			mlength);
		lnet_res_unlock(cpt);
		return -ENOENT;	/* -ve: OK but no match */
	}

	CDEBUG(D_NET, "%s: Reply from %s of length %d/%d into md %#llx\n",
	       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
	       mlength, rlength, hdr->msg.reply.dst_wmd.wh_object_cookie);

	lnet_msg_attach_md(msg, md, 0, mlength);

	if (mlength != 0)
		lnet_setpayloadbuffer(msg);

	lnet_res_unlock(cpt);

	lnet_build_msg_event(msg, LNET_EVENT_REPLY);

	lnet_ni_recv(ni, private, msg, 0, 0, mlength, rlength);
	return 0;
}

static int
lnet_parse_ack(struct lnet_ni *ni, struct lnet_msg *msg)
{
	struct lnet_hdr *hdr = &msg->msg_hdr;
	struct lnet_process_id src = {0};
	struct lnet_libmd *md;
	int cpt;

	src.nid = hdr->src_nid;
	src.pid = hdr->src_pid;

	/* Convert ack fields to host byte order */
	hdr->msg.ack.match_bits = le64_to_cpu(hdr->msg.ack.match_bits);
	hdr->msg.ack.mlength = le32_to_cpu(hdr->msg.ack.mlength);

	cpt = lnet_cpt_of_cookie(hdr->msg.ack.dst_wmd.wh_object_cookie);
	lnet_res_lock(cpt);

	/* NB handles only looked up by creator (no flips) */
	md = lnet_wire_handle2md(&hdr->msg.ack.dst_wmd);
	if (md == NULL || md->md_threshold == 0 || md->md_me != NULL) {
		/* Don't moan; this is expected */
		CDEBUG(D_NET,
		       "%s: Dropping ACK from %s to %s MD %#llx.%#llx\n",
		       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
		       (md == NULL) ? "invalid" : "inactive",
		       hdr->msg.ack.dst_wmd.wh_interface_cookie,
		       hdr->msg.ack.dst_wmd.wh_object_cookie);
		if (md != NULL && md->md_me != NULL)
			CERROR("Source MD also attached to portal %d\n",
			       md->md_me->me_portal);

		lnet_res_unlock(cpt);
		return -ENOENT;			 /* -ve! */
	}

	CDEBUG(D_NET, "%s: ACK from %s into md %#llx\n",
	       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
	       hdr->msg.ack.dst_wmd.wh_object_cookie);

	lnet_msg_attach_md(msg, md, 0, 0);

	lnet_res_unlock(cpt);

	lnet_build_msg_event(msg, LNET_EVENT_ACK);

	lnet_ni_recv(ni, msg->msg_private, msg, 0, 0, 0, msg->msg_len);
	return 0;
}

/**
 * \retval LNET_CREDIT_OK	If \a msg is forwarded
 * \retval LNET_CREDIT_WAIT	If \a msg is blocked because w/o buffer
 * \retval -ve			error code
 */
int
lnet_parse_forward_locked(struct lnet_ni *ni, struct lnet_msg *msg)
{
	int	rc = 0;

	if (!the_lnet.ln_routing)
		return -ECANCELED;

	if (msg->msg_rxpeer->lpni_rtrcredits <= 0 ||
	    lnet_msg2bufpool(msg)->rbp_credits <= 0) {
		if (ni->ni_net->net_lnd->lnd_eager_recv == NULL) {
			msg->msg_rx_ready_delay = 1;
		} else {
			lnet_net_unlock(msg->msg_rx_cpt);
			rc = lnet_ni_eager_recv(ni, msg);
			lnet_net_lock(msg->msg_rx_cpt);
		}
	}

	if (rc == 0)
		rc = lnet_post_routed_recv_locked(msg, 0);
	return rc;
}

int
lnet_parse_local(struct lnet_ni *ni, struct lnet_msg *msg)
{
	int	rc;

	switch (msg->msg_type) {
	case LNET_MSG_ACK:
		rc = lnet_parse_ack(ni, msg);
		break;
	case LNET_MSG_PUT:
		rc = lnet_parse_put(ni, msg);
		break;
	case LNET_MSG_GET:
		rc = lnet_parse_get(ni, msg, msg->msg_rdma_get);
		break;
	case LNET_MSG_REPLY:
		rc = lnet_parse_reply(ni, msg);
		break;
	default: /* prevent an unused label if !kernel */
		LASSERT(0);
		return -EPROTO;
	}

	LASSERT(rc == 0 || rc == -ENOENT);
	return rc;
}

char *
lnet_msgtyp2str (int type)
{
	switch (type) {
	case LNET_MSG_ACK:
		return ("ACK");
	case LNET_MSG_PUT:
		return ("PUT");
	case LNET_MSG_GET:
		return ("GET");
	case LNET_MSG_REPLY:
		return ("REPLY");
	case LNET_MSG_HELLO:
		return ("HELLO");
	default:
		return ("<UNKNOWN>");
	}
}

void
lnet_print_hdr(struct lnet_hdr *hdr)
{
	struct lnet_process_id src = {
		.nid = hdr->src_nid,
		.pid = hdr->src_pid,
	};
	struct lnet_process_id dst = {
		.nid = hdr->dest_nid,
		.pid = hdr->dest_pid,
	};
	char *type_str = lnet_msgtyp2str(hdr->type);

	CWARN("P3 Header at %p of type %s\n", hdr, type_str);
	CWARN("    From %s\n", libcfs_id2str(src));
	CWARN("    To	%s\n", libcfs_id2str(dst));

	switch (hdr->type) {
	default:
		break;

	case LNET_MSG_PUT:
		CWARN("    Ptl index %d, ack md %#llx.%#llx, "
		      "match bits %llu\n",
		      hdr->msg.put.ptl_index,
		      hdr->msg.put.ack_wmd.wh_interface_cookie,
		      hdr->msg.put.ack_wmd.wh_object_cookie,
		      hdr->msg.put.match_bits);
		CWARN("    Length %d, offset %d, hdr data %#llx\n",
		      hdr->payload_length, hdr->msg.put.offset,
		      hdr->msg.put.hdr_data);
		break;

	case LNET_MSG_GET:
		CWARN("    Ptl index %d, return md %#llx.%#llx, "
		      "match bits %llu\n", hdr->msg.get.ptl_index,
		      hdr->msg.get.return_wmd.wh_interface_cookie,
		      hdr->msg.get.return_wmd.wh_object_cookie,
		      hdr->msg.get.match_bits);
		CWARN("    Length %d, src offset %d\n",
		      hdr->msg.get.sink_length,
		      hdr->msg.get.src_offset);
		break;

	case LNET_MSG_ACK:
		CWARN("    dst md %#llx.%#llx, "
		      "manipulated length %d\n",
		      hdr->msg.ack.dst_wmd.wh_interface_cookie,
		      hdr->msg.ack.dst_wmd.wh_object_cookie,
		      hdr->msg.ack.mlength);
		break;

	case LNET_MSG_REPLY:
		CWARN("    dst md %#llx.%#llx, "
		      "length %d\n",
		      hdr->msg.reply.dst_wmd.wh_interface_cookie,
		      hdr->msg.reply.dst_wmd.wh_object_cookie,
		      hdr->payload_length);
	}

}

int
lnet_parse(struct lnet_ni *ni, struct lnet_hdr *hdr, lnet_nid_t from_nid,
	   void *private, int rdma_req)
{
	int		rc = 0;
	int		cpt;
	int		for_me;
	struct lnet_msg	*msg;
	lnet_pid_t     dest_pid;
	lnet_nid_t     dest_nid;
	lnet_nid_t     src_nid;
	struct lnet_peer_ni *lpni;
	__u32          payload_length;
	__u32          type;

	LASSERT (!in_interrupt ());

	type = le32_to_cpu(hdr->type);
	src_nid = le64_to_cpu(hdr->src_nid);
	dest_nid = le64_to_cpu(hdr->dest_nid);
	dest_pid = le32_to_cpu(hdr->dest_pid);
	payload_length = le32_to_cpu(hdr->payload_length);

	for_me = (ni->ni_nid == dest_nid);
	cpt = lnet_cpt_of_nid(from_nid, ni);

	CDEBUG(D_NET, "TRACE: %s(%s) <- %s : %s - %s\n",
		libcfs_nid2str(dest_nid),
		libcfs_nid2str(ni->ni_nid),
		libcfs_nid2str(src_nid),
		lnet_msgtyp2str(type),
		(for_me) ? "for me" : "routed");

	switch (type) {
	case LNET_MSG_ACK:
	case LNET_MSG_GET:
		if (payload_length > 0) {
			CERROR("%s, src %s: bad %s payload %d (0 expected)\n",
			       libcfs_nid2str(from_nid),
			       libcfs_nid2str(src_nid),
			       lnet_msgtyp2str(type), payload_length);
			return -EPROTO;
		}
		break;

	case LNET_MSG_PUT:
	case LNET_MSG_REPLY:
		if (payload_length >
		    (__u32)(for_me ? LNET_MAX_PAYLOAD : LNET_MTU)) {
			CERROR("%s, src %s: bad %s payload %d "
			       "(%d max expected)\n",
			       libcfs_nid2str(from_nid),
			       libcfs_nid2str(src_nid),
			       lnet_msgtyp2str(type),
			       payload_length,
			       for_me ? LNET_MAX_PAYLOAD : LNET_MTU);
			return -EPROTO;
		}
		break;

	default:
		CERROR("%s, src %s: Bad message type 0x%x\n",
		       libcfs_nid2str(from_nid),
		       libcfs_nid2str(src_nid), type);
		return -EPROTO;
	}

	if (the_lnet.ln_routing &&
	    ni->ni_last_alive != ktime_get_real_seconds()) {
		/* NB: so far here is the only place to set NI status to "up */
		lnet_ni_lock(ni);
		ni->ni_last_alive = ktime_get_real_seconds();
		if (ni->ni_status != NULL &&
		    ni->ni_status->ns_status == LNET_NI_STATUS_DOWN)
			ni->ni_status->ns_status = LNET_NI_STATUS_UP;
		lnet_ni_unlock(ni);
	}

	/* Regard a bad destination NID as a protocol error.  Senders should
	 * know what they're doing; if they don't they're misconfigured, buggy
	 * or malicious so we chop them off at the knees :) */

	if (!for_me) {
		if (LNET_NIDNET(dest_nid) == LNET_NIDNET(ni->ni_nid)) {
			/* should have gone direct */
			CERROR("%s, src %s: Bad dest nid %s "
			       "(should have been sent direct)\n",
				libcfs_nid2str(from_nid),
				libcfs_nid2str(src_nid),
				libcfs_nid2str(dest_nid));
			return -EPROTO;
		}

		if (lnet_islocalnid(dest_nid)) {
			/* dest is another local NI; sender should have used
			 * this node's NID on its own network */
			CERROR("%s, src %s: Bad dest nid %s "
			       "(it's my nid but on a different network)\n",
				libcfs_nid2str(from_nid),
				libcfs_nid2str(src_nid),
				libcfs_nid2str(dest_nid));
			return -EPROTO;
		}

		if (rdma_req && type == LNET_MSG_GET) {
			CERROR("%s, src %s: Bad optimized GET for %s "
			       "(final destination must be me)\n",
				libcfs_nid2str(from_nid),
				libcfs_nid2str(src_nid),
				libcfs_nid2str(dest_nid));
			return -EPROTO;
		}

		if (!the_lnet.ln_routing) {
			CERROR("%s, src %s: Dropping message for %s "
			       "(routing not enabled)\n",
				libcfs_nid2str(from_nid),
				libcfs_nid2str(src_nid),
				libcfs_nid2str(dest_nid));
			goto drop;
		}
	}

	/* Message looks OK; we're not going to return an error, so we MUST
	 * call back lnd_recv() come what may... */

	if (!list_empty(&the_lnet.ln_test_peers) &&	/* normally we don't */
	    fail_peer(src_nid, 0)) {			/* shall we now? */
		CERROR("%s, src %s: Dropping %s to simulate failure\n",
		       libcfs_nid2str(from_nid), libcfs_nid2str(src_nid),
		       lnet_msgtyp2str(type));
		goto drop;
	}

	if (!list_empty(&the_lnet.ln_drop_rules) &&
	    lnet_drop_rule_match(hdr, NULL)) {
		CDEBUG(D_NET, "%s, src %s, dst %s: Dropping %s to simulate"
			      "silent message loss\n",
		       libcfs_nid2str(from_nid), libcfs_nid2str(src_nid),
		       libcfs_nid2str(dest_nid), lnet_msgtyp2str(type));
		goto drop;
	}

	if (lnet_drop_asym_route && for_me &&
	    LNET_NIDNET(src_nid) != LNET_NIDNET(from_nid)) {
		struct lnet_net *net;
		struct lnet_remotenet *rnet;
		bool found = true;

		/* we are dealing with a routed message,
		 * so see if route to reach src_nid goes through from_nid
		 */
		lnet_net_lock(cpt);
		net = lnet_get_net_locked(LNET_NIDNET(ni->ni_nid));
		if (!net) {
			lnet_net_unlock(cpt);
			CERROR("net %s not found\n",
			       libcfs_net2str(LNET_NIDNET(ni->ni_nid)));
			return -EPROTO;
		}

		rnet = lnet_find_rnet_locked(LNET_NIDNET(src_nid));
		if (rnet) {
			struct lnet_peer_ni *gw = NULL;
			struct lnet_route *route;

			list_for_each_entry(route, &rnet->lrn_routes, lr_list) {
				found = false;
				gw = route->lr_gateway;
				if (gw->lpni_net != net)
					continue;
				if (gw->lpni_nid == from_nid) {
					found = true;
					break;
				}
			}
		}
		lnet_net_unlock(cpt);
		if (!found) {
			/* we would not use from_nid to route a message to
			 * src_nid
			 * => asymmetric routing detected but forbidden
			 */
			CERROR("%s, src %s: Dropping asymmetrical route %s\n",
			       libcfs_nid2str(from_nid),
			       libcfs_nid2str(src_nid), lnet_msgtyp2str(type));
			goto drop;
		}
	}

	msg = lnet_msg_alloc();
	if (msg == NULL) {
		CERROR("%s, src %s: Dropping %s (out of memory)\n",
		       libcfs_nid2str(from_nid), libcfs_nid2str(src_nid),
		       lnet_msgtyp2str(type));
		goto drop;
	}

	/* msg zeroed in lnet_msg_alloc; i.e. flags all clear,
	 * pointers NULL etc */

	msg->msg_type = type;
	msg->msg_private = private;
	msg->msg_receiving = 1;
	msg->msg_rdma_get = rdma_req;
	msg->msg_len = msg->msg_wanted = payload_length;
	msg->msg_offset = 0;
	msg->msg_hdr = *hdr;
	/* for building message event */
	msg->msg_from = from_nid;
	if (!for_me) {
		msg->msg_target.pid	= dest_pid;
		msg->msg_target.nid	= dest_nid;
		msg->msg_routing	= 1;

	} else {
		/* convert common msg->hdr fields to host byteorder */
		msg->msg_hdr.type	= type;
		msg->msg_hdr.src_nid	= src_nid;
		msg->msg_hdr.src_pid	= le32_to_cpu(msg->msg_hdr.src_pid);
		msg->msg_hdr.dest_nid	= dest_nid;
		msg->msg_hdr.dest_pid	= dest_pid;
		msg->msg_hdr.payload_length = payload_length;
	}

	lnet_net_lock(cpt);
	lpni = lnet_nid2peerni_locked(from_nid, ni->ni_nid, cpt);
	if (IS_ERR(lpni)) {
		lnet_net_unlock(cpt);
		CERROR("%s, src %s: Dropping %s "
		       "(error %ld looking up sender)\n",
		       libcfs_nid2str(from_nid), libcfs_nid2str(src_nid),
		       lnet_msgtyp2str(type), PTR_ERR(lpni));
		lnet_msg_free(msg);
		if (rc == -ESHUTDOWN)
			/* We are shutting down.  Don't do anything more */
			return 0;
		goto drop;
	}
	msg->msg_rxpeer = lpni;
	msg->msg_rxni = ni;
	lnet_ni_addref_locked(ni, cpt);
	/* Multi-Rail: Primary NID of source. */
	msg->msg_initiator = lnet_peer_primary_nid_locked(src_nid);

	if (lnet_isrouter(msg->msg_rxpeer)) {
		lnet_peer_set_alive(msg->msg_rxpeer);
		if (avoid_asym_router_failure &&
		    LNET_NIDNET(src_nid) != LNET_NIDNET(from_nid)) {
			/* received a remote message from router, update
			 * remote NI status on this router.
			 * NB: multi-hop routed message will be ignored.
			 */
			lnet_router_ni_update_locked(msg->msg_rxpeer,
						     LNET_NIDNET(src_nid));
		}
	}

	lnet_msg_commit(msg, cpt);

	/* message delay simulation */
	if (unlikely(!list_empty(&the_lnet.ln_delay_rules) &&
		     lnet_delay_rule_match_locked(hdr, msg))) {
		lnet_net_unlock(cpt);
		return 0;
	}

	if (!for_me) {
		rc = lnet_parse_forward_locked(ni, msg);
		lnet_net_unlock(cpt);

		if (rc < 0)
			goto free_drop;

		if (rc == LNET_CREDIT_OK) {
			lnet_ni_recv(ni, msg->msg_private, msg, 0,
				     0, payload_length, payload_length);
		}
		return 0;
	}

	lnet_net_unlock(cpt);

	rc = lnet_parse_local(ni, msg);
	if (rc != 0)
		goto free_drop;
	return 0;

 free_drop:
	LASSERT(msg->msg_md == NULL);
	lnet_finalize(msg, rc);

 drop:
	lnet_drop_message(ni, cpt, private, payload_length, type);
	return 0;
}
EXPORT_SYMBOL(lnet_parse);

void
lnet_drop_delayed_msg_list(struct list_head *head, char *reason)
{
	while (!list_empty(head)) {
		struct lnet_process_id id = {0};
		struct lnet_msg	*msg;

		msg = list_entry(head->next, struct lnet_msg, msg_list);
		list_del(&msg->msg_list);

		id.nid = msg->msg_hdr.src_nid;
		id.pid = msg->msg_hdr.src_pid;

		LASSERT(msg->msg_md == NULL);
		LASSERT(msg->msg_rx_delayed);
		LASSERT(msg->msg_rxpeer != NULL);
		LASSERT(msg->msg_hdr.type == LNET_MSG_PUT);

		CWARN("Dropping delayed PUT from %s portal %d match %llu"
		      " offset %d length %d: %s\n",
		      libcfs_id2str(id),
		      msg->msg_hdr.msg.put.ptl_index,
		      msg->msg_hdr.msg.put.match_bits,
		      msg->msg_hdr.msg.put.offset,
		      msg->msg_hdr.payload_length, reason);

		/* NB I can't drop msg's ref on msg_rxpeer until after I've
		 * called lnet_drop_message(), so I just hang onto msg as well
		 * until that's done */

		lnet_drop_message(msg->msg_rxni, msg->msg_rx_cpt,
				  msg->msg_private, msg->msg_len,
				  msg->msg_type);

		msg->msg_no_resend = true;
		/*
		 * NB: message will not generate event because w/o attached MD,
		 * but we still should give error code so lnet_msg_decommit()
		 * can skip counters operations and other checks.
		 */
		lnet_finalize(msg, -ENOENT);
	}
}

void
lnet_recv_delayed_msg_list(struct list_head *head)
{
	while (!list_empty(head)) {
		struct lnet_msg	*msg;
		struct lnet_process_id id;

		msg = list_entry(head->next, struct lnet_msg, msg_list);
		list_del(&msg->msg_list);

		/* md won't disappear under me, since each msg
		 * holds a ref on it */

		id.nid = msg->msg_hdr.src_nid;
		id.pid = msg->msg_hdr.src_pid;

		LASSERT(msg->msg_rx_delayed);
		LASSERT(msg->msg_md != NULL);
		LASSERT(msg->msg_rxpeer != NULL);
		LASSERT(msg->msg_rxni != NULL);
		LASSERT(msg->msg_hdr.type == LNET_MSG_PUT);

		CDEBUG(D_NET, "Resuming delayed PUT from %s portal %d "
		       "match %llu offset %d length %d.\n",
			libcfs_id2str(id), msg->msg_hdr.msg.put.ptl_index,
			msg->msg_hdr.msg.put.match_bits,
			msg->msg_hdr.msg.put.offset,
			msg->msg_hdr.payload_length);

		lnet_recv_put(msg->msg_rxni, msg);
	}
}

static void
lnet_attach_rsp_tracker(struct lnet_rsp_tracker *rspt, int cpt,
			struct lnet_libmd *md, struct lnet_handle_md mdh)
{
	s64 timeout_ns;
	bool new_entry = true;
	struct lnet_rsp_tracker *local_rspt;

	/*
	 * MD has a refcount taken by message so it's not going away.
	 * The MD however can be looked up. We need to secure the access
	 * to the md_rspt_ptr by taking the res_lock.
	 * The rspt can be accessed without protection up to when it gets
	 * added to the list.
	 */

	lnet_res_lock(cpt);
	local_rspt = md->md_rspt_ptr;
	timeout_ns = lnet_transaction_timeout * NSEC_PER_SEC;
	if (local_rspt != NULL) {
		/*
		 * we already have an rspt attached to the md, so we'll
		 * update the deadline on that one.
		 */
		LIBCFS_FREE(rspt, sizeof(*rspt));
		new_entry = false;
	} else {
		/* new md */
		rspt->rspt_mdh = mdh;
		rspt->rspt_cpt = cpt;
		/* store the rspt so we can access it when we get the REPLY */
		md->md_rspt_ptr = rspt;
		local_rspt = rspt;
	}
	local_rspt->rspt_deadline = ktime_add_ns(ktime_get(), timeout_ns);

	/*
	 * add to the list of tracked responses. It's added to tail of the
	 * list in order to expire all the older entries first.
	 */
	lnet_net_lock(cpt);
	if (!new_entry && !list_empty(&local_rspt->rspt_on_list))
		list_del_init(&local_rspt->rspt_on_list);
	list_add_tail(&local_rspt->rspt_on_list, the_lnet.ln_mt_rstq[cpt]);
	lnet_net_unlock(cpt);
	lnet_res_unlock(cpt);
}

/**
 * Initiate an asynchronous PUT operation.
 *
 * There are several events associated with a PUT: completion of the send on
 * the initiator node (LNET_EVENT_SEND), and when the send completes
 * successfully, the receipt of an acknowledgment (LNET_EVENT_ACK) indicating
 * that the operation was accepted by the target. The event LNET_EVENT_PUT is
 * used at the target node to indicate the completion of incoming data
 * delivery.
 *
 * The local events will be logged in the EQ associated with the MD pointed to
 * by \a mdh handle. Using a MD without an associated EQ results in these
 * events being discarded. In this case, the caller must have another
 * mechanism (e.g., a higher level protocol) for determining when it is safe
 * to modify the memory region associated with the MD.
 *
 * Note that LNet does not guarantee the order of LNET_EVENT_SEND and
 * LNET_EVENT_ACK, though intuitively ACK should happen after SEND.
 *
 * \param self Indicates the NID of a local interface through which to send
 * the PUT request. Use LNET_NID_ANY to let LNet choose one by itself.
 * \param mdh A handle for the MD that describes the memory to be sent. The MD
 * must be "free floating" (See LNetMDBind()).
 * \param ack Controls whether an acknowledgment is requested.
 * Acknowledgments are only sent when they are requested by the initiating
 * process and the target MD enables them.
 * \param target A process identifier for the target process.
 * \param portal The index in the \a target's portal table.
 * \param match_bits The match bits to use for MD selection at the target
 * process.
 * \param offset The offset into the target MD (only used when the target
 * MD has the LNET_MD_MANAGE_REMOTE option set).
 * \param hdr_data 64 bits of user data that can be included in the message
 * header. This data is written to an event queue entry at the target if an
 * EQ is present on the matching MD.
 *
 * \retval  0	   Success, and only in this case events will be generated
 * and logged to EQ (if it exists).
 * \retval -EIO    Simulated failure.
 * \retval -ENOMEM Memory allocation failure.
 * \retval -ENOENT Invalid MD object.
 *
 * \see struct lnet_event::hdr_data and lnet_event_kind_t.
 */
int
LNetPut(lnet_nid_t self, struct lnet_handle_md mdh, enum lnet_ack_req ack,
	struct lnet_process_id target, unsigned int portal,
	__u64 match_bits, unsigned int offset,
	__u64 hdr_data)
{
	struct lnet_msg *msg;
	struct lnet_libmd *md;
	int cpt;
	int rc;
	struct lnet_rsp_tracker *rspt = NULL;

	LASSERT(the_lnet.ln_refcount > 0);

	if (!list_empty(&the_lnet.ln_test_peers) &&	/* normally we don't */
	    fail_peer(target.nid, 1)) {			/* shall we now? */
		CERROR("Dropping PUT to %s: simulated failure\n",
		       libcfs_id2str(target));
		return -EIO;
	}

	msg = lnet_msg_alloc();
	if (msg == NULL) {
		CERROR("Dropping PUT to %s: ENOMEM on struct lnet_msg\n",
		       libcfs_id2str(target));
		return -ENOMEM;
	}
	msg->msg_vmflush = !!memory_pressure_get();

	cpt = lnet_cpt_of_cookie(mdh.cookie);

	if (ack == LNET_ACK_REQ) {
		rspt = lnet_rspt_alloc(cpt);
		if (!rspt) {
			CERROR("Dropping PUT to %s: ENOMEM on response tracker\n",
				libcfs_id2str(target));
			return -ENOMEM;
		}
		INIT_LIST_HEAD(&rspt->rspt_on_list);
	}

	lnet_res_lock(cpt);

	md = lnet_handle2md(&mdh);
	if (md == NULL || md->md_threshold == 0 || md->md_me != NULL) {
		CERROR("Dropping PUT (%llu:%d:%s): MD (%d) invalid\n",
		       match_bits, portal, libcfs_id2str(target),
		       md == NULL ? -1 : md->md_threshold);
		if (md != NULL && md->md_me != NULL)
			CERROR("Source MD also attached to portal %d\n",
			       md->md_me->me_portal);
		lnet_res_unlock(cpt);

		LIBCFS_FREE(rspt, sizeof(*rspt));
		lnet_msg_free(msg);
		return -ENOENT;
	}

	CDEBUG(D_NET, "LNetPut -> %s\n", libcfs_id2str(target));

	lnet_msg_attach_md(msg, md, 0, 0);

	lnet_prep_send(msg, LNET_MSG_PUT, target, 0, md->md_length);

	msg->msg_hdr.msg.put.match_bits = cpu_to_le64(match_bits);
	msg->msg_hdr.msg.put.ptl_index = cpu_to_le32(portal);
	msg->msg_hdr.msg.put.offset = cpu_to_le32(offset);
	msg->msg_hdr.msg.put.hdr_data = hdr_data;

	/* NB handles only looked up by creator (no flips) */
	if (ack == LNET_ACK_REQ) {
		msg->msg_hdr.msg.put.ack_wmd.wh_interface_cookie =
			the_lnet.ln_interface_cookie;
		msg->msg_hdr.msg.put.ack_wmd.wh_object_cookie =
			md->md_lh.lh_cookie;
	} else {
		msg->msg_hdr.msg.put.ack_wmd.wh_interface_cookie =
			LNET_WIRE_HANDLE_COOKIE_NONE;
		msg->msg_hdr.msg.put.ack_wmd.wh_object_cookie =
			LNET_WIRE_HANDLE_COOKIE_NONE;
	}

	lnet_res_unlock(cpt);

	lnet_build_msg_event(msg, LNET_EVENT_SEND);

	if (ack == LNET_ACK_REQ)
		lnet_attach_rsp_tracker(rspt, cpt, md, mdh);

	rc = lnet_send(self, msg, LNET_NID_ANY);
	if (rc != 0) {
		CNETERR("Error sending PUT to %s: %d\n",
			libcfs_id2str(target), rc);
		msg->msg_no_resend = true;
		lnet_finalize(msg, rc);
	}

	/* completion will be signalled by an event */
	return 0;
}
EXPORT_SYMBOL(LNetPut);

/*
 * The LND can DMA direct to the GET md (i.e. no REPLY msg).  This
 * returns a msg for the LND to pass to lnet_finalize() when the sink
 * data has been received.
 *
 * CAVEAT EMPTOR: 'getmsg' is the original GET, which is freed when
 * lnet_finalize() is called on it, so the LND must call this first
 */
struct lnet_msg *
lnet_create_reply_msg(struct lnet_ni *ni, struct lnet_msg *getmsg)
{
	struct lnet_msg	*msg = lnet_msg_alloc();
	struct lnet_libmd *getmd = getmsg->msg_md;
	struct lnet_process_id peer_id = getmsg->msg_target;
	int cpt;

	LASSERT(!getmsg->msg_target_is_router);
	LASSERT(!getmsg->msg_routing);

	if (msg == NULL) {
		CERROR("%s: Dropping REPLY from %s: can't allocate msg\n",
		       libcfs_nid2str(ni->ni_nid), libcfs_id2str(peer_id));
		goto drop;
	}

	cpt = lnet_cpt_of_cookie(getmd->md_lh.lh_cookie);
	lnet_res_lock(cpt);

	LASSERT(getmd->md_refcount > 0);

	if (getmd->md_threshold == 0) {
		CERROR("%s: Dropping REPLY from %s for inactive MD %p\n",
			libcfs_nid2str(ni->ni_nid), libcfs_id2str(peer_id),
			getmd);
		lnet_res_unlock(cpt);
		goto drop;
	}

	LASSERT(getmd->md_offset == 0);

	CDEBUG(D_NET, "%s: Reply from %s md %p\n",
	       libcfs_nid2str(ni->ni_nid), libcfs_id2str(peer_id), getmd);

	/* setup information for lnet_build_msg_event */
	msg->msg_initiator = getmsg->msg_txpeer->lpni_peer_net->lpn_peer->lp_primary_nid;
	msg->msg_from = peer_id.nid;
	msg->msg_type = LNET_MSG_GET; /* flag this msg as an "optimized" GET */
	msg->msg_hdr.src_nid = peer_id.nid;
	msg->msg_hdr.payload_length = getmd->md_length;
	msg->msg_receiving = 1; /* required by lnet_msg_attach_md */

	lnet_msg_attach_md(msg, getmd, getmd->md_offset, getmd->md_length);
	lnet_res_unlock(cpt);

	cpt = lnet_cpt_of_nid(peer_id.nid, ni);

	lnet_net_lock(cpt);
	lnet_msg_commit(msg, cpt);
	lnet_net_unlock(cpt);

	lnet_build_msg_event(msg, LNET_EVENT_REPLY);

	return msg;

 drop:
	cpt = lnet_cpt_of_nid(peer_id.nid, ni);

	lnet_net_lock(cpt);
	lnet_incr_stats(&ni->ni_stats, LNET_MSG_GET, LNET_STATS_TYPE_DROP);
	the_lnet.ln_counters[cpt]->lct_common.lcc_drop_count++;
	the_lnet.ln_counters[cpt]->lct_common.lcc_drop_length +=
		getmd->md_length;
	lnet_net_unlock(cpt);

	if (msg != NULL)
		lnet_msg_free(msg);

	return NULL;
}
EXPORT_SYMBOL(lnet_create_reply_msg);

void
lnet_set_reply_msg_len(struct lnet_ni *ni, struct lnet_msg *reply,
		       unsigned int len)
{
	/* Set the REPLY length, now the RDMA that elides the REPLY message has
	 * completed and I know it. */
	LASSERT(reply != NULL);
	LASSERT(reply->msg_type == LNET_MSG_GET);
	LASSERT(reply->msg_ev.type == LNET_EVENT_REPLY);

	/* NB I trusted my peer to RDMA.  If she tells me she's written beyond
	 * the end of my buffer, I might as well be dead. */
	LASSERT(len <= reply->msg_ev.mlength);

	reply->msg_ev.mlength = len;
}
EXPORT_SYMBOL(lnet_set_reply_msg_len);

/**
 * Initiate an asynchronous GET operation.
 *
 * On the initiator node, an LNET_EVENT_SEND is logged when the GET request
 * is sent, and an LNET_EVENT_REPLY is logged when the data returned from
 * the target node in the REPLY has been written to local MD.
 *
 * On the target node, an LNET_EVENT_GET is logged when the GET request
 * arrives and is accepted into a MD.
 *
 * \param self,target,portal,match_bits,offset See the discussion in LNetPut().
 * \param mdh A handle for the MD that describes the memory into which the
 * requested data will be received. The MD must be "free floating" (See LNetMDBind()).
 *
 * \retval  0	   Success, and only in this case events will be generated
 * and logged to EQ (if it exists) of the MD.
 * \retval -EIO    Simulated failure.
 * \retval -ENOMEM Memory allocation failure.
 * \retval -ENOENT Invalid MD object.
 */
int
LNetGet(lnet_nid_t self, struct lnet_handle_md mdh,
	struct lnet_process_id target, unsigned int portal,
	__u64 match_bits, unsigned int offset, bool recovery)
{
	struct lnet_msg *msg;
	struct lnet_libmd *md;
	struct lnet_rsp_tracker *rspt;
	int cpt;
	int rc;

	LASSERT(the_lnet.ln_refcount > 0);

	if (!list_empty(&the_lnet.ln_test_peers) &&	/* normally we don't */
	    fail_peer(target.nid, 1))			/* shall we now? */
	{
		CERROR("Dropping GET to %s: simulated failure\n",
		       libcfs_id2str(target));
		return -EIO;
	}

	msg = lnet_msg_alloc();
	if (!msg) {
		CERROR("Dropping GET to %s: ENOMEM on struct lnet_msg\n",
		       libcfs_id2str(target));
		return -ENOMEM;
	}

	cpt = lnet_cpt_of_cookie(mdh.cookie);

	rspt = lnet_rspt_alloc(cpt);
	if (!rspt) {
		CERROR("Dropping GET to %s: ENOMEM on response tracker\n",
		       libcfs_id2str(target));
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&rspt->rspt_on_list);

	msg->msg_recovery = recovery;

	lnet_res_lock(cpt);

	md = lnet_handle2md(&mdh);
	if (md == NULL || md->md_threshold == 0 || md->md_me != NULL) {
		CERROR("Dropping GET (%llu:%d:%s): MD (%d) invalid\n",
		       match_bits, portal, libcfs_id2str(target),
		       md == NULL ? -1 : md->md_threshold);
		if (md != NULL && md->md_me != NULL)
			CERROR("REPLY MD also attached to portal %d\n",
			       md->md_me->me_portal);

		lnet_res_unlock(cpt);

		lnet_msg_free(msg);
		LIBCFS_FREE(rspt, sizeof(*rspt));
		return -ENOENT;
	}

	CDEBUG(D_NET, "LNetGet -> %s\n", libcfs_id2str(target));

	lnet_msg_attach_md(msg, md, 0, 0);

	lnet_prep_send(msg, LNET_MSG_GET, target, 0, 0);

	msg->msg_hdr.msg.get.match_bits = cpu_to_le64(match_bits);
	msg->msg_hdr.msg.get.ptl_index = cpu_to_le32(portal);
	msg->msg_hdr.msg.get.src_offset = cpu_to_le32(offset);
	msg->msg_hdr.msg.get.sink_length = cpu_to_le32(md->md_length);

	/* NB handles only looked up by creator (no flips) */
	msg->msg_hdr.msg.get.return_wmd.wh_interface_cookie =
		the_lnet.ln_interface_cookie;
	msg->msg_hdr.msg.get.return_wmd.wh_object_cookie =
		md->md_lh.lh_cookie;

	lnet_res_unlock(cpt);

	lnet_build_msg_event(msg, LNET_EVENT_SEND);

	lnet_attach_rsp_tracker(rspt, cpt, md, mdh);

	rc = lnet_send(self, msg, LNET_NID_ANY);
	if (rc < 0) {
		CNETERR("Error sending GET to %s: %d\n",
			libcfs_id2str(target), rc);
		msg->msg_no_resend = true;
		lnet_finalize(msg, rc);
	}

	/* completion will be signalled by an event */
	return 0;
}
EXPORT_SYMBOL(LNetGet);

/**
 * Calculate distance to node at \a dstnid.
 *
 * \param dstnid Target NID.
 * \param srcnidp If not NULL, NID of the local interface to reach \a dstnid
 * is saved here.
 * \param orderp If not NULL, order of the route to reach \a dstnid is saved
 * here.
 *
 * \retval 0 If \a dstnid belongs to a local interface, and reserved option
 * local_nid_dist_zero is set, which is the default.
 * \retval positives Distance to target NID, i.e. number of hops plus one.
 * \retval -EHOSTUNREACH If \a dstnid is not reachable.
 */
int
LNetDist(lnet_nid_t dstnid, lnet_nid_t *srcnidp, __u32 *orderp)
{
	struct list_head *e;
	struct lnet_ni *ni = NULL;
	struct lnet_remotenet *rnet;
	__u32 dstnet = LNET_NIDNET(dstnid);
	int hops;
	int cpt;
	__u32 order = 2;
	struct list_head *rn_list;

	/* if !local_nid_dist_zero, I don't return a distance of 0 ever
	 * (when lustre sees a distance of 0, it substitutes 0@lo), so I
	 * keep order 0 free for 0@lo and order 1 free for a local NID
	 * match */

	LASSERT(the_lnet.ln_refcount > 0);

	cpt = lnet_net_lock_current();

	while ((ni = lnet_get_next_ni_locked(NULL, ni))) {
		if (ni->ni_nid == dstnid) {
			if (srcnidp != NULL)
				*srcnidp = dstnid;
			if (orderp != NULL) {
				if (dstnid == LNET_NID_LO_0)
					*orderp = 0;
				else
					*orderp = 1;
			}
			lnet_net_unlock(cpt);

			return local_nid_dist_zero ? 0 : 1;
		}

		if (LNET_NIDNET(ni->ni_nid) == dstnet) {
			/* Check if ni was originally created in
			 * current net namespace.
			 * If not, assign order above 0xffff0000,
			 * to make this ni not a priority. */
			if (current->nsproxy &&
			    !net_eq(ni->ni_net_ns, current->nsproxy->net_ns))
					order += 0xffff0000;
			if (srcnidp != NULL)
				*srcnidp = ni->ni_nid;
			if (orderp != NULL)
				*orderp = order;
			lnet_net_unlock(cpt);
			return 1;
		}

		order++;
	}

	rn_list = lnet_net2rnethash(dstnet);
	list_for_each(e, rn_list) {
		rnet = list_entry(e, struct lnet_remotenet, lrn_list);

		if (rnet->lrn_net == dstnet) {
			struct lnet_route *route;
			struct lnet_route *shortest = NULL;
			__u32 shortest_hops = LNET_UNDEFINED_HOPS;
			__u32 route_hops;

			LASSERT(!list_empty(&rnet->lrn_routes));

			list_for_each_entry(route, &rnet->lrn_routes,
					    lr_list) {
				route_hops = route->lr_hops;
				if (route_hops == LNET_UNDEFINED_HOPS)
					route_hops = 1;
				if (shortest == NULL ||
				    route_hops < shortest_hops) {
					shortest = route;
					shortest_hops = route_hops;
				}
			}

			LASSERT(shortest != NULL);
			hops = shortest_hops;
			if (srcnidp != NULL) {
				ni = lnet_get_next_ni_locked(
					shortest->lr_gateway->lpni_net,
					NULL);
				*srcnidp = ni->ni_nid;
			}
			if (orderp != NULL)
				*orderp = order;
			lnet_net_unlock(cpt);
			return hops + 1;
		}
		order++;
	}

	lnet_net_unlock(cpt);
	return -EHOSTUNREACH;
}
EXPORT_SYMBOL(LNetDist);
