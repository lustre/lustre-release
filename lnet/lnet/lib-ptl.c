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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/lnet/lib-ptl.c
 *
 * portal & match routines
 *
 * Author: liang@whamcloud.com
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>

static int
lnet_ptl_match_type(unsigned int index, lnet_process_id_t match_id,
		    __u64 mbits, __u64 ignore_bits)
{
	struct lnet_portal	*ptl = the_lnet.ln_portals[index];
	int			unique;

	unique = ignore_bits == 0 &&
		 match_id.nid != LNET_NID_ANY &&
		 match_id.pid != LNET_PID_ANY;

	LASSERT(!lnet_ptl_is_unique(ptl) || !lnet_ptl_is_wildcard(ptl));

	/* prefer to check w/o any lock */
	if (likely(lnet_ptl_is_unique(ptl) || lnet_ptl_is_wildcard(ptl)))
		goto match;

	/* unset, new portal */
	lnet_res_lock();
	/* check again with lock */
	if (unlikely(lnet_ptl_is_unique(ptl) || lnet_ptl_is_wildcard(ptl))) {
		lnet_res_unlock();
		goto match;
	}

	/* still not set */
	if (unique)
		lnet_ptl_setopt(ptl, LNET_PTL_MATCH_UNIQUE);
	else
		lnet_ptl_setopt(ptl, LNET_PTL_MATCH_WILDCARD);

	lnet_res_unlock();

	return 1;

 match:
	if ((lnet_ptl_is_unique(ptl) && !unique) ||
	    (lnet_ptl_is_wildcard(ptl) && unique))
		return 0;
	return 1;
}

static int
lnet_try_match_md(int index, int op_mask, lnet_process_id_t src,
		  unsigned int rlength, unsigned int roffset,
		  __u64 match_bits, lnet_libmd_t *md, lnet_msg_t *msg)
{
	/* ALWAYS called holding the lnet_res_lock, and can't lnet_res_unlock;
	 * lnet_match_blocked_msg() relies on this to avoid races */
	unsigned int	offset;
	unsigned int	mlength;
	lnet_me_t	*me = md->md_me;

	/* mismatched MD op */
	if ((md->md_options & op_mask) == 0)
		return LNET_MATCHMD_NONE;

	/* MD exhausted */
	if (lnet_md_exhausted(md))
		return LNET_MATCHMD_NONE;

	/* mismatched ME nid/pid? */
	if (me->me_match_id.nid != LNET_NID_ANY &&
	    me->me_match_id.nid != src.nid)
		return LNET_MATCHMD_NONE;

	if (me->me_match_id.pid != LNET_PID_ANY &&
	    me->me_match_id.pid != src.pid)
		return LNET_MATCHMD_NONE;

	/* mismatched ME matchbits? */
	if (((me->me_match_bits ^ match_bits) & ~me->me_ignore_bits) != 0)
		return LNET_MATCHMD_NONE;

	/* Hurrah! This _is_ a match; check it out... */

	if ((md->md_options & LNET_MD_MANAGE_REMOTE) == 0)
		offset = md->md_offset;
	else
		offset = roffset;

	if ((md->md_options & LNET_MD_MAX_SIZE) != 0) {
		mlength = md->md_max_size;
		LASSERT(md->md_offset + mlength <= md->md_length);
	} else {
		mlength = md->md_length - offset;
	}

	if (rlength <= mlength) {        /* fits in allowed space */
		mlength = rlength;
	} else if ((md->md_options & LNET_MD_TRUNCATE) == 0) {
		/* this packet _really_ is too big */
		CERROR("Matching packet from %s, match "LPU64
		       " length %d too big: %d left, %d allowed\n",
		       libcfs_id2str(src), match_bits, rlength,
		       md->md_length - offset, mlength);

		return LNET_MATCHMD_DROP;
	}

	/* Commit to this ME/MD */
	CDEBUG(D_NET, "Incoming %s index %x from %s of "
	       "length %d/%d into md "LPX64" [%d] + %d\n",
	       (op_mask == LNET_MD_OP_PUT) ? "put" : "get",
	       index, libcfs_id2str(src), mlength, rlength,
	       md->md_lh.lh_cookie, md->md_niov, offset);

	lnet_msg_attach_md(msg, md, offset, mlength);
	md->md_offset = offset + mlength;

	/* Auto-unlink NOW, so the ME gets unlinked if required.
	 * We bumped md->md_refcount above so the MD just gets flagged
	 * for unlink when it is finalized. */
	if ((md->md_flags & LNET_MD_FLAG_AUTO_UNLINK) != 0 &&
	    lnet_md_exhausted(md)) {
		lnet_md_unlink(md);
	}

	return LNET_MATCHMD_OK;
}

struct lnet_match_table *
lnet_mt_of_attach(unsigned int index, lnet_process_id_t id,
		  __u64 mbits, __u64 ignore_bits, lnet_ins_pos_t pos)
{
	struct lnet_portal *ptl;

	LASSERT(index < the_lnet.ln_nportals);

	if (!lnet_ptl_match_type(index, id, mbits, ignore_bits))
		return NULL;

	ptl = the_lnet.ln_portals[index];
	/* NB: Now we only have one match-table for each portal,
	 * and will have match-table per CPT in upcoming changes,
	 * ME will be scattered to different match-tables based
	 * on attaching information */
	return ptl->ptl_mtable;
}

struct lnet_match_table *
lnet_mt_of_match(unsigned int index, lnet_process_id_t id, __u64 mbits)
{
	struct lnet_portal *ptl;

	LASSERT(index < the_lnet.ln_nportals);

	ptl = the_lnet.ln_portals[index];
	if (!lnet_ptl_is_unique(ptl) &&
	    !lnet_ptl_is_wildcard(ptl) && !lnet_ptl_is_lazy(ptl))
		return NULL;

	/* NB: Now we only have one match-table for each portal,
	 * and will have match-table per CPT in upcoming changes,
	 * request will be scattered to different match-tables based
	 * on matching information */
	return ptl->ptl_mtable;
}

cfs_list_t *
lnet_mt_match_head(struct lnet_match_table *mtable,
		   lnet_process_id_t id, __u64 mbits)
{
	struct lnet_portal *ptl = the_lnet.ln_portals[mtable->mt_portal];

	if (lnet_ptl_is_wildcard(ptl)) {
		return &mtable->mt_mlist;

	} else if (lnet_ptl_is_unique(ptl)) {
		unsigned long hash = mbits + id.nid + id.pid;

		hash = cfs_hash_long(hash, LNET_MT_HASH_BITS);
		return &mtable->mt_mhash[hash];
	}

	return NULL;
}

int
lnet_mt_match_md(struct lnet_match_table *mtable,
		 int op_mask, lnet_process_id_t src,
		 unsigned int rlength, unsigned int roffset,
		 __u64 match_bits, lnet_msg_t *msg)
{
	cfs_list_t		*head;
	lnet_me_t		*me;
	lnet_me_t		*tmp;
	int			rc;

	head = lnet_mt_match_head(mtable, src, match_bits);
	if (head == NULL) /* nobody posted anything on this portal */
		goto out;

	cfs_list_for_each_entry_safe(me, tmp, head, me_list) {
		/* ME attached but MD not attached yet */
		if (me->me_md == NULL)
			continue;

		LASSERT(me == me->me_md->md_me);

		rc = lnet_try_match_md(mtable->mt_portal,
				       op_mask, src, rlength, roffset,
				       match_bits, me->me_md, msg);
		switch (rc) {
		default:
			LBUG();

		case LNET_MATCHMD_NONE:
			continue;

		case LNET_MATCHMD_OK:
			return LNET_MATCHMD_OK;

		case LNET_MATCHMD_DROP:
			return LNET_MATCHMD_DROP;
		}
		/* not reached */
	}

 out:
	if (op_mask == LNET_MD_OP_GET ||
	    !lnet_ptl_is_lazy(the_lnet.ln_portals[mtable->mt_portal]))
		return LNET_MATCHMD_DROP;

	return LNET_MATCHMD_NONE;
}

int
lnet_ptl_match_md(unsigned int index, int op_mask, lnet_process_id_t src,
		  unsigned int rlength, unsigned int roffset,
		  __u64 match_bits, lnet_msg_t *msg)
{
	struct lnet_match_table	*mtable;
	struct lnet_portal	*ptl;
	int			rc;

	CDEBUG(D_NET, "Request from %s of length %d into portal %d "
	       "MB="LPX64"\n", libcfs_id2str(src), rlength, index, match_bits);

	if (index >= the_lnet.ln_nportals) {
		CERROR("Invalid portal %d not in [0-%d]\n",
		       index, the_lnet.ln_nportals);
		return LNET_MATCHMD_DROP;
	}

	mtable = lnet_mt_of_match(index, src, match_bits);
	if (mtable == NULL) {
		CDEBUG(D_NET, "Drop early message from %s of length %d into "
			      "portal %d MB="LPX64"\n",
			      libcfs_id2str(src), rlength, index, match_bits);
		return LNET_MATCHMD_DROP;
	}

	ptl = the_lnet.ln_portals[index];
	lnet_res_lock();

	if (the_lnet.ln_shutdown) {
		rc =  LNET_MATCHMD_DROP;
		goto out;
	}

	rc = lnet_mt_match_md(mtable, op_mask, src, rlength,
			      roffset, match_bits, msg);
	if (rc != LNET_MATCHMD_NONE) /* matched or dropping */
		goto out;

	if (!msg->msg_rx_ready_delay)
		goto out;

	LASSERT(!msg->msg_rx_delayed);
	msg->msg_rx_delayed = 1;
	cfs_list_add_tail(&msg->msg_list, &ptl->ptl_msgq);

	CDEBUG(D_NET,
	       "Delaying %s from %s portal %d MB "LPX64" offset %d len %d\n",
	       op_mask == LNET_MD_OP_PUT ? "PUT" : "GET",
	       libcfs_id2str(src), index, match_bits, roffset, rlength);
 out:
	lnet_res_unlock();
	return rc;
}

void
lnet_ptl_detach_md(lnet_me_t *me, lnet_libmd_t *md)
{
	LASSERT(me->me_md == md && md->md_me == me);

	me->me_md = NULL;
	md->md_me = NULL;
}

/* called with lnet_res_lock held */
void
lnet_ptl_attach_md(lnet_me_t *me, lnet_libmd_t *md,
		   cfs_list_t *matches, cfs_list_t *drops)
{
	struct lnet_portal	*ptl = the_lnet.ln_portals[me->me_portal];
	lnet_msg_t		*tmp;
	lnet_msg_t		*msg;

	LASSERT(md->md_refcount == 0); /* a brand new MD */

	me->me_md = md;
	md->md_me = me;

	cfs_list_for_each_entry_safe(msg, tmp, &ptl->ptl_msgq, msg_list) {
		int               rc;
		int               index;
		lnet_hdr_t       *hdr;
		lnet_process_id_t src;

		LASSERT(msg->msg_rx_delayed);

		hdr   = &msg->msg_hdr;
		index = hdr->msg.put.ptl_index;

		src.nid = hdr->src_nid;
		src.pid = hdr->src_pid;

		rc = lnet_try_match_md(index, LNET_MD_OP_PUT, src,
				       hdr->payload_length,
				       hdr->msg.put.offset,
				       hdr->msg.put.match_bits, md, msg);

		if (rc == LNET_MATCHMD_NONE)
			continue;

		/* Hurrah! This _is_ a match */
		cfs_list_del(&msg->msg_list);

		if (rc == LNET_MATCHMD_OK) {
			cfs_list_add_tail(&msg->msg_list, matches);

			CDEBUG(D_NET, "Resuming delayed PUT from %s portal %d "
			       "match "LPU64" offset %d length %d.\n",
			       libcfs_id2str(src),
			       hdr->msg.put.ptl_index,
			       hdr->msg.put.match_bits,
			       hdr->msg.put.offset,
			       hdr->payload_length);
		} else {
			LASSERT(rc == LNET_MATCHMD_DROP);

			cfs_list_add_tail(&msg->msg_list, drops);
		}

		if (lnet_md_exhausted(md))
			break;
	}
}

void
lnet_ptl_cleanup(struct lnet_portal *ptl)
{
	struct lnet_match_table	*mtable;

	LASSERT(cfs_list_empty(&ptl->ptl_msgq));

	if (ptl->ptl_mtable == NULL) /* uninitialized portal */
		return;

	do { /* iterate over match-tables when we have percpt match-table */
		cfs_list_t	*mhash;
		lnet_me_t	*me;
		int		j;

		mtable = ptl->ptl_mtable;

		if (mtable->mt_mhash == NULL) /* uninitialized match-table */
			continue;

		mhash = mtable->mt_mhash;
		/* cleanup ME */
		while (!cfs_list_empty(&mtable->mt_mlist)) {
			me = cfs_list_entry(mtable->mt_mlist.next,
					    lnet_me_t, me_list);
			CERROR("Active wildcard ME %p on exit\n", me);
			cfs_list_del(&me->me_list);
			lnet_me_free(me);
		}

		for (j = 0; j < LNET_MT_HASH_SIZE; j++) {
			while (!cfs_list_empty(&mhash[j])) {
				me = cfs_list_entry(mhash[j].next,
						    lnet_me_t, me_list);
				CERROR("Active unique ME %p on exit\n", me);
				cfs_list_del(&me->me_list);
				lnet_me_free(me);
			}
		}

		LIBCFS_FREE(mhash, sizeof(*mhash) * LNET_MT_HASH_SIZE);
	} while (0);

	LIBCFS_FREE(ptl->ptl_mtable, sizeof(*mtable));
	ptl->ptl_mtable = NULL;
}

int
lnet_ptl_setup(struct lnet_portal *ptl, int index)
{
	struct lnet_match_table	*mtable;
	cfs_list_t		*mhash;
	int			j;

	ptl->ptl_index = index;
	CFS_INIT_LIST_HEAD(&ptl->ptl_msgq);

	LIBCFS_ALLOC(mtable, sizeof(*mtable));
	if (mtable == NULL) {
		CERROR("Failed to create match table for portal %d\n", index);
		return -ENOMEM;
	}

	ptl->ptl_mtable = mtable;
	do { /* iterate over match-tables when we have percpt match-table */
		LIBCFS_ALLOC(mhash, sizeof(*mhash) * LNET_MT_HASH_SIZE);
		if (mhash == NULL) {
			CERROR("Failed to create match hash for portal %d\n",
			       index);
			goto failed;
		}

		mtable->mt_mhash = mhash;
		for (j = 0; j < LNET_MT_HASH_SIZE; j++)
			CFS_INIT_LIST_HEAD(&mhash[j]);

		CFS_INIT_LIST_HEAD(&mtable->mt_mlist);
		mtable->mt_portal = index;
	} while (0);

	return 0;
 failed:
	lnet_ptl_cleanup(ptl);
	return -ENOMEM;
}

void
lnet_portals_destroy(void)
{
	int	i;

	if (the_lnet.ln_portals == NULL)
		return;

	for (i = 0; i < the_lnet.ln_nportals; i++)
		lnet_ptl_cleanup(the_lnet.ln_portals[i]);

	cfs_array_free(the_lnet.ln_portals);
	the_lnet.ln_portals = NULL;
}

int
lnet_portals_create(void)
{
	int	size;
	int	i;

	size = sizeof(struct lnet_portal);

	the_lnet.ln_nportals = MAX_PORTALS;
	the_lnet.ln_portals = cfs_array_alloc(the_lnet.ln_nportals, size);
	if (the_lnet.ln_portals == NULL) {
		CERROR("Failed to allocate portals table\n");
		return -ENOMEM;
	}

	for (i = 0; i < the_lnet.ln_nportals; i++) {
		if (lnet_ptl_setup(the_lnet.ln_portals[i], i)) {
			lnet_portals_destroy();
			return -ENOMEM;
		}
	}

	return 0;
}

/**
 * Turn on the lazy portal attribute. Use with caution!
 *
 * This portal attribute only affects incoming PUT requests to the portal,
 * and is off by default. By default, if there's no matching MD for an
 * incoming PUT request, it is simply dropped. With the lazy attribute on,
 * such requests are queued indefinitely until either a matching MD is
 * posted to the portal or the lazy attribute is turned off.
 *
 * It would prevent dropped requests, however it should be regarded as the
 * last line of defense - i.e. users must keep a close watch on active
 * buffers on a lazy portal and once it becomes too low post more buffers as
 * soon as possible. This is because delayed requests usually have detrimental
 * effects on underlying network connections. A few delayed requests often
 * suffice to bring an underlying connection to a complete halt, due to flow
 * control mechanisms.
 *
 * There's also a DOS attack risk. If users don't post match-all MDs on a
 * lazy portal, a malicious peer can easily stop a service by sending some
 * PUT requests with match bits that won't match any MD. A routed server is
 * especially vulnerable since the connections to its neighbor routers are
 * shared among all clients.
 *
 * \param portal Index of the portal to enable the lazy attribute on.
 *
 * \retval 0       On success.
 * \retval -EINVAL If \a portal is not a valid index.
 */
int
LNetSetLazyPortal(int portal)
{
	struct lnet_portal *ptl;

	if (portal < 0 || portal >= the_lnet.ln_nportals)
		return -EINVAL;

	CDEBUG(D_NET, "Setting portal %d lazy\n", portal);
	ptl = the_lnet.ln_portals[portal];

	lnet_res_lock();
	lnet_ptl_setopt(ptl, LNET_PTL_LAZY);
	lnet_res_unlock();

	return 0;
}

/**
 * Turn off the lazy portal attribute. Delayed requests on the portal,
 * if any, will be all dropped when this function returns.
 *
 * \param portal Index of the portal to disable the lazy attribute on.
 *
 * \retval 0       On success.
 * \retval -EINVAL If \a portal is not a valid index.
 */
int
LNetClearLazyPortal(int portal)
{
	struct lnet_portal	*ptl;
	CFS_LIST_HEAD		(zombies);

	if (portal < 0 || portal >= the_lnet.ln_nportals)
		return -EINVAL;

	ptl = the_lnet.ln_portals[portal];

	lnet_res_lock();

	if (!lnet_ptl_is_lazy(ptl)) {
		lnet_res_unlock();
		return 0;
	}

	if (the_lnet.ln_shutdown)
		CWARN("Active lazy portal %d on exit\n", portal);
	else
		CDEBUG(D_NET, "clearing portal %d lazy\n", portal);

	/* grab all the blocked messages atomically */
	cfs_list_splice_init(&ptl->ptl_msgq, &zombies);

	lnet_ptl_unsetopt(ptl, LNET_PTL_LAZY);

	lnet_res_unlock();

	lnet_drop_delayed_msg_list(&zombies, "Clearing lazy portal attr");

	return 0;
}
