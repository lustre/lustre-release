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

int
lnet_ptl_type_match(struct lnet_portal *ptl, lnet_process_id_t match_id,
		    __u64 mbits, __u64 ignore_bits)
{
	int unique;

	unique = ignore_bits == 0 &&
		 match_id.nid != LNET_NID_ANY &&
		 match_id.pid != LNET_PID_ANY;

	LASSERT(!lnet_ptl_is_unique(ptl) || !lnet_ptl_is_wildcard(ptl));

	/* prefer to check w/o any lock */
	if (likely(lnet_ptl_is_unique(ptl) || lnet_ptl_is_wildcard(ptl)))
		goto match;

	/* unset, new portal */
	LNET_LOCK();
	/* check again with lock */
	if (unlikely(lnet_ptl_is_unique(ptl) || lnet_ptl_is_wildcard(ptl))) {
		LNET_UNLOCK();
		goto match;
	}

	/* still not set */
	if (unique)
		lnet_ptl_setopt(ptl, LNET_PTL_MATCH_UNIQUE);
	else
		lnet_ptl_setopt(ptl, LNET_PTL_MATCH_WILDCARD);

	LNET_UNLOCK();

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
	/* ALWAYS called holding the LNET_LOCK, and can't LNET_UNLOCK;
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

int
lnet_match_md(int index, int op_mask, lnet_process_id_t src,
	      unsigned int rlength, unsigned int roffset,
	      __u64 match_bits, lnet_msg_t *msg)
{
	struct lnet_portal	*ptl = the_lnet.ln_portals[index];
	cfs_list_t		*head;
	lnet_me_t		*me;
	lnet_me_t		*tmp;
	lnet_libmd_t		*md;
	int			rc;

	CDEBUG(D_NET, "Request from %s of length %d into portal %d "
	       "MB="LPX64"\n", libcfs_id2str(src), rlength, index, match_bits);

	if (index < 0 || index >= the_lnet.ln_nportals) {
		CERROR("Invalid portal %d not in [0-%d]\n",
		       index, the_lnet.ln_nportals);
		return LNET_MATCHMD_DROP;
	}

	head = lnet_ptl_me_head(index, src, match_bits);
	if (head == NULL) /* nobody posted anything on this portal */
		goto out;

	cfs_list_for_each_entry_safe(me, tmp, head, me_list) {
		md = me->me_md;

		/* ME attached but MD not attached yet */
		if (md == NULL)
			continue;

		LASSERT(me == md->md_me);

		rc = lnet_try_match_md(index, op_mask, src, rlength,
				       roffset, match_bits, md, msg);
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
	    !lnet_ptl_is_lazy(ptl))
		return LNET_MATCHMD_DROP;

	return LNET_MATCHMD_NONE;
}

/* called with LNET_LOCK held */
void
lnet_match_blocked_msg(lnet_libmd_t *md)
{
	CFS_LIST_HEAD		(drops);
	CFS_LIST_HEAD		(matches);
	cfs_list_t		*tmp;
	cfs_list_t		*entry;
	lnet_msg_t		*msg;
	struct lnet_portal	*ptl;
	lnet_me_t		*me  = md->md_me;

	LASSERT(me->me_portal < (unsigned int)the_lnet.ln_nportals);

	ptl = the_lnet.ln_portals[me->me_portal];
	if (!lnet_ptl_is_lazy(ptl)) {
		LASSERT(cfs_list_empty(&ptl->ptl_msgq));
		return;
	}

	LASSERT(md->md_refcount == 0); /* a brand new MD */

	cfs_list_for_each_safe(entry, tmp, &ptl->ptl_msgq) {
		int               rc;
		int               index;
		lnet_hdr_t       *hdr;
		lnet_process_id_t src;

		msg = cfs_list_entry(entry, lnet_msg_t, msg_list);

		LASSERT(msg->msg_delayed);

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
		ptl->ptl_msgq_version++;

		if (rc == LNET_MATCHMD_OK) {
			cfs_list_add_tail(&msg->msg_list, &matches);

			CDEBUG(D_NET, "Resuming delayed PUT from %s portal %d "
			       "match "LPU64" offset %d length %d.\n",
			       libcfs_id2str(src),
			       hdr->msg.put.ptl_index,
			       hdr->msg.put.match_bits,
			       hdr->msg.put.offset,
			       hdr->payload_length);
		} else {
			LASSERT(rc == LNET_MATCHMD_DROP);

			cfs_list_add_tail(&msg->msg_list, &drops);
		}

		if (lnet_md_exhausted(md))
			break;
	}

	LNET_UNLOCK();

	lnet_drop_delayed_msg_list(&drops, "Bad match");
	lnet_recv_delayed_msg_list(&matches);

	LNET_LOCK();
}

void
lnet_ptl_cleanup(struct lnet_portal *ptl)
{
	lnet_me_t		*me;
	int			j;

	LASSERT(cfs_list_empty(&ptl->ptl_msgq));
	LASSERT(cfs_list_empty(&ptl->ptl_mlist));

	if (ptl->ptl_mhash == NULL) /* uninitialized portal */
		return;

	/* cleanup ME */
	while (!cfs_list_empty(&ptl->ptl_mlist)) {
		me = cfs_list_entry(ptl->ptl_mlist.next,
				    lnet_me_t, me_list);
		CERROR("Active wildcard ME %p on exit\n", me);
		cfs_list_del(&me->me_list);
		lnet_me_free(me);
	}

	for (j = 0; j < LNET_PORTAL_HASH_SIZE; j++) {
		while (!cfs_list_empty(&ptl->ptl_mhash[j])) {
			me = cfs_list_entry(ptl->ptl_mhash[j].next,
				       lnet_me_t, me_list);
			CERROR("Active unique ME %p on exit\n", me);
			cfs_list_del(&me->me_list);
			lnet_me_free(me);
		}
	}

	LIBCFS_FREE(ptl->ptl_mhash,
		    LNET_PORTAL_HASH_SIZE * sizeof(ptl->ptl_mhash[0]));
	ptl->ptl_mhash = NULL; /* mark it as finalized */
}

int
lnet_ptl_setup(struct lnet_portal *ptl, int index)
{
	cfs_list_t		*mhash;
	int			i;

	ptl->ptl_index = index;
	CFS_INIT_LIST_HEAD(&ptl->ptl_msgq);
	CFS_INIT_LIST_HEAD(&ptl->ptl_mlist);

	LIBCFS_ALLOC(mhash, sizeof(*mhash) * LNET_PORTAL_HASH_SIZE);
	if (mhash == NULL) {
		CERROR("Failed to create match table for portal %d\n", index);
		return -ENOMEM;
	}

	for (i = 0; i < LNET_PORTAL_HASH_SIZE; i++)
		CFS_INIT_LIST_HEAD(&mhash[i]);

	ptl->ptl_mhash = mhash; /* initialized */

	return 0;
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

	LNET_LOCK();
	lnet_ptl_setopt(ptl, LNET_PTL_LAZY);
	LNET_UNLOCK();

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

	LNET_LOCK();

	if (!lnet_ptl_is_lazy(ptl)) {
		LNET_UNLOCK();
		return 0;
	}

	if (the_lnet.ln_shutdown)
		CWARN("Active lazy portal %d on exit\n", portal);
	else
		CDEBUG(D_NET, "clearing portal %d lazy\n", portal);

	/* grab all the blocked messages atomically */
	cfs_list_splice_init(&ptl->ptl_msgq, &zombies);

	ptl->ptl_msgq_version++;
	lnet_ptl_unsetopt(ptl, LNET_PTL_LAZY);

	LNET_UNLOCK();

	lnet_drop_delayed_msg_list(&zombies, "Clearing lazy portal attr");

	return 0;
}
