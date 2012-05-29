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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/lnet/peer.c
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>

int
lnet_peer_table_create(void)
{
	struct lnet_peer_table	*ptable;
	cfs_list_t		*hash;
	int			j;

	LIBCFS_ALLOC(ptable, sizeof(*ptable));
	if (ptable == NULL) {
		CERROR("Failed to allocate cpu-partition peer tables\n");
		return -ENOMEM;
	}

	the_lnet.ln_peer_table = ptable;

	do { /* we will have per CPT peer-tables iterate them by then */
		CFS_INIT_LIST_HEAD(&ptable->pt_deathrow);

		LIBCFS_ALLOC(hash, LNET_PEER_HASH_SIZE * sizeof(*hash));
		if (hash == NULL) {
			CERROR("Failed to create peer hash table\n");
			lnet_peer_table_destroy();
			return -ENOMEM;
		}

		for (j = 0; j < LNET_PEER_HASH_SIZE; j++)
			CFS_INIT_LIST_HEAD(&hash[j]);
		ptable->pt_hash = hash; /* sign of initialization */
	} while (0);

	return 0;
}

void
lnet_peer_table_destroy(void)
{
	struct lnet_peer_table	*ptable;
	cfs_list_t		*hash;
	int			j;

	if (the_lnet.ln_peer_table == NULL)
		return;

	ptable = the_lnet.ln_peer_table;

	do { /* we will have per CPT peer-tables iterate them by then */
		hash = ptable->pt_hash;
		if (hash == NULL) /* not intialized */
			break;

		LASSERT(cfs_list_empty(&ptable->pt_deathrow));

		ptable->pt_hash = NULL;
		for (j = 0; j < LNET_PEER_HASH_SIZE; j++)
			LASSERT(cfs_list_empty(&hash[j]));

		LIBCFS_FREE(hash, LNET_PEER_HASH_SIZE * sizeof(*hash));
	} while (0);

	LIBCFS_FREE(ptable, sizeof(*ptable));
	the_lnet.ln_peer_table = NULL;
}

void
lnet_peer_table_cleanup(void)
{
	struct lnet_peer_table	*ptable;
	int			j;

	LASSERT(the_lnet.ln_shutdown);	/* i.e. no new peers */
	ptable = the_lnet.ln_peer_table;

	do { /* we will have per CPT peer-tables iterate them by then */
		LNET_LOCK();

		for (j = 0; j < LNET_PEER_HASH_SIZE; j++) {
			cfs_list_t *peers = &ptable->pt_hash[j];

			while (!cfs_list_empty(peers)) {
				lnet_peer_t *lp = cfs_list_entry(peers->next,
								 lnet_peer_t,
								 lp_hashlist);
				cfs_list_del_init(&lp->lp_hashlist);
				/* lose hash table's ref */
				lnet_peer_decref_locked(lp);
			}
		}

		LNET_UNLOCK();
	} while (0);

	do { /* we will have per CPT peer-tables iterate them by then */
		CFS_LIST_HEAD	(deathrow);
		lnet_peer_t	*lp;

		LNET_LOCK();

		for (j = 3; ptable->pt_number != 0; j++) {
			LNET_UNLOCK();

			if ((j & (j - 1)) == 0) {
				CDEBUG(D_WARNING,
				       "Waiting for %d peers on peer table\n",
				       ptable->pt_number);
			}
			cfs_pause(cfs_time_seconds(1) / 2);
			LNET_LOCK();
		}
		cfs_list_splice_init(&ptable->pt_deathrow, &deathrow);

		LNET_UNLOCK();

		while (!cfs_list_empty(&deathrow)) {
			lp = cfs_list_entry(deathrow.next,
					    lnet_peer_t, lp_hashlist);
			cfs_list_del(&lp->lp_hashlist);
			LIBCFS_FREE(lp, sizeof(*lp));
		}
	} while (0);
}

void
lnet_destroy_peer_locked(lnet_peer_t *lp)
{
	struct lnet_peer_table *ptable = the_lnet.ln_peer_table;

	LASSERT(lp->lp_refcount == 0);
	LASSERT(lp->lp_rtr_refcount == 0);
	LASSERT(cfs_list_empty(&lp->lp_txq));
	LASSERT(cfs_list_empty(&lp->lp_hashlist));
	LASSERT(lp->lp_txqnob == 0);

	LASSERT(ptable->pt_number > 0);
	ptable->pt_number--;

	lnet_ni_decref_locked(lp->lp_ni);
	lp->lp_ni = NULL;

	cfs_list_add(&lp->lp_hashlist, &ptable->pt_deathrow);
}

lnet_peer_t *
lnet_find_peer_locked(lnet_nid_t nid)
{
	cfs_list_t	*peers;
	lnet_peer_t	*lp;

	if (the_lnet.ln_shutdown)
		return NULL;

	peers = &the_lnet.ln_peer_table->pt_hash[lnet_nid2peerhash(nid)];
	cfs_list_for_each_entry(lp, peers, lp_hashlist) {
		if (lp->lp_nid == nid) {
			lnet_peer_addref_locked(lp);
			return lp;
		}
	}

	return NULL;
}

int
lnet_nid2peer_locked(lnet_peer_t **lpp, lnet_nid_t nid)
{
	struct lnet_peer_table	*ptable = the_lnet.ln_peer_table;
	lnet_peer_t		*lp = NULL;
	lnet_peer_t		*lp2;

        lp = lnet_find_peer_locked(nid);
        if (lp != NULL) {
                *lpp = lp;
                return 0;
        }

	if (!cfs_list_empty(&ptable->pt_deathrow)) {
		lp = cfs_list_entry(ptable->pt_deathrow.next,
				    lnet_peer_t, lp_hashlist);
		cfs_list_del(&lp->lp_hashlist);
	}

	LNET_UNLOCK();

	if (lp != NULL)
		memset(lp, 0, sizeof(*lp));
	else
		LIBCFS_ALLOC(lp, sizeof(*lp));

	if (lp == NULL) {
                *lpp = NULL;
                LNET_LOCK();
                return -ENOMEM;
        }

	CFS_INIT_LIST_HEAD(&lp->lp_txq);
        CFS_INIT_LIST_HEAD(&lp->lp_rtrq);
	CFS_INIT_LIST_HEAD(&lp->lp_routes);

        lp->lp_notify = 0;
        lp->lp_notifylnd = 0;
        lp->lp_notifying = 0;
        lp->lp_alive_count = 0;
        lp->lp_timestamp = 0;
        lp->lp_alive = !lnet_peers_start_down(); /* 1 bit!! */
        lp->lp_last_alive = cfs_time_current(); /* assumes alive */
        lp->lp_last_query = 0; /* haven't asked NI yet */
        lp->lp_ping_timestamp = 0;
	lp->lp_ping_version = LNET_PROTO_PING_UNKNOWN;
        lp->lp_nid = nid;
        lp->lp_refcount = 2;                    /* 1 for caller; 1 for hash */
        lp->lp_rtr_refcount = 0;

        LNET_LOCK();

        lp2 = lnet_find_peer_locked(nid);
        if (lp2 != NULL) {
		cfs_list_add(&lp->lp_hashlist, &ptable->pt_deathrow);

                if (the_lnet.ln_shutdown) {
                        lnet_peer_decref_locked(lp2);
                        *lpp = NULL;
                        return -ESHUTDOWN;
                }

                *lpp = lp2;
                return 0;
        }
                
        lp->lp_ni = lnet_net2ni_locked(LNET_NIDNET(nid));
        if (lp->lp_ni == NULL) {
		cfs_list_add(&lp->lp_hashlist, &ptable->pt_deathrow);

                *lpp = NULL;
                return the_lnet.ln_shutdown ? -ESHUTDOWN : -EHOSTUNREACH;
        }

        lp->lp_txcredits    =
        lp->lp_mintxcredits = lp->lp_ni->ni_peertxcredits;
        lp->lp_rtrcredits    =
        lp->lp_minrtrcredits = lnet_peer_buffer_credits(lp->lp_ni);

        /* can't add peers after shutdown starts */
        LASSERT (!the_lnet.ln_shutdown);

	cfs_list_add_tail(&lp->lp_hashlist,
			  &ptable->pt_hash[lnet_nid2peerhash(nid)]);
	ptable->pt_version++;
	ptable->pt_number++;

	*lpp = lp;
	return 0;
}

void
lnet_debug_peer(lnet_nid_t nid)
{
        char        *aliveness = "NA";
        int          rc;
        lnet_peer_t *lp;

        LNET_LOCK();

        rc = lnet_nid2peer_locked(&lp, nid);
        if (rc != 0) {
                LNET_UNLOCK();
                CDEBUG(D_WARNING, "No peer %s\n", libcfs_nid2str(nid));
                return;
        }

        if (lnet_isrouter(lp) || lnet_peer_aliveness_enabled(lp))
                aliveness = lp->lp_alive ? "up" : "down";

        CDEBUG(D_WARNING, "%-24s %4d %5s %5d %5d %5d %5d %5d %ld\n",
               libcfs_nid2str(lp->lp_nid), lp->lp_refcount,
               aliveness, lp->lp_ni->ni_peertxcredits,
               lp->lp_rtrcredits, lp->lp_minrtrcredits,
               lp->lp_txcredits, lp->lp_mintxcredits, lp->lp_txqnob);

        lnet_peer_decref_locked(lp);

        LNET_UNLOCK();
}
