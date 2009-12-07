/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
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
lnet_create_peer_table(void)
{
	struct list_head *hash;
	int               i;

	LASSERT (the_lnet.ln_peer_hash == NULL);
	LIBCFS_ALLOC(hash, LNET_PEER_HASHSIZE * sizeof(struct list_head));
	
	if (hash == NULL) {
		CERROR("Can't allocate peer hash table\n");
		return -ENOMEM;
	}

	for (i = 0; i < LNET_PEER_HASHSIZE; i++)
		CFS_INIT_LIST_HEAD(&hash[i]);

	the_lnet.ln_peer_hash = hash;
	return 0;
}

void
lnet_destroy_peer_table(void)
{
	int         i;

        if (the_lnet.ln_peer_hash == NULL)
                return;

	for (i = 0; i < LNET_PEER_HASHSIZE; i++)
		LASSERT (list_empty(&the_lnet.ln_peer_hash[i]));
	
	LIBCFS_FREE(the_lnet.ln_peer_hash,
		    LNET_PEER_HASHSIZE * sizeof (struct list_head));
        the_lnet.ln_peer_hash = NULL;
}

void
lnet_clear_peer_table(void)
{
	int         i;

        LASSERT (the_lnet.ln_shutdown);         /* i.e. no new peers */
	
	for (i = 0; i < LNET_PEER_HASHSIZE; i++) {
		struct list_head *peers = &the_lnet.ln_peer_hash[i];

		LNET_LOCK();
		while (!list_empty(peers)) {
			lnet_peer_t *lp = list_entry(peers->next,
						     lnet_peer_t, lp_hashlist);
			
			list_del(&lp->lp_hashlist);
                        lnet_peer_decref_locked(lp);   /* lose hash table's ref */
		}
		LNET_UNLOCK();
	}

        LNET_LOCK();
        for (i = 3; the_lnet.ln_npeers != 0;i++) {
                LNET_UNLOCK();

                if ((i & (i-1)) == 0)
                        CDEBUG(D_WARNING,"Waiting for %d peers\n", 
                               the_lnet.ln_npeers);
                cfs_pause(cfs_time_seconds(1));

                LNET_LOCK();
        }
        LNET_UNLOCK();
}

void
lnet_destroy_peer_locked (lnet_peer_t *lp) 
{
        lnet_ni_decref_locked(lp->lp_ni);
        LNET_UNLOCK();

        LASSERT (lp->lp_refcount == 0);
        LASSERT (lp->lp_rtr_refcount == 0);
	LASSERT (list_empty(&lp->lp_txq));
        LASSERT (lp->lp_txqnob == 0);
        LASSERT (lp->lp_rcd == NULL);

	LIBCFS_FREE(lp, sizeof(*lp));

        LNET_LOCK();

        LASSERT(the_lnet.ln_npeers > 0);
        the_lnet.ln_npeers--;
}

lnet_peer_t *
lnet_find_peer_locked (lnet_nid_t nid)
{
	unsigned int      idx = LNET_NIDADDR(nid) % LNET_PEER_HASHSIZE;
	struct list_head *peers = &the_lnet.ln_peer_hash[idx];
	struct list_head *tmp;
        lnet_peer_t      *lp;

	if (the_lnet.ln_shutdown)
                return NULL;

	list_for_each (tmp, peers) {
		lp = list_entry(tmp, lnet_peer_t, lp_hashlist);
		
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
	lnet_peer_t    *lp;
	lnet_peer_t    *lp2;

        lp = lnet_find_peer_locked(nid);
        if (lp != NULL) {
                *lpp = lp;
                return 0;
        }
        
        LNET_UNLOCK();
	
	LIBCFS_ALLOC(lp, sizeof(*lp));
	if (lp == NULL) {
                *lpp = NULL;
                LNET_LOCK();
                return -ENOMEM;
        }

        memset(lp, 0, sizeof(*lp));             /* zero counters etc */
        
	CFS_INIT_LIST_HEAD(&lp->lp_txq);
        CFS_INIT_LIST_HEAD(&lp->lp_rtrq);
	
        lp->lp_notify = 0;
        lp->lp_notifylnd = 0;
        lp->lp_notifying = 0;
        lp->lp_alive_count = 0;
        lp->lp_timestamp = 0;
        lp->lp_alive = !lnet_peers_start_down(); /* 1 bit!! */
        lp->lp_last_alive = cfs_time_current(); /* assumes alive */
        lp->lp_last_query = 0; /* haven't asked NI yet */
        lp->lp_ping_timestamp = 0;
        lp->lp_nid = nid;
        lp->lp_refcount = 2;                    /* 1 for caller; 1 for hash */
        lp->lp_rtr_refcount = 0;

        LNET_LOCK();

        lp2 = lnet_find_peer_locked(nid);
        if (lp2 != NULL) {
                LNET_UNLOCK();
                LIBCFS_FREE(lp, sizeof(*lp));
                LNET_LOCK();

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
                LNET_UNLOCK();
                LIBCFS_FREE(lp, sizeof(*lp));
                LNET_LOCK();

                *lpp = NULL;
                return the_lnet.ln_shutdown ? -ESHUTDOWN : -EHOSTUNREACH;
        }

        lp->lp_txcredits    =
        lp->lp_mintxcredits = lp->lp_ni->ni_peertxcredits;
        lp->lp_rtrcredits    =
        lp->lp_minrtrcredits = lnet_peer_buffer_credits(lp->lp_ni);

        /* can't add peers after shutdown starts */
        LASSERT (!the_lnet.ln_shutdown);

        list_add_tail(&lp->lp_hashlist, lnet_nid2peerhash(nid));
        the_lnet.ln_npeers++;
        the_lnet.ln_peertable_version++;
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
