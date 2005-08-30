/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals
 *   http://sourceforge.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "router.h"

#ifdef __KERNEL__

kpr_state_t kpr_state;

static int forwarding = 0;
CFS_MODULE_PARM(forwarding, "i", int, 0444,
                "Boolean: set non-zero to forward between networks");

static char *routes = "";
CFS_MODULE_PARM(routes, "s", charp, 0444,
                "routes to non-local networks");

int
kpr_forwarding ()
{
        return forwarding;
}

void
kpr_do_upcall (void *arg)
{
        kpr_upcall_t *u = (kpr_upcall_t *)arg;
        char          nidstr[36];
        char          whenstr[36];
        char         *argv[] = {
                NULL,
                "ROUTER_NOTIFY",
                nidstr,
                u->kpru_alive ? "up" : "down",
                whenstr,
                NULL};

        snprintf (nidstr, sizeof(nidstr), "%s", libcfs_nid2str(u->kpru_nid));
        snprintf (whenstr, sizeof(whenstr), "%ld", u->kpru_when);

        portals_run_upcall (argv);

        PORTAL_FREE(u, sizeof(*u));
}

void
kpr_upcall (lnet_nid_t gw_nid, int alive, time_t when)
{
        /* May be in arbitrary context */
        kpr_upcall_t  *u;

        PORTAL_ALLOC_ATOMIC(u, sizeof(*u));
        if (u == NULL) {
                CERROR ("Upcall out of memory: nid %s %s\n",
                        libcfs_nid2str(gw_nid), alive ? "up" : "down");
                return;
        }

        u->kpru_nid        = gw_nid;
        u->kpru_alive      = alive;
        u->kpru_when       = when;

        prepare_work (&u->kpru_tq, kpr_do_upcall, u);
        schedule_work (&u->kpru_tq);
}

int
kpr_notify (ptl_ni_t *ni, lnet_nid_t gateway_nid, int alive, time_t when)
{
	unsigned long	     flags;
        int                  found;
        kpr_gateway_entry_t *ge = NULL;
        struct timeval       now;
	struct list_head    *e;
	struct list_head    *n;

        CDEBUG (D_NET, "%s notifying %s: %s\n", 
                (ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
                libcfs_nid2str(gateway_nid),
                alive ? "up" : "down");
        
        if (ni != NULL &&
            PTL_NIDNET(ni->ni_nid) != PTL_NIDNET(gateway_nid)) {
                CWARN ("Ignoring notification of %s %s by %s (different net)\n",
                        libcfs_nid2str(gateway_nid), alive ? "birth" : "death",
                        libcfs_nid2str(ni->ni_nid));
                return -EINVAL;
        }
        
        /* can't do predictions... */
        do_gettimeofday (&now);
        if (when > now.tv_sec) {
                CWARN ("Ignoring prediction from %s of %s %s "
                       "%ld seconds in the future\n", 
                       (ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
                       libcfs_nid2str(gateway_nid), alive ? "up" : "down", 
                       when - now.tv_sec);
                return -EINVAL;
        }

        /* Serialise with lookups (i.e. write lock) */
	write_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        found = 0;
        list_for_each_safe (e, n, &kpr_state.kpr_gateways) {

                ge = list_entry(e, kpr_gateway_entry_t, kpge_list);
                if (ge->kpge_nid != gateway_nid)
                        continue;

                found = 1;
                break;
        }

        if (!found) {
                /* gateway not found */
                write_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                CDEBUG (D_NET, "Gateway not found\n");
                return (0);
        }
        
        if (when < ge->kpge_timestamp) {
                /* out of date information */
                write_unlock_irqrestore (&kpr_state.kpr_rwlock, flags);
                CDEBUG (D_NET, "Out of date\n");
                return (0);
        }

        /* update timestamp */
        ge->kpge_timestamp = when;

        if ((!ge->kpge_alive) == (!alive)) {
                /* new date for old news */
                write_unlock_irqrestore (&kpr_state.kpr_rwlock, flags);
                CDEBUG (D_NET, "Old news\n");
                return (0);
        }

        ge->kpge_alive = alive;
        CDEBUG(D_NET, "set %s [%p] %d\n", 
               libcfs_nid2str(gateway_nid), ge, alive);

        if (alive) {
                /* Reset all gateway weights so the newly-enabled gateway
                 * doesn't have to play catch-up */
                list_for_each_safe (e, n, &kpr_state.kpr_gateways) {
                        kpr_gateway_entry_t *ge = list_entry(e, kpr_gateway_entry_t,
                                                             kpge_list);
                        atomic_set (&ge->kpge_weight, 0);
                }
        }

        write_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);

        if (ni == NULL) {
                /* userland notified me: notify NAL? */
                ni = ptl_net2ni(PTL_NIDNET(gateway_nid));
                if (ni != NULL) {
                        ni->ni_nal->nal_notify(ni, gateway_nid, alive);
                        ptl_ni_decref(ni);
                }
        } else {
                /* It wasn't userland that notified me... */
                CWARN ("Upcall: NID %s is %s\n",
                       libcfs_nid2str(gateway_nid),
                       alive ? "alive" : "dead");
                kpr_upcall (gateway_nid, alive, when);
        }

        return (0);
}

int
kpr_ge_isbetter (kpr_gateway_entry_t *ge1, kpr_gateway_entry_t *ge2)
{
        const int significant_bits = 0x00ffffff;
        /* We use atomic_t to record/compare route weights for
         * load-balancing.  Here we limit ourselves to only using
         * 'significant_bits' when we do an 'after' comparison */

        int    diff = (atomic_read (&ge1->kpge_weight) -
                       atomic_read (&ge2->kpge_weight)) & significant_bits;
        int    rc = (diff > (significant_bits >> 1));

        CDEBUG(D_NET, "[%p]"LPX64"=%d %s [%p]"LPX64"=%d\n",
               ge1, ge1->kpge_nid, atomic_read (&ge1->kpge_weight),
               rc ? ">" : "<",
               ge2, ge2->kpge_nid, atomic_read (&ge2->kpge_weight));

        return (rc);
}

void
kpr_update_weight (kpr_gateway_entry_t *ge, int nob)
{
        int weight = 1 + (nob + sizeof (ptl_hdr_t)/2)/sizeof (ptl_hdr_t);

        /* We've chosen this route entry (i.e. gateway) to forward payload
         * of length 'nob'; update the route's weight to make it less
         * favoured.  Note that the weight is 1 plus the payload size
         * rounded and scaled to the portals header size, so we get better
         * use of the significant bits in kpge_weight. */

        CDEBUG(D_NET, "gateway [%p]"LPX64" += %d\n", ge,
               ge->kpge_nid, weight);
        
        atomic_add (weight, &ge->kpge_weight);
}

lnet_nid_t
kpr_lookup (ptl_ni_t **nip, lnet_nid_t target_nid, int nob)
{
        ptl_ni_t            *ni = *nip;
        lnet_nid_t            gwnid;
	struct list_head    *e;
        kpr_net_entry_t     *ne = NULL;
        kpr_route_entry_t   *re;
        int                  found;
        unsigned long        flags;
        ptl_ni_t            *gwni = NULL;
        ptl_ni_t            *tmpni = NULL;
        kpr_gateway_entry_t *ge = NULL;
        __u32                target_net = PTL_NIDNET(target_nid);

        /* Return the NID I must send to, to reach 'target_nid' */
        
        CDEBUG (D_NET, "lookup "LPX64" from %s\n", target_nid, 
                (ni == NULL) ? "<>" : libcfs_nid2str(ni->ni_nid));

        if (ni == NULL) {                       /* ni not determined yet */
                gwni = ptl_net2ni(target_net);  /* is it a local network? */
                if (gwni != NULL) {
                        *nip = gwni;
                        return target_nid;
                }
        } else {                                /* ni already determined */
                if (PTL_NETNAL(PTL_NIDNET(ni->ni_nid)) == LONAL ||
                    target_net == PTL_NIDNET(ni->ni_nid)) {
                        ptl_ni_addref(ni);      /* extra ref so caller can drop blindly */
                        return target_nid;
                }
        }
        
        CDEBUG(D_NET, "%s from %s\n", libcfs_nid2str(target_nid),
               (ni == NULL) ? "<none>" : libcfs_nid2str(ni->ni_nid));

	read_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        if (ni != NULL && ni->ni_shutdown) {
                /* pre-determined ni is shutting down */
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
		return LNET_NID_ANY;
        }

	/* Search routes for one that has a gateway to target_nid on the callers network */
        found = 0;
        list_for_each (e, &kpr_state.kpr_nets) {
		ne = list_entry (e, kpr_net_entry_t, kpne_list);
                
                found = ne->kpne_net == target_net;
                if (found)
                        break;
        }
        
        if (!found) {
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                return LNET_NID_ANY;
        }
        
	/* Search routes for one that has a gateway to target_nid on the callers network */
        list_for_each (e, &ne->kpne_routes) {
		re = list_entry (e, kpr_route_entry_t, kpre_list);

                if (!re->kpre_gateway->kpge_alive) /* gateway down */
                        continue;
                
                if (ni != NULL) {
                        /* local ni determined */
                        if (PTL_NIDNET(ni->ni_nid) != /* gateway not on ni's net */
                            PTL_NIDNET(re->kpre_gateway->kpge_nid))
                                continue;

                        if (ge != NULL &&
                            kpr_ge_isbetter (ge, re->kpre_gateway))
                                continue;

                } else if (gwni != NULL &&
                           PTL_NIDNET(gwni->ni_nid) ==
                           PTL_NIDNET(ge->kpge_nid)) {
                        /* another gateway on the same net */

                        if (kpr_ge_isbetter(ge, re->kpre_gateway))
                                continue;
                } else {
                        /* another gateway on a new/different net */

                        tmpni = ptl_net2ni(PTL_NIDNET(re->kpre_gateway->kpge_nid));
                        if (tmpni == NULL)      /* gateway not on a local net */
                                continue;
                
                        if (ge != NULL &&
                            kpr_ge_isbetter(ge, re->kpre_gateway)) {
                                ptl_ni_decref(tmpni);
                                continue;
                        }
                        
                        if (gwni != NULL)
                                ptl_ni_decref(gwni);
                        gwni = tmpni;
                }

                ge = re->kpre_gateway;
	}

        if (ge == NULL) {
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                LASSERT (gwni == NULL);
                
                return LNET_NID_ANY;
        }
        
        kpr_update_weight(ge, nob);
        gwnid = ge->kpge_nid;
	read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
        
        /* NB can't deref 're/ge' after lock released! */
        CDEBUG (D_NET, "lookup %s from %s: %s\n",
                libcfs_nid2str(target_nid),
                (ni == NULL) ? "<>" : libcfs_nid2str(ni->ni_nid),
                libcfs_nid2str(gwnid));

        LASSERT ((gwni == NULL) != (ni == NULL));

        if (ni != NULL)
                ptl_ni_addref(ni);              /* extra ref so caller can drop blindly */
        else
                *nip = gwni;                    /* already got a ref */

	return gwnid;
}

void
kpr_fwd_start (ptl_ni_t *src_ni, kpr_fwd_desc_t *fwd)
{
	lnet_nid_t            target_nid = fwd->kprfd_target_nid;
        __u32                target_net = PTL_NIDNET(target_nid);
        __u32                receiver_net = PTL_NIDNET(src_ni->ni_nid);
        int                  nob = fwd->kprfd_nob;
        kpr_gateway_entry_t *ge;
        ptl_ni_t            *dst_ni;
        ptl_ni_t            *tmp_ni;
        unsigned long        flags;
	struct list_head    *e;
        kpr_net_entry_t     *ne = NULL;
        kpr_route_entry_t   *re;
        int                  rc;
        int                  found;

        CDEBUG (D_NET, "src %s sender %s receiver %s target %s\n", 
                libcfs_nid2str(fwd->kprfd_source_nid),
                libcfs_nid2str(fwd->kprfd_sender_nid),
                libcfs_nid2str(src_ni->ni_nid),
                libcfs_nid2str(target_nid));

        LASSERT (nob == ptl_kiov_nob (fwd->kprfd_niov, fwd->kprfd_kiov));

        /* it's not for any local NID (i.e. it's going to get sent) */
        LASSERT (!ptl_islocalnid(target_nid));

	fwd->kprfd_src_ni = src_ni;             /* stash calling ni */

	read_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        spin_lock(&kpr_state.kpr_stats_lock);
        kpr_state.kpr_fwd_packets++;
        kpr_state.kpr_fwd_bytes += nob + sizeof(ptl_hdr_t);
        spin_unlock(&kpr_state.kpr_stats_lock);

        rc = -EDESTADDRREQ;
        if (target_net == receiver_net) {
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                LCONSOLE_ERROR("Refusing to forward message from %s for %s "
                               "received from %s on %s: it should have been "
                               "sent directly\n",
                               libcfs_nid2str(fwd->kprfd_source_nid),
                               libcfs_nid2str(fwd->kprfd_target_nid),
                               libcfs_nid2str(fwd->kprfd_sender_nid),
                               libcfs_nid2str(src_ni->ni_nid));
                goto failed;
        }

        rc = -ESHUTDOWN;
	if (src_ni->ni_shutdown) {              /* caller is shutting down */
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                LCONSOLE_ERROR("Refusing to forward message from %s for %s "
                               "received from %s on %s: system shutting down\n",
                               libcfs_nid2str(fwd->kprfd_source_nid),
                               libcfs_nid2str(fwd->kprfd_target_nid),
                               libcfs_nid2str(fwd->kprfd_sender_nid),
                               libcfs_nid2str(src_ni->ni_nid));
		goto failed;
        }
        
        rc = -ENETUNREACH;
        if (!kpr_forwarding()) {                /* I'm not a router */
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                LCONSOLE_ERROR("Refusing to forward message from %s for %s "
                               "received from %s on %s: forwarding disabled!\n",
                               libcfs_nid2str(fwd->kprfd_source_nid),
                               libcfs_nid2str(fwd->kprfd_target_nid),
                               libcfs_nid2str(fwd->kprfd_sender_nid),
                               libcfs_nid2str(src_ni->ni_nid));
                goto failed;
        }
        
        /* Is the target_nid on a local network? */
        dst_ni = ptl_net2ni(target_net);
        if (dst_ni != NULL) {
                if (dst_ni->ni_nal->nal_fwd == NULL) {
                        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                        LCONSOLE_ERROR("Refusing to forward message from %s for %s "
                                       "received from %s on %s: "
                                       "net %s doesn't route!\n",
                                       libcfs_nid2str(fwd->kprfd_source_nid),
                                       libcfs_nid2str(fwd->kprfd_target_nid),
                                       libcfs_nid2str(fwd->kprfd_sender_nid),
                                       libcfs_nid2str(src_ni->ni_nid),
                                       libcfs_net2str(PTL_NIDNET(dst_ni->ni_nid)));
                        goto failed;
                }
                
                fwd->kprfd_gateway_nid = target_nid;
                atomic_inc (&kpr_state.kpr_queue_depth);

                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);

                CDEBUG (D_NET, "forward [%p] %s: src ni %s dst ni %s\n",
                        fwd, libcfs_nid2str(target_nid),
                        libcfs_nid2str(src_ni->ni_nid),
                        libcfs_nid2str(dst_ni->ni_nid));

                dst_ni->ni_nal->nal_fwd(dst_ni, fwd);
                ptl_ni_decref(dst_ni);
                return;
        }

        /* Search nets */
        found = 0;
        list_for_each (e, &kpr_state.kpr_nets) {
                ne = list_entry (e, kpr_net_entry_t, kpne_list);

                found = (ne->kpne_net == target_net);
                if (found)
                        break;
        }

        if (!found) {
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                LCONSOLE_ERROR("Can't forward message from %s for %s "
                               "received from %s on %s: "
                               "no routes to destination network!\n",
                               libcfs_nid2str(fwd->kprfd_source_nid),
                               libcfs_nid2str(fwd->kprfd_target_nid),
                               libcfs_nid2str(fwd->kprfd_sender_nid),
                               libcfs_nid2str(src_ni->ni_nid));
                goto failed;
        }
        
	/* Search routes for one that has a gateway to target_nid NOT on the caller's network */
        dst_ni = NULL;
        ge = NULL;
        list_for_each (e, &ne->kpne_routes) {
		re = list_entry (e, kpr_route_entry_t, kpre_list);

		if (PTL_NIDNET(re->kpre_gateway->kpge_nid) == receiver_net)
			continue;               /* don't route to same net */

                if (!re->kpre_gateway->kpge_alive)
                        continue;               /* gateway is dead */

                tmp_ni = ptl_net2ni(PTL_NIDNET(re->kpre_gateway->kpge_nid));
                if (tmp_ni == NULL)
                        continue;

                if (tmp_ni->ni_nal->nal_fwd == NULL) { 
                        ptl_ni_decref(tmp_ni);  /* doesn't forward */
                        continue;
                }
                
                if (ge != NULL &&
                    kpr_ge_isbetter(ge, re->kpre_gateway)) {
                        ptl_ni_decref(tmp_ni);
                        continue;
                }
                
                if (dst_ni != NULL)
                        ptl_ni_decref(dst_ni);
                                
                dst_ni = tmp_ni;
                ge = re->kpre_gateway;
        }

        LASSERT ((ge == NULL) == (dst_ni == NULL));
        
        if (ge == NULL) {
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                LCONSOLE_ERROR("Can't forward message from %s for %s "
                               "received from %s on %s: "
                               "all relevant gateways are down!\n",
                               libcfs_nid2str(fwd->kprfd_source_nid),
                               libcfs_nid2str(fwd->kprfd_target_nid),
                               libcfs_nid2str(fwd->kprfd_sender_nid),
                               libcfs_nid2str(src_ni->ni_nid));
                goto failed;
        }
        
        kpr_update_weight (ge, nob);

        fwd->kprfd_gateway_nid = ge->kpge_nid;
        atomic_inc (&kpr_state.kpr_queue_depth);

        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);

        CDEBUG (D_NET, "forward [%p] %s: src ni %s dst ni %s gw %s\n",
                fwd, libcfs_nid2str(target_nid),
                libcfs_nid2str(src_ni->ni_nid),
                libcfs_nid2str(dst_ni->ni_nid),
                libcfs_nid2str(fwd->kprfd_gateway_nid));

        dst_ni->ni_nal->nal_fwd(dst_ni, fwd);
        ptl_ni_decref(dst_ni);
        return;

 failed:
        spin_lock_irqsave(&kpr_state.kpr_stats_lock, flags);
        kpr_state.kpr_fwd_errors++;
        spin_unlock_irqrestore(&kpr_state.kpr_stats_lock, flags);

        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);

        CDEBUG (D_NET, "Failed to forward [%p] %s from %s\n", fwd, 
                libcfs_nid2str(target_nid), libcfs_nid2str(src_ni->ni_nid));

	(fwd->kprfd_callback)(src_ni, fwd->kprfd_callback_arg, rc);
}

void
kpr_fwd_done (ptl_ni_t *dst_ni, kpr_fwd_desc_t *fwd, int error)
{
	ptl_ni_t *src_ni = fwd->kprfd_src_ni;

        CDEBUG (D_NET, "complete(1) [%p] from %s to %s: %d\n", fwd,
                libcfs_nid2str(src_ni->ni_nid),
                libcfs_nid2str(dst_ni->ni_nid), error);

	(fwd->kprfd_callback)(src_ni, fwd->kprfd_callback_arg, error);

        atomic_dec (&kpr_state.kpr_queue_depth);
}

int
kpr_add_route (__u32 net, lnet_nid_t gateway_nid)
{
	unsigned long	     flags;
	struct list_head    *e;
	kpr_net_entry_t     *ne = NULL;
	kpr_route_entry_t   *re = NULL;
        kpr_gateway_entry_t *ge = NULL;
        int                  dup = 0;

        CDEBUG(D_NET, "Add route: net %s : gw %s\n",
               libcfs_net2str(net), libcfs_nid2str(gateway_nid));

        if (gateway_nid == LNET_NID_ANY)
                return (-EINVAL);

        /* Assume net, route, gateway all new */
        PORTAL_ALLOC(ge, sizeof(*ge));
        PORTAL_ALLOC(re, sizeof(*re));
        PORTAL_ALLOC(ne, sizeof(*ne));

        if (ge == NULL || re == NULL || ne == NULL) {
                if (ge != NULL)
                        PORTAL_FREE(ge, sizeof(*ge));
                if (re != NULL)
                        PORTAL_FREE(re, sizeof(*re));
                if (ne != NULL)
                        PORTAL_FREE(ne, sizeof(*ne));
                return -ENOMEM;
        }

        ge->kpge_nid   = gateway_nid;
        ge->kpge_alive = 1;
        ge->kpge_timestamp = 0;
        ge->kpge_refcount = 0;
        atomic_set (&ge->kpge_weight, 0);

        ne->kpne_net = net;
        INIT_LIST_HEAD(&ne->kpne_routes);
        
        LASSERT(!in_interrupt());
	write_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        list_for_each (e, &kpr_state.kpr_nets) {
                kpr_net_entry_t *ne2 = 
                        list_entry(e, kpr_net_entry_t, kpne_list);
                
                if (ne2->kpne_net == net) {
                        PORTAL_FREE(ne, sizeof(*ne));
                        ne = ne2;
                        dup = 1;
                        break;
                }
        }
        
        if (!dup) { /* Adding a new network? */
                list_add_tail(&ne->kpne_list, &kpr_state.kpr_nets);
        } else {
                dup = 0;
                list_for_each (e, &ne->kpne_routes) {
                        kpr_route_entry_t *re2 = 
                                list_entry(e, kpr_route_entry_t, kpre_list);
                        
                        dup = (re2->kpre_gateway->kpge_nid == gateway_nid);
                        if (dup)
                                break;
                }
                
                if (dup) { /* Ignore duplicate route entry */
                        write_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);

                        PORTAL_FREE(re, sizeof(*re));
                        PORTAL_FREE(ge, sizeof(*ge));
                        return 0;
                }
        }

        list_add_tail(&re->kpre_list, &ne->kpne_routes);
                
        list_for_each (e, &kpr_state.kpr_gateways) {
                kpr_gateway_entry_t *ge2 = 
                        list_entry(e, kpr_gateway_entry_t, kpge_list);

                if (ge2->kpge_nid == gateway_nid) {
                        PORTAL_FREE (ge, sizeof (*ge));
                        ge = ge2;
                        dup = 1;
                        break;
                }
        }

        if (!dup) {
                /* Adding a new gateway... */
                list_add (&ge->kpge_list, &kpr_state.kpr_gateways);

                /* ...zero all gateway weights so this one doesn't have to
                 * play catch-up */

                list_for_each (e, &kpr_state.kpr_gateways) {
                        kpr_gateway_entry_t *ge2 = list_entry(e, kpr_gateway_entry_t,
                                                              kpge_list);
                        atomic_set (&ge2->kpge_weight, 0);
                }
        }

        re->kpre_gateway = ge;
        ge->kpge_refcount++;
        kpr_state.kpr_generation++;

        write_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
        return 0;
}

int
kpr_del_route (__u32 net, lnet_nid_t gw_nid)
{
        unsigned long        flags;
        kpr_net_entry_t     *ne;
        kpr_route_entry_t   *re;
        kpr_gateway_entry_t *ge;
        struct list_head    *e1;
        struct list_head    *n1;
        struct list_head    *e2;
        struct list_head    *n2;
        int                  rc = -ENOENT;

        CDEBUG(D_NET, "Del route: net %s : gw %s\n",
               libcfs_net2str(net), libcfs_nid2str(gw_nid));
        LASSERT(!in_interrupt());

        /* NB Caller may specify either all routes via the given gateway
         * or a specific route entry actual NIDs) */

        write_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        list_for_each_safe (e1, n1, &kpr_state.kpr_nets) {
                ne = list_entry(e1, kpr_net_entry_t, kpne_list);
                
                if (!(net != PTL_NIDNET(LNET_NID_ANY) ||
                      net == ne->kpne_net))
                        continue;
                
                list_for_each_safe (e2, n2, &ne->kpne_routes) {
                        re = list_entry(e2, kpr_route_entry_t, kpre_list);
                        ge = re->kpre_gateway;
                        
                        if (!(gw_nid == LNET_NID_ANY ||
                              gw_nid == ge->kpge_nid))
                                continue;

                        rc = 0;

                        if (--ge->kpge_refcount == 0) {
                                list_del (&ge->kpge_list);
                                PORTAL_FREE (ge, sizeof (*ge));
                        }

                        list_del(&re->kpre_list);
                        PORTAL_FREE(re, sizeof (*re));
                }

                if (list_empty(&ne->kpne_routes)) {
                        list_del(&ne->kpne_list);
                        PORTAL_FREE(ne, sizeof(*ne));
                }
        }

        if (rc == 0)
                kpr_state.kpr_generation++;

        write_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);

        return rc;
}

int
kpr_get_route (int idx, __u32 *net, lnet_nid_t *gateway_nid, __u32 *alive)
{
	struct list_head    *e1;
	struct list_head    *e2;
        kpr_net_entry_t     *ne;
        kpr_route_entry_t   *re;
        kpr_gateway_entry_t *ge;
        unsigned long        flags;

        LASSERT (!in_interrupt());
	read_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        list_for_each (e1, &kpr_state.kpr_nets) {
                ne = list_entry(e1, kpr_net_entry_t, kpne_list);
                
                list_for_each (e2, &ne->kpne_routes) {
                        re = list_entry(e2, kpr_route_entry_t, kpre_list);
                        ge = re->kpre_gateway;
                
                        if (idx-- == 0) {
                                *net = ne->kpne_net;
                                *gateway_nid = ge->kpge_nid;
                                *alive = ge->kpge_alive;

                                read_unlock_irqrestore(&kpr_state.kpr_rwlock, 
                                                       flags);
                                return 0;
                        }
                }
        }
        
        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
        return -ENOENT;
}

int 
kpr_ctl(unsigned int cmd, void *arg)
{
        struct portal_ioctl_data *data = arg;

        switch(cmd) {
        default:
                return -EINVAL;
                
        case IOC_PORTAL_ADD_ROUTE:
                return kpr_add_route(data->ioc_net, data->ioc_nid);

        case IOC_PORTAL_DEL_ROUTE:
                return kpr_del_route (data->ioc_net, data->ioc_nid);

        case IOC_PORTAL_GET_ROUTE:
                return kpr_get_route(data->ioc_count, &data->ioc_net,
                                     &data->ioc_nid, &data->ioc_flags);

        case IOC_PORTAL_NOTIFY_ROUTER:
                return kpr_notify(NULL, data->ioc_nid, data->ioc_flags, 
                                  (time_t)data->ioc_u64[0]);
        }
}


void
kpr_finalise (void)
{
        kpr_proc_fini();

        while (!list_empty (&kpr_state.kpr_nets)) {
                kpr_net_entry_t *ne = list_entry(kpr_state.kpr_nets.next,
                                                 kpr_net_entry_t, kpne_list);
                
                while (!list_empty (&ne->kpne_routes)) {
                        kpr_route_entry_t *re = list_entry(ne->kpne_routes.next,
                                                           kpr_route_entry_t,
                                                           kpre_list);

                        list_del(&re->kpre_list);
                        PORTAL_FREE(re, sizeof(*re));
                }

                list_del(&ne->kpne_list);
                PORTAL_FREE(ne, sizeof(*ne));
        }

        while (!list_empty (&kpr_state.kpr_gateways)) {
                kpr_gateway_entry_t *ge = list_entry(kpr_state.kpr_gateways.next,
                                                     kpr_gateway_entry_t,
                                                     kpge_list);

                list_del(&ge->kpge_list);
                PORTAL_FREE(ge, sizeof (*ge));
        }

        CDEBUG(D_MALLOC, "kpr_finalise: kmem back to %d\n",
               atomic_read(&portal_kmemory));
}

int
kpr_initialise (void)
{
        int     rc;
        
        CDEBUG(D_MALLOC, "kpr_initialise: kmem %d\n",
               atomic_read(&portal_kmemory));

        memset(&kpr_state, 0, sizeof(kpr_state));

        INIT_LIST_HEAD(&kpr_state.kpr_nets);
        INIT_LIST_HEAD(&kpr_state.kpr_gateways);
        rwlock_init(&kpr_state.kpr_rwlock);
        spin_lock_init(&kpr_state.kpr_stats_lock);

        rc = ptl_parse_routes(routes);
        if (rc != 0)
                kpr_finalise();

        if (rc == 0)
                kpr_proc_init();

        return (rc == 0) ? 0 : -EINVAL;
}

EXPORT_SYMBOL(kpr_forwarding);
EXPORT_SYMBOL(kpr_lookup);
EXPORT_SYMBOL(kpr_fwd_start);
EXPORT_SYMBOL(kpr_fwd_done);
EXPORT_SYMBOL(kpr_notify);

#else

lnet_nid_t
kpr_lookup (ptl_ni_t **nip, lnet_nid_t target_nid, int nob)
{
        ptl_ni_t            *ni = *nip;
        ptl_ni_t            *gwni;
        __u32                target_net = PTL_NIDNET(target_nid);

        if (ni == NULL) {                       /* ni not determined yet */
                gwni = ptl_net2ni(target_net);  /* is it a local network? */
                if (gwni != NULL) {
                        *nip = gwni;
                        return target_nid;
                }
        } else {                                /* ni already determined */
                if (target_net == PTL_NIDNET(ni->ni_nid)) {
                        ptl_ni_addref(ni);      /* extra ref so caller can drop blindly */
                        return target_nid;
                }
        }

        CERROR("Nid %s is not on a local network and "
               "userspace portals does not support routing\n",
               libcfs_nid2str(target_nid));

        return LNET_NID_ANY;
}

int
kpr_add_route (__u32 net, lnet_nid_t gateway_nid)
{
        return -EOPNOTSUPP;
}

int 
kpr_ctl(unsigned int cmd, void *arg)
{
        return -EINVAL;
}

void
kpr_finalise (void)
{
}

int
kpr_initialise (void)
{
        return 0;
}

#endif
