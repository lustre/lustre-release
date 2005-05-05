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

struct kpr_state;

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
        char          nidstr[PTL_NALFMT_SIZE];
        char          whenstr[36];
        char         *argv[] = {
                NULL,
                "ROUTER_NOTIFY",
                nidstr,
                u->kpru_alive ? "up" : "down",
                whenstr,
                NULL};

        strcpy(nidstr, libcfs_nid2str(u->kpru_nid));
        snprintf (whenstr, sizeof(whenstr), "%ld", u->kpru_when);

        portals_run_upcall (argv);

        PORTAL_FREE(u, sizeof(*u));
}

void
kpr_upcall (ptl_nid_t gw_nid, int alive, time_t when)
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
kpr_notify (ptl_ni_t *ni, ptl_nid_t gateway_nid, int alive, time_t when)
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

ptl_nid_t
kpr_lookup (ptl_ni_t **nip, ptl_nid_t target_nid, int nob)
{
        ptl_ni_t            *ni = *nip;
        ptl_nid_t            gwnid;
	struct list_head    *e;
        kpr_route_entry_t   *re;
        unsigned long        flags;
        ptl_ni_t            *gwni = NULL;
        ptl_ni_t            *tmpni = NULL;
        kpr_gateway_entry_t *ge = NULL;
	int                  rc = -ENOENT;
        __u32                target_net = PTL_NIDNET(target_nid);
        
        /* Caller wants to know if 'target_nid' can be reached via a gateway
         * ON HER OWN NETWORK */

        CDEBUG (D_NET, "lookup "LPX64" from %s\n", target_nid, 
                (ni == NULL) ? "<>" : libcfs_nid2str(ni->ni_nid));

        if (ni == NULL) {                       /* ni not determined yet */
                gwni = ptl_net2ni(target_net);  /* is it a local network? */
                if (gwni != NULL) {
                        *nip = gwni;
                        return gwni->ni_nid;
                }
        } else if (target_net == PTL_NIDNET(ni->ni_nid)) {
                ptl_ni_addref(ni);    /* extra ref so caller can drop blindly */
                return ni->ni_nid;
        }

	read_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        if (ni != NULL && ni->ni_shutdown) {
                /* pre-determined ni is shutting down */
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
		return PTL_NID_ANY;
        }

	/* Search routes for one that has a gateway to target_nid on the callers network */
        list_for_each (e, &kpr_state.kpr_routes) {
		re = list_entry (e, kpr_route_entry_t, kpre_list);

                if (re->kpre_net != target_net) /* incorrect target net */
			continue;

                if (!re->kpre_gateway->kpge_alive) /* gateway down */
                        continue;
                
                if (ni != NULL) {
                        /* local ni determined */
                        if (PTL_NIDNET(ni->ni_nid) != /* gateway not on ni's net */
                            PTL_NIDNET(re->kpre_gateway->kpge_nid))
                                continue;
                        tmpni = NULL;
                } else {
                        tmpni = ptl_net2ni(PTL_NIDNET(ge->kpge_nid));
                        if (tmpni == NULL)      /* gateway not on a local net */
                                continue;
                }
                
                if (ge == NULL ||
                    kpr_ge_isbetter (re->kpre_gateway, ge)) {
                        if (gwni != NULL)
                                ptl_ni_decref(gwni);
                        ge = re->kpre_gateway;
                        gwni = tmpni;
                } else if (tmpni != NULL) {
                        ptl_ni_decref(tmpni);
                }
	}

        if (ge == NULL) {
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                LASSERT (gwni == NULL);
                
                return PTL_NID_ANY;
        }
        
        kpr_update_weight (ge, nob);
        gwnid = ge->kpge_nid;
	read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
        
        /* NB can't deref 're/ge' after lock released! */
        CDEBUG (D_NET, "lookup %s from %s: %s\n",
                libcfs_nid2str(target_nid),
                (ni == NULL) ? "<>" : libcfs_nid2str(ni->ni_nid),
                libcfs_nid2str(gwnid));

        LASSERT ((gwni == NULL) != (ni == NULL));

        if (gwni == NULL)
                ptl_ni_addref(ni);              /* extra ref so caller can drop blindly */
        else
                *nip = gwni;                    /* already got a ref */

	return gwnid;
}

void
kpr_fwd_start (ptl_ni_t *src_ni, kpr_fwd_desc_t *fwd)
{
	ptl_nid_t            target_nid = fwd->kprfd_target_nid;
        __u32                target_net = PTL_NIDNET(target_nid);
        __u32                source_net = PTL_NIDNET(src_ni->ni_nid);
        int                  nob = fwd->kprfd_nob;
        kpr_gateway_entry_t *ge = NULL;
        ptl_ni_t            *dst_ni = NULL;
        ptl_ni_t            *tmp_ni;
        unsigned long        flags;
	struct list_head    *e;
        kpr_route_entry_t   *re;
        int                  rc;

        CDEBUG (D_NET, "forward [%p] %s from %s\n", fwd,
                libcfs_nid2str(target_nid), libcfs_nid2str(src_ni->ni_nid));

        LASSERT (nob == ptl_kiov_nob (fwd->kprfd_niov, fwd->kprfd_kiov));

	fwd->kprfd_src_ni = src_ni;             /* stash calling ni */

	read_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        spin_lock(&kpr_state.kpr_stats_lock);
        kpr_state.kpr_fwd_packets++;
        kpr_state.kpr_fwd_bytes += nob + sizeof(ptl_hdr_t);
        spin_unlock(&kpr_state.kpr_stats_lock);

        if (!kpr_forwarding()) {
                /* I'm not a router */
                rc = -EHOSTUNREACH;
                goto out;
        }

	if (src_ni->ni_shutdown) {              /* caller is shutting down */
                rc = -ESHUTDOWN;
		goto out;
        }

	/* Search routes for one that has a gateway to target_nid NOT on the caller's network */

        list_for_each (e, &kpr_state.kpr_routes) {
		re = list_entry (e, kpr_route_entry_t, kpre_list);

                if (re->kpre_net != target_net) /* no match */
			continue;

		if (PTL_NIDNET(re->kpre_gateway->kpge_nid) == source_net)
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
                
                if (ge == NULL ||
                    kpr_ge_isbetter (re->kpre_gateway, ge)) {
                        if (dst_ni != NULL)
                                ptl_ni_decref(dst_ni);
                                
                        dst_ni = tmp_ni;
                        ge = re->kpre_gateway;
                }
        }
        
        if (ge != NULL) {
                LASSERT (dst_ni != NULL);
                
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
	}

        rc = -EHOSTUNREACH;
 out:
        spin_lock_irqsave(&kpr_state.kpr_stats_lock, flags);
        kpr_state.kpr_fwd_errors++;
        spin_unlock_irqrestore(&kpr_state.kpr_stats_lock, flags);

        CDEBUG (D_NET, "Failed to forward [%p] %s from %s\n", fwd, 
                libcfs_nid2str(target_nid), libcfs_nid2str(src_ni->ni_nid));

	(fwd->kprfd_callback)(src_ni, fwd->kprfd_callback_arg, rc);

        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
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
kpr_add_route (__u32 net, ptl_nid_t gateway_nid)
{
	unsigned long	     flags;
	struct list_head    *e;
	kpr_route_entry_t   *re;
        kpr_gateway_entry_t *ge;
        int                  dup = 0;

        CDEBUG(D_NET, "Add route: net %s : gw %s\n",
               libcfs_net2str(net), libcfs_nid2str(gateway_nid));

        if (gateway_nid == PTL_NID_ANY)
                return (-EINVAL);

        PORTAL_ALLOC (ge, sizeof (*ge));
        if (ge == NULL)
                return (-ENOMEM);

        ge->kpge_nid   = gateway_nid;
        ge->kpge_alive = 1;
        ge->kpge_timestamp = 0;
        ge->kpge_refcount = 0;
        atomic_set (&ge->kpge_weight, 0);

        PORTAL_ALLOC (re, sizeof (*re));
        if (re == NULL) {
                PORTAL_FREE (ge, sizeof (*ge));
                return (-ENOMEM);
        }

        re->kpre_net = net;

        LASSERT(!in_interrupt());
	write_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        list_for_each (e, &kpr_state.kpr_gateways) {
                kpr_gateway_entry_t *ge2 = list_entry(e, kpr_gateway_entry_t,
                                                      kpge_list);

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
        list_add (&re->kpre_list, &kpr_state.kpr_routes);
        kpr_state.kpr_generation++;

        write_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
        return (0);
}

int
kpr_del_route (__u32 net, ptl_nid_t gw_nid)
{
        unsigned long      flags;
        int                rc = -ENOENT;
        struct list_head  *e;
        struct list_head  *n;

        CDEBUG(D_NET, "Del route: net %s : gw %s\n",
               libcfs_net2str(net), libcfs_nid2str(gw_nid));
        LASSERT(!in_interrupt());

        /* NB Caller may specify either all routes via the given gateway
         * or a specific route entry actual NIDs) */

        write_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        list_for_each_safe (e, n, &kpr_state.kpr_routes) {
                kpr_route_entry_t   *re = list_entry(e, kpr_route_entry_t,
                                                   kpre_list);
                kpr_gateway_entry_t *ge = re->kpre_gateway;

                if (!(net == PTL_NIDNET(PTL_NID_ANY) ||
                      net == re->kpre_net))
                        continue;

                if (!(gw_nid == PTL_NID_ANY ||
                      gw_nid == ge->kpge_nid))
                        continue;

                rc = 0;

                if (--ge->kpge_refcount == 0) {
                        list_del (&ge->kpge_list);
                        PORTAL_FREE (ge, sizeof (*ge));
                }

                list_del (&re->kpre_list);
                PORTAL_FREE(re, sizeof (*re));
        }

        kpr_state.kpr_generation++;
        write_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);

        return (rc);
}

int
kpr_get_route (int idx, __u32 *net, ptl_nid_t *gateway_nid, __u32 *alive)
{
	struct list_head  *e;
        unsigned long      flags;

        LASSERT (!in_interrupt());
	read_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        for (e = kpr_state.kpr_routes.next; e != &kpr_state.kpr_routes; e = e->next) {
                kpr_route_entry_t   *re = list_entry(e, kpr_route_entry_t,
                                                     kpre_list);
                kpr_gateway_entry_t *ge = re->kpre_gateway;
                
                if (idx-- == 0) {
                        *net = re->kpre_net;
                        *gateway_nid = ge->kpge_nid;
                        *alive = ge->kpge_alive;

                        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                        return (0);
                }
        }

        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
        return (-ENOENT);
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
#ifdef __KERNEL__
        kpr_proc_fini();
#endif
        while (!list_empty (&kpr_state.kpr_routes)) {
                kpr_route_entry_t *re = list_entry(kpr_state.kpr_routes.next,
                                                   kpr_route_entry_t,
                                                   kpre_list);

                list_del(&re->kpre_list);
                PORTAL_FREE(re, sizeof (*re));
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

        INIT_LIST_HEAD(&kpr_state.kpr_routes);
        INIT_LIST_HEAD(&kpr_state.kpr_gateways);
        rwlock_init(&kpr_state.kpr_rwlock);
        spin_lock_init(&kpr_state.kpr_stats_lock);

        rc = ptl_parse_routes(routes);

#ifdef __KERNEL__
        if (rc == 0)
                kpr_proc_init();
#endif

        return rc;
}

EXPORT_SYMBOL(kpr_forwarding);
EXPORT_SYMBOL(kpr_lookup);
EXPORT_SYMBOL(kpr_fwd_start);
EXPORT_SYMBOL(kpr_fwd_done);
EXPORT_SYMBOL(kpr_notify);
