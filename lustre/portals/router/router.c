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

LIST_HEAD(kpr_routes);
LIST_HEAD(kpr_gateways);
LIST_HEAD(kpr_nals);

unsigned long long kpr_fwd_bytes;
unsigned long      kpr_fwd_packets;
unsigned long      kpr_fwd_errors;
atomic_t           kpr_queue_depth;

/* Mostly the tables are read-only (thread and interrupt context)
 *
 * Once in a blue moon we register/deregister NALs and add/remove routing
 * entries (thread context only)... */
rwlock_t         kpr_rwlock = RW_LOCK_UNLOCKED;

kpr_router_interface_t kpr_router_interface = {
	kprri_register:		kpr_register_nal,
	kprri_lookup:		kpr_lookup_target,
	kprri_fwd_start:	kpr_forward_packet,
	kprri_fwd_done:		kpr_complete_packet,
        kprri_notify:           kpr_nal_notify,
	kprri_shutdown:		kpr_shutdown_nal,
	kprri_deregister:	kpr_deregister_nal,
};

kpr_control_interface_t kpr_control_interface = {
	kprci_add_route:	kpr_add_route,
	kprci_del_route:        kpr_del_route,
	kprci_get_route:        kpr_get_route,
	kprci_notify:           kpr_sys_notify,
};

int
kpr_register_nal (kpr_nal_interface_t *nalif, void **argp)
{
	unsigned long      flags;
	struct list_head  *e;
	kpr_nal_entry_t   *ne;

        CDEBUG (D_NET, "Registering NAL %d\n", nalif->kprni_nalid);

	PORTAL_ALLOC (ne, sizeof (*ne));
	if (ne == NULL)
		return (-ENOMEM);

	memset (ne, 0, sizeof (*ne));
        memcpy ((void *)&ne->kpne_interface, (void *)nalif, sizeof (*nalif));

	LASSERT (!in_interrupt());
	write_lock_irqsave (&kpr_rwlock, flags);

	for (e = kpr_nals.next; e != &kpr_nals; e = e->next)
	{
		kpr_nal_entry_t *ne2 = list_entry (e, kpr_nal_entry_t, kpne_list);

		if (ne2->kpne_interface.kprni_nalid == ne->kpne_interface.kprni_nalid)
		{
			write_unlock_irqrestore (&kpr_rwlock, flags);

			CERROR ("Attempt to register same NAL %d twice\n", ne->kpne_interface.kprni_nalid);

			PORTAL_FREE (ne, sizeof (*ne));
			return (-EEXIST);
		}
	}

        list_add (&ne->kpne_list, &kpr_nals);

	write_unlock_irqrestore (&kpr_rwlock, flags);

	*argp = ne;
	PORTAL_MODULE_USE;
        return (0);
}

void
kpr_do_upcall (void *arg)
{
        kpr_upcall_t *u = (kpr_upcall_t *)arg;
        char          nalstr[10];
        char          nidstr[36];
        char          whenstr[36];
        char         *argv[] = {
                NULL,
                "ROUTER_NOTIFY",
                nalstr,
                nidstr,
                u->kpru_alive ? "up" : "down",
                whenstr,
                NULL};
        
        snprintf (nalstr, sizeof(nalstr), "%d", u->kpru_nal_id);
        snprintf (nidstr, sizeof(nidstr), LPX64, u->kpru_nid);
        snprintf (whenstr, sizeof(whenstr), "%ld", u->kpru_when);

        portals_run_upcall (argv);

        kfree (u);
}

void
kpr_upcall (int gw_nalid, ptl_nid_t gw_nid, int alive, time_t when)
{
        /* May be in arbitrary context */
        kpr_upcall_t  *u = kmalloc (sizeof (kpr_upcall_t), GFP_ATOMIC);

        if (u == NULL) {
                CERROR ("Upcall out of memory: nal %d nid "LPX64" %s\n",
                        gw_nalid, gw_nid, alive ? "up" : "down");
                return;
        }

        u->kpru_nal_id     = gw_nalid;
        u->kpru_nid        = gw_nid;
        u->kpru_alive      = alive;
        u->kpru_when       = when;

        prepare_work (&u->kpru_tq, kpr_do_upcall, u);
        schedule_work (&u->kpru_tq);
}

int
kpr_do_notify (int byNal, int gateway_nalid, ptl_nid_t gateway_nid,
               int alive, time_t when)
{
	unsigned long	     flags;
        int                  found;
        kpr_nal_entry_t     *ne = NULL;
        kpr_gateway_entry_t *ge = NULL;
        struct timeval       now;
	struct list_head    *e;
	struct list_head    *n;

        CDEBUG (D_NET, "%s notifying [%d] "LPX64": %s\n", 
                byNal ? "NAL" : "userspace", 
                gateway_nalid, gateway_nid, alive ? "up" : "down");

        /* can't do predictions... */
        do_gettimeofday (&now);
        if (when > now.tv_sec) {
                CWARN ("Ignoring prediction from %s of [%d] "LPX64" %s "
                       "%ld seconds in the future\n", 
                       byNal ? "NAL" : "userspace", 
                       gateway_nalid, gateway_nid, 
                       alive ? "up" : "down",
                       when - now.tv_sec);
                return (EINVAL);
        }

        LASSERT (when <= now.tv_sec);

        /* Serialise with lookups (i.e. write lock) */
	write_lock_irqsave(&kpr_rwlock, flags);

        found = 0;
        list_for_each_safe (e, n, &kpr_gateways) {

                ge = list_entry(e, kpr_gateway_entry_t, kpge_list);
                if ((gateway_nalid != 0 &&
                     ge->kpge_nalid != gateway_nalid) ||
                    ge->kpge_nid != gateway_nid)
                        continue;

                found = 1;
                break;
        }

        if (!found) {
                /* gateway not found */
                write_unlock_irqrestore(&kpr_rwlock, flags);
                CDEBUG (D_NET, "Gateway not found\n");
                return (0);
        }
        
        if (when < ge->kpge_timestamp) {
                /* out of date information */
                write_unlock_irqrestore (&kpr_rwlock, flags);
                CDEBUG (D_NET, "Out of date\n");
                return (0);
        }

        /* update timestamp */
        ge->kpge_timestamp = when;

        if ((!ge->kpge_alive) == (!alive)) {
                /* new date for old news */
                write_unlock_irqrestore (&kpr_rwlock, flags);
                CDEBUG (D_NET, "Old news\n");
                return (0);
        }

        ge->kpge_alive = alive;
        CDEBUG(D_NET, "set "LPX64" [%p] %d\n", gateway_nid, ge, alive);

        if (alive) {
                /* Reset all gateway weights so the newly-enabled gateway
                 * doesn't have to play catch-up */
                list_for_each_safe (e, n, &kpr_gateways) {
                        kpr_gateway_entry_t *ge = list_entry(e, kpr_gateway_entry_t,
                                                             kpge_list);
                        atomic_set (&ge->kpge_weight, 0);
                }
        }

        found = 0;
        if (!byNal) {
                /* userland notified me: notify NAL? */
                ne = kpr_find_nal_entry_locked (ge->kpge_nalid);
                if (ne != NULL) {
                        if (!ne->kpne_shutdown &&
                            ne->kpne_interface.kprni_notify != NULL) {
                                /* take a ref on this NAL until notifying
                                 * it has completed... */
                                atomic_inc (&ne->kpne_refcount);
                                found = 1;
                        }
                }
        }

        write_unlock_irqrestore(&kpr_rwlock, flags);

        if (found) {
                ne->kpne_interface.kprni_notify (ne->kpne_interface.kprni_arg,
                                                 gateway_nid, alive);
                /* 'ne' can disappear now... */
                atomic_dec (&ne->kpne_refcount);
        }
        
        if (byNal) {
                /* It wasn't userland that notified me... */
                CWARN ("Upcall: NAL %d NID "LPX64" is %s\n",
                       gateway_nalid, gateway_nid,
                       alive ? "alive" : "dead");
                kpr_upcall (gateway_nalid, gateway_nid, alive, when);
        } else {
                CDEBUG (D_NET, " NOT Doing upcall\n");
        }
        
        return (0);
}

void
kpr_nal_notify (void *arg, ptl_nid_t peer, int alive, time_t when)
{
        kpr_nal_entry_t *ne = (kpr_nal_entry_t *)arg;
        
        kpr_do_notify (1, ne->kpne_interface.kprni_nalid, peer, alive, when);
}

void
kpr_shutdown_nal (void *arg)
{
	unsigned long    flags;
	kpr_nal_entry_t *ne = (kpr_nal_entry_t *)arg;

        CDEBUG (D_NET, "Shutting down NAL %d\n", ne->kpne_interface.kprni_nalid);

	LASSERT (!ne->kpne_shutdown);
	LASSERT (!in_interrupt());

	write_lock_irqsave (&kpr_rwlock, flags); /* locking a bit spurious... */
	ne->kpne_shutdown = 1;
	write_unlock_irqrestore (&kpr_rwlock, flags); /* except it's a memory barrier */

	while (atomic_read (&ne->kpne_refcount) != 0)
	{
		CDEBUG (D_NET, "Waiting for refcount on NAL %d to reach zero (%d)\n",
			ne->kpne_interface.kprni_nalid, atomic_read (&ne->kpne_refcount));

		set_current_state (TASK_UNINTERRUPTIBLE);
		schedule_timeout (HZ);
	}
}

void
kpr_deregister_nal (void *arg)
{
	unsigned long     flags;
	kpr_nal_entry_t  *ne = (kpr_nal_entry_t *)arg;

        CDEBUG (D_NET, "Deregister NAL %d\n", ne->kpne_interface.kprni_nalid);

	LASSERT (ne->kpne_shutdown);		/* caller must have issued shutdown already */
	LASSERT (atomic_read (&ne->kpne_refcount) == 0); /* can't be busy */
	LASSERT (!in_interrupt());

	write_lock_irqsave (&kpr_rwlock, flags);

	list_del (&ne->kpne_list);

	write_unlock_irqrestore (&kpr_rwlock, flags);

	PORTAL_FREE (ne, sizeof (*ne));
        PORTAL_MODULE_UNUSE;
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

int
kpr_lookup_target (void *arg, ptl_nid_t target_nid, int nob,
                   ptl_nid_t *gateway_nidp)
{
	kpr_nal_entry_t     *ne = (kpr_nal_entry_t *)arg;
	struct list_head    *e;
        kpr_route_entry_t   *re;
        kpr_gateway_entry_t *ge = NULL;
	int                  rc = -ENOENT;

        /* Caller wants to know if 'target_nid' can be reached via a gateway
         * ON HER OWN NETWORK */

        CDEBUG (D_NET, "lookup "LPX64" from NAL %d\n", target_nid, 
                ne->kpne_interface.kprni_nalid);

	if (ne->kpne_shutdown)		/* caller is shutting down */
		return (-ENOENT);

	read_lock (&kpr_rwlock);

	/* Search routes for one that has a gateway to target_nid on the callers network */

        list_for_each (e, &kpr_routes) {
		re = list_entry (e, kpr_route_entry_t, kpre_list);

		if (re->kpre_lo_nid > target_nid ||
                    re->kpre_hi_nid < target_nid)
			continue;

		/* found table entry */

		if (re->kpre_gateway->kpge_nalid != ne->kpne_interface.kprni_nalid ||
                    !re->kpre_gateway->kpge_alive) {
                        /* different NAL or gateway down */
                        rc = -EHOSTUNREACH;
                        continue;
                }
                
                if (ge == NULL ||
                    kpr_ge_isbetter (re->kpre_gateway, ge))
                    ge = re->kpre_gateway;
	}

        if (ge != NULL) {
                kpr_update_weight (ge, nob);
                *gateway_nidp = ge->kpge_nid;
                rc = 0;
        }
        
	read_unlock (&kpr_rwlock);

        /* NB can't deref 're' now; it might have been removed! */

        CDEBUG (D_NET, "lookup "LPX64" from NAL %d: %d ("LPX64")\n",
                target_nid, ne->kpne_interface.kprni_nalid, rc,
                (rc == 0) ? *gateway_nidp : (ptl_nid_t)0);
	return (rc);
}

kpr_nal_entry_t *
kpr_find_nal_entry_locked (int nal_id)
{
        struct list_head    *e;
        
        /* Called with kpr_rwlock held */

        list_for_each (e, &kpr_nals) {
                kpr_nal_entry_t *ne = list_entry (e, kpr_nal_entry_t, kpne_list);

                if (nal_id != ne->kpne_interface.kprni_nalid) /* no match */
                        continue;

                return (ne);
        }
        
        return (NULL);
}

void
kpr_forward_packet (void *arg, kpr_fwd_desc_t *fwd)
{
	kpr_nal_entry_t     *src_ne = (kpr_nal_entry_t *)arg;
	ptl_nid_t            target_nid = fwd->kprfd_target_nid;
        int                  nob = fwd->kprfd_nob;
        kpr_gateway_entry_t *ge = NULL;
        kpr_nal_entry_t     *dst_ne = NULL;
	struct list_head    *e;
        kpr_route_entry_t   *re;
        kpr_nal_entry_t     *tmp_ne;

        CDEBUG (D_NET, "forward [%p] "LPX64" from NAL %d\n", fwd,
                target_nid, src_ne->kpne_interface.kprni_nalid);

        LASSERT (nob >= sizeof (ptl_hdr_t)); /* at least got a packet header */
        LASSERT (nob == lib_iov_nob (fwd->kprfd_niov, fwd->kprfd_iov));
        
        atomic_inc (&kpr_queue_depth);
	atomic_inc (&src_ne->kpne_refcount); /* source nal is busy until fwd completes */

        kpr_fwd_packets++;                   /* (loose) stats accounting */
        kpr_fwd_bytes += nob;

	if (src_ne->kpne_shutdown)           /* caller is shutting down */
		goto out;

	fwd->kprfd_router_arg = src_ne;      /* stash caller's nal entry */

	read_lock (&kpr_rwlock);

	/* Search routes for one that has a gateway to target_nid NOT on the caller's network */

        list_for_each (e, &kpr_routes) {
		re = list_entry (e, kpr_route_entry_t, kpre_list);

		if (re->kpre_lo_nid > target_nid || /* no match */
                    re->kpre_hi_nid < target_nid)
			continue;

		if (re->kpre_gateway->kpge_nalid == src_ne->kpne_interface.kprni_nalid)
			continue;               /* don't route to same NAL */

                if (!re->kpre_gateway->kpge_alive)
                        continue;               /* gateway is dead */
                
                tmp_ne = kpr_find_nal_entry_locked (re->kpre_gateway->kpge_nalid);

                if (tmp_ne == NULL ||
                    tmp_ne->kpne_shutdown) {
                        /* NAL must be registered and not shutting down */
                        continue;
                }

                if (ge == NULL ||
                    kpr_ge_isbetter (re->kpre_gateway, ge)) {
                        ge = re->kpre_gateway;
                        dst_ne = tmp_ne;
                }
        }
        
        if (ge != NULL) {
                LASSERT (dst_ne != NULL);
                
                kpr_update_weight (ge, nob);

                fwd->kprfd_gateway_nid = ge->kpge_nid;
                atomic_inc (&dst_ne->kpne_refcount); /* dest nal is busy until fwd completes */

                read_unlock (&kpr_rwlock);

                CDEBUG (D_NET, "forward [%p] "LPX64" from NAL %d: "
                        "to "LPX64" on NAL %d\n", 
                        fwd, target_nid, src_ne->kpne_interface.kprni_nalid,
                        fwd->kprfd_gateway_nid, dst_ne->kpne_interface.kprni_nalid);

                dst_ne->kpne_interface.kprni_fwd (dst_ne->kpne_interface.kprni_arg, fwd);
                return;
	}

        read_unlock (&kpr_rwlock);
 out:
        kpr_fwd_errors++;

        CDEBUG (D_NET, "Failed to forward [%p] "LPX64" from NAL %d\n", fwd,
                target_nid, src_ne->kpne_interface.kprni_nalid);

	/* Can't find anywhere to forward to */
	(fwd->kprfd_callback)(fwd->kprfd_callback_arg, -EHOSTUNREACH);

        atomic_dec (&kpr_queue_depth);
	atomic_dec (&src_ne->kpne_refcount);
}

void
kpr_complete_packet (void *arg, kpr_fwd_desc_t *fwd, int error)
{
	kpr_nal_entry_t *dst_ne = (kpr_nal_entry_t *)arg;
	kpr_nal_entry_t *src_ne = (kpr_nal_entry_t *)fwd->kprfd_router_arg;

        CDEBUG (D_NET, "complete(1) [%p] from NAL %d to NAL %d: %d\n", fwd,
                src_ne->kpne_interface.kprni_nalid, dst_ne->kpne_interface.kprni_nalid, error);

	atomic_dec (&dst_ne->kpne_refcount);    /* CAVEAT EMPTOR dst_ne can disappear now!!! */

	(fwd->kprfd_callback)(fwd->kprfd_callback_arg, error);

        CDEBUG (D_NET, "complete(2) [%p] from NAL %d: %d\n", fwd,
                src_ne->kpne_interface.kprni_nalid, error);

        atomic_dec (&kpr_queue_depth);
	atomic_dec (&src_ne->kpne_refcount);    /* CAVEAT EMPTOR src_ne can disappear now!!! */
}

int
kpr_add_route (int gateway_nalid, ptl_nid_t gateway_nid, 
               ptl_nid_t lo_nid, ptl_nid_t hi_nid)
{
	unsigned long	     flags;
	struct list_head    *e;
	kpr_route_entry_t   *re;
        kpr_gateway_entry_t *ge;
        int                  dup = 0;

        CDEBUG(D_NET, "Add route: %d "LPX64" : "LPX64" - "LPX64"\n",
               gateway_nalid, gateway_nid, lo_nid, hi_nid);

        if (gateway_nalid == PTL_NID_ANY ||
            lo_nid == PTL_NID_ANY ||
            hi_nid == PTL_NID_ANY ||
            lo_nid > hi_nid)
                return (-EINVAL);

        PORTAL_ALLOC (ge, sizeof (*ge));
        if (ge == NULL)
                return (-ENOMEM);

        ge->kpge_nalid = gateway_nalid;
        ge->kpge_nid   = gateway_nid;
        ge->kpge_alive = 1;
        ge->kpge_timestamp = 0;
        ge->kpge_refcount = 0;
        atomic_set (&ge->kpge_weight, 0);

        PORTAL_ALLOC (re, sizeof (*re));
        if (re == NULL)
                return (-ENOMEM);

        re->kpre_lo_nid = lo_nid;
        re->kpre_hi_nid = hi_nid;

        LASSERT(!in_interrupt());
	write_lock_irqsave (&kpr_rwlock, flags);

        list_for_each (e, &kpr_gateways) {
                kpr_gateway_entry_t *ge2 = list_entry(e, kpr_gateway_entry_t,
                                                      kpge_list);
                
                if (ge2->kpge_nalid == gateway_nalid &&
                    ge2->kpge_nid == gateway_nid) {
                        PORTAL_FREE (ge, sizeof (*ge));
                        ge = ge2;
                        dup = 1;
                        break;
                }
        }

        if (!dup) {
                /* Adding a new gateway... */
 
                list_add (&ge->kpge_list, &kpr_gateways);

                /* ...zero all gateway weights so this one doesn't have to
                 * play catch-up */

                list_for_each (e, &kpr_gateways) {
                        kpr_gateway_entry_t *ge2 = list_entry(e, kpr_gateway_entry_t,
                                                              kpge_list);
                        atomic_set (&ge2->kpge_weight, 0);
                }
                
        }

        re->kpre_gateway = ge;
        ge->kpge_refcount++;
        list_add (&re->kpre_list, &kpr_routes);

        write_unlock_irqrestore (&kpr_rwlock, flags);
        return (0);
}

int
kpr_sys_notify (int gateway_nalid, ptl_nid_t gateway_nid,
            int alive, time_t when)
{
        return (kpr_do_notify (0, gateway_nalid, gateway_nid, alive, when));
}

int
kpr_del_route (int gw_nalid, ptl_nid_t gw_nid,
               ptl_nid_t lo, ptl_nid_t hi)
{
        int                specific = (lo != PTL_NID_ANY);
	unsigned long	   flags;
        int                rc = -ENOENT;
	struct list_head  *e;
	struct list_head  *n;

        CDEBUG(D_NET, "Del route [%d] "LPX64" : "LPX64" - "LPX64"\n", 
               gw_nalid, gw_nid, lo, hi);

        LASSERT(!in_interrupt());

        /* NB Caller may specify either all routes via the given gateway
         * (lo/hi == PTL_NID_ANY) or a specific route entry (lo/hi are
         * actual NIDs) */
        
        if (specific ? (hi == PTL_NID_ANY || hi < lo) : (hi != PTL_NID_ANY))
                return (-EINVAL);

	write_lock_irqsave(&kpr_rwlock, flags);

        list_for_each_safe (e, n, &kpr_routes) {
                kpr_route_entry_t   *re = list_entry(e, kpr_route_entry_t,
                                                   kpre_list);
                kpr_gateway_entry_t *ge = re->kpre_gateway;
                
                if (ge->kpge_nalid != gw_nalid ||
                    ge->kpge_nid != gw_nid ||
                    (specific && 
                     (lo != re->kpre_lo_nid || hi != re->kpre_hi_nid)))
                        continue;

                rc = 0;

                if (--ge->kpge_refcount == 0) {
                        list_del (&ge->kpge_list);
                        PORTAL_FREE (ge, sizeof (*ge));
                }

                list_del (&re->kpre_list);
                PORTAL_FREE(re, sizeof (*re));

                if (specific)
                        break;
        }

        write_unlock_irqrestore(&kpr_rwlock, flags);
        return (rc);
}

int
kpr_get_route (int idx, int *gateway_nalid, ptl_nid_t *gateway_nid,
               ptl_nid_t *lo_nid, ptl_nid_t *hi_nid, int *alive)
{
	struct list_head  *e;

	read_lock(&kpr_rwlock);

        for (e = kpr_routes.next; e != &kpr_routes; e = e->next) {
                kpr_route_entry_t   *re = list_entry(e, kpr_route_entry_t,
                                                     kpre_list);
                kpr_gateway_entry_t *ge = re->kpre_gateway;
                
                if (idx-- == 0) {
                        *gateway_nalid = ge->kpge_nalid;
                        *gateway_nid = ge->kpge_nid;
                        *alive = ge->kpge_alive;
                        *lo_nid = re->kpre_lo_nid;
                        *hi_nid = re->kpre_hi_nid;

                        read_unlock(&kpr_rwlock);
                        return (0);
                }
        }

        read_unlock (&kpr_rwlock);
        return (-ENOENT);
}

static void /*__exit*/
kpr_finalise (void)
{
        LASSERT (list_empty (&kpr_nals));

        while (!list_empty (&kpr_routes)) {
                kpr_route_entry_t *re = list_entry(kpr_routes.next,
                                                   kpr_route_entry_t,
                                                   kpre_list);

                list_del(&re->kpre_list);
                PORTAL_FREE(re, sizeof (*re));
        }

        kpr_proc_fini();

        PORTAL_SYMBOL_UNREGISTER(kpr_router_interface);
        PORTAL_SYMBOL_UNREGISTER(kpr_control_interface);

        CDEBUG(D_MALLOC, "kpr_finalise: kmem back to %d\n",
               atomic_read(&portal_kmemory));
}

static int __init
kpr_initialise (void)
{
        CDEBUG(D_MALLOC, "kpr_initialise: kmem %d\n",
               atomic_read(&portal_kmemory));

        kpr_proc_init();

        PORTAL_SYMBOL_REGISTER(kpr_router_interface);
        PORTAL_SYMBOL_REGISTER(kpr_control_interface);
        return (0);
}

MODULE_AUTHOR("Eric Barton");
MODULE_DESCRIPTION("Kernel Portals Router v0.01");
MODULE_LICENSE("GPL");

module_init (kpr_initialise);
module_exit (kpr_finalise);

EXPORT_SYMBOL (kpr_control_interface);
EXPORT_SYMBOL (kpr_router_interface);
