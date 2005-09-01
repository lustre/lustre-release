/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
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

#ifndef _KPTLROUTER_H
#define _KPTLROUTER_H
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_PTLROUTER

#include <lnet/lib-lnet.h>

#ifdef __KERNEL__

typedef struct
{
        struct list_head        kpge_list;
        atomic_t                kpge_weight;
        time_t                  kpge_timestamp;
        int                     kpge_alive;
        int                     kpge_refcount;
        lnet_nid_t               kpge_nid;
} kpr_gateway_entry_t;

typedef struct
{
	struct list_head   	kpre_list;
        kpr_gateway_entry_t    *kpre_gateway;
} kpr_route_entry_t;

typedef struct
{
        struct list_head        kpne_list;
        struct list_head        kpne_routes;
        __u32                   kpne_net;
} kpr_net_entry_t;

typedef struct
{
        work_struct_t           kpru_tq;
        lnet_nid_t               kpru_nid;
        int                     kpru_alive;
        time_t                  kpru_when;
} kpr_upcall_t;

typedef struct{
        struct list_head        kpr_nets;       /* net -> gateways lookup */
        struct list_head        kpr_gateways;   /* known gateways */
        unsigned long long      kpr_generation; /* validity stamp */
        rwlock_t                kpr_rwlock;     /* stabilize */

        atomic_t                kpr_queue_depth; /* packets being forwarded */

        unsigned long long      kpr_fwd_bytes;  /* counters */
        unsigned long long      kpr_fwd_packets;
        unsigned long long      kpr_fwd_errors;
        spinlock_t              kpr_stats_lock; /* serialise */
        
} kpr_state_t;

extern kpr_state_t  kpr_state;

extern void kpr_proc_init (void);
extern void kpr_proc_fini (void);
#endif /* __KERNEL__ */

#endif /* _KPLROUTER_H */
