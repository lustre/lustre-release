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

#ifndef _KPTLROUTER_H
#define _KPTLROUTER_H
#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/init.h>

#define DEBUG_SUBSYSTEM S_PTLROUTER

#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>

typedef struct
{
	struct list_head	kpne_list;
	kpr_nal_interface_t     kpne_interface;
	atomic_t                kpne_refcount;
	int                     kpne_shutdown;
} kpr_nal_entry_t;

typedef struct
{
	struct list_head   	kpre_list;
	int                     kpre_gateway_nalid;
	ptl_nid_t           	kpre_gateway_nid;
	ptl_nid_t           	kpre_lo_nid;
        ptl_nid_t               kpre_hi_nid;
} kpr_route_entry_t;

extern int kpr_register_nal (kpr_nal_interface_t *nalif, void **argp);
extern int kpr_lookup_target (void *arg, ptl_nid_t target_nid, ptl_nid_t *gateway_nidp);
extern void kpr_forward_packet (void *arg, kpr_fwd_desc_t *fwd);
extern void kpr_complete_packet (void *arg, kpr_fwd_desc_t *fwd, int error);
extern void kpr_shutdown_nal (void *arg);
extern void kpr_deregister_nal (void *arg);

extern void kpr_proc_init (void);
extern void kpr_proc_fini (void);

extern int kpr_add_route (int gateway_nal, ptl_nid_t gateway_nid, 
                          ptl_nid_t lo_nid, ptl_nid_t hi_nid);
extern int kpr_del_route (ptl_nid_t nid);
extern int kpr_get_route (int idx, int *gateway_nal, ptl_nid_t *gateway_nid, 
                          ptl_nid_t *lo_nid, ptl_nid_t *hi_nid);

extern unsigned long long kpr_fwd_bytes;
extern unsigned long      kpr_fwd_packets;
extern unsigned long      kpr_fwd_errors;
extern atomic_t           kpr_queue_depth;

#endif /* _KPLROUTER_H */
