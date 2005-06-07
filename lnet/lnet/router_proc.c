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
#include <linux/seq_file.h>

#define KPR_PROC_STATS  "sys/portals/router_stats"
#define KPR_PROC_ROUTES "sys/portals/routes"

static int 
kpr_proc_stats_read (char *page, char **start, off_t off,
                     int count, int *eof, void *data)
{
        unsigned long long bytes;
        unsigned long long packets;
        unsigned long long errors;
        unsigned int       qdepth;
        unsigned long      flags;

        *start = page;
        *eof = 1;
        if (off != 0)
                return 0;
        
        spin_lock_irqsave(&kpr_state.kpr_stats_lock, flags);

        bytes   = kpr_state.kpr_fwd_bytes;
        packets = kpr_state.kpr_fwd_packets;
        errors  = kpr_state.kpr_fwd_errors;
        qdepth  = atomic_read(&kpr_state.kpr_queue_depth);

        spin_unlock_irqrestore(&kpr_state.kpr_stats_lock, flags);

        return sprintf(page, "%Ld %Ld %Ld %d\n", bytes, packets, errors, qdepth);
}

static int 
kpr_proc_stats_write(struct file *file, const char *ubuffer,
                     unsigned long count, void *data)
{
        unsigned long      flags;

        spin_lock_irqsave(&kpr_state.kpr_stats_lock, flags);

        /* just zero the stats */
        kpr_state.kpr_fwd_bytes = 0;
        kpr_state.kpr_fwd_packets = 0;
        kpr_state.kpr_fwd_errors = 0;

        spin_unlock_irqrestore(&kpr_state.kpr_stats_lock, flags);
        return (count);
}

typedef struct {
        unsigned long long   sri_generation;
        kpr_net_entry_t     *sri_net;
        kpr_route_entry_t   *sri_route;
        loff_t               sri_off;
} kpr_seq_route_iterator_t;

int
kpr_seq_routes_seek (kpr_seq_route_iterator_t *sri, loff_t off)
{
        struct list_head  *n;
        struct list_head  *r;
        int                rc;
        unsigned long      flags;
        loff_t             here;
        
        read_lock_irqsave(&kpr_state.kpr_rwlock, flags);
        
        if (sri->sri_net != NULL &&
            sri->sri_generation != kpr_state.kpr_generation) {
                /* tables have changed */
                rc = -ESTALE;
                goto out;
        }
        
        if (sri->sri_net == NULL || sri->sri_off > off) {
                /* search from start */
                n = kpr_state.kpr_nets.next;
                r = NULL;
                here = 0;
        } else {
                /* continue search */
                n = &sri->sri_net->kpne_list;
                r = &sri->sri_route->kpre_list;
                here = sri->sri_off;
        }
        
        sri->sri_generation = kpr_state.kpr_generation;
        sri->sri_off        = off;
        
        while (n != &kpr_state.kpr_nets) {
                kpr_net_entry_t *ne = 
                        list_entry(n, kpr_net_entry_t, kpne_list);
                
                if (r == NULL)
                        r = ne->kpne_routes.next;
                
                while (r != &ne->kpne_routes) {
                        kpr_route_entry_t *re =
                                list_entry(r, kpr_route_entry_t,
                                           kpre_list);
                        
                        if (here == off) {
                                sri->sri_net = ne;
                                sri->sri_route = re;
                                rc = 0;
                                goto out;
                        }
                        
                        r = r->next;
                        here++;
                }
                
                r = NULL;
                n = n->next;
        }

        sri->sri_net   = NULL;
        sri->sri_route = NULL;
        rc             = -ENOENT;
 out:
        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
        return rc;
}

static void *
kpr_seq_routes_start (struct seq_file *s, loff_t *pos) 
{
        kpr_seq_route_iterator_t *sri;
        int                       rc;
        
        PORTAL_ALLOC(sri, sizeof(*sri));
        if (sri == NULL)
                return NULL;

        sri->sri_net = NULL;
        rc = kpr_seq_routes_seek(sri, *pos);
        if (rc == 0)
                return sri;
        
        PORTAL_FREE(sri, sizeof(*sri));
        return NULL;
}

static void
kpr_seq_routes_stop (struct seq_file *s, void *iter)
{
        kpr_seq_route_iterator_t  *sri = iter;
        
        if (sri != NULL)
                PORTAL_FREE(sri, sizeof(*sri));
}

static void *
kpr_seq_routes_next (struct seq_file *s, void *iter, loff_t *pos)
{
        kpr_seq_route_iterator_t *sri = iter;
        int                       rc;
        loff_t                    next = *pos + 1;

        rc = kpr_seq_routes_seek(sri, next);
        if (rc != 0) {
                PORTAL_FREE(sri, sizeof(*sri));
                return NULL;
        }
        
        *pos = next;
        return sri;
}

static int 
kpr_seq_routes_show (struct seq_file *s, void *iter)
{
        kpr_seq_route_iterator_t *sri = iter;
        unsigned long             flags;
        __u32                     net;
        ptl_nid_t                 nid;
        int                       alive;

        read_lock_irqsave(&kpr_state.kpr_rwlock, flags);

        LASSERT (sri->sri_net != NULL);
        LASSERT (sri->sri_route != NULL);

        if (sri->sri_generation != kpr_state.kpr_generation) {
                read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);
                return -ESTALE;
        }

        net = sri->sri_net->kpne_net;
        nid = sri->sri_route->kpre_gateway->kpge_nid;
        alive = sri->sri_route->kpre_gateway->kpge_alive;

        read_unlock_irqrestore(&kpr_state.kpr_rwlock, flags);

        seq_printf(s, "net %12s: gateway %s %s\n",
                   libcfs_net2str(net), libcfs_nid2str(nid),
                   alive ? "up" : "down");
        return 0;
}

static struct seq_operations kpr_routes_sops = {
        .start = kpr_seq_routes_start,
        .stop  = kpr_seq_routes_stop,
        .next  = kpr_seq_routes_next,
        .show  = kpr_seq_routes_show,
};

static int
kpr_seq_routes_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file       *sf;
        int                    rc;
        
        rc = seq_open(file, &kpr_routes_sops);
        if (rc == 0) {
                sf = file->private_data;
                sf->private = dp->data;
        }
        
        return rc;
}

static struct file_operations kpr_routes_fops = {
        .owner   = THIS_MODULE,
        .open    = kpr_seq_routes_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

void 
kpr_proc_init(void)
{
        struct proc_dir_entry *stats;
        struct proc_dir_entry *routes;

        /* Initialize KPR_PROC_STATS */
        stats = create_proc_entry (KPR_PROC_STATS, 0644, NULL);
        if (stats == NULL) {
                CERROR("couldn't create proc entry %s\n", KPR_PROC_STATS);
                return;
        }

        stats->data = NULL;
        stats->read_proc = kpr_proc_stats_read;
        stats->write_proc = kpr_proc_stats_write;

        /* Initialize KPR_PROC_ROUTES */
        routes = create_proc_entry (KPR_PROC_ROUTES, 0444, NULL);
        if (routes == NULL) {
                CERROR("couldn't create proc entry %s\n", KPR_PROC_ROUTES);
                return;
        }
        
        routes->proc_fops = &kpr_routes_fops;
        routes->data = NULL;
}

void
kpr_proc_fini(void)
{
        remove_proc_entry(KPR_PROC_STATS, 0);
        remove_proc_entry(KPR_PROC_ROUTES, 0);
}
