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

#define DEBUG_SUBSYSTEM S_LNET
#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>

#if defined(__KERNEL__) && defined(LNET_ROUTER)

#include <linux/seq_file.h>
#include <linux/lustre_compat25.h>

/* this is really lnet_proc.c */

#define LNET_PROC_STATS   "sys/lnet/stats"
#define LNET_PROC_ROUTES  "sys/lnet/routes"
#define LNET_PROC_ROUTERS "sys/lnet/routers"
#define LNET_PROC_PEERS   "sys/lnet/peers"
#define LNET_PROC_BUFFERS "sys/lnet/buffers"
#define LNET_PROC_NIS     "sys/lnet/nis"

static int
lnet_router_proc_stats_read (char *page, char **start, off_t off,
                             int count, int *eof, void *data)
{
        lnet_counters_t *ctrs;
        int              rc;

        *start = page;
        *eof = 1;
        if (off != 0)
                return 0;

        LIBCFS_ALLOC(ctrs, sizeof(*ctrs));
        if (ctrs == NULL)
                return -ENOMEM;

        LNET_LOCK();
        *ctrs = the_lnet.ln_counters;
        LNET_UNLOCK();

        rc = sprintf(page,
                     "%u %u %u %u %u %u %u "LPU64" "LPU64" "LPU64" "LPU64"\n",
                     ctrs->msgs_alloc, ctrs->msgs_max,
                     ctrs->errors,
                     ctrs->send_count, ctrs->recv_count,
                     ctrs->route_count, ctrs->drop_count,
                     ctrs->send_length, ctrs->recv_length,
                     ctrs->route_length, ctrs->drop_length);

        LIBCFS_FREE(ctrs, sizeof(*ctrs));
        return rc;
}

static int
lnet_router_proc_stats_write(struct file *file, const char *ubuffer,
                     unsigned long count, void *data)
{
        LNET_LOCK();
        memset(&the_lnet.ln_counters, 0, sizeof(the_lnet.ln_counters));
        LNET_UNLOCK();

        return (count);
}

typedef struct {
        __u64                lrsi_version;
        lnet_remotenet_t    *lrsi_net;
        lnet_route_t        *lrsi_route;
        loff_t               lrsi_off;
} lnet_route_seq_iterator_t;

int
lnet_route_seq_seek (lnet_route_seq_iterator_t *lrsi, loff_t off)
{
        struct list_head  *n;
        struct list_head  *r;
        int                rc;
        loff_t             here;

        if (off == 0) {
                lrsi->lrsi_net = NULL;
                lrsi->lrsi_route = NULL;
                lrsi->lrsi_off = 0;
                return 0;
        }

        LNET_LOCK();

        if (lrsi->lrsi_net != NULL &&
            lrsi->lrsi_version != the_lnet.ln_remote_nets_version) {
                /* tables have changed */
                rc = -ESTALE;
                goto out;
        }

        if (lrsi->lrsi_net == NULL || lrsi->lrsi_off > off) {
                /* search from start */
                n = the_lnet.ln_remote_nets.next;
                r = NULL;
                here = 1;
        } else {
                /* continue search */
                n = &lrsi->lrsi_net->lrn_list;
                r = &lrsi->lrsi_route->lr_list;
                here = lrsi->lrsi_off;
        }

        lrsi->lrsi_version = the_lnet.ln_remote_nets_version;
        lrsi->lrsi_off        = off;

        while (n != &the_lnet.ln_remote_nets) {
                lnet_remotenet_t *rnet =
                        list_entry(n, lnet_remotenet_t, lrn_list);

                if (r == NULL)
                        r = rnet->lrn_routes.next;

                while (r != &rnet->lrn_routes) {
                        lnet_route_t *re =
                                list_entry(r, lnet_route_t,
                                           lr_list);

                        if (here == off) {
                                lrsi->lrsi_net = rnet;
                                lrsi->lrsi_route = re;
                                rc = 0;
                                goto out;
                        }

                        r = r->next;
                        here++;
                }

                r = NULL;
                n = n->next;
        }

        lrsi->lrsi_net   = NULL;
        lrsi->lrsi_route = NULL;
        rc             = -ENOENT;
 out:
        LNET_UNLOCK();
        return rc;
}

static void *
lnet_route_seq_start (struct seq_file *s, loff_t *pos)
{
        lnet_route_seq_iterator_t *lrsi;
        int                        rc;

        LIBCFS_ALLOC(lrsi, sizeof(*lrsi));
        if (lrsi == NULL)
                return NULL;

        lrsi->lrsi_net = NULL;
        rc = lnet_route_seq_seek(lrsi, *pos);
        if (rc == 0)
                return lrsi;

        LIBCFS_FREE(lrsi, sizeof(*lrsi));
        return NULL;
}

static void
lnet_route_seq_stop (struct seq_file *s, void *iter)
{
        lnet_route_seq_iterator_t  *lrsi = iter;

        if (lrsi != NULL)
                LIBCFS_FREE(lrsi, sizeof(*lrsi));
}

static void *
lnet_route_seq_next (struct seq_file *s, void *iter, loff_t *pos)
{
        lnet_route_seq_iterator_t *lrsi = iter;
        int                        rc;
        loff_t                     next = *pos + 1;

        rc = lnet_route_seq_seek(lrsi, next);
        if (rc != 0) {
                LIBCFS_FREE(lrsi, sizeof(*lrsi));
                return NULL;
        }

        *pos = next;
        return lrsi;
}

static int
lnet_route_seq_show (struct seq_file *s, void *iter)
{
        lnet_route_seq_iterator_t *lrsi = iter;
        __u32                      net;
        unsigned int               hops;
        lnet_nid_t                 nid;
        int                        alive;

        if (lrsi->lrsi_off == 0) {
                seq_printf(s, "Routing %s\n",
                           the_lnet.ln_routing ? "enabled" : "disabled");
                seq_printf(s, "%-8s %4s %7s %s\n",
                           "net", "hops", "state", "router");
                return 0;
        }

        LASSERT (lrsi->lrsi_net != NULL);
        LASSERT (lrsi->lrsi_route != NULL);

        LNET_LOCK();

        if (lrsi->lrsi_version != the_lnet.ln_remote_nets_version) {
                LNET_UNLOCK();
                return -ESTALE;
        }

        net   = lrsi->lrsi_net->lrn_net;
        hops  = lrsi->lrsi_net->lrn_hops;
        nid   = lrsi->lrsi_route->lr_gateway->lp_nid;
        alive = lrsi->lrsi_route->lr_gateway->lp_alive;

        LNET_UNLOCK();

        seq_printf(s, "%-8s %4u %7s %s\n", libcfs_net2str(net), hops,
                   alive ? "up" : "down", libcfs_nid2str(nid));
        return 0;
}

static struct seq_operations lnet_routes_sops = {
        .start = lnet_route_seq_start,
        .stop  = lnet_route_seq_stop,
        .next  = lnet_route_seq_next,
        .show  = lnet_route_seq_show,
};

static int
lnet_route_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file       *sf;
        int                    rc;

        rc = seq_open(file, &lnet_routes_sops);
        if (rc == 0) {
                sf = file->private_data;
                sf->private = dp->data;
        }

        return rc;
}

static struct file_operations lnet_routes_fops = {
        .owner   = THIS_MODULE,
        .open    = lnet_route_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

typedef struct {
        __u64                lrtrsi_version;
        lnet_peer_t          *lrtrsi_router;
        loff_t               lrtrsi_off;
} lnet_router_seq_iterator_t;

int
lnet_router_seq_seek (lnet_router_seq_iterator_t *lrtrsi, loff_t off)
{
        struct list_head  *r;
        lnet_peer_t       *lp;
        int                rc;
        loff_t             here;

        if (off == 0) {
                lrtrsi->lrtrsi_router = NULL;
                lrtrsi->lrtrsi_off = 0;
                return 0;
        }

        LNET_LOCK();

        lp = lrtrsi->lrtrsi_router;

        if (lp != NULL &&
            lrtrsi->lrtrsi_version != the_lnet.ln_routers_version) {
                /* tables have changed */
                rc = -ESTALE;
                goto out;
        }

        if (lp == NULL || lrtrsi->lrtrsi_off > off) {
                /* search from start */
                r = the_lnet.ln_routers.next;
                here = 1;
        } else {
                /* continue search */
                r = &lp->lp_rtr_list;
                here = lrtrsi->lrtrsi_off;
        }

        lrtrsi->lrtrsi_version = the_lnet.ln_routers_version;
        lrtrsi->lrtrsi_off        = off;

        while (r != &the_lnet.ln_routers) {
                lnet_peer_t *rtr = list_entry(r, 
                                              lnet_peer_t,
                                              lp_rtr_list);

                if (here == off) {
                        lrtrsi->lrtrsi_router = rtr;
                        rc = 0;
                        goto out;
                }

                r = r->next;
                here++;
        }

        lrtrsi->lrtrsi_router = NULL;
        rc             = -ENOENT;
 out:
        LNET_UNLOCK();
        return rc;
}

static void *
lnet_router_seq_start (struct seq_file *s, loff_t *pos)
{
        lnet_router_seq_iterator_t *lrtrsi;
        int                        rc;

        LIBCFS_ALLOC(lrtrsi, sizeof(*lrtrsi));
        if (lrtrsi == NULL)
                return NULL;

        lrtrsi->lrtrsi_router = NULL;
        rc = lnet_router_seq_seek(lrtrsi, *pos);
        if (rc == 0)
                return lrtrsi;

        LIBCFS_FREE(lrtrsi, sizeof(*lrtrsi));
        return NULL;
}

static void
lnet_router_seq_stop (struct seq_file *s, void *iter)
{
        lnet_router_seq_iterator_t  *lrtrsi = iter;

        if (lrtrsi != NULL)
                LIBCFS_FREE(lrtrsi, sizeof(*lrtrsi));
}

static void *
lnet_router_seq_next (struct seq_file *s, void *iter, loff_t *pos)
{
        lnet_router_seq_iterator_t *lrtrsi = iter;
        int                        rc;
        loff_t                     next = *pos + 1;

        rc = lnet_router_seq_seek(lrtrsi, next);
        if (rc != 0) {
                LIBCFS_FREE(lrtrsi, sizeof(*lrtrsi));
                return NULL;
        }

        *pos = next;
        return lrtrsi;
}

static int
lnet_router_seq_show (struct seq_file *s, void *iter)
{
        lnet_router_seq_iterator_t *lrtrsi = iter;
        lnet_peer_t *lp;
        lnet_nid_t  nid;
        int         alive;
        int         nrefs;
        int         nrtrrefs;

        if (lrtrsi->lrtrsi_off == 0) {
                seq_printf(s, "%-4s %7s %9s %6s %12s %s\n",
                           "ref", "rtr_ref", "alive_cnt", "state", "last_ping", "router");
                return 0;
        }

        lp = lrtrsi->lrtrsi_router;
        LASSERT (lp != NULL);

        LNET_LOCK();

        if (lrtrsi->lrtrsi_version != the_lnet.ln_routers_version) {
                LNET_UNLOCK();
                return -ESTALE;
        }

        nrefs = lp->lp_refcount;
        nrtrrefs = lp->lp_rtr_refcount;
        nid   = lp->lp_nid;
        alive = lp->lp_alive;

        LNET_UNLOCK();

        seq_printf(s, 
                   "%-4d %7d %9d %6s %12lu %s\n", 
                   nrefs, nrtrrefs,
                   lp->lp_alive_count,
                   alive ? "up" : "down", 
                   lp->lp_ping_timestamp,
                   libcfs_nid2str(nid));
        return 0;
}

static struct seq_operations lnet_routers_sops = {
        .start = lnet_router_seq_start,
        .stop  = lnet_router_seq_stop,
        .next  = lnet_router_seq_next,
        .show  = lnet_router_seq_show,
};

static int
lnet_router_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file       *sf;
        int                    rc;

        rc = seq_open(file, &lnet_routers_sops);
        if (rc == 0) {
                sf = file->private_data;
                sf->private = dp->data;
        }

        return rc;
}

static struct file_operations lnet_routers_fops = {
        .owner   = THIS_MODULE,
        .open    = lnet_router_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

typedef struct {
        unsigned long long   lpsi_version;
        int                  lpsi_idx;
        lnet_peer_t         *lpsi_peer;
        loff_t               lpsi_off;
} lnet_peer_seq_iterator_t;

int
lnet_peer_seq_seek (lnet_peer_seq_iterator_t *lpsi, loff_t off)
{
        int                idx;
        struct list_head  *p;
        loff_t             here;
        int                rc;

        if (off == 0) {
                lpsi->lpsi_idx = 0;
                lpsi->lpsi_peer = NULL;
                lpsi->lpsi_off = 0;
                return 0;
        }

        LNET_LOCK();

        if (lpsi->lpsi_peer != NULL &&
            lpsi->lpsi_version != the_lnet.ln_peertable_version) {
                /* tables have changed */
                rc = -ESTALE;
                goto out;
        }

        if (lpsi->lpsi_peer == NULL ||
            lpsi->lpsi_off > off) {
                /* search from start */
                idx = 0;
                p = NULL;
                here = 1;
        } else {
                /* continue search */
                idx = lpsi->lpsi_idx;
                p = &lpsi->lpsi_peer->lp_hashlist;
                here = lpsi->lpsi_off;
        }

        lpsi->lpsi_version = the_lnet.ln_peertable_version;
        lpsi->lpsi_off     = off;

        while (idx < LNET_PEER_HASHSIZE) {
                if (p == NULL)
                        p = the_lnet.ln_peer_hash[idx].next;

                while (p != &the_lnet.ln_peer_hash[idx]) {
                        lnet_peer_t *lp = list_entry(p, lnet_peer_t,
                                                     lp_hashlist);

                        if (here == off) {
                                lpsi->lpsi_idx = idx;
                                lpsi->lpsi_peer = lp;
                                rc = 0;
                                goto out;
                        }

                        here++;
                        p = lp->lp_hashlist.next;
                }

                p = NULL;
                idx++;
        }

        lpsi->lpsi_idx  = 0;
        lpsi->lpsi_peer = NULL;
        rc              = -ENOENT;
 out:
        LNET_UNLOCK();
        return rc;
}

static void *
lnet_peer_seq_start (struct seq_file *s, loff_t *pos)
{
        lnet_peer_seq_iterator_t *lpsi;
        int                        rc;

        LIBCFS_ALLOC(lpsi, sizeof(*lpsi));
        if (lpsi == NULL)
                return NULL;

        lpsi->lpsi_idx = 0;
        lpsi->lpsi_peer = NULL;
        rc = lnet_peer_seq_seek(lpsi, *pos);
        if (rc == 0)
                return lpsi;

        LIBCFS_FREE(lpsi, sizeof(*lpsi));
        return NULL;
}

static void
lnet_peer_seq_stop (struct seq_file *s, void *iter)
{
        lnet_peer_seq_iterator_t  *lpsi = iter;

        if (lpsi != NULL)
                LIBCFS_FREE(lpsi, sizeof(*lpsi));
}

static void *
lnet_peer_seq_next (struct seq_file *s, void *iter, loff_t *pos)
{
        lnet_peer_seq_iterator_t *lpsi = iter;
        int                       rc;
        loff_t                    next = *pos + 1;

        rc = lnet_peer_seq_seek(lpsi, next);
        if (rc != 0) {
                LIBCFS_FREE(lpsi, sizeof(*lpsi));
                return NULL;
        }

        *pos = next;
        return lpsi;
}

static int
lnet_peer_seq_show (struct seq_file *s, void *iter)
{
        lnet_peer_seq_iterator_t *lpsi = iter;
        lnet_peer_t              *lp;
        lnet_nid_t                nid;
        int                       maxcr;
        int                       mintxcr;
        int                       txcr;
        int                       minrtrcr;
        int                       rtrcr;
        int                       alive;
        int                       txqnob;
        int                       nrefs;

        if (lpsi->lpsi_off == 0) {
                seq_printf(s, "%-24s %4s %5s %5s %5s %5s %5s %5s %s\n",
                           "nid", "refs", "state", "max",
                           "rtr", "min", "tx", "min", "queue");
                return 0;
        }

        LASSERT (lpsi->lpsi_peer != NULL);

        LNET_LOCK();

        if (lpsi->lpsi_version != the_lnet.ln_peertable_version) {
                LNET_UNLOCK();
                return -ESTALE;
        }

        lp = lpsi->lpsi_peer;

        nid      = lp->lp_nid;
        maxcr    = lp->lp_ni->ni_peertxcredits;
        txcr     = lp->lp_txcredits;
        mintxcr  = lp->lp_mintxcredits;
        rtrcr    = lp->lp_rtrcredits;
        minrtrcr = lp->lp_minrtrcredits;
        alive    = lp->lp_alive;
        txqnob   = lp->lp_txqnob;
        nrefs    = lp->lp_refcount;

        LNET_UNLOCK();

        seq_printf(s, "%-24s %4d %5s %5d %5d %5d %5d %5d %d\n",
                   libcfs_nid2str(nid), nrefs, alive ? "up" : "down",
                   maxcr, rtrcr, minrtrcr, txcr, mintxcr, txqnob);
        return 0;
}

static struct seq_operations lnet_peer_sops = {
        .start = lnet_peer_seq_start,
        .stop  = lnet_peer_seq_stop,
        .next  = lnet_peer_seq_next,
        .show  = lnet_peer_seq_show,
};

static int
lnet_peer_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file       *sf;
        int                    rc;

        rc = seq_open(file, &lnet_peer_sops);
        if (rc == 0) {
                sf = file->private_data;
                sf->private = dp->data;
        }

        return rc;
}

static struct file_operations lnet_peer_fops = {
        .owner   = THIS_MODULE,
        .open    = lnet_peer_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

typedef struct {
        int                  lbsi_idx;
        loff_t               lbsi_off;
} lnet_buffer_seq_iterator_t;

int
lnet_buffer_seq_seek (lnet_buffer_seq_iterator_t *lbsi, loff_t off)
{
        int                idx;
        loff_t             here;
        int                rc;

        if (off == 0) {
                lbsi->lbsi_idx = -1;
                lbsi->lbsi_off = 0;
                return 0;
        }

        LNET_LOCK();

        if (lbsi->lbsi_idx < 0 ||
            lbsi->lbsi_off > off) {
                /* search from start */
                idx = 0;
                here = 1;
        } else {
                /* continue search */
                idx = lbsi->lbsi_idx;
                here = lbsi->lbsi_off;
        }

        lbsi->lbsi_off     = off;

        while (idx < LNET_NRBPOOLS) {
                if (here == off) {
                        lbsi->lbsi_idx = idx;
                        rc = 0;
                        goto out;
                }
                here++;
                idx++;
        }

        lbsi->lbsi_idx  = -1;
        rc              = -ENOENT;
 out:
        LNET_UNLOCK();
        return rc;
}

static void *
lnet_buffer_seq_start (struct seq_file *s, loff_t *pos)
{
        lnet_buffer_seq_iterator_t *lbsi;
        int                        rc;

        LIBCFS_ALLOC(lbsi, sizeof(*lbsi));
        if (lbsi == NULL)
                return NULL;

        lbsi->lbsi_idx = -1;
        rc = lnet_buffer_seq_seek(lbsi, *pos);
        if (rc == 0)
                return lbsi;

        LIBCFS_FREE(lbsi, sizeof(*lbsi));
        return NULL;
}

static void
lnet_buffer_seq_stop (struct seq_file *s, void *iter)
{
        lnet_buffer_seq_iterator_t  *lbsi = iter;

        if (lbsi != NULL)
                LIBCFS_FREE(lbsi, sizeof(*lbsi));
}

static void *
lnet_buffer_seq_next (struct seq_file *s, void *iter, loff_t *pos)
{
        lnet_buffer_seq_iterator_t *lbsi = iter;
        int                         rc;
        loff_t                      next = *pos + 1;

        rc = lnet_buffer_seq_seek(lbsi, next);
        if (rc != 0) {
                LIBCFS_FREE(lbsi, sizeof(*lbsi));
                return NULL;
        }

        *pos = next;
        return lbsi;
}

static int
lnet_buffer_seq_show (struct seq_file *s, void *iter)
{
        lnet_buffer_seq_iterator_t *lbsi = iter;
        lnet_rtrbufpool_t          *rbp;
        int                         npages;
        int                         nbuf;
        int                         cr;
        int                         mincr;

        if (lbsi->lbsi_off == 0) {
                seq_printf(s, "%5s %5s %7s %7s\n",
                           "pages", "count", "credits", "min");
                return 0;
        }

        LASSERT (lbsi->lbsi_idx >= 0 && lbsi->lbsi_idx < LNET_NRBPOOLS);

        LNET_LOCK();

        rbp = &the_lnet.ln_rtrpools[lbsi->lbsi_idx];

        npages = rbp->rbp_npages;
        nbuf   = rbp->rbp_nbuffers;
        cr     = rbp->rbp_credits;
        mincr  = rbp->rbp_mincredits;

        LNET_UNLOCK();

        seq_printf(s, "%5d %5d %7d %7d\n",
                   npages, nbuf, cr, mincr);
        return 0;
}

static struct seq_operations lnet_buffer_sops = {
        .start = lnet_buffer_seq_start,
        .stop  = lnet_buffer_seq_stop,
        .next  = lnet_buffer_seq_next,
        .show  = lnet_buffer_seq_show,
};

static int
lnet_buffer_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file       *sf;
        int                    rc;

        rc = seq_open(file, &lnet_buffer_sops);
        if (rc == 0) {
                sf = file->private_data;
                sf->private = dp->data;
        }

        return rc;
}

static struct file_operations lnet_buffers_fops = {
        .owner   = THIS_MODULE,
        .open    = lnet_buffer_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

typedef struct {
        lnet_ni_t           *lnsi_ni;
        loff_t               lnsi_off;
} lnet_ni_seq_iterator_t;

int
lnet_ni_seq_seek (lnet_ni_seq_iterator_t *lnsi, loff_t off)
{
        struct list_head  *n;
        loff_t             here;
        int                rc;

        if (off == 0) {
                lnsi->lnsi_ni = NULL;
                lnsi->lnsi_off = 0;
                return 0;
        }

        LNET_LOCK();

        if (lnsi->lnsi_ni == NULL ||
            lnsi->lnsi_off > off) {
                /* search from start */
                n = NULL;
                here = 1;
        } else {
                /* continue search */
                n = &lnsi->lnsi_ni->ni_list;
                here = lnsi->lnsi_off;
        }

        lnsi->lnsi_off = off;

        if (n == NULL)
                n = the_lnet.ln_nis.next;

        while (n != &the_lnet.ln_nis) {
                if (here == off) {
                        lnsi->lnsi_ni = list_entry(n, lnet_ni_t, ni_list);
                        rc = 0;
                        goto out;
                }
                here++;
                n = n->next;
        }

        lnsi->lnsi_ni  = NULL;
        rc             = -ENOENT;
 out:
        LNET_UNLOCK();
        return rc;
}

static void *
lnet_ni_seq_start (struct seq_file *s, loff_t *pos)
{
        lnet_ni_seq_iterator_t *lnsi;
        int                     rc;

        LIBCFS_ALLOC(lnsi, sizeof(*lnsi));
        if (lnsi == NULL)
                return NULL;

        lnsi->lnsi_ni = NULL;
        rc = lnet_ni_seq_seek(lnsi, *pos);
        if (rc == 0)
                return lnsi;

        LIBCFS_FREE(lnsi, sizeof(*lnsi));
        return NULL;
}

static void
lnet_ni_seq_stop (struct seq_file *s, void *iter)
{
        lnet_ni_seq_iterator_t  *lnsi = iter;

        if (lnsi != NULL)
                LIBCFS_FREE(lnsi, sizeof(*lnsi));
}

static void *
lnet_ni_seq_next (struct seq_file *s, void *iter, loff_t *pos)
{
        lnet_ni_seq_iterator_t *lnsi = iter;
        int                     rc;
        loff_t                  next = *pos + 1;

        rc = lnet_ni_seq_seek(lnsi, next);
        if (rc != 0) {
                LIBCFS_FREE(lnsi, sizeof(*lnsi));
                return NULL;
        }

        *pos = next;
        return lnsi;
}

static int
lnet_ni_seq_show (struct seq_file *s, void *iter)
{
        lnet_ni_seq_iterator_t *lnsi = iter;
        lnet_ni_t              *ni;
        int                     maxtxcr;
        int                     txcr;
        int                     mintxcr;
        int                     npeertxcr;
        lnet_nid_t              nid;
        int                     nref;

        if (lnsi->lnsi_off == 0) {
                seq_printf(s, "%-24s %4s %4s %5s %5s %5s\n",
                           "nid", "refs", "peer", "max", "tx", "min");
                return 0;
        }

        LASSERT (lnsi->lnsi_ni != NULL);

        LNET_LOCK();

        ni = lnsi->lnsi_ni;

        maxtxcr   = ni->ni_maxtxcredits;
        txcr      = ni->ni_txcredits;
        mintxcr   = ni->ni_mintxcredits;
        npeertxcr = ni->ni_peertxcredits;
        nid       = ni->ni_nid;
        nref      = ni->ni_refcount;

        LNET_UNLOCK();

        seq_printf(s, "%-24s %4d %4d %5d %5d %5d\n",
                   libcfs_nid2str(nid), nref,
                   npeertxcr, maxtxcr, txcr, mintxcr);
        return 0;
}

static struct seq_operations lnet_ni_sops = {
        .start = lnet_ni_seq_start,
        .stop  = lnet_ni_seq_stop,
        .next  = lnet_ni_seq_next,
        .show  = lnet_ni_seq_show,
};

static int
lnet_ni_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file       *sf;
        int                    rc;

        rc = seq_open(file, &lnet_ni_sops);
        if (rc == 0) {
                sf = file->private_data;
                sf->private = dp->data;
        }

        return rc;
}

static struct file_operations lnet_ni_fops = {
        .owner   = THIS_MODULE,
        .open    = lnet_ni_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

void
lnet_proc_init(void)
{
        struct proc_dir_entry *stats;
        struct proc_dir_entry *routes;
        struct proc_dir_entry *routers;
        struct proc_dir_entry *peers;

        /* Initialize LNET_PROC_STATS */
        stats = create_proc_entry (LNET_PROC_STATS, 0644, NULL);
        if (stats == NULL) {
                CERROR("couldn't create proc entry %s\n", LNET_PROC_STATS);
                return;
        }

        stats->data = NULL;
        stats->read_proc = lnet_router_proc_stats_read;
        stats->write_proc = lnet_router_proc_stats_write;

        /* Initialize LNET_PROC_ROUTES */
        routes = create_proc_entry (LNET_PROC_ROUTES, 0444, NULL);
        if (routes == NULL) {
                CERROR("couldn't create proc entry %s\n", LNET_PROC_ROUTES);
                return;
        }

        routes->proc_fops = &lnet_routes_fops;
        routes->data = NULL;

        /* Initialize LNET_PROC_ROUTERS */
        routers = create_proc_entry (LNET_PROC_ROUTERS, 0444, NULL);
        if (routers == NULL) {
                CERROR("couldn't create proc entry %s\n", LNET_PROC_ROUTERS);
                return;
        }

        routers->proc_fops = &lnet_routers_fops;
        routers->data = NULL;

        /* Initialize LNET_PROC_PEERS */
        peers = create_proc_entry (LNET_PROC_PEERS, 0444, NULL);
        if (peers == NULL) {
                CERROR("couldn't create proc entry %s\n", LNET_PROC_PEERS);
                return;
        }

        peers->proc_fops = &lnet_peer_fops;
        peers->data = NULL;

        /* Initialize LNET_PROC_BUFFERS */
        peers = create_proc_entry (LNET_PROC_BUFFERS, 0444, NULL);
        if (peers == NULL) {
                CERROR("couldn't create proc entry %s\n", LNET_PROC_BUFFERS);
                return;
        }

        peers->proc_fops = &lnet_buffers_fops;
        peers->data = NULL;

        /* Initialize LNET_PROC_NIS */
        peers = create_proc_entry (LNET_PROC_NIS, 0444, NULL);
        if (peers == NULL) {
                CERROR("couldn't create proc entry %s\n", LNET_PROC_NIS);
                return;
        }

        peers->proc_fops = &lnet_ni_fops;
        peers->data = NULL;
}

void
lnet_proc_fini(void)
{
        remove_proc_entry(LNET_PROC_STATS, 0);
        remove_proc_entry(LNET_PROC_ROUTES, 0);
        remove_proc_entry(LNET_PROC_ROUTERS, 0);
        remove_proc_entry(LNET_PROC_PEERS, 0);
        remove_proc_entry(LNET_PROC_BUFFERS, 0);
        remove_proc_entry(LNET_PROC_NIS, 0);
}

#else

void
lnet_proc_init(void)
{
}

void
lnet_proc_fini(void)
{
}

#endif
