/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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

/* this is really lnet_proc.c */

static cfs_sysctl_table_header_t *lnet_table_header = NULL;

#ifndef HAVE_SYSCTL_UNNUMBERED
#define CTL_LNET         (0x100)
enum {
        PSDEV_LNET_STATS = 100,
        PSDEV_LNET_ROUTES,
        PSDEV_LNET_ROUTERS,
        PSDEV_LNET_PEERS,
        PSDEV_LNET_BUFFERS,
        PSDEV_LNET_NIS,
};
#else
#define CTL_LNET           CTL_UNNUMBERED
#define PSDEV_LNET_STATS   CTL_UNNUMBERED
#define PSDEV_LNET_ROUTES  CTL_UNNUMBERED
#define PSDEV_LNET_ROUTERS CTL_UNNUMBERED
#define PSDEV_LNET_PEERS   CTL_UNNUMBERED
#define PSDEV_LNET_BUFFERS CTL_UNNUMBERED
#define PSDEV_LNET_NIS     CTL_UNNUMBERED
#endif

/*
 * NB: we don't use the highest bit of *ppos because it's signed;
 *     next 9 bits is used to stash idx (assuming that
 *     LNET_PEER_HASHSIZE < 512)
 */
#define LNET_LOFFT_BITS        (sizeof(loff_t) * 8)
#define LNET_VERSION_BITS      MAX(((MIN(LNET_LOFFT_BITS, 64)) / 4), 8)
#define LNET_PHASH_IDX_BITS    9
#define LNET_PHASH_NUM_BITS    (LNET_LOFFT_BITS - 1 -\
                                LNET_VERSION_BITS - LNET_PHASH_IDX_BITS)
#define LNET_PHASH_BITS        (LNET_PHASH_IDX_BITS + LNET_PHASH_NUM_BITS)

#define LNET_VERSION_BITMASK   ((1ULL << LNET_VERSION_BITS) - 1)
#define LNET_PHASH_IDX_BITMASK ((1ULL << LNET_PHASH_IDX_BITS) - 1)
#define LNET_PHASH_NUM_BITMASK ((1ULL << LNET_PHASH_NUM_BITS) - 1)

#define LNET_VERSION_MASK      (LNET_VERSION_BITMASK << LNET_PHASH_BITS)
#define LNET_PHASH_IDX_MASK    (LNET_PHASH_IDX_BITMASK << LNET_PHASH_NUM_BITS)
#define LNET_PHASH_NUM_MASK    (LNET_PHASH_NUM_BITMASK)

#define LNET_VERSION_GET(pos)   (int)(((pos) & LNET_VERSION_MASK) >> \
                                     LNET_PHASH_BITS)
#define LNET_PHASH_IDX_GET(pos) (int)(((pos) & LNET_PHASH_IDX_MASK) >> \
                                      LNET_PHASH_NUM_BITS)
#define LNET_PHASH_NUM_GET(pos) (int)((pos) & LNET_PHASH_NUM_MASK)
#define LNET_VERSION_VALID_MASK(ver) \
                                ((unsigned int)((ver) & LNET_VERSION_BITMASK))
#define LNET_PHASH_POS_MAKE(ver, idx, num)                                     \
                                (((((loff_t)(ver)) & LNET_VERSION_BITMASK) <<  \
                                   LNET_PHASH_BITS) |                          \
                                 ((((loff_t)(idx)) & LNET_PHASH_IDX_BITMASK) <<\
                                   LNET_PHASH_NUM_BITS) |                      \
                                 ((num) & LNET_PHASH_NUM_BITMASK))

static int __proc_lnet_stats(void *data, int write,
                             loff_t pos, void *buffer, int nob)
{
        int              rc;
        lnet_counters_t *ctrs;
        int              len;
        char            *tmpstr;
        const int        tmpsiz = 256; /* 7 %u and 4 LPU64 */

        if (write) {
                LNET_LOCK();
                memset(&the_lnet.ln_counters, 0, sizeof(the_lnet.ln_counters));
                LNET_UNLOCK();
                return 0;
        }

        /* read */

        LIBCFS_ALLOC(ctrs, sizeof(*ctrs));
        if (ctrs == NULL)
                return -ENOMEM;

        LIBCFS_ALLOC(tmpstr, tmpsiz);
        if (tmpstr == NULL) {
                LIBCFS_FREE(ctrs, sizeof(*ctrs));
                return -ENOMEM;
        }

        LNET_LOCK();
        *ctrs = the_lnet.ln_counters;
        LNET_UNLOCK();

        len = snprintf(tmpstr, tmpsiz,
                       "%u %u %u %u %u %u %u "LPU64" "LPU64" "
                       LPU64" "LPU64,
                       ctrs->msgs_alloc, ctrs->msgs_max,
                       ctrs->errors,
                       ctrs->send_count, ctrs->recv_count,
                       ctrs->route_count, ctrs->drop_count,
                       ctrs->send_length, ctrs->recv_length,
                       ctrs->route_length, ctrs->drop_length);

        if (pos >= min_t(int, len, strlen(tmpstr)))
                rc = 0;
        else
                rc = trace_copyout_string(buffer, nob,
                                          tmpstr + pos, "\n");

        LIBCFS_FREE(tmpstr, tmpsiz);
        LIBCFS_FREE(ctrs, sizeof(*ctrs));
        return rc;
}

DECLARE_PROC_HANDLER(proc_lnet_stats);

int LL_PROC_PROTO(proc_lnet_routes)
{
        int        rc     = 0;
        char      *tmpstr;
        char      *s;
        const int  tmpsiz = 256;
        int        len;
        int        ver;
        int        num;

        DECLARE_LL_PROC_PPOS_DECL;

        num = LNET_PHASH_NUM_GET(*ppos);
        ver = LNET_VERSION_GET(*ppos);

        LASSERT (!write);

        if (*lenp == 0)
                return 0;

        LIBCFS_ALLOC(tmpstr, tmpsiz);
        if (tmpstr == NULL)
                return -ENOMEM;

        s = tmpstr; /* points to current position in tmpstr[] */

        if (*ppos == 0) {
                s += snprintf(s, tmpstr + tmpsiz - s, "Routing %s\n",
                              the_lnet.ln_routing ? "enabled" : "disabled");
                LASSERT (tmpstr + tmpsiz - s > 0);

                s += snprintf(s, tmpstr + tmpsiz - s, "%-8s %4s %7s %s\n",
                              "net", "hops", "state", "router");
                LASSERT (tmpstr + tmpsiz - s > 0);

                LNET_LOCK();
                ver = (unsigned int)the_lnet.ln_remote_nets_version;
                LNET_UNLOCK();
                *ppos = LNET_PHASH_POS_MAKE(ver, 0, num);
        } else {
                struct list_head  *n;
                struct list_head  *r;
                lnet_route_t      *route = NULL;
                lnet_remotenet_t  *rnet  = NULL;
                int                skip  = num - 1;

                LNET_LOCK();

                if (ver != LNET_VERSION_VALID_MASK(the_lnet.ln_remote_nets_version)) {
                        LNET_UNLOCK();
                        LIBCFS_FREE(tmpstr, tmpsiz);
                        return -ESTALE;
                }

                n = the_lnet.ln_remote_nets.next;

                while (n != &the_lnet.ln_remote_nets && route == NULL) {
                        rnet = list_entry(n, lnet_remotenet_t, lrn_list);

                        r = rnet->lrn_routes.next;

                        while (r != &rnet->lrn_routes) {
                                lnet_route_t *re = list_entry(r, lnet_route_t,
                                                              lr_list);
                                if (skip == 0) {
                                        route = re;
                                        break;
                                }

                                skip--;
                                r = r->next;
                        }

                        n = n->next;
                }

                if (route != NULL) {
                        __u32        net   = rnet->lrn_net;
                        unsigned int hops  = route->lr_hops;
                        lnet_nid_t   nid   = route->lr_gateway->lp_nid;
                        int          alive = route->lr_gateway->lp_alive;

                        s += snprintf(s, tmpstr + tmpsiz - s, "%-8s %4u %7s %s\n",
                                      libcfs_net2str(net), hops,
                                      alive ? "up" : "down", libcfs_nid2str(nid));
                        LASSERT (tmpstr + tmpsiz - s > 0);
                }

                LNET_UNLOCK();
        }

        len = s - tmpstr;     /* how many bytes was written */

        if (len > *lenp) {    /* linux-supplied buffer is too small */
                rc = -EINVAL;
        } else if (len > 0) { /* wrote something */
                if (copy_to_user(buffer, tmpstr, len))
                        rc = -EFAULT;
                else {
                        num += 1;
                        *ppos = LNET_PHASH_POS_MAKE(ver, 0, num);
                }
        }

        LIBCFS_FREE(tmpstr, tmpsiz);

        if (rc == 0)
                *lenp = len;

        return rc;
}

int LL_PROC_PROTO(proc_lnet_routers)
{
        int        rc = 0;
        char      *tmpstr;
        char      *s;
        const int  tmpsiz = 256;
        int        len;
        int        ver;
        int        num;

        DECLARE_LL_PROC_PPOS_DECL;

        num = LNET_PHASH_NUM_GET(*ppos);
        ver = LNET_VERSION_GET(*ppos);

        LASSERT (!write);

        if (*lenp == 0)
                return 0;

        LIBCFS_ALLOC(tmpstr, tmpsiz);
        if (tmpstr == NULL)
                return -ENOMEM;

        s = tmpstr; /* points to current position in tmpstr[] */

        if (*ppos == 0) {
                s += snprintf(s, tmpstr + tmpsiz - s,
                              "%-4s %7s %9s %6s %12s %9s %8s %7s %s\n",
                              "ref", "rtr_ref", "alive_cnt", "state", "last_ping",
                              "ping_sent", "deadline", "down_ni", "router");
                LASSERT (tmpstr + tmpsiz - s > 0);

                LNET_LOCK();
                ver = (unsigned int)the_lnet.ln_routers_version;
                LNET_UNLOCK();
                *ppos = LNET_PHASH_POS_MAKE(ver, 0, num);
        } else {
                struct list_head  *r;
                lnet_peer_t       *peer = NULL;
                int                skip = num - 1;

                LNET_LOCK();

                if (ver != LNET_VERSION_VALID_MASK(the_lnet.ln_routers_version)) {
                        LNET_UNLOCK();
                        LIBCFS_FREE(tmpstr, tmpsiz);
                        return -ESTALE;
                }

                r = the_lnet.ln_routers.next;

                while (r != &the_lnet.ln_routers) {
                        lnet_peer_t *lp = list_entry(r, lnet_peer_t,
                                                     lp_rtr_list);

                        if (skip == 0) {
                                peer = lp;
                                break;
                        }

                        skip--;
                        r = r->next;
                }

                if (peer != NULL) {
                        lnet_nid_t nid = peer->lp_nid;
                        cfs_time_t now = cfs_time_current();
                        cfs_time_t deadline = peer->lp_ping_deadline;
                        int nrefs     = peer->lp_refcount;
                        int nrtrrefs  = peer->lp_rtr_refcount;
                        int alive_cnt = peer->lp_alive_count;
                        int alive     = peer->lp_alive;
                        int pingsent  = !peer->lp_ping_notsent;
                        int last_ping = cfs_duration_sec(cfs_time_sub(now,
                                                     peer->lp_ping_timestamp));
                        int down_ni   = lnet_router_down_ni(peer,
                                                    LNET_NIDNET(LNET_NID_ANY));

                        if (deadline == 0)
                                s += snprintf(s, tmpstr + tmpsiz - s,
                                              "%-4d %7d %9d %6s %12d %9d %8s %7d %s\n",
                                              nrefs, nrtrrefs, alive_cnt,
                                              alive ? "up" : "down", last_ping,
                                              pingsent, "NA", down_ni,
                                              libcfs_nid2str(nid));
                        else
                                s += snprintf(s, tmpstr + tmpsiz - s,
                                              "%-4d %7d %9d %6s %12d %9d %8lu %7d %s\n",
                                              nrefs, nrtrrefs, alive_cnt,
                                              alive ? "up" : "down", last_ping,
                                              pingsent,
                                              cfs_duration_sec(cfs_time_sub(deadline, now)),
                                              down_ni, libcfs_nid2str(nid));
                        LASSERT (tmpstr + tmpsiz - s > 0);
                }

                LNET_UNLOCK();
        }

        len = s - tmpstr;     /* how many bytes was written */

        if (len > *lenp) {    /* linux-supplied buffer is too small */
                rc = -EINVAL;
        } else if (len > 0) { /* wrote something */
                if (copy_to_user(buffer, tmpstr, len))
                        rc = -EFAULT;
                else {
                        num += 1;
                        *ppos = LNET_PHASH_POS_MAKE(ver, 0, num);
                }
        }

        LIBCFS_FREE(tmpstr, tmpsiz);

        if (rc == 0)
                *lenp = len;

        return rc;
}

int LL_PROC_PROTO(proc_lnet_peers)
{
        int        rc = 0;
        char      *tmpstr;
        char      *s;
        const int  tmpsiz      = 256;
        int        len;
        int        ver;
        int        idx;
        int        num;

        DECLARE_LL_PROC_PPOS_DECL;

        idx = LNET_PHASH_IDX_GET(*ppos);
        num = LNET_PHASH_NUM_GET(*ppos);
        ver = LNET_VERSION_GET(*ppos);

        CLASSERT ((1ULL << LNET_PHASH_BITS) > LNET_PEER_HASHSIZE);

        LASSERT (!write);

        if (*lenp == 0)
                return 0;

        LIBCFS_ALLOC(tmpstr, tmpsiz);
        if (tmpstr == NULL)
                return -ENOMEM;

        s = tmpstr; /* points to current position in tmpstr[] */

        if (*ppos == 0) {
                s += snprintf(s, tmpstr + tmpsiz - s,
                              "%-24s %4s %5s %5s %5s %5s %5s %5s %s\n",
                              "nid", "refs", "state", "max",
                              "rtr", "min", "tx", "min", "queue");
                LASSERT (tmpstr + tmpsiz - s > 0);

                LNET_LOCK();
                ver = (unsigned int)the_lnet.ln_peertable_version;
                LNET_UNLOCK();
                *ppos = LNET_PHASH_POS_MAKE(ver, idx, num);

                num++;
        } else {
                struct list_head  *p    = NULL;
                lnet_peer_t       *peer = NULL;
                int                skip = num - 1;

                LNET_LOCK();

                if (ver != LNET_VERSION_VALID_MASK(the_lnet.ln_peertable_version)) {
                        LNET_UNLOCK();
                        LIBCFS_FREE(tmpstr, tmpsiz);
                        return -ESTALE;
                }

                while (idx < LNET_PEER_HASHSIZE) {
                        if (p == NULL)
                                p = the_lnet.ln_peer_hash[idx].next;

                        while (p != &the_lnet.ln_peer_hash[idx]) {
                                lnet_peer_t *lp = list_entry(p, lnet_peer_t,
                                                             lp_hashlist);
                                if (skip == 0) {
                                        peer = lp;

                                        /* minor optimiztion: start from idx+1
                                         * on next iteration if we've just
                                         * drained lp_hashlist */
                                        if (lp->lp_hashlist.next ==
                                            &the_lnet.ln_peer_hash[idx]) {
                                                num = 1;
                                                idx++;
                                        } else {
                                                num++;
                                        }

                                        break;
                                }

                                skip--;
                                p = lp->lp_hashlist.next;
                        }

                        if (peer != NULL)
                                break;

                        p = NULL;
                        num = 1;
                        idx++;
                }

                if (peer != NULL) {
                        lnet_nid_t nid       = peer->lp_nid;
                        int        nrefs     = peer->lp_refcount;
                        char      *aliveness = "NA";
                        int        maxcr     = peer->lp_ni->ni_peertxcredits;
                        int        txcr      = peer->lp_txcredits;
                        int        mintxcr   = peer->lp_mintxcredits;
                        int        rtrcr     = peer->lp_rtrcredits;
                        int        minrtrcr  = peer->lp_minrtrcredits;
                        int        txqnob    = peer->lp_txqnob;

                        if (lnet_isrouter(peer) ||
                            lnet_peer_aliveness_enabled(peer))
                                aliveness = peer->lp_alive ? "up" : "down";

                        s += snprintf(s, tmpstr + tmpsiz - s,
                                      "%-24s %4d %5s %5d %5d %5d %5d %5d %d\n",
                                      libcfs_nid2str(nid), nrefs, aliveness,
                                      maxcr, rtrcr, minrtrcr, txcr,
                                      mintxcr, txqnob);
                        LASSERT (tmpstr + tmpsiz - s > 0);
                }

                LNET_UNLOCK();
        }

        len = s - tmpstr;     /* how many bytes was written */

        if (len > *lenp) {    /* linux-supplied buffer is too small */
                rc = -EINVAL;
        } else if (len > 0) { /* wrote something */
                if (copy_to_user(buffer, tmpstr, len))
                        rc = -EFAULT;
                else
                        *ppos = LNET_PHASH_POS_MAKE(ver, idx, num);
        }

        LIBCFS_FREE(tmpstr, tmpsiz);

        if (rc == 0)
                *lenp = len;

        return rc;
}

static int __proc_lnet_buffers(void *data, int write,
                               loff_t pos, void *buffer, int nob)
{

        int              rc;
        int              len;
        char            *s;
        char            *tmpstr;
        const int        tmpsiz = 64 * (LNET_NRBPOOLS + 1); /* (4 %d) * 4 */
        int              idx;

        LASSERT (!write);

        LIBCFS_ALLOC(tmpstr, tmpsiz);
        if (tmpstr == NULL)
                return -ENOMEM;

        s = tmpstr; /* points to current position in tmpstr[] */

        s += snprintf(s, tmpstr + tmpsiz - s,
                      "%5s %5s %7s %7s\n",
                      "pages", "count", "credits", "min");
        LASSERT (tmpstr + tmpsiz - s > 0);

        LNET_LOCK();

        for (idx = 0; idx < LNET_NRBPOOLS; idx++) {
                lnet_rtrbufpool_t *rbp = &the_lnet.ln_rtrpools[idx];

                int npages = rbp->rbp_npages;
                int nbuf   = rbp->rbp_nbuffers;
                int cr     = rbp->rbp_credits;
                int mincr  = rbp->rbp_mincredits;

                s += snprintf(s, tmpstr + tmpsiz - s,
                              "%5d %5d %7d %7d\n",
                              npages, nbuf, cr, mincr);
                LASSERT (tmpstr + tmpsiz - s > 0);
        }

        LNET_UNLOCK();

        len = s - tmpstr;

        if (pos >= min_t(int, len, strlen(tmpstr)))
                rc = 0;
        else
                rc = trace_copyout_string(buffer, nob,
                                          tmpstr + pos, NULL);

        LIBCFS_FREE(tmpstr, tmpsiz);
        return rc;
}

DECLARE_PROC_HANDLER(proc_lnet_buffers);

int LL_PROC_PROTO(proc_lnet_nis)
{
        int        rc = 0;
        char      *tmpstr;
        char      *s;
        const int  tmpsiz = 256;
        int        len;

        DECLARE_LL_PROC_PPOS_DECL;

        LASSERT (!write);

        if (*lenp == 0)
                return 0;

        LIBCFS_ALLOC(tmpstr, tmpsiz);
        if (tmpstr == NULL)
                return -ENOMEM;

        s = tmpstr; /* points to current position in tmpstr[] */

        if (*ppos == 0) {
                s += snprintf(s, tmpstr + tmpsiz - s,
                              "%-24s %6s %5s %4s %4s %4s %5s %5s %5s\n",
                              "nid", "status", "alive", "refs", "peer",
                              "rtr", "max", "tx", "min");
                LASSERT (tmpstr + tmpsiz - s > 0);
        } else {
                struct list_head  *n;
                lnet_ni_t         *ni   = NULL;
                int                skip = *ppos - 1;

                LNET_LOCK();

                n = the_lnet.ln_nis.next;

                while (n != &the_lnet.ln_nis) {
                        lnet_ni_t *a_ni = list_entry(n, lnet_ni_t, ni_list);

                        if (skip == 0) {
                                ni = a_ni;
                                break;
                        }

                        skip--;
                        n = n->next;
                }

                if (ni != NULL) {
                        cfs_time_t now = cfs_time_current();
                        int        last_alive = -1;
                        int        maxtxcr = ni->ni_maxtxcredits;
                        int        txcr = ni->ni_txcredits;
                        int        mintxcr = ni->ni_mintxcredits;
                        int        npeertxcr = ni->ni_peertxcredits;
                        int        npeerrtrcr = ni->ni_peerrtrcredits;
                        lnet_nid_t nid = ni->ni_nid;
                        int        nref = ni->ni_refcount;
                        char      *stat;

                        if (the_lnet.ln_routing)
                                last_alive = cfs_duration_sec(cfs_time_sub(now,
                                                            ni->ni_last_alive));
                        if (ni->ni_lnd->lnd_type == LOLND)  /* @lo forever alive */
                                last_alive = 0;

                        LASSERT (ni->ni_status != NULL);
                        stat = (ni->ni_status->ns_status == LNET_NI_STATUS_UP) ?
                                                                  "up" : "down";

                        s += snprintf(s, tmpstr + tmpsiz - s,
                                      "%-24s %6s %5d %4d %4d %4d %5d %5d %5d\n",
                                      libcfs_nid2str(nid), stat, last_alive, nref,
                                      npeertxcr, npeerrtrcr, maxtxcr,
                                      txcr, mintxcr);
                        LASSERT (tmpstr + tmpsiz - s > 0);
                }

                LNET_UNLOCK();
        }

        len = s - tmpstr;     /* how many bytes was written */

        if (len > *lenp) {    /* linux-supplied buffer is too small */
                rc = -EINVAL;
        } else if (len > 0) { /* wrote something */
                if (copy_to_user(buffer, tmpstr, len))
                        rc = -EFAULT;
                else
                        *ppos += 1;
        }

        LIBCFS_FREE(tmpstr, tmpsiz);

        if (rc == 0)
                *lenp = len;

        return rc;
}

static cfs_sysctl_table_t lnet_table[] = {
        /*
         * NB No .strategy entries have been provided since sysctl(8) prefers
         * to go via /proc for portability.
         */
        {
                .ctl_name = PSDEV_LNET_STATS,
                .procname = "stats",
                .mode     = 0644,
                .proc_handler = &proc_lnet_stats,
        },
        {
                .ctl_name = PSDEV_LNET_ROUTES,
                .procname = "routes",
                .mode     = 0444,
                .proc_handler = &proc_lnet_routes,
        },
        {
                .ctl_name = PSDEV_LNET_ROUTERS,
                .procname = "routers",
                .mode     = 0444,
                .proc_handler = &proc_lnet_routers,
        },
        {
                .ctl_name = PSDEV_LNET_PEERS,
                .procname = "peers",
                .mode     = 0444,
                .proc_handler = &proc_lnet_peers,
        },
        {
                .ctl_name = PSDEV_LNET_PEERS,
                .procname = "buffers",
                .mode     = 0444,
                .proc_handler = &proc_lnet_buffers,
        },
        {
                .ctl_name = PSDEV_LNET_NIS,
                .procname = "nis",
                .mode     = 0444,
                .proc_handler = &proc_lnet_nis,
        },
        {0}
};

static cfs_sysctl_table_t top_table[] = {
        {
                .ctl_name = CTL_LNET,
                .procname = "lnet",
                .mode     = 0555,
                .data     = NULL,
                .maxlen   = 0,
                .child    = lnet_table,
        },
        {
                .ctl_name = 0
        }
};

void
lnet_proc_init(void)
{
#ifdef CONFIG_SYSCTL
        if (lnet_table_header == NULL)
                lnet_table_header = cfs_register_sysctl_table(top_table, 0);
#endif
}

void
lnet_proc_fini(void)
{
#ifdef CONFIG_SYSCTL
        if (lnet_table_header != NULL)
                cfs_unregister_sysctl_table(lnet_table_header);

        lnet_table_header = NULL;
#endif
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
