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

#define KPR_PROC_ROUTER "sys/portals/router"
#define KPR_PROC_ROUTES "sys/portals/routes"

/* Used for multi-page route list book keeping */
struct proc_route_data {
        struct list_head *curr;
        unsigned int generation;
        off_t skip;
} kpr_read_routes_data;

/* nal2name support re-used from utils/portals.c */
struct name2num {
        char *name;
        int   num;
} nalnames[] = {
        { "any",         0},
        { "elan",        QSWNAL},
        { "tcp",         SOCKNAL},
        { "gm",          GMNAL},
        { "ib",          OPENIBNAL},
        { NULL,          -1}
};

static struct name2num *name2num_lookup_num(struct name2num *table, int num)
{
        while (table->name != NULL)
                if (num == table->num)
                        return (table);
                else
                        table++;
        return (NULL);
}

static char *nal2name(int nal)
{
        struct name2num *e = name2num_lookup_num(nalnames, nal);
        return ((e == NULL) ? "???" : e->name);
}


static int kpr_proc_router_read(char *page, char **start, off_t off,
                                int count, int *eof, void *data)
{
        unsigned long long bytes = kpr_fwd_bytes;
        unsigned long      packets = kpr_fwd_packets;
        unsigned long      errors = kpr_fwd_errors;
        unsigned int       qdepth = atomic_read (&kpr_queue_depth);
        int                len;

        *eof = 1;
        if (off != 0)
                return (0);

        len = sprintf(page, "%Ld %ld %ld %d\n", bytes, packets, errors, qdepth);

        *start = page;
        return (len);
}

static int kpr_proc_router_write(struct file *file, const char *ubuffer,
                                 unsigned long count, void *data)
{
        /* Ignore what we've been asked to write, and just zero the stats */
        kpr_fwd_bytes = 0;
        kpr_fwd_packets = 0;
        kpr_fwd_errors = 0;

        return (count);
}

static int kpr_proc_routes_read(char *page, char **start, off_t off,
                                int count, int *eof, void *data)
{
        struct proc_route_data *prd = data;
        kpr_route_entry_t     *re;
        kpr_gateway_entry_t *ge;
        int                 chunk_len = 0;
        int                 line_len = 0;
        int                 user_len = 0;

        *eof = 1;
        *start = page;

        if (prd->curr == NULL) {
                if (off != 0)
                        return 0;

                /* First pass, initialize our private data */
                prd->curr = kpr_routes.next;
                prd->generation = kpr_routes_generation;
                prd->skip = 0;
        } else {
                /* Abort route list generation change */
                if (prd->generation != kpr_routes_generation) {
                        prd->curr = NULL;
                        return sprintf(page, "\nError: Routes Changed\n");
                }

                /* All the routes have been walked */
                if (prd->curr == &kpr_routes) {
                        prd->curr = NULL;
                        return 0;
                }
        }

        read_lock(&kpr_rwlock);
        *start = page + prd->skip;
        user_len = -prd->skip;

        while ((prd->curr != NULL) && (prd->curr != &kpr_routes)) {
                re = list_entry(prd->curr, kpr_route_entry_t, kpre_list);
                ge = re->kpre_gateway;

                line_len = sprintf(page + chunk_len,
                        "%12s  "LPX64" : "LPX64" - "LPX64", %s\n",
                        nal2name(ge->kpge_nalid), ge->kpge_nid,
                        re->kpre_lo_nid, re->kpre_hi_nid,
                        ge->kpge_alive ? "up" : "down");
                chunk_len += line_len;
                user_len += line_len;

                /* Abort the route list changed */
                if (prd->curr->next == NULL) {
                        prd->curr = NULL;
                        read_unlock(&kpr_rwlock);
                        return sprintf(page, "\nError: Routes Changed\n");
                }

                prd->curr = prd->curr->next;

                /* The route table will exceed one page, break the while loop
                 * so the function can be re-called with a new page.
                 */
                if ((chunk_len > (PAGE_SIZE - 80)) || (user_len > count))
                        break;
        }

        *eof = 0;

        /* Caller received only a portion of the last entry, the
         * remaining will be delivered in the next page if asked for.
         */
        if (user_len > count) {
                prd->curr = prd->curr->prev;
                prd->skip = line_len - (user_len - count);
                read_unlock(&kpr_rwlock);
                return count;
        }

        /* Not enough data to entirely satify callers request */
        prd->skip = 0;
        read_unlock(&kpr_rwlock);
        return user_len;
}

static int kpr_proc_routes_write(struct file *file, const char *ubuffer,
                                 unsigned long count, void *data)
{
        /* no-op; lctl should be used to adjust the routes */
        return (count);
}

void kpr_proc_init(void)
{
        struct proc_dir_entry *router_entry;
        struct proc_dir_entry *routes_entry;

        /* Initialize KPR_PROC_ROUTER */
        router_entry = create_proc_entry (KPR_PROC_ROUTER,
                S_IFREG | S_IRUGO | S_IWUSR, NULL);

        if (router_entry == NULL) {
                CERROR("couldn't create proc entry %s\n", KPR_PROC_ROUTER);
                return;
        }

        router_entry->data = NULL;
        router_entry->read_proc = kpr_proc_router_read;
        router_entry->write_proc = kpr_proc_router_write;

        /* Initialize KPR_PROC_ROUTES */
        routes_entry = create_proc_entry (KPR_PROC_ROUTES,
                S_IFREG | S_IRUGO | S_IWUSR, NULL);

        if (routes_entry == NULL) {
                CERROR("couldn't create proc entry %s\n", KPR_PROC_ROUTES);
                return;
        }

        kpr_read_routes_data.curr = NULL;
        kpr_read_routes_data.generation = 0;
        kpr_read_routes_data.skip = 0;

        routes_entry->data = &kpr_read_routes_data;
        routes_entry->read_proc = kpr_proc_routes_read;
        routes_entry->write_proc = kpr_proc_routes_write;
}

void kpr_proc_fini(void)
{
        remove_proc_entry(KPR_PROC_ROUTER, 0);
        remove_proc_entry(KPR_PROC_ROUTES, 0);
}
