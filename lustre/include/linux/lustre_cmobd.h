/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Data structures for Cache Manager 
 *
 */

#ifndef _LUSTRE_CMOBD_H
#define _LUSTRE_CMOBD_H

#include <linux/obd_class.h>

#define OBD_CMOBD_DEVICENAME    "cmobd"

#define CMOBD_MAX_THREADS       32UL

#define CMOBD_NUM_THREADS       max(min_t(unsigned long, num_physpages / 8192, \
                                          CMOBD_MAX_THREADS), 2UL)

#define CMOBD_MAX_EXTENT_SZ     PTLRPC_MAX_BRW_PAGES * PAGE_SIZE

#define CMOBD_MAX_EXTENTS       1024

/* for keeping the capacity of handle multi extents simultaneously */
struct cmobd_extent_set {
        struct ldlm_extent       es_extent;
        struct obdo              es_oa; 
        
        struct lov_stripe_md    *es_lsm;
        struct obd_export       *es_exp;
        
        /* maximum length of per sub extent */ 
        unsigned long            es_ext_sz;
        /* sub extents count */
        obd_count                es_count;
        /* pages to be sent */
        struct list_head         es_pages;        
        /* protect the es_pages and es_count */
        spinlock_t               es_lock;
        
        wait_queue_head_t        es_waitq;
};

struct cmobd_extent_info {
        struct list_head         ei_link;
        struct cmobd_extent_set *ei_set;
        struct ldlm_extent       ei_extent;
};

struct cmobd_async_page {
        struct list_head         cmap_link;
        struct page             *cmap_page;
        void                    *cmap_cookie;
        struct cmobd_extent_set *cmap_es;
};

struct cmobd_write_service {
        struct list_head        ws_threads;
        int                     ws_nthreads;
        spinlock_t              ws_thread_lock;

        struct list_head        ws_extents;
        int                     ws_nextents;
        spinlock_t              ws_extent_lock;
        wait_queue_head_t       ws_waitq_provider;      /* extent provider queue */
        wait_queue_head_t       ws_waitq_consumer;      /* extent consumer queue */
};

#endif /* _LUSTRE_CMOBD_H */
