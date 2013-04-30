/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef OST_INTERNAL_H
#define OST_INTERNAL_H

#define OSS_SERVICE_WATCHDOG_FACTOR 2

/*
 * tunables for per-thread page pool (bug 5137)
 */
#define OST_THREAD_POOL_SIZE PTLRPC_MAX_BRW_PAGES  /* pool size in pages */
#define OST_THREAD_POOL_GFP  CFS_ALLOC_HIGHUSER    /* GFP mask for pool pages */

struct page;
struct niobuf_local;
struct niobuf_remote;
struct ptlrpc_request;

/*
 * struct ost_thread_local_cache is allocated and initialized for each OST
 * thread by ost_thread_init().
 */
struct ost_thread_local_cache {
        /*
         * pool of nio buffers used by write-path
         */
        struct niobuf_local   local[OST_THREAD_POOL_SIZE];
        unsigned int          temporary:1;
};

struct ost_thread_local_cache *ost_tls(struct ptlrpc_request *r);

#ifdef LPROCFS
void lprocfs_ost_init_vars(struct lprocfs_static_vars *lvars);
#else
static void lprocfs_ost_init_vars(struct lprocfs_static_vars *lvars)
{
        memset(lvars, 0, sizeof(*lvars));
}
#endif

#endif /* OST_INTERNAL_H */
