/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 */

#ifndef _LUSTRE_DEBUG_H
#define _LUSTRE_DEBUG_H

#include <lustre_net.h>

#if defined(__linux__)
#include <linux/lustre_debug.h>
#elif defined(__APPLE__)
#include <darwin/lustre_debug.h>
#elif defined(__WINNT__)
#include <winnt/lustre_debug.h>
#else
#error Unsupported operating system.
#endif

#define ASSERT_MAX_SIZE_MB 60000ULL
#define ASSERT_PAGE_INDEX(index, OP)                                    \
do { if (index > ASSERT_MAX_SIZE_MB << (20 - CFS_PAGE_SHIFT)) {         \
        CERROR("bad page index %lu > %Lu\n", index,                     \
               ASSERT_MAX_SIZE_MB << (20 - CFS_PAGE_SHIFT));            \
        libcfs_debug = ~0UL;                                            \
        OP;                                                             \
}} while(0)

#define ASSERT_FILE_OFFSET(offset, OP)                                  \
do { if (offset > ASSERT_MAX_SIZE_MB << 20) {                           \
        CERROR("bad file offset %Lu > %Lu\n", offset,                   \
               ASSERT_MAX_SIZE_MB << 20);                               \
        libcfs_debug = ~0UL;                                            \
        OP;                                                             \
}} while(0)

/* lib/debug.c */
int dump_lniobuf(struct niobuf_local *lnb);
int dump_rniobuf(struct niobuf_remote *rnb);
int dump_ioo(struct obd_ioobj *nb);
int dump_req(struct ptlrpc_request *req);
int dump_obdo(struct obdo *oa);
void dump_lsm(int level, struct lov_stripe_md *lsm);
int block_debug_setup(void *addr, int len, __u64 off, __u64 id);
int block_debug_check(char *who, void *addr, int len, __u64 off, __u64 id);
#endif
