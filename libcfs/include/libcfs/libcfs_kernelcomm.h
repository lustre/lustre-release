/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 *
 * libcfs/include/libcfs/libcfs_kernelcomm.h
 *
 * Kernel <-> userspace communication routines.  We'll use a shorthand term
 * "lnl" (Lustre NetLink) for this interface name for all arches, even though
 * an implemtation may not use NetLink.
 * The definitions below are used in the kernel and userspace.
 *
 */

#ifndef __LIBCFS_KERNELCOMM_H__
#define __LIBCFS_KERNELCOMM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

/* LNL message header.
 * All current and future LNL messages should use this header.
 * To avoid having to include Lustre headers from libcfs, define this here.
 */
struct lnl_hdr {
        __u16 lnl_magic;
        __u8  lnl_transport;  /* Each new Lustre feature should use a different
                                 transport */
        __u8  lnl_flags;
        __u16 lnl_msgtype;    /* Message type or opcode, transport-specific */
        __u16 lnl_msglen;
} __attribute__((aligned(sizeof(__u64))));

#define LNL_MAGIC  0x191C /*Lustre9etLinC */
#define LNL_FL_BLOCK 0x01   /* Wait for send */

/* lnl_msgtype values are defined in each transport */
enum lnl_transport_type {
        LNL_TRANSPORT_GENERIC   = 1,
        LNL_TRANSPORT_HSM       = 2,
        LNL_TRANSPORT_CHANGELOG = 3,
};

enum lnl_generic_message_type {
        LNL_MSG_SHUTDOWN = 1,
};

/* LNL Broadcast Groups. This determines which userspace process hears which
 * messages.  Mutliple transports may be used within a group, or multiple
 * groups may use the same transport.  Broadcast
 * groups need not be used if e.g. a PID is specified instead;
 * use group 0 to signify unicast.
 */
#define LNL_GRP_HSM           0x02
#define LNL_GRP_CNT              2


#if defined(HAVE_NETLINK) && defined (__KERNEL__)
extern int libcfs_klnl_start(int transport);
extern int libcfs_klnl_stop(int transport, int group);
extern int libcfs_klnl_msg_put(int pid, int group, void *payload);
#else
static inline int libcfs_klnl_start(int transport) {
        return -ENOSYS;
}
static inline int libcfs_klnl_stop(int transport, int group) {
        return 0;
}
static inline int libcfs_klnl_msg_put(int pid, int group, void *payload) {
        return -ENOSYS;
}
#endif

/*
 * NetLink socket number, see include/linux/netlink.h
 * All LNL users share a single netlink socket.  This actually is NetLink
 * specific, but is not to be used outside of the Linux implementation
 * (linux-kernelcomm.c and posix-kernelcomm.c).
 */
#define LNL_SOCKET 26


#endif /* __LIBCFS_KERNELCOMM_H__ */

