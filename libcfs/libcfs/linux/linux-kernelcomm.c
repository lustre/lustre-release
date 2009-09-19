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
 * Kernel <-> userspace communication routines.  We'll use a shorthand term
 * "lnl" (Lustre NetLink) for the interface names for all arches (even though
 * implemtation may not use NetLink).
 * For Linux, we use Netlink sockets.
 */

#define DEBUG_SUBSYSTEM S_CLASS


/* This is the kernel side.
 * See libcfs/ulinux/ulinux-kernelcomm.c for the user side.
 */

#if defined(HAVE_NETLINK) && defined(__KERNEL__)

#include <linux/module.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <net/netlink.h>

#include <libcfs/libcfs.h>

/* OFED backport #defines netlink_kernel_create with 6 args.
   I haven't a clue why that header file gets included here,
   but we must undo its mischief. */
#ifdef BACKPORT_LINUX_NETLINK_H
#undef netlink_kernel_create
#endif


/* Single Netlink Message type to send all Lustre messages */
#define LNL_MSG 26

static struct sock *lnl_socket = NULL;
static atomic_t lnl_start_count = ATOMIC_INIT(0);
static spinlock_t lnl_lock = SPIN_LOCK_UNLOCKED;

/** Start the netlink socket for this transport
 * @param transport lnl_transport
 */
int libcfs_klnl_start(int transport)
{
        int rc = 0;
        ENTRY;

        /* If anyone needs it, we can add per-transport incoming message
           callbacks.  Add the callback as a param here.  Store the transport
           and callback in a table. Include a generalized incoming msg
           callback here to dispatch messages to the appropriate
           per-transport callback. */

        spin_lock(&lnl_lock);
        if (atomic_inc_return(&lnl_start_count) > 1)
                GOTO(out, rc = 0);

        lnl_socket = netlink_kernel_create(LNL_SOCKET, LNL_GRP_CNT,
                                           NULL /* incoming cb */,
                                           THIS_MODULE);
        if (lnl_socket == NULL) {
                CERROR("Cannot open socket %d\n", LNL_SOCKET);
                atomic_dec(&lnl_start_count);
                GOTO(out, rc = -ENODEV);
        }

out:
        spin_unlock(&lnl_lock);
        RETURN(rc);
}
EXPORT_SYMBOL(libcfs_klnl_start);

static void send_shutdown_msg(int transport, int group) {
        struct lnl_hdr lh;

        lh.lnl_magic = LNL_MAGIC;
        lh.lnl_transport = LNL_TRANSPORT_GENERIC;
        lh.lnl_msgtype = LNL_MSG_SHUTDOWN;
        lh.lnl_msglen = sizeof(lh);

        libcfs_klnl_msg_put(0, group, &lh);
}

/* This should be called once per (started) transport
 * @param transport lnl_transport
 * @param group Broadcast group for shutdown message */
int libcfs_klnl_stop(int transport, int group)
{
        if (group)
                send_shutdown_msg(transport, group);

        spin_lock(&lnl_lock);

        if (atomic_dec_and_test(&lnl_start_count)) {
                sock_release(lnl_socket->sk_socket);
                lnl_socket = NULL;
        }

        spin_unlock(&lnl_lock);
        return 0;
}
EXPORT_SYMBOL(libcfs_klnl_stop);

static struct sk_buff *netlink_make_msg(int pid, int seq, void *payload,
                                        int size)
{
        struct sk_buff  *skb;
        struct nlmsghdr *nlh;
        int             len = NLMSG_SPACE(size);
        void            *data;

#ifdef HAVE_NETLINK_NL2
        skb = nlmsg_new(len, GFP_KERNEL);
#else   /* old */
        skb = nlmsg_new(len);
#endif

        if (!skb)
                return NULL;

        nlh = nlmsg_put(skb, pid, seq, LNL_MSG, size, 0);
        if (!nlh) {
                nlmsg_free(skb);
                return NULL;
        }

        data = nlmsg_data(nlh);
        memcpy(data, payload, size);
        return skb;
}

/**
 * libcfs_klnl_msg_put - send an message from kernel to userspace
 * @param pid Process id to send message to for unicast messages; must be 0 for
 *   broadcast
 * @param group Broadcast group; 0 for unicast messages
 * @param payload Payload data.  First field of payload is always struct lnl_hdr
 *
 * Allocates an skb, builds the netlink message, and sends it to the pid.
 */
int libcfs_klnl_msg_put(int pid, int group, void *payload)
{
        struct lnl_hdr *lnlh = (struct lnl_hdr *)payload;
        struct sk_buff  *skb;
        int rc;

        if (lnl_socket == NULL) {
                CERROR("LustreNetLink: not running\n");
                return -ENOSYS;
        }

        if (lnlh->lnl_magic != LNL_MAGIC) {
                CERROR("LustreNetLink: bad magic %x\n", lnlh->lnl_magic);
                return -ENOSYS;
        }

        if ((pid != 0) && (group != 0)) {
                CERROR("LustreNetLink: pid=%d or group=%d must be 0\n",
                       pid, group);
                return -EINVAL;
        }

        skb = netlink_make_msg(pid, 0, payload, lnlh->lnl_msglen);
        if (!skb)
                return -ENOMEM;

        if (pid) {
                rc = netlink_unicast(lnl_socket, skb, pid,
                             lnlh->lnl_flags & LNL_FL_BLOCK ? 0 : MSG_DONTWAIT);
                if (rc > 0)
                        rc = 0;
        } else {
                rc = nlmsg_multicast(lnl_socket, skb, 0, group);
        }

        CDEBUG(0, "Sent message pid=%d, group=%d, rc=%d\n", pid, group, rc);

        if (rc < 0)
                CWARN("message send failed (%d) [pid=%d,group=%d]\n", rc,
                      pid, group);

        return rc;
}
EXPORT_SYMBOL(libcfs_klnl_msg_put);


#endif

