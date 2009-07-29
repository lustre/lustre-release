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
 * Kernel - userspace communication routines.  We'll use a shorthand term
 * "lnl" (Lustre NetLink) for the interface names for all arches (even though
 * implemtation may not use NetLink).
 * For Linux, we use Netlink sockets.
 */

#define DEBUG_SUBSYSTEM S_CLASS

/* This is the userspace side.
 * See libcfs/linux/linux-kernelcomm.c for the kernel side.
 */

#ifdef HAVE_NETLINK

#include <sys/socket.h>
#include <linux/netlink.h>

#include <libcfs/libcfs.h>

/** Start the userspace side of a LNL pipe.
 * @param link Private descriptor for pipe/socket.
 * @param groups LNL broadcast group to listen to
 *          (can be null for unicast to this pid)
 */
int libcfs_ulnl_start(lustre_netlink *link, int groups)
{
        struct sockaddr_nl src_addr;
        int sock;
        int rc = 0;

        sock = socket(PF_NETLINK, SOCK_RAW, LNL_SOCKET);
        if (sock < 0)
                return -errno;

        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();  /* self pid */
        src_addr.nl_groups = groups;
        rc = bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
        if (rc < 0) {
                close(sock);
                return -errno;
        }
        *link = sock;
        return 0;
}

int libcfs_ulnl_stop(lustre_netlink *link)
{
        return close(*link);
}

/** Read a message from the netlink layer.
 *
 * @param link Private descriptor for pipe/socket.
 * @param maxsize Maximum message size allowed
 * @param transport Only listen to messages on this transport
 *      (and the generic transport)
 * @param lnlhh Handle to the new LNL message
 */
int libcfs_ulnl_msg_get(lustre_netlink *link, int maxsize, int transport,
                        struct lnl_hdr **lnlhh)
{
        struct iovec iov;
        struct sockaddr_nl dest_addr;
        struct msghdr msg;
        struct nlmsghdr *nlh = NULL;
        struct lnl_hdr *lnlh;
        int rc = 0;

        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(maxsize));
        if (!nlh)
                return -ENOMEM;

        memset(nlh, 0, NLMSG_SPACE(maxsize));
        iov.iov_base = (void *)nlh;
        iov.iov_len = NLMSG_SPACE(maxsize);

        memset(&dest_addr, 0, sizeof(dest_addr));
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        CDEBUG(0, "Waiting for message from kernel on pid %d\n", getpid());

        while (1) {
                /* Read message from kernel */
                rc = recvmsg(*link, &msg, 0);
                if (rc <= 0) {
                        perror("recv");
                        rc = -errno;
                        break;
                }
                lnlh = (struct lnl_hdr *)NLMSG_DATA(nlh);
                CDEBUG(0, " Received message mg=%x t=%d m=%d l=%d\n",
                       lnlh->lnl_magic, lnlh->lnl_transport, lnlh->lnl_msgtype,
                       lnlh->lnl_msglen);
                if (lnlh->lnl_magic != LNL_MAGIC) {
                        CERROR("bad message magic %x != %x\n",
                               lnlh->lnl_magic, LNL_MAGIC);
                        rc = -EPROTO;
                        break;
                }
                if (lnlh->lnl_transport == transport ||
                    lnlh->lnl_transport == LNL_TRANSPORT_GENERIC) {
                        *lnlhh = lnlh;
                        return 0;
                }
                /* Ignore messages on other transports */
        }
        free(nlh);
        return rc;
}

/* Free a message returned by the above fn */
int libcfs_ulnl_msg_free(struct lnl_hdr **lnlhh)
{
        /* compute nlmsdghdr offset */
        char *p = (char *)NLMSG_DATA(0);

        free((void *)((char *)*lnlhh - p));
        *lnlhh = NULL;
        return 0;
}

#else /* HAVE_NETLINK */

#include <errno.h>

typedef int lustre_netlink;
int libcfs_ulnl_start(lustre_netlink *link, int groups) {
        return -ENOSYS;
}
int libcfs_ulnl_stop(lustre_netlink *link) {
        return 0;
}
struct lnl_hdr;
int libcfs_ulnl_msg_get(lustre_netlink *link, int maxsize, int transport,
                        struct lnl_hdr **lnlhh) {
        return -ENOSYS;
}
int libcfs_ulnl_msg_free(struct lnl_hdr **lnlhh) {
        return -ENOSYS;
}
#endif /* HAVE_NETLINK */

