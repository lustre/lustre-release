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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/include/libcfs/linux/linux-tcpip.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_TCP_H__
#define __LIBCFS_LINUX_CFS_TCP_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__
#include <net/sock.h>

typedef struct socket   cfs_socket_t;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,72))
# define sk_allocation  allocation
# define sk_data_ready  data_ready
# define sk_write_space write_space
# define sk_user_data   user_data
# define sk_prot        prot
# define sk_sndbuf      sndbuf
# define sk_rcvbuf      rcvbuf
# define sk_socket      socket
# define sk_sleep       sleep
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
# define sk_wmem_queued wmem_queued
# define sk_err         err
# define sk_route_caps  route_caps
#endif

#define SOCK_SNDBUF(so)         ((so)->sk->sk_sndbuf)
#define SOCK_TEST_NOSPACE(so)   test_bit(SOCK_NOSPACE, &(so)->flags)

static inline int
libcfs_sock_error(struct socket *sock)
{
        return sock->sk->sk_err;
}

static inline int
libcfs_sock_wmem_queued(struct socket *sock)
{
        return sock->sk->sk_wmem_queued;
}

#else   /* !__KERNEL__ */

#include "../user-tcpip.h"

#endif /* __KERNEL__ */

#endif
