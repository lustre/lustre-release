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
 * Basic library routines. 
 *
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
#define SOCK_WMEM_QUEUED(so)    ((so)->sk->sk_wmem_queued)
#define SOCK_ERROR(so)          ((so)->sk->sk_err)
#define SOCK_TEST_NOSPACE(so)   test_bit(SOCK_NOSPACE, &(so)->flags)

#endif

#endif
