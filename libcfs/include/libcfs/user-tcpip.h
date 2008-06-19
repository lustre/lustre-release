/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
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
 */

#ifndef __LIBCFS_USER_TCPIP_H__
#define __LIBCFS_USER_TCPIP_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifndef __KERNEL__

#include <sys/uio.h>

/*
 * Functions to get network interfaces info
 */

int libcfs_sock_ioctl(int cmd, unsigned long arg);
int libcfs_ipif_query (char *name, int *up, __u32 *ip);
void libcfs_ipif_free_enumeration (char **names, int n);
int libcfs_ipif_enumerate (char ***namesp);

/*
 * Network function used by user-land lnet acceptor
 */

int libcfs_sock_listen (int *sockp, __u32 local_ip, int local_port, int backlog);
int libcfs_sock_accept (int *newsockp, int sock, __u32 *peer_ip, int *peer_port);
int libcfs_sock_read (int sock, void *buffer, int nob, int timeout);
void libcfs_sock_abort_accept(__u16 port);

/*
 * Network functions of common use
 */

int libcfs_getpeername(int sock_fd, __u32 *ipaddr_p, __u16 *port_p);
int libcfs_socketpair(int *fdp);
int libcfs_fcntl_nonblock(int fd);
int libcfs_sock_set_nagle(int fd, int nagle);
int libcfs_sock_set_bufsiz(int fd, int bufsiz);
int libcfs_sock_create(int *fdp);
int libcfs_sock_bind_to_port(int fd, __u16 port);
int libcfs_sock_connect(int fd, __u32 ip, __u16 port);
int libcfs_sock_writev(int fd, const struct iovec *vector, int count);
int libcfs_sock_readv(int fd, const struct iovec *vector, int count);

/*
 * Macros for easy printing IP-adresses
 */

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#if defined(__LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN)
#define HIPQUAD(addr)                \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN) || defined(_BIG_ENDIAN)
#define HIPQUAD NIPQUAD
#else
#error "Undefined byteorder??"
#endif /* __LITTLE_ENDIAN */

#endif /* !__KERNEL__ */

#endif
