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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

typedef struct cfs_socket {
        int s_fd;
} cfs_socket_t;

#define LIBCFS_SOCK2FD(sock) ((sock)->s_fd)

int libcfs_sock_listen(cfs_socket_t **sockp, __u32 ip, int port, int backlog);
int libcfs_sock_accept(cfs_socket_t **newsockp, cfs_socket_t *sock);
int libcfs_sock_read(cfs_socket_t *sock, void *buffer, int nob, int timeout);
int libcfs_sock_write(cfs_socket_t *sock, void *buffer, int nob, int timeout);
void libcfs_sock_abort_accept(cfs_socket_t *sock);
void libcfs_sock_release(cfs_socket_t *sock);
int libcfs_sock_getaddr(cfs_socket_t *sock, int remote, __u32 *ip, int *port);

/*
 * Network functions of common use
 */

int libcfs_socketpair(cfs_socket_t **sockp);
int libcfs_fcntl_nonblock(cfs_socket_t *sock);
int libcfs_sock_set_nagle(cfs_socket_t *sock, int nagle);
int libcfs_sock_set_bufsiz(cfs_socket_t *sock, int bufsiz);
int libcfs_sock_connect(cfs_socket_t *sock, __u32 ip, __u16 port);
int libcfs_sock_writev(cfs_socket_t *sock,
                       const struct iovec *vector, int count);
int libcfs_sock_readv(cfs_socket_t *sock,
                      const struct iovec *vector, int count);
int libcfs_sock_create(cfs_socket_t **sockp, int *fatal,
                       __u32 local_ip, int local_port);


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
