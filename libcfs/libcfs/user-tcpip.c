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

#if !defined(__KERNEL__) || !defined(REDSTORM)

#include <libcfs/libcfs.h>

#include <sys/socket.h>
#ifdef  HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>

/*
 * Functions to get network interfaces info
 */

int
libcfs_sock_ioctl(int cmd, unsigned long arg)
{
        int fd, rc;

        fd = socket(AF_INET, SOCK_STREAM, 0);

        if (fd < 0) {
                rc = -errno;
                CERROR("socket() failed: errno==%d\n", errno);
                return rc;
        }

        rc = ioctl(fd, cmd, arg);

        close(fd);
        return rc;
}

int
libcfs_ipif_query (char *name, int *up, __u32 *ip)
{
        struct ifreq   ifr;
        int            nob;
        int            rc;
        __u32          val;

        nob = strlen(name);
        if (nob >= IFNAMSIZ) {
                CERROR("Interface name %s too long\n", name);
                return -EINVAL;
        }

        CLASSERT (sizeof(ifr.ifr_name) >= IFNAMSIZ);

        strcpy(ifr.ifr_name, name);
        rc = libcfs_sock_ioctl(SIOCGIFFLAGS, (unsigned long)&ifr);

        if (rc != 0) {
                CERROR("Can't get flags for interface %s\n", name);
                return rc;
        }

        if ((ifr.ifr_flags & IFF_UP) == 0) {
                CDEBUG(D_NET, "Interface %s down\n", name);
                *up = 0;
                *ip = 0;
                return 0;
        }

        *up = 1;

        strcpy(ifr.ifr_name, name);
        ifr.ifr_addr.sa_family = AF_INET;
        rc = libcfs_sock_ioctl(SIOCGIFADDR, (unsigned long)&ifr);

        if (rc != 0) {
                CERROR("Can't get IP address for interface %s\n", name);
                return rc;
        }

        val = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        *ip = ntohl(val);

        return 0;
}

void
libcfs_ipif_free_enumeration (char **names, int n)
{
        int      i;

        LASSERT (n > 0);

        for (i = 0; i < n && names[i] != NULL; i++)
                LIBCFS_FREE(names[i], IFNAMSIZ);

        LIBCFS_FREE(names, n * sizeof(*names));
}

int
libcfs_ipif_enumerate (char ***namesp)
{
        /* Allocate and fill in 'names', returning # interfaces/error */
        char          **names;
        int             nalloc;
        int             nfound;
        struct ifreq   *ifr;
        struct ifconf   ifc;
        int             rc;
        int             nob;
        int             i;


        nalloc = 16;        /* first guess at max interfaces */
        for (;;) {
                LIBCFS_ALLOC(ifr, nalloc * sizeof(*ifr));
                if (ifr == NULL) {
                        CERROR ("ENOMEM enumerating up to %d interfaces\n",
                                nalloc);
                        rc = -ENOMEM;
                        goto out0;
                }

                ifc.ifc_buf = (char *)ifr;
                ifc.ifc_len = nalloc * sizeof(*ifr);

                rc = libcfs_sock_ioctl(SIOCGIFCONF, (unsigned long)&ifc);

                if (rc < 0) {
                        CERROR ("Error %d enumerating interfaces\n", rc);
                        goto out1;
                }

                LASSERT (rc == 0);

                nfound = ifc.ifc_len/sizeof(*ifr);
                LASSERT (nfound <= nalloc);

                if (nfound < nalloc)
                        break;

                LIBCFS_FREE(ifr, nalloc * sizeof(*ifr));
                nalloc *= 2;
        }

        if (nfound == 0)
                goto out1;

        LIBCFS_ALLOC(names, nfound * sizeof(*names));
        if (names == NULL) {
                rc = -ENOMEM;
                goto out1;
        }
        /* NULL out all names[i] */
        memset (names, 0, nfound * sizeof(*names));

        for (i = 0; i < nfound; i++) {

                nob = strlen (ifr[i].ifr_name);
                if (nob >= IFNAMSIZ) {
                        /* no space for terminating NULL */
                        CERROR("interface name %.*s too long (%d max)\n",
                               nob, ifr[i].ifr_name, IFNAMSIZ);
                        rc = -ENAMETOOLONG;
                        goto out2;
                }

                LIBCFS_ALLOC(names[i], IFNAMSIZ);
                if (names[i] == NULL) {
                        rc = -ENOMEM;
                        goto out2;
                }

                memcpy(names[i], ifr[i].ifr_name, nob);
                names[i][nob] = 0;
        }

        *namesp = names;
        rc = nfound;

 out2:
        if (rc < 0)
                libcfs_ipif_free_enumeration(names, nfound);
 out1:
        LIBCFS_FREE(ifr, nalloc * sizeof(*ifr));
 out0:
        return rc;
}

/*
 * Network functions used by user-land lnet acceptor
 */

int
libcfs_sock_listen (cfs_socket_t **sockp,
                    __u32 local_ip, int local_port, int backlog)
{
        int rc;
        int fatal;

        rc = libcfs_sock_create(sockp, &fatal, local_ip, local_port);
        if (rc != 0)
                return rc;

        if ( listen((*sockp)->s_fd, backlog) ) {
                rc = -errno;
                CERROR("listen() with backlog==%d failed: errno==%d\n",
                       backlog, errno);
                goto failed;
        }

        return 0;

  failed:
        libcfs_sock_release(*sockp);
        return rc;
}

void
libcfs_sock_release (cfs_socket_t *sock)
{
        close(sock->s_fd);
        LIBCFS_FREE(sock, sizeof(cfs_socket_t));
}

int
libcfs_sock_accept (cfs_socket_t **newsockp, cfs_socket_t *sock)
{
        struct sockaddr_in accaddr;
        socklen_t          accaddr_len = sizeof(struct sockaddr_in);

        LIBCFS_ALLOC(*newsockp, sizeof(cfs_socket_t));
        if (*newsockp == NULL) {
                CERROR ("Can't alloc memory for cfs_socket_t\n");
                return -ENOMEM;
        }

        (*newsockp)->s_fd = accept(sock->s_fd,
                                   (struct sockaddr *)&accaddr, &accaddr_len);

        if ( (*newsockp)->s_fd < 0 ) {
                int rc = -errno;
                CERROR("accept() failed: errno==%d\n", -rc);
                LIBCFS_FREE(*newsockp, sizeof(cfs_socket_t));
                return rc;
        }

        return 0;
}

int
libcfs_sock_read (cfs_socket_t *sock, void *buffer, int nob, int timeout)
{
        int           rc;
        struct pollfd pfd;
        cfs_time_t    start_time = cfs_time_current();

        pfd.fd = sock->s_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        /* poll(2) measures timeout in msec */
        timeout *= 1000;

        while (nob != 0 && timeout > 0) {
                cfs_time_t current_time;

                rc = poll(&pfd, 1, timeout);
                if (rc < 0)
                        return -errno;
                if (rc == 0)
                        return -ETIMEDOUT;
                if ((pfd.revents & POLLIN) == 0)
                        return -EIO;

                rc = read(sock->s_fd, buffer, nob);
                if (rc < 0)
                        return -errno;
                if (rc == 0)
                        return -EIO;

                buffer = ((char *)buffer) + rc;
                nob -= rc;

                current_time = cfs_time_current();
                timeout -= 1000 *
                        cfs_duration_sec(cfs_time_sub(current_time,
                                                      start_time));
                start_time = current_time;
        }

        if (nob == 0)
                return 0;
        else
                return -ETIMEDOUT;
}

int
libcfs_sock_write (cfs_socket_t *sock, void *buffer, int nob, int timeout)
{
        int           rc;
        struct pollfd pfd;
        cfs_time_t    start_time = cfs_time_current();

        pfd.fd = sock->s_fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        /* poll(2) measures timeout in msec */
        timeout *= 1000;

        while (nob != 0 && timeout > 0) {
                cfs_time_t current_time;

                rc = poll(&pfd, 1, timeout);
                if (rc < 0)
                        return -errno;
                if (rc == 0)
                        return -ETIMEDOUT;
                if ((pfd.revents & POLLOUT) == 0)
                        return -EIO;

                rc = write(sock->s_fd, buffer, nob);
                if (rc < 0)
                        return -errno;
                if (rc == 0)
                        return -EIO;

                buffer = ((char *)buffer) + rc;
                nob -= rc;

                current_time = cfs_time_current();
                timeout -= 1000 *
                        cfs_duration_sec(cfs_time_sub(current_time,
                                                      start_time));
                start_time = current_time;
        }

        if (nob == 0)
                return 0;
        else
                return -ETIMEDOUT;
}

/* Just try to connect to localhost to wake up entity that are
 * sleeping in accept() */
void
libcfs_sock_abort_accept(cfs_socket_t *sock)
{
        int                fd, rc;
        struct sockaddr_in remaddr;
        struct sockaddr_in locaddr;
        socklen_t          alen = sizeof(struct sockaddr_in);

        rc = getsockname(sock->s_fd, (struct sockaddr *)&remaddr, &alen);
        if ( rc != 0 ) {
                CERROR("getsockname() failed: errno==%d\n", errno);
                return;
        }

        memset(&locaddr, 0, sizeof(locaddr));
        locaddr.sin_family = AF_INET;
        locaddr.sin_port = remaddr.sin_port;
        locaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if ( fd < 0 ) {
                CERROR("socket() failed: errno==%d\n", errno);
                return;
        }

        rc = connect(fd, (struct sockaddr *)&locaddr, sizeof(locaddr));
        if ( rc != 0 ) {
                if ( errno != ECONNREFUSED )
                        CERROR("connect() failed: errno==%d\n", errno);
                else
                        CDEBUG(D_NET, "Nobody to wake up at %d\n",
                               ntohs(remaddr.sin_port));
        }

        close(fd);
}

int
libcfs_sock_getaddr(cfs_socket_t *sock, int remote, __u32 *ip, int *port)
{
        int                rc;
        struct sockaddr_in peer_addr;
        socklen_t          peer_addr_len = sizeof(peer_addr);

        LASSERT(remote == 1);

        rc = getpeername(sock->s_fd,
                         (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (rc != 0)
                return -errno;

        if (ip != NULL)
                *ip = ntohl(peer_addr.sin_addr.s_addr);
        if (port != NULL)
                *port = ntohs(peer_addr.sin_port);

        return rc;
}

/*
 * Network functions of common use
 */

int
libcfs_socketpair(cfs_socket_t **sockp)
{
        int rc, i, fdp[2];

        LIBCFS_ALLOC(sockp[0], sizeof(cfs_socket_t));
        if (sockp[0] == NULL) {
                CERROR ("Can't alloc memory for cfs_socket_t (1)\n");
                return -ENOMEM;
        }

        LIBCFS_ALLOC(sockp[1], sizeof(cfs_socket_t));
        if (sockp[1] == NULL) {
                CERROR ("Can't alloc memory for cfs_socket_t (2)\n");
                LIBCFS_FREE(sockp[0], sizeof(cfs_socket_t));
                return -ENOMEM;
        }

        rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fdp);
        if (rc != 0) {
                rc = -errno;
                CERROR ("Cannot create socket pair\n");
                LIBCFS_FREE(sockp[0], sizeof(cfs_socket_t));
                LIBCFS_FREE(sockp[1], sizeof(cfs_socket_t));
                return rc;
        }

        sockp[0]->s_fd = fdp[0];
        sockp[1]->s_fd = fdp[1];

        for (i = 0; i < 2; i++) {
                rc = libcfs_fcntl_nonblock(sockp[i]);
                if (rc) {
                        libcfs_sock_release(sockp[0]);
                        libcfs_sock_release(sockp[1]);
                        return rc;
                }
        }

        return 0;
}

int
libcfs_fcntl_nonblock(cfs_socket_t *sock)
{
        int rc, flags;

        flags = fcntl(sock->s_fd, F_GETFL, 0);
        if (flags == -1) {
                rc = -errno;
                CERROR ("Cannot get socket flags\n");
                return rc;
        }

        rc = fcntl(sock->s_fd, F_SETFL, flags | O_NONBLOCK);
        if (rc != 0) {
                rc = -errno;
                CERROR ("Cannot set socket flags\n");
                return rc;
        }

        return 0;
}

int
libcfs_sock_set_nagle(cfs_socket_t *sock, int nagle)
{
        int rc;
        int option = nagle ? 0 : 1;

        rc = setsockopt(sock->s_fd,
                        IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option));
        if (rc != 0) {
                rc = -errno;
                CERROR ("Cannot set NODELAY socket option\n");
                return rc;
        }

        return 0;
}

int
libcfs_sock_set_bufsiz(cfs_socket_t *sock, int bufsiz)
{
        int rc, option;

        LASSERT (bufsiz != 0);

        option = bufsiz;
        rc = setsockopt(sock->s_fd,
                        SOL_SOCKET, SO_SNDBUF, &option, sizeof(option));
        if (rc != 0) {
                rc = -errno;
                CERROR ("Cannot set SNDBUF socket option\n");
                return rc;
        }

        option = bufsiz;
        rc = setsockopt(sock->s_fd,
                        SOL_SOCKET, SO_RCVBUF, &option, sizeof(option));
        if (rc != 0) {
                rc = -errno;
                CERROR ("Cannot set RCVBUF socket option\n");
                return rc;
        }

        return 0;
}

int
libcfs_sock_bind(cfs_socket_t *sock, __u32 ip, __u16 port)
{
        int                rc;
        struct sockaddr_in locaddr;

        if (ip == 0 && port == 0)
                return 0;

        memset(&locaddr, 0, sizeof(locaddr));
        locaddr.sin_family = AF_INET;
        locaddr.sin_addr.s_addr = (ip == 0) ? INADDR_ANY : htonl(ip);
        locaddr.sin_port = htons(port);

        rc = bind(sock->s_fd, (struct sockaddr *)&locaddr, sizeof(locaddr));
        if (rc != 0) {
                rc = -errno;
                CERROR("Cannot bind to %d.%d.%d.%d %d: %d\n",
                       HIPQUAD(ip), port, rc);
                return rc;
        }

        return 0;
}

int
libcfs_sock_create(cfs_socket_t **sockp, int *fatal,
                   __u32 local_ip, int local_port)
{
        int rc, fd, option;

        *fatal = 1;

        LIBCFS_ALLOC(*sockp, sizeof(cfs_socket_t));
        if (*sockp == NULL) {
                CERROR("Can't alloc memory for cfs_socket_t\n");
                return -ENOMEM;
        }

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
                rc = -errno;
                CERROR("Cannot create socket: %d\n", rc);
                LIBCFS_FREE(*sockp, sizeof(cfs_socket_t));
                return rc;
        }

        (*sockp)->s_fd = fd;

        option = 1;
        rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                        &option, sizeof(option));
        if (rc != 0) {
                rc = -errno;
                CERROR("Cannot set SO_REUSEADDR for socket: %d\n", rc);
                libcfs_sock_release(*sockp);
                return rc;
        }

        rc = libcfs_sock_bind(*sockp, local_ip, local_port);
        if (rc != 0) {
                *fatal = 0;
                libcfs_sock_release(*sockp);
        }

        return rc;
}

int
libcfs_sock_connect(cfs_socket_t *sock, __u32 ip, __u16 port)
{
        int                rc;
        struct sockaddr_in addr;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(ip);
        addr.sin_port        = htons(port);

        rc = connect(sock->s_fd, (struct sockaddr *)&addr,
                     sizeof(struct sockaddr_in));

        if(rc != 0 && errno != EINPROGRESS) {
                rc = -errno;
                if (rc != -EADDRINUSE && rc != -EADDRNOTAVAIL)
                        CERROR ("Cannot connect to %u.%u.%u.%u:%d (err=%d)\n",
                                HIPQUAD(ip), port, errno);
                return rc;
        }

        return 0;
}

/* NB: EPIPE and ECONNRESET are considered as non-fatal
 * because:
 * 1) it still makes sense to continue reading &&
 * 2) anyway, poll() will set up POLLHUP|POLLERR flags */
int
libcfs_sock_writev(cfs_socket_t *sock, const struct iovec *vector, int count)
{
        int rc;

        rc = syscall(SYS_writev, sock->s_fd, vector, count);

        if (rc == 0) /* write nothing */
                return 0;

        if (rc < 0) {
                if (errno == EAGAIN ||   /* write nothing   */
                    errno == EPIPE ||    /* non-fatal error */
                    errno == ECONNRESET) /* non-fatal error */
                        return 0;
                else
                        return -errno;
        }

        return rc;
}

int
libcfs_sock_readv(cfs_socket_t *sock, const struct iovec *vector, int count)
{
        int rc;

        rc = syscall(SYS_readv, sock->s_fd, vector, count);

        if (rc == 0) /* EOF */
                return -EIO;

        if (rc < 0) {
                if (errno == EAGAIN) /* read nothing */
                        return 0;
                else
                        return -errno;
        }

        return rc;
}

#endif /* !__KERNEL__ || !defined(REDSTORM) */
