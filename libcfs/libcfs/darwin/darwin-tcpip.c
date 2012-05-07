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
 *
 * libcfs/libcfs/darwin/darwin-tcpip.c
 *
 * Darwin porting library
 * Make things easy to port
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#include <mach/mach_types.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/protosw.h>
#include <net/if.h>

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

static __inline__ struct sockaddr_in
blank_sin()
{
        struct sockaddr_in  blank = { sizeof(struct sockaddr_in), AF_INET };
        return (blank);
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

#ifdef __DARWIN8__
/*
 * Darwin 8.x 
 *
 * No hack kernel structre, all using KPI.
 */

int
libcfs_ipif_query (char *name, int *up, __u32 *ip, __u32 *mask)
{
        struct ifreq    ifr;
        socket_t        so;
        __u32           val;
        int             nob;
        int             rc;

        rc = -sock_socket(PF_INET, SOCK_STREAM, 0, 
                          NULL, NULL, &so);
        if (rc != 0) {
                CERROR ("Can't create socket: %d\n", rc);
                return rc;
        }

        nob = strnlen(name, IFNAMSIZ);
        if (nob == IFNAMSIZ) {
                CERROR("Interface name %s too long\n", name);
                rc = -EINVAL;
                goto out;
        }

        CLASSERT (sizeof(ifr.ifr_name) >= IFNAMSIZ);
        bzero(&ifr, sizeof(ifr));
        strcpy(ifr.ifr_name, name);
        rc = -sock_ioctl (so, SIOCGIFFLAGS, &ifr);

        if (rc != 0) {
                CERROR("Can't get flags for interface %s\n", name);
                goto out;
        }
        
        if ((ifr.ifr_flags & IFF_UP) == 0) {
                CDEBUG(D_NET, "Interface %s down\n", name);
                *up = 0;
                *ip = *mask = 0;
                goto out;
        }

        *up = 1;

        bzero(&ifr, sizeof(ifr));
        strcpy(ifr.ifr_name, name);
        *((struct sockaddr_in *)&ifr.ifr_addr) = blank_sin();
        rc = -sock_ioctl(so, SIOCGIFADDR, &ifr);

        if (rc != 0) {
                CERROR("Can't get IP address for interface %s\n", name);
                goto out;
        }
        
        val = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        *ip = ntohl(val);

        bzero(&ifr, sizeof(ifr));
        strcpy(ifr.ifr_name, name);
        *((struct sockaddr_in *)&ifr.ifr_addr) = blank_sin();
        rc = -sock_ioctl(so, SIOCGIFNETMASK, &ifr);

        if (rc != 0) {
                CERROR("Can't get netmask for interface %s\n", name);
                goto out;
        }

        val = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        *mask = ntohl(val);
out:
        sock_close(so);
        return rc;
}

int
libcfs_ipif_enumerate (char ***namesp)
{
        /* Allocate and fill in 'names', returning # interfaces/error */
        char           **names;
        int             toobig;
        int             nalloc;
        int             nfound;
        socket_t        so;
        struct ifreq   *ifr;
        struct ifconf   ifc;
        int             rc;
        int             nob;
        int             i;

        rc = -sock_socket(PF_INET, SOCK_STREAM, 0, 
                          NULL, NULL, &so);
        if (rc != 0) {
                CERROR ("Can't create socket: %d\n", rc);
                return (rc);
        }

        nalloc = 16;    /* first guess at max interfaces */
        toobig = 0;
        for (;;) {
                if (nalloc * sizeof(*ifr) > CFS_PAGE_SIZE) {
                        toobig = 1;
                        nalloc = CFS_PAGE_SIZE/sizeof(*ifr);
                        CWARN("Too many interfaces: only enumerating first %d\n",
                              nalloc);
                }

                LIBCFS_ALLOC(ifr, nalloc * sizeof(*ifr));
                if (ifr == NULL) {
                        CERROR ("ENOMEM enumerating up to %d interfaces\n", nalloc);
                                rc = -ENOMEM;
                        goto out0;
                }
                                
                ifc.ifc_buf = (char *)ifr;
                ifc.ifc_len = nalloc * sizeof(*ifr);
                                        
#if 1
                /*
                 * XXX Liang:
                 * sock_ioctl(..., SIOCGIFCONF, ...) is not supposed to be used in
                 * kernel space because it always try to copy result to userspace. 
                 * So we can't get interfaces name by sock_ioctl(...,SIOCGIFCONF,...).
                 * I've created a bug for Apple, let's wait...
                 */
                nfound = 0;
                for (i = 0; i < 16; i++) {
                        struct ifreq    en;
                        bzero(&en, sizeof(en));
                        snprintf(en.ifr_name, IFNAMSIZ, "en%d", i);
                        rc = -sock_ioctl (so, SIOCGIFFLAGS, &en);
                        if (rc != 0)
                                continue;
                        strcpy(ifr[nfound++].ifr_name, en.ifr_name);
                }

#else           /* NOT in using now */
                rc = -sock_ioctl(so, SIOCGIFCONF, (caddr_t)&ifc);
                                
                if (rc < 0) {
                        CERROR ("Error %d enumerating interfaces\n", rc);
                        goto out1;
                }

                nfound = ifc.ifc_len/sizeof(*ifr);
                LASSERT (nfound <= nalloc);
#endif

                if (nfound < nalloc || toobig)
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

                nob = strnlen (ifr[i].ifr_name, IFNAMSIZ);
                if (nob == IFNAMSIZ) {
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
        sock_close(so);
        return rc;

}

/*
 * Public entry of socket upcall.
 *
 * so_upcall can only be installed while create/accept of socket in 
 * Darwin 8.0, so we setup libcfs_sock_upcall() as upcall for all 
 * sockets in creat/accept, it will call upcall provided by user 
 * which can be setup after create/accept of socket.
 */
static void libcfs_sock_upcall(socket_t so, void* arg, int waitf)
{
        cfs_socket_t    *sock;

        sock = (cfs_socket_t *)arg;
        LASSERT(sock->s_magic == CFS_SOCK_MAGIC);

        if ((sock->s_flags & CFS_SOCK_UPCALL) != 0 && sock->s_upcall != NULL)
                sock->s_upcall(so, sock->s_upcallarg, waitf);
        return;
}

void libcfs_sock_set_cb(cfs_socket_t *sock, so_upcall callback, void *arg)
{
        sock->s_upcall = callback;
        sock->s_upcallarg = arg;
        sock->s_flags |= CFS_SOCK_UPCALL;
        return;
}

void libcfs_sock_reset_cb(cfs_socket_t *sock)
{
        sock->s_flags &= ~CFS_SOCK_UPCALL;
        sock->s_upcall = NULL;
        sock->s_upcallarg = NULL;
        return;
}

static int
libcfs_sock_create (cfs_socket_t **sockp, int *fatal,
                    __u32 local_ip, int local_port)
{
        struct sockaddr_in  locaddr;
        cfs_socket_t    *sock;
        int             option;
        int             optlen;
        int             rc;

        /* All errors are fatal except bind failure if the port is in use */
        *fatal = 1;

        sock = _MALLOC(sizeof(cfs_socket_t), M_TEMP, M_WAITOK|M_ZERO);
        if (!sock) {
                CERROR("Can't allocate cfs_socket.\n");
                return -ENOMEM;
        }
        *sockp = sock;
        sock->s_magic = CFS_SOCK_MAGIC;

        rc = -sock_socket(PF_INET, SOCK_STREAM, 0, 
                          libcfs_sock_upcall, sock, &C2B_SOCK(sock));
        if (rc != 0) 
                goto out;
        option = 1;
        optlen = sizeof(option);
        rc = -sock_setsockopt(C2B_SOCK(sock), SOL_SOCKET, 
                              SO_REUSEADDR, &option, optlen);
        if (rc != 0)
                goto out;

        /* can't specify a local port without a local IP */
        LASSERT (local_ip == 0 || local_port != 0);

        if (local_ip != 0 || local_port != 0) {
                bzero (&locaddr, sizeof (locaddr));
                locaddr.sin_len = sizeof(struct sockaddr_in);
                locaddr.sin_family = AF_INET;
                locaddr.sin_port = htons (local_port);
                locaddr.sin_addr.s_addr = (local_ip != 0) ? htonl(local_ip) : INADDR_ANY;
                rc = -sock_bind(C2B_SOCK(sock), (struct sockaddr *)&locaddr);
                if (rc == -EADDRINUSE) {
                        CDEBUG(D_NET, "Port %d already in use\n", local_port);
                        *fatal = 0;
                        goto out;
                }
                if (rc != 0) {
                        CERROR("Error trying to bind to port %d: %d\n",
                               local_port, rc);
                        goto out;
                }
        }
        return 0;
out:
        if (C2B_SOCK(sock) != NULL) 
                sock_close(C2B_SOCK(sock));
        FREE(sock, M_TEMP);
        return rc;
}

int
libcfs_sock_listen (cfs_socket_t **sockp,
                   __u32 local_ip, int local_port, int backlog)
{
        cfs_socket_t    *sock;
        int             fatal;
        int             rc;

        rc = libcfs_sock_create(&sock, &fatal, local_ip, local_port);
        if (rc != 0)  {
                if (!fatal)
                        CERROR("Can't create socket: port %d already in use\n",
                                local_port);
                return rc;

        }
        rc = -sock_listen(C2B_SOCK(sock), backlog);
        if (rc == 0) {
                *sockp = sock;
                return 0;
        }

        if (C2B_SOCK(sock) != NULL) 
                sock_close(C2B_SOCK(sock));
        FREE(sock, M_TEMP);
        return rc;
}

int
libcfs_sock_accept (cfs_socket_t **newsockp, cfs_socket_t *sock)
{
        cfs_socket_t   *newsock;
        int             rc;

        newsock = _MALLOC(sizeof(cfs_socket_t), M_TEMP, M_WAITOK|M_ZERO);
        if (!newsock) {
                CERROR("Can't allocate cfs_socket.\n");
                return -ENOMEM;
        }
        newsock->s_magic = CFS_SOCK_MAGIC;
        /*
         * thread will sleep in sock_accept by calling of msleep(), 
         * it can be interrupted because msleep() use PCATCH as argument.
         */
        rc = -sock_accept(C2B_SOCK(sock), NULL, 0, 0, 
                          libcfs_sock_upcall, newsock, &C2B_SOCK(newsock));
        if (rc) {
                if (C2B_SOCK(newsock) != NULL) 
                        sock_close(C2B_SOCK(newsock));
                FREE(newsock, M_TEMP);
                if ((sock->s_flags & CFS_SOCK_DOWN) != 0)
                        /* shutdown by libcfs_sock_abort_accept(), fake 
                         * error number for lnet_acceptor() */
                        rc = -EAGAIN;
                return rc;
        }
        *newsockp = newsock;
        return 0;
}

void
libcfs_sock_abort_accept (cfs_socket_t *sock)
{
        /*
         * XXX Liang: 
         *
         * we want to wakeup thread blocked by sock_accept, but we don't
         * know the address where thread is sleeping on, so we cannot 
         * wakeup it directly.
         * The thread slept in sock_accept will be waken up while:
         * 1. interrupt by signal
         * 2. new connection is coming (sonewconn)
         * 3. disconnecting of the socket (soisconnected)
         * 
         * Cause we can't send signal to a thread directly(no KPI), so the 
         * only thing can be done here is disconnect the socket (by 
         * sock_shutdown() or sth else? ).
         *
         * Shutdown request of socket with SHUT_WR or SHUT_RDWR will
         * be issured to the protocol.
         * sock_shutdown()->tcp_usr_shutdown()->tcp_usrclosed()->
         * tcp_close()->soisdisconnected(), it will wakeup thread by
         * wakeup((caddr_t)&so->so_timeo);
         */
        sock->s_flags |= CFS_SOCK_DOWN;
        sock_shutdown(C2B_SOCK(sock), SHUT_RDWR);
}

int
libcfs_sock_read (cfs_socket_t *sock, void *buffer, int nob, int timeout)
{
        size_t          rcvlen;
        int             rc;
        cfs_duration_t  to = cfs_time_seconds(timeout);
        cfs_time_t      then;
        struct timeval  tv;

        LASSERT(nob > 0);

        for (;;) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct  msghdr  msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &iov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = 0,
                };
                cfs_duration_usec(to, &tv);
                rc = -sock_setsockopt(C2B_SOCK(sock), SOL_SOCKET, SO_RCVTIMEO,
                                      &tv, sizeof(tv));
                if (rc != 0) {
                        CERROR("Can't set socket recv timeout "
                                        "%ld.%06d: %d\n",
                                        (long)tv.tv_sec, (int)tv.tv_usec, rc);
                        return rc;
                }

                then = cfs_time_current();
                rc = -sock_receive(C2B_SOCK(sock), &msg, 0, &rcvlen);
                to -= cfs_time_current() - then;

                if (rc != 0 && rc != -EWOULDBLOCK)
                        return rc;
                if (rcvlen == nob)
                        return 0;

                if (to <= 0)
                        return -EAGAIN;

                buffer = ((char *)buffer) + rcvlen;
                nob -= rcvlen;
        }
        return 0;
}

int
libcfs_sock_write (cfs_socket_t *sock, void *buffer, int nob, int timeout)
{
        size_t          sndlen;
        int             rc;
        cfs_duration_t  to = cfs_time_seconds(timeout);
        cfs_time_t      then;
        struct timeval  tv;

        LASSERT(nob > 0);

        for (;;) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct  msghdr  msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &iov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = (timeout == 0) ? MSG_DONTWAIT : 0,
                };

                if (timeout != 0) {
                        cfs_duration_usec(to, &tv);
                        rc = -sock_setsockopt(C2B_SOCK(sock), SOL_SOCKET, SO_SNDTIMEO,
                                              &tv, sizeof(tv));
                        if (rc != 0) {
                                CERROR("Can't set socket send timeout "
                                       "%ld.%06d: %d\n",
                                       (long)tv.tv_sec, (int)tv.tv_usec, rc);
                                return rc;
                        }
                }

                then = cfs_time_current();
                rc = -sock_send(C2B_SOCK(sock), &msg, 
                                ((timeout == 0) ? MSG_DONTWAIT : 0), &sndlen);
                to -= cfs_time_current() - then;

                if (rc != 0 && rc != -EWOULDBLOCK)
                        return rc;
                if (sndlen == nob)
                        return 0;

                if (to <= 0)
                        return -EAGAIN;
                buffer = ((char *)buffer) + sndlen;
                nob -= sndlen;
        }
        return 0;

}

int
libcfs_sock_getaddr (cfs_socket_t *sock, int remote, __u32 *ip, int *port)
{
        struct sockaddr_in sin;
        int                rc;

        if (remote != 0) 
                /* Get remote address */
                rc = -sock_getpeername(C2B_SOCK(sock), (struct sockaddr *)&sin, sizeof(sin));
        else 
                /* Get local address */
                rc = -sock_getsockname(C2B_SOCK(sock), (struct sockaddr *)&sin, sizeof(sin));
        if (rc != 0) {
                CERROR ("Error %d getting sock %s IP/port\n",
                         rc, remote ? "peer" : "local");
                return rc;
        }

        if (ip != NULL)
                *ip = ntohl (sin.sin_addr.s_addr);

        if (port != NULL)
                *port = ntohs (sin.sin_port);
        return 0;
}

int
libcfs_sock_setbuf (cfs_socket_t *sock, int txbufsize, int rxbufsize)
{
        int                 option;
        int                 rc;
        
        if (txbufsize != 0) {
                option = txbufsize;
                rc = -sock_setsockopt(C2B_SOCK(sock), SOL_SOCKET, SO_SNDBUF,
                                     (char *)&option, sizeof (option));
                if (rc != 0) {
                        CERROR ("Can't set send buffer %d: %d\n",
                                option, rc);
                        return (rc);
                } 
        } 
        
        if (rxbufsize != 0) {
                option = rxbufsize;
                rc = -sock_setsockopt (C2B_SOCK(sock), SOL_SOCKET, SO_RCVBUF,
                                      (char *)&option, sizeof (option));
                if (rc != 0) {
                        CERROR ("Can't set receive buffer %d: %d\n",
                                option, rc);
                        return (rc);
                }
        }
        return 0;
}

int
libcfs_sock_getbuf (cfs_socket_t *sock, int *txbufsize, int *rxbufsize)
{
        int                 option;
        int                 optlen;
        int                 rc; 
        
        if (txbufsize != NULL) {
                optlen = sizeof(option);
                rc = -sock_getsockopt(C2B_SOCK(sock), SOL_SOCKET, SO_SNDBUF,
                                (char *)&option, &optlen);
                if (rc != 0) {
                        CERROR ("Can't get send buffer size: %d\n", rc);
                        return (rc);
                }
                *txbufsize = option;
        } 
        
        if (rxbufsize != NULL) {
                optlen = sizeof(option);
                rc = -sock_getsockopt (C2B_SOCK(sock), SOL_SOCKET, SO_RCVBUF,
                                (char *)&option, &optlen);
                if (rc != 0) {
                        CERROR ("Can't get receive buffer size: %d\n", rc);
                        return (rc);
                }
                *rxbufsize = option;
        }
        return 0;
}

void
libcfs_sock_release (cfs_socket_t *sock)
{
        if (C2B_SOCK(sock) != NULL) {
                sock_shutdown(C2B_SOCK(sock), 2);
                sock_close(C2B_SOCK(sock));
        }
        FREE(sock, M_TEMP);
}

int
libcfs_sock_connect (cfs_socket_t **sockp, int *fatal,
                     __u32 local_ip, int local_port,
                     __u32 peer_ip, int peer_port)
{
        cfs_socket_t       *sock;
        struct sockaddr_in  srvaddr;
        int                 rc; 
        
        rc = libcfs_sock_create(&sock, fatal, local_ip, local_port);
        if (rc != 0)
                return rc;

        bzero(&srvaddr, sizeof(srvaddr));
        srvaddr.sin_len = sizeof(struct sockaddr_in);
        srvaddr.sin_family = AF_INET;
        srvaddr.sin_port = htons(peer_port);
        srvaddr.sin_addr.s_addr = htonl(peer_ip);

        rc = -sock_connect(C2B_SOCK(sock), (struct sockaddr *)&srvaddr, 0);
        if (rc == 0) {
                *sockp = sock;
                return 0;
        }

        *fatal = !(rc == -EADDRNOTAVAIL || rc == -EADDRINUSE);
        CDEBUG_LIMIT(*fatal ? D_NETERROR : D_NET,
               "Error %d connecting %u.%u.%u.%u/%d -> %u.%u.%u.%u/%d\n", rc,
               HIPQUAD(local_ip), local_port, HIPQUAD(peer_ip), peer_port);

        libcfs_sock_release(sock);
        return rc;
}

#else   /* !__DARWIN8__ */

/*
 * To use bigger buffer for socket:
 * 1. Increase nmbclusters (Cannot increased by sysctl because it's ready only, so
 *    we must patch kernel).
 * 2. Increase net.inet.tcp.reass.maxsegments
 * 3. Increase net.inet.tcp.sendspace
 * 4. Increase net.inet.tcp.recvspace
 * 5. Increase kern.ipc.maxsockbuf
 */
#define KSOCK_MAX_BUF        (1152*1024)

int
libcfs_ipif_query (char *name, int *up, __u32 *ip, __u32 *mask)
{
        struct socket      *so;
        struct ifreq       ifr;
        int                nob;
        int                rc;
        __u32              val;
        CFS_DECL_FUNNEL_DATA;

        CFS_NET_IN;
        rc = socreate(PF_INET, &so, SOCK_STREAM, 0);
        CFS_NET_EX;
        if (rc != 0) {
                CERROR ("Can't create socket: %d\n", rc);
                return (-rc);
        }
        nob = strnlen(name, IFNAMSIZ);
        if (nob == IFNAMSIZ) {
                CERROR("Interface name %s too long\n", name);
                rc = -EINVAL;
                goto out;
        }

        CLASSERT (sizeof(ifr.ifr_name) >= IFNAMSIZ);
        strcpy(ifr.ifr_name, name);
        CFS_NET_IN;
        rc = ifioctl(so, SIOCGIFFLAGS, (caddr_t)&ifr, current_proc());
        CFS_NET_EX;

        if (rc != 0) {
                CERROR("Can't get flags for interface %s\n", name);
                goto out;
        }
        if ((ifr.ifr_flags & IFF_UP) == 0) {
                CDEBUG(D_NET, "Interface %s down\n", name);
                *up = 0;
                *ip = *mask = 0;
                goto out;
        }
       
        *up = 1;
        strcpy(ifr.ifr_name, name);
        *((struct sockaddr_in *)&ifr.ifr_addr) = blank_sin();
        CFS_NET_IN;
        rc = ifioctl(so, SIOCGIFADDR, (caddr_t)&ifr, current_proc());
        CFS_NET_EX;

        if (rc != 0) {
                CERROR("Can't get IP address for interface %s\n", name);
                goto out;
        }

        val = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        *ip = ntohl(val);

        strcpy(ifr.ifr_name, name);
        *((struct sockaddr_in *)&ifr.ifr_addr) = blank_sin();
        CFS_NET_IN;
        rc = ifioctl(so, SIOCGIFNETMASK, (caddr_t)&ifr, current_proc());
        CFS_NET_EX;

        if (rc != 0) {
                CERROR("Can't get netmask for interface %s\n", name);
                goto out;
        }

        val = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        *mask = ntohl(val);
out:
        CFS_NET_IN;
        soclose(so);
        CFS_NET_EX;
        return -rc;
}

int
libcfs_ipif_enumerate (char ***namesp)
{
        /* Allocate and fill in 'names', returning # interfaces/error */
        char           **names;
        int             toobig;
        int             nalloc;
        int             nfound;
        struct socket  *so;
        struct ifreq   *ifr;
        struct ifconf   ifc;
        int             rc;
        int             nob;
        int             i;
        CFS_DECL_FUNNEL_DATA;

        CFS_NET_IN;
        rc = socreate(PF_INET, &so, SOCK_STREAM, 0);
        CFS_NET_EX;
        if (rc != 0) {
                CERROR ("Can't create socket: %d\n", rc);
                return (-rc);
        }

        nalloc = 16;    /* first guess at max interfaces */
        toobig = 0;
        for (;;) {
                if (nalloc * sizeof(*ifr) > CFS_PAGE_SIZE) {
                        toobig = 1;
                        nalloc = CFS_PAGE_SIZE/sizeof(*ifr);
                        CWARN("Too many interfaces: only enumerating first %d\n",
                              nalloc);
                }

                LIBCFS_ALLOC(ifr, nalloc * sizeof(*ifr));
                if (ifr == NULL) {
                        CERROR ("ENOMEM enumerating up to %d interfaces\n", nalloc);
                                rc = -ENOMEM;
                        goto out0;
                }
                                
                ifc.ifc_buf = (char *)ifr;
                ifc.ifc_len = nalloc * sizeof(*ifr);
                                        
                CFS_NET_IN;
                rc = -ifioctl(so, SIOCGIFCONF, (caddr_t)&ifc, current_proc());
                CFS_NET_EX;
                                
                if (rc < 0) {
                        CERROR ("Error %d enumerating interfaces\n", rc);
                        goto out1;
                }

                nfound = ifc.ifc_len/sizeof(*ifr);
                LASSERT (nfound <= nalloc);

                if (nfound < nalloc || toobig)
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

                nob = strnlen (ifr[i].ifr_name, IFNAMSIZ);
                if (nob == IFNAMSIZ) {
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
        CFS_NET_IN;
        soclose(so);
        CFS_NET_EX;
        return rc;
}

static int
libcfs_sock_create (struct socket **sockp, int *fatal,
                    __u32 local_ip, int local_port)
{
        struct sockaddr_in  locaddr;
        struct socket      *so;
        struct sockopt      sopt;
        int                 option;
        int                 rc;
        CFS_DECL_FUNNEL_DATA;

        *fatal = 1;
        CFS_NET_IN;
        rc = socreate(PF_INET, &so, SOCK_STREAM, 0);
        CFS_NET_EX;
        if (rc != 0) {
                CERROR ("Can't create socket: %d\n", rc);
                return (-rc);
        }
        
        bzero(&sopt, sizeof sopt);
        option = 1;
        sopt.sopt_level = SOL_SOCKET;
        sopt.sopt_name = SO_REUSEADDR;
        sopt.sopt_val = &option;
        sopt.sopt_valsize = sizeof(option);
        CFS_NET_IN;
        rc = sosetopt(so, &sopt);
        if (rc != 0) {
                CFS_NET_EX;
                CERROR ("Can't set sock reuse address: %d\n", rc);
                goto out;
        }
        /* can't specify a local port without a local IP */
        LASSERT (local_ip == 0 || local_port != 0);

        if (local_ip != 0 || local_port != 0) {
                bzero (&locaddr, sizeof (locaddr));
                locaddr.sin_len = sizeof(struct sockaddr_in);
                locaddr.sin_family = AF_INET;
                locaddr.sin_port = htons (local_port);
                locaddr.sin_addr.s_addr = (local_ip != 0) ? htonl(local_ip) :
                                                            INADDR_ANY;

                rc = sobind(so, (struct sockaddr *)&locaddr);
                if (rc == EADDRINUSE) {
                        CFS_NET_EX;
                        CDEBUG(D_NET, "Port %d already in use\n", local_port);
                        *fatal = 0;
                        goto out;
                }
                if (rc != 0) {
                        CFS_NET_EX;
                        CERROR ("Can't bind to local IP Address %u.%u.%u.%u: %d\n",
                        HIPQUAD(local_ip), rc);
                        goto out;
                }
        }
        *sockp = so;
        return 0;
out:
        CFS_NET_IN;
        soclose(so);
        CFS_NET_EX;
        return -rc;
}

int
libcfs_sock_listen (struct socket **sockp,
                    __u32 local_ip, int local_port, int backlog)
{
        int      fatal;
        int      rc;
        CFS_DECL_FUNNEL_DATA;

        rc = libcfs_sock_create(sockp, &fatal, local_ip, local_port);
        if (rc != 0) {
                if (!fatal)
                        CERROR("Can't create socket: port %d already in use\n",
                               local_port);
                return rc;
        }
        CFS_NET_IN;
        rc = solisten(*sockp, backlog);
        CFS_NET_EX;
        if (rc == 0)
                return 0;
        CERROR("Can't set listen backlog %d: %d\n", backlog, rc);
        CFS_NET_IN;
        soclose(*sockp);
        CFS_NET_EX;
        return -rc;
}

int
libcfs_sock_accept (struct socket **newsockp, struct socket *sock)
{
        struct socket *so;
        struct sockaddr *sa;
        int error, s;
        CFS_DECL_FUNNEL_DATA;

        CFS_NET_IN;
        s = splnet();
        if ((sock->so_options & SO_ACCEPTCONN) == 0) {
                splx(s);
                CFS_NET_EX;
                return (-EINVAL);
        }

        if ((sock->so_state & SS_NBIO) && sock->so_comp.tqh_first == NULL) {
                splx(s);
                CFS_NET_EX;
                return (-EWOULDBLOCK);
        }

        error = 0;
        while (TAILQ_EMPTY(&sock->so_comp) && sock->so_error == 0) {
                if (sock->so_state & SS_CANTRCVMORE) {
                        sock->so_error = ECONNABORTED;
                        break;
                }
                error = tsleep((caddr_t)&sock->so_timeo, PSOCK | PCATCH,
                                "accept", 0);
                if (error) {
                        splx(s);
                        CFS_NET_EX;
                        return (-error);
                }
        }
        if (sock->so_error) {
                error = sock->so_error;
                sock->so_error = 0;
                splx(s);
                CFS_NET_EX;
                return (-error);
        }

        /*
         * At this point we know that there is at least one connection
         * ready to be accepted. Remove it from the queue prior to
         * allocating the file descriptor for it since falloc() may
         * block allowing another process to accept the connection
         * instead.
         */
        so = TAILQ_FIRST(&sock->so_comp);
        TAILQ_REMOVE(&sock->so_comp, so, so_list);
        sock->so_qlen--;

        so->so_state &= ~SS_COMP;
        so->so_head = NULL;
        sa = 0;
        (void) soaccept(so, &sa);

        *newsockp = so;
        FREE(sa, M_SONAME);
        splx(s);
        CFS_NET_EX;
        return (-error);
}

void
libcfs_sock_abort_accept (struct socket *sock)
{
        wakeup(&sock->so_timeo);
}

/*
 * XXX Liang: timeout for write is not supported yet.
 */
int
libcfs_sock_write (struct socket *sock, void *buffer, int nob, int timeout)
{
        int            rc;
        CFS_DECL_NET_DATA;

        while (nob > 0) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct  uio suio = {
                        .uio_iov        = &iov,
                        .uio_iovcnt     = 1,
                        .uio_offset     = 0,
                        .uio_resid      = nob,
                        .uio_segflg     = UIO_SYSSPACE,
                        .uio_rw         = UIO_WRITE,
                        .uio_procp      = NULL
                };
                                
                CFS_NET_IN;
                rc = sosend(sock, NULL, &suio, (struct mbuf *)0, (struct mbuf *)0, 0);
                CFS_NET_EX;
                                
                if (rc != 0) {
                        if ( suio.uio_resid != nob && ( rc == ERESTART || rc == EINTR ||\
                             rc == EWOULDBLOCK))
                        rc = 0;
                        if ( rc != 0 )
                                return -rc;
                        rc = nob - suio.uio_resid;
                        buffer = ((char *)buffer) + rc;
                        nob = suio.uio_resid;
                        continue;
                }
                break;
        }
        return (0);
}

/*
 * XXX Liang: timeout for read is not supported yet.
 */
int
libcfs_sock_read (struct socket *sock, void *buffer, int nob, int timeout)
{
        int            rc;
        CFS_DECL_NET_DATA;

        while (nob > 0) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct uio  ruio = {
                        .uio_iov        = &iov,
                        .uio_iovcnt     = 1,
                        .uio_offset     = 0,
                        .uio_resid      = nob,
                        .uio_segflg     = UIO_SYSSPACE,
                        .uio_rw         = UIO_READ,
                        .uio_procp      = NULL
                };
                
                CFS_NET_IN;
                rc = soreceive(sock, (struct sockaddr **)0, &ruio, (struct mbuf **)0, (struct mbuf **)0, (int *)0);
                CFS_NET_EX;
                
                if (rc != 0) {
                        if ( ruio.uio_resid != nob && ( rc == ERESTART || rc == EINTR ||\
                                rc == EWOULDBLOCK))
                                rc = 0;
                        if (rc != 0)
                                return -rc;
                        rc = nob - ruio.uio_resid;
                        buffer = ((char *)buffer) + rc;
                        nob = ruio.uio_resid;
                        continue;
                }
                break;
        }
        return (0);
}

int
libcfs_sock_setbuf (struct socket *sock, int txbufsize, int rxbufsize)
{
        struct sockopt  sopt;
        int             rc = 0;
        int             option;
        CFS_DECL_NET_DATA;

        bzero(&sopt, sizeof sopt);
        sopt.sopt_dir = SOPT_SET;
        sopt.sopt_level = SOL_SOCKET;
        sopt.sopt_val = &option;
        sopt.sopt_valsize = sizeof(option);

        if (txbufsize != 0) {
                option = txbufsize;
                if (option > KSOCK_MAX_BUF)
                        option = KSOCK_MAX_BUF;
        
                sopt.sopt_name = SO_SNDBUF;
                CFS_NET_IN;
                rc = sosetopt(sock, &sopt);
                CFS_NET_EX;
                if (rc != 0) {
                        CERROR ("Can't set send buffer %d: %d\n",
                                option, rc);
                        
                        return -rc;
                }
        }
                
        if (rxbufsize != 0) {
                option = rxbufsize;
                sopt.sopt_name = SO_RCVBUF;
                CFS_NET_IN;
                rc = sosetopt(sock, &sopt);
                CFS_NET_EX;
                if (rc != 0) {
                        CERROR ("Can't set receive buffer %d: %d\n",
                                option, rc);
                        return -rc;
                }
        }
        return 0;
}

int
libcfs_sock_getaddr (struct socket *sock, int remote, __u32 *ip, int *port)
{
        struct sockaddr_in *sin;
        struct sockaddr    *sa = NULL;
        int                rc;
        CFS_DECL_NET_DATA;

        if (remote != 0) {
                CFS_NET_IN;
                rc = sock->so_proto->pr_usrreqs->pru_peeraddr(sock, &sa);
                CFS_NET_EX;

                if (rc != 0) {
                        if (sa) FREE(sa, M_SONAME);
                        CERROR ("Error %d getting sock peer IP\n", rc);
                        return -rc;
                }
        } else {
                CFS_NET_IN;
                rc = sock->so_proto->pr_usrreqs->pru_sockaddr(sock, &sa);
                CFS_NET_EX;
                if (rc != 0) {
                        if (sa) FREE(sa, M_SONAME);
                        CERROR ("Error %d getting sock local IP\n", rc);
                        return -rc;
                }
        }
        if (sa != NULL) {
                sin = (struct sockaddr_in *)sa;
                if (ip != NULL)
                        *ip = ntohl (sin->sin_addr.s_addr);
                if (port != NULL)
                        *port = ntohs (sin->sin_port);
                if (sa) 
                        FREE(sa, M_SONAME);
        }
        return 0;
}

int
libcfs_sock_getbuf (struct socket *sock, int *txbufsize, int *rxbufsize)
{
        struct sockopt  sopt;
        int rc;
        CFS_DECL_NET_DATA;

        bzero(&sopt, sizeof sopt);
        sopt.sopt_dir = SOPT_GET;
        sopt.sopt_level = SOL_SOCKET;

        if (txbufsize != NULL) {
                sopt.sopt_val = txbufsize;
                sopt.sopt_valsize = sizeof(*txbufsize);
                sopt.sopt_name = SO_SNDBUF;
                CFS_NET_IN;
                rc = sogetopt(sock, &sopt);
                CFS_NET_EX;
                if (rc != 0) {
                        CERROR ("Can't get send buffer size: %d\n", rc);
                        return -rc;
                }
        }

        if (rxbufsize != NULL) {
                sopt.sopt_val = rxbufsize;
                sopt.sopt_valsize = sizeof(*rxbufsize);
                sopt.sopt_name = SO_RCVBUF;
                CFS_NET_IN;
                rc = sogetopt(sock, &sopt);
                CFS_NET_EX;
                if (rc != 0) {
                        CERROR ("Can't get receive buffer size: %d\n", rc);
                        return -rc;
                }
        }
        return 0;
}

int
libcfs_sock_connect (struct socket **sockp, int *fatal,
                     __u32 local_ip, int local_port,
                     __u32 peer_ip, int peer_port)
{
        struct sockaddr_in  srvaddr;
        struct socket      *so;
        int                 s;
        int                 rc; 
        CFS_DECL_FUNNEL_DATA;
        
        rc = libcfs_sock_create(sockp, fatal, local_ip, local_port);
        if (rc != 0)
                return rc;
        so = *sockp;
        bzero(&srvaddr, sizeof(srvaddr));
        srvaddr.sin_len = sizeof(struct sockaddr_in);
        srvaddr.sin_family = AF_INET;
        srvaddr.sin_port = htons (peer_port);
        srvaddr.sin_addr.s_addr = htonl (peer_ip);

        CFS_NET_IN;
        rc = soconnect(so, (struct sockaddr *)&srvaddr);
        if (rc != 0) {
                CFS_NET_EX;
                if (rc != EADDRNOTAVAIL && rc != EADDRINUSE)
                        CNETERR("Error %d connecting %u.%u.%u.%u/%d -> %u.%u.%u.%u/%d\n", rc,
                               HIPQUAD(local_ip), local_port, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        s = splnet();
        while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
                CDEBUG(D_NET, "ksocknal sleep for waiting auto_connect.\n");
                (void) tsleep((caddr_t)&so->so_timeo, PSOCK, "ksocknal_conn", hz);
        }
        if ((rc = so->so_error) != 0) {
                so->so_error = 0;
                splx(s);
                CFS_NET_EX;
                CNETERR("Error %d connecting %u.%u.%u.%u/%d -> %u.%u.%u.%u/%d\n", rc,
                       HIPQUAD(local_ip), local_port, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        LASSERT(so->so_state & SS_ISCONNECTED);
        splx(s);
        CFS_NET_EX;
        if (sockp)
                *sockp = so;
        return (0);
out:
        CFS_NET_IN;
        soshutdown(so, 2);
        soclose(so);
        CFS_NET_EX;
        return (-rc);
}

void
libcfs_sock_release (struct socket *sock)
{
        CFS_DECL_FUNNEL_DATA;
        CFS_NET_IN;
        soshutdown(sock, 0);
        CFS_NET_EX;
}

#endif
