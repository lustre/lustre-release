/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 * 
 * Copyright (C) 2002 Cluster File Systems, Inc.
 * Author: Phil Schwan <phil@clusterfs.com>
 * 
 * This file is part of Lustre, http://www.lustre.org.
 * 
 * Lustre is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 * 
 * Lustre is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Lustre; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * 
 * Darwin porting library
 * Make things easy to port
 */ 
#define DEBUG_SUBSYSTEM S_LNET

#include <mach/mach_types.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/protosw.h>
#include <net/if.h>
#include <sys/file.h>
#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>

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

static __inline__ struct sockaddr_in
blank_sin()
{
        struct sockaddr_in  blank = { sizeof(struct sockaddr_in), AF_INET };
        return (blank);
}

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
                if (nalloc * sizeof(*ifr) > PAGE_SIZE) {
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

void
libcfs_ipif_free_enumeration (char **names, int n)
{
        int      i;

        LASSERT (n > 0);

        for (i = 0; i < n && names[i] != NULL; i++)
                LIBCFS_FREE(names[i], IFNAMSIZ);
                
        LIBCFS_FREE(names, n * sizeof(*names));
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
        if (rc = 0)
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
                        CDEBUG(*fatal ? D_ERROR : D_NET,
                               "Error %d connecting %u.%u.%u.%u/%d -> %u.%u.%u.%u/%d\n", rc,
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
                CDEBUG(*fatal ? D_ERROR : D_NET,
                       "Error %d connecting %u.%u.%u.%u/%d -> %u.%u.%u.%u/%d\n", rc,
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

