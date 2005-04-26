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
#include <mach/mach_types.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/file.h>

#include "socknal.h"

#if 0
#undef SOCKNAL_SINGLE_FRAG_TX
#define SOCKNAL_SINGLE_FRAG_TX  1
#undef SOCKNAL_SINGLE_FRAG_RX
#define SOCKNAL_SINGLE_FRAG_RX  1
#endif

#if !CFS_SYSFS_MODULE_PARM
#error "this can't use ksocknal_tunables to get the addresses of the tuning vars"

SYSCTL_DECL(_portals);

SYSCTL_NODE (_portals,           OID_AUTO,       ksocknal,        CTLFLAG_RW, 
             0,                 "ksocknal_sysctl");

SYSCTL_INT(_portals_ksocknal,    OID_AUTO,       timeout, 
           CTLTYPE_INT | CTLFLAG_RW ,            ksocknal_tunables.ksnd_timeout, 
           0,                                   "timeout");
SYSCTL_INT(_portals_ksocknal,    OID_AUTO,       eager_ack, 
           CTLTYPE_INT | CTLFLAG_RW ,            ksocknal_tunables.ksnd_eager_ack, 
           0,                                   "eager_ack");
SYSCTL_INT(_portals_ksocknal,    OID_AUTO,       typed, 
           CTLTYPE_INT | CTLFLAG_RW ,            ksocknal_tunables.ksnd_typed_conns, 
           0,                                   "typed");
SYSCTL_INT(_portals_ksocknal,    OID_AUTO,       min_bulk, 
           CTLTYPE_INT | CTLFLAG_RW ,            ksocknal_tunables.ksnd_min_bulk, 
           0,                                   "min_bulk");
SYSCTL_INT(_portals_ksocknal,    OID_AUTO,       buffer_size, 
           CTLTYPE_INT | CTLFLAG_RW ,            ksocknal_tunables.ksnd_buffer_size, 
           0,                                   "buffer_size");
SYSCTL_INT(_portals_ksocknal,    OID_AUTO,       nagle, 
           CTLTYPE_INT | CTLFLAG_RW ,            ksocknal_tunables.ksnd_nagle, 
           0,                                   "nagle");

cfs_sysctl_table_t      ksocknal_top_ctl_table [] = {
        &sysctl__portals_ksocknal,
        &sysctl__portals_ksocknal_timeout,
        &sysctl__portals_ksocknal_eager_ack,
        &sysctl__portals_ksocknal_typed,
        &sysctl__portals_ksocknal_min_bulk,
        &sysctl__portals_ksocknal_buffer_size,
        &sysctl__portals_ksocknal_nagle,
        NULL
};

int
ksocknal_lib_tunables_init ()
{
        ksocknal_tunables.ksnd_sysctl =
                register_sysctl_table (ksocknal_top_ctl_table, 0);

        if (ksocknal_tunables.ksnd_sysctl == NULL)
		return -ENOMEM;

	return 0;
}

int
ksocknal_lib_tunables_fini ()
{
        if (ksocknal_tunables.ksnd_sysctl != NULL)
                unregister_sysctl_table (ksocknal_tunables.ksnd_sysctl);	
}
#else
int
ksocknal_lib_tunables_init ()
{
	return 0;
}

int
ksocknal_lib_tunables_fini ()
{
}
#endif

static unsigned long  ksocknal_mbuf_size = (u_quad_t)SB_MAX * MCLBYTES / (MSIZE + MCLBYTES);

extern struct fileops socketops;

void
ksocknal_lib_release_sock(struct socket *so)
{
        CFS_DECL_FUNNEL_DATA;

        CFS_NET_IN;
	soshutdown(so, 0);
        CFS_NET_EX;
}

void
ksocknal_lib_bind_irq (unsigned int irq)
{
        return;
}

unsigned int
ksocknal_lib_sock_irq (struct socket *sock)
{
        return 0;
}

int
ksocknal_lib_get_conn_addrs (ksock_conn_t *conn)
{ 
        struct sockaddr_in *sin; 
        struct sockaddr    *sa; 
        int                rc; 
        CFS_DECL_NET_DATA;

        CFS_NET_IN; 
        rc = conn->ksnc_sock->so_proto->pr_usrreqs->pru_peeraddr(conn->ksnc_sock, &sa); 
        LASSERT (!conn->ksnc_closing); 
        if (rc != 0) { 
                CFS_NET_EX; 
                if (sa) FREE(sa, M_SONAME); 
                CERROR ("Error %d getting sock peer IP\n", rc); 
                return rc; 
        } 
        sin = (struct sockaddr_in *)sa; 
        conn->ksnc_ipaddr = ntohl (sin->sin_addr.s_addr); 
        conn->ksnc_port = ntohs (sin->sin_port); 
        if (sa) FREE(sa, M_SONAME); 
        rc = conn->ksnc_sock->so_proto->pr_usrreqs->pru_sockaddr(conn->ksnc_sock, &sa); 
        CFS_NET_EX; 
        if (rc != 0) { 
                if (sa) FREE(sa, M_SONAME); 
                CERROR ("Error %d getting sock local IP\n", rc); 
                return rc; 
        } 
        conn->ksnc_myipaddr = ntohl (sin->sin_addr.s_addr);

        return 0;
}

int
ksocknal_lib_send_iov (ksock_conn_t *conn, ksock_tx_t *tx)
{ 
#if SOCKNAL_SINGLE_FRAG_TX 
        struct iovec    scratch; 
        struct iovec   *scratchiov = &scratch; 
        int             niov = 1;
#else 
        struct iovec   *scratchiov = conn->ksnc_tx_scratch_iov; 
        int             niov = tx->tx_niov;
#endif
        struct socket *sock = conn->ksnc_sock;
        int            nob;
        int            rc;
        int            i;
        struct uio  suio = {
                .uio_iov        = scratchiov,
                .uio_iovcnt     = niov,
                .uio_offset     = 0,
                .uio_resid      = 0,            /* This will be valued after a while */
                .uio_segflg     = UIO_SYSSPACE,
                .uio_rw         = UIO_WRITE,
                .uio_procp      = NULL
        };
        int  flags = MSG_DONTWAIT;
        CFS_DECL_NET_DATA;

        for (nob = i = 0; i < niov; i++) { 
                scratchiov[i] = tx->tx_iov[i]; 
                nob += scratchiov[i].iov_len; 
        }
        suio.uio_resid = nob;

        CFS_NET_IN;
        rc = sosend(sock, NULL, &suio, (struct mbuf *)0, (struct mbuf *)0, flags);
        CFS_NET_EX; 

        /* NB there is no return value can indicate how many 
         * have been sent and how many resid, we have to get 
         * sent bytes from suio. */
        if (rc != 0) {
                if (suio.uio_resid != nob &&\
                    (rc == ERESTART || rc == EINTR || rc == EWOULDBLOCK))
                        /* We have sent something */
                        rc = nob - suio.uio_resid;
                else if ( rc == EWOULDBLOCK ) 
                        /* Actually, EAGAIN and EWOULDBLOCK have same value in OSX */
                        rc = -EAGAIN;   
                else 
                        rc = -rc;
        } else  /* rc == 0 */
                rc = nob - suio.uio_resid;

        return rc;
}

int
ksocknal_lib_send_kiov (ksock_conn_t *conn, ksock_tx_t *tx)
{
#if SOCKNAL_SINGLE_FRAG_TX || !SOCKNAL_RISK_KMAP_DEADLOCK 
        struct iovec  scratch; 
        struct iovec *scratchiov = &scratch; 
        int           niov = 1;
#else
        struct iovec *scratchiov = conn->ksnc_tx_scratch_iov; 
        int           niov = tx->tx_nkiov;
#endif
        struct socket *sock = conn->ksnc_sock;
        ptl_kiov_t    *kiov = tx->tx_kiov;
        int            nob;
        int            rc;
        int            i;
        struct  uio suio = {
                .uio_iov        = scratchiov,
                .uio_iovcnt     = niov,
                .uio_offset     = 0, 
                .uio_resid      = 0,    /* It should be valued after a while */
                .uio_segflg     = UIO_SYSSPACE,
                .uio_rw         = UIO_WRITE,
                .uio_procp      = NULL
        };
        int  flags = MSG_DONTWAIT;
        CFS_DECL_NET_DATA; 
        
        for (nob = i = 0; i < niov; i++) { 
                scratchiov[i].iov_base = cfs_kmap(kiov[i].kiov_page) + 
                                         kiov[i].kiov_offset; 
                nob += scratchiov[i].iov_len = kiov[i].kiov_len; 
        }
        suio.uio_resid = nob;

        CFS_NET_IN;
        rc = sosend(sock, NULL, &suio, (struct mbuf *)0, (struct mbuf *)0, flags);
        CFS_NET_EX;

        for (i = 0; i < niov; i++) 
                cfs_kunmap(kiov[i].kiov_page);

        if (rc != 0) {
                if (suio.uio_resid != nob &&\
                    (rc == ERESTART || rc == EINTR || rc == EWOULDBLOCK))
                        /* We have sent something */
                        rc = nob - suio.uio_resid; 
                else if ( rc == EWOULDBLOCK ) 
                        /* EAGAIN and EWOULD BLOCK have same value in OSX */
                        rc = -EAGAIN;   
                else 
                        rc = -rc;
        } else  /* rc == 0 */
                rc = nob - suio.uio_resid;

        return rc;
}

/*
 * liang: Hack of inpcb and tcpcb.
 * To get tcpcb of a socket, and call tcp_output
 * to send quick ack.
 */
struct ks_tseg_qent{
        int foo;
};

struct ks_tcptemp{
        int foo;
};

LIST_HEAD(ks_tsegqe_head, ks_tseg_qent);

struct ks_tcpcb {
        struct ks_tsegqe_head t_segq;
        int     t_dupacks;
        struct ks_tcptemp *unused;
        int    t_timer[4];
        struct inpcb *t_inpcb;
        int    t_state;
        u_int  t_flags;
        /*
         * There are more fields but we dont need
         * ......
         */
};

#define TF_ACKNOW       0x00001
#define TF_DELACK       0x00002

struct ks_inpcb {
        LIST_ENTRY(ks_inpcb) inp_hash;
        struct  in_addr reserved1;
        struct  in_addr reserved2;
        u_short inp_fport;
        u_short inp_lport;
        LIST_ENTRY(inpcb) inp_list;
        caddr_t inp_ppcb;
        /*
         * There are more fields but we dont need
         * ......
         */
};

#define ks_sotoinpcb(so)   ((struct ks_inpcb *)(so)->so_pcb)
#define ks_intotcpcb(ip)   ((struct ks_tcpcb *)(ip)->inp_ppcb)
#define ks_sototcpcb(so)   (intotcpcb(sotoinpcb(so)))

void
ksocknal_lib_eager_ack (ksock_conn_t *conn)
{
        struct socket *sock = conn->ksnc_sock;
        struct ks_inpcb  *inp = ks_sotoinpcb(sock);
        struct ks_tcpcb  *tp = ks_intotcpcb(inp);
        int s;
        CFS_DECL_NET_DATA;

        extern int tcp_output(register struct ks_tcpcb *tp);

        CFS_NET_IN;
        s = splnet();

        if (tp && tp->t_flags & TF_DELACK){
                tp->t_flags &= ~TF_DELACK;
                tp->t_flags |= TF_ACKNOW;
                (void) tcp_output(tp);
        }
        splx(s);

        /*
         * No TCP_QUICKACK supported in BSD, so I have to call tcp_fasttimo
         * to send immediate ACK. It's not the best resolution because
         * tcp_fasttimo will send out ACK for all delayed-ack tcp socket.
         * Anyway, it's working now. 
         * extern void tcp_fasttimo(); 
         * tcp_fasttimo();
         */
        CFS_NET_EX;

        return;
}

int
ksocknal_lib_recv_iov (ksock_conn_t *conn)
{
#if SOCKNAL_SINGLE_FRAG_RX 
        struct iovec  scratch; 
        struct iovec *scratchiov = &scratch; 
        int           niov = 1;
#else 
        struct iovec *scratchiov = conn->ksnc_rx_scratch_iov; 
        int           niov = conn->ksnc_rx_niov;
#endif
        struct iovec *iov = conn->ksnc_rx_iov;
        int          nob;
        int          rc;
        int          i;
        struct uio  ruio = {
                .uio_iov        = scratchiov,
                .uio_iovcnt     = niov,
                .uio_offset     = 0,
                .uio_resid      = 0,    /* It should be valued after a while */
                .uio_segflg     = UIO_SYSSPACE,
                .uio_rw         = UIO_READ,
                .uio_procp      = NULL
        };
        int         flags = MSG_DONTWAIT;
        CFS_DECL_NET_DATA;

        for (nob = i = 0; i < niov; i++) { 
                scratchiov[i] = iov[i]; 
                nob += scratchiov[i].iov_len; 
        } 
        LASSERT (nob <= conn->ksnc_rx_nob_wanted);

        ruio.uio_resid = nob;

        CFS_NET_IN;
        rc = soreceive(conn->ksnc_sock, (struct sockaddr **)0, &ruio, (struct mbuf **)0, (struct mbuf **)0, &flags);
        CFS_NET_EX;
        if (rc){
                if (ruio.uio_resid != nob && \
                    (rc == ERESTART || rc == EINTR || rc == EWOULDBLOCK || rc == EAGAIN))
                        /* data particially received */
                        rc = nob - ruio.uio_resid; 
                else if (rc == EWOULDBLOCK) 
                        /* EAGAIN and EWOULD BLOCK have same value in OSX */
                        rc = -EAGAIN; 
                else
                        rc = -rc;
        } else 
                rc = nob - ruio.uio_resid;

        return (rc);
}

int
ksocknal_lib_recv_kiov (ksock_conn_t *conn)
{
#if SOCKNAL_SINGLE_FRAG_RX || !SOCKNAL_RISK_KMAP_DEADLOCK 
        struct iovec  scratch; 
        struct iovec *scratchiov = &scratch; 
        int           niov = 1;
#else 
        struct iovec *scratchiov = conn->ksnc_rx_scratch_iov; 
        int           niov = conn->ksnc_rx_nkiov;
#endif
        ptl_kiov_t    *kiov = conn->ksnc_rx_kiov;
        int           nob;
        int           rc;
        int           i;
        struct uio  ruio = {
                .uio_iov        = scratchiov,
                .uio_iovcnt     = niov,
                .uio_offset     = 0,
                .uio_resid      = 0,
                .uio_segflg     = UIO_SYSSPACE,
                .uio_rw         = UIO_READ,
                .uio_procp      = NULL
        };
        int         flags = MSG_DONTWAIT;
        CFS_DECL_NET_DATA;

        for (nob = i = 0; i < niov; i++) { 
                scratchiov[i].iov_base = cfs_kmap(kiov[i].kiov_page) + kiov[i].kiov_offset; 
                nob += scratchiov[i].iov_len = kiov[i].kiov_len; 
        } 
        LASSERT (nob <= conn->ksnc_rx_nob_wanted);

        ruio.uio_resid = nob;

        CFS_NET_IN;
        rc = soreceive(conn->ksnc_sock, (struct sockaddr **)0, &ruio, (struct mbuf **)0, NULL, &flags);
        CFS_NET_EX;

        for (i = 0; i < niov; i++) 
                cfs_kunmap(kiov[i].kiov_page);

        if (rc){
                if (ruio.uio_resid != nob && \
                    (rc == ERESTART || rc == EINTR || rc == EWOULDBLOCK))
                        /* data particially received */
                        rc = nob - ruio.uio_resid; 
                else if (rc == EWOULDBLOCK)
                        /* receive blocked, EWOULDBLOCK == EAGAIN */ 
                        rc = -EAGAIN; 
                else
                        rc = -rc;
        } else
                rc = nob - ruio.uio_resid;

        return (rc);
}

int
ksocknal_lib_sock_write (struct socket *sock, void *buffer, int nob)
{
        int           rc;
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

int
ksocknal_lib_sock_read (struct socket *sock, void *buffer, int nob)
{
        int           rc;
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
ksocknal_lib_get_conn_tunables (ksock_conn_t *conn, int *txmem, int *rxmem, int *nagle)
{
        struct sockopt  sopt;
        struct socket *sock = conn->ksnc_sock;
        int            len;
        int            rc;
        CFS_DECL_NET_DATA;

        rc = ksocknal_connsock_addref(conn);
        if (rc != 0) {
                LASSERT (conn->ksnc_closing);
                *txmem = *rxmem = *nagle = 0;
                rc = -ESHUTDOWN;
                goto out;
        }
        len = sizeof(*txmem);
        bzero(&sopt, sizeof sopt);
        sopt.sopt_dir = SOPT_GET; 
        sopt.sopt_level = SOL_SOCKET; 
        sopt.sopt_name = SO_SNDBUF; 
        sopt.sopt_val = txmem; 
        sopt.sopt_valsize = len;

        CFS_NET_IN;
        rc = sogetopt(sock, &sopt);
        if (rc == 0) {
                len = sizeof(*rxmem);
                sopt.sopt_name = SO_RCVBUF;
                sopt.sopt_val = rxmem;
                rc = sogetopt(sock, &sopt);
        }
        if (rc == 0) {
                len = sizeof(*nagle);
                sopt.sopt_level = IPPROTO_TCP;
                sopt.sopt_name = TCP_NODELAY;
                sopt.sopt_val = nagle;
                rc = sogetopt(sock, &sopt);
        }
        CFS_NET_EX;

        ksocknal_connsock_decref(conn);

        if (rc == 0)
                *nagle = !*nagle;
        else
                *txmem = *rxmem = *nagle = 0;
out:
        return (-rc);
}

int
ksocknal_lib_setup_sock (struct socket *so)
{
        struct sockopt  sopt;
        int             rc; 
        int             option; 
        int             keep_idle; 
        int             keep_intvl; 
        int             keep_count; 
        int             do_keepalive; 
        struct linger   linger;
        CFS_DECL_NET_DATA;

        /* Ensure this socket aborts active sends immediately when we close
         * it. */

        bzero(&sopt, sizeof sopt);

        linger.l_onoff = 0;
        linger.l_linger = 0;
        sopt.sopt_dir = SOPT_SET;
        sopt.sopt_level = SOL_SOCKET;
        sopt.sopt_name = SO_LINGER;
        sopt.sopt_val = &linger;
        sopt.sopt_valsize = sizeof(linger);

        CFS_NET_IN;
        rc = sosetopt(so, &sopt);
        if (rc != 0) {
                CERROR ("Can't set SO_LINGER: %d\n", rc);
                goto out;
        }


        if (!*ksocknal_tunables.ksnd_nagle) { 
                option = 1; 
                bzero(&sopt, sizeof sopt);
                sopt.sopt_dir = SOPT_SET; 
                sopt.sopt_level = IPPROTO_TCP;
                sopt.sopt_name = TCP_NODELAY; 
                sopt.sopt_val = &option; 
                sopt.sopt_valsize = sizeof(option);
                rc = sosetopt(so, &sopt);
                if (rc != 0) { 
                        CERROR ("Can't disable nagle: %d\n", rc); 
                        goto out;
                } 
        } 
        if (*ksocknal_tunables.ksnd_buffer_size > 0) { 
                option = *ksocknal_tunables.ksnd_buffer_size; 
                if (option > ksocknal_mbuf_size) 
                        option = ksocknal_mbuf_size; 
                                                
                sopt.sopt_dir = SOPT_SET; 
                sopt.sopt_level = SOL_SOCKET; 
                sopt.sopt_name = SO_SNDBUF; 
                sopt.sopt_val = &option; 
                sopt.sopt_valsize = sizeof(option); 
                rc = sosetopt(so, &sopt); 
                if (rc != 0) { 
                        CERROR ("Can't set send buffer %d: %d\n", 
                                        option, rc); 
                        goto out;
                } 
                
                sopt.sopt_name = SO_RCVBUF; 
                rc = sosetopt(so, &sopt); 
                if (rc != 0) { 
                        CERROR ("Can't set receive buffer %d: %d\n", 
                                        option, rc); 
                        goto out;
                }
        } 
        /* snapshot tunables */ 
        keep_idle  = *ksocknal_tunables.ksnd_keepalive_idle; 
        keep_count = *ksocknal_tunables.ksnd_keepalive_count; 
        keep_intvl = *ksocknal_tunables.ksnd_keepalive_intvl;

        do_keepalive = (keep_idle > 0 && keep_count > 0 && keep_intvl > 0); 
        option = (do_keepalive ? 1 : 0); 
        bzero(&sopt, sizeof sopt); 
        sopt.sopt_dir = SOPT_SET; 
        sopt.sopt_level = SOL_SOCKET; 
        sopt.sopt_name = SO_KEEPALIVE; 
        sopt.sopt_val = &option; 
        sopt.sopt_valsize = sizeof(option); 
        rc = sosetopt(so, &sopt); 
        if (rc != 0) { 
                CERROR ("Can't set SO_KEEPALIVE: %d\n", rc); 
                goto out; 
        }
        
        if (!do_keepalive) { 
                /* no more setting, just return */
                rc = 0;
                goto out;
        } 
        
        bzero(&sopt, sizeof sopt); 
        sopt.sopt_dir = SOPT_SET; 
        sopt.sopt_level = IPPROTO_TCP; 
        sopt.sopt_name = TCP_KEEPALIVE; 
        sopt.sopt_val = &keep_idle; 
        sopt.sopt_valsize = sizeof(keep_idle); 
        rc = sosetopt(so, &sopt); 
        if (rc != 0) { 
                CERROR ("Can't set TCP_KEEPALIVE : %d\n", rc); 
                goto out; 
        }
out:
        CFS_NET_EX;
        return (-rc);
}

int
ksocknal_lib_connect_sock (struct socket **sockp, int *fatal, 
                           ksock_route_t *route, int local_port)
{
        struct sockaddr_in  locaddr;
        struct sockaddr_in  srvaddr;
        struct timeval      tv;
        int                 fd;
        struct socket      *so;
        struct sockopt      sopt;
        int                 option;
        int                 rc;
        int                 s;
        CFS_DECL_FUNNEL_DATA;

        ENTRY; 
        bzero (&locaddr, sizeof (locaddr)); 
        locaddr.sin_len = sizeof(struct sockaddr_in); 
        locaddr.sin_family = AF_INET; 
        locaddr.sin_port = htons (local_port);
        locaddr.sin_addr.s_addr = 
                (route->ksnr_myipaddr != 0) ? htonl(route->ksnr_myipaddr)
                                            : INADDR_ANY;
        bzero(&srvaddr, sizeof(srvaddr));
        srvaddr.sin_len = sizeof(struct sockaddr_in);
        srvaddr.sin_family = AF_INET;
        srvaddr.sin_port = htons (route->ksnr_port);
        srvaddr.sin_addr.s_addr = htonl (route->ksnr_ipaddr);

        *fatal = 1;

        CFS_NET_IN;
        rc = socreate(PF_INET, &so, SOCK_STREAM, 0); 
        CFS_NET_EX;
        *sockp = so;
        if (rc != 0) {
                CERROR ("Can't create autoconnect socket: %d\n", rc);
                return (-rc);
        }

        /* Set the socket timeouts, so our connection attempt completes in
         * finite time */
        tv.tv_sec = *ksocknal_tunables.ksnd_timeout;
        tv.tv_usec = 0;
        bzero(&sopt, sizeof sopt);
        sopt.sopt_dir = SOPT_SET;
        sopt.sopt_level = SOL_SOCKET;
        sopt.sopt_name = SO_SNDTIMEO;
        sopt.sopt_val = &tv;
        sopt.sopt_valsize = sizeof(tv);

        CFS_NET_IN;
        rc = sosetopt(so, &sopt);
        if (rc != 0) { 
                CFS_NET_EX;
                CERROR ("Can't set send timeout %d: %d\n",
                        *ksocknal_tunables.ksnd_timeout, rc);
                goto out;
        }
        sopt.sopt_level = SOL_SOCKET;
        sopt.sopt_name = SO_RCVTIMEO;
        rc = sosetopt(so, &sopt);
        if (rc != 0) {
                CFS_NET_EX;
                CERROR ("Can't set receive timeout %d: %d\n",
                        *ksocknal_tunables.ksnd_timeout, rc);
                goto out;
        } 
        option = 1;
        sopt.sopt_level = SOL_SOCKET;
        sopt.sopt_name = SO_REUSEADDR;
        sopt.sopt_val = &option;
        sopt.sopt_valsize = sizeof(option);
        rc = sosetopt(so, &sopt);
        if (rc != 0) {
                CFS_NET_EX;
                CERROR ("Can't set sock reuse address: %d\n", rc);
                goto out;
        } 
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
                        HIPQUAD(route->ksnr_myipaddr), rc); 
                goto out; 
        }
        rc = soconnect(so, (struct sockaddr *)&srvaddr);
        *fatal = !(rc == EADDRNOTAVAIL || rc == EADDRINUSE);
        if (rc != 0) { 
                CFS_NET_EX;
                if (rc != EADDRNOTAVAIL && rc != EADDRINUSE)
                        CERROR ("Can't connect to nid "LPX64 
                                " local IP: %u.%u.%u.%u," 
                                " remote IP: %u.%u.%u.%u/%d: %d\n", 
                                route->ksnr_peer->ksnp_nid, 
                                HIPQUAD(route->ksnr_myipaddr), 
                                HIPQUAD(route->ksnr_ipaddr), 
                                route->ksnr_port, rc); 
                goto out;
        }

        s = splnet();
        while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
                CDEBUG(D_NET, "ksocknal sleep for waiting auto_connect.\n");
                (void) tsleep((caddr_t)&so->so_timeo, PSOCK, "ksocknal_conn", hz);
        }
        LASSERT((so->so_state & SS_ISCONNECTED));
        splx(s);
        CFS_NET_EX;

        rc = so->so_error; 
        if (rc != 0) { 
                CERROR ("Error %d waiting for connection to nid "LPX64 
                        " local IP: %u.%u.%u.%u," 
                        " remote IP: %u.%u.%u.%u/%d: %d\n", rc,
                        route->ksnr_peer->ksnp_nid, 
                        HIPQUAD(route->ksnr_myipaddr), 
                        HIPQUAD(route->ksnr_ipaddr), 
                        route->ksnr_port, rc); 
                goto out; 
        }
        return (-rc);

 out:
        ksocknal_lib_release_sock(so);
        return (-rc);
}

void
ksocknal_lib_push_conn(ksock_conn_t *conn)
{ 
        struct socket   *sock; 
        struct sockopt  sopt; 
        int             val = 1; 
        int             rc; 
        CFS_DECL_NET_DATA; 
        
        rc = ksocknal_connsock_addref(conn); 
        if (rc != 0)            /* being shut down */ 
                return; 
        sock = conn->ksnc_sock; 
        bzero(&sopt, sizeof sopt); 
        sopt.sopt_dir = SOPT_SET; 
        sopt.sopt_level = IPPROTO_TCP; 
        sopt.sopt_name = TCP_NODELAY; 
        sopt.sopt_val = &val; 
        sopt.sopt_valsize = sizeof val; 

        CFS_NET_IN; 
        sosetopt(sock, &sopt); 
        CFS_NET_EX; 

        ksocknal_connsock_decref(conn);
        return;
}

extern void ksocknal_read_callback (ksock_conn_t *conn);
extern void ksocknal_write_callback (ksock_conn_t *conn);

static void
ksocknal_upcall(struct socket *so, caddr_t arg, int waitf)
{
        ksock_conn_t  *conn;
        CFS_DECL_NET_DATA;
        ENTRY;

        read_lock (&ksocknal_data.ksnd_global_lock);
        conn = so->reserved3;

        if (conn == NULL){
                /* More processing is needed?  */
                goto out;
        }
        if ((so->so_rcv.sb_flags & SB_UPCALL) || !arg ) {
                extern int soreadable(struct socket *so);
                CFS_NET_IN;
                if (conn->ksnc_rx_nob_wanted && soreadable(so)){
                        /* To verify whether the upcall is for receive */
                        CFS_NET_EX;
                        ksocknal_read_callback (conn);
                }else
                        CFS_NET_EX;
        }
        /* go foward? */
        if ((so->so_snd.sb_flags & SB_UPCALL) || !arg){
                extern int sowriteable(struct socket *so);
                CFS_NET_IN;
                if (sowriteable(so)){
                        /* socket is writable */
                        CFS_NET_EX;
                        ksocknal_write_callback(conn);
                } else 
                        CFS_NET_EX;
        }
out:
        read_unlock (&ksocknal_data.ksnd_global_lock);

        EXIT;
}

void
ksocknal_lib_save_callback(struct socket *sock, ksock_conn_t *conn)
{ 
        /* No callback need to save in osx */
        return;
}

void
ksocknal_lib_set_callback(struct socket *sock, ksock_conn_t *conn)
{ 
        CFS_DECL_NET_DATA;

        CFS_NET_IN;
        sock->so_upcallarg = (void *)sock;  /* anything not NULL */ 
        sock->so_upcall = ksocknal_upcall; 
        sock->so_snd.sb_timeo = 0; 
        sock->so_rcv.sb_timeo = 2 * HZ; 
        sock->so_rcv.sb_flags |= SB_UPCALL; 
        sock->so_snd.sb_flags |= SB_UPCALL; 
        sock->reserved3 = conn;
        CFS_NET_EX;
        return;
}

void
ksocknal_lib_act_callback(struct socket *sock)
{
        /* upcall will take the network funnel */
        ksocknal_upcall (sock, 0, 0);
}

void 
ksocknal_lib_reset_callback(struct socket *sock, ksock_conn_t *conn)
{ 
        CFS_DECL_NET_DATA;

        CFS_NET_IN;
        sock->so_upcall = NULL; 
        sock->so_upcallarg = NULL; 
        sock->so_rcv.sb_flags &= ~SB_UPCALL; 
        sock->so_snd.sb_flags &= ~SB_UPCALL;
        CFS_NET_EX;
}


