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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lnet/klnds/socklnd/socklnd_lib-winnt.c
 *
 * windows socknal library
 */

#include "socklnd.h"

# if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
static ctl_table ksocknal_ctl_table[18];

ctl_table ksocknal_top_ctl_table[] = {
        {200, "socknal", NULL, 0, 0555, ksocknal_ctl_table},
        { 0 }
};

int
ksocknal_lib_tunables_init () 
{
	    int    i = 0;
	    int    j = 1;
	
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "timeout", ksocknal_tunables.ksnd_timeout, 
		 sizeof (int), 0644, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "credits", ksocknal_tunables.ksnd_credits, 
		 sizeof (int), 0444, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "peer_credits", ksocknal_tunables.ksnd_peercredits, 
		 sizeof (int), 0444, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "nconnds", ksocknal_tunables.ksnd_nconnds, 
		 sizeof (int), 0444, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "min_reconnectms", ksocknal_tunables.ksnd_min_reconnectms, 
		 sizeof (int), 0444, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "max_reconnectms", ksocknal_tunables.ksnd_max_reconnectms, 
		 sizeof (int), 0444, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "eager_ack", ksocknal_tunables.ksnd_eager_ack, 
		 sizeof (int), 0644, NULL, &proc_dointvec};
#if SOCKNAL_ZC
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "zero_copy", ksocknal_tunables.ksnd_zc_min_frag, 
		 sizeof (int), 0644, NULL, &proc_dointvec};
#endif
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "typed", ksocknal_tunables.ksnd_typed_conns, 
		 sizeof (int), 0444, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "min_bulk", ksocknal_tunables.ksnd_min_bulk, 
		 sizeof (int), 0644, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "buffer_size", ksocknal_tunables.ksnd_buffer_size, 
		 sizeof(int), 0644, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "nagle", ksocknal_tunables.ksnd_nagle, 
		 sizeof(int), 0644, NULL, &proc_dointvec};
#ifdef CPU_AFFINITY
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "irq_affinity", ksocknal_tunables.ksnd_irq_affinity, 
		 sizeof(int), 0644, NULL, &proc_dointvec};
#endif
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "keepalive_idle", ksocknal_tunables.ksnd_keepalive_idle, 
		 sizeof(int), 0644, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "keepalive_count", ksocknal_tunables.ksnd_keepalive_count, 
		 sizeof(int), 0644, NULL, &proc_dointvec};
	ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "keepalive_intvl", ksocknal_tunables.ksnd_keepalive_intvl, 
		 sizeof(int), 0644, NULL, &proc_dointvec};

	LASSERT (j == i+1);
	LASSERT (i < sizeof(ksocknal_ctl_table)/sizeof(ksocknal_ctl_table[0]));

        ksocknal_tunables.ksnd_sysctl =
                register_sysctl_table(ksocknal_top_ctl_table, 0);

        if (ksocknal_tunables.ksnd_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");

	return 0;
}

void
ksocknal_lib_tunables_fini () 
{
        if (ksocknal_tunables.ksnd_sysctl != NULL)
                unregister_sysctl_table(ksocknal_tunables.ksnd_sysctl);	
}
#else
int
ksocknal_lib_tunables_init () 
{
	return 0;
}

void 
ksocknal_lib_tunables_fini ()
{
}
#endif

void
ksocknal_lib_bind_irq (unsigned int irq)
{
}

int
ksocknal_lib_get_conn_addrs (ksock_conn_t *conn)
{
        int rc = libcfs_sock_getaddr(conn->ksnc_sock, 1,
				     &conn->ksnc_ipaddr, &conn->ksnc_port);

        /* Didn't need the {get,put}connsock dance to deref ksnc_sock... */
        LASSERT (!conn->ksnc_closing);

        if (rc != 0) {
                CERROR ("Error %d getting sock peer IP\n", rc);
                return rc;
        }

        rc = libcfs_sock_getaddr(conn->ksnc_sock, 0,
				 &conn->ksnc_myipaddr, NULL);
        if (rc != 0) {
                CERROR ("Error %d getting sock local IP\n", rc);
                return rc;
        }

        return 0;
}

unsigned int
ksocknal_lib_sock_irq (struct socket *sock)
{
    return 0;
}

#if (SOCKNAL_ZC && SOCKNAL_VADDR_ZC)
static struct page *
ksocknal_kvaddr_to_page (unsigned long vaddr)
{
        struct page *page;

        if (vaddr >= VMALLOC_START &&
            vaddr < VMALLOC_END)
                page = vmalloc_to_page ((void *)vaddr);
#ifdef CONFIG_HIGHMEM
        else if (vaddr >= PKMAP_BASE &&
                 vaddr < (PKMAP_BASE + LAST_PKMAP * PAGE_SIZE))
                page = vmalloc_to_page ((void *)vaddr);
                /* in 2.4 ^ just walks the page tables */
#endif
        else
                page = virt_to_page (vaddr);

        if (page == NULL ||
            !VALID_PAGE (page))
                return (NULL);

        return (page);
}
#endif

/*
 * ks_lock_iovs
 *   Lock the i/o vector buffers into MDL structure
 *
 * Arguments:
 *   iov:  the array of i/o vectors
 *   niov: number of i/o vectors to be locked
 *   len:  the real length of the iov vectors
 *
 * Return Value:
 *   ksock_mdl_t *: the Mdl of the locked buffers or
 *         NULL pointer in failure case
 *
 * Notes: 
 *   N/A
 */

ksock_mdl_t *
ks_lock_iovs(
    IN struct iovec  *iov,
    IN int            niov,
    IN int            recving,
    IN int *          len )
{
    int             rc = 0;

    int             i = 0;
    int             total = 0;
    ksock_mdl_t *   mdl = NULL;
    ksock_mdl_t *   tail = NULL;

    LASSERT(iov != NULL);
    LASSERT(niov > 0);
    LASSERT(len != NULL);

    for (i=0; i < niov; i++) {

        ksock_mdl_t * Iovec = NULL;
            
        rc = ks_lock_buffer(
                iov[i].iov_base,
                FALSE,
                iov[i].iov_len,
                recving ? IoWriteAccess : IoReadAccess,
                &Iovec );

        if (rc < 0) {
            break;
        }

        if (tail) {
            tail->Next = Iovec;
        } else {
            mdl = Iovec;
        }

        tail = Iovec;

        total +=iov[i].iov_len;
    }

    if (rc >= 0) {
        *len = total;
    } else {
        if (mdl) {
            ks_release_mdl(mdl, FALSE);
            mdl = NULL;
        }
    }

    return mdl;
}

/*
 * ks_lock_kiovs
 *   Lock the kiov pages into MDL structure
 *
 * Arguments:
 *   kiov:  the array of kiov pages
 *   niov:  number of kiov to be locked
 *   len:   the real length of the kiov arrary
 *
 * Return Value:
 *   PMDL: the Mdl of the locked buffers or NULL
 *         pointer in failure case
 *
 * Notes: 
 *   N/A
 */
ksock_mdl_t *
ks_lock_kiovs(
    IN lnet_kiov_t *  kiov,
    IN int            nkiov,
    IN int            recving,
    IN int *          len )
{
    int             rc = 0;
    int             i = 0;
    int             total = 0;
    ksock_mdl_t *   mdl = NULL;
    ksock_mdl_t *   tail = NULL;

    LASSERT(kiov != NULL);
    LASSERT(nkiov > 0);
    LASSERT(len != NULL);

    for (i=0; i < nkiov; i++) {

        ksock_mdl_t *        Iovec = NULL;


        //
        //  Lock the kiov page into Iovec бн
        //

        rc = ks_lock_buffer(
                (PUCHAR)kiov[i].kiov_page->addr + 
                     kiov[i].kiov_offset,
                FALSE,
                kiov[i].kiov_len,
                recving ? IoWriteAccess : IoReadAccess,
                &Iovec
            );

        if (rc < 0) {
            break;
        }

        //
        // Attach the Iovec to the mdl chain
        //

        if (tail) {
            tail->Next = Iovec;
        } else {
            mdl = Iovec;
        }

        tail = Iovec;

        total += kiov[i].kiov_len;

    }

    if (rc >= 0) {
        *len = total;
    } else {
        if (mdl) {
            ks_release_mdl(mdl, FALSE);
            mdl = NULL;
        }
    }

    return mdl;
}


int
ksocknal_lib_send_iov (ksock_conn_t *conn, ksock_tx_t *tx)
{
        struct socket *sock = conn->ksnc_sock;
#if (SOCKNAL_ZC && SOCKNAL_VADDR_ZC)
        unsigned long  vaddr = (unsigned long)iov->iov_base
        int            offset = vaddr & (PAGE_SIZE - 1);
        int            zcsize = MIN (iov->iov_len, PAGE_SIZE - offset);
        struct page   *page;
#endif
        int            nob;
        int            rc;
        ksock_mdl_t *  mdl;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone. */

#if (SOCKNAL_ZC && SOCKNAL_VADDR_ZC)
        if (zcsize >= ksocknal_data.ksnd_zc_min_frag &&
            (sock->sk->sk_route_caps & NETIF_F_SG) &&
            (sock->sk->sk_route_caps & (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)) &&
            (page = ksocknal_kvaddr_to_page (vaddr)) != NULL) {
                int msgflg = MSG_DONTWAIT;

                CDEBUG(D_NET, "vaddr %p, page %p->%p + offset %x for %d\n",
                       (void *)vaddr, page, page_address(page), offset, zcsize);

                if (!list_empty (&conn->ksnc_tx_queue) ||
                    zcsize < tx->tx_resid)
                        msgflg |= MSG_MORE;

                rc = tcp_sendpage_zccd(sock, page, offset, zcsize, msgflg, &tx->tx_zccd);
        } else
#endif
        {
                /* lock the whole tx iovs into a single mdl chain */
                mdl = ks_lock_iovs(tx->tx_iov, tx->tx_niov, FALSE, &nob);

                if (mdl) {
                        /* send the total mdl chain */
                        rc = ks_send_mdl( conn->ksnc_sock, tx, mdl, nob, 
                                    (!list_empty (&conn->ksnc_tx_queue) || nob < tx->tx_resid) ? 
                                    (MSG_DONTWAIT | MSG_MORE) : MSG_DONTWAIT);
                } else {
                        rc = -ENOMEM;
                }
        }

	    return rc;
}

int
ksocknal_lib_send_kiov (ksock_conn_t *conn, ksock_tx_t *tx)
{
        struct socket *sock = conn->ksnc_sock;
        lnet_kiov_t    *kiov = tx->tx_kiov;
        int            rc;
        int            nob;
        ksock_mdl_t *  mdl;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone. */

#if SOCKNAL_ZC
        if (kiov->kiov_len >= *ksocknal_tunables.ksnd_zc_min_frag &&
            (sock->sk->sk_route_caps & NETIF_F_SG) &&
            (sock->sk->sk_route_caps & (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM))) {
                struct page   *page = kiov->kiov_page;
                int            offset = kiov->kiov_offset;
                int            fragsize = kiov->kiov_len;
                int            msgflg = MSG_DONTWAIT;

                CDEBUG(D_NET, "page %p + offset %x for %d\n",
                               page, offset, kiov->kiov_len);

                if (!list_empty(&conn->ksnc_tx_queue) ||
                    fragsize < tx->tx_resid)
                        msgflg |= MSG_MORE;

                rc = tcp_sendpage_zccd(sock, page, offset, fragsize, msgflg,
                                       &tx->tx_zccd);
        } else
#endif
        {
                /* lock the whole tx kiovs into a single mdl chain */
                mdl = ks_lock_kiovs(tx->tx_kiov, tx->tx_nkiov, FALSE, &nob);

                if (mdl) {
                        /* send the total mdl chain */
                        rc = ks_send_mdl(
                                    conn->ksnc_sock, tx, mdl, nob,
                                    (!list_empty(&conn->ksnc_tx_queue) || nob < tx->tx_resid) ?
                                    (MSG_DONTWAIT | MSG_MORE) : MSG_DONTWAIT);
                } else {
                        rc = -ENOMEM;
                }
        }

	    return rc;
}


int
ksocknal_lib_recv_iov (ksock_conn_t *conn)
{
        struct iovec *iov = conn->ksnc_rx_iov;
        int           rc;
        int           size;
        ksock_mdl_t * mdl;

        /* lock the whole tx iovs into a single mdl chain */
        mdl = ks_lock_iovs(iov, conn->ksnc_rx_niov, TRUE, &size);

        if (!mdl) {
            return (-ENOMEM);
        }
        
        LASSERT (size <= conn->ksnc_rx_nob_wanted);

        /* try to request data for the whole mdl chain */
        rc = ks_recv_mdl (conn->ksnc_sock, mdl, size, MSG_DONTWAIT);

        return rc;
}

int
ksocknal_lib_recv_kiov (ksock_conn_t *conn)
{
        lnet_kiov_t  *kiov = conn->ksnc_rx_kiov;
        int           size;
        int           rc;
        ksock_mdl_t * mdl;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone, so we only receive 1 frag at a time. */
        LASSERT (conn->ksnc_rx_nkiov > 0);

        /* lock the whole tx kiovs into a single mdl chain */
        mdl = ks_lock_kiovs(kiov, conn->ksnc_rx_nkiov, TRUE, &size);

        if (!mdl) {
            rc = -ENOMEM;
            return (rc);
        }
        
        LASSERT (size <= conn->ksnc_rx_nob_wanted);

        /* try to request data for the whole mdl chain */
        rc = ks_recv_mdl (conn->ksnc_sock, mdl, size, MSG_DONTWAIT);

        return rc;
}

void
ksocknal_lib_eager_ack (ksock_conn_t *conn)
{
        __u32   option = 1;
        int     rc = 0;
                
        rc = ks_set_tcp_option(
                conn->ksnc_sock, TCP_SOCKET_NODELAY,
                &option, sizeof(option) );
        if (rc != 0) {
                CERROR("Can't disable nagle: %d\n", rc);
        }
}

int
ksocknal_lib_get_conn_tunables (ksock_conn_t *conn, int *txmem, int *rxmem, int *nagle)
{
        ksock_tconn_t * tconn = conn->ksnc_sock;
        int             len;
        int             rc;

        ks_get_tconn (tconn);
        
        *txmem = *rxmem = 0;

        len = sizeof(*nagle);

        rc = ks_get_tcp_option(
                    tconn, TCP_SOCKET_NODELAY,
                    (__u32 *)nagle, &len);

        ks_put_tconn (tconn);

        printk("ksocknal_get_conn_tunables: nodelay = %d rc = %d\n", *nagle, rc);

        if (rc == 0)
                *nagle = !*nagle;
        else
                *txmem = *rxmem = *nagle = 0;
                
        return (rc);
}

int
ksocknal_lib_buffersize (int current_sz, int tunable_sz)
{
	    /* ensure >= SOCKNAL_MIN_BUFFER */
	    if (current_sz < SOCKNAL_MIN_BUFFER)
		        return MAX(SOCKNAL_MIN_BUFFER, tunable_sz);

	    if (tunable_sz > SOCKNAL_MIN_BUFFER)
		        return tunable_sz;
	
	    /* leave alone */
	    return 0;
}

int
ksocknal_lib_setup_sock (struct socket *sock)
{
        int             rc;

        int             keep_idle;
        int             keep_count;
        int             keep_intvl;
        int             keep_alive;

        __u32           option;

        /* set the window size */

#if 0
        tconn->kstc_snd_wnd = ksocknal_tunables.ksnd_buffer_size;
        tconn->kstc_rcv_wnd = ksocknal_tunables.ksnd_buffer_size;
#endif

        /* disable nagle */
        if (!ksocknal_tunables.ksnd_nagle) {
                option = 1;
                
                rc = ks_set_tcp_option(
                            sock, TCP_SOCKET_NODELAY,
                            &option, sizeof (option));
                if (rc != 0) {
                        printk ("Can't disable nagle: %d\n", rc);
                        return (rc);
                }
        }

        /* snapshot tunables */
        keep_idle  = *ksocknal_tunables.ksnd_keepalive_idle;
        keep_count = *ksocknal_tunables.ksnd_keepalive_count;
        keep_intvl = *ksocknal_tunables.ksnd_keepalive_intvl;
        
        keep_alive = (keep_idle > 0 && keep_count > 0 && keep_intvl > 0);

        option = (__u32)(keep_alive ? 1 : 0);

        rc = ks_set_tcp_option(
                    sock, TCP_SOCKET_KEEPALIVE,
                    &option, sizeof (option));
        if (rc != 0) {
                CERROR ("Can't disable nagle: %d\n", rc);
                return (rc);
        }

        return (0);
}

void
ksocknal_lib_push_conn (ksock_conn_t *conn)
{
        ksock_tconn_t * tconn;
        __u32           nagle;
        __u32           val = 1;
        int             rc;

        tconn = conn->ksnc_sock;

        ks_get_tconn(tconn);

        spin_lock(&tconn->kstc_lock);
        if (tconn->kstc_type == kstt_sender) {
            nagle = tconn->sender.kstc_info.nagle;
            tconn->sender.kstc_info.nagle = 0;
        } else {
            LASSERT(tconn->kstc_type == kstt_child);
            nagle = tconn->child.kstc_info.nagle;
            tconn->child.kstc_info.nagle = 0;
        }

        spin_unlock(&tconn->kstc_lock);

        val = 1;
        rc = ks_set_tcp_option(
                    tconn,
                    TCP_SOCKET_NODELAY,
                    &(val),
                    sizeof(__u32)
                    );

        LASSERT (rc == 0);
        spin_lock(&tconn->kstc_lock);

        if (tconn->kstc_type == kstt_sender) {
            tconn->sender.kstc_info.nagle = nagle;
        } else {
            LASSERT(tconn->kstc_type == kstt_child);
            tconn->child.kstc_info.nagle = nagle;
        }
        spin_unlock(&tconn->kstc_lock);

        ks_put_tconn(tconn);
}

/* @mode: 0: receiving mode / 1: sending mode */
void
ksocknal_sched_conn (ksock_conn_t *conn, int mode, ksock_tx_t *tx)
{
        int             flags;
        ksock_sched_t * sched;
        ENTRY;

        /* interleave correctly with closing sockets... */
        read_lock (&ksocknal_data.ksnd_global_lock);

        sched = conn->ksnc_scheduler;

        spin_lock_irqsave (&sched->kss_lock, flags);

        if (mode) { /* transmission can continue ... */ 

#error "This is out of date - we should be calling ksocknal_write_callback()"
                conn->ksnc_tx_ready = 1;

                if (tx) {
                    /* Incomplete send: place tx on HEAD of tx_queue */
                    list_add (&tx->tx_list, &conn->ksnc_tx_queue);
                }

                if ( !conn->ksnc_tx_scheduled &&
                     !list_empty(&conn->ksnc_tx_queue)) {  //packets to send
                        list_add_tail (&conn->ksnc_tx_list,
                                       &sched->kss_tx_conns);
                        conn->ksnc_tx_scheduled = 1;
                        /* extra ref for scheduler */
                        atomic_inc (&conn->ksnc_conn_refcount);

                        cfs_waitq_signal (&sched->kss_waitq);
                }
        } else {    /* receiving can continue ... */

                conn->ksnc_rx_ready = 1;

                if ( !conn->ksnc_rx_scheduled) {  /* not being progressed */
                        list_add_tail(&conn->ksnc_rx_list,
                                      &sched->kss_rx_conns);
                        conn->ksnc_rx_scheduled = 1;
                        /* extra ref for scheduler */
                        atomic_inc (&conn->ksnc_conn_refcount);

                        cfs_waitq_signal (&sched->kss_waitq);
                }
        }

        spin_unlock_irqrestore (&sched->kss_lock, flags);
        read_unlock (&ksocknal_data.ksnd_global_lock);

        EXIT;
}

void ksocknal_schedule_callback(struct socket*sock, int mode, void * tx, ulong_ptr bytes)
{
    ksock_conn_t * conn = (ksock_conn_t *) sock->kstc_conn;

    if (mode) {
        ksocknal_sched_conn(conn, mode, tx);
    } else {
        if ( CAN_BE_SCHED(bytes, (ulong_ptr)conn->ksnc_rx_nob_wanted )) {
            ksocknal_sched_conn(conn, mode, tx);
        }
    }
}

extern void
ksocknal_tx_launched (ksock_tx_t *tx);

void
ksocknal_fini_sending(ksock_tcpx_fini_t *tcpx)
{
    ksocknal_tx_launched(tcpx->tx);
    cfs_free(tcpx);
}

void *
ksocknal_update_tx(
    struct socket*  tconn,
    void *          txp,
    ulong_ptr       rc
    )
{
    ksock_tx_t *    tx = (ksock_tx_t *)txp;

    /*
     *  the transmission was done, we need update the tx
     */

    LASSERT(tx->tx_resid >= (int)rc);
    tx->tx_resid -= (int)rc;

    /*
     *  just partial of tx is sent out, we need update
     *  the fields of tx and schedule later transmission.
     */

    if (tx->tx_resid) {

        if (tx->tx_niov > 0) {

            /* if there's iov, we need process iov first */
            while (rc > 0 ) {
                if (rc < tx->tx_iov->iov_len) {
                    /* didn't send whole iov entry... */
                    tx->tx_iov->iov_base = 
                        (char *)(tx->tx_iov->iov_base) + rc;
                    tx->tx_iov->iov_len -= rc;
                    rc = 0;
                 } else {
                    /* the whole of iov was sent out */
                    rc -= tx->tx_iov->iov_len;
                    tx->tx_iov++;
                    tx->tx_niov--;
                }
            }

        } else {

            /* now we need process the kiov queues ... */

            while (rc > 0 ) {

                if (rc < tx->tx_kiov->kiov_len) {
                    /* didn't send whole kiov entry... */
                    tx->tx_kiov->kiov_offset += rc;
                    tx->tx_kiov->kiov_len -= rc;
                    rc = 0;
                } else {
                    /* whole kiov was sent out */
                    rc -= tx->tx_kiov->kiov_len;
                    tx->tx_kiov++;
                    tx->tx_nkiov--;
                }
            }
        }

    } else {

        ksock_tcpx_fini_t * tcpx = 
                cfs_alloc(sizeof(ksock_tcpx_fini_t), CFS_ALLOC_ZERO);

        ASSERT(tx->tx_resid == 0);

        if (!tcpx) {

            ksocknal_tx_launched (tx);

        } else {

            tcpx->tx = tx;
            ExInitializeWorkItem(
                    &(tcpx->item), 
                    ksocknal_fini_sending,
                    tcpx
            );
            ExQueueWorkItem(
                    &(tcpx->item),
                    CriticalWorkQueue
                    );
        }

        tx = NULL;
    }

    return (void *)tx;
}

void
ksocknal_lib_save_callback(struct socket *sock, ksock_conn_t *conn)
{
}

void
ksocknal_lib_set_callback(struct socket *sock,  ksock_conn_t *conn)
{
        sock->kstc_conn      = conn;
        sock->kstc_sched_cb  = ksocknal_schedule_callback;
        sock->kstc_update_tx = ksocknal_update_tx;
}

void
ksocknal_lib_reset_callback(struct socket *sock, ksock_conn_t *conn)
{
        sock->kstc_conn      = NULL;
        sock->kstc_sched_cb  = NULL;
        sock->kstc_update_tx = NULL;
}
