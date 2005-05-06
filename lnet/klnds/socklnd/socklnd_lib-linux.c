#include "socknal.h"

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
		{j++, "port", ksocknal_tunables.ksnd_port, 
		 sizeof (int), 0444, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "backlog", ksocknal_tunables.ksnd_backlog, 
		 sizeof (int), 0444, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "timeout", ksocknal_tunables.ksnd_timeout, 
		 sizeof (int), 0644, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "listen_timeout", ksocknal_tunables.ksnd_listen_timeout, 
		 sizeof (int), 0644, NULL, &proc_dointvec};
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
		 sizeof (int), 0644, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "min_bulk", ksocknal_tunables.ksnd_min_bulk, 
		 sizeof (int), 0644, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "buffer_size", ksocknal_tunables.ksnd_buffer_size, 
		 sizeof(int), 0644, NULL, &proc_dointvec};
        ksocknal_ctl_table[i++] = (ctl_table)
		{j++, "nagle", ksocknal_tunables.ksnd_nagle, 
		 sizeof(int), 0644, NULL, &proc_dointvec};
#if CPU_AFFINITY
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
#if (defined(CONFIG_SMP) && CPU_AFFINITY)
        int              bind;
        int              cpu;
        unsigned long    flags;
        char             cmdline[64];
        ksock_irqinfo_t *info;
        char            *argv[] = {"/bin/sh",
                                   "-c",
                                   cmdline,
                                   NULL};
        char            *envp[] = {"HOME=/",
                                   "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                                   NULL};

        LASSERT (irq < NR_IRQS);
        if (irq == 0)              /* software NIC or affinity disabled */
                return;

        info = &ksocknal_data.ksnd_irqinfo[irq];

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        LASSERT (info->ksni_valid);
        bind = !info->ksni_bound;
        info->ksni_bound = 1;

        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        if (!bind)                              /* bound already */
                return;

        cpu = ksocknal_irqsched2cpu(info->ksni_sched);
        snprintf (cmdline, sizeof (cmdline),
                  "echo %d > /proc/irq/%u/smp_affinity", 1 << cpu, irq);

        printk (KERN_INFO "Lustre: Binding irq %u to CPU %d with cmd: %s\n",
                irq, cpu, cmdline);

        /* FIXME: Find a better method of setting IRQ affinity...
         */

        USERMODEHELPER(argv[0], argv, envp);
#endif
}

int
ksocknal_lib_get_conn_addrs (ksock_conn_t *conn)
{
        struct sockaddr_in sin;
        int                len = sizeof (sin);
        int                rc;

        rc = conn->ksnc_sock->ops->getname (conn->ksnc_sock,
                                            (struct sockaddr *)&sin, &len, 2);
        /* Didn't need the {get,put}connsock dance to deref ksnc_sock... */
        LASSERT (!conn->ksnc_closing);

        if (rc != 0) {
                CERROR ("Error %d getting sock peer IP\n", rc);
                return rc;
        }

        conn->ksnc_ipaddr = ntohl (sin.sin_addr.s_addr);
        conn->ksnc_port   = ntohs (sin.sin_port);

        rc = conn->ksnc_sock->ops->getname (conn->ksnc_sock,
                                            (struct sockaddr *)&sin, &len, 0);
        if (rc != 0) {
                CERROR ("Error %d getting sock local IP\n", rc);
                return rc;
        }

        conn->ksnc_myipaddr = ntohl (sin.sin_addr.s_addr);

        return 0;
}

unsigned int
ksocknal_lib_sock_irq (struct socket *sock)
{
        int                irq = 0;
        struct dst_entry  *dst;

        if (!ksocknal_tunables.ksnd_irq_affinity)
                return 0;

        dst = sk_dst_get (sock->sk);
        if (dst != NULL) {
                if (dst->dev != NULL) {
                        irq = dst->dev->irq;
                        if (irq >= NR_IRQS) {
                                CERROR ("Unexpected IRQ %x\n", irq);
                                irq = 0;
                        }
                }
                dst_release (dst);
        }

        return (irq);
}

#if (SOCKNAL_ZC && SOCKNAL_VADDR_ZC)
static struct page *
ksocknal_kvaddr_to_page (unsigned long vaddr)
{
        struct page *page;

        if (vaddr >= VMALLOC_START &&
            vaddr < VMALLOC_END)
                page = vmalloc_to_page ((void *)vaddr);
#if CONFIG_HIGHMEM
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

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone. */

#if (SOCKNAL_ZC && SOCKNAL_VADDR_ZC)
        if (zcsize >= ksocknal_data.ksnd_zc_min_frag &&
            (sock->sk->route_caps & NETIF_F_SG) &&
            (sock->sk->route_caps & (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)) &&
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
#if SOCKNAL_SINGLE_FRAG_TX
                struct iovec    scratch;
                struct iovec   *scratchiov = &scratch;
                int             niov = 1;
#else
                struct iovec   *scratchiov = conn->ksnc_tx_scratch_iov;
                int             niov = tx->tx_niov;
#endif
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = scratchiov,
                        .msg_iovlen     = niov,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = MSG_DONTWAIT
                };
                mm_segment_t oldmm = get_fs();
                int  i;

                for (nob = i = 0; i < niov; i++) {
                        scratchiov[i] = tx->tx_iov[i];
                        nob += scratchiov[i].iov_len;
                }

                if (!list_empty(&conn->ksnc_tx_queue) ||
                    nob < tx->tx_resid)
                        msg.msg_flags |= MSG_MORE;

                set_fs (KERNEL_DS);
                rc = sock_sendmsg(sock, &msg, nob);
                set_fs (oldmm);
        }
	return rc;
}

int
ksocknal_lib_send_kiov (ksock_conn_t *conn, ksock_tx_t *tx)
{
        struct socket *sock = conn->ksnc_sock;
        ptl_kiov_t    *kiov = tx->tx_kiov;
        int            rc;
        int            nob;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone. */

#if SOCKNAL_ZC
        if (kiov->kiov_len >= *ksocknal_tunables.ksnd_zc_min_frag &&
            (sock->sk->route_caps & NETIF_F_SG) &&
            (sock->sk->route_caps & (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM))) {
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
#if SOCKNAL_SINGLE_FRAG_TX || !SOCKNAL_RISK_KMAP_DEADLOCK
                struct iovec  scratch;
                struct iovec *scratchiov = &scratch;
                int           niov = 1;
#else
#ifdef CONFIG_HIGHMEM
#warning "XXX risk of kmap deadlock on multiple frags..."
#endif
                struct iovec *scratchiov = conn->ksnc_tx_scratch_iov;
                int           niov = tx->tx_nkiov;
#endif
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = scratchiov,
                        .msg_iovlen     = niov,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = MSG_DONTWAIT
                };
                mm_segment_t  oldmm = get_fs();
                int           i;

                for (nob = i = 0; i < niov; i++) {
                        scratchiov[i].iov_base = kmap(kiov[i].kiov_page) +
                                                 kiov[i].kiov_offset;
                        nob += scratchiov[i].iov_len = kiov[i].kiov_len;
                }

                if (!list_empty(&conn->ksnc_tx_queue) ||
                    nob < tx->tx_resid)
                        msg.msg_flags |= MSG_DONTWAIT;

                set_fs (KERNEL_DS);
                rc = sock_sendmsg(sock, &msg, nob);
                set_fs (oldmm);

                for (i = 0; i < niov; i++)
                        kunmap(kiov[i].kiov_page);
        }
	return rc;
}

void
ksocknal_lib_eager_ack (ksock_conn_t *conn)
{
        int            opt = 1;
        mm_segment_t   oldmm = get_fs();
        struct socket *sock = conn->ksnc_sock;

        /* Remind the socket to ACK eagerly.  If I don't, the socket might
         * think I'm about to send something it could piggy-back the ACK
         * on, introducing delay in completing zero-copy sends in my
         * peer. */

        set_fs(KERNEL_DS);
        sock->ops->setsockopt (sock, SOL_TCP, TCP_QUICKACK,
                               (char *)&opt, sizeof (opt));
        set_fs(oldmm);
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
        struct msghdr msg = {
                .msg_name       = NULL,
                .msg_namelen    = 0,
                .msg_iov        = scratchiov,
                .msg_iovlen     = niov,
                .msg_control    = NULL,
                .msg_controllen = 0,
                .msg_flags      = 0
        };
        mm_segment_t oldmm = get_fs();
        int          nob;
        int          i;
        int          rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone. */
        LASSERT (niov > 0);

        for (nob = i = 0; i < niov; i++) {
                scratchiov[i] = iov[i];
                nob += scratchiov[i].iov_len;
        }
        LASSERT (nob <= conn->ksnc_rx_nob_wanted);

        set_fs (KERNEL_DS);
        rc = sock_recvmsg (conn->ksnc_sock, &msg, nob, MSG_DONTWAIT);
        /* NB this is just a boolean..........................^ */
        set_fs (oldmm);

	return rc;
}

int
ksocknal_lib_recv_kiov (ksock_conn_t *conn)
{
#if SOCKNAL_SINGLE_FRAG_RX || !SOCKNAL_RISK_KMAP_DEADLOCK
        struct iovec  scratch;
        struct iovec *scratchiov = &scratch;
        int           niov = 1;
#else
#ifdef CONFIG_HIGHMEM
#warning "XXX risk of kmap deadlock on multiple frags..."
#endif
        struct iovec *scratchiov = conn->ksnc_rx_scratch_iov;
        int           niov = conn->ksnc_rx_nkiov;
#endif
        ptl_kiov_t   *kiov = conn->ksnc_rx_kiov;
        struct msghdr msg = {
                .msg_name       = NULL,
                .msg_namelen    = 0,
                .msg_iov        = scratchiov,
                .msg_iovlen     = niov,
                .msg_control    = NULL,
                .msg_controllen = 0,
                .msg_flags      = 0
        };
        mm_segment_t oldmm = get_fs();
        int          nob;
        int          i;
        int          rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone. */
        for (nob = i = 0; i < niov; i++) {
                scratchiov[i].iov_base = kmap(kiov[i].kiov_page) + kiov[i].kiov_offset;
                nob += scratchiov[i].iov_len = kiov[i].kiov_len;
        }
        LASSERT (nob <= conn->ksnc_rx_nob_wanted);

        set_fs (KERNEL_DS);
        rc = sock_recvmsg (conn->ksnc_sock, &msg, nob, MSG_DONTWAIT);
        /* NB this is just a boolean.......................^ */
        set_fs (oldmm);

        for (i = 0; i < niov; i++)
                kunmap(kiov[i].kiov_page);

	return (rc);
}

int
ksocknal_lib_sock_write (struct socket *sock, void *buffer, int nob)
{
        int           rc;
        mm_segment_t  oldmm = get_fs();

        while (nob > 0) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &iov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = 0
                };

                set_fs (KERNEL_DS);
                rc = sock_sendmsg (sock, &msg, iov.iov_len);
                set_fs (oldmm);

                if (rc < 0)
                        return (rc);

                if (rc == 0) {
                        CERROR ("Unexpected zero rc\n");
                        return (-ECONNABORTED);
                }

                buffer = ((char *)buffer) + rc;
                nob -= rc;
        }

        return (0);
}

int
ksocknal_lib_sock_read (struct socket *sock, void *buffer, int nob)
{
        int           rc;
        mm_segment_t  oldmm = get_fs();

        while (nob > 0) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &iov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = 0
                };

                set_fs (KERNEL_DS);
                rc = sock_recvmsg (sock, &msg, iov.iov_len, 0);
                set_fs (oldmm);

                if (rc < 0)
                        return (rc);

                if (rc == 0)
                        return (-ECONNABORTED);

                buffer = ((char *)buffer) + rc;
                nob -= rc;
        }

        return (0);
}

int
ksocknal_lib_get_conn_tunables (ksock_conn_t *conn, int *txmem, int *rxmem, int *nagle)
{
        mm_segment_t   oldmm = get_fs ();
        struct socket *sock = conn->ksnc_sock;
        int            len;
        int            rc;

        rc = ksocknal_connsock_addref(conn);
        if (rc != 0) {
                LASSERT (conn->ksnc_closing);
                *txmem = *rxmem = *nagle = 0;
                return (-ESHUTDOWN);
        }

        set_fs (KERNEL_DS);

        len = sizeof(*txmem);
        rc = sock_getsockopt(sock, SOL_SOCKET, SO_SNDBUF,
                             (char *)txmem, &len);
        if (rc == 0) {
                len = sizeof(*rxmem);
                rc = sock_getsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                                     (char *)rxmem, &len);
        }
        if (rc == 0) {
                len = sizeof(*nagle);
                rc = sock->ops->getsockopt(sock, SOL_TCP, TCP_NODELAY,
                                           (char *)nagle, &len);
        }

        set_fs (oldmm);
        ksocknal_connsock_decref(conn);

        if (rc == 0)
                *nagle = !*nagle;
        else
                *txmem = *rxmem = *nagle = 0;

        return (rc);
}

int
ksocknal_lib_setup_sock (struct socket *sock)
{
        mm_segment_t    oldmm = get_fs ();
        int             rc;
        int             option;
        int             keep_idle;
        int             keep_intvl;
        int             keep_count;
        int             do_keepalive;
        struct linger   linger;

        sock->sk->sk_allocation = GFP_NOFS;

        /* Ensure this socket aborts active sends immediately when we close
         * it. */

        linger.l_onoff = 0;
        linger.l_linger = 0;

        set_fs (KERNEL_DS);
        rc = sock_setsockopt (sock, SOL_SOCKET, SO_LINGER,
                              (char *)&linger, sizeof (linger));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set SO_LINGER: %d\n", rc);
                return (rc);
        }

        option = -1;
        set_fs (KERNEL_DS);
        rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_LINGER2,
                                    (char *)&option, sizeof (option));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set SO_LINGER2: %d\n", rc);
                return (rc);
        }

        if (!ksocknal_tunables.ksnd_nagle) {
                option = 1;

                set_fs (KERNEL_DS);
                rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_NODELAY,
                                            (char *)&option, sizeof (option));
                set_fs (oldmm);
                if (rc != 0) {
                        CERROR ("Can't disable nagle: %d\n", rc);
                        return (rc);
                }
        }

        if (ksocknal_tunables.ksnd_buffer_size > 0) {
                option = *ksocknal_tunables.ksnd_buffer_size;

                set_fs (KERNEL_DS);
                rc = sock_setsockopt (sock, SOL_SOCKET, SO_SNDBUF,
                                      (char *)&option, sizeof (option));
                set_fs (oldmm);
                if (rc != 0) {
                        CERROR ("Can't set send buffer %d: %d\n",
                                option, rc);
                        return (rc);
                }

                set_fs (KERNEL_DS);
                rc = sock_setsockopt (sock, SOL_SOCKET, SO_RCVBUF,
                                      (char *)&option, sizeof (option));
                set_fs (oldmm);
                if (rc != 0) {
                        CERROR ("Can't set receive buffer %d: %d\n",
                                option, rc);
                        return (rc);
                }
        }

        /* snapshot tunables */
        keep_idle  = *ksocknal_tunables.ksnd_keepalive_idle;
        keep_count = *ksocknal_tunables.ksnd_keepalive_count;
        keep_intvl = *ksocknal_tunables.ksnd_keepalive_intvl;

        do_keepalive = (keep_idle > 0 && keep_count > 0 && keep_intvl > 0);

        option = (do_keepalive ? 1 : 0);
        set_fs (KERNEL_DS);
        rc = sock_setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE,
                              (char *)&option, sizeof (option));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set SO_KEEPALIVE: %d\n", rc);
                return (rc);
        }

        if (!do_keepalive)
                return (0);

        set_fs (KERNEL_DS);
        rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_KEEPIDLE,
                                    (char *)&keep_idle, sizeof (keep_idle));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set TCP_KEEPIDLE: %d\n", rc);
                return (rc);
        }

        set_fs (KERNEL_DS);
        rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_KEEPINTVL,
                                    (char *)&keep_intvl, sizeof (keep_intvl));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set TCP_KEEPINTVL: %d\n", rc);
                return (rc);
        }

        set_fs (KERNEL_DS);
        rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_KEEPCNT,
                                    (char *)&keep_count, sizeof (keep_count));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set TCP_KEEPCNT: %d\n", rc);
                return (rc);
        }

        return (0);
}

int
ksocknal_lib_set_sock_timeout (struct socket *sock, int timeout)
{
	struct timeval tv;
	int            rc;
        mm_segment_t   oldmm = get_fs();

        /* Set the socket timeouts, so our connection handshake completes in
         * finite time */
        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        set_fs (KERNEL_DS);
        rc = sock_setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO,
                              (char *)&tv, sizeof (tv));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set send timeout %d: %d\n", timeout, rc);
		return rc;
        }

        set_fs (KERNEL_DS);
        rc = sock_setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO,
                              (char *)&tv, sizeof (tv));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set receive timeout %d: %d\n", timeout, rc);
		return rc;
        }

	return 0;
}

void
ksocknal_lib_release_sock(struct socket *sock)
{
	sock_release(sock);
}

int
ksocknal_lib_create_sock(struct socket **sockp, int *fatal,
			 int timeout, __u32 local_ip, int local_port)
{
        struct sockaddr_in  locaddr;
        struct socket      *sock;
        int                 rc;
        int                 option;
        mm_segment_t        oldmm = get_fs();

	*fatal = 1;				/* assume errors are fatal */

        memset(&locaddr, 0, sizeof(locaddr));
        locaddr.sin_family = AF_INET;
        locaddr.sin_port = htons(local_port);
        locaddr.sin_addr.s_addr = (local_ip == 0) ? 
				  INADDR_ANY : htonl(local_ip);

        rc = sock_create (PF_INET, SOCK_STREAM, 0, &sock);
        *sockp = sock;
        if (rc != 0) {
                CERROR ("Can't create socket: %d\n", rc);
                return (rc);
        }

	rc = ksocknal_lib_set_sock_timeout(sock, timeout);
	if (rc != 0)
		goto failed;

        set_fs (KERNEL_DS);
        option = 1;
        rc = sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                             (char *)&option, sizeof (option));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR("Can't set SO_REUSEADDR for socket: %d\n", rc);
                goto failed;
        }

        rc = sock->ops->bind(sock,
                             (struct sockaddr *)&locaddr, sizeof(locaddr));
        if (rc == -EADDRINUSE) {
                CDEBUG(D_WARNING, "Port %d already in use\n", local_port);
                *fatal = 0;
                goto failed;
        }
        if (rc != 0) {
                CERROR("Error trying to bind to reserved port %d: %d\n",
                       local_port, rc);
                goto failed;
        }

	return 0;

 failed:
        sock_release(sock);
        return rc;
}

int
ksocknal_lib_listen(struct socket **sockp, int port, int backlog)
{
	int      fatal;
	int      rc;

	rc = ksocknal_lib_create_sock(sockp, &fatal, 1, 0, port);
	if (rc != 0)
		return rc;

	rc = (*sockp)->ops->listen(*sockp, backlog);
	if (rc == 0)
		return 0;
	
	CERROR("Can't set listen backlog %d: %d\n", backlog, rc);
	sock_release(*sockp);
	return rc;
}

int
ksocknal_lib_accept(struct socket *sock, ksock_connreq_t **crp)
{
	wait_queue_t   wait;
	struct socket *newsock;
	int            rc;

	init_waitqueue_entry(&wait, current);

	newsock = sock_alloc();
	if (newsock == NULL) {
		CERROR("Can't allocate socket\n");
		return -ENOMEM;
	}

	/* XXX this should add a ref to sock->ops->owner, if
	 * TCP could be a module */
	newsock->type = sock->type;
	newsock->ops = sock->ops;

	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(sock->sk->sk_sleep, &wait);
	
	rc = sock->ops->accept(sock, newsock, O_NONBLOCK);
	if (rc == -EAGAIN) {
		/* Nothing ready, so wait for activity */
		schedule();
		rc = sock->ops->accept(sock, newsock, O_NONBLOCK);
	}
	
	remove_wait_queue(sock->sk->sk_sleep, &wait);
	set_current_state(TASK_RUNNING);

	if (rc != 0)
		goto failed;
	
	rc = ksocknal_lib_set_sock_timeout(newsock, 
					   *ksocknal_tunables.ksnd_listen_timeout);
	if (rc != 0)
		goto failed;
	
	rc = -ENOMEM;
	PORTAL_ALLOC(*crp, sizeof(**crp));
	if (*crp == NULL)
		goto failed;

	(*crp)->ksncr_sock = newsock;
	return 0;

 failed:
	sock_release(newsock);
	return rc;
}

void
ksocknal_lib_abort_accept(struct socket *sock)
{
	wake_up_all(sock->sk->sk_sleep);
}

int
ksocknal_lib_connect_sock(struct socket **sockp, int *fatal,
			  ksock_route_t *route, int local_port)
{
        struct sockaddr_in  srvaddr;
        int                 rc;

        memset (&srvaddr, 0, sizeof (srvaddr));
        srvaddr.sin_family = AF_INET;
        srvaddr.sin_port = htons (route->ksnr_port);
        srvaddr.sin_addr.s_addr = htonl (route->ksnr_ipaddr);

	rc = ksocknal_lib_create_sock(sockp, fatal,
				      *ksocknal_tunables.ksnd_timeout,
				      route->ksnr_myipaddr, local_port);
	if (rc != 0)
		return rc;

        rc = (*sockp)->ops->connect(*sockp,
				    (struct sockaddr *)&srvaddr, sizeof(srvaddr),
				    0);
        if (rc == 0)
                return 0;

        /* EADDRNOTAVAIL probably means we're already connected to the same
         * peer/port on the same local port on a differently typed
         * connection.  Let our caller retry with a different local
         * port... */
        *fatal = !(rc == -EADDRNOTAVAIL);

        CDEBUG(*fatal ? D_ERROR : D_NET,
               "Error %d connecting %u.%u.%u.%u/%d -> %u.%u.%u.%u/%d\n", rc,
               HIPQUAD(route->ksnr_myipaddr), local_port,
               HIPQUAD(route->ksnr_ipaddr), route->ksnr_port);

	sock_release(*sockp);
        return rc;
}

int
ksocknal_lib_getifaddr(struct socket *sock, char *name, __u32 *ip, __u32 *mask)
{
	mm_segment_t   oldmm = get_fs();
	struct ifreq   ifr;
	int            rc;
	__u32          val;

	LASSERT (strnlen(name, IFNAMSIZ) < IFNAMSIZ);
	
	strcpy(ifr.ifr_name, name);
	ifr.ifr_addr.sa_family = AF_INET;
	set_fs(KERNEL_DS);
	rc = sock->ops->ioctl(sock, SIOCGIFADDR, (unsigned long)&ifr);
	set_fs(oldmm);

	if (rc != 0)
		return rc;

	val = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	*ip = ntohl(val);

	strcpy(ifr.ifr_name, name);
	ifr.ifr_addr.sa_family = AF_INET;
	set_fs(KERNEL_DS);
	rc = sock->ops->ioctl(sock, SIOCGIFNETMASK, (unsigned long)&ifr);
	set_fs(oldmm);
	
	if (rc != 0)
		return rc;
	
	val = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
	*mask = ntohl(val);
	return 0;
}

int
ksocknal_lib_init_if (ksock_interface_t *iface, char *name)
{
	struct socket  *sock;
	int             rc;
	int             nob;

	rc = sock_create (PF_INET, SOCK_STREAM, 0, &sock);
	if (rc != 0) {
		CERROR ("Can't create socket: %d\n", rc);
		return rc;
	}
	
	nob = strnlen(name, IFNAMSIZ);
	if (nob == IFNAMSIZ) {
		CERROR("Interface name %s too long\n", name);
		rc -EINVAL;
	} else {
		CLASSERT (sizeof(iface->ksni_name) >= IFNAMSIZ);
		strcpy(iface->ksni_name, name);

		rc = ksocknal_lib_getifaddr(sock, name,
					    &iface->ksni_ipaddr,
					    &iface->ksni_netmask);
		if (rc != 0)
			CERROR("Can't get IP address for interface %s\n", name);
	}

	sock_release(sock);
	return rc;
}

int
ksocknal_lib_enumerate_ifs (ksock_interface_t *ifs, int nifs)
{
	int             nalloc = PTL_MAX_INTERFACES;
	char            name[IFNAMSIZ];
	int             nfound;
	int             nused;
	struct socket  *sock;
	struct ifconf   ifc;
	struct ifreq   *ifr;
	mm_segment_t    oldmm = get_fs();
	__u32           ipaddr;
	__u32           netmask;
	int             rc;
	int             i;

	rc = sock_create (PF_INET, SOCK_STREAM, 0, &sock);
	if (rc != 0) {
		CERROR ("Can't create socket: %d\n", rc);
		return rc;
	}

	for (;;) {
		PORTAL_ALLOC(ifr, nalloc * sizeof(*ifr));
		if (ifr == NULL) {
			CERROR ("ENOMEM enumerating up to %d interfaces\n", nalloc);
			rc = -ENOMEM;
			goto out0;
		}
		
		ifc.ifc_buf = (char *)ifr;
		ifc.ifc_len = nalloc * sizeof(*ifr);
		
		set_fs(KERNEL_DS);
		rc = sock->ops->ioctl(sock, SIOCGIFCONF, (unsigned long)&ifc);
		set_fs(oldmm);

		if (rc < 0) {
			CERROR ("Error %d enumerating interfaces\n", rc);
			goto out1;
		}
		
		LASSERT (rc == 0);
		nfound = rc/sizeof(*ifr);
		LASSERT (nfound <= nalloc);
		
		if (nfound <= nalloc)
			break;
		
		/* Assume there are more interfaces */
		if (nalloc >= 16 * PTL_MAX_INTERFACES) {
			CWARN("Too many interfaces: "
			      "only trying the first %d\n", nfound);
			break;
		}

		nalloc *= 2;
	}

	for (i = nused = 0; i < nfound; i++) {
		strncpy(name, ifr[i].ifr_name, IFNAMSIZ); /* ensure terminated name */
		name[IFNAMSIZ-1] = 0;
		
		if (!strncmp(name, "lo", 2)) {
			CDEBUG(D_WARNING, "ignoring %s\n", name);
			continue;
		}
		
		strcpy(ifr[i].ifr_name, name);
		set_fs(KERNEL_DS);
		rc = sock->ops->ioctl(sock, SIOCGIFFLAGS, 
				      (unsigned long)&ifr[i]);
		set_fs(oldmm);

		if (rc != 0) {
			CDEBUG(D_WARNING, "Can't get flags for %s\n", name);
			continue;
		}

		if ((ifr[i].ifr_flags & IFF_UP) == 0) {
			CDEBUG(D_WARNING, "Interface %s down\n", name);
			continue;
		}

		rc = ksocknal_lib_getifaddr(sock, name, &ipaddr, &netmask);
		if (rc != 0) {
			CDEBUG(D_WARNING, 
			       "Can't get IP address or netmask for %s\n",
			       name);
			continue;
		}

		if (nused >= nifs) {
			CWARN("Too many available interfaces: "
			      "only using the first %d\n", nused);
			break;
		}
		
		memset(&ifs[nused], 0, sizeof(ifs[nused]));
		
		CLASSERT(sizeof(ifs[nused].ksni_name) >= IFNAMSIZ);
		strcpy(ifs[nused].ksni_name, name);
		ifs[nused].ksni_ipaddr = ipaddr;
		ifs[nused].ksni_netmask = netmask;
		nused++;
	}

	rc = nused;
 out1:
	PORTAL_FREE(ifr, nalloc * sizeof(*ifr));
 out0:
	sock_release(sock);
	return rc;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
struct tcp_opt *sock2tcp_opt(struct sock *sk)
{
        return &(sk->tp_pinfo.af_tcp);
}
#else
struct tcp_opt *sock2tcp_opt(struct sock *sk)
{
        struct tcp_sock *s = (struct tcp_sock *)sk;
        return &s->tcp;
}
#endif

void
ksocknal_lib_push_conn (ksock_conn_t *conn)
{
        struct sock    *sk;
        struct tcp_opt *tp;
        int             nonagle;
        int             val = 1;
        int             rc;
        mm_segment_t    oldmm;

        rc = ksocknal_connsock_addref(conn);
        if (rc != 0)                            /* being shut down */
                return;

        sk = conn->ksnc_sock->sk;
        tp = sock2tcp_opt(sk);

        lock_sock (sk);
        nonagle = tp->nonagle;
        tp->nonagle = 1;
        release_sock (sk);

        oldmm = get_fs ();
        set_fs (KERNEL_DS);

        rc = sk->sk_prot->setsockopt (sk, SOL_TCP, TCP_NODELAY,
                                      (char *)&val, sizeof (val));
        LASSERT (rc == 0);

        set_fs (oldmm);

        lock_sock (sk);
        tp->nonagle = nonagle;
        release_sock (sk);

        ksocknal_connsock_decref(conn);
}

extern void ksocknal_read_callback (ksock_conn_t *conn);
extern void ksocknal_write_callback (ksock_conn_t *conn);
/*
 * socket call back in Linux
 */
static void
ksocknal_data_ready (struct sock *sk, int n)
{
        ksock_conn_t  *conn;
        ENTRY;

        /* interleave correctly with closing sockets... */
        read_lock (&ksocknal_data.ksnd_global_lock);

        conn = sk->sk_user_data;
        if (conn == NULL) {             /* raced with ksocknal_terminate_conn */
                LASSERT (sk->sk_data_ready != &ksocknal_data_ready);
                sk->sk_data_ready (sk, n);
        } else
		ksocknal_read_callback(conn);

        read_unlock (&ksocknal_data.ksnd_global_lock);

        EXIT;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,7))
#define tcp_wspace(sk) sk_stream_wspace(sk)
#endif

static void
ksocknal_write_space (struct sock *sk)
{
        ksock_conn_t  *conn;

        /* interleave correctly with closing sockets... */
        read_lock (&ksocknal_data.ksnd_global_lock);

        conn = sk->sk_user_data;

        CDEBUG(D_NET, "sk %p wspace %d low water %d conn %p%s%s%s\n",
               sk, tcp_wspace(sk), SOCKNAL_TX_LOW_WATER(sk), conn,
               (conn == NULL) ? "" : (conn->ksnc_tx_ready ?
                                      " ready" : " blocked"),
               (conn == NULL) ? "" : (conn->ksnc_tx_scheduled ?
                                      " scheduled" : " idle"),
               (conn == NULL) ? "" : (list_empty (&conn->ksnc_tx_queue) ?
                                      " empty" : " queued"));

        if (conn == NULL) {             /* raced with ksocknal_terminate_conn */
                LASSERT (sk->sk_write_space != &ksocknal_write_space);
                sk->sk_write_space (sk);

                read_unlock (&ksocknal_data.ksnd_global_lock);
                return;
        }

        if (tcp_wspace(sk) >= SOCKNAL_TX_LOW_WATER(sk)) { /* got enough space */
		ksocknal_write_callback(conn);

		/* Clear SOCK_NOSPACE _after_ ksocknal_write_callback so the
		 * ENOMEM check in ksocknal_transmit is race-free (think about
		 * it). */

                clear_bit (SOCK_NOSPACE, &sk->sk_socket->flags);
        }

        read_unlock (&ksocknal_data.ksnd_global_lock);
}

void
ksocknal_lib_save_callback(struct socket *sock, ksock_conn_t *conn)
{
	conn->ksnc_saved_data_ready = sock->sk->sk_data_ready;
	conn->ksnc_saved_write_space = sock->sk->sk_write_space;
}

void
ksocknal_lib_set_callback(struct socket *sock,  ksock_conn_t *conn)
{
	sock->sk->sk_user_data = conn;
	sock->sk->sk_data_ready = ksocknal_data_ready;
	sock->sk->sk_write_space = ksocknal_write_space;
	return;
}

void
ksocknal_lib_act_callback(struct socket *sock, ksock_conn_t *conn)
{
	ksocknal_data_ready (sock->sk, 0);
	ksocknal_write_space (sock->sk);
	return;
}

void
ksocknal_lib_reset_callback(struct socket *sock, ksock_conn_t *conn)
{
	/* Remove conn's network callbacks.
	 * NB I _have_ to restore the callback, rather than storing a noop,
	 * since the socket could survive past this module being unloaded!! */
	sock->sk->sk_data_ready = conn->ksnc_saved_data_ready;
	sock->sk->sk_write_space = conn->ksnc_saved_write_space;

	/* A callback could be in progress already; they hold a read lock
	 * on ksnd_global_lock (to serialise with me) and NOOP if
	 * sk_user_data is NULL. */
	sock->sk->sk_user_data = NULL;

	return ;
}

