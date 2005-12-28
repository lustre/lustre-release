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
}

int
ksocknal_lib_get_conn_addrs (ksock_conn_t *conn)
{
        int rc = libcfs_sock_getaddr(conn->ksnc_sock, 1,
				     &conn->ksnc_ipaddr,
				     &conn->ksnc_port);

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
        int                irq = 0;
        return irq;
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


void
ksocknal_lib_eager_ack (ksock_conn_t *conn)
{
}

int
ksocknal_lib_get_conn_tunables (ksock_conn_t *conn, int *txmem, int *rxmem, int *nagle)
{
        ksock_tconn_t * tconn = conn->ksnc_sock;
        int             len;
        int             rc;

        ksocknal_get_tconn (tconn);
        
        *txmem = *rxmem = 0;

        len = sizeof(*nagle);

        rc = ksocknal_get_tcp_option(
                    tconn, TCP_SOCKET_NODELAY,
                    (__u32 *)nagle, &len);

        ksocknal_put_tconn (tconn);

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
                
                rc = ksocknal_set_tcp_option(
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

        rc = ksocknal_set_tcp_option(
                    sock, TCP_SOCKET_KEEPALIVE,
                    &option, sizeof (option));
        if (rc != 0) {
                CERROR (("Can't disable nagle: %d\n", rc));
                return (rc);
        }

        return (0);
}

void
ksocknal_push_conn (ksock_conn_t *conn)
{
        ksock_tconn_t * tconn;
        __u32           nagle;
        __u32           val = 1;
        int             rc;

        tconn = conn->ksnc_sock;

        ksocknal_get_tconn(tconn);

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
        rc = ksocknal_set_tcp_option(
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

        ksocknal_put_tconn(tconn);
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


void
ksocknal_fini_sending(ksock_tcpx_fini_t *tcpx)
{
    ksocknal_tx_launched(tcpx->tx);
    cfs_free(tcpx);
}

PVOID
ksocknal_update_tx(
    struct socket*  tconn,
    PVOID           txp,
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

    return (PVOID)tx;
}

void
ksocknal_lib_save_callback(struct socket *sock, ksock_conn_t *conn)
{
}

void
ksocknal_lib_set_callback(struct socket *sock,  ksock_conn_t *conn)
{
    sock->kstc_sched_cb  = ksocknal_schedule_callback;
    sock->kstc_update_tx = ksocknal_update_tx;

	return;
}

void
ksocknal_lib_act_callback(struct socket *sock, ksock_conn_t *conn)
{
    sock->kstc_sched_cb(sock, TRUE,  NULL, 0);
    sock->kstc_sched_cb(sock, FALSE, NULL, 0);

	return;
}

void
ksocknal_lib_reset_callback(struct socket *sock, ksock_conn_t *conn)
{
	return ;
}

/*
 * ksocknal_lock_kiovs
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
ksocknal_lock_kiovs(
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

        rc = ksocknal_lock_buffer(
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
            ksocknal_release_mdl(mdl, FALSE);
            mdl = NULL;
        }
    }

    return mdl;
}

void
ksocknal_eager_ack (ksock_conn_t *conn)
{
    return;
}