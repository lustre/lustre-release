/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "socknal.h"

ptl_handle_ni_t         ksocknal_ni;
static nal_t            ksocknal_api;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
ksock_nal_data_t ksocknal_data;
#else
static ksock_nal_data_t ksocknal_data;
#endif

kpr_nal_interface_t ksocknal_router_interface = {
        kprni_nalid:      SOCKNAL,
        kprni_arg:        &ksocknal_data,
        kprni_fwd:        ksocknal_fwd_packet,
};


int
ksocknal_api_forward(nal_t *nal, int id, void *args, size_t args_len,
                       void *ret, size_t ret_len)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;

        lib_dispatch(nal_cb, k, id, args, ret); /* ksocknal_send needs k */
        return PTL_OK;
}

int
ksocknal_api_shutdown(nal_t *nal, int ni)
{
        CDEBUG (D_NET, "closing all connections\n");

        return ksocknal_close_sock(0);          /* close all sockets */
}

void
ksocknal_api_yield(nal_t *nal)
{
        our_cond_resched();
        return;
}

void
ksocknal_api_lock(nal_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;
        nal_cb->cb_cli(nal_cb,flags);
}

void
ksocknal_api_unlock(nal_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;
        nal_cb->cb_sti(nal_cb,flags);
}

nal_t *
ksocknal_init(int interface, ptl_pt_index_t ptl_size,
              ptl_ac_index_t ac_size, ptl_pid_t requested_pid)
{
        CDEBUG(D_NET, "calling lib_init with nid "LPX64"\n", (ptl_nid_t)0);
        lib_init(&ksocknal_lib, (ptl_nid_t)0, 0, 10, ptl_size, ac_size);
        return (&ksocknal_api);
}

/*
 *  EXTRA functions follow
 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define SOCKET_I(inode) (&(inode)->u.socket_i)
#endif
static __inline__ struct socket *
socki_lookup(struct inode *inode)
{
        return SOCKET_I(inode);
}

int
ksocknal_set_mynid(ptl_nid_t nid)
{
        lib_ni_t *ni = &ksocknal_lib.ni;

        /* FIXME: we have to do this because we call lib_init() at module
         * insertion time, which is before we have 'mynid' available.  lib_init
         * sets the NAL's nid, which it uses to tell other nodes where packets
         * are coming from.  This is not a very graceful solution to this
         * problem. */

        CDEBUG(D_IOCTL, "setting mynid to "LPX64" (old nid="LPX64")\n",
               nid, ni->nid);

        ni->nid = nid;
        return (0);
}

void
ksocknal_bind_irq (unsigned int irq, int cpu)
{
#if (defined(CONFIG_SMP) && CPU_AFFINITY)
        char  cmdline[64];
        char *argv[] = {"/bin/sh",
                        "-c",
                        cmdline,
                        NULL};
        char *envp[] = {"HOME=/",
                        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                        NULL};

        snprintf (cmdline, sizeof (cmdline),
                  "echo %d > /proc/irq/%u/smp_affinity", 1 << cpu, irq);

        printk (KERN_INFO "Binding irq %u to CPU %d with cmd: %s\n",
                irq, cpu, cmdline);

        /* FIXME: Find a better method of setting IRQ affinity...
         */

        call_usermodehelper (argv[0], argv, envp);
#endif
}

int
ksocknal_add_sock (ptl_nid_t nid, int fd, int bind_irq)
{
        unsigned long      flags;
        ksock_conn_t      *conn;
        struct file       *file = NULL;
        struct socket     *sock = NULL;
        ksock_sched_t     *sched = NULL;
        unsigned int       irq = 0;
        struct net_device *dev = NULL;
        int                ret;
        int                idx;
        ENTRY;

        LASSERT (!in_interrupt());

        file = fget(fd);
        if (file == NULL)
                RETURN(-EINVAL);

        ret = -EINVAL;
        sock = socki_lookup(file->f_dentry->d_inode);
        if (sock == NULL)
                GOTO(error, ret);

        ret = -ENOMEM;
        PORTAL_ALLOC(conn, sizeof(*conn));
        if (!conn)
                GOTO(error, ret);

        memset (conn, 0, sizeof (conn));        /* zero for consistency */

        conn->ksnc_file = file;
        conn->ksnc_sock = sock;
        conn->ksnc_saved_data_ready = sock->sk->data_ready;
        conn->ksnc_saved_write_space = sock->sk->write_space;
        conn->ksnc_peernid = nid;
        atomic_set (&conn->ksnc_refcount, 1);    /* 1 ref for socklist */

        conn->ksnc_rx_ready = 0;
        conn->ksnc_rx_scheduled = 0;
        ksocknal_new_packet (conn, 0);

        INIT_LIST_HEAD (&conn->ksnc_tx_queue);
        conn->ksnc_tx_ready = 0;
        conn->ksnc_tx_scheduled = 0;

#warning check it is OK to derefence sk->dst_cache->dev like this...
        lock_sock (conn->ksnc_sock->sk);

        if (conn->ksnc_sock->sk->dst_cache != NULL) {
                dev = conn->ksnc_sock->sk->dst_cache->dev;
                if (dev != NULL) {
                        irq = dev->irq;
                        if (irq >= NR_IRQS) {
                                CERROR ("Unexpected IRQ %x\n", irq);
                                irq = 0;
                        }
                }
        }

        release_sock (conn->ksnc_sock->sk);

        write_lock_irqsave (&ksocknal_data.ksnd_socklist_lock, flags);

        if (irq == 0 ||
            ksocknal_data.ksnd_irq_info[irq] == SOCKNAL_IRQ_UNASSIGNED) {
                /* This is a software NIC, or we haven't associated it with
                 * a CPU yet */

                /* Choose the CPU with the fewest connections */
                sched = ksocknal_data.ksnd_schedulers;
                for (idx = 1; idx < SOCKNAL_N_SCHED; idx++)
                        if (sched->kss_nconns >
                            ksocknal_data.ksnd_schedulers[idx].kss_nconns)
                                sched = &ksocknal_data.ksnd_schedulers[idx];

                if (irq != 0) {                 /* Hardware NIC */
                        /* Remember which scheduler we chose */
                        idx = sched - ksocknal_data.ksnd_schedulers;

                        LASSERT (idx < SOCKNAL_IRQ_SCHED_MASK);

                        if (bind_irq)       /* remember if we will bind below */
                                idx |= SOCKNAL_IRQ_BOUND;

                        ksocknal_data.ksnd_irq_info[irq] = idx;
                }
        } else { 
                /* This is a hardware NIC, associated with a CPU */
                idx = ksocknal_data.ksnd_irq_info[irq];

                /* Don't bind again if we've bound already */
                if ((idx & SOCKNAL_IRQ_BOUND) != 0)
                        bind_irq = 0;
                
                sched = &ksocknal_data.ksnd_schedulers[idx & SOCKNAL_IRQ_SCHED_MASK];
        }

        sched->kss_nconns++;
        conn->ksnc_scheduler = sched;

        list_add(&conn->ksnc_list, &ksocknal_data.ksnd_socklist);

        write_unlock_irqrestore (&ksocknal_data.ksnd_socklist_lock, flags);

        if (bind_irq &&                         /* irq binding required */
            irq != 0)                           /* hardware NIC */
                ksocknal_bind_irq (irq, sched - ksocknal_data.ksnd_schedulers);

        /* NOW it's safe to get called back when socket is ready... */
        sock->sk->user_data = conn;
        sock->sk->data_ready = ksocknal_data_ready;
        sock->sk->write_space = ksocknal_write_space;

        /* ...which I call right now to get things going */
        ksocknal_data_ready (sock->sk, 0);
        ksocknal_write_space (sock->sk);

        CDEBUG(D_IOCTL, "conn [%p] registered for nid "LPX64"\n",
               conn, conn->ksnc_peernid);

        /* Can't unload while connection active */
        PORTAL_MODULE_USE;
        RETURN(0);

error:
        fput(file);
        return (ret);
}

/* Passing in a zero nid will close all connections */
int
ksocknal_close_sock(ptl_nid_t nid)
{
        long               flags;
        ksock_conn_t      *conn;
        LIST_HEAD         (death_row);
        struct list_head  *tmp;

        LASSERT (!in_interrupt());
        write_lock_irqsave (&ksocknal_data.ksnd_socklist_lock, flags);

        if (nid == 0) {                         /* close ALL connections */
                /* insert 'death row' into the socket list... */
                list_add (&death_row, &ksocknal_data.ksnd_socklist);
                /* ...extract and reinitialise the socket list itself... */
                list_del_init (&ksocknal_data.ksnd_socklist);
                /* ...and voila, death row is the proud owner of all conns */
        } else list_for_each (tmp, &ksocknal_data.ksnd_socklist) {

                conn = list_entry (tmp, ksock_conn_t, ksnc_list);

                if (conn->ksnc_peernid == nid) {
                        list_del (&conn->ksnc_list);
                        list_add (&conn->ksnc_list, &death_row);
                        break;
                }
        }

        write_unlock_irqrestore (&ksocknal_data.ksnd_socklist_lock, flags);

        if (nid && list_empty (&death_row))
                return (-ENOENT);

        while (!list_empty (&death_row)) {
                conn = list_entry (death_row.next, ksock_conn_t, ksnc_list);
                list_del (&conn->ksnc_list);

                /* NB I _have_ to restore the callback, rather than storing
                 * a noop, since the socket could survive past this module
                 * being unloaded!! */
                conn->ksnc_sock->sk->data_ready = conn->ksnc_saved_data_ready;
                conn->ksnc_sock->sk->write_space = conn->ksnc_saved_write_space;

                /* OK; no more callbacks, but they could be in progress now,
                 * so wait for them to complete... */
                write_lock_irqsave (&ksocknal_data.ksnd_socklist_lock, flags);

                /* ...however if I get the lock before a callback gets it,
                 * this will make them noop
                 */
                conn->ksnc_sock->sk->user_data = NULL;

                /* And drop the scheduler's connection count while I've got
                 * the exclusive lock */
                conn->ksnc_scheduler->kss_nconns--;

                write_unlock_irqrestore(&ksocknal_data.ksnd_socklist_lock,
                                        flags);

                ksocknal_put_conn (conn);       /* drop ref for ksnd_socklist */
        }

        return (0);
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
ksocknal_push_conn (ksock_conn_t *conn)
{
        struct sock    *sk = conn->ksnc_sock->sk;
        struct tcp_opt *tp = sock2tcp_opt(sk);
        int             nonagle;
        int             val = 1;
        int             rc;
        mm_segment_t    oldmm;

        lock_sock (sk);
        nonagle = tp->nonagle;
        tp->nonagle = 1;
        release_sock (sk);

        oldmm = get_fs ();
        set_fs (KERNEL_DS);

        rc = sk->prot->setsockopt (sk, SOL_TCP, TCP_NODELAY,
                                   (char *)&val, sizeof (val));
        LASSERT (rc == 0);

        set_fs (oldmm);

        lock_sock (sk);
        tp->nonagle = nonagle;
        release_sock (sk);
}

/* Passing in a zero nid pushes all connections */
int
ksocknal_push_sock (ptl_nid_t nid)
{
        ksock_conn_t      *conn;
        struct list_head  *tmp;
        int                index;
        int                i;

        if (nid != 0) {
                conn = ksocknal_get_conn (nid);

                if (conn == NULL)
                        return (-ENOENT);

                ksocknal_push_conn (conn);
                ksocknal_put_conn (conn);

                return (0);
        }

        /* NB we can't remove connections from the socket list so we have to
         * cope with them being removed from under us...
         */
        for (index = 0; ; index++) {
                read_lock (&ksocknal_data.ksnd_socklist_lock);

                i = 0;
                conn = NULL;

                list_for_each (tmp, &ksocknal_data.ksnd_socklist) {
                        if (i++ == index) {
                                conn = list_entry(tmp, ksock_conn_t, ksnc_list);
                                atomic_inc (&conn->ksnc_refcount); // take a ref
                                break;
                        }
                }

                read_unlock (&ksocknal_data.ksnd_socklist_lock);

                if (conn == NULL)
                        break;

                ksocknal_push_conn (conn);
                ksocknal_put_conn (conn);
        }

        return (0);
}

ksock_conn_t *
ksocknal_get_conn (ptl_nid_t nid)
{
        struct list_head *tmp;
        ksock_conn_t     *conn;

        PROF_START(conn_list_walk);

        read_lock (&ksocknal_data.ksnd_socklist_lock);

        list_for_each(tmp, &ksocknal_data.ksnd_socklist) {

                conn = list_entry(tmp, ksock_conn_t, ksnc_list);

                if (conn->ksnc_peernid == nid) {
                        /* caller is referencing */
                        atomic_inc (&conn->ksnc_refcount);

                        read_unlock (&ksocknal_data.ksnd_socklist_lock);

                        CDEBUG(D_NET, "got conn [%p] -> "LPX64" (%d)\n",
                               conn, nid, atomic_read (&conn->ksnc_refcount));

                        PROF_FINISH(conn_list_walk);
                        return (conn);
                }
        }

        read_unlock (&ksocknal_data.ksnd_socklist_lock);

        CDEBUG(D_NET, "No connection found when looking for nid "LPX64"\n",
               nid);
        PROF_FINISH(conn_list_walk);
        return (NULL);
}

void
ksocknal_close_conn (ksock_conn_t *conn)
{
        CDEBUG (D_NET, "connection [%p] closed \n", conn);

        fput (conn->ksnc_file);
        PORTAL_FREE (conn, sizeof (*conn));

        /* One less connection keeping us hanging on */
        PORTAL_MODULE_UNUSE;
}

void
_ksocknal_put_conn (ksock_conn_t *conn)
{
        unsigned long flags;

        CDEBUG (D_NET, "connection [%p] handed the black spot\n", conn);

        /* "But what is the black spot, captain?" I asked.
         * "That's a summons, mate..." */

        LASSERT (atomic_read (&conn->ksnc_refcount) == 0);
        LASSERT (conn->ksnc_sock->sk->data_ready != ksocknal_data_ready);
        LASSERT (conn->ksnc_sock->sk->write_space != ksocknal_write_space);
        LASSERT (conn->ksnc_sock->sk->user_data == NULL);
        LASSERT (!conn->ksnc_rx_scheduled);

        if (!in_interrupt()) {
                ksocknal_close_conn (conn);
                return;
        }

        spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);

        list_add (&conn->ksnc_list, &ksocknal_data.ksnd_reaper_list);
        wake_up (&ksocknal_data.ksnd_reaper_waitq);

        spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);
}

int
ksocknal_cmd(struct portal_ioctl_data * data, void * private)
{
        int rc = -EINVAL;

        LASSERT (data != NULL);

        switch(data->ioc_nal_cmd) {
        case NAL_CMD_REGISTER_PEER_FD: {
                rc = ksocknal_add_sock(data->ioc_nid, data->ioc_fd,
                                       data->ioc_flags);
                break;
        }
        case NAL_CMD_CLOSE_CONNECTION: {
                rc = ksocknal_close_sock(data->ioc_nid);
                break;
        }
        case NAL_CMD_REGISTER_MYNID: {
                rc = ksocknal_set_mynid (data->ioc_nid);
                break;
        }
        case NAL_CMD_PUSH_CONNECTION: {
                rc = ksocknal_push_sock (data->ioc_nid);
                break;
        }
        }

        return rc;
}

void
ksocknal_free_buffers (void)
{
        if (ksocknal_data.ksnd_fmbs != NULL) {
                ksock_fmb_t *fmb = (ksock_fmb_t *)ksocknal_data.ksnd_fmbs;
                int          i;
                int          j;

                for (i = 0;
                     i < (SOCKNAL_SMALL_FWD_NMSGS + SOCKNAL_LARGE_FWD_NMSGS);
                     i++, fmb++)
                        for (j = 0; j < fmb->fmb_npages; j++)
                                if (fmb->fmb_pages[j] != NULL)
                                        __free_page (fmb->fmb_pages[j]);

                PORTAL_FREE (ksocknal_data.ksnd_fmbs,
                             sizeof (ksock_fmb_t) * (SOCKNAL_SMALL_FWD_NMSGS +
                                                     SOCKNAL_LARGE_FWD_NMSGS));
        }

        if (ksocknal_data.ksnd_ltxs != NULL)
                PORTAL_FREE (ksocknal_data.ksnd_ltxs,
                             sizeof (ksock_ltx_t) * (SOCKNAL_NLTXS +
                                                     SOCKNAL_NNBLK_LTXS));

        if (ksocknal_data.ksnd_schedulers != NULL)
                PORTAL_FREE (ksocknal_data.ksnd_schedulers,
                             sizeof (ksock_sched_t) * SOCKNAL_N_SCHED);
}

void __exit
ksocknal_module_fini (void)
{
        int   i;

        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        switch (ksocknal_data.ksnd_init) {
        default:
                LASSERT (0);

        case SOCKNAL_INIT_ALL:
                kportal_nal_unregister(SOCKNAL);
                PORTAL_SYMBOL_UNREGISTER (ksocknal_ni);
                /* fall through */

        case SOCKNAL_INIT_PTL:
                PtlNIFini(ksocknal_ni);
                lib_fini(&ksocknal_lib);
                /* fall through */

        case SOCKNAL_INIT_DATA:
                /* Module refcount only gets to zero when all connections
                 * have been closed so all lists must be empty */
                LASSERT (list_empty (&ksocknal_data.ksnd_socklist));
                LASSERT (list_empty (&ksocknal_data.ksnd_reaper_list));
                LASSERT (list_empty (&ksocknal_data.ksnd_small_fmp.fmp_blocked_conns));
                LASSERT (list_empty (&ksocknal_data.ksnd_large_fmp.fmp_blocked_conns));

                if (ksocknal_data.ksnd_schedulers != NULL)
                        for (i = 0; i < SOCKNAL_N_SCHED; i++) {
                                ksock_sched_t *kss =
                                        &ksocknal_data.ksnd_schedulers[i];

                                LASSERT (list_empty (&kss->kss_tx_conns));
                                LASSERT (list_empty (&kss->kss_rx_conns));
                                LASSERT (kss->kss_nconns == 0);
                        }

                /* stop router calling me */
                kpr_shutdown (&ksocknal_data.ksnd_router);

                /* flag threads to terminate; wake and wait for them to die */
                ksocknal_data.ksnd_shuttingdown = 1;
                wake_up_all (&ksocknal_data.ksnd_reaper_waitq);

                for (i = 0; i < SOCKNAL_N_SCHED; i++)
                       wake_up_all(&ksocknal_data.ksnd_schedulers[i].kss_waitq);

                while (atomic_read (&ksocknal_data.ksnd_nthreads) != 0) {
                        CDEBUG (D_NET, "waitinf for %d threads to terminate\n",
                                atomic_read (&ksocknal_data.ksnd_nthreads));
                        set_current_state (TASK_UNINTERRUPTIBLE);
                        schedule_timeout (HZ);
                }

                kpr_deregister (&ksocknal_data.ksnd_router);

                ksocknal_free_buffers();
                /* fall through */

        case SOCKNAL_INIT_NOTHING:
                break;
        }

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        printk(KERN_INFO "Routing socket NAL unloaded (final mem %d)\n",
               atomic_read(&portal_kmemory));
}


int __init
ksocknal_module_init (void)
{
        int   pkmem = atomic_read(&portal_kmemory);
        int   rc;
        int   i;
        int   j;

        /* packet descriptor must fit in a router descriptor's scratchpad */
        LASSERT(sizeof (ksock_tx_t) <= sizeof (kprfd_scratch_t));

        LASSERT (ksocknal_data.ksnd_init == SOCKNAL_INIT_NOTHING);

        ksocknal_api.forward  = ksocknal_api_forward;
        ksocknal_api.shutdown = ksocknal_api_shutdown;
        ksocknal_api.yield    = ksocknal_api_yield;
        ksocknal_api.validate = NULL;           /* our api validate is a NOOP */
        ksocknal_api.lock     = ksocknal_api_lock;
        ksocknal_api.unlock   = ksocknal_api_unlock;
        ksocknal_api.nal_data = &ksocknal_data;

        ksocknal_lib.nal_data = &ksocknal_data;

        memset (&ksocknal_data, 0, sizeof (ksocknal_data)); /* zero pointers */

        INIT_LIST_HEAD(&ksocknal_data.ksnd_socklist);
        rwlock_init(&ksocknal_data.ksnd_socklist_lock);

        ksocknal_data.ksnd_nal_cb = &ksocknal_lib;
        spin_lock_init (&ksocknal_data.ksnd_nal_cb_lock);

        spin_lock_init(&ksocknal_data.ksnd_small_fmp.fmp_lock);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_small_fmp.fmp_idle_fmbs);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_small_fmp.fmp_blocked_conns);

        spin_lock_init(&ksocknal_data.ksnd_large_fmp.fmp_lock);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_large_fmp.fmp_idle_fmbs);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_large_fmp.fmp_blocked_conns);

        spin_lock_init(&ksocknal_data.ksnd_idle_ltx_lock);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_idle_nblk_ltx_list);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_idle_ltx_list);
        init_waitqueue_head(&ksocknal_data.ksnd_idle_ltx_waitq);

        spin_lock_init (&ksocknal_data.ksnd_reaper_lock);
        INIT_LIST_HEAD (&ksocknal_data.ksnd_reaper_list);
        init_waitqueue_head(&ksocknal_data.ksnd_reaper_waitq);

        memset (&ksocknal_data.ksnd_irq_info, SOCKNAL_IRQ_UNASSIGNED,
                sizeof (ksocknal_data.ksnd_irq_info));

        /* flag lists/ptrs/locks initialised */
        ksocknal_data.ksnd_init = SOCKNAL_INIT_DATA;

        PORTAL_ALLOC(ksocknal_data.ksnd_schedulers,
                     sizeof(ksock_sched_t) * SOCKNAL_N_SCHED);
        if (ksocknal_data.ksnd_schedulers == NULL)
                RETURN(-ENOMEM);

        for (i = 0; i < SOCKNAL_N_SCHED; i++) {
                ksock_sched_t *kss = &ksocknal_data.ksnd_schedulers[i];

                spin_lock_init (&kss->kss_lock);
                INIT_LIST_HEAD (&kss->kss_rx_conns);
                INIT_LIST_HEAD (&kss->kss_tx_conns);
#if SOCKNAL_ZC
                INIT_LIST_HEAD (&kss->kss_zctxdone_list);
#endif
                init_waitqueue_head (&kss->kss_waitq);
        }

        CERROR ("ltx "LPSZ", total "LPSZ"\n", sizeof (ksock_ltx_t),
                sizeof (ksock_ltx_t) * (SOCKNAL_NLTXS + SOCKNAL_NNBLK_LTXS));

        PORTAL_ALLOC(ksocknal_data.ksnd_ltxs,
                     sizeof(ksock_ltx_t) * (SOCKNAL_NLTXS +SOCKNAL_NNBLK_LTXS));
        if (ksocknal_data.ksnd_ltxs == NULL) {
                ksocknal_module_fini ();
                return (-ENOMEM);
        }

        /* Deterministic bugs please */
        memset (ksocknal_data.ksnd_ltxs, 0xeb,
                sizeof (ksock_ltx_t) * (SOCKNAL_NLTXS + SOCKNAL_NNBLK_LTXS));

        for (i = 0; i < SOCKNAL_NLTXS + SOCKNAL_NNBLK_LTXS; i++) {
                ksock_ltx_t *ltx = &((ksock_ltx_t *)ksocknal_data.ksnd_ltxs)[i];

                ltx->ltx_idle = i < SOCKNAL_NLTXS ?
                                &ksocknal_data.ksnd_idle_ltx_list :
                                &ksocknal_data.ksnd_idle_nblk_ltx_list;
                list_add (&ltx->ltx_tx.tx_list, ltx->ltx_idle);
        }

        rc = PtlNIInit(ksocknal_init, 32, 4, 0, &ksocknal_ni);
        if (rc != 0) {
                CERROR("ksocknal: PtlNIInit failed: error %d\n", rc);
                ksocknal_module_fini ();
                RETURN (rc);
        }
        PtlNIDebug(ksocknal_ni, ~0);

        ksocknal_data.ksnd_init = SOCKNAL_INIT_PTL; // flag PtlNIInit() called

        for (i = 0; i < SOCKNAL_N_SCHED; i++) {
                rc = ksocknal_thread_start (ksocknal_scheduler,
                                            &ksocknal_data.ksnd_schedulers[i]);
                if (rc != 0) {
                        CERROR("Can't spawn socknal scheduler[%d]: %d\n",
                               i, rc);
                        ksocknal_module_fini ();
                        RETURN (rc);
                }
        }

        rc = ksocknal_thread_start (ksocknal_reaper, NULL);
        if (rc != 0) {
                CERROR("Can't spawn socknal reaper: %d\n", rc);
                ksocknal_module_fini ();
                RETURN (rc);
        }

        rc = kpr_register(&ksocknal_data.ksnd_router,
                          &ksocknal_router_interface);
        if (rc != 0) {
                CDEBUG(D_NET, "Can't initialise routing interface "
                       "(rc = %d): not routing\n", rc);
        } else {
                /* Only allocate forwarding buffers if I'm on a gateway */

                PORTAL_ALLOC(ksocknal_data.ksnd_fmbs,
                             sizeof(ksock_fmb_t) * (SOCKNAL_SMALL_FWD_NMSGS +
                                                    SOCKNAL_LARGE_FWD_NMSGS));
                if (ksocknal_data.ksnd_fmbs == NULL) {
                        ksocknal_module_fini ();
                        RETURN(-ENOMEM);
                }

                /* NULL out buffer pointers etc */
                memset(ksocknal_data.ksnd_fmbs, 0,
                       sizeof(ksock_fmb_t) * (SOCKNAL_SMALL_FWD_NMSGS +
                                              SOCKNAL_LARGE_FWD_NMSGS));

                for (i = 0; i < (SOCKNAL_SMALL_FWD_NMSGS +
                                 SOCKNAL_LARGE_FWD_NMSGS); i++) {
                        ksock_fmb_t *fmb =
                                &((ksock_fmb_t *)ksocknal_data.ksnd_fmbs)[i];

                        if (i < SOCKNAL_SMALL_FWD_NMSGS) {
                                fmb->fmb_npages = SOCKNAL_SMALL_FWD_PAGES;
                                fmb->fmb_pool = &ksocknal_data.ksnd_small_fmp;
                        } else {
                                fmb->fmb_npages = SOCKNAL_LARGE_FWD_PAGES;
                                fmb->fmb_pool = &ksocknal_data.ksnd_large_fmp;
                        }

                        LASSERT (fmb->fmb_npages > 0);
                        for (j = 0; j < fmb->fmb_npages; j++) {
                                fmb->fmb_pages[j] = alloc_page (GFP_KERNEL);

                                if (fmb->fmb_pages[j] == NULL) {
                                        ksocknal_module_fini ();
                                        return (-ENOMEM);
                                }

                                LASSERT(page_address (fmb->fmb_pages[j]) !=
                                        NULL);
                        }

                        list_add(&fmb->fmb_list, &fmb->fmb_pool->fmp_idle_fmbs);
                }
        }

        rc = kportal_nal_register(SOCKNAL, &ksocknal_cmd, NULL);
        if (rc != 0) {
                CERROR ("Can't initialise command interface (rc = %d)\n", rc);
                ksocknal_module_fini ();
                return (rc);
        }

        PORTAL_SYMBOL_REGISTER(ksocknal_ni);

        /* flag everything initialised */
        ksocknal_data.ksnd_init = SOCKNAL_INIT_ALL;

        printk(KERN_INFO "Routing socket NAL loaded (Routing %s, initial "
               "mem %d)\n",
               kpr_routing (&ksocknal_data.ksnd_router) ?
               "enabled" : "disabled", pkmem);

        return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel TCP Socket NAL v0.01");
MODULE_LICENSE("GPL");

module_init(ksocknal_module_init);
module_exit(ksocknal_module_fini);

EXPORT_SYMBOL (ksocknal_ni);
