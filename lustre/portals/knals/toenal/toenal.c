/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *   Author: Kedar Sovani <kedar@calsoftinc.com>
 *   Author: Amey Inamdar <amey@calsoftinc.com>
 *
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
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
 *
 */
#include <linux/poll.h>
#include "toenal.h"

ptl_handle_ni_t         ktoenal_ni;
static nal_t            ktoenal_api;
static ksock_nal_data_t ktoenal_data;

/*
ksocknal_interface_t ktoenal_interface = {
        ksni_add_sock:		ktoenal_add_sock,
        ksni_close_sock:	ktoenal_close_sock,
        ksni_set_mynid:		ktoenal_set_mynid,
};
*/

kpr_nal_interface_t ktoenal_router_interface = {
        kprni_nalid:	TOENAL,
        kprni_arg:     &ktoenal_data,
        kprni_fwd:	ktoenal_fwd_packet,
};


int
ktoenal_api_forward(nal_t *nal, int id, void *args, size_t args_len,
                       void *ret, size_t ret_len)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;

        lib_dispatch(nal_cb, k, id, args, ret); /* ktoenal_send needs k */
        return PTL_OK;
}

int
ktoenal_api_shutdown(nal_t *nal, int ni)
{
	CDEBUG (D_NET, "closing all connections\n");

        return ktoenal_close_sock(0);          /* close all sockets */
}

void
ktoenal_api_yield(nal_t *nal)
{
        our_cond_resched();
        return;
}

void
ktoenal_api_lock(nal_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;
        nal_cb->cb_cli(nal_cb,flags);
}

void
ktoenal_api_unlock(nal_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;
        nal_cb->cb_sti(nal_cb,flags);
}

nal_t *
ktoenal_init(int interface, ptl_pt_index_t ptl_size,
              ptl_ac_index_t ac_size, ptl_pid_t requested_pid)
{
        CDEBUG(D_NET, "calling lib_init with nid "LPX64"\n",
               ktoenal_data.ksnd_mynid);
        lib_init(&ktoenal_lib, ktoenal_data.ksnd_mynid, 0, 10, ptl_size,
                 ac_size);
        return (&ktoenal_api);
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
ktoenal_set_mynid(ptl_nid_t nid)
{
        lib_ni_t *ni = &ktoenal_lib.ni;

        /* FIXME: we have to do this because we call lib_init() at module
         * insertion time, which is before we have 'mynid' available.  lib_init
         * sets the NAL's nid, which it uses to tell other nodes where packets
         * are coming from.  This is not a very graceful solution to this
         * problem. */

        CDEBUG(D_IOCTL, "setting mynid to "LPX64" (old nid="LPX64")\n", nid, ni->nid);

        ktoenal_data.ksnd_mynid = nid;
        ni->nid = nid;
        return (0);
}

int
ktoenal_add_sock (ptl_nid_t nid, int fd)
{
        unsigned long      flags;
        ksock_conn_t      *conn;
        struct file       *file = NULL;
        struct socket     *sock = NULL;
        int                ret;
        ENTRY;

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
        file->f_flags |= O_NONBLOCK;  /*  Does this have any conflicts */
        conn->ksnc_file = file;
        conn->ksnc_sock = sock;
        conn->ksnc_peernid = nid;
        atomic_set (&conn->ksnc_refcount, 1);    /* 1 ref for socklist */

        conn->ksnc_rx_ready = 0;
        conn->ksnc_rx_scheduled = 0;
        ktoenal_new_packet (conn, 0);

        INIT_LIST_HEAD (&conn->ksnc_tx_queue);
        conn->ksnc_tx_ready = 0;
        conn->ksnc_tx_scheduled = 0;

        LASSERT (!in_interrupt());
        write_lock_irqsave (&ktoenal_data.ksnd_socklist_lock, flags);

        list_add(&conn->ksnc_list, &ktoenal_data.ksnd_socklist);
        write_unlock_irqrestore (&ktoenal_data.ksnd_socklist_lock, flags);

        ktoenal_data_ready(conn);
        ktoenal_write_space(conn);

        ktoenal_data.ksnd_slistchange = 1;
        wake_up_process(ktoenal_data.ksnd_pollthread_tsk);
        /* Schedule pollthread so that it will poll
         * for newly created socket
         */


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
ktoenal_close_sock(ptl_nid_t nid)
{
        long               flags;
        ksock_conn_t      *conn;
        LIST_HEAD         (death_row);
        struct list_head  *tmp;

        LASSERT (!in_interrupt());
        write_lock_irqsave (&ktoenal_data.ksnd_socklist_lock, flags);

        if (nid == 0)                           /* close ALL connections */
        {
                /* insert 'death row' into the socket list... */
                list_add (&death_row, &ktoenal_data.ksnd_socklist);
                /* ...extract and reinitialise the socket list itself... */
                list_del_init (&ktoenal_data.ksnd_socklist);
                /* ...and voila, death row is the proud owner of all conns */
        } else list_for_each (tmp, &ktoenal_data.ksnd_socklist) {

                conn = list_entry (tmp, ksock_conn_t, ksnc_list);

                if (conn->ksnc_peernid == nid)
                {
                        list_del (&conn->ksnc_list);
                        list_add (&conn->ksnc_list, &death_row);
                        break;
                }
        }


        write_unlock_irqrestore (&ktoenal_data.ksnd_socklist_lock, flags);

        if (list_empty (&death_row))
                return (-ENOENT);

        do {
                conn = list_entry (death_row.next, ksock_conn_t, ksnc_list);
                list_del (&conn->ksnc_list);
                ktoenal_put_conn (conn);       /* drop ref for ksnd_socklist */
        } while (!list_empty (&death_row));

        ktoenal_data.ksnd_slistchange = 1;
        wake_up_process(ktoenal_data.ksnd_pollthread_tsk);

        return (0);
}


ksock_conn_t *
ktoenal_get_conn (ptl_nid_t nid)
{
        struct list_head *tmp;
        ksock_conn_t     *conn;

        PROF_START(conn_list_walk);

        read_lock (&ktoenal_data.ksnd_socklist_lock);

        list_for_each(tmp, &ktoenal_data.ksnd_socklist) {

                conn = list_entry(tmp, ksock_conn_t, ksnc_list);

                if (conn->ksnc_peernid == nid)
                {
                        /* caller is referencing */
                        atomic_inc (&conn->ksnc_refcount);

                        read_unlock (&ktoenal_data.ksnd_socklist_lock);

                        CDEBUG(D_NET, "got conn [%p] -> "LPX64" (%d)\n",
                               conn, nid, atomic_read (&conn->ksnc_refcount));

                        PROF_FINISH(conn_list_walk);
                        return (conn);
                }
        }

        read_unlock (&ktoenal_data.ksnd_socklist_lock);

        CDEBUG(D_NET, "No connection found when looking for nid "LPX64"\n", nid);
        PROF_FINISH(conn_list_walk);
        return (NULL);
}

void
ktoenal_close_conn (ksock_conn_t *conn)
{
        CDEBUG (D_NET, "connection [%p] closed \n", conn);

        fput (conn->ksnc_file);
        PORTAL_FREE (conn, sizeof (*conn));
        /* One less connection keeping us hanging on */
        PORTAL_MODULE_UNUSE;
}

void
_ktoenal_put_conn (ksock_conn_t *conn)
{
        unsigned long flags;

        CDEBUG (D_NET, "connection [%p] handed the black spot\n", conn);

        /* "But what is the black spot, captain?" I asked.
         * "That's a summons, mate..." */

        LASSERT (atomic_read (&conn->ksnc_refcount) == 0);
        LASSERT (!conn->ksnc_rx_scheduled);

        if (!in_interrupt())
        {
                ktoenal_close_conn (conn);
                return;
        }

        spin_lock_irqsave (&ktoenal_data.ksnd_reaper_lock, flags);

        list_add (&conn->ksnc_list, &ktoenal_data.ksnd_reaper_list);
        wake_up (&ktoenal_data.ksnd_reaper_waitq);

        spin_unlock_irqrestore (&ktoenal_data.ksnd_reaper_lock, flags);
}

void
ktoenal_free_buffers (void)
{
        if (ktoenal_data.ksnd_fmbs != NULL)
        {
                ksock_fmb_t *fmb = (ksock_fmb_t *)ktoenal_data.ksnd_fmbs;
                int          i;
                int          j;

                for (i = 0; i < (SOCKNAL_SMALL_FWD_NMSGS + SOCKNAL_LARGE_FWD_NMSGS); i++, fmb++)
                        for (j = 0; j < fmb->fmb_npages; j++)
                                if (fmb->fmb_pages[j] != NULL)
                                        __free_page (fmb->fmb_pages[j]);

                PORTAL_FREE (ktoenal_data.ksnd_fmbs,
                             sizeof (ksock_fmb_t) * (SOCKNAL_SMALL_FWD_NMSGS + SOCKNAL_LARGE_FWD_NMSGS));
        }

        if (ktoenal_data.ksnd_ltxs != NULL)
                PORTAL_FREE (ktoenal_data.ksnd_ltxs,
                             sizeof (ksock_ltx_t) * (SOCKNAL_NLTXS + SOCKNAL_NNBLK_LTXS));
}

int
ktoenal_cmd(struct portal_ioctl_data * data, void * private)
{
        int rc = -EINVAL;

        LASSERT (data != NULL);

        switch(data->ioc_nal_cmd) {
        case NAL_CMD_REGISTER_PEER_FD: {
                rc = ktoenal_add_sock(data->ioc_nid, data->ioc_fd);
                break;
        }
        case NAL_CMD_CLOSE_CONNECTION: {
                rc = ktoenal_close_sock(data->ioc_nid);
                break;
        }
        case NAL_CMD_REGISTER_MYNID: {
                rc = ktoenal_set_mynid (data->ioc_nid);
                break;
        }
        }

        return rc;
}


void __exit
ktoenal_module_fini (void)
{
        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        switch (ktoenal_data.ksnd_init)
        {
        default:
                LASSERT (0);

        case SOCKNAL_INIT_ALL:
                kportal_nal_unregister(TOENAL);
                PORTAL_SYMBOL_UNREGISTER (ktoenal_ni);
                /* fall through */

        case SOCKNAL_INIT_PTL:
                PtlNIFini(ktoenal_ni);
                lib_fini(&ktoenal_lib);
                /* fall through */

        case SOCKNAL_INIT_DATA:
                /* Module refcount only gets to zero when all connections
                 * have been closed so all lists must be empty */
                LASSERT (list_empty (&ktoenal_data.ksnd_socklist));
                LASSERT (list_empty (&ktoenal_data.ksnd_reaper_list));
                LASSERT (list_empty (&ktoenal_data.ksnd_rx_conns));
                LASSERT (list_empty (&ktoenal_data.ksnd_tx_conns));
                LASSERT (list_empty (&ktoenal_data.ksnd_small_fmp.fmp_blocked_conns));
                LASSERT (list_empty (&ktoenal_data.ksnd_large_fmp.fmp_blocked_conns));

                kpr_shutdown (&ktoenal_data.ksnd_router); /* stop router calling me */

                /* flag threads to terminate; wake and wait for them to die */
                ktoenal_data.ksnd_shuttingdown = 1;
                wake_up_all (&ktoenal_data.ksnd_reaper_waitq);
                wake_up_all (&ktoenal_data.ksnd_sched_waitq);
                wake_up_process(ktoenal_data.ksnd_pollthread_tsk);

                while (atomic_read (&ktoenal_data.ksnd_nthreads) != 0)
                {
                        CDEBUG (D_NET, "waitinf for %d threads to terminate\n",
                                atomic_read (&ktoenal_data.ksnd_nthreads));
                        set_current_state (TASK_UNINTERRUPTIBLE);
                        schedule_timeout (HZ);
                }

                kpr_deregister (&ktoenal_data.ksnd_router);

                ktoenal_free_buffers();
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
ktoenal_module_init (void)
{
        int   pkmem = atomic_read(&portal_kmemory);
        int   rc;
        int   i;
        int   j;

        /* packet descriptor must fit in a router descriptor's scratchpad */
        LASSERT(sizeof (ksock_tx_t) <= sizeof (kprfd_scratch_t));

        LASSERT (ktoenal_data.ksnd_init == SOCKNAL_INIT_NOTHING);

        ktoenal_api.forward  = ktoenal_api_forward;
        ktoenal_api.shutdown = ktoenal_api_shutdown;
        ktoenal_api.yield    = ktoenal_api_yield;
        ktoenal_api.validate = NULL;           /* our api validate is a NOOP */
        ktoenal_api.lock     = ktoenal_api_lock;
        ktoenal_api.unlock   = ktoenal_api_unlock;
        ktoenal_api.nal_data = &ktoenal_data;

        ktoenal_lib.nal_data = &ktoenal_data;

        memset (&ktoenal_data, 0, sizeof (ktoenal_data)); /* zero pointers */

        INIT_LIST_HEAD(&ktoenal_data.ksnd_socklist);
        rwlock_init(&ktoenal_data.ksnd_socklist_lock);

        ktoenal_data.ksnd_nal_cb = &ktoenal_lib;
        spin_lock_init (&ktoenal_data.ksnd_nal_cb_lock);

        spin_lock_init (&ktoenal_data.ksnd_sched_lock);

        init_waitqueue_head (&ktoenal_data.ksnd_sched_waitq);

        INIT_LIST_HEAD (&ktoenal_data.ksnd_rx_conns);
        INIT_LIST_HEAD (&ktoenal_data.ksnd_tx_conns);

        INIT_LIST_HEAD(&ktoenal_data.ksnd_small_fmp.fmp_idle_fmbs);
        INIT_LIST_HEAD(&ktoenal_data.ksnd_small_fmp.fmp_blocked_conns);
        INIT_LIST_HEAD(&ktoenal_data.ksnd_large_fmp.fmp_idle_fmbs);
        INIT_LIST_HEAD(&ktoenal_data.ksnd_large_fmp.fmp_blocked_conns);

        INIT_LIST_HEAD(&ktoenal_data.ksnd_idle_nblk_ltx_list);
        INIT_LIST_HEAD(&ktoenal_data.ksnd_idle_ltx_list);
        init_waitqueue_head(&ktoenal_data.ksnd_idle_ltx_waitq);

        INIT_LIST_HEAD (&ktoenal_data.ksnd_reaper_list);
        init_waitqueue_head(&ktoenal_data.ksnd_reaper_waitq);
        spin_lock_init (&ktoenal_data.ksnd_reaper_lock);

        ktoenal_data.ksnd_init = SOCKNAL_INIT_DATA; /* flag lists/ptrs/locks initialised */

        PORTAL_ALLOC(ktoenal_data.ksnd_fmbs,
                     sizeof(ksock_fmb_t) * (SOCKNAL_SMALL_FWD_NMSGS + SOCKNAL_LARGE_FWD_NMSGS));
        if (ktoenal_data.ksnd_fmbs == NULL)
                RETURN(-ENOMEM);

        /* NULL out buffer pointers etc */
        memset(ktoenal_data.ksnd_fmbs, 0,
               sizeof(ksock_fmb_t) * (SOCKNAL_SMALL_FWD_NMSGS + SOCKNAL_LARGE_FWD_NMSGS));

        for (i = 0; i < (SOCKNAL_SMALL_FWD_NMSGS + SOCKNAL_LARGE_FWD_NMSGS); i++)
        {
                ksock_fmb_t *fmb = &((ksock_fmb_t *)ktoenal_data.ksnd_fmbs)[i];

                if (i < SOCKNAL_SMALL_FWD_NMSGS)
                {
                        fmb->fmb_npages = SOCKNAL_SMALL_FWD_PAGES;
                        fmb->fmb_pool = &ktoenal_data.ksnd_small_fmp;
                }
                else
                {
                        fmb->fmb_npages = SOCKNAL_LARGE_FWD_PAGES;
                        fmb->fmb_pool = &ktoenal_data.ksnd_large_fmp;
                }

                LASSERT (fmb->fmb_npages > 0);
                for (j = 0; j < fmb->fmb_npages; j++)
                {
                        fmb->fmb_pages[j] = alloc_page (GFP_KERNEL);

                        if (fmb->fmb_pages[j] == NULL)
                        {
                                ktoenal_module_fini ();
                                return (-ENOMEM);
                        }

                        LASSERT (page_address (fmb->fmb_pages[j]) != NULL);
                }

                list_add (&fmb->fmb_list, &fmb->fmb_pool->fmp_idle_fmbs);
        }

        PORTAL_ALLOC(ktoenal_data.ksnd_ltxs,
                     sizeof (ksock_ltx_t) * (SOCKNAL_NLTXS + SOCKNAL_NNBLK_LTXS));
        if (ktoenal_data.ksnd_ltxs == NULL)
        {
                ktoenal_module_fini ();
                return (-ENOMEM);
        }

        /* Deterministic bugs please */
        memset (ktoenal_data.ksnd_ltxs, 0xeb,
                sizeof (ksock_ltx_t) * (SOCKNAL_NLTXS + SOCKNAL_NNBLK_LTXS));

        for (i = 0; i < SOCKNAL_NLTXS + SOCKNAL_NNBLK_LTXS; i++)
        {
                ksock_ltx_t *ltx = &((ksock_ltx_t *)ktoenal_data.ksnd_ltxs)[i];

                ltx->ltx_idle = i < SOCKNAL_NLTXS ?
                                &ktoenal_data.ksnd_idle_ltx_list :
                                &ktoenal_data.ksnd_idle_nblk_ltx_list;
                list_add (&ltx->ltx_tx.tx_list, ltx->ltx_idle);
        }

        rc = PtlNIInit(ktoenal_init, 32, 4, 0, &ktoenal_ni);
        if (rc != 0)
        {
                CERROR("ktoenal: PtlNIInit failed: error %d\n", rc);
                ktoenal_module_fini ();
                RETURN (rc);
        }
        PtlNIDebug(ktoenal_ni, ~0);

        ktoenal_data.ksnd_init = SOCKNAL_INIT_PTL; /* flag PtlNIInit() called */

        ktoenal_data.ksnd_slistchange = 1;
        for (i = 0; i < TOENAL_N_SCHED; i++)
        {
                rc = ktoenal_thread_start (ktoenal_scheduler, NULL);
                if (rc != 0)
                {
                        CERROR("Can't spawn socknal scheduler[%d]: %d\n", i, rc);
                        ktoenal_module_fini ();
                        RETURN (rc);
                }
        }

        rc = ktoenal_thread_start (ktoenal_reaper, NULL);
        if (rc != 0)
        {
                CERROR("Can't spawn socknal reaper: %d\n", rc);
                ktoenal_module_fini ();
                RETURN (rc);
        }

        rc = ktoenal_thread_start (ktoenal_pollthread, NULL);
        if (rc != 0)
        {
                CERROR("Can't spawn socknal pollthread: %d\n", rc);
                ktoenal_module_fini ();
                RETURN (rc);
        }

        rc = kpr_register(&ktoenal_data.ksnd_router,
                  &ktoenal_router_interface);
        if (rc != 0)
                CDEBUG (D_NET, "Can't initialise routing interface (rc = %d): not routing\n", rc);

        rc = kportal_nal_register(TOENAL, &ktoenal_cmd, NULL);
        if (rc != 0)
                CDEBUG(D_NET, "Can't initialise command interface (rc = %d)\n",
                       rc);

        PORTAL_SYMBOL_REGISTER(ktoenal_ni);

        /* flag everything initialised */
        ktoenal_data.ksnd_init = SOCKNAL_INIT_ALL;

	printk(KERN_INFO"Routing TOE NAL loaded (Routing %s, initial mem %d)\n",
	       kpr_routing(&ktoenal_data.ksnd_router) ? "enabled" : "disabled",
               pkmem);

        return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel TCP Socket NAL v0.01");
MODULE_LICENSE("GPL");

module_init(ktoenal_module_init);
module_exit(ktoenal_module_fini);

EXPORT_SYMBOL (ktoenal_ni);
