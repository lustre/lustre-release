/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Based on ksocknal and qswnal
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Robert Read  <rread@datarithm.net>
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

#include "gmnal.h"

ptl_handle_ni_t kgmnal_ni;
nal_t  kgmnal_api;

kgmnal_data_t kgmnal_data;
int gmnal_debug = 0;

kpr_nal_interface_t kqswnal_router_interface = {
        kprni_nalid:        GMNAL,
        kprni_arg:        NULL,
        kprni_fwd:          kgmnal_fwd_packet,
};

static int kgmnal_forward(nal_t   *nal,
                          int     id,
                          void    *args,  size_t args_len,
                          void    *ret,   size_t ret_len)
{
        kgmnal_data_t *k = nal->nal_data;
        nal_cb_t      *nal_cb = k->kgm_cb;

        LASSERT (nal == &kgmnal_api);
        LASSERT (k == &kgmnal_data);
        LASSERT (nal_cb == &kgmnal_lib);

        lib_dispatch(nal_cb, k, id, args, ret); /* nal needs k */
        return PTL_OK;
}

static void kgmnal_lock(nal_t *nal, unsigned long *flags)
{
        kgmnal_data_t *k = nal->nal_data;
        nal_cb_t      *nal_cb = k->kgm_cb;


        LASSERT (nal == &kgmnal_api);
        LASSERT (k == &kgmnal_data);
        LASSERT (nal_cb == &kgmnal_lib);

        nal_cb->cb_cli(nal_cb,flags);
}

static void kgmnal_unlock(nal_t *nal, unsigned long *flags)
{
        kgmnal_data_t *k = nal->nal_data;
        nal_cb_t      *nal_cb = k->kgm_cb;


        LASSERT (nal == &kgmnal_api);
        LASSERT (k == &kgmnal_data);
        LASSERT (nal_cb == &kgmnal_lib);

        nal_cb->cb_sti(nal_cb,flags);
}

static int kgmnal_shutdown(nal_t *nal, int ni)
{
        LASSERT (nal == &kgmnal_api);
        return 0;
}

static void kgmnal_yield( nal_t *nal )
{
        LASSERT (nal == &kgmnal_api);

        if (current->need_resched)
                schedule();
        return;
}

kgmnal_rx_t *kgm_add_recv(kgmnal_data_t *data,int ndx)
{
        kgmnal_rx_t *conn;

        PORTAL_ALLOC(conn, sizeof(kgmnal_rx_t));
        /* Check for out of mem here */
        if (conn==NULL) {
                        printk("kgm_add_recv: memory alloc failed\n");
                        return NULL;
        }

        list_add(&conn->krx_item,(struct list_head *)&data->kgm_list);
        //        conn->ndx=ndx;
        //        conn->len=conn->ptlhdr_copied=0;
        //        conn->loopback=0;
        return conn;
}

static nal_t *kgmnal_init(int interface, ptl_pt_index_t ptl_size,
                          ptl_ac_index_t  ac_size, ptl_pid_t requested_pid)
{
        unsigned int nnids;

        gm_max_node_id_in_use(kgmnal_data.kgm_port, &nnids);

        CDEBUG(D_NET, "calling lib_init with nid 0x%Lx of %d\n",
               kgmnal_data.kgm_nid, nnids);
        lib_init(&kgmnal_lib, kgmnal_data.kgm_nid, 0, nnids,ptl_size, ac_size);
        return &kgmnal_api;
}

static void /*__exit*/
kgmnal_finalize(void)
{
        struct list_head *tmp;

        PORTAL_SYMBOL_UNREGISTER (kgmnal_ni);
        PtlNIFini(kgmnal_ni);
        lib_fini(&kgmnal_api);

        if (kgmnal_data.kgm_port) {
                gm_close(kgmnal_data.kgm_port);
        }

        /* FIXME: free dma buffers */
        /* FIXME: kill receiver thread */

        PORTAL_FREE (kgmnal_data.kgm_trans, bsizeof(kgmnal_tx_t)*TXMSGS);

        list_for_each(tmp, &kgmnal_data.kgm_list) {
                kgmnal_rx_t *conn;
                conn = list_entry(tmp, kgmnal_rx_t, krx_item);
                CDEBUG(D_IOCTL, "freeing conn %p\n",conn);
                tmp = tmp->next;
                list_del(&conn->krx_item);
                PORTAL_FREE(conn, sizeof(*conn));
        }

        CDEBUG (D_MALLOC, "done kmem %d\n", atomic_read (&portal_kmemory));

        return;
}

static int __init
kgmnal_initialize(void)
{
        int rc;
        int ntok;
        unsigned long sizemask;
        unsigned int nid;

        CDEBUG (D_MALLOC, "start kmem %d\n", atomic_read (&portal_kmemory));

        kgmnal_api.forward = kgmnal_forward;
        kgmnal_api.shutdown = kgmnal_shutdown;
        kgmnal_api.yield = kgmnal_yield;
        kgmnal_api.validate = NULL;         /* our api validate is a NOOP */
        kgmnal_api.lock= kgmnal_lock;
        kgmnal_api.unlock= kgmnal_unlock;
        kgmnal_api.nal_data = &kgmnal_data;

        kgmnal_lib.nal_data = &kgmnal_data;

        memset(&kgmnal_data, 0, sizeof(kgmnal_data));

        INIT_LIST_HEAD(&kgmnal_data.kgm_list);
        kgmnal_data.kgm_cb = &kgmnal_lib;

        /* Allocate transmit descriptors */
        PORTAL_ALLOC (kgmnal_data.kgm_trans, sizeof(kgmnal_tx_t)*TXMSGS);
        if (kgmnal_data.kgm_trans==NULL) {
                printk("kgmnal: init: failed to allocate transmit "
                       "descriptors\n");
                return -1;
        }
        memset(kgmnal_data.kgm_trans,-1,sizeof(kgmnal_tx_t)*(TXMSGS));

        spin_lock_init(&kgmnal_data.kgm_dispatch_lock);
        spin_lock_init(&kgmnal_data.kgm_update_lock);
        spin_lock_init(&kgmnal_data.kgm_send_lock);

        /* Do the receiver and xmtr allocation */

        rc = gm_init();
        if (rc != GM_SUCCESS) {
                CERROR("gm_init failed: %d\n", rc);
                return -1;
        }

        rc = gm_open(&kgmnal_data.kgm_port, 0 , KGM_PORT_NUM, KGM_HOSTNAME,
                     GM_API_VERSION_1_1);
        if (rc != GM_SUCCESS) {
                gm_finalize();
                kgmnal_data.kgm_port = NULL;
                CERROR("gm_open failed: %d\n", rc);
                return -1;
        }
        gm_get_node_id(kgmnal_data.kgm_port, &nid);
        kgmnal_data.kgm_nid = nid;
        /* Allocate 2 different sizes of buffers. For new, use half
           the tokens for each. */
        ntok = gm_num_receive_tokens(kgmnal_data.kgm_port)/2;
        CDEBUG(D_NET, "gmnal_init: creating %d large %d byte recv buffers\n",
               ntok, MSG_LEN_LARGE);
        while (ntok-- > 0) {
                void * buffer = gm_dma_malloc(kgmnal_data.kgm_port,
                                              MSG_LEN_LARGE);
                if (buffer == NULL) {
                        CERROR("gm_init failed: %d\n", rc);
                        return (-ENOMEM);
                }
                CDEBUG(D_NET, " add buffer: port %p buf %p len %d size %d "
                       "pri %d\n ", kgmnal_data.kgm_port, buffer,
                       MSG_LEN_LARGE, MSG_SIZE_LARGE, GM_LOW_PRIORITY);

                gm_provide_receive_buffer(kgmnal_data.kgm_port, buffer,
                                          MSG_SIZE_LARGE, GM_LOW_PRIORITY);
        }

        ntok = gm_num_receive_tokens(kgmnal_data.kgm_port)/2;
        CDEBUG(D_NET, "gmnal_init: creating %d small %d byte recv buffers\n",
               ntok, MSG_LEN_SMALL);
        while (ntok-- > 0) {
                void * buffer = gm_dma_malloc(kgmnal_data.kgm_port,
                                              MSG_LEN_SMALL);
                if (buffer == NULL) {
                        CERROR("gm_init failed: %d\n", rc);
                        return (-ENOMEM);
                }
                CDEBUG(D_NET, " add buffer: port %p buf %p len %d size %d "
                       "pri %d\n ", kgmnal_data.kgm_port, buffer,
                       MSG_LEN_SMALL, MSG_SIZE_SMALL, GM_LOW_PRIORITY);

                gm_provide_receive_buffer(kgmnal_data.kgm_port, buffer,
                                          MSG_SIZE_SMALL, GM_LOW_PRIORITY);

        }
        sizemask = (1 << MSG_SIZE_LARGE) | (1 << MSG_SIZE_SMALL);
        CDEBUG(D_NET, "gm_set_acceptable_sizes port %p pri %d mask 0x%x\n",
                        kgmnal_data.kgm_port, GM_LOW_PRIORITY, sizemask);
        gm_set_acceptable_sizes(kgmnal_data.kgm_port, GM_LOW_PRIORITY,
                                sizemask);
        gm_set_acceptable_sizes(kgmnal_data.kgm_port, GM_HIGH_PRIORITY, 0);

        /* Initialize Network Interface */
        rc = PtlNIInit(kgmnal_init, 32, 4, 0, &kgmnal_ni);
        if (rc) {
                CERROR("PtlNIInit failed %d\n", rc);
                return (-ENOMEM);
        }

        /* Start receiver thread */
        kernel_thread(kgmnal_recv_thread, &kgmnal_data, 0);

        PORTAL_SYMBOL_REGISTER(kgmnal_ni);

        kgmnal_data.kgm_init = 1;

        return 0;
}

MODULE_AUTHOR("Robert Read <rread@datarithm.net>");
MODULE_DESCRIPTION("Kernel Myrinet GM NAL v0.1");
MODULE_LICENSE("GPL");

module_init (kgmnal_initialize);
module_exit (kgmnal_finalize);

EXPORT_SYMBOL (kgmnal_ni);
