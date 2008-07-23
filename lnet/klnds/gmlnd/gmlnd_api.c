/*
 * -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
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
 *
 * Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

/*
 *	Implements the API NAL functions
 */

#include "gmlnd.h"

lnd_t the_gmlnd =
{
        .lnd_type            = GMLND,
        .lnd_startup         = gmnal_startup,
        .lnd_shutdown        = gmnal_shutdown,
        .lnd_ctl             = gmnal_ctl,
        .lnd_send            = gmnal_send,
        .lnd_recv            = gmnal_recv,
};

gmnal_ni_t *the_gmni = NULL;

int
gmnal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg)
{
        struct libcfs_ioctl_data *data = arg;

        switch (cmd) {
        case IOC_LIBCFS_REGISTER_MYNID:
                if (data->ioc_nid == ni->ni_nid)
                        return 0;

                LASSERT (LNET_NIDNET(data->ioc_nid) == LNET_NIDNET(ni->ni_nid));

                CERROR("obsolete IOC_LIBCFS_REGISTER_MYNID for %s(%s)\n",
                       libcfs_nid2str(data->ioc_nid),
                       libcfs_nid2str(ni->ni_nid));
                return 0;

        default:
                return (-EINVAL);
        }
}

int
gmnal_set_local_nid (gmnal_ni_t *gmni)
{
        lnet_ni_t       *ni = gmni->gmni_ni;
        __u32            local_gmid;
        __u32            global_gmid;
        gm_status_t      gm_status;

        /* Called before anything initialised: no need to lock */
        gm_status = gm_get_node_id(gmni->gmni_port, &local_gmid);
        if (gm_status != GM_SUCCESS)
                return 0;

        CDEBUG(D_NET, "Local node id is [%u]\n", local_gmid);

        gm_status = gm_node_id_to_global_id(gmni->gmni_port, 
                                            local_gmid, 
                                            &global_gmid);
        if (gm_status != GM_SUCCESS)
                return 0;

        CDEBUG(D_NET, "Global node id is [%u]\n", global_gmid);

        ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), global_gmid);
        return 1;
}

void
gmnal_shutdown(lnet_ni_t *ni)
{
        gmnal_ni_t *gmni = ni->ni_data;

        CDEBUG(D_TRACE, "gmnal_api_shutdown: gmni [%p]\n", gmni);

        LASSERT (gmni == the_gmni);

        /* stop processing messages */
        gmnal_stop_threads(gmni);

        /* stop all network callbacks */
        gm_close(gmni->gmni_port);
        gmni->gmni_port = NULL;

        gm_finalize();

        gmnal_free_ltxbufs(gmni);
        gmnal_free_txs(gmni);
        gmnal_free_rxs(gmni);

        LIBCFS_FREE(gmni, sizeof(*gmni));

        the_gmni = NULL;
        PORTAL_MODULE_UNUSE;
}

int
gmnal_startup(lnet_ni_t *ni)
{
        gmnal_ni_t  *gmni = NULL;
        gmnal_rx_t  *rx = NULL;
        gm_status_t  gm_status;
        int          rc;

        LASSERT (ni->ni_lnd == &the_gmlnd);

        ni->ni_maxtxcredits = *gmnal_tunables.gm_credits;
        ni->ni_peertxcredits = *gmnal_tunables.gm_peer_credits;

        if (the_gmni != NULL) {
                CERROR("Only 1 instance supported\n");
                return -EINVAL;
        }

        LIBCFS_ALLOC(gmni, sizeof(*gmni));
        if (gmni == NULL) {
                CERROR("can't allocate gmni\n");
                return -ENOMEM;
        }

        ni->ni_data = gmni;

        memset(gmni, 0, sizeof(*gmni));
        gmni->gmni_ni = ni;
        spin_lock_init(&gmni->gmni_tx_lock);
        spin_lock_init(&gmni->gmni_gm_lock);
        INIT_LIST_HEAD(&gmni->gmni_idle_txs);
        INIT_LIST_HEAD(&gmni->gmni_idle_ltxbs);
        INIT_LIST_HEAD(&gmni->gmni_buf_txq);
        INIT_LIST_HEAD(&gmni->gmni_cred_txq);
        sema_init(&gmni->gmni_rx_mutex, 1);
        PORTAL_MODULE_USE;

        /*
         * initialise the interface,
         */
        CDEBUG(D_NET, "Calling gm_init\n");
        if (gm_init() != GM_SUCCESS) {
                CERROR("call to gm_init failed\n");
                goto failed_0;
        }

        CDEBUG(D_NET, "Calling gm_open with port [%d], version [%d]\n",
               *gmnal_tunables.gm_port, GM_API_VERSION);

        gm_status = gm_open(&gmni->gmni_port, 0, *gmnal_tunables.gm_port, 
                            "gmnal", GM_API_VERSION);

        if (gm_status != GM_SUCCESS) {
                CERROR("Can't open GM port %d: %d (%s)\n",
                       *gmnal_tunables.gm_port, gm_status, 
                       gmnal_gmstatus2str(gm_status));
                goto failed_1;
        }

        CDEBUG(D_NET,"gm_open succeeded port[%p]\n",gmni->gmni_port);

        if (!gmnal_set_local_nid(gmni))
                goto failed_2;

        CDEBUG(D_NET, "portals_nid is %s\n", libcfs_nid2str(ni->ni_nid));

        gmni->gmni_large_msgsize = 
                offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[LNET_MAX_PAYLOAD]);
        gmni->gmni_large_gmsize = 
                gm_min_size_for_length(gmni->gmni_large_msgsize);
        gmni->gmni_large_pages =
                (gmni->gmni_large_msgsize + PAGE_SIZE - 1)/PAGE_SIZE;

        gmni->gmni_small_msgsize = MIN(GM_MTU, PAGE_SIZE);
        gmni->gmni_small_gmsize = 
                gm_min_size_for_length(gmni->gmni_small_msgsize);

        gmni->gmni_netaddr_base = GMNAL_NETADDR_BASE;
        gmni->gmni_netaddr_size = 0;

        CDEBUG(D_NET, "Msg size %08x/%08x [%d/%d]\n", 
               gmni->gmni_large_msgsize, gmni->gmni_small_msgsize,
               gmni->gmni_large_gmsize, gmni->gmni_small_gmsize);

        if (gmnal_alloc_rxs(gmni) != 0) {
                CERROR("Failed to allocate rx descriptors\n");
                goto failed_2;
        }

        if (gmnal_alloc_txs(gmni) != 0) {
                CERROR("Failed to allocate tx descriptors\n");
                goto failed_2;
        }

        if (gmnal_alloc_ltxbufs(gmni) != 0) {
                CERROR("Failed to allocate large tx buffers\n");
                goto failed_2;
        }

        rc = gmnal_start_threads(gmni);
        if (rc != 0) {
                CERROR("Can't start threads: %d\n", rc);
                goto failed_2;
        }

        /* Start listening */
        for (rx = gmni->gmni_rxs; rx != NULL; rx = rx->rx_next)
                gmnal_post_rx(gmni, rx);

        the_gmni = gmni;

        CDEBUG(D_NET, "gmnal_init finished\n");
        return 0;

 failed_2:
        gm_close(gmni->gmni_port);
        gmni->gmni_port = NULL;

 failed_1:
        gm_finalize();

 failed_0:
        /* safe to free descriptors after network has been shut down */
        gmnal_free_ltxbufs(gmni);
        gmnal_free_txs(gmni);
        gmnal_free_rxs(gmni);

        LIBCFS_FREE(gmni, sizeof(*gmni));
        PORTAL_MODULE_UNUSE;

        return -EIO;
}

/* 
 *        Called when module loaded
 */
int gmnal_init(void)
{
        lnet_register_lnd(&the_gmlnd);
        return 0;
}

/*
 *	Called when module removed
 */
void gmnal_fini()
{
        lnet_unregister_lnd(&the_gmlnd);
}
