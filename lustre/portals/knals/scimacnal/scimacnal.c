/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:cindent:
 *
 * Copyright (C) 2003 High Performance Computing Center North (HPC2N)
 *   Author: Niklas Edmundsson <nikke@hpc2n.umu.se>

 * Based on gmnal, which is based on ksocknal and qswnal
 *
 * This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 * Portals is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Portals is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#include "scimacnal.h"

ptl_handle_ni_t kscimacnal_ni;
nal_t  kscimacnal_api;

kscimacnal_data_t kscimacnal_data;

kpr_nal_interface_t kscimacnal_router_interface = {
        kprni_nalid:    SCIMACNAL,
        kprni_arg:      NULL,
        kprni_fwd:      kscimacnal_fwd_packet,
};


static int kscimacnal_forward(nal_t   *nal,
                          int     id,
                          void    *args,  size_t args_len,
                          void    *ret,   size_t ret_len)
{
        kscimacnal_data_t *ksci = nal->nal_data;
        nal_cb_t      *nal_cb = ksci->ksci_cb;

        LASSERT (nal == &kscimacnal_api);
        LASSERT (ksci == &kscimacnal_data);
        LASSERT (nal_cb == &kscimacnal_lib);

        lib_dispatch(nal_cb, ksci, id, args, ret); /* nal needs ksci */
        return PTL_OK;
}


static void kscimacnal_lock(nal_t *nal, unsigned long *flags)
{
        kscimacnal_data_t *ksci = nal->nal_data;
        nal_cb_t      *nal_cb = ksci->ksci_cb;


        LASSERT (nal == &kscimacnal_api);
        LASSERT (ksci == &kscimacnal_data);
        LASSERT (nal_cb == &kscimacnal_lib);

        nal_cb->cb_cli(nal_cb,flags);
}


static void kscimacnal_unlock(nal_t *nal, unsigned long *flags)
{
        kscimacnal_data_t *ksci = nal->nal_data;
        nal_cb_t      *nal_cb = ksci->ksci_cb;


        LASSERT (nal == &kscimacnal_api);
        LASSERT (ksci == &kscimacnal_data);
        LASSERT (nal_cb == &kscimacnal_lib);

        nal_cb->cb_sti(nal_cb,flags);
}


static int kscimacnal_shutdown(nal_t *nal, int ni)
{
        LASSERT (nal == &kscimacnal_api);
        return 0;
}


static void kscimacnal_yield( nal_t *nal )
{
        LASSERT (nal == &kscimacnal_api);

        if (current->need_resched) 
                schedule();
        return;
}


static nal_t *kscimacnal_init(int interface, ptl_pt_index_t  ptl_size,
                ptl_ac_index_t  ac_size, ptl_pid_t requested_pid)
{
        int     nnids = 512; /* FIXME: Need ScaMac funktion to get #nodes */

        CDEBUG(D_NET, "calling lib_init with nid 0x%Lx nnids %d\n", kscimacnal_data.ksci_nid, nnids);
        lib_init(&kscimacnal_lib, kscimacnal_data.ksci_nid, 0, nnids,ptl_size, ac_size); 
        return &kscimacnal_api;
}


/* Called by kernel at module unload time */
static void __exit 
kscimacnal_finalize(void)
{
        /* FIXME: How should the shutdown procedure really look? */
        kscimacnal_data.ksci_shuttingdown=1;

        PORTAL_SYMBOL_UNREGISTER(kscimacnal_ni);

        PtlNIFini(kscimacnal_ni);
        lib_fini(&kscimacnal_lib);

        mac_finish(kscimacnal_data.ksci_machandle);

        CDEBUG (D_MALLOC, "done kmem %d\n", atomic_read (&portal_kmemory));

        return;
}


/* Called by kernel at module insertion time */
static int __init
kscimacnal_initialize(void)
{
        int rc;
        unsigned long     nid=0;
        mac_handle_t    *machandle = NULL;


        CDEBUG (D_MALLOC, "start kmem %d\n", atomic_read (&portal_kmemory));

        kscimacnal_api.forward = kscimacnal_forward;
        kscimacnal_api.shutdown = kscimacnal_shutdown;
        kscimacnal_api.yield = kscimacnal_yield;
        kscimacnal_api.validate = NULL;         /* our api validate is a NOOP */
        kscimacnal_api.lock= kscimacnal_lock;
        kscimacnal_api.unlock= kscimacnal_unlock;
        kscimacnal_api.nal_data = &kscimacnal_data;

        kscimacnal_lib.nal_data = &kscimacnal_data;

        memset(&kscimacnal_data, 0, sizeof(kscimacnal_data));

        kscimacnal_data.ksci_cb = &kscimacnal_lib;

        /* We're not using this, but cli/sti callbacks does... ??? */
        spin_lock_init(&kscimacnal_data.ksci_dispatch_lock);

        /* FIXME: We only support one adapter for now */
        machandle = mac_init(0, MAC_SAPID_LUSTRE, kscimacnal_rx,
                        &kscimacnal_data);

        if(!machandle) {
                CERROR("mac_init() failed\n");
                return -1;
        }

        kscimacnal_data.ksci_machandle = machandle;

        /* Make sure the scimac MTU is tuned */
        if(mac_get_mtusize(machandle) < SCIMACNAL_MTU) {
                CERROR("scimac mtu of %ld smaller than SCIMACNAL MTU of %d\n",
                                mac_get_mtusize(machandle), SCIMACNAL_MTU);
                CERROR("Consult README.scimacnal for more information\n");
                mac_finish(machandle);
                return -1;
        }

        /* Get the node ID */
        /* mac_get_physaddrlen() is a function instead of define, sigh */
        LASSERT(mac_get_physaddrlen(machandle) <= sizeof(nid));
        if(mac_get_physaddr(machandle, (mac_physaddr_t *) &nid)) {
                CERROR("mac_get_physaddr() failed\n");
                mac_finish(machandle);
                return -1;
        }
        nid = ntohl(nid);
        kscimacnal_data.ksci_nid = nid;


        /* Initialize Network Interface */
        /* FIXME: What do the magic numbers mean? Documentation anyone? */
        rc = PtlNIInit(kscimacnal_init, 32, 4, 0, &kscimacnal_ni);
        if (rc) {
                CERROR("PtlNIInit failed %d\n", rc);
                mac_finish(machandle);
                return (-ENOMEM);
        }

        PORTAL_SYMBOL_REGISTER(kscimacnal_ni);

        /* We're done now, it's OK for the RX callback to do stuff */
        kscimacnal_data.ksci_init = 1;

        return 0;
}


MODULE_AUTHOR("Niklas Edmundsson <nikke@hpc2n.umu.se>");
MODULE_DESCRIPTION("Kernel Scali ScaMAC SCI NAL v0.0");
MODULE_LICENSE("GPL");

module_init (kscimacnal_initialize);
module_exit (kscimacnal_finalize);

EXPORT_SYMBOL(kscimacnal_ni);
