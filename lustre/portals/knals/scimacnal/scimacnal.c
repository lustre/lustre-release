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

nal_t  kscimacnal_api;

kscimacnal_data_t kscimacnal_data;

kpr_nal_interface_t kscimacnal_router_interface = {
        kprni_nalid:    SCIMACNAL,
        kprni_arg:      NULL,
        kprni_fwd:      kscimacnal_fwd_packet,
};


int kscimacnal_cmd (struct portal_ioctl_data *data, void *private)
{
        LASSERT (data != NULL);

        switch (data->ioc_nal_cmd) {
                case NAL_CMD_REGISTER_MYNID:
                        if(kscimacnal_lib.ni.nid == data->ioc_nid) {
                                break;
                        }
                        CDEBUG (D_IOCTL, "Can't change NID from "LPX64" to "LPX64")\n", kscimacnal_lib.ni.nid, data->ioc_nid);
                        return(-EINVAL);
                default:
                        return(-EINVAL);
        }

        return(0);
}

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


static void kscimacnal_shutdown(nal_t *nal, int ni)
{
        LASSERT (nal == &kscimacnal_api);
        LASSERT (kscimacnal_data.ksci_init);

        if (nal->nal_refct != 0)
                return;

        /* Called on last matching PtlNIFini() */

        /* FIXME: How should the shutdown procedure really look? 
         */
        kscimacnal_data.ksci_shuttingdown=1;

        /* Stop handling ioctls */
        libcfs_nal_cmd_unregister(SCIMACNAL);

        mac_finish(kscimacnal_data.ksci_machandle);

        /* finalise lib after net shuts up */
        lib_fini(&kscimacnal_lib);

        kscimacnal_data.ksci_init = 0;

        /* Allow unload */
        PORTAL_MODULE_UNUSE;

        return;
}


static void kscimacnal_yield( nal_t *nal, unsigned long *flags, int milliseconds )
{
        LASSERT (nal == &kscimacnal_api);

        if (milliseconds != 0) {
                CERROR ("Blocking yield not implemented yet\n");
                LBUG();
        }

        if (current->need_resched) 
                schedule();
        return;
}


static int kscimacnal_startup(nal_t *nal, ptl_pid_t requested_pid,
                              ptl_ni_limits_t *requested_limits,
                              ptl_ni_limits_t *actual_limits)
{
        int rc;
        mac_physaddr_t   mac_physaddr;
        ptl_process_id_t process_id;
        mac_handle_t    *machandle = NULL;

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL)
                        *actual_limits = kscimacnal_lib.ni.actual_limits;
                return (PTL_OK);
        }

        /* Called on first PtlNIInit(SCIMACNAL) */

        LASSERT (nal == kscimacnal_api);
        LASSERT (!kscimacnal_data.ksci_init);
        
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
                return PTL_FAIL;
        }

        kscimacnal_data.ksci_machandle = machandle;

        /* Make sure the scimac MTU is tuned */
        if(mac_get_mtusize(machandle) < SCIMACNAL_MTU) {
                CERROR("scimac mtu of %ld smaller than SCIMACNAL MTU of %d\n",
                                mac_get_mtusize(machandle), SCIMACNAL_MTU);
                CERROR("Consult README.scimacnal for more information\n");
                mac_finish(machandle);
                return PTL_FAIL;
        }

        /* Get the node ID */
        /* mac_get_physaddrlen() is a function instead of define, sigh */
        LASSERT(mac_get_physaddrlen(machandle) <= sizeof(mac_physaddr));
        if(mac_get_physaddr(machandle, &mac_physaddr)) {
                CERROR("mac_get_physaddr() failed\n");
                mac_finish(machandle);
                return PTL_FAIL;
        }
        kscimacnal_data.ksci_nid = (ptl_nid_t)(ntohl(mac_physaddr));

        process_id.pid = 0;
        process_id.nid = kscimacnal_data.ksci_nid;

        CDEBUG(D_NET, "calling lib_init with nid "LPX64"\n",
               kscimacnal_data.ksci_nid);

        rc = lib_init(&kscimacnal_lib, process_id,
                      requested_limits, actual_limits);
        if (rc != PTL_OK) {
                CERROR("PtlNIInit failed %d\n", rc);
                mac_finish(machandle);
                return (rc);
        }

        /* Init command interface */
        rc = libcfs_nal_cmd_register (SCIMACNAL, &kscimacnal_cmd, NULL);
        if (rc != 0) {
                CERROR ("Can't initialise command interface (rc = %d)\n", rc);
                lib_fini(&kscimacnal_lib);
                mac_finish(machandle);
                return (PTL_FAIL);
        }

        /* We're done now, it's OK for the RX callback to do stuff */
        kscimacnal_data.ksci_init = 1;

        /* Prevent unload before matching PtlNIFini() */
        PORTAL_MODULE_USE;
        
        return (PTL_OK);
}


/* Called by kernel at module unload time */
static void /*__exit*/ 
kscimacnal_finalize(void)
{
        LASSERT (!kscimacnal_data.ksci_init);
        
        ptl_unregister_nal(SCIMACNAL);

        CDEBUG (D_MALLOC, "done kmem %d\n", atomic_read (&portal_kmemory));

        return;
}


/* Called by kernel at module insertion time */
static int __init
kscimacnal_initialize(void)
{
        int rc;

        CDEBUG (D_MALLOC, "start kmem %d\n", atomic_read (&portal_kmemory));

        kscimacnal_api.startup = kscimacnal_startup;
        kscimacnal_api.forward = kscimacnal_forward;
        kscimacnal_api.shutdown = kscimacnal_shutdown;
        kscimacnal_api.yield = kscimacnal_yield;
        kscimacnal_api.lock= kscimacnal_lock;
        kscimacnal_api.unlock= kscimacnal_unlock;
        kscimacnal_api.nal_data = &kscimacnal_data;

        rc = ptl_register_nal(SCIMACNAL, &kscimacnal_api);
        if (rc != PTL_OK) {
                CERROR("Can't register SCIMACNAL: %d\n", rc);
                return (-ENODEV);
        }
        
        return 0;
}


MODULE_AUTHOR("Niklas Edmundsson <nikke@hpc2n.umu.se>");
MODULE_DESCRIPTION("Kernel Scali ScaMAC SCI NAL v0.1");
MODULE_LICENSE("GPL");

module_init (kscimacnal_initialize);
module_exit (kscimacnal_finalize);

EXPORT_SYMBOL(kscimacnal_ni);
