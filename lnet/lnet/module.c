/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_PORTALS
#include <portals/lib-p30.h>

static int config_on_load = 1;
CFS_MODULE_PARM(config_on_load, "i", int, 0444,
                "configure network at module load");

static int kportal_ioctl(unsigned int cmd, struct portal_ioctl_data *data)
{
        ptl_err_t          initrc;
        int                rc;
        ptl_handle_ni_t    nih;

        if (cmd == IOC_PORTAL_UNCONFIGURE) {
                /* ghastly hack to prevent repeated net config */
                PTL_MUTEX_DOWN(&ptl_apini.apini_api_mutex);
                initrc = ptl_apini.apini_niinit_self;
                ptl_apini.apini_niinit_self = 0;
                rc = ptl_apini.apini_refcount;
                PTL_MUTEX_UP(&ptl_apini.apini_api_mutex);

                if (initrc) {
                        rc--;
                        PtlNIFini((ptl_handle_ni_t){0});
                }
                
                return rc == 0 ? 0 : -EBUSY;
        }
        
        initrc = PtlNIInit(PTL_IFACE_DEFAULT, LUSTRE_SRV_PTL_PID, 
                           NULL, NULL, &nih);
        if (!(initrc == PTL_OK || initrc == PTL_IFACE_DUP))
                RETURN (-ENETDOWN);

        rc = PtlNICtl(nih, cmd, data);

        if (initrc == PTL_OK) {
                PTL_MUTEX_DOWN(&ptl_apini.apini_api_mutex);
                /* I instantiated the network */
                ptl_apini.apini_niinit_self = 1;
                PTL_MUTEX_UP(&ptl_apini.apini_api_mutex);
        } else {
                PtlNIFini(nih);
        }
        
        return rc;
}

DECLARE_IOCTL_HANDLER(kportal_ioctl_handler, kportal_ioctl);

static int init_kportals_module(void)
{
        int rc;
        ENTRY;

        rc = PtlInit(NULL);
        if (rc) {
                CERROR("PtlInit: error %d\n", rc);
                RETURN(rc);
        }

        if (config_on_load) {
                ptl_handle_ni_t    nih;

                PTL_MUTEX_DOWN(&ptl_apini.apini_api_mutex);
                ptl_apini.apini_niinit_self = 1;
                PTL_MUTEX_UP(&ptl_apini.apini_api_mutex);

                rc = PtlNIInit(PTL_IFACE_DEFAULT, LUSTRE_SRV_PTL_PID,
                               NULL, NULL, &nih);
                if (rc != PTL_OK) {
                        PtlFini();
                        return -ENETDOWN;
                }
        }
        
        rc = libcfs_register_ioctl(&kportal_ioctl_handler);
        LASSERT (rc == 0);

        RETURN(rc);
}

static void exit_kportals_module(void)
{
        int rc;

        rc = libcfs_deregister_ioctl(&kportal_ioctl_handler);
        LASSERT (rc == 0);

        PtlFini();
}

EXPORT_SYMBOL(ptl_register_nal);
EXPORT_SYMBOL(ptl_unregister_nal);

EXPORT_SYMBOL(ptl_err_str);
EXPORT_SYMBOL(PtlMEAttach);
EXPORT_SYMBOL(PtlMEInsert);
EXPORT_SYMBOL(PtlMEUnlink);
EXPORT_SYMBOL(PtlEQAlloc);
EXPORT_SYMBOL(PtlMDAttach);
EXPORT_SYMBOL(PtlMDUnlink);
EXPORT_SYMBOL(PtlNIInit);
EXPORT_SYMBOL(PtlNIFini);
EXPORT_SYMBOL(PtlInit);
EXPORT_SYMBOL(PtlFini);
EXPORT_SYMBOL(PtlSnprintHandle);
EXPORT_SYMBOL(PtlPut);
EXPORT_SYMBOL(PtlGet);
EXPORT_SYMBOL(PtlEQWait);
EXPORT_SYMBOL(PtlEQFree);
EXPORT_SYMBOL(PtlEQGet);
EXPORT_SYMBOL(PtlGetId);
EXPORT_SYMBOL(PtlMDBind);
EXPORT_SYMBOL(ptl_iov_nob);
EXPORT_SYMBOL(ptl_copy_iov2buf);
EXPORT_SYMBOL(ptl_copy_buf2iov);
EXPORT_SYMBOL(ptl_extract_iov);
EXPORT_SYMBOL(ptl_kiov_nob);
EXPORT_SYMBOL(ptl_copy_kiov2buf);
EXPORT_SYMBOL(ptl_copy_buf2kiov);
EXPORT_SYMBOL(ptl_extract_kiov);
EXPORT_SYMBOL(ptl_finalize);
EXPORT_SYMBOL(ptl_parse);
EXPORT_SYMBOL(ptl_create_reply_msg);
EXPORT_SYMBOL(ptl_net2ni);
EXPORT_SYMBOL(ptl_queue_zombie_ni);

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Portals v3.1");
MODULE_LICENSE("GPL");

cfs_module(portals, "1.0.0", init_kportals_module, exit_kportals_module);
