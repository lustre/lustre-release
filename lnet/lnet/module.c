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
#include <lnet/lib-lnet.h>

static int config_on_load = 0;
CFS_MODULE_PARM(config_on_load, "i", int, 0444,
                "configure network at module load");

static int kportal_ioctl(unsigned int cmd, struct portal_ioctl_data *data)
{
        int                initrc;
        int                rc;

        if (cmd == IOC_PORTAL_UNCONFIGURE) {
                /* ghastly hack to prevent repeated net config */
                PTL_MUTEX_DOWN(&lnet_apini.apini_api_mutex);
                initrc = lnet_apini.apini_niinit_self;
                lnet_apini.apini_niinit_self = 0;
                rc = lnet_apini.apini_refcount;
                PTL_MUTEX_UP(&lnet_apini.apini_api_mutex);

                if (initrc) {
                        rc--;
                        LNetNIFini();
                }
                
                return rc == 0 ? 0 : -EBUSY;
        }
        
        initrc = LNetNIInit(LUSTRE_SRV_PTL_PID);
        if (initrc < 0)
                RETURN (-ENETDOWN);

        rc = LNetCtl(cmd, data);

        if (initrc == 0) {
                PTL_MUTEX_DOWN(&lnet_apini.apini_api_mutex);
                /* I instantiated the network */
                lnet_apini.apini_niinit_self = 1;
                PTL_MUTEX_UP(&lnet_apini.apini_api_mutex);
        } else {
                LNetNIFini();
        }
        
        return rc;
}

DECLARE_IOCTL_HANDLER(kportal_ioctl_handler, kportal_ioctl);

static int init_kportals_module(void)
{
        int rc;
        ENTRY;

        rc = LNetInit();
        if (rc != 0) {
                CERROR("LNetInit: error %d\n", rc);
                RETURN(rc);
        }

        if (config_on_load) {
                PTL_MUTEX_DOWN(&lnet_apini.apini_api_mutex);
                lnet_apini.apini_niinit_self = 1;
                PTL_MUTEX_UP(&lnet_apini.apini_api_mutex);

                rc = LNetNIInit(LUSTRE_SRV_PTL_PID);
                if (rc != 0) {
                        /* Can't LNetFini or fail now if I loaded NALs */
                        PTL_MUTEX_DOWN(&lnet_apini.apini_api_mutex);
                        lnet_apini.apini_niinit_self = 0;
                        PTL_MUTEX_UP(&lnet_apini.apini_api_mutex);
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

        LNetFini();
}

EXPORT_SYMBOL(lnet_register_nal);
EXPORT_SYMBOL(lnet_unregister_nal);

EXPORT_SYMBOL(LNetMEAttach);
EXPORT_SYMBOL(LNetMEInsert);
EXPORT_SYMBOL(LNetMEUnlink);
EXPORT_SYMBOL(LNetEQAlloc);
EXPORT_SYMBOL(LNetMDAttach);
EXPORT_SYMBOL(LNetMDUnlink);
EXPORT_SYMBOL(LNetNIInit);
EXPORT_SYMBOL(LNetNIFini);
EXPORT_SYMBOL(LNetInit);
EXPORT_SYMBOL(LNetFini);
EXPORT_SYMBOL(LNetSnprintHandle);
EXPORT_SYMBOL(LNetPut);
EXPORT_SYMBOL(LNetGet);
EXPORT_SYMBOL(LNetEQWait);
EXPORT_SYMBOL(LNetEQFree);
EXPORT_SYMBOL(LNetEQGet);
EXPORT_SYMBOL(LNetGetId);
EXPORT_SYMBOL(LNetMDBind);
EXPORT_SYMBOL(LNetDist);
EXPORT_SYMBOL(lnet_apini);
EXPORT_SYMBOL(lnet_iov_nob);
EXPORT_SYMBOL(lnet_copy_iov2buf);
EXPORT_SYMBOL(lnet_copy_buf2iov);
EXPORT_SYMBOL(lnet_extract_iov);
EXPORT_SYMBOL(lnet_kiov_nob);
EXPORT_SYMBOL(lnet_copy_kiov2buf);
EXPORT_SYMBOL(lnet_copy_buf2kiov);
EXPORT_SYMBOL(lnet_extract_kiov);
EXPORT_SYMBOL(lnet_finalize);
EXPORT_SYMBOL(lnet_parse);
EXPORT_SYMBOL(lnet_create_reply_msg);
EXPORT_SYMBOL(lnet_net2ni);
EXPORT_SYMBOL(lnet_getpid);

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Portals v3.1");
MODULE_LICENSE("GPL");

cfs_module(portals, "1.0.0", init_kportals_module, exit_kportals_module);
