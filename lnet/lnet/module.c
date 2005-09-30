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
#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/lib-lnet.h>

static int config_on_load = 1;
CFS_MODULE_PARM(config_on_load, "i", int, 0444,
                "configure network at module load");

static int lnet_ioctl(unsigned int cmd, struct libcfs_ioctl_data *data)
{
        int                initrc;
        int                rc;

        if (cmd == IOC_LIBCFS_UNCONFIGURE) {
                /* ghastly hack to prevent repeated net config */
                LNET_MUTEX_DOWN(&the_lnet.ln_api_mutex);
                initrc = the_lnet.ln_niinit_self;
                the_lnet.ln_niinit_self = 0;
                rc = the_lnet.ln_refcount;
                LNET_MUTEX_UP(&the_lnet.ln_api_mutex);

                if (initrc) {
                        rc--;
                        LNetNIFini();
                }
                
                return rc == 0 ? 0 : -EBUSY;
        }
        
        initrc = LNetNIInit(LUSTRE_SRV_LNET_PID);
        if (initrc < 0)
                RETURN (-ENETDOWN);

        rc = LNetCtl(cmd, data);

        if (initrc == 0) {
                LNET_MUTEX_DOWN(&the_lnet.ln_api_mutex);
                /* I instantiated the network */
                the_lnet.ln_niinit_self = 1;
                LNET_MUTEX_UP(&the_lnet.ln_api_mutex);
        } else {
                LNetNIFini();
        }
        
        return rc;
}

DECLARE_IOCTL_HANDLER(lnet_ioctl_handler, lnet_ioctl);

void
lnet_configure (void *arg)
{
        int    rc;

        LNET_MUTEX_DOWN(&the_lnet.ln_api_mutex);
        the_lnet.ln_niinit_self = 1;
        LNET_MUTEX_UP(&the_lnet.ln_api_mutex);

        rc = LNetNIInit(LUSTRE_SRV_LNET_PID);
        if (rc != 0) {
                LNET_MUTEX_DOWN(&the_lnet.ln_api_mutex);
                the_lnet.ln_niinit_self = 0;
                LNET_MUTEX_UP(&the_lnet.ln_api_mutex);
        }
}

static int init_lnet(void)
{
        static work_struct_t work;
        int                  rc;
        ENTRY;

        rc = LNetInit();
        if (rc != 0) {
                CERROR("LNetInit: error %d\n", rc);
                RETURN(rc);
        }

        rc = libcfs_register_ioctl(&lnet_ioctl_handler);
        LASSERT (rc == 0);

        if (config_on_load) {
                /* Have to schedule a task to avoid deadlocking modload */
                prepare_work(&work, lnet_configure, NULL);
                schedule_work(&work);
        }

        RETURN(0);
}

static void fini_lnet(void)
{
        int rc;

        rc = libcfs_deregister_ioctl(&lnet_ioctl_handler);
        LASSERT (rc == 0);

        LNetFini();
}

EXPORT_SYMBOL(lnet_register_lnd);
EXPORT_SYMBOL(lnet_unregister_lnd);

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
EXPORT_SYMBOL(LNetCtl);
EXPORT_SYMBOL(the_lnet);
EXPORT_SYMBOL(lnet_iov_nob);
EXPORT_SYMBOL(lnet_extract_iov);
EXPORT_SYMBOL(lnet_kiov_nob);
EXPORT_SYMBOL(lnet_extract_kiov);
EXPORT_SYMBOL(lnet_copy_iov2iov);
EXPORT_SYMBOL(lnet_copy_iov2kiov);
EXPORT_SYMBOL(lnet_copy_kiov2iov);
EXPORT_SYMBOL(lnet_copy_kiov2kiov);
EXPORT_SYMBOL(lnet_finalize);
EXPORT_SYMBOL(lnet_parse);
EXPORT_SYMBOL(lnet_create_reply_msg);
EXPORT_SYMBOL(lnet_net2ni);

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Portals v3.1");
MODULE_LICENSE("GPL");

cfs_module(portals, "1.0.0", init_lnet, fini_lnet);
