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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>

#include <portals/lib-p30.h>
#include <portals/p30.h>
#include <portals/nal.h>
#include <linux/kp30.h>
#include <linux/kpr.h>
#include <linux/portals_compat25.h>

extern void (kping_client)(struct portal_ioctl_data *);

static int kportal_ioctl(struct portal_ioctl_data *data, 
                         unsigned int cmd, unsigned long arg)
{
        int err;
        char str[PTL_NALFMT_SIZE];
        ENTRY;

        switch (cmd) {
        case IOC_PORTAL_PING: {
                void (*ping)(struct portal_ioctl_data *);

                CDEBUG(D_IOCTL, "doing %d pings to nid "LPX64" (%s)\n",
                       data->ioc_count, data->ioc_nid,
                       portals_nid2str(data->ioc_nal, data->ioc_nid, str));
                ping = PORTAL_SYMBOL_GET(kping_client);
                if (!ping)
                        CERROR("PORTAL_SYMBOL_GET failed\n");
                else {
                        ping(data);
                        PORTAL_SYMBOL_PUT(kping_client);
                }
                RETURN(0);
        }

        case IOC_PORTAL_GET_NID: {
                ptl_handle_ni_t    nih;
                ptl_process_id_t   pid;

                CDEBUG (D_IOCTL, "Getting nid for nal [%d]\n", data->ioc_nal);

                err = PtlNIInit(data->ioc_nal, 0, NULL, NULL, &nih);
                if (!(err == PTL_OK || err == PTL_IFACE_DUP))
                        RETURN (-EINVAL);

                err = PtlGetId (nih, &pid);
                LASSERT (err == PTL_OK);

                PtlNIFini(nih);

                data->ioc_nid = pid.nid;
                if (copy_to_user ((char *)arg, data, sizeof (*data)))
                        RETURN (-EFAULT);
                RETURN(0);
        }

        case IOC_PORTAL_FAIL_NID: {
                ptl_handle_ni_t    nih;

                CDEBUG (D_IOCTL, "fail nid: [%d] "LPU64" count %d\n",
                        data->ioc_nal, data->ioc_nid, data->ioc_count);

                err = PtlNIInit(data->ioc_nal, 0, NULL, NULL, &nih);
                if (!(err == PTL_OK || err == PTL_IFACE_DUP))
                        return (-EINVAL);

                if (err == PTL_OK) {
                        /* There's no point in failing an interface that
                         * came into existance just for this */
                        err = -EINVAL;
                } else {
                        err = PtlFailNid (nih, data->ioc_nid, data->ioc_count);
                        if (err != PTL_OK)
                                err = -EINVAL;
                }

                PtlNIFini(nih);
                RETURN (err);
        }
        default:
                RETURN(-EINVAL);
        }
        /* Not Reached */
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
EXPORT_SYMBOL(lib_dispatch);
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
EXPORT_SYMBOL(lib_iov_nob);
EXPORT_SYMBOL(lib_copy_iov2buf);
EXPORT_SYMBOL(lib_copy_buf2iov);
EXPORT_SYMBOL(lib_extract_iov);
EXPORT_SYMBOL(lib_kiov_nob);
EXPORT_SYMBOL(lib_copy_kiov2buf);
EXPORT_SYMBOL(lib_copy_buf2kiov);
EXPORT_SYMBOL(lib_extract_kiov);
EXPORT_SYMBOL(lib_finalize);
EXPORT_SYMBOL(lib_parse);
EXPORT_SYMBOL(lib_create_reply_msg);
EXPORT_SYMBOL(lib_init);
EXPORT_SYMBOL(lib_fini);
EXPORT_SYMBOL(dispatch_name);

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Portals v3.1");
MODULE_LICENSE("GPL");
module_init(init_kportals_module);
module_exit(exit_kportals_module);
