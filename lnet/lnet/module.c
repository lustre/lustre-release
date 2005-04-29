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

static int kportal_ioctl(unsigned int cmd, struct portal_ioctl_data *data)
{
        int                rc;
        ptl_handle_ni_t    nih;

        rc = PtlNIInit(PTL_IFACE_DEFAULT, LUSTRE_SRV_PTL_PID, 
                       NULL, NULL, &nih);
        if (!(rc == PTL_OK || rc == PTL_IFACE_DUP))
                RETURN (-EINVAL);

        rc = PtlNICtl(nih, cmd, data);

        PtlNIFini(nih);
        return rc;
}

DECLARE_IOCTL_HANDLER(kportal_ioctl_handler, kportal_ioctl);
extern struct semaphore ptl_mutex;

static int init_kportals_module(void)
{
        int rc;
        ENTRY;

        init_mutex(&ptl_mutex);
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

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Portals v3.1");
MODULE_LICENSE("GPL");

cfs_module(portals, "1.0.0", init_kportals_module, exit_kportals_module);
