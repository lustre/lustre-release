/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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
 *
 */

#include <linux/module.h>
#include <linux/autoconf.h>
#include <linux/sysctl.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/swapctl.h>
#endif
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/ctype.h>
#include <asm/bitops.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/utsname.h>

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_support.h>

struct ctl_table_header *obd_table_header = NULL;

#define OBD_SYSCTL 300

enum {
        OBD_FAIL_LOC = 1,       /* control test failures instrumentation */
        OBD_TIMEOUT,            /* RPC timeout before recovery/intr */
        OBD_UPCALL,             /* path to recovery upcall */
        OBD_SYNCFILTER,         /* XXX temporary, as we play with sync osts.. */
};

int proc_fail_loc(ctl_table *table, int write, struct file *filp,
                  void *buffer, size_t *lenp);

static ctl_table obd_table[] = {
        {OBD_FAIL_LOC, "fail_loc", &obd_fail_loc, sizeof(int), 0644, NULL,
                &proc_dointvec},
        {OBD_TIMEOUT, "timeout", &obd_timeout, sizeof(int), 0644, NULL,
                &proc_fail_loc},
        /* XXX need to lock so we avoid update races with recovery upcall! */
        {OBD_UPCALL, "upcall", obd_lustre_upcall, 128, 0644, NULL,
                &proc_dostring, &sysctl_string },
        {OBD_SYNCFILTER, "filter_sync_on_commit", &obd_sync_filter, sizeof(int),
                0644, NULL, &proc_dointvec},
        { 0 }
};

static ctl_table parent_table[] = {
       {OBD_SYSCTL, "lustre", NULL, 0, 0555, obd_table},
       {0}
};

void obd_sysctl_init (void)
{
#ifdef CONFIG_SYSCTL
        if ( !obd_table_header )
                obd_table_header = register_sysctl_table(parent_table, 0);
#endif
}

void obd_sysctl_clean (void)
{
#ifdef CONFIG_SYSCTL
        if ( obd_table_header )
                unregister_sysctl_table(obd_table_header);
        obd_table_header = NULL;
#endif
}

int proc_fail_loc(ctl_table *table, int write, struct file *filp,
                  void *buffer, size_t *lenp)
{
        int rc;
        int old_fail_loc = obd_fail_loc;

        rc = proc_dointvec(table,write,filp,buffer,lenp);
        if (old_fail_loc != obd_fail_loc)
                wake_up(&obd_race_waitq);
        return rc;
}
