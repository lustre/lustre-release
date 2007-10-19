/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
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

#include <obd_support.h>
#include <lprocfs_status.h>

cfs_sysctl_table_header_t *obd_table_header = NULL;

#define OBD_SYSCTL 300

enum {
        OBD_FAIL_LOC = 1,       /* control test failures instrumentation */
        OBD_FAIL_VAL,           /* userdata for fail loc */
        OBD_TIMEOUT,            /* RPC timeout before recovery/intr */
        OBD_DUMP_ON_TIMEOUT,    /* dump kernel debug log upon eviction */
        OBD_MEMUSED,            /* bytes currently OBD_ALLOCated */
        OBD_SYNCFILTER,         /* XXX temporary, as we play with sync osts.. */
        OBD_LDLM_TIMEOUT,       /* LDLM timeout for ASTs before client eviction */
        OBD_DUMP_ON_EVICTION,   /* dump kernel debug log upon eviction */
        OBD_DEBUG_PEER_ON_TIMEOUT, /* dump peer debug when RPC times out */
        OBD_ALLOC_FAIL_RATE,    /* memory allocation random failure rate */
        ADAPTIVE_MAX,           /* Adaptive timeout upper limit */
        ADAPTIVE_HISTORY,       /* Adaptive timeout timebase */
};

int LL_PROC_PROTO(proc_fail_loc)
{
        int rc;
        int old_fail_loc = obd_fail_loc;

        rc = ll_proc_dointvec(table, write, filp, buffer, lenp, ppos);
        if (old_fail_loc != obd_fail_loc)
                wake_up(&obd_race_waitq);
        return rc;
}

int LL_PROC_PROTO(proc_set_timeout)
{
        int rc;

        rc = ll_proc_dointvec(table, write, filp, buffer, lenp, ppos);
        if (ldlm_timeout >= obd_timeout)
                ldlm_timeout = max(obd_timeout / 3, 1U);
        return rc;
}

#ifdef RANDOM_FAIL_ALLOC
int LL_PROC_PROTO(proc_alloc_fail_rate)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
        loff_t *ppos = &filp->f_pos;
#endif
        int rc = 0;

        if (!table->data || !table->maxlen || !*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write) {
                rc = lprocfs_write_frac_helper(buffer, *lenp, 
                                               (unsigned int*)table->data,
                                               OBD_ALLOC_FAIL_MULT);
        } else {
                char buf[21];
                int  len;

                len = lprocfs_read_frac_helper(buf, 21,
                                               *(unsigned int*)table->data,
                                               OBD_ALLOC_FAIL_MULT);
                if (len > *lenp)
                        len = *lenp;
                buf[len] = '\0';
                if (copy_to_user(buffer, buf, len))
                        return -EFAULT;
                *lenp = len;
        }
        *ppos += *lenp;
        return rc;
}
#endif

static cfs_sysctl_table_t obd_table[] = {
        {
                .ctl_name = OBD_FAIL_LOC,
                .procname = "fail_loc",
                .data     = &obd_fail_loc,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_fail_loc
        },
        {
                .ctl_name = OBD_FAIL_VAL,
                .procname = "fail_val",
                .data     = &obd_fail_val,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = OBD_TIMEOUT,
                .procname = "timeout",
                .data     = &obd_timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_set_timeout
        },
        {
                .ctl_name = OBD_DEBUG_PEER_ON_TIMEOUT,
                .procname = "debug_peer_on_timeout",
                .data     = &obd_debug_peer_on_timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = OBD_DUMP_ON_TIMEOUT,
                .procname = "dump_on_timeout",
                .data     = &obd_dump_on_timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = OBD_DUMP_ON_EVICTION,
                .procname = "dump_on_eviction",
                .data     = &obd_dump_on_eviction,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = OBD_MEMUSED,
                .procname = "memused",
                .data     = (int *)&obd_memory.counter,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = OBD_LDLM_TIMEOUT,
                .procname = "ldlm_timeout",
                .data     = &ldlm_timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_set_timeout
        },
#ifdef RANDOM_FAIL_ALLOC
        {
                .ctl_name = OBD_ALLOC_FAIL_RATE,
                .procname = "alloc_fail_rate",
                .data     = &obd_alloc_fail_rate,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_alloc_fail_rate
        },
#endif
        {
                .ctl_name = ADAPTIVE_MAX,
                .procname = "adaptive_max",
                .data     = &adaptive_timeout_max,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = ADAPTIVE_HISTORY,
                .procname = "adaptive_history",
                .data     = &adaptive_timeout_history,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        { 0 }
};

static cfs_sysctl_table_t parent_table[] = {
       {
               .ctl_name = OBD_SYSCTL,
               .procname = "lustre",
               .data     = NULL,
               .maxlen   = 0,
               .mode     = 0555,
               .child    = obd_table
       },
       {0}
};

void obd_sysctl_init (void)
{
#ifdef CONFIG_SYSCTL
        if ( !obd_table_header )
                obd_table_header = cfs_register_sysctl_table(parent_table, 0);
#endif
}

void obd_sysctl_clean (void)
{
#ifdef CONFIG_SYSCTL
        if ( obd_table_header )
                cfs_unregister_sysctl_table(obd_table_header);
        obd_table_header = NULL;
#endif
}
