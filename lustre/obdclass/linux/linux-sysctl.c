/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
        OBD_PAGESUSED,          /* pages currently OBD_PAGE_ALLOCated */
        OBD_MAXMEMUSED,         /* maximum bytes OBD_ALLOCated concurrently */
        OBD_MAXPAGESUSED,       /* maximum pages OBD_PAGE_ALLOCated concurrently */
        OBD_SYNCFILTER,         /* XXX temporary, as we play with sync osts.. */
        OBD_LDLM_TIMEOUT,       /* LDLM timeout for ASTs before client eviction */
        OBD_DUMP_ON_EVICTION,   /* dump kernel debug log upon eviction */
        OBD_DEBUG_PEER_ON_TIMEOUT, /* dump peer debug when RPC times out */
        OBD_ALLOC_FAIL_RATE,    /* memory allocation random failure rate */
        OBD_MAX_DIRTY_PAGES,    /* maximum dirty pages */
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

int LL_PROC_PROTO(proc_max_dirty_pages_in_mb)
{
        int rc = 0;
        DECLARE_LL_PROC_PPOS_DECL;

        if (!table->data || !table->maxlen || !*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write) {
                rc = lprocfs_write_frac_helper(buffer, *lenp,
                                               (unsigned int*)table->data,
                                               1 << (20 - CFS_PAGE_SHIFT));
                /* Don't allow them to let dirty pages exceed 90% of system memory,
                 * and set a hard minimum of 4MB. */
                if (obd_max_dirty_pages > ((num_physpages / 10) * 9)) {
                        CERROR("Refusing to set max dirty pages to %u, which "
                               "is more than 90%% of available RAM; setting to %lu\n",
                               obd_max_dirty_pages, ((num_physpages / 10) * 9));
                        obd_max_dirty_pages = ((num_physpages / 10) * 9);
                } else if (obd_max_dirty_pages < 4 << (20 - CFS_PAGE_SHIFT)) {
                        obd_max_dirty_pages = 4 << (20 - CFS_PAGE_SHIFT);
                }
        } else {
                char buf[21];
                int len;

                len = lprocfs_read_frac_helper(buf, sizeof(buf),
                                               *(unsigned int*)table->data,
                                               1 << (20 - CFS_PAGE_SHIFT));
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

#ifdef RANDOM_FAIL_ALLOC
int LL_PROC_PROTO(proc_alloc_fail_rate)
{
        int rc = 0;
        DECLARE_LL_PROC_PPOS_DECL;

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

                len = lprocfs_read_frac_helper(buf, sizeof(buf),
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

int LL_PROC_PROTO(proc_memory_alloc)
{
        char buf[22];
        int len;
        DECLARE_LL_PROC_PPOS_DECL;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write)
                return -EINVAL;

        len = snprintf(buf, sizeof(buf), LPU64"\n", obd_memory_sum());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
        if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}

int LL_PROC_PROTO(proc_pages_alloc)
{
        char buf[22];
        int len;
        DECLARE_LL_PROC_PPOS_DECL;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write)
                return -EINVAL;

        len = snprintf(buf, sizeof(buf), LPU64"\n", obd_pages_sum());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
        if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}

int LL_PROC_PROTO(proc_mem_max)
{
        char buf[22];
        int len;
        DECLARE_LL_PROC_PPOS_DECL;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write)
                return -EINVAL;

        len = snprintf(buf, sizeof(buf), LPU64"\n", obd_memory_max());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
        if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}

int LL_PROC_PROTO(proc_pages_max)
{
        char buf[22];
        int len;
        DECLARE_LL_PROC_PPOS_DECL;

        if (!*lenp || (*ppos && !write)) {
                *lenp = 0;
                return 0;
        }
        if (write)
                return -EINVAL;

        len = snprintf(buf, sizeof(buf), LPU64"\n", obd_pages_max());
        if (len > *lenp)
                len = *lenp;
        buf[len] = '\0';
        if (copy_to_user(buffer, buf, len))
                return -EFAULT;
        *lenp = len;
        *ppos += *lenp;
        return 0;
}

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
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0444,
                .proc_handler = &proc_memory_alloc
        },
        {
                .ctl_name = OBD_PAGESUSED,
                .procname = "pagesused",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0444,
                .proc_handler = &proc_pages_alloc
        },
        {
                .ctl_name = OBD_MAXMEMUSED,
                .procname = "memused_max",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0444,
                .proc_handler = &proc_mem_max
        },
        {
                .ctl_name = OBD_MAXPAGESUSED,
                .procname = "pagesused_max",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0444,
                .proc_handler = &proc_pages_max
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
                .ctl_name = OBD_MAX_DIRTY_PAGES,
                .procname = "max_dirty_mb",
                .data     = &obd_max_dirty_pages,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_max_dirty_pages_in_mb
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
