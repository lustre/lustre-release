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
#include <linux/swapctl.h>
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

static int vars[2];
static int index = 0;

static int obd_sctl_vars( ctl_table * table, int write, struct file *
                          filp, void * buffer, size_t * lenp );
static int obd_sctl_reset( ctl_table * table, int write, struct file
                           * filp, void * buffer, size_t * lenp );

#define OBD_SYSCTL 300

#define OBD_FAIL_LOC        1       /* control test failures instrumentation */
#define OBD_ENTRY           2       /* control enter/leave pattern */
#define OBD_VARS            3
#define OBD_INDEX           4
#define OBD_RESET           5
#define OBD_TIMEOUT         6       /* RPC timeout before recovery/intr */
/* XXX move to /proc/sys/lustre/recovery? */
#define OBD_UPCALL          7       /* path to recovery upcall */

#define OBD_VARS_SLOT       2

static ctl_table obd_table[] = {
        {OBD_FAIL_LOC, "fail_loc", &obd_fail_loc, sizeof(int), 0644, NULL, &proc_dointvec},
        {OBD_VARS, "vars", &vars[0], sizeof(int), 0644, NULL, &proc_dointvec},
        {OBD_INDEX, "index", &index, sizeof(int), 0644, NULL, &obd_sctl_vars},
        {OBD_RESET, "reset", NULL, 0, 0644, NULL, &obd_sctl_reset},
        {OBD_TIMEOUT, "timeout", &obd_timeout, sizeof(int), 0644, NULL, &proc_dointvec},
        /* XXX need to lock so we avoid update races with the recovery upcall! */
        {OBD_UPCALL, "recovery_upcall", obd_recovery_upcall, 128, 0644, NULL,
         &proc_dostring, &sysctl_string },
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

int obd_sctl_reset (ctl_table * table, int write, 
                    struct file * filp, void * buffer, 
                    size_t * lenp)
{
        if ( write ) {
                /* do something here */
                vars[0]=0;
                vars[1]=0;
        }

        *lenp = 0;
        return 0;
}

int obd_sctl_vars (ctl_table * table, int write, 
                   struct file * filp, void * buffer, 
                   size_t * lenp)
{
        int rc;

        rc = proc_dointvec(table, write, filp, buffer, lenp);

        if ( rc ) 
                return rc;

        if ( index < 0 || index > 1 ) {
                CERROR("Illegal index %d!\n", index);
                index = 0;
        } else {
                obd_table[OBD_VARS_SLOT].data = &vars[index];
        }

        return rc; 
}
