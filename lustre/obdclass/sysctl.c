/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
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

#define OBD_DEBUG           1       /* control debugging */
#define OBD_ENTRY           2       /* control enter/leave pattern */
#define OBD_TIMEOUT         3       /* timeout on upcalls to become intrble */
#define OBD_HARD            4       /* mount type "hard" or "soft" */
#define OBD_VARS            5       
#define OBD_INDEX           6
#define OBD_RESET           7

#define OBD_VARS_SLOT       2

static ctl_table obd_table[] = {
        {OBD_DEBUG, "debug", &obd_debug_level, sizeof(int), 0644, NULL, &proc_dointvec},
        {OBD_VARS, "vars", &vars[0], sizeof(int), 0644, NULL, &proc_dointvec},
        {OBD_INDEX, "index", &index, sizeof(int), 0644, NULL, &obd_sctl_vars},
        {OBD_RESET, "reset", NULL, 0, 0644, NULL, &obd_sctl_reset},
	{ 0 }
};

static ctl_table parent_table[] = {
       {OBD_SYSCTL, "obd",    NULL, 0, 0555, obd_table},
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
