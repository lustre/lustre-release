/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */
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

struct ctl_table_header *ll_table_header = NULL;

int ll_debug_level = 0;
int ll_print_entry = 1;


#define LL_SYSCTL 1

#define LL_DEBUG  	    1  	    /* control debugging */
#define LL_ENTRY	    2       /* control enter/leave pattern */
#define LL_TIMEOUT         3       /* timeout on upcalls to become intrble */
#define LL_HARD            4       /* mount type "hard" or "soft" */
#define LL_VARS            5       
#define LL_INDEX           6
#define LL_RESET           7

#define LL_VARS_SLOT       2

static ctl_table ll_table[] = {
	{LL_DEBUG, "debug", &ll_debug_level, sizeof(int), 0644, NULL, &proc_dointvec},
	{LL_ENTRY, "trace", &ll_print_entry, sizeof(int), 0644, NULL, &proc_dointvec},
	{ 0 }
};

static ctl_table top_table[] = {
       {LL_SYSCTL, "lustre_light",    NULL, 0, 0555, ll_table},
       {0}
};

void ll_sysctl_init (void)
{

#ifdef CONFIG_SYSCTL
	if ( !ll_table_header )
		ll_table_header = register_sysctl_table(top_table, 0); 
#endif
}

void ll_sysctl_clean (void)
{
#ifdef CONFIG_SYSCTL
	if ( ll_table_header )
		unregister_sysctl_table(ll_table_header);
	ll_table_header = NULL;
#endif
}
