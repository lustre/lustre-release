#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/swapctl.h>
#include <linux/proc_fs.h>
#include <linux/malloc.h>
#include <linux/stat.h>
#include <linux/ctype.h>
#include <asm/bitops.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/utsname.h>

#include <linux/sim_obd.h>
#include <linux/presto.h>
#include <linux/obd_psdev.h>
#include <linux/presto_upcall.h>

struct ctl_table_header *obdfs_table_header = NULL;

int obdfs_debug_level = 4095;
int obdfs_print_entry = 1;


#define OBDFS_SYSCTL 1

#define OBDFS_DEBUG  	    1  	    /* control debugging */
#define OBDFS_ENTRY	    2       /* control enter/leave pattern */
#define OBDFS_TIMEOUT         3       /* timeout on upcalls to become intrble */
#define OBDFS_HARD            4       /* mount type "hard" or "soft" */
#define OBDFS_VARS            5       
#define OBDFS_INDEX           6
#define OBDFS_RESET           7

#define OBDFS_VARS_SLOT       2

static ctl_table obdfs_table[] = {
	{OBDFS_DEBUG, "debug", &obdfs_debug_level, sizeof(int), 0644, NULL, &proc_dointvec},
	{OBDFS_ENTRY, "trace", &obdfs_print_entry, sizeof(int), 0644, NULL, &proc_dointvec},
	{ 0 }
};

static ctl_table jukebox_table[] = {
       {OBDFS_SYSCTL, "obdfs",    NULL, 0, 0555, obdfs_table},
       {0}
};

void obdfs_sysctl_init (void)
{
#ifdef CONFIG_SYSCTL
	if ( !obdfs_table_header )
		obdfs_table_header = register_sysctl_table(jukebox_table, 0); 
#endif
}

void obdfs_sysctl_clean (void)
{
#ifdef CONFIG_SYSCTL
	if ( obdfs_table_header )
		unregister_sysctl_table(obdfs_table_header);
	obdfs_table_header = NULL;
#endif
}
