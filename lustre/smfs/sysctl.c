/*
 *  Sysctrl entries for Snapfs
 */

/* /proc entries */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>

#include "smfs_internal.h" 


#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *proc_smfs_root;
#endif


/* SYSCTL below */

static struct ctl_table_header *smfs_table_header = NULL;
/* 0x100 to avoid any chance of collisions at any point in the tree with
 * non-directories
 */
#define PSDEV_SMFS  (0x130)

#define PSDEV_DEBUG	   1      /* control debugging */
#define PSDEV_TRACE	   2      /* control enter/leave pattern */

/* These are global control options */
#define ENTRY_CNT 3

int sm_print_entry = 1;
int sm_debug_level = 0;

/* XXX - doesn't seem to be working in 2.2.15 */
static struct ctl_table smfs_ctltable[] =
{
	{PSDEV_DEBUG, "debug", &sm_debug_level, sizeof(int), 0644, NULL, &proc_dointvec},
	{PSDEV_TRACE, "trace", &sm_print_entry, sizeof(int), 0644, NULL, &proc_dointvec},
	{0}
};

static ctl_table smfs_table[2] = {
	{PSDEV_SMFS, "smfs",    NULL, 0, 0555, smfs_ctltable},
	{0}
};


int  __init  init_smfs_proc_sys(void)
{
#ifdef CONFIG_PROC_FS
	proc_smfs_root = proc_mkdir("smfs", proc_root_fs);
	if (!proc_smfs_root) {
		printk(KERN_ERR "SMFS: error registering /proc/fs/smfs\n");
		RETURN(-ENOMEM);
	}
	proc_smfs_root->owner = THIS_MODULE;
#endif

#ifdef CONFIG_SYSCTL
	if ( !smfs_table_header )
		smfs_table_header =
			register_sysctl_table(smfs_table, 0);
#endif
	return 0;
}

void cleanup_smfs_proc_sys(void) 
{
#ifdef CONFIG_SYSCTL
	if ( smfs_table_header )
		unregister_sysctl_table(smfs_table_header);
	smfs_table_header = NULL;
#endif
#if CONFIG_PROC_FS
	remove_proc_entry("smfs", proc_root_fs);
#endif
}

