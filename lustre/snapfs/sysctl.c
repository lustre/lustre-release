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
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>

#include "snapfs_internal.h" 


#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *proc_snapfs_root;
#endif


/* SYSCTL below */

static struct ctl_table_header *snapfs_table_header = NULL;
/* 0x100 to avoid any chance of collisions at any point in the tree with
 * non-directories
 */
#define PSDEV_SNAPFS  (0x120)

#define PSDEV_DEBUG	   1      /* control debugging */
#define PSDEV_TRACE	   2      /* control enter/leave pattern */

/* These are global control options */
#define ENTRY_CNT 3

/* XXX - doesn't seem to be working in 2.2.15 */
static struct ctl_table snapfs_ctltable[] =
{
#ifdef SNAP_DEBUG
	{PSDEV_DEBUG, "debug", &snap_debug_level, sizeof(int), 0644, NULL, &proc_dointvec},
#endif
	{PSDEV_TRACE, "trace", &snap_print_entry, sizeof(int), 0644, NULL, &proc_dointvec},
	{0}
};

static ctl_table snapfs_table[2] = {
	{PSDEV_SNAPFS, "snapfs",    NULL, 0, 0555, snapfs_ctltable},
	{0}
};


int  __init  init_snapfs_proc_sys(void)
{
#ifdef CONFIG_PROC_FS
	proc_snapfs_root = proc_mkdir("snapfs", proc_root_fs);
	if (!proc_snapfs_root) {
		printk(KERN_ERR "SNAPFS: error registering /proc/fs/snapfs\n");
		RETURN(-ENOMEM);
	}
	proc_snapfs_root->owner = THIS_MODULE;
#endif

#ifdef CONFIG_SYSCTL
	if ( !snapfs_table_header )
		snapfs_table_header =
			register_sysctl_table(snapfs_table, 0);
#endif
	return 0;
}

void cleanup_snapfs_proc_sys(void) 
{
#ifdef CONFIG_SYSCTL
	if ( snapfs_table_header )
		unregister_sysctl_table(snapfs_table_header);
	snapfs_table_header = NULL;
#endif
#if CONFIG_PROC_FS
	remove_proc_entry("snapfs", proc_root_fs);
#endif

}

