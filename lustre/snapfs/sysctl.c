/*
 *  Sysctrl entries for Snapfs
 */

#define __NO_VERSION__
#include <linux/config.h> /* for CONFIG_PROC_FS */
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/swapctl.h>
#include <linux/proc_fs.h>
#include <linux/malloc.h>
#include <linux/vmalloc.h>
#include <linux/stat.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <asm/bitops.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/utsname.h>
#include <linux/blk.h>
 
#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>


/* /proc entries */

#ifdef CONFIG_PROC_FS


static void snapfs_proc_modcount(struct inode *inode, int fill)
{
	if (fill)
		MOD_INC_USE_COUNT;
	else
		MOD_DEC_USE_COUNT;
}

struct proc_dir_entry proc_fs_snapfs = {
	0, 10, "snapfs",
	S_IFDIR | S_IRUGO | S_IXUGO, 2, 0, 0,
	0, &proc_dir_inode_operations,
	NULL, NULL,
	NULL,
	NULL, NULL
};


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
static struct ctl_table snapfs_ctltable[ENTRY_CNT] =
{
	{PSDEV_DEBUG, "debug", &snap_debug_level, sizeof(int), 0644, NULL, &proc_dointvec},
	{PSDEV_TRACE, "trace", &snap_print_entry, sizeof(int), 0644, NULL, &proc_dointvec},
	{0}
};

static ctl_table snapfs_table[2] = {
	{PSDEV_SNAPFS, "snapfs",    NULL, 0, 0555, snapfs_ctltable},
	{0}
};


int /* __init */ init_snapfs_proc_sys(void)
{

#ifdef CONFIG_SYSCTL
	if ( !snapfs_table_header )
		snapfs_table_header =
			register_sysctl_table(snapfs_table, 0);
#endif
#ifdef CONFIG_PROC_FS
	proc_register(&proc_root_fs, &proc_fs_snapfs);
	proc_fs_snapfs.fill_inode = &snapfs_proc_modcount;
#endif
	return 0;
}

void cleanup_snapfs_proc_sys(void) {

#ifdef CONFIG_SYSCTL
	if ( snapfs_table_header )
		unregister_sysctl_table(snapfs_table_header);
	snapfs_table_header = NULL;
#endif

#if CONFIG_PROC_FS
	proc_unregister(&proc_root_fs, proc_fs_snapfs.low_ino);
#endif
}

