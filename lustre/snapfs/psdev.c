/*
 *              A file system filter driver in the style of InterMezzo
 *              to manage file system snapshots
 *
 * 		Author:  Peter J. Braam <braam@mountainviewdata.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define EXPORT_SYMTAB

#include <linux/config.h> /* for CONFIG_PROC_FS */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
/* #include <linux/kmod.h>    for request_module() */
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/malloc.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

#if 1 /* XXX - enable for debug messages */
int snap_print_entry = 1;
int snap_debug_level = ~D_INFO;
#else
int snap_print_entry = 0;
int snap_debug_level = 0;
#endif
int snap_inodes = 0;
long snap_memory = 0;

struct snap_control_device snap_dev;

extern int snap_ioctl (struct inode * inode, struct file * filp, 
		       unsigned int cmd, unsigned long arg);

/* called when opening /dev/device */
static int snap_psdev_open(struct inode * inode, struct file * file)
{
	int dev;
        ENTRY;

	if (!inode)
		return -EINVAL;
	dev = MINOR(inode->i_rdev);
	if (dev != SNAP_PSDEV_MINOR)
		return -ENODEV;

        MOD_INC_USE_COUNT;
        EXIT;
        return 0;
}

/* called when closing /dev/device */
static int snap_psdev_release(struct inode * inode, struct file * file)
{
	int dev;
        ENTRY;

	if (!inode)
		return -EINVAL;
	dev = MINOR(inode->i_rdev);
	if (dev != SNAP_PSDEV_MINOR)
		return -ENODEV;

        MOD_DEC_USE_COUNT;

        EXIT;
        return 0;
}

/* XXX need ioctls here to do snap_delete and snap_restore, snap_backup */


/* declare character device */
static struct file_operations snapcontrol_fops = {
	NULL,                  /* llseek */
	NULL,                  /* read */
	NULL,                  /* write */
	NULL,		       /* presto_psdev_readdir */
        NULL,                  /* poll */
	snap_ioctl,            /* ioctl */
	NULL,		       /* presto_psdev_mmap */
	snap_psdev_open,       /* open */
	NULL,
	snap_psdev_release,    /* release */
	NULL,                  /* fsync */
	NULL,                  /* fasync */
	NULL                   /* lock */
};



#define SNAPFS_MINOR 240

static struct miscdevice snapcontrol_dev = {
	SNAPFS_MINOR,
	"snapcontrol",
	&snapcontrol_fops
};

int init_snap_psdev(void)
{
	printk(KERN_INFO "SNAP psdev driver  v0.01, braam@mountainviewdata.com\n");
	
	misc_register( &snapcontrol_dev );

	return 0;
}

void snap_cleanup_psdev(void)
{
        ENTRY;
	misc_deregister(&snapcontrol_dev);
	EXIT;
}

#ifdef MODULE
MODULE_AUTHOR("Peter J. Braam <braam@cs.cmu.edu>");
MODULE_DESCRIPTION("Snapfs file system filters v0.01");

extern int init_snapfs(void);
extern int cleanup_snapfs(void);
extern int init_clonefs(void);
extern int init_snap_sysctl(void); 

int init_module(void)
{
	int err;
	if ( (err = init_snap_psdev()) ) {
		printk("Error initializing snap_psdev, %d\n", err);
		return -EINVAL;
	}

	if ( (err = init_snapfs()) ) {
		printk("Error initializing snapfs, %d\n", err);
		return -EINVAL;
	}

	if ( (err = init_snapfs_proc_sys()) ) {
		printk("Error initializing snapfs proc sys, %d\n", err);
		return -EINVAL;
	}


	return 0;
}

void cleanup_module(void)
{

	cleanup_snapfs();
	snap_cleanup_psdev();
	
}
#endif

