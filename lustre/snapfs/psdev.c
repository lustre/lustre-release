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


#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/miscdevice.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>

#include "snapfs_internal.h" 


int snap_inodes = 0;
long snap_kmemory = 0;
int snap_stack = 0;
struct snap_control_device snap_dev;

extern int snap_ioctl (struct inode * inode, struct file * filp, 
		       unsigned int cmd, unsigned long arg);

/* called when opening /dev/device */
static int snap_psdev_open(struct inode * inode, struct file * file)
{
	int dev;
        ENTRY;

	if (!inode)
		RETURN(-EINVAL);
	dev = MINOR(inode->i_rdev);
	if (dev != SNAP_PSDEV_MINOR)
		RETURN(-ENODEV);

        RETURN(0);
}

/* called when closing /dev/device */
static int snap_psdev_release(struct inode * inode, struct file * file)
{
	int dev;
        ENTRY;

	if (!inode)
		RETURN(-EINVAL);
	dev = MINOR(inode->i_rdev);
	if (dev != SNAP_PSDEV_MINOR)
		RETURN(-ENODEV);

        RETURN(0);
}

/* XXX need ioctls here to do snap_delete and snap_restore, snap_backup */


/* declare character device */
static struct file_operations snapcontrol_fops = {
	ioctl:		snap_ioctl,            /* ioctl */
	open:		snap_psdev_open,       /* open */
	release:	snap_psdev_release,    /* release */
};



#define SNAPFS_MINOR 240

static struct miscdevice snapcontrol_dev = {
	minor:	SNAPFS_MINOR,
	name:	"snapcontrol",
	fops:	&snapcontrol_fops
};

int init_snap_psdev(void)
{
	printk(KERN_INFO "SNAP psdev driver  v0.01, braam@clusterfs.com\n");
	
	misc_register( &snapcontrol_dev );

	return 0;
}

void snap_cleanup_psdev(void)
{
        ENTRY;
	misc_deregister(&snapcontrol_dev);
	EXIT;
}

MODULE_AUTHOR("Peter J. Braam <braam@cs.cmu.edu>");
MODULE_DESCRIPTION("Snapfs file system filters v0.01");

extern int init_snapfs(void);
extern int cleanup_snapfs(void);
extern int init_clonefs(void);
extern int init_snap_sysctl(void); 

static int __init snapfs_init(void)
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

static void __exit snapfs_cleanup(void)
{

	cleanup_snapfs();
	snap_cleanup_psdev();
	
}
module_init(snapfs_init);
module_exit(snapfs_cleanup);
                                                                                                                                                                                                     

