#define DEBUG_SUBSYSTEM S_SM

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/miscdevice.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_debug.h>
#include <linux/lustre_smfs.h>   

#include "smfs_internal.h" 


struct smfs_control_device smfs_dev;

static int smfs_handle_ioctl(unsigned int cmd, unsigned long arg)
{
        struct obd_ioctl_data *data = NULL;
 	struct super_block *sb = NULL;
	char *buf = NULL, *dir = NULL;
        int err = 0, len = 0, count = 0, do_kml = 0;
      	 
	if (obd_ioctl_getdata(&buf, &len, (void *)arg)) {
                CERROR("OBD ioctl: data error\n");
                GOTO(out, err = -EINVAL);
        }
        data = (struct obd_ioctl_data *)buf;
	
        switch (cmd) {
	case IOC_SMFS_START:
	case IOC_SMFS_STOP:
	case IOC_SMFS_REINT:
	case IOC_SMFS_UNDO:{
		char *name;
		if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
        		CERROR("No mountpoint passed!\n");
                	GOTO(out, err = -EINVAL);
        	}
		name = (char*) data->ioc_inlbuf1;
		sb = smfs_get_sb_by_path(name,  data->ioc_inllen1);
		if (!sb) {
			CERROR("can not find superblock at %s\n", buf);
			GOTO(out, err = -EINVAL);
		}
		/*get cmd count*/
		if (data->ioc_inllen2 && data->ioc_inlbuf2) {
			dir = (char *)data->ioc_inlbuf2;
		}
		if (data->ioc_plen1)
			count = *((int*)data->ioc_pbuf1);	
		if (data->ioc_plen2)
			do_kml = *((int*)data->ioc_pbuf2);	
		break;
	}
	default: {
		CERROR("The command passed in is Invalid\n");
		GOTO(out, err = -EINVAL);
	}	
	}
	
	switch (cmd) {
	case IOC_SMFS_START:
		err = smfs_start_rec(sb);
		break;
	case IOC_SMFS_STOP:
		err = smfs_stop_rec(sb);
		break;
	case IOC_SMFS_REINT: 
	case IOC_SMFS_UNDO: {
		int flags = 0;
		if (cmd == IOC_SMFS_REINT)
			SET_REC_OP_FLAGS(flags, SMFS_REINT_REC);
		else
			SET_REC_OP_FLAGS(flags, SMFS_UNDO_REC);
		if (count == 0)
			SET_REC_COUNT_FLAGS(flags, SMFS_REC_ALL);
		if (do_kml)
			SET_REC_WRITE_KML_FLAGS(flags, SMFS_WRITE_KML);	
		err = smfs_process_rec(sb, count, dir, flags);
		break;
	}
	}			
out:
	if (buf)
		obd_ioctl_freedata(buf, len);
	RETURN(err);
}
static int smfs_psdev_ioctl (struct inode * inode, struct file * filp, 
		       unsigned int cmd, unsigned long arg)
{
	int rc = 0;
	rc = smfs_handle_ioctl(cmd, arg);	
	RETURN(rc);	
}

/* called when opening /dev/device */
static int smfs_psdev_open(struct inode * inode, struct file * file)
{
	int dev;
        ENTRY;

	if (!inode)
		RETURN(-EINVAL);
	dev = MINOR(inode->i_rdev);
	if (dev != SMFS_PSDEV_MINOR)
		RETURN(-ENODEV);

        RETURN(0);
}

/* called when closing /dev/device */
static int smfs_psdev_release(struct inode * inode, struct file * file)
{
	int dev;
        ENTRY;

	if (!inode)
		RETURN(-EINVAL);
	dev = MINOR(inode->i_rdev);
	if (dev != SMFS_PSDEV_MINOR)
		RETURN(-ENODEV);

        RETURN(0);
}

/* declare character device */
static struct file_operations smfscontrol_fops = {
	ioctl:		smfs_psdev_ioctl,            /* ioctl */
	open:		smfs_psdev_open,       /* open */
	release:	smfs_psdev_release,    /* release */
};

#define SMFS_MINOR 250
static struct miscdevice smfscontrol_dev = {
	minor:	SMFS_MINOR,
	name:	"smfscontrol",
	fops:	&smfscontrol_fops
};

int init_smfs_psdev(void)
{
	printk(KERN_INFO "SMFS psdev driver  v0.01, braam@clusterfs.com\n");
	
	misc_register(&smfscontrol_dev);

	return 0;
}

void smfs_cleanup_psdev(void)
{
        ENTRY;
	misc_deregister(&smfscontrol_dev);
	EXIT;
}
