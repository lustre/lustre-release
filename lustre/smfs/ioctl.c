/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/ioctl.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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
 */
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
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_debug.h>
#include <linux/lustre_smfs.h>
#include <linux/lustre_snap.h>

#include "smfs_internal.h"

static struct super_block *smfs_get_sb_by_path(char *path, int len)
{
        struct super_block *sb;
        struct nameidata nd;

        ENTRY;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (path_init(path, LOOKUP_FOLLOW, &nd)) {
                int error = 0;
                error = path_walk(path, &nd);
                if (error) {
                        path_release(&nd);
                        RETURN(NULL);
                }
        } else {
                RETURN(NULL);
        }
#else
        if (path_lookup(path, LOOKUP_FOLLOW, &nd))
                RETURN(NULL); 
        
#endif
        /* FIXME-WANGDI: add some check code here. */
        sb = nd.dentry->d_sb;
        path_release(&nd);
        RETURN(sb);
}

struct smfs_control_device smfs_dev;

static int smfs_handle_ioctl(unsigned int cmd, unsigned long arg)
{
        struct obd_ioctl_data *data = NULL;
         struct super_block *sb = NULL;
        char *buf = NULL;
        int err = 0, len = 0;

        if (obd_ioctl_getdata(&buf, &len, (void *)arg)) {
                CERROR("OBD ioctl: data error\n");
                GOTO(out, err = -EINVAL);
        }
        data = (struct obd_ioctl_data *)buf;

        switch (cmd) {
        case OBD_IOC_SMFS_SNAP_ADD:{
                char *name, *snapshot_name;
                if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
                        CERROR("No mountpoint passed!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (!data->ioc_inllen2 || !data->ioc_inlbuf2) {
                        CERROR("No snapshotname passed!\n");
                        GOTO(out, err = -EINVAL);
                }
                name = (char*) data->ioc_inlbuf1;
                sb = smfs_get_sb_by_path(name,  data->ioc_inllen1);
                if (!sb) {
                        CERROR("can not find superblock at %s\n", buf);
                        GOTO(out, err = -EINVAL);
                }
                snapshot_name = (char *)data->ioc_inlbuf2;
#ifdef CONFIG_SNAPFS
                err = smfs_add_snap_item(sb, name, snapshot_name);
#endif         
                break;
        }
        default: {
                CERROR("The command passed in is Invalid\n");
                GOTO(out, err = -EINVAL);
        }
        }
out:
        if (buf)
                obd_ioctl_freedata(buf, len);
        RETURN(err);
}
#define SMFS_MINOR 250
static int smfs_psdev_ioctl(struct inode * inode, struct file * filp,
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
        if (dev != SMFS_MINOR)
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
        if (dev != SMFS_MINOR)
                RETURN(-ENODEV);

        RETURN(0);
}

/* declare character device */
static struct file_operations smfscontrol_fops = {
        .owner   = THIS_MODULE,
        .ioctl   = smfs_psdev_ioctl,            /* ioctl */
        .open    = smfs_psdev_open,       /* open */
        .release = smfs_psdev_release,    /* release */
};
static struct miscdevice smfscontrol_dev = {
        minor:        SMFS_MINOR,
        name:        "smfscontrol",
        fops:        &smfscontrol_fops
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
