/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/symlink.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>

#include "smfs_internal.h"

static int smfs_readlink(struct dentry *dentry, char *buffer, int buflen)
{
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry;
        int rc = -ENOMEM;
        struct hook_symlink_msg msg = {
                .dentry = dentry,
        };
        
        ENTRY;

        if (!cache_inode || !cache_inode->i_op->readlink)
                RETURN(-ENOENT);
        
        cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);
        if (!cache_dentry) {
                rc = -ENOMEM;
                goto exit;
        }

        SMFS_PRE_HOOK(dentry->d_inode, HOOK_READLINK, &msg);
        
        rc = cache_inode->i_op->readlink(cache_dentry, buffer, buflen);

        SMFS_POST_HOOK(dentry->d_inode, HOOK_READLINK, &msg, rc); 
       
exit:
        post_smfs_dentry(cache_dentry);
        RETURN(rc);
}

static int smfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry;
        int rc = -ENOMEM;
        ENTRY;

        if (!cache_inode || !cache_inode->i_op->follow_link)
                RETURN(-ENOENT);

        cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);
        if (cache_dentry)
                rc = cache_inode->i_op->follow_link(cache_dentry, nd);

        post_smfs_dentry(cache_dentry);
        RETURN(rc);
}

struct inode_operations smfs_sym_iops = {
        .readlink        = smfs_readlink,
        .follow_link     = smfs_follow_link,
        .setxattr        = smfs_setxattr,
        .getxattr        = smfs_getxattr,
        .listxattr       = smfs_listxattr,
        .removexattr     = smfs_removexattr,
        .permission      = smfs_permission,
};

struct file_operations smfs_sym_fops = {
};
