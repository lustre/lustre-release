/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */ 
#ifndef __LVFS_LINUX_H__
#define __LVFS_LINUX_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/jbd.h>

#include <linux/lvfs.h>
/* we have made EXT3_IOC_SETFLAGS a Lustre constant */
#include <linux/ext3_fs.h>

#define l_file file
#define l_dentry dentry
#define l_inode inode

#define l_filp_open filp_open

struct obd_run_ctxt;
struct l_file *l_dentry_open(struct obd_run_ctxt *, struct l_dentry *,
                             int flags);

struct l_linux_dirent {
        struct list_head lld_list;
        ino_t           lld_ino;
        unsigned long   lld_off;
        char            lld_name[LL_FID_NAMELEN];
};
struct l_readdir_callback {
        struct l_linux_dirent *lrc_dirent;
        struct list_head      *lrc_list;
};

#endif
