#ifndef __LVFS_LINUX_H__
#define __LVFS_LINUX_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <linux/lvfs.h>

#define l_file file
#define l_dentry dentry
#define l_inode inode

#define l_filp_open filp_open

struct obd_run_ctxt;
struct l_file *l_dentry_open(struct obd_run_ctxt *, struct l_dentry *,
                             int flags);

#endif
