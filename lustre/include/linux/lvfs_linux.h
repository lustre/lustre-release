/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */ 
#ifndef __LVFS_LINUX_H__
#define __LVFS_LINUX_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/sched.h>

#include <lvfs.h>

#define l_file file
#define l_dentry dentry
#define l_inode inode

#define l_filp_open filp_open

struct lvfs_run_ctxt;
struct l_file *l_dentry_open(struct lvfs_run_ctxt *, struct l_dentry *,
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

# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  define BDEVNAME_DECLARE_STORAGE(foo) char foo[BDEVNAME_SIZE]
#  define ll_bdevname(SB, STORAGE) __bdevname(kdev_t_to_nr(SB->s_dev), STORAGE)
#  define lvfs_sbdev(SB)       ((SB)->s_bdev)
#  define lvfs_sbdev_type      struct block_device *
   int fsync_bdev(struct block_device *);
#  define lvfs_sbdev_sync      fsync_bdev
# else
#  define BDEVNAME_DECLARE_STORAGE(foo) char __unused_##foo
#  define ll_bdevname(SB,STORAGE) ((void)__unused_##STORAGE,bdevname(lvfs_sbdev(SB)))
#  define lvfs_sbdev(SB)       (kdev_t_to_nr((SB)->s_dev))
#  define lvfs_sbdev_type      kdev_t
#  define lvfs_sbdev_sync      fsync_dev
# endif

void lvfs_set_rdonly(lvfs_sbdev_type dev);
int lvfs_check_rdonly(lvfs_sbdev_type dev);
void lvfs_clear_rdonly(lvfs_sbdev_type dev);

#endif
