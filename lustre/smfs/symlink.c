/*
 *  fs/snap/snap.c
 *
 *  A snap shot file system.
 *
 */
#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "smfs_internal.h" 

struct inode_operations smfs_sym_iops = {
};

struct file_operations smfs_sym_fops = {
};
