/*
 * file.c
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/pagemap.h>
#include "smfs_internal.h" 

struct address_space_operations smfs_file_aops = {
};
                                                                                                                                                                                                     
struct file_operations smfs_file_fops = {
};
                                                                                                                                                                                                     
struct inode_operations smfs_file_iops = {
};

