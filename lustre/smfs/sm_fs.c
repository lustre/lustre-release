/*
 *  fs/smfs/sm_fs.c
 *
 *  A storage management file system.
 *
 */
#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_SM
                                                                                                                                                                                                     
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/miscdevice.h>
#include <linux/lustre_idl.h>                                                                                                                                                                                                     
#include "smfs_internal.h" 

int sm_stack = 0;
long sm_kmemory = 0;

                                                                                                                                                                                                     
MODULE_AUTHOR("Peter J. Braam <braam@cs.cmu.edu>");
MODULE_DESCRIPTION("Smfs file system filters v0.01");
                                                                                                                                                                                                     
extern int init_smfs(void);
extern int cleanup_smfs(void);
extern int init_snap_sysctl(void);
                                                                                                                                                                                                     
static int __init smfs_init(void)
{
        int err;
                                                                                                                                                                                                     
        if ( (err = init_smfs()) ) {
                printk("Error initializing snapfs, %d\n", err);
                return -EINVAL;
        }
                                                                                                                                                                                                     
        if ( (err = init_smfs_proc_sys()) ) {
                printk("Error initializing snapfs proc sys, %d\n", err);
                return -EINVAL;
        }
                                                                                                                                                                                                     
        return 0;
}
                                                                                                                                                                                                     
static void __exit smfs_cleanup(void)
{
	cleanup_smfs();
}
module_init(smfs_init);
module_exit(smfs_cleanup);

