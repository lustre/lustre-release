/*
 *  snap_current
 *
 *  Copyright (C) 1998 Peter J. Braam
 *  Copyright (C) 2000 Stelias Computing, Inc.
 *  Copyright (C) 2000 Red Hat, Inc.
 *  Copyright (C) 2000 Mountain View Data, Inc.
 *
 *  Author: Peter J. Braam <braam@mountainviewdata.com>
 */
#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/loop.h>
//#include <linux/jbd.h>
//#include <linux/ext3_fs.h>
#include <linux/errno.h>
#include "smfs_internal.h" 

/* Find the options for the clone. These consist of a cache device
   and an index in the snaptable associated with that device. 
*/
static char *smfs_options(char *options, char **devstr, char **namestr)
{
	struct option *opt_value = NULL;
	char *pos;
	
	while (!(get_opt(&opt_value, &pos))) { 			
		if (!strcmp(opt_value->opt, "dev")) {
			if (devstr != NULL)
				*devstr = opt_value->value;
		} else if (!strcmp(opt_value->opt, "type")) {
			if (namestr != NULL)
				*namestr = opt_value->value;
		} else {
			break;
		}
	}
	return pos;
}
extern struct super_operations smfs_super_ops;

static struct super_block *sm_mount_cache(struct super_block *sb, 
				          char *devstr,
					  char *typestr)
{
	return NULL;	
}

struct super_block *
smfs_read_super(
        struct super_block *sb,
        void *data,
        int silent)
{
	struct smfs_inode_info *smi;
	struct smfs_super_info *smb;
	struct dentry *bottom_root;
	struct inode *root_inode = NULL;
	struct super_block *cache_sb;
	char *devstr = NULL, *typestr = NULL;
	char *cache_data;
	ino_t root_ino;
	int err = 0;

	ENTRY;

	CDEBUG(D_SUPER, "mount opts: %s\n", data ? (char *)data : "(none)");
	
	init_option(data);
	/* read and validate options */
	cache_data = smfs_options(data, &devstr, &typestr);
	if (*cache_data) {
		CERROR("invalid mount option %s\n", (char*)data);
		GOTO(out_err, err=-EINVAL);
	}
	if (!typestr || !devstr) {
		CERROR("mount options name and dev mandatory\n");
		GOTO(out_err, err=-EINVAL);
	}
	
	cache_sb = sm_mount_cache(sb, devstr, typestr);
	if (!cache_sb) {
		CERROR("Can not mount %s as %s\n", devstr, typestr);
		GOTO(out_err, err=-EINVAL);
	}
	/* set up the super block */
	smb = S2SMI(sb); 
	smb->smsi_sb = cache_sb;
	sb->s_op = &smfs_super_ops;

	bottom_root = dget(cache_sb->s_root);
	if (!bottom_root) {
		CERROR("bottom not mounted\n");
		GOTO(out_err, err=-ENOENT);
        }

	root_ino = bottom_root->d_inode->i_ino;
	smi = I2SMI(root_inode);
	/*FIXME Intialize smi here*/
	
	CDEBUG(D_SUPER, "readinode %p, root ino %ld, root inode at %p\n",
	       sb->s_op->read_inode, root_ino, root_inode);
	
	sb->s_root = d_alloc_root(bottom_root->d_inode);
	
	if (!sb->s_root) {
		GOTO(out_err, err=-EINVAL);
	}

	CDEBUG(D_SUPER, "sb %lx, &sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) &sb->u.generic_sbp);
 	
 out_err:
	cleanup_option();
	if (err)
		return NULL;
	return sb;
}

static DECLARE_FSTYPE(smfs_type, "smfs", smfs_read_super, 0);

int init_smfs(void)
{
	int err;

	err = register_filesystem(&smfs_type);
	if (err) {
		CERROR("smfs: failed in register Storage Management filesystem!\n");
	}
	return err;
}

int cleanup_smfs(void)
{
	int err;

	ENTRY;
	err = unregister_filesystem(&smfs_type);
	if (err) {
		CERROR("smfs: failed to unregister Storage Management filesystem!\n");
	}
	return 0;
}
