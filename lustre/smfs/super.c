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
static int get_fd(struct file *filp)
{
	struct files_struct *files = current->files;	
	int fd = 0;
	
	write_lock(&files->file_lock);
	for (fd = 0; fd < files->max_fds; fd++) {
		if(files->fd[fd] == filp) {
			write_unlock(&files->file_lock);
			return fd;	
		}	
	}
	write_unlock(&files->file_lock);
	RETURN(-1);
}
#define MAX_LOOP_DEVICES	256
static char *parse_path2dev(struct super_block *sb, char *dev_path)
{
	struct file   *filp;
	int i = 0, fd = 0, error = 0;
	char *name = NULL;
		
	filp = filp_open(dev_path, 0, 0);
	if (!filp) 
		RETURN(NULL);

	if (S_ISREG(filp->f_dentry->d_inode->i_mode)) {
		/*here we must walk through all the snap cache to 
		 *find the loop device */
		for (i = 0; i < MAX_LOOP_DEVICES; i++) {
			fd = get_fd(filp);
			error = sb->s_bdev->bd_op->ioctl(filp->f_dentry->d_inode, 
						 filp, LOOP_SET_FD,
                                                 (unsigned long)&fd);
			if (!error) {
				filp_close(filp, current->files); 
				/*FIXME later, the loop file should 
			         *be different for different system*/
				SM_ALLOC(name, strlen("/dev/loop/") + 2);
				sprintf(name, "dev/loop/%d", i);
				RETURN(name);	 				
			}
		}
	}
	SM_ALLOC(name, strlen(dev_path) + 1);
	memcpy(name, dev_path, strlen(dev_path) + 1);
	filp_close(filp, current->files); 
	RETURN(name);
}
extern struct super_operations smfs_super_ops;

static int sm_mount_cache(struct super_block *sb, 
			  char *devstr,
			  char *typestr)
{
	struct vfsmount *mnt;	
	struct smfs_super_info *smb;
	char *dev_name = NULL;
	unsigned long page;
	int 	err = 0;
	
	dev_name = parse_path2dev(sb, devstr);
	if (!dev_name) {
        	GOTO(err_out, err = -ENOMEM);
	}
	if (!(page = __get_free_page(GFP_KERNEL))) {
        	GOTO(err_out, err = -ENOMEM);
	}                                                                                                                                                   
        memset((void *)page, 0, PAGE_SIZE);
        sprintf((char *)page, "iopen_nopriv");
                                                                                                                                                                                                     
        mnt = do_kern_mount(typestr, 0, dev_name, (void *)page);
        free_page(page);
	
	if (IS_ERR(mnt)) {
                CERROR("do_kern_mount failed: rc = %d\n", err);
                GOTO(err_out, 0);
        }
	smb = S2SMI(sb); 
	smb->smsi_sb = mnt->mnt_sb;
	smb->smsi_mnt = mnt;
	sm_set_sb_ops(mnt->mnt_sb, sb);	
err_out:
	if (dev_name) 
		SM_FREE(dev_name, strlen(dev_name) + 2);
		
	return err;	
}

struct super_block *
smfs_read_super(
        struct super_block *sb,
        void *data,
        int silent)
{
	struct smfs_inode_info *smi;
	struct dentry *bottom_root;
	struct inode *root_inode = NULL;
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
	
	err = sm_mount_cache(sb, devstr, typestr);
	if (err) {
		CERROR("Can not mount %s as %s\n", devstr, typestr);
		GOTO(out_err, 0);
	}
	/* set up the super block */

	bottom_root = dget(S2SMI(sb)->smsi_sb->s_root);
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
	int err = 0;

	err = register_filesystem(&smfs_type);
	if (err) {
		CERROR("smfs: failed in register Storage Management filesystem!\n");
	}
	init_smfs_cache();		
	return err;
}

int cleanup_smfs(void)
{
	int err = 0;

	ENTRY;
	err = unregister_filesystem(&smfs_type);
	if (err) {
		CERROR("smfs: failed to unregister Storage Management filesystem!\n");
	}
	cleanup_smfs_cache();		
	return 0;
}
