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
#define DEBUG_SUBSYSTEM S_SM

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/slab.h>
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
static int close_fd(int fd)
{
	struct files_struct *files = current->files;	
        
	write_lock(&files->file_lock);
       
	files->fd[fd] = NULL;
        __put_unused_fd(files, fd); 
	
	write_unlock(&files->file_lock);
	return 0;
}
static int set_loop_fd(char *dev_path, char *loop_dev)
{
        struct loop_info loopinfo;
	struct nameidata nd;
	struct dentry *dentry;
	struct block_device_operations *bd_ops;
	struct file   *filp;
	int    fd = 0, error = 0;
	
	fd = get_unused_fd();

	if (!fd) RETURN(-EINVAL);
	
	filp = filp_open(dev_path, FMODE_WRITE, 0);
	if (!filp || !S_ISREG(filp->f_dentry->d_inode->i_mode)) 
		RETURN(-EINVAL);
	
	fd_install(fd, filp);		

	if (path_init(loop_dev, LOOKUP_FOLLOW, &nd)) {
       		error = path_walk(loop_dev, &nd);
       		if (error) {
			path_release(&nd);
			filp_close(filp, current->files); 
			RETURN(-EINVAL);
		}
       	} else {
		path_release(&nd);
		filp_close(filp, current->files); 
		RETURN(-EINVAL);
	}                                                                                                                                                                    
	dentry = nd.dentry;
	bd_ops = get_blkfops(LOOP_MAJOR); 
	
	error = bd_ops->ioctl(dentry->d_inode, filp, LOOP_SET_FD,
                              (unsigned long)fd);
	if (error) {
		path_release(&nd);
		filp_close(filp, current->files); 
		RETURN(-EINVAL);
	}
	memset(&loopinfo, 0, sizeof(struct loop_info));

	error = bd_ops->ioctl(dentry->d_inode, filp, LOOP_SET_STATUS,
                              (unsigned long)(&loopinfo));
	path_release(&nd);
	RETURN(error);	
}

#define SIZE(a) (sizeof(a)/sizeof(a[0]))
static char *find_unused_and_set_loop_device(char *dev_path)
{
        char *loop_formats[] = { "/dev/loop/%d", "/dev/loop%d"};
        struct loop_info loopinfo;
	struct nameidata nd;
	struct dentry *dentry;
      	char *dev = NULL;
        int i, j, error;
                                                                                                                                                                                             
        for (j = 0; j < SIZE(loop_formats); j++) {
		SM_ALLOC(dev, strlen(loop_formats[i]) + 1);
		for(i = 0; i < 256; i++) {
			struct block_device_operations *bd_ops;

			sprintf(dev, loop_formats[j], i);
                       	
			if (path_init(dev, LOOKUP_FOLLOW, &nd)) {
                		error = path_walk(dev, &nd);
                		if (error && error != -ENOENT) {
					path_release(&nd);
                        		SM_FREE(dev, strlen(loop_formats[i]) + 1); 
					RETURN(NULL);
				}
        		} else {
                       		SM_FREE(dev, strlen(loop_formats[i]) + 1); 
                		RETURN(NULL);
                        }      
			dentry = nd.dentry;
			bd_ops = get_blkfops(LOOP_MAJOR); 
			error = bd_ops->ioctl(dentry->d_inode, NULL, LOOP_GET_STATUS, 
					      (unsigned long)&loopinfo);
			path_release(&nd);
                        
			if (error == -ENXIO) {
				/*find unused loop and set dev_path to loopdev*/
				error = set_loop_fd(dev_path, dev);
				if (error) {
					SM_FREE(dev, strlen(loop_formats[i]) + 1);
					dev = NULL;		
				}
				return dev;/* probably free */
			}
        	}
        	SM_FREE(dev, strlen(loop_formats[i]) + 1);
	}
	RETURN(NULL);
}

#define MAX_LOOP_DEVICES	256
static char *parse_path2dev(struct super_block *sb, char *dev_path)
{
	struct dentry *dentry;
	struct nameidata nd;
	char *name = NULL;
	int  error = 0;

	if (path_init(dev_path, LOOKUP_FOLLOW, &nd)) {
     		error = path_walk(dev_path, &nd);
     		if (error) {
			path_release(&nd);
			RETURN(NULL);
		}
       	} else {
               	RETURN(NULL);
	}      
	dentry = nd.dentry;

	if (!dentry->d_inode || is_bad_inode(dentry->d_inode) || 
	    (!S_ISBLK(dentry->d_inode->i_mode) && 
             !S_ISREG(dentry->d_inode->i_mode))){
		path_release(&nd);
		RETURN(NULL);
	}
		
	if (S_ISREG(dentry->d_inode->i_mode)) {
		name = find_unused_and_set_loop_device(dev_path);
		path_release(&nd);
		RETURN(name); 			
	}
	SM_ALLOC(name, strlen(dev_path) + 1);
	memcpy(name, dev_path, strlen(dev_path) + 1);
	RETURN(name);
}
static void duplicate_sb(struct super_block *csb, 
			 struct super_block *sb)
{
	sb->s_blocksize = csb->s_blocksize;
	sb->s_magic = csb->s_magic;
	sb->s_blocksize_bits = csb->s_blocksize_bits;
	sb->s_maxbytes = csb->s_maxbytes;
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
	
	duplicate_sb(mnt->mnt_sb, sb);
	sm_set_sb_ops(mnt->mnt_sb, sb);	
err_out:
	if (dev_name) 
		SM_FREE(dev_name, strlen(dev_name) + 2);
		
	return err;	
}
static int sm_umount_cache(struct super_block *sb)
{
	struct smfs_super_info *smb = S2SMI(sb);
	
	mntput(smb->smsi_mnt);
	
	return 0;
}
void smfs_put_super(struct super_block *sb)
{
	if (sb)
		sm_umount_cache(sb);
	return; 
}

struct super_block *
smfs_read_super(
        struct super_block *sb,
        void *data,
        int silent)
{
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

	root_ino = S2CSB(sb)->s_root->d_inode->i_ino;
	root_inode = iget(sb, root_ino);
		
	CDEBUG(D_SUPER, "readinode %p, root ino %ld, root inode at %p\n",
	       sb->s_op->read_inode, root_ino, root_inode);
	
	sb->s_root = d_alloc_root(root_inode);
	
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
