/*
 * OBDFS Super operations
 *
 * Copryright (C) 1996 Peter J. Braam <braam@stelias.com>
 * Copryright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copryright (C) 1999 Seagate Technology Inc.
 *
 */

#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/segment.h>

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd_sim.h>  /* XXX for development/debugging only */
#include <obdfs.h>

/* VFS super_block ops */
static struct super_block *obdfs_read_super(struct super_block *, void *, int);
static void obdfs_read_inode(struct inode *);
static int  obdfs_notify_change(struct dentry *dentry, struct iattr *attr);
static void obdfs_write_inode(struct inode *);
static void obdfs_delete_inode(struct inode *);
static void obdfs_put_super(struct super_block *);
static int obdfs_statfs(struct super_block *sb, struct statfs *buf, 
		       int bufsiz);

/* exported operations */
struct super_operations obdfs_super_operations =
{
	obdfs_read_inode,       /* read_inode */
	obdfs_write_inode,      /* write_inode */
	NULL,	                /* put_inode */
	obdfs_delete_inode,     /* delete_inode */
	obdfs_notify_change,	/* notify_change */
	obdfs_put_super,	/* put_super */
	NULL,			/* write_super */
	obdfs_statfs,           /* statfs */
	NULL			/* remount_fs */
};

struct obdfs_sb_info obdfs_super_info;
int obd_minor = 0;
int obd_root_ino = 2;

static struct super_block * obdfs_read_super(struct super_block *sb, 
					    void *data, int silent)
{
        struct inode *root = 0; 
	struct obdfs_sb_info *sbi = NULL;
        int error = 0;
	unsigned long blocksize;
	unsigned long blocksize_bits;
	unsigned long root_ino;
	int scratch;
	

	ENTRY;
        MOD_INC_USE_COUNT; 

	sbi = &obdfs_super_info;

        if ( sbi->osi_super ) {
		printk("Already mounted\n");
		MOD_DEC_USE_COUNT;
		return NULL;
	}

	sbi->osi_obd = &obd_dev[obd_minor];
	sbi->osi_ops = sbi->osi_obd->obd_type->typ_ops;
	
        error  = sbi->osi_ops->o_connect(sbi->osi_obd, &sbi->osi_conn_info);
	if ( error ) {
		printk("OBDFS: cannot connect to 0x%x.\n", obd_minor);
		goto error;
	}

	sbi->osi_super = sb;

	error = sbi->osi_ops->o_get_info(sbi->osi_conn_info.conn_id, 
					 strlen("blocksize"), 
					 "blocksize", 
					 &scratch, (void *)&blocksize);
	if ( error ) {
		printk("Getinfo call to drive failed (blocksize)\n");
		goto error;
	}

	error = sbi->osi_ops->o_get_info(sbi->osi_conn_info.conn_id, 
					 strlen("blocksize_bits"), 
					 "blocksize_bits", 
					 &scratch, (void *)&blocksize_bits);
	if ( error ) {
		printk("Getinfo call to drive failed (blocksize_bits)\n");
		goto error;
	}

	error = sbi->osi_ops->o_get_info(sbi->osi_conn_info.conn_id, 
					 strlen("root_ino"), 
					 "root_ino", 
					 &scratch, (void *)&root_ino);
	if ( error ) {
		printk("Getinfo call to drive failed (root_ino)\n");
		goto error;
	}
	

        lock_super(sb);
        sb->u.generic_sbp = sbi;
	
        sb->s_blocksize = blocksize;
        sb->s_blocksize_bits = (unsigned char)blocksize_bits;
        sb->s_magic = OBDFS_SUPER_MAGIC;
        sb->s_op = &obdfs_super_operations;

	/* make root inode */
	root = iget(sb, root_ino);
        if (!root || is_bad_inode(root)) {
	    printk("OBDFS: bad iget for root\n");
	    sb->s_dev = 0;
	    error = ENOENT;
	    unlock_super(sb);
	    goto error;
	} 

	printk("obdfs_read_super: rootinode is %ld dev %d\n", 
	       root->i_ino, root->i_dev);
	sb->s_root = d_alloc_root(root);
	unlock_super(sb);
	EXIT;  
        return sb;

 error:
	EXIT;  
	MOD_DEC_USE_COUNT;
	if (sbi) {
		sbi->osi_super = NULL;
	}
        if (root) {
                iput(root);
        }
        sb->s_dev = 0;
        return NULL;
}

static void obdfs_put_super(struct super_block *sb)
{
        struct obdfs_sb_info *sbi;

        ENTRY;


        sb->s_dev = 0;
	
	/* XXX flush stuff */
	sbi = sb->u.generic_sbp;
	sb->u.generic_sbp = NULL;
	sbi->osi_ops->o_disconnect(sbi->osi_conn_info.conn_id);
	sbi->osi_super = NULL;

	
	printk("OBDFS: Bye bye.\n");
	memset(sbi, 0, sizeof(* sbi));

        MOD_DEC_USE_COUNT;
	EXIT;
}

extern struct inode_operations obdfs_inode_ops;

/* all filling in of inodes postponed until lookup */
static void obdfs_read_inode(struct inode *inode)
{
	int error;
	struct obdfs_sb_info *sbi = inode->i_sb->u.generic_sbp;
	ENTRY;

	error = sbi->osi_ops->o_getattr(sbi->osi_conn_info.conn_id, 
					inode->i_ino, inode);
	if (error) {
		printk("obdfs_read_inode: ibd_getattr fails (%d)\n", error);
		return;
	}

	inode->i_op = &obdfs_inode_ops;
	return;
}

static void obdfs_write_inode(struct inode *inode) 
{
        struct obdfs_sb_info *sbi;
	int error;
	
	sbi = inode->i_sb->u.generic_sbp;
	error = sbi->osi_ops->o_setattr(sbi->osi_conn_info.conn_id, 
					inode->i_ino, inode);
	if (error) {
		printk("obdfs_write_inode: ibd_setattr fails (%d)\n", error);
		return;
	}

	return;
}

static void obdfs_delete_inode(struct inode *inode)
{
        struct obdfs_sb_info *sbi;
	int error;
        ENTRY;

	sbi = inode->i_sb->u.generic_sbp;
	error = sbi->osi_ops->o_destroy(sbi->osi_conn_info.conn_id, 
					inode->i_ino);
	if (error) {
		printk("obdfs_delete_node: ibd_destroy fails (%d)\n", error);
		return;
	}

	EXIT;
}

static int  obdfs_notify_change(struct dentry *de, struct iattr *iattr)
{
	struct inode *inode = de->d_inode;
	struct iattr saved_copy;
	struct obdfs_sb_info * sbi;
	int error;

	ENTRY;
	inode_to_iattr(inode, &saved_copy);

	sbi = inode->i_sb->u.generic_sbp;
	inode_setattr(inode, iattr);
        error = sbi->osi_ops->o_setattr(sbi->osi_conn_info.conn_id, 
					inode->i_ino, inode);
	if ( error ) {
		inode_setattr(inode, &saved_copy);
		printk("obdfs_notify_change: obd_setattr fails (%d)\n", error);
		return error;
	}
	EXIT;
        return error;
}


static int obdfs_statfs(struct super_block *sb, struct statfs *buf, 
		       int bufsize)
{
	struct statfs tmp;
	struct obdfs_sb_info * sbi;
	int error;

	ENTRY;

	sbi = sb->u.generic_sbp;
	error = sbi->osi_ops->o_statfs(sbi->osi_conn_info.conn_id, &tmp);
	if ( error ) { 
		printk("obdfs_notify_change: obd_statfs fails (%d)\n", error);
		return error;
	}
	copy_to_user(buf, &tmp, (bufsize<sizeof(tmp)) ? bufsize : sizeof(tmp));

	EXIT;

	return error; 
}

struct file_system_type obdfs_fs_type = {
   "obdfs", 0, obdfs_read_super, NULL
};

int init_obdfs(void)
{
	printk(KERN_INFO "OBDFS v0.1, braam@stelias.com\n");

	obdfs_sysctl_init();

	obd_sbi = &obdfs_super_info;
	obd_fso = &obdfs_file_ops;

	return register_filesystem(&obdfs_fs_type);
}


#ifdef MODULE
int init_module(void)
{
	return init_obdfs();
}

void cleanup_module(void)
{
        ENTRY;

	obdfs_sysctl_clean();
	unregister_filesystem(&obdfs_fs_type);
}
void obdfs_psdev_dec_use_count(void)
{
	MOD_DEC_USE_COUNT;
}

EXPORT_SYMBOL(obdfs_psdev_dec_use_count);

#endif
