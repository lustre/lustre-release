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
#include <linux/obdfs.h>

/* VFS super_block ops */
static struct super_block *obdfs_read_super(struct super_block *, void *, int);
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

static char *obdfs_read_opt(const char *opt, char *data)
{
	char *value;
	char *retval;

	CDEBUG(D_SUPER, "option: %s, data %s\n", opt, data);
	if ( strncmp(opt, data, strlen(opt)) )
		return NULL;

	if ( (value = strchr(data, '=')) == NULL )
		return NULL;

	value++;
	OBD_ALLOC(retval, char *, strlen(value) + 1);
	if ( !retval ) {
		printk("OBDFS: Out of memory!\n");
		return NULL;
	}
	
	memcpy(retval, value, strlen(value)+1);
	CDEBUG(D_SUPER, "Assigned option: %s, value %s\n", opt, retval);
	return retval;
}

void obdfs_options(char *options, char **dev, char **vers)
{
	char *this_char;

	if (!options)
		return;

	for (this_char = strtok (options, ",");
	     this_char != NULL;
	     this_char = strtok (NULL, ",")) {
		CDEBUG(D_SUPER, "this_char %s\n", this_char);
		if ( (!*dev && (*dev = obdfs_read_opt("device", this_char)))||
		     (!*vers && (*vers = obdfs_read_opt("version", this_char))) )
			continue;
		
	}
}

static int obdfs_getdev(char *devpath, int *dev)
{
	struct dentry *dentry;
	kdev_t devno;

	dentry = lookup_dentry(devpath, NULL, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	
	if (!S_ISCHR(dentry->d_inode->i_mode))
		return -ENODEV;

	devno = dentry->d_inode->i_rdev;
	if ( MAJOR(devno) != OBD_PSDEV_MAJOR ) 
		return -ENODEV;
	
	if ( MINOR(devno) >= MAX_OBD_DEVICES ) 
		return -ENODEV;

	*dev = devno;
	return 0;
}

static struct super_block * obdfs_read_super(struct super_block *sb, 
					    void *data, int silent)
{
        struct inode *root = 0; 
	struct obdfs_sb_info *sbi = (struct obdfs_sb_info *)(&sb->u.generic_sbp);
	struct obd_device *obddev;
        int error = 0;
	char *device = NULL;
	char *version = NULL;
	int devno;
	int err;
	unsigned long blocksize;
	unsigned long blocksize_bits;
	unsigned long root_ino;
	int scratch;
	

	ENTRY;
        MOD_INC_USE_COUNT; 
	
	memset(sbi, 0, sizeof(*sbi));
	
	obdfs_options(data, &device, &version);
	if ( !device ) {
		printk("No device\n");
		MOD_DEC_USE_COUNT;
		EXIT;
		return NULL;
	}

	if ( (err = obdfs_getdev(device, &devno)) ) {
		printk("Cannot get devno of %s, error %d\n", device, err);
		MOD_DEC_USE_COUNT;
		EXIT;
		return NULL;
	}

	if ( MAJOR(devno) != OBD_PSDEV_MAJOR ) {
		printk("Wrong major number!\n");
		MOD_DEC_USE_COUNT;
		EXIT;
		return NULL;
	}
		
	if ( MINOR(devno) >= MAX_OBD_DEVICES ) {
		printk("Minor of %s too high (%d)\n", device, MINOR(devno));
		MOD_DEC_USE_COUNT;
		EXIT;
		return NULL;
	} 

	obddev = &obd_dev[MINOR(devno)];

	if ( ! (obddev->obd_flags & OBD_ATTACHED) || 
	     ! (obddev->obd_flags & OBD_SET_UP) ){
		printk("Device %s not attached or not set up (%d)\n", 
		       device, MINOR(devno));
		MOD_DEC_USE_COUNT;
		EXIT;
		return NULL;
	} 

	sbi->osi_obd = obddev;
	sbi->osi_ops = sbi->osi_obd->obd_type->typ_ops;
	
	sbi->osi_conn.oc_dev = obddev;
        error  = sbi->osi_ops->o_connect(&sbi->osi_conn);
	if ( error ) {
		printk("OBDFS: cannot connect to %s\n", device);
		goto error;
	}

	

	sbi->osi_super = sb;

	error = sbi->osi_ops->o_get_info(&sbi->osi_conn,
					 strlen("blocksize"), 
					 "blocksize", 
					 &scratch, (void *)&blocksize);
	if ( error ) {
		printk("Getinfo call to drive failed (blocksize)\n");
		goto error;
	}

	error = sbi->osi_ops->o_get_info(&sbi->osi_conn,
					 strlen("blocksize_bits"), 
					 "blocksize_bits", 
					 &scratch, (void *)&blocksize_bits);
	if ( error ) {
		printk("Getinfo call to drive failed (blocksize_bits)\n");
		goto error;
	}

	error = sbi->osi_ops->o_get_info(&sbi->osi_conn,
					 strlen("root_ino"), 
					 "root_ino", 
					 &scratch, (void *)&root_ino);
	if ( error ) {
		printk("Getinfo call to drive failed (root_ino)\n");
		goto error;
	}
	


        lock_super(sb);
	
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
	

	printk("obdfs_read_super: sbdev %d, rootino: %ld, dev %s, "
	       "minor: %d, blocksize: %ld, blocksize bits %ld\n", 
	       sb->s_dev, root->i_ino, device, MINOR(devno), 
	       blocksize, blocksize_bits);
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
	sbi = (struct obdfs_sb_info *) &sb->u.generic_sbp;

	OPS(sb,disconnect)(ID(sb));

	memset(sbi, 0, sizeof(* sbi));
	
	printk("OBDFS: Bye bye.\n");

        MOD_DEC_USE_COUNT;
	EXIT;
}

extern struct inode_operations obdfs_inode_ops;

/* all filling in of inodes postponed until lookup */
void obdfs_read_inode(struct inode *inode)
{
	int error;
	ENTRY;

	error = IOPS(inode, getattr)(IID(inode), inode);
	if (error) {
		printk("obdfs_read_inode: obd_getattr fails (%d)\n", error);
		return;
	}
	CDEBUG(D_INODE, "ino %ld, COWFL %x\n", inode->i_ino, inode->i_flags & 0x0010000);
	IDEBUG(inode);
	inode->i_op = &obdfs_inode_ops;
	return;
}

static void obdfs_write_inode(struct inode *inode) 
{
	int error;
	
	error = IOPS(inode, setattr)(IID(inode), inode);
	if (error) {
		printk("obdfs_write_inode: obd_setattr fails (%d)\n", error);
		return;
	}
	
	return;
}

static void obdfs_delete_inode(struct inode *inode)
{
	int error;
        ENTRY;

	error = IOPS(inode, destroy)(IID(inode), inode);
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
	int error;

	ENTRY;
	inode_to_iattr(inode, &saved_copy);

	inode_setattr(inode, iattr);
        error = IOPS(inode, setattr)(IID(inode), inode);
	if ( error ) {
		inode_setattr(inode, &saved_copy);
		printk("obdfs_notify_change: obd_setattr fails (%d)\n", error);
		return error;
	}

	CDEBUG(D_INODE, "inode blocks now %ld\n", inode->i_blocks);
	EXIT;
        return error;
}


static int obdfs_statfs(struct super_block *sb, struct statfs *buf, 
		       int bufsize)
{
	struct statfs tmp;
	int error;

	ENTRY;

	error = OPS(sb,statfs)(ID(sb), &tmp);
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

#endif
