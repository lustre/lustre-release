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

struct list_head obdfs_super_list;

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


/* XXX allocate a super_entry, and add the super to the obdfs_super_list */
static struct super_block * obdfs_read_super(struct super_block *sb, 
					    void *data, int silent)
{
        struct inode *root = 0; 
	struct obdfs_sb_info *sbi = (struct obdfs_sb_info *)(&sb->u.generic_sbp);
	struct obd_device *obddev;
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
        err = sbi->osi_ops->o_connect(&sbi->osi_conn);
	if ( err ) {
		printk("OBDFS: cannot connect to %s\n", device);
		goto ERR;
	}

	INIT_LIST_HEAD(&sbi->osi_list);

	sbi->osi_super = sb;

	err = sbi->osi_ops->o_get_info(&sbi->osi_conn, strlen("blocksize"),
				       "blocksize", &scratch,
				       (void *)&blocksize);
	if ( err ) {
		printk("Getinfo call to drive failed (blocksize)\n");
		goto ERR;
	}

	err = sbi->osi_ops->o_get_info(&sbi->osi_conn, strlen("blocksize_bits"),
				       "blocksize_bits", &scratch,
				       (void *)&blocksize_bits);
	if ( err ) {
		printk("Getinfo call to drive failed (blocksize_bits)\n");
		goto ERR;
	}

	err = sbi->osi_ops->o_get_info(&sbi->osi_conn, strlen("root_ino"), 
				       "root_ino", &scratch, (void *)&root_ino);
	if ( err ) {
		printk("Getinfo call to drive failed (root_ino)\n");
		goto ERR;
	}
	
        lock_super(sb);
	
        sb->s_blocksize = blocksize;
        sb->s_blocksize_bits = (unsigned char)blocksize_bits;
        sb->s_magic = OBDFS_SUPER_MAGIC;
        sb->s_op = &obdfs_super_operations;

	/* XXX how to get "sb->s_flags |= MS_RDONLY" here for snapshots? */

	/* make root inode */
	root = iget(sb, root_ino);
        if (!root || is_bad_inode(root)) {
	    printk("OBDFS: bad iget for root\n");
	    sb->s_dev = 0;
	    err = -ENOENT;
	    unlock_super(sb);
	    goto ERR;
	} 
	
	printk("obdfs_read_super: sbdev %d, rootino: %ld, dev %s, "
	       "minor: %d, blocksize: %ld, blocksize bits %ld\n", 
	       sb->s_dev, root->i_ino, device, MINOR(devno), 
	       blocksize, blocksize_bits);
	sb->s_root = d_alloc_root(root);
	unlock_super(sb);
	EXIT;  
        return sb;

ERR:
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

/* XXX remove the super to the obdfs_super_list */
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

void inline obdfs_from_inode(struct obdo *oa, struct inode *inode)
{
	obdo_from_inode(oa, inode);

	CDEBUG(D_INODE, "oinfo flags 0x%08x\n", OBDFS_INFO(inode)->oi_flags);
	if (obdfs_has_inline(inode)) {
		struct obdfs_inode_info *oinfo = OBDFS_INFO(inode);

		CDEBUG(D_INODE, "inode %ld has inline data\n", inode->i_ino);
		memcpy(oa->o_inline, oinfo->oi_inline, OBD_INLINESZ);
		oa->o_obdflags |= OBD_FL_INLINEDATA;
	}
}

void inline obdfs_to_inode(struct inode *inode, struct obdo *oa)
{
	obdo_to_inode(inode, oa);
	if (obdo_has_inline(oa)) {
		struct obdfs_inode_info *oinfo = OBDFS_INFO(inode);

		memcpy(oinfo->oi_inline, oa->o_inline, OBD_INLINESZ);
		oinfo->oi_flags |= OBD_FL_INLINEDATA;
	}
}

/* all filling in of inodes postponed until lookup */
void obdfs_read_inode(struct inode *inode)
{
	struct obdo *oa;
	int err;

	ENTRY;
	oa = obdo_alloc();
	if (!oa) {
		printk("obdfs_read_inode: obdo_alloc failed\n");
		EXIT;
		return;
	}
	oa->o_valid = ~OBD_MD_FLOBDMD;
	oa->o_id = inode->i_ino;

	INIT_LIST_HEAD(&OBDFS_INFO(inode)->oi_pages);
	
	err = IOPS(inode, getattr)(IID(inode), oa);
	if (err) {
		printk("obdfs_read_inode: obd_getattr fails (%d)\n", err);
		obdo_free(oa);
		EXIT;
		return;
	}

	ODEBUG(oa);
	obdfs_to_inode(inode, oa);
	INIT_LIST_HEAD(&OBDFS_LIST(inode));

	obdo_free(oa);
	OIDEBUG(inode);

	if (S_ISREG(inode->i_mode))
		inode->i_op = &obdfs_file_inode_operations;
	else if (S_ISDIR(inode->i_mode))
		inode->i_op = &obdfs_dir_inode_operations;
	else if (S_ISLNK(inode->i_mode))
		inode->i_op = &obdfs_symlink_inode_operations;
	else
		/* XXX what do we pass here??? */
		init_special_inode(inode, inode->i_mode, 0 /* XXX XXX */ );

	EXIT;
	return;
}

static void obdfs_write_inode(struct inode *inode) 
{
	struct obdo *oa;
	int err;
	
	ENTRY;
	oa = obdo_alloc();
	oa->o_valid = OBD_MD_FLALL;
	obdfs_from_inode(oa, inode);
	err = IOPS(inode, setattr)(IID(inode), oa);

	obdo_free(oa);

	if (err) {
		printk("obdfs_write_inode: obd_setattr fails (%d)\n", err);
		EXIT;
		return;
	}
	
	EXIT;
}

static void obdfs_delete_inode(struct inode *inode)
{
	struct obdo *oa;
	int err;
        ENTRY;

	oa = obdo_alloc();
	/* XXX we currently assume "id" is all that's needed for destroy */
	oa->o_id = inode->i_ino;
	err = IOPS(inode, destroy)(IID(inode), oa);
	obdo_free(oa);

	if (err) {
		printk("obdfs_delete_node: obd_destroy fails (%d)\n", err);
		return;
	}

	EXIT;
}




static int obdfs_notify_change(struct dentry *de, struct iattr *attr)
{
	struct inode *inode = de->d_inode;
	struct obdo *oa;
	int err;

	ENTRY;
	oa = obdo_alloc();
	if (!oa) {
		printk("obdfs_notify_change: obdo_alloc fails\n");
		return -ENOMEM;
	}

	oa->o_id = inode->i_ino;
	obdo_from_iattr(oa, attr);
        err = IOPS(inode, setattr)(IID(inode), oa);
	obdo_free(oa);

	if ( err ) {
		printk("obdfs_notify_change: obd_setattr fails (%d)\n", err);
		return err;
	}
	inode_setattr(inode, attr);

	CDEBUG(D_INODE, "inode blocks now %ld\n", inode->i_blocks);
	EXIT;
        return err;
}


static int obdfs_statfs(struct super_block *sb, struct statfs *buf, 
		       int bufsize)
{
	struct statfs tmp;
	int err;

	ENTRY;

	err = OPS(sb,statfs)(ID(sb), &tmp);
	if ( err ) { 
		printk("obdfs_notify_change: obd_statfs fails (%d)\n", err);
		return err;
	}
	copy_to_user(buf, &tmp, (bufsize<sizeof(tmp)) ? bufsize : sizeof(tmp));

	EXIT;

	return err; 
}

struct file_system_type obdfs_fs_type = {
   "obdfs", 0, obdfs_read_super, NULL
};

int init_obdfs(void)
{
	int err;

	printk(KERN_INFO "OBDFS v0.1, braam@stelias.com\n");

	obdfs_sysctl_init();

	INIT_LIST_HEAD(&obdfs_super_list);
	err = obdfs_init_pgrqcache();
	if (err)
		return err;

	flushd_init();
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
	obdfs_cleanup_pgrqcache();
	unregister_filesystem(&obdfs_fs_type);

	EXIT;
}

#endif
