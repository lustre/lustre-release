
/*
 * OBDFS Super operations
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copryright (C) 1996 Peter J. Braam <braam@stelias.com>
 * Copryright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copryright (C) 1999 Seagate Technology Inc.
 * Copryright (C) 2001 Mountain View Data, Inc.
 * Copryright (C) 2002 Cluster File Systems, Inc.
 *
 */

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
#include <linux/lustre_light.h>

struct list_head ll_super_list;
extern struct address_space_operations ll_aops;
struct super_operations ll_super_operations;
long ll_cache_count = 0;
long ll_mutex_start = 0;
long obd_memory = 0;

static char *ll_read_opt(const char *opt, char *data)
{
        char *value;
        char *retval;

        CDEBUG(D_INFO, "option: %s, data %s\n", opt, data);
        if ( strncmp(opt, data, strlen(opt)) )
                return NULL;

        if ( (value = strchr(data, '=')) == NULL )
                return NULL;

        value++;
        OBD_ALLOC(retval, char *, strlen(value) + 1);
        if ( !retval ) {
                printk(KERN_ALERT __FUNCTION__ ": out of memory!\n");
                return NULL;
        }
        
        memcpy(retval, value, strlen(value)+1);
        CDEBUG(D_PSDEV, "Assigned option: %s, value %s\n", opt, retval);
        return retval;
}

static void ll_options(char *options, char **dev, char **vers)
{
        char *this_char;

        if (!options)
                return;

        for (this_char = strtok (options, ",");
             this_char != NULL;
             this_char = strtok (NULL, ",")) {
                CDEBUG(D_INFO, "this_char %s\n", this_char);
                if ( (!*dev && (*dev = ll_read_opt("device", this_char)))||
                     (!*vers && (*vers = ll_read_opt("version", this_char))) )
                        continue;
                
        }
}

static struct super_block * ll_read_super(struct super_block *sb, 
                                            void *data, int silent)
{
        struct inode *root = 0; 
        struct ll_sb_info *sbi = (struct ll_sb_info *)(&sb->u.generic_sbp);
        struct obd_device *obddev;
	char *device = NULL;
        char *version = NULL;
	int root_ino = 2;
	int connected = 0;
        int devno;
        int err;
	struct obdo *oa;
        

        ENTRY;
        MOD_INC_USE_COUNT; 
        memset(sbi, 0, sizeof(*sbi));
        
        CDEBUG(D_INFO, "\n"); 
        ll_options(data, &device, &version);
        if ( !device ) {
                printk(__FUNCTION__ ": no device\n");
                EXIT;
                goto ERR;
        }

	devno = simple_strtoul(device, NULL, 0);
        CDEBUG(D_INFO, "\n"); 
        if ( devno >= MAX_OBD_DEVICES ) {
                printk(__FUNCTION__ ": device of %s too high (%d)\n", device, devno);
                EXIT;
                goto ERR;
        } 

        CDEBUG(D_INFO, "\n"); 
        obddev = &obd_dev[devno];


        CDEBUG(D_INFO, "\n"); 
        if ( ! (obddev->obd_flags & OBD_ATTACHED) || 
             ! (obddev->obd_flags & OBD_SET_UP) ){
                printk("device %s not attached or not set up (%d)\n", 
                       device, MINOR(devno));
                EXIT;
                goto ERR;;
        } 

        CDEBUG(D_INFO, "\n"); 
        sbi->ll_obd = obddev;
        sbi->ll_ops = sbi->ll_obd->obd_type->typ_ops;
        
        sbi->ll_conn.oc_dev = obddev;
        err = sbi->ll_ops->o_connect(&sbi->ll_conn);
        if ( err ) {
                printk("OBDFS: cannot connect to %s\n", device);
                EXIT;
                goto ERR;
        }

	connected = 1;
        CDEBUG(D_INFO, "\n"); 
        /* list of dirty inodes, and a mutex to hold while modifying it */
        INIT_LIST_HEAD(&sbi->ll_inodes);
        init_MUTEX (&sbi->ll_list_mutex);

        CDEBUG(D_INFO, "\n"); 
        sbi->ll_super = sb;
	sbi->ll_rootino = 2;
        
        CDEBUG(D_INFO, "\n"); 
	sb->s_maxbytes = 1LL << 36;
	printk("Max bytes: %Lx\n", sb->s_maxbytes);
        sb->s_blocksize = PAGE_SIZE;
        sb->s_blocksize_bits = (unsigned char)PAGE_SHIFT;
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_op = &ll_super_operations;

        /* make root inode */
        CDEBUG(D_INFO, "\n"); 
        oa = obdo_fromid(&sbi->ll_conn, root_ino, S_IFDIR,
                         OBD_MD_FLNOTOBD | OBD_MD_FLBLOCKS);
        CDEBUG(D_INFO, "mode %o\n", oa->o_mode); 
        if ( IS_ERR(oa) ) {
                printk(__FUNCTION__ ": obdo_fromid failed\n");
		iput(root); 
                EXIT;
                goto ERR;
        }
        CDEBUG(D_INFO, "\n"); 
        root = iget4(sb, root_ino, NULL, oa);
	obdo_free(oa);
        CDEBUG(D_INFO, "\n"); 
        if (!root) {
            printk("OBDFS: bad iget4 for root\n");
            sb->s_dev = 0;
            err = -ENOENT;
            EXIT;
            goto ERR;
        } 
        
        sb->s_root = d_alloc_root(root);
        list_add(&sbi->ll_list, &ll_super_list);
        OBD_FREE(device, strlen(device) + 1);
        if (version)
                OBD_FREE(version, strlen(version) + 1);
        EXIT;  
        return sb;

ERR:
        MOD_DEC_USE_COUNT;
        if (device)
                OBD_FREE(device, strlen(device) + 1);
        if (version)
                OBD_FREE(version, strlen(version) + 1);
	if (connected) 
		sbi->ll_ops->o_disconnect(&sbi->ll_conn);

        if (sbi) {
                sbi->ll_super = NULL;
        }
        if (root) {
                iput(root);
        }
        sb->s_dev = 0;
        return NULL;
} /* ll_read_super */


static void ll_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi;

        ENTRY;
        sb->s_dev = 0;
        
        sbi = (struct ll_sb_info *) &sb->u.generic_sbp;
        //ll_flush_reqs(&sbi->ll_inodes, ~0UL);

        OPS(sb,disconnect)(ID(sb));
        list_del(&sbi->ll_list);
        
        printk(KERN_INFO "OBDFS: Bye bye.\n");

        MOD_DEC_USE_COUNT;
        EXIT;
} /* ll_put_super */


void ll_do_change_inode(struct inode *inode, int valid)
{
        struct obdo *oa;
        int err;
        
        ENTRY;
        if (IOPS(inode, setattr) == NULL) {
                printk(KERN_ERR __FUNCTION__ ": no setattr method!\n");
                EXIT;
                return;
        }
        oa = obdo_alloc();
        if ( !oa ) {
                printk(__FUNCTION__ ": obdo_alloc failed\n");
                EXIT;
                return;
        }

        oa->o_valid = OBD_MD_FLNOTOBD & (valid | OBD_MD_FLID);
        ll_from_inode(oa, inode);
	oa->o_mode = inode->i_mode;
        err = IOPS(inode, setattr)(IID(inode), oa);

        if ( err )
                printk(__FUNCTION__ ": obd_setattr fails (%d)\n", err);

        EXIT;
        obdo_free(oa);
} /* ll_write_inode */

void ll_change_inode(struct inode *inode, int mask)
{
	return ll_do_change_inode(inode, OBD_MD_FLNLINK); 
}


extern void write_inode_pages(struct inode *);
/* This routine is called from iput() (for each unlink on the inode).
 * We can't put this call into delete_inode() since that is called only
 * when i_count == 0, and we need to keep a reference on the inode while
 * it is in the page cache, which means i_count > 0.  Catch 22.
 */
static void ll_put_inode(struct inode *inode)
{
        ENTRY;
        if (inode->i_nlink && (atomic_read(&inode->i_count) == 1)) {
		write_inode_pages(inode);
                EXIT;
                return;
        }

        //ll_dequeue_pages(inode);
        EXIT;
} /* ll_put_inode */


static void ll_delete_inode(struct inode *inode)
{
	ll_do_change_inode(inode, ~0);
	clear_inode(inode); 
}
#if 0
{
        struct obdo *oa;
        int err;

        ENTRY;
        if (IOPS(inode, destroy) == NULL) {
                printk(KERN_ERR __FUNCTION__ ": no destroy method!\n");
                EXIT;
                return;
        }

        oa = obdo_alloc();
        if ( !oa ) {
                printk(__FUNCTION__ ": obdo_alloc failed\n");
                EXIT;
                return;
        }
        oa->o_valid = OBD_MD_FLNOTOBD;
        ll_from_inode(oa, inode);

	/* XXX how do we know that this inode is now clean? */
	printk("delete_inode ------> link %d\n", inode->i_nlink);
        ODEBUG(oa);
        err = IOPS(inode, destroy)(IID(inode), oa);
        obdo_free(oa);
        clear_inode(inode);
        if (err) {
                printk(__FUNCTION__ ": obd_destroy fails (%d)\n", err);
                EXIT;
                return;
        }

        EXIT;
} /* ll_delete_inode */
#endif


static int ll_attr2inode(struct inode * inode, struct iattr * attr)
{
	unsigned int ia_valid = attr->ia_valid;
	int error = 0;

	if (ia_valid & ATTR_SIZE) {
		error = vmtruncate(inode, attr->ia_size);
		if (error)
			goto out;
	}

	if (ia_valid & ATTR_UID)
		inode->i_uid = attr->ia_uid;
	if (ia_valid & ATTR_GID)
		inode->i_gid = attr->ia_gid;
	if (ia_valid & ATTR_ATIME)
		inode->i_atime = attr->ia_atime;
	if (ia_valid & ATTR_MTIME)
		inode->i_mtime = attr->ia_mtime;
	if (ia_valid & ATTR_CTIME)
		inode->i_ctime = attr->ia_ctime;
	if (ia_valid & ATTR_MODE) {
		inode->i_mode = attr->ia_mode;
		if (!in_group_p(inode->i_gid) && !capable(CAP_FSETID))
			inode->i_mode &= ~S_ISGID;
	}
out:
	return error;
}

int ll_setattr(struct dentry *de, struct iattr *attr)
{
        struct inode *inode = de->d_inode;
        struct obdo *oa;
        int err;

        ENTRY;
        if (IOPS(inode, setattr) == NULL) {
                printk(KERN_ERR __FUNCTION__ ": no setattr method!\n");
                EXIT;
                return -EIO;
        }
        oa = obdo_alloc();
        if ( !oa ) {
                printk(__FUNCTION__ ": obdo_alloc failed\n");
                return -ENOMEM;
        }

	ll_attr2inode(inode, attr);
        oa->o_id = inode->i_ino;
	oa->o_mode = inode->i_mode;
        obdo_from_iattr(oa, attr);
        err = IOPS(inode, setattr)(IID(inode), oa);

        if ( err )
                printk(__FUNCTION__ ": obd_setattr fails (%d)\n", err);

        EXIT;
        obdo_free(oa);
        return err;
} /* ll_setattr */



static int ll_statfs(struct super_block *sb, struct statfs *buf)
{
        struct statfs tmp;
        int err;

        ENTRY;

        err = OPS(sb,statfs)(ID(sb), &tmp);
        if ( err ) { 
                printk(__FUNCTION__ ": obd_statfs fails (%d)\n", err);
                return err;
        }
	memcpy(buf, &tmp, sizeof(*buf));
	CDEBUG(D_SUPER, "statfs returns avail %ld\n", tmp.f_bavail);
        EXIT;

        return err; 
}

static inline void ll_read_inode2(struct inode *inode, void *opaque)
{
	struct obdo *oa = opaque; 
	
	ENTRY;
	ll_to_inode(inode, oa); 

        INIT_LIST_HEAD(ll_iplist(inode)); /* list of dirty pages on inode */
        INIT_LIST_HEAD(ll_islist(inode)); /* list of inodes in superblock */

        /* OIDEBUG(inode); */

        if (S_ISREG(inode->i_mode)) {
                inode->i_op = &ll_file_inode_operations;
                inode->i_fop = &ll_file_operations;
                inode->i_mapping->a_ops = &ll_aops;
                EXIT;
        } else if (S_ISDIR(inode->i_mode)) {
                inode->i_op = &ll_dir_inode_operations;
                inode->i_fop = &ll_dir_operations; 
                inode->i_mapping->a_ops = &ll_aops;
                EXIT;
        } else if (S_ISLNK(inode->i_mode)) {
                if (inode->i_blocks) { 
                        inode->i_op = &ll_symlink_inode_operations;
                        inode->i_mapping->a_ops = &ll_aops;
                }else {
                        inode->i_op = &ll_fast_symlink_inode_operations;
                }
                EXIT;
        } else {
                init_special_inode(inode, inode->i_mode,
                                   ((int *)ll_i2info(inode)->oi_inline)[0]);
        }

	EXIT;
        return;
}

/* exported operations */
struct super_operations ll_super_operations =
{
	read_inode2: ll_read_inode2,
	// put_inode: ll_put_inode,
        // delete_inode: ll_delete_inode,
        // put_super: ll_put_super,
        // statfs: ll_statfs
};



struct file_system_type lustre_light_fs_type = {
   "lustre_light", 0, ll_read_super, NULL
};

static int __init init_lustre_light(void)
{
        printk(KERN_INFO "Lustre Light 0.0.1, braam@clusterfs.com\n");

        return register_filesystem(&lustre_light_fs_type);
}

static void __exit exit_lustre_light(void)
{
        unregister_filesystem(&lustre_light_fs_type);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Light Client File System v1.0");
MODULE_LICENSE("GPL");

module_init(init_lustre_light);
module_exit(exit_lustre_light);
