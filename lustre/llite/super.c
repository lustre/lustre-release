/*
 * Lustre Light Super operations
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

//struct list_head ll_super_list;
extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;
struct super_operations ll_super_operations;
long ll_cache_count = 0;
long ll_mutex_start = 0;
long obd_memory = 0;

static char *ll_read_opt(const char *opt, char *data)
{
        char *value;
        char *retval;
	ENTRY;

        CDEBUG(D_INFO, "option: %s, data %s\n", opt, data);
        if ( strncmp(opt, data, strlen(opt)) ) {
		EXIT;
                return NULL;
	}
        if ( (value = strchr(data, '=')) == NULL ) {
		EXIT;
                return NULL;
	}

        value++;
        OBD_ALLOC(retval, char *, strlen(value) + 1);
        if ( !retval ) {
                printk(KERN_ALERT __FUNCTION__ ": out of memory!\n");
                return NULL;
        }
        
        memcpy(retval, value, strlen(value)+1);
        CDEBUG(D_PSDEV, "Assigned option: %s, value %s\n", opt, retval);
	EXIT;
        return retval;
}

static void ll_options(char *options, char **dev, char **vers)
{
        char *this_char;
	ENTRY; 

        if (!options) { 
		EXIT;
                return;
	}

        for (this_char = strtok (options, ",");
             this_char != NULL;
             this_char = strtok (NULL, ",")) {
                CDEBUG(D_INFO, "this_char %s\n", this_char);
                if ( (!*dev && (*dev = ll_read_opt("device", this_char)))||
                     (!*vers && (*vers = ll_read_opt("version", this_char))) )
                        continue;
                
        }
	EXIT;
}

static struct super_block * ll_read_super(struct super_block *sb, 
                                            void *data, int silent)
{
        struct inode *root = 0; 
        struct ll_sb_info *sbi = (struct ll_sb_info *)(&sb->u.generic_sbp);
	char *device = NULL;
        char *version = NULL;
	int connected = 0;
        int devno;
        int err;
	struct mds_rep *rep; 
	struct ptlrep_hdr *hdr = NULL; 

        ENTRY;
        MOD_INC_USE_COUNT; 

        memset(sbi, 0, sizeof(*sbi));

	printk(__FUNCTION__ "line %d\n", __LINE__); 

        ll_options(data, &device, &version);
	printk(__FUNCTION__ "line %d\n", __LINE__); 
        if ( !device ) {
                printk(__FUNCTION__ ": no device\n");
		sb = NULL; 
                goto ERR;
        }
	printk(__FUNCTION__ "line %d\n", __LINE__); 

	devno = simple_strtoul(device, NULL, 0);
        if ( devno >= MAX_OBD_DEVICES ) {
                printk(__FUNCTION__ ": device of %s too high\n", device);
		sb = NULL; 
                goto ERR;
        } 
	printk(__FUNCTION__ "line %d\n", __LINE__); 

        sbi->ll_conn.oc_dev = &obd_dev[devno];
        err = obd_connect(&sbi->ll_conn);
        if ( err ) {
                printk(__FUNCTION__ "cannot connect to %s\n", device);
		sb = NULL; 
                goto ERR;
        }
	printk(__FUNCTION__ "line %d\n", __LINE__); 
	connected = 1;

	printk(__FUNCTION__ "line %d\n", __LINE__); 
	err = kportal_uuid_to_peer("mds", &sbi->ll_peer);
	if (err == 0)
		sbi->ll_peer_ptr = &sbi->ll_peer;
	printk(__FUNCTION__ "line %d\n", __LINE__); 

        sbi->ll_super = sb;
	sbi->ll_rootino = 2;

	sb->s_maxbytes = 1LL << 36;
        sb->s_blocksize = PAGE_SIZE;
        sb->s_blocksize_bits = (unsigned char)PAGE_SHIFT;
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_op = &ll_super_operations;
	printk(__FUNCTION__ "line %d\n", __LINE__); 

        /* make root inode */
	err = mdc_getattr(sbi->ll_peer_ptr, sbi->ll_rootino, S_IFDIR, 
			  OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 
			  &rep, &hdr);
	printk(__FUNCTION__ "line %d\n", __LINE__); 
        if (err) {
                printk(__FUNCTION__ ": mds_getattr failed for root %d\n", err);
		sb = NULL; 
                goto ERR;
        }
	printk(__FUNCTION__ "line %d\n", __LINE__); 
                         
        root = iget4(sb, sbi->ll_rootino, NULL, rep);
        if (root) {
		sb->s_root = d_alloc_root(root);
	} else {
            printk("lustre_light: bad iget4 for root\n");
	    sb = NULL; 
            goto ERR;
        } 
	printk(__FUNCTION__ "line %d\n", __LINE__); 
        
ERR:
	if (hdr)
		kfree(hdr);
        if (device)
                OBD_FREE(device, strlen(device) + 1);
        if (version)
                OBD_FREE(version, strlen(version) + 1);
	if (!sb && connected) 
		obd_disconnect(&sbi->ll_conn);

        if (!sb && root) {
                iput(root);
        }
	if (!sb) 
		MOD_DEC_USE_COUNT;

	EXIT;
        return sb;
} /* ll_read_super */

static void ll_put_super(struct super_block *sb)
{
        ENTRY;

        obd_disconnect(ID(sb));

        MOD_DEC_USE_COUNT;
        EXIT;
} /* ll_put_super */


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

/* like inode_setattr, but doesn't mark the inode dirty */ 
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
	struct ptlrep_hdr *hdr = NULL;
        struct ll_sb_info *sbi =
		(struct ll_sb_info *)(&inode->i_sb->u.generic_sbp);
	int err;

        ENTRY;

	/* change incore inode */
	ll_attr2inode(inode, attr);

	err = mdc_setattr(sbi->ll_peer_ptr, inode, attr, NULL, &hdr); 
        if ( err )
                printk(__FUNCTION__ ": ll_setattr fails (%d)\n", err);

        EXIT;
        return err;
} /* ll_setattr */



static int ll_statfs(struct super_block *sb, struct statfs *buf)
{
        struct statfs tmp;
        int err;

        ENTRY;

        err = obd_statfs(ID(sb), &tmp);
        if ( err ) { 
                printk(__FUNCTION__ ": obd_statfs fails (%d)\n", err);
                return err;
        }
	memcpy(buf, &tmp, sizeof(*buf));
	CDEBUG(D_SUPER, "statfs returns avail %ld\n", tmp.f_bavail);
        EXIT;

        return err; 
}

static void inline ll_to_inode(struct inode *dst, struct mds_rep *rep)
{
	struct ll_inode_info *ii = 
		(struct ll_inode_info *) &dst->u.generic_ip;

	/* core attributes first */
        if ( rep->valid & OBD_MD_FLID )
                dst->i_ino = rep->ino;
        if ( rep->valid & OBD_MD_FLATIME ) 
                dst->i_atime = rep->atime;
        if ( rep->valid & OBD_MD_FLMTIME ) 
                dst->i_mtime = rep->mtime;
        if ( rep->valid & OBD_MD_FLCTIME ) 
                dst->i_ctime = rep->ctime;
        if ( rep->valid & OBD_MD_FLSIZE ) 
                dst->i_size = rep->size;
        if ( rep->valid & OBD_MD_FLMODE ) 
                dst->i_mode = rep->mode;
        if ( rep->valid & OBD_MD_FLUID ) 
                dst->i_uid = rep->uid;
        if ( rep->valid & OBD_MD_FLGID ) 
                dst->i_gid = rep->gid;
        if ( rep->valid & OBD_MD_FLFLAGS ) 
                dst->i_flags = rep->flags;
        if ( rep->valid & OBD_MD_FLNLINK )
                dst->i_nlink = rep->nlink;
        if ( rep->valid & OBD_MD_FLGENER )
                dst->i_generation = rep->generation;

	/* this will become more elaborate for striping etc */ 
	if (rep->valid & OBD_MD_FLOBJID) 
		ii->lli_objid = rep->objid;
#if 0

        if (obdo_has_inline(oa)) {
		if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		    S_ISFIFO(inode->i_mode)) {
			obd_rdev rdev = *((obd_rdev *)oa->o_inline);
			CDEBUG(D_INODE,
			       "copying device %x from obdo to inode\n", rdev);
			init_special_inode(inode, inode->i_mode, rdev);
		} else {
			CDEBUG(D_INFO, "copying inline from obdo to inode\n");
			memcpy(oinfo->lli_inline, oa->o_inline, OBD_INLINESZ);
		}
                oinfo->lli_flags |= OBD_FL_INLINEDATA;
        }
#endif 
} /* ll_to_inode */

static inline void ll_read_inode2(struct inode *inode, void *opaque)
{
	struct mds_rep *rep = opaque; 
	
	ENTRY;
	ll_to_inode(inode, rep); 

        /* OIDEBUG(inode); */

        if (S_ISREG(inode->i_mode)) {
                inode->i_op = &ll_file_inode_operations;
                inode->i_fop = &ll_file_operations;
                inode->i_mapping->a_ops = &ll_aops;
                EXIT;
        } else if (S_ISDIR(inode->i_mode)) {
                inode->i_op = &ll_dir_inode_operations;
                inode->i_fop = &ll_dir_operations; 
                inode->i_mapping->a_ops = &ll_dir_aops;
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
                                   ((int *)ll_i2info(inode)->lli_inline)[0]);
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
        put_super: ll_put_super,
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
