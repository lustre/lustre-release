/*
 *  fs/snap/snap.c
 *
 *  A snap shot file system.
 *
 */

#define EXPORT_SYMTAB


#define __NO_VERSION__
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/locks.h>
#include <linux/quotaops.h>
#include <linux/list.h>
#include <linux/file.h>
#include <asm/bitops.h>
#include <asm/byteorder.h>

#ifdef CONFIG_SNAPFS_EXT2
#include <linux/ext2_fs.h>
#endif
#ifdef CONFIG_SNAPFS_EXT3
#include <linux/ext3_fs.h>
#endif

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>


extern int currentfs_remount(struct super_block * sb, int *flags, char *data);

/* XXX PJB: this is exactly what we need to put things under 
   filters - we don't want the ext2 methods hardcoded, we want them
   in the filter (in read_super) and then call those methods. 
   See how InterMezzo gets the journal operations .
*/
 
extern void currentfs_dotsnap_read_inode(struct snap_cache *, struct inode *);

/* Superblock operations. */
static void currentfs_read_inode(struct inode *inode)
{
        struct snap_cache *cache;
	ENTRY;

	if( !inode ) 
	{
		EXIT;
		return;
	}

	CDEBUG(D_INODE, "read_inode ino %lu\n", inode->i_ino);

	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) {
		printk("currentfs_read_inode: cannot find cache\n");
		make_bad_inode(inode);
		EXIT;
		return ;
	}

	if ( inode->i_ino & 0xF0000000 ) { 
		CDEBUG(D_INODE, "\n");
		currentfs_dotsnap_read_inode(cache, inode);
		EXIT;
		return ;
	}

	if( filter_c2csops(cache->cache_filter) )
		filter_c2csops(cache->cache_filter)->read_inode(inode);

	/* XXX now set the correct snap_{file,dir,sym}_iops */
	if ( S_ISDIR(inode->i_mode) ) 
		inode->i_op = filter_c2udiops(cache->cache_filter);
	else if ( S_ISREG(inode->i_mode) ) {
		if ( !filter_c2cfiops(cache->cache_filter) ) {
			filter_setup_file_ops(cache->cache_filter,
				inode->i_op, &currentfs_file_iops);
		}
		inode->i_op = filter_c2ufiops(cache->cache_filter);
		printk("inode %lu, i_op at %p\n", inode->i_ino, inode->i_op);
	}
	else if ( S_ISLNK(inode->i_mode) ) {
		if ( !filter_c2csiops(cache->cache_filter) ) {
			filter_setup_symlink_ops(cache->cache_filter,
				inode->i_op, &currentfs_sym_iops);
		}
		inode->i_op = filter_c2usiops(cache->cache_filter);
		printk("inode %lu, i_op at %p\n", inode->i_ino, inode->i_op);
	}

	EXIT;
	return; 
}


static int currentfs_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	struct snap_cache *cache;
	int rc;
	struct super_operations *sops;

	ENTRY;

	if (currentfs_is_under_dotsnap(dentry)) {
		EXIT;
		return -EPERM;
	}

	cache = snap_find_cache(dentry->d_inode->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	/* XXX better alloc a new dentry */

	if ( snap_needs_cow(dentry->d_inode) != -1 ) {
		printk("notify_change:snap_needs_cow for ino %lu \n",
			dentry->d_inode->i_ino);
		snap_do_cow(dentry->d_inode, 
			dentry->d_parent->d_inode->i_ino, 0);
	}

	sops = filter_c2csops(cache->cache_filter); 
	if (!sops ||
	    !sops->notify_change) {
		EXIT;
		return -EINVAL;
	}
	rc = sops->notify_change(dentry, iattr);
	
	EXIT;
	return rc;
}


static void currentfs_put_super(struct super_block *sb)
{

	struct snap_cache *cache;
	ENTRY;

	CDEBUG(D_SUPER, "sb %lx, sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) sb->u.generic_sbp);
	cache = snap_find_cache(sb->s_dev);
	if (!cache) {
		EXIT;
		goto exit;
	}
	/* handle COMPAT_FEATUREs */
#ifdef CONFIG_SNAPFS_EXT2
	else if( cache->cache_type == FILTER_FS_EXT2 ){
		if( !EXT2_HAS_COMPAT_FEATURE(sb, EXT2_FEATURE_COMPAT_SNAPFS) ){
			sb->u.ext2_sb.s_feature_compat &=
				~EXT2_FEATURE_COMPAT_BLOCKCOW;
			sb->u.ext2_sb.s_es->s_feature_compat &=
				cpu_to_le32(~EXT2_FEATURE_COMPAT_BLOCKCOW);
		}
	}
#endif
#ifdef CONFIG_SNAPFS_EXT3
	else if( cache->cache_type == FILTER_FS_EXT3 ){
		if( !EXT3_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_SNAPFS) ){
			sb->u.ext3_sb.s_es->s_feature_compat &=
				cpu_to_le32(~EXT3_FEATURE_COMPAT_BLOCKCOW);
		}
	}
#endif
        /*
         * If there is a saved 'put_super' function for the underlying
         * fs then call it.
         */
	if (cache->cache_filter->o_caops.cache_sops->put_super) { 
		cache->cache_filter->o_caops.cache_sops->put_super(sb);
	}
	
	if (!list_empty(&cache->cache_clone_list)) {
		printk("Warning: snap_put_super: clones exist!\n");
	}

	list_del(&cache->cache_chain);
	snap_free_cache(cache);

	CDEBUG(D_SUPER, "sb %lx, sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) sb->u.generic_sbp);
exit:
	CDEBUG(D_MALLOC, "after umount: kmem %ld, vmem %ld\n",
	       snap_kmemory, snap_vmemory);
	MOD_DEC_USE_COUNT;
	EXIT;
	return ;
}

struct super_operations currentfs_super_ops = {
	currentfs_read_inode,
	NULL, /* write inode */
	NULL, /* put inode */
	NULL, /* delete inode */
	currentfs_notify_change,
	currentfs_put_super,
	NULL, /* write super */
	NULL,
	NULL, /* remount */
};
