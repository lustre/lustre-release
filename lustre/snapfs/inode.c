/*
 *  fs/snap/snap.c
 *
 *  A snap shot file system.
 *
 */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/string.h>
#include <linux/snap.h>
#include "snapfs_internal.h" 


extern int currentfs_remount(struct super_block * sb, int *flags, char *data);

/* XXX PJB: this is exactly what we need to put things under 
   filters - we don't want the ext2 methods hardcoded, we want them
   in the filter (in read_super) and then call those methods. 
   See how InterMezzo gets the journal operations .
*/
 
extern void currentfs_dotsnap_read_inode(struct snap_cache *, struct inode *);

static kmem_cache_t *filter_info_cache = NULL;

void cleanup_filter_info_cache()
{
	kmem_cache_destroy(filter_info_cache);
}

int init_filter_info_cache()
{
	filter_info_cache = kmem_cache_create("snapfs_filter_info",
					       sizeof(struct filter_inode_info), 
					    0, 0, NULL, NULL);
        if (!filter_info_cache) {
                CERROR("unable to create snap_inode info cache\n");
		return -ENOMEM;
        }
        return 0;
}


void init_filter_data(struct inode *inode, 
			     int flag)
{
	struct filter_inode_info *i;
        struct snap_cache *cache;
	struct snapshot_operations *snapops; 

	if (inode->i_filterdata || inode->i_ino & 0xF0000000)
                return;
	cache = snap_find_cache(inode->i_dev);
	if (!cache) {
		CERROR("currentfs_read_inode: cannot find cache\n");
		make_bad_inode(inode);
		return;
	}
	snapops = filter_c2csnapops(cache->cache_filter);
	
	inode->i_filterdata = (struct filter_inode_info *) \
			      kmem_cache_alloc(filter_info_cache, SLAB_KERNEL);
	i = inode->i_filterdata;
	i -> generation = snapops->get_generation(inode);
	i -> flags      = flag;
}
/* Superblock operations. */
static void currentfs_read_inode(struct inode *inode)
{
        struct snap_cache *cache;
	struct snapshot_operations *snapops;	
	ENTRY;

	if( !inode ) 
		return;

	CDEBUG(D_INODE, "read_inode ino %lu\n", inode->i_ino);

	cache = snap_find_cache(inode->i_dev);
	if (!cache) {
		CERROR("currentfs_read_inode: cannot find cache\n");
		make_bad_inode(inode);
		return;
	}

	if (inode->i_ino & 0xF0000000) { 
		currentfs_dotsnap_read_inode(cache, inode);
		return;
	}
	snapops = filter_c2csnapops(cache->cache_filter);
	
	if (!snapops || !snapops->get_indirect) 
		return;

	if(filter_c2csops(cache->cache_filter))
		filter_c2csops(cache->cache_filter)->read_inode(inode);

	/* XXX now set the correct snap_{file,dir,sym}_iops */
	if (S_ISDIR(inode->i_mode)) 
		inode->i_op = filter_c2udiops(cache->cache_filter);
	else if (S_ISREG(inode->i_mode)) {
		if ( !filter_c2cfiops(cache->cache_filter) ) {
			filter_setup_file_ops(cache->cache_filter, inode, 
					      &currentfs_file_iops, 
					      &currentfs_file_fops, 
					      &currentfs_file_aops);
		}
		CDEBUG(D_INODE, "inode %lu, i_op at %p\n", 
		       inode->i_ino, inode->i_op);
	}
	else if (S_ISLNK(inode->i_mode)) {
		if ( !filter_c2csiops(cache->cache_filter) ) {
			filter_setup_symlink_ops(cache->cache_filter, inode,
				&currentfs_sym_iops, &currentfs_sym_fops);
		}
		inode->i_op = filter_c2usiops(cache->cache_filter);
		CDEBUG(D_INODE, "inode %lu, i_op at %p\n", 
		       inode->i_ino, inode->i_op);
	}
	/*init filter_data struct 
	 * FIXME flag should be set future*/
	init_filter_data(inode, 0); 
	return; 
}

static void currentfs_put_super(struct super_block *sb)
{

	struct snap_cache *cache;
	ENTRY;

	CDEBUG(D_SUPER, "sb %lx, sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) sb->u.generic_sbp);
	cache = snap_find_cache(sb->s_dev);

	if (!cache) 
		GOTO(exit, 0);	
	
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
		CWARN("snap_put_super: clones exist!\n");
	}

	list_del(&cache->cache_chain);
	snap_free_cache(cache);

	CDEBUG(D_SUPER, "sb %lx, sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) sb->u.generic_sbp);
exit:
	EXIT;
	return;
}
static void currentfs_clear_inode(struct inode *inode)
{
	struct snap_cache *cache;
        struct super_operations *sops;
	ENTRY;			                                                                                                                                                                                                     
        cache = snap_find_cache(inode->i_dev);
        if (!cache) {
                CDEBUG(D_INODE, "inode has invalid dev\n");
                return;
        }
	
	if (inode->i_filterdata) {
		kmem_cache_free(filter_info_cache, inode->i_filterdata);
		inode->i_filterdata = NULL;
	}

	sops = filter_c2csops(cache->cache_filter);
        if (sops && sops->clear_inode)
                sops->clear_inode(inode);
}

struct super_operations currentfs_super_ops = {
	read_inode:	currentfs_read_inode,
	put_super:	currentfs_put_super,
	clear_inode:	currentfs_clear_inode,
};
