/*
 * filter.c
 */
#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>

#include "snapfs_internal.h" 


/*
 * The function in this file are responsible for setting up the 
 * correct methods layered file systems like InterMezzo and SnapFS
 */


static struct filter_fs filter_oppar[FILTER_FS_TYPES];

/* get to the upper methods (intermezzo, snapfs) */
inline struct super_operations *filter_c2usops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_sops;
}

inline struct inode_operations *filter_c2udiops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_dir_iops;
}

inline struct inode_operations *filter_c2ufiops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_file_iops;
}

inline struct inode_operations *filter_c2usiops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_sym_iops;
}

inline struct file_operations *filter_c2udfops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_dir_fops;
}

inline struct file_operations *filter_c2uffops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_file_fops;
}

inline struct address_space_operations *filter_c2ufaops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_file_aops;
}

inline struct file_operations *filter_c2usfops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_sym_fops;
}

inline struct dentry_operations *filter_c2udops(struct filter_fs *cache)
{
	return &cache->o_fops.filter_dentry_ops;
}

/* get to the cache (lower) methods */
inline struct super_operations *filter_c2csops(struct filter_fs *cache)
{
	return cache->o_caops.cache_sops;
}

inline struct inode_operations *filter_c2cdiops(struct filter_fs *cache)
{
	return cache->o_caops.cache_dir_iops;
}

inline struct inode_operations *filter_c2cfiops(struct filter_fs *cache)
{
	return cache->o_caops.cache_file_iops;
}

inline struct address_space_operations *filter_c2cfaops(struct filter_fs *cache)
{
	return cache->o_caops.cache_file_aops;
}

inline struct inode_operations *filter_c2csiops(struct filter_fs *cache)
{
	return cache->o_caops.cache_sym_iops;
}

inline struct file_operations *filter_c2cdfops(struct filter_fs *cache)
{
	return cache->o_caops.cache_dir_fops;
}

inline struct file_operations *filter_c2cffops(struct filter_fs *cache)
{
	return cache->o_caops.cache_file_fops;
}

inline struct file_operations *filter_c2csfops(struct filter_fs *cache)
{
	return cache->o_caops.cache_sym_fops;
}

inline struct dentry_operations *filter_c2cdops(struct filter_fs *cache)
{
	return cache->o_caops.cache_dentry_ops;
}
/* snapfs: for snapshot operations */
inline struct snapshot_operations *filter_c2csnapops(struct filter_fs *cache)
{
	return cache->o_snapops;
}

/* find the cache for this FS */
struct filter_fs *filter_get_filter_fs(const char *cache_type)
{
	struct filter_fs *ops = NULL;
	ENTRY;

	if ( strlen(cache_type) == strlen("ext2") &&
	     memcmp(cache_type, "ext2", strlen("ext2")) == 0 ) {
		ops = &filter_oppar[FILTER_FS_EXT2];
		CDEBUG(D_SUPER, "ops at %p\n", ops);
	}

	if ( strlen(cache_type) == strlen("ext3") &&
	     memcmp(cache_type, "ext3", strlen("ext3")) == 0 ) {
		ops = &filter_oppar[FILTER_FS_EXT3];
		CDEBUG(D_SUPER, "ops at %p\n", ops);
	}
	if ( strlen(cache_type) == strlen("reiser") &&
	     memcmp(cache_type, "reiser", strlen("reiser")) == 0 ) {
		ops = &filter_oppar[FILTER_FS_REISER];
		CDEBUG(D_SUPER, "ops at %p\n", ops);
	}

	if (ops == NULL) {
		CERROR("prepare to die: unrecognized cache type for Filter\n");
	}
	EXIT;
	return ops;
}

/*
 *  Frobnicate the InterMezzo/SnapFS operations
 *    this establishes the link between the InterMezzo/SnapFS file system
 *    and the underlying file system used for the cache.
 */

void filter_setup_super_ops(struct filter_fs *cache, 
		            struct super_operations *cache_sops, 
			    struct super_operations *filter_sops)
{
        /* Get ptr to the shared struct snapfs_ops structure. */
	struct filter_ops *uops = &cache->o_fops;
        /* Get ptr to the shared struct cache_ops structure. */
	struct cache_ops *caops = &cache->o_caops;

	ENTRY;

	if ( cache->o_flags & FILTER_DID_SUPER_OPS ) {
		EXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_SUPER_OPS;

        /* Set the cache superblock operations to point to the
	   superblock operations of the underlying file system.  */
	caops->cache_sops = cache_sops;
        /*
         * Copy the cache (real fs) superblock ops to the "filter"
         * superblock ops as defaults. Some will be changed below
         */
	memcpy(&uops->filter_sops, cache_sops, sizeof(*cache_sops));

	/*  now overwrite with filtering ops */
	if (cache_sops->put_super && uops->filter_sops.put_super) { 
		uops->filter_sops.put_super = filter_sops->put_super;
	}
	if (cache_sops->read_inode && uops->filter_sops.read_inode) {
		uops->filter_sops.read_inode = filter_sops->read_inode;
		CDEBUG(D_INODE, "setting filter_read_inode, cache_ops %p, cache %p, ri at %p\n",
		      cache, cache, uops->filter_sops.read_inode);
	}
	uops->filter_sops.clear_inode = filter_sops->clear_inode;
	
	EXIT;
}

void filter_setup_dir_ops(struct filter_fs *cache, 
			  struct inode	   *inode,
			  struct inode_operations *filter_iops, 
			  struct file_operations *filter_fops)
{
	struct inode_operations *u_iops;
	struct file_operations *u_fops;
	
	ENTRY;

	if (cache->o_flags & FILTER_DID_DIR_OPS) {
		EXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_DIR_OPS;

	/* steal the old ops */
	cache->o_caops.cache_dir_iops = inode->i_op;
	cache->o_caops.cache_dir_fops = inode->i_fop;
	
	u_iops = filter_c2udiops(cache);
	u_fops = filter_c2udfops(cache); 
	
	/* setup our dir iops and fops: copy and modify */
	memcpy(u_iops, inode->i_op, sizeof(struct inode_operations));
	memcpy(u_fops, inode->i_fop, sizeof(struct file_operations));

	/* methods that filter if cache filesystem has these ops */
	if (filter_iops) {
		struct inode_operations *cache_iops = inode->i_op;
		
		if (cache_iops->lookup && filter_iops->lookup) 
			u_iops->lookup = filter_iops->lookup;
		if (cache_iops->create && filter_iops->create)
			u_iops->create = filter_iops->create;
		if (cache_iops->link && filter_iops->link)
			u_iops->link = filter_iops->link;
		if (cache_iops->unlink && filter_iops->unlink)
			u_iops->unlink = filter_iops->unlink;
		if (cache_iops->mkdir && filter_iops->mkdir)
			u_iops->mkdir = filter_iops->mkdir;
		if (cache_iops->rmdir && filter_iops->rmdir)
			u_iops->rmdir = filter_iops->rmdir;
		if (cache_iops->symlink && filter_iops->symlink)
			u_iops->symlink = filter_iops->symlink;
		if (cache_iops->rename && filter_iops->rename)
			u_iops->rename = filter_iops->rename;
		if (cache_iops->mknod && filter_iops->mknod)
			u_iops->mknod = filter_iops->mknod;
		if (cache_iops->permission && filter_iops->permission)
			u_iops->permission = filter_iops->permission;
	}
	/* copy dir fops */
	
	if (filter_fops) {
		struct file_operations *cache_fops = inode->i_fop;
		
		if(cache_fops->readdir && filter_fops->readdir)
			u_fops->readdir = filter_fops->readdir;
	}
	EXIT;
}

void filter_setup_file_ops(struct filter_fs 	   *cache, 
			   struct inode		   *inode,
			   struct inode_operations *filter_iops,
			   struct file_operations  *filter_fops,
			   struct address_space_operations *filter_aops)
{
	struct inode_operations *u_iops;
	struct file_operations *u_fops;
	struct address_space_operations *u_aops;
	ENTRY;

	if (cache->o_flags & FILTER_DID_FILE_OPS || !inode ) { 
		EXIT;
		return;
	}

	cache->o_flags |= FILTER_DID_FILE_OPS;

	/* steal the old ops */
	cache->o_caops.cache_file_iops = inode->i_op; 
	cache->o_caops.cache_file_fops = inode->i_fop;

	/* abbreviate */
	u_iops = filter_c2ufiops(cache); 
	u_fops = filter_c2uffops(cache); 
	u_aops = filter_c2ufaops(cache); 
		
	/* setup our dir iops: copy and modify */
	memcpy(u_iops, inode->i_op, sizeof(struct inode_operations));
	memcpy(u_fops, inode->i_fop, sizeof(struct file_operations));

	if (inode->i_mapping && inode->i_mapping->a_ops) {
		cache->o_caops.cache_file_aops = inode->i_mapping->a_ops; 
		memcpy(u_aops, inode->i_mapping->a_ops, 
		       sizeof(struct address_space_operations));
	}
	if (filter_iops) {
		if (filter_iops->revalidate)
			u_iops->revalidate = filter_iops->revalidate;
	}
	if (filter_fops) {
		if (filter_fops->read)
			u_fops->read = filter_fops->read;
	}
	if (filter_aops) {
		if (filter_aops->readpage)
			u_aops->readpage = filter_aops->readpage;
	}
	EXIT;
}

void filter_setup_symlink_ops(struct filter_fs *cache, 
			      struct inode *inode,
		              struct inode_operations *filter_iops, 
			      struct file_operations *filter_fops)
{
	struct inode_operations *u_iops;
	struct file_operations *u_fops;
	
	ENTRY;

	if (cache->o_flags & FILTER_DID_SYMLINK_OPS || !inode ) {
		EXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_SYMLINK_OPS;

	/* steal the old ops */
	cache->o_caops.cache_sym_iops = inode->i_op;
	cache->o_caops.cache_sym_fops = inode->i_fop; 

	/* abbreviate */
	u_iops = filter_c2usiops(cache); 
	u_fops = filter_c2usfops(cache); 

	/* setup our dir iops: copy and modify */
	memcpy(u_iops, inode->i_op, sizeof(struct inode_operations));
	memcpy(u_fops, inode->i_fop, sizeof(struct file_operations));
	if (filter_iops) {
		struct inode_operations *cache_iops = inode->i_op; 
		if (cache_iops->readlink && filter_iops->readlink) 
			u_iops->readlink = filter_iops->readlink;
		if (cache_iops->follow_link && filter_iops->follow_link)
			u_iops->follow_link = filter_iops->follow_link;
	}
	EXIT;
}

void filter_setup_dentry_ops(struct filter_fs *cache,
			     struct dentry_operations *cache_dop,
			     struct dentry_operations *filter_dop)
{
	if ( cache->o_flags & FILTER_DID_DENTRY_OPS ) {
		EXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_DENTRY_OPS;

	cache->o_caops.cache_dentry_ops = cache_dop;
	memcpy(&cache->o_fops.filter_dentry_ops,
	       filter_dop, sizeof(*filter_dop));
	
	if (cache_dop &&  cache_dop != filter_dop && cache_dop->d_revalidate){
		CWARN("filter overriding revalidation!\n");
	}
	EXIT;
	return;
}
/* snapfs : for snapshot operations */
void filter_setup_snapshot_ops (struct filter_fs *cache, 
				struct snapshot_operations *cache_snapops)
{
	ENTRY;

	if ( cache->o_flags & FILTER_DID_SNAPSHOT_OPS ) {
		EXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_SNAPSHOT_OPS;

	cache->o_snapops = cache_snapops;

	EXIT;
}

void filter_setup_journal_ops (struct filter_fs *cache,
			       struct journal_ops *cache_journal_ops)
{
	ENTRY;

	if( cache->o_flags & FILTER_DID_JOURNAL_OPS ){
		EXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_JOURNAL_OPS;

	cache->o_trops = cache_journal_ops;

	EXIT;
}
