/*
 *
 *
 *  Copyright (C) 2000 Stelias Computing, Inc.
 *  Copyright (C) 2000 Red Hat, Inc.
 *  Copyright (C) 2000 Mountain View Data, Inc.
 *
 *
 */

#include <stdarg.h>

#include <asm/bitops.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/malloc.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/locks.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#define __NO_VERSION__
#include <linux/module.h>

#include <linux/filter.h>

int filter_print_entry = 1;
int filter_debug = 0xfffffff;
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
	FENTRY;

	if ( strlen(cache_type) == strlen("ext2") &&
	     memcmp(cache_type, "ext2", strlen("ext2")) == 0 ) {
		ops = &filter_oppar[FILTER_FS_EXT2];
		FDEBUG(D_SUPER, "ops at %p\n", ops);
	}

	if ( strlen(cache_type) == strlen("ext3") &&
	     memcmp(cache_type, "ext3", strlen("ext3")) == 0 ) {
		ops = &filter_oppar[FILTER_FS_EXT3];
		FDEBUG(D_SUPER, "ops at %p\n", ops);
	}
	if ( strlen(cache_type) == strlen("reiser") &&
	     memcmp(cache_type, "reiser", strlen("reiser")) == 0 ) {
		ops = &filter_oppar[FILTER_FS_REISER];
		FDEBUG(D_SUPER, "ops at %p\n", ops);
	}

	if (ops == NULL) {
		printk("prepare to die: unrecognized cache type for Filter\n");
	}
	FEXIT;
	return ops;
}


/*
 *  Frobnicate the InterMezzo/SnapFS operations
 *    this establishes the link between the InterMezzo/SnapFS file system
 *    and the underlying file system used for the cache.
 */

void filter_setup_super_ops(struct filter_fs *cache, struct super_operations *cache_sops, struct super_operations *filter_sops)
{
        /* Get ptr to the shared struct snapfs_ops structure. */
	struct filter_ops *uops = &cache->o_fops;
        /* Get ptr to the shared struct cache_ops structure. */
	struct cache_ops *caops = &cache->o_caops;

	FENTRY;

	if ( cache->o_flags & FILTER_DID_SUPER_OPS ) {
		FEXIT;
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
		FDEBUG(D_INODE, "setting filter_read_inode, cache_ops %p, cache %p, ri at %p\n",
		      cache, cache, uops->filter_sops.read_inode);
	}
	if (cache_sops->notify_change && uops->filter_sops.notify_change) 
		uops->filter_sops.notify_change = filter_sops->notify_change;
	if (cache_sops->remount_fs && uops->filter_sops.remount_fs)
		uops->filter_sops.remount_fs = filter_sops->remount_fs;
	FEXIT;
}


void filter_setup_dir_ops(struct filter_fs *cache, struct inode_operations *cache_iops, struct inode_operations *filter_iops)
{
	struct inode_operations *u_iops;
	struct file_operations *u_fops, *c_fops, *f_fops;
	FENTRY;

	if ( cache->o_flags & FILTER_DID_DIR_OPS ) {
		FEXIT;
		return;
	}
	FDEBUG(D_SUPER, "\n");
	cache->o_flags |= FILTER_DID_DIR_OPS;

	/* steal the old ops */
	cache->o_caops.cache_dir_iops = cache_iops;
	cache->o_caops.cache_dir_fops = 
		cache_iops->default_file_ops;

	FDEBUG(D_SUPER, "\n");
	/* abbreviate */
	u_iops = &cache->o_fops.filter_dir_iops;

	/* setup our dir iops: copy and modify */
	memcpy(u_iops, cache_iops, sizeof(*cache_iops));
	FDEBUG(D_SUPER, "\n");

	/* methods that filter if cache filesystem has these ops */
	if ( cache_iops->lookup && filter_iops->lookup ) {
	FDEBUG(D_SUPER, "\n");
		u_iops->lookup = filter_iops->lookup;
		FDEBUG(D_SUPER, "lookup at %p\n", &filter_iops->lookup);
	}
	if (cache_iops->create && filter_iops->create)
		u_iops->create = filter_iops->create;
	FDEBUG(D_SUPER, "\n");
	if (cache_iops->link && filter_iops->link)
		u_iops->link = filter_iops->link;
	FDEBUG(D_SUPER, "\n");
	if (cache_iops->unlink && filter_iops->unlink)
		u_iops->unlink = filter_iops->unlink;
	FDEBUG(D_SUPER, "\n");
	if (cache_iops->mkdir && filter_iops->mkdir)
		u_iops->mkdir = filter_iops->mkdir;
	FDEBUG(D_SUPER, "\n");
	if (cache_iops->rmdir && filter_iops->rmdir)
		u_iops->rmdir = filter_iops->rmdir;
	FDEBUG(D_SUPER, "\n");
	if (cache_iops->symlink && filter_iops->symlink)
		u_iops->symlink = filter_iops->symlink;
	FDEBUG(D_SUPER, "\n");
	if (cache_iops->rename && filter_iops->rename)
		u_iops->rename = filter_iops->rename;
	FDEBUG(D_SUPER, "\n");
	if (cache_iops->mknod && filter_iops->mknod)
		u_iops->mknod = filter_iops->mknod;
	FDEBUG(D_SUPER, "\n");
	if (cache_iops->permission && filter_iops->permission)
		u_iops->permission = filter_iops->permission;

	/* copy dir fops */
	FDEBUG(D_SUPER, "\n");
	u_fops = &cache->o_fops.filter_dir_fops;
	c_fops = cache_iops->default_file_ops;
	f_fops = filter_iops->default_file_ops;

        memcpy(u_fops, c_fops, sizeof(*c_fops));

	if( c_fops->readdir && f_fops->readdir )
		u_fops->readdir = f_fops->readdir;

	/* assign */
	FDEBUG(D_SUPER, "\n");
	filter_c2udiops(cache)->default_file_ops = filter_c2udfops(cache);
	FDEBUG(D_SUPER, "\n");

	/* unconditional filtering operations */
	if ( filter_iops->default_file_ops && 
	     filter_iops->default_file_ops->open ) 
		filter_c2udfops(cache)->open = 
			filter_iops->default_file_ops->open;

	FEXIT;
}


void filter_setup_file_ops(struct filter_fs *cache, struct inode_operations *cache_iops, struct inode_operations *filter_iops)
{
	struct inode_operations *u_iops;
	FENTRY;

	if ( cache->o_flags & FILTER_DID_FILE_OPS ) {
		FEXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_FILE_OPS;

	/* steal the old ops */
	cache->o_caops.cache_file_iops = cache_iops;
	cache->o_caops.cache_file_fops = 
		cache_iops->default_file_ops;

	/* abbreviate */
	u_iops = filter_c2ufiops(cache); 

	/* setup our dir iops: copy and modify */
	memcpy(u_iops, cache_iops, sizeof(*cache_iops));

	/* copy dir fops */
        memcpy(filter_c2uffops(cache), cache_iops->default_file_ops, 
	       sizeof(*cache_iops->default_file_ops));
	/* assign */
	filter_c2ufiops(cache)->default_file_ops = filter_c2uffops(cache);

	/* unconditional filtering operations */
	if (filter_iops->default_file_ops &&
	    filter_iops->default_file_ops->open ) 
		filter_c2uffops(cache)->open = 
			filter_iops->default_file_ops->open;
	if (filter_iops->default_file_ops &&
	    filter_iops->default_file_ops->release ) 
		filter_c2uffops(cache)->release = 
			filter_iops->default_file_ops->release;
	if (filter_iops->default_file_ops &&
	    filter_iops->default_file_ops->write ) 
		filter_c2uffops(cache)->write = 
			filter_iops->default_file_ops->write;

	/* set up readpage */
	if (filter_iops->readpage) 
		filter_c2ufiops(cache)->readpage = filter_iops->readpage;

	FEXIT;
}

/* XXX in 2.3 there are "fast" and "slow" symlink ops for ext2 XXX */
void filter_setup_symlink_ops(struct filter_fs *cache, struct inode_operations *cache_iops, struct inode_operations *filter_iops)
{
	struct inode_operations *u_iops;
	FENTRY;

	if ( cache->o_flags & FILTER_DID_SYMLINK_OPS ) {
		FEXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_SYMLINK_OPS;

	/* steal the old ops */
	cache->o_caops.cache_sym_iops = cache_iops;
	cache->o_caops.cache_sym_fops = 
		cache_iops->default_file_ops;

	/* abbreviate */
	u_iops = filter_c2usiops(cache); 

	/* setup our dir iops: copy and modify */
	memcpy(u_iops, cache_iops, sizeof(*cache_iops));

	/* copy fops - careful for symlinks they might be NULL */
	if ( cache_iops->default_file_ops ) { 
		memcpy(filter_c2usfops(cache), cache_iops->default_file_ops, 
		       sizeof(*cache_iops->default_file_ops));
	}

	/* assign */
	filter_c2usiops(cache)->default_file_ops = filter_c2usfops(cache);

	if (cache_iops->readlink && filter_iops->readlink) 
		u_iops->readlink = filter_iops->readlink;
	if (cache_iops->follow_link && filter_iops->follow_link)
		u_iops->follow_link = filter_iops->follow_link;

	FEXIT;
}

void filter_setup_dentry_ops(struct filter_fs *cache,
			     struct dentry_operations *cache_dop,
			     struct dentry_operations *filter_dop)
{
	if ( cache->o_flags & FILTER_DID_DENTRY_OPS ) {
		FEXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_DENTRY_OPS;

	cache->o_caops.cache_dentry_ops = cache_dop;
	memcpy(&cache->o_fops.filter_dentry_ops,
	       filter_dop, sizeof(*filter_dop));
	
	if (cache_dop &&  cache_dop != filter_dop && cache_dop->d_revalidate){
		printk("WARNING: filter overriding revalidation!\n");
	}
	return;
}
/* snapfs : for snapshot operations */
void filter_setup_snapshot_ops (struct filter_fs *cache, 
				struct snapshot_operations *cache_snapops)
{
	FENTRY;

	if ( cache->o_flags & FILTER_DID_SNAPSHOT_OPS ) {
		FEXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_SNAPSHOT_OPS;

	cache->o_snapops = cache_snapops;

	FEXIT;
}

void filter_setup_journal_ops (struct filter_fs *cache,
			       struct journal_ops *cache_journal_ops)
{
	FENTRY;

	if( cache->o_flags & FILTER_DID_JOURNAL_OPS ){
		FEXIT;
		return;
	}
	cache->o_flags |= FILTER_DID_JOURNAL_OPS;

	cache->o_trops = cache_journal_ops;

	FEXIT;
}
