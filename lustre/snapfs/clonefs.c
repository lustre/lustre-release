/*
 * Super block/filesystem wide operations
 *
 * Copryright (C) 1996 Peter J. Braam <braam@maths.ox.ac.uk> and
 * Michael Callahan <callahan@maths.ox.ac.uk>
 *
 * Rewritten for Linux 2.1.  Peter Braam <braam@cs.cmu.edu>
 * Copyright (C) Carnegie Mellon University
 * 
 * Copyright (C) 2000, Mountain View Data, Inc, authors
 * Peter Braam <braam@mountainviewdata.com>, 
 * Harrison Xing <harrisonx@mountainviewdata.com>
 * 
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


/* Clone is a simple file system, read only that just follows redirectors
   we have placed the entire implementation except clone_read_super in
   this file 
 */

struct inode_operations clonefs_dir_inode_ops;
struct inode_operations clonefs_file_inode_ops;
struct inode_operations clonefs_symlink_inode_ops;
//struct inode_operations clonefs_special_inode_operations;
struct file_operations clonefs_dir_file_ops;
struct file_operations clonefs_file_file_ops;
//struct file_operations clonefs_special_file_operations;
struct address_space_operations clonefs_file_address_ops;

/* support routines for following redirectors */

/* Parameter is clonefs inode, 'inode', and typically this may be
   called before read_inode has completed on this clonefs inode,
   i.e. we may only assume that i_ino is valid.

   We return an underlying (likely disk) fs inode.  This involved
   handling any redirector inodes found along the way. 

   This function is used by all clone fs interface functions to get an
   underlying fs inode.  
*/

struct inode *clonefs_get_inode(struct inode *inode)
{
	struct snap_clone_info *clone_sb;
	struct inode *cache_inode, *redirected_inode;

	ENTRY;

        /* this only works if snapfs_current does NOT overwrite read_inode */
	clone_sb = (struct snap_clone_info *) &inode->i_sb->u.generic_sbp;

	/* basic invariant: clone and current ino's are equal */
        cache_inode = iget(clone_sb->clone_cache->cache_sb, inode->i_ino); 

	redirected_inode = snap_redirect(cache_inode, inode->i_sb);

	CDEBUG(D_SNAP, "redirected_inode: %lx, cache_inode %lx\n",
	       (unsigned long) redirected_inode, (unsigned long) cache_inode);

	CDEBUG(D_SNAP, "cache_inode: %lx, ino %ld, sb %lx, count %d\n",
	       (unsigned long) cache_inode, cache_inode->i_ino, 
	       (unsigned long) cache_inode->i_sb, atomic_read(&cache_inode->i_count));
	
	iput(cache_inode); 
	
	return redirected_inode;
}


/* super operations */
static void clonefs_read_inode(struct inode *inode)
{
	struct inode *cache_inode;

	ENTRY;

	CDEBUG(D_SNAP, "inode: %lx, ino %ld, sb %lx, count %d\n",
	       (unsigned long)inode, inode->i_ino, (long) inode->i_sb, 
	       atomic_read(&inode->i_count));

	/* redirecting inode in the cache */
        cache_inode = clonefs_get_inode(inode);
	if (!cache_inode) {
		make_bad_inode(inode);
		return;
	}
	/* copy attrs of that inode to our clone inode */
	snapfs_cpy_attrs(inode, cache_inode);

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &clonefs_file_inode_ops;
		if (inode->i_mapping)
			inode->i_mapping->a_ops = &clonefs_file_address_ops;
		inode->i_fop = &clonefs_file_file_ops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &clonefs_dir_inode_ops;
		inode->i_fop = &clonefs_dir_file_ops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &clonefs_symlink_inode_ops;
	} else {
	/* init special inode 
	 * FIXME whether we should replace special inode ops*/
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                init_special_inode(inode, inode->i_mode,
                                   kdev_t_to_nr(inode->i_rdev));
#else
                init_special_inode(inode, inode->i_mode, inode->i_rdev);
#endif
	}
	iput(cache_inode);

	CDEBUG(D_SNAP, "cache_inode: %lx ino %ld, sb %lx, count %d\n",
               (unsigned long) cache_inode, cache_inode->i_ino, 
	       (unsigned long) cache_inode->i_sb, 
	       atomic_read(&cache_inode->i_count));
	EXIT; 
}


static void clonefs_put_super(struct super_block *sb)
{
	struct snap_clone_info *clone_sb;

	ENTRY;
	CDEBUG(D_SUPER, "sb %lx, &sb->u.generic_sbp: %lx\n",
                (unsigned long) sb, (unsigned long) &sb->u.generic_sbp);
	clone_sb = (struct snap_clone_info *)&sb->u.generic_sbp;
	dput(clone_sb->clone_cache->cache_sb->s_root);
	list_del(&clone_sb->clone_list_entry);

	EXIT;
}

static int clonefs_statfs(struct super_block *sb, struct statfs *buf) 
{
	struct snap_clone_info *clone_sb;
	struct snap_cache *cache; 

	ENTRY;
	clone_sb = (struct snap_clone_info *)&sb->u.generic_sbp;

	cache = clone_sb->clone_cache;
	if (!cache) {
		CERROR("clone_statfs: no cache\n");
		RETURN(-EINVAL);
	}

	return cache->cache_filter->o_caops.cache_sops->statfs
		(cache->cache_sb, buf);
}

struct super_operations clone_super_ops =
{
	read_inode:	clonefs_read_inode,     /* read_inode */
	put_super:	clonefs_put_super,	/* put_super */
	statfs:		clonefs_statfs,   	/* statfs */
};


/* ***************** end of clonefs super ops *******************  */ 
/* ***************** begin clonefs dir ops *******************  */ 

static void d_unalloc(struct dentry *dentry)
{

	list_del(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_hash);
	dput(dentry); /* this will free the dentry memory */
}

/*
 * Return the underlying fs dentry with name in 'dentry' that points
 * to the right inode. 'dir' is the clone fs directory to search for
 * the 'dentry'.
 */
struct dentry *clonefs_lookup(struct inode *dir,  struct dentry *dentry)
{
	struct inode            *cache_dir = NULL;
	struct dentry           *cache_dentry = NULL, *tmp = NULL;
	struct inode            *cache_inode;
	struct dentry           *result;
	struct inode            *inode;
	struct snap_clone_info  *clone_sb;

	ENTRY;

	cache_dir = clonefs_get_inode(dir); 
  	if (!cache_dir) 
		RETURN(ERR_PTR(-ENOENT));
		
	tmp = dget(list_entry(cache_dir->i_dentry.next, struct dentry, d_alias));

	cache_dentry = d_alloc(tmp->d_parent, &dentry->d_name);
	
	if (!cache_dentry) {
                iput(cache_dir);
		dput(tmp);
		RETURN(ERR_PTR(-ENOENT));
	}

        /* Lock cache directory inode. */
	down(&cache_dir->i_sem);
	dput(tmp);
        /*
         * Call underlying fs lookup function to set the 'd_inode' pointer
         * to the corresponding directory inode.
         *
         * Note: If the lookup function does not return NULL, return
         * from 'clone_lookup' with an error.
         */
	result = cache_dir->i_op->lookup(cache_dir, cache_dentry);
	if (result) { 
		dput(cache_dentry);
	        up(&cache_dir->i_sem);
                iput(cache_dir);
		dentry->d_inode = NULL;
		RETURN(ERR_PTR(-ENOENT));
	}
        /* Unlock cache directory inode. */
	up(&cache_dir->i_sem);

        /*
         * If there is no inode pointer in the underlying fs 'cache_dentry'
         * then the directory doesn't have an entry with this name.  In fs/ext2
	 * we see that we return 0 and put dentry->d_inode = NULL;
         */
	cache_inode = cache_dentry->d_inode;
	if ( cache_inode == NULL ) {
                inode = NULL;
	} else {
	        clone_sb = (struct snap_clone_info *) &dir->i_sb->u.generic_sbp;
		/* note, iget below will follow a redirector, since 
		   it calls into clone_read_inode 
		*/ 
                inode = iget(dir->i_sb, cache_inode->i_ino);
	}

        /* dput(cache_dentry) will not put the dentry away
         * immediately, unless we first arrange that its hash list is
         * empty.
	 */

	if ( cache_inode != NULL ) {
		CDEBUG(D_INODE, "cache ino %ld, count %d, dir %ld, count %d\n", 
		       cache_inode->i_ino, atomic_read(&cache_inode->i_count), 
		       cache_dir->i_ino, atomic_read(&cache_dir->i_count));
	}

	d_unalloc(cache_dentry);
	iput(cache_dir);

        /*
         * Add 'inode' to the directory entry 'dentry'.
         */
	d_add(dentry, inode);

        RETURN(NULL);
}


/* instantiate a file handle to the cache file */
static void clonefs_prepare_snapfile(struct inode *i,
				     struct file *clone_file, 
				     struct inode *cache_inode,
				     struct file *cache_file,
				     struct dentry *cache_dentry)
{
	ENTRY;
        
	cache_file->f_pos = clone_file->f_pos;
        cache_file->f_mode = clone_file->f_mode;
        cache_file->f_flags = clone_file->f_flags;
        cache_file->f_count  = clone_file->f_count;
        cache_file->f_owner  = clone_file->f_owner;
	cache_file->f_op = cache_inode->i_fop;
	cache_file->f_dentry = cache_dentry;
        cache_file->f_dentry->d_inode = cache_inode;
	
	EXIT;
}

/* update the clonefs file struct after IO in cache file */
static void clonefs_restore_snapfile(struct inode *cache_inode,
				   struct file *cache_file, 
				   struct inode *clone_inode,
				   struct file *clone_file)
{
	ENTRY;
 
	cache_file->f_pos = clone_file->f_pos;
	cache_inode->i_size = clone_inode->i_size;
	
	EXIT;
}

static int clonefs_readdir(struct file *file, void *dirent, 
			   filldir_t filldir)
{
	int result;
	struct inode *cache_inode;
        struct file open_file;
	struct dentry open_dentry;
	struct inode *inode = file->f_dentry->d_inode;

	ENTRY;

	if(!inode) {
		RETURN(-EINVAL);
	}
        cache_inode = clonefs_get_inode(inode);

	if (!cache_inode) {
		make_bad_inode(inode);
		RETURN(-ENOMEM);
	}

	CDEBUG(D_INODE,"clone ino %ld\n",cache_inode->i_ino);

	clonefs_prepare_snapfile(inode, file, cache_inode, &open_file,
			      &open_dentry);
	/* potemkin case: we are handed a directory inode */
	result = -ENOENT;
	if (open_file.f_op->readdir) {
		down(&cache_inode->i_sem);
		result = open_file.f_op->readdir(&open_file, dirent, filldir);
		up(&cache_inode->i_sem);
	}
	clonefs_restore_snapfile(inode, file, cache_inode, &open_file);
	iput(cache_inode);
	RETURN(result);
}

struct file_operations clonefs_dir_file_ops = {
	readdir:	clonefs_readdir,        /* readdir */
};

struct inode_operations clonefs_dir_inode_ops = {
	lookup:		clonefs_lookup,   /* lookup */
};


/* ***************** end of clonefs dir ops *******************  */ 
/* ***************** begin clonefs file ops *******************  */ 

static int clonefs_readpage(struct file *file, struct page *page)
{
	int result = 0;
	struct inode *cache_inode;
	struct file open_file;
	struct dentry open_dentry;
	struct inode *inode;

	ENTRY;

	inode = file->f_dentry->d_inode;
        cache_inode = clonefs_get_inode(file->f_dentry->d_inode); 
	if (!cache_inode) {
		make_bad_inode(file->f_dentry->d_inode);
		RETURN(-ENOMEM);
	}

	clonefs_prepare_snapfile(inode, file, cache_inode, &open_file,
			      &open_dentry);
	/* tell currentfs_readpage the primary inode number */
	open_dentry.d_fsdata = (void*)inode->i_ino;

	/* potemkin case: we are handed a directory inode */
	down(&cache_inode->i_sem);
        /* XXX - readpage NULL on directories... */
        result = cache_inode->i_mapping->a_ops->readpage(&open_file, page);

	up(&cache_inode->i_sem);
	clonefs_restore_snapfile(inode, file, cache_inode, &open_file);
	iput(cache_inode);
	RETURN(result);
}

struct file_operations clonefs_file_file_ops = {
	read:	generic_file_read,      /* read -- bad */
	mmap:	generic_file_mmap,      /* mmap */
};

struct address_space_operations clonefs_file_address_ops = {
        readpage:       clonefs_readpage
};


/* ***************** end of clonefs file ops *******************  */ 
/* ***************** begin clonefs symlink ops *******************  */ 

static int clonefs_readlink(struct dentry *dentry, char *buf, int len)
{
	int res;
	struct inode * cache_inode;
	struct inode * old_inode;

	ENTRY;

	cache_inode = clonefs_get_inode(dentry->d_inode); 

	res = -ENOENT;

	if ( ! cache_inode ) {
		CDEBUG(D_INODE, "clonefs_get_inode failed, NULL\n");
		RETURN(res);	
	}
	
	/* XXX: shall we allocate a new dentry ? 
		The following is safe for ext3, etc. because ext2_readlink only
		use the inode info */

	/* save the old dentry inode */	
	old_inode = dentry->d_inode;
	/* set dentry inode to cache inode */
	dentry->d_inode = cache_inode;

	if ( cache_inode->i_op->readlink ) {
		res = cache_inode->i_op->readlink(dentry, buf, len); 
	}else {
		CDEBUG(D_INODE,"NO readlink for ino %lu\n", cache_inode->i_ino);
	}

	/* restore the old inode */
	dentry->d_inode = old_inode;

	iput(cache_inode);

	RETURN(res);
}

static int clonefs_follow_link(struct dentry * dentry, struct nameidata *nd)
{
	struct inode * cache_inode;
	struct inode * old_inode;
	int    res;

	ENTRY;

	cache_inode = clonefs_get_inode(dentry->d_inode); 
	if ( ! cache_inode ) {
		CDEBUG(D_INODE, "clonefs_get_inode failed, NULL\n");
		RETURN(-ENOENT);	
	}

	/* XXX: shall we allocate a new dentry ? 
		The following is safe for ext2, etc. because ext2_follow_link 
		only use the inode info */

	/* save the old dentry inode */	
	old_inode = dentry->d_inode;
	/* set dentry inode to cache inode */
	dentry->d_inode = cache_inode;

	if ( cache_inode->i_op->follow_link ) {
		res = cache_inode->i_op->follow_link(dentry, nd); 
	}

	/* restore the old inode */
	dentry->d_inode = old_inode;

	iput(cache_inode);

	RETURN(res);
}

struct inode_operations clonefs_symlink_inode_ops =
{
	/*FIXME later getxattr, listxattr, 
	 * other method need to be replaced too 
	 * */  
	readlink:	clonefs_readlink,   /* readlink */              
	follow_link:	clonefs_follow_link,/* follow_link */             
};


