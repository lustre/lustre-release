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

#define __NO_VERSION__
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
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/malloc.h>
#include <linux/vmalloc.h>
#include <asm/segment.h>

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

/* Clone is a simple file system, read only that just follows redirectors
   we have placed the entire implementation except clone_read_super in
   this file 
 */

struct inode_operations clonefs_dir_inode_operations;
struct inode_operations clonefs_file_inode_operations;
struct inode_operations clonefs_symlink_inode_operations;
struct inode_operations clonefs_special_inode_operations;
struct file_operations clonefs_dir_file_operations;
struct file_operations clonefs_file_file_operations;
struct file_operations clonefs_special_file_operations;

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
	       (ulong) redirected_inode, (ulong) cache_inode);

	CDEBUG(D_SNAP, "cache_inode: %lx, ino %ld, sb %lx, count %d\n",
	       (ulong) cache_inode, cache_inode->i_ino, 
	       (ulong) cache_inode->i_sb, cache_inode->i_count);

	iput(cache_inode); 
	EXIT;
	return redirected_inode;
}


/* super operations */
static void clonefs_read_inode(struct inode *inode)
{
	struct inode *cache_inode;

	ENTRY;

	CDEBUG(D_SNAP, "inode: %lx, ino %ld, sb %lx, count %d\n",
	       (ulong) inode , inode->i_ino, (long) inode->i_sb, 
	       inode->i_count);

	/* redirecting inode in the cache */
        cache_inode = clonefs_get_inode(inode);
	if (!cache_inode) {
		make_bad_inode(inode);
		EXIT;
		return;
	}
	/* copy attrs of that inode to our clone inode */
	snapfs_cpy_attrs(inode, cache_inode);

	if (S_ISREG(inode->i_mode))
		inode->i_op = &clonefs_file_inode_operations;
	else if (S_ISDIR(inode->i_mode))
		inode->i_op = &clonefs_dir_inode_operations;
	else if (S_ISLNK(inode->i_mode))
		inode->i_op = &clonefs_symlink_inode_operations;
	else if (S_ISCHR(inode->i_mode))
		inode->i_op = &chrdev_inode_operations;
	else if (S_ISBLK(inode->i_mode))
		inode->i_op = &blkdev_inode_operations;
	else if (S_ISFIFO(inode->i_mode))
		init_fifo(inode);

	iput(cache_inode);

	CDEBUG(D_SNAP, "cache_inode: %lx ino %ld, sb %lx, count %d\n",
                (ulong) cache_inode, cache_inode->i_ino, 
	       (ulong) cache_inode->i_sb, cache_inode->i_count);
	EXIT;
	return; 
}


static void clonefs_put_super(struct super_block *sb)
{
	struct snap_clone_info *clone_sb;

	ENTRY;
	CDEBUG(D_SUPER, "sb %lx, &sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) &sb->u.generic_sbp);
	clone_sb = (struct snap_clone_info *)&sb->u.generic_sbp;
	dput( clone_sb->clone_cache->cache_sb->s_root );
	list_del(&clone_sb->clone_list_entry);

	MOD_DEC_USE_COUNT;

	EXIT;
}

static int clonefs_statfs(struct super_block *sb, struct statfs *buf, 
			int bufsiz)
{
	struct snap_clone_info *clone_sb;
	struct snap_cache *cache; 

	ENTRY;
	clone_sb = (struct snap_clone_info *)&sb->u.generic_sbp;

	cache = clone_sb->clone_cache;
	if (!cache) {
		printk("clone_statfs: no cache\n");
		return -EINVAL;
	}

	EXIT;
	return cache->cache_filter->o_caops.cache_sops->statfs
		(cache->cache_sb, buf, bufsiz);
}

struct super_operations clone_super_ops =
{
	clonefs_read_inode,       /* read_inode */
	NULL,                   /* write_inode */
	NULL,	                /* put_inode */
	NULL,                   /* delete_inode */
	NULL,	                /* notify_change */
	clonefs_put_super,	/* put_super */
	NULL,			/* write_super */
	clonefs_statfs,   	/* statfs */
	NULL			/* remount_fs */
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
	struct inode            *cache_dir;
	struct dentry           *cache_dentry;
	struct inode            *cache_inode;
	struct dentry           *result;
	struct inode            *inode;
	struct snap_clone_info  *clone_sb;

	ENTRY;

	cache_dir = clonefs_get_inode(dir); 

	cache_dentry = d_alloc(dentry->d_parent, &dentry->d_name);
	if (!cache_dentry) {
                iput(cache_dir);
		EXIT;
		return ERR_PTR(-ENOENT);
	}

        /* Lock cache directory inode. */
	down(&cache_dir->i_sem);
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
		EXIT;
		return ERR_PTR(-ENOENT);
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
				cache_inode->i_ino, cache_inode->i_count, cache_dir->i_ino, 
				cache_dir->i_count);
	}

	d_unalloc(cache_dentry);
	iput(cache_dir);

        /*
         * Add 'inode' to the directory entry 'dentry'.
         */
	d_add(dentry, inode);

	EXIT;
        return NULL;
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
	cache_file->f_op = cache_inode->i_op->default_file_ops;
	cache_file->f_dentry = cache_dentry;
        cache_file->f_dentry->d_inode = cache_inode;
	EXIT;
        return ;
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
        return;
}

static int clonefs_readdir(struct file *file, void *dirent, 
			   filldir_t filldir)
{
	int result;
	struct inode *cache_inode;
        struct file open_file;
	struct dentry open_dentry;
	struct inode *inode=file->f_dentry->d_inode;

	ENTRY;

	if(!inode) {
 		EXIT;
		return -EINVAL;
	}
        cache_inode = clonefs_get_inode(inode);

	if (!cache_inode) {
		make_bad_inode(inode);
		EXIT;
		return -ENOMEM;
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
        EXIT;
	return result;
}

struct file_operations clonefs_dir_file_operations = {
        NULL,                   /* lseek */
        NULL,                   /* read -- bad */
        NULL,                   /* write */
        clonefs_readdir,        /* readdir */
        NULL,                   /* select */
        NULL,                   /* ioctl */
        NULL,                   /* mmap */
        NULL,                   /* open */
	NULL,
        NULL,                   /* release */
	NULL,                   /* fsync */
        NULL,                   
	NULL,
	NULL
};

struct inode_operations clonefs_dir_inode_operations =
{
	&clonefs_dir_file_operations,
	NULL,	        /* create */
	clonefs_lookup,   /* lookup */
	NULL,	        /* link */
	NULL,           /* unlink */
	NULL,	        /* symlink */
	NULL,	        /* mkdir */
	NULL,           /* rmdir */
	NULL,	        /* mknod */
	NULL,	        /* rename */
	NULL,           /* readlink */
	NULL,           /* follow_link */
	NULL,           /* readpage */
	NULL,           /* writepage */
	NULL,	        /* bmap */
	NULL,	        /* truncate */
	NULL,	        /* permission */
	NULL,           /* smap */
	NULL,           /* update page */
        NULL,           /* revalidate */
};


/* ***************** end of clonefs dir ops *******************  */ 
/* ***************** begin clonefs file ops *******************  */ 

int clonefs_readpage(struct file *file, struct page *page)
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
		EXIT;
		return -ENOMEM;
	}

	clonefs_prepare_snapfile(inode, file, cache_inode, &open_file,
			      &open_dentry);
	/* tell currentfs_readpage the primary inode number */
	open_dentry.d_fsdata = (void*)inode->i_ino;

	/* potemkin case: we are handed a directory inode */
	down(&cache_inode->i_sem);
        /* XXX - readpage NULL on directories... */
        if (cache_inode->i_op->readpage == NULL)
                printk("Yes, Grigori, directories are a problem.\n");
        else
	        cache_inode->i_op->readpage(&open_file, page);
	up(&cache_inode->i_sem);
	clonefs_restore_snapfile(inode, file, cache_inode, &open_file);
	iput(cache_inode);
        EXIT;
	return result;
}


struct file_operations clonefs_file_file_operations = {
        NULL,                   /* lseek */
        generic_file_read,      /* read -- bad */
        NULL,                   /* write */
        NULL,                   /* readdir */
        NULL,                   /* select */
        NULL,                   /* ioctl */
        generic_file_mmap,      /* mmap */
        NULL,                   /* open */
	NULL,
        NULL,                   /* release */
	NULL,                   /* fsync */
        NULL,                   
	NULL,
	NULL
};

struct inode_operations clonefs_file_inode_operations =
{
	&clonefs_file_file_operations,
	NULL,	        /* create */
	NULL,           /* lookup */
	NULL,	        /* link */
	NULL,           /* unlink */
	NULL,	        /* symlink */
	NULL,	        /* mkdir */
	NULL,           /* rmdir */
	NULL,	        /* mknod */
	NULL,	        /* rename */
	NULL,           /* readlink */
	NULL,           /* follow_link */
	clonefs_readpage, /* readpage */
	NULL,           /* writepage */
	NULL,	        /* bmap */
	NULL,	        /* truncate */
	NULL,	        /* permission */
	NULL,           /* smap */
	NULL,           /* update page */
        NULL,           /* revalidate */
};



/* ***************** end of clonefs file ops *******************  */ 
/* ***************** begin clonefs symlink ops *******************  */ 

int clonefs_readlink(struct dentry *dentry, char *buf, int len)
{
	int res;
	struct inode * cache_inode;
	struct inode * old_inode;

	ENTRY;

	cache_inode = clonefs_get_inode(dentry->d_inode); 

	res = -ENOENT;

	if ( ! cache_inode ) {
		CDEBUG(D_INODE, "clonefs_get_inode failed, NULL\n");
		EXIT;
		return res;	
	}
	
	/* XXX: shall we allocate a new dentry ? 
		The following is safe for ext2, etc. because ext2_readlink only
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

	EXIT;
	return res;
}

struct dentry * clonefs_follow_link(struct dentry * dentry,
                                        struct dentry *base,
                                        unsigned int follow)
{
	struct dentry * res;
	struct inode * cache_inode;
	struct inode * old_inode;

	ENTRY;
	res = ERR_PTR(-ENOENT);

	cache_inode = clonefs_get_inode(dentry->d_inode); 
	if ( ! cache_inode ) {
		CDEBUG(D_INODE, "clonefs_get_inode failed, NULL\n");
		EXIT;
		return res;	
	}

	/* XXX: shall we allocate a new dentry ? 
		The following is safe for ext2, etc. because ext2_follow_link 
		only use the inode info */

	/* save the old dentry inode */	
	old_inode = dentry->d_inode;
	/* set dentry inode to cache inode */
	dentry->d_inode = cache_inode;

	if ( cache_inode->i_op->follow_link ) {
		res = cache_inode->i_op->follow_link(dentry, base, follow); 
	}

	/* restore the old inode */
	dentry->d_inode = old_inode;

	iput(cache_inode);

	EXIT;
	return res;
}

struct inode_operations clonefs_symlink_inode_operations =
{
	NULL,               /* no file operations */      
	NULL,	            /* create */                  
	NULL,               /* lookup */                  
	NULL,	            /* link */                    
	NULL,               /* unlink */                  
	NULL,	            /* symlink */                 
	NULL,	            /* mkdir */                   
	NULL,               /* rmdir */                   
	NULL,	            /* mknod */                   
	NULL,	            /* rename */                  
	clonefs_readlink,   /* readlink */              
	clonefs_follow_link,/* follow_link */             
	NULL,               /* readpage */                
	NULL,               /* writepage */               
	NULL,	            /* bmap */                    
	NULL,	            /* truncate */                
	NULL,	            /* permission */              
	NULL,               /* smap */                    
	NULL,               /* update page */             
        NULL,               /* revalidate */          
};


