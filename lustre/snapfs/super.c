/*
 *  snap_current
 *
 *  Copyright (C) 1998 Peter J. Braam
 *  Copyright (C) 2000 Stelias Computing, Inc.
 *  Copyright (C) 2000 Red Hat, Inc.
 *  Copyright (C) 2000 Mountain View Data, Inc.
 *
 *  Author: Peter J. Braam <braam@mountainviewdata.com>
 */


#include <stdarg.h>

#include <asm/bitops.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#ifdef CONFIG_SNAPFS_EXT2
#include <linux/ext2_fs.h>
#endif
#ifdef CONFIG_SNAPFS_EXT3
#include <linux/ext3_fs.h>
#endif

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
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

#ifdef SNAP_DEBUG
long snap_vmemory = 0;
long snap_kmemory = 0;
unsigned int snap_debug_failcode = 0;
#endif

extern struct snap_cache *snap_init_cache(void);
extern inline void snap_cache_add(struct snap_cache *, kdev_t);
extern inline void snap_init_cache_hash(void);

extern int snap_get_index_from_name (int tableno, char *name);

#ifdef CONFIG_SNAPFS_EXT2
extern struct snapshot_operations ext2_snap_operations;
extern struct journal_ops snap_ext2_journal_ops;
#endif

#ifdef CONFIG_SNAPFS_EXT3
extern struct snapshot_operations ext3_snap_operations;
extern struct journal_ops snap_ext3_journal_ops;
#endif

/* returns an allocated string, copied out from data if opt is found */
static char *read_opt(const char *opt, char *data)
{
	char *value;
	char *retval;

	CDEBUG(D_SUPER, "option: %s, data %s\n", opt, data);
	if ( strncmp(opt, data, strlen(opt)) )
		return NULL;

	if ( (value = strchr(data, '=')) == NULL )
		return NULL;

	value++;
	SNAP_ALLOC(retval, char *, strlen(value) + 1);
	if ( !retval ) {
		printk("snapfs: Out of memory!\n");
		return NULL;
	}

	strcpy(retval, value);
	CDEBUG(D_SUPER, "Assigned option: %s, value %s\n", opt, retval);
	return retval;
}

static inline void store_opt(char **dst, char *opt)
{
	if (dst) {
		if (*dst)
			SNAP_FREE(*dst, strlen(*dst) + 1);
		*dst = opt;
	} else
		SNAP_FREE(opt, strlen(opt) + 1);
}

/* Find the options for snapfs in "options", saving them into the
 * passed pointers.  If the pointer is null, the option is discarded.
 * Copy out all non-snapfs options into cache_data (to be passed
 * to the read_super operation of the cache).  The return value will
 * be a pointer to the end of the cache_data.
 */
static char *snapfs_options(char *options, char *cache_data,
			    char **cache_type, char **cow_type,
			    char **snaptable)
{
	char *this_char;
	char *cache_data_end = cache_data;

	/* set the defaults here */
	if (cache_type && !*cache_type) {
		SNAP_ALLOC(*cache_type, char *, strlen("ext2") + 1);
		strcpy(*cache_type, "ext2");
	}
	if (cow_type && !*cow_type) {
		SNAP_ALLOC(*cow_type, char *, strlen("block") + 1);
		strcpy(*cow_type, "block");
	}
	if (snaptable && !*snaptable) {
		SNAP_ALLOC(*snaptable, char *, strlen("-1")+1);
		strcpy(*snaptable, "-1");
	}

	if (!options || !cache_data)
		return cache_data_end;

	CDEBUG(D_SUPER, "parsing options\n");
	for (this_char = strtok (options, ",");
	     this_char != NULL;
	     this_char = strtok (NULL, ",")) {
		char *opt;
		CDEBUG(D_SUPER, "this_char %s\n", this_char);

		if ( (opt = read_opt("cache_type", this_char)) ) {
			store_opt(cache_type, opt);
			continue;
		}
		if ( (opt = read_opt("cow_type", this_char)) ){
			store_opt(cow_type, opt);
			continue;
		}
		if ( (opt = read_opt("table", this_char)) ) {
			store_opt(snaptable, opt);
			continue;
		}

		cache_data_end += sprintf(cache_data_end, "%s%s",
					  cache_data_end != cache_data ? ",":"",
					  this_char);
	}

	return cache_data_end;
}

int snapfs_remount(struct super_block * sb, int *flags, char *data)
{
	char *cache_data = NULL;
	char *snapno = NULL;
	char *cache_data_end;
	struct snap_cache *cache = NULL;
	struct super_operations *sops;
	int err = 0;

	ENTRY;
	CDEBUG(D_MALLOC, "before remount: kmem %ld, vmem %ld\n",
	       snap_kmemory, snap_vmemory);
	CDEBUG(D_SUPER, "remount opts: %s\n", data ? (char *)data : "(none)");
	if (data) {
		/* reserve space for the cache's data */
		SNAP_ALLOC(cache_data, void *, PAGE_SIZE);
		if ( !cache_data ) {
			err = -ENOMEM;
			EXIT;
			goto out_err;
		}
	}

	cache = snap_find_cache(sb->s_dev);
	if (!cache) {
		printk(__FUNCTION__ ": cannot find cache on remount\n");
		err = -ENODEV;
		EXIT;
		goto out_err;
	}

	/* If an option has not yet been set, we allow it to be set on
	 * remount.  If an option already has a value, we pass NULL for
	 * the option pointer, which means that the snapfs option
	 * will be parsed but discarded.
	 */
	cache_data_end = snapfs_options(data, cache_data, NULL, NULL, &snapno);

	if (cache_data) {
		if (cache_data_end == cache_data) {
			SNAP_FREE(cache_data, PAGE_SIZE);
			cache_data = NULL;
		} else {
			CDEBUG(D_SUPER, "cache_data at %p is: %s\n", cache_data,
			       cache_data);
		}
	}


	sops = filter_c2csops(cache->cache_filter);
	if (sops->remount_fs) {
		err = sops->remount_fs(sb, flags, cache_data);
	}

	CDEBUG(D_MALLOC, "after remount: kmem %ld, vmem %ld\n",
	       snap_kmemory, snap_vmemory);
	EXIT;
out_err:
	if (cache_data)
		SNAP_FREE(cache_data, PAGE_SIZE);
	return err;
}

/* XXXX remount: needed if snapfs was mounted RO at boot time
   without a snaptable 
*/ 


/*
 * snapfs super block read.
 *
 * Allocate a struct snap_cache, determine the underlying fs type,
 * read the underlying fs superblock, save the underlying fs ops,
 * and then replace them with snapfs ops.
 *
 * Remove the snapfs options before passing to underlying fs.
 */
struct super_block *
snapfs_read_super (
        struct super_block *sb,
        void *data,
        int silent)
{
	struct file_system_type *fstype;
	struct snap_cache *cache = NULL;
	char *cache_data = NULL;
	char *cache_data_end;
	char *cache_type = NULL;
	char *cow_type = NULL;
	char *snapno = NULL;
	char *endptr;
	int tableno;

	ENTRY;
	CDEBUG(D_MALLOC, "before parsing: kmem %ld, vmem %ld\n",
	       snap_kmemory, snap_vmemory);

	/* reserve space for the cache's data */
	SNAP_ALLOC(cache_data, void *, PAGE_SIZE);
	if ( !cache_data ) {
		printk("snapfs_read_super: Cannot allocate data page.\n");
		EXIT;
		goto out_err;
	}

	CDEBUG(D_SUPER, "mount opts: %s\n", data ? (char *)data : "(none)");

	/* read and validate options */
	cache_data_end = snapfs_options(data, cache_data, &cache_type, &cow_type, &snapno);

	/* Need to free cache_type and snapno when it's not in use */

	/* was there anything for the cache filesystem in the data? */
	if (cache_data_end == cache_data) {
		SNAP_FREE(cache_data, PAGE_SIZE);
		cache_data = NULL;
	} else {
		CDEBUG(D_SUPER, "cache_data at %p is: %s\n", cache_data,
		       cache_data);
	}

	/* set up the cache */
	cache = snap_init_cache();
	if ( !cache ) {
		printk("snapfs_read_super: failure allocating cache.\n");
		EXIT;
		goto out_err;
	}

	fstype = get_fs_type(cache_type);
	if ( !fstype || !fstype->read_super) {
		EXIT;
		goto out_err;
	}
	
	cache->cache_filter = filter_get_filter_fs((const char *)cache_type); 
	/* XXX if cache->cache_filter==NULL?although it's rare ***/


	/*
         * Read the underlying file system superblock - ext2, ext3, reiser.
         * This performs the underlying mount operation. The snapfs options
         * have been removed from 'cache_data'.
         *
         * Note: It's assumed that sb is always returned.
         */
	CDEBUG(D_SUPER, "\n");
	if (fstype->read_super(sb, cache_data, silent) != sb) {
		printk("snapfs: cache mount failure.\n");
		EXIT;
		goto out_err;
        }

	/* XXX now look at the flags in the superblock and determine if this 
	       is a block cow file system or a file cow fs.  Then assign the 
	       snap operations accordingly.  This goes in the sections for ext2/ext3/xfs etc
        */ 

	/* this might have been freed above */
	CDEBUG(D_SUPER, "\n");
	if (cache_data) {
		SNAP_FREE(cache_data, PAGE_SIZE);
		cache_data = NULL;
	}


	/*
         * We now know the dev of the cache: hash the cache.
         *
         * 'cache' is the struct snap_cache allocated for this
         * snapfs mount.
         */
	CDEBUG(D_SUPER, "\n");
	snap_cache_add(cache, sb->s_dev);

	tableno  =  simple_strtoul(snapno, &endptr, 0);
	cache->cache_snap_tableno = tableno;

	CDEBUG(D_SUPER, "get tableno %d\n", cache->cache_snap_tableno);

	/*
         * make sure we have our own super operations
         *
         * Initialize or re-initialize the cache->cache_ops shared
         * struct snap_ops structure set based on the underlying
         * file system type.
         */
	CDEBUG(D_SUPER, "\n");
	filter_setup_super_ops(cache->cache_filter, sb->s_op,
			       &currentfs_super_ops);
	CDEBUG(D_SUPER, "\n");
	sb->s_op = filter_c2usops(cache->cache_filter); 
        /*
         * Save pointers in the snap_cache structure to the
         * snapfs and underlying file system superblocks.
         */
	cache->cache_sb = sb; /* Underlying file system superblock. */

	/* set up snapshot ops, handle COMPAT_FEATUREs */
	if( 0 ){
	}
#ifdef CONFIG_SNAPFS_EXT2
	else if ( strcmp (cache_type,"ext2") == 0 ){
		cache->cache_type = FILTER_FS_EXT2;
		filter_setup_snapshot_ops(cache->cache_filter, 
					&ext2_snap_operations);
		filter_setup_journal_ops(cache->cache_filter,
					&snap_ext2_journal_ops);
		if( !EXT2_HAS_COMPAT_FEATURE(sb, EXT2_FEATURE_COMPAT_SNAPFS) ){
			if( strcmp(cow_type, "block")==0 ){
				sb->u.ext2_sb.s_feature_compat |=
					EXT2_FEATURE_COMPAT_BLOCKCOW;
				sb->u.ext2_sb.s_es->s_feature_compat |=
					cpu_to_le32(EXT2_FEATURE_COMPAT_BLOCKCOW);
			}
		}
                sb->u.ext2_sb.s_last_cowed_ino = 0;
	}
#endif
#ifdef CONFIG_SNAPFS_EXT3
	else if ( strcmp (cache_type,"ext3") == 0 ){
		cache->cache_type = FILTER_FS_EXT3;
		filter_setup_snapshot_ops(cache->cache_filter,
			       		&ext3_snap_operations);
		filter_setup_journal_ops(cache->cache_filter,
					&snap_ext3_journal_ops);
		if( !EXT3_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_SNAPFS) ){
			if( strcmp(cow_type, "block")==0 ){
				sb->u.ext3_sb.s_es->s_feature_compat |=
					cpu_to_le32(EXT3_FEATURE_COMPAT_BLOCKCOW);
			}
		}
		sb->u.ext3_sb.s_last_cowed_ino = 0;
	}
#endif

	CDEBUG(D_SUPER, "\n");
	/* now get our own directory operations */
	if ( sb->s_root && sb->s_root->d_inode ) {
		CDEBUG(D_SUPER, "\n");
		filter_setup_dir_ops(cache->cache_filter, 
				     sb->s_root->d_inode->i_op,
				     &currentfs_dir_iops);
		CDEBUG(D_SUPER, "\n");
		sb->s_root->d_inode->i_op =filter_c2udiops(cache->cache_filter);
//	CDEBUG(D_SUPER, "\n");
//		sb->s_root->d_inode->i_snapop = ext2_snapops();

		CDEBUG(D_SUPER, "lookup at %p\n", 
		       sb->s_root->d_inode->i_op->lookup);
#if 0
		/* XXX is this needed ?? */
		filter_setup_dentry_ops(cache->cache_filter, 
					sb->s_root->d_op, 
					&currentfs_dentry_ops);
		sb->s_root->d_op = filter_c2udops(cache->cache_filter);
#endif
	}
        /*
         * Save a pointer to the snap_cache structure in the
         * "snap_current" superblock.
         */
        (struct snap_cache *) sb->u.generic_sbp = cache;
	CDEBUG(D_SUPER, "sb %lx, sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) sb->u.generic_sbp);

	/* we can free snapno and cache_type now, because it's not used */
	if (snapno) {
		SNAP_FREE(snapno, strlen(snapno) + 1);
		snapno = NULL;
	}
	if (cache_type) {
		SNAP_FREE(cache_type, strlen(cache_type) + 1);
		snapno = NULL;
	}
	if (cow_type) {
		SNAP_FREE(cow_type, strlen(cow_type) + 1);
		cow_type = NULL;
	}

	CDEBUG(D_MALLOC, "after mounting: kmem %ld, vmem %ld\n",
	       snap_kmemory, snap_vmemory);

	MOD_INC_USE_COUNT;
	EXIT;
	return sb;

 out_err:
	CDEBUG(D_SUPER, "out_err called\n");
	if (cache)
		SNAP_FREE(cache, sizeof(struct snap_cache));
	if (cache_data)
		SNAP_FREE(cache_data, PAGE_SIZE);
	if (snapno)
		SNAP_FREE(snapno, strlen(snapno) + 1);
	if (cache_type)
		SNAP_FREE(cache_type, strlen(cache_type) + 1);
	if (cow_type)
		SNAP_FREE(cow_type, strlen(cow_type) + 1);

	CDEBUG(D_MALLOC, "mount error exit: kmem %ld, vmem %ld\n",
	       snap_kmemory, snap_vmemory);
	return NULL;
}


struct file_system_type snapfs_current_type = {
	"snap_current",
	FS_REQUIRES_DEV, /* can use Ibaskets when ext2 does */
	snapfs_read_super,
	NULL
};


/* Find the options for the clone. These consist of a cache device
   and an index in the snaptable associated with that device. 
*/
static char *clonefs_options(char *options, char *cache_data,
			    char **devstr, char **namestr)
{
	char *this_char;
	char *cache_data_end = cache_data;

	if (!options || !cache_data)
		return cache_data_end;

	CDEBUG(D_SUPER, "parsing options\n");
	for (this_char = strtok (options, ",");
	     this_char != NULL;
	     this_char = strtok (NULL, ",")) {
		char *opt;
		CDEBUG(D_SUPER, "this_char %s\n", this_char);

		if ( (opt = read_opt("dev", this_char)) ) {
			store_opt(devstr, opt);
			continue;
		}
		if ( (opt = read_opt("name", this_char)) ) {
			store_opt(namestr, opt);
			continue;
		}

		cache_data_end += sprintf(cache_data_end, "%s%s",
					  cache_data_end != cache_data ? ",":"",
					  this_char);
	}

	return cache_data_end;
}

static int snapfs_path2dev(char *dev_path, kdev_t *dev)
{
	struct dentry *dentry;

	dentry = lookup_dentry(dev_path, NULL, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!dentry->d_inode)
		return -ENODEV;

	if (!S_ISBLK(dentry->d_inode->i_mode))
		return -ENODEV;

	*dev = dentry->d_inode->i_rdev;

	return 0;
}


extern struct super_operations clone_super_ops;

/*
 * We always need to remove the snapfs options before passing
 * to bottom FS.
 */
struct super_block *
clone_read_super(
        struct super_block *sb,
        void *data,
        int silent)
{
	struct snap_clone_info *clone_sb;
	struct snap_cache *snap_cache = NULL;
	int err;
	char *cache_data = NULL;
	char *cache_data_end;
	char *devstr = NULL;
	kdev_t dev;
	char *namestr = NULL;
	//char *endptr;
	int index;
	ino_t root_ino;
	struct inode *root_inode;

	ENTRY;

	CDEBUG(D_MALLOC, "before parsing: kmem %ld, vmem %ld\n",
	       snap_kmemory, snap_vmemory);

	/* reserve space for the cache's data */
	SNAP_ALLOC(cache_data, void *, PAGE_SIZE);
	if ( !cache_data ) {
		printk("clone_read_super: Cannot allocate data page.\n");
		EXIT;
		goto out_err;
	}

	CDEBUG(D_SUPER, "mount opts: %s\n", data ? (char *)data : "(none)");

	/* read and validate options */
	cache_data_end = clonefs_options(data, cache_data, &devstr, &namestr);

	/* was there anything for the cache filesystem in the data? */
	if (cache_data_end == cache_data) {
		SNAP_FREE(cache_data, PAGE_SIZE);
		cache_data = NULL;
	} else {
		printk("clonefs: invalid mount option %s\n", cache_data);
		EXIT;
		goto out_err;
	}

	if (!namestr || !devstr) {
		printk("snapfs: mount options name and dev mandatory\n");
		EXIT;
		goto out_err;
	}

	err = snapfs_path2dev(devstr, &dev);
	if ( err ) {
		printk("snap: incorrect device option %s\n", devstr);
		EXIT;
		goto out_err;
	}
	
	snap_cache = snap_find_cache(dev);
	if ( !snap_cache ) {
		printk("snap: incorrect device option %s\n", devstr);
		EXIT;
		goto out_err;
	}

	/*index =  simple_strtoul(indexstr, &endptr, 0);
	if ( indexstr == endptr ) {
		printk("No valid index passed to mount\n"); 
		EXIT;
		goto out_err;
	}
	*/

	index = snap_get_index_from_name (snap_cache->cache_snap_tableno, 
					namestr);
	CDEBUG(D_SUPER, "tableno %d, name %s, get index %d\n", 
			snap_cache->cache_snap_tableno, namestr, index);

	if(index < 0 ) {
		printk("No valid index for name %s passed to mount\n",namestr); 
		EXIT;
		goto out_err;
	}

        /*
         * Force clone fs to be read-only.
         *
         * XXX - Is there a way to change the mount options too so
         * the fs is listed as RO by mount?
         */
        sb->s_flags |= MS_RDONLY;

	/* set up the super block */
	clone_sb = (struct snap_clone_info *)&sb->u.generic_sbp;
	list_add(&clone_sb->clone_list_entry, &snap_cache->cache_clone_list);
	clone_sb->clone_cache = snap_cache;
	clone_sb->clone_index = index;
	sb->s_op = &clone_super_ops;

	root_ino = snap_cache->cache_sb->s_root->d_inode->i_ino;
	root_inode = iget(sb, root_ino);

	CDEBUG(D_SUPER, "readinode %p, root ino %ld, root inode at %p\n",
	       sb->s_op->read_inode, root_ino, root_inode);

	sb->s_root = d_alloc_root(root_inode, NULL);
	if (!sb->s_root) {
		list_del(&clone_sb->clone_list_entry);
		sb = NULL;
	}

	dget( snap_cache->cache_sb->s_root );

	if (cache_data)
		SNAP_FREE(cache_data, PAGE_SIZE);
	if (devstr)
		SNAP_FREE(devstr, strlen(devstr) + 1);
	if (namestr)
		SNAP_FREE(namestr, strlen(namestr) + 1);
	CDEBUG(D_SUPER, "sb %lx, &sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) &sb->u.generic_sbp);

	MOD_INC_USE_COUNT;
	EXIT;
	return sb;
 out_err:
	CDEBUG(D_MALLOC, "mount error exit: kmem %ld, vmem %ld\n",
	       snap_kmemory, snap_vmemory);
	return NULL;
}


struct file_system_type snapfs_clone_type = {
	"snap_clone",
	0,
	clone_read_super,
	NULL
};


int init_snapfs(void)
{
	int status;

	snap_init_cache_hash();

	status = register_filesystem(&snapfs_current_type);
	if (status) {
		printk("snapfs: failed in register current filesystem!\n");
	}
	status = register_filesystem(&snapfs_clone_type);
	if (status) {
		unregister_filesystem(&snapfs_current_type);
		printk("snapfs: failed in register clone filesystem!\n");
	}
	return status;
}



int cleanup_snapfs(void)
{
	int err;

	ENTRY;

	err = unregister_filesystem(&snapfs_clone_type);
	if ( err ) {
		printk("snapfs: failed to unregister clone filesystem\n");
	}
	err = unregister_filesystem(&snapfs_current_type);
	if ( err ) {
		printk("snapfs: failed to unregister filesystem\n");
	}

	return 0;
}
