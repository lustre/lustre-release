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
#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/loop.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>
#include <linux/errno.h>
#include "snapfs_internal.h" 


#ifdef SNAP_DEBUG
unsigned int snap_debug_failcode = 0;
#endif

extern struct snap_cache *snap_init_cache(void);
extern inline void snap_cache_add(struct snap_cache *, kdev_t);
extern inline void snap_init_cache_hash(void);

extern int snap_get_index_from_name (int tableno, char *name);


extern struct snapshot_operations ext3_snap_operations;
extern struct journal_ops snap_ext3_journal_ops;
                                                                                                                                                                                                     
static void put_filesystem(struct file_system_type *fs)
{
	if (fs->owner)
		__MOD_DEC_USE_COUNT(fs->owner);
}

static struct vfsmount* get_vfsmount(struct super_block *sb)
{
	struct vfsmount	*rootmnt, *mnt, *ret = NULL;
	struct list_head *end, *list;

	rootmnt = mntget(current->fs->rootmnt);
	end = list = &rootmnt->mnt_list;
	do {
		mnt = list_entry(list, struct vfsmount, mnt_list);
		if (mnt->mnt_sb == sb) {
			ret = mnt;
			break;
		}
		list = list->next;
	} while (end != list);
	mntput(current->fs->rootmnt);
	return ret;
}

void get_snap_current_mnt(struct super_block *sb)
{
	struct vfsmount *mnt;

	mnt = get_vfsmount(sb);
	if (mnt) 
		mntget(mnt);
}
void put_snap_current_mnt(struct super_block *sb)
{
	struct vfsmount *mnt;

	mnt = get_vfsmount(sb);
	if (mnt) 
		mntput(mnt);
}

/* In get_opt we get options in opt, value in opt_value
 * we must remember to free opt and opt_value*/
static char * snapfs_options(char *options, char **cache_type, 
			     char **cow_type, char **snaptable)
{
	struct option *opt_value;
	char *pos;
	
	while (!(get_opt(&opt_value, &pos))) { 			
		if (!strcmp(opt_value->opt, "cache_type")) {
			if (cache_type != NULL)
				*cache_type = opt_value->value;
		} else if (!strcmp(opt_value->opt, "cow_type")) {
			if (cow_type != NULL)
				*cow_type = opt_value->value;
		} else if (!strcmp(opt_value->opt, "snap_table")) {
			if (snaptable != NULL)
				*snaptable = opt_value->value;
		} else {
			break;
		}
	}
	if (!*cache_type && cache_type) 
		*cache_type = "ext3"; 
	if (!*cow_type && cow_type) 
		*cow_type = "block";
	if (!*snaptable && snaptable)
		*snaptable = "0";
	return pos;
}
int snapfs_remount(struct super_block * sb, int *flags, char *data)
{
	struct super_operations *sops;
	struct snap_cache *cache = NULL;
	char *snapno = NULL, *pos = NULL;
	char *cache_data = NULL;
	int err = 0;

	ENTRY;
	CDEBUG(D_SUPER, "remount opts: %s\n", data ? (char *)data : "(none)");

	if ((err = init_option(data))) {
		GOTO(out_err, 0); 	
	}
	cache = snap_find_cache(sb->s_dev);
	if (!cache) {
		CERROR("cannot find cache on remount\n");
		GOTO(out_err, err = -ENODEV);
	}

	/* If an option has not yet been set, we allow it to be set on
	 * remount.  If an option already has a value, we pass NULL for
	 * the option pointer, which means that the snapfs option
	 * will be parsed but discarded.
	 */
	cache_data = snapfs_options(data, NULL, NULL, &snapno);

	CDEBUG(D_SUPER, "cache_data at %p is: %s\n", cache_data, cache_data); 
	sops = filter_c2csops(cache->cache_filter);
	if (sops->remount_fs) 
		err = sops->remount_fs(sb, flags, pos);
out_err:
	cleanup_option();
	RETURN(err);
}
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
	char *cache_type = NULL, *cow_type = NULL;
	char *snapno = NULL, *cache_data = NULL;
	int tableno, rc = 0;

	ENTRY;

	init_option(data);
	cache_data = snapfs_options(data, &cache_type, &cow_type, &snapno);
	/* set up the cache */
	cache = snap_init_cache();
	if ( !cache ) {
		CERROR("snapfs_read_super: failure allocating cache.\n");
		GOTO(out_err, rc = -EINVAL);
	}
	/*get cache and cache filter type */	
	fstype = get_fs_type((const char *)cache_type);

	if ( !fstype || !fstype->read_super) {
		CERROR("Unrecognized cache type %s \n", cache_type);
		GOTO(out_err, rc = -EINVAL);
	}
	cache->cache_filter = filter_get_filter_fs((const char *)cache_type); 
	if (!cache->cache_filter) {
		CERROR("Unrecognized cache type %s \n", cache_type);
		GOTO(out_err, rc = -EINVAL);
	}

	/*
         * Read the underlying file system superblock - ext2, ext3, reiser.
         * This performs the underlying mount operation. The snapfs options
         * have been removed from 'cache_data'.
         *
         * Note: It's assumed that sb is always returned.
         */
	if (fstype->read_super(sb, cache_data, silent) != sb) {
		CERROR("snapfs: cache mount failure.\n");
		GOTO(out_err, rc = -EINVAL);
        }
	/*
         * We now know the dev of the cache: hash the cache.
         *
         * 'cache' is the struct snap_cache allocated for this
         * snapfs mount.
         */
	snap_cache_add(cache, sb->s_dev);

	tableno = simple_strtoul(snapno, NULL, 0);
	cache->cache_snap_tableno = tableno;
	CDEBUG(D_SUPER, "get tableno %d\n", cache->cache_snap_tableno);
	
	/*
         * make sure we have our own super operations
         *
         * Initialize or re-initialize the cache->cache_ops shared
         * struct snap_ops structure set based on the underlying
         * file system type.
         */
	filter_setup_super_ops(cache->cache_filter, sb->s_op,
			       &currentfs_super_ops);
	sb->s_op = filter_c2usops(cache->cache_filter); 
        /*
         * Save pointers in the snap_cache structure to the
         * snapfs and underlying file system superblocks.
         */
	cache->cache_sb = sb; /* Underlying file system superblock. */

	/* set up snapshot ops, handle COMPAT_FEATUREs */
	if( 0 ){
	}
	else if (strcmp (cache_type,"ext3") == 0 || !cache_type){
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
		sb->u.ext3_sb.s_last_cowed_pri_ino = 0;
		sb->u.ext3_sb.s_first_cowed_pri_ino = 0;
	}
	/* now get our own directory operations */
	if ( sb->s_root && sb->s_root->d_inode ) {
		filter_setup_dir_ops(cache->cache_filter, 
				     sb->s_root->d_inode,
				     &currentfs_dir_iops, &currentfs_dir_fops);
		sb->s_root->d_inode->i_op =filter_c2udiops(cache->cache_filter);

		CDEBUG(D_SUPER, "lookup at %p\n", 
		       sb->s_root->d_inode->i_op->lookup);
		/* XXX is this needed ?? ext3 do not have dentry operations*/
		filter_setup_dentry_ops(cache->cache_filter, 
					sb->s_root->d_op, 
					&currentfs_dentry_ops);
		sb->s_root->d_op = filter_c2udops(cache->cache_filter);
		init_filter_data(sb->s_root->d_inode, 0); 
	}
        /*
         * Save a pointer to the snap_cache structure in the
         * "snap_current" superblock.
         */
        (struct snap_cache *) sb->u.generic_sbp = cache;

	snapfs_read_snaptable(cache, tableno);
	
	CDEBUG(D_SUPER, "sb %lx, sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) sb->u.generic_sbp);
out_err:
	cleanup_option();
	/* Inc in get_fs_type, Dec in put_fs_type*/
	if (fstype)
		put_filesystem(fstype);
	if (rc) 
		return NULL;
	return sb; 
}

static DECLARE_FSTYPE_DEV(snapfs_current_type, 
		          "snap_current", snapfs_read_super);

/* Find the options for the clone. These consist of a cache device
   and an index in the snaptable associated with that device. 
*/
static char *clonefs_options(char *options, char **devstr, char **namestr)
{
	struct option *opt_value = NULL;
	char *pos;
	
	while (!(get_opt(&opt_value, &pos))) { 			
		if (!strcmp(opt_value->opt, "dev")) {
			if (devstr != NULL)
				*devstr = opt_value->value;
		} else if (!strcmp(opt_value->opt, "name")) {
			if (namestr != NULL)
				*namestr = opt_value->value;
		} else {
			break;
		}
	}
	return pos;
}
static int snap_cache_lookup_ino_cb(struct snap_cache *cache, void *in, unsigned long *out)
{
	ino_t ino = *((unsigned long*)in);

	if (cache) {
		struct super_block *sb = cache->cache_sb;
		kdev_t dev = sb->s_dev;

		if (MAJOR(dev) != LOOP_MAJOR) 
			return 0;
		if (sb->s_bdev->bd_op && sb->s_bdev->bd_op->ioctl) {
			struct inode *inode = sb->s_bdev->bd_inode;
			struct loop_info loop_info;

			sb->s_bdev->bd_op->ioctl(inode, NULL, LOOP_GET_INFO, 
					         (unsigned long)&loop_info);
			
			if(loop_info.lo_inode == ino) {
				*out = sb->s_dev; 
				return 1;
			}
		}
	}
	return 0;	
}
static int snapfs_path2dev(char *dev_path, kdev_t *dev)
{
	struct dentry *dentry;
	struct nameidata nd;
	int error = 0;
	
	if (path_init(dev_path, LOOKUP_FOLLOW, &nd)) {
		error = path_walk(dev_path, &nd);
		if (error)
			return error;
	} else
		return -EINVAL;

	dentry = nd.dentry;

	if (!dentry->d_inode || is_bad_inode(dentry->d_inode) || 
	    (!S_ISBLK(dentry->d_inode->i_mode) && 
             !S_ISREG(dentry->d_inode->i_mode))){
		path_release(&nd);
		return -ENODEV;
	}
	if (S_ISBLK(dentry->d_inode->i_mode)) {
		*dev = kdev_t_to_nr(dentry->d_inode->i_rdev);
	} else {
		/*here we must walk through all the snap cache to 
		 *find the loop device */
		kdev_t tmp;

		if (snap_cache_process(snap_cache_lookup_ino_cb,
				       &dentry->d_inode->i_ino, 
				       (unsigned long*)&tmp))
			return -EINVAL;
		*dev = tmp;
	}
	path_release(&nd);
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
	struct inode *root_inode = NULL;
	char *devstr = NULL, *namestr = NULL;
	char *cache_data;
	kdev_t dev;
	int index;
	ino_t root_ino;
	int err = 0;

	ENTRY;

	CDEBUG(D_SUPER, "mount opts: %s\n", data ? (char *)data : "(none)");
	
	init_option(data);
	/* read and validate options */
	cache_data = clonefs_options(data, &devstr, &namestr);
	if (*cache_data) {
		CERROR("clonefs: invalid mount option %s\n", (char*)data);
		GOTO(out_err, err=-EINVAL);
	}
	if (!namestr || !devstr) {
		CERROR("snapfs: mount options name and dev mandatory\n");
		GOTO(out_err, err=-EINVAL);
	}

	err = snapfs_path2dev(devstr, &dev);
	if ( err ) {
		CERROR("snap: incorrect device option %s\n", devstr);
		GOTO(out_err, err=-EINVAL);
	}
	
	snap_cache = snap_find_cache(dev);
	if ( !snap_cache ) {
		CERROR("snap: incorrect device option %s\n", devstr);
		GOTO(out_err, err=-EINVAL);
	}

	index = snap_get_index_from_name (snap_cache->cache_snap_tableno, 
					namestr);
	CDEBUG(D_SUPER, "tableno %d, name %s, get index %d\n", 
			snap_cache->cache_snap_tableno, namestr, index);

	if(index < 0 ) {
		CERROR("No valid index for name %s passed to mount\n",namestr); 
		GOTO(out_err, err=-EINVAL);
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

	sb->s_root = d_alloc_root(root_inode);
	
	if (!sb->s_root) {
		list_del(&clone_sb->clone_list_entry);
		GOTO(out_err, err=-EINVAL);
	}
	dget(snap_cache->cache_sb->s_root);

	CDEBUG(D_SUPER, "sb %lx, &sb->u.generic_sbp: %lx\n",
                (ulong) sb, (ulong) &sb->u.generic_sbp);
 	
	get_snap_current_mnt(snap_cache->cache_sb);
 out_err:
	cleanup_option();
	if (err)
		return NULL;
	return sb;
}

static DECLARE_FSTYPE(snapfs_clone_type, "snap_clone", clone_read_super, 0);

int init_snapfs(void)
{
	int status;

	snap_init_cache_hash();
	init_filter_info_cache();

	status = register_filesystem(&snapfs_current_type);
	if (status) {
		CERROR("snapfs: failed in register current filesystem!\n");
	}

	status = register_filesystem(&snapfs_clone_type);
	if (status) {
		unregister_filesystem(&snapfs_current_type);
		CERROR("snapfs: failed in register clone filesystem!\n");
	}

	return status;
}



int cleanup_snapfs(void)
{
	int err;

	ENTRY;

	cleanup_filter_info_cache();
	err = unregister_filesystem(&snapfs_clone_type);
	if ( err ) {
		CERROR("snapfs: failed to unregister clone filesystem\n");
	}
	err = unregister_filesystem(&snapfs_current_type);
	if ( err ) {
		CERROR("snapfs: failed to unregister filesystem\n");
	}
	return 0;
}
