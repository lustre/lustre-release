/*
 * dir.c
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

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

#ifdef CONFIG_SNAPFS_EXT3
void ext3_orphan_del(handle_t *handle, struct inode *inode);
#endif

static ino_t get_parent_ino(struct inode * inode)
{
	ino_t ino = 0;
	struct dentry * dentry;

	if (list_empty(&inode->i_dentry)) {
       		printk("snapfs ERROR: no dentry for ino %lu\n", inode->i_ino);
                return 0;
        }

       	dentry = dget(list_entry(inode->i_dentry.next, struct dentry, d_alias));

        if(dentry->d_parent->d_inode)
		ino = dentry->d_parent->d_inode->i_ino;

	dput(dentry);
	return ino;

}

static void d_unadd_iput(struct dentry *dentry)
{
	list_del(&dentry->d_alias);
	INIT_LIST_HEAD(&dentry->d_alias);
	list_del(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_hash);
	iput(dentry->d_inode);
	dentry->d_inode = NULL;
}

/* XXX check the return values */
static struct dentry *currentfs_lookup(struct inode * dir,struct dentry *dentry)
{
	struct snap_cache *cache;
	struct dentry *rc;
	struct inode_operations *iops;
	struct inode *cache_inode;
	int index;

	ENTRY;

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return ERR_PTR(-EINVAL);
	}

	if ( dentry->d_name.len == strlen(".snap") &&
	     (memcmp(dentry->d_name.name, ".snap", strlen(".snap")) == 0) ) {
		struct inode *snap;
		ino_t ino;

		/* Don't permit .snap in clonefs */
		if( dentry->d_sb != cache->cache_sb )
			return ERR_PTR(-ENOENT);

		/* Don't permit .snap under .snap */
		if( currentfs_is_under_dotsnap(dentry) )
			return ERR_PTR(-ENOENT);

		ino = 0xF0000000 | dir->i_ino;
		snap = iget(dir->i_sb, ino);
		CDEBUG(D_INODE, ".snap inode ino %ld, mode %o\n", snap->i_ino, snap->i_mode);
		d_add(dentry, snap);
		EXIT;
		return NULL;
	}

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops || !iops->lookup) {
		EXIT;
		return ERR_PTR(-EINVAL);
	}

	rc = iops->lookup(dir, dentry);
	if ( rc || !dentry->d_inode) {
		EXIT;
		return NULL;
	}
	
	/*
	 * If we are under dotsnap, we need save extra data into
	 * dentry->d_fsdata:  For dir, we only need _this_ snapshot's index; 
	 * For others, save primary ino, with it we could found index later
	 * anyway
	 */
	cache_inode = dentry->d_inode;
	if ( (index = currentfs_is_under_dotsnap(dentry)) ) {
		struct snapshot_operations *snapops;
		struct inode *ind_inode;
		ino_t pri_ino, ind_ino;
	       
		pri_ino = cache_inode->i_ino;
		snapops = filter_c2csnapops(cache->cache_filter);
		if( !snapops )
			goto err_out;

		ind_ino = snapops->get_indirect_ino(cache_inode, index);
		if( ind_ino <=0 && ind_ino != -ENOATTR )
			goto err_out;
		else if( ind_ino != -ENOATTR ){
			ind_inode = iget(cache_inode->i_sb, ind_ino);
			if( !ind_inode ){
				goto err_out;
			}
			list_del(&dentry->d_alias);
			INIT_LIST_HEAD(&dentry->d_alias);
			list_add(&dentry->d_alias, &ind_inode->i_dentry);
			dentry->d_inode = ind_inode;
			iput(cache_inode);
		}

		if( S_ISDIR(dentry->d_inode->i_mode) )
			dentry->d_fsdata = (void*)index;
		else
			dentry->d_fsdata = (void*)pri_ino;
	}

	EXIT;
	return NULL;

#if 0
	/* XXX: PJB these need to be set up again. See dcache.c */
	printk("set up dentry ops\n");
	CDEBUG(D_CACHE, "\n");
        filter_setup_dentry_ops(cache->cache_filter,
                                dentry->d_op, &currentfs_dentry_ops);
        dentry->d_op = filter_c2udops(cache->cache_filter);
        CDEBUG(D_CACHE, "\n");
#endif

err_out:
	d_unadd_iput(dentry);
	EXIT;
	return ERR_PTR(-EINVAL);
}

static int currentfs_create(struct inode *dir, struct dentry *dentry, int mode)
{
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	void *handle = NULL;

	ENTRY;

	if (currentfs_is_under_dotsnap(dentry)) {
		EXIT;
		return -EPERM;
	}

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	handle = snap_trans_start(cache, dir, SNAP_OP_CREATE);

	if ( snap_needs_cow(dir) != -1 ) {
		printk("snap_needs_cow for ino %lu \n",dir->i_ino);
		snap_debug_device_fail(dir->i_dev, SNAP_OP_CREATE, 1);
		snap_do_cow(dir, get_parent_ino(dir), 0);
	}

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops ||
	    !iops->create) {
		rc = -EINVAL;
		goto exit;
	}
	snap_debug_device_fail(dir->i_dev, SNAP_OP_CREATE, 2);
	rc = iops->create(dir, dentry, mode);

	/* XXX now set the correct snap_{file,dir,sym}_iops */
        if ( ! dentry->d_inode) {
                printk("Error in currentfs_create, dentry->d_inode is NULL\n");
                goto exit;
        }

	if ( S_ISDIR(dentry->d_inode->i_mode) )
                dentry->d_inode->i_op = filter_c2udiops(cache->cache_filter);
        else if ( S_ISREG(dentry->d_inode->i_mode) ) {
                if ( !filter_c2cfiops(cache->cache_filter) ) {
                        filter_setup_file_ops(cache->cache_filter,
                                dentry->d_inode->i_op, &currentfs_file_iops);
                }
                dentry->d_inode->i_op = filter_c2ufiops(cache->cache_filter);
        }
	printk("inode %lu, i_op %p\n", dentry->d_inode->i_ino, dentry->d_inode->i_op);

	snap_debug_device_fail(dir->i_dev, SNAP_OP_CREATE, 3);
	
exit:
	snap_trans_commit(cache, handle);
	EXIT;
	return rc;
}

static int currentfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	void *handle = NULL;

	ENTRY;

	if (currentfs_is_under_dotsnap(dentry)) {
		EXIT;
		return -EPERM;
	}

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	handle = snap_trans_start(cache, dir, SNAP_OP_MKDIR);

	if ( snap_needs_cow(dir) != -1 ) {
		CDEBUG(D_FILE, "snap_needs_cow for ino %lu \n",dir->i_ino);
		snap_debug_device_fail(dir->i_dev, SNAP_OP_MKDIR, 1);
		snap_do_cow(dir, get_parent_ino(dir), 0);
	}

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops ||
	    !iops->mkdir) {
		rc = -EINVAL;
		goto exit;
	}

	snap_debug_device_fail(dir->i_dev, SNAP_OP_MKDIR, 2);
	rc = iops->mkdir(dir, dentry, mode);

        if ( rc ) 
                goto exit;
                     
	/* XXX now set the correct snap_{file,dir,sym}_iops */
        if ( dentry->d_inode) {
                dentry->d_inode->i_op = filter_c2udiops(cache->cache_filter);
	        printk("inode %lu, i_op %p\n", dentry->d_inode->i_ino, dentry->d_inode->i_op);
        } else {
                printk("Error in currentfs_mkdir, dentry->d_inode is NULL\n");
        }

	snap_debug_device_fail(dir->i_dev, SNAP_OP_MKDIR, 3);
	
exit:
	snap_trans_commit(cache, handle);
	EXIT;
	return rc;
}

static int currentfs_link (struct dentry * old_dentry, struct inode * dir, 
			struct dentry *dentry)
{
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	void *handle = NULL;

	ENTRY;

	if (currentfs_is_under_dotsnap(dentry)) {
		EXIT;
		return -EPERM;
	}

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	handle = snap_trans_start(cache, dir, SNAP_OP_LINK);

	if ( snap_needs_cow(dir) != -1 ) {
		printk("snap_needs_cow for ino %lu \n",dir->i_ino);
		snap_debug_device_fail(dir->i_dev, SNAP_OP_LINK, 1);
		snap_do_cow(dir, get_parent_ino(dir), 0);
	}
        if ( snap_needs_cow(old_dentry->d_inode) != -1 ) {
		printk("snap_needs_cow for ino %lu \n",old_dentry->d_inode->i_ino);
		snap_debug_device_fail(dir->i_dev, SNAP_OP_LINK, 2);
		snap_do_cow(old_dentry->d_inode, dir->i_ino, 0);
	}

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops ||
	    !iops->link) {
		rc = -EINVAL;
		goto exit;
	}
	snap_debug_device_fail(dir->i_dev, SNAP_OP_LINK, 2);
	rc = iops->link(old_dentry,dir, dentry);
	snap_debug_device_fail(dir->i_dev, SNAP_OP_LINK, 3);
	
exit:
	snap_trans_commit(cache, handle);
	EXIT;
	return rc;
}

static int currentfs_symlink(struct inode *dir, struct dentry *dentry, 
			const char * symname)
{
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	void *handle = NULL;

	ENTRY;

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	handle = snap_trans_start(cache, dir, SNAP_OP_SYMLINK);

	if ( snap_needs_cow(dir) != -1 ) {
		printk("snap_needs_cow for ino %lu \n",dir->i_ino);
		snap_debug_device_fail(dir->i_dev, SNAP_OP_SYMLINK, 1);
		snap_do_cow(dir, get_parent_ino(dir), 0);
	}

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops ||
	    !iops->symlink) {
		rc = -EINVAL;
		goto exit;
	}
	snap_debug_device_fail(dir->i_dev, SNAP_OP_SYMLINK, 2);
	rc = iops->symlink(dir, dentry, symname);
	snap_debug_device_fail(dir->i_dev, SNAP_OP_SYMLINK, 3);
	
exit:
	snap_trans_commit(cache, handle);
	EXIT;
	return rc;
}

static int currentfs_mknod(struct inode *dir, struct dentry *dentry, int mode, 
			int rdev)
{
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	void *handle = NULL;

	ENTRY;

	if (currentfs_is_under_dotsnap(dentry)) {
		EXIT;
		return -EPERM;
	}

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	handle = snap_trans_start(cache, dir, SNAP_OP_MKNOD);

	if ( snap_needs_cow(dir) != -1 ) {
		printk("snap_needs_cow for ino %lu \n",dir->i_ino);
		snap_debug_device_fail(dir->i_dev, SNAP_OP_MKNOD, 1);
		snap_do_cow(dir, get_parent_ino(dir), 0);
	}

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops ||
	    !iops->mknod) {
		rc = -EINVAL;
		goto exit;
	}
	snap_debug_device_fail(dir->i_dev, SNAP_OP_MKNOD, 2);
	rc = iops->mknod(dir, dentry, mode, rdev);
	snap_debug_device_fail(dir->i_dev, SNAP_OP_MKNOD, 3);
	
	/* XXX do we need to set the correct snap_{*}_iops */

exit:
	snap_trans_commit(cache, handle);
	EXIT;
	return rc;
}

static int currentfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	struct inode *inode = NULL;
//	time_t i_ctime = 0;
	nlink_t	i_nlink = 0;
	off_t	i_size = 0;
	ino_t ino = 0;
	int keep_inode = 0;
//	struct dentry_operations *save_dop = NULL;
	void *handle = NULL;

	ENTRY;

	if (currentfs_is_under_dotsnap(dentry)) {
		EXIT;
		return -EPERM;
	}

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	handle = snap_trans_start(cache, dir, SNAP_OP_RMDIR);

	if ( snap_needs_cow(dir) != -1 ) {
		printk("snap_needs_cow for ino %lu \n",dir->i_ino);
		snap_debug_device_fail(dir->i_dev, SNAP_OP_RMDIR, 1);
		snap_do_cow(dir, get_parent_ino(dir), 0);
	}

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops ||
	    !iops->rmdir) {
		rc = -EINVAL;
		goto exit;
	}

	/* XXX : there are two cases that we can't remove this inode from disk. 
		1. the inode needs to be cowed. 
		2. the inode is a redirector.
		then we must keep this inode(dir) so that the inode 
		will not be deleted after rmdir, will only remove dentry 
	*/

	if( snap_needs_cow(dentry->d_inode) != -1) {
		snap_debug_device_fail(dir->i_dev, SNAP_OP_RMDIR, 2);
		snap_do_cow (dentry->d_inode, dir->i_ino, 
				SNAP_DEL_PRI_WITHOUT_IND);
		keep_inode = 1;
	}
	else if( snap_is_redirector(dentry->d_inode) ) {
		snap_debug_device_fail(dir->i_dev, SNAP_OP_RMDIR, 3);
		snap_do_cow(dentry->d_inode, dir->i_ino, SNAP_DEL_PRI_WITH_IND);
		keep_inode = 1;
	}	
#if 0
	if ( keep_inode ) {	
       		printk("set up dentry ops, before %p\n",dentry->d_op);
		save_dop = dentry->d_op;

     		filter_setup_dentry_ops(cache->cache_filter,
                                dentry->d_op, &currentfs_dentry_ops);
        	dentry->d_op = filter_c2udops(cache->cache_filter);

       		printk("set up dentry ops, after %p\n",dentry->d_op);

	}

#endif

	if( keep_inode && dentry->d_inode ) {
		ino = dentry->d_inode->i_ino;
	//	i_ctime = dentry->d_inode->i_ctime;
		i_nlink = dentry->d_inode->i_nlink;
		i_size = dentry->d_inode->i_size;
	
}

	snap_debug_device_fail(dir->i_dev, SNAP_OP_RMDIR, 4);
	rc = iops->rmdir(dir, dentry);
	snap_debug_device_fail(dir->i_dev, SNAP_OP_RMDIR, 5);

	/* XXX : check this */
#if 0
	if ( keep_inode ) {
		dentry->d_op = save_dop;
		printk("restore dentry ops, now at %p\n",dentry->d_op);
	}

#endif

	if( keep_inode && ino) {
		inode = iget ( dir->i_sb, ino);
		if( inode) {
//			inode->i_ctime = i_ctime;
			inode->i_nlink = i_nlink;
			inode->i_size = i_size;
			mark_inode_dirty(inode);
			iput( inode);
#ifdef CONFIG_SNAPFS_EXT3
			/*
			 * In Ext3, rmdir() will put this inode into
			 * orphan list, we must remove it out. It's ugly!!
			 */
			if( cache->cache_type == FILTER_FS_EXT3 )
				ext3_orphan_del(handle, inode);
#endif
			snap_debug_device_fail(dir->i_dev, SNAP_OP_RMDIR, 6);
		}
	}

exit:
	snap_trans_commit(cache, handle);
	EXIT;
	return rc;
}

static int currentfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	void *handle = NULL;

	ENTRY;

	if (currentfs_is_under_dotsnap(dentry)) {
		EXIT;
		return -EPERM;
	}

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	handle = snap_trans_start(cache, dir, SNAP_OP_UNLINK);

	if ( snap_needs_cow(dir) != -1 ) {
		printk("snap_needs_cow for ino %lu \n",dir->i_ino);
		snap_debug_device_fail(dir->i_dev, SNAP_OP_UNLINK, 1);
		snap_do_cow(dir, get_parent_ino(dir), 0);
	}

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops ||
	    !iops->unlink) {
		rc = -EINVAL;
		goto exit;
	}

	/* XXX : if nlink for this inode is 1, there are two cases that we 
		can't remove this inode from disk. 
		1. the inode needs to be cowed. 
		2. the inode is a redirector.
		then we increament dentry->d_inode->i_nlink so that the inode 
		will not be deleted after unlink, will only remove dentry 
	*/

	if( snap_needs_cow (inode) != -1) {
		/* call snap_do_cow with DEL_WITHOUT_IND option */
		snap_debug_device_fail(dir->i_dev, SNAP_OP_UNLINK, 2);
		snap_do_cow(inode, dir->i_ino,SNAP_DEL_PRI_WITHOUT_IND);
		if( inode->i_nlink == 1 )
			inode->i_nlink++;
	}
	else if( snap_is_redirector (inode) && inode->i_nlink == 1 ) {
		/* call snap_do_cow with DEL_WITH_IND option 
		 * just free the blocks of inode, not really delete it
		 */
		snap_debug_device_fail(dir->i_dev, SNAP_OP_UNLINK, 3);
		snap_do_cow (inode, dir->i_ino, SNAP_DEL_PRI_WITH_IND);
		inode->i_nlink++;
	}	

	snap_debug_device_fail(dir->i_dev, SNAP_OP_UNLINK, 4);
	rc = iops->unlink(dir, dentry);
	snap_debug_device_fail(dir->i_dev, SNAP_OP_UNLINK, 5);

exit:
	snap_trans_commit(cache, handle);
	EXIT;
	return rc;
}

static int currentfs_rename (struct inode * old_dir, struct dentry *old_dentry,
                      	struct inode * new_dir, struct dentry *new_dentry)
{
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	void *handle = NULL;

	ENTRY;

	if (currentfs_is_under_dotsnap(old_dentry) ||
	    currentfs_is_under_dotsnap(new_dentry)) {
		EXIT;
		return -EPERM;
	}

	cache = snap_find_cache(old_dir->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	handle = snap_trans_start(cache, old_dir, SNAP_OP_RENAME);
       
        /* Always cow the old dir and old dentry->d_inode */ 
	if ( snap_needs_cow(old_dir) != -1 ) {
		printk("rename: needs_cow for old_dir %lu\n",old_dir->i_ino);
		snap_debug_device_fail(old_dir->i_dev, SNAP_OP_RENAME, 1);
		snap_do_cow(old_dir, get_parent_ino(old_dir), 0);
	}
	if( snap_needs_cow (old_dentry->d_inode) != -1) {
		printk("rename: needs_cow for old_dentry, ino %lu\n",
                       old_dentry->d_inode->i_ino);
		snap_debug_device_fail(old_dir->i_dev, SNAP_OP_RENAME, 2);
		snap_do_cow(old_dentry->d_inode, old_dir->i_ino,0);
	}

	/* If it's not in the same dir, whether the new_dentry is NULL or not,
         * we should cow the new_dir. Because rename will use the ino of 
         * old_dentry as the ino of the new_dentry in new_dir. 
         */
	if(( old_dir != new_dir) ) {
		if( snap_needs_cow(new_dir) !=-1 ){
			printk("rename:snap_needs_cow for new_dir %lu\n",
				new_dir->i_ino);
			snap_debug_device_fail(old_dir->i_dev,SNAP_OP_RENAME,3);
			snap_do_cow(new_dir, get_parent_ino(new_dir),0);	
		}
	}

#if 0
	if( ( old_dir != new_dir) && ( new_dentry->d_inode )) {
		if(snap_needs_cow(new_dentry->d_inode) !=-1 ){
			printk("rename:needs_cow for new_entry ,ino %lu\n",
				new_dentry->d_inode->i_ino);
			snap_debug_device_fail(old_dir->i_dev, SNAP_OP_RENAME, 4);
			snap_do_cow (new_dentry->d_inode, 
				new_dentry->d_parent->d_inode->i_ino, 0);	
		}
	}
#endif
        /* The inode for the new_dentry will be freed for normal rename option.
         * But we should keep this inode since we need to keep it available 
         * for the clone and for snap rollback
         */
        if( new_dentry->d_inode && new_dentry->d_inode->i_nlink == 1 ) {
		if( snap_needs_cow (new_dentry->d_inode) != -1) {
        		/* call snap_do_cow with DEL_WITHOUT_IND option */
	        	snap_debug_device_fail(old_dir->i_dev,SNAP_OP_RENAME,4);
	                snap_do_cow(new_dentry->d_inode, new_dir->i_ino,
                                    SNAP_DEL_PRI_WITHOUT_IND);
	                new_dentry->d_inode->i_nlink++;
	        }
	        else if( snap_is_redirector (new_dentry->d_inode) ) {
		        /* call snap_do_cow with DEL_WITH_IND option 
	       		 * just free the blocks of inode, not really delete it
	        	 */
		        snap_debug_device_fail(old_dir->i_dev,SNAP_OP_RENAME,4);
	        	snap_do_cow (new_dentry->d_inode, new_dir->i_ino, 
                                     SNAP_DEL_PRI_WITH_IND);
	        	new_dentry->d_inode->i_nlink++;
	       	}	
        }

	iops = filter_c2cdiops(cache->cache_filter); 
	if (!iops ||
	    !iops->rename) {
		rc = -EINVAL;
		goto exit;
	}

	snap_debug_device_fail(old_dir->i_dev, SNAP_OP_RENAME, 5);
	rc = iops->rename(old_dir, old_dentry, new_dir, new_dentry);
	snap_debug_device_fail(old_dir->i_dev, SNAP_OP_RENAME, 6);

exit:
	snap_trans_commit(cache, handle);
	EXIT;
	return rc;
}

static int currentfs_readdir(struct file *filp, void *dirent,
			     filldir_t filldir)
{
	struct snap_cache *cache;
	struct file_operations *fops;
	int rc;
	
	ENTRY;
	if( !filp || !filp->f_dentry || !filp->f_dentry->d_inode ) {
		EXIT;
		return -EINVAL;
	}

	cache = snap_find_cache(filp->f_dentry->d_inode->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}
	fops = filter_c2cdfops( cache->cache_filter );
	if( !fops ) {
		EXIT;
		return -EINVAL;
	}

	/*
	 * no action if we are under clonefs or .snap
	 */
	if( cache->cache_show_dotsnap &&
	    (filp->f_dentry->d_sb == cache->cache_sb) &&
	    !currentfs_is_under_dotsnap(filp->f_dentry) ){
		if( filp->f_pos == 0 ){
			if( filldir(dirent, ".snap",
				    strlen(".snap")+1, filp->f_pos,
				    0xF0000000|filp->f_dentry->d_inode->i_ino) ){
				return -EINVAL;
			}
			filp->f_pos += strlen(".snap")+1;
		}
		filp->f_pos -= strlen(".snap")+1;
		rc = fops->readdir(filp, dirent, filldir);
		filp->f_pos += strlen(".snap")+1;
	}else
		rc = fops->readdir(filp, dirent, filldir);

	return rc;
}

struct file_operations currentfs_dir_fops = {
	readdir: currentfs_readdir
};

struct inode_operations currentfs_dir_iops = { 
	default_file_ops: &currentfs_dir_fops,
	create: currentfs_create,
	mkdir: currentfs_mkdir,
	link: currentfs_link,
	symlink: currentfs_symlink,
	mknod: currentfs_mknod,
	rmdir: currentfs_rmdir,
	unlink: currentfs_unlink,
	rename: currentfs_rename,
	lookup:	currentfs_lookup
};
