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

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

static inline int inode_has_ea(struct inode *inode)
{               
        return (inode->u.ext2_i.i_file_acl != 0); 
}               

static int currentfs_readlink(struct dentry * dentry, char * buffer, int buflen)
{
	struct snap_cache *cache;
	int rc;
	struct inode_operations *iops;
	struct inode * inode = dentry->d_inode;
	int bpib = inode->i_sb->s_blocksize >> 9;
	__u32 save_i_blocks;

	ENTRY;

	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	iops = filter_c2csiops(cache->cache_filter); 
	if (!iops ||
	    !iops->readlink) {
		rc = -EINVAL;
		goto exit;
	}

	save_i_blocks = inode->i_blocks;
	/* If this link has ea and its i_blocks is ea's block, 
	 * then we should treate it as a fast symlink 
	 */
	if( inode_has_ea(inode) && inode->i_blocks == bpib ) {
		inode->i_blocks = 0; 
	}
	rc = iops->readlink(dentry, buffer, buflen);
	
	if( inode->i_blocks != save_i_blocks ){
		inode->i_blocks = save_i_blocks;
		mark_inode_dirty(inode);
	}
	
exit:
	EXIT;
	return rc;
}

static int cat_str_ahead(char *buf, int pos, const char* str)
{
	int len = strlen(str);

	if( pos - len -1 < 0 )
		return pos;

	buf[--pos] = '/';
	memcpy(&buf[pos-len], str, len);
	return pos-len;
}

/*
 * Adjust the following path if we are under dotsnap (skip .snap/clonexx...)
 * in following two case, we just return null and let caller do
 * the normal follow_link:
 * (1) we are not lies in .snap
 * (2) we are already in the root's .snap
 */
static struct dentry * dotsnap_follow_link(struct dentry *base,
					   struct dentry *dentry,
					   int follow)
{
	struct super_block *sb = dentry->d_inode->i_sb;
	struct dentry *rc = NULL;
	struct dentry *de = dentry, *de_save1=NULL, *de_save2=NULL;
	char *buf = NULL;
	int pos = D_MAXLEN;

	SNAP_ALLOC(buf, char*, D_MAXLEN);
	if( !buf )
		return ERR_PTR(-ENOMEM);

	/*
	 * iterate upward to construct the path
	 */
	do {
		if( de_save2 )
			pos = cat_str_ahead(buf, pos, de_save2->d_name.name);

		if ( de->d_inode && de->d_inode->i_ino & 0xF0000000 )
			goto lookup;

		de_save2 = de_save1;
		de_save1 = de;
		de = de->d_parent;
	} while (de->d_parent != de);

	/* we are not under dotsnap */
	goto exit; 

lookup:
	/* See if we already under root's .snap */
	de = de->d_parent;
	if( de == sb->s_root )
		goto exit;

	while( (de->d_parent != de) && (de != sb->s_root) ){
		pos = cat_str_ahead(buf, pos, de->d_name.name);
		de = de->d_parent;
	}
	if( de_save1 )
		pos = cat_str_ahead(buf, pos, de_save1->d_name.name);

	pos = cat_str_ahead(buf, pos, ".snap");
	buf[D_MAXLEN-1] = 0;
	CDEBUG(D_FILE, "constructed path: %s\n", &buf[pos]);

	/* FIXME lookup_dentry will never return NULL ?? */
	rc = lookup_dentry(&buf[pos], dget(sb->s_root), follow);
	if( !rc ){
		rc = ERR_PTR(-ENOENT);
		CDEBUG(D_FILE, "lookup_dentry return NULL~!@#$^&*\n");
	}
	dput(base);

exit:
	SNAP_FREE(buf, D_MAXLEN);
	return rc;
}

static struct dentry * currentfs_follow_link (	struct dentry *dentry, 
						struct dentry *base,
						unsigned int follow)
{
	struct snap_cache *cache;
	struct dentry * rc;
	struct inode_operations *iops;
	struct inode * inode = dentry->d_inode;
	int bpib = inode->i_sb->s_blocksize >> 9;
	__u32 save_i_blocks;

	ENTRY;

	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) { 
		EXIT;
		return ERR_PTR(-EINVAL);
	}

	iops = filter_c2csiops(cache->cache_filter); 
	if (!iops ||
	    !iops->follow_link) {
		rc = ERR_PTR(-EINVAL);
		goto exit;
	}

	if( currentfs_is_under_dotsnap(dentry) ){
		rc = dotsnap_follow_link( base, dentry, follow );
		if( rc )
			goto exit;
	}

	save_i_blocks = inode->i_blocks;
	/* If this link has ea and its i_blocks is ea's block, 
	 * then we should treate it as a fast symlink 
	 */
	if( inode_has_ea(inode) && inode->i_blocks == bpib ) {
		inode->i_blocks = 0; 
	}
	rc = iops->follow_link(dentry, base, follow);
	
	if( inode->i_blocks != save_i_blocks ){
		inode->i_blocks = save_i_blocks;
		mark_inode_dirty(inode);
	}
	
exit:
	EXIT;
	return rc;
}

struct inode_operations currentfs_sym_iops = {
	readlink:	currentfs_readlink,
	follow_link:	currentfs_follow_link
};

struct file_operations currentfs_sym_fops;
