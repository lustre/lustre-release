/*
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/ext2/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *  Directory entry file type support and forward compatibility hooks
 *      for B-tree directories by Theodore Ts'o (tytso@mit.edu), 1998
 * 
 *  Changes for use in OBDFS
 *  Copyright (c) 1999, Seagate Technology Inc.
 *  Copyright (C) 2001, Cluster File Systems, Inc.
 *                       Rewritten based on recent ext2 page cache use.
 * 
 */

#include <linux/fs.h>
#include <linux/locks.h>
#include <linux/quotaops.h>
#include <linux/obd_support.h>
#include <linux/lustre_light.h>
extern struct address_space_operations ll_aops;

/* from super.c */
extern void ll_change_inode(struct inode *inode);
extern int ll_setattr(struct dentry *de, struct iattr *attr);

/* from dir.c */
extern int ext2_add_link (struct dentry *dentry, struct inode *inode);
ino_t ll_inode_by_name(struct inode * dir, struct dentry *dentry, int *typ);
int ext2_make_empty(struct inode *inode, struct inode *parent);
struct ext2_dir_entry_2 * ext2_find_entry (struct inode * dir,
		   struct dentry *dentry, struct page ** res_page);
int ext2_delete_entry (struct ext2_dir_entry_2 * dir, struct page * page );
int ext2_empty_dir (struct inode * inode);
struct ext2_dir_entry_2 * ext2_dotdot (struct inode *dir, struct page **p);
void ext2_set_link(struct inode *dir, struct ext2_dir_entry_2 *de,
		   struct page *page, struct inode *inode);

/*
 * Couple of helper functions - make the code slightly cleaner.
 */
static inline void ext2_inc_count(struct inode *inode)
{
	inode->i_nlink++;
	ll_change_inode(inode);
}

/* postpone the disk update until the inode really goes away */ 
static inline void ext2_dec_count(struct inode *inode)
{
	inode->i_nlink--;
	if (inode->i_nlink > 0) 
		ll_change_inode(inode);
}

static inline int ext2_add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err;
	err = ext2_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	ext2_dec_count(inode);
	iput(inode);
	return err;
}

/* methods */
static struct dentry *ll_lookup(struct inode * dir, struct dentry *dentry)
{
        struct obdo *oa;
	struct inode * inode = NULL;
	int type;
	ino_t ino;
	
        ENTRY;
	if (dentry->d_name.len > EXT2_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = ll_inode_by_name(dir, dentry, &type);
	if (!ino)
		goto negative;

        oa = obdo_fromid(IID(dir), ino, type, 
			 OBD_MD_FLNOTOBD | OBD_MD_FLBLOCKS);
        if ( IS_ERR(oa) ) {
                printk(__FUNCTION__ ": obdo_fromid failed\n");
                EXIT;
                return ERR_PTR(-EACCES); 
        }

	inode = iget4(dir->i_sb, ino, NULL, oa);
        obdo_free(oa);

	if (!inode) 
		return ERR_PTR(-EACCES);

 negative:
	d_add(dentry, inode);
	return NULL;
}


/*
 * NOTE! unlike strncmp, ext2_match returns 1 for success, 0 for failure.
 *
 * `len <= EXT2_NAME_LEN' is guaranteed by caller.
 * `de != NULL' is guaranteed by caller.
 */
static inline int ext2_match (int len, const char * const name,
                       struct ext2_dir_entry_2 * de)
{
        if (len != de->name_len)
                return 0;
        if (!de->inode)
                return 0;
        return !memcmp(name, de->name, len);
}

static struct inode *ll_new_inode(struct inode *dir, int mode)
{
        struct obdo *oa;
        struct inode *inode;
        int err;

        ENTRY;
        if (IOPS(dir, create) == NULL) {
                printk(KERN_ERR __FUNCTION__ ": no create method!\n");
                EXIT;
                return ERR_PTR(-EIO);
        }
        oa = obdo_alloc();
        if (!oa) {
                EXIT;
                return ERR_PTR(-ENOMEM);
        }

        /* Send a hint to the create method on the type of file to create */
        oa->o_mode = mode;
        oa->o_valid |= OBD_MD_FLMODE;
	CDEBUG(D_INODE, "\n");
        err = IOPS(dir, create)(IID(dir), oa);
	CDEBUG(D_INODE, "\n");

        if ( err ) {
                printk("new_inode - fatal: err %d\n", err);
                obdo_free(oa);
                EXIT;
                return ERR_PTR(err);
        }
	CDEBUG(D_INODE, "obdo mode %o\n", oa->o_mode);

        inode = iget4(dir->i_sb, (ino_t)oa->o_id, NULL, oa);
	CDEBUG(D_INODE, "\n");
        obdo_free(oa);

        if (!inode) {
                printk("new_inode -fatal:  %ld\n", (long)oa->o_id);
                IOPS(dir, destroy)(IID(dir), oa);
                EXIT;
                return ERR_PTR(-EIO);
        }

        if (!list_empty(&inode->i_dentry)) {
                printk("new_inode -fatal: aliases %ld, ct %d lnk %d\n", 
		       (long)oa->o_id,
		       atomic_read(&inode->i_count), 
		       inode->i_nlink);
                IOPS(dir, destroy)(IID(dir), oa);
                iput(inode);
                EXIT;
                return ERR_PTR(-EIO);
        }

        EXIT;
        return inode;
} /* ll_new_inode */


/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate(). 
 */
static int ll_create (struct inode * dir, struct dentry * dentry, int mode)
{
	struct inode * inode = ll_new_inode (dir, mode);
	int err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		inode->i_op = &ll_file_inode_operations;
		inode->i_fop = &ll_file_operations;
		inode->i_mapping->a_ops = &ll_aops;
		err = ext2_add_nondir(dentry, inode);
	}
	return err;
} /* ll_create */


static int ll_mknod (struct inode * dir, struct dentry *dentry, int mode, int rdev)
{
	struct inode * inode = ll_new_inode (dir, mode);
	int err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		init_special_inode(inode, mode, rdev);
		ll_change_inode(inode);
		err = ext2_add_nondir(dentry, inode);
	}
	return err;
}

static int ll_symlink (struct inode * dir, struct dentry * dentry,
	const char * symname)
{
	struct super_block * sb = dir->i_sb;
	int err = -ENAMETOOLONG;
	unsigned l = strlen(symname)+1;
	struct inode * inode;
        struct ll_inode_info *oinfo;

	if (l > sb->s_blocksize)
		goto out;

	inode = ll_new_inode (dir, S_IFLNK | S_IRWXUGO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

        oinfo = ll_i2info(inode);
        if (l >= sizeof(oinfo->lli_inline)) {
		/* slow symlink */
		inode->i_op = &page_symlink_inode_operations;
		inode->i_mapping->a_ops = &ll_aops;
		err = block_symlink(inode, symname, l);
		if (err)
			goto out_fail;
	} else {
		/* fast symlink */
		inode->i_op = &ll_fast_symlink_inode_operations;
		memcpy(oinfo->lli_inline, symname, l);
		inode->i_size = l-1;
	}
	ll_change_inode(inode);

	err = ext2_add_nondir(dentry, inode);
out:
	return err;

out_fail:
	ext2_dec_count(inode);
	iput (inode);
	goto out;
}



static int ll_link (struct dentry * old_dentry, struct inode * dir,
	struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;

	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	if (inode->i_nlink >= EXT2_LINK_MAX)
		return -EMLINK;

	inode->i_ctime = CURRENT_TIME;
	ext2_inc_count(inode);
	atomic_inc(&inode->i_count);

	return ext2_add_nondir(dentry, inode);
}


static int ll_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
	struct inode * inode;
	int err = -EMLINK;
	ENTRY;

	if (dir->i_nlink >= EXT2_LINK_MAX)
		goto out;

	ext2_inc_count(dir);

	inode = ll_new_inode (dir, S_IFDIR | mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	inode->i_op = &ll_dir_inode_operations;
	inode->i_fop = &ll_dir_operations;
	inode->i_mapping->a_ops = &ll_aops;

	ext2_inc_count(inode);

	err = ext2_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = ext2_add_link(dentry, inode);
	if (err)
		goto out_fail;

	d_instantiate(dentry, inode);
out:
	EXIT;
	return err;

out_fail:
	ext2_dec_count(inode);
	ext2_dec_count(inode);
	iput(inode);
	EXIT;
out_dir:
	ext2_dec_count(dir);
	EXIT;
	goto out;
}

static int ll_unlink(struct inode * dir, struct dentry *dentry)
{
	struct inode * inode = dentry->d_inode;
	struct ext2_dir_entry_2 * de;
	struct page * page;
	int err = -ENOENT;

	de = ext2_find_entry (dir, dentry, &page);
	if (!de)
		goto out;

	err = ext2_delete_entry (de, page);
	if (err)
		goto out;

	inode->i_ctime = dir->i_ctime;
	ext2_dec_count(inode);
	err = 0;
out:
	return err;
}


static int ll_rmdir (struct inode * dir, struct dentry *dentry)
{
	struct inode * inode = dentry->d_inode;
	int err = -ENOTEMPTY;

	if (ext2_empty_dir(inode)) {
		err = ll_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			ext2_dec_count(inode);
			ext2_dec_count(dir);
		}
	}
	return err;
}

static int ll_rename (struct inode * old_dir, struct dentry * old_dentry,
	struct inode * new_dir,	struct dentry * new_dentry )
{
	struct inode * old_inode = old_dentry->d_inode;
	struct inode * new_inode = new_dentry->d_inode;
	struct page * dir_page = NULL;
	struct ext2_dir_entry_2 * dir_de = NULL;
	struct page * old_page;
	struct ext2_dir_entry_2 * old_de;
	int err = -ENOENT;

	old_de = ext2_find_entry (old_dir, old_dentry, &old_page);
	if (!old_de)
		goto out;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = ext2_dotdot(old_inode, &dir_page);
		if (!dir_de)
			goto out_old;
	}

	if (new_inode) {
		struct page *new_page;
		struct ext2_dir_entry_2 *new_de;

		err = -ENOTEMPTY;
		if (dir_de && !ext2_empty_dir (new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = ext2_find_entry (new_dir, new_dentry, &new_page);
		if (!new_de)
			goto out_dir;
		ext2_inc_count(old_inode);
		ext2_set_link(new_dir, new_de, new_page, old_inode);
		new_inode->i_ctime = CURRENT_TIME;
		if (dir_de)
			new_inode->i_nlink--;
		ext2_dec_count(new_inode);
	} else {
		if (dir_de) {
			err = -EMLINK;
			if (new_dir->i_nlink >= EXT2_LINK_MAX)
				goto out_dir;
		}
		ext2_inc_count(old_inode);
		err = ext2_add_link(new_dentry, old_inode);
		if (err) {
			ext2_dec_count(old_inode);
			goto out_dir;
		}
		if (dir_de)
			ext2_inc_count(new_dir);
	}

	ext2_delete_entry (old_de, old_page);
	ext2_dec_count(old_inode);

	if (dir_de) {
		ext2_set_link(old_inode, dir_de, dir_page, new_dir);
		ext2_dec_count(old_dir);
	}
	return 0;


out_dir:
	if (dir_de) {
		kunmap(dir_page);
		page_cache_release(dir_page);
	}
out_old:
	kunmap(old_page);
	page_cache_release(old_page);
out:
	return err;
}

struct inode_operations ll_dir_inode_operations = {
	create:		ll_create,
	lookup:		ll_lookup,
	link:		ll_link,
	unlink:		ll_unlink,
	symlink:	ll_symlink,
	mkdir:		ll_mkdir,
	rmdir:		ll_rmdir,
	mknod:		ll_mknod,
	rename:		ll_rename,
	setattr:        ll_setattr
};
