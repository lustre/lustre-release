/*
 *  linux/fs/obdfs/namei.c
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
 *  	for B-tree directories by Theodore Ts'o (tytso@mit.edu), 1998
 * 
 *  Changes for use in OBDFS
 *  Copyright (c) 1999, Seagate Technology Inc.
 * 
 */

#include <linux/fs.h>
#include <linux/locks.h>
#include <linux/quotaops.h>
#include <linux/obd_support.h>
#include <linux/obdfs.h>


/*
 * define how far ahead to read directories while searching them.
 */
#define NAMEI_RA_CHUNKS  2
#define NAMEI_RA_BLOCKS  4
#define NAMEI_RA_SIZE        (NAMEI_RA_CHUNKS * NAMEI_RA_BLOCKS)
#define NAMEI_RA_INDEX(c,b)  (((c) * NAMEI_RA_BLOCKS) + (b))

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

/*
 *	obdfs_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the cache buffer in which the entry was found, and the entry
 * itself (as a parameter - res_dir). It does NOT read the inode of the
 * entry - you'll have to do that yourself if you want to.
 */
static struct page * obdfs_find_entry (struct inode * dir,
				       const char * const name, int namelen,
				       struct ext2_dir_entry_2 ** res_dir,
				       int lock)
{
	struct super_block * sb;
	unsigned long offset;
	struct page * page;

	ENTRY;
	CDEBUG(D_INFO, "find entry for %*s\n", namelen, name);

	*res_dir = NULL;
	sb = dir->i_sb;

	if (namelen > EXT2_NAME_LEN)
		return NULL;

	CDEBUG(D_INFO, "dirsize is %Ld\n", dir->i_size);

	page = 0;
	offset = 0;
	while ( offset < dir->i_size ) {
		struct ext2_dir_entry_2 * de;
		char * dlimit;

		page = obdfs_getpage(dir, offset, 0, lock);

		if ( !page ) {
			CDEBUG(D_INFO, "No page, offset %lx\n", offset);
			return NULL;
		}

		de = (struct ext2_dir_entry_2 *) page_address(page);
		dlimit = (char *)page_address(page) + PAGE_SIZE; 
		while ((char *) de < dlimit) {
			/* this code is executed quadratically often */
			/* do minimal checking `by hand' */
			int de_len;
			/* CDEBUG(D_INFO, "Entry %p len %d, page at %#lx - %#lx , offset %lx\n",
			       de, le16_to_cpu(de->rec_len), page_address(page),
			       page_address(page) + PAGE_SIZE, offset); */

			if ((char *) de + namelen <= dlimit &&
			    ext2_match (namelen, name, de)) {
				/* found a match -
				   just to be sure, do a full check */
				if (!obdfs_check_dir_entry("ext2_find_entry",
							  dir, de, page, offset))
					goto failure;
				*res_dir = de;
				EXIT;
				return page;
			}
			/* prevent looping on a bad block */
			de_len = le16_to_cpu(de->rec_len);
			if (de_len <= 0) {
				printk("Bad entry at %p len %d\n", de, de_len);
				goto failure;
			}
			offset += de_len;
			de = (struct ext2_dir_entry_2 *)
				((char *) de + de_len);
			/* CDEBUG(D_INFO, "Next while %lx\n", offset); */
		}
		if ( lock ) 
			UnlockPage(page);
		page_cache_release(page);
		page = NULL;
		CDEBUG(D_INFO, "Next for %lx\n", offset);
	}

failure:
	CDEBUG(D_INFO, "Negative case, page %p, offset %ld\n", page, offset);
	if (page) {
		if (lock) 
			UnlockPage(page);
		page_cache_release(page);
	}
	EXIT;
	return NULL;
} /* obdfs_find_entry */

struct dentry *obdfs_lookup(struct inode *dir, struct dentry *dentry)
{
	struct inode * inode;
	struct ext2_dir_entry_2 * de;
	struct page *page;
	ENTRY;

	if (dentry->d_name.len > EXT2_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	page = obdfs_find_entry(dir, dentry->d_name.name, dentry->d_name.len,
				&de, LOCKED);
	inode = NULL;
	if ( !page ) 
		CDEBUG(D_INFO, "No page - negative entry.\n");
	if ( page && !de ) {
		CDEBUG(D_INODE, "Danger: PAGE but de.\n");
		return ERR_PTR(-ENOENT);
	}
	if (page) {
		unsigned long ino = le32_to_cpu(de->inode);
		UnlockPage(page);
		page_cache_release(page);
		inode = iget(dir->i_sb, ino);

		if (!inode) { 
			CDEBUG(D_INODE, "No inode.\n");
			EXIT;
			return ERR_PTR(-EACCES);
		}
	}
	d_add(dentry, inode);
	EXIT;
	return NULL;
} /* obdfs_lookup */

/*
 *	obdfs_add_entry()
 *
 * adds a file entry to the specified directory, using the same
 * semantics as ext2_find_entry(). It returns NULL if it failed.
 *
 * NOTE!! The inode part of 'de' is left at 0 - which means you
 * may not sleep between calling this and putting something into
 * the entry, as someone else might have used it while you slept.
 *
 * returns a locked and held page upon success 
 */


/* We do this with a locked page: that's not necessary, since the semaphore
 * on the inode protects this page as well.
 */
static struct page *obdfs_add_entry (struct inode * dir,
				     const char * name, int namelen,
				     struct ext2_dir_entry_2 ** res_dir,
				     int *err)
{
	unsigned long offset;
	unsigned short rec_len;
	struct page *page;
	struct ext2_dir_entry_2 * de, * de1;
	struct super_block * sb;

	ENTRY;
	*err = -EINVAL;
	*res_dir = NULL;
	if (!dir || !dir->i_nlink) {
		CDEBUG(D_INODE, "bad directory\n");
		EXIT;
		return NULL;
	}
	sb = dir->i_sb;

	if (!namelen) { 
		CDEBUG(D_INODE, "bad directory\n");
		EXIT;
		return NULL;
	}
	/*
	 * Is this a busy deleted directory?  Can't create new files if so
	 */
	if (dir->i_size == 0)
	{
		OIDEBUG(dir);
		*err = -ENOENT;
		EXIT;
		return NULL;
	}
	page = obdfs_getpage(dir, 0, 0, LOCKED);
	if (!page) {
		EXIT;
		return NULL;
	}
	rec_len = EXT2_DIR_REC_LEN(namelen);
	/* CDEBUG(D_INFO, "reclen: %d\n", rec_len); */
	/* PDEBUG(page, "starting search"); */
	offset = 0;
	de = (struct ext2_dir_entry_2 *) page_address(page);
	*err = -ENOSPC;
	while (1) {
		/* CDEBUG(D_INFO,
		       "Entry at %p, (page at %#lx - %#lx), offset %ld\n",
		       de, page_address(page), page_address(page) + PAGE_SIZE,
		       offset); */
		if ((char *)de >= PAGE_SIZE + (char *)page_address(page)) {
			UnlockPage(page);
			page_cache_release(page);
			page = obdfs_getpage(dir, offset, 1, LOCKED);
			if (!page) {
				EXIT;
				return NULL;
			}
			PDEBUG(page, "new directory page");
			if (dir->i_size <= offset) {
				if (dir->i_size == 0) {
					*err = -ENOENT;
					EXIT;
					return NULL;
				}

				CDEBUG(D_INFO, "creating next block\n");

				de = (struct ext2_dir_entry_2 *) page_address(page);
				de->inode = 0;
				de->rec_len = cpu_to_le16(PAGE_SIZE);
				dir->i_size = offset + PAGE_SIZE;
				dir->u.ext2_i.i_flags &= ~EXT2_BTREE_FL;
				mark_inode_dirty(dir);
			} else {

				ext2_debug ("skipping to next block\n");

				de = (struct ext2_dir_entry_2 *) page_address(page);
			}
		}
		if (!obdfs_check_dir_entry ("ext2_add_entry", dir, de, page,
					   offset)) {
			*err = -ENOENT;
			UnlockPage(page);
			page_cache_release(page);
			EXIT;
			return NULL;
		}
		CDEBUG(D_INFO, "\n");
		if (ext2_match (namelen, name, de)) {
				*err = -EEXIST;
				UnlockPage(page);
				page_cache_release(page);
				EXIT;
				return NULL;
		}
		/* CDEBUG(D_INFO, "Testing for enough space at de %p\n", de);*/
		if ((le32_to_cpu(de->inode) == 0 && le16_to_cpu(de->rec_len) >= rec_len) ||
		    (le16_to_cpu(de->rec_len) >= EXT2_DIR_REC_LEN(de->name_len) + rec_len)) {
			offset += le16_to_cpu(de->rec_len);
			/* CDEBUG(D_INFO,
			       "Found enough space de %p, offset %#lx\n",
			       de, offset); */
			if (le32_to_cpu(de->inode)) {
				/*CDEBUG(D_INFO, "Insert new in %p\n", de);*/
				de1 = (struct ext2_dir_entry_2 *) ((char *) de +
					EXT2_DIR_REC_LEN(de->name_len));
				/*CDEBUG(D_INFO, "-- de1 at %p\n", de1);*/
				de1->rec_len = cpu_to_le16(le16_to_cpu(de->rec_len) -
					EXT2_DIR_REC_LEN(de->name_len));
				de->rec_len = cpu_to_le16(EXT2_DIR_REC_LEN(de->name_len));
				de = de1;
			}
			/* CDEBUG(D_INFO,
			       "Reclen adjusted; copy %d bytes to %p, "
			       "page at %#lx EOP at %#lx\n",
			       namelen, de->name, page_address(page),
			       page_address(page) + PAGE_SIZE); */
			de->inode = 0;
			de->name_len = namelen;
			de->file_type = 0;
			memcpy (de->name, name, namelen);
			/*
			 * XXX shouldn't update any times until successful
			 * completion of syscall, but too many callers depend
			 * on this.
			 *
			 * XXX similarly, too many callers depend on
			 * ext2_new_inode() setting the times, but error
			 * recovery deletes the inode, so the worst that can
			 * happen is that the times are slightly out of date
			 * and/or different from the directory change time.
			 */
			dir->i_mtime = dir->i_ctime = CURRENT_TIME;
			dir->u.ext2_i.i_flags &= ~EXT2_BTREE_FL;
			mark_inode_dirty(dir);
			dir->i_version = ++event;
			*res_dir = de;
			*err = 0;
			/* PDEBUG(page, "add_entry"); */
			/* XXX unlock page here */
			EXIT;
			return page;
		}
		offset += le16_to_cpu(de->rec_len);
		de = (struct ext2_dir_entry_2 *) ((char *) de + le16_to_cpu(de->rec_len));
		
	}

	UnlockPage(page);
	page_cache_release(page);
	/* PDEBUG(page, "add_entry"); */
	EXIT;
	return NULL;
} /* obdfs_add_entry */

/*
 * obdfs_delete_entry deletes a directory entry by merging it with the
 * previous entry
 */
static int obdfs_delete_entry (struct ext2_dir_entry_2 * dir,
			      struct page * page)
{
	struct ext2_dir_entry_2 * de, * pde;
	int i;

	i = 0;
	pde = NULL;
	de = (struct ext2_dir_entry_2 *) page_address(page);
	while (i < PAGE_SIZE) {
		if (!obdfs_check_dir_entry ("ext2_delete_entry", NULL, 
					   de, page, i))
			return -EIO;
		if (de == dir)  {
			if (pde)
				pde->rec_len =
					cpu_to_le16(le16_to_cpu(pde->rec_len) +
						    le16_to_cpu(dir->rec_len));
			else
				dir->inode = 0;
			return 0;
		}
		i += le16_to_cpu(de->rec_len);
		pde = de;
		de = (struct ext2_dir_entry_2 *) ((char *) de + le16_to_cpu(de->rec_len));
	}
	return -ENOENT;
} /* obdfs_delete_entry */


static inline void ext2_set_de_type(struct super_block *sb,
				struct ext2_dir_entry_2 *de,
				umode_t mode) {
	/* XXX fix this to check for obdfs feature, not ext2 feature */
	if (!EXT2_HAS_INCOMPAT_FEATURE(sb, EXT2_FEATURE_INCOMPAT_FILETYPE))
		return;
	if (S_ISREG(mode))
		de->file_type = EXT2_FT_REG_FILE;
	else if (S_ISDIR(mode))  
		de->file_type = EXT2_FT_DIR;
	else if (S_ISLNK(mode))
		de->file_type = EXT2_FT_SYMLINK;
	else if (S_ISSOCK(mode))
		de->file_type = EXT2_FT_SOCK;
	else if (S_ISFIFO(mode))  
		de->file_type = EXT2_FT_FIFO;
	else if (S_ISCHR(mode))
		de->file_type = EXT2_FT_CHRDEV;
	else if (S_ISBLK(mode))
		de->file_type = EXT2_FT_BLKDEV;
}


/*
 * Display all dentries holding the specified inode.
 */
#if 0
static void show_dentry(struct list_head * dlist, int subdirs)
{
	struct list_head *tmp = dlist;

	while ((tmp = tmp->next) != dlist) {
		struct dentry * dentry;
		const char * unhashed = "";

		if ( subdirs ) 
			dentry  = list_entry(tmp, struct dentry, d_child);
		else 
			dentry  = list_entry(tmp, struct dentry, d_alias);

		if (list_empty(&dentry->d_hash))
			unhashed = "(unhashed)";

		if ( dentry->d_inode ) 
			printk("show_dentry: %s/%s, d_count=%d%s (ino %ld, dev %d, ct %d)\n",
			       dentry->d_parent->d_name.name,
			       dentry->d_name.name, dentry->d_count,
			       unhashed, dentry->d_inode->i_ino, 
			       dentry->d_inode->i_dev, 
			       dentry->d_inode->i_count);
		else 
			printk("show_dentry: %s/%s, d_count=%d%s \n",
			       dentry->d_parent->d_name.name,
			       dentry->d_name.name, dentry->d_count,
			       unhashed);
	}
} /* show_dentry */
#endif


static struct inode *obdfs_new_inode(struct inode *dir, int mode)
{
	struct obdo *oa;
	struct inode *inode;
	int err;

	ENTRY;
	oa = obdo_alloc();
	if (!oa) {
		EXIT;
		return ERR_PTR(-ENOMEM);
	}

	/* Send a hint to the create method on the type of file to create */
	oa->o_mode = mode;
	oa->o_valid |= OBD_MD_FLMODE;

	err = IOPS(dir, create)(IID(dir), oa);

	if ( err ) {
		CDEBUG(D_INODE, "fatal: creating new inode (err %d)\n", err);
		obdo_free(oa);
		EXIT;
		return ERR_PTR(err);
	}

	inode = iget(dir->i_sb, (ino_t)oa->o_id);

	if (!inode) {
		CDEBUG(D_INODE, "fatal: get new inode %ld\n", (long)oa->o_id);
		IOPS(dir, destroy)(IID(dir), oa);
		obdo_free(oa);
		EXIT;
		return ERR_PTR(-EIO);
	}

	if (!list_empty(&inode->i_dentry)) {
		CDEBUG(D_INODE, "New inode (%ld) has aliases!\n", inode->i_ino);
		IOPS(dir, destroy)(IID(dir), oa);
		obdo_free(oa);
		iput(inode);
		EXIT;
		return ERR_PTR(-EIO);
	}
	obdo_free(oa);

	EXIT;
	return inode;
} /* obdfs_new_inode */


/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate(). 
 */
int obdfs_create (struct inode * dir, struct dentry * dentry, int mode)
{
	struct inode * inode;
	struct page *page;
	struct ext2_dir_entry_2 * de;
	int err = -EIO;

        ENTRY;
	inode = obdfs_new_inode(dir, mode);
	if ( IS_ERR(inode) ) {
		EXIT;
		return PTR_ERR(inode);
	}

	inode->i_op = &obdfs_file_inode_operations;
	mark_inode_dirty(inode);
	page = obdfs_add_entry (dir, dentry->d_name.name, dentry->d_name.len, &de, &err);
	if (!page) {
		inode->i_nlink--;
		mark_inode_dirty(inode);
		iput (inode);
		EXIT;
		return err;
	}
	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type(dir->i_sb, de, S_IFREG);
	dir->i_version = ++event;

	err = obdfs_do_writepage(dir, page, IS_SYNC(dir));
	UnlockPage(page);

	page_cache_release(page);
	d_instantiate(dentry, inode);
	EXIT;
	return err;
} /* obdfs_create */

int obdfs_mknod (struct inode * dir, struct dentry *dentry, int mode, int rdev)
{
	struct inode * inode;
	struct page *page;
	struct ext2_dir_entry_2 * de;
	int err;

        ENTRY;
	inode = obdfs_new_inode(dir, mode);
	if ( IS_ERR(inode) ) {
		EXIT;
		return PTR_ERR(inode);
	}

	inode->i_uid = current->fsuid;
	init_special_inode(inode, mode, rdev);
	page = obdfs_add_entry (dir, dentry->d_name.name, dentry->d_name.len, &de, &err);
	if (!page)
		goto out_no_entry;
	de->inode = cpu_to_le32(inode->i_ino);
	dir->i_version = ++event;
	ext2_set_de_type(dir->i_sb, de, inode->i_mode);
	mark_inode_dirty(inode);

	err = obdfs_do_writepage(dir, page, IS_SYNC(dir));
	UnlockPage(page);

	d_instantiate(dentry, inode);
	page_cache_release(page);
	err = 0;
out:
	return err;

out_no_entry:
	inode->i_nlink--;
	mark_inode_dirty(inode);
	iput(inode);
	goto out;
} /* obdfs_mknod */

int obdfs_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
	struct inode * inode;
	struct page *page, *inode_page;
	struct ext2_dir_entry_2 * de;
	int err;

	ENTRY;

	err = -EMLINK;
	if (dir->i_nlink >= EXT2_LINK_MAX)
		goto out;

	mode |= S_IFDIR;
	if (dir->i_mode & S_ISGID)
		mode |= S_ISGID;

	inode = obdfs_new_inode(dir, mode);
	if ( IS_ERR(inode) ) {
		EXIT;
		return PTR_ERR(inode);
	}

	inode->i_op = &obdfs_dir_inode_operations;
	inode->i_blocks = 0;	
	inode_page = obdfs_getpage(inode, 0, 1, LOCKED);
	if (!inode_page) {
		inode->i_nlink--; /* is this nlink == 0? */
		mark_inode_dirty(inode);
		iput (inode);
		return -EIO;
	}
	de = (struct ext2_dir_entry_2 *) page_address(inode_page);

	/* create . and .. */
	de->inode = cpu_to_le32(inode->i_ino);
	de->name_len = 1;
	de->rec_len = cpu_to_le16(EXT2_DIR_REC_LEN(de->name_len));
	strcpy (de->name, ".");
	ext2_set_de_type(dir->i_sb, de, S_IFDIR);
	de = (struct ext2_dir_entry_2 *) ((char *) de + le16_to_cpu(de->rec_len));
	de->inode = cpu_to_le32(dir->i_ino);
	de->rec_len = cpu_to_le16(PAGE_SIZE - EXT2_DIR_REC_LEN(1));
	de->name_len = 2;
	strcpy (de->name, "..");
	ext2_set_de_type(dir->i_sb, de, S_IFDIR);
	inode->i_nlink = 2;
	
	err = obdfs_do_writepage(inode, inode_page, IS_SYNC(inode));
	inode->i_blocks = PAGE_SIZE/inode->i_sb->s_blocksize;
	inode->i_size = PAGE_SIZE;
	UnlockPage(inode_page);
	page_cache_release(inode_page);
	mark_inode_dirty(inode);
	if (err) {
		EXIT;
		goto out_no_entry;
	}

	/* now deal with the parent */
	page = obdfs_add_entry(dir, dentry->d_name.name, dentry->d_name.len, &de, &err);
	if (!page) {
		EXIT;
		goto out_no_entry;
	}

	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type(dir->i_sb, de, S_IFDIR);
	dir->i_version = ++event;

	dir->i_nlink++;
	dir->u.ext2_i.i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(dir);
	err = obdfs_do_writepage(dir, page, IS_SYNC(dir));

	UnlockPage(page);

	page_cache_release(page);
	d_instantiate(dentry, inode);
	EXIT;
out:
	return err;

out_no_entry:
	inode->i_nlink = 0;
	mark_inode_dirty(inode);
	iput (inode);
	goto out;
} /* obdfs_mkdir */


/*
 * routine to check that the specified directory is empty (for rmdir)
 */
static int empty_dir (struct inode * inode)
{
	unsigned long offset;
	struct page *page;
	struct ext2_dir_entry_2 * de, * de1;
	struct super_block * sb;

	sb = inode->i_sb;
	if (inode->i_size < EXT2_DIR_REC_LEN(1) + EXT2_DIR_REC_LEN(2) ||
	    !(page = obdfs_getpage (inode, 0, 0, LOCKED))) {
	    	ext2_warning (inode->i_sb, "empty_dir",
			      "bad directory (dir #%lu) - no data block",
			      inode->i_ino);
		return 1;
	}
	de = (struct ext2_dir_entry_2 *) page_address(page);
	de1 = (struct ext2_dir_entry_2 *) ((char *) de + le16_to_cpu(de->rec_len));
	if (le32_to_cpu(de->inode) != inode->i_ino || !le32_to_cpu(de1->inode) || 
	    strcmp (".", de->name) || strcmp ("..", de1->name)) {
	    	ext2_warning (inode->i_sb, "empty_dir",
			      "bad directory (dir #%lu) - no `.' or `..'",
			      inode->i_ino);
		page_cache_release(page);
		return 1;
	}
	offset = le16_to_cpu(de->rec_len) + le16_to_cpu(de1->rec_len);
	de = (struct ext2_dir_entry_2 *) ((char *) de1 + le16_to_cpu(de1->rec_len));
	while (offset < inode->i_size ) {
		if (!page || (void *) de >= (void *) (page_address(page) + PAGE_SIZE)) {
			if (page) {
				UnlockPage(page);
				page_cache_release(page);
			}
			page = obdfs_getpage(inode, offset, 0, LOCKED);
			if (!page) {
#if 0
				ext2_error (sb, "empty_dir",
					    "directory #%lu contains a hole at offset %lu",
					    inode->i_ino, offset);
#endif
				offset += sb->s_blocksize;
				continue;
			}
			de = (struct ext2_dir_entry_2 *) page_address(page);
		}
		if (!obdfs_check_dir_entry ("empty_dir", inode, de, page,
					   offset)) {
			UnlockPage(page);
			page_cache_release(page);
			return 1;
		}
		if (le32_to_cpu(de->inode)) {
			UnlockPage(page);
			page_cache_release(page);
			return 0;
		}
		offset += le16_to_cpu(de->rec_len);
		de = (struct ext2_dir_entry_2 *) ((char *) de + le16_to_cpu(de->rec_len));
	}
	UnlockPage(page);
	page_cache_release(page);
	return 1;
} /* empty_dir */

int obdfs_rmdir (struct inode * dir, struct dentry *dentry)
{
	int retval;
	struct inode * inode;
	struct page *page;
	struct ext2_dir_entry_2 * de;

	ENTRY;

	retval = -ENOENT;
	page = obdfs_find_entry (dir, dentry->d_name.name, dentry->d_name.len, &de, LOCKED);
	if (!page)
		goto end_rmdir;

	inode = dentry->d_inode;
	DQUOT_INIT(inode);

	retval = -EIO;
	if (le32_to_cpu(de->inode) != inode->i_ino)
		goto end_rmdir;

	retval = -ENOTEMPTY;
	if (!empty_dir (inode))
		goto end_rmdir;

	retval = obdfs_delete_entry (de, page);
	dir->i_version = ++event;
	if (retval)
		goto end_rmdir;
	retval = obdfs_do_writepage(dir, page, IS_SYNC(dir));
	/* XXX handle err? */
	UnlockPage(page);

	if (inode->i_nlink != 2)
		ext2_warning (inode->i_sb, "ext2_rmdir",
			      "empty directory has nlink!=2 (%d)",
			      inode->i_nlink);
	inode->i_version = ++event;
	inode->i_nlink = 0;
	inode->i_size = 0;
	mark_inode_dirty(inode);
	dir->i_nlink--;
	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	dir->u.ext2_i.i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(dir);
	d_delete(dentry);

end_rmdir:
	if ( page )
		page_cache_release(page);
	EXIT;
	return retval;
} /* obdfs_rmdir */

int obdfs_unlink(struct inode * dir, struct dentry *dentry)
{
	int retval;
	struct inode * inode;
	struct page *page;
	struct ext2_dir_entry_2 * de;

        ENTRY;

	retval = -ENOENT;
	page = obdfs_find_entry (dir, dentry->d_name.name, dentry->d_name.len, &de, LOCKED);
	if (!page)
		goto end_unlink;

	inode = dentry->d_inode;
	DQUOT_INIT(inode);

	retval = -EIO;
	if (le32_to_cpu(de->inode) != inode->i_ino)
		goto end_unlink;
	
	if (!inode->i_nlink) {
		ext2_warning (inode->i_sb, "ext2_unlink",
			      "Deleting nonexistent file (%lu), %d",
			      inode->i_ino, inode->i_nlink);
		inode->i_nlink = 1;
	}
	retval = obdfs_delete_entry (de, page);
	if (retval)
		goto end_unlink;
	dir->i_version = ++event;
	retval = obdfs_do_writepage(dir, page, IS_SYNC(dir));
	/* XXX handle err? */
	UnlockPage(page);

	dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	dir->u.ext2_i.i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(dir);
	inode->i_nlink--;
	mark_inode_dirty(inode);
	inode->i_ctime = dir->i_ctime;
	d_delete(dentry);	/* This also frees the inode */

end_unlink:
	if (page)
		page_cache_release(page);
	EXIT;
	return retval;
} /* obdfs_unlink */

int obdfs_symlink (struct inode * dir, struct dentry *dentry,
		   const char * symname)
{
	struct inode * inode;
	struct ext2_dir_entry_2 * de;
	struct obdfs_inode_info *oinfo;
	struct page* page = NULL, * name_page = NULL;
	char * link;
	int l, err;

        ENTRY;
	err = -ENAMETOOLONG;
	l = strlen(symname)+1;
	if (l > PAGE_SIZE) {
		EXIT;
		goto out;
	}

	inode = obdfs_new_inode(dir, S_IFLNK);
	if ( IS_ERR(inode) ) {
		EXIT;
		goto out;
	}

	inode->i_mode = S_IFLNK | S_IRWXUGO;
	oinfo = obdfs_i2info(inode);

	if (l >= sizeof(oinfo->oi_inline)) {
		CDEBUG(D_INFO, "l=%d, normal symlink\n", l);
		inode->i_op = &obdfs_symlink_inode_operations;

		name_page = obdfs_getpage(inode, 0, 1, LOCKED);
		if (!name_page) {
			EXIT;
			err = -ENOMEM;
			goto out_no_entry;
		}
		link = (char *)page_address(name_page);
	} else {
		CDEBUG(D_INFO, "l=%d, fast symlink\n", l);
		inode->i_op = &obdfs_fast_symlink_inode_operations;
		link = oinfo->oi_inline;
		oinfo->oi_flags |= OBD_FL_INLINEDATA;
	}
	memcpy(link, symname, l);
	if (name_page) {
		err = obdfs_do_writepage(inode, name_page, IS_SYNC(inode));
		/* PDEBUG(name_page, "symlink"); */
		UnlockPage(name_page);
		page_cache_release(name_page);
		if (err) {
			EXIT;
			goto out_no_entry;
		}
	}
	inode->i_size = l-1;
	mark_inode_dirty(inode);

	page = obdfs_add_entry (dir, dentry->d_name.name, dentry->d_name.len,
				&de, &err);
	if (!page)
		goto out_no_entry;
	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type(dir->i_sb, de, S_IFLNK);
	dir->i_version = ++event;
	err = obdfs_do_writepage(dir, page, IS_SYNC(dir));
	UnlockPage(page);

	d_instantiate(dentry, inode);
out:
	EXIT;
	return err;

out_no_entry:
	inode->i_nlink--;
	mark_inode_dirty(inode);
	iput (inode);
	goto out;
} /* obdfs_symlink */

int obdfs_link (struct dentry * old_dentry,
		struct inode * dir, struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	struct ext2_dir_entry_2 * de;
	struct page *page;
	int err;

        ENTRY;

	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	if (inode->i_nlink >= EXT2_LINK_MAX)
		return -EMLINK;

	page = obdfs_add_entry (dir, dentry->d_name.name, dentry->d_name.len, &de, &err);
	if (!page)
		return err;

	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type(dir->i_sb, de, inode->i_mode);
	dir->i_version = ++event;

	err = obdfs_do_writepage(dir, page, IS_SYNC(dir));
	UnlockPage(page);

	page_cache_release(page);
	inode->i_nlink++;
	inode->i_ctime = CURRENT_TIME;
	mark_inode_dirty(inode);
	inode->i_count++;
	d_instantiate(dentry, inode);
	return err;
} /* obdfs_link */

#define PARENT_INO(buffer) \
	((struct ext2_dir_entry_2 *) ((char *) buffer + \
	le16_to_cpu(((struct ext2_dir_entry_2 *) buffer)->rec_len)))->inode

/*
 * Anybody can rename anything with this: the permission checks are left to the
 * higher-level routines.
 */
int obdfs_rename (struct inode * old_dir, struct dentry *old_dentry,
			   struct inode * new_dir, struct dentry *new_dentry)
{
	struct inode * old_inode, * new_inode;
	struct page * old_page, * new_page, * dir_page;
	struct ext2_dir_entry_2 * old_de, * new_de;
	int retval;

        ENTRY;

	new_page = dir_page = NULL;

	/* does the old entry exist? - if not get out */
	old_page = obdfs_find_entry (old_dir, old_dentry->d_name.name, old_dentry->d_name.len, &old_de, NOLOCK);
	/* PDEBUG(old_page, "rename - old page"); */
	/*
	 *  Check for inode number is _not_ due to possible IO errors.
	 *  We might rmdir the source, keep it as pwd of some process
	 *  and merrily kill the link to whatever was created under the
	 *  same name. Goodbye sticky bit ;-<
	 */
	old_inode = old_dentry->d_inode;
	retval = -ENOENT;
	if (!old_page || le32_to_cpu(old_de->inode) != old_inode->i_ino) {
		EXIT;
		goto end_rename;
	}

	/* find new inode */
	new_inode = new_dentry->d_inode;
	new_page = obdfs_find_entry (new_dir, new_dentry->d_name.name,
				new_dentry->d_name.len, &new_de, NOLOCK);
	/* PDEBUG(new_page, "rename - new page "); */
	if (new_page) {
		if (!new_inode) {
			page_cache_release(new_page);
			new_page = NULL;
		} else {
			DQUOT_INIT(new_inode);
		}
	}
	/* in this case we to check more ... */
	if (S_ISDIR(old_inode->i_mode)) {
		/* can only rename into empty new directory */
		if (new_inode) {
			retval = -ENOTEMPTY;
			if (!empty_dir (new_inode)) {
				EXIT;
				goto end_rename;
			}
		}
		retval = -EIO;
		dir_page = obdfs_getpage (old_inode, 0, 0, LOCKED);
		/* PDEBUG(dir_page, "rename dir page"); */

		if (!dir_page) {
			EXIT;
			goto end_rename;
		}
		if (le32_to_cpu(PARENT_INO(page_address(dir_page))) !=
		    old_dir->i_ino) {
			EXIT;
			goto end_rename;
		}
		retval = -EMLINK;
		if (!new_inode && new_dir!=old_dir &&
				new_dir->i_nlink >= EXT2_LINK_MAX) {
			EXIT;
			goto end_rename;
		}
	}
	/* create the target dir entry */
	if (!new_page) {
		new_page = obdfs_add_entry (new_dir, new_dentry->d_name.name,
					    new_dentry->d_name.len, &new_de,
					    &retval);
		/* PDEBUG(new_page, "rename new page"); */
		if (!new_page) {
			EXIT;
			goto end_rename;
		}
	}
	new_dir->i_version = ++event;

	/*
	 * remove the old entry
	 */
	new_de->inode = le32_to_cpu(old_inode->i_ino);
	if (EXT2_HAS_INCOMPAT_FEATURE(new_dir->i_sb,
				      EXT2_FEATURE_INCOMPAT_FILETYPE))
		new_de->file_type = old_de->file_type;
	
	obdfs_delete_entry (old_de, old_page);

	old_dir->i_version = ++event;
	if (new_inode) {
		new_inode->i_nlink--;
		new_inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(new_inode);
	}
	old_dir->i_ctime = old_dir->i_mtime = CURRENT_TIME;
	old_dir->u.ext2_i.i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(old_dir);
	if (dir_page) {
		PARENT_INO(page_address(dir_page)) =le32_to_cpu(new_dir->i_ino);
		retval = obdfs_do_writepage(old_inode, dir_page,
					    IS_SYNC(old_inode));
		/* XXX handle err - not sure if this is correct */
		if (retval) {
			EXIT;
			goto end_rename;
		}
		old_dir->i_nlink--;
		mark_inode_dirty(old_dir);
		if (new_inode) {
			new_inode->i_nlink--;
			mark_inode_dirty(new_inode);
		} else {
			new_dir->i_nlink++;
			new_dir->u.ext2_i.i_flags &= ~EXT2_BTREE_FL;
			mark_inode_dirty(new_dir);
		}
	}
	if ( old_page != new_page ) {
		unsigned long index = old_page->index;
		/* lock the old_page and release unlocked copy */
		CDEBUG(D_INFO, "old_page at %p\n", old_page);
		page_cache_release(old_page);
		old_page = obdfs_getpage(old_dir, index << PAGE_SHIFT, 0,
					 LOCKED);
		CDEBUG(D_INFO, "old_page at %p\n", old_page);
		retval = obdfs_do_writepage(old_dir, old_page,IS_SYNC(old_dir));
		/* XXX handle err - not sure if this is correct */
		if (retval) {
			EXIT;
			goto end_rename;
		}
	}

	retval = obdfs_do_writepage(new_dir, new_page, IS_SYNC(new_dir));

end_rename:
	if (old_page && PageLocked(old_page) )
		UnlockPage(old_page);
	if (old_page)
		page_cache_release(old_page);
	if (new_page && PageLocked(new_page) )
		UnlockPage(new_page);
	if (new_page)
		page_cache_release(new_page);
	if (dir_page && PageLocked(dir_page) )
		UnlockPage(dir_page);
	if (dir_page)
		page_cache_release(dir_page);

	return retval;
} /* obdfs_rename */
