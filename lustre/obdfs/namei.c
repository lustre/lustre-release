/*
 *  linux/fs/obdfs/namei.c
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
#include <linux/obdfs.h>
extern struct address_space_operations obdfs_aops;
/*
 * Couple of helper functions - make the code slightly cleaner.
 */

extern int ext2_add_link (struct dentry *dentry, struct inode *inode);
extern ino_t ext2_inode_by_name(struct inode * dir, struct dentry *dentry);
int ext2_make_empty(struct inode *inode, struct inode *parent);
struct ext2_dir_entry_2 * ext2_find_entry (struct inode * dir,
		   struct dentry *dentry, struct page ** res_page);
int ext2_delete_entry (struct ext2_dir_entry_2 * dir, struct page * page );


static inline void ext2_inc_count(struct inode *inode)
{
	inode->i_nlink++;
	mark_inode_dirty(inode);
}

static inline void ext2_dec_count(struct inode *inode)
{
	inode->i_nlink--;
	mark_inode_dirty(inode);
}

static inline int ext2_add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = ext2_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	ext2_dec_count(inode);
	iput(inode);
	return err;
}

/* methods */
struct dentry *new_obdfs_lookup(struct inode * dir, struct dentry *dentry)
{
	struct inode * inode;
	ino_t ino;
	
	if (dentry->d_name.len > EXT2_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = ext2_inode_by_name(dir, dentry);
	inode = NULL;
	if (ino) {
		inode = iget(dir->i_sb, ino);
		if (!inode) 
			return ERR_PTR(-EACCES);
	}
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


/*
 *      obdfs_find_entry()
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
                obd_unlock_page(page);
                page_cache_release(page);
                page = NULL;
                CDEBUG(D_INFO, "Next for %lx\n", offset);
        }

failure:
        CDEBUG(D_INFO, "Negative case, page %p, offset %ld\n", page, offset);
        if (page) {
                obd_unlock_page(page);
                page_cache_release(page);
        }
        EXIT;
        return NULL;
} /* obdfs_find_entry */

/*
 *      obdfs_add_entry()
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
                        obd_unlock_page(page);
                        page_cache_release(page);
                        page = obdfs_getpage(dir, offset, 1, LOCKED);
                        if (!page) {
                                EXIT;
                                return NULL;
                        }
                        /* PDEBUG(page, "new directory page"); */
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

                                CDEBUG(D_INFO, "skipping to next block\n");

                                de = (struct ext2_dir_entry_2 *) page_address(page);
                        }
                }
                if (!obdfs_check_dir_entry ("ext2_add_entry", dir, de, page,
                                           offset)) {
                        *err = -ENOENT;
                        obd_unlock_page(page);
                        page_cache_release(page);
                        EXIT;
                        return NULL;
                }
                CDEBUG(D_INFO, "\n");
                if (ext2_match (namelen, name, de)) {
                                *err = -EEXIST;
                                obd_unlock_page(page);
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
			//                        PDEBUG(page, "add_entry");
                        /* XXX unlock page here */
                        EXIT;
                        return page;
                }
                offset += le16_to_cpu(de->rec_len);
                de = (struct ext2_dir_entry_2 *) ((char *) de + le16_to_cpu(de->rec_len));
        }

        obd_unlock_page(page);
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
        return;
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
	struct inode * inode = obdfs_new_inode (dir, mode);
	int err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		inode->i_op = &obdfs_file_inode_operations;
		inode->i_fop = &obdfs_file_operations;
		inode->i_mapping->a_ops = &obdfs_aops;
		mark_inode_dirty(inode);
		err = ext2_add_nondir(dentry, inode);
	}
	return err;
} /* obdfs_create */


int obdfs_mknod (struct inode * dir, struct dentry *dentry, int mode, int rdev)
{
	struct inode * inode = obdfs_new_inode (dir, mode);
	int err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		init_special_inode(inode, mode, rdev);
		mark_inode_dirty(inode);
		err = ext2_add_nondir(dentry, inode);
	}
	return err;
}

int obdfs_symlink (struct inode * dir, struct dentry * dentry,
	const char * symname)
{
	struct super_block * sb = dir->i_sb;
	int err = -ENAMETOOLONG;
	unsigned l = strlen(symname)+1;
	struct inode * inode;
        struct obdfs_inode_info *oinfo;
        oinfo = obdfs_i2info(inode);

	if (l > sb->s_blocksize)
		goto out;

	inode = obdfs_new_inode (dir, S_IFLNK | S_IRWXUGO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

        if (l >= sizeof(oinfo->oi_inline)) {
		/* slow symlink */
		inode->i_op = &obdfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &obdfs_aops;
		err = block_symlink(inode, symname, l);
		if (err)
			goto out_fail;
	} else {
		/* fast symlink */
		inode->i_op = &obdfs_fast_symlink_inode_operations;
		memcpy((char*)&inode->u.ext2_i.i_data,symname,l);
		inode->i_size = l-1;
	}
	mark_inode_dirty(inode);

	err = ext2_add_nondir(dentry, inode);
out:
	return err;

out_fail:
	ext2_dec_count(inode);
	iput (inode);
	goto out;
}



int obdfs_link (struct dentry * old_dentry, struct inode * dir,
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


int obdfs_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
	struct inode * inode;
	int err = -EMLINK;

	if (dir->i_nlink >= EXT2_LINK_MAX)
		goto out;

	ext2_inc_count(dir);

	inode = obdfs_new_inode (dir, S_IFDIR | mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	inode->i_op = &obdfs_dir_inode_operations;
	inode->i_fop = &obdfs_dir_operations;
	inode->i_mapping->a_ops = &obdfs_aops;

	ext2_inc_count(inode);

	err = ext2_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = ext2_add_link(dentry, inode);
	if (err)
		goto out_fail;

	d_instantiate(dentry, inode);
out:
	return err;

out_fail:
	ext2_dec_count(inode);
	ext2_dec_count(inode);
	iput(inode);
out_dir:
	ext2_dec_count(dir);
	goto out;
}

int obdfs_unlink(struct inode * dir, struct dentry *dentry)
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
                                obd_unlock_page(page);
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
                        obd_unlock_page(page);
                        page_cache_release(page);
                        return 1;
                }
                if (le32_to_cpu(de->inode)) {
                        obd_unlock_page(page);
                        page_cache_release(page);
                        return 0;
                }
                offset += le16_to_cpu(de->rec_len);
                de = (struct ext2_dir_entry_2 *) ((char *) de + le16_to_cpu(de->rec_len));
        }
        obd_unlock_page(page);
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
        retval = obdfs_do_writepage(page, IS_SYNC(dir));
        /* XXX handle err? */
        obd_unlock_page(page);

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
                retval = obdfs_do_writepage(dir_page, IS_SYNC(old_inode));
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
                retval = obdfs_do_writepage(old_page,IS_SYNC(old_dir));
                /* XXX handle err - not sure if this is correct */
                if (retval) {
                        EXIT;
                        goto end_rename;
                }
        }

        retval = obdfs_do_writepage(new_page, IS_SYNC(new_dir));

end_rename:
        if (old_page && PageLocked(old_page) )
                obd_unlock_page(old_page);
        if (old_page)
                page_cache_release(old_page);
        if (new_page && PageLocked(new_page) )
                obd_unlock_page(new_page);
        if (new_page)
                page_cache_release(new_page);
        if (dir_page && PageLocked(dir_page) )
                obd_unlock_page(dir_page);
        if (dir_page)
                page_cache_release(dir_page);

        return retval;
} /* obdfs_rename */
