// SPDX-License-Identifier: GPL-2.0

/*
 * lustre/osd-wbcfs/osd_wbcfs.c
 *
 * Author: Yingjin Qian <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM	S_OSD

#include <linux/namei.h>
#include <linux/file.h>
#include <linux/uidgid.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/xattr.h>
#include <linux/swap.h>
#include <linux/statfs.h>
#ifdef HAVE_FS_CONTEXT_H
#include <linux/fs_context.h>
#endif

#include <lustre_compat.h>

#include "wbcfs.h"

#ifndef HAVE_USER_NAMESPACE_ARG
#define inode_init_owner(ns, inode, dir, mode)  \
	inode_init_owner(inode, dir, mode)
#define memfs_mknod(ns, dir, dch, mode, rd)	memfs_mknod(dir, dch, mode, rd)
#define memfs_mkdir(ns, dir, dch, mode)		memfs_mkdir(dir, dch, mode)
#define memfs_create_nd(ns, dir, de, mode, ex)	\
	memfs_create_nd(dir, de, mode, ex)
#endif /* HAVE_USER_NAMESPCE_ARG */

/*
 * In-memory xattr entry.
 * Borrowed from osd-ldiskfs @osd_xattr_entry and @simple_xattrs in Linux
 * kernel. This part of codes in-memory XATTRs should put into libcfs module.
 * The first part of @mxe_buf is XATTR name, and is '\0' terminated.
 * The left part is for value, binary mode.
 */
struct mem_xattr_entry {
	struct list_head	mxe_list;
	size_t			mxe_len;
	size_t			mxe_namelen;
	bool			mxe_exist;
	struct rcu_head		mxe_rcu;
	char			mxe_buf[];
};

static int mem_xattr_get(struct mem_xattrs *xattrs, const char *name,
			 void *buf, size_t len)
{
	struct mem_xattr_entry *mxe = NULL;
	struct mem_xattr_entry *tmp;
	size_t namelen = strlen(name);
	int rc;

	ENTRY;

	rcu_read_lock();
	list_for_each_entry_rcu(tmp, &xattrs->mex_xattr_list, mxe_list) {
		if (namelen == tmp->mxe_namelen &&
		    strncmp(name, tmp->mxe_buf, namelen) == 0) {
			mxe = tmp;
			break;
		}
	}

	if (mxe == NULL)
		GOTO(out, rc = -ENODATA);

	if (!mxe->mxe_exist)
		GOTO(out, rc = -ENODATA);

	/* Value length */
	rc = mxe->mxe_len - sizeof(*mxe) - mxe->mxe_namelen - 1;
	LASSERT(rc > 0);

	if (buf == NULL)
		GOTO(out, rc);

	if (len < rc)
		GOTO(out, rc = -ERANGE);

	memcpy(buf, &mxe->mxe_buf[namelen + 1], rc);
out:
	rcu_read_unlock();
	RETURN(rc);
}

static void mem_xattr_free(struct rcu_head *head)
{
	struct mem_xattr_entry *mxe;

	mxe = container_of(head, struct mem_xattr_entry, mxe_rcu);
	OBD_FREE(mxe, mxe->mxe_len);
}

static int mem_xattr_add(struct mem_xattrs *xattrs, const char *name,
			 const char *buf, int buflen)
{
	struct mem_xattr_entry *mxe;
	struct mem_xattr_entry *old = NULL;
	struct mem_xattr_entry *tmp;
	size_t namelen = strlen(name);
	size_t len = sizeof(*mxe) + namelen + 1 + buflen;

	ENTRY;

	OBD_ALLOC(mxe, len);
	if (mxe == NULL)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&mxe->mxe_list);
	mxe->mxe_len = len;
	mxe->mxe_namelen = namelen;
	memcpy(mxe->mxe_buf, name, namelen);
	if (buflen > 0) {
		LASSERT(buf != NULL);
		memcpy(mxe->mxe_buf + namelen + 1, buf, buflen);
		mxe->mxe_exist = true;
	} else {
		mxe->mxe_exist = false;
	}

	/* This should be rarely called, just remove old and add new */
	spin_lock(&xattrs->mex_lock);
	list_for_each_entry(tmp, &xattrs->mex_xattr_list, mxe_list) {
		if (namelen == tmp->mxe_namelen &&
		    strncmp(name, tmp->mxe_buf, namelen) == 0) {
			old = tmp;
			break;
		}
	}
	if (old != NULL) {
		list_replace_rcu(&old->mxe_list, &mxe->mxe_list);
		call_rcu(&old->mxe_rcu, mem_xattr_free);
	} else {
		list_add_tail_rcu(&mxe->mxe_list, &xattrs->mex_xattr_list);
	}
	spin_unlock(&xattrs->mex_lock);

	RETURN(0);
}

static void mem_xattr_del(struct mem_xattrs *xattrs, const char *name)
{
	struct mem_xattr_entry *mxe;
	size_t namelen = strlen(name);

	spin_lock(&xattrs->mex_lock);
	list_for_each_entry(mxe, &xattrs->mex_xattr_list, mxe_list) {
		if (namelen == mxe->mxe_namelen &&
		    strncmp(name, mxe->mxe_buf, namelen) == 0) {
			list_del_rcu(&mxe->mxe_list);
			call_rcu(&mxe->mxe_rcu, mem_xattr_free);
			break;
		}
	}
	spin_unlock(&xattrs->mex_lock);
}

static inline void mem_xattrs_init(struct mem_xattrs *xattrs)
{
	INIT_LIST_HEAD(&xattrs->mex_xattr_list);
	spin_lock_init(&xattrs->mex_lock);
}

static void mem_xattrs_fini(struct mem_xattrs *xattrs)
{
	struct mem_xattr_entry *mxe, *next;

	list_for_each_entry_safe(mxe, next, &xattrs->mex_xattr_list, mxe_list) {
		list_del(&mxe->mxe_list);
		OBD_FREE(mxe, mxe->mxe_len);
	}
}

int memfs_xattr_get(struct inode *inode, void *buf, size_t len,
		    const char *name)
{
	return mem_xattr_get(&MEMFS_I(inode)->mei_xattrs, name, buf, len);
}

int memfs_xattr_set(struct inode *inode, void *buf, size_t len,
		    const char *name, int flags)
{
	return mem_xattr_add(&MEMFS_I(inode)->mei_xattrs, name, buf, len);
}

void memfs_xattr_del(struct inode *inode, const char *name)
{
	mem_xattr_del(&MEMFS_I(inode)->mei_xattrs, name);
}

static const struct super_operations memfs_ops;
static const struct address_space_operations memfs_aops;
static const struct file_operations memfs_file_operations;
static const struct inode_operations memfs_inode_operations;
static const struct file_operations memfs_dir_operations;
static const struct inode_operations memfs_dir_inode_operations;
static struct file_system_type memfs_fstype;

static inline struct memfs_sb_info *MEMFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static int memfs_reserve_inode(struct super_block *sb)
{
	return 0;
}

static void memfs_free_inode(struct super_block *sb)
{
}

struct inode *memfs_create_inode(struct super_block *sb, struct inode *dir,
				 umode_t mode, struct iattr *iattr, dev_t dev,
				 bool update_link)
{
	struct memfs_sb_info *sbinfo = MEMFS_SB(sb);
	struct memfs_inode_info *mei;
	struct inode *inode;

	ENTRY;

	inode = new_inode(sb);
	if (!inode)
		RETURN(ERR_PTR(-ENOMEM));

	if (iattr) {
		uid_t owner[2] = { 0, 0 };

		if (iattr->ia_valid & ATTR_UID)
			owner[0] = from_kuid(&init_user_ns, iattr->ia_uid);
		if (iattr->ia_valid & ATTR_GID)
			owner[1] = from_kgid(&init_user_ns, iattr->ia_gid);

		inode->i_mode = mode;
		i_uid_write(inode, owner[0]);
		i_gid_write(inode, owner[1]);
	} else {
		inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
	}

	if (iattr) {
		if (iattr->ia_valid & ATTR_CTIME)
			inode_set_ctime_to_ts(inode, iattr->ia_ctime);
		if (iattr->ia_valid & ATTR_MTIME)
			inode_set_mtime_to_ts(inode, iattr->ia_mtime);
		if (iattr->ia_valid & ATTR_ATIME)
			inode_set_atime_to_ts(inode, iattr->ia_atime);
	}

	inode->i_blocks = 0;

	mei = MEMFS_I(inode);
	mei->mei_crtime = inode_get_mtime(inode);
	mem_xattrs_init(&mei->mei_xattrs);
	mei->mei_index_type = INDEX_TYPE_NONE;
	cache_no_acl(inode);

	if (sbinfo->msi_noswap)
		mapping_set_unevictable(inode->i_mapping);

	switch (mode & S_IFMT) {
	case S_IFREG:
		inode->i_mapping->a_ops = &memfs_aops;
		inode->i_op = &memfs_inode_operations;
		inode->i_fop = &memfs_file_operations;
		break;
	case S_IFDIR:
		if (update_link)
			inc_nlink(inode);
		/* Some things misbehave if size == 0 on a directory */
		inode->i_size = 2 * BOGO_DIRENT_SIZE;
		inode->i_op = &memfs_dir_inode_operations;
		inode->i_fop = &memfs_dir_operations;
		break;
	case S_IFLNK:
		break;
	default:
		CERROR("Unsupport file mode %#o\n", mode);
		iput(inode);
		/*
		 * TODO: Add support for other file types.
		 * Fix the error in sanity/test_28.
		 */
		RETURN(ERR_PTR(-EOPNOTSUPP));
	}

	return inode;
}

static int memfs_mknod(struct mnt_idmap *map, struct inode *dir,
		       struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode *inode;

	ENTRY;

	inode = memfs_create_inode(dir->i_sb, dir, mode, NULL, dev, true);
	if (IS_ERR(inode))
		RETURN(PTR_ERR(inode));

	dir->i_size += BOGO_DIRENT_SIZE;
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	d_instantiate(dentry, inode);
	dget(dentry); /* Extra count - pin the dentry in core */

	RETURN(0);
}

static int memfs_mkdir(struct mnt_idmap *map, struct inode *dir,
		       struct dentry *dchild, umode_t mode)
{
	int rc;

	rc = memfs_mknod(map, dir, dchild, mode | S_IFDIR, 0);
	if (rc)
		return rc;

	inc_nlink(dir);
	return 0;
}

static int memfs_create_nd(struct mnt_idmap *map, struct inode *dir,
			   struct dentry *dentry, umode_t mode, bool want_excl)
{
	return memfs_mknod(map, dir, dentry, mode | S_IFREG, 0);
}

static int memfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);

	if (inode->i_nlink > 1 && !S_ISDIR(inode->i_mode))
		memfs_free_inode(inode->i_sb);

	dir->i_size -= BOGO_DIRENT_SIZE;
	inode_set_mtime_to_ts(dir, inode_set_ctime_to_ts(dir,
			      inode_set_ctime_current(inode)));
	inode_inc_iversion(dir);
	drop_nlink(inode);
	dput(dentry);
	return 0;
}

static int memfs_rmdir(struct inode *dir, struct dentry *dchild)
{
	if (!simple_empty(dchild))
		return -ENOTEMPTY;

	drop_nlink(d_inode(dchild));
	drop_nlink(dir);
	return memfs_unlink(dir, dchild);
}

static int memfs_link(struct dentry *old_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);

	ENTRY;

	/*
	 * No ordinary (disk based) filesystem counts links as inodes;
	 * but each new link needs a new dentry, pinning lowmem, and
	 * tmpfs dentries cannot be pruned until they are unlinked.
	 * But if an O_TMPFILE file is linked into the tmpfs, the
	 * first link must skip that, to get the accounting right.
	 */
	if (inode->i_nlink) {
		int rc = 0;

		rc = memfs_reserve_inode(inode->i_sb);
		if (rc)
			RETURN(rc);
	}

	dir->i_size += BOGO_DIRENT_SIZE;
	inode_set_mtime_to_ts(dir, inode_set_ctime_to_ts(dir,
			      inode_set_ctime_current(inode)));
	inode_inc_iversion(dir);
	inc_nlink(inode);
	ihold(inode);	/* New dentry reference */
	dget(dentry);	/* Extra pinning count for the created dentry */
	d_instantiate(dentry, inode);
	return 0;
}

#ifdef HAVE_DENTRY_D_CHILDREN
/* parent is locked at least shared */
/*
 * Returns an element of siblings' list.
 * We are looking for <count>th positive after <p>; if
 * found, dentry is grabbed and returned to caller.
 * If no such element exists, NULL is returned.
 */
static struct dentry *scan_positives(struct dentry *cursor,
					struct hlist_node **p,
					loff_t count,
					struct dentry *last)
{
	struct dentry *dentry = cursor->d_parent, *found = NULL;

	spin_lock(&dentry->d_lock);
	while (*p) {
		struct dentry *d = hlist_entry(*p, struct dentry, d_sib);

		p = &d->d_sib.next;
		// we must at least skip cursors, to avoid livelocks
		if (d->d_flags & DCACHE_DENTRY_CURSOR)
			continue;
		if (simple_positive(d) && !--count) {
			spin_lock_nested(&d->d_lock, DENTRY_D_LOCK_NESTED);
			if (simple_positive(d))
				found = dget_dlock(d);
			spin_unlock(&d->d_lock);
			if (likely(found))
				break;
			count = 1;
		}
		if (need_resched()) {
			if (!hlist_unhashed(&cursor->d_sib))
				__hlist_del(&cursor->d_sib);
			hlist_add_behind(&cursor->d_sib, &d->d_sib);
			p = &cursor->d_sib.next;
			spin_unlock(&dentry->d_lock);
			cond_resched();
			spin_lock(&dentry->d_lock);
		}
	}
	spin_unlock(&dentry->d_lock);
	dput(last);
	return found;
}

/*
 * Directory is locked and all positive dentries in it are safe, since
 * for ramfs-type trees they can't go away without unlink() or rmdir(),
 * both impossible due to the lock on directory.
 */

static int memfs_dcache_readdir(struct file *file, struct dir_context *ctx)
{
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *cursor = file->private_data;
	struct memfs_dir_context *mctx = (struct memfs_dir_context *)ctx;
	struct dentry *next = NULL;
	struct hlist_node **p;

	if (!dir_emit_dots(file, ctx))
		return 0;

	if (ctx->pos == 2)
		p = &dentry->d_children.first;
	else
		p = &cursor->d_sib.next;

	while ((next = scan_positives(cursor, p, 1, next)) != NULL) {
		mctx->dentry = next;
		if (!dir_emit(ctx, next->d_name.name, next->d_name.len,
			      d_inode(next)->i_ino,
			      fs_umode_to_dtype(d_inode(next)->i_mode)))
			break;
		ctx->pos++;
		p = &next->d_sib.next;
	}
	spin_lock(&dentry->d_lock);
	hlist_del_init(&cursor->d_sib);
	if (next)
		hlist_add_before(&cursor->d_sib, &next->d_sib);
	spin_unlock(&dentry->d_lock);
	dput(next);

	return 0;
}

#else /* !HAVE_DENTRY_D_CHILDREN */

/* Relationship between i_mode and the DT_xxx types */
static inline unsigned char dt_type(struct inode *inode)
{
	return (inode->i_mode >> 12) & 15;
}

/*
 * linux/fs/libfs.c: simple_positive()
 * Public in linux/include/linux/dcache.h
 * kernel 4.1-rc3 commit dc3f4198eac14e52a98dfc79cd84b45e280f59cd
 */
static inline int __simple_positive(struct dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

/*
 * Returns an element of siblings' list.
 * We are looking for <count>th positive after <p>; if
 * found, dentry is grabbed and returned to caller.
 * If no such element exists, NULL is returned.
 */
/* parent is locked at least shared */
static struct dentry *scan_positives(struct dentry *cursor,
					struct list_head *p,
					loff_t count,
					struct dentry *last)
{
	struct dentry *dentry = cursor->d_parent, *found = NULL;

	spin_lock(&dentry->d_lock);
	while ((p = p->next) != &dentry->d_subdirs) {
		struct dentry *d = list_entry(p, struct dentry, d_child);
		/* We must at least skip cursors, to avoid livelocks */
		if (d->d_flags & DCACHE_DENTRY_CURSOR)
			continue;
		if (__simple_positive(d) && !--count) {
			spin_lock_nested(&d->d_lock, DENTRY_D_LOCK_NESTED);
			if (__simple_positive(d))
				found = dget_dlock(d);
			spin_unlock(&d->d_lock);
			if (likely(found))
				break;
			count = 1;
		}
		if (need_resched()) {
			list_move(&cursor->d_child, p);
			p = &cursor->d_child;
			spin_unlock(&dentry->d_lock);
			cond_resched();
			spin_lock(&dentry->d_lock);
		}
	}
	spin_unlock(&dentry->d_lock);
	dput(last);
	return found;
}

/* linux/fs/libfs.c: dcache_readdir() */
/*
 * Directory is locked and all positive dentries in it are safe, since
 * for ramfs-type trees they can't go away without unlink() or rmdir(),
 * both impossible due to the lock on directory.
 */
static int memfs_dcache_readdir(struct file *file, struct dir_context *ctx)
{
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *cursor = file->private_data;
	struct list_head *anchor = &dentry->d_subdirs;
	struct memfs_dir_context *mctx = (struct memfs_dir_context *)ctx;
	struct dentry *next = NULL;
	struct list_head *p;

	if (!dir_emit_dots(file, ctx))
		return 0;

	if (ctx->pos == 2)
		p = anchor;
	else if (!list_empty(&cursor->d_child))
		p = &cursor->d_child;
	else
		return 0;

	while ((next = scan_positives(cursor, p, 1, next)) != NULL) {
		/*
		 * TODO: Add a new f_flags O_HAVE_DIR_CONTEXT_EXT to
		 * distinguish the normal readdir() access from the user space.
		 */
		mctx->dentry = next;
		if (!dir_emit(ctx, next->d_name.name, next->d_name.len,
			      d_inode(next)->i_ino, dt_type(d_inode(next))))
			break;
		ctx->pos++;
		p = &next->d_child;
	}
	spin_lock(&dentry->d_lock);
	if (next)
		list_move_tail(&cursor->d_child, &next->d_child);
	else
		list_del_init(&cursor->d_child);
	spin_unlock(&dentry->d_lock);
	dput(next);

	return 0;
}
#endif /* HAVE_DENTRY_D_CHILDREN */

/*
 * Copied from @simple_write_end in the kernel.
 * It does not export on the new kernel such as rhel9.
 */
static int memfs_write_end(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned int len, unsigned int copied,
			   struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;
	loff_t last_pos = pos + copied;

	/* zero the stale part of the page if we did a short copy */
	if (!PageUptodate(page)) {
		if (copied < len) {
			unsigned int from = pos & (PAGE_SIZE - 1);

			zero_user(page, from + copied, len - copied);
		}
		SetPageUptodate(page);
	}
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold the i_mutex.
	 */
	if (last_pos > inode->i_size)
		i_size_write(inode, last_pos);

	set_page_dirty(page);
	unlock_page(page);
	put_page(page);

	return copied;
}

/* TODO: implement file splice read/write interface for MemFS. */
static ssize_t memfs_file_splice_read(struct file *in_file, loff_t *ppos,
				      struct pipe_inode_info *pipe,
				      size_t count, unsigned int flags)
{
	RETURN(0);
}

/*
 * linux/mm/shmem.c
 * TODO: mmap support.
 */
static int memfs_getpage(struct inode *inode, pgoff_t index,
			 struct page **pagep)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;

	if (index > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return -EFBIG;

	page = find_lock_page(mapping, index);
	/* fallocated page? */
	if (page && !PageUptodate(page)) {
		unlock_page(page);
		put_page(page);
		page = NULL;
	}

	*pagep = page;
	return 0;
}

#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
/* linux/mm/shmem.c shmem_file_read_iter() */
static ssize_t memfs_file_read_iter(struct kiocb *iocb,
				    struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	loff_t *ppos = &iocb->ki_pos;
	unsigned long offset;
	ssize_t retval = 0;
	pgoff_t index;
	int error = 0;

	ENTRY;

	/*
	 * Might this read be for a stacking filesystem?  Then when reading
	 * holes of a sparse file, we actually need to allocate those pages,
	 * and even mark them dirty, so it cannot exceed the max_blocks limit.
	 */

	index = *ppos >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page = NULL;
		pgoff_t end_index;
		unsigned long nr, ret;
		loff_t i_size = i_size_read(inode);

		end_index = i_size >> PAGE_SHIFT;
		if (index > end_index)
			break;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset)
				break;
		}

		error = memfs_getpage(inode, index, &page);
		if (error) {
			if (error == -EINVAL)
				error = 0;
			break;
		}
		if (page)
			unlock_page(page);

		/*
		 * We must evaluate after, since reads (unlike writes)
		 * are called without i_mutex protection against truncate
		 */
		nr = PAGE_SIZE;
		i_size = i_size_read(inode);
		end_index = i_size >> PAGE_SHIFT;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset) {
				if (page)
					put_page(page);
				break;
			}
		}
		nr -= offset;

		if (page) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_page(page);
			/*
			 * Mark the page accessed if we read the beginning.
			 */
			if (!offset)
				mark_page_accessed(page);
		} else {
			page = ZERO_PAGE(0);
			get_page(page);
		}

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 */
		ret = copy_page_to_iter(page, offset, nr, to);
		retval += ret;
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;

		put_page(page);
		if (!iov_iter_count(to))
			break;
		if (ret < nr) {
			error = -EFAULT;
			break;
		}
		cond_resched();
	}

	*ppos = ((loff_t) index << PAGE_SHIFT) + offset;
	file_accessed(file);
	return retval ? retval : error;
}

/* TODO: space limiting for write. */
static ssize_t memfs_file_write_iter(struct kiocb *iocb,
				     struct iov_iter *iter)
{
	RETURN(generic_file_write_iter(iocb, iter));
}

#else

/*
 * It can not use simple_readpage() directly in Linux ramfs especially when
 * there are holes in the file which is cached MemFS. It must rewrite the read
 * VFS interface similar to Linux tmpfs.
 */
/* linux/mm/filemap.c */
static int memfs_file_read_actor(read_descriptor_t *desc, struct page *page,
				 unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long left, count = desc->count;

	if (size > count)
		size = count;

	/*
	 * Faults on the destination of a read are common, so do it before
	 * taking the kmap.
	 */
	if (IS_ENABLED(CONFIG_HIGHMEM) &&
	    !fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page);
		left = __copy_to_user_inatomic(desc->arg.buf,
						kaddr + offset, size);
		kunmap_atomic(kaddr);
		if (left == 0)
			goto success;
	}

	/* Do it the slow way */
	kaddr = kmap(page);
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);
	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
success:
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

/* linux/mm/shmem.c do_shmem_file_read() */
static void do_memfs_file_read(struct file *filp,
			       loff_t *ppos, read_descriptor_t *desc,
			       read_actor_t actor)
{
	struct inode *inode = file_inode(filp);
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index;
	unsigned long offset;

	/*
	 * Might this read be for a stacking filesystem?  Then when reading
	 * holes of a sparse file, we actually need to allocate those pages,
	 * and even mark them dirty, so it cannot exceed the max_blocks limit.
	 */

	index = *ppos >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page = NULL;
		pgoff_t end_index;
		unsigned long nr, ret;
		loff_t i_size = i_size_read(inode);

		end_index = i_size >> PAGE_SHIFT;
		if (index > end_index)
			break;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset)
				break;
		}

		desc->error = memfs_getpage(inode, index, &page);
		if (desc->error) {
			if (desc->error == -EINVAL)
				desc->error = 0;
			break;
		}
		if (page)
			unlock_page(page);

		/*
		 * We must evaluate after, since reads (unlike writes)
		 * are called without i_mutex protection against truncate
		 */
		nr = PAGE_SIZE;
		i_size = i_size_read(inode);
		end_index = i_size >> PAGE_SHIFT;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset) {
				if (page)
					put_page(page);
				break;
			}
		}
		nr -= offset;

		if (page) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_page(page);
			/*
			 * Mark the page accessed if we read the beginning.
			 */
			if (!offset)
				mark_page_accessed(page);
		} else {
			page = ZERO_PAGE(0);
			get_page(page);
		}

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		ret = actor(desc, page, offset, nr);
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;

		put_page(page);
		if (ret != nr || !desc->count)
			break;

		cond_resched();
	}

	*ppos = ((loff_t) index << PAGE_SHIFT) + offset;
	file_accessed(filp);
}

static ssize_t memfs_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
				   unsigned long nr_segs, loff_t pos)
{
	struct file *filp = iocb->ki_filp;
	ssize_t retval;
	unsigned long seg;
	size_t count;
	loff_t *ppos = &iocb->ki_pos;

	retval = generic_segment_checks(iov, &nr_segs, &count, VERIFY_WRITE);
	if (retval)
		return retval;

	for (seg = 0; seg < nr_segs; seg++) {
		read_descriptor_t desc;

		desc.written = 0;
		desc.arg.buf = iov[seg].iov_base;
		desc.count = iov[seg].iov_len;
		if (desc.count == 0)
			continue;
		desc.error = 0;
		do_memfs_file_read(filp, ppos, &desc, memfs_file_read_actor);
		retval += desc.written;
		if (desc.error) {
			retval = retval ?: desc.error;
			break;
		}
		if (desc.count > 0)
			break;
	}
	return retval;
}

static ssize_t memfs_file_read(struct file *file, char __user *buf,
			       size_t count, loff_t *ppos)
{
	RETURN(do_sync_read(file, buf, count, ppos));
}

static ssize_t memfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
				    unsigned long nr_segs, loff_t pos)
{
	RETURN(generic_file_aio_write(iocb, iov, nr_segs, pos));
}

static ssize_t memfs_file_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	RETURN(do_sync_write(file, buf, count, ppos));
}
#endif /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */

static void memfs_put_super(struct super_block *sb)
{
	struct memfs_sb_info *sbinfo = MEMFS_SB(sb);

	OBD_FREE_PTR(sbinfo);
	sb->s_fs_info = NULL;
}

#ifdef HAVE_FS_CONTEXT_H
static int memfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct memfs_options *ctx = fc->fs_private;
	struct memfs_sb_info *sbinfo;
	struct inode *inode;
	int rc;

	ENTRY;

	OBD_ALLOC_PTR(sbinfo);
	if (!sbinfo)
		return -ENOMEM;

	sb->s_fs_info = sbinfo;
	sb->s_flags |= SB_NOUSER | SB_NOSEC;

	sbinfo->msi_uid = ctx->meo_uid;
	sbinfo->msi_gid = ctx->meo_gid;
	sbinfo->msi_mode = ctx->meo_mode;
	sbinfo->msi_max_blocks = ctx->meo_blocks;
	sbinfo->msi_free_inodes = sbinfo->msi_max_inodes = ctx->meo_inodes;
	/* Swap space for the larger capacity is not supported. */
	sbinfo->msi_noswap = true;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = WBCFS_MAGIC;
	sb->s_op = &memfs_ops;
	sb->s_d_op = &simple_dentry_operations;
	sb->s_time_gran = 1;
	uuid_gen(&sb->s_uuid);

	inode = memfs_create_inode(sb, NULL, S_IFDIR | sbinfo->msi_mode,
				   NULL, 0, true);
	if (IS_ERR(inode))
		GOTO(out_fail, rc = PTR_ERR(inode));

	inode->i_uid = sbinfo->msi_uid;
	inode->i_gid = sbinfo->msi_gid;
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		GOTO(out_fail, rc = -ENOMEM);

	RETURN(0);
out_fail:
	memfs_put_super(sb);
	RETURN(rc);
}

static int memfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, memfs_fill_super);
}

static void memfs_free_fc(struct fs_context *fc)
{
	struct memfs_options *ctx = fc->fs_private;

	if (ctx)
		OBD_FREE_PTR(ctx);
}

static const struct fs_context_operations memfs_context_ops = {
	.free		= memfs_free_fc,
	.get_tree	= memfs_get_tree,
};

static int memfs_init_fs_context(struct fs_context *fc)
{
	struct memfs_options *ctx;

	OBD_ALLOC_PTR(ctx);
	if (!ctx)
		return -ENOMEM;

	ctx->meo_mode = 0777 | S_ISVTX;
	ctx->meo_uid = current_fsuid();
	ctx->meo_gid = current_fsgid();

	fc->fs_private = ctx;
	fc->ops = &memfs_context_ops;
	return 0;
}

#else /* !HAVE_FS_CONTEXT_H */

static int memfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct memfs_sb_info *sbinfo;
	struct inode *inode;
	int rc;

	/* Round up to L1_CACHE_BYTES to resist false sharing */
	OBD_ALLOC_PTR(sbinfo);
	if (!sbinfo)
		return -ENOMEM;

	sbinfo->msi_mode = S_IRWXUGO | S_ISVTX;
	sbinfo->msi_uid = current_fsuid();
	sbinfo->msi_gid = current_fsgid();
	sb->s_fs_info = sbinfo;

	/*
	 * Per default we only allow half of the physical ram per
	 * tmpfs instance, limiting inodes to one per page of lowmem;
	 * but the internal instance is left unlimited.
	 */
	if (!(sb->s_flags & MS_KERNMOUNT)) {
		sbinfo->msi_max_blocks = memfs_default_max_blocks();
		sbinfo->msi_max_inodes = memfs_default_max_inodes();
	} else {
		sb->s_flags |= MS_NOUSER;
	}

	sb->s_flags |= MS_NOSEC | MS_NOUSER;
	sbinfo->msi_free_inodes = sbinfo->msi_max_inodes;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = WBCFS_MAGIC;
	sb->s_op = &memfs_ops;
	sb->s_d_op = &simple_dentry_operations;
	sb->s_time_gran = 1;

	inode = memfs_create_inode(sb, NULL, S_IFDIR | sbinfo->msi_mode, NULL,
				   0, true);
	if (IS_ERR(inode))
		GOTO(out_fail, rc = PTR_ERR(inode));

	inode->i_uid = sbinfo->msi_uid;
	inode->i_gid = sbinfo->msi_gid;
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		GOTO(out_fail, rc = -ENOMEM);
	return 0;
out_fail:
	memfs_put_super(sb);
	return rc;
}

static struct dentry *memfs_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, memfs_fill_super);
}
#endif /* HAVE_FS_CONTEXT_H */

static struct kmem_cache *memfs_inode_cachep;

static struct inode *memfs_alloc_inode(struct super_block *sb)
{
	struct memfs_inode_info *mei;

	mei = kmem_cache_alloc(memfs_inode_cachep, GFP_KERNEL);
	if (!mei)
		return NULL;

	return &mei->mei_vfs_inode;
}

static void memfs_destroy_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	ENTRY;
	/* TOOD: free symlink name. */
	kmem_cache_free(memfs_inode_cachep, MEMFS_I(inode));
	EXIT;
}

static void memfs_destroy_inode(struct inode *inode)
{
	struct memfs_inode_info *mei = MEMFS_I(inode);

	if (mei->mei_index_type == INDEX_TYPE_HASH)
		hash_index_fini(&mei->mei_hash_index);

	call_rcu(&inode->i_rcu, memfs_destroy_callback);
}

static void memfs_init_inode(void *foo)
{
	struct memfs_inode_info *mei = (struct memfs_inode_info *)foo;

	inode_init_once(&mei->mei_vfs_inode);
}

static void memfs_init_inodecache(void)
{
	memfs_inode_cachep = kmem_cache_create("memfs_inode_cache",
					       sizeof(struct memfs_inode_info),
					       0, SLAB_PANIC | SLAB_ACCOUNT,
					       memfs_init_inode);
}

static void memfs_destroy_inodecache(void)
{
	kmem_cache_destroy(memfs_inode_cachep);
}

static inline bool memfs_mapping(struct address_space *mapping)
{
	return mapping->a_ops == &memfs_aops;
}

static void memfs_evict_inode(struct inode *inode)
{
	struct memfs_inode_info *mei = MEMFS_I(inode);

	if (memfs_mapping(inode->i_mapping)) {
		inode->i_size = 0;
		mapping_set_exiting(inode->i_mapping);
		truncate_inode_pages_range(inode->i_mapping, 0, (loff_t)-1);
	}

	mem_xattrs_fini(&mei->mei_xattrs);
	memfs_free_inode(inode->i_sb);
	clear_inode(inode);
}

static int memfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct memfs_sb_info *sbinfo = MEMFS_SB(dentry->d_sb);

	buf->f_type = WBCFS_MAGIC;
	buf->f_bsize = PAGE_SIZE;
	buf->f_namelen = NAME_MAX;
	if (sbinfo->msi_max_blocks) {
		buf->f_blocks = sbinfo->msi_max_blocks;
		buf->f_bavail =
		buf->f_bfree  = sbinfo->msi_max_blocks -
				percpu_counter_sum(&sbinfo->msi_used_blocks);
	}
	if (sbinfo->msi_max_inodes) {
		buf->f_files = sbinfo->msi_max_inodes;
		buf->f_ffree = sbinfo->msi_free_inodes;
	}
	/* else leave those fields 0 like simple_statfs */

	return 0;
}

static const struct super_operations memfs_ops = {
	.alloc_inode	= memfs_alloc_inode,
	.destroy_inode	= memfs_destroy_inode,
	.statfs		= memfs_statfs,
	.evict_inode	= memfs_evict_inode,
	.drop_inode	= generic_delete_inode,
	.put_super	= memfs_put_super,
};

/*
 * TODO: Using the new kernel data structure Maple Tree:
 * @simple_offset_dir_operations to manage and access the dentries
 * within a directory. It is much efficient than linear list.
 */
static const struct file_operations memfs_dir_operations = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.llseek		= dcache_dir_lseek,
	.read		= generic_read_dir,
	.iterate_shared	= memfs_dcache_readdir,
	.fsync		= noop_fsync,
};

static const struct inode_operations memfs_dir_inode_operations = {
	.mknod		= memfs_mknod,
	.lookup		= simple_lookup,
	.create		= memfs_create_nd,
	.unlink		= memfs_unlink,
	.mkdir		= memfs_mkdir,
	.rmdir		= memfs_rmdir,
	.link		= memfs_link,
	.setattr	= simple_setattr,
	.getattr	= simple_getattr,
};

static const struct file_operations memfs_file_operations = {
#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
# ifdef HAVE_SYNC_READ_WRITE
	.read		= new_sync_read,
	.write		= new_sync_write,
# endif
	.read_iter	= memfs_file_read_iter,
	.write_iter	= memfs_file_write_iter,
#else /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.read		= memfs_file_read,
	.aio_read	= memfs_file_aio_read,
	.write		= memfs_file_write,
	.aio_write	= memfs_file_aio_write,
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.mmap		= generic_file_mmap,
	.llseek		= generic_file_llseek,
	.splice_read	= memfs_file_splice_read,
	.fsync		= noop_fsync,
};

static const struct address_space_operations memfs_aops = {
#ifdef HAVE_DIRTY_FOLIO
	.dirty_folio	= noop_dirty_folio,
#else
	/*
	 * TODO: reimplemet ->set_page_dirty() interface.
	 * - The call __set_page_dirty_nobuffers will mark the inode dirty and
	 *   put the inode into the writeback control list. Instead, it would
	 *   better to call mark_inode_dirty() only one time when close the file
	 *   once the file data was modified.
	 * - Here it can be optimized to use light weight function:
	 *   __set_page_dirty_no_writeback(); The writeback related data
	 *   structure can be delayed to initilize during data assimliation.
	 */
	.set_page_dirty	= __set_page_dirty_nobuffers,
#endif
	.write_begin	= simple_write_begin,
	.write_end	= memfs_write_end,
};

static struct file_system_type memfs_fstype = {
	.owner			= THIS_MODULE,
	.name			= "wbcfs",
#ifdef HAVE_FS_CONTEXT_H
	.init_fs_context	= memfs_init_fs_context,
#else
	.mount			= memfs_mount,
#endif
	.kill_sb		= kill_litter_super,
	.fs_flags		= FS_USERNS_MOUNT,
};

int memfs_init(void)
{
	int rc;

	memfs_init_inodecache();
	rc = register_filesystem(&memfs_fstype);
	if (rc)
		memfs_destroy_inodecache();

	return rc;
}

void memfs_fini(void)
{
	unregister_filesystem(&memfs_fstype);
	memfs_destroy_inodecache();
}
