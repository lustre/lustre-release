/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _LUSTRE_COMPAT_H
#define _LUSTRE_COMPAT_H

#include <linux/fs_struct.h>
#include <linux/namei.h>

#include <lustre_patchless_compat.h>

#ifdef HAVE_FS_STRUCT_RWLOCK
# define LOCK_FS_STRUCT(fs)	write_lock(&(fs)->lock)
# define UNLOCK_FS_STRUCT(fs)	write_unlock(&(fs)->lock)
#else
# define LOCK_FS_STRUCT(fs)	spin_lock(&(fs)->lock)
# define UNLOCK_FS_STRUCT(fs)	spin_unlock(&(fs)->lock)
#endif

static inline void ll_set_fs_pwd(struct fs_struct *fs, struct vfsmount *mnt,
                                 struct dentry *dentry)
{
        struct path path;
        struct path old_pwd;

        path.mnt = mnt;
        path.dentry = dentry;
        LOCK_FS_STRUCT(fs);
        old_pwd = fs->pwd;
        path_get(&path);
        fs->pwd = path;
        UNLOCK_FS_STRUCT(fs);

        if (old_pwd.dentry)
                path_put(&old_pwd);
}

/*
 * set ATTR_BLOCKS to a high value to avoid any risk of collision with other
 * ATTR_* attributes (see bug 13828)
 */
#define ATTR_BLOCKS    (1 << 27)

#define current_ngroups current_cred()->group_info->ngroups
#define current_groups current_cred()->group_info->small_block

/*
 * OBD need working random driver, thus all our
 * initialization routines must be called after device
 * driver initialization
 */
#ifndef MODULE
#undef module_init
#define module_init(a)     late_initcall(a)
#endif

#ifndef MODULE_ALIAS_FS
#define MODULE_ALIAS_FS(name)
#endif

#define LTIME_S(time)                   (time.tv_sec)

#ifdef HAVE_GENERIC_PERMISSION_2ARGS
# define ll_generic_permission(inode, mask, flags, check_acl) \
	 generic_permission(inode, mask)
#elif defined HAVE_GENERIC_PERMISSION_4ARGS
# define ll_generic_permission(inode, mask, flags, check_acl) \
	 generic_permission(inode, mask, flags, check_acl)
#else
# define ll_generic_permission(inode, mask, flags, check_acl) \
	 generic_permission(inode, mask, check_acl)
#endif

#ifdef HAVE_4ARGS_VFS_SYMLINK
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                vfs_symlink(dir, dentry, path, mode)
#else
#define ll_vfs_symlink(dir, dentry, mnt, path, mode) \
                       vfs_symlink(dir, dentry, path)
#endif

#if !defined(HAVE_FILE_LLSEEK_SIZE) || defined(HAVE_FILE_LLSEEK_SIZE_5ARGS)
#define ll_generic_file_llseek_size(file, offset, origin, maxbytes, eof) \
		generic_file_llseek_size(file, offset, origin, maxbytes, eof);
#else
#define ll_generic_file_llseek_size(file, offset, origin, maxbytes, eof) \
		generic_file_llseek_size(file, offset, origin, maxbytes);
#endif

#ifdef HAVE_INODE_DIO_WAIT
/* inode_dio_wait(i) use as-is for write lock */
# define inode_dio_write_done(i)	do {} while (0) /* for write unlock */
# define inode_dio_read(i)		atomic_inc(&(i)->i_dio_count)
/* inode_dio_done(i) use as-is for read unlock */
#else
# define inode_dio_wait(i)		down_write(&(i)->i_alloc_sem)
# define inode_dio_write_done(i)	up_write(&(i)->i_alloc_sem)
# define inode_dio_read(i)		down_read(&(i)->i_alloc_sem)
# define inode_dio_done(i)		up_read(&(i)->i_alloc_sem)
#endif

#ifndef FS_HAS_FIEMAP
#define FS_HAS_FIEMAP			(0)
#endif

/* add a lustre compatible layer for crypto API */
#include <linux/crypto.h>
static inline int ll_crypto_hmac(struct crypto_hash *tfm,
                                 u8 *key, unsigned int *keylen,
                                 struct scatterlist *sg,
                                 unsigned int size, u8 *result)
{
        struct hash_desc desc;
        int              rv;
        desc.tfm   = tfm;
        desc.flags = 0;
        rv = crypto_hash_setkey(desc.tfm, key, *keylen);
        if (rv) {
                CERROR("failed to hash setkey: %d\n", rv);
                return rv;
        }
        return crypto_hash_digest(&desc, sg, size, result);
}

static inline
unsigned int ll_crypto_tfm_alg_min_keysize(struct crypto_blkcipher *tfm)
{
        return crypto_blkcipher_tfm(tfm)->__crt_alg->cra_blkcipher.min_keysize;
}

#ifndef HAVE_SIMPLE_SETATTR
#define simple_setattr(dentry, ops) inode_setattr((dentry)->d_inode, ops)
#endif

#ifndef SLAB_DESTROY_BY_RCU
#define SLAB_DESTROY_BY_RCU 0
#endif

#ifndef HAVE_DQUOT_SUSPEND
# define ll_vfs_dq_init             vfs_dq_init
# define ll_vfs_dq_drop             vfs_dq_drop
# define ll_vfs_dq_transfer         vfs_dq_transfer
# define ll_vfs_dq_off(sb, remount) vfs_dq_off(sb, remount)
#else
# define ll_vfs_dq_init             dquot_initialize
# define ll_vfs_dq_drop             dquot_drop
# define ll_vfs_dq_transfer         dquot_transfer
# define ll_vfs_dq_off(sb, remount) dquot_suspend(sb, -1)
#endif

#ifndef HAVE_BLKDEV_GET_BY_DEV
# define blkdev_get_by_dev(dev, mode, holder) open_by_devnum(dev, mode)
#endif

#ifdef HAVE_BVEC_ITER
#define bio_idx(bio)			(bio->bi_iter.bi_idx)
#define bio_set_sector(bio, sector)	(bio->bi_iter.bi_sector = sector)
#else
#define bio_idx(bio)			(bio->bi_idx)
#define bio_set_sector(bio, sector)	(bio->bi_sector = sector)
#define bio_sectors(bio)		((bio)->bi_size >> 9)
#ifndef HAVE_BIO_END_SECTOR
#define bio_end_sector(bio)		(bio->bi_sector + bio_sectors(bio))
#endif
#define bvec_iter_page(bvec, iter)	(*bvec->bv_page)
#endif

#ifndef HAVE_BLK_QUEUE_MAX_SEGMENTS
#define blk_queue_max_segments(rq, seg)                      \
        do { blk_queue_max_phys_segments(rq, seg);           \
             blk_queue_max_hw_segments(rq, seg); } while (0)
#else
#define queue_max_phys_segments(rq)       queue_max_segments(rq)
#define queue_max_hw_segments(rq)         queue_max_segments(rq)
#endif

#ifdef HAVE_KMAP_ATOMIC_HAS_1ARG
#define ll_kmap_atomic(a, b)	kmap_atomic(a)
#define ll_kunmap_atomic(a, b)	kunmap_atomic(a)
#else
#define ll_kmap_atomic(a, b)	kmap_atomic(a, b)
#define ll_kunmap_atomic(a, b)	kunmap_atomic(a, b)
#endif

#ifndef HAVE_CLEAR_INODE
#define clear_inode(i)		end_writeback(i)
#endif

#ifdef HAVE_DENTRY_D_ALIAS_HLIST
#define ll_d_hlist_node hlist_node
#define ll_d_hlist_empty(list) hlist_empty(list)
#define ll_d_hlist_entry(ptr, type, name) hlist_entry(ptr.first, type, name)
#define ll_d_hlist_for_each(tmp, i_dentry) hlist_for_each(tmp, i_dentry)
#ifdef HAVE_HLIST_FOR_EACH_3ARG
#define ll_d_hlist_for_each_entry(dentry, p, i_dentry, alias) \
	p = NULL; hlist_for_each_entry(dentry, i_dentry, alias)
#else
#define ll_d_hlist_for_each_entry(dentry, p, i_dentry, alias) \
        hlist_for_each_entry(dentry, p, i_dentry, alias)
#endif
#define DECLARE_LL_D_HLIST_NODE_PTR(name) struct ll_d_hlist_node *name
#else
#define ll_d_hlist_node list_head
#define ll_d_hlist_empty(list) list_empty(list)
#define ll_d_hlist_entry(ptr, type, name) list_entry(ptr.next, type, name)
#define ll_d_hlist_for_each(tmp, i_dentry) list_for_each(tmp, i_dentry)
#define ll_d_hlist_for_each_entry(dentry, p, i_dentry, alias) \
	list_for_each_entry(dentry, i_dentry, alias)
#define DECLARE_LL_D_HLIST_NODE_PTR(name) /* nothing */
#endif

#ifndef QUOTA_OK
# define QUOTA_OK 0
#endif
#ifndef NO_QUOTA
# define NO_QUOTA (-EDQUOT)
#endif

#ifndef SEEK_DATA
#define SEEK_DATA      3       /* seek to the next data */
#endif
#ifndef SEEK_HOLE
#define SEEK_HOLE      4       /* seek to the next hole */
#endif

#ifndef FMODE_UNSIGNED_OFFSET
#define FMODE_UNSIGNED_OFFSET	((__force fmode_t)0x2000)
#endif

#if !defined(_ASM_GENERIC_BITOPS_EXT2_NON_ATOMIC_H_) && !defined(ext2_set_bit)
# define ext2_set_bit             __test_and_set_bit_le
# define ext2_clear_bit           __test_and_clear_bit_le
# define ext2_test_bit            test_bit_le
# define ext2_find_first_zero_bit find_first_zero_bit_le
# define ext2_find_next_zero_bit  find_next_zero_bit_le
#endif

#ifdef ATTR_TIMES_SET
# define TIMES_SET_FLAGS (ATTR_MTIME_SET | ATTR_ATIME_SET | ATTR_TIMES_SET)
#else
# define TIMES_SET_FLAGS (ATTR_MTIME_SET | ATTR_ATIME_SET)
#endif

#ifndef HAVE_LM_XXX_LOCK_MANAGER_OPS
# define lm_compare_owner	fl_compare_owner
#endif

/*
 * After 3.1, kernel's nameidata.intent.open.flags is different
 * with lustre's lookup_intent.it_flags, as lustre's it_flags'
 * lower bits equal to FMODE_xxx while kernel doesn't transliterate
 * lower bits of nameidata.intent.open.flags to FMODE_xxx.
 * */
#include <linux/version.h>
static inline int ll_namei_to_lookup_intent_flag(int flag)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	flag = (flag & ~O_ACCMODE) | OPEN_FMODE(flag);
#endif
	return flag;
}

#ifdef HAVE_VOID_MAKE_REQUEST_FN
# define ll_mrf_ret void
# define LL_MRF_RETURN(rc)
#else
# define ll_mrf_ret int
# define LL_MRF_RETURN(rc) RETURN(rc)
#endif

#include <linux/fs.h>
#ifndef HAVE_PROTECT_I_NLINK
static inline void set_nlink(struct inode *inode, unsigned int nlink)
{
	inode->i_nlink = nlink;
}
#endif

#ifdef HAVE_INODEOPS_USE_UMODE_T
# define ll_umode_t	umode_t
#else
# define ll_umode_t	int
#endif

#include <linux/dcache.h>
#ifndef HAVE_D_MAKE_ROOT
static inline struct dentry *d_make_root(struct inode *root)
{
	struct dentry *res = d_alloc_root(root);

	if (res == NULL && root)
		iput(root);

	return res;
}
#endif

#ifdef HAVE_DIRTY_INODE_HAS_FLAG
# define ll_dirty_inode(inode, flag)	(inode)->i_sb->s_op->dirty_inode((inode), flag)
#else
# define ll_dirty_inode(inode, flag)	(inode)->i_sb->s_op->dirty_inode((inode))
#endif

#ifdef HAVE_FILE_F_INODE
# define set_file_inode(file, inode)	(file)->f_inode = inode
#else
# define set_file_inode(file, inode)
#endif

#ifdef HAVE_OLDSIZE_TRUNCATE_PAGECACHE
#define ll_truncate_pagecache(inode, size) truncate_pagecache(inode, 0, size)
#else
#define ll_truncate_pagecache(inode, size) truncate_pagecache(inode, size)
#endif

#ifdef HAVE_VFS_RENAME_5ARGS
#define ll_vfs_rename(a, b, c, d) vfs_rename(a, b, c, d, NULL)
#elif defined HAVE_VFS_RENAME_6ARGS
#define ll_vfs_rename(a, b, c, d) vfs_rename(a, b, c, d, NULL, 0)
#else
#define ll_vfs_rename(a, b, c, d) vfs_rename(a, b, c, d)
#endif

#ifdef HAVE_VFS_UNLINK_3ARGS
#define ll_vfs_unlink(a, b) vfs_unlink(a, b, NULL)
#else
#define ll_vfs_unlink(a, b) vfs_unlink(a, b)
#endif

#ifndef HAVE_RADIX_EXCEPTION_ENTRY
static inline int radix_tree_exceptional_entry(void *arg)
{
	return 0;
}
#endif

#ifndef HAVE_TRUNCATE_INODE_PAGES_FINAL
static inline void truncate_inode_pages_final(struct address_space *map)
{
	truncate_inode_pages(map, 0);
		/* Workaround for LU-118 */
	if (map->nrpages) {
		spin_lock_irq(&map->tree_lock);
		spin_unlock_irq(&map->tree_lock);
	}	/* Workaround end */
}
#endif

#ifndef SIZE_MAX
#define SIZE_MAX	(~(size_t)0)
#endif

#endif /* _LUSTRE_COMPAT_H */
