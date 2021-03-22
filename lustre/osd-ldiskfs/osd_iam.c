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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * iam.c
 * Top-level entry points into iam module
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

/*
 * iam: big theory statement.
 *
 * iam (Index Access Module) is a module providing abstraction of persistent
 * transactional container on top of generalized ldiskfs htree.
 *
 * iam supports:
 *
 *     - key, pointer, and record size specifiable per container.
 *
 *     - trees taller than 2 index levels.
 *
 *     - read/write to existing ldiskfs htree directories as iam containers.
 *
 * iam container is a tree, consisting of leaf nodes containing keys and
 * records stored in this container, and index nodes, containing keys and
 * pointers to leaf or index nodes.
 *
 * iam does not work with keys directly, instead it calls user-supplied key
 * comparison function (->dpo_keycmp()).
 *
 * Pointers are (currently) interpreted as logical offsets (measured in
 * blocksful) within underlying flat file on top of which iam tree lives.
 *
 * On-disk format:
 *
 * iam mostly tries to reuse existing htree formats.
 *
 * Format of index node:
 *
 * +-----+-------+-------+-------+------+-------+------------+
 * |     | count |       |       |      |       |            |
 * | gap |   /   | entry | entry | .... | entry | free space |
 * |     | limit |       |       |      |       |            |
 * +-----+-------+-------+-------+------+-------+------------+
 *
 *       gap           this part of node is never accessed by iam code. It
 *                     exists for binary compatibility with ldiskfs htree (that,
 *                     in turn, stores fake struct ext2_dirent for ext2
 *                     compatibility), and to keep some unspecified per-node
 *                     data. Gap can be different for root and non-root index
 *                     nodes. Gap size can be specified for each container
 *                     (gap of 0 is allowed).
 *
 *       count/limit   current number of entries in this node, and the maximal
 *                     number of entries that can fit into node. count/limit
 *                     has the same size as entry, and is itself counted in
 *                     count.
 *
 *       entry         index entry: consists of a key immediately followed by
 *                     a pointer to a child node. Size of a key and size of a
 *                     pointer depends on container. Entry has neither
 *                     alignment nor padding.
 *
 *       free space    portion of node new entries are added to
 *
 * Entries in index node are sorted by their key value.
 *
 * Format of a leaf node is not specified. Generic iam code accesses leaf
 * nodes through ->id_leaf methods in struct iam_descr.
 *
 * The IAM root block is a special node, which contains the IAM descriptor.
 * It is on disk format:
 *
 * +---------+-------+--------+---------+-------+------+-------+------------+
 * |IAM desc | count |  idle  |         |       |      |       |            |
 * |(fix/var)|   /   | blocks | padding | entry | .... | entry | free space |
 * |         | limit |        |         |       |      |       |            |
 * +---------+-------+--------+---------+-------+------+-------+------------+
 *
 * The padding length is calculated with the parameters in the IAM descriptor.
 *
 * The field "idle_blocks" is used to record empty leaf nodes, which have not
 * been released but all contained entries in them have been removed. Usually,
 * the idle blocks in the IAM should be reused when need to allocate new leaf
 * nodes for new entries, it depends on the IAM hash functions to map the new
 * entries to these idle blocks. Unfortunately, it is not easy to design some
 * hash functions for such clever mapping, especially considering the insert/
 * lookup performance.
 *
 * So the IAM recycles the empty leaf nodes, and put them into a per-file based
 * idle blocks pool. If need some new leaf node, it will try to take idle block
 * from such pool with priority, in spite of how the IAM hash functions to map
 * the entry.
 *
 * The idle blocks pool is organized as a series of tables, and each table
 * can be described as following (on-disk format):
 *
 * +---------+---------+---------+---------+------+---------+-------+
 * |  magic  |  count  |  next   |  logic  |      |  logic  | free  |
 * |(16 bits)|(16 bits)|  table  |  blk #  | .... |  blk #  | space |
 * |         |         |(32 bits)|(32 bits)|      |(32 bits)|       |
 * +---------+---------+---------+---------+------+---------+-------+
 *
 * The logic blk# for the first table is stored in the root node "idle_blocks".
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/time.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>

#include <ldiskfs/ldiskfs.h>
#include <ldiskfs/xattr.h>
#undef ENTRY

#include "osd_internal.h"

#include <ldiskfs/acl.h>

static struct buffer_head *
iam_load_idle_blocks(struct iam_container *c, iam_ptr_t blk)
{
	struct inode *inode = c->ic_object;
	struct iam_idle_head *head;
	struct buffer_head *bh;

	LASSERT(mutex_is_locked(&c->ic_idle_mutex));

	if (blk == 0)
		return NULL;

	bh = __ldiskfs_bread(NULL, inode, blk, 0);
	if (IS_ERR_OR_NULL(bh)) {
		CERROR("%s: cannot load idle blocks, blk = %u: rc = %ld\n",
		       osd_ino2name(inode), blk, bh ? PTR_ERR(bh) : -EIO);
		c->ic_idle_failed = 1;
		if (bh == NULL)
			bh = ERR_PTR(-EIO);
		return bh;
	}

	head = (struct iam_idle_head *)(bh->b_data);
	if (le16_to_cpu(head->iih_magic) != IAM_IDLE_HEADER_MAGIC) {
		int rc = -EBADF;

		CERROR("%s: invalid idle block head, blk = %u, magic = %x: rc = %d\n",
		       osd_ino2name(inode), blk, le16_to_cpu(head->iih_magic),
		       rc);
		brelse(bh);
		c->ic_idle_failed = 1;
		return ERR_PTR(rc);
	}

	return bh;
}

/*
 * Determine format of given container. This is done by scanning list of
 * registered formats and calling ->if_guess() method of each in turn.
 */
static int iam_format_guess(struct iam_container *c)
{
	int result;

	result = iam_lvar_guess(c);
	if (result)
		result = iam_lfix_guess(c);

	if (result == 0) {
		struct buffer_head *bh;
		__u32 *idle_blocks;

		LASSERT(c->ic_root_bh != NULL);

		idle_blocks = (__u32 *)(c->ic_root_bh->b_data +
					c->ic_descr->id_root_gap +
					sizeof(struct dx_countlimit));
		mutex_lock(&c->ic_idle_mutex);
		bh = iam_load_idle_blocks(c, le32_to_cpu(*idle_blocks));
		if (bh != NULL && IS_ERR(bh))
			result = PTR_ERR(bh);
		else
			c->ic_idle_bh = bh;
		mutex_unlock(&c->ic_idle_mutex);
	}

	return result;
}

/*
 * Initialize container @c.
 */
int iam_container_init(struct iam_container *c,
		       struct iam_descr *descr, struct inode *inode)
{
	memset(c, 0, sizeof *c);
	c->ic_descr = descr;
	c->ic_object = inode;
	init_rwsem(&c->ic_sem);
	dynlock_init(&c->ic_tree_lock);
	mutex_init(&c->ic_idle_mutex);
	return 0;
}

/*
 * Determine container format.
 */
int iam_container_setup(struct iam_container *c)
{
	return iam_format_guess(c);
}

/*
 * Finalize container @c, release all resources.
 */
void iam_container_fini(struct iam_container *c)
{
	brelse(c->ic_idle_bh);
	c->ic_idle_bh = NULL;
	brelse(c->ic_root_bh);
	c->ic_root_bh = NULL;
}

void iam_path_init(struct iam_path *path, struct iam_container *c,
                   struct iam_path_descr *pd)
{
	memset(path, 0, sizeof *path);
	path->ip_container = c;
	path->ip_frame = path->ip_frames;
	path->ip_data = pd;
	path->ip_leaf.il_path = path;
}

static void iam_leaf_fini(struct iam_leaf *leaf);

void iam_path_release(struct iam_path *path)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(path->ip_frames); i++) {
		if (path->ip_frames[i].bh != NULL) {
			path->ip_frames[i].at_shifted = 0;
			brelse(path->ip_frames[i].bh);
			path->ip_frames[i].bh = NULL;
		}
	}
}

void iam_path_fini(struct iam_path *path)
{
	iam_leaf_fini(&path->ip_leaf);
	iam_path_release(path);
}


void iam_path_compat_init(struct iam_path_compat *path, struct inode *inode)
{
	int i;

	path->ipc_hinfo = &path->ipc_hinfo_area;
	for (i = 0; i < ARRAY_SIZE(path->ipc_scratch); ++i)
		path->ipc_descr.ipd_key_scratch[i] =
			(struct iam_ikey *)&path->ipc_scratch[i];

	iam_path_init(&path->ipc_path, &path->ipc_container, &path->ipc_descr);
}

void iam_path_compat_fini(struct iam_path_compat *path)
{
	iam_path_fini(&path->ipc_path);
}

/*
 * Helper function initializing iam_path_descr and its key scratch area.
 */
struct iam_path_descr *iam_ipd_alloc(void *area, int keysize)
{
	struct iam_path_descr *ipd;
	void *karea;
	int i;

	ipd = area;
	karea = ipd + 1;
	for (i = 0; i < ARRAY_SIZE(ipd->ipd_key_scratch); ++i, karea += keysize)
		ipd->ipd_key_scratch[i] = karea;
	return ipd;
}

void iam_ipd_free(struct iam_path_descr *ipd)
{
}

int iam_node_read(struct iam_container *c, iam_ptr_t ptr,
                  handle_t *h, struct buffer_head **bh)
{
	/*
	 * NB: it can be called by iam_lfix_guess() which is still at
	 * very early stage, c->ic_root_bh and c->ic_descr->id_ops
	 * haven't been intialized yet.
	 * Also, we don't have this for IAM dir.
	 */
	if (c->ic_root_bh != NULL &&
	    c->ic_descr->id_ops->id_root_ptr(c) == ptr) {
		get_bh(c->ic_root_bh);
		*bh = c->ic_root_bh;
		return 0;
	}

	*bh = __ldiskfs_bread(h, c->ic_object, (int)ptr, 0);
	if (IS_ERR(*bh))
		return PTR_ERR(*bh);

	if (*bh == NULL)
		return -EIO;

	return 0;
}

/*
 * Return pointer to current leaf record. Pointer is valid while corresponding
 * leaf node is locked and pinned.
 */
static struct iam_rec *iam_leaf_rec(const struct iam_leaf *leaf)
{
	return iam_leaf_ops(leaf)->rec(leaf);
}

/*
 * Return pointer to the current leaf key. This function returns pointer to
 * the key stored in node.
 *
 * Caller should assume that returned pointer is only valid while leaf node is
 * pinned and locked.
 */
static struct iam_key *iam_leaf_key(const struct iam_leaf *leaf)
{
	return iam_leaf_ops(leaf)->key(leaf);
}

static int iam_leaf_key_size(const struct iam_leaf *leaf)
{
	return iam_leaf_ops(leaf)->key_size(leaf);
}

static struct iam_ikey *iam_leaf_ikey(const struct iam_leaf *leaf,
                                      struct iam_ikey *key)
{
	return iam_leaf_ops(leaf)->ikey(leaf, key);
}

static int iam_leaf_keycmp(const struct iam_leaf *leaf,
                           const struct iam_key *key)
{
	return iam_leaf_ops(leaf)->key_cmp(leaf, key);
}

static int iam_leaf_keyeq(const struct iam_leaf *leaf,
                          const struct iam_key *key)
{
	return iam_leaf_ops(leaf)->key_eq(leaf, key);
}

#if LDISKFS_INVARIANT_ON
static int iam_path_check(struct iam_path *p)
{
	int i;
	int result;
	struct iam_frame *f;
	struct iam_descr *param;

	result = 1;
	param = iam_path_descr(p);
	for (i = 0; result && i < ARRAY_SIZE(p->ip_frames); ++i) {
		f = &p->ip_frames[i];
		if (f->bh != NULL) {
			result = dx_node_check(p, f);
			if (result)
				result = !param->id_ops->id_node_check(p, f);
		}
	}
	if (result && p->ip_leaf.il_bh != NULL)
		result = 1;
	if (result == 0)
		ldiskfs_std_error(iam_path_obj(p)->i_sb, result);

	return result;
}
#endif

static int iam_leaf_load(struct iam_path *path)
{
	iam_ptr_t block;
	int err;
	struct iam_container *c;
	struct buffer_head *bh;
	struct iam_leaf *leaf;
	struct iam_descr *descr;

	c     = path->ip_container;
	leaf  = &path->ip_leaf;
	descr = iam_path_descr(path);
	block = path->ip_frame->leaf;
	if (block == 0) {
		/* XXX bug 11027 */
		printk(KERN_EMERG "wrong leaf: %lu %d [%p %p %p]\n",
		       (long unsigned)path->ip_frame->leaf,
		       dx_get_count(dx_node_get_entries(path, path->ip_frame)),
		       path->ip_frames[0].bh, path->ip_frames[1].bh,
		       path->ip_frames[2].bh);
	}
	err = descr->id_ops->id_node_read(c, block, NULL, &bh);
	if (err == 0) {
		leaf->il_bh = bh;
		leaf->il_curidx = block;
		err = iam_leaf_ops(leaf)->init(leaf);
	}
	return err;
}

static void iam_unlock_htree(struct iam_container *ic,
			     struct dynlock_handle *lh)
{
	if (lh != NULL)
		dynlock_unlock(&ic->ic_tree_lock, lh);
}


static void iam_leaf_unlock(struct iam_leaf *leaf)
{
	if (leaf->il_lock != NULL) {
		iam_unlock_htree(iam_leaf_container(leaf),
				 leaf->il_lock);
		do_corr(schedule());
		leaf->il_lock = NULL;
	}
}

static void iam_leaf_fini(struct iam_leaf *leaf)
{
	if (leaf->il_path != NULL) {
		iam_leaf_unlock(leaf);
		iam_leaf_ops(leaf)->fini(leaf);
		if (leaf->il_bh) {
			brelse(leaf->il_bh);
			leaf->il_bh = NULL;
			leaf->il_curidx = 0;
		}
	}
}

static void iam_leaf_start(struct iam_leaf *folio)
{
	iam_leaf_ops(folio)->start(folio);
}

void iam_leaf_next(struct iam_leaf *folio)
{
	iam_leaf_ops(folio)->next(folio);
}

static void iam_leaf_rec_add(struct iam_leaf *leaf, const struct iam_key *key,
                             const struct iam_rec *rec)
{
	iam_leaf_ops(leaf)->rec_add(leaf, key, rec);
}

static void iam_rec_del(struct iam_leaf *leaf, int shift)
{
	iam_leaf_ops(leaf)->rec_del(leaf, shift);
}

int iam_leaf_at_end(const struct iam_leaf *leaf)
{
	return iam_leaf_ops(leaf)->at_end(leaf);
}

static void iam_leaf_split(struct iam_leaf *l, struct buffer_head **bh,
			   iam_ptr_t nr)
{
	iam_leaf_ops(l)->split(l, bh, nr);
}

static inline int iam_leaf_empty(struct iam_leaf *l)
{
	return iam_leaf_ops(l)->leaf_empty(l);
}

int iam_leaf_can_add(const struct iam_leaf *l,
                     const struct iam_key *k, const struct iam_rec *r)
{
	return iam_leaf_ops(l)->can_add(l, k, r);
}

static int iam_txn_dirty(handle_t *handle,
                         struct iam_path *path, struct buffer_head *bh)
{
	int result;

	result = ldiskfs_handle_dirty_metadata(handle, NULL, bh);
	if (result != 0)
		ldiskfs_std_error(iam_path_obj(path)->i_sb, result);
	return result;
}

static int iam_txn_add(handle_t *handle,
                       struct iam_path *path, struct buffer_head *bh)
{
	int result;

	result = ldiskfs_journal_get_write_access(handle, bh);
	if (result != 0)
		ldiskfs_std_error(iam_path_obj(path)->i_sb, result);
	return result;
}

/***********************************************************************/
/* iterator interface                                                  */
/***********************************************************************/

static enum iam_it_state it_state(const struct iam_iterator *it)
{
	return it->ii_state;
}

/*
 * Helper function returning scratch key.
 */
static struct iam_container *iam_it_container(const struct iam_iterator *it)
{
	return it->ii_path.ip_container;
}

static inline int it_keycmp(const struct iam_iterator *it,
                            const struct iam_key *k)
{
	return iam_leaf_keycmp(&it->ii_path.ip_leaf, k);
}

static inline int it_keyeq(const struct iam_iterator *it,
                           const struct iam_key *k)
{
	return iam_leaf_keyeq(&it->ii_path.ip_leaf, k);
}

static int it_ikeycmp(const struct iam_iterator *it, const struct iam_ikey *ik)
{
	return iam_ikeycmp(it->ii_path.ip_container,
			   iam_leaf_ikey(&it->ii_path.ip_leaf,
					iam_path_ikey(&it->ii_path, 0)), ik);
}

static inline int it_at_rec(const struct iam_iterator *it)
{
	return !iam_leaf_at_end(&it->ii_path.ip_leaf);
}

static inline int it_before(const struct iam_iterator *it)
{
	return it_state(it) == IAM_IT_SKEWED && it_at_rec(it);
}

/*
 * Helper wrapper around iam_it_get(): returns 0 (success) only when record
 * with exactly the same key as asked is found.
 */
static int iam_it_get_exact(struct iam_iterator *it, const struct iam_key *k)
{
	int result;

	result = iam_it_get(it, k);
	if (result > 0)
		result = 0;
	else if (result == 0)
		/*
		 * Return -ENOENT if cursor is located above record with a key
		 * different from one specified, or in the empty leaf.
		 *
		 * XXX returning -ENOENT only works if iam_it_get() never
		 * returns -ENOENT as a legitimate error.
		 */
		result = -ENOENT;
	return result;
}

void iam_container_write_lock(struct iam_container *ic)
{
	down_write(&ic->ic_sem);
}

void iam_container_write_unlock(struct iam_container *ic)
{
	up_write(&ic->ic_sem);
}

void iam_container_read_lock(struct iam_container *ic)
{
	down_read(&ic->ic_sem);
}

void iam_container_read_unlock(struct iam_container *ic)
{
	up_read(&ic->ic_sem);
}

/*
 * Initialize iterator to IAM_IT_DETACHED state.
 *
 * postcondition: it_state(it) == IAM_IT_DETACHED
 */
int  iam_it_init(struct iam_iterator *it, struct iam_container *c, __u32 flags,
                 struct iam_path_descr *pd)
{
	memset(it, 0, sizeof *it);
	it->ii_flags  = flags;
	it->ii_state  = IAM_IT_DETACHED;
	iam_path_init(&it->ii_path, c, pd);
	return 0;
}

/*
 * Finalize iterator and release all resources.
 *
 * precondition: it_state(it) == IAM_IT_DETACHED
 */
void iam_it_fini(struct iam_iterator *it)
{
	assert_corr(it_state(it) == IAM_IT_DETACHED);
	iam_path_fini(&it->ii_path);
}

/*
 * this locking primitives are used to protect parts
 * of dir's htree. protection unit is block: leaf or index
 */
static struct dynlock_handle *iam_lock_htree(struct iam_container *ic,
					     unsigned long value,
					     enum dynlock_type lt)
{
	return dynlock_lock(&ic->ic_tree_lock, value, lt, GFP_NOFS);
}

static int iam_index_lock(struct iam_path *path, struct dynlock_handle **lh)
{
	struct iam_frame *f;

	for (f = path->ip_frame; f >= path->ip_frames; --f, ++lh) {
		do_corr(schedule());
		*lh = iam_lock_htree(path->ip_container, f->curidx, DLT_READ);
		if (*lh == NULL)
			return -ENOMEM;
	}
	return 0;
}

/*
 * Fast check for frame consistency.
 */
static int iam_check_fast(struct iam_path *path, struct iam_frame *frame)
{
	struct iam_container *bag;
	struct iam_entry *next;
	struct iam_entry *last;
	struct iam_entry *entries;
	struct iam_entry *at;

	bag = path->ip_container;
	at = frame->at;
	entries = frame->entries;
	last = iam_entry_shift(path, entries, dx_get_count(entries) - 1);

	if (unlikely(at > last))
		return -EAGAIN;

	if (unlikely(dx_get_block(path, at) != frame->leaf))
		return -EAGAIN;

	if (unlikely(iam_ikeycmp(bag, iam_ikey_at(path, at),
		     path->ip_ikey_target) > 0))
		return -EAGAIN;

	next = iam_entry_shift(path, at, +1);
	if (next <= last) {
		if (unlikely(iam_ikeycmp(bag, iam_ikey_at(path, next),
					 path->ip_ikey_target) <= 0))
			return -EAGAIN;
	}
	return 0;
}

int dx_index_is_compat(struct iam_path *path)
{
	return iam_path_descr(path) == NULL;
}

/*
 * dx_find_position
 *
 * search position of specified hash in index
 *
 */

static struct iam_entry *iam_find_position(struct iam_path *path,
					   struct iam_frame *frame)
{
	int count;
	struct iam_entry *p;
	struct iam_entry *q;
	struct iam_entry *m;

	count = dx_get_count(frame->entries);
	assert_corr(count && count <= dx_get_limit(frame->entries));
	p = iam_entry_shift(path, frame->entries,
			    dx_index_is_compat(path) ? 1 : 2);
	q = iam_entry_shift(path, frame->entries, count - 1);
	while (p <= q) {
		m = iam_entry_shift(path, p, iam_entry_diff(path, q, p) / 2);
		if (iam_ikeycmp(path->ip_container, iam_ikey_at(path, m),
				path->ip_ikey_target) > 0)
			q = iam_entry_shift(path, m, -1);
		else
			p = iam_entry_shift(path, m, +1);
	}
	return iam_entry_shift(path, p, -1);
}



static iam_ptr_t iam_find_ptr(struct iam_path *path, struct iam_frame *frame)
{
	return dx_get_block(path, iam_find_position(path, frame));
}

void iam_insert_key(struct iam_path *path, struct iam_frame *frame,
                    const struct iam_ikey *key, iam_ptr_t ptr)
{
	struct iam_entry *entries = frame->entries;
	struct iam_entry *new = iam_entry_shift(path, frame->at, +1);
	int count = dx_get_count(entries);

	/*
	 * Unfortunately we cannot assert this, as this function is sometimes
	 * called by VFS under i_sem and without pdirops lock.
	 */
	assert_corr(1 || iam_frame_is_locked(path, frame));
	assert_corr(count < dx_get_limit(entries));
	assert_corr(frame->at < iam_entry_shift(path, entries, count));
	assert_inv(dx_node_check(path, frame));

	memmove(iam_entry_shift(path, new, 1), new,
		(char *)iam_entry_shift(path, entries, count) - (char *)new);
	dx_set_ikey(path, new, key);
	dx_set_block(path, new, ptr);
	dx_set_count(entries, count + 1);
	assert_inv(dx_node_check(path, frame));
}

void iam_insert_key_lock(struct iam_path *path, struct iam_frame *frame,
                         const struct iam_ikey *key, iam_ptr_t ptr)
{
	iam_lock_bh(frame->bh);
	iam_insert_key(path, frame, key, ptr);
	iam_unlock_bh(frame->bh);
}
/*
 * returns 0 if path was unchanged, -EAGAIN otherwise.
 */
static int iam_check_path(struct iam_path *path, struct iam_frame *frame)
{
	int equal;

	iam_lock_bh(frame->bh);
	equal = iam_check_fast(path, frame) == 0 ||
		frame->leaf == iam_find_ptr(path, frame);
	DX_DEVAL(iam_lock_stats.dls_bh_again += !equal);
	iam_unlock_bh(frame->bh);

	return equal ? 0 : -EAGAIN;
}

static int iam_lookup_try(struct iam_path *path)
{
	u32 ptr;
	int err = 0;
	int i;

	struct iam_descr *param;
	struct iam_frame *frame;
	struct iam_container *c;

	param = iam_path_descr(path);
	c = path->ip_container;

	ptr = param->id_ops->id_root_ptr(c);
	for (frame = path->ip_frames, i = 0; i <= path->ip_indirect;
	     ++frame, ++i) {
		err = param->id_ops->id_node_read(c, (iam_ptr_t)ptr, NULL,
						  &frame->bh);
		do_corr(schedule());

		iam_lock_bh(frame->bh);
		/*
		 * node must be initialized under bh lock because concurrent
		 * creation procedure may change it and iam_lookup_try() will
		 * see obsolete tree height. -bzzz
		 */
		if (err != 0)
			break;

		if (LDISKFS_INVARIANT_ON) {
			err = param->id_ops->id_node_check(path, frame);
			if (err != 0)
				break;
		}

		err = param->id_ops->id_node_load(path, frame);
		if (err != 0)
			break;

		assert_inv(dx_node_check(path, frame));
		/*
		 * splitting may change root index block and move hash we're
		 * looking for into another index block so, we have to check
		 * this situation and repeat from begining if path got changed
		 * -bzzz
		 */
		if (i > 0) {
			err = iam_check_path(path, frame - 1);
			if (err != 0)
				break;
		}

		frame->at = iam_find_position(path, frame);
		frame->curidx = ptr;
		frame->leaf = ptr = dx_get_block(path, frame->at);

		iam_unlock_bh(frame->bh);
		do_corr(schedule());
	}
	if (err != 0)
		iam_unlock_bh(frame->bh);
	path->ip_frame = --frame;
	return err;
}

static int __iam_path_lookup(struct iam_path *path)
{
	int err;
	int i;

	for (i = 0; i < DX_MAX_TREE_HEIGHT; ++ i)
		assert(path->ip_frames[i].bh == NULL);

	do {
		err = iam_lookup_try(path);
		do_corr(schedule());
		if (err != 0)
			iam_path_fini(path);
	} while (err == -EAGAIN);

	return err;
}

/*
 * returns 0 if path was unchanged, -EAGAIN otherwise.
 */
static int iam_check_full_path(struct iam_path *path, int search)
{
	struct iam_frame *bottom;
	struct iam_frame *scan;
	int i;
	int result;

	do_corr(schedule());

	for (bottom = path->ip_frames, i = 0;
	     i < DX_MAX_TREE_HEIGHT && bottom->bh != NULL; ++bottom, ++i) {
		; /* find last filled in frame */
	}

	/*
	 * Lock frames, bottom to top.
	 */
	for (scan = bottom - 1; scan >= path->ip_frames; --scan)
		iam_lock_bh(scan->bh);
	/*
	 * Check them top to bottom.
	 */
	result = 0;
	for (scan = path->ip_frames; scan < bottom; ++scan) {
		struct iam_entry *pos;

		if (search) {
			if (iam_check_fast(path, scan) == 0)
				continue;

			pos = iam_find_position(path, scan);
			if (scan->leaf != dx_get_block(path, pos)) {
				result = -EAGAIN;
				break;
			}
			scan->at = pos;
		} else {
			pos = iam_entry_shift(path, scan->entries,
					      dx_get_count(scan->entries) - 1);
			if (scan->at > pos ||
			    scan->leaf != dx_get_block(path, scan->at)) {
				result = -EAGAIN;
				break;
			}
		}
	}

	/*
	 * Unlock top to bottom.
	 */
	for (scan = path->ip_frames; scan < bottom; ++scan)
                iam_unlock_bh(scan->bh);
	DX_DEVAL(iam_lock_stats.dls_bh_full_again += !!result);
	do_corr(schedule());

	return result;
}


/*
 * Performs path lookup and returns with found leaf (if any) locked by htree
 * lock.
 */
static int iam_lookup_lock(struct iam_path *path,
			   struct dynlock_handle **dl, enum dynlock_type lt)
{
	int result;

	while ((result = __iam_path_lookup(path)) == 0) {
		do_corr(schedule());
		*dl = iam_lock_htree(path->ip_container, path->ip_frame->leaf,
				     lt);
		if (*dl == NULL) {
			iam_path_fini(path);
			result = -ENOMEM;
			break;
		}
		do_corr(schedule());
		/*
		 * while locking leaf we just found may get split so we need
		 * to check this -bzzz
		 */
		if (iam_check_full_path(path, 1) == 0)
			break;
		iam_unlock_htree(path->ip_container, *dl);
		*dl = NULL;
		iam_path_fini(path);
	}
	return result;
}
/*
 * Performs tree top-to-bottom traversal starting from root, and loads leaf
 * node.
 */
static int iam_path_lookup(struct iam_path *path, int index)
{
	struct iam_leaf  *leaf;
	int result;

	leaf = &path->ip_leaf;
	result = iam_lookup_lock(path, &leaf->il_lock, DLT_WRITE);
	assert_inv(iam_path_check(path));
	do_corr(schedule());
	if (result == 0) {
		result = iam_leaf_load(path);
		if (result == 0) {
			do_corr(schedule());
			if (index)
				result = iam_leaf_ops(leaf)->
					ilookup(leaf, path->ip_ikey_target);
			else
				result = iam_leaf_ops(leaf)->
					lookup(leaf, path->ip_key_target);
			do_corr(schedule());
		}
		if (result < 0)
			iam_leaf_unlock(leaf);
	}
	return result;
}

/*
 * Common part of iam_it_{i,}get().
 */
static int __iam_it_get(struct iam_iterator *it, int index)
{
	int result;

	assert_corr(it_state(it) == IAM_IT_DETACHED);

	result = iam_path_lookup(&it->ii_path, index);
	if (result >= 0) {
		int collision;

		collision = result & IAM_LOOKUP_LAST;
		switch (result & ~IAM_LOOKUP_LAST) {
		case IAM_LOOKUP_EXACT:
			result = +1;
			it->ii_state = IAM_IT_ATTACHED;
			break;
		case IAM_LOOKUP_OK:
			result = 0;
			it->ii_state = IAM_IT_ATTACHED;
			break;
		case IAM_LOOKUP_BEFORE:
		case IAM_LOOKUP_EMPTY:
			result = 0;
			it->ii_state = IAM_IT_SKEWED;
			break;
		default:
			assert(0);
		}
		result |= collision;
	}
	/*
	 * See iam_it_get_exact() for explanation.
	 */
	assert_corr(result != -ENOENT);
	return result;
}

/*
 * Correct hash, but not the same key was found, iterate through hash
 * collision chain, looking for correct record.
 */
static int iam_it_collision(struct iam_iterator *it)
{
	int result;

	assert(ergo(it_at_rec(it), !it_keyeq(it, it->ii_path.ip_key_target)));

	while ((result = iam_it_next(it)) == 0) {
		do_corr(schedule());
		if (it_ikeycmp(it, it->ii_path.ip_ikey_target) != 0)
			return -ENOENT;
		if (it_keyeq(it, it->ii_path.ip_key_target))
			return 0;
	}
	return result;
}

/*
 * Attach iterator. After successful completion, @it points to record with
 * least key not larger than @k.
 *
 * Return value: 0: positioned on existing record,
 *             +ve: exact position found,
 *             -ve: error.
 *
 * precondition:  it_state(it) == IAM_IT_DETACHED
 * postcondition: ergo(result == 0 && it_state(it) == IAM_IT_ATTACHED,
 *                     it_keycmp(it, k) <= 0)
 */
int iam_it_get(struct iam_iterator *it, const struct iam_key *k)
{
	int result;

	assert_corr(it_state(it) == IAM_IT_DETACHED);

	it->ii_path.ip_ikey_target = NULL;
	it->ii_path.ip_key_target  = k;

	result = __iam_it_get(it, 0);

	if (result == IAM_LOOKUP_LAST) {
		result = iam_it_collision(it);
		if (result != 0) {
			iam_it_put(it);
			iam_it_fini(it);
			result = __iam_it_get(it, 0);
		} else
			result = +1;
	}
	if (result > 0)
		result &= ~IAM_LOOKUP_LAST;

	assert_corr(ergo(result > 0, it_keycmp(it, k) == 0));
	assert_corr(ergo(result == 0 && it_state(it) == IAM_IT_ATTACHED,
		    it_keycmp(it, k) <= 0));
	return result;
}

/*
 * Attach iterator by index key.
 */
static int iam_it_iget(struct iam_iterator *it, const struct iam_ikey *k)
{
	assert_corr(it_state(it) == IAM_IT_DETACHED);

	it->ii_path.ip_ikey_target = k;
	return __iam_it_get(it, 1) & ~IAM_LOOKUP_LAST;
}

/*
 * Attach iterator, and assure it points to the record (not skewed).
 *
 * Return value: 0: positioned on existing record,
 *             +ve: exact position found,
 *             -ve: error.
 *
 * precondition:  it_state(it) == IAM_IT_DETACHED &&
 *                !(it->ii_flags&IAM_IT_WRITE)
 * postcondition: ergo(result == 0, it_state(it) == IAM_IT_ATTACHED)
 */
int iam_it_get_at(struct iam_iterator *it, const struct iam_key *k)
{
	int result;

	assert_corr(it_state(it) == IAM_IT_DETACHED &&
		    !(it->ii_flags&IAM_IT_WRITE));
	result = iam_it_get(it, k);
	if (result == 0) {
		if (it_state(it) != IAM_IT_ATTACHED) {
			assert_corr(it_state(it) == IAM_IT_SKEWED);
			result = iam_it_next(it);
		}
	}
	assert_corr(ergo(result >= 0, it_state(it) == IAM_IT_ATTACHED));
	return result;
}

/*
 * Duplicates iterator.
 *
 * postcondition: it_state(dst) == it_state(src) &&
 *                iam_it_container(dst) == iam_it_container(src) &&
 *                dst->ii_flags = src->ii_flags &&
 *                ergo(it_state(src) == IAM_IT_ATTACHED,
 *                     iam_it_rec_get(dst) == iam_it_rec_get(src) &&
 *                     iam_it_key_get(dst) == iam_it_key_get(src))
 */
void iam_it_dup(struct iam_iterator *dst, const struct iam_iterator *src)
{
	dst->ii_flags = src->ii_flags;
	dst->ii_state = src->ii_state;
	/* XXX not yet. iam_path_dup(&dst->ii_path, &src->ii_path); */
	/*
	 * XXX: duplicate lock.
	 */
	assert_corr(it_state(dst) == it_state(src));
	assert_corr(iam_it_container(dst) == iam_it_container(src));
	assert_corr(dst->ii_flags = src->ii_flags);
	assert_corr(ergo(it_state(src) == IAM_IT_ATTACHED,
		    iam_it_rec_get(dst) == iam_it_rec_get(src) &&
		    iam_it_key_get(dst) == iam_it_key_get(src)));
}

/*
 * Detach iterator. Does nothing it detached state.
 *
 * postcondition: it_state(it) == IAM_IT_DETACHED
 */
void iam_it_put(struct iam_iterator *it)
{
	if (it->ii_state != IAM_IT_DETACHED) {
		it->ii_state = IAM_IT_DETACHED;
		iam_leaf_fini(&it->ii_path.ip_leaf);
	}
}

static struct iam_ikey *iam_it_ikey_get(const struct iam_iterator *it,
                                        struct iam_ikey *ikey);


/*
 * This function increments the frame pointer to search the next leaf
 * block, and reads in the necessary intervening nodes if the search
 * should be necessary.  Whether or not the search is necessary is
 * controlled by the hash parameter.  If the hash value is even, then
 * the search is only continued if the next block starts with that
 * hash value.  This is used if we are searching for a specific file.
 *
 * If the hash value is HASH_NB_ALWAYS, then always go to the next block.
 *
 * This function returns 1 if the caller should continue to search,
 * or 0 if it should not.  If there is an error reading one of the
 * index blocks, it will a negative error code.
 *
 * If start_hash is non-null, it will be filled in with the starting
 * hash of the next page.
 */
static int iam_htree_advance(struct inode *dir, __u32 hash,
                              struct iam_path *path, __u32 *start_hash,
                              int compat)
{
	struct iam_frame *p;
	struct buffer_head *bh;
	int err, num_frames = 0;
	__u32 bhash;

	p = path->ip_frame;
	/*
	 * Find the next leaf page by incrementing the frame pointer.
	 * If we run out of entries in the interior node, loop around and
	 * increment pointer in the parent node.  When we break out of
	 * this loop, num_frames indicates the number of interior
	 * nodes need to be read.
	 */
	while (1) {
		do_corr(schedule());
		iam_lock_bh(p->bh);
		if (p->at_shifted)
			p->at_shifted = 0;
		else
			p->at = iam_entry_shift(path, p->at, +1);
		if (p->at < iam_entry_shift(path, p->entries,
					    dx_get_count(p->entries))) {
			p->leaf = dx_get_block(path, p->at);
			iam_unlock_bh(p->bh);
			break;
		}
		iam_unlock_bh(p->bh);
		if (p == path->ip_frames)
			return 0;
		num_frames++;
		--p;
	}

	if (compat) {
		/*
		 * Htree hash magic.
		 */

		/*
		 * If the hash is 1, then continue only if the next page has a
		 * continuation hash of any value.  This is used for readdir
		 * handling.  Otherwise, check to see if the hash matches the
		 * desired contiuation hash.  If it doesn't, return since
		 * there's no point to read in the successive index pages.
		 */
		dx_get_ikey(path, p->at, (struct iam_ikey *)&bhash);
		if (start_hash)
			*start_hash = bhash;
		if ((hash & 1) == 0) {
			if ((bhash & ~1) != hash)
				return 0;
		}
	}
	/*
	 * If the hash is HASH_NB_ALWAYS, we always go to the next
	 * block so no check is necessary
	 */
	while (num_frames--) {
		iam_ptr_t idx;

		do_corr(schedule());
		iam_lock_bh(p->bh);
		idx = p->leaf = dx_get_block(path, p->at);
		iam_unlock_bh(p->bh);
		err = iam_path_descr(path)->id_ops->
			id_node_read(path->ip_container, idx, NULL, &bh);
		if (err != 0)
			return err; /* Failure */
		++p;
		brelse(p->bh);
		assert_corr(p->bh != bh);
		p->bh = bh;
		p->entries = dx_node_get_entries(path, p);
		p->at = iam_entry_shift(path, p->entries, !compat);
		assert_corr(p->curidx != idx);
		p->curidx = idx;
		iam_lock_bh(p->bh);
		assert_corr(p->leaf != dx_get_block(path, p->at));
		p->leaf = dx_get_block(path, p->at);
		iam_unlock_bh(p->bh);
		assert_inv(dx_node_check(path, p));
	}
	return 1;
}

static inline int iam_index_advance(struct iam_path *path)
{
	return iam_htree_advance(iam_path_obj(path), 0, path, NULL, 0);
}

static void iam_unlock_array(struct iam_container *ic,
			     struct dynlock_handle **lh)
{
	int i;

	for (i = 0; i < DX_MAX_TREE_HEIGHT; ++i, ++lh) {
		if (*lh != NULL) {
			iam_unlock_htree(ic, *lh);
			*lh = NULL;
		}
	}
}
/*
 * Advance index part of @path to point to the next leaf. Returns 1 on
 * success, 0, when end of container was reached. Leaf node is locked.
 */
int iam_index_next(struct iam_container *c, struct iam_path *path)
{
	iam_ptr_t cursor;
	struct dynlock_handle *lh[DX_MAX_TREE_HEIGHT] = { NULL, };
	int result;

	/*
	 * Locking for iam_index_next()... is to be described.
	 */

	cursor = path->ip_frame->leaf;

	while (1) {
		result = iam_index_lock(path, lh);
		do_corr(schedule());
		if (result < 0)
			break;

		result = iam_check_full_path(path, 0);
		if (result == 0 && cursor == path->ip_frame->leaf) {
			result = iam_index_advance(path);

			assert_corr(result == 0 ||
				    cursor != path->ip_frame->leaf);
			break;
		}
		do {
			iam_unlock_array(c, lh);

			iam_path_release(path);
			do_corr(schedule());

			result = __iam_path_lookup(path);
			if (result < 0)
				break;

			while (path->ip_frame->leaf != cursor) {
				do_corr(schedule());

				result = iam_index_lock(path, lh);
				do_corr(schedule());
				if (result < 0)
					break;

				result = iam_check_full_path(path, 0);
				if (result != 0)
					break;

				result = iam_index_advance(path);
				if (result == 0) {
					CERROR("cannot find cursor : %u\n",
						cursor);
					result = -EIO;
				}
				if (result < 0)
					break;
				result = iam_check_full_path(path, 0);
				if (result != 0)
					break;
				iam_unlock_array(c, lh);
			}
		} while (result == -EAGAIN);
		if (result < 0)
			break;
	}
	iam_unlock_array(c, lh);
	return result;
}

/*
 * Move iterator one record right.
 *
 * Return value: 0: success,
 *              +1: end of container reached
 *             -ve: error
 *
 * precondition:  (it_state(it) == IAM_IT_ATTACHED ||
 *                 it_state(it) == IAM_IT_SKEWED) && it->ii_flags&IAM_IT_MOVE
 * postcondition: ergo(result == 0, it_state(it) == IAM_IT_ATTACHED) &&
 *                ergo(result >  0, it_state(it) == IAM_IT_DETACHED)
 */
int iam_it_next(struct iam_iterator *it)
{
	int result;
	struct iam_path *path;
	struct iam_leaf *leaf;

	do_corr(struct iam_ikey *ik_orig);

	/* assert_corr(it->ii_flags&IAM_IT_MOVE); */
	assert_corr(it_state(it) == IAM_IT_ATTACHED ||
		    it_state(it) == IAM_IT_SKEWED);

	path = &it->ii_path;
	leaf = &path->ip_leaf;

	assert_corr(iam_leaf_is_locked(leaf));

	result = 0;
	do_corr(ik_orig = it_at_rec(it) ?
		iam_it_ikey_get(it, iam_path_ikey(path, 2)) : NULL);
	if (it_before(it)) {
		assert_corr(!iam_leaf_at_end(leaf));
		it->ii_state = IAM_IT_ATTACHED;
	} else {
		if (!iam_leaf_at_end(leaf))
			/* advance within leaf node */
			iam_leaf_next(leaf);
		/*
		 * multiple iterations may be necessary due to empty leaves.
		 */
		while (result == 0 && iam_leaf_at_end(leaf)) {
			do_corr(schedule());
			/* advance index portion of the path */
			result = iam_index_next(iam_it_container(it), path);
			assert_corr(iam_leaf_is_locked(leaf));
			if (result == 1) {
				struct dynlock_handle *lh;
				lh = iam_lock_htree(iam_it_container(it),
						    path->ip_frame->leaf,
						    DLT_WRITE);
				if (lh != NULL) {
					iam_leaf_fini(leaf);
					leaf->il_lock = lh;
					result = iam_leaf_load(path);
					if (result == 0)
						iam_leaf_start(leaf);
				} else
					result = -ENOMEM;
			} else if (result == 0)
				/* end of container reached */
				result = +1;
			if (result != 0)
				iam_it_put(it);
		}
		if (result == 0)
			it->ii_state = IAM_IT_ATTACHED;
	}
	assert_corr(ergo(result == 0, it_state(it) == IAM_IT_ATTACHED));
	assert_corr(ergo(result >  0, it_state(it) == IAM_IT_DETACHED));
	assert_corr(ergo(result == 0 && ik_orig != NULL,
		    it_ikeycmp(it, ik_orig) >= 0));
	return result;
}

/*
 * Return pointer to the record under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED && it_at_rec(it)
 * postcondition: it_state(it) == IAM_IT_ATTACHED
 */
struct iam_rec *iam_it_rec_get(const struct iam_iterator *it)
{
	assert_corr(it_state(it) == IAM_IT_ATTACHED);
	assert_corr(it_at_rec(it));
	return iam_leaf_rec(&it->ii_path.ip_leaf);
}

static void iam_it_reccpy(struct iam_iterator *it, const struct iam_rec *r)
{
	struct iam_leaf *folio;

	folio = &it->ii_path.ip_leaf;
	iam_leaf_ops(folio)->rec_set(folio, r);
}

/*
 * Replace contents of record under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED &&
 *                it->ii_flags&IAM_IT_WRITE
 * postcondition: it_state(it) == IAM_IT_ATTACHED &&
 *                ergo(result == 0, !memcmp(iam_it_rec_get(it), r, ...))
 */
int iam_it_rec_set(handle_t *h,
                   struct iam_iterator *it, const struct iam_rec *r)
{
	int result;
	struct iam_path *path;
	struct buffer_head *bh;

	assert_corr(it_state(it) == IAM_IT_ATTACHED &&
		    it->ii_flags&IAM_IT_WRITE);
	assert_corr(it_at_rec(it));

	path = &it->ii_path;
	bh = path->ip_leaf.il_bh;
	result = iam_txn_add(h, path, bh);
	if (result == 0) {
		iam_it_reccpy(it, r);
		result = iam_txn_dirty(h, path, bh);
	}
	return result;
}

/*
 * Return pointer to the index key under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_SKEWED
 */
static struct iam_ikey *iam_it_ikey_get(const struct iam_iterator *it,
                                        struct iam_ikey *ikey)
{
	assert_corr(it_state(it) == IAM_IT_ATTACHED ||
		    it_state(it) == IAM_IT_SKEWED);
	assert_corr(it_at_rec(it));
	return iam_leaf_ikey(&it->ii_path.ip_leaf, ikey);
}

/*
 * Return pointer to the key under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_SKEWED
 */
struct iam_key *iam_it_key_get(const struct iam_iterator *it)
{
	assert_corr(it_state(it) == IAM_IT_ATTACHED ||
		    it_state(it) == IAM_IT_SKEWED);
	assert_corr(it_at_rec(it));
	return iam_leaf_key(&it->ii_path.ip_leaf);
}

/*
 * Return size of key under iterator (in bytes)
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_SKEWED
 */
int iam_it_key_size(const struct iam_iterator *it)
{
	assert_corr(it_state(it) == IAM_IT_ATTACHED ||
		    it_state(it) == IAM_IT_SKEWED);
	assert_corr(it_at_rec(it));
	return iam_leaf_key_size(&it->ii_path.ip_leaf);
}

static struct buffer_head *
iam_new_node(handle_t *h, struct iam_container *c, iam_ptr_t *b, int *e)
{
	struct inode *inode = c->ic_object;
	struct buffer_head *bh = NULL;
	struct iam_idle_head *head;
	struct buffer_head *idle;
	__u32 *idle_blocks;
	__u16 count;

	if (c->ic_idle_bh == NULL)
		goto newblock;

	mutex_lock(&c->ic_idle_mutex);
	if (unlikely(c->ic_idle_bh == NULL)) {
		mutex_unlock(&c->ic_idle_mutex);
		goto newblock;
	}

	head = (struct iam_idle_head *)(c->ic_idle_bh->b_data);
	count = le16_to_cpu(head->iih_count);
	if (count > 0) {
		*e = ldiskfs_journal_get_write_access(h, c->ic_idle_bh);
		if (*e != 0)
			goto fail;

		--count;
		*b = le32_to_cpu(head->iih_blks[count]);
		head->iih_count = cpu_to_le16(count);
		*e = ldiskfs_handle_dirty_metadata(h, inode, c->ic_idle_bh);
		if (*e != 0)
			goto fail;

		mutex_unlock(&c->ic_idle_mutex);
		bh = __ldiskfs_bread(NULL, inode, *b, 0);
		if (IS_ERR_OR_NULL(bh)) {
			if (IS_ERR(bh))
				*e = PTR_ERR(bh);
			else
				*e = -EIO;
			return NULL;
		}
		goto got;
	}

	/* The block itself which contains the iam_idle_head is
	 * also an idle block, and can be used as the new node. */
	idle_blocks = (__u32 *)(c->ic_root_bh->b_data +
				c->ic_descr->id_root_gap +
				sizeof(struct dx_countlimit));
	*e = ldiskfs_journal_get_write_access(h, c->ic_root_bh);
	if (*e != 0)
		goto fail;

	*b = le32_to_cpu(*idle_blocks);
	iam_lock_bh(c->ic_root_bh);
	*idle_blocks = head->iih_next;
	iam_unlock_bh(c->ic_root_bh);
	*e = ldiskfs_handle_dirty_metadata(h, inode, c->ic_root_bh);
	if (*e != 0) {
		iam_lock_bh(c->ic_root_bh);
		*idle_blocks = cpu_to_le32(*b);
		iam_unlock_bh(c->ic_root_bh);
		goto fail;
	}

	bh = c->ic_idle_bh;
	idle = iam_load_idle_blocks(c, le32_to_cpu(*idle_blocks));
	if (idle != NULL && IS_ERR(idle)) {
		*e = PTR_ERR(idle);
		c->ic_idle_bh = NULL;
		brelse(bh);
		goto fail;
	}

	c->ic_idle_bh = idle;
	mutex_unlock(&c->ic_idle_mutex);

got:
	/* get write access for the found buffer head */
	*e = ldiskfs_journal_get_write_access(h, bh);
	if (*e != 0) {
		brelse(bh);
		bh = NULL;
		ldiskfs_std_error(inode->i_sb, *e);
	} else {
		/* Clear the reused node as new node does. */
		memset(bh->b_data, 0, inode->i_sb->s_blocksize);
		set_buffer_uptodate(bh);
	}
	return bh;

newblock:
	bh = osd_ldiskfs_append(h, inode, b);
	if (IS_ERR(bh)) {
		*e = PTR_ERR(bh);
		bh = NULL;
	}

	return bh;

fail:
	mutex_unlock(&c->ic_idle_mutex);
	ldiskfs_std_error(inode->i_sb, *e);
	return NULL;
}

/*
 * Insertion of new record. Interaction with jbd during non-trivial case (when
 * split happens) is as following:
 *
 *  - new leaf node is involved into transaction by iam_new_node();
 *
 *  - old leaf node is involved into transaction by iam_add_rec();
 *
 *  - leaf where insertion point ends in, is marked dirty by iam_add_rec();
 *
 *  - leaf without insertion point is marked dirty (as @new_leaf) by
 *  iam_new_leaf();
 *
 *  - split index nodes are involved into transaction and marked dirty by
 *  split_index_node().
 *
 *  - "safe" index node, which is no split, but where new pointer is inserted
 *  is involved into transaction and marked dirty by split_index_node().
 *
 *  - index node where pointer to new leaf is inserted is involved into
 *  transaction by split_index_node() and marked dirty by iam_add_rec().
 *
 *  - inode is marked dirty by iam_add_rec().
 *
 */

static int iam_new_leaf(handle_t *handle, struct iam_leaf *leaf)
{
	int err;
	iam_ptr_t blknr;
	struct buffer_head *new_leaf;
	struct buffer_head *old_leaf;
	struct iam_container *c;
	struct inode *obj;
	struct iam_path *path;

	c = iam_leaf_container(leaf);
	path = leaf->il_path;

	obj = c->ic_object;
	new_leaf = iam_new_node(handle, c, &blknr, &err);
	do_corr(schedule());
	if (new_leaf != NULL) {
		struct dynlock_handle *lh;

		lh = iam_lock_htree(c, blknr, DLT_WRITE);
		do_corr(schedule());
		if (lh != NULL) {
			iam_leaf_ops(leaf)->init_new(c, new_leaf);
			do_corr(schedule());
			old_leaf = leaf->il_bh;
			iam_leaf_split(leaf, &new_leaf, blknr);
			if (old_leaf != leaf->il_bh) {
				/*
				 * Switched to the new leaf.
				 */
				iam_leaf_unlock(leaf);
				leaf->il_lock = lh;
				path->ip_frame->leaf = blknr;
			} else
				iam_unlock_htree(path->ip_container, lh);
			do_corr(schedule());
			err = iam_txn_dirty(handle, path, new_leaf);
			if (err == 0)
				err = ldiskfs_mark_inode_dirty(handle, obj);
			do_corr(schedule());
		} else
			err = -ENOMEM;
		brelse(new_leaf);
	}
	assert_inv(iam_path_check(iam_leaf_path(leaf)));
	return err;
}

static inline void dx_set_limit(struct iam_entry *entries, unsigned value)
{
	((struct dx_countlimit *) entries)->limit = cpu_to_le16(value);
}

static int iam_shift_entries(struct iam_path *path,
                         struct iam_frame *frame, unsigned count,
                         struct iam_entry *entries, struct iam_entry *entries2,
                         u32 newblock)
{
	unsigned count1;
	unsigned count2;
	int delta;

	struct iam_frame *parent = frame - 1;
	struct iam_ikey *pivot = iam_path_ikey(path, 3);

	delta = dx_index_is_compat(path) ? 0 : +1;

	count1 = count/2 + delta;
	count2 = count - count1;
	dx_get_ikey(path, iam_entry_shift(path, entries, count1), pivot);

	dxtrace(printk("Split index %d/%d\n", count1, count2));

	memcpy((char *) iam_entry_shift(path, entries2, delta),
	       (char *) iam_entry_shift(path, entries, count1),
	       count2 * iam_entry_size(path));

	dx_set_count(entries2, count2 + delta);
	dx_set_limit(entries2, dx_node_limit(path));

	/*
	 * NOTE: very subtle piece of code competing dx_probe() may find 2nd
	 * level index in root index, then we insert new index here and set
	 * new count in that 2nd level index. so, dx_probe() may see 2nd level
	 * index w/o hash it looks for. the solution is to check root index
	 * after we locked just founded 2nd level index -bzzz
	 */
	iam_insert_key_lock(path, parent, pivot, newblock);

	/*
	 * now old and new 2nd level index blocks contain all pointers, so
	 * dx_probe() may find it in the both.  it's OK -bzzz
	 */
	iam_lock_bh(frame->bh);
	dx_set_count(entries, count1);
	iam_unlock_bh(frame->bh);

	/*
	 * now old 2nd level index block points to first half of leafs. it's
	 * importand that dx_probe() must check root index block for changes
	 * under dx_lock_bh(frame->bh) -bzzz
	 */

	return count1;
}


int split_index_node(handle_t *handle, struct iam_path *path,
                     struct dynlock_handle **lh)
{
	struct iam_entry *entries;   /* old block contents */
	struct iam_entry *entries2;  /* new block contents */
	struct iam_frame *frame, *safe;
	struct buffer_head *bh_new[DX_MAX_TREE_HEIGHT] = {NULL};
	u32 newblock[DX_MAX_TREE_HEIGHT] = {0};
	struct dynlock_handle *lock[DX_MAX_TREE_HEIGHT] = {NULL,};
	struct dynlock_handle *new_lock[DX_MAX_TREE_HEIGHT] = {NULL,};
	struct inode *dir = iam_path_obj(path);
	struct iam_descr *descr;
	int nr_splet;
	int i, err;

	descr = iam_path_descr(path);
	/*
	 * Algorithm below depends on this.
	 */
	assert_corr(dx_root_limit(path) < dx_node_limit(path));

	frame = path->ip_frame;
	entries = frame->entries;

	/*
	 * Tall-tree handling: we might have to split multiple index blocks
	 * all the way up to tree root. Tricky point here is error handling:
	 * to avoid complicated undo/rollback we
	 *
	 *   - first allocate all necessary blocks
	 *
	 *   - insert pointers into them atomically.
	 */

	/*
	 * Locking: leaf is already locked. htree-locks are acquired on all
	 * index nodes that require split bottom-to-top, on the "safe" node,
	 * and on all new nodes
	 */

	dxtrace(printk("using %u of %u node entries\n",
		       dx_get_count(entries), dx_get_limit(entries)));

	/* What levels need split? */
	for (nr_splet = 0; frame >= path->ip_frames &&
	     dx_get_count(frame->entries) == dx_get_limit(frame->entries);
	     --frame, ++nr_splet) {
		do_corr(schedule());
		if (nr_splet == DX_MAX_TREE_HEIGHT) {
			/*
			 * CWARN(dir->i_sb, __FUNCTION__,
			 * "Directory index full!\n");
			 */
			err = -ENOSPC;
			goto cleanup;
		}
	}

	safe = frame;

	/*
	 * Lock all nodes, bottom to top.
	 */
	for (frame = path->ip_frame, i = nr_splet; i >= 0; --i, --frame) {
		do_corr(schedule());
		lock[i] = iam_lock_htree(path->ip_container, frame->curidx,
					 DLT_WRITE);
		if (lock[i] == NULL) {
			err = -ENOMEM;
			goto cleanup;
		}
	}

	/*
	 * Check for concurrent index modification.
	 */
	err = iam_check_full_path(path, 1);
	if (err)
		goto cleanup;
	/*
	 * And check that the same number of nodes is to be split.
	 */
	for (i = 0, frame = path->ip_frame; frame >= path->ip_frames &&
	     dx_get_count(frame->entries) == dx_get_limit(frame->entries);
	     --frame, ++i) {
		;
	}
	if (i != nr_splet) {
		err = -EAGAIN;
		goto cleanup;
	}

	/*
	 * Go back down, allocating blocks, locking them, and adding into
	 * transaction...
	 */
	for (frame = safe + 1, i = 0; i < nr_splet; ++i, ++frame) {
		bh_new[i] = iam_new_node(handle, path->ip_container,
					 &newblock[i], &err);
		do_corr(schedule());
		if (!bh_new[i] ||
		    descr->id_ops->id_node_init(path->ip_container,
						bh_new[i], 0) != 0)
			goto cleanup;

		new_lock[i] = iam_lock_htree(path->ip_container, newblock[i],
					     DLT_WRITE);
		if (new_lock[i] == NULL) {
			err = -ENOMEM;
			goto cleanup;
		}
		do_corr(schedule());
		BUFFER_TRACE(frame->bh, "get_write_access");
		err = ldiskfs_journal_get_write_access(handle, frame->bh);
		if (err)
			goto journal_error;
	}
	/* Add "safe" node to transaction too */
	if (safe + 1 != path->ip_frames) {
		do_corr(schedule());
		err = ldiskfs_journal_get_write_access(handle, safe->bh);
		if (err)
			goto journal_error;
	}

	/* Go through nodes once more, inserting pointers */
	for (frame = safe + 1, i = 0; i < nr_splet; ++i, ++frame) {
		unsigned count;
		int idx;
		struct buffer_head *bh2;
		struct buffer_head *bh;

		entries = frame->entries;
		count = dx_get_count(entries);
		idx = iam_entry_diff(path, frame->at, entries);

		bh2 = bh_new[i];
		entries2 = dx_get_entries(path, bh2->b_data, 0);

		bh = frame->bh;
		if (frame == path->ip_frames) {
			/* splitting root node. Tricky point:
			 *
			 * In the "normal" B-tree we'd split root *and* add
			 * new root to the tree with pointers to the old root
			 * and its sibling (thus introducing two new nodes).
			 *
			 * In htree it's enough to add one node, because
			 * capacity of the root node is smaller than that of
			 * non-root one.
			 */
			struct iam_frame *frames;
			struct iam_entry *next;

			assert_corr(i == 0);

			do_corr(schedule());

			frames = path->ip_frames;
			memcpy((char *) entries2, (char *) entries,
			       count * iam_entry_size(path));
			dx_set_limit(entries2, dx_node_limit(path));

			/* Set up root */
			iam_lock_bh(frame->bh);
			next = descr->id_ops->id_root_inc(path->ip_container,
							  path, frame);
			dx_set_block(path, next, newblock[0]);
			iam_unlock_bh(frame->bh);

			do_corr(schedule());
			/* Shift frames in the path */
			memmove(frames + 2, frames + 1,
			       (sizeof path->ip_frames) - 2 * sizeof frames[0]);
			/* Add new access path frame */
			frames[1].at = iam_entry_shift(path, entries2, idx);
			frames[1].entries = entries = entries2;
			frames[1].bh = bh2;
			assert_inv(dx_node_check(path, frame));
			++ path->ip_frame;
			++ frame;
			assert_inv(dx_node_check(path, frame));
			bh_new[0] = NULL; /* buffer head is "consumed" */
			err = ldiskfs_handle_dirty_metadata(handle, NULL, bh2);
			if (err)
				goto journal_error;
			do_corr(schedule());
		} else {
			/* splitting non-root index node. */
			struct iam_frame *parent = frame - 1;

			do_corr(schedule());
			count = iam_shift_entries(path, frame, count,
						entries, entries2, newblock[i]);
			/* Which index block gets the new entry? */
			if (idx >= count) {
				int d = dx_index_is_compat(path) ? 0 : +1;

				frame->at = iam_entry_shift(path, entries2,
							    idx - count + d);
				frame->entries = entries = entries2;
				frame->curidx = newblock[i];
				swap(frame->bh, bh2);
				assert_corr(lock[i + 1] != NULL);
				assert_corr(new_lock[i] != NULL);
				swap(lock[i + 1], new_lock[i]);
				bh_new[i] = bh2;
				parent->at = iam_entry_shift(path,
							     parent->at, +1);
			}
			assert_inv(dx_node_check(path, frame));
			assert_inv(dx_node_check(path, parent));
			dxtrace(dx_show_index("node", frame->entries));
			dxtrace(dx_show_index("node",
				((struct dx_node *) bh2->b_data)->entries));
			err = ldiskfs_handle_dirty_metadata(handle, NULL, bh2);
			if (err)
				goto journal_error;
			do_corr(schedule());
			err = ldiskfs_handle_dirty_metadata(handle, NULL,
							    parent->bh);
			if (err)
				goto journal_error;
		}
		do_corr(schedule());
		err = ldiskfs_handle_dirty_metadata(handle, NULL, bh);
		if (err)
			goto journal_error;
	}
		/*
		 * This function was called to make insertion of new leaf
		 * possible. Check that it fulfilled its obligations.
		 */
		assert_corr(dx_get_count(path->ip_frame->entries) <
			    dx_get_limit(path->ip_frame->entries));
	assert_corr(lock[nr_splet] != NULL);
	*lh = lock[nr_splet];
	lock[nr_splet] = NULL;
	if (nr_splet > 0) {
		/*
		 * Log ->i_size modification.
		 */
		err = ldiskfs_mark_inode_dirty(handle, dir);
		if (err)
			goto journal_error;
	}
	goto cleanup;
journal_error:
	ldiskfs_std_error(dir->i_sb, err);

cleanup:
	iam_unlock_array(path->ip_container, lock);
	iam_unlock_array(path->ip_container, new_lock);

	assert_corr(err || iam_frame_is_locked(path, path->ip_frame));

	do_corr(schedule());
	for (i = 0; i < ARRAY_SIZE(bh_new); ++i) {
		if (bh_new[i] != NULL)
			brelse(bh_new[i]);
	}
	return err;
}

static int iam_add_rec(handle_t *handle, struct iam_iterator *it,
                       struct iam_path *path,
                       const struct iam_key *k, const struct iam_rec *r)
{
	int err;
	struct iam_leaf *leaf;

	leaf = &path->ip_leaf;
	assert_inv(iam_path_check(path));
	err = iam_txn_add(handle, path, leaf->il_bh);
	if (err == 0) {
		do_corr(schedule());
		if (!iam_leaf_can_add(leaf, k, r)) {
			struct dynlock_handle *lh = NULL;

			do {
				assert_corr(lh == NULL);
				do_corr(schedule());
				err = split_index_node(handle, path, &lh);
				if (err == -EAGAIN) {
					assert_corr(lh == NULL);

					iam_path_fini(path);
					it->ii_state = IAM_IT_DETACHED;

					do_corr(schedule());
					err = iam_it_get_exact(it, k);
					if (err == -ENOENT)
						err = +1; /* repeat split */
					else if (err == 0)
						err = -EEXIST;
				}
			} while (err > 0);
			assert_inv(iam_path_check(path));
			if (err == 0) {
				assert_corr(lh != NULL);
				do_corr(schedule());
				err = iam_new_leaf(handle, leaf);
				if (err == 0)
					err = iam_txn_dirty(handle, path,
							    path->ip_frame->bh);
			}
			iam_unlock_htree(path->ip_container, lh);
			do_corr(schedule());
		}
		if (err == 0) {
			iam_leaf_rec_add(leaf, k, r);
			err = iam_txn_dirty(handle, path, leaf->il_bh);
		}
	}
	assert_inv(iam_path_check(path));
	return err;
}

/*
 * Insert new record with key @k and contents from @r, shifting records to the
 * right. On success, iterator is positioned on the newly inserted record.
 *
 * precondition: it->ii_flags&IAM_IT_WRITE &&
 *               (it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_SKEWED) &&
 *               ergo(it_state(it) == IAM_IT_ATTACHED,
 *                    it_keycmp(it, k) <= 0) &&
 *               ergo(it_before(it), it_keycmp(it, k) > 0));
 * postcondition: ergo(result == 0,
 *                     it_state(it) == IAM_IT_ATTACHED &&
 *                     it_keycmp(it, k) == 0 &&
 *                     !memcmp(iam_it_rec_get(it), r, ...))
 */
int iam_it_rec_insert(handle_t *h, struct iam_iterator *it,
                      const struct iam_key *k, const struct iam_rec *r)
{
	int result;
	struct iam_path *path;

	path = &it->ii_path;

	assert_corr(it->ii_flags&IAM_IT_WRITE);
	assert_corr(it_state(it) == IAM_IT_ATTACHED ||
		    it_state(it) == IAM_IT_SKEWED);
	assert_corr(ergo(it_state(it) == IAM_IT_ATTACHED,
		    it_keycmp(it, k) <= 0));
	assert_corr(ergo(it_before(it), it_keycmp(it, k) > 0));
	result = iam_add_rec(h, it, path, k, r);
	if (result == 0)
		it->ii_state = IAM_IT_ATTACHED;
	assert_corr(ergo(result == 0,
			 it_state(it) == IAM_IT_ATTACHED &&
			 it_keycmp(it, k) == 0));
	return result;
}

static inline int iam_idle_blocks_limit(struct inode *inode)
{
	return (inode->i_sb->s_blocksize - sizeof(struct iam_idle_head)) >> 2;
}

/*
 * If the leaf cannnot be recycled, we will lose one block for reusing.
 * It is not a serious issue because it almost the same of non-recycle.
 */
static iam_ptr_t iam_index_shrink(handle_t *h, struct iam_path *p,
				  struct iam_leaf *l, struct buffer_head **bh)
{
	struct iam_container *c = p->ip_container;
	struct inode *inode = c->ic_object;
	struct iam_frame *frame = p->ip_frame;
	struct iam_entry *entries;
	struct iam_entry *pos;
	struct dynlock_handle *lh;
	int count;
	int rc;

	if (c->ic_idle_failed)
		return 0;

	if (unlikely(frame == NULL))
		return 0;

	if (!iam_leaf_empty(l))
		return 0;

	lh = iam_lock_htree(c, frame->curidx, DLT_WRITE);
	if (lh == NULL) {
		CWARN("%s: No memory to recycle idle blocks\n",
		      osd_ino2name(inode));
		return 0;
	}

	rc = iam_txn_add(h, p, frame->bh);
	if (rc != 0) {
		iam_unlock_htree(c, lh);
		return 0;
	}

	iam_lock_bh(frame->bh);
	entries = frame->entries;
	count = dx_get_count(entries);
	/*
	 * NOT shrink the last entry in the index node, which can be reused
	 * directly by next new node.
	 */
	if (count == 2) {
		iam_unlock_bh(frame->bh);
		iam_unlock_htree(c, lh);
		return 0;
	}

	pos = iam_find_position(p, frame);
	/*
	 * There may be some new leaf nodes have been added or empty leaf nodes
	 * have been shrinked during my delete operation.
	 *
	 * If the empty leaf is not under current index node because the index
	 * node has been split, then just skip the empty leaf, which is rare.
	 */
	if (unlikely(frame->leaf != dx_get_block(p, pos))) {
		iam_unlock_bh(frame->bh);
		iam_unlock_htree(c, lh);
		return 0;
	}

	frame->at = pos;
	if (frame->at < iam_entry_shift(p, entries, count - 1)) {
		struct iam_entry *n = iam_entry_shift(p, frame->at, 1);

		memmove(frame->at, n,
			(char *)iam_entry_shift(p, entries, count) - (char *)n);
		frame->at_shifted = 1;
	}
	dx_set_count(entries, count - 1);
	iam_unlock_bh(frame->bh);
	rc = iam_txn_dirty(h, p, frame->bh);
	iam_unlock_htree(c, lh);
	if (rc != 0)
		return 0;

	get_bh(l->il_bh);
	*bh = l->il_bh;
	return frame->leaf;
}

static int
iam_install_idle_blocks(handle_t *h, struct iam_path *p, struct buffer_head *bh,
			__u32 *idle_blocks, iam_ptr_t blk)
{
	struct iam_container *c = p->ip_container;
	struct buffer_head *old = c->ic_idle_bh;
	struct iam_idle_head *head;
	int rc;

	head = (struct iam_idle_head *)(bh->b_data);
	head->iih_magic = cpu_to_le16(IAM_IDLE_HEADER_MAGIC);
	head->iih_count = 0;
	head->iih_next = *idle_blocks;
	/* The bh already get_write_accessed. */
	rc = iam_txn_dirty(h, p, bh);
	if (rc != 0)
		return rc;

	rc = iam_txn_add(h, p, c->ic_root_bh);
	if (rc != 0)
		return rc;

	iam_lock_bh(c->ic_root_bh);
	*idle_blocks = cpu_to_le32(blk);
	iam_unlock_bh(c->ic_root_bh);
	rc = iam_txn_dirty(h, p, c->ic_root_bh);
	if (rc == 0) {
		/* NOT release old before new assigned. */
		get_bh(bh);
		c->ic_idle_bh = bh;
		brelse(old);
	} else {
		iam_lock_bh(c->ic_root_bh);
		*idle_blocks = head->iih_next;
		iam_unlock_bh(c->ic_root_bh);
	}
	return rc;
}

/*
 * If the leaf cannnot be recycled, we will lose one block for reusing.
 * It is not a serious issue because it almost the same of non-recycle.
 */
static void iam_recycle_leaf(handle_t *h, struct iam_path *p,
			     struct buffer_head *bh, iam_ptr_t blk)
{
	struct iam_container *c = p->ip_container;
	struct inode *inode = c->ic_object;
	struct iam_idle_head *head;
	__u32 *idle_blocks;
	int count;
	int rc;

	mutex_lock(&c->ic_idle_mutex);
	if (unlikely(c->ic_idle_failed)) {
		rc = -EFAULT;
		goto unlock;
	}

	idle_blocks = (__u32 *)(c->ic_root_bh->b_data +
				c->ic_descr->id_root_gap +
				sizeof(struct dx_countlimit));
	/* It is the first idle block. */
	if (c->ic_idle_bh == NULL) {
		rc = iam_install_idle_blocks(h, p, bh, idle_blocks, blk);
		goto unlock;
	}

	head = (struct iam_idle_head *)(c->ic_idle_bh->b_data);
	count = le16_to_cpu(head->iih_count);
	/* Current ic_idle_bh is full, to be replaced by the leaf. */
	if (count == iam_idle_blocks_limit(inode)) {
		rc = iam_install_idle_blocks(h, p, bh, idle_blocks, blk);
		goto unlock;
	}

	/* Just add to ic_idle_bh. */
	rc = iam_txn_add(h, p, c->ic_idle_bh);
	if (rc != 0)
		goto unlock;

	head->iih_blks[count] = cpu_to_le32(blk);
	head->iih_count = cpu_to_le16(count + 1);
	rc = iam_txn_dirty(h, p, c->ic_idle_bh);

unlock:
	mutex_unlock(&c->ic_idle_mutex);
	if (rc != 0)
		CWARN("%s: idle blocks failed, will lose the blk %u\n",
		      osd_ino2name(inode), blk);
}

/*
 * Delete record under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED &&
 *                it->ii_flags&IAM_IT_WRITE &&
 *                it_at_rec(it)
 * postcondition: it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_DETACHED
 */
int iam_it_rec_delete(handle_t *h, struct iam_iterator *it)
{
	int result;
	struct iam_leaf *leaf;
	struct iam_path *path;

	assert_corr(it_state(it) == IAM_IT_ATTACHED &&
		    it->ii_flags&IAM_IT_WRITE);
	assert_corr(it_at_rec(it));

	path = &it->ii_path;
	leaf = &path->ip_leaf;

	assert_inv(iam_path_check(path));

	result = iam_txn_add(h, path, leaf->il_bh);
	/*
	 * no compaction for now.
	 */
	if (result == 0) {
		iam_rec_del(leaf, it->ii_flags&IAM_IT_MOVE);
		result = iam_txn_dirty(h, path, leaf->il_bh);
		if (result == 0 && iam_leaf_at_end(leaf)) {
			struct buffer_head *bh = NULL;
			iam_ptr_t blk;

			blk = iam_index_shrink(h, path, leaf, &bh);
			if (it->ii_flags & IAM_IT_MOVE) {
				result = iam_it_next(it);
				if (result > 0)
					result = 0;
			}

			if (bh != NULL) {
				iam_recycle_leaf(h, path, bh, blk);
				brelse(bh);
			}
		}
	}
	assert_inv(iam_path_check(path));
	assert_corr(it_state(it) == IAM_IT_ATTACHED ||
		    it_state(it) == IAM_IT_DETACHED);
	return result;
}

/*
 * Convert iterator to cookie.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED &&
 *                iam_path_descr(it->ii_path)->id_key_size <= sizeof(iam_pos_t)
 * postcondition: it_state(it) == IAM_IT_ATTACHED
 */
iam_pos_t iam_it_store(const struct iam_iterator *it)
{
	iam_pos_t result;

	assert_corr(it_state(it) == IAM_IT_ATTACHED);
	assert_corr(it_at_rec(it));
	assert_corr(iam_it_container(it)->ic_descr->id_ikey_size <=
		    sizeof result);

	result = 0;
	return *(iam_pos_t *)iam_it_ikey_get(it, (void *)&result);
}

/*
 * Restore iterator from cookie.
 *
 * precondition:  it_state(it) == IAM_IT_DETACHED && it->ii_flags&IAM_IT_MOVE &&
 *                iam_path_descr(it->ii_path)->id_key_size <= sizeof(iam_pos_t)
 * postcondition: ergo(result == 0, it_state(it) == IAM_IT_ATTACHED &&
 *                                  iam_it_store(it) == pos)
 */
int iam_it_load(struct iam_iterator *it, iam_pos_t pos)
{
	assert_corr(it_state(it) == IAM_IT_DETACHED &&
		it->ii_flags&IAM_IT_MOVE);
	assert_corr(iam_it_container(it)->ic_descr->id_ikey_size <= sizeof pos);
	return iam_it_iget(it, (struct iam_ikey *)&pos);
}

/***********************************************************************/
/* invariants                                                          */
/***********************************************************************/

static inline int ptr_inside(void *base, size_t size, void *ptr)
{
	return (base <= ptr) && (ptr < base + size);
}

static int iam_frame_invariant(struct iam_frame *f)
{
	return
		(f->bh != NULL &&
		f->bh->b_data != NULL &&
		ptr_inside(f->bh->b_data, f->bh->b_size, f->entries) &&
		ptr_inside(f->bh->b_data, f->bh->b_size, f->at) &&
		f->entries <= f->at);
}

static int iam_leaf_invariant(struct iam_leaf *l)
{
	return
		l->il_bh != NULL &&
		l->il_bh->b_data != NULL &&
		ptr_inside(l->il_bh->b_data, l->il_bh->b_size, l->il_entries) &&
		ptr_inside(l->il_bh->b_data, l->il_bh->b_size, l->il_at) &&
		l->il_entries <= l->il_at;
}

static int iam_path_invariant(struct iam_path *p)
{
	int i;

	if (p->ip_container == NULL ||
	    p->ip_indirect < 0 || p->ip_indirect > DX_MAX_TREE_HEIGHT - 1 ||
	    p->ip_frame != p->ip_frames + p->ip_indirect ||
	    !iam_leaf_invariant(&p->ip_leaf))
		return 0;
	for (i = 0; i < ARRAY_SIZE(p->ip_frames); ++i) {
		if (i <= p->ip_indirect) {
			if (!iam_frame_invariant(&p->ip_frames[i]))
				return 0;
		}
	}
	return 1;
}

int iam_it_invariant(struct iam_iterator *it)
{
	return
		(it->ii_state == IAM_IT_DETACHED ||
		it->ii_state == IAM_IT_ATTACHED ||
		it->ii_state == IAM_IT_SKEWED) &&
		!(it->ii_flags & ~(IAM_IT_MOVE | IAM_IT_WRITE)) &&
		ergo(it->ii_state == IAM_IT_ATTACHED ||
		it->ii_state == IAM_IT_SKEWED,
		iam_path_invariant(&it->ii_path) &&
		equi(it_at_rec(it), it->ii_state == IAM_IT_SKEWED));
}

/*
 * Search container @c for record with key @k. If record is found, its data
 * are moved into @r.
 *
 * Return values: 0: found, -ENOENT: not-found, -ve: error
 */
int iam_lookup(struct iam_container *c, const struct iam_key *k,
               struct iam_rec *r, struct iam_path_descr *pd)
{
	struct iam_iterator it;
	int result;

	iam_it_init(&it, c, 0, pd);

	result = iam_it_get_exact(&it, k);
	if (result == 0)
		/*
		 * record with required key found, copy it into user buffer
		 */
		iam_reccpy(&it.ii_path.ip_leaf, r);
	iam_it_put(&it);
	iam_it_fini(&it);
	return result;
}

/*
 * Insert new record @r with key @k into container @c (within context of
 * transaction @h).
 *
 * Return values: 0: success, -ve: error, including -EEXIST when record with
 * given key is already present.
 *
 * postcondition: ergo(result == 0 || result == -EEXIST,
 *                                  iam_lookup(c, k, r2) > 0;
 */
int iam_insert(handle_t *h, struct iam_container *c, const struct iam_key *k,
               const struct iam_rec *r, struct iam_path_descr *pd)
{
	struct iam_iterator it;
	int result;

	iam_it_init(&it, c, IAM_IT_WRITE, pd);

	result = iam_it_get_exact(&it, k);
	if (result == -ENOENT)
		result = iam_it_rec_insert(h, &it, k, r);
	else if (result == 0)
		result = -EEXIST;
	iam_it_put(&it);
	iam_it_fini(&it);
	return result;
}

/*
 * Update record with the key @k in container @c (within context of
 * transaction @h), new record is given by @r.
 *
 * Return values: +1: skip because of the same rec value, 0: success,
 * -ve: error, including -ENOENT if no record with the given key found.
 */
int iam_update(handle_t *h, struct iam_container *c, const struct iam_key *k,
               const struct iam_rec *r, struct iam_path_descr *pd)
{
	struct iam_iterator it;
	struct iam_leaf *folio;
	int result;

	iam_it_init(&it, c, IAM_IT_WRITE, pd);

	result = iam_it_get_exact(&it, k);
	if (result == 0) {
		folio = &it.ii_path.ip_leaf;
		result = iam_leaf_ops(folio)->rec_eq(folio, r);
		if (result == 0)
			iam_it_rec_set(h, &it, r);
		else
			result = 1;
	}
	iam_it_put(&it);
	iam_it_fini(&it);
	return result;
}

/*
 * Delete existing record with key @k.
 *
 * Return values: 0: success, -ENOENT: not-found, -ve: other error.
 *
 * postcondition: ergo(result == 0 || result == -ENOENT,
 *                                 !iam_lookup(c, k, *));
 */
int iam_delete(handle_t *h, struct iam_container *c, const struct iam_key *k,
               struct iam_path_descr *pd)
{
	struct iam_iterator it;
	int result;

	iam_it_init(&it, c, IAM_IT_WRITE, pd);

	result = iam_it_get_exact(&it, k);
	if (result == 0)
		iam_it_rec_delete(h, &it);
	iam_it_put(&it);
	iam_it_fini(&it);
	return result;
}

int iam_root_limit(int rootgap, int blocksize, int size)
{
	int limit;
	int nlimit;

	limit = (blocksize - rootgap) / size;
	nlimit = blocksize / size;
	if (limit == nlimit)
		limit--;
	return limit;
}
