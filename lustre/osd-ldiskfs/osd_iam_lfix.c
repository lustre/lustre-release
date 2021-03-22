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
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * iam_lfix.c
 * implementation of iam format for fixed size records.
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#include <linux/types.h>
#include "osd_internal.h"

/*
 * Leaf operations.
 */

enum {
	IAM_LEAF_HEADER_MAGIC = 0x1976 /* This is duplicated in
                                        * lustre/utils/create_iam.c */
};

/* This is duplicated in lustre/utils/create_iam.c */
struct iam_leaf_head {
	__le16 ill_magic;
	__le16 ill_count;
};

static inline int iam_lfix_entry_size(const struct iam_leaf *l)
{
	return iam_leaf_descr(l)->id_key_size + iam_leaf_descr(l)->id_rec_size;
}

static inline struct iam_lentry *
iam_lfix_shift(const struct iam_leaf *l, struct iam_lentry *entry, int shift)
{
	return (void *)entry + shift * iam_lfix_entry_size(l);
}

static inline struct iam_key *iam_leaf_key_at(struct iam_lentry *entry)
{
	return (struct iam_key *)entry;
}

static inline int lfix_keycmp(const struct iam_container *c,
			      const struct iam_key *k1,
			      const struct iam_key *k2)
{
	return memcmp(k1, k2, c->ic_descr->id_key_size);
}

static struct iam_leaf_head *iam_get_head(const struct iam_leaf *l)
{
	return (struct iam_leaf_head *)l->il_bh->b_data;
}

static struct iam_lentry *iam_entries(const struct buffer_head *bh)
{
	return (void *)bh->b_data + sizeof(struct iam_leaf_head);
}

static struct iam_lentry *iam_get_lentries(const struct iam_leaf *l)
{
	return iam_entries(l->il_bh);
}

static int leaf_count_limit(const struct iam_leaf *leaf)
{
	int free_space;

	free_space = iam_leaf_container(leaf)->ic_object->i_sb->s_blocksize;
	free_space -= sizeof(struct iam_leaf_head);
	return free_space / iam_lfix_entry_size(leaf);
}

static int lentry_count_get(const struct iam_leaf *leaf)
{
	return le16_to_cpu(iam_get_head(leaf)->ill_count);
}

static void lentry_count_set(struct iam_leaf *leaf, unsigned count)
{
	assert_corr(0 <= count && count <= leaf_count_limit(leaf));
	iam_get_head(leaf)->ill_count = cpu_to_le16(count);
}

static struct iam_lentry *iam_lfix_get_end(const struct iam_leaf *l);

#if LDISKFS_CORRECTNESS_ON || LDISKFS_INVARIANT_ON
static int iam_leaf_at_rec(const struct iam_leaf *folio)
{
	return iam_get_lentries(folio) <= folio->il_at &&
		folio->il_at < iam_lfix_get_end(folio);
}
#endif

static struct iam_ikey *iam_lfix_ikey(const struct iam_leaf *l,
				      struct iam_ikey *key)
{
	void *ie = l->il_at;

	assert_corr(iam_leaf_at_rec(l));
	return (struct iam_ikey *)ie;
}

static struct iam_key *iam_lfix_key(const struct iam_leaf *l)
{
	void *ie = l->il_at;

	assert_corr(iam_leaf_at_rec(l));
	return (struct iam_key *)ie;
}

static int iam_lfix_key_size(const struct iam_leaf *l)
{
	return iam_leaf_descr(l)->id_key_size;
}

static void iam_lfix_start(struct iam_leaf *l)
{
	l->il_at = iam_get_lentries(l);
}

static inline ptrdiff_t iam_lfix_diff(const struct iam_leaf *l,
				      const struct iam_lentry *e1,
				      const struct iam_lentry *e2)
{
	ptrdiff_t diff;
	int esize;

	esize = iam_lfix_entry_size(l);
	diff = (void *)e1 - (void *)e2;
	assert_corr(diff / esize * esize == diff);
	return diff / esize;
}

static int iam_lfix_init(struct iam_leaf *l)
{
	int result;
	struct iam_leaf_head *ill;
	int count;

	assert_corr(l->il_bh != NULL);

	ill = iam_get_head(l);
	count = le16_to_cpu(ill->ill_count);
	if (le16_to_cpu(ill->ill_magic) == IAM_LEAF_HEADER_MAGIC &&
			0 <= count && count <= leaf_count_limit(l)) {
		l->il_at = l->il_entries = iam_get_lentries(l);
		result = 0;
	} else {
		struct inode *obj;

		result = -EIO;
		obj = iam_leaf_container(l)->ic_object;
		CERROR(
		"Bad magic in node %llu #%lu: %#x != %#x or bad cnt: %d %d: rc = %d\n",
			(unsigned long long)l->il_bh->b_blocknr, obj->i_ino,
			le16_to_cpu(ill->ill_magic), IAM_LEAF_HEADER_MAGIC,
			count, leaf_count_limit(l), result);
	}
	return result;
}

static void iam_lfix_fini(struct iam_leaf *l)
{
	l->il_entries = l->il_at = NULL;
}

static struct iam_lentry *iam_lfix_get_end(const struct iam_leaf *l)
{
	int count = lentry_count_get(l);
	struct iam_lentry *ile = iam_lfix_shift(l, l->il_entries, count);

	return ile;
}

static struct iam_rec *iam_lfix_rec(const struct iam_leaf *l)
{
	void *e = l->il_at;

	assert_corr(iam_leaf_at_rec(l));
	return e + iam_leaf_descr(l)->id_key_size;
}

static void iam_lfix_next(struct iam_leaf *l)
{
	assert_corr(iam_leaf_at_rec(l));
	l->il_at = iam_lfix_shift(l, l->il_at, 1);
}

/*
 * Bug chasing.
 */
int lfix_dump = 0;

static char hdigit(char ch)
{
	static const char d[] = "0123456789abcdef";

	return d[ch & 0xf];
}

static char *hex(char ch, char *area)
{
	area[0] = hdigit(ch >> 4);
	area[1] = hdigit(ch);
	area[2] = 0;
	return area;
}

static void l_print(struct iam_leaf *leaf, struct iam_lentry *entry)
{
	int i;
	char *area;
	char h[3];

	area = (char *)entry;
	printk(KERN_EMERG "[");
	for (i = iam_lfix_key_size(leaf); i > 0; --i, ++area)
		printk("%s", hex(*area, h));
	printk("]-(");
	for (i = iam_leaf_descr(leaf)->id_rec_size; i > 0; --i, ++area)
		printk("%s", hex(*area, h));
	printk(")\n");
}

static void lfix_print(struct iam_leaf *leaf)
{
	struct iam_lentry *entry;
	int count;
	int i;

	entry = leaf->il_entries;
	count = lentry_count_get(leaf);
	printk(KERN_EMERG "lfix: %p %p %d\n", leaf, leaf->il_at, count);
	for (i = 0; i < count; ++i, entry = iam_lfix_shift(leaf, entry, 1))
		l_print(leaf, entry);
}

static int iam_lfix_lookup(struct iam_leaf *l, const struct iam_key *k)
{
	struct iam_lentry *p, *q, *m, *t;
	struct iam_container *c;
	int count;
	int result;

	count = lentry_count_get(l);
	if (count == 0)
                return IAM_LOOKUP_EMPTY;

	result = IAM_LOOKUP_OK;
	c = iam_leaf_container(l);

	p = l->il_entries;
	q = iam_lfix_shift(l, p, count - 1);
	if (lfix_keycmp(c, k, iam_leaf_key_at(p)) < 0) {
		/*
		 * @k is less than the least key in the leaf
		 */
		l->il_at = p;
		result = IAM_LOOKUP_BEFORE;
	} else if (lfix_keycmp(c, iam_leaf_key_at(q), k) <= 0) {
		l->il_at = q;
	} else {
		/*
		 * EWD1293
		 */
		while (iam_lfix_shift(l, p, 1) != q) {
			m = iam_lfix_shift(l, p, iam_lfix_diff(l, q, p) / 2);
			assert_corr(p < m && m < q);
			if (lfix_keycmp(c, iam_leaf_key_at(m), k) <= 0)
				p = m;
			else
				q = m;
		}
		assert_corr(lfix_keycmp(c, iam_leaf_key_at(p), k) <= 0 &&
			    lfix_keycmp(c, k, iam_leaf_key_at(q)) < 0);
		/*
		 * skip over records with duplicate keys.
		 */
		while (p > l->il_entries) {
			t = iam_lfix_shift(l, p, -1);
			if (lfix_keycmp(c, iam_leaf_key_at(t), k) == 0)
				p = t;
			else
				break;
		}
		l->il_at = p;
	}
	assert_corr(iam_leaf_at_rec(l));

	if (lfix_keycmp(c, iam_leaf_key_at(l->il_at), k) == 0)
                result = IAM_LOOKUP_EXACT;

	if (lfix_dump)
                lfix_print(l);

	return result;
}

static int iam_lfix_ilookup(struct iam_leaf *l, const struct iam_ikey *ik)
{
	return iam_lfix_lookup(l, (const struct iam_key *)ik);
}

static void iam_lfix_key_set(struct iam_leaf *l, const struct iam_key *k)
{
	assert_corr(iam_leaf_at_rec(l));
	memcpy(iam_leaf_key_at(l->il_at), k, iam_leaf_descr(l)->id_key_size);
}

static int iam_lfix_key_cmp(const struct iam_leaf *l, const struct iam_key *k)
{
	return lfix_keycmp(iam_leaf_container(l), iam_leaf_key_at(l->il_at), k);
}

static int iam_lfix_key_eq(const struct iam_leaf *l, const struct iam_key *k)
{
	return !lfix_keycmp(iam_leaf_container(l),
			    iam_leaf_key_at(l->il_at), k);
}

static void iam_lfix_rec_set(struct iam_leaf *l, const struct iam_rec *r)
{
	assert_corr(iam_leaf_at_rec(l));
	memcpy(iam_lfix_rec(l), r, iam_leaf_descr(l)->id_rec_size);
}

static inline int lfix_reccmp(const struct iam_container *c,
			      const struct iam_rec *r1,
			      const struct iam_rec *r2)
{
	return memcmp(r1, r2, c->ic_descr->id_rec_size);
}

static int iam_lfix_rec_eq(const struct iam_leaf *l, const struct iam_rec *r)
{
	return !lfix_reccmp(iam_leaf_container(l), iam_lfix_rec(l), r);
}

static void iam_lfix_rec_get(const struct iam_leaf *l, struct iam_rec *r)
{
	assert_corr(iam_leaf_at_rec(l));
	memcpy(r, iam_lfix_rec(l), iam_leaf_descr(l)->id_rec_size);
}

static void iam_lfix_rec_add(struct iam_leaf *leaf,
			     const struct iam_key *k, const struct iam_rec *r)
{
	struct iam_lentry *end;
	struct iam_lentry *cur;
	struct iam_lentry *start;
	ptrdiff_t diff;
	int count;

	assert_corr(iam_leaf_can_add(leaf, k, r));

	count = lentry_count_get(leaf);
	/*
	 * This branch handles two exceptional cases:
	 *
	 *   - leaf positioned beyond last record, and
	 *
	 *   - empty leaf.
	 */
	if (!iam_leaf_at_end(leaf)) {
		end   = iam_lfix_get_end(leaf);
		cur   = leaf->il_at;
		if (lfix_keycmp(iam_leaf_container(leaf),
				k, iam_leaf_key_at(cur)) >= 0)
			iam_lfix_next(leaf);
		else
			/*
			 * Another exceptional case: insertion with the key
			 * less than least key in the leaf.
			 */
			assert_corr(cur == leaf->il_entries);

		start = leaf->il_at;
		diff  = (void *)end - (void *)start;
		assert_corr(diff >= 0);
		memmove(iam_lfix_shift(leaf, start, 1), start, diff);
	}
	lentry_count_set(leaf, count + 1);
	iam_lfix_key_set(leaf, k);
	iam_lfix_rec_set(leaf, r);
	assert_corr(iam_leaf_at_rec(leaf));
}

static void iam_lfix_rec_del(struct iam_leaf *leaf, int shift)
{
	struct iam_lentry *next, *end;
	int count;
	ptrdiff_t diff;

	assert_corr(iam_leaf_at_rec(leaf));

	count = lentry_count_get(leaf);
	end = iam_lfix_get_end(leaf);
	next = iam_lfix_shift(leaf, leaf->il_at, 1);
	diff = (void *)end - (void *)next;
	memmove(leaf->il_at, next, diff);

	lentry_count_set(leaf, count - 1);
}

static int iam_lfix_can_add(const struct iam_leaf *l,
			    const struct iam_key *k, const struct iam_rec *r)
{
	return lentry_count_get(l) < leaf_count_limit(l);
}

static int iam_lfix_at_end(const struct iam_leaf *folio)
{
	return folio->il_at == iam_lfix_get_end(folio);
}

static void iam_lfix_init_new(struct iam_container *c, struct buffer_head *bh)
{
	struct iam_leaf_head *hdr;

	hdr = (struct iam_leaf_head *)bh->b_data;
	hdr->ill_magic = cpu_to_le16(IAM_LEAF_HEADER_MAGIC);
	hdr->ill_count = cpu_to_le16(0);
}

static void iam_lfix_split(struct iam_leaf *l, struct buffer_head **bh,
			   iam_ptr_t new_blknr)
{
	struct iam_path *path;
	struct iam_leaf_head *hdr;
	const struct iam_ikey *pivot;
	struct buffer_head *new_leaf;

	unsigned int count;
	unsigned int split;

	void *start;
	void *finis;

	new_leaf = *bh;
	path = iam_leaf_path(l);

	hdr = (void *)new_leaf->b_data;

	count = lentry_count_get(l);
	split = count / 2;

	start = iam_lfix_shift(l, iam_get_lentries(l), split);
	finis = iam_lfix_shift(l, iam_get_lentries(l), count);

	pivot = (const struct iam_ikey *)iam_leaf_key_at(start);

	memmove(iam_entries(new_leaf), start, finis - start);
	hdr->ill_count = cpu_to_le16(count - split);
	lentry_count_set(l, split);
	if ((void *)l->il_at >= start) {
		/*
		 * insertion point moves into new leaf.
		 */
		int shift;

		shift = iam_lfix_diff(l, l->il_at, start);
		*bh = l->il_bh;
		l->il_bh = new_leaf;
		l->il_curidx = new_blknr;
		iam_lfix_init(l);
		/*
		 * init cannot fail, as node was just initialized.
		 */
		assert_corr(result == 0);
		l->il_at = iam_lfix_shift(l, iam_get_lentries(l), shift);
	}
	/*
	 * Insert pointer to the new node (together with the least key in
	 * the node) into index node.
	 */
	iam_insert_key_lock(path, path->ip_frame, pivot, new_blknr);
}

static int iam_lfix_leaf_empty(struct iam_leaf *leaf)
{
	return lentry_count_get(leaf) == 0;
}

static const struct iam_leaf_operations iam_lfix_leaf_ops = {
	.init           = iam_lfix_init,
	.init_new       = iam_lfix_init_new,
	.fini           = iam_lfix_fini,
	.start          = iam_lfix_start,
	.next           = iam_lfix_next,
	.key            = iam_lfix_key,
	.ikey           = iam_lfix_ikey,
	.rec            = iam_lfix_rec,
	.key_set        = iam_lfix_key_set,
	.key_cmp        = iam_lfix_key_cmp,
	.key_eq         = iam_lfix_key_eq,
	.key_size       = iam_lfix_key_size,
	.rec_set        = iam_lfix_rec_set,
	.rec_eq         = iam_lfix_rec_eq,
	.rec_get        = iam_lfix_rec_get,
	.lookup         = iam_lfix_lookup,
	.ilookup        = iam_lfix_ilookup,
	.at_end         = iam_lfix_at_end,
	.rec_add        = iam_lfix_rec_add,
	.rec_del        = iam_lfix_rec_del,
	.can_add        = iam_lfix_can_add,
	.split          = iam_lfix_split,
	.leaf_empty     = iam_lfix_leaf_empty,
};

/*
 * Index operations.
 */

enum {
	/* This is duplicated in lustre/utils/create_iam.c */
	/*
	 * Then shalt thou see the dew-BEDABBLED wretch
	 * Turn, and return, indenting with the way;
	 * Each envious brier his weary legs doth scratch,
	 * Each shadow makes him stop, each murmur stay:
	 * For misery is trodden on by many,
	 * And being low never relieved by any.
	 */
	IAM_LFIX_ROOT_MAGIC = 0xbedabb1edULL /* d01efull */
};

/* This is duplicated in lustre/utils/create_iam.c */
struct iam_lfix_root {
	__le64  ilr_magic;
	__le16  ilr_keysize;
	__le16  ilr_recsize;
	__le16  ilr_ptrsize;
	u8      ilr_indirect_levels;
	u8      ilr_padding;
};

static __u32 iam_lfix_root_ptr(struct iam_container *c)
{
	return 0;
}

static int iam_lfix_node_init(struct iam_container *c, struct buffer_head *bh,
                              int root)
{
	return 0;
}

static struct iam_entry *iam_lfix_root_inc(struct iam_container *c,
					   struct iam_path *path,
					   struct iam_frame *frame)
{
	struct iam_lfix_root *root;
	struct iam_entry *entries;

	entries = frame->entries;

	dx_set_count(entries, 2);
	assert_corr(dx_get_limit(entries) == dx_root_limit(path));

	root = (void *)frame->bh->b_data;
	assert_corr(le64_to_cpu(root->ilr_magic) == IAM_LFIX_ROOT_MAGIC);
	root->ilr_indirect_levels++;
	frame->at = entries = iam_entry_shift(path, entries, 1);
	memset(iam_ikey_at(path, entries), 0,
	       iam_path_descr(path)->id_ikey_size);
	return entries;
}

static int iam_lfix_node_check(struct iam_path *path, struct iam_frame *frame)
{
	unsigned int count;
	unsigned int limit;
	unsigned int limit_correct;
	struct iam_entry *entries;

	entries = dx_node_get_entries(path, frame);

	if (frame == path->ip_frames) {
		struct iam_lfix_root *root;

		root = (void *)frame->bh->b_data;
		if (le64_to_cpu(root->ilr_magic) != IAM_LFIX_ROOT_MAGIC)
			return -EIO;
		limit_correct = dx_root_limit(path);
	} else {
		limit_correct = dx_node_limit(path);
	}
	count = dx_get_count(entries);
	limit = dx_get_limit(entries);
	if (count > limit)
		return -EIO;
	if (limit != limit_correct)
		return -EIO;
	return 0;
}

static int iam_lfix_node_load(struct iam_path *path, struct iam_frame *frame)
{
	struct iam_entry *entries;
	void *data;

	entries = dx_node_get_entries(path, frame);
	data = frame->bh->b_data;

	if (frame == path->ip_frames) {
		struct iam_lfix_root *root;

		root = data;
		path->ip_indirect = root->ilr_indirect_levels;
		if (path->ip_ikey_target == NULL)
			path->ip_ikey_target =
				(struct iam_ikey *)path->ip_key_target;
	}
	frame->entries = frame->at = entries;
	return 0;
}

static int iam_lfix_ikeycmp(const struct iam_container *c,
			    const struct iam_ikey *k1,
			    const struct iam_ikey *k2)
{
	return memcmp(k1, k2, c->ic_descr->id_ikey_size);
}

static struct iam_path_descr *iam_lfix_ipd_alloc(const struct iam_container *c,
						 void *area)
{
	return iam_ipd_alloc(area, c->ic_descr->id_ikey_size);
}

static const struct iam_operations iam_lfix_ops = {
	.id_root_ptr    = iam_lfix_root_ptr,
	.id_node_read   = iam_node_read,
	.id_node_init   = iam_lfix_node_init,
	.id_node_check  = iam_lfix_node_check,
	.id_node_load   = iam_lfix_node_load,
	.id_ikeycmp     = iam_lfix_ikeycmp,
	.id_root_inc    = iam_lfix_root_inc,
	.id_ipd_alloc   = iam_lfix_ipd_alloc,
	.id_ipd_free    = iam_ipd_free,
	.id_name        = "lfix"
};

int iam_lfix_guess(struct iam_container *c)
{
	int result;
	struct buffer_head *bh;
	const struct iam_lfix_root *root;

	assert_corr(c->ic_object != NULL);

	result = iam_node_read(c, iam_lfix_root_ptr(c), NULL, &bh);
	if (result == 0) {
		root = (void *)bh->b_data;
		if (le64_to_cpu(root->ilr_magic) == IAM_LFIX_ROOT_MAGIC) {
			struct iam_descr *descr;

			descr = c->ic_descr;
			descr->id_key_size  = le16_to_cpu(root->ilr_keysize);
			descr->id_ikey_size = le16_to_cpu(root->ilr_keysize);
			descr->id_rec_size  = le16_to_cpu(root->ilr_recsize);
			descr->id_ptr_size  = le16_to_cpu(root->ilr_ptrsize);
			descr->id_root_gap  = sizeof(struct iam_lfix_root);
			descr->id_node_gap  = 0;
			descr->id_ops       = &iam_lfix_ops;
			descr->id_leaf_ops  = &iam_lfix_leaf_ops;
			c->ic_root_bh = bh;
		} else {
			result = -EBADF;
			brelse(bh);
		}
	}
	return result;
}

/*
 * Debugging aid.
 */

#define KEYSIZE (8)
#define RECSIZE (8)
#define PTRSIZE (4)

#define LFIX_ROOT_RECNO \
        ((4096 - sizeof(struct iam_lfix_root)) / (KEYSIZE + PTRSIZE))

#define LFIX_INDEX_RECNO (4096 / (KEYSIZE + PTRSIZE))

#define LFIX_LEAF_RECNO \
        ((4096 - sizeof(struct iam_leaf_head)) / (KEYSIZE + RECSIZE))

	struct lfix_root {
	struct iam_lfix_root lr_root;
	struct {
		char key[KEYSIZE];
		char ptr[PTRSIZE];
	} lr_entry[LFIX_ROOT_RECNO];
};

	struct lfix_index {
	struct dx_countlimit li_cl;
	char   li_padding[KEYSIZE + PTRSIZE - sizeof(struct dx_countlimit)];
	struct {
		char key[KEYSIZE];
		char ptr[PTRSIZE];
	} li_entry[LFIX_INDEX_RECNO - 1];
};

	struct lfix_leaf {
		struct iam_leaf_head ll_head;
		struct {
			char key[KEYSIZE];
			char rec[RECSIZE];
		} ll_entry[LFIX_LEAF_RECNO];
	};

#define STORE_UNALIGNED(val, dst)			\
({							\
	typeof(val) __val = (val);			\
	BUILD_BUG_ON(sizeof(val) != sizeof(*(dst)));	\
	memcpy(dst, &__val, sizeof(*(dst)));		\
})

static void lfix_root(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct iam_lfix_root *root;
	struct dx_countlimit *limit;
	void *entry;

	root = buf;
	*root = (typeof(*root)) {
		.ilr_magic           = cpu_to_le64(IAM_LFIX_ROOT_MAGIC),
		.ilr_keysize         = cpu_to_le16(keysize),
		.ilr_recsize         = cpu_to_le16(recsize),
		.ilr_ptrsize         = cpu_to_le16(ptrsize),
		.ilr_indirect_levels = 0
	};

	limit = (void *)(root + 1);
	*limit = (typeof(*limit)){
		/*
		 * limit itself + one pointer to the leaf.
		 */
		.count = cpu_to_le16(2),
		.limit = iam_root_limit(sizeof(struct iam_lfix_root),
					blocksize, keysize + ptrsize)
	};

	/* To guarantee that the padding "keysize + ptrsize"
	 * covers the "dx_countlimit" and the "idle_blocks". */
	LASSERT((keysize + ptrsize) >=
		(sizeof(struct dx_countlimit) + sizeof(__u32)));

	entry = (void *)(limit + 1);
	/* Put "idle_blocks" just after the limit. There was padding after
	 * the limit, the "idle_blocks" re-uses part of the padding, so no
	 * compatibility issues with old layout.
	 */
	*(__u32 *)entry = 0;

	/*
	 * Skip over @limit.
	 */
	entry = (void *)(root + 1) + keysize + ptrsize;

	/*
	 * Entry format is <key> followed by <ptr>. In the minimal tree
	 * consisting of a root and single node, <key> is a minimal possible
	 * key.
	 *
	 * XXX: this key is hard-coded to be a sequence of 0's.
	 */

	memset(entry, 0, keysize);
	entry += keysize;
	/* now @entry points to <ptr> */
	if (ptrsize == 4)
		STORE_UNALIGNED(cpu_to_le32(1), (u_int32_t *)entry);
	else
		STORE_UNALIGNED(cpu_to_le64(1), (u_int64_t *)entry);
}

static void lfix_leaf(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct iam_leaf_head *head;
	void *entry;

	/* form leaf */
	head = buf;
	*head = (struct iam_leaf_head) {
		.ill_magic = cpu_to_le16(IAM_LEAF_HEADER_MAGIC),
		/*
		 * Leaf contains an entry with the smallest possible key
		 * (created by zeroing).
		 */
		.ill_count = cpu_to_le16(1),
	};

	entry = (void *)(head + 1);
	memset(entry, 0, keysize + recsize);
}

int iam_lfix_create(struct inode *obj,
		    int keysize, int ptrsize, int recsize, handle_t *handle)
{
	struct buffer_head *root_node;
	struct buffer_head *leaf_node;
	struct super_block *sb;
	u32 blknr;
	int result = 0;
	unsigned long bsize;

	assert_corr(obj->i_size == 0);

	sb = obj->i_sb;
	bsize = sb->s_blocksize;
	root_node = osd_ldiskfs_append(handle, obj, &blknr);
	if (IS_ERR(root_node))
		GOTO(out, result = PTR_ERR(root_node));

	leaf_node = osd_ldiskfs_append(handle, obj, &blknr);
	if (IS_ERR(leaf_node))
		GOTO(out_root, result = PTR_ERR(leaf_node));

	lfix_root(root_node->b_data, bsize, keysize, ptrsize, recsize);
	lfix_leaf(leaf_node->b_data, bsize, keysize, ptrsize, recsize);
	ldiskfs_mark_inode_dirty(handle, obj);
	result = ldiskfs_handle_dirty_metadata(handle, NULL, root_node);
	if (result == 0)
		result = ldiskfs_handle_dirty_metadata(handle, NULL, leaf_node);
	if (result != 0)
		ldiskfs_std_error(sb, result);

	brelse(leaf_node);

	GOTO(out_root, result);

out_root:
	brelse(root_node);
out:
	return result;
}
