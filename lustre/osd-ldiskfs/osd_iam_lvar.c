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
 * iam_lvar.c
 *
 * implementation of iam format for fixed size records, variable sized keys.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#include <linux/types.h>
#include "osd_internal.h"

/*
 * Leaf operations.
 */

enum {
	/* This is duplicated in lustre/utils/create_iam.c */
	IAM_LVAR_LEAF_MAGIC = 0x1973
};

/* This is duplicated in lustre/utils/create_iam.c */
struct lvar_leaf_header {
	__le16 vlh_magic; /* magic number IAM_LVAR_LEAF_MAGIC */
	__le16 vlh_used;  /* used bytes, including header */
};

/*
 * Format of leaf entry:
 *
 * __le16 keysize
 *     u8 key[keysize]
 *     u8 record[rec_size]
 *
 * Entries are ordered in key order.
 */

/* This is duplicated in lustre/utils/create_iam.c */
typedef u32 lvar_hash_t;

/* This is duplicated in lustre/utils/create_iam.c */
struct lvar_leaf_entry {
	__le32 vle_hash;
	__le16 vle_keysize;
	u8 vle_key[0];
};

#define PDIFF(ptr0, ptr1) (((char *)(ptr0)) - ((char *)(ptr1)))


static inline int blocksize(const struct iam_leaf *leaf)
{
	return iam_leaf_container(leaf)->ic_object->i_sb->s_blocksize;
}

static inline const char *kchar(const struct iam_key *key)
{
	return (void *)key;
}

static inline struct iam_lentry *lvar_lentry(const struct lvar_leaf_entry *ent)
{
	return (struct iam_lentry *)ent;
}

static inline struct lvar_leaf_entry *lentry_lvar(const struct iam_lentry *lent)
{
	return (struct lvar_leaf_entry *)lent;
}


static inline int e_keysize(const struct lvar_leaf_entry *ent)
{
	return le16_to_cpu(ent->vle_keysize);
}

/* This is duplicated in lustre/utils/create_iam.c */
enum {
	LVAR_PAD   = 4,
	LVAR_ROUND = LVAR_PAD - 1
};

static inline int getsize(const struct iam_leaf *leaf, int namelen, int recsize)
{
	BUILD_BUG_ON((LVAR_PAD & (LVAR_PAD - 1)));

	return (offsetof(struct lvar_leaf_entry, vle_key) +
			namelen + recsize + LVAR_ROUND) & ~LVAR_ROUND;
}

static inline int rec_size(const struct iam_rec *rec)
{
	return *(const char *)rec;
}

static inline struct iam_rec *e_rec(const struct lvar_leaf_entry *ent)
{
	return ((void *)ent) +
		offsetof(struct lvar_leaf_entry, vle_key) + e_keysize(ent);
}

static inline int e_size(const struct iam_leaf *leaf,
			 const struct lvar_leaf_entry *ent)
{
	return getsize(leaf, e_keysize(ent), rec_size(e_rec(ent)));
}

static inline char *e_char(const struct lvar_leaf_entry *ent)
{
	return (char *)&ent->vle_key;
}

static inline struct iam_key *e_key(const struct lvar_leaf_entry *ent)
{
	return (struct iam_key *)e_char(ent);
}

static inline lvar_hash_t e_hash(const struct lvar_leaf_entry *ent)
{
	return le32_to_cpu(ent->vle_hash);
}

static void e_print(const struct lvar_leaf_entry *ent)
{
	CERROR("        %p %8.8x \"%*.*s\"\n", ent, e_hash(ent),
			e_keysize(ent), e_keysize(ent), e_char(ent));
}

static inline struct lvar_leaf_entry *e_next(const struct iam_leaf *leaf,
					     const struct lvar_leaf_entry *ent)
{
	return ((void *)ent) + e_size(leaf, ent);
}

#define LVAR_HASH_SANDWICH  (0)
#define LVAR_HASH_TEA       (1)
#define LVAR_HASH_R5        (0)
#define LVAR_HASH_PREFIX    (0)

#ifdef HAVE_LDISKFSFS_GETHASH_INODE_ARG
/*
 * NOTE: doing this breaks on file systems configured with
 *       case-insensitive file name lookups
 *
 * kernel 5.2 commit b886ee3e778ec2ad43e276fd378ab492cf6819b7
 * ext4: Support case-insensitive file name lookups
 *
 * FUTURE:
 *  We need to pass the struct inode *dir down to hash_build0
 *  to enable case-insensitive file name support ext4/ldiskfs
 */
#define e_ldiskfsfs_dirhash(name, len, info) \
		__ldiskfsfs_dirhash(name, len, info)
#else
#define e_ldiskfsfs_dirhash(name, len, info) \
		ldiskfsfs_dirhash(name, len, info)
#endif

static u32 hash_build0(const char *name, int namelen)
{
	u32 result;

	if (namelen == 0)
		return 0;
	if (strncmp(name, ".", 1) == 0 && namelen == 1)
		return 1;
	if (strncmp(name, "..", 2) == 0 && namelen == 2)
		return 2;

	if (LVAR_HASH_PREFIX) {
		result = 0;
		strncpy((void *)&result,
			name, min_t(int, namelen, sizeof(result)));
	} else {
		struct ldiskfs_dx_hash_info hinfo;

		hinfo.hash_version = LDISKFS_DX_HASH_TEA;
		hinfo.seed = NULL;
		e_ldiskfsfs_dirhash(name, namelen, &hinfo);
		result = hinfo.hash;
		if (LVAR_HASH_SANDWICH) {
			u32 result2;

			hinfo.hash_version = LDISKFS_DX_HASH_TEA;
			hinfo.seed = NULL;
			e_ldiskfsfs_dirhash(name, namelen, &hinfo);
			result2 = hinfo.hash;
			result = (0xfc000000 & result2) | (0x03ffffff & result);
		}
	}
	return result;
}

enum {
	HASH_GRAY_AREA = 1024,
	HASH_MAX_SIZE  = 0x7fffffffUL
};

static u32 hash_build(const char *name, int namelen)
{
	u32 hash;

	hash = (hash_build0(name, namelen) << 1) & HASH_MAX_SIZE;
	if (hash > HASH_MAX_SIZE - HASH_GRAY_AREA)
		hash &= HASH_GRAY_AREA - 1;
	return hash;
}

static inline lvar_hash_t get_hash(const struct iam_container *bag,
				   const char *name, int namelen)
{
	return hash_build(name, namelen);
}

static inline int e_eq(const struct lvar_leaf_entry *ent,
		       const char *name, int namelen)
{
	return namelen == e_keysize(ent) && !memcmp(e_char(ent), name, namelen);
}

static inline int e_cmp(const struct iam_leaf *leaf,
			const struct lvar_leaf_entry *ent, lvar_hash_t hash)
{
	lvar_hash_t ehash;

	ehash = e_hash(ent);
	return ehash == hash ? 0 : (ehash < hash ? -1 : 1);
}

static struct lvar_leaf_header *n_head(const struct iam_leaf *l)
{
	return (struct lvar_leaf_header *)l->il_bh->b_data;
}

static int h_used(const struct lvar_leaf_header *hdr)
{
	return le16_to_cpu(hdr->vlh_used);
}

static void h_used_adj(const struct iam_leaf *leaf,
		       struct lvar_leaf_header *hdr, int adj)
{
	int used;

	used = h_used(hdr) + adj;
	assert_corr(sizeof(*hdr) <= used && used <= blocksize(leaf));
	hdr->vlh_used = cpu_to_le16(used);
}

static struct lvar_leaf_entry *n_start(const struct iam_leaf *leaf)
{
	return (void *)leaf->il_bh->b_data + sizeof(struct lvar_leaf_header);
}

static struct lvar_leaf_entry *n_end(const struct iam_leaf *l)
{
	return (void *)l->il_bh->b_data + h_used(n_head(l));
}

static struct lvar_leaf_entry *n_cur(const struct iam_leaf *l)
{
	return lentry_lvar(l->il_at);
}

void n_print(const struct iam_leaf *l)
{
	struct lvar_leaf_entry *scan;

	CERROR("used: %d\n", h_used(n_head(l)));
	for (scan = n_start(l); scan < n_end(l); scan = e_next(l, scan))
		e_print(scan);
}

#if LDISKFS_CORRECTNESS_ON
static int n_at_rec(const struct iam_leaf *folio)
{
	return n_start(folio) <= lentry_lvar(folio->il_at) &&
		lentry_lvar(folio->il_at) < n_end(folio);
}

#if LDISKFS_INVARIANT_ON
static int n_invariant(const struct iam_leaf *leaf)
{
	struct iam_path *path;
	struct lvar_leaf_entry *scan;
	struct lvar_leaf_entry *end;
	lvar_hash_t hash;
	lvar_hash_t nexthash;
	lvar_hash_t starthash;

	end  = n_end(leaf);
	hash = 0;
	path = leaf->il_path;

	if (h_used(n_head(leaf)) > blocksize(leaf))
		return 0;

	/*
	 * Delimiting key in the parent index node. Clear least bit to account
	 * for hash collision marker.
	 */
	starthash = *(lvar_hash_t *)iam_ikey_at(path, path->ip_frame->at) & ~1;
	for (scan = n_start(leaf); scan < end; scan = e_next(leaf, scan)) {
		nexthash = e_hash(scan);
		if (nexthash != get_hash(iam_leaf_container(leaf),
					e_char(scan), e_keysize(scan))) {
			BREAKPOINT();
			return 0;
		}
		if (0 && nexthash < starthash) {
			/*
			 * Unfortunately this useful invariant cannot be
			 * reliably checked as parent node is not necessarily
			 * locked.
			 */
			n_print(leaf);
			CERROR("%#x < %#x\n", nexthash, starthash);
			dump_stack();
			return 0;
		}
		if (nexthash < hash) {
			BREAKPOINT();
			return 0;
		}
		hash = nexthash;
	}
	if (scan != end) {
		BREAKPOINT();
		return 0;
	}
	return 1;
}
/* LDISKFS_INVARIANT_ON */
#endif

/* LDISKFS_CORRECTNESS_ON */
#endif

static struct iam_ikey *lvar_ikey(const struct iam_leaf *l,
				  struct iam_ikey *key)
{
	lvar_hash_t *hash;

	assert_corr(n_at_rec(l));

	hash = (void *)key;
	*hash = e_hash(n_cur(l));
	return key;
}

static struct iam_key *lvar_key(const struct iam_leaf *l)
{
	return e_key(n_cur(l));
}

static int lvar_key_size(const struct iam_leaf *l)
{
	return e_keysize(n_cur(l));
}

static void lvar_start(struct iam_leaf *l)
{
	l->il_at = lvar_lentry(n_start(l));
}

static int lvar_init(struct iam_leaf *l)
{
	int result;
	int used;
	struct lvar_leaf_header *head;

	assert_corr(l->il_bh != NULL);

	head = n_head(l);
	used = h_used(head);
	if (le16_to_cpu(head->vlh_magic) == IAM_LVAR_LEAF_MAGIC &&
			used <= blocksize(l)) {
		l->il_at = l->il_entries = lvar_lentry(n_start(l));
		result = 0;
	} else {
		struct inode *obj;

		obj = iam_leaf_container(l)->ic_object;
		CERROR(
		"Bad magic in node %llu (#%lu): %#x != %#x or wrong used: %d\n",
		(unsigned long long)l->il_bh->b_blocknr, obj->i_ino,
		le16_to_cpu(head->vlh_magic), IAM_LVAR_LEAF_MAGIC,
		used);
		result = -EIO;
	}
	return result;
}

static void lvar_fini(struct iam_leaf *l)
{
	l->il_entries = l->il_at = NULL;
}

static struct iam_rec *lvar_rec(const struct iam_leaf *l)
{
	assert_corr(n_at_rec(l));
	return e_rec(n_cur(l));
}

static void lvar_next(struct iam_leaf *l)
{
	assert_corr(n_at_rec(l));
	assert_corr(iam_leaf_is_locked(l));
	l->il_at = lvar_lentry(e_next(l, n_cur(l)));
}

static int lvar_lookup(struct iam_leaf *leaf, const struct iam_key *k)
{
	struct lvar_leaf_entry *found;
	struct lvar_leaf_entry *scan;
	struct lvar_leaf_entry *end;
	int result;
	const char *name;
	int namelen;
	int found_equal;
	lvar_hash_t hash;
	int last;

	assert_inv(n_invariant(leaf));
	end = n_end(leaf);

	name = kchar(k);
	namelen = strlen(name);
	hash = get_hash(iam_leaf_container(leaf), name, namelen);
	found = NULL;
	found_equal = 0;
	last = 1;

	for (scan = n_start(leaf); scan < end; scan = e_next(leaf, scan)) {
		lvar_hash_t scan_hash;

		scan_hash = e_hash(scan);
		if (scan_hash < hash)
			found = scan;
		else if (scan_hash == hash) {
			if (e_eq(scan, name, namelen)) {
				/*
				 * perfect match
				 */
				leaf->il_at = lvar_lentry(scan);
				return IAM_LOOKUP_EXACT;
			} else if (!found_equal) {
				found = scan;
				found_equal = 1;
			}
		} else {
			last = 0;
			break;
		}
	}
	if (found == NULL) {
		/*
		 * @k is less than all hashes in the leaf.
		 */
		lvar_start(leaf);
		result = IAM_LOOKUP_BEFORE;
	} else {
		leaf->il_at = lvar_lentry(found);
		result = IAM_LOOKUP_OK;
		assert_corr(n_at_rec(leaf));
	}
	if (last)
		result |= IAM_LOOKUP_LAST;
	assert_inv(n_invariant(leaf));

	return result;
}

static int lvar_ilookup(struct iam_leaf *leaf, const struct iam_ikey *ik)
{
	struct lvar_leaf_entry *scan;
	struct lvar_leaf_entry *end;
	lvar_hash_t hash;

	assert_inv(n_invariant(leaf));
	end  = n_end(leaf);
	hash = *(const lvar_hash_t *)ik;

	lvar_start(leaf);
	for (scan = n_start(leaf); scan < end; scan = e_next(leaf, scan)) {
		lvar_hash_t scan_hash;

		scan_hash = e_hash(scan);
		if (scan_hash > hash)
			return scan == n_start(leaf) ?
				IAM_LOOKUP_BEFORE : IAM_LOOKUP_OK;
		leaf->il_at = lvar_lentry(scan);
		if (scan_hash == hash)
			return IAM_LOOKUP_EXACT;
	}
	assert_inv(n_invariant(leaf));
	/*
	 * @ik is greater than any key in the node. Return last record in the
	 * node.
	 */
	return IAM_LOOKUP_OK;
}

static void __lvar_key_set(struct iam_leaf *l, const struct iam_key *k)
{
	memcpy(e_key(n_cur(l)), k, e_keysize(n_cur(l)));
}

static void lvar_key_set(struct iam_leaf *l, const struct iam_key *k)
{
	assert_corr(n_at_rec(l));
	assert_corr(strlen(kchar(k)) == e_keysize(n_cur(l)));
	assert_corr(iam_leaf_is_locked(l));
	__lvar_key_set(l, k);
	assert_inv(n_invariant(l));
}

static int lvar_key_cmp(const struct iam_leaf *l, const struct iam_key *k)
{
	lvar_hash_t hash;
	const char *name;

	name = kchar(k);

	hash = get_hash(iam_leaf_container(l), name, strlen(name));
	return e_cmp(l, n_cur(l), hash);
}

static int lvar_key_eq(const struct iam_leaf *l, const struct iam_key *k)
{
	const char *name;

	name = kchar(k);
	return e_eq(n_cur(l), name, strlen(name));
}

static void __lvar_rec_set(struct iam_leaf *l, const struct iam_rec *r)
{
	memcpy(e_rec(n_cur(l)), r, rec_size(r));
}

static void lvar_rec_set(struct iam_leaf *l, const struct iam_rec *r)
{
	assert_corr(n_at_rec(l));
	assert_corr(iam_leaf_is_locked(l));
	__lvar_rec_set(l, r);
	assert_inv(n_invariant(l));
}

static int lvar_rec_eq(const struct iam_leaf *l, const struct iam_rec *r)
{
	struct iam_rec *rec = e_rec(n_cur(l));

	if (rec_size(rec) != rec_size(r))
		return 0;
	return !memcmp(rec, r, rec_size(r));
}

static void lvar_rec_get(const struct iam_leaf *l, struct iam_rec *r)
{
	struct iam_rec *rec;

	rec = e_rec(n_cur(l));
	assert_corr(n_at_rec(l));
	assert_corr(iam_leaf_is_locked(l));
	memcpy(r, rec, rec_size(rec));
	assert_inv(n_invariant(l));
}

static int lvar_can_add(const struct iam_leaf *l,
			const struct iam_key *k, const struct iam_rec *r)
{
	assert_corr(iam_leaf_is_locked(l));
	return h_used(n_head(l)) +
		getsize(l, strlen(kchar(k)), rec_size(r)) <= blocksize(l);
}

static int lvar_at_end(const struct iam_leaf *folio)
{
	assert_corr(iam_leaf_is_locked(folio));
	return n_cur(folio) == n_end(folio);
}

static void lvar_rec_add(struct iam_leaf *leaf,
			 const struct iam_key *k, const struct iam_rec *r)
{
	const char *key;
	int ksize;
	int shift;
	void *end;
	void *start;
	ptrdiff_t diff;

	assert_corr(lvar_can_add(leaf, k, r));
	assert_inv(n_invariant(leaf));
	assert_corr(iam_leaf_is_locked(leaf));

	key   = kchar(k);
	ksize = strlen(key);
	shift = getsize(leaf, ksize, rec_size(r));

	if (!lvar_at_end(leaf)) {
		assert_corr(n_cur(leaf) < n_end(leaf));
		end = n_end(leaf);
		if (lvar_key_cmp(leaf, k) <= 0)
			lvar_next(leaf);
		else
			/*
			 * Another exceptional case: insertion with the key
			 * less than least key in the leaf.
			 */
			assert_corr(leaf->il_at == leaf->il_entries);

		start = leaf->il_at;
		diff  = PDIFF(end, start);
		assert_corr(diff >= 0);
		memmove(start + shift, start, diff);
	}
	h_used_adj(leaf, n_head(leaf), shift);
	n_cur(leaf)->vle_keysize = cpu_to_le16(ksize);
	n_cur(leaf)->vle_hash = cpu_to_le32(get_hash(iam_leaf_container(leaf),
					    key, ksize));
	__lvar_key_set(leaf, k);
	__lvar_rec_set(leaf, r);
	assert_corr(n_at_rec(leaf));
	assert_inv(n_invariant(leaf));
}

static void lvar_rec_del(struct iam_leaf *leaf, int shift)
{
	void *next;
	void *end;
	int nob;

	assert_corr(n_at_rec(leaf));
	assert_inv(n_invariant(leaf));
	assert_corr(iam_leaf_is_locked(leaf));

	end  = n_end(leaf);
	next = e_next(leaf, n_cur(leaf));
	nob  = e_size(leaf, n_cur(leaf));
	memmove(leaf->il_at, next, end - next);
	h_used_adj(leaf, n_head(leaf), -nob);
	assert_inv(n_invariant(leaf));
}

static void lvar_init_new(struct iam_container *c, struct buffer_head *bh)
{
	struct lvar_leaf_header *hdr;

	hdr = (struct lvar_leaf_header *)bh->b_data;
	hdr->vlh_magic = cpu_to_le16(IAM_LVAR_LEAF_MAGIC);
	hdr->vlh_used  = sizeof(*hdr);
}

static struct lvar_leaf_entry *find_pivot(const struct iam_leaf *leaf,
					  struct lvar_leaf_entry **prev)
{
	void *scan;
	void *start;
	int threshold;

	*prev = NULL;
	threshold = blocksize(leaf) / 2;
	for (scan = start = n_start(leaf); scan - start <= threshold;
			*prev = scan, scan = e_next(leaf, scan)) {
		;
	}
	return scan;
}

static void lvar_split(struct iam_leaf *leaf, struct buffer_head **bh,
		       iam_ptr_t new_blknr)
{
	struct lvar_leaf_entry *first_to_move;
	struct lvar_leaf_entry *last_to_stay;
	struct iam_path *path;
	struct lvar_leaf_header *hdr;
	struct buffer_head *new_leaf;
	ptrdiff_t tomove;
	lvar_hash_t hash;

	assert_inv(n_invariant(leaf));
	assert_corr(iam_leaf_is_locked(leaf));

	new_leaf = *bh;
	path = iam_leaf_path(leaf);

	hdr = (void *)new_leaf->b_data;

	first_to_move = find_pivot(leaf, &last_to_stay);
	assert_corr(last_to_stay != NULL);
	assert_corr(e_next(leaf, last_to_stay) == first_to_move);

	hash = e_hash(first_to_move);
	if (hash == e_hash(last_to_stay))
		/*
		 * Duplicate hash.
		 */
		hash |= 1;

	tomove = PDIFF(n_end(leaf), first_to_move);
	memmove(hdr + 1, first_to_move, tomove);

	h_used_adj(leaf, hdr, tomove);
	h_used_adj(leaf, n_head(leaf), -tomove);

	assert_corr(n_end(leaf) == first_to_move);

	if (n_cur(leaf) >= first_to_move) {
		/*
		 * insertion point moves into new leaf.
		 */
		ptrdiff_t shift;

		shift = PDIFF(leaf->il_at, first_to_move);
		*bh = leaf->il_bh;
		leaf->il_bh = new_leaf;
		leaf->il_curidx = new_blknr;

		assert_corr(iam_leaf_is_locked(leaf));
		lvar_init(leaf);
		/*
		 * init cannot fail, as node was just initialized.
		 */
		assert_corr(result == 0);
		leaf->il_at = ((void *)leaf->il_at) + shift;
	}
	/*
	 * Insert pointer to the new node (together with the least key in
	 * the node) into index node.
	 */
	iam_insert_key_lock(path, path->ip_frame, (struct iam_ikey *)&hash,
			    new_blknr);
	assert_corr(n_cur(leaf) < n_end(leaf));
	assert_inv(n_invariant(leaf));
}

static int lvar_leaf_empty(struct iam_leaf *leaf)
{
	return h_used(n_head(leaf)) == sizeof(struct lvar_leaf_header);
}

static const struct iam_leaf_operations lvar_leaf_ops = {
	.init           = lvar_init,
	.init_new       = lvar_init_new,
	.fini           = lvar_fini,
	.start          = lvar_start,
	.next           = lvar_next,
	.key            = lvar_key,
	.ikey           = lvar_ikey,
	.rec            = lvar_rec,
	.key_set        = lvar_key_set,
	.key_cmp        = lvar_key_cmp,
	.key_eq         = lvar_key_eq,
	.key_size       = lvar_key_size,
	.rec_set        = lvar_rec_set,
	.rec_eq         = lvar_rec_eq,
	.rec_get        = lvar_rec_get,
	.lookup         = lvar_lookup,
	.ilookup        = lvar_ilookup,
	.at_end         = lvar_at_end,
	.rec_add        = lvar_rec_add,
	.rec_del        = lvar_rec_del,
	.can_add        = lvar_can_add,
	.split          = lvar_split,
	.leaf_empty     = lvar_leaf_empty,
};

/*
 * Index operations.
 */

enum {
	/* This is duplicated in lustre/utils/create_iam.c */
	/* egrep -i '^o?x?[olabcdef]*$' /usr/share/dict/words */
	IAM_LVAR_ROOT_MAGIC = 0xb01dface
};

/* This is duplicated in lustre/utils/create_iam.c */
struct lvar_root {
	__le32 vr_magic;
	__le16 vr_recsize;
	__le16 vr_ptrsize;
	u8 vr_indirect_levels;
	u8 vr_padding0;
	__le16 vr_padding1;
};

static u32 lvar_root_ptr(struct iam_container *c)
{
	return 0;
}

static int lvar_node_init(struct iam_container *c, struct buffer_head *bh,
			  int root)
{
	return 0;
}

static struct iam_entry *lvar_root_inc(struct iam_container *c,
				       struct iam_path *path,
				       struct iam_frame *frame)
{
	struct lvar_root *root;
	struct iam_entry *entries;

	assert_corr(iam_frame_is_locked(path, frame));
	entries = frame->entries;

	dx_set_count(entries, 2);
	assert_corr(dx_get_limit(entries) == dx_root_limit(path));

	root = (void *)frame->bh->b_data;
	assert_corr(le64_to_cpu(root->vr_magic) == IAM_LVAR_ROOT_MAGIC);
	root->vr_indirect_levels++;
	frame->at = entries = iam_entry_shift(path, entries, 1);
	memset(iam_ikey_at(path, entries), 0,
	       iam_path_descr(path)->id_ikey_size);
	return entries;
}

static int lvar_node_check(struct iam_path *path, struct iam_frame *frame)
{
	unsigned int count;
	unsigned int limit;
	unsigned int limit_correct;
	struct iam_entry *entries;

	entries = dx_node_get_entries(path, frame);

	if (frame == path->ip_frames) {
		struct lvar_root *root;

		root = (void *)frame->bh->b_data;
		if (le32_to_cpu(root->vr_magic) != IAM_LVAR_ROOT_MAGIC)
			return -EIO;
		limit_correct = dx_root_limit(path);
	} else
		limit_correct = dx_node_limit(path);
	count = dx_get_count(entries);
	limit = dx_get_limit(entries);
	if (count > limit)
		return -EIO;
	if (limit != limit_correct)
		return -EIO;
	return 0;
}

static int lvar_node_load(struct iam_path *path, struct iam_frame *frame)
{
	struct iam_entry *entries;
	void *data;

	entries = dx_node_get_entries(path, frame);
	data = frame->bh->b_data;

	if (frame == path->ip_frames) {
		struct lvar_root *root;
		const char *name;

		root = data;
		name = kchar(path->ip_key_target);
		path->ip_indirect = root->vr_indirect_levels;
		if (path->ip_ikey_target == NULL) {
			path->ip_ikey_target = iam_path_ikey(path, 4);
			*(lvar_hash_t *)path->ip_ikey_target =
				get_hash(path->ip_container, name,
					 strlen(name));
		}
	}
	frame->entries = frame->at = entries;
	return 0;
}

static int lvar_ikeycmp(const struct iam_container *c,
			const struct iam_ikey *k1, const struct iam_ikey *k2)
{
	lvar_hash_t p1 = le32_to_cpu(*(lvar_hash_t *)k1);
	lvar_hash_t p2 = le32_to_cpu(*(lvar_hash_t *)k2);

	return p1 > p2 ? 1 : (p1 < p2 ? -1 : 0);
}

static struct iam_path_descr *lvar_ipd_alloc(const struct iam_container *c,
					     void *area)
{
	return iam_ipd_alloc(area, c->ic_descr->id_ikey_size);
}

static void lvar_root(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct lvar_root *root;
	struct dx_countlimit *limit;
	void *entry;
	int isize;

	isize = sizeof(lvar_hash_t) + ptrsize;
	root = buf;
	*root = (typeof(*root)) {
		.vr_magic            = cpu_to_le32(IAM_LVAR_ROOT_MAGIC),
		.vr_recsize          = cpu_to_le16(recsize),
		.vr_ptrsize          = cpu_to_le16(ptrsize),
		.vr_indirect_levels  = 0
	};

	limit = (void *)(root + 1);
	*limit = (typeof(*limit)){
		/*
		 * limit itself + one pointer to the leaf.
		 */
		.count = cpu_to_le16(2),
		.limit = iam_root_limit(sizeof(struct lvar_root), blocksize,
					sizeof(lvar_hash_t) + ptrsize)
	};

	/* To guarantee that the padding "keysize + ptrsize"
	 * covers the "dx_countlimit" and the "idle_blocks". */
	LASSERT((keysize + ptrsize) >=
		(sizeof(struct dx_countlimit) + sizeof(u32)));

	entry = (void *)(limit + 1);
	/* Put "idle_blocks" just after the limit. There was padding after
	 * the limit, the "idle_blocks" re-uses part of the padding, so no
	 * compatibility issues with old layout.
	 */
	*(u32 *)entry = 0;

	/*
	 * Skip over @limit.
	 */
	entry = (void *)(root + 1) + isize;

	/*
	 * Entry format is <key> followed by <ptr>. In the minimal tree
	 * consisting of a root and single node, <key> is a minimal possible
	 * key.
	 */
	*(lvar_hash_t *)entry = 0;
	entry += sizeof(lvar_hash_t);
	/* now @entry points to <ptr> */
	if (ptrsize == 4)
		*(u_int32_t *)entry = cpu_to_le32(1);
	else
		*(u_int64_t *)entry = cpu_to_le64(1);
}

static int lvar_esize(int namelen, int recsize)
{
	return (offsetof(struct lvar_leaf_entry, vle_key) +
			namelen + recsize + LVAR_ROUND) & ~LVAR_ROUND;
}

static void lvar_leaf(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct lvar_leaf_header *head;
	struct lvar_leaf_entry *entry;

	/* form leaf */
	head = buf;
	*head = (typeof(*head)) {
		.vlh_magic = cpu_to_le16(IAM_LVAR_LEAF_MAGIC),
		.vlh_used  = cpu_to_le16(sizeof(*head) + lvar_esize(0, recsize))
	};
	entry = (void *)(head + 1);
	*entry = (typeof(*entry)) {
		.vle_hash    = 0,
		.vle_keysize = 0
	};
	memset(e_rec(entry), 0, recsize);
	*(char *)e_rec(entry) = recsize;
}

int iam_lvar_create(struct inode *obj,
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

	lvar_root(root_node->b_data, bsize, keysize, ptrsize, recsize);
	lvar_leaf(leaf_node->b_data, bsize, keysize, ptrsize, recsize);
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

static const struct iam_operations lvar_ops = {
	.id_root_ptr    = lvar_root_ptr,
	.id_node_read   = iam_node_read,
	.id_node_init   = lvar_node_init,
	.id_node_check  = lvar_node_check,
	.id_node_load   = lvar_node_load,
	.id_ikeycmp     = lvar_ikeycmp,
	.id_root_inc    = lvar_root_inc,
	.id_ipd_alloc   = lvar_ipd_alloc,
	.id_ipd_free    = iam_ipd_free,
	.id_name        = "lvar"
};

int iam_lvar_guess(struct iam_container *c)
{
	int result;
	struct buffer_head *bh;
	const struct lvar_root *root;

	assert_corr(c->ic_object != NULL);

	result = iam_node_read(c, lvar_root_ptr(c), NULL, &bh);
	if (result == 0) {
		root = (void *)bh->b_data;

		if (le32_to_cpu(root->vr_magic) == IAM_LVAR_ROOT_MAGIC) {
			struct iam_descr *descr;

			descr = c->ic_descr;
			descr->id_key_size  = LDISKFS_NAME_LEN;
			descr->id_ikey_size = sizeof(lvar_hash_t);
			descr->id_rec_size  = le16_to_cpu(root->vr_recsize);
			descr->id_ptr_size  = le16_to_cpu(root->vr_ptrsize);
			descr->id_root_gap  = sizeof(*root);
			descr->id_node_gap  = 0;
			descr->id_ops       = &lvar_ops;
			descr->id_leaf_ops  = &lvar_leaf_ops;
			c->ic_root_bh = bh;
		} else {
			result = -EBADF;
			brelse(bh);
		}
	}
	return result;
}
