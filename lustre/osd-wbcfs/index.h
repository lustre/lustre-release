/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025-2026, DDN/Whamcloud, Inc.
 */

/*
 * Index Access Module.
 *
 * Author: Yingjin Qian <qian@ddn.com>
 */

#ifndef __OSD_INDEX_H_
#define __OSD_INDEX_H_

#include <linux/rhashtable.h>

/* Store key and value together in @he_buf. */
struct hash_index_entry {
	struct rhash_head	he_hash;
	struct list_head	he_list_item;
	__u64			he_offset;
	size_t			he_len;
	size_t			he_keylen;
	char			he_buf[];
};

/* Index access via @rhashtable. */
struct hash_index {
	struct rhashtable		hi_htbl;
	struct rhashtable_params	hi_htbl_params;
	struct list_head		hi_list;
	size_t				hi_reclen;
	__u64				hi_next_offset;
};

int hash_index_init(struct hash_index *hind, size_t kenlen, size_t reclen);
void hash_index_fini(struct hash_index *hind);
struct hash_index_entry *hash_index_lookup_entry(struct hash_index *hind,
						 const void *key);
int hash_index_lookup(struct hash_index *hind, const void *key, void *rec);
int hash_index_insert(struct hash_index *hind, void *key, size_t keylen,
		      void *rec, size_t reclen);
void hash_index_remove(struct hash_index *hind, const void *key);

/* TODO: Index access via Maple Tree. Only support in newer kernels. */

#endif /* __OSD_INDEX_H_ */
