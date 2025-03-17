// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2024-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2025-2026, DDN/Whamcloud, Inc.
 */

/*
 * Hash index with FIXED key length.
 * Traverse the index via linear list scanning.
 *
 * Author: Timothy Day <timday@amazon.com>
 * Author: Yingjin Qian <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <libcfs/libcfs.h>
#include <obd_support.h>

#include "index.h"

static u32 hash_index_keyhash(const void *data, u32 len, u32 seed)
{
	return jhash(data, len, seed);
}

static u32 hash_index_entry_keyhash(const void *data, u32 len, u32 seed)
{
	struct hash_index_entry *entry = (struct hash_index_entry *)data;

	return hash_index_keyhash(&entry->he_buf, entry->he_keylen, seed);
}

static int hash_index_keycmp(struct rhashtable_compare_arg *arg,
			     const void *obj)
{
	struct hash_index_entry *entry = (struct hash_index_entry *)obj;

	LASSERT(arg->ht->key_len == entry->he_keylen);

	if (!memcpy(entry->he_buf, arg->key, entry->he_keylen))
		return 0;

	/* ESRCH is typical for rhashtable */
	return -ESRCH;
}

static const struct rhashtable_params hash_index_params = {
	.head_offset		= offsetof(struct hash_index_entry, he_hash),
	.hashfn			= hash_index_keyhash,
	.obj_hashfn		= hash_index_entry_keyhash,
	.obj_cmpfn		= hash_index_keycmp,
	.automatic_shrinking	= true,
};

int hash_index_init(struct hash_index *hind, size_t keylen, size_t reclen)
{
	int rc;

	LASSERT(keylen > 0);
	INIT_LIST_HEAD(&hind->hi_list);
	hind->hi_htbl_params = hash_index_params;
	hind->hi_htbl_params.key_len = keylen;
	hind->hi_reclen = reclen;
	rc = rhashtable_init(&hind->hi_htbl, &hind->hi_htbl_params);
	return rc;
}

void hash_index_fini(struct hash_index *hind)
{
	struct hash_index_entry *entry, *tmp;

	if (!hind)
		return;

	list_for_each_entry_safe(entry, tmp, &hind->hi_list, he_list_item) {
		rhashtable_remove_fast(&hind->hi_htbl, &entry->he_hash,
				       hind->hi_htbl_params);
		list_del(&entry->he_list_item);
		OBD_FREE(entry, entry->he_len);
	}

	rhashtable_destroy(&hind->hi_htbl);
}

struct hash_index_entry *
hash_index_lookup_entry(struct hash_index *hind, const void *key)
{
	struct hash_index_entry *entry;

	entry = rhashtable_lookup_fast(&hind->hi_htbl, key,
				       hind->hi_htbl_params);
	return entry;
}

int hash_index_lookup(struct hash_index *hind, const void *key, void *rec)
{
	struct hash_index_entry *entry;
	int rc = 0;

	entry = rhashtable_lookup_fast(&hind->hi_htbl, key,
				       hind->hi_htbl_params);
	if (entry) {
		size_t reclen;

		reclen = entry->he_len - sizeof(*entry) - entry->he_keylen;
		LASSERT(ergo(hind->hi_reclen, hind->hi_reclen == reclen));
		memcpy(rec, entry->he_buf + entry->he_keylen, reclen);
		return 1;
	}

	return rc;
}

int hash_index_insert(struct hash_index *hind, void *key, size_t keylen,
		      void *rec, size_t reclen)
{
	struct hash_index_entry *entry;
	size_t len;
	int rc = 0;

	ENTRY;

	if (!keylen)
		keylen = hind->hi_htbl_params.key_len;
	else
		LASSERT(keylen == hind->hi_htbl_params.key_len);
	if (!reclen)
		reclen = hind->hi_reclen;
	else
		LASSERT(reclen == hind->hi_reclen);

	len = sizeof(*entry) + keylen + reclen;
	OBD_ALLOC(entry, len);
	if (!entry)
		RETURN(-ENOMEM);

	entry->he_len = len;
	entry->he_keylen = keylen;
	memcpy(entry->he_buf, key, keylen);
	memcpy(entry->he_buf + keylen, rec, reclen);

	rc = rhashtable_insert_fast(&hind->hi_htbl, &entry->he_hash,
				    hind->hi_htbl_params);
	LASSERT(rc != -EBUSY);
	if (rc)
		GOTO(out_free, rc);

	list_add_tail(&entry->he_list_item, &hind->hi_list);

	/* TODO: Rollover? Should at least add detection... */
	entry->he_offset = hind->hi_next_offset++;
	RETURN(0);

out_free:
	OBD_FREE(entry, len);
	RETURN(rc);
}

void hash_index_remove(struct hash_index *hind, const void *key)
{
	struct hash_index_entry *entry;

	entry = rhashtable_lookup_fast(&hind->hi_htbl, key,
				       hind->hi_htbl_params);
	if (!entry)
		return;

	rhashtable_remove_fast(&hind->hi_htbl, &entry->he_hash,
			       hind->hi_htbl_params);
	/* FIXME: use RCU for list insert/remove. */
	list_del(&entry->he_list_item);
	OBD_FREE(entry, entry->he_len);
}
