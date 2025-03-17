// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2024-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2025-2026, DDN/Whamcloud, Inc.
 */

/*
 * Index Access Module.
 *
 * Author: Timothy Day <timday@amazon.com>
 * Author: Yingjin Qian <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM	S_OSD

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <obd.h>
#include <obd_class.h>

#include "osd_internal.h"
#include "wbcfs.h"

static int osd_hash_index_lookup(const struct lu_env *env, struct dt_object *dt,
				 struct dt_rec *rec, const struct dt_key *key)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct hash_index *hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;
	int rc;

	ENTRY;

	down_read(&obj->oo_sem);
	rc = hash_index_lookup(hind, (void *)key, rec);
	up_read(&obj->oo_sem);

	RETURN(rc);
}

static int
osd_hash_index_insert(const struct lu_env *env, struct dt_object *dt,
		      const struct dt_rec *rec, const struct dt_key *key,
		      struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct hash_index *hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;
	int rc;

	ENTRY;

	down_write(&obj->oo_sem);
	rc = hash_index_insert(hind, (void *)key, 0, (void *)rec, 0);
	up_write(&obj->oo_sem);
	RETURN(rc);
}

static int osd_hash_index_delete(const struct lu_env *env, struct dt_object *dt,
				 const struct dt_key *key, struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct hash_index *hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;

	ENTRY;

	down_write(&obj->oo_sem);
	hash_index_remove(hind, (void *)key);
	up_write(&obj->oo_sem);

	RETURN(0);
}

static struct dt_it *osd_hash_index_it_init(const struct lu_env *env,
					    struct dt_object *dt, __u32 unused)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct hash_index *hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;
	struct osd_hash_it *it;

	ENTRY;

	if (obj->oo_destroyed)
		RETURN(ERR_PTR(-ENOENT));

	OBD_SLAB_ALLOC_PTR(it, osd_hash_it_cachep);
	if (!it)
		RETURN(ERR_PTR(-ENOMEM));

	/* FIXME: race between concurrent iterating and deleting */
	it->hit_cursor = &hind->hi_list;
	it->hit_obj = obj;

	RETURN((struct dt_it *)it);
}

static void osd_hash_index_it_fini(const struct lu_env *env,
				   struct dt_it *di)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;

	ENTRY;
	OBD_SLAB_FREE_PTR(it, osd_hash_it_cachep);
	EXIT;
}

static int osd_hash_index_it_get(const struct lu_env *env, struct dt_it *di,
				 const struct dt_key *key)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;
	struct osd_object *obj = it->hit_obj;
	struct hash_index_entry *entry;
	struct hash_index *hind;
	size_t keylen;
	int rc = -EIO;

	ENTRY;

	if (obj->oo_destroyed)
		RETURN(-ENOENT);

	hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;
	keylen = hind->hi_htbl_params.key_len;

	down_read(&obj->oo_sem);
	list_for_each_entry(entry, &hind->hi_list, he_list_item) {
		if (memcmp(key, entry->he_buf, keylen) == 0) {
			it->hit_cursor = &entry->he_list_item;
			rc = 0;
			break;
		}
	}
	up_read(&obj->oo_sem);

	RETURN(rc);
}

/* TODO: remove and make fp optional. */
static void osd_hash_index_it_put(const struct lu_env *env, struct dt_it *di)
{
}

static int osd_hash_index_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;
	struct osd_object *obj = it->hit_obj;
	struct hash_index *hind;
	int rc = 0;

	ENTRY;

	if (obj->oo_destroyed)
		RETURN(-ENOENT);

	hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;
	down_read(&obj->oo_sem);
	it->hit_cursor = it->hit_cursor->next;
	if (it->hit_cursor == &hind->hi_list)
		rc = 1;
	up_read(&obj->oo_sem);
	RETURN(rc);
}

static struct dt_key *osd_hash_index_it_key(const struct lu_env *env,
					    const struct dt_it *di)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;
	struct osd_object *obj = it->hit_obj;
	struct hash_index_entry *entry;

	ENTRY;

	if (obj->oo_destroyed)
		RETURN(ERR_PTR(-ENOENT));

	entry = container_of(it->hit_cursor, struct hash_index_entry,
			     he_list_item);
	RETURN((struct dt_key *)entry->he_buf);
}

static int osd_hash_index_it_key_size(const struct lu_env *env,
				      const struct dt_it *di)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;
	struct osd_object *obj = it->hit_obj;

	RETURN(MEMFS_I(obj->oo_inode)->mei_hash_index.hi_htbl_params.key_len);
}

static int osd_hash_index_it_rec(const struct lu_env *env,
				 const struct dt_it *di, struct dt_rec *rec,
				 __u32 attr)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;
	struct osd_object *obj = it->hit_obj;
	struct hash_index_entry *entry;
	struct hash_index *hind;
	size_t reclen;

	ENTRY;

	hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;
	/* FIXME: use RCU to avoid concurrent operations on the list. */
	entry = container_of(it->hit_cursor, struct hash_index_entry,
			     he_list_item);
	reclen = entry->he_len - sizeof(*entry) - entry->he_keylen;
	LASSERT(ergo(hind->hi_reclen, hind->hi_reclen == reclen));
	memcpy(rec, entry->he_buf + entry->he_keylen, reclen);
	RETURN(0);
}

static int osd_hash_index_it_rec_size(const struct lu_env *env,
				      const struct dt_it *di, __u32 attr)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;
	struct osd_object *obj = it->hit_obj;
	struct hash_index_entry *entry;
	struct hash_index *hind;
	size_t reclen;

	ENTRY;

	hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;
	if (hind->hi_reclen == 0) {
		entry = container_of(it->hit_cursor, struct hash_index_entry,
				     he_list_item);
		reclen = entry->he_len - sizeof(*entry) - entry->he_keylen;
	} else {
		reclen = hind->hi_reclen;
	}

	RETURN(reclen);
}

static __u64 osd_hash_index_it_store(const struct lu_env *env,
				     const struct dt_it *di)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;
	struct hash_index_entry *entry;

	ENTRY;

	entry = container_of(it->hit_cursor, struct hash_index_entry,
			     he_list_item);
	RETURN(entry->he_offset);
}

static int osd_hash_index_it_load(const struct lu_env *env,
				  const struct dt_it *di, __u64 hash)
{
	struct osd_hash_it *it = (struct osd_hash_it *)di;
	struct osd_object *obj = it->hit_obj;
	struct hash_index_entry *entry;
	struct hash_index *hind;
	int rc = 1;

	ENTRY;

	hind = &MEMFS_I(obj->oo_inode)->mei_hash_index;
	if (hash == 0) {
		it->hit_cursor = &hind->hi_list;
		it->hit_cursor = it->hit_cursor->next;
		if (it->hit_cursor == &hind->hi_list)
			rc = 0;

		RETURN(rc);
	}

	/* TODO: A linear scan is not efficient, will use Maple Tree instead. */
	list_for_each_entry(entry, &hind->hi_list, he_list_item) {
		if (entry->he_offset == hash) {
			it->hit_cursor = &entry->he_list_item;
			rc = 1;
			break;
		}
	}

	RETURN(rc);
}

const struct dt_index_operations osd_hash_index_ops = {
	.dio_lookup		= osd_hash_index_lookup,
	.dio_insert		= osd_hash_index_insert,
	.dio_delete		= osd_hash_index_delete,
	.dio_it	= {
		.init		= osd_hash_index_it_init,
		.fini		= osd_hash_index_it_fini,
		.get		= osd_hash_index_it_get,
		.put		= osd_hash_index_it_put,
		.next		= osd_hash_index_it_next,
		.key		= osd_hash_index_it_key,
		.key_size	= osd_hash_index_it_key_size,
		.rec		= osd_hash_index_it_rec,
		.rec_size	= osd_hash_index_it_rec_size,
		.store		= osd_hash_index_it_store,
		.load		= osd_hash_index_it_load
	}
};
