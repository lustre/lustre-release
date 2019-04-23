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
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/lu_tgt_descs.c
 *
 * Lustre target descriptions
 * These are the only exported functions, they provide some generic
 * infrastructure for target description management used by LOD/LMV
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/list.h>
#include <libcfs/libcfs.h>
#include <libcfs/libcfs_hash.h> /* hash_long() */
#include <libcfs/linux/linux-mem.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lu_object.h>

/**
 * Allocate and initialize target table.
 *
 * A helper function to initialize the target table and allocate
 * a bitmap of the available targets.
 *
 * \param[in] ltd		target's table to initialize
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
int lu_tgt_descs_init(struct lu_tgt_descs *ltd)
{
	mutex_init(&ltd->ltd_mutex);
	init_rwsem(&ltd->ltd_rw_sem);

	/*
	 * the tgt array and bitmap are allocated/grown dynamically as tgts are
	 * added to the LOD/LMV, see lu_tgt_descs_add()
	 */
	ltd->ltd_tgt_bitmap = CFS_ALLOCATE_BITMAP(BITS_PER_LONG);
	if (!ltd->ltd_tgt_bitmap)
		return -ENOMEM;

	ltd->ltd_tgts_size  = BITS_PER_LONG;
	ltd->ltd_tgtnr      = 0;

	ltd->ltd_death_row = 0;
	ltd->ltd_refcount  = 0;

	return 0;
}
EXPORT_SYMBOL(lu_tgt_descs_init);

/**
 * Free bitmap and target table pages.
 *
 * \param[in] ltd	target table
 */
void lu_tgt_descs_fini(struct lu_tgt_descs *ltd)
{
	int i;

	CFS_FREE_BITMAP(ltd->ltd_tgt_bitmap);
	for (i = 0; i < TGT_PTRS; i++) {
		if (ltd->ltd_tgt_idx[i])
			OBD_FREE_PTR(ltd->ltd_tgt_idx[i]);
	}
	ltd->ltd_tgts_size = 0;
}
EXPORT_SYMBOL(lu_tgt_descs_fini);

/**
 * Expand size of target table.
 *
 * When the target table is full, we have to extend the table. To do so,
 * we allocate new memory with some reserve, move data from the old table
 * to the new one and release memory consumed by the old table.
 *
 * \param[in] ltd		target table
 * \param[in] newsize		new size of the table
 *
 * \retval			0 on success
 * \retval			-ENOMEM if reallocation failed
 */
static int lu_tgt_descs_resize(struct lu_tgt_descs *ltd, __u32 newsize)
{
	struct cfs_bitmap *new_bitmap, *old_bitmap = NULL;

	/* someone else has already resize the array */
	if (newsize <= ltd->ltd_tgts_size)
		return 0;

	new_bitmap = CFS_ALLOCATE_BITMAP(newsize);
	if (!new_bitmap)
		return -ENOMEM;

	if (ltd->ltd_tgts_size > 0) {
		/* the bitmap already exists, copy data from old one */
		cfs_bitmap_copy(new_bitmap, ltd->ltd_tgt_bitmap);
		old_bitmap = ltd->ltd_tgt_bitmap;
	}

	ltd->ltd_tgts_size  = newsize;
	ltd->ltd_tgt_bitmap = new_bitmap;

	if (old_bitmap)
		CFS_FREE_BITMAP(old_bitmap);

	CDEBUG(D_CONFIG, "tgt size: %d\n", ltd->ltd_tgts_size);

	return 0;
}

/**
 * Add new target to target table.
 *
 * Extend target table if it's full, update target table and bitmap.
 * Notice we need to take ltd_rw_sem exclusively before entry to ensure
 * atomic switch.
 *
 * \param[in] ltd		target table
 * \param[in] tgt		new target desc
 *
 * \retval			0 on success
 * \retval			-ENOMEM if reallocation failed
 *				-EEXIST if target existed
 */
int lu_tgt_descs_add(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt)
{
	__u32 index = tgt->ltd_index;
	int rc;

	ENTRY;

	if (index >= ltd->ltd_tgts_size) {
		__u32 newsize = 1;

		while (newsize < index + 1)
			newsize = newsize << 1;

		rc = lu_tgt_descs_resize(ltd, newsize);
		if (rc)
			RETURN(rc);
	} else if (cfs_bitmap_check(ltd->ltd_tgt_bitmap, index)) {
		RETURN(-EEXIST);
	}

	if (ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] == NULL) {
		OBD_ALLOC_PTR(ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK]);
		if (ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] == NULL)
			RETURN(-ENOMEM);
	}

	LTD_TGT(ltd, tgt->ltd_index) = tgt;
	cfs_bitmap_set(ltd->ltd_tgt_bitmap, tgt->ltd_index);
	ltd->ltd_tgtnr++;

	RETURN(0);
}
EXPORT_SYMBOL(lu_tgt_descs_add);

/**
 * Delete target from target table
 */
void lu_tgt_descs_del(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt)
{
	LTD_TGT(ltd, tgt->ltd_index) = NULL;
	cfs_bitmap_clear(ltd->ltd_tgt_bitmap, tgt->ltd_index);
	ltd->ltd_tgtnr--;
}
EXPORT_SYMBOL(lu_tgt_descs_del);
