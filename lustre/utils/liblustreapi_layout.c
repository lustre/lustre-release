/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 * lustre/utils/liblustreapi_layout.c
 *
 * lustreapi library for layout calls for interacting with the layout of
 * Lustre files while hiding details of the internal data structures
 * from the user.
 *
 * Copyright (c) 2016, Intel Corporation.
 *
 * Author: Ned Bass <bass6@llnl.gov>
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/xattr.h>

#include <libcfs/util/list.h>
#include <lustre/lustreapi.h>
#include <lustre/lustre_idl.h>
#include "lustreapi_internal.h"

/**
 * Layout component, which contains all attributes of a plain
 * V1/V3 layout.
 */
struct llapi_layout_comp {
	uint64_t	llc_pattern;
	uint64_t	llc_stripe_size;
	uint64_t	llc_stripe_count;
	uint64_t	llc_stripe_offset;
	/* Add 1 so user always gets back a null terminated string. */
	char		llc_pool_name[LOV_MAXPOOLNAME + 1];
	/** Number of objects in llc_objects array if was initialized. */
	uint32_t	llc_objects_count;
	struct		lov_user_ost_data_v1 *llc_objects;
	/* fields used only for composite layouts */
	struct lu_extent	llc_extent;	/* [start, end) of component */
	uint32_t		llc_id;		/* unique ID of component */
	uint32_t		llc_flags;	/* LCME_FL_* flags */
	struct list_head	llc_list;	/* linked to the llapi_layout
						   components list */
};

/**
 * An Opaque data type abstracting the layout of a Lustre file.
 */
struct llapi_layout {
	uint32_t	llot_magic; /* LLAPI_LAYOUT_MAGIC */
	uint32_t	llot_gen;
	uint32_t	llot_flags;
	bool		llot_is_composite;
	/* Cursor pointing to one of the components in llot_comp_list */
	struct llapi_layout_comp *llot_cur_comp;
	struct list_head	  llot_comp_list;
};

/**
 * Compute the number of elements in the lmm_objects array of \a lum
 * with size \a lum_size.
 *
 * \param[in] lum	the struct lov_user_md to check
 * \param[in] lum_size	the number of bytes in \a lum
 *
 * \retval		number of elements in array lum->lmm_objects
 */
static int llapi_layout_objects_in_lum(struct lov_user_md *lum, size_t lum_size)
{
	uint32_t magic;
	size_t base_size;

	if (lum_size < lov_user_md_size(0, LOV_MAGIC_V1))
		return 0;

	if (lum->lmm_magic == __swab32(LOV_MAGIC_V1) ||
	    lum->lmm_magic == __swab32(LOV_MAGIC_V3))
		magic = __swab32(lum->lmm_magic);
	else
		magic = lum->lmm_magic;

	base_size = lov_user_md_size(0, magic);

	if (lum_size <= base_size)
		return 0;
	else
		return (lum_size - base_size) / sizeof(lum->lmm_objects[0]);
}

/**
 * Byte-swap the fields of struct lov_user_md.
 *
 * XXX Rather than duplicating swabbing code here, we should eventually
 * refactor the needed functions in lustre/ptlrpc/pack_generic.c
 * into a library that can be shared between kernel and user code.
 */
static void
llapi_layout_swab_lov_user_md(struct lov_user_md *lum, int lum_size)
{
	int i, j, ent_count, obj_count;
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_comp_md_entry_v1 *ent;
	struct lov_user_ost_data *lod;

	if (lum->lmm_magic != __swab32(LOV_MAGIC_V1) &&
	    lum->lmm_magic != __swab32(LOV_MAGIC_V3) &&
	    lum->lmm_magic != __swab32(LOV_MAGIC_COMP_V1))
		return;

	if (lum->lmm_magic == __swab32(LOV_MAGIC_COMP_V1))
		comp_v1 = (struct lov_comp_md_v1 *)lum;

	if (comp_v1 != NULL) {
		__swab32s(&comp_v1->lcm_magic);
		__swab32s(&comp_v1->lcm_size);
		__swab32s(&comp_v1->lcm_layout_gen);
		__swab16s(&comp_v1->lcm_flags);
		__swab16s(&comp_v1->lcm_entry_count);
		ent_count = comp_v1->lcm_entry_count;
	} else {
		ent_count = 1;
	}

	for (i = 0; i < ent_count; i++) {
		if (comp_v1 != NULL) {
			ent = &comp_v1->lcm_entries[i];
			__swab32s(&ent->lcme_id);
			__swab32s(&ent->lcme_flags);
			__swab64s(&ent->lcme_extent.e_start);
			__swab64s(&ent->lcme_extent.e_end);
			__swab32s(&ent->lcme_offset);
			__swab32s(&ent->lcme_size);

			lum = (struct lov_user_md *)((char *)comp_v1 +
					ent->lcme_offset);
			lum_size = ent->lcme_size;
		}
		obj_count = llapi_layout_objects_in_lum(lum, lum_size);

		__swab32s(&lum->lmm_magic);
		__swab32s(&lum->lmm_pattern);
		__swab32s(&lum->lmm_stripe_size);
		__swab16s(&lum->lmm_stripe_count);
		__swab16s(&lum->lmm_stripe_offset);

		if (lum->lmm_magic != LOV_MAGIC_V1) {
			struct lov_user_md_v3 *v3;
			v3 = (struct lov_user_md_v3 *)lum;
			lod = v3->lmm_objects;
		} else {
			lod = lum->lmm_objects;
		}

		for (j = 0; j < obj_count; j++)
			__swab32s(&lod[j].l_ost_idx);
	}
}

/**
 * (Re-)allocate llc_objects[] to \a num_stripes stripes.
 *
 * Copy over existing llc_objects[], if any, to the new llc_objects[].
 *
 * \param[in] layout		existing layout to be modified
 * \param[in] num_stripes	number of stripes in new layout
 *
 * \retval	0 if the objects are re-allocated successfully
 * \retval	-1 on error with errno set
 */
static int __llapi_comp_objects_realloc(struct llapi_layout_comp *comp,
					unsigned int new_stripes)
{
	struct lov_user_ost_data_v1 *new_objects;
	unsigned int i;

	if (new_stripes > LOV_MAX_STRIPE_COUNT) {
		errno = EINVAL;
		return -1;
	}

	if (new_stripes == comp->llc_objects_count)
		return 0;

	if (new_stripes != 0 && new_stripes <= comp->llc_objects_count)
		return 0;

	new_objects = realloc(comp->llc_objects,
			      sizeof(*new_objects) * new_stripes);
	if (new_objects == NULL && new_stripes != 0) {
		errno = ENOMEM;
		return -1;
	}

	for (i = comp->llc_objects_count; i < new_stripes; i++)
		new_objects[i].l_ost_idx = LLAPI_LAYOUT_IDX_MAX;

	comp->llc_objects = new_objects;
	comp->llc_objects_count = new_stripes;

	return 0;
}

/**
 * Allocate storage for a llapi_layout_comp with \a num_stripes stripes.
 *
 * \param[in] num_stripes	number of stripes in new layout
 *
 * \retval	valid pointer if allocation succeeds
 * \retval	NULL if allocation fails
 */
static struct llapi_layout_comp *__llapi_comp_alloc(unsigned int num_stripes)
{
	struct llapi_layout_comp *comp;

	if (num_stripes > LOV_MAX_STRIPE_COUNT) {
		errno = EINVAL;
		return NULL;
	}

	comp = calloc(1, sizeof(*comp));
	if (comp == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	comp->llc_objects = NULL;
	comp->llc_objects_count = 0;

	if (__llapi_comp_objects_realloc(comp, num_stripes) < 0) {
		free(comp);
		return NULL;
	}

	/* Set defaults. */
	comp->llc_pattern = LLAPI_LAYOUT_DEFAULT;
	comp->llc_stripe_size = LLAPI_LAYOUT_DEFAULT;
	comp->llc_stripe_count = LLAPI_LAYOUT_DEFAULT;
	comp->llc_stripe_offset = LLAPI_LAYOUT_DEFAULT;
	comp->llc_pool_name[0] = '\0';
	comp->llc_extent.e_start = 0;
	comp->llc_extent.e_end = LUSTRE_EOF;
	comp->llc_flags = 0;
	comp->llc_id = 0;
	INIT_LIST_HEAD(&comp->llc_list);

	return comp;
}

/**
 * Free memory allocated for \a comp
 *
 * \param[in] comp	previously allocated by __llapi_comp_alloc()
 */
static void __llapi_comp_free(struct llapi_layout_comp *comp)
{
	if (comp->llc_objects != NULL)
		free(comp->llc_objects);
	free(comp);
}

/**
 * Free memory allocated for \a layout.
 *
 * \param[in] layout	previously allocated by llapi_layout_alloc()
 */
void llapi_layout_free(struct llapi_layout *layout)
{
	struct llapi_layout_comp *comp, *n;

	if (layout == NULL)
		return;

	list_for_each_entry_safe(comp, n, &layout->llot_comp_list, llc_list) {
		list_del_init(&comp->llc_list);
		__llapi_comp_free(comp);
	}
	free(layout);
}

/**
 * Allocate and initialize a llapi_layout structure.
 *
 * \retval	valid llapi_layout pointer on success
 * \retval	NULL if memory allocation fails
 */
static struct llapi_layout *__llapi_layout_alloc(void)
{
	struct llapi_layout *layout;

	layout = calloc(1, sizeof(*layout));
	if (layout == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	/* Set defaults. */
	layout->llot_magic = LLAPI_LAYOUT_MAGIC;
	layout->llot_gen = 0;
	layout->llot_flags = 0;
	layout->llot_is_composite = false;
	layout->llot_cur_comp = NULL;
	INIT_LIST_HEAD(&layout->llot_comp_list);

	return layout;
}

/**
 * Allocate and initialize a new plain layout.
 *
 * \retval	valid llapi_layout pointer on success
 * \retval	NULL if memory allocation fails
 */
struct llapi_layout *llapi_layout_alloc(void)
{
	struct llapi_layout_comp *comp;
	struct llapi_layout *layout;

	layout = __llapi_layout_alloc();
	if (layout == NULL)
		return NULL;

	comp = __llapi_comp_alloc(0);
	if (comp == NULL) {
		free(layout);
		return NULL;
	}

	list_add_tail(&comp->llc_list, &layout->llot_comp_list);
	layout->llot_cur_comp = comp;

	return layout;
}

/**
 * Convert the data from a lov_user_md to a newly allocated llapi_layout.
 * The caller is responsible for freeing the returned pointer.
 *
 * \param[in] lum	LOV user metadata structure to copy data from
 * \param[in] lum_size	size the the lum passed in
 *
 * \retval		valid llapi_layout pointer on success
 * \retval		NULL if memory allocation fails
 */
static struct llapi_layout *
llapi_layout_from_lum(const struct lov_user_md *lum, int lum_size)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_comp_md_entry_v1 *ent;
	struct lov_user_md *v1;
	struct llapi_layout *layout;
	struct llapi_layout_comp *comp;
	int i, ent_count = 0, obj_count;

	layout = __llapi_layout_alloc();
	if (layout == NULL)
		return NULL;

	if (lum->lmm_magic == LOV_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)lum;
		ent_count = comp_v1->lcm_entry_count;
		layout->llot_is_composite = true;
		layout->llot_gen = comp_v1->lcm_layout_gen;
		layout->llot_flags = comp_v1->lcm_flags;
	} else if (lum->lmm_magic == LOV_MAGIC_V1 ||
		   lum->lmm_magic == LOV_MAGIC_V3) {
		ent_count = 1;
		layout->llot_is_composite = false;
	}

	if (ent_count == 0) {
		errno = EINVAL;
		goto error;
	}

	v1 = (struct lov_user_md *)lum;
	for (i = 0; i < ent_count; i++) {
		if (comp_v1 != NULL) {
			ent = &comp_v1->lcm_entries[i];
			v1 = (struct lov_user_md *)((char *)comp_v1 +
				ent->lcme_offset);
			lum_size = ent->lcme_size;
		} else {
			ent = NULL;
		}

		obj_count = llapi_layout_objects_in_lum(v1, lum_size);
		comp = __llapi_comp_alloc(obj_count);
		if (comp == NULL)
			goto error;

		if (ent != NULL) {
			comp->llc_extent.e_start = ent->lcme_extent.e_start;
			comp->llc_extent.e_end = ent->lcme_extent.e_end;
			comp->llc_id = ent->lcme_id;
			comp->llc_flags = ent->lcme_flags;
		} else {
			comp->llc_extent.e_start = 0;
			comp->llc_extent.e_end = LUSTRE_EOF;
			comp->llc_id = 0;
			comp->llc_flags = 0;
		}

		if (v1->lmm_pattern == LOV_PATTERN_RAID0)
			comp->llc_pattern = LLAPI_LAYOUT_RAID0;
		else
			/* Lustre only supports RAID0 for now. */
			comp->llc_pattern = v1->lmm_pattern;

		if (v1->lmm_stripe_size == 0)
			comp->llc_stripe_size = LLAPI_LAYOUT_DEFAULT;
		else
			comp->llc_stripe_size = v1->lmm_stripe_size;

		if (v1->lmm_stripe_count == (typeof(v1->lmm_stripe_count))-1)
			comp->llc_stripe_count = LLAPI_LAYOUT_WIDE;
		else if (v1->lmm_stripe_count == 0)
			comp->llc_stripe_count = LLAPI_LAYOUT_DEFAULT;
		else
			comp->llc_stripe_count = v1->lmm_stripe_count;

		if (v1->lmm_stripe_offset ==
		    (typeof(v1->lmm_stripe_offset))-1)
			comp->llc_stripe_offset = LLAPI_LAYOUT_DEFAULT;
		else
			comp->llc_stripe_offset = v1->lmm_stripe_offset;

		if (v1->lmm_magic != LOV_USER_MAGIC_V1) {
			const struct lov_user_md_v3 *lumv3;
			lumv3 = (struct lov_user_md_v3 *)v1;
			snprintf(comp->llc_pool_name,
				 sizeof(comp->llc_pool_name),
				 "%s", lumv3->lmm_pool_name);
			memcpy(comp->llc_objects, lumv3->lmm_objects,
			       obj_count * sizeof(lumv3->lmm_objects[0]));
		} else {
			const struct lov_user_md_v1 *lumv1;
			lumv1 = (struct lov_user_md_v1 *)v1;
			memcpy(comp->llc_objects, lumv1->lmm_objects,
			       obj_count * sizeof(lumv1->lmm_objects[0]));
		}

		if (obj_count != 0)
			comp->llc_stripe_offset =
				comp->llc_objects[0].l_ost_idx;

		list_add_tail(&comp->llc_list, &layout->llot_comp_list);
		layout->llot_cur_comp = comp;
	}

	return layout;
error:
	llapi_layout_free(layout);
	return NULL;
}

/**
 * Convert the data from a llapi_layout to a newly allocated lov_user_md.
 * The caller is responsible for freeing the returned pointer.
 *
 * \param[in] layout	the layout to copy from
 *
 * \retval	valid lov_user_md pointer on success
 * \retval	NULL if memory allocation fails or the layout is invalid
 */
static struct lov_user_md *
llapi_layout_to_lum(const struct llapi_layout *layout)
{
	struct llapi_layout_comp *comp;
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_comp_md_entry_v1 *ent;
	struct lov_user_md *lum = NULL;
	size_t lum_size = 0;
	int ent_idx = 0;
	uint32_t offset = 0;

	if (layout == NULL ||
	    list_empty((struct list_head *)&layout->llot_comp_list)) {
		errno = EINVAL;
		return NULL;
	}

	/* Allocate header of lov_comp_md_v1 if necessary */
	if (layout->llot_is_composite) {
		int comp_cnt = 0;

		list_for_each_entry(comp, &layout->llot_comp_list, llc_list)
			comp_cnt++;

		lum_size = sizeof(*comp_v1) + comp_cnt * sizeof(*ent);
		lum = malloc(lum_size);
		if (lum == NULL) {
			errno = ENOMEM;
			return NULL;
		}
		comp_v1 = (struct lov_comp_md_v1 *)lum;
		comp_v1->lcm_magic = LOV_USER_MAGIC_COMP_V1;
		comp_v1->lcm_size = lum_size;
		comp_v1->lcm_layout_gen = 0;
		comp_v1->lcm_flags = 0;
		comp_v1->lcm_entry_count = comp_cnt;
		offset += lum_size;
	}

	list_for_each_entry(comp, &layout->llot_comp_list, llc_list) {
		struct lov_user_md *blob;
		size_t blob_size;
		uint32_t magic;
		int i, obj_count = 0;
		struct lov_user_ost_data *lmm_objects;
		uint64_t pattern = comp->llc_pattern;

		if ((pattern & LLAPI_LAYOUT_SPECIFIC) != 0) {
			if (comp->llc_objects_count <
			    comp->llc_stripe_count) {
				errno = EINVAL;
				goto error;
			}
			magic = LOV_USER_MAGIC_SPECIFIC;
			obj_count = comp->llc_stripe_count;
			pattern &= ~LLAPI_LAYOUT_SPECIFIC;
		} else if (strlen(comp->llc_pool_name) != 0) {
			magic = LOV_USER_MAGIC_V3;
		} else {
			magic = LOV_USER_MAGIC_V1;
		}
		/* All stripes must be specified when the pattern contains
		 * LLAPI_LAYOUT_SPECIFIC */
		for (i = 0; i < obj_count; i++) {
			if (comp->llc_objects[i].l_ost_idx ==
			    LLAPI_LAYOUT_IDX_MAX) {
				errno = EINVAL;
				goto error;
			}
		}

		blob_size = lov_user_md_size(obj_count, magic);
		blob = realloc(lum, lum_size + blob_size);
		if (blob == NULL) {
			errno = ENOMEM;
			goto error;
		} else {
			lum = blob;
			comp_v1 = (struct lov_comp_md_v1 *)lum;
			blob = (struct lov_user_md *)((char *)lum + lum_size);
			lum_size += blob_size;
		}

		blob->lmm_magic = magic;
		if (pattern == LLAPI_LAYOUT_DEFAULT)
			blob->lmm_pattern = 0;
		else if (pattern == LLAPI_LAYOUT_RAID0)
			blob->lmm_pattern = LOV_PATTERN_RAID0;
		else
			blob->lmm_pattern = pattern;

		if (comp->llc_stripe_size == LLAPI_LAYOUT_DEFAULT)
			blob->lmm_stripe_size = 0;
		else
			blob->lmm_stripe_size = comp->llc_stripe_size;

		if (comp->llc_stripe_count == LLAPI_LAYOUT_DEFAULT)
			blob->lmm_stripe_count = 0;
		else if (comp->llc_stripe_count == LLAPI_LAYOUT_WIDE)
			blob->lmm_stripe_count = LOV_ALL_STRIPES;
		else
			blob->lmm_stripe_count = comp->llc_stripe_count;

		if (comp->llc_stripe_offset == LLAPI_LAYOUT_DEFAULT)
			blob->lmm_stripe_offset = -1;
		else
			blob->lmm_stripe_offset = comp->llc_stripe_offset;

		if (magic == LOV_USER_MAGIC_V3 ||
		    magic == LOV_USER_MAGIC_SPECIFIC) {
			struct lov_user_md_v3 *lumv3 =
				(struct lov_user_md_v3 *)blob;

			if (comp->llc_pool_name[0] != '\0') {
				strncpy(lumv3->lmm_pool_name,
					comp->llc_pool_name,
					sizeof(lumv3->lmm_pool_name));
			} else {
				memset(lumv3->lmm_pool_name, 0,
				       sizeof(lumv3->lmm_pool_name));
			}
			lmm_objects = lumv3->lmm_objects;
		} else {
			lmm_objects = blob->lmm_objects;
		}

		for (i = 0; i < obj_count; i++)
			lmm_objects[i].l_ost_idx =
				comp->llc_objects[i].l_ost_idx;

		if (layout->llot_is_composite) {
			ent = &comp_v1->lcm_entries[ent_idx];
			ent->lcme_id = comp->llc_id;
			ent->lcme_flags = comp->llc_flags;
			ent->lcme_extent.e_start = comp->llc_extent.e_start;
			ent->lcme_extent.e_end = comp->llc_extent.e_end;
			ent->lcme_size = blob_size;
			ent->lcme_offset = offset;
			offset += blob_size;
			comp_v1->lcm_size += blob_size;
			ent_idx++;
		} else {
			break;
		}
	}

	return lum;
error:
	free(lum);
	return NULL;
}

/**
 * Get the parent directory of a path.
 *
 * \param[in] path	path to get parent of
 * \param[out] buf	buffer in which to store parent path
 * \param[in] size	size in bytes of buffer \a buf
 */
static void get_parent_dir(const char *path, char *buf, size_t size)
{
	char *p;

	strncpy(buf, path, size);
	p = strrchr(buf, '/');

	if (p != NULL) {
		*p = '\0';
	} else if (size >= 2) {
		strncpy(buf, ".", 2);
		buf[size - 1] = '\0';
	}
}

/**
 * Substitute unspecified attribute values in \a layout with values
 * from fs global settings. (lov.stripesize, lov.stripecount,
 * lov.stripeoffset)
 *
 * \param[in] layout	layout to inherit values from
 * \param[in] path	file path of the filesystem
 */
static void inherit_sys_attributes(struct llapi_layout *layout,
				   const char *path)
{
	struct llapi_layout_comp *comp;
	unsigned int ssize, scount, soffset;
	int rc;

	rc = sattr_cache_get_defaults(NULL, path, &scount, &ssize, &soffset);
	if (rc)
		return;

	list_for_each_entry(comp, &layout->llot_comp_list, llc_list) {
		if (comp->llc_pattern == LLAPI_LAYOUT_DEFAULT)
			comp->llc_pattern = LLAPI_LAYOUT_RAID0;
		if (comp->llc_stripe_size == LLAPI_LAYOUT_DEFAULT)
			comp->llc_stripe_size = ssize;
		if (comp->llc_stripe_count == LLAPI_LAYOUT_DEFAULT)
			comp->llc_stripe_count = scount;
		if (comp->llc_stripe_offset == LLAPI_LAYOUT_DEFAULT)
			comp->llc_stripe_offset = soffset;
	}
}

/**
 * Get the current component of \a layout.
 *
 * \param[in] layout	layout to get current component
 *
 * \retval	valid llapi_layout_comp pointer on success
 * \retval	NULL on error
 */
static struct llapi_layout_comp *
__llapi_layout_cur_comp(const struct llapi_layout *layout)
{
	struct llapi_layout_comp *comp;

	if (layout == NULL || layout->llot_magic != LLAPI_LAYOUT_MAGIC) {
		errno = EINVAL;
		return NULL;
	}
	if (layout->llot_cur_comp == NULL) {
		errno = EINVAL;
		return NULL;
	}
	/* Verify data consistency */
	list_for_each_entry(comp, &layout->llot_comp_list, llc_list)
		if (comp == layout->llot_cur_comp)
			return comp;
	errno = EFAULT;
	return NULL;
}

/**
 * Test if any attributes of \a layout are specified.
 *
 * \param[in] layout	the layout to check
 *
 * \retval true		any attributes are specified
 * \retval false	all attributes are unspecified
 */
static bool is_any_specified(const struct llapi_layout *layout)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return false;

	if (layout->llot_is_composite)
		return true;

	return comp->llc_pattern != LLAPI_LAYOUT_DEFAULT ||
	       comp->llc_stripe_size != LLAPI_LAYOUT_DEFAULT ||
	       comp->llc_stripe_count != LLAPI_LAYOUT_DEFAULT ||
	       comp->llc_stripe_offset != LLAPI_LAYOUT_DEFAULT ||
	       strlen(comp->llc_pool_name);
}

/**
 * Check if the given \a lum_size is large enough to hold the required
 * fields in \a lum.
 *
 * \param[in] lum	the struct lov_user_md to check
 * \param[in] lum_size	the number of bytes in \a lum
 *
 * \retval true		the \a lum_size is too small
 * \retval false	the \a lum_size is large enough
 */
static bool llapi_layout_lum_truncated(struct lov_user_md *lum, size_t lum_size)
{
	uint32_t magic;

	if (lum_size < sizeof(lum->lmm_magic))
		return true;

	if (lum->lmm_magic == LOV_MAGIC_V1 ||
	    lum->lmm_magic == __swab32(LOV_MAGIC_V1))
		magic = LOV_MAGIC_V1;
	else if (lum->lmm_magic == LOV_MAGIC_V3 ||
		 lum->lmm_magic == __swab32(LOV_MAGIC_V3))
		magic = LOV_MAGIC_V3;
	else if (lum->lmm_magic == LOV_MAGIC_COMP_V1 ||
		 lum->lmm_magic == __swab32(LOV_MAGIC_COMP_V1))
		magic = LOV_MAGIC_COMP_V1;
	else
		return true;

	if (magic == LOV_MAGIC_V1 || magic == LOV_MAGIC_V3)
		return lum_size < lov_user_md_size(0, magic);
	else
		return lum_size < sizeof(struct lov_comp_md_v1);
}

/* Verify if the objects count in lum is consistent with the
 * stripe count in lum. It applies to regular file only. */
static bool llapi_layout_lum_valid(struct lov_user_md *lum, int lum_size)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	int i, ent_count, obj_count;

	if (lum->lmm_magic == LOV_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)lum;
		ent_count = comp_v1->lcm_entry_count;
	} else if (lum->lmm_magic == LOV_MAGIC_V1 ||
		   lum->lmm_magic == LOV_MAGIC_V3) {
		ent_count = 1;
	} else {
		return false;
	}

	for (i = 0; i < ent_count; i++) {
		if (comp_v1) {
			lum = (struct lov_user_md *)((char *)comp_v1 +
				comp_v1->lcm_entries[i].lcme_offset);
			lum_size = comp_v1->lcm_entries[i].lcme_size;
		}
		obj_count = llapi_layout_objects_in_lum(lum, lum_size);

		if (comp_v1) {
			if (!(comp_v1->lcm_entries[i].lcme_flags &
				 LCME_FL_INIT) && obj_count != 0)
				return false;
		} else if (obj_count != lum->lmm_stripe_count) {
			return false;
		}
	}
	return true;
}

/**
 * Get the striping layout for the file referenced by file descriptor \a fd.
 *
 * If the filesystem does not support the "lustre." xattr namespace, the
 * file must be on a non-Lustre filesystem, so set errno to ENOTTY per
 * convention.  If the file has no "lustre.lov" data, the file will
 * inherit default values, so return a default layout.
 *
 * If the kernel gives us back less than the expected amount of data,
 * we fail with errno set to EINTR.
 *
 * \param[in] fd	open file descriptor
 * \param[in] flags	open file descriptor
 *
 * \retval	valid llapi_layout pointer on success
 * \retval	NULL if an error occurs
 */
struct llapi_layout *llapi_layout_get_by_fd(int fd, uint32_t flags)
{
	size_t lum_len;
	struct lov_user_md *lum;
	struct llapi_layout *layout = NULL;
	ssize_t bytes_read;
	struct stat st;

	lum_len = XATTR_SIZE_MAX;
	lum = malloc(lum_len);
	if (lum == NULL)
		return NULL;

	bytes_read = fgetxattr(fd, XATTR_LUSTRE_LOV, lum, lum_len);
	if (bytes_read < 0) {
		if (errno == EOPNOTSUPP)
			errno = ENOTTY;
		else if (errno == ENODATA)
			layout = llapi_layout_alloc();
		goto out;
	}

	/* Return an error if we got back a partial layout. */
	if (llapi_layout_lum_truncated(lum, bytes_read)) {
		errno = EINTR;
		goto out;
	}

	llapi_layout_swab_lov_user_md(lum, bytes_read);

	/* Directories may have a positive non-zero lum->lmm_stripe_count
	 * yet have an empty lum->lmm_objects array. For non-directories the
	 * amount of data returned from the kernel must be consistent
	 * with the stripe count. */
	if (fstat(fd, &st) < 0)
		goto out;

	if (!S_ISDIR(st.st_mode) && !llapi_layout_lum_valid(lum, bytes_read)) {
		errno = EINTR;
		goto out;
	}

	layout = llapi_layout_from_lum(lum, bytes_read);
out:
	free(lum);
	return layout;
}

/**
 * Get the expected striping layout for a file at \a path.
 *
 * Substitute expected inherited attribute values for unspecified
 * attributes.  Unspecified attributes may belong to directories and
 * never-written-to files, and indicate that default values will be
 * assigned when files are created or first written to.  A default value
 * is inherited from the parent directory if the attribute is specified
 * there, otherwise it is inherited from the filesystem root.
 * Unspecified attributes normally have the value LLAPI_LAYOUT_DEFAULT.
 *
 * The complete \a path need not refer to an existing file or directory,
 * but some leading portion of it must reside within a lustre filesystem.
 * A use case for this interface would be to obtain the literal striping
 * values that would be assigned to a new file in a given directory.
 *
 * \param[in] path	path for which to get the expected layout
 *
 * \retval	valid llapi_layout pointer on success
 * \retval	NULL if an error occurs
 */
static struct llapi_layout *llapi_layout_expected(const char *path)
{
	struct llapi_layout	*path_layout = NULL;
	char			donor_path[PATH_MAX];
	struct stat st;
	int fd;
	int rc;

	fd = open(path, O_RDONLY);
	if (fd < 0 && errno != ENOENT)
		return NULL;

	if (fd >= 0) {
		int tmp;

		path_layout = llapi_layout_get_by_fd(fd, 0);
		tmp = errno;
		close(fd);
		errno = tmp;
	}

	if (path_layout == NULL) {
		if (errno != ENODATA && errno != ENOENT)
			return NULL;

		path_layout = llapi_layout_alloc();
		if (path_layout == NULL)
			return NULL;
	}

	if (is_any_specified(path_layout)) {
		inherit_sys_attributes(path_layout, path);
		return path_layout;
	}

	llapi_layout_free(path_layout);

	rc = stat(path, &st);
	if (rc < 0 && errno != ENOENT)
		return NULL;

	/* If path is a not a directory or doesn't exist, inherit layout
	 * from parent directory. */
	if ((rc == 0 && !S_ISDIR(st.st_mode)) ||
	    (rc < 0 && errno == ENOENT)) {
		get_parent_dir(path, donor_path, sizeof(donor_path));
		path_layout = llapi_layout_get_by_path(donor_path, 0);
		if (path_layout != NULL) {
			if (is_any_specified(path_layout)) {
				inherit_sys_attributes(path_layout, donor_path);
				return path_layout;
			}
			llapi_layout_free(path_layout);
		}
	}

	/* Inherit layout from the filesystem root. */
	rc = llapi_search_mounts(path, 0, donor_path, NULL);
	if (rc < 0)
		return NULL;
	path_layout = llapi_layout_get_by_path(donor_path, 0);
	if (path_layout == NULL)
		return NULL;

	inherit_sys_attributes(path_layout, donor_path);
	return path_layout;
}

/**
 * Get the striping layout for the file at \a path.
 *
 * If \a flags contains LAYOUT_GET_EXPECTED, substitute
 * expected inherited attribute values for unspecified attributes. See
 * llapi_layout_expected().
 *
 * \param[in] path	path for which to get the layout
 * \param[in] flags	flags to control how layout is retrieved
 *
 * \retval	valid llapi_layout pointer on success
 * \retval	NULL if an error occurs
 */
struct llapi_layout *llapi_layout_get_by_path(const char *path, uint32_t flags)
{
	struct llapi_layout *layout = NULL;
	int fd;
	int tmp;

	if (flags & LAYOUT_GET_EXPECTED)
		return llapi_layout_expected(path);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return layout;

	layout = llapi_layout_get_by_fd(fd, flags);
	tmp = errno;
	close(fd);
	errno = tmp;

	return layout;
}

/**
 * Get the layout for the file with FID \a fidstr in filesystem \a lustre_dir.
 *
 * \param[in] lustre_dir	path within Lustre filesystem containing \a fid
 * \param[in] fid		Lustre identifier of file to get layout for
 *
 * \retval	valid llapi_layout pointer on success
 * \retval	NULL if an error occurs
 */
struct llapi_layout *llapi_layout_get_by_fid(const char *lustre_dir,
					     const lustre_fid *fid,
					     uint32_t flags)
{
	int fd;
	int tmp;
	int saved_msg_level = llapi_msg_get_level();
	struct llapi_layout *layout = NULL;

	/* Prevent llapi internal routines from writing to console
	 * while executing this function, then restore previous message
	 * level. */
	llapi_msg_set_level(LLAPI_MSG_OFF);
	fd = llapi_open_by_fid(lustre_dir, fid, O_RDONLY);
	llapi_msg_set_level(saved_msg_level);

	if (fd < 0)
		return NULL;

	layout = llapi_layout_get_by_fd(fd, flags);
	tmp = errno;
	close(fd);
	errno = tmp;

	return layout;
}

/**
 * Get the stripe count of \a layout.
 *
 * \param[in] layout	layout to get stripe count from
 * \param[out] count	integer to store stripe count in
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
int llapi_layout_stripe_count_get(const struct llapi_layout *layout,
				  uint64_t *count)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (count == NULL) {
		errno = EINVAL;
		return -1;
	}

	*count = comp->llc_stripe_count;

	return 0;
}

/*
 * The llapi_layout API functions have these extra validity checks since
 * they use intuitively named macros to denote special behavior, whereas
 * the old API uses 0 and -1.
 */

static bool llapi_layout_stripe_count_is_valid(int64_t stripe_count)
{
	return stripe_count == LLAPI_LAYOUT_DEFAULT ||
		stripe_count == LLAPI_LAYOUT_WIDE ||
		(stripe_count != 0 && stripe_count != -1 &&
		 llapi_stripe_count_is_valid(stripe_count));
}

static bool llapi_layout_stripe_size_is_valid(uint64_t stripe_size)
{
	return stripe_size == LLAPI_LAYOUT_DEFAULT ||
		(stripe_size != 0 &&
		 llapi_stripe_size_is_aligned(stripe_size) &&
		 !llapi_stripe_size_is_too_big(stripe_size));
}

static bool llapi_layout_stripe_index_is_valid(int64_t stripe_index)
{
	return stripe_index == LLAPI_LAYOUT_DEFAULT ||
		(stripe_index >= 0 &&
		llapi_stripe_index_is_valid(stripe_index));
}

/**
 * Set the stripe count of \a layout.
 *
 * \param[in] layout	layout to set stripe count in
 * \param[in] count	value to be set
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
int llapi_layout_stripe_count_set(struct llapi_layout *layout,
				  uint64_t count)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (!llapi_layout_stripe_count_is_valid(count)) {
		errno = EINVAL;
		return -1;
	}

	comp->llc_stripe_count = count;

	return 0;
}

/**
 * Get the stripe size of \a layout.
 *
 * \param[in] layout	layout to get stripe size from
 * \param[out] size	integer to store stripe size in
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
int llapi_layout_stripe_size_get(const struct llapi_layout *layout,
				 uint64_t *size)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (size == NULL) {
		errno = EINVAL;
		return -1;
	}

	*size = comp->llc_stripe_size;

	return 0;
}

/**
 * Set the stripe size of \a layout.
 *
 * \param[in] layout	layout to set stripe size in
 * \param[in] size	value to be set
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
int llapi_layout_stripe_size_set(struct llapi_layout *layout,
				 uint64_t size)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (!llapi_layout_stripe_size_is_valid(size)) {
		errno = EINVAL;
		return -1;
	}

	comp->llc_stripe_size = size;

	return 0;
}

/**
 * Get the RAID pattern of \a layout.
 *
 * \param[in] layout	layout to get pattern from
 * \param[out] pattern	integer to store pattern in
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
int llapi_layout_pattern_get(const struct llapi_layout *layout,
			     uint64_t *pattern)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (pattern == NULL) {
		errno = EINVAL;
		return -1;
	}

	*pattern = comp->llc_pattern;

	return 0;
}

/**
 * Set the RAID pattern of \a layout.
 *
 * \param[in] layout	layout to set pattern in
 * \param[in] pattern	value to be set
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid or RAID pattern
 *		is unsupported
 */
int llapi_layout_pattern_set(struct llapi_layout *layout, uint64_t pattern)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (pattern != LLAPI_LAYOUT_DEFAULT &&
	    pattern != LLAPI_LAYOUT_RAID0) {
		errno = EOPNOTSUPP;
		return -1;
	}

	comp->llc_pattern = pattern |
			    (comp->llc_pattern & LLAPI_LAYOUT_SPECIFIC);

	return 0;
}

static inline int stripe_number_roundup(int stripe_number)
{
	unsigned int round_up = (stripe_number + 8) & ~7;
	return round_up > LOV_MAX_STRIPE_COUNT ?
		LOV_MAX_STRIPE_COUNT : round_up;
}

/**
 * Set the OST index of stripe number \a stripe_number to \a ost_index.
 *
 * If only the starting stripe's OST index is specified, then this can use
 * the normal LOV_MAGIC_{V1,V3} layout type.  If multiple OST indices are
 * given, then allocate an array to hold the list of indices and ensure that
 * the LOV_USER_MAGIC_SPECIFIC layout is used when creating the file.
 *
 * \param[in] layout		layout to set OST index in
 * \param[in] stripe_number	stripe number to set index for
 * \param[in] ost_index		the index to set
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid or an unsupported stripe number
 *		was specified, error returned in errno
 */
int llapi_layout_ost_index_set(struct llapi_layout *layout, int stripe_number,
			       uint64_t ost_index)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (!llapi_layout_stripe_index_is_valid(ost_index)) {
		errno = EINVAL;
		return -1;
	}

	if (stripe_number == 0 && ost_index == LLAPI_LAYOUT_DEFAULT) {
		comp->llc_stripe_offset = ost_index;
		comp->llc_pattern &= ~LLAPI_LAYOUT_SPECIFIC;
		__llapi_comp_objects_realloc(comp, 0);
	} else if (stripe_number >= 0 &&
		   stripe_number < LOV_MAX_STRIPE_COUNT) {
		if (ost_index >= LLAPI_LAYOUT_IDX_MAX) {
			errno = EINVAL;
			return -1;
		}

		/* Preallocate a few more stripes to avoid realloc() overhead.*/
		if (__llapi_comp_objects_realloc(comp,
				stripe_number_roundup(stripe_number)) < 0)
			return -1;

		comp->llc_objects[stripe_number].l_ost_idx = ost_index;

		if (stripe_number == 0)
			comp->llc_stripe_offset = ost_index;
		else
			comp->llc_pattern |= LLAPI_LAYOUT_SPECIFIC;

		if (comp->llc_stripe_count == LLAPI_LAYOUT_DEFAULT ||
		    comp->llc_stripe_count <= stripe_number)
			comp->llc_stripe_count = stripe_number + 1;
	} else {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/**
 * Get the OST index associated with stripe \a stripe_number.
 *
 * Stripes are indexed starting from zero.
 *
 * \param[in] layout		layout to get index from
 * \param[in] stripe_number	stripe number to get index for
 * \param[out] index		integer to store index in
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
int llapi_layout_ost_index_get(const struct llapi_layout *layout,
			       uint64_t stripe_number, uint64_t *index)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (index == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (stripe_number >= comp->llc_stripe_count ||
	    stripe_number >= comp->llc_objects_count) {
		errno = EINVAL;
		return -1;
	}

	if (comp->llc_stripe_offset == LLAPI_LAYOUT_DEFAULT)
		*index = LLAPI_LAYOUT_DEFAULT;
	else
		*index = comp->llc_objects[stripe_number].l_ost_idx;

	return 0;
}

/**
 *
 * Get the pool name of layout \a layout.
 *
 * \param[in] layout	layout to get pool name from
 * \param[out] dest	buffer to store pool name in
 * \param[in] n		size in bytes of buffer \a dest
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
int llapi_layout_pool_name_get(const struct llapi_layout *layout, char *dest,
			       size_t n)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (dest == NULL) {
		errno = EINVAL;
		return -1;
	}

	strncpy(dest, comp->llc_pool_name, n);

	return 0;
}

/**
 * Set the name of the pool of layout \a layout.
 *
 * \param[in] layout	layout to set pool name in
 * \param[in] pool_name	pool name to set
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid or pool name is too long
 */
int llapi_layout_pool_name_set(struct llapi_layout *layout,
			       const char *pool_name)
{
	struct llapi_layout_comp *comp;
	char *ptr;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (pool_name == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* Strip off any 'fsname.' portion. */
	ptr = strchr(pool_name, '.');
	if (ptr != NULL)
		pool_name = ptr + 1;

	if (strlen(pool_name) > LOV_MAXPOOLNAME) {
		errno = EINVAL;
		return -1;
	}

	strncpy(comp->llc_pool_name, pool_name, sizeof(comp->llc_pool_name));

	return 0;
}

/**
 * Open and possibly create a file with a given \a layout.
 *
 * If \a layout is NULL this function acts as a simple wrapper for
 * open().  By convention, ENOTTY is returned in errno if \a path
 * refers to a non-Lustre file.
 *
 * \param[in] path		name of the file to open
 * \param[in] open_flags	open() flags
 * \param[in] mode		permissions to create new file with
 * \param[in] layout		layout to create new file with
 *
 * \retval		non-negative file descriptor on successful open
 * \retval		-1 if an error occurred
 */
int llapi_layout_file_open(const char *path, int open_flags, mode_t mode,
			   const struct llapi_layout *layout)
{
	int fd;
	int rc;
	int tmp;
	struct lov_user_md *lum;
	size_t lum_size;

	if (path == NULL ||
	    (layout != NULL && layout->llot_magic != LLAPI_LAYOUT_MAGIC)) {
		errno = EINVAL;
		return -1;
	}

	/* Object creation must be postponed until after layout attributes
	 * have been applied. */
	if (layout != NULL && (open_flags & O_CREAT))
		open_flags |= O_LOV_DELAY_CREATE;

	fd = open(path, open_flags, mode);

	if (layout == NULL || fd < 0)
		return fd;

	lum = llapi_layout_to_lum(layout);

	if (lum == NULL) {
		tmp = errno;
		close(fd);
		errno = tmp;
		return -1;
	}

	if (lum->lmm_magic == LOV_USER_MAGIC_COMP_V1)
		lum_size = ((struct lov_comp_md_v1 *)lum)->lcm_size;
	else if (lum->lmm_magic == LOV_USER_MAGIC_SPECIFIC)
		lum_size = lov_user_md_size(lum->lmm_stripe_count,
					    lum->lmm_magic);
	else
		lum_size = lov_user_md_size(0, lum->lmm_magic);

	rc = fsetxattr(fd, XATTR_LUSTRE_LOV, lum, lum_size, 0);
	if (rc < 0) {
		tmp = errno;
		close(fd);
		errno = tmp;
		fd = -1;
	}

	free(lum);
	errno = errno == EOPNOTSUPP ? ENOTTY : errno;

	return fd;
}

/**
 * Create a file with a given \a layout.
 *
 * Force O_CREAT and O_EXCL flags on so caller is assured that file was
 * created with the given \a layout on successful function return.
 *
 * \param[in] path		name of the file to open
 * \param[in] open_flags	open() flags
 * \param[in] mode		permissions to create new file with
 * \param[in] layout		layout to create new file with
 *
 * \retval		non-negative file descriptor on successful open
 * \retval		-1 if an error occurred
 */
int llapi_layout_file_create(const char *path, int open_flags, int mode,
			     const struct llapi_layout *layout)
{
	return llapi_layout_file_open(path, open_flags|O_CREAT|O_EXCL, mode,
				      layout);
}

/**
 * Fetch the start and end offset of the current layout component.
 *
 * \param[in] layout	the layout component
 * \param[out] start	extent start, inclusive
 * \param[out] end	extent end, exclusive
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_extent_get(const struct llapi_layout *layout,
				 uint64_t *start, uint64_t *end)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (start == NULL || end == NULL) {
		errno = EINVAL;
		return -1;
	}

	*start = comp->llc_extent.e_start;
	*end = comp->llc_extent.e_end;

	return 0;
}

/**
 * Set the layout extent of a layout.
 *
 * \param[in] layout	the layout to be set
 * \param[in] start	extent start, inclusive
 * \param[in] end	extent end, exclusive
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_extent_set(struct llapi_layout *layout,
				 uint64_t start, uint64_t end)
{
	struct llapi_layout_comp *prev, *next, *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (start >= end) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * We need to make sure the extent to be set is valid: the new
	 * extent must be adjacent with the prev & next component.
	 */
	if (comp->llc_list.prev != &layout->llot_comp_list) {
		prev = list_entry(comp->llc_list.prev, typeof(*prev),
				  llc_list);
		if (start != prev->llc_extent.e_end) {
			errno = EINVAL;
			return -1;
		}
	}

	if (comp->llc_list.next != &layout->llot_comp_list) {
		next = list_entry(comp->llc_list.next, typeof(*next),
				  llc_list);
		if (end != next->llc_extent.e_start) {
			errno = EINVAL;
			return -1;
		}
	}

	comp->llc_extent.e_start = start;
	comp->llc_extent.e_end = end;
	layout->llot_is_composite = true;

	return 0;
}

/**
 * Gets the attribute flags of the current component.
 *
 * \param[in] layout	the layout component
 * \param[out] flags	stored the returned component flags
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_flags_get(const struct llapi_layout *layout,
				uint32_t *flags)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (flags == NULL) {
		errno = EINVAL;
		return -1;
	}

	*flags = comp->llc_flags;

	return 0;
}

/**
 * Sets the specified flags of the current component leaving other flags as-is.
 *
 * \param[in] layout	the layout component
 * \param[in] flags	component flags to be set
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_flags_set(struct llapi_layout *layout, uint32_t flags)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	comp->llc_flags |= flags;

	return 0;
}

/**
 * Clears the flags specified in the flags leaving other flags as-is.
 *
 * \param[in] layout	the layout component
 * \param[in] flags	component flags to be cleared
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_flags_clear(struct llapi_layout *layout,
				  uint32_t flags)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	comp->llc_flags &= ~flags;

	return 0;
}

/**
 * Fetches the file-unique component ID of the current layout component.
 *
 * \param[in] layout	the layout component
 * \param[out] id	stored the returned component ID
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_id_get(const struct llapi_layout *layout, uint32_t *id)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (id == NULL) {
		errno = EINVAL;
		return -1;
	}
	*id = comp->llc_id;

	return 0;
}

/**
 * Adds a component to \a layout, the new component will be added to
 * the tail of components list and it'll inherit attributes of existing
 * ones. The \a layout will change it's current component pointer to
 * the newly added component, and it'll be turned into a composite
 * layout if it was not before the adding.
 *
 * \param[in] layout	existing composite or plain layout
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_add(struct llapi_layout *layout)
{
	struct llapi_layout_comp *last, *comp, *new;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	new = __llapi_comp_alloc(0);
	if (new == NULL)
		return -1;

	last = list_entry(layout->llot_comp_list.prev, typeof(*last),
			  llc_list);

	/* Inherit some attributes from existing component */
	new->llc_stripe_size = comp->llc_stripe_size;
	new->llc_stripe_count = comp->llc_stripe_count;
	if (comp->llc_pool_name[0] != '\0')
		strncpy(new->llc_pool_name, comp->llc_pool_name,
			sizeof(comp->llc_pool_name));
	if (new->llc_extent.e_end <= last->llc_extent.e_end) {
		__llapi_comp_free(new);
		errno = EINVAL;
		return -1;
	}
	new->llc_extent.e_start = last->llc_extent.e_end;

	list_add_tail(&new->llc_list, &layout->llot_comp_list);
	layout->llot_cur_comp = new;
	layout->llot_is_composite = true;

	return 0;
}

/**
 * Deletes current component from the composite layout. The component
 * to be deleted must be the tail of components list, and it can't be
 * the only component in the layout.
 *
 * \param[in] layout	composite layout
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_del(struct llapi_layout *layout)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (!layout->llot_is_composite) {
		errno = EINVAL;
		return -1;
	}

	/* It must be the tail of the list (for PFL, can be relaxed
	 * once we get mirrored components) */
	if (comp->llc_list.next != &layout->llot_comp_list) {
		errno = EINVAL;
		return -1;
	}
	/* It can't be the only one on the list */
	if (comp->llc_list.prev == &layout->llot_comp_list) {
		errno = EINVAL;
		return -1;
	}

	layout->llot_cur_comp =
		list_entry(comp->llc_list.prev, typeof(*comp), llc_list);
	list_del_init(&comp->llc_list);
	__llapi_comp_free(comp);

	return 0;
}

/**
 * Move the current component pointer to the component with
 * specified component ID.
 *
 * \param[in] layout	composite layout
 * \param[in] id	component ID
 *
 * \retval	=0 : moved successfully
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_use_id(struct llapi_layout *layout, uint32_t comp_id)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1; /* use previously set errno */

	if (!layout->llot_is_composite) {
		errno = EINVAL;
		return -1;
	}

	if (comp_id == LCME_ID_INVAL) {
		errno = EINVAL;
		return -1;
	}

	list_for_each_entry(comp, &layout->llot_comp_list, llc_list) {
		if (comp->llc_id == comp_id) {
			layout->llot_cur_comp = comp;
			return 0;
		}
	}
	errno = ENOENT;
	return -1;
}

/**
 * Move the current component pointer to a specified position.
 *
 * \param[in] layout	composite layout
 * \param[in] pos	the position to be moved, it can be:
 *			LLAPI_LAYOUT_COMP_USE_FIRST: use first component
 *			LLAPI_LAYOUT_COMP_USE_LAST: use last component
 *			LLAPI_LAYOUT_COMP_USE_NEXT: use component after current
 *			LLAPI_LAYOUT_COMP_USE_PREV: use component before current
 *
 * \retval	=0 : moved successfully
 * \retval	=1 : at last component with NEXT, at first component with PREV
 * \retval	<0 if error occurs
 */
int llapi_layout_comp_use(struct llapi_layout *layout,
			  enum llapi_layout_comp_use pos)
{
	struct llapi_layout_comp *comp, *head, *tail;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (!layout->llot_is_composite) {
		errno = EINVAL;
		return -1;
	}

	head = list_entry(layout->llot_comp_list.next, typeof(*head), llc_list);
	tail = list_entry(layout->llot_comp_list.prev, typeof(*tail), llc_list);
	switch (pos) {
	case LLAPI_LAYOUT_COMP_USE_FIRST:
		layout->llot_cur_comp = head;
		break;
	case LLAPI_LAYOUT_COMP_USE_NEXT:
		if (comp == tail) {
			errno = ENOENT;
			return 1;
		}
		layout->llot_cur_comp = list_entry(comp->llc_list.next,
						   typeof(*comp), llc_list);
		break;
	case LLAPI_LAYOUT_COMP_USE_LAST:
		layout->llot_cur_comp = tail;
		break;
	case LLAPI_LAYOUT_COMP_USE_PREV:
		if (comp == head) {
			errno = ENOENT;
			return 1;
		}
		layout->llot_cur_comp = list_entry(comp->llc_list.prev,
						   typeof(*comp), llc_list);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/**
 * Add layout component(s) to an existing file.
 *
 * \param[in] path	The path name of the file
 * \param[in] layout	The layout component(s) to be added
 */
int llapi_layout_file_comp_add(const char *path,
			       const struct llapi_layout *layout)
{
	int rc, fd, lum_size, tmp_errno = 0;
	struct lov_user_md *lum;

	if (path == NULL || layout == NULL ||
	    layout->llot_magic != LLAPI_LAYOUT_MAGIC) {
		errno = EINVAL;
		return -1;
	}

	lum = llapi_layout_to_lum(layout);
	if (lum == NULL)
		return -1;

	if (lum->lmm_magic != LOV_USER_MAGIC_COMP_V1) {
		free(lum);
		errno = EINVAL;
		return -1;
	}
	lum_size = ((struct lov_comp_md_v1 *)lum)->lcm_size;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	rc = fsetxattr(fd, XATTR_LUSTRE_LOV".add", lum, lum_size, 0);
	if (rc < 0) {
		tmp_errno = errno;
		close(fd);
		rc = -1;
		goto out;
	}
	close(fd);
out:
	free(lum);
	errno = tmp_errno;
	return rc;
}

/**
 * Delete component(s) by the specified component id or component flags
 * from an existing file.
 *
 * \param[in] path	path name of the file
 * \param[in] id	unique component ID
 * \param[in] flags	flags: LCME_FL_* or;
 *			negative flags: (LCME_FL_NEG|LCME_FL_*)
 */
int llapi_layout_file_comp_del(const char *path, uint32_t id, uint32_t flags)
{
	int rc, fd, lum_size;
	struct llapi_layout *layout;
	struct llapi_layout_comp *comp;
	struct lov_user_md *lum;

	if (path == NULL || id > LCME_ID_MAX || (flags & ~LCME_KNOWN_FLAGS)) {
		errno = EINVAL;
		return -1;
	}

	/* Can only specify ID or flags, not both. */
	if (id != 0 && flags != 0) {
		errno = EINVAL;
		return -1;
	}

	layout = llapi_layout_alloc();
	if (layout == NULL)
		return -1;

	llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL) {
		llapi_layout_free(layout);
		return -1;
	}

	comp->llc_id = id;
	comp->llc_flags = flags;

	lum = llapi_layout_to_lum(layout);
	if (lum == NULL) {
		llapi_layout_free(layout);
		return -1;
	}
	lum_size = ((struct lov_comp_md_v1 *)lum)->lcm_size;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		rc = -1;
		goto out;
	}

	rc = fsetxattr(fd, XATTR_LUSTRE_LOV".del", lum, lum_size, 0);
	if (rc < 0) {
		int tmp_errno = errno;
		close(fd);
		errno = tmp_errno;
		rc = -1;
		goto out;
	}
	close(fd);
out:
	free(lum);
	llapi_layout_free(layout);
	return rc;
}

/**
 * Change flags or other parameters of the component(s) by component ID of an
 * existing file. The component to be modified is specified by the
 * comp->lcme_id value, which must be an unique component ID. The new
 * attributes are passed in by @comp and @valid is used to specify which
 * attributes in the component are going to be changed.
 */
int llapi_layout_file_comp_set(const char *path,
			       const struct llapi_layout *comp,
			       uint32_t valid)
{
	errno = EOPNOTSUPP;
	return -1;
}
