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
 * Copyright (c) 2016, 2017, Intel Corporation.
 *
 * Author: Ned Bass <bass6@llnl.gov>
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <sys/xattr.h>
#include <sys/param.h>

#include <libcfs/util/list.h>
#include <lustre/lustreapi.h>
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
	uint64_t		llc_timestamp;	/* snapshot timestamp */
	struct list_head	llc_list;	/* linked to the llapi_layout
						   components list */
	bool		llc_ondisk;
};

/**
 * An Opaque data type abstracting the layout of a Lustre file.
 */
struct llapi_layout {
	uint32_t	llot_magic; /* LLAPI_LAYOUT_MAGIC */
	uint32_t	llot_gen;
	uint32_t	llot_flags;
	bool		llot_is_composite;
	uint16_t	llot_mirror_count;
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
		comp_v1->lcm_magic = __swab32(comp_v1->lcm_magic);
		comp_v1->lcm_size = __swab32(comp_v1->lcm_size);
		comp_v1->lcm_layout_gen = __swab32(comp_v1->lcm_layout_gen);
		comp_v1->lcm_flags = __swab16(comp_v1->lcm_flags);
		comp_v1->lcm_entry_count = __swab16(comp_v1->lcm_entry_count);
		ent_count = comp_v1->lcm_entry_count;
	} else {
		ent_count = 1;
	}

	for (i = 0; i < ent_count; i++) {
		if (comp_v1 != NULL) {
			ent = &comp_v1->lcm_entries[i];
			ent->lcme_id = __swab32(ent->lcme_id);
			ent->lcme_flags = __swab32(ent->lcme_flags);
			ent->lcme_timestamp = __swab64(ent->lcme_timestamp);
			ent->lcme_extent.e_start = __swab64(ent->lcme_extent.e_start);
			ent->lcme_extent.e_end = __swab64(ent->lcme_extent.e_end);
			ent->lcme_offset = __swab32(ent->lcme_offset);
			ent->lcme_size = __swab32(ent->lcme_size);

			lum = (struct lov_user_md *)((char *)comp_v1 +
					ent->lcme_offset);
			lum_size = ent->lcme_size;
		}
		obj_count = llapi_layout_objects_in_lum(lum, lum_size);

		lum->lmm_magic = __swab32(lum->lmm_magic);
		lum->lmm_pattern = __swab32(lum->lmm_pattern);
		lum->lmm_stripe_size = __swab32(lum->lmm_stripe_size);
		lum->lmm_stripe_count = __swab16(lum->lmm_stripe_count);
		lum->lmm_stripe_offset = __swab16(lum->lmm_stripe_offset);

		if (lum->lmm_magic != LOV_MAGIC_V1) {
			struct lov_user_md_v3 *v3;
			v3 = (struct lov_user_md_v3 *)lum;
			lod = v3->lmm_objects;
		} else {
			lod = lum->lmm_objects;
		}

		for (j = 0; j < obj_count; j++)
			lod[j].l_ost_idx = __swab32(lod[j].l_ost_idx);
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
	layout->llot_mirror_count = 1;
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
 * Convert the data from a lov_user_md to a newly allocated llapi_layout.
 * The caller is responsible for freeing the returned pointer.
 *
 * \param[in] lov_xattr		LOV user metadata xattr to copy data from
 * \param[in] lov_xattr_size	size the lov_xattr_size passed in
 * \param[in] flags		flags to control how layout is retrieved
 *
 * \retval		valid llapi_layout pointer on success
 * \retval		NULL if memory allocation fails
 */
struct llapi_layout *llapi_layout_get_by_xattr(void *lov_xattr,
					      ssize_t lov_xattr_size,
					      enum llapi_layout_get_flags flags)
{
	struct lov_user_md *lum = lov_xattr;
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_comp_md_entry_v1 *ent;
	struct lov_user_md *v1;
	struct llapi_layout *layout = NULL;
	struct llapi_layout_comp *comp;
	int i, ent_count = 0, obj_count;

	if (lov_xattr == NULL || lov_xattr_size <= 0) {
		errno = EINVAL;
		return NULL;
	}

	/* Return an error if we got back a partial layout. */
	if (llapi_layout_lum_truncated(lov_xattr, lov_xattr_size)) {
		errno = ERANGE;
		return NULL;
	}

#if __BYTE_ORDER == __BIG_ENDIAN
	if (flags & LLAPI_LAYOUT_GET_COPY) {
		lum = malloc(lov_xattr_size);
		if (lum == NULL) {
			errno = ENOMEM;
			return NULL;
		}
		memcpy(lum, lov_xattr, lov_xattr_size);
	}
#endif

	llapi_layout_swab_lov_user_md(lum, lov_xattr_size);

#if LUSTRE_VERSION_CODE > OBD_OCD_VERSION(2, 16, 53, 0)
#define LLAPI_LXF_CHECK_OLD 0x0001
	if (flags & LLAPI_LXF_CHECK_OLD)
		flags = (flags & ~LLAPI_LXF_CHECK_OLD) | LLAPI_LAYOUT_GET_CHECK;
#endif
	if ((flags & LLAPI_LAYOUT_GET_CHECK) &&
	    !llapi_layout_lum_valid(lum, lov_xattr_size)) {
		errno = EBADSLT;
		goto out;
	}

	layout = __llapi_layout_alloc();
	if (layout == NULL) {
		errno = ENOMEM;
		goto out;
	}

	if (lum->lmm_magic == LOV_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)lum;
		ent_count = comp_v1->lcm_entry_count;
		layout->llot_gen = comp_v1->lcm_layout_gen;
		layout->llot_is_composite = true;
		layout->llot_mirror_count = comp_v1->lcm_mirror_count + 1;
		layout->llot_gen = comp_v1->lcm_layout_gen;
		layout->llot_flags = comp_v1->lcm_flags;
	} else if (lum->lmm_magic == LOV_MAGIC_V1 ||
		   lum->lmm_magic == LOV_MAGIC_V3) {
		ent_count = 1;
		layout->llot_is_composite = false;

		if (lov_xattr_size <= 0) {
			errno = EINVAL;
			goto out_layout;
		}
	} else {
		errno = EOPNOTSUPP;
		goto out_layout;
	}

	if (ent_count == 0) {
		errno = EINVAL;
		goto out_layout;
	}

	v1 = (struct lov_user_md *)lum;
	for (i = 0; i < ent_count; i++) {
		if (comp_v1 != NULL) {
			ent = &comp_v1->lcm_entries[i];
			v1 = (struct lov_user_md *)((char *)comp_v1 +
				ent->lcme_offset);
			lov_xattr_size = ent->lcme_size;
		} else {
			ent = NULL;
		}

		obj_count = llapi_layout_objects_in_lum(v1, lov_xattr_size);
		comp = __llapi_comp_alloc(obj_count);
		if (comp == NULL)
			goto out_layout;

		if (ent != NULL) {
			comp->llc_extent.e_start = ent->lcme_extent.e_start;
			comp->llc_extent.e_end = ent->lcme_extent.e_end;
			comp->llc_id = ent->lcme_id;
			comp->llc_flags = ent->lcme_flags;
			if (comp->llc_flags & LCME_FL_NOSYNC)
				comp->llc_timestamp = ent->lcme_timestamp;
		} else {
			comp->llc_extent.e_start = 0;
			comp->llc_extent.e_end = LUSTRE_EOF;
			comp->llc_id = 0;
			comp->llc_flags = 0;
		}

		if (v1->lmm_pattern == LOV_PATTERN_RAID0)
			comp->llc_pattern = LLAPI_LAYOUT_RAID0;
		else if (v1->lmm_pattern == (LOV_PATTERN_RAID0 |
					 LOV_PATTERN_OVERSTRIPING))
			comp->llc_pattern = LLAPI_LAYOUT_OVERSTRIPING;
		else if (v1->lmm_pattern == LOV_PATTERN_MDT)
			comp->llc_pattern = LLAPI_LAYOUT_MDT;
		else
			/* Lustre only supports RAID0, overstripping
			 * and DoM for now.
			 */
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

		comp->llc_ondisk = true;
		list_add_tail(&comp->llc_list, &layout->llot_comp_list);
		layout->llot_cur_comp = comp;
	}

out:
	if (lum != lov_xattr)
		free(lum);
	return layout;
out_layout:
	llapi_layout_free(layout);
	layout = NULL;
	goto out;
}

__u32 llapi_pattern_to_lov(uint64_t pattern)
{
	__u32 lov_pattern;

	switch (pattern) {
	case LLAPI_LAYOUT_DEFAULT:
		lov_pattern = LOV_PATTERN_RAID0;
		break;
	case LLAPI_LAYOUT_RAID0:
		lov_pattern = LOV_PATTERN_RAID0;
		break;
	case LLAPI_LAYOUT_MDT:
		lov_pattern = LOV_PATTERN_MDT;
		break;
	case LLAPI_LAYOUT_OVERSTRIPING:
		lov_pattern = LOV_PATTERN_OVERSTRIPING | LOV_PATTERN_RAID0;
		break;
	default:
		lov_pattern = EINVAL;
	}

	return lov_pattern;
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
		lum = calloc(lum_size, 1);
		if (lum == NULL) {
			errno = ENOMEM;
			return NULL;
		}
		comp_v1 = (struct lov_comp_md_v1 *)lum;
		comp_v1->lcm_magic = LOV_USER_MAGIC_COMP_V1;
		comp_v1->lcm_size = lum_size;
		comp_v1->lcm_layout_gen = 0;
		comp_v1->lcm_flags = layout->llot_flags;
		comp_v1->lcm_entry_count = comp_cnt;
		comp_v1->lcm_mirror_count = layout->llot_mirror_count - 1;
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
		blob->lmm_pattern = llapi_pattern_to_lov(pattern);
		if (blob->lmm_pattern == EINVAL) {
			errno = EINVAL;
			goto error;
		}

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
			if (ent->lcme_flags & LCME_FL_NOSYNC)
				ent->lcme_timestamp = comp->llc_timestamp;
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

	strncpy(buf, path, size - 1);
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

	if (layout->llot_is_composite || layout->llot_mirror_count != 1)
		return true;

	return comp->llc_pattern != LLAPI_LAYOUT_DEFAULT ||
	       comp->llc_stripe_size != LLAPI_LAYOUT_DEFAULT ||
	       comp->llc_stripe_count != LLAPI_LAYOUT_DEFAULT ||
	       comp->llc_stripe_offset != LLAPI_LAYOUT_DEFAULT ||
	       strlen(comp->llc_pool_name);
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
struct llapi_layout *llapi_layout_get_by_fd(int fd,
					    enum llapi_layout_get_flags flags)
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

	/* Directories may have a positive non-zero lum->lmm_stripe_count
	 * yet have an empty lum->lmm_objects array. For non-directories the
	 * amount of data returned from the kernel must be consistent
	 * with the stripe count. */
	if (fstat(fd, &st) < 0)
		goto out;

	layout = llapi_layout_get_by_xattr(lum, bytes_read,
			S_ISDIR(st.st_mode) ? 0 : LLAPI_LAYOUT_GET_CHECK);
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
 * If \a flags contains LLAPI_LAYOUT_GET_EXPECTED, substitute
 * expected inherited attribute values for unspecified attributes. See
 * llapi_layout_expected().
 *
 * \param[in] path	path for which to get the layout
 * \param[in] flags	flags to control how layout is retrieved
 *
 * \retval	valid llapi_layout pointer on success
 * \retval	NULL if an error occurs
 */
struct llapi_layout *llapi_layout_get_by_path(const char *path,
					      enum llapi_layout_get_flags flags)
{
	struct llapi_layout *layout = NULL;
	int fd;
	int tmp;

	if (flags & LLAPI_LAYOUT_GET_EXPECTED)
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
					     const struct lu_fid *fid,
					     enum llapi_layout_get_flags flags)
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

bool llapi_layout_stripe_count_is_valid(int64_t stripe_count)
{
	return stripe_count == LLAPI_LAYOUT_DEFAULT ||
		stripe_count == LLAPI_LAYOUT_WIDE ||
		(stripe_count != 0 && stripe_count != -1 &&
		 llapi_stripe_count_is_valid(stripe_count));
}

static bool llapi_layout_extension_size_is_valid(uint64_t ext_size)
{
	return (ext_size != 0 &&
		llapi_stripe_size_is_aligned(ext_size) &&
		!llapi_stripe_size_is_too_big(ext_size));
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
 * Get the stripe/extension size of \a layout.
 *
 * \param[in] layout	layout to get stripe size from
 * \param[out] size	integer to store stripe size in
 * \param[in] extension flag if extenion size is requested
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
static int layout_stripe_size_get(const struct llapi_layout *layout,
				  uint64_t *size, bool extension)
{
	struct llapi_layout_comp *comp;
	int comp_ext;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (size == NULL) {
		errno = EINVAL;
		return -1;
	}

	comp_ext = comp->llc_flags & LCME_FL_EXTENSION;
	if ((comp_ext && !extension) || (!comp_ext && extension)) {
		errno = EINVAL;
		return -1;
	}

	*size = comp->llc_stripe_size;
	if (comp->llc_flags & LCME_FL_EXTENSION)
		*size *= SEL_UNIT_SIZE;

	return 0;
}

int llapi_layout_stripe_size_get(const struct llapi_layout *layout,
				 uint64_t *size)
{
	return layout_stripe_size_get(layout, size, false);
}

int llapi_layout_extension_size_get(const struct llapi_layout *layout,
				    uint64_t *size)
{
	return layout_stripe_size_get(layout, size, true);
}

/**
 * Set the stripe/extension size of \a layout.
 *
 * \param[in] layout	layout to set stripe size in
 * \param[in] size	value to be set
 * \param[in] extension flag if extenion size is passed
 *
 * \retval	0 on success
 * \retval	-1 if arguments are invalid
 */
static int layout_stripe_size_set(struct llapi_layout *layout,
				  uint64_t size, bool extension)
{
	struct llapi_layout_comp *comp;
	int comp_ext;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	comp_ext = comp->llc_flags & LCME_FL_EXTENSION;
	if ((comp_ext && !extension) || (!comp_ext && extension)) {
		errno = EINVAL;
		return -1;
	}

	if (comp_ext)
		size /= SEL_UNIT_SIZE;

	if ((comp_ext && !llapi_layout_extension_size_is_valid(size)) ||
	    (!comp_ext && !llapi_layout_stripe_size_is_valid(size))) {
		errno = EINVAL;
		return -1;
	}

	comp->llc_stripe_size = size;
	return 0;
}

int llapi_layout_stripe_size_set(struct llapi_layout *layout,
				 uint64_t size)
{
	return layout_stripe_size_set(layout, size, false);
}

int llapi_layout_extension_size_set(struct llapi_layout *layout,
				    uint64_t size)
{
	return layout_stripe_size_set(layout, size, true);
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
 * Set the pattern of \a layout.
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
	    pattern != LLAPI_LAYOUT_RAID0 && pattern != LLAPI_LAYOUT_MDT
	    && pattern != LLAPI_LAYOUT_OVERSTRIPING) {
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
			       char *pool_name)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (!llapi_pool_name_is_valid(&pool_name, NULL)) {
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
 * \param[in] mode		permissions to create file, filtered by umask
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

	if (layout) {
		rc = llapi_layout_sanity((struct llapi_layout *)layout,
					 path, false,
					 !!(layout->llot_mirror_count > 1));
		if (rc) {
			llapi_layout_sanity_perror(rc);
			return -1;
		}
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

int llapi_layout_flags_get(struct llapi_layout *layout, uint32_t *flags)
{
	if (layout->llot_magic != LLAPI_LAYOUT_MAGIC) {
		errno = EINVAL;
		return -1;
	}

	*flags = layout->llot_flags;
	return 0;
}

/**
 * Set flags to the header of a component layout.
 */
int llapi_layout_flags_set(struct llapi_layout *layout, uint32_t flags)
{
	if (layout->llot_magic != LLAPI_LAYOUT_MAGIC) {
		errno = EINVAL;
		return -1;
	}

	layout->llot_flags = flags;
	return 0;
}

const char *llapi_layout_flags_string(uint32_t flags)
{
	switch (flags & LCM_FL_FLR_MASK) {
	case LCM_FL_RDONLY:
		return "ro";
	case LCM_FL_WRITE_PENDING:
		return "wp";
	case LCM_FL_SYNC_PENDING:
		return "sp";
	}

	return "0";
}

const __u16 llapi_layout_string_flags(char *string)
{
	if (strncmp(string, "ro", strlen(string)) == 0)
		return LCM_FL_RDONLY;
	if (strncmp(string, "wp", strlen(string)) == 0)
		return LCM_FL_WRITE_PENDING;
	if (strncmp(string, "sp", strlen(string)) == 0)
		return LCM_FL_SYNC_PENDING;

	return 0;
}

/**
 * llapi_layout_mirror_count_is_valid() - Check the validity of mirror count.
 * @count: Mirror count value to be checked.
 *
 * This function checks the validity of mirror count.
 *
 * Return: true on success or false on failure.
 */
static bool llapi_layout_mirror_count_is_valid(uint16_t count)
{
	return count >= 0 && count <= LUSTRE_MIRROR_COUNT_MAX;
}

/**
 * llapi_layout_mirror_count_get() - Get mirror count from the header of
 *				     a layout.
 * @layout: Layout to get mirror count from.
 * @count:  Returned mirror count value.
 *
 * This function gets mirror count from the header of a layout.
 *
 * Return: 0 on success or -1 on failure.
 */
int llapi_layout_mirror_count_get(struct llapi_layout *layout,
				  uint16_t *count)
{
	if (layout->llot_magic != LLAPI_LAYOUT_MAGIC) {
		errno = EINVAL;
		return -1;
	}

	*count = layout->llot_mirror_count;
	return 0;
}

/**
 * llapi_layout_mirror_count_set() - Set mirror count to the header of a layout.
 * @layout: Layout to set mirror count in.
 * @count:  Mirror count value to be set.
 *
 * This function sets mirror count to the header of a layout.
 *
 * Return: 0 on success or -1 on failure.
 */
int llapi_layout_mirror_count_set(struct llapi_layout *layout,
				  uint16_t count)
{
	if (layout->llot_magic != LLAPI_LAYOUT_MAGIC) {
		errno = EINVAL;
		return -1;
	}

	if (!llapi_layout_mirror_count_is_valid(count)) {
		errno = EINVAL;
		return -1;
	}

	layout->llot_mirror_count = count;
	return 0;
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
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (start > end) {
		errno = EINVAL;
		return -1;
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
 * Return the mirror id of the current layout component.
 *
 * \param[in] layout	the layout component
 * \param[out] id	stored the returned mirror ID
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_mirror_id_get(const struct llapi_layout *layout, uint32_t *id)
{
	struct llapi_layout_comp *comp;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	if (id == NULL) {
		errno = EINVAL;
		return -1;
	}

	*id = mirror_id_of(comp->llc_id);

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
	bool composite = layout->llot_is_composite;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	new = __llapi_comp_alloc(0);
	if (new == NULL)
		return -1;

	last = list_entry(layout->llot_comp_list.prev, typeof(*last),
			  llc_list);

	list_add_tail(&new->llc_list, &layout->llot_comp_list);

	/* We must mark the layout composite for the sanity check, but it may
	 * not stay that way if the check fails */
	layout->llot_is_composite = true;
	layout->llot_cur_comp = new;

	/* We need to set a temporary non-zero value for "end" when we call
	 * comp_extent_set, so we use LUSTRE_EOF-1, which is > all allowed
	 * for the end of the previous component.  (If we're adding this
	 * component, the end of the previous component cannot be EOF.) */
	if (llapi_layout_comp_extent_set(layout, last->llc_extent.e_end,
					LUSTRE_EOF - 1)) {
		llapi_layout_comp_del(layout);
		layout->llot_is_composite = composite;
		return -1;
	}

	return 0;
}
/**
 * Adds a first component of a mirror to \a layout.
 * The \a layout will change it's current component pointer to
 * the newly added component, and it'll be turned into a composite
 * layout if it was not before the adding.
 *
 * \param[in] layout		existing composite or plain layout
 *
 * \retval	0 on success
 * \retval	<0 if error occurs
 */
int llapi_layout_add_first_comp(struct llapi_layout *layout)
{
	struct llapi_layout_comp *comp, *new;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL)
		return -1;

	new = __llapi_comp_alloc(0);
	if (new == NULL)
		return -1;

	new->llc_extent.e_start = 0;

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
	layout->llot_cur_comp =
		list_entry(comp->llc_list.prev, typeof(*comp), llc_list);
	if (comp->llc_list.prev == &layout->llot_comp_list)
		layout->llot_cur_comp = NULL;

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
		if (pos == LLAPI_LAYOUT_COMP_USE_FIRST ||
		    pos == LLAPI_LAYOUT_COMP_USE_LAST)
			return 0;
		errno = ENOENT;
		return 1;
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
	int rc, fd = -1, lum_size, tmp_errno = 0;
	struct llapi_layout *existing_layout = NULL;
	struct lov_user_md *lum = NULL;

	if (path == NULL || layout == NULL ||
	    layout->llot_magic != LLAPI_LAYOUT_MAGIC) {
		errno = EINVAL;
		return -1;
	}

	fd = open(path, O_RDWR);
	if (fd < 0) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	existing_layout = llapi_layout_get_by_fd(fd, 0);
	if (existing_layout == NULL) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	rc = llapi_layout_merge(&existing_layout, layout);
	if (rc) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	rc = llapi_layout_sanity(existing_layout, path, false, false);
	if (rc) {
		tmp_errno = errno;
		llapi_layout_sanity_perror(rc);
		rc = -1;
		goto out;
	}

	lum = llapi_layout_to_lum(layout);
	if (lum == NULL) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	if (lum->lmm_magic != LOV_USER_MAGIC_COMP_V1) {
		tmp_errno = EINVAL;
		rc = -1;
		goto out;
	}
	lum_size = ((struct lov_comp_md_v1 *)lum)->lcm_size;

	rc = fsetxattr(fd, XATTR_LUSTRE_LOV".add", lum, lum_size, 0);
	if (rc < 0) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}
out:
	if (fd >= 0)
		close(fd);
	free(lum);
	llapi_layout_free(existing_layout);
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
	int rc = 0, fd = -1, lum_size, tmp_errno = 0;
	struct llapi_layout *layout;
	struct llapi_layout_comp *comp, *next;
	struct llapi_layout *existing_layout = NULL;
	struct lov_user_md *lum = NULL;

	if (path == NULL || id > LCME_ID_MAX || (flags & ~LCME_KNOWN_FLAGS)) {
		errno = EINVAL;
		return -1;
	}

	/* Can only specify ID or flags, not both, not none. */
	if ((id != LCME_ID_INVAL && flags != 0) ||
	    (id == LCME_ID_INVAL && flags == 0)) {
		errno = EINVAL;
		return -1;
	}

	layout = llapi_layout_alloc();
	if (layout == NULL)
		return -1;

	llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	comp->llc_id = id;
	comp->llc_flags = flags;

	lum = llapi_layout_to_lum(layout);
	if (lum == NULL) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}
	lum_size = ((struct lov_comp_md_v1 *)lum)->lcm_size;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	existing_layout = llapi_layout_get_by_fd(fd, 0);
	if (existing_layout == NULL) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	comp = NULL;
	next = NULL;
	while (rc == 0 && existing_layout->llot_cur_comp != NULL) {
		rc = llapi_layout_comp_use(existing_layout, comp ?
					   LLAPI_LAYOUT_COMP_USE_PREV :
					   LLAPI_LAYOUT_COMP_USE_LAST);
		if (rc != 0)
			break;

		next = comp;
		comp = __llapi_layout_cur_comp(existing_layout);
		if (comp == NULL) {
			rc = -1;
			break;
		}

		if (id != LCME_ID_INVAL && id != comp->llc_id)
			continue;
		else if ((flags & LCME_FL_NEG) && (flags & comp->llc_flags))
			continue;
		else if (flags && !(flags & comp->llc_flags))
			continue;

		rc = llapi_layout_comp_del(existing_layout);
		/* the layout position is moved to previous one, adjust */
		comp = next;
	}
	if (rc < 0) {
		tmp_errno = errno;
		goto out;
	}

	rc = llapi_layout_sanity(existing_layout, path, false, false);
	if (rc) {
		tmp_errno = errno;
		llapi_layout_sanity_perror(rc);
		rc = -1;
		goto out;
	}

	rc = fsetxattr(fd, XATTR_LUSTRE_LOV".del", lum, lum_size, 0);
	if (rc < 0) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

out:
	if (fd >= 0)
		close(fd);
	free(lum);
	llapi_layout_free(layout);
	llapi_layout_free(existing_layout);
	errno = tmp_errno;

	return rc;
}

/* Internal utility function to apply flags for sanity checking */
static void llapi_layout_comp_apply_flags(struct llapi_layout_comp *comp,
					  uint32_t flags)
{
	if (flags & LCME_FL_NEG)
		comp->llc_flags &= ~flags;
	else
		comp->llc_flags |= flags;
}

struct llapi_layout_apply_flags_args {
	uint32_t *lfa_ids;
	uint32_t *lfa_flags;
	int lfa_count;
	int lfa_rc;
};


static int llapi_layout_apply_flags_cb(struct llapi_layout *layout,
				       void *arg)
{
	struct llapi_layout_apply_flags_args *args = arg;
	struct llapi_layout_comp *comp;
	int i = 0;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL) {
		args->lfa_rc = -1;
		return LLAPI_LAYOUT_ITER_STOP;
	}

	for (i = 0; i < args->lfa_count; i++) {
		if (comp->llc_id == args->lfa_ids[i])
			llapi_layout_comp_apply_flags(comp, args->lfa_flags[i]);
	}

	return LLAPI_LAYOUT_ITER_CONT;
}

/* Apply flags to the layout for sanity checking */
static int llapi_layout_apply_flags(struct llapi_layout *layout, uint32_t *ids,
				    uint32_t *flags, int count)
{
	struct llapi_layout_apply_flags_args args;
	int rc = 0;

	if (!ids || !flags || count == 0) {
		errno = EINVAL;
		return -1;
	}

	args.lfa_ids = ids;
	args.lfa_flags = flags;
	args.lfa_count = count;
	args.lfa_rc = 0;

	rc = llapi_layout_comp_iterate(layout,
				       llapi_layout_apply_flags_cb,
				       &args);
	if (errno == ENOENT)
		errno = 0;

	if (rc != LLAPI_LAYOUT_ITER_CONT)
		rc = args.lfa_rc;

	return rc;
}
/**
 * Change flags by component ID of components of an existing file.
 * The component to be modified is specified by the comp->lcme_id value,
 * which must be a unique component ID.
 *
 * \param[in] path	path name of the file
 * \param[in] ids	An array of component IDs
 * \param[in] flags	flags: LCME_FL_* or;
 *			negative flags: (LCME_FL_NEG|LCME_FL_*)
 * \param[in] count	Number of elements in ids and flags array
 */
int llapi_layout_file_comp_set(const char *path, uint32_t *ids, uint32_t *flags,
			       size_t count)
{
	int rc = -1, fd = -1, i, tmp_errno = 0;
	size_t lum_size;
	struct llapi_layout *existing_layout = NULL;
	struct llapi_layout *layout = NULL;
	struct llapi_layout_comp *comp;
	struct lov_user_md *lum = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (!count)
		return 0;

	for (i = 0; i < count; i++) {
		if (!ids[i] || !flags[i]) {
			errno = EINVAL;
			return -1;
		}

		if (ids[i] > LCME_ID_MAX || (flags[i] & ~LCME_KNOWN_FLAGS)) {
			errno = EINVAL;
			return -1;
		}

		/* do not allow to set or clear INIT flag */
		if (flags[i] & LCME_FL_INIT) {
			errno = EINVAL;
			return -1;
		}
	}

	fd = open(path, O_RDWR);
	if (fd < 0) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	existing_layout = llapi_layout_get_by_fd(fd, 0);
	if (existing_layout == NULL) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	if (llapi_layout_apply_flags(existing_layout, ids, flags, count)) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	rc = llapi_layout_sanity(existing_layout, path, false, false);
	if (rc) {
		tmp_errno = errno;
		llapi_layout_sanity_perror(rc);
		rc = -1;
		goto out;
	}

	layout = __llapi_layout_alloc();
	if (layout == NULL) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	layout->llot_is_composite = true;
	for (i = 0; i < count; i++) {
		comp = __llapi_comp_alloc(0);
		if (comp == NULL) {
			tmp_errno = errno;
			rc = -1;
			goto out;
		}

		comp->llc_id = ids[i];
		comp->llc_flags = flags[i];

		list_add_tail(&comp->llc_list, &layout->llot_comp_list);
		layout->llot_cur_comp = comp;
	}

	lum = llapi_layout_to_lum(layout);
	if (lum == NULL) {
		tmp_errno = errno;
		rc = -1;
		goto out;
	}

	lum_size = ((struct lov_comp_md_v1 *)lum)->lcm_size;

	/* flush cached pages from clients */
	rc = llapi_file_flush(fd);
	if (rc) {
		tmp_errno = -rc;
		rc = -1;
		goto out;
	}

	rc = fsetxattr(fd, XATTR_LUSTRE_LOV".set.flags", lum, lum_size, 0);
	if (rc < 0) {
		tmp_errno = errno;
		goto out;
	}

	rc = 0;

out:
	if (fd >= 0)
		close(fd);

	free(lum);
	llapi_layout_free(existing_layout);
	llapi_layout_free(layout);
	errno = tmp_errno;
	return rc;
}

/**
 * Check if the file layout is composite.
 *
 * \param[in] layout	the file layout	to check
 *
 * \retval true		composite
 * \retval false	not composite
 */
bool llapi_layout_is_composite(struct llapi_layout *layout)
{
	return layout->llot_is_composite;
}

/**
 * Iterate every components in the @layout and call callback function @cb.
 *
 * \param[in] layout	component layout list.
 * \param[in] cb	callback for each component
 * \param[in] cbdata	callback data
 *
 * \retval < 0				error happens during the iteration
 * \retval LLAPI_LAYOUT_ITER_CONT	finished the iteration w/o error
 * \retval LLAPI_LAYOUT_ITER_STOP	got something, stop the iteration
 */
int llapi_layout_comp_iterate(struct llapi_layout *layout,
			      llapi_layout_iter_cb cb, void *cbdata)
{
	int rc;

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (rc < 0)
		return rc;

	/**
	 * make sure on success llapi_layout_comp_use() API returns 0 with
	 * USE_FIRST.
	 */
	assert(rc == 0);

	while (1) {
		rc = cb(layout, cbdata);
		if (rc != LLAPI_LAYOUT_ITER_CONT)
			break;

		rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
		if (rc < 0)
			return rc;
		else if (rc == 1)	/* reached the last comp */
			return LLAPI_LAYOUT_ITER_CONT;
	}

	return rc;
}

/**
 * llapi_layout_merge() - Merge a composite layout into another one.
 * @dst_layout: Destination composite layout.
 * @src_layout: Source composite layout.
 *
 * This function copies all of the components from @src_layout and
 * appends them to @dst_layout.
 *
 * Return: 0 on success or -1 on failure.
 */
int llapi_layout_merge(struct llapi_layout **dst_layout,
		       const struct llapi_layout *src_layout)
{
	struct llapi_layout *new_layout = *dst_layout;
	struct llapi_layout_comp *new = NULL;
	struct llapi_layout_comp *comp = NULL;
	int i = 0;

	if (src_layout == NULL ||
	    list_empty((struct list_head *)&src_layout->llot_comp_list))
		return 0;

	if (new_layout == NULL) {
		new_layout = __llapi_layout_alloc();
		if (new_layout == NULL) {
			errno = ENOMEM;
			return -1;
		}
	}

	list_for_each_entry(comp, &src_layout->llot_comp_list, llc_list) {
		new = __llapi_comp_alloc(0);
		if (new == NULL) {
			errno = ENOMEM;
			goto error;
		}

		new->llc_pattern = comp->llc_pattern;
		new->llc_stripe_size = comp->llc_stripe_size;
		new->llc_stripe_count = comp->llc_stripe_count;
		new->llc_stripe_offset = comp->llc_stripe_offset;

		if (comp->llc_pool_name[0] != '\0')
			strncpy(new->llc_pool_name, comp->llc_pool_name,
				sizeof(new->llc_pool_name));

		for (i = 0; i < comp->llc_objects_count; i++) {
			if (__llapi_comp_objects_realloc(new,
			    stripe_number_roundup(i)) < 0) {
				errno = EINVAL;
				__llapi_comp_free(new);
				goto error;
			}
			new->llc_objects[i].l_ost_idx = \
				comp->llc_objects[i].l_ost_idx;
		}

		new->llc_objects_count = comp->llc_objects_count;
		new->llc_extent.e_start = comp->llc_extent.e_start;
		new->llc_extent.e_end = comp->llc_extent.e_end;
		new->llc_id = comp->llc_id;
		new->llc_flags = comp->llc_flags;

		list_add_tail(&new->llc_list, &new_layout->llot_comp_list);
		new_layout->llot_cur_comp = new;
	}
	new_layout->llot_is_composite = true;

	*dst_layout = new_layout;
	return 0;
error:
	llapi_layout_free(new_layout);
	return -1;
}

/**
 * Get the last initialized component
 *
 * \param[in] layout	component layout list.
 *
 * \retval 0		found
 * \retval -EINVAL	not found
 * \retval -EISDIR	directory layout
 */
int llapi_layout_get_last_init_comp(struct llapi_layout *layout)
{
	struct llapi_layout_comp *comp = NULL, *head = NULL;

	if (!layout->llot_is_composite)
		return 0;

	head = list_entry(layout->llot_comp_list.next, typeof(*comp), llc_list);
	if (head == NULL)
		return -EINVAL;
	if (head->llc_id == 0 && !(head->llc_flags & LCME_FL_INIT))
		/* a directory */
		return -EISDIR;

	/* traverse the components from the tail to find the last init one */
	comp = list_entry(layout->llot_comp_list.prev, typeof(*comp), llc_list);
	while (comp != head) {
		if (comp->llc_flags & LCME_FL_INIT)
			break;
		comp = list_entry(comp->llc_list.prev, typeof(*comp), llc_list);
	}

	layout->llot_cur_comp = comp;

	return comp->llc_flags & LCME_FL_INIT ? 0 : -EINVAL;
}

/**
 * Interit stripe info from the file's component to the mirror
 *
 * \param[in] layout	file component layout list.
 * \param[in] layout	mirro component layout list.
 *
 * \retval 0		on success
 * \retval -EINVAL	on error
 */
int llapi_layout_mirror_inherit(struct llapi_layout *f_layout,
				struct llapi_layout *m_layout)
{
	struct llapi_layout_comp *m_comp = NULL;
	struct llapi_layout_comp *f_comp = NULL;
	int rc = 0;

	f_comp = __llapi_layout_cur_comp(f_layout);
	if (f_comp == NULL)
		return -EINVAL;
	m_comp = __llapi_layout_cur_comp(m_layout);
	if (m_comp == NULL)
		return -EINVAL;

	m_comp->llc_stripe_size = f_comp->llc_stripe_size;
	m_comp->llc_stripe_count = f_comp->llc_stripe_count;

	return rc;
}

/**
 * Find all stale components.
 *
 * \param[in] layout		component layout list.
 * \param[out] comp		array of stale component info.
 * \param[in] comp_size		array size of @comp.
 * \param[in] mirror_ids	array of mirror id that only components
 *				belonging to these mirror will be collected.
 * \param[in] ids_nr		number of mirror ids array.
 *
 * \retval		number of component info collected on sucess or
 *			an error code on failure.
 */
int llapi_mirror_find_stale(struct llapi_layout *layout,
		struct llapi_resync_comp *comp, size_t comp_size,
		__u16 *mirror_ids, int ids_nr)
{
	int idx = 0;
	int rc;

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (rc < 0)
		goto error;

	while (rc == 0) {
		uint32_t id;
		uint32_t mirror_id;
		uint32_t flags;
		uint64_t start, end;

		rc = llapi_layout_comp_flags_get(layout, &flags);
		if (rc < 0)
			goto error;

		if (!(flags & LCME_FL_STALE))
			goto next;

		rc = llapi_layout_mirror_id_get(layout, &mirror_id);
		if (rc < 0)
			goto error;

		/* the caller only wants stale components from specific
		 * mirrors */
		if (ids_nr > 0) {
			int j;

			for (j = 0; j < ids_nr; j++) {
				if (mirror_ids[j] == mirror_id)
					break;
			}

			/* not in the specified mirror */
			if (j == ids_nr)
				goto next;
		} else if (flags & LCME_FL_NOSYNC) {
			/* if not specified mirrors, do not resync "nosync"
			 * mirrors */
			goto next;
		}

		rc = llapi_layout_comp_id_get(layout, &id);
		if (rc < 0)
			goto error;

		rc = llapi_layout_comp_extent_get(layout, &start, &end);
		if (rc < 0)
			goto error;

		/* pack this component into @comp array */
		comp[idx].lrc_id = id;
		comp[idx].lrc_mirror_id = mirror_id;
		comp[idx].lrc_start = start;
		comp[idx].lrc_end = end;
		idx++;

		if (idx >= comp_size) {
			rc = -EINVAL;
			goto error;
		}

	next:
		rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
		if (rc < 0) {
			rc = -EINVAL;
			goto error;
		}
	}
error:
	return rc < 0 ? rc : idx;
}

/* locate @layout to a valid component covering file [file_start, file_end) */
uint32_t llapi_mirror_find(struct llapi_layout *layout,
			   uint64_t file_start, uint64_t file_end,
			   uint64_t *endp)
{
	uint32_t mirror_id = 0;
	int rc;

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (rc < 0)
		return rc;

	*endp = 0;
	while (rc == 0) {
		uint64_t start, end;
		uint32_t flags, id, rid;

		rc = llapi_layout_comp_flags_get(layout, &flags);
		if (rc < 0)
			return rc;

		if (flags & LCME_FL_STALE)
			goto next;

		rc = llapi_layout_mirror_id_get(layout, &rid);
		if (rc < 0)
			return rc;

		rc = llapi_layout_comp_id_get(layout, &id);
		if (rc < 0)
			return rc;

		rc = llapi_layout_comp_extent_get(layout, &start, &end);
		if (rc < 0)
			return rc;

		if (file_start >= start && file_start < end) {
			if (!mirror_id)
				mirror_id = rid;
			else if (mirror_id != rid || *endp != start)
				break;

			file_start = *endp = end;
			if (end >= file_end)
				break;
		}

	next:
		rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
		if (rc < 0)
			return rc;
	}
	if (!mirror_id)
		return -ENOENT;

	return mirror_id;
}

int llapi_mirror_resync_many(int fd, struct llapi_layout *layout,
			     struct llapi_resync_comp *comp_array,
			     int comp_size,  uint64_t start, uint64_t end)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	const size_t buflen = 4 << 20; /* 4M */
	void *buf;
	uint64_t pos = start;
	uint64_t data_off = pos, data_end = pos;
	uint32_t src = 0;
	int i;
	int rc;
	int rc2 = 0;

	rc = posix_memalign(&buf, page_size, buflen);
	if (rc)
		return -rc;

	while (pos < end) {
		uint64_t mirror_end;
		ssize_t bytes_read;
		size_t to_read;
		size_t to_write;

		if (pos >= data_end) {
			off_t tmp_off;
			size_t data_size;

			if (pos >= mirror_end || !src) {
				rc = llapi_mirror_find(layout, pos, end,
							&mirror_end);
				if (rc < 0)
					return rc;
				src = rc;
				/* restrict mirror end by resync end */
				mirror_end = MIN(end, mirror_end);
			}

			tmp_off = llapi_mirror_data_seek(fd, src, pos,
							 &data_size);
			if (tmp_off < 0) {
				/* switch to full copy */
				to_read = mirror_end - pos;
				goto do_read;
			}
			data_off = tmp_off;
			data_end = data_off + data_size;

			data_off = MIN(data_off, mirror_end);
			data_end = MIN(data_end, mirror_end);

			/* align by page, if there is data block to copy */
			if (data_size)
				data_off &= ~(page_size - 1);
		}

		if (pos < data_off) {
			for (i = 0; i < comp_size; i++) {
				uint64_t cur_pos;
				size_t to_punch;
				uint32_t mid = comp_array[i].lrc_mirror_id;

				/* skip non-overlapped component */
				if (pos >= comp_array[i].lrc_end ||
				    data_off <= comp_array[i].lrc_start)
					continue;

				if (pos < comp_array[i].lrc_start)
					cur_pos = comp_array[i].lrc_start;
				else
					cur_pos = pos;

				if (data_off > comp_array[i].lrc_end)
					to_punch = comp_array[i].lrc_end -
						   cur_pos;
				else
					to_punch = data_off - cur_pos;

				if (comp_array[i].lrc_end == OBD_OBJECT_EOF) {
					/* the last component can be truncated
					 * safely
					 */
					rc = llapi_mirror_truncate(fd, mid,
								   cur_pos);
					/* hole at the end of file, so just
					 * truncate up to set size.
					 */
					if (!rc && data_off == data_end)
						rc = llapi_mirror_truncate(fd,
								mid, data_end);
				} else {
					rc = llapi_mirror_punch(fd,
						comp_array[i].lrc_mirror_id,
						cur_pos, to_punch);
				}
				/* if failed then read failed hole range */
				if (rc < 0) {
					rc = 0;
					pos = cur_pos;
					if (pos + to_punch == data_off)
						to_read = data_end - pos;
					else
						to_read = to_punch;
					goto do_read;
				}
			}
			pos = data_off;
		}
		if (pos == mirror_end)
			continue;
		to_read = data_end - pos;
do_read:
		if (!to_read)
			break;

		assert(data_end <= mirror_end);

		to_read = MIN(buflen, to_read);
		to_read = ((to_read - 1) | (page_size - 1)) + 1;
		bytes_read = llapi_mirror_read(fd, src, buf, to_read, pos);
		if (bytes_read == 0) {
			/* end of file */
			break;
		}
		if (bytes_read < 0) {
			rc = bytes_read;
			break;
		}

		/* round up to page align to make direct IO happy. */
		to_write = ((bytes_read - 1) | (page_size - 1)) + 1;

		for (i = 0; i < comp_size; i++) {
			ssize_t written;
			off_t pos2 = pos;
			size_t to_write2 = to_write;

			/* skip non-overlapped component */
			if (pos >= comp_array[i].lrc_end ||
			    pos + to_write <= comp_array[i].lrc_start)
				continue;

			if (pos < comp_array[i].lrc_start)
				pos2 = comp_array[i].lrc_start;

			to_write2 -= pos2 - pos;

			if ((pos + to_write) > comp_array[i].lrc_end)
				to_write2 -= pos + to_write -
					     comp_array[i].lrc_end;

			written = llapi_mirror_write(fd,
					comp_array[i].lrc_mirror_id,
					buf + pos2 - pos,
					to_write2, pos2);
			if (written < 0) {
				/**
				 * this component is not written successfully,
				 * mark it using its lrc_synced, it is supposed
				 * to be false before getting here.
				 *
				 * And before this function returns, all
				 * elements of comp_array will reverse their
				 * lrc_synced flag to reflect their true
				 * meanings.
				 */
				comp_array[i].lrc_synced = true;
				llapi_error(LLAPI_MSG_ERROR, written,
					    "component %u not synced",
					    comp_array[i].lrc_id);
				if (rc2 == 0)
					rc2 = (int)written;
				continue;
			}
			assert(written == to_write2);
		}
		pos += bytes_read;
	}

	free(buf);

	if (rc < 0) {
		/* fatal error happens */
		for (i = 0; i < comp_size; i++)
			comp_array[i].lrc_synced = false;
		return rc;
	}

	/**
	 * no fatal error happens, each lrc_synced tells whether the component
	 * has been resync successfully (note: we'd reverse the value to
	 * reflect its true meaning.
	 */
	for (i = 0; i < comp_size; i++) {
		comp_array[i].lrc_synced = !comp_array[i].lrc_synced;
		if (comp_array[i].lrc_synced && pos & (page_size - 1)) {
			rc = llapi_mirror_truncate(fd,
					comp_array[i].lrc_mirror_id, pos);
			if (rc < 0)
				comp_array[i].lrc_synced = false;
		}
	}

	/**
	 * returns the first error code for partially successful resync if
	 * possible.
	 */
	return rc2;
}

enum llapi_layout_comp_sanity_error {
	LSE_OK,
	LSE_INCOMPLETE_MIRROR,
	LSE_ADJACENT_EXTENSION,
	LSE_INIT_EXTENSION,
	LSE_FLAGS,
	LSE_DOM_EXTENSION,
	LSE_DOM_EXTENSION_FOLLOWING,
	LSE_DOM_FIRST,
	LSE_SET_COMP_START,
	LSE_NOT_ZERO_LENGTH_EXTENDABLE,
	LSE_END_NOT_GREATER,
	LSE_ZERO_LENGTH_NORMAL,
	LSE_NOT_ADJACENT_PREV,
	LSE_START_GT_END,
	LSE_ALIGN_END,
	LSE_ALIGN_EXT,
	LSE_UNKNOWN_OST,
	LSE_LAST,
};

const char *const llapi_layout_strerror[] =
{
	[LSE_OK] = "",
	[LSE_INCOMPLETE_MIRROR] =
		"Incomplete mirror - must go to EOF",
	[LSE_ADJACENT_EXTENSION] =
		"No adjacent extension space components",
	[LSE_INIT_EXTENSION] =
		"Cannot apply extension flag to init components",
	[LSE_FLAGS] =
		"Wrong flags",
	[LSE_DOM_EXTENSION] =
		"DoM components can't be extension space",
	[LSE_DOM_EXTENSION_FOLLOWING] =
		"DoM components cannot be followed by extension space",
	[LSE_DOM_FIRST] =
		"DoM component should be the first one in a file/mirror",
	[LSE_SET_COMP_START] =
		"Must set previous component extent before adding next",
	[LSE_NOT_ZERO_LENGTH_EXTENDABLE] =
		"Extendable component must start out zero-length",
	[LSE_END_NOT_GREATER] =
		"Component end is before end of previous component",
	[LSE_ZERO_LENGTH_NORMAL] =
		"Zero length components must be followed by extension",
	[LSE_NOT_ADJACENT_PREV] =
		"Components not adjacent (end != next->start",
	[LSE_START_GT_END] =
		"Component start is > end",
	[LSE_ALIGN_END] =
		"The component end must be aligned by the stripe size",
	[LSE_ALIGN_EXT] =
		"The extension size must be aligned by the stripe size",
	[LSE_UNKNOWN_OST] =
		"An unknown OST idx is specified",
};

struct llapi_layout_sanity_args {
	char lsa_fsname[MAX_OBD_NAME + 1];
	bool lsa_incomplete;
	bool lsa_flr;
	bool lsa_ondisk;
	int lsa_rc;
};

/* The component flags can be set by users at creation/modification time. */
#define LCME_USER_COMP_FLAGS	(LCME_FL_PREF_RW | LCME_FL_NOSYNC | \
				 LCME_FL_EXTENSION)

/**
 * When modified, adjust llapi_stripe_param_verify() if needed as well.
 */
static int llapi_layout_sanity_cb(struct llapi_layout *layout,
				  void *arg)
{
	struct llapi_layout_comp *comp, *next, *prev;
	struct llapi_layout_sanity_args *args = arg;
	bool first_comp = false;

	comp = __llapi_layout_cur_comp(layout);
	if (comp == NULL) {
		args->lsa_rc = -1;
		goto out_err;
	}

	if (comp->llc_list.prev != &layout->llot_comp_list)
		prev = list_entry(comp->llc_list.prev, typeof(*prev),
				  llc_list);
	else
		prev = NULL;

	if (comp->llc_list.next != &layout->llot_comp_list)
		next = list_entry(comp->llc_list.next, typeof(*next),
				  llc_list);
	else
		next = NULL;

	/* Start of zero implies a new mirror */
	if (comp->llc_extent.e_start == 0) {
		first_comp = true;
		/* Most checks apply only within one mirror, this is an
		 * exception. */
		if (prev && prev->llc_extent.e_end != LUSTRE_EOF) {
			args->lsa_rc = LSE_INCOMPLETE_MIRROR;
			goto out_err;
		}

		prev = NULL;
	}

	if (next && next->llc_extent.e_start == 0)
		next = NULL;

	/* Flag sanity checks */
	/* No adjacent extension components */
	if ((comp->llc_flags & LCME_FL_EXTENSION) && next &&
	    (next->llc_flags & LCME_FL_EXTENSION)) {
		args->lsa_rc = LSE_ADJACENT_EXTENSION;
		goto out_err;
	}

	/* Extension flag cannot be applied to init components and the first
	 * component of each mirror is automatically init */
	if ((comp->llc_flags & LCME_FL_EXTENSION) &&
	    (comp->llc_flags & LCME_FL_INIT || first_comp)) {
		args->lsa_rc = LSE_INIT_EXTENSION;
		goto out_err;
	}

	if (comp->llc_ondisk) {
		if (comp->llc_flags & LCME_FL_NEG)
			args->lsa_rc = LSE_FLAGS;
	} else if (!args->lsa_incomplete) {
		if (args->lsa_flr) {
			if (comp->llc_flags & ~LCME_USER_COMP_FLAGS)
				args->lsa_rc = LSE_FLAGS;
		} else {
			if (comp->llc_flags &
			    ~(LCME_FL_EXTENSION | LCME_FL_PREF_RW))
				args->lsa_rc = LSE_FLAGS;
		}
	}
	if (args->lsa_rc)
		goto out_err;

	/* DoM sanity checks */
	if (comp->llc_pattern == LLAPI_LAYOUT_MDT ||
	    comp->llc_pattern == LOV_PATTERN_MDT) {
		/* DoM components can't be extension components */
		if (comp->llc_flags & LCME_FL_EXTENSION) {
			args->lsa_rc = LSE_DOM_EXTENSION;
			goto out_err;
		}
		/* DoM components cannot be followed by an extension comp */
		if (next && (next->llc_flags & LCME_FL_EXTENSION)) {
			args->lsa_rc = LSE_DOM_EXTENSION_FOLLOWING;
			goto out_err;
		}

		/* DoM should be the first component in a mirror */
		if (!first_comp) {
			args->lsa_rc = LSE_DOM_FIRST;
			errno = EINVAL;
			goto out_err;
		}
	}

	/* Extent sanity checks */
	/* Must set previous component extent before adding another */
	if (prev && prev->llc_extent.e_start == 0 &&
	    prev->llc_extent.e_end == 0) {
		args->lsa_rc = LSE_SET_COMP_START;
		goto out_err;
	}

	if (!args->lsa_incomplete) {
		/* Components followed by extension space (extendable
		 * components) must be zero length before initialization.
		 * (Except for first comp, which will be initialized on
		 * creation). */
		if (next && (next->llc_flags & LCME_FL_EXTENSION) &&
		    !first_comp && !(comp->llc_flags & LCME_FL_INIT) &&
		    comp->llc_extent.e_start != comp->llc_extent.e_end) {
			args->lsa_rc = LSE_NOT_ZERO_LENGTH_EXTENDABLE;
			goto out_err;
		}

		/* End must come after end of previous comp */
		if (prev && comp->llc_extent.e_end < prev->llc_extent.e_end) {
			args->lsa_rc = LSE_END_NOT_GREATER;
			goto out_err;
		}

		/* Components not followed by ext space must have length > 0. */
		if (comp->llc_extent.e_start == comp->llc_extent.e_end &&
		    (next == NULL || !(next->llc_flags & LCME_FL_EXTENSION))) {
			args->lsa_rc = LSE_ZERO_LENGTH_NORMAL;
			goto out_err;
		}

		/* The component end must be aligned by the stripe size */
		if ((comp->llc_flags & LCME_FL_EXTENSION) &&
		    (prev->llc_stripe_size != LLAPI_LAYOUT_DEFAULT)) {
			if (comp->llc_extent.e_end != LUSTRE_EOF &&
			    comp->llc_extent.e_end % prev->llc_stripe_size) {
				args->lsa_rc = LSE_ALIGN_END;
				goto out_err;
			}
			if ((comp->llc_stripe_size * SEL_UNIT_SIZE) %
			    prev->llc_stripe_size) {
				args->lsa_rc = LSE_ALIGN_EXT;
				goto out_err;
			}
		} else if (!(comp->llc_flags & LCME_FL_EXTENSION) &&
			   (comp->llc_stripe_size != LLAPI_LAYOUT_DEFAULT)) {
			if (comp->llc_extent.e_end != LUSTRE_EOF &&
			    comp->llc_extent.e_end !=
			    comp->llc_extent.e_start &&
			    comp->llc_extent.e_end % comp->llc_stripe_size) {
				args->lsa_rc = LSE_ALIGN_END;
				goto out_err;
			}
		}
	}

	/* Components must have start == prev->end */
	if (prev && comp->llc_extent.e_start != 0 &&
	    comp->llc_extent.e_start != prev->llc_extent.e_end) {
		args->lsa_rc = LSE_NOT_ADJACENT_PREV;
		goto out_err;
	}

	/* Components must have start <= end */
	if (comp->llc_extent.e_start > comp->llc_extent.e_end) {
		args->lsa_rc = LSE_START_GT_END;
		goto out_err;
	}

	if (args->lsa_fsname[0] != '\0') {
		int i, rc = 0;

		if (comp->llc_pattern & LLAPI_LAYOUT_SPECIFIC) {
			assert(comp->llc_stripe_count <=
			       comp->llc_objects_count);

			for (i = 0; i < comp->llc_stripe_count && rc == 0; i++){
				if (comp->llc_objects[i].l_ost_idx ==
				    LLAPI_LAYOUT_IDX_MAX) {
					args->lsa_rc = -1;
					goto out_err;
				}
				rc = llapi_layout_search_ost(
					comp->llc_objects[i].l_ost_idx,
					comp->llc_pool_name, args->lsa_fsname);
			}
		} else if (comp->llc_stripe_offset != LLAPI_LAYOUT_DEFAULT) {
			rc = llapi_layout_search_ost(
				comp->llc_stripe_offset,
				comp->llc_pool_name, args->lsa_fsname);
		}
		if (rc) {
			args->lsa_rc = LSE_UNKNOWN_OST;
			goto out_err;
		}
	}

	return LLAPI_LAYOUT_ITER_CONT;

out_err:
	errno = errno ? errno : EINVAL;
	return LLAPI_LAYOUT_ITER_STOP;
}

/* Print explanation of layout error */
void llapi_layout_sanity_perror(int error)
{
	if (error >= LSE_LAST || error < 0) {
		fprintf(stdout, "Invalid layout, unrecognized error: %d\n",
			error);
	} else {
		fprintf(stdout, "Invalid layout: %s\n",
			llapi_layout_strerror[error]);
	}
}

/* Walk a layout and enforce sanity checks that apply to > 1 component
 *
 * The core idea here is that of sanity checking individual tokens vs semantic
 * checking.
 * We cannot check everything at the individual component level ('token'),
 * instead we must check whether or not the full layout has a valid meaning.
 *
 * An example of a component level check is "is stripe size valid?".  That is
 * handled when setting stripe size.
 *
 * An example of a layout level check is "are the extents of these components
 * valid when adjacent to one another", or "can we set these flags on adjacent
 * components"?
 *
 * \param[in] layout            component layout list.
 * \param[in] fname		file the layout to be checked for
 * \param[in] incomplete        if layout is complete or not - some checks can
 *                              only be done on complete layouts.
 * \param[in] flr		set when this is called from FLR mirror create
 *
 * \retval                      0, success, positive: various errors, see
 *                              llapi_layout_sanity_perror, -1, failure
 */
int llapi_layout_sanity(struct llapi_layout *layout,
			const char *fname,
			bool incomplete,
			bool flr)
{
	struct llapi_layout_sanity_args args = { { 0 } };
	struct llapi_layout_comp *curr;
	int rc = 0;

	if (!layout)
		return 0;

	curr = layout->llot_cur_comp;
	if (!curr)
		return 0;

	/* Make sure we are on a Lustre file system */
	if (fname) {
		rc = llapi_search_fsname(fname, args.lsa_fsname);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "'%s' is not on a Lustre filesystem",
				    fname);
			return rc;
		}
	}

	/* Set up args */
	args.lsa_rc = 0;
	args.lsa_flr = flr;
	args.lsa_incomplete = incomplete;

	/* When we modify an existing layout, this tells us if it's FLR */
	if (mirror_id_of(curr->llc_id) > 0)
		args.lsa_flr = true;

	errno = 0;
	rc = llapi_layout_comp_iterate(layout,
				       llapi_layout_sanity_cb,
				       &args);
	if (errno == ENOENT)
		errno = 0;

	if (rc != LLAPI_LAYOUT_ITER_CONT)
		rc = args.lsa_rc;

	layout->llot_cur_comp = curr;

	return rc;
}

int llapi_layout_dom_size(struct llapi_layout *layout, uint64_t *size)
{
	uint64_t pattern, start;
	int rc;

	if (!layout || !llapi_layout_is_composite(layout)) {
		*size = 0;
		return 0;
	}

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (rc)
		return -errno;

	rc = llapi_layout_pattern_get(layout, &pattern);
	if (rc)
		return -errno;

	if (pattern != LOV_PATTERN_MDT && pattern != LLAPI_LAYOUT_MDT) {
		*size = 0;
		return 0;
	}

	rc = llapi_layout_comp_extent_get(layout, &start, size);
	if (rc)
		return -errno;
	if (start)
		return -ERANGE;
	return 0;
}

int lov_comp_md_size(struct lov_comp_md_v1 *lcm)
{
	if (lcm->lcm_magic == LOV_MAGIC_V1 || lcm->lcm_magic == LOV_MAGIC_V3) {
		struct lov_user_md *lum = (void *)lcm;

		return lov_user_md_size(lum->lmm_stripe_count, lum->lmm_magic);
	}

	if (lcm->lcm_magic == LOV_MAGIC_FOREIGN) {
		struct lov_foreign_md *lfm = (void *)lcm;

		return lfm->lfm_length;
	}

	if (lcm->lcm_magic != LOV_MAGIC_COMP_V1)
		return -EOPNOTSUPP;

	return lcm->lcm_size;
}

int llapi_get_lum_file_fd(int dir_fd, const char *fname, __u64 *valid,
			  lstatx_t *statx, struct lov_user_md *lum,
			  size_t lumsize)
{
	struct lov_user_mds_data *lmd;
	char buf[65536 + offsetof(typeof(*lmd), lmd_lmm)];
	int parent_fd = -1;
	int rc;

	if (lum && lumsize < sizeof(*lum))
		return -EINVAL;

	/* If a file name is provided, it is relative to the parent directory */
	if (fname) {
		parent_fd = dir_fd;
		dir_fd = -1;
	}

	lmd = (struct lov_user_mds_data *)buf;
	rc = get_lmd_info_fd(fname, parent_fd, dir_fd, buf, sizeof(buf),
			     GET_LMD_INFO);
	if (rc)
		return rc;

	if (valid)
		*valid = lmd->lmd_flags;

	if (statx)
		memcpy(statx, &lmd->lmd_stx, sizeof(*statx));

	if (lum) {
		if (lmd->lmd_lmmsize > lumsize)
			return -EOVERFLOW;
		memcpy(lum, &lmd->lmd_lmm, lmd->lmd_lmmsize);
	}

	return 0;
}

int llapi_get_lum_dir_fd(int dir_fd, __u64 *valid, lstatx_t *statx,
			 struct lov_user_md *lum, size_t lumsize)
{
	return llapi_get_lum_file_fd(dir_fd, NULL, valid, statx, lum, lumsize);
}

int llapi_get_lum_file(const char *path, __u64 *valid, lstatx_t *statx,
		       struct lov_user_md *lum, size_t lumsize)
{
	char parent[PATH_MAX];
	const char *fname;
	char *tmp;
	int offset;
	int dir_fd;
	int rc;

	tmp = strrchr(path, '/');
	if (!tmp) {
		strncpy(parent, ".", sizeof(parent) - 1);
		offset = -1;
	} else {
		strncpy(parent, path, tmp - path);
		offset = tmp - path - 1;
		parent[tmp - path] = 0;
	}

	fname = path;
	if (offset >= 0)
		fname += offset + 2;

	dir_fd = open(parent, O_RDONLY);
	if (dir_fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'", path);
		return rc;
	}

	rc = llapi_get_lum_file_fd(dir_fd, fname, valid, statx, lum, lumsize);
	close(dir_fd);
	return rc;
}

int llapi_get_lum_dir(const char *path, __u64 *valid, lstatx_t *statx,
		      struct lov_user_md *lum, size_t lumsize)
{
	int dir_fd;
	int rc;

	dir_fd = open(path, O_RDONLY);
	if (dir_fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'", path);
		return rc;
	}

	rc = llapi_get_lum_dir_fd(dir_fd, valid, statx, lum, lumsize);
	close(dir_fd);
	return rc;
}
