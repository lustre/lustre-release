/* SPDX-License-Identifier: MIT */

/*
 * Copyright (c) 2025 DDN. All rights reserved.
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file.
 */

#include <lustre/lustreapi.h>
#include "wrapper.h"

// These constants are derived from other constants in lustreapi.h.
// bindgen doesn't include them, so we do it here.

#ifdef LLAPI_LAYOUT_WIDE_MIN
__u64 llapi_LAYOUT_WIDE_MIN(void)
{
	return LLAPI_LAYOUT_WIDE_MIN;
}
#endif

#ifdef LLAPI_LAYOUT_WIDE_MAX
__u64 llapi_LAYOUT_WIDE_MAX(void)
{
	 return LLAPI_LAYOUT_WIDE_MAX;
}
#endif

#ifdef LLAPI_OVERSTRIPE_COUNT_MIN
__u64 llapi_OVERSTRIPE_COUNT_MIN(void)
{
	return LLAPI_OVERSTRIPE_COUNT_MIN;
}
#endif

#ifdef LLAPI_OVERSTRIPE_COUNT_MAX
__u64 llapi_OVERSTRIPE_COUNT_MAX(void)
{
	return LLAPI_OVERSTRIPE_COUNT_MAX;
}
#endif

int llapi_O_LOV_DELAY_CREATE(void)
{
	return O_LOV_DELAY_CREATE;
}


// Helper functions to access the hsm_action_list struct
struct hsm_action_item *hai_first__extern(struct hsm_action_list *hal)
{
	return hai_first(hal);
}

struct hsm_action_item *hai_next__extern(struct hsm_action_item *hai)
{
	return hai_next(hai);
}

__kernel_size_t hal_size__extern(struct hsm_action_list *hal)
{
	return hal_size(hal);
}


// Different magic than the copytool one
#define CM_PRIV_MAGIC ((int)0xC0BE2222)


/// This matches hsm_copytool_private and used
/// by movers to communicate with coordinator.

struct hsm_mover_private {
	int				 magic;
	char			*mnt;
	struct kuc_hdr	*kuch; // unused
	int				 mnt_fd;
	int				 open_by_fid_fd;
	struct lustre_kernelcomm	*kuc; // unused
};

// TODO: Remove mover funcs when EX-11759 lands

/// Mostly copied from llapi_hsm_copytool_register.
/// This is essentially creating a copytool with no kuch connecion.

/** Register a mover
 * \param[out] priv		Opaque private control structure
 * \param mnt			Lustre filesystem mount point
 *
 * \retval 0 on success.
 * \retval -errno on error.
 */
int llapi_hsm_mover_register(struct hsm_mover_private **priv,
				const char *mnt)
{
	struct hsm_mover_private	*ct;
	int				 rc;

	ct = calloc(1, sizeof(*ct));
	if (ct == NULL)
		return -ENOMEM;

	ct->magic = CM_PRIV_MAGIC;
	ct->mnt_fd = -1;
	ct->open_by_fid_fd = -1;

	ct->mnt = strdup(mnt);
	if (ct->mnt == NULL) {
		rc = -ENOMEM;
		goto out_err;
	}

	ct->mnt_fd = open(ct->mnt, O_RDONLY);
	if (ct->mnt_fd < 0) {
		rc = -errno;
		goto out_err;
	}

	ct->open_by_fid_fd = openat(ct->mnt_fd, ".lustre/fid", O_RDONLY);
	if (ct->open_by_fid_fd < 0) {
		rc = -errno;
		goto out_err;
	}

	*priv = ct;

	return 0;

out_err:
	if (!(ct->mnt_fd < 0))
		close(ct->mnt_fd);

	if (!(ct->open_by_fid_fd < 0))
		close(ct->open_by_fid_fd);

	free(ct->mnt);

	free(ct);

	return rc;
}

/** Deregister a mover
 */
int llapi_hsm_mover_unregister(struct hsm_mover_private **priv)
{
	struct hsm_mover_private *ct;

	if (priv == NULL || *priv == NULL)
		return -EINVAL;

	ct = *priv;
	if (ct->magic != CM_PRIV_MAGIC)
		return -EINVAL;

	close(ct->open_by_fid_fd);
	close(ct->mnt_fd);
	free(ct->mnt);
	free(ct);
	*priv = NULL;

	return 0;
}
