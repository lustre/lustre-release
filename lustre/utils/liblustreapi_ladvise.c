// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2015, DataDirect Networks, Inc, all rights reserved.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * library for passing file access advice from applications to storage
 *
 * Author: Li Xi <lixi@ddn.com>
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <lustre/lustreapi.h>
#include "lustreapi_internal.h"

/*
 * Give file access advices
 *
 * \param fd       File to give advice on.
 * \param ladvise  Advice to give.
 *
 * \retval 0 on success.
 * \retval -1 on failure, errno set
 */
int llapi_ladvise(int fd, unsigned long long flags, int num_advise,
		  struct llapi_lu_ladvise *ladvise)
{
	struct llapi_ladvise_hdr *ladvise_hdr;
	int rc;
	int i;

	if (num_advise < 1 || num_advise >= LAH_COUNT_MAX) {
		errno = EINVAL;
		llapi_error(LLAPI_MSG_ERROR, -EINVAL,
			    "bad advice number %d", num_advise);
		return -1;
	}

	ladvise_hdr = calloc(1, offsetof(typeof(*ladvise_hdr),
			     lah_advise[num_advise]));
	if (ladvise_hdr == NULL) {
		errno = ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM, "not enough memory");
		return -1;
	}
	ladvise_hdr->lah_magic = LADVISE_MAGIC;
	ladvise_hdr->lah_count = num_advise;
	ladvise_hdr->lah_flags = flags & LF_MASK;
	memcpy(ladvise_hdr->lah_advise, ladvise, sizeof(*ladvise) * num_advise);

	rc = ioctl(fd, LL_IOC_LADVISE, ladvise_hdr);
	if (rc < 0) {
		/* replace NFS error code with correct one */
		if (errno == ENOTSUP)
			errno = EOPNOTSUPP;
		llapi_error(LLAPI_MSG_ERROR, -errno, "cannot give advice");
		goto out;
	} else {
		rc = 0;
	}

	/* Copy results back in to caller provided structs */
	for (i = 0; i < num_advise; i++) {
		struct llapi_lu_ladvise *ladvise_iter;

		ladvise_iter = &ladvise_hdr->lah_advise[i];

		if (ladvise_iter->lla_advice == LU_LADVISE_LOCKAHEAD)
			ladvise[i].lla_lockahead_result =
					ladvise_iter->lla_lockahead_result;
	}

out:
	free(ladvise_hdr);
	return rc;
}

