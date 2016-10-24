/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright (c) 2015, DataDirect Networks Inc, all rights reserved.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * LGPL version 2.1 or (at your discretion) any later version.
 * LGPL version 2.1 accompanies this distribution, and is available at
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
 * lustre/utils/liblustreapi_ladvise.c
 *
 * lustreapi library for ladvise
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
	int rc;
	struct llapi_ladvise_hdr *ladvise_hdr;

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
		llapi_error(LLAPI_MSG_ERROR, -errno, "cannot give advice");
		return -1;
	}
	return 0;
}

