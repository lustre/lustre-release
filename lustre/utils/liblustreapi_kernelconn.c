// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 *
 * Kernel <-> userspace communication routines.
 * Using pipes for all arches.
 */

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include <lustre/lustreapi.h>

#include "lustreapi_internal.h"

/** Start the userspace side of a KUC pipe.
 * @param link Private descriptor for pipe/socket.
 * @param groups KUC broadcast group to listen to
 *          (can be null for unicast to this pid)
 * @param rfd_flags flags for read side of pipe (e.g. O_NONBLOCK)
 */
int libcfs_ukuc_start(struct lustre_kernelcomm *link,
		      int group, int rfd_flags)
{
	int pfd[2];
	int rc;

	link->lk_rfd = link->lk_wfd = LK_NOFD;

	if (pipe(pfd) < 0)
		return -errno;

	if (fcntl(pfd[0], F_SETFL, rfd_flags) < 0) {
		rc = -errno;
		close(pfd[0]);
		close(pfd[1]);
		return rc;
	}

	memset(link, 0, sizeof(*link));
	link->lk_rfd = pfd[0];
	link->lk_wfd = pfd[1];
	link->lk_group = group;
	link->lk_uid = getpid();
	return 0;
}

int libcfs_ukuc_stop(struct lustre_kernelcomm *link)
{
	int rc;

	if (link->lk_wfd != LK_NOFD)
		close(link->lk_wfd);
	rc = close(link->lk_rfd);
	link->lk_rfd = link->lk_wfd = LK_NOFD;
	return rc;
}

/** Returns the file descriptor for the read side of the pipe,
 *  to be used with poll/select.
 * @param link Private descriptor for pipe/socket.
 */
int libcfs_ukuc_get_rfd(struct lustre_kernelcomm *link)
{
	return link->lk_rfd;
}

#define lhsz sizeof(*kuch)

/* Read exactly @count bytes from the pipe into @buf, looping over short
 * reads. Returns 0 on success, a negative errno on failure.
 */
static int ukuc_full_read(int fd, char *buf, size_t count)
{
	size_t total = 0;

	while (total < count) {
		ssize_t rc = read(fd, buf + total, count - total);

		if (rc > 0) {
			total += rc;
		} else if (rc == 0) {
			return -EPIPE;
		} else if (errno == EINTR) {
			continue;
		} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			struct pollfd pfd = { .fd = fd, .events = POLLIN };

			/* No bytes yet: propagate EAGAIN so that O_NONBLOCK
			 * callers multiplexing with poll(2) keep working.
			 */
			if (total == 0)
				return -EAGAIN;

			/* Mid-message: we have already consumed part of a
			 * framed message and must finish it to stay in sync.
			 * Wait for the remainder.
			 */
			if (poll(&pfd, 1, -1) < 0 && errno != EINTR)
				return -errno;
		} else {
			return -errno;
		}
	}
	return 0;
}

/** Read a message from the link.
 * Reads one complete message into @a buf (caller-allocated).
 *
 * @param link Private descriptor for pipe/socket.
 * @param buf Buffer to read into, must include size for kuc_hdr
 * @param maxsize Maximum message size allowed
 * @param transport Only listen to messages on this transport
 *      (and the generic transport)
 */
int libcfs_ukuc_msg_get(struct lustre_kernelcomm *link, char *buf, int maxsize,
			int transport)
{
	struct kuc_hdr *kuch;
	int rc = 0;

	if (buf == NULL || maxsize < 0 || maxsize < lhsz)
		return -EINVAL;

	memset(buf, 0, maxsize);

	while (1) {
		/* Read header first to get message size */
		rc = ukuc_full_read(link->lk_rfd, buf, lhsz);
		if (rc < 0)
			break;

		kuch = (struct kuc_hdr *)buf;

		if (kuch->kuc_magic != KUC_MAGIC) {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "bad message magic %x != %x\n",
					  kuch->kuc_magic, KUC_MAGIC);
			rc = -EPROTO;
			break;
		}

		if (kuch->kuc_msglen < lhsz) {
			rc = -EPROTO;
			break;
		}

		if (kuch->kuc_msglen > maxsize) {
			rc = -EMSGSIZE;
			break;
		}

		/* Read payload */
		rc = ukuc_full_read(link->lk_rfd, buf + lhsz, kuch->kuc_msglen - lhsz);
		if (rc < 0)
			break;

		if (kuch->kuc_transport == transport ||
		    kuch->kuc_transport == KUC_TRANSPORT_GENERIC) {
			return 0;
		}
		/* Drop messages for other transports */
	}
	return rc;
}

