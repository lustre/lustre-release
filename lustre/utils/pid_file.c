// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright 2020, DataDirect Networks Storage.
 */
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "pid_file.h"

int create_pid_file(const char *path)
{
	char buf[3 * sizeof(long long) + 2];
	size_t buf_len;
	int fd = -1;
	int rc2;

	fd = open(path, O_RDWR|O_CREAT|O_CLOEXEC, 0600);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open '%s': %s\n",
			program_invocation_short_name, path, strerror(errno));
		return -1;
	}

	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};

	rc2 = fcntl(fd, F_SETLK, &fl);
	if (rc2 < 0) {
		fprintf(stderr, "%s: cannot lock '%s': %s\n",
			program_invocation_short_name, path, strerror(errno));
		goto out;
	}

	rc2 = ftruncate(fd, 0);
	if (rc2 < 0) {
		fprintf(stderr, "%s: cannot truncate '%s': %s\n",
			program_invocation_short_name, path, strerror(errno));
		goto out;
	}

	buf_len = snprintf(buf, sizeof(buf), "%lld\n", (long long)getpid());
	rc2 = write(fd, buf, buf_len);
	if (rc2 < 0) {
		fprintf(stderr, "%s: cannot write '%s': %s\n",
			program_invocation_short_name, path, strerror(errno));
		goto out;
	}
out:
	if (rc2 < 0 && !(fd < 0)) {
		close(fd);
		fd = -1;
	}

	return fd;
}
