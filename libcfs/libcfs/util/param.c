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
 * libcfs/libcfs/utils/param.c
 *
 * This code handles user interaction with the configuration interface
 * to the Lustre file system to fine tune it.
 */
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <mntent.h>
#include <paths.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/limits.h>
#include <libcfs/util/string.h>
#include <sys/vfs.h>
#include <linux/magic.h>

/**
 * Get parameter path matching the pattern
 *
 * \param[out] paths	glob_t structure used to hold the final result
 * \param[in]  pattern	the pattern containing sprintf format specifiers
 *			which will be used to create the path to match
 *
 * The \param pattern is appended to the default path glob to complete the
 * absolute path to the file the caller is requesting. If the results point
 * to one or more files that exist those results are stored in the \param
 * paths glob_t structure that is passed by the caller.
 *
 * Lustre tunables traditionally were in /proc/{sys,fs}/{lnet,lustre}
 * but in upstream kernels starting with Linux 4.2 these parameters
 * have been moved to /sys/fs/lustre and /sys/kernel/debug/{lnet,lustre}
 * so the user tools need to check both locations.
 *
 * \retval	 0 for success, with results stored in \param paths.
 * \retval	-1 for failure with errno set to report the reason.
 */
int
cfs_get_param_paths(glob_t *paths, const char *pattern, ...)
{
	char topdir[PATH_MAX] = "{/sys/{fs,kernel/debug}/{lnet,lustre},"
				"/proc/{fs,sys}/{lnet,lustre}}";
	static bool test_mounted = false;
	char path[PATH_MAX];
	char buf[PATH_MAX];
	struct statfs statfsbuf;
	va_list args;
	int rc;


	if (test_mounted)
		goto skip_mounting;
	test_mounted = true;

	rc = statfs("/sys/kernel/debug/", &statfsbuf);
	if (rc == 0 && statfsbuf.f_type == DEBUGFS_MAGIC)
		goto skip_mounting;

	if (mount("none", "/sys/kernel/debug", "debugfs", 0, "") == -1) {
		/* Already mounted or don't have permission to mount is okay */
		if (errno != EPERM && errno != EBUSY)
			fprintf(stderr, "Warning: failed to mount debug: %s\n",
				strerror(errno));
	} else {
		struct stat mtab;

		/* This is all for RHEL6 which is old school. Can be removed
		 * later when RHEL6 client support is dropped. */
		rc = lstat(_PATH_MOUNTED, &mtab);
		if (!rc && !S_ISLNK(mtab.st_mode)) {
			FILE *fp = setmntent(_PATH_MOUNTED, "r+");

			if (fp != NULL) {
				const struct mntent fs = {
					.mnt_fsname	= "debugfs",
					.mnt_dir	= "/sys/kernel/debug",
					.mnt_type	= "debugfs",
					.mnt_opts	= "rw,relatime",
				};

				rc = addmntent(fp, &fs);
				if (rc) {
					fprintf(stderr,
						"failed to add debugfs to %s: %s\n",
						_PATH_MOUNTED, strerror(errno));
				}
				endmntent(fp);
			} else {
				fprintf(stderr, "could not open %s: %s\n",
					_PATH_MOUNTED, strerror(errno));
			}
		}
	}
skip_mounting:
	va_start(args, pattern);
	rc = vsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);
	if (rc < 0) {
		return rc;
	} else if (rc >= sizeof(buf)) {
		errno = EINVAL;
		return -1;
	}

	if (snprintf(path, sizeof(path), "%s/%s", topdir, buf) >=
	    sizeof(path)) {
		errno = E2BIG;
		return -1;
	}

	rc = glob(path, GLOB_BRACE, NULL, paths);
	if (rc != 0) {
		switch (rc) {
		case GLOB_NOSPACE:
			errno = ENOMEM;
			break;
		case GLOB_ABORTED:
			errno = ENODEV;
			break;
		case GLOB_NOMATCH:
		default:
			errno = ENOENT;
			break;
		}
		rc = -1;
	}

	return rc;
}
