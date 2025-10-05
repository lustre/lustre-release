// SPDX-License-Identifier: LGPL-2.1+

/*
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
#include <libcfs/util/param.h>
#include <sys/vfs.h>
#include <linux/magic.h>

static void cfs_try_mount_sys_kernel_debug(void)
{
	struct statfs statfsbuf;
	int rc;

	rc = statfs("/sys/kernel/debug/", &statfsbuf);
	if (rc == 0 && statfsbuf.f_type == DEBUGFS_MAGIC)
		return;

	if (mount("none", "/sys/kernel/debug", "debugfs", 0, "") == 0)
		return;

	/* Already mounted or don't have permission to mount is okay */
	if (errno != EPERM && errno != EBUSY)
		fprintf(stderr, "%d: warning: failed to mount /sys/kernel/debug",
			errno);
}

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
 * To access module parameters, the pattern should start with "module"
 *
 * \retval	 0 for success, with results stored in \param paths.
 * \retval	-1 for failure with errno set to report the reason.
 */
int
cfs_get_param_paths(glob_t *paths, const char *pattern, ...)
{
	char topdir[PATH_MAX] = "{{/proc,/sys}/fs/lustre,"
				"/sys/kernel/debug/{lnet,lustre}}";
	static bool test_mounted = false;
	char path[PATH_MAX];
	char buf[PATH_MAX];
	char *param;
	va_list args;
	int rc;

	if (!test_mounted) {
		cfs_try_mount_sys_kernel_debug();
		test_mounted = true;
	}

	va_start(args, pattern);
	rc = vsnprintf(buf, sizeof(buf), pattern, args);
	va_end(args);
	if (rc < 0) {
		return rc;
	}
	if (rc >= sizeof(buf)) {
		errno = EINVAL;
		return -EINVAL;
	}

	param = strstr(buf, "module");
	if (param) {
		param += strlen("module");
		if (*param == '/')
			param++;

		memmove(buf, param, strlen(param) + 1);
		*strrchr(topdir, '}') = '\0';
		strcat(topdir, ",/sys/module/{lnet,osc,mdd,obdclass,ofd,ptlrpc,mgc,ksocklnd,mdt,osd_ldiskfs,lquota}/parameters}");
	}

	if (snprintf(path, sizeof(path), "%s/%s", topdir, buf) >=
	    sizeof(path)) {
		errno = E2BIG;
		return -E2BIG;
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
		rc = -errno;
	}

	return rc;
}
