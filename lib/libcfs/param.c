// SPDX-License-Identifier: LGPL-2.1+

/*
 * This code handles user interaction with the configuration interface
 * to the Lustre file system to fine tune it.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
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
#include <sys/utsname.h>
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

/*
 * Lustre/LNet kernel modules that are loaded or built into the kernel.
 * Only these are searched for parameters when the module name in the
 * pattern has wildcards, so that "lctl list_param --module '*'" doesn't
 * list the parameters of every other module in the kernel.
 */
#define CFS_PARAM_MODULES_MAX	128
#define CFS_MODULE_NAME_LEN	64
struct cfs_param_modules {
	int	cpm_count;
	char	cpm_names[CFS_PARAM_MODULES_MAX][CFS_MODULE_NAME_LEN];
};

/* add module @name to @mods if not already there, return true if added */
static bool cfs_param_module_add(struct cfs_param_modules *mods,
				 const char *name, size_t len)
{
	char *module;
	char *p;
	int i;

	if (len == 0 || len >= CFS_MODULE_NAME_LEN || name[0] == '.' ||
	    mods->cpm_count >= CFS_PARAM_MODULES_MAX)
		return false;
	/* module names use '_', even if the .ko file uses '-' */
	module = mods->cpm_names[mods->cpm_count];
	snprintf(module, CFS_MODULE_NAME_LEN, "%.*s", (int)len, name);
	for (p = strchr(module, '-'); p; p = strchr(p, '-'))
		*p = '_';

	for (i = 0; i < mods->cpm_count; i++)
		if (strcmp(mods->cpm_names[i], module) == 0)
			return false;

	mods->cpm_count++;
	return true;
}

static int cfs_param_module_cmp(const void *a, const void *b)
{
	return strcmp(a, b);
}

/* add all modules using module @name, return false if @name is built in */
static bool cfs_param_modules_holders(struct cfs_param_modules *mods,
				      const char *name)
{
	char path[PATH_MAX];
	struct dirent *de;
	DIR *dir;

	snprintf(path, sizeof(path), CFS_MODULE_PARAM_DIR"/%s/holders", name);
	dir = opendir(path);
	if (!dir)
		return false;

	while ((de = readdir(dir)) != NULL)
		if (cfs_param_module_add(mods, de->d_name, strlen(de->d_name)))
			cfs_param_modules_holders(mods, de->d_name);
	closedir(dir);

	return true;
}

/* add modules installed under a lustre/ or lnet/ directory in @file */
static void cfs_param_modules_file(struct cfs_param_modules *mods,
				   const char *file)
{
	char path[PATH_MAX];
	char line[PATH_MAX];
	struct utsname uts;
	FILE *fp;

	if (uname(&uts) < 0)
		return;
	snprintf(path, sizeof(path), "/lib/modules/%s/%s", uts.release, file);
	fp = fopen(path, "r");
	if (!fp)
		return;

	/* e.g. "kernel/fs/lustre/obdclass.ko", with ": DEPS" in modules.dep */
	while (fgets(line, sizeof(line), fp)) {
		char *name;
		char *end;

		end = strstr(line, ".ko");
		if (!end)
			continue;
		*end = '\0';
		if (!strstr(line, "/lustre/") && !strstr(line, "/lnet/"))
			continue;
		name = strrchr(line, '/') + 1;
		cfs_param_module_add(mods, name, end - name);
	}
	fclose(fp);
}

/**
 * cfs_param_modules_get() - Find the Lustre/LNet kernel modules
 *
 * Every Lustre module depends on libcfs, so walk the module "holders"
 * from libcfs to find all of the loaded Lustre modules without keeping a
 * list of module names here.  If libcfs is built into the kernel it has
 * no holders, so instead find the modules installed in lustre/ or lnet/
 * directories from the built-in and loadable module lists.
 */
static void cfs_param_modules_get(struct cfs_param_modules *mods)
{
	struct stat st;

	mods->cpm_count = 0;
	if (stat(CFS_MODULE_PARAM_DIR"/libcfs", &st) < 0)
		return;

	cfs_param_module_add(mods, "libcfs", strlen("libcfs"));
	if (!cfs_param_modules_holders(mods, "libcfs")) {
		cfs_param_modules_file(mods, "modules.builtin");
		cfs_param_modules_file(mods, "modules.dep");
	}
	qsort(mods->cpm_names, mods->cpm_count, CFS_MODULE_NAME_LEN,
	      cfs_param_module_cmp);
}

/* convert {a,b} brace lists in @pattern to FNM_EXTMATCH @(a|b) lists */
static int cfs_brace_to_extmatch(char *buf, size_t size, const char *pattern)
{
	size_t len = 0;
	int depth = 0;

	for (; *pattern; pattern++) {
		if (len + 2 >= size)
			return -E2BIG;
		if (*pattern == '{') {
			buf[len++] = '@';
			buf[len++] = '(';
			depth++;
		} else if (*pattern == '}' && depth > 0) {
			buf[len++] = ')';
			depth--;
		} else if (*pattern == ',' && depth > 0) {
			buf[len++] = '|';
		} else {
			buf[len++] = *pattern;
		}
	}
	buf[len] = '\0';

	return 0;
}

/* module names use '_', but '-' as seen in device types (osd-ldiskfs,
 * osd-zfs) is accepted too, since the kernel treats them the same; skip
 * bracket expressions, where '-' marks a character range.
 */
static void cfs_module_name_fixup(char *module)
{
	bool bracket = false;
	char *p;

	for (p = module; *p; p++) {
		if (*p == '[')
			bracket = true;
		else if (*p == ']')
			bracket = false;
		else if (*p == '-' && !bracket)
			*p = '_';
	}
}

/**
 * cfs_module_param_path() - Build the glob for module parameters
 * @path: buffer to hold the resulting glob [out]
 * @size: size of @path
 * @param: parameter pattern in the form "MODULE[/PARAMETER]"
 *
 * Module parameters are named "MODULE.PARAMETER" and are resolved to
 * CFS_MODULE_PARAM_DIR/MODULE/parameters/PARAMETER.  If MODULE contains
 * wildcards then it is matched only against the Lustre modules found by
 * cfs_param_modules_get(), otherwise it is used as-is.
 *
 * Return: length of the glob in @path, 0 if no modules match @param,
 *	   or %-E2BIG if @path is too small
 */
static int cfs_module_param_path(char *path, size_t size, const char *param)
{
	struct cfs_param_modules mods;
	char module[NAME_MAX + 1];
	char match[2 * (NAME_MAX + 1)];
	const char *rest;
	int count = 0;
	int len;
	int i;

	rest = strchr(param, '/');
	len = rest ? rest - param : strlen(param);
	if (!rest)
		rest = "";
	if (len == 0 || len >= sizeof(module))
		return 0;
	memcpy(module, param, len);
	module[len] = '\0';
	cfs_module_name_fixup(module);

	/* explicit module name or {a,b} list without wildcards is used as-is */
	if (!strpbrk(module, "*?[")) {
		len = snprintf(path, size,
			       CFS_MODULE_PARAM_DIR"/%s/parameters%s",
			       module, rest);
		return len < size ? len : -E2BIG;
	}

	if (cfs_brace_to_extmatch(match, sizeof(match), module) < 0)
		return 0;

	cfs_param_modules_get(&mods);
	len = snprintf(path, size, CFS_MODULE_PARAM_DIR"/{");
	if (len >= size)
		return -E2BIG;
	for (i = 0; i < mods.cpm_count; i++) {
		if (fnmatch(match, mods.cpm_names[i], FNM_EXTMATCH) != 0)
			continue;
		len += snprintf(path + len, size - len, "%s%s",
				count++ ? "," : "", mods.cpm_names[i]);
		if (len >= size)
			return -E2BIG;
	}
	if (count == 0)
		return 0;

	len += snprintf(path + len, size - len, "}/parameters%s", rest);

	return len < size ? len : -E2BIG;
}

static int cfs_vget_param_paths(glob_t *paths, bool modules,
				const char *pattern, va_list args)
{
	static const char topdir[] = "{{/proc,/sys}/fs/lustre,/sys/kernel/debug/{lnet,lustre}}";
	static bool test_mounted = false;
	char modpath[PATH_MAX];
	char path[PATH_MAX];
	char buf[PATH_MAX];
	int rc;

	if (!test_mounted) {
		cfs_try_mount_sys_kernel_debug();
		test_mounted = true;
	}

	rc = vsnprintf(buf, sizeof(buf), pattern, args);
	if (rc < 0)
		return rc;
	if (rc >= sizeof(buf)) {
		errno = EINVAL;
		return -EINVAL;
	}

	rc = 0;
	if (modules)
		rc = cfs_module_param_path(modpath, sizeof(modpath), buf);
	if (rc < 0) {
		errno = E2BIG;
		return -E2BIG;
	}

	if (rc > 0)
		rc = snprintf(path, sizeof(path), "{%s/%s,%s}",
			      topdir, buf, modpath);
	else
		rc = snprintf(path, sizeof(path), "%s/%s", topdir, buf);
	if (rc >= sizeof(path)) {
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

/**
 * cfs_get_param_paths() - Get parameter path matching the pattern
 * @paths: glob_t structure used to hold the final result [out]
 * @pattern: the pattern containing printf-style format specifiers
 *	     which will be used to create the path to match
 *
 * The @pattern is appended to the default path glob to complete the
 * absolute path to the file the caller is requesting. If the results point
 * to one or more files that exist those results are stored in the @paths
 * glob_t structure that is passed by the caller.
 *
 * Lustre tunables traditionally were in /proc/{sys,fs}/{lnet,lustre}
 * but in upstream kernels starting with Linux 4.2 these parameters
 * have been moved to /sys/fs/lustre and /sys/kernel/debug/{lnet,lustre}
 * so the user tools need to check both locations.
 *
 * Return: 0 for success, with results stored in @paths,
 *	   negative errno for failure with errno set to report the reason
 */
int cfs_get_param_paths(glob_t *paths, const char *pattern, ...)
{
	va_list args;
	int rc;

	va_start(args, pattern);
	rc = cfs_vget_param_paths(paths, false, pattern, args);
	va_end(args);

	return rc;
}

/**
 * cfs_get_param_paths_modules() - Get parameter and module parameter paths
 * @paths: glob_t structure used to hold the final result [out]
 * @pattern: the pattern containing printf-style format specifiers
 *	     which will be used to create the path to match
 *
 * The same as cfs_get_param_paths(), but also match kernel module parameters
 * in CFS_MODULE_PARAM_DIR/MODULE/parameters/PARAMETER, where @pattern is in
 * the form "MODULE/PARAMETER".  The module name is required so that
 * identically-named parameters in different modules (e.g.
 * lnet.peer_buffer_credits and ksocklnd.peer_buffer_credits) are distinct.
 *
 * Return: 0 for success, with results stored in @paths,
 *	   negative errno for failure with errno set to report the reason
 */
int cfs_get_param_paths_modules(glob_t *paths, const char *pattern, ...)
{
	va_list args;
	int rc;

	va_start(args, pattern);
	rc = cfs_vget_param_paths(paths, true, pattern, args);
	va_end(args);

	return rc;
}
