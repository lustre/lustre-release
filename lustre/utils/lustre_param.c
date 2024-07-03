/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/lustre_param.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Robert Read <rread@clusterfs.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/string.h>
#include <libcfs/util/param.h>
#include <libcfs/util/parser.h>
#include <lustre/lustreapi.h>
#include <linux/lnet/nidstr.h>
#include <linux/lustre/lustre_cfg.h>
#include <linux/lustre/lustre_ioctl.h>
#include <linux/lustre/lustre_ver.h>

#include "lctl_thread.h"
#include "lustreapi_internal.h"

#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>

#include "obdctl.h"
#include <stdio.h>
#include <yaml.h>

static int sp_parse_param_value(int argc, char **argv, char **param,
				char **value)
{
	char *tmp;

	if (argc < 1 || !(argv && param && value))
		return -EINVAL;

	*param = argv[0];
	tmp = strchr(*param, '=');
	if (tmp) {
		/* format: set_param a=b */
		*tmp = '\0';
		tmp++;
		if (*tmp == '\0')
			return -EINVAL;
		*value = tmp;
		return 1;
	}

	/* format: set_param a b */
	if (argc < 2)
		return -EINVAL;
	*value = argv[1];

	return 2;
}

/**
 * Display a parameter path in the same format as sysctl.
 * E.g. obdfilter.lustre-OST0000.stats
 *
 * \param[in] filename	file name of the parameter
 * \param[in] st	parameter file stats
 * \param[in] popt	set/get param options
 *
 * \retval allocated pointer containing modified filename
 */
static char *display_name(const char *filename, struct stat *st,
			  struct param_opts *popt)
{
	size_t suffix_len = 0;
	char *suffix = NULL;
	char *param_name;
	char *tmp;

	if (popt->po_show_type) {
		if (S_ISDIR(st->st_mode))
			suffix = "/";
		else if (S_ISLNK(st->st_mode))
			suffix = "@";
		else if (st->st_mode & S_IWUSR)
			suffix = "=";
	}

	/* Take the original filename string and chop off the glob addition */
	tmp = strstr(filename, "/lustre/");
	if (!tmp) {
		tmp = strstr(filename, "/lnet/");
		if (tmp)
			tmp += strlen("/lnet/");
	} else {
		tmp += strlen("/lustre/");
	}

	/* Allocate return string */
	param_name = strdup(tmp);
	if (!param_name)
		return NULL;

	/* replace '/' with '.' to match conf_param and sysctl */
	for (tmp = strchr(param_name, '/'); tmp != NULL; tmp = strchr(tmp, '/'))
		*tmp = '.';

	/* Append the indicator to entries if needed. */
	if (popt->po_show_type && suffix != NULL) {
		suffix_len = strlen(suffix);

		tmp = realloc(param_name, suffix_len + strlen(param_name) + 1);
		if (tmp) {
			param_name = tmp;
			strncat(param_name, suffix,
				strlen(param_name) + suffix_len);
		}
	}

	return param_name;
}

/**
 * Turns a lctl parameter string into a procfs/sysfs subdirectory path pattern.
 *
 * \param[in] popt		Used to control parameter usage. For this
 *				function it is used to see if the path has
 *				a added suffix.
 * \param[in,out] path		lctl parameter string that is turned into
 *				the subdirectory path pattern that is used
 *				to search the procfs/sysfs tree.
 *
 * \retval -errno on error.
 */
static int clean_path(struct param_opts *popt, char *path)
{
	char *nidstart = NULL;
	char *nidend = NULL;
	char *tmp;

	if (popt == NULL || path == NULL || strlen(path) == 0)
		return -EINVAL;

	/* If path contains a suffix we need to remove it */
	if (popt->po_show_type) {
		size_t path_end = strlen(path) - 1;

		tmp = path + path_end;
		switch (*tmp) {
		case '@':
		case '=':
		case '/':
			*tmp = '\0';
		default:
			break;
		}
	}

	/* get rid of '\', glob doesn't like it */
	tmp = strrchr(path, '\\');
	if (tmp) {
		char *tail = path + strlen(path);

		while (tmp != path) {
			if (*tmp == '\\') {
				memmove(tmp, tmp + 1, tail - tmp);
				--tail;
			}
			--tmp;
		}
	}

	/* Does path contain a NID string?  Skip '.->/' replacement for it. */
	tmp = strchr(path, '@');
	if (tmp) {
		/* First find the NID start.  NIDs may have variable (0-4) '.',
		 * so find the common NID prefixes instead of trying to count
		 * the dots.  Not great, but there are only two, and faster
		 * than multiple speculative NID parses and bad DNS lookups.
		 */
		if ((tmp = strstr(path, ".exports.")))
			nidstart = tmp + strlen(".exports.");
		else if ((tmp = strstr(path, ".MGC")))
			nidstart = tmp + 1;

		/* Next, find the end of the NID string. */
		if (nidstart)
			nidend = strchrnul(strchr(nidstart, '@'), '.');
	}

	/* replace param '.' with '/' */
	for (tmp = strchr(path, '.'); tmp != NULL; tmp = strchr(tmp, '.')) {
		*tmp++ = '/';

		/*
		 * There exist cases where some of the subdirectories of the
		 * parameter tree has embedded in its name a NID string.
		 * This means that it is possible that these subdirectories
		 * could have actual '.' in its name. If this is the case we
		 * don't want to blindly replace the '.' with '/', so skip
		 * over the part of the parameter containing the NID.
		 */
		if (tmp == nidstart)
			tmp = nidend;
	}

	return 0;
}

/**
 * The application lctl can perform three operations for lustre
 * tunables. This enum defines those four operations which are
 *
 * 1) LIST_PARAM	- list available tunables
 * 2) GET_PARAM		- report the current setting of a tunable
 * 3) SET_PARAM		- set the tunable to a new value
 * 4) LIST_PATHNAME	- list paths of available tunables
 */
enum parameter_operation {
	LIST_PARAM,
	GET_PARAM,
	SET_PARAM,
	LIST_PATHNAME,
};

char *parameter_opname[] = {
	[LIST_PARAM] = "list_param",
	[GET_PARAM] = "get_param",
	[SET_PARAM] = "set_param",
	[LIST_PATHNAME] = "list_pathname",
};

/**
 * Read the value of parameter
 *
 * \param[in]	path		full path to the parameter
 * \param[in]	param_name	lctl parameter format of the
 *				parameter path
 * \param[in]	popt		set/get param options
 *
 * \retval 0 on success.
 * \retval -errno on error.
 */
static int read_param(const char *path, const char *param_name,
		      struct param_opts *popt)
{
	int rc = 0;
	char *buf = NULL;
	size_t buflen;

	rc = llapi_param_get_value(path, &buf, &buflen);
	if (rc != 0) {
		fprintf(stderr,
			"error: %s: '%s': %s\n",
			"read_param", path, strerror(-rc));
		goto free_buf;
	}
	/* don't print anything for empty files */
	if (buf[0] == '\0') {
		if (popt->po_header)
			printf("%s=\n", param_name);
		goto free_buf;
	}

	if (popt->po_header) {
		char *oldbuf = buf;
		char *next;

		do {
			/* Split at first \n, if any */
			next = strchrnul(oldbuf, '\n');

			printf("%s=%.*s\n", param_name, (int)(next - oldbuf),
			       oldbuf);

			buflen -= next - oldbuf + 1;
			oldbuf = next + 1;

		} while (buflen > 0);

	} else if (popt->po_show_name) {
		bool multilines = memchr(buf, '\n', buflen - 1);

		printf("%s=%s%s", param_name, multilines ? "\n" : "", buf);
	} else {
		printf("%s", buf);
	}

free_buf:
	free(buf);
	return rc;
}

/**
 * Set a parameter to a specified value
 *
 * \param[in] path		full path to the parameter
 * \param[in] param_name	lctl parameter format of the parameter path
 * \param[in] popt		set/get param options
 * \param[in] value		value to set the parameter to
 *
 * \retval number of bytes written on success.
 * \retval -errno on error.
 */
int write_param(const char *path, const char *param_name,
		struct param_opts *popt, const char *value)
{
	int fd, rc = 0;
	ssize_t count;

	if (!value)
		return -EINVAL;

	/* Write the new value to the file */
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		rc = -errno;
		fprintf(stderr, "error: set_param: opening '%s': %s\n",
			path, strerror(errno));
		return rc;
	}

	count = write(fd, value, strlen(value));
	if (count < 0) {
		rc = -errno;
		if (errno != EIO) {
			fprintf(stderr, "error: set_param: setting %s=%s: %s\n",
				path, value, strerror(errno));
		}
	} else if (count < strlen(value)) { /* Truncate case */
		rc = -EINVAL;
		fprintf(stderr,
			"error: set_param: setting %s=%s: wrote only %zd\n",
			path, value, count);
	} else if (popt->po_show_name) {
		printf("%s=%s\n", param_name, value);
	}
	close(fd);

	return rc;
}

/**
 * Perform a read, write or just a listing of a parameter
 *
 * \param[in] popt	list,set,get parameter options
 * \param[in] pattern	search filter for the path of the parameter
 * \param[in] value	value to set the parameter if write operation
 * \param[in] oper	what operation to perform with the parameter
 * \param[out] wq	the work queue to which work items will be added or NULL
 *			if not in parallel
 *
 * \retval number of bytes written on success.
 * \retval -errno on error and prints error message.
 */
static int do_param_op(struct param_opts *popt, char *pattern, char *value,
		       enum parameter_operation oper, struct sp_workq *wq)
{
	int dup_count = 0;
	char **dup_cache;
	glob_t paths;
	char *opname = parameter_opname[oper];
	int rc, i;

	if (!wq && popt_is_parallel(*popt))
		return -EINVAL;

	rc = llapi_param_get_paths(pattern, &paths);
	if (rc) {
		rc = -errno;
		if (!popt->po_recursive && !(rc == -ENOENT && getuid() != 0)) {
			fprintf(stderr, "error: %s: param_path '%s': %s\n",
				opname, pattern, strerror(errno));
		}
		return rc;
	}

	if (popt_is_parallel(*popt) && paths.gl_pathc > 1) {
		/* Allocate space for the glob paths in advance. */
		rc = spwq_expand(wq, paths.gl_pathc);
		if (rc < 0)
			goto out_param;
	}

	dup_cache = calloc(paths.gl_pathc, sizeof(char *));
	if (!dup_cache) {
		rc = -ENOMEM;
		fprintf(stderr,
			"error: %s: allocating '%s' dup_cache[%zd]: %s\n",
			opname, pattern, paths.gl_pathc, strerror(-rc));
		goto out_param;
	}

	for (i = 0; i < paths.gl_pathc; i++) {
		char *param_name = NULL, *tmp;
		char pathname[PATH_MAX], param_dir[PATH_MAX + 2];
		struct stat st;
		int rc2, j;

		if (!popt->po_follow_symlinks)
			rc2 = lstat(paths.gl_pathv[i], &st);
		else
			rc2 = stat(paths.gl_pathv[i], &st);

		if (rc2 == -1) {
			fprintf(stderr, "error: %s: stat '%s': %s\n",
				opname, paths.gl_pathv[i], strerror(errno));
			if (!rc)
				rc = -errno;
			continue;
		}

		if (S_ISLNK(st.st_mode) && !popt->po_follow_symlinks)
			continue;
		if (popt->po_only_dir && !S_ISDIR(st.st_mode))
			continue;

		param_name = display_name(paths.gl_pathv[i], &st, popt);
		if (!param_name) {
			fprintf(stderr,
				"error: %s: generating name for '%s': %s\n",
				opname, paths.gl_pathv[i], strerror(ENOMEM));
			if (!rc)
				rc = -ENOMEM;
			continue;
		}

		switch (oper) {
		case GET_PARAM:
			/* Read the contents of file to stdout */
			if (S_ISREG(st.st_mode)) {
				rc2 = read_param(paths.gl_pathv[i], param_name,
						 popt);
				if (rc2 < 0 && !rc)
					rc = rc2;
			}
			break;
		case SET_PARAM:
			if (S_ISREG(st.st_mode)) {
				if (popt_is_parallel(*popt))
					rc2 = spwq_add_item(wq,
							    paths.gl_pathv[i],
							    param_name, value);
				else
					rc2 = write_param(paths.gl_pathv[i],
							  param_name, popt,
							  value);

				if (rc2 < 0 && !rc)
					rc = rc2;
			}
			break;
		case LIST_PARAM:
			/**
			 * For the upstream client the parameter files locations
			 * are split between under both /sys/kernel/debug/lustre
			 * and /sys/fs/lustre. The parameter files containing
			 * small amounts of data, less than a page in size, are
			 * located under /sys/fs/lustre and in the case of large
			 * parameter data files, think stats for example, are
			 * located in the debugfs tree. Since the files are
			 * split across two trees the directories are often
			 * duplicated which means these directories are listed
			 * twice which leads to duplicate output to the user.
			 * To avoid scanning a directory twice we have to cache
			 * any directory and check if a search has been
			 * requested twice.
			 */
			for (j = 0; j < dup_count; j++) {
				if (!strcmp(dup_cache[j], param_name))
					break;
			}
			if (j != dup_count) {
				free(param_name);
				param_name = NULL;
				continue;
			}
			dup_cache[dup_count++] = strdup(param_name);

			if (popt->po_show_name)
				printf("%s\n", param_name);
			break;
		case LIST_PATHNAME:
			for (j = 0; j < dup_count; j++) {
				if (!strcmp(dup_cache[j], param_name))
					break;
			}
			if (j != dup_count) {
				free(param_name);
				param_name = NULL;
				continue;
			}
			dup_cache[dup_count++] = strdup(param_name);
			if (popt->po_show_name)
				printf("%s\n", paths.gl_pathv[i]);
			break;
		}

		/*
		 * Only directories are searched recursively if
		 * requested by the user
		 */
		if (!S_ISDIR(st.st_mode) || !popt->po_recursive) {
			free(param_name);
			param_name = NULL;
			continue;
		}

		/* Turn param_name into file path format */
		rc2 = clean_path(popt, param_name);
		if (rc2 < 0) {
			fprintf(stderr, "error: %s: cleaning '%s': %s\n",
				opname, param_name, strerror(-rc2));
			free(param_name);
			param_name = NULL;
			if (!rc)
				rc = rc2;
			continue;
		}

		/* Use param_name to grab subdirectory tree from full path */
		snprintf(param_dir, sizeof(param_dir), "/%s", param_name);
		tmp = strstr(paths.gl_pathv[i], param_dir);

		/* cleanup paramname now that we are done with it */
		free(param_name);
		param_name = NULL;
		memset(&param_dir, '\0', sizeof(param_dir));

		/* Shouldn't happen but just in case */
		if (!tmp) {
			if (!rc)
				rc = -EINVAL;
			continue;
		}
		tmp++;

		rc2 = snprintf(pathname, sizeof(pathname), "%s/*", tmp);
		if (rc2 < 0) {
			/*
			 * snprintf() should never an error, and if it does
			 * there isn't much point trying to use fprintf()
			 */
			continue;
		}
		if (rc2 >= sizeof(pathname)) {
			fprintf(stderr, "error: %s: overflow processing '%s'\n",
				opname, pathname);
			if (!rc)
				rc = -EINVAL;
			continue;
		}

		rc2 = do_param_op(popt, pathname, value, oper, wq);
		if (!rc2 && rc2 != -ENOENT) {
			/* errors will be printed by do_param_op() */
			if (!rc)
				rc = rc2;
			continue;
		}
	}

	for (i = 0; i < dup_count; i++)
		free(dup_cache[i]);
	free(dup_cache);
out_param:
	llapi_param_paths_free(&paths);
	return rc;
}

static int listparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
	struct option long_opts[] = {
	{ .val = 'D',	.name = "dir-only",	.has_arg = no_argument},
	{ .val = 'D',	.name = "directory-only", .has_arg = no_argument},
	{ .val = 'F',	.name = "classify",	.has_arg = no_argument},
	{ .val = 'l',	.name = "links",	.has_arg = no_argument},
	{ .val = 'L',	.name = "no-links",	.has_arg = no_argument},
	{ .val = 'R',	.name = "recursive",	.has_arg = no_argument},
	};

	int ch;

	popt->po_show_name = 1;
	popt->po_only_name = 1;
	popt->po_follow_symlinks = 1;

	while ((ch = getopt_long(argc, argv, "DFlLpR",
				      long_opts, NULL)) != -1) {
		switch (ch) {
		case 'D':
			popt->po_only_dir = 1;
			break;
		case 'F':
			popt->po_show_type = 1;
			break;
		case 'l':
			popt->po_follow_symlinks = 1;
			break;
		case 'L':
			popt->po_follow_symlinks = 0;
			break;
		case 'p':
			popt->po_only_pathname = 1;
			break;
		case 'R':
			popt->po_recursive = 1;
			break;
		default:
			return -1;
		}
	}

	return optind;
}

int jt_lcfg_listparam(int argc, char **argv)
{
	int rc = 0, index, i;
	struct param_opts popt;
	char *path;

	memset(&popt, 0, sizeof(popt));
	index = listparam_cmdline(argc, argv, &popt);
	if (index < 0 || index >= argc)
		return CMD_HELP;

	for (i = index; i < argc; i++) {
		int rc2;

		path = argv[i];

		rc2 = clean_path(&popt, path);
		if (rc2 < 0) {
			fprintf(stderr, "error: %s: cleaning '%s': %s\n",
				jt_cmdname(argv[0]), path, strerror(-rc2));
			if (rc == 0)
				rc = rc2;
			continue;
		}

		rc2 = do_param_op(&popt, path, NULL, popt.po_only_pathname ?
				  LIST_PATHNAME : LIST_PARAM, NULL);
		if (rc2 < 0) {
			if (rc == 0)
				rc = rc2;

			if (rc2 == -ENOENT && getuid() != 0)
				rc2 = llapi_param_display_value(path, 0, 0,
								stdout);
			if (rc2 < 0) {
				fprintf(stderr, "error: %s: listing '%s': %s\n",
					jt_cmdname(argv[0]), path,
					strerror(-rc2));
			}
			continue;
		}
	}

	return rc;
}

static int getparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
	struct option long_opts[] = {
	{ .val = 'F',	.name = "classify",	.has_arg = no_argument},
	{ .val = 'H',	.name = "header",	.has_arg = no_argument},
	{ .val = 'l',	.name = "links",	.has_arg = no_argument},
	{ .val = 'L',	.name = "no-links",	.has_arg = no_argument},
	{ .val = 'n',	.name = "no-name",	.has_arg = no_argument},
	{ .val = 'N',	.name = "only-name",	.has_arg = no_argument},
	{ .val = 'R',	.name = "recursive",	.has_arg = no_argument},
	{ .val = 'y',	.name = "yaml",		.has_arg = no_argument},
	};

	int ch;

	popt->po_show_name = 1;
	popt->po_follow_symlinks = 1;

	while ((ch = getopt_long(argc, argv, "FHlLnNRy",
				      long_opts, NULL)) != -1) {
		switch (ch) {
		case 'F':
			popt->po_show_type = 1;
			break;
		case 'H':
			popt->po_header = 1;
			break;
		case 'l':
			popt->po_follow_symlinks = 1;
			break;
		case 'L':
			popt->po_follow_symlinks = 0;
			break;
		case 'n':
			popt->po_show_name = 0;
			break;
		case 'N':
			popt->po_only_name = 1;
			break;
		case 'R':
			popt->po_recursive = 1;
			break;
		case 'y':
			popt->po_yaml = 1;
			break;
		default:
			return -1;
		}
	}

	return optind;
}

int jt_lcfg_getparam(int argc, char **argv)
{
	int version = LUSTRE_GENL_VERSION;
	enum parameter_operation mode;
	int rc = 0, index, i;
	struct param_opts popt;
	int flags = 0;
	char *path;

	memset(&popt, 0, sizeof(popt));
	index = getparam_cmdline(argc, argv, &popt);
	if (index < 0 || index >= argc)
		return CMD_HELP;

	mode = popt.po_only_name ? LIST_PARAM : GET_PARAM;
	if (mode == LIST_PARAM)
		version = 0;

	if (popt.po_yaml)
		flags |= PARAM_FLAGS_YAML_FORMAT;
	if (popt.po_show_name)
		flags |= PARAM_FLAGS_SHOW_SOURCE;

	for (i = index; i < argc; i++) {
		int rc2;

		path = argv[i];

		rc2 = clean_path(&popt, path);
		if (rc2 < 0) {
			fprintf(stderr, "error: %s: cleaning '%s': %s\n",
				jt_cmdname(argv[0]), path, strerror(-rc2));
			if (rc == 0)
				rc = rc2;
			continue;
		}

		rc2 = do_param_op(&popt, path, NULL,
				  popt.po_only_name ? LIST_PARAM : GET_PARAM,
				  NULL);
		if (rc2 < 0) {
			if (rc == 0)
				rc = rc2;

			if (rc2 == -ENOENT && getuid() != 0)
				rc2 = llapi_param_display_value(path, version,
								flags, stdout);
			continue;
		}
	}

	return rc;
}

/**
 * Parses the commandline options to set_param.
 *
 * \param[in] argc	count of arguments given to set_param
 * \param[in] argv	array of arguments given to set_param
 * \param[out] popt	where set_param options will be saved
 *
 * \retval index in argv of the first nonoption argv element (optind value)
 */
static int setparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
	struct option long_opts[] = {
	{ .val = 'd',	.name = "delete",	.has_arg = no_argument},
	{ .val = 'F',	.name = "file",		.has_arg = no_argument},
	{ .val = 'n',	.name = "noname",	.has_arg = no_argument},
	{ .val = 'P',	.name = "perm",		.has_arg = no_argument},
	{ .val = 'P',	.name = "permanent",	.has_arg = no_argument},
	{ .val = 't',	.name = "thread",	.has_arg = optional_argument},
	};

	int ch;

	popt->po_show_name = 1;
	popt->po_only_name = 0;
	popt->po_show_type = 0;
	popt->po_recursive = 0;
	popt->po_perm = 0;
	popt->po_delete = 0;
	popt->po_file = 0;
	popt->po_parallel_threads = 0;
	popt->po_follow_symlinks = 1;
	opterr = 0;

	/* reset optind for each getopt_long() in case of multiple calls */
	optind = 0;
	while ((ch = getopt_long(argc, argv, "dFnPt::",
				 long_opts, NULL)) != -1) {
		switch (ch) {
		case 'n':
			popt->po_show_name = 0;
			break;
		case 't':
#if HAVE_LIBPTHREAD
			if (optarg)
				popt->po_parallel_threads = atoi(optarg);
			else
				popt->po_parallel_threads = LCFG_THREADS_DEF;
			if (popt->po_parallel_threads < 2)
				return -EINVAL;
#else
			{
				static bool printed;

				if (!printed) {
					printed = true;
					fprintf(stderr,
						"warning: set_param: no pthread support, proceeding serially.\n");
				}
			}
#endif
			break;
		case 'P':
			popt->po_perm = 1;
			break;
		case 'd':
			popt->po_delete = 1;
			break;
		case 'F':
			popt->po_file = 1;
			break;
		default:
			return -1;
		}
	}
	if (popt->po_perm && popt->po_file) {
		fprintf(stderr, "warning: ignoring -P option\n");
		popt->po_perm = 0;
	}
	if (popt->po_delete && !popt->po_perm)
		popt->po_perm = 1;
	return optind;
}

/**
 * Main set_param function.
 *
 * \param[in] argc	count of arguments given to set_param
 * \param[in] argv	array of arguments given to set_param
 *
 * \retval 0 if successful
 * \retval -errno if unsuccessful
 */
int jt_lcfg_setparam(int argc, char **argv)
{
	int rc = 0;
	int index = 0;
	struct param_opts popt;
	struct sp_workq wq;
	struct sp_workq *wq_ptr = NULL;

	memset(&popt, 0, sizeof(popt));
	index = setparam_cmdline(argc, argv, &popt);
	if (index < 0 || index >= argc)
		return CMD_HELP;

	if (popt.po_perm)
		/*
		 * We can't delete parameters that were
		 * set with old conf_param interface
		 */
		return jt_lcfg_setparam_perm(argc, argv, &popt);

	if (popt.po_file) {
		fprintf(stderr,
			"warning: 'lctl set_param -F' is deprecated, use 'lctl apply_yaml' instead\n");
		return -EINVAL;
	}

	if (popt_is_parallel(popt)) {
		rc = spwq_init(&wq, &popt);
		if (rc < 0) {
			fprintf(stderr,
				"warning: parallel %s: failed to init work queue: %s. Proceeding serially.\n",
				jt_cmdname(argv[0]), strerror(-rc));
			rc = 0;
			popt.po_parallel_threads = 0;
		} else {
			wq_ptr = &wq;
		}
	}

	while (index < argc) {
		char *path = NULL;
		char *value = NULL;

		rc = sp_parse_param_value(argc - index, argv + index,
					  &path, &value);
		if (rc < 0) {
			fprintf(stderr, "error: %s: setting %s: %s\n",
				jt_cmdname(argv[0]), path, strerror(-rc));
			break;
		}
		/* Increment index by the number of arguments consumed. */
		index += rc;

		rc = clean_path(&popt, path);
		if (rc < 0)
			break;

		rc = do_param_op(&popt, path, value, SET_PARAM, wq_ptr);
		if (rc < 0)
			fprintf(stderr, "error: %s: setting '%s'='%s': %s\n",
				jt_cmdname(argv[0]), path, value,
				strerror(-rc));
	}

	if (popt_is_parallel(popt)) {
		int rc2;
		/* Spawn threads to set the parameters which made it into the
		 * work queue to emulate serial set_param behavior when errors
		 * are encountered above.
		 */
		rc2 = sp_run_threads(&wq);
		if (rc2 < 0) {
			fprintf(stderr,
				"error: parallel %s: failed to run threads: %s\n",
				jt_cmdname(argv[0]), strerror(-rc2));
			if (!rc)
				rc = rc2;
		}
		rc2 = spwq_destroy(&wq);
		if (rc2 < 0) {
			fprintf(stderr,
				"warning: parallel %s: failed to cleanup work queue: %s\n",
				jt_cmdname(argv[0]), strerror(-rc2));
		}
	}

	return rc;
}
