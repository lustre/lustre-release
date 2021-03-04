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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <stddef.h>
#include <libgen.h>
#include <syslog.h>

#include <libcfs/util/param.h>
#include <linux/lnet/nidstr.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_idl.h>

#define PERM_PATHNAME "/etc/lustre/perm.conf"

/*
 * permission file format is like this:
 * {nid} {uid} {perms}
 *
 * '*' nid means any nid
 * '*' uid means any uid
 * the valid values for perms are:
 * setuid/setgid/setgrp		-- enable corresponding perm
 * nosetuid/nosetgid/nosetgrp	-- disable corresponding perm
 * they can be listed together, separated by ',',
 * when perm and noperm are in the same line (item), noperm is preferential,
 * when they are in different lines (items), the latter is preferential,
 * '*' nid is as default perm, and is not preferential.
 */

static char *progname;

static void usage(void)
{
	fprintf(stderr,
		"\nusage: %s {-d|mdtname} {uid}\n"
		"Normally invoked as an upcall from Lustre, set via:\n"
		"lctl set_param mdt.${mdtname}.identity_upcall={path to upcall}\n"
		"\t-d: debug, print values to stdout instead of Lustre\n",
		progname);
}

static int compare_u32(const void *v1, const void *v2)
{
	return *(__u32 *)v1 - *(__u32 *)v2;
}

static void errlog(const char *fmt, ...)
{
	va_list args;

	openlog(progname, LOG_PERROR | LOG_PID, LOG_AUTHPRIV);

	va_start(args, fmt);
	vsyslog(LOG_WARNING, fmt, args);
	va_end(args);

	closelog();
}

int get_groups_local(struct identity_downcall_data *data,
		     unsigned int maxgroups)
{
	gid_t *groups, *groups_tmp = NULL;
	unsigned int ngroups = 0;
	int ngroups_tmp;
	struct passwd *pw;
	int i;

	pw = getpwuid(data->idd_uid);
	if (!pw) {
		errlog("no such user %u\n", data->idd_uid);
		data->idd_err = errno ? errno : EIDRM;
		return -1;
	}

	data->idd_gid = pw->pw_gid;

	groups = data->idd_groups;

	/*
	 * Allocate array of size maxgroups instead of handling two
	 * consecutive and potentially racy getgrouplist() calls.
	 */
	groups_tmp = malloc(maxgroups * sizeof(gid_t));
	if (!groups_tmp) {
		data->idd_err = errno ? errno : ENOMEM;
		errlog("malloc error=%u\n", data->idd_err);
		return -1;
	}

	ngroups_tmp = maxgroups;
	if (getgrouplist(pw->pw_name, pw->pw_gid, groups_tmp, &ngroups_tmp) <
	    0) {
		free(groups_tmp);
		data->idd_err = errno ? errno : EIDRM;
		errlog("getgrouplist() error for uid %u: error=%u\n",
		       data->idd_uid, data->idd_err);
		return -1;
	}

	/* Do not place user's group ID in to the resulting groups list */
	for (i = 0; i < ngroups_tmp; i++)
		if (pw->pw_gid != groups_tmp[i])
			groups[ngroups++] = groups_tmp[i];

	if (ngroups > 0)
		qsort(groups, ngroups, sizeof(*groups), compare_u32);
	data->idd_ngroups = ngroups;

	free(groups_tmp);
	return 0;
}

static inline int comment_line(char *line)
{
	char *p = line;

	while (*p && (*p == ' ' || *p == '\t'))
		p++;

	if (!*p || *p == '\n' || *p == '#')
		return 1;
	return 0;
}

static inline int match_uid(uid_t uid, const char *str)
{
	char *end;
	uid_t uid2;

	if (!strcmp(str, "*"))
		return -1;

	uid2 = strtoul(str, &end, 0);
	if (*end)
		return 0;
	return (uid == uid2);
}

typedef struct {
	char *name;
	__u32 bit;
} perm_type_t;

static perm_type_t perm_types[] = {
	{ "setuid", CFS_SETUID_PERM },
	{ "setgid", CFS_SETGID_PERM },
	{ "setgrp", CFS_SETGRP_PERM },
	{ "rmtacl", 0 },
	{ "rmtown", 0 },
	{ 0 }
};

static perm_type_t noperm_types[] = {
	{ "nosetuid", CFS_SETUID_PERM },
	{ "nosetgid", CFS_SETGID_PERM },
	{ "nosetgrp", CFS_SETGRP_PERM },
	{ "normtacl", 0 },
	{ "normtown", 0 },
	{ 0 }
};

int parse_perm(__u32 *perm, __u32 *noperm, char *str)
{
	char *start, *end;
	char name[64];
	perm_type_t *pt;

	*perm = 0;
	*noperm = 0;
	start = str;
	while (1) {
		size_t len;

		memset(name, 0, sizeof(name));
		end = strchr(start, ',');
		if (!end)
			end = str + strlen(str);
		if (start >= end)
			break;
		len = end - start;
		if (len >= sizeof(name))
			return -E2BIG;
		strncpy(name, start, len);
		name[len] = '\0';
		for (pt = perm_types; pt->name; pt++) {
			if (!strcasecmp(name, pt->name)) {
				*perm |= pt->bit;
				break;
			}
		}

		if (!pt->name) {
			for (pt = noperm_types; pt->name; pt++) {
				if (!strcasecmp(name, pt->name)) {
					*noperm |= pt->bit;
					break;
				}
			}

			if (!pt->name) {
				printf("unkown type: %s\n", name);
				return -1;
			}
		}

		start = end + 1;
	}
	return 0;
}

static int
parse_perm_line(struct identity_downcall_data *data, char *line, size_t size)
{
	char uid_str[size];
	char nid_str[size];
	char perm_str[size];
	lnet_nid_t nid;
	__u32 perm, noperm;
	int rc, i;

	if (data->idd_nperms >= N_PERMS_MAX) {
		errlog("permission count %d > max %d\n",
		       data->idd_nperms, N_PERMS_MAX);
		return -1;
	}

	rc = sscanf(line, "%s %s %s", nid_str, uid_str, perm_str);
	if (rc != 3) {
		errlog("can't parse line %s\n", line);
		return -1;
	}

	if (!match_uid(data->idd_uid, uid_str))
		return 0;

	if (!strcmp(nid_str, "*")) {
		nid = LNET_NID_ANY;
	} else {
		nid = libcfs_str2nid(nid_str);
		if (nid == LNET_NID_ANY) {
			errlog("can't parse nid %s\n", nid_str);
			return -1;
		}
	}

	if (parse_perm(&perm, &noperm, perm_str)) {
		errlog("invalid perm %s\n", perm_str);
		return -1;
	}

	/*
	 * merge the perms with the same nid.
	 *
	 * If there is LNET_NID_ANY in data->idd_perms[i].pdd_nid,
	 * it must be data->idd_perms[0].pdd_nid, and act as default perm.
	 */
	if (nid != LNET_NID_ANY) {
		int found = 0;

		/* search for the same nid */
		for (i = data->idd_nperms - 1; i >= 0; i--) {
			if (data->idd_perms[i].pdd_nid == nid) {
				data->idd_perms[i].pdd_perm =
					(data->idd_perms[i].pdd_perm | perm) &
					~noperm;
				found = 1;
				break;
			}
		}

		/* NOT found, add to tail */
		if (!found) {
			data->idd_perms[data->idd_nperms].pdd_nid = nid;
			data->idd_perms[data->idd_nperms].pdd_perm =
				perm & ~noperm;
			data->idd_nperms++;
		}
	} else {
		if (data->idd_nperms > 0) {
			/* the first one isn't LNET_NID_ANY, need exchange */
			if (data->idd_perms[0].pdd_nid != LNET_NID_ANY) {
				data->idd_perms[data->idd_nperms].pdd_nid =
					data->idd_perms[0].pdd_nid;
				data->idd_perms[data->idd_nperms].pdd_perm =
					data->idd_perms[0].pdd_perm;
				data->idd_perms[0].pdd_nid = LNET_NID_ANY;
				data->idd_perms[0].pdd_perm = perm & ~noperm;
				data->idd_nperms++;
			} else {
				/* only fix LNET_NID_ANY item */
				data->idd_perms[0].pdd_perm =
					(data->idd_perms[0].pdd_perm | perm) &
					~noperm;
			}
		} else {
			/* it is the first one, only add to head */
			data->idd_perms[0].pdd_nid = LNET_NID_ANY;
			data->idd_perms[0].pdd_perm = perm & ~noperm;
			data->idd_nperms = 1;
		}
	}

	return 0;
}

int get_perms(struct identity_downcall_data *data)
{
	FILE *fp;
	char line[PATH_MAX];

	fp = fopen(PERM_PATHNAME, "r");
	if (!fp) {
		if (errno == ENOENT)
			return 0;
		errlog("open %s failed: %s\n",
		       PERM_PATHNAME, strerror(errno));
		data->idd_err = errno;
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (comment_line(line))
			continue;

		if (parse_perm_line(data, line, sizeof(line))) {
			errlog("parse line %s failed!\n", line);
			data->idd_err = EINVAL;
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}

static void show_result(struct identity_downcall_data *data)
{
	int i;

	if (data->idd_err) {
		errlog("failed to get identity for uid %d: %s\n",
		       data->idd_uid, strerror(data->idd_err));
		return;
	}

	printf("uid=%d gid=%d", data->idd_uid, data->idd_gid);
	for (i = 0; i < data->idd_ngroups; i++)
		printf(",%u", data->idd_groups[i]);
	printf("\n");
	printf("permissions:\n"
	       "  nid\t\t\tperm\n");
	for (i = 0; i < data->idd_nperms; i++) {
		struct perm_downcall_data *pdd;

		pdd = &data->idd_perms[i];

		printf("  %#jx\t0x%x\n", (uintmax_t)pdd->pdd_nid,
		       pdd->pdd_perm);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	char *end;
	struct identity_downcall_data *data = NULL;
	glob_t path;
	unsigned long uid;
	int fd, rc = -EINVAL, size, maxgroups;

	progname = basename(argv[0]);
	if (argc != 3) {
		usage();
		goto out;
	}

	uid = strtoul(argv[2], &end, 0);
	if (*end) {
		errlog("%s: invalid uid '%s'\n", progname, argv[2]);
		goto out;
	}

	maxgroups = sysconf(_SC_NGROUPS_MAX);
	if (maxgroups > NGROUPS_MAX)
		maxgroups = NGROUPS_MAX;
	if (maxgroups == -1) {
		rc = -EINVAL;
		goto out;
	}

	size = offsetof(struct identity_downcall_data, idd_groups[maxgroups]);
	data = malloc(size);
	if (!data) {
		errlog("malloc identity downcall data(%d) failed!\n", size);
		rc = -ENOMEM;
		goto out;
	}

	memset(data, 0, size);
	data->idd_magic = IDENTITY_DOWNCALL_MAGIC;
	data->idd_uid = uid;
	/* get groups for uid */
	rc = get_groups_local(data, maxgroups);
	if (rc)
		goto downcall;

	size = offsetof(struct identity_downcall_data,
			idd_groups[data->idd_ngroups]);
	/* read permission database */
	rc = get_perms(data);

downcall:
	if (strcmp(argv[1], "-d") == 0 || getenv("L_GETIDENTITY_TEST")) {
		show_result(data);
		rc = 0;
		goto out;
	}

	rc = cfs_get_param_paths(&path, "mdt/%s/identity_info", argv[1]);
	if (rc != 0) {
		rc = -errno;
		goto out;
	}

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd < 0) {
		errlog("can't open file '%s':%s\n", path.gl_pathv[0],
		       strerror(errno));
		rc = -errno;
		goto out_params;
	}

	rc = write(fd, data, size);
	close(fd);
	if (rc != size) {
		errlog("partial write ret %d: %s\n", rc, strerror(errno));
		rc = -1;
	} else {
		rc = 0;
	}

out_params:
	cfs_free_param_data(&path);
out:
	if (data)
		free(data);
	return rc;
}
