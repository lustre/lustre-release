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
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <stddef.h>
#include <libgen.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <nss.h>
#include <dlfcn.h>

#include <libcfs/util/param.h>
#include <linux/lnet/nidstr.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_idl.h>

#define PERM_PATHNAME "/etc/lustre/perm.conf"
#define LUSTRE_PASSWD "/etc/lustre/passwd"
#define LUSTRE_GROUP  "/etc/lustre/group"

#define L_GETIDENTITY_LOOKUP_CMD "lookup"
#define NSS_MODULES_MAX_NR 8
#define NSS_MODULE_NAME_SIZE 32
#define NSS_SYMBOL_NAME_LEN_MAX 256

static int nss_pw_buf_len;
static void *nss_pw_buf;
static int nss_grent_buf_len;
static void *nss_grent_buf;
static int g_n_nss_modules;
static int grent_mod_no = -1;

struct nss_module {
	char name[NSS_MODULE_NAME_SIZE];
	int (*getpwuid)(struct nss_module *mod, uid_t, struct passwd *pwd);
	int (*getgrent)(struct nss_module *mod, struct group *result);
	void (*endgrent)(struct nss_module *mod);
	void (*fini)(struct nss_module *mod);

	union {
		struct {
			void *l_ptr;
			int  (*l_getpwuid)(uid_t, struct passwd *pwd,
					   char *buffer, size_t buflen,
					   int *errnop);
			int  (*l_getgrent)(struct group *result, char *buffer,
					   size_t buflen, int *errnop);
			int  (*l_endgrent)(void);
		} lib;
		struct {
			FILE *f_passwd;
			FILE *f_group;
		} files;
	} u;
};

static struct nss_module g_nss_modules[NSS_MODULES_MAX_NR];

#define NSS_LIB_NAME_PATTERN "libnss_%s.so.2"

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
		"\t-d: debug, print values to stdout instead of Lustre\n"
		"\tNSS support enabled\n",
		progname);
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

static int compare_gids(const void *v1, const void *v2)
{
	return (*(gid_t *)v1 - *(gid_t *)v2);
}

/** getpwuid() replacement */
static struct passwd *getpwuid_nss(uid_t uid)
{
	static struct passwd pw;
	int i;

	for (i = 0; i < g_n_nss_modules; i++) {
		struct nss_module *mod = g_nss_modules + i;

		if (mod->getpwuid(mod, uid, &pw) == 0)
			return &pw;
	}
	return NULL;
}

/**
 * getgrent() replacement.
 *  simulate getgrent(3) across nss modules
 */
static struct group *getgrent_nss(void)
{
	static struct group grp;

	if (grent_mod_no < 0)
		grent_mod_no = 0;

	while (grent_mod_no < g_n_nss_modules) {
		struct nss_module *mod = g_nss_modules + grent_mod_no;

		if (mod->getgrent(mod, &grp) == 0)
			return &grp;
		mod->endgrent(mod);
		grent_mod_no++;
	}
	return NULL;
}

/** endgrent() replacement */
static void endgrent_nss(void)
{
	if (grent_mod_no < g_n_nss_modules
		&& grent_mod_no >= 0) {
		struct nss_module *mod = g_nss_modules+grent_mod_no;

		mod->endgrent(mod);
	}
	grent_mod_no = -1;
}

/** lookup symbol in dynamically loaded nss module */
static void *get_nss_sym(struct nss_module *mod, const char *op)
{
	void *res;
	int bytes;
	char symbuf[NSS_SYMBOL_NAME_LEN_MAX];

	bytes = snprintf(symbuf, NSS_SYMBOL_NAME_LEN_MAX - 1, "_nss_%s_%s",
			mod->name, op);
	if (bytes >= NSS_SYMBOL_NAME_LEN_MAX - 1) {
		errlog("symbol name too long\n");
		return NULL;
	}
	res = dlsym(mod->u.lib.l_ptr, symbuf);
	if (res == NULL)
		errlog("cannot find symbol %s in nss module \"%s\": %s\n",
			symbuf, mod->name, dlerror());
	return res;
}

/** allocate bigger buffer */
static void enlarge_nss_buffer(void **buf, int *bufsize)
{
	free(*buf);
	*bufsize = *bufsize * 2;
	*buf = malloc(*bufsize);
	if (*buf == NULL) {
		errlog("no memory to allocate bigger buffer of %d bytes\n",
			*bufsize);
		exit(-1);
	}
}

static int getpwuid_nss_lib(struct nss_module *nss, uid_t uid,
			    struct passwd *pw)
{
	int tmp_errno, err;

	while (1) {
		err = nss->u.lib.l_getpwuid(uid, pw, nss_pw_buf,
				nss_pw_buf_len, &tmp_errno);
		if (err == NSS_STATUS_TRYAGAIN) {
			if (tmp_errno == ERANGE) {
				/* buffer too small */
				enlarge_nss_buffer(&nss_pw_buf,
						&nss_pw_buf_len);
			}
			continue;
		}
		break;
	}
	if (err == NSS_STATUS_SUCCESS)
		return 0;
	return -ENOENT;
}

static int getgrent_nss_lib(struct nss_module *nss, struct group *gr)
{
	int tmp_errno, err;

	while (1) {
		err = nss->u.lib.l_getgrent(gr, nss_grent_buf,
				nss_grent_buf_len, &tmp_errno);
		if (err == NSS_STATUS_TRYAGAIN) {
			if (tmp_errno == ERANGE) {
				/* buffer too small */
				enlarge_nss_buffer(&nss_grent_buf,
						&nss_grent_buf_len);
			}
			continue;
		}
		break;
	}
	if (err == NSS_STATUS_SUCCESS)
		return 0;
	return -ENOENT;
}

static void endgrent_nss_lib(struct nss_module *mod)
{
	mod->u.lib.l_endgrent();
}

/** destroy a "shared lib" nss module */
static void fini_nss_lib_module(struct nss_module *mod)
{
	if (mod->u.lib.l_ptr)
		dlclose(mod->u.lib.l_ptr);
}

/** load and initialize a "shared lib" nss module */
static int init_nss_lib_module(struct nss_module *mod, char *name)
{
	char lib_file_name[sizeof(NSS_LIB_NAME_PATTERN) + sizeof(mod->name)];

	if (strlen(name) >= sizeof(mod->name)) {
		errlog("module name (%s) too long\n", name);
		exit(1);
	}

	strncpy(mod->name, name, sizeof(mod->name));
	mod->name[sizeof(mod->name) - 1] = '\0';

	snprintf(lib_file_name, sizeof(lib_file_name), NSS_LIB_NAME_PATTERN,
		 name);

	mod->getpwuid = getpwuid_nss_lib;
	mod->getgrent = getgrent_nss_lib;
	mod->endgrent = endgrent_nss_lib;
	mod->fini = fini_nss_lib_module;

	mod->u.lib.l_ptr = dlopen(lib_file_name, RTLD_NOW);
	if (mod->u.lib.l_ptr == NULL) {
		errlog("dl error %s\n", dlerror());
		exit(1);
	}
	mod->u.lib.l_getpwuid = get_nss_sym(mod, "getpwuid_r");
	if (mod->getpwuid == NULL)
		exit(1);

	mod->u.lib.l_getgrent = get_nss_sym(mod, "getgrent_r");
	if (mod->getgrent == NULL)
		exit(1);

	mod->u.lib.l_endgrent = get_nss_sym(mod, "endgrent");
	if (mod->endgrent == NULL)
		exit(1);

	return 0;
}

static void fini_lustre_nss_module(struct nss_module *mod)
{
	if (mod->u.files.f_passwd)
		fclose(mod->u.files.f_passwd);
	if (mod->u.files.f_group)
		fclose(mod->u.files.f_group);
}

static int getpwuid_lustre_nss(struct nss_module *mod, uid_t uid,
			      struct passwd *pw)
{
	struct passwd *pos;

	while ((pos = fgetpwent(mod->u.files.f_passwd)) != NULL) {
		if (pos->pw_uid == uid) {
			*pw = *pos;
			return 0;
		}
	}
	return -1;
}

static int getgrent_lustre_nss(struct nss_module *mod, struct group *gr)
{
	struct group *pos;

	pos = fgetgrent(mod->u.files.f_group);
	if (pos) {
		*gr = *pos;
		return 0;
	}
	return 1;
}

static void endgrent_lustre_nss(struct nss_module *mod)
{
}

/** initialize module to access local /etc/lustre/passwd,group files */
static int init_lustre_module(struct nss_module *mod)
{
	mod->fini = fini_lustre_nss_module;
	mod->getpwuid = getpwuid_lustre_nss;
	mod->getgrent = getgrent_lustre_nss;
	mod->endgrent = endgrent_lustre_nss;

	mod->u.files.f_passwd = fopen(LUSTRE_PASSWD, "r");
	if (mod->u.files.f_passwd == NULL)
		exit(1);

	mod->u.files.f_group = fopen(LUSTRE_GROUP, "r");
	if (mod->u.files.f_group == NULL)
		exit(1);

	snprintf(mod->name, sizeof(mod->name), "lustre");
	return 0;
}

/** load and initialize the "nss" system */
static void init_nss(void)
{
	nss_pw_buf_len = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (nss_pw_buf_len == -1) {
		perror("sysconf");
		exit(1);
	}
	nss_pw_buf = malloc(nss_pw_buf_len);
	if (nss_pw_buf == NULL) {
		perror("pw buffer allocation");
		exit(1);
	}

	nss_grent_buf_len = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (nss_grent_buf_len == -1) {
		perror("sysconf");
		exit(1);
	}
	nss_grent_buf = malloc(nss_grent_buf_len);
	if (nss_grent_buf == NULL) {
		perror("grent buffer allocation");
		exit(1);
	}
}

/** unload "nss" */
static void fini_nss(void)
{
	int i;

	for (i = 0; i < g_n_nss_modules; i++) {
		struct nss_module *mod = g_nss_modules + i;

		mod->fini(mod);
	}

	free(nss_pw_buf);
	free(nss_grent_buf);
}

/** get supplementary group info and fill downcall data */
static int get_groups_nss(struct identity_downcall_data *data,
			  unsigned int maxgroups)
{
	struct passwd *pw;
	struct group *gr;
	gid_t *groups;
	unsigned int ngroups = 0;
	char *pw_name;
	int i;

	pw = getpwuid_nss(data->idd_uid);
	if (pw == NULL) {
		data->idd_err = errno ? errno : EIDRM;
		errlog("no such user %u\n", data->idd_uid);
		return -1;
	}

	data->idd_gid = pw->pw_gid;
	pw_name = strdup(pw->pw_name);
	groups = data->idd_groups;

	while ((gr = getgrent_nss()) != NULL && ngroups < maxgroups) {
		if (gr->gr_gid == pw->pw_gid)
			continue;
		if (!gr->gr_mem)
			continue;
		for (i = 0; gr->gr_mem[i]; i++) {
			if (!strcmp(gr->gr_mem[i], pw_name)) {
				groups[ngroups++] = gr->gr_gid;
				break;
			}
		}
	}

	endgrent_nss();

	if (ngroups > 0)
		qsort(groups, ngroups, sizeof(*groups), compare_gids);
	data->idd_ngroups = ngroups;

	free(pw_name);
	return 0;
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
		qsort(groups, ngroups, sizeof(*groups), compare_gids);
	data->idd_ngroups = ngroups;

	free(groups_tmp);
	return 0;
}

int get_groups_common(struct identity_downcall_data *data,
		      unsigned int maxgroups)
{
	if (g_n_nss_modules)
		return get_groups_nss(data, maxgroups);
	return get_groups_local(data, maxgroups);
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

struct perm_type {
	char *name;
	__u32 bit;
};

static struct perm_type perm_types[] = {
	{ "setuid", CFS_SETUID_PERM },
	{ "setgid", CFS_SETGID_PERM },
	{ "setgrp", CFS_SETGRP_PERM },
	{ "rmtacl", 0 },
	{ "rmtown", 0 },
	{ 0 }
};

static struct perm_type noperm_types[] = {
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
	struct perm_type *pt;

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

static char *striml(char *s)
{
	while (isspace(*s))
		s++;
	return s;
}

static void check_new_nss_module(struct nss_module *mod)
{
	int i;

	for (i = 0; i < g_n_nss_modules; i++) {
		struct nss_module *pos = g_nss_modules + i;

		if (!strcmp(mod->name, pos->name)) {
			errlog("attempt to initialize \"%s\" module twice\n",
				pos->name);
			exit(-1);
		}
	}
}

#define ONE_DAY (24 * 60 * 60)

static void do_warn_interval(struct timeval *now)
{
	bool write_warning = false;
	bool show_warning = false;
	const char *perm_warning = PERM_PATHNAME "-warning";
	struct stat sbuf;
	const char msg[] =
		"Use 'lookup lustre'. The 'files' alias is deprecated.\n";

	if (stat(perm_warning, &sbuf)) {
		if (errno == ENOENT)
			write_warning = true;
	} else {
		show_warning = (now->tv_sec - sbuf.st_mtim.tv_sec) > ONE_DAY;
		write_warning = sbuf.st_size == 0; /* file still empty? */
	}

	if (write_warning || show_warning) {
		const struct timespec times[] = {
			{.tv_sec = UTIME_NOW},
			{.tv_sec = UTIME_NOW},
		};
		mode_t mode = 0640;
		int oflags = O_RDWR | O_CREAT;
		int fd = open(perm_warning, oflags, mode);

		/* if we cannot rate-limit ... better to be quiet */
		if (fd == -1)
			return;
		if (write_warning) {
			ssize_t written = write(fd, msg, sizeof(msg));

			/* unlikely, but rate-limiting may be broken */
			if (written <= 0)
				goto out_close;
		}
		errlog("WARNING: %s", msg);

		/* rate limiting is working */
		if (show_warning)
			if (futimens(fd, times) < 0)
				errlog("Change Timestamp failed: %s\n",
				       strerror(errno));
out_close:
		close(fd);
	}
}

/** initialize module to access local /etc/lustre/passwd,group files */
static int init_lustre_files_module(struct nss_module *mod,
				    struct timeval *start)
{
	do_warn_interval(start);
	return init_lustre_module(mod);
}

/**
 * Check and parse lookup db config line.
 * File should start with 'lookup' followed by the modules
 * to be loaded, for example:
 *
 *  [/etc/lustre/perm.conf]
 *  lookup lustre ldap
 *
 * Should search, in order, first found wins:
 *    lustre [/etc/lustre/passwd and /etc/lustre/group]
 *    ldap
 *
 * Other common nss modules: nis sss db files
 * Since historically 'files' has been used exclusively
 *  to mean 'lustre auth files' and disabled using local auth
 *  via libnss_files users must select 'nss_files' to explicitly
 *  enable libnss_files, which is an uncommon configuration.
 */
static int lookup_db_line_nss(char *line, struct timeval *start)
{
	char *p, *tok;
	int ret = 0;

	p = striml(line);
	if (strncmp(p, L_GETIDENTITY_LOOKUP_CMD,
	    sizeof(L_GETIDENTITY_LOOKUP_CMD) - 1))
		return -EAGAIN;

	tok = strtok(p, " \t");
	if (tok == NULL || strcmp(tok, L_GETIDENTITY_LOOKUP_CMD))
		return -EIO;

	while ((tok = strtok(NULL, " \t\n")) != NULL) {
		struct nss_module *newmod = NULL;

		if (g_n_nss_modules < NSS_MODULES_MAX_NR)
			newmod = &g_nss_modules[g_n_nss_modules];
		else
			return -ERANGE;

		if (!strcmp(tok, "files"))
			ret = init_lustre_files_module(newmod, start);
		else if (!strcmp(tok, "lustre"))
			ret = init_lustre_module(newmod);
		else if (!strcmp(tok, "nss_files"))
			ret = init_nss_lib_module(newmod, "files");
		else
			ret = init_nss_lib_module(newmod, tok);

		if (ret)
			break;
		check_new_nss_module(newmod);
		g_n_nss_modules++;
	}

	return ret;
}

int get_perms(struct identity_downcall_data *data, struct timeval *start)
{
	FILE *fp;
	char line[PATH_MAX];
	int ret;

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
		ret = lookup_db_line_nss(line, start); /* lookup parsed */
		if (ret == 0)
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

#define difftime(a, b)					\
	((a).tv_sec - (b).tv_sec +			\
	 ((a).tv_usec - (b).tv_usec) / 1000000.0)

int main(int argc, char **argv)
{
	char *end;
	struct identity_downcall_data *data = NULL;
	glob_t path;
	unsigned long uid;
	struct timeval start, idgot, fini;
	int fd, rc = -EINVAL, size, maxgroups;
	bool alreadyfailed = false;

	progname = basename(argv[0]);
	if (argc != 3) {
		usage();
		goto out_no_nss;
	}

	errno = 0;
	uid = strtoul(argv[2], &end, 0);
	if (*end != '\0' || end == argv[2] || errno != 0) {
		errlog("%s: invalid uid '%s'\n", progname, argv[2]);
		goto out_no_nss;
	}
	gettimeofday(&start, NULL);

	maxgroups = sysconf(_SC_NGROUPS_MAX);
	if (maxgroups > NGROUPS_MAX)
		maxgroups = NGROUPS_MAX;
	if (maxgroups == -1) {
		rc = -EINVAL;
		goto out_no_nss;
	}

retry:
	size = offsetof(struct identity_downcall_data, idd_groups[maxgroups]);
	data = malloc(size);
	if (!data) {
		errlog("malloc identity downcall data(%d) failed!\n", size);
		if (!alreadyfailed) {
			alreadyfailed = true;
			goto retry;
		}
		rc = -ENOMEM;
		goto out_no_nss;
	}

	memset(data, 0, size);
	data->idd_magic = IDENTITY_DOWNCALL_MAGIC;
	data->idd_uid = uid;

	init_nss();

	/* read permission database and/or load nss modules
	 * rc is -1 only when file exists and is not readable or
	 * content has format / syntax errors
	 */
	rc = get_perms(data, &start);
	if (rc)
		goto downcall;

	/* get groups for uid */
	rc = get_groups_common(data, maxgroups);
	if (rc)
		goto downcall;

	size = offsetof(struct identity_downcall_data,
			idd_groups[data->idd_ngroups]);

	gettimeofday(&idgot, NULL);
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
	gettimeofday(&fini, NULL);
	close(fd);
	if (rc != size) {
		errlog("partial write ret %d: %s\n", rc, strerror(errno));
		if (!alreadyfailed) {
			alreadyfailed = true;
			cfs_free_param_data(&path);
			if (data)
				free(data);
			goto retry;
		}
		rc = -1;
	} else {
		rc = 0;
	}
	/* log if it takes more than 20 second to avoid rate limite */
	if (rc || difftime(fini, start) > 20)
		errlog("get identity for uid %lu start time %ld.%06ld got time %ld.%06ld end time %ld.%06ld: rc = %d\n",
		       uid, start.tv_sec, start.tv_usec, idgot.tv_sec,
		       idgot.tv_usec, fini.tv_sec, fini.tv_usec, rc);

out_params:
	cfs_free_param_data(&path);
out:
	fini_nss();
out_no_nss:
	if (data)
		free(data);
	return rc;
}
