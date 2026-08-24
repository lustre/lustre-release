// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * lfs find's command line in one place: the predicate table, its parse loop
 * and the argument helpers.
 */

/* strptime() is declared only under _XOPEN_SOURCE or _GNU_SOURCE, and this
 * file is meant to compile outside lustre/utils' AM_CFLAGS as well
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <libcfs/util/parser.h>
#include <linux/lustre/lustre_idl.h>
#include <lustre/lustreapi.h>
#include "lfs_find_parse.h"
#include "lstddef.h"

static int xattr_match_info_append(struct xattr_match_info *xmi, bool exclude,
				   char *name_pattern, char *value_pattern);

bool arg_is_eof(char *arg)
{
	return !strncmp(arg, "-1", strlen("-1")) ||
	       !strncmp(arg, "EOF", strlen("EOF")) ||
	       !strncmp(arg, "eof", strlen("eof"));
}

uint32_t check_foreign_type_name(const char *foreign_type_name)
{
	uint32_t i;

	for (i = 0; i < LU_FOREIGN_TYPE_UNKNOWN; i++) {
		if (!lu_foreign_types[i].lft_name)
			break;
		if (strcmp(foreign_type_name,
			   lu_foreign_types[i].lft_name) == 0)
			return lu_foreign_types[i].lft_type;
	}

	return LU_FOREIGN_TYPE_UNKNOWN;
}

/*
 * Convert input string (dir hash) to its number value
 *
 * Return 0 on unrecognized hash (failure) or positive value on success
 */
enum lmv_hash_type check_hashtype(const char *hashtype)
{
	int type_num;
	int i;

	if (!hashtype)
		goto out;

	type_num = atoi(hashtype);

	/* numeric hash type */
	if (lmv_is_known_hash_type(type_num))
		return type_num;
	/* string hash type */
	for (i = LMV_HASH_TYPE_ALL_CHARS; i < ARRAY_SIZE(mdt_hash_name); i++)
		if (strcmp(hashtype, mdt_hash_name[i]) == 0)
			return i;
out:
	return LMV_HASH_TYPE_UNKNOWN;
}

/**
 * compile_xattr_match_regex() - Compile regexes for matching xattr names and
 * values, returning an error if either fails to compile.
 * @optarg: Input (example NAME=VALUE)
 * @exclude: If %true exclude extended attr, else if %false include attr
 * @param: Pointer to struct find_param
 *
 * The argument should be in the form "NAME=VALUE". The first '=' found
 * is assumed to be the separator between the name regex and the value regex.
 *
 * VALUE may be empty. If it is empty, it is not compiled and left NULL.
 * NAME must not be empty.
 *
 * Return: 0 if argument string is succesfully processed, nonzero if any
 *         errors encountered.
 */
static int compile_xattr_match_regex(char *optarg, bool exclude,
				     struct find_param *param)
{
	char *sep;

	sep = strchr(optarg, '=');
	if (sep)
		*sep = '\0';

	/* error if no NAME pattern specified */
	if (*optarg == '\0') {
		fprintf(stderr, "%s: must specify xattr pattern\n", progname);
		return CMD_HELP;
	}

	/* if first -xattr option seen */
	if (param->fp_xattr_match_info == NULL) {
		param->fp_xattr_match_info = calloc(1,
					sizeof(struct xattr_match_info));
		if (param->fp_xattr_match_info == NULL) {
			fprintf(stderr, "%s: %s\n", progname, strerror(ENOMEM));
			return -ENOMEM;
		}
	}

	/*
	 * if '=' was not provided, or if there is no value after the '=',
	 * then pass NULL to xattr_match_info_append() so that no VALUE regex
	 * is compiled.
	 */
	if (sep) {
		sep++;
		if (*sep == '\0')
			sep = NULL;
	}

	return xattr_match_info_append(param->fp_xattr_match_info, exclude,
				       optarg, sep);
}

int comp_str2flags(char *string, __u32 *flags, __u32 *neg_flags)
{
	char *name;
	char *dup_string = NULL;
	int rc = 0;

	*flags = 0;
	*neg_flags = 0;

	if (!string || !string[0])
		return -EINVAL;

	dup_string = strdup(string);
	if (!dup_string) {
		llapi_printf(LLAPI_MSG_ERROR,
			     "%s: insufficient memory\n",
			     progname);
		return -ENOMEM;
	}

	for (name = strtok(dup_string, ","); name; name = strtok(NULL, ",")) {
		bool found = false;
		int i;

		for (i = 0; i < ARRAY_SIZE(comp_flags_table); i++) {
			__u32 comp_flag = comp_flags_table[i].cfn_flag;
			const char *comp_name = comp_flags_table[i].cfn_name;

			if (strcmp(name, comp_name) == 0) {
				*flags |= comp_flag;
				found = true;
			} else if (strncmp(name, "^", 1) == 0 &&
				   strcmp(name + 1, comp_name) == 0) {
				*neg_flags |= comp_flag;
				found = true;
			}
		}
		if (!found) {
			llapi_printf(LLAPI_MSG_ERROR,
				     "%s: component flag '%s' not supported\n",
				     progname, name);
			rc = -EINVAL;
			goto out_free;
		}
	}

	if (!*flags && !*neg_flags)
		rc = -EINVAL;

	/* don't allow to set and exclude the same flag */
	if (*flags & *neg_flags)
		rc = -EINVAL;

out_free:
	free(dup_string);
	return rc;
}

static int mdthash_input(char *string, __u32 *inflags,
			 __u32 *exflags, __u32 *type)
{
	char *name;
	struct mhf_list {
		char *name;
		__u32 flag;
	} mhflist[] = {
		{"migrating", LMV_HASH_FLAG_MIGRATION},
		{"bad_type", LMV_HASH_FLAG_BAD_TYPE},
		{"badtype", LMV_HASH_FLAG_BAD_TYPE},
		{"lost_lmv", LMV_HASH_FLAG_LOST_LMV},
		{"lostlmv", LMV_HASH_FLAG_LOST_LMV},
	};

	if (string == NULL)
		return -EINVAL;

	*inflags = 0;
	*exflags = 0;
	*type = 0;
	for (name = strtok(string, ","); name; name = strtok(NULL, ",")) {
		bool found = false;
		int i;

		for (i = 0; i < ARRAY_SIZE(mhflist); i++) {
			if (strcmp(name, mhflist[i].name) == 0 ||
			    name[0] == mhflist[i].name[0]) {
				*inflags |= mhflist[i].flag;
				found = true;
			} else if (name[0] == '^' &&
				   (strcmp(name + 1, mhflist[i].name) == 0 ||
				    name[1] == mhflist[i].name[0])) {
				*exflags |= mhflist[i].flag;
				found = true;
			}
		}
		if (!found) {
			i = check_hashtype(name);
			if (i > 0) {
				*type |= 1 << i;
				continue;
			}
			llapi_printf(LLAPI_MSG_ERROR,
				     "%s: invalid mdt_hash value '%s'\n",
				     progname, name);
			return -EINVAL;
		}
	}

	/* don't allow to include and exclude the same flag */
	if (*inflags & *exflags) {
		llapi_printf(LLAPI_MSG_ERROR,
			     "%s: include and exclude same flag '%s'\n",
			     progname, string);
		return -EINVAL;
	}

	return 0;
}

static int mirror_str2state(char *string, __u16 *state, __u16 *neg_state)
{
	if (!string)
		return -EINVAL;

	*state = 0;
	*neg_state = 0;

	if (strncmp(string, "^", 1) == 0) {
		*neg_state = llapi_layout_string_flags(string + 1);
		if (*neg_state != 0)
			return 0;
	} else {
		*state = llapi_layout_string_flags(string);
		if (*state != 0)
			return 0;
	}

	llapi_printf(LLAPI_MSG_ERROR,
		     "%s: mirrored file state '%s' not supported\n",
		     progname, string);
	return -EINVAL;
}

static int name2attrs(char *name, __u64 *attrs, __u64 *neg_attrs)
{
	char *ptr, *attr_name = name;
	struct attrs_name *ap;
	int islongopt = 0; /* 1 true; 0 not known yet; -1 false. */

	*attrs = 0;
	*neg_attrs = 0;

	if (strchr(name, ','))
		islongopt = 1;

	for (ptr = name; ; ptr = NULL) {
		if (islongopt != -1)
			attr_name = strtok(ptr, ",");
		else
			attr_name = attr_name + 1;
		if (!attr_name || *attr_name == '\0')
			break;

		for (ap = (struct attrs_name *)attrs_array;
		     ap->an_attr != 0;
		     ap++) {
			if (islongopt != -1 &&
			    strcmp(attr_name, ap->an_name) == 0) {
				*attrs |= ap->an_attr;
				islongopt = 1;
				break;
			} else if (islongopt != -1 && attr_name[0] == '^' &&
				   strcmp(attr_name + 1, ap->an_name) == 0) {
				*neg_attrs |= ap->an_attr;
				islongopt = 1;
				break;
			} else if (islongopt != 1 &&
				   *attr_name == ap->an_shortname) {
				*attrs |= ap->an_attr;
				islongopt = -1;
				break;
			} else if (islongopt != 1 && *attr_name == '^' &&
				   attr_name[1] == ap->an_shortname) {
				*neg_attrs |= ap->an_attr;
				islongopt = -1;
				attr_name++;
				break;
			}
		}

		if (ap->an_attr == 0) {
			/* provided attr is unknown */
			fprintf(stderr, "error: bad attribute name '%s'\n",
				attr_name);
			return -1;
		}
	}
	return 0;
}

int name2gid(__u32 *id, const char *name)
{
	struct group *group;

	group = getgrnam(name);
	if (!group)
		return -ENOENT;
	*id = group->gr_gid;

	return 0;
}

int name2projid(__u32 *id, const char *name)
{
	struct ll_project prj = { .lprj_valid = LPRJ_VALID_SIZE,
				  .lprj_size = sizeof(prj) };
	int rc;
	const char *name2;

	name2 = strchr(name, ':');
	if (name2) {
		name2++;
		rc = str2quotaid(id, name2);
		if (!rc)
			return 0;
		if (strncmp(name, "u:", 2) == 0 ||
		    strncmp(name, "user:", 5) == 0)
			return name2uid(id, name2);
		if (strncmp(name, "g:", 2) == 0 ||
		    strncmp(name, "group:", 5) == 0)
			return name2gid(id, name2);
		return -EINVAL;
	}

	rc = llapi_project_getnam(&prj, name);
	if (rc)
		return rc;

	if (prj.lprj_valid & LPRJ_VALID_ID)
		*id = prj.lprj_projid;
	else
		rc = -ENOENT;

	return rc;
}

int name2uid(__u32 *id, const char *name)
{
	struct passwd *passwd;

	passwd = getpwnam(name);
	if (!passwd)
		return -ENOENT;
	*id = passwd->pw_uid;

	return 0;
}

static int parse_symbolic(const char *input, mode_t *outmode, const char **end)
{
	int loop;
	int user, group, other;
	int who, all;
	char c, op;
	mode_t perm;
	mode_t usermask;
	mode_t previous_flags;

	user = group = other = 0;
	all = 0;
	loop = 1;
	perm = 0;
	previous_flags = 0;
	*end = input;
	usermask = 0;

	while (loop) {
		switch (*input) {
		case 'u':
			user = 1;
			break;
		case 'g':
			group = 1;
			break;
		case 'o':
			other = 1;
			break;
		case 'a':
			user = group = other = 1;
			all = 1;
			break;
		default:
			loop = 0;
		}

		if (loop)
			input++;
	}

	who = user || group || other;
	if (!who) {
		/* get the umask */
		usermask = umask(0022);
		umask(usermask);
		usermask &= 07777;
	}

	if (*input == '-' || *input == '+' || *input == '=')
		op = *input++;
	else
		/* operation is required */
		return -1;

	/* get the flags in *outmode */
	switch (*input) {
	case 'u':
		previous_flags = (*outmode & 0700);
		perm |= user  ? previous_flags : 0;
		perm |= group ? (previous_flags >> 3) : 0;
		perm |= other ? (previous_flags >> 6) : 0;
		input++;
		goto write_perm;
	case 'g':
		previous_flags = (*outmode & 0070);
		perm |= user  ? (previous_flags << 3) : 0;
		perm |= group ? previous_flags : 0;
		perm |= other ? (previous_flags >> 3) : 0;
		input++;
		goto write_perm;
	case 'o':
		previous_flags = (*outmode & 0007);
		perm |= user  ? (previous_flags << 6) : 0;
		perm |= group ? (previous_flags << 3) : 0;
		perm |= other ? previous_flags : 0;
		input++;
		goto write_perm;
	default:
		break;
	}

	/* this part is optional,
	 * if empty perm = 0 and *outmode is not modified
	 */
	loop = 1;
	while (loop) {
		c = *input;
		switch (c) {
		case 'r':
			perm |= user  ? 0400 : 0;
			perm |= group ? 0040 : 0;
			perm |= other ? 0004 : 0;
			/* set read permission for uog except for umask's
			 * permissions
			 */
			perm |= who   ? 0 : (0444 & ~usermask);
			break;
		case 'w':
			perm |= user  ? 0200 : 0;
			perm |= group ? 0020 : 0;
			perm |= other ? 0002 : 0;
			/* set write permission for uog except for umask'
			 * permissions
			 */
			perm |= who   ? 0 : (0222 & ~usermask);
			break;
		case 'x':
			perm |= user  ? 0100 : 0;
			perm |= group ? 0010 : 0;
			perm |= other ? 0001 : 0;
			/* set execute permission for uog except for umask'
			 * permissions
			 */
			perm |= who   ? 0 : (0111 & ~usermask);
			break;
		case 'X':
			/*
			 * Adds execute permission to 'u', 'g' and/or 'g' if
			 * specified and either 'u', 'g' or 'o' already has
			 * execute permissions.
			 */
			if ((*outmode & 0111) != 0) {
				perm |= user  ? 0100 : 0;
				perm |= group ? 0010 : 0;
				perm |= other ? 0001 : 0;
				perm |= !who  ? 0111 : 0;
			}
			break;
		case 's':
			/* s is ignored if o is given, but it's not an error */
			if (other && !group && !user)
				break;
			perm |= user  ? S_ISUID : 0;
			perm |= group ? S_ISGID : 0;
			break;
		case 't':
			/* 't' should be used when 'a' is given
			 * or who is empty
			 */
			perm |= (!who || all) ? S_ISVTX : 0;
			/* using ugo with t is not an error */
			break;
		default:
			loop = 0;
			break;
		}
		if (loop)
			input++;
	}

write_perm:
	/* uog flags should be only one character long */
	if (previous_flags && (*input != '\0' && *input != ','))
		return -1;

	switch (op) {
	case '-':
		/* remove the flags from outmode */
		*outmode &= ~perm;
		break;
	case '+':
		/* add the flags to outmode */
		*outmode |= perm;
		break;
	case '=':
		/* set the flags of outmode to perm */
		if (perm != 0)
			*outmode = perm;
		break;
	}

	*end = input;
	return 0;
}

static int set_time(struct find_param *param, time_t *time, time_t *set_t,
		    int *sign_t, char *str)
{
	long long t = 0;
	int sign = 0;
	char *endptr = "AD";
	char *timebuf;
	time_t prev_set = 0;
	int prev_sign = 0;

	if (str[0] == '+')
		sign = 1;
	else if (str[0] == '-')
		sign = -1;

	if (sign)
		str++;

	if (*set_t) {
		prev_set = *set_t;
		prev_sign = *sign_t;
	}

	for (timebuf = str; *endptr && *(endptr + 1); timebuf = endptr + 1) {
		long long val = strtoll(timebuf, &endptr, 0);
		int unit = 1;

		switch (*endptr) {
		case  'y':
			unit *= 52; /* 52 weeks + 1 day below */
			fallthrough;
		case  'w':
			unit *= 7;
			if (param->fp_time_margin == FP_DEFAULT_TIME_MARGIN)
				param->fp_time_margin *= (1 + unit / 52);
			unit += (*endptr == 'y'); /* +1 day for 365 days/year */
			fallthrough;
		case '\0': /* days are default unit if none used */
			fallthrough;
		case  'd':
			unit *= 24;
			fallthrough;
		case  'h':
			unit *= 60;
			fallthrough;
		case  'm':
			unit *= 60;
			fallthrough;
		case  's':
			break;
			/* don't need to multiply by 1 for seconds */
		default:
			fprintf(stderr,
				"%s find: bad time string '%s': %s\n",
				progname, timebuf, strerror(EINVAL));
			return INT_MAX;
		}

		if (param->fp_time_margin == 0 ||
		    (*endptr && unit < param->fp_time_margin))
			param->fp_time_margin = unit;

		t += val * unit;
	}
	if (*time < t) {
		if (sign != 0)
			str--;
		fprintf(stderr, "%s find: bad time '%s': too large\n",
			progname, str);
		return INT_MAX;
	}

	*set_t = *time - t;
	/* if user requested a time range via "-xtime +M -xtime -N" then
	 * use the largest time and increase margin to cover the difference
	 * This will occur as long as the signs differ.
	 */
	if (sign * prev_sign == -1) {
		param->fp_time_margin = abs(*set_t - prev_set);
		if (prev_set > *set_t)
			*set_t = prev_set;
		return 0;
	}

	return sign;
}

static int str2mode_t(const char *input, mode_t *outmode)
{
	int ret;
	const char *iter;

	ret = 0;

	if (*input >= '0' && *input <= '7') {
		/* parse octal representation */
		char *end;

		iter = input;

		/* look for invalid digits in octal representation */
		while (isdigit(*iter))
			if (*iter++ > '7')
				return -1;

		errno = 0;
		*outmode = strtoul(input, &end, 8);

		if (errno != 0 || *outmode > 07777) {
			*outmode = 0;
			ret = -1;
		}

	} else if (*input == '8' || *input == '9') {
		/* error: invalid octal number */
		ret = -1;
	} else {
		/* parse coma seperated list of symbolic representation */
		int rc;
		const char *end;

		*outmode = 0;
		rc = 0;
		end = NULL;

		do {
			rc = parse_symbolic(input, outmode, &end);
			if (rc)
				return -1;

			input = end+1;
		} while (*end == ',');

		if (*end != '\0')
			ret = -1;
	}
	return ret;
}

int str2quotaid(__u32 *id, const char *arg)
{
	unsigned long id_tmp = 0;
	char *endptr = NULL;

	id_tmp = strtoul(arg, &endptr, 10);
	if (*endptr != '\0')
		return -EINVAL;
	/* UINT32_MAX is not allowed - see projid_valid()/INVALID_PROJID */
	if (id_tmp >= MDT_INVALID_PROJID)
		return -ERANGE;

	*id = id_tmp;
	return 0;
}

/**
 * xattr_match_info_append() - add the supplied name and value regex patterns
 *                             to the supplied xattr_match_info struct.
 * @xmi: key-value store (pointer to struct xattr_match_info)
 * @exclude: If %true exclude extended attr, else if %false include attr
 * @name_pattern: extended attributes name
 * @value_pattern: extended attributes value
 *
 * Return: %0 for success, nonzero if any errors encountered.
 */
static int xattr_match_info_append(struct xattr_match_info *xmi, bool exclude,
				   char *name_pattern, char *value_pattern)
{
	int flags = REG_EXTENDED;
	char *err_buf;
	int err_len;
	void *nptr;
	int ret;
	int n;

	if (xmi->xattr_name_buf == NULL) {
		xmi->xattr_name_buf = malloc(XATTR_LIST_MAX);
		if (xmi->xattr_name_buf == NULL)
			goto err_out;
	}

	if (xmi->xattr_value_buf == NULL) {
		/*
		 * an xattr value need not be null-terminated, so allocate an
		 * extra byte to append a '\0', since regexec() expects a null-
		 * terminated string.
		 */
		xmi->xattr_value_buf = malloc(XATTR_SIZE_MAX + 1);
		if (xmi->xattr_value_buf == NULL)
			goto err_out;
	}

	n = ++xmi->xattr_regex_count;

	nptr = realloc(xmi->xattr_regex_matched, n * sizeof(bool));
	if (nptr == NULL)
		goto err_out;
	xmi->xattr_regex_matched = nptr;

	nptr = realloc(xmi->xattr_regex_exclude, n * sizeof(bool));
	if (nptr == NULL)
		goto err_out;
	xmi->xattr_regex_exclude = nptr;

	nptr = realloc(xmi->xattr_regex_name, n * sizeof(regex_t *));
	if (nptr == NULL)
		goto err_out;
	xmi->xattr_regex_name = nptr;

	nptr = realloc(xmi->xattr_regex_value, n * sizeof(regex_t *));
	if (nptr == NULL)
		goto err_out;
	xmi->xattr_regex_value = nptr;

	n--;

	xmi->xattr_regex_exclude[n] = exclude;

	xmi->xattr_regex_name[n] = malloc(sizeof(regex_t));
	if (xmi->xattr_regex_name[n] == NULL)
		goto err_out;

	ret = regcomp(xmi->xattr_regex_name[n], name_pattern, flags);
	if (ret) {
		err_len = regerror(ret, xmi->xattr_regex_name[n], NULL, 0);
		err_buf = malloc(err_len);
		if (err_buf == NULL)
			goto err_out;

		regerror(ret, xmi->xattr_regex_name[n], err_buf, err_len);
		fprintf(stderr, "%s: %s: %s\n",
			progname, name_pattern, err_buf);
		free(err_buf);
		return ret;
	}

	if (value_pattern && value_pattern[0] != '\0') {
		xmi->xattr_regex_value[n] = malloc(sizeof(regex_t));
		ret = regcomp(xmi->xattr_regex_value[n], value_pattern, flags);
		if (ret) {
			err_len = regerror(ret, xmi->xattr_regex_value[n],
					   NULL, 0);
			err_buf = malloc(err_len);
			if (err_buf == NULL)
				goto err_out;

			regerror(ret, xmi->xattr_regex_value[n], err_buf,
				 err_len);
			fprintf(stderr, "%s: %s: %s\n",
				progname, value_pattern, err_buf);
			free(err_buf);
			return ret;
		}
	} else {
		xmi->xattr_regex_value[n] = NULL;
	}

	return 0;

err_out:
	fprintf(stderr, "%s: %s\n", progname, strerror(ENOMEM));
	return -ENOMEM;
}

static void xattr_match_info_free(struct xattr_match_info *xmi)
{
	int i;

	free(xmi->xattr_regex_exclude);
	xmi->xattr_regex_exclude = NULL;

	free(xmi->xattr_regex_matched);
	xmi->xattr_regex_matched = NULL;

	for (i = 0; i < xmi->xattr_regex_count; i++) {
		if (xmi->xattr_regex_name[i]) {
			regfree(xmi->xattr_regex_name[i]);
			free(xmi->xattr_regex_name[i]);
		}

		if (xmi->xattr_regex_value[i]) {
			regfree(xmi->xattr_regex_value[i]);
			free(xmi->xattr_regex_value[i]);
		}
	}

	xmi->xattr_regex_count = 0;

	free(xmi->xattr_regex_name);
	xmi->xattr_regex_name = NULL;

	free(xmi->xattr_regex_value);
	xmi->xattr_regex_value = NULL;

	free(xmi->xattr_name_buf);
	xmi->xattr_name_buf = NULL;

	free(xmi->xattr_value_buf);
	xmi->xattr_value_buf = NULL;
}

/* The option table and its loop, moved out of lfs_find() unchanged. */
int lfs_find_parse(int argc, char **argv, struct find_param *param,
		   int *pathstartp, int *pathendp, bool *stopped)
{
	int c, rc;
	int ret = 0;
	time_t t;
	struct option long_opts[] = {
	{ .val = 'A',	.name = "atime",	.has_arg = required_argument },
	{ .val = LFS_ATTRS_OPT,
			.name = "attrs",	.has_arg = required_argument },
	{ .val = 'b',	.name = "blocks",	.has_arg = required_argument },
	{ .val = 'B',	.name = "btime",	.has_arg = required_argument },
	{ .val = 'B',	.name = "Btime",	.has_arg = required_argument },
	{ .val = 'B',	.name = "crtime",	.has_arg = required_argument },
	{ .val = LFS_COMP_COUNT_OPT,
			.name = "comp-count",	.has_arg = required_argument },
	{ .val = LFS_COMP_COUNT_OPT,
			.name = "component-count",
						.has_arg = required_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "comp-flags",	.has_arg = required_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "component-flags",
						.has_arg = required_argument },
	{ .val = LFS_COMP_START_OPT,
			.name = "comp-start",	.has_arg = required_argument },
	{ .val = LFS_COMP_START_OPT,
			.name = "component-start",
						.has_arg = required_argument },
	{ .val = LFS_MIRROR_STATE_OPT,
			.name = "mirror-state",	.has_arg = required_argument },
	{ .val = LFS_NEWERXY_OPT,
			.name = "newer",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "neweraa",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "neweram",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerac",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerab",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerma",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newermm",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newermc",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newermb",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerca",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newercm",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newercc",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newercb",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerba",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerbm",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerbc",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerbb",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBa",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBm",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBc",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBB",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerat",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newermt",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerct",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerbt",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBt",	.has_arg = required_argument},
	{ .val = 'c',	.name = "stripe-count",	.has_arg = required_argument },
	{ .val = 'c',	.name = "stripe_count",	.has_arg = required_argument },
	{ .val = 'C',	.name = "ctime",	.has_arg = required_argument },
/* getstripe { .val = 'd', .name = "directory",	.has_arg = no_argument }, */
	{ .val = 'd',	.name = "mindepth",	.has_arg = required_argument },
	{ .val = 'D',	.name = "maxdepth",	.has_arg = required_argument },
	{ .val = 'E',	.name = "comp-end",	.has_arg = required_argument },
	{ .val = 'E',	.name = "component-end",
						.has_arg = required_argument },
/* find	{ .val = 'F',	.name = "fid",		.has_arg = no_argument }, */
	{ .val = LFS_LAYOUT_FOREIGN_OPT,
			.name = "foreign",	.has_arg = optional_argument},
	{ .val = 'g',	.name = "gid",		.has_arg = required_argument },
	{ .val = 'G',	.name = "group",	.has_arg = required_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'H',	.name = "mdt-hash",	.has_arg = required_argument },
	{ .val = 'i',	.name = "stripe-index",	.has_arg = required_argument },
	{ .val = 'i',	.name = "stripe_index",	.has_arg = required_argument },
/* getstripe { .val = 'I', .name = "comp-id",	.has_arg = required_argument }*/
	{ .val = 'k',	.name = "skip",		.has_arg = required_argument },
	{ .val = 'l',	.name = "lazy",		.has_arg = no_argument },
	{ .val = 'L',	.name = "layout",	.has_arg = required_argument },
	{ .val = LFS_LINKS_OPT,
			.name = "links",	.has_arg = required_argument },
	{ .val = LFS_PRINTF_LS,
			.name = "ls",		.has_arg = no_argument },
	{ .val = 'm',	.name = "mdt",		.has_arg = required_argument },
	{ .val = 'm',	.name = "mdt-index",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mdt_index",	.has_arg = required_argument },
	{ .val = 'M',	.name = "mtime",	.has_arg = required_argument },
	{ .val = 'n',	.name = "name",		.has_arg = required_argument },
	{ .val = 'N',	.name = "mirror-count",	.has_arg = required_argument },
/* find	{ .val = 'o'	.name = "or", .has_arg = no_argument }, like find(1) */
	{ .val = 'O',	.name = "obd",		.has_arg = required_argument },
	{ .val = 'O',	.name = "ost",		.has_arg = required_argument },
	{ .val = LFS_FIND_PERM,
			.name = "perm",		.has_arg = required_argument },
	/* no short option for pool yet, can be 'p' after 2.18 */
	{ .val = LFS_POOL_OPT,
			.name = "pool",		.has_arg = required_argument },
	{ .val = '0',	.name = "print0",	.has_arg = no_argument },
	{ .val = LFS_THREAD_OPT,
			.name = "threads",	.has_arg = required_argument },
	{ .val = 'P',	.name = "print",	.has_arg = no_argument },
	{ .val = LFS_PRINTF_OPT,
			.name = "printf",       .has_arg = required_argument },
	{ .val = LFS_PROJID_OPT,
			.name = "projid",	.has_arg = required_argument },
/* getstripe { .val = 'q', .name = "quiet",	.has_arg = no_argument }, */
/* getstripe { .val = 'r', .name = "recursive",	.has_arg = no_argument }, */
/* getstripe { .val = 'R', .name = "raw",	.has_arg = no_argument }, */
	{ .val = 's',	.name = "size",		.has_arg = required_argument },
	{ .val = 'S',	.name = "stripe-size",	.has_arg = required_argument },
	{ .val = 'S',	.name = "stripe_size",	.has_arg = required_argument },
	{ .val = 't',	.name = "type",		.has_arg = required_argument },
	{ .val = 'T',	.name = "mdt-count",	.has_arg = required_argument },
	{ .val = 'u',	.name = "uid",		.has_arg = required_argument },
	{ .val = 'U',	.name = "user",		.has_arg = required_argument },
/* getstripe { .val = 'v', .name = "verbose",	.has_arg = no_argument }, */
/*migrate{.val = 'W', .name = "bandwidth-limit",.has_arg = required_argument},*/
	{ .val = LFS_XATTRS_MATCH_OPT,
			.name = "xattr",	.has_arg = required_argument },
	{ .val = 'z',	.name = "extension-size",
						.has_arg = required_argument },
	{ .val = 'z',	.name = "ext-size",	.has_arg = required_argument },
	{ .name = NULL } };
	/*
	 * optind and opterr are the caller's, and this reads both.
	 * prev_optind seeds @pathstartp, so it has to be the index of the
	 * first argument to look at -- 1, as getopt() and
	 * cfs_parser_execarg() leave optind.
	 *
	 * 0 is the exception, and a caller in tree leaves it there: the
	 * interactive shell's execute_line() sets optind = 0 before calling
	 * the command, which getopt() reads as "reinitialise" and answers by
	 * scanning from argv[1] anyway.  Seeding from that 0 made pathstart
	 * 0, so `lfs> find /mnt/lustre -type f` searched argv[0] -- "find"
	 * -- before the path.  1 is where getopt() will start either way.
	 *
	 * opterr has to be 0, as lfs.c's main() sets it,
	 * or getopt() prints its own diagnostic on top of the one the switch
	 * default below prints.
	 */
	int prev_optind = optind ? optind : 1;
	int optidx = 0;
	int pathstart = -1;
	int pathend = -1;
	int neg_opt = 0;
	time_t *xtime;
	int *xsign;
	int isoption;
	char *endptr;

	time(&t);

	/* all three are out-parameters, so none of them reads back whatever
	 * the caller happened to leave there when the parse stops early
	 */
	*pathstartp = -1;
	*pathendp = -1;
	*stopped = false;

	/* when getopt_long_only() hits '!' it returns 1, puts "!" in optarg */
	while ((c = getopt_long_only(argc, argv,
		"-0A:b:B:c:C:d:D:E:g:G:hH:i:k:lL:m:M:n:N:O:Ppqrs:S:t:T:u:U:z:",
		long_opts, &optidx)) >= 0) {
		xtime = NULL;
		xsign = NULL;
		if (neg_opt)
			--neg_opt;
		/* '!' is part of option */
		/*
		 * when getopt_long_only() finds a string which is not
		 * an option nor a known option argument it returns 1
		 * in that case if we already have found pathstart and pathend
		 * (i.e. we have the list of pathnames),
		 * the only supported value is "!"
		 */
		isoption = (c != 1) || (strcmp(optarg, "!") == 0);
		if (!isoption && pathend != -1) {
			fprintf(stderr,
				"err: %s: filename|dirname must either precede options or follow options\n",
				argv[0]);
			ret = CMD_HELP;
			goto out;
		}
		if (!isoption && pathstart == -1)
			pathstart = prev_optind;
		if (isoption && pathstart != -1 && pathend == -1)
			pathend = prev_optind;

		prev_optind = optind;

		switch (c) {
		case 0:
			/* Long options. */
			break;
		case 1:
			/*
			 * unknown; opt is "!" or path component,
			 * checking done above.
			 */
			if (strcmp(optarg, "!") == 0)
				neg_opt = 2;
			break;
		case 'A':
			xtime = &param->fp_atime;
			xsign = &param->fp_asign;
			param->fp_exclude_atime = !!neg_opt;
			/* no break, this falls through to 'B' for btime */
			fallthrough;
		case 'B':
			if (c == 'B') {
				xtime = &param->fp_btime;
				xsign = &param->fp_bsign;
				param->fp_exclude_btime = !!neg_opt;
			}
			/* no break, this falls through to 'C' for ctime */
			fallthrough;
		case 'C':
			if (c == 'C') {
				xtime = &param->fp_ctime;
				xsign = &param->fp_csign;
				param->fp_exclude_ctime = !!neg_opt;
			}
			/* no break, this falls through to 'M' for mtime */
			fallthrough;
		case 'M':
			if (c == 'M') {
				xtime = &param->fp_mtime;
				xsign = &param->fp_msign;
				param->fp_exclude_mtime = !!neg_opt;
			}
			rc = set_time(param, &t, xtime, xsign, optarg);
			if (rc == INT_MAX) {
				ret = -1;
				goto out;
			}
			*xsign = rc;
			break;
		case LFS_ATTRS_OPT:
			ret = name2attrs(optarg, &param->fp_attrs,
					 &param->fp_neg_attrs);
			if (ret)
				goto out;
			param->fp_exclude_attrs = !!neg_opt;
			break;
		case 'b':
			if (optarg[0] == '+') {
				param->fp_blocks_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_blocks_sign =  1;
				optarg++;
			}

			param->fp_blocks_units = 512;
			ret = llapi_parse_size(optarg, &param->fp_blocks,
					       &param->fp_blocks_units, 0);
			if (ret) {
				fprintf(stderr, "error: bad blocks '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_blocks = 1;
			param->fp_exclude_blocks = !!neg_opt;
			break;
		case LFS_COMP_COUNT_OPT:
			if (optarg[0] == '+') {
				param->fp_comp_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_comp_count_sign =  1;
				optarg++;
			}

			errno = 0;
			param->fp_comp_count = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' ||
			    param->fp_comp_count > UINT32_MAX) {
				fprintf(stderr,
					"error: bad component count '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_comp_count = 1;
			param->fp_exclude_comp_count = !!neg_opt;
			break;
		case LFS_COMP_FLAGS_OPT:
			rc = comp_str2flags(optarg, &param->fp_comp_flags,
					    &param->fp_comp_neg_flags);
			if (rc) {
				fprintf(stderr,
					"error: bad component flags '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_comp_flags = 1;
			if (neg_opt) {
				__u32 flags = param->fp_comp_neg_flags;

				param->fp_comp_neg_flags = param->fp_comp_flags;
				param->fp_comp_flags = flags;
			}
			break;
		case LFS_COMP_START_OPT:
			if (optarg[0] == '+') {
				param->fp_comp_start_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_comp_start_sign =  1;
				optarg++;
			}

			rc = llapi_parse_size(optarg, &param->fp_comp_start,
					      &param->fp_comp_start_units, 0);
			if (rc) {
				fprintf(stderr,
					"error: bad component start '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_comp_start = 1;
			param->fp_exclude_comp_start = !!neg_opt;
			break;
		case LFS_MIRROR_STATE_OPT:
			rc = mirror_str2state(optarg, &param->fp_mirror_state,
					      &param->fp_mirror_neg_state);
			if (rc) {
				fprintf(stderr,
					"error: bad mirrored file state '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_mirror_state = 1;
			if (neg_opt) {
				__u16 state = param->fp_mirror_neg_state;

				param->fp_mirror_neg_state =
					param->fp_mirror_state;
				param->fp_mirror_state = state;
			}
			break;
		case 'c':
			if (optarg[0] == '+') {
				param->fp_stripe_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_stripe_count_sign =  1;
				optarg++;
			}

			errno = 0;
			param->fp_stripe_count = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' ||
			    param->fp_stripe_count > LOV_MAX_STRIPE_COUNT) {
				fprintf(stderr,
					"error: bad stripe_count '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			param->fp_check_stripe_count = 1;
			param->fp_exclude_stripe_count = !!neg_opt;
			break;
		case 'd':
			errno = 0;
			param->fp_min_depth = strtoul(optarg, 0, 0);
			if (errno != 0 || param->fp_min_depth > PATH_MAX / 2) {
				fprintf(stderr,
					"error: bad mindepth '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			break;
		case 'D':
			errno = 0;
			param->fp_max_depth = strtol(optarg, 0, 0);
			if (errno != 0 || param->fp_max_depth < 0) {
				fprintf(stderr,
					"error: bad maxdepth '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			break;
		case 'E':
			if (optarg[0] == '+') {
				param->fp_comp_end_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_comp_end_sign =  1;
				optarg++;
			}

			if (arg_is_eof(optarg)) {
				param->fp_comp_end = LUSTRE_EOF;
				param->fp_comp_end_units = 1;
				rc = 0;
			} else {
				rc = llapi_parse_size(optarg,
						&param->fp_comp_end,
						&param->fp_comp_end_units, 0);
				/* assume units of KB if too small */
				if (param->fp_comp_end < 4096)
					param->fp_comp_end *= 1024;
			}
			if (rc) {
				fprintf(stderr,
					"error: bad component end '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_comp_end = 1;
			param->fp_exclude_comp_end = !!neg_opt;
			break;
		case LFS_LAYOUT_FOREIGN_OPT: {
			/* all types by default */
			uint32_t type = LU_FOREIGN_TYPE_UNKNOWN;

			if (optarg) {
				/* check pure numeric */
				type = strtoul(optarg, &endptr, 0);
				if (*endptr) {
					/* check name */
					type = check_foreign_type_name(optarg);
					if (type == LU_FOREIGN_TYPE_UNKNOWN) {
						fprintf(stderr,
							"%s %s: unknown foreign type '%s'\n",
							progname, argv[0],
							optarg);
						ret = CMD_HELP;
						goto out;
					}
				} else if (type >= UINT32_MAX) {
					fprintf(stderr,
						"%s %s: invalid foreign type '%s'\n",
						progname, argv[0], optarg);
					ret = CMD_HELP;
					goto out;
				}
			}
			param->fp_foreign_type = type;
			param->fp_check_foreign = 1;
			param->fp_exclude_foreign = !!neg_opt;
			break;
		}
		case LFS_NEWERXY_OPT: {
			char x = 'm';
			char y = 'm';
			int xidx;
			int negidx;
			time_t *newery;
			time_t ref = time(NULL);

			/* no need to check bad options, they won't get here */
			if (strlen(long_opts[optidx].name) == 7) {
				x = long_opts[optidx].name[5];
				y = long_opts[optidx].name[6];
			}

			if (y == 't') {
				static const char *const fmts[] = {
					"%Y-%m-%d %H:%M:%S",
					"%Y-%m-%d %H:%M",
					"%Y-%m-%d",
					"%H:%M:%S", /* sometime today */
					"%H:%M",
					"@%s",
					"%s",
					NULL };
				struct tm tm;
				bool found = false;
				int i;

				for (i = 0; fmts[i] != NULL; i++) {
					char *ptr;

					/* Init for times relative to today */
					if (strncmp(fmts[i], "%H", 2) == 0) {
						localtime_r(&ref, &tm);
					} else {
						memset(&tm, 0, sizeof(tm));
						tm.tm_isdst = -1;
					}
					ptr = strptime(optarg, fmts[i], &tm);
					/* Skip spaces */
					while (ptr && isspace(*ptr))
						ptr++;
					if (ptr == optarg + strlen(optarg)) {
						found = true;
						break;
					}
				}

				if (!found) {
					fprintf(stderr,
						"%s: invalid time '%s'\n",
						progname, optarg);
					fprintf(stderr,
						"supported formats are:\n  ");
					for (i = 0; fmts[i] != NULL; i++)
						fprintf(stderr, "'%s', ",
							fmts[i]);
					fprintf(stderr, "\n");
					ret = -EINVAL;
					goto out;
				}

				ref = mktime(&tm);
			} else if (y == 'b' || y == 'B') {
				lstatx_t stx;

				rc = llapi_get_lum_file(optarg, NULL, &stx,
							NULL, 0);
				if (rc || !(stx.stx_mask & STATX_BTIME)) {
					if (!(stx.stx_mask & STATX_BTIME))
						ret = -EOPNOTSUPP;
					else
						ret = -errno;
					fprintf(stderr,
						"%s: get btime failed '%s': %s\n",
						progname, optarg,
						strerror(-ret));
					goto out;
				}

				ref = stx.stx_btime.tv_sec;
			} else {
				struct stat statbuf;

				if (stat(optarg, &statbuf) < 0) {
					fprintf(stderr,
						"%s: cannot stat file '%s': %s\n",
						progname, optarg,
						strerror(errno));
					ret = -errno;
					goto out;
				}

				switch (y) {
				case 'a':
					ref = statbuf.st_atime;
					break;
				case 'm':
					ref = statbuf.st_mtime;
					break;
				case 'c':
					ref = statbuf.st_ctime;
					break;
				default:
					fprintf(stderr,
						"%s: invalid Y argument: '%c'\n",
						progname, x);
					ret = -EINVAL;
					goto out;
				}
			}

			switch (x) {
			case 'a':
				xidx = NEWERXY_ATIME;
				break;
			case 'm':
				xidx = NEWERXY_MTIME;
				break;
			case 'c':
				xidx = NEWERXY_CTIME;
				break;
			case 'b':
			case 'B':
				xidx = NEWERXY_BTIME;
				break;
			default:
				fprintf(stderr,
					"%s: invalid X argument: '%c'\n",
					progname, x);
				ret = -EINVAL;
				goto out;
			}

			negidx = !!neg_opt;
			newery = &param->fp_newery[xidx][negidx];

			if (*newery == 0) {
				*newery = ref;
			} else {
				if (negidx)
					*newery = *newery > ref ? ref : *newery;
				else
					*newery = *newery > ref ? *newery : ref;
			}
			param->fp_newerxy = 1;
			break;
		}
		case 'g':
		case 'G':
			rc = name2gid(&param->fp_gid, optarg);
			if (rc && str2quotaid(&param->fp_gid, optarg)) {
				fprintf(stderr, "invalid group/GID '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			param->fp_exclude_gid = !!neg_opt;
			param->fp_check_gid = 1;
			break;
		case 'H':
			rc = mdthash_input(optarg, &param->fp_hash_inflags,
					   &param->fp_hash_exflags,
					   &param->fp_hash_type);
			if (rc) {
				ret = -1;
				goto out;
			}
			if (param->fp_hash_inflags || param->fp_hash_exflags)
				param->fp_check_hash_flag = 1;
			param->fp_exclude_hash_type = !!neg_opt;
			break;
		case 'k': {
			unsigned long pct = strtoul(optarg, &endptr, 10);

			if (pct < 0 || pct >= 100 ||
			    (*endptr != '\0' && *endptr != '%')) {
				ret = -1;
				fprintf(stderr,
					"error: invalid skip percentage '%s'\n",
					optarg);
				goto out;
			}
			param->fp_skip_percent = pct;
			break;
		}
		case 'l':
			param->fp_lazy = 1;
			break;
		case 'L':
			ret = llapi_lov_string_pattern(optarg, &param->fp_layout);
			if (ret)
				goto out;
			param->fp_exclude_layout = !!neg_opt;
			param->fp_check_layout = 1;
			break;
		case LFS_LINKS_OPT:
			if (optarg[0] == '+') {
				param->fp_nlink_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_nlink_sign =  1;
				optarg++;
			}
			errno = 0;
			param->fp_nlink = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' || !param->fp_nlink) {
				fprintf(stderr, "error: bad link count '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			param->fp_exclude_nlink = !!neg_opt;
			break;
		case 'u':
		case 'U':
			rc = name2uid(&param->fp_uid, optarg);
			if (rc && str2quotaid(&param->fp_uid, optarg)) {
				fprintf(stderr, "invalid username/UID '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			param->fp_exclude_uid = !!neg_opt;
			param->fp_check_uid = 1;
			break;
		case 'n':
			param->fp_pattern = (char *)optarg;
			param->fp_exclude_pattern = !!neg_opt;
			break;
		case 'N':
			if (optarg[0] == '+') {
				param->fp_mirror_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_mirror_count_sign =  1;
				optarg++;
			}

			errno = 0;
			param->fp_mirror_count = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' ||
			    param->fp_mirror_count > LUSTRE_MIRROR_COUNT_MAX) {
				fprintf(stderr,
					"error: bad mirror count '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_mirror_count = 1;
			param->fp_exclude_mirror_count = !!neg_opt;
			break;
		case 'm':
		case 'i':
		case 'O': {
			int len, rc2;
			int *p_num, *p_alloc;
			struct obd_uuid **pp_uuid, *tmp;
			const char *p1 = optarg, *p2;
			char buf[UUID_MAX];
			const char *pattern = "^([0-9]+)-([0-9]+)$";
			regex_t reg;
			regmatch_t pmatch[3];

			if (c == 'm') {
				param->fp_exclude_mdt = !!neg_opt;
				p_num = &param->fp_num_mdts;
				p_alloc = &param->fp_num_alloc_mdts;
				pp_uuid = &param->fp_mdt_uuid;
			} else {
				param->fp_exclude_obd = !!neg_opt;
				p_num = &param->fp_num_obds;
				p_alloc = &param->fp_num_alloc_obds;
				pp_uuid = &param->fp_obd_uuid;
			}
			regcomp(&reg, pattern, REG_EXTENDED);

			while (p1 && *p1 != '\0') {
				/* grab one uuid/idx/idx_range */
				p2 = strchr(p1, ',');
				if (p2 == NULL)
					p2 = p1 + strlen(p1);

				len = p2 - p1;
				if (len >= sizeof(buf)) {
					regfree(&reg);
					ret = -E2BIG;
					goto out;
				}
				strncpy(buf, p1, len);
				buf[len] = '\0';

				if (*p2 == '\0')
					p1 = p2;
				else
					p1 = p2 + 1;

				/* extend array if necessary */
				if (*p_num >= *p_alloc) {
					tmp = realloc(*pp_uuid,
						      (*p_alloc + 16) *
						      sizeof((*pp_uuid)[0]));
					if (tmp == NULL) {
						regfree(&reg);
						ret = -ENOMEM;
						goto out;
					}
					*pp_uuid = tmp;
					*p_alloc += 16;
				}

				/* check pattern */
				rc2 = regexec(&reg, buf, 3, pmatch, 0);
				if (rc2 == 0) {
					/* idx range such as 0-3 */
					int start, end;

					start = atoi(&buf[pmatch[1].rm_so]);
					end = atoi(&buf[pmatch[2].rm_so]);
					for ( ; start <= end; start++) {
						if (*p_num >= *p_alloc) {
							tmp = realloc(*pp_uuid,
								      (*p_alloc + 16) *
								      sizeof((*pp_uuid)[0]));
							if (tmp == NULL) {
								regfree(&reg);
								ret = -ENOMEM;
								goto out;
							}
							*pp_uuid = tmp;
							*p_alloc += 16;
						}
						sprintf(buf, "%d", start);
						strcpy((*pp_uuid)[(*p_num)++].uuid, buf);
					}
				} else if (rc2 == REG_NOMATCH) {
					/* single idx or uuid */
					strcpy((*pp_uuid)[(*p_num)++].uuid, buf);
				} else {
					regfree(&reg);
					ret = -errno;
					goto out;
				}
			}

			regfree(&reg);
			break;
		}
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 18, 53, 0)
		case 'p':
#endif
		case LFS_POOL_OPT:
			if (strlen(optarg) > LOV_MAXPOOLNAME) {
				fprintf(stderr,
					"Pool name %s is too long (max %d)\n",
					optarg, LOV_MAXPOOLNAME);
				ret = -1;
				goto out;
			}
			/*
			 * We do check for empty pool because empty pool
			 * is used to find V1 LOV attributes
			 */
			snprintf(param->fp_poolname, sizeof(param->fp_poolname),
				 "%s", optarg);
			param->fp_exclude_pool = !!neg_opt;
			param->fp_check_pool = 1;
			break;
		case '0':
			param->fp_zero_end = 1;
			break;
		case LFS_THREAD_OPT:
			param->fp_thread_count = strtol(optarg, &endptr, 0);
			if (*endptr != '\0' || param->fp_thread_count < 1) {
				fprintf(stderr,
					"error: bad thread count '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			break;
		case 'P': /* we always print, this option is a no-op */
			break;
		case LFS_PRINTF_OPT:
			param->fp_format_printf_str = strdup(optarg);
			break;
		case LFS_PRINTF_LS:
			param->fp_format_printf_str =
				strdup("%18i %10k %M %4n %-8u %-8g %13s %t %p\n");
			break;
		case LFS_PROJID_OPT:
			rc = name2projid(&param->fp_projid, optarg);
			if (rc && str2quotaid(&param->fp_projid, optarg)) {
				fprintf(stderr, "invalid project id: '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			param->fp_exclude_projid = !!neg_opt;
			param->fp_check_projid = 1;
			break;
		case 's':
			if (optarg[0] == '+') {
				param->fp_size_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_size_sign =  1;
				optarg++;
			}

			param->fp_size_units = 512;
			ret = llapi_parse_size(optarg, &param->fp_size,
					       &param->fp_size_units, 0);
			if (ret) {
				fprintf(stderr, "error: bad file size '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_size = 1;
			param->fp_exclude_size = !!neg_opt;
			break;
		case 'S':
			if (optarg[0] == '+') {
				param->fp_stripe_size_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_stripe_size_sign =  1;
				optarg++;
			}

			ret = llapi_parse_size(optarg, &param->fp_stripe_size,
					       &param->fp_stripe_size_units, 0);
			/* assume units of KB if too small to be valid */
			if (param->fp_stripe_size < 4096)
				param->fp_stripe_size *= 1024;
			if (ret) {
				fprintf(stderr, "error: bad stripe_size '%s'\n",
					optarg);
				goto out;
			}
			param->fp_check_stripe_size = 1;
			param->fp_exclude_stripe_size = !!neg_opt;
			break;
		case 't':
			param->fp_exclude_type = !!neg_opt;
			switch (optarg[0]) {
			case 'b':
				param->fp_type = S_IFBLK;
				break;
			case 'c':
				param->fp_type = S_IFCHR;
				break;
			case 'd':
				param->fp_type = S_IFDIR;
				break;
			case 'f':
				param->fp_type = S_IFREG;
				break;
			case 'l':
				param->fp_type = S_IFLNK;
				break;
			case 'p':
				param->fp_type = S_IFIFO;
				break;
			case 's':
				param->fp_type = S_IFSOCK;
				break;
			default:
				fprintf(stderr, "%s: bad type '%s'\n",
					progname, optarg);
				ret = CMD_HELP;
				goto out;
			}
			break;
		case LFS_FIND_PERM:
			param->fp_exclude_perm = !!neg_opt;
			param->fp_perm_sign = LFS_FIND_PERM_EXACT;
			if (*optarg == '/') {
				param->fp_perm_sign = LFS_FIND_PERM_ANY;
				optarg++;
			} else if (*optarg == '-') {
				param->fp_perm_sign = LFS_FIND_PERM_ALL;
				optarg++;
			}

			if (str2mode_t(optarg, &param->fp_perm)) {
				fprintf(stderr, "error: invalid mode '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			break;
		case 'T':
			if (optarg[0] == '+') {
				param->fp_mdt_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_mdt_count_sign =  1;
				optarg++;
			}

			errno = 0;
			param->fp_mdt_count = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' ||
			    param->fp_mdt_count >= UINT32_MAX) {
				fprintf(stderr, "error: bad mdt_count '%s'\n",
					optarg);
				ret = -1;
				goto out;
			}
			param->fp_check_mdt_count = 1;
			param->fp_exclude_mdt_count = !!neg_opt;
			break;
		case LFS_XATTRS_MATCH_OPT:
			ret = compile_xattr_match_regex(optarg, neg_opt,
							param);
			if (ret)
				goto out;
			break;
		case 'z':
			if (optarg[0] == '+') {
				param->fp_ext_size_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_ext_size_sign =  1;
				optarg++;
			}

			ret = llapi_parse_size(optarg, &param->fp_ext_size,
					       &param->fp_ext_size_units, 0);
			if (ret) {
				fprintf(stderr, "error: bad ext-size '%s'\n",
					optarg);
				goto out;
			}
			param->fp_ext_size /= SEL_UNIT_SIZE;
			param->fp_ext_size_units /= SEL_UNIT_SIZE;
			param->fp_check_ext_size = 1;
			param->fp_exclude_ext_size = !!neg_opt;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
		case 'h':
			ret = CMD_HELP;
			goto out;
		}
	}
	if (!param->fp_verbose)
		param->fp_verbose = VERBOSE_DEFAULT;

	*pathstartp = pathstart;
	*pathendp = pathend;

	return ret;
out:
	/*
	 * Several jumps here give up without setting ret, so the return value
	 * alone cannot say whether the parse stopped: a bad --comp-flags has
	 * always printed its error and exited 0.  Preserved, not fixed --
	 * fixing it changes what the command returns.
	 */
	*stopped = true;

	return ret;
}

void lfs_find_parse_init(struct find_param *param)
{
	*param = (struct find_param){
		.fp_max_depth	= -1,
		.fp_min_depth	= 0,
		.fp_quiet	= 1,
		.fp_time_margin	= FP_DEFAULT_TIME_MARGIN,
	};
}

void lfs_find_parse_fini(struct find_param *param)
{
	if (param->fp_obd_uuid && param->fp_num_alloc_obds) {
		free(param->fp_obd_uuid);
		param->fp_obd_uuid = NULL;
	}

	if (param->fp_mdt_uuid && param->fp_num_alloc_mdts) {
		free(param->fp_mdt_uuid);
		param->fp_mdt_uuid = NULL;
	}

	if (param->fp_format_printf_str) {
		free(param->fp_format_printf_str);
		param->fp_format_printf_str = NULL;
	}

	if (param->fp_xattr_match_info) {
		xattr_match_info_free(param->fp_xattr_match_info);
		free(param->fp_xattr_match_info);
		param->fp_xattr_match_info = NULL;
	}
}
