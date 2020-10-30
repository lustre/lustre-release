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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/mkfs_lustre.c
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
*/

/* This source file is compiled into both mkfs.lustre and tunefs.lustre */

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <mntent.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>

#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <ctype.h>
#include <linux/lnet/nidstr.h>
#include <linux/lnet/lnetctl.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_ver.h>

#include "mount_utils.h"

char *progname;
int verbose = 1;
int version;
static int print_only;

#ifdef HAVE_LDISKFS_OSD
#define FSLIST_LDISKFS "ldiskfs"
#define HAVE_FSLIST
#else
 #define FSLIST_LDISKFS ""
#endif /* HAVE_LDISKFS_OSD */
#ifdef HAVE_ZFS_OSD
 #ifdef HAVE_FSLIST
   #define FSLIST_ZFS "|zfs"
 #else
  #define FSLIST_ZFS "zfs"
  #define HAVE_FSLIST
 #endif
#else
 #define FSLIST_ZFS ""
#endif /* HAVE_ZFS_OSD */

#ifndef HAVE_FSLIST
 #error "no backing OSD types (ldiskfs or ZFS) are configured"
#endif

#define FSLIST FSLIST_LDISKFS FSLIST_ZFS

void usage(FILE *out)
{
	fprintf(out, "usage: %s <target type> [--backfstype="FSLIST"] "
		"--fsname=<filesystem name>\n"
		"\t--index=<target index> [options] <device>\n", progname);
#ifdef HAVE_ZFS_OSD
	fprintf(out, "usage: %s <target type> --backfstype=zfs "
		"--fsname=<filesystem name> [options]\n"
		"\t<pool name>/<dataset name>\n"
		"\t[[<vdev type>] <device> [<device> ...] [vdev type>] ...]\n",
		progname);
#endif
	fprintf(out,
		"\t<device>:block device or file (e.g /dev/sda or /tmp/ost1)\n"
#ifdef HAVE_ZFS_OSD
		"\t<pool name>: name of ZFS pool where target is created "
			"(e.g. tank)\n"
		"\t<dataset name>: name of new dataset, must be unique within "
			"pool (e.g. ost1)\n"
		"\t<vdev type>: type of vdev (mirror, raidz, raidz2, spare, "
			"cache, log)\n"
#endif
		"\n"
		"\ttarget types:\n"
		"\t\t--mgs: configuration management service\n"
		"\t\t--nomgs: turn off MGS service on this MDT\n"
#ifndef TUNEFS
		"\t\t--mdt: metadata storage, mutually exclusive with ost\n"
		"\t\t--ost: object storage, mutually exclusive with mdt, mgs\n"
#endif
		"\toptions (in order of popularity):\n"
		"\t\t--index=#N: numerical target index (0..N)\n"
		"\t\t\trequired for all targets other than the MGS,\n"
		"\t\t\ttarget index may either be a decimal number or\n"
		"\t\t\thexadecimal number starting with '0x'\n"
		"\t\t--fsname=<8_char_filesystem_name>: fs targets belong to\n"
		"\t\t\trequired for all targets other than MGS\n"
		"\t\t--mgsnode=<nid>[,<...>]: NID(s) of remote MGS\n"
		"\t\t\trequired for all targets other than MGS\n"
		"\t\t--mountfsoptions=<opts>: permanent Lustre mount options\n"
		"\t\t--backfs-mount-opts=<opts>: backing fs mount options\n"
		"\t\t--failnode=<nid>[,<...>]: NID(s) of backup failover node\n"
		"\t\t\tmutually exclusive with --servicenode\n"
		"\t\t--servicenode=<nid>[,<...>]: NID(s) of service partners\n"
		"\t\t\ttreat nodes as equal service node, mutually exclusive "
			"with --failnode\n"
		"\t\t--param <key>=<value>: set a permanent parameter\n"
		"\t\t\te.g. --param sys.timeout=40\n"
		"\t\t\t     --param lov.stripesize=2M\n"
		"\t\t--network=<net>[,<...>]: restrict OST/MDT to network(s)\n"
#ifndef TUNEFS
		"\t\t--backfstype=<fstype>: backing fs type (ldiskfs, zfs)\n"
		"\t\t--device-size=#N(KB): device size for loop devices\n"
		"\t\t--mkfsoptions=<opts>: format options\n"
		"\t\t--reformat: overwrite an existing disk\n"
		"\t\t--replace: replace an old target with the same index\n"
		"\t\t--stripe-count-hint=#N: for optimizing MDT inode size\n"
#else
		"\t\t--erase-param <key>: erase all instances of a parameter\n"
		"\t\t--erase-params: erase all old parameter settings\n"
		"\t\t--writeconf: erase all config logs for this fs.\n"
		"\t\t--nolocallogs: use logs from MGS, not local ones.\n"
		"\t\t--quota: enable space accounting on old 2.x device.\n"
		"\t\t--rename: rename the filesystem name\n"
#endif
		"\t\t--comment=<user comment>: arbitrary string (%d bytes)\n"
		"\t\t--dryrun: report what we would do; don't write to disk\n"
		"\t\t--verbose: e.g. show mkfs progress\n"
		"\t\t--force-nohostid: Ignore hostid requirement for ZFS "
			"import\n"
		"\t\t-V|--version: output build version of the utility and\n"
		"\t\t\texit\n"
		"\t\t--quiet\n",
		(int)sizeof(((struct lustre_disk_data *)0)->ldd_userdata));
}

/* ==================== Lustre config functions =============*/

void print_ldd(char *str, struct mkfs_opts *mop)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;

	printf("\n   %s:\n", str);
	printf("Target:     %s\n", ldd->ldd_svname);
	if (ldd->ldd_svindex == INDEX_UNASSIGNED)
		printf("Index:      unassigned\n");
	else
		printf("Index:      %d\n", ldd->ldd_svindex);
	if (ldd->ldd_uuid[0])
		printf("UUID:       %s\n", (char *)ldd->ldd_uuid);
	printf("Lustre FS:  %s\n", ldd->ldd_fsname);
	printf("Mount type: %s\n", MT_STR(ldd));
	printf("Flags:      %#x\n", ldd->ldd_flags);
	printf("              (%s%s%s%s%s%s%s%s%s)\n",
	       IS_MDT(ldd) ? "MDT " : "",
	       IS_OST(ldd) ? "OST " : "",
	       IS_MGS(ldd) ? "MGS " : "",
	       ldd->ldd_flags & LDD_F_NEED_INDEX ? "needs_index " : "",
	       ldd->ldd_flags & LDD_F_VIRGIN     ? "first_time " : "",
	       ldd->ldd_flags & LDD_F_UPDATE     ? "update " : "",
	       ldd->ldd_flags & LDD_F_WRITECONF  ? "writeconf " : "",
	       ldd->ldd_flags & LDD_F_NO_PRIMNODE ? "no_primnode " : "",
	       ldd->ldd_flags & LDD_F_NO_LOCAL_LOGS ? "nolocallogs " : "");
	printf("Persistent mount opts: %s\n", ldd->ldd_mount_opts);
	osd_print_ldd_params(mop);
	if (ldd->ldd_userdata[0])
		printf("Comment: %s\n", ldd->ldd_userdata);
	printf("\n");
}

void set_defaults(struct mkfs_opts *mop)
{
	mop->mo_ldd.ldd_magic = LDD_MAGIC;
	mop->mo_ldd.ldd_config_ver = 1;
	mop->mo_ldd.ldd_flags = LDD_F_NEED_INDEX | LDD_F_UPDATE | LDD_F_VIRGIN;
#ifdef HAVE_LDISKFS_OSD
	mop->mo_ldd.ldd_mount_type = LDD_MT_LDISKFS;
#else
	mop->mo_ldd.ldd_mount_type = LDD_MT_ZFS;
#endif
	mop->mo_ldd.ldd_svindex = INDEX_UNASSIGNED;
	mop->mo_mgs_failnodes = 0;
	mop->mo_stripe_count = 1;
	mop->mo_pool_vdevs = NULL;
}

/* Make the mdt/ost server obd name based on the filesystem name */
static bool server_make_name(__u32 flags, __u16 index, const char *fs,
			     char *name_buf, size_t name_buf_size)
{
	bool invalid_flag = false;

	if (flags & (LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_OST)) {
		if (!(flags & LDD_F_SV_ALL))
			snprintf(name_buf, name_buf_size, "%.8s%c%s%04x", fs,
				(flags & LDD_F_VIRGIN) ? ':' :
				((flags & LDD_F_WRITECONF) ? '=' :
				((flags & LDD_F_NO_LOCAL_LOGS) ? '+' : '-')),
				(flags & LDD_F_SV_TYPE_MDT) ? "MDT" : "OST",
				index);
	} else if (flags & LDD_F_SV_TYPE_MGS) {
		snprintf(name_buf, name_buf_size, "MGS");
	} else {
		fprintf(stderr, "unknown server type %#x\n", flags);
		invalid_flag = true;
	}
	return invalid_flag;
}

static inline void badopt(const char *opt, char *type)
{
	fprintf(stderr, "%s: '--%s' only valid for %s\n",
		progname, opt, type);
	usage(stderr);
}

#ifdef TUNEFS
/**
 * Removes all existing instances of the parameter passed in \a param,
 * which are in the form of "key=<value>", from the buffer at \a buf.
 *
 * The parameter can be either in the form of "key" when passed by option
 * "--erase-param", or in the form of "key=<value>" when passed by option
 * "--param".
 *
 * \param buf	  the buffer holding on-disk server parameters.
 * \param param	  the parameter whose instances are to be removed from \a buf.
 * \param withval true means the parameter is in the form of "key=<value>"
 *		  false means the parameter is in the form of "key"
 *
 * \retval 0	  success, parameter was erased,
 * \retval 1	  success, parameter was not found, don't need to do erase_ldd,
 * \retval EINVAL failure, invalid input parameter.
 */
static int erase_param(const char *const buf, const char *const param,
		       bool withval)
{
	char	search[PARAM_MAX + 8] = "";
	char	*buffer = (char *)buf;
	bool	found = false;

	if (strlen(param) > PARAM_MAX) {
		fprintf(stderr, "%s: param to erase is too long-\n%s\n",
			progname, param);
		return EINVAL;
	}

	/* add_param() writes a space as the first character in ldd_params */
	search[0] = ' ';

	/* "key" or "key=<value>" */
	if (withval) {
		char *keyend;

		keyend = strchr(param, '=');
		if (!keyend)
			return EINVAL;
		strncpy(&search[1], param, keyend - param + 1);
	} else {
		snprintf(search + 1, sizeof(search) - 1, "%s=", param);
	}

	while (1) {
		char	*space;

		buffer = strstr(buffer, search);
		if (!buffer)
			return found == true ? 0 : 1;
		found = true;
		space = strchr(buffer + 1, ' ');
		if (space) {
			memmove(buffer, space, strlen(space) + 1);
		} else {
			*buffer = '\0';
			return 0;
		}
	}
}
#endif

/* from mount_lustre */
/* Get rid of symbolic hostnames for tcp, since kernel can't do lookups */
#define MAXNIDSTR 1024
static char *convert_hostnames(char *s1)
{
	char *converted, *s2 = 0, *c, *end, sep;
	int left = MAXNIDSTR;
	lnet_nid_t nid;

	converted = malloc(left);
	if (!converted)
		return NULL;

	end = s1 + strlen(s1);
	c = converted;
	while ((left > 0) && (s1 < end)) {
		s2 = strpbrk(s1, ",:");
		if (!s2)
			s2 = end;
		sep = *s2;
		*s2 = '\0';
		nid = libcfs_str2nid(s1);
		*s2 = sep;

		if (nid == LNET_NID_ANY) {
			fprintf(stderr, "%s: Cannot resolve hostname '%s'.\n",
				progname, s1);
			free(converted);
			return NULL;
		}
		if (strncmp(libcfs_nid2str(nid), "127.0.0.1",
			    strlen("127.0.0.1")) == 0) {
			fprintf(stderr,
				"%s: The NID '%s' resolves to the loopback address '%s'.  Lustre requires a non-loopback address.\n",
				progname, s1, libcfs_nid2str(nid));
			free(converted);
			return NULL;
		}

		c += snprintf(c, left, "%s%c", libcfs_nid2str(nid), sep);
		left = converted + MAXNIDSTR - c;
		s1 = s2 + 1;
	}
	return converted;
}

int parse_opts(int argc, char *const argv[], struct mkfs_opts *mop,
	       char **mountopts, char *old_fsname)
{
	static struct option long_opts[] = {
	{ .val = 'B',	.name =  "backfs-mount-opts",
						.has_arg = required_argument},
	{ .val = 'f',	.name =  "failnode",	.has_arg = required_argument},
	{ .val = 'f',	.name =  "failover",	.has_arg = required_argument},
	{ .val = 'G',	.name =  "mgs",		.has_arg = no_argument},
	{ .val = 'h',	.name =  "help",	.has_arg = no_argument},
	{ .val = 'i',	.name =  "index",	.has_arg = required_argument},
	{ .val = 'L',	.name =  "fsname",	.has_arg = required_argument},
	{ .val = 'm',	.name =  "mgsnode",	.has_arg = required_argument},
	{ .val = 'm',	.name =  "mgsnid",	.has_arg = required_argument},
	{ .val = 'n',	.name =  "dryrun",	.has_arg = no_argument},
	{ .val = 'N',	.name =  "nomgs",	.has_arg = no_argument},
	{ .val = 'o',	.name =  "mountfsoptions",
						.has_arg = required_argument},
	{ .val = 'p',	.name =  "param",	.has_arg = required_argument},
	{ .val = 'q',	.name =  "quiet",	.has_arg = no_argument},
	{ .val = 's',	.name =  "servicenode",	.has_arg = required_argument},
	{ .val = 't',	.name =  "network",	.has_arg = required_argument},
	{ .val = 'u',	.name =  "comment",	.has_arg = required_argument},
	{ .val = 'U',	.name =  "force-nohostid",
						.has_arg = no_argument},
	{ .val = 'v',	.name =  "verbose",	.has_arg = no_argument},
	{ .val = 'V',	.name =  "version",	.has_arg = no_argument},
#ifndef TUNEFS
	{ .val = 'b',	.name =  "backfstype",	.has_arg = required_argument},
	{ .val = 'c',	.name =  "stripe-count-hint",
						.has_arg = required_argument},
	{ .val = 'd',	.name =  "device-size",	.has_arg = required_argument},
	{ .val = 'k',	.name =  "mkfsoptions",	.has_arg = required_argument},
	{ .val = 'M',	.name =  "mdt",		.has_arg = no_argument},
	{ .val = 'O',	.name =  "ost",		.has_arg = no_argument},
	{ .val = 'r',	.name =  "reformat",	.has_arg = no_argument},
	{ .val = 'R',	.name =  "replace",	.has_arg = no_argument},
#else
	{ .val = 'E',	.name =  "erase-param",	.has_arg = required_argument},
	{ .val = 'e',	.name =  "erase-params",
						.has_arg = no_argument},
	{ .val = 'l',	.name =  "nolocallogs", .has_arg = no_argument},
	{ .val = 'Q',	.name =  "quota",	.has_arg = no_argument},
	{ .val = 'R',	.name =  "rename",	.has_arg = optional_argument},
	{ .val = 'w',	.name =  "writeconf",	.has_arg = no_argument},
#endif
	{ .name = NULL } };
	char *short_opts = "B:f:Ghi:L:m:nNo:p:qs:t:u:vV"
#ifndef TUNEFS
			  "b:c:d:k:MOrR";
#else
			  "E:elQR::w";
#endif
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	char new_fsname[16] = { 0 };
	int opt;
	int rc, longidx;
	int failnode_set = 0, servicenode_set = 0;
	int replace = 0;
	bool index_option = false;

#ifdef TUNEFS
	/*
	 * For the right semantics, if '-e'/'--erase-params' is specified,
	 * it must be picked out and all old parameters should be erased
	 * before any other changes are done.
	 */
	while ((opt = getopt_long(argc, argv, short_opts, long_opts,
				  &longidx)) != EOF) {
		switch (opt) {
		case 'e':
			ldd->ldd_params[0] = '\0';
			mop->mo_flags |= MO_ERASE_ALL;
			ldd->ldd_flags |= LDD_F_UPDATE;
			break;
		default:
			break;
		}
		if (mop->mo_flags & MO_ERASE_ALL)
			break;
	}
	optind = 0;
#endif
	while ((opt = getopt_long(argc, argv, short_opts, long_opts,
				  &longidx)) != EOF) {
		switch (opt) {
		case 'B':
			mop->mo_mountopts = optarg;
			break;
		case 'f':
		case 's': {
			char *nids;

			if ((opt == 'f' && servicenode_set) ||
			    (opt == 's' && failnode_set)) {
				fprintf(stderr, "%s: %s cannot use with --%s\n",
					progname, long_opts[longidx].name,
					opt == 'f' ? "servicenode" :
					"failnode");
				return 1;
			}

			nids = convert_hostnames(optarg);
			if (!nids)
				return 1;

			rc = append_param(ldd->ldd_params, PARAM_FAILNODE,
					  nids, ':');
			free(nids);
			if (rc != 0)
				return rc;

			/* Must update the mgs logs */
			ldd->ldd_flags |= LDD_F_UPDATE;
			if (opt == 'f') {
				ldd->ldd_flags &= ~LDD_F_NO_PRIMNODE;
				failnode_set = 1;
			} else {
				ldd->ldd_flags |= LDD_F_NO_PRIMNODE;
				servicenode_set = 1;
			}
			mop->mo_flags |= MO_FAILOVER;
			break;
		}
		case 'G':
			ldd->ldd_flags |= LDD_F_SV_TYPE_MGS;
			break;
		case 'h':
			usage(stdout);
			return 1;
		case 'i': {
			char *endptr = NULL;
			int base;

			index_option = true;
			/* LU-2374: check whether it is OST/MDT later */
			base = (strlen(optarg) > 1 &&
				!strncmp(optarg, "0x", 2)) ? 16 : 10;
			/* Allowed input are base 16 and base 10 numbers only */
			mop->mo_ldd.ldd_svindex = strtoul(optarg,
							  &endptr, base);
			if (*endptr != '\0') {
				fprintf(stderr,
					"%s: wrong index %s. Target index must be decimal or hexadecimal.\n",
					progname, optarg);
				return 1;
			}
			if (ldd->ldd_svindex >= INDEX_UNASSIGNED) {
				fprintf(stderr,
					"%s: wrong index %u. Target index must be less than %u.\n",
					progname, ldd->ldd_svindex,
					INDEX_UNASSIGNED);
				return 1;
			}

			ldd->ldd_flags &= ~LDD_F_NEED_INDEX;
			break;
		}
		case 'L': {
			const char *tmp;
			size_t len;

			len = strlen(optarg);
			if (len < 1 || len > LUSTRE_MAXFSNAME) {
				fprintf(stderr,
					"%s: filesystem name must be 1-%d chars\n",
					progname, LUSTRE_MAXFSNAME);
				return 1;
			}

			for (tmp = optarg; *tmp != '\0'; ++tmp) {
				if (isalnum(*tmp) || *tmp == '_' || *tmp == '-')
					continue;
				else
					break;
			}
			if (*tmp != '\0') {
				fprintf(stderr,
					"%s: char '%c' not allowed in filesystem name\n",
					progname, *tmp);
				return 1;
			}
			strscpy(new_fsname, optarg, sizeof(new_fsname));
			break;
		}
		case 'm': {
			char *nids = convert_hostnames(optarg);

			if (!nids)
				return 1;

			rc = append_param(ldd->ldd_params, PARAM_MGSNODE,
					  nids, ':');
			free(nids);
			if (rc != 0)
				return rc;

			mop->mo_mgs_failnodes++;
			break;
		}
		case 'n':
			print_only++;
			break;
		case 'N':
			ldd->ldd_flags &= ~LDD_F_SV_TYPE_MGS;
			break;
		case 'o':
			*mountopts = optarg;
			break;
		case 'p':
#ifdef TUNEFS
			/*
			 * Removes all existing instances of the parameter
			 * before adding new values.
			 */
			rc = erase_param(ldd->ldd_params, optarg, true);
			if (rc > 1)
				return rc;
#endif
			rc = add_param(ldd->ldd_params, NULL, optarg);
			if (rc != 0)
				return rc;
			/* Must update the mgs logs */
			ldd->ldd_flags |= LDD_F_UPDATE;
			break;
		case 'q':
			verbose--;
			break;
		case 't':
			if (!IS_MDT(ldd) && !IS_OST(ldd)) {
				badopt(long_opts[longidx].name, "MDT,OST");
				return 1;
			}

			if (!optarg)
				return 1;

			rc = add_param(ldd->ldd_params, PARAM_NETWORK, optarg);
			if (rc != 0)
				return rc;

			/* Must update the mgs logs */
			ldd->ldd_flags |= LDD_F_UPDATE;
			break;
		case 'u':
			strscpy(ldd->ldd_userdata, optarg,
				sizeof(ldd->ldd_userdata));
			break;
		case 'U':
			mop->mo_flags |= MO_NOHOSTID_CHECK;
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			++version;
			fprintf(stdout, "%s %s\n", progname,
				LUSTRE_VERSION_STRING);
			return 0;
#ifndef TUNEFS
		case 'b': {
			int i = 0;

			do {
				if (strcmp(optarg, mt_str(i)) == 0) {
					ldd->ldd_mount_type = i;
					break;
				}
			} while (++i < LDD_MT_LAST);

			if (i == LDD_MT_LAST) {
				fprintf(stderr,
					"%s: invalid backend filesystem type %s\n",
					progname, optarg);
				return 1;
			}
			break;
		}
		case 'c':
			if (IS_MDT(ldd)) {
				int stripe_count = atol(optarg);

				if (stripe_count <= 0) {
					fprintf(stderr,
						"%s: bad stripe count %s\n",
						progname, optarg);
					return 1;
				}
				mop->mo_stripe_count = stripe_count;
			} else {
				badopt(long_opts[longidx].name, "MDT");
				return 1;
			}
			break;
		case 'd':
			mop->mo_device_kb = atol(optarg);
			break;
		case 'k':
			strscpy(mop->mo_mkfsopts, optarg,
				sizeof(mop->mo_mkfsopts));
			break;
		case 'M':
			ldd->ldd_flags |= LDD_F_SV_TYPE_MDT;
			break;
		case 'O':
			ldd->ldd_flags |= LDD_F_SV_TYPE_OST;
			break;
		case 'r':
			mop->mo_flags |= MO_FORCEFORMAT;
			break;
		case 'R':
			replace = 1;
			break;
#else /* TUNEFS */
		case 'E':
			rc = erase_param(ldd->ldd_params, optarg, false);
			/*
			 * (rc == 1) means not found, so don't need to
			 * call osd_erase_ldd().
			 */
			if (rc > 1)
				return rc;
			if (!rc) {
				rc = osd_erase_ldd(mop, optarg);
				if (rc)
					return rc;
			}
			/* Must update the mgs logs */
			ldd->ldd_flags |= LDD_F_UPDATE;
			break;
		case 'e':
			/* Already done in the beginning */
			break;
		case 'Q':
			mop->mo_flags |= MO_QUOTA;
			break;
		case 'R': {
			char *tmp;

			mop->mo_flags |= MO_RENAME;
			if (!optarg) {
				if (IS_SEPARATED_MGS(ldd)) {
					fprintf(stderr,
						"%s: must specify the old fsname to be renamed for separated MGS\n",
						progname);
					return 1;
				}
				break;
			}

			if ((strlen(optarg) < 1) || (strlen(optarg) > 8)) {
				fprintf(stderr,
					"%s: filesystem name must be 1-8 chars\n",
					progname);
				return 1;
			}

			tmp = strpbrk(optarg, "/:");
			if (tmp) {
				fprintf(stderr,
					"%s: char '%c' not allowed in filesystem name\n",
					progname, *tmp);
				return 1;
			}

			if (IS_SEPARATED_MGS(ldd)) {
				strscpy(old_fsname, optarg,
					sizeof(ldd->ldd_fsname));
			} else if (strlen(old_fsname) != strlen(optarg) ||
				   strcmp(old_fsname, optarg) != 0) {
				fprintf(stderr,
					"%s: the given fsname '%s' to be renamed does not exist\n",
					progname, optarg);
				return 1;
			}
			break;
		}
		case 'w':
			ldd->ldd_flags |= LDD_F_WRITECONF;
			break;
		case 'l':
			if (ldd->ldd_flags & (LDD_F_VIRGIN | LDD_F_WRITECONF)) {
				fprintf(stderr, "Can not apply nolocallogs to the target that was writeconfed or never been registered\n");
				return EINVAL;
			}
			ldd->ldd_flags |= LDD_F_NO_LOCAL_LOGS;
			break;
#endif /* !TUNEFS */
		default:
			if (opt != '?') {
				fatal();
				fprintf(stderr, "Unknown option '%c'\n", opt);
			}
			return EINVAL;
		}
	}

	if (strlen(new_fsname) > 0) {
		if (!(mop->mo_flags & (MO_FORCEFORMAT | MO_RENAME)) &&
		    (!(ldd->ldd_flags & (LDD_F_VIRGIN | LDD_F_WRITECONF)))) {
			fprintf(stderr,
				"%s: cannot change the name of a registered target\n",
				progname);
			return 1;
		}

		strscpy(ldd->ldd_fsname, new_fsname, sizeof(ldd->ldd_fsname));
	}

	if (index_option && !(mop->mo_ldd.ldd_flags &
			      (LDD_F_VIRGIN | LDD_F_WRITECONF))) {
		fprintf(stderr,
			"%s: cannot change the index of a registered target\n",
			progname);
		return 1;
	}

#ifdef TUNEFS
	if (mop->mo_flags & MO_RENAME) {
		if (new_fsname[0] == '\0') {
			fprintf(stderr,
				"%s: need to specify new fsname for renaming case\n",
				progname);
			return 1;
		}

		if (strcmp(old_fsname, new_fsname) == 0) {
			fprintf(stderr,
				"%s: cannot rename fsname '%s' to the same name\n",
				progname, old_fsname);
			return 1;
		}
	}
#endif

	/* Need to clear this flag after parsing 'L' and 'i' options. */
	if (replace)
		ldd->ldd_flags &= ~LDD_F_VIRGIN;

	if (optind == argc) {
		/* The user didn't specify device name */
		fatal();
		fprintf(stderr,
			"Not enough arguments - device name or pool/dataset name not specified.\n");
		return EINVAL;
	}

	/*  The device or pool/filesystem name */
	strscpy(mop->mo_device, argv[optind], sizeof(mop->mo_device));

	/* Followed by optional vdevs */
	if (optind < argc - 1)
		mop->mo_pool_vdevs = (char **)&argv[optind + 1];

	return 0;
}

int main(int argc, char *const argv[])
{
	struct mkfs_opts mop;
	struct lustre_disk_data *ldd = &mop.mo_ldd;
	char *mountopts = NULL;
	char wanted_mountopts[512] = "";
	char old_fsname[16] = "";
	unsigned int mount_type;
	int ret = 0;
	int ret2 = 0;

	progname = strrchr(argv[0], '/');
	if (progname)
		progname++;
	else
		progname = argv[0];

	if ((argc < 2) || (argv[argc - 1][0] == '-')) {
		usage(stderr);
		return EINVAL;
	}

	memset(&mop, 0, sizeof(mop));
	set_defaults(&mop);

	/* device is last arg */
	strscpy(mop.mo_device, argv[argc - 1], sizeof(mop.mo_device));

	ret = osd_init();
	if (ret != 0) {
		fprintf(stderr, "%s: osd_init() failed: %d (%s)\n",
			progname, ret, strerror(ret));
		return ret;
	}

#ifdef TUNEFS
	/*
	 * For tunefs, we must read in the old values before parsing any
	 * new ones.
	 */

	/* Check whether the disk has already been formatted by mkfs.lustre */
	ret = osd_is_lustre(mop.mo_device, &mount_type);
	if (ret == 0) {
		fatal();
		fprintf(stderr,
			"Device %s has not been formatted with mkfs.lustre\n",
			mop.mo_device);
		ret = ENODEV;
		goto out;
	}
	ldd->ldd_mount_type = mount_type;

	ret = osd_read_ldd(mop.mo_device, ldd);
	if (ret != 0) {
		fatal();
		fprintf(stderr,
			"Failed to read previous Lustre data from %s (%d)\n",
			mop.mo_device, ret);
		goto out;
	}

	strscpy(old_fsname, ldd->ldd_fsname, sizeof(ldd->ldd_fsname));
	ldd->ldd_flags &= ~(LDD_F_WRITECONF | LDD_F_VIRGIN |
			    LDD_F_NO_LOCAL_LOGS);

	/* svname of the form lustre:OST1234 means never registered */
	ret = strlen(ldd->ldd_svname);
	if (ldd->ldd_svname[ret - 8] == ':') {
		ldd->ldd_svname[ret - 8] = '-';
		ldd->ldd_flags |= LDD_F_VIRGIN;
	} else if (ldd->ldd_svname[ret - 8] == '=') {
		ldd->ldd_svname[ret - 8] = '-';
		ldd->ldd_flags |= LDD_F_WRITECONF;
	} else if (ldd->ldd_svname[ret - 8] == '+') {
		ldd->ldd_svname[ret - 8] = '-';
		ldd->ldd_flags |= LDD_F_NO_LOCAL_LOGS;
	}

	if (strstr(ldd->ldd_params, PARAM_MGSNODE))
		mop.mo_mgs_failnodes++;

	if (verbose > 0)
		print_ldd("Read previous values", &mop);
#endif /* TUNEFS */

	ret = parse_opts(argc, argv, &mop, &mountopts, old_fsname);
	if (ret != 0 || version)
		goto out;

	if (!IS_MDT(ldd) && !IS_OST(ldd) && !IS_MGS(ldd)) {
		fatal();
		fprintf(stderr, "must set target type: MDT,OST,MGS\n");
		ret = EINVAL;
		goto out;
	}

	if (((IS_MDT(ldd) || IS_MGS(ldd))) && IS_OST(ldd)) {
		fatal();
		fprintf(stderr, "OST type is exclusive with MDT,MGS\n");
		ret = EINVAL;
		goto out;
	}

	/* Stand alone MGS doesn't need an index */
	if (!IS_MDT(ldd) && IS_MGS(ldd)) {
#ifndef TUNEFS
		/* But if --index was specified flag an error */
		if (!(ldd->ldd_flags & LDD_F_NEED_INDEX)) {
			badopt("index", "MDT,OST");
			goto out;
		}
#endif
		ldd->ldd_flags &= ~LDD_F_NEED_INDEX;
	}

	if (ldd->ldd_flags & LDD_F_NEED_INDEX)
		fprintf(stderr,
			"warning: %s: for Lustre 2.4 and later, the target index must be specified with --index\n",
			mop.mo_device);

	/* If no index is supplied for MDT by default set index to zero */
	if (IS_MDT(ldd) && (ldd->ldd_svindex == INDEX_UNASSIGNED)) {
		ldd->ldd_flags &= ~LDD_F_NEED_INDEX;
		ldd->ldd_svindex = 0;
	}
#ifndef TUNEFS
	if (!IS_MGS(ldd) && (mop.mo_mgs_failnodes == 0)) {
#else
	/*
	 * Don't check --mgs or --mgsnode if print_only is set or
	 * --erase-params is set.
	 */
	if (!IS_MGS(ldd) && (mop.mo_mgs_failnodes == 0) && !print_only &&
	    !(mop.mo_flags & MO_ERASE_ALL)) {
#endif
		fatal();
		if (IS_MDT(ldd))
			fprintf(stderr, "Must specify --mgs or --mgsnode\n");
		else
			fprintf(stderr, "Must specify --mgsnode\n");
		ret = EINVAL;
		goto out;
	}
	if ((IS_MDT(ldd) || IS_OST(ldd)) && ldd->ldd_fsname[0] == '\0') {
		fatal();
		fprintf(stderr, "Must specify --fsname for MDT/OST device\n");
		ret = EINVAL;
		goto out;
	}

	/* These are the permanent mount options (always included) */
	ret = osd_prepare_lustre(&mop,
				 wanted_mountopts, sizeof(wanted_mountopts));
	if (ret != 0) {
		fatal();
		fprintf(stderr, "unable to prepare backend (%d)\n", ret);
		goto out;
	}

	if (mountopts) {
		trim_mountfsoptions(mountopts);
		if (check_mountfsoptions(mountopts, wanted_mountopts)) {
			ret = EINVAL;
			goto out;
		}
		snprintf(ldd->ldd_mount_opts, sizeof(ldd->ldd_mount_opts),
			 "%s", mountopts);
	} else {
#ifdef TUNEFS
		if (ldd->ldd_mount_opts[0] == 0)
		/* use the defaults unless old opts exist */
#endif
		{
			snprintf(ldd->ldd_mount_opts,
				 sizeof(ldd->ldd_mount_opts),
				 "%s", wanted_mountopts);
			trim_mountfsoptions(ldd->ldd_mount_opts);
		}
	}

	ret = osd_fix_mountopts(&mop, ldd->ldd_mount_opts,
				sizeof(ldd->ldd_mount_opts));
	if (ret != 0) {
		fatal();
		fprintf(stderr, "unable to fix mountfsoptions (%d)\n", ret);
		goto out;
	}

	if (server_make_name(ldd->ldd_flags, ldd->ldd_svindex,
			     ldd->ldd_fsname, ldd->ldd_svname,
			     sizeof(ldd->ldd_svname))) {
		printf("unknown server type %#x\n", ldd->ldd_flags);
		goto out;
	}

	if (verbose >= 0)
		print_ldd("Permanent disk data", &mop);

	if (print_only) {
		printf("exiting before disk write.\n");
		goto out;
	}

	if (check_mtab_entry(mop.mo_device, mop.mo_device, NULL, NULL)) {
		fprintf(stderr, "%s: is currently mounted, exiting without any change\n",
			mop.mo_device);
		return EEXIST;
	}

	/* Create the loopback file */
	if (mop.mo_flags & MO_IS_LOOP) {
		ret = access(mop.mo_device, F_OK);
		if (ret != 0)
			ret = errno;

#ifndef TUNEFS
		/* Reformat the loopback file */
		if (ret != 0 || (mop.mo_flags & MO_FORCEFORMAT)) {
			ret = loop_format(&mop);
			if (ret != 0)
				goto out;
		}
#endif
		if (ret == 0)
			ret = loop_setup(&mop);
		if (ret != 0) {
			fatal();
			fprintf(stderr, "Loop device setup for %s failed: %s\n",
				mop.mo_device, strerror(ret));
			goto out;
		}
	}

#ifndef TUNEFS
	/* Check whether the disk has already been formatted by mkfs.lustre */
	if (!(mop.mo_flags & MO_FORCEFORMAT)) {
		ret = osd_is_lustre(mop.mo_device, &mount_type);
		if (ret != 0) {
			fatal();
			fprintf(stderr,
				"Device %s was previously formatted for lustre. Use --reformat to reformat it, or tunefs.lustre to modify.\n",
				mop.mo_device);
			goto out;
		}
	}

	/* Format the backing filesystem */
	ret = osd_make_lustre(&mop);
	if (ret != 0) {
		fatal();
		fprintf(stderr, "mkfs failed %d\n", ret);
		goto out;
	}
#else /* TUNEFS */
	/* update svname with '=' to refresh config */
	if (ldd->ldd_flags & LDD_F_WRITECONF) {
		struct mount_opts opts;

		opts.mo_ldd = *ldd;
		opts.mo_source = mop.mo_device;
		(void)osd_label_lustre(&opts);
	}

	/* update svname with '+' to force remote logs */
	if (ldd->ldd_flags & LDD_F_NO_LOCAL_LOGS) {
		struct mount_opts opts;

		opts.mo_ldd = *ldd;
		opts.mo_source = mop.mo_device;
		(void) osd_label_lustre(&opts);
	}

	/* Rename filesystem fsname */
	if (mop.mo_flags & MO_RENAME) {
		ret = osd_rename_fsname(&mop, old_fsname);
		if (ret)
			goto out;
	}

	/* Enable quota accounting */
	if (mop.mo_flags & MO_QUOTA) {
		ret = osd_enable_quota(&mop);
		goto out;
	}
#endif /* !TUNEFS */

	/* Write our config files */
	ret = osd_write_ldd(&mop);
	if (ret != 0) {
		fatal();
		fprintf(stderr, "failed to write local files\n");
		goto out;
	}
out:
	osd_fini();
	ret2 = loop_cleanup(&mop);
	if (ret == 0)
		ret = ret2;

	/* Fix any crazy return values from system() */
	if (ret != 0 && ((ret & 255) == 0))
		return 1;

	if (ret != 0)
		verrprint("%s: exiting with %d (%s)\n",
			  progname, ret, strerror(ret));
	return ret;
}
