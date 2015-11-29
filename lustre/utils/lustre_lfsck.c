/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * lustre/utils/lustre_lfsck.c
 *
 * Lustre user-space tools for LFSCK.
 *
 * Author: Fan Yong <yong.fan@whamcloud.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <time.h>

#include "obdctl.h"

#include <lustre/lustre_lfsck_user.h>
#include <lnet/lnetctl.h>
#include <lustre_ioctl.h>
/* Needs to be last to avoid clashes */
#include <libcfs/util/ioctl.h>

static struct option long_opt_start[] = {
	{"device",		required_argument, 0, 'M'},
	{"all",			no_argument,	   0, 'A'},
	{"create_ostobj",	optional_argument, 0, 'c'},
	{"create_mdtobj",	optional_argument, 0, 'C'},
	{"error",		required_argument, 0, 'e'},
	{"help",		no_argument,	   0, 'h'},
	{"dryrun",		optional_argument, 0, 'n'},
	{"orphan",		no_argument,	   0, 'o'},
	{"reset",		no_argument,	   0, 'r'},
	{"speed",		required_argument, 0, 's'},
	{"type",		required_argument, 0, 't'},
	{"window_size",		required_argument, 0, 'w'},
	{0,			0,		   0,  0 }
};

static struct option long_opt_stop[] = {
	{"device",      required_argument, 0, 'M'},
	{"all", 	no_argument,       0, 'A'},
	{"help",	no_argument,       0, 'h'},
	{0,		0,		   0,  0 }
};

static struct option long_opt_query[] = {
	{"device",      required_argument, 0, 'M'},
	{"type",	required_argument, 0, 't'},
	{"help",	no_argument,       0, 'h'},
	{"wait",	no_argument,       0, 'w'},
	{0,		0,		   0,  0 }
};

struct lfsck_type_name {
	char		*ltn_name;
	enum lfsck_type  ltn_type;
};

static struct lfsck_type_name lfsck_types_names[] = {
	{ "scrub",	LFSCK_TYPE_SCRUB },
	{ "layout",	LFSCK_TYPE_LAYOUT },
	{ "namespace",	LFSCK_TYPE_NAMESPACE },
	{ "default",	LFSCK_TYPES_DEF },
	{ "all",	LFSCK_TYPES_SUPPORTED },
	{ NULL,		0 }
};

static enum lfsck_type lfsck_name2type(const char *name)
{
	int i;

	for (i = 0; lfsck_types_names[i].ltn_name != NULL; i++) {
		if (strcmp(lfsck_types_names[i].ltn_name, name) == 0)
			return lfsck_types_names[i].ltn_type;
	}
	return -1;
}

static const char *lfsck_type2name(__u16 type)
{
	int i;

	for (i = 0; lfsck_types_names[i].ltn_name != NULL; i++) {
		if (type == lfsck_types_names[i].ltn_type)
			return lfsck_types_names[i].ltn_name;
	}

	return NULL;
}

static void usage_start(void)
{
	fprintf(stderr, "start LFSCK\n"
		"usage:\n"
		"lfsck_start <-M | --device {MDT,OST}_device>\n"
		"	     [-A | --all] [-c | --create_ostobj [on | off]]\n"
		"	     [-C | --create_mdtobj [on | off]]\n"
		"	     [-e | --error {continue | abort}] [-h | --help]\n"
		"	     [-n | --dryrun [on | off]] [-o | --orphan]\n"
		"            [-r | --reset] [-s | --speed ops_per_sec_limit]\n"
		"            [-t | --type check_type[,check_type...]]\n"
		"	     [-w | --window_size size]\n"
		"options:\n"
		"-M: device to start LFSCK/scrub on\n"
		"-A: start LFSCK on all MDT devices\n"
		"-c: create the lost OST-object for dangling LOV EA "
		    "(default 'off', or 'on')\n"
		"-C: create the lost MDT-object for dangling name entry "
		    "(default 'off', or 'on')\n"
		"-e: error handle mode (default 'continue', or 'abort')\n"
		"-h: this help message\n"
		"-n: check with no modification (default 'off', or 'on')\n"
		"-o: repair orphan OST-objects\n"
		"-r: reset scanning to the start of the device\n"
		"-s: maximum items to be scanned per second "
		    "(default '%d' = no limit)\n"
		"-t: check type(s) to be performed (default all)\n"
		"-w: window size for async requests pipeline\n",
		LFSCK_SPEED_NO_LIMIT);
}

static void usage_stop(void)
{
	fprintf(stderr, "stop LFSCK\n"
		"usage:\n"
		"lfsck_stop <-M | --device {MDT,OST}_device>\n"
		"           [-A | --all] [-h | --help]\n"
		"options:\n"
		"-M: device to stop LFSCK/scrub on\n"
		"-A: stop LFSCK on all MDT devices\n"
		"-h: this help message\n");
}

static void usage_query(void)
{
	fprintf(stderr, "check the LFSCK global status\n"
		"usage:\n"
		"lfsck_query <-M | --device MDT_device> [-h | --help]\n"
		"            [-t | --type check_type[,check_type...]]\n"
		"            [-t | --wait]\n"
		"options:\n"
		"-M: device to query LFSCK on\n"
		"-t: LFSCK type(s) to be queried (default is all)\n"
		"-h: this help message\n"
		"-w: do not return until LFSCK not running\n");
}

static int lfsck_pack_dev(struct obd_ioctl_data *data, char *device, char *arg)
{
	int len = strlen(arg) + 1;

	if (len > MAX_OBD_NAME) {
		fprintf(stderr, "device name is too long. "
			"Valid length should be less than %d\n", MAX_OBD_NAME);
		return -EINVAL;
	}

	memcpy(device, arg, len);
	data->ioc_inlbuf4 = device;
	data->ioc_inllen4 = len;
	data->ioc_dev = OBD_DEV_BY_DEVNAME;
	return 0;
}

int jt_lfsck_start(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	char device[MAX_OBD_NAME];
	struct lfsck_start start;
	char *optstring = "Ac::C::e:hM:n::ors:t:w:";
	int opt, index, rc, val, i;

	memset(&data, 0, sizeof(data));
	memset(&start, 0, sizeof(start));
	memset(device, 0, MAX_OBD_NAME);
	start.ls_version = LFSCK_VERSION_V1;
	start.ls_active = LFSCK_TYPES_ALL;

	/* Reset the 'optind' for the case of getopt_long() called multiple
	 * times under the same lctl. */
	optind = 0;
	while ((opt = getopt_long(argc, argv, optstring, long_opt_start,
				  &index)) != EOF) {
		switch (opt) {
		case 'A':
			start.ls_flags |= LPF_ALL_TGT | LPF_BROADCAST;
			break;
		case 'c':
			if (optarg == NULL || strcmp(optarg, "on") == 0) {
				start.ls_flags |= LPF_CREATE_OSTOBJ;
			} else if (strcmp(optarg, "off") != 0) {
				fprintf(stderr, "invalid switch: -c '%s'. "
					"valid switches are:\n"
					"empty ('on'), or 'off' without space. "
					"For example:\n"
					"'-c', '-con', '-coff'\n", optarg);
				return -EINVAL;
			}
			start.ls_valid |= LSV_CREATE_OSTOBJ;
			break;
		case 'C':
			if (optarg == NULL || strcmp(optarg, "on") == 0) {
				start.ls_flags |= LPF_CREATE_MDTOBJ;
			} else if (strcmp(optarg, "off") != 0) {
				fprintf(stderr, "invalid switch: -C '%s'. "
					"valid switches are:\n"
					"empty ('on'), or 'off' without space. "
					"For example:\n"
					"'-C', '-Con', '-Coff'\n", optarg);
				return -EINVAL;
			}
			start.ls_valid |= LSV_CREATE_MDTOBJ;
			break;
		case 'e':
			if (strcmp(optarg, "abort") == 0) {
				start.ls_flags |= LPF_FAILOUT;
			} else if (strcmp(optarg, "continue") != 0) {
				fprintf(stderr, "invalid error mode: -e '%s'."
					"valid modes are: "
					"'continue' or 'abort'.\n", optarg);
				return -EINVAL;
			}
			start.ls_valid |= LSV_ERROR_HANDLE;
			break;
		case 'h':
			usage_start();
			return 0;
		case 'M':
			rc = lfsck_pack_dev(&data, device, optarg);
			if (rc != 0)
				return rc;
			break;
		case 'n':
			if (optarg == NULL || strcmp(optarg, "on") == 0) {
				start.ls_flags |= LPF_DRYRUN;
			} else if (strcmp(optarg, "off") != 0) {
				fprintf(stderr, "invalid switch: -n '%s'. "
					"valid switches are:\n"
					"empty ('on'), or 'off' without space. "
					"For example:\n"
					"'-n', '-non', '-noff'\n", optarg);
				return -EINVAL;
			}
			start.ls_valid |= LSV_DRYRUN;
			break;
		case 'o':
			start.ls_flags |= LPF_ALL_TGT | LPF_BROADCAST |
					  LPF_OST_ORPHAN;
			break;
		case 'r':
			start.ls_flags |= LPF_RESET;
			break;
		case 's':
			val = atoi(optarg);
			start.ls_speed_limit = val;
			start.ls_valid |= LSV_SPEED_LIMIT;
			break;
		case 't': {
			char *typename;

			if (start.ls_active == LFSCK_TYPES_ALL)
				start.ls_active = 0;
			while ((typename = strsep(&optarg, ",")) != NULL) {
				enum lfsck_type type;

				type = lfsck_name2type(typename);
				if (type == -1)
					goto bad_type;
				start.ls_active |= type;
			}
			break;
bad_type:
			fprintf(stderr, "invalid check type -t '%s'. "
				"valid types are:\n", typename);
			for (i = 0; lfsck_types_names[i].ltn_name != NULL; i++)
				fprintf(stderr, "%s%s", i != 0 ? "," : "",
					lfsck_types_names[i].ltn_name);
			fprintf(stderr, "\n");
			return -EINVAL;
		}
		case 'w':
			val = atoi(optarg);
			if (val < 1 || val > LFSCK_ASYNC_WIN_MAX) {
				fprintf(stderr,
					"Invalid async window size that "
					"may cause memory issues. The valid "
					"range is [1 - %u].\n",
					LFSCK_ASYNC_WIN_MAX);
				return -EINVAL;
			}

			start.ls_async_windows = val;
			start.ls_valid |= LSV_ASYNC_WINDOWS;
			break;
		default:
			fprintf(stderr, "Invalid option, '-h' for help.\n");
			return -EINVAL;
		}
	}

	if (start.ls_active == LFSCK_TYPES_ALL)
		start.ls_active = LFSCK_TYPES_DEF;

	if (data.ioc_inlbuf4 == NULL) {
		if (lcfg_get_devname() != NULL) {
			rc = lfsck_pack_dev(&data, device, lcfg_get_devname());
			if (rc != 0)
				return rc;
		} else {
			fprintf(stderr,
				"Must specify device to start LFSCK.\n");
			return -EINVAL;
		}
	}

	data.ioc_inlbuf1 = (char *)&start;
	data.ioc_inllen1 = sizeof(start);
	memset(buf, 0, sizeof(rawbuf));
	rc = obd_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc != 0) {
		fprintf(stderr, "Fail to pack ioctl data: rc = %d.\n", rc);
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_START_LFSCK, buf);
	if (rc < 0) {
		perror("Fail to start LFSCK");
		return rc;
	}

	obd_ioctl_unpack(&data, buf, sizeof(rawbuf));
	printf("Started LFSCK on the device %s: scrub", device);
	for (i = 0; lfsck_types_names[i].ltn_name != NULL; i++) {
		if (start.ls_active & lfsck_types_names[i].ltn_type) {
			printf(" %s", lfsck_types_names[i].ltn_name);
			start.ls_active &= ~lfsck_types_names[i].ltn_type;
		}
	}
	if (start.ls_active != 0)
		printf(" unknown(0x%x)", start.ls_active);
	printf("\n");

	return 0;
}

int jt_lfsck_stop(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	char device[MAX_OBD_NAME];
	struct lfsck_stop stop;
	char *optstring = "AhM:";
	int opt, index, rc;

	memset(&data, 0, sizeof(data));
	memset(&stop, 0, sizeof(stop));
	memset(device, 0, MAX_OBD_NAME);

	/* Reset the 'optind' for the case of getopt_long() called multiple
	 * times under the same lctl. */
	optind = 0;
	while ((opt = getopt_long(argc, argv, optstring, long_opt_stop,
				  &index)) != EOF) {
		switch (opt) {
		case 'A':
			stop.ls_flags |= LPF_ALL_TGT | LPF_BROADCAST;
			break;
		case 'h':
			usage_stop();
			return 0;
		case 'M':
			rc = lfsck_pack_dev(&data, device, optarg);
			if (rc != 0)
				return rc;
			break;
		default:
			fprintf(stderr, "Invalid option, '-h' for help.\n");
			return -EINVAL;
		}
	}

	if (data.ioc_inlbuf4 == NULL) {
		if (lcfg_get_devname() != NULL) {
			rc = lfsck_pack_dev(&data, device, lcfg_get_devname());
			if (rc != 0)
				return rc;
		} else {
			fprintf(stderr,
				"Must specify device to stop LFSCK.\n");
			return -EINVAL;
		}
	}

	data.ioc_inlbuf1 = (char *)&stop;
	data.ioc_inllen1 = sizeof(stop);
	memset(buf, 0, sizeof(rawbuf));
	rc = obd_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc != 0) {
		fprintf(stderr, "Fail to pack ioctl data: rc = %d.\n", rc);
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_STOP_LFSCK, buf);
	if (rc < 0) {
		perror("Fail to stop LFSCK");
		return rc;
	}

	printf("Stopped LFSCK on the device %s.\n", device);
	return 0;
}

int jt_lfsck_query(int argc, char **argv)
{
	struct obd_ioctl_data data = { 0 };
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	char device[MAX_OBD_NAME] = "";
	struct lfsck_query query = { .lu_types = LFSCK_TYPES_ALL };
	int opt, index, rc, i;
	enum lfsck_type type;

	while ((opt = getopt_long(argc, argv, "hM:t:w", long_opt_query,
				  &index)) != EOF) {
		switch (opt) {
		case 'h':
			usage_query();
			return 0;
		case 'M':
			rc = lfsck_pack_dev(&data, device, optarg);
			if (rc != 0)
				return rc;
			break;
		case 't': {
			char *typename;

			if (query.lu_types == LFSCK_TYPES_ALL)
				query.lu_types = 0;
			while ((typename = strsep(&optarg, ",")) != NULL) {
				type = lfsck_name2type(typename);
				if (type == -1)
					goto bad_type;
				query.lu_types |= type;
			}
			break;

bad_type:
			fprintf(stderr, "invalid LFSCK type -t '%s'. "
				"valid types are:\n", typename);
			for (i = 0; lfsck_types_names[i].ltn_name != NULL; i++)
				fprintf(stderr, "%s%s", i != 0 ? "," : "",
					lfsck_types_names[i].ltn_name);
			fprintf(stderr, "\n");
			return -EINVAL;
		}
		case 'w':
			query.lu_flags |= LPF_WAIT;
			break;
		default:
			fprintf(stderr, "Invalid option, '-h' for help.\n");
			usage_query();
			return -EINVAL;
		}
	}

	if (data.ioc_inlbuf4 == NULL) {
		if (lcfg_get_devname() != NULL) {
			rc = lfsck_pack_dev(&data, device, lcfg_get_devname());
			if (rc != 0)
				return rc;
		} else {
			fprintf(stderr,
				"Must specify device to query LFSCK.\n");
			return -EINVAL;
		}
	}

	data.ioc_inlbuf1 = (char *)&query;
	data.ioc_inllen1 = sizeof(query);
	memset(buf, 0, sizeof(rawbuf));
	rc = obd_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc != 0) {
		fprintf(stderr, "Fail to pack ioctl data: rc = %d.\n", rc);
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_QUERY_LFSCK, buf);
	if (rc < 0) {
		perror("Fail to query LFSCK");
		return rc;
	}

	obd_ioctl_unpack(&data, buf, sizeof(rawbuf));
	for (i = 0, type = 1 << i; i < LFSCK_TYPE_BITS; i++, type = 1 << i) {
		const char *name;
		int j;

		if (!(query.lu_types & type))
			continue;

		name = lfsck_type2name(type);
		for (j = 0; j <= LS_MAX; j++)
			printf("%s_mdts_%s: %d\n", name,
			       lfsck_status2name(j), query.lu_mdts_count[i][j]);

		for (j = 0; j <= LS_MAX; j++)
			printf("%s_osts_%s: %d\n", name,
			       lfsck_status2name(j), query.lu_osts_count[i][j]);

		printf("%s_repaired: %llu\n", name, query.lu_repaired[i]);
	}

	return 0;
}
