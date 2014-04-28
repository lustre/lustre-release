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
 * Copyright (c) 2012, 2013, Intel Corporation.
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
#include <time.h>

#include "obdctl.h"

#include <lustre/lustre_lfsck_user.h>
#include <libcfs/libcfsutil.h>
#include <lnet/lnetctl.h>
#include <lustre_ioctl.h>

static struct option long_opt_start[] = {
	{"device",		required_argument, 0, 'M'},
	{"all",			no_argument,	   0, 'A'},
	{"create_ostobj",	optional_argument, 0, 'c'},
	{"error",		required_argument, 0, 'e'},
	{"help",		no_argument,	   0, 'h'},
	{"dryrun",		optional_argument, 0, 'n'},
	{"orphan",		no_argument,	   0, 'o'},
	{"reset",		no_argument,	   0, 'r'},
	{"speed",		required_argument, 0, 's'},
	{"type",		required_argument, 0, 't'},
	{"windows",		required_argument, 0, 'w'},
	{0,			0,		   0,  0 }
};

static struct option long_opt_stop[] = {
	{"device",      required_argument, 0, 'M'},
	{"all", 	no_argument,       0, 'A'},
	{"help",	no_argument,       0, 'h'},
	{0,		0,		   0,   0}
};

struct lfsck_type_name {
	char		*name;
	int		 namelen;
	enum lfsck_type  type;
};

static struct lfsck_type_name lfsck_types_names[] = {
	{ "layout",     6,	LT_LAYOUT },
	{ "namespace",	9,	LT_NAMESPACE},
	{ 0,		0,	0 }
};

static inline int lfsck_name2type(const char *name, int namelen)
{
	int i = 0;

	while (lfsck_types_names[i].name != NULL) {
		if (namelen == lfsck_types_names[i].namelen &&
		    strncmp(lfsck_types_names[i].name, name, namelen) == 0)
			return lfsck_types_names[i].type;
		i++;
	}
	return 0;
}

static void usage_start(void)
{
	fprintf(stderr, "Start LFSCK.\n"
		"SYNOPSIS:\n"
		"lfsck_start <-M | --device [MDT,OST]_device>\n"
		"	     [-A | --all] [-c | --create_ostobj [swtich]]\n"
		"	     [-e | --error error_handle] [-h | --help]\n"
		"	     [-n | --dryrun [switch]] [-o | --orphan]\n"
		"	     [-r | --reset] [-s | --speed speed_limit]\n"
		"	     [-t | --type lfsck_type[,lfsck_type...]]\n"
		"	     [-w | --windows win_size]\n"
		"OPTIONS:\n"
		"-M: The device to start LFSCK/scrub on.\n"
		"-A: Start LFSCK on all MDT devices.\n"
		"-c: create the lost OST-object for dangling LOV EA. "
		    "'off'(default) or 'on'.\n"
		"-e: Error handle, 'continue'(default) or 'abort'.\n"
		"-h: Help information.\n"
		"-n: Check without modification. 'off'(default) or 'on'.\n"
		"-o: handle orphan objects.\n"
		"-r: Reset scanning start position to the device beginning.\n"
		"-s: How many items can be scanned at most per second. "
		    "'%d' means no limit (default).\n"
		"-t: The LFSCK type(s) to be started.\n"
		"-w: The windows size for async requests pipeline.\n",
		LFSCK_SPEED_NO_LIMIT);
}

static void usage_stop(void)
{
	fprintf(stderr, "Stop LFSCK.\n"
		"SYNOPSIS:\n"
		"lfsck_stop <-M | --device [MDT,OST]_device>\n"
		"[-A | --all] [-h | --help]\n"
		"OPTIONS:\n"
		"-M: The device to stop LFSCK/scrub on.\n"
		"-A: Stop LFSCK on all MDT devices.\n"
		"-h: Help information.\n");
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
	char *optstring = "M:Ac::e:hn::ors:t:w:";
	int opt, index, rc, val, i, type;

	memset(&data, 0, sizeof(data));
	memset(&start, 0, sizeof(start));
	memset(device, 0, MAX_OBD_NAME);
	start.ls_version = LFSCK_VERSION_V1;
	start.ls_active = LFSCK_TYPES_DEF;

	/* Reset the 'optind' for the case of getopt_long() called multiple
	 * times under the same lctl. */
	optind = 0;
	while ((opt = getopt_long(argc, argv, optstring, long_opt_start,
				  &index)) != EOF) {
		switch (opt) {
		case 'M':
			rc = lfsck_pack_dev(&data, device, optarg);
			if (rc != 0)
				return rc;
			break;
		case 'A':
			start.ls_flags |= LPF_ALL_TGT | LPF_BROADCAST;
			break;
		case 'c':
			if (optarg == NULL || strcmp(optarg, "on") == 0) {
				start.ls_flags |= LPF_CREATE_OSTOBJ;
			} else if (strcmp(optarg, "off") != 0) {
				fprintf(stderr, "Invalid switch: %s. "
					"The valid switch should be: 'on' "
					"or 'off' (default) without blank, "
					"or empty. For example: '-non' or "
					"'-noff' or '-n'.\n", optarg);
				return -EINVAL;
			}
			start.ls_valid |= LSV_CREATE_OSTOBJ;
			break;
		case 'e':
			if (strcmp(optarg, "abort") == 0) {
				start.ls_flags |= LPF_FAILOUT;
			} else if (strcmp(optarg, "continue") != 0) {
				fprintf(stderr, "Invalid error handler: %s. "
					"The valid value should be: 'continue'"
					"(default) or 'abort'.\n", optarg);
				return -EINVAL;
			}
			start.ls_valid |= LSV_ERROR_HANDLE;
			break;
		case 'h':
			usage_start();
			return 0;
		case 'n':
			if (optarg == NULL || strcmp(optarg, "on") == 0) {
				start.ls_flags |= LPF_DRYRUN;
			} else if (strcmp(optarg, "off") != 0) {
				fprintf(stderr, "Invalid switch: %s. "
					"The valid switch should be: 'on' "
					"or 'off' (default) without blank, "
					"or empty. For example: '-non' or "
					"'-noff' or '-n'.\n", optarg);
				return -EINVAL;
			}
			start.ls_valid |= LSV_DRYRUN;
			break;
		case 'o':
			start.ls_flags |= LPF_ALL_TGT | LPF_BROADCAST |
					  LPF_ORPHAN;
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
			char *str = optarg, *p, c;

			start.ls_active = 0;
			while (*str) {
				while (*str == ' ' || *str == ',')
					str++;

				if (*str == 0)
					break;

				p = str;
				while (*p != 0 && *p != ' ' && *p != ',')
					p++;

				c = *p;
				*p = 0;
				type = lfsck_name2type(str, strlen(str));
				if (type == 0) {
					fprintf(stderr, "Invalid type (%s).\n"
						"The valid value should be "
						"'layout' or 'namespace'.\n",
						str);
					*p = c;
					return -EINVAL;
				}

				*p = c;
				str = p;

				start.ls_active |= type;
			}
			if (start.ls_active == 0) {
				fprintf(stderr, "Miss LFSCK type(s).\n"
					"The valid value should be "
					"'layout' or 'namespace'.\n");
				return -EINVAL;
			}
			break;
		}
		case 'w':
			val = atoi(optarg);
			if (val < 0 || val > LFSCK_ASYNC_WIN_MAX) {
				fprintf(stderr,
					"Too large async windows size, "
					"which may cause memory issues. "
					"The valid range is [0 - %u]. "
					"If you do not want to restrict "
					"the windows size for async reqeusts "
					"pipeline, just set it as 0.\n",
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
	if (rc) {
		fprintf(stderr, "Fail to pack ioctl data: rc = %d.\n", rc);
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_START_LFSCK, buf);
	if (rc < 0) {
		perror("Fail to start LFSCK");
		return rc;
	}

	obd_ioctl_unpack(&data, buf, sizeof(rawbuf));
	if (start.ls_active == 0) {
		printf("Started LFSCK on the device %s", device);
	} else {
		printf("Started LFSCK on the device %s:", device);
		i = 0;
		while (lfsck_types_names[i].name != NULL) {
			if (start.ls_active & lfsck_types_names[i].type) {
				printf(" %s", lfsck_types_names[i].name);
				start.ls_active &= ~lfsck_types_names[i].type;
			}
			i++;
		}
		if (start.ls_active != 0)
			printf(" unknown(0x%x)", start.ls_active);
	}
	printf(".\n");
	return 0;
}

int jt_lfsck_stop(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	char device[MAX_OBD_NAME];
	struct lfsck_stop stop;
	char *optstring = "M:Ah";
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
		case 'M':
			rc = lfsck_pack_dev(&data, device, optarg);
			if (rc != 0)
				return rc;
			break;
		case 'A':
			stop.ls_flags |= LPF_ALL_TGT | LPF_BROADCAST;
			break;
		case 'h':
			usage_stop();
			return 0;
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
	if (rc) {
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
