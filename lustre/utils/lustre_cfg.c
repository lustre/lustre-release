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
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/lustre_cfg.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Robert Read <rread@clusterfs.com>
 */

#include <errno.h>
#include <fcntl.h>
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
#include <lnet/nidstr.h>
#include <linux/lustre_cfg.h>
#include <linux/lustre_ioctl.h>
#include <lustre_ver.h>

#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>

#include "obdctl.h"
#include <lnet/lnetctl.h>
#include <stdio.h>

static char * lcfg_devname;

int lcfg_set_devname(char *name)
{
        char *ptr;
        int digit = 1;

        if (name) {
                if (lcfg_devname)
                        free(lcfg_devname);
                /* quietly strip the unnecessary '$' */
                if (*name == '$' || *name == '%')
                        name++;

                ptr = name;
                while (*ptr != '\0') {
                        if (!isdigit(*ptr)) {
                            digit = 0;
                            break;
                        }
                        ptr++;
                }

                if (digit) {
                        /* We can't translate from dev # to name */
                        lcfg_devname = NULL;
                } else {
                        lcfg_devname = strdup(name);
                }
        } else {
                lcfg_devname = NULL;
        }
        return 0;
}

char * lcfg_get_devname(void)
{
        return lcfg_devname;
}

int jt_lcfg_device(int argc, char **argv)
{
        return jt_obd_device(argc, argv);
}

static int jt_lcfg_ioctl(struct lustre_cfg_bufs *bufs, char *arg, int cmd)
{
	struct lustre_cfg *lcfg;
	int rc;

	lcfg = malloc(lustre_cfg_len(bufs->lcfg_bufcount, bufs->lcfg_buflen));
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		lustre_cfg_init(lcfg, cmd, bufs);
		rc = lcfg_ioctl(arg, OBD_DEV_ID, lcfg);
		free(lcfg);
	}
	if (rc < 0)
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(arg),
			strerror(rc = errno));
	return rc;
}

int jt_lcfg_attach(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        int rc;

        if (argc != 4)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, NULL);

        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);
        lustre_cfg_bufs_set_string(&bufs, 0, argv[2]);
        lustre_cfg_bufs_set_string(&bufs, 2, argv[3]);

	rc = jt_lcfg_ioctl(&bufs, argv[0], LCFG_ATTACH);
	if (rc == 0)
		lcfg_set_devname(argv[2]);

	return rc;
}

int jt_lcfg_setup(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        int i;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'device name' to set the "
                        "device name for config commands.\n",
                        jt_cmdname(argv[0]));
                return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        if (argc > 6)
                return CMD_HELP;

        for (i = 1; i < argc; i++) {
                lustre_cfg_bufs_set_string(&bufs, i, argv[i]);
        }

	return jt_lcfg_ioctl(&bufs, argv[0], LCFG_SETUP);
}

int jt_obd_detach(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'device name' to set the "
                        "device name for config commands.\n",
                        jt_cmdname(argv[0]));
                return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        if (argc != 1)
                return CMD_HELP;

	return jt_lcfg_ioctl(&bufs, argv[0], LCFG_DETACH);
}

int jt_obd_cleanup(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        char force = 'F';
        char failover = 'A';
        char flags[3] = { 0 };
        int flag_cnt = 0, n;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'device name' to set the "
                        "device name for config commands.\n",
                        jt_cmdname(argv[0]));
                return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        if (argc < 1 || argc > 3)
                return CMD_HELP;

        /* we are protected from overflowing our buffer by the argc
         * check above
         */
        for (n = 1; n < argc; n++) {
                if (strcmp(argv[n], "force") == 0) {
                        flags[flag_cnt++] = force;
                } else if (strcmp(argv[n], "failover") == 0) {
                        flags[flag_cnt++] = failover;
		} else {
			fprintf(stderr, "unknown option: %s\n", argv[n]);
			return CMD_HELP;
		}
	}

        if (flag_cnt) {
                lustre_cfg_bufs_set_string(&bufs, 1, flags);
        }

	return jt_lcfg_ioctl(&bufs, argv[0], LCFG_CLEANUP);
}

static
int do_add_uuid(char *func, char *uuid, lnet_nid_t nid)
{
	int rc;
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg;

	lustre_cfg_bufs_reset(&bufs, lcfg_devname);
	if (uuid != NULL)
		lustre_cfg_bufs_set_string(&bufs, 1, uuid);

	lcfg = malloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		lustre_cfg_init(lcfg, LCFG_ADD_UUID, &bufs);
		lcfg->lcfg_nid = nid;

		rc = lcfg_ioctl(func, OBD_DEV_ID, lcfg);
		free(lcfg);
	}
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_ADD_UUID failed: %s\n",
                        strerror(errno));
                return -1;
        }

	if (uuid != NULL)
		printf("Added uuid %s: %s\n", uuid, libcfs_nid2str(nid));

	return 0;
}

int jt_lcfg_add_uuid(int argc, char **argv)
{
        lnet_nid_t nid;

        if (argc != 3) {
                return CMD_HELP;
        }

        nid = libcfs_str2nid(argv[2]);
        if (nid == LNET_NID_ANY) {
                fprintf (stderr, "Can't parse NID %s\n", argv[2]);
                return (-1);
        }

        return do_add_uuid(argv[0], argv[1], nid);
}

int jt_lcfg_del_uuid(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;

        if (argc != 2) {
                fprintf(stderr, "usage: %s <uuid>\n", argv[0]);
                return 0;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);
        if (strcmp (argv[1], "_all_"))
                lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

	return jt_lcfg_ioctl(&bufs, argv[0], LCFG_DEL_UUID);
}

int jt_lcfg_del_mount_option(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;

        if (argc != 2)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        /* profile name */
        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

	return jt_lcfg_ioctl(&bufs, argv[0], LCFG_DEL_MOUNTOPT);
}

int jt_lcfg_set_timeout(int argc, char **argv)
{
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        fprintf(stderr, "%s has been deprecated. Use conf_param instead.\n"
                "e.g. conf_param lustre-MDT0000 obd_timeout=50\n",
                jt_cmdname(argv[0]));
        return CMD_HELP;


        if (argc != 2)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

	lcfg = malloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		lustre_cfg_init(lcfg, LCFG_SET_TIMEOUT, &bufs);
		lcfg->lcfg_num = atoi(argv[1]);

		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		free(lcfg);
	}
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
}

int jt_lcfg_add_conn(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int priority;
        int rc;

        if (argc == 2)
                priority = 0;
        else if (argc == 3)
                priority = 1;
        else
                return CMD_HELP;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'device name' to set the "
                        "device name for config commands.\n",
                        jt_cmdname(argv[0]));
                return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

	lcfg = malloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		lustre_cfg_init(lcfg, LCFG_ADD_CONN, &bufs);
		lcfg->lcfg_num = priority;

		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		free(lcfg);
	}
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }

        return rc;
}

int jt_lcfg_del_conn(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;

        if (argc != 2)
                return CMD_HELP;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'device name' to set the "
                        "device name for config commands.\n",
                        jt_cmdname(argv[0]));
                return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        /* connection uuid */
        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

	return jt_lcfg_ioctl(&bufs, argv[0], LCFG_DEL_MOUNTOPT);
}

/* Param set locally, directly on target */
int jt_lcfg_param(int argc, char **argv)
{
	struct lustre_cfg_bufs bufs;
	int i;

        if (argc >= LUSTRE_CFG_MAX_BUFCOUNT)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, NULL);

        for (i = 1; i < argc; i++) {
                lustre_cfg_bufs_set_string(&bufs, i, argv[i]);
        }

	return jt_lcfg_ioctl(&bufs, argv[0], LCFG_PARAM);
}

struct param_opts {
	unsigned int po_only_path:1;
	unsigned int po_show_path:1;
	unsigned int po_show_type:1;
	unsigned int po_recursive:1;
	unsigned int po_params2:1;
	unsigned int po_delete:1;
	unsigned int po_only_dir:1;
};

/* Param set to single log file, used by all clients and servers.
 * This should be loaded after the individual config logs.
 * Called from set param with -P option.
 */
static int jt_lcfg_mgsparam2(int argc, char **argv, struct param_opts *popt)
{
	int	rc, i;
	int	first_param;
	struct	lustre_cfg_bufs bufs;
	struct	lustre_cfg *lcfg;
	char	*buf = NULL;
	int	len;

	first_param = optind;
	if (first_param < 0 || first_param >= argc)
		return CMD_HELP;

	for (i = first_param, rc = 0; i < argc; i++) {
		lustre_cfg_bufs_reset(&bufs, NULL);
		/* This same command would be executed on all nodes, many
		 * of which should fail (silently) because they don't have
		 * that proc file existing locally. There would be no
		 * preprocessing on the MGS to try to figure out which
		 * parameter files to add this to, there would be nodes
		 * processing on the cluster nodes to try to figure out
		 * if they are the intended targets. They will blindly
		 * try to set the parameter, and ENOTFOUND means it wasn't
		 * for them.
		 * Target name "general" means call on all targets. It is
		 * left here in case some filtering will be added in
		 * future.
		 */
		lustre_cfg_bufs_set_string(&bufs, 0, "general");

		len = strlen(argv[i]);

		/* put an '=' on the end in case it doesn't have one */
		if (popt->po_delete && argv[i][len - 1] != '=') {
			buf = malloc(len + 1);
			if (buf == NULL) {
				rc = -ENOMEM;
				break;
			}
			sprintf(buf, "%s=", argv[i]);
		} else {
			buf = argv[i];
		}
		lustre_cfg_bufs_set_string(&bufs, 1, buf);


		lcfg = malloc(lustre_cfg_len(bufs.lcfg_bufcount,
			      bufs.lcfg_buflen));
		if (lcfg == NULL) {
			fprintf(stderr, "error: allocating lcfg for %s: %s\n",
				jt_cmdname(argv[0]), strerror(-ENOMEM));
			if (rc == 0)
				rc = -ENOMEM;
		} else {
			int rc2;

			lustre_cfg_init(lcfg, LCFG_SET_PARAM, &bufs);
			rc2 = lcfg_mgs_ioctl(argv[0], OBD_DEV_ID, lcfg);
			if (rc2 != 0) {
				fprintf(stderr, "error: executing %s: %s\n",
					jt_cmdname(argv[0]), strerror(errno));
				if (rc == 0)
					rc = rc2;
			}
			free(lcfg);
		}
		if (buf != argv[i])
			free(buf);
	}

	return rc;
}

/* Param set in config log on MGS */
/* conf_param key=value */
/* Note we can actually send mgc conf_params from clients, but currently
 * that's only done for default file striping (see ll_send_mgc_param),
 * and not here. */
/* After removal of a parameter (-d) Lustre will use the default
 * AT NEXT REBOOT, not immediately. */
int jt_lcfg_mgsparam(int argc, char **argv)
{
	int rc;
	int del = 0;
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg;
	char *buf = NULL;

        /* mgs_setparam processes only lctl buf #1 */
        if ((argc > 3) || (argc <= 1))
                return CMD_HELP;

        while ((rc = getopt(argc, argv, "d")) != -1) {
                switch (rc) {
                        case 'd':
                                del = 1;
                                break;
                        default:
                                return CMD_HELP;
                }
        }

        lustre_cfg_bufs_reset(&bufs, NULL);
        if (del) {
                char *ptr;

                /* for delete, make it "<param>=\0" */
                buf = malloc(strlen(argv[optind]) + 2);
		if (buf == NULL) {
			rc = -ENOMEM;
			goto out;
		}
                /* put an '=' on the end in case it doesn't have one */
                sprintf(buf, "%s=", argv[optind]);
                /* then truncate after the first '=' */
                ptr = strchr(buf, '=');
                *(++ptr) = '\0';
                lustre_cfg_bufs_set_string(&bufs, 1, buf);
        } else {
                lustre_cfg_bufs_set_string(&bufs, 1, argv[optind]);
        }

	/* We could put other opcodes here. */
	lcfg = malloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		lustre_cfg_init(lcfg, LCFG_PARAM, &bufs);
		rc = lcfg_mgs_ioctl(argv[0], OBD_DEV_ID, lcfg);
		if (rc < 0)
			rc = -errno;
		free(lcfg);
	}
	if (buf)
		free(buf);
out:
	if (rc < 0) {
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(-rc));
	}

	return rc;
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
static char *
display_name(const char *filename, struct stat *st, struct param_opts *popt)
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
	if (tmp == NULL) {
		tmp = strstr(filename, "/lnet/");
		if (tmp != NULL)
			tmp += strlen("/lnet/");
	} else {
		tmp += strlen("/lustre/");
	}

	/* Allocate return string */
	param_name = strdup(tmp);
	if (param_name == NULL)
		return NULL;

	/* replace '/' with '.' to match conf_param and sysctl */
	for (tmp = strchr(param_name, '/'); tmp != NULL; tmp = strchr(tmp, '/'))
		*tmp = '.';

	/* Append the indicator to entries if needed. */
	if (popt->po_show_type && suffix != NULL) {
		suffix_len = strlen(suffix);

		tmp = realloc(param_name, suffix_len + strlen(param_name) + 1);
		if (tmp != NULL) {
			param_name = tmp;
			strncat(param_name, suffix, suffix_len);
		}
	}

	return param_name;
}

/* Find a character in a length limited string */
/* BEWARE - kernel definition of strnchr has args in different order! */
static char *strnchr(const char *p, char c, size_t n)
{
       if (!p)
               return (0);

       while (n-- > 0) {
               if (*p == c)
                       return ((char *)p);
               p++;
       }
       return (0);
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
static int
clean_path(struct param_opts *popt, char *path)
{
	char *nidstr = NULL;
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
	if (tmp != NULL) {
		char *tail = path + strlen(path);

		while (tmp != path) {
			if (*tmp == '\\') {
				memmove(tmp, tmp + 1, tail - tmp);
				--tail;
			}
			--tmp;
		}
	}

	/* Does this path contain a NID string ? */
	tmp = strchr(path, '@');
	if (tmp != NULL) {
		char *find_nid = strdup(path);
		lnet_nid_t nid;

		if (find_nid == NULL)
			return -ENOMEM;

		/* First we need to chop off rest after nid string.
		 * Since find_nid is a clone of path it better have
		 * '@' */
		tmp = strchr(find_nid, '@');
		tmp = strchr(tmp, '.');
		if (tmp != NULL)
			*tmp = '\0';

		/* Now chop off the front. */
		for (tmp = strchr(find_nid, '.'); tmp != NULL;
		     tmp = strchr(tmp, '.')) {
			/* Remove MGC to make it NID format */
			if (!strncmp(++tmp, "MGC", 3))
				tmp += 3;

			nid = libcfs_str2nid(tmp);
			if (nid != LNET_NID_ANY) {
				nidstr = libcfs_nid2str(nid);
				if (nidstr == NULL)
					return -EINVAL;
				break;
			}
		}
		free(find_nid);
	}

	/* replace param '.' with '/' */
	for (tmp = strchr(path, '.'); tmp != NULL; tmp = strchr(tmp, '.')) {
		*tmp++ = '/';

		/* Remove MGC to make it NID format */
		if (!strncmp(tmp, "MGC", 3))
			tmp += 3;

		/* There exist cases where some of the subdirectories of the
		 * the parameter tree has embedded in its name a NID string.
		 * This means that it is possible that these subdirectories
		 * could have actual '.' in its name. If this is the case we
		 * don't want to blindly replace the '.' with '/'. */
		if (nidstr != NULL) {
			char *match = strstr(tmp, nidstr);

			if (tmp == match)
				tmp += strlen(nidstr);
		}
	}

	return 0;
}

/**
 * The application lctl can perform three operations for lustre
 * tunables. This enum defines those three operations which are
 *
 * 1) LIST_PARAM	- list available tunables
 * 2) GET_PARAM		- report the current setting of a tunable
 * 3) SET_PARAM		- set the tunable to a new value
 */
enum parameter_operation {
	LIST_PARAM,
	GET_PARAM,
	SET_PARAM,
};

char *parameter_opname[] = {
	[LIST_PARAM] = "list_param",
	[GET_PARAM] = "get_param",
	[SET_PARAM] = "set_param",
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
static int
read_param(const char *path, const char *param_name, struct param_opts *popt)
{
	bool display_path = popt->po_show_path;
	long page_size = sysconf(_SC_PAGESIZE);
	int rc = 0;
	char *buf;
	int fd;

	/* Read the contents of file to stdout */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		fprintf(stderr,
			"error: get_param: opening '%s': %s\n",
			path, strerror(errno));
		return rc;
	}

	buf = calloc(1, page_size);
	if (buf == NULL) {
		fprintf(stderr,
			"error: get_param: allocating '%s' buffer: %s\n",
			path, strerror(errno));
		close(fd);
		return -ENOMEM;
	}

	while (1) {
		ssize_t count = read(fd, buf, page_size);

		if (count == 0)
			break;
		if (count < 0) {
			rc = -errno;
			if (errno != EIO) {
				fprintf(stderr, "error: get_param: "
					"reading '%s': %s\n",
					param_name, strerror(errno));
			}
			break;
		}

		/* Print the output in the format path=value if the value does
		 * not contain a new line character and the output can fit in
		 * a single line, else print value on new line */
		if (display_path) {
			bool longbuf;

			longbuf = strnchr(buf, count - 1, '\n') != NULL ||
					  count + strlen(param_name) >= 80;
			printf("%s=%s", param_name, longbuf ? "\n" : buf);

			/* Make sure it doesn't print again while looping */
			display_path = false;

			if (!longbuf)
				continue;
		}

		if (fwrite(buf, 1, count, stdout) != count) {
			rc = -errno;
			fprintf(stderr,
				"error: get_param: write to stdout: %s\n",
				strerror(errno));
			break;
		}
	}
	close(fd);
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
static int
write_param(const char *path, const char *param_name, struct param_opts *popt,
	    const char *value)
{
	int fd, rc = 0;
	ssize_t count;

	if (value == NULL)
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
		fprintf(stderr, "error: set_param: setting %s=%s: "
			"wrote only %zd\n", path, value, count);
	} else if (popt->po_show_path) {
		printf("%s=%s\n", param_name, value);
	}
	close(fd);

	return rc;
}

/**
 * Perform a read, write or just a listing of a parameter
 *
 * \param[in] popt		list,set,get parameter options
 * \param[in] pattern		search filter for the path of the parameter
 * \param[in] value		value to set the parameter if write operation
 * \param[in] mode		what operation to perform with the parameter
 *
 * \retval number of bytes written on success.
 * \retval -errno on error and prints error message.
 */
static int
param_display(struct param_opts *popt, char *pattern, char *value,
	      enum parameter_operation mode)
{
	int dir_count = 0;
	char **dir_cache;
	glob_t paths;
	char *opname = parameter_opname[mode];
	int rc, i;

	rc = cfs_get_param_paths(&paths, "%s", pattern);
	if (rc != 0) {
		rc = -errno;
		if (!popt->po_recursive) {
			fprintf(stderr, "error: %s: param_path '%s': %s\n",
				opname, pattern, strerror(errno));
		}
		return rc;
	}

	dir_cache = calloc(paths.gl_pathc, sizeof(char *));
	if (dir_cache == NULL) {
		rc = -ENOMEM;
		fprintf(stderr,
			"error: %s: allocating '%s' dir_cache[%zd]: %s\n",
			opname, pattern, paths.gl_pathc, strerror(-rc));
		goto out_param;
	}

	for (i = 0; i < paths.gl_pathc; i++) {
		char *param_name = NULL, *tmp;
		char pathname[PATH_MAX];
		struct stat st;
		int rc2;

		if (stat(paths.gl_pathv[i], &st) == -1) {
			fprintf(stderr, "error: %s: stat '%s': %s\n",
				opname, paths.gl_pathv[i], strerror(errno));
			if (rc == 0)
				rc = -errno;
			continue;
		}

		if (popt->po_only_dir && !S_ISDIR(st.st_mode))
			continue;

		param_name = display_name(paths.gl_pathv[i], &st, popt);
		if (param_name == NULL) {
			fprintf(stderr,
				"error: %s: generating name for '%s': %s\n",
				opname, paths.gl_pathv[i], strerror(ENOMEM));
			if (rc == 0)
				rc = -ENOMEM;
			continue;
		}

		/**
		 * For the upstream client the parameter files locations
		 * are split between under both /sys/kernel/debug/lustre
		 * and /sys/fs/lustre. The parameter files containing
		 * small amounts of data, less than a page in size, are
		 * located under /sys/fs/lustre and in the case of large
		 * parameter data files, think stats for example, are
		 * located in the debugfs tree. Since the files are split
		 * across two trees the directories are often duplicated
		 * which means these directories are listed twice which
		 * leads to duplicate output to the user. To avoid scanning
		 * a directory twice we have to cache any directory and
		 * check if a search has been requested twice.
		 */
		if (S_ISDIR(st.st_mode)) {
			int j;

			for (j = 0; j < dir_count; j++) {
				if (!strcmp(dir_cache[j], param_name))
					break;
			}
			if (j != dir_count) {
				free(param_name);
				param_name = NULL;
				continue;
			}
			dir_cache[dir_count++] = strdup(param_name);
		}

		switch (mode) {
		case GET_PARAM:
			/* Read the contents of file to stdout */
			if (S_ISREG(st.st_mode))
				read_param(paths.gl_pathv[i], param_name, popt);
			break;
		case SET_PARAM:
			if (S_ISREG(st.st_mode)) {
				rc2 = write_param(paths.gl_pathv[i],
						  param_name, popt, value);
				if (rc2 < 0 && rc == 0)
					rc = rc2;
			}
			break;
		case LIST_PARAM:
			if (popt->po_show_path)
				printf("%s\n", param_name);
			break;
		}

		/* Only directories are searched recursively if
		 * requested by the user */
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
			if (rc == 0)
				rc = rc2;
			continue;
		}

		/* Use param_name to grab subdirectory tree from full path */
		tmp = strstr(paths.gl_pathv[i], param_name);

		/* cleanup paramname now that we are done with it */
		free(param_name);
		param_name = NULL;

		/* Shouldn't happen but just in case */
		if (tmp == NULL) {
			if (rc == 0)
				rc = -EINVAL;
			continue;
		}

		rc2 = snprintf(pathname, sizeof(pathname), "%s/*", tmp);
		if (rc2 < 0) {
			/* snprintf() should never an error, and if it does
			 * there isn't much point trying to use fprintf() */
			continue;
		}
		if (rc2 >= sizeof(pathname)) {
			fprintf(stderr, "error: %s: overflow processing '%s'\n",
				opname, pathname);
			if (rc == 0)
				rc = -EINVAL;
			continue;
		}

		rc2 = param_display(popt, pathname, value, mode);
		if (rc2 != 0 && rc2 != -ENOENT) {
			/* errors will be printed by param_display() */
			if (rc == 0)
				rc = rc2;
			continue;
		}
	}

	for (i = 0; i < dir_count; i++)
		free(dir_cache[i]);
	free(dir_cache);
out_param:
	cfs_free_param_data(&paths);
	return rc;
}

static int listparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
	int ch;

	popt->po_show_path = 1;
	popt->po_only_path = 1;

	while ((ch = getopt(argc, argv, "FRD")) != -1) {
		switch (ch) {
		case 'F':
			popt->po_show_type = 1;
			break;
		case 'R':
			popt->po_recursive = 1;
			break;
		case 'D':
			popt->po_only_dir = 1;
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

		rc2 = param_display(&popt, path, NULL, LIST_PARAM);
		if (rc2 < 0) {
			fprintf(stderr, "error: %s: listing '%s': %s\n",
				jt_cmdname(argv[0]), path, strerror(-rc2));
			if (rc == 0)
				rc = rc2;
			continue;
		}
	}

	return rc;
}

static int getparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
	int ch;

	popt->po_show_path = 1;

	while ((ch = getopt(argc, argv, "FnNR")) != -1) {
		switch (ch) {
		case 'F':
			popt->po_show_type = 1;
			break;
		case 'n':
			popt->po_show_path = 0;
			break;
		case 'N':
			popt->po_only_path = 1;
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

int jt_lcfg_getparam(int argc, char **argv)
{
	int rc = 0, index, i;
	struct param_opts popt;
	char *path;

	memset(&popt, 0, sizeof(popt));
	index = getparam_cmdline(argc, argv, &popt);
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

		rc2 = param_display(&popt, path, NULL,
				   popt.po_only_path ? LIST_PARAM : GET_PARAM);
		if (rc2 < 0) {
			if (rc == 0)
				rc = rc2;
			continue;
		}
	}

	return rc;
}

/**
 * Output information about nodemaps.
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * [list|nodemap_name|all]	\a list will list all nodemaps (default).
 *				Specifying a \a nodemap_name will
 *				display info about that specific nodemap.
 *				\a all will display info for all nodemaps.
 * \retval			0 on success
 */
int jt_nodemap_info(int argc, char **argv)
{
	const char		usage_str[] = "usage: nodemap_info "
					      "[list|nodemap_name|all]\n";
	struct param_opts	popt;
	int			rc = 0;

	memset(&popt, 0, sizeof(popt));
	popt.po_show_path = 1;

	if (argc > 2) {
		fprintf(stderr, usage_str);
		return -1;
	}

	if (argc == 1 || strcmp("list", argv[1]) == 0) {
		popt.po_only_path = 1;
		popt.po_only_dir = 1;
		rc = param_display(&popt, "nodemap/*", NULL, LIST_PARAM);
	} else if (strcmp("all", argv[1]) == 0) {
		rc = param_display(&popt, "nodemap/*/*", NULL, LIST_PARAM);
	} else {
		char	pattern[PATH_MAX];

		snprintf(pattern, sizeof(pattern), "nodemap/%s/*", argv[1]);
		rc = param_display(&popt, pattern, NULL, LIST_PARAM);
		if (rc == -ESRCH)
			fprintf(stderr, "error: nodemap_info: cannot find "
					"nodemap %s\n", argv[1]);
	}
	return rc;
}

static int setparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
        int ch;

        popt->po_show_path = 1;
        popt->po_only_path = 0;
        popt->po_show_type = 0;
        popt->po_recursive = 0;
	popt->po_params2 = 0;
	popt->po_delete = 0;

	while ((ch = getopt(argc, argv, "nPd")) != -1) {
                switch (ch) {
                case 'n':
                        popt->po_show_path = 0;
                        break;
		case 'P':
			popt->po_params2 = 1;
			break;
		case 'd':
			popt->po_delete = 1;
			break;
                default:
                        return -1;
                }
        }
        return optind;
}

int jt_lcfg_setparam(int argc, char **argv)
{
	int rc = 0, index, i;
	struct param_opts popt;
	char *path = NULL, *value = NULL;

	memset(&popt, 0, sizeof(popt));
	index = setparam_cmdline(argc, argv, &popt);
	if (index < 0 || index >= argc)
		return CMD_HELP;

	if (popt.po_params2)
		/* We can't delete parameters that were
		 * set with old conf_param interface */
		return jt_lcfg_mgsparam2(argc, argv, &popt);

	for (i = index; i < argc; i++) {
		int rc2;
		path = NULL;

		value = strchr(argv[i], '=');
		if (value != NULL) {
			/* format: set_param a=b */
			*value = '\0';
			value++;
			path = argv[i];
			if (*value == '\0') {
				fprintf(stderr,
					"error: %s: setting %s: no value\n",
					jt_cmdname(argv[0]), path);
				if (rc == 0)
					rc = -EINVAL;
				continue;
			}
		} else {
			/* format: set_param a b */
			path = argv[i];
			i++;
			if (i >= argc) {
				fprintf(stderr,
					"error: %s: setting %s: no value\n",
					jt_cmdname(argv[0]), path);
				if (rc == 0)
					rc = -EINVAL;
				break;
			} else {
				value = argv[i];
			}
		}

		rc2 = clean_path(&popt, path);
		if (rc2 < 0) {
			fprintf(stderr, "error: %s: cleaning %s: %s\n",
				jt_cmdname(argv[0]), path, strerror(-rc2));
			if (rc == 0)
				rc = rc2;
			continue;
		}

		rc2 = param_display(&popt, path, value, SET_PARAM);
		if (rc == 0)
			rc = rc2;
	}

	return rc;
}
