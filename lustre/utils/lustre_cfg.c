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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
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

#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <glob.h>

#include <libcfs/libcfs.h>
#include <lnet/nidstr.h>
#include <lustre_cfg.h>
#include <lustre/lustre_idl.h>
#include <lustre/lustre_build_version.h>

#include <unistd.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>


#include "obdctl.h"
#include <lnet/lnetctl.h>
#include <libcfs/libcfsutil.h>
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

int jt_lcfg_attach(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        if (argc != 4)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, NULL);

        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);
        lustre_cfg_bufs_set_string(&bufs, 0, argv[2]);
        lustre_cfg_bufs_set_string(&bufs, 2, argv[3]);

        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (rc < 0) {
                fprintf(stderr, "error: %s: LCFG_ATTACH %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));
        } else {
                lcfg_set_devname(argv[2]);
        }

        return rc;
}

int jt_lcfg_setup(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int i;
        int rc;

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

        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_detach(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'device name' to set the "
                        "device name for config commands.\n",
                        jt_cmdname(argv[0]));
                return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        if (argc != 1)
                return CMD_HELP;

        lcfg = lustre_cfg_new(LCFG_DETACH, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_cleanup(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        char force = 'F';
        char failover = 'A';
        char flags[3] = { 0 };
        int flag_cnt = 0, n;
        int rc;

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

        lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

static
int do_add_uuid(char * func, char *uuid, lnet_nid_t nid)
{
	int rc;
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg;

	lustre_cfg_bufs_reset(&bufs, lcfg_devname);
	if (uuid != NULL)
		lustre_cfg_bufs_set_string(&bufs, 1, uuid);

        lcfg = lustre_cfg_new(LCFG_ADD_UUID, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		lcfg->lcfg_nid = nid;

		rc = lcfg_ioctl(func, OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
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
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        if (argc != 2) {
                fprintf(stderr, "usage: %s <uuid>\n", argv[0]);
                return 0;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);
        if (strcmp (argv[1], "_all_"))
                lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

        lcfg = lustre_cfg_new(LCFG_DEL_UUID, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_DEL_UUID failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_lcfg_del_mount_option(int argc, char **argv)
{
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        if (argc != 2)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        /* profile name */
        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

        lcfg = lustre_cfg_new(LCFG_DEL_MOUNTOPT, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
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
        lcfg = lustre_cfg_new(LCFG_SET_TIMEOUT, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		lcfg->lcfg_num = atoi(argv[1]);

		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
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

        lcfg = lustre_cfg_new(LCFG_ADD_CONN, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		lcfg->lcfg_num = priority;

		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
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
        struct lustre_cfg *lcfg;
        int rc;

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

        lcfg = lustre_cfg_new(LCFG_DEL_MOUNTOPT, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }

        return rc;
}

/* Param set locally, directly on target */
int jt_lcfg_param(int argc, char **argv)
{
        int i, rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        if (argc >= LUSTRE_CFG_MAX_BUFCOUNT)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, NULL);

        for (i = 1; i < argc; i++) {
                lustre_cfg_bufs_set_string(&bufs, i, argv[i]);
        }

        lcfg = lustre_cfg_new(LCFG_PARAM, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
}

struct param_opts {
	unsigned int po_only_path:1;
	unsigned int po_show_path:1;
	unsigned int po_show_type:1;
	unsigned int po_recursive:1;
	unsigned int po_params2:1;
	unsigned int po_delete:1;
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
			sprintf(buf, "%s=", argv[i]);
		} else {
			buf = argv[i];
		}
		lustre_cfg_bufs_set_string(&bufs, 1, buf);

		lcfg = lustre_cfg_new(LCFG_SET_PARAM, &bufs);
		if (lcfg == NULL) {
			fprintf(stderr, "error: allocating lcfg for %s: %s\n",
				jt_cmdname(argv[0]), strerror(-ENOMEM));
			if (rc == 0)
				rc = -ENOMEM;
		} else {
			int rc2 = lcfg_mgs_ioctl(argv[0], OBD_DEV_ID, lcfg);
			if (rc2 != 0) {
				fprintf(stderr, "error: executing %s: %s\n",
					jt_cmdname(argv[0]), strerror(errno));
				if (rc == 0)
					rc = rc2;
			}
			lustre_cfg_free(lcfg);
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

#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 7, 53, 0)
	fprintf(stderr, "warning: 'lctl conf_param' is deprecated, "
		"use 'lctl set_param -P' instead\n");
#endif

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
        lcfg = lustre_cfg_new(LCFG_PARAM, &bufs);
	if (lcfg == NULL) {
		rc = -ENOMEM;
	} else {
		rc = lcfg_mgs_ioctl(argv[0], OBD_DEV_ID, lcfg);
		lustre_cfg_free(lcfg);
	}
        if (buf)
                free(buf);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }

        return rc;
}

/* Display the path in the same format as sysctl
 * For eg. obdfilter.lustre-OST0000.stats */
static char *
display_name(char *filename, size_t filename_size, bool po_show_type)
{
	struct stat st;
	char *tmp;
	char *suffix = NULL;

	if (po_show_type) {
		if (lstat(filename, &st) == -1)
			return NULL;

		if (S_ISDIR(st.st_mode))
			suffix = "/";
		else if (S_ISLNK(st.st_mode))
			suffix = "@";
		else if (st.st_mode & S_IWUSR)
			suffix = "=";
	}

	filename += strlen("/proc/");
	if (strncmp(filename, "fs/", strlen("fs/")) == 0)
		filename += strlen("fs/");
	else
		filename += strlen("sys/");

	if (strncmp(filename, "lustre/", strlen("lustre/")) == 0)
		filename += strlen("lustre/");
	else if (strncmp(filename, "lnet/", strlen("lnet/")) == 0)
		filename += strlen("lnet/");

	/* replace '/' with '.' to match conf_param and sysctl */
	tmp = filename;
	while ((tmp = strchr(tmp, '/')) != NULL)
		*tmp = '.';

	/* Append the indicator to entries.  We know there is enough space
	 * for the suffix, since the path prefix was deleted. */
	if (po_show_type && suffix != NULL)
		strncat(filename, suffix, filename_size);

	return filename;
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

static char *globerrstr(int glob_rc)
{
        switch(glob_rc) {
        case GLOB_NOSPACE:
                return "Out of memory";
        case GLOB_ABORTED:
                return "Read error";
        case GLOB_NOMATCH:
                return "Found no match";
        }
        return "Unknown error";
}

static void clean_path(char *path)
{
        char *tmp;

        /* If the input is in form Eg. obdfilter.*.stats */
        if (strchr(path, '.')) {
                tmp = path;
                while (*tmp != '\0') {
                        if ((*tmp == '.') &&
                            (tmp != path) && (*(tmp - 1) != '\\'))
                                *tmp = '/';
                        tmp ++;
                }
        }
        /* get rid of '\', glob doesn't like it */
        if ((tmp = strrchr(path, '\\')) != NULL) {
                char *tail = path + strlen(path);
                while (tmp != path) {
                        if (*tmp == '\\') {
                                memmove(tmp, tmp + 1, tail - tmp);
                                --tail;
                        }
                        --tmp;
                }
        }
}

/* Take a parameter name and turn it into a pathname glob.
 * Disallow relative pathnames to avoid potential problems. */
static int lprocfs_param_pattern(const char *pattern, char *buf, size_t bufsize)
{
	int rc;

	rc = snprintf(buf, bufsize, "/proc/{fs,sys}/{lnet,lustre}/%s", pattern);
	if (rc < 0) {
		rc = -errno;
	} else if (rc >= bufsize) {
		fprintf(stderr, "error: parameter '%s' too long\n", pattern);
		rc = -E2BIG;
	}

	return rc;
}

static int listparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
        int ch;

        popt->po_show_path = 1;
        popt->po_only_path = 1;
        popt->po_show_type = 0;
        popt->po_recursive = 0;

        while ((ch = getopt(argc, argv, "FR")) != -1) {
                switch (ch) {
                case 'F':
                        popt->po_show_type = 1;
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

static int listparam_display(struct param_opts *popt, char *pattern)
{
	glob_t glob_info;
	char filename[PATH_MAX + 1];    /* extra 1 byte for file type */
	int rc;
	int i;

	rc = lprocfs_param_pattern(pattern, filename, sizeof(filename));
	if (rc < 0)
		return rc;

	rc = glob(filename, GLOB_BRACE | (popt->po_recursive ? GLOB_MARK : 0),
		  NULL, &glob_info);
	if (rc) {
		fprintf(stderr, "error: list_param: %s: %s\n",
			pattern, globerrstr(rc));
		return -ESRCH;
	}

	for (i = 0; i  < glob_info.gl_pathc; i++) {
		int len = sizeof(filename), last;
		char *valuename = NULL;

		/* Trailing '/' will indicate recursion into directory */
		last = strlen(glob_info.gl_pathv[i]) - 1;

		/* Remove trailing '/' or it will be converted to '.' */
		if (last > 0 && glob_info.gl_pathv[i][last] == '/')
			glob_info.gl_pathv[i][last] = '\0';
		else
			last = 0;
		strlcpy(filename, glob_info.gl_pathv[i], len);
		valuename = display_name(filename, len, popt->po_show_type);
		if (valuename)
			printf("%s\n", valuename);
		if (last) {
			strlcpy(filename, glob_info.gl_pathv[i], len);
			strlcat(filename, "/*", len);
			listparam_display(popt, filename);
		}
	}

	globfree(&glob_info);
	return rc;
}

int jt_lcfg_listparam(int argc, char **argv)
{
	int rc = 0, i;
	struct param_opts popt;
	char *pattern;

	rc = listparam_cmdline(argc, argv, &popt);
	if (rc == argc && popt.po_recursive) {
		rc--;           /* we know at least "-R" is a parameter */
		argv[rc] = "*";
	} else if (rc < 0 || rc >= argc) {
		return CMD_HELP;
	}

	for (i = rc; i < argc; i++) {
		pattern = argv[i];

		clean_path(pattern);

		rc = listparam_display(&popt, pattern);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int getparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
	int ch;

	popt->po_show_path = 1;
	popt->po_only_path = 0;
	popt->po_show_type = 0;
	popt->po_recursive = 0;

	while ((ch = getopt(argc, argv, "nNF")) != -1) {
		switch (ch) {
		case 'N':
			popt->po_only_path = 1;
			break;
		case 'n':
			popt->po_show_path = 0;
			break;
		case 'F':
			popt->po_show_type = 1;
			break;
		default:
			return -1;
		}
	}

	return optind;
}

static int getparam_display(struct param_opts *popt, char *pattern)
{
	glob_t glob_info;
	char filename[PATH_MAX + 1];    /* extra 1 byte for file type */
	char *buf;
	int rc;
	int fd;
	int i;

	rc = lprocfs_param_pattern(pattern, filename, sizeof(filename));
	if (rc < 0)
		return rc;

	rc = glob(filename, GLOB_BRACE, NULL, &glob_info);
	if (rc) {
		fprintf(stderr, "error: get_param: %s: %s\n",
			pattern, globerrstr(rc));
		return -ESRCH;
	}

	buf = malloc(PAGE_CACHE_SIZE);
	if (buf == NULL)
		return -ENOMEM;

	for (i = 0; i  < glob_info.gl_pathc; i++) {
		char *valuename = NULL;

		memset(buf, 0, PAGE_CACHE_SIZE);
		/* As listparam_display is used to show param name (with type),
		 * here "if (only_path)" is ignored.*/
		if (popt->po_show_path) {
			if (strlen(glob_info.gl_pathv[i]) >
			    sizeof(filename) - 1) {
				free(buf);
				return -E2BIG;
			}
			strncpy(filename, glob_info.gl_pathv[i],
				sizeof(filename));
			valuename = display_name(filename, sizeof(filename),
						 false);
		}

                /* Write the contents of file to stdout */
                fd = open(glob_info.gl_pathv[i], O_RDONLY);
                if (fd < 0) {
                        fprintf(stderr,
                                "error: get_param: opening('%s') failed: %s\n",
                                glob_info.gl_pathv[i], strerror(errno));
                        continue;
                }

		do {
			rc = read(fd, buf, PAGE_CACHE_SIZE);
			if (rc == 0)
				break;
			if (rc < 0) {
				fprintf(stderr, "error: get_param: "
					"read('%s') failed: %s\n",
					glob_info.gl_pathv[i], strerror(errno));
				break;
			}
			/* Print the output in the format path=value if the
			 * value contains no new line character or can be
			 * occupied in a line, else print value on new line */
			if (valuename && popt->po_show_path) {
				int longbuf;

				longbuf = strnchr(buf, rc - 1, '\n') != NULL ||
					rc + strlen(valuename) >= 80;
				printf("%s=%s", valuename,
				       longbuf ? "\n" : buf);
                                valuename = NULL;
                                if (!longbuf)
                                        continue;
                                fflush(stdout);
                        }
                        rc = write(fileno(stdout), buf, rc);
                        if (rc < 0) {
                                fprintf(stderr, "error: get_param: "
                                        "write to stdout failed: %s\n",
                                        strerror(errno));
                                break;
                        }
                } while (1);
                close(fd);
        }

        globfree(&glob_info);
        free(buf);
        return rc;
}

int jt_lcfg_getparam(int argc, char **argv)
{
	int rc = 0, i;
	struct param_opts popt;
	char *param;

	rc = getparam_cmdline(argc, argv, &popt);
	if (rc < 0 || rc >= argc)
		return CMD_HELP;

	for (i = rc, rc = 0; i < argc; i++) {
		int rc2;

		param = argv[i];

		clean_path(param);

		if (popt.po_only_path)
			rc2 = listparam_display(&popt, param);
		else
			rc2 = getparam_display(&popt, param);
		if (rc2 < 0 && rc == 0)
			rc = rc2;
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

static int setparam_display(struct param_opts *popt, char *pattern, char *value)
{
	glob_t glob_info;
	char filename[PATH_MAX + 1];    /* extra 1 byte for file type */
	int rc;
	int fd;
	int i;

	rc = lprocfs_param_pattern(pattern, filename, sizeof(filename));
	if (rc < 0)
		return rc;

	rc = glob(filename, GLOB_BRACE, NULL, &glob_info);
	if (rc) {
		fprintf(stderr, "error: set_param: %s: %s\n",
			pattern, globerrstr(rc));
		return -ESRCH;
	}
	for (i = 0; i  < glob_info.gl_pathc; i++) {
		char *valuename = NULL;

		if (popt->po_show_path) {
			if (strlen(glob_info.gl_pathv[i]) > sizeof(filename)-1)
				return -E2BIG;
			strncpy(filename, glob_info.gl_pathv[i],
				sizeof(filename));
			valuename = display_name(filename, sizeof(filename),
						 false);
			if (valuename)
				printf("%s=%s\n", valuename, value);
		}
		/* Write the new value to the file */
		fd = open(glob_info.gl_pathv[i], O_WRONLY);
		if (fd >= 0) {
			int rc2;

			rc2 = write(fd, value, strlen(value));
			if (rc2 < 0) {
				if (rc == 0)
					rc = -errno;
				fprintf(stderr, "error: set_param: setting "
					"%s=%s: %s\n", glob_info.gl_pathv[i],
					value, strerror(errno));
			}
			close(fd);
		} else {
			if (rc == 0)
				rc = -errno;
			fprintf(stderr, "error: set_param: opening %s: %s\n",
				strerror(errno), glob_info.gl_pathv[i]);
		}
	}

	globfree(&glob_info);
	return rc;
}

int jt_lcfg_setparam(int argc, char **argv)
{
	int rc = 0, i;
	struct param_opts popt;
	char *pattern = NULL, *value = NULL;

	rc = setparam_cmdline(argc, argv, &popt);
	if (rc < 0 || rc >= argc)
		return CMD_HELP;

	if (popt.po_params2)
		/* We can't delete parameters that were
		 * set with old conf_param interface */
		return jt_lcfg_mgsparam2(argc, argv, &popt);

	for (i = rc, rc = 0; i < argc; i++) {
		int rc2;

		value = strchr(argv[i], '=');
		if (value != NULL) {
			/* format: set_param a=b */
			*value = '\0';
			value++;
			pattern = argv[i];
			if (*value == '\0')
				break;
		} else {
			/* format: set_param a b */
			if (pattern == NULL) {
				pattern = argv[i];
				continue;
			} else {
				value = argv[i];
			}
		}

		clean_path(pattern);

		rc2 = setparam_display(&popt, pattern, value);
		pattern = NULL;
		value = NULL;
		if (rc2 < 0 && rc == 0)
			rc = rc2;
	}
	if (pattern != NULL && (value == NULL || *value == '\0'))
		fprintf(stderr, "error: %s: setting %s=: %s\n",
			jt_cmdname(argv[0]), pattern, strerror(rc = EINVAL));

	return rc;
}
