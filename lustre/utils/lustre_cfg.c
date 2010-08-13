/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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

#ifndef __KERNEL__
#include <liblustre.h>
#endif
#include <lustre_lib.h>
#include <lustre_cfg.h>
#include <lustre/lustre_idl.h>
#include <lustre_dlm.h>
#include <obd.h>          /* for struct lov_stripe_md */
#include <obd_lov.h>
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
        if (name) {
                if (lcfg_devname)
                        free(lcfg_devname);
                /* quietly strip the unnecessary '$' */
                if (*name == '$' || *name == '%')
                        name++;
                if (isdigit(*name)) {
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
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: LCFG_ATTACH %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));
        } else if (argc == 3) {
                char name[1024];

                lcfg_set_devname(argv[2]);
                if (strlen(argv[2]) > 128) {
                        printf("Name too long to set environment\n");
                        return -EINVAL;
                }
                snprintf(name, 512, "LUSTRE_DEV_%s", argv[2]);
                rc = setenv(name, argv[1], 1);
                if (rc) {
                        printf("error setting env variable %s\n", name);
                }
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
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
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
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
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
                        fprintf(stderr, "unknown option: %s", argv[n]);
                        return CMD_HELP;
                }
        }

        if (flag_cnt) {
                lustre_cfg_bufs_set_string(&bufs, 1, flags);
        }

        lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
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
        if (uuid)
                lustre_cfg_bufs_set_string(&bufs, 1, uuid);

        lcfg = lustre_cfg_new(LCFG_ADD_UUID, &bufs);
        lcfg->lcfg_nid = nid;
        /* Poison NAL -- pre 1.4.6 will LASSERT on 0 NAL, this way it
           doesn't work without crashing (bz 10130) */
        lcfg->lcfg_nal = 0x5a;

#if 0
        fprintf(stderr, "adding\tnid: %d\tuuid: %s\n",
               lcfg->lcfg_nid, uuid);
#endif
        rc = lcfg_ioctl(func, OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_ADD_UUID failed: %s\n",
                        strerror(errno));
                return -1;
        }

        printf ("Added uuid %s: %s\n", uuid, libcfs_nid2str(nid));
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

int obd_add_uuid(char *uuid, lnet_nid_t nid)
{
        return do_add_uuid("obd_add_uuid", uuid, nid);
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
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
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
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
}

int jt_lcfg_set_timeout(int argc, char **argv)
{
        fprintf(stderr, "%s has been deprecated. Use conf_param instead.\n"
                "e.g. conf_param sys.testfs.obd_timeout=50\n",
                jt_cmdname(argv[0]));
        return CMD_HELP;
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
        lcfg->lcfg_num = priority;

        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free (lcfg);
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

        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
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

        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
}

/* Could this element of a parameter be an obd type?
 * returns boolean
 */
static int element_could_be_obd(char *el)
{
        char *ptr = el;

        /* Rather than try to enumerate known obd types and risk
         * becoming stale, I'm just going to check for no wacky chars */
        while ((*ptr != '\0') && (*ptr != '.')) {
                if (!isalpha(*ptr++))
                        return 0;
        }
        return 1;
}

/* Convert set_param into conf_param format.  Examples of differences:
 * conf_param testfs.sys.at_max=1200
 * set_param at_max=1200   -- no fsname, but conf_param needs a valid one
 * conf_param lustre.llite.max_read_ahead_mb=16
 * set_param llite.lustre-ffff81003f157000.max_read_ahead_mb=16
 * conf_param lustre-MDT0000.lov.stripesize=2M
 * set_param lov.lustre-MDT0000-mdtlov.stripesize=2M
 * set_param lov.lustre-clilov-ffff81003f157000.stripesize=2M  --  clilov
 * conf_param lustre-OST0001.osc.active=0
 * set_param osc.lustre-OST0000-osc-ffff81003f157000.active=0
 * conf_param lustre-OST0000.osc.max_dirty_mb=29.15
 * set_param osc.lustre-OST0000-osc-ffff81003f157000.max_dirty_mb=16
 * conf_param lustre-OST0001.ost.client_cache_seconds=15
 * set_param obdfilter.lustre-OST0001.client_cache_seconds=15  --  obdfilter/ost
 * conf_param testfs-OST0000.failover.node=1.2.3.4@tcp1
 * no proc, but osc.testfs-OST0000.failover.node -- would be appropriate
 */
static int rearrange_setparam_syntax(char *in)
{
        char buf[MGS_PARAM_MAXLEN];
        char *element[3];
        int elements = 0;
        int dev, obd;
        char *ptr, *value;
        __u32 index;
        int type;
        int rc;

        value = strchr(in, '=');
        if (!value)
                return -EINVAL;
        *value = '\0';

        /* Separate elements 0.1.all_the_rest */
        element[elements++] = in;
        for (ptr = in; *ptr != '\0' && (elements < 3); ptr++) {
                if (*ptr == '.') {
                        *ptr = '\0';
                        element[elements++] = ++ptr;
                }
        }
        if (elements != 3) {
                fprintf(stderr, "error: Parameter format is "
                        "<obd>.<fsname|devname>.<param>.\n"
                        "Wildcards are not supported. Examples:\n"
                        "sys.testfs.at_max=1200\n"
                        "llite.testfs.max_read_ahead_mb=16\n"
                        "lov.testfs-MDT0000.qos_threshold_rr=30\n"
                        "mdc.testfs-MDT0000.max_rpcs_in_flight=6\n"
                        "osc.testfs-OST0000.active=0\n"
                        "osc.testfs-OST0000.max_dirty_mb=16\n"
                        "obdfilter.testfs-OST0001.client_cache_seconds=15\n"
                        "osc.testfs-OST0000.failover.node=1.2.3.4@tcp\n\n"
                        );
                return -EINVAL;
        }

        /* e.g. testfs-OST003f-junk.ost.param */
        rc = libcfs_str2server(element[0], &type, &index, &ptr);
        if (rc == 0) {
                *ptr = '\0'; /* trunc the junk */
                goto out0;
        }
        /* e.g. ost.testfs-OST003f-junk.param */
        rc = libcfs_str2server(element[1], &type, &index, &ptr);
        if (rc == 0) {
                *ptr = '\0';
                goto out1;
        }

        /* llite.fsname.param or fsname.obd.param */
        if (!element_could_be_obd(element[0]) &&
            element_could_be_obd(element[1]))
                /* fsname-junk.obd.param */
                goto out0;
        if (element_could_be_obd(element[0]) &&
            !element_could_be_obd(element[1]))
                /* obd.fsname-junk.param */
                goto out1;
        if (!element_could_be_obd(element[0]) &&
            !element_could_be_obd(element[1])) {
                fprintf(stderr, "error: Parameter format is "
                        "<obd>.<fsname|devname>.<param>\n");
                return -EINVAL;
        }
        /* Either element could be obd.  Assume set_param syntax
         * (obd.fsname.param) */
        goto out1;

out0:
        dev = 0;
        obd = 1;
        goto out;
out1:
        dev = 1;
        obd = 0;
out:
        /* Don't worry Mom, we'll check it out */
        if (strncmp(element[2], "failover", 8) != 0) { /* no proc for this */
                char *argt[3];

                if (strcmp(element[obd], "sys") == 0)
                        sprintf(buf, "%s", element[2]);
                else
                        sprintf(buf, "%s.%s*.%s", element[obd], element[dev],
                                element[2]);
                argt[1] = "-q";
                argt[2] = buf;
                rc = jt_lcfg_listparam(3, argt);
                if (rc)
                        fprintf(stderr, "warning: can't find local param '%s'\n"
                                "(but that service may not be running locally)."
                                "\n", buf);
        }

        /* s/obdfilter/ost/ */
        if (strcmp(element[obd], "obdfilter") == 0)
                sprintf(element[obd], "ost");

        sprintf(buf, "%s.%s.%s=%s", element[dev], element[obd],
                element[2], value + 1);
        strcpy(in, buf);

        return 0;
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
        char buf[MGS_PARAM_MAXLEN];

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

        if (del) {
                char *ptr;

                /* for delete, make it "<param>=\0" */
                /* put an '=' on the end in case it doesn't have one */
                sprintf(buf, "%s=", argv[optind]);
                /* then truncate after the first '=' */
                ptr = strchr(buf, '=');
                *(++ptr) = '\0';
        } else {
                sprintf(buf, "%s", argv[optind]);
        }

        rc = rearrange_setparam_syntax(buf);
        if (rc)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, NULL);
        lustre_cfg_bufs_set_string(&bufs, 1, buf);

        /* We could put other opcodes here. */
        lcfg = lustre_cfg_new(LCFG_PARAM, &bufs);

        rc = lcfg_mgs_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
                if (rc == ENOENT) {
                        char *argt[3];
                        fprintf(stderr, "Does this filesystem/target exist on "
                                "the MGS?\n");
                        printf("Known targets:\n");
                        sprintf(buf, "mgs.MGS.live.*");
                        argt[1] = "-n";
                        argt[2] = buf;
                        jt_lcfg_getparam(3, argt);
                }
        }

        return rc;
}

/* Display the path in the same format as sysctl
 * For eg. obdfilter.lustre-OST0000.stats */
static char *display_name(char *filename, int show_type)
{
        char *tmp;
        struct stat st;

        if (show_type) {
                if (lstat(filename, &st) < 0)
                        return NULL;
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

        /* append the indicator to entries */
        if (show_type) {
                if (S_ISDIR(st.st_mode))
                        strcat(filename, "/");
                else if (S_ISLNK(st.st_mode))
                        strcat(filename, "@");
                else if (st.st_mode & S_IWUSR)
                        strcat(filename, "=");
        }

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

struct param_opts {
        int only_path:1;
        int show_path:1;
        int show_type:1;
        int recursive:1;
};

static int listparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
        int ch;

        popt->show_path = 1;
        popt->only_path = 1;
        popt->show_type = 0;
        popt->recursive = 0;

        while ((ch = getopt(argc, argv, "FRq")) != -1) {
                switch (ch) {
                case 'F':
                        popt->show_type = 1;
                        break;
                case 'R':
                        popt->recursive = 1;
                        break;
                case 'q':
                        popt->show_path = 0;
                        break;
                default:
                        return -1;
                }
        }

        return optind;
}

static int listparam_display(struct param_opts *popt, char *pattern)
{
        int rc;
        int i;
        glob_t glob_info;
        char filename[PATH_MAX + 1];    /* extra 1 byte for file type */

        rc = glob(pattern, GLOB_BRACE | (popt->recursive ? GLOB_MARK : 0),
                  NULL, &glob_info);
        if (rc) {
                if (popt->show_path) /* when quiet, don't show errors */
                        fprintf(stderr, "error: list_param: %s: %s\n",
                                pattern, globerrstr(rc));
                return -ESRCH;
        }

        if (popt->show_path) {
                for (i = 0; i  < glob_info.gl_pathc; i++) {
                        char *valuename = NULL;
                        int last;

                        /* Trailing '/' will indicate recursion into directory */
                        last = strlen(glob_info.gl_pathv[i]) - 1;

                        /* Remove trailing '/' or it will be converted to '.' */
                        if (last > 0 && glob_info.gl_pathv[i][last] == '/')
                                glob_info.gl_pathv[i][last] = '\0';
                        else
                                last = 0;
                        strcpy(filename, glob_info.gl_pathv[i]);
                        valuename = display_name(filename, popt->show_type);
                        if (valuename)
                                printf("%s\n", valuename);
                        if (last) {
                                strcpy(filename, glob_info.gl_pathv[i]);
                                strcat(filename, "/*");
                                listparam_display(popt, filename);
                        }
                }
        }

        globfree(&glob_info);
        return rc;
}

int jt_lcfg_listparam(int argc, char **argv)
{
        int fp;
        int rc = 0, i;
        struct param_opts popt;
        char pattern[PATH_MAX];
        char *path;

        rc = listparam_cmdline(argc, argv, &popt);
        if (rc == argc && popt.recursive) {
                rc--;           /* we know at least "-R" is a parameter */
                argv[rc] = "*";
        } else if (rc < 0 || rc >= argc) {
                return CMD_HELP;
        }

        for (i = rc; i < argc; i++) {
                path = argv[i];

                clean_path(path);

                /* If the entire path is specified as input */
                fp = open(path, O_RDONLY);
                if (fp < 0) {
                        snprintf(pattern, PATH_MAX, "/proc/{fs,sys}/{lnet,lustre}/%s",
                                 path);
                } else {
                        strcpy(pattern, path);
                        close(fp);
                }

                rc = listparam_display(&popt, pattern);
                if (rc < 0)
                        return rc;
        }

        return 0;
}

static int getparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
        int ch;

        popt->show_path = 1;
        popt->only_path = 0;
        popt->show_type = 0;
        popt->recursive = 0;

        while ((ch = getopt(argc, argv, "nNF")) != -1) {
                switch (ch) {
                case 'N':
                        popt->only_path = 1;
                        break;
                case 'n':
                        popt->show_path = 0;
                case 'F':
                        popt->show_type = 1;
                        break;
                default:
                        return -1;
                }
        }

        return optind;
}

static int getparam_display(struct param_opts *popt, char *pattern)
{
        int rc;
        int fd;
        int i;
        char *buf;
        glob_t glob_info;
        char filename[PATH_MAX + 1];    /* extra 1 byte for file type */

        rc = glob(pattern, GLOB_BRACE, NULL, &glob_info);
        if (rc) {
                fprintf(stderr, "error: get_param: %s: %s\n",
                        pattern, globerrstr(rc));
                return -ESRCH;
        }

        buf = malloc(CFS_PAGE_SIZE);
        for (i = 0; i  < glob_info.gl_pathc; i++) {
                char *valuename = NULL;

                memset(buf, 0, CFS_PAGE_SIZE);
                /* As listparam_display is used to show param name (with type),
                 * here "if (only_path)" is ignored.*/
                if (popt->show_path) {
                        strcpy(filename, glob_info.gl_pathv[i]);
                        valuename = display_name(filename, 0);
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
                        rc = read(fd, buf, CFS_PAGE_SIZE);
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
                        if (valuename && popt->show_path) {
                                int longbuf = strnchr(buf, rc - 1, '\n') != NULL
                                              || rc > 60;
                                printf("%s=%s", valuename, longbuf ? "\n" : buf);
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
        int fp;
        int rc = 0, i;
        struct param_opts popt;
        char pattern[PATH_MAX];
        char *path;

        rc = getparam_cmdline(argc, argv, &popt);
        if (rc < 0 || rc >= argc)
                return CMD_HELP;

        for (i = rc; i < argc; i++) {
                path = argv[i];

                clean_path(path);

                /* If the entire path is specified as input */
                fp = open(path, O_RDONLY);
                if (fp < 0) {
                        snprintf(pattern, PATH_MAX, "/proc/{fs,sys}/{lnet,lustre}/%s",
                                 path);
                } else {
                        strcpy(pattern, path);
                        close(fp);
                }

                if (popt.only_path)
                        rc = listparam_display(&popt, pattern);
                else
                        rc = getparam_display(&popt, pattern);
                if (rc < 0)
                        return rc;
        }

        return 0;
}

static int setparam_cmdline(int argc, char **argv, struct param_opts *popt)
{
        int ch;

        popt->show_path = 1;
        popt->only_path = 0;
        popt->show_type = 0;
        popt->recursive = 0;

        while ((ch = getopt(argc, argv, "n")) != -1) {
                switch (ch) {
                case 'n':
                        popt->show_path = 0;
                        break;
                default:
                        return -1;
                }
        }
        return optind;
}

static int setparam_display(struct param_opts *popt, char *pattern, char *value)
{
        int rc;
        int fd;
        int i;
        glob_t glob_info;
        char filename[PATH_MAX + 1];    /* extra 1 byte for file type */

        rc = glob(pattern, GLOB_BRACE, NULL, &glob_info);
        if (rc) {
                fprintf(stderr, "error: set_param: %s: %s\n",
                        pattern, globerrstr(rc));
                return -ESRCH;
        }
        for (i = 0; i  < glob_info.gl_pathc; i++) {
                char *valuename = NULL;

                if (popt->show_path) {
                        strcpy(filename, glob_info.gl_pathv[i]);
                        valuename = display_name(filename, 0);
                        if (valuename)
                                printf("%s=%s\n", valuename, value);
                }
                /* Write the new value to the file */
                fd = open(glob_info.gl_pathv[i], O_WRONLY);
                if (fd > 0) {
                        rc = write(fd, value, strlen(value));
                        if (rc < 0)
                                fprintf(stderr, "error: set_param: "
                                        "writing to file %s: %s\n",
                                        glob_info.gl_pathv[i], strerror(errno));
                        else
                                rc = 0;
                        close(fd);
                } else {
                        fprintf(stderr, "error: set_param: %s opening %s\n",
                                strerror(rc = errno), glob_info.gl_pathv[i]);
                }
        }

        globfree(&glob_info);
        return rc;
}

int jt_lcfg_setparam(int argc, char **argv)
{
        int fp;
        int rc = 0, i;
        struct param_opts popt;
        char pattern[PATH_MAX];
        char *path = NULL, *value = NULL;

        rc = setparam_cmdline(argc, argv, &popt);
        if (rc < 0 || rc >= argc)
                return CMD_HELP;

        for (i = rc; i < argc; i++) {
                if ((value = strchr(argv[i], '=')) != NULL) {
                        /* format: set_param a=b */
                        *value = '\0';
                        value ++;
                        path = argv[i];
                } else {
                        /* format: set_param a b */
                        if (path == NULL) {
                                path = argv[i];
                                continue;
                        } else {
                                value = argv[i];
                        }
                }

                clean_path(path);

                /* If the entire path is specified as input */
                fp = open(path, O_RDONLY);
                if (fp < 0) {
                        snprintf(pattern, PATH_MAX, "/proc/{fs,sys}/{lnet,lustre}/%s",
                                 path);
                } else {
                        strcpy(pattern, path);
                        close(fp);
                }

                rc = setparam_display(&popt, pattern, value);
                path = NULL;
                value = NULL;
                if (rc < 0)
                        return rc;
        }

        return 0;
}
