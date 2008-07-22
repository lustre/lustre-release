/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Robert Read <rread@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdlib.h>
#include <sys/ioctl.h>
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
#include "parser.h"
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
        lcfg->lcfg_num = atoi(argv[1]);
        
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        //rc = lcfg_mgs_ioctl(argv[0], OBD_DEV_ID, lcfg);

        lustre_cfg_free(lcfg);
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

/* Param set in config log on MGS */
/* conf_param key1=value1 [key2=value2...] */
int jt_lcfg_mgsparam(int argc, char **argv)
{
        int i, rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        if ((argc >= LUSTRE_CFG_MAX_BUFCOUNT) || (argc <= 1))
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, NULL);

        for (i = 1; i < argc; i++) {
                lustre_cfg_bufs_set_string(&bufs, i, argv[i]);
        }

        /* We could put other opcodes here. */
        lcfg = lustre_cfg_new(LCFG_PARAM, &bufs);

        rc = lcfg_mgs_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        
        return rc;
}

/* Display the path in the same format as sysctl
 * For eg. obdfilter.lustre-OST0000.stats */
static char *display_name(char *filename)
{
        char *tmp;

        filename += strlen("/proc/");
        if (strncmp(filename, "fs/", strlen("fs/")) == 0)
                filename += strlen("fs/");
        else
                filename += strlen("sys/");

        if (strncmp(filename, "lustre/", strlen("lustre/")) == 0)
                filename += strlen("lustre/");

        /* replace '/' with '.' to match conf_param and sysctl */
        tmp = filename;
        while ((tmp = strchr(tmp, '/')) != NULL)
                *tmp = '.';

        return filename;
}

/* Find a character in a length limited string */
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

int jt_lcfg_getparam(int argc, char **argv)
{
        int fp;
        int rc = 0, i, show_path = 0, only_path = 0;
        char pattern[PATH_MAX];
        char *path, *tmp, *buf;
        glob_t glob_info;

        if (argc == 3 && (strcmp(argv[1], "-n") == 0 ||
                          strcmp(argv[1], "-N") == 0)) {
                path = argv[2];
                if (strcmp(argv[1], "-N") == 0) {
                        only_path = 1;
                        show_path = 1;
                }
        } else if (argc == 2) {
                show_path = 1;
                path = argv[1];
        } else {
                return CMD_HELP;
        }

        /* If the input is in form Eg. obdfilter.*.stats */
        if (strchr(path, '.')) {
                tmp = path;
                while (*tmp != '\0') {
                        if (*tmp == '.')
                                *tmp = '/';
                        tmp ++;
                }
        }

        /* If the entire path is specified as input */
        fp = open(path, O_RDONLY);
        if (fp < 0)
                snprintf(pattern, PATH_MAX, "/proc/{fs,sys}/{lnet,lustre}/%s",
                         path);
        else {
                strcpy(pattern, path);
                close(fp);
        }

        rc = glob(pattern, GLOB_BRACE, NULL, &glob_info);
        if (rc) {
                fprintf(stderr, "error : glob %s: %s \n", pattern,strerror(rc));
                return rc;
        }

        buf = malloc(CFS_PAGE_SIZE);
        for (i = 0; i  < glob_info.gl_pathc; i++) {
                char *valuename = NULL;

                memset(buf, 0, CFS_PAGE_SIZE);
                if (show_path) {
                        char *filename;
                        filename = strdup(glob_info.gl_pathv[i]);
                        valuename = display_name(filename);
                        if (valuename && only_path) {
                                printf("%s\n", valuename);
                                continue;
                        }
                }

                /* Write the contents of file to stdout */
                fp = open(glob_info.gl_pathv[i], O_RDONLY);
                if (fp < 0) {
                        fprintf(stderr, "error: %s: opening('%s') failed: %s\n",
                                jt_cmdname(argv[0]), glob_info.gl_pathv[i],
                                strerror(errno));
                        continue;
                }

                do {
                        rc = read(fp, buf, CFS_PAGE_SIZE);
                        if (rc == 0)
                                break;
                        if (rc < 0) {
                                fprintf(stderr, "error: %s: read('%s') "
                                        "failed: %s\n", jt_cmdname(argv[0]),
                                        glob_info.gl_pathv[i], strerror(errno));
                                break;
                        }
                        /* Print the output in the format path=value if the
                         * value contains no new line character or cab be
                         * occupied in a line, else print value on new line */
                        if (valuename && show_path) {
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
                                fprintf(stderr, "error: %s: write to stdout "
                                        "failed: %s\n", jt_cmdname(argv[0]),
                                        strerror(errno));
                                break;
                        }
                } while (1);
                close(fp);
        }

        globfree(&glob_info);
        free(buf);
        return rc;
}


int jt_lcfg_setparam(int argc, char **argv)
{
        int rc = 0, i;
        int fp, show_path = 0;
        char pattern[PATH_MAX];
        char *path, *value, *tmp;
        glob_t glob_info;

        path = argv[1];
        if (argc == 4 && (strcmp(argv[1], "-n") == 0)) {
                /* Format: lctl set_param -n param value */
                path = argv[2];
                value = argv[3];
        } else if (argc == 3) {
                if (strcmp(argv[1], "-n") != 0) {
                        /* Format: lctl set_param param value */
                        show_path = 1;
                        value = argv[2];
                } else if ((value = strchr(argv[2], '=')) != NULL) {
                        /* Format: lctl set_param -n param=value */
                        path = argv[2];
                        *value = '\0';
                        value ++;
                } else {
                        fprintf(stderr, "error: %s Incorrect arguments."
                                        "See Usage\n",
                                jt_cmdname(argv[0]));
                        return CMD_HELP;
                }
        } else if (argc == 2 && ((value = strchr(argv[1], '=')) != NULL)) {
                /* Format: lctl set_param param=value */
                show_path = 1;
                *value = '\0';
                value++;
        } else {
                fprintf(stderr, "error: %s Incorrect arguments. See Usage\n",
                        jt_cmdname(argv[0]));
                return CMD_HELP;
        }

        /* If the input is in form Eg. obdfilter.*.stats */
        if (strchr(path, '.')) {
                tmp = path;
                while (*tmp != '\0') {
                        if (*tmp == '.')
                                *tmp = '/';
                        tmp ++;
                }
        }

        fp = open(path, O_RDONLY);
        if (fp < 0)
                snprintf(pattern, PATH_MAX, "/proc/{fs,sys}/{lnet,lustre}/%s",
                         path);
        else {
                strcpy(pattern, path);
                close(fp);
        }

        rc = glob(pattern, GLOB_BRACE, NULL, &glob_info);
        if (rc) {
                fprintf(stderr, "error : glob %s: %s \n", pattern,strerror(rc));
                return rc;
        }
        for (i = 0; i  < glob_info.gl_pathc; i++) {
                if (show_path) {
                        char *valuename, *filename;
                        filename = strdup(glob_info.gl_pathv[i]);
                        valuename = display_name(filename);
                        printf("%s=%s\n", valuename, value);
                }
                /* Write the new value to the file */
                fp = open(glob_info.gl_pathv[i], O_WRONLY);
                if (fp > 0) {
                        rc = write(fp, value, strlen(value));
                        if (rc < 0)
                                fprintf(stderr,
                                        "error writing to file %s (%s)\n",
                                        glob_info.gl_pathv[i], strerror(errno));
                        else
                                rc = 0;
                        close(fp);
                } else {
                        fprintf(stderr, "error: %s: %s opening %s\n",
                                jt_cmdname(argv[0]), strerror(rc = errno),
                                glob_info.gl_pathv[i]);
                }
        }

        globfree(&glob_info);
        return rc;
}
