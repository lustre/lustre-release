/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <mntent.h>
#include <portals/api-support.h>
#include <portals/ptlctl.h>

#include <liblustre.h>
#include <linux/lustre_idl.h>
#include <lustre/liblustreapi.h>
#include <lustre/lustre_user.h>

#include "parser.h"
#include "obdctl.h"

/* all functions */
//static int lfs_dsetstripe(int argc, char **argv);
static int lfs_setstripe(int argc, char **argv);
static int lfs_find(int argc, char **argv);
static int lfs_getstripe(int argc, char **argv);
static int lfs_osts(int argc, char **argv);
static int lfs_check(int argc, char **argv);
static int lfs_catinfo(int argc, char **argv);

/* all avaialable commands */
command_t cmdlist[] = {
        {"setstripe", lfs_setstripe, 0,
         "To create a new file with a specific striping pattern, or to set default striping pattern on an existing directory\n"
         "usage: setstripe <filename|dirname> <stripe size> <stripe start> <stripe count>\n"
         "\tstripe size:  Number of bytes in each stripe (0 default)\n"
         "\tstripe start: OST index of first stripe (-1 default)\n"
         "\tstripe count: Number of OSTs to stripe over (0 default)"},
/*        {"dsetstripe", lfs_dsetstripe, 0,
         "To set a specific striping pattern for an existing directory.\n"
         "usage: dsetstripe <dirname> <stripe size> <stripe start> <stripe count>\n"
         "\tstripe size:  Number of bytes in each stripe (0 default)\n"
         "\tstripe start: OST index of first stripe (-1 default)\n"
         "\tstripe count: Number of OSTs to stripe over (0 default)"},
*/        {"find", lfs_find, 0,
         "To list the extended attributes for a given filename or files in a directory "
         "or recursively for all files in a directory tree.\n"
         "usage: find [--obd <uuid>] [--quiet | --verbose] [--recursive] <dir|file> ..."},
        {"getstripe", lfs_getstripe, 0,
         "To list the striping pattern for given filename.\n"
         "usage:getstripe <filename>"},
        {"check", lfs_check, 0,
         "Display the status of MDS or OSTs (as specified in the command) "
         "or all the servers (MDS and OSTs).\n"
         "usage: check <osts|mds|servers>"},
        {"catinfo", lfs_catinfo, 0,
         "Show information of specified type logs.\n"
         "usage: catinfo <keyword> [node name]"
         "keywords are one of followings: config, deletions.\n"
         "client node name must be provided when use keyword config."},
        {"osts", lfs_osts, 0, "osts"},
        {"help", Parser_help, 0, "help"},
        {"exit", Parser_quit, 0, "quit"},
        {"quit", Parser_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};

/* functions */
static int lfs_setstripe(int argc, char **argv)
{
        int result;
        long st_size;
        int  st_offset, st_count;
        char *end;
        struct stat statbuf;

        if (argc != 5)
                return CMD_HELP;

        // get the stripe size
        st_size = strtoul(argv[2], &end, 0);
        if (*end != '\0') {
                fprintf(stderr, "error: %s: bad stripe size '%s'\n",
                                argv[0], argv[2]);
                return CMD_HELP;
        }
        // get the stripe offset
        st_offset = strtoul(argv[3], &end, 0);
        if (*end != '\0') {
                fprintf(stderr, "error: %s: bad stripe offset '%s'\n",
                                argv[0], argv[3]);
                return CMD_HELP;
        }
        // get the stripe count
        st_count = strtoul(argv[4], &end, 0);
        if (*end != '\0') {
                fprintf(stderr, "error: %s: bad stripe count '%s'\n",
                                argv[0], argv[4]);
                return CMD_HELP;
        }

        result = stat(argv[1], &statbuf);
        if ((result == 0) && S_ISDIR(statbuf.st_mode)) {
               result = op_setstripe_dir(argv[1], st_size, st_offset, 
                                         st_count);
        } else {
                result = op_create_file(argv[1], st_size, st_offset, st_count);
        }

        if (result)
                fprintf(stderr, "error: %s: create stripe file failed\n",
                                argv[0]);

        return result;
}
#if 0
static int lfs_dsetstripe(int argc, char **argv)
{
        int result;
        long st_size;
        int  st_offset, st_count;
        char *end;

        if (argc != 5)
                return CMD_HELP;

        // get the stripe size
        st_size = strtoul(argv[2], &end, 0);
        if (*end != '\0') {
                fprintf(stderr, "error: %s: bad stripe size '%s'\n",
                                argv[0], argv[2]);
                return CMD_HELP;
        }
        // get the stripe offset
        st_offset = strtoul(argv[3], &end, 0);
        if (*end != '\0') {
                fprintf(stderr, "error: %s: bad stripe offset '%s'\n",
                                argv[0], argv[3]);
                return CMD_HELP;
        }
        // get the stripe count
        st_count = strtoul(argv[4], &end, 0);
        if (*end != '\0') {
                fprintf(stderr, "error: %s: bad stripe count '%s'\n",
                                argv[0], argv[4]);
                return CMD_HELP;
        }

        result = op_setstripe_dir(argv[1], st_size, st_offset, st_count);
        if (result)
                fprintf(stderr, "error: %s: create stripe file failed\n",
                                argv[0]);

        return result;

}
#endif
static int lfs_find(int argc, char **argv)
{
        struct option long_opts[] = {
                {"obd", 1, 0, 'o'},
                {"quiet", 0, 0, 'q'},
                {"recursive", 0, 0, 'r'},
                {"verbose", 0, 0, 'v'},
                {0, 0, 0, 0}
        };
        char short_opts[] = "ho:qrv";
        int quiet, verbose, recursive, c, rc;
        struct obd_uuid *obduuid = NULL;

        optind = 0;
        quiet = verbose = recursive = 0;
        while ((c = getopt_long(argc, argv, short_opts,
                                        long_opts, NULL)) != -1) {
                switch (c) {
                case 'o':
                        if (obduuid) {
                                fprintf(stderr,
                                        "error: %s: only one obduuid allowed",
                                        argv[0]);
                                return CMD_HELP;
                        }
                        obduuid = (struct obd_uuid *)optarg;
                        break;
                case 'q':
                        quiet++;
                        verbose = 0;
                        break;
                case 'r':
                        recursive = 1;
                        break;
                case 'v':
                        verbose++;
                        quiet = 0;
                        break;
                case '?':
                        return CMD_HELP;
                        break;
                default:
                        fprintf(stderr, "error: %s: option '%s' unrecognized\n",
                                argv[0], argv[optind - 1]);
                        return CMD_HELP;
                        break;
                }
        }

        if (optind >= argc)
                return CMD_HELP;

        do {
                rc = op_find(argv[optind], obduuid, recursive, verbose, quiet);
        } while (++optind < argc && !rc);

        if (rc)
                fprintf(stderr, "error: %s: find failed\n", argv[0]);
        return rc;
}

static int lfs_getstripe(int argc, char **argv)
{
        struct obd_uuid *obduuid = NULL;
        int rc;

        if (argc != 2)
                return CMD_HELP;

        optind = 1;

        do {
                rc = op_find(argv[optind], obduuid, 0, 0, 0);
        } while (++optind < argc && !rc);

        if (rc)
                fprintf(stderr, "error: %s: getstripe failed for %s\n",
                        argv[0], argv[1]);

        return rc;
}

static int lfs_osts(int argc, char **argv)
{
        FILE *fp;
        struct mntent *mnt = NULL;
        struct obd_uuid *obduuid = NULL;
        int rc=0;

        if (argc != 1)
                return CMD_HELP;

        fp = setmntent(MOUNTED, "r");

        if (fp == NULL) {
                 fprintf(stderr, "setmntent(%s): %s:", MOUNTED,
                        strerror (errno));
        } else {
                mnt = getmntent(fp);
                while (feof(fp) == 0 && ferror(fp) ==0) {
                        if (strcmp(mnt->mnt_type, "lustre_lite") == 0) {
                                rc = op_find(mnt->mnt_dir, obduuid, 0, 0, 0);
                                if (rc)
                                        fprintf(stderr, "error: lfs osts failed for %s\n",
                                                mnt->mnt_dir);
                        }
                        mnt = getmntent(fp);
                }
                endmntent(fp);
        }

        return rc;
}

static int lfs_check(int argc, char **argv)
{
        int rc;
        FILE *fp;
        struct mntent *mnt = NULL;
        int type_num = 1;
        char *obd_type_p[2];
        char obd_type1[4];
        char obd_type2[4];

        if (argc != 2)
                return CMD_HELP;

        obd_type_p[1]=obd_type1;
        obd_type_p[2]=obd_type2;

        if (strcmp(argv[1],"osts")==0) {
                strcpy(obd_type_p[0],"osc");
        } else if (strcmp(argv[1],"mds")==0) {
                strcpy(obd_type_p[0],"mdc");
        } else if (strcmp(argv[1],"servers")==0) {
                type_num=2;
                strcpy(obd_type_p[0],"osc");
                strcpy(obd_type_p[1],"mdc");
        } else {
                fprintf(stderr, "error: %s: option '%s' unrecognized\n",
                                argv[0], argv[1]);
                        return CMD_HELP;
        }

        fp = setmntent(MOUNTED, "r");
        if (fp == NULL) {
                 fprintf(stderr, "setmntent(%s): %s:", MOUNTED,
                        strerror (errno));
        } else {
                mnt = getmntent(fp);
                while (feof(fp) == 0 && ferror(fp) ==0) {
                        if (strcmp(mnt->mnt_type, "lustre_lite") == 0) 
                                break;
                        mnt = getmntent(fp);
                }
                endmntent(fp);
        }
           
        rc = op_check(type_num,obd_type_p,mnt->mnt_dir);

        if (rc)
                fprintf(stderr, "error: %s: %s status failed\n",
                                argv[0],argv[1]);
                                                                                                                             
        return rc;

}

static int lfs_catinfo(int argc, char **argv)
{
        FILE *fp;
        struct mntent *mnt = NULL;
        int rc;
        
        if (argc < 2 || (!strcmp(argv[1],"config") && argc < 3))
                return CMD_HELP;

        if (strcmp(argv[1], "config") && strcmp(argv[1], "deletions"))
                return CMD_HELP;

        fp = setmntent(MOUNTED, "r");
        if (fp == NULL) {
                 fprintf(stderr, "setmntent(%s): %s:", MOUNTED, 
                         strerror(errno));
        } else {
                mnt = getmntent(fp);
                while (feof(fp) == 0 && ferror(fp) == 0) {
                        if (strcmp(mnt->mnt_type, "lustre_lite") == 0) 
                                break;
                        mnt = getmntent(fp);
                }
                endmntent(fp);
        }

        if (mnt) {
                if (argc == 3)
                        rc = op_catinfo(mnt->mnt_dir, argv[1], argv[2]);
                else
                        rc = op_catinfo(mnt->mnt_dir, argv[1], NULL);
        } else {
                fprintf(stderr, "no lustre_lite mounted.\n");
                rc = -1;
        }

        return rc;
}

int main(int argc, char **argv)
{
        int rc;

        setlinebuf(stdout);
                                                                                                                             
        ptl_initialize(argc, argv);
        if (obd_initialize(argc, argv) < 0)
                exit(2);
        if (dbg_initialize(argc, argv) < 0)
                exit(3);
                                                                                                                             
        Parser_init("lfs > ", cmdlist);

        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                rc = Parser_commands();
        }

        obd_finalize(argc, argv);
        return rc;
}
