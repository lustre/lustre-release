/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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


#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <mntent.h>
#include <getopt.h>
#include <sys/utsname.h>

#include "obdctl.h"
#include <lnet/lnetctl.h>

int          verbose;
int          nomtab;
int          fake;
int          force;
int          retry;
static char *progname = NULL;
#define MAX_RETRIES 99

void usage(FILE *out)
{
        fprintf(out, "%s v1.%d\n", progname, LMD_MAGIC & 0xFF);
        fprintf(out, "usage: %s <mdsnode>[,<altmdsnode>]:/<mdsname>/<cfgname>"
                " <mountpt> [-fhnv] [-o mntopt]\n", progname);
        fprintf(out, "\t<mdsnode>: nid of MDS (config) node\n"
                "\t<mdsname>: name of MDS service (e.g. mds1)\n"
                "\t<cfgname>: name of client config (e.g. client)\n"
                "\t<mountpt>: filesystem mountpoint (e.g. /mnt/lustre)\n"
                "\t-f|--fake: fake mount (updates /etc/mtab)\n"
                "\t--force: force mount even if already in /etc/mtab\n"
                "\t-h|--help: print this usage message\n"
                "\t-n|--nomtab: do not update /etc/mtab after mount\n"
                "\t-v|--verbose: print verbose config settings\n"
                "\t-o: filesystem mount options:\n"
                "\t\tflock/noflock: enable/disable flock support\n"
                "\t\troute=<gw>[-<gw>]:<low>[-<high>]: portal route to MDS\n"
                "\t\tuser_xattr/nouser_xattr: enable/disable user extended "
                "attributes\n"
                );
        exit(out != stdout);
}

static int check_mtab_entry(char *spec, char *mtpt, char *type)
{
        FILE *fp;
        struct mntent *mnt;

        if (!force) {
                fp = setmntent(MOUNTED, "r");
                if (fp == NULL)
                        return(0);

                while ((mnt = getmntent(fp)) != NULL) {
                        if (strcmp(mnt->mnt_fsname, spec) == 0 &&
                            strcmp(mnt->mnt_dir, mtpt) == 0 &&
                            strcmp(mnt->mnt_type, type) == 0) {
                                fprintf(stderr, "%s: according to %s %s is "
                                        "already mounted on %s\n",
                                        progname, MOUNTED, spec, mtpt);
                                return(1); /* or should we return an error? */
                        }
                }
                endmntent(fp);
        }
        return(0);
}

static int
update_mtab_entry(char *spec, char *mtpt, char *type, char *opts,
                  int flags, int freq, int pass)
{
        FILE *fp;
        struct mntent mnt;
        int rc = 0;

        mnt.mnt_fsname = spec;
        mnt.mnt_dir = mtpt;
        mnt.mnt_type = type;
        mnt.mnt_opts = opts ? opts : "";
        mnt.mnt_freq = freq;
        mnt.mnt_passno = pass;

        fp = setmntent(MOUNTED, "a+");
        if (fp == NULL) {
                fprintf(stderr, "%s: setmntent(%s): %s:",
                        progname, MOUNTED, strerror (errno));
                rc = 16;
        } else {
                if ((addmntent(fp, &mnt)) == 1) {
                        fprintf(stderr, "%s: addmntent: %s:",
                                progname, strerror (errno));
                        rc = 16;
                } else if (verbose > 1) {
                        fprintf(stderr, "%s: added %s on %s to %s\n",
                                progname, spec, mtpt, MOUNTED);
                }
                endmntent(fp);
        }

        return rc;
}

int
init_options(struct lustre_mount_data *lmd)
{
        memset(lmd, 0, sizeof(*lmd));
        lmd->lmd_magic = LMD_MAGIC;
        return 0;
}

int
print_options(FILE *out, struct lustre_mount_data *lmd, const char *options)
{
        int i;
        for (i = 0; i < lmd->lmd_nid_count; i++) {
                fprintf(out, "mds nid %d:       %s\n", i,
                        libcfs_nid2str(lmd->lmd_nid[i]));
        }
        fprintf(out, "mds name:        %s\n", lmd->lmd_mds);
        fprintf(out, "profile:         %s\n", lmd->lmd_profile);
        fprintf(out, "options:         %s\n", options);
        fprintf(out, "retry:           %d\n", retry);

        return 0;
}

static int parse_nids(struct lustre_mount_data *lmd, char *nids)
{
        int i = 0;
        char *tmp = 0;
        lnet_nid_t nid;

        while ((tmp = strsep(&nids, ",:"))) {
                nid = libcfs_str2nid(tmp);
                if (nid == LNET_NID_ANY) {
                        fprintf(stderr, "%s: Can't parse NID '%s'\n",
                                progname, tmp);
                        continue;
                }
                lmd->lmd_nid[lmd->lmd_nid_count++] = nid;
                if (lmd->lmd_nid_count >= MAX_FAILOVER_NIDS) {
                        fprintf(stderr, "%s: Too many target NIDs: "
                                "ignoring nids after %s\n",
                                progname, tmp);
                        break;
                }
        }
        return (lmd->lmd_nid_count);
}


/*****************************************************************************
 *
 * This part was cribbed from util-linux/mount/mount.c.  There was no clear
 * license information, but many other files in the package are identified as
 * GNU GPL, so it's a pretty safe bet that was their intent.
 *
 ****************************************************************************/
struct opt_map {
        const char *opt;        /* option name */
        int skip;               /* skip in mtab option string */
        int inv;                /* true if flag value should be inverted */
        int ms_mask;            /* MS flag mask value */
        int lmd_mask;           /* LMD flag mask value */
};

static const struct opt_map opt_map[] = {
  { "defaults", 0, 0, 0, 0         },      /* default options */
  { "rw",       1, 1, MS_RDONLY, 0 },      /* read-write */
  { "ro",       0, 0, MS_RDONLY, 0 },      /* read-only */
  { "exec",     0, 1, MS_NOEXEC, 0 },      /* permit execution of binaries */
  { "noexec",   0, 0, MS_NOEXEC, 0 },      /* don't execute binaries */
  { "suid",     0, 1, MS_NOSUID, 0 },      /* honor suid executables */
  { "nosuid",   0, 0, MS_NOSUID, 0 },      /* don't honor suid executables */
  { "dev",      0, 1, MS_NODEV,  0 },      /* interpret device files  */
  { "nodev",    0, 0, MS_NODEV,  0 },      /* don't interpret devices */
  { "async",    0, 1, MS_SYNCHRONOUS, 0},  /* asynchronous I/O */
  { "auto",     0, 0, 0, 0         },      /* Can be mounted using -a */
  { "noauto",   0, 0, 0, 0         },      /* Can only be mounted explicitly */
  { "nousers",  0, 1, 0, 0         },      /* Forbid ordinary user to mount */
  { "nouser",   0, 1, 0, 0         },      /* Forbid ordinary user to mount */
  { "noowner",  0, 1, 0, 0         },      /* Device owner has no special privs */
  { "_netdev",  0, 0, 0, 0         },      /* Device accessible only via network */
  { "flock",    0, 0, 0, LMD_FLG_FLOCK},   /* Enable flock support */
  { "noflock",  1, 1, 0, LMD_FLG_FLOCK},   /* Disable flock support */
  { "user_xattr", 0, 0, 0, LMD_FLG_USER_XATTR}, /* Enable get/set user xattr */
  { "nouser_xattr", 1, 1, 0, LMD_FLG_USER_XATTR}, /* Disable user xattr */
  { "acl",      0, 0, 0, LMD_FLG_ACL},     /* Enable ACL support */
  { "noacl",    1, 1, 0, LMD_FLG_ACL},     /* Disable ACL support */
  /* please add new mount options to usage message */
  { NULL,       0, 0, 0, 0         }
};
/****************************************************************************/

static int parse_one_option(const char *check, int *ms_flags, int *lmd_flags)
{
        const struct opt_map *opt;

        for (opt = &opt_map[0]; opt->opt != NULL; opt++) {
                if (strcmp(check, opt->opt) == 0) {
                        if (opt->inv) {
                                *ms_flags &= ~(opt->ms_mask);
                                *lmd_flags &= ~(opt->lmd_mask);
                        } else {
                                *ms_flags |= opt->ms_mask;
                                *lmd_flags |= opt->lmd_mask;
                        }
                        return 1;
                }
        }
        return 0;
}

int parse_options(char *options, struct lustre_mount_data *lmd, int *flagp)
{
        int val;
        char *opt, *opteq;

        *flagp = 0;
        /* parsing ideas here taken from util-linux/mount/nfsmount.c */
        for (opt = strtok(options, ","); opt; opt = strtok(NULL, ",")) {
                if ((opteq = strchr(opt, '='))) {
                        val = atoi(opteq + 1);
                        *opteq = '\0';
                        if (!strcmp(opt, "retry")) {
                                if (val >= 0 || val < MAX_RETRIES)
                                        retry = val;
                                else
                                        retry = 0;
                        } else {
                                fprintf(stderr, "%s: unknown option '%s'. "
                                        "Ignoring.\n", progname, opt);
                                /* Ignore old nettype= for now 
                                usage(stderr);
                                */
                        }
                } else {
                        if (parse_one_option(opt, flagp, &lmd->lmd_flags))
                                continue;

                        fprintf(stderr, "%s: unknown option '%s'\n",
                                progname, opt);
                        usage(stderr);
                }
        }
        return 0;
}

int
build_data(char *source, char *options, struct lustre_mount_data *lmd,
           int *flagp)
{
        char  buf[1024];
        char *nid = NULL;
        char *mds = NULL;
        char *profile = NULL;
        char *s;
        int   rc;

        if (lmd_bad_magic(lmd))
                return 4;

        if (strlen(source) >= sizeof(buf)) {
                fprintf(stderr, "%s: nid:/mds/profile argument too long\n",
                        progname);
                return 1;
        }
        strcpy(buf, source);
        if ((s = strchr(buf, ':'))) {
                nid = buf;
                *s = '\0';

                while (*++s == '/')
                        ;
                mds = s;
                if ((s = strchr(mds, '/'))) {
                        *s = '\0';
                        profile = s + 1;
                } else {
                        fprintf(stderr, "%s: directory to mount not in "
                                "nid:/mds/profile format\n",
                                progname);
                        return(1);
                }
        } else {
                fprintf(stderr, "%s: "
                        "directory to mount not in nid:/mds/profile format\n",
                        progname);
                return(1);
        }

        rc = parse_options(options, lmd, flagp);
        if (rc)
                return rc;

        if (parse_nids(lmd, nid) == 0) {
                fprintf(stderr, "%s: Can't parse any mds nids\n", progname);
                return(1);
        }

        if (strlen(mds) + 1 > sizeof(lmd->lmd_mds)) {
                fprintf(stderr, "%s: mds name too long\n", progname);
                return(1);
        }
        strcpy(lmd->lmd_mds, mds);

        if (strlen(profile) + 1 > sizeof(lmd->lmd_profile)) {
                fprintf(stderr, "%s: profile name too long\n", progname);
                return(1);
        }
        strcpy(lmd->lmd_profile, profile);

        return 0;
}

int main(int argc, char *const argv[])
{
        char *source, *target, *options = "", optbuf[65536] = { '\0' };
        int i, nargs = 3, opt, rc, flags, buflen = sizeof(optbuf) - 1;
        struct lustre_mount_data lmd;
        static struct option long_opt[] = {
                {"fake", 0, 0, 'f'},
                {"force", 0, 0, 1},
                {"help", 0, 0, 'h'},
                {"nomtab", 0, 0, 'n'},
                {"options", 1, 0, 'o'},
                {"verbose", 0, 0, 'v'},
                {0, 0, 0, 0}
        };

        progname = strrchr(argv[0], '/');
        progname = progname ? progname + 1 : argv[0];

        while ((opt = getopt_long(argc, argv, "fhno:v", long_opt,NULL)) != EOF){
                switch (opt) {
                case 1:
                        ++force;
                        if (verbose)
                                printf("force: %d\n", force);
                        nargs++;
                        break;
                case 'f':
                        ++fake;
                        if (verbose)
                                printf("fake: %d\n", fake);
                        nargs++;
                        break;
                case 'h':
                        usage(stdout);
                        break;
                case 'n':
                        ++nomtab;
                        if (verbose)
                                printf("nomtab: %d\n", nomtab);
                        nargs++;
                        break;
                case 'o':
                        options = optarg;
                        nargs++;
                        break;
                case 'v':
                        ++verbose;
                        printf("verbose: %d\n", verbose);
                        nargs++;
                        break;
                default:
                        fprintf(stderr, "%s: unknown option '%c'\n",
                                progname, opt);
                        usage(stderr);
                        break;
                }
        }

        if (optind + 2 > argc) {
                fprintf(stderr, "%s: too few arguments\n", progname);
                usage(stderr);
        }

        source = argv[optind];
        target = argv[optind + 1];

        if (verbose) {
                for (i = 0; i < argc; i++)
                        printf("arg[%d] = %s\n", i, argv[i]);
                printf("source = %s, target = %s\n", source, target);
        }

        if (!force && check_mtab_entry(source, target, "lustre"))
                exit(32);

        init_options(&lmd);

        /* need to copy options, as parse_options->strtok() clobbers it
         * and we can't use it later to put in /etc/mtab. */
        if (strlen(options) > buflen)
                fprintf(stderr, "%s: options too long (%d > %d), ignore last\n",
                        progname, strlen(options), buflen);
        strncpy(optbuf, options, buflen);

        rc = build_data(source, optbuf, &lmd, &flags);
        if (rc) {
                exit(1);
        }

        if (verbose)
                print_options(stdout, &lmd, options);

        rc = access(target, F_OK);
        if (rc) {
                rc = errno;
                fprintf(stderr, "%s: %s inaccessible: %s\n", progname, target,
                        strerror(errno));
                return 1;
        }

        if (!fake) {
                FILE *modpipe = popen("/sbin/modprobe -q llite", "r");
                if (modpipe != NULL)
                        pclose(modpipe);
                /* use <= to include the initial mount before we retry */
                for (i = 0, rc = -EAGAIN; i <= retry && rc != 0; i++)
                        rc = mount(source, target, "lustre", flags, &lmd);
        }
        if (rc) {
                fprintf(stderr, "%s: mount(%s, %s) failed: %s\n", progname,
                        source, target, strerror(errno));
                print_options(stderr, &lmd, options);
                if (errno == ENODEV) {
                        struct utsname unamebuf;
                        char *modfile = "/etc/modutils.conf";

                        if (uname(&unamebuf) == 0 &&
                            strncmp(unamebuf.release, "2.4", 3) == 0)
                                modfile = "/etc/modules.conf";

                        fprintf(stderr, "Are the lustre modules loaded?\n"
                                "Check %s and /proc/filesystems\n");
                }
                rc = 32;
        } else if (!nomtab) {
                rc = update_mtab_entry(source, target, "lustre", options,0,0,0);
        }
        return rc;
}
