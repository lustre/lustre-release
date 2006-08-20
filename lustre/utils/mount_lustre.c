/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Robert Read <rread@clusterfs.com>
 *   Author: Nathan Rutman <nathan@clusterfs.com>
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
#include <lustre_ver.h>

int          verbose = 0;
int          nomtab = 0;
int          fake = 0;
int          force = 0;
static char *progname = NULL;

void usage(FILE *out)
{
        fprintf(out, "%s v"LUSTRE_VERSION_STRING"\n", progname);
        fprintf(out, "\nThis mount helper should only be invoked via the "
                "mount (8) command,\ne.g. mount -t lustre dev dir\n\n");
        fprintf(out, "usage: %s [-fhnv] [-o <mntopt>] <device> <mountpt>\n", 
                progname);
        fprintf(out, 
                "\t<device>: the disk device, or for a client:\n"
                "\t\t<mgmtnid>[:<altmgtnid>...]:/<filesystem>-client\n"
                "\t<filesystem>: name of the Lustre filesystem (e.g. lustre1)\n"
                "\t<mountpt>: filesystem mountpoint (e.g. /mnt/lustre)\n"
                "\t-f|--fake: fake mount (updates /etc/mtab)\n"
                "\t--force: force mount even if already in /etc/mtab\n"
                "\t-h|--help: print this usage message\n"
                "\t-n|--nomtab: do not update /etc/mtab after mount\n"
                "\t-v|--verbose: print verbose config settings\n"
                "\t<mntopt>: one or more comma separated of:\n"
                "\t\t(no)flock,(no)user_xattr,(no)acl\n"
                "\t\tnosvc: only start MGC/MGS obds\n"
                "\t\texclude=<ostname>[:<ostname>] : colon-separated list of "
                "inactive OSTs (e.g. lustre-OST0001)\n"
                );
        exit((out != stdout) ? EINVAL : 0);
}

static int check_mtab_entry(char *spec, char *mtpt, char *type)
{
        FILE *fp;
        struct mntent *mnt;

        fp = setmntent(MOUNTED, "r");
        if (fp == NULL)
                return(0);

        while ((mnt = getmntent(fp)) != NULL) {
                if (strcmp(mnt->mnt_fsname, spec) == 0 &&
                        strcmp(mnt->mnt_dir, mtpt) == 0 &&
                        strcmp(mnt->mnt_type, type) == 0) {
                        endmntent(fp);
                        return(EEXIST); 
                }
        }
        endmntent(fp);

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
                }
                endmntent(fp);
        }

        return rc;
}

/* Get rid of symbolic hostnames for tcp, since kernel can't do lookups */
#define MAXNIDSTR 1024
static char *convert_hostnames(char *s1)
{
        char *converted, *s2 = 0, *c;
        char sep;
        int left = MAXNIDSTR;
        lnet_nid_t nid;
        
        converted = malloc(left);
        c = converted;
        while ((left > 0) && (*s1 != '/')) {
                s2 = strpbrk(s1, ",:");
                if (!s2)
                        goto out_free;
                sep = *s2;
                *s2 = '\0';     
                nid = libcfs_str2nid(s1);
                if (nid == LNET_NID_ANY)
                        goto out_free;
                c += snprintf(c, left, "%s%c", libcfs_nid2str(nid), sep);
                left = converted + MAXNIDSTR - c;
                s1 = s2 + 1;
        }
        snprintf(c, left, "%s", s1);
        return converted;
out_free:
        fprintf(stderr, "%s: Can't parse NID '%s'\n", progname, s1);
        free(converted);
        return NULL;
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
        int inv;                /* true if flag value should be inverted */
        int mask;               /* flag mask value */
};

static const struct opt_map opt_map[] = {
  /*"optname", inv,ms_mask */
  /* These flags are parsed by mount, not lustre */
  { "defaults", 0, 0         },      /* default options */
  { "remount",  0, MS_REMOUNT},      /* remount with different options */
  { "rw",       1, MS_RDONLY },      /* read-write */
  { "ro",       0, MS_RDONLY },      /* read-only */
  { "exec",     1, MS_NOEXEC },      /* permit execution of binaries */
  { "noexec",   0, MS_NOEXEC },      /* don't execute binaries */
  { "suid",     1, MS_NOSUID },      /* honor suid executables */
  { "nosuid",   0, MS_NOSUID },      /* don't honor suid executables */
  { "dev",      1, MS_NODEV  },      /* interpret device files  */
  { "nodev",    0, MS_NODEV  },      /* don't interpret devices */
  { "async",    1, MS_SYNCHRONOUS},  /* asynchronous I/O */
  { "auto",     0, 0         },      /* Can be mounted using -a */
  { "noauto",   0, 0         },      /* Can only be mounted explicitly */
  { "nousers",  1, 0         },      /* Forbid ordinary user to mount */
  { "nouser",   1, 0         },      /* Forbid ordinary user to mount */
  { "noowner",  1, 0         },      /* Device owner has no special privs */
  { "_netdev",  0, 0         },      /* Device accessible only via network */
  { NULL,       0, 0         }
};
/****************************************************************************/

/* 1  = don't pass on to lustre
   0  = pass on to lustre */
static int parse_one_option(const char *check, int *flagp)
{
        const struct opt_map *opt;

        for (opt = &opt_map[0]; opt->opt != NULL; opt++) {
                if (strncmp(check, opt->opt, strlen(opt->opt)) == 0) {
                        if (opt->mask) {
                                if (opt->inv)
                                        *flagp &= ~(opt->mask);
                                else
                                        *flagp |= opt->mask;
                        }
                        return 1;
                }
        }
        /* Assume any unknown options are valid and pass them on.  The mount
           will fail if lmd_parse, ll_options or ldiskfs doesn't recognize it.*/
        return 0;
}

/* Replace options with subset of Lustre-specific options, and
   fill in mount flags */
int parse_options(char *orig_options, int *flagp)
{
        char *options, *opt, *nextopt;

        options = calloc(strlen(orig_options) + 1, 1);
        *flagp = 0;
        nextopt = orig_options;
        while ((opt = strsep(&nextopt, ","))) {
                if (!*opt) 
                        /* empty option */
                        continue;
                if (parse_one_option(opt, flagp) == 0) {
                        /* pass this on as an option */
                        if (*options)
                                strcat(options, ",");
                        strcat(options, opt);
                }
        }
        strcpy(orig_options, options);
        free(options);
        return 0;
}


int main(int argc, char *const argv[])
{
        char default_options[] = "";
        char *source, *target, *ptr;
        char *options, *optcopy, *orig_options = default_options;
        int i, nargs = 3, opt, rc, flags, optlen;
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

        while ((opt = getopt_long(argc, argv, "fhno:v",
                                  long_opt, NULL)) != EOF){
                switch (opt) {
                case 1:
                        ++force;
                        printf("force: %d\n", force);
                        nargs++;
                        break;
                case 'f':
                        ++fake;
                        printf("fake: %d\n", fake);
                        nargs++;
                        break;
                case 'h':
                        usage(stdout);
                        break;
                case 'n':
                        ++nomtab;
                        printf("nomtab: %d\n", nomtab);
                        nargs++;
                        break;
                case 'o':
                        orig_options = optarg;
                        nargs++;
                        break;
                case 'v':
                        ++verbose;
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

        source = convert_hostnames(argv[optind]);
        target = argv[optind + 1];
        ptr = target + strlen(target) - 1;
        while ((ptr > target) && (*ptr == '/')) {
                *ptr = 0;
                ptr--;
        }

        if (!source) {
                usage(stderr);
        }

        if (verbose) {
                for (i = 0; i < argc; i++)
                        printf("arg[%d] = %s\n", i, argv[i]);
                printf("source = %s, target = %s\n", source, target);
                printf("options = %s\n", orig_options);
        }

        options = malloc(strlen(orig_options) + 1);
        strcpy(options, orig_options);
        rc = parse_options(options, &flags); 
        if (rc) {
                fprintf(stderr, "%s: can't parse options: %s\n",
                        progname, options);
                return(EINVAL);
        }

        if (!force) {
                rc = check_mtab_entry(source, target, "lustre");
                if (rc && !(flags & MS_REMOUNT)) {
                        fprintf(stderr, "%s: according to %s %s is "
                                "already mounted on %s\n",
                                progname, MOUNTED, source, target);
                        return(EEXIST);
                }
                if (!rc && (flags & MS_REMOUNT)) {
                        fprintf(stderr, "%s: according to %s %s is "
                                "not already mounted on %s\n",
                                progname, MOUNTED, source, target);
                        return(ENOENT);
                }
        }
        if (flags & MS_REMOUNT) 
                nomtab++;

        rc = access(target, F_OK);
        if (rc) {
                rc = errno;
                fprintf(stderr, "%s: %s inaccessible: %s\n", progname, target,
                        strerror(errno));
                return rc;
        }

        /* In Linux 2.4, the target device doesn't get passed to any of our
           functions.  So we'll stick it on the end of the options. */
        optlen = strlen(options) + strlen(",device=") + strlen(source) + 1;
        optcopy = malloc(optlen);
        strcpy(optcopy, options);
        if (*optcopy)
                strcat(optcopy, ",");
        strcat(optcopy, "device=");
        strcat(optcopy, source);

        if (verbose) 
                printf("mounting device %s at %s, flags=%#x options=%s\n",
                       source, target, flags, optcopy);
        
        if (!fake)
                /* flags and target get to lustre_get_sb, but not 
                   lustre_fill_super.  Lustre ignores the flags, but mount 
                   does not. */
                rc = mount(source, target, "lustre", flags, (void *)optcopy);

        if (rc) {
                char *cli;

                rc = errno;

                cli = strrchr(source, ':');
                if (cli && (strlen(cli) > 2)) 
                        cli += 2;
                else
                        cli = NULL;

                fprintf(stderr, "%s: mount %s at %s failed: %s\n", progname, 
                        source, target, strerror(errno));
                if (errno == ENODEV)
                        fprintf(stderr, "Are the lustre modules loaded?\n"
                                "Check /etc/modprobe.conf and /proc/filesystems"
                                "\nNote 'alias lustre llite' should be removed"
                                " from modprobe.conf\n");
                if (errno == ENOTBLK)
                        fprintf(stderr, "Do you need -o loop?\n");
                if (errno == ENOMEDIUM)
                        fprintf(stderr, 
                                "This filesystem needs at least 1 OST\n");
                if (errno == ENOENT) {
                        fprintf(stderr, "Is the MGS specification correct?\n");
                        fprintf(stderr, "Is the filesystem name correct?\n");
                        fprintf(stderr, "If upgrading, is the copied client log"
                                " valid? (see upgrade docs)\n");
                }
                if (errno == EALREADY)
                        fprintf(stderr, "The target service is already running."
                                " (%s)\n", source);
                if (errno == ENXIO)
                        fprintf(stderr, "The target service failed to start "
                                "(bad config log?) (%s).  "
                                "See /var/log/messages.\n", source);
                if (errno == EIO)
                        fprintf(stderr, "Is the MGS running?\n");
                if (errno == EADDRINUSE)
                        fprintf(stderr, "The target service's index is already "
                                "in use. (%s)\n", source);
                if (errno == EINVAL) {
                        fprintf(stderr, "This may have multiple causes.\n");
                        if (cli) 
                                fprintf(stderr, "Is '%s' the correct filesystem"
                                        " name?\n", cli);
                        fprintf(stderr, "Are the mount options correct?\n");
                        fprintf(stderr, "Check the syslog for more info.\n");
                }

                /* May as well try to clean up loop devs */
                if (strncmp(source, "/dev/loop", 9) == 0) {
                        char cmd[256];
                        sprintf(cmd, "/sbin/losetup -d %s", source);
                        system(cmd);
                }

        } else if (!nomtab) {
                rc = update_mtab_entry(source, target, "lustre", orig_options,
                                       0,0,0);
        }

        free(optcopy);
        free(source);
        return rc;
}
