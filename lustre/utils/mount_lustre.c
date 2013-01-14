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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/mount_lustre.c
 *
 * Author: Robert Read <rread@clusterfs.com>
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <mntent.h>
#include <getopt.h>
#include "obdctl.h"
#include <lustre_ver.h>
#include <glob.h>
#include <ctype.h>
#include <limits.h>
#include "mount_utils.h"

#define MAX_HW_SECTORS_KB_PATH  "queue/max_hw_sectors_kb"
#define MAX_SECTORS_KB_PATH     "queue/max_sectors_kb"
#define STRIPE_CACHE_SIZE       "md/stripe_cache_size"
#define MAX_RETRIES 99

int          verbose = 0;
int          nomtab = 0;
int          fake = 0;
int          force = 0;
int          retry = 0;
int          md_stripe_cache_size = 16384;
char         *progname = NULL;

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
                "\t-o force|--force: force mount even if already in /etc/mtab\n"
                "\t-h|--help: print this usage message\n"
                "\t-n|--nomtab: do not update /etc/mtab after mount\n"
                "\t-v|--verbose: print verbose config settings\n"
                "\t<mntopt>: one or more comma separated of:\n"
                "\t\t(no)flock,(no)user_xattr,(no)acl\n"
                "\t\tnosvc: only start MGC/MGS obds\n"
                "\t\tnomgs: only start target obds, using existing MGS\n"
                "\t\texclude=<ostname>[:<ostname>] : colon-separated list of "
                "inactive OSTs (e.g. lustre-OST0001)\n"
                "\t\tretry=<num>: number of times mount is retried by client\n"
                "\t\tmd_stripe_cache_size=<num>: set the raid stripe cache "
                "size for the underlying raid if present\n"
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
        if (converted == NULL) {
                fprintf(stderr, "out of memory: needed %d bytes\n",
                        MAXNIDSTR);
                return NULL;
        }
        c = converted;
        while ((left > 0) && (*s1 != '/')) {
                s2 = strpbrk(s1, ",:");
                if (!s2)
                        goto out_free;
                sep = *s2;
                *s2 = '\0';
                nid = libcfs_str2nid(s1);
                *s2 = sep;                      /* back to original string */
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
  { "sync",     0, MS_SYNCHRONOUS},  /* synchronous I/O */
  { "async",    1, MS_SYNCHRONOUS},  /* asynchronous I/O */
  { "atime",    1, MS_NOATIME  },    /* set file access time on read */
  { "noatime",  0, MS_NOATIME  },    /* do not set file access time on read */
#ifdef MS_NODIRATIME
  { "diratime", 1, MS_NODIRATIME },  /* set file access time on read */
  { "nodiratime",0,MS_NODIRATIME },  /* do not set file access time on read */
#endif
#ifdef MS_RELATIME
  { "relatime", 0, MS_RELATIME },  /* set file access time on read */
  { "norelatime",1,MS_RELATIME },  /* do not set file access time on read */
#endif
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
        char *options, *opt, *nextopt, *arg, *val;

        options = calloc(strlen(orig_options) + 1, 1);
        *flagp = 0;
        nextopt = orig_options;
        while ((opt = strsep(&nextopt, ","))) {
                if (!*opt)
                        /* empty option */
                        continue;

                /* Handle retries in a slightly different
                 * manner */
                arg = opt;
                val = strchr(opt, '=');
                /* please note that some ldiskfs mount options are also in the form
                 * of param=value. We should pay attention not to remove those
                 * mount options, see bug 22097. */
                if (val && strncmp(arg, "md_stripe_cache_size", 20) == 0) {
                        md_stripe_cache_size = atoi(val + 1);
                } else if (val && strncmp(arg, "retry", 5) == 0) {
                        retry = atoi(val + 1);
                        if (retry > MAX_RETRIES)
                                retry = MAX_RETRIES;
                        else if (retry < 0)
                                retry = 0;
                } else if (strcmp(opt, "force") == 0) {
                        //XXX special check for 'force' option
                        ++force;
                        printf("force: %d\n", force);
                } else if (parse_one_option(opt, flagp) == 0) {
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


int read_file(char *path, char *buf, int size)
{
        FILE *fd;

        fd = fopen(path, "r");
        if (fd == NULL)
                return errno;

        /* should not ignore fgets(3)'s return value */
        if (!fgets(buf, size, fd)) {
                fprintf(stderr, "reading from %s: %s", path, strerror(errno));
                fclose(fd);
                return 1;
        }
        fclose(fd);
        return 0;
}

int write_file(char *path, char *buf)
{
        FILE *fd;

        fd = fopen(path, "w");
        if (fd == NULL)
                return errno;

        fputs(buf, fd);
        fclose(fd);
        return 0;
}

/* This is to tune the kernel for good SCSI performance.
 * For that we set the value of /sys/block/{dev}/queue/max_sectors_kb
 * to the value of /sys/block/{dev}/queue/max_hw_sectors_kb */
int set_blockdev_tunables(char *source)
{
        glob_t glob_info;
        struct stat stat_buf;
        char *chk_major, *chk_minor;
        char *savept = NULL, *dev;
        char *ret_path;
        char buf[PATH_MAX] = {'\0'}, path[PATH_MAX] = {'\0'};
        char real_path[PATH_MAX] = {'\0'};
        int i, rc = 0;
        int major, minor;

        if (!source)
                return -EINVAL;

        ret_path = realpath(source, real_path);
        if (ret_path == NULL) {
                if (verbose)
                        fprintf(stderr, "warning: %s: cannot resolve: %s\n",
                                source, strerror(errno));
                return -EINVAL;
        }

        if (strncmp(real_path, "/dev/loop", 9) == 0)
                return 0;

        if ((real_path[0] != '/') && (strpbrk(real_path, ",:") != NULL))
                return 0;

        snprintf(path, sizeof(path), "/sys/block%s", real_path + 4);
        if (access(path, X_OK) == 0)
                goto set_params;

        /* The name of the device say 'X' specified in /dev/X may not
         * match any entry under /sys/block/. In that case we need to
         * match the major/minor number to find the entry under
         * sys/block corresponding to /dev/X */

        /* Don't chop tail digit on /dev/mapper/xxx, LU-478 */
        if (strncmp(real_path, "/dev/mapper", 11) != 0) {
                dev = real_path + strlen(real_path);
                while (--dev > real_path && isdigit(*dev))
                        *dev = 0;

                if (strncmp(real_path, "/dev/md_", 8) == 0)
                        *dev = 0;
        }

        rc = stat(real_path, &stat_buf);
        if (rc) {
                if (verbose)
                        fprintf(stderr, "warning: %s, device %s stat failed\n",
                                strerror(errno), real_path);
                return rc;
        }

        major = major(stat_buf.st_rdev);
        minor = minor(stat_buf.st_rdev);
        rc = glob("/sys/block/*", GLOB_NOSORT, NULL, &glob_info);
        if (rc) {
                if (verbose)
                        fprintf(stderr, "warning: failed to read entries under "
                                "/sys/block\n");
                return rc;
        }

        for (i = 0; i < glob_info.gl_pathc; i++){
                snprintf(path, sizeof(path), "%s/dev", glob_info.gl_pathv[i]);

                rc = read_file(path, buf, sizeof(buf));
                if (rc)
                        continue;

                if (buf[strlen(buf) - 1] == '\n')
                        buf[strlen(buf) - 1] = '\0';

                chk_major = strtok_r(buf, ":", &savept);
                chk_minor = savept;
                if (major == atoi(chk_major) &&minor == atoi(chk_minor))
                        break;
        }

        if (i == glob_info.gl_pathc) {
                if (verbose)
                        fprintf(stderr,"warning: device %s does not match any "
                                "entry under /sys/block\n", real_path);
                globfree(&glob_info);
                return -EINVAL;
        }

        /* Chop off "/dev" from path we found */
        path[strlen(glob_info.gl_pathv[i])] = '\0';
        globfree(&glob_info);

set_params:
        if (strncmp(real_path, "/dev/md", 7) == 0) {
                snprintf(real_path, sizeof(real_path), "%s/%s", path,
                         STRIPE_CACHE_SIZE);

                rc = read_file(real_path, buf, sizeof(buf));
                if (rc) {
                        if (verbose)
                                fprintf(stderr, "warning: opening %s: %s\n",
                                        real_path, strerror(errno));
                        return rc;
                }

                if (atoi(buf) >= md_stripe_cache_size)
                        return 0;

                if (strlen(buf) - 1 > 0) {
                        snprintf(buf, sizeof(buf), "%d", md_stripe_cache_size);
                        rc = write_file(real_path, buf);
                        if (rc && verbose)
                                fprintf(stderr, "warning: opening %s: %s\n",
                                        real_path, strerror(errno));
                }
                /* Return since raid and disk tunables are different */
                return rc;
        }

        snprintf(real_path, sizeof(real_path), "%s/%s", path,
                 MAX_HW_SECTORS_KB_PATH);
        rc = read_file(real_path, buf, sizeof(buf));
        if (rc) {
                if (verbose)
                        fprintf(stderr, "warning: opening %s: %s\n",
                                real_path, strerror(errno));
                /* No MAX_HW_SECTORS_KB_PATH isn't necessary an
                 * error for some device. */
                rc = 0;
        }

        if (strlen(buf) - 1 > 0) {
                snprintf(real_path, sizeof(real_path), "%s/%s", path,
                         MAX_SECTORS_KB_PATH);
                rc = write_file(real_path, buf);
                if (rc && verbose)
                        fprintf(stderr, "warning: writing to %s: %s\n",
                                real_path, strerror(errno));
                /* No MAX_HW_SECTORS_KB_PATH isn't necessary an
                 * error for some device. */
                rc = 0;
        }
        return rc;
}

int main(int argc, char *const argv[])
{
        char default_options[] = "";
        char *usource, *source;
        char target[PATH_MAX] = {'\0'};
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

        usource = argv[optind];
        if (!usource) {
                usage(stderr);
        }

        source = convert_hostnames(usource);
        if (!source) {
                usage(stderr);
        }

        if (realpath(argv[optind + 1], target) == NULL) {
                rc = errno;
                fprintf(stderr, "warning: %s: cannot resolve: %s\n",
                        argv[optind + 1], strerror(errno));
                return rc;
        }

        if (verbose) {
                for (i = 0; i < argc; i++)
                        printf("arg[%d] = %s\n", i, argv[i]);
                printf("source = %s (%s), target = %s\n", usource, source, target);
                printf("options = %s\n", orig_options);
        }

        options = malloc(strlen(orig_options) + 1);
        if (options == NULL) {
                fprintf(stderr, "can't allocate memory for options\n");
                return -1;
        }
        strcpy(options, orig_options);
        rc = parse_options(options, &flags);
        if (rc) {
                fprintf(stderr, "%s: can't parse options: %s\n",
                        progname, options);
                return(EINVAL);
        }

        if (!force) {
                rc = check_mtab_entry(usource, target, "lustre");
                if (rc && !(flags & MS_REMOUNT)) {
                        fprintf(stderr, "%s: according to %s %s is "
                                "already mounted on %s\n",
                                progname, MOUNTED, usource, target);
                        return(EEXIST);
                }
                if (!rc && (flags & MS_REMOUNT)) {
                        fprintf(stderr, "%s: according to %s %s is "
                                "not already mounted on %s\n",
                                progname, MOUNTED, usource, target);
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
        if (optcopy == NULL) {
                fprintf(stderr, "can't allocate memory to optcopy\n");
                return -1;
        }
        strcpy(optcopy, options);
        if (*optcopy)
                strcat(optcopy, ",");
        strcat(optcopy, "device=");
        strcat(optcopy, source);

        if (verbose)
                printf("mounting device %s at %s, flags=%#x options=%s\n",
                       source, target, flags, optcopy);

        if (!strstr(usource, ":/") && set_blockdev_tunables(source)) {
                if (verbose)
                        fprintf(stderr, "%s: unable to set tunables for %s"
                                " (may cause reduced IO performance)\n",
                                argv[0], source);
        }

        register_service_tags(usource, source, target);

        if (!fake) {
                /* flags and target get to lustre_get_sb, but not
                   lustre_fill_super.  Lustre ignores the flags, but mount
                   does not. */
                for (i = 0, rc = -EAGAIN; i <= retry && rc != 0; i++) {
                        rc = mount(source, target, "lustre", flags,
                                   (void *)optcopy);
                        if (rc) {
                                if (verbose) {
                                        fprintf(stderr, "%s: mount %s at %s "
                                                "failed: %s retries left: "
                                                "%d\n", basename(progname),
                                                usource, target,
                                                strerror(errno), retry-i);
                                }

                                if (retry) {
                                        sleep(1 << max((i/2), 5));
                                }
                                else {
                                        rc = errno;
                                }
                        }
                }
        }

        if (rc) {
                char *cli;

                rc = errno;

                cli = strrchr(usource, ':');
                if (cli && (strlen(cli) > 2))
                        cli += 2;
                else
                        cli = NULL;

                fprintf(stderr, "%s: mount %s at %s failed: %s\n", progname,
                        usource, target, strerror(errno));
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
                                " (%s)\n", usource);
                if (errno == ENXIO)
                        fprintf(stderr, "The target service failed to start "
                                "(bad config log?) (%s).  "
                                "See /var/log/messages.\n", usource);
                if (errno == EIO)
                        fprintf(stderr, "Is the MGS running?\n");
                if (errno == EADDRINUSE)
                        fprintf(stderr, "The target service's index is already "
                                "in use. (%s)\n", usource);
                if (errno == EINVAL) {
                        fprintf(stderr, "This may have multiple causes.\n");
                        if (cli)
                                fprintf(stderr, "Is '%s' the correct filesystem"
                                        " name?\n", cli);
                        fprintf(stderr, "Are the mount options correct?\n");
                        fprintf(stderr, "Check the syslog for more info.\n");
                }

                /* May as well try to clean up loop devs */
                if (strncmp(usource, "/dev/loop", 9) == 0) {
                        char cmd[256];
                        int ret;
                        sprintf(cmd, "/sbin/losetup -d %s", usource);
                        if ((ret = system(cmd)) < 0)
                                rc = errno;
                        else if (ret > 0)
                                rc = WEXITSTATUS(ret);
                }

        } else if (!nomtab) {
                rc = update_mtab_entry(usource, target, "lustre", orig_options,
                                       0,0,0);
        }

        free(optcopy);
        free(source);
        return rc;
}
