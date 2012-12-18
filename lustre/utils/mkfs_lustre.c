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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/mkfs_lustre.c
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
*/

/* This source file is compiled into both mkfs.lustre and tunefs.lustre */

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <mntent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>

#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <ctype.h>

#ifdef __linux__
/* libcfs.h is not really needed here, but on SLES10/PPC, fs.h includes idr.h
 * which requires BITS_PER_LONG to be defined */
#include <libcfs/libcfs.h>
#ifndef BLKGETSIZE64
#include <linux/fs.h> /* for BLKGETSIZE64 */
#endif
#include <linux/version.h>
#endif
#include <lustre_disk.h>
#include <lustre_param.h>
#include <lnet/lnetctl.h>
#include <lustre_ver.h>
#include "mount_utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_LOOP_DEVICES 16
#define L_BLOCK_SIZE 4096
#define INDEX_UNASSIGNED 0xFFFF
#define MO_IS_LOOP     0x01
#define MO_FORCEFORMAT 0x02

/* used to describe the options to format the lustre disk, not persistent */
struct mkfs_opts {
        struct lustre_disk_data mo_ldd; /* to be written in MOUNT_DATA_FILE */
        char  mo_device[128];           /* disk device name */
        char  mo_loopdev[128];          /* in case a loop dev is needed */
        char  mo_mkfsopts[512];         /* options to the backing-store mkfs */
        __u64 mo_device_sz;             /* in KB */
        int   mo_stripe_count;
        int   mo_flags;
        int   mo_mgs_failnodes;
};

char *progname;
int verbose = 1;
static int print_only = 0;
static int failover = 0;
static int upgrade_to_18 = 0;

void usage(FILE *out)
{
        fprintf(out, "%s v"LUSTRE_VERSION_STRING"\n", progname);
        fprintf(out, "usage: %s <target types> [options] <device>\n", progname);
        fprintf(out,
                "\t<device>:block device or file (e.g /dev/sda or /tmp/ost1)\n"
                "\ttarget types:\n"
                "\t\t--ost: object storage, mutually exclusive with mdt,mgs\n"
                "\t\t--mdt: metadata storage, mutually exclusive with ost\n"
                "\t\t--mgs: configuration management service - one per site\n"
                "\toptions (in order of popularity):\n"
                "\t\t--mgsnode=<nid>[,<...>] : NID(s) of a remote mgs node\n"
                "\t\t\trequired for all targets other than the mgs node\n"
                "\t\t--fsname=<filesystem_name> : default is 'lustre'\n"
                "\t\t--failnode=<nid>[,<...>] : NID(s) of a failover partner\n"
                "\t\t\tcannot be used with --servicenode\n"
                "\t\t--servicenode=<nid>[,<...>] : NID(s) of all service partners\n"
                "\t\t\ttreat all nodes as equal service node, cannot be used with --failnode\n"
                "\t\t--param <key>=<value> : set a permanent parameter\n"
                "\t\t\te.g. --param sys.timeout=40\n"
                "\t\t\t     --param lov.stripesize=2M\n"
                "\t\t--index=#N : target index (i.e. ost index within lov)\n"
                "\t\t--comment=<user comment>: arbitrary string (%d bytes)\n"
                "\t\t--mountfsoptions=<opts> : permanent mount options\n"
                "\t\t--network=<net>[,<...>] : restrict OST/MDT to network(s)\n"
#ifndef TUNEFS
                "\t\t--backfstype=<fstype> : backing fs type (ext3, ldiskfs)\n"
                "\t\t--device-size=#N(KB) : device size for loop devices\n"
                "\t\t--mkfsoptions=<opts> : format options\n"
                "\t\t--reformat: overwrite an existing disk\n"
                "\t\t--stripe-count-hint=#N : for optimizing MDT inode size\n"
                "\t\t--iam-dir: use IAM directory format, not ext3 compatible\n"
#else
                "\t\t--erase-params : erase all old parameter settings\n"
                "\t\t--nomgs: turn off MGS service on this MDT\n"
                "\t\t--writeconf: erase all config logs for this fs.\n"
#endif
                "\t\t--dryrun: just report what we would do; "
                "don't write to disk\n"
                "\t\t--verbose : e.g. show mkfs progress\n"
                "\t\t--quiet\n",
                (int)sizeof(((struct lustre_disk_data *)0)->ldd_userdata));
        return;
}

#define vprint if (verbose > 0) printf
#define verrprint if (verbose >= 0) printf

/*================ utility functions =====================*/

char *strscat(char *dst, char *src, int buflen) {
        dst[buflen - 1] = 0;
        if (strlen(dst) + strlen(src) >= buflen) {
                fprintf(stderr, "string buffer overflow (max %d): '%s' + '%s'"
                        "\n", buflen, dst, src);
                exit(EOVERFLOW);
        }
        return strcat(dst, src);

}

char *strscpy(char *dst, char *src, int buflen) {
        dst[0] = 0;
        return strscat(dst, src, buflen);
}

inline unsigned int
dev_major (unsigned long long int __dev)
{
        return ((__dev >> 8) & 0xfff) | ((unsigned int) (__dev >> 32) & ~0xfff);
}

inline unsigned int
dev_minor (unsigned long long int __dev)
{
        return (__dev & 0xff) | ((unsigned int) (__dev >> 12) & ~0xff);
}

int get_os_version()
{
        static int version = 0;

        if (!version) {
                int fd;
                char release[4] = "";

                fd = open("/proc/sys/kernel/osrelease", O_RDONLY);
                if (fd < 0) {
                        fprintf(stderr, "%s: Warning: Can't resolve kernel "
                                "version, assuming 2.6\n", progname);
                } else {
                        if (read(fd, release, 4) < 0) {
                                fprintf(stderr, "reading from /proc/sys/kernel"
                                        "/osrelease: %s\n", strerror(errno));
                                close(fd);
                                exit(-1);
                        }
                        close(fd);
                }
                if (strncmp(release, "2.4.", 4) == 0)
                        version = 24;
                else
                        version = 26;
        }
        return version;
}

static int check_mtab_entry(char *spec)
{
        FILE *fp;
        struct mntent *mnt;

        fp = setmntent(MOUNTED, "r");
        if (fp == NULL)
                return(0);

        while ((mnt = getmntent(fp)) != NULL) {
                if (strcmp(mnt->mnt_fsname, spec) == 0) {
                        endmntent(fp);
                        fprintf(stderr, "%s: according to %s %s is "
                                "already mounted on %s\n",
                                progname, MOUNTED, spec, mnt->mnt_dir);
                        return(EEXIST);
                }
        }
        endmntent(fp);

        return(0);
}

/*============ disk dev functions ===================*/

/* Setup a file in the first unused loop_device */
int loop_setup(struct mkfs_opts *mop)
{
        char loop_base[20];
        char l_device[64];
        int i, ret = 0;

        /* Figure out the loop device names */
        if (!access("/dev/loop0", F_OK | R_OK)) {
                strcpy(loop_base, "/dev/loop\0");
        } else if (!access("/dev/loop/0", F_OK | R_OK)) {
                strcpy(loop_base, "/dev/loop/\0");
        } else {
                fprintf(stderr, "%s: can't access loop devices\n", progname);
                return EACCES;
        }

        /* Find unused loop device */
        for (i = 0; i < MAX_LOOP_DEVICES; i++) {
                char cmd[PATH_MAX];
                int cmdsz = sizeof(cmd);

                sprintf(l_device, "%s%d", loop_base, i);
                if (access(l_device, F_OK | R_OK))
                        break;
                snprintf(cmd, cmdsz, "losetup %s > /dev/null 2>&1", l_device);
                ret = system(cmd);

                /* losetup gets 1 (ret=256) for non-set-up device */
                if (ret) {
                        /* Set up a loopback device to our file */
                        snprintf(cmd, cmdsz, "losetup %s %s", l_device,
                                 mop->mo_device);
                        ret = run_command(cmd, cmdsz);
                        if (ret == 256)
                                /* someone else picked up this loop device
                                 * behind our back */
                                continue;
                        if (ret) {
                                fprintf(stderr, "%s: error %d on losetup: %s\n",
                                        progname, ret, strerror(ret));
                                return ret;
                        }
                        strscpy(mop->mo_loopdev, l_device,
                                sizeof(mop->mo_loopdev));
                        return ret;
                }
        }

        fprintf(stderr, "%s: out of loop devices!\n", progname);
        return EMFILE;
}

int loop_cleanup(struct mkfs_opts *mop)
{
        char cmd[150];
        int ret = 1;
        if ((mop->mo_flags & MO_IS_LOOP) && *mop->mo_loopdev) {
                sprintf(cmd, "losetup -d %s", mop->mo_loopdev);
                ret = run_command(cmd, sizeof(cmd));
        }
        return ret;
}

/* Determine if a device is a block device (as opposed to a file) */
int is_block(char* devname)
{
        struct stat st;
        int ret = 0;

        ret = access(devname, F_OK);
        if (ret != 0)
                return 0;
        ret = stat(devname, &st);
        if (ret != 0) {
                fprintf(stderr, "%s: cannot stat %s\n", progname, devname);
                return -1;
        }
        return S_ISBLK(st.st_mode);
}

__u64 get_device_size(char* device)
{
        int ret, fd;
        __u64 size = 0;

        fd = open(device, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "%s: cannot open %s: %s\n",
                        progname, device, strerror(errno));
                return 0;
        }

#ifdef BLKGETSIZE64
        /* size in bytes. bz5831 */
        ret = ioctl(fd, BLKGETSIZE64, (void*)&size);
#else
        {
                __u32 lsize = 0;
                /* size in blocks */
                ret = ioctl(fd, BLKGETSIZE, (void*)&lsize);
                size = (__u64)lsize * 512;
        }
#endif
        close(fd);
        if (ret < 0) {
                fprintf(stderr, "%s: size ioctl failed: %s\n",
                        progname, strerror(errno));
                return 0;
        }

        vprint("device size = "LPU64"MB\n", size >> 20);
        /* return value in KB */
        return size >> 10;
}

int loop_format(struct mkfs_opts *mop)
{
        int ret = 0;

        if (mop->mo_device_sz == 0) {
                fatal();
                fprintf(stderr, "loop device requires a --device-size= "
                        "param\n");
                return EINVAL;
        }

        ret = creat(mop->mo_device, S_IRUSR|S_IWUSR);
        if (ret < 0) {
                ret = errno;
                fprintf(stderr, "%s: Unable to create backing store: %d\n",
                        progname, ret);
        } else {
                close(ret);
        }

        ret = truncate(mop->mo_device, mop->mo_device_sz * 1024);
        if (ret != 0) {
                ret = errno;
                fprintf(stderr, "%s: Unable to truncate backing store: %d\n",
                        progname, ret);
        }

        return ret;
}

/* Display the need for the latest e2fsprogs to be installed. make_backfs
 * indicates if the caller is make_lustre_backfs() or not. */
static void disp_old_e2fsprogs_msg(const char *feature, int make_backfs)
{
        static int msg_displayed;

        if (msg_displayed) {
                fprintf(stderr, "WARNING: %s does not support %s "
                        "feature.\n\n", E2FSPROGS, feature);
                return;
        }

        msg_displayed++;

        fprintf(stderr, "WARNING: The %s package currently installed on "
                "your system does not support \"%s\" feature.\n",
                E2FSPROGS, feature);
#if !(HAVE_LDISKFSPROGS)
        fprintf(stderr, "Please install the latest version of e2fsprogs from\n"
                "http://downloads.whamcloud.com/public/e2fsprogs/latest/\n"
                "to enable this feature.\n");
#endif
        if (make_backfs)
                fprintf(stderr, "Feature will not be enabled until %s"
                        "is updated and '%s -O %s %%{device}' "
                        "is run.\n\n", E2FSPROGS, TUNE2FS, feature);
}

/* Check whether the file exists in the device */
static int file_in_dev(char *file_name, char *dev_name)
{
        FILE *fp;
        char debugfs_cmd[256];
        unsigned int inode_num;
        int i;

        /* Construct debugfs command line. */
        snprintf(debugfs_cmd, sizeof(debugfs_cmd),
                "%s -c -R 'stat %s' '%s' 2>&1 | egrep '(Inode|unsupported)'",
                DEBUGFS, file_name, dev_name);

        fp = popen(debugfs_cmd, "r");
        if (!fp) {
                fprintf(stderr, "%s: %s\n", progname, strerror(errno));
                return 0;
        }

        if (fscanf(fp, "Inode: %u", &inode_num) == 1) { /* exist */
                pclose(fp);
                return 1;
        }
        i = fread(debugfs_cmd, 1, sizeof(debugfs_cmd), fp);
        if (i) {
                debugfs_cmd[i] = 0;
                fprintf(stderr, "%s", debugfs_cmd);
                if (strstr(debugfs_cmd, "unsupported feature")) {
                          disp_old_e2fsprogs_msg("an unknown", 0);
                }
                pclose(fp);
                return -1;
        }
        pclose(fp);
        return 0;
}

/* Check whether the device has already been used with lustre */
static int is_lustre_target(struct mkfs_opts *mop)
{
        int rc;

        vprint("checking for existing Lustre data: ");

        if ((rc = file_in_dev(MOUNT_DATA_FILE, mop->mo_device))) {
                vprint("found %s\n",
                       (rc == 1) ? MOUNT_DATA_FILE : "extents");
                 /* in the -1 case, 'extents' means this really IS a lustre
                    target */
                return rc;
        }

        if ((rc = file_in_dev(LAST_RCVD, mop->mo_device))) {
                vprint("found %s\n", LAST_RCVD);
                return rc;
        }

        vprint("not found\n");
        return 0; /* The device is not a lustre target. */
}

/* Check if a certain feature is supported by e2fsprogs.
 * Firstly we try to use "debugfs supported_features" command to check if
 * the feature is supported. If this fails we try to set this feature with
 * mke2fs to check for its support. */
static int is_e2fsprogs_feature_supp(const char *feature)
{
        static char supp_features[4096] = "";
        FILE *fp;
        char cmd[PATH_MAX];
        char imgname[] = "/tmp/test-img-XXXXXX";
        int fd = -1;
        int ret = 1;

        if (supp_features[0] == '\0') {
                snprintf(cmd, sizeof(cmd), "%s -c -R supported_features 2>&1",
                         DEBUGFS);

                /* Using popen() instead of run_command() since debugfs does
                 * not return proper error code if command is not supported */
                fp = popen(cmd, "r");
                if (!fp) {
                        fprintf(stderr, "%s: %s\n", progname, strerror(errno));
                        return 0;
                }
                ret = fread(supp_features, 1, sizeof(supp_features), fp);
                fclose(fp);
        }
        if (ret > 0 && strstr(supp_features,
                              strncmp(feature, "-O ", 3) ? feature : feature+3))
                return 0;

        if ((fd = mkstemp(imgname)) < 0)
                return -1;
        else
                close(fd);

        snprintf(cmd, sizeof(cmd), "%s -F %s %s 100 >/dev/null 2>&1",
                 MKE2FS, feature, imgname);
        /* run_command() displays the output of mke2fs when it fails for
         * some feature, so use system() directly */
        ret = system(cmd);
        unlink(imgname);

        return ret;
}

/**
 * append_unique: append @key or @key=@val pair to @buf only if @key does not
 *                exists
 *      @buf: buffer to hold @key or @key=@val
 *      @prefix: prefix string before @key
 *      @key: key string
 *      @val: value string if it's a @key=@val pair
 */
static void append_unique(char *buf, char *prefix, char *key, char *val,
                          size_t maxbuflen)
{
        char *anchor, *end;
        int  len;

        if (key == NULL)
                return;

        anchor = end = strstr(buf, key);
        /* try to find exact match string in @buf */
        while (end && *end != '\0' && *end != ',' && *end != ' ' && *end != '=')
                ++end;
        len = end - anchor;
        if (anchor == NULL || strlen(key) != len ||
            strncmp(anchor, key, len) != 0) {
                if (prefix != NULL)
                        strscat(buf, prefix, maxbuflen);

                strscat(buf, key, maxbuflen);
                if (val != NULL) {
                        strscat(buf, "=", maxbuflen);
                        strscat(buf, val, maxbuflen);
                }
        }
}

static void enable_default_ext4_features(struct mkfs_opts *mop, char *anchor,
                                         size_t maxbuflen, int user_spec)
{
        if (IS_OST(&mop->mo_ldd)) {
                append_unique(anchor, user_spec ? "," : " -O ",
                              "extents", NULL, sizeof(mop->mo_mkfsopts));
                append_unique(anchor, ",", "uninit_bg", NULL, maxbuflen);
        } else if (IS_MDT(&mop->mo_ldd)) {
                append_unique(anchor, user_spec ? "," : " -O ",
                              "dirdata", NULL, maxbuflen);
                append_unique(anchor, ",", "uninit_bg", NULL, maxbuflen);
		append_unique(anchor, ",", "^extents", NULL, maxbuflen);
        } else {
                append_unique(anchor, user_spec ? "," : " -O ",
                              "uninit_bg", NULL, maxbuflen);
        }

        /* Multiple mount protection enabled only if failover node specified */
        if (failover) {
                if (is_e2fsprogs_feature_supp("-O mmp") == 0)
                        append_unique(anchor, ",", "mmp", NULL, maxbuflen);
                else
                        disp_old_e2fsprogs_msg("mmp", 1);
        }

        /* Allow more than 65000 subdirectories */
        if (is_e2fsprogs_feature_supp("-O dir_nlink") == 0)
                append_unique(anchor, ",", "dir_nlink", NULL, maxbuflen);

#ifdef HAVE_EXT4_LDISKFS
        /* The following options are only valid for ext4-based ldiskfs.
         * If --backfstype=ext3 is specified, do not enable them. */
        if (mop->mo_ldd.ldd_mount_type == LDD_MT_EXT3)
                return;

        /* Allow files larger than 2TB.  Also needs LU-16, but not harmful. */
        if (is_e2fsprogs_feature_supp("-O huge_file") == 0)
                append_unique(anchor, ",", "huge_file", NULL, maxbuflen);

        /* Enable large block addresses if the LUN is over 2^32 blocks. */
        if (mop->mo_device_sz / (L_BLOCK_SIZE >> 10) >= 0x100002000ULL &&
                    is_e2fsprogs_feature_supp("-O 64bit") == 0)
                append_unique(anchor, ",", "64bit", NULL, maxbuflen);

        /* Cluster inode/block bitmaps and inode table for more efficient IO.
         * Align the flex groups on a 1MB boundary for better performance. */
        /* This -O feature needs to go last, since it adds the "-G" option. */
        if (is_e2fsprogs_feature_supp("-O flex_bg") == 0) {
                char tmp_buf[64];

                append_unique(anchor, ",", "flex_bg", NULL, maxbuflen);

                if (IS_OST(&mop->mo_ldd)) {
                        snprintf(tmp_buf, sizeof(tmp_buf), " -G %u",
                                 (1 << 20) / L_BLOCK_SIZE);
                        strscat(anchor, tmp_buf, maxbuflen);
                }
        }
        /* Don't add any more "-O" options here, see last comment above */
#endif
}

/**
 * moveopts_to_end: find the option string, move remaining strings to
 *                  where option string starts, and append the option
 *                  string at the end
 *      @start: where the option string starts before the move
 *      RETURN: where the option string starts after the move
 */
static char *moveopts_to_end(char *start)
{
        char save[512];
        char *end, *idx;

        /* skip whitespace before options */
        end = start + 2;
        while (*end == ' ')
                ++end;

        /* find end of option characters */
        while (*end != ' ' && *end != '\0')
                ++end;

        /* save options */
        strncpy(save, start, end - start);
        save[end - start] = '\0';

        /* move remaining options up front */
        if (*end)
                memmove(start, end, strlen(end));
        *(start + strlen(end)) = '\0';

        /* append the specified options */
        if (*(start + strlen(start) - 1) != ' ')
                strcat(start, " ");
        idx = start + strlen(start);
        strcat(start, save);

        return idx;
}

/* Build fs according to type */
int make_lustre_backfs(struct mkfs_opts *mop)
{
        __u64 device_sz = mop->mo_device_sz, block_count = 0;
        char mkfs_cmd[PATH_MAX];
        char buf[64];
        char *start;
        char *dev;
        int ret = 0, ext_opts = 0;
        size_t maxbuflen;

        if (!(mop->mo_flags & MO_IS_LOOP)) {
                mop->mo_device_sz = get_device_size(mop->mo_device);

                if (mop->mo_device_sz == 0)
                        return ENODEV;

                /* Compare to real size */
                if (device_sz == 0 || device_sz > mop->mo_device_sz)
                        device_sz = mop->mo_device_sz;
                else
                        mop->mo_device_sz = device_sz;
        }

        if (mop->mo_device_sz != 0) {
                if (mop->mo_device_sz < 8096){
                        fprintf(stderr, "%s: size of filesystem must be larger "
                                "than 8MB, but is set to %lldKB\n",
                                progname, (long long)mop->mo_device_sz);
                        return EINVAL;
                }
                block_count = mop->mo_device_sz / (L_BLOCK_SIZE >> 10);
                /* If the LUN size is just over 2^32 blocks, limit the
                 * filesystem size to 2^32-1 blocks to avoid problems with
                 * ldiskfs/mkfs not handling this size.  Bug 22906 */
                if (block_count > 0xffffffffULL && block_count < 0x100002000ULL)
                        block_count = 0xffffffffULL;
        }

        if ((mop->mo_ldd.ldd_mount_type == LDD_MT_EXT3) ||
            (mop->mo_ldd.ldd_mount_type == LDD_MT_LDISKFS) ||
            (mop->mo_ldd.ldd_mount_type == LDD_MT_LDISKFS2)) {
                long inode_size = 0;

                /* Journal size in MB */
                if (strstr(mop->mo_mkfsopts, "-J") == NULL) {
                        /* Choose our own default journal size */
                        long journal_sz = 0, max_sz;
                        if (device_sz > 1024 * 1024) /* 1GB */
                                journal_sz = (device_sz / 102400) * 4;
                        /* cap journal size at 1GB */
                        if (journal_sz > 1024L)
                                journal_sz = 1024L;
                        /* man mkfs.ext3 */
                        max_sz = (102400 * L_BLOCK_SIZE) >> 20; /* 400MB */
                        if (journal_sz > max_sz)
                                journal_sz = max_sz;
                        if (journal_sz) {
                                sprintf(buf, " -J size=%ld", journal_sz);
                                strscat(mop->mo_mkfsopts, buf,
                                        sizeof(mop->mo_mkfsopts));
                        }
                }

                /* Inode size (for extended attributes).  The LOV EA size is
                 * 32 (EA hdr) + 32 (lov_mds_md) + stripes * 24 (lov_ost_data),
                 * and we want some margin above that for ACLs, other EAs... */
                if (strstr(mop->mo_mkfsopts, "-I") == NULL) {
                        if (IS_MDT(&mop->mo_ldd)) {
                                if (mop->mo_stripe_count > 72)
                                        inode_size = 512; /* bz 7241 */
                                        /* see also "-i" below for EA blocks */
                                else if (mop->mo_stripe_count > 32)
                                        inode_size = 2048;
                                else if (mop->mo_stripe_count > 10)
                                        inode_size = 1024;
                                else
                                        inode_size = 512;
                        } else if (IS_OST(&mop->mo_ldd)) {
                                /* We store MDS FID and OST objid in EA on OST
                                 * we need to make inode bigger as well. */
                                inode_size = 256;
                        }

                        if (inode_size > 0) {
                                sprintf(buf, " -I %ld", inode_size);
                                strscat(mop->mo_mkfsopts, buf,
                                        sizeof(mop->mo_mkfsopts));
                        }
                }

                /* Bytes_per_inode: disk size / num inodes */
                if (strstr(mop->mo_mkfsopts, "-i") == NULL &&
                    strstr(mop->mo_mkfsopts, "-N") == NULL) {
                        long bytes_per_inode = 0;

                        /* Allocate more inodes on MDT devices.  There is
                         * no data stored on the MDT, and very little extra
                         * metadata beyond the inode.  It could go down as
                         * low as 1024 bytes, but this is conservative.
                         * Account for external EA blocks for wide striping. */
                        if (IS_MDT(&mop->mo_ldd)) {
                                bytes_per_inode = inode_size + 1536;

                                if (mop->mo_stripe_count > 72) {
                                        int extra = mop->mo_stripe_count * 24;
                                        extra = ((extra - 1) | 4095) + 1;
                                        bytes_per_inode += extra;
                                }
                        }

                        /* Allocate fewer inodes on large OST devices.  Most
                         * filesystems can be much more aggressive than even
                         * this, but it is impossible to know in advance. */
                        if (IS_OST(&mop->mo_ldd)) {
                                /* OST > 16TB assume average file size 1MB */
                                if (device_sz > (16ULL << 30))
                                        bytes_per_inode = 1024 * 1024;
                                /* OST > 4TB assume average file size 512kB */
                                else if (device_sz > (4ULL << 30))
                                        bytes_per_inode = 512 * 1024;
                                /* OST > 1TB assume average file size 256kB */
                                else if (device_sz > (1ULL << 30))
                                        bytes_per_inode = 256 * 1024;
                                /* OST > 10GB assume average file size 64kB,
                                 * plus a bit so that inodes will fit into a
                                 * 256x flex_bg without overflowing */
                                else if (device_sz > (10ULL << 20))
                                        bytes_per_inode = 69905;
                        }

                        if (bytes_per_inode > 0) {
                                sprintf(buf, " -i %ld", bytes_per_inode);
                                strscat(mop->mo_mkfsopts, buf,
                                        sizeof(mop->mo_mkfsopts));
                        }
                }

                if (verbose < 2) {
                        strscat(mop->mo_mkfsopts, " -q",
                                sizeof(mop->mo_mkfsopts));
                }

                /* start handle -O mkfs options */
                if ((start = strstr(mop->mo_mkfsopts, "-O")) != NULL) {
                        if (strstr(start + 2, "-O") != NULL) {
                                fprintf(stderr,
                                        "%s: don't specify multiple -O options\n",
                                        progname);
                                return EINVAL;
                        }
                        start = moveopts_to_end(start);
                        maxbuflen = sizeof(mop->mo_mkfsopts) -
                                    (start - mop->mo_mkfsopts) - strlen(start);
                        enable_default_ext4_features(mop, start, maxbuflen, 1);
                } else {
                        start = mop->mo_mkfsopts + strlen(mop->mo_mkfsopts),
                        maxbuflen = sizeof(mop->mo_mkfsopts) -
                                    strlen(mop->mo_mkfsopts);
                        enable_default_ext4_features(mop, start, maxbuflen, 0);
                }
                /* end handle -O mkfs options */

                /* start handle -E mkfs options */
                if ((start = strstr(mop->mo_mkfsopts, "-E")) != NULL) {
                        if (strstr(start + 2, "-E") != NULL) {
                                fprintf(stderr,
                                        "%s: don't specify multiple -E options\n",
                                        progname);
                                return EINVAL;
                        }
                        start = moveopts_to_end(start);
                        maxbuflen = sizeof(mop->mo_mkfsopts) -
                                    (start - mop->mo_mkfsopts) - strlen(start);
                        ext_opts = 1;
                } else {
                        start = mop->mo_mkfsopts + strlen(mop->mo_mkfsopts);
                        maxbuflen = sizeof(mop->mo_mkfsopts) -
                                    strlen(mop->mo_mkfsopts);
                }

                /* In order to align the filesystem metadata on 1MB boundaries,
                 * give a resize value that will reserve a power-of-two group
                 * descriptor blocks, but leave one block for the superblock.
                 * Only useful for filesystems with < 2^32 blocks due to resize
                 * limitations. */
                if (IS_OST(&mop->mo_ldd) && mop->mo_device_sz > 100 * 1024 &&
                    mop->mo_device_sz * 1024 / L_BLOCK_SIZE <= 0xffffffffULL) {
                        unsigned group_blocks = L_BLOCK_SIZE * 8;
                        unsigned desc_per_block = L_BLOCK_SIZE / 32;
                        unsigned resize_blks;

                        resize_blks = (1ULL<<32) - desc_per_block*group_blocks;
                        snprintf(buf, sizeof(buf), "%u", resize_blks);
                        append_unique(start, ext_opts ? "," : " -E ",
                                      "resize", buf, maxbuflen);
                        ext_opts = 1;
                }

                /* Avoid zeroing out the full journal - speeds up mkfs */
                if (is_e2fsprogs_feature_supp("-E lazy_journal_init") == 0)
                        append_unique(start, ext_opts ? "," : " -E ",
                                      "lazy_journal_init", NULL, maxbuflen);
                /* end handle -E mkfs options */

                /* Allow reformat of full devices (as opposed to
                   partitions.)  We already checked for mounted dev. */
                strscat(mop->mo_mkfsopts, " -F", sizeof(mop->mo_mkfsopts));

                snprintf(mkfs_cmd, sizeof(mkfs_cmd),
                         "%s -j -b %d -L %s ", MKE2FS, L_BLOCK_SIZE,
                         mop->mo_ldd.ldd_svname);
        } else {
                fprintf(stderr,"%s: unsupported fs type: %d (%s)\n",
                        progname, mop->mo_ldd.ldd_mount_type,
                        MT_STR(&mop->mo_ldd));
                return EINVAL;
        }

        /* For loop device format the dev, not the filename */
        dev = mop->mo_device;
        if (mop->mo_flags & MO_IS_LOOP)
                dev = mop->mo_loopdev;

        vprint("formatting backing filesystem %s on %s\n",
               MT_STR(&mop->mo_ldd), dev);
        vprint("\ttarget name  %s\n", mop->mo_ldd.ldd_svname);
        vprint("\t4k blocks     "LPU64"\n", block_count);
        vprint("\toptions       %s\n", mop->mo_mkfsopts);

        /* mkfs_cmd's trailing space is important! */
        strscat(mkfs_cmd, mop->mo_mkfsopts, sizeof(mkfs_cmd));
        strscat(mkfs_cmd, " ", sizeof(mkfs_cmd));
        strscat(mkfs_cmd, dev, sizeof(mkfs_cmd));
        if (block_count != 0) {
                sprintf(buf, " "LPU64, block_count);
                strscat(mkfs_cmd, buf, sizeof(mkfs_cmd));
        }

        vprint("mkfs_cmd = %s\n", mkfs_cmd);
        ret = run_command(mkfs_cmd, sizeof(mkfs_cmd));
        if (ret) {
                fatal();
                fprintf(stderr, "Unable to build fs %s (%d)\n", dev, ret);
        }
        return ret;
}

/* ==================== Lustre config functions =============*/

void print_ldd(char *str, struct lustre_disk_data *ldd)
{
        printf("\n   %s:\n", str);
        printf("Target:     %s\n", ldd->ldd_svname);
        if (ldd->ldd_svindex == INDEX_UNASSIGNED)
                printf("Index:      unassigned\n");
        else
                printf("Index:      %d\n", ldd->ldd_svindex);
        if (ldd->ldd_uuid[0])
                printf("UUID:       %s\n", (char *)ldd->ldd_uuid);
        printf("Lustre FS:  %s\n", ldd->ldd_fsname);
        printf("Mount type: %s\n", MT_STR(ldd));
        printf("Flags:      %#x\n", ldd->ldd_flags);
        printf("              (%s%s%s%s%s%s%s%s%s%s)\n",
               IS_MDT(ldd) ? "MDT ":"",
               IS_OST(ldd) ? "OST ":"",
               IS_MGS(ldd) ? "MGS ":"",
               ldd->ldd_flags & LDD_F_NEED_INDEX ? "needs_index ":"",
               ldd->ldd_flags & LDD_F_VIRGIN     ? "first_time ":"",
               ldd->ldd_flags & LDD_F_UPDATE     ? "update ":"",
               ldd->ldd_flags & LDD_F_WRITECONF  ? "writeconf ":"",
               ldd->ldd_flags & LDD_F_IAM_DIR  ? "IAM_dir_format ":"",
               ldd->ldd_flags & LDD_F_NO_PRIMNODE? "no_primnode ":"",
               ldd->ldd_flags & LDD_F_UPGRADE14  ? "upgrade1.4 ":"");
        printf("Persistent mount opts: %s\n", ldd->ldd_mount_opts);
        printf("Parameters:%s\n", ldd->ldd_params);
        if (ldd->ldd_userdata[0])
                printf("Comment: %s\n", ldd->ldd_userdata);
        printf("\n");
}

static int touch_file(char *filename)
{
        int fd;

        if (filename == NULL) {
                return 1;
        }

        fd = open(filename, O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
                return 1;
        } else {
                close(fd);
                return 0;
        }
}

/* keep it less than LL_FID_NAMELEN */
#define DUMMY_FILE_NAME_LEN             25
#define EXT3_DIRENT_SIZE                DUMMY_FILE_NAME_LEN

/* Need to add these many entries to this directory to make HTREE dir. */
#define MIN_ENTRIES_REQ_FOR_HTREE       ((L_BLOCK_SIZE / EXT3_DIRENT_SIZE))

static int add_dummy_files(char *dir)
{
        char fpname[PATH_MAX];
        int i;
        int rc;

        for (i = 0; i < MIN_ENTRIES_REQ_FOR_HTREE; i++) {
                snprintf(fpname, PATH_MAX, "%s/%0*d", dir,
                         DUMMY_FILE_NAME_LEN, i);

                rc = touch_file(fpname);
                if (rc && rc != -EEXIST) {
                        fprintf(stderr,
                                "%s: Can't create dummy file %s: %s\n",
                                progname, fpname , strerror(errno));
                        return rc;
                }
        }
        return 0;
}

static int __l_mkdir(char * filepnm, int mode , struct mkfs_opts *mop)
{
        int ret;

        ret = mkdir(filepnm, mode);
        if (ret && ret != -EEXIST)
                return ret;

        /* IAM mode supports ext3 directories of HTREE type only. So add dummy
         * entries to new directory to create htree type of container for
         * this directory. */
        if (mop->mo_ldd.ldd_flags & LDD_F_IAM_DIR)
                return add_dummy_files(filepnm);
        return 0;
}

/* Write the server config files */
int write_local_files(struct mkfs_opts *mop)
{
        char mntpt[] = "/tmp/mntXXXXXX";
        char filepnm[128];
        char *dev;
        FILE *filep;
        int ret = 0;
        size_t num;

        /* Mount this device temporarily in order to write these files */
        if (!mkdtemp(mntpt)) {
                fprintf(stderr, "%s: Can't create temp mount point %s: %s\n",
                        progname, mntpt, strerror(errno));
                return errno;
        }

        dev = mop->mo_device;
        if (mop->mo_flags & MO_IS_LOOP)
                dev = mop->mo_loopdev;

        ret = mount(dev, mntpt, MT_STR(&mop->mo_ldd), 0,
                    mop->mo_ldd.ldd_mount_opts);
        if (ret) {
                fprintf(stderr, "%s: Unable to mount %s: %s\n",
                        progname, dev, strerror(errno));
                ret = errno;
                if (errno == ENODEV) {
                        fprintf(stderr, "Is the %s module available?\n",
                                MT_STR(&mop->mo_ldd));
                }
                goto out_rmdir;
        }

        /* Set up initial directories */
        sprintf(filepnm, "%s/%s", mntpt, MOUNT_CONFIGS_DIR);
        ret = __l_mkdir(filepnm, 0777, mop);
        if ((ret != 0) && (errno != EEXIST)) {
                fprintf(stderr, "%s: Can't make configs dir %s (%s)\n",
                        progname, filepnm, strerror(errno));
                goto out_umnt;
        } else if (errno == EEXIST) {
                ret = 0;
        }

        /* Save the persistent mount data into a file. Lustre must pre-read
           this file to get the real mount options. */
        vprint("Writing %s\n", MOUNT_DATA_FILE);
        sprintf(filepnm, "%s/%s", mntpt, MOUNT_DATA_FILE);
        filep = fopen(filepnm, "w");
        if (!filep) {
                fprintf(stderr, "%s: Unable to create %s file: %s\n",
                        progname, filepnm, strerror(errno));
                goto out_umnt;
        }
        num = fwrite(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
        if (num < 1 && ferror(filep)) {
                fprintf(stderr, "%s: Unable to write to file (%s): %s\n",
                        progname, filepnm, strerror(errno));
                goto out_umnt;
        }
        fclose(filep);
        /* COMPAT_146 */
#ifdef TUNEFS
        /* Check for upgrade */
        if ((mop->mo_ldd.ldd_flags & (LDD_F_UPGRADE14 | LDD_F_SV_TYPE_MGS))
            == (LDD_F_UPGRADE14 | LDD_F_SV_TYPE_MGS)) {
                char cmd[128];
                char *term;
                int cmdsz = sizeof(cmd);
                vprint("Copying old logs\n");

                /* Copy the old client log to fsname-client */
                sprintf(filepnm, "%s/%s/%s-client",
                        mntpt, MOUNT_CONFIGS_DIR, mop->mo_ldd.ldd_fsname);
                snprintf(cmd, cmdsz, "cp %s/%s/client %s", mntpt, MDT_LOGS_DIR,
                         filepnm);
                ret = run_command(cmd, cmdsz);
                if (ret) {
                        fprintf(stderr, "%s: Can't copy 1.4 config %s/client "
                                "(%d)\n", progname, MDT_LOGS_DIR, ret);
                        fprintf(stderr, "mount -t ldiskfs %s somewhere, "
                                "find the client log for fs %s and "
                                "copy it manually into %s/%s-client, "
                                "then umount.\n",
                                mop->mo_device,
                                mop->mo_ldd.ldd_fsname, MOUNT_CONFIGS_DIR,
                                mop->mo_ldd.ldd_fsname);
                        goto out_umnt;
                }

                /* We need to use the old mdt log because otherwise mdt won't
                   have complete lov if old clients connect before all
                   servers upgrade. */
                /* Copy the old mdt log to fsname-MDT0000 (get old
                   name from mdt_UUID) */
                ret = 1;
                strscpy(filepnm, (char *)mop->mo_ldd.ldd_uuid, sizeof(filepnm));
                term = strstr(filepnm, "_UUID");
                if (term) {
                        *term = '\0';
                        snprintf(cmd, cmdsz, "cp %s/%s/%s %s/%s/%s",
                                 mntpt, MDT_LOGS_DIR, filepnm,
                                 mntpt, MOUNT_CONFIGS_DIR,
                                 mop->mo_ldd.ldd_svname);
                        ret = run_command(cmd, cmdsz);
                }
                if (ret) {
                        fprintf(stderr, "%s: Can't copy 1.4 config %s/%s "
                                "(%d)\n", progname, MDT_LOGS_DIR, filepnm, ret);
                        fprintf(stderr, "mount -t ext3 %s somewhere, "
                                "find the MDT log for fs %s and "
                                "copy it manually into %s/%s, "
                                "then umount.\n",
                                mop->mo_device,
                                mop->mo_ldd.ldd_fsname, MOUNT_CONFIGS_DIR,
                                mop->mo_ldd.ldd_svname);
                        goto out_umnt;
                }
        }
#endif
        /* end COMPAT_146 */

out_umnt:
        umount(mntpt);
out_rmdir:
        rmdir(mntpt);
        return ret;
}

int read_local_files(struct mkfs_opts *mop)
{
        char tmpdir[] = "/tmp/dirXXXXXX";
        char cmd[PATH_MAX];
        char filepnm[128];
        char *dev;
        FILE *filep;
        int ret = 0;
        int cmdsz = sizeof(cmd);

        /* Make a temporary directory to hold Lustre data files. */
        if (!mkdtemp(tmpdir)) {
                fprintf(stderr, "%s: Can't create temporary directory %s: %s\n",
                        progname, tmpdir, strerror(errno));
                return errno;
        }

        dev = mop->mo_device;

        /* TODO: it's worth observing the get_mountdata() function that is
                 in mount_utils.c for getting the mountdata out of the
                 filesystem */

        /* Construct debugfs command line. */
        snprintf(cmd, cmdsz, "%s -c -R 'dump /%s %s/mountdata' '%s'",
                 DEBUGFS, MOUNT_DATA_FILE, tmpdir, dev);

        ret = run_command(cmd, cmdsz);
        if (ret)
                verrprint("%s: Unable to dump %s dir (%d)\n",
                          progname, MOUNT_CONFIGS_DIR, ret);

        sprintf(filepnm, "%s/mountdata", tmpdir);
        filep = fopen(filepnm, "r");
        if (filep) {
                size_t num_read;
                vprint("Reading %s\n", MOUNT_DATA_FILE);
                num_read = fread(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
                if (num_read < 1 && ferror(filep)) {
                        fprintf(stderr, "%s: Unable to read from file %s: %s\n",
                                progname, filepnm, strerror(errno));
                        goto out_close;
                }
        } else {
                /* COMPAT_146 */
                /* Try to read pre-1.6 config from last_rcvd */
                struct lr_server_data lsd;
                verrprint("%s: Unable to read %d.%d config %s.\n",
                          progname, LUSTRE_MAJOR, LUSTRE_MINOR, filepnm);

                verrprint("Trying 1.4 config from last_rcvd\n");
                sprintf(filepnm, "%s/%s", tmpdir, LAST_RCVD);

                /* Construct debugfs command line. */
                snprintf(cmd, cmdsz, "%s -c -R 'dump /%s %s' %s",
                         DEBUGFS, LAST_RCVD, filepnm, dev);

                ret = run_command(cmd, cmdsz);
                if (ret) {
                        fprintf(stderr, "%s: Unable to dump %s file (%d)\n",
                                progname, LAST_RCVD, ret);
                        goto out_rmdir;
                }

                filep = fopen(filepnm, "r");
                if (!filep) {
                        fprintf(stderr, "%s: Unable to open %s: %s\n",
                                progname, filepnm, strerror(errno));
                        ret = errno;
                        verrprint("Contents of %s:\n", tmpdir);
                        verbose+=2;
                        snprintf(cmd, cmdsz, "ls -l %s/", tmpdir);
                        run_command(cmd, cmdsz);
                        verrprint("Contents of disk:\n");
                        snprintf(cmd, cmdsz, "%s -c -R 'ls -l /' %s",
                                 DEBUGFS, dev);
                        run_command(cmd, cmdsz);

                        goto out_rmdir;
                }
                vprint("Reading %s\n", LAST_RCVD);
                ret = fread(&lsd, 1, sizeof(lsd), filep);
                if (ret < sizeof(lsd)) {
                        fprintf(stderr, "%s: Short read (%d of %d)\n",
                                progname, ret, (int)sizeof(lsd));
                        ret = ferror(filep);
                        if (ret)
                                goto out_close;
                }
                vprint("Feature compat=%x, incompat=%x\n",
                       lsd.lsd_feature_compat, lsd.lsd_feature_incompat);

                if ((lsd.lsd_feature_compat & OBD_COMPAT_OST) ||
                    (lsd.lsd_feature_incompat & OBD_INCOMPAT_OST)) {
                        mop->mo_ldd.ldd_flags = LDD_F_SV_TYPE_OST;
                        mop->mo_ldd.ldd_svindex = lsd.lsd_ost_index;
                } else if ((lsd.lsd_feature_compat & OBD_COMPAT_MDT) ||
                           (lsd.lsd_feature_incompat & OBD_INCOMPAT_MDT)) {
                        /* We must co-locate so mgs can see old logs.
                           If user doesn't want this, they can copy the old
                           logs manually and re-tunefs. */
                        mop->mo_ldd.ldd_flags =
                                LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_MGS;
                        mop->mo_ldd.ldd_svindex = lsd.lsd_mdt_index;
                } else  {
                        /* If neither is set, we're pre-1.4.6, make a guess. */
                        /* Construct debugfs command line. */
                        snprintf(cmd, cmdsz, "%s -c -R 'rdump /%s %s' %s",
                                 DEBUGFS, MDT_LOGS_DIR, tmpdir, dev);
                        run_command(cmd, cmdsz);

                        sprintf(filepnm, "%s/%s", tmpdir, MDT_LOGS_DIR);
                        if (lsd.lsd_ost_index > 0) {
                                mop->mo_ldd.ldd_flags = LDD_F_SV_TYPE_OST;
                                mop->mo_ldd.ldd_svindex = lsd.lsd_ost_index;
                        } else {
                                /* If there's a LOGS dir, it's an MDT */
                                if ((ret = access(filepnm, F_OK)) == 0) {
                                        mop->mo_ldd.ldd_flags =
                                        LDD_F_SV_TYPE_MDT |
                                        LDD_F_SV_TYPE_MGS;
                                        /* Old MDT's are always index 0
                                           (pre CMD) */
                                        mop->mo_ldd.ldd_svindex = 0;
                                } else {
                                        /* The index may not be correct */
                                        mop->mo_ldd.ldd_flags =
                                        LDD_F_SV_TYPE_OST | LDD_F_NEED_INDEX;
                                        verrprint("OST with unknown index\n");
                                }
                        }
                }

                ret = 0;
                memcpy(mop->mo_ldd.ldd_uuid, lsd.lsd_uuid,
                       sizeof(mop->mo_ldd.ldd_uuid));
                mop->mo_ldd.ldd_flags |= LDD_F_UPGRADE14;
        }
        /* end COMPAT_146 */
out_close:
        fclose(filep);

out_rmdir:
        snprintf(cmd, cmdsz, "rm -rf %s", tmpdir);
        run_command(cmd, cmdsz);
        if (ret)
                verrprint("Failed to read old data (%d)\n", ret);
        return ret;
}


void set_defaults(struct mkfs_opts *mop)
{
        mop->mo_ldd.ldd_magic = LDD_MAGIC;
        mop->mo_ldd.ldd_config_ver = 1;
        mop->mo_ldd.ldd_flags = LDD_F_NEED_INDEX | LDD_F_UPDATE | LDD_F_VIRGIN;
        mop->mo_mgs_failnodes = 0;
        strcpy(mop->mo_ldd.ldd_fsname, "lustre");
        mop->mo_ldd.ldd_mount_type = LDD_MT_LDISKFS;

        mop->mo_ldd.ldd_svindex = INDEX_UNASSIGNED;
        mop->mo_stripe_count = 1;
}

static inline void badopt(const char *opt, char *type)
{
        fprintf(stderr, "%s: '--%s' only valid for %s\n",
                progname, opt, type);
        usage(stderr);
}

static int add_param(char *buf, char *key, char *val)
{
        int end = sizeof(((struct lustre_disk_data *)0)->ldd_params);
        int start = strlen(buf);
        int keylen = 0;

        if (key)
                keylen = strlen(key);
        if (start + 1 + keylen + strlen(val) >= end) {
                fprintf(stderr, "%s: params are too long-\n%s %s%s\n",
                        progname, buf, key ? key : "", val);
                return 1;
        }

        sprintf(buf + start, " %s%s", key ? key : "", val);
        return 0;
}

/* from mount_lustre */
/* Get rid of symbolic hostnames for tcp, since kernel can't do lookups */
#define MAXNIDSTR 1024
static char *convert_hostnames(char *s1)
{
        char *converted, *s2 = 0, *c, *end, sep;
        int left = MAXNIDSTR;
        lnet_nid_t nid;

        converted = malloc(left);
        if (converted == NULL) {
                return NULL;
        }

        end = s1 + strlen(s1);
        c = converted;
        while ((left > 0) && (s1 < end)) {
                s2 = strpbrk(s1, ",:");
                if (!s2)
                        s2 = end;
                sep = *s2;
                *s2 = '\0';
                nid = libcfs_str2nid(s1);

                if (nid == LNET_NID_ANY) {
                        fprintf(stderr, "%s: Can't parse NID '%s'\n",
                                progname, s1);
                        free(converted);
                        return NULL;
                }
                if (strncmp(libcfs_nid2str(nid), "127.0.0.1",
                            strlen("127.0.0.1")) == 0) {
                        fprintf(stderr, "%s: The NID '%s' resolves to the "
                                "loopback address '%s'.  Lustre requires a "
                                "non-loopback address.\n",
                                progname, s1, libcfs_nid2str(nid));
                        free(converted);
                        return NULL;
                }

                c += snprintf(c, left, "%s%c", libcfs_nid2str(nid), sep);
                left = converted + MAXNIDSTR - c;
                s1 = s2 + 1;
        }
        return converted;
}

int parse_opts(int argc, char *const argv[], struct mkfs_opts *mop,
               char **mountopts)
{
        static struct option long_opt[] = {
                {"iam-dir", 0, 0, 'a'},
                {"backfstype", 1, 0, 'b'},
                {"stripe-count-hint", 1, 0, 'c'},
                {"comment", 1, 0, 'u'},
                {"configdev", 1, 0, 'C'},
                {"device-size", 1, 0, 'd'},
                {"dryrun", 0, 0, 'n'},
                {"erase-params", 0, 0, 'e'},
                {"failnode", 1, 0, 'f'},
                {"failover", 1, 0, 'f'},
                {"mgs", 0, 0, 'G'},
                {"help", 0, 0, 'h'},
                {"index", 1, 0, 'i'},
                {"mkfsoptions", 1, 0, 'k'},
                {"mgsnode", 1, 0, 'm'},
                {"mgsnid", 1, 0, 'm'},
                {"mdt", 0, 0, 'M'},
                {"fsname",1, 0, 'L'},
                {"noformat", 0, 0, 'n'},
                {"nomgs", 0, 0, 'N'},
                {"mountfsoptions", 1, 0, 'o'},
                {"ost", 0, 0, 'O'},
                {"param", 1, 0, 'p'},
                {"print", 0, 0, 'n'},
                {"quiet", 0, 0, 'q'},
                {"reformat", 0, 0, 'r'},
                {"servicenode", 1, 0, 's'},
                {"verbose", 0, 0, 'v'},
                {"writeconf", 0, 0, 'w'},
                {"upgrade_to_18", 0, 0, 'U'},
                {"network", 1, 0, 't'},
                {0, 0, 0, 0}
        };
        char *optstring = "b:c:C:d:ef:Ghi:k:L:m:MnNo:Op:Pqrs:t:Uu:vw";
        int opt;
        int rc, longidx;
        int failnode_set = 0, servicenode_set = 0;

        while ((opt = getopt_long(argc, argv, optstring, long_opt, &longidx)) !=
               EOF) {
                switch (opt) {
                case 'a': {
                        if (IS_MDT(&mop->mo_ldd))
                                mop->mo_ldd.ldd_flags |= LDD_F_IAM_DIR;
                        break;
                }
                case 'b': {
                        int i = 0;
                        while (i < LDD_MT_LAST) {
                                if (strcmp(optarg, mt_str(i)) == 0) {
                                        mop->mo_ldd.ldd_mount_type = i;
                                        break;
                                }
                                i++;
                        }
                        break;
                }
                case 'c':
                        if (IS_MDT(&mop->mo_ldd)) {
                                int stripe_count = atol(optarg);
                                if (stripe_count <= 0) {
                                        fprintf(stderr, "%s: bad stripe count "
                                                "%d\n", progname, stripe_count);
                                        return 1;
                                }
                                mop->mo_stripe_count = stripe_count;
                        } else {
                                badopt(long_opt[longidx].name, "MDT");
                                return 1;
                        }
                        break;
                case 'C': /* Configdev */
                        //FIXME
                        printf("Configdev not implemented\n");
                        return 1;
                case 'd':
                        mop->mo_device_sz = atol(optarg);
                        break;
                case 'e':
                        mop->mo_ldd.ldd_params[0] = '\0';
                        /* Must update the mgs logs */
                        mop->mo_ldd.ldd_flags |= LDD_F_UPDATE;
                        break;
                case 'f':
                case 's': {
                        char *nids;

                        if ((opt == 'f' && servicenode_set)
                            || (opt == 's' && failnode_set)) {
                                fprintf(stderr, "%s: %s cannot use with --%s\n",
                                        progname, long_opt[longidx].name,
                                        opt == 'f' ? "servicenode" : "failnode");
                                return 1;
                        }

                        nids = convert_hostnames(optarg);
                        if (!nids)
                                return 1;
                        rc = add_param(mop->mo_ldd.ldd_params, PARAM_FAILNODE,
                                       nids);
                        free(nids);
                        if (rc)
                                return rc;
                        /* Must update the mgs logs */
                        mop->mo_ldd.ldd_flags |= LDD_F_UPDATE;
                        if (opt == 'f') {
                                failnode_set = 1;
                        } else {
                                mop->mo_ldd.ldd_flags |= LDD_F_NO_PRIMNODE;
                                servicenode_set = 1;
                        }
                        failover = 1;
                        break;
                }
                case 'G':
                        mop->mo_ldd.ldd_flags |= LDD_F_SV_TYPE_MGS;
                        break;
                case 'h':
                        usage(stdout);
                        return 1;
                case 'i':
                        if (!(mop->mo_ldd.ldd_flags &
                              (LDD_F_UPGRADE14 | LDD_F_VIRGIN |
                               LDD_F_WRITECONF))) {
                                fprintf(stderr, "%s: cannot change the index of"
                                        " a registered target\n", progname);
                                return 1;
                        }
                        if (IS_MDT(&mop->mo_ldd) || IS_OST(&mop->mo_ldd)) {
                                mop->mo_ldd.ldd_svindex = atol(optarg);
                                mop->mo_ldd.ldd_flags &= ~LDD_F_NEED_INDEX;
                        } else {
                                badopt(long_opt[longidx].name, "MDT,OST");
                                return 1;
                        }
                        break;
                case 'k':
                        strscpy(mop->mo_mkfsopts, optarg,
                                sizeof(mop->mo_mkfsopts));
                        break;
                case 'L': {
                        char *tmp;
                        if (!(mop->mo_flags & MO_FORCEFORMAT) &&
                            (!(mop->mo_ldd.ldd_flags &
                               (LDD_F_UPGRADE14 | LDD_F_VIRGIN |
                                LDD_F_WRITECONF)))) {
                                fprintf(stderr, "%s: cannot change the name of"
                                        " a registered target\n", progname);
                                return 1;
                        }
                        if ((strlen(optarg) < 1) || (strlen(optarg) > 8)) {
                                fprintf(stderr, "%s: filesystem name must be "
                                        "1-8 chars\n", progname);
                                return 1;
                        }
                        if ((tmp = strpbrk(optarg, "/:"))) {
                                fprintf(stderr, "%s: char '%c' not allowed in "
                                        "filesystem name\n", progname, *tmp);
                                return 1;
                        }
                        strscpy(mop->mo_ldd.ldd_fsname, optarg,
                                sizeof(mop->mo_ldd.ldd_fsname));
                        break;
                }
                case 'm': {
                        char *nids = convert_hostnames(optarg);
                        if (!nids)
                                return 1;
                        rc = add_param(mop->mo_ldd.ldd_params, PARAM_MGSNODE,
                                       nids);
                        free(nids);
                        if (rc)
                                return rc;
                        mop->mo_mgs_failnodes++;
                        break;
                }
                case 'M':
                        mop->mo_ldd.ldd_flags |= LDD_F_SV_TYPE_MDT;
                        break;
                case 'n':
                        print_only++;
                        break;
                case 'N':
                        mop->mo_ldd.ldd_flags &= ~LDD_F_SV_TYPE_MGS;
                        break;
                case 'o':
                        *mountopts = optarg;
                        break;
                case 'O':
                        mop->mo_ldd.ldd_flags |= LDD_F_SV_TYPE_OST;
                        break;
                case 'p':
                        rc = add_param(mop->mo_ldd.ldd_params, NULL, optarg);
                        if (rc)
                                return rc;
                        /* Must update the mgs logs */
                        mop->mo_ldd.ldd_flags |= LDD_F_UPDATE;
                        break;
                case 'q':
                        verbose--;
                        break;
                case 'r':
                        mop->mo_flags |= MO_FORCEFORMAT;
                        break;
                case 't':
                        if (!IS_MDT(&mop->mo_ldd) && !IS_OST(&mop->mo_ldd)) {
                                badopt(long_opt[longidx].name, "MDT,OST");
                                return 1;
                        }

                        if (!optarg)
                                return 1;

                        rc = add_param(mop->mo_ldd.ldd_params,
                                       PARAM_NETWORK, optarg);
                        if (rc != 0)
                                return rc;
                        /* Must update the mgs logs */
                        mop->mo_ldd.ldd_flags |= LDD_F_UPDATE;
                        break;
                case 'u':
                        strscpy(mop->mo_ldd.ldd_userdata, optarg,
                                sizeof(mop->mo_ldd.ldd_userdata));
                        break;
                case 'v':
                        verbose++;
                        break;
                case 'w':
                        mop->mo_ldd.ldd_flags |= LDD_F_WRITECONF;
                        break;
                case 'U':
                        upgrade_to_18 = 1;
                        break;
                default:
                        if (opt != '?') {
                                fatal();
                                fprintf(stderr, "Unknown option '%c'\n", opt);
                        }
                        return EINVAL;
                }
        }//while

        /* Last arg is device */
        if (optind != argc - 1) {
                fatal();
                fprintf(stderr, "Bad argument: %s\n", argv[optind]);
                return EINVAL;
        }

        /* single argument: <device> */
        if (argc == 2)
                ++print_only;

        return 0;
}

/* Search for opt in mntlist, returning true if found.
 */
static int in_mntlist(char *opt, char *mntlist)
{
        char *ml, *mlp, *item, *ctx = NULL;

        if (!(ml = strdup(mntlist))) {
                fprintf(stderr, "%s: out of memory\n", progname);
                exit(1);
        }
        mlp = ml;
        while ((item = strtok_r(mlp, ",", &ctx))) {
                if (!strcmp(opt, item))
                        break;
                mlp = NULL;
        }
        free(ml);
        return (item != NULL);
}

/* Issue a message on stderr for every item in wanted_mountopts that is not
 * present in mountopts.  The justwarn boolean toggles between error and
 * warning message.  Return an error count.
 */
static int check_mountfsoptions(char *mountopts, char *wanted_mountopts,
                                int justwarn)
{
        char *ml, *mlp, *item, *ctx = NULL;
        int errors = 0;

        if (!(ml = strdup(wanted_mountopts))) {
                fprintf(stderr, "%s: out of memory\n", progname);
                exit(1);
        }
        mlp = ml;
        while ((item = strtok_r(mlp, ",", &ctx))) {
                if (!in_mntlist(item, mountopts)) {
                        fprintf(stderr, "%s: %s mount option `%s' is missing\n",
                                progname, justwarn ? "Warning: default"
                                : "Error: mandatory", item);
                        errors++;
                }
                mlp = NULL;
        }
        free(ml);
        return errors;
}

/* Trim embedded white space, leading and trailing commas from string s.
 */
static void trim_mountfsoptions(char *s)
{
        char *p;

        for (p = s; *p; ) {
                if (isspace(*p)) {
                        memmove(p, p + 1, strlen(p + 1) + 1);
                        continue;
                }
                p++;
        }

        while (s[0] == ',')
                memmove(&s[0], &s[1], strlen(&s[1]) + 1);

        p = s + strlen(s) - 1;
        while (p >= s && *p == ',')
                *p-- = '\0';
}

int main(int argc, char *const argv[])
{
        struct mkfs_opts mop;
        struct lustre_disk_data *ldd;
        char *mountopts = NULL;
        char always_mountopts[512] = "";
        char default_mountopts[512] = "";
        int ret = 0;

        if ((progname = strrchr(argv[0], '/')) != NULL)
                progname++;
        else
                progname = argv[0];

        if ((argc < 2) || (argv[argc - 1][0] == '-')) {
                usage(stderr);
                return(EINVAL);
        }

        memset(&mop, 0, sizeof(mop));
        set_defaults(&mop);

        /* device is last arg */
        strscpy(mop.mo_device, argv[argc - 1], sizeof(mop.mo_device));

        /* Are we using a loop device? */
        ret = is_block(mop.mo_device);
        if (ret < 0)
                goto out;
        if (ret == 0)
                mop.mo_flags |= MO_IS_LOOP;

#ifdef TUNEFS
        /* For tunefs, we must read in the old values before parsing any
           new ones. */

        /* Check whether the disk has already been formatted by mkfs.lustre */
        ret = is_lustre_target(&mop);
        if (ret == 0) {
                fatal();
                fprintf(stderr, "Device %s has not been formatted with "
                        "mkfs.lustre\n", mop.mo_device);
                ret = ENODEV;
                goto out;
        }

        ret = read_local_files(&mop);
        if (ret) {
                fatal();
                fprintf(stderr, "Failed to read previous Lustre data from %s "
                        "(%d)\n", mop.mo_device, ret);
                goto out;
        }
        if (strstr(mop.mo_ldd.ldd_params, PARAM_MGSNODE))
            mop.mo_mgs_failnodes++;

        if (verbose > 0)
                print_ldd("Read previous values", &(mop.mo_ldd));
#endif

        ret = parse_opts(argc, argv, &mop, &mountopts);
        if (ret)
                goto out;

        ldd = &mop.mo_ldd;

        if (!(IS_MDT(ldd) || IS_OST(ldd) || IS_MGS(ldd))) {
                fatal();
                fprintf(stderr, "must set target type: MDT,OST,MGS\n");
                ret = EINVAL;
                goto out;
        }

        if (((IS_MDT(ldd) || IS_MGS(ldd))) && IS_OST(ldd)) {
                fatal();
                fprintf(stderr, "OST type is exclusive with MDT,MGS\n");
                ret = EINVAL;
                goto out;
        }

        if ((mop.mo_ldd.ldd_flags & (LDD_F_NEED_INDEX | LDD_F_UPGRADE14)) ==
            (LDD_F_NEED_INDEX | LDD_F_UPGRADE14)) {
                fatal();
                fprintf(stderr, "Can't find the target index, "
                        "specify with --index\n");
                ret = EINVAL;
                goto out;
        }
#if 0
        /*
         * Comment out these 2 checks temporarily, since for multi-MDSes
         * in single node only 1 mds node could have mgs service
         */
        if (IS_MDT(ldd) && !IS_MGS(ldd) && (mop.mo_mgs_failnodes == 0)) {
                verrprint("No management node specified, adding MGS to this "
                          "MDT\n");
                ldd->ldd_flags |= LDD_F_SV_TYPE_MGS;
        }
        if (!IS_MGS(ldd) && (mop.mo_mgs_failnodes == 0)) {
                fatal();
                if (IS_MDT(ldd))
                        fprintf(stderr, "Must specify --mgs or --mgsnode=\n");
                else
                        fprintf(stderr, "Must specify --mgsnode=\n");
                ret = EINVAL;
                goto out;
        }
#endif

        /* These are the permanent mount options (always included) */
        switch (ldd->ldd_mount_type) {
        case LDD_MT_EXT3:
        case LDD_MT_LDISKFS:
        case LDD_MT_LDISKFS2:
                strscat(default_mountopts, ",errors=remount-ro",
                        sizeof(default_mountopts));
                if (IS_MDT(ldd) || IS_MGS(ldd))
                        strscat(always_mountopts, ",user_xattr",
                                sizeof(always_mountopts));
                /* NB: Files created while extents are enabled can only be read
                 * if mounted using the ext4 or ldiskfs filesystem type. */
                if (IS_OST(ldd) &&
                    (ldd->ldd_mount_type == LDD_MT_LDISKFS ||
                     ldd->ldd_mount_type == LDD_MT_LDISKFS2)) {
                        strscat(default_mountopts, ",extents,mballoc",
                                sizeof(default_mountopts));
                }
                break;
        default:
                fatal();
                fprintf(stderr, "unknown fs type %d '%s'\n",
                        ldd->ldd_mount_type,
                        MT_STR(ldd));
                ret = EINVAL;
                goto out;
        }

        if (mountopts) {
                trim_mountfsoptions(mountopts);
                (void)check_mountfsoptions(mountopts, default_mountopts, 1);
                if (check_mountfsoptions(mountopts, always_mountopts, 0)) {
                        ret = EINVAL;
                        goto out;
                }
                sprintf(ldd->ldd_mount_opts, "%s", mountopts);
        } else {
#ifdef TUNEFS
                if (ldd->ldd_mount_opts[0] == 0)
                        /* use the defaults unless old opts exist */
#endif
                {
                        sprintf(ldd->ldd_mount_opts, "%s%s",
                                always_mountopts, default_mountopts);
                        trim_mountfsoptions(ldd->ldd_mount_opts);
                }
        }

        server_make_name(ldd->ldd_flags, ldd->ldd_svindex,
                         ldd->ldd_fsname, ldd->ldd_svname);

        if (verbose >= 0)
                print_ldd("Permanent disk data", ldd);

        if (print_only) {
                printf("exiting before disk write.\n");
                goto out;
        }

        if (check_mtab_entry(mop.mo_device))
                return(EEXIST);

        /* Create the loopback file */
        if (mop.mo_flags & MO_IS_LOOP) {
                ret = access(mop.mo_device, F_OK);
                if (ret)
                        ret = errno;
#ifndef TUNEFS /* mkfs.lustre */
                /* Reformat the loopback file */
                if (ret || (mop.mo_flags & MO_FORCEFORMAT))
                        ret = loop_format(&mop);
#endif
                if (ret == 0)
                        ret = loop_setup(&mop);
                if (ret) {
                        fatal();
                        fprintf(stderr, "Loop device setup for %s failed: %s\n",
                                mop.mo_device, strerror(ret));
                        goto out;
                }
        }

#ifndef TUNEFS /* mkfs.lustre */
        /* Check whether the disk has already been formatted by mkfs.lustre */
        if (!(mop.mo_flags & MO_FORCEFORMAT)) {
                ret = is_lustre_target(&mop);
                if (ret) {
                        fatal();
                        fprintf(stderr, "Device %s was previously formatted "
                                "for lustre. Use --reformat to reformat it, "
                                "or tunefs.lustre to modify.\n",
                                mop.mo_device);
                        goto out;
                }
        }

        /* Format the backing filesystem */
        ret = make_lustre_backfs(&mop);
        if (ret != 0) {
                fatal();
                fprintf(stderr, "mkfs failed %d\n", ret);
                goto out;
        }
#endif

        /* Write our config files */
        ret = write_local_files(&mop);
        if (ret != 0) {
                fatal();
                fprintf(stderr, "failed to write local files\n");
                goto out;
        }

out:
        loop_cleanup(&mop);

        /* Fix any crazy return values from system() */
        if (ret && ((ret & 255) == 0))
                return (1);
        if (ret)
                verrprint("%s: exiting with %d (%s)\n",
                          progname, ret, strerror(ret));
        return (ret);
}
