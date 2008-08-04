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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
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

#ifdef __linux__
/* kp30.h is not really needed here, but on SLES10/PPC, fs.h includes idr.h which
 * requires BITS_PER_LONG to be defined */
#include <libcfs/kp30.h>
#include <linux/fs.h> /* for BLKGETSIZE64 */
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
        char  mo_mkfsopts[128];         /* options to the backing-store mkfs */
        char  mo_loopdev[128];          /* in case a loop dev is needed */
        __u64 mo_device_sz;             /* in KB */
        int   mo_stripe_count;
        int   mo_flags;
        int   mo_mgs_failnodes;
};

char *progname;
int verbose = 1;
static int print_only = 0;
static int failover = 0;

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
                "\t\t--param <key>=<value> : set a permanent parameter\n"
                "\t\t\te.g. --param sys.timeout=40\n"
                "\t\t\t     --param lov.stripesize=2M\n"
                "\t\t--index=#N : target index (i.e. ost index within the lov)\n"
                /* FIXME implement 1.6.x
                "\t\t--configdev=<altdevice|file>: store configuration info\n"
                "\t\t\tfor this device on an alternate device\n"
                */
                "\t\t--comment=<user comment>: arbitrary user string (%d bytes)\n"
                "\t\t--mountfsoptions=<opts> : permanent mount options\n"
#ifndef TUNEFS
                "\t\t--backfstype=<fstype> : backing fs type (ext3, ldiskfs)\n"
                "\t\t--device-size=#N(KB) : device size for loop devices\n"
                "\t\t--mkfsoptions=<opts> : format options\n"
                "\t\t--reformat: overwrite an existing disk\n"
                "\t\t--stripe-count-hint=#N : used for optimizing MDT inode size\n"
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
                if (fd < 0)
                        fprintf(stderr, "%s: Warning: Can't resolve kernel "
                                "version, assuming 2.6\n", progname);
                else {
                        read(fd, release, 4);
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
        int i,ret = 0;

        /* Figure out the loop device names */
        if (!access("/dev/loop0", F_OK | R_OK))
                strcpy(loop_base, "/dev/loop\0");
        else if (!access("/dev/loop/0", F_OK | R_OK))
                strcpy(loop_base, "/dev/loop/\0");
        else {
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
        ret = truncate(mop->mo_device, mop->mo_device_sz * 1024);
        if (ret != 0) {
                ret = errno;
                fprintf(stderr, "%s: Unable to create backing store: %d\n",
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
                fprintf(stderr, "WARNING: e2fsprogs does not support %s "
                        "feature.\n\n", feature);
                return;
        }

        msg_displayed++;

        fprintf(stderr, "WARNING: The e2fsprogs package currently installed on "
                "your system does not support \"%s\" feature.\nPlease install "
                "the latest version of e2fsprogs from http://downloads.lustre.org"
                "/public/tools/e2fsprogs/\nto enable this feature.\n", feature);

        if (make_backfs)
                fprintf(stderr, "Feature will not be enabled until e2fsprogs "
                        "is updated and 'tune2fs -O %s %%{device}' "
                        "is run.\n\n", feature);
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
                "debugfs -c -R 'stat %s' %s 2>&1 | egrep '(Inode|unsupported)'",
                file_name, dev_name);

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
        FILE *fp;
        char cmd[PATH_MAX];
        char imgname[] = "/tmp/test-img-XXXXXX";
        int fd = -1;
        int ret = 0;

        snprintf(cmd, sizeof(cmd),
                 "debugfs -c -R \"supported_features %s\" 2>&1", feature);

        /* Using popen() instead of run_command() since debugfs does not return
         * proper error code if command is not supported */
        fp = popen(cmd, "r");
        if (!fp) {
                fprintf(stderr, "%s: %s\n", progname, strerror(errno));
                return 0;
        }
        ret = fread(cmd, 1, sizeof(cmd), fp);
        if (ret > 0) {
                if (strstr(cmd, feature) && !(strstr(cmd, "Unknown")))
                        return 0;
        }

        if ((fd = mkstemp(imgname)) < 0)
                return -1;

        snprintf(cmd, sizeof(cmd), "mke2fs -F -O %s %s 100 >/dev/null 2>&1",
                 feature, imgname);
        /* run_command() displays the output of mke2fs when it fails for
         * some feature, so use system() directly */
        ret = system(cmd);
        if (fd >= 0)
                remove(imgname);

        return ret;
}

static void disp_old_kernel_msg(char *feature)
{
       fprintf(stderr, "WARNING: ldiskfs filesystem does not support \"%s\" "
               "feature.\n\n", feature);
}

static void enable_default_backfs_features(struct mkfs_opts *mop)
{
        struct utsname uts;
        int maj_high, maj_low, min;
        int ret;

        strscat(mop->mo_mkfsopts, " -O dir_index", sizeof(mop->mo_mkfsopts));

        /* Upstream e2fsprogs called our uninit_groups feature uninit_bg,
         * check for both of them when testing e2fsprogs features. */
        if (is_e2fsprogs_feature_supp("uninit_groups") == 0)
                strscat(mop->mo_mkfsopts, ",uninit_groups",
                        sizeof(mop->mo_mkfsopts));
        else if (is_e2fsprogs_feature_supp("uninit_bg") == 0)
                strscat(mop->mo_mkfsopts, ",uninit_bg",
                        sizeof(mop->mo_mkfsopts));
        else
                disp_old_e2fsprogs_msg("uninit_bg", 1);

        ret = uname(&uts);
        if (ret)
                return;

        sscanf(uts.release, "%d.%d.%d", &maj_high, &maj_low, &min);
        printf("%d %d %d\n", maj_high, maj_low, min);

        /* Multiple mount protection is enabled only if failover node is
         * specified and if kernel version is higher than 2.6.9 */
        if (failover) {
                if (KERNEL_VERSION(maj_high, maj_low, min) >=
                    KERNEL_VERSION(2,6,9)) {
                        if (is_e2fsprogs_feature_supp("mmp") == 0)
                                strscat(mop->mo_mkfsopts, ",mmp",
                                        sizeof(mop->mo_mkfsopts));
                        else
                                disp_old_e2fsprogs_msg("mmp", 1);
                } else {
                        disp_old_kernel_msg("mmp");
                }
        }
}
/* Build fs according to type */
int make_lustre_backfs(struct mkfs_opts *mop)
{
        char mkfs_cmd[PATH_MAX];
        char buf[64];
        char *dev;
        int ret = 0;
        int block_count = 0;

        if (mop->mo_device_sz != 0) {
                if (mop->mo_device_sz < 8096){
                        fprintf(stderr, "%s: size of filesystem must be larger "
                                "than 8MB, but is set to %lluKB\n",
                                progname, (long long)mop->mo_device_sz);
                        return EINVAL;
                }
                block_count = mop->mo_device_sz / (L_BLOCK_SIZE >> 10);
        }

        if ((mop->mo_ldd.ldd_mount_type == LDD_MT_EXT3) ||
            (mop->mo_ldd.ldd_mount_type == LDD_MT_LDISKFS) ||
            (mop->mo_ldd.ldd_mount_type == LDD_MT_LDISKFS2)) {
                __u64 device_sz = mop->mo_device_sz;

                /* we really need the size */
                if (device_sz == 0) {
                        device_sz = get_device_size(mop->mo_device);
                        if (device_sz == 0)
                                return ENODEV;
                }

                /* Journal size in MB */
                if (strstr(mop->mo_mkfsopts, "-J") == NULL) {
                        /* Choose our own default journal size */
                        long journal_sz = 0, max_sz;
                        if (device_sz > 1024 * 1024) /* 1GB */
                                journal_sz = (device_sz / 102400) * 4;
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

                /* bytes_per_inode: disk size / num inodes */
                if (strstr(mop->mo_mkfsopts, "-i") == NULL) {
                        long bytes_per_inode = 0;

                        if (IS_MDT(&mop->mo_ldd))
                                bytes_per_inode = 4096;

                        /* Allocate fewer inodes on large OST devices.  Most
                           filesystems can be much more aggressive than even
                           this. */
                        if ((IS_OST(&mop->mo_ldd) && (device_sz > 1000000)))
                                bytes_per_inode = 16384;

                        if (bytes_per_inode > 0) {
                                sprintf(buf, " -i %ld", bytes_per_inode);
                                strscat(mop->mo_mkfsopts, buf,
                                        sizeof(mop->mo_mkfsopts));
                        }
                }

                /* Inode size (for extended attributes).  The LOV EA size is
                 * 32 (EA hdr) + 32 (lov_mds_md) + stripes * 24 (lov_ost_data),
                 * and we want some margin above that for ACLs, other EAs... */
                if (strstr(mop->mo_mkfsopts, "-I") == NULL) {
                        long inode_size = 0;
                        if (IS_MDT(&mop->mo_ldd)) {
                                if (mop->mo_stripe_count > 72)
                                        inode_size = 512; /* bz 7241 */
                                /* cray stripes across all osts (>60) */
                                else if (mop->mo_stripe_count > 32)
                                        inode_size = 2048;
                                else if (mop->mo_stripe_count > 10)
                                        inode_size = 1024;
                                else
                                        inode_size = 512;
                        } else if (IS_OST(&mop->mo_ldd)) {
                                /* now as we store fids in EA on OST we need
                                   to make inode bigger */
                                inode_size = 256;
                        }

                        if (inode_size > 0) {
                                sprintf(buf, " -I %ld", inode_size);
                                strscat(mop->mo_mkfsopts, buf,
                                        sizeof(mop->mo_mkfsopts));
                        }
                }

                if (verbose < 2) {
                        strscat(mop->mo_mkfsopts, " -q",
                                sizeof(mop->mo_mkfsopts));
                }

                if (strstr(mop->mo_mkfsopts, "-O") == NULL)
                        enable_default_backfs_features(mop);

                /* Allow reformat of full devices (as opposed to
                   partitions.)  We already checked for mounted dev. */
                strscat(mop->mo_mkfsopts, " -F", sizeof(mop->mo_mkfsopts));

                snprintf(mkfs_cmd, sizeof(mkfs_cmd),
                         "mkfs.ext2 -j -b %d -L %s ", L_BLOCK_SIZE,
                         mop->mo_ldd.ldd_svname);

        } else if (mop->mo_ldd.ldd_mount_type == LDD_MT_REISERFS) {
                long journal_sz = 0; /* FIXME default journal size */
                if (journal_sz > 0) {
                        sprintf(buf, " --journal_size %ld", journal_sz);
                        strscat(mop->mo_mkfsopts, buf,
                                sizeof(mop->mo_mkfsopts));
                }
                snprintf(mkfs_cmd, sizeof(mkfs_cmd), "mkreiserfs -ff ");

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
        vprint("\t4k blocks     %d\n", block_count);
        vprint("\toptions       %s\n", mop->mo_mkfsopts);

        /* mkfs_cmd's trailing space is important! */
        strscat(mkfs_cmd, mop->mo_mkfsopts, sizeof(mkfs_cmd));
        strscat(mkfs_cmd, " ", sizeof(mkfs_cmd));
        strscat(mkfs_cmd, dev, sizeof(mkfs_cmd));
        if (block_count != 0) {
                sprintf(buf, " %d", block_count);
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
        printf("              (%s%s%s%s%s%s%s%s)\n",
               IS_MDT(ldd) ? "MDT ":"",
               IS_OST(ldd) ? "OST ":"",
               IS_MGS(ldd) ? "MGS ":"",
               ldd->ldd_flags & LDD_F_NEED_INDEX ? "needs_index ":"",
               ldd->ldd_flags & LDD_F_VIRGIN     ? "first_time ":"",
               ldd->ldd_flags & LDD_F_UPDATE     ? "update ":"",
               ldd->ldd_flags & LDD_F_WRITECONF  ? "writeconf ":"",
               ldd->ldd_flags & LDD_F_UPGRADE14  ? "upgrade1.4 ":"");
        printf("Persistent mount opts: %s\n", ldd->ldd_mount_opts);
        printf("Parameters:%s\n", ldd->ldd_params);
        if (ldd->ldd_userdata[0])
                printf("Comment: %s\n", ldd->ldd_userdata);
        printf("\n");
}

/* Write the server config files */
int write_local_files(struct mkfs_opts *mop)
{
        char mntpt[] = "/tmp/mntXXXXXX";
        char filepnm[128];
        char *dev;
        FILE *filep;
        int ret = 0;

        /* Mount this device temporarily in order to write these files */
        if (!mkdtemp(mntpt)) {
                fprintf(stderr, "%s: Can't create temp mount point %s: %s\n",
                        progname, mntpt, strerror(errno));
                return errno;
        }

        dev = mop->mo_device;
        if (mop->mo_flags & MO_IS_LOOP)
                dev = mop->mo_loopdev;

        ret = mount(dev, mntpt, MT_STR(&mop->mo_ldd), 0, NULL);
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
        ret = mkdir(filepnm, 0777);
        if ((ret != 0) && (errno != EEXIST)) {
                fprintf(stderr, "%s: Can't make configs dir %s: %s\n",
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
        fwrite(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
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
        snprintf(cmd, cmdsz, "debugfs -c -R 'dump /%s %s/mountdata' %s",
                 MOUNT_DATA_FILE, tmpdir, dev);

        ret = run_command(cmd, cmdsz);
        if (ret)
                verrprint("%s: Unable to dump %s dir (%d)\n",
                          progname, MOUNT_CONFIGS_DIR, ret);

        sprintf(filepnm, "%s/mountdata", tmpdir);
        filep = fopen(filepnm, "r");
        if (filep) {
                vprint("Reading %s\n", MOUNT_DATA_FILE);
                fread(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
        } else {
                /* COMPAT_146 */
                /* Try to read pre-1.6 config from last_rcvd */
                struct lr_server_data lsd;
                verrprint("%s: Unable to read %d.%d config %s.\n",
                          progname, LUSTRE_MAJOR, LUSTRE_MINOR, filepnm);

                verrprint("Trying 1.4 config from last_rcvd\n");
                sprintf(filepnm, "%s/%s", tmpdir, LAST_RCVD);

                /* Construct debugfs command line. */
                snprintf(cmd, cmdsz, "debugfs -c -R 'dump /%s %s' %s",
                         LAST_RCVD, filepnm, dev);

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
                        snprintf(cmd, cmdsz, "debugfs -c -R 'ls -l /' %s", dev);
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
                        snprintf(cmd, cmdsz, "debugfs -c -R 'rdump /%s %s' %s",
                                 MDT_LOGS_DIR, tmpdir, dev);
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
        if (get_os_version() == 24)
                mop->mo_ldd.ldd_mount_type = LDD_MT_EXT3;
        else
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

static int clean_param(char *buf, char *key)
{
        char *sub, *next;

        if (!buf)
                return 1;
        if ((sub = strstr(buf, key)) != NULL) {
                if ((next = strchr(sub, ' ')) != NULL) {
                        next++;
                        memmove(sub, next, strlen(next) + 1);
                } else {
                        *sub = '\0';
                }
        }
        return 0;
}

static int add_param(char *buf, char *key, char *val, int unique)
{
        int end = sizeof(((struct lustre_disk_data *)0)->ldd_params);
        int start;
        int keylen = 0;
        char *ptr;

        if (key)
                keylen = strlen(key);
        if (unique) {
                if (key) {
                        clean_param(buf, key);
                } else {
                        if ((ptr = strchr(val, '=')) == NULL)
                                return 1;
                        *ptr = '\0';
                        clean_param(buf, val);
                        *ptr = '=';
                }
        }

        start = strlen(buf);
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
                        fprintf(stderr, "%s: Can't parse NID '%s'\n", progname, s1);
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
                {"verbose", 0, 0, 'v'},
                {"writeconf", 0, 0, 'w'},
                {0, 0, 0, 0}
        };
        char *optstring = "b:c:C:d:ef:Ghi:k:L:m:MnNo:Op:Pqru:vw";
        int opt;
        int rc, longidx;
        int upcall = 0;
        const size_t prefix_len = sizeof(PARAM_MDT_UPCALL) - 1;

        while ((opt = getopt_long(argc, argv, optstring, long_opt, &longidx)) !=
               EOF) {
                switch (opt) {
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
                case 'f': {
                        char *nids = convert_hostnames(optarg);
                        if (!nids)
                                return 1;
                        rc = add_param(mop->mo_ldd.ldd_params, PARAM_FAILNODE,
                                       nids, 0);
                        free(nids);
                        if (rc)
                                return rc;
                        /* Must update the mgs logs */
                        mop->mo_ldd.ldd_flags |= LDD_F_UPDATE;
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
                                       nids, 0);
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
                        /* Test if the param is valid for mdt.group_upcall */
                        if (!strncmp(optarg, PARAM_MDT_UPCALL, prefix_len)) {
                                upcall++;
                                if (strcmp(optarg + prefix_len, "NONE") &&
                                    access(optarg + prefix_len, R_OK | X_OK))
                                        fprintf(stderr, "WARNING: group upcall "
                                                "parameter not executable: %s\n"
                                                "NOTE: you can change the path "
                                                "to the group upcall through "
                                                "tunefs.lustre(8)\n", optarg +
                                                prefix_len);
                        }
                        rc = add_param(mop->mo_ldd.ldd_params, NULL, optarg, 0);
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

#ifndef TUNEFS
        if (mop->mo_ldd.ldd_flags & LDD_F_SV_TYPE_MDT && 0 == upcall) {
                if (access("/usr/sbin/l_getgroups", R_OK | X_OK)) {
                        fprintf(stderr, "WARNING: MDS group upcall is not set, "
                                "using 'NONE'\n");
                } else {
                        rc = add_param(mop->mo_ldd.ldd_params, PARAM_MDT_UPCALL,
                                       "/usr/sbin/l_getgroups", 1);
                        if (rc)
                                return rc;
                        /* Must update the mgs logs */
                        mop->mo_ldd.ldd_flags |= LDD_F_UPDATE;
                }
        }
#endif

        return 0;
}

int main(int argc, char *const argv[])
{
        struct mkfs_opts mop;
        struct lustre_disk_data *ldd;
        char *mountopts = NULL;
        char always_mountopts[512] = "";
        char default_mountopts[512] = "";
        int  ret = 0;

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

        if (!IS_MGS(ldd) && (mop.mo_mgs_failnodes == 0)) {
                fatal();
                if (IS_MDT(ldd))
                        fprintf(stderr, "Must specify --mgs or --mgsnode=\n");
                else
                        fprintf(stderr, "Must specify --mgsnode=\n");
                ret = EINVAL;
                goto out;
        }

        /* These are the permanent mount options (always included) */
        switch (ldd->ldd_mount_type) {
        case LDD_MT_EXT3:
        case LDD_MT_LDISKFS:
        case LDD_MT_LDISKFS2: {
                sprintf(always_mountopts, "errors=remount-ro");
                if (IS_MDT(ldd) || IS_MGS(ldd))
                        strscat(always_mountopts, ",iopen_nopriv,user_xattr",
                                sizeof(always_mountopts));
                if ((get_os_version() == 24) && IS_OST(ldd))
                        strscat(always_mountopts, ",asyncdel",
                                sizeof(always_mountopts));
                /* NB: Files created while extents are enabled cannot be read
                   if mounted with a kernel that doesn't include the Lustre ldiskfs
                   patches! */
                if (IS_OST(ldd) &&
                    (ldd->ldd_mount_type == LDD_MT_LDISKFS ||
                     ldd->ldd_mount_type == LDD_MT_LDISKFS2)) {
                        strscat(default_mountopts, ",extents,mballoc",
                                sizeof(default_mountopts));
                }
                break;
        }
        case LDD_MT_SMFS: {
                mop.mo_flags |= MO_IS_LOOP;
                sprintf(always_mountopts, "type=ext3,dev=%s",
                        mop.mo_device);
                break;
        }
        default: {
                fatal();
                fprintf(stderr, "unknown fs type %d '%s'\n",
                        ldd->ldd_mount_type,
                        MT_STR(ldd));
                ret = EINVAL;
                goto out;
        }
        }

        if (mountopts) {
                /* If user specifies mount opts, don't use defaults,
                   but always use always_mountopts */
                sprintf(ldd->ldd_mount_opts, "%s,%s",
                        always_mountopts, mountopts);
        } else {
#ifdef TUNEFS
                if (ldd->ldd_mount_opts[0] == 0)
                        /* use the defaults unless old opts exist */
#endif
                {
                        sprintf(ldd->ldd_mount_opts, "%s%s",
                                always_mountopts, default_mountopts);
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
