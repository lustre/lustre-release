/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Lin Song Tao <lincent@clusterfs.com>
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
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <string.h>
#include <getopt.h>

#include <linux/types.h>
#define NO_SYS_VFS 1
#include <linux/fs.h> // for BLKGETSIZE64
#include <linux/lustre_disk.h>
#include <lnet/lnetctl.h>
#include "obdctl.h"

/* So obd.o will link */
#include "parser.h"
command_t cmdlist[] = {
        { 0, 0, 0, NULL }
};

/* FIXME */
#define MAX_LOOP_DEVICES 256

static char *progname;
static int verbose = 1;
static int print_only = 0;

/* for running system() */
static char cmd[128];
static char cmd_out[32][128];
static char *ret_file = "/tmp/mkfs.log";
        

void usage(FILE *out)
{
        fprintf(out, "usage: %s <target types> [options] <device>\n", progname);

        fprintf(out, 
                "\t<device>:block device or file (e.g /dev/sda or /tmp/ost1)\n"
                "\ttarget types:\n"
                "\t\t--ost: object storage, mutually exclusive with mdt\n"
                "\t\t--mdt: metadata storage, mutually exclusive with ost\n"
                "\t\t--mgs: configuration management service - one per site\n"
                "\toptions:\n"
                "\t\t--mgsnid=<nid>[,<...>] : NID(s) of a remote mgs node\n"
                "\t\t\trequired for all targets other than the mgs node\n"
                "\t\t--fsname=<filesystem_name> : default is 'lustre'\n"
#if 0 /* FIXME implement */
                "\t\t--configdev=<altdevice|file>: store configuration info\n"
                "\t\t\tfor this device on an alternate device\n"
#endif
                "\t\t--failover=<nid>[,<...>] : list of NIDs for the failover\n"
                "\t\t\tpartners for this target\n" 
                "\t\t--backfstype=<fstype> : backing fs type (ext3, ldiskfs)\n"
                "\t\t--device-size=#N(KB) : device size for loop devices\n"
                "\t\t--stripe-count=#N : default number of stripes\n"
                "\t\t--stripe-size=#N(KB) : default stripe size\n"
                "\t\t--index=#N : target index\n"
                "\t\t--mountfsoptions=<opts> : permanent mount options\n"
#ifndef TUNEFS
                "\t\t--mkfsoptions=<opts> : format options\n"
                "\t\t--reformat: overwrite an existing disk\n"
#else
                "\t\t--nomgs: turn off MGS service on this MDT\n"
#endif
                "\t\t--print: just report what we would do; don't write to "
                "disk\n"
                "\t\t--timeout=<secs> : system timeout period\n"
                "\t\t--verbose\n"
                "\t\t--quiet\n");
        return;
}

#define vprint if (verbose > 0) printf

static void fatal(void)
{
        verbose = 0;
        fprintf(stderr, "\n%s FATAL: ", progname);
}

/*================ utility functions =====================*/

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

int run_command(char *cmd)
{
       int i = 0;
       FILE *fp = NULL;

       if (verbose > 1)
               printf("cmd: %s\n", cmd);
       
       strcat(cmd, " >");
       strcat(cmd, ret_file);
       strcat(cmd, " 2>&1");
  
       fp = popen(cmd, "r");
       if (!fp) {
               fprintf(stderr, "%s: %s\n", progname, strerror(errno));
               return -1;
       }
      
       memset(cmd_out, 0, sizeof(cmd_out));
       while (fgets(cmd_out[i], 128, fp) != NULL) {
               if (verbose > 2) 
                       printf("  _ %s", cmd_out[i]); 
               i++;
               if (i >= 32) 
                       break;
       }
       pclose(fp);

       return 0;
}

static void run_command_out()
{
        int i;
        for (i = 0; i < 32; i++) {
                if (strlen(cmd_out[i]) == 0)
                        break;
                fprintf(stderr, cmd_out[i]);
        }
}

#if 0
static int lnet_setup = 0;
static int lnet_start()
{
        ptl_initialize(0, NULL);
        if (access("/proc/sys/lnet", X_OK) != 0) {
                fprintf(stderr, "%s: The LNET module must be loaded to "
                        "determine local NIDs\n", progname);
                return 1;
        }
        if (jt_ptl_get_nids(NULL) == -ENETDOWN) {
                char *cmd[]={"network", "up"};
                jt_ptl_network(2, cmd);
                lnet_setup++;
        }
        return 0;
}

static void lnet_stop()
{
        char *cmd[]={"network", "down"};
        if (--lnet_setup == 0)
                jt_ptl_network(2, cmd);
}
#endif

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
                return 1;
        }

        /* Find unused loop device */
        for (i = 0; i < MAX_LOOP_DEVICES; i++) {
                sprintf(l_device, "%s%d", loop_base, i);
                if (access(l_device, F_OK | R_OK)) 
                        break;
                sprintf(cmd, "losetup %s > /dev/null 2>&1", l_device);
                if (verbose > 1) 
                        printf("cmd: %s\n", cmd);
                ret = system(cmd);
                /* losetup gets 1 (ret=256) for non-set-up device */
                if (ret) {
                        /* Set up a loopback device to our file */
                        sprintf(cmd, "losetup %s %s", l_device, mop->mo_device);
                        ret = run_command(cmd);
                        if (ret) {
                                fprintf(stderr, "%s: error %d on losetup: %s\n",
                                        progname, ret, strerror(ret));
                                return ret;
                        }
                        strcpy(mop->mo_loopdev, l_device);
                        return ret;
                }
        }
        
        fprintf(stderr,"%s: out of loop devices!\n", progname);
        return EMFILE;
}       

int loop_cleanup(struct mkfs_opts *mop)
{
        int ret = 1;
        if ((mop->mo_flags & MO_IS_LOOP) && *mop->mo_loopdev) {
                sprintf(cmd, "losetup -d %s", mop->mo_loopdev);
                ret = run_command(cmd);
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

#if 0
        sprintf(cmd, "sfdisk -s %s", device);
        ret = run_command(cmd);
        if (ret == 0) {
                size = atoll(cmd_out[0]);
                return (size);
        }
#endif
        /* bz5831 BLKGETSIZE64 */
        fd = open(device, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "%s: cannot open %s: %s\n", 
                        progname, device, strerror(errno));
                return 0;
        }

        ret = ioctl(fd, BLKGETSIZE64, (void*)&size);
        close(fd);
        if (ret < 0) {
                fprintf(stderr, "%s: size ioctl failed: %s\n", 
                        progname, strerror(errno));
                return 0;
        }
        
        return size;
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

/* Check whether the file exists in the device */
static int file_in_dev(char *file_name, char *dev_name)
{
        FILE *fp;
        char debugfs_cmd[256];
        unsigned int inode_num;

        /* Construct debugfs command line. */
        memset(debugfs_cmd, 0, sizeof(debugfs_cmd));
        sprintf(debugfs_cmd, "debugfs -c -R 'stat %s' %s 2>&1 | egrep Inode",
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

        pclose(fp);
        return 0;
}

/* Check whether the device has already been fomatted by mkfs.lustre */
static int is_lustre_target(struct mkfs_opts *mop)
{
        /* Check whether there exist MOUNT_DATA_FILE,
           LAST_RCVD or CATLIST in the device. */
        vprint("checking for existing Lustre data\n");
        
        if (file_in_dev(MOUNT_DATA_FILE, mop->mo_device)
            || file_in_dev(LAST_RCVD, mop->mo_device)
            || file_in_dev(CATLIST, mop->mo_device)) { 
                vprint("found Lustre data\n");
                return 1; 
        }

        return 0; /* The device is not a lustre target. */
}

/* Build fs according to type */
int make_lustre_backfs(struct mkfs_opts *mop)
{
        char mkfs_cmd[256];
        char buf[40];
        char *dev;
        int ret = 0;
        int block_count = 0;

        if (mop->mo_device_sz != 0) {
                if (mop->mo_device_sz < 8096){
                        fprintf(stderr, "%s: size of filesystem must be larger "
                                "than 8MB, but is set to %lldKB\n",
                                progname, mop->mo_device_sz);
                        return EINVAL;
                }
                block_count = mop->mo_device_sz / 4; /* block size is 4096 */
        }       
        
        if ((mop->mo_ldd.ldd_mount_type == LDD_MT_EXT3) ||
            (mop->mo_ldd.ldd_mount_type == LDD_MT_LDISKFS)) { 
                __u64 device_sz = mop->mo_device_sz;

                /* we really need the size */
                if (device_sz == 0) {
                        device_sz = get_device_size(mop->mo_device);
                        if (device_sz == 0) 
                                return ENODEV;
                }

                if (strstr(mop->mo_mkfsopts, "-J") == NULL) {
                        /* Choose our own default journal size */
                        long journal_sz = 0;
                        if (device_sz > 1024 * 1024) 
                                journal_sz = (device_sz / 102400) * 4;
                        if (journal_sz > 400)
                                journal_sz = 400;
                        if (journal_sz) {
                                sprintf(buf, " -J size=%ld", journal_sz);
                                strcat(mop->mo_mkfsopts, buf);
                        }
                }

                /* Default bytes_per_inode is block size */
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
                                strcat(mop->mo_mkfsopts, buf);
                        }
                }
                
                /* This is an undocumented mke2fs option. Default is 128. */
                if (strstr(mop->mo_mkfsopts, "-I") == NULL) {
                        long inode_size = 0;
                        if (IS_MDT(&mop->mo_ldd)) {
                                if (mop->mo_ldd.ldd_stripe_count > 77)
                                        inode_size = 512; /* bz 7241 */
                                else if (mop->mo_ldd.ldd_stripe_count > 34)
                                        inode_size = 2048;
                                else if (mop->mo_ldd.ldd_stripe_count > 13)
                                        inode_size = 1024;
                                else 
                                        inode_size = 512;
                        }
                        
                        if (inode_size > 0) {
                                sprintf(buf, " -I %ld", inode_size);
                                strcat(mop->mo_mkfsopts, buf);
                        }
                        
                }

                /* Enable hashed b-tree directory lookup in large dirs bz6224 */
                if (strstr(mop->mo_mkfsopts, "-O") == NULL) {
                        sprintf(buf, " -O dir_index");
                        strcat(mop->mo_mkfsopts, buf);
                }

                sprintf(mkfs_cmd, "mkfs.ext2 -j -b 4096 -L %s ",
                        mop->mo_ldd.ldd_svname);

        } else if (mop->mo_ldd.ldd_mount_type == LDD_MT_REISERFS) {
                long journal_sz = 0; /* FIXME default journal size */
                if (journal_sz > 0) { 
                        sprintf(buf, " --journal_size %ld", journal_sz);
                        strcat(mop->mo_mkfsopts, buf);
                }
                sprintf(mkfs_cmd, "mkreiserfs -ff ");

        } else {
                fprintf(stderr,"%s: unsupported fs type: %d (%s)\n",
                        progname, mop->mo_ldd.ldd_mount_type, 
                        MT_STR(&mop->mo_ldd));
                return EINVAL;
        }

        /* Loop device? */
        dev = mop->mo_device;
        if (mop->mo_flags & MO_IS_LOOP) 
                dev = mop->mo_loopdev;
        
        vprint("formatting backing filesystem %s on %s\n",
               MT_STR(&mop->mo_ldd), dev);
        vprint("\ttarget name  %s\n", mop->mo_ldd.ldd_svname);
        vprint("\t4k blocks     %d\n", block_count);
        vprint("\toptions       %s\n", mop->mo_mkfsopts);

        /* mkfs_cmd's trailing space is important! */
        strcat(mkfs_cmd, mop->mo_mkfsopts);
        strcat(mkfs_cmd, " ");
        strcat(mkfs_cmd, dev);
        if (block_count != 0) {
                sprintf(buf, " %d", block_count);
                strcat(mkfs_cmd, buf);
        }

        vprint("mkfs_cmd = %s\n", mkfs_cmd);
        ret = run_command(mkfs_cmd);
        if (ret) {
                fatal();
                fprintf(stderr, "Unable to build fs: %s \n", dev);
                run_command_out();
                goto out;
        }

out:
        return ret;
}

/* ==================== Lustre config functions =============*/

void print_ldd(char *str, struct lustre_disk_data *ldd)
{
        int i = 0;
        printf("\n   %s:\n", str);
        printf("Target:     %s\n", ldd->ldd_svname);
        printf("Index:      %d\n", ldd->ldd_svindex);
        printf("UUID:       %s\n", (char *)ldd->ldd_uuid);
        printf("Lustre FS:  %s\n", ldd->ldd_fsname);
        printf("Mount type: %s\n", MT_STR(ldd));
        printf("Flags:      %#x\n", ldd->ldd_flags);
        printf("              (%s%s%s%s%s%s)\n",
               IS_MDT(ldd) ? "MDT ":"", 
               IS_OST(ldd) ? "OST ":"",
               IS_MGS(ldd) ? "MGS ":"",
               ldd->ldd_flags & LDD_F_NEED_INDEX ? "needs_index ":"",
               ldd->ldd_flags & LDD_F_NEED_REGISTER ? "must_register ":"",
               ldd->ldd_flags & LDD_F_UPGRADE14 ? "upgrade1.4 ":"");
        printf("Persistent mount opts: %s\n", ldd->ldd_mount_opts);
        printf("MGS nids: ");
        for (i = 0; i < ldd->ldd_mgsnid_count; i++) {
                printf("%c %s", (i == 0) ? ' ' : ',',
                       libcfs_nid2str(ldd->ldd_mgsnid[i]));
        }
        printf("\nFailover nids: ");
        for (i = 0; i < ldd->ldd_failnid_count; i++) {
                printf("%c %s", (i == 0) ? ' ' : ',',
                       libcfs_nid2str(ldd->ldd_failnid[i]));
        }

        printf("\n\n");
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
        vprint("mounting backing device\n");
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
                        progname, mop->mo_device, strerror(ret));
                goto out_rmdir;
        }

        /* Set up initial directories */
        sprintf(filepnm, "%s/%s", mntpt, MOUNT_CONFIGS_DIR);
        ret = mkdir(filepnm, 0777);
        if ((ret != 0) && (errno != EEXIST)) {
                fprintf(stderr, "%s: Can't make configs dir %s (%d)\n", 
                        progname, filepnm, ret);
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
                fprintf(stderr, "%s: Unable to create %s file\n",
                        progname, filepnm);
                goto out_umnt;
        }
        fwrite(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
        fclose(filep);
        
        /* COMPAT_146 */
#ifdef TUNEFS
        /* Check for upgrade */
        if ((mop->mo_ldd.ldd_flags & (LDD_F_UPGRADE14 | LDD_F_SV_TYPE_MGS)) 
            == (LDD_F_UPGRADE14 | LDD_F_SV_TYPE_MGS)) {
                char *term;
                vprint("Copying old logs\n");
                /* Copy the old client log to fsname-client */
                sprintf(filepnm, "%s/%s/%s-client", 
                        mntpt, MOUNT_CONFIGS_DIR, mop->mo_ldd.ldd_fsname);
                sprintf(cmd, "cp %s/%s/client %s", mntpt, MDT_LOGS_DIR,
                        filepnm);
                if (verbose > 1) 
                        printf("cmd: %s\n", cmd);
                ret = system(cmd);
                if (ret) {
                        fprintf(stderr, "%s: Can't copy 1.4 config %s/client "
                                "(%d)\n", progname, MDT_LOGS_DIR, ret);
                        fprintf(stderr, "mount -t ext3 %s somewhere, "
                                "find the client log for fs %s and "
                                "copy it manually into %s/%s-client, "
                                "then umount.\n",
                                mop->mo_device, 
                                mop->mo_ldd.ldd_fsname, MOUNT_CONFIGS_DIR,
                                mop->mo_ldd.ldd_fsname);
                        goto out_umnt;
                }
                /* Copy the old mdt log to fsname-MDT0000 (get old
                   name from mdt_UUID) */
                ret = 1;
                strcpy(filepnm, mop->mo_ldd.ldd_uuid);
                term = strstr(filepnm, "_UUID");
                if (term) {
                        *term = '\0';
                        sprintf(cmd, "cp %s/%s/%s %s/%s/%s",
                                mntpt, MDT_LOGS_DIR, filepnm, 
                                mntpt, MOUNT_CONFIGS_DIR,
                                mop->mo_ldd.ldd_svname);
                        if (verbose > 1) 
                                printf("cmd: %s\n", cmd);
                        ret = system(cmd);
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
        vprint("unmounting backing device\n");
        umount(mntpt);    
out_rmdir:
        rmdir(mntpt);
        return ret;
}

int read_local_files(struct mkfs_opts *mop)
{
        char mntpt[] = "/tmp/mntXXXXXX";
        char filepnm[128];
        char *dev;
        FILE *filep;
        int ret = 0;

        /* Mount this device temporarily in order to read these files */
        vprint("mounting backing device\n");
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
                        progname, mop->mo_device, strerror(ret));
                goto out_rmdir;
        }

        sprintf(filepnm, "%s/%s", mntpt, MOUNT_DATA_FILE);
        filep = fopen(filepnm, "r");
        if (filep) {
                vprint("Reading %s\n", MOUNT_DATA_FILE);
                fread(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
        } else {
                /* COMPAT_146 */
                /* Try to read pre-1.6 config from last_rcvd */
                struct lr_server_data lsd;
                fprintf(stderr, "%s: Unable to read %s, trying last_rcvd\n",
                        progname, MOUNT_DATA_FILE);
                sprintf(filepnm, "%s/%s", mntpt, LAST_RCVD);
                filep = fopen(filepnm, "r");
                if (!filep) {
                        fprintf(stderr, "%s: Unable to read old data\n",
                                progname);
                        ret = errno;
                        goto out_umnt;
                }
                vprint("Reading %s\n", LAST_RCVD);
                fread(&lsd, sizeof(lsd), 1, filep);

                if (lsd.lsd_feature_compat & OBD_COMPAT_OST) {
                        mop->mo_ldd.ldd_flags = LDD_F_SV_TYPE_OST;
                        mop->mo_ldd.ldd_svindex = lsd.lsd_ost_index;
                } else if (lsd.lsd_feature_compat & OBD_COMPAT_MDT) {
                        /* We must co-locate so mgs can see old logs.
                           If user doesn't want this, they can copy the old
                           logs manually and re-tunefs. */
                        mop->mo_ldd.ldd_flags = 
                                LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_MGS;
                        mop->mo_ldd.ldd_svindex = lsd.lsd_mdt_index;
                } else  {
                        /* If neither is set, we're pre-1.4.6, make a guess. */
                        sprintf(filepnm, "%s/%s", mntpt, MDT_LOGS_DIR);
                        if (lsd.lsd_ost_index > 0) {
                                mop->mo_ldd.ldd_flags = LDD_F_SV_TYPE_OST;
                                mop->mo_ldd.ldd_svindex = lsd.lsd_ost_index;
                        } else {
                                if ((ret = access(filepnm, F_OK)) == 0) {
                                        mop->mo_ldd.ldd_flags =
                                        LDD_F_SV_TYPE_MDT | 
                                        LDD_F_SV_TYPE_MGS;
                                        /* Old MDT's are always index 0 
                                           (pre CMD) */
                                        mop->mo_ldd.ldd_svindex = 0;
                                } else {
                                        /* The index won't be correct */
                                        mop->mo_ldd.ldd_flags =
                                        LDD_F_SV_TYPE_OST | LDD_F_NEED_INDEX;
                                }
                        }
                }

                memcpy(mop->mo_ldd.ldd_uuid, lsd.lsd_uuid, 
                       sizeof(mop->mo_ldd.ldd_uuid));
                mop->mo_ldd.ldd_flags |= LDD_F_UPGRADE14;
        }
        /* end COMPAT_146 */
        fclose(filep);
        
out_umnt:
        vprint("unmounting backing device\n");
        umount(mntpt);    
out_rmdir:
        rmdir(mntpt);
        return ret;
}


void set_defaults(struct mkfs_opts *mop)
{
        mop->mo_ldd.ldd_magic = LDD_MAGIC;
        mop->mo_ldd.ldd_config_ver = 1;
        mop->mo_ldd.ldd_flags = LDD_F_NEED_INDEX | LDD_F_NEED_REGISTER;
        mop->mo_ldd.ldd_mgsnid_count = 0;
        strcpy(mop->mo_ldd.ldd_fsname, "lustre");
        if (get_os_version() == 24) 
                mop->mo_ldd.ldd_mount_type = LDD_MT_EXT3;
        else 
                mop->mo_ldd.ldd_mount_type = LDD_MT_LDISKFS;
        
        mop->mo_ldd.ldd_svindex = -1;
        mop->mo_ldd.ldd_stripe_count = 1;
        mop->mo_ldd.ldd_stripe_sz = 1024 * 1024;
        mop->mo_ldd.ldd_stripe_pattern = 0;
}

static inline void badopt(const char *opt, char *type)
{
        fprintf(stderr, "%s: '--%s' only valid for %s\n",
                progname, opt, type);
        usage(stderr);
}

int parse_opts(int argc, char *const argv[], struct mkfs_opts *mop,
               char *mountopts)
{
        static struct option long_opt[] = {
                {"backfstype", 1, 0, 'b'},
                {"configdev", 1, 0, 'C'},
                {"device-size", 1, 0, 'd'},
                {"fsname",1, 0, 'n'},
                {"failover", 1, 0, 'f'},
                {"help", 0, 0, 'h'},
                {"mdt", 0, 0, 'M'},
                {"mgs", 0, 0, 'G'},
                {"mgsnid", 1, 0, 'm'},
                {"mkfsoptions", 1, 0, 'k'},
                {"mountfsoptions", 1, 0, 'o'},
                {"nomgs", 0, 0, 'N'},
                {"ost", 0, 0, 'O'},
                {"print", 0, 0, 'p'},
                {"quiet", 0, 0, 'q'},
                {"reformat", 0, 0, 'r'},
                {"startupwait", 1, 0, 'w'},
                {"stripe-count", 1, 0, 'c'},
                {"stripe-size", 1, 0, 's'},
                {"stripe-index", 1, 0, 'i'},
                {"index", 1, 0, 'i'},
                {"timeout", 1, 0, 't'},
                {"verbose", 0, 0, 'v'},
                {0, 0, 0, 0}
        };
        char *optstring = "b:C:d:n:f:hI:MGm:k:No:Opqrw:c:s:i:t:v";
        char opt;
        int longidx;

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
                                mop->mo_ldd.ldd_stripe_count = stripe_count;
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
                case 'f': {
                        int i = 0;
                        char *s1 = optarg, *s2;
                        while ((s2 = strsep(&s1, ","))) {
                                mop->mo_ldd.ldd_failnid[i++] =
                                        libcfs_str2nid(s2);
                                if (i >= MTI_NIDS_MAX) {
                                        fprintf(stderr, "%s: too many failover "
                                                "nids, ignoring %s...\n", 
                                                progname, s1);
                                        break;
                                }
                        }
                        mop->mo_ldd.ldd_failnid_count = i;
                        break;
                }
                case 'G':
                        mop->mo_ldd.ldd_flags |= LDD_F_SV_TYPE_MGS;
                        break;
                case 'h':
                        usage(stdout);
                        return 1;
                case 'i':
                        if (IS_MDT(&mop->mo_ldd) || IS_OST(&mop->mo_ldd)) {
                                mop->mo_ldd.ldd_svindex = atoi(optarg);
                                mop->mo_ldd.ldd_flags &= ~LDD_F_NEED_INDEX;
                        } else {
                                badopt(long_opt[longidx].name, "MDT,OST");
                                return 1;
                        }
                        break;
                case 'k':
                        strncpy(mop->mo_mkfsopts, optarg, 
                                sizeof(mop->mo_mkfsopts) - 1);
                        break;
                case 'm': {
                        int i = 0;
                        char *s1 = optarg, *s2;
                        if (IS_MGS(&mop->mo_ldd)) {
                                badopt(long_opt[longidx].name, 
                                       "non-MGMT MDT,OST");
                                return 1;
                        }
                        while ((s2 = strsep(&s1, ","))) {
                                mop->mo_ldd.ldd_mgsnid[i++] =
                                        libcfs_str2nid(s2);
                                if (i >= MTI_NIDS_MAX) {
                                        fprintf(stderr, "%s: too many MGS nids,"
                                                " ignoring %s...\n", 
                                                progname, s1);
                                        break;
                                }
                        }
                        mop->mo_ldd.ldd_mgsnid_count = i;
                        break;
                }
                case 'M':
                        mop->mo_ldd.ldd_flags |= LDD_F_SV_TYPE_MDT;
                        break;
                case 'n':
                        if (!(IS_MDT(&mop->mo_ldd) || IS_OST(&mop->mo_ldd))) {
                                badopt(long_opt[longidx].name, "MDT,OST");
                                return 1;
                        }
                        if (strlen(optarg) > 8) {
                                fprintf(stderr, "%s: filesystem name must be "
                                        "<= 8 chars\n", progname);
                                return 1;
                        }
                        if (optarg[0] != 0) 
                                strncpy(mop->mo_ldd.ldd_fsname, optarg, 
                                        sizeof(mop->mo_ldd.ldd_fsname) - 1);
                        break;
                case 'N':
                        mop->mo_ldd.ldd_flags &= ~LDD_F_SV_TYPE_MGS;
                        break;
                case 'o':
                        mountopts = optarg;
                        break;
                case 'O':
                        mop->mo_ldd.ldd_flags |= LDD_F_SV_TYPE_OST;
                        break;
                case 'p':
                        print_only++;
                        break;
                case 'q':
                        verbose--;
                        break;
                case 'r':
                        mop->mo_flags |= MO_FORCEFORMAT;
                        break;
                case 's':
                        if (IS_MDT(&mop->mo_ldd)) {
                                mop->mo_ldd.ldd_stripe_sz = atol(optarg) * 1024;
                        } else {
                                badopt(long_opt[longidx].name, "MDT");
                                return 1;
                        }
                        break;
                case 't':
                        mop->mo_ldd.ldd_timeout = atol(optarg);
                        break;
                case 'v':
                        verbose++;
                        break;
                default:
                        if (opt != '?') {
                                fatal();
                                fprintf(stderr, "Unknown option '%c'\n", opt);
                        }
                        usage(stderr);
                        return 1;
                }
        }//while
        if (optind >= argc) {
                fatal();
                fprintf(stderr, "Bad arguments\n");
                usage(stderr);
                return 1;
        }

        return 0;
}

int main(int argc, char *const argv[])
{
        struct mkfs_opts mop;
        char *mountopts = NULL;
        char default_mountopts[1024] = "";
        int  ret = 0;

        if ((progname = strrchr(argv[0], '/')) != NULL)
                progname++;
        else
                progname = argv[0];

        if (argc < 2) {
                usage(stderr);
                ret = 1;
                goto out;
        }

        memset(&mop, 0, sizeof(mop));
        set_defaults(&mop);

        /* device is last arg */
        strcpy(mop.mo_device, argv[argc - 1]);
        /* Are we using a loop device? */
        ret = is_block(mop.mo_device);
        if (ret < 0) 
                goto out;
        if (ret == 0) 
                mop.mo_flags |= MO_IS_LOOP;

#ifdef TUNEFS
        /* For tunefs, we must read in the old values before parsing any
           new ones. */
        /* Create the loopback file */
        if (mop.mo_flags & MO_IS_LOOP) {
                ret = access(mop.mo_device, F_OK);
                if (ret == 0)  
                        ret = loop_setup(&mop);
                if (ret) {
                        fatal();
                        fprintf(stderr, "Loop device setup for %s failed: %s\n", 
                                mop.mo_device, strerror(ret));
                        goto out;
                }
        }
        
        /* Check whether the disk has already been formatted by mkfs.lustre */
        ret = is_lustre_target(&mop);
        if (ret == 0) {
                fatal();
                fprintf(stderr, "Device %s has not been formatted with "
                        "mkfs.lustre\n", mop.mo_device);
                goto out;
        }

        ret = read_local_files(&mop);
        if (ret) {
                fatal();
                fprintf(stderr, "Failed to read previous Lustre data from %s\n",
                        mop.mo_device);
                goto out;
        }

        if (verbose > 0) 
                print_ldd("Read previous values", &(mop.mo_ldd));
#endif

        ret = parse_opts(argc, argv, &mop, mountopts);
        if (ret) 
                goto out;

        if (!(IS_MDT(&mop.mo_ldd) || IS_OST(&mop.mo_ldd) || 
              IS_MGS(&mop.mo_ldd))) {
                fatal();
                fprintf(stderr, "must set target type :{mdt,ost,mgs}\n");
                usage(stderr);
                ret = 1;
                goto out;
        }

        if (IS_MDT(&mop.mo_ldd) && !IS_MGS(&mop.mo_ldd) && 
            mop.mo_ldd.ldd_mgsnid_count == 0) {
                vprint("No management node specified, adding MGS to this "
                       "MDT\n");
                mop.mo_ldd.ldd_flags |= LDD_F_SV_TYPE_MGS;
        }

#if 0
        if (IS_MGS(&mop.mo_ldd) && (mop.mo_ldd.ldd_mgsnid_count == 0)) {
                int i;
                __u64 *nids;
                
                vprint("No mgs nids specified, using all local nids\n");
                ret = lnet_start();
                if (ret)
                        goto out;
                i = jt_ptl_get_nids(&nids);
                if (i < 0) {
                        fprintf(stderr, "%s: Can't find local nids "
                                "(is the lnet module loaded?)\n", progname);
                } else {
                        if (i > 0) {
                                if (i > MTI_NIDS_MAX) 
                                        i = MTI_NIDS_MAX;
                                vprint("Adding %d local nids for MGS\n", i);
                                memcpy(mop.mo_ldd.ldd_mgsnid, nids,
                                       sizeof(mop.mo_ldd.ldd_mgsnid));
                                free(nids);
                        }
                        mop.mo_ldd.ldd_mgsnid_count = i;
                }
        }

        if (IS_MGS(&mop.mo_ldd) && mop.mo_ldd.ldd_failnid_count) {
                /* Add failover nids to mgsnids if we start an MGS
                   (MDT must have all possible MGS nids for failover.) */
                int i = 0, j = mop.mo_ldd.ldd_mgsnid_count;
                while (i < mop.mo_ldd.ldd_failnid_count) {
                        if (j >= MTI_NIDS_MAX) 
                                break;
                        mop.mo_ldd.ldd_mgsnid[j++] =
                                mop.mo_ldd.ldd_failnid[i++];
                }
                mop.mo_ldd.ldd_mgsnid_count = j;
        }
#endif
        
        if (!IS_MGS(&mop.mo_ldd) && (mop.mo_ldd.ldd_mgsnid_count == 0)) {
                fatal();
                fprintf(stderr, "Must specify either --mgs or --mgsnid\n");
                usage(stderr);
                goto out;
        }

        /* These are the permanent mount options (always included) */ 
        switch (mop.mo_ldd.ldd_mount_type) {
        case LDD_MT_EXT3:
        case LDD_MT_LDISKFS: {
                sprintf(default_mountopts, "errors=remount-ro");
                if (IS_MDT(&mop.mo_ldd) || IS_MGS(&mop.mo_ldd))
                        strcat(default_mountopts,
                               ",iopen_nopriv,user_xattr");
                if ((get_os_version() == 24) && IS_OST(&mop.mo_ldd))
                        strcat(default_mountopts, ",asyncdel");
#if 0
                /* Files created while extents are enabled cannot be read if
                   mounted with a kernel that doesn't include the CFS patches.*/
                if ((get_os_version() == 26) && IS_OST(&mop.mo_ldd) && 
                    mop.mo_ldd.ldd_mount_type == LDD_MT_LDISKFS) {
                        strcat(default_mountopts, ",extents,mballoc");
                }
#endif               
 
                break;
        }
        case LDD_MT_SMFS: {
                mop.mo_flags |= MO_IS_LOOP;
                sprintf(default_mountopts, "type=ext3,dev=%s",
                        mop.mo_device);
                break;
        }
        default: {
                fatal();
                fprintf(stderr, "unknown fs type %d '%s'\n",
                        mop.mo_ldd.ldd_mount_type,
                        MT_STR(&mop.mo_ldd));
                ret = EINVAL;
                goto out;
        }
        }               

#ifndef TUNEFS /* mkfs.lustre */
        if (mountopts) 
                /* Tack on user supplied opts */
                sprintf(mop.mo_ldd.ldd_mount_opts, "%s,%s", 
                        default_mountopts, mountopts);
        else
                strcpy(mop.mo_ldd.ldd_mount_opts, default_mountopts);
#else   /* tunefs.lustre - if mountopts are specified, they override 
           whatever we had before, so no defaults. */
        if (mountopts) 
                strcpy(mop.mo_ldd.ldd_mount_opts, mountopts);
        else if (*mop.mo_ldd.ldd_mount_opts == 0) 
                /* no mount opts were set ever, use the defaults. */
                strcpy(mop.mo_ldd.ldd_mount_opts, default_mountopts);
        /* otherwise, use the old. */
#endif

        ldd_make_sv_name(&(mop.mo_ldd));

        if (verbose > 0)
                print_ldd("Permanent disk data", &(mop.mo_ldd));

        if (print_only) {
                printf("exiting before disk write.\n");
                goto out;
        }

#ifndef TUNEFS /* mkfs.lustre */
        /* Create the loopback file of the correct size */
        if (mop.mo_flags & MO_IS_LOOP) {
                ret = access(mop.mo_device, F_OK);
                /* Don't destroy the loopback file if no FORCEFORMAT */
                if (ret || (mop.mo_flags & MO_FORCEFORMAT))
                        ret = loop_format(&mop);
                if (ret == 0)  
                        ret = loop_setup(&mop);
                if (ret) {
                        fatal();
                        fprintf(stderr, "Loop device setup failed: %s\n", 
                                strerror(ret));
                        goto out;
                }
        }

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

        ret = write_local_files(&mop);
        if (ret != 0) {
                fatal();
                fprintf(stderr, "failed to write local files\n");
                goto out;
        }

out:
        loop_cleanup(&mop);      
        return ret;
}
