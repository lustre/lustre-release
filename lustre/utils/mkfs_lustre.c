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

#include <string.h>
#include <getopt.h>

#include <linux/types.h>
#include <linux/lustre_disk.h>
#include <portals/ptlctl.h>
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

/* for running system() */
static char cmd[128];
static char cmd_out[32][128];
static char *ret_file = "/tmp/mkfs.log";
        
/* for init loop */
static char loop_base[20];

void usage(FILE *out)
{
        fprintf(out, "usage: %s [options] <device>\n", progname);

        fprintf(out, 
                "\t<device>:block device or file (e.g /dev/sda or /tmp/ost1)\n"
                "\toptions:\n"
                "\t\t--ost: object storage, mutually exclusive with mdt\n"
                "\t\t--mdt: metadata storage, mutually exclusive with ost\n"
                "\t\t--mgmt: configuration management service - one per site\n"
                "\t\t--mgmtnode=<mgtnode>[,<failover-mgtnode>]:nid of a remote\n"
                "\t\t\tmgmt node [and the failover mgmt node]\n"
                "\t\t--fsname=<filesystem_name>\n"
                "\t\t--configdev=<altdevice|file>: store configuration info\n"
                "\t\t\tfor this device on an alternate device\n"
                "\t\t--failover=<failover-address>\n"
                "\t\t--backfstype=<fstype>: backing fs type (ext3, ldiskfs)\n"
                "\t\t--device_size=#N(KB):device size \n"
                "\t\t--stripe_count=#N:number of stripe\n"
                "\t\t--stripe_size=#N(KB):stripe size\n"
                "\t\t--index=#N:target index\n"
                "\t\t--mountfsoptions=<opts>: permanent mount options\n"
                "\t\t--mkfsoptions=<opts>: format options\n"
                "\t\t--timeout=<secs>: system timeout period\n"
                "\t\t--startupwait=<secs>: time to wait for other servers to join\n"
                "\t\t--reformat: overwrite an existing disk\n"
                "\t\t--verbose\n");
        exit(out != stdout);
}

#define vprint if (verbose) printf

static void fatal(void)
{
        verbose = 0;
        fprintf(stderr, "\n%s FATAL: ", progname);
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
                        fprintf(stderr, "Warning: Can't resolve kernel version,"
                        " assuming 2.6\n");
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

//Ugly implement. FIXME 
int run_command(char *cmd)
{
       int i = 0,ret = 0;
       FILE *rfile = NULL;

       vprint("cmd: %s\n", cmd);
       
       strcat(cmd, " >");
       strcat(cmd, ret_file);
       strcat(cmd, " 2>&1");
  
       ret = system(cmd);

       rfile = fopen(ret_file, "r");
       if (rfile == NULL){
                fprintf(stderr,"Could not open %s \n",ret_file);
                exit(2);
       }
      
       memset(cmd_out, 0, sizeof(cmd_out));
       while (fgets(cmd_out[i], 128, rfile) != NULL) {
               if (verbose > 2) printf("  _ %s", cmd_out[i]); 
               i++;
               if (i >= 32) {
                       fprintf(stderr,"WARNING losing some output from %s",
                               cmd);
                       break;
               }
       }
       fclose(rfile);

       return ret;
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

/* Figure out the loop device names */
void loop_init()
{
        if (!access("/dev/loop0", F_OK | R_OK))
                strcpy(loop_base, "/dev/loop\0");
        else if (!access("/dev/loop/0", F_OK | R_OK))
                strcpy(loop_base, "/dev/loop/\0");
        else {
                fprintf(stderr, "can't access loop devices\n");
                exit(1);
        }
        return;
}

/* Setup a file in the first unused loop_device */
int loop_setup(struct mkfs_opts *mop)
{
        char l_device[64];
        int i,ret = 0;

        for (i = 0; i < MAX_LOOP_DEVICES; i++) {
                sprintf(l_device, "%s%d", loop_base, i);
                if (access(l_device, F_OK | R_OK)) 
                        break;

                sprintf(cmd, "losetup %s", l_device);
                ret = run_command(cmd);
                /* losetup gets 1 (256?) for good non-set-up device */
                if (ret) {
                        sprintf(cmd, "losetup %s %s", l_device, mop->mo_device);
                        ret = run_command(cmd);
                        if (ret) {
                                fprintf(stderr, "error %d on losetup: %s\n",
                                        ret, strerror(ret));
                                exit(8);
                        }
                        strcpy(mop->mo_loopdev, l_device);
                        return ret;
                }
        }
        
        fprintf(stderr,"out of loop devices!\n");
        return EMFILE;
}

int loop_cleanup(struct mkfs_opts *mop)
{
        int ret = 1;
        if (mop->mo_flags & MO_IS_LOOP) {
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
                fprintf(stderr, "cannot stat %s\n",devname);
                exit(4);
        }
        return S_ISBLK(st.st_mode);
}

/* Get the devsize from /proc/partitions with the major and minor number */
int device_size_proc(char* device) 
{
        int major,minor,i,ret;
        char *ma, *mi, *sz;
        struct stat st;

        ret = stat(device,&st);
        if (ret != 0) {
                fprintf(stderr,"can not stat %s\n",device);
                exit(4);
        }
        major = dev_major(st.st_rdev);
        minor = dev_minor(st.st_rdev);

        sprintf(cmd, "cat /proc/partitions");
        ret = run_command(cmd);
        for (i = 0; i < 32; i++) {
                if (strlen(cmd_out[i]) == 0) 
                        break;
                ma = strtok(cmd_out[i], " ");
                mi = strtok(NULL, " ");
                if ((major == atol(ma)) && (minor == atol(mi))) {
                        sz = strtok(NULL," ");
                        return atol(sz);
                }
        }

        return 0; //FIXME : no entries in /proc/partitions
}

void set_nid_pair(struct host_desc *nids, char *str)
{
        nids->primary = libcfs_str2nid(str);
        // FIXME secondary too (,altnid)
}

/* Write the server config files */
int write_local_files(struct mkfs_opts *mop)
{
        struct lr_server_data lsd;
        char mntpt[] = "/tmp/mntXXXXXX";
        char filepnm[128];
        char local_mount_opts[sizeof(mop->mo_ldd.ldd_mount_opts)] = "";
        FILE *filep;
        int ret = 0;

        /* Mount this device temporarily in order to write these files */
        vprint("mounting backing device\n");
        if (!mkdtemp(mntpt)) {
                fprintf(stderr, "Can't create temp mount point %s: %s\n",
                        mntpt, strerror(errno));
                return errno;
        }

        if (mop->mo_flags & MO_IS_LOOP) {
                /* ext3 can't understand iopen_nopriv, others */
                if (strlen(mop->mo_ldd.ldd_mount_opts)) 
                        snprintf(local_mount_opts, sizeof(local_mount_opts),
                                 "loop,%s", mop->mo_ldd.ldd_mount_opts);
                else 
                        sprintf(local_mount_opts, "loop");
        }
        sprintf(cmd, "mount -t %s %s%s %s %s",
                MT_STR(&mop->mo_ldd), strlen(local_mount_opts) ? "-o ": "", 
                local_mount_opts, mop->mo_device, mntpt);
        ret = run_command(cmd);
        if (ret) {
                fprintf(stderr, "Unable to mount %s\n", mop->mo_device);
                run_command_out();
                goto out_rmdir;
        }

        /* Set up initial directories */
        sprintf(filepnm, "%s/%s", mntpt, MOUNT_CONFIGS_DIR);
        ret = mkdir(filepnm, 0755);
        if (ret) {
                fprintf(stderr, "Can't make configs dir %s (%d)\n", 
                        filepnm, ret);
                goto out_umnt;
        }

        /* Save the persistent mount data into a file. Lustre must pre-read
           this file to get the real mount options. */
        vprint("Writing %s\n", MOUNT_DATA_FILE);
        sprintf(filepnm, "%s/%s", mntpt, MOUNT_DATA_FILE);
        filep = fopen(filepnm, "w");
        if (!filep) {
                fprintf(stderr, "Unable to create %s file\n", filepnm);
                goto out_umnt;
        }
        fwrite(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
        fclose(filep);
        
        /* Create the inital last_rcvd file */
        vprint("Writing %s\n", LAST_RCVD);
        sprintf(filepnm, "%s/%s", mntpt, LAST_RCVD);
        filep = fopen(filepnm, "w");
        if (!filep) {
                ret = errno;
                fprintf(stderr,"Unable to create %s file\n", filepnm);
                goto out_umnt;
        }
        memset(&lsd, 0, sizeof(lsd));
        strncpy(lsd.lsd_uuid, mop->mo_ldd.ldd_svname, sizeof(lsd.lsd_uuid));
        lsd.lsd_index = mop->mo_index;
        lsd.lsd_feature_compat |= cpu_to_le32(LR_COMPAT_COMMON_LR);
        lsd.lsd_server_size = cpu_to_le32(LR_SERVER_SIZE);
        lsd.lsd_client_start = cpu_to_le32(LR_CLIENT_START);
        lsd.lsd_client_size = cpu_to_le16(LR_CLIENT_SIZE);
        if (IS_MDT(&mop->mo_ldd))
                lsd.lsd_feature_rocompat = cpu_to_le32(MDS_ROCOMPAT_LOVOBJID);
        
        fwrite(&lsd, sizeof(lsd), 1, filep);
        ret = 0;
        fclose(filep);
out_umnt:
        vprint("unmounting backing device\n");
        sprintf(cmd, "umount %s", mntpt);
        run_command(cmd);
out_rmdir:
        rmdir(mntpt);
        return ret;
}

int loop_format(struct mkfs_opts *mop)
{
        int ret = 0;
       
        loop_init();

        sprintf(cmd, "dd if=/dev/zero bs=1k count=0 seek=%ld of=%s", 
                mop->mo_device_sz, mop->mo_device);
        ret = run_command(cmd);
        if (ret != 0){
                fprintf(stderr, "Unable to create backing store: %d\n", ret);
        }
        return ret;
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
                        fprintf(stderr, "size of filesystem must be larger "
                                "than 8MB, but is set to %ldKB\n",
                                mop->mo_device_sz);
                        return EINVAL;
                }
                block_count = mop->mo_device_sz / 4; /* block size is 4096 */
        }       
        
        if ((mop->mo_ldd.ldd_mount_type == LDD_MT_EXT3) ||
            (mop->mo_ldd.ldd_mount_type == LDD_MT_LDISKFS)) { 
                long device_sz = mop->mo_device_sz;

                /* we really need the size */
                if (device_sz == 0){
                        sprintf(cmd, "sfdisk -s %s", mop->mo_device);
                        ret = run_command(cmd);
                        if (ret == 0)
                                device_sz = atol(cmd_out[0]);
                        else 
                                device_sz = device_size_proc(mop->mo_device);
                }           

                if (strstr(mop->mo_mkfsopts, "-J") == NULL) {
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

                if (strstr(mop->mo_mkfsopts, "-i") == NULL) {
                        long inode_sz = 0;
                        
                       /* The larger the bytes-per-inode ratio, the fewer
                          inodes will  be  created. */
                        if (mop->mo_stripe_count > 77)
                                inode_sz = 4096;
                        else if (mop->mo_stripe_count > 35)
                                inode_sz = 2048;
                        else if (IS_MDT(&mop->mo_ldd)) 
                                inode_sz = 1024;
                        else if ((IS_OST(&mop->mo_ldd) && (device_sz > 1000000))) 
                                  inode_sz = 16384;
                        if (inode_sz > 0) {
                                sprintf(buf, " -i %ld", inode_sz);
                                strcat(mop->mo_mkfsopts, buf);
                        }
                }

                sprintf(mkfs_cmd, "mkfs.ext2 -j -b 4096 -L %s ",
                        mop->mo_ldd.ldd_svname);

        } else if (mop->mo_ldd.ldd_mount_type == LDD_MT_REISERFS) {
                long journal_sz = 0;
                if (journal_sz > 0) { /* FIXME */
                        sprintf(buf, " --journal_size %ld", journal_sz);
                        strcat(mop->mo_mkfsopts, buf);
                }
                sprintf(mkfs_cmd, "mkreiserfs -ff ");

        } else {
                fprintf(stderr,"unsupported fs type: %d (%s)\n",
                        mop->mo_ldd.ldd_mount_type, 
                        MT_STR(&mop->mo_ldd));
                return EINVAL;
        }

        /* Loop device? */
        dev = mop->mo_device;
        if (mop->mo_flags & MO_IS_LOOP) {
                ret = loop_format(mop);
                if (!ret)
                        ret = loop_setup(mop);
                if (ret) {
                        fatal();
                        fprintf(stderr, "Loop device setup failed %d\n", ret);
                        return ret;
                }
                dev = mop->mo_loopdev;
        }
        
        vprint("formatting backing filesystem %s on %s\n",
               MT_STR(&mop->mo_ldd), dev);
        vprint("\tservice name  %s\n", mop->mo_ldd.ldd_svname);
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
        if (ret != 0) {
                fatal();
                fprintf(stderr, "Unable to build fs: %s \n", dev);
                run_command_out();
                goto out;
        }

        /* Enable hashed b-tree directory lookup in large dirs 
           FIXME MDT only? */
        if ((mop->mo_ldd.ldd_mount_type == LDD_MT_EXT3) ||
            (mop->mo_ldd.ldd_mount_type == LDD_MT_LDISKFS)) { 
                sprintf(cmd, "tune2fs -O dir_index %s", dev);
                ret = run_command(cmd);
                if (ret) {
                        fatal();
                        fprintf(stderr,"Unable to enable htree: %s\n",
                                mop->mo_device);
                        goto out;
                }
        }

out:
        loop_cleanup(mop);      
        return ret;
}

static int load_module(char *module_name)
{
        char buf[256];
        int rc;
        
        vprint("loading %s\n", module_name);
        sprintf(buf, "/sbin/modprobe %s", module_name);
        rc = system(buf);
        if (rc) {
                fprintf(stderr, "%s: failed to modprobe %s (%d)\n", 
                        progname, module_name, rc);
                fprintf(stderr, "Check /etc/modules.conf\n");
        }
        return rc;
}

static int load_modules(struct mkfs_opts *mop)
{
        int rc = 0;

        //client: rc = load_module("lustre");
        vprint("Loading modules...");

        /* portals, ksocknal, fsfilt, etc. in modules.conf */
        rc = load_module("_lustre");
        if (rc) return rc;

        /* FIXME currently use the MDT to write llogs, should be a MGS */
        rc = load_module("mds");
        vprint("done\n");
        return rc;
}

static int jt_setup()
{
        int ret;
        /* FIXME uneeded? */
        ret = access(PORTALS_DEV_PATH, F_OK);
        if (ret) 
                system("mknod "PORTALS_DEV_PATH" c 10 240");
        ret = access(OBD_DEV_PATH, F_OK);
        if (ret) 
                system("mknod "OBD_DEV_PATH" c 10 241");

        ptl_initialize(0, NULL);
        obd_initialize(0, NULL);
        return 0; 
}

/* see jt_ptl_network */
int jt_getnids(ptl_nid_t *nidarray, int maxnids)
{
        struct portal_ioctl_data data;
        int                      count;
        int                      rc;

        for (count = 0; count < maxnids; count++) {
                PORTAL_IOC_INIT (data);
                data.ioc_count = count;
                rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_GET_NI, &data);

                if (rc >= 0) {
                        vprint("%s\n", libcfs_nid2str(data.ioc_nid));
                        nidarray[count] = data.ioc_nid;
                        continue;
                }

                if (errno == ENOENT)
                        break;

                fprintf(stderr,"IOC_PORTAL_GET_NI error %d: %s\n",
                        errno, strerror(errno));
                return -1;
        }
        
        if (count == 0)
                printf("<no local networks>\n");
        return count;
}

static void jt_print(char *cmd_name, int argc, char **argv)
{
        int i = 0;
        printf("%-20.20s: ", cmd_name);
        while (i < argc) {
                printf("%s ", argv[i]);
                i++;
        }
        printf("\n");
}
        
static int _do_jt(int (*cmd)(int argc, char **argv), char *cmd_name, ...)
{
        va_list ap;
        char *jt_cmds[10];
        char *s;
        int i = 0;
        int ret;
                
        va_start(ap, cmd_name);
        while (i < 10) {
                s = va_arg(ap, char *);
                if (!s) 
                        break;
                jt_cmds[i] = malloc(strlen(s) + 1);
                strcpy(jt_cmds[i], s);
                i++;
        }
        va_end(ap);

        if (verbose) 
                jt_print(cmd_name, i, jt_cmds);

        ret = (*cmd)(i, jt_cmds);
        if (ret) 
                fprintf(stderr, "%s: jt_cmd %s: (%d) %s\n",
                        progname, jt_cmds[0], ret, strerror(abs(ret)));

        while (i) 
                free(jt_cmds[--i]);

        return ret;
}

#define do_jt(cmd, a...)  if ((ret = _do_jt(cmd, #cmd, ## a))) goto out_jt
#define do_jt_noret(cmd, a...)  _do_jt(cmd, #cmd, ## a) 

int write_llog_files(struct mkfs_opts *mop)
{
        char confname[] = "llog_writer";
        char name[128];
        char *dev;
        int  ret = 0;

        load_modules(mop);

        vprint("Creating Lustre logs\n"); 
        if ((ret = jt_setup()))
                return ret;
        
        dev = mop->mo_device;
        if (mop->mo_flags & MO_IS_LOOP) {
                ret = loop_setup(mop);
                if (ret)
                        return ret;
                dev = mop->mo_loopdev;
        }

        /* FIXME can't we just write these log files ourselves? Why do we 
           have to go through an obd at all? jt_ioc_dump()? */
        /* FIXME use mgmt server obd to write logs. Can start it by mounting
           I think. */
        /* Set up a temporary obd for writing logs. 
           mds and confobd can handle OBD_IOC_DORECORD */
        ret = do_jt_noret(jt_lcfg_attach, "attach", "mds"/*confobd*/, confname,
                          mop->mo_ldd.ldd_svname/*uuid*/, 0);
        if (ret)
                return ENODEV;
        ret = do_jt_noret(jt_lcfg_device, "cfg_device", confname, 0);
        if (ret)
                return ENODEV;
        do_jt(jt_lcfg_setup,  "setup", dev,  
              MT_STR(&mop->mo_ldd), /*mop->mo_ldd.ldd_mount_opts,*/ 0);
        /* Record on this device. */
        do_jt(jt_obd_device,  "device", confname, 0);

        snprintf(name, sizeof(name), "%s-conf", mop->mo_ldd.ldd_svname);

        if (IS_OST(&mop->mo_ldd)) {
                do_jt(jt_cfg_clear_log, "clear_log", name, 0);
                do_jt(jt_cfg_record,    "record", name, 0);
                do_jt(jt_lcfg_attach,   "attach", "obdfilter", 
                      mop->mo_ldd.ldd_svname, mop->mo_ldd.ldd_svname/*uuid*/, 0);
                do_jt(jt_lcfg_device,   "cfg_device", mop->mo_ldd.ldd_svname, 0);
                /* FIXME setup needs to change - no disk info */
                do_jt(jt_lcfg_setup,    "setup", mop->mo_device, 
                      MT_STR(&mop->mo_ldd),
                      "f", /* f=recovery enabled, n=disabled */
                      mop->mo_ldd.ldd_mount_opts, 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
                do_jt(jt_cfg_dump_log,  "dump_log", name, 0);

                do_jt(jt_cfg_clear_log, "clear_log", "OSS-conf", 0);
                do_jt(jt_cfg_record,    "record", "OSS-conf", 0);
                do_jt(jt_lcfg_attach,   "attach", "ost", "OSS", "OSS_UUID", 0);
                do_jt(jt_lcfg_device,   "cfg_device", "OSS", 0);
                do_jt(jt_lcfg_setup,    "setup", 0);
                if (mop->mo_timeout)
                        do_jt(jt_lcfg_set_timeout, "set_timeout", 
                              mop->mo_timeout, 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
        }
        
        if (IS_MDT(&mop->mo_ldd)) {
                ptl_nid_t nidarray[128];
                char scnt[20], ssz[20], soff[20], spat[20];
                char cliname[sizeof(mop->mo_ldd.ldd_fsname)];
                char mdcname[sizeof(mop->mo_ldd.ldd_fsname)];
                ptl_nid_t nid;
                int numnids;

                /* Write mds-conf log */
                do_jt(jt_cfg_clear_log, "clear_log", name, 0);
                do_jt(jt_cfg_record,    "record", name, 0);
                do_jt(jt_lcfg_attach,   "attach", "mdt", "MDT", "MDT_UUID", 0);
                do_jt(jt_lcfg_device,   "cfg_device", "MDT", 0);
                do_jt(jt_lcfg_setup,    "setup", 0);
                do_jt(jt_lcfg_attach,   "attach", "mds", mop->mo_ldd.ldd_svname,
                      mop->mo_ldd.ldd_svname/*uuid*/, 0);
                do_jt(jt_lcfg_device,   "cfg_device", mop->mo_ldd.ldd_svname, 0);
                do_jt(jt_lcfg_setup,    "setup", mop->mo_device,
                      MT_STR(&mop->mo_ldd), mop->mo_ldd.ldd_svname, 
                      mop->mo_ldd.ldd_mount_opts, 0);
                if (mop->mo_timeout)
                        do_jt(jt_lcfg_set_timeout, "set_timeout", 
                              mop->mo_timeout, 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);

                /* Write mds startup log */
                do_jt(jt_cfg_clear_log,  "clear_log", mop->mo_ldd.ldd_svname, 0);
                do_jt(jt_cfg_record,     "record", mop->mo_ldd.ldd_svname, 0);
                /*attach lov lov_conf_mdsA f0591_lov_conf_mdsA_224a85b5fc
                  lov_setup lovA_UUID 0 1048576 0 0 ost1_UUID
                  mount_option mdsA lov_conf_mdsA
                */
                snprintf(name, sizeof(name), "lov-%s", mop->mo_ldd.ldd_svname);
                do_jt(jt_lcfg_attach,    "attach", "lov", name, 
                      name/*uuid*/, 0);
                snprintf(scnt, sizeof(scnt), "%d", mop->mo_stripe_count);
                snprintf(ssz, sizeof(ssz), "%d", mop->mo_stripe_sz);
                snprintf(soff, sizeof(soff), "%d", 0 /*FIXME?*/);
                snprintf(spat, sizeof(spat), "%d", mop->mo_stripe_pattern);
                do_jt(jt_lcfg_lov_setup, "lov_setup", name/*uuid*/,
                      scnt, ssz, soff, spat, 0);
                /* Then for every failover ost pair we would add to mdt and client:
#03 L add_uuid nid=c0a80203 nal_type=0 0:(null) 1:NID_uml3_UUID
#04 L attach   0:OSC_uml1_ost1_MNT_client 1:osc 2:e61f5_lov1_84b41a5f41
#05 L setup    0:OSC_uml1_ost1_MNT_client 1:ost1_UUID 2:NID_uml3_UUID
#06 L add_uuid nid=c0a80204 nal_type=0 0:(null) 1:NID_uml4_UUID
#07 L add_conn 0:OSC_uml1_ost1_MNT_client 1:NID_uml4_UUID
#08 L lov_modify_tgts add 0:lov1 1:ost1_UUID 2: 3:
                */
                /* This was an old hack to pass the lov name to the MDS:
                   mds_postsetup calls class_get_profile
                   to lookup the lov name: (profile=mds,osc=lov,mdc=0);
                   This command was originally intended for clients: 
                   class_add_profile(profile,osc,mdc).  
                   FIXME if we always make lovname=f(mdsname), we probably
                   don't need this. */
                do_jt(jt_lcfg_mount_option, "mount_option", 
                      mop->mo_ldd.ldd_svname/*mds*/, name/*lov*/, 0);
                if (mop->mo_timeout)
                        do_jt(jt_lcfg_set_timeout, "set_timeout", 
                              mop->mo_timeout, 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);

                /* Write client startup logs */
                numnids = jt_getnids(nidarray, 
                                     sizeof(nidarray) / sizeof(nidarray[0]));
#if 0
//Let the MGS create the client logs after the MDT has registered 
                if (numnids <= 0) {
                        fprintf(stderr, "%s: Can't figure out local nids, "
                                "skipping client log creation\n", progname);
                        goto out_jt;
                }

                snprintf(mdcname, sizeof(mdcname), "%s-mdc", 
                         mop->mo_ldd.ldd_fsname);
                while (numnids) {
                        numnids--;
                        nid = nidarray[numnids];
                        snprintf(cliname, sizeof(cliname), "client-%s",
                                 libcfs_net2str(PTL_NIDNET(nid)));
                        vprint("log for %s\n", cliname);
                        do_jt(jt_cfg_clear_log,  "clear_log", cliname, 0);
                        do_jt(jt_cfg_record,     "record", cliname, 0);
                        do_jt(jt_lcfg_attach,    "attach", "lov", name, 
                              name/*uuid*/, 0);
                        do_jt(jt_lcfg_lov_setup, "lov_setup", name/*uuid*/,
                              scnt, ssz, soff, spat, 0);
                /* add osts here as in mdt above */
                /* add mdc
#09 L add_uuid nid=c0a80201 nal_type=0 0:(null) 1:NID_uml1_UUID
#10 L attach   0:MDC_uml1_mdsA_MNT_client 1:mdc 2:efdac_MNT_client_fec96dc7f9
#11 L setup    0:MDC_uml1_mdsA_MNT_client 1:mdsA_UUID 2:NID_uml1_UUID
#12 L add_uuid nid=c0a80202 nal_type=0 0:(null) 1:NID_uml2_UUID
#13 L add_conn 0:MDC_uml1_mdsA_MNT_client 1:NID_uml2_UUID
                */
                        /* FIXME we need to put _all_possible_nids_ for 
                           every server in the client startup llog.  client
                           will then choose which nid to use. */
                        do_jt(jt_lcfg_add_uuid, "add_uuid", 
                              mop->mo_ldd.ldd_svname /*FIXME mds name */,
                              libcfs_nid2str(mop->mo_hostnid.primary), 0);
                        do_jt(jt_lcfg_attach,   "attach", "mdc", mdcname, 
                              mdcname/*uuid*/, 0);
                        do_jt(jt_lcfg_device,   "cfg_device", mdcname, 0);
                        /* mdc_setup client_uuid server_uuid */
                        do_jt(jt_lcfg_setup,    "setup", cliname, 
                              mop->mo_ldd.ldd_svname, 0);
                        if (mop->mo_hostnid.backup != PTL_NID_ANY) {
                                do_jt(jt_lcfg_add_uuid, "add_uuid", 
                                      libcfs_nid2str(mop->mo_hostnid.backup),
                                      mop->mo_hostnid.backup, 0);
                                do_jt(jt_lcfg_add_conn, "add_conn", 
                                      libcfs_nid2str(mop->mo_hostnid.backup)/*uuid*/, 0);
                        }
                        do_jt(jt_lcfg_mount_option, "mount_option", 
                              cliname, name/*osc(lov)*/, mdcname, 0);
                        if (mop->mo_timeout)
                                do_jt(jt_lcfg_set_timeout, "set_timeout", 
                                      mop->mo_timeout, 0);
                }
#endif
        }

out_jt:        
        if (ret)
                /* Assume we erred while writing a record */
                do_jt_noret(jt_cfg_endrecord, "endrecord", 0);
        /* Clean up the confobd when we're done writing logs */
        do_jt_noret(jt_lcfg_device, "cfg_device", confname, 0);
        do_jt_noret(jt_obd_cleanup, "cleanup", 0);
        do_jt_noret(jt_obd_detach,  "detach", 0);

        obd_finalize(1, (char **)&name /*dummy*/);
        loop_cleanup(mop);
        return ret;
}

/* Make the mdt/ost server obd name based on the filesystem name */
static void make_sv_name(struct mkfs_opts *mop)
{
        /* FIXME if we're not given an index, we have to change our name
           later -- can't have two servers with the same name. 
           So rewrite ost log, last_rcvd, and disk label, or we need to talk
           to MGMT now to get index # */

        if (IS_MDT(&mop->mo_ldd) || IS_OST(&mop->mo_ldd)) {
                sprintf(mop->mo_ldd.ldd_svname, "%.8s-%s%04x",
                        mop->mo_ldd.ldd_fsname,
                        IS_MDT(&mop->mo_ldd) ? "MDT" : "OST",  
                        mop->mo_index);
        } else {
                sprintf(mop->mo_ldd.ldd_svname, "MGMT");
        }
        vprint("Server name: %s\n", mop->mo_ldd.ldd_svname);
}

void set_defaults(struct mkfs_opts *mop)
{
        char hostname[128];
        mop->mo_ldd.ldd_magic = LDD_MAGIC;
        mop->mo_ldd.ldd_flags = LDD_F_NEED_INDEX;

        if (get_os_version() == 24) 
                mop->mo_ldd.ldd_mount_type = LDD_MT_EXT3;
        else 
                mop->mo_ldd.ldd_mount_type = LDD_MT_LDISKFS;
        
        strcpy(mop->mo_ldd.ldd_fsname, "lustre");
        mop->mo_stripe_count = 1;
        mop->mo_index = -1;

        gethostname(hostname, sizeof(hostname));
        mop->mo_hostnid.primary = libcfs_str2nid(hostname);
}

static inline void badopt(char opt, char *type)
{
        fprintf(stderr, "%s: '%c' only valid for %s\n",
                progname, opt, type);
        usage(stderr);
        exit(1);
}

int main(int argc , char *const argv[])
{
        struct mkfs_opts mop;
        static struct option long_opt[] = {
                {"backfstype", 1, 0, 'b'},
                {"configdev", 1, 0, 'C'},
                {"device_size", 1, 0, 'd'},
                {"fsname",1, 0, 'n'},
                {"failover", 1, 0, 'f'},
                {"help", 0, 0, 'h'},
                {"index", 1, 0, 'I'},
                {"mdt", 0, 0, 'M'},
                {"mgmt", 0, 0, 'G'},
                {"mgmtnode", 1, 0, 'm'},
                {"mkfsoptions", 1, 0, 'k'},
                {"mountfsoptions", 1, 0, 'o'},
                {"ost", 0, 0, 'O'},
                {"reformat", 0, 0, 'r'},
                {"startupwait", 1, 0, 'w'},
                {"stripe_count", 1, 0, 'c'},
                {"stripe_size", 1, 0, 's'},
                {"stripe_index", 1, 0, 'i'},
                {"timeout", 1, 0, 't'},
                {"verbose", 0, 0, 'v'},
                {0, 0, 0, 0}
        };
        char *optstring = "b:C:d:n:f:hI:MGm:k:o:Orw:c:s:i:t:v";
        char opt;
        char *mountopts = NULL;
        int  ret = 0;

        progname = argv[0];
        if (argc < 3) 
                usage(stderr);
           
        memset(&mop, 0, sizeof(mop));
        set_defaults(&mop);

        while ((opt = getopt_long(argc, argv, optstring, long_opt, NULL)) != 
               EOF) {
                switch (opt) {
                case 'b': {
                        int i = 0;
                        while (i < LDD_MT_LAST) {
                                if (strcmp(optarg, mt_str(i)) == 0) {
                                        mop.mo_ldd.ldd_mount_type = i;
                                        break;
                                }
                                i++;
                        }
                        break;
                }
                case 'C':
                        //FIXME
                        exit(2);
                case 'c':
                        if (IS_MDT(&mop.mo_ldd)) {
                                int stripe_count = atol(optarg);
                                mop.mo_stripe_count = stripe_count;
                        } else {
                                badopt(opt, "MDT");
                        }
                        break;
                case 'd':
                        mop.mo_device_sz = atol(optarg); 
                        break;
                case 'k':
                        strncpy(mop.mo_mkfsopts, optarg, 
                                sizeof(mop.mo_mkfsopts) - 1);
                        break;
                case 'f':
                        mop.mo_hostnid.backup = libcfs_str2nid(optarg);
                        break;
                case 'G':
                        mop.mo_ldd.ldd_flags |= LDD_F_SV_TYPE_MGMT;
                        break;
                case 'h':
                        usage(stdout);
                        break;
                case 'i':
                        if (IS_MDT(&mop.mo_ldd) || IS_OST(&mop.mo_ldd)) {
                                mop.mo_index = atol(optarg);
                                mop.mo_ldd.ldd_flags &= ~LDD_F_NEED_INDEX;
                        } else {
                                badopt(opt, "MDT,OST");
                        }
                        break;
                case 'm':
                        if (IS_MGMT(&mop.mo_ldd))
                                badopt(opt, "non-MGMT MDT,OST");
                        set_nid_pair(&mop.mo_ldd.ldd_mgmtnid, optarg);
                        break;
                case 'M':
                        mop.mo_ldd.ldd_flags |= LDD_F_SV_TYPE_MDT;
                        break;
                case 'n':
                        if (!(IS_MDT(&mop.mo_ldd) || IS_OST(&mop.mo_ldd)))
                                badopt(opt, "MDT,OST");
                        if (strlen(optarg) > 8) {
                                fprintf(stderr, "%s: filesystem name must be "
                                        "<= 8 chars\n", progname);
                                exit(1);
                        }
                        if (optarg[0] != 0) 
                                strncpy(mop.mo_ldd.ldd_fsname, optarg, 
                                        sizeof(mop.mo_ldd.ldd_fsname) - 1);
                        break;
                case 'o':
                        mountopts = optarg;
                        break;
                case 'O':
                        mop.mo_ldd.ldd_flags |= LDD_F_SV_TYPE_OST;
                        break;
                case 'r':
                        mop.mo_flags |= MO_FORCEFORMAT;
                        break;
                case 's':
                        if (IS_MDT(&mop.mo_ldd)) 
                                mop.mo_stripe_sz = atol(optarg) * 1024;
                        else 
                                badopt(opt, "MDT");
                        break;
                case 't':
                        mop.mo_timeout = atol(optarg);
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
                        break;
                }
        }//while
        if (optind >= argc) {
                fatal();
                fprintf(stderr, "Bad arguments\n");
                usage(stderr);
        }

        if (!(IS_MDT(&mop.mo_ldd) || IS_OST(&mop.mo_ldd) || 
              IS_MGMT(&mop.mo_ldd))) {
                fatal();
                fprintf(stderr, "must set server type :{mdt,ost,mgmt}\n");
                usage(stderr);
        }

        if (IS_MDT(&mop.mo_ldd) && !IS_MGMT(&mop.mo_ldd) && 
            mop.mo_ldd.ldd_mgmtnid.primary == PTL_NID_ANY) {
                vprint("No MGMT specified, adding to this MDT\n");
                mop.mo_ldd.ldd_flags |= LDD_F_SV_TYPE_MGMT;
                //FIXME mop.mo_ldd.ldd_mgmt.primary == libcfs_str2nid(localhost);
        }

        if (mop.mo_ldd.ldd_mgmtnid.primary == PTL_NID_ANY) {
                fatal();
                fprintf(stderr, "Must specify either --mgmt or --mgmtnode\n");
                usage(stderr);
        }

        if (IS_MDT(&mop.mo_ldd) && (mop.mo_stripe_sz == 0))
                mop.mo_stripe_sz = 1024 * 1024;
        
        strcpy(mop.mo_device, argv[optind]);
        
        /* These are the permanent mount options. */ 
        if (mop.mo_ldd.ldd_mount_type == LDD_MT_EXT3) {
                sprintf(mop.mo_ldd.ldd_mount_opts, "errors=remount-ro");
                if (IS_OST(&mop.mo_ldd))
                        strcat(mop.mo_ldd.ldd_mount_opts, ",asyncdel");
        } else if (mop.mo_ldd.ldd_mount_type == LDD_MT_LDISKFS) {
                sprintf(mop.mo_ldd.ldd_mount_opts, "errors=remount-ro");
                if (IS_MDT(&mop.mo_ldd))
                        strcat(mop.mo_ldd.ldd_mount_opts, ",iopen_nopriv");
        } else if (mop.mo_ldd.ldd_mount_type == LDD_MT_SMFS) {
                sprintf(mop.mo_ldd.ldd_mount_opts, "type=ext3,dev=%s",
                        mop.mo_device);
        } else {
                fatal();
                fprintf(stderr, "%s: unknown fs type %d '%s'\n",
                        progname, mop.mo_ldd.ldd_mount_type,
                        MT_STR(&mop.mo_ldd));
                return EINVAL;
        }
        if (mountopts) {
                strcat(mop.mo_ldd.ldd_mount_opts, ",");
                strcat(mop.mo_ldd.ldd_mount_opts, mountopts);
        }

        if ((mop.mo_ldd.ldd_mount_type == LDD_MT_SMFS) ||
            !is_block(mop.mo_device)) {
                mop.mo_flags |= MO_IS_LOOP;
                if (mop.mo_device_sz == 0) {
                        fatal();
                        fprintf(stderr, "loop device requires a --device_size= "
                                "param\n");
                        return EINVAL;
                }
        }
                
        make_sv_name(&mop);

        ret = make_lustre_backfs(&mop);
        if (ret != 0) {
                fatal();
                fprintf(stderr, "mkfs failed %d\n", ret);
                return ret;
        }
        
        ret = write_local_files(&mop);
        if (ret != 0) {
                fatal();
                fprintf(stderr, "failed to write local files\n");
                return ret;
        }

        ret = write_llog_files(&mop);
        if (ret != 0) {
                fatal();
                fprintf(stderr, "failed to write setup logs\n");
                return ret;
        }
        
        return ret;
}
