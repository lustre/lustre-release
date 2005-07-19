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

#include "obdctl.h"
#include <portals/ptlctl.h>

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
static char cmd[50];
static char cmd_out[32][128];
static char *ret_file = "/tmp/mkfs.log";
        
/* for init loop */
static char loop_base[20];

void usage(FILE *out)
{
        fprintf(out, "usage: %s <type> [options] <device>\n", progname);

        fprintf(out, 
                "\t<type>:type of Lustre service [mds|ost|mgmt]\n"
                "\t<device>:block device or file (e.g /dev/hda or /tmp/ost1)\n"
                "\t-h|--help: print this usage message\n"
                "\toptions:\n"
                "\t\t--mgmtnode=<mgtnode>[,<failover-mgtnode>]:nid of mgmt node [and the failover mgmt node]\n"
                "\t\t--failover=<failover-address>\n"
                "\t\t--device_size=#N(KB):device size \n"
                "\t\t--stripe_count=#N:number of stripe\n"
                "\t\t--stripe_size=#N(KB):stripe size\n"
                "\t\t--index=#N:target index\n"
                "\t\t--smfsopts <smfs options>\n"
                "\t\t--ext3opts <ext3 options>\n");
        exit(out != stdout);
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

#define vprint if (verbose) printf

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
int run_command(char *cmd, char out[32][128])
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
      
       memset(out, 0, sizeof(out));
       while (fgets(out[i], 128, rfile) != NULL) {
                i++;
                if (i >= 32) {
                        fprintf(stderr,"WARNING losing some outputs when run %s",
                               cmd);
                        break;
                }
       }
       fclose(rfile);

       return ret;
}

/* Figure out the loop device names */
void init_loop_base()
{
        if (!access("/dev/loop0",F_OK|R_OK))
                strcpy(loop_base,"/dev/loop\0");
        else if (!access("/dev/loop/0",F_OK|R_OK))
                strcpy(loop_base,"/dev/loop/\0");
        else {
                fprintf(stderr,"can't access loop devices\n");
                exit(1);
        }
        return;
}

/* Setup a file in the first unused loop_device */
int setup_loop(char* file, char* loop_device)
{
        int i,ret = 0;
        char l_device[20];

        for (i = 0; i < MAX_LOOP_DEVICES; i++) {
                sprintf(l_device, "%s%d", loop_base, i);
                if (access(l_device, F_OK | R_OK)) 
                        break;

                sprintf(cmd, "losetup %s", l_device);
                ret = run_command(cmd, cmd_out);
                /* losetup gets 1 (256?) for good non-set-up device */
                if (ret) {
                        sprintf(cmd, "losetup %s %s", l_device, file);
                        ret = run_command(cmd, cmd_out);
                        if (ret) {
                                fprintf(stderr, "error %d on losetup: %s\n",
                                        ret, strerror(ret));
                                exit(8);
                        }
                        strcpy(loop_device, l_device);
                        return ret;
                }
        }
        
        fprintf(stderr,"out of loop devices!\n");
        return 1;
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
                fprintf(stderr,"can not stat %s\n",devname);
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

        sprintf(cmd,"cat /proc/partitions ");
        ret = run_command(cmd,cmd_out);
        for (i=0; i<32; i++) {
                if (strlen(cmd_out[i]) == 0) 
                        break;
                ma = strtok(cmd_out[i]," ");
                mi = strtok(NULL," ");
                if ( (major == atol(ma)) && (minor == atol(mi)) ) {
                        sz = strtok(NULL," ");
                        return atol(sz);
                }
        }

        return 0; //FIXME : no entries in /proc/partitions
}

/* Write the server config files */
int write_local_files(struct mkfs_opts *mop)
{
        struct lr_server_data lsd;
        char mntpt[] = "/tmp/mntXXXXXX";
        char filepnm[sizeof(mntpt) + 15];
        FILE *filep;
        int ret = 0;

        /* Mount this device temporarily as ext3 in order to write this file */
        if (!mkdtemp(mntpt)) {
                fprintf(stderr, "Can't create temp mount point %s: %s\n",
                        mntpt, strerror(errno));
                return errno;
        }

        if (mop->mo_flags & MO_IS_LOOP)
                sprintf(cmd, "mount -o loop %s %s", mop->mo_device, mntpt);
        else
                sprintf(cmd, "mount -t ext3 %s %s", mop->mo_device, mntpt);
        ret = run_command(cmd, cmd_out);
        if (ret) {
                fprintf(stderr, "Unable to mount %s\n", mop->mo_device);
                goto out_rmdir;
        }

        /* Save the persistent mount data into a file. Lustre must pre-read
           this file to get the real mount options. */
        sprintf(filepnm, "%s/%s", mntpt, MOUNT_DATA_FILE);
        filep = fopen(filepnm, "w");
        if (!filep) {
                fprintf(stderr,"Unable to create %s file\n", filepnm);
                goto out_umnt;
        }
        fwrite(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
        fclose(filep);
        
        /* FIXME this info should be part of the startup llogs */
        if (IS_MDT(mop->mo_ldd)) {
                uint32_t stripe_size = mop->mo_stripe_sz;
                uint32_t stripe_count = mop->mo_stripe_count;
                uint32_t stripe_pattern = mop->mo_stripe_pattern;
                sprintf(filepnm, "%s/%s", mntpt, STRIPE_FILE);
                filep = fopen(filepnm, "w");
                if (!filep) {
                        fprintf(stderr,"Unable to create %s file\n", filepnm);
                        goto out_umnt;
                }

                ret = fwrite(&stripe_size, sizeof(stripe_size), 1, filep);
                if (ret <= 0) {
                        fprintf(stderr, "Can't write options file (%d)\n",
                                ferror(filep));
                        goto out_close;
                }
                ret = fwrite(&stripe_count, sizeof(stripe_count), 1, filep);
                ret = fwrite(&stripe_pattern, sizeof(stripe_pattern), 1, filep);

                fclose(filep);
        }

        /* Create the inital last_rcvd file */
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
        fwrite(&lsd, sizeof(lsd), 1, filep);
        ret = 0;

out_close:
        fclose(filep);
out_umnt:
        sprintf(cmd, "umount %s", mntpt);
        run_command(cmd, cmd_out);
out_rmdir:
        rmdir(mntpt);
        return ret;
}

/* Build fs according to type */
int make_lustre_backfs(struct mkfs_opts *mop)
{
        int i,ret=0;
        int block_count = 0;
        char mkfs_cmd[256];
        char buf[40];

        if (mop->mo_device_sz != 0) {
                if (mop->mo_device_sz < 8096){
                        fprintf(stderr, "size of filesystem must be larger "
                                "than 8MB, but is set to %dKB\n",
                                mop->mo_device_sz);
                        return EINVAL;
                }
                block_count = mop->mo_device_sz / 4; /* block size is 4096 */
        }       
        
        if ((mop->ldd.ldd_fs_type == LDD_FS_TYPE_EXT3) ||
            (mop->ldd.ldd_fs_type == LDD_FS_TYPE_LDISKFS)) { 
                long device_sz = mop->mo_device_sz;
                long inode_sz = 0;
                if (device_sz == 0){
                        sprintf(cmd, "sfdisk -s %s", mop->mo_device);
                        ret = run_command(cmd, cmd_out);
                        if (ret == 0)
                                device_sz = atol(cmd_out[0]);
                        else 
                                device_sz = device_size_proc(mop->mo_device);
                }           

                if (strstr(mop->mo_mkfsopts, "-J" == NULL) {
                        long journal_sz = 0;
                        if (device_sz > 1024 * 1024) 
                                journal_sz = (device_sz / 102400) * 4;
                        if (journal_sz > 400)
                                journal_sz = 400;
                        if (journal_sz) {
                                sprintf(buf, " -J size=%d", journal_sz);
                                strcat(mop->mo_mkfsopts, buf);
                        }
                }

                /* The larger the bytes-per-inode ratio, the fewer inodes
                   will  be  created. */
                if (mop->mo_stripe_count > 77)
                        inode_sz = 4096;
                else if (mop->mo_stripe_count > 35)
                        inode_sz = 2048;
                else if (IS_MDT(mop->mo_ldd)) 
                        inode_sz = 1024;
                else if ((IS_OST(mop->mo_ldd) && (device_sz > 1000000) 
                        inode_sz = 16384;
                if (inode_sz > 0) {
                        sprintf(buf, " -i %d", mop->inode_size);
                        strcat(mop->mkfsopts, buf);
                }

                sprintf(mkfs_cmd, "mkfs.ext2 -j -b 4096 -L %s ",
                        mop->mo_ldd.ldd_svname);

        } else if (mop->ldd.ldd_fs_type == LDD_FS_TYPE_REISERFS) {
                long journal_sz = 0;
                if (journal_sz > 0) { /* FIXME */
                        sprintf(buf, " --journal_size %d", journal_sz);
                        strcat(mop->mkfsopts, buf);
                }
                sprintf(mkfs_cmd, "mkreiserfs -ff ");

        } else {
                fprintf(stderr,"unsupported fs type: %s\n",
                        mop->fs_type_string);
                return EINVAL;
        }

        vprint("formatting backing filesystem %s on %s\n",
               mop->mo_mount_type_string, mop->mo_device);
        vprint("\tdevice name  %s\n", mop->mo_ldd.ldd_svname);
        vprint("\t4k blocks    %d\n", block_count);
        vprint("\toptions      %s\n", mop->mo_mkfsopts);

        /* mkfs_cmd's trailing space is important! */
        strcat(mkfs_cmd, mop->mo_mkfsopts);
        strcat(mkfs_cmd, " ");
        strcat(mkfs_cmd, mop->mo_device);
        if (block_count != 0) {
                sprintf(buf, " %d", block_count);
                strcat(mkfs_cmd, buf);
        }

        vprint("mkfs_cmd = %s\n", mkfs_cmd);
        ret = run_command(mkfs_cmd, cmd_out);
        if (ret != 0) {
                fprintf(stderr, "Unable to build fs: %s \n", mop->mo_device);
                for (i = 0; i < 32; i++) {
                        if (strlen(cmd_out[i]) == 0)
                                break;
                        fprintf(stderr, cmd_out[i]);
                }
                return EIO;
        }

        /* Enable hashed b-tree directory lookup in large dirs 
           FIXME MDT only? */
        if ((mop->ldd.ldd_fs_type == LDD_FS_TYPE_EXT3) ||
            (mop->ldd.ldd_fs_type == LDD_FS_TYPE_LDISKFS)) { 
                sprintf(cmd, "tune2fs -O dir_index %s", mop->mo_device);
                ret = run_command(cmd, cmd_out);
                if (ret) {
                        fprintf(stderr,"Unable to enable htree: %s\n",
                                mop->device);
                        exit(4);
                }
        }
       
        return ret;
}

int setup_loop_device(struct mkfs_opts *mop)
{
        char loop_device[20] = "";
        int ret = 0;
       
        init_loop_base();

        sprintf(cmd, "dd if=/dev/zero bs=1k count=0 seek=%d of=%s", 
                mop->mo_device_sz, mop->mo_device);
        ret = run_command(cmd, cmd_out);
        if (ret != 0){
                fprintf(stderr, "Unable to create backing store: %d\n", ret);
                return ret;
        }

        ret = setup_loop(mop->mo_device, loop_device);
        
        if (ret == 0)
                /* Our device is now the loop device, not the file name */
                strcpy(mop->mo_device, loop_device);
        else
                fprintf(stderr, "Loop device setup failed %d\n", ret);
                
        return ret;
}

static int jt_setup()
{
        int ret;
        ret = access("/dev/portals", F_OK);
        if (ret) 
                system("mknod /dev/portals c 10 240");
        ret = access("/dev/obd", F_OK);
        if (ret) 
                system("mknod /dev/obd c 10 241");

        ptl_initialize(0, NULL);
        ret = obd_initialize(0, NULL);
        if (ret) {
                fprintf(stderr,"Can't obd initialize\n");
                return 2;
        }
        return 0; 
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

#define do_jt(cmd, a...)  if ((ret = _do_jt(cmd, #cmd, ## a))) goto out 
#define do_jt_noret(cmd, a...)  _do_jt(cmd, #cmd, ## a) 

int lustre_log_setup(struct mkfs_opts *mop)
{
        char confname[] = "confobd";
        char name[128];
        int  ret = 0;

        vprint("Creating Lustre logs\n"); 

        if (jt_setup())
                return 2;

        /* Set up our confobd for writing logs */
        ret = do_jt_noret(jt_lcfg_attach, "attach", "confobd", confname,
                          "conf_uuid", 0);
        if (ret)
                return ENODEV;
        ret = do_jt_noret(jt_lcfg_device, "cfg_device", confname, 0);
        if (ret)
                return ENODEV;
        do_jt(jt_lcfg_setup,  "setup", mop->device,  mop->fs_type_string,
              mop->mountfsopts, 0);
        do_jt(jt_obd_device,  "device", "confobd", 0);

        sprintf(name, "%s-conf", mop->mo_ldd.ldd_svname);

        if (IS_OST(mop->mo_ldd)) {
                do_jt(jt_cfg_clear_log, "clear_log", name, 0);
                do_jt(jt_cfg_record,    "record", name, 0);
                do_jt(jt_lcfg_attach, "attach", "obdfilter", mop->mo_ldd.ldd_svname,
                      mop->obduuid, 0);
                do_jt(jt_lcfg_device, "cfg_device", mop->mo_ldd.ldd_svname, 0);
                do_jt(jt_lcfg_setup,  "setup", mop->device, 
                      mop->fs_type_string,
                      "n", /*mop->u.ost.host.failover_addr*/
                      mop->mountfsopts, 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
                do_jt(jt_cfg_dump_log,  "dump_log", name, 0);

                do_jt(jt_cfg_clear_log, "clear_log", "OSS-conf", 0);
                do_jt(jt_cfg_record,    "record", "OSS-conf", 0);
                do_jt(jt_lcfg_attach,   "attach", "ost", "OSS", "OSS_UUID", 0);
                do_jt(jt_lcfg_device,   "cfg_device", "OSS", 0);
                do_jt(jt_lcfg_setup,    "setup", 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
        }

        if (IS_MDT(mop->mo_ldd)) {
                /* write mds-conf log */
                do_jt(jt_cfg_clear_log, "clear_log", name, 0);
                do_jt(jt_cfg_record,    "record", name, 0);
                do_jt(jt_lcfg_attach,   "attach", "mdt", "MDT", "MDT_UUID", 0);
                do_jt(jt_lcfg_device,   "cfg_device", "MDT", 0);
                do_jt(jt_lcfg_setup,    "setup", 0);
                do_jt(jt_lcfg_attach,   "attach", "mds", mop->mo_ldd.ldd_svname,
                      mop->obduuid, 0);
                do_jt(jt_lcfg_device,   "cfg_device", mop->mo_ldd.ldd_svname, 0);
                do_jt(jt_lcfg_setup,    "setup", mop->device,
                      mop->fs_type_string,
                      mop->mo_ldd.ldd_svname, mop->mountfsopts, 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
                
                /* TEMPORARY - needs to be moved into mds_setup for 1st mount */
#if 0
                /* write mds startup log */
                do_jt(jt_cfg_clear_log,  "clear_log", mop->mo_ldd.ldd_svname, 0);
                do_jt(jt_cfg_record,     "record", mop->mo_ldd.ldd_svname, 0);
                /*add_uuid NID_uml2_UUID uml2 tcp
                  network tcp
                  add_peer uml2 uml2 988*/
                /*attach lov lov_conf_mdsA f0591_lov_conf_mdsA_224a85b5fc
                  lov_setup lovA_UUID 0 1048576 0 0 ost1_UUID
                  mount_option mdsA lov_conf_mdsA
                */
                do_jt(jt_lcfg_attach,    "attach", "lov", "lov_c", "lov_c_uuid", 0);
                do_jt(jt_lcfg_lov_setup, "lov_setup", "lovA_uuid",
                      "0" /*mop->u.mds.stripe_count*/,
                      "1048576" /*mop->u.mds.stripe_size*/,
                      "0" /* stripe_off FIXME */,
                      "0" /* stripe_pattern */, 0);
                do_jt(jt_lcfg_mount_option,"mount_option", mop->mo_ldd.ldd_svname, "lov_c", 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
#endif        
        }

out:        
        if (ret)
                /* Assume we erred while writing a record */
                do_jt_noret(jt_cfg_endrecord, "endrecord", 0);
        /* Clean up the confobd when we're done writing logs */
        do_jt_noret(jt_lcfg_device, "cfg_device", confname, 0);
        do_jt_noret(jt_obd_cleanup, "cleanup", 0);
        do_jt_noret(jt_obd_detach,  "detach", 0);

        do_jt_noret(obd_finalize,   "finalize", 0);
        
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

/* Make the mdt/ost server obd name based on the filesystem name */
static void make_sv_name(struct mkfs_opts *mop)
{
        /* FIXME if we're not given an index, we have to change our name
           later -- can't have two servers with the same name. 
           So rewrite ost log and last_rcvd, or we need to talk
           to MGMT now to get index # */

        if (IS_MGMT(mop->mo_ldd)) {
                sprintf(mop->mo_ldd.ldd_svname, "MGMT");
        } else {
                sprintf(mop->mo_ldd.ldd_svname, "%.8s-%s%04x",
                        mop->mo_ldd.ldd_fsname,
                        IS_MDT(mop->mo_ldd) ? "MDT" : "OST",  
                        mop->mo_index);
}

void set_defaults(struct mkfs_opts *mop)
{
        mop->mo_ldd.ldd_magic = LDD_MAGIC;

        if (get_os_version() == 24) { 
                mop->ldd.ldd_fs_type = LDD_FS_TYPE_EXT3;
                strcpy(mop->fs_type_string, "ext3");
        } else {
                mop->ldd.ldd_fs_type = LDD_FS_TYPE_LDISKFS;
                strcpy(mop->fs_type_string, "ldiskfs");
        }
        
        strcpy(mop->mo_ldd.ldd_fsname, "lustre");
        mop->mo_index = -1;
}

static inline badopt(char opt, char *type)
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
                {"help", 0, 0, 'h'},
                {"fsname",1, 0, 'n'},
                {"mgmtnode", 1, 0, 'm'},
                {"failover", 1, 0, 'f'},
                {"device_size", 1, 0, 'd'},
                {"stripe_count", 1, 0, 'c'},
                {"stripe_size", 1, 0, 's'},
                {"stripe_index", 1, 0, 'i'},
                {"smfsopts", 1, 0, 'S'},
                {"ext3opts", 1, 0, 'e'},
                {0, 0, 0, 0}
        };
        char *optstring = "hn:m:f:d:c:s:i:S:e:";
        char opt;
        int  ret = 0;

        progname = argv[0];
        if (argc < 3) 
                usage(stderr);
           
        memset(&mop, 0, sizeof(mop));
        set_defaults(&mop);

        if (strcasecmp(argv[1], "mdt") == 0) {
                mop.mo_ldd.ldd_flags |= LDD_SV_TYPE_MDT;
        } else if (strcasecmp(argv[1], "ost") == 0) {
                mop.mo_ldd.ldd_flags |= LDD_SV_TYPE_OST;
        } else if (strcasecmp(argv[1], "mgmt") == 0) {
                mop.mo_ldd.ldd_flags |= LDD_SV_TYPE_MGT;
        } else {
                fprintf(stderr, "%s: must set server type :{mdt,ost,mgmt}\n",
                                progname);
                usage(stderr);
        }

        optind++;

        while ((opt = getopt_long(argc,argv,optstring,long_opt,NULL)) != EOF) {
                switch (opt) {
                case 'h':
                        usage(stdout);
                        break;
                case 'n':
                        if (IS_MGMT(&mop.mo_ldd))
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
                case 'm':
                        if (IS_MGMT(&mop.mo_ldd))
                                badopt(opt, "MDT,OST");
                        mop.mo_ldd->ldd_mgmt.primary = libcfs_str2nid(optarg);
                        break;
                case 'f':
                        mop.mo_failover_nid = libcfs_str2nid(optarg);
                        break;
                case 'd':
                        mop.mo_device_sz = atol(optarg); 
                        break;
                case 'c':
                        if (IS_MDT(&mop.mo_ldd)) {
                                int stripe_count = atol(optarg);
                                mop.mo_stripe_count = stripe_count;
                        } else {
                                badopt(opt, "MDT");
                        }
                        break;
                case 's':
                        if (IS_MDT(&mop.mo_ldd)) 
                                mop.mo_stripe_sz = atol(optarg) * 1024;
                        else 
                                badopt(opt, "MDT");
                        break;
                case 'i':
                        if (IS_MGMT(&mop.mo_ldd))
                                badopt(opt, "MDT,OST");
                        else
                                mop.mo_index = atol(optarg);
                        break;
                case 'S':
                        mop.mo_ldd.ldd_fs_type = LDD_FS_TYPE_SMFS;
                        strcpy(mop.fs_type_string, "smfs");
                        strncpy(mop.mkfsopts, optarg, sizeof(mop.mkfsopts) - 1);
                        break;
                case 'e':
                        if ((mop.mo_ldd.ldd_fs_type == LDD_FS_TYPE_LDISKFS) ||
                            (mop.mo_ldd.ldd_fs_type == LDD_FS_TYPE_EXT3))
                                strncpy(mop.mkfsopts, optarg, 
                                        sizeof(mop.mkfsopts) - 1);
                        else
                                badopt(opt, "ext3,ldiskfs");
                        break;
                default:
                        fprintf(stderr, "%s: unknown option '%c'\n",
                                progname, opt);
                        usage(stderr);
                        break;
                }
        }//while

        strcpy(mop.mo_device, argv[optind]);

        if (IS_MDT(&mop.mo_ldd) && (mop.mo_stripe_sz == 0))
                mop.mo_stripe_sz = 1024 * 1024;
        
        /* These are the permanent mount options. */ 
        if ((mop.mo_ldd.ldd_fs_type == LDD_FS_TYPE_EXT3) ||
            (mop.mo_ldd.ldd_fs_type == LDD_FS_TYPE_LDISKFS)) {
                sprintf(mop.mo_ldd.ldd_mountfsopts, "errors=remount-ro");
                if (IS_MDT(&mop.mo_ldd))
                        strcat(mop.mo_ldd.ldd_mountfsopts, ",iopen_nopriv");
                if ((IS_OST(&mop.mo_ldd)) && (get_os_version() == 24))
                        strcat(mmop.mo_ldd.ldd_mountfsopts, ",asyncdel");
        } else if (mop.mo_ldd.ldd_fs_type == LDD_FS_TYPE_SMFS) {
                sprintf(mop.mo_ldd.ldd_mountfsopts, "type=ext3,dev=%s",
                        mop.mo_device);
        } else {
                fprintf(stderr, "%s: unknown fs type %d '%s'\n",
                        progname, mop.mo_ldd.ldd_fs_type,
                        mop.mo_mount_type_string);
                return EINVAL;
        }
    
        make_obdname(&mop);

        if ((mop->mo_ldd.ldd_fs_type == LDD_FS_TYPE_SMFS) ||
            !is_block(mop.device)) {
                mop.flags |= MO_IS_LOOP;
                ret = setup_loop_device(&mop);
                if (ret) 
                        return ret;
        }
                
        ret = make_lustre_backfs(&mop);
        if (ret != 0) {
              fprintf(stderr, "mkfs failed\n");
              goto out;
        }
        
        ret = write_local_files(&mop);
        if (ret != 0) {
              fprintf(stderr, "failed to write local files\n");
              goto out;
        }

        ret = lustre_log_setup(&mop);
        if (ret != 0) {
              fprintf(stderr, "failed to write setup logs\n");
              goto out;
        }

out:
        if (mop.mo_flags & MO_IS_LOOP) {
                sprintf(cmd, "losetup -d %s", mop.mo_device);
                ret = run_command(cmd, cmd_out);
        }

        return ret;
}
