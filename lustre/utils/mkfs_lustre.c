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

static char *progname = "lmkfs";
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
                "\t<type>:type of Lustre service (mds, ost or mgt)\n"
                "\t<device>:block device or file (e.g /dev/hda or /tmp/ost1)\n"
                "\t-h|--help: print this usage message\n"
                "\tmkfs.lustre options:\n"
                "\t\t--mgmtnode=<mgtnode>[,<failover-mgtnode>]:nid of mgmt node [and the failover mgmt node]\n"
                "\t\t--failover=<failover-address>\n"
                "\t\t--device_size=#N(KB):device size \n"
                "\t\t--stripe_count=#N:number of stripe\n"
                "\t\t--stripe_size=#N(KB):stripe size\n"
                "\t\t--stripe_index=#N:stripe index for ost\n"
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

/* Find loop device assigned to the file */
int find_assigned_loop(char* file, char* loop_device)
{
        int  i,ret;
        char l_device[20];
        char *loop_file;

        for (i = 0; i < MAX_LOOP_DEVICES; i++) {
                sprintf(l_device, "%s%d", loop_base, i);
                if (access(l_device, F_OK | R_OK)) 
                        break;

                sprintf(cmd, "losetup %s", l_device);
                ret = run_command(cmd, cmd_out);
                /* losetup gets 0 for set-up device */
                if (!ret) {
                        loop_file = strrchr(cmd_out[0], '(') + 1;
                        if (!strncmp(loop_file, file, strlen(file))){
                                strcpy(loop_device, l_device);
                                return 1;
                        }
                }
        }
        return 0;
}

/* Setup file in first unused loop_device */
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
        
        fprintf(stderr,"out of loop device\n");
        return 1;
}


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

/* get the devsize from /proc/partitions with the major and minor number */
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

int write_local_files(struct lustre_disk_data *data)
{
        struct lr_server_data lsd;
        char mntpt[] = "/tmp/mntXXXXXX";
        char filepnm[sizeof(mntpt) + 15];
        FILE *filep;
        int ret = 0;

        /* mount this device temporarily as ext3 in order to write this file */
        if (!mkdtemp(mntpt)) {
                fprintf(stderr, "Can't create temp mount point %s: %s\n",
                        mntpt, strerror(errno));
                return errno;
        }

        if (data->flags & MO_IS_LOOP)
                sprintf(cmd, "mount -o loop %s %s", data->device, mntpt);
        else
                sprintf(cmd, "mount -t ext3 %s %s", data->device, mntpt);
        ret = run_command(cmd, cmd_out);
        if (ret) {
                fprintf(stderr, "Unable to mount %s\n",
                        data->device);
                goto out_rmdir;
        }

        /* Save the disk mount options into a file.  llmount must pre-read
           this file to get the real mount options. I suppose you could try
           to parse this out of the *-conf logs instead, but bleah. */
        sprintf(filepnm, "%s/%s", mntpt, MOUNTOPTS_FILE_NAME);
        filep = fopen(filepnm, "w");
        if (!filep) {
                fprintf(stderr,"Unable to create %s file\n", filepnm);
                goto out_umnt;
        }

        ret = fprintf(filep, "%x\n", data->magic);
        if (ret <= 0) {
                fprintf(stderr, "Can't write options file (%d)\n",
                        ferror(filep));
                goto out_close;
        }
        fprintf(filep, "%s\n", data->fs_type_string);
        fprintf(filep, "%s\n", data->mountfsopts);
        fprintf(filep, "%x\n", data->disk_type);
        fwrite(&data->mgt.host, sizeof(data->mgt.host), 1, filep);
        fclose(filep);
        
        if IS_MDS(data) {
                uint32_t stripe_size = data->u.mds.stripe_size;
                uint32_t stripe_count = data->u.mds.stripe_count;
                uint32_t stripe_pattern = data->u.mds.stripe_pattern;
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
        strncpy(lsd.lsd_uuid, data->obduuid, sizeof(lsd.lsd_uuid));
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

/* build fs according to type 
   FIXME:dangerous */
int make_lustre_backfs(struct lustre_disk_data *data)
{
        int i,ret=0;
        int block_count = 0;
        char mkfs_cmd[256];
        char buf[40];

        if (data->device_size != 0) {
                if (data->device_size < 8096){
                        fprintf(stderr, "size of filesystem must be larger "
                                "than 8MB, but is set to %dKB\n",
                                data->device_size);
                        return EINVAL;
                }
                block_count = data->device_size / 4; /* block size is 4096 */
        }       
        
        //FIXME: no ext2 here 
        if ((data->fs_type == FS_EXT3) || (data->fs_type == FS_LDISKFS)) { 
                if (data->device_size == 0){
                        sprintf(cmd, "sfdisk -s %s", data->device);
                        ret = run_command(cmd, cmd_out);
                        if (ret == 0)
                                data->device_size = atol(cmd_out[0]);
                        else 
                                data->device_size =
                                device_size_proc(data->device);
                }                                
                if (data->journal_size == 0) {    //FIXME: kick the jdev in prototype 
                        if (data->device_size > 1024 * 1024) 
                                data->journal_size = (data->device_size / 
                                                      102400) * 4;
                        if (data->journal_size > 400)
                                data->journal_size = 400;
                } 
                if (data->journal_size > 0) {
                        sprintf(buf, " -J size=%d", data->journal_size);
                        strcat(data->mkfsopts, buf);
                }
                if (data->inode_size > 0) {
                        sprintf(buf, " -i %d ", data->inode_size);
                        strcat(data->mkfsopts, buf);
                }

                sprintf(mkfs_cmd, "mkfs.ext2 -j -b 4096 -L %s ", data->obdname);
                //FIXME: losing the jdev in this phases 
        } else if (data->fs_type == FS_REISERFS) {
                if (data->journal_size > 0) {
                        sprintf(buf, " --journal_size %d", data->journal_size);
                        strcat(data->mkfsopts, buf);
                }
                sprintf(mkfs_cmd, "mkreiserfs -ff ");
        } else {
                fprintf(stderr,"unsupported fs type: %s\n",
                        data->fs_type_string);
                return EINVAL;
        }

        vprint("formatting backing filesystem %s on %s\n",
               data->fs_type_string, data->device);
        vprint("\tdevice label %s\n", data->fsname);
        vprint("\tdevice size  %dMB\n", data->device_size / 1024);
        vprint("\tjournal size %d\n", data->journal_size);
        vprint("\tinode size   %d\n", data->inode_size);
        vprint("\t4k blocks    %d\n", block_count);
        vprint("\toptions      %s\n", data->mkfsopts);

        /* mkfs_cmd's trailing space is important! */
        strcat(mkfs_cmd, data->mkfsopts);
        strcat(mkfs_cmd, data->device);
        if (block_count != 0) {
                sprintf(buf, " %d", block_count);
                strcat(mkfs_cmd, buf);
        }

        vprint("mkfs_cmd = %s\n", mkfs_cmd);
        ret = run_command(mkfs_cmd, cmd_out);
        if (ret != 0) {
                fprintf(stderr, "Unable to build fs: %s \n", data->device);
                for (i = 0; i < 32; i++) {
                        if (strlen(cmd_out[i]) == 0)
                                break;
                        fprintf(stderr, cmd_out[i]);
                }
                return EIO;
        }

        if ((data->fs_type == FS_EXT3) || (data->fs_type == FS_LDISKFS)) { 
                sprintf(cmd, "tune2fs -O dir_index %s", data->device);
                ret = run_command(cmd, cmd_out);
                if (ret) {
                        fprintf(stderr,"Unable to enable htree: %s\n",
                                data->device);
                        exit(4);
                }
        }
       
        return ret;
}

int setup_loop_device(struct lustre_disk_data *data)
{
        char loop_device[20] = "";
        int ret = 0;
       
        init_loop_base();

#if 0  /* Do we need this? */
        if (find_assigned_loop(data->device, loop_device)) {
                fprintf(stderr,"WARNING file %s already mapped to %s\n",
                        data->device, loop_device);
                return 1;
        }
#endif
        
        sprintf(cmd, "dd if=/dev/zero bs=1k count=0 seek=%d of=%s", 
                data->device_size, data->device);
        ret = run_command(cmd, cmd_out);
        if (ret != 0){
                fprintf(stderr, "Unable to create backing store: %d\n", ret);
                return ret;
        }

        ret = setup_loop(data->device, loop_device);
        
        if (ret == 0)
                /* Our device is now the loop device, not the file name */
                strcpy(data->device, loop_device);
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

int lustre_log_setup(struct lustre_disk_data *data)
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
        do_jt(jt_lcfg_setup,  "setup", data->device,  data->fs_type_string,
              data->mountfsopts, 0);
        do_jt(jt_obd_device,  "device", "confobd", 0);

        sprintf(name, "%s-conf", data->obdname);

        if (IS_OST(data)) {
                do_jt(jt_cfg_clear_log, "clear_log", name, 0);
                do_jt(jt_cfg_record,    "record", name, 0);
                do_jt(jt_lcfg_attach, "attach", "obdfilter", data->obdname,
                      data->obduuid, 0);
                do_jt(jt_lcfg_device, "cfg_device", data->obdname, 0);
                do_jt(jt_lcfg_setup,  "setup", data->device, 
                      data->fs_type_string,
                      "n", /*data->u.ost.host.failover_addr*/
                      data->mountfsopts, 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
                do_jt(jt_cfg_dump_log,  "dump_log", name, 0);

                do_jt(jt_cfg_clear_log, "clear_log", "OSS-conf", 0);
                do_jt(jt_cfg_record,    "record", "OSS-conf", 0);
                do_jt(jt_lcfg_attach,   "attach", "ost", "OSS", "OSS_UUID", 0);
                do_jt(jt_lcfg_device,   "cfg_device", "OSS", 0);
                do_jt(jt_lcfg_setup,    "setup", 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
        }

        if (IS_MDS(data)) {
                /* write mds-conf log */
                do_jt(jt_cfg_clear_log, "clear_log", name, 0);
                do_jt(jt_cfg_record,    "record", name, 0);
                do_jt(jt_lcfg_attach,   "attach", "mdt", "MDT", "MDT_UUID", 0);
                do_jt(jt_lcfg_device,   "cfg_device", "MDT", 0);
                do_jt(jt_lcfg_setup,    "setup", 0);
                do_jt(jt_lcfg_attach,   "attach", "mds", data->obdname,
                      data->obduuid, 0);
                do_jt(jt_lcfg_device,   "cfg_device", data->obdname, 0);
                do_jt(jt_lcfg_setup,    "setup", data->device,
                      data->fs_type_string,
                      data->obdname, data->mountfsopts, 0);
                do_jt(jt_cfg_endrecord, "endrecord", 0);
                
                /* TEMPORARY - needs to be moved into mds_setup for 1st mount */
#if 0
                /* write mds startup log */
                do_jt(jt_cfg_clear_log,  "clear_log", data->obdname, 0);
                do_jt(jt_cfg_record,     "record", data->obdname, 0);
                /*add_uuid NID_uml2_UUID uml2 tcp
                  network tcp
                  add_peer uml2 uml2 988*/
                /*attach lov lov_conf_mdsA f0591_lov_conf_mdsA_224a85b5fc
                  lov_setup lovA_UUID 0 1048576 0 0 ost1_UUID
                  mount_option mdsA lov_conf_mdsA
                */
                do_jt(jt_lcfg_attach,    "attach", "lov", "lov_c", "lov_c_uuid", 0);
                do_jt(jt_lcfg_lov_setup, "lov_setup", "lovA_uuid",
                      "0" /*data->u.mds.stripe_count*/,
                      "1048576" /*data->u.mds.stripe_size*/,
                      "0" /* stripe_off FIXME */,
                      "0" /* stripe_pattern */, 0);
                do_jt(jt_lcfg_mount_option,"mount_option", data->obdname, "lov_c", 0);
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

/* Make the mds/ost obd name based on the filesystem name */
static void make_obdname(struct lustre_disk_data *data)
{
        int maxlen = sizeof(data->obdname) - 1;

        if (IS_MDS(data)) {
                snprintf(data->obdname, maxlen, "MDS%s", data->fsname);
        } else if (IS_OST(data)) {
                char number[5];
                snprintf(data->obdname, maxlen, "OST%s", data->fsname);
                /* FIXME if we're not given an index, we might
                   have to change our name later -- can't have two ost's
                   with the same name. Rewrite ost log?? */
                snprintf(number, 5, "%04x", data->u.ost.stripe_index);
                /* Truncate label if need be to get the whole index number */
                data->obdname[maxlen - 4] = 0;
                strcat(data->obdname, number);
        } else {
                snprintf(data->obdname, maxlen, "MGT%s", data->fsname);
        }         

        /* This uuid must match the client's concept of the server uuid in
           confobd_update_logs*/
        snprintf(data->obduuid, sizeof(data->obduuid), "%s_UUID", data->obdname); 
}

void set_defaults(struct lustre_disk_data *data)
{
        data->magic = LDD_MAGIC;

        if (get_os_version() == 24) { 
                data->fs_type = FS_EXT3;
                strcpy(data->fs_type_string, "ext3");
        } else {
                data->fs_type = FS_LDISKFS;
                strcpy(data->fs_type_string, "ldiskfs");
        }
        
        strcpy(data->fsname, "lustre");
}

int main(int argc , char *const argv[])
{
        struct lustre_disk_data data;
        static struct option long_opt[] = {
                {"help", 0, 0, 'h'},
                {"fsname",1, 0, 'n'},
                {"mgtnode", 1, 0, 'm'},
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

        if (argc < 3) 
                usage(stderr);
           
        progname = argv[0];
        memset(&data, 0, sizeof(data));
        set_defaults(&data);

        if (!strcasecmp(argv[1], "mds")){
                data.disk_type |= MDS_DISK_TYPE;
                data.disk_type |= MGT_DISK_TYPE;
        }
        else if (!strcasecmp(argv[1], "ost")) {
                data.disk_type |= OST_DISK_TYPE;
                data.u.ost.stripe_index = -1;
        } else if (!strcasecmp(argv[1], "mgt")) {
                data.disk_type |= MGT_DISK_TYPE;
        } else {
                fprintf(stderr, "%s: need to know disk type :{mds,ost,mgt}\n",
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
                        if (optarg[0] != 0) 
                                strncpy(data.fsname, optarg, 
                                        sizeof(data.fsname) - 1);
                        break;
                case 'm':
                        if IS_MGT(&data){
                                fprintf(stderr, "%s: wrong option for mgt"
                                        "%s \n", progname, optarg);
                                usage(stderr);
                        }
                        if IS_MDS(&data){
                                /* FIXME after the network is done */  
                                strcpy(data.u.mds.mgt_node.host, optarg);
                                data.disk_type &= ~MGT_DISK_TYPE;
                        }
                        if IS_OST(&data)
                                strcpy(data.u.ost.mgt_node.host,optarg);
                        break;
                case 'f': /* FIXME after the network is done */  
                        if IS_MDS(&data)
                                strcpy(data.u.mds.host.failover_addr,optarg);
                        if IS_OST(&data)
                                strcpy(data.u.ost.host.failover_addr,optarg);
                        if IS_MGT(&data)
                                strcpy(data.mgt.host.failover_addr,optarg);
                        break;
                case 'd':
                        data.device_size = atol (optarg); 
                        break;
                case 'c':
                        if IS_MDS(&data) {
                                int stripe_count = atol(optarg);
                                data.u.mds.stripe_count = stripe_count;
                                if (stripe_count > 77)
                                        data.inode_size = 4096;
                                else if (stripe_count > 35)
                                        data.inode_size = 2048;
                                else 
                                        data.inode_size = 1024;
                        }
                        if IS_MGT(&data)
                                data.mgt.stripe_count = atol(optarg);
                        else {
                                fprintf(stderr,"%s: wrong option for ost %s\n",
                                        progname,optarg);
                                usage(stderr);
                        }
                        break;
                case 's':
                        if IS_MDS(&data)
                                data.u.mds.stripe_size = atol(optarg)*1024;
                        else {
                                fprintf(stderr, "%s: wrong option for mgt%s\n",
                                        progname,optarg);
                                usage(stderr);
                        }
                        break;
                case 'i':
                        if IS_OST(&data)
                                data.u.ost.stripe_index = atol(optarg);
                        else {
                                fprintf(stderr, 
                                        "%s: wrong option for mds/mgt%s\n",
                                        progname,optarg);
                                usage(stderr);
                        }
                        break;
                case 'S':
                        data.fs_type = FS_SMFS;
                        strcpy(data.fs_type_string, "smfs");
                        strncpy(data.mkfsopts, optarg, sizeof(data.mkfsopts)-1);
                        break;
                case 'e':
                        data.fs_type = FS_EXT3;
                        strcpy(data.fs_type_string, "ext3");
                        strncpy(data.mkfsopts, optarg, sizeof(data.mkfsopts)-1);
                        break;
                default:
                        fprintf(stderr, "%s: unknown option '%c'\n",
                                progname, opt);
                        usage(stderr);
                        break;
                }
        }//while

        strcpy(data.device, argv[optind]);

        if (IS_OST(&data) && (data.u.ost.stripe_index == -1)) {
                fprintf(stderr, "You must set --stripe_index=?? for now.\n");
                return EINVAL;
        }
        
        if (IS_MDS(&data) && (data.u.mds.stripe_size == 0))
                data.u.mds.stripe_size = 1024 * 1024;
        
        /* These are the mount options stored in the log files.  
           llmount must use the same options to start the confobd. */
        if ((data.fs_type == FS_EXT3) || (data.fs_type == FS_LDISKFS)) {
                sprintf(data.mountfsopts, "errors=remount-ro");
                if (IS_MDS(&data))
                        strcat(data.mountfsopts, ",iopen_nopriv");
                if ((IS_OST(&data)) && (get_os_version() == 24))
                        strcat(data.mountfsopts, ",asyncdel");
        } else if (data.fs_type == FS_SMFS) {
                sprintf(data.mountfsopts, "type=ext3,dev=%s", data.device);
        } else {
                fprintf(stderr, "%s: unknown fs type %d '%s'\n",
                        progname, data.fs_type, data.fs_type_string);
                return EINVAL;
        }
    
        make_obdname(&data);

        if (load_module("confobd"))
                return ENOSYS;

        if ((data.fs_type == FS_SMFS) || !is_block(data.device)) {
                data.flags |= MO_IS_LOOP;
                ret = setup_loop_device(&data);
                if (ret) 
                        return ret;
        }
                
        ret = make_lustre_backfs(&data);
        if (ret != 0) {
              fprintf(stderr, "mkfs failed\n");
              goto out;
        }
        
        ret = write_local_files(&data);
        if (ret != 0) {
              fprintf(stderr, "failed to write local files\n");
              goto out;
        }

        ret = lustre_log_setup(&data);
        if (ret != 0) {
              fprintf(stderr, "failed to write setup logs\n");
              goto out;
        }

out:
        if (data.flags & MO_IS_LOOP) {
                sprintf(cmd, "losetup -d %s", data.device);
                ret = run_command(cmd, cmd_out);
        }

        return ret;
}
