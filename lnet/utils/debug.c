/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Some day I'll split all of this functionality into a cfs_debug module
 * of its own.  That day is not today.
 *
 */

#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <syscall.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#define BUG()                            /* workaround for module.h includes */
#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/module.h>
#endif

#include <portals/api-support.h>
#include <portals/ptlctl.h>
#include "parser.h"

static char rawbuf[8192];
static char *buf = rawbuf;
static int max = 8192;
//static int g_pfd = -1;
static int subsystem_array[1 << 8];
static int debug_mask = ~0;

static const char *portal_debug_subsystems[] =
        {"undefined", "mdc", "mds", "osc", "ost", "class", "obdfs", "llite",
         "rpc", "ext2obd", "portals", "socknal", "qswnal", "pinger", "filter",
         "obdtrace", "echo", "ldlm", "lov", "gmnal", "router", "ptldb", NULL};
static const char *portal_debug_masks[] =
        {"trace", "inode", "super", "ext2", "malloc", "cache", "info", "ioctl",
         "blocks", "net", "warning", "buffs", "other", "dentry", "portals",
         "page", "dlmtrace", "error", "emerg", "ha", "rpctrace", "vfstrace", NULL};

struct debug_daemon_cmd {
        char *cmd;
        unsigned int cmdv;
};

static const struct debug_daemon_cmd portal_debug_daemon_cmd[] = {
        {"start", DEBUG_DAEMON_START},
        {"stop", DEBUG_DAEMON_STOP},
        {"pause", DEBUG_DAEMON_PAUSE},
        {"continue", DEBUG_DAEMON_CONTINUE},
        {0, 0}
};

static int do_debug_mask(char *name, int enable)
{
        int found = 0, i;

        for (i = 0; portal_debug_subsystems[i] != NULL; i++) {
                if (strcasecmp(name, portal_debug_subsystems[i]) == 0 ||
                    strcasecmp(name, "all_subs") == 0) {
                        printf("%s output from subsystem \"%s\"\n",
                                enable ? "Enabling" : "Disabling",
                                portal_debug_subsystems[i]);
                        subsystem_array[i] = enable;
                        found = 1;
                }
        }
        for (i = 0; portal_debug_masks[i] != NULL; i++) {
                if (strcasecmp(name, portal_debug_masks[i]) == 0 ||
                    strcasecmp(name, "all_types") == 0) {
                        printf("%s output of type \"%s\"\n",
                                enable ? "Enabling" : "Disabling",
                                portal_debug_masks[i]);
                        if (enable)
                                debug_mask |= (1 << i);
                        else
                                debug_mask &= ~(1 << i);
                        found = 1;
                }
        }

        return found;
}

int dbg_initialize(int argc, char **argv)
{
        memset(subsystem_array, 1, sizeof(subsystem_array));
        return 0;
}

int jt_dbg_filter(int argc, char **argv)
{
        int   i;

        if (argc < 2) {
                fprintf(stderr, "usage: %s <subsystem ID or debug mask>\n",
                        argv[0]);
                return 0;
        }

        for (i = 1; i < argc; i++)
                if (!do_debug_mask(argv[i], 0))
                        fprintf(stderr, "Unknown subsystem or debug type: %s\n",
                                argv[i]);
        return 0;
}

int jt_dbg_show(int argc, char **argv)
{
        int    i;

        if (argc < 2) {
                fprintf(stderr, "usage: %s <subsystem ID or debug mask>\n",
                        argv[0]);
                return 0;
        }

        for (i = 1; i < argc; i++)
                if (!do_debug_mask(argv[i], 1))
                        fprintf(stderr, "Unknown subsystem or debug type: %s\n",
                                argv[i]);

        return 0;
}

static int applymask(char* procpath, int value)
{
        int rc;
        char buf[64];
        int len = snprintf(buf, 64, "%d", value);

        int fd = open(procpath, O_WRONLY);
        if (fd == -1) {
                fprintf(stderr, "Unable to open %s: %s\n",
                        procpath, strerror(errno));
                return fd;
        }
        rc = write(fd, buf, len+1);
        if (rc<0) {
                fprintf(stderr, "Write to %s failed: %s\n",
                        procpath, strerror(errno));
                return rc;
        }
        close(fd);
        return 0;
}

extern char *dump_filename;
extern int dump(int dev_id, int opc, void *buf);

static void applymask_all(unsigned int subs_mask, unsigned int debug_mask)
{
        if (!dump_filename) {
                applymask("/proc/sys/portals/subsystem_debug", subs_mask);
                applymask("/proc/sys/portals/debug", debug_mask);
        } else {
                struct portals_debug_ioctl_data data;

                data.hdr.ioc_len = sizeof(data);
                data.hdr.ioc_version = 0;
                data.subs = subs_mask;
                data.debug = debug_mask;

                dump(OBD_DEV_ID, PTL_IOC_DEBUG_MASK, &data);
        }
        printf("Applied subsystem_debug=%d, debug=%d to /proc/sys/portals\n",
               subs_mask, debug_mask);
}

int jt_dbg_list(int argc, char **argv)
{
        int i;

        if (argc != 2) {
                fprintf(stderr, "usage: %s <subs || types>\n", argv[0]);
                return 0;
        }

        if (strcasecmp(argv[1], "subs") == 0) {
                printf("Subsystems: all_subs");
                for (i = 0; portal_debug_subsystems[i] != NULL; i++)
                        printf(", %s", portal_debug_subsystems[i]);
                printf("\n");
        } else if (strcasecmp(argv[1], "types") == 0) {
                printf("Types: all_types");
                for (i = 0; portal_debug_masks[i] != NULL; i++)
                        printf(", %s", portal_debug_masks[i]);
                printf("\n");
        }
        else if (strcasecmp(argv[1], "applymasks") == 0) {
                unsigned int subsystem_mask = 0;
                for (i = 0; portal_debug_subsystems[i] != NULL; i++) {
                        if (subsystem_array[i]) subsystem_mask |= (1 << i);
                }
                applymask_all(subsystem_mask, debug_mask);
        }
        return 0;
}

/* if 'raw' is true, don't strip the debug information from the front of the
 * lines */
static void dump_buffer(FILE *fd, char *buf, int size, int raw)
{
        char *p, *z;
        unsigned long subsystem, debug, dropped = 0, kept = 0;
        int max_sub, max_type;

        for (max_sub = 0; portal_debug_subsystems[max_sub] != NULL; max_sub++)
                ;
        for (max_type = 0; portal_debug_masks[max_type] != NULL; max_type++)
                ;

        while (size) {
                p = memchr(buf, '\n', size);
                if (!p)
                        break;
                subsystem = strtoul(buf, &z, 16);
                debug = strtoul(z + 1, &z, 16);

                z++;
                /* for some reason %*s isn't working. */
                *p = '\0';
                if (subsystem < max_sub &&
                    subsystem_array[subsystem] &&
                    (!debug || (debug_mask & debug))) {
                        if (raw)
                                fprintf(fd, "%s\n", buf);
                        else
                                fprintf(fd, "%s\n", z);
                        //printf("%s\n", buf);
                        kept++;
                } else {
                        //fprintf(stderr, "dropping line (%lx:%lx): %s\n", subsystem, debug, buf);
                        dropped++;
                }
                *p = '\n';
                p++;
                size -= (p - buf);
                buf = p;
        }

        printf("Debug log: %lu lines, %lu kept, %lu dropped.\n",
                dropped + kept, kept, dropped);
}

int jt_dbg_debug_kernel(int argc, char **argv)
{
        int rc, raw = 1;
        FILE *fd = stdout;
        const int databuf_size = (6 << 20);
        struct portal_ioctl_data data, *newdata;
        char *databuf = NULL;

        if (argc > 3) {
                fprintf(stderr, "usage: %s [file] [raw]\n", argv[0]);
                return 0;
        }

        if (argc > 1) {
                fd = fopen(argv[1], "w");
                if (fd == NULL) {
                        fprintf(stderr, "fopen(%s) failed: %s\n", argv[1],
                                strerror(errno));
                        return -1;
                }
        }
        if (argc > 2)
                raw = atoi(argv[2]);

        databuf = malloc(databuf_size);
        if (!databuf) {
                fprintf(stderr, "No memory for buffer.\n");
                goto out;
        }

        memset(&data, 0, sizeof(data));
        data.ioc_plen1 = databuf_size;
        data.ioc_pbuf1 = databuf;

        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                goto out;
        }

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_GET_DEBUG, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_GET_DEBUG failed: %s\n",
                        strerror(errno));
                goto out;
        }

        newdata = (struct portal_ioctl_data *)buf;
        if (newdata->ioc_size > 0)
                dump_buffer(fd, databuf, newdata->ioc_size, raw);
        else
                fprintf(stderr, "No data in the debug buffer.\n");

 out:
        if (databuf)
                free(databuf);
        if (fd != stdout)
                fclose(fd);
        return 0;
}

int jt_dbg_debug_daemon(int argc, char **argv)
{
        int i, rc;
        unsigned int cmd = 0;
        FILE *fd = stdout;
        struct portal_ioctl_data data;

        if (argc <= 1) {
                fprintf(stderr, "usage: %s [start file <#MB>|stop|pause|"
                        "continue]\n", argv[0]);
                return 0;
        }
        for (i = 0; portal_debug_daemon_cmd[i].cmd != NULL; i++) {
                if (strcasecmp(argv[1], portal_debug_daemon_cmd[i].cmd) == 0) {
                        cmd = portal_debug_daemon_cmd[i].cmdv;
                        break;
                }
        }
        if (portal_debug_daemon_cmd[i].cmd == NULL) {
                fprintf(stderr, "usage: %s [start file <#MB>|stop|pause|"
                        "continue]\n", argv[0]);
                return 0;
        }
        memset(&data, 0, sizeof(data));
        if (cmd == DEBUG_DAEMON_START) {
                if (argc < 3) {
                        fprintf(stderr, "usage: %s [start file <#MB>|stop|"
                                "pause|continue]\n", argv[0]);
                        return 0;
                }
                if (access(argv[2], F_OK) != 0) {
                        fd = fopen(argv[2], "w");
                        if (fd != NULL) {
                                fclose(fd);
                                remove(argv[2]);
                                goto ok;
                        }
                }
                if (access(argv[2], W_OK) == 0)
                        goto ok;
                fprintf(stderr, "fopen(%s) failed: %s\n", argv[2],
                        strerror(errno));
                return -1;
ok:
                data.ioc_inllen1 = strlen(argv[2]) + 1;
                data.ioc_inlbuf1 = argv[2];
                data.ioc_misc = 0;
                if (argc == 4) {
                        unsigned long size;
                        errno = 0;
                        size = strtoul(argv[3], NULL, 0);
                        if (errno) {
                                fprintf(stderr, "file size(%s): error %s\n",
                                        argv[3], strerror(errno));
                                return -1;
                        }
                        data.ioc_misc = size;
                }
        }
        data.ioc_count = cmd;
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }
        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_SET_DAEMON, buf);
        if (rc < 0) {
                fprintf(stderr, "IOC_PORTAL_SET_DEMON failed: %s\n",
                                strerror(errno));
                return rc;
        }
        return 0;
}

int jt_dbg_debug_file(int argc, char **argv)
{
        int rc, fd = -1, raw = 1;
        FILE *output = stdout;
        char *databuf = NULL;
        struct stat statbuf;

        if (argc > 4 || argc < 2) {
                fprintf(stderr, "usage: %s <input> [output] [raw]\n", argv[0]);
                return 0;
        }

        fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "fopen(%s) failed: %s\n", argv[1],
                        strerror(errno));
                return -1;
        }
#warning FIXME: cleanup fstat issue here
#ifndef SYS_fstat64
#define __SYS_fstat__ SYS_fstat
#else
#define __SYS_fstat__ SYS_fstat64
#endif
        rc = syscall(__SYS_fstat__, fd, &statbuf);
        if (rc < 0) {
                fprintf(stderr, "fstat failed: %s\n", strerror(errno));
                goto out;
        }

        if (argc >= 3) {
                output = fopen(argv[2], "w");
                if (output == NULL) {
                        fprintf(stderr, "fopen(%s) failed: %s\n", argv[2],
                                strerror(errno));
                        goto out;
                }
        }

        if (argc == 4)
                raw = atoi(argv[3]);

        databuf = mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE, fd, 0);
        if (databuf == NULL) {
                fprintf(stderr, "mmap failed: %s\n", strerror(errno));
                goto out;
        }

        dump_buffer(output, databuf, statbuf.st_size, raw);

 out:
        if (databuf)
                munmap(databuf, statbuf.st_size);
        if (output != stdout)
                fclose(output);
        if (fd > 0)
                close(fd);
        return 0;
}

int jt_dbg_clear_debug_buf(int argc, char **argv)
{
        int rc;
        struct portal_ioctl_data data;

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", argv[0]);
                return 0;
        }

        memset(&data, 0, sizeof(data));
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_CLEAR_DEBUG, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_CLEAR_DEBUG failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_dbg_mark_debug_buf(int argc, char **argv)
{
        int rc;
        struct portal_ioctl_data data;
        char *text;
        time_t now = time(NULL);

        if (argc > 2) {
                fprintf(stderr, "usage: %s [marker text]\n", argv[0]);
                return 0;
        }

        if (argc == 2) {
                text = argv[1];
        } else {
                text = ctime(&now);
                text[strlen(text) - 1] = '\0'; /* stupid \n */
        }

        memset(&data, 0, sizeof(data));
        data.ioc_inllen1 = strlen(text) + 1;
        data.ioc_inlbuf1 = text;
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_MARK_DEBUG, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_MARK_DEBUG failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}


int jt_dbg_modules(int argc, char **argv)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        struct mod_paths {
                char *name, *path;
        } *mp, mod_paths[] = {
                {"portals", "lustre/portals/libcfs"},
                {"ksocknal", "lustre/portals/knals/socknal"},
                {"obdclass", "lustre/obdclass"},
                {"ptlrpc", "lustre/ptlrpc"},
                {"obdext2", "lustre/obdext2"},
                {"ost", "lustre/ost"},
                {"osc", "lustre/osc"},
                {"mds", "lustre/mds"},
                {"mdc", "lustre/mdc"},
                {"llite", "lustre/llite"},
                {"obdecho", "lustre/obdecho"},
                {"ldlm", "lustre/ldlm"},
                {"obdfilter", "lustre/obdfilter"},
                {"extN", "lustre/extN"},
                {"lov", "lustre/lov"},
                {"fsfilt_ext3", "lustre/obdclass"},
                {"fsfilt_extN", "lustre/obdclass"},
                {"mds_ext2", "lustre/mds"},
                {"mds_ext3", "lustre/mds"},
                {"mds_extN", "lustre/mds"},
                {"ptlbd", "lustre/ptlbd"},
                {NULL, NULL}
        };
        char *path = "..";
        char *kernel = "linux";

        if (argc >= 2)
                path = argv[1];
        if (argc == 3)
                kernel = argv[2];
        if (argc > 3) {
                printf("%s [path] [kernel]\n", argv[0]);
                return 0;
        }

        for (mp = mod_paths; mp->name != NULL; mp++) {
                struct module_info info;
                int rc;
                size_t crap;
                int query_module(const char *name, int which, void *buf,
                                 size_t bufsize, size_t *ret);

                rc = query_module(mp->name, QM_INFO, &info, sizeof(info),
                                  &crap);
                if (rc < 0) {
                        if (errno != ENOENT)
                                printf("query_module(%s) failed: %s\n",
                                       mp->name, strerror(errno));
                } else {
                        printf("add-symbol-file %s/%s/%s.o 0x%0lx\n", path,
                               mp->path, mp->name,
                               info.addr + sizeof(struct module));
                }
        }

        return 0;
#else
        printf("jt_dbg_module is not yet implemented for Linux 2.5\n");
        return 0;
#endif /* linux 2.5 */
}

int jt_dbg_panic(int argc, char **argv)
{
        int rc;
        struct portal_ioctl_data data;

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", argv[0]);
                return 0;
        }

        memset(&data, 0, sizeof(data));
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_PANIC, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_PANIC failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}
