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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <asm/atomic.h>
#include <linux/module.h>
#include <portals/api-support.h>

#include "lctl.h"

/* current debug flag
 */
int lctl_debug;

static char rawbuf[8192];
static char *buf = rawbuf;
static int max = 8192;
static int g_pfd = -1;
static int subsystem_array[1 << 8];
static int debug_mask = ~0;

static const char *portal_debug_subsystems[] =
        {"undefined", "mdc", "mds", "osc", "ost", "class", "obdfs", "llite",
         "rpc", "ext2obd", "portals", "socknal", "qswnal", "pinger", "filter",
         "obdtrace", "echo", "ldlm", "lov", "gmnal", "router", NULL};
static const char *portal_debug_masks[] =
        {"trace", "inode", "super", "ext2", "malloc", "cache", "info", "ioctl",
         "blocks", "net", "warning", "buffs", "other", "dentry", "portals",
         "page", "dlmtrace", NULL};

int debug_setup(int argc, char **argv) {
        memset(subsystem_array, 1, sizeof(subsystem_array));
        return 0;
}

static int do_debug_mask(char *name, int enable) {
        int found = 0, i;

        for (i = 0; portal_debug_subsystems[i] != NULL; i++) {
                if (strcasecmp(name, portal_debug_subsystems[i]) == 0 ||
                    strcasecmp(name, "all_subs") == 0) {
                        fprintf(stderr, "%s output from subsystem \"%s\"\n",
                                enable ? "Enabling" : "Disabling",
                                portal_debug_subsystems[i]);
                        subsystem_array[i] = enable;
                        found = 1;
                }
        }
        for (i = 0; portal_debug_masks[i] != NULL; i++) {
                if (strcasecmp(name, portal_debug_masks[i]) == 0 ||
                    strcasecmp(name, "all_types") == 0) {
                        fprintf(stderr, "%s output of type \"%s\"\n",
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

/* if 'raw' is true, don't strip the debug information from the
 * front of the lines */
static void dump_buffer(FILE *fd, char *buf, int size, int raw) {
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

        fprintf(stderr, "Debug log: %lu lines, %lu kept, %lu dropped.\n",
                dropped + kept, kept, dropped);
}

int jt_debug_kernel(int argc, char **argv) {
        int rc, raw = 0;
        FILE *fd = stdout;
        const int databuf_size = (6 << 20);
        struct portal_ioctl_data data, *newdata;
        char *databuf = NULL;

        PORTALS_CONNECT;

        if (argc > 3)
                return CMD_HELP;

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

        rc = ioctl(g_pfd, IOC_PORTAL_GET_DEBUG, buf);
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

int jt_debug_file(int argc, char **argv) {
        int rc, fd = -1, raw = 0;
        FILE *output = stdout;
        char *databuf = NULL;
        struct stat statbuf;

        if (argc > 4 || argc < 2)
                return CMD_HELP;

        fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "fopen(%s) failed: %s\n", argv[1],
                        strerror(errno));
                return -1;
        }
        rc = fstat(fd, &statbuf);
        if (rc < 0) {
                fprintf(stderr, "fstat failed: %s\n", strerror(errno));
                goto out;
        }

        if (argc == 3) {
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

int jt_debug_clear(int argc, char **argv) {
        int rc;
        struct portal_ioctl_data data;

        PORTALS_CONNECT;
        if (argc != 1)
                return CMD_HELP;

        memset(&data, 0, sizeof(data));
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }

        rc = ioctl(g_pfd, IOC_PORTAL_CLEAR_DEBUG, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_CLEAR_DEBUG failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_debug_mark(int argc, char **argv) {
        int rc;
        struct portal_ioctl_data data;
        char *text;
        time_t now = time(NULL);

        PORTALS_CONNECT;
        if (argc > 2)
                return CMD_HELP;

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

        rc = ioctl(g_pfd, IOC_PORTAL_MARK_DEBUG, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_MARK_DEBUG failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_debug_filter(int argc, char **argv) {
        int   i;
        
        if (argc < 2) 
                return CMD_HELP;

        for (i = 1; i < argc; i++)
                if (!do_debug_mask(argv[i], 0))
                        fprintf(stderr, "Unknown subsystem or "
                                "debug type: %s\n", argv[i]);
        return 0;
}

int jt_debug_show(int argc, char **argv) {
        int i;
        
        if (argc < 2)
                return CMD_HELP;

        for (i = 1; i < argc; i++)
                if (!do_debug_mask(argv[i], 1))
                        fprintf(stderr, "Unknown subsystem or "
                                "debug type: %s\n", argv[i]);

        return 0;
}

int jt_debug_list(int argc, char **argv) {
        int i;

        if (argc != 2)
                return CMD_HELP; 

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
        return 0;
}

int jt_debug_modules(int argc, char **argv) {
        char *modules[] = {"portals", "ksocknal", "obdclass", "ptlrpc",
                           "obdext2", "ost", "osc", "mds", "mdc", "llite",
                           "obdecho", "ldlm", "obdfilter", "extN", "lov",
                           "mds_ext2", "mds_ext3", "mds_extN", NULL};
        char *paths[] = {"portals/linux/oslib", "portals/linux/socknal",
                         "lustre/obdclass", "lustre/ptlrpc", "lustre/obdext2",
                         "lustre/ost", "lustre/osc", "lustre/mds", "lustre/mdc",
                         "lustre/llite", "lustre/obdecho", "lustre/ldlm",
                         "lustre/obdfilter", "lustre/extN", "lustre/lov",
                         "lustre/mds", "lustre/mds", "lustre/mds", NULL};
        char *path = "..";
        char *kernel = "linux";
        int i;

        if (argc >= 2)
                path = argv[1];
        if (argc == 3) 
                kernel = argv[2];
        if (argc > 3) {
                printf("%s [path] [kernel]\n", argv[0]);
                return 0;
        }

        printf("set height 1000\n"
               "symbol-file\n"
               "delete\n"
               "symbol-file %s\n"
               "b panic\n"
               "b stop\n", kernel); 

        for (i = 0; modules[i] != NULL; i++) {
                struct module_info info;
                int rc;
                size_t crap;
                int query_module(const char *name, int which, void *buf,
                                 size_t bufsize, size_t *ret);

                rc = query_module(modules[i], QM_INFO, &info, sizeof(info),
                                  &crap);
                if (rc < 0) {
                        if (errno != ENOENT)
                                printf("query_module(%s) failed: %s\n",
                                       modules[i], strerror(errno));
                } else {
                        printf("add-symbol-file %s/%s/%s.o 0x%0lx\n", path,
                               paths[i], modules[i],
                               info.addr + sizeof(struct module));
                }
        }
        printf("set height 24\n");

        return 0;
}

int jt_debug_panic(int argc, char **argv) {
        int rc;
        struct portal_ioctl_data data;

        PORTALS_CONNECT;
        if (argc != 1)
                return CMD_HELP;

        memset(&data, 0, sizeof(data));
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }

        rc = ioctl(g_pfd, IOC_PORTAL_PANIC, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_PANIC failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_debug_lctl(int argc, char **argv) {
        if (argc == 2) {
                lctl_debug = strtoul(argv[1], NULL, 0);
        } else
                printf("current lctl_debug: 0x%x\n", lctl_debug);
        return 0;
}
