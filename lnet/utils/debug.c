/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre Networking, http://www.lustre.org.
 *
 *   LNET is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   LNET is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with LNET; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Some day I'll split all of this functionality into a cfs_debug module
 * of its own.  That day is not today.
 *
 */

#define __USE_FILE_OFFSET64
#define  _GNU_SOURCE

#include <stdio.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifndef _IOWR
#include "ioctl.h"
#endif
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#include <lnet/api-support.h>
#include <lnet/lnetctl.h>
#include <libcfs/portals_utils.h>
#include "parser.h"

#include <time.h>

static char rawbuf[8192];
static char *buf = rawbuf;
static int max = 8192;
/*static int g_pfd = -1;*/
static int subsystem_mask = ~0;
static int debug_mask = ~0;

#define MAX_MARK_SIZE 256

static const char *libcfs_debug_subsystems[] =
        {"undefined", "mdc", "mds", "osc",
         "ost", "class", "log", "llite",
         "rpc", "", "lnet", "lnd",
         "pinger", "filter", "", "echo",
         "ldlm", "lov", "", "",
         "", "", "", "lmv",
         "", "sec", "gss", "", "mgc", "mgs",
         "fid", "fld", NULL};
static const char *libcfs_debug_masks[] =
        {"trace", "inode", "super", "ext2",
         "malloc", "cache", "info", "ioctl",
         "blocks", "net", "warning", "buffs",
         "other", "dentry", "lnet", "page",
         "dlmtrace", "error", "emerg", "ha",
         "rpctrace", "vfstrace", "reada", "mmap",
         "config", "console", "quota", "sec", NULL};

struct debug_daemon_cmd {
        char *cmd;
        unsigned int cmdv;
};

static const struct debug_daemon_cmd libcfs_debug_daemon_cmd[] = {
        {"start", DEBUG_DAEMON_START},
        {"stop", DEBUG_DAEMON_STOP},
        {0, 0}
};

#ifdef __linux__

#define DAEMON_CTL_NAME         "/proc/sys/lnet/daemon_file"
#define SUBSYS_DEBUG_CTL_NAME   "/proc/sys/lnet/subsystem_debug"
#define DEBUG_CTL_NAME          "/proc/sys/lnet/debug"
#define DUMP_KERNEL_CTL_NAME    "/proc/sys/lnet/dump_kernel"

static int
dbg_open_ctlhandle(const char *str)
{
        int fd;
        fd = open(str, O_WRONLY);
        if (fd < 0) {
                fprintf(stderr, "open %s failed: %s\n", str,
                        strerror(errno));
                return -1;
        }
        return fd;
}

static void
dbg_close_ctlhandle(int fd)
{
        close(fd);
}

static int
dbg_write_cmd(int fd, char *str, int len)
{
        int    rc  = write(fd, str, len);

        return (rc == len ? 0 : 1);
}

#elif defined(__DARWIN__)

#define DAEMON_CTL_NAME         "lnet.trace_daemon"
#define SUBSYS_DEBUG_CTL_NAME   "lnet.subsystem_debug"
#define DEBUG_CTL_NAME          "lnet.debug"
#define DUMP_KERNEL_CTL_NAME    "lnet.trace_dumpkernel"

static char     sysctl_name[128];
static int
dbg_open_ctlhandle(const char *str)
{

        if (strlen(str)+1 > 128) {
                fprintf(stderr, "sysctl name is too long: %s.\n", str);
                return -1;
        }
        strcpy(sysctl_name, str);

        return 0;
}

static void
dbg_close_ctlhandle(int fd)
{
        sysctl_name[0] = '\0';
        return;
}

static int
dbg_write_cmd(int fd, char *str, int len)
{
        int     rc;

        rc = sysctlbyname(sysctl_name, NULL, NULL, str, len+1);
        if (rc != 0) {
                fprintf(stderr, "sysctl %s with cmd (%s) error: %d\n",
                        sysctl_name, str, errno);
        }
        return (rc == 0 ? 0: 1);
}

#else
#error - Unknown sysctl convention.
#endif

static int do_debug_mask(char *name, int enable)
{
        int found = 0, i;

        for (i = 0; libcfs_debug_subsystems[i] != NULL; i++) {
                if (strcasecmp(name, libcfs_debug_subsystems[i]) == 0 ||
                    strcasecmp(name, "all_subs") == 0) {
                        printf("%s output from subsystem \"%s\"\n",
                                enable ? "Enabling" : "Disabling",
                                libcfs_debug_subsystems[i]);
                        if (enable)
                                subsystem_mask |= (1 << i);
                        else
                                subsystem_mask &= ~(1 << i);
                        found = 1;
                }
        }
        for (i = 0; libcfs_debug_masks[i] != NULL; i++) {
                if (strcasecmp(name, libcfs_debug_masks[i]) == 0 ||
                    strcasecmp(name, "all_types") == 0) {
                        printf("%s output of type \"%s\"\n",
                                enable ? "Enabling" : "Disabling",
                                libcfs_debug_masks[i]);
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

        int fd = dbg_open_ctlhandle(procpath);
        if (fd == -1) {
                fprintf(stderr, "Unable to open %s: %s\n",
                        procpath, strerror(errno));
                return fd;
        }
        rc = dbg_write_cmd(fd, buf, len+1);
        if (rc != 0) {
                fprintf(stderr, "Write to %s failed: %s\n",
                        procpath, strerror(errno));
                return rc;
        }
        dbg_close_ctlhandle(fd);
        return 0;
}

static void applymask_all(unsigned int subs_mask, unsigned int debug_mask)
{
        if (!dump_filename) {
                applymask(SUBSYS_DEBUG_CTL_NAME, subs_mask);
                applymask(DEBUG_CTL_NAME, debug_mask);
        } else {
                struct libcfs_debug_ioctl_data data;

                data.hdr.ioc_len = sizeof(data);
                data.hdr.ioc_version = 0;
                data.subs = subs_mask;
                data.debug = debug_mask;

                dump(OBD_DEV_ID, LIBCFS_IOC_DEBUG_MASK, &data);
        }
        printf("Applied subsystem_debug=%d, debug=%d to /proc/sys/lnet\n",
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
                for (i = 0; libcfs_debug_subsystems[i] != NULL; i++)
                        if (libcfs_debug_subsystems[i][0])
                                printf(", %s", libcfs_debug_subsystems[i]);
                printf("\n");
        } else if (strcasecmp(argv[1], "types") == 0) {
                printf("Types: all_types");
                for (i = 0; libcfs_debug_masks[i] != NULL; i++)
                        printf(", %s", libcfs_debug_masks[i]);
                printf("\n");
        } else if (strcasecmp(argv[1], "applymasks") == 0) {
                applymask_all(subsystem_mask, debug_mask);
        }
        return 0;
}

/* all strings nul-terminated; only the struct and hdr need to be freed */
struct dbg_line {
        struct ptldebug_header *hdr;
        char *file;
        char *fn;
        char *text;
        struct list_head chain;
};

/* nurr. */
static void list_add_ordered(struct dbg_line *new, struct list_head *head)
{
        struct list_head *pos;
        struct dbg_line *curr;

        list_for_each(pos, head) {
                curr = list_entry(pos, struct dbg_line, chain);

                if (curr->hdr->ph_sec < new->hdr->ph_sec)
                        continue;
                if (curr->hdr->ph_sec == new->hdr->ph_sec &&
                    curr->hdr->ph_usec < new->hdr->ph_usec)
                        continue;

                list_add(&new->chain, pos->prev);
                return;
        }
        list_add_tail(&new->chain, head);
}

static void print_saved_records(struct list_head *list, FILE *out)
{
        struct list_head *pos, *tmp;

        list_for_each_safe(pos, tmp, list) {
                struct dbg_line *line;
                struct ptldebug_header *hdr;

                line = list_entry(pos, struct dbg_line, chain);
                list_del(&line->chain);

                hdr = line->hdr;
                fprintf(out, "%08x:%08x:%u:%u.%06llu:%u:%u:%u:(%s:%u:%s()) %s",
                        hdr->ph_subsys, hdr->ph_mask, hdr->ph_cpu_id,
                        hdr->ph_sec, (unsigned long long)hdr->ph_usec,
                        hdr->ph_stack, hdr->ph_pid, hdr->ph_extern_pid,
                        line->file, hdr->ph_line_num, line->fn, line->text);
                free(line->hdr);
                free(line);
        }
}

static int parse_buffer(FILE *in, FILE *out)
{
        struct dbg_line *line;
        struct ptldebug_header *hdr;
        char buf[4097], *p;
        int rc;
        unsigned long dropped = 0, kept = 0;
        struct list_head chunk_list;

        CFS_INIT_LIST_HEAD(&chunk_list);

        while (1) {
                rc = fread(buf, sizeof(hdr->ph_len) + sizeof(hdr->ph_flags), 1, in);
                if (rc <= 0)
                        break;

                hdr = (void *)buf;
                if (hdr->ph_len == 0)
                        break;
                if (hdr->ph_len > 4094) {
                        fprintf(stderr, "unexpected large record: %d bytes.  "
                                "aborting.\n",
                                hdr->ph_len);
                        break;
                }

                if (hdr->ph_flags & PH_FLAG_FIRST_RECORD) {
                        print_saved_records(&chunk_list, out);
                        assert(list_empty(&chunk_list));
                }

                rc = fread(buf + sizeof(hdr->ph_len) + sizeof(hdr->ph_flags), 1,
                           hdr->ph_len - sizeof(hdr->ph_len) - sizeof(hdr->ph_flags), in);
                if (rc <= 0)
                        break;

                if (hdr->ph_mask &&
                    (!(subsystem_mask & hdr->ph_subsys) ||
                     (!(debug_mask & hdr->ph_mask)))) {
                        dropped++;
                        continue;
                }

                line = malloc(sizeof(*line));
                if (line == NULL) {
                        fprintf(stderr, "malloc failed; printing accumulated "
                                "records and exiting.\n");
                        break;
                }

                line->hdr = malloc(hdr->ph_len + 1);
                if (line->hdr == NULL) {
                        free(line);
                        fprintf(stderr, "malloc failed; printing accumulated "
                                "records and exiting.\n");
                        break;
                }

                p = (void *)line->hdr;
                memcpy(line->hdr, buf, hdr->ph_len);
                p[hdr->ph_len] = '\0';

                p += sizeof(*hdr);
                line->file = p;
                p += strlen(line->file) + 1;
                line->fn = p;
                p += strlen(line->fn) + 1;
                line->text = p;

                list_add_ordered(line, &chunk_list);
                kept++;
        }

        print_saved_records(&chunk_list, out);

        printf("Debug log: %lu lines, %lu kept, %lu dropped.\n",
                dropped + kept, kept, dropped);
        return 0;
}

int jt_dbg_debug_kernel(int argc, char **argv)
{
        char filename[4096];
        struct stat st;
        int rc, raw = 0, fd;
        FILE *in, *out = stdout;

        if (argc > 3) {
                fprintf(stderr, "usage: %s [file] [raw]\n", argv[0]);
                return 0;
        }

        if (argc > 2) {
                raw = atoi(argv[2]);
        } else if (argc > 1 && (argv[1][0] == '0' || argv[1][0] == '1')) {
                raw = atoi(argv[1]);
                argc--;
        }

        /* If we are dumping raw (which means no conversion step to ASCII)
         * then dump directly to any supplied filename, otherwise this is
         * just a temp file and we dump to the real file at convert time. */
        if (argc > 1 && raw)
                strcpy(filename, argv[1]);
        else
                sprintf(filename, "/tmp/lustre-log.%lu.%u",time(NULL),getpid());

        if (stat(filename, &st) == 0 && S_ISREG(st.st_mode))
                unlink(filename);

        fd = dbg_open_ctlhandle(DUMP_KERNEL_CTL_NAME);
        if (fd < 0) {
                fprintf(stderr, "open(dump_kernel) failed: %s\n",
                        strerror(errno));
                return 1;
        }

        rc = dbg_write_cmd(fd, filename, strlen(filename));
        if (rc != 0) {
                fprintf(stderr, "write(%s) failed: %s\n", filename,
                        strerror(errno));
                close(fd);
                return 1;
        }
        dbg_close_ctlhandle(fd);

        if (raw)
                return 0;

        in = fopen(filename, "r");
        if (in == NULL) {
                if (errno == ENOENT) /* no dump file created */
                        return 0;

                fprintf(stderr, "fopen(%s) failed: %s\n", filename,
                        strerror(errno));
                return 1;
        }
        if (argc > 1) {
                out = fopen(argv[1], "w");
                if (out == NULL) {
                        fprintf(stderr, "fopen(%s) failed: %s\n", argv[1],
                                strerror(errno));
                        fclose(in);
                        return 1;
                }
        }

        rc = parse_buffer(in, out);
        fclose(in);
        if (argc > 1)
                fclose(out);
        if (rc) {
                fprintf(stderr, "parse_buffer failed; leaving tmp file %s "
                        "behind.\n", filename);
        } else {
                rc = unlink(filename);
                if (rc)
                        fprintf(stderr, "dumped successfully, but couldn't "
                                "unlink tmp file %s: %s\n", filename,
                                strerror(errno));
        }
        return rc;
}

int jt_dbg_debug_file(int argc, char **argv)
{
        int    fdin;
        int    fdout;
        FILE  *in;
        FILE  *out = stdout;
        int    rc;

        if (argc > 3 || argc < 2) {
                fprintf(stderr, "usage: %s <input> [output]\n", argv[0]);
                return 0;
        }

        fdin = open(argv[1], O_RDONLY | O_LARGEFILE);
        if (fdin == -1) {
                fprintf(stderr, "open(%s) failed: %s\n", argv[1],
                        strerror(errno));
                return 1;
        }
        in = fdopen(fdin, "r");
        if (in == NULL) {
                fprintf(stderr, "fopen(%s) failed: %s\n", argv[1],
                        strerror(errno));
                close(fdin);
                return 1;
        }
        if (argc > 2) {
                fdout = open(argv[2],
                             O_CREAT | O_TRUNC | O_WRONLY | O_LARGEFILE,
                             0600);
                if (fdout == -1) {
                        fprintf(stderr, "open(%s) failed: %s\n", argv[2],
                                strerror(errno));
                        fclose(in);
                        return 1;
                }
                out = fdopen(fdout, "w");
                if (out == NULL) {
                        fprintf(stderr, "fopen(%s) failed: %s\n", argv[2],
                                strerror(errno));
                        fclose(in);
                        close(fdout);
                        return 1;
                }
        }

        rc = parse_buffer(in, out);

        fclose(in);
        if (out != stdout)
                fclose(out);

        return rc;
}

const char debug_daemon_usage[] = "usage: %s {start file [MB]|stop}\n";

int jt_dbg_debug_daemon(int argc, char **argv)
{
        int  rc;
        int  fd;

        if (argc <= 1) {
                fprintf(stderr, debug_daemon_usage, argv[0]);
                return 1;
        }

        fd = dbg_open_ctlhandle(DAEMON_CTL_NAME);
        if (fd < 0)
                return -1;

        rc = -1;
        if (strcasecmp(argv[1], "start") == 0) {
             if (argc < 3 || argc > 4 ||
                    (argc == 4 && strlen(argv[3]) > 5)) {
                        fprintf(stderr, debug_daemon_usage, argv[0]);
                        goto out;
                }
                if (argc == 4) {
                        char       buf[12];
                        const long min_size = 10;
                        const long max_size = 20480;
                        long       size;
                        char      *end;

                        size = strtoul(argv[3], &end, 0);
                        if (size < min_size ||
                            size > max_size ||
                            *end != 0) {
                                fprintf(stderr, "size %s invalid, must be in "
                                        "the range %ld-%ld MB\n", argv[3],
                                        min_size, max_size);
                                goto out;
                        }
                        snprintf(buf, sizeof(buf), "size=%ld", size);
                        rc = dbg_write_cmd(fd, buf, strlen(buf));

                        if (rc != 0) {
                                fprintf(stderr, "set %s failed: %s\n",
                                        buf, strerror(errno));
                                goto out;
                        }
                }

                rc = dbg_write_cmd(fd, argv[2], strlen(argv[2]));
                if (rc != 0) {
                        fprintf(stderr, "start debug_daemon on %s failed: %s\n",
                                argv[2], strerror(errno));
                        goto out;
                }
                rc = 0;
                goto out;
        }
        if (strcasecmp(argv[1], "stop") == 0) {
                rc = dbg_write_cmd(fd, "stop", 4);
                if (rc != 0) {
                        fprintf(stderr, "stopping debug_daemon failed: %s\n",
                                strerror(errno));
                        goto out;
                }

                rc = 0;
                goto out;
        }

        fprintf(stderr, debug_daemon_usage, argv[0]);
        rc = -1;
out:
        dbg_close_ctlhandle(fd);
        return rc;
}

int jt_dbg_clear_debug_buf(int argc, char **argv)
{
        int rc;
        struct libcfs_ioctl_data data;

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", argv[0]);
                return 0;
        }

        memset(&data, 0, sizeof(data));
        if (libcfs_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "libcfs_ioctl_pack failed.\n");
                return -1;
        }

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_CLEAR_DEBUG, buf);
        if (rc) {
                fprintf(stderr, "IOC_LIBCFS_CLEAR_DEBUG failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_dbg_mark_debug_buf(int argc, char **argv)
{
        static char scratch[MAX_MARK_SIZE] = { '\0' };
        int rc, max_size = MAX_MARK_SIZE-1;
        struct libcfs_ioctl_data data = { 0 };
        char *text;
        time_t now = time(NULL);

        if (argc > 1) {
                int count;
                text = scratch;
                strncpy(text, argv[1], max_size);
                max_size-=strlen(argv[1]);
                for (count = 2; (count < argc) && (max_size > 0); count++){
                        strncat(text, " ", max_size);
                        max_size -= 1;
                        strncat(text, argv[count], max_size);
                        max_size -= strlen(argv[count]);
                }
        } else {
                text = ctime(&now);
        }

        data.ioc_inllen1 = strlen(text) + 1;
        data.ioc_inlbuf1 = text;
        if (libcfs_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "libcfs_ioctl_pack failed.\n");
                return -1;
        }

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_MARK_DEBUG, buf);
        if (rc) {
                fprintf(stderr, "IOC_LIBCFS_MARK_DEBUG failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

static struct mod_paths {
        char *name, *path;
} mod_paths[] = {
        {"libcfs", "lnet/libcfs"},
        {"lnet", "lnet/lnet"},
        {"kciblnd", "lnet/klnds/ciblnd"},
        {"kgmlnd", "lnet/klnds/gmlnd"},
        {"kmxlnd", "lnet/klnds/mxlnd"},
        {"kiiblnd", "lnet/klnds/iiblnd"},
        {"ko2iblnd", "lnet/klnds/o2iblnd"},
        {"kopeniblnd", "lnet/klnds/openiblnd"},
        {"kptllnd", "lnet/klnds/ptllnd"},
        {"kqswlnd", "lnet/klnds/qswlnd"},
        {"kralnd", "lnet/klnds/ralnd"},
        {"ksocklnd", "lnet/klnds/socklnd"},
        {"ktdilnd", "lnet/klnds/tdilnd"},
        {"kviblnd", "lnet/klnds/viblnd"},
        {"lvfs", "lustre/lvfs"},
        {"obdclass", "lustre/obdclass"},
        {"llog_test", "lustre/obdclass"},
        {"ptlrpc_gss", "lustre/ptlrpc/gss"},
        {"ptlrpc", "lustre/ptlrpc"},
        {"gks", "lustre/sec/gks"},
        {"gkc", "lustre/sec/gks"},
        {"ost", "lustre/ost"},
        {"osc", "lustre/osc"},
        {"mds", "lustre/mds"},
        {"mdc", "lustre/mdc"},
        {"llite", "lustre/llite"},
        {"lustre", "lustre/llite"},
        {"ldiskfs", "lustre/ldiskfs"},
        {"smfs", "lustre/smfs"},
        {"obdecho", "lustre/obdecho"},
        {"ldlm", "lustre/ldlm"},
        {"obdfilter", "lustre/obdfilter"},
        {"lov", "lustre/lov"},
        {"lmv", "lustre/lmv"},
        {"fsfilt_ext3", "lustre/lvfs"},
        {"fsfilt_reiserfs", "lustre/lvfs"},
        {"fsfilt_smfs", "lustre/lvfs"},
        {"fsfilt_ldiskfs", "lustre/lvfs"},
        {"mds_ext3", "lustre/mds"},
        {"cobd", "lustre/cobd"},
        {"cmobd", "lustre/cmobd"},
        {"lquota", "lustre/quota"},
        {"mgs", "lustre/mgs"},
        {"mgc", "lustre/mgc"},
        {"mdt", "lustre/mdt"},
        {"mdd", "lustre/mdd"},
        {"osd", "lustre/osd"},
        {"cmm", "lustre/cmm"},
        {"fid", "lustre/fid"},
        {"fld", "lustre/fld"},
        {NULL, NULL}
};

static int jt_dbg_modules_2_4(int argc, char **argv)
{
#ifdef HAVE_LINUX_VERSION_H
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        struct mod_paths *mp;
        char *path = "";
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
                        printf("add-symbol-file %s%s%s/%s.o 0x%0lx\n", path,
                               path[0] ? "/" : "", mp->path, mp->name,
                               info.addr + sizeof(struct module));
                }
        }

        return 0;
#endif // Headers are 2.6-only
#endif // !HAVE_LINUX_VERSION_H
        return -EINVAL;
}

static int jt_dbg_modules_2_5(int argc, char **argv)
{
        struct mod_paths *mp;
        char *path = "";
        char *kernel = "linux";
        const char *proc = "/proc/modules";
        char modname[128], others[4096];
        long modaddr;
        int rc;
        FILE *file;

        if (argc >= 2)
                path = argv[1];
        if (argc == 3)
                kernel = argv[2];
        if (argc > 3) {
                printf("%s [path] [kernel]\n", argv[0]);
                return 0;
        }

        file = fopen(proc, "r");
        if (!file) {
                printf("failed open %s: %s\n", proc, strerror(errno));
                return 0;
        }

        while ((rc = fscanf(file, "%s %s %s %s %s %lx\n",
                modname, others, others, others, others, &modaddr)) == 6) {
                for (mp = mod_paths; mp->name != NULL; mp++) {
                        if (!strcmp(mp->name, modname))
                                break;
                }
                if (mp->name) {
                        printf("add-symbol-file %s%s%s/%s.o 0x%0lx\n", path,
                               path[0] ? "/" : "", mp->path, mp->name, modaddr);
                }
        }

        fclose(file);
        return 0;
}

int jt_dbg_modules(int argc, char **argv)
{
        int rc = 0;
        struct utsname sysinfo;

        rc = uname(&sysinfo);
        if (rc) {
                printf("uname() failed: %s\n", strerror(errno));
                return 0;
        }

        if (sysinfo.release[2] > '4') {
                return jt_dbg_modules_2_5(argc, argv);
        } else {
                return jt_dbg_modules_2_4(argc, argv);
        }

        return 0;
}

int jt_dbg_panic(int argc, char **argv)
{
        int rc;
        struct libcfs_ioctl_data data;

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", argv[0]);
                return 0;
        }

        memset(&data, 0, sizeof(data));
        if (libcfs_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "libcfs_ioctl_pack failed.\n");
                return -1;
        }

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_PANIC, buf);
        if (rc) {
                fprintf(stderr, "IOC_LIBCFS_PANIC failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}
