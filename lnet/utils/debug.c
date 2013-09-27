/*
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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/utils/debug.c
 * Some day I'll split all of this functionality into a cfs_debug module
 * of its own. That day is not today.
 */

#define __USE_FILE_OFFSET64
#ifndef _GNU_SOURCE
#define  _GNU_SOURCE
#endif

#include <libcfs/libcfsutil.h>
#include <lnet/lnetctl.h>


static char rawbuf[8192];
static char *buf = rawbuf;
static int max = 8192;
/*static int g_pfd = -1;*/
static int subsystem_mask = ~0;
static int debug_mask = ~0;

#define MAX_MARK_SIZE 256

static const char *libcfs_debug_subsystems[] = LIBCFS_DEBUG_SUBSYS_NAMES;
static const char *libcfs_debug_masks[] = LIBCFS_DEBUG_MASKS_NAMES;

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

#elif defined(__WINNT__)

#define DAEMON_CTL_NAME         "/proc/sys/lnet/daemon_file"
#define SUBSYS_DEBUG_CTL_NAME   "/proc/sys/lnet/subsystem_debug"
#define DEBUG_CTL_NAME          "/proc/sys/lnet/debug"
#define DUMP_KERNEL_CTL_NAME    "/proc/sys/lnet/dump_kernel"

static int
dbg_open_ctlhandle(const char *str)
{
        int fd;
        fd = cfs_proc_open((char *)str, (int)O_WRONLY);
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
        cfs_proc_close(fd);
}

static int
dbg_write_cmd(int fd, char *str, int len)
{
        int    rc  = cfs_proc_write(fd, str, len);

        return (rc == len ? 0 : 1);
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
        }

        dbg_close_ctlhandle(fd);

        return rc;
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
};

static int cmp_rec(const void *p1, const void *p2)
{
        struct dbg_line *d1 = *(struct dbg_line **)p1;
        struct dbg_line *d2 = *(struct dbg_line **)p2;

        if (d1->hdr->ph_sec < d2->hdr->ph_sec)
                return -1;
        if (d1->hdr->ph_sec == d2->hdr->ph_sec &&
            d1->hdr->ph_usec < d2->hdr->ph_usec)
                return -1;
        if (d1->hdr->ph_sec == d2->hdr->ph_sec &&
            d1->hdr->ph_usec == d2->hdr->ph_usec)
                return 0;
        return 1;
}

static void print_rec(struct dbg_line ***linevp, int used, int fdout)
{
        struct dbg_line **linev = *linevp;
        int i;

        qsort(linev, used, sizeof(struct dbg_line *), cmp_rec);
        for (i = 0; i < used; i++) {
                struct dbg_line *line = linev[i];
                struct ptldebug_header *hdr = line->hdr;
                char out[4097];
                char *buf = out;
                int bytes;
                ssize_t bytes_written;

                bytes = sprintf(out, "%08x:%08x:%u.%u%s:%u.%06llu:%u:%u:%u:(%s:%u:%s()) %s",
                                hdr->ph_subsys, hdr->ph_mask,
                                hdr->ph_cpu_id, hdr->ph_type,
                                hdr->ph_flags & PH_FLAG_FIRST_RECORD ? "F" : "",
                                hdr->ph_sec, (unsigned long long)hdr->ph_usec,
                                hdr->ph_stack, hdr->ph_pid, hdr->ph_extern_pid,
                                line->file, hdr->ph_line_num, line->fn, line->text);
                while (bytes > 0) {
                        bytes_written = write(fdout, buf, bytes);
                        if (bytes_written <= 0)
                                break;
                        bytes -= bytes_written;
                        buf += bytes_written;
                }
                free(line->hdr);
                free(line);
        }
        free(linev);
        *linevp = NULL;
}

static int add_rec(struct dbg_line *line, struct dbg_line ***linevp, int *lenp,
                   int used)
{
        struct dbg_line **linev = *linevp;

        if (used == *lenp) {
                int nlen = *lenp + 4096;
                int nsize = nlen * sizeof(struct dbg_line *);

                linev = realloc(*linevp, nsize);
                if (!linev)
                        return -ENOMEM;

                *linevp = linev;
                *lenp = nlen;
        }
        linev[used] = line;

        return 0;
}
  
static void dump_hdr(unsigned long long offset, struct ptldebug_header *hdr)
{
        fprintf(stderr, "badly-formed record at offset = %llu\n", offset);
        fprintf(stderr, "  len = %u\n", hdr->ph_len);
        fprintf(stderr, "  flags = %x\n", hdr->ph_flags);
        fprintf(stderr, "  subsystem = %x\n", hdr->ph_subsys);
        fprintf(stderr, "  mask = %x\n", hdr->ph_mask);
        fprintf(stderr, "  cpu_id = %u\n", hdr->ph_cpu_id);
        fprintf(stderr, "  type = %u\n", hdr->ph_type);
        fprintf(stderr, "  seconds = %u\n", hdr->ph_sec);
        fprintf(stderr, "  microseconds = %lu\n", (long)hdr->ph_usec);
        fprintf(stderr, "  stack = %u\n", hdr->ph_stack);
        fprintf(stderr, "  pid = %u\n", hdr->ph_pid);
        fprintf(stderr, "  host pid = %u\n", hdr->ph_extern_pid);
        fprintf(stderr, "  line number = %u\n", hdr->ph_line_num);
}
 
#define HDR_SIZE sizeof(*hdr)
 
static int parse_buffer(int fdin, int fdout)
{
        struct dbg_line *line;
        struct ptldebug_header *hdr;
        char buf[4097], *ptr;
        unsigned long dropped = 0, kept = 0, bad = 0;
        struct dbg_line **linev = NULL;
        int linev_len = 0;
        int rc;
 
        hdr = (void *)buf;
  
        while (1) {
                int first_bad = 1;
                int count;
 
                count = HDR_SIZE;
                ptr = buf;
        readhdr:
                rc = read(fdin, ptr, count);
                if (rc <= 0)
                         goto print;
  
                ptr += rc;
                count -= rc;
                if (count > 0)
                        goto readhdr;
                
                if (hdr->ph_len > 4094 ||       /* is this header bogus? */
                    hdr->ph_type >= libcfs_tcd_type_max() ||
                    hdr->ph_stack > 65536 ||
                    hdr->ph_sec < (1 << 30) ||
                    hdr->ph_usec > 1000000000 ||
                    hdr->ph_line_num > 65536) {
                        if (first_bad)
                                dump_hdr(lseek(fdin, 0, SEEK_CUR), hdr);
                        bad += first_bad;
                        first_bad = 0;
 
                        /* try to restart on next line */
                        while (count < HDR_SIZE && buf[count] != '\n')
                                count++;
                        if (buf[count] == '\n')
                                count++; /* move past '\n' */
                        if (HDR_SIZE - count > 0) {
                                int left = HDR_SIZE - count;

                                memmove(buf, buf + count, left);
                                ptr = buf + left;

                                goto readhdr;
                        }

                        continue;
                }
  
                if (hdr->ph_len == 0)
                        continue;

                count = hdr->ph_len - HDR_SIZE;
        readmore:
                rc = read(fdin, ptr, count);
                if (rc <= 0)
                        break;
  
                ptr += rc;
                count -= rc;
                if (count > 0)
                        goto readmore;
 
                first_bad = 1;

                if ((hdr->ph_subsys && !(subsystem_mask & hdr->ph_subsys)) ||
                    (hdr->ph_mask && !(debug_mask & hdr->ph_mask))) {
                        dropped++;
                        continue;
                }
  
        retry_alloc:
                line = malloc(sizeof(*line));
                if (line == NULL) {
                         if (linev) {
                                fprintf(stderr, "error: line malloc(%u): "
                                        "printing accumulated records\n",
                                        (unsigned int)sizeof(*line));
                                print_rec(&linev, kept, fdout);

                                goto retry_alloc;
                        }
                        fprintf(stderr, "error: line malloc(%u): exiting\n",
                                (unsigned int)sizeof(*line));
                        break;
                }

                line->hdr = malloc(hdr->ph_len + 1);
                if (line->hdr == NULL) {
                        free(line);
                        if (linev) {
                                fprintf(stderr, "error: hdr malloc(%u): "
                                        "printing accumulated records\n",
                                        hdr->ph_len + 1);
                                print_rec(&linev, kept, fdout);
 
                                goto retry_alloc;
                        }
                        fprintf(stderr, "error: hdr malloc(%u): exiting\n",
                                        hdr->ph_len + 1);
                        break;
                }
  
                ptr = (void *)line->hdr;
                memcpy(line->hdr, buf, hdr->ph_len);
                ptr[hdr->ph_len] = '\0';

                ptr += sizeof(*hdr);
                line->file = ptr;
                ptr += strlen(line->file) + 1;
                line->fn = ptr;
                ptr += strlen(line->fn) + 1;
                line->text = ptr;
 
        retry_add:
                if (add_rec(line, &linev, &linev_len, kept) < 0) {
                        if (linev) {
                                fprintf(stderr, "error: add_rec[%u] failed; "
                                        "print accumulated records\n",
                                        linev_len);
                                print_rec(&linev, kept, fdout);

                                goto retry_add;
                        }
                        fprintf(stderr, "error: add_rec[0] failed; exiting\n");
                        break;
                }
                kept++;
        }

print:
        if (linev)
                print_rec(&linev, kept, fdout);

        printf("Debug log: %lu lines, %lu kept, %lu dropped, %lu bad.\n",
                dropped + kept + bad, kept, dropped, bad);

        return 0;
}

int jt_dbg_debug_kernel(int argc, char **argv)
{
        char filename[4096];
        struct stat st;
        int raw = 0;
        int save_errno;
        int fdin;
        int fdout;
        int rc;

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
	if (argc > 1 && raw) {
		if (strlen(argv[1]) > sizeof(filename)-1) {
			fprintf(stderr, "File name too long: %s\n", argv[1]);
			return 1;
		}
		strncpy(filename, argv[1], sizeof(filename));
	} else {
		if (snprintf(filename, sizeof(filename), "%s"CFS_TIME_T".%u",
			     LIBCFS_DEBUG_FILE_PATH_DEFAULT, time(NULL),
			     getpid()) >=
		    sizeof(filename)) {
			fprintf(stderr, "File name too long\n");
			return 1;
		}
	}

        if (stat(filename, &st) == 0 && S_ISREG(st.st_mode))
                unlink(filename);

        fdin = dbg_open_ctlhandle(DUMP_KERNEL_CTL_NAME);
        if (fdin < 0) {
                fprintf(stderr, "open(dump_kernel) failed: %s\n",
                        strerror(errno));
                return 1;
        }

        rc = dbg_write_cmd(fdin, filename, strlen(filename));
        save_errno = errno;
        dbg_close_ctlhandle(fdin);
        if (rc != 0) {
                fprintf(stderr, "write(%s) failed: %s\n", filename,
                        strerror(save_errno));
                return 1;
        }

        if (raw)
                return 0;

        fdin = open(filename, O_RDONLY);
        if (fdin < 0) {
                if (errno == ENOENT) /* no dump file created */
                        return 0;
                fprintf(stderr, "fopen(%s) failed: %s\n", filename,
                        strerror(errno));
                return 1;
        }
        if (argc > 1) {
                fdout = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC,
                             S_IRUSR | S_IWUSR);
                if (fdout < 0) {
                        fprintf(stderr, "fopen(%s) failed: %s\n", argv[1],
                                strerror(errno));
                        close(fdin);
                        return 1;
                }
        } else {
		fdout = fileno(stdout);
	}

        rc = parse_buffer(fdin, fdout);
        close(fdin);
        if (argc > 1)
                close(fdout);
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
        int    rc;

        if (argc > 3 || argc < 2) {
                fprintf(stderr, "usage: %s <input> [output]\n", argv[0]);
                return 0;
        }

        fdin = open(argv[1], O_RDONLY | O_LARGEFILE);
        if (fdin < 0) {
                fprintf(stderr, "open(%s) failed: %s\n", argv[1],
                        strerror(errno));
                return 1;
        }
        if (argc > 2) {
                fdout = open(argv[2],
                             O_CREAT | O_TRUNC | O_WRONLY | O_LARGEFILE,
                             0600);
                if (fdout < 0) {
                        fprintf(stderr, "open(%s) failed: %s\n", argv[2],
                                strerror(errno));
                        close(fdin);
                        return 1;
                }
        } else {
                fdout = fileno(stdout);
        }

        rc = parse_buffer(fdin, fdout);

        close(fdin);
        if (fdout != fileno(stdout))
                close(fdout);

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
	{ "libcfs", "libcfs/libcfs" },
	{ "lnet", "lnet/lnet" },
	{ "kmxlnd", "lnet/klnds/mxlnd" },
	{ "ko2iblnd", "lnet/klnds/o2iblnd" },
	{ "kptllnd", "lnet/klnds/ptllnd" },
	{ "kgnilnd", "lnet/klnds/gnilnd"},
	{ "kqswlnd", "lnet/klnds/qswlnd" },
	{ "kralnd", "lnet/klnds/ralnd" },
	{ "ksocklnd", "lnet/klnds/socklnd" },
	{ "ktdilnd", "lnet/klnds/tdilnd" },
	{ "obdclass", "lustre/obdclass" },
	{ "llog_test", "lustre/obdclass" },
	{ "ptlrpc_gss", "lustre/ptlrpc/gss" },
	{ "ptlrpc", "lustre/ptlrpc" },
	{ "gks", "lustre/sec/gks" },
	{ "gkc", "lustre/sec/gks" },
	{ "ost", "lustre/ost" },
	{ "osc", "lustre/osc" },
	{ "mds", "lustre/mds" },
	{ "mdc", "lustre/mdc" },
	{ "lustre", "lustre/llite" },
	{ "llite_lloop", "lustre/llite" },
	{ "ldiskfs", "ldiskfs" },
	{ "obdecho", "lustre/obdecho" },
	{ "ldlm", "lustre/ldlm" },
	{ "obdfilter", "lustre/obdfilter" },
	{ "lov", "lustre/lov" },
	{ "lmv", "lustre/lmv" },
	{ "lquota", "lustre/quota" },
	{ "mgs", "lustre/mgs" },
	{ "mgc", "lustre/mgc" },
	{ "mdt", "lustre/mdt" },
	{ "mdd", "lustre/mdd" },
	{ "osd", "lustre/osd" },
	{ "cmm", "lustre/cmm" },
        {"fid", "lustre/fid"},
        {"fld", "lustre/fld"},
	{"lod", "lustre/lod"},
	{"osp", "lustre/osp"},
	{ "lfsck", "lustre/lfsck" },
        {NULL, NULL}
};

int jt_dbg_modules(int argc, char **argv)
{
        struct mod_paths *mp;
        char *path = "";
        const char *proc = "/proc/modules";
        char modname[128], buf[4096];
        long modaddr;
        FILE *file;

        if (argc >= 2)
                path = argv[1];
        if (argc > 3) {
                printf("%s [path] [kernel]\n", argv[0]);
                return 0;
        }

        file = fopen(proc, "r");
        if (!file) {
                printf("failed open %s: %s\n", proc, strerror(errno));
                return 0;
        }

        while (fgets(buf, sizeof(buf), file) != NULL) {
                if (sscanf(buf, "%s %*s %*s %*s %*s %lx", modname, &modaddr) == 2) {
                        for (mp = mod_paths; mp->name != NULL; mp++) {
                                if (!strcmp(mp->name, modname))
                                        break;
                        }
			if (mp->name) {
				printf("add-symbol-file %s%s%s/%s.o 0x%0lx\n",
					path, path[0] ? "/" : "",
					mp->path, mp->name, modaddr);
			}
                }
        }

        fclose(file);
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
