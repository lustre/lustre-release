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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/libcfs/debug.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

# define DEBUG_SUBSYSTEM S_LNET

#include <stdarg.h>
#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>
#include "tracefile.h"

static char debug_file_name[1024];

#ifdef __KERNEL__
unsigned int libcfs_subsystem_debug = ~0;
CFS_MODULE_PARM(libcfs_subsystem_debug, "i", int, 0644,
                "Lustre kernel debug subsystem mask");
EXPORT_SYMBOL(libcfs_subsystem_debug);

unsigned int libcfs_debug = (D_EMERG | D_ERROR | D_WARNING | D_CONSOLE |
                             D_NETERROR | D_HA | D_CONFIG | D_IOCTL);
CFS_MODULE_PARM(libcfs_debug, "i", int, 0644,
                "Lustre kernel debug mask");
EXPORT_SYMBOL(libcfs_debug);

int libcfs_debug_mb = -1;
CFS_MODULE_PARM(libcfs_debug_mb, "i", int, 0644,
                "Total debug buffer size.");
EXPORT_SYMBOL(libcfs_debug_mb);

unsigned int libcfs_printk = D_CANTMASK;
CFS_MODULE_PARM(libcfs_printk, "i", uint, 0644,
                "Lustre kernel debug console mask");
EXPORT_SYMBOL(libcfs_printk);

unsigned int libcfs_console_ratelimit = 1;
CFS_MODULE_PARM(libcfs_console_ratelimit, "i", uint, 0644,
                "Lustre kernel debug console ratelimit (0 to disable)");
EXPORT_SYMBOL(libcfs_console_ratelimit);

cfs_duration_t libcfs_console_max_delay;
CFS_MODULE_PARM(libcfs_console_max_delay, "l", ulong, 0644,
                "Lustre kernel debug console max delay (jiffies)");
EXPORT_SYMBOL(libcfs_console_max_delay);

cfs_duration_t libcfs_console_min_delay;
CFS_MODULE_PARM(libcfs_console_min_delay, "l", ulong, 0644,
                "Lustre kernel debug console min delay (jiffies)");
EXPORT_SYMBOL(libcfs_console_min_delay);

unsigned int libcfs_console_backoff = CDEBUG_DEFAULT_BACKOFF;
CFS_MODULE_PARM(libcfs_console_backoff, "i", uint, 0644,
                "Lustre kernel debug console backoff factor");
EXPORT_SYMBOL(libcfs_console_backoff);

unsigned int libcfs_debug_binary = 1;
EXPORT_SYMBOL(libcfs_debug_binary);

unsigned int libcfs_stack;
EXPORT_SYMBOL(libcfs_stack);

unsigned int portal_enter_debugger;
EXPORT_SYMBOL(portal_enter_debugger);

unsigned int libcfs_catastrophe;
EXPORT_SYMBOL(libcfs_catastrophe);

unsigned int libcfs_panic_on_lbug = 0;
CFS_MODULE_PARM(libcfs_panic_on_lbug, "i", uint, 0644,
                "Lustre kernel panic on LBUG");
EXPORT_SYMBOL(libcfs_panic_on_lbug);

atomic_t libcfs_kmemory = ATOMIC_INIT(0);
EXPORT_SYMBOL(libcfs_kmemory);

static cfs_waitq_t debug_ctlwq;

#ifdef HAVE_BGL_SUPPORT
char debug_file_path_arr[1024] = "/bgl/ion/tmp/lustre-log";
#elif defined(__arch_um__)
char debug_file_path_arr[1024] = "/r/tmp/lustre-log";
#else
char debug_file_path_arr[1024] = "/tmp/lustre-log";
#endif
/* We need to pass a pointer here, but elsewhere this must be a const */
static char *debug_file_path = &debug_file_path_arr[0];
CFS_MODULE_PARM(debug_file_path, "s", charp, 0644,
                "Path for dumping debug logs, "
                "set 'NONE' to prevent log dumping");

int libcfs_panic_in_progress;

/* libcfs_debug_token2mask() expects the returned
 * string in lower-case */
const char *
libcfs_debug_subsys2str(int subsys)
{
        switch (subsys) {
        default:
                return NULL;
        case S_UNDEFINED:
                return "undefined";
        case S_MDC:
                return "mdc";
        case S_MDS:
                return "mds";
        case S_OSC:
                return "osc";
        case S_OST:
                return "ost";
        case S_CLASS:
                return "class";
        case S_LOG:
                return "log";
        case S_LLITE:
                return "llite";
        case S_RPC:
                return "rpc";
        case S_LNET:
                return "lnet";
        case S_LND:
                return "lnd";
        case S_PINGER:
                return "pinger";
        case S_FILTER:
                return "filter";
        case S_ECHO:
                return "echo";
        case S_LDLM:
                return "ldlm";
        case S_LOV:
                return "lov";
        case S_LQUOTA:
                return "lquota";
        case S_LMV:
                return "lmv";
        case S_SEC:
                return "sec";
        case S_GSS:
                return "gss";
        case S_MGC:
                return "mgc";
        case S_MGS:
                return "mgs";
        case S_FID:
                return "fid";
        case S_FLD:
                return "fld";
        }
}

/* libcfs_debug_token2mask() expects the returned
 * string in lower-case */
const char *
libcfs_debug_dbg2str(int debug)
{
        switch (debug) {
        default:
                return NULL;
        case D_TRACE:
                return "trace";
        case D_INODE:
                return "inode";
        case D_SUPER:
                return "super";
        case D_EXT2:
                return "ext2";
        case D_MALLOC:
                return "malloc";
        case D_CACHE:
                return "cache";
        case D_INFO:
                return "info";
        case D_IOCTL:
                return "ioctl";
        case D_NETERROR:
                return "neterror";
        case D_NET:
                return "net";
        case D_WARNING:
                return "warning";
        case D_BUFFS:
                return "buffs";
        case D_OTHER:
                return "other";
        case D_DENTRY:
                return "dentry";
        case D_NETTRACE:
                return "nettrace";
        case D_PAGE:
                return "page";
        case D_DLMTRACE:
                return "dlmtrace";
        case D_ERROR:
                return "error";
        case D_EMERG:
                return "emerg";
        case D_HA:
                return "ha";
        case D_RPCTRACE:
                return "rpctrace";
        case D_VFSTRACE:
                return "vfstrace";
        case D_READA:
                return "reada";
        case D_MMAP:
                return "mmap";
        case D_CONFIG:
                return "config";
        case D_CONSOLE:
                return "console";
        case D_QUOTA:
                return "quota";
        case D_SEC:
                return "sec";
        }
}

int
libcfs_debug_mask2str(char *str, int size, int mask, int is_subsys)
{
        const char *(*fn)(int bit) = is_subsys ? libcfs_debug_subsys2str :
                                                 libcfs_debug_dbg2str;
        int           len = 0;
        const char   *token;
        int           bit;
        int           i;

        if (mask == 0) {                        /* "0" */
                if (size > 0)
                        str[0] = '0';
                len = 1;
        } else {                                /* space-separated tokens */
                for (i = 0; i < 32; i++) {
                        bit = 1 << i;

                        if ((mask & bit) == 0)
                                continue;

                        token = fn(bit);
                        if (token == NULL)              /* unused bit */
                                continue;

                        if (len > 0) {                  /* separator? */
                                if (len < size)
                                        str[len] = ' ';
                                len++;
                        }

                        while (*token != 0) {
                                if (len < size)
                                        str[len] = *token;
                                token++;
                                len++;
                        }
                }
        }

        /* terminate 'str' */
        if (len < size)
                str[len] = 0;
        else
                str[size - 1] = 0;

        return len;
}

int
libcfs_debug_token2mask(int *mask, const char *str, int len, int is_subsys)
{
        const char *(*fn)(int bit) = is_subsys ? libcfs_debug_subsys2str :
                                                 libcfs_debug_dbg2str;
        int           i;
        int           j;
        int           bit;
        const char   *token;

        /* match against known tokens */
        for (i = 0; i < 32; i++) {
                bit = 1 << i;

                token = fn(bit);
                if (token == NULL)              /* unused? */
                        continue;

                /* strcasecmp */
                for (j = 0; ; j++) {
                        if (j == len) {         /* end of token */
                                if (token[j] == 0) {
                                        *mask = bit;
                                        return 0;
                                }
                                break;
                        }

                        if (token[j] == 0)
                                break;

                        if (str[j] == token[j])
                                continue;

                        if (str[j] < 'A' || 'Z' < str[j])
                                break;

                        if (str[j] - 'A' + 'a' != token[j])
                                break;
                }
        }

        return -EINVAL;                         /* no match */
}

int
libcfs_debug_str2mask(int *mask, const char *str, int is_subsys)
{
        int         m = 0;
        char        op = 0;
        int         matched;
        int         n;
        int         t;

        /* Allow a number for backwards compatibility */

        for (n = strlen(str); n > 0; n--)
                if (!isspace(str[n-1]))
                        break;
        matched = n;

        if ((t = sscanf(str, "%i%n", &m, &matched)) >= 1 &&
            matched == n) {
                *mask = m;
                return 0;
        }

        /* <str> must be a list of debug tokens or numbers separated by
         * whitespace and optionally an operator ('+' or '-').  If an operator
         * appears first in <str>, '*mask' is used as the starting point
         * (relative), otherwise 0 is used (absolute).  An operator applies to
         * all following tokens up to the next operator. */

        matched = 0;
        while (*str != 0) {
                while (isspace(*str)) /* skip whitespace */
                        str++;

                if (*str == 0)
                        break;

                if (*str == '+' || *str == '-') {
                        op = *str++;

                        /* op on first token == relative */
                        if (!matched)
                                m = *mask;

                        while (isspace(*str)) /* skip whitespace */
                                str++;

                        if (*str == 0)          /* trailing op */
                                return -EINVAL;
                }

                /* find token length */
                for (n = 0; str[n] != 0 && !isspace(str[n]); n++);

                /* match token */
                if (libcfs_debug_token2mask(&t, str, n, is_subsys) != 0)
                        return -EINVAL;

                matched = 1;
                if (op == '-')
                        m &= ~t;
                else
                        m |= t;

                str += n;
        }

        if (!matched)
                return -EINVAL;

        *mask = m;
        return 0;
}

/**
 * Dump Lustre log to ::debug_file_path by calling tracefile_dump_all_pages()
 */
void libcfs_debug_dumplog_internal(void *arg)
{
        CFS_DECL_JOURNAL_DATA;

        CFS_PUSH_JOURNAL;

        if (strncmp(debug_file_path_arr, "NONE", 4) != 0) {
                snprintf(debug_file_name, sizeof(debug_file_name) - 1,
                         "%s.%ld.%ld", debug_file_path_arr,
                         cfs_time_current_sec(), (long)arg);
                printk(KERN_ALERT "LustreError: dumping log to %s\n",
                       debug_file_name);

                tracefile_dump_all_pages(debug_file_name);
                libcfs_run_debug_log_upcall(debug_file_name);
        }
        CFS_POP_JOURNAL;
}

int libcfs_debug_dumplog_thread(void *arg)
{
        cfs_daemonize("");
        libcfs_debug_dumplog_internal(arg);
        cfs_waitq_signal(&debug_ctlwq);
        return 0;
}

void libcfs_debug_dumplog(void)
{
        int            rc;
        cfs_waitlink_t wait;
        ENTRY;

        /* we're being careful to ensure that the kernel thread is
         * able to set our state to running as it exits before we
         * get to schedule() */
        cfs_waitlink_init(&wait);
        set_current_state(TASK_INTERRUPTIBLE);
        cfs_waitq_add(&debug_ctlwq, &wait);

        rc = cfs_kernel_thread(libcfs_debug_dumplog_thread,
                               (void *)(long)cfs_curproc_pid(),
                               CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0)
                printk(KERN_ERR "LustreError: cannot start log dump thread: "
                       "%d\n", rc);
        else
                cfs_waitq_wait(&wait, CFS_TASK_INTERRUPTIBLE);

        /* be sure to teardown if kernel_thread() failed */
        cfs_waitq_del(&debug_ctlwq, &wait);
        set_current_state(TASK_RUNNING);
}

int libcfs_debug_init(unsigned long bufsize)
{
        int    rc = 0;
        int    max = libcfs_debug_mb;

        cfs_waitq_init(&debug_ctlwq);
        libcfs_console_max_delay = CDEBUG_DEFAULT_MAX_DELAY;
        libcfs_console_min_delay = CDEBUG_DEFAULT_MIN_DELAY;
        /* If libcfs_debug_mb is set to an invalid value or uninitialized
         * then just make the total buffers smp_num_cpus * TCD_MAX_PAGES */
        if (max > trace_max_debug_mb() || max < num_possible_cpus()) {
                max = TCD_MAX_PAGES;
        } else {
                max = (max / num_possible_cpus());
                max = (max << (20 - CFS_PAGE_SHIFT));
        }
        rc = tracefile_init(max);

        if (rc == 0)
                libcfs_register_panic_notifier();

        return rc;
}

int libcfs_debug_cleanup(void)
{
        libcfs_unregister_panic_notifier();
        tracefile_exit();
        return 0;
}

int libcfs_debug_clear_buffer(void)
{
        trace_flush_pages();
        return 0;
}

/* Debug markers, although printed by S_LNET
 * should not be be marked as such. */
#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_UNDEFINED
int libcfs_debug_mark_buffer(const char *text)
{
        CDEBUG(D_TRACE,"***************************************************\n");
        CDEBUG(D_WARNING, "DEBUG MARKER: %s\n", text);
        CDEBUG(D_TRACE,"***************************************************\n");

        return 0;
}
#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_LNET

void libcfs_debug_set_level(unsigned int debug_level)
{
        printk(KERN_WARNING "Lustre: Setting portals debug level to %08x\n",
               debug_level);
        libcfs_debug = debug_level;
}

EXPORT_SYMBOL(libcfs_debug_dumplog);
EXPORT_SYMBOL(libcfs_debug_set_level);


#else /* !__KERNEL__ */

#include <libcfs/libcfs.h>

#ifdef HAVE_CATAMOUNT_DATA_H
#include <catamount/data.h>
#include <catamount/lputs.h>

static char source_nid[16];
/* 0 indicates no messages to console, 1 is errors, > 1 is all debug messages */
static int toconsole = 1;
unsigned int libcfs_console_ratelimit = 1;
cfs_duration_t libcfs_console_max_delay;
cfs_duration_t libcfs_console_min_delay;
unsigned int libcfs_console_backoff = CDEBUG_DEFAULT_BACKOFF;
#else /* !HAVE_CATAMOUNT_DATA_H */
#ifdef HAVE_NETDB_H
#include <sys/utsname.h>
#endif /* HAVE_NETDB_H */
struct utsname *tmp_utsname;
static char source_nid[sizeof(tmp_utsname->nodename)];
#endif /* HAVE_CATAMOUNT_DATA_H */

static int source_pid;
int smp_processor_id = 1;
char debug_file_path[1024];
FILE *debug_file_fd;

int portals_do_debug_dumplog(void *arg)
{
        printf("Look in %s\n", debug_file_name);
        return 0;
}


void portals_debug_print(void)
{
        return;
}


void libcfs_debug_dumplog(void)
{
        printf("Look in %s\n", debug_file_name);
        return;
}

int libcfs_debug_init(unsigned long bufsize)
{
        char *debug_mask = NULL;
        char *debug_subsys = NULL;
        char *debug_filename;

#ifdef HAVE_CATAMOUNT_DATA_H
        char *debug_console = NULL;
        char *debug_ratelimit = NULL;
        char *debug_max_delay = NULL;
        char *debug_min_delay = NULL;
        char *debug_backoff = NULL;

        libcfs_console_max_delay = CDEBUG_DEFAULT_MAX_DELAY;
        libcfs_console_min_delay = CDEBUG_DEFAULT_MIN_DELAY;

        snprintf(source_nid, sizeof(source_nid) - 1, "%u", _my_pnid);
        source_pid = _my_pid;

        debug_console = getenv("LIBLUSTRE_DEBUG_CONSOLE");
        if (debug_console != NULL) {
                toconsole = strtoul(debug_console, NULL, 0);
                CDEBUG(D_INFO, "set liblustre toconsole to %u\n", toconsole);
        }
        debug_ratelimit = getenv("LIBLUSTRE_DEBUG_CONSOLE_RATELIMIT");
        if (debug_ratelimit != NULL) {
                libcfs_console_ratelimit = strtoul(debug_ratelimit, NULL, 0);
                CDEBUG(D_INFO, "set liblustre console ratelimit to %u\n",
                                libcfs_console_ratelimit);
        }
        debug_max_delay = getenv("LIBLUSTRE_DEBUG_CONSOLE_MAX_DELAY");
        if (debug_max_delay != NULL)
                libcfs_console_max_delay =
                            cfs_time_seconds(strtoul(debug_max_delay, NULL, 0));
        debug_min_delay = getenv("LIBLUSTRE_DEBUG_CONSOLE_MIN_DELAY");
        if (debug_min_delay != NULL)
                libcfs_console_min_delay =
                            cfs_time_seconds(strtoul(debug_min_delay, NULL, 0));
        if (debug_min_delay || debug_max_delay) {
                if (!libcfs_console_max_delay || !libcfs_console_min_delay ||
                    libcfs_console_max_delay < libcfs_console_min_delay) {
                        libcfs_console_max_delay = CDEBUG_DEFAULT_MAX_DELAY;
                        libcfs_console_min_delay = CDEBUG_DEFAULT_MIN_DELAY;
                        CDEBUG(D_INFO, "LIBLUSTRE_DEBUG_CONSOLE_MAX_DELAY "
                                       "should be greater than "
                                       "LIBLUSTRE_DEBUG_CONSOLE_MIN_DELAY "
                                       "and both parameters should be non-null"
                                       ": restore default values\n");
                } else {
                        CDEBUG(D_INFO, "set liblustre console max delay to %lus"
                                       " and min delay to %lus\n",
                               (cfs_duration_t)
                                     cfs_duration_sec(libcfs_console_max_delay),
                               (cfs_duration_t)
                                    cfs_duration_sec(libcfs_console_min_delay));
                }
        }
        debug_backoff = getenv("LIBLUSTRE_DEBUG_CONSOLE_BACKOFF");
        if (debug_backoff != NULL) {
                libcfs_console_backoff = strtoul(debug_backoff, NULL, 0);
                if (libcfs_console_backoff <= 0) {
                        libcfs_console_backoff = CDEBUG_DEFAULT_BACKOFF;
                        CDEBUG(D_INFO, "LIBLUSTRE_DEBUG_CONSOLE_BACKOFF <= 0: "
                                       "restore default value\n");
                } else {
                        CDEBUG(D_INFO, "set liblustre console backoff to %u\n",
                               libcfs_console_backoff);
                }
        }
#else
        struct utsname myname;

        if (uname(&myname) == 0)
                strcpy(source_nid, myname.nodename);
        source_pid = getpid();
#endif
        /* debug masks */
        debug_mask = getenv("LIBLUSTRE_DEBUG_MASK");
        if (debug_mask)
                libcfs_debug = (unsigned int) strtol(debug_mask, NULL, 0);

        debug_subsys = getenv("LIBLUSTRE_DEBUG_SUBSYS");
        if (debug_subsys)
                libcfs_subsystem_debug =
                                (unsigned int) strtol(debug_subsys, NULL, 0);

        debug_filename = getenv("LIBLUSTRE_DEBUG_BASE");
        if (debug_filename)
                strncpy(debug_file_path,debug_filename,sizeof(debug_file_path));

        debug_filename = getenv("LIBLUSTRE_DEBUG_FILE");
        if (debug_filename)
                strncpy(debug_file_name,debug_filename,sizeof(debug_file_name));

        if (debug_file_name[0] == '\0' && debug_file_path[0] != '\0')
                snprintf(debug_file_name, sizeof(debug_file_name) - 1,
                         "%s-%s-"CFS_TIME_T".log", debug_file_path, source_nid, time(0));

        if (strcmp(debug_file_name, "stdout") == 0 ||
            strcmp(debug_file_name, "-") == 0) {
                debug_file_fd = stdout;
        } else if (strcmp(debug_file_name, "stderr") == 0) {
                debug_file_fd = stderr;
        } else if (debug_file_name[0] != '\0') {
                debug_file_fd = fopen(debug_file_name, "w");
                if (debug_file_fd == NULL)
                        fprintf(stderr, "%s: unable to open '%s': %s\n",
                                source_nid, debug_file_name, strerror(errno));
        }

        if (debug_file_fd == NULL)
                debug_file_fd = stdout;

        return 0;
}

int libcfs_debug_cleanup(void)
{
        if (debug_file_fd != stdout && debug_file_fd != stderr)
                fclose(debug_file_fd);
        return 0;
}

int libcfs_debug_clear_buffer(void)
{
        return 0;
}

int libcfs_debug_mark_buffer(char *text)
{

        fprintf(debug_file_fd, "*******************************************************************************\n");
        fprintf(debug_file_fd, "DEBUG MARKER: %s\n", text);
        fprintf(debug_file_fd, "*******************************************************************************\n");

        return 0;
}

#ifdef HAVE_CATAMOUNT_DATA_H
#define CATAMOUNT_MAXLINE (256-4)
void catamount_printline(char *buf, size_t size)
{
    char *pos = buf;
    int prsize = size;

    while (prsize > 0){
        lputs(pos);
        pos += CATAMOUNT_MAXLINE;
        prsize -= CATAMOUNT_MAXLINE;
    }
}
#endif

int
libcfs_debug_vmsg2(cfs_debug_limit_state_t *cdls,
                   int subsys, int mask,
                   const char *file, const char *fn, const int line,
                   const char *format1, va_list args,
                   const char *format2, ...)
{
        struct timeval tv;
        int            nob;
        int            remain;
        va_list        ap;
        char           buf[CFS_PAGE_SIZE]; /* size 4096 used for compatimble
                                            * with linux, where message can`t
                                            * be exceed PAGE_SIZE */
        int            console = 0;
        char *prefix = "Lustre";

#ifdef HAVE_CATAMOUNT_DATA_H
        /* toconsole == 0 - all messages to debug_file_fd
         * toconsole == 1 - warnings to console, all to debug_file_fd
         * toconsole >  1 - all debug to console */
        if (((mask & libcfs_printk) && toconsole == 1) || toconsole > 1)
                console = 1;
#endif

        if ((!console) && (!debug_file_fd)) {
                return 0;
        }

        if (mask & (D_EMERG | D_ERROR))
               prefix = "LustreError";

        nob = snprintf(buf, sizeof(buf), "%s: %u-%s:(%s:%d:%s()): ", prefix,
                       source_pid, source_nid, file, line, fn);

        remain = sizeof(buf) - nob;
        if (format1) {
                nob += vsnprintf(&buf[nob], remain, format1, args);
        }

        remain = sizeof(buf) - nob;
        if ((format2) && (remain > 0)) {
                va_start(ap, format2);
                nob += vsnprintf(&buf[nob], remain, format2, ap);
                va_end(ap);
        }

#ifdef HAVE_CATAMOUNT_DATA_H
        if (console) {
                /* check rate limit for console */
                if (cdls != NULL) {
                        if (libcfs_console_ratelimit &&
                                cdls->cdls_next != 0 &&     /* not first time ever */
                                !cfs_time_after(cfs_time_current(), cdls->cdls_next)) {

                                /* skipping a console message */
                                cdls->cdls_count++;
                                goto out_file;
                        }

                        if (cfs_time_after(cfs_time_current(), cdls->cdls_next +
                                           libcfs_console_max_delay +
                                           cfs_time_seconds(10))) {
                                /* last timeout was a long time ago */
                                cdls->cdls_delay /= libcfs_console_backoff * 4;
                        } else {
                                cdls->cdls_delay *= libcfs_console_backoff;

                                if (cdls->cdls_delay <
                                                libcfs_console_min_delay)
                                        cdls->cdls_delay =
                                                libcfs_console_min_delay;
                                else if (cdls->cdls_delay >
                                                libcfs_console_max_delay)
                                        cdls->cdls_delay =
                                                libcfs_console_max_delay;
                        }

                        /* ensure cdls_next is never zero after it's been seen */
                        cdls->cdls_next = (cfs_time_current() + cdls->cdls_delay) | 1;
                }

                if (cdls != NULL && cdls->cdls_count != 0) {
                        char buf2[100];

                        nob = snprintf(buf2, sizeof(buf2),
                                       "Skipped %d previous similar message%s\n",
                                       cdls->cdls_count, (cdls->cdls_count > 1) ? "s" : "");

                        catamount_printline(buf2, nob);
                        cdls->cdls_count = 0;
                        goto out_file;
                }
                catamount_printline(buf, nob);
       }
out_file:
        /* return on toconsole > 1, as we don't want the user getting
        * spammed by the debug data */
        if (toconsole > 1)
                return 0;
#endif
        if (debug_file_fd == NULL)
                return 0;

        gettimeofday(&tv, NULL);

        fprintf(debug_file_fd, CFS_TIME_T".%06lu:%u:%s:(%s:%d:%s()): %s",
                tv.tv_sec, tv.tv_usec, source_pid, source_nid,
                file, line, fn, buf);

        return 0;
}

void
libcfs_assertion_failed(const char *expr, const char *file, const char *func,
                        const int line)
{
        libcfs_debug_msg(NULL, 0, D_EMERG, file, func, line,
                         "ASSERTION(%s) failed\n", expr);
        abort();
}

#endif /* __KERNEL__ */
