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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/posix/posix_debug.c
 *
 * Userspace debugging.
 *
 */

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

static char debug_file_name[1024];

#ifdef HAVE_CATAMOUNT_DATA_H
#include <catamount/data.h>
#include <catamount/lputs.h>

static char source_nid[16];
/* 0 indicates no messages to console, 1 is errors, > 1 is all debug messages */
static int toconsole = 1;
unsigned int libcfs_console_ratelimit = 1;
unsigned int libcfs_console_max_delay;
unsigned int libcfs_console_min_delay;
unsigned int libcfs_console_backoff = CDEBUG_DEFAULT_BACKOFF;
#else /* !HAVE_CATAMOUNT_DATA_H */
#ifdef HAVE_NETDB_H
#include <sys/utsname.h>
#endif /* HAVE_NETDB_H */
struct utsname *tmp_utsname;
static char source_nid[sizeof(tmp_utsname->nodename)];
#endif /* HAVE_CATAMOUNT_DATA_H */

static int source_pid;
int cfs_smp_processor_id = 1;
char libcfs_debug_file_path[1024];
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
                strncpy(libcfs_debug_file_path, debug_filename,
                        sizeof(libcfs_debug_file_path));

        debug_filename = getenv("LIBLUSTRE_DEBUG_FILE");
        if (debug_filename)
                strncpy(debug_file_name,debug_filename,sizeof(debug_file_name));

        if (debug_file_name[0] == '\0' && libcfs_debug_file_path[0] != '\0')
                snprintf(debug_file_name, sizeof(debug_file_name) - 1,
                         "%s-%s-"CFS_TIME_T".log", libcfs_debug_file_path,
                         source_nid, time(0));

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

int libcfs_debug_mark_buffer(const char *text)
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

int libcfs_debug_msg(struct libcfs_debug_msg_data *msgdata,
                     const char *format, ...)
{
        va_list args;
        int     rc;

        va_start(args, format);
        rc = libcfs_debug_vmsg2(msgdata, format, args, NULL);
        va_end(args);

        return rc;
}

int
libcfs_debug_vmsg2(struct libcfs_debug_msg_data *msgdata,
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
        if (((msgdata->msg_mask & libcfs_printk) && toconsole == 1) || toconsole > 1)
                console = 1;
#endif

        if ((!console) && (!debug_file_fd)) {
                return 0;
        }

        if (msgdata->msg_mask & (D_EMERG | D_ERROR))
               prefix = "LustreError";

        nob = snprintf(buf, sizeof(buf), "%s: %u-%s:(%s:%d:%s()): ", prefix,
                       source_pid, source_nid, msgdata->msg_file,
                       msgdata->msg_line, msgdata->msg_fn);

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
                cfs_debug_limit_state_t *cdls = msgdata->msg_cdls;

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
                msgdata->msg_file, msgdata->msg_line, msgdata->msg_fn, buf);

        return 0;
}

void
libcfs_assertion_failed(const char *expr, struct libcfs_debug_msg_data *msgdata)
{
        libcfs_debug_msg(msgdata, "ASSERTION(%s) failed\n", expr);
        abort();
}

/*
 * a helper function for RETURN(): the sole purpose is to save 8-16 bytes
 * on the stack - function calling RETURN() doesn't need to allocate two
 * additional 'rc' on the stack
 */
long libcfs_log_return(struct libcfs_debug_msg_data *msgdata, long rc)
{
        libcfs_debug_msg(msgdata, "Process leaving (rc=%lu : %ld : %lx)\n",
                         rc, rc, rc);
        return rc;
}

/*
 * a helper function for GOTO(): the sole purpose is to save 8-16 bytes
 * on the stack - function calling GOTO() doesn't need to allocate two
 * additional 'rc' on the stack
 */
void libcfs_log_goto(struct libcfs_debug_msg_data *msgdata, const char *l,
                     long_ptr_t rc)
{
        libcfs_debug_msg(msgdata, "Process leaving via %s (rc=" LPLU " : "
                         LPLD " : " LPLX ")\n", l, (ulong_ptr_t) rc, rc, rc);
}
