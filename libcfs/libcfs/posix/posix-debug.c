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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
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
unsigned int libcfs_subsystem_debug = ~(S_LNET | S_LND);
unsigned int libcfs_debug = 0;

#ifdef HAVE_NETDB_H
#include <sys/utsname.h>
#endif /* HAVE_NETDB_H */
struct utsname *tmp_utsname;
static char source_nid[sizeof(tmp_utsname->nodename)];

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

        struct utsname myname;

        if (uname(&myname) == 0)
                strcpy(source_nid, myname.nodename);
        source_pid = getpid();

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

        if (debug_file_fd == NULL)
                return 0;

        gettimeofday(&tv, NULL);

        fprintf(debug_file_fd, CFS_TIME_T".%06lu:%u:%s:(%s:%d:%s()): %s",
                tv.tv_sec, tv.tv_usec, source_pid, source_nid,
                msgdata->msg_file, msgdata->msg_line, msgdata->msg_fn, buf);

        return 0;
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
