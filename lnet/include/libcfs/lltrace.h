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
 * Compile with:
 * cc -I../../portals/include -o fio fio.c -L../../portals/linux/utils -lptlctl
 */

#ifndef __LIBCFS_LLTRACE_H__
#define __LIBCFS_LLTRACE_H__

#if defined(__linux__)
#include <libcfs/linux/lltrace.h>
#elif defined(__APPLE__)
#include <libcfs/darwin/lltrace.h>
#elif defined(__WINNT__)
#include <libcfs/winnt/lltrace.h>
#else
#error Unsupported Operating System
#endif

static inline int ltrace_write_file(char* fname)
{
        char* argv[3];

        argv[0] = "debug_kernel";
        argv[1] = fname;
        argv[2] = "1";

        fprintf(stderr, "[ptlctl] %s %s %s\n", argv[0], argv[1], argv[2]);

        return jt_dbg_debug_kernel(3, argv);
}

static inline int ltrace_clear()
{
        char* argv[1];

        argv[0] = "clear";

        fprintf(stderr, "[ptlctl] %s\n", argv[0]);

        return jt_dbg_clear_debug_buf(1, argv);
}

static inline int ltrace_mark(int indent_level, char* text)
{
        char* argv[2];
        char mark_buf[PATH_MAX];

        snprintf(mark_buf, PATH_MAX, "====%d=%s", indent_level, text);

        argv[0] = "mark";
        argv[1] = mark_buf;
        return jt_dbg_mark_debug_buf(2, argv);
}

static inline int ltrace_applymasks()
{
        char* argv[2];
        argv[0] = "list";
        argv[1] = "applymasks";

        fprintf(stderr, "[ptlctl] %s %s\n", argv[0], argv[1]);

        return jt_dbg_list(2, argv);
}


static inline int ltrace_filter(char* subsys_or_mask)
{
        char* argv[2];
        argv[0] = "filter";
        argv[1] = subsys_or_mask;
        return jt_dbg_filter(2, argv);
}

static inline int ltrace_show(char* subsys_or_mask)
{
        char* argv[2];
        argv[0] = "show";
        argv[1] = subsys_or_mask;
        return jt_dbg_show(2, argv);
}

static inline int ltrace_start()
{
        int rc = 0;
        dbg_initialize(0, NULL);
#ifdef LNET_DEV_ID
        rc = register_ioc_dev(LNET_DEV_ID, LNET_DEV_PATH,
                              LNET_DEV_MAJOR, LNET_DEV_MINOR);
#endif
        ltrace_filter("class");
        ltrace_filter("nal");
        ltrace_filter("portals");

        ltrace_show("all_types");
        ltrace_filter("trace");
        ltrace_filter("malloc");
        ltrace_filter("net");
        ltrace_filter("page");
        ltrace_filter("other");
        ltrace_filter("info");
        ltrace_applymasks();

        return rc;
}


static inline void ltrace_stop()
{
#ifdef LNET_DEV_ID
        unregister_ioc_dev(LNET_DEV_ID);
#endif
}

static inline int not_uml()
{
  /* Return Values:
   *   0 when run under UML
   *   1 when run on host
   *  <0 when lookup failed
   */
        struct stat buf;
        int rc = stat("/dev/ubd", &buf);
        rc = ((rc<0) && (errno == ENOENT)) ? 1 : rc;
        if (rc<0) {
          fprintf(stderr, "Cannot stat /dev/ubd: %s\n", strerror(errno));
          rc = 1; /* Assume host */
        }
        return rc;
}

#define LTRACE_MAX_NOB   256
static inline void ltrace_add_processnames(char* fname)
{
        char cmdbuf[LTRACE_MAX_NOB];
        struct timeval tv;
        struct timezone tz;
        int nob;
        int underuml = !not_uml();

        gettimeofday(&tv, &tz);

        nob = snprintf(cmdbuf, LTRACE_MAX_NOB, "ps --no-headers -eo \"");

        /* Careful - these format strings need to match the CDEBUG
         * formats in portals/linux/debug.c EXACTLY
         */
        nob += snprintf(cmdbuf+nob, LTRACE_MAX_NOB, "%02x:%06x:%d:%lu.%06lu ",
                        S_RPC >> 24, D_VFSTRACE, 0, tv.tv_sec, tv.tv_usec);

        if (underuml && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))) {
                nob += snprintf (cmdbuf+nob, LTRACE_MAX_NOB,
                                 "(%s:%d:%s() %d | %d+%lu): ",
                                 "lltrace.h", __LINE__, __FUNCTION__, 0, 0, 0L);
        }
        else {
                nob += snprintf (cmdbuf+nob, LTRACE_MAX_NOB,
                                 "(%s:%d:%s() %d+%lu): ",
                                 "lltrace.h", __LINE__, __FUNCTION__, 0, 0L);
        }

        nob += snprintf(cmdbuf+nob, LTRACE_MAX_NOB, " %%p %%c\" >> %s", fname);
        system(cmdbuf);
}

#endif
