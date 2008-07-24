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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <stddef.h>
#include <syslog.h>
#include <sys/mman.h>
#include <time.h>

#include <lustre/lustre_user.h>

#define CHECK_DURATION_START                                            \
do {                                                                    \
        time_t __check_start = time(NULL)

#define CHECK_DURATION_END(str, secs)                                   \
        if (time(NULL) > __check_start + (secs))                        \
                errlog("LONG OP %s: %d elapsed, %d expected\n", str,    \
                       time(NULL) - __check_start, secs);               \
} while (0)

void usage(FILE *out, const char *progname)
{
        fprintf(out, "\nusage: %s [-v] {-d | <mdsname>} <uid>\n"
                     "usage: %s [-v] -s\n"
                     "Normally invoked as an upcall from Lustre, set via:\n"
                     "  /proc/fs/lustre/mds/{mdsname}/group_upcall\n"
                     "\t-d: debug, print values to stdout instead of Lustre\n"
                     "\t-s: sleep, mlock memory in core and sleep forever\n"
                     "\t-v: verbose, log start/stop to syslog\n",
                     progname, progname);
}

static int compare_u32(const void *v1, const void *v2)
{
        return (*(__u32 *)v1 - *(__u32 *)v2);
}

static void errlog(const char *fmt, ...)
{
        va_list arg, carg;

        va_start(arg, fmt);
        va_copy(carg, arg);
        vsyslog(LOG_NOTICE, fmt, arg);
        va_end(arg);

        vfprintf(stderr, fmt, carg);
        va_end(carg);
}

int get_groups_local(struct mds_grp_downcall_data **grp)
{
        struct mds_grp_downcall_data *param;
        int i, maxgroups, size;
        struct passwd *pw;
        struct group  *gr;

        CHECK_DURATION_START;
        pw = getpwuid((*grp)->mgd_uid);
        CHECK_DURATION_END("getpwuid", 2);
        if (!pw) {
                errlog("no such user %u\n", (*grp)->mgd_uid);
                (*grp)->mgd_err = errno ? errno : EIDRM;
                return sizeof(*param);
        }
        (*grp)->mgd_gid = pw->pw_gid;

        maxgroups = sysconf(_SC_NGROUPS_MAX);
        size = offsetof(struct mds_grp_downcall_data, mgd_groups[maxgroups]);
        param = malloc(size);
        if (param == NULL) {
                errlog("fail to alloc %d bytes for uid %u with %d groups\n",
                       size, (*grp)->mgd_uid, maxgroups);
                return sizeof(*param);
        }

        memcpy(param, *grp, sizeof(*param));
        param->mgd_groups[param->mgd_ngroups++] = pw->pw_gid;
        *grp = param;
        CHECK_DURATION_START;
        while ((gr = getgrent())) {
                if (gr->gr_gid == pw->pw_gid)
                        continue;
                if (!gr->gr_mem)
                        continue;
                for (i = 0; gr->gr_mem[i]; i++) {
                        if (strcmp(gr->gr_mem[i], pw->pw_name) == 0) {
                                param->mgd_groups[param->mgd_ngroups++] =
                                        gr->gr_gid;
                                break;
                        }
                }
                if (param->mgd_ngroups == maxgroups)
                        break;
        }
        CHECK_DURATION_END("getgrent loop", 3);
        endgrent();
        qsort(param->mgd_groups, param->mgd_ngroups,
              sizeof(param->mgd_groups[0]), compare_u32);

        return size;
}

/* Note that we need to make the downcall regardless of error, so that the
 * MDS doesn't continue to wait on the upcall. */
int main(int argc, char **argv)
{
        int fd, rc, c, size;
        int debug = 0, sleepy = 0, verbose = 0, print_usage = 0;
        pid_t mypid;
        struct mds_grp_downcall_data sparam = { MDS_GRP_DOWNCALL_MAGIC };
        struct mds_grp_downcall_data *param = &sparam;
        char pathname[1024], *end, *progname, *mdsname = NULL;

        progname = strrchr(argv[0], '/');
        if (progname == NULL)
                progname = argv[0];
        else
                progname++;

        if (strstr(progname, "verbose"))
                verbose++;

        openlog(progname, LOG_PERROR, LOG_AUTHPRIV);

        opterr = 0;
        while ((c = getopt(argc, argv, "dhsv")) != -1) {
                switch (c) {
                case 'd':
                        debug++;
                        break;
                case 's':
                        sleepy++;
                        break;
                case 'v':
                        verbose++;
                        break;
                default:
                        errlog("bad parameter '%c'\n", optopt);
                        print_usage++;
                case 'h':
                        print_usage++;
                        break;
                }
        }

        /* sleep has 0 param, debug has 1 param, upcall has 2 param */
        if (!sleepy && optind + !sleepy + !debug != argc)
                print_usage++;

        if (print_usage) {
                usage(stderr, progname);
                return print_usage > 1 ? EINVAL : 0;
        }

        if (!sleepy) {
                param->mgd_uid = strtoul(argv[optind + !debug], &end, 0);
                if (*end) {
                        errlog("invalid uid '%s'", argv[optind + !debug]);
                        usage(stderr, progname);
                        return EINVAL;
                }
                if (!debug)
                        mdsname = argv[optind];
        }

        mypid = getpid();

        if (verbose)
                syslog(LOG_DEBUG, "starting l_getgroups(pid %u) for uid %u\n",
                       mypid, param->mgd_uid);

        CHECK_DURATION_START;
        size = get_groups_local(&param);
        CHECK_DURATION_END("get_groups_local", 10);
        if (debug) {
                int i;
                if (param->mgd_err) {
                        if (param->mgd_err != ENXIO)
                                errlog("error getting uid %d groups: %s\n",
                                       param->mgd_uid,strerror(param->mgd_err));
                        rc = param->mgd_err;
                } else {
                        printf("uid=%d gid=", param->mgd_uid);
                        for (i = 0; i < param->mgd_ngroups; i++)
                                printf("%s%d", i > 0 ? "," : "",
                                       param->mgd_groups[i]);
                        printf("\n");
                        rc = 0;
                }
        } else if (sleepy) {
                rc = mlockall(MCL_CURRENT);
                errlog("%s all pages in RAM (pid %u): rc %d\n",
                       rc ? "failed to lock" : "locked", mypid, rc);
                sleep(1000000000);
        } else {
                snprintf(pathname, 1024, "/proc/fs/lustre/mds/%s/group_info",
                         mdsname);
                CHECK_DURATION_START;
                fd = open(pathname, O_WRONLY);
                if (fd < 0) {
                        errlog("can't open device %s: %s\n",
                               pathname, strerror(errno));
                        rc = errno;
                } else {
                        rc = write(fd, param, size);
                        if (rc > 0)
                                rc = 0;

                        close(fd);
                }
                CHECK_DURATION_END("group_info write", 1);
        }
        if (verbose)
                syslog(LOG_DEBUG, "ending l_getgroups(pid %u) for uid %u\n",
                       mypid, param->mgd_uid);

        closelog();
        return rc;
}
