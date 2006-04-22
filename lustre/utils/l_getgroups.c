/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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

#include <lustre/lustre_user.h>

static char *progname;

void usage(FILE *out)
{
        fprintf(out, "\nusage: %s {-d | mdsname} {uid}\n"
                     "Normally invoked as an upcall from Lustre, set via:\n"
                     "  /proc/fs/lustre/mds/{mdsname}/group_upcall\n"
                     "\t-d: debug, print values to stdout instead of Lustre\n",
                     progname);
}

static int compare_u32(const void *v1, const void *v2)
{
        return (*(__u32 *)v1 - *(__u32 *)v2);
}

static void errlog(const char *fmt, ...)
{
        va_list arg;

        openlog(progname, LOG_PERROR, LOG_AUTHPRIV);

        va_start(arg, fmt);
        vsyslog(LOG_NOTICE, fmt, arg);
        va_end(arg);

        closelog();
}

int get_groups_local(struct mds_grp_downcall_data **grp)
{
        struct mds_grp_downcall_data *param;
        int i, maxgroups, size;
        struct passwd *pw;
        struct group  *gr;

        pw = getpwuid((*grp)->mgd_uid);
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
        endgrent();
        qsort(param->mgd_groups, param->mgd_ngroups,
              sizeof(param->mgd_groups[0]), compare_u32);

        return size;
}

/* Note that we need to make the downcall regardless of error, so that the
 * MDS doesn't continue to wait on the upcall. */
int main(int argc, char **argv)
{
        int fd, rc, size, debug = 0;
        struct mds_grp_downcall_data sparam = { MDS_GRP_DOWNCALL_MAGIC };
        struct mds_grp_downcall_data *param = &sparam;
        char pathname[1024], *end;

        progname = strrchr(argv[0], '/');
        if (progname == NULL)
                progname = argv[0];
        else
                progname++;

        if (argc != 3) {
                fprintf(stderr, "%s: bad parameter count\n", progname);
                usage(stderr);
                return EINVAL;
        }

        if (strcmp(argv[1], "-d") == 0)
                debug = 1;

        param->mgd_uid = strtoul(argv[2], &end, 0);
        if (*end) {
                fprintf(stderr, "%s: invalid uid '%s'\n", progname, argv[2]);
                usage(stderr);
                return EINVAL;
        }

        size = get_groups_local(&param);
        if (debug) {
                int i;
                if (param->mgd_err) {
                        if (param->mgd_err != ENXIO)
                                fprintf(stderr,
                                        "%s: error getting uid %d groups: %s\n",
                                        progname, param->mgd_uid,
                                        strerror(param->mgd_err));
                        rc = param->mgd_err;
                } else {
                        printf("uid=%d gid=", param->mgd_uid);
                        for (i = 0; i < param->mgd_ngroups; i++)
                                printf("%s%d", i > 0 ? "," : "",
                                       param->mgd_groups[i]);
                        printf("\n");
                        rc = 0;
                }
        } else {
                snprintf(pathname, 1024, "/proc/fs/lustre/mds/%s/group_info",
                         argv[1]);
                fd = open(pathname, O_WRONLY);
                if (fd < 0) {
                        fprintf(stderr, "%s: can't open device %s: %s\n",
                                progname, pathname, strerror(errno));
                        rc = errno;
                } else {
                        rc = write(fd, param, size);
                        if (rc > 0)
                                rc = 0;

                        close(fd);
                }
        }
        return rc;
}
