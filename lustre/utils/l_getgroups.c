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
#include <lustre/lustre_user.h>

int get_groups_local(struct mds_grp_downcall_data **grp)
{
        struct mds_grp_downcall_data *param;
        int i, maxgroups, size;
        struct passwd *pw;
        struct group  *gr;

        pw = getpwuid((*grp)->mgd_uid);
        if (!pw) {
                (*grp)->mgd_err = -errno;
                return sizeof(*param);
        }

        maxgroups = sysconf(_SC_NGROUPS_MAX);
        size = offsetof(struct mds_grp_downcall_data, mgd_groups[maxgroups]);
        param = malloc(size);
        if (param == NULL) {
                (*grp)->mgd_err = -ENOMEM;
                return sizeof(*param);
        }

        memcpy(param, *grp, sizeof(*param));
        *grp = param;
        while ((gr = getgrent())) {
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

        return size;
}

/* Note that we need to make the downcall regardless of error, so that the
 * MDS doesn't continue to wait on the upcall. */
int main(int argc, char **argv)
{
        int fd, rc, size;
        struct mds_grp_downcall_data sparam = { MDS_GRP_DOWNCALL_MAGIC };
        struct mds_grp_downcall_data *param = &sparam;
        char pathname[1024];

        if (argc != 3) {
                printf("bad parameter\n");
                return -1;
        }

        snprintf(pathname, 1024, "/proc/fs/lustre/mds/%s/group_info", argv[1]);
        param->mgd_uid = atoi(argv[2]);

        fd = open(pathname, O_WRONLY);
        if (fd < 0) {
                printf("can't open device %s\n", pathname);
                return -1;
        }

        size = get_groups_local(&param);

        rc = write(fd, param, size);

        close(fd);
        return rc;
}
