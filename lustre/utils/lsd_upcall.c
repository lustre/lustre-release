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

#include <liblustre.h>
#include <linux/lustre_idl.h>
#include <linux/obd.h>
#include <linux/lustre_mds.h>

/*
 * return:
 *  0:      fail to insert (found identical)
 *  1:      inserted
 */
int insert_sort(gid_t *groups, int size, gid_t grp)
{
        int i;
        gid_t save;

        for (i = 0; i < size; i++) {
                if (groups[i] == grp)
                        return 0;
                if (groups[i] > grp)
                        break;
        }

        for (; i <= size; i++) {
                save = groups[i];
                groups[i] = grp;
                grp = save;
        }
        return 1;
}

int get_groups_local(uid_t uid, gid_t *gid, int *ngroups, gid_t **groups)
{
        int     maxgroups;
        int     i, size = 0;
        struct passwd *pw;
        struct group  *gr;

        *ngroups = 0;
        *groups = NULL;
        maxgroups = sysconf(_SC_NGROUPS_MAX);
        *groups = malloc(maxgroups * sizeof(gid_t));
        if (!*groups)
                return -ENOMEM;

        pw = getpwuid(uid);
        if (!pw)
                return -errno;

        *gid = pw->pw_gid;

        while ((gr = getgrent())) {
                if (!gr->gr_mem)
                        continue;
                for (i = 0; gr->gr_mem[i]; i++) {
                        if (strcmp(gr->gr_mem[i], pw->pw_name))
                                continue;
                        size += insert_sort(*groups, size, gr->gr_gid);
                        break;
                }
                if (size == maxgroups)
                        break;
        }
        endgrent();
        *ngroups = size;
        return 0;
}

int main (int argc, char **argv)
{
        char   *pathname = "/proc/fs/lustre/mds/lsd_downcall";
        int     fd, rc;
        struct lsd_downcall_args ioc_data;

        if (argc != 2) {
                printf("bad parameter\n");
                return -EINVAL;
        }

        ioc_data.uid = atoi(argv[1]);

        fd = open(pathname, O_WRONLY);
        if (fd < 0) {
                rc = -errno;
                printf("can't open device %s\n", pathname);
                return rc;
        }

        ioc_data.err = get_groups_local(ioc_data.uid, &ioc_data.gid,
                                        &ioc_data.ngroups, &ioc_data.groups);

        /* FIXME get these from config file */
        ioc_data.allow_setuid = 1;
        ioc_data.allow_setgid = 1;
        ioc_data.allow_setgrp = 1;

        rc = write(fd, &ioc_data, sizeof(ioc_data));
        return (rc != sizeof(ioc_data));
}
