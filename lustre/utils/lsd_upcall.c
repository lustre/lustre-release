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
#include <syslog.h>

#include <liblustre.h>
#include <linux/lustre_idl.h>
#include <linux/obd.h>
#include <linux/lustre_mds.h>

#include <portals/types.h>
#include <portals/ptlctl.h>

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
                return -ENOENT;

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

#define LINEBUF_SIZE    (1024)
static char linebuf[LINEBUF_SIZE];

int readline(FILE *fp, char *buf, int bufsize)
{
        char *p = buf;
        int i = 0;

        if (fgets(buf, bufsize, fp) == NULL)
                return -1;

        while (*p) {
                if (*p == '#') {
                        *p = '\0';
                        break;
                }
                if (*p == '\n') {
                        *p = '\0';
                        break;
                }
                i++;
                p++;
        }

        return i;
}

#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')

void remove_space_head(char **buf)
{
        char *p = *buf;

        while (IS_SPACE(*p))
                p++;

        *buf = p;
}

void remove_space_tail(char **buf)
{
        char *p = *buf;
        char *spc = NULL;

        while (*p) {
                if (!IS_SPACE(*p)) {
                        if (spc) spc = NULL;
                } else
                        if (!spc) spc = p;
                p++;
        }

        if (spc)
                *spc = '\0';
}

int get_next_uid_range(char **buf, uid_t *uid_range)
{
        char *p = *buf;
        char *comma, *sub;

        remove_space_head(&p);
        if (strlen(p) == 0)
                return -1;

        comma = strchr(p, ',');
        if (comma) {
                *comma = '\0';
                *buf = comma + 1;
        } else
                *buf = p + strlen(p);

        sub = strchr(p, '-');
        if (!sub) {
                uid_range[0] = uid_range[1] = atoi(p);
        } else {
                *sub++ = '\0';
                uid_range[0] = atoi(p);
                uid_range[1] = atoi(sub);
        }

        return 0;
}

/*
 * return 0: ok
 */
int remove_bracket(char **buf)
{
        char *p = *buf;
        char *p2;

        if (*p++ != '[')
                return -1;

        p2 = strchr(p, ']');
        if (!p2)
                return -1;

        *p2++ = '\0';
        while (*p2) {
                if (*p2 != ' ' && *p2 != '\t')
                        return -1;
                p2++;
        }

        remove_space_tail(&p);
        *buf = p;
        return 0;
}

/* return 0: found a match */
int search_uid(FILE *fp, uid_t uid)
{
        char *p;
        uid_t uid_range[2];
        int rc;

        while (1) {
                rc = readline(fp, linebuf, LINEBUF_SIZE);
                if (rc < 0)
                        return rc;
                if (rc == 0)
                        continue;

                p = linebuf;
                if (remove_bracket(&p))
                        continue;

                while (get_next_uid_range(&p, uid_range) == 0) {
                        if (uid >= uid_range[0] && uid <= uid_range[1]) {
                                return 0;
                        }
                }
                continue;
        }
}

static struct {
        char   *name;
        __u32   bit;
} perm_types[] =  {
        {"setuid",      LSD_PERM_SETUID},
        {"setgid",      LSD_PERM_SETGID},
        {"setgrp",      LSD_PERM_SETGRP},
};
#define N_PERM_TYPES    (3)

int parse_perm(__u32 *perm, char *str)
{
        char *p = str;
        char *comma;
        int i;

        *perm = 0;

        while (1) {
                p = str;
                comma = strchr(str, ',');
                if (comma) {
                        *comma = '\0';
                        str = comma + 1;
                }

                for (i = 0; i < N_PERM_TYPES; i++) {
                        if (!strcasecmp(p, perm_types[i].name)) {
                                *perm |= perm_types[i].bit;
                                break;
                        }
                }

                if (i >= N_PERM_TYPES) {
                        printf("unkown perm type: %s\n", p);
                        return -1;
                }

                if (!comma)
                        break;
        }
        return 0;
}

int parse_nid(ptl_nid_t *nidp, char *nid_str)
{
        if (!strcmp(nid_str, "*")) {
                *nidp = PTL_NID_ANY;
                return 0;
        }

        return ptl_parse_nid(nidp, nid_str);
}

int get_one_perm(FILE *fp, struct lsd_permission *perm)
{
        char nid_str[256], perm_str[256];
        int rc;

again:
        rc = readline(fp, linebuf, LINEBUF_SIZE);
        if (rc < 0)
                return rc;
        if (rc == 0)
                goto again;

        rc = sscanf(linebuf, "%s %s", nid_str, perm_str);
        if (rc != 2)
                return -1;

        if (parse_nid(&perm->nid, nid_str))
                return -1;

        if (parse_perm(&perm->perm, perm_str))
                return -1;

        perm->netid = 0;
        return 0;
}

#define MAX_PERMS       (50)

int get_perms(FILE *fp, uid_t uid, int *nperms, struct lsd_permission **perms)
{
        static struct lsd_permission _perms[MAX_PERMS];

        if (search_uid(fp, uid))
                return -1;

        *nperms = 0;
        while (*nperms < MAX_PERMS) {
                if (get_one_perm(fp, &_perms[*nperms]))
                        break;
                (*nperms)++;
        }
        *perms = _perms;
        return 0;
}

void show_result(struct lsd_downcall_args *dc)
{
        int i;

        printf("err: %d, uid %u, gid %d\n"
               "ngroups: %d\n",
               dc->err, dc->uid, dc->gid, dc->ngroups);
        for (i = 0; i < dc->ngroups; i++)
                printf("\t%d\n", dc->groups[i]);

        printf("nperms: %d\n", dc->nperms);
        for (i = 0; i < dc->nperms; i++)
                printf("\t: netid %u, nid "LPX64", bits %x\n", i,
                        dc->perms[i].nid, dc->perms[i].perm);
}

#define log_msg(testing, fmt, args...)                  \
        {                                               \
                if (testing)                            \
                        printf(fmt, ## args);           \
                else                                    \
                        syslog(LOG_ERR, fmt, ## args);  \
        }

void usage(char *prog)
{
        printf("Usage: %s [-t] uid\n", prog);
        exit(1);
}

int main (int argc, char **argv)
{
        char   *dc_name = "/proc/fs/lustre/mds/lsd_downcall";
        int     dc_fd;
        char   *conf_name = "/etc/lustre/lsd.conf";
        FILE   *conf_fp;
        struct lsd_downcall_args ioc_data;
        extern char *optarg;
        int     opt, testing = 0, rc;

        while ((opt = getopt(argc, argv, "t")) != -1) {
                switch (opt) {
                case 't':
                        testing = 1;
                        break;
                default:
                        usage(argv[0]);
                }
        }

        if (optind >= argc)
                usage(argv[0]);

        memset(&ioc_data, 0, sizeof(ioc_data));
        ioc_data.uid = atoi(argv[optind]);

        /* read user/group database */
        ioc_data.err = get_groups_local(ioc_data.uid, &ioc_data.gid,
                                        (int *)&ioc_data.ngroups,
                                        &ioc_data.groups);
        if (ioc_data.err)
                goto do_downcall;

        /* read lsd config database */
        conf_fp = fopen(conf_name, "r");
        if (conf_fp) {
                get_perms(conf_fp, ioc_data.uid,
                          (int *)&ioc_data.nperms,
                          &ioc_data.perms);
                fclose(conf_fp);
        }


do_downcall:
        if (testing) {
                show_result(&ioc_data);
                return 0;
        } else {
                dc_fd = open(dc_name, O_WRONLY);
                if (dc_fd < 0) {
                        log_msg(testing, "can't open device %s: %s\n",
                                dc_name, strerror(errno));

                        return -errno;
                }

                rc = write(dc_fd, &ioc_data, sizeof(ioc_data));
                if (rc != sizeof(ioc_data)) {
                        log_msg(testing, "partial write ret %d: %s\n",
                                rc, strerror(errno));
                }

                return (rc != sizeof(ioc_data));
        }
}
