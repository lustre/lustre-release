/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004-2006 Cluster File Systems, Inc.
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
#include <libgen.h>
#include <syslog.h>

#include <liblustre.h>
#include <lustre/lustre_user.h>
#include <lustre/lustre_idl.h>
#include <libcfs/kp30.h>

#define SETXID_PATHNAME "/etc/lustre/setxid.conf"

/* setxid permission file format is like this:
 * {nid} {uid} {perms}
 * the valid values for perms are setuid/setgid/setgrp, and they can be listed
 * together, seperated by ','.
 */

static char *progname;

static void usage(void)
{
        fprintf(stderr,
                "\nusage: %s {mdtname} {uid}\n"
                "Normally invoked as an upcall from Lustre, set via:\n"
                "  /proc/fs/lustre/mdt/{mdtname}/identity_upcall\n",
                progname);
}

static int compare_u32(const void *v1, const void *v2)
{
        return (*(__u32 *)v1 - *(__u32 *)v2);
}

static void errlog(const char *fmt, ...)
{
        va_list args;

        openlog(progname, LOG_PERROR, LOG_AUTHPRIV);

        va_start(args, fmt);
        vsyslog(LOG_NOTICE, fmt, args);
        fprintf(stderr, fmt, args);
        va_end(args);

        closelog();
}

int get_groups_local(struct identity_downcall_data *data)
{
        int maxgroups;
        gid_t *groups;
        unsigned int ngroups = 0;
        struct passwd *pw;
        struct group *gr;
        char *pw_name;
        int namelen;
        int i;

        pw = getpwuid(data->idd_uid);
        if (!pw) {
                errlog("no such user %u\n", data->idd_uid);
                data->idd_err = errno ? errno : EIDRM;
                return -1;
        }
        data->idd_gid = pw->pw_gid;

        namelen = sysconf(_SC_LOGIN_NAME_MAX);
        if (namelen < _POSIX_LOGIN_NAME_MAX)
                namelen = _POSIX_LOGIN_NAME_MAX;
        pw_name = (char *)malloc(namelen);
        if (!pw_name) {
                errlog("malloc error\n");
                data->idd_err = errno;
                return -1;
        }
        memset(pw_name, 0, namelen);
        strncpy(pw_name, pw->pw_name, namelen - 1);

        maxgroups = sysconf(_SC_NGROUPS_MAX);
        if (maxgroups > NGROUPS_MAX)
                maxgroups = NGROUPS_MAX;
        groups = data->idd_groups;

        groups[ngroups++] = pw->pw_gid;
        while ((gr = getgrent())) {
                if (gr->gr_gid == groups[0])
                        continue;
                if (!gr->gr_mem)
                        continue;
                for (i = 0; gr->gr_mem[i]; i++) {
                        if (!strcmp(gr->gr_mem[i], pw_name)) {
                                groups[ngroups++] = gr->gr_gid;
                                break;
                        }
                }
                if (ngroups == maxgroups)
                        break;
        }
        endgrent();
        qsort(groups, ngroups, sizeof(*groups), compare_u32);
        data->idd_ngroups = ngroups;

        free(pw_name);
        return 0;
}

static inline int comment_line(char *line)
{
        char *p = line;

        while (*p && (*p == ' ' || *p == '\t')) p++;

        if (!*p || *p == '\n' || *p == '#')
                return 1;
        return 0;
}

static inline int match_uid(uid_t uid, const char *str)
{
        char *end;
        uid_t uid2;

        uid2 = strtoul(str, &end, 0);
        if (*end)
                return 0;

        return (uid == uid2);
}

static struct setxid_perm_type_t {
        char   *name;
        __u32   bit;
} setxid_perm_types[] =  {
        { "setuid", LUSTRE_SETUID_PERM },
        { "setgid", LUSTRE_SETGID_PERM },
        { "setgrp", LUSTRE_SETGRP_PERM },
        { NULL },
};

int parse_setxid_perm(__u32 *perm, char *str)
{
        char *start, *end;
        char name[64];
        struct setxid_perm_type_t *pt;

        *perm = 0;
        start = str;
        while (1) {
                memset(name, 0, sizeof(name));
                end = strchr(start, ',');
                if (!end)
                        end = str + strlen(str);
                if (start >= end)
                        break;
                strncpy(name, start, end - start);
                for (pt = setxid_perm_types; pt->name; pt++) {
                        if (!strcasecmp(name, pt->name)) {
                                *perm |= pt->bit;
                                break;
                        }
                }

                if (!pt->name) {
                        printf("unkown perm type: %s\n", name);
                        return -1;
                }

                start = end + 1;
        }
        return 0;
}

int parse_setxid_perm_line(struct identity_downcall_data *data, char *line)
{
        char uid_str[256], nid_str[256], perm_str[256];
        lnet_nid_t nid;
        __u32 perm;
        struct setxid_perm_downcall_data *pdd =
                              &data->idd_perms[data->idd_nperms];
        int rc, i;

        if (data->idd_nperms >= N_SETXID_PERMS_MAX) {
                errlog("setxid permission count %d > max %d\n",
                        data->idd_nperms, N_SETXID_PERMS_MAX);
                return -1;
        }

        rc = sscanf(line, "%s %s %s", nid_str, uid_str, perm_str);
        if (rc != 3) {
                errlog("can't parse line %s\n", line);
                return -1;
        }

        if (!match_uid(data->idd_uid, uid_str))
                return 0;

        if (!strcmp(nid_str, "*")) {
                nid = LNET_NID_ANY;
        } else {
                nid = libcfs_str2nid(nid_str);
                if (nid == LNET_NID_ANY) {
                        errlog("can't parse nid %s\n", nid_str);
                        return -1;
                }
        }

        if (parse_setxid_perm(&perm, perm_str)) {
                errlog("invalid setxid perm %s\n", perm_str);
                return -1;
        }

        /* merge the perms with the same nid */
        for (i = 0; i < data->idd_nperms; i++) {
                if (data->idd_perms[i].pdd_nid == nid) {
                        data->idd_perms[i].pdd_perm |= perm;
                        return 0;
                }
        }

        pdd->pdd_nid = nid;
        pdd->pdd_perm = perm;
        data->idd_nperms++;
        return 0;
}

int get_setxid_perms(FILE *fp, struct identity_downcall_data *data)
{
        char line[1024];

        while (fgets(line, 1024, fp)) {
                if (comment_line(line))
                        continue;

                if (parse_setxid_perm_line(data, line)) {
                        errlog("parse line %s failed!\n", line);
                        return -1;
                }
        }

        return 0;
}

static void show_result(struct identity_downcall_data *data)
{
        int i;

        if (data->idd_err) {
                errlog("failed to get identity for uid %d: %s\n",
                       data->idd_uid, strerror(data->idd_err));
                return;
        }

        printf("uid=%d gid=", data->idd_uid);
        for (i = 0; i < data->idd_ngroups; i++)
                printf("%s%u", i > 0 ? "," : "", data->idd_groups[i]);
        printf("\n");
        printf("setxid permissions:\n"
               "  nid\t\t\tperm\n");
        for (i = 0; i < data->idd_nperms; i++) {
                struct setxid_perm_downcall_data *pdd;

                pdd = &data->idd_perms[i];

                printf("  %#llx\t0x%x\n", pdd->pdd_nid, pdd->pdd_perm);
        }
        printf("\n");
}

int main(int argc, char **argv)
{
        FILE *perms_fp;
        char *end;
        struct identity_downcall_data *data;
        char procname[1024];
        unsigned long uid;
        int fd, rc;

        progname = basename(argv[0]);

        if (argc != 3) {
                usage();
                return 1;
        }

        uid = strtoul(argv[2], &end, 0);
        if (*end) {
                errlog("%s: invalid uid '%s'\n", progname, argv[2]);
                usage();
                return 1;
        }

        data = malloc(sizeof(*data));
        if (!data) {
                errlog("malloc identity downcall data(%d) failed!\n",
                       sizeof(*data));
                return 1;
        }
        memset(data, 0, sizeof(*data));
        data->idd_magic = IDENTITY_DOWNCALL_MAGIC;
        data->idd_uid = uid;

        /* get groups for uid */
        rc = get_groups_local(data);
        if (rc)
                goto downcall;

        /* read permission database */
        perms_fp = fopen(SETXID_PATHNAME, "r");
        if (perms_fp) {
                get_setxid_perms(perms_fp, data);
                fclose(perms_fp);
        } else if (errno != ENOENT) {
                errlog("open %s failed: %s\n",
                       SETXID_PATHNAME, strerror(errno));
        }

downcall:
        if (getenv("L_GETIDENTITY_TEST")) {
                show_result(data);
                return 0;
        }

        snprintf(procname, sizeof(procname),
                 "/proc/fs/lustre/mdt/%s/identity_info", argv[1]);
        fd = open(procname, O_WRONLY);
        if (fd < 0) {
                errlog("can't open file %s: %s\n", procname, strerror(errno));
                return 1;
        }

        rc = write(fd, data, sizeof(*data));
        close(fd);
        if (rc != sizeof(*data)) {
                errlog("partial write ret %d: %s\n", rc, strerror(errno));
                return 1;
        }

        return 0;
}
