/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2005 Cluster File Systems, Inc.
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

#include <sys/types.h>
#include <sys/wait.h>
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
#include <linux/obd_support.h>

#include <portals/ptlctl.h>
#include <portals/types.h>

static int g_testing = 0;

#define log_msg(fmt, args...)                           \
        {                                               \
                if (g_testing)                          \
                        printf(fmt, ## args);           \
                else                                    \
                        syslog(LOG_ERR, fmt, ## args);  \
        }

int switch_user_identity(uid_t uid)
{
        gid_t           gid;
        struct passwd  *pw;
        int             maxgroups, ngroups = 0;
        gid_t          *groups;
        struct group   *gr;
        int             i;

        /* originally must be root */
        if (getuid() != 0 || geteuid() != 0) {
                log_msg("non-root: %u/%u\n", getuid(), geteuid());
                return -EPERM;
        }

        /* nothing more is needed for root */
        if (uid == 0)
                return 0;

        /* - groups
         * - gid
         * - uid
         */
        maxgroups = sysconf(_SC_NGROUPS_MAX);
        groups = malloc(maxgroups * sizeof(gid_t));
        if (!groups) {
                log_msg("memory alloc failure\n");
                return -ENOMEM;
        }

        pw = getpwuid(uid);
        if (!pw) {
                log_msg("no such uid %u\n", uid);
                return -EPERM;
        }

        gid = pw->pw_gid;

        while ((gr = getgrent())) {
                if (!gr->gr_mem)
                        continue;
                for (i = 0; gr->gr_mem[i]; i++) {
                        if (strcmp(gr->gr_mem[i], pw->pw_name))
                                continue;
                        groups[ngroups++] = gr->gr_gid;
                        break;
                }
                if (ngroups == maxgroups)
                        break;
        }
        endgrent();

        if (setgroups(ngroups, groups) == -1) {
                log_msg("set %d groups: %s\n", ngroups, strerror(errno));
                free(groups);
                return -EPERM;
        }
        free(groups);

        if (setgid(gid) == -1) {
                log_msg("setgid %u: %s\n", gid, strerror(errno));
                return -EPERM;
        }

        if (setuid(uid) == -1) {
                log_msg("setuid %u: %s\n", uid, strerror(errno));
                return -EPERM;
        }

        return 0;
}

/*
 * caller guarantee args not empty
 */
int compose_command_line(char *cmdline, char *op, char *args)
{
        char *p, *params, *file;

        /* skip the white space at the tail */
        p = args + strlen(args) - 1;

        while (p >= args) {
                if (*p != ' ' && *p != '\t')
                        break;
                p--;
        }

        /* not allow empty args */
        if (p < args)
                return -1;

        *(p + 1) = '\0';

        /* find next space */
        while (p >= args) {
                if (*p == ' ' || *p == '\t')
                        break;
                p--;
        }

        if (p >= args) {
                *p = '\0';
                file = p + 1; /* file name */
                params = args;
        } else {
                file = args;
                params = "";
        }

        /* backward path not allowed */
        if (strstr(file, ".."))
                return -EPERM;

        /* absolute path not allowed */
        if (file[0] == '/')
                return -EPERM;

        snprintf(cmdline, PATH_MAX, "%sfacl %s %s",
                 op, params, file);
        return 0;
}

void do_acl_command(uid_t uid, char *lroot, char *cmdline)
{
        if (switch_user_identity(uid)) {
                printf("MDS: invalid user %u\n", uid);
                return;
        }

        if (chdir(lroot) < 0) {
                log_msg("chdir to %s: %s\n", lroot, strerror(errno));
                printf("MDS: can't change dir\n");
                return;
        }

        execl("/bin/sh", "sh", "-c", cmdline, NULL);
        printf("MDS: can't execute\n");
}

#define ERRSTR_NO_CMDLINE       "No command line supplied\n"
#define ERRSTR_INVALID_ARGS     "Invalid arguments\n"
#define ERRSTR_MDS_PROCESS      "MDS procession error\n"

/*
 * The args passed in are:
 * 1. key (in hex)
 * 2. uid (in uint)
 * 3. lustre root
 * 4. get/set
 * 5. command line
 */
#define OUTPUT_BUFSIZE          8192
int main (int argc, char **argv)
{
        struct   rmtacl_downcall_args dc_args;
        char    *dc_name = "/proc/fs/lustre/mds/lacl_downcall";
        int      dc_fd;
        int      uid;
        char     output[OUTPUT_BUFSIZE];
        char     cmdline[PATH_MAX];
        int      pipeout[2], pipeerr[2], pid;
        int      output_size, rd, childret;

        if (argc != 6) {
                log_msg("invalid argc %d\n", argc);
                return -1;
        }

        /* XXX temp for debugging */
        log_msg("enter: %s %s %s %s %s\n",
                argv[1], argv[2], argv[3], argv[4], argv[5]);

        if (strcmp(argv[4], "get") && strcmp(argv[4], "set")) {
                log_msg("invalid arg 4: %s\n", argv[4]);
                return -1;
        }

        dc_args.key = strtoull(argv[1], NULL, 16);
        dc_args.res = output;
        dc_args.reslen = 0;
        dc_args.status = -1; /* default return error */

        uid = atoi(argv[2]);

        if (strlen(argv[5]) == 0) {
                dc_args.reslen = sizeof(ERRSTR_NO_CMDLINE);
                memcpy(output, ERRSTR_NO_CMDLINE, dc_args.reslen);
                goto downcall;
        }

        if (compose_command_line(cmdline, argv[4], argv[5])) {
                dc_args.reslen = sizeof(ERRSTR_INVALID_ARGS);
                memcpy(output, ERRSTR_INVALID_ARGS, dc_args.reslen);
                goto downcall;
        }

        /* create pipe */
        if (pipe(pipeout) < 0 || pipe(pipeerr) < 0) {
                dc_args.reslen = sizeof(ERRSTR_MDS_PROCESS);
                memcpy(output, ERRSTR_MDS_PROCESS, dc_args.reslen);
                goto downcall;
        }

        if ((pid = fork()) < 0) {
                dc_args.reslen = sizeof(ERRSTR_MDS_PROCESS);
                memcpy(output, ERRSTR_MDS_PROCESS, dc_args.reslen);
                goto downcall;
        } else if (pid == 0) {
                close(pipeout[0]);
                if (pipeout[1] != STDOUT_FILENO) {
                        dup2(pipeout[1], STDOUT_FILENO);
                        close(pipeout[1]);
                }

                close(pipeerr[0]);
                if (pipeerr[1] != STDERR_FILENO) {
                        dup2(pipeerr[1], STDERR_FILENO);
                        close(pipeerr[1]);
                }

                close(STDIN_FILENO);

                do_acl_command(uid, argv[3], cmdline);
                exit(-1);
        }

        /* parent process handling */
        close(pipeout[1]);
        close(pipeerr[1]);

        output[0] = 0;
        output_size = 0;
        while (1) {
                rd = read(pipeout[0], output + output_size,
                          OUTPUT_BUFSIZE - output_size);
                if (rd < 0) {
                        output_size = sizeof(ERRSTR_MDS_PROCESS);
                        memcpy(output, ERRSTR_MDS_PROCESS, dc_args.reslen);
                        break;
                }
                if (rd == 0)
                        break;
                output_size += rd;
                if (output_size >= OUTPUT_BUFSIZE)
                        break;
        }

        /* if we got standard output, just leave; otherwise collect
         * error output.
         */
        if (output_size != 0)
                goto wait_child;

        while (1) {
                rd = read(pipeerr[0], output + output_size,
                          OUTPUT_BUFSIZE - output_size);
                if (rd < 0) {
                        output_size = sizeof(ERRSTR_MDS_PROCESS);
                        memcpy(output, ERRSTR_MDS_PROCESS, dc_args.reslen);
                        break;
                }
                if (rd == 0)
                        break;
                output_size += rd;
                if (output_size >= OUTPUT_BUFSIZE)
                        break;
        }

wait_child:
        wait(&childret);

        dc_args.status = childret;
        dc_args.reslen = output_size;

downcall:
        dc_fd = open(dc_name, O_WRONLY);
        if (dc_fd < 0) {
                log_msg("can't open %s: %s\n", dc_name, strerror(errno));
        } else {
                int rc;

                rc = write(dc_fd, &dc_args, sizeof(dc_args));
                if (rc != sizeof(dc_args))
                        log_msg("write error: ret %d\n", rc);

                close(dc_fd);
        }

        /* XXX temp for debugging */
        log_msg("finished upcall\n");
        return 0;
}
