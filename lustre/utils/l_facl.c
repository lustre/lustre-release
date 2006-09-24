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
#include <sys/types.h>
#include <sys/wait.h>
#include <mntent.h>

#include <lustre/liblustreapi.h>
#include <lustre/lustre_user.h>

#include "obdctl.h"

static char *progname;

static void usage(void)
{
        fprintf(stderr,
                "\nusage: %s {mdsname} {ino} {handle} {cmd}\n"
                "Normally invoked as an upcall from Lustre, set via:\n"
                "  /proc/fs/lustre/mds/{mdsname}/rmtacl_upcall\n",
                progname);
}

static inline void show_result(struct rmtacl_downcall_data *data)
{
        fprintf(stdout, "buflen %d\n\n%s\n", data->add_buflen, data->add_buf);
}

#define MDS_ERR "server processing error"

static void errlog(char *buf, const char *fmt, ...)
{
        va_list args;

        va_start(args, fmt);
        vsprintf(buf, fmt, args);
        va_end(args);
}

static char *get_lustre_mount(void)
{
        FILE *fp;
        struct mntent *mnt;
        static char mntpath[PATH_MAX] = "";

        fp = setmntent(MOUNTED, "r");
        if (fp == NULL) {
                fprintf(stderr, "setmntent %s failed: %s\n",
                        MOUNTED, strerror(errno));
                return NULL;
        }

        while (1) {
                mnt = getmntent(fp);
                if (!mnt)
                        break;

                if (!llapi_is_lustre_mnttype(mnt))
                        continue;

                if (strstr(mnt->mnt_fsname, ":/lustre")) {
                        /* save the mountpoint dir part */
                        strncpy(mntpath, mnt->mnt_dir, sizeof(mntpath));
                        endmntent(fp);
                        return mntpath;
                }
        }
        endmntent(fp);

        return NULL;
}

int main(int argc, char **argv)
{
        struct rmtacl_downcall_data *data;
        char procname[1024], *buf, *mntpath;
        int out_pipe[2], err_pipe[2], pid, size, buflen, fd, rc;

        progname = basename(argv[0]);

        if (argc != 5) {
                usage();
                return 1;
        }

        size = offsetof(struct rmtacl_downcall_data, add_buf[RMTACL_SIZE_MAX]);
        data = malloc(size);
        if (!data) {
                fprintf(stderr, "malloc %d failed\n", size);
                return 1;
        }
        memset(data, 0, size);
        data->add_magic = RMTACL_DOWNCALL_MAGIC;
        data->add_ino = strtoll(argv[2], NULL, 10);
        data->add_handle = strtoul(argv[3], NULL, 10);
        buf = data->add_buf;

        mntpath = get_lustre_mount();
        if (!mntpath) {
                errlog(buf, MDS_ERR"(no lustre mounted on MDS)\n");
                goto downcall;
        }

        /* create pipe */
        if (pipe(out_pipe) < 0 || pipe(err_pipe) < 0) {
                errlog(buf, MDS_ERR"(pipe failed): %s\n", strerror(errno));
                goto downcall;
        }

        if ((pid = fork()) < 0) {
                errlog(buf, MDS_ERR"(fork failed): %s\n", strerror(errno));
                goto downcall;
        } else if (pid == 0) {
                close(out_pipe[0]);
                if (out_pipe[1] != STDOUT_FILENO) {
                        dup2(out_pipe[1], STDOUT_FILENO);
                        close(out_pipe[1]);
                }
                close(err_pipe[0]);
                if (err_pipe[1] != STDERR_FILENO) {
                        dup2(err_pipe[1], STDERR_FILENO);
                        close(err_pipe[1]);
                }
                close(STDIN_FILENO);

                if (chdir(mntpath) < 0) {
                        fprintf(stderr, "chdir %s failed: %s\n",
                                mntpath, strerror(errno));
                        return 1;
                }

                execl("/bin/sh", "sh", "-c", argv[4], NULL);
                fprintf(stderr, "execl %s failed: %s\n",
                        argv[4], strerror(errno));

                return 1;
        }

        /* parent process handling */
        close(out_pipe[1]);
        close(err_pipe[1]);

        buflen = 0;
        while (1) {
                rc = read(out_pipe[0], buf + buflen, RMTACL_SIZE_MAX - buflen);
                if (rc < 0) {
                        errlog(buf, MDS_ERR"(read failed): %s\n",
                               strerror(errno));
                        break;
                }
                if (rc == 0)
                        break;
                buflen += rc;
                if (buflen >= RMTACL_SIZE_MAX)
                        break;
        }

        if (buflen != 0) {
                wait(&rc);
                goto downcall;
        }

        while (1) {
                rc = read(err_pipe[0], buf + buflen, RMTACL_SIZE_MAX - buflen);
                if (rc < 0) {
                        errlog(buf, MDS_ERR"(read failed): %s\n",
                               strerror(errno));
                        break;
                }
                if (rc == 0)
                        break;
                buflen += rc;
                if (buflen >= RMTACL_SIZE_MAX)
                        break;
        }

        wait(&rc);

downcall:
        buf[RMTACL_SIZE_MAX - 1] = 0;
        data->add_buflen = strlen(buf) + 1;
        if (getenv("L_FACL_TEST")) {
                show_result(data);
                free(data);
                return 0;
        }

        snprintf(procname, sizeof(procname),
                 "/proc/fs/lustre/mds/%s/rmtacl_info", argv[1]);
        fd = open(procname, O_WRONLY);
        if (fd < 0) {
                fprintf(stderr, "open %s failed: %s\n",
                        procname, strerror(errno));
                free(data);
                return 1;
        }

        buflen = offsetof(struct rmtacl_downcall_data,
                          add_buf[data->add_buflen]);
        rc = write(fd, data, buflen);
        close(fd);
        if (rc != buflen) {
                fprintf(stderr, "write %s len %d return %d: %s\n",
                        procname, buflen, rc, strerror(errno));
                free(data);
                return 1;
        }

        free(data);
        return 0;
}
