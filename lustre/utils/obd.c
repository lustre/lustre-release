/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Robert Read <rread@clusterfs.com>
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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#define printk printf

#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/obd_lov.h>

#include <unistd.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>

#include <asm/page.h>           /* needed for PAGE_SIZE - rread */

#define __KERNEL__
#include <linux/list.h>
#undef __KERNEL__

#include "obdctl.h"
#include "parser.h"
#include <stdio.h>

#define SHMEM_STATS 1
#if SHMEM_STATS
# include <sys/ipc.h>
# include <sys/shm.h>

# define MAX_SHMEM_COUNT 1024
static long long *shared_counters;
static long long counter_snapshot[2][MAX_SHMEM_COUNT];
struct timeval prev_time;
#endif

int fd = -1;
uint64_t conn_addr = -1;
uint64_t conn_cookie;
char rawbuf[8192];
char *buf = rawbuf;
int max = sizeof(rawbuf);

static int thread;

static int getfd(char *func);
static char *cmdname(char *func);

#define IOCINIT(data)                                                   \
do {                                                                    \
        memset(&data, 0, sizeof(data));                                 \
        data.ioc_version = OBD_IOCTL_VERSION;                           \
        data.ioc_addr = conn_addr;                                      \
        data.ioc_cookie = conn_cookie;                                  \
        data.ioc_len = sizeof(data);                                    \
        if (fd < 0) {                                                   \
                fprintf(stderr, "No device open, use device\n");        \
                return 1;                                               \
        }                                                               \
} while (0)

char *obdo_print(struct obdo *obd)
{
        char buf[1024];

        sprintf(buf, "id: %Ld\ngrp: %Ld\natime: %Ld\nmtime: %Ld\nctime: %Ld\n"
                "size: %Ld\nblocks: %Ld\nblksize: %d\nmode: %o\nuid: %d\n"
                "gid: %d\nflags: %x\nobdflags: %x\nnlink: %d,\nvalid %x\n",
                obd->o_id,
                obd->o_gr,
                obd->o_atime,
                obd->o_mtime,
                obd->o_ctime,
                obd->o_size,
                obd->o_blocks,
                obd->o_blksize,
                obd->o_mode,
                obd->o_uid,
                obd->o_gid,
                obd->o_flags, obd->o_obdflags, obd->o_nlink, obd->o_valid);
        return strdup(buf);
}


#define BAD_VERBOSE (-999999999)

#define N2D_OFF 0x100      /* So we can tell between error codes and devices */

static int do_name2dev(char *func, char *name)
{
        struct obd_ioctl_data data;
        int rc;

        if (getfd(func))
                return -1;

        IOCINIT(data);

        data.ioc_inllen1 = strlen(name) + 1;
        data.ioc_inlbuf1 = name;

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(func));
                return -2;
        }
        rc = ioctl(fd, OBD_IOC_NAME2DEV, buf);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s - %s\n", cmdname(func),
                        name, strerror(rc = errno));
                return rc;
        }

        memcpy((char *)(&data), buf, sizeof(data));

        return data.ioc_dev + N2D_OFF;
}

/*
 * resolve a device name to a device number.
 * supports a number or name.
 * FIXME: support UUID
 */
static int parse_devname(char *func, char *name)
{
        int rc;
        int ret = -1;

        if (!name)
                return ret;
        if (name[0] == '$') {
                rc = do_name2dev(func, name + 1);
                if (rc >= N2D_OFF) {
                        ret = rc - N2D_OFF;
                        printf("%s is device %d\n", name, ret);
                } else {
                        fprintf(stderr, "error: %s: %s: %s\n", cmdname(func),
                                name, "device not found");
                }
        } else
                ret = strtoul(name, NULL, 0);

        return ret;
}

static char *cmdname(char *func)
{
        static char buf[512];

        if (thread) {
                sprintf(buf, "%s-%d", func, thread);
                return buf;
        }

        return func;
}

static int getfd(char *func)
{
        if (fd == -1)
                fd = open("/dev/obd", O_RDWR);
        if (fd == -1) {
                fprintf(stderr, "error: %s: opening /dev/obd: %s\n"
                        "hint: lustre kernel modules may not be loaded.\n",
                        cmdname(func), strerror(errno));
                return -1;
        }
        return 0;
}

#define difftime(a, b)                                          \
        ((double)(a)->tv_sec - (b)->tv_sec +                    \
         ((double)((a)->tv_usec - (b)->tv_usec) / 1000000))

static int be_verbose(int verbose, struct timeval *next_time,
                      __u64 num, __u64 *next_num, int num_total)
{
        struct timeval now;

        if (!verbose)
                return 0;

        if (next_time != NULL)
                gettimeofday(&now, NULL);

        /* A positive verbosity means to print every X iterations */
        if (verbose > 0 &&
            (next_num == NULL || num >= *next_num || num >= num_total)) {
                *next_num += verbose;
                if (next_time) {
                        next_time->tv_sec = now.tv_sec - verbose;
                        next_time->tv_usec = now.tv_usec;
                }
                return 1;
        }

        /* A negative verbosity means to print at most each X seconds */
        if (verbose < 0 && next_time != NULL && difftime(&now, next_time) >= 0){
                next_time->tv_sec = now.tv_sec - verbose;
                next_time->tv_usec = now.tv_usec;
                if (next_num)
                        *next_num = num;
                return 1;
        }

        return 0;
}

static int get_verbose(char *func, const char *arg)
{
        int verbose;
        char *end;

        if (!arg || arg[0] == 'v')
                verbose = 1;
        else if (arg[0] == 's' || arg[0] == 'q')
                verbose = 0;
        else {
                verbose = (int)strtoul(arg, &end, 0);
                if (*end) {
                        fprintf(stderr, "error: %s: bad verbose option '%s'\n",
                                cmdname(func), arg);
                        return BAD_VERBOSE;
                }
        }

        if (verbose < 0)
                printf("Print status every %d seconds\n", -verbose);
        else if (verbose == 1)
                printf("Print status every operation\n");
        else if (verbose > 1)
                printf("Print status every %d operations\n", verbose);

        return verbose;
}

int do_disconnect(char *func, int verbose)
{
        int rc;
        struct obd_ioctl_data data;

        if (conn_addr == -1)
                return 0;

        IOCINIT(data);

        rc = ioctl(fd, OBD_IOC_DISCONNECT, &data);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %x %s\n", cmdname(func),
                        OBD_IOC_DISCONNECT, strerror(errno));
        } else {
                if (verbose)
                        printf("%s: disconnected conn %Lx\n", cmdname(func),
                               conn_addr);
                conn_addr = -1;
        }

        return rc;
}

#if SHMEM_STATS
static void shmem_setup(void)
{
        int shmid = shmget(IPC_PRIVATE, sizeof(counter_snapshot[0]), 0600);

        if (shmid == -1) {
                fprintf(stderr, "Can't create shared memory counters: %s\n",
                        strerror(errno));
                return;
        }

        shared_counters = (long long *)shmat(shmid, NULL, 0);

        if (shared_counters == (long long *)(-1)) {
                fprintf(stderr, "Can't attach shared memory counters: %s\n",
                        strerror(errno));
                shared_counters = NULL;
                return;
        }
}

static inline void shmem_reset(void)
{
        if (shared_counters == NULL)
                return;

        memset(shared_counters, 0, sizeof(counter_snapshot[0]));
        memset(counter_snapshot, 0, sizeof(counter_snapshot));
        gettimeofday(&prev_time, NULL);
}

static inline void shmem_bump(void)
{
        if (shared_counters == NULL || thread <= 0 || thread > MAX_SHMEM_COUNT)
                return;

        shared_counters[thread - 1]++;
}

static void shmem_snap(int n)
{
        struct timeval this_time;
        int non_zero = 0;
        long long total = 0;
        double secs;
        int i;

        if (shared_counters == NULL || n > MAX_SHMEM_COUNT)
                return;

        memcpy(counter_snapshot[1], counter_snapshot[0],
               n * sizeof(counter_snapshot[0][0]));
        memcpy(counter_snapshot[0], shared_counters,
               n * sizeof(counter_snapshot[0][0]));
        gettimeofday(&this_time, NULL);

        for (i = 0; i < n; i++) {
                long long this_count =
                        counter_snapshot[0][i] - counter_snapshot[1][i];

                if (this_count != 0) {
                        non_zero++;
                        total += this_count;
                }
        }

        secs = (this_time.tv_sec + this_time.tv_usec / 1000000.0) -
                (prev_time.tv_sec + prev_time.tv_usec / 1000000.0);

        printf("%d/%d Total: %f/second\n", non_zero, n, total / secs);

        prev_time = this_time;
}

#define SHMEM_SETUP()	shmem_setup()
#define SHMEM_RESET()	shmem_reset()
#define SHMEM_BUMP()	shmem_bump()
#define SHMEM_SNAP(n)	shmem_snap(n)
#else
#define SHMEM_SETUP()
#define SHMEM_RESET()
#define SHMEM_BUMP()
#define SHMEM_SNAP(n)
#endif

extern command_t cmdlist[];

static int do_device(char *func, int dev)
{
        struct obd_ioctl_data data;

        memset(&data, 0, sizeof(data));

        data.ioc_dev = dev;

        if (getfd(func))
                return -1;

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(func));
                return -2;
        }

        return ioctl(fd, OBD_IOC_DEVICE, buf);
}

int jt_obd_device(int argc, char **argv)
{
        int rc, dev;
        do_disconnect(argv[0], 1);

        if (argc != 2)
                return CMD_HELP;

        dev = parse_devname(argv[0], argv[1]);
        if (dev < 0)
                return -1;

        rc = do_device(argv[0], dev);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_connect(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        do_disconnect(argv[0], 1);

#warning TODO: implement timeout per lctl usage for probe
        if (argc != 1)
                return CMD_HELP;

        rc = ioctl(fd, OBD_IOC_CONNECT, &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %x %s\n", cmdname(argv[0]),
                        OBD_IOC_CONNECT, strerror(rc = errno));
        else {
                conn_addr = data.ioc_addr;
                conn_cookie = data.ioc_cookie;
        }
        return rc;
}

int jt_obd_disconnect(int argc, char **argv)
{
        if (argc != 1)
                return CMD_HELP;

        if (conn_addr == -1)
                return 0;

        return do_disconnect(argv[0], 0);
}

int jt_opt_device(int argc, char **argv)
{
        char *arg2[3];
        int ret;
        int rc;

        if (argc < 3)
                return CMD_HELP;

        rc = do_device("device", parse_devname(argv[0], argv[1]));

        if (!rc) {
                arg2[0] = "connect";
                arg2[1] = NULL;
                rc = jt_obd_connect(1, arg2);
        }

        if (!rc)
                rc = Parser_execarg(argc - 2, argv + 2, cmdlist);

        ret = do_disconnect(argv[0], 0);
        if (!rc)
                rc = ret;

        return rc;
}

int jt_opt_threads(int argc, char **argv)
{
        __u64 threads, next_thread;
        int verbose;
        int rc = 0;
        char *end;
        int i;

        if (argc < 5)
                return CMD_HELP;

        threads = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid page count '%s'\n",
                        cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }

        verbose = get_verbose(argv[0], argv[2]);
        if (verbose == BAD_VERBOSE)
                return CMD_HELP;

        if (verbose != 0)
                printf("%s: starting "LPD64" threads on device %s running %s\n",
                       argv[0], threads, argv[3], argv[4]);

        SHMEM_RESET();

        for (i = 1, next_thread = verbose; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n", argv[0], i,
                                strerror(rc = errno));
                        break;
                } else if (rc == 0) {
                        thread = i;
                        argv[2] = "--device";
                        return jt_opt_device(argc - 2, argv + 2);
                } else if (be_verbose(verbose, NULL, i, &next_thread, threads))
                        printf("%s: thread #%d (PID %d) started\n",
                               argv[0], i, rc);
                rc = 0;
        }

        if (!thread) {          /* parent process */
                int live_threads = threads;

                while (live_threads > 0) {
                        int status;
                        pid_t ret;

                        ret = waitpid(0, &status, verbose < 0 ? WNOHANG : 0);
                        if (ret == 0) {
                                if (verbose >= 0)
                                        abort();

                                sleep(-verbose);
                                SHMEM_SNAP(threads);
                                continue;
                        }

                        if (ret < 0) {
                                fprintf(stderr, "error: %s: wait - %s\n",
                                        argv[0], strerror(errno));
                                if (!rc)
                                        rc = errno;
                        } else {
                                /*
                                 * This is a hack.  We _should_ be able to use
                                 * WIFEXITED(status) to see if there was an
                                 * error, but it appears to be broken and it
                                 * always returns 1 (OK).  See wait(2).
                                 */
                                int err = WEXITSTATUS(status);
                                if (err || WIFSIGNALED(status))
                                        fprintf(stderr,
                                                "%s: PID %d had rc=%d\n",
                                                argv[0], ret, err);
                                if (!rc)
                                        rc = err;

                                live_threads--;
                        }
                }
        }

        return rc;
}

int jt_obd_detach(int argc, char **argv)
{
        struct obd_ioctl_data data;
        char force = 'F';
        int rc;

        IOCINIT(data);

        if (argc != 1 && argc != 2)
                return CMD_HELP;

        if (argc == 2) {
                data.ioc_inllen1 = 1;
                data.ioc_inlbuf1 = &force;
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, OBD_IOC_DETACH, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_cleanup(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if (argc != 1)
                return CMD_HELP;

        rc = ioctl(fd, OBD_IOC_CLEANUP, &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_newdev(int argc, char **argv)
{
        int rc;
        struct obd_ioctl_data data;

        if (getfd(argv[0]))
                return -1;

        IOCINIT(data);

        if (argc != 1)
                return CMD_HELP;

        rc = ioctl(fd, OBD_IOC_NEWDEV, &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));
        else {
                printf("Current device set to %d\n", data.ioc_dev);
        }

        return rc;
}

int jt_obd_list(int argc, char **argv)
{
        int rc;
        char buf[8192];
        struct obd_ioctl_data *data = (struct obd_ioctl_data *)buf;

        if (getfd(argv[0]))
                return -1;

        memset(buf, 0, sizeof(buf));
        data->ioc_version = OBD_IOCTL_VERSION;
        data->ioc_addr = conn_addr;
        data->ioc_cookie = conn_addr;
        data->ioc_len = sizeof(buf);
        data->ioc_inllen1 = sizeof(buf) - size_round(sizeof(*data));

        if (argc != 1)
                return CMD_HELP;

        rc = ioctl(fd, OBD_IOC_LIST, data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));
        else {
                printf("%s", data->ioc_bulk);
        }

        return rc;
}

int jt_obd_attach(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if (argc != 2 && argc != 3 && argc != 4)
                return CMD_HELP;

        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        if (argc >= 3) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }

        if (argc == 4) {
                data.ioc_inllen3 = strlen(argv[3]) + 1;
                data.ioc_inlbuf3 = argv[3];
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, OBD_IOC_ATTACH, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %x %s\n", cmdname(argv[0]),
                        OBD_IOC_ATTACH, strerror(rc = errno));
        else if (argc == 3) {
                char name[1024];
                if (strlen(argv[2]) > 128) {
                        printf("Name too long to set environment\n");
                        return -EINVAL;
                }
                snprintf(name, 512, "LUSTRE_DEV_%s", argv[2]);
                rc = setenv(name, argv[1], 1);
                if (rc) {
                        printf("error setting env variable %s\n", name);
                }
        }

        return rc;
}

int jt_obd_name2dev(int argc, char **argv)
{
        int rc;

        if (argc != 2)
                return CMD_HELP;

        rc = do_name2dev(argv[0], argv[1]);
        if (rc >= N2D_OFF) {
                int dev = rc - N2D_OFF;
                rc = do_device(argv[0], dev);
                if (rc == 0)
                        printf("%d\n", dev);
        }
        return rc;
}

int jt_obd_setup(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if (argc > 3)
                return CMD_HELP;

        data.ioc_dev = -1;
        if (argc > 1) {
                data.ioc_dev = parse_devname(argv[0], argv[1]);
                if (data.ioc_dev < 0)
                        return -1;
                data.ioc_inllen1 = strlen(argv[1]) + 1;
                data.ioc_inlbuf1 = argv[1];
        }
        if (argc == 3) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }
        rc = ioctl(fd, OBD_IOC_SETUP, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}


int jt_obd_create(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval next_time;
        __u64 count = 1, next_count;
        int verbose = 1;
        int mode = 0100644;
        int rc = 0, i;
        char *end;

        IOCINIT(data);
        if (argc < 2 || argc > 4)
                return CMD_HELP;

        count = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid iteration count '%s'\n",
                        cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }

        if (argc > 2) {
                mode = strtoul(argv[2], &end, 0);
                if (*end) {
                        fprintf(stderr, "error: %s: invalid mode '%s'\n",
                                cmdname(argv[0]), argv[2]);
                        return CMD_HELP;
                }
                if (!(mode & S_IFMT))
                        mode |= S_IFREG;
        }

        if (argc > 3) {
                verbose = get_verbose(argv[0], argv[3]);
                if (verbose == BAD_VERBOSE)
                        return CMD_HELP;
        }

        printf("%s: "LPD64" objects\n", cmdname(argv[0]), count);
        gettimeofday(&next_time, NULL);
        next_time.tv_sec -= verbose;

        for (i = 1, next_count = verbose; i <= count; i++) {
                data.ioc_obdo1.o_mode = mode;
                data.ioc_obdo1.o_id = i;
                data.ioc_obdo1.o_uid = 0;
                data.ioc_obdo1.o_gid = 0;
                data.ioc_obdo1.o_valid = OBD_MD_FLTYPE | OBD_MD_FLMODE |
                                OBD_MD_FLID | OBD_MD_FLUID | OBD_MD_FLGID;;

                rc = ioctl(fd, OBD_IOC_CREATE, &data);
                SHMEM_BUMP();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno));
                        break;
                }
                if (!(data.ioc_obdo1.o_valid & OBD_MD_FLID)) {
                        fprintf(stderr, "error: %s: objid not valid #%d:%08x\n",
                                cmdname(argv[0]), i, data.ioc_obdo1.o_valid);
                        rc = EINVAL;
                        break;
                }

                if (be_verbose(verbose, &next_time, i, &next_count, count))
                        printf("%s: #%d is object id 0x%Lx\n", cmdname(argv[0]),
                               i, (long long)data.ioc_obdo1.o_id);
        }
        return rc;
}

int jt_obd_setattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        char *end;
        int rc;

        IOCINIT(data);
        if (argc != 2)
                return CMD_HELP;

        data.ioc_obdo1.o_id = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid objid '%s'\n",
                        cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }
        data.ioc_obdo1.o_mode = S_IFREG | strtoul(argv[2], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid mode '%s'\n",
                        cmdname(argv[0]), argv[2]);
                return CMD_HELP;
        }
        data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

        rc = ioctl(fd, OBD_IOC_SETATTR, &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_destroy(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval next_time;
        __u64 count = 1, next_count;
        int verbose = 1;
        __u64 id;
        char *end;
        int rc = 0, i;

        IOCINIT(data);
        if (argc < 2 || argc > 4)
                return CMD_HELP;

        id = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid objid '%s'\n",
                        cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }
        if (argc > 2) {
                count = strtoull(argv[2], &end, 0);
                if (*end) {
                        fprintf(stderr,
                                "error: %s: invalid iteration count '%s'\n",
                                cmdname(argv[0]), argv[2]);
                        return CMD_HELP;
                }
        }

        if (argc > 3) {
                verbose = get_verbose(argv[0], argv[3]);
                if (verbose == BAD_VERBOSE)
                        return CMD_HELP;
        }

        printf("%s: "LPD64" objects\n", cmdname(argv[0]), count);
        gettimeofday(&next_time, NULL);
        next_time.tv_sec -= verbose;

        for (i = 1, next_count = verbose; i <= count; i++, id++) {
                data.ioc_obdo1.o_id = id;
                data.ioc_obdo1.o_mode = S_IFREG | 0644;

                rc = ioctl(fd, OBD_IOC_DESTROY, &data);
                SHMEM_BUMP();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: objid "LPX64": %s\n",
                                cmdname(argv[0]), id, strerror(rc = errno));
                        break;
                }

                if (be_verbose(verbose, &next_time, i, &next_count, count))
                        printf("%s: #%d is object id 0x%Lx\n", cmdname(argv[0]),
                               i, (long long)data.ioc_obdo1.o_id);
        }

        return rc;
}

int jt_obd_getattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        char *end;
        int rc;

        if (argc != 2)
                return CMD_HELP;

        IOCINIT(data);
        data.ioc_obdo1.o_id = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid objid '%s'\n",
                        cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }
        /* to help obd filter */
        data.ioc_obdo1.o_mode = 0100644;
        data.ioc_obdo1.o_valid = 0xffffffff;
        printf("%s: object id %Ld\n", cmdname(argv[0]), data.ioc_obdo1.o_id);

        rc = ioctl(fd, OBD_IOC_GETATTR, &data);
        if (rc) {
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));
        } else {
                printf("%s: object id %Ld, mode %o\n", cmdname(argv[0]),
                       data.ioc_obdo1.o_id, data.ioc_obdo1.o_mode);
        }
        return rc;
}

int jt_obd_test_getattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval start, next_time;
        __u64 i, count, next_count;
        int verbose = 1;
        obd_id objid = 3;
        char *end;
        int rc = 0;

        if (argc < 2 && argc > 4)
                return CMD_HELP;

        IOCINIT(data);
        count = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid iteration count '%s'\n",
                        cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }

        if (argc >= 3) {
                verbose = get_verbose(argv[0], argv[2]);
                if (verbose == BAD_VERBOSE)
                        return CMD_HELP;
        }

        if (argc >= 4) {
                if (argv[3][0] == 't') {
                        objid = strtoull(argv[3] + 1, &end, 0);
                        if (thread)
                                objid += thread - 1;
                } else
                        objid = strtoull(argv[3], &end, 0);
                if (*end) {
                        fprintf(stderr, "error: %s: invalid objid '%s'\n",
                                cmdname(argv[0]), argv[3]);
                        return CMD_HELP;
                }
        }

        gettimeofday(&start, NULL);
        next_time.tv_sec = start.tv_sec - verbose;
        next_time.tv_usec = start.tv_usec;
        if (verbose != 0)
                printf("%s: getting "LPD64" attrs (objid "LPX64"): %s",
                       cmdname(argv[0]), count, objid, ctime(&start.tv_sec));

        for (i = 1, next_count = verbose; i <= count; i++) {
                data.ioc_obdo1.o_id = objid;
                data.ioc_obdo1.o_mode = S_IFREG;
                data.ioc_obdo1.o_valid = 0xffffffff;
                rc = ioctl(fd, OBD_IOC_GETATTR, &data);
                SHMEM_BUMP();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #"LPD64" - %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno));
                        break;
                } else {
                        if (be_verbose
                            (verbose, &next_time, i, &next_count, count))
                                printf("%s: got attr #"LPD64"\n",
                                       cmdname(argv[0]), i);
                }
        }

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = difftime(&end, &start);

                --i;
                if (verbose != 0)
                        printf("%s: "LPD64" attrs in %.4gs (%.4g attr/s): %s",
                               cmdname(argv[0]), i, diff, (double)i / diff,
                               ctime(&end.tv_sec));
        }
        return rc;
}

int jt_obd_test_brw(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval start, next_time;
        int pages = 1;
        __u64 count, next_count;
        __u64 objid = 3;
        int verbose = 1, write = 0, rw;
        char *end;
        int thr_offset = 0;
        int i;
        int len;
        int rc = 0;

        if (argc < 2 || argc > 6) {
                fprintf(stderr, "error: %s: bad number of arguments: %d\n",
                        cmdname(argv[0]), argc);
                return CMD_HELP;
        }

        /* make each thread write to a different offset */
        if (argv[1][0] == 't') {
                count = strtoull(argv[1] + 1, &end, 0);
                if (thread)
                        thr_offset = thread - 1;
        } else
                count = strtoull(argv[1], &end, 0);

        if (*end) {
                fprintf(stderr, "error: %s: bad iteration count '%s'\n",
                        cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }

        if (argc >= 3) {
                if (argv[2][0] == 'w' || argv[2][0] == '1')
                        write = 1;
                else if (argv[2][0] == 'r' || argv[2][0] == '0')
                        write = 0;
        }

        if (argc >= 4) {
                verbose = get_verbose(argv[0], argv[3]);
                if (verbose == BAD_VERBOSE)
                        return CMD_HELP;
        }

        if (argc >= 5) {
                pages = strtoul(argv[4], &end, 0);
                if (*end) {
                        fprintf(stderr, "error: %s: bad page count '%s'\n",
                                cmdname(argv[0]), argv[4]);
                        return CMD_HELP;
                }
        }
        if (argc >= 6) {
                if (argv[5][0] == 't') {
                        objid = strtoull(argv[5] + 1, &end, 0);
                        if (thread)
                                objid += thread - 1;
                } else
                        objid = strtoull(argv[5], &end, 0);
                if (*end) {
                        fprintf(stderr, "error: %s: bad objid '%s'\n",
                                cmdname(argv[0]), argv[5]);
                        return CMD_HELP;
                }
        }

        len = pages * PAGE_SIZE;

        IOCINIT(data);
        data.ioc_obdo1.o_id = objid;
        data.ioc_obdo1.o_mode = S_IFREG;
        data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;
        data.ioc_count = len;
        data.ioc_offset = thr_offset * len * count;

        gettimeofday(&start, NULL);
        next_time.tv_sec = start.tv_sec - verbose;
        next_time.tv_usec = start.tv_usec;

        if (verbose != 0)
                printf("%s: %s "LPU64"x%d pages (obj "LPX64", off "LPU64"): %s",
                       cmdname(argv[0]), write ? "writing" : "reading", count,
                       pages, objid, data.ioc_offset, ctime(&start.tv_sec));

        rc = ioctl(fd, OBD_IOC_OPEN, &data);
        if (rc) {
                fprintf(stderr, "error: brw_open: %s\n", strerror(rc = errno));
                return rc;
        }

        rw = write ? OBD_IOC_BRW_WRITE : OBD_IOC_BRW_READ;
        for (i = 1, next_count = verbose; i <= count; i++) {
                rc = ioctl(fd, rw, &data);
                SHMEM_BUMP();
                if (rc) {
                        fprintf(stderr, "error: %s: #%d - %s on %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno),
                                write ? "write" : "read");
                        break;
                } else if (be_verbose(verbose, &next_time,i, &next_count,count))
                        printf("%s: %s number %dx%d\n", cmdname(argv[0]),
                               write ? "write" : "read", i, pages);

                data.ioc_offset += len;
        }

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = difftime(&end, &start);

                --i;
                if (verbose != 0)
                        printf("%s: %s %dx%d pages in %.4gs (%.4g pg/s): %s",
                               cmdname(argv[0]), write ? "wrote" : "read",
                               i, pages, diff, (double)i * pages / diff,
                               ctime(&end.tv_sec));
        }
        rw = ioctl(fd, OBD_IOC_CLOSE, &data);
        if (rw) {
                fprintf(stderr, "error: brw_close: %s\n", strerror(rw = errno));
                if (!rc)
                        rc = rw;
        }

        return rc;
}

int jt_obd_lov_setconfig(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct lov_desc desc;
        obd_uuid_t *uuidarray, *ptr;
        int rc, i;
        char *end;

        IOCINIT(data);

        if (argc <= 6)
                return CMD_HELP;

        if (strlen(argv[1]) > sizeof(desc.ld_uuid) - 1) {
                fprintf(stderr,
                        "error: %s: LOV uuid '%s' longer than %d characters\n",
                        cmdname(argv[0]), argv[1], sizeof(desc.ld_uuid) - 1);
                return -EINVAL;
        }

        memset(&desc, 0, sizeof(desc));
        strncpy(desc.ld_uuid, argv[1], sizeof(desc.ld_uuid) - 1);
        desc.ld_tgt_count = argc - 6;
        desc.ld_default_stripe_count = strtoul(argv[2], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad default stripe count '%s'\n",
                        cmdname(argv[0]), argv[2]);
                return CMD_HELP;
        }
        if (desc.ld_default_stripe_count > desc.ld_tgt_count) {
                fprintf(stderr,
                        "error: %s: default stripe count %u > OST count %u\n",
                        cmdname(argv[0]), desc.ld_default_stripe_count,
                        desc.ld_tgt_count);
                return -EINVAL;
        }

        desc.ld_default_stripe_size = strtoull(argv[3], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad default stripe size '%s'\n",
                        cmdname(argv[0]), argv[3]);
                return CMD_HELP;
        }
        if (desc.ld_default_stripe_size < 4096) {
                fprintf(stderr,
                        "error: %s: default stripe size "LPU64" too small\n",
                        cmdname(argv[0]), desc.ld_default_stripe_size);
                return -EINVAL;
        } else if ((long)desc.ld_default_stripe_size <
                   desc.ld_default_stripe_size) {
                fprintf(stderr,
                        "error: %s: default stripe size "LPU64" too large\n",
                        cmdname(argv[0]), desc.ld_default_stripe_size);
                return -EINVAL;
        }
        desc.ld_default_stripe_offset = strtoull(argv[4], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad default stripe offset '%s'\n",
                        cmdname(argv[0]), argv[4]);
                return CMD_HELP;
        }
        desc.ld_pattern = strtoul(argv[5], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad stripe pattern '%s'\n",
                        cmdname(argv[0]), argv[5]);
                return CMD_HELP;
        }

        /* NOTE: it is possible to overwrite the default striping parameters,
         *       but EXTREME care must be taken when saving the OST UUID list.
         *       It must be EXACTLY the same, or have only additions at the
         *       end of the list, or only overwrite individual OST entries
         *       that are restored from backups of the previous OST.
         */
        uuidarray = calloc(desc.ld_tgt_count, sizeof(*uuidarray));
        if (!uuidarray) {
                fprintf(stderr, "error: %s: no memory for %d UUIDs\n",
                        cmdname(argv[0]), desc.ld_tgt_count);
                rc = -ENOMEM;
                goto out;
        }
        for (i = 6, ptr = uuidarray; i < argc; i++, ptr++) {
                if (strlen(argv[i]) >= sizeof(*ptr)) {
                        fprintf(stderr, "error: %s: arg %d (%s) too long\n",
                                cmdname(argv[0]), i, argv[i]);
                        rc = -EINVAL;
                        goto out;
                }
                strcpy((char *)ptr, argv[i]);
        }

        data.ioc_inllen1 = sizeof(desc);
        data.ioc_inlbuf1 = (char *)&desc;
        data.ioc_inllen2 = desc.ld_tgt_count * sizeof(*uuidarray);
        data.ioc_inlbuf2 = (char *)uuidarray;

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                rc = -EINVAL;
                goto out;
        }

        rc = ioctl(fd, OBD_IOC_LOV_SET_CONFIG, buf);
        if (rc)
                fprintf(stderr, "error: %s: ioctl error: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));
out:
        free(uuidarray);
        return rc;
}

#define DEF_UUID_ARRAY_LEN (8192 / 40)

int jt_obd_lov_getconfig(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct lov_desc desc;
        obd_uuid_t *uuidarray;
        int rc;

        IOCINIT(data);

        if (argc != 2)
                return CMD_HELP;

        if (strlen(argv[1]) > sizeof(desc.ld_uuid) - 1) {
                fprintf(stderr,
                        "error: %s: LOV uuid '%s' longer than %d characters\n",
                        cmdname(argv[0]), argv[1], sizeof(desc.ld_uuid) - 1);
                return -EINVAL;
        }

        memset(&desc, 0, sizeof(desc));
        strncpy(desc.ld_uuid, argv[1], sizeof(desc.ld_uuid) - 1);
        desc.ld_tgt_count = DEF_UUID_ARRAY_LEN;
repeat:
        uuidarray = calloc(desc.ld_tgt_count, sizeof(*uuidarray));
        if (!uuidarray) {
                fprintf(stderr, "error: %s: no memory for %d uuid's\n",
                        cmdname(argv[0]), desc.ld_tgt_count);
                return -ENOMEM;
        }

        data.ioc_inllen1 = sizeof(desc);
        data.ioc_inlbuf1 = (char *)&desc;
        data.ioc_inllen2 = desc.ld_tgt_count * sizeof(*uuidarray);
        data.ioc_inlbuf2 = (char *)uuidarray;

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                rc = -EINVAL;
                goto out;
        }

        rc = ioctl(fd, OBD_IOC_LOV_GET_CONFIG, buf);
        if (rc == -ENOSPC) {
                free(uuidarray);
                goto repeat;
        } else if (rc) {
                fprintf(stderr, "error: %s: ioctl error: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));
        } else {
                obd_uuid_t *ptr;
                int i;

                if (obd_ioctl_unpack(&data, buf, max)) {
                        fprintf(stderr, "error: %s: invalid reply\n",
                                cmdname(argv[0]));
                        rc = -EINVAL;
                        goto out;
                }
                printf("default_stripe_count: %u\n",
                       desc.ld_default_stripe_count);
                printf("default_stripe_size: "LPU64"\n",
                       desc.ld_default_stripe_size);
                printf("default_stripe_offset: "LPU64"\n",
                       desc.ld_default_stripe_offset);
                printf("default_stripe_pattern: %u\n", desc.ld_pattern);
                printf("obd_count: %u\n", desc.ld_tgt_count);
                for (i = 0, ptr = uuidarray; i < desc.ld_tgt_count; i++, ptr++)
                        printf("%u: %s\n", i, (char *)ptr);
        }
out:
        free(uuidarray);
        return rc;
}

int jt_obd_test_ldlm(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc != 1)
                return CMD_HELP;

        rc = ioctl(fd, IOC_LDLM_TEST, &data);
        if (rc)
                fprintf(stderr, "error: %s: test failed: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));
        return rc;
}

int jt_obd_dump_ldlm(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc != 1)
                return CMD_HELP;

        rc = ioctl(fd, IOC_LDLM_DUMP, &data);
        if (rc)
                fprintf(stderr, "error: %s failed: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));
        return rc;
}

int jt_obd_ldlm_regress_start(int argc, char **argv)
{
        int rc;
        struct obd_ioctl_data data;
        char argstring[200];
        int i, count = sizeof(argstring) - 1;

        IOCINIT(data);
        if (argc > 5)
                return CMD_HELP;

        argstring[0] = '\0';
        for (i = 1; i < argc; i++) {
                strncat(argstring, " ", count);
                count--;
                strncat(argstring, argv[i], count);
                count -= strlen(argv[i]);
        }

        if (strlen(argstring)) {
                data.ioc_inlbuf1 = argstring;
                data.ioc_inllen1 = strlen(argstring) + 1;
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, IOC_LDLM_REGRESS_START, buf);

        if (rc)
                fprintf(stderr, "error: %s: test failed: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));

        return rc;
}

int jt_obd_ldlm_regress_stop(int argc, char **argv)
{
        int rc;
        struct obd_ioctl_data data;
        IOCINIT(data);

        if (argc != 1)
                return CMD_HELP;

        rc = ioctl(fd, IOC_LDLM_REGRESS_STOP, &data);

        if (rc)
                fprintf(stderr, "error: %s: test failed: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));
        return rc;
}

int jt_obd_lov_set_osc_active(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc != 3)
                return CMD_HELP;

        data.ioc_inlbuf1 = argv[1];
        data.ioc_inllen1 = strlen(argv[1]) + 1;

        /* reuse offset for 'active' */
        data.ioc_offset = atoi(argv[2]);

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, IOC_LOV_SET_OSC_ACTIVE, buf);

        if (rc)
                fprintf(stderr, "error: %s: failed: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));

        return rc;
}

int jt_obd_newconn(int argc, char **argv)
{
        int rc;
        struct obd_ioctl_data data;

        IOCINIT(data);
        if (argc < 2 || argc > 3)
                return CMD_HELP;

        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];

        if (argc == 3) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, OBD_IOC_RECOVD_NEWCONN, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_failconn(int argc, char **argv)
{
        int rc;
        struct obd_ioctl_data data;

        IOCINIT(data);
        if (argc < 2)
                return CMD_HELP;

        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, OBD_IOC_RECOVD_FAILCONN, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));
        
        return rc;
}

static void signal_server(int sig)
{
        if (sig == SIGINT) {
                do_disconnect("sigint", 1);
                exit(1);
        } else
                fprintf(stderr, "%s: got signal %d\n", cmdname("sigint"), sig);
}

int obd_initialize(int argc, char **argv)
{
        SHMEM_SETUP();
        return 0;
}


void obd_cleanup(int argc, char **argv)
{
        struct sigaction sigact;

        sigact.sa_handler = signal_server;
        sigfillset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sigact, NULL);

        do_disconnect(argv[0], 1);
}
