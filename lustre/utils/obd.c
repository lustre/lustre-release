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

#include "obdctl.h"

#include <obd.h>          /* for struct lov_stripe_md */
#include <lustre/lustre_build_version.h>

#include <unistd.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_ASM_PAGE_H
#include <asm/page.h>           /* needed for PAGE_SIZE - rread */
#endif

#include <obd_class.h>
#include <lnet/lnetctl.h>
#include "parser.h"
#include "platform.h"
#include <stdio.h>

#define MAX_STRING_SIZE 128
#define DEVICES_LIST "/proc/fs/lustre/devices"

#if HAVE_LIBPTHREAD
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

#define MAX_THREADS 1024

struct shared_data {
        __u64 counters[MAX_THREADS];
        __u64 offsets[MAX_THREADS];
        int   running;
        int   barrier;
        int   stop;
        l_mutex_t mutex;
        l_cond_t  cond;
};

static struct shared_data *shared_data;
static __u64 counter_snapshot[2][MAX_THREADS];
static int prev_valid;
static struct timeval prev_time;
static int thread;
static int nthreads;
#else
const int thread = 0;
const int nthreads = 1;
#endif

static char rawbuf[8192];
static char *buf = rawbuf;
static int max = sizeof(rawbuf);

static int cur_device = -1;


#define MAX_STRIPES     170
struct lov_oinfo lov_oinfos[MAX_STRIPES];

struct lsm_buffer {
        struct lov_stripe_md lsm;
        struct lov_oinfo *ptrs[MAX_STRIPES];
} lsm_buffer;

static int l2_ioctl(int dev_id, int opc, void *buf)
{
        return l_ioctl(dev_id, opc, buf);
}

#define IOC_INIT(data)                                                  \
do {                                                                    \
        memset(&data, 0, sizeof(data));                                 \
        data.ioc_dev = cur_device;                                      \
} while (0)

#define IOC_PACK(func, data)                                            \
do {                                                                    \
        memset(buf, 0, sizeof(rawbuf));                                 \
        if (obd_ioctl_pack(&data, &buf, max)) {                         \
                fprintf(stderr, "error: %s: invalid ioctl\n",           \
                        jt_cmdname(func));                                 \
                return -2;                                              \
        }                                                               \
} while (0)

#define IOC_UNPACK(func, data)                                          \
do {                                                                    \
        if (obd_ioctl_unpack(&data, buf, max)) {                        \
                fprintf(stderr, "error: %s: invalid reply\n",           \
                        jt_cmdname(func));                                 \
                return -2;                                              \
        }                                                               \
} while (0)

int lcfg_ioctl(char * func, int dev_id, struct lustre_cfg *lcfg)
{
        struct obd_ioctl_data data;
        int rc;

        IOC_INIT(data);
        data.ioc_type = LUSTRE_CFG_TYPE;
        data.ioc_plen1 = lustre_cfg_len(lcfg->lcfg_bufcount,
                                        lcfg->lcfg_buflens);
        data.ioc_pbuf1 = (void *)lcfg;
        IOC_PACK(func, data);

        rc =  l_ioctl(dev_id, OBD_IOC_PROCESS_CFG, buf);

        return rc;
}

static int do_device(char *func, char *devname);

int lcfg_mgs_ioctl(char *func, int dev_id, struct lustre_cfg *lcfg)
{
        struct obd_ioctl_data data;
        static int mgs_device = -1;
        char mgs[] = "$MGS";
        int rc;

        /* Always operates on MGS dev */
        if (mgs_device == -1) {
                do_disconnect(NULL, 1);
                rc = do_device("mgsioc", mgs);
                if (rc) {
                        errno = ENODEV;
                        return -1;
                }
                mgs_device = cur_device;
        }

        IOC_INIT(data);
        data.ioc_dev = mgs_device;
        data.ioc_type = LUSTRE_CFG_TYPE;
        data.ioc_plen1 = lustre_cfg_len(lcfg->lcfg_bufcount,
                                        lcfg->lcfg_buflens);
        data.ioc_pbuf1 = (void *)lcfg;
        IOC_PACK(func, data);

        rc =  l_ioctl(dev_id, OBD_IOC_PARAM, buf);

        if (rc == ENODEV)
                fprintf(stderr, "Is the MGS running on this node?\n");
        if (rc == ENOSYS)
                fprintf(stderr, "Make sure cfg_device is set first.\n");
        if (rc == EINVAL)
                fprintf(stderr, "cfg_device should be of the form "
                        "'lustre-MDT0000'\n");

        return rc;
}

char *obdo_print(struct obdo *obd)
{
        char buf[1024];

        sprintf(buf, "id: "LPX64"\ngrp: "LPX64"\natime: "LPU64"\nmtime: "LPU64
                "\nctime: "LPU64"\nsize: "LPU64"\nblocks: "LPU64
                "\nblksize: %u\nmode: %o\nuid: %d\ngid: %d\nflags: %x\n"
                "misc: %x\nnlink: %d,\nvalid "LPX64"\n",
                obd->o_id, obd->o_gr, obd->o_atime, obd->o_mtime, obd->o_ctime,
                obd->o_size, obd->o_blocks, obd->o_blksize, obd->o_mode,
                obd->o_uid, obd->o_gid, obd->o_flags, obd->o_misc,
                obd->o_nlink, obd->o_valid);
        return strdup(buf);
}


#define BAD_VERBOSE (-999999999)

#define N2D_OFF 0x100      /* So we can tell between error codes and devices */

static int do_name2dev(char *func, char *name)
{
        struct obd_ioctl_data data;
        int rc;

        IOC_INIT(data);

        data.ioc_inllen1 = strlen(name) + 1;
        data.ioc_inlbuf1 = name;

        IOC_PACK(func, data);
        rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_NAME2DEV, buf);
        if (rc < 0)
                return errno;
        IOC_UNPACK(func, data);

        return data.ioc_dev + N2D_OFF;
}

/*
 * resolve a device name to a device number.
 * supports a number, $name or %uuid.
 */
int parse_devname(char *func, char *name)
{
        int rc;
        int ret = -1;

        if (!name)
                return ret;
        if (isdigit(name[0])) {
                ret = strtoul(name, NULL, 0);
        } else {
                if (name[0] == '$' || name[0] == '%')
                        name++;
                rc = do_name2dev(func, name);
                if (rc >= N2D_OFF) {
                        ret = rc - N2D_OFF;
                        // printf("Name %s is device %d\n", name, ret);
                } else {
                        fprintf(stderr, "No device found for name %s: %s\n",
                               name, strerror(rc));
                }
        }
        return ret;
}

static void
reset_lsmb (struct lsm_buffer *lsmb)
{
        memset (&lsmb->lsm, 0, sizeof (lsmb->lsm));
        memset(lov_oinfos, 0, sizeof(lov_oinfos));
        lsmb->lsm.lsm_magic = LOV_MAGIC;
}

static int
parse_lsm (struct lsm_buffer *lsmb, char *string)
{
        struct lov_stripe_md *lsm = &lsmb->lsm;
        char                 *end;
        int                   i;

        /*
         * object_id[=size#count[@offset:id]*]
         */

        reset_lsmb (lsmb);

        lsm->lsm_object_id = strtoull (string, &end, 0);
        if (end == string)
                return (-1);
        string = end;

        if (*string == 0)
                return (0);

        if (*string != '=')
                return (-1);
        string++;

        lsm->lsm_stripe_size = strtoul (string, &end, 0);
        if (end == string)
                return (-1);
        string = end;

        if (*string != '#')
                return (-1);
        string++;

        lsm->lsm_stripe_count = strtoul (string, &end, 0);
        if (end == string)
                return (-1);
        string = end;

        if (*string == 0)               /* don't have to specify obj ids */
                return (0);

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                if (*string != '@')
                        return (-1);
                string++;
                lsm->lsm_oinfo[i]->loi_ost_idx = strtoul(string, &end, 0);
                if (*end != ':')
                        return (-1);
                string = end + 1;
                lsm->lsm_oinfo[i]->loi_id = strtoull(string, &end, 0);
                string = end;
        }

        if (*string != 0)
                return (-1);

        return (0);
}

char *jt_cmdname(char *func)
{
        static char buf[512];

        if (thread) {
                sprintf(buf, "%s-%d", func, thread);
                return buf;
        }

        return func;
}

#define difftime(a, b)                                  \
        ((a)->tv_sec - (b)->tv_sec +                    \
         ((a)->tv_usec - (b)->tv_usec) / 1000000.0)

static int be_verbose(int verbose, struct timeval *next_time,
                      __u64 num, __u64 *next_num, int num_total)
{
        struct timeval now;

        if (!verbose)
                return 0;

        if (next_time != NULL)
                gettimeofday(&now, NULL);

        /* A positive verbosity means to print every X iterations */
        if (verbose > 0 && (num >= *next_num || num >= num_total)) {
                *next_num += verbose;
                if (next_time) {
                        next_time->tv_sec = now.tv_sec - verbose;
                        next_time->tv_usec = now.tv_usec;
                }
                return 1;
        }

        /* A negative verbosity means to print at most each X seconds */
        if (verbose < 0 && next_time != NULL &&
            difftime(&now, next_time) >= 0.0){
                next_time->tv_sec = now.tv_sec - verbose;
                next_time->tv_usec = now.tv_usec;
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
                                jt_cmdname(func), arg);
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
        lcfg_set_devname(NULL);
        cur_device = -1;
        return 0;
}

#ifdef MAX_THREADS
static void shmem_setup(void)
{
        /* Create new segment */
        int shmid = shmget(IPC_PRIVATE, sizeof(*shared_data), 0600);

        if (shmid == -1) {
                fprintf(stderr, "Can't create shared data: %s\n",
                        strerror(errno));
                return;
        }

        /* Attatch to new segment */
        shared_data = (struct shared_data *)shmat(shmid, NULL, 0);

        if (shared_data == (struct shared_data *)(-1)) {
                fprintf(stderr, "Can't attach shared data: %s\n",
                        strerror(errno));
                shared_data = NULL;
                return;
        }

        /* Mark segment as destroyed, so it will disappear when we exit.
         * Forks will inherit attached segments, so we should be OK.
         */
        if (shmctl(shmid, IPC_RMID, NULL) == -1) {
                fprintf(stderr, "Can't destroy shared data: %s\n",
                        strerror(errno));
        }
}

static inline void shmem_lock(void)
{
        l_mutex_lock(&shared_data->mutex);
}

static inline void shmem_unlock(void)
{
        l_mutex_unlock(&shared_data->mutex);
}

static inline void shmem_reset(int total_threads)
{
        if (shared_data == NULL)
                return;

        memset(shared_data, 0, sizeof(*shared_data));
        l_mutex_init(&shared_data->mutex);
        l_cond_init(&shared_data->cond);
        memset(counter_snapshot, 0, sizeof(counter_snapshot));
        prev_valid = 0;
        shared_data->barrier = total_threads;
}

static inline void shmem_bump(void)
{
        static int bumped_running;

        if (shared_data == NULL || thread <= 0 || thread > MAX_THREADS)
                return;

        shmem_lock();
        shared_data->counters[thread - 1]++;
        if (!bumped_running)
                shared_data->running++;
        shmem_unlock();
        bumped_running = 1;
}

static void shmem_snap(int total_threads, int live_threads)
{
        struct timeval this_time;
        int non_zero = 0;
        __u64 total = 0;
        double secs;
        int running;
        int i;

        if (shared_data == NULL || total_threads > MAX_THREADS)
                return;

        shmem_lock();
        memcpy(counter_snapshot[0], shared_data->counters,
               total_threads * sizeof(counter_snapshot[0][0]));
        running = shared_data->running;
        shmem_unlock();

        gettimeofday(&this_time, NULL);

        for (i = 0; i < total_threads; i++) {
                long long this_count =
                        counter_snapshot[0][i] - counter_snapshot[1][i];

                if (this_count != 0) {
                        non_zero++;
                        total += this_count;
                }
        }

        secs = (this_time.tv_sec + this_time.tv_usec / 1000000.0) -
               (prev_time.tv_sec + prev_time.tv_usec / 1000000.0);

        if (prev_valid &&
            live_threads == total_threads &&
            secs > 0.0)                    /* someone screwed with the time? */
                printf("%d/%d Total: %f/second\n", non_zero, total_threads, total / secs);

        memcpy(counter_snapshot[1], counter_snapshot[0],
               total_threads * sizeof(counter_snapshot[0][0]));
        prev_time = this_time;
        if (!prev_valid &&
            running == total_threads)
                prev_valid = 1;
}

static void shmem_stop(void)
{
        if (shared_data == NULL)
                return;

        shared_data->stop = 1;
}

static int shmem_running(void)
{
        return (shared_data == NULL ||
                !shared_data->stop);
}
#else
static void shmem_setup(void)
{
}

static inline void shmem_reset(int total_threads)
{
}

static inline void shmem_bump(void)
{
}

static void shmem_lock()
{
}

static void shmem_unlock()
{
}

static void shmem_stop(void)
{
}

static int shmem_running(void)
{
        return 1;
}
#endif

extern command_t cmdlist[];

static int do_device(char *func, char *devname)
{
        int dev;

        dev = parse_devname(func, devname);
        if (dev < 0)
                return -1;

        lcfg_set_devname(devname);
        cur_device = dev;
        return 0;
}

int jt_obd_get_device()
{
        return cur_device;
}

int jt_obd_device(int argc, char **argv)
{
        int rc;

        if (argc > 2)
                return CMD_HELP;

        if (argc == 1) {
                printf("current device is %d - %s\n",
                       cur_device, lcfg_get_devname() ? : "not set");
                return 0;
        }
        rc = do_device("device", argv[1]);
        return rc;
}

int jt_opt_device(int argc, char **argv)
{
        int ret;
        int rc;

        if (argc < 3)
                return CMD_HELP;

        rc = do_device("device", argv[1]);

        if (!rc)
                rc = Parser_execarg(argc - 2, argv + 2, cmdlist);

        ret = do_disconnect(argv[0], 0);
        if (!rc)
                rc = ret;

        return rc;
}

#ifdef MAX_THREADS
static void parent_sighandler (int sig)
{
        return;
}

int jt_opt_threads(int argc, char **argv)
{
        static char      cmdstr[128];
        sigset_t         saveset;
        sigset_t         sigset;
        struct sigaction sigact;
        struct sigaction saveact1;
        struct sigaction saveact2;
        unsigned long    threads;
        __u64            next_thread;
        int verbose;
        int rc = 0;
        int report_count = -1;
        char *end;
        int i;

        if (argc < 5)
                return CMD_HELP;

        threads = strtoul(argv[1], &end, 0);

        if (*end == '.')
                report_count = strtoul(end + 1, &end, 0);

        if (*end || threads > MAX_THREADS) {
                fprintf(stderr, "error: %s: invalid thread count '%s'\n",
                        jt_cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }

        verbose = get_verbose(argv[0], argv[2]);
        if (verbose == BAD_VERBOSE)
                return CMD_HELP;

        if (verbose != 0) {
                snprintf(cmdstr, sizeof(cmdstr), "%s", argv[4]);
                for (i = 5; i < argc; i++)
                        snprintf(cmdstr + strlen(cmdstr), sizeof(cmdstr),
                                 " %s", argv[i]);

                printf("%s: starting %ld threads on device %s running %s\n",
                       argv[0], threads, argv[3], cmdstr);
        }

        shmem_reset(threads);

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGALRM);
        sigaddset(&sigset, SIGCHLD);
        sigprocmask(SIG_BLOCK, &sigset, &saveset);

        nthreads = threads;

        for (i = 1, next_thread = verbose; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n", argv[0], i,
                                strerror(rc = errno));
                        break;
                } else if (rc == 0) {
                        sigprocmask(SIG_SETMASK, &saveset, NULL);

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

                sigemptyset(&sigset);
                sigemptyset(&sigact.sa_mask);
                sigact.sa_handler = parent_sighandler;
                sigact.sa_flags = 0;

                sigaction(SIGALRM, &sigact, &saveact1);
                sigaction(SIGCHLD, &sigact, &saveact2);

                while (live_threads > 0) {
                        int status;
                        pid_t ret;

                        if (verbose < 0)        /* periodic stats */
                                alarm(-verbose);

                        sigsuspend(&sigset);
                        alarm(0);

                        while (live_threads > 0) {
                                ret = waitpid(0, &status, WNOHANG);
                                if (ret == 0)
                                        break;

                                if (ret < 0) {
                                        fprintf(stderr, "error: %s: wait - %s\n",
                                                argv[0], strerror(errno));
                                        if (!rc)
                                                rc = errno;
                                        continue;
                                } else {
                                        /*
                                         * This is a hack.  We _should_ be able
                                         * to use WIFEXITED(status) to see if
                                         * there was an error, but it appears
                                         * to be broken and it always returns 1
                                         * (OK).  See wait(2).
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

                        /* Show stats while all threads running */
                        if (verbose < 0) {
                                shmem_snap(threads, live_threads);
                                if (report_count > 0 && --report_count == 0)
                                        shmem_stop();
                        }
                }
                sigaction(SIGCHLD, &saveact2, NULL);
                sigaction(SIGALRM, &saveact1, NULL);
        }

        sigprocmask(SIG_SETMASK, &saveset, NULL);

        return rc;
}
#else
int jt_opt_threads(int argc, char **argv)
{
        fprintf(stderr, "%s not-supported in a single-threaded runtime\n",
                jt_cmdname(argv[0]));
        return CMD_HELP;
}
#endif

int jt_opt_net(int argc, char **argv)
{
        char *arg2[3];
        int rc;

        if (argc < 3)
                return CMD_HELP;

        arg2[0] = argv[0];
        arg2[1] = argv[1];
        arg2[2] = NULL;
        rc = jt_ptl_network (2, arg2);

        if (!rc)
                rc = Parser_execarg(argc - 2, argv + 2, cmdlist);

        return rc;
}

int jt_obd_no_transno(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOC_INIT(data);

        if (argc != 1)
                return CMD_HELP;

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_NO_TRANSNO, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_set_readonly(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOC_INIT(data);

        if (argc != 1)
                return CMD_HELP;

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_SET_READONLY, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_abort_recovery(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOC_INIT(data);

        if (argc != 1)
                return CMD_HELP;

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_ABORT_RECOVERY, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_get_version(int argc, char **argv)
{
        int rc;
        char buf[8192];
        struct obd_ioctl_data *data = (struct obd_ioctl_data *)buf;

        if (argc != 1)
                return CMD_HELP;

        memset(buf, 0, sizeof(buf));
        data->ioc_version = OBD_IOCTL_VERSION;
        data->ioc_inllen1 = sizeof(buf) - size_round(sizeof(*data));
        data->ioc_inlbuf1 = buf + size_round(sizeof(*data));
        data->ioc_len = obd_ioctl_packlen(data);

        rc = l2_ioctl(OBD_DEV_ID, OBD_GET_VERSION, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        else {
                printf("Lustre version: %s\n", data->ioc_bulk);
        }

        printf("lctl   version: %s\n", BUILD_VERSION);
        return rc;
}

/*
 * Print an obd device line with the ost_conn_uuid inserted, if the obd
 * is an osc.
 */
static void print_obd_line(char *s)
{
        char buf[MAX_STRING_SIZE];
        char obd_name[MAX_OBD_NAME];
        FILE *fp = NULL;
        char *ptr;

        if (sscanf(s, " %*d %*s osc %s %*s %*d ", obd_name) == 0)
                goto try_mdc;
        snprintf(buf, sizeof(buf),
                 "/proc/fs/lustre/osc/%s/ost_conn_uuid", obd_name);
        if ((fp = fopen(buf, "r")) == NULL)
                goto try_mdc;
        goto got_one;

try_mdc:
        if (sscanf(s, " %*d %*s mdc %s %*s %*d ", obd_name) == 0)
                goto fail;
        snprintf(buf, sizeof(buf),
                 "/proc/fs/lustre/mdc/%s/mds_conn_uuid", obd_name);
        if ((fp = fopen(buf, "r")) == NULL)
                goto fail;

got_one:
        fgets(buf, sizeof(buf), fp);
        fclose(fp);

        /* trim trailing newlines */
        ptr = strrchr(buf, '\n');
        if (ptr) *ptr = '\0';
        ptr = strrchr(s, '\n');
        if (ptr) *ptr = '\0';

        printf("%s %s\n", s, buf);
        return;

fail:
        printf("%s", s);
        return;
}

/* get device list by ioctl */
int jt_obd_list_ioctl(int argc, char **argv)
{
        int rc, index;
        char buf[8192];
        struct obd_ioctl_data *data = (struct obd_ioctl_data *)buf;

        if (argc > 2)
                return CMD_HELP;
        /* Just ignore a -t option.  Only supported with /proc. */
        else if (argc == 2 && strcmp(argv[1], "-t") != 0)
                return CMD_HELP;

        for (index = 0;; index++) {
                memset(buf, 0, sizeof(buf));
                data->ioc_version = OBD_IOCTL_VERSION;
                data->ioc_inllen1 = sizeof(buf) - size_round(sizeof(*data));
                data->ioc_inlbuf1 = buf + size_round(sizeof(*data));
                data->ioc_len = obd_ioctl_packlen(data);
                data->ioc_count = index;

                rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_GETDEVICE, buf);
                if (rc != 0)
                        break;
                printf("%s\n", (char *)data->ioc_bulk);
        }
        if (rc != 0) {
                if (errno == ENOENT)
                        /* no device or the last device */
                        rc = 0;
                else
                        fprintf(stderr, "Error getting device list: %s: "
                                        "check dmesg.\n",
                                        strerror(errno));
        }
        return rc;
}

int jt_obd_list(int argc, char **argv)
{
        int rc;
        char buf[MAX_STRING_SIZE];
        FILE *fp = NULL;
        int print_obd = 0;

        if (argc > 2)
                return CMD_HELP;
        else if (argc == 2) {
                if (strcmp(argv[1], "-t") == 0)
                        print_obd = 1;
                else
                        return CMD_HELP;
        }

        fp = fopen(DEVICES_LIST, "r");
        if (fp == NULL) {
                fprintf(stderr, "error: %s: %s opening "DEVICES_LIST"\n",
                        jt_cmdname(argv[0]), strerror(rc =  errno));
                return jt_obd_list_ioctl(argc, argv);
        }

        while (fgets(buf, sizeof(buf), fp) != NULL)
                if (print_obd)
                        print_obd_line(buf);
                else
                        printf("%s", buf);

        fclose(fp);
        return 0;
}




/* Create one or more objects, arg[4] may describe stripe meta-data.  If
 * not, defaults assumed.  This echo-client instance stashes the stripe
 * object ids.  Use get_stripe on this node to print full lsm and
 * set_stripe on another node to cut/paste between nodes.
 */
/* create <count> [<file_create_mode>] [q|v|# verbosity] [striping] */
int jt_obd_create(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval next_time;
        __u64 count = 1, next_count, base_id = 0;
        int verbose = 1, mode = 0100644, rc = 0, i, valid_lsm = 0;
        char *end;

        IOC_INIT(data);
        if (argc < 2 || argc > 5)
                return CMD_HELP;

        count = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid iteration count '%s'\n",
                        jt_cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }

        if (argc > 2) {
                mode = strtoul(argv[2], &end, 0);
                if (*end) {
                        fprintf(stderr, "error: %s: invalid mode '%s'\n",
                                jt_cmdname(argv[0]), argv[2]);
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

        if (argc < 5)
                reset_lsmb (&lsm_buffer);       /* will set default */
        else {
                rc = parse_lsm (&lsm_buffer, argv[4]);
                if (rc != 0) {
                        fprintf(stderr, "error: %s: invalid lsm '%s'\n",
                                jt_cmdname(argv[0]), argv[4]);
                        return CMD_HELP;
                }
                base_id = lsm_buffer.lsm.lsm_object_id;
                valid_lsm = 1;
        }

        printf("%s: "LPD64" objects\n", jt_cmdname(argv[0]), count);
        gettimeofday(&next_time, NULL);
        next_time.tv_sec -= verbose;

        for (i = 1, next_count = verbose; i <= count && shmem_running(); i++) {
                data.ioc_obdo1.o_mode = mode;
                data.ioc_obdo1.o_id = base_id;
                data.ioc_obdo1.o_uid = 0;
                data.ioc_obdo1.o_gid = 0;
                data.ioc_obdo1.o_valid = OBD_MD_FLTYPE | OBD_MD_FLMODE |
                        OBD_MD_FLID | OBD_MD_FLUID | OBD_MD_FLGID;

                if (valid_lsm) {
                        data.ioc_plen1 = sizeof lsm_buffer;
                        data.ioc_pbuf1 = (char *)&lsm_buffer;
                }

                IOC_PACK(argv[0], data);
                rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_CREATE, buf);
                IOC_UNPACK(argv[0], data);
                shmem_bump();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n",
                                jt_cmdname(argv[0]), i, strerror(rc = errno));
                        break;
                }
                if (!(data.ioc_obdo1.o_valid & OBD_MD_FLID)) {
                        fprintf(stderr,"error: %s: oid not valid #%d:"LPX64"\n",
                                jt_cmdname(argv[0]), i, data.ioc_obdo1.o_valid);
                        rc = EINVAL;
                        break;
                }

                if (be_verbose(verbose, &next_time, i, &next_count, count))
                        printf("%s: #%d is object id "LPX64"\n",
                                jt_cmdname(argv[0]), i, data.ioc_obdo1.o_id);
        }
        return rc;
}

int jt_obd_setattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        char *end;
        int rc;

        IOC_INIT(data);
        if (argc != 2)
                return CMD_HELP;

        data.ioc_obdo1.o_id = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid objid '%s'\n",
                        jt_cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }
        data.ioc_obdo1.o_mode = S_IFREG | strtoul(argv[2], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid mode '%s'\n",
                        jt_cmdname(argv[0]), argv[2]);
                return CMD_HELP;
        }
        data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_SETATTR, buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_test_setattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval start, next_time;
        __u64 i, count, next_count;
        int verbose = 1;
        obd_id objid = 3;
        char *end;
        int rc = 0;

        if (argc < 2 || argc > 4)
                return CMD_HELP;

        IOC_INIT(data);
        count = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid iteration count '%s'\n",
                        jt_cmdname(argv[0]), argv[1]);
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
                                jt_cmdname(argv[0]), argv[3]);
                        return CMD_HELP;
                }
        }

        gettimeofday(&start, NULL);
        next_time.tv_sec = start.tv_sec - verbose;
        next_time.tv_usec = start.tv_usec;
        if (verbose != 0)
                printf("%s: setting "LPD64" attrs (objid "LPX64"): %s",
                       jt_cmdname(argv[0]), count, objid, ctime(&start.tv_sec));

        for (i = 1, next_count = verbose; i <= count && shmem_running(); i++) {
                data.ioc_obdo1.o_id = objid;
                data.ioc_obdo1.o_mode = S_IFREG;
                data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;
                IOC_PACK(argv[0], data);
                rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_SETATTR, &data);
                shmem_bump();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #"LPD64" - %d:%s\n",
                                jt_cmdname(argv[0]), i, errno, strerror(rc = errno));
                        break;
                } else {
                        if (be_verbose
                            (verbose, &next_time, i, &next_count, count))
                                printf("%s: set attr #"LPD64"\n",
                                       jt_cmdname(argv[0]), i);
                }
        }

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = difftime(&end, &start);

                --i;
                if (verbose != 0)
                        printf("%s: "LPD64" attrs in %.3fs (%.3f attr/s): %s",
                               jt_cmdname(argv[0]), i, diff, i / diff,
                               ctime(&end.tv_sec));
        }
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

        IOC_INIT(data);
        if (argc < 2 || argc > 4)
                return CMD_HELP;

        id = strtoull(argv[1], &end, 0);
        if (*end || id == 0 || errno != 0) {
                fprintf(stderr, "error: %s: invalid objid '%s'\n",
                        jt_cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }
        if (argc > 2) {
                count = strtoull(argv[2], &end, 0);
                if (*end) {
                        fprintf(stderr,
                                "error: %s: invalid iteration count '%s'\n",
                                jt_cmdname(argv[0]), argv[2]);
                        return CMD_HELP;
                }
        }

        if (argc > 3) {
                verbose = get_verbose(argv[0], argv[3]);
                if (verbose == BAD_VERBOSE)
                        return CMD_HELP;
        }

        printf("%s: "LPD64" objects\n", jt_cmdname(argv[0]), count);
        gettimeofday(&next_time, NULL);
        next_time.tv_sec -= verbose;

        for (i = 1, next_count = verbose; i <= count && shmem_running(); i++, id++) {
                data.ioc_obdo1.o_id = id;
                data.ioc_obdo1.o_mode = S_IFREG | 0644;
                data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLMODE;

                IOC_PACK(argv[0], data);
                rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_DESTROY, buf);
                IOC_UNPACK(argv[0], data);
                shmem_bump();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: objid "LPX64": %s\n",
                                jt_cmdname(argv[0]), id, strerror(rc = errno));
                        break;
                }

                if (be_verbose(verbose, &next_time, i, &next_count, count))
                        printf("%s: #%d is object id "LPX64"\n",
                               jt_cmdname(argv[0]), i, id);
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

        IOC_INIT(data);
        data.ioc_obdo1.o_id = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid objid '%s'\n",
                        jt_cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }
        /* to help obd filter */
        data.ioc_obdo1.o_mode = 0100644;
        data.ioc_obdo1.o_valid = 0xffffffff;
        printf("%s: object id "LPX64"\n", jt_cmdname(argv[0]),data.ioc_obdo1.o_id);

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_GETATTR, buf);
        IOC_UNPACK(argv[0], data);
        if (rc) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        } else {
                printf("%s: object id "LPX64", mode %o\n", jt_cmdname(argv[0]),
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

        if (argc < 2 || argc > 4)
                return CMD_HELP;

        IOC_INIT(data);
        count = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: invalid iteration count '%s'\n",
                        jt_cmdname(argv[0]), argv[1]);
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
                                jt_cmdname(argv[0]), argv[3]);
                        return CMD_HELP;
                }
        }

        gettimeofday(&start, NULL);
        next_time.tv_sec = start.tv_sec - verbose;
        next_time.tv_usec = start.tv_usec;
        if (verbose != 0)
                printf("%s: getting "LPD64" attrs (objid "LPX64"): %s",
                       jt_cmdname(argv[0]), count, objid, ctime(&start.tv_sec));

        for (i = 1, next_count = verbose; i <= count && shmem_running(); i++) {
                data.ioc_obdo1.o_id = objid;
                data.ioc_obdo1.o_mode = S_IFREG;
                data.ioc_obdo1.o_valid = 0xffffffff;
                IOC_PACK(argv[0], data);
                rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_GETATTR, &data);
                shmem_bump();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #"LPD64" - %d:%s\n",
                                jt_cmdname(argv[0]), i, errno, strerror(rc = errno));
                        break;
                } else {
                        if (be_verbose
                            (verbose, &next_time, i, &next_count, count))
                                printf("%s: got attr #"LPD64"\n",
                                       jt_cmdname(argv[0]), i);
                }
        }

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = difftime(&end, &start);

                --i;
                if (verbose != 0)
                        printf("%s: "LPD64" attrs in %.3fs (%.3f attr/s): %s",
                               jt_cmdname(argv[0]), i, diff, i / diff,
                               ctime(&end.tv_sec));
        }
        return rc;
}

/* test_brw <cnt>                                               count
        <r|w[r(repeat)x(noverify)]>                             mode
        <q|v|#(print interval)>                                 verbosity
        <npages[+offset]>                                       blocksize
        <[[<interleave_threads>]t(inc obj by thread#)]obj>      object
        [p|g<args>]                                             batch */
int jt_obd_test_brw(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval start, next_time;
        __u64 count, next_count, len, stride, thr_offset = 0, objid = 3;
        int write = 0, verbose = 1, cmd, i, rc = 0, pages = 1;
        int offset_pages = 0;
        long n;
        int repeat_offset = 0;
        unsigned long long ull;
        int  nthr_per_obj = 0;
        int  verify = 1;
        int  obj_idx = 0;
        char *end;

        if (argc < 2 || argc > 7) {
                fprintf(stderr, "error: %s: bad number of arguments: %d\n",
                        jt_cmdname(argv[0]), argc);
                return CMD_HELP;
        }

        count = strtoull(argv[1], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad iteration count '%s'\n",
                        jt_cmdname(argv[0]), argv[1]);
                return CMD_HELP;
        }

        if (argc >= 3) {
                if (argv[2][0] == 'w' || argv[2][0] == '1')
                        write = 1;
                /* else it's a read */

                if (argv[2][0] != 0)
                        for (i = 1; argv[2][i] != 0; i++)
                                switch (argv[2][i]) {
                                case 'r':
                                        repeat_offset = 1;
                                        break;

                                case 'x':
                                        verify = 0;
                                        break;

                                default:
                                        fprintf (stderr, "Can't parse cmd '%s'\n",
                                                 argv[2]);
                                        return CMD_HELP;
                                }
        }

        if (argc >= 4) {
                verbose = get_verbose(argv[0], argv[3]);
                if (verbose == BAD_VERBOSE)
                        return CMD_HELP;
        }

        if (argc >= 5) {
                pages = strtoul(argv[4], &end, 0);

                if (*end == '+')
                        offset_pages = strtoul(end + 1, &end, 0);

                if (*end != 0 ||
                    offset_pages < 0 || offset_pages >= pages) {
                        fprintf(stderr, "error: %s: bad npages[+offset] parameter '%s'\n",
                                jt_cmdname(argv[0]), argv[4]);
                        return CMD_HELP;
                }
        }

        if (argc >= 6) {
                if (thread &&
                    (n = strtol(argv[5], &end, 0)) > 0 &&
                    *end == 't' &&
                    (ull = strtoull(end + 1, &end, 0)) > 0 &&
                    *end == 0) {
                        nthr_per_obj = n;
                        objid = ull;
                } else if (thread &&
                           argv[5][0] == 't') {
                        nthr_per_obj = 1;
                        objid = strtoull(argv[5] + 1, &end, 0);
                } else {
                        nthr_per_obj = 0;
                        objid = strtoull(argv[5], &end, 0);
                }
                if (*end) {
                        fprintf(stderr, "error: %s: bad objid '%s'\n",
                                jt_cmdname(argv[0]), argv[5]);
                        return CMD_HELP;
                }
        }

        IOC_INIT(data);

        /* communicate the 'type' of brw test and batching to echo_client.
         * don't start.  we'd love to refactor this lctl->echo_client
         * interface */
        data.ioc_pbuf1 = (void *)1;
        data.ioc_plen1 = 1;

        if (argc >= 7) {
                switch(argv[6][0]) {
                        case 'g': /* plug and unplug */
                                data.ioc_pbuf1 = (void *)2;
                                data.ioc_plen1 = strtoull(argv[6] + 1, &end,
                                                          0);
                                break;
                        case 'p': /* prep and commit */
                                data.ioc_pbuf1 = (void *)3;
                                data.ioc_plen1 = strtoull(argv[6] + 1, &end,
                                                          0);
                                break;
                        default:
                                fprintf(stderr, "error: %s: batching '%s' "
                                        "needs to specify 'p' or 'g'\n",
                                        jt_cmdname(argv[0]), argv[6]);
                                return CMD_HELP;
                }

                if (*end) {
                        fprintf(stderr, "error: %s: bad batching '%s'\n",
                                jt_cmdname(argv[0]), argv[6]);
                        return CMD_HELP;
                }
                data.ioc_plen1 *= getpagesize();
        }

        len = pages * getpagesize();
        thr_offset = offset_pages * getpagesize();
        stride = len;

#ifdef MAX_THREADS
        if (thread) {
                shmem_lock ();
                if (nthr_per_obj != 0) {
                        /* threads interleave */
                        obj_idx = (thread - 1)/nthr_per_obj;
                        objid += obj_idx;
                        stride *= nthr_per_obj;
                        if (thread == 1)
                                shared_data->offsets[obj_idx] = stride + thr_offset;
                        thr_offset += ((thread - 1) % nthr_per_obj) * len;
                } else {
                        /* threads disjoint */
                        thr_offset += (thread - 1) * len;
                }

                shared_data->barrier--;
                if (shared_data->barrier == 0)
                        l_cond_broadcast(&shared_data->cond);
                else
                        l_cond_wait(&shared_data->cond,
                                          &shared_data->mutex);

                shmem_unlock ();
        }
#endif

        data.ioc_obdo1.o_id = objid;
        data.ioc_obdo1.o_mode = S_IFREG;
        data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLFLAGS;
        data.ioc_obdo1.o_flags = (verify ? OBD_FL_DEBUG_CHECK : 0);
        data.ioc_count = len;
        data.ioc_offset = (repeat_offset ? 0 : thr_offset);

        gettimeofday(&start, NULL);
        next_time.tv_sec = start.tv_sec - verbose;
        next_time.tv_usec = start.tv_usec;

        if (verbose != 0)
                printf("%s: %s "LPU64"x%d pages (obj "LPX64", off "LPU64"): %s",
                       jt_cmdname(argv[0]), write ? "writing" : "reading", count,
                       pages, objid, data.ioc_offset, ctime(&start.tv_sec));

        cmd = write ? OBD_IOC_BRW_WRITE : OBD_IOC_BRW_READ;
        for (i = 1, next_count = verbose; i <= count && shmem_running(); i++) {
                data.ioc_obdo1.o_valid &= ~(OBD_MD_FLBLOCKS|OBD_MD_FLGRANT);
                IOC_PACK(argv[0], data);
                rc = l2_ioctl(OBD_DEV_ID, cmd, buf);
                shmem_bump();
                if (rc) {
                        fprintf(stderr, "error: %s: #%d - %s on %s\n",
                                jt_cmdname(argv[0]), i, strerror(rc = errno),
                                write ? "write" : "read");
                        break;
                } else if (be_verbose(verbose, &next_time,i, &next_count,count)) {
                        shmem_lock ();
                        printf("%s: %s number %d @ "LPD64":"LPU64" for %d\n",
                               jt_cmdname(argv[0]), write ? "write" : "read", i,
                               data.ioc_obdo1.o_id, data.ioc_offset,
                               (int)(pages * getpagesize()));
                        shmem_unlock ();
                }

                if (!repeat_offset) {
#ifdef MAX_THREADS
                        if (stride == len) {
                                data.ioc_offset += stride;
                        } else if (i < count) {
                                shmem_lock ();
                                data.ioc_offset = shared_data->offsets[obj_idx];
                                shared_data->offsets[obj_idx] += len;
                                shmem_unlock ();
                        }
#else
                        data.ioc_offset += len;
                        obj_idx = 0; /* avoids an unused var warning */
#endif
                }
        }

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = difftime(&end, &start);

                --i;
                if (verbose != 0)
                        printf("%s: %s %dx%d pages in %.3fs (%.3f MB/s): %s",
                               jt_cmdname(argv[0]), write ? "wrote" : "read",
                               i, pages, diff,
                               ((double)i * pages * getpagesize()) /
                               (diff * 1048576.0),
                               ctime(&end.tv_sec));
        }

        return rc;
}

int jt_obd_lov_getconfig(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct lov_desc desc;
        struct obd_uuid *uuidarray;
        __u32 *obdgens;
        char *path;
        int rc, fd;

        IOC_INIT(data);

        if (argc != 2)
                return CMD_HELP;

        path = argv[1];
        fd = open(path, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "open \"%s\" failed: %s\n", path,
                        strerror(errno));
                return -errno;
        }

        memset(&desc, 0, sizeof(desc));
        obd_str2uuid(&desc.ld_uuid, argv[1]);
        desc.ld_tgt_count = ((OBD_MAX_IOCTL_BUFFER-sizeof(data)-sizeof(desc)) /
                             (sizeof(*uuidarray) + sizeof(*obdgens)));


repeat:
        uuidarray = calloc(desc.ld_tgt_count, sizeof(*uuidarray));
        if (!uuidarray) {
                fprintf(stderr, "error: %s: no memory for %d uuid's\n",
                        jt_cmdname(argv[0]), desc.ld_tgt_count);
                rc = -ENOMEM;
                goto out;
        }
        obdgens = calloc(desc.ld_tgt_count, sizeof(*obdgens));
        if (!obdgens) {
                fprintf(stderr, "error: %s: no memory for %d generation #'s\n",
                        jt_cmdname(argv[0]), desc.ld_tgt_count);
                rc = -ENOMEM;
                goto out_uuidarray;
        }

        data.ioc_inllen1 = sizeof(desc);
        data.ioc_inlbuf1 = (char *)&desc;
        data.ioc_inllen2 = desc.ld_tgt_count * sizeof(*uuidarray);
        data.ioc_inlbuf2 = (char *)uuidarray;
        data.ioc_inllen3 = desc.ld_tgt_count * sizeof(*obdgens);
        data.ioc_inlbuf3 = (char *)obdgens;

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n",
                        jt_cmdname(argv[0]));
                rc = -EINVAL;
                goto out_obdgens;
        }
        rc = ioctl(fd, OBD_IOC_LOV_GET_CONFIG, buf);
        if (rc == -ENOSPC) {
                free(uuidarray);
                free(obdgens);
                goto repeat;
        } else if (rc) {
                fprintf(stderr, "error: %s: ioctl error: %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));
        } else {
                struct obd_uuid *uuidp;
                __u32 *genp;
                int i;

                if (obd_ioctl_unpack(&data, buf, max)) {
                        fprintf(stderr, "error: %s: invalid reply\n",
                                jt_cmdname(argv[0]));
                        rc = -EINVAL;
                        goto out;
                }
                if (desc.ld_default_stripe_count == (__u16)-1)
                        printf("default_stripe_count: %d\n", -1);
                else
                        printf("default_stripe_count: %u\n",
                               desc.ld_default_stripe_count);
                printf("default_stripe_size: "LPU64"\n",
                       desc.ld_default_stripe_size);
                printf("default_stripe_offset: "LPU64"\n",
                       desc.ld_default_stripe_offset);
                printf("default_stripe_pattern: %u\n", desc.ld_pattern);
                printf("obd_count: %u\n", desc.ld_tgt_count);
                printf("OBDS:\tobdidx\t\tobdgen\t\t obduuid\n");
                uuidp = uuidarray;
                genp = obdgens;
                for (i = 0; i < desc.ld_tgt_count; i++, uuidp++, genp++)
                        printf("\t%6u\t%14u\t\t %s\n", i, *genp, (char *)uuidp);
        }
out_obdgens:
        free(obdgens);
out_uuidarray:
        free(uuidarray);
out:
        close(fd);
        return rc;
}

int jt_obd_ldlm_regress_start(int argc, char **argv)
{
        int rc;
        struct obd_ioctl_data data;
        char argstring[200];
        int i, count = sizeof(argstring) - 1;

        IOC_INIT(data);
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

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, IOC_LDLM_REGRESS_START, buf);
        if (rc)
                fprintf(stderr, "error: %s: test failed: %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));

        return rc;
}

int jt_obd_ldlm_regress_stop(int argc, char **argv)
{
        int rc;
        struct obd_ioctl_data data;
        IOC_INIT(data);

        if (argc != 1)
                return CMD_HELP;

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, IOC_LDLM_REGRESS_STOP, buf);

        if (rc)
                fprintf(stderr, "error: %s: test failed: %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));
        return rc;
}

static int do_activate(int argc, char **argv, int flag)
{
        struct obd_ioctl_data data;
        int rc;

        IOC_INIT(data);
        if (argc != 1)
                return CMD_HELP;

        /* reuse offset for 'active' */
        data.ioc_offset = flag;

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, IOC_OSC_SET_ACTIVE, buf);
        if (rc)
                fprintf(stderr, "error: %s: failed: %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));

        return rc;
}

int jt_obd_deactivate(int argc, char **argv)
{
        return do_activate(argc, argv, 0);
}

int jt_obd_activate(int argc, char **argv)
{
        return do_activate(argc, argv, 1);
}

int jt_obd_recover(int argc, char **argv)
{
        int rc;
        struct obd_ioctl_data data;

        IOC_INIT(data);
        if (argc > 2)
                return CMD_HELP;

        if (argc == 2) {
                data.ioc_inllen1 = strlen(argv[1]) + 1;
                data.ioc_inlbuf1 = argv[1];
        }

        IOC_PACK(argv[0], data);
        rc = l2_ioctl(OBD_DEV_ID, OBD_IOC_CLIENT_RECOVER, buf);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }

        return rc;
}

int jt_obd_mdc_lookup(int argc, char **argv)
{
        struct obd_ioctl_data data;
        char *parent, *child;
        int rc, fd, verbose = 1;

        if (argc < 3 || argc > 4)
                return CMD_HELP;

        parent = argv[1];
        child = argv[2];
        if (argc == 4)
                verbose = get_verbose(argv[0], argv[3]);

        IOC_INIT(data);

        data.ioc_inllen1 = strlen(child) + 1;
        data.ioc_inlbuf1 = child;

        IOC_PACK(argv[0], data);

        fd = open(parent, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "open \"%s\" failed: %s\n", parent,
                        strerror(errno));
                return -1;
        }

        rc = ioctl(fd, IOC_MDC_LOOKUP, buf);
        if (rc < 0) {
                fprintf(stderr, "error: %s: ioctl error: %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));
        }
        close(fd);

        if (verbose) {
                IOC_UNPACK(argv[0], data);
                printf("%s: mode %o uid %d gid %d\n", child,
                       data.ioc_obdo1.o_mode, data.ioc_obdo1.o_uid,
                       data.ioc_obdo1.o_gid);
        }

        return rc;
}

int jt_cfg_dump_log(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOC_INIT(data);

        if (argc != 2)
                return CMD_HELP;

        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];

        IOC_PACK(argv[0], data);
        rc = l_ioctl(OBD_DEV_ID, OBD_IOC_DUMP_LOG, buf);
        if (rc < 0)
                fprintf(stderr, "OBD_IOC_DUMP_LOG failed: %s\n",
                        strerror(errno));

        return rc;
}

int jt_llog_catlist(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        if (argc != 1)
                return CMD_HELP;

        IOC_INIT(data);
        data.ioc_inllen1 = max - size_round(sizeof(data));
        IOC_PACK(argv[0], data);

        rc = l_ioctl(OBD_DEV_ID, OBD_IOC_CATLOGLIST, buf);
        if (rc == 0)
                fprintf(stdout, "%s", ((struct obd_ioctl_data*)buf)->ioc_bulk);
        else
                fprintf(stderr, "OBD_IOC_CATLOGLIST failed: %s\n",
                        strerror(errno));

        return rc;
}

int jt_llog_info(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        if (argc != 2)
                return CMD_HELP;

        IOC_INIT(data);
        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        data.ioc_inllen2 = max - size_round(sizeof(data)) -
                size_round(data.ioc_inllen1);
        IOC_PACK(argv[0], data);

        rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_INFO, buf);
        if (rc == 0)
                fprintf(stdout, "%s", ((struct obd_ioctl_data*)buf)->ioc_bulk);
        else
                fprintf(stderr, "OBD_IOC_LLOG_INFO failed: %s\n",
                        strerror(errno));

        return rc;
}

int jt_llog_print(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        if (argc != 2 && argc != 4)
                return CMD_HELP;

        IOC_INIT(data);
        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        if (argc == 4) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
                data.ioc_inllen3 = strlen(argv[3]) + 1;
                data.ioc_inlbuf3 = argv[3];
        } else {
                char from[2] = "1", to[3] = "-1";
                data.ioc_inllen2 = strlen(from) + 1;
                data.ioc_inlbuf2 = from;
                data.ioc_inllen3 = strlen(to) + 1;
                data.ioc_inlbuf3 = to;
        }
        data.ioc_inllen4 = max - size_round(sizeof(data)) -
                size_round(data.ioc_inllen1) -
                size_round(data.ioc_inllen2) -
                size_round(data.ioc_inllen3);
        IOC_PACK(argv[0], data);

        rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_PRINT, buf);
        if (rc == 0)
                fprintf(stdout, "%s", ((struct obd_ioctl_data*)buf)->ioc_bulk);
        else
                fprintf(stderr, "OBD_IOC_LLOG_PRINT failed: %s\n",
                        strerror(errno));

        return rc;
}

int jt_llog_cancel(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        if (argc != 4)
                return CMD_HELP;

        IOC_INIT(data);
        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        data.ioc_inllen2 = strlen(argv[2]) + 1;
        data.ioc_inlbuf2 = argv[2];
        data.ioc_inllen3 = strlen(argv[3]) + 1;
        data.ioc_inlbuf3 = argv[3];
        IOC_PACK(argv[0], data);

        rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_CANCEL, buf);
        if (rc == 0)
                fprintf(stdout, "index %s be canceled.\n", argv[3]);
        else
                fprintf(stderr, "OBD_IOC_LLOG_CANCEL failed: %s\n",
                        strerror(errno));

        return rc;

}
int jt_llog_check(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        if (argc != 2 && argc != 4)
                return CMD_HELP;

        IOC_INIT(data);
        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        if (argc == 4) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
                data.ioc_inllen3 = strlen(argv[3]) + 1;
                data.ioc_inlbuf3 = argv[3];
        } else {
                char from[2] = "1", to[3] = "-1";
                data.ioc_inllen2 = strlen(from) + 1;
                data.ioc_inlbuf2 = from;
                data.ioc_inllen3 = strlen(to) + 1;
                data.ioc_inlbuf3 = to;
        }
        data.ioc_inllen4 = max - size_round(sizeof(data)) -
                size_round(data.ioc_inllen1) -
                size_round(data.ioc_inllen2) -
                size_round(data.ioc_inllen3);
        IOC_PACK(argv[0], data);

        rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_CHECK, buf);
        if (rc == 0)
                fprintf(stdout, "%s", ((struct obd_ioctl_data*)buf)->ioc_bulk);
        else
                fprintf(stderr, "OBD_IOC_LLOG_CHECK failed: %s\n",
                        strerror(errno));
        return rc;
}

int jt_llog_remove(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        if (argc != 3 && argc != 2)
                return CMD_HELP;

        IOC_INIT(data);
        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        if (argc == 3){
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }
        IOC_PACK(argv[0], data);

        rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_REMOVE, buf);
        if (rc == 0) {
                if (argc == 3)
                        fprintf(stdout, "log %s are removed.\n", argv[2]);
                else
                        fprintf(stdout, "the log in catalog %s are removed. \n", argv[1]);
        } else
                fprintf(stderr, "OBD_IOC_LLOG_REMOVE failed: %s\n",
                        strerror(errno));

        return rc;
}

/* attach a regular file to virtual block device.
 * return vaule:
 *  -1: fatal error
 *  1: error, it always means the command run failed
 *  0: success
 */
static int jt_blockdev_run_process(const char *file, char *argv[])
{
        pid_t pid;
        int rc;

        pid = vfork();
        if (pid == 0) { /* child process */
                /* don't print error messages */
                close(1), close(2);
                (void)execvp(file, argv);
                exit(-1);
        } else if (pid > 0) {
                int status;

                rc = waitpid(pid, &status, 0);
                if (rc < 0 || !WIFEXITED(status))
                        return -1;

                return WEXITSTATUS(status);
        }

        return -1;
}

static int jt_blockdev_find_module(const char *module)
{
        FILE *fp;
        int found = 0;
        char modname[256];

        fp = fopen("/proc/modules", "r");
        if (fp == NULL)
                return -1;

        while (fscanf(fp, "%s %*s %*s %*s %*s %*s", modname) == 1) {
                if (strcmp(module, modname) == 0) {
                        found = 1;
                        break;
                }
        }
        fclose(fp);

        return found;
}

static int jt_blockdev_probe_module(const char *module)
{
        char buf[1024];
        char *argv[10];
        int c, rc;

        if (jt_blockdev_find_module(module) == 1)
                return 0;

        /* run modprobe first */
        c = 0;
        argv[c++] = "/sbin/modprobe";
        argv[c++] = "-q";
        argv[c++] = (char *)module;
        argv[c++] = NULL;
        rc = jt_blockdev_run_process("modprobe", argv);
        if (rc != 1)
                return rc;

        /* cannot find the module in default directory ... */
        sprintf(buf, "../llite/%s.ko", module);
        c = 0;
        argv[c++] = "/sbin/insmod";
        argv[c++] = buf;
        argv[c++] = NULL;
        rc = jt_blockdev_run_process("insmod", argv);
        return rc ? -1 : 0;
}

int jt_blockdev_attach(int argc, char **argv)
{
        int rc, fd;
        struct stat st;
        char *filename, *devname;
        unsigned long dev;

        if (argc != 3)
                return CMD_HELP;

        if (jt_blockdev_probe_module("llite_lloop") < 0) {
                fprintf(stderr, "error: cannot find module llite_lloop.(k)o\n");
                return ENOENT;
        }

        filename = argv[1];
        devname = argv[2];

        fd = open(filename, O_RDWR);
        if (fd < 0) {
                fprintf(stderr, "file %s can't be opened(%s)\n\n",
                        filename, strerror(errno));
                return CMD_HELP;
        }

        rc = ioctl(fd, LL_IOC_LLOOP_ATTACH, &dev);
        if (rc < 0) {
                rc = errno;
                fprintf(stderr, "attach error(%s)\n", strerror(rc));
                goto out;
        }

        rc = stat(devname, &st);
        if (rc == 0 && (!S_ISBLK(st.st_mode) || st.st_rdev != dev)) {
                rc = EEXIST;
        } else if (rc < 0) {
                if (errno == ENOENT &&
                    !mknod(devname, S_IFBLK|S_IRUSR|S_IWUSR, dev))
                        rc = 0;
                else
                        rc = errno;
        }

        if (rc) {
                fprintf(stderr, "error: the file %s could be attached to block "
                                "device %X but creating %s failed: %s\n"
                                "now detaching the block device..",
                        filename, (int)dev, devname, strerror(rc));

                (void)ioctl(fd, LL_IOC_LLOOP_DETACH_BYDEV, dev);
                fprintf(stderr, "%s\n", strerror(errno));
        }
out:
        close(fd);
        return -rc;
}

int jt_blockdev_detach(int argc, char **argv)
{
        char *filename;
        int rc, fd;

        if (argc != 2)
                return CMD_HELP;

        filename = argv[1];
        fd = open(filename, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "cannot open file %s error %s\n",
                        filename, strerror(errno));
                return CMD_HELP;
        }

        rc = ioctl(fd, LL_IOC_LLOOP_DETACH, 0);
        if (rc < 0) {
                rc = errno;
                fprintf(stderr, "detach error(%s)\n", strerror(rc));
        } else {
                (void)unlink(filename);
        }

        close(fd);
        return -rc;
}

int jt_blockdev_info(int argc, char **argv)
{
        char *filename;
        int rc, fd;
        __u64  ino;

        if (argc != 2)
                return CMD_HELP;

        filename = argv[1];
        fd = open(filename, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "cannot open file %s error: %s\n",
                        filename, strerror(errno));
                return CMD_HELP;
        }

        rc = ioctl(fd, LL_IOC_LLOOP_INFO, &ino);
        if (rc < 0) {
                rc = errno;
                fprintf(stderr, "error: %s\n", strerror(errno));
                goto out;
        }
        fprintf(stdout, "lloop device info: ");
        if (ino == 0ULL)
                fprintf(stdout, "Not attached\n");
        else
                fprintf(stdout, "attached to inode "LPU64"\n", ino);
out:
        close(fd);
        return -rc;
}

static void signal_server(int sig)
{
        if (sig == SIGINT) {
                do_disconnect("sigint", 1);
                exit(1);
        } else
                fprintf(stderr, "%s: got signal %d\n", jt_cmdname("sigint"), sig);
}

int obd_initialize(int argc, char **argv)
{
        int i;

        for (i = 0; i < MAX_STRIPES; i++)
                lsm_buffer.lsm.lsm_oinfo[i] = lov_oinfos + i;

        shmem_setup();
        register_ioc_dev(OBD_DEV_ID, OBD_DEV_PATH,
                         OBD_DEV_MAJOR, OBD_DEV_MINOR);

        return 0;
}

void obd_finalize(int argc, char **argv)
{
        struct sigaction sigact;

        sigact.sa_handler = signal_server;
        sigfillset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sigact, NULL);

        shmem_stop();
        do_disconnect(argv[0], 1);
}
