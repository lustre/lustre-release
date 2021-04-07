/*
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
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/obd.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Robert Read <rread@clusterfs.com>
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include "obdctl.h"
#include "lustreapi_internal.h"
#include <libcfs/util/list.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/param.h>
#include <libcfs/util/parser.h>
#include <libcfs/util/string.h>

#include <linux/lnet/nidstr.h>
#include <linux/lnet/lnetctl.h>
#ifdef HAVE_SERVER_SUPPPORT
#include <linux/lustre/lustre_barrier_user.h>
#include <linux/lustre/lustre_disk.h>
#endif
#include <linux/lustre/lustre_cfg.h>
#include <linux/lustre/lustre_ioctl.h>
#include <linux/lustre/lustre_ostid.h>
#include <linux/lustre/lustre_param.h>
#include <linux/lustre/lustre_ver.h>

#include <lustre/lustreapi.h>

#define MAX_STRING_SIZE 128

#if HAVE_LIBPTHREAD
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

#define MAX_THREADS 4096
#define MAX_BASE_ID 0xffffffff
#define NIDSTRING_LENGTH 64
struct shared_data {
	pthread_mutex_t	mutex;
	pthread_cond_t	cond;
	int       stopping;
	struct {
		__u64 counters[MAX_THREADS];
		__u64 offsets[MAX_THREADS];
		int   thr_running;
		int   start_barrier;
		int   stop_barrier;
		struct timeval start_time;
		struct timeval end_time;
	} body;
};

static struct shared_data *shared_data;
static __u64 counter_snapshot[2][MAX_THREADS];
static int prev_valid;
static struct timeval prev_time;
static int thread;
static int nthreads;
#else
const int thread;
const int nthreads = 1;
#endif

static int cur_device = -1;

int lcfg_ioctl(char *func, int dev_id, struct lustre_cfg *lcfg)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	data.ioc_type = LUSTRE_CFG_TYPE;
	data.ioc_plen1 = lustre_cfg_len(lcfg->lcfg_bufcount,
					lcfg->lcfg_buflens);
	data.ioc_pbuf1 = (void *)lcfg;
	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n", jt_cmdname(func));
		return rc;
	}

	rc =  l_ioctl(dev_id, OBD_IOC_PROCESS_CFG, buf);

	return rc;
}

static int do_device(char *func, char *devname);

static int get_mgs_device(void)
{
	char mgs[] = "$MGS";
	static int mgs_device = -1;

	if (mgs_device == -1) {
		int rc;

		do_disconnect(NULL, 1);
		rc = do_device("mgsioc", mgs);
		if (rc) {
			fprintf(stderr,
				"This command must be run on the MGS.\n");
			errno = ENODEV;
			return -1;
		}
		mgs_device = cur_device;
	}
	return mgs_device;
}

/* Returns -1 on error with errno set */
int lcfg_mgs_ioctl(char *func, int dev_id, struct lustre_cfg *lcfg)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	memset(&data, 0, sizeof(data));
	rc = data.ioc_dev = get_mgs_device();
	if (rc < 0)
		goto out;
	data.ioc_type = LUSTRE_CFG_TYPE;
	data.ioc_plen1 = lustre_cfg_len(lcfg->lcfg_bufcount,
					lcfg->lcfg_buflens);
	data.ioc_pbuf1 = (void *)lcfg;
	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n", jt_cmdname(func));
		return rc;
	}

	rc = l_ioctl(dev_id, OBD_IOC_PARAM, buf);
out:
	if (rc && errno == ENOSYS)
		fprintf(stderr, "Make sure cfg_device is set first.\n");

	return rc;
}

char *obdo_print(struct obdo *obd)
{
	char buf[1024];

	snprintf(buf, sizeof(buf), "id: %#jx\ngrp: %#jx\natime: %ju\n"
		 "mtime: %ju\nctime: %ju\nsize: %ju\nblocks: %ju"
		 "\nblksize: %u\nmode: %o\nuid: %d\ngid: %d\nflags: %x\n"
		 "misc: %x\nnlink: %d,\nvalid %#jx\n",
		 (uintmax_t)ostid_id(&obd->o_oi),
		 (uintmax_t)ostid_seq(&obd->o_oi),
		 (uintmax_t)obd->o_atime, (uintmax_t)obd->o_mtime,
		 (uintmax_t)obd->o_ctime, (uintmax_t)obd->o_size,
		 (uintmax_t)obd->o_blocks, obd->o_blksize, obd->o_mode,
		 obd->o_uid, obd->o_gid, obd->o_flags, obd->o_misc,
		 obd->o_nlink, (uintmax_t)obd->o_valid);
	return strdup(buf);
}

#define BAD_VERBOSE (-999999999)

#define N2D_OFF 0x100      /* So we can tell between error codes and devices */

static int do_name2dev(char *func, char *name)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	data.ioc_inllen1 = strlen(name) + 1;
	data.ioc_inlbuf1 = name;

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc < 0) {
		fprintf(stderr, "error: %s: invalid ioctl\n", jt_cmdname(func));
		return -rc;
	}
	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_NAME2DEV, buf);
	if (rc < 0)
		return errno;
	rc = llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid reply\n", jt_cmdname(func));
		return rc;
	}

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
	int try_digit;

	if (!name)
		return ret;

	try_digit = isdigit(name[0]);

	if (name[0] == '$' || name[0] == '%')
		name++;

	rc = do_name2dev(func, name);
	if (rc >= N2D_OFF)
		return rc - N2D_OFF;

	if (try_digit)
		ret = strtoul(name, NULL, 0);
	else
		fprintf(stderr, "No device found for name %s: %s\n",
			name, strerror(rc));
	return ret;
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

	if (next_time)
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
	if (verbose < 0 && next_time && difftime(&now, next_time) >= 0.0) {
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

	if (!arg || arg[0] == 'v') {
		verbose = 1;
	} else if (arg[0] == 's' || arg[0] == 'q') {
		verbose = 0;
	} else {
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
static int shmem_setup(void)
{
	pthread_mutexattr_t mattr;
	pthread_condattr_t  cattr;
	int rc;
	int shmid;

	/* Create new segment */
	shmid = shmget(IPC_PRIVATE, sizeof(*shared_data), 0600);
	if (shmid == -1) {
		fprintf(stderr, "Can't create shared data: %s\n",
			strerror(errno));
		return errno;
	}

	/* Attatch to new segment */
	shared_data = (struct shared_data *)shmat(shmid, NULL, 0);

	if (shared_data == (struct shared_data *)(-1)) {
		fprintf(stderr, "Can't attach shared data: %s\n",
			strerror(errno));
		shared_data = NULL;
		return errno;
	}

	/*
	 * Mark segment as destroyed, so it will disappear when we exit.
	 * Forks will inherit attached segments, so we should be OK.
	 */
	if (shmctl(shmid, IPC_RMID, NULL) == -1) {
		fprintf(stderr, "Can't destroy shared data: %s\n",
			strerror(errno));
		return errno;
	}

	pthread_mutexattr_init(&mattr);
	pthread_condattr_init(&cattr);

	rc = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
	if (rc != 0) {
		fprintf(stderr, "Can't set shared mutex attr\n");
		goto out;
	}

	rc = pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
	if (rc != 0) {
		fprintf(stderr, "Can't set shared cond attr\n");
		goto out;
	}

	pthread_mutex_init(&shared_data->mutex, &mattr);
	pthread_cond_init(&shared_data->cond, &cattr);
out:
	pthread_mutexattr_destroy(&mattr);
	pthread_condattr_destroy(&cattr);

	return rc;
}

static inline void shmem_lock(void)
{
	pthread_mutex_lock(&shared_data->mutex);
}

static inline void shmem_unlock(void)
{
	pthread_mutex_unlock(&shared_data->mutex);
}

static inline void shmem_wait(void)
{
	pthread_cond_wait(&shared_data->cond, &shared_data->mutex);
}

static inline void shmem_wakeup_all(void)
{
	pthread_cond_broadcast(&shared_data->cond);
}

static inline void shmem_reset(int total_threads)
{
	if (!shared_data)
		return;

	memset(&shared_data->body, 0, sizeof(shared_data->body));
	memset(counter_snapshot, 0, sizeof(counter_snapshot));
	prev_valid = 0;
	shared_data->stopping = 0;
	shared_data->body.start_barrier = total_threads;
	shared_data->body.stop_barrier = total_threads;
}

static inline void shmem_bump(__u32 counter)
{
	static bool running_not_bumped = true;

	if (!shared_data || thread <= 0 || thread > MAX_THREADS)
		return;

	shmem_lock();
	shared_data->body.counters[thread - 1] += counter;
	if (running_not_bumped) {
		shared_data->body.thr_running++;
		running_not_bumped = false;
	}
	shmem_unlock();
}

static void shmem_total(int total_threads)
{
	__u64 total = 0;
	double secs;
	int i;

	if (!shared_data || total_threads > MAX_THREADS)
		return;

	shmem_lock();
	for (i = 0; i < total_threads; i++)
		total += shared_data->body.counters[i];

	secs = difftime(&shared_data->body.end_time,
			&shared_data->body.start_time);
	shmem_unlock();

	printf("Total: total %ju threads %d sec %f %f/second\n",
	       (uintmax_t)total, total_threads, secs, total / secs);
}

static void shmem_snap(int total_threads, int live_threads)
{
	struct timeval this_time;
	int non_zero = 0;
	__u64 total = 0;
	double secs;
	int running;
	int i;

	if (!shared_data || total_threads > MAX_THREADS)
		return;

	shmem_lock();
	memcpy(counter_snapshot[0], shared_data->body.counters,
	       total_threads * sizeof(counter_snapshot[0][0]));
	running = shared_data->body.thr_running;
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

	secs = difftime(&this_time, &prev_time);
	if (prev_valid && secs > 1.0) {   /* someone screwed with the time? */
		printf("%d/%d Total: %f/second\n", non_zero, total_threads,
		       total / secs);

		memcpy(counter_snapshot[1], counter_snapshot[0],
		       total_threads * sizeof(counter_snapshot[0][0]));
		prev_time = this_time;
	}
	if (!prev_valid && running == total_threads) {
		prev_valid = 1;
		/* drop counters when all threads were started */
		memcpy(counter_snapshot[1], counter_snapshot[0],
		       total_threads * sizeof(counter_snapshot[0][0]));
		prev_time = this_time;
	}
}

static void shmem_stop(void)
{
	if (!shared_data)
		return;

	shared_data->stopping = 1;
}

static void shmem_cleanup(void)
{
	if (!shared_data)
		return;

	shmem_stop();

	pthread_mutex_destroy(&shared_data->mutex);
	pthread_cond_destroy(&shared_data->cond);
}

static int shmem_running(void)
{
	return (!shared_data || !shared_data->stopping);
}

static void shmem_end_time_locked(void)
{
	shared_data->body.stop_barrier--;
	if (shared_data->body.stop_barrier == 0)
		gettimeofday(&shared_data->body.end_time, NULL);
}

static void shmem_start_time_locked(void)
{
	shared_data->body.start_barrier--;
	if (shared_data->body.start_barrier == 0) {
		shmem_wakeup_all();
		gettimeofday(&shared_data->body.start_time, NULL);
	} else {
		shmem_wait();
	}
}

#else
static int shmem_setup(void)
{
	return 0;
}

static inline void shmem_reset(int total_threads)
{
}

static inline void shmem_bump(__u32 counters)
{
}

static void shmem_lock(void)
{
}

static void shmem_unlock(void)
{
}

static void shmem_cleanup(void)
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

int jt_obd_get_device(void)
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
static void parent_sighandler(int sig)
{
}

int jt_opt_threads(int argc, char **argv)
{
	static char      cmdstr[129];
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
			snprintf(cmdstr + strlen(cmdstr),
				 sizeof(cmdstr) - strlen(cmdstr),
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
			exit(jt_opt_device(argc - 2, argv + 2));
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
					fprintf(stderr,
						"error: %s: wait - %s\n",
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

	shmem_total(threads);
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
	rc = jt_ptl_network(2, arg2);

	if (!rc)
		rc = Parser_execarg(argc - 2, argv + 2, cmdlist);

	return rc;
}

#ifdef HAVE_SERVER_SUPPORT
/*
 * Place this here so we can build tools that work with
 * older Lustre versions
 */
#ifndef OBD_IOC_NO_TRANSNO
#define OBD_IOC_NO_TRANSNO	_IOW('f', 140, OBD_IOC_DATA_TYPE)
#endif

int jt_obd_no_transno(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	glob_t path;
	int count;
	int fd;
	int rc;

	if (argc != 1)
		return CMD_HELP;

	memset(buf, 0, sizeof(rawbuf));

	rc = cfs_get_param_paths(&path, "no_transno");
	if (rc != 0)
		goto old_ioctl;

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd < 0) {
		cfs_free_param_data(&path);
		goto old_ioctl;
	}

	snprintf(rawbuf, sizeof(rawbuf), "%d", cur_device);

	count = write(fd, rawbuf, strlen(rawbuf));
	if (count < 0)
		rc = errno;

	cfs_free_param_data(&path);
	close(fd);
	if (rc)
		goto old_ioctl;

	return 0;

old_ioctl:
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;

	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}
	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_NO_TRANSNO, buf);
	if (rc < 0)
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(rc = errno));
#endif
	return rc;
}

int jt_obd_set_readonly(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;

	if (argc != 1)
		return CMD_HELP;

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}
	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_SET_READONLY, buf);
	if (rc < 0)
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(rc = errno));

	return rc;
}

static int obd_abort_recovery(char *cmd, enum obd_abort_recovery_flags flags)
{
	struct obd_ioctl_data data = {
		.ioc_dev = cur_device,
		.ioc_type = flags,
	};
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(cmd));
		return rc;
	}
	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_ABORT_RECOVERY, buf);
	if (rc < 0)
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(cmd),
			strerror(rc = errno));

	return rc;
}

int jt_obd_abort_recovery(int argc, char **argv)
{
	if (argc != 1)
		return CMD_HELP;

	return obd_abort_recovery(argv[0], OBD_FLG_ABORT_RECOV_OST);
}

int jt_obd_abort_recovery_mdt(int argc, char **argv)
{
	if (argc != 1)
		return CMD_HELP;

	return obd_abort_recovery(argv[0], OBD_FLG_ABORT_RECOV_MDT);
}
#else /* ! HAVE_SERVER_SUPPROT */
int jt_obd_no_transno(int argc, char **argv)
{
	if (argc != 1)
		return CMD_HELP;

	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_obd_set_readonly(int argc, char **argv)
{
	if (argc != 1)
		return CMD_HELP;

	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_obd_abort_recovery(int argc, char **argv)
{
	if (argc != 1)
		return CMD_HELP;

	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_obd_abort_recovery_mdt(int argc, char **argv)
{
	if (argc != 1)
		return CMD_HELP;

	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}
#endif /* HAVE_SERVER_SUPPORT */

int jt_get_version(int argc, char **argv)
{
	char version[128];
	int rc;

	if (argc != 1)
		return CMD_HELP;

	rc = llapi_get_version_string(version, sizeof(version));
	if (rc)
		printf("Lustre version: %s\n", LUSTRE_VERSION_STRING);
	else
		printf("Lustre version: %s\n", version);

	return 0;
}

static void print_obd_line(char *s)
{
	const char *param = "osc/%s/ost_conn_uuid";
	char buf[MAX_STRING_SIZE];
	char obd_name[MAX_OBD_NAME];
	FILE *fp = NULL;
	glob_t path;
	char *ptr;
retry:
	/* obd device type is the first 3 characters of param name */
	snprintf(buf, sizeof(buf), " %%*d %%*s %.3s %%%zus %%*s %%*d ",
		 param, sizeof(obd_name) - 1);
	if (sscanf(s, buf, obd_name) == 0)
		goto try_mdc;
	if (cfs_get_param_paths(&path, param, obd_name) != 0)
		goto try_mdc;
	fp = fopen(path.gl_pathv[0], "r");
	if (!fp) {
		/* need to free path data before retry */
		cfs_free_param_data(&path);
try_mdc:
		if (param[0] == 'o') { /* failed with osc, try mdc */
			param = "mdc/%s/mds_conn_uuid";
			goto retry;
		}
		buf[0] = '\0';
		goto fail_print;
	}

	/* should not ignore fgets(3)'s return value */
	if (!fgets(buf, sizeof(buf), fp)) {
		fprintf(stderr, "reading from %s: %s", buf, strerror(errno));
		goto fail_close;
	}

fail_close:
	fclose(fp);
	cfs_free_param_data(&path);

	/* trim trailing newlines */
	ptr = strrchr(buf, '\n');
	if (ptr)
		*ptr = '\0';
fail_print:
	ptr = strrchr(s, '\n');
	if (ptr)
		*ptr = '\0';
	printf("%s%s%s\n", s, buf[0] ? " " : "", buf);
}

/* get device list by ioctl */
int jt_obd_list_ioctl(int argc, char **argv)
{
	int rc, index;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	struct obd_ioctl_data *data = (struct obd_ioctl_data *)buf;

	if (argc > 2)
		return CMD_HELP;
	/* Just ignore a -t option.  Only supported with /proc. */
	else if (argc == 2 && strcmp(argv[1], "-t") != 0)
		return CMD_HELP;

	for (index = 0;; index++) {
		memset(buf, 0, sizeof(rawbuf));
		data->ioc_version = OBD_IOCTL_VERSION;
		data->ioc_inllen1 =
			sizeof(rawbuf) - __ALIGN_KERNEL(sizeof(*data), 8);
		data->ioc_inlbuf1 = buf + __ALIGN_KERNEL(sizeof(*data), 8);
		data->ioc_len = obd_ioctl_packlen(data);
		data->ioc_count = index;

		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_GETDEVICE, buf);
		if (rc != 0)
			break;
		printf("%s\n", (char *)data->ioc_bulk);
	}
	if (rc != 0) {
		if (errno == ENOENT)
			/* no device or the last device */
			rc = 0;
		else
			fprintf(stderr,
				"Error getting device list: %s: check dmesg\n",
				strerror(errno));
	}
	return rc;
}

int jt_obd_list(int argc, char **argv)
{
	char buf[MAX_STRING_SIZE];
	int print_obd = 0;
	glob_t path;
	FILE *fp;

	if (argc > 2)
		return CMD_HELP;

	if (argc == 2) {
		if (strcmp(argv[1], "-t") == 0)
			print_obd = 1;
		else
			return CMD_HELP;
	}

	if (cfs_get_param_paths(&path, "devices") ||
	    !(fp = fopen(path.gl_pathv[0], "r"))) {
		cfs_free_param_data(&path);

		return jt_obd_list_ioctl(argc, argv);
	}

	while (fgets(buf, sizeof(buf), fp) != NULL)
		if (print_obd)
			print_obd_line(buf);
		else
			printf("%s", buf);

	cfs_free_param_data(&path);
	fclose(fp);
	return 0;
}

struct jt_fid_space {
	__u64	jt_seq;
	__u64	jt_id;
	int	jt_width;
};

int jt_obd_alloc_fids(struct jt_fid_space *space, struct lu_fid *fid,
		      __u64 *count)
{
	int rc;

	if (space->jt_seq == 0 || space->jt_id == space->jt_width) {
		struct obd_ioctl_data  data;
		char rawbuf[MAX_IOC_BUFLEN];
		char *buf = rawbuf;
		__u64 seqnr;
		int max_count;

		memset(&data, 0, sizeof(data));
		data.ioc_dev = cur_device;

		data.ioc_pbuf1 = (char *)&seqnr;
		data.ioc_plen1 = sizeof(seqnr);

		data.ioc_pbuf2 = (char *)&max_count;
		data.ioc_plen2 = sizeof(max_count);

		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: invalid ioctl rc = %d\n", rc);
			return rc;
		}

		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_ECHO_ALLOC_SEQ, buf);
		if (rc) {
			fprintf(stderr, "ioctl error: rc = %d\n", rc);
			return rc;
		}

		space->jt_seq = *(__u64 *)data.ioc_pbuf1;
		space->jt_width = *(int *)data.ioc_pbuf2;
		space->jt_id = 1;
	}
	fid->f_seq = space->jt_seq;
	fid->f_oid = space->jt_id;
	fid->f_ver = 0;

	space->jt_id = space->jt_id + *count;
	if (space->jt_id > space->jt_width)
		space->jt_id = space->jt_width;

	*count = space->jt_id - fid->f_oid;
	return 0;
}

#define MD_STEP_COUNT 1000
int jt_obd_md_common(int argc, char **argv, int cmd)
{
	struct obd_ioctl_data  data;
	struct timeval         start;
	struct timeval         end_time;
	char rawbuf[MAX_IOC_BUFLEN];
	char *buf = rawbuf;
	int mode = 0000644;
	int create_mode;
	int rc = 0;
	char *parent_basedir = NULL;
	char dirname[4096];
	int parent_base_id = 0;
	int parent_count = 1;
	__u64 child_base_id = -1;
	int stripe_count = 0;
	int stripe_index = -1;
	int count = 0;
	char *end;
	__u64 seconds = 0;
	double diff;
	int c;
	__u64 total_count = 0;
	char *name = NULL;
	struct jt_fid_space fid_space = {0};
	int version = 0;
	struct option long_opts[] = {
	{ .val = 'b',	.name = "child_base_id",
						.has_arg = required_argument },
	{ .val = 'c',	.name = "stripe_count",
						.has_arg = required_argument },
	{ .val = 'd',	.name = "parent_basedir",
						.has_arg = required_argument },
	{ .val = 'D',	.name = "parent_dircount",
						.has_arg = required_argument },
	{ .val = 'i',	.name = "stripe_index",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mode",		.has_arg = required_argument },
	{ .val = 'n',	.name = "count",	.has_arg = required_argument },
	{ .val = 't',	.name = "time",		.has_arg = required_argument },
	{ .val = 'v',	.name = "version",	.has_arg = no_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "b:c:d:D:m:n:t:v",
				long_opts, NULL)) >= 0) {
		switch (c) {
		case 'b':
			child_base_id = strtoull(optarg, &end, 0);
			if (*end) {
				fprintf(stderr,
					"error: %s: bad child_base_id '%s'\n",
					jt_cmdname(argv[0]), optarg);
				return CMD_HELP;
			}
			break;
		case 'c':
			stripe_count = strtoul(optarg, &end, 0);
			if (*end) {
				fprintf(stderr,
					"error: %s: bad stripe count '%s'\n",
					jt_cmdname(argv[0]), optarg);
				return CMD_HELP;
			}
			break;
		case 'd':
			parent_basedir = optarg;
			break;
		case 'D':
			parent_count = strtoul(optarg, &end, 0);
			if (*end) {
				fprintf(stderr,
					"error: %s: bad parent count '%s'\n",
					jt_cmdname(argv[0]), optarg);
				return CMD_HELP;
			}
			break;
		case 'i':
			stripe_index = strtoul(optarg, &end, 0);
			if (*end) {
				fprintf(stderr,
					"error: %s: bad stripe index '%s'\n",
					jt_cmdname(argv[0]), optarg);
				return CMD_HELP;
			}
			break;
		case 'm':
			mode = strtoul(optarg, &end, 0);
			if (*end) {
				fprintf(stderr, "error: %s: bad mode '%s'\n",
					jt_cmdname(argv[0]), optarg);
				return CMD_HELP;
			}
			break;
		case 'n':
			total_count = strtoul(optarg, &end, 0);
			if (*end || total_count == 0) {
				fprintf(stderr, "%s: bad child count '%s'\n",
					jt_cmdname(argv[0]), optarg);
				return CMD_HELP;
			}
			break;
		case 't':
			seconds = strtoull(optarg, &end, 0);
			if (*end) {
				fprintf(stderr, "error: %s: seconds '%s'\n",
					jt_cmdname(argv[0]), optarg);
				return CMD_HELP;
			}
			break;
		case 'v':
			version = 1;
			break;
		default:
			fprintf(stderr,
				"error: %s: option '%s' unrecognized\n",
				argv[0], argv[optind - 1]);
			return CMD_HELP;
		}
	}

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	if (child_base_id == -1) {
		if (optind >= argc)
			return CMD_HELP;
		name = argv[optind];
		total_count = 1;
	} else {
		if (optind < argc) {
			fprintf(stderr,
				"child_base_id and name can not specified at the same time\n");
			return CMD_HELP;
		}
	}

	if (stripe_count == 0 && stripe_index != -1) {
		fprintf(stderr,
			"If stripe_count is 0, stripe_index can not be specified\n");
		return CMD_HELP;
	}

	if (total_count == 0 && seconds == 0) {
		fprintf(stderr, "count or seconds needs to be indicated\n");
		return CMD_HELP;
	}

	if (parent_count <= 0) {
		fprintf(stderr, "parent count must < 0\n");
		return CMD_HELP;
	}

#ifdef MAX_THREADS
	if (thread) {
		shmem_lock();
		/* threads interleave */
		if (parent_base_id != -1)
			parent_base_id += (thread - 1) % parent_count;

		if (child_base_id != -1)
			child_base_id +=  (thread - 1) *
				(MAX_BASE_ID / nthreads);

		shmem_start_time_locked();
		shmem_unlock();
	}
#endif
	/*
	 * If parent directory is not specified, try to get the directory
	 * from name
	 */
	if (!parent_basedir) {
		char *last_lash;

		if (!name) {
			fprintf(stderr,
				"parent_basedir or name must be indicated!\n");
			return CMD_HELP;
		}
		/*Get directory and name from name*/
		last_lash = strrchr(name, '/');
		if (!last_lash || name[0] != '/') {
			fprintf(stderr, "Can not locate %s\n", name);
			return CMD_HELP;
		}

		if (last_lash == name) {
			sprintf(dirname, "%s", "/");
			name++;
		} else {
			int namelen = (unsigned long)last_lash -
				      (unsigned long)name + 1;
			snprintf(dirname, namelen, "%s", name);
			name = last_lash + 1;
		}

		data.ioc_pbuf1 = dirname;
		data.ioc_plen1 = strlen(dirname);

		data.ioc_pbuf2 = name;
		data.ioc_plen2 = strlen(name);
	} else {
		if (name) {
			data.ioc_pbuf2 = name;
			data.ioc_plen2 = strlen(name);
		}
		if (parent_base_id > 0)
			sprintf(dirname, "%s%d", parent_basedir,
				parent_base_id);
		else
			sprintf(dirname, "%s", parent_basedir);
		data.ioc_pbuf1 = dirname;
		data.ioc_plen1 = strlen(dirname);
	}

	if (cmd == ECHO_MD_MKDIR || cmd == ECHO_MD_RMDIR)
		create_mode = S_IFDIR;
	else
		create_mode = S_IFREG;

	data.ioc_obdo1.o_mode = mode | S_IFDIR;
	data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE |
				 OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
	data.ioc_command = cmd;

	gettimeofday(&start, NULL);
	while (shmem_running()) {
		struct lu_fid fid = { 0 };

		if (child_base_id != -1)
			data.ioc_obdo2.o_oi.oi.oi_id = child_base_id;
		data.ioc_obdo2.o_mode = mode | create_mode;
		data.ioc_obdo2.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE |
					 OBD_MD_FLMODE | OBD_MD_FLFLAGS |
					 OBD_MD_FLGROUP;
		data.ioc_obdo2.o_misc = stripe_count;
		data.ioc_obdo2.o_stripe_idx = stripe_index;

		if (total_count > 0) {
			if ((total_count - count) > MD_STEP_COUNT)
				data.ioc_count = MD_STEP_COUNT;
			else
				data.ioc_count = total_count - count;
		} else {
			data.ioc_count = MD_STEP_COUNT;
		}

		if (cmd == ECHO_MD_CREATE || cmd == ECHO_MD_MKDIR) {
			/*Allocate fids for the create */
			rc = jt_obd_alloc_fids(&fid_space, &fid,
					       &data.ioc_count);
			if (rc) {
				fprintf(stderr, "Allocate fids error %d.\n",
					rc);
				return rc;
			}
			data.ioc_obdo1.o_oi.oi_fid = fid;
		}

		child_base_id += data.ioc_count;
		count += data.ioc_count;

		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: %s: invalid ioctl %d\n",
				jt_cmdname(argv[0]), rc);
			return rc;
		}

		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_ECHO_MD, buf);
		if (rc) {
			fprintf(stderr, "error: %s: %s\n",
				jt_cmdname(argv[0]), strerror(rc = errno));
			return rc;
		}
		shmem_bump(data.ioc_count);

		gettimeofday(&end_time, NULL);
		diff = difftime(&end_time, &start);
		if (seconds > 0 && (__u64)diff > seconds)
			break;

		if (count >= total_count && total_count > 0)
			break;
	}

	if (count > 0 && version) {
		gettimeofday(&end_time, NULL);
		diff = difftime(&end_time, &start);
		printf("%s: %d in %.3fs (%.3f /s): %s",
		       jt_cmdname(argv[0]), count, diff,
		       (double)count / diff, ctime(&end_time.tv_sec));
	}

#ifdef MAX_THREADS
	if (thread) {
		shmem_lock();
		shmem_end_time_locked();
		shmem_unlock();
	}
#endif
	return rc;
}

int jt_obd_test_create(int argc, char **argv)
{
	return jt_obd_md_common(argc, argv, ECHO_MD_CREATE);
}

int jt_obd_test_mkdir(int argc, char **argv)
{
	return jt_obd_md_common(argc, argv, ECHO_MD_MKDIR);
}

int jt_obd_test_destroy(int argc, char **argv)
{
	return jt_obd_md_common(argc, argv, ECHO_MD_DESTROY);
}

int jt_obd_test_rmdir(int argc, char **argv)
{
	return jt_obd_md_common(argc, argv, ECHO_MD_RMDIR);
}

int jt_obd_test_lookup(int argc, char **argv)
{
	return jt_obd_md_common(argc, argv, ECHO_MD_LOOKUP);
}

int jt_obd_test_setxattr(int argc, char **argv)
{
	return jt_obd_md_common(argc, argv, ECHO_MD_SETATTR);
}

int jt_obd_test_md_getattr(int argc, char **argv)
{
	return jt_obd_md_common(argc, argv, ECHO_MD_GETATTR);
}

int jt_obd_create(int argc, char **argv)
{
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	struct obd_ioctl_data data;
	struct timeval next_time;
	__u64 count = 1, next_count, base_id = 1;
	int verbose = 1, mode = 0100644, rc = 0, i;
	char *end;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	if (argc < 2 || argc > 4)
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

	printf("%s: %jd objects\n", jt_cmdname(argv[0]), (uintmax_t)count);
	gettimeofday(&next_time, NULL);
	next_time.tv_sec -= verbose;

	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	for (i = 1, next_count = verbose; i <= count && shmem_running(); i++) {
		/*
		 * base_id is 1 so we don't need to worry about it being
		 * greater than OBIF_MAX_OID
		 */
		data.ioc_obdo1.o_oi.oi_fid.f_oid = base_id;
		data.ioc_obdo1.o_mode = mode;
		data.ioc_obdo1.o_uid = 0;
		data.ioc_obdo1.o_gid = 0;
		data.ioc_obdo1.o_projid = 0;
		data.ioc_obdo1.o_valid = OBD_MD_FLTYPE | OBD_MD_FLMODE |
					 OBD_MD_FLID | OBD_MD_FLUID |
					 OBD_MD_FLGID | OBD_MD_FLGROUP |
					 OBD_MD_FLPROJID;

		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: %s: invalid ioctl\n",
				jt_cmdname(argv[0]));
			return rc;
		}
		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_CREATE, buf);
		llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
		shmem_bump(1);
		if (rc < 0) {
			fprintf(stderr, "error: %s: #%d - %s\n",
				jt_cmdname(argv[0]), i, strerror(rc = errno));
			break;
		}
		if (!(data.ioc_obdo1.o_valid & OBD_MD_FLID)) {
			fprintf(stderr, "error: %s: oid not valid #%d:%#jx\n",
				jt_cmdname(argv[0]), i,
				(uintmax_t)data.ioc_obdo1.o_valid);
			rc = EINVAL;
			break;
		}

		if (be_verbose(verbose, &next_time, i, &next_count, count))
			printf("%s: #%d is object id %#jx\n",
			       jt_cmdname(argv[0]), i,
			       (uintmax_t)ostid_id(&data.ioc_obdo1.o_oi));
	}

	return rc;
}

int jt_obd_setattr(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	__u64 objid;
	char *end;
	int mode;
	int rc;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	if (argc != 2)
		return CMD_HELP;

	objid = strtoull(argv[1], &end, 0);
	if (*end) {
		fprintf(stderr, "error: %s: objid '%s' is not a number\n",
			jt_cmdname(argv[0]), argv[1]);
		return CMD_HELP;
	}

	if (objid >= OBIF_MAX_OID) {
		fprintf(stderr, "error: %s: invalid objid '%s'\n",
			jt_cmdname(argv[0]), argv[1]);
		return CMD_HELP;
	}

	mode = strtoul(argv[2], &end, 0);
	if (*end) {
		fprintf(stderr, "error: %s: invalid mode '%s'\n",
			jt_cmdname(argv[0]), argv[2]);
		return CMD_HELP;
	}

	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	data.ioc_obdo1.o_mode = S_IFREG | mode;
	data.ioc_obdo1.o_oi.oi_fid.f_oid = objid;
	data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}
	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_SETATTR, buf);
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
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int verbose = 1;
	__u64 objid = 3;
	char *end;
	int rc = 0;

	if (argc < 2 || argc > 4)
		return CMD_HELP;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
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
		} else {
			objid = strtoull(argv[3], &end, 0);
		}
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
		printf("%s: setting %jd attrs (objid %#jx): %s",
		       jt_cmdname(argv[0]), (uintmax_t)count,
		       (uintmax_t)objid, ctime(&start.tv_sec));

	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	for (i = 1, next_count = verbose; i <= count && shmem_running(); i++) {
		if (objid >= OBIF_MAX_OID) {
			fprintf(stderr, "errr: %s: invalid objid '%llu'\n",
				jt_cmdname(argv[0]), (unsigned long long)objid);
			return -E2BIG;
		}

		data.ioc_obdo1.o_oi.oi_fid.f_oid = objid;
		data.ioc_obdo1.o_mode = S_IFREG;
		data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE |
					 OBD_MD_FLMODE;
		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: %s: invalid ioctl\n",
				jt_cmdname(argv[0]));
			return rc;
		}
		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_SETATTR, &data);
		shmem_bump(1);
		if (rc < 0) {
			fprintf(stderr, "error: %s: #%jd - %d:%s\n",
				jt_cmdname(argv[0]), (uintmax_t)i,
				errno, strerror(rc = errno));
			break;
		}
		if (be_verbose(verbose, &next_time, i, &next_count, count))
			printf("%s: set attr #%jd\n",
			       jt_cmdname(argv[0]), (uintmax_t)i);
	}

	if (!rc) {
		struct timeval end;
		double diff;

		gettimeofday(&end, NULL);

		diff = difftime(&end, &start);

		--i;
		if (verbose != 0)
			printf("%s: %jd attrs in %.3fs (%.3f attr/s): %s",
			       jt_cmdname(argv[0]), (uintmax_t)i, diff,
			       i / diff, ctime(&end.tv_sec));
	}
	return rc;
}

int jt_obd_destroy(int argc, char **argv)
{
	struct obd_ioctl_data data;
	struct timeval next_time;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	__u64 count = 1, next_count;
	int verbose = 1;
	__u64 id;
	char *end;
	int rc = 0, i;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	if (argc < 2 || argc > 4)
		return CMD_HELP;

	errno = 0;
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

	printf("%s: %jd objects\n", jt_cmdname(argv[0]), (uintmax_t)count);
	gettimeofday(&next_time, NULL);
	next_time.tv_sec -= verbose;

	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	for (i = 1, next_count = verbose; i <= count && shmem_running();
	     i++, id++) {
		if (id >= OBIF_MAX_OID) {
			fprintf(stderr, "errr: %s: invalid objid '%llu'\n",
				jt_cmdname(argv[0]), (unsigned long long)id);
			return -E2BIG;
		}

		data.ioc_obdo1.o_oi.oi_fid.f_oid = id;
		data.ioc_obdo1.o_mode = S_IFREG | 0644;
		data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLMODE;

		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: %s: invalid ioctl\n",
				jt_cmdname(argv[0]));
			return rc;
		}
		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_DESTROY, buf);
		llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
		shmem_bump(1);
		if (rc < 0) {
			fprintf(stderr, "error: %s: objid %#jx: %s\n",
				jt_cmdname(argv[0]), (uintmax_t)id,
				strerror(rc = errno));
			break;
		}

		if (be_verbose(verbose, &next_time, i, &next_count, count))
			printf("%s: #%d is object id %#jx\n",
			       jt_cmdname(argv[0]), i, (uintmax_t)id);
	}

	return rc;
}

int jt_obd_getattr(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	__u64 objid;
	char *end;
	int rc;

	if (argc != 2)
		return CMD_HELP;

	objid = strtoull(argv[1], &end, 0);
	if (*end) {
		fprintf(stderr, "error: %s: objid '%s' is not a number\n",
			jt_cmdname(argv[0]), argv[1]);
		return CMD_HELP;
	}

	if (objid >= OBIF_MAX_OID) {
		fprintf(stderr, "error: %s: invalid objid '%s'\n",
			jt_cmdname(argv[0]), argv[1]);
		return CMD_HELP;
	}

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	data.ioc_obdo1.o_oi.oi_fid.f_oid = objid;
	/* to help obd filter */
	data.ioc_obdo1.o_mode = 0100644;
	data.ioc_obdo1.o_valid = 0xffffffff;
	printf("%s: object id %#jx\n", jt_cmdname(argv[0]),
	       (uintmax_t)ostid_id(&data.ioc_obdo1.o_oi));

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}
	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_GETATTR, buf);
	llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(rc = errno));
	} else {
		printf("%s: object id %ju, mode %o\n", jt_cmdname(argv[0]),
		       (uintmax_t)ostid_id(&data.ioc_obdo1.o_oi),
		       data.ioc_obdo1.o_mode);
	}
	return rc;
}

int jt_obd_test_getattr(int argc, char **argv)
{
	struct obd_ioctl_data data;
	struct timeval start, next_time;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	__u64 i, count, next_count;
	int verbose = 1;
	__u64 objid = 3;
	char *end;
	int rc = 0;

	if (argc < 2 || argc > 4)
		return CMD_HELP;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
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
		} else {
			objid = strtoull(argv[3], &end, 0);
		}
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
		printf("%s: getting %jd attrs (objid %#jx): %s",
		       jt_cmdname(argv[0]), (uintmax_t)count,
		       (uintmax_t)objid, ctime(&start.tv_sec));

	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	for (i = 1, next_count = verbose; i <= count && shmem_running(); i++) {
		if (objid >= OBIF_MAX_OID) {
			fprintf(stderr, "errr: %s: invalid objid '%llu'\n",
				jt_cmdname(argv[0]), (unsigned long long)objid);
			return -E2BIG;
		}

		data.ioc_obdo1.o_oi.oi_fid.f_oid = objid;
		data.ioc_obdo1.o_mode = S_IFREG;
		data.ioc_obdo1.o_valid = 0xffffffff;
		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: %s: invalid ioctl\n",
				jt_cmdname(argv[0]));
			return rc;
		}
		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_GETATTR, &data);
		shmem_bump(1);
		if (rc < 0) {
			fprintf(stderr, "error: %s: #%jd - %d:%s\n",
				jt_cmdname(argv[0]), (uintmax_t)i,
				errno, strerror(rc = errno));
			break;
		}
		if (be_verbose(verbose, &next_time, i, &next_count, count))
			printf("%s: got attr #%jd\n",
			       jt_cmdname(argv[0]), (uintmax_t)i);
	}

	if (!rc) {
		struct timeval end;
		double diff;

		gettimeofday(&end, NULL);

		diff = difftime(&end, &start);

		--i;
		if (verbose != 0)
			printf("%s: %jd attrs in %.3fs (%.3f attr/s): %s",
			       jt_cmdname(argv[0]), (uintmax_t)i, diff,
			       i / diff, ctime(&end.tv_sec));
	}

	return rc;
}

/*
 * test_brw <cnt>                                               count
 *	<r|w[r(repeat)x(noverify)]>                             mode
 *	<q|v|#(print interval)>                                 verbosity
 *	<npages[+offset]>                                       blocksize
 *	<[[<interleave_threads>]t(inc obj by thread#)]obj>      object
 *	[p|g<args>]                                             batch
 */
int jt_obd_test_brw(int argc, char **argv)
{
	struct obd_ioctl_data data;
	struct timeval start, next_time;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
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
					fprintf(stderr,
						"Can't parse cmd '%s'\n",
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

		if (*end != 0 || offset_pages < 0 || offset_pages >= pages) {
			fprintf(stderr, "error: %s: bad npages[+offset] parameter '%s'\n",
				jt_cmdname(argv[0]), argv[4]);
			return CMD_HELP;
		}
	}

	if (argc >= 6) {
		if (thread && (n = strtol(argv[5], &end, 0)) > 0 &&
		    *end == 't' && (ull = strtoull(end + 1, &end, 0)) > 0 &&
		    *end == 0) {
			nthr_per_obj = n;
			objid = ull;
		} else if (thread && argv[5][0] == 't') {
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

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;

	/*
	 * communicate the 'type' of brw test and batching to echo_client.
	 * don't start.  we'd love to refactor this lctl->echo_client
	 * interface
	 */
	data.ioc_pbuf1 = (void *)1;
	data.ioc_plen1 = 1;

	if (argc >= 7) {
		switch (argv[6][0]) {
		case 'g': /* plug and unplug */
			data.ioc_pbuf1 = (void *)2;
			data.ioc_plen1 = strtoull(argv[6] + 1, &end, 0);
			break;
		case 'p': /* prep and commit */
			data.ioc_pbuf1 = (void *)3;
			data.ioc_plen1 = strtoull(argv[6] + 1, &end, 0);
			break;
		default:
			fprintf(stderr,
				"error: %s: batching '%s' needs to specify 'p' or 'g'\n",
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
		shmem_lock();
		if (nthr_per_obj != 0) {
			/* threads interleave */
			obj_idx = (thread - 1) / nthr_per_obj;
			objid += obj_idx;
			stride *= nthr_per_obj;
			if ((thread - 1) % nthr_per_obj == 0) {
				shared_data->body.offsets[obj_idx] =
					stride + thr_offset;
			}
			thr_offset += ((thread - 1) % nthr_per_obj) * len;
		} else {
			/* threads disjoint */
			thr_offset += (thread - 1) * len;
		}

		shmem_start_time_locked();
		shmem_unlock();
	}
#endif

	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	if (objid >= OBIF_MAX_OID) {
		fprintf(stderr, "errr: %s: invalid objid '%llu'\n",
			jt_cmdname(argv[0]), (unsigned long long)objid);
		return -E2BIG;
	}

	data.ioc_obdo1.o_oi.oi_fid.f_oid = objid;
	data.ioc_obdo1.o_mode = S_IFREG;
	data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE |
				 OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
	data.ioc_obdo1.o_flags = (verify ? OBD_FL_DEBUG_CHECK : 0);
	data.ioc_count = len;
	data.ioc_offset = (repeat_offset ? 0 : thr_offset);

	gettimeofday(&start, NULL);
	next_time.tv_sec = start.tv_sec - verbose;
	next_time.tv_usec = start.tv_usec;

	if (verbose != 0)
		printf("%s: %s %jux%d pages (obj %#jx, off %ju): %s",
		       jt_cmdname(argv[0]), write ? "writing" : "reading",
		       (uintmax_t)count, pages, (uintmax_t)objid,
		       (uintmax_t)data.ioc_offset, ctime(&start.tv_sec));

	cmd = write ? OBD_IOC_BRW_WRITE : OBD_IOC_BRW_READ;
	for (i = 1, next_count = verbose; i <= count && shmem_running(); i++) {
		data.ioc_obdo1.o_valid &= ~(OBD_MD_FLBLOCKS | OBD_MD_FLGRANT);
		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: %s: invalid ioctl\n",
				jt_cmdname(argv[0]));
			return rc;
		}
		rc = l_ioctl(OBD_DEV_ID, cmd, buf);
		shmem_bump(1);
		if (rc) {
			fprintf(stderr, "error: %s: #%d - %s on %s\n",
				jt_cmdname(argv[0]), i, strerror(rc = errno),
				write ? "write" : "read");
			break;
		} else if (be_verbose(verbose, &next_time, i,
				      &next_count, count)) {
			shmem_lock();
			printf("%s: %s number %d @ %jd:%ju for %d\n",
			       jt_cmdname(argv[0]), write ? "write" : "read", i,
			       (uintmax_t)ostid_id(&data.ioc_obdo1.o_oi),
			       (uintmax_t)data.ioc_offset,
			       (int)(pages * getpagesize()));
			shmem_unlock();
		}

		if (!repeat_offset) {
#ifdef MAX_THREADS
			if (stride == len) {
				data.ioc_offset += stride;
			} else if (i < count) {
				shmem_lock();
				data.ioc_offset =
					shared_data->body.offsets[obj_idx];
				shared_data->body.offsets[obj_idx] += len;
				shmem_unlock();
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
			       (diff * 1048576.0), ctime(&end.tv_sec));
	}

#ifdef MAX_THREADS
	if (thread) {
		shmem_lock();
		shmem_end_time_locked();
		shmem_unlock();
	}
#endif
	return rc;
}

static int do_activate(int argc, char **argv, int flag)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	if (argc != 1)
		return CMD_HELP;

	/* reuse offset for 'active' */
	data.ioc_offset = flag;

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}
	rc = l_ioctl(OBD_DEV_ID, IOC_OSC_SET_ACTIVE, buf);
	if (rc)
		fprintf(stderr, "error: %s: failed: %s\n",
			jt_cmdname(argv[0]), strerror(rc = errno));

	return rc;
}

/**
 * Replace nids for given device.
 * lctl replace_nids <devicename> <nid1>[,nid2,nid3]
 * Command should be started on MGS server.
 * Only MGS server should be started (command execution
 * returns error in another cases). Command mount
 * -t lustre <MDT partition> -o nosvc <mount point>
 * can be used for that.
 *
 * llogs for MDTs and clients are processed. All
 * records copied as is except add_uuid and setup. This records
 * are skipped and recorded with new nids and uuid.
 *
 * \see mgs_replace_nids
 * \see mgs_replace_log
 * \see mgs_replace_nids_handler
 */
int jt_replace_nids(int argc, char **argv)
{
	int rc;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	struct obd_ioctl_data data;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = get_mgs_device();
	if (argc != 3)
		return CMD_HELP;

	data.ioc_inllen1 = strlen(argv[1]) + 1;
	data.ioc_inlbuf1 = argv[1];

	data.ioc_inllen2 = strlen(argv[2]) + 1;
	data.ioc_inlbuf2 = argv[2];
	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_REPLACE_NIDS, buf);
	if (rc < 0) {
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(rc = errno));
	}

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
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	struct obd_ioctl_data data;
	int rc;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	if (argc > 2)
		return CMD_HELP;

	if (argc == 2) {
		data.ioc_inllen1 = strlen(argv[1]) + 1;
		data.ioc_inlbuf1 = argv[1];
	}

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}
	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_CLIENT_RECOVER, buf);
	if (rc < 0) {
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(rc = errno));
	}

	return rc;
}

int jt_obd_mdc_lookup(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	char *parent, *child;
	int rc, fd, verbose = 1;

	if (argc < 3 || argc > 4)
		return CMD_HELP;

	parent = argv[1];
	child = argv[2];
	if (argc == 4)
		verbose = get_verbose(argv[0], argv[3]);

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;

	data.ioc_inllen1 = strlen(child) + 1;
	data.ioc_inlbuf1 = child;

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}

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
		rc = llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: %s: invalid reply\n",
				jt_cmdname(argv[0]));
			return rc;
		}
		printf("%s: mode %o uid %d gid %d\n",
		       child, data.ioc_obdo1.o_mode, data.ioc_obdo1.o_uid,
		       data.ioc_obdo1.o_gid);
	}

	return rc;
}

#ifdef HAVE_SERVER_SUPPORT
/**
 * Clear config logs for given device or filesystem.
 * lctl clear_conf <devicename|fsname>
 * Command has to be run on MGS node having MGS device mounted with -o
 * nosvc.
 *
 * Configuration logs for filesystem or one particular log is
 * processed. New log is created, original log is read, its records
 * marked SKIP do not get copied to new log. Others are copied as-is.
 * Original file is renamed to log.${time}.bak.
 *
 * \see mgs_clear_configs
 * \see mgs_replace_log
 * \see mgs_clear_config_handler
 **/
int jt_lcfg_clear(int argc, char **argv)
{
	int rc;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	struct obd_ioctl_data data;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = get_mgs_device();
	if (argc != 2)
		return CMD_HELP;

	data.ioc_inllen1 = strlen(argv[1]) + 1;
	data.ioc_inlbuf1 = argv[1];

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_CLEAR_CONFIGS, buf);
	if (rc < 0) {
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(rc = errno));
	}

	return rc;
}

int jt_lcfg_fork(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	if (argc != 3)
		return CMD_HELP;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = get_mgs_device();
	data.ioc_inllen1 = strlen(argv[1]) + 1;
	data.ioc_inlbuf1 = argv[1];
	data.ioc_inllen2 = strlen(argv[2]) + 1;
	data.ioc_inlbuf2 = argv[2];

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LCFG_FORK, buf);
	if (rc < 0)
		fprintf(stderr, "error: %s: OBD_IOC_LCFG_FORK failed: %s\n",
			jt_cmdname(argv[0]), strerror(errno));

	return rc;
}

int jt_lcfg_erase(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	if (argc == 3) {
		if (strncmp(argv[2], "-q", strlen("-q")) != 0 &&
		    strncmp(argv[2], "--quiet", strlen("--quiet")) != 0)
			return CMD_HELP;
	} else if (argc != 2) {
		return CMD_HELP;
	}

	memset(&data, 0, sizeof(data));
	data.ioc_dev = get_mgs_device();
	data.ioc_inllen1 = strlen(argv[1]) + 1;
	data.ioc_inlbuf1 = argv[1];

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LCFG_ERASE, buf);
	if (rc < 0)
		fprintf(stderr, "error: %s: OBD_IOC_LCFG_ERASE failed: %s\n",
			jt_cmdname(argv[0]), strerror(errno));

	return rc;
}
#else /* !HAVE_SERVER_SUPPORT */
int jt_lcfg_clear(int argc, char **argv)
{
	if (argc != 2)
		return CMD_HELP;

	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_lcfg_fork(int argc, char **argv)
{
	if (argc != 3)
		return CMD_HELP;

	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_lcfg_erase(int argc, char **argv)
{
	if (argc != 3)
		return CMD_HELP;

	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}
#endif /* HAVE_SERVER_SUPPORT */

enum llog_default_dev_op {
	LLOG_DFLT_MGS_SET = 0,
	LLOG_DFLT_DEV_RESET
};

static int llog_default_device(enum llog_default_dev_op op)
{
	int rc = 0;
	static int dflt_dev = -1;

	if (op == LLOG_DFLT_MGS_SET && (cur_device == -1)) {
		char mgs[] = "$MGS";

		rc = do_device("llog_default_device", mgs);
		dflt_dev = cur_device;

	} else if (op == LLOG_DFLT_DEV_RESET && (dflt_dev != -1)) {
		do_disconnect(NULL, 1);
		dflt_dev = -1;
	}

	return rc;
}

int jt_llog_catlist(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	char *tmp = NULL;
	int start = 0;
	int rc;

	if (argc != 1)
		return CMD_HELP;

	if (llog_default_device(LLOG_DFLT_MGS_SET))
		return CMD_INCOMPLETE;

	do {
		memset(&data, 0, sizeof(data));
		data.ioc_dev = cur_device;
		data.ioc_inllen1 = sizeof(rawbuf) -
				   __ALIGN_KERNEL(sizeof(data), 8);
		data.ioc_count = start;
		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "error: %s: invalid ioctl\n",
				jt_cmdname(argv[0]));
			goto err;
		}
		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_CATLOGLIST, buf);
		if (rc < 0)
			break;
		tmp = ((struct obd_ioctl_data *)buf)->ioc_bulk;
		if (strlen(tmp) > 0)
			fprintf(stdout, "%s", tmp);
		else
			break;
		start = ((struct obd_ioctl_data *)buf)->ioc_count;
	} while (start);

	if (rc < 0)
		fprintf(stderr, "OBD_IOC_CATLOGLIST failed: %s\n",
			strerror(errno));

err:
	llog_default_device(LLOG_DFLT_DEV_RESET);

	return rc;
}

int jt_llog_info(int argc, char **argv)
{
	const struct option long_opts[] = {
	/* Allow optional "--catalog" for compatibility with llog commands. */
	{ .val = 'c',	.name = "catalog",	.has_arg = required_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .name = NULL } };
	struct obd_ioctl_data data = { 0 };
	char rawbuf[MAX_IOC_BUFLEN] = "", *buf = rawbuf;
	char *cmd = argv[0];
	char *catalog = NULL;
	int rc, c;

	while ((c = getopt_long(argc, argv, "c:h", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			catalog = optarg;
			break;
		case 'h':
		default:
			return CMD_HELP;
		}
	}
	argc -= optind;
	argv += optind;
	/* support "logname" positional parameter */
	if (argc == 1) {
		if (catalog) {
			fprintf(stderr,
				"%s: catalog is set, unknown argument '%s'\n",
				cmd, optarg);
			return CMD_HELP;
		}
		catalog = argv[0];
	} else if (!catalog || argc > 1) {
		return CMD_HELP;
	}

	/* Manage default device */
	if (llog_default_device(LLOG_DFLT_MGS_SET))
		return CMD_INCOMPLETE;

	data.ioc_dev = cur_device;
	data.ioc_inllen1 = strlen(catalog) + 1;
	data.ioc_inlbuf1 = catalog;
	data.ioc_inllen2 = sizeof(rawbuf) - __ALIGN_KERNEL(sizeof(data), 8) -
			   __ALIGN_KERNEL(data.ioc_inllen1, 8);
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "%s: ioctl_pack failed for catalog '%s': %s\n",
			jt_cmdname(cmd), catalog, strerror(-rc));
		goto err;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_INFO, buf);
	if (rc == 0)
		fprintf(stdout, "%s", ((struct obd_ioctl_data *)buf)->ioc_bulk);
	else
		fprintf(stderr, "%s: OBD_IOC_LLOG_INFO failed: %s\n",
			jt_cmdname(cmd), strerror(errno));

err:
	llog_default_device(LLOG_DFLT_DEV_RESET);

	return rc;
}

int jt_llog_print_cb(const char *record, void *private)
{
	printf("%s\n", record);

	return 0;
}

static int
llog_process_records(int (record_cb)(const char *record, void *private),
		     const char *record, void *private, bool reverse)
{
	char *ptr = NULL;
	char *tmp = NULL;
	int rc = 0;

	if (!reverse) {
		do {
			ptr = strchr(record, '\n');
			if (ptr)
				*ptr = '\0';
			rc = record_cb(record, private);
			if (rc)
				goto out;
			if (ptr)
				record = ptr + 1;
		} while (ptr && *(ptr + 1));
	} else {
		tmp = (char *)record;

		ptr = strrchr(record, '\n');
		if (ptr)
			*ptr = '\0';
		else
			goto out;
		while ((ptr = strrchr(record, '\n'))) {
			tmp = ptr + 1;
			*ptr = '\0';
			rc = record_cb(tmp, private);
			if (rc)
				goto out;
		};
		rc = record_cb(record, private);
		if (rc)
			goto out;
	}
out:
	return rc;
}

/**
 * Iterate over llog records, typically YAML-formatted configuration logs
 *
 * \param logname[in]	name of llog file or FID
 * \param start[in]	first record to process
 * \param end[in]	last record to process (inclusive)
 * \param cb[in]	callback for records. Return -ve error, or +ve abort.
 * \param private[in,out] private data passed to the \a record_cb function
 * \param reverse[in]	print the llog records from the beginning or the end
 *
 * \retval		0 on success
 *			others handled by the caller
 */
int jt_llog_print_iter(char *logname, long start, long end,
		       int (record_cb)(const char *record, void *private),
		       void *private, bool reverse)
{
	struct obd_ioctl_data data = { 0 };
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	char startbuf[16], endbuf[16];
	static long inc = sizeof(rawbuf) / 128;
	long rec;
	int rc = 0;

	if (end == -1)
		end = 0x7fffffff;

	data.ioc_dev = cur_device;
	data.ioc_inlbuf1 = logname;
	data.ioc_inllen1 = strlen(logname) + 1;

	/*
	 * Estimate about 128 characters per configuration record.  Not all
	 * records will be printed in any case, so they should easily fit.  If
	 * not, the kernel will return -EOVERFLOW and ask for fewer records.
	 *
	 * We don't want to request records from the kernel one-at-a-time, as
	 * it restarts the config llog iteration from the beginning, so we
	 * fetch multiple records from the kernel per call and split locally.
	 */
	for (rec = start; rec < end; rec += inc) {
		char *record = ((struct obd_ioctl_data *)buf)->ioc_bulk;

retry:
		snprintf(startbuf, sizeof(startbuf), "%lu", rec);
		snprintf(endbuf, sizeof(endbuf), "%lu",
			 end < rec + inc - 1 ? end : rec + inc - 1);

		/* start and end record numbers are passed as ASCII digits */
		data.ioc_inlbuf2 = startbuf;
		data.ioc_inllen2 = strlen(startbuf) + 1;
		data.ioc_inlbuf3 = endbuf;
		data.ioc_inllen3 = strlen(endbuf) + 1;

		data.ioc_inllen4 = sizeof(rawbuf) -
			__ALIGN_KERNEL(sizeof(data), 8) -
			__ALIGN_KERNEL(data.ioc_inllen1, 8) -
			__ALIGN_KERNEL(data.ioc_inllen2, 8) -
			__ALIGN_KERNEL(data.ioc_inllen3, 8);
		memset(buf, 0, sizeof(rawbuf));
		rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
		if (rc) {
			fprintf(stderr, "%s: invalid ioctl data\n", logname);
			goto out;
		}

		rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_PRINT, buf);
		if (rc == -EOVERFLOW && inc > 2) {
			inc /= 2;
			goto retry;
		}
		if (rc) {
			fprintf(stderr, "%s: OBD_IOC_LLOG_PRINT failed: %s\n",
				logname, strerror(errno));
			rc = -errno;
			goto out;
		}

		/* There is no "end of list" marker, record was not modified */
		if (strcmp(record, logname) == 0)
			break;

		rc = llog_process_records(record_cb, record, private, reverse);
		if (rc)
			goto out;
	}

out:
	return rc;
}

static int llog_parse_catalog_start_end(int *argc, char **argv[],
					char **catalog, long *start, long *end)
{
	const struct option long_opts[] = {
	/* the --catalog option is not required, just for consistency */
	{ .val = 'c',	.name = "catalog",	.has_arg = required_argument },
	{ .val = 'e',	.name = "end",		.has_arg = required_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 's',	.name = "start",	.has_arg = required_argument },
	{ .name = NULL } };
	char *cmd = (*argv)[0];
	char *endp;
	int c;

	if (!catalog || !start || !end)
		return -EINVAL;

	/* now process command line arguments*/
	while ((c = getopt_long(*argc, *argv, "c:e:hs:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			*catalog = optarg;
			break;
		case 'e':
			*end = strtol(optarg, &endp, 0);
			if (*endp != '\0') {
				fprintf(stderr, "%s: bad end value '%s'\n",
					cmd, optarg);
				return CMD_HELP;
			}
			break;
		case 's':
			*start = strtol(optarg, &endp, 0);
			if (*endp != '\0') {
				fprintf(stderr, "%s: bad start value '%s'\n",
					cmd, optarg);
				return CMD_HELP;
			}
			break;
		case 'h':
		default:
			return CMD_HELP;
		}
	}
	*argc -= optind;
	*argv += optind;

	/*
	 * support old optional positional parameters only if they were
	 * not already specified with named arguments: logname [start [end]]
	 */
	if (*argc >= 1) {
		if (*catalog) {
			fprintf(stderr,
				"%s: logname is set, unknown argument '%s'\n",
				cmd, (*argv)[0]);
			return CMD_HELP;
		}
		*catalog = (*argv)[0];
		(*argc)--;
		(*argv)++;
	}

	if (*catalog == NULL) {
		fprintf(stderr, "%s: no logname specified\n", cmd);
		return CMD_HELP;
	}

	if (*argc >= 1) {
		if (*start != 1) {
			fprintf(stderr,
				"%s: --start is set, unknown argument '%s'\n",
				cmd, (*argv)[0]);
			return CMD_HELP;
		}

		*start = strtol((*argv)[0], &endp, 0);
		if (*endp != '\0') {
			fprintf(stderr, "%s: bad start value '%s'\n",
				cmd, (*argv)[0]);
			return CMD_HELP;
		}
		(*argc)--;
		(*argv)++;
	}
	if (*argc >= 1) {
		if (*end != -1) {
			fprintf(stderr,
				"%s: --end is set, unknown argument '%s'\n",
				cmd, (*argv)[0]);
			return CMD_HELP;
		}

		*end = strtol((*argv)[0], &endp, 0);
		if (*endp != '\0') {
			fprintf(stderr, "%s: bad end value '%s'\n",
				cmd, (*argv)[0]);
			return CMD_HELP;
		}
		(*argc)--;
		(*argv)++;
	}
	if (*argc > 1) {
		fprintf(stderr, "%s: unknown argument '%s'\n", cmd, (*argv)[0]);
		return CMD_HELP;
	}

	if (*end != -1 && *end < *start) {
		fprintf(stderr, "%s: end '%lu' less than than start '%lu'\n",
			cmd, *end, *start);
		return CMD_HELP;
	}

	return 0;
}

int jt_llog_print(int argc, char **argv)
{
	char *catalog = NULL;
	long start = 1, end = -1;
	int rc;

	rc = llog_parse_catalog_start_end(&argc, &argv, &catalog, &start, &end);
	if (rc)
		return rc;

	if (llog_default_device(LLOG_DFLT_MGS_SET))
		return CMD_INCOMPLETE;

	rc = jt_llog_print_iter(catalog, start, end, jt_llog_print_cb,
				NULL, false);

	llog_default_device(LLOG_DFLT_DEV_RESET);

	return rc;
}

/*
 * Parse catalog, log ID, and optionally a log index with either optional
 * arguments or positional arguments.  Only the initial catalog argument
 * may be positional with other optional arguments.
 *
 * The positional arguments option should eventually be phased out.
 */
static int llog_parse_catalog_log_idx(int *argc, char ***argv, const char *opts,
				      int max_args, struct obd_ioctl_data *data)
{
	const struct option long_opts[] = {
	/* the --catalog option is not required, just for consistency */
	{ .val = 'c',	.name = "catalog",	.has_arg = required_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'i',	.name = "log_idx",	.has_arg = required_argument },
	{ .val = 'l',	.name = "log_id",	.has_arg = required_argument },
	{ .name = NULL } };
	int c;

	/* sanity check */
	if (!data || *argc <= 1)
		return -1;

	data->ioc_dev = cur_device;

	/* now process command line arguments*/
	while ((c = getopt_long(*argc, *argv, opts, long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			data->ioc_inllen1 = strlen(optarg) + 1;
			data->ioc_inlbuf1 = optarg;
			break;
		case 'i':
			data->ioc_inllen3 = strlen(optarg) + 1;
			data->ioc_inlbuf3 = optarg;
			break;
		case 'l': /* The log_id option isn't currently needed for
			   * cancel as mdt_iocontrol() handles IOC_LLOG_CANCEL,
			   * but we may as well keep it for now.
			   */
			data->ioc_inllen2 = strlen(optarg) + 1;
			data->ioc_inlbuf2 = optarg;
			break;
		case 'h':
		default:
			return CMD_HELP;
		}
	}

	*argc -= optind;
	*argv += optind;

	/* Allow catalog to be specified as first option without --catalog */
	if (!data->ioc_inlbuf1 && *argc > 0) {
		data->ioc_inlbuf1 = (*argv)[0];
		data->ioc_inllen1 = strlen((*argv)[0]) + 1;
		(*argc)--;
		(*argv)++;
	}

	return 0;
}

int jt_llog_cancel(int argc, char **argv)
{
	struct obd_ioctl_data data = { 0 };
	char rawbuf[MAX_IOC_BUFLEN] = "", *buf = rawbuf;
	char *cmd = argv[0];
	int rc;

	/* Manage default device */
	if (llog_default_device(LLOG_DFLT_MGS_SET))
		return CMD_INCOMPLETE;

	/* Parse catalog file (in inlbuf1) and named parameters */
	rc = llog_parse_catalog_log_idx(&argc, &argv, "c:hi:l:", 3, &data);

	/*
	 * Handle old positional parameters if not using named parameters,
	 * either "<catalog> <log_idx>" or "<catalog> <log_id> <log_idx>".
	 * It was "inlbuf3 = log_idx", and "inlbuf2 = log_id" (ignored by
	 * config log cancel), and shows why I hate positional parameters.
	 */
	if (argc == 1) {
		data.ioc_inllen3 = strlen(argv[0]) + 1;
		data.ioc_inlbuf3 = argv[0];
	} else if (argc == 2) {
		data.ioc_inllen2 = strlen(argv[0]) + 1;
		data.ioc_inlbuf2 = argv[0];
		data.ioc_inllen3 = strlen(argv[1]) + 1;
		data.ioc_inlbuf3 = argv[1];
	}

	if (!data.ioc_inlbuf1 || !data.ioc_inlbuf3) {
		/* missing mandatory parameters */
		rc = CMD_HELP;
		goto err;
	}

	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "%s: ioctl_pack for catalog '%s' failed: %s\n",
			jt_cmdname(cmd), data.ioc_inlbuf1, strerror(-rc));
		goto err;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_CANCEL, buf);
	if (rc)
		fprintf(stderr, "%s: cancel catalog '%s:%s' failed: %s\n",
			jt_cmdname(cmd), data.ioc_inlbuf1, data.ioc_inlbuf3,
			strerror(errno));

err:
	llog_default_device(LLOG_DFLT_DEV_RESET);
	return rc;
}

int jt_llog_check(int argc, char **argv)
{
	struct obd_ioctl_data data = { 0 };
	char rawbuf[MAX_IOC_BUFLEN] = "", *buf = rawbuf;
	char *catalog = NULL;
	char startbuf[16], endbuf[16];
	long start = 1, end = -1;
	char *cmd = argv[0];
	int rc;

	rc = llog_parse_catalog_start_end(&argc, &argv, &catalog, &start, &end);
	if (rc)
		return rc;

	if (llog_default_device(LLOG_DFLT_MGS_SET))
		return CMD_INCOMPLETE;

	if (end == -1)
		end = 0x7fffffff;

	data.ioc_dev = cur_device;
	data.ioc_inllen1 = strlen(catalog) + 1;
	data.ioc_inlbuf1 = catalog;

	snprintf(startbuf, sizeof(startbuf), "%lu", start);
	snprintf(endbuf, sizeof(endbuf), "%lu", end);
	/* start and end record numbers are passed as ASCII digits */
	data.ioc_inllen2 = strlen(startbuf) + 1;
	data.ioc_inlbuf2 = startbuf;
	data.ioc_inllen3 = strlen(endbuf) + 1;
	data.ioc_inlbuf3 = endbuf;

	data.ioc_inllen4 = sizeof(rawbuf) - __ALIGN_KERNEL(sizeof(data), 8) -
			   __ALIGN_KERNEL(data.ioc_inllen1, 8) -
			   __ALIGN_KERNEL(data.ioc_inllen2, 8) -
			   __ALIGN_KERNEL(data.ioc_inllen3, 8);
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "%s: ioctl_pack failed for catalog '%s': %s\n",
			jt_cmdname(cmd), data.ioc_inlbuf1, strerror(-rc));
		goto err;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_CHECK, buf);
	if (rc == 0)
		fprintf(stdout, "%s", ((struct obd_ioctl_data *)buf)->ioc_bulk);
	else
		fprintf(stderr, "%s: OBD_IOC_LLOG_CHECK failed: %s\n",
			jt_cmdname(cmd), strerror(errno));
err:
	llog_default_device(LLOG_DFLT_DEV_RESET);
	return rc;
}

int jt_llog_remove(int argc, char **argv)
{
	struct obd_ioctl_data data = { 0 };
	char rawbuf[MAX_IOC_BUFLEN] = "", *buf = rawbuf;
	char *cmd = argv[0];
	int rc;

	if (llog_default_device(LLOG_DFLT_MGS_SET))
		return CMD_INCOMPLETE;

	rc = llog_parse_catalog_log_idx(&argc, &argv, "c:hl:", 2, &data);
	if (rc)
		goto err;

	if (argc == 1) {
		if (data.ioc_inlbuf2) {
			fprintf(stderr,
				"%s: --log_id is set, unknown argument '%s'\n",
				jt_cmdname(cmd), argv[0]);
			rc = CMD_HELP;
			goto err;
		}

		data.ioc_inllen2 = strlen(argv[0]) + 1;
		data.ioc_inlbuf2 = argv[0];
	}

	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "%s: ioctl_pack for catalog '%s' failed: %s\n",
			jt_cmdname(cmd), data.ioc_inlbuf1, strerror(-rc));
		goto err;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_REMOVE, buf);
	if (rc)
		fprintf(stderr, "%s: cancel catalog '%s:%s' failed: %s\n",
			jt_cmdname(cmd), data.ioc_inlbuf1, data.ioc_inlbuf2,
			strerror(-rc));

err:
	llog_default_device(LLOG_DFLT_DEV_RESET);
	return rc;
}

static void signal_server(int sig)
{
	if (sig == SIGINT) {
		do_disconnect("sigint", 1);
		exit(1);
	} else {
		fprintf(stderr, "%s: got signal %d\n", jt_cmdname("sigint"),
			sig);
	}
}

int obd_initialize(int argc, char **argv)
{
	if (shmem_setup() != 0)
		return -1;

	register_ioc_dev(OBD_DEV_ID, OBD_DEV_PATH);

	return 0;
}

void obd_finalize(int argc, char **argv)
{
	struct sigaction sigact;

	/* sigact initialization */
	sigact.sa_handler = signal_server;
	sigfillset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;
	/* coverity[uninit_use_in_call] */
	sigaction(SIGINT, &sigact, NULL);

	shmem_cleanup();
	do_disconnect(argv[0], 1);
}

/**
 * Get the index of the last llog record
 *
 * logid:            [0x3:0xa:0x0]:0
 * flags:            4 (plain)
 * records_count:    57
 * last_index:       57
 *
 * \param logname[in]	pointer to config log name
 *
 * \retval		> 0 on success
 *			<= 0 on error
 */
static long llog_last_index(char *logname)
{
	struct obd_ioctl_data data = { 0 };
	char rawbuf[MAX_IOC_BUFLEN] = "", *buf = rawbuf;
	char *last_index;
	long rc;

	data.ioc_dev = cur_device;
	data.ioc_inllen1 = strlen(logname) + 1;
	data.ioc_inlbuf1 = logname;
	data.ioc_inllen2 = sizeof(rawbuf) - __ALIGN_KERNEL(sizeof(data), 8) -
			   __ALIGN_KERNEL(data.ioc_inllen1, 8);
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "%s: ioctl_pack failed for catalog '%s': %s\n",
			__func__, logname, strerror(-rc));
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LLOG_INFO, buf);
	if (rc == 0) {
		last_index = strstr(((struct obd_ioctl_data *)buf)->ioc_bulk,
				    "last_index:");
		return strtol(last_index + 11, NULL, 10);
	}

	rc = -errno;

	return rc;
}

static char *get_llog_event_name(__u32 cmd)
{
	struct lcfg_type_data *data;

	data = lcfg_cmd2data(cmd);
	if (data)
		return data->ltd_name;
	return NULL;
}

static char *get_event_filter(__u32 cmd)
{
	char *event_name;
	char *filter = NULL;
	int len;

	event_name = get_llog_event_name(cmd);
	if (event_name) {
		/* 9 bytes for "event: , " */
		len = 9 + strlen(event_name);
		filter = malloc(len + 1);
		if (!filter)
			return NULL;
		memset(filter, 0, len + 1);
		snprintf(filter, len, "event: %s, ", event_name);
		return filter;
	}

	return NULL;
}

/**
 * Callback to search ostname in llog
 * - { index: 23, event: attach, device: lustre-OST0000-osc, type: osc,
 *     UUID: lustre-clilov_UUID }
 * - { index: 24, event: setup, device: lustre-OST0000-osc,
 *     UUID: lustre-OST0000_UUID, node: 192.168.0.120@tcp }
 * - { index: 25, event: add_osc, device: lustre-clilov,
 *     ost: lustre-OST0000_UUID, index: 0, gen: 1 }
 *
 * \param record[in]	pointer to llog record
 * \param data[in]	pointer to ostname
 *
 * \retval		1 if ostname is found
 *			0 if ostname is not found
 *			-ENOENT if ostname is deleted
 */
static int llog_search_ost_cb(const char *record, void *data)
{
	char *ostname = data;
	char ost_filter[MAX_STRING_SIZE] = {'\0'};
	char *add_osc, *del_osc, *setup, *cleanup;

	add_osc = get_event_filter(LCFG_LOV_ADD_OBD);
	del_osc = get_event_filter(LCFG_LOV_DEL_OBD);
	setup = get_event_filter(LCFG_SETUP);
	cleanup = get_event_filter(LCFG_CLEANUP);
	if (!add_osc || !del_osc || !setup || !cleanup)
		return -ENOMEM;

	if (ostname && ostname[0])
		snprintf(ost_filter, sizeof(ost_filter), " %s,", ostname);

	if (strstr(record, ost_filter)) {
		if (strstr(record, add_osc) || strstr(record, setup))
			return 1;
		if (strstr(record, del_osc) || strstr(record, cleanup))
			return -ENOENT;
	}

	free(add_osc);
	free(del_osc);
	free(setup);
	free(cleanup);

	return 0;
}

/**
 * Search ost in llog
 *
 * \param logname[in]		pointer to config log name
 * \param last_index[in]	the index of the last llog record
 * \param ostname[in]		pointer to ost name
 *
 * \retval			1 if ostname is found
 *				0 if ostname is not found
 */
static int llog_search_ost(char *logname, long last_index, char *ostname)
{
	long start, end, inc = MAX_IOC_BUFLEN / 128;
	int rc = 0;

	for (end = last_index; end > 1; end -= inc) {
		start = end - inc > 0 ? end - inc : 1;
		rc = jt_llog_print_iter(logname, start, end, llog_search_ost_cb,
					ostname, true);
		if (rc)
			break;
	}

	return (rc == 1 ? 1 : 0);
}

struct llog_pool_data {
	char lpd_fsname[LUSTRE_MAXFSNAME + 1];
	char lpd_poolname[LOV_MAXPOOLNAME + 1];
	char lpd_ostname[MAX_OBD_NAME + 1];
	enum lcfg_command_type lpd_cmd_type;
	bool lpd_pool_exists;
	int lpd_ost_num;
};

/**
 * Called for each formatted line in the config log (within range).
 *
 * - { index: 74, event: new_pool, device: tfs-clilov, fsname: tfs, pool: tmp }
 * - { index: 77, event: add_pool, device: tfs-clilov, fsname: tfs, pool: tmp,
 *     ost: tfs-OST0000_UUID }
 * - { index: 224, event: remove_pool, device: tfs-clilov, fsname: tfs,
 *     pool: tmp, ost: tfs-OST0003_UUID }
 * - { index: 227, event: del_pool, device: tfs-clilov, fsname: tfs, pool: tmp }
 *
 * \param record[in]	pointer to llog record
 * \param data[in]	pointer to llog_pool_data
 *
 * \retval		1 if pool or OST is found
 *			0 if pool or OST is not found
 *			-ENOENT if pool or OST is removed
 */
static int llog_search_pool_cb(const char *record, void *data)
{
	struct llog_pool_data *lpd = data;
	char pool_filter[MAX_STRING_SIZE] = "";
	char *new_pool, *del_pool, *add_pool, *rem_pool;
	char *found = NULL;
	int fs_pool_len = 0, rc = 0;

	new_pool = get_event_filter(LCFG_POOL_NEW);
	del_pool = get_event_filter(LCFG_POOL_DEL);
	add_pool = get_event_filter(LCFG_POOL_ADD);
	rem_pool = get_event_filter(LCFG_POOL_REM);
	if (!new_pool || !del_pool || !add_pool || !rem_pool) {
		rc = -ENOMEM;
		goto out;
	}

	fs_pool_len = 16 + strlen(lpd->lpd_fsname) + strlen(lpd->lpd_poolname);
	snprintf(pool_filter, fs_pool_len + 1, "fsname: %s, pool: %s",
		 lpd->lpd_fsname, lpd->lpd_poolname);

	/* search poolname */
	found = strstr(record, pool_filter);
	if (found &&
	    (found[fs_pool_len] == ' ' || found[fs_pool_len] == ',')) {
		if (strstr(record, new_pool)) {
			lpd->lpd_pool_exists = true;
			rc = 1;
			goto out;
		}
		if (strstr(record, del_pool)) {
			lpd->lpd_pool_exists = false;
			rc = -ENOENT;
			goto out;
		}

		if (lpd->lpd_cmd_type == LCFG_POOL_NEW ||
		    lpd->lpd_cmd_type == LCFG_POOL_DEL) {
			if (strstr(record, add_pool))
				lpd->lpd_ost_num++;
			if (strstr(record, rem_pool))
				lpd->lpd_ost_num--;
		} else if (lpd->lpd_ostname && lpd->lpd_ostname[0]) {
			if (strstr(record, lpd->lpd_ostname)) {
				lpd->lpd_pool_exists = true;
				if (strstr(record, add_pool)) {
					lpd->lpd_ost_num = 1;
					rc = 1;
					goto out;
				}
				if (strstr(record, rem_pool)) {
					lpd->lpd_ost_num = 0;
					rc = -ENOENT;
					goto out;
				}
			}
		}
	}
out:
	if (new_pool)
		free(new_pool);
	if (del_pool)
		free(del_pool);
	if (add_pool)
		free(add_pool);
	if (rem_pool)
		free(rem_pool);

	return rc;
}

/* Search pool and its ost in llog
 *
 * \param logname[in]		pointer to config log name
 * \param last_index[in]	the index of the last llog record
 * \param fsname[in]		pointer to filesystem name
 * \param poolname[in]		pointer pool name
 * \param ostname[in]		pointer to OST name(OSTnnnn-UUID)
 * \param cmd[in]		pool command type
 *
 * \retval			< 0 on error
 *				0 if pool is empty or OST is not found
 *				1 if pool is not empty or OST is found
 */
static int llog_search_pool(char *logname, long last_index, char *fsname,
			    char *poolname, char *ostname,
			    enum lcfg_command_type cmd)
{
	struct llog_pool_data lpd;
	long start, end, inc = MAX_IOC_BUFLEN / 128;
	int rc = 0;

	memset(&lpd, 0, sizeof(lpd));
	lpd.lpd_cmd_type = cmd;
	lpd.lpd_pool_exists = false;
	lpd.lpd_ost_num = 0;
	strncpy(lpd.lpd_fsname, fsname, sizeof(lpd.lpd_fsname) - 1);
	if (poolname && poolname[0])
		strncpy(lpd.lpd_poolname, poolname,
			sizeof(lpd.lpd_poolname) - 1);
	if (ostname && ostname[0])
		strncpy(lpd.lpd_ostname, ostname, sizeof(lpd.lpd_ostname) - 1);

	for (end = last_index; end > 1; end -= inc) {
		start = end - inc > 0 ? end - inc : 1;
		rc = jt_llog_print_iter(logname, start, end,
					llog_search_pool_cb, &lpd, true);
		if (rc) {
			if (rc == 1 && lpd.lpd_pool_exists)
				rc = lpd.lpd_ost_num ? 1 : 0;
			else if (rc == -ENOENT && lpd.lpd_pool_exists &&
				 !lpd.lpd_ost_num)
				rc = 0;
			goto out;
		}
	}

	rc = -ENOENT;
out:
	return rc;
}

static bool combined_mgs_mds(char *fsname)
{
	glob_t path;
	int rc;

	rc = cfs_get_param_paths(&path, "mdt/%s-MDT0000", fsname);
	if (!rc)
		cfs_free_param_data(&path);

	if (get_mgs_device() > 0 && !rc)
		return true;

	return false;
}

/*
 * if pool is NULL, search ostname in target_obd
 * if pool is not NULL:
 *  - if pool not found returns errno < 0
 *  - if ostname is NULL, returns 1 if pool is not empty and 0 if pool empty
 *  - if ostname is not NULL, returns 1 if OST is in pool and 0 if not
 */
int lctl_search_ost(char *fsname, char *poolname, char *ostname,
		    enum lcfg_command_type cmd)
{
	char logname[MAX_OBD_NAME] = {'\0'};
	long last_index;

	if (fsname && fsname[0] == '\0')
		fsname = NULL;
	if (!fsname)
		return -EINVAL;

	if (combined_mgs_mds(fsname))
		return llapi_search_ost(fsname, poolname, ostname);

	/* fetch the last_index of llog record */
	snprintf(logname, sizeof(logname), "%s-client", fsname);
	last_index = llog_last_index(logname);
	if (last_index < 0)
		return last_index;

	/* if pool is NULL, search ostname in target_obd */
	if (!poolname && ostname)
		return llog_search_ost(logname, last_index, ostname);

	return llog_search_pool(logname, last_index, fsname, poolname,
				ostname, cmd);
}

static int check_pool_cmd(enum lcfg_command_type cmd, char *fsname,
			  char *poolname, char *ostname)
{
	int rc;

	rc = lctl_search_ost(fsname, poolname, ostname, cmd);
	if (rc < 0 && (cmd != LCFG_POOL_NEW)) {
		fprintf(stderr, "Pool %s.%s not found\n",
			fsname, poolname);
		return rc;
	}

	switch (cmd) {
	case LCFG_POOL_NEW: {
		if (ostname)
			return -EINVAL;

		if (rc >= 0) {
			fprintf(stderr, "Pool %s.%s already exists\n",
				fsname, poolname);
			return -EEXIST;
		}
		return 0;
	}
	case LCFG_POOL_DEL: {
		if (ostname)
			return -EINVAL;

		if (rc == 1) {
			fprintf(stderr,
				"Pool %s.%s not empty, please remove all members\n",
				fsname, poolname);
			return -ENOTEMPTY;
		}
		return 0;
	}
	case LCFG_POOL_ADD: {
		if (rc == 1) {
			fprintf(stderr, "OST %s is already in pool %s.%s\n",
				ostname, fsname, poolname);
			return -EEXIST;
		}
		rc = lctl_search_ost(fsname, NULL, ostname, cmd);
		if (rc == 0) {
			fprintf(stderr, "OST %s is not part of the '%s' fs.\n",
				ostname, fsname);
			return -ENOENT;
		}
		return 0;
	}
	case LCFG_POOL_REM: {
		if (rc == 0) {
			fprintf(stderr, "OST %s not found in pool %s.%s\n",
				ostname, fsname, poolname);
			return -ENOENT;
		}
		return 0;
	}
	default:
		break;
	} /* switch */
	return -EINVAL;
}

/*
 * This check only verifies that the changes have been "pushed out" to
 * the client successfully.  This involves waiting for a config update,
 * and so may fail because of problems in that code or post-command
 * network loss. So reporting a warning is appropriate, but not a failure.
 */
static int check_pool_cmd_result(enum lcfg_command_type cmd, char *fsname,
				 char *poolname, char *ostname)
{
	int cpt = 10;
	int rc = 0;

	switch (cmd) {
	case LCFG_POOL_NEW: {
		do {
			rc = lctl_search_ost(fsname, poolname, NULL, cmd);
			if (rc == -ENODEV)
				return rc;
			if (rc < 0)
				sleep(2);
			cpt--;
		} while ((rc < 0) && (cpt > 0));
		if (rc >= 0) {
			fprintf(stderr, "Pool %s.%s created\n",
				fsname, poolname);
			return 0;
		}

		fprintf(stderr, "Warning, pool %s.%s not found\n", fsname,
			poolname);
		return -ENOENT;
	}
	case LCFG_POOL_DEL: {
		do {
			rc = lctl_search_ost(fsname, poolname, NULL, cmd);
			if (rc == -ENODEV)
				return rc;
			if (rc >= 0)
				sleep(2);
			cpt--;
		} while ((rc >= 0) && (cpt > 0));
		if (rc < 0) {
			fprintf(stderr, "Pool %s.%s destroyed\n",
				fsname, poolname);
			return 0;
		}

		fprintf(stderr, "Warning, pool %s.%s still found\n", fsname,
			poolname);
		return -EEXIST;
	}
	case LCFG_POOL_ADD: {
		do {
			rc = lctl_search_ost(fsname, poolname, ostname, cmd);
			if (rc == -ENODEV)
				return rc;
			if (rc != 1)
				sleep(2);
			cpt--;
		} while ((rc != 1) && (cpt > 0));
		if (rc == 1) {
			fprintf(stderr, "OST %s added to pool %s.%s\n",
				ostname, fsname, poolname);
			return 0;
		}
		fprintf(stderr, "Warning, OST %s not found in pool %s.%s\n",
			ostname, fsname, poolname);
		return -ENOENT;
	}
	case LCFG_POOL_REM: {
		do {
			rc = lctl_search_ost(fsname, poolname, ostname, cmd);
			if (rc == -ENODEV)
				return rc;
			if (rc == 1)
				sleep(2);
			cpt--;
		} while ((rc == 1) && (cpt > 0));
		if (rc != 1) {
			fprintf(stderr, "OST %s removed from pool %s.%s\n",
				ostname, fsname, poolname);
			return 0;
		}
		fprintf(stderr, "Warning, OST %s still found in pool %s.%s\n",
			ostname, fsname, poolname);
		return -EEXIST;
	}
	default:
		break;
	}
	return -EINVAL;
}

static int check_and_complete_ostname(char *fsname, char *ostname)
{
	char *ptr;
	char real_ostname[MAX_OBD_NAME + 1];
	char i;

	/* if OST name does not start with fsname, we add it */
	/* if not check if the fsname is the right one */
	ptr = strchr(ostname, '-');
	if (!ptr) {
		sprintf(real_ostname, "%s-%s", fsname, ostname);
	} else if (strncmp(ostname, fsname, strlen(fsname)) != 0) {
		fprintf(stderr, "%s does not start with fsname %s\n",
			ostname, fsname);
		return -EINVAL;
	} else {
		if (strlen(ostname) > sizeof(real_ostname) - 1)
			return -E2BIG;

		strncpy(real_ostname, ostname, sizeof(real_ostname));
	}

	/* real_ostname is fsname-????? */
	ptr = real_ostname + strlen(fsname) + 1;
	if (strncmp(ptr, "OST", 3) != 0) {
		fprintf(stderr, "%s does not start by %s-OST nor OST\n",
			ostname, fsname);
		return -EINVAL;
	}
	/* real_ostname is fsname-OST????? */
	ptr += 3;
	for (i = 0; i < 4; i++) {
		if (!isxdigit(*ptr)) {
			fprintf(stderr,
				"ost's index in %s is not an hexa number\n",
				ostname);
			return -EINVAL;
		}
		ptr++;
	}
	/* real_ostname is fsname-OSTXXXX????? */
	/* if OST name does not end with _UUID, we add it */
	if (*ptr == '\0') {
		strcat(real_ostname, "_UUID");
	} else if (strcmp(ptr, "_UUID") != 0) {
		fprintf(stderr,
			"ostname %s does not end with _UUID\n", ostname);
		return -EINVAL;
	}
	/* real_ostname is fsname-OSTXXXX_UUID */
	strcpy(ostname, real_ostname);
	return 0;
}

/* returns 0 or -errno */
static int pool_cmd(enum lcfg_command_type cmd, char *cmdname,
		    char *fullpoolname, char *fsname, char *poolname,
		    char *ostname)
{
	int rc = 0;
	struct obd_ioctl_data data;
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;

	rc = check_pool_cmd(cmd, fsname, poolname, ostname);
	if (rc == -ENODEV)
		fprintf(stderr,
			"Can't verify pool command since there is no local MDT or client, proceeding anyhow...\n");
	else if (rc)
		return rc;

	lustre_cfg_bufs_reset(&bufs, NULL);
	lustre_cfg_bufs_set_string(&bufs, 0, cmdname);
	lustre_cfg_bufs_set_string(&bufs, 1, fullpoolname);
	if (ostname)
		lustre_cfg_bufs_set_string(&bufs, 2, ostname);

	lcfg = malloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (!lcfg)
		return -ENOMEM;
	lustre_cfg_init(lcfg, cmd, &bufs);

	memset(&data, 0, sizeof(data));
	rc = data.ioc_dev = get_mgs_device();
	if (rc < 0)
		goto out;

	data.ioc_type = LUSTRE_CFG_TYPE;
	data.ioc_plen1 = lustre_cfg_len(lcfg->lcfg_bufcount,
					lcfg->lcfg_buflens);
	data.ioc_pbuf1 = (void *)lcfg;

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(cmdname));
		free(lcfg);
		return rc;
	}
	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_POOL, buf);
out:
	if (rc)
		rc = -errno;
	switch (rc) {
	case -ENAMETOOLONG:
		fprintf(stderr,
			"error: %s: either the pool or file system name is too long (max pool name len is %d and file system name is %d)\n",
			jt_cmdname(cmdname), LOV_MAXPOOLNAME, LUSTRE_MAXFSNAME);
		break;
	case -EINVAL:
		fprintf(stderr,
			"error: %s can contain only alphanumeric characters, underscores, and dashes besides the required '.'\n",
			jt_cmdname(cmdname));
	default:
		break;
	}
	free(lcfg);
	return rc;
}

#ifdef HAVE_SERVER_SUPPORT
/**
 * Format and send the ioctl to the MGS.
 *
 * \param	cmd		IOCTL to send
 * \param	ret_data	void pointer to return anything from
 *				ioctl
 * \param	num_args	number of arguments to pack into the
 *				ioctl buffer
 * \param	argv[]		variable number of string arguments
 *
 * \retval			0 on success
 */
static int nodemap_cmd(enum lcfg_command_type cmd, void *ret_data,
		       unsigned int ret_size, ...)
{
	va_list			ap;
	char			*arg;
	int			i = 0;
	struct lustre_cfg_bufs	bufs;
	struct obd_ioctl_data	data;
	struct lustre_cfg	*lcfg;
	char			rawbuf[MAX_IOC_BUFLEN];
	char			*buf = rawbuf;
	int			rc = 0;

	lustre_cfg_bufs_reset(&bufs, NULL);

	va_start(ap, ret_size);
	arg = va_arg(ap, char *);
	while (arg) {
		lustre_cfg_bufs_set_string(&bufs, i, arg);
		i++;
		arg = va_arg(ap, char *);
	}
	va_end(ap);

	lcfg = malloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (!lcfg)
		return -ENOMEM;
	lustre_cfg_init(lcfg, cmd, &bufs);

	memset(&data, 0, sizeof(data));
	rc = data.ioc_dev = get_mgs_device();
	if (rc < 0)
		goto out;

	data.ioc_type = LUSTRE_CFG_TYPE;
	data.ioc_plen1 = lustre_cfg_len(lcfg->lcfg_bufcount,
					lcfg->lcfg_buflens);
	data.ioc_pbuf1 = (void *)lcfg;

	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc != 0) {
		fprintf(stderr,
			"error: invalid ioctl: %08x errno: %d with rc=%d\n",
			cmd, errno, rc);
		goto out;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_NODEMAP, buf);
	if (rc != 0) {
		fprintf(stderr,
			"error: invalid ioctl: %08x errno: %d with rc=%d\n",
			cmd, errno, rc);
		goto out;
	}

	if (ret_data) {
		rc = llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
		if (rc != 0)
			goto out;

		if (ret_size > data.ioc_plen1)
			ret_size = data.ioc_plen1;

		memcpy(ret_data, data.ioc_pbuf1, ret_size);
	}
out:
	free(lcfg);

	return rc;
}

/**
 * activate nodemap functions
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * argv[0]			1 for activate or 0 for deactivate
 *
 * \retval			0 on success
 */
int jt_nodemap_activate(int argc, char **argv)
{
	int rc;

	rc = nodemap_cmd(LCFG_NODEMAP_ACTIVATE, NULL, 0, argv[0], argv[1],
			 NULL);

	if (rc != 0) {
		errno = -rc;
		perror(argv[0]);
	}

	return rc;
}

/**
 * add a nodemap
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * argv[0]			nodemap name
 *
 * \retval			0 on success
 */
int jt_nodemap_add(int argc, char **argv)
{
	int rc;

	rc = llapi_nodemap_exists(argv[1]);
	if (rc == 0) {
		fprintf(stderr, "error: %s existing nodemap name\n", argv[1]);
		return 1;
	}

	rc = nodemap_cmd(LCFG_NODEMAP_ADD, NULL, 0, argv[0], argv[1], NULL);

	if (rc != 0) {
		errno = -rc;
		perror(argv[0]);
	}

	return rc;
}

/**
 * delete a nodemap
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * argv[0]			nodemap name
 *
 * \retval			0 on success
 */
int jt_nodemap_del(int argc, char **argv)
{
	int rc;

	rc = llapi_nodemap_exists(argv[1]);
	if (rc != 0) {
		fprintf(stderr, "error: %s not existing nodemap name\n",
			argv[1]);
		return rc;
	}
	rc = nodemap_cmd(LCFG_NODEMAP_DEL, NULL, 0, argv[0], argv[1], NULL);

	if (rc != 0) {
		errno = -rc;
		perror(argv[0]);
	}

	return rc;
}

/**
 * test a nid for nodemap membership
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * argv[0]			properly formatted nid
 *
 * \retval			0 on success
 */
int jt_nodemap_test_nid(int argc, char **argv)
{
	char	rawbuf[MAX_IOC_BUFLEN];
	int	rc;

	rc = nodemap_cmd(LCFG_NODEMAP_TEST_NID, &rawbuf, sizeof(rawbuf),
			 argv[0], argv[1], NULL);
	if (rc == 0)
		printf("%s\n", (char *)rawbuf);

	return rc;
}

/**
 * test a nodemap id pair for mapping
 *
 * \param	argc		number of args
 * \param	argv[[]		variable string arguments
 *
 * \retval			0 on success
 *
 * The argv array should contain the nodemap name, the id
 * to checking the mapping on, and the id type (UID or GID)
 *
 */
int jt_nodemap_test_id(int argc, char **argv)
{
	char	rawbuf[MAX_IOC_BUFLEN];
	char	*nidstr = NULL;
	char	*idstr = NULL;
	char	*typestr = NULL;
	int	rc = 0;
	int	c;

	static struct option long_opts[] = {
		{ .val = 'i',	.name = "id",	.has_arg = required_argument },
		{ .val = 'n',	.name = "nid",	.has_arg = required_argument },
		{ .val = 't',	.name = "idtype",
						.has_arg = required_argument },
		{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "n:t:i:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'n':
			nidstr = optarg;
			break;
		case 't':
			typestr = optarg;
			break;
		case 'i':
			idstr = optarg;
			break;
		}
	}

	if (!nidstr || !typestr || !idstr) {
		fprintf(stderr,
			"usage: nodemap_test_id --nid <nid> --idtype [uid|gid] --id <id>\n");
		return -1;
	}

	rc = nodemap_cmd(LCFG_NODEMAP_TEST_ID, &rawbuf, sizeof(rawbuf),
			 argv[0], nidstr, typestr, idstr);
	if (rc == 0)
		printf("%s\n", (char *)rawbuf);

	return rc;
}

/**
 * parse nid range
 *
 * \param	nodemap_range	--range string
 * \param	nid_range	nid range string, min_nid:max_nid
 *
 * \retval			0 on success
 */
static int parse_nid_range(char *nodemap_range, char *nid_range, int range_len)
{
	char			min_nid[LNET_NIDSTR_SIZE + 1];
	char			max_nid[LNET_NIDSTR_SIZE + 1];
	struct list_head	nidlist;
	int			rc = 0;

	INIT_LIST_HEAD(&nidlist);

	if (cfs_parse_nidlist(nodemap_range, strlen(nodemap_range),
			      &nidlist) <= 0) {
		fprintf(stderr,
			"error: nodemap_xxx_range: can't parse nid range: %s\n",
			nodemap_range);
		return -1;
	}

	rc = cfs_nidrange_find_min_max(&nidlist, &min_nid[0], &max_nid[0],
				       LNET_NIDSTR_SIZE);
	if (rc < 0) {
		if (rc == -EINVAL)
			fprintf(stderr,
				"error: nodemap_xxx_range: nid range uses currently unsupported features\n");
		else if (rc == -ERANGE)
			fprintf(stderr,
				"error: nodemap_xxx_range: nodemap ranges must be contiguous\n");

		return rc;
	}

	snprintf(nid_range, range_len, "%s:%s", min_nid, max_nid);

	return rc;
}

/**
 * add an nid range to a nodemap
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * --name			nodemap name
 * --range			properly formatted nid range
 *
 * \retval			0 on success
 */
int jt_nodemap_add_range(int argc, char **argv)
{
	char			*nodemap_name = NULL;
	char			*nodemap_range = NULL;
	char			nid_range[2 * LNET_NIDSTR_SIZE + 2];
	int			rc = 0;
	int			c;

	static struct option long_opts[] = {
	{ .val = 'n',	.name = "name",		.has_arg = required_argument },
	{ .val = 'r',	.name = "range",	.has_arg = required_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "n:r:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'n':
			nodemap_name = optarg;
			break;
		case 'r':
			nodemap_range = optarg;
			break;
		}
	}

	if (!nodemap_name || !nodemap_range) {
		fprintf(stderr,
			"usage: nodemap_add_range --name <name> --range <range>\n");
		return -1;
	}

	rc = parse_nid_range(nodemap_range, nid_range, sizeof(nid_range));
	if (rc) {
		errno = -rc;
		return rc;
	}
	rc = nodemap_cmd(LCFG_NODEMAP_ADD_RANGE, NULL, 0, argv[0],
			 nodemap_name, nid_range, NULL);
	if (rc != 0) {
		errno = -rc;
		fprintf(stderr,
			"error: %s: cannot add range '%s' to nodemap '%s': rc = %d\n",
			jt_cmdname(argv[0]), nodemap_range, nodemap_name, rc);
	}

	return rc;
}

/**
 * delete an nid range to a nodemap
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * --name			nodemap name
 * --range			properly formatted nid range
 *
 * \retval			0 on success
 */
int jt_nodemap_del_range(int argc, char **argv)
{
	char			*nodemap_name = NULL;
	char			*nodemap_range = NULL;
	char			nid_range[2 * LNET_NIDSTR_SIZE + 2];
	int			rc = 0;
	int			c;

	static struct option long_opts[] = {
	{ .val = 'n',	.name = "name",		.has_arg = required_argument },
	{ .val = 'r',	.name = "range",	.has_arg = required_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "n:r:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'n':
			nodemap_name = optarg;
			break;
		case 'r':
			nodemap_range = optarg;
			break;
		}
	}

	if (!nodemap_name || !nodemap_range) {
		fprintf(stderr,
			"usage: nodemap_del_range --name <name> --range <range>\n");
		return -1;
	}

	rc = parse_nid_range(nodemap_range, nid_range, sizeof(nid_range));
	if (rc) {
		errno = -rc;
		return rc;
	}
	rc = nodemap_cmd(LCFG_NODEMAP_DEL_RANGE, NULL, 0, argv[0],
			 nodemap_name, nid_range, NULL);
	if (rc != 0) {
		errno = -rc;
		fprintf(stderr,
			"error: %s: cannot delete range '%s' to nodemap '%s': rc = %d\n",
			jt_cmdname(argv[0]), nodemap_range, nodemap_name, rc);
	}

	return rc;
}

/**
 * set a fileset on a nodemap
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * --name			nodemap name
 * --fileset			fileset name
 *
 * \retval			0 on success
 */
int jt_nodemap_set_fileset(int argc, char **argv)
{
	char *nodemap_name = NULL;
	char *fileset_name = NULL;
	int   rc = 0;
	int   c;

	static struct option long_opts[] = {
	{ .val = 'f',	.name = "fileset",	.has_arg = required_argument },
	{ .val = 'n',	.name = "name",		.has_arg = required_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "n:f:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'n':
			nodemap_name = optarg;
			break;
		case 'f':
			fileset_name = optarg;
			break;
		}
	}

	if (!nodemap_name || !fileset_name) {
		fprintf(stderr,
			"usage: nodemap_set_fileset --name <name> --fileset <fileset>\n");
		return -1;
	}

	rc = nodemap_cmd(LCFG_NODEMAP_SET_FILESET, NULL, 0, argv[0],
			 nodemap_name, fileset_name, NULL);
	if (rc != 0) {
		errno = -rc;
		fprintf(stderr,
			"error: %s: cannot set fileset '%s' on nodemap '%s': rc = %d\n",
			jt_cmdname(argv[0]), fileset_name, nodemap_name, rc);
	}

	return rc;
}

/**
 * set SELinux policy info on a nodemap
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * --name			nodemap name
 * --sepol			SELinux policy info
 *
 * \retval			0 on success
 */
int jt_nodemap_set_sepol(int argc, char **argv)
{
	char *nodemap_name = NULL;
	char *sepol = NULL;
	int   rc = 0;
	int   c;

	static struct option long_options[] = {
		{
			.name		= "name",
			.has_arg	= required_argument,
			.val		= 'n',
		},
		{
			.name		= "sepol",
			.has_arg	= required_argument,
			.val		= 's',
		},
		{
			.name = NULL,
		}
	};

	while ((c = getopt_long(argc, argv, "n:s:",
				long_options, NULL)) != -1) {
		switch (c) {
		case 'n':
			nodemap_name = optarg;
			break;
		case 's':
			sepol = optarg;
			break;
		}
	}

	if (!nodemap_name || !sepol) {
		fprintf(stderr,
			"usage: nodemap_set_sepol --name <name> --sepol <sepol>\n");
		return -1;
	}

	rc = nodemap_cmd(LCFG_NODEMAP_SET_SEPOL, NULL, 0, argv[0],
			 nodemap_name, sepol, NULL);
	if (rc != 0) {
		errno = -rc;
		fprintf(stderr,
			"error: %s: cannot set sepol '%s' on nodemap '%s': rc = %d\n",
			jt_cmdname(argv[0]), sepol, nodemap_name, rc);
	}

	return rc;
}

/**
 * modify a nodemap's behavior
 *
 * \param	argc		number of args
 * \param	argv[]		variable string arguments
 *
 * --name			nodemap name
 * --property			nodemap property to change
 *				admin, trusted, squash_uid, squash_gid)
 * --value			value to set property
 *
 * \retval			0 on success
 */
int jt_nodemap_modify(int argc, char **argv)
{
	int			c;
	int			rc = 0;
	enum lcfg_command_type	cmd = 0;
	char			*nodemap_name = NULL;
	char			*param = NULL;
	char			*value = NULL;

	static struct option long_opts[] = {
	{ .val = 'n',	.name = "name",		.has_arg = required_argument },
	{ .val = 'p',	.name = "property",	.has_arg = required_argument },
	{ .val = 'v',	.name = "value",	.has_arg = required_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "n:p:v:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'n':
			nodemap_name = optarg;
			break;
		case 'p':
			param = optarg;
			break;
		case 'v':
			value = optarg;
			break;
		}
	}

	if (!nodemap_name || !param || !value) {
		fprintf(stderr,
			"usage: nodemap_modify --name <nodemap_name> --property <property_name> --value <value>\n");
		fprintf(stderr,
			"valid properties: admin trusted map_mode squash_uid squash_gid deny_unknown audit_mode forbid_encryption\n");
		return -1;
	}

	if (strcmp("admin", param) == 0) {
		cmd = LCFG_NODEMAP_ADMIN;
	} else if (strcmp("trusted", param) == 0) {
		cmd = LCFG_NODEMAP_TRUSTED;
	} else if (strcmp("deny_unknown", param) == 0) {
		cmd = LCFG_NODEMAP_DENY_UNKNOWN;
	} else if (strcmp("squash_uid", param) == 0) {
		cmd = LCFG_NODEMAP_SQUASH_UID;
	} else if (strcmp("squash_gid", param) == 0) {
		cmd = LCFG_NODEMAP_SQUASH_GID;
	} else if (strcmp("map_mode", param) == 0) {
		cmd = LCFG_NODEMAP_MAP_MODE;
	} else if (strcmp("audit_mode", param) == 0) {
		cmd = LCFG_NODEMAP_AUDIT_MODE;
	} else if (strcmp("forbid_encryption", param) == 0) {
		cmd = LCFG_NODEMAP_FORBID_ENCRYPT;
	} else {
		fprintf(stderr,
			"error: %s: nodemap_modify invalid subcommand: %s\n",
			jt_cmdname(argv[0]), param);
		return -1;
	}

	rc = nodemap_cmd(cmd, NULL, 0, argv[0], nodemap_name, param,
			 value, NULL);
	if (rc != 0) {
		errno = -rc;
		fprintf(stderr,
			"error: %s: cannot modify nodemap '%s' to param '%s': value '%s': rc = %d\n",
			jt_cmdname(argv[0]), nodemap_name, param, value, rc);
	}

	return rc;
}

int jt_nodemap_add_idmap(int argc, char **argv)
{
	int			c;
	enum			lcfg_command_type cmd = 0;
	char			*nodemap_name = NULL;
	char			*idmap = NULL;
	char			*idtype = NULL;
	int			rc = 0;

	static struct option long_opts[] = {
	{ .val = 'i',	.name = "idtype",	.has_arg = required_argument },
	{ .val = 'm',	.name = "idmap",	.has_arg = required_argument },
	{ .val = 'n',	.name = "name",		.has_arg = required_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "n:m:i:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'n':
			nodemap_name = optarg;
			break;
		case 'm':
			idmap = optarg;
			break;
		case 'i':
			idtype = optarg;
			break;
		}
	}

	if (!nodemap_name || !idmap || !idtype) {
		fprintf(stderr,
			"usage: %s --name <name> --idtype [uid | gid] --idmap <client id>:<filesystem id>\n",
			argv[0]);
		return -1;
	}

	if (strcmp("uid", idtype) == 0) {
		cmd = LCFG_NODEMAP_ADD_UIDMAP;
	} else if (strcmp("gid", idtype) == 0) {
		cmd = LCFG_NODEMAP_ADD_GIDMAP;
	} else {
		fprintf(stderr,
			"usage: %s --name <name> --idtype [uid | gid] --idmap <client id>:<filesystem id>\n",
			argv[0]);
		return -1;
	}

	rc = nodemap_cmd(cmd, NULL, 0, argv[0], nodemap_name, idmap, NULL);
	if (rc != 0) {
		errno = -rc;
		fprintf(stderr,
			"cannot add %smap '%s' to nodemap '%s': rc = %d\n",
			idtype, idmap, nodemap_name, rc);
	}

	return rc;
}

int jt_nodemap_del_idmap(int argc, char **argv)
{
	int			c;
	enum			lcfg_command_type cmd = 0;
	char			*nodemap_name = NULL;
	char			*idmap = NULL;
	char			*idtype = NULL;
	int			rc = 0;

	static struct option long_opts[] = {
	{ .val = 'i',	.name = "idtype",	.has_arg = required_argument },
	{ .val = 'm',	.name = "idmap",	.has_arg = required_argument },
	{ .val = 'n',	.name = "name",		.has_arg = required_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "n:m:i:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'n':
			nodemap_name = optarg;
			break;
		case 'm':
			idmap = optarg;
			break;
		case 'i':
			idtype = optarg;
			break;
		}
	}

	if (!nodemap_name || !idmap || !idtype) {
		fprintf(stderr,
			"usage: %s --name <name> --idtype [uid | gid] --idmap <client id>:<filesystem id>\n",
			argv[0]);
		return -1;
	}

	if (strcmp("uid", idtype) == 0)
		cmd = LCFG_NODEMAP_DEL_UIDMAP;
	else
		cmd = LCFG_NODEMAP_DEL_GIDMAP;

	rc = nodemap_cmd(cmd, NULL, 0, argv[0], nodemap_name, idmap, NULL);
	if (rc != 0) {
		errno = -rc;
		fprintf(stderr,
			"cannot delete %smap '%s' from nodemap '%s': rc = %d\n",
			idtype, idmap, nodemap_name, rc);
	}

	return rc;
}
#else /* !HAVE_SERVER_SUPPORT */
int jt_nodemap_activate(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_add(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_del(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_modify(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_add_range(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_test_nid(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_del_range(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_add_idmap(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_del_idmap(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_test_id(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_set_fileset(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_set_sepol(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_nodemap_info(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}
#endif /* HAVE_SERVER_SUPPORT */

/*
 * this function tranforms a rule [start-end/step] into an array
 * of matching numbers
 * supported forms are:
 * [start]                : just this number
 * [start-end]            : all numbers from start to end
 * [start-end/step]       : numbers from start to end with increment of step
 * on return, format contains a printf format string which can be used
 * to generate all the strings
 */
static int get_array_idx(char *rule, char *format, int **array)
{
	char *start, *end, *ptr;
	unsigned int lo, hi, step;
	int array_sz = 0;
	int i, array_idx;
	int rc;

	start = strchr(rule, '[');
	end = strchr(rule, ']');
	if ((!start) || (!end)) {
		*array = malloc(sizeof(int));
		if (!*array)
			return 0;
		strcpy(format, rule);
		array_sz = 1;
		return array_sz;
	}
	*start = '\0';
	*end = '\0';
	end++;
	start++;
	/* put in format the printf format (the rule without the range) */
	sprintf(format, "%s%%.4x%s", rule, end);

	array_idx = 0;
	array_sz = 0;
	*array = NULL;
	/* loop on , separator */
	do {
		/* extract the 3 fields */
		rc = sscanf(start, "%x-%x/%u", &lo, &hi, &step);
		switch (rc) {
		case 0:
			goto err;
		case 1: {
			void *tmp;

			array_sz++;
			tmp = realloc(*array, array_sz * sizeof(int));
			if (!tmp)
				goto err;
			*array = tmp;
			(*array)[array_idx] = lo;
			array_idx++;
			break;
		}
		case 2: {
			step = 1;
			/* do not break to share code with case 3: */
		}
		case 3: {
			void *tmp;

			if ((hi < lo) || (step == 0))
				goto err;
			array_sz += (hi - lo) / step + 1;
			tmp = realloc(*array, array_sz * sizeof(int));
			if (!tmp)
				goto err;
			*array = tmp;
			for (i = lo; i <= hi; i += step, array_idx++)
				(*array)[array_idx] = i;
			break;
		}
		}
		ptr = strchr(start, ',');
		if (ptr)
			start = ptr + 1;

	} while (ptr);
	return array_sz;
err:
	if (*array) {
		free(*array);
		*array = NULL;
	}
	return 0;
}

struct llog_pool_name {
	char lpn_name[UUID_MAX];
	struct list_head lpn_list;
};

struct llog_pool_list_data {
	char lpld_fsname[LUSTRE_MAXFSNAME + 1];
	char lpld_poolname[LOV_MAXPOOLNAME + 1];
	bool lpld_exists;
	struct list_head lpld_list_head;
};

/**
 * Callback to list pool information in llog
 * - { index: 74, event: new_pool, device: tfs-clilov, fsname: tfs, pool: tmp }
 * - { index: 77, event: add_pool, device: tfs-clilov, fsname: tfs, pool: tmp,
 *     ost: tfs-OST0000_UUID }
 * - { index: 224, event: remove_pool, device: tfs-clilov, fsname: tfs,
 *     pool: tmp, ost: tfs-OST0003_UUID }
 * - { index: 227, event: del_pool, device: tfs-clilov, fsname: tfs, pool: tmp }
 *
 * \param record[in]	pointer to llog record
 * \param data[in]	pointer to struct llog_pool_list_data
 *
 * \retval		0 on success
 *			<0 on error
 */
static int llog_poollist_cb(const char *record, void *data)
{
	struct llog_pool_list_data *lpld = data;
	char pool_filter[MAX_STRING_SIZE] = "";
	char *new_record, *del_record, *del_pool, *found;
	char type[10] = "";
	int filter_len, rc = 0;

	filter_len = snprintf(pool_filter, sizeof(pool_filter), " fsname: %s,",
			      lpld->lpld_fsname);
	if (lpld->lpld_poolname[0] == '\0') {
		new_record = get_event_filter(LCFG_POOL_NEW);
		del_record = get_event_filter(LCFG_POOL_DEL);
		strncpy(type, " pool: ", sizeof(type));
	} else {
		filter_len += snprintf(pool_filter + filter_len,
				       sizeof(pool_filter) - filter_len,
				       " pool: %s", lpld->lpld_poolname);
		new_record = get_event_filter(LCFG_POOL_ADD);
		del_record = get_event_filter(LCFG_POOL_REM);
		strncpy(type, " ost: ", sizeof(type));
	}
	del_pool = get_event_filter(LCFG_POOL_DEL);

	if (!new_record || !del_record || !del_pool) {
		rc = -ENOMEM;
		goto out;
	}

	found = strstr(record, pool_filter);
	if (found &&
	    (found[filter_len] == ' ' || found[filter_len] == ',')) {
		struct llog_pool_name *tmp = NULL;
		struct list_head *head = &lpld->lpld_list_head;
		char *name;
		int name_len, type_len = strlen(type);

		lpld->lpld_exists = true;
		if (strstr(record, new_record)) {
			name = strstr(record, type);
			/* 2 bytes for " }" */
			name_len = strlen(name) - type_len - 2;
			if (name_len <= 0 || name_len > sizeof(tmp->lpn_name))
				return -EINVAL;
			tmp = malloc(sizeof(struct llog_pool_name));
			if (!tmp) {
				rc = -ENOMEM;
				goto out;
			}
			memset(tmp, 0, sizeof(struct llog_pool_name));
			strncpy(tmp->lpn_name, name + type_len, name_len);
			list_add_tail(&tmp->lpn_list, &lpld->lpld_list_head);
		} else if (strstr(record, del_record)) {
			name = strstr(record, type);
			name_len = strlen(name) - type_len - 2;
			list_for_each_entry(tmp, head, lpn_list) {
				if (strncmp(tmp->lpn_name, name + type_len,
					    name_len) == 0 &&
					    tmp->lpn_name[name_len] == '\0') {
					list_del(&tmp->lpn_list);
					free(tmp);
					break;
				}
			}
		}
		/* verify if the specified pool still exists */
		if (lpld->lpld_poolname[0] && strstr(record, del_pool))
			lpld->lpld_exists = false;
	}
out:
	if (new_record)
		free(new_record);
	if (del_record)
		free(del_record);
	if (del_pool)
		free(del_pool);

	return rc;
}

/**
 * List pool information by config log
 *
 * \param fsname[in]	pointer to filesystem name
 * \param poolname[in]	pointer to pool name
 *
 * \retval		0 on success
 *			< 0 on error
 */
int llog_poollist(char *fsname, char *poolname)
{
	char logname[MAX_OBD_NAME] = {'\0'};
	struct llog_pool_list_data lpld;
	struct llog_pool_name *tmp;
	struct list_head *head;
	int rc = 0;

	if (fsname && fsname[0] == '\0')
		fsname = NULL;
	if (!fsname)
		return -EINVAL;

	memset(&lpld, 0, sizeof(lpld));
	INIT_LIST_HEAD(&lpld.lpld_list_head);
	lpld.lpld_exists = false;
	strncpy(lpld.lpld_fsname, fsname, sizeof(lpld.lpld_fsname) - 1);
	if (poolname && poolname[0])
		strncpy(lpld.lpld_poolname, poolname,
			sizeof(lpld.lpld_poolname) - 1);
	snprintf(logname, sizeof(logname), "%s-client", fsname);
	rc = jt_llog_print_iter(logname, 0, -1, llog_poollist_cb, &lpld, false);

	if (poolname && poolname[0])
		printf("Pool: %s.%s\n", fsname, poolname);
	else
		printf("Pools from %s:\n", fsname);

	head = &lpld.lpld_list_head;
	if (poolname && poolname[0] && !lpld.lpld_exists && list_empty(head))
		return -ENOENT;

	list_for_each_entry(tmp, head, lpn_list) {
		if (poolname && poolname[0])
			printf("%s\n", tmp->lpn_name);
		else
			printf("%s.%s\n", fsname, tmp->lpn_name);
		list_del(&tmp->lpn_list);
		free(tmp);
	}

	return rc;
}

static bool get_pools_path(char *fsname)
{
	glob_t path;
	int rc;

	rc = cfs_get_param_paths(&path, "lov/%s-*/pools", fsname);
	if (!rc)
		cfs_free_param_data(&path);

	return (rc == 0);
}

static int extract_fsname_poolname(char **argv, char *fsname,
				   char *poolname)
{
	char *cmd = argv[0], *param = argv[1];
	char *ptr;
	int rc;

	snprintf(fsname, PATH_MAX + 1, "%s", param);
	ptr = strchr(fsname, '.');
	if (!ptr) {
		if (strcmp(cmd, "pool_list") == 0) {
			poolname = NULL;
			goto out;
		}
		fprintf(stderr, ". is missing in %s\n", fsname);
		rc = -EINVAL;
		goto err;
	}

	if ((ptr - fsname) == 0) {
		fprintf(stderr, "fsname is empty\n");
		rc = -EINVAL;
		goto err;
	}

	*ptr = '\0';
	++ptr;

	if (strlen(ptr) == 0) {
		fprintf(stderr, "poolname is empty\n");
		rc = -EINVAL;
		goto err;
	}

	strncpy(poolname, ptr, LOV_MAXPOOLNAME);
	poolname[LOV_MAXPOOLNAME] = '\0';

	if (strncmp(poolname, "none", LOV_MAXPOOLNAME) == 0) {
		fprintf(stderr, "poolname cannot be 'none'\n");
		return -EINVAL;
	}
out:
	return 0;

err:
	fprintf(stderr, "argument %s must be <fsname>.<poolname>\n", param);
	return rc;
}

int jt_pool_cmd(int argc, char **argv)
{
	enum lcfg_command_type cmd;
	char fsname[PATH_MAX + 1];
	char poolname[LOV_MAXPOOLNAME + 1];
	char *ostnames_buf = NULL;
	int i, rc;
	int *array = NULL, array_sz;
	struct {
		int     rc;
		char   *ostname;
	} *cmds = NULL;

	switch (argc) {
	case 0:
	case 1: return CMD_HELP;
	case 2: {
		rc = extract_fsname_poolname(argv, fsname, poolname);
		if (rc)
			break;

		if (strcmp("pool_new", argv[0]) == 0) {
			cmd = LCFG_POOL_NEW;
		} else if (strcmp("pool_destroy", argv[0]) == 0) {
			cmd = LCFG_POOL_DEL;
		} else if (strcmp("pool_list", argv[0]) == 0) {
			if (get_pools_path(fsname))
				return llapi_poollist(argv[1]);
			if (get_mgs_device() > 0)
				return llog_poollist(fsname, poolname);
			fprintf(stderr,
				"Cannot run pool_list command since there is no local MGS/MDT or client\n");
			return CMD_HELP;
		} else {
			return CMD_HELP;
		}

		rc = pool_cmd(cmd, argv[0], argv[1], fsname, poolname, NULL);
		if (rc)
			break;

		check_pool_cmd_result(cmd, fsname, poolname, NULL);
		break;
	}
	default: {
		char format[2 * MAX_OBD_NAME];

		if (strcmp("pool_remove", argv[0]) == 0)
			cmd = LCFG_POOL_REM;
		else if (strcmp("pool_add", argv[0]) == 0)
			cmd = LCFG_POOL_ADD;
		else
			return CMD_HELP;

		rc = extract_fsname_poolname(argv, fsname, poolname);
		if (rc)
			break;

		for (i = 2; i < argc; i++) {
			int j;

			array_sz = get_array_idx(argv[i], format, &array);
			if (array_sz == 0)
				return CMD_HELP;

			cmds = malloc(array_sz * sizeof(cmds[0]));
			if (cmds) {
				ostnames_buf = malloc(array_sz *
						      (MAX_OBD_NAME + 1));
			} else {
				free(array);
				rc = -ENOMEM;
				goto out;
			}

			for (j = 0; j < array_sz; j++) {
				char ostname[MAX_OBD_NAME + 1];
				int rc2;

				snprintf(ostname, MAX_OBD_NAME, format,
					 array[j]);
				ostname[MAX_OBD_NAME] = '\0';

				rc2 = check_and_complete_ostname(fsname,
								ostname);
				if (rc2) {
					free(array);
					free(cmds);
					if (ostnames_buf)
						free(ostnames_buf);
					rc = rc ? rc : rc2;
					goto out;
				}
				if (ostnames_buf) {
					cmds[j].ostname =
					&ostnames_buf[(MAX_OBD_NAME + 1) * j];
					strcpy(cmds[j].ostname, ostname);
				} else {
					cmds[j].ostname = NULL;
				}
				cmds[j].rc = pool_cmd(cmd, argv[0], argv[1],
						      fsname, poolname,
						      ostname);
				/* Return an err if any of the add/dels fail */
				if (!rc)
					rc = cmds[j].rc;
			}
			for (j = 0; j < array_sz; j++) {
				if (!cmds[j].rc) {
					char ostname[MAX_OBD_NAME + 1];

					if (!cmds[j].ostname) {
						snprintf(ostname, MAX_OBD_NAME,
							 format, array[j]);
						ostname[MAX_OBD_NAME] = '\0';
						check_and_complete_ostname(
							fsname, ostname);
					} else {
						strcpy(ostname,
						       cmds[j].ostname);
					}
					check_pool_cmd_result(cmd, fsname,
							      poolname,
							      ostname);
				}
			}
			if (array_sz > 0)
				free(array);
			if (cmds)
				free(cmds);
			if (ostnames_buf)
				free(ostnames_buf);
		}
		/* fall through */
	}
	} /* switch */

out:
	if (rc != 0) {
		errno = -rc;
		perror(argv[0]);
	}

	return rc;
}

#ifdef HAVE_SERVER_SUPPORT
static const char *barrier_status2name(enum barrier_status status)
{
	switch (status) {
	case BS_INIT:
		return "init";
	case BS_FREEZING_P1:
		return "freezing_p1";
	case BS_FREEZING_P2:
		return "freezing_p2";
	case BS_FROZEN:
		return "frozen";
	case BS_THAWING:
		return "thawing";
	case BS_THAWED:
		return "thawed";
	case BS_FAILED:
		return "failed";
	case BS_EXPIRED:
		return "expired";
	case BS_RESCAN:
		return "rescan";
	default:
		return "unknown";
	}
}

int jt_barrier_freeze(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	struct barrier_ctl bc;
	int rc;

	if (argc < 2 || argc > 3)
		return CMD_HELP;

	memset(&data, 0, sizeof(data));
	rc = data.ioc_dev = get_mgs_device();
	if (rc < 0)
		return rc;

	memset(&bc, 0, sizeof(bc));
	bc.bc_version = BARRIER_VERSION_V1;
	bc.bc_cmd = BC_FREEZE;
	if (argc == 3)
		bc.bc_timeout = atoi(argv[2]);
	if (bc.bc_timeout == 0)
		bc.bc_timeout = BARRIER_TIMEOUT_DEFAULT;

	if (strlen(argv[1]) > 8) {
		fprintf(stderr,
			"%s: fsname name %s is too long. It should not exceed 8.\n",
			argv[0], argv[1]);
		return -EINVAL;
	}

	strncpy(bc.bc_name, argv[1], sizeof(bc.bc_name));
	data.ioc_inlbuf1 = (char *)&bc;
	data.ioc_inllen1 = sizeof(bc);
	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "Fail to pack ioctl data: rc = %d.\n", rc);
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_BARRIER, buf);
	if (rc < 0)
		fprintf(stderr, "Fail to freeze barrier for %s: %s\n",
			argv[1], strerror(errno));

	return rc;
}

int jt_barrier_thaw(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	struct barrier_ctl bc;
	int rc;

	if (argc != 2)
		return CMD_HELP;

	memset(&data, 0, sizeof(data));
	rc = data.ioc_dev = get_mgs_device();
	if (rc < 0)
		return rc;

	memset(&bc, 0, sizeof(bc));
	bc.bc_version = BARRIER_VERSION_V1;
	bc.bc_cmd = BC_THAW;

	if (strlen(argv[1]) > 8) {
		fprintf(stderr,
			"fsname name %s is too long. It should not exceed 8.\n",
			argv[1]);
		return -EINVAL;
	}

	strncpy(bc.bc_name, argv[1], sizeof(bc.bc_name));
	data.ioc_inlbuf1 = (char *)&bc;
	data.ioc_inllen1 = sizeof(bc);
	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "Fail to pack ioctl data: rc = %d.\n", rc);
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_BARRIER, buf);
	if (rc < 0)
		fprintf(stderr, "Fail to thaw barrier for %s: %s\n",
			argv[1], strerror(errno));

	return rc;
}

int __jt_barrier_stat(const char *fsname, struct barrier_ctl *bc)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	int rc;

	memset(&data, 0, sizeof(data));
	rc = data.ioc_dev = get_mgs_device();
	if (rc < 0)
		return rc;

	memset(bc, 0, sizeof(*bc));
	bc->bc_version = BARRIER_VERSION_V1;
	bc->bc_cmd = BC_STAT;
	strncpy(bc->bc_name, fsname, sizeof(bc->bc_name) - 1);
	data.ioc_inlbuf1 = (char *)bc;
	data.ioc_inllen1 = sizeof(*bc);
	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "Fail to pack ioctl data: rc = %d.\n", rc);
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_BARRIER, buf);
	if (rc < 0)
		fprintf(stderr, "Fail to query barrier for %s: %s\n",
			fsname, strerror(errno));
	else
		llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));

	return rc;
}

int jt_barrier_stat(int argc, char **argv)
{
	struct barrier_ctl bc;
	static struct option long_opt_barrier_stat[] = {
		{
			.val		= 's',
			.name		= "state",
			.has_arg	= no_argument,
		},
		{	.val		= 't',
			.name		= "timeout",
			.has_arg	= no_argument,
		},
		{
			NULL
		}
	};
	const char *name;
	int index;
	int opt;
	int rc;
	bool state = false;
	bool timeout = false;

	while ((opt = getopt_long(argc, argv, "st", long_opt_barrier_stat,
				  &index)) != EOF) {
		switch (opt) {
		case 's':
			state = true;
			break;
		case 't':
			timeout = true;
			break;
		default:
			return CMD_HELP;
		}
	}

	if (optind >= argc)
		return CMD_HELP;

	name = argv[optind];
	if (strlen(name) > 8) {
		fprintf(stderr,
			"fsname name %s is too long. It should not exceed 8.\n",
			name);
		return -EINVAL;
	}

	rc = __jt_barrier_stat(name, &bc);
	if (!rc) {
		if (state && !timeout)
			printf("%s\n", barrier_status2name(bc.bc_status));
		else if (timeout && !state)
			printf("%d\n",
			       (bc.bc_status == BS_FREEZING_P1 ||
				bc.bc_status == BS_FREEZING_P2 ||
				bc.bc_status == BS_FROZEN) ?
			       bc.bc_timeout : 0);
		else
			printf("state: %s\ntimeout: %d seconds\n",
			       barrier_status2name(bc.bc_status),
			       (bc.bc_status == BS_FREEZING_P1 ||
				bc.bc_status == BS_FREEZING_P2 ||
				bc.bc_status == BS_FROZEN) ?
			       bc.bc_timeout : 0);
	}

	return rc;
}

int jt_barrier_rescan(int argc, char **argv)
{
	struct obd_ioctl_data data;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf;
	struct barrier_ctl bc;
	int rc;

	if (argc < 2 || argc > 3)
		return CMD_HELP;

	memset(&data, 0, sizeof(data));
	rc = data.ioc_dev = get_mgs_device();
	if (rc < 0)
		return rc;

	memset(&bc, 0, sizeof(bc));
	bc.bc_version = BARRIER_VERSION_V1;
	bc.bc_cmd = BC_RESCAN;
	if (argc == 3)
		bc.bc_timeout = atoi(argv[2]);
	if (bc.bc_timeout == 0)
		bc.bc_timeout = BARRIER_TIMEOUT_DEFAULT;

	if (strlen(argv[1]) > 8) {
		fprintf(stderr,
			"fsname name %s is too long. It should not exceed 8.\n",
			argv[1]);
		return -EINVAL;
	}

	strncpy(bc.bc_name, argv[1], sizeof(bc.bc_name));
	data.ioc_inlbuf1 = (char *)&bc;
	data.ioc_inllen1 = sizeof(bc);
	memset(buf, 0, sizeof(rawbuf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "Fail to pack ioctl data: rc = %d.\n", rc);
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_BARRIER, buf);
	if (rc < 0) {
		fprintf(stderr, "Fail to rescan barrier bitmap for %s: %s\n",
			argv[1], strerror(errno));
	} else {
		llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
		printf("%u of %u MDT(s) in the filesystem %s are inactive\n",
		       bc.bc_absence, bc.bc_total, argv[1]);
	}

	return rc;
}
#endif /* HAVE_SERVER_SUPPORT */

int jt_get_obj_version(int argc, char **argv)
{
	struct lu_fid fid;
	struct obd_ioctl_data data;
	__u64 version, id = ULLONG_MAX, group = ULLONG_MAX;
	char rawbuf[MAX_IOC_BUFLEN], *buf = rawbuf, *fidstr;
	int rc, c;

	while ((c = getopt(argc, argv, "i:g:")) != -1) {
		switch (c) {
		case 'i':
			id = strtoull(optarg, NULL, 0);
			break;
		case 'g':
			group = strtoull(optarg, NULL, 0);
			break;
		default:
			return CMD_HELP;
		}
	}

	argc -= optind;
	fidstr = *(argv + optind);

	if (!(id != ULLONG_MAX && group != ULLONG_MAX && argc == 0) &&
	    !(id == ULLONG_MAX && group == ULLONG_MAX && argc == 1))
		return CMD_HELP;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = cur_device;
	if (argc == 1) {
		rc = llapi_fid_parse(fidstr, &fid, NULL);
		if (rc) {
			fprintf(stderr, "%s: error parsing FID '%s': %s\n",
				jt_cmdname(argv[0]), fidstr, strerror(-rc));
			return rc;
		}

		data.ioc_inlbuf1 = (char *)&fid;
		data.ioc_inllen1 = sizeof(fid);
	} else {
		data.ioc_inlbuf3 = (char *)&id;
		data.ioc_inllen3 = sizeof(id);
		data.ioc_inlbuf4 = (char *)&group;
		data.ioc_inllen4 = sizeof(group);
	}
	data.ioc_inlbuf2 = (char *)&version;
	data.ioc_inllen2 = sizeof(version);

	memset(buf, 0, sizeof(*buf));
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		fprintf(stderr, "error: %s: packing ioctl arguments: %s\n",
			jt_cmdname(argv[0]), strerror(-rc));
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_GET_OBJ_VERSION, buf);
	if (rc == -1) {
		fprintf(stderr, "error: %s: ioctl: %s\n",
			jt_cmdname(argv[0]), strerror(errno));
		return -errno;
	}

	llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
	printf("%#jx\n", (uintmax_t)version);

	return 0;
}

#ifdef HAVE_SERVER_SUPPORT
int jt_changelog_register(int argc, char **argv)
{
	struct obd_ioctl_data	 data = { 0 };
	char			 rawbuf[MAX_IOC_BUFLEN] = "";
	char			*buf = rawbuf;
	char			*device = lcfg_get_devname();
	bool			 print_name_only = false;
	int			 c;
	int			 rc;

	if (argc > 2)
		return CMD_HELP;

	while ((c = getopt(argc, argv, "hn")) >= 0) {
		switch (c) {
		case 'n':
			print_name_only = true;
			break;
		case 'h':
		default:
			return CMD_HELP;
		}
	}

	if (cur_device < 0 || !device)
		return CMD_HELP;

	data.ioc_dev = cur_device;

	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc < 0) {
		fprintf(stderr, "error: %s: cannot pack ioctl: %s\n",
			jt_cmdname(argv[0]), strerror(-rc));
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_CHANGELOG_REG, buf);
	if (rc < 0) {
		rc = -errno;
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(-rc));
		return rc;
	}

	llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));

	if (data.ioc_u32_1 == 0) {
		fprintf(stderr, "received invalid userid!\n");
		return -EPROTO;
	}

	if (print_name_only)
		printf("%s%u\n", CHANGELOG_USER_PREFIX, data.ioc_u32_1);
	else
		printf("%s: Registered changelog userid '%s%u'\n",
		       device, CHANGELOG_USER_PREFIX, data.ioc_u32_1);

	return 0;
}

int jt_changelog_deregister(int argc, char **argv)
{
	struct obd_ioctl_data	 data = { 0 };
	char			 rawbuf[MAX_IOC_BUFLEN] = "";
	char			*buf = rawbuf;
	char			*device = lcfg_get_devname();
	int			 id;
	int			 rc;

	if (argc != 2 || cur_device < 0 || !device)
		return CMD_HELP;

	rc = sscanf(argv[1], CHANGELOG_USER_PREFIX"%d", &id);
	if (rc != 1 || id <= 0) {
		fprintf(stderr,
			"error: %s: expected id of the form %s<num> got '%s'\n",
			jt_cmdname(argv[0]), CHANGELOG_USER_PREFIX, argv[1]);
		return CMD_HELP;
	}

	data.ioc_dev = cur_device;
	data.ioc_u32_1 = id;

	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc < 0) {
		fprintf(stderr, "error: %s: invalid ioctl\n",
			jt_cmdname(argv[0]));
		return rc;
	}

	rc = l_ioctl(OBD_DEV_ID, OBD_IOC_CHANGELOG_DEREG, buf);
	if (rc < 0) {
		fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
			strerror(rc = errno));
		return rc;
	}

	llapi_ioctl_unpack(&data, buf, sizeof(rawbuf));
	printf("%s: Deregistered changelog user '%s%u'\n",
	       device, CHANGELOG_USER_PREFIX, data.ioc_u32_1);

	return 0;
}
#else /* !HAVE_SERVER_SUPPORT */
int jt_changelog_register(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}

int jt_changelog_deregister(int argc, char **argv)
{
	fprintf(stderr, "error: %s: invalid ioctl\n",
		jt_cmdname(argv[0]));
	return -EOPNOTSUPP;
}
#endif /* HAVE_SERVER_SUPPORT */

int jt_pcc_add(int argc, char **argv)
{
	struct option long_opts[] = {
		{ .val = 'p', .name = "param", .has_arg = required_argument },
		{ .name = NULL } };
	const char *mntpath;
	const char *pccpath;
	char *param = NULL;
	char cmd[PATH_MAX];
	int rc;

	optind = 1;
	while ((rc = getopt_long(argc, argv, "p:", long_opts, NULL)) != -1) {
		switch (rc) {
		case 'p':
			param = optarg;
			break;
		default:
			return CMD_HELP;
		}
	}

	if (!param) {
		fprintf(stderr, "%s: must specify the config param for PCC\n",
			jt_cmdname(argv[0]));
		return CMD_HELP;
	}

	if (optind + 2 != argc) {
		fprintf(stderr,
			"%s: must specify mount path and PCC path %d:%d\n",
			jt_cmdname(argv[0]), optind, argc);
		return CMD_HELP;
	}

	mntpath = argv[optind++];
	pccpath = argv[optind];

	snprintf(cmd, PATH_MAX, "add %s %s", pccpath, param);
	rc = llapi_pccdev_set(mntpath, cmd);
	if (rc < 0)
		fprintf(stderr, "%s: failed to run '%s' on %s\n",
			jt_cmdname(argv[0]), cmd, mntpath);

	return rc;
}

int jt_pcc_del(int argc, char **argv)
{
	const char *mntpath;
	const char *pccpath;
	char cmd[PATH_MAX];
	int rc;

	optind = 1;
	if (argc != 3) {
		fprintf(stderr, "%s: require 3 arguments\n",
			jt_cmdname(argv[0]));
		return CMD_HELP;
	}

	mntpath = argv[optind++];
	pccpath = argv[optind++];

	snprintf(cmd, PATH_MAX, "del %s", pccpath);
	rc = llapi_pccdev_set(mntpath, cmd);
	if (rc < 0)
		fprintf(stderr, "%s: failed to run '%s' on %s\n",
			jt_cmdname(argv[0]), cmd, mntpath);

	return rc;
}

int jt_pcc_clear(int argc, char **argv)
{
	const char *mntpath;
	int rc;

	optind = 1;
	if (argc != 2) {
		fprintf(stderr, "%s: require 2 arguments\n",
			jt_cmdname(argv[0]));
		return CMD_HELP;
	}

	mntpath = argv[optind];
	rc = llapi_pccdev_set(mntpath, "clear");
	if (rc < 0)
		fprintf(stderr, "%s: failed to run 'clear' on %s\n",
			jt_cmdname(argv[0]), mntpath);

	return rc;
}

int jt_pcc_list(int argc, char **argv)
{
	const char *mntpath;
	int rc;

	optind = 1;
	if (argc != 2) {
		fprintf(stderr, "%s: require 2 arguments\n",
			jt_cmdname(argv[0]));
		return CMD_HELP;
	}

	mntpath = argv[optind];
	rc = llapi_pccdev_get(mntpath);
	if (rc < 0)
		fprintf(stderr, "%s: failed to run 'pcc list' on %s\n",
			jt_cmdname(argv[0]), mntpath);

	return rc;
}
