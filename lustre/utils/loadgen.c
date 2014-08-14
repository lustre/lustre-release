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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/loadgen.c
 *
 * See how many local OSCs we can start whaling on a OST
 * We're doing direct ioctls instead of going though a system() call to lctl
 * to avoid the bash overhead.
 * Adds an osc / echo client pair in each thread and starts echo transactions.
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>

#include <lnet/lnetctl.h>
#include <lnet/nidstr.h>
#include <libcfs/libcfsutil.h>
#include <lustre_ioctl.h>
#include "obdctl.h"

static char cmdname[512];
static char target[64] = "";
char nid[64] = "";
static int sig_received = 0;
static int o_verbose = 4; /* 0-5 */
static int my_oss = 0;
static int my_ecs = 0;

static int jt_quit(int argc, char **argv) {
        Parser_quit(argc, argv);
        return 0;
}

static int loadgen_usage(int argc, char **argv)
{
        if (argc == 1) {
                fprintf(stderr,
        "This is a test program used to simulate large numbers of\n"
        "clients.  The echo obds are used, so the obdecho module must\n"
        "be loaded.\n"
        "Typical usage would be:\n"
        "  loadgen> dev lustre-OST0000       set the target device\n"
        "  loadgen> start 20                 start 20 echo clients\n"
        "  loadgen> wr 10 5                  have 10 clients do the brw_write\n"
        "                                      test 5 times each\n"
                        );
        }
        return (Parser_help(argc, argv));
}

static int loadgen_verbose(int argc, char **argv);
static int loadgen_target(int argc, char **argv);
static int loadgen_start_echosrv(int argc, char **argv);
static int loadgen_start_clients(int argc, char **argv);
static int loadgen_wait(int argc, char **argv);
static int loadgen_write(int argc, char **argv);

command_t cmdlist[] = {
        {"device", loadgen_target, 0,
         "set target ost name (e.g. lustre-OST0000)\n"
         "usage: device <name> [<nid>]"},
        {"dl", jt_obd_list, 0, "show all devices\n"
         "usage: dl"},
        {"echosrv", loadgen_start_echosrv, 0, "start an echo server\n"},
        {"start", loadgen_start_clients, 0, "set up echo clients\n"
         "usage: start_clients <num>"},
        {"verbose", loadgen_verbose, 0, "set verbosity level 0-5\n"
         "usage: verbose <level>"},
        {"wait", loadgen_wait, 0,
         "wait for all threads to finish\n"},
        {"write", loadgen_write, 0,
         "start a test_brw write test on X clients for Y iterations\n"
         "usage: write <num_clients> <num_iter> [<delay>]"},

        /* User interface commands */
        {"help", loadgen_usage, 0, "help"},
        {"exit", jt_quit, 0, "quit"},
        {"quit", jt_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};


/* Command flags */
#define C_STOP           0x0001
#define C_CREATE_EVERY   0x0002  /* destroy and recreate every time */
#define C_READ           0x0004
#define C_WRITE          0x0008

struct command_t {
        int           c_flags;
        int           c_rpt;
        int           c_delay;
};

struct kid_t {
        struct command_t k_cmd;
        struct kid_t    *k_next;
        pthread_t        k_pthread;
        __u64            k_objid;
        int              k_id;
        int              k_dev;
};

static int live_threads = 0;
static struct kid_t *kid_list = NULL;
pthread_mutex_t m_list = PTHREAD_MUTEX_INITIALIZER;

static struct kid_t *push_kid(int tnum)
{
        struct kid_t *kid;
        kid = (struct kid_t *)calloc(1, sizeof(struct kid_t));
        if (kid == NULL) {
                fprintf(stderr, "malloc failure\n");
                return NULL;
        }
        kid->k_pthread = pthread_self();
        pthread_mutex_lock(&m_list);
        kid->k_next = kid_list;
        kid->k_id = tnum;
        kid_list = kid;
        live_threads++;
        pthread_mutex_unlock(&m_list);
        return kid;
}

int trigger_count = 0;
int waiting_count = 0;
int timer_on = 0;
int all_done = 1;
struct timeval trigger_start;
struct command_t trigger_cmd;
pthread_mutex_t m_trigger = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cv_trigger = PTHREAD_COND_INITIALIZER;

unsigned long long write_bytes;
pthread_mutex_t m_count = PTHREAD_MUTEX_INITIALIZER;

static void trigger(int command, int threads, int repeat, int delay)
{

        pthread_mutex_lock(&m_trigger);
        trigger_cmd.c_flags = command;
        trigger_cmd.c_rpt = repeat;
        trigger_cmd.c_delay = delay;
        trigger_count = threads;
        if (o_verbose > 4)
                printf("trigger %d cmd c=%d f=%x\n", trigger_count,
                       trigger_cmd.c_rpt, trigger_cmd.c_flags);
        gettimeofday(&trigger_start, NULL);
        timer_on = 1;
        pthread_mutex_lock(&m_count);
        write_bytes = 0;
        pthread_mutex_unlock(&m_count);

        pthread_cond_broadcast(&cv_trigger);
        pthread_mutex_unlock(&m_trigger);
}

static __inline__ void stop_all(int unused)
{
        sig_received++;
}

static void kill_kids(void)
{
        struct kid_t *tmp = kid_list;

        stop_all(SIGINT);
        trigger(C_STOP, 0, 0, 0);
        while(tmp) {
                pthread_kill(tmp->k_pthread, SIGTERM);
                tmp = tmp->k_next;
        }
}

static void sig_master(int unused)
{
        stop_all(SIGINT);
        //jt_quit(0, NULL);
}

static int wait_for_threads()
{
        struct kid_t *tmp = kid_list;
        int rc = 0, status;
        void *statusp;

        printf("waiting for %d children\n", live_threads);

        while(tmp) {
                rc = pthread_join(tmp->k_pthread, &statusp);
                status = (long)statusp;
                if (o_verbose > 2)
                        printf("%d: joined, rc = %d, status = %d\n",
                               tmp->k_id, rc, status);
                kid_list = tmp->k_next;
                free(tmp);
                tmp = kid_list;
                live_threads--;
        }

        if (o_verbose > 0)
                printf("%s done, rc = %d\n", cmdname, rc);
        return rc;
}

static int write_proc(char *proc_path, char *value)
{
        int fd, rc;

        fd = open(proc_path, O_WRONLY);
        if (fd == -1) {
                fprintf(stderr, "open('%s') failed: %s\n",
                        proc_path, strerror(errno));
                rc = errno;
        } else {
                rc = write(fd, value, strlen(value));
                if (rc < 0) {
                        fprintf(stderr, "write('%s') failed: %s\n",
                                proc_path, strerror(errno));
                }
                close(fd);
        }
        return rc;
}

static int read_proc(char *proc_path,  unsigned long long *value)
{
        int fd, rc;
        char buf[50];

        fd = open(proc_path, O_RDONLY);
        if (fd == -1) {
                fprintf(stderr, "open('%s') failed: %s\n",
                        proc_path, strerror(errno));
                return (errno);
        }

        rc = read(fd, buf, sizeof(buf));
        close(fd);
        if (errno == EOPNOTSUPP) {
                /* probably an echo server */
                return rc;
        }
        if (rc <= 0) {
                fprintf(stderr, "read('%s') failed: %s (%d)\n",
                        proc_path, strerror(errno), errno);
                return rc;
        }
        *value = strtoull(buf, NULL, 10);
        return 0;
}

static int grant_estimate(int thread)
{
        unsigned long long avail, grant;
        char proc_path[50];
        int rc;
        static int ran = 0;

        /* I don't really care about protecting this with a mutex */
        if (ran)
                return 0;

        if (o_verbose < 2)
                return 0;

        /* Divide /proc/fs/lustre/osc/o_0001/kbytesavail
           by /proc/fs/lustre/osc/o_0001/cur_grant_bytes to find max clients */
        sprintf(proc_path, "/proc/fs/lustre/osc/o%.5d/kbytesavail", thread);
        rc = read_proc(proc_path, &avail);
        if (rc)
                return rc;
        sprintf(proc_path, "/proc/fs/lustre/osc/o%.5d/cur_grant_bytes", thread);
        rc = read_proc(proc_path, &grant);
        if (rc)
                return rc;
        if (grant == 0) {
                return -EINVAL;
        }
        printf("Estimate %llu clients before we run out of grant space "
               "(%lluK / %llu)\n", (avail << 10)  / grant, avail, grant);
        ran++;
        return 0;
}

/* We hold a thread mutex around create/cleanup because cur_dev is not
   shared-memory safe */
pthread_mutex_t m_config = PTHREAD_MUTEX_INITIALIZER;

static int cleanup(char *obdname, int quiet)
{
        char *args[3];
        int rc;

        pthread_mutex_lock(&m_config);

        args[0] = cmdname;
        args[1] = obdname;
        rc = jt_lcfg_device(2, args);
        if (rc && !quiet)
                fprintf(stderr, "%s: can't configure '%s' (%d)\n",
                        cmdname, obdname, rc);
        args[1] = "force";
        rc = jt_obd_cleanup(2, args);
        if (rc && !quiet)
                fprintf(stderr, "%s: can't cleanup '%s' (%d)\n",
                        cmdname, obdname, rc);
        rc = jt_obd_detach(1, args);
        if (rc && !quiet)
                fprintf(stderr, "%s: can't detach '%s' (%d)\n",
                        cmdname, obdname, rc);

        pthread_mutex_unlock(&m_config);
        return rc;
}

static int echocli_setup(char *oname, char *ename, int *dev)
{
        char *args[5];
        char proc_path[50];
        int rc;

        pthread_mutex_lock(&m_config);

        args[0] = cmdname;

        /* OSC */
        /* attach "osc" oscname oscuuid */
        args[1] = "osc";
        args[2] = args[3] = oname;
        rc = jt_lcfg_attach(4, args);
        if (rc) {
                fprintf(stderr, "%s: can't attach osc '%s' (%d)\n",
                        cmdname, oname, rc);
                /* Assume we want e.g. an old one cleaned anyhow. */
                goto clean;
        }
        /* setup ostname "OSS_UUID" */
        args[1] = target;
        args[2] = "OSS_UUID";
        rc = jt_lcfg_setup(3, args);
        if (rc) {
                fprintf(stderr, "%s: can't setup osc '%s' (%d)\n",
                        cmdname, oname, rc);
                goto clean;
        }

        /* Large grants cause ENOSPC to be reported, even though
           there's space left.  We can reduce the grant size by
           minimizing these */
        sprintf(proc_path, "/proc/fs/lustre/osc/%s/max_dirty_mb", oname);
        rc = write_proc(proc_path, "1");
        sprintf(proc_path, "/proc/fs/lustre/osc/%s/max_rpcs_in_flight", oname);
        rc = write_proc(proc_path, "1");

        /* ECHO CLI */
        /* attach "echo_client" echoname echouuid */
        args[1] = "echo_client";
        args[2] = args[3] = ename;
        rc = jt_lcfg_attach(4, args);
        if (rc) {
                fprintf(stderr, "%s: can't attach '%s' (%d)\n",
                        cmdname, ename, rc);
                if (rc == ENODEV)
                        fprintf(stderr, "%s: is the obdecho module loaded?\n",
                                cmdname);
                goto clean;
        }
        /* setup oscname */
        args[1] = oname;
        rc = jt_lcfg_setup(2, args);
        if (rc) {
                fprintf(stderr, "%s: can't setup '%s' (%d)\n",
                        cmdname, ename, rc);
                goto clean;
        }

        args[1] = ename;
        rc = jt_obd_device(2, args);
        if (rc) {
                fprintf(stderr, "%s: can't set device '%s' (%d)\n",
                        cmdname, ename, rc);
                goto clean;
        }

        if (!rc)
                *dev = jt_obd_get_device();
        pthread_mutex_unlock(&m_config);
        return rc;

clean:
        pthread_mutex_unlock(&m_config);
        cleanup(ename, 1);
        cleanup(oname, 1);
        return rc;
}

/* We can't use the libptlctl library fns because they are not shared-memory
   safe with respect to the ioctl device (cur_dev) */
static int obj_ioctl(int cmd, struct obd_ioctl_data *data, int unpack)
{
        char *buf = NULL;
        int rc;

        //IOC_PACK(cmdname, data);
        if (obd_ioctl_pack(data, &buf, sizeof(*data))) {
                fprintf(stderr, "dev %d invalid ioctl\n", data->ioc_dev);
                rc = EINVAL;
                goto out;
        }

        rc = l_ioctl(OBD_DEV_ID, cmd, buf);

        if (unpack) {
                //IOC_UNPACK(argv[0], data);
                if (obd_ioctl_unpack(data, buf, sizeof(*data))) {
                        fprintf(stderr, "dev %d invalid reply\n", data->ioc_dev);
                        rc = EINVAL;
                        goto out;
                }
        }

out:
        if (buf)
                free(buf);
        return rc;
}

/* See jt_obd_create */
static int obj_create(struct kid_t *kid)
{
	struct obd_ioctl_data data;
	int rc;

	memset(&data, 0, sizeof(data));
	data.ioc_dev = kid->k_dev;
	data.ioc_obdo1.o_mode = 0100644;
	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	ostid_set_id(&data.ioc_obdo1.o_oi, 1);
	data.ioc_obdo1.o_uid = 0;
	data.ioc_obdo1.o_gid = 0;
	data.ioc_obdo1.o_valid = OBD_MD_FLTYPE | OBD_MD_FLMODE |
			OBD_MD_FLID | OBD_MD_FLUID | OBD_MD_FLGID;

        rc = obj_ioctl(OBD_IOC_CREATE, &data, 1);
        if (rc) {
                fprintf(stderr, "%d: create (%d) %s\n",
                        kid->k_id, rc, strerror(errno));
                return rc;
        }

        if (!(data.ioc_obdo1.o_valid & OBD_MD_FLID)) {
                fprintf(stderr, "%d: create oid not valid "LPX64"\n",
                        kid->k_id, data.ioc_obdo1.o_valid);
                return rc;
        }

	kid->k_objid = ostid_id(&data.ioc_obdo1.o_oi);

        if (o_verbose > 4)
                printf("%d: cr "LPX64"\n", kid->k_id, kid->k_objid);

        return rc;
}

/* See jt_obd_destroy */
static int obj_delete(struct kid_t *kid)
{
        struct obd_ioctl_data data;
        int rc;

        if (o_verbose > 4)
                printf("%d: del "LPX64"\n", kid->k_id, kid->k_objid);

        memset(&data, 0, sizeof(data));
        data.ioc_dev = kid->k_dev;
	ostid_set_id(&data.ioc_obdo1.o_oi, kid->k_objid);
        data.ioc_obdo1.o_mode = S_IFREG | 0644;
        data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLMODE;

        rc = obj_ioctl(OBD_IOC_DESTROY, &data, 1);
        if (rc)
                fprintf(stderr, "%s-%d: can't destroy obj "LPX64" (%d)\n",
                        cmdname, kid->k_id, kid->k_objid, rc);

        kid->k_objid = 0;
        return rc;
}

#define difftime(a, b)                                  \
        ((a)->tv_sec - (b)->tv_sec +                    \
         ((a)->tv_usec - (b)->tv_usec) / 1000000.0)

/* See jt_obd_test_brw */
static int obj_write(struct kid_t *kid)
{
        struct obd_ioctl_data data;
        struct timeval start;
        __u64 count, len;
        int rc = 0, i, pages = 0;

        if (o_verbose > 4)
                printf("%d: wr "LPX64"\n", kid->k_id, kid->k_objid);

        count = 10;
        pages = 32;
        len = pages * getpagesize();

        memset(&data, 0, sizeof(data));
        data.ioc_dev = kid->k_dev;
        /* communicate the 'type' of brw test and batching to echo_client.
         * don't start.  we'd love to refactor this lctl->echo_client
         * interface */
        data.ioc_pbuf1 = (void *)1;
        data.ioc_plen1 = 1;

	ostid_set_seq_echo(&data.ioc_obdo1.o_oi);
	ostid_set_id(&data.ioc_obdo1.o_oi, kid->k_objid);
	data.ioc_obdo1.o_mode = S_IFREG;
	data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE |
				 OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
	data.ioc_obdo1.o_flags = OBD_FL_DEBUG_CHECK;
	data.ioc_count = len;
	data.ioc_offset = 0;

        gettimeofday(&start, NULL);

        for (i = 1; i <= count; i++) {
                data.ioc_obdo1.o_valid &= ~(OBD_MD_FLBLOCKS|OBD_MD_FLGRANT);
                rc = obj_ioctl(OBD_IOC_BRW_WRITE, &data, 0);
                if (rc) {
                        fprintf(stderr, "%d: write %s\n", kid->k_id,
                                strerror(rc = errno));
                        break;
                }

                data.ioc_offset += len;
        }

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);
                diff = difftime(&end, &start);

                --i;

                pthread_mutex_lock(&m_count);
                write_bytes += i * len;
                pthread_mutex_unlock(&m_count);

                if (o_verbose > 4)
                        printf("%d: wrote %dx%d pages in %.3fs (%.3f MB/s): %s",
                               kid->k_id, i, pages, diff,
                               ((double)i * len) / (diff * 1048576.0),
                               ctime(&end.tv_sec));
        }

        if (rc)
                fprintf(stderr, "%s-%d: err test_brw obj "LPX64" (%d)\n",
                        cmdname, kid->k_id, kid->k_objid, rc);
        return rc;
}

static int do_work(struct kid_t *kid)
{
        int rc = 0, err, iter = 0;

        if (!(kid->k_cmd.c_flags & C_CREATE_EVERY))
                rc = obj_create(kid);

        for (iter = 0; iter < kid->k_cmd.c_rpt; iter++) {
                if (rc || sig_received)
                        break;

                if (kid->k_cmd.c_flags & C_CREATE_EVERY) {
                        rc = obj_create(kid);
                        if (rc)
                                break;
                }

                if (kid->k_cmd.c_flags & C_WRITE) {
                        rc = obj_write(kid);
                        grant_estimate(kid->k_id);
                }

                if (kid->k_cmd.c_flags & C_CREATE_EVERY) {
                        err = obj_delete(kid);
                        if (!rc) rc = err;
                }

                if ((o_verbose > 3) && (iter % 10 == 0))
                        printf("%d: i%d\n", kid->k_id, iter);
                if (!rc)
                        sleep(kid->k_cmd.c_delay);
        }

        if (!(kid->k_cmd.c_flags & C_CREATE_EVERY)) {
                err = obj_delete(kid);
                if (!rc) rc = err;
        }

        if (o_verbose > 2)
                printf("%d: done (%d)\n", kid->k_id, rc);

        return rc;
}

static void report_perf()
{
        struct timeval end;
        double diff;

        gettimeofday(&end, NULL);
        diff = difftime(&end, &trigger_start);
        if (o_verbose > 2) {
                pthread_mutex_lock(&m_count);
                printf("wrote %lluMB in %.3fs (%.3f MB/s)\n",
                       write_bytes >> 20, diff,
                       (write_bytes >> 20) / diff);
                pthread_mutex_unlock(&m_count);
        }
}

static void *run_one_child(void *threadvp)
{
	struct kid_t *kid;
	char oname[16], ename[16];
	int thread = (long)threadvp;
	int dev = 0;
	int err;
	int rc;

	if (o_verbose > 2)
		printf("%s: running thread #%d\n", cmdname, thread);

	rc = snprintf(oname, sizeof(oname), "o%.5d", thread);
	if (rc != 1) {
		rc = -EFAULT;
		goto out_exit;
	}
	rc = snprintf(ename, sizeof(ename), "e%.5d", thread);
	if (rc != 1) {
		rc = -EFAULT;
		goto out_exit;
	}
        rc = echocli_setup(oname, ename, &dev);
        if (rc) {
                fprintf(stderr, "%s: can't setup '%s/%s' (%d)\n",
                        cmdname, oname, ename, rc);
		goto out_exit;
        }

        kid = push_kid(thread);
        if (!kid) {
                rc = -ENOMEM;
                goto out;
        }
        kid->k_dev = dev;

        while(!(rc || sig_received)) {
                pthread_mutex_lock(&m_trigger);
    		pthread_mutex_lock(&m_list);
                waiting_count++;
                if ((waiting_count == live_threads) && timer_on) {
                        report_perf();
                        timer_on = 0;
                        all_done = 1;
                }
    		pthread_mutex_unlock(&m_list);
                pthread_cond_wait(&cv_trigger, &m_trigger);
                waiting_count--;
                all_done = 0;

                /* First trigger_count threads will do the work, the rest
                   will block again */
                if (trigger_count) {
                        if (o_verbose > 4)
                                printf("%d: trigger %d cmd %x\n",
                                       kid->k_id, trigger_count,
                                       trigger_cmd.c_flags);
                        trigger_count--;
                        memcpy(&kid->k_cmd, &trigger_cmd, sizeof(trigger_cmd));
                        pthread_mutex_unlock(&m_trigger);
                        rc = do_work(kid);
                } else {
                        pthread_mutex_unlock(&m_trigger);
                }
        }

        if (o_verbose > 1)
                printf("%s: thread #%d done (%d)\n", cmdname, thread, rc);

        if (rc)
                stop_all(SIGINT);

out:
        err = cleanup(ename, 0);
        if (!rc) rc = err;
        err = cleanup(oname, 0);
        if (!rc) rc = err;

out_exit:
	pthread_exit((void *)(long)rc);
}

/* 
 * PTHREAD_STACK_MIN is 16K minimal stack for threads. This
 * is stack consumed by one thread, which executes NULL procedure.
 * We need some more here and 20k stack for one client thread
 * is enough to not overflow. In same time it does not consume
 * a lot of memory for large number of threads.
 *
 * 20K virtual clients will only consume 320M + 400M. Still to
 * create this number of virtual clients we need to fix 8192
 * OBDs limit.
 */
#define CLIENT_THREAD_STACK_SIZE (PTHREAD_STACK_MIN + (20 * 1024))

static int loadgen_start_clients(int argc, char **argv)
{
        int rc = 0, i, numt;
        struct timespec ts = {0, 1000*1000*100}; /* .1 sec */
        pthread_attr_t attr;

        if (argc != 2)
                return CMD_HELP;

        numt = strtoul(argv[1], NULL, 0);
        if (numt < 1)
                return CMD_HELP;

        if (!target[0]) {
                fprintf(stderr, "%s: target OST is not defined, use 'device' "
                        "command\n", cmdname);
                return -EINVAL;
        }

        rc = pthread_attr_init(&attr);
        if (rc) {
                fprintf(stderr, "%s: pthread_attr_init:(%d) %s\n",
                        cmdname, rc, strerror(errno));
                return -errno;
        }
        pthread_attr_setstacksize (&attr, CLIENT_THREAD_STACK_SIZE);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

        numt += live_threads;
        i = live_threads;
        printf("start %d to %d\n", i, numt);
        while(!rc && !sig_received && (i < numt)) {
                pthread_t thread;

                i++;
                rc = pthread_create(&thread, &attr, run_one_child,
                                    (void *)(long)i);
                if (rc) {
                        fprintf(stderr, "%s: pthread: #%d - (%d) %s\n",
                                cmdname, i, rc, strerror(rc));
                        break;
                }

                /* give them slightly different start times */
                nanosleep(&ts, NULL);
        }

        pthread_attr_destroy(&attr);

        return -rc;
}

static int loadgen_target(int argc, char **argv)
{
        char *args[3];
        __u64 nidx = 0;
        int rc = 0;

        if (argc < 2 || argc > 3)
                return CMD_HELP;

        args[0] = cmdname;

        if (argc == 3) {
                nidx = libcfs_str2nid(argv[2]);
                if (nidx == LNET_NID_ANY) {
                        fprintf(stderr, "%s: invalid nid '%s'\n",
                                cmdname, argv[2]);
                        return -EINVAL;
                }
        } else {
                /* Local device should be in list */
                args[1] = argv[1];
                rc = jt_obd_device(2, args);
                if (rc) {
                        fprintf(stderr, "%s: local device '%s' doesn't "
                                "seem to exist. You must use obdfilter device "
                                "names like 'lustre-OST0000'.  Use 'dl' to "
                                "list all devices.\n",
                                cmdname, argv[1]);
                        return -EINVAL;
                }

                /* Use the first local nid */
                args[1] = (char *)(&nidx);
                args[1][0] = 1; /* hack to get back first nid */
                rc = jt_ptl_list_nids(2, args);
                if (rc) {
                        fprintf(stderr, "%s: can't get local nid (%d)\n",
                                cmdname, rc);
                        return rc;
                }
        }
        if (strcmp(nid, libcfs_nid2str(nidx)) != 0) {
                /* if new, do an add_uuid */
                sprintf(nid, "%s", libcfs_nid2str(nidx));

                /* Fixme change the uuid for every new one */
                args[1] = "OSS_UUID";
                args[2] = nid;
                rc = jt_lcfg_add_uuid(3, args);
                if (rc) {
                        fprintf(stderr, "%s: can't add uuid '%s' (%d)\n",
                                cmdname, args[2], rc);
                        return rc;
                }
        }

        snprintf(target, sizeof(target), "%s", argv[1]);
        printf("Target OST name is '%s'\n", target);

        return rc;
}

static int loadgen_verbose(int argc, char **argv)
{
        if (argc != 2)
                return CMD_HELP;
        o_verbose = atoi(argv[1]);
        printf("verbosity set to %d\n", o_verbose);
        return 0;
}

static int loadgen_write(int argc, char **argv)
{
        int threads;

        if (argc < 3 || argc > 4)
                return CMD_HELP;
        threads = atoi(argv[1]);
        pthread_mutex_lock(&m_list);
        if (threads > live_threads) {
    		pthread_mutex_unlock(&m_list);
                fprintf(stderr, "requested %d threads but only %d are running. "
                        "Use 'start' to start some more.\n",
                        threads, live_threads);
                return -EOVERFLOW;
        } else {
    		pthread_mutex_unlock(&m_list);
        }
        trigger(C_WRITE, threads, atoi(argv[2]),
                (argc == 4) ? atoi(argv[3]) : 0);
        return 0;
}

char ecsname[] = "echosrv";
static int loadgen_stop_echosrv(int argc, char **argv)
{
        int verbose = (argc != 9);
        if (my_oss) {
                char name[]="OSS";
                cleanup(name, verbose);
                my_oss = 0;
        }
        if (my_ecs || (argc == 9)) {
                cleanup(ecsname, verbose);
                my_ecs = 0;
        }
        return 0;
}

static int loadgen_start_echosrv(int argc, char **argv)
{
        char *args[5];
        int rc;

        pthread_mutex_lock(&m_config);

        args[0] = cmdname;

        /* attach obdecho echosrv echosrv_UUID */
        args[1] = "obdecho";
        args[2] = args[3] = ecsname;
        rc = jt_lcfg_attach(4, args);
        if (rc) {
                fprintf(stderr, "%s: can't attach echo server (%d)\n",
                        cmdname, rc);
                /* Assume we want e.g. an old one cleaned anyhow. */
                goto clean;
        }
        my_ecs = 1;

        /* setup */
        rc = jt_lcfg_setup(1, args);
        if (rc) {
                fprintf(stderr, "%s: can't setup echo server (%d)\n",
                        cmdname, rc);
                goto clean;
        }

        /* Create an OSS to handle the communications */
        /* attach ost OSS OSS_UUID */
        args[1] = "ost";
        args[2] = args[3] = "OSS";

        rc = jt_lcfg_attach(4, args);
        if (rc == EEXIST) {
                /* Already set up for somebody else, that's fine. */
                printf("OSS already set up, no problem.\n");
                pthread_mutex_unlock(&m_config);
                return 0;
        }
        if (rc) {
                fprintf(stderr, "%s: can't attach OSS (%d)\n",
                        cmdname, rc);
                goto clean;
        }
        my_oss = 1;

        /* setup */
        rc = jt_lcfg_setup(1, args);
        if (rc) {
                fprintf(stderr, "%s: can't setup OSS (%d)\n",
                        cmdname, rc);
                goto clean;
        }

        pthread_mutex_unlock(&m_config);
        return rc;

clean:
        pthread_mutex_unlock(&m_config);
        loadgen_stop_echosrv(9, argv);
        return rc;
}

static int loadgen_wait(int argc, char **argv)
{
        /* Give scripts a chance to start some threads */
        sleep(1);
        while (!all_done) {
                sleep(1);
        }
        return 0;
}

static int loadgen_init(int argc, char **argv)
{
        char *args[4];
        int rc;

        sprintf(cmdname, "%s", argv[0]);

        signal(SIGTERM, sig_master);
        signal(SIGINT, sig_master);

        /* Test to make sure obdecho module is loaded */
        args[0] = cmdname;
        args[1] = "echo_client";
        args[2] = args[3] = "ecc_test";
        rc = jt_lcfg_attach(4, args);
        if (rc) {
                fprintf(stderr, "%s: can't attach echo client (%d)\n",
                        cmdname, rc);
                if (rc == ENODEV)
                        fprintf(stderr, "%s: is the obdecho module loaded?\n",
                                cmdname);
        } else {
                args[1] = args[2];
                jt_obd_detach(1, args);
        }

        return rc;
}

static int loadgen_exit()
{
        int rc;

        printf("stopping %d children\n", live_threads);
        kill_kids();
        rc = wait_for_threads();

        loadgen_stop_echosrv(0, NULL);

        return rc;
}

/* libptlctl interface */
static int loadgen_main(int argc, char **argv)
{
        int rc;

        setlinebuf(stdout);
        /* without this threaded errors cause segfault */
        setlinebuf(stderr);

        if ((rc = ptl_initialize(argc, argv)) < 0)
                exit(rc);
        if ((rc = obd_initialize(argc, argv)) < 0)
                exit(rc);
        if ((rc = dbg_initialize(argc, argv)) < 0)
                exit(rc);

        Parser_init("loadgen> ", cmdlist);

        rc = loadgen_init(argc, argv);
        if (rc)
                goto out;

        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                rc = Parser_commands();
        }

        rc = loadgen_exit();

out:
        obd_finalize(argc, argv);
        return rc < 0 ? -rc : rc;
}

#ifndef LIBLUSTRE_TEST
int main (int argc, char **argv)
{
        int rc;
        rc = loadgen_main(argc, argv);
        pthread_exit((void *)(long)rc);

        return rc;
}
#endif
