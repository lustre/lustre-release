/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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
 */

/* api.c:
 *  This file provides the 'api' side for the process-based nals.
 *  it is responsible for creating the 'library' side thread,
 *  and passing wrapped portals transactions to it.
 *
 *  Along with initialization, shutdown, and transport to the library
 *  side, this file contains some stubs to satisfy the nal definition.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifndef __CYGWIN__
#include <syscall.h>
#endif
#include <sys/socket.h>
#include <procbridge.h>
#include <pqtimer.h>
#include <dispatch.h>
#include <errno.h>


/* XXX CFS workaround, to give a chance to let nal thread wake up
 * from waiting in select
 */
static int procbridge_notifier_handler(void *arg)
{
    static char buf[8];
    procbridge p = (procbridge) arg;

    syscall(SYS_read, p->notifier[1], buf, sizeof(buf));
    return 1;
}

void procbridge_wakeup_nal(procbridge p)
{
    static char buf[8];
    syscall(SYS_write, p->notifier[0], buf, sizeof(buf));
}

/* Function: forward
 * Arguments: nal_t *nal: pointer to my top-side nal structure
 *            id: the command to pass to the lower layer
 *            args, args_len:pointer to and length of the request
 *            ret, ret_len:  pointer to and size of the result
 * Returns: a portals status code
 *
 * forwards a packaged api call from the 'api' side to the 'library'
 *   side, and collects the result
 */
static int procbridge_forward(nal_t *n, int id, void *args, size_t args_len,
			      void *ret, ptl_size_t ret_len)
{
    bridge b = (bridge) n->nal_data;

    if (id == PTL_FINI) {
            lib_fini(b->nal_cb);

            if (b->shutdown)
                (*b->shutdown)(b);
    }

    lib_dispatch(b->nal_cb, NULL, id, args, ret);

    return (PTL_OK);
}


/* Function: shutdown
 * Arguments: nal: a pointer to my top side nal structure
 *            ni: my network interface index
 *
 * cleanup nal state, reclaim the lower side thread and
 *   its state using PTL_FINI codepoint
 */
static int procbridge_shutdown(nal_t *n, int ni)
{
    bridge b=(bridge)n->nal_data;
    procbridge p=(procbridge)b->local;

    p->nal_flags |= NAL_FLAG_STOPPING;
    procbridge_wakeup_nal(p);

    do {
        pthread_mutex_lock(&p->mutex);
        if (p->nal_flags & NAL_FLAG_STOPPED) {
                pthread_mutex_unlock(&p->mutex);
                break;
        }
        pthread_cond_wait(&p->cond, &p->mutex);
        pthread_mutex_unlock(&p->mutex);
    } while (1);

    free(p);
    return(0);
}


/* Function: validate
 *    useless stub
 */
static int procbridge_validate(nal_t *nal, void *base, size_t extent)
{
    return(0);
}


/* FIXME cfs temporary workaround! FIXME
 * global time out value
 */
int __tcpnal_eqwait_timeout_value = 0;
int __tcpnal_eqwait_timedout = 0;

/* Function: yield
 * Arguments:  pid:
 *
 *  this function was originally intended to allow the
 *   lower half thread to be scheduled to allow progress. we
 *   overload it to explicitly block until signalled by the
 *   lower half.
 */
static void procbridge_yield(nal_t *n)
{
    bridge b=(bridge)n->nal_data;
    procbridge p=(procbridge)b->local;

    pthread_mutex_lock(&p->mutex);
    if (!__tcpnal_eqwait_timeout_value) {
        pthread_cond_wait(&p->cond,&p->mutex);
    } else {
        struct timeval now;
        struct timespec timeout;

        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + __tcpnal_eqwait_timeout_value;
        timeout.tv_nsec = now.tv_usec * 1000;

        __tcpnal_eqwait_timedout =
                pthread_cond_timedwait(&p->cond, &p->mutex, &timeout);
    }
    pthread_mutex_unlock(&p->mutex);
}


static void procbridge_lock(nal_t * nal, unsigned long *flags){}
static void procbridge_unlock(nal_t * nal, unsigned long *flags){}
/* api_nal
 *  the interface vector to allow the generic code to access
 *  this nal. this is seperate from the library side nal_cb.
 *  TODO: should be dyanmically allocated
 */
static nal_t api_nal = {
    ni:       {0},
    nal_data: NULL,
    forward:  procbridge_forward,
    shutdown: procbridge_shutdown,
    validate: procbridge_validate,
    yield:    procbridge_yield,
    lock:     procbridge_lock,
    unlock:   procbridge_unlock
};

ptl_nid_t tcpnal_mynid;

/* Function: procbridge_interface
 *
 * Arguments:  pid: requested process id (port offset)
 *                  PTL_ID_ANY not supported.
 *             desired: limits passed from the application
 *                      and effectively ignored
 *             actual:  limits actually allocated and returned
 *
 * Returns: a pointer to my statically allocated top side NAL
 *          structure
 *
 * initializes the tcp nal. we define unix_failure as an
 * error wrapper to cut down clutter.
 */
nal_t *procbridge_interface(int num_interface,
                            ptl_pt_index_t ptl_size,
                            ptl_ac_index_t acl_size,
                            ptl_pid_t requested_pid)
{
    nal_init_args_t args;
    procbridge p;
    bridge b;
    static int initialized=0;
    ptl_ni_limits_t limits = {-1,-1,-1,-1,-1};
    int nal_type = PTL_IFACE_TCP;/* PTL_IFACE_DEFAULT FIXME hack */

    if(initialized) return (&api_nal);

    init_unix_timer();

    b=(bridge)malloc(sizeof(struct bridge));
    p=(procbridge)malloc(sizeof(struct procbridge));
    api_nal.nal_data=b;
    b->local=p;

    if (ptl_size)
	    limits.max_ptable_index = ptl_size;
    if (acl_size)
	    limits.max_atable_index = acl_size;

    args.nia_requested_pid = requested_pid;
    args.nia_limits = &limits;
    args.nia_nal_type = nal_type;
    args.nia_bridge = b;

    /* init procbridge */
    pthread_mutex_init(&p->mutex,0);
    pthread_cond_init(&p->cond, 0);
    p->nal_flags = 0;
    pthread_mutex_init(&p->nal_cb_lock, 0);

    /* initialize notifier */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, p->notifier)) {
        perror("socketpair failed");
        return NULL;
    }

    if (!register_io_handler(p->notifier[1], READ_HANDLER,
                procbridge_notifier_handler, p)) {
        perror("fail to register notifier handler");
        return NULL;
    }

    /* create nal thread */
    if (pthread_create(&p->t, NULL, nal_thread, &args)) {
        perror("nal_init: pthread_create");
        return(NULL);
    }

    do {
        pthread_mutex_lock(&p->mutex);
        if (p->nal_flags & (NAL_FLAG_RUNNING | NAL_FLAG_STOPPED)) {
                pthread_mutex_unlock(&p->mutex);
                break;
        }
        pthread_cond_wait(&p->cond, &p->mutex);
        pthread_mutex_unlock(&p->mutex);
    } while (1);

    if (p->nal_flags & NAL_FLAG_STOPPED)
        return (NULL);

    b->nal_cb->ni.nid = tcpnal_mynid;
    initialized = 1;

    return (&api_nal);
}
