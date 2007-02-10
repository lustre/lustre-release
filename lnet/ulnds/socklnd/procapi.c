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
# include <syscall.h>
#endif
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <procbridge.h>
#include <pqtimer.h>
#include <dispatch.h>
#include <errno.h>
#ifdef HAVE_GETHOSTBYNAME
# include <sys/utsname.h>
#endif

#if !HAVE_LIBPTHREAD
# error "This LND requires a multi-threaded runtime"
#endif

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

lnd_t the_tcplnd = {
        .lnd_type      = SOCKLND,
        .lnd_startup   = procbridge_startup,
        .lnd_shutdown  = procbridge_shutdown,
        .lnd_send      = tcpnal_send,
        .lnd_recv      = tcpnal_recv,
        .lnd_notify    = tcpnal_notify,
};
int       tcpnal_running;

/* Function: shutdown
 * Arguments: ni: the instance of me
 *
 * cleanup nal state, reclaim the lower side thread and
 *   its state using PTL_FINI codepoint
 */
void
procbridge_shutdown(lnet_ni_t *ni)
{
    bridge b=(bridge)ni->ni_data;
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
    tcpnal_running = 0;
}

#ifdef ENABLE_SELECT_DISPATCH
procbridge __global_procbridge = NULL;
#endif

/* Function: procbridge_startup
 *
 * Arguments:  ni:          the instance of me
 *             interfaces:  ignored
 *
 * Returns: portals rc
 *
 * initializes the tcp nal. we define unix_failure as an
 * error wrapper to cut down clutter.
 */
int
procbridge_startup (lnet_ni_t *ni)
{
    procbridge p;
    bridge     b;
    int        rc;

    /* NB The local NID is not assigned.  We only ever connect to the socknal,
     * which assigns the src nid/pid on incoming non-privileged connections
     * (i.e. us), and we don't accept connections. */

    LASSERT (ni->ni_lnd == &the_tcplnd);
    LASSERT (!tcpnal_running);                  /* only single instance supported */
    LASSERT (ni->ni_interfaces[0] == NULL);     /* explicit interface(s) not supported */

    /* The credit settings here are pretty irrelevent.  Userspace tcplnd has no
     * tx descriptor pool to exhaust and does a blocking send; that's the real
     * limit on send concurrency. */
    ni->ni_maxtxcredits = 1000;
    ni->ni_peertxcredits = 1000;
    
    init_unix_timer();

    b=(bridge)malloc(sizeof(struct bridge));
    p=(procbridge)malloc(sizeof(struct procbridge));
    b->local=p;
    b->b_ni = ni;
    ni->ni_data = b;

    /* init procbridge */
    pthread_mutex_init(&p->mutex,0);
    pthread_cond_init(&p->cond, 0);
    p->nal_flags = 0;

    /* initialize notifier */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, p->notifier)) {
        perror("socketpair failed");
        rc = -errno;
        return rc;
    }

    if (!register_io_handler(p->notifier[1], READ_HANDLER,
                procbridge_notifier_handler, p)) {
        perror("fail to register notifier handler");
        return -ENOMEM;
    }

#ifdef ENABLE_SELECT_DISPATCH
    __global_procbridge = p;
#endif

    /* create nal thread */
    rc = pthread_create(&p->t, NULL, nal_thread, b);
    if (rc != 0) {
        perror("nal_init: pthread_create");
        return -ESRCH;
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
        return -ENETDOWN;

    tcpnal_running = 1;

    return 0;
}
