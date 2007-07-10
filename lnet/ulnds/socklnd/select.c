/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2002 Eric Hoffman
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

/* select.c:
 *  Provides a general mechanism for registering and dispatching
 *  io events through the select system call.
 */

#define DEBUG_SUBSYSTEM S_LND

#ifdef sun
#include <sys/filio.h>
#else
#include <sys/ioctl.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <syscall.h>
#include <pthread.h>
#include <errno.h>
#include <pqtimer.h>
#include <dispatch.h>
#include <procbridge.h>


static struct timeval beginning_of_epoch;
static io_handler io_handlers;

/* Function: now
 *
 * Return: the current time in canonical units: a 64 bit number
 *   where the most significant 32 bits contains the number
 *   of seconds, and the least signficant a count of (1/(2^32))ths
 *   of a second.
 */
when now()
{
    struct timeval result;

    gettimeofday(&result,0);
    return((((unsigned long long)result.tv_sec)<<32)|
           (((unsigned long long)result.tv_usec)<<32)/1000000);
}


/* Function: register_io_handler
 * Arguments: fd: the file descriptor of interest
 *            type: a mask of READ_HANDLER, WRITE_HANDLER, EXCEPTION_HANDLER
 *            function: a function to call when io is available on fd
 *            arg: an opaque correlator to return to the handler
 * Returns: a pointer to the io_handler structure
 */
io_handler register_io_handler(int fd,
                               int type,
                               int (*function)(void *),
                               void *arg)
{
    io_handler i=(io_handler)malloc(sizeof(struct io_handler));
    if ((i->fd=fd)>=0){
        i->type=type;
        i->function=function;
        i->argument=arg;
        i->disabled=0;
        i->last=&io_handlers;
        if ((i->next=io_handlers)) i->next->last=&i->next;
        io_handlers=i;
    }
    return(i);
}

/* Function: remove_io_handler
 * Arguments: i: a pointer to the handler to stop servicing
 *
 * remove_io_handler() doesn't actually free the handler, due
 * to reentrancy problems. it just marks the handler for
 * later cleanup by the blocking function.
 */
void remove_io_handler (io_handler i)
{
    i->disabled=1;
}

static void set_flag(io_handler n,fd_set *r, fd_set *w, fd_set *e)
{
    if (n->type & READ_HANDLER) FD_SET(n->fd, r);
    if (n->type & WRITE_HANDLER) FD_SET(n->fd, w);
    if (n->type & EXCEPTION_HANDLER) FD_SET(n->fd, e);
}

static int prepare_fd_sets(fd_set *r, fd_set *w, fd_set *e)
{
    io_handler j;
    io_handler *k;
    int max = 0;

    FD_ZERO(r);
    FD_ZERO(w);
    FD_ZERO(e);
    for (k=&io_handlers;*k;){
        if ((*k)->disabled){
            j=*k;
            *k=(*k)->next;
            free(j);
        }
        if (*k) {
	    set_flag(*k,r,w,e);
            if ((*k)->fd > max)
                max = (*k)->fd;
	    k=&(*k)->next;
	}
    }
    return max + 1;
}

static int execute_callbacks(fd_set *r, fd_set *w, fd_set *e)
{
    io_handler j;
    int n = 0, t;

    for (j = io_handlers; j; j = j->next) {
        if (j->disabled)
            continue;

        t = 0;
        if (FD_ISSET(j->fd, r) && (j->type & READ_HANDLER)) {
            FD_CLR(j->fd, r);
            t++;
        }
        if (FD_ISSET(j->fd, w) && (j->type & WRITE_HANDLER)) {
            FD_CLR(j->fd, w);
            t++;
        }
        if (FD_ISSET(j->fd, e) && (j->type & EXCEPTION_HANDLER)) {
            FD_CLR(j->fd, e);
            t++;
        }
        if (t == 0)
            continue;

        if (!(*j->function)(j->argument))
            j->disabled = 1;

        n += t;
    }

    return n;
}

#ifdef ENABLE_SELECT_DISPATCH

static struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    int             submitted;
    int             nready;
    int             maxfd;
    fd_set         *rset;
    fd_set         *wset;
    fd_set         *eset;
    struct timeval *timeout;
    struct timeval  submit_time;
} fd_extra = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    0, 0, 0,
    NULL, NULL, NULL, NULL,
};

extern int liblustre_wait_event(int timeout);
extern procbridge __global_procbridge;

/*
 * this will intercept syscall select() of user apps
 * such as MPI libs.
 */
int select(int n, fd_set *rset, fd_set *wset, fd_set *eset,
           struct timeval *timeout)
{
    LASSERT(fd_extra.submitted == 0);

    fd_extra.nready = 0;
    fd_extra.maxfd = n;
    fd_extra.rset = rset;
    fd_extra.wset = wset;
    fd_extra.eset = eset;
    fd_extra.timeout = timeout;

    liblustre_wait_event(0);
    pthread_mutex_lock(&fd_extra.mutex);
    gettimeofday(&fd_extra.submit_time, NULL);
    fd_extra.submitted = 1;
    LASSERT(__global_procbridge);
    procbridge_wakeup_nal(__global_procbridge);

again:
    if (fd_extra.submitted)
        pthread_cond_wait(&fd_extra.cond, &fd_extra.mutex);
    pthread_mutex_unlock(&fd_extra.mutex);

    liblustre_wait_event(0);

    pthread_mutex_lock(&fd_extra.mutex);
    if (fd_extra.submitted)
        goto again;
    pthread_mutex_unlock(&fd_extra.mutex);

    LASSERT(fd_extra.nready >= 0);
    LASSERT(fd_extra.submitted == 0);
    return fd_extra.nready;
}

static int merge_fds(int max, fd_set *rset, fd_set *wset, fd_set *eset)
{
    int i;

    LASSERT(rset);
    LASSERT(wset);
    LASSERT(eset);

    for (i = 0; i < __FD_SETSIZE/__NFDBITS; i++) {
        LASSERT(!fd_extra.rset ||
                !(__FDS_BITS(rset)[i] & __FDS_BITS(fd_extra.rset)[i]));
        LASSERT(!fd_extra.wset ||
                !(__FDS_BITS(wset)[i] & __FDS_BITS(fd_extra.wset)[i]));
        LASSERT(!fd_extra.eset ||
                !(__FDS_BITS(eset)[i] & __FDS_BITS(fd_extra.eset)[i]));

        if (fd_extra.rset && __FDS_BITS(fd_extra.rset)[i])
            __FDS_BITS(rset)[i] |= __FDS_BITS(fd_extra.rset)[i];
        if (fd_extra.wset && __FDS_BITS(fd_extra.wset)[i])
            __FDS_BITS(wset)[i] |= __FDS_BITS(fd_extra.wset)[i];
        if (fd_extra.eset && __FDS_BITS(fd_extra.eset)[i])
            __FDS_BITS(eset)[i] |= __FDS_BITS(fd_extra.eset)[i];
    }

    return (fd_extra.maxfd > max ? fd_extra.maxfd : max);
}

static inline
int timeval_ge(struct timeval *tv1, struct timeval *tv2)
{
    LASSERT(tv1 && tv2);
    return ((tv1->tv_sec - tv2->tv_sec) * 1000000 +
            (tv1->tv_usec - tv2->tv_usec) >= 0);
}

/*
 * choose the most recent timeout value
 */
static struct timeval *choose_timeout(struct timeval *tv1,
                                      struct timeval *tv2)
{
    if (!tv1)
        return tv2;
    else if (!tv2)
        return tv1;

    if (timeval_ge(tv1, tv2))
        return tv2;
    else
        return tv1;
}

/* Function: select_timer_block
 * Arguments: until: an absolute time when the select should return
 *
 *   This function dispatches the various file descriptors' handler
 *   functions, if the kernel indicates there is io available.
 */
void select_timer_block(when until)
{
    fd_set fds[3];
    struct timeval timeout;
    struct timeval *timeout_pointer, *select_timeout;
    int max, nready, nexec;
    int fd_handling;

again:
    if (until) {
        when interval;

        interval = until - now();
        timeout.tv_sec = (interval >> 32);
        timeout.tv_usec = ((interval << 32) / 1000000) >> 32;
        timeout_pointer = &timeout;
    } else
        timeout_pointer = NULL;

    fd_handling = 0;
    max = prepare_fd_sets(&fds[0], &fds[1], &fds[2]);
    select_timeout = timeout_pointer;

    pthread_mutex_lock(&fd_extra.mutex);
    fd_handling = fd_extra.submitted;
    pthread_mutex_unlock(&fd_extra.mutex);
    if (fd_handling) {
        max = merge_fds(max, &fds[0], &fds[1], &fds[2]);
        select_timeout = choose_timeout(timeout_pointer, fd_extra.timeout);
    }

    /* XXX only compile for linux */
#if (__WORDSIZE == 64) && !defined(__mips64__)
    nready = syscall(SYS_select, max, &fds[0], &fds[1], &fds[2],
                     select_timeout);
#else
    nready = syscall(SYS__newselect, max, &fds[0], &fds[1], &fds[2],
                     select_timeout);
#endif
    if (nready < 0) {
        CERROR("select return err %d, errno %d\n", nready, errno);
        return;
    }

    if (nready) {
        nexec = execute_callbacks(&fds[0], &fds[1], &fds[2]);
        nready -= nexec;
    } else
        nexec = 0;

    /* even both nready & nexec are 0, we still need try to wakeup
     * upper thread since it may have timed out
     */
    if (fd_handling) {
        LASSERT(nready >= 0);

        pthread_mutex_lock(&fd_extra.mutex);
        if (nready) {
            if (fd_extra.rset)
                *fd_extra.rset = fds[0];
            if (fd_extra.wset)
                *fd_extra.wset = fds[1];
            if (fd_extra.eset)
                *fd_extra.eset = fds[2];
            fd_extra.nready = nready;
            fd_extra.submitted = 0;
        } else {
            struct timeval t;

            fd_extra.nready = 0;
            if (fd_extra.timeout) {
                gettimeofday(&t, NULL);
                if (timeval_ge(&t, &fd_extra.submit_time))
                    fd_extra.submitted = 0;
            }
        }

        pthread_cond_signal(&fd_extra.cond);
        pthread_mutex_unlock(&fd_extra.mutex);
    }

    /* haven't found portals event, go back to loop if time
     * is not expired */
    if (!nexec) {
        if (timeout_pointer == NULL || now() >= until)
            goto again;
    }
}

#else /* !ENABLE_SELECT_DISPATCH */

/* Function: select_timer_block
 * Arguments: until: an absolute time when the select should return
 *
 *   This function dispatches the various file descriptors' handler
 *   functions, if the kernel indicates there is io available.
 */
void select_timer_block(when until)
{
    fd_set fds[3];
    struct timeval timeout;
    struct timeval *timeout_pointer;
    int max, nready;

    if (until) {
        when interval;
        interval = until - now();
        timeout.tv_sec = (interval >> 32);
        timeout.tv_usec = ((interval << 32) / 1000000) >> 32;
        timeout_pointer = &timeout;
    } else
        timeout_pointer = NULL;

    max = prepare_fd_sets(&fds[0], &fds[1], &fds[2]);

    nready = select(max, &fds[0], &fds[1], &fds[2], timeout_pointer);
    if (nready > 0)
        execute_callbacks(&fds[0], &fds[1], &fds[2]);
}
#endif /* ENABLE_SELECT_DISPATCH */

/* Function: init_unix_timer()
 *   is called to initialize the library
 */
void init_unix_timer()
{
    io_handlers=0;
    gettimeofday(&beginning_of_epoch, 0);
    initialize_timer(select_timer_block);
}
