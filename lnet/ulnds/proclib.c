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

/* lib.c:
 *  This file provides the 'library' side for the process-based nals.
 *  it is responsible for communication with the 'api' side and
 *  providing service to the generic portals 'library'
 *  implementation. 'library' might be better termed 'communication'
 *  or 'kernel'.
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <procbridge.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <timer.h>
#include <dispatch.h>

/* the following functions are stubs to satisfy the nal definition
   without doing anything particularily useful*/

static ptl_err_t nal_write(nal_cb_t *nal,
                           void *private,
                           user_ptr dst_addr,
                           void *src_addr,
                           size_t len)
{
    memcpy(dst_addr, src_addr, len);
    return PTL_OK;
}

static ptl_err_t nal_read(nal_cb_t * nal,
                          void *private,
                          void *dst_addr,
                          user_ptr src_addr,
                          size_t len)
{
	memcpy(dst_addr, src_addr, len);
	return PTL_OK;
}

static void *nal_malloc(nal_cb_t *nal,
                        size_t len)
{
    void *buf =  malloc(len);
    return buf;
}

static void nal_free(nal_cb_t *nal,
                     void *buf,
                     size_t len)
{
    free(buf);
}

static void nal_printf(nal_cb_t *nal,
                       const char *fmt,
                       ...)
{
    va_list        ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}


static void nal_cli(nal_cb_t *nal,
                    unsigned long *flags)
{
    bridge b = (bridge) nal->nal_data;
    procbridge p = (procbridge) b->local;

    pthread_mutex_lock(&p->mutex);
}


static void nal_sti(nal_cb_t *nal,
                    unsigned long *flags)
{
    bridge b = (bridge)nal->nal_data;
    procbridge p = (procbridge) b->local;

    pthread_mutex_unlock(&p->mutex);
}

static void nal_callback(nal_cb_t *nal, void *private,
                         lib_eq_t *eq, ptl_event_t *ev)
{
        bridge b = (bridge)nal->nal_data;
        procbridge p = (procbridge) b->local;

        /* holding p->mutex */
        if (eq->event_callback != NULL)
                eq->event_callback(ev);
        
        pthread_cond_broadcast(&p->cond);
}

static int nal_dist(nal_cb_t *nal,
                    ptl_nid_t nid,
                    unsigned long *dist)
{
    return 0;
}

static void check_stopping(void *z)
{
    bridge b = z;
    procbridge p = b->local;

    if ((p->nal_flags & NAL_FLAG_STOPPING) == 0)
            return;
    
    pthread_mutex_lock(&p->mutex);
    p->nal_flags |= NAL_FLAG_STOPPED;
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->mutex);

    pthread_exit(0);
}


/* Function:  nal_thread
 * Arguments: z: an opaque reference to a nal control structure
 *               allocated and partially populated by the api level code
 * Returns: nothing, and only on error or explicit shutdown
 *
 *  This function is the entry point of the pthread initiated on 
 *  the api side of the interface. This thread is used to handle
 *  asynchronous delivery to the application.
 * 
 *  We define a limit macro to place a ceiling on limits
 *   for syntactic convenience
 */
#define LIMIT(x,y,max)\
     if ((unsigned int)x > max) y = max;

extern int tcpnal_init(bridge);

nal_initialize nal_table[PTL_IFACE_MAX]={0,tcpnal_init,0};

void *nal_thread(void *z)
{
    nal_init_args_t *args = (nal_init_args_t *) z;
    bridge b = args->nia_bridge;
    procbridge p=b->local;
    int rc;
    ptl_pid_t pid_request;
    int nal_type;
    ptl_ni_limits_t desired;
    ptl_ni_limits_t actual;
    
    b->nal_cb=(nal_cb_t *)malloc(sizeof(nal_cb_t));
    b->nal_cb->nal_data=b;
    b->nal_cb->cb_read=nal_read;
    b->nal_cb->cb_write=nal_write;
    b->nal_cb->cb_malloc=nal_malloc;
    b->nal_cb->cb_free=nal_free;
    b->nal_cb->cb_map=NULL;
    b->nal_cb->cb_unmap=NULL;
    b->nal_cb->cb_printf=nal_printf;
    b->nal_cb->cb_cli=nal_cli;
    b->nal_cb->cb_sti=nal_sti;
    b->nal_cb->cb_callback=nal_callback;
    b->nal_cb->cb_dist=nal_dist;

    pid_request = args->nia_requested_pid;
    desired = *args->nia_limits;
    nal_type = args->nia_nal_type;

    actual = desired;
    LIMIT(desired.max_match_entries,actual.max_match_entries,MAX_MES);
    LIMIT(desired.max_mem_descriptors,actual.max_mem_descriptors,MAX_MDS);
    LIMIT(desired.max_event_queues,actual.max_event_queues,MAX_EQS);
    LIMIT(desired.max_atable_index,actual.max_atable_index,MAX_ACLS);
    LIMIT(desired.max_ptable_index,actual.max_ptable_index,MAX_PTLS);

    set_address(b,pid_request);

    if (nal_table[nal_type]) rc=(*nal_table[nal_type])(b);
    /* initialize the generic 'library' level code */

    rc = lib_init(b->nal_cb, 
                  b->nal_cb->ni.nid,
                  b->nal_cb->ni.pid,
		  10,
		  actual.max_ptable_index,
		  actual.max_atable_index);

    /*
     * Whatever the initialization returned is passed back to the
     * user level code for further interpretation.  We just exit if
     * it is non-zero since something went wrong.
     */
    /* this should perform error checking */
    pthread_mutex_lock(&p->mutex);
    p->nal_flags |= rc ? NAL_FLAG_STOPPED : NAL_FLAG_RUNNING;
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->mutex);

    if (!rc) {
        /* the thunk function is called each time the timer loop
           performs an operation and returns to blocking mode. we
           overload this function to inform the api side that
           it may be interested in looking at the event queue */
        register_thunk(check_stopping,b);
        timer_loop();
    }
    return(0);
}
#undef LIMIT
