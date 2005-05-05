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

static int nal_dist(lib_nal_t *nal,
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
extern int tcpnal_init(bridge);

nal_initialize nal_table[PTL_IFACE_MAX]={0,tcpnal_init,0};

void *nal_thread(void *z)
{
    nal_init_args_t *args = (nal_init_args_t *) z;
    bridge b = args->nia_bridge;
    procbridge p=b->local;
    int rc;
    ptl_process_id_t process_id;
    int nal_type;
    
    b->lib_nal=(lib_nal_t *)malloc(sizeof(lib_nal_t));
    b->lib_nal->libnal_data=b;
    b->lib_nal->libnal_map=NULL;
    b->lib_nal->libnal_unmap=NULL;
    b->lib_nal->libnal_dist=nal_dist;

    nal_type = args->nia_nal_type;

    /* Wierd, but this sets b->lib_nal->libnal_ni.ni_pid.{nid,pid}, which
     * lib_init() is about to do from the process_id passed to it...*/
    set_address(b,args->nia_requested_pid);

    process_id = b->lib_nal->libnal_ni.ni_pid;
    
    if (nal_table[nal_type]) rc=(*nal_table[nal_type])(b);
    /* initialize the generic 'library' level code */

    rc = lib_init(b->lib_nal, args->nia_apinal, 
                  process_id, 
                  args->nia_requested_limits, 
                  args->nia_actual_limits);

    /*
     * Whatever the initialization returned is passed back to the
     * user level code for further interpretation.  We just exit if
     * it is non-zero since something went wrong.
     */
    /* this should perform error checking */
    pthread_mutex_lock(&p->mutex);
    p->nal_flags |= (rc != PTL_OK) ? NAL_FLAG_STOPPED : NAL_FLAG_RUNNING;
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->mutex);

    if (rc == PTL_OK) {
        /* the thunk function is called each time the timer loop
           performs an operation and returns to blocking mode. we
           overload this function to inform the api side that
           it may be interested in looking at the event queue */
        register_thunk(check_stopping,b);
        timer_loop();
    }
    return(0);
}
