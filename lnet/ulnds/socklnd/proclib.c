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
extern int tcpnal_init(bridge);
extern void tcpnal_shutdown(bridge);

static void check_stopping(void *z)
{
    bridge b = z;
    procbridge p = b->local;

    if ((p->nal_flags & NAL_FLAG_STOPPING) == 0)
            return;
    
    tcpnal_shutdown(b);

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

void *nal_thread(void *z)
{
    bridge b = (bridge) z;
    procbridge p=b->local;
    int rc;
    
    rc = tcpnal_init(b);

    /*
     * Whatever the initialization returned is passed back to the
     * user level code for further interpretation.  We just exit if
     * it is non-zero since something went wrong.
     */

    pthread_mutex_lock(&p->mutex);
    p->nal_flags |= (rc != 0) ? NAL_FLAG_STOPPED : NAL_FLAG_RUNNING;
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->mutex);

    if (rc == 0) {
        /* the thunk function is called each time the timer loop
           performs an operation and returns to blocking mode. we
           overload this function to inform the api side that
           it may be interested in looking at the event queue */
        register_thunk(check_stopping,b);
        timer_loop();
    }
    return(0);
}
