/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2.1 of the GNU Lesser General
 *   Public License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Portals; if not, write to the Free Software
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
#include <syscall.h>
#include <procbridge.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <timer.h>
//#include <util/pqtimer.h>
#include <dispatch.h>

/* the following functions are stubs to satisfy the nal definition
   without doing anything particularily useful*/

static int nal_write(nal_cb_t *nal,
                     void *private,
                     user_ptr dst_addr,
                     void *src_addr,
                     ptl_size_t len)
{
    memcpy(dst_addr, src_addr, len);
    return 0;
}

static int nal_read(nal_cb_t * nal,
                    void *private,
		    void *dst_addr,
		    user_ptr src_addr,
		    size_t len)
{
	memcpy(dst_addr, src_addr, len);
	return 0;
}

static void *nal_malloc(nal_cb_t *nal,
                        ptl_size_t len)
{
    void *buf =  malloc(len);
    return buf;
}

static void nal_free(nal_cb_t *nal,
                     void *buf,
                     ptl_size_t len)
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
}


static void nal_sti(nal_cb_t *nal,
                    unsigned long *flags)
{
}


static int nal_dist(nal_cb_t *nal,
                    ptl_nid_t nid,
                    unsigned long *dist)
{
    return 0;
}
    


/* Function:  data_from_api
 * Arguments: t: the nal state for this interface
 * Returns: whether to continue reading from the pipe
 *
 *   data_from_api() reads data from the api side in response
 *   to a select.
 *
 *   We define data_failure() for syntactic convenience
 *   of unix error reporting.
 */

#define data_failure(operand,fd,buffer,length)\
       if(syscall(SYS_##operand,fd,buffer,length)!=length){\
          lib_fini(b->nal_cb);\
          return(0);\
       }
static int data_from_api(void *arg)
{
        bridge b = arg;
    procbridge p=(procbridge)b->local;
    /* where are these two sizes derived from ??*/
    char arg_block[ 256 ];
    char ret_block[ 128 ];
    ptl_size_t arg_len,ret_len;
    int fd=p->to_lib[0];
    int index;

    data_failure(read,fd, &index, sizeof(index));

    if (index==PTL_FINI) {
        lib_fini(b->nal_cb);
        if (b->shutdown) (*b->shutdown)(b);
        syscall(SYS_write, p->from_lib[1],&b->alive,sizeof(b->alive));

        /* a heavy-handed but convenient way of shutting down
           the lower side thread */
        pthread_exit(0);
    }

    data_failure(read,fd, &arg_len, sizeof(arg_len));
    data_failure(read,fd, &ret_len, sizeof(ret_len));
    data_failure(read,fd, arg_block, arg_len);

    lib_dispatch(b->nal_cb, NULL, index, arg_block, ret_block);

    data_failure(write,p->from_lib[1],ret_block, ret_len);
    return(1);
}
#undef data_failure



static void wakeup_topside(void *z)
{
    bridge b=z;
    procbridge p=b->local;

    pthread_mutex_lock(&p->mutex);
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->mutex);
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
    bridge b=z;
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
    b->nal_cb->cb_dist=nal_dist;


    register_io_handler(p->to_lib[0],READ_HANDLER,data_from_api,(void *)b);

    if(!(rc = syscall(SYS_read, p->to_lib[0], &pid_request, sizeof(pid_request))))
        perror("procbridge read from api");
    if(!(rc = syscall(SYS_read, p->to_lib[0], &desired, sizeof(ptl_ni_limits_t))))
        perror("procbridge read from api");
    if(!(rc = syscall(SYS_read, p->to_lib[0], &nal_type, sizeof(nal_type))))
        perror("procbridge read from api");

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
#if 0
    write(p->from_lib[1], &actual, sizeof(ptl_ni_limits_t));
#endif
    syscall(SYS_write, p->from_lib[1], &rc, sizeof(rc));
    
    if(!rc) {
        /* the thunk function is called each time the timer loop
           performs an operation and returns to blocking mode. we
           overload this function to inform the api side that
           it may be interested in looking at the event queue */
        register_thunk(wakeup_topside,b);
        timer_loop();
    }
    return(0);
}
#undef LIMIT

