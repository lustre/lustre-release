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
#include <syscall.h>
#include <procbridge.h>
#include <pqtimer.h>
#include <dispatch.h>
#include <errno.h>


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
#define forward_failure(operand,fd,buffer,length)\
       if(syscall(SYS_##operand,fd,buffer,length)!=length){\
          lib_fini(b->nal_cb);\
          return(PTL_SEGV);\
       }
static int procbridge_forward(nal_t *n, int id, void *args, ptl_size_t args_len,
			      void *ret, ptl_size_t ret_len)
{
    bridge b=(bridge)n->nal_data;
    procbridge p=(procbridge)b->local;
    int lib=p->to_lib[1];
    int k;

    forward_failure(write,lib, &id, sizeof(id));
    forward_failure(write,lib,&args_len, sizeof(args_len));
    forward_failure(write,lib,&ret_len, sizeof(ret_len));
    forward_failure(write,lib,args, args_len);

    do {
        k=syscall(SYS_read, p->from_lib[0], ret, ret_len);
    } while ((k!=ret_len) && (errno += EINTR));

    if(k!=ret_len){
        perror("nal: read return block");
        return PTL_SEGV;
    }
    return (PTL_OK);
}
#undef forward_failure


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
    int code=PTL_FINI;

    syscall(SYS_write, p->to_lib[1],&code,sizeof(code));
    syscall(SYS_read, p->from_lib[0],&code,sizeof(code));

    syscall(SYS_close, p->to_lib[0]);
    syscall(SYS_close, p->to_lib[1]);
    syscall(SYS_close, p->from_lib[0]);
    syscall(SYS_close, p->from_lib[1]);

    free(p);
    return(0);
}


/* Function: validate
 *    useless stub
 */
static int procbridge_validate(nal_t *nal, void *base, ptl_size_t extent)
{
    return(0);
}


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
    pthread_cond_wait(&p->cond,&p->mutex);
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

/* Function: bridge_init
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
#define unix_failure(operand,fd,buffer,length,text)\
       if(syscall(SYS_##operand,fd,buffer,length)!=length){\
          perror(text);\
          return(NULL);\
       }
#if 0
static nal_t *bridge_init(ptl_interface_t nal,
                          ptl_pid_t pid_request,
                          ptl_ni_limits_t *desired,
                          ptl_ni_limits_t *actual,
                          int *rc)
{
    procbridge p;
    bridge b;
    static int initialized=0;
    ptl_ni_limits_t limits = {-1,-1,-1,-1,-1};

    if(initialized) return (&api_nal);

    init_unix_timer();

    b=(bridge)malloc(sizeof(struct bridge));
    p=(procbridge)malloc(sizeof(struct procbridge));
    api_nal.nal_data=b;
    b->local=p;

    if(pipe(p->to_lib) || pipe(p->from_lib)) {
        perror("nal_init: pipe");
        return(NULL);
    }

    if (desired) limits = *desired;
    unix_failure(write,p->to_lib[1], &pid_request, sizeof(pid_request),
                       "nal_init: write");
    unix_failure(write,p->to_lib[1], &limits, sizeof(ptl_ni_limits_t),
                       "nal_init: write");
    unix_failure(write,p->to_lib[1], &nal, sizeof(ptl_interface_t),
                       "nal_init: write");

    if(pthread_create(&p->t, NULL, nal_thread, b)) {
        perror("nal_init: pthread_create");
        return(NULL);
    }

    unix_failure(read,p->from_lib[0], actual, sizeof(ptl_ni_limits_t),
                 "tcp_init: read");
    unix_failure(read,p->from_lib[0], rc, sizeof(rc),
                 "nal_init: read");

    if(*rc) return(NULL);

    initialized = 1;
    pthread_mutex_init(&p->mutex,0);
    pthread_cond_init(&p->cond, 0);

    return (&api_nal);
}
#endif

ptl_nid_t tcpnal_mynid;

nal_t *procbridge_interface(int num_interface,
                            ptl_pt_index_t ptl_size,
                            ptl_ac_index_t acl_size,
                            ptl_pid_t requested_pid)
{
    procbridge p;
    bridge b;
    static int initialized=0;
    ptl_ni_limits_t limits = {-1,-1,-1,-1,-1};
    int rc, nal_type = PTL_IFACE_TCP;/* PTL_IFACE_DEFAULT FIXME hack */

    if(initialized) return (&api_nal);

    init_unix_timer();

    b=(bridge)malloc(sizeof(struct bridge));
    p=(procbridge)malloc(sizeof(struct procbridge));
    api_nal.nal_data=b;
    b->local=p;

    if(pipe(p->to_lib) || pipe(p->from_lib)) {
        perror("nal_init: pipe");
        return(NULL);
    }

    if (ptl_size)
	    limits.max_ptable_index = ptl_size;
    if (acl_size)
	    limits.max_atable_index = acl_size;

    unix_failure(write,p->to_lib[1], &requested_pid, sizeof(requested_pid),
                       "nal_init: write");
    unix_failure(write,p->to_lib[1], &limits, sizeof(ptl_ni_limits_t),
                       "nal_init: write");
    unix_failure(write,p->to_lib[1], &nal_type, sizeof(nal_type),
                       "nal_init: write");

    if(pthread_create(&p->t, NULL, nal_thread, b)) {
        perror("nal_init: pthread_create");
        return(NULL);
    }

    unix_failure(read,p->from_lib[0], &rc, sizeof(rc),
                 "nal_init: read");

    if(rc) return(NULL);

    b->nal_cb->ni.nid = tcpnal_mynid;
    initialized = 1;
    pthread_mutex_init(&p->mutex,0);
    pthread_cond_init(&p->cond, 0);

    return (&api_nal);
}
#undef unix_failure
