/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2002 Eric Hoffman
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

/* select.c:
 *  Provides a general mechanism for registering and dispatching
 *  io events through the select system call.
 */

#ifdef sun
#include <sys/filio.h>
#else
#include <sys/ioctl.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pqtimer.h>
#include <dispatch.h>


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

static void set_flag(io_handler n,fd_set *fds)
{
    if (n->type & READ_HANDLER) FD_SET(n->fd,fds);
    if (n->type & WRITE_HANDLER) FD_SET(n->fd,fds+1);
    if (n->type & EXCEPTION_HANDLER) FD_SET(n->fd,fds+2);
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
    struct timeval *timeout_pointer;
    int result;
    io_handler j;
    io_handler *k;

    /* TODO: loop until the entire interval is expired*/
    if (until){
	when interval=until-now();
        timeout.tv_sec=(interval>>32);
        timeout.tv_usec=((interval<<32)/1000000)>>32;
        timeout_pointer=&timeout;
    } else timeout_pointer=0;

    FD_ZERO(fds);
    FD_ZERO(fds+1);
    FD_ZERO(fds+2);
    for (k=&io_handlers;*k;){
        if ((*k)->disabled){
            j=*k;
            *k=(*k)->next;
            free(j);
        }
        if (*k) {
	    set_flag(*k,fds);
	    k=&(*k)->next;
	}
    }
    result=select(FD_SETSIZE,fds,fds+1,fds+2,timeout_pointer);

    if (result > 0)
        for (j=io_handlers;j;j=j->next){
            if (!(j->disabled) && 
                ((FD_ISSET(j->fd,fds) && (j->type & READ_HANDLER)) ||
                 (FD_ISSET(j->fd,fds+1) && (j->type & WRITE_HANDLER)) ||
                 (FD_ISSET(j->fd,fds+2) && (j->type & EXCEPTION_HANDLER)))){
                if (!(*j->function)(j->argument))
                    j->disabled=1;
            }
        }
}

/* Function: init_unix_timer()
 *   is called to initialize the library 
 */
void init_unix_timer()
{
    io_handlers=0;
    gettimeofday(&beginning_of_epoch, 0);
    initialize_timer(select_timer_block);
}
