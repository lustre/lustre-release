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

/* connection.c:
   This file provides a simple stateful connection manager which
   builds tcp connections on demand and leaves them open for
   future use. It also provides the machinery to allow peers
   to connect to it
*/

#include <stdlib.h>
#include <pqtimer.h>
#include <dispatch.h>
#include <table.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <connection.h>
#include <errno.h>


/* global variable: acceptor port */
unsigned short tcpnal_acceptor_port = 988;


/* Function:  compare_connection
 * Arguments: connection c:      a connection in the hash table
 *            ptl_process_id_t:  an id to verify  agains
 * Returns: 1 if the connection is the one requested, 0 otherwise
 *
 *    compare_connection() tests for collisions in the hash table
 */
static int compare_connection(void *arg1, void *arg2)
{
        connection c = arg1;
        unsigned int * id = arg2;
        return((c->ip==id[0]) && (c->port==id[1]));
}


/* Function:  connection_key
 * Arguments: ptl_process_id_t id:  an id to hash
 * Returns: a not-particularily-well-distributed hash
 *          of the id
 */
static unsigned int connection_key(unsigned int *id)
{
    return(id[0]^id[1]);
}


/* Function:  remove_connection
 * Arguments: c: the connection to remove
 */
void remove_connection(void *arg)
{
        connection c = arg;
        unsigned int id[2];
        
        id[0]=c->ip;
        id[1]=c->port;
        hash_table_remove(c->m->connections,id);
        close(c->fd);
        free(c);
}


/* Function:  read_connection: 
 * Arguments: c:    the connection to read from 
 *            dest: the buffer to read into
 *            len:  the number of bytes to read   
 * Returns: success as 1, or failure as 0
 *
 *   read_connection() reads data from the connection, continuing
 *   to read partial results until the request is satisfied or
 *   it errors. TODO: this read should be covered by signal protection.
 */
int read_connection(connection c,
                    unsigned char *dest,
                    int len)
{
    int offset=0,rc;

    if (len){
        do {
            if((rc=syscall(SYS_read, c->fd, dest+offset, len-offset))<=0){
                if (errno==EINTR) {
                    rc=0;
                } else {
                    remove_connection(c);
                    return(0);
                }
            }
            offset+=rc;
        } while (offset<len);
    }
    return(1);
}

static int connection_input(void *d)
{
        connection c = d;
        return((*c->m->handler)(c->m->handler_arg,c));
}


/* Function:  allocate_connection
 * Arguments: t:    tcpnal the allocation is occuring in the context of
 *            dest: portal endpoint address for this connection
 *            fd:   open file descriptor for the socket
 * Returns: an allocated connection structure
 *
 * just encompasses the action common to active and passive
 *  connections of allocation and placement in the global table
 */
static connection allocate_connection(manager m,
                               unsigned int ip,
                               unsigned short port,
                               int fd)
{
    connection c=malloc(sizeof(struct connection));
    unsigned int id[2];
    c->m=m;
    c->fd=fd;
    c->ip=ip;
    c->port=port;
    id[0]=ip;
    id[1]=port;
    register_io_handler(fd,READ_HANDLER,connection_input,c);
    hash_table_insert(m->connections,c,id);
    return(c);
}


/* Function:  new_connection
 * Arguments: t: opaque argument holding the tcpname
 * Returns: 1 in order to reregister for new connection requests
 *
 *  called when the bound service socket recieves
 *     a new connection request, it always accepts and
 *     installs a new connection
 */
static int new_connection(void *z)
{
    manager m=z;
    struct sockaddr_in s;
    int len=sizeof(struct sockaddr_in);
    int fd=accept(m->bound,(struct sockaddr *)&s,&len);
    unsigned int nid=*((unsigned int *)&s.sin_addr);
    /* cfs specific hack */
    //unsigned short pid=s.sin_port;
    allocate_connection(m,htonl(nid),0/*pid*/,fd);
    return(1);
}


/* Function:  force_tcp_connection
 * Arguments: t: tcpnal
 *            dest: portals endpoint for the connection
 * Returns: an allocated connection structure, either
 *          a pre-existing one, or a new connection
 */
connection force_tcp_connection(manager m,
                                unsigned int ip,
                                unsigned short port)
{
    connection c;
    struct sockaddr_in addr;
    unsigned int id[2];

    port = tcpnal_acceptor_port;

    id[0]=ip;
    id[1]=port;

    if (!(c=hash_table_find(m->connections,id))){
        int fd;

        bzero((char *) &addr, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(ip);
        addr.sin_port        = htons(port);

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
            perror("tcpnal socket failed");
            exit(-1);
        }
        if (connect(fd,
                    (struct sockaddr *)&addr,
                    sizeof(struct sockaddr_in)))
            {
                perror("tcpnal connect");
                return(0);
            }
        return(allocate_connection(m,ip,port,fd));
    }
    return(c);
}


/* Function:  bind_socket
 * Arguments: t: the nal state for this interface
 *            port: the port to attempt to bind to
 * Returns: 1 on success, or 0 on error
 *
 * bind_socket() attempts to allocate and bind a socket to the requested
 *  port, or dynamically assign one from the kernel should the port be
 *  zero. Sets the bound and bound_handler elements of m.
 *
 *  TODO: The port should be an explicitly sized type.
 */
static int bind_socket(manager m,unsigned short port)
{
    struct sockaddr_in addr;
    int alen=sizeof(struct sockaddr_in);
    
    if ((m->bound = socket(AF_INET, SOCK_STREAM, 0)) < 0)  
        return(0);
    
    bzero((char *) &addr, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = 0;
    addr.sin_port        = port; 
    
    if (bind(m->bound,(struct sockaddr *)&addr,alen)<0){
        perror ("tcpnal bind"); 
        return(0);
    }
    
    getsockname(m->bound,(struct sockaddr *)&addr, &alen);

    m->bound_handler=register_io_handler(m->bound,READ_HANDLER,
                                         new_connection,m);
    listen(m->bound,5); 
    m->port=addr.sin_port;
    return(1);
}


/* Function:  shutdown_connections
 * Arguments: m: the manager structure
 *
 * close all connections and reclaim resources
 */
void shutdown_connections(manager m)
{
    close(m->bound);
    remove_io_handler(m->bound_handler);
    hash_destroy_table(m->connections,remove_connection);
    free(m);
}


/* Function:  init_connections
 * Arguments: t: the nal state for this interface
 *            port: the port to attempt to bind to
 * Returns: a newly allocated manager structure, or
 *          zero if the fixed port could not be bound
 */
manager init_connections(unsigned short pid,
                         int (*input)(void *, void *),
                         void *a)
{
    manager m=(manager)malloc(sizeof(struct manager));
    m->connections=hash_create_table(compare_connection,connection_key);
    m->handler=input;
    m->handler_arg=a;
    if (bind_socket(m,pid)) return(m);
    free(m);
    return(0);
}
