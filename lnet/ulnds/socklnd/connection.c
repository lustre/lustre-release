/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
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

/* connection.c:
   This file provides a simple stateful connection manager which
   builds tcp connections on demand and leaves them open for
   future use. 
*/

#include <stdlib.h>
#include <pqtimer.h>
#include <dispatch.h>
#include <table.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <lnet/types.h>
#include <lnet/lib-types.h>
#include <lnet/socklnd.h>
#include <libcfs/kp30.h>
#include <connection.h>
#include <pthread.h>
#include <errno.h>
#ifndef __CYGWIN__
#include <syscall.h>
#endif

/* tunables (via environment) */
int tcpnal_acceptor_port = 988;
int tcpnal_buffer_size   = 0;
int tcpnal_nagle         = 0;

int
tcpnal_env_param (char *name, int *val)
{
        char   *env = getenv(name);
        int     n;

        if (env == NULL)
                return 1;

        n = strlen(env);                /* scanf may not assign on EOS */
        if (sscanf(env, "%i%n", val, &n) >= 1 && n == strlen(env)) {
                CDEBUG(D_INFO, "Environment variable %s set to %d\n",
                       name, *val);
                return 1;
        }

        CERROR("Can't parse environment variable '%s=%s'\n",
               name, env);
        return 0;
}

int
tcpnal_set_global_params (void)
{
        return  tcpnal_env_param("TCPNAL_PORT",
                                &tcpnal_acceptor_port) &&
                tcpnal_env_param("TCPLND_PORT",
                                &tcpnal_acceptor_port) &&
                tcpnal_env_param("TCPNAL_BUFFER_SIZE",
                                 &tcpnal_buffer_size) &&
                tcpnal_env_param("TCPLND_BUFFER_SIZE",
                                 &tcpnal_buffer_size) &&
                tcpnal_env_param("TCPNAL_NAGLE",
                                 &tcpnal_nagle) &&
                tcpnal_env_param("TCPLND_NAGLE",
                                 &tcpnal_nagle);
}

/* Function:  compare_connection
 * Arguments: connection c:      a connection in the hash table
 *            lnet_process_id_t:  an id to verify  agains
 * Returns: 1 if the connection is the one requested, 0 otherwise
 *
 *    compare_connection() tests for collisions in the hash table
 */
static int compare_connection(void *arg1, void *arg2)
{
    connection  c = arg1;
    lnet_nid_t *nid = arg2;

    return (c->peer_nid == *nid);
}

/* Function:  connection_key
 * Arguments: lnet_process_id_t id:  an id to hash
 * Returns: a not-particularily-well-distributed hash
 *          of the id
 */
static unsigned int connection_key(void *arg)
{
        lnet_nid_t *nid = arg;
        
        return (unsigned int)(*nid);
}

void
close_connection(void *arg)
{
        connection c = arg;
        
        close(c->fd);
        free(c);
}

/* Function:  remove_connection
 * Arguments: c: the connection to remove
 */
void remove_connection(void *arg)
{
        connection c = arg;
        
        hash_table_remove(c->m->connections,&c->peer_nid);
        close_connection(c);
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
    int offset = 0,rc;

    if (len) {
        do {
#ifndef __CYGWIN__
            rc = syscall(SYS_read, c->fd, dest+offset, len-offset);
#else
            rc = recv(c->fd, dest+offset, len-offset, 0);
#endif
            if (rc <= 0) {
                if (errno == EINTR) {
                    rc = 0;
                } else {
                    remove_connection(c);
                    return (0);
                }
            }
            offset += rc;
        } while (offset < len);
    }
    return (1);
}

static int connection_input(void *d)
{
        connection c = d;
        return((*c->m->handler)(c->m->handler_arg,c));
}


static connection 
allocate_connection(manager        m,
                    lnet_nid_t     nid,
                    int            fd)
{
    connection c=malloc(sizeof(struct connection));

    c->m=m;
    c->fd=fd;
    c->peer_nid = nid;

    register_io_handler(fd,READ_HANDLER,connection_input,c);
    hash_table_insert(m->connections,c,&nid);
    return(c);
}

int
tcpnal_write(lnet_nid_t nid, int sockfd, void *buffer, int nob)
{
        int rc = syscall(SYS_write, sockfd, buffer, nob);
        
        /* NB called on an 'empty' socket with huge buffering! */
        if (rc == nob)
                return 0;

        if (rc < 0) {
                CERROR("Failed to send to %s: %s\n",
                       libcfs_nid2str(nid), strerror(errno));
                return -1;
        }
        
        CERROR("Short send to %s: %d/%d\n",
               libcfs_nid2str(nid), rc, nob);
        return -1;
}

int
tcpnal_read(lnet_nid_t nid, int sockfd, void *buffer, int nob) 
{
        int       rc;

        while (nob > 0) {
                rc = syscall(SYS_read, sockfd, buffer, nob);
                
                if (rc == 0) {
                        CERROR("Unexpected EOF from %s\n",
                               libcfs_nid2str(nid));
                        return -1;
                }

                if (rc < 0) {
                        CERROR("Failed to receive from %s: %s\n",
                               libcfs_nid2str(nid), strerror(errno));
                        return -1;
                }

                nob -= rc;
        }
        return 0;
}

int
tcpnal_hello (int sockfd, lnet_nid_t nid)
{
        struct timeval          tv;
        __u64                   incarnation;
        int                     rc;
        int                     nob;
        lnet_acceptor_connreq_t cr;
        lnet_hdr_t              hdr;
        lnet_magicversion_t     hmv;

        gettimeofday(&tv, NULL);
        incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

        memset(&cr, 0, sizeof(cr));
        cr.acr_magic   = LNET_PROTO_ACCEPTOR_MAGIC;
        cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;
        cr.acr_nid     = nid;

        /* hmv initialised and copied separately into hdr; compiler "optimize"
         * likely due to confusion about pointer alias of hmv and hdr when this
         * was done in-place. */
        hmv.magic         = cpu_to_le32(LNET_PROTO_TCP_MAGIC);
        hmv.version_major = cpu_to_le32(LNET_PROTO_TCP_VERSION_MAJOR);
        hmv.version_minor = cpu_to_le32(LNET_PROTO_TCP_VERSION_MINOR);

        memset (&hdr, 0, sizeof (hdr));

        CLASSERT (sizeof (hmv) == sizeof (hdr.dest_nid));
        memcpy(&hdr.dest_nid, &hmv, sizeof(hmv));

        /* hdr.src_nid/src_pid are ignored at dest */

        hdr.type    = cpu_to_le32(LNET_MSG_HELLO);
        hdr.msg.hello.type = cpu_to_le32(SOCKLND_CONN_ANY);
        hdr.msg.hello.incarnation = cpu_to_le64(incarnation);

        /* I don't send any interface info */

        /* Assume sufficient socket buffering for these messages... */
        rc = tcpnal_write(nid, sockfd, &cr, sizeof(cr));
        if (rc != 0)
                return -1;

        rc = tcpnal_write(nid, sockfd, &hdr, sizeof(hdr));
        if (rc != 0)
                return -1;

        rc = tcpnal_read(nid, sockfd, &hmv, sizeof(hmv));
        if (rc != 0)
                return -1;
        
        if (hmv.magic != le32_to_cpu(LNET_PROTO_TCP_MAGIC)) {
                CERROR ("Bad magic %#08x (%#08x expected) from %s\n",
                        cpu_to_le32(hmv.magic), LNET_PROTO_TCP_MAGIC, 
                        libcfs_nid2str(nid));
                return -1;
        }

        if (hmv.version_major != cpu_to_le16 (LNET_PROTO_TCP_VERSION_MAJOR) ||
            hmv.version_minor != cpu_to_le16 (LNET_PROTO_TCP_VERSION_MINOR)) {
                CERROR ("Incompatible protocol version %d.%d (%d.%d expected)"
                        " from %s\n",
                        le16_to_cpu (hmv.version_major),
                        le16_to_cpu (hmv.version_minor),
                        LNET_PROTO_TCP_VERSION_MAJOR,
                        LNET_PROTO_TCP_VERSION_MINOR,
                        libcfs_nid2str(nid));
                return -1;
        }

#if (LNET_PROTO_TCP_VERSION_MAJOR != 1)
# error "This code only understands protocol version 1.x"
#endif
        /* version 1 sends magic/version as the dest_nid of a 'hello' header,
         * so read the rest of it in now... */

        rc = tcpnal_read(nid, sockfd, ((char *)&hdr) + sizeof (hmv),
                         sizeof(hdr) - sizeof(hmv));
        if (rc != 0)
                return -1;

        /* ...and check we got what we expected */
        if (hdr.type != cpu_to_le32 (LNET_MSG_HELLO)) {
                CERROR ("Expecting a HELLO hdr "
                        " but got type %d with %d payload from %s\n",
                        le32_to_cpu (hdr.type),
                        le32_to_cpu (hdr.payload_length), libcfs_nid2str(nid));
                return -1;
        }

        if (le64_to_cpu(hdr.src_nid) == LNET_NID_ANY) {
                CERROR("Expecting a HELLO hdr with a NID, but got LNET_NID_ANY\n");
                return -1;
        }

        if (nid != le64_to_cpu (hdr.src_nid)) {
                CERROR ("Connected to %s, but expecting %s\n",
                        libcfs_nid2str(le64_to_cpu (hdr.src_nid)), 
                        libcfs_nid2str(nid));
                return -1;
        }

        /* Ignore any interface info in the payload */
        nob = le32_to_cpu(hdr.payload_length);
        if (nob != 0) {
                CERROR("Unexpected HELLO payload %d from %s\n",
                       nob, libcfs_nid2str(nid));
                return -1;
        }

        return 0;
}

/* Function:  force_tcp_connection
 * Arguments: t: tcpnal
 *            dest: portals endpoint for the connection
 * Returns: an allocated connection structure, either
 *          a pre-existing one, or a new connection
 */
connection force_tcp_connection(manager    m,
                                lnet_nid_t nid,
                                procbridge pb)
{
    unsigned int       ip = LNET_NIDADDR(nid);
    connection         conn;
    struct sockaddr_in addr;
    struct sockaddr_in locaddr; 
    int                fd;
    int                option;
    int                rc;
    int                sz;

    pthread_mutex_lock(&m->conn_lock);

    conn = hash_table_find(m->connections, &nid);
    if (conn)
            goto out;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(ip);
    addr.sin_port        = htons(tcpnal_acceptor_port);

    memset(&locaddr, 0, sizeof(locaddr)); 
    locaddr.sin_family = AF_INET; 
    locaddr.sin_addr.s_addr = INADDR_ANY;
    locaddr.sin_port = htons(m->port);

#if 1 /* tcpnal connects from a non-privileged port */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
            perror("tcpnal socket failed");
            goto out;
    } 

    option = 1;
    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 
                    &option, sizeof(option));
    if (rc != 0) {
            perror ("Can't set SO_REUSEADDR for socket"); 
            close(fd);
            goto out;
    } 

    if (m->port != 0) {
            /* Bind all subsequent connections to the same port */
            rc = bind(fd, (struct sockaddr *)&locaddr, sizeof(locaddr));
            if (rc != 0) {
                    perror("Error binding port");
                    close(fd);
                    goto out;
            }
    }
    
    rc = connect(fd, (struct sockaddr *)&addr,
                 sizeof(struct sockaddr_in));
    if (rc != 0) {
            perror("Error connecting to remote host");
            close(fd);
            goto out;
    }

    sz = sizeof(locaddr);
    rc = getsockname(fd, (struct sockaddr *)&locaddr, &sz);
    if (rc != 0) {
            perror ("Error on getsockname");
            close(fd);
            goto out;
    }

    if (m->port == 0)
            m->port = ntohs(locaddr.sin_port);
    
#else
    for (rport = IPPORT_RESERVED - 1; rport > IPPORT_RESERVED / 2; --rport) {
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) {
                    perror("tcpnal socket failed");
                    goto out;
            } 
            
            option = 1;
            rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 
                            &option, sizeof(option));
            if (rc != 0) {
                    perror ("Can't set SO_REUSEADDR for socket"); 
                    close(fd);
                    goto out;
            } 

            locaddr.sin_port = htons(rport);
            rc = bind(fd, (struct sockaddr *)&locaddr, sizeof(locaddr));
            if (rc == 0 || errno == EACCES) {
                    rc = connect(fd, (struct sockaddr *)&addr,
                                 sizeof(struct sockaddr_in));
                    if (rc == 0) {
                            break;
                    } else if (errno != EADDRINUSE && errno != EADDRNOTAVAIL) {
                            perror("Error connecting to remote host");
                            close(fd);
                            goto out;
                    }
            } else if (errno != EADDRINUSE) {
                    perror("Error binding to privileged port");
                    close(fd);
                    goto out;
            }
            close(fd);
    }
    
    if (rport == IPPORT_RESERVED / 2) {
            fprintf(stderr, "Out of ports trying to bind to a reserved port\n");
            goto out;
    }
#endif
    
    option = tcpnal_nagle ? 0 : 1;
    setsockopt(fd, SOL_TCP, TCP_NODELAY, &option, sizeof(option));
    option = tcpnal_buffer_size;
    if (option != 0) {
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &option, sizeof(option));
            option = tcpnal_buffer_size;
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &option, sizeof(option));
    }
    
    /* say hello */
    if (tcpnal_hello(fd, nid)) {
            close(fd);
            goto out;
    }
    
    conn = allocate_connection(m, nid, fd);
    
    /* let nal thread know this event right away */
    if (conn)
            procbridge_wakeup_nal(pb);

out:
    pthread_mutex_unlock(&m->conn_lock);
    return (conn);
}


#if 0                                           /* we don't accept connections */
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
    pthread_mutex_lock(&m->conn_lock);
    allocate_connection(m,htonl(nid),0/*pid*/,fd);
    pthread_mutex_unlock(&m->conn_lock);
    return(1);
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
    addr.sin_port        = htons(port);

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
#endif


/* Function:  shutdown_connections
 * Arguments: m: the manager structure
 *
 * close all connections and reclaim resources
 */
void shutdown_connections(manager m)
{
#if 0
        /* we don't accept connections */
        close(m->bound);
        remove_io_handler(m->bound_handler);
#endif
        hash_destroy_table(m->connections,close_connection);
        free(m);
}


/* Function:  init_connections
 * Arguments: t: the nal state for this interface
 * Returns: a newly allocated manager structure, or
 *          zero if the fixed port could not be bound
 */
manager init_connections(int (*input)(void *, void *), void *a)
{
    manager m = (manager)malloc(sizeof(struct manager));

    m->connections = hash_create_table(compare_connection,connection_key);
    m->handler = input;
    m->handler_arg = a;
    m->port = 0;                                /* set on first connection */
    pthread_mutex_init(&m->conn_lock, 0);

    return m;
#if 0
    if (bind_socket(m,pid))
        return(m);

    free(m);
    return(0);
#endif
}
