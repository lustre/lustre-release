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

/* address.c:
 * this file provides functions to aquire the IP address of the node
 * and translate them into a NID/PID pair which supports a static
 * mapping of virtual nodes into the port range of an IP socket.
*/

#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <portals/p30.h>
#include <bridge.h>
#include <ipmap.h>


/* Function:  get_node_id
 * Returns: a 32 bit id for this node, actually a big-endian IP address
 *
 * get_node_id() determines the host name and uses the resolver to
 *  find out its ip address. This is fairly fragile and inflexible, but
 *  explicitly asking about interfaces and their addresses is very
 *  complicated and nonportable.
 */
static unsigned int get_node_id(void)
{
    char buffer[255];
    unsigned int x;
    struct hostent *he;
    char * host_envp;

    if (!(host_envp = getenv("PTL_HOSTID")))
        {
            gethostname(buffer,sizeof(buffer));
            he=gethostbyname(buffer);
            if (he)
                    x=*(unsigned int *)he->h_addr_list[0];
            else
                    x = 0;
            return(ntohl(x));
        }
    else 
        {
            if (host_envp[1] != 'x')
                {
                    int a, b, c, d;
                    sscanf(host_envp, "%d.%d.%d.%d", &a, &b, &c, &d);
                    return ((a<<24) | (b<<16) | (c<<8) | d);
                }
            else
                {
                    long long hostid = strtoll(host_envp, 0, 0);
                    return((unsigned int) hostid);
                }
        }
}


/* Function:  set_address
 * Arugments: t: a procnal structure to populate with the request
 *
 * set_address performs the bit manipulations to set the nid, pid, and
 *    iptop8 fields of the procnal structures.
 *
 * TODO: fix pidrequest to try to do dynamic binding if PTL_ID_ANY
 */

#ifdef DIRECT_IP_MODE
void set_address(bridge t,ptl_pid_t pidrequest)
{
    int port;
    if (pidrequest==(unsigned short)PTL_PID_ANY) port = 0;
    else port=pidrequest;
    t->nal_cb->ni.nid=get_node_id();
    t->nal_cb->ni.pid=port;
}
#else

void set_address(bridge t,ptl_pid_t pidrequest)
{
    int virtnode, in_addr, port; 
    ptl_pid_t pid;

    /* get and remember my node id*/
    if (!getenv("PTL_VIRTNODE"))
        virtnode = 0;
    else 
        {
            int maxvnode = PNAL_VNODE_MASK - (PNAL_BASE_PORT 
                                              >> PNAL_VNODE_SHIFT);
            virtnode = atoi(getenv("PTL_VIRTNODE"));
            if (virtnode > maxvnode)
                {
                    fprintf(stderr, "PTL_VIRTNODE of %d is too large - max %d\n",
                            virtnode, maxvnode);
                    return;
                }
        }
    
    in_addr = get_node_id();

    t->iptop8 = in_addr >> PNAL_HOSTID_SHIFT;/* for making new connections */
    t->nal_cb->ni.nid = ((in_addr & PNAL_HOSTID_MASK) 
                            << PNAL_VNODE_SHIFT)
        + virtnode;

    pid=pidrequest;
    /* TODO: Support of pid PTL_ID_ANY with virtual nodes needs more work. */
#ifdef notyet
    if (pid==(unsigned short)PTL_PID_ANY) port = 0;
#endif
    if (pid==(unsigned short)PTL_PID_ANY) 
        {
            fprintf(stderr, "portal pid PTL_ID_ANY is not currently supported\n");
            return;
        }
    else if (pid > PNAL_PID_MASK)
        {
            fprintf(stderr, "portal pid of %d is too large - max %d\n",
                    pid, PNAL_PID_MASK);
            return;
        }
    else port = ((virtnode << PNAL_VNODE_SHIFT) + pid) + PNAL_BASE_PORT;
    t->nal_cb->ni.pid=pid;
}
#endif
