/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

#define DIRECT_IP_MODE
#ifdef DIRECT_IP_MODE
#define PNAL_NID(in_addr, port) (in_addr)
#define PNAL_PID(pid) (pid)
#define PNAL_IP(in_addr, port) (in_addr)
#define PNAL_PORT(nid, pid) (pid)
#else

#define PNAL_BASE_PORT 4096
#define PNAL_HOSTID_SHIFT 24
#define PNAL_HOSTID_MASK ((1 << PNAL_HOSTID_SHIFT) - 1)
#define PNAL_VNODE_SHIFT 8
#define PNAL_VNODE_MASK ((1 << PNAL_VNODE_SHIFT) - 1)
#define PNAL_PID_SHIFT 8
#define PNAL_PID_MASK ((1 << PNAL_PID_SHIFT) - 1)

#define PNAL_NID(in_addr, port) (((ntohl(in_addr) & PNAL_HOSTID_MASK) \
                                    << PNAL_VNODE_SHIFT) \
                                   | (((ntohs(port)-PNAL_BASE_PORT) >>\
                                       PNAL_PID_SHIFT)))
#define PNAL_PID(port) ((ntohs(port) - PNAL_BASE_PORT)  & PNAL_PID_MASK)

#define PNAL_IP(nid,t)  (htonl((((unsigned)(nid))\
                                >> PNAL_VNODE_SHIFT)\
                               | (t->iptop8 << PNAL_HOSTID_SHIFT)))
#define PNAL_PORT(nid, pid) (htons(((((nid) & PNAL_VNODE_MASK) \
                                 << PNAL_VNODE_SHIFT) \
                                | ((pid) & PNAL_PID_MASK)) \
                               + PNAL_BASE_PORT))
#endif
