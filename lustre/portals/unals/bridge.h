/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

#ifndef TCPNAL_PROCBRIDGE_H
#define TCPNAL_PROCBRIDGE_H

#include <portals/lib-p30.h>
#include <portals/nal.h>

#define PTL_IFACE_TCP 1
#define PTL_IFACE_ER 2
#define PTL_IFACE_SS 3
#define PTL_IFACE_MAX 4

typedef struct bridge {
    int alive;
    nal_cb_t *nal_cb;
    void *lower;
    void *local;
    void (*shutdown)(struct bridge *);
    /* this doesn't really belong here */
    unsigned char iptop8;
} *bridge;


typedef int (*nal_initialize)(bridge);
extern nal_initialize nal_table[PTL_IFACE_MAX];

#endif
