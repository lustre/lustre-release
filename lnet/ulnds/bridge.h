/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

#include <portals/lib-p30.h>

typedef struct bridge {
    int alive;
    nal_cb_t *nal_cb;
    void *lower;
    void *local;
    void (*shutdown)(struct bridge *);
    /* this doesn't really belong here */
    unsigned char iptop8;
} *bridge;


nal_t *bridge_init(ptl_interface_t nal,
                   ptl_pid_t pid_request,
                   ptl_ni_limits_t *desired,
                   ptl_ni_limits_t *actual,
                   int *rc);

typedef int (*nal_initialize)(bridge);
extern nal_initialize nal_table[PTL_IFACE_MAX];
