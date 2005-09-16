/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

#ifndef TCPNAL_PROCBRIDGE_H
#define TCPNAL_PROCBRIDGE_H

#include <lnet/lib-lnet.h>

typedef struct bridge {
    int alive;
    lnet_ni_t *b_ni;
    void *lower;
    void *local;
    /* this doesn't really belong here */
    unsigned char iptop8;
} *bridge;

#endif
