/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

#ifndef _PROCBRIDGE_H_
#define _PROCBRIDGE_H_

#include <pthread.h>
#include <bridge.h>
#include <ipmap.h>


typedef struct procbridge {
    pthread_t t;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    int to_lib[2];
    int from_lib[2];
} *procbridge;

extern void *nal_thread(void *);


#define PTL_INIT        (LIB_MAX_DISPATCH+1)
#define PTL_FINI        (LIB_MAX_DISPATCH+2)

#define MAX_ACLS        1
#define MAX_PTLS        128

extern void set_address(bridge t,ptl_pid_t pidrequest);
extern nal_t *procbridge_interface(int num_interface,
                            ptl_pt_index_t ptl_size,
                            ptl_ac_index_t acl_size,
                            ptl_pid_t requested_pid);

#endif
