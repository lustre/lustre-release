/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

#ifndef _PROCBRIDGE_H_
#define _PROCBRIDGE_H_

#include <pthread.h>
#include <bridge.h>
#include <ipmap.h>


#define NAL_FLAG_RUNNING        1
#define NAL_FLAG_STOPPING       2
#define NAL_FLAG_STOPPED        4

typedef struct procbridge {
    /* sync between user threads and nal thread */
    pthread_t t;
    pthread_cond_t cond;
    pthread_mutex_t mutex;

    /* socket pair used to notify nal thread */
    int notifier[2];

    int nal_flags;

    pthread_mutex_t nal_cb_lock;
} *procbridge;

typedef struct nal_init_args {
    ptl_pid_t        nia_requested_pid;
    ptl_ni_limits_t *nia_limits;
    int              nia_nal_type;
    bridge           nia_bridge;
} nal_init_args_t;

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
extern void procbridge_wakeup_nal(procbridge p);

#endif
