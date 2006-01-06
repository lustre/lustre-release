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

} *procbridge;

typedef struct nal_init_args {
    lnet_pid_t        nia_requested_pid;
    bridge           nia_bridge;
} nal_init_args_t;

extern void *nal_thread(void *);

extern void procbridge_wakeup_nal(procbridge p);

extern int procbridge_startup (lnet_ni_t *);
extern void procbridge_shutdown (lnet_ni_t *);

extern void tcpnal_notify(lnet_ni_t *ni, lnet_nid_t nid, int alive);

extern int tcpnal_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int tcpnal_recv(lnet_ni_t *ni, void *private, lnet_msg_t *cookie,
                int delayed, unsigned int niov,
                struct iovec *iov, lnet_kiov_t *kiov,
                unsigned int offset, unsigned int mlen, unsigned int rlen);
extern int tcpnal_set_global_params();




#endif
