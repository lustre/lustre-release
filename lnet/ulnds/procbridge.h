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

} *procbridge;

typedef struct nal_init_args {
    ptl_pid_t        nia_requested_pid;
    bridge           nia_bridge;
} nal_init_args_t;

extern void *nal_thread(void *);

extern void set_address(bridge t,ptl_pid_t pidrequest);
extern void procbridge_wakeup_nal(procbridge p);

extern ptl_err_t procbridge_startup (ptl_ni_t *);
extern void procbridge_shutdown (ptl_ni_t *);

extern ptl_err_t tcpnal_send(ptl_ni_t *ni, void *private, ptl_msg_t *cookie,
                             ptl_hdr_t *hdr, int type, ptl_process_id_t target,
                             int routing, unsigned int niov, struct iovec *iov,
                             size_t offset, size_t len);
ptl_err_t tcpnal_recv(ptl_ni_t *ni, void *private, ptl_msg_t *cookie,
                      unsigned int niov, struct iovec *iov,
                      size_t offset, size_t mlen, size_t rlen);




#endif
