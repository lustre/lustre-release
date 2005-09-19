/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef MGC_INTERNAL_H
#define MGC_INTERNAL_H

struct mgc_rpc_lock {
        struct semaphore rpcl_sem;
};

static inline void mgc_init_rpc_lock(struct mgc_rpc_lock *lck)
{
        sema_init(&lck->rpcl_sem, 1);
}

#endif
