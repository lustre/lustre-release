/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef __DARWIN_OBD_H
#define __DARWIN_OBD_H

#ifndef __OBD_H
#error Do not #include this file directly. #include <obd.h> instead
#endif

#include <libcfs/libcfs.h>

typedef struct semaphore client_obd_lock_t;

static inline void client_obd_list_lock_init(client_obd_lock_t *lock)
{
        sema_init(lock, 1);
}

static inline void client_obd_list_lock_done(client_obd_lock_t *lock)
{}

static inline void client_obd_list_lock(client_obd_lock_t *lock)
{
        mutex_down(lock);
}

static inline void client_obd_list_unlock(client_obd_lock_t *lock)
{
        mutex_up(lock);
}

#endif /* __DARWIN_OBD_H */
