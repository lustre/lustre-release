/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre_lib.h
 *
 * Basic Lustre library routines.
 */

#ifndef _LUSTRE_LIB_H
#define _LUSTRE_LIB_H

/** \defgroup lib lib
 *
 * @{
 */

#include <libcfs/libcfs.h>
#include <lustre/lustre_idl.h>
#include <lustre_ver.h>
#include <lustre_cfg.h>
#if defined(__linux__)
#include <linux/lustre_lib.h>
#elif defined(__APPLE__)
#include <darwin/lustre_lib.h>
#elif defined(__WINNT__)
#include <winnt/lustre_lib.h>
#else
#error Unsupported operating system.
#endif

/* target.c */
struct ptlrpc_request;
struct obd_export;
struct lu_target;
struct l_wait_info;
#include <lustre_ha.h>
#include <lustre_net.h>

#ifdef HAVE_SERVER_SUPPORT
void target_client_add_cb(struct obd_device *obd, __u64 transno, void *cb_data,
                          int error);
int target_handle_connect(struct ptlrpc_request *req);
int target_handle_disconnect(struct ptlrpc_request *req);
void target_destroy_export(struct obd_export *exp);
int target_handle_ping(struct ptlrpc_request *req);
void target_committed_to_req(struct ptlrpc_request *req);
void target_cancel_recovery_timer(struct obd_device *obd);
void target_stop_recovery_thread(struct obd_device *obd);
void target_cleanup_recovery(struct obd_device *obd);
int target_queue_recovery_request(struct ptlrpc_request *req,
                                  struct obd_device *obd);
int target_bulk_io(struct obd_export *exp, struct ptlrpc_bulk_desc *desc,
                   struct l_wait_info *lwi);
#endif

int target_pack_pool_reply(struct ptlrpc_request *req);
int do_set_info_async(struct obd_import *imp,
                      int opcode, int version,
                      obd_count keylen, void *key,
                      obd_count vallen, void *val,
                      struct ptlrpc_request_set *set);

#define OBD_RECOVERY_MAX_TIME (obd_timeout * 18) /* b13079 */

void target_send_reply(struct ptlrpc_request *req, int rc, int fail_id);

/* client.c */

int client_sanobd_setup(struct obd_device *obddev, struct lustre_cfg* lcfg);
struct client_obd *client_conn2cli(struct lustre_handle *conn);

struct md_open_data;
struct obd_client_handle {
	struct lustre_handle	 och_fh;
	struct lu_fid		 och_fid;
	struct md_open_data	*och_mod;
	struct lustre_handle	 och_lease_handle; /* open lock for lease */
	__u32			 och_magic;
	int			 och_flags;
};
#define OBD_CLIENT_HANDLE_MAGIC 0xd15ea5ed

/* statfs_pack.c */
void statfs_pack(struct obd_statfs *osfs, struct kstatfs *sfs);
void statfs_unpack(struct kstatfs *sfs, struct obd_statfs *osfs);

/* Until such time as we get_info the per-stripe maximum from the OST,
 * we define this to be 2T - 4k, which is the ext3 maxbytes. */
#define LUSTRE_STRIPE_MAXBYTES 0x1fffffff000ULL

/* Special values for remove LOV EA from disk */
#define LOVEA_DELETE_VALUES(size, count, offset) (size == 0 && count == 0 && \
                                                 offset == (typeof(offset))(-1))

#define LMVEA_DELETE_VALUES(count, offset) ((count) == 0 && \
					    (offset) == (typeof(offset))(-1))
/* #define POISON_BULK 0 */

/*
 * l_wait_event is a flexible sleeping function, permitting simple caller
 * configuration of interrupt and timeout sensitivity along with actions to
 * be performed in the event of either exception.
 *
 * The first form of usage looks like this:
 *
 * struct l_wait_info lwi = LWI_TIMEOUT_INTR(timeout, timeout_handler,
 *                                           intr_handler, callback_data);
 * rc = l_wait_event(waitq, condition, &lwi);
 *
 * l_wait_event() makes the current process wait on 'waitq' until 'condition'
 * is TRUE or a "killable" signal (SIGTERM, SIKGILL, SIGINT) is pending.  It
 * returns 0 to signify 'condition' is TRUE, but if a signal wakes it before
 * 'condition' becomes true, it optionally calls the specified 'intr_handler'
 * if not NULL, and returns -EINTR.
 *
 * If a non-zero timeout is specified, signals are ignored until the timeout
 * has expired.  At this time, if 'timeout_handler' is not NULL it is called.
 * If it returns FALSE l_wait_event() continues to wait as described above with
 * signals enabled.  Otherwise it returns -ETIMEDOUT.
 *
 * LWI_INTR(intr_handler, callback_data) is shorthand for
 * LWI_TIMEOUT_INTR(0, NULL, intr_handler, callback_data)
 *
 * The second form of usage looks like this:
 *
 * struct l_wait_info lwi = LWI_TIMEOUT(timeout, timeout_handler);
 * rc = l_wait_event(waitq, condition, &lwi);
 *
 * This form is the same as the first except that it COMPLETELY IGNORES
 * SIGNALS.  The caller must therefore beware that if 'timeout' is zero, or if
 * 'timeout_handler' is not NULL and returns FALSE, then the ONLY thing that
 * can unblock the current process is 'condition' becoming TRUE.
 *
 * Another form of usage is:
 * struct l_wait_info lwi = LWI_TIMEOUT_INTERVAL(timeout, interval,
 *                                               timeout_handler);
 * rc = l_wait_event(waitq, condition, &lwi);
 * This is the same as previous case, but condition is checked once every
 * 'interval' jiffies (if non-zero).
 *
 * Subtle synchronization point: this macro does *not* necessary takes
 * wait-queue spin-lock before returning, and, hence, following idiom is safe
 * ONLY when caller provides some external locking:
 *
 *             Thread1                            Thread2
 *
 *   l_wait_event(&obj->wq, ....);                                       (1)
 *
 *                                    wake_up(&obj->wq):                 (2)
 *                                         spin_lock(&q->lock);          (2.1)
 *                                         __wake_up_common(q, ...);     (2.2)
 *                                         spin_unlock(&q->lock, flags); (2.3)
 *
 *   OBD_FREE_PTR(obj);                                                  (3)
 *
 * As l_wait_event() may "short-cut" execution and return without taking
 * wait-queue spin-lock, some additional synchronization is necessary to
 * guarantee that step (3) can begin only after (2.3) finishes.
 *
 * XXX nikita: some ptlrpc daemon threads have races of that sort.
 *
 */
static inline int back_to_sleep(void *arg)
{
        return 0;
}

#define LWI_ON_SIGNAL_NOOP ((void (*)(void *))(-1))

struct l_wait_info {
        cfs_duration_t lwi_timeout;
        cfs_duration_t lwi_interval;
        int            lwi_allow_intr;
        int  (*lwi_on_timeout)(void *);
        void (*lwi_on_signal)(void *);
        void  *lwi_cb_data;
};

/* NB: LWI_TIMEOUT ignores signals completely */
#define LWI_TIMEOUT(time, cb, data)             \
((struct l_wait_info) {                         \
        .lwi_timeout    = time,                 \
        .lwi_on_timeout = cb,                   \
        .lwi_cb_data    = data,                 \
        .lwi_interval   = 0,                    \
        .lwi_allow_intr = 0                     \
})

#define LWI_TIMEOUT_INTERVAL(time, interval, cb, data)  \
((struct l_wait_info) {                                 \
        .lwi_timeout    = time,                         \
        .lwi_on_timeout = cb,                           \
        .lwi_cb_data    = data,                         \
        .lwi_interval   = interval,                     \
        .lwi_allow_intr = 0                             \
})

#define LWI_TIMEOUT_INTR(time, time_cb, sig_cb, data)   \
((struct l_wait_info) {                                 \
        .lwi_timeout    = time,                         \
        .lwi_on_timeout = time_cb,                      \
        .lwi_on_signal  = sig_cb,                       \
        .lwi_cb_data    = data,                         \
        .lwi_interval   = 0,                            \
        .lwi_allow_intr = 0                             \
})

#define LWI_TIMEOUT_INTR_ALL(time, time_cb, sig_cb, data)       \
((struct l_wait_info) {                                         \
        .lwi_timeout    = time,                                 \
        .lwi_on_timeout = time_cb,                              \
        .lwi_on_signal  = sig_cb,                               \
        .lwi_cb_data    = data,                                 \
        .lwi_interval   = 0,                                    \
        .lwi_allow_intr = 1                                     \
})

#define LWI_INTR(cb, data)  LWI_TIMEOUT_INTR(0, NULL, cb, data)

#ifdef __KERNEL__

/*
 * wait for @condition to become true, but no longer than timeout, specified
 * by @info.
 */
#define __l_wait_event(wq, condition, info, ret, l_add_wait)                   \
do {                                                                           \
	wait_queue_t __wait;                                                   \
	cfs_duration_t __timeout = info->lwi_timeout;                          \
	sigset_t   __blocked;                                              \
	int   __allow_intr = info->lwi_allow_intr;                             \
									       \
	ret = 0;                                                               \
	if (condition)                                                         \
		break;                                                         \
									       \
	init_waitqueue_entry_current(&__wait);				       \
	l_add_wait(&wq, &__wait);                                              \
									       \
	/* Block all signals (just the non-fatal ones if no timeout). */       \
	if (info->lwi_on_signal != NULL && (__timeout == 0 || __allow_intr))   \
		__blocked = cfs_block_sigsinv(LUSTRE_FATAL_SIGS);              \
	else                                                                   \
		__blocked = cfs_block_sigsinv(0);                              \
									       \
	for (;;) {                                                             \
		unsigned       __wstate;                                       \
									       \
		__wstate = info->lwi_on_signal != NULL &&                      \
			   (__timeout == 0 || __allow_intr) ?                  \
			TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE;             \
									       \
		set_current_state(TASK_INTERRUPTIBLE);			       \
									       \
		if (condition)                                                 \
			break;                                                 \
									       \
		if (__timeout == 0) {                                          \
			waitq_wait(&__wait, __wstate);                         \
		} else {                                                       \
			cfs_duration_t interval = info->lwi_interval?          \
					     min_t(cfs_duration_t,             \
						 info->lwi_interval,__timeout):\
					     __timeout;                        \
			cfs_duration_t remaining = waitq_timedwait(&__wait,    \
						   __wstate,                   \
						   interval);                  \
			__timeout = cfs_time_sub(__timeout,                    \
					    cfs_time_sub(interval, remaining));\
			if (__timeout == 0) {                                  \
				if (info->lwi_on_timeout == NULL ||            \
				    info->lwi_on_timeout(info->lwi_cb_data)) { \
					ret = -ETIMEDOUT;                      \
					break;                                 \
				}                                              \
				/* Take signals after the timeout expires. */  \
				if (info->lwi_on_signal != NULL)               \
				    (void)cfs_block_sigsinv(LUSTRE_FATAL_SIGS);\
			}                                                      \
		}                                                              \
                                                                               \
                if (condition)                                                 \
                        break;                                                 \
                if (cfs_signal_pending()) {                                    \
                        if (info->lwi_on_signal != NULL &&                     \
                            (__timeout == 0 || __allow_intr)) {                \
                                if (info->lwi_on_signal != LWI_ON_SIGNAL_NOOP) \
                                        info->lwi_on_signal(info->lwi_cb_data);\
                                ret = -EINTR;                                  \
                                break;                                         \
                        }                                                      \
			/* We have to do this here because some signals */     \
			/* are not blockable - ie from strace(1).       */     \
			/* In these cases we want to schedule_timeout() */     \
			/* again, because we don't want that to return  */     \
			/* -EINTR when the RPC actually succeeded.      */     \
			/* the recalc_sigpending() below will deliver the */   \
			/* signal properly.                             */     \
			cfs_clear_sigpending();                                \
                }                                                              \
        }                                                                      \
                                                                               \
	cfs_restore_sigs(__blocked);                                           \
                                                                               \
	set_current_state(TASK_RUNNING);                               	       \
	remove_wait_queue(&wq, &__wait);                                       \
} while (0)

#else /* !__KERNEL__ */

#define __l_wait_event(wq, condition, info, ret, l_add_wait)            \
do {                                                                    \
        long __timeout = info->lwi_timeout;                             \
        long __now;                                                     \
        long __then = 0;                                                \
        int  __timed_out = 0;                                           \
        int  __interval = obd_timeout;                                  \
                                                                        \
        ret = 0;                                                        \
        if (condition)                                                  \
                break;                                                  \
                                                                        \
        if (__timeout != 0)                                             \
                __then = time(NULL);                                    \
                                                                        \
        if (__timeout && __timeout < __interval)                        \
                __interval = __timeout;                                 \
        if (info->lwi_interval && info->lwi_interval < __interval)      \
                __interval = info->lwi_interval;                        \
                                                                        \
        while (!(condition)) {                                          \
                liblustre_wait_event(__interval);                       \
                if (condition)                                          \
                        break;                                          \
                                                                        \
                if (!__timed_out && info->lwi_timeout != 0) {           \
                        __now = time(NULL);                             \
                        __timeout -= __now - __then;                    \
                        __then = __now;                                 \
                                                                        \
                        if (__timeout > 0)                              \
                                continue;                               \
                                                                        \
                        __timeout = 0;                                  \
                        __timed_out = 1;                                \
                        if (info->lwi_on_timeout == NULL ||             \
                            info->lwi_on_timeout(info->lwi_cb_data)) {  \
                                ret = -ETIMEDOUT;                       \
                                break;                                  \
                        }                                               \
                }                                                       \
        }                                                               \
} while (0)

#endif /* __KERNEL__ */


#define l_wait_event(wq, condition, info)                       \
({                                                              \
	int                 __ret;                              \
	struct l_wait_info *__info = (info);                    \
								\
	__l_wait_event(wq, condition, __info,                   \
		       __ret, add_wait_queue);			\
	__ret;                                                  \
})

#define l_wait_event_exclusive(wq, condition, info)             \
({                                                              \
	int                 __ret;                              \
	struct l_wait_info *__info = (info);                    \
								\
	__l_wait_event(wq, condition, __info,                   \
		       __ret, add_wait_queue_exclusive);        \
	__ret;                                                  \
})

#define l_wait_event_exclusive_head(wq, condition, info)        \
({                                                              \
	int                 __ret;                              \
	struct l_wait_info *__info = (info);                    \
								\
	__l_wait_event(wq, condition, __info,                   \
		       __ret, add_wait_queue_exclusive_head);	\
	__ret;                                                  \
})

#define l_wait_condition(wq, condition)                         \
({                                                              \
        struct l_wait_info lwi = { 0 };                         \
        l_wait_event(wq, condition, &lwi);                      \
})

#define l_wait_condition_exclusive(wq, condition)               \
({                                                              \
        struct l_wait_info lwi = { 0 };                         \
        l_wait_event_exclusive(wq, condition, &lwi);            \
})

#define l_wait_condition_exclusive_head(wq, condition)          \
({                                                              \
        struct l_wait_info lwi = { 0 };                         \
        l_wait_event_exclusive_head(wq, condition, &lwi);       \
})

#ifdef __KERNEL__
#define LIBLUSTRE_CLIENT (0)
#else
#define LIBLUSTRE_CLIENT (1)
#endif

/** @} lib */

#endif /* _LUSTRE_LIB_H */
