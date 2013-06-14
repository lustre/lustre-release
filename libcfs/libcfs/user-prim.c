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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/user-prim.c
 *
 * Implementations of portable APIs for liblustre
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

/*
 * liblustre is single-threaded, so most "synchronization" APIs are trivial.
 */

#ifndef __KERNEL__

#include <string.h>
#include <libcfs/libcfs.h>

/*
 * Wait queue. No-op implementation.
 */

void cfs_waitq_init(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitlink_init(struct cfs_waitlink *link)
{
        LASSERT(link != NULL);
        (void)link;
}

void cfs_waitq_add(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

void cfs_waitq_add_exclusive(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

void cfs_waitq_add_exclusive_head(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        cfs_waitq_add_exclusive(waitq, link);
}

void cfs_waitq_del(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

int cfs_waitq_active(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
        return 0;
}

void cfs_waitq_signal(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_signal_nr(struct cfs_waitq *waitq, int nr)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_broadcast(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_wait(struct cfs_waitlink *link, cfs_task_state_t state)
{
        LASSERT(link != NULL);
        (void)link;

        /* well, wait for something to happen */
	call_wait_handler(0);
}

int64_t cfs_waitq_timedwait(struct cfs_waitlink *link, cfs_task_state_t state,
                            int64_t timeout)
{
        LASSERT(link != NULL);
        (void)link;
	call_wait_handler(timeout);
        return 0;
}

void cfs_schedule_timeout_and_set_state(cfs_task_state_t state, int64_t timeout)
{
        cfs_waitlink_t    l;
        /* sleep(timeout) here instead? */
        cfs_waitq_timedwait(&l, state, timeout);
}

void
cfs_pause(cfs_duration_t d)
{
        struct timespec s;

        cfs_duration_nsec(d, &s);
        nanosleep(&s, NULL);
}

int cfs_need_resched(void)
{
        return 0;
}

void cfs_cond_resched(void)
{
}

/*
 * Timer
 */

void cfs_init_timer(cfs_timer_t *t)
{
        CFS_INIT_LIST_HEAD(&t->tl_list);
}

void cfs_timer_init(cfs_timer_t *l, cfs_timer_func_t *func, void *arg)
{
        CFS_INIT_LIST_HEAD(&l->tl_list);
        l->function = func;
        l->data = (ulong_ptr_t)arg;
        return;
}

int cfs_timer_is_armed(cfs_timer_t *l)
{
        if (cfs_time_before(cfs_time_current(), l->expires))
                return 1;
        else
                return 0;
}

void cfs_timer_arm(cfs_timer_t *l, cfs_time_t deadline)
{
        l->expires = deadline;
}

void cfs_timer_disarm(cfs_timer_t *l)
{
}
cfs_time_t cfs_timer_deadline(cfs_timer_t *l)
{
        return l->expires;
}


#ifdef HAVE_LIBPTHREAD

/*
 * Threads
 */

struct lustre_thread_arg {
        cfs_thread_t f;
        void *arg;
};
static void *cfs_thread_helper(void *data)
{
        struct lustre_thread_arg *targ = data;
        cfs_thread_t f  = targ->f;
        void *arg = targ->arg;

        free(targ);

        (void)f(arg);
        return NULL;
}

void *kthread_run(cfs_thread_t func, void *arg, const char namefmt[], ...)
{
	pthread_t tid;
	pthread_attr_t tattr;
	int rc;
	struct lustre_thread_arg *targ_p =
				malloc(sizeof(struct lustre_thread_arg));

	if (targ_p == NULL)
		return ERR_PTR(-ENOMEM);

	targ_p->f = func;
	targ_p->arg = arg;

	pthread_attr_init(&tattr);
	pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &tattr, cfs_thread_helper, targ_p);
	pthread_attr_destroy(&tattr);
	return ERR_PTR(rc);
}
#endif

uid_t cfs_curproc_uid(void)
{
        return getuid();
}

gid_t cfs_curproc_gid(void)
{
        return getgid();
}

uid_t cfs_curproc_fsuid(void)
{
        return getuid();
}

gid_t cfs_curproc_fsgid(void)
{
        return getgid();
}

#ifndef HAVE_STRLCPY /* not in glibc for RHEL 5.x, remove when obsolete */
size_t strlcpy(char *tgt, const char *src, size_t tgt_len)
{
	int src_len = strlen(src);

	strncpy(tgt, src, tgt_len - 1);
	tgt[tgt_len - 1] = '\0';

	return src_len + 1;
}
#endif

#ifndef HAVE_STRLCAT /* not in glibc for RHEL 5.x, remove when obsolete */
size_t strlcat(char *tgt, const char *src, size_t size)
{
	size_t tgt_len = strlen(tgt);

	if (size > tgt_len) {
		strncat(tgt, src, size - tgt_len - 1);
		tgt[size - 1] = '\0';
	}

	return tgt_len + strlen(src);
}
#endif

/* Read the environment variable of current process specified by @key. */
int cfs_get_environ(const char *key, char *value, int *val_len)
{
	char *entry;
	int len;

	entry = getenv(key);
	if (entry == NULL)
		return -ENOENT;

	len = strlcpy(value, entry, *val_len);
	if (len >= *val_len)
		return -EOVERFLOW;

	return 0;
}

void cfs_enter_debugger(void)
{
        /*
         * nothing for now.
         */
}

int unshare_fs_struct()
{
	return 0;
}

cfs_sigset_t cfs_block_allsigs(void)
{
	cfs_sigset_t   all;
	cfs_sigset_t   old;
	int            rc;

	sigfillset(&all);
	rc = sigprocmask(SIG_BLOCK, &all, &old);
	LASSERT(rc == 0);

	return old;
}

cfs_sigset_t cfs_block_sigs(unsigned long sigs)
{
	cfs_sigset_t   old;
	cfs_sigset_t   blocks = { { sigs } }; /* kludge */
	int   rc;

	rc = sigprocmask(SIG_BLOCK, &blocks, &old);
	LASSERT (rc == 0);

	return old;
}

/* Block all signals except for the @sigs. It's only used in
 * Linux kernel, just a dummy here. */
cfs_sigset_t cfs_block_sigsinv(unsigned long sigs)
{
        cfs_sigset_t old;
        int rc;

        /* Return old blocked sigs */
        rc = sigprocmask(SIG_SETMASK, NULL, &old);
        LASSERT(rc == 0);

        return old;
}

void cfs_restore_sigs(cfs_sigset_t old)
{
        int   rc = sigprocmask(SIG_SETMASK, &old, NULL);

        LASSERT (rc == 0);
}

int cfs_signal_pending(void)
{
        cfs_sigset_t    empty;
        cfs_sigset_t    set;
        int  rc;

        rc = sigpending(&set);
        LASSERT (rc == 0);

        sigemptyset(&empty);

        return !memcmp(&empty, &set, sizeof(set));
}

void cfs_clear_sigpending(void)
{
        return;
}

#ifdef __linux__

/*
 * In glibc (NOT in Linux, so check above is not right), implement
 * stack-back-tracing through backtrace() function.
 */
#include <execinfo.h>

void cfs_stack_trace_fill(struct cfs_stack_trace *trace)
{
        backtrace(trace->frame, ARRAY_SIZE(trace->frame));
}

void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no)
{
        if (0 <= frame_no && frame_no < ARRAY_SIZE(trace->frame))
                return trace->frame[frame_no];
        else
                return NULL;
}

#else

void cfs_stack_trace_fill(struct cfs_stack_trace *trace)
{}
void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no)
{
        return NULL;
}

/* __linux__ */
#endif

void lbug_with_loc(struct libcfs_debug_msg_data *msgdata)
{
        /* No libcfs_catastrophe in userspace! */
        libcfs_debug_msg(msgdata, "LBUG\n");
        abort();
}

/* !__KERNEL__ */
#endif

/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
