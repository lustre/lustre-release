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
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/user-prim.h
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_USER_PRIM_H__
#define __LIBCFS_USER_PRIM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

/* Implementations of portable APIs for liblustre */

/*
 * liblustre is single-threaded, so most "synchronization" APIs are trivial.
 */

#ifndef EXPORT_SYMBOL
# define EXPORT_SYMBOL(s)
#endif

/*
 * Just present a single processor until will add thread support.
 */
#ifndef smp_processor_id
# define smp_processor_id() 0
#endif
#ifndef num_online_cpus
# define num_online_cpus() 1
#endif
#ifndef num_possible_cpus
# define num_possible_cpus() 1
#endif
#ifndef get_cpu
# define get_cpu() 0
#endif
#ifndef put_cpu
# define put_cpu() do {} while (0)
#endif
#ifndef NR_CPUS
# define NR_CPUS 1
#endif
#ifndef for_each_possible_cpu
# define for_each_possible_cpu(cpu) for ((cpu) = 0; (cpu) < 1; (cpu)++)
#endif

/*
 * Wait Queue.
 */

typedef struct cfs_waitlink {
	struct list_head sleeping;
	void *process;
} wait_queue_t;

typedef struct cfs_waitq {
	struct list_head sleepers;
} wait_queue_head_t;

#define CFS_DECL_WAITQ(wq) wait_queue_head_t wq
void init_waitqueue_head(struct cfs_waitq *waitq);
void init_waitqueue_entry_current(struct cfs_waitlink *link);
void add_wait_queue(struct cfs_waitq *waitq, struct cfs_waitlink *link);
void add_wait_queue_exclusive(struct cfs_waitq *waitq, struct cfs_waitlink *link);
void add_wait_queue_exclusive_head(struct cfs_waitq *waitq, struct cfs_waitlink *link);
void remove_wait_queue(struct cfs_waitq *waitq, struct cfs_waitlink *link);
int waitqueue_active(struct cfs_waitq *waitq);
void wake_up(struct cfs_waitq *waitq);
void wake_up_nr(struct cfs_waitq *waitq, int nr);
void wake_up_all(struct cfs_waitq *waitq);
void waitq_wait(struct cfs_waitlink *link, long state);
int64_t waitq_timedwait(struct cfs_waitlink *link, long state, int64_t timeout);
void schedule_timeout_and_set_state(long state, int64_t timeout);
void cfs_pause(cfs_duration_t d);
int need_resched(void);
void cond_resched(void);

/*
 * Task states
 */
#define TASK_INTERRUPTIBLE  (0)
#define TASK_UNINTERRUPTIBLE          (1)
#define TASK_RUNNING        (2)

static inline void schedule(void)			{}
static inline void schedule_timeout(int64_t t)	{}
static inline void set_current_state(int state)
{
}

/*
 * Lproc
 */
typedef int (read_proc_t)(char *page, char **start, off_t off,
				int count, int *eof, void *data);

struct file; /* forward ref */
typedef int (write_proc_t)(struct file *file, const char *buffer,
                               unsigned long count, void *data);

/*
 * Signal
 */

/*
 * Timer
 */

struct timer_list {
	struct list_head tl_list;
	void (*function)(ulong_ptr_t unused);
	ulong_ptr_t data;
	long expires;
};


#define in_interrupt()    (0)

struct miscdevice{
};

static inline int misc_register(struct miscdevice *foo)
{
	return 0;
}

static inline int misc_deregister(struct miscdevice *foo)
{
	return 0;
}

#define cfs_recalc_sigpending(l)        do {} while (0)

#define DAEMON_FLAGS                0

#define L1_CACHE_ALIGN(x)		(x)

#ifdef HAVE_LIBPTHREAD
typedef int (*cfs_thread_t)(void *);
void *kthread_run(cfs_thread_t func, void *arg, const char namefmt[], ...);
#else
/* Fine, crash, but stop giving me compile warnings */
#define kthread_run(f, a, n, ...) LBUG()
#endif

uid_t current_uid(void);
gid_t current_gid(void);
uid_t current_fsuid(void);
gid_t current_fsgid(void);

#ifndef HAVE_STRLCPY /* not in glibc for RHEL 5.x, remove when obsolete */
size_t strlcpy(char *tgt, const char *src, size_t tgt_len);
#endif

#ifndef HAVE_STRLCAT /* not in glibc for RHEL 5.x, remove when obsolete */
size_t strlcat(char *tgt, const char *src, size_t tgt_len);
#endif

#define LIBCFS_REALLOC(ptr, size) realloc(ptr, size)

#define cfs_online_cpus() sysconf(_SC_NPROCESSORS_ONLN)

// static inline void local_irq_save(unsigned long flag) {return;}
// static inline void local_irq_restore(unsigned long flag) {return;}

enum {
        CFS_STACK_TRACE_DEPTH = 16
};

struct cfs_stack_trace {
        void *frame[CFS_STACK_TRACE_DEPTH];
};

/*
 * arithmetic
 */
#ifndef do_div /* gcc only, platform-specific will override */
#define do_div(a,b)                     \
        ({                              \
                unsigned long remainder;\
                remainder = (a) % (b);  \
                (a) = (a) / (b);        \
                (remainder);            \
        })
#endif

/*
 * Groups
 */
struct group_info{ };

#ifndef min
# define min(x,y) ((x)<(y) ? (x) : (y))
#endif

#ifndef max
# define max(x,y) ((x)>(y) ? (x) : (y))
#endif

#define get_random_bytes(val, size)     (*val) = 0

/* utility libcfs init/fini entries */
static inline int libcfs_arch_init(void) {
        return 0;
}
static inline void libcfs_arch_cleanup(void) {
}

#endif /* __LIBCFS_USER_PRIM_H__ */
