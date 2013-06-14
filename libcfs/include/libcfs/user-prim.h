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
 * Copyright (c) 2012, Intel Corporation.
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

#ifndef __KERNEL__

typedef struct proc_dir_entry           cfs_proc_dir_entry_t;

/*
 * Just present a single processor until will add thread support.
 */
#ifndef smp_processor_id
# define cfs_smp_processor_id() 0
#else
# define cfs_smp_processor_id() smp_processor_id()
#endif
#ifndef num_online_cpus
# define cfs_num_online_cpus() 1
#else
# define cfs_num_online_cpus() num_online_cpus()
#endif
#ifndef num_possible_cpus
# define cfs_num_possible_cpus() 1
#else
# define cfs_num_possible_cpus() num_possible_cpus()
#endif
#ifndef num_present_cpus
# define cfs_num_present_cpus() 1
#else
# define cfs_num_present_cpus() num_present_cpus()
#endif
/*
 * Wait Queue.
 */

typedef struct cfs_waitlink {
        cfs_list_t sleeping;
        void *process;
} cfs_waitlink_t;

typedef struct cfs_waitq {
        cfs_list_t sleepers;
} cfs_waitq_t;

#define CFS_DECL_WAITQ(wq) cfs_waitq_t wq

/*
 * Task states
 */
typedef long cfs_task_state_t;

#define CFS_TASK_INTERRUPTIBLE  (0)
#define CFS_TASK_UNINT          (1)
#define CFS_TASK_RUNNING        (2)

static inline void cfs_schedule(void)			{}
static inline void cfs_schedule_timeout(int64_t t)	{}

/*
 * Lproc
 */
typedef int (cfs_read_proc_t)(char *page, char **start, off_t off,
                          int count, int *eof, void *data);

struct file; /* forward ref */
typedef int (cfs_write_proc_t)(struct file *file, const char *buffer,
                               unsigned long count, void *data);

/*
 * Signal
 */
typedef sigset_t                        cfs_sigset_t;

/*
 * Timer
 */

typedef struct {
        cfs_list_t tl_list;
        void (*function)(ulong_ptr_t unused);
        ulong_ptr_t data;
        long expires;
} cfs_timer_t;


#define cfs_in_interrupt()    (0)

typedef void cfs_psdev_t;

static inline int cfs_psdev_register(cfs_psdev_t *foo)
{
        return 0;
}

static inline int cfs_psdev_deregister(cfs_psdev_t *foo)
{
        return 0;
}

#define cfs_sigfillset(l)               do {} while (0)
#define cfs_recalc_sigpending(l)        do {} while (0)
/* Fine, crash, but stop giving me compile warnings */
#define cfs_kthread_run(fn,d,fmt,...)   LBUG()

#define CFS_DAEMON_FLAGS                0

#define CFS_L1_CACHE_ALIGN(x)		(x)

#ifdef HAVE_LIBPTHREAD
typedef int (*cfs_thread_t)(void *);
void *kthread_run(cfs_thread_t func, void *arg, const char namefmt[], ...);
#else
/* Fine, crash, but stop giving me compile warnings */
#define kthread_run(f, a, n, ...) LBUG()
#endif

uid_t cfs_curproc_uid(void);
gid_t cfs_curproc_gid(void);
uid_t cfs_curproc_fsuid(void);
gid_t cfs_curproc_fsgid(void);

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
typedef struct cfs_group_info {

} cfs_group_info_t;

#ifndef min
# define min(x,y) ((x)<(y) ? (x) : (y))
#endif

#ifndef max
# define max(x,y) ((x)>(y) ? (x) : (y))
#endif

#define cfs_get_random_bytes_prim(val, size)     (*val) = 0

/* utility libcfs init/fini entries */
#ifdef __WINNT__
extern int libcfs_arch_init(void);
extern void libcfs_arch_cleanup(void);
#else /* !__WINNT__ */
static inline int libcfs_arch_init(void) {
        return 0;
}
static inline void libcfs_arch_cleanup(void) {
}
/* __WINNT__ */
#endif

/* proc interface wrappers for non-win OS */
#ifndef __WINNT__
#define cfs_proc_open   open
#define cfs_proc_mknod  mknod
#define cfs_proc_ioctl  ioctl
#define cfs_proc_close  close
#define cfs_proc_read   read
#define cfs_proc_write  write
#define cfs_proc_fopen  fopen
#define cfs_proc_fclose fclose
#define cfs_proc_fgets  fgets
/* !__WINNT__ */
#endif

/* !__KERNEL__ */
#endif

/* __LIBCFS_USER_PRIM_H__ */
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
