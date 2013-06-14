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
 * libcfs/libcfs/darwin/darwin-prim.c
 *
 * Darwin porting library
 * Make things easy to port
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <mach/mach_types.h>
#include <string.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/filedesc.h>
#include <sys/namei.h>
#include <miscfs/devfs/devfs.h>
#include <kern/thread.h>

#include <libcfs/libcfs.h>

/*
 * cfs pseudo device, actually pseudo char device in darwin
 */
#define KLNET_MAJOR  -1

kern_return_t  cfs_psdev_register(cfs_psdev_t *dev) {
	dev->index = cdevsw_add(KLNET_MAJOR, dev->devsw);
	if (dev->index < 0) {
		printf("libcfs_init: failed to allocate a major number!\n");
		return KERN_FAILURE;
	}
	dev->handle = devfs_make_node(makedev (dev->index, 0),
                                      DEVFS_CHAR, UID_ROOT,
                                      GID_WHEEL, 0666, (char *)dev->name, 0);
	return KERN_SUCCESS;
}

kern_return_t  cfs_psdev_deregister(cfs_psdev_t *dev) {
	devfs_remove(dev->handle);
	cdevsw_remove(dev->index, dev->devsw);
	return KERN_SUCCESS;
}

/*
 * KPortal symbol register / unregister support
 */
struct rw_semaphore             cfs_symbol_lock;
struct list_head                cfs_symbol_list;

void *
cfs_symbol_get(const char *name)
{
        struct list_head    *walker;
        struct cfs_symbol   *sym = NULL;

        down_read(&cfs_symbol_lock);
        list_for_each(walker, &cfs_symbol_list) {
                sym = list_entry (walker, struct cfs_symbol, sym_list);
                if (!strcmp(sym->name, name)) {
                        sym->ref ++;
                        break;
                }
        }
        up_read(&cfs_symbol_lock);
        if (sym != NULL)
                return sym->value;
        return NULL;
}

kern_return_t
cfs_symbol_put(const char *name)
{
        struct list_head    *walker;
        struct cfs_symbol   *sym = NULL;

        down_read(&cfs_symbol_lock);
        list_for_each(walker, &cfs_symbol_list) {
                sym = list_entry (walker, struct cfs_symbol, sym_list);
                if (!strcmp(sym->name, name)) {
                        sym->ref --;
                        LASSERT(sym->ref >= 0);
                        break;
                }
        }
        up_read(&cfs_symbol_lock);
        LASSERT(sym != NULL);

        return 0;
}

kern_return_t
cfs_symbol_register(const char *name, const void *value)
{
        struct list_head    *walker;
        struct cfs_symbol   *sym = NULL;
        struct cfs_symbol   *new = NULL;

        MALLOC(new, struct cfs_symbol *, sizeof(struct cfs_symbol), M_TEMP, M_WAITOK|M_ZERO);
        strncpy(new->name, name, CFS_SYMBOL_LEN);
        new->value = (void *)value;
        new->ref = 0;
        CFS_INIT_LIST_HEAD(&new->sym_list);

        down_write(&cfs_symbol_lock);
        list_for_each(walker, &cfs_symbol_list) {
                sym = list_entry (walker, struct cfs_symbol, sym_list);
                if (!strcmp(sym->name, name)) {
                        up_write(&cfs_symbol_lock);
                        FREE(new, M_TEMP);
                        return KERN_NAME_EXISTS;
                }

        }
        list_add_tail(&new->sym_list, &cfs_symbol_list);
        up_write(&cfs_symbol_lock);

        return KERN_SUCCESS;
}

kern_return_t
cfs_symbol_unregister(const char *name)
{
        struct list_head    *walker;
        struct list_head    *nxt;
        struct cfs_symbol   *sym = NULL;

        down_write(&cfs_symbol_lock);
        list_for_each_safe(walker, nxt, &cfs_symbol_list) {
                sym = list_entry (walker, struct cfs_symbol, sym_list);
                if (!strcmp(sym->name, name)) {
                        LASSERT(sym->ref == 0);
                        list_del (&sym->sym_list);
                        FREE(sym, M_TEMP);
                        break;
                }
        }
        up_write(&cfs_symbol_lock);

        return KERN_SUCCESS;
}

void
cfs_symbol_init()
{
        CFS_INIT_LIST_HEAD(&cfs_symbol_list);
        init_rwsem(&cfs_symbol_lock);
}

void
cfs_symbol_fini()
{
        struct list_head    *walker;
        struct cfs_symbol   *sym = NULL;

        down_write(&cfs_symbol_lock);
        list_for_each(walker, &cfs_symbol_list) {
                sym = list_entry (walker, struct cfs_symbol, sym_list);
                LASSERT(sym->ref == 0);
                list_del (&sym->sym_list);
                FREE(sym, M_TEMP);
        }
        up_write(&cfs_symbol_lock);

        fini_rwsem(&cfs_symbol_lock);
        return;
}

struct kernel_thread_arg
{
	spinlock_t	lock;
	atomic_t	inuse;
	cfs_thread_t	func;
	void		*arg;
};

struct kernel_thread_arg cfs_thread_arg;

#define THREAD_ARG_FREE			0
#define THREAD_ARG_HOLD			1
#define THREAD_ARG_RECV			2

#define set_targ_stat(a, v)		atomic_set(&(a)->inuse, v)
#define get_targ_stat(a)		atomic_read(&(a)->inuse)

/*
 * Hold the thread argument and set the status of thread_status
 * to THREAD_ARG_HOLD, if the thread argument is held by other
 * threads (It's THREAD_ARG_HOLD already), current-thread has to wait.
 */
#define thread_arg_hold(pta, _func, _arg)			\
	do {							\
		spin_lock(&(pta)->lock);			\
		if (get_targ_stat(pta) == THREAD_ARG_FREE) {	\
			set_targ_stat((pta), THREAD_ARG_HOLD);	\
			(pta)->arg = (void *)_arg;		\
			(pta)->func = _func;			\
			spin_unlock(&(pta)->lock);		\
			break;					\
		}						\
		spin_unlock(&(pta)->lock);			\
		cfs_schedule();					\
	} while(1);						\

/*
 * Release the thread argument if the thread argument has been
 * received by the child-thread (Status of thread_args is
 * THREAD_ARG_RECV), otherwise current-thread has to wait.
 * After release, the thread_args' status will be set to
 * THREAD_ARG_FREE, and others can re-use the thread_args to
 * create new kernel_thread.
 */
#define thread_arg_release(pta)					\
	do {							\
		spin_lock(&(pta)->lock);			\
		if (get_targ_stat(pta) == THREAD_ARG_RECV) {	\
			(pta)->arg = NULL;			\
			(pta)->func = NULL;			\
			set_targ_stat(pta, THREAD_ARG_FREE);	\
			spin_unlock(&(pta)->lock);		\
			break;					\
		}						\
		spin_unlock(&(pta)->lock);			\
		cfs_schedule();					\
	} while(1)

/*
 * Receive thread argument (Used in child thread), set the status
 * of thread_args to THREAD_ARG_RECV.
 */
#define __thread_arg_recv_fin(pta, _func, _arg, fin)		\
	do {							\
		spin_lock(&(pta)->lock);			\
		if (get_targ_stat(pta) == THREAD_ARG_HOLD) {	\
			if (fin)				\
			    set_targ_stat(pta, THREAD_ARG_RECV);\
			_arg = (pta)->arg;			\
			_func = (pta)->func;			\
			spin_unlock(&(pta)->lock);		\
			break;					\
		}						\
		spin_unlock(&(pta)->lock);			\
		cfs_schedule();					\
	} while (1);						\

/*
 * Just set the thread_args' status to THREAD_ARG_RECV
 */
#define thread_arg_fin(pta)					\
	do {							\
		spin_lock(&(pta)->lock);			\
		assert( get_targ_stat(pta) == THREAD_ARG_HOLD);	\
		set_targ_stat(pta, THREAD_ARG_RECV);		\
		spin_unlock(&(pta)->lock);			\
	} while(0)

#define thread_arg_recv(pta, f, a)	__thread_arg_recv_fin(pta, f, a, 1)
#define thread_arg_keep(pta, f, a)	__thread_arg_recv_fin(pta, f, a, 0)

void
cfs_thread_agent_init(void)
{
        set_targ_stat(&cfs_thread_arg, THREAD_ARG_FREE);
        spin_lock_init(&cfs_thread_arg.lock);
        cfs_thread_arg.arg = NULL;
        cfs_thread_arg.func = NULL;
}

void
cfs_thread_agent_fini(void)
{
        assert(get_targ_stat(&cfs_thread_arg) == THREAD_ARG_FREE);

        spin_lock_done(&cfs_thread_arg.lock);
}

/*
 *
 * All requests to create kernel thread will create a new
 * thread instance of cfs_thread_agent, one by one.
 * cfs_thread_agent will call the caller's thread function
 * with argument supplied by caller.
 */
void
cfs_thread_agent (void)
{
        cfs_thread_t           func = NULL;
        void                   *arg = NULL;

        thread_arg_recv(&cfs_thread_arg, func, arg);
        /* printf("entry of thread agent (func: %08lx).\n", (void *)func); */
        assert(func != NULL);
        func(arg);
        /* printf("thread agent exit. (func: %08lx)\n", (void *)func); */
        (void) thread_terminate(current_thread());
}

extern thread_t kernel_thread(task_t task, void (*start)(void));

cfs_task_t
kthread_run(cfs_thread_t func, void *arg, const char namefmt[], ...)
{
	int ret = 0;
	thread_t th = NULL;

	thread_arg_hold(&cfs_thread_arg, func, arg);
	th = kernel_thread(kernel_task, cfs_thread_agent);
	thread_arg_release(&cfs_thread_arg);
	if (th != THREAD_NULL) {
		/*
		 * FIXME: change child thread name...
		 * cfs_curproc_comm() is already broken. So it is left as is...
		va_list args;
		va_start(args, namefmt);
		snprintf(cfs_curproc_comm(), CFS_CURPROC_COMM_MAX,
			 namefmt, args);
		va_end(args);
		 */
	} else {
                ret = -1;
	}
	return (cfs_task_t)((long)ret);
}

/*
 * XXX Liang: kexts cannot access sigmask in Darwin8.
 * it's almost impossible for us to get/set signal mask
 * without patching kernel.
 * Should we provide these functions in xnu?
 *
 * These signal functions almost do nothing now, we 
 * need to investigate more about signal in Darwin.
 */

extern int block_procsigmask(struct proc *p,  int bit);

cfs_sigset_t cfs_block_allsigs()
{
        cfs_sigset_t    old = 0;
#ifdef __DARWIN8__
#else
        block_procsigmask(current_proc(), -1);
#endif
        return old;
}

cfs_sigset_t cfs_block_sigs(unsigned long sigs)
{
	cfs_sigset_t    old = 0;
#ifdef __DARWIN8__
#else
	block_procsigmask(current_proc(), sigs);
#endif
	return old;
}

/* Block all signals except for the @sigs. It's only used in
 * Linux kernel, just a dummy here. */
cfs_sigset_t cfs_block_sigsinv(unsigned long sigs)
{
        cfs_sigset_t old = 0;
        return old;
}

void cfs_restore_sigs(cfs_sigset_t old)
{
}

int cfs_signal_pending(void)

{
#ifdef __DARWIN8__
        extern int thread_issignal(proc_t, thread_t, sigset_t);
        return thread_issignal(current_proc(), current_thread(), (sigset_t)-1);
#else
        return SHOULDissignal(current_proc(), current_uthread())
#endif
}

void cfs_clear_sigpending(void)
{
#ifdef __DARWIN8__
#else
        clear_procsiglist(current_proc(), -1);
#endif
}

#ifdef __DARWIN8__

#else /* !__DARWIN8__ */

void lustre_cone_in(boolean_t *state, funnel_t **cone)
{
        *cone = thread_funnel_get();
        if (*cone == network_flock)
                thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
        else if (*cone == NULL)
                *state = thread_funnel_set(kernel_flock, TRUE);
}

void lustre_cone_ex(boolean_t state, funnel_t *cone)
{
        if (cone == network_flock)
                thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
        else if (cone == NULL)
                (void) thread_funnel_set(kernel_flock, state);
}

void lustre_net_in(boolean_t *state, funnel_t **cone)
{
        *cone = thread_funnel_get();
        if (*cone == kernel_flock)
                thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
        else if (*cone == NULL)
                *state = thread_funnel_set(network_flock, TRUE);
}

void lustre_net_ex(boolean_t state, funnel_t *cone)
{
        if (cone == kernel_flock)
                thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
        else if (cone == NULL)
                (void) thread_funnel_set(network_flock, state);
}
#endif /* !__DARWIN8__ */

void cfs_waitq_init(struct cfs_waitq *waitq)
{
	ksleep_chan_init(&waitq->wq_ksleep_chan);
}

void cfs_waitlink_init(struct cfs_waitlink *link)
{
	ksleep_link_init(&link->wl_ksleep_link);
}

void cfs_waitq_add(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        link->wl_waitq = waitq;
	ksleep_add(&waitq->wq_ksleep_chan, &link->wl_ksleep_link);
}

void cfs_waitq_add_exclusive(struct cfs_waitq *waitq,
                             struct cfs_waitlink *link)
{
        link->wl_waitq = waitq;
	link->wl_ksleep_link.flags |= KSLEEP_EXCLUSIVE;
	ksleep_add(&waitq->wq_ksleep_chan, &link->wl_ksleep_link);
}

void cfs_waitq_del(struct cfs_waitq *waitq,
                   struct cfs_waitlink *link)
{
	ksleep_del(&waitq->wq_ksleep_chan, &link->wl_ksleep_link);
}

int cfs_waitq_active(struct cfs_waitq *waitq)
{
	return (1);
}

void cfs_waitq_signal(struct cfs_waitq *waitq)
{
	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */
	ksleep_wake(&waitq->wq_ksleep_chan);
}

void cfs_waitq_signal_nr(struct cfs_waitq *waitq, int nr)
{
	ksleep_wake_nr(&waitq->wq_ksleep_chan, nr);
}

void cfs_waitq_broadcast(struct cfs_waitq *waitq)
{
	ksleep_wake_all(&waitq->wq_ksleep_chan);
}

void cfs_waitq_wait(struct cfs_waitlink *link, cfs_task_state_t state)
{
        ksleep_wait(&link->wl_waitq->wq_ksleep_chan, state);
}

cfs_duration_t  cfs_waitq_timedwait(struct cfs_waitlink *link,
                                    cfs_task_state_t state,
                                    cfs_duration_t timeout)
{
        return ksleep_timedwait(&link->wl_waitq->wq_ksleep_chan, 
                                state, timeout);
}

typedef  void (*ktimer_func_t)(void *);
void cfs_timer_init(cfs_timer_t *t, void (* func)(unsigned long), void *arg)
{
        ktimer_init(&t->t, (ktimer_func_t)func, arg);
}

void cfs_timer_done(struct cfs_timer *t)
{
        ktimer_done(&t->t);
}

void cfs_timer_arm(struct cfs_timer *t, cfs_time_t deadline)
{
        ktimer_arm(&t->t, deadline);
}

void cfs_timer_disarm(struct cfs_timer *t)
{
        ktimer_disarm(&t->t);
}

int  cfs_timer_is_armed(struct cfs_timer *t)
{
        return ktimer_is_armed(&t->t);
}

cfs_time_t cfs_timer_deadline(struct cfs_timer *t)
{
        return ktimer_deadline(&t->t);
}

void cfs_enter_debugger(void)
{
#ifdef __DARWIN8__
        extern void Debugger(const char * reason);
        Debugger("CFS");
#else
        extern void PE_enter_debugger(char *cause);
        PE_enter_debugger("CFS");
#endif
}

int cfs_online_cpus(void)
{
        int     activecpu;
        size_t  size;

#ifdef __DARWIN8__ 
        size = sizeof(int);
        sysctlbyname("hw.activecpu", &activecpu, &size, NULL, 0);
        return activecpu;
#else
        host_basic_info_data_t hinfo;
        kern_return_t kret;
        int count = HOST_BASIC_INFO_COUNT;
#define BSD_HOST 1
        kret = host_info(BSD_HOST, HOST_BASIC_INFO, &hinfo, &count);
        if (kret == KERN_SUCCESS) 
                return (hinfo.avail_cpus);
        return(-EINVAL);
#endif
}

int cfs_ncpus(void)
{
        int     ncpu;
        size_t  size;

        size = sizeof(int);

        sysctlbyname("hw.ncpu", &ncpu, &size, NULL, 0);
        return ncpu;
}
