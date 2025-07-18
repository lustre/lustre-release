/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_LINUX_WAIT_H
#define __LIBCFS_LINUX_WAIT_H

/* Make sure we can see if we have TASK_NOLOAD */
#include <linux/sched.h>
#include <linux/wait.h>

#ifndef HAVE_WAIT_QUEUE_ENTRY
#define wait_queue_entry_t wait_queue_t
#endif

#ifndef HAVE_PREPARE_TO_WAIT_EVENT
#define __add_wait_queue_entry_tail __add_wait_queue_tail
#endif

#ifndef HAVE_PREPARE_TO_WAIT_EVENT
extern long prepare_to_wait_event(wait_queue_head_t *wq_head,
				  wait_queue_entry_t *wq_entry, int state);
#endif

/* ___wait_cond_timeout changed number of args in v3.12-rc1-78-g35a2af94c7ce
 * so let's define our own ___wait_cond_timeout1
 */

#define ___wait_cond_timeout1(condition)				\
({									\
	bool __cond = (condition);					\
	if (__cond && !__ret)						\
		__ret = 1;						\
	__cond || !__ret;						\
})

/*
 * prepare_to_wait_event() does not support an exclusive
 * lifo wait.
 * However it will not relink the wait_queue_entry if
 * it is already linked.  So we link to the head of the
 * queue here, and it will stay there.
 */
static inline void prepare_to_wait_exclusive_head(
	wait_queue_head_t *waitq, wait_queue_entry_t *link)
{
	unsigned long flags;

	spin_lock_irqsave(&(waitq->lock), flags);
#ifdef HAVE_WAIT_QUEUE_ENTRY_LIST
	if (list_empty(&link->entry))
#else
	if (list_empty(&link->task_list))
#endif
		__add_wait_queue_exclusive(waitq, link);
	spin_unlock_irqrestore(&((waitq)->lock), flags);
}

#ifndef ___wait_event
/*
 * The below macro ___wait_event() has an explicit shadow of the __ret
 * variable when used from the wait_event_*() macros.
 *
 * This is so that both can use the ___wait_cond_timeout1() construct
 * to wrap the condition.
 *
 * The type inconsistency of the wait_event_*() __ret variable is also
 * on purpose; we use long where we can return timeout values and int
 * otherwise.
 */

#define ___wait_event(wq_head, condition, state, exclusive, ret, cmd)	\
({									\
	__label__ __out;						\
	wait_queue_entry_t __wq_entry;					\
	long __ret = ret;	/* explicit shadow */			\
									\
	init_wait(&__wq_entry);						\
	if (exclusive)							\
		__wq_entry.flags = WQ_FLAG_EXCLUSIVE;			\
	for (;;) {							\
		long __int = prepare_to_wait_event(&wq_head,		\
						  &__wq_entry, state);	\
									\
		if (condition)						\
			break;						\
									\
		if (___wait_is_interruptible(state) && __int) {		\
			__ret = __int;					\
			goto __out;					\
		}							\
									\
		cmd;							\
	}								\
	finish_wait(&wq_head, &__wq_entry);				\
__out:	__ret;								\
})
#endif

#ifndef TASK_NOLOAD

#define TASK_IDLE TASK_INTERRUPTIBLE

#define ___wait_event_idle(wq_head, condition, exclusive, ret, cmd)	\
({									\
	wait_queue_entry_t __wq_entry;					\
	unsigned long flags;						\
	long __ret = ret;	/* explicit shadow */			\
	sigset_t __old_blocked, __new_blocked;				\
									\
	siginitset(&__new_blocked, LUSTRE_FATAL_SIGS);			\
	sigprocmask(0, &__new_blocked, &__old_blocked);			\
	init_wait(&__wq_entry);						\
	if (exclusive)							\
		__wq_entry.flags = WQ_FLAG_EXCLUSIVE;			\
	for (;;) {							\
		prepare_to_wait_event(&wq_head,				\
				   &__wq_entry,				\
				   TASK_INTERRUPTIBLE);			\
									\
		if (condition)						\
			break;						\
		/* We have to do this here because some signals */	\
		/* are not blockable - ie from strace(1).       */	\
		/* In these cases we want to schedule_timeout() */	\
		/* again, because we don't want that to return  */	\
		/* -EINTR when the RPC actually succeeded.      */	\
		/* the recalc_sigpending() below will deliver the */	\
		/* signal properly.                             */	\
		if (signal_pending(current)) {				\
			spin_lock_irqsave(&current->sighand->siglock,	\
					  flags);			\
			clear_tsk_thread_flag(current, TIF_SIGPENDING);	\
			spin_unlock_irqrestore(&current->sighand->siglock,\
					       flags);			\
		}							\
		cmd;							\
	}								\
	finish_wait(&wq_head, &__wq_entry);				\
	sigprocmask(SIG_SETMASK, &__old_blocked, NULL);			\
	__ret;								\
})

#define wait_event_idle(wq_head, condition)				\
do {									\
	might_sleep();							\
	if (!(condition))						\
		___wait_event_idle(wq_head, condition, 0, 0, schedule());\
} while (0)

#define wait_event_idle_exclusive(wq_head, condition)			\
do {									\
	might_sleep();							\
	if (!(condition))						\
		___wait_event_idle(wq_head, condition, 1, 0, schedule());\
} while (0)

#define __wait_event_idle_exclusive_timeout(wq_head, condition, timeout)\
	___wait_event_idle(wq_head, ___wait_cond_timeout1(condition),	\
			   1, timeout,					\
			   __ret = schedule_timeout(__ret))

#define wait_event_idle_exclusive_timeout(wq_head, condition, timeout)	\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout1(condition))				\
		__ret = __wait_event_idle_exclusive_timeout(		\
			wq_head, condition, timeout);			\
	__ret;								\
})

#define __wait_event_idle_exclusive_timeout_cmd(wq_head, condition,	\
						timeout, cmd1, cmd2)	\
	___wait_event_idle(wq_head, ___wait_cond_timeout1(condition),	\
			   1, timeout,					\
			   cmd1; __ret = schedule_timeout(__ret); cmd2)

#define wait_event_idle_exclusive_timeout_cmd(wq_head, condition, timeout,\
					      cmd1, cmd2)		\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout1(condition))				\
		__ret = __wait_event_idle_exclusive_timeout_cmd(	\
			wq_head, condition, timeout, cmd1, cmd2);	\
	__ret;								\
})

#define __wait_event_idle_timeout(wq_head, condition, timeout)		\
	___wait_event_idle(wq_head, ___wait_cond_timeout1(condition),	\
			   0, timeout,					\
			   __ret = schedule_timeout(__ret))

#define wait_event_idle_timeout(wq_head, condition, timeout)		\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout1(condition))				\
		__ret = __wait_event_idle_timeout(wq_head, condition,	\
						  timeout);		\
	__ret;								\
})

#else /* TASK_IDLE */
#ifndef wait_event_idle
/**
 * wait_event_idle - wait for a condition without contributing to system load
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_IDLE) until the
 * @condition evaluates to true.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 */
#define wait_event_idle(wq_head, condition)				\
do {									\
	might_sleep();							\
	if (!(condition))						\
		___wait_event(wq_head, condition, TASK_IDLE, 0, 0,	\
			      schedule());				\
} while (0)
#endif
#ifndef wait_event_idle_exclusive
/**
 * wait_event_idle_exclusive - wait for a condition without contributing to
 *               system load
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_IDLE) until the
 * @condition evaluates to true.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * The process is put on the wait queue with an WQ_FLAG_EXCLUSIVE flag
 * set thus if other processes wait on the same list, when this
 * process is woken further processes are not considered.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 */
#define wait_event_idle_exclusive(wq_head, condition)			\
do {									\
	might_sleep();							\
	if (!(condition))						\
		___wait_event(wq_head, condition, TASK_IDLE, 1, 0,	\
			      schedule());				\
} while (0)
#endif
#ifndef wait_event_idle_exclusive_timeout
/**
 * wait_event_idle_exclusive_timeout - sleep without load until a condition
 *                       becomes true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_IDLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * The process is put on the wait queue with an WQ_FLAG_EXCLUSIVE flag
 * set thus if other processes wait on the same list, when this
 * process is woken further processes are not considered.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * Returns:
 * 0 if the @condition evaluated to %false after the @timeout elapsed,
 * 1 if the @condition evaluated to %true after the @timeout elapsed,
 * or the remaining jiffies (at least 1) if the @condition evaluated
 * to %true before the @timeout elapsed.
 */
#define wait_event_idle_exclusive_timeout(wq_head, condition, timeout)	\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout1(condition))				\
		__ret = __wait_event_idle_exclusive_timeout(wq_head,	\
							    condition,	\
							    timeout);	\
	__ret;								\
})
#endif
#ifndef wait_event_idle_exclusive_timeout_cmd
#define __wait_event_idle_exclusive_timeout_cmd(wq_head, condition,	\
						timeout, cmd1, cmd2)	\
	___wait_event(wq_head, ___wait_cond_timeout1(condition),	\
		      TASK_IDLE, 1, timeout,				\
		      cmd1; __ret = schedule_timeout(__ret); cmd2)

#define wait_event_idle_exclusive_timeout_cmd(wq_head, condition, timeout,\
					      cmd1, cmd2)		\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout1(condition))				\
		__ret = __wait_event_idle_exclusive_timeout_cmd(	\
			wq_head, condition, timeout, cmd1, cmd2);	\
	__ret;								\
})
#endif

#ifndef wait_event_idle_timeout

#define __wait_event_idle_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout1(condition),	\
		      TASK_IDLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))

/**
 * wait_event_idle_timeout - sleep without load until a condition becomes
 *                           true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_IDLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * Returns:
 * 0 if the @condition evaluated to %false after the @timeout elapsed,
 * 1 if the @condition evaluated to %true after the @timeout elapsed,
 * or the remaining jiffies (at least 1) if the @condition evaluated
 * to %true before the @timeout elapsed.
 */
#define wait_event_idle_timeout(wq_head, condition, timeout)		\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout1(condition))				\
		__ret = __wait_event_idle_timeout(wq_head, condition,	\
						  timeout);		\
	__ret;								\
})
#endif
#endif /* TASK_IDLE */

/* ___wait_event_lifo is used for lifo exclusive 'idle' waits */
#ifdef TASK_NOLOAD

#define ___wait_event_lifo(wq_head, condition, ret, cmd)		\
({									\
	wait_queue_entry_t	 __wq_entry;				\
	long __ret = ret;	/* explicit shadow */			\
									\
	init_wait(&__wq_entry);						\
	__wq_entry.flags =  WQ_FLAG_EXCLUSIVE;				\
	for (;;) {							\
		prepare_to_wait_exclusive_head(&wq_head, &__wq_entry);	\
		prepare_to_wait_event(&wq_head, &__wq_entry, TASK_IDLE);\
									\
		if (condition)						\
			break;						\
									\
		cmd;							\
	}								\
	finish_wait(&wq_head, &__wq_entry);				\
	__ret;								\
})
#else
#define ___wait_event_lifo(wq_head, condition, ret, cmd)		\
({									\
	wait_queue_entry_t __wq_entry;					\
	unsigned long flags;						\
	long __ret = ret;	/* explicit shadow */			\
	sigset_t __old_blocked, __new_blocked;				\
									\
	siginitset(&__new_blocked, LUSTRE_FATAL_SIGS);			\
	sigprocmask(0, &__new_blocked, &__old_blocked);			\
	init_wait(&__wq_entry);						\
	__wq_entry.flags = WQ_FLAG_EXCLUSIVE;				\
	for (;;) {							\
		prepare_to_wait_exclusive_head(&wq_head, &__wq_entry);	\
		prepare_to_wait_event(&wq_head, &__wq_entry,		\
				      TASK_INTERRUPTIBLE);		\
									\
		if (condition)						\
			break;						\
		/* See justification in ___wait_event_idle */		\
		if (signal_pending(current)) {				\
			spin_lock_irqsave(&current->sighand->siglock,	\
					  flags);			\
			clear_tsk_thread_flag(current, TIF_SIGPENDING);	\
			spin_unlock_irqrestore(&current->sighand->siglock,\
					       flags);			\
		}							\
		cmd;							\
	}								\
	sigprocmask(SIG_SETMASK, &__old_blocked, NULL);			\
	finish_wait(&wq_head, &__wq_entry);				\
	__ret;								\
})
#endif

#define wait_event_idle_exclusive_lifo(wq_head, condition)		\
do {									\
	might_sleep();							\
	if (!(condition))						\
		___wait_event_lifo(wq_head, condition, 0, schedule());	\
} while (0)

#define __wait_event_idle_lifo_timeout(wq_head, condition, timeout)	\
	___wait_event_lifo(wq_head, ___wait_cond_timeout1(condition),	\
			   timeout,					\
			   __ret = schedule_timeout(__ret))

#define wait_event_idle_exclusive_lifo_timeout(wq_head, condition, timeout)\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout1(condition))				\
		__ret = __wait_event_idle_lifo_timeout(wq_head,		\
						       condition,	\
						       timeout);	\
	__ret;								\
})

/* l_wait_event_abortable() is a bit like wait_event_killable()
 * except there is a fixed set of signals which will abort:
 * LUSTRE_FATAL_SIGS
 */
#define LUSTRE_FATAL_SIGS					 \
	(sigmask(SIGKILL) | sigmask(SIGINT) | sigmask(SIGTERM) | \
	 sigmask(SIGQUIT) | sigmask(SIGALRM))

#define l_wait_event_abortable(wq, condition)				\
({									\
	sigset_t __new_blocked, __old_blocked;				\
	int __ret = 0;							\
	siginitsetinv(&__new_blocked, LUSTRE_FATAL_SIGS);		\
	sigprocmask(SIG_BLOCK, &__new_blocked, &__old_blocked);		\
	__ret = wait_event_interruptible(wq, condition);		\
	sigprocmask(SIG_SETMASK, &__old_blocked, NULL);			\
	__ret;								\
})

#define l_wait_event_abortable_exclusive(wq, condition)			\
({									\
	sigset_t __new_blocked, __old_blocked;				\
	int __ret = 0;							\
	siginitsetinv(&__new_blocked, LUSTRE_FATAL_SIGS);		\
	sigprocmask(SIG_BLOCK, &__new_blocked, &__old_blocked);		\
	__ret = wait_event_interruptible_exclusive(wq, condition);	\
	sigprocmask(SIG_SETMASK, &__old_blocked, NULL);			\
	__ret;								\
})

#ifndef HAVE_WAIT_WOKEN
#define WQ_FLAG_WOKEN		0x02
long wait_woken(wait_queue_entry_t *wait, unsigned int mode, long timeout);
int woken_wake_function(wait_queue_entry_t *wait, unsigned int mode,
			int sync, void *key);
#endif /* HAVE_WAIT_WOKEN */

#endif /* __LICBFS_LINUX_WAIT_H */
