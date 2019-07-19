/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LIBCFS_LINUX_WAIT_BIT_H
#define __LIBCFS_LINUX_WAIT_BIT_H

/*
 * Linux wait-bit related types and methods:
 */
#ifdef HAVE_WAIT_BIT_HEADER_H
#include <linux/wait_bit.h>
#endif
#include <linux/wait.h>

#ifndef HAVE_WAIT_QUEUE_ENTRY
#define wait_queue_entry_t wait_queue_t
#endif

#ifndef HAVE_WAIT_BIT_HEADER_H
struct wait_bit_queue_entry {
	struct wait_bit_key	key;
	wait_queue_entry_t	wq_entry;
};

#define ___wait_is_interruptible(state)                                         \
	(!__builtin_constant_p(state) ||                                        \
		state == TASK_INTERRUPTIBLE || state == TASK_KILLABLE)          \

#endif /* ! HAVE_WAIT_BIT_HEADER_H */

#ifndef HAVE_PREPARE_TO_WAIT_EVENT
extern long prepare_to_wait_event(wait_queue_head_t *wq_head,
				  wait_queue_entry_t *wq_entry, int state);
#endif

#ifndef HAVE_CLEAR_AND_WAKE_UP_BIT
/**
 * clear_and_wake_up_bit - clear a bit and wake up anyone waiting on that bit
 *
 * @bit: the bit of the word being waited on
 * @word: the word being waited on, a kernel virtual address
 *
 * You can use this helper if bitflags are manipulated atomically rather than
 * non-atomically under a lock.
 */
static inline void clear_and_wake_up_bit(int bit, void *word)
{
	clear_bit_unlock(bit, word);
	/* See wake_up_bit() for which memory barrier you need to use. */
	smp_mb__after_atomic();
	wake_up_bit(word, bit);
}
#endif /* ! HAVE_CLEAR_AND_WAKE_UP_BIT */

#ifndef HAVE_WAIT_VAR_EVENT
extern void __init wait_bit_init(void);
extern void init_wait_var_entry(struct wait_bit_queue_entry *wbq_entry,
				void *var, int flags);
extern void wake_up_var(void *var);
extern wait_queue_head_t *__var_waitqueue(void *p);

#define ___wait_var_event(var, condition, state, exclusive, ret, cmd)	\
({									\
	__label__ __out;						\
	wait_queue_head_t *__wq_head = __var_waitqueue(var);		\
	struct wait_bit_queue_entry __wbq_entry;			\
	long __ret = ret; /* explicit shadow */				\
									\
	init_wait_var_entry(&__wbq_entry, var,				\
			    exclusive ? WQ_FLAG_EXCLUSIVE : 0);		\
	for (;;) {							\
		long __int = prepare_to_wait_event(__wq_head,		\
						   &__wbq_entry.wq_entry, \
						   state);		\
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
	finish_wait(__wq_head, &__wbq_entry.wq_entry);			\
__out:	__ret;								\
})

#define __wait_var_event(var, condition)				\
	___wait_var_event(var, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			  schedule())

#define wait_var_event(var, condition)					\
do {									\
	might_sleep();							\
	if (condition)							\
		break;							\
	__wait_var_event(var, condition);				\
} while (0)

#define __wait_var_event_killable(var, condition)			\
	___wait_var_event(var, condition, TASK_KILLABLE, 0, 0,		\
			  schedule())

#define wait_var_event_killable(var, condition)				\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_var_event_killable(var, condition);	\
	__ret;								\
})

#define __wait_var_event_timeout(var, condition, timeout)		\
	___wait_var_event(var, ___wait_cond_timeout(condition),		\
			  TASK_UNINTERRUPTIBLE, 0, timeout,		\
			  __ret = schedule_timeout(__ret))

#define wait_var_event_timeout(var, condition, timeout)			\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_var_event_timeout(var, condition, timeout); \
	__ret;								\
})
#endif /* ! HAVE_WAIT_VAR_EVENT */

#endif /* __LICBFS_LINUX_WAIT_BIT_H */
