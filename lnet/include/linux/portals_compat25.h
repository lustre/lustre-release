/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _KERNEL_COMPAT_H
#define _KERNEL_COMPAT_H


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)

#define SIGNAL_MASK_LOCK(task, flags)         \
        spin_lock_irqsave( &task->sighand->siglock, flags)
#define SIGNAL_MASK_UNLOCK(task, flags)       \
        spin_unlock_irqrestore(&task->sighand->siglock, flags)
#define USERMODEHELPER(path, argv, envp)       \
        call_usermodehelper(path, argv, envp, 1)
#define RECALC_SIGPENDING       recalc_sigpending()
#define CURRENT_SECONDS         get_seconds()

#else 
        /* 2.4.. */

#define SIGNAL_MASK_LOCK(task, flags)         \
        spin_lock_irqsave(&task->sigmask_lock, flags)
#define SIGNAL_MASK_UNLOCK(task, flags)       \
        spin_unlock_irqrestore(&task->sigmask_lock, flags)
#define USERMODEHELPER(path, argv, envp)       \
        call_usermodehelper(path, argv, envp)
#define RECALC_SIGPENDING         recalc_sigpending(current)
#define CURRENT_SECONDS         CURRENT_TIME

#endif

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20))
# define THREAD_NAME(comm, fmt, a...)					\
	sprintf(comm, fmt "|%d", ## a, current->thread.extern_pid)
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
# define THREAD_NAME(comm, fmt, a...)					\
        sprintf(comm, fmt "|%d", ## a, current->thread.mode.tt.extern_pid)
#else
# define THREAD_NAME(comm, fmt, a...)                                   \
	sprintf(comm, fmt, ## a)
#endif

#endif /* _KERNEL_COMPAT_H */
