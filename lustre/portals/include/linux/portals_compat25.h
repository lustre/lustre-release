/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _PORTALS_COMPAT_H
#define _PORTALS_COMPAT_H

// XXX BUG 1511 -- remove this stanza and all callers when bug 1511 is resolved
#if SPINLOCK_DEBUG
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)) || defined(CONFIG_RH_2_4_20)
#  define SIGNAL_MASK_ASSERT() \
   LASSERT(current->sighand->siglock.magic == SPINLOCK_MAGIC)
# else
#  define SIGNAL_MASK_ASSERT() \
   LASSERT(current->sigmask_lock.magic == SPINLOCK_MAGIC)
# endif
#else
# define SIGNAL_MASK_ASSERT()
#endif
// XXX BUG 1511 -- remove this stanza and all callers when bug 1511 is resolved

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))

# define SIGNAL_MASK_LOCK(task, flags)                                  \
  spin_lock_irqsave(&task->sighand->siglock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)                                \
  spin_unlock_irqrestore(&task->sighand->siglock, flags)
# define USERMODEHELPER(path, argv, envp)                               \
  call_usermodehelper(path, argv, envp, 1)
# define RECALC_SIGPENDING         recalc_sigpending()
# define CURRENT_SECONDS           get_seconds()

#elif defined(CONFIG_RH_2_4_20) /* RH 2.4.x */

# define SIGNAL_MASK_LOCK(task, flags)                                  \
  spin_lock_irqsave(&task->sighand->siglock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)                                \
  spin_unlock_irqrestore(&task->sighand->siglock, flags)
# define USERMODEHELPER(path, argv, envp)                               \
  call_usermodehelper(path, argv, envp)
# define RECALC_SIGPENDING         recalc_sigpending()
# define CURRENT_SECONDS           CURRENT_TIME

# define kernel_text_address(addr) is_kernel_text_address(addr)
extern int is_kernel_text_address(unsigned long addr);

#else /* 2.4.x */

# define SIGNAL_MASK_LOCK(task, flags)                                  \
  spin_lock_irqsave(&task->sigmask_lock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)                                \
  spin_unlock_irqrestore(&task->sigmask_lock, flags)
# define USERMODEHELPER(path, argv, envp)                               \
  call_usermodehelper(path, argv, envp)
# define RECALC_SIGPENDING         recalc_sigpending(current)
# define CURRENT_SECONDS           CURRENT_TIME

# define kernel_text_address(addr) is_kernel_text_address(addr)
extern int is_kernel_text_address(unsigned long addr);

#endif

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20))
# define THREAD_NAME(comm, fmt, a...)                                   \
        sprintf(comm, fmt "|%d", ## a, current->thread.extern_pid)
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
# define THREAD_NAME(comm, fmt, a...)                                   \
        sprintf(comm, fmt "|%d", ## a, current->thread.mode.tt.extern_pid)
#else
# define THREAD_NAME(comm, fmt, a...)                                   \
        sprintf(comm, fmt, ## a)
#endif

#ifdef HAVE_PAGE_LIST
/* 2.4 alloc_page users can use page->list */
#define PAGE_LIST_ENTRY list
#define PAGE_LIST(page) ((page)->list)
#else
/* 2.6 alloc_page users can use page->lru */
#define PAGE_LIST_ENTRY lru
#define PAGE_LIST(page) ((page)->lru)
#endif

#endif /* _PORTALS_COMPAT_H */
