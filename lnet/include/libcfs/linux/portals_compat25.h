/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LIBCFS_LINUX_PORTALS_COMPAT_H__
#define __LIBCFS_LINUX_PORTALS_COMPAT_H__

// XXX BUG 1511 -- remove this stanza and all callers when bug 1511 is resolved
#if defined(SPINLOCK_DEBUG) && SPINLOCK_DEBUG
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
# define CLEAR_SIGPENDING          clear_tsk_thread_flag(current,       \
                                                         TIF_SIGPENDING)
# define CURRENT_SECONDS           get_seconds()
# define smp_num_cpus              num_online_cpus()


#elif defined(CONFIG_RH_2_4_20) /* RH 2.4.x */

# define SIGNAL_MASK_LOCK(task, flags)                                  \
  spin_lock_irqsave(&task->sighand->siglock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)                                \
  spin_unlock_irqrestore(&task->sighand->siglock, flags)
# define USERMODEHELPER(path, argv, envp)                               \
  call_usermodehelper(path, argv, envp)
# define RECALC_SIGPENDING         recalc_sigpending()
# define CLEAR_SIGPENDING          (current->sigpending = 0)
# define CURRENT_SECONDS           CURRENT_TIME
# define wait_event_interruptible_exclusive(wq, condition)              \
        wait_event_interruptible(wq, condition)

#else /* 2.4.x */

# define SIGNAL_MASK_LOCK(task, flags)                                  \
  spin_lock_irqsave(&task->sigmask_lock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)                                \
  spin_unlock_irqrestore(&task->sigmask_lock, flags)
# define USERMODEHELPER(path, argv, envp)                               \
  call_usermodehelper(path, argv, envp)
# define RECALC_SIGPENDING         recalc_sigpending(current)
# define CLEAR_SIGPENDING          (current->sigpending = 0)
# define CURRENT_SECONDS           CURRENT_TIME
# define wait_event_interruptible_exclusive(wq, condition)              \
        wait_event_interruptible(wq, condition)

#endif

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20))
#define UML_PID(tsk) ((tsk)->thread.extern_pid)
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define UML_PID(tsk) ((tsk)->thread.mode.tt.extern_pid)
#else
#define UML_PID(tsk) ((tsk)->pid)
#endif

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
# define THREAD_NAME(comm, len, fmt, a...)                              \
        snprintf(comm, len,fmt"|%d", ## a, UML_PID(current))
#else
# define THREAD_NAME(comm, len, fmt, a...)                              \
        snprintf(comm, len, fmt, ## a)
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

#ifndef HAVE_CPU_ONLINE
#define cpu_online(cpu) ((1<<cpu) & (cpu_online_map))
#endif
#ifndef HAVE_CPUMASK_T
typedef unsigned long cpumask_t;
#define cpu_set(cpu, map) set_bit(cpu, &(map))
#define cpus_clear(map) memset(&(map), 0, sizeof(cpumask_t))
#endif

#ifndef __user
#define __user
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#define ll_proc_dointvec(table, write, filp, buffer, lenp, ppos)        \
        proc_dointvec(table, write, filp, buffer, lenp)
#define ll_proc_dostring(table, write, filp, buffer, lenp, ppos)        \
        proc_dostring(table, write, filp, buffer, lenp)
#define LL_PROC_PROTO(name)                                             \
        name(ctl_table *table, int write, struct file *filp,            \
             void __user *buffer, size_t *lenp)
#else
#define ll_proc_dointvec(table, write, filp, buffer, lenp, ppos)        \
        proc_dointvec(table, write, filp, buffer, lenp, ppos);
#define ll_proc_dostring(table, write, filp, buffer, lenp, ppos)        \
        proc_dostring(table, write, filp, buffer, lenp, ppos);
#define LL_PROC_PROTO(name)                                             \
        name(ctl_table *table, int write, struct file *filp,            \
             void __user *buffer, size_t *lenp, loff_t *ppos)
#endif

#endif /* _PORTALS_COMPAT_H */
