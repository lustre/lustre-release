#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)) || defined(CONFIG_RH_2_4_20)
# define SIGNAL_MASK_LOCK(task, flags)					\
  spin_lock_irqsave(&task->sighand->siglock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)				\
  spin_unlock_irqrestore(&task->sighand->siglock, flags)
# define RECALC_SIGPENDING         recalc_sigpending()
#else
# define SIGNAL_MASK_LOCK(task, flags)					\
  spin_lock_irqsave(&task->sigmask_lock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)				\
  spin_unlock_irqrestore(&task->sigmask_lock, flags)
# define RECALC_SIGPENDING         recalc_sigpending(current)
#endif

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20))
# define THREAD_NAME(comm, fmt, a...)					\
	sprintf(comm, fmt "|%d", ## a, current->thread.extern_pid)
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
# define THREAD_NAME(comm, fmt, a...)					\
        sprintf(comm, fmt "|%d", ## a, current->thread.mode.tt.extern_pid)
#else
# define THREAD_NAME(comm, fmt, a...) strcpy(comm, base, ## a)
#endif
