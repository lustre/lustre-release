#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)) || defined(CONFIG_RH_2_4_20)
# define SIGNAL_MASK_LOCK(task, flags)                              \
  spin_lock_irqsave(&task->sighand->siglock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)                            \
  spin_unlock_irqrestore(&task->sighand->siglock, flags)
# define RECALC_SIGPENDING         recalc_sigpending()
#else
# define SIGNAL_MASK_LOCK(task, flags)                              \
  spin_lock_irqsave(&task->sigmask_lock, flags)
# define SIGNAL_MASK_UNLOCK(task, flags)                            \
  spin_unlock_irqrestore(&task->sigmask_lock, flags)
# define RECALC_SIGPENDING         recalc_sigpending(current)
#endif
