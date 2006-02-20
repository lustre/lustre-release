#define DEBUG_SUBSYSTEM S_LNET
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <libcfs/libcfs.h>

void cfs_enter_debugger(void)
{
#if defined(CONFIG_KGDB)
	extern void breakpoint(void);
	breakpoint();
#elif defined(__arch_um__)
        asm("int $3");
#else
        /* nothing */
#endif
}

void cfs_daemonize(char *str) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,63))
	daemonize(str);
#else
	daemonize();
	snprintf (current->comm, sizeof (current->comm), "%s", str);
#endif
}

sigset_t
cfs_get_blockedsigs(void)
{
	unsigned long  	flags; 
	sigset_t	old;
	
	SIGNAL_MASK_LOCK(current, flags);
	old = current->blocked;
	SIGNAL_MASK_UNLOCK(current, flags);
	return old;
}

sigset_t
cfs_block_allsigs(void)
{
	unsigned long  	flags; 
	sigset_t	old;
	
	SIGNAL_MASK_LOCK(current, flags);
	old = current->blocked;
	sigfillset(&current->blocked);
	RECALC_SIGPENDING;
	SIGNAL_MASK_UNLOCK(current, flags);

	return old;
}

sigset_t
cfs_block_sigs(sigset_t bits)
{
	unsigned long  flags;
	sigset_t	old;

	SIGNAL_MASK_LOCK(current, flags);
	old = current->blocked;
	current->blocked = bits;
	RECALC_SIGPENDING;
	SIGNAL_MASK_UNLOCK(current, flags);
	return old;
}

void
cfs_restore_sigs (cfs_sigset_t old)
{
	unsigned long  flags;

	SIGNAL_MASK_LOCK(current, flags);
	current->blocked = old;
	RECALC_SIGPENDING;
	SIGNAL_MASK_UNLOCK(current, flags);
}

int
cfs_signal_pending(void)
{
	return signal_pending(current);
}

void
cfs_clear_sigpending(void)
{
	unsigned long flags;

	SIGNAL_MASK_LOCK(current, flags);
	CLEAR_SIGPENDING;
	SIGNAL_MASK_UNLOCK(current, flags);
}

int
libcfs_arch_init(void)
{
	return 0;
}

void
libcfs_arch_cleanup(void)
{
	return;
}

EXPORT_SYMBOL(libcfs_arch_init);
EXPORT_SYMBOL(libcfs_arch_cleanup);
EXPORT_SYMBOL(cfs_daemonize);
EXPORT_SYMBOL(cfs_block_allsigs);
EXPORT_SYMBOL(cfs_block_sigs);
EXPORT_SYMBOL(cfs_get_blockedsigs);
EXPORT_SYMBOL(cfs_restore_sigs);
EXPORT_SYMBOL(cfs_signal_pending);
EXPORT_SYMBOL(cfs_clear_sigpending);
