#ifndef __LIBCFS_DARWIN_CFS_PRIM_H__
#define __LIBCFS_DARWIN_CFS_PRIM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__
#include <sys/types.h>
#include <sys/systm.h>

#ifndef __APPLE_API_PRIVATE
#define __APPLE_API_PRIVATE
#include <sys/user.h>
#undef __APPLE_API_PRIVATE
#else
#include <sys/user.h>
#endif

#include <sys/kernel.h>

#include <mach/thread_act.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/thread_switch.h>
#include <mach/time_value.h>
#include <kern/sched_prim.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <mach/machine/vm_param.h>
#include <machine/machine_routines.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <sys/param.h>
#include <sys/vm.h>

#include <libcfs/darwin/darwin-types.h>
#include <libcfs/darwin/darwin-utils.h>
#include <libcfs/darwin/darwin-lock.h>

/*
 * Symbol functions for libcfs
 *
 * OSX has no facility for use to register symbol.
 * So we have to implement it.
 */
#define CFS_SYMBOL_LEN     64

struct  cfs_symbol {
	char    name[CFS_SYMBOL_LEN];
	void    *value;
	int     ref;
	struct  list_head sym_list;
};

extern kern_return_t            cfs_symbol_register(const char *, const void *);
extern kern_return_t            cfs_symbol_unregister(const char *);
extern void *                   cfs_symbol_get(const char *);
extern kern_return_t            cfs_symbol_put(const char *);

/*
 * sysctl typedef
 *
 * User can register/unregister a list of sysctl_oids
 * sysctl_oid is data struct of osx's sysctl-entry
 */
#define 	CONFIG_SYSCTL	1

typedef struct sysctl_oid *     cfs_sysctl_table_t;
typedef cfs_sysctl_table_t      cfs_sysctl_table_header_t;
cfs_sysctl_table_header_t	*cfs_register_sysctl_table (cfs_sysctl_table_t *table, int arg);
void cfs_unregister_sysctl_table (cfs_sysctl_table_header_t *table);

/*
 * Proc file system APIs, no /proc fs support in OSX
 */
typedef struct cfs_proc_dir_entry{
	void		*data;
}cfs_proc_dir_entry_t;

cfs_proc_dir_entry_t * cfs_create_proc_entry(char *name, int mod,
					  cfs_proc_dir_entry_t *parent);
void cfs_free_proc_entry(cfs_proc_dir_entry_t *de);
void cfs_remove_proc_entry(char *name, cfs_proc_dir_entry_t *entry);

typedef int (cfs_read_proc_t)(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
typedef int (cfs_write_proc_t)(struct file *file, const char *buffer,
			   unsigned long count, void *data);

/*
 * cfs pseudo device
 *
 * cfs_psdev_t
 * cfs_psdev_register:
 * cfs_psdev_deregister:
 */
typedef struct {
	int             index;
	void            *handle;
	const char      *name;
	struct cdevsw   *devsw;
	void            *private;
} cfs_psdev_t;

extern kern_return_t            cfs_psdev_register(cfs_psdev_t *);
extern kern_return_t            cfs_psdev_deregister(cfs_psdev_t *);

/*
 * Task struct and ...
 *
 * Using BSD current_proc in Darwin
 */
extern boolean_t        assert_wait_possible(void);
extern void             *get_bsdtask_info(task_t);

typedef struct uthread		cfs_task_t;
#define current_uthread()       ((struct uthread *)get_bsdthread_info(current_act()))
#define cfs_current()		current_uthread()
#define cfs_task_lock(t)	do {;} while (0)
#define cfs_task_unlock(t)	do {;} while (0)

#define set_current_state(s)	do {;} while (0)
#define reparent_to_init()	do {;} while (0)

#define CFS_DECL_JOURNAL_DATA	
#define CFS_PUSH_JOURNAL	do {;} while(0)
#define CFS_POP_JOURNAL		do {;} while(0)

#define THREAD_NAME(comm, fmt, a...)
/*
 * Kernel thread:
 *
 * OSX kernel thread can not be created with args,
 * so we have to implement new APIs to create thread with args
 *
 * All requests to create kernel thread will create a new
 * thread instance of cfs_thread_agent, one by one.
 * cfs_thread_agent will call the caller's thread function
 * with argument supplied by caller.
 */

typedef int (*cfs_thread_t)(void *);

extern task_t	kernel_task;

struct kernel_thread_arg
{
	spinlock_t	lock;
	atomic_t	inuse;
	cfs_thread_t	func;
	void		*arg;
};

extern struct kernel_thread_arg cfs_thread_arg;
extern void cfs_thread_agent(void);

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

/*
 * cloning flags, no use in OSX, just copy them from Linux
 */
#define CSIGNAL         0x000000ff      /* signal mask to be sent at exit */
#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers and blocked signals shared */
#define CLONE_PID       0x00001000      /* set if pid shared */
#define CLONE_PTRACE    0x00002000      /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK     0x00004000      /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT    0x00008000      /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD    0x00010000      /* Same thread group? */
#define CLONE_NEWNS     0x00020000      /* New namespace group? */

#define CLONE_SIGNAL    (CLONE_SIGHAND | CLONE_THREAD)

extern int cfs_kernel_thread(cfs_thread_t func, void *arg, int flag);


/*
 * Wait Queue implementation
 *
 * Like wait_queue in Linux
 */
typedef struct cfs_waitq {
	struct ksleep_chan wq_ksleep_chan;
} cfs_waitq_t;

typedef struct cfs_waitlink {
	struct cfs_waitq   *wl_waitq;
	struct ksleep_link  wl_ksleep_link;
} cfs_waitlink_t;

typedef int cfs_task_state_t;

#define CFS_TASK_INTERRUPTIBLE	THREAD_INTERRUPTIBLE
#define CFS_TASK_UNINT		THREAD_UNINT

void cfs_waitq_init(struct cfs_waitq *waitq);
void cfs_waitlink_init(struct cfs_waitlink *link);

void cfs_waitq_add(struct cfs_waitq *waitq, struct cfs_waitlink *link);
void cfs_waitq_add_exclusive(struct cfs_waitq *waitq,
			     struct cfs_waitlink *link);
void cfs_waitq_forward(struct cfs_waitlink *link, struct cfs_waitq *waitq);
void cfs_waitq_del(struct cfs_waitq *waitq, struct cfs_waitlink *link);
int  cfs_waitq_active(struct cfs_waitq *waitq);

void cfs_waitq_signal(struct cfs_waitq *waitq);
void cfs_waitq_signal_nr(struct cfs_waitq *waitq, int nr);
void cfs_waitq_broadcast(struct cfs_waitq *waitq);

void cfs_waitq_wait(struct cfs_waitlink *link, cfs_task_state_t state);
cfs_duration_t cfs_waitq_timedwait(struct cfs_waitlink *link,
				   cfs_task_state_t state, 
				   cfs_duration_t timeout);

/*
 * Thread schedule APIs.
 */
#define MAX_SCHEDULE_TIMEOUT    ((long)(~0UL>>12))

static inline int cfs_schedule_timeout(int state, int64_t timeout)
{
	int          result;
	
	AbsoluteTime clock_current;
	AbsoluteTime clock_delay;
	result = assert_wait((event_t)current_uthread(), state);
	if (timeout > 0) {
		clock_get_uptime(&clock_current);
		nanoseconds_to_absolutetime(timeout, &clock_delay);
		ADD_ABSOLUTETIME(&clock_current, &clock_delay);
		thread_set_timer_deadline(clock_current);
	}
	if (result == THREAD_WAITING)
		result = thread_block(THREAD_CONTINUE_NULL);
	if (timeout > 0)
		thread_cancel_timer();
	if (result == THREAD_TIMED_OUT)
		result = 0;
	else
		result = 1;
	return result;
}

#define cfs_schedule()	cfs_schedule_timeout(CFS_TASK_UNINT, CFS_MIN_DELAY)
#define cfs_pause(tick)	cfs_schedule_timeout(CFS_TASK_UNINT, tick)

#define __wait_event(wq, condition)				\
do {								\
	struct cfs_waitlink __wait;				\
								\
	cfs_waitlink_init(&__wait);				\
	for (;;) {						\
		cfs_waitq_add(&wq, &__wait);			\
		if (condition)					\
			break;					\
		cfs_waitq_wait(&__wait, CFS_TASK_UNINT);	\
		cfs_waitq_del(&wq, &__wait);			\
	}							\
	cfs_waitq_del(&wq, &__wait);				\
} while (0)

#define wait_event(wq, condition) 				\
do {								\
	if (condition)	 					\
		break;						\
	__wait_event(wq, condition);				\
} while (0)

#define __wait_event_interruptible(wq, condition, ret)		\
do {								\
	struct cfs_waitlink __wait;				\
								\
	cfs_waitlink_init(&__wait);				\
	for (;;) {						\
		cfs_waitq_add(&wq, &__wait);			\
		if (condition)					\
			break;					\
		if (!cfs_signal_pending(cfs_current())) {	\
			cfs_waitq_wait(&__wait, 		\
				       CFS_TASK_INTERRUPTIBLE);	\
			cfs_waitq_del(&wq, &__wait);		\
			continue;				\
		}						\
		ret = -ERESTARTSYS;				\
		break;						\
	}							\
	cfs_waitq_del(&wq, &__wait);				\
} while (0)

#define wait_event_interruptible(wq, condition)			\
({								\
 	int __ret = 0;						\
 	if (!condition)						\
		__wait_event_interruptible(wq, 			\
			                   condition, __ret);	\
	__ret;							\
})

extern void	wakeup_one __P((void * chan));
/* only used in tests */
#define wake_up_process(p)			\
	do {					\
		wakeup_one(p);			\
	} while (0)
	
/* used in couple of places */
static inline void sleep_on(cfs_waitq_t *waitq)
{
	cfs_waitlink_t link;
	
	cfs_waitlink_init(&link);
	cfs_waitq_add(waitq, &link);
	cfs_waitq_wait(&link, CFS_TASK_UNINT);
	cfs_waitq_del(waitq, &link);
}

/*
 * Signal
 * We don't use signal_lock/signal_unlock in cfs_sigmask_lock()
 * and cfs_sigmask_unlock() because they will be called in 
 * signal kernel APIs by xnu.
 */
typedef sigset_t	cfs_sigset_t;
#define cfs_sigmask_lock(t, f)		do { f = 0; } while (0)
#define cfs_sigmask_unlock(t, f)	do { f = 0; } while (0)
#define cfs_signal_pending(ut)		SHOULDissignal(current_proc(), ut)

/*
 * We don't need to recalc_sigpending because xnu always
 * call SHOULDissignal to checking if there are pending signals.
 */
#define cfs_recalc_sigpending(ut)	do {} while (0)
/*
 * Clear all pending signals.
 */
#define cfs_clear_sigpending(ut)	clear_procsiglist(current_proc(), -1)

#define SIGNAL_MASK_ASSERT()

/*
 * Timer
 */

typedef struct cfs_timer {
	struct ktimer t;
} cfs_timer_t;

#define cfs_init_timer(t)	do {} while(0)
void cfs_timer_init(struct cfs_timer *t, void (*func)(unsigned long), void *arg);
void cfs_timer_done(struct cfs_timer *t);
void cfs_timer_arm(struct cfs_timer *t, cfs_time_t deadline);
void cfs_timer_disarm(struct cfs_timer *t);
int  cfs_timer_is_armed(struct cfs_timer *t);

cfs_time_t cfs_timer_deadline(struct cfs_timer *t);

/*
 * Ioctl
 * We don't need to copy out everything in osx
 */
#define cfs_ioctl_data_out(a, d, l)			\
	({						\
		int __size;				\
		int __rc = 0;				\
		assert((l) >= sizeof(*d));		\
		__size = (l) - sizeof(*d);		\
		if (__size > 0)				\
			__rc = copy_to_user((void *)a + __size,	\
			     (void *)d + __size,	\
			     __size);			\
		__rc;					\
	})

/*
 * CPU
 */
#include <machine/cpu_number.h>
/* Run in PowerG5 who is PPC64 */
#define SMP_CACHE_BYTES                         128
#define __cacheline_aligned                     __attribute__((__aligned__(SMP_CACHE_BYTES)))
/* XXX How to get the value of NCPUS from xnu ? */
#define NR_CPUS					2
#define smp_processor_id()			cpu_number()
#define smp_num_cpus				NR_CPUS
/* XXX smp_call_function is not supported in xnu */
#define smp_call_function(f, a, n, w)		do {} while(0)
int cfs_online_cpus(void);

/*
 * Misc
 */
#ifndef likely
#define likely(exp) (exp)
#endif
#ifndef unlikely
#define unlikely(exp) (exp)
#endif

#define lock_kernel()				do {} while(0)
#define unlock_kernel()				do {} while(0)

#define exit_mm(t)				do {} while(0)
#define exit_files(t)				do {} while(0)

#define CAP_SYS_ADMIN                           0
#define capable(a)		suser(current_proc()->p_ucred, &(current_proc()->p_acflag))

#define USERMODEHELPER(path, argv, envp)	(0)

#define cfs_module(name, version, init, fini)				\
extern kern_return_t _start(kmod_info_t *ki, void *data);		\
extern kern_return_t _stop(kmod_info_t *ki, void *data);		\
__private_extern__ kern_return_t name##_start(kmod_info_t *ki, void *data); \
__private_extern__ kern_return_t name##_stop(kmod_info_t *ki, void *data); \
									\
kmod_info_t KMOD_INFO_NAME = { 0, KMOD_INFO_VERSION, -1,		\
                               { "com.clusterfs.lustre." #name }, { version }, \
                               -1, 0, 0, 0, 0, name##_start, name##_stop }; \
									\
__private_extern__ kmod_start_func_t *_realmain = name##_start;		\
__private_extern__ kmod_stop_func_t *_antimain = name##_stop;		\
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;			\
									\
kern_return_t name##_start(kmod_info_t *ki, void *d)			\
{									\
	return init();							\
}									\
									\
kern_return_t name##_stop(kmod_info_t *ki, void *d)			\
{									\
        fini();								\
        return KERN_SUCCESS;						\
}									\
									\
/*									\
 * to allow semicolon after cfs_module(...)				\
 */									\
struct __dummy_ ## name ## _struct {}

#define inter_module_get(n)			cfs_symbol_get(n)
#define inter_module_put(n)			cfs_symbol_put(n)

static inline int request_module(char *name)
{
	return (-EINVAL);
}

#ifndef __exit
#define __exit
#endif
#ifndef __init
#define __init
#endif

#define EXPORT_SYMBOL(s)
#define MODULE_AUTHOR(s)
#define MODULE_DESCRIPTION(s)
#define MODULE_LICENSE(s)
#define MODULE_PARM(a, b)
#define MODULE_PARM_DESC(a, b)

#define KERNEL_VERSION(a,b,c) ((a)*100+(b)*10+c)
#define LINUX_VERSION_CODE KERNEL_VERSION(2,5,0)

#define NR_IRQS				512
#define in_interrupt()			ml_at_interrupt_context()

#define KERN_EMERG      "<0>"   /* system is unusable                   */
#define KERN_ALERT      "<1>"   /* action must be taken immediately     */
#define KERN_CRIT       "<2>"   /* critical conditions                  */
#define KERN_ERR        "<3>"   /* error conditions                     */
#define KERN_WARNING    "<4>"   /* warning conditions                   */
#define KERN_NOTICE     "<5>"   /* normal but significant condition     */
#define KERN_INFO       "<6>"   /* informational                        */
#define KERN_DEBUG      "<7>"   /* debug-level messages                 */

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

#define ERR_PTR(err)	((void *)err)

/* XXX */
#define IS_ERR(p)	(0)

#else	/* !__KERNEL__ */

typedef struct cfs_proc_dir_entry{
	void		*data;
}cfs_proc_dir_entry_t;

#include <libcfs/user-prim.h>
#define __WORDSIZE	32

#endif	/* END __KERNEL__ */
/*
 * Error number
 */
#define EPROTO          EPROTOTYPE
#define EBADR		EBADRPC
#define ERESTARTSYS	512
#define EDEADLOCK	EDEADLK
#define ECOMM		EINVAL
#define ENODATA		EINVAL

#if BYTE_ORDER == BIG_ENDIAN
# define __BIG_ENDIAN
#else
# define __LITTLE_ENDIAN
#endif

#endif	/* __LIBCFS_DARWIN_CFS_PRIM_H__ */
