#
# LN_CONFIG_CDEBUG
#
# whether to enable various libcfs debugs (CDEBUG, ENTRY/EXIT, LASSERT, etc.)
#
AC_DEFUN([LN_CONFIG_CDEBUG],
[
AC_MSG_CHECKING([whether to enable CDEBUG, CWARN])
AC_ARG_ENABLE([libcfs_cdebug],
	AC_HELP_STRING([--disable-libcfs-cdebug],
			[disable libcfs CDEBUG, CWARN]),
	[],[enable_libcfs_cdebug='yes'])
AC_MSG_RESULT([$enable_libcfs_cdebug])
if test x$enable_libcfs_cdebug = xyes; then
   AC_DEFINE(CDEBUG_ENABLED, 1, [enable libcfs CDEBUG, CWARN])
else
   AC_DEFINE(CDEBUG_ENABLED, 0, [disable libcfs CDEBUG, CWARN])
fi

AC_MSG_CHECKING([whether to enable ENTRY/EXIT])
AC_ARG_ENABLE([libcfs_trace],
	AC_HELP_STRING([--disable-libcfs-trace],
			[disable libcfs ENTRY/EXIT]),
	[],[enable_libcfs_trace='yes'])
AC_MSG_RESULT([$enable_libcfs_trace])
if test x$enable_libcfs_trace = xyes; then
   AC_DEFINE(CDEBUG_ENTRY_EXIT, 1, [enable libcfs ENTRY/EXIT])
else
   AC_DEFINE(CDEBUG_ENTRY_EXIT, 0, [disable libcfs ENTRY/EXIT])
fi

AC_MSG_CHECKING([whether to enable LASSERT, LASSERTF])
AC_ARG_ENABLE([libcfs_assert],
	AC_HELP_STRING([--disable-libcfs-assert],
			[disable libcfs LASSERT, LASSERTF]),
	[],[enable_libcfs_assert='yes'])
AC_MSG_RESULT([$enable_libcfs_assert])
if test x$enable_libcfs_assert = xyes; then
   AC_DEFINE(LIBCFS_DEBUG, 1, [enable libcfs LASSERT, LASSERTF])
fi
])

#
# LIBCFS_CONFIG_PANIC_DUMPLOG
#
# check if tunable panic_dumplog is wanted
#
AC_DEFUN([LIBCFS_CONFIG_PANIC_DUMPLOG],
[AC_MSG_CHECKING([for tunable panic_dumplog support])
AC_ARG_ENABLE([panic_dumplog],
       AC_HELP_STRING([--enable-panic_dumplog],
                      [enable panic_dumplog]),
       [],[enable_panic_dumplog='no'])
if test x$enable_panic_dumplog = xyes ; then
       AC_DEFINE(LNET_DUMP_ON_PANIC, 1, [use dumplog on panic])
       AC_MSG_RESULT([yes (by request)])
else
       AC_MSG_RESULT([no])
fi
])

#
# LIBCFS_FUNC_CPU_ONLINE
#
# cpu_online is different in rh 2.4, vanilla 2.4, and 2.6
#
AC_DEFUN([LIBCFS_FUNC_CPU_ONLINE],
[AC_MSG_CHECKING([if kernel defines cpu_online()])
LB_LINUX_TRY_COMPILE([
       #include <linux/sched.h>
],[
       cpu_online(0);
],[
       AC_MSG_RESULT([yes])
       AC_DEFINE(HAVE_CPU_ONLINE, 1, [cpu_online found])
],[
       AC_MSG_RESULT([no])
])
])

#
# LIBCFS_TYPE_GFP_T
#
# check if gfp_t is typedef-ed
#
AC_DEFUN([LIBCFS_TYPE_GFP_T],
[AC_MSG_CHECKING([if kernel defines gfp_t])
LB_LINUX_TRY_COMPILE([
        #include <linux/gfp.h>
],[
	return sizeof(gfp_t);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_GFP_T, 1, [gfp_t found])
],[
	AC_MSG_RESULT([no])
])
])

#
# LIBCFS_FUNC_SHOW_TASK
#
# we export show_task(), but not all kernels have it (yet)
#
AC_DEFUN([LIBCFS_FUNC_SHOW_TASK],
[LB_CHECK_SYMBOL_EXPORT([show_task],
[kernel/ksyms.c kernel/sched.c],[
AC_DEFINE(HAVE_SHOW_TASK, 1, [show_task is exported])
],[
        LB_CHECK_SYMBOL_EXPORT([sched_show_task],
        [kernel/ksyms.c kernel/sched.c],[
        AC_DEFINE(HAVE_SCHED_SHOW_TASK, 1, [sched_show_task is exported])
        ],[])
])
])

# check kernel __u64 type
AC_DEFUN([LIBCFS_U64_LONG_LONG_LINUX],
[
AC_MSG_CHECKING([kernel __u64 is long long type])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/types.h>
	#include <linux/stddef.h>
],[
	unsigned long long *data;

	data = (__u64*)sizeof(data);
],[
	AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_KERN__U64_LONG_LONG, 1,
                  [kernel __u64 is long long type])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

# check if task_struct with rcu memeber
AC_DEFUN([LIBCFS_TASK_RCU],
[AC_MSG_CHECKING([if task_struct has a rcu field])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
        memset(((struct task_struct *)0)->rcu.next, 0, 0);
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_TASK_RCU, 1, [task_struct has rcu field])
],[
        AC_MSG_RESULT([no])
])
])

# LIBCFS_TASKLIST_LOCK
# 2.6.18 remove tasklist_lock export
AC_DEFUN([LIBCFS_TASKLIST_LOCK],
[LB_CHECK_SYMBOL_EXPORT([tasklist_lock],
[kernel/fork.c],[
AC_DEFINE(HAVE_TASKLIST_LOCK, 1,
         [tasklist_lock exported])
],[
])
])

# 2.6.19 API changes
# kmem_cache_destroy(cachep) return void instead of
# int
AC_DEFUN([LIBCFS_KMEM_CACHE_DESTROY_INT],
[AC_MSG_CHECKING([kmem_cache_destroy(cachep) return int])
LB_LINUX_TRY_COMPILE([
        #include <linux/slab.h>
],[
	int i = kmem_cache_destroy(NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_KMEM_CACHE_DESTROY_INT, 1,
                [kmem_cache_destroy(cachep) return int])
],[
        AC_MSG_RESULT(NO)
])
])

# 2.6.19 API change
#panic_notifier_list use atomic_notifier operations
#
AC_DEFUN([LIBCFS_ATOMIC_PANIC_NOTIFIER],
[AC_MSG_CHECKING([panic_notifier_list is atomic])
LB_LINUX_TRY_COMPILE([
	#include <linux/notifier.h>
	#include <linux/kernel.h>
],[
	struct atomic_notifier_head panic_notifier_list;
],[
        AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_ATOMIC_PANIC_NOTIFIER, 1,
		[panic_notifier_list is atomic_notifier_head])
],[
        AC_MSG_RESULT(NO)
])
])

# since 2.6.19 nlmsg_multicast() needs 5 argument.
AC_DEFUN([LIBCFS_NLMSG_MULTICAST],
[AC_MSG_CHECKING([nlmsg_multicast needs 5 argument])
LB_LINUX_TRY_COMPILE([
	#include <net/netlink.h>
],[
        nlmsg_multicast(NULL, NULL, 0, 0, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_NLMSG_MULTICAST_5ARGS, 1,
                  [nlmsg_multicast needs 5 argument])
],[
        AC_MSG_RESULT(NO)
])
])

#
# LIBCFS_NETLINK
#
# If we have netlink.h, and nlmsg_new takes 2 args (2.6.19)
#
AC_DEFUN([LIBCFS_NETLINK],
[AC_MSG_CHECKING([if netlink.h can be compiled])
LB_LINUX_TRY_COMPILE([
        #include <net/netlink.h>
],[],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_NETLINK, 1, [net/netlink.h found])

        AC_MSG_CHECKING([if nlmsg_new takes a 2nd argument])
        LB_LINUX_TRY_COMPILE([
                #include <net/netlink.h>
        ],[
                nlmsg_new(100, GFP_KERNEL);
        ],[
                AC_MSG_RESULT([yes])
                AC_DEFINE(HAVE_NETLINK_NL2, 1, [nlmsg_new takes 2 args])
        ],[
                AC_MSG_RESULT([no])
        ])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.20 API change INIT_WORK use 2 args and not
# store data inside
AC_DEFUN([LIBCFS_3ARGS_INIT_WORK],
[AC_MSG_CHECKING([check INIT_WORK want 3 args])
LB_LINUX_TRY_COMPILE([
	#include <linux/workqueue.h>
],[
	struct work_struct work;

	INIT_WORK(&work, NULL, NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_3ARGS_INIT_WORK, 1,
                  [INIT_WORK use 3 args and store data inside])
],[
        AC_MSG_RESULT(NO)
])
])

# 2.6.21 api change. 'register_sysctl_table' use only one argument,
# instead of more old which need two.
AC_DEFUN([LIBCFS_2ARGS_REGISTER_SYSCTL],
[AC_MSG_CHECKING([check register_sysctl_table want 2 args])
LB_LINUX_TRY_COMPILE([
        #include <linux/sysctl.h>
],[
	return register_sysctl_table(NULL,0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_2ARGS_REGISTER_SYSCTL, 1,
                  [register_sysctl_table want 2 args])
],[
        AC_MSG_RESULT(NO)
])
])

# 2.6.21 marks kmem_cache_t deprecated and uses struct kmem_cache
# instead
AC_DEFUN([LIBCFS_KMEM_CACHE],
[AC_MSG_CHECKING([check kernel has struct kmem_cache])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
        #include <linux/slab.h>
        typedef struct kmem_cache cache_t;
],[
	cache_t *cachep = NULL;

	kmem_cache_alloc(cachep, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_KMEM_CACHE, 1,
                  [kernel has struct kmem_cache])
],[
        AC_MSG_RESULT(NO)
])
EXTRA_KCFLAGS="$tmp_flags"
])

# 2.6.23 lost dtor argument
AC_DEFUN([LIBCFS_KMEM_CACHE_CREATE_DTOR],
[AC_MSG_CHECKING([check kmem_cache_create has dtor argument])
LB_LINUX_TRY_COMPILE([
        #include <linux/slab.h>
],[
	kmem_cache_create(NULL, 0, 0, 0, NULL, NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_KMEM_CACHE_CREATE_DTOR, 1,
                  [kmem_cache_create has dtor argument])
],[
        AC_MSG_RESULT(NO)
])
])

#2.6.23 has new shrinker API
AC_DEFUN([LC_REGISTER_SHRINKER],
[AC_MSG_CHECKING([if kernel has register_shrinker])
LB_LINUX_TRY_COMPILE([
        #include <linux/mm.h>
],[
        register_shrinker(NULL);
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_REGISTER_SHRINKER, 1,
                [kernel has register_shrinker])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.24 
AC_DEFUN([LIBCFS_NETLINK_CBMUTEX],
[AC_MSG_CHECKING([for mutex in netlink_kernel_create])
LB_LINUX_TRY_COMPILE([
        #include <linux/netlink.h>
],[
        struct mutex *lock = NULL;

        netlink_kernel_create(0, 0, NULL, lock, NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_NETLINK_CBMUTEX, 1,
                  [netlink_kernel_create want mutex for callback])
],[
        AC_MSG_RESULT(NO)
])
])

# 2.6.24 request not use real numbers for ctl_name
AC_DEFUN([LIBCFS_SYSCTL_UNNUMBERED],
[AC_MSG_CHECKING([for CTL_UNNUMBERED])
LB_LINUX_TRY_COMPILE([
        #include <linux/sysctl.h>
],[
	#ifndef CTL_UNNUMBERED
	#error CTL_UNNUMBERED not exist in kernel
	#endif
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SYSCTL_UNNUMBERED, 1,
                  [sysctl has CTL_UNNUMBERED])
],[
        AC_MSG_RESULT(NO)
])
])

# 2.6.24 lost scatterlist->page
AC_DEFUN([LIBCFS_SCATTERLIST_SETPAGE],
[AC_MSG_CHECKING([for exist sg_set_page])
LB_LINUX_TRY_COMPILE([
        #include <asm/types.h>
        #include <linux/scatterlist.h>
],[
	sg_set_page(NULL,NULL,0,0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SCATTERLIST_SETPAGE, 1,
                  [struct scatterlist has page member])
],[
        AC_MSG_RESULT(NO)
])
])

# 2.6.24 
AC_DEFUN([LIBCFS_NETWORK_NAMESPACE],
[AC_MSG_CHECKING([for network stack has namespaces])
LB_LINUX_TRY_COMPILE([
        #include <net/net_namespace.h>
],[
        struct net *net = &init_net;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_INIT_NET, 1,
                  [kernel is support network namespaces ])
],[
        AC_MSG_RESULT(NO)
])
])


# 2.6.24 
AC_DEFUN([LIBCFS_NETLINK_NETNS],
[AC_MSG_CHECKING([for netlink support net ns])
LB_LINUX_TRY_COMPILE([
        #include <linux/netlink.h>
],[
        struct net *net = NULL;
        struct mutex *lock = NULL;

        netlink_kernel_create(net, 0, 0, NULL,
                              lock,
                              NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_NETLINK_NS, 1,
                  [netlink is support network namespace])
# XXX
# for now - if kernel have netlink ns - he uses cbmutex
        AC_DEFINE(HAVE_NETLINK_CBMUTEX, 1,
                  [netlink_kernel_create want mutex for callback])

],[
        AC_MSG_RESULT(NO)
])
])

# ~2.6.24
AC_DEFUN([LIBCFS_NL_BROADCAST_GFP],
[AC_MSG_CHECKING([for netlink_broadcast is want to have gfp parameter])
LB_LINUX_TRY_COMPILE([
        #include <linux/netlink.h>
],[
	gfp_t gfp = GFP_KERNEL;

        netlink_broadcast(NULL, NULL, 0, 0, gfp);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_NL_BROADCAST_GFP, 1,
                  [netlink brouacast is want to have gfp paramter])
],[
        AC_MSG_RESULT(NO)
])
])

#
# LIBCFS_FUNC_DUMP_TRACE
#
# 2.6.23 exports dump_trace() so we can dump_stack() on any task
# 2.6.24 has stacktrace_ops.address with "reliable" parameter
#
AC_DEFUN([LIBCFS_FUNC_DUMP_TRACE],
[LB_CHECK_SYMBOL_EXPORT([dump_trace],
[kernel/ksyms.c arch/${LINUX_ARCH%_64}/kernel/traps_64.c arch/x86/kernel/dumpstack_32.c arch/x86/kernel/dumpstack_64.c],[
	tmp_flags="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="-Werror"
	AC_MSG_CHECKING([whether we can really use dump_trace])
	LB_LINUX_TRY_COMPILE([
		struct task_struct;
		struct pt_regs;
		#include <asm/stacktrace.h>
	],[
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_DUMP_TRACE, 1, [dump_trace is exported])
	],[
		AC_MSG_RESULT(no)
	],[
	])
	AC_MSG_CHECKING([whether print_trace_address has reliable argument])
	LB_LINUX_TRY_COMPILE([
		struct task_struct;
		struct pt_regs;
		#include <asm/stacktrace.h>
	],[
		((struct stacktrace_ops *)0)->address(NULL, 0, 0);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_TRACE_ADDRESS_RELIABLE, 1,
			  [print_trace_address has reliable argument])
	],[
		AC_MSG_RESULT(no)
	],[
	])
	AC_MSG_CHECKING([whether stacktrace_ops.warning is exist])
	LB_LINUX_TRY_COMPILE([
		struct task_struct;
		struct pt_regs;
		#include <asm/stacktrace.h>
	],[
		((struct stacktrace_ops *)0)->warning(NULL, NULL);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_STACKTRACE_WARNING, 1, [stacktrace_ops.warning is exist])
	],[
		AC_MSG_RESULT(no)
	],[
	])
	AC_MSG_CHECKING([dump_trace want address])
	LB_LINUX_TRY_COMPILE([
		struct task_struct;
		struct pt_regs;
		#include <asm/stacktrace.h>
	],[
		dump_trace(NULL, NULL, NULL, 0, NULL, NULL);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_DUMP_TRACE_ADDRESS, 1,
			  [dump_trace want address argument])
	],[
		AC_MSG_RESULT(no)
	],[
	])

EXTRA_KCFLAGS="$tmp_flags"
])
])


# 2.6.26 use int instead of atomic for sem.count
AC_DEFUN([LIBCFS_SEM_COUNT],
[AC_MSG_CHECKING([atomic sem.count])
LB_LINUX_TRY_COMPILE([
        #include <asm/semaphore.h>
],[
	struct semaphore s;
	
	atomic_read(&s.count);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SEM_COUNT_ATOMIC, 1,
                  [semaphore counter is atomic])
],[
        AC_MSG_RESULT(NO)
])
])

# 2.6.27 have second argument to sock_map_fd
AC_DEFUN([LIBCFS_SOCK_MAP_FD_2ARG],
[AC_MSG_CHECKING([sock_map_fd have second argument])
LB_LINUX_TRY_COMPILE([
	#include <linux/net.h>
],[
        sock_map_fd(NULL, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SOCK_MAP_FD_2ARG, 1,
                  [sock_map_fd have second argument])
],[
        AC_MSG_RESULT(NO)
])
])

# LIBCFS_CRED_WRAPPERS
#
# wrappers for task's credentials are in sles11
#
AC_DEFUN([LIBCFS_CRED_WRAPPERS],
[AC_MSG_CHECKING([if kernel has wrappers for task's credentials])
LB_LINUX_TRY_COMPILE([
       #include <linux/sched.h>
],[
       uid_t uid;

       uid = current_uid() + sizeof(uid);
],[
       AC_MSG_RESULT([yes])
       AC_DEFINE(HAVE_CRED_WRAPPERS, 1, [task's cred wrappers found])
],[
       AC_MSG_RESULT([no])
])
])

#
# LN_STRUCT_CRED_IN_TASK
#
# struct cred was introduced in 2.6.29 to streamline credentials in task struct
#
AC_DEFUN([LIBCFS_STRUCT_CRED_IN_TASK],
[AC_MSG_CHECKING([if kernel has struct cred])
LB_LINUX_TRY_COMPILE([
       #include <linux/sched.h>
],[
       struct task_struct *tsk = NULL;
       tsk->real_cred = NULL;
],[
       AC_MSG_RESULT([yes])
       AC_DEFINE(HAVE_STRUCT_CRED, 1, [struct cred found])
],[
       AC_MSG_RESULT([no])
])
])

#
# LIBCFS_FUNC_UNSHARE_FS_STRUCT
#
# unshare_fs_struct was introduced in 2.6.30 to prevent others to directly
# mess with copy_fs_struct
#
AC_DEFUN([LIBCFS_FUNC_UNSHARE_FS_STRUCT],
[AC_MSG_CHECKING([if kernel defines unshare_fs_struct()])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
       #include <linux/sched.h>
       #include <linux/fs_struct.h>
],[
       unshare_fs_struct();
],[
       AC_MSG_RESULT([yes])
       AC_DEFINE(HAVE_UNSHARE_FS_STRUCT, 1, [unshare_fs_struct found])
],[
       AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# LIBCFS_HAVE_IS_COMPAT_TASK
#
# Added in 2.6.17, it wasn't until 2.6.29 that all
# Linux architectures have is_compat_task()
#
AC_DEFUN([LIBCFS_HAVE_IS_COMPAT_TASK],
[AC_MSG_CHECKING([if is_compat_task() is declared])
LB_LINUX_TRY_COMPILE([
        #include <linux/compat.h>
],[
        int i = is_compat_task();
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_IS_COMPAT_TASK, 1, [is_compat_task() is available])
],[
        AC_MSG_RESULT([no])
])
])

#
# LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK
#
# 2.6.32-30.el6 adds a new 'walk_stack' field in 'struct stacktrace_ops'
#
AC_DEFUN([LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK],
[AC_MSG_CHECKING([if 'struct stacktrace_ops' has 'walk_stack' field])
LB_LINUX_TRY_COMPILE([
        #include <asm/stacktrace.h>
],[
        ((struct stacktrace_ops *)0)->walk_stack(NULL, NULL, 0, NULL, NULL, NULL, NULL);
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(STACKTRACE_OPS_HAVE_WALK_STACK, 1, ['struct stacktrace_ops' has 'walk_stack' field])
],[
        AC_MSG_RESULT([no])
])
])

AC_DEFUN([LIBCFS_HAVE_OOM_H],
[LB_CHECK_FILE([$LINUX/include/linux/oom.h], [
        AC_DEFINE(HAVE_LINUX_OOM_H, 1,
                [kernel has include/oom.h])
],[
        AC_MSG_RESULT([no])
])
])

#
# RHEL6/2.6.32 want to have pointer to shrinker self pointer in handler function
#
AC_DEFUN([LC_SHRINKER_WANT_SHRINK_PTR],
[AC_MSG_CHECKING([shrinker want self pointer in handler])
LB_LINUX_TRY_COMPILE([
        #include <linux/mm.h>
],[
        struct shrinker *tmp = NULL;
        tmp->shrink(tmp, 0, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SHRINKER_WANT_SHRINK_PTR, 1,
                  [shrinker want self pointer in handler])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.18 store oom parameters in task struct.
# 2.6.32 store oom parameters in signal struct
AC_DEFUN([LIBCFS_OOMADJ_IN_SIG],
[AC_MSG_CHECKING([kernel store oom parameters in task])
LB_LINUX_TRY_COMPILE([
        #include <linux/sched.h>
],[
        ((struct signal_struct *)0)->oom_adj = 0;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_OOMADJ_IN_SIG, 1,
                  [kernel store a oom parameters in signal struct])
],[
        AC_MSG_RESULT(no)
])
])

#
# 2.6.33 no longer has ctl_name & strategy field in struct ctl_table.
#
AC_DEFUN([LIBCFS_SYSCTL_CTLNAME],
[AC_MSG_CHECKING([if ctl_table has a ctl_name field])
LB_LINUX_TRY_COMPILE([
        #include <linux/sysctl.h>
],[
        struct ctl_table ct;
        ct.ctl_name = sizeof(ct);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SYSCTL_CTLNAME, 1,
                  [ctl_table has ctl_name field])
],[
        AC_MSG_RESULT(no)
])
])

#
# LIBCFS_ADD_WAIT_QUEUE_EXCLUSIVE
#
# 2.6.34 adds __add_wait_queue_exclusive
#
AC_DEFUN([LIBCFS_ADD_WAIT_QUEUE_EXCLUSIVE],
[AC_MSG_CHECKING([if __add_wait_queue_exclusive exists])
LB_LINUX_TRY_COMPILE([
        #include <linux/wait.h>
],[
        wait_queue_head_t queue;
        wait_queue_t      wait;

        __add_wait_queue_exclusive(&queue, &wait);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE___ADD_WAIT_QUEUE_EXCLUSIVE, 1,
                  [__add_wait_queue_exclusive exists])
],[
        AC_MSG_RESULT(no)
])
])

#
# 2.6.35 kernel has sk_sleep function
#
AC_DEFUN([LC_SK_SLEEP],
[AC_MSG_CHECKING([if kernel has sk_sleep])
LB_LINUX_TRY_COMPILE([
        #include <net/sock.h>
],[
        sk_sleep(NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SK_SLEEP, 1, [kernel has sk_sleep])
],[
        AC_MSG_RESULT(no)
])
])

#
# FC15 2.6.40-5 backported the "shrink_control" parameter to the memory
# pressure shrinker from Linux 3.0
#
AC_DEFUN([LC_SHRINK_CONTROL],
[AC_MSG_CHECKING([shrink_control is present])
LB_LINUX_TRY_COMPILE([
        #include <linux/mm.h>
],[
        struct shrink_control tmp = {0};
        tmp.nr_to_scan = sizeof(tmp);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SHRINK_CONTROL, 1,
                  [shrink_control is present])
],[
        AC_MSG_RESULT(no)
])
])

#
# LIBCFS_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LIBCFS_PROG_LINUX],
[
LIBCFS_FUNC_CPU_ONLINE
LIBCFS_TYPE_GFP_T
LIBCFS_CONFIG_PANIC_DUMPLOG

LIBCFS_FUNC_SHOW_TASK
LIBCFS_U64_LONG_LONG_LINUX
LIBCFS_TASK_RCU
# 2.6.18
LIBCFS_TASKLIST_LOCK
LIBCFS_HAVE_IS_COMPAT_TASK
# 2.6.19
LIBCFS_NETLINK
LIBCFS_NLMSG_MULTICAST
LIBCFS_KMEM_CACHE_DESTROY_INT
LIBCFS_ATOMIC_PANIC_NOTIFIER
# 2.6.20
LIBCFS_3ARGS_INIT_WORK
# 2.6.21
LIBCFS_2ARGS_REGISTER_SYSCTL
LIBCFS_KMEM_CACHE
# 2.6.23
LIBCFS_KMEM_CACHE_CREATE_DTOR
LIBCFS_NETLINK_CBMUTEX
LC_REGISTER_SHRINKER
# 2.6.24
LIBCFS_SYSCTL_UNNUMBERED
LIBCFS_SCATTERLIST_SETPAGE
LIBCFS_NL_BROADCAST_GFP
LIBCFS_NETWORK_NAMESPACE
LIBCFS_NETLINK_NETNS
LIBCFS_FUNC_DUMP_TRACE
# 2.6.26
LIBCFS_SEM_COUNT
# 2.6.27
LIBCFS_CRED_WRAPPERS
# 2.6.29
LIBCFS_STRUCT_CRED_IN_TASK
# 2.6.30
LIBCFS_FUNC_UNSHARE_FS_STRUCT
LIBCFS_SOCK_MAP_FD_2ARG
# 2.6.32
LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK
LC_SHRINKER_WANT_SHRINK_PTR
LIBCFS_HAVE_OOM_H
LIBCFS_OOMADJ_IN_SIG
# 2.6.33
LIBCFS_SYSCTL_CTLNAME
# 2.6.34
LIBCFS_ADD_WAIT_QUEUE_EXCLUSIVE
# 2.6.35
LC_SK_SLEEP
# 2.6.40 fc15
LC_SHRINK_CONTROL
])

#
# LIBCFS_PROG_DARWIN
#
# Darwin checks
#
AC_DEFUN([LIBCFS_PROG_DARWIN],
[LB_DARWIN_CHECK_FUNCS([get_preemption_level])
])

#
# LIBCFS_PATH_DEFAULTS
#
# default paths for installed files
#
AC_DEFUN([LIBCFS_PATH_DEFAULTS],
[
])

#
# LIBCFS_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LIBCFS_CONFIGURE],
[# lnet/utils/portals.c
AC_CHECK_HEADERS([asm/types.h endian.h sys/ioctl.h])

# lnet/utils/debug.c
AC_CHECK_HEADERS([linux/version.h])

AC_CHECK_TYPE([spinlock_t],
	[AC_DEFINE(HAVE_SPINLOCK_T, 1, [spinlock_t is defined])],
	[],
	[#include <linux/spinlock.h>])

# lnet/utils/wirecheck.c
AC_CHECK_FUNCS([strnlen])

AC_CHECK_TYPE([umode_t],
	[AC_DEFINE(HAVE_UMODE_T, 1, [umode_t is defined])],
	[],
	[#include <asm/types.h>])

AC_CHECK_TYPE([__s8],
	[AC_DEFINE(HAVE___S8, 1, [__s8 is defined])],
	[],
	[#include <asm/types.h>])

AC_CHECK_TYPE([__u8],
	[AC_DEFINE(HAVE___U8, 1, [__u8 is defined])],
	[],
	[#include <asm/types.h>])

AC_CHECK_TYPE([__s16],
	[AC_DEFINE(HAVE___S16, 1, [__s16 is defined])],
	[],
	[#include <asm/types.h>])

AC_CHECK_TYPE([__u16],
	[AC_DEFINE(HAVE___U16, 1, [__u16 is defined])],
	[],
	[#include <asm/types.h>])

AC_CHECK_TYPE([__s32],
	[AC_DEFINE(HAVE___S32, 1, [__s32 is defined])],
	[],
	[#include <asm/types.h>])

AC_CHECK_TYPE([__u32],
	[AC_DEFINE(HAVE___U32, 1, [__u32 is defined])],
	[],
	[#include <asm/types.h>])

AC_CHECK_TYPE([__u64],
	[AC_DEFINE(HAVE___U64, 1, [__u64 is defined])],
	[],
	[#include <asm/types.h>])

AC_CHECK_TYPE([__s64],
	[AC_DEFINE(HAVE___S64, 1, [__s64 is defined])],
	[],
	[#include <asm/types.h>])

# check userland __u64 type
AC_MSG_CHECKING([userspace __u64 is long long type])
tmp_flags="$CFLAGS"
CFLAGS="$CFLAGS -Werror"
AC_COMPILE_IFELSE([
	#include <stdio.h>
	#include <linux/types.h>
	#include <linux/stddef.h>
	int main(void) {
		unsigned long long *data1;
		__u64 *data2 = NULL;

		data1 = data2;
		return 0;
	}
],[
	AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_USER__U64_LONG_LONG, 1,
                  [__u64 is long long type])
],[
	AC_MSG_RESULT([no])
])
CFLAGS="$tmp_flags"

# --------  Check for required packages  --------------


AC_MSG_CHECKING([if efence debugging support is requested])
AC_ARG_ENABLE(efence,
	AC_HELP_STRING([--enable-efence],
			[use efence library]),
	[],[enable_efence='no'])
AC_MSG_RESULT([$enable_efence])
if test "$enable_efence" = "yes" ; then
	LIBEFENCE="-lefence"
	AC_DEFINE(HAVE_LIBEFENCE, 1, [libefence support is requested])
else
	LIBEFENCE=""
fi
AC_SUBST(LIBEFENCE)


# -------- check for -lpthread support ----
AC_MSG_CHECKING([whether to use libpthread for libcfs library])
AC_ARG_ENABLE([libpthread],
       	AC_HELP_STRING([--disable-libpthread],
               	[disable libpthread]),
       	[],[enable_libpthread=yes])
if test "$enable_libpthread" = "yes" ; then
	AC_CHECK_LIB([pthread], [pthread_create],
		[ENABLE_LIBPTHREAD="yes"],
		[ENABLE_LIBPTHREAD="no"])
	if test "$ENABLE_LIBPTHREAD" = "yes" ; then
		AC_MSG_RESULT([$ENABLE_LIBPTHREAD])
		PTHREAD_LIBS="-lpthread"
		AC_DEFINE([HAVE_LIBPTHREAD], 1, [use libpthread])
	else
		PTHREAD_LIBS=""
		AC_MSG_RESULT([no libpthread is found])
	fi
	AC_SUBST(PTHREAD_LIBS)
else
	AC_MSG_RESULT([no (disabled explicitly)])
	ENABLE_LIBPTHREAD="no"
fi
AC_SUBST(ENABLE_LIBPTHREAD)


])

#
# LIBCFS_CONDITIONALS
#
# AM_CONDITOINAL defines for lnet
#
AC_DEFUN([LIBCFS_CONDITIONALS],
[
])

#
# LIBCFS_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LIBCFS_CONFIG_FILES],
[AC_CONFIG_FILES([
libcfs/Kernelenv
libcfs/Makefile
libcfs/autoMakefile
libcfs/autoconf/Makefile
libcfs/include/Makefile
libcfs/include/libcfs/Makefile
libcfs/include/libcfs/linux/Makefile
libcfs/include/libcfs/posix/Makefile
libcfs/include/libcfs/util/Makefile
libcfs/libcfs/Makefile
libcfs/libcfs/autoMakefile
libcfs/libcfs/linux/Makefile
libcfs/libcfs/posix/Makefile
libcfs/libcfs/util/Makefile
libcfs/include/libcfs/darwin/Makefile
libcfs/libcfs/darwin/Makefile
])
])
