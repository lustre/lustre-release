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
# LIBCFS_STRUCT_PAGE_LIST
#
# 2.6.4 no longer has page->list
#
AC_DEFUN([LIBCFS_STRUCT_PAGE_LIST],
[AC_MSG_CHECKING([if struct page has a list field])
LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
],[
	struct page page;
	&page.list;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_PAGE_LIST, 1, [struct page has a list field])
],[
	AC_MSG_RESULT([no])
])
])

#
# LIBCFS_STRUCT_SIGHAND
#
# red hat 2.4 adds sighand to struct task_struct
#
AC_DEFUN([LIBCFS_STRUCT_SIGHAND],
[AC_MSG_CHECKING([if task_struct has a sighand field])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	struct task_struct p;
	p.sighand = NULL;
],[
	AC_DEFINE(CONFIG_RH_2_4_20, 1, [this kernel contains Red Hat 2.4.20 patches])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
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
# LIBCFS_TYPE_CPUMASK_T
#
# same goes for cpumask_t
#
AC_DEFUN([LIBCFS_TYPE_CPUMASK_T],
[AC_MSG_CHECKING([if kernel defines cpumask_t])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	return sizeof (cpumask_t);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_CPUMASK_T, 1, [cpumask_t found])
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
])
])

# check userland & kernel __u64 type
AC_DEFUN([LIBCFS_U64_LONG_LONG],
[AC_MSG_CHECKING([u64 is long long type])
tmp_flags="$CFLAGS"
CFLAGS="$CFLAGS -Werror"
AC_COMPILE_IFELSE([
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
AC_MSG_CHECKING([kernel __u64 is long long type])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/types.h>
	#include <linux/stddef.h>
],[
	unsigned long long *data1;
	__u64 *data2 = NULL;

	data1 = data2;
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
        struct task_struct tsk;

        tsk.rcu.next = NULL;
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_TASK_RCU, 1,
                  [task_struct has rcu field])
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

# from 2.6.24 please use sg_init_table
AC_DEFUN([LIBCFS_SCATTERLIST_INITTABLE],
[AC_MSG_CHECKING([if sg_init_table is defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/scatterlist.h>
],[
       sg_init_table(NULL,0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SCATTERLIST_INITTABLE, 1,
                  [sg_init_table is defined])
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
[kernel/ksyms.c arch/${LINUX_ARCH%_64}/kernel/traps_64.c],[
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
		void print_addr(void *data, unsigned long addr, int reliable);
		#include <asm/stacktrace.h>
	],[
		struct stacktrace_ops ops;

		ops.address = print_addr;
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_TRACE_ADDRESS_RELIABLE, 1,
			  [print_trace_address has reliable argument])
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

       uid = current_uid();
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
# LIBCFS_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LIBCFS_PROG_LINUX],
[
LIBCFS_FUNC_CPU_ONLINE
LIBCFS_TYPE_GFP_T
LIBCFS_TYPE_CPUMASK_T
LIBCFS_CONFIG_PANIC_DUMPLOG

LIBCFS_STRUCT_PAGE_LIST
LIBCFS_STRUCT_SIGHAND
LIBCFS_FUNC_SHOW_TASK
LIBCFS_U64_LONG_LONG
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
# 2.6.24
LIBCFS_SYSCTL_UNNUMBERED
LIBCFS_SCATTERLIST_SETPAGE
LIBCFS_SCATTERLIST_INITTABLE
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

# ===========================================================================
#        http://www.gnu.org/software/autoconf-archive/ax_pthread.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PTHREAD([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
#
# DESCRIPTION
#
#   This macro figures out how to build C programs using POSIX threads. It
#   sets the PTHREAD_LIBS output variable to the threads library and linker
#   flags, and the PTHREAD_CFLAGS output variable to any special C compiler
#   flags that are needed. (The user can also force certain compiler
#   flags/libs to be tested by setting these environment variables.)
#
#   Also sets PTHREAD_CC to any special C compiler that is needed for
#   multi-threaded programs (defaults to the value of CC otherwise). (This
#   is necessary on AIX to use the special cc_r compiler alias.)
#
#   NOTE: You are assumed to not only compile your program with these flags,
#   but also link it with them as well. e.g. you should link with
#   $PTHREAD_CC $CFLAGS $PTHREAD_CFLAGS $LDFLAGS ... $PTHREAD_LIBS $LIBS
#
#   If you are only building threads programs, you may wish to use these
#   variables in your default LIBS, CFLAGS, and CC:
#
#     LIBS="$PTHREAD_LIBS $LIBS"
#     CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
#     CC="$PTHREAD_CC"
#
#   In addition, if the PTHREAD_CREATE_JOINABLE thread-attribute constant
#   has a nonstandard name, defines PTHREAD_CREATE_JOINABLE to that name
#   (e.g. PTHREAD_CREATE_UNDETACHED on AIX).
#
#   ACTION-IF-FOUND is a list of shell commands to run if a threads library
#   is found, and ACTION-IF-NOT-FOUND is a list of commands to run it if it
#   is not found. If ACTION-IF-FOUND is not specified, the default action
#   will define HAVE_PTHREAD.
#
#   Please let the authors know if this macro fails on any platform, or if
#   you have any other suggestions or comments. This macro was based on work
#   by SGJ on autoconf scripts for FFTW (http://www.fftw.org/) (with help
#   from M. Frigo), as well as ac_pthread and hb_pthread macros posted by
#   Alejandro Forero Cuervo to the autoconf macro repository. We are also
#   grateful for the helpful feedback of numerous users.
#
# LICENSE
#
#   Copyright (c) 2008 Steven G. Johnson <stevenj@alum.mit.edu>
#
#   This program is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation, either version 3 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 8

AU_ALIAS([ACX_PTHREAD], [AX_PTHREAD])
AC_DEFUN([AX_PTHREAD], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_SAVE
AC_LANG_C
ax_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, ax_pthread_ok=yes)
        AC_MSG_RESULT($ax_pthread_ok)
        if test x"$ax_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all, and "pthread-config"
# which is a program returning the flags for the Pth emulation library.

ax_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread --thread-safe -mt pthread-config"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
#      ... -mt is also the pthreads flag for HP/aCC
# pthread: Linux, etcetera
# --thread-safe: KAI C++
# pthread-config: use pthread-config program (for GNU Pth library)

case "${host_cpu}-${host_os}" in
        *solaris*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthreads/-mt/
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        ax_pthread_flags="-pthreads pthread -mt -pthread $ax_pthread_flags"
        ;;

	*-darwin*)
	ax_pthread_flags="-pthread $ax_pthread_flags"
	;;
esac

if test x"$ax_pthread_ok" = xno; then
for flag in $ax_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

		pthread-config)
		AC_CHECK_PROG(ax_pthread_config, pthread-config, yes, no)
		if test x"$ax_pthread_config" = xno; then continue; fi
		PTHREAD_CFLAGS="`pthread-config --cflags`"
		PTHREAD_LIBS="`pthread-config --ldflags` `pthread-config --libs`"
		;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK([#include <pthread.h>
	             static void routine(void* a) {a=0;}
	             static void* start_routine(void* a) {return a;}],
                    [pthread_t th; pthread_attr_t attr;
                     pthread_join(th, 0);
                     pthread_attr_init(&attr);
                     pthread_cleanup_push(routine, 0);
                     pthread_create(&th,0,start_routine,0);
                     pthread_cleanup_pop(0); ],
                    [ax_pthread_ok=yes])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($ax_pthread_ok)
        if test "x$ax_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$ax_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: JOINABLE attribute is called UNDETACHED.
	AC_MSG_CHECKING([for joinable pthread attribute])
	attr_name=unknown
	for attr in PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_UNDETACHED; do
	    AC_TRY_LINK([#include <pthread.h>], [int attr=$attr; return attr;],
                        [attr_name=$attr; break])
	done
        AC_MSG_RESULT($attr_name)
        if test "$attr_name" != PTHREAD_CREATE_JOINABLE; then
            AC_DEFINE_UNQUOTED(PTHREAD_CREATE_JOINABLE, $attr_name,
                               [Define to necessary symbol if this constant
                                uses a non-standard name on your system.])
        fi

        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
        case "${host_cpu}-${host_os}" in
            *-aix* | *-freebsd* | *-darwin*) flag="-D_THREAD_SAFE";;
            *solaris* | *-osf* | *-hpux*) flag="-D_REENTRANT";;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
            PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with xlc_r or cc_r
	if test x"$GCC" != xyes; then
          AC_CHECK_PROGS(PTHREAD_CC, xlc_r cc_r, ${CC})
        else
          PTHREAD_CC=$CC
	fi
else
        PTHREAD_CC="$CC"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$ax_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        ax_pthread_ok=no
        $2
fi
AC_LANG_RESTORE
])dnl AX_PTHREAD

AX_PTHREAD([[]])


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
