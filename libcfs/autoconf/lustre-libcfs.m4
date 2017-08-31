#
# LIBCFS_CONFIG_CDEBUG
#
# whether to enable various libcfs debugs (CDEBUG, ENTRY/EXIT, LASSERT, etc.)
#
AC_DEFUN([LIBCFS_CONFIG_CDEBUG], [
AC_MSG_CHECKING([whether to enable CDEBUG, CWARN])
AC_ARG_ENABLE([libcfs_cdebug],
	AC_HELP_STRING([--disable-libcfs-cdebug],
		[disable libcfs CDEBUG, CWARN]),
	[], [enable_libcfs_cdebug="yes"])
AC_MSG_RESULT([$enable_libcfs_cdebug])
AS_IF([test "x$enable_libcfs_cdebug" = xyes],
	[AC_DEFINE(CDEBUG_ENABLED, 1, [enable libcfs CDEBUG, CWARN])])

AC_MSG_CHECKING([whether to enable ENTRY/EXIT])
AC_ARG_ENABLE([libcfs_trace],
	AC_HELP_STRING([--disable-libcfs-trace],
		[disable libcfs ENTRY/EXIT]),
	[], [enable_libcfs_trace="yes"])
AC_MSG_RESULT([$enable_libcfs_trace])
AS_IF([test "x$enable_libcfs_trace" = xyes],
	[AC_DEFINE(CDEBUG_ENTRY_EXIT, 1, [enable libcfs ENTRY/EXIT])])

AC_MSG_CHECKING([whether to enable LASSERT, LASSERTF])
AC_ARG_ENABLE([libcfs_assert],
	AC_HELP_STRING([--disable-libcfs-assert],
		[disable libcfs LASSERT, LASSERTF]),
	[], [enable_libcfs_assert="yes"])
AC_MSG_RESULT([$enable_libcfs_assert])
AS_IF([test x$enable_libcfs_assert = xyes],
	[AC_DEFINE(LIBCFS_DEBUG, 1, [enable libcfs LASSERT, LASSERTF])])
]) # LIBCFS_CONFIG_CDEBUG

#
# LIBCFS_CONFIG_PANIC_DUMPLOG
#
# check if tunable panic_dumplog is wanted
#
AC_DEFUN([LIBCFS_CONFIG_PANIC_DUMPLOG], [
AC_MSG_CHECKING([whether to use tunable 'panic_dumplog' support])
AC_ARG_ENABLE([panic_dumplog],
	AC_HELP_STRING([--enable-panic_dumplog],
		[enable panic_dumplog]),
	[], [enable_panic_dumplog="no"])
AC_MSG_RESULT([$enable_panic_dumplog])
AS_IF([test "x$enable_panic_dumplog" = xyes],
	[AC_DEFINE(LNET_DUMP_ON_PANIC, 1, [use dumplog on panic])])
]) # LIBCFS_CONFIG_PANIC_DUMPLOG

#
# LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK
#
# 2.6.32-30.el6 adds a new 'walk_stack' field in 'struct stacktrace_ops'
#
AC_DEFUN([LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK], [
LB_CHECK_COMPILE([if 'struct stacktrace_ops' has 'walk_stack' field],
stacktrace_ops_walk_stack, [
	#include <asm/stacktrace.h>
],[
	((struct stacktrace_ops *)0)->walk_stack(NULL, NULL, 0, NULL, NULL, NULL, NULL);
],[
	AC_DEFINE(STACKTRACE_OPS_HAVE_WALK_STACK, 1,
		['struct stacktrace_ops' has 'walk_stack' field])
])
]) # LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK

#
# LIBCFS_STACKTRACE_WARNING
#
# 3.0 removes stacktrace_ops warning* functions
#
AC_DEFUN([LIBCFS_STACKTRACE_WARNING], [
LB_CHECK_COMPILE([if 'stacktrace_ops.warning' is exist],
stacktrace_ops_warning, [
	struct task_struct;
	struct pt_regs;
	#include <asm/stacktrace.h>
],[
	((struct stacktrace_ops *)0)->warning(NULL, NULL);
],[
	AC_DEFINE(HAVE_STACKTRACE_WARNING, 1,
		[stacktrace_ops.warning is exist])
])
]) # LIBCFS_STACKTRACE_WARNING

#
# LIBCFS_REINIT_COMPLETION
#
AC_DEFUN([LIBCFS_REINIT_COMPLETION], [
LB_CHECK_COMPILE([if 'reinit_completion' exists],
reinit_completion, [
	#include <linux/completion.h>
],[
	struct completion x;
	reinit_completion(&x);
],[
	AC_DEFINE(HAVE_REINIT_COMPLETION, 1,
		[reinit_completion is exist])
])
]) # LIBCFS_REINIT_COMPLETION

#
# LC_SHRINKER_WANT_SHRINK_PTR
#
# RHEL6/2.6.32 want to have pointer to shrinker self pointer in handler function
#
AC_DEFUN([LC_SHRINKER_WANT_SHRINK_PTR], [
LB_CHECK_COMPILE([if 'shrinker' want self pointer in handler],
shrink_self_pointer, [
	#include <linux/mm.h>
],[
	struct shrinker *tmp = NULL;
	tmp->shrink(tmp, 0, 0);
],[
	AC_DEFINE(HAVE_SHRINKER_WANT_SHRINK_PTR, 1,
		[shrinker want self pointer in handler])
])
]) # LC_SHRINKER_WANT_SHRINK_PTR

#
# LIBCFS_SYSCTL_CTLNAME
#
# 2.6.33 no longer has ctl_name & strategy field in struct ctl_table.
#
AC_DEFUN([LIBCFS_SYSCTL_CTLNAME], [
LB_CHECK_COMPILE([if 'ctl_table' has a 'ctl_name' field],
ctl_table_ctl_name, [
	#include <linux/sysctl.h>
],[
	struct ctl_table ct;
	ct.ctl_name = sizeof(ct);
],[
	AC_DEFINE(HAVE_SYSCTL_CTLNAME, 1,
		[ctl_table has ctl_name field])
])
]) # LIBCFS_SYSCTL_CTLNAME

#
# LIBCFS_KSTRTOUL
#
# 2.6.38 kstrtoul is added
#
AC_DEFUN([LIBCFS_KSTRTOUL], [
LB_CHECK_COMPILE([if Linux kernel has 'kstrtoul'],
kstrtoul, [
	#include <linux/kernel.h>
],[
	unsigned long result;
	return kstrtoul("12345", 0, &result);
],[
	AC_DEFINE(HAVE_KSTRTOUL, 1,
		[kernel has kstrtoul])
])
]) # LIBCFS_KSTRTOUL

#
# LIBCFS_DUMP_TRACE_ADDRESS
#
# 2.6.39 adds a base pointer address argument to dump_trace
#
AC_DEFUN([LIBCFS_DUMP_TRACE_ADDRESS], [
LB_CHECK_COMPILE([if 'dump_trace' want address],
dump_trace_address, [
	struct task_struct;
	struct pt_regs;
	#include <asm/stacktrace.h>
],[
	dump_trace(NULL, NULL, NULL, 0, NULL, NULL);
],[
	AC_DEFINE(HAVE_DUMP_TRACE_ADDRESS, 1,
		[dump_trace want address argument])
])
]) # LIBCFS_DUMP_TRACE_ADDRESS

#
# LC_SHRINK_CONTROL
#
# FC15 2.6.40-5 backported the "shrink_control" parameter to the memory
# pressure shrinker from Linux 3.0
#
AC_DEFUN([LC_SHRINK_CONTROL], [
LB_CHECK_COMPILE([if 'shrink_control' is present],
shrink_control, [
	#include <linux/atomic.h>
	#include <linux/mm.h>
],[
	struct shrink_control tmp = {0};
	tmp.nr_to_scan = sizeof(tmp);
],[
	AC_DEFINE(HAVE_SHRINK_CONTROL, 1,
		[shrink_control is present])
])
]) # LC_SHRINK_CONTROL

#
# LIBCFS_PROCESS_NAMESPACE
#
# 3.5 introduced process namespace
AC_DEFUN([LIBCFS_PROCESS_NAMESPACE], [
LB_CHECK_LINUX_HEADER([linux/uidgid.h], [
	AC_DEFINE(HAVE_UIDGID_HEADER, 1,
		[uidgid.h is present])])
]) # LIBCFS_PROCESS_NAMESPACE

#
# LIBCFS_I_UID_READ
#
# 3.5 added helpers to read the new uid/gid types from VFS structures
# SLE11 SP3 has uidgid.h but not the helpers
#
AC_DEFUN([LIBCFS_I_UID_READ], [
LB_CHECK_COMPILE([if 'i_uid_read' is present],
i_uid_read, [
	#include <linux/fs.h>
],[
	i_uid_read(NULL);
],[
	AC_DEFINE(HAVE_I_UID_READ, 1, [i_uid_read is present])
])
]) # LIBCFS_I_UID_READ

#
# LIBCFS_SOCK_ALLOC_FILE
#
# FC18 3.7.2-201 unexport sock_map_fd() change to
# use sock_alloc_file().
# upstream commit 56b31d1c9f1e6a3ad92e7bfe252721e05d92b285
#
AC_DEFUN([LIBCFS_SOCK_ALLOC_FILE], [
LB_CHECK_EXPORT([sock_alloc_file], [net/socket.c], [
	LB_CHECK_COMPILE([if 'sock_alloc_file' takes 3 arguments],
	sock_alloc_file_3args, [
		#include <linux/net.h>
	],[
		sock_alloc_file(NULL, 0, NULL);
	],[
		AC_DEFINE(HAVE_SOCK_ALLOC_FILE_3ARGS, 1,
			[sock_alloc_file takes 3 arguments])
	],[
		AC_DEFINE(HAVE_SOCK_ALLOC_FILE, 1,
			[sock_alloc_file is exported])
	])
])
]) # LIBCFS_SOCK_ALLOC_FILE

#
# LIBCFS_HAVE_CRC32
#
AC_DEFUN([LIBCFS_HAVE_CRC32], [
LB_CHECK_CONFIG_IM([CRC32],
	[have_crc32="yes"], [have_crc32="no"])
AS_IF([test "x$have_crc32" = xyes],
	[AC_DEFINE(HAVE_CRC32, 1,
		[kernel compiled with CRC32 functions])])
]) # LIBCFS_HAVE_CRC32

#
# LIBCFS_ENABLE_CRC32_ACCEL
#
AC_DEFUN([LIBCFS_ENABLE_CRC32_ACCEL], [
LB_CHECK_CONFIG_IM([CRYPTO_CRC32_PCLMUL],
	[enable_crc32_crypto="no"], [enable_crc32_crypto="yes"])
AS_IF([test "x$have_crc32" = xyes -a "x$enable_crc32_crypto" = xyes], [
	AC_DEFINE(NEED_CRC32_ACCEL, 1, [need pclmulqdq based crc32])
	AC_MSG_WARN([No crc32 pclmulqdq crypto api found, enable internal pclmulqdq based crc32])])
]) # LIBCFS_ENABLE_CRC32_ACCEL

#
# LIBCFS_ENABLE_CRC32C_ACCEL
#
AC_DEFUN([LIBCFS_ENABLE_CRC32C_ACCEL], [
LB_CHECK_CONFIG_IM([CRYPTO_CRC32C_INTEL],
	[enable_crc32c_crypto="no"], [enable_crc32c_crypto="yes"])
AS_IF([test "x$enable_crc32c_crypto" = xyes], [
	AC_DEFINE(NEED_CRC32C_ACCEL, 1, [need pclmulqdq based crc32c])
	AC_MSG_WARN([No crc32c pclmulqdq crypto api found, enable internal pclmulqdq based crc32c])])
]) # LIBCFS_ENABLE_CRC32C_ACCEL

#
# Kernel version 3.11 introduced ktime_get_ts64
#
AC_DEFUN([LIBCFS_KTIME_GET_TS64],[
LB_CHECK_COMPILE([does function 'ktime_get_ts64' exist],
ktime_get_ts64, [
	#include <linux/ktime.h>
],[
	struct timespec64 *ts = NULL;

	ktime_get_ts64(ts);
],[
	AC_DEFINE(HAVE_KTIME_GET_TS64, 1,
		['ktime_get_ts64' is available])
])
]) # LIBCFS_KTIME_GET_TS64

#
# Kernel version 3.12 introduced ktime_add
#
AC_DEFUN([LIBCFS_KTIME_ADD],[
LB_CHECK_COMPILE([does function 'ktime_add' exist],
ktime_add, [
	#include <linux/ktime.h>
],[
	ktime_t start = ktime_set(0, 0);
	ktime_t end = start;
	ktime_t total;

	total = ktime_add(start, end);
],[
	AC_DEFINE(HAVE_KTIME_ADD, 1,
		[ktime_add is available])
])
]) # LIBCFS_KTIME_ADD

#
# Kernel version 3.12 introduced ktime_after
#
AC_DEFUN([LIBCFS_KTIME_AFTER],[
LB_CHECK_COMPILE([does function 'ktime_after' exist],
ktime_after, [
	#include <linux/ktime.h>
],[
	ktime_t start = ktime_set(0, 0);
	ktime_t end = start;

	ktime_after(start, end);
],[
	AC_DEFINE(HAVE_KTIME_AFTER, 1,
		[ktime_after is available])
])
]) # LIBCFS_KTIME_AFTER

#
# Kernel version 3.12 introduced ktime_before
# See linux commit 67cb9366ff5f99868100198efba5ca88aaa6ad25
#
AC_DEFUN([LIBCFS_KTIME_BEFORE],[
LB_CHECK_COMPILE([does function 'ktime_before' exist],
ktime_before, [
	#include <linux/ktime.h>
],[
	ktime_t start = ktime_set(0, 0);
	ktime_t end = start;

	ktime_before(start, end);
],[
	AC_DEFINE(HAVE_KTIME_BEFORE, 1,
		[ktime_before is available])
])
]) # LIBCFS_KTIME_BEFORE

#
# FC19 3.12 kernel struct shrinker change
#
AC_DEFUN([LIBCFS_SHRINKER_COUNT],[
LB_CHECK_COMPILE([shrinker has 'count_objects'],
shrinker_count_objects, [
	#include <linux/mmzone.h>
	#include <linux/shrinker.h>
],[
	((struct shrinker*)0)->count_objects(NULL, NULL);
],[
	AC_DEFINE(HAVE_SHRINKER_COUNT, 1,
		[shrinker has count_objects member])
])
]) # LIBCFS_SHRINKER_COUNT

#
# Kernel version 3.17 changed hlist_add_after to
# hlist_add_behind
#
AC_DEFUN([LIBCFS_HLIST_ADD_AFTER],[
LB_CHECK_COMPILE([does function 'hlist_add_after' exist],
hlist_add_after, [
	#include <linux/list.h>
],[
	hlist_add_after(NULL, NULL);
],[
	AC_DEFINE(HAVE_HLIST_ADD_AFTER, 1,
		[hlist_add_after is available])
])
]) # LIBCFS_HLIST_ADD_AFTER

#
# Kernel version 3.17 introduced struct timespec64
#
AC_DEFUN([LIBCFS_TIMESPEC64],[
LB_CHECK_COMPILE([does 'struct timespec64' exist],
timespec64, [
	#include <linux/time.h>
],[
	struct timespec64 ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 0;
],[
	AC_DEFINE(HAVE_TIMESPEC64, 1,
		['struct timespec64' is available])
])
]) # LIBCFS_TIMESPEC64

#
# Kernel version 3.17 introduced ktime_get_real_ts64
#
AC_DEFUN([LIBCFS_KTIME_GET_REAL_TS64],[
LB_CHECK_COMPILE([does function 'ktime_get_real_ts64' exist],
ktime_get_real_ts64, [
	#include <linux/ktime.h>
],[
	struct timespec64 *ts = NULL;

	ktime_get_real_ts64(ts);
],[
	AC_DEFINE(HAVE_KTIME_GET_REAL_TS64, 1,
		['ktime_get_real_ts64' is available])
])
]) # LIBCFS_KTIME_GET_REAL_TS64

#
# Kernel version 3.17 introduced ktime_get_real_seconds
#
AC_DEFUN([LIBCFS_KTIME_GET_REAL_SECONDS],[
LB_CHECK_COMPILE([does function 'ktime_get_real_seconds' exist],
ktime_get_real_seconds, [
	#include <linux/ktime.h>
],[
	time64_t now;

	now = ktime_get_real_seconds();
],[
	AC_DEFINE(HAVE_KTIME_GET_REAL_SECONDS, 1,
		['ktime_get_real_seconds' is available])
])
]) # LIBCFS_KTIME_GET_REAL_SECONDS

#
# Kernel version 3.17 created ktime_get_real_ns wrapper
#
AC_DEFUN([LIBCFS_KTIME_GET_REAL_NS],[
LB_CHECK_COMPILE([does function 'ktime_get_real_ns' exist],
ktime_get_real_ns, [
	#include <linux/ktime.h>
],[
	u64 nanoseconds;

	nanoseconds = ktime_get_real_ns();
],[],[
	AC_DEFINE(NEED_KTIME_GET_REAL_NS, 1,
		['ktime_get_real_ns' is not available])
])
]) # LIBCFS_KTIME_GET_REAL_NS

#
# Kernel version 3.17 introduced ktime_to_timespec64
#
AC_DEFUN([LIBCFS_KTIME_TO_TIMESPEC64],[
LB_CHECK_COMPILE([does function 'ktime_to_timespec64' exist],
ktime_to_timespec64, [
	#include <linux/ktime.h>
],[
	struct timespec64 ts;
	ktime_t now;

	ts = ktime_to_timespec64(now);
],[
	AC_DEFINE(HAVE_KTIME_TO_TIMESPEC64, 1,
		['ktime_to_timespec64' is available])
])
]) # LIBCFS_KTIME_TO_TIMESPEC64

#
# Kernel version 3.17 introduced timespec64_sub
#
AC_DEFUN([LIBCFS_TIMESPEC64_SUB],[
LB_CHECK_COMPILE([does function 'timespec64_sub' exist],
timespec64_sub, [
	#include <linux/time.h>
],[
	struct timespec64 later,earlier,diff;

	diff = timespec64_sub(later, earlier);
],[
	AC_DEFINE(HAVE_TIMESPEC64_SUB, 1,
		['timespec64_sub' is available])
])
]) # LIBCFS_TIMESPEC64_SUB

#
# Kernel version 3.17 introduced timespec64_to_ktime
#
AC_DEFUN([LIBCFS_TIMESPEC64_TO_KTIME],[
LB_CHECK_COMPILE([does function 'timespec64_to_ktime' exist],
timespec64_to_ktime, [
	#include <linux/ktime.h>
],[
	struct timespec64 ts;
	ktime_t now;

	now = timespec64_to_ktime(ts);
],[
	AC_DEFINE(HAVE_TIMESPEC64_TO_KTIME, 1,
		['timespec64_to_ktime' is available])
])
]) # LIBCFS_TIMESPEC64_TO_KTIME

#
# Kernel version 3.19 introduced ktime_get_seconds
#
AC_DEFUN([LIBCFS_KTIME_GET_SECONDS],[
LB_CHECK_COMPILE([does function 'ktime_get_seconds' exist],
ktime_get_seconds, [
	#include <linux/ktime.h>
],[
	time64_t now;

	now = ktime_get_seconds();
],[
	AC_DEFINE(HAVE_KTIME_GET_SECONDS, 1,
		['ktime_get_seconds' is available])
])
]) # LIBCFS_KTIME_GET_SECONDS

#
# Kernel version 3.19 commit 5aaba36318e5995e8c95d077a46d9a4d00fcc1cd
# This patch creates a new helper function cpumap_print_to_pagebuf in
# cpumask.h using newly added bitmap_print_to_pagebuf and consolidates
# most of those sysfs functions using the new helper function.
#
AC_DEFUN([LIBCFS_HAVE_CPUMASK_PRINT_TO_PAGEBUF],[
LB_CHECK_COMPILE([does function 'cpumap_print_to_pagebuf' exist],
cpumap_print_to_pagebuf, [
	#include <linux/topology.h>
],[
	int n;
	char *buf = NULL;
	const struct cpumask *mask = NULL;
	n = cpumap_print_to_pagebuf(true, buf, mask);
],[
	AC_DEFINE(HAVE_CPUMASK_PRINT_TO_PAGEBUF, 1,
		[cpumap_print_to_pagebuf is available])
])
]) # LIBCFS_HAVE_CPUMASK_PRINT_TO_PAGEBUF

#
# Kernel version 4.2 changed topology_thread_cpumask
# to topology_sibling_cpumask
#
AC_DEFUN([LIBCFS_HAVE_TOPOLOGY_SIBLING_CPUMASK],[
LB_CHECK_COMPILE([does function 'topology_sibling_cpumask' exist],
topology_sibling_cpumask, [
	#include <linux/topology.h>
],[
	const struct cpumask *mask;

	mask = topology_sibling_cpumask(0);
],[
	AC_DEFINE(HAVE_TOPOLOGY_SIBLING_CPUMASK, 1,
		[topology_sibling_cpumask is available])
])
]) # LIBCFS_HAVE_TOPOLOGY_SIBLING_CPUMASK

#
# Kernel version 4.2 commit df6b35f409af0a8ff1ef62f552b8402f3fef8665
# header file i387.h was renamed to fpu/api.h
#
AC_DEFUN([LIBCFS_FPU_API], [
LB_CHECK_LINUX_HEADER([asm/fpu/api.h], [
	AC_DEFINE(HAVE_FPU_API_HEADER, 1,
		[fpu/api.h is present])])
]) # LIBCFS_FPU_API

#
# Kernel version 4.5-rc1 commit d12481bc58fba89427565f8592e88446ec084a24
# added crypto hash helpers
#
AC_DEFUN([LIBCFS_CRYPTO_HASH_HELPERS], [
LB_CHECK_COMPILE([does crypto hash helper functions exist],
crypto_hash_helpers, [
	#include <crypto/hash.h>
],[
	crypto_ahash_alg_name(NULL);
	crypto_ahash_driver_name(NULL);
],[
	AC_DEFINE(HAVE_CRYPTO_HASH_HELPERS, 1,
		[crypto hash helper functions are available])
])
]) # LIBCFS_CRYPTO_HASH_HELPERS

#
# LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT
#
# linux 4.6 kernel changed stacktrace_ops address to return an int
#
AC_DEFUN([LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT], [
LB_CHECK_COMPILE([if 'struct stacktrace_ops' address function returns an int],
stacktrace_ops_address_return_int, [
	#include <asm/stacktrace.h>
],[
	int rc;

	rc = ((struct stacktrace_ops *)0)->address(NULL, 0, 0);
],[
	AC_DEFINE(STACKTRACE_OPS_ADDRESS_RETURN_INT, 1,
		['struct stacktrace_ops' address function returns an int])
])
]) # LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT

#
# Kernel version 4.6 removed both struct task_struct and struct mm_struct
# arguments to get_user_pages
#
AC_DEFUN([LIBCFS_GET_USER_PAGES_6ARG], [
LB_CHECK_COMPILE([if 'get_user_pages()' takes 6 arguments],
get_user_pages_6arg, [
	#include <linux/mm.h>
],[
	int rc;

	rc = get_user_pages(0, 0, 0, 0, NULL, NULL);
],[
	AC_DEFINE(HAVE_GET_USER_PAGES_6ARG, 1,
		[get_user_pages takes 6 arguments])
])
]) # LIBCFS_GET_USER_PAGES_6ARG

#
# LIBCFS_STACKTRACE_OPS
#
# Kernel version 4.8 commit c8fe4609827aedc9c4b45de80e7cdc8ccfa8541b
# removed both struct stacktrace_ops and dump_trace() function
#
AC_DEFUN([LIBCFS_STACKTRACE_OPS], [
LB_CHECK_COMPILE([if 'struct stacktrace_ops' exists],
stacktrace_ops, [
	struct task_struct;
	struct pt_regs;
	#include <asm/stacktrace.h>
],[
	struct stacktrace_ops ops;
	ops.stack = NULL;
],[
	AC_DEFINE(HAVE_STACKTRACE_OPS, 1,
		[struct stacktrace_ops exists])
])
]) # LIBCFS_STACKTRACE_OPS

#
# Kernel version 4.9 commit 768ae309a96103ed02eb1e111e838c87854d8b51
# mm: replace get_user_pages() write/force parameters with gup_flags
#
AC_DEFUN([LIBCFS_GET_USER_PAGES_GUP_FLAGS], [
LB_CHECK_COMPILE([if 'get_user_pages()' takes gup_flags in arguments],
get_user_pages_gup_flags, [
	#include <linux/mm.h>
],[
	int rc;
	rc = get_user_pages(0, 0, FOLL_WRITE, NULL, NULL);
],[
	AC_DEFINE(HAVE_GET_USER_PAGES_GUP_FLAGS, 1,
		[get_user_pages takes gup_flags in arguments])
])
]) # LIBCFS_GET_USER_PAGES_GUP_FLAGS

#
# Kernel version 4.10 commit 7b737965b33188bd3dbb44e938535c4006d97fbb
# libcfs: Convert to hotplug state machine
#
AC_DEFUN([LIBCFS_HOTPLUG_STATE_MACHINE], [
LB_CHECK_COMPILE([if libcfs supports CPU hotplug state machine],
cpu_hotplug_state_machine, [
	#include <linux/cpuhotplug.h>
],[
	cpuhp_remove_state(CPUHP_LUSTRE_CFS_DEAD);
],[
	AC_DEFINE(HAVE_HOTPLUG_STATE_MACHINE, 1,
		[hotplug state machine is supported])
])
]) # LIBCFS_HOTPLUG_STATE_MACHINE

#
# LIBCFS_SCHED_HEADERS
#
# 4.11 has broken up sched.h into more headers.
#
AC_DEFUN([LIBCFS_SCHED_HEADERS], [
LB_CHECK_LINUX_HEADER([linux/sched/signal.h], [
	AC_DEFINE(HAVE_SCHED_HEADERS, 1,
		[linux/sched header directory exist])])
]) # LIBCFS_SCHED_HEADERS

#
# LIBCFS_PROG_LINUX
#
# LibCFS linux kernel checks
#
AC_DEFUN([LIBCFS_PROG_LINUX], [
AC_MSG_NOTICE([LibCFS kernel checks
==============================================================================])
LIBCFS_CONFIG_PANIC_DUMPLOG

# 2.6.32
LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK
LC_SHRINKER_WANT_SHRINK_PTR
# 2.6.33
LIBCFS_SYSCTL_CTLNAME
# 2.6.38
LIBCFS_KSTRTOUL
# 2.6.39
LIBCFS_DUMP_TRACE_ADDRESS
# 2.6.40 fc15
LC_SHRINK_CONTROL
# 3.0
LIBCFS_STACKTRACE_WARNING
LIBCFS_REINIT_COMPLETION
# 3.5
LIBCFS_PROCESS_NAMESPACE
LIBCFS_I_UID_READ
# 3.7
LIBCFS_SOCK_ALLOC_FILE
# 3.8
LIBCFS_HAVE_CRC32
LIBCFS_ENABLE_CRC32_ACCEL
# 3.10
LIBCFS_ENABLE_CRC32C_ACCEL
# 3.11
LIBCFS_KTIME_GET_TS64
# 3.12
LIBCFS_KTIME_ADD
LIBCFS_KTIME_AFTER
LIBCFS_KTIME_BEFORE
LIBCFS_SHRINKER_COUNT
# 3.17
LIBCFS_HLIST_ADD_AFTER
LIBCFS_TIMESPEC64
LIBCFS_KTIME_GET_REAL_TS64
LIBCFS_KTIME_GET_REAL_SECONDS
LIBCFS_KTIME_GET_REAL_NS
LIBCFS_KTIME_TO_TIMESPEC64
LIBCFS_TIMESPEC64_SUB
LIBCFS_TIMESPEC64_TO_KTIME
# 3.19
LIBCFS_KTIME_GET_SECONDS
LIBCFS_HAVE_CPUMASK_PRINT_TO_PAGEBUF
# 4.2
LIBCFS_HAVE_TOPOLOGY_SIBLING_CPUMASK
LIBCFS_FPU_API
# 4.5
LIBCFS_CRYPTO_HASH_HELPERS
# 4.6
LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT
LIBCFS_GET_USER_PAGES_6ARG
# 4.8
LIBCFS_STACKTRACE_OPS
# 4.9
LIBCFS_GET_USER_PAGES_GUP_FLAGS
# 4.10
LIBCFS_HOTPLUG_STATE_MACHINE
# 4.11
LIBCFS_SCHED_HEADERS
]) # LIBCFS_PROG_LINUX

#
# LIBCFS_PATH_DEFAULTS
#
# default paths for installed files
#
AC_DEFUN([LIBCFS_PATH_DEFAULTS], [
]) # LIBCFS_PATH_DEFAULTS

#
# LIBCFS_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LIBCFS_CONFIGURE], [
AC_MSG_NOTICE([LibCFS core checks
==============================================================================])

# lnet/utils/portals.c
AC_CHECK_HEADERS([asm/types.h endian.h sys/ioctl.h])

# lnet/utils/debug.c
AC_CHECK_HEADERS([linux/version.h])

AC_CHECK_TYPE([spinlock_t],
	[AC_DEFINE(HAVE_SPINLOCK_T, 1, [spinlock_t is defined])],
	[],
	[#include <linux/spinlock.h>])

# lnet/utils/wirecheck.c
AC_CHECK_FUNCS([strnlen])

# lnet/libcfs/user-prim.c, missing for RHEL5 and earlier userspace
AC_CHECK_FUNCS([strlcpy])

# libcfs/libcfs/user-prim.c, missing for RHEL5 and earlier userspace
AC_CHECK_FUNCS([strlcat])

# libcfs/include/libcfs/linux/linux-prim.h, ...
AC_CHECK_HEADERS([linux/types.h sys/types.h linux/unistd.h unistd.h])

# libcfs/include/libcfs/linux/linux-prim.h
AC_CHECK_HEADERS([linux/random.h], [], [],
		 [#ifdef HAVE_LINUX_TYPES_H
		  #include <linux/types.h>
		  #endif
		 ])

# libcfs/include/libcfs/linux/libcfs.h
# libcfs/include/libcfs/byteorder.h
# libcfs/libcfs/util/nidstrings.c
AC_CHECK_HEADERS([netdb.h asm/types.h endian.h])
AC_CHECK_FUNCS([gethostbyname])

# --------  Check for required packages  --------------

AC_MSG_NOTICE([LibCFS required packages checks
==============================================================================])

AC_MSG_CHECKING([whether to enable readline support])
AC_ARG_ENABLE(readline,
	AC_HELP_STRING([--disable-readline],
		[disable readline support]),
	[], [enable_readline="yes"])
AC_MSG_RESULT([$enable_readline])

LIBREADLINE=""
AS_IF([test "x$enable_readline" = xyes], [
	AC_CHECK_LIB([readline], [readline], [
		LIBREADLINE="-lreadline"
		AC_DEFINE(HAVE_LIBREADLINE, 1,
			[readline library is available])
	])
])
AC_SUBST(LIBREADLINE)

AC_MSG_CHECKING([whether to use libpthread for libcfs library])
AC_ARG_ENABLE([libpthread],
	AC_HELP_STRING([--disable-libpthread],
		[disable libpthread]),
	[], [enable_libpthread="yes"])
AC_MSG_RESULT([$enable_libpthread])

PTHREAD_LIBS=""
AS_IF([test "x$enable_libpthread" = xyes], [
	AC_CHECK_LIB([pthread], [pthread_create], [
		PTHREAD_LIBS="-lpthread"
		AC_DEFINE([HAVE_LIBPTHREAD], 1,
			[use libpthread for libcfs library])
	])
], [
	AC_MSG_WARN([Using libpthread for libcfs library is disabled explicitly])
])
AC_SUBST(PTHREAD_LIBS)
]) # LIBCFS_CONFIGURE

#
# LIBCFS_CONDITIONALS
#
AC_DEFUN([LIBCFS_CONDITIONALS], [
AM_CONDITIONAL(HAVE_CRC32, [test "x$have_crc32" = xyes])
AM_CONDITIONAL(NEED_PCLMULQDQ_CRC32,  [test "x$have_crc32" = xyes -a "x$enable_crc32_crypto" = xyes])
AM_CONDITIONAL(NEED_PCLMULQDQ_CRC32C, [test "x$enable_crc32c_crypto" = xyes])
]) # LIBCFS_CONDITIONALS

#
# LIBCFS_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LIBCFS_CONFIG_FILES], [
AC_CONFIG_FILES([
libcfs/Makefile
libcfs/autoMakefile
libcfs/autoconf/Makefile
libcfs/include/Makefile
libcfs/include/libcfs/Makefile
libcfs/include/libcfs/linux/Makefile
libcfs/include/libcfs/util/Makefile
libcfs/libcfs/Makefile
libcfs/libcfs/autoMakefile
libcfs/libcfs/linux/Makefile
libcfs/libcfs/util/Makefile
])
]) # LIBCFS_CONFIG_FILES
