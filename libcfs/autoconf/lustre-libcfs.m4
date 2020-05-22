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
# LIBCFS_MODULE_LOCKING
#
# 2.6.36 introduced locking to module params. RHEL6 lacks this support
#
AC_DEFUN([LIBCFS_MODULE_LOCKING],[
LB_CHECK_COMPILE([does the kernel support module param locking],
module_param_locking, [
	#include <linux/moduleparam.h>
],[
	__kernel_param_lock(NULL);
	__kernel_param_unlock(NULL);
],[
	AC_DEFINE(HAVE_MODULE_PARAM_LOCKING, 1,
		[locking module param is supported])
])
]) # LIBCFS_MODULE_LOCKING

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
# Kernel version v3.8-rc4-82-g4f522a247bc2 exported d_hash_and_lookup()
# It was added in v2.6.16-3821-g3e7e241f8c5c, so no worries about header.
#
AC_DEFUN([LIBCFS_D_HASH_AND_LOOKUP],[
LB_CHECK_EXPORT([d_hash_and_lookup], [fs/dcache.c],
	[AC_DEFINE(HAVE_D_HASH_AND_LOOKUP, 1,
		[d_hash_and_lookup is exported by the kernel])])
]) # LIBCFS_D_HASH_AND_LOOKUP

#
# Kernel version 3.11 introduced ktime_get_ts64
#
AC_DEFUN([LIBCFS_KTIME_GET_TS64],[
LB_CHECK_COMPILE([does function 'ktime_get_ts64' exist],
ktime_get_ts64, [
	#include <linux/hrtimer.h>
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
# Kernel version 3.12-rc4 commit c2d816443ef30 added prepare_to_wait_event()
#
AC_DEFUN([LIBCFS_PREPARE_TO_WAIT_EVENT],[
LB_CHECK_COMPILE([does function 'prepare_to_wait_event' exist],
prepare_to_wait_event, [
	#include <linux/wait.h>
],[
	prepare_to_wait_event(NULL, NULL, 0);
],[
	AC_DEFINE(HAVE_PREPARE_TO_WAIT_EVENT, 1,
		['prepare_to_wait_event' is available])
])
]) # LIBCFS_PREPARE_TO_WAIT_EVENT

#
# Linux kernel 3.12 introduced struct kernel_param_ops
# This has been backported to all lustre supported
# clients except RHEL6. We have to handle the differences.
#
AC_DEFUN([LIBCFS_KERNEL_PARAM_OPS],[
LB_CHECK_COMPILE([does 'struct kernel_param_ops' exist],
kernel_param_ops, [
	#include <linux/module.h>
],[
	struct kernel_param_ops ops;

	ops.set = NULL;
],[
	AC_DEFINE(HAVE_KERNEL_PARAM_OPS, 1,
		['struct kernel_param_ops' is available])
])
]) # LIBCFS_KERNEL_PARAM_OPS

#
# Kernel version 3.12 introduced ktime_add
#
AC_DEFUN([LIBCFS_KTIME_ADD],[
LB_CHECK_COMPILE([does function 'ktime_add' exist],
ktime_add, [
	#include <linux/hrtimer.h>
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
	#include <linux/hrtimer.h>
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
	#include <linux/hrtimer.h>
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
# Kernel version 3.12 introduced ktime_compare
#
AC_DEFUN([LIBCFS_KTIME_COMPARE],[
LB_CHECK_COMPILE([does function 'ktime_compare' exist],
ktime_compare, [
	#include <linux/hrtimer.h>
	#include <linux/ktime.h>
],[
	ktime_t start = ktime_set(0, 0);
	ktime_t end = start;

	ktime_compare(start, end);
],[
	AC_DEFINE(HAVE_KTIME_COMPARE, 1,
		[ktime_compare is available])
])
]) # LIBCFS_KTIME_COMPARE

#
# FC19 3.12 kernel struct shrinker change
#
AC_DEFUN([LIBCFS_SHRINKER_COUNT],[
LB_CHECK_COMPILE([shrinker has 'count_objects'],
shrinker_count_objects, [
	#include <linux/mmzone.h>
	#include <linux/shrinker.h>
],[
	struct shrinker shrinker;

	shrinker.count_objects = NULL;
],[
	AC_DEFINE(HAVE_SHRINKER_COUNT, 1,
		[shrinker has count_objects member])
])
]) # LIBCFS_SHRINKER_COUNT

#
# LIBCFS_IOV_ITER_HAS_TYPE
#
# kernel 3.15-rc4 commit 71d8e532b1549a478e6a6a8a44f309d050294d00
# start adding the tag to iov_iter
#
AC_DEFUN([LIBCFS_IOV_ITER_HAS_TYPE], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if iov_iter has member type],
iov_iter_has_type_member, [
	#include <linux/uio.h>
],[
	struct iov_iter iter = { .type = ITER_KVEC };
	(void)iter;
],[
	AC_DEFINE(HAVE_IOV_ITER_HAS_TYPE_MEMBER, 1,
		[if iov_iter has member type])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_IOV_ITER_HAS_TYPE

#
# Kernel version 3.16 added rhashtable.h in 7e1e77636e36075eb
#
AC_DEFUN([LIBCFS_LINUX_RHASHTABLE_H],[
LB_CHECK_LINUX_HEADER([linux/rhashtable.h], [
	AC_DEFINE(HAVE_LINUX_RHASHTABLE_H, 1,
		[linux/rhashtable.h is present])
])
]) # LIBCFS_LINUX_RHASHTABLE_H

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
	#include <linux/hrtimer.h>
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
# Kernel version 3.17 created ktime_get_ns wrapper
#
AC_DEFUN([LIBCFS_KTIME_GET_NS],[
LB_CHECK_COMPILE([does function 'ktime_get_ns' exist],
ktime_get_ns, [
	#include <linux/hrtimer.h>
	#include <linux/ktime.h>
],[
	u64 nanoseconds;

	nanoseconds = ktime_get_ns();
],[],[
	AC_DEFINE(NEED_KTIME_GET_NS, 1,
		['ktime_get_ns' is not available])
])
]) # LIBCFS_KTIME_GET_NS

#
# Kernel version 3.17 created ktime_get_real_ns wrapper
#
AC_DEFUN([LIBCFS_KTIME_GET_REAL_NS],[
LB_CHECK_COMPILE([does function 'ktime_get_real_ns' exist],
ktime_get_real_ns, [
	#include <linux/hrtimer.h>
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
	#include <linux/hrtimer.h>
	#include <linux/ktime.h>
],[
	ktime_t now = ktime_set(0, 0);
	struct timespec64 ts;

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
	struct timespec64 later = { }, earlier = { }, diff;

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
# Kernel version 4.0 commit 41fbf3b39d5eca01527338b4d0ee15ee1ae1023c
# introduced the helper function ktime_ms_delta.
#
AC_DEFUN([LIBCFS_KTIME_MS_DELTA],[
LB_CHECK_COMPILE([does function 'ktime_ms_delta' exist],
ktime_ms_delta, [
	#include <linux/ktime.h>
],[
	ktime_t start = ktime_set(0, 0);
	ktime_t end = start;

	ktime_ms_delta(start, end);
],[
	AC_DEFINE(HAVE_KTIME_MS_DELTA, 1,
		['ktime_ms_delta' is available])
])
]) # LIBCFS_KTIME_MS_DELTA

#
# Kernel version 4.1 commit b51d23e4e9fea6f264d39535c2a62d1f51e7ccc3
# create per module locks which added kernel_param_[un]lock(). Older
# kernels you have to use __kernel_param_[un]lock(). In that case its
# a global lock for all modules but that is okay since its a rare event.
#
AC_DEFUN([LIBCFS_KERNEL_PARAM_LOCK],[
LB_CHECK_COMPILE([does function 'kernel_param_[un]lock' exist],
kernel_param_lock, [
	#include <linux/moduleparam.h>
],[
	kernel_param_lock(NULL);
	kernel_param_unlock(NULL);
],[
	AC_DEFINE(HAVE_KERNEL_PARAM_LOCK, 1,
		['kernel_param_[un]lock' is available])
])
]) # LIBCFS_KERNEL_PARAM_LOCK

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
# Kernel version 4.4 commit ef951599074ba4fad2d0efa0a977129b41e6d203
# introduced kstrtobool and kstrtobool_from_user.
#
AC_DEFUN([LIBCFS_KSTRTOBOOL_FROM_USER], [
LB_CHECK_COMPILE([if Linux kernel has 'kstrtobool_from_user'],
kstrtobool_from_user, [
	#include <linux/kernel.h>
],[
	bool result;
	return kstrtobool_from_user(NULL, 0, &result);
],[
	AC_DEFINE(HAVE_KSTRTOBOOL_FROM_USER, 1,
		[kernel has kstrtobool_from_user])
])
]) # LIBCFS_KSTRTOBOOL_FROM_USER

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
# Kernerl version 4.5-rc3 commit 2fe829aca9d7bed5fd6b49c6a1452e5e486b6cc3dd
# made kset_find_obj() exportable to modules
#
AC_DEFUN([LIBCFS_EXPORT_KSET_FIND_OBJ], [
LB_CHECK_EXPORT([kset_find_obj], [lib/kobject.c],
	[AC_DEFINE(HAVE_KSET_FIND_OBJ, 1,
		[kset_find_obj is exported by the kernel])])
]) # LIBCFS_EXPORT_KSET_FIND_OBJ

#
# Kernel version 4.6+ commit ef703f49a6c5b909a85149bb6625c4ed0d697186
# fixed the brokenness of hash_64(). The fix removed GOLDEN_RATIO_PRIME_64
# since it was a poor prime value.
#
AC_DEFUN([LIBCFS_BROKEN_HASH_64], [
LB_CHECK_COMPILE([kernel has fixed hash_64()],
broken_hash_64, [
	#include <linux/hash.h>
],[
	int tmp = GOLDEN_RATIO_PRIME_64;
],[
	AC_DEFINE(HAVE_BROKEN_HASH_64, 1, [kernel hash_64() is broken])
])
]) # LIBCFS_BROKEN_HASH_64

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
# LIBCFS_STRINGHASH
#
# 4.6 kernel created stringhash.h which moved stuff out of dcache.h
# commit f4bcbe792b8f434e32487cff9d9e30ab45a3ce02
#
AC_DEFUN([LIBCFS_STRINGHASH], [
LB_CHECK_LINUX_HEADER([linux/stringhash.h], [
	AC_DEFINE(HAVE_STRINGHASH, 1,
		[stringhash.h is present])])
]) # LIBCFS_STRINGHASH

#
# LIBCFS_RHASHTABLE_INSERT_FAST
#
# 4.7+ kernel commit 5ca8cc5bf11faed257c762018aea9106d529232f
# changed __rhashtable_insert_fast to support the new function
# rhashtable_lookup_get_insert_key().
#
AC_DEFUN([LIBCFS_RHASHTABLE_INSERT_FAST], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if internal '__rhashtable_insert_fast()' returns int],
rhashtable_insert_fast, [
	#include <linux/rhashtable.h>
],[
	const struct rhashtable_params params = { 0 };
	int rc;

	rc = __rhashtable_insert_fast(NULL, NULL, NULL, params);
],[
	AC_DEFINE(HAVE_HASHTABLE_INSERT_FAST_RETURN_INT, 1,
		  ['__rhashtable_insert_fast()' returns int])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_RHASHTABLE_INSERT_FAST

#
# Kernel version 4.8-rc6 commit ca26893f05e86497a86732768ec53cd38c0819ca
# introduced rhashtable_lookup
#
AC_DEFUN([LIBCFS_RHASHTABLE_LOOKUP], [
LB_CHECK_COMPILE([if 'rhashtable_lookup' exist],
rhashtable_lookup, [
	#include <linux/rhashtable.h>
],[
	const struct rhashtable_params params = { 0 };
	void *ret;

	ret = rhashtable_lookup(NULL, NULL, params);
],[
	AC_DEFINE(HAVE_RHASHTABLE_LOOKUP, 1,
		[rhashtable_lookup() is available])
])
]) # LIBCFS_RHASHTABLE_LOOKUP

#
# LIBCFS_RHLTABLE
# Kernel version 4.8-rc6 commit ca26893f05e86497a86732768ec53cd38c0819ca
# created the rhlist interface to allow inserting duplicate objects
# into the same table.
#
AC_DEFUN([LIBCFS_RHLTABLE], [
LB_CHECK_COMPILE([does 'struct rhltable' exist],
rhtable, [
	#include <linux/rhashtable.h>
],[
	struct rhltable *hlt;

	rhltable_destroy(hlt);
],[
	AC_DEFINE(HAVE_RHLTABLE, 1,
		  [struct rhltable exist])
])
]) # LIBCFS_RHLTABLE

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
# Kernel version 4.11 commit f9fe1c12d126f9887441fa5bb165046f30ddd4b5
# introduced rhashtable_lookup_get_insert_fast
#
AC_DEFUN([LIBCFS_RHASHTABLE_LOOKUP_GET_INSERT_FAST], [
LB_CHECK_COMPILE([if 'rhashtable_lookup_get_insert_fast' exist],
rhashtable_lookup_get_insert_fast, [
	#include <linux/rhashtable.h>
],[
	const struct rhashtable_params params = { 0 };
	void *ret;

	ret = rhashtable_lookup_get_insert_fast(NULL, NULL, params);
],[
	AC_DEFINE(HAVE_RHASHTABLE_LOOKUP_GET_INSERT_FAST, 1,
		[rhashtable_lookup_get_insert_fast() is available])
])
]) # LIBCFS_RHASHTABLE_LOOKUP_GET_INSERT_FAST

#
# Kernel verison 4.12-rc6 commit 5dd43ce2f69d42a71dcacdb13d17d8c0ac1fe8f7
# created wait_bit.h
#
AC_DEFUN([LIBCFS_HAVE_WAIT_BIT_HEADER], [
LB_CHECK_LINUX_HEADER([linux/wait_bit.h], [
	AC_DEFINE(HAVE_WAIT_BIT_HEADER_H, 1,
		[wait_bit.h is present])])
]) # LIBCFS_HAVE_WAIT_BIT_HEADER

#
# Kernel version 4.12-rc6 commmit 2055da97389a605c8a00d163d40903afbe413921
# changed:
#	struct wait_queue_head::task_list       => ::head
#	struct wait_queue_entry::task_list      => ::entry
#
AC_DEFUN([LIBCFS_WAIT_QUEUE_TASK_LIST_RENAME], [
LB_CHECK_COMPILE([if linux wait_queue_head list_head is named head],
wait_queue_task_list, [
	#include <linux/wait.h>
],[
	wait_queue_head_t e;

	INIT_LIST_HEAD(&e.head);
],[
	AC_DEFINE(HAVE_WAIT_QUEUE_ENTRY_LIST, 1,
		[linux wait_queue_head_t list_head is name head])
])
]) # LIBCFS_WAIT_QUEUE_TASK_LIST_RENAME

#
# LIBCFS_WAIT_QUEUE_ENTRY
#
# Kernel version 4.13 ac6424b981bce1c4bc55675c6ce11bfe1bbfa64f
# Rename wait_queue_t => wait_queue_entry_t
#
AC_DEFUN([LIBCFS_WAIT_QUEUE_ENTRY], [
LB_CHECK_COMPILE([if 'wait_queue_entry_t' exists],
wait_queue_entry, [
	#include <linux/wait.h>
],[
	wait_queue_entry_t e;

	e.flags = 0;
],[
	AC_DEFINE(HAVE_WAIT_QUEUE_ENTRY, 1,
		['wait_queue_entry_t' is available])
])
]) # LIBCFS_WAIT_QUEUE_ENTRY

#
# LIBCFS_NEW_KERNEL_WRITE
#
# Kernel version 4.14 e13ec939e96b13e664bb6cee361cc976a0ee621a
# changed kernel_write prototype to make is plug compatible
# with the unexported vfs_write()
#
AC_DEFUN([LIBCFS_NEW_KERNEL_WRITE], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'kernel_write' matches other read/write helpers],
kernel_write_match, [
	#include <linux/fs.h>
],[
	const void *buf = NULL;
	loff_t pos = 0;
	return kernel_write(NULL, buf, 0, &pos);
],[
	AC_DEFINE(HAVE_NEW_KERNEL_WRITE, 1,
		['kernel_write' aligns with read/write helpers])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_NEW_KERNEL_WRITE

#
# LIBCFS_DEFINE_TIMER
#
# Kernel version 4.14 commit 1d27e3e2252ba9d949ca82fbdb73cde102cb2067
# remove expires and data arguments from DEFINE_TIMER. Also the callback
# when from using unsigned long argument to using struct timer_list pointer.
#
AC_DEFUN([LIBCFS_DEFINE_TIMER], [
LB_CHECK_COMPILE([if DEFINE_TIMER takes only 2 arguments],
define_timer, [
	#include <linux/timer.h>
],[
	static DEFINE_TIMER(my_timer, NULL);
],[
	AC_DEFINE(HAVE_NEW_DEFINE_TIMER, 1,
		[DEFINE_TIMER uses only 2 arguements])
])
]) # LIBCFS_DEFINE_TIMER

#
# LIBCFS_EXPORT_SAVE_STACK_TRACE_TSK
#
# Kernel 2.6.27 commit 8594698ebddeef5443b7da8258ae33b3eaca61d5
# exported save_stack_trace_tsk for x86.
# Kernel 2.6.27 commit 01f4b8b8b8db09b88be7df7e51192e4e678b69d3
# exported save_stack_trace_tsk for powerpc
# Kernel 4.13 commit e27c7fa015d61c8be6a2c32b2144aad2ae6ec975
# exported save_stack_trace_tsk for arm64
# Kernel 4.14 commit 9a3dc3186fc3795e076a4122da9e0258651a9631
# exported save_stack_trace_tsk for arm
#
AC_DEFUN([LIBCFS_EXPORT_SAVE_STACK_TRACE_TSK], [
LB_CHECK_EXPORT([save_stack_trace_tsk], [arch/$SUBARCH/kernel/stacktrace.c],
	[AC_DEFINE(HAVE_SAVE_STACK_TRACE_TSK, 1,
		[save_stack_trace_tsk is exported])])
]) # LIBCFS_EXPORT_SAVE_STACK_TRACE_TSK

#
# LIBCFS_TIMER_SETUP
#
# Kernel version 4.15 commit e99e88a9d2b067465adaa9c111ada99a041bef9a
# setup_timer() was replaced by timer_setup(), where the callback
# argument is the structure already holding the struct timer_list.
#
AC_DEFUN([LIBCFS_TIMER_SETUP], [
LB_CHECK_COMPILE([if setup_timer has been replaced with timer_setup],
timer_setup, [
	#include <linux/timer.h>
],[
	timer_setup(NULL, NULL, 0);
],[
	AC_DEFINE(HAVE_TIMER_SETUP, 1,
		[timer_setup has replaced setup_timer])
])
]) # LIBCFS_TIMER_SETUP

#
# LIBCFS_WAIT_VAR_EVENT
#
# Kernel version 4.16-rc4 commit 6b2bb7265f0b62605e8caee3613449ed0db270b9
# added wait_var_event()
#
AC_DEFUN([LIBCFS_WAIT_VAR_EVENT], [
LB_CHECK_COMPILE([if 'wait_var_event' exist],
wait_var_event, [
	#ifdef HAVE_WAIT_BIT_HEADER_H
	#include <linux/wait_bit.h>
	#endif
	#include <linux/wait.h>
],[
	wake_up_var(NULL);
],[
	AC_DEFINE(HAVE_WAIT_VAR_EVENT, 1,
		['wait_var_event' is available])
])
]) # LIBCFS_WAIT_VAR_EVENT

#
# LIBCFS_CLEAR_AND_WAKE_UP_BIT
#
# Kernel version 4.17-rc2 commit 8236b0ae31c837d2b3a2565c5f8d77f637e824cc
# added clear_and_wake_up_bit()
#
AC_DEFUN([LIBCFS_CLEAR_AND_WAKE_UP_BIT], [
LB_CHECK_COMPILE([if 'clear_and_wake_up_bit' exist],
clear_and_wake_up_bit, [
	#ifdef HAVE_WAIT_BIT_HEADER_H
	#include <linux/wait_bit.h>
	#endif
	#include <linux/wait.h>
],[
	clear_and_wake_up_bit(0, NULL);
],[
	AC_DEFINE(HAVE_CLEAR_AND_WAKE_UP_BIT, 1,
		['clear_and_wake_up_bit' is available])
])
]) # LIBCFS_CLEAR_AND_WAKE_UP_BIT

#
# LIBCFS_HAVE_IOV_ITER_TYPE
#
# kernel 4.20 commit 00e23707442a75b404392cef1405ab4fd498de6b
# iov_iter: Use accessor functions to access an iterator's type and direction.
#
AC_DEFUN([LIBCFS_HAVE_IOV_ITER_TYPE], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if iov_iter_type exists],
macro_iov_iter_type_exists, [
	#include <linux/uio.h>
],[
	struct iov_iter iter = { .type = ITER_KVEC };
	enum iter_type type = iov_iter_type(&iter);
	(void)type;
],[
	AC_DEFINE(HAVE_IOV_ITER_TYPE, 1,
		[if iov_iter_type exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_HAVE_IOV_ITER_TYPE

#
# LIBCFS_CACHE_DETAIL_WRITERS
#
# kernel v5.3-rc2-1-g64a38e840ce5
# SUNRPC: Track writers of the 'channel' file to improve cache_listeners_exist
#
AC_DEFUN([LIBCFS_CACHE_DETAIL_WRITERS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if struct cache_detail has writers],
cache_detail_writers_atomic, [
	#include <linux/sunrpc/cache.h>

	static struct cache_detail rsi_cache;
],[
	atomic_set(&rsi_cache.writers, 0);
],[
	AC_DEFINE(HAVE_CACHE_DETAIL_WRITERS, 1,
		[struct cache_detail has writers])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_CACHE_DETAIL_WRITERS


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
# 2.6.36
LIBCFS_MODULE_LOCKING
# 2.6.38
LIBCFS_KSTRTOUL
# 2.6.39
LIBCFS_DUMP_TRACE_ADDRESS
# 2.6.40 fc15
LC_SHRINK_CONTROL
# 3.0
LIBCFS_STACKTRACE_WARNING
# 3.5
LIBCFS_PROCESS_NAMESPACE
LIBCFS_I_UID_READ
# 3.8
LIBCFS_HAVE_CRC32
LIBCFS_D_HASH_AND_LOOKUP
LIBCFS_ENABLE_CRC32_ACCEL
# 3.10
LIBCFS_ENABLE_CRC32C_ACCEL
# 3.11
LIBCFS_KTIME_GET_TS64
# 3.12
LIBCFS_PREPARE_TO_WAIT_EVENT
LIBCFS_KERNEL_PARAM_OPS
LIBCFS_KTIME_ADD
LIBCFS_KTIME_AFTER
LIBCFS_KTIME_BEFORE
LIBCFS_KTIME_COMPARE
LIBCFS_SHRINKER_COUNT
# 3.15
LIBCFS_IOV_ITER_HAS_TYPE
# 3.16
LIBCFS_LINUX_RHASHTABLE_H
# 3.17
LIBCFS_HLIST_ADD_AFTER
LIBCFS_TIMESPEC64
LIBCFS_KTIME_GET_NS
LIBCFS_KTIME_GET_REAL_TS64
LIBCFS_KTIME_GET_REAL_SECONDS
LIBCFS_KTIME_GET_REAL_NS
LIBCFS_KTIME_TO_TIMESPEC64
LIBCFS_TIMESPEC64_SUB
LIBCFS_TIMESPEC64_TO_KTIME
# 3.19
LIBCFS_KTIME_GET_SECONDS
# 4.0
LIBCFS_KTIME_MS_DELTA
# 4.1
LIBCFS_KERNEL_PARAM_LOCK
# 4.2
LIBCFS_HAVE_TOPOLOGY_SIBLING_CPUMASK
LIBCFS_FPU_API
# 4.4
LIBCFS_KSTRTOBOOL_FROM_USER
# 4.5
LIBCFS_CRYPTO_HASH_HELPERS
LIBCFS_EXPORT_KSET_FIND_OBJ
# 4.6
LIBCFS_BROKEN_HASH_64
LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT
LIBCFS_GET_USER_PAGES_6ARG
LIBCFS_STRINGHASH
# 4.7
LIBCFS_RHASHTABLE_INSERT_FAST
# 4.8
LIBCFS_RHASHTABLE_LOOKUP
LIBCFS_RHLTABLE
LIBCFS_STACKTRACE_OPS
# 4.9
LIBCFS_GET_USER_PAGES_GUP_FLAGS
# 4.10
LIBCFS_HOTPLUG_STATE_MACHINE
# 4.11
LIBCFS_RHASHTABLE_LOOKUP_GET_INSERT_FAST
LIBCFS_SCHED_HEADERS
# 4.12
LIBCFS_HAVE_WAIT_BIT_HEADER
LIBCFS_WAIT_QUEUE_TASK_LIST_RENAME
# 4.13
LIBCFS_WAIT_QUEUE_ENTRY
# 4.14
LIBCFS_DEFINE_TIMER
LIBCFS_NEW_KERNEL_WRITE
LIBCFS_EXPORT_SAVE_STACK_TRACE_TSK
# 4.15
LIBCFS_TIMER_SETUP
# 4.16
LIBCFS_WAIT_VAR_EVENT
# 4.17
LIBCFS_CLEAR_AND_WAKE_UP_BIT
# 4.20
LIBCFS_HAVE_IOV_ITER_TYPE
# 5.3
LIBCFS_CACHE_DETAIL_WRITERS
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
