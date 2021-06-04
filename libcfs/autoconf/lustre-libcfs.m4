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
# LIBCFS_HAVE_NS_TO_TIMESPEC64
#
# Kernel version 4.16-rc3 commit a84d1169164b274f13b97a23ff235c000efe3b49
# introduced struct __kernel_old_timeval
#
AC_DEFUN([LIBCFS_HAVE_NS_TO_TIMESPEC64],[
LB_CHECK_COMPILE([does 'ns_to_timespec64()' exist],
kernel_old_timeval, [
	#include <linux/time.h>
],[
	struct timespec64 kts;

	kts = ns_to_timespec64(0);
],[
	AC_DEFINE(HAVE_NS_TO_TIMESPEC64, 1,
		[ns_to_timespec64() is available])
])
]) # LIBCFS_HAVE_NS_TO_TIMESPEC64

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
# Kernel version 4.5-rc1 commit 3502cad73c4bbf8f6365d539e814159275252c59
# introduced rhashtable_replace_fast
#
AC_DEFUN([LIBCFS_RHASHTABLE_REPLACE], [
LB_CHECK_COMPILE([if 'rhashtable_replace_fast' exists],
rhashtable_replace_fast, [
	#include <linux/rhashtable.h>
],[
	const struct rhashtable_params params = { 0 };

	rhashtable_replace_fast(NULL, NULL, NULL, params);
],[
	AC_DEFINE(HAVE_RHASHTABLE_REPLACE, 1,
		[rhashtable_replace_fast() is available])
])
]) # LIBCFS_RHASHTABLE_REPLACE

#
# Kernel version 4.5-rc3 commit 2fe829aca9d7bed5fd6b49c6a1452e5e486b6cc3dd
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
# Kernel version 4.7-rc1 commit 8f6fd83c6c5ec66a4a70c728535ddcdfef4f3697
# added 3rd arg to rhashtable_walk_init
#
AC_DEFUN([LIBCFS_RHASHTABLE_WALK_INIT_3ARG], [
LB_CHECK_COMPILE([if 'rhashtable_walk_init' has 3 args],
rhashtable_walk_init, [
	#include <linux/gfp.h>
	#include <linux/rhashtable.h>
],[
	rhashtable_walk_init(NULL, NULL, GFP_KERNEL);
],[
	AC_DEFINE(HAVE_3ARG_RHASHTABLE_WALK_INIT, 1,
		[rhashtable_walk_init() has 3 args])
])
]) # LIBCFS_RHASHTABLE_REPLACE

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
# Kernel version 4.9-rc1 commit 246779dd090bd1b74d2652b3a6ca7759f593b27a
# introduced rhashtable_walk_enter
#
AC_DEFUN([LIBCFS_RHASHTABLE_WALK_ENTER], [
LB_CHECK_COMPILE([if 'rhashtable_walk_enter' exists],
rhashtable_walk_enter, [
	#include <linux/rhashtable.h>
],[
	rhashtable_walk_enter(NULL, NULL);
],[
	AC_DEFINE(HAVE_RHASHTABLE_WALK_ENTER, 1,
		[rhashtable_walk_enter() is available])
])
]) # LIBCFS_RHASHTABLE_REPLACE

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
# Kernel version 4.10-rc3 commit f405df5de3170c00e5c54f8b7cf4766044a032ba
# introduced refcount_t which is atomic_t plus over flow guards.
#
AC_DEFUN([LIBCFS_REFCOUNT_T], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_LINUX_HEADER([linux/refcount.h], [
	AC_DEFINE(HAVE_REFCOUNT_T, 1,
		[refcount_t is supported])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_REFCOUNT_T

#
# Kernel version 4.12 commit 499118e966f1d2150bd66647c8932343c4e9a0b8
# introduce memalloc_noreclaim_{save,restore}
#
AC_DEFUN([LIBCFS_MEMALLOC_NORECLAIM], [
LB_CHECK_COMPILE([if memalloc_noreclaim_{save,restore} exist],
memalloc_noreclaim, [
	#include <linux/sched/mm.h>
],[
	int flag = memalloc_noreclaim_save();
	memalloc_noreclaim_restore(flag);
],[
	AC_DEFINE(HAVE_MEMALLOC_RECLAIM, 1,
		[memalloc_noreclaim_{save,restore}() is supported])
])
]) # LIBCFS_MEMALLOC_NORECLAIM

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
# Kernel version 4.11-rc1 commit 2c935bc57221cc2edc787c72ea0e2d30cdcd3d5e
# introduce kref_read
#
AC_DEFUN([LIBCFS_KREF_READ], [
LB_CHECK_COMPILE([if 'kref_read' exists],
kref_read, [
	#include <linux/kref.h>
],[
	kref_read(NULL);
],[
	AC_DEFINE(HAVE_KREF_READ, 1,
		[kref_read() is available])
])
]) LIBCFS_KREF_READ

#
# Kernel version 4.11-rc1 commit da20420f83ea0fbcf3d03afda08d971ea1d8a356
# introduced rht_bucket_var
#
AC_DEFUN([LIBCFS_RHT_BUCKET_VAR], [
LB_CHECK_COMPILE([if 'rht_bucket_var' exists],
rht_bucket_var, [
	#include <linux/rhashtable.h>
],[

	rht_bucket_var(NULL, 0);
],[
	AC_DEFINE(HAVE_RHT_BUCKET_VAR, 1,
		[rht_bucket_var() is available])
])
]) # LIBCFS_RHT_BUCKET_VAR

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
# Kernel version 4.12-rc2 8f553c498e1772cccb39a114da4a498d22992758
# provide proper CPU hotplug locking
#
AC_DEFUN([LIBCFS_CPUS_READ_LOCK], [
LB_CHECK_COMPILE([if 'cpus_read_[un]lock' exist],
cpu_read_lock, [
	#include <linux/cpu.h>
],[
	cpus_read_lock();
	cpus_read_unlock();
],[
	AC_DEFINE(HAVE_CPUS_READ_LOCK, 1, ['cpus_read_lock' exist])
])
]) # LIBCFS_CPUS_READ_LOCK

#
# Kernel version 4.12-rc3 f9727a17db9bab71ddae91f74f11a8a2f9a0ece6
# renamed uuid_be to uuid_t
#
AC_DEFUN([LIBCFS_UUID_T], [
LB_CHECK_COMPILE([if 'uuid_t' exist],
uuid_t, [
	#include <linux/uuid.h>
],[
	uuid_t uuid;

	memset(uuid.b, 0, 16);
],[
	AC_DEFINE(HAVE_UUID_T, 1, ['uuid_t' exist])
])
]) # LIBCFS_UUID_T

#
# Kernel version 4.12-rc3 commit fd851a3cdc196bfc1d229b5f22369069af532bf8
# introduce processor.h
#
AC_DEFUN([LIBCFS_HAVE_PROCESSOR_HEADER], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_LINUX_HEADER([linux/processor.h], [
	AC_DEFINE(HAVE_PROCESSOR_H, 1,
		[processor.h is present])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_HAVE_PROCESSOR_HEADER

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
# LIBCFS_MM_TOTALRAM_PAGES_FUNC
#
# kernel 5.0 commit ca79b0c211af63fa3276f0e3fd7dd9ada2439839
# mm: convert totalram_pages and totalhigh_pages variables to atomic
#
AC_DEFUN([LIBCFS_MM_TOTALRAM_PAGES_FUNC], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if totalram_pages is a function],
totalram_pages, [
	#include <linux/mm.h>
],[
	totalram_pages_inc();
],[
	AC_DEFINE(HAVE_TOTALRAM_PAGES_AS_FUNC, 1,
		[if totalram_pages is a function])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_MM_TOTALRAM_PAGES_FUNC

#
# LIBCFS_NEW_KERNEL_WRITE
#
# 4.14 commit bdd1d2d3d251c65b74ac4493e08db18971c09240 changed
# the signature of kernel_read to match other read/write helpers
# and place offset last.
#
AC_DEFUN([LIBCFS_NEW_KERNEL_READ], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'kernel_read()' has loff_t *pos as last parameter],
kernel_read, [
	#include <linux/fs.h>
	],[
	loff_t pos = 0;
	kernel_read(NULL, NULL, 0, &pos);
],[
	AC_DEFINE(HAVE_KERNEL_READ_LAST_POSP, 1,
		[kernel_read() signature ends with loff_t *pos])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_NEW_KERNEL_READ

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
# LIBCFS_LOCKDEP_IS_HELD
#
# Kernel v4.15-rc8-106-g08f36ff64234
# lockdep: Make lockdep checking constant
#
AC_DEFUN([LIBCFS_LOCKDEP_IS_HELD], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'lockdep_is_held()' uses const argument],
lockdep_is_held, [
	#include <linux/lockdep.h>
],[
#ifdef CONFIG_LOCKDEP
	const struct spinlock *lock = NULL;

	lockdep_is_held(lock);
#endif
],[],[
	AC_DEFINE(NEED_LOCKDEP_IS_HELD_DISCARD_CONST, 1,
		[lockdep_is_held() argument is const])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_LOCKDEP_IS_HELD

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
# LIBCFS_BITMAP_ALLOC
#
# Kernel version 4.17 commit c42b65e363ce97a828f81b59033c3558f8fa7f70
# added bitmap memory allocation handling.
#
AC_DEFUN([LIBCFS_BITMAP_ALLOC], [
LB_CHECK_COMPILE([if Linux bitmap memory management exist],
bitmap_alloc, [
	#include <linux/bitmap.h>
],[
	unsigned long *map = bitmap_alloc(1, GFP_KERNEL);
],[
	AC_DEFINE(HAVE_BITMAP_ALLOC, 1,
		[Linux bitmap can be allocated])
])
]) # LIBCFS_BITMAP_ALLOC

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
# LIBCFS_TCP_SOCK_SET_NODELAY
#
# kernel 4.18.0-293.el8
# tcp_sock_set_nodelay() was added
AC_DEFUN([LIBCFS_TCP_SOCK_SET_NODELAY], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'tcp_sock_set_nodelay()' exists],
tcp_sock_set_nodelay_exists, [
	#include <linux/tcp.h>
],[
	tcp_sock_set_nodelay(NULL);
],[
	AC_DEFINE(HAVE_TCP_SOCK_SET_NODELAY, 1,
		['tcp_sock_set_nodelay()' exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_TCP_SOCK_SET_NODELAY

#
# LIBCFS_TCP_SOCK_SET_KEEPIDLE
#
# kernel 4.18.0-293.el8
# tcp_sock_set_keepidle() was added
AC_DEFUN([LIBCFS_TCP_SOCK_SET_KEEPIDLE], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'tcp_sock_set_keepidle()' exists],
tcp_sock_set_keepidle_exists, [
	#include <linux/tcp.h>
],[
	tcp_sock_set_keepidle(NULL, 0);
],[
	AC_DEFINE(HAVE_TCP_SOCK_SET_KEEPIDLE, 1,
		['tcp_sock_set_keepidle()' exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_TCP_SOCK_SET_KEEPIDLE

#
# LIBCFS_XARRAY_SUPPORT
#
# 4.19-rc5 kernel commit 3159f943aafdbacb2f94c38fdaadabf2bbde2a14
# replaced the radix tree implementation with Xarrays. This change
# introduced functionaly needed for general Xarray support
#
AC_DEFUN([LIBCFS_XARRAY_SUPPORT], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if page cache uses Xarray],
xarray_support, [
	#include <linux/xarray.h>
],[
	xa_is_value(NULL);
],[
	AC_DEFINE(HAVE_XARRAY_SUPPORT, 1,
		[kernel Xarray implementation lacks 'xa_is_value'])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_XARRAY_SUPPORT

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
# LIBCFS_GET_REQUEST_KEY_AUTH
#
# kernel 5.0 commit 822ad64d7e46a8e2c8b8a796738d7b657cbb146d
# keys: Fix dependency loop between construction record and auth key
#
# Added <keys/request_key_auth-type.h> and get_request_key_auth()
# which was propagated to stable
#
AC_DEFUN([LIBCFS_GET_REQUEST_KEY_AUTH], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if get_request_key_auth() is available],
get_request_key_auth_exported, [
	#include <linux/key.h>
	#include <linux/keyctl.h>
	#include <keys/request_key_auth-type.h>
],[
	struct key *ring;
	const struct key *key = NULL;
	struct request_key_auth *rka = get_request_key_auth(key);

	ring = key_get(rka->dest_keyring);
],[
	AC_DEFINE(HAVE_GET_REQUEST_KEY_AUTH, 1,
		[get_request_key_auth() is available])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_GET_REQUEST_KEY_AUTH

#
# LIBCFS_LOOKUP_USER_KEY
#
# kernel 5.3 commit 3cf5d076fb4d48979f382bc9452765bf8b79e740
# signal: Remove task parameter from force_sig
#
AC_DEFUN([LIBCFS_LOOKUP_USER_KEY], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if lookup_user_key() is available],
lookup_user_key_exported, [
	#include <linux/key.h>
	#include <linux/keyctl.h>
],[
	lookup_user_key(KEY_SPEC_USER_KEYRING, 0, 0);
],[
	AC_DEFINE(HAVE_LOOKUP_USER_KEY, 1,
		[lookup_user_key() is available])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_LOOKUP_USER_KEY

#
# LIBCFS_FORCE_SIG_WITH_TASK
#
# kernel 5.3 commit 3cf5d076fb4d48979f382bc9452765bf8b79e740
# signal: Remove task parameter from force_sig
#
AC_DEFUN([LIBCFS_FORCE_SIG_WITH_TASK], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if force_sig has task parameter],
force_sig_with_task, [
	#include <linux/sched/signal.h>
],[
	force_sig(SIGINT, NULL);
],[
	AC_DEFINE(HAVE_FORCE_SIG_WITH_TASK, 1,
		[force_sig() has task parameter])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_FORCE_SIG_WITH_TASK

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
# LIBCFS_HAVE_NR_UNSTABLE_NFS
#
# kernel v5.8-rc1~201^2~75
# mm/writeback: discard NR_UNSTABLE_NFS, use NR_WRITEBACK instead
#
AC_DEFUN([LIBCFS_HAVE_NR_UNSTABLE_NFS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if NR_UNSTABLE_NFS still in use],
nr_unstable_nfs_exists, [
	#include <linux/mm.h>

	int i;
],[
	i = NR_UNSTABLE_NFS;
],[
	AC_DEFINE(HAVE_NR_UNSTABLE_NFS, 1,
		[NR_UNSTABLE_NFS is still in use.])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_HAVE_NR_UNSTABLE_NFS

AC_DEFUN([LIBCFS_PROG_LINUX_SRC], [] )
AC_DEFUN([LIBCFS_PROG_LINUX_RESULTS], [])

#
# LIBCFS_PROG_LINUX
#
# LibCFS linux kernel checks
#
AC_DEFUN([LIBCFS_PROG_LINUX], [
AC_MSG_NOTICE([LibCFS kernel checks
==============================================================================])
LIBCFS_CONFIG_PANIC_DUMPLOG

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
LIBCFS_HAVE_NS_TO_TIMESPEC64
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
# 4.4
LIBCFS_KSTRTOBOOL_FROM_USER
# 4.5
LIBCFS_CRYPTO_HASH_HELPERS
LIBCFS_EXPORT_KSET_FIND_OBJ
LIBCFS_RHASHTABLE_REPLACE
# 4.6
LIBCFS_BROKEN_HASH_64
LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT
LIBCFS_GET_USER_PAGES_6ARG
LIBCFS_STRINGHASH
# 4.7
LIBCFS_RHASHTABLE_INSERT_FAST
LIBCFS_RHASHTABLE_WALK_INIT_3ARG
# 4.8
LIBCFS_RHASHTABLE_LOOKUP
LIBCFS_RHLTABLE
LIBCFS_STACKTRACE_OPS
# 4.9
LIBCFS_GET_USER_PAGES_GUP_FLAGS
LIBCFS_RHASHTABLE_WALK_ENTER
# 4.10
LIBCFS_HOTPLUG_STATE_MACHINE
LIBCFS_REFCOUNT_T
# 4.11
LIBCFS_RHASHTABLE_LOOKUP_GET_INSERT_FAST
LIBCFS_SCHED_HEADERS
LIBCFS_KREF_READ
LIBCFS_RHT_BUCKET_VAR
# 4.12
LIBCFS_HAVE_PROCESSOR_HEADER
LIBCFS_HAVE_WAIT_BIT_HEADER
LIBCFS_MEMALLOC_NORECLAIM
LIBCFS_WAIT_QUEUE_TASK_LIST_RENAME
LIBCFS_CPUS_READ_LOCK
LIBCFS_UUID_T
# 4.13
LIBCFS_WAIT_QUEUE_ENTRY
# 4.14
LIBCFS_DEFINE_TIMER
LIBCFS_NEW_KERNEL_WRITE
LIBCFS_NEW_KERNEL_READ
LIBCFS_EXPORT_SAVE_STACK_TRACE_TSK
# 4.15
LIBCFS_LOCKDEP_IS_HELD
LIBCFS_TIMER_SETUP
# 4.16
LIBCFS_WAIT_VAR_EVENT
# 4.17
LIBCFS_BITMAP_ALLOC
LIBCFS_CLEAR_AND_WAKE_UP_BIT
# 4.18
LIBCFS_TCP_SOCK_SET_NODELAY
LIBCFS_TCP_SOCK_SET_KEEPIDLE
# 4.19
LIBCFS_XARRAY_SUPPORT
# 4.20
LIBCFS_HAVE_IOV_ITER_TYPE
# 5.0
LIBCFS_MM_TOTALRAM_PAGES_FUNC
LIBCFS_GET_REQUEST_KEY_AUTH
# 5.3
LIBCFS_LOOKUP_USER_KEY
LIBCFS_FORCE_SIG_WITH_TASK
LIBCFS_CACHE_DETAIL_WRITERS
LIBCFS_HAVE_NR_UNSTABLE_NFS
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
libcfs/include/uapi/Makefile
libcfs/include/libcfs/linux/Makefile
libcfs/include/libcfs/util/Makefile
libcfs/include/libcfs/crypto/Makefile
libcfs/include/uapi/linux/Makefile
libcfs/libcfs/Makefile
libcfs/libcfs/autoMakefile
libcfs/libcfs/linux/Makefile
libcfs/libcfs/util/Makefile
libcfs/libcfs/crypto/Makefile
])
]) # LIBCFS_CONFIG_FILES
