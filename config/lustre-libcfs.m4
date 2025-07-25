# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

#
# LIBCFS_CONFIG_CDEBUG
#
# whether to enable various libcfs debugs (CDEBUG, ENTRY/EXIT, LASSERT, etc.)
#
AC_DEFUN([LIBCFS_CONFIG_CDEBUG], [
AC_MSG_CHECKING([whether to enable CDEBUG, CWARN])
AC_ARG_ENABLE([libcfs_cdebug],
	AS_HELP_STRING([--disable-libcfs-cdebug],
		[disable libcfs CDEBUG, CWARN]),
	[], [enable_libcfs_cdebug="yes"])
AC_MSG_RESULT([$enable_libcfs_cdebug])
AS_IF([test "x$enable_libcfs_cdebug" = xyes], [
	AC_DEFINE(CDEBUG_ENABLED, 1, [enable libcfs CDEBUG, CWARN])
	AC_SUBST(ENABLE_LIBCFS_CDEBUG, yes)
], [
	AC_SUBST(ENABLE_LIBCFS_CDEBUG, no)
])

AC_MSG_CHECKING([whether to enable ENTRY/EXIT])
AC_ARG_ENABLE([libcfs_trace],
	AS_HELP_STRING([--disable-libcfs-trace],
		[disable libcfs ENTRY/EXIT]),
	[], [enable_libcfs_trace="yes"])
AC_MSG_RESULT([$enable_libcfs_trace])
AS_IF([test "x$enable_libcfs_trace" = xyes], [
	AC_DEFINE(CDEBUG_ENTRY_EXIT, 1, [enable libcfs ENTRY/EXIT])
	AC_SUBST(ENABLE_LIBCFS_TRACE, yes)
], [
	AC_SUBST(ENABLE_LIBCFS_TRACE, no)
])

AC_MSG_CHECKING([whether to enable LASSERT, LASSERTF])
AC_ARG_ENABLE([libcfs_assert],
	AS_HELP_STRING([--disable-libcfs-assert],
		[disable libcfs LASSERT, LASSERTF]),
	[], [enable_libcfs_assert="yes"])
AC_MSG_RESULT([$enable_libcfs_assert])
AS_IF([test x$enable_libcfs_assert = xyes], [
	AC_DEFINE(LIBCFS_DEBUG, 1, [enable libcfs LASSERT, LASSERTF])
	AC_SUBST(ENABLE_LIBCFS_ASSERT, yes)
], [
	AC_SUBST(ENABLE_LIBCFS_ASSERT, no)
])
]) # LIBCFS_CONFIG_CDEBUG

#
# LIBCFS_CONFIG_PANIC_DUMPLOG
#
# check if tunable panic_dumplog is wanted
#
AC_DEFUN([LIBCFS_CONFIG_PANIC_DUMPLOG], [
AC_MSG_CHECKING([whether to use tunable 'panic_dumplog' support])
AC_ARG_ENABLE([panic_dumplog],
	AS_HELP_STRING([--enable-panic_dumplog],
		[enable panic_dumplog]),
	[], [enable_panic_dumplog="no"])
AC_MSG_RESULT([$enable_panic_dumplog])
AS_IF([test "x$enable_panic_dumplog" = xyes], [
	AC_DEFINE(LNET_DUMP_ON_PANIC, 1, [use dumplog on panic])
	AC_SUBST(ENABLE_PANIC_DUMPLOG, yes)
], [
	AC_SUBST(ENABLE_PANIC_DUMPLOG, no)
])
]) # LIBCFS_CONFIG_PANIC_DUMPLOG

#
# Kernel version 3.11 introduced ktime_get_ts64
#
AC_DEFUN([LIBCFS_SRC_KTIME_GET_TS64], [
	LB2_LINUX_TEST_SRC([ktime_get_ts64], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		struct timespec64 *ts = NULL;

		ktime_get_ts64(ts);
	])
])
AC_DEFUN([LIBCFS_KTIME_GET_TS64], [
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_get_ts64' exist],
	[ktime_get_ts64], [
		AC_DEFINE(HAVE_KTIME_GET_TS64, 1,
			['ktime_get_ts64' is available])
	])
]) # LIBCFS_KTIME_GET_TS64

#
# Kernel version 3.12-rc4 commit c2d816443ef30 added prepare_to_wait_event()
#
AC_DEFUN([LIBCFS_SRC_PREPARE_TO_WAIT_EVENT],[
	LB2_LINUX_TEST_SRC([prepare_to_wait_event], [
		#include <linux/wait.h>
	],[
		prepare_to_wait_event(NULL, NULL, 0);
	])
])
AC_DEFUN([LIBCFS_PREPARE_TO_WAIT_EVENT],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'prepare_to_wait_event' exist],
	[prepare_to_wait_event], [
		AC_DEFINE(HAVE_PREPARE_TO_WAIT_EVENT, 1,
			['prepare_to_wait_event' is available])
	])
]) # LIBCFS_PREPARE_TO_WAIT_EVENT

#
# Linux kernel 3.12 introduced struct kernel_param_ops
# This has been backported to all lustre supported
# clients except RHEL6. We have to handle the differences.
#
AC_DEFUN([LIBCFS_SRC_KERNEL_PARAM_OPS],[
	LB2_LINUX_TEST_SRC([kernel_param_ops], [
		#include <linux/module.h>
	],[
		struct kernel_param_ops ops;

		ops.set = NULL;
	])
])
AC_DEFUN([LIBCFS_KERNEL_PARAM_OPS],[
	LB2_MSG_LINUX_TEST_RESULT([if 'struct kernel_param_ops' exist],
	[kernel_param_ops], [
		AC_DEFINE(HAVE_KERNEL_PARAM_OPS, 1,
			['struct kernel_param_ops' is available])
	])
]) # LIBCFS_KERNEL_PARAM_OPS

#
# Kernel version 3.12 introduced ktime_add
#
AC_DEFUN([LIBCFS_SRC_KTIME_ADD],[
	LB2_LINUX_TEST_SRC([ktime_add], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		ktime_t start = ktime_set(0, 0);
		ktime_t end = start;
		ktime_t total;

		total = ktime_add(start, end);
	])
])
AC_DEFUN([LIBCFS_KTIME_ADD],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_add' exist],
	[ktime_add], [
		AC_DEFINE(HAVE_KTIME_ADD, 1, [ktime_add is available])
	])
]) # LIBCFS_KTIME_ADD

#
# Kernel version 3.12 introduced ktime_after
#
AC_DEFUN([LIBCFS_SRC_KTIME_AFTER],[
	LB2_LINUX_TEST_SRC([ktime_after], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		ktime_t start = ktime_set(0, 0);
		ktime_t end = start;

		ktime_after(start, end);
	])
])
AC_DEFUN([LIBCFS_KTIME_AFTER],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_after' exist],
	[ktime_after], [
		AC_DEFINE(HAVE_KTIME_AFTER, 1, [ktime_after is available])
	])
]) # LIBCFS_KTIME_AFTER

#
# Kernel version 3.12 introduced ktime_before
# See linux commit 67cb9366ff5f99868100198efba5ca88aaa6ad25
#
AC_DEFUN([LIBCFS_SRC_KTIME_BEFORE],[
	LB2_LINUX_TEST_SRC([ktime_before], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		ktime_t start = ktime_set(0, 0);
		ktime_t end = start;

		ktime_before(start, end);
	])
])
AC_DEFUN([LIBCFS_KTIME_BEFORE],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_before' exist],
	[ktime_before], [
		AC_DEFINE(HAVE_KTIME_BEFORE, 1, [ktime_before is available])
	])
]) # LIBCFS_KTIME_BEFORE

#
# Kernel version 3.12 introduced ktime_compare
#
AC_DEFUN([LIBCFS_SRC_KTIME_COMPARE],[
	LB2_LINUX_TEST_SRC([ktime_compare], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		ktime_t start = ktime_set(0, 0);
		ktime_t end = start;

		ktime_compare(start, end);
	])
])
AC_DEFUN([LIBCFS_KTIME_COMPARE],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_compare' exist],
	[ktime_compare], [
		AC_DEFINE(HAVE_KTIME_COMPARE, 1,
			[ktime_compare is available])
	])
]) # LIBCFS_KTIME_COMPARE

#
# FC19 3.12 kernel struct shrinker change
#
AC_DEFUN([LIBCFS_SRC_SHRINKER_COUNT],[
	LB2_LINUX_TEST_SRC([shrinker_count_objects], [
		#include <linux/mmzone.h>
		#include <linux/shrinker.h>
	],[
		struct shrinker shrinker;

		shrinker.count_objects = NULL;
	])
])
AC_DEFUN([LIBCFS_SHRINKER_COUNT],[
	LB2_MSG_LINUX_TEST_RESULT([if shrinker has 'count_objects'],
	[shrinker_count_objects], [
		AC_DEFINE(HAVE_SHRINKER_COUNT, 1,
			[shrinker has count_objects member])
	])
]) # LIBCFS_SHRINKER_COUNT

#
# Kernel version 3.13 commit aace05097a0fd467230e39acb148be0fdaa90068
# add match_wildcard() function.
#
AC_DEFUN([LIBCFS_SRC_MATCH_WILDCARD],[
	LB2_LINUX_TEST_SRC([match_wildcard], [
		#include <linux/parser.h>
	],[
		bool match;

		match = match_wildcard(NULL, NULL);
	])
])
AC_DEFUN([LIBCFS_MATCH_WILDCARD],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'match_wildcard' exist],
	[match_wildcard], [
		AC_DEFINE(HAVE_MATCH_WILDCARD, 1,
			[match_wildcard() is available])
	])
]) # LIBCFS_MATCH_WILDCARD

#
# LIBCFS_HAVE_MAPPING_AS_EXITING_FLAG
#
# v3.14-7405-g91b0abe36a7b added AS_EXITING flag with
# mapping_exiting() and mapping_set_exiting()
#
AC_DEFUN([LIBCFS_SRC_HAVE_MAPPING_AS_EXITING_FLAG], [
m4_pattern_allow([AS_EXITING])
	LB2_LINUX_TEST_SRC([mapping_exiting_exists], [
		#include <linux/pagemap.h>
	],[
		enum mapping_flags flag = AS_EXITING;
		(void)flag;
	],[-Werror])
])
AC_DEFUN([LIBCFS_HAVE_MAPPING_AS_EXITING_FLAG], [
	LB2_MSG_LINUX_TEST_RESULT([if enum mapping_flags has AS_EXITING flag],
	[mapping_exiting_exists], [
		AC_DEFINE(HAVE_MAPPING_AS_EXITING_FLAG, 1,
			[enum mapping_flags has AS_EXITING flag])
	])
]) # LIBCFS_HAVE_MAPPING_AS_EXITING_FLAG

#
# LIBCFS_IOV_ITER_HAS_TYPE
#
# kernel 3.15-rc4 commit 71d8e532b1549a478e6a6a8a44f309d050294d00
# start adding the tag to iov_iter
#
AC_DEFUN([LIBCFS_SRC_IOV_ITER_HAS_TYPE], [
	LB2_LINUX_TEST_SRC([iov_iter_has_type_member], [
		#include <linux/uio.h>
	],[
		struct iov_iter iter = { .type = ITER_KVEC };
		(void)iter;
	],
	[-Werror])
])
AC_DEFUN([LIBCFS_IOV_ITER_HAS_TYPE], [
	LB2_MSG_LINUX_TEST_RESULT([if iov_iter has member type],
	[iov_iter_has_type_member], [
		AC_DEFINE(HAVE_IOV_ITER_HAS_TYPE_MEMBER, 1,
			[if iov_iter has member type])
	])
]) # LIBCFS_IOV_ITER_HAS_TYPE

#
# LIBCFS_HAVE_NS_TO_TIMESPEC64
#
# Kernel version 3.16-rc3 commit a84d1169164b274f13b97a23ff235c000efe3b49
# introduced struct __kernel_old_timeval
#
AC_DEFUN([LIBCFS_SRC_HAVE_NS_TO_TIMESPEC64],[
	LB2_LINUX_TEST_SRC([kernel_old_timeval], [
		#include <linux/time.h>
	],[
		struct timespec64 kts;

		kts = ns_to_timespec64(0);
	])
])
AC_DEFUN([LIBCFS_HAVE_NS_TO_TIMESPEC64],[
	LB2_MSG_LINUX_TEST_RESULT([if 'ns_to_timespec64()' exist],
	[kernel_old_timeval], [
		AC_DEFINE(HAVE_NS_TO_TIMESPEC64, 1,
			[ns_to_timespec64() is available])
	])
]) # LIBCFS_HAVE_NS_TO_TIMESPEC64

#
# LIBCFS_HAVE_GLOB
#
# Kernel version 3.16 commit b01250856b25f4417c51aa33afc451fbf7da1484
# added glob support to the Linux kernel
#
AC_DEFUN([LIBCFS_SRC_HAVE_GLOB],[
	LB2_LINUX_TEST_SRC([glob_match], [
		#include <linux/glob.h>
	],[
		return glob_match(NULL, NULL);
	],[-Werror])
])
AC_DEFUN([LIBCFS_HAVE_GLOB],[
	LB2_MSG_LINUX_TEST_RESULT([if 'glob_match()' exist],
	[glob_match], [
		AC_DEFINE(HAVE_GLOB, 1,
			[glob_match() is available])
	])
]) # LIBCFS_HAVE_GLOB

#
# Kernel version 3.17 introduced struct timespec64
#
AC_DEFUN([LIBCFS_SRC_TIMESPEC64],[
	LB2_LINUX_TEST_SRC([timespec64], [
		#include <linux/time.h>
	],[
		struct timespec64 ts;

		ts.tv_sec = 0;
		ts.tv_nsec = 0;
	])
])
AC_DEFUN([LIBCFS_TIMESPEC64],[
	LB2_MSG_LINUX_TEST_RESULT([if 'struct timespec64' exist],
	[timespec64], [
		AC_DEFINE(HAVE_TIMESPEC64, 1,
			['struct timespec64' is available])
	])
]) # LIBCFS_TIMESPEC64

#
# Kernel version 3.17 introduced ktime_get_real_ts64
#
AC_DEFUN([LIBCFS_SRC_KTIME_GET_REAL_TS64],[
	LB2_LINUX_TEST_SRC([ktime_get_real_ts64], [
		#include <linux/ktime.h>
	],[
		struct timespec64 *ts = NULL;

		ktime_get_real_ts64(ts);
	])
])
AC_DEFUN([LIBCFS_KTIME_GET_REAL_TS64],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_get_real_ts64' exist],
	[ktime_get_real_ts64], [
		AC_DEFINE(HAVE_KTIME_GET_REAL_TS64, 1,
			['ktime_get_real_ts64' is available])
	])
]) # LIBCFS_KTIME_GET_REAL_TS64

#
# Kernel version 3.17 introduced ktime_get_real_seconds
#
AC_DEFUN([LIBCFS_SRC_KTIME_GET_REAL_SECONDS],[
	LB2_LINUX_TEST_SRC([ktime_get_real_seconds], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		time64_t now;

		now = ktime_get_real_seconds();
	])
])
AC_DEFUN([LIBCFS_KTIME_GET_REAL_SECONDS],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_get_real_ts64' exist],
	[ktime_get_real_seconds], [
		AC_DEFINE(HAVE_KTIME_GET_REAL_SECONDS, 1,
			['ktime_get_real_seconds' is available])
	])
]) # LIBCFS_KTIME_GET_REAL_SECONDS

#
# Kernel version 3.17 created ktime_get_ns wrapper
#
AC_DEFUN([LIBCFS_SRC_KTIME_GET_NS],[
	LB2_LINUX_TEST_SRC([ktime_get_ns], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		u64 nanoseconds;

		nanoseconds = ktime_get_ns();
	])
])
AC_DEFUN([LIBCFS_KTIME_GET_NS],[
	LB2_MSG_LINUX_TEST_RESULT([does function 'ktime_get_ns' exist],
	[ktime_get_ns], [],[
		AC_DEFINE(NEED_KTIME_GET_NS, 1,
			['ktime_get_ns' is not available])
	])
]) # LIBCFS_KTIME_GET_NS

#
# Kernel version 3.17 created ktime_get_real_ns wrapper
#
AC_DEFUN([LIBCFS_SRC_KTIME_GET_REAL_NS],[
	LB2_LINUX_TEST_SRC([ktime_get_real_ns], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		u64 nanoseconds;

		nanoseconds = ktime_get_real_ns();
	])
])
AC_DEFUN([LIBCFS_KTIME_GET_REAL_NS],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_get_real_ns' exist],
	[ktime_get_real_ns], [],[
		AC_DEFINE(NEED_KTIME_GET_REAL_NS, 1,
			['ktime_get_real_ns' is not available])
	])
]) # LIBCFS_KTIME_GET_REAL_NS

#
# Kernel version 3.17 introduced ktime_to_timespec64
#
AC_DEFUN([LIBCFS_SRC_KTIME_TO_TIMESPEC64],[
	LB2_LINUX_TEST_SRC([ktime_to_timespec64], [
		#include <linux/hrtimer.h>
		#include <linux/ktime.h>
	],[
		ktime_t now = ktime_set(0, 0);
		struct timespec64 ts;

		ts = ktime_to_timespec64(now);
	])
])
AC_DEFUN([LIBCFS_KTIME_TO_TIMESPEC64],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_to_timespec64' exist],
	[ktime_to_timespec64], [
		AC_DEFINE(HAVE_KTIME_TO_TIMESPEC64, 1,
			['ktime_to_timespec64' is available])
	])
]) # LIBCFS_KTIME_TO_TIMESPEC64

#
# Kernel version 3.17 introduced timespec64_sub
#
AC_DEFUN([LIBCFS_SRC_TIMESPEC64_SUB],[
	LB2_LINUX_TEST_SRC([timespec64_sub], [
		#include <linux/time.h>
	],[
		struct timespec64 later = { }, earlier = { }, diff;

		diff = timespec64_sub(later, earlier);
	])
])
AC_DEFUN([LIBCFS_TIMESPEC64_SUB],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'timespec64_sub' exist],
	[timespec64_sub], [
		AC_DEFINE(HAVE_TIMESPEC64_SUB, 1,
			['timespec64_sub' is available])
	])
]) # LIBCFS_TIMESPEC64_SUB

#
# Kernel version 3.17 introduced timespec64_to_ktime
#
AC_DEFUN([LIBCFS_SRC_TIMESPEC64_TO_KTIME],[
	LB2_LINUX_TEST_SRC([timespec64_to_ktime], [
	#include <linux/ktime.h>
	],[
		struct timespec64 ts;
		ktime_t now;

		now = timespec64_to_ktime(ts);
	])
])
AC_DEFUN([LIBCFS_TIMESPEC64_TO_KTIME],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'timespec64_to_ktime' exist],
	[timespec64_to_ktime], [
		AC_DEFINE(HAVE_TIMESPEC64_TO_KTIME, 1,
			['timespec64_to_ktime' is available])
	])
]) # LIBCFS_TIMESPEC64_TO_KTIME

#
# Kernel version 3.19 introduced ktime_get_seconds
#
AC_DEFUN([LIBCFS_SRC_KTIME_GET_SECONDS],[
	LB2_LINUX_TEST_SRC([ktime_get_seconds], [
		#include <linux/ktime.h>
	],[
		time64_t now;

		now = ktime_get_seconds();
	])
])
AC_DEFUN([LIBCFS_KTIME_GET_SECONDS],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_get_seconds' exist],
	[ktime_get_seconds], [
		AC_DEFINE(HAVE_KTIME_GET_SECONDS, 1,
			['ktime_get_seconds' is available])
	])
]) # LIBCFS_KTIME_GET_SECONDS

#
# Kernel version 3.19 commit v3.18-rc2-26-g61ada528dea0
# introduce wait_woken()
#
AC_DEFUN([LIBCFS_SRC_WAIT_WOKEN],[
	LB2_LINUX_TEST_SRC([wait_woken], [
		#include <linux/wait.h>
	],[
		wait_woken(NULL, 0, 0);
	])
])
AC_DEFUN([LIBCFS_WAIT_WOKEN],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'wait_woken' exist],
	[wait_woken], [
		AC_DEFINE(HAVE_WAIT_WOKEN, 1,
			['wait_woken, is available'])
	])
]) # LIBCFS_WAIT_WOKEN

#
# Kernel version 4.0 commit 41fbf3b39d5eca01527338b4d0ee15ee1ae1023c
# introduced the helper function ktime_ms_delta.
#
AC_DEFUN([LIBCFS_SRC_KTIME_MS_DELTA],[
	LB2_LINUX_TEST_SRC([ktime_ms_delta], [
		#include <linux/ktime.h>
	],[
		ktime_t start = ktime_set(0, 0);
		ktime_t end = start;

		ktime_ms_delta(start, end);
	])
])
AC_DEFUN([LIBCFS_KTIME_MS_DELTA],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'ktime_ms_delta' exist],
	[ktime_ms_delta], [
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
AC_DEFUN([LIBCFS_SRC_KERNEL_PARAM_LOCK],[
	LB2_LINUX_TEST_SRC([kernel_param_lock], [
		#include <linux/moduleparam.h>
	],[
		kernel_param_lock(NULL);
		kernel_param_unlock(NULL);
	])
])
AC_DEFUN([LIBCFS_KERNEL_PARAM_LOCK],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'kernel_param_[un]lock' exist],
	[kernel_param_lock], [
		AC_DEFINE(HAVE_KERNEL_PARAM_LOCK, 1,
			['kernel_param_[un]lock' is available])
	])
]) # LIBCFS_KERNEL_PARAM_LOCK

#
# LIBCFS_STRSCPY_EXISTS
#
# Linux commit v4.2-rc1-2-g30035e45753b
#  string: provide strscpy()
#
# If strscpy exists, prefer it over strlcpy
#
AC_DEFUN([LIBCFS_SRC_STRSCPY_EXISTS], [
	LB2_LINUX_TEST_SRC([strscpy_exists], [
		#include <linux/string.h>
	],[
		char buf[129];

		strscpy(buf, "something", sizeof(buf));
	],[-Werror])
])
AC_DEFUN([LIBCFS_STRSCPY_EXISTS], [
	LB2_MSG_LINUX_TEST_RESULT([if kernel strscpy is available],
	[strscpy_exists], [
		AC_DEFINE(HAVE_STRSCPY, 1,
			[kernel strscpy is available])
	])
]) # LIBCFS_STRSCPY_EXISTS

#
# Kernel version 4.2 changed topology_thread_cpumask
# to topology_sibling_cpumask
#
AC_DEFUN([LIBCFS_SRC_HAVE_TOPOLOGY_SIBLING_CPUMASK],[
	LB2_LINUX_TEST_SRC([topology_sibling_cpumask], [
		#include <linux/topology.h>
	],[
		const struct cpumask *mask;

		mask = topology_sibling_cpumask(0);
	])
])
AC_DEFUN([LIBCFS_HAVE_TOPOLOGY_SIBLING_CPUMASK],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'topology_sibling_cpumask' exist],
	[topology_sibling_cpumask], [
		AC_DEFINE(HAVE_TOPOLOGY_SIBLING_CPUMASK, 1,
			[topology_sibling_cpumask is available])
	])
]) # LIBCFS_HAVE_TOPOLOGY_SIBLING_CPUMASK

#
# Kernel version 4.4 commit ef951599074ba4fad2d0efa0a977129b41e6d203
# introduced kstrtobool and kstrtobool_from_user.
#
AC_DEFUN([LIBCFS_SRC_KSTRTOBOOL_FROM_USER], [
	LB2_LINUX_TEST_SRC([kstrtobool_from_user], [
		#include <linux/kernel.h>
	],[
		bool result;
		return kstrtobool_from_user(NULL, 0, &result);
	])
])
AC_DEFUN([LIBCFS_KSTRTOBOOL_FROM_USER], [
	LB2_MSG_LINUX_TEST_RESULT([if Linux kernel has 'kstrtobool_from_user'],
	[kstrtobool_from_user], [
		AC_DEFINE(HAVE_KSTRTOBOOL_FROM_USER, 1,
			[kernel has kstrtobool_from_user])
	])
]) # LIBCFS_KSTRTOBOOL_FROM_USER

#
# LIBCFS_NETLINK_CALLBACK_START
#
# Kernel version 4.4-rc3 commit fc9e50f5a5a4e1fa9ba2756f745a13e693cf6a06
# added a start function callback for struct netlink_callback
#
AC_DEFUN([LIBCFS_SRC_NETLINK_CALLBACK_START], [
	LB2_LINUX_TEST_SRC([cb_start], [
		#include <net/genetlink.h>
	],[
		struct genl_ops ops;

		ops.start = NULL;
	],[])
])
AC_DEFUN([LIBCFS_NETLINK_CALLBACK_START], [
	LB2_MSG_LINUX_TEST_RESULT([if struct genl_ops has start callback],
	[cb_start], [
		AC_DEFINE(HAVE_NETLINK_CALLBACK_START, 1,
			[struct genl_ops has 'start' callback])
	])
]) # LIBCFS_NETLINK_CALLBACK_START

#
# Kernel version 4.5-rc1 commit d12481bc58fba89427565f8592e88446ec084a24
# added crypto hash helpers
#
AC_DEFUN([LIBCFS_SRC_CRYPTO_HASH_HELPERS], [
	LB2_LINUX_TEST_SRC([crypto_hash_helpers], [
		#include <crypto/hash.h>
	],[
		crypto_ahash_alg_name(NULL);
		crypto_ahash_driver_name(NULL);
	])
])
AC_DEFUN([LIBCFS_CRYPTO_HASH_HELPERS], [
	LB2_MSG_LINUX_TEST_RESULT([if crypto hash helper functions exist],
	[crypto_hash_helpers], [
		AC_DEFINE(HAVE_CRYPTO_HASH_HELPERS, 1,
			[crypto hash helper functions are available])
	])
]) # LIBCFS_CRYPTO_HASH_HELPERS

#
# Kernel version 4.5-rc1 commit 3502cad73c4bbf8f6365d539e814159275252c59
# introduced rhashtable_replace_fast
#
AC_DEFUN([LIBCFS_SRC_RHASHTABLE_REPLACE], [
	LB2_LINUX_TEST_SRC([rhashtable_replace_fast], [
		#include <linux/rhashtable.h>
	],[
		const struct rhashtable_params params = { 0 };

		rhashtable_replace_fast(NULL, NULL, NULL, params);
	])
])
AC_DEFUN([LIBCFS_RHASHTABLE_REPLACE], [
	LB2_MSG_LINUX_TEST_RESULT([if 'rhashtable_replace_fast' exists],
	[rhashtable_replace_fast], [
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
AC_DEFUN([LIBCFS_SRC_BROKEN_HASH_64], [
	LB2_LINUX_TEST_SRC([broken_hash_64], [
	#include <linux/hash.h>
	],[
		int tmp = GOLDEN_RATIO_PRIME_64;
	])
])
AC_DEFUN([LIBCFS_BROKEN_HASH_64], [
	LB2_MSG_LINUX_TEST_RESULT([if kernel has fixed hash_64()],
	[broken_hash_64], [
		AC_DEFINE(HAVE_BROKEN_HASH_64, 1, [kernel hash_64() is broken])
	])
]) # LIBCFS_BROKEN_HASH_64

#
# LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT
#
# linux 4.6 kernel changed stacktrace_ops address to return an int
#
AC_DEFUN([LIBCFS_SRC_STACKTRACE_OPS_ADDRESS_RETURN_INT], [
	LB2_LINUX_TEST_SRC([stacktrace_ops_address_return_int], [
		#include <asm/stacktrace.h>
	],[
		int rc;

		rc = ((struct stacktrace_ops *)0)->address(NULL, 0, 0);
	])
])
AC_DEFUN([LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT], [
	LB2_MSG_LINUX_TEST_RESULT([if 'struct stacktrace_ops' address function returns an int],
	[stacktrace_ops_address_return_int], [
		AC_DEFINE(STACKTRACE_OPS_ADDRESS_RETURN_INT, 1,
			['struct stacktrace_ops' address function returns an int])
	])
]) # LIBCFS_STACKTRACE_OPS_ADDRESS_RETURN_INT

#
# Kernel version 4.6 removed both struct task_struct and struct mm_struct
# arguments to get_user_pages
#
AC_DEFUN([LIBCFS_SRC_GET_USER_PAGES_6ARG], [
	LB2_LINUX_TEST_SRC([get_user_pages_6arg], [
		#include <linux/mm.h>
	],[
		int rc;

		rc = get_user_pages(0, 0, 0, 0, NULL, NULL);
	])
])
AC_DEFUN([LIBCFS_GET_USER_PAGES_6ARG], [
	LB2_MSG_LINUX_TEST_RESULT([if 'get_user_pages()' takes 6 arguments],
	[get_user_pages_6arg], [
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
AC_DEFUN([LIBCFS_SRC_STRINGHASH], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/stringhash.h], [-Werror])
])
AC_DEFUN([LIBCFS_STRINGHASH], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/stringhash.h], [
		AC_DEFINE(HAVE_STRINGHASH, 1,
			[stringhash.h is present])
	])
]) # LIBCFS_STRINGHASH

#
# LIBCFS_RHASHTABLE_INSERT_FAST
#
# 4.7+ kernel commit 5ca8cc5bf11faed257c762018aea9106d529232f
# changed __rhashtable_insert_fast to support the new function
# rhashtable_lookup_get_insert_key().
#
AC_DEFUN([LIBCFS_SRC_RHASHTABLE_INSERT_FAST], [
	LB2_LINUX_TEST_SRC([rhashtable_insert_fast], [
		#include <linux/rhashtable.h>
	],[
		const struct rhashtable_params params = { 0 };
		int rc;

		rc = __rhashtable_insert_fast(NULL, NULL, NULL, params);
	],
	[-Werror])
])
AC_DEFUN([LIBCFS_RHASHTABLE_INSERT_FAST], [
	LB2_MSG_LINUX_TEST_RESULT([if internal '__rhashtable_insert_fast()' returns int],
	[rhashtable_insert_fast], [
		AC_DEFINE(HAVE_HASHTABLE_INSERT_FAST_RETURN_INT, 1,
			  ['__rhashtable_insert_fast()' returns int])
	])
]) # LIBCFS_RHASHTABLE_INSERT_FAST

#
# Kernel version 4.7-rc1 commit 8f6fd83c6c5ec66a4a70c728535ddcdfef4f3697
# added 3rd arg to rhashtable_walk_init
#
AC_DEFUN([LIBCFS_SRC_RHASHTABLE_WALK_INIT_3ARG], [
	LB2_LINUX_TEST_SRC([rhashtable_walk_init], [
		#include <linux/gfp.h>
		#include <linux/rhashtable.h>
	],[
		rhashtable_walk_init(NULL, NULL, GFP_KERNEL);
	])
])
AC_DEFUN([LIBCFS_RHASHTABLE_WALK_INIT_3ARG], [
	LB2_MSG_LINUX_TEST_RESULT([if 'rhashtable_walk_init' has 3 args],
	[rhashtable_walk_init], [
		AC_DEFINE(HAVE_3ARG_RHASHTABLE_WALK_INIT, 1,
			[rhashtable_walk_init() has 3 args])
	])
]) # LIBCFS_RHASHTABLE_WALK_INIT_3ARG

#
# Kernel version 4.8-rc6 commit ca26893f05e86497a86732768ec53cd38c0819ca
# introduced rhashtable_lookup
#
AC_DEFUN([LIBCFS_SRC_RHASHTABLE_LOOKUP], [
	LB2_LINUX_TEST_SRC([rhashtable_lookup], [
		#include <linux/rhashtable.h>
	],[
		const struct rhashtable_params params = { 0 };
		void *ret;

		ret = rhashtable_lookup(NULL, NULL, params);
	])
])
AC_DEFUN([LIBCFS_RHASHTABLE_LOOKUP], [
	LB2_MSG_LINUX_TEST_RESULT([if 'rhashtable_lookup' exist],
	[rhashtable_lookup], [
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
AC_DEFUN([LIBCFS_SRC_RHLTABLE], [
	LB2_LINUX_TEST_SRC([rhtable], [
		#include <linux/rhashtable.h>
	],[
		struct rhltable *hlt = NULL;

		rhltable_destroy(hlt);
	])
])
AC_DEFUN([LIBCFS_RHLTABLE], [
	LB2_MSG_LINUX_TEST_RESULT([if 'struct rhltable' exist],
	[rhtable], [
		AC_DEFINE(HAVE_RHLTABLE, 1, [struct rhltable exist])
	])
]) # LIBCFS_RHLTABLE

#
# LIBCFS_STACKTRACE_OPS
#
# Kernel version 4.8 commit c8fe4609827aedc9c4b45de80e7cdc8ccfa8541b
# removed both struct stacktrace_ops and dump_trace() function
#
AC_DEFUN([LIBCFS_SRC_STACKTRACE_OPS], [
	LB2_LINUX_TEST_SRC([stacktrace_ops], [
		struct task_struct;
		struct pt_regs;
		#include <asm/stacktrace.h>
	],[
		struct stacktrace_ops ops;
		ops.stack = NULL;
	])
])
AC_DEFUN([LIBCFS_STACKTRACE_OPS], [
LB2_MSG_LINUX_TEST_RESULT([if 'struct stacktrace_ops' exists],
	[stacktrace_ops], [
		AC_DEFINE(HAVE_STACKTRACE_OPS, 1,
			[struct stacktrace_ops exists])
	])
]) # LIBCFS_STACKTRACE_OPS

#
# LIBCFS_RHASHTABLE_WALK_ENTER
#
# Kernel version 4.9-rc1 commit 246779dd090bd1b74d2652b3a6ca7759f593b27a
# introduced rhashtable_walk_enter
#
AC_DEFUN([LIBCFS_SRC_RHASHTABLE_WALK_ENTER], [
	LB2_LINUX_TEST_SRC([rhashtable_walk_enter], [
		#include <linux/rhashtable.h>
	],[
		rhashtable_walk_enter(NULL, NULL);
	])
])
AC_DEFUN([LIBCFS_RHASHTABLE_WALK_ENTER], [
	LB2_MSG_LINUX_TEST_RESULT([if 'rhashtable_walk_enter' exists],
	[rhashtable_walk_enter], [
		AC_DEFINE(HAVE_RHASHTABLE_WALK_ENTER, 1,
			[rhashtable_walk_enter() is available])
	])
]) # LIBCFS_RHASHTABLE_WALK_ENTER

#
# Kernel version 4.9 commit 768ae309a96103ed02eb1e111e838c87854d8b51
# mm: replace get_user_pages() write/force parameters with gup_flags
#
AC_DEFUN([LIBCFS_SRC_GET_USER_PAGES_GUP_FLAGS], [
	LB2_LINUX_TEST_SRC([get_user_pages_gup_flags], [
		#include <linux/mm.h>
	],[
		int rc;
		rc = get_user_pages(0, 0, FOLL_WRITE, NULL, NULL);
	])
])
AC_DEFUN([LIBCFS_GET_USER_PAGES_GUP_FLAGS], [
	LB2_MSG_LINUX_TEST_RESULT([if 'get_user_pages()' takes gup_flags in arguments],
	[get_user_pages_gup_flags], [
		AC_DEFINE(HAVE_GET_USER_PAGES_GUP_FLAGS, 1,
			[get_user_pages takes gup_flags in arguments])
		])
]) # LIBCFS_GET_USER_PAGES_GUP_FLAGS

#
# LIBCFS_HOTPLUG_STATE_MACHINE
#
# Linux commit v4.9-12227-g7b737965b331 introduced
#   staging/lustre/libcfs: Convert to hotplug state machine
#   Which introduced: CPUHP_LUSTRE_CFS_DEAD
#
# Linux commit v4.10-rc1-5-g4205e4786d0b
#   cpu/hotplug: Provide dynamic range for prepare stage
#   Which introduced: CPUHP_BP_PREPARE_DYN
#
# Linux commit v6.7-rc2-1-g15bece7bec0d
#   cpu/hotplug: Remove unused CPU hotplug states
#   Which removed: CPUHP_LUSTRE_CFS_DEAD
#
# With no distro kernels between 4.10 and 4.11 switch to CPUHP_BP_PREPARE_DYN
#
AC_DEFUN([LIBCFS_SRC_HOTPLUG_STATE_MACHINE], [
	LB2_LINUX_TEST_SRC([cpu_hotplug_state_machine], [
		#include <linux/cpuhotplug.h>
	],[
		cpuhp_remove_state(CPUHP_BP_PREPARE_DYN);
	])
])
AC_DEFUN([LIBCFS_HOTPLUG_STATE_MACHINE], [
	LB2_MSG_LINUX_TEST_RESULT([if libcfs supports CPU hotplug state machine],
	[cpu_hotplug_state_machine], [
		AC_DEFINE(HAVE_HOTPLUG_STATE_MACHINE, 1,
			[hotplug state machine is supported])
	])
]) # LIBCFS_HOTPLUG_STATE_MACHINE

#
# LIBCFS_HAVE_NODE_NR_WRITEBACK
#
# kernel v4.10-rc1 commit 11fb998986a72aa7e997d96d63d52582a01228c5
# mm: move most file-based accounting to the node
# i.e. NR_UNSTABLE_NFS and NR_WRITEBACK are moved into node_stat_item enum
#
AC_DEFUN([LIBCFS_SRC_HAVE_NODE_NR_WRITEBACK], [
	LB2_LINUX_TEST_SRC([node_nr_writeback_exists], [
		#include <linux/mmzone.h>
	],[
		enum node_stat_item item = NR_WRITEBACK;
		(void)item;
	],[-Werror])
])
AC_DEFUN([LIBCFS_HAVE_NODE_NR_WRITEBACK], [
	LB2_MSG_LINUX_TEST_RESULT([if NR_WRITEBACK node_stat_item enum is available],
	[node_nr_writeback_exists], [
		AC_DEFINE(HAVE_NODE_NR_WRITEBACK, 1,
			[NR_WRITEBACK is moved into the node.])
	])
]) # LIBCFS_HAVE_NODE_NR_WRITEBACK

#
# LIBCFS_REFCOUNT_T
#
# Kernel version 4.10-rc3 commit f405df5de3170c00e5c54f8b7cf4766044a032ba
# introduced refcount_t which is atomic_t plus over flow guards.
#
AC_DEFUN([LIBCFS_SRC_REFCOUNT_T], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/refcount.h], [-Werror])
])
AC_DEFUN([LIBCFS_REFCOUNT_T], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/refcount.h], [
		AC_DEFINE(HAVE_REFCOUNT_T, 1,
			[refcount_t is supported])
	])
]) # LIBCFS_REFCOUNT_T

#
# HAVE_NLA_PUT_U64_64BIT
#
# Kernel version 4.10 commit 73520786b0793c612ef4de3e9addb2ec411bea20
# added nla_put_u64_64bit
#
AC_DEFUN([LIBCFS_SRC_NLA_PUT_U64_64BIT], [
	LB2_LINUX_TEST_SRC([nla_put_u64_64bit], [
		#include <net/genetlink.h>
	],[
		nla_put_u64_64bit(NULL, 0, 0, 0)
	])
])
AC_DEFUN([LIBCFS_NLA_PUT_U64_64BIT], [
	LB2_MSG_LINUX_TEST_RESULT([if 'nla_put_u64_64bit()' exists],
	[nla_put_u64_64bit], [
		AC_DEFINE(HAVE_NLA_PUT_U64_64BIT, 1,
			['nla_put_u64_64bit' is available])
	])
]) # LIBCFS_NLA_PUT_U64_64BIT

#
# Kernel version 4.12 commit 499118e966f1d2150bd66647c8932343c4e9a0b8
# introduce memalloc_noreclaim_{save,restore}
#
AC_DEFUN([LIBCFS_SRC_MEMALLOC_NORECLAIM], [
	LB2_LINUX_TEST_SRC([memalloc_noreclaim], [
		#include <linux/sched/mm.h>
	],[
		int flag = memalloc_noreclaim_save();
		memalloc_noreclaim_restore(flag);
	])
])
AC_DEFUN([LIBCFS_MEMALLOC_NORECLAIM], [
	LB2_MSG_LINUX_TEST_RESULT([if memalloc_noreclaim_{save,restore} exist],
	[memalloc_noreclaim], [
		AC_DEFINE(HAVE_MEMALLOC_RECLAIM, 1,
			[memalloc_noreclaim_{save,restore}() is supported])
	])
]) # LIBCFS_MEMALLOC_NORECLAIM

#
# LIBCFS_SCHED_HEADERS
#
# 4.11 has broken up sched.h into more headers.
#
AC_DEFUN([LIBCFS_SRC_SCHED_HEADERS], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/sched/signal.h], [-Werror])
])
AC_DEFUN([LIBCFS_SCHED_HEADERS], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/sched/signal.h], [
		AC_DEFINE(HAVE_SCHED_HEADERS, 1,
			[linux/sched header directory exist])
	])
]) # LIBCFS_SCHED_HEADERS

#
# Kernel version 4.11-rc1 commit 2c935bc57221cc2edc787c72ea0e2d30cdcd3d5e
# introduce kref_read
#
AC_DEFUN([LIBCFS_SRC_KREF_READ], [
	LB2_LINUX_TEST_SRC([kref_read], [
		#include <linux/kref.h>
	],[
		kref_read(NULL);
	])
])
AC_DEFUN([LIBCFS_KREF_READ], [
	LB2_MSG_LINUX_TEST_RESULT([if 'kref_read' exists],
	[kref_read], [
		AC_DEFINE(HAVE_KREF_READ, 1, [kref_read() is available])
	])
]) # LIBCFS_KREF_READ

#
# Kernel version 4.11-rc1 commit da20420f83ea0fbcf3d03afda08d971ea1d8a356
# introduced rht_bucket_var
#
AC_DEFUN([LIBCFS_SRC_RHT_BUCKET_VAR], [
	LB2_LINUX_TEST_SRC([rht_bucket_var], [
		#include <linux/rhashtable.h>
	],[
		rht_bucket_var(NULL, 0);
	])
])
AC_DEFUN([LIBCFS_RHT_BUCKET_VAR], [
	LB2_MSG_LINUX_TEST_RESULT([if 'rht_bucket_var' exists],
	[rht_bucket_var], [
		AC_DEFINE(HAVE_RHT_BUCKET_VAR, 1,
			[rht_bucket_var() is available])
	])
]) # LIBCFS_RHT_BUCKET_VAR

#
# Kernel version 4.11-rc5 commit fceb6435e85298f747fee938415057af837f5a8a
# began the enhanchement of Netlink with extended ACK struct for advanced
# error handling. By commit 7ab606d1609dd6dfeae9c8ad0a8a4e051d831e46 we
# had full support for this new feature.
#
AC_DEFUN([LIBCFS_SRC_NL_EXT_ACK], [
	LB2_LINUX_TEST_SRC([netlink_ext_ack], [
		#include <net/genetlink.h>
	],[
		struct genl_info info;

		info.extack = NULL;
	])
])
AC_DEFUN([LIBCFS_NL_EXT_ACK], [
	LB2_MSG_LINUX_TEST_RESULT([if Netlink supports netlink_ext_ack],
	[netlink_ext_ack], [
		AC_DEFINE(HAVE_NL_PARSE_WITH_EXT_ACK, 1,
			[netlink_ext_ack is an argument to nla_parse type function])
	])
]) # LIBCFS_NL_EXT_ACK

#
# Kernel version 4.11 commit f9fe1c12d126f9887441fa5bb165046f30ddd4b5
# introduced rhashtable_lookup_get_insert_fast
#
AC_DEFUN([LIBCFS_SRC_RHASHTABLE_LOOKUP_GET_INSERT_FAST], [
	LB2_LINUX_TEST_SRC([rhashtable_lookup_get_insert_fast], [
		#include <linux/rhashtable.h>
	],[
		const struct rhashtable_params params = { 0 };
		void *ret;

		ret = rhashtable_lookup_get_insert_fast(NULL, NULL, params);
	])
])
AC_DEFUN([LIBCFS_RHASHTABLE_LOOKUP_GET_INSERT_FAST], [
	LB2_MSG_LINUX_TEST_RESULT([if 'rhashtable_lookup_get_insert_fast' exist],
	[rhashtable_lookup_get_insert_fast], [
		AC_DEFINE(HAVE_RHASHTABLE_LOOKUP_GET_INSERT_FAST, 1,
			[rhashtable_lookup_get_insert_fast() is available])
	])
]) # LIBCFS_RHASHTABLE_LOOKUP_GET_INSERT_FAST

#
# Kernel version 4.12-rc2 8f553c498e1772cccb39a114da4a498d22992758
# provide proper CPU hotplug locking
#
AC_DEFUN([LIBCFS_SRC_CPUS_READ_LOCK], [
	LB2_LINUX_TEST_SRC([cpu_read_lock], [
		#include <linux/cpu.h>
	],[
		cpus_read_lock();
		cpus_read_unlock();
	])
])
AC_DEFUN([LIBCFS_CPUS_READ_LOCK], [
	LB2_MSG_LINUX_TEST_RESULT([if 'cpus_read_[un]lock' exist],
	[cpu_read_lock], [
		AC_DEFINE(HAVE_CPUS_READ_LOCK, 1, ['cpus_read_lock' exist])
	])
]) # LIBCFS_CPUS_READ_LOCK

#
# LIBCFS_HAVE_PROCESSOR_HEADER
#
# Kernel version 4.12-rc3 commit fd851a3cdc196bfc1d229b5f22369069af532bf8
# introduce processor.h
#
AC_DEFUN([LIBCFS_SRC_HAVE_PROCESSOR_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/processor.h], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_PROCESSOR_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/processor.h], [
		AC_DEFINE(HAVE_PROCESSOR_H, 1,
			[processor.h is present])
	],[])
]) # LIBCFS_HAVE_PROCESSOR_HEADER

#
# LIBCFS_HAVE_WAIT_BIT_HEADER
#
# Kernel verison 4.12-rc6 commit 5dd43ce2f69d42a71dcacdb13d17d8c0ac1fe8f7
# created wait_bit.h
#
AC_DEFUN([LIBCFS_SRC_HAVE_WAIT_BIT_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/wait_bit.h], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_WAIT_BIT_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/wait_bit.h], [
		AC_DEFINE(HAVE_WAIT_BIT_HEADER_H, 1,
			[wait_bit.h is present])
	],[])
]) # LIBCFS_HAVE_PROCESSOR_HEADER

#
# Kernel version 4.12-rc6 commmit 2055da97389a605c8a00d163d40903afbe413921
# changed:
#	struct wait_queue_head::task_list       => ::head
#	struct wait_queue_entry::task_list      => ::entry
#
AC_DEFUN([LIBCFS_SRC_WAIT_QUEUE_TASK_LIST_RENAME], [
	LB2_LINUX_TEST_SRC([wait_queue_task_list], [
		#include <linux/wait.h>
	],[
		wait_queue_head_t e;

		INIT_LIST_HEAD(&e.head);
	])
])
AC_DEFUN([LIBCFS_WAIT_QUEUE_TASK_LIST_RENAME], [
	LB2_MSG_LINUX_TEST_RESULT([if linux wait_queue_head list_head is named head],
	[wait_queue_task_list], [
		AC_DEFINE(HAVE_WAIT_QUEUE_ENTRY_LIST, 1,
			[linux wait_queue_head_t list_head is name head])
	])
]) # LIBCFS_WAIT_QUEUE_TASK_LIST_RENAME

#
# LIBCFS_WAIT_BIT_QUEUE_ENTRY_EXISTS
#
# Kernel version v4.12-rc6-23-g76c85ddc4695
# sched/wait: Standardize wait_bit_queue naming
#
# renamed struct wait_bit_queue  => wait_bit_queue_entry
#
AC_DEFUN([LIBCFS_SRC_WAIT_BIT_QUEUE_ENTRY_EXISTS], [
	LB2_LINUX_TEST_SRC([struct_wait_bit_queue_entry_exists], [
		#include <linux/wait.h>
		#if HAVE_WAIT_BIT_HEADER_H
			#include <linux/wait_bit.h>
		#endif
	],[
		struct wait_bit_queue_entry entry;
		memset(&entry, 0, sizeof(entry));
	])
])
AC_DEFUN([LIBCFS_WAIT_BIT_QUEUE_ENTRY_EXISTS], [
	LB2_MSG_LINUX_TEST_RESULT([if struct wait_bit_queue_entry exists],
	[struct_wait_bit_queue_entry_exists], [
		AC_DEFINE(HAVE_WAIT_BIT_QUEUE_ENTRY, 1,
			[if struct wait_bit_queue_entry exists])
	])
]) # LIBCFS_WAIT_BIT_QUEUE_ENTRY_EXISTS

#
# LIBCFS_NLA_STRDUP
#
# Kernel version 4.13-rc1 commit 2cf0c8b3e6942ecafe6ebb1a6d0328a81641bf39
# created nla_strdup(). This is needed since push strings can be
# any size.
#
AC_DEFUN([LIBCFS_SRC_NLA_STRDUP], [
	LB2_LINUX_TEST_SRC([nla_strdup], [
		#include <net/netlink.h>
	],[
		char *tmp = nla_strdup(NULL, GFP_KERNEL);
		(void)tmp;
	],[])
])
AC_DEFUN([LIBCFS_NLA_STRDUP], [
	LB2_MSG_LINUX_TEST_RESULT([if 'nla_strdup()' exists],
	[nla_strdup], [
		AC_DEFINE(HAVE_NLA_STRDUP, 1,
			['nla_strdup' is available])
	])
]) # LIBCFS_NLA_STRDUP

#
# LIBCFS_WAIT_QUEUE_ENTRY
#
# Kernel version 4.13 ac6424b981bce1c4bc55675c6ce11bfe1bbfa64f
# Rename wait_queue_t => wait_queue_entry_t
#
AC_DEFUN([LIBCFS_SRC_WAIT_QUEUE_ENTRY], [
	LB2_LINUX_TEST_SRC([wait_queue_entry], [
		#include <linux/wait.h>
	],[
		wait_queue_entry_t e;

		e.flags = 0;
	])
])
AC_DEFUN([LIBCFS_WAIT_QUEUE_ENTRY], [
	LB2_MSG_LINUX_TEST_RESULT([if 'wait_queue_entry_t' exists],
	[wait_queue_entry], [
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
AC_DEFUN([LIBCFS_SRC_NEW_KERNEL_WRITE], [
	LB2_LINUX_TEST_SRC([kernel_write_match], [
		#include <linux/fs.h>
	],[
		const void *buf = NULL;
		loff_t pos = 0;
		return kernel_write(NULL, buf, 0, &pos);
	],[-Werror])
])
AC_DEFUN([LIBCFS_NEW_KERNEL_WRITE], [
	LB2_MSG_LINUX_TEST_RESULT([if 'kernel_write' matches other read/write helpers],
	[kernel_write_match], [
		AC_DEFINE(HAVE_NEW_KERNEL_WRITE, 1,
			['kernel_write' aligns with read/write helpers])
	])
]) # LIBCFS_NEW_KERNEL_WRITE

#
# LIBCFS_MM_TOTALRAM_PAGES_FUNC
#
# kernel 5.0 commit ca79b0c211af63fa3276f0e3fd7dd9ada2439839
# mm: convert totalram_pages and totalhigh_pages variables to atomic
#
AC_DEFUN([LIBCFS_SRC_MM_TOTALRAM_PAGES_FUNC], [
	LB2_LINUX_TEST_SRC([totalram_pages], [
		#include <linux/mm.h>
	],[
		totalram_pages_inc();
	],[-Werror])
])
AC_DEFUN([LIBCFS_MM_TOTALRAM_PAGES_FUNC], [
	LB2_MSG_LINUX_TEST_RESULT([if totalram_pages is a function],
	[totalram_pages], [
		AC_DEFINE(HAVE_TOTALRAM_PAGES_AS_FUNC, 1,
			[if totalram_pages is a function])
	])
]) # LIBCFS_MM_TOTALRAM_PAGES_FUNC

#
# LIBCFS_NEW_KERNEL_READ
#
# 4.14 commit bdd1d2d3d251c65b74ac4493e08db18971c09240 changed
# the signature of kernel_read to match other read/write helpers
# and place offset last.
#
AC_DEFUN([LIBCFS_SRC_NEW_KERNEL_READ], [
	LB2_LINUX_TEST_SRC([kernel_read], [
		#include <linux/fs.h>
	],[
		loff_t pos = 0;
		kernel_read(NULL, NULL, 0, &pos);
	],[-Werror])
])
AC_DEFUN([LIBCFS_NEW_KERNEL_READ], [
	LB2_MSG_LINUX_TEST_RESULT([if 'kernel_read()' has loff_t *pos as last parameter],
	[kernel_read], [
		AC_DEFINE(HAVE_KERNEL_READ_LAST_POSP, 1,
			[kernel_read() signature ends with loff_t *pos])
	])
]) # LIBCFS_NEW_KERNEL_READ

#
# LIBCFS_DEFINE_TIMER
#
# Kernel version 4.14 commit 1d27e3e2252ba9d949ca82fbdb73cde102cb2067
# remove expires and data arguments from DEFINE_TIMER. Also the callback
# when from using unsigned long argument to using struct timer_list pointer.
#
AC_DEFUN([LIBCFS_SRC_DEFINE_TIMER], [
	LB2_LINUX_TEST_SRC([define_timer], [
		#include <linux/timer.h>
	],[
		static DEFINE_TIMER(my_timer, NULL);
	])
])
AC_DEFUN([LIBCFS_DEFINE_TIMER], [
	LB2_MSG_LINUX_TEST_RESULT([if DEFINE_TIMER takes only 2 arguments],
	[define_timer], [
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
AC_DEFUN([LIBCFS_SRC_LOCKDEP_IS_HELD], [
	LB2_LINUX_TEST_SRC([lockdep_is_held], [
		#include <linux/lockdep.h>
	],[
	#ifdef CONFIG_LOCKDEP
		const struct spinlock *lock = NULL;

		lockdep_is_held(lock);
	#endif
	],[-Werror])
])
AC_DEFUN([LIBCFS_LOCKDEP_IS_HELD], [
	LB2_MSG_LINUX_TEST_RESULT([if 'lockdep_is_held()' uses const argument],
	[lockdep_is_held], [
	],[
		AC_DEFINE(NEED_LOCKDEP_IS_HELD_DISCARD_CONST, 1,
			[lockdep_is_held() argument is const])
	])
]) # LIBCFS_LOCKDEP_IS_HELD

#
# LIBCFS_BITMAP_TO_ARR32
#
# Kernel commit v4.15-10794-gc724f19 introduced
# bitmap_{from,to}_arr32, which are handy functions, to move
# data back and forth between a bitmap and a u32 array
#
AC_DEFUN([LIBCFS_SRC_BITMAP_TO_ARR32], [
	LB2_LINUX_TEST_SRC([bitmap_to_arr32], [
		#include <linux/bitmap.h>
	],[
		bitmap_to_arr32(NULL, NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_BITMAP_TO_ARR32], [
	LB2_MSG_LINUX_TEST_RESULT([if 'bitmap_to_arr32()' exist],
	[bitmap_to_arr32], [
		AC_DEFINE(HAVE_BITMAP_TO_ARR32, 1,
			[bitmap_to_arr32() exist])
	])
]) # LIBCFS_BITMAP_TO_ARR32

#
# LIBCFS_TIMER_SETUP
#
# Kernel version 4.15 commit e99e88a9d2b067465adaa9c111ada99a041bef9a
# setup_timer() was replaced by timer_setup(), where the callback
# argument is the structure already holding the struct timer_list.
#
AC_DEFUN([LIBCFS_SRC_TIMER_SETUP], [
	LB2_LINUX_TEST_SRC([timer_setup], [
		#include <linux/timer.h>
	],[
		timer_setup(NULL, NULL, 0);
	])
])
AC_DEFUN([LIBCFS_TIMER_SETUP], [
	LB2_MSG_LINUX_TEST_RESULT([if setup_timer has been replaced with timer_setup],
	[timer_setup], [
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
AC_DEFUN([LIBCFS_SRC_WAIT_VAR_EVENT], [
	if test "x$lb_cv_header_linux_wait_bit_h" = xyes; then
		WAIT_BIT_H="-DHAVE_WAIT_BIT_HEADER_H=1"
	else
		WAIT_BIT_H=""
	fi
	LB2_LINUX_TEST_SRC([wait_var_event], [
		#ifdef HAVE_WAIT_BIT_HEADER_H
		#include <linux/wait_bit.h>
		#endif
		#include <linux/wait.h>
	],[
		wake_up_var(NULL);
	],[${WAIT_BIT_H}])
])
AC_DEFUN([LIBCFS_WAIT_VAR_EVENT], [
	LB2_MSG_LINUX_TEST_RESULT([if 'wait_var_event' exist],
	[wait_var_event], [
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
AC_DEFUN([LIBCFS_SRC_BITMAP_ALLOC], [
	LB2_LINUX_TEST_SRC([bitmap_alloc], [
		#include <linux/bitmap.h>
	],[
		unsigned long *map = bitmap_alloc(1, GFP_KERNEL);
		(void)map;
	])
])
AC_DEFUN([LIBCFS_BITMAP_ALLOC], [
	LB2_MSG_LINUX_TEST_RESULT([if Linux bitmap memory management exist],
	[bitmap_alloc], [
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
AC_DEFUN([LIBCFS_SRC_CLEAR_AND_WAKE_UP_BIT], [
	if test "x$lb_cv_header_linux_wait_bit_h" = xyes; then
		WAIT_BIT_H="-DHAVE_WAIT_BIT_HEADER_H=1"
	else
		WAIT_BIT_H=""
	fi
	LB2_LINUX_TEST_SRC([clear_and_wake_up_bit], [
		#ifdef HAVE_WAIT_BIT_HEADER_H
		#include <linux/wait_bit.h>
		#endif
		#include <linux/wait.h>
	],[
		clear_and_wake_up_bit(0, NULL);
	],[${WAIT_BIT_H}])
])
AC_DEFUN([LIBCFS_CLEAR_AND_WAKE_UP_BIT], [
	LB2_MSG_LINUX_TEST_RESULT([if 'clear_and_wake_up_bit' exist],
	[clear_and_wake_up_bit], [
		AC_DEFINE(HAVE_CLEAR_AND_WAKE_UP_BIT, 1,
			['clear_and_wake_up_bit' is available])
	])
]) # LIBCFS_CLEAR_AND_WAKE_UP_BIT

#
# LIBCFS_TCP_SOCK_SET_NODELAY
#
# kernel 4.18.0-293.el8
# tcp_sock_set_nodelay() was added
AC_DEFUN([LIBCFS_SRC_TCP_SOCK_SET_NODELAY], [
	LB2_LINUX_TEST_SRC([tcp_sock_set_nodelay_exists], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_nodelay(NULL);
	],[-Werror])
])
AC_DEFUN([LIBCFS_TCP_SOCK_SET_NODELAY], [
	LB2_MSG_LINUX_TEST_RESULT([if 'tcp_sock_set_nodelay()' exists],
	[tcp_sock_set_nodelay_exists], [
		AC_DEFINE(HAVE_TCP_SOCK_SET_NODELAY, 1,
			['tcp_sock_set_nodelay()' exists])
	])
]) # LIBCFS_TCP_SOCK_SET_NODELAY

#
# LIBCFS_TCP_SOCK_SET_KEEPIDLE
#
# kernel 4.18.0-293.el8
# tcp_sock_set_keepidle() was added
#
AC_DEFUN([LIBCFS_SRC_TCP_SOCK_SET_KEEPIDLE], [
	LB2_LINUX_TEST_SRC([tcp_sock_set_keepidle_exists], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_keepidle(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_TCP_SOCK_SET_KEEPIDLE], [
	LB2_MSG_LINUX_TEST_RESULT([if 'tcp_sock_set_keepidle()' exists],
	[tcp_sock_set_keepidle_exists], [
		AC_DEFINE(HAVE_TCP_SOCK_SET_KEEPIDLE, 1,
			['tcp_sock_set_keepidle()' exists])
	])
]) # LIBCFS_TCP_SOCK_SET_KEEPIDLE

#
# LIBCFS_TCP_SOCK_SET_QUICKACK
# kernel v5.7-rc6-2504-gddd061b8daed
#   tcp: add tcp_sock_set_quickack
#
AC_DEFUN([LIBCFS_SRC_TCP_SOCK_SET_QUICKACK], [
	LB2_LINUX_TEST_SRC([tcp_sock_set_quickack_exists], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_quickack(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_TCP_SOCK_SET_QUICKACK], [
	LB2_MSG_LINUX_TEST_RESULT([if 'tcp_sock_set_quickack()' exists],
	[tcp_sock_set_quickack_exists], [
		AC_DEFINE(HAVE_TCP_SOCK_SET_QUICKACK, 1,
			['tcp_sock_set_quickack()' exists])
	])
]) # LIBCFS_TCP_SOCK_SET_QUICKACK

#
# LIBCFS_TCP_SOCK_SET_KEEPINTVL
# v5.7-rc6-2508-gd41ecaac903c
# tcp: add tcp_sock_set_keepintvl
#
AC_DEFUN([LIBCFS_SRC_TCP_SOCK_SET_KEEPINTVL], [
	LB2_LINUX_TEST_SRC([tcp_sock_set_keepintvl_exists], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_keepintvl(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_TCP_SOCK_SET_KEEPINTVL], [
	LB2_MSG_LINUX_TEST_RESULT([if 'tcp_sock_set_keepintvl()' exists],
	[tcp_sock_set_keepintvl_exists], [
		AC_DEFINE(HAVE_TCP_SOCK_SET_KEEPINTVL, 1,
			['tcp_sock_set_keepintvl()' exists])
	])
]) # LIBCFS_TCP_SOCK_SET_KEEPINTVL

#
# LIBCFS_TCP_SOCK_SET_KEEPCNT
# v5.7-rc6-2509-g480aeb9639d6
# tcp: add tcp_sock_set_keepcnt
#
AC_DEFUN([LIBCFS_SRC_TCP_SOCK_SET_KEEPCNT], [
	LB2_LINUX_TEST_SRC([tcp_sock_set_keepcnt_exists], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_keepcnt(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_TCP_SOCK_SET_KEEPCNT], [
	LB2_MSG_LINUX_TEST_RESULT([if 'tcp_sock_set_keepcnt()' exists],
	[tcp_sock_set_keepcnt_exists], [
		AC_DEFINE(HAVE_TCP_SOCK_SET_KEEPCNT, 1,
			['tcp_sock_set_keepcnt()' exists])
	])
]) # LIBCFS_TCP_SOCK_SET_KEEPCNT

#
# LIBCFS_XARRAY_SUPPORT
#
# 4.19-rc5 kernel commit 3159f943aafdbacb2f94c38fdaadabf2bbde2a14
# replaced the radix tree implementation with Xarrays. This change
# introduced functionaly needed for general Xarray support
#
AC_DEFUN([LIBCFS_SRC_XARRAY_SUPPORT], [
	LB2_LINUX_TEST_SRC([xarray_support], [
		#include <linux/xarray.h>
	],[
		xa_is_value(NULL);
	],[-Werror])
])
AC_DEFUN([LIBCFS_XARRAY_SUPPORT], [
	LB2_MSG_LINUX_TEST_RESULT([if page cache uses Xarray],
	[xarray_support], [
		AC_DEFINE(HAVE_XARRAY_SUPPORT, 1,
			[kernel Xarray implementation lacks 'xa_is_value'])
	])
]) # LIBCFS_XARRAY_SUPPORT

#
# LIBCFS_NL_DUMP_EXT_ACK
#
# Kernel version 4.19-rc6 commit 4a19edb60d0203cd5bf95a8b46ea8f63fd41194c
# added extended ACK handling to Netlink dump handlers
#
AC_DEFUN([LIBCFS_SRC_NL_DUMP_EXT_ACK], [
	LB2_LINUX_TEST_SRC([netlink_dump_ext_ack], [
		#include <net/netlink.h>
	],[
		struct netlink_callback *cb = NULL;
		cb->extack = NULL;
	],[])
])
AC_DEFUN([LIBCFS_NL_DUMP_EXT_ACK], [
	LB2_MSG_LINUX_TEST_RESULT([if Netlink dump handlers support ext_ack],
	[netlink_dump_ext_ack], [
		AC_DEFINE(HAVE_NL_DUMP_WITH_EXT_ACK, 1,
			[netlink_ext_ack is handled for Netlink dump handlers])
	])
]) # LIBCFS_NL_DUMP_EXT_ACK

#
# LIBCFS_HAVE_IOV_ITER_TYPE
#
# kernel 4.20 commit 00e23707442a75b404392cef1405ab4fd498de6b
# iov_iter: Use accessor functions to access an iterator's type and direction.
#
AC_DEFUN([LIBCFS_SRC_HAVE_IOV_ITER_TYPE], [
	LB2_LINUX_TEST_SRC([macro_iov_iter_type_exists], [
		#include <linux/uio.h>
	],[
		struct iov_iter iter = { };
		enum iter_type type = iov_iter_type(&iter);
		(void)type;
	],[-Werror])
])
AC_DEFUN([LIBCFS_HAVE_IOV_ITER_TYPE], [
	LB2_MSG_LINUX_TEST_RESULT([if iov_iter_type exists],
	[macro_iov_iter_type_exists], [
		AC_DEFINE(HAVE_IOV_ITER_TYPE, 1,
			[if iov_iter_type exists])
	])
]) # LIBCFS_HAVE_IOV_ITER_TYPE

#
# LIBCFS_GENRADIX
#
# Kernel 5.0 commit ba20ba2e3743bac786dff777954c11930256075e
# implemented generic radix trees to handle very large memory
# allocation that can be used instead of vmalloc which has
# a performance penalty.
#
AC_DEFUN([LIBCFS_GENRADIX], [
LB_CHECK_EXPORT([__genradix_ptr], [lib/generic-radix-tree.c],
	[AC_DEFINE(HAVE_GENRADIX_SUPPORT, 1,
		[generic-radix-tree is present])])
]) # LIBCFS_GENRADIX

#
# LIBCFS_GET_REQUEST_KEY_AUTH
#
# kernel 5.0 commit 822ad64d7e46a8e2c8b8a796738d7b657cbb146d
# keys: Fix dependency loop between construction record and auth key
#
# Added <keys/request_key_auth-type.h> and get_request_key_auth()
# which was propagated to stable
#
AC_DEFUN([LIBCFS_SRC_GET_REQUEST_KEY_AUTH], [
	LB2_LINUX_TEST_SRC([get_request_key_auth_exported], [
		#include <linux/key.h>
		#include <linux/keyctl.h>
		#include <keys/request_key_auth-type.h>
	],[
		struct key *ring;
		const struct key *key = NULL;
		struct request_key_auth *rka = get_request_key_auth(key);

		ring = key_get(rka->dest_keyring);
	],[-Werror])
])
AC_DEFUN([LIBCFS_GET_REQUEST_KEY_AUTH], [
	LB2_MSG_LINUX_TEST_RESULT([if get_request_key_auth() is available],
	[get_request_key_auth_exported], [
		AC_DEFINE(HAVE_GET_REQUEST_KEY_AUTH, 1,
			[get_request_key_auth() is available])
	])
]) # LIBCFS_GET_REQUEST_KEY_AUTH

#
# LIBCFS_KOBJ_TYPE_DEFAULT_GROUPS
#
# Linux commit v5.1-rc3-29-gaa30f47cf666
#    kobject: Add support for default attribute groups to kobj_type
# Linux commit v5.18-rc1-2-gcdb4f26a63c3
#    kobject: kobj_type: remove default_attrs
#
AC_DEFUN([LIBCFS_SRC_KOBJ_TYPE_DEFAULT_GROUPS],[
	LB2_LINUX_TEST_SRC([kobj_type_default_groups], [
		#include <linux/kobject.h>
	],[
		struct kobj_type *kobj_type = NULL;
		void *has = kobj_type->default_groups;
		(void) has;
	])
])
AC_DEFUN([LIBCFS_KOBJ_TYPE_DEFAULT_GROUPS],[
	LB2_MSG_LINUX_TEST_RESULT([if struct kobj_type have 'default_groups' member],
	[kobj_type_default_groups], [
		AC_DEFINE(HAVE_KOBJ_TYPE_DEFAULT_GROUPS, 1,
			[struct kobj_type has 'default_groups' member])
	])
]) # LIBCFS_KOBJ_TYPE_DEFAULT_GROUPS

#
# LIBCFS_LOOKUP_USER_KEY
#
# kernel 5.3 commit 3cf5d076fb4d48979f382bc9452765bf8b79e740
# signal: Remove task parameter from force_sig
#
AC_DEFUN([LIBCFS_SRC_LOOKUP_USER_KEY], [
	LB2_LINUX_TEST_SRC([lookup_user_key_exported], [
		#include <linux/key.h>
		#include <linux/keyctl.h>
	],[
		lookup_user_key(KEY_SPEC_USER_KEYRING, 0, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_LOOKUP_USER_KEY], [
	LB2_MSG_LINUX_TEST_RESULT([if lookup_user_key() is available],
	[lookup_user_key_exported], [
		AC_DEFINE(HAVE_LOOKUP_USER_KEY, 1,
			[lookup_user_key() is available])
	])
]) # LIBCFS_LOOKUP_USER_KEY

#
# LIBCFS_CACHE_DETAIL_WRITERS
#
# kernel v5.3-rc2-1-g64a38e840ce5
# SUNRPC: Track writers of the 'channel' file to improve cache_listeners_exist
#
AC_DEFUN([LIBCFS_SRC_CACHE_DETAIL_WRITERS], [
	LB2_LINUX_TEST_SRC([cache_detail_writers_atomic], [
		#include <linux/sunrpc/cache.h>

		static struct cache_detail rsi_cache;
	],[
		atomic_set(&rsi_cache.writers, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_CACHE_DETAIL_WRITERS], [
	LB2_MSG_LINUX_TEST_RESULT([if struct cache_detail has writers],
	[cache_detail_writers_atomic], [
		AC_DEFINE(HAVE_CACHE_DETAIL_WRITERS, 1,
			[struct cache_detail has writers])
	])
]) # LIBCFS_CACHE_DETAIL_WRITERS

#
# LIBCFS_GENL_DUMPIT_INFO
#
# kernel v5.4-rc1 commit bf813b0afeae2f012f0e527a526c1b78ca21ad82
# expanded struct genl_dumpit_info to include struct genl_family.
#
AC_DEFUN([LIBCFS_SRC_GENL_DUMPIT_INFO], [
	LB2_LINUX_TEST_SRC([genl_dumpit_info], [
		#include <net/genetlink.h>
	],[
		static struct genl_dumpit_info info;

		info.family = NULL;
	],[-Werror])
])
AC_DEFUN([LIBCFS_GENL_DUMPIT_INFO], [
	LB2_MSG_LINUX_TEST_RESULT([if struct genl_dumpit_info has family field],
	[genl_dumpit_info], [
		AC_DEFINE(HAVE_GENL_DUMPIT_INFO, 1,
			[struct genl_dumpit_info has family field])
	])
]) # LIBCFS_GENL_DUMPIT_INFO

#
# LIBCFS_KALLSYMS_LOOKUP
#
# kernel v5.6-11591-g0bd476e6c671
# kallsyms: unexport kallsyms_lookup_name() and kallsyms_on_each_symbol()
AC_DEFUN([LIBCFS_KALLSYMS_LOOKUP], [
LB_CHECK_EXPORT([kallsyms_lookup_name], [kernel/kallsyms.c],
	[AC_DEFINE(HAVE_KALLSYMS_LOOKUP_NAME, 1,
		[kallsyms_lookup_name is exported by kernel])])
]) # LIBCFS_KALLSYMS_LOOKUP

#
# v5.5-8862-gd56c0d45f0e2
# proc: decouple proc from VFS with "struct proc_ops"
#
AC_DEFUN([LIBCFS_SRC_HAVE_PROC_OPS], [
	LB2_LINUX_TEST_SRC([proc_ops], [
		#include <linux/proc_fs.h>

		static struct proc_ops *my_proc;
	],[
		my_proc->proc_lseek = NULL;
	],[-Werror])
]) # LIBCFS_SRC_HAVE_PROC_OPS
AC_DEFUN([LIBCFS_HAVE_PROC_OPS], [
	LB2_MSG_LINUX_TEST_RESULT([if struct proc_ops exists],
	[proc_ops], [
		AC_DEFINE(HAVE_PROC_OPS, 1,
			[struct proc_ops exists])
	])
]) # LIBCFS_HAVE_PROC_OPS

#
# LIBCFS_IP6_SET_PREF
#
# kernel v5.8-rc1~165^2~71^2~3 commit 18d5ad62327576cbb1e5b9938a59d63ac0c15832
# ipv6: add ip6_sock_set_addr_preferences
#
AC_DEFUN([LIBCFS_SRC_IP6_SET_PREF], [
	LB2_LINUX_TEST_SRC([ip6_set_pref_test], [
		#include <net/ipv6.h>
	],[
		ip6_sock_set_addr_preferences(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_IP6_SET_PREF], [
	LB2_MSG_LINUX_TEST_RESULT([if ip6_sock_set_addr_preferences() exists],
	[ip6_set_pref_test], [
		AC_DEFINE(HAVE_IP6_SET_PREF, 1,
			[if ip6_sock_set_addr_preferences exists])
	])
]) # LIBCFS_IP6_SET_PREF

#
# LIBCFS_IP_SET_TOS
#
# kernel v5.8-rc1~165^2~71^2~3 commit 6ebf71bab9fb476fc8132be4c12b88201278f0ca
# ipv4: add ip_sock_set_tos
#
AC_DEFUN([LIBCFS_SRC_IP_SET_TOS], [
	LB2_LINUX_TEST_SRC([ip_set_tos_test], [
		#include <net/ip.h>
	],[
		ip_sock_set_tos(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_IP_SET_TOS], [
	LB2_MSG_LINUX_TEST_RESULT([if ip_sock_set_tos() exists],
	[ip_set_tos_test], [
		AC_DEFINE(HAVE_IP_SET_TOS, 1,
			[if ip_sock_set_tos exists])
	])
]) # LIBCFS_IP_SET_TOS

#
# LIBCFS_VMALLOC_2ARGS
#
# kernel v5.8-rc1~201^2~19
# mm: remove the pgprot argument to __vmalloc
AC_DEFUN([LIBCFS_SRC_VMALLOC_2ARGS], [
	LB2_LINUX_TEST_SRC([vmalloc_2args], [
		#include <linux/vmalloc.h>
	],[
		__vmalloc(0, 0);
	],[])
])
AC_DEFUN([LIBCFS_VMALLOC_2ARGS], [
	LB2_MSG_LINUX_TEST_RESULT([if __vmalloc has 2 args],
	[vmalloc_2args], [
		AC_DEFINE(HAVE_VMALLOC_2ARGS, 1,
			[__vmalloc only takes 2 args.])
	])
]) # LIBCFS_VMALLOC_2ARGS

#
# LIBCFS_HAVE_NR_UNSTABLE_NFS
#
# kernel v5.8-rc1~201^2~75
# mm/writeback: discard NR_UNSTABLE_NFS, use NR_WRITEBACK instead
#
AC_DEFUN([LIBCFS_SRC_HAVE_NR_UNSTABLE_NFS], [
	LB2_LINUX_TEST_SRC([nr_unstable_nfs_exists], [
		#include <linux/mm.h>

		int i;
	],[
		i = NR_UNSTABLE_NFS;
	],[-Werror])
])
AC_DEFUN([LIBCFS_HAVE_NR_UNSTABLE_NFS], [
	LB2_MSG_LINUX_TEST_RESULT([if NR_UNSTABLE_NFS still in use],
	[nr_unstable_nfs_exists], [
		AC_DEFINE(HAVE_NR_UNSTABLE_NFS, 1,
			[NR_UNSTABLE_NFS is still in use.])
	])
]) # LIBCFS_HAVE_NR_UNSTABLE_NFS

#
# LIBCFS_NR_UNSTABLE_NFS_DEPRECATED
#
# SLES15 still defines NR_UNSTABLE_NFS, but DEPRECATED it
#
AC_DEFUN([LIBCFS_NR_UNSTABLE_NFS_DEPRECATED], [
	AC_MSG_CHECKING([if NR_UNSTABLE_NFS is defined but DEPRECATED])
	AS_IF([grep -q -E "NFS unstable pages - DEPRECATED DO NOT USE" "$LINUX/include/linux/mmzone.h" 2>/dev/null], [
		AC_DEFINE([HAVE_NR_UNSTABLE_NFS_DEPRECATED], 1,
			  [NR_UNSTABLE_NFS is defined but deprecated])
		AC_MSG_RESULT(yes)
	],[
		AC_MSG_RESULT(no)
	])
]) # LIBCFS_NR_UNSTABLE_NFS_DEPRECATED

#
# LIBCFS_HAVE_MMAP_LOCK
#
# kernel v5.8-rc1~83^2~24
# mmap locking API: rename mmap_sem to mmap_lock
#
AC_DEFUN([LIBCFS_SRC_HAVE_MMAP_LOCK], [
	LB2_LINUX_TEST_SRC([mmap_write_lock], [
		#include <linux/mm.h>
	],[
		mmap_write_lock(NULL);
	],[])
])
AC_DEFUN([LIBCFS_HAVE_MMAP_LOCK], [
	LB2_MSG_LINUX_TEST_RESULT([if mmap_lock API is available],
	[mmap_write_lock], [
		AC_DEFINE(HAVE_MMAP_LOCK, 1,
			[mmap_lock API is available.])
	])
]) # LIBCFS_HAVE_MMAP_LOCK

#
# LIBCFS_KERNEL_SETSOCKOPT
#
# kernel v5.8-rc1~165^2~59^2
# net: remove kernel_setsockopt
AC_DEFUN([LIBCFS_SRC_KERNEL_SETSOCKOPT], [
	LB2_LINUX_TEST_SRC([kernel_setsockopt_exists], [
		#include <linux/net.h>
	],[
		kernel_setsockopt(NULL, 0, 0, NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_KERNEL_SETSOCKOPT], [
	LB2_MSG_LINUX_TEST_RESULT([if kernel_setsockopt still in use],
	[kernel_setsockopt_exists], [
	AC_DEFINE(HAVE_KERNEL_SETSOCKOPT, 1,
		[kernel_setsockopt still in use])
	])
]) # LIBCFS_KERNEL_SETSOCKOPT

#
# LIBCFS_USER_UID_KEYRING
#
# kernel 5.2 commit 0f44e4d976f9 removed uid_keyring
# from the user_struct struct
#
AC_DEFUN([LIBCFS_SRC_USER_UID_KEYRING], [
	LB2_LINUX_TEST_SRC([user_uid_keyring_exists], [
		#include <linux/sched/user.h>
	],[
		((struct user_struct *)0)->uid_keyring = NULL;
	],[-Werror])
])
AC_DEFUN([LIBCFS_USER_UID_KEYRING], [
	AC_MSG_CHECKING([if uid_keyring exists])
	LB2_LINUX_TEST_RESULT([user_uid_keyring_exists], [
		AC_DEFINE(HAVE_USER_UID_KEYRING, 1,
			[uid_keyring exists])
	])
]) # LIBCFS_USER_UID_KEYRING

#
# LIBCFS_KEY_NEED_UNLINK
#
# kernel 5.8 commit 8c0637e950d68933a67f7438f779d79b049b5e5c
# keys: Make the KEY_NEED_* perms an enum rather than a mask
#
AC_DEFUN([LIBCFS_SRC_KEY_NEED_UNLINK], [
	LB2_LINUX_TEST_SRC([key_need_unlink_exists], [
		#include <linux/key.h>
		#include <linux/keyctl.h>
	],[
		lookup_user_key(0, 0, KEY_NEED_UNLINK);
	],[-Werror])
])
AC_DEFUN([LIBCFS_KEY_NEED_UNLINK], [
	LB2_MSG_LINUX_TEST_RESULT([if KEY_NEED_UNLINK exists],
	[key_need_unlink_exists], [
		AC_DEFINE(HAVE_KEY_NEED_UNLINK, 1,
			[KEY_NEED_UNLINK exists])
	])
]) # LIBCFS_KEY_NEED_UNLINK

#
# LIBCFS_SEC_RELEASE_SECCTX
#
# kernel linux-hwe-5.8 (5.8.0-22.23~20.04.1)
# LSM: Use lsmcontext in security_release_secctx
AC_DEFUN([LIBCFS_SRC_SEC_RELEASE_SECCTX], [
	LB2_LINUX_TEST_SRC([security_release_secctx_1arg], [
		#include <linux/security.h>
	],[
		security_release_secctx(NULL);
	],[])
])
AC_DEFUN([LIBCFS_SEC_RELEASE_SECCTX], [
	LB2_MSG_LINUX_TEST_RESULT([if security_release_secctx has 1 arg],
	[security_release_secctx_1arg], [
		AC_DEFINE(HAVE_SEC_RELEASE_SECCTX_1ARG, 1,
			[security_release_secctx has 1 arg.])
	])
]) # LIBCFS_SEC_RELEASE_SECCTX

#
# LIBCFS_HAVE_KMAP_LOCAL
#
# Linux commit v5.10-rc2-80-gf3ba3c710ac5
#   mm/highmem: Provide kmap_local*
#
AC_DEFUN([LIBCFS_SRC_HAVE_KMAP_LOCAL], [
	LB2_LINUX_TEST_SRC([kmap_local_page], [
		#include <linux/highmem.h>
	],[
		struct page *pg = NULL;
		void *kaddr = kmap_local_page(pg);

		kunmap_local(kaddr);
	],[-Werror])
])
AC_DEFUN([LIBCFS_HAVE_KMAP_LOCAL], [
	LB2_MSG_LINUX_TEST_RESULT([if 'kmap_local*' are available],
	[kmap_local_page], [
		AC_DEFINE(HAVE_KMAP_LOCAL, 1,
			[kmap_local_* functions are available])
	],[
		## Map kmap_local_page to kmap_atomic for older kernels
		AC_DEFINE([kmap_local_page(p)], [kmap_atomic(p)],
			  [need kmap_local_page map to atomic])
		AC_DEFINE([kunmap_local(kaddr)], [kunmap_atomic((kaddr))],
			  [need kunmap_local map to atomic])
	])
]) # LIBCFS_HAVE_KMAP_LOCAL

#
# LIBCFS_HAVE_KFREE_SENSITIVE
#
# kernel v5.10-rc1~3
# mm: remove kzfree() compatibility definition
#
AC_DEFUN([LIBCFS_SRC_HAVE_KFREE_SENSITIVE], [
	LB2_LINUX_TEST_SRC([kfree_sensitive_exists], [
		#include <linux/slab.h>
	],[
		kfree_sensitive(NULL);
	], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_KFREE_SENSITIVE], [
	LB2_MSG_LINUX_TEST_RESULT([if kfree_sensitive() is available],
	[kfree_sensitive_exists], [
		AC_DEFINE(HAVE_KFREE_SENSITIVE, 1,
			[kfree_sensitive() is available.])
	])
]) # LIBCFS_HAVE_KFREE_SENSITIVE

#
# LIBCFS_HAVE_CRYPTO_SHA2_HEADER
#
# Kernel v5.10-rc1-114-ga24d22b225ce
# crypto: sha - split sha.h into sha1.h and sha2.h
#
AC_DEFUN([LIBCFS_SRC_HAVE_CRYPTO_SHA2_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([crypto/sha2.h], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_CRYPTO_SHA2_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([crypto/sha2.h], [
		AC_DEFINE(HAVE_CRYPTO_SHA2_HEADER, 1,
			[crypto/sha2.h is present])
	])
]) # LIBCFS_HAVE_CRYPTO_SHA2_HEADER

#
# LIBCFS_HAVE_LIST_CMP_FUNC_T
#
# kernel 5.10.70 commit 4f0f586bf0c898233d8f316f471a21db2abd522d
# treewide: Change list_sort to use const pointers
AC_DEFUN([LIBCFS_SRC_HAVE_LIST_CMP_FUNC_T], [
	LB2_LINUX_TEST_SRC([list_cmp_func_t_exists], [
		#include <linux/list_sort.h>
	],[
		list_cmp_func_t cmp;
		(void)cmp;
	], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_LIST_CMP_FUNC_T], [
	LB2_MSG_LINUX_TEST_RESULT([if list_cmp_func_t type is defined],
	[list_cmp_func_t_exists], [
		AC_DEFINE(HAVE_LIST_CMP_FUNC_T, 1,
			[list_cmp_func_t type is defined])
	])
]) # LIBCFS_HAVE_LIST_CMP_FUNC_T

#
# LIBCFS_NLA_STRLCPY
#
# Kernel version 5.10-rc3 commit 872f690341948b502c93318f806d821c56772c42
# replaced nla_strlcpy() with nla_strscpy().
#
AC_DEFUN([LIBCFS_SRC_NLA_STRLCPY], [
	LB2_LINUX_TEST_SRC([nla_strlcpy], [
		#include <net/netlink.h>
	],[
		if (nla_strlcpy(NULL, NULL, 0) == 0)
			return -EINVAL;
	])
])
AC_DEFUN([LIBCFS_NLA_STRLCPY], [
	LB2_MSG_LINUX_TEST_RESULT([if 'nla_strlcpy()' still exists],
	[nla_strlcpy], [
		AC_DEFINE(HAVE_NLA_STRLCPY, 1,
			['nla_strlcpy' is available])
	])
]) # LIBCFS_NLA_STRLCPY

#
# LIBCFS_RB_FIND
#
# Kernel v5.11-20-g2d24dd5798d0
#   rbtree: Add generic add and find helpers
#
AC_DEFUN([LIBCFS_SRC_RB_FIND], [
	LB2_LINUX_TEST_SRC([rb_find], [
		#include <linux/rbtree.h>
		static int cmp(const void *key, const struct rb_node *node)
		{
			return 0;
		}
	],[
		void *key = NULL;
		struct rb_root *tree = NULL;
		struct rb_node *node __maybe_unused = rb_find(key, tree, cmp);
	])
])
AC_DEFUN([LIBCFS_RB_FIND], [
	LB2_MSG_LINUX_TEST_RESULT([if 'rb_find()' is available],
	[rb_find], [
		AC_DEFINE(HAVE_RB_FIND, 1,
			['rb_find()' is available])
	])
]) # LIBCFS_RB_FIND

#
# LIBCFS_LINUX_FORTIFY_STRING_HEADER
#
# Linux v5.11-11104-ga28a6e860c6c
#  string.h: move fortified functions definitions in a dedicated header.
#
AC_DEFUN([LIBCFS_SRC_LINUX_FORTIFY_STRING_HEADER],[
	LB2_LINUX_TEST_SRC([linux_fortify_string_header], [
		#include <linux/fortify-string.h>
	],[
	],[])
])
AC_DEFUN([LIBCFS_LINUX_FORTIFY_STRING_HEADER],[
	LB2_MSG_LINUX_TEST_RESULT([if linux/fortify-string.h header available],
	[linux_fortify_string_header], [
		AC_DEFINE(HAVE_LINUX_FORTIFY_STRING_HEADER, 1,
			[linux/fortify-string.h header available])
	])
]) # LIBCFS_LINUX_FORTIFY_STRING_HEADER

#
# LIBCFS_HAVE_CIPHER_HEADER
#
# Kernel 5.12 commit 0eb76ba29d16df2951d37c54ca279c4e5630b071
# crypto: remove cipher routines from public crypto API
#
AC_DEFUN([LIBCFS_SRC_HAVE_CIPHER_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([crypto/internal/cipher.h], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_CIPHER_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([crypto/internal/cipher.h], [
		AC_DEFINE(HAVE_CIPHER_H, 1,
			[crypto/internal/cipher.h is present])
	])
]) # LIBCFS_HAVE_CIPHER_HEADER

#
# LIBCFS_HAVE_TASK_RUNNING
#
# Kernel 5.13-rc6 commit b03fbd4ff24c5f075e58eb19261d5f8b3e40d
# introduced task_is_running() macro.
#
AC_DEFUN([LIBCFS_SRC_HAVE_TASK_IS_RUNNING], [
	LB2_LINUX_TEST_SRC([task_is_running], [
		#include <linux/sched.h>
	],[
		if (task_is_running(current))
			schedule();
	], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_TASK_IS_RUNNING], [
	LB2_MSG_LINUX_TEST_RESULT([if task_is_running() is defined],
	[task_is_running], [
		AC_DEFINE(HAVE_TASK_IS_RUNNING, 1,
			[task_is_running() is defined])
	])
]) # LIBCFS_HAVE_TASK_IS_RUNNING

#
# LIBCFS_LINUX_STDARG_HEADER
#
# Kernel 5.14-rc5 commit c0891ac15f0428ffa81b2e818d416bdf3cb74ab6
# isystem: ship and use stdarg.h
#
AC_DEFUN([LIBCFS_SRC_LINUX_STDARG_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/stdarg.h], [-Werror])
])
AC_DEFUN([LIBCFS_LINUX_STDARG_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/stdarg.h], [
		AC_DEFINE(HAVE_LINUX_STDARG_HEADER, 1,
			[linux/stdarg.h is present])
	])
]) # LIBCFS_LINUX_STDARG_HEADER

#
# LIBCFS_HAVE_PANIC_NOTIFIER_HEADER
#
# Kernel 5.14 commit f39650de687e35766572ac89dbcd16a5911e2f0a
# kernel.h: split out panic and oops helpers
#
AC_DEFUN([LIBCFS_SRC_HAVE_PANIC_NOTIFIER_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/panic_notifier.h], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_PANIC_NOTIFIER_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/panic_notifier.h], [
		AC_DEFINE(HAVE_PANIC_NOTIFIER_H, 1,
			[linux/panic_notifier.h is present])
	])
]) # LIBCFS_HAVE_PANIC_NOTIFIER_HEADER

#
# LIBCFS_PARAM_SET_UINT_MINMAX
#
# Kernel 5.15-rc1 commit 2a14c9ae15a38148484a128b84bff7e9ffd90d68
# moved param_set_uint_minmax to common code
#
AC_DEFUN([LIBCFS_SRC_PARAM_SET_UINT_MINMAX],[
	LB2_LINUX_TEST_SRC([param_set_uint_minmax], [
		#include <linux/moduleparam.h>
	],[
		param_set_uint_minmax(NULL, NULL, 0, 0);
	], [])
])
AC_DEFUN([LIBCFS_PARAM_SET_UINT_MINMAX],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'param_set_uint_minmax' exist],
	[param_set_uint_minmax], [
		AC_DEFINE(HAVE_PARAM_SET_UINT_MINMAX, 1,
			['param_set_uint_minmax' is available])
	])
]) # LIBCFS_PARAM_SET_UINT_MINMAX

#
# LIBCFS_LINUX_BLK_INTEGRITY_HEADER
#
# Kernel 5.15-rc6 commit fe45e630a1035aea94c29016f2598bbde149bbe3
# block: move integrity handling out of <linux/blkdev.h>
#
AC_DEFUN([LIBCFS_SRC_LINUX_BLK_INTEGRITY_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/blk-integrity.h], [-Werror])
])
AC_DEFUN([LIBCFS_LINUX_BLK_INTEGRITY_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/blk-integrity.h], [
		AC_DEFINE(HAVE_LINUX_BLK_INTEGRITY_HEADER, 1,
			[linux/blk-integrity.h is present])
	])
]) # LIBCFS_LINUX_BLK_INTEGRITY_HEADER

#
# LIBCFS_PDE_DATA_EXISTS
#
# Linux commit v5.16-11573-g6dfbbae14a7b
#    introduce pde_data()
# Linux commit v5.16-11574-g359745d78351
#    remove PDE_DATA()
#
AC_DEFUN([LIBCFS_SRC_PDE_DATA_EXISTS],[
	LB2_LINUX_TEST_SRC([pde_data], [
		#include <linux/proc_fs.h>
	],[
		struct inode *inode = NULL;
		void *data =pde_data(inode);
		(void)data;
	],[])
])
AC_DEFUN([LIBCFS_PDE_DATA_EXISTS],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'pde_data' exist],
	[pde_data], [
		AC_DEFINE(HAVE_pde_data, 1, [function pde_data() available])
	],[
		AC_DEFINE(pde_data(inode), PDE_DATA(inode),
			  [function pde_data() unavailable])
	])
]) # LIBCFS_PDE_DATA_EXISTS

#
# LIBCFS_BIO_ALLOC_WITH_BDEV
#
# Linux commit v5.17-rc2-21-g07888c665b40
#   block: pass a block_device and opf to bio_alloc
#
AC_DEFUN([LIBCFS_SRC_BIO_ALLOC_WITH_BDEV],[
	LB2_LINUX_TEST_SRC([bio_alloc_with_bdev], [
		#include <linux/bio.h>
	],[
		struct block_device *bdev = NULL;
		unsigned short nr_vecs = 1;
		gfp_t gfp = GFP_KERNEL;
		struct bio *bio = bio_alloc(bdev, nr_vecs, REQ_OP_WRITE, gfp);
		(void) bio;
	],[])
])
AC_DEFUN([LIBCFS_BIO_ALLOC_WITH_BDEV],[
	LB2_MSG_LINUX_TEST_RESULT([if bio_alloc() takes a struct block_device],
	[bio_alloc_with_bdev], [
		AC_DEFINE(HAVE_BIO_ALLOC_WITH_BDEV, 1,
			[bio_alloc() takes a struct block_device])
	])
]) # LIBCFS_BIO_ALLOC_WITH_BDEV

#
# LIBCFS_TIMER_DELETE_SYNC
#
# Linux commit v6.1-rc1-7-g9a5a30568697
#   timers: Get rid of del_singleshot_timer_sync()
# Linux commit v6.1-rc1-11-g9b13df3fb64e
#   timers: Rename del_timer_sync() to timer_delete_sync()
#
AC_DEFUN([LIBCFS_SRC_TIMER_DELETE_SYNC],[
	LB2_LINUX_TEST_SRC([timer_delete_sync], [
		#include <linux/timer.h>
	],[
		struct timer_list *timer = NULL;
		(void)timer_delete_sync(timer);
	],[])
])
AC_DEFUN([LIBCFS_TIMER_DELETE_SYNC],[
	LB2_MSG_LINUX_TEST_RESULT([if timer_delete_sync() is available],
	[timer_delete_sync], [
		AC_DEFINE(HAVE_TIMER_DELETE_SYNC, 1,
			[timer_delete_sync() is available])
	],[
		AC_DEFINE(timer_delete_sync(t), del_timer_sync(t),
			[timer_delete_sync() not is available])
	])
]) # LIBCFS_TIMER_DELETE_SYNC

#
# LIBCFS_TIMER_DELETE_SYNC
#
# Linux commit v6.1-rc1-12-gbb663f0f3c39
#   timers: Rename del_timer() to timer_delete()
#
AC_DEFUN([LIBCFS_SRC_TIMER_DELETE],[
	LB2_LINUX_TEST_SRC([timer_delete], [
		#include <linux/timer.h>
	],[
		struct timer_list *timer = NULL;
		(void)timer_delete(timer);
	],[])
])
AC_DEFUN([LIBCFS_TIMER_DELETE],[
	LB2_MSG_LINUX_TEST_RESULT([if timer_delete() is available],
	[timer_delete], [
		AC_DEFINE(HAVE_TIMER_DELETE, 1,
			[timer_delete() is available])
	],[
		AC_DEFINE(timer_delete(t), del_timer(t),
			[timer_delete() not is available])
	])
]) # LIBCFS_TIMER_DELETE

#
# LIBCFS_CONSTIFY_CTR_TABLE
#
# Linux commit v6.10-12269-g78eb4ea25cd5
#   sysctl: treewide: constify the ctl_table argument of proc_handlers
#
AC_DEFUN([LIBCFS_SRC_CONSTIFY_CTR_TABLE],[
	LB2_LINUX_TEST_SRC([constify_struct_ctl_table], [
		#include <linux/sysctl.h>

		static int handler(const struct ctl_table *table, int write,
				   void __user *buf, size_t *lenp, loff_t *ppos)
		{
			return 0;
		}
	],[
		static struct ctl_table ctl_tbl __attribute__ ((unused)) = {
			.proc_handler	= &handler,
		};
	],[-Werror])
])
AC_DEFUN([LIBCFS_CONSTIFY_CTR_TABLE],[
	LB2_MSG_LINUX_TEST_RESULT(
	[if struct ctl_table argument to proc_handler() is const],
	[constify_struct_ctl_table], [
		AC_DEFINE(HAVE_CONST_CTR_TABLE, 1,
			[struct ctl_table argument to proc_handler() is const])
	])
]) # LIBCFS_CONSTIFY_CTR_TABLE

#
# LIBCFS_BLK_INTEGRITY_NOVERIFY
#
# Linux commit v6.10-rc3-25-g9f4aa46f2a74
#   block: invert the BLK_INTEGRITY_{GENERATE,VERIFY} flags
#
AC_DEFUN([LIBCFS_SRC_BLK_INTEGRITY_NOVERIFY], [
	LB2_LINUX_TEST_SRC([blk_integrity_noverify], [
		#include <linux/blk-integrity.h>
	],[
		int flag __attribute__ ((unused)) = BLK_INTEGRITY_NOVERIFY;
	],[-Werror])
])
AC_DEFUN([LIBCFS_BLK_INTEGRITY_NOVERIFY], [
	LB2_MSG_LINUX_TEST_RESULT([if BLK_INTEGRITY_NOVERIFY is available],
	[blk_integrity_noverify], [
		AC_DEFINE(HAVE_BLK_INTEGRITY_NOVERIFY, 1,
			[BLK_INTEGRITY_NOVERIFY is available])
	])
]) # LIBCFS_BLK_INTEGRITY_NOVERIFY

dnl #
dnl # Generate and compile all of the kernel API test cases to determine
dnl # which interfaces are available.  By invoking the kernel build system
dnl # only once the compilation can be done in parallel significantly
dnl # speeding up the process.
dnl #
AC_DEFUN([LIBCFS_PROG_LINUX_SRC], [
	# 3.11
	LIBCFS_SRC_KTIME_GET_TS64
	# 3.12
	LIBCFS_SRC_PREPARE_TO_WAIT_EVENT
	LIBCFS_SRC_KERNEL_PARAM_OPS
	LIBCFS_SRC_KTIME_ADD
	LIBCFS_SRC_KTIME_AFTER
	LIBCFS_SRC_KTIME_BEFORE
	LIBCFS_SRC_KTIME_COMPARE
	LIBCFS_SRC_SHRINKER_COUNT
	# 3.13
	LIBCFS_SRC_MATCH_WILDCARD
	# 3.14
	LIBCFS_SRC_HAVE_MAPPING_AS_EXITING_FLAG
	# 3.15
	LIBCFS_SRC_IOV_ITER_HAS_TYPE
	# 3.16
	LIBCFS_SRC_HAVE_GLOB
	# 3.17
	LIBCFS_SRC_TIMESPEC64
	LIBCFS_SRC_KTIME_GET_NS
	LIBCFS_SRC_KTIME_GET_REAL_TS64
	LIBCFS_SRC_KTIME_GET_REAL_SECONDS
	LIBCFS_SRC_KTIME_GET_REAL_NS
	LIBCFS_SRC_KTIME_TO_TIMESPEC64
	LIBCFS_SRC_TIMESPEC64_SUB
	LIBCFS_SRC_TIMESPEC64_TO_KTIME
	# 3.19
	LIBCFS_SRC_KTIME_GET_SECONDS
	LIBCFS_SRC_WAIT_WOKEN
	# 4.0
	LIBCFS_SRC_KTIME_MS_DELTA
	# 4.1
	LIBCFS_SRC_KERNEL_PARAM_LOCK
	# 4.2
	LIBCFS_SRC_STRSCPY_EXISTS
	LIBCFS_SRC_HAVE_TOPOLOGY_SIBLING_CPUMASK
	# 4.4
	LIBCFS_SRC_KSTRTOBOOL_FROM_USER
	LIBCFS_SRC_NETLINK_CALLBACK_START
	# 4.5
	LIBCFS_SRC_CRYPTO_HASH_HELPERS
	LIBCFS_SRC_RHASHTABLE_REPLACE
	# 4.6
	LIBCFS_SRC_BROKEN_HASH_64
	LIBCFS_SRC_STACKTRACE_OPS_ADDRESS_RETURN_INT
	LIBCFS_SRC_GET_USER_PAGES_6ARG
	LIBCFS_SRC_STRINGHASH
	# 4.7
	LIBCFS_SRC_RHASHTABLE_INSERT_FAST
	LIBCFS_SRC_RHASHTABLE_WALK_INIT_3ARG
	# 4.8
	LIBCFS_SRC_RHASHTABLE_LOOKUP
	LIBCFS_SRC_RHLTABLE
	LIBCFS_SRC_STACKTRACE_OPS
	# 4.9
	LIBCFS_SRC_GET_USER_PAGES_GUP_FLAGS
	LIBCFS_SRC_RHASHTABLE_WALK_ENTER
	# 4.10
	LIBCFS_SRC_HOTPLUG_STATE_MACHINE
	LIBCFS_SRC_NLA_PUT_U64_64BIT
	LIBCFS_SRC_HAVE_NODE_NR_WRITEBACK
	# 4.11
	LIBCFS_SRC_NL_EXT_ACK
	LIBCFS_SRC_RHASHTABLE_LOOKUP_GET_INSERT_FAST
	LIBCFS_SRC_SCHED_HEADERS
	LIBCFS_SRC_KREF_READ
	LIBCFS_SRC_RHT_BUCKET_VAR
	# 4.12
	LIBCFS_SRC_CPUS_READ_LOCK
	LIBCFS_SRC_HAVE_PROCESSOR_HEADER
	LIBCFS_SRC_WAIT_QUEUE_TASK_LIST_RENAME
	LIBCFS_SRC_WAIT_BIT_QUEUE_ENTRY_EXISTS
	LIBCFS_SRC_REFCOUNT_T
	LIBCFS_SRC_MEMALLOC_NORECLAIM
	# 4.13
	LIBCFS_SRC_NLA_STRDUP
	LIBCFS_SRC_WAIT_QUEUE_ENTRY
	# 4.14
	LIBCFS_SRC_DEFINE_TIMER
	LIBCFS_SRC_NEW_KERNEL_WRITE
	LIBCFS_SRC_NEW_KERNEL_READ
	# 4.15
	LIBCFS_SRC_BITMAP_TO_ARR32
	LIBCFS_SRC_TIMER_SETUP
	# 4.16
	LIBCFS_SRC_HAVE_NS_TO_TIMESPEC64
	LIBCFS_SRC_WAIT_VAR_EVENT
	# 4.17
	LIBCFS_SRC_BITMAP_ALLOC
	LIBCFS_SRC_CLEAR_AND_WAKE_UP_BIT
	# 4.18
	LIBCFS_SRC_TCP_SOCK_SET_NODELAY
	LIBCFS_SRC_TCP_SOCK_SET_KEEPIDLE
	# 4.19
	LIBCFS_SRC_XARRAY_SUPPORT
	LIBCFS_SRC_NL_DUMP_EXT_ACK
	# 4.20
	LIBCFS_SRC_HAVE_IOV_ITER_TYPE
	# 5.0
	LIBCFS_SRC_MM_TOTALRAM_PAGES_FUNC
	LIBCFS_SRC_GET_REQUEST_KEY_AUTH
	# 5.2
	LIBCFS_SRC_KOBJ_TYPE_DEFAULT_GROUPS
	LIBCFS_SRC_USER_UID_KEYRING
	# 5.3
	LIBCFS_SRC_LOOKUP_USER_KEY
	LIBCFS_SRC_CACHE_DETAIL_WRITERS
	# 5.4
	LIBCFS_SRC_GENL_DUMPIT_INFO
	# 5.6
	LIBCFS_SRC_HAVE_PROC_OPS
	# 5.7
	LIBCFS_SRC_TCP_SOCK_SET_QUICKACK
	LIBCFS_SRC_TCP_SOCK_SET_KEEPINTVL
	LIBCFS_SRC_TCP_SOCK_SET_KEEPCNT
	# 5.8
	LIBCFS_SRC_IP6_SET_PREF
	LIBCFS_SRC_IP_SET_TOS
	LIBCFS_SRC_VMALLOC_2ARGS
	LIBCFS_SRC_HAVE_NR_UNSTABLE_NFS
	LIBCFS_SRC_KERNEL_SETSOCKOPT
	LIBCFS_SRC_KEY_NEED_UNLINK
	LIBCFS_SRC_SEC_RELEASE_SECCTX
	# 5.10
	LIBCFS_SRC_HAVE_KMAP_LOCAL
	LIBCFS_SRC_HAVE_KFREE_SENSITIVE
	LIBCFS_SRC_HAVE_CRYPTO_SHA2_HEADER
	LIBCFS_SRC_HAVE_LIST_CMP_FUNC_T
	LIBCFS_SRC_NLA_STRLCPY
	# 5.12
	LIBCFS_SRC_RB_FIND
	LIBCFS_SRC_LINUX_FORTIFY_STRING_HEADER
	LIBCFS_SRC_HAVE_CIPHER_HEADER
	# 5.13
	LIBCFS_SRC_HAVE_TASK_IS_RUNNING
	# 5.14
	LIBCFS_SRC_LINUX_STDARG_HEADER
	LIBCFS_SRC_HAVE_PANIC_NOTIFIER_HEADER
	# 5.15
	LIBCFS_SRC_PARAM_SET_UINT_MINMAX
	# 5.17
	LIBCFS_SRC_PDE_DATA_EXISTS
	LIBCFS_SRC_BIO_ALLOC_WITH_BDEV
	# 6.2
	LIBCFS_SRC_TIMER_DELETE_SYNC
	LIBCFS_SRC_TIMER_DELETE
	# 6.11
	LIBCFS_SRC_CONSTIFY_CTR_TABLE
	LIBCFS_SRC_BLK_INTEGRITY_NOVERIFY
])

dnl #
dnl # Check results of kernel interface tests.
dnl #
AC_DEFUN([LIBCFS_PROG_LINUX_RESULTS], [
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
	# 3.13
	LIBCFS_MATCH_WILDCARD
	# 3.14
	LIBCFS_HAVE_MAPPING_AS_EXITING_FLAG
	# 3.15
	LIBCFS_IOV_ITER_HAS_TYPE
	# 3.16
	LIBCFS_HAVE_GLOB
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
	LIBCFS_WAIT_WOKEN
	# 4.0
	LIBCFS_KTIME_MS_DELTA
	# 4.1
	LIBCFS_KERNEL_PARAM_LOCK
	# 4.2
	LIBCFS_STRSCPY_EXISTS
	LIBCFS_HAVE_TOPOLOGY_SIBLING_CPUMASK
	# 4.4
	LIBCFS_KSTRTOBOOL_FROM_USER
	LIBCFS_NETLINK_CALLBACK_START
	# 4.5
	LIBCFS_CRYPTO_HASH_HELPERS
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
	LIBCFS_NLA_PUT_U64_64BIT
	LIBCFS_HAVE_NODE_NR_WRITEBACK
	# 4.11
	LIBCFS_NL_EXT_ACK
	LIBCFS_RHASHTABLE_LOOKUP_GET_INSERT_FAST
	LIBCFS_SCHED_HEADERS
	LIBCFS_KREF_READ
	LIBCFS_RHT_BUCKET_VAR
	# 4.12
	LIBCFS_CPUS_READ_LOCK
	LIBCFS_HAVE_PROCESSOR_HEADER
	LIBCFS_WAIT_QUEUE_TASK_LIST_RENAME
	LIBCFS_WAIT_BIT_QUEUE_ENTRY_EXISTS
	LIBCFS_REFCOUNT_T
	LIBCFS_MEMALLOC_NORECLAIM
	# 4.13
	LIBCFS_NLA_STRDUP
	LIBCFS_WAIT_QUEUE_ENTRY
	# 4.14
	LIBCFS_DEFINE_TIMER
	LIBCFS_NEW_KERNEL_WRITE
	LIBCFS_NEW_KERNEL_READ
	# 4.15
	LIBCFS_BITMAP_TO_ARR32
	LIBCFS_TIMER_SETUP
	# 4.16
	LIBCFS_HAVE_NS_TO_TIMESPEC64
	LIBCFS_WAIT_VAR_EVENT
	# 4.17
	LIBCFS_BITMAP_ALLOC
	LIBCFS_CLEAR_AND_WAKE_UP_BIT
	# 4.18
	LIBCFS_TCP_SOCK_SET_NODELAY
	LIBCFS_TCP_SOCK_SET_KEEPIDLE
	# 4.19
	LIBCFS_XARRAY_SUPPORT
	LIBCFS_NL_DUMP_EXT_ACK
	# 4.20
	LIBCFS_HAVE_IOV_ITER_TYPE
	# 5.0
	LIBCFS_MM_TOTALRAM_PAGES_FUNC
	LIBCFS_GET_REQUEST_KEY_AUTH
	# 5.2
	LIBCFS_KOBJ_TYPE_DEFAULT_GROUPS
	LIBCFS_USER_UID_KEYRING
	# 5.3
	LIBCFS_LOOKUP_USER_KEY
	LIBCFS_CACHE_DETAIL_WRITERS
	# 5.4
	LIBCFS_GENL_DUMPIT_INFO
	# 5.6
	LIBCFS_HAVE_PROC_OPS
	# 5.7
	LIBCFS_TCP_SOCK_SET_QUICKACK
	LIBCFS_TCP_SOCK_SET_KEEPINTVL
	LIBCFS_TCP_SOCK_SET_KEEPCNT
	# 5.8
	LIBCFS_IP6_SET_PREF
	LIBCFS_IP_SET_TOS
	LIBCFS_VMALLOC_2ARGS
	LIBCFS_HAVE_NR_UNSTABLE_NFS
	LIBCFS_NR_UNSTABLE_NFS_DEPRECATED
	LIBCFS_KERNEL_SETSOCKOPT
	LIBCFS_KEY_NEED_UNLINK
	LIBCFS_SEC_RELEASE_SECCTX
	# 5.10
	LIBCFS_HAVE_KMAP_LOCAL
	LIBCFS_HAVE_KFREE_SENSITIVE
	LIBCFS_HAVE_CRYPTO_SHA2_HEADER
	LIBCFS_HAVE_LIST_CMP_FUNC_T
	LIBCFS_NLA_STRLCPY
	# 5.12
	LIBCFS_RB_FIND
	LIBCFS_LINUX_FORTIFY_STRING_HEADER
	LIBCFS_HAVE_CIPHER_HEADER
	# 5.13
	LIBCFS_HAVE_TASK_IS_RUNNING
	# 5.14
	LIBCFS_LINUX_STDARG_HEADER
	LIBCFS_HAVE_PANIC_NOTIFIER_HEADER
	# 5.15
	LIBCFS_PARAM_SET_UINT_MINMAX
	# 5.17
	LIBCFS_PDE_DATA_EXISTS
	LIBCFS_BIO_ALLOC_WITH_BDEV
	# 6.2
	LIBCFS_TIMER_DELETE_SYNC
	LIBCFS_TIMER_DELETE
	# 6.11
	LIBCFS_CONSTIFY_CTR_TABLE
	LIBCFS_BLK_INTEGRITY_NOVERIFY
])

#
# LIBCFS_PROG_LINUX
#
# LibCFS linux kernel checks
#
AC_DEFUN([LIBCFS_PROG_LINUX], [
AC_MSG_NOTICE([LibCFS kernel checks
==============================================================================])
LIBCFS_CONFIG_PANIC_DUMPLOG

# 4.6 - Export Check
LIBCFS_EXPORT_KSET_FIND_OBJ
# 4.13 - Export Check
LIBCFS_EXPORT_SAVE_STACK_TRACE_TSK
# 5.0 - Export Check
LIBCFS_GENRADIX
# 5.7 - Export Check
LIBCFS_KALLSYMS_LOOKUP
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

# --------  Check for required packages  --------------

AC_MSG_NOTICE([LibCFS required packages checks
==============================================================================])

AC_MSG_CHECKING([whether to enable readline support])
AC_ARG_ENABLE(readline,
	AS_HELP_STRING([--disable-readline],
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

	AC_SUBST(ENABLE_READLINE, yes)
], [
	AC_SUBST(ENABLE_READLINE, no)
])
AC_SUBST(LIBREADLINE)

AC_MSG_CHECKING([whether to use libpthread for libcfs library])
AC_ARG_ENABLE([libpthread],
	AS_HELP_STRING([--disable-libpthread],
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

	AC_SUBST(ENABLE_LIBPTHREAD, yes)
], [
	AC_SUBST(ENABLE_LIBPTHREAD, no)
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
