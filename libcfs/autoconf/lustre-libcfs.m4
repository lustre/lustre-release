#
# LN_CONFIG_CDEBUG
#
# whether to enable various libcfs debugs (CDEBUG, ENTRY/EXIT, LASSERT, etc.)
#
AC_DEFUN([LN_CONFIG_CDEBUG], [
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
]) # LN_CONFIG_CDEBUG

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
# LIBCFS_U64_LONG_LONG_LINUX
#
# check kernel __u64 type
#
AC_DEFUN([LIBCFS_U64_LONG_LONG_LINUX], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Werror"
LB_CHECK_COMPILE([if Linux kernel '__u64' is 'long long' type],
kernel_u64_long_long, [
	#include <linux/types.h>
	#include <linux/stddef.h>
],[
	unsigned long long *data;
	data = (__u64*)sizeof(data);
],[
	AC_DEFINE(HAVE_KERN__U64_LONG_LONG, 1,
		[Linux kernel __u64 is long long type])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LIBCFS_U64_LONG_LONG_LINUX

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
# LIBCFS_ADD_WAIT_QUEUE_EXCLUSIVE
#
# 2.6.34 adds __add_wait_queue_exclusive
#
AC_DEFUN([LIBCFS_ADD_WAIT_QUEUE_EXCLUSIVE], [
LB_CHECK_COMPILE([if '__add_wait_queue_exclusive' exists],
__add_wait_queue_exclusive, [
	#include <linux/wait.h>
],[
	wait_queue_head_t queue;
	wait_queue_t      wait;
	__add_wait_queue_exclusive(&queue, &wait);
],[
	AC_DEFINE(HAVE___ADD_WAIT_QUEUE_EXCLUSIVE, 1,
		[__add_wait_queue_exclusive exists])
])
]) # LIBCFS_ADD_WAIT_QUEUE_EXCLUSIVE

#
# LC_SK_SLEEP
#
# 2.6.35 kernel has sk_sleep function
#
AC_DEFUN([LC_SK_SLEEP], [
LB_CHECK_COMPILE([if Linux kernel has 'sk_sleep'],
sk_sleep, [
	#include <net/sock.h>
],[
	sk_sleep(NULL);
],[
	AC_DEFINE(HAVE_SK_SLEEP, 1,
		[kernel has sk_sleep])
])
]) # LC_SK_SLEEP

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
# 3.4 introduced process namespace
AC_DEFUN([LIBCFS_PROCESS_NAMESPACE], [
LB_CHECK_LINUX_HEADER([linux/uidgid.h], [
	AC_DEFINE(HAVE_UIDGID_HEADER, 1,
		[uidgid.h is present])])
]) # LIBCFS_PROCESS_NAMESPACE

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
	AC_MSG_WARN([

No crc32 pclmulqdq crypto api found, enable internal pclmulqdq based crc32
])])
]) # LIBCFS_ENABLE_CRC32_ACCEL

#
# LIBCFS_ENABLE_CRC32C_ACCEL
#
AC_DEFUN([LIBCFS_ENABLE_CRC32C_ACCEL], [
LB_CHECK_CONFIG_IM([CRYPTO_CRC32C_INTEL],
	[enable_crc32c_crypto="no"], [enable_crc32c_crypto="yes"])
AS_IF([test "x$enable_crc32c_crypto" = xyes], [
	AC_DEFINE(NEED_CRC32C_ACCEL, 1, [need pclmulqdq based crc32c])
	AC_MSG_WARN([

No crc32c pclmulqdq crypto api found, enable internal pclmulqdq based crc32c
])])
]) # LIBCFS_ENABLE_CRC32C_ACCEL

#
# LIBCFS_PROG_LINUX
#
# LibCFS linux kernel checks
#
AC_DEFUN([LIBCFS_PROG_LINUX], [
AC_MSG_NOTICE([LibCFS kernel checks
==============================================================================])
LIBCFS_CONFIG_PANIC_DUMPLOG

LIBCFS_U64_LONG_LONG_LINUX
# 2.6.32
LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK
LC_SHRINKER_WANT_SHRINK_PTR
# 2.6.33
LIBCFS_SYSCTL_CTLNAME
# 2.6.34
LIBCFS_ADD_WAIT_QUEUE_EXCLUSIVE
# 2.6.35
LC_SK_SLEEP
# 2.6.39
LIBCFS_DUMP_TRACE_ADDRESS
# 2.6.40 fc15
LC_SHRINK_CONTROL
# 3.0
LIBCFS_STACKTRACE_WARNING
# 3.4
LIBCFS_PROCESS_NAMESPACE
# 3.7
LIBCFS_SOCK_ALLOC_FILE
# 3.8
LIBCFS_HAVE_CRC32
LIBCFS_ENABLE_CRC32_ACCEL
# 3.10
LIBCFS_ENABLE_CRC32C_ACCEL
]) # LIBCFS_PROG_LINUX

#
# LIBCFS_PROG_DARWIN
#
# Darwin checks
#
AC_DEFUN([LIBCFS_PROG_DARWIN], [
LB_DARWIN_CHECK_FUNCS([get_preemption_level])
]) # LIBCFS_PROG_DARWIN

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
tmp_flags="$CFLAGS"
CFLAGS="$CFLAGS -Werror"
AC_CACHE_CHECK([if userspace '__u64' is 'long long' type],
lb_cv_compile_userspace_u64_long_long, [
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
	#include <stdio.h>
	#include <linux/types.h>
	#include <linux/stddef.h>
	int main(void) {
		unsigned long long *data1;
		__u64 *data2 = NULL;
		data1 = data2;
		data2 = data1;
		return 0;
	}
])],
	[lb_cv_compile_userspace_u64_long_long="yes"],
	[lb_cv_compile_userspace_u64_long_long="no"])
])
CFLAGS="$tmp_flags"
AS_IF([test "x$lb_cv_compile_userspace_u64_long_long" = xyes],
	[AC_DEFINE(HAVE_USER__U64_LONG_LONG, 1,
		[__u64 is long long type])])

# --------  Check for required packages  --------------

AC_MSG_NOTICE([LibCFS required packages checks
==============================================================================])

AC_MSG_CHECKING([whether to enable 'efence' debugging support])
AC_ARG_ENABLE(efence,
	AC_HELP_STRING([--enable-efence],
		[use efence library]),
	[], [enable_efence="no"])
AC_MSG_RESULT([$enable_efence])
AS_IF([test "$enable_efence" = yes], [
	LIBEFENCE="-lefence"
	AC_DEFINE(HAVE_LIBEFENCE, 1, [libefence support is requested])
], [
	LIBEFENCE=""
])
AC_SUBST(LIBEFENCE)

# -------- check for -lpthread support ----

AC_MSG_CHECKING([whether to use libpthread for libcfs library])
AC_ARG_ENABLE([libpthread],
	AC_HELP_STRING([--disable-libpthread],
		[disable libpthread]),
	[], [enable_libpthread="yes"])
AC_MSG_RESULT([$enable_libpthread])
AS_IF([test "x$enable_libpthread" = xyes], [
	AC_CHECK_LIB([pthread], [pthread_create],
		[ENABLE_LIBPTHREAD="yes"],
		[ENABLE_LIBPTHREAD="no"])
	AS_IF([test "$ENABLE_LIBPTHREAD" = yes], [
		PTHREAD_LIBS="-lpthread"
		AC_DEFINE([HAVE_LIBPTHREAD], 1, [use libpthread])
	], [
		PTHREAD_LIBS=""
	])
	AC_SUBST(PTHREAD_LIBS)
], [
	AC_MSG_WARN([Using libpthread for libcfs library is disabled explicitly])
	ENABLE_LIBPTHREAD="no"
])
AC_SUBST(ENABLE_LIBPTHREAD)
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
]) # LIBCFS_CONFIG_FILES
