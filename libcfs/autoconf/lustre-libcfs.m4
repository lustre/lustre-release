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

# check cpumask_size (2.6.28)
AC_DEFUN([LIBCFS_CPUMASK_SIZE],
[AC_MSG_CHECKING([whether have cpumask_size()])
LB_LINUX_TRY_COMPILE([
	#include <linux/cpumask.h>
],[
	int size = cpumask_size();
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_CPUMASK_SIZE, 1, [have cpumask_size()])
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

AC_DEFUN([LIBCFS_HAVE_KEYTYPE_H],
[LB_CHECK_FILE([$LINUX/include/linux/key-type.h], [
        AC_DEFINE(HAVE_LINUX_KEYTYPE_H, 1,
                [kernel has include/key-type.h])
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
# FC18 3.7.2-201 unexport sock_map_fd() change to
# use sock_alloc_file().
# upstream commit 56b31d1c9f1e6a3ad92e7bfe252721e05d92b285
#
AC_DEFUN([LIBCFS_SOCK_ALLOC_FILE],
[AC_MSG_CHECKING([sock_alloc_file is exported])
LB_CHECK_SYMBOL_EXPORT([sock_alloc_file], [net/socket.c],[
	LB_LINUX_TRY_COMPILE([
		#include <linux/net.h>
	],[
		sock_alloc_file(NULL, 0, NULL);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_SOCK_ALLOC_FILE_3ARGS, 1,
			[sock_alloc_file takes 3 arguments])
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_SOCK_ALLOC_FILE, 1,
			[sock_alloc_file is exported])
	])
],[
])
])

#
# LIBCFS_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LIBCFS_PROG_LINUX],
[
LIBCFS_CONFIG_PANIC_DUMPLOG

LIBCFS_U64_LONG_LONG_LINUX
# 2.6.24
LIBCFS_SYSCTL_UNNUMBERED
LIBCFS_FUNC_DUMP_TRACE
LIBCFS_HAVE_KEYTYPE_H
# 2.6.30
LIBCFS_SOCK_MAP_FD_2ARG
# 2.6.32
LIBCFS_STACKTRACE_OPS_HAVE_WALK_STACK
LC_SHRINKER_WANT_SHRINK_PTR
# 2.6.33
LIBCFS_SYSCTL_CTLNAME
# 2.6.34
LIBCFS_ADD_WAIT_QUEUE_EXCLUSIVE
# 2.6.35
LC_SK_SLEEP
# 2.6.40 fc15
LC_SHRINK_CONTROL
# 3.7
LIBCFS_SOCK_ALLOC_FILE
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

# lnet/libcfs/user-prim.c, missing for RHEL5 and earlier userspace
AC_CHECK_FUNCS([strlcpy])

# libcfs/libcfs/user-prim.c, missing for RHEL5 and earlier userspace
AC_CHECK_FUNCS([strlcat])

AC_CHECK_TYPE([umode_t],
	[AC_DEFINE(HAVE_UMODE_T, 1, [umode_t is defined])],
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
		data2 = data1;
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
