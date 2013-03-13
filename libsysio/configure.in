AC_INIT(libsysio, 1.2)

AC_CANONICAL_SYSTEM

case "$host_os" in
	aix*)
		;;
	linux*)
		;;
	*)
		AC_MSG_WARN('***' ${host_os}: Unsupported OS target)
		;;
esac

AM_INIT_AUTOMAKE([subdir-objects 1.9 tar-ustar])
AM_MAINTAINER_MODE([enable])
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB
AC_CHECK_TOOL(CC, gcc, [no])
AC_CHECK_TOOL(LD, ld, [no])
AC_CHECK_TOOL(AR, ar, [no])
AC_CHECK_TOOL(OBJDUMP, objdump, [no])
AC_CHECK_TOOL(STRIP, strip, [no])
AC_PROG_MAKE_SET
AC_HEADER_STDC
AC_HEADER_STAT
AC_HEADER_TIME

case $target_vendor in
	# The K1OM architecture is an extension of the x86 architecture.
	# So, the $target_arch is x86_64.
	k1om)
		CC_TARGET_ARCH=`$CC -v 2>&1 | grep Target: | sed -e 's/Target: //'`
		if test $CC_TARGET_ARCH != x86_64-$target_vendor-linux ; then
			AC_MSG_ERROR([Cross compiler not found in PATH.])
		fi
		CCAS=$CC
		;;
	*)
		;;
esac

if test ${target_cpu} == "powerpc64"; then
	AC_MSG_WARN([set compiler with -m64])
	CC="$CC -m64"
fi

have_lib_dir=yes;
AC_ARG_WITH(lib-dir,
  AC_HELP_STRING([--with-lib-dir=<sysio lib build directory>],
  [directory for sysio library]),
  [     case "${withval}" in
         "yes"|"no"|"") have_lib_dir=no ;;
         *) LIBBUILD_DIR=${withval};
            test -d ${LIBBUILD_DIR} || mkdir ${LIBBUILD_DIR} ||
                have_lib_dir=no;;
        esac;],
  [ LIBBUILD_DIR=`pwd`/lib;
    test -d ${LIBBUILD_DIR} || mkdir ${LIBBUILD_DIR} || have_lib_dir=no;])
if test x${have_lib_dir} = xyes; then
  echo "Using sysio library directory ${LIBBUILD_DIR}"
else
  AC_MSG_ERROR(Need writeable path to sysio library directory ${LIBBUILD_DIR})
fi
AC_SUBST(LIBBUILD_DIR)

AC_ARG_WITH(native_driver,
  AC_HELP_STRING([--with-native-driver],[build native test driver]),
  [	case "${withval}" in
	 yes) ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-native-driver) ;;
	esac;],
  [with_native_driver=yes;])
AM_CONDITIONAL(WITH_NATIVE_DRIVER, test x$with_native_driver = xyes)

AC_ARG_WITH(incore-driver,
  AC_HELP_STRING([--with-incore-driver],[build incore test driver]),
  [ 	case "${withval}" in
	 yes) ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-incore-driver) ;;
	esac],
  [with_incore_driver=yes])
AM_CONDITIONAL(WITH_INCORE_DRIVER, test x$with_incore_driver = xyes)

AC_ARG_WITH(tests,
  AC_HELP_STRING([--with-tests],[build tests]),
  [	case "${withval}" in
	 yes) ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-tests) ;;
	esac],
  [with_tests=yes])
AM_CONDITIONAL(WITH_TESTS, test x$with_tests = xyes)

AC_ARG_WITH(automount,
  AC_HELP_STRING([--with-automount@<:@=<automount-file-name>@:>@],
    [with automounts @<:@<automount-file-name>=.mount@:>@]),
  [	if test x${withval} = xyes; then
	 AUTOMOUNT=-DAUTOMOUNT_FILE_NAME="\\\".mount\\\"" 
	elif test x${withval} != x; then
	 AUTOMOUNT=-DAUTOMOUNT_FILE_NAME="\\\"${withval}\\\""
	fi])
AC_SUBST(AUTOMOUNT)

AC_ARG_WITH(stdfd-dev,
  AC_HELP_STRING([--with-stdfd-dev],
    [build standard file descriptors pseudo-driver]),
  [	case "${withval}" in
	 yes) ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-stdfd-dev) ;;
	esac],
  [with_stdfd_dev=yes])
AM_CONDITIONAL(WITH_STDFD_DEV, test x$with_stdfd_dev = xyes)

AC_ARG_WITH(zero-sum-memory,
  AC_HELP_STRING([--with-zero-sum-memory],
    [free all dynamically allocated memory at the end -- useful for debugging]),
  [	case "${withval}" in
	 yes) ZERO_SUM_MEMORY=-DZERO_SUM_MEMORY=1 ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-zero-sum-memory) ;;
	esac],
  [with_zero_sum_memory=no])
AC_SUBST(ZERO_SUM_MEMORY)

AC_ARG_WITH(defer-init-cwd,
  AC_HELP_STRING([--with-defer-init-cwd],
    [defer initialization of current working directory]),
  [	case "${withval}" in
	 yes) DEFER_INIT_CWD=-DDEFER_INIT_CWD=1 ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-defer-init-cwd) ;;
	esac],
  [with_defer_init_cwd=no])
AC_SUBST(DEFER_INIT_CWD)

AC_ARG_WITH(tracing,
  AC_HELP_STRING([--with-tracing],
    [enable tracing support]),
  [	case "${withval}" in
	 yes) TRACING=-DSYSIO_TRACING=1 ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-tracing) ;;
	esac],
  [TRACING=-DSYSIO_TRACING=1])
AC_SUBST(TRACING)

AC_ARG_WITH(cplant_yod,
   AC_HELP_STRING([--with-cplant-yod],[build cplant yod I/O driver]),
   [	case "${withval}" in	
	yes) if test x${with_stdfd_dev} != xyes; then
		with_stdfd_dev=yes
		AM_CONDITIONAL(WITH_STDFD_DEV, test x$with_stdfd_dev = xyes)
	     fi ;;
	no) ;;
	*) AC_MSG_ERROR(bad value ${withval} for --with-cplant-yod);;
	esac],
    [with_cplant_yod=no])
AM_CONDITIONAL(WITH_CPLANT_YOD, test x$with_cplant_yod = xyes)

AC_ARG_WITH(cplant_tests,
   AC_HELP_STRING([--with-cplant-tests=<cplant-build-path>],
     [build libsysio tests for cplant platform]),
   [	case "${withval}" in
	yes) AC_MSG_ERROR(need path to compiler for --with-cplant-tests);;
	no)  with_cplant_tests=no;;
	*) CC=${withval}
	   CCDEPMODE=${CC} 
	   CPP="${CC} -E"
	   AC_CHECK_FILE(${CC},
		[ if test x${with_cplant_yod} != xyes; then
                	with_cplant_yod=yes
                	AM_CONDITIONAL(WITH_CPLANT_YOD, test x$with_cplant_yod = xyes)
             	  fi],
		[ AC_MSG_ERROR(path not found ${CC} for --with-cplant-tests) ]);;
	esac],
    [with_cplant_tests=no])
AM_CONDITIONAL(WITH_CPLANT_TESTS, test x$with_cplant_tests != xno)

AC_ARG_WITH(sockets,
  AC_HELP_STRING([--with-sockets],
    [build sockets interface driver (EXPERIMENTAL)]),
  [	case "${withval}" in
	 yes) ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-sockets) ;;
	esac],
  [with_sockets=no])
AM_CONDITIONAL(WITH_SOCKETS_DRIVER, test x$with_sockets = xyes)

AC_ARG_WITH(lustre-hack,
  AC_HELP_STRING([--with-lustre-hack],
    [have hacking code which needed to support liblustre driver (EXPERIMENTAL)]),
  [	case "${withval}" in
	 yes) ;;
	 no) ;;
	 *) AC_MSG_ERROR(bad value ${withval} for --with-lustre-hack) ;;
	esac],
  [with_lustre_hack=no])
AM_CONDITIONAL(WITH_LUSTRE_HACK, test x$with_lustre_hack = xyes)
if test x$with_lustre_hack = xyes; then
	AC_DEFINE(HAVE_LUSTRE_HACK)
fi

AC_ARG_WITH(alternate-symbols,
  AC_HELP_STRING([--with-alternate-symbols@<:@=<qualifier>@:>@],
    [Prepend standard, public, symbols with a unique qualifer]),
  [	case "${withval}" in
	 yes) SYSIO_LABEL_NAMES=-DSYSIO_LABEL_NAMES=sysio_ ;;
	 no) ;;
	 *) SYSIO_LABEL_NAMES=-DSYSIO_LABEL_NAMES="${withval}" ;;
	esac])
AC_SUBST(SYSIO_LABEL_NAMES)

# We keep the original values in `$config_*' and never modify them, so we
# can write them unchanged into config.make.  Everything else uses
# $machine, $vendor, and $os, and changes them whenever convenient.
config_machine=$host_cpu config_vendor=$host_vendor config_os=$host_os

# Don't allow vendor == "unknown"
test "$config_vendor" = unknown && config_vendor=
config_os="`echo $config_os | sed 's/^unknown-//'`"

# Some configurations imply other options.
case "$host_os" in
  gnu* | linux* | bsd4.4* | netbsd* | freebsd*)
	# These systems always use GNU tools.
	gnu_ld=yes gnu_as=yes ;;
esac
case "$host_os" in
  # i586-linuxaout is mangled into i586-pc-linux-gnuaout
  linux*ecoff* | linux*aout* | gnu*aout* | gnu*ecoff*)
	;;
  gnu* | linux* | freebsd* | netbsd* | sysv4* | solaris2* | irix6*)
	# These systems (almost) always use the ELF format.
	elf=yes
	;;
  aix*)
	# These systems are always xcoff
	xcoff=yes
	elf=no
	;;
esac

machine=$config_machine
vendor=$config_vendor
os=$config_os

# config.guess on some IBM machines says `rs6000' instead of `powerpc'.
# Unify this here.
if test "$machine" = rs6000; then
	machine="powerpc"
fi

case "$host_os" in
  gnu* | linux*)
	AC_DEFINE(_XOPEN_SOURCE, 600)
	;;
  aix*)
	# ... and always needed...
	AC_DEFINE(__USE_LARGEFILE64)
	AC_DEFINE(_LARGE_FILES)
	AC_DEFINE(_LARGE_FILE_API)
	AC_DEFINE(_ALL_SOURCE)
	AC_DEFINE(_XOPEN_SOURCE_EXTENDED)
	;;
esac

AC_MSG_CHECKING(for symlink support)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/stat.h>
],[
#ifndef S_ISLNK
#error
#endif
],
	symlink_support="yes",
	symlink_support="no"
)
AC_MSG_RESULT($symlink_support)

if test x$symlink_support = xyes; then
	AC_MSG_CHECKING(if readlink returns int)
	AC_TRY_COMPILE([
#include <unistd.h>
	],[
		extern int readlink(const char *, char *, size_t);
	],
		readlink_returns_int="yes",
		readlink_returns_int="no"
	)
	AC_MSG_RESULT($readlink_returns_int)
	if test x$readlink_returns_int = no; then
		AC_DEFINE(HAVE_POSIX_1003_READLINK,
			  1,
			  [readlink returns ssize_t])
	fi
fi

AC_MSG_CHECKING(if readlink returns ssize_t)
AC_TRY_COMPILE([
	#include <unistd.h>
],[
	ssize_t readlink(const char *, char *, size_t);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_POSIX_1003_READLINK, 1, [readlink returns ssize_t])
],[
	AC_MSG_RESULT([no])
])

# If we can't provoke the declaration of stat64 then we assume the
# environment supports 64-bit file support naturally. Beware!
AC_MSG_CHECKING(whether _LARGEFILE64_SOURCE definition is required)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>], [
struct stat64 st64;],
sysio_largefile64_source_required=no,
sysio_largefile64_source_required=maybe)
if test x$sysio_largefile64_source_required = xmaybe; then
	AC_TRY_COMPILE([
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>], [
struct stat64 st64;],
		       sysio_largefile64_source_required=yes,
		       sysio_largefile64_source_required=no)
fi
AC_MSG_RESULT($sysio_largefile64_source_required)
if test x$sysio_largefile64_source_required = xyes; then
	AC_DEFINE(_LARGEFILE64_SOURCE)
fi

# Alpha linux defines 
# 
AC_MSG_CHECKING(for alpha linux)
alpha_linux_env=no
if test `expr ${machine} : "alpha"` = 5 && \
   test `expr ${os} : "linux"` = 5; then
	alpha_linux_env=yes
	AC_DEFINE(ALPHA_LINUX)
fi
AC_MSG_RESULT($alpha_linux_env)
AM_CONDITIONAL(TEST_ALPHA_ARG, test x$alpha_linux_env = xyes)

# Check for __st_ino 
#
AC_MSG_CHECKING(for __st_ino)
AC_TRY_COMPILE([
#include <sys/stat.h>],
[struct stat st;
st.__st_ino = 0;],
	have__st_ino=yes,
	have__st_ino=no)
AC_MSG_RESULT($have__st_ino)
if test x$have__st_ino = xyes; then
	AC_DEFINE(HAVE__ST_INO)
fi

# Check for st_gen 
#
AC_MSG_CHECKING(for st_gen)
AC_TRY_COMPILE([
#include <sys/stat.h>],
[struct stat st;
st.st_gen = 0;],
	have_st_gen=yes,
	have_st_gen=no)
AC_MSG_RESULT($have_st_gen)
if test x$have_st_gen = xyes; then
	AC_DEFINE(HAVE_GENERATION)
fi

AC_MSG_CHECKING(for POSIX 2008 preadv)
tmp_flags="$CFLAGS"
CFLAGS="$CFLAGS -Wall -Werror"
AC_TRY_COMPILE([
#include <sys/uio.h>
ssize_t preadv (int __fd, const struct iovec *__iovec,
                int __count, off_t off)
{
    return 0;
}
],[
],[
AC_DEFINE(HAVE_POSIX2008_PREADV, 1, [POSIX 2008 preadv])
AC_MSG_RESULT(yes)
],[
AC_MSG_RESULT(no)
])
CFLAGS="$tmp_flags"

AC_MSG_CHECKING(for POSIX 2008 scandir)
tmp_flags="$CFLAGS"
CFLAGS="$CFLAGS -Wall -Werror"
AC_TRY_COMPILE([
#define _BSD_SOURCE

#include <stdio.h>
#include <dirent.h>

int scandir(const char *dir,
	 struct dirent ***namelist,
	 int(*filter)(const struct dirent *),
	 int(*compar)(const struct dirent **,
	              const struct dirent **)
	);

],[
], [
AC_DEFINE(HAVE_POSIX2008_SCANDIR, 1, [POSIX 2008 scandir])
AC_MSG_RESULT(yes) 
],[
AC_MSG_RESULT(no)
])
CFLAGS="$tmp_flags"


AC_MSG_CHECKING(for POSIX 2008 preadv)
tmp_flags="$CFLAGS"
CFLAGS="$CFLAGS -Wall -Werror"
AC_TRY_COMPILE([
#include <sys/uio.h>
ssize_t preadv (int __fd, const struct iovec *__iovec,
                int __count, off_t off)
{
    return 0;
}
],[
],[
AC_DEFINE(HAVE_POSIX2008_PREADV, 1, [POSIX 2008 preadv])
AC_MSG_RESULT(yes)
],[
AC_MSG_RESULT(no)
])
CFLAGS="$tmp_flags"

AC_MSG_CHECKING(for POSIX 2008 scandir)
tmp_flags="$CFLAGS"
CFLAGS="$CFLAGS -Wall -Werror"
AC_TRY_COMPILE([
#define _BSD_SOURCE

#include <stdio.h>
#include <dirent.h>

int scandir(const char *dir,
        struct dirent ***namelist,
        int(*filter)(const struct dirent *),
        int(*compar)(const struct dirent **,
                     const struct dirent **)
       );

],[
], [
AC_DEFINE(HAVE_POSIX2008_SCANDIR, 1, [POSIX 2008 scandir])
AC_MSG_RESULT(yes) 
],[
AC_MSG_RESULT(no)
])
CFLAGS="$tmp_flags"


AC_MSG_CHECKING(whether .text pseudo-op must be used)
AC_CACHE_VAL(am_cv_sysio_asm_dot_text, [dnl
cat > conftest.s <<EOF
	.text
EOF
	am_cv_sysio_asm_dot_text=
	if ${CC-cc} $CFLAGS -c conftest.s 2>/dev/null; then
		am_cv_sysio_asm_dot_text=.text
	fi
	rm -f conftest*])
if test -z "$am_cv_sysio_asm_dot_text"; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
fi

AC_CACHE_CHECK(for assembler global-symbol directive,
  am_cv_sysio_asm_global_directive, [dnl
am_cv_sysio_asm_global_directive=UNKNOWN
for ac_globl in .globl .global .EXPORT; do
	cat > conftest.s <<EOF
		${am_cv_sysio_asm_dot_text}
		${ac_globl} foo
foo:
EOF
	if ${CC-cc} $CFLAGS -c conftest.s 2>/dev/null; then
	am_cv_sysio_asm_global_directive=${ac_globl}
	fi
	rm -f conftest*
	test $am_cv_sysio_asm_global_directive != UNKNOWN && break
done])
if test $am_cv_sysio_asm_global_directive = UNKNOWN; then
	AC_MSG_ERROR(cannot determine asm global directive)
#else
#	AC_DEFINE_UNQUOTED(ASM_GLOBAL_DIRECTIVE, ${am_cv_sysio_asm_global_directive})
fi

AC_CACHE_CHECK(for .set assembler directive,
  am_cv_sysio_asm_set_directive, [dnl
cat > conftest.s<<EOF
${am_cv_sysio_asm_dot_text}
foo:
.set bar, foo
${am_cv_sysio_asm_global_directive} bar
EOF
	# The alpha-dec-osf1 assembler gives only a warning for `.set'
	# (but it doesn't work), so we must do a linking check to be sure.
cat > conftest1.c <<EOF
extern int bar;
main () { printf ("%d\n", bar); }
EOF
	if ${CC-cc} $CFLAGS $CPPFLAGS $LDFLAGS \
	   -o conftest conftest.s conftest1.c 1>&AC_FD_CC 2>&AC_FD_CC; then
		am_cv_sysio_asm_set_directive=yes
	else
		am_cv_sysio_asm_set_directive=no
	fi
	rm -f conftest*])
#if test $am_cv_sysio_asm_set_directive = yes; then
#	AC_DEFINE(HAVE_ASM_SET_DIRECTIVE)
#fi

AC_CACHE_CHECK(for assembler .weak directive, am_cv_sysio_asm_weak_directive,
	       [dnl
cat > conftest.s <<EOF
${am_cv_sysio_asm_dot_text}
foo:
.weak foo
EOF
	if ${CC-cc} $CFLAGS -c conftest.s 2>/dev/null; then
		am_cv_sysio_asm_weak_directive=yes
	else
		am_cv_sysio_asm_weak_directive=no
	fi
	rm -f conftest*])

if test $am_cv_sysio_asm_weak_directive = no; then
	AC_CACHE_CHECK(for assembler .weakext directive,
		       am_cv_sysio_asm_weakext_directive, [dnl
cat > conftest.s <<EOF
${am_cv_sysio_asm_dot_text}
${am_cv_sysio_asm_global_directive} foo
foo:
.weakext bar foo
.weakext baz
${am_cv_sysio_asm_global_directive} baz
baz:
EOF
		if ${CC-cc} $CFLAGS -c conftest.s 2>/dev/null; then
			am_cv_sysio_asm_weakext_directive=yes
		else
			am_cv_sysio_asm_weakext_directive=no
		fi
		rm -f conftest*])
fi # no .weak

if test x$am_cv_sysio_asm_weak_directive = xyes; then
	AC_DEFINE(HAVE_ASM_WEAK_DIRECTIVE)
fi
if test x$am_cv_sysio_asm_weakext_directive = xyes; then
	AC_DEFINE(HAVE_ASM_WEAKEXT_DIRECTIVE)
fi

AC_OUTPUT(
	Makefile
	tests/Makefile)
