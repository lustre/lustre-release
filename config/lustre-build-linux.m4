#
# LB_LINUX_VERSION
#
# Set things accordingly for a linux kernel
#
AC_DEFUN([LB_LINUX_VERSION], [
KMODEXT=".ko"
AC_SUBST(KMODEXT)

makerule="$PWD/build"
AC_CACHE_CHECK([for external module build target], lb_cv_module_target,
[
	lb_cv_module_target=""
	rm -f build/conftest.i
	MODULE_TARGET="M"
	makerule="$PWD/build"
	LB_LINUX_TRY_MAKE([], [],
		[$makerule LUSTRE_KERNEL_TEST=conftest.i],
		[test -s build/conftest.i],
		[lb_cv_module_target="M54"], [
	MODULE_TARGET="M"
	makerule="_module_$PWD/build"
	LB_LINUX_TRY_MAKE([], [],
		[$makerule LUSTRE_KERNEL_TEST=conftest.i],
		[test -s build/conftest.i],
		[lb_cv_module_target="M"], [
	MODULE_TARGET="M"
	makerule=""
	LB_LINUX_TRY_MAKE([], [],
		[$makerule LUSTRE_KERNEL_TEST=conftest.i],
		[test -s build/conftest.i],
		[lb_cv_module_target="M58"], [
	makerule=""
	lb_cv_dequote_CC_VERSION_TEXT=yes
	LB_LINUX_TRY_MAKE([], [],
		[$makerule LUSTRE_KERNEL_TEST=conftest.i],
		[test -s build/conftest.i],
		[lb_cv_module_target="M517"], [
			AC_MSG_ERROR([kernel module make failed; check config.log for details])
	])])])])
])
# Linux commit v5.16-rc3-26-g129ab0d2d9f3
#  added quotes around "$(CONFIG_CC_VERSION_TEXT)", however .config stores
#  CONFIG_CC_VERSION_TEXT with quotes thus breaking the GNU make Makefile
#  for external modules.
#  Workaround by providing a non-quoted value to override the value in .config
unset lb_cv_dequote_CC_VERSION_TEXT
AC_CACHE_CHECK([for compiler version text], lb_cv_dequote_CC_VERSION_TEXT, [
	AS_IF([test "x$lb_cv_module_target" = "xM517"],
		[lb_cv_dequote_CC_VERSION_TEXT=yes],
		[lb_cv_dequote_CC_VERSION_TEXT=yes])
])
AS_IF([test -z "$lb_cv_module_target"],
	[AC_MSG_ERROR([unknown external module build target])],
[test "x$lb_cv_module_target" = "xM54"],
	[makerule="$PWD/build"
	lb_cv_module_target="M"],
[test "x$lb_cv_module_target" = "xM58"],
	[makerule=""
	lb_cv_module_target="M"],
[test "x$lb_cv_module_target" = "xM517"],
	[makerule=""
	lb_cv_module_target="M"],
[test "x$lb_cv_module_target" = "xM"],
	[makerule="_module_$PWD/build"])
MODULE_TARGET=$lb_cv_module_target
AC_SUBST(MODULE_TARGET)
])

#
# LB_LINUX_UTSRELEASE
#
# Determine the Linux kernel version string from the utsrelease
#
AC_DEFUN([LB_LINUX_UTSRELEASE], [
AC_CACHE_CHECK([for Linux kernel utsrelease], lb_cv_utsrelease, [
lb_cv_utsrelease=""
utsrelease1=$LINUX_OBJ/include/generated/utsrelease.h
utsrelease2=$LINUX_OBJ/include/linux/utsrelease.h
utsrelease3=$LINUX_OBJ/include/linux/version.h
AS_IF([test -r $utsrelease1 && fgrep -q UTS_RELEASE $utsrelease1],
	[utsrelease=$utsrelease1],
[test -r $utsrelease2 && fgrep -q UTS_RELEASE $utsrelease2],
	[utsrelease=$utsrelease2],
[test -r $utsrelease3 && fgrep -q UTS_RELEASE $utsrelease3],
	[utsrelease=$utsrelease3])
AS_IF([test -n "$utsrelease"],
	[lb_cv_utsrelease=$(awk -F \" '/ UTS_RELEASE / { print [$]2 }' $utsrelease)],
	[AC_MSG_ERROR([

Cannot find UTS_RELEASE definition.

This is often provided by the kernel-devel package.
])
	])
])
AS_IF([test -z "$lb_cv_utsrelease"],
	[AC_MSG_ERROR([Cannot determine Linux kernel version.])])
LINUXRELEASE=$lb_cv_utsrelease
AC_SUBST(LINUXRELEASE)
])

#
# LB_LINUX_RELEASE
#
# get the release version of linux
#
AC_DEFUN([LB_LINUX_RELEASE], [
	LB_LINUX_UTSRELEASE

	# Define default states
	RHEL_KERNEL="no"
	SUSE_KERNEL="no"
	UBUNTU_KERNEL="no"
	# And if any of the above kernels has been detected yet
	KERNEL_FOUND="no"

	# Check for RedHat first (no need to check KERNEL_FOUND
	AC_CACHE_CHECK([for RedHat kernel release number], lb_cv_rhel_kernel_version, [
		lb_cv_rhel_kernel_version=""
		AS_IF([fgrep -q RHEL_RELEASE $LINUX_OBJ/include/$VERSION_HDIR/version.h], [
			lb_cv_rhel_kernel_version=$(awk '/ RHEL_MAJOR / { print [$]3 }' \
				$LINUX_OBJ/include/$VERSION_HDIR/version.h)$(awk \
				'/ RHEL_MINOR / { print [$]3 }' \
				$LINUX_OBJ/include/$VERSION_HDIR/version.h)
		])
	])
	AS_IF([test -n "$lb_cv_rhel_kernel_version"], [
		RHEL_KERNEL="yes"
		KERNEL_FOUND="yes"
		RHEL_RELEASE_NO=$lb_cv_rhel_kernel_version
	])

	# Check for SuSE
	AS_IF([test "x$KERNEL_FOUND" = "xno"], [
		LB_CHECK_CONFIG([SUSE_KERNEL], [
			SUSE_KERNEL="yes"
			KERNEL_FOUND="yes"
		], [])
	])

	# Check for Ubuntu
	AS_IF([test "x$KERNEL_FOUND" = "xno"], [
		AC_CACHE_CHECK([for Ubuntu kernel signature], lb_cv_ubuntu_kernel_sig, [
			lb_cv_ubuntu_kernel_sig="no"
			AS_IF([fgrep -q "CONFIG_VERSION_SIGNATURE \"Ubuntu" $LINUX_OBJ/include/generated/autoconf.h], [
				lb_cv_ubuntu_kernel_sig="yes"
			])
		])
		AS_IF([test "x$lb_cv_ubuntu_kernel_sig" = "xyes"], [
			UBUNTU_KERNEL="yes"
			KERNEL_FOUND="yes"
		])
	])

	# Check for a ELRepo -ml kernel on RHEL 7/8
	AS_IF([test "x$KERNEL_FOUND" = "xno"], [
		AC_CACHE_CHECK([for ELRepo -ml kernel signature on CentOS],
				lb_cv_mainline_kernel_sig, [
			lb_cv_mainline_kernel_sig="no"
			AS_IF([fgrep -q '.el7.' $LINUX_OBJ/include/generated/utsrelease.h], [
				lb_cv_mainline_kernel_sig="yes"
			])
			AS_IF([fgrep -q '.el8.' $LINUX_OBJ/include/generated/utsrelease.h], [
				lb_cv_mainline_kernel_sig="yes"
			])
		])
		AS_IF([test "x$lb_cv_mainline_kernel_sig" = "xyes"], [
			RHEL_KERNEL="yes"
			KERNEL_FOUND="yes"
		])
	])

	# If still no kernel was found, a warning is issued
	AS_IF([test "x$KERNEL_FOUND" = "xno"], [
		AC_MSG_WARN([Kernel Distro seems to be neither RedHat, SuSE nor Ubuntu])
	])

	AC_MSG_CHECKING([for Linux kernel module package directory])
	AC_ARG_WITH([kmp-moddir],
		AS_HELP_STRING([--with-kmp-moddir=string],
			[set the kmod updates or extra directory]),
		[KMP_MODDIR=$withval
		 IN_KERNEL=''],[
		AS_IF([test x$RHEL_KERNEL = xyes], [KMP_MODDIR="extra/kernel"],
		      [test x$SUSE_KERNEL = xyes], [KMP_MODDIR="updates/kernel"],
		      [test x$UBUNTU_KERNEL = xyes], [KMP_MODDIR="updates/kernel"],
		      [AC_MSG_WARN([Kernel Distro seems to be neither RedHat, SuSE nor Ubuntu])]
		)
		IN_KERNEL="${PACKAGE}"])
	AC_MSG_RESULT($KMP_MODDIR)

	moduledir="/lib/modules/${LINUXRELEASE}/${KMP_MODDIR}"

	modulefsdir="${moduledir}/fs/${IN_KERNEL}"
	AC_SUBST(modulefsdir)

	modulenetdir="${moduledir}/net/${IN_KERNEL}"
	AC_SUBST(modulenetdir)

	AC_SUBST(KMP_MODDIR)
])

#
# LB_LINUX_SYMVERFILE
#
# SLES 9 uses a different name for this file - unsure about vanilla kernels
# around this version, but it matters for servers only.
AC_DEFUN([LB_LINUX_SYMVERFILE], [
AC_CACHE_CHECK([for the name of module symbol version file], lb_cv_module_symvers, [
AS_IF([grep -q Modules.symvers $LINUX/scripts/Makefile.modpost],
	[lb_cv_module_symvers=Modules.symvers],
	[lb_cv_module_symvers=Module.symvers])
])
SYMVERFILE=$lb_cv_module_symvers
AC_SUBST(SYMVERFILE)
])

#
# LB_ARG_REPLACE_PATH(PACKAGE, PATH)
#
AC_DEFUN([LB_ARG_REPLACE_PATH], [
new_configure_args=
eval set -- $ac_configure_args
for arg; do
	case $arg in
		--with-[$1]=*)
			arg=--with-[$1]=[$2] ;;
		*\'*)
			arg=$(printf %s\n ["$arg"] | sed "s/'/'\\\\\\\\''/g") ;;
	esac
	dnl AS_VAR_APPEND([new_configure_args], [" '$arg'"])
	new_configure_args="$new_configure_args '$arg'"
done
ac_configure_args=$new_configure_args
])

#
# __LB_ARG_CANON_PATH
#
# this is the work-horse of the next function
#
AC_DEFUN([__LB_ARG_CANON_PATH], [
	[$3]=$(readlink -f $with_$2)
	LB_ARG_REPLACE_PATH([$1], $[$3])
])

#
# LB_ARG_CANON_PATH
#
# a front-end for the above function that transforms - and . in the
# PACKAGE portion of --with-PACKAGE into _ suitable for variable names
#
AC_DEFUN([LB_ARG_CANON_PATH], [
	__LB_ARG_CANON_PATH([$1], m4_translit([$1], [-.], [__]), [$2])
])

#
# LB_LINUX_PATH
#
# Find paths for linux, handling kernel-source rpms
#
AC_DEFUN([LB_LINUX_PATH], [
for DEFAULT_LINUX in /usr/src/linux-source-* /lib/modules/$(uname -r)/{source,build} /usr/src/linux* $(find /usr/src/kernels/ -maxdepth 1 -name @<:@0-9@:>@\* | xargs -r ls -d | tail -n 1); do
	AS_IF([readlink -q -e $DEFAULT_LINUX >/dev/null], [break])
done
if test "$DEFAULT_LINUX" = "/lib/modules/$(uname -r)/source"; then
	PATHS="/lib/modules/$(uname -r)/build"
else
	PATHS="/usr/src/linux-headers-$(uname -r)"
fi
PATHS+=" $DEFAULT_LINUX"
for DEFAULT_LINUX_OBJ in $PATHS; do
	AS_IF([readlink -q -e $DEFAULT_LINUX_OBJ >/dev/null], [break])
done

AC_MSG_CHECKING([for Linux sources])
AC_ARG_WITH([linux],
	AS_HELP_STRING([--with-linux=path],
		       [set path to Linux source (default=/lib/modules/$(uname -r)/{source,build},/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux], [LINUX])
	DEFAULT_LINUX_OBJ=$LINUX],
	[LINUX=$DEFAULT_LINUX])
AC_MSG_RESULT([$LINUX])

# -------- check for linux --------
LB_CHECK_FILE([$LINUX], [],
	[AC_MSG_ERROR([Kernel source $LINUX could not be found.])])

# -------- linux objects (for 2.6) --
AC_MSG_CHECKING([for Linux objects])
AC_ARG_WITH([linux-obj],
	AS_HELP_STRING([--with-linux-obj=path],
			[set path to Linux objects (default=/lib/modules/$(uname -r)/build,/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux-obj], [LINUX_OBJ])],
	[LINUX_OBJ=$DEFAULT_LINUX_OBJ])
AC_MSG_RESULT([$LINUX_OBJ])

## -------- with linux should point to <kernel>-common on Debian
AS_IF([test ${LINUX} == ${LINUX_OBJ} -a ${LINUX} == $(realpath ${LINUX})],[
	this_arch=$(realpath ${LINUX} | sed 's/-/\n/g' | tail -1)
	linux_headers_common=$(realpath ${LINUX}|sed "s/-${this_arch}\$/-common/g")
	AS_IF([test "${this_arch}" != common],[
		_cah="${linux_headers_common}/include/linux/compiler_attributes.h"
		_cgh="${linux_headers_common}/include/linux/compiler-gcc.h"
		AS_IF([test -f "${_cah}" -o -f "${_cgh}"],[
			AC_MSG_WARN([Setting LINUX to ${linux_headers_common} was ${LINUX}])
			LINUX=${linux_headers_common}])
		])
	])
AC_SUBST(LINUX)
AC_SUBST(LINUX_OBJ)
# -------- check for .config --------
AC_ARG_WITH([linux-config],
	[AS_HELP_STRING([--with-linux-config=path],
			[set path to Linux .conf (default=$LINUX_OBJ/.config)])],
	[LB_ARG_CANON_PATH([linux-config], [LINUX_CONFIG])],
	[LINUX_CONFIG=$LINUX_OBJ/.config])

# -------- check if .config exists --
LB_CHECK_FILE([$LINUX_CONFIG], [],
	[AC_MSG_ERROR([

Kernel config could not be found.
])
])
AC_SUBST(LINUX_CONFIG)

LB_CHECK_FILE([/boot/kernel.h],
	[KERNEL_SOURCE_HEADER='/boot/kernel.h'],
	[LB_CHECK_FILE([/var/adm/running-kernel.h],
		[KERNEL_SOURCE_HEADER='/var/adm/running-kernel.h'])])

AC_ARG_WITH([kernel-source-header],
	AS_HELP_STRING([--with-kernel-source-header=path],
			[Use a different kernel version header.]),
	[LB_ARG_CANON_PATH([kernel-source-header], [KERNEL_SOURCE_HEADER])])

# ----------- make dep run? ------------------
# at 2.6.19 # $LINUX/include/linux/config.h is removed
# and at more old has only one line include <autoconf.h>
#
LB_CHECK_FILE([$LINUX_OBJ/include/generated/autoconf.h],
	[AUTOCONF_HDIR=generated],
	[LB_CHECK_FILE([$LINUX_OBJ/include/linux/autoconf.h],
		[AUTOCONF_HDIR=linux],
		[AC_MSG_ERROR([Run make config in $LINUX.])])])
AC_SUBST(AUTOCONF_HDIR)

LB_CHECK_FILE([$LINUX_OBJ/include/linux/version.h],
	[VERSION_HDIR=linux],
	[LB_CHECK_FILE([$LINUX_OBJ/include/generated/uapi/linux/version.h],
		[VERSION_HDIR=generated/uapi/linux],
		[AC_MSG_ERROR([Run make config in $LINUX.])])])
AC_SUBST(VERSION_HDIR)

# ----------- kconfig.h exists ---------------
# kernel 3.1, $LINUX/include/linux/kconfig.h is added
# see kernel commit 2a11c8ea20bf850b3a2c60db8c2e7497d28aba99
#
LB_CHECK_FILE([$LINUX/include/linux/kconfig.h],
	      [CONFIG_INCLUDE=$LINUX/include/linux/kconfig.h],
              [CONFIG_INCLUDE=include/$AUTOCONF_HDIR/autoconf.h])
AC_SUBST(CONFIG_INCLUDE)

# ------------ rhconfig.h includes runtime-generated bits --
# RedHat kernel-source checks

# we know this exists after the check above.  if the user
# tarred up the tree and ran make dep etc. in it, then
# version.h gets overwritten with a standard linux one.

AS_IF([grep rhconfig $LINUX_OBJ/include/$VERSION_HDIR/version.h >/dev/null], [
	# This is a clean kernel-source tree, we need to
	# enable extensive workarounds to get this to build modules
	LB_CHECK_FILE([$KERNEL_SOURCE_HEADER], [
		AS_IF([test $KERNEL_SOURCE_HEADER = '/boot/kernel.h'],
			[AC_MSG_WARN([

Using /boot/kernel.h from RUNNING kernel.

If this is not what you want, use --with-kernel-source-header.
Consult build/README.kernel-source for details.
])
		])],
		[AC_MSG_ERROR([

$KERNEL_SOURCE_HEADER not found.

Consult build/README.kernel-source for details.
])
		])
	EXTRA_KCFLAGS="-include $KERNEL_SOURCE_HEADER $EXTRA_KCFLAGS"
])

AS_IF([test -n SUBARCH],
[SUBARCH=$(echo $target_cpu | sed -e 's/powerpc.*/powerpc/' -e 's/ppc.*/powerpc/' -e 's/x86_64/x86/' -e 's/i.86/x86/' -e 's/k1om/x86/' -e 's/aarch64.*/arm64/' -e 's/armv7.*/arm/')
])

# this is needed before we can build modules
LB_LINUX_VERSION

# --- Parallel config for kernel v5.17+
AS_IF([test "x$lb_cv_dequote_CC_VERSION_TEXT" = "xyes"], [
	CC_VERSION_TEXT=$(gcc --version | head -n1 | tr ' ()' '.')
	MAKE_KMOD_ENV="CONFIG_CC_VERSION_TEXT='$CC_VERSION_TEXT'"])

# --- check that we can build modules at all
LB_CHECK_COMPILE([that modules can be built at all], build_modules,
	[], [], [], [
	AC_MSG_ERROR([

Kernel modules cannot be built. Consult config.log for details.

If you are trying to build with a kernel-source rpm,
consult build/README.kernel-source
])
])

LB_LINUX_RELEASE
]) # end of LB_LINUX_PATH

#
# LC_MODULE_LOADING
#
# after 2.6.28 CONFIG_KMOD is removed, and only CONFIG_MODULES remains
# so we test if request_module is implemented or not
AC_DEFUN([LC_MODULE_LOADING], [
AC_CACHE_CHECK([if Linux kernel module loading is possible], lb_cv_module_loading, [
LB_LINUX_TRY_MAKE([
	#include <linux/kmod.h>
], [
	int myretval=ENOSYS ;
	return myretval;
], [
	$makerule LUSTRE_KERNEL_TEST=conftest.i
], [dnl
	grep request_module build/conftest.i |dnl
		grep -v `grep "int myretval=" build/conftest.i |dnl
			cut -d= -f2 | cut -d" "  -f1`dnl
		>/dev/null dnl
], [lb_cv_module_loading="yes"], [lb_cv_module_loading="no"])
])
AS_IF([test "$lb_cv_module_loading" = yes],
	[AC_DEFINE(HAVE_MODULE_LOADING_SUPPORT, 1,
		[kernel module loading is possible])],
	[AC_MSG_WARN([

Kernel module loading support is highly recommended.

])
	])
])

AC_DEFUN([LB_PROG_LINUX_SRC], [
	LB2_SRC_CHECK_CONFIG([MODULES])
	LB2_SRC_CHECK_CONFIG([MODVERSIONS])
])

AC_DEFUN([LB_PROG_LINUX_RESULTS], [
	LB2_TEST_CHECK_CONFIG([MODULES], [], [AC_MSG_ERROR(
		[module support is required to build Lustre kernel modules.])
	])
	LB2_TEST_CHECK_CONFIG([MODVERSIONS],[],[])
])

#
# LB_PROG_LINUX
#
# linux tests
#
AC_DEFUN([LB_PROG_LINUX], [
LB_LINUX_PATH
LB_LINUX_SYMVERFILE
# 2.6.28
LC_MODULE_LOADING
])

#
# LB_USES_DPKG
#
# Determine if the target is a dpkg system or rpm
#
AC_DEFUN([LB_USES_DPKG], [
AC_CACHE_CHECK([if this distro uses dpkg], lb_cv_uses_dpkg, [
lb_cv_uses_dpkg="no"
AS_CASE([$(which dpkg 2>/dev/null)],[*/dpkg], [lb_cv_uses_dpkg="yes"])
])
uses_dpkg=$lb_cv_uses_dpkg
])

#
# LB_CHECK_EXPORT
#
# check symbol exported or not
# $1 - symbol
# $2 - file(s) for find.
# $3 - do 'yes'
# $4 - do 'no'
#
# 2.6 based kernels - put modversion info into $LINUX/Module.modvers or check
#
AC_DEFUN([LB_CHECK_EXPORT], [
AS_VAR_PUSHDEF([lb_export], [lb_cv_export_$1])dnl
AC_CACHE_CHECK([if Linux kernel exports '$1'], lb_export, [
AS_VAR_SET([lb_export], [no])
AS_IF([grep -q -E '[[[:space:]]]$1[[[:space:]]]' $LINUX_OBJ/$SYMVERFILE 2>/dev/null],
	[AS_VAR_SET([lb_export], [yes])],
	[for file in $2; do
		AS_IF([grep -q -E "EXPORT_SYMBOL.*\($1\)" "$LINUX/$file" 2>/dev/null], [
			AS_VAR_SET([lb_export], [yes])
			break
		])
	done])
])
AS_VAR_IF([lb_export], [yes], [$3], [$4])[]dnl
AS_VAR_POPDEF([lb_export])dnl
]) # LB_CHECK_EXPORT

#
# LB_CHECK_CONFIG
#
# check if a given config option is defined
# $1 - CONFIG_<name>
# $2 - do 'yes'
# $3 - do 'no'
#
AC_DEFUN([LB_CHECK_CONFIG], [
LB_CHECK_COMPILE([if Linux kernel was built with CONFIG_$1],
config_$1, [
	#include <$AUTOCONF_HDIR/autoconf.h>
], [
	#ifndef CONFIG_$1
	#error CONFIG_$1 not #defined
	#endif
], [$2], [$3])
]) # LB_CHECK_CONFIG

#
# LB_CHECK_CONFIG_IM
#
# check if a given config option is builtin or as module
# $1 - CONFIG_<name> or CONFIG_<name>_MODULE
# $2 - do 'yes'
# $3 - do 'no'
#
AC_DEFUN([LB_CHECK_CONFIG_IM], [
LB_CHECK_COMPILE([if Linux kernel was built with CONFIG_$1 in or as module],
config_im_$1, [
	#include <$AUTOCONF_HDIR/autoconf.h>
], [
	#if !(defined(CONFIG_$1) || defined(CONFIG_$1_MODULE))
	#error CONFIG_$1 and CONFIG_$1_MODULE not #defined
	#endif
], [$2], [$3])
]) # LB_CHECK_CONFIG_IM

#
# these are like AC_TRY_COMPILE, but try to build modules against the
# kernel, inside the build directory
#

#
# LB_LANG_PROGRAM(C)([PROLOGUE], [BODY])
# --------------------------------------
#
m4_define([LB_LANG_PROGRAM],
[
#include <linux/kernel.h>
#include <linux/module.h>

#if defined(NEED_LOCKDEP_IS_HELD_DISCARD_CONST) \
 && defined(CONFIG_LOCKDEP) \
 && defined(lockdep_is_held)
#undef lockdep_is_held
	#define lockdep_is_held(lock) \
		lock_is_held((struct lockdep_map *)&(lock)->dep_map)
#endif

$1
int
main (void)
{
dnl Do *not* indent the following line: there may be CPP directives.
dnl Don't move the `;' right after for the same reason.
$2
  ;
  return 0;
};
MODULE_LICENSE("GPL");])

#
# LB_LINUX_COMPILE_IFELSE
#
# like AC_COMPILE_IFELSE
#
# $1 - AC_LANG_SOURCE()
# $2 - make target
# $3 - check command
# $4 - do 'yes'
# $5 - do 'no'
#
AC_DEFUN([LB_LINUX_COMPILE_IFELSE],
[m4_ifvaln([$1], [AC_LANG_CONFTEST([AC_LANG_SOURCE([$1])])])dnl
rm -f build/conftest.o build/conftest.mod.c build/conftest.ko
AS_IF([AC_TRY_COMMAND(cp conftest.c build && make -d [$2] DEQUOTE_CC_VERSION_TEXT=$lb_cv_dequote_CC_VERSION_TEXT LDFLAGS= ${LD:+LD="$LD"} CC="$CC" -f $PWD/build/Makefile LUSTRE_LINUX_CONFIG=$LINUX_CONFIG LINUXINCLUDE="$EXTRA_CHECK_INCLUDE -I$LINUX/arch/$SUBARCH/include -Iinclude -Iarch/$SUBARCH/include/generated -I$LINUX/include -Iinclude2 -I$LINUX/include/uapi -Iinclude/generated -I$LINUX/arch/$SUBARCH/include/uapi -Iarch/$SUBARCH/include/generated/uapi -I$LINUX/include/uapi -Iinclude/generated/uapi ${SPL_OBJ:+-include $SPL_OBJ/spl_config.h} ${ZFS_OBJ:+-include $ZFS_OBJ/zfs_config.h} ${SPL:+-I$SPL/include } ${ZFS:+-I$ZFS -I$ZFS/include -I$ZFS/include/os/linux/kernel -I$ZFS/include/os/linux/spl -I$ZFS/include/os/linux/zfs -I${SPL:-$ZFS/include/spl}} -include $CONFIG_INCLUDE" KBUILD_EXTRA_SYMBOLS="${ZFS_OBJ:+$ZFS_OBJ/Module.symvers} $KBUILD_EXTRA_SYMBOLS" -o tmp_include_depends -o scripts -o include/config/MARKER -C $LINUX_OBJ EXTRA_CFLAGS="-Werror-implicit-function-declaration $EXTRA_KCFLAGS" $MODULE_TARGET=$PWD/build) >/dev/null && AC_TRY_COMMAND([$3])],
	[$4],
	[_AC_MSG_LOG_CONFTEST
m4_ifvaln([$5],[$5])dnl])
rm -f build/conftest.o build/conftest.mod.c build/conftest.mod.o build/conftest.ko m4_ifval([$1], [build/conftest.c conftest.c])[]dnl
])

#
# LB_LINUX_TRY_COMPILE
#
# like AC_TRY_COMPILE
#
AC_DEFUN([LB_LINUX_TRY_COMPILE], [
LB_LINUX_COMPILE_IFELSE(
	[AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
	[modules], [test -s build/conftest.o],
	[$3], [$4])
])

#
# LB_LINUX_TRY_MAKE
#
# like LB_LINUX_TRY_COMPILE, but with different arguments
#
AC_DEFUN([LB_LINUX_TRY_MAKE], [
LB_LINUX_COMPILE_IFELSE(
	[AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
	[$3], [$4], [$5], [$6])
])

#
# LB_CHECK_COMPILE
# $1 - checking message
# $2 - variable name
# $3 - header
# $4 - body
# $5 - do 'yes'
# $6 - do 'no'
#
AC_DEFUN([LB_CHECK_COMPILE], [
AS_VAR_PUSHDEF([lb_compile], [lb_cv_compile_$2])dnl
AC_CACHE_CHECK([$1], lb_compile, [
	LB_LINUX_TRY_COMPILE([$3], [$4],
		[AS_VAR_SET([lb_compile], [yes])],
		[AS_VAR_SET([lb_compile], [no])])
])
AS_VAR_IF([lb_compile], [yes], [$5], [$6])[]dnl
AS_VAR_POPDEF([lb_compile])dnl
]) # LB_CHECK_COMPILE

#
# LB_CHECK_LINUX_HEADER
#
# Like AC_CHECK_HEADER but checks for a kernel-space header
#
AC_DEFUN([LB_CHECK_LINUX_HEADER], [
	AS_VAR_PUSHDEF([lb_header], [lb_cv_header_$1])
	AC_CACHE_CHECK([for $1], lb_header, [
		LB_LINUX_COMPILE_IFELSE([LB_LANG_PROGRAM([@%:@include <$1>])],
			[modules], [test -s build/conftest.o],
			[AS_VAR_SET([lb_header], [yes])],
			[AS_VAR_SET([lb_header], [no])])
	])
	AS_VAR_IF([lb_header], [yes], [$2], [$3])
	AS_VAR_POPDEF([lb_header])
]) # LB_CHECK_LINUX_HEADER

# ------------------------------------------------------------------------------
# Support 2 stage: parallel compile then checked test results
# Heavily inspired by OpenZFS

# When converting tests from an LB_CHECK_COMPILE to use an
# LB2_LINUX_TEST_SRC and LB2_LINUX_TEST_RESULT pairing the primary
# consideration if dependencies on the results of LB2_LINUX_TEST_RESULT
# or LB2_TEST_CHECK_CONFIG[_IM] are used by annother compile test.
# Such dependencies should be avoided without a clear understanding
# of when the test result is actually available.
# The serial LB_CHECK_* test produces immediate results
# where as the LB2_ variant is not available until an intermediate
# LB2_LINUX_TEST_COMPILE_ALL has been executed.
#
# Currently all of the non-conditional LB_CHECK_COMPILE and
# LB_CHECK_CONFIG[_IM] cases are executed before any of the
# LB2_LINUX_TEST_SRC, or LB2_SRC_CHECK_CONFIG[_IM] code snippets
# are written. [Reference LB_CONFIG_MODULES for more details]
#
# This allows such LB2_*_SRC_* test cases to rely on
# prior LB_CHECK_* results, provided such results are preserved
# in the global configure name space. Likewise an LB2_LINUX_TEST_RESULT
# or LB2_TEST_CHECK_CONFIG[_IM] may conditionally execute a further
# LB_CHECK_* if required. Although it would be typcially be faster
# to run a few compile tests and conditionally ignore the results
# the reduced configure time may not always out weight the added
# complexity.
#
# It is worth noting that the LB_CHECK_COMPILE macros second argument
# is used as the configure test cache name. While is has been important
# that this name be globally unique it is even more important in the
# parallel case. The is somewhat alleviated by the sanity check in the
# LB2_LINUX_TEST_RESULT macro as it will abort with an error if
# the cache name does not exist. However care should be taken
# that the cache name is a globally unique identifier.
#
# Non-unique cases that are otherwise correct can be identified in the
# configure output when a results include ".. (cached)". This indicates
# either a duplicate LB_CHECK_* execution which is not critical or a
# duplicate identifier which needs to be corrected.
#
# At this point the number of LB_ and LB2_ examples should be
# sufficient for the casual developer to perform cut-paste-modify
# without serious confusion or complication.
# ------------------------------------------------------------------------------

AC_DEFUN([LB2_LINUX_CONFTEST_C], [
TEST_DIR=${TEST_DIR:-${ac_pwd}/_lpb}
test -d ${TEST_DIR}/$2 || mkdir -p ${TEST_DIR}/$2
cat confdefs.h - <<_EOF >${TEST_DIR}/$2/$2.c
$1
_EOF
])

#
# LB2_LINUX_CONFTEST_MAKEFILE
#
# $1 - *unique* test case name
# $2 - additional build flags (ccflags)
# $3 - external kernel includes for lnet o2ib|gni
# $4 - extra symbol in Psuedo.symvers (optional)
#
AC_DEFUN([LB2_LINUX_CONFTEST_MAKEFILE], [
	TEST_DIR=${TEST_DIR:-${ac_pwd}/_lpb}
	test -d ${TEST_DIR} || mkdir -p ${TEST_DIR}
	test -d ${TEST_DIR}/$1 || mkdir -p ${TEST_DIR}/$1

	file=${TEST_DIR}/$1/Makefile
	EXT_INCLUDE="$3"
	EXT_SYMBOL="$4"
	PSYM_FILE=""
	if test "${EXT_SYMBOL}x" != "x" ; then
		PSYM_FILE=${TEST_DIR}/$1/Psuedo.symvers
		echo -e "0x12345678\t${EXT_SYMBOL}\tvmlinux\tEXPORT_SYMBOL\t" > ${PSYM_FILE}
	fi
	XTRA_SYM=
	if test "x$O2IBPATH" != "x"; then
		if test "x$O2IBPATH" != "x$LINUX_OBJ"; then
			XTRA_SYM="$O2IBPATH/Module.symvers"
		fi
	fi

	cat - <<_EOF >$file
# Example command line to manually build source
# make modules -C $LINUX_OBJ $ARCH_UM M=${TEST_DIR}/$1 $MAKE_KMOD_ENV

${LD:+LD="$LD"}
CC=$CC
ZINC=${ZFS}
SINC=${SPL}
ZOBJ=${ZFS_OBJ}
SOBJ=${SPL_OBJ}
PSYM=${PSYM_FILE}

LINUXINCLUDE  = $EXT_INCLUDE
LINUXINCLUDE += -I$LINUX/arch/$SUBARCH/include
LINUXINCLUDE += -Iinclude -Iarch/$SUBARCH/include/generated
LINUXINCLUDE += -I$LINUX/include
LINUXINCLUDE += -Iinclude2
LINUXINCLUDE += -I$LINUX/include/uapi
LINUXINCLUDE += -Iinclude/generated
LINUXINCLUDE += -I$LINUX/arch/$SUBARCH/include/uapi
LINUXINCLUDE += -Iarch/$SUBARCH/include/generated/uapi
LINUXINCLUDE += -I$LINUX/include/uapi -Iinclude/generated/uapi
ifneq (\$(SOBJ),)
LINUXINCLUDE += -include \$(SOBJ)/spl_config.h
endif
ifneq (\$(ZOBJ),)
LINUXINCLUDE += -include \$(ZOBJ)/zfs_config.h
endif
ifneq (\$(SINC),)
LINUXINCLUDE += -I\$(SINC)/include
endif
ifneq (\$(ZINC),)
LINUXINCLUDE += -I\$(ZINC) -I\$(ZINC)/include
ifneq (\$(SINC),)
LINUXINCLUDE += -I\$(SINC)
else
LINUXINCLUDE += -I\$(ZINC)/include/spl
endif
endif
LINUXINCLUDE += -include $CONFIG_INCLUDE
KBUILD_EXTRA_SYMBOLS += ${ZFS_OBJ:+$ZFS_OBJ/Module.symvers}
KBUILD_EXTRA_SYMBOLS += ${XTRA_SYM}
ifneq (\$(PSYM),)
KBUILD_EXTRA_SYMBOLS += \$(PSYM)
endif

ccflags-y := -Werror-implicit-function-declaration
_EOF

	# Additional custom CFLAGS as requested.
	m4_ifval($2, [echo "ccflags-y += $2" >>$file], [])

	# Test case source
	echo "obj-m := $1.o" >>$file
	echo "obj-m += $1/" >>${TEST_DIR}/Makefile
])

#
# LB2_LINUX_TEST_COMPILE
#
# Perform a full compile excluding the final modpost phase.
# $1 - flavor
# $2 - dirname
#
AC_DEFUN([LB2_LINUX_TEST_COMPILE], [
	D="$(realpath [$2])"
	L="$D/build.log.$1"
	J=${TEST_JOBS:-$(nproc)}

	AC_MSG_NOTICE([Making $1 in $D])
	AC_MSG_NOTICE([KBUILD_MODPOST_NOFINAL="yes" make modules -k -j${J} -C $LINUX_OBJ $ARCH_UM M=${D} $MAKE_KMOD_ENV])

	AC_TRY_COMMAND([KBUILD_MODPOST_NOFINAL="yes"
		make modules -k -j${J} -C $LINUX_OBJ $ARCH_UM M=${D} $MAKE_KMOD_ENV >${L} 2>&1])
	AS_IF([test -f ${L}],
	      [AS_IF([test -f $2/Makefile],
		     [mv $2/Makefile $2/Makefile.compile.$1])],
	      [AC_MSG_ERROR([*** Unable to compile test source ... $3])
	])
])

#
# Perform the compilation of the test cases in two phases.
#
# Phase 1) attempt to build the object files for all of the tests
#          defined by the LB2_LINUX_TEST_SRC macro.
#
# Phase 2) disable all tests which failed the initial compilation.
#
# This allows us efficiently build the test cases in parallel while
# remaining resilient to build failures which are expected when
# detecting the available kernel interfaces.
#
# The maximum allowed parallelism can be controlled by setting the
# TEST_JOBS environment variable which defaults to $(nproc).
#
AC_DEFUN([LB2_LINUX_TEST_COMPILE_ALL], [
	TEST_DIR=${TEST_DIR:-${ac_pwd}/_lpb}
	# Phase 1 - Compilation only, final linking is skipped.
	LB2_LINUX_TEST_COMPILE([$1], [${TEST_DIR}], [$2])
	for dir in $(awk '/^obj-m/ { print [$]3 }' \
	    ${TEST_DIR}/Makefile.compile.$1); do
		name=${dir%/}
		touch ${TEST_DIR}/$name/$name.tested
	done
])

#
# LB2_LINUX_TEST_SRC
#
# $1 - *unique* name
# $2 - global
# $3 - source
# $4 - extra cflags
# $5 - external include paths
# $6 - fake symvers entry
#
# NOTICE as all of the test cases are compiled in parallel tests may not
# depend on the results other tests.
# Each test needs resolve any external dependencies at the time the program
# source is generated.
#
AC_DEFUN([LB2_LINUX_TEST_SRC], [
	TEST_DIR=${TEST_DIR:-${ac_pwd}/_lpb}
	AS_VAR_PUSHDEF([lb_test], [lb_cv_test_$1])
	# Skip test write and build steps if the result is already known.
	LB2_LINUX_CONFTEST_C([LB_LANG_PROGRAM([[$2]], [[$3]])], [$1_pc])
	LB2_LINUX_CONFTEST_MAKEFILE([$1_pc], [$4], [$5], [$6])
	AS_VAR_POPDEF([lb_test])
])

#
# LB2_LINUX_TEST_RESULT
#
# $1 - *unique* name matching the LB2_LINUX_TEST_SRC macro
# $2 - run on success (valid .ko generated)
# $3 - run on failure (unable to compile)
#
AC_DEFUN([LB2_LINUX_TEST_RESULT],[
	TEST_DIR=${TEST_DIR:-${ac_pwd}/_lpb}
	AS_VAR_PUSHDEF([lb_test], [lb_cv_test_$1])
	D="$(realpath ${TEST_DIR})"
	T=${D}/$1_pc
	O=${T}/$1_pc
	AS_IF([test -d ${T}], [
		# test source exists, was the compile test run?
		AS_IF([test -f ${O}.tested],[
			# compile test was run.
		],[
			# compile test was NOT run. Re-compile everything.
			AC_MSG_NOTICE([** Rebuilding all tests **])

			J=${TEST_JOBS:-$(nproc)}
			for mf in $(ls -1 ${TEST_DIR}/Makefile.compile.*); do
				ln -sf $mf ${D}/Makefile
				KBUILD_MODPOST_NOFINAL="yes"
				make modules -k -j${J} -C $LINUX_OBJ $ARCH_UM M=${D} >> rebuild.log 2>&1

				for dir in $(awk '/^obj-m/ { print [$]3 }' ${D}/$mf); do
					name=${dir%/}
					AC_MSG_NOTICE([touch ${D}/$name/$name.tested])
					touch ${D}/$name/$name.tested
				done
				rm ${D}/Makefile
			done
			# compile test was NOT run. Re-compile everything.
		])
	],[
		# test source does not exist:
		AC_MSG_ERROR([
*** No matching source for the "$1" test, check that
*** both the test source and result macros refer to the same name.
		])
	])
	# Abort if key does not exist
	AS_IF([test -f ${O}.tested], [],
		[AC_MSG_ERROR([*** Compile test for $1 was not run.])])
	# If test was compiled and if we got an object ...
	AS_IF([test -f ${O}.o], [touch ${O}.ko])
	# key is valid. Cache should be valid, set the variable
	AC_CACHE_CHECK([for $1], lb_test,
		AS_IF([test -f ${O}.ko],
			AS_VAR_SET([lb_test], [yes]),
			AS_VAR_SET([lb_test], [no])))
	# Read the variable and run the caller's actions for yes (arg2) or no (arg3)
	AS_VAR_IF([lb_test], [yes], $2, $3)
	AS_VAR_POPDEF([lb_test])
]) # LB2_LINUX_TEST_RESULT

#
# LB2_SRC_CHECK_CONFIG
#
# generate source to check if a given config option is defined
#
#   $1 - CONFIG_<name>
#
AC_DEFUN([LB2_SRC_CHECK_CONFIG], [
	LB2_LINUX_TEST_SRC([config_$1], [
		#include <$AUTOCONF_HDIR/autoconf.h>
	], [
		#ifndef CONFIG_$1
		#error CONFIG_$1 not #defined
		#endif
	])
]) # LB2_SRC_CHECK_CONFIG

#
# LB2_TEST_CHECK_CONFIG
#
# test result compile test from LB2_SRC_CHECK_CONFIG
#
#   $1 - CONFIG_<name>
#   $2 - do 'yes'
#   $3 - do 'no'
#
AC_DEFUN([LB2_TEST_CHECK_CONFIG], [
	AC_MSG_CHECKING([if Linux kernel was built with CONFIG_$1])
	LB2_LINUX_TEST_RESULT([config_$1], [
		$2
	],[
		$3
	])
]) # LB2_TEST_CHECK_CONFIG

#
# LB2_SRC_CHECK_CONFIG_IM
#
# generate source to check if a given config option is defined as built-in
# or as a module.
#
#    $1 - CONFIG_<name> or CONFIG_<name>_MODULE
#
AC_DEFUN([LB2_SRC_CHECK_CONFIG_IM], [
	LB2_LINUX_TEST_SRC([config_im_$1], [
		#include <$AUTOCONF_HDIR/autoconf.h>
	], [
		#if !(defined(CONFIG_$1) || defined(CONFIG_$1_MODULE))
		#error CONFIG_$1 and CONFIG_$1_MODULE not #defined
		#endif
	])
]) # LB2_SRC_CHECK_CONFIG_IM


#
# LB2_TEST_CHECK_CONFIG_IM
#
# test result compile test from LB2_SRC_CHECK_CONFIG_IM
#
#   $1 - CONFIG_<name>
#   $2 - do 'yes'
#   $3 - do 'no'
#
AC_DEFUN([LB2_TEST_CHECK_CONFIG_IM], [
	AC_MSG_CHECKING([if Linux kernel enabled CONFIG_$1 as built-in or module])
	LB2_LINUX_TEST_RESULT([config_im_$1], [
		$2
	],[
		$3
	])
]) # LB2_TEST_CHECK_CONFIG_IM
