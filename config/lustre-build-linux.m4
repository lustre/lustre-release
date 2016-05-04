#
# LB_LINUX_VERSION
#
# Set things accordingly for a linux kernel
#
AC_DEFUN([LB_LINUX_VERSION], [
KMODEXT=".ko"
AC_SUBST(KMODEXT)

makerule="$PWD/build"
AC_CACHE_CHECK([for external module build target], lb_cv_module_target, [
lb_cv_module_target=""
MODULE_TARGET="SUBDIRS"
rm -f build/conftest.i
LB_LINUX_TRY_MAKE([], [],
	[$makerule LUSTRE_KERNEL_TEST=conftest.i],
	[test -s build/conftest.i],
	[lb_cv_module_target="SUBDIRS"], [
		MODULE_TARGET="M"
		makerule="_module_$PWD/build"
		LB_LINUX_TRY_MAKE([], [],
			[$makerule LUSTRE_KERNEL_TEST=conftest.i],
			[test -s build/conftest.i],
			[lb_cv_module_target="M"], [
				AC_MSG_ERROR([unknown; check config.log for details])
			])
	])
])
AS_IF([test -z "$lb_cv_module_target"],
	[AC_MSG_ERROR([unknown external module build target])],
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

# check if the kernel is one from RHEL or SUSE
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
	RHEL_RELEASE_NO=$lb_cv_rhel_kernel_version
], [
	RHEL_KERNEL="no"
	LB_CHECK_CONFIG([SUSE_KERNEL], [SUSE_KERNEL="yes"], [SUSE_KERNEL="no"])
])

AC_MSG_CHECKING([for Linux kernel module package directory])
AC_ARG_WITH([kmp-moddir],
	AC_HELP_STRING([--with-kmp-moddir=string],
		[set the kmod updates or extra directory]),
	[KMP_MODDIR=$withval
	 IN_KERNEL=''],[
	AS_IF([test x$RHEL_KERNEL = xyes], [KMP_MODDIR="extra/kernel"],
	      [test x$SUSE_KERNEL = xyes], [KMP_MODDIR="updates/kernel"])
	IN_KERNEL="${PACKAGE}"])
AC_MSG_RESULT($KMP_MODDIR)

moduledir="/lib/modules/${LINUXRELEASE}/${KMP_MODDIR}"

modulefsdir="${moduledir}/fs/${IN_KERNEL}"
AC_SUBST(modulefsdir)

modulenetdir="${moduledir}/net/${IN_KERNEL}"
AC_SUBST(modulenetdir)
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
for DEFAULT_LINUX in /lib/modules/$(uname -r)/{source,build} /usr/src/linux; do
	AS_IF([readlink -q -e $DEFAULT_LINUX >/dev/null], [break])
done
if test "$DEFAULT_LINUX" = "/lib/modules/$(uname -r)/source"; then
	PATHS="/lib/modules/$(uname -r)/build"
fi
PATHS+=" $DEFAULT_LINUX"
for DEFAULT_LINUX_OBJ in $PATHS; do
	AS_IF([readlink -q -e $DEFAULT_LINUX_OBJ >/dev/null], [break])
done

AC_MSG_CHECKING([for Linux sources])
AC_ARG_WITH([linux],
	AC_HELP_STRING([--with-linux=path],
		       [set path to Linux source (default=/lib/modules/$(uname -r)/{source,build},/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux], [LINUX])
	DEFAULT_LINUX_OBJ=$LINUX],
	[LINUX=$DEFAULT_LINUX])
AC_MSG_RESULT([$LINUX])
AC_SUBST(LINUX)

# -------- check for linux --------
LB_CHECK_FILE([$LINUX], [],
	[AC_MSG_ERROR([Kernel source $LINUX could not be found.])])

# -------- linux objects (for 2.6) --
AC_MSG_CHECKING([for Linux objects])
AC_ARG_WITH([linux-obj],
	AC_HELP_STRING([--with-linux-obj=path],
			[set path to Linux objects (default=/lib/modules/$(uname -r)/build,/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux-obj], [LINUX_OBJ])],
	[LINUX_OBJ=$DEFAULT_LINUX_OBJ])
AC_MSG_RESULT([$LINUX_OBJ])
AC_SUBST(LINUX_OBJ)

# -------- check for .config --------
AC_ARG_WITH([linux-config],
	[AC_HELP_STRING([--with-linux-config=path],
			[set path to Linux .conf (default=$LINUX_OBJ/.config)])],
	[LB_ARG_CANON_PATH([linux-config], [LINUX_CONFIG])],
	[LINUX_CONFIG=$LINUX_OBJ/.config])

# -------- check if .config exists --
LB_CHECK_FILE([$LINUX_CONFIG], [],
	[AC_MSG_ERROR([

Kernel config could not be found.

If you are building from a kernel-source rpm consult build/README.kernel-source
])
])
AC_SUBST(LINUX_CONFIG)

LB_CHECK_FILE([/boot/kernel.h],
	[KERNEL_SOURCE_HEADER='/boot/kernel.h'],
	[LB_CHECK_FILE([/var/adm/running-kernel.h],
		[KERNEL_SOURCE_HEADER='/var/adm/running-kernel.h'])])

AC_ARG_WITH([kernel-source-header],
	AC_HELP_STRING([--with-kernel-source-header=path],
			[Use a different kernel version header.  Consult build/README.kernel-source for details.]),
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

# this is needed before we can build modules
LB_LINUX_VERSION

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

#
# LB_PROG_LINUX
#
# linux tests
#
AC_DEFUN([LB_PROG_LINUX], [
LB_LINUX_PATH
LB_LINUX_SYMVERFILE

LB_CHECK_CONFIG([MODULES], [], [
	AC_MSG_ERROR([

module support is required to build Lustre kernel modules.
])
	])

LB_CHECK_CONFIG([MODVERSIONS])

LB_CHECK_CONFIG([KALLSYMS], [], [
	AC_MSG_ERROR([

Lustre requires that CONFIG_KALLSYMS is enabled in your kernel.
])
	])

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
AS_CASE([$(lsb_release -i -s 2>/dev/null)],
	[Ubuntu | Debian], [lb_cv_uses_dpkg="yes"])
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
$1
int
main (void)
{
dnl Do *not* indent the following line: there may be CPP directives.
dnl Don't move the `;' right after for the same reason.
$2
  ;
  return 0;
}])

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
SUBARCH=$(echo $target_cpu | sed -e 's/powerpc.*/powerpc/' -e 's/ppc.*/powerpc/' -e 's/x86_64/x86/' -e 's/i.86/x86/' -e 's/k1om/x86/' -e 's/aarch64.*/arm64/')
AS_IF([AC_TRY_COMMAND(cp conftest.c build && make -d [$2] LDFLAGS= ${LD:+LD="$LD"} CC="$CC" -f $PWD/build/Makefile LUSTRE_LINUX_CONFIG=$LINUX_CONFIG LINUXINCLUDE="$EXTRA_CHECK_INCLUDE -I$LINUX/arch/$SUBARCH/include -Iinclude -Iarch/$SUBARCH/include/generated -I$LINUX/include -Iinclude2 -I$LINUX/include/uapi -Iinclude/generated -I$LINUX/arch/$SUBARCH/include/uapi -Iarch/$SUBARCH/include/generated/uapi -I$LINUX/include/uapi -Iinclude/generated/uapi ${SPL_OBJ:+-include $SPL_OBJ/spl_config.h} ${ZFS_OBJ:+-include $ZFS_OBJ/zfs_config.h} ${SPL:+-I$SPL -I$SPL/include } ${ZFS:+-I$ZFS -I$ZFS/include} -include $CONFIG_INCLUDE" -o tmp_include_depends -o scripts -o include/config/MARKER -C $LINUX_OBJ EXTRA_CFLAGS="-Werror-implicit-function-declaration $EXTRA_KCFLAGS" $MODULE_TARGET=$PWD/build) >/dev/null && AC_TRY_COMMAND([$3])],
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
m4_define([LB_CHECK_LINUX_HEADER], [
AS_VAR_PUSHDEF([lb_header], [lb_cv_header_$1])dnl
AC_CACHE_CHECK([for $1], lb_header, [
	LB_LINUX_COMPILE_IFELSE([LB_LANG_PROGRAM([@%:@include <$1>])],
		[modules], [test -s build/conftest.o],
		[AS_VAR_SET([lb_header], [yes])],
		[AS_VAR_SET([lb_header], [no])])
])
AS_VAR_IF([lb_header], [yes], [$2], [$3])[]dnl
AS_VAR_POPDEF([lb_header])dnl
]) # LB_CHECK_LINUX_HEADER
