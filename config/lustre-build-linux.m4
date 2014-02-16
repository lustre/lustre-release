#
# LB_LINUX_VERSION
#
# Set things accordingly for a linux kernel
#
AC_DEFUN([LB_LINUX_VERSION],[
KMODEXT=".ko"

MODULE_TARGET="SUBDIRS"
makerule="$PWD/build"
AC_MSG_CHECKING([for external module build support])
rm -f build/conftest.i
LB_LINUX_TRY_MAKE([],[],
	[$makerule LUSTRE_KERNEL_TEST=conftest.i],
	[test -s build/conftest.i],
	[
		AC_MSG_RESULT([no])
	],[
		makerule="_module_$makerule"
		MODULE_TARGET="M"
		LB_LINUX_TRY_MAKE([],[],
			[$makerule LUSTRE_KERNEL_TEST=conftest.i],
			[test -s build/conftest.i],
			[
				AC_MSG_RESULT([yes])
			],[
				AC_MSG_ERROR([unknown; check config.log for details])
			])
	])

AC_SUBST(MODULE_TARGET)
AC_SUBST(KMODEXT)
])

#
# LB_LINUX_UTSRELEASE
#
# Determine the Linux kernel version string from the utsrelease
#
AC_DEFUN([LB_LINUX_UTSRELEASE], [
	AC_MSG_CHECKING([kernel source version])

	utsrelease1=${LINUX_OBJ}/include/generated/utsrelease.h
	utsrelease2=${LINUX_OBJ}/include/linux/utsrelease.h
	utsrelease3=${LINUX_OBJ}/include/linux/version.h
	AS_IF([test -r ${utsrelease1} && fgrep -q UTS_RELEASE ${utsrelease1}], [
		utsrelease=${utsrelease1}
	], [test -r ${utsrelease2} && fgrep -q UTS_RELEASE ${utsrelease2}], [
		utsrelease=${utsrelease2}
	], [test -r ${utsrelease3} && fgrep -q UTS_RELEASE ${utsrelease3}], [
		utsrelease=${utsrelease3}
	])

	AS_IF([test ! -z "${utsrelease}"], [
		UTS_RELEASE=$(awk -F \" '/ UTS_RELEASE / { print [$]2 }' \
		              ${utsrelease})
		AS_IF([test -z "$UTS_RELEASE"], [
			AC_MSG_RESULT([Not found])
			AC_MSG_ERROR([*** Cannot determine kernel version.])
		])
	], [
		AC_MSG_RESULT([Not found])
		AC_MSG_ERROR([
	*** Cannot find UTS_RELEASE definition.
	*** This is often provided by the kernel-devel package.])
	])

	AC_MSG_RESULT([${UTS_RELEASE}])

	LINUX_VERSION=${UTS_RELEASE}
	AC_SUBST(LINUX_VERSION)
	LINUXRELEASE=${UTS_RELEASE}
	AC_SUBST(LINUXRELEASE)
])


#
# LB_LINUX_RELEASE
#
# get the release version of linux
#
AC_DEFUN([LB_LINUX_RELEASE],
[
LB_LINUX_UTSRELEASE

# ------------ RELEASE --------------------------------
AC_MSG_CHECKING([for Lustre release])
AC_ARG_WITH([release],
	AC_HELP_STRING([--with-release=string],
		       [set the release string (default=$kvers_YYYYMMDDhhmm)]),
	[RELEASE=$withval],[
	RELEASE=""
	if test -n "$DOWNSTREAM_RELEASE"; then
		RELEASE="${DOWNSTREAM_RELEASE}_"
	fi
	RELEASE="$RELEASE`echo ${LINUXRELEASE} | tr '-' '_'`_$BUILDID"])
AC_MSG_RESULT($RELEASE)
AC_SUBST(RELEASE)

# check if the kernel is one from RHEL or SUSE
AC_MSG_CHECKING([for RedHat kernel version])
	AS_IF([fgrep -q RHEL_RELEASE ${LINUX_OBJ}/include/$VERSION_HDIR/version.h], [
		RHEL_KERNEL="yes"
		RHEL_RELEASE=$(expr 0$(awk -F \" '/ RHEL_RELEASE / { print [$]2 }' \
			       ${LINUX_OBJ}/include/$VERSION_HDIR/version.h) + 1)
		KERNEL_VERSION=$(sed -e 's/\(@<:@23@:>@\.@<:@0-9@:>@*\.@<:@0-9@:>@*\).*/\1/' <<< ${LINUXRELEASE})
		RHEL_KERNEL_VERSION=${KERNEL_VERSION}-${RHEL_RELEASE}
		AC_SUBST(RHEL_KERNEL_VERSION)
		AC_MSG_RESULT([${RHEL_KERNEL_VERSION}])
	], [
		AC_MSG_RESULT([not found])
		LB_LINUX_CONFIG([SUSE_KERNEL],[SUSE_KERNEL="yes"],[])
	])

AC_MSG_CHECKING([for kernel module package directory])
AC_ARG_WITH([kmp-moddir],
	AC_HELP_STRING([--with-kmp-moddir=string],
		       [set the kmod updates or extra directory]),
	[KMP_MODDIR=$withval],[
	AS_IF([test x$RHEL_KERNEL = xyes], [KMP_MODDIR="extra"],
	      [test x$SUSE_KERNEL = xyes], [KMP_MODDIR="updates"])])

AC_MSG_RESULT($KMP_MODDIR)
AC_SUBST(KMP_MODDIR)

moduledir='$(CROSS_PATH)/lib/modules/$(LINUXRELEASE)/$(KMP_MODDIR)/kernel'
AC_SUBST(moduledir)

modulefsdir='$(moduledir)/fs/$(PACKAGE)'
AC_SUBST(modulefsdir)

modulenetdir='$(moduledir)/net/$(PACKAGE)'
AC_SUBST(modulenetdir)

])

# LB_ARG_REPLACE_PATH(PACKAGE, PATH)
AC_DEFUN([LB_ARG_REPLACE_PATH],[
	new_configure_args=
	eval "set x $ac_configure_args"
	shift
	for arg; do
		case $arg in
			--with-[$1]=*)
				arg=--with-[$1]=[$2]
				;;
			*\'*)
				arg=$(printf %s\n ["$arg"] | \
				      sed "s/'/'\\\\\\\\''/g")
				;;
		esac
		dnl AS_VAR_APPEND([new_configure_args], [" '$arg'"])
		new_configure_args="$new_configure_args \"$arg\""
	done
	ac_configure_args=$new_configure_args
])

# this is the work-horse of the next function
AC_DEFUN([__LB_ARG_CANON_PATH], [
	[$3]=$(readlink -f $with_$2)
	LB_ARG_REPLACE_PATH([$1], $[$3])
])

# a front-end for the above function that transforms - and . in the
# PACKAGE portion of --with-PACKAGE into _ suitable for variable names
AC_DEFUN([LB_ARG_CANON_PATH], [
	__LB_ARG_CANON_PATH([$1], m4_translit([$1], [-.], [__]), [$2])
])

#
#
# LB_LINUX_PATH
#
# Find paths for linux, handling kernel-source rpms
#
AC_DEFUN([LB_LINUX_PATH],
[# prep some default values
for DEFAULT_LINUX in /lib/modules/$(uname -r)/{source,build} /usr/src/linux; do
	if readlink -q -e $DEFAULT_LINUX; then
		break
	fi
done
if test "$DEFAULT_LINUX" = "/lib/modules/$(uname -r)/source"; then
	PATHS="/lib/modules/$(uname -r)/build"
fi
PATHS+=" $DEFAULT_LINUX"
for DEFAULT_LINUX_OBJ in $PATHS; do
	if readlink -q -e $DEFAULT_LINUX_OBJ; then
		break
	fi
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
LB_CHECK_FILE([$LINUX],[],
	[AC_MSG_ERROR([Kernel source $LINUX could not be found.])])

# -------- linux objects (for 2.6) --
AC_MSG_CHECKING([for Linux objects dir])
AC_ARG_WITH([linux-obj],
	AC_HELP_STRING([--with-linux-obj=path],
			[set path to Linux objects dir (default=/lib/modules/$(uname -r)/build,/usr/src/linux)]),
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
AC_SUBST(LINUX_CONFIG)

LB_CHECK_FILE([/boot/kernel.h],
	[KERNEL_SOURCE_HEADER='/boot/kernel.h'],
	[LB_CHECK_FILE([/var/adm/running-kernel.h],
		[KERNEL_SOURCE_HEADER='/var/adm/running-kernel.h'])])

AC_ARG_WITH([kernel-source-header],
	AC_HELP_STRING([--with-kernel-source-header=path],
			[Use a different kernel version header.  Consult build/README.kernel-source for details.]),
	[LB_ARG_CANON_PATH([kernel-source-header], [KERNEL_SOURCE_HEADER])])

# ------------ .config exists ----------------
LB_CHECK_FILE([$LINUX_CONFIG],[],
	[AC_MSG_ERROR([Kernel config could not be found.  If you are building from a kernel-source rpm consult build/README.kernel-source])])

# ----------- make dep run? ------------------
# at 2.6.19 # $LINUX/include/linux/config.h is removed
# and at more old has only one line
# include <autoconf.h>
LB_CHECK_FILE([$LINUX_OBJ/include/generated/autoconf.h],[AUTOCONF_HDIR=generated],
        [LB_CHECK_FILE([$LINUX_OBJ/include/linux/autoconf.h],[AUTOCONF_HDIR=linux],
	[AC_MSG_ERROR([Run make config in $LINUX.])])])
        AC_SUBST(AUTOCONF_HDIR)
LB_CHECK_FILE([$LINUX_OBJ/include/linux/version.h], [VERSION_HDIR=linux],
	[LB_CHECK_FILE([$LINUX_OBJ/include/generated/uapi/linux/version.h],
		[VERSION_HDIR=generated/uapi/linux],
		[AC_MSG_ERROR([Run make config in $LINUX.])])
	])
	AC_SUBST(VERSION_HDIR)

# ----------- kconfig.h exists ---------------
# kernel 3.1, $LINUX/include/linux/kconfig.h is added
# see kernel commit 2a11c8ea20bf850b3a2c60db8c2e7497d28aba99
LB_CHECK_FILE([$LINUX_OBJ/include/linux/kconfig.h],
              [CONFIG_INCLUDE=include/linux/kconfig.h],
              [CONFIG_INCLUDE=include/$AUTOCONF_HDIR/autoconf.h])
	AC_SUBST(CONFIG_INCLUDE)

# ------------ rhconfig.h includes runtime-generated bits --
# red hat kernel-source checks

# we know this exists after the check above.  if the user
# tarred up the tree and ran make dep etc. in it, then
# version.h gets overwritten with a standard linux one.

if grep rhconfig $LINUX_OBJ/include/$VERSION_HDIR/version.h >/dev/null ; then
	# This is a clean kernel-source tree, we need to
	# enable extensive workarounds to get this to build
	# modules
	LB_CHECK_FILE([$KERNEL_SOURCE_HEADER],
		[if test $KERNEL_SOURCE_HEADER = '/boot/kernel.h' ; then
			AC_MSG_WARN([Using /boot/kernel.h from RUNNING kernel.])
			AC_MSG_WARN([If this is not what you want, use --with-kernel-source-header.])
			AC_MSG_WARN([Consult build/README.kernel-source for details.])
		fi],
		[AC_MSG_ERROR([$KERNEL_SOURCE_HEADER not found.  Consult build/README.kernel-source for details.])])
	EXTRA_KCFLAGS="-include $KERNEL_SOURCE_HEADER $EXTRA_KCFLAGS"
fi

# this is needed before we can build modules
LB_LINUX_CROSS
LB_LINUX_VERSION

# --- check that we can build modules at all
AC_MSG_CHECKING([that modules can be built at all])
LB_LINUX_TRY_COMPILE([],[],[
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
	AC_MSG_WARN([Consult config.log for details.])
	AC_MSG_WARN([If you are trying to build with a kernel-source rpm, consult build/README.kernel-source])
	AC_MSG_ERROR([Kernel modules cannot be built.])
])

LB_LINUX_RELEASE
]) # end of LB_LINUX_PATH

# LB_LINUX_SYMVERFILE
# SLES 9 uses a different name for this file - unsure about vanilla kernels
# around this version, but it matters for servers only.
AC_DEFUN([LB_LINUX_SYMVERFILE],
	[AC_MSG_CHECKING([name of module symbol version file])
	if grep -q Modules.symvers $LINUX/scripts/Makefile.modpost ; then
		SYMVERFILE=Modules.symvers
	else
		SYMVERFILE=Module.symvers
	fi
	AC_MSG_RESULT($SYMVERFILE)
	AC_SUBST(SYMVERFILE)
])

#
# LB_LINUX_CROSS
#
# check for cross compilation
#
AC_DEFUN([LB_LINUX_CROSS],
	[AC_MSG_CHECKING([for cross compilation])
AS_IF([test "x$cross_compiling" = xno], [AC_MSG_RESULT([no])],
	[case $host_vendor in
		# The K1OM architecture is an extension of the x86 architecture
		# and in MPSS 2.1 it's defined in $host_vendor. But in MPSS 3.x
		# it's defined in $host_arch. So, try to support both case.
		k1om | mpss)
			AC_MSG_RESULT([Intel(R) Xeon Phi(TM)])
			CC_TARGET_ARCH=`$CC -v 2>&1 | grep Target: | sed -e 's/Target: //'`
			AC_SUBST(CC_TARGET_ARCH)
			if test \( $CC_TARGET_ARCH != x86_64-k1om-linux \
				-a $CC_TARGET_ARCH != k1om-mpss-linux \)
			then
				AC_MSG_ERROR([Cross compiler not found in PATH.])
			fi
			CROSS_VARS="ARCH=k1om CROSS_COMPILE=${CC_TARGET_ARCH}-"
			CROSS_PATH="${CROSS_PATH:=/opt/lustre/${VERSION}/${CC_TARGET_ARCH}}"
			CCAS=$CC
			# need to produce special section for debuginfo extraction
			LDFLAGS="${LDFLAGS} -Wl,--build-id"
			EXTRA_KLDFLAGS="${EXTRA_KLDFLAGS} -Wl,--build-id"
			if test x$enable_server != xno ; then
				AC_MSG_WARN([Disabling server (not supported for k1om architecture).])
				enable_server='no'
			fi
			;;
		*)
			AC_MSG_RESULT([yes, but no changes])
			;;
	esac
	])
AC_SUBST(CROSS_VARS)
AC_SUBST(CROSS_PATH)
])

# these are like AC_TRY_COMPILE, but try to build modules against the
# kernel, inside the build directory

# LB_LANG_PROGRAM(C)([PROLOGUE], [BODY])
# --------------------------------------
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
AC_DEFUN([LB_LINUX_COMPILE_IFELSE],
[m4_ifvaln([$1], [AC_LANG_CONFTEST([$1])])dnl
rm -f build/conftest.o build/conftest.mod.c build/conftest.ko
SUBARCH=$(echo $target_cpu | sed -e 's/powerpc64/powerpc/' -e 's/x86_64/x86/' -e 's/i.86/x86/' -e 's/k1om/x86/')
AS_IF([AC_TRY_COMMAND(cp conftest.c build && make -d [$2] ${LD:+"LD=$LD"} CC="$CC" -f $PWD/build/Makefile LUSTRE_LINUX_CONFIG=$LINUX_CONFIG LINUXINCLUDE="$EXTRA_OFED_INCLUDE -I$LINUX/arch/$SUBARCH/include -I$LINUX/arch/$SUBARCH/include/generated -Iinclude -I$LINUX/include -Iinclude2 -I$LINUX/include/uapi -I$LINUX/include/generated -I$LINUX/arch/$SUBARCH/include/uapi -Iarch/$SUBARCH/include/generated/uapi -I$LINUX/include/uapi -Iinclude/generated/uapi ${SPL_OBJ:+-include $SPL_OBJ/spl_config.h} ${ZFS_OBJ:+-include $ZFS_OBJ/zfs_config.h} ${SPL:+-I$SPL -I$SPL/include } ${ZFS:+-I$ZFS -I$ZFS/include} -include $CONFIG_INCLUDE" -o tmp_include_depends -o scripts -o include/config/MARKER -C $LINUX_OBJ EXTRA_CFLAGS="-Werror-implicit-function-declaration $EXTRA_KCFLAGS" $CROSS_VARS $MODULE_TARGET=$PWD/build) >/dev/null && AC_TRY_COMMAND([$3])],
	[$4],
	[_AC_MSG_LOG_CONFTEST
m4_ifvaln([$5],[$5])dnl])
rm -f build/conftest.o build/conftest.mod.c build/conftest.mod.o build/conftest.ko m4_ifval([$1], [build/conftest.c conftest.c])[]dnl
])

#
# LB_LINUX_ARCH
#
# Determine the kernel's idea of the current architecture
#
AC_DEFUN([LB_LINUX_ARCH],
         [AC_MSG_CHECKING([Linux kernel architecture])
          AS_IF([rm -f $PWD/build/arch
                 make -s --no-print-directory echoarch -f $PWD/build/Makefile \
                     LUSTRE_LINUX_CONFIG=$LINUX_CONFIG -C $LINUX $CROSS_VARS  \
                     ARCHFILE=$PWD/build/arch && LINUX_ARCH=`cat $PWD/build/arch`],
                [AC_MSG_RESULT([$LINUX_ARCH])],
                [AC_MSG_ERROR([Could not determine the kernel architecture.])])
          rm -f build/arch])

#
# LB_LINUX_TRY_COMPILE
#
# like AC_TRY_COMPILE
#
AC_DEFUN([LB_LINUX_TRY_COMPILE],
[LB_LINUX_COMPILE_IFELSE(
	[AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
	[modules],
	[test -s build/conftest.o],
	[$3], [$4])])

#
# LB_LINUX_CONFIG
#
# check if a given config option is defined
#
AC_DEFUN([LB_LINUX_CONFIG],[
	AC_MSG_CHECKING([if Linux was built with CONFIG_$1])
	LB_LINUX_TRY_COMPILE([
		#include <$AUTOCONF_HDIR/autoconf.h>
	],[
		#ifndef CONFIG_$1
		#error CONFIG_$1 not #defined
		#endif
	],[
		AC_MSG_RESULT([yes])
		$2
	],[
		AC_MSG_RESULT([no])
		$3
	])
])

#
# LB_LINUX_CONFIG_IM
#
# check if a given config option is builtin or as module
#
AC_DEFUN([LB_LINUX_CONFIG_IM],[
	AC_MSG_CHECKING([if Linux was built with CONFIG_$1 in or as module])
	LB_LINUX_TRY_COMPILE([
		#include <$AUTOCONF_HDIR/autoconf.h>
	],[
		#if !(defined(CONFIG_$1) || defined(CONFIG_$1_MODULE))
		#error CONFIG_$1 and CONFIG_$1_MODULE not #defined
		#endif
	],[
		AC_MSG_RESULT([yes])
		$2
	],[
		AC_MSG_RESULT([no])
		$3
	])
])

#
# LB_LINUX_TRY_MAKE
#
# like LB_LINUX_TRY_COMPILE, but with different arguments
#
AC_DEFUN([LB_LINUX_TRY_MAKE],
	[LB_LINUX_COMPILE_IFELSE(
		[AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
		[$3], [$4], [$5], [$6]
	)]
)

#
# LB_CONFIG_COMPAT_RDMA
#
AC_DEFUN([LB_CONFIG_COMPAT_RDMA],
[AC_MSG_CHECKING([whether to use Compat RDMA])
# set default
AC_ARG_WITH([o2ib],
	AC_HELP_STRING([--with-o2ib=path],
		       [build o2iblnd against path]),
	[
		case $with_o2ib in
		yes)    O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
			ENABLEO2IB=2
			;;
		no)     ENABLEO2IB=0
			;;
		*)      O2IBPATHS=$with_o2ib
			ENABLEO2IB=3
			;;
		esac
	],[
		O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
		ENABLEO2IB=1
	])
if test $ENABLEO2IB -eq 0; then
	AC_MSG_RESULT([no])
else
	o2ib_found=false
	for O2IBPATH in $O2IBPATHS; do
		if test \( -f ${O2IBPATH}/include/rdma/rdma_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_verbs.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_fmr_pool.h \); then
			o2ib_found=true
			break
		fi
	done
	compatrdma_found=false
	if $o2ib_found; then
		if test \( -f ${O2IBPATH}/include/linux/compat-2.6.h \); then
			compatrdma_found=true
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_COMPAT_RDMA, 1, [compat rdma found])
		else
			AC_MSG_RESULT([no])
		fi
	fi
fi
])

# LC_MODULE_LOADING
# after 2.6.28 CONFIG_KMOD is removed, and only CONFIG_MODULES remains
# so we test if request_module is implemented or not
AC_DEFUN([LC_MODULE_LOADING],
[AC_MSG_CHECKING([if kernel module loading is possible])
LB_LINUX_TRY_MAKE([
	#include <linux/kmod.h>
],[
	int myretval=ENOSYS ;
	return myretval;
],[
	$makerule LUSTRE_KERNEL_TEST=conftest.i
],[dnl
	grep request_module build/conftest.i |dnl
		grep -v `grep "int myretval=" build/conftest.i |dnl
			cut -d= -f2 | cut -d" "  -f1`dnl
		>/dev/null dnl
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_MODULE_LOADING_SUPPORT, 1,
		  [kernel module loading is possible])
],[
	AC_MSG_RESULT(no)
	AC_MSG_WARN([])
	AC_MSG_WARN([Kernel module loading support is highly recommended.])
	AC_MSG_WARN([])
])
])

#
# LB_PROG_LINUX
#
# linux tests
#
AC_DEFUN([LB_PROG_LINUX],
[LB_LINUX_PATH
LB_LINUX_ARCH
LB_LINUX_SYMVERFILE


LB_LINUX_CONFIG([MODULES],[],[
	AC_MSG_ERROR([module support is required to build Lustre kernel modules.])
])

LB_LINUX_CONFIG([MODVERSIONS])

LB_LINUX_CONFIG([KALLSYMS],[],[
	AC_MSG_ERROR([Lustre requires that CONFIG_KALLSYMS is enabled in your kernel.])
])

# 2.6.28
LC_MODULE_LOADING
])

#
# LB_CHECK_SYMBOL_EXPORT
# check symbol exported or not
# $1 - symbol
# $2 - file(s) for find.
# $3 - do 'yes'
# $4 - do 'no'
#
# 2.6 based kernels - put modversion info into $LINUX/Module.modvers
# or check
AC_DEFUN([LB_CHECK_SYMBOL_EXPORT],
[AC_MSG_CHECKING([if Linux was built with symbol $1 exported])
grep -q -E '[[[:space:]]]$1[[[:space:]]]' $LINUX_OBJ/$SYMVERFILE 2>/dev/null
rc=$?
if test $rc -ne 0; then
	export=0
	for file in $2; do
		grep -q -E "EXPORT_SYMBOL.*\($1\)" "$LINUX/$file" 2>/dev/null
		rc=$?
		if test $rc -eq 0; then
			export=1
			break;
		fi
	done
	if test $export -eq 0; then
		AC_MSG_RESULT([no])
		$4
	else
		AC_MSG_RESULT([yes])
		$3
	fi
else
	AC_MSG_RESULT([yes])
	$3
fi
])

#
# Like AC_CHECK_HEADER but checks for a kernel-space header
#
m4_define([LB_CHECK_LINUX_HEADER],
[AS_VAR_PUSHDEF([ac_Header], [ac_cv_header_$1])dnl
AC_CACHE_CHECK([for $1], ac_Header,
	       [LB_LINUX_COMPILE_IFELSE([LB_LANG_PROGRAM([@%:@include <$1>])],
				  [modules],
				  [test -s build/conftest.o],
				  [AS_VAR_SET(ac_Header, [yes])],
				  [AS_VAR_SET(ac_Header, [no])])])
AS_IF([test AS_VAR_GET(ac_Header) = yes], [$2], [$3])[]dnl
AS_VAR_POPDEF([ac_Header])dnl
])

#
# LB_USES_DPKG
#
# Determine if the target is a dpkg system or rpm
#
AC_DEFUN([LB_USES_DPKG],
[
AC_MSG_CHECKING([if this distro uses dpkg])
case `lsb_release -i -s 2>/dev/null` in
        Ubuntu | Debian)
                AC_MSG_RESULT([yes])
                uses_dpkg=yes
                ;;
        *)
                AC_MSG_RESULT([no])
                uses_dpkg=no
                ;;
esac
])
