# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# config/lustre-build.m4
#
# Generic Lustre configuration options
#

#
# LB_CANONICAL_SYSTEM
#
# fixup $target_os for use in other places
#
AC_DEFUN([LB_CANONICAL_SYSTEM], [
case $target_os in
	linux*)
		lb_target_os="linux"
		;;
esac
AC_SUBST(lb_target_os)
]) # LB_CANONICAL_SYSTEM

#
# LB_DOWNSTREAM_RELEASE (DEPRECATED)
#
AC_DEFUN([LB_DOWNSTREAM_RELEASE],
[AC_ARG_WITH([downstream-release],,
	AC_MSG_ERROR([--downstream-release was deprecated.  Please read Documentation/versioning.txt.])
)]) # LB_DOWNSTREAM_RELEASE

#
# LB_CHECK_FILE
#
# Check for file existence even when cross compiling
# $1 - file to check
# $2 - do 'yes'
# $3 - do 'no'
#
AC_DEFUN([LB_CHECK_FILE], [
AS_VAR_PUSHDEF([lb_file], [lb_cv_file_$1])dnl
AC_CACHE_CHECK([for $1], lb_file, [
AS_IF([test -r "$1"],
	[AS_VAR_SET(lb_file, [yes])],
	[AS_VAR_SET(lb_file, [no])])
])
AS_VAR_IF([lb_file], [yes], [$2], [$3])[]dnl
AS_VAR_POPDEF([lb_file])dnl
]) # LB_CHECK_FILE

#
# LB_ARG_LIBS_INCLUDES
#
# support for --with-foo, --with-foo-includes, and --with-foo-libs in
# a single magical macro
#
AC_DEFUN([LB_ARG_LIBS_INCLUDES], [
lb_pathvar="m4_bpatsubst([$2], -, _)"
AC_MSG_CHECKING([for $1])
AC_ARG_WITH([$2],
	AS_HELP_STRING([--with-$2=path],
		[path to $1]),
	[], [withval=$4])
AS_IF([test "x$withval" = xyes],
	[eval "$lb_pathvar='$3'"],
	[eval "$lb_pathvar='$withval'"])
AC_MSG_RESULT([${!lb_pathvar:-no}])

AS_IF([test "x${!lb_pathvar}" != x -a "x${!lb_pathvar}" != xno], [
	AC_MSG_CHECKING([for $1 includes])
	AC_ARG_WITH([$2-includes],
		AS_HELP_STRING([--with-$2-includes=path],
			[path to $1 includes]),
		[], [withval="yes"])

	lb_includevar="${lb_pathvar}_includes"
	AS_IF([test "x$withval" = xyes],
		[eval "${lb_includevar}='${!lb_pathvar}/include'"],
		[eval "${lb_includevar}='$withval'"])
	AC_MSG_RESULT([${!lb_includevar}])

	AC_MSG_CHECKING([for $1 libs])
	AC_ARG_WITH([$2-libs],
		AS_HELP_STRING([--with-$2-libs=path],
			[path to $1 libs]),
		[], [withval="yes"])

	lb_libvar="${lb_pathvar}_libs"
	AS_IF([test "x$withval" = xyes],
		[eval "${lb_libvar}='${!lb_pathvar}/lib'"],
		[eval "${lb_libvar}='$withval'"])
	AC_MSG_RESULT([${!lb_libvar}])
])
]) # LB_ARG_LIBS_INCLUDES

#
# LB_PATH_LUSTREIOKIT
#
# We no longer handle external lustre-iokit
#
AC_DEFUN([LB_PATH_LUSTREIOKIT], [
AC_MSG_CHECKING([whether to build iokit])
AC_ARG_ENABLE([iokit],
	AS_HELP_STRING([--disable-iokit],
		[disable iokit (default is enable)]),
	[], [enable_iokit="yes"])
AC_MSG_RESULT([$enable_iokit])
AS_IF([test "x$enable_iokit" = xyes],
	[LUSTREIOKIT_SUBDIR="lustre-iokit"],
	[LUSTREIOKIT_SUBDIR=""])
AC_SUBST(LUSTREIOKIT_SUBDIR)
AM_CONDITIONAL([BUILD_LUSTREIOKIT], [test "x$enable_iokit" = xyes])
]) # LB_PATH_LUSTREIOKIT

#
# LB_LIBMOUNT
#
# Check whether build with libmount for mount.lustre.
# libmount is part of the util-linux since v2.18.
# We need it to manipulate utab file.
#
AC_DEFUN([LB_LIBMOUNT], [
AC_CHECK_HEADER([libmount/libmount.h], [
	AC_CHECK_LIB([mount], [mnt_update_set_fs], [
		LDLIBMOUNT="-lmount"
		AC_SUBST(LDLIBMOUNT)
		with_libmount="yes"
	],[with_libmount="no"])
], [with_libmount="no"])
AC_MSG_CHECKING([whether to build with libmount])
AS_IF([test "x$with_libmount" = xyes], [
	AC_MSG_RESULT([yes])
], [
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([libmount development package is required])
])
]) # LB_LIBMOUNT

#
# LB_CONFIG_MODULES
#
# Build kernel modules?
#
AC_DEFUN([LB_CONFIG_MODULES], [
AC_MSG_CHECKING([whether to build Linux kernel modules])
AC_ARG_ENABLE([modules],
	AS_HELP_STRING([--disable-modules],
		[disable building of Lustre kernel modules]),
	[ AC_DEFINE(HAVE_NATIVE_LINUX_CLIENT, 1, [support native Linux client])], [
		LC_TARGET_SUPPORTED([enable_modules="yes"],
				    [enable_modules="no"])
	])
	AC_MSG_RESULT([$enable_modules ($target_os)])
	AS_IF([test "x$enable_modules" = xyes], [
		AS_IF([test "x$FLEX" = "x"], [AC_MSG_ERROR(
			[flex package is required to build kernel modules])])
		AS_IF([test "x$BISON" = "x"], [AC_MSG_ERROR(
			[bison package is required to build kernel modules])])
	AS_CASE([$target_os], [linux*], [
			# Ensure SUBARCH is defined
			SUBARCH=$(echo $target_cpu | sed -e 's/powerpc.*/powerpc/' -e 's/ppc.*/powerpc/' -e 's/x86_64/x86/' -e 's/i.86/x86/' -e 's/k1om/x86/' -e 's/aarch64.*/arm64/' -e 's/armv7.*/arm/')
			LB_PROG_LINUX
			AS_IF([test "x$enable_server" != xno],
				[LB_EXT4_SOURCE_PATH])
		], [*], [
			# This is strange - Lustre supports a target we don't
			AC_MSG_ERROR([Modules are not supported on $target_os])
	])
])

AC_DEFUN([LB_KABI_CHECKS], [
	AS_CASE([$target_os],
		[linux*], [
			# Ensure SUBARCH is defined
			SUBARCH=$(echo $target_cpu | sed -e 's/powerpc.*/powerpc/' -e 's/ppc.*/powerpc/' -e 's/x86_64/x86/' -e 's/i.86/x86/' -e 's/k1om/x86/' -e 's/aarch64.*/arm64/' -e 's/armv7.*/arm/')

			# Run serial tests
			LIBCFS_PROG_LINUX
			LN_PROG_LINUX
			LC_PROG_LINUX
			AS_IF([test "x$enable_zfs" = xyes],
				[LZ_ZFS_KABI_SERIAL])

			# Run 'early' checks. The results of these are used in
			# other configure tests:
			LIBCFS_SRC_LOCKDEP_IS_HELD
			LIBCFS_SRC_HAVE_WAIT_BIT_HEADER
			LIBCFS_SRC_LINUX_BLK_INTEGRITY_HEADER
			LIBCFS_SRC_HAVE_MMAP_LOCK
			LC_SRC_STRUCT_LSM_CONTEXT_EARLY

			LB2_LINUX_TEST_COMPILE_ALL([early],
				[for available lustre kapi interfaces])

			LIBCFS_LOCKDEP_IS_HELD
			LIBCFS_HAVE_WAIT_BIT_HEADER
			LIBCFS_LINUX_BLK_INTEGRITY_HEADER
			LIBCFS_HAVE_MMAP_LOCK
			LC_STRUCT_LSM_CONTEXT_EARLY

			# Run any parallel compile tests
			LB_PROG_LINUX_SRC
			LIBCFS_PROG_LINUX_SRC
			LN_PROG_LINUX_SRC
			AS_IF([test "x$enable_server" != xno],
				[LB_EXT4_LDISKFS_TESTS])
			LC_PROG_LINUX_SRC
			AS_IF([test "x$enable_zfs" = xyes],
				[LZ_KABI_ZFS_TESTS])

			LB2_LINUX_TEST_COMPILE_ALL([lustre],
				[for available lustre kapi interfaces])

			# Collect parallel compile tests results
			LB_PROG_LINUX_RESULTS
			LIBCFS_PROG_LINUX_RESULTS
			LN_PROG_LINUX_RESULTS
			AS_IF([test "x$enable_server" != xno],
				[LB_EXT4_LDISKFS_CHECKS])
			LC_PROG_LINUX_RESULTS
			AS_IF([test "x$enable_zfs" = xyes],
				[LZ_KABI_ZFS_CHECKS])

		], [*], [
			# This is strange - Lustre supports a target we don't
			AC_MSG_ERROR([Modules are not supported on $target_os])
	])
	# Use OpenSFS UAPI header path instead of linux kernel
	CPPFLAGS="-I$PWD/lnet/include/uapi -I$PWD/lustre/include/uapi $CPPFLAGS"
])
]) # LB_CONFIG_MODULES

#
# LB_CONFIG_UTILS
#
# Build utils?
#
AC_DEFUN([LB_CONFIG_UTILS], [
AC_MSG_CHECKING([whether to build Lustre utilities])
AC_ARG_ENABLE([utils],
	AS_HELP_STRING([--disable-utils],
		[disable building of Lustre utility programs]),
	[], [enable_utils="yes"])
AC_MSG_RESULT([$enable_utils])
]) # LB_CONFIG_UTILS

#
# LB_CONFIG_LUTF
#
# Build LNet Unit Test Framework?
#
AC_DEFUN([LB_CONFIG_LUTF], [
# Python development libs are optional, disable LUTF is not available
# if you have python 2 and python3 and python defaults to 2 you can enable
# python3 here by setting PYTHON_VERSION=3 before calling configure, example:
#  $ PYTHON_VERSION=3 ./configure [options]
AX_PYTHON_DEVEL([>= '3.6'], [true])
AS_IF([test "x$enable_dist" != xno], [
	enable_lutf="yes"
], [
  AS_IF([test "x$ax_python_devel_found" = xno], [
	enable_lutf="no"
  ], [
	AX_PKG_SWIG(2.0, [ enable_lutf="yes" ],
			 [ enable_lutf="no" ])
  ])
])
AC_ARG_ENABLE([lutf],
	AS_HELP_STRING([--disable-lutf],
		[disable building of LUTF]),
	[], [enable_lutf="yes"])
AC_MSG_CHECKING([whether to build LUTF (LNet Unit Test Framework)])
AC_MSG_RESULT([$enable_lutf])
]) # LB_CONFIG_LUTF

#
# LB_CONFIG_TESTS
#
# Build Lustre/LNet regression tests?
#
AC_DEFUN([LB_CONFIG_TESTS], [
AC_MSG_CHECKING([whether to build Lustre tests])
AC_ARG_ENABLE([tests],
	AS_HELP_STRING([--disable-tests],
		[disable building of Lustre tests]),
	[], [enable_tests="yes"])
AC_MSG_RESULT([$enable_tests])
]) # LB_CONFIG_TESTS

#
# LB_CONFIG_DIST
#
# Just enough configure so that "make dist" is useful
#
# this simply re-adjusts some defaults, which of course can be overridden
# on the configure line after the --for-dist option
#
AC_DEFUN([LB_CONFIG_DIST], [
AC_MSG_CHECKING([whether to configure just enough for make dist])
AC_ARG_ENABLE([dist],
	AS_HELP_STRING([--enable-dist],
			[only configure enough for make dist]),
	[], [enable_dist="no"])
AC_MSG_RESULT([$enable_dist])
AS_IF([test "x$enable_dist" != xno], [
	enable_doc="no"
	enable_utils="no"
	enable_tests="no"
	enable_modules="no"
])
]) # LB_CONFIG_DIST

#
# LB_CONFIG_DOCS
#
# Build docs?
#
AC_DEFUN([LB_CONFIG_DOCS], [
AC_MSG_CHECKING([whether to build Lustre docs])
AC_ARG_ENABLE([doc],
	AS_HELP_STRING([--disable-doc],
			[skip creation of pdf documentation]),
	[], [enable_doc="no"])
AC_MSG_RESULT([$enable_doc])
AS_IF([test "x$enable_doc" = xyes],
	[ENABLE_DOC=1], [ENABLE_DOC=0])
AC_SUBST(ENABLE_DOC)
]) # LB_CONFIG_DOCS

#
# LB_CONFIG_MANPAGES
#
# Build manpages?
#
AC_DEFUN([LB_CONFIG_MANPAGES], [
AC_MSG_CHECKING([whether to build Lustre manpages])
AC_ARG_ENABLE([manpages],
	AS_HELP_STRING([--disable-manpages],
			[skip creation and inclusion of man pages (default is enable)]),
	[], [enable_manpages="yes"])
AC_MSG_RESULT([$enable_manpages])
]) # LB_CONFIG_MANPAGES

#
# LB_CONFIG_HEADERS
#
# add -include config.h
#
AC_DEFUN([LB_CONFIG_HEADERS], [
AC_CONFIG_HEADERS([config.h])
CPPFLAGS="-include $PWD/undef.h -include $PWD/config.h $CPPFLAGS"
EXTRA_KCFLAGS="-include $PWD/undef.h -include $PWD/config.h $EXTRA_KCFLAGS"
AC_SUBST(EXTRA_KCFLAGS)
]) # LB_CONFIG_HEADERS

#
# LB_INCLUDE_RULES
#
# defines for including the toplevel Rules
#
AC_DEFUN([LB_INCLUDE_RULES], [
INCLUDE_RULES="include $PWD/Rules"
AC_SUBST(INCLUDE_RULES)
]) # LB_INCLUDE_RULES

#
# LB_PATH_DEFAULTS
#
# 'fixup' default paths
#
AC_DEFUN([LB_PATH_DEFAULTS], [
# directories for binaries
AC_PREFIX_DEFAULT([/usr])

sysconfdir='/etc'
AC_SUBST(sysconfdir)

# Directories for documentation and demos.
docdir='${datadir}/doc/$(PACKAGE)'
AC_SUBST(docdir)

LIBCFS_PATH_DEFAULTS
LN_PATH_DEFAULTS
LC_PATH_DEFAULTS
]) # LB_PATH_DEFAULTS

#
# LB_CONDITIONALS
#
# AM_CONDITIONAL instances for everything
# (so that portals/lustre can disable some if needed)
#
AC_DEFUN([LB_CONDITIONALS], [
AM_CONDITIONAL([PLUGINS], [test x$enable_shared = xyes])
AM_CONDITIONAL([MODULES], [test x$enable_modules = xyes])
AM_CONDITIONAL([UTILS], [test x$enable_utils = xyes])
AM_CONDITIONAL([TESTS], [test x$enable_tests = xyes])
AM_CONDITIONAL([DOC], [test x$ENABLE_DOC = x1])
AM_CONDITIONAL([MANPAGES], [test x$enable_manpages = xyes])
AM_CONDITIONAL([LINUX], [test x$lb_target_os = xlinux])
AM_CONDITIONAL([USE_QUILT], [test x$use_quilt = xyes])
AM_CONDITIONAL([RHEL], [test -f /etc/redhat-release -o -f /etc/openEuler-release])
AM_CONDITIONAL([SUSE], [test -f /etc/SUSE-brand -o -f /etc/SuSE-release])
AM_CONDITIONAL([UBUNTU], [test x$UBUNTU_KERNEL = xyes])
AM_CONDITIONAL([BUILD_LUTF], [test x$enable_lutf = xyes])
AM_CONDITIONAL([DEQUOTE_CC_VERSION_TEXT], [test x$lb_cv_dequote_CC_VERSION_TEXT = xyes])

LN_CONDITIONALS
LC_CONDITIONALS
]) # LB_CONDITIONALS

#
# LB_CONFIG_FILES
#
# build-specific config files
#
AC_DEFUN([LB_CONFIG_FILES], [
	AC_CONFIG_FILES([
		Makefile
		autoMakefile]
		config/Makefile
		[Rules:config/Rules.in]
		AC_PACKAGE_TARNAME[.spec]
		AC_PACKAGE_TARNAME[-dkms.spec]
		ldiskfs/Makefile
		ldiskfs/autoMakefile
		lnet/utils/lnet.pc
		lustre/utils/lustre.pc
		lustre-iokit/Makefile
		lustre-iokit/obdfilter-survey/Makefile
		lustre-iokit/ost-survey/Makefile
		lustre-iokit/sgpdd-survey/Makefile
		lustre-iokit/mds-survey/Makefile
		lustre-iokit/ior-survey/Makefile
		lustre-iokit/stats-collect/Makefile
		lustre-iokit/lst-survey/Makefile
		Documentation/Makefile
		Documentation/man1/Makefile
		Documentation/man3/Makefile
		Documentation/man5/Makefile
		Documentation/man7/Makefile
		Documentation/man8/Makefile
	)
])

#
# LB_CONFIG_SERVERS
#
AC_DEFUN([LB_CONFIG_SERVERS], [
AC_ARG_ENABLE([server],
	AS_HELP_STRING([--disable-server],
			[disable Lustre server support]), [
		AS_IF([test x$enable_server != xyes -a x$enable_server != xno],
			[AC_MSG_ERROR([server valid options are "yes" or "no"])])
		AS_IF([test x$enable_server = xyes -a x$enable_dist = xyes],
			[AC_MSG_ERROR([--enable-server cannot be used with --enable-dist])])
	], [
		AS_IF([test x$enable_dist = xyes],
			[enable_server=no], [enable_server=maybe])
	])

# There are at least two good reasons why we should really run
# LB_CONFIG_MODULES elsewhere before the call to LB_CONFIG_SERVERS:
# LB_CONFIG_MODULES needs to be run for client support even when
# servers are disabled, and because module support is actually a
# prerequisite of server support.  However, some things under
# LB_CONFIG_MODULES need us to already have checked for --disable-server,
# before running, so until LB_CONFIG_MODULES can be reorganized, we
# call it here.
LB_CONFIG_MODULES
AS_IF([test x$enable_modules = xno], [enable_server=no])
LB_CONFIG_LDISKFS
LB_CONFIG_ZFS
AS_IF([test "x$enable_modules" = xyes], [
	LB_KABI_LDISKFS
	LZ_KABI_ZFS
	LB_KABI_CHECKS
])

# If no backends were configured, and the user did not explicitly
# require servers to be enabled, we just disable servers.
AS_IF([test x$enable_ldiskfs = xno -a x$enable_zfs = xno], [
	AS_CASE([$enable_server],
		[maybe], [enable_server=no],
		[yes], [AC_MSG_WARN([no backends were configured])])
	], [
		AS_IF([test x$enable_server = xmaybe], [enable_server=yes])
	])

AC_MSG_CHECKING([whether to build Lustre server support])
AC_MSG_RESULT([$enable_server])
AS_IF([test x$enable_server = xyes], [
	AC_DEFINE(HAVE_SERVER_SUPPORT, 1, [support server])
	AC_SUBST(ENABLE_SERVER, yes)
], [
	AC_SUBST(ENABLE_SERVER, no)
])
]) # LB_CONFIG_SERVERS

#
# LB_CONFIG_RPMBUILD_OPTIONS
#
# The purpose of this function is to assemble command line options
# for the rpmbuild command based on the options passed to the configure
# script, and also upon the decisions that configure makes based on
# the tests that it runs.
# These strings can be passed to rpmbuild on the command line
# in the Make targets named "rpms" and "srpm".
#
AC_DEFUN([LB_CONFIG_RPMBUILD_OPTIONS], [
RPMBINARGS=
CONFIGURE_ARGS=
eval set -- $ac_configure_args
for arg; do
	case $arg in
		--*dir=* ) ;;
		-C | --cache-file=* ) ;;
		--prefix=* | --*-prefix=* ) ;;
		--enable-dist ) ;;
		--with-kmp-moddir=* ) ;;
		--with-linux=* | --with-linux-obj=* ) ;;
		--enable-shared | --disable-shared ) ;;
		--enable-static | --disable-static ) ;;
		--enable-ldiskfs | --disable-ldiskfs ) ;;
		--enable-modules | --disable-modules ) ;;
		--enable-server | --disable-server ) ;;
		--enable-tests | --disable-tests ) ;;
		--enable-utils | --disable-utils ) ;;
		--enable-iokit | --disable-iokit ) ;;
		--enable-manpages | --disable-manpages ) ;;
		* ) CONFIGURE_ARGS="$CONFIGURE_ARGS '$arg'" ;;
	esac
done
if test -n "$CONFIGURE_ARGS" ; then
	RPMBINARGS="$RPMBINARGS --define \"configure_args $CONFIGURE_ARGS\""
fi
if test -n "$LINUX" ; then
	RPMBINARGS="$RPMBINARGS --define \"kdir $LINUX\""
	if test -n "$LINUX_OBJ" -a "$LINUX_OBJ" != x"$LINUX" ; then
		RPMBINARGS="$RPMBINARGS --define \"kobjdir $LINUX_OBJ\""
	fi
fi
if test x$enable_modules != xyes ; then
	RPMBINARGS="$RPMBINARGS --without lustre_modules"
fi
if test x$enable_tests != xyes ; then
	RPMBINARGS="$RPMBINARGS --without lustre_tests"
fi
if test x$enable_lutf != xyes ; then
	RPMBINARGS="$RPMBINARGS --without lustre_tests_lutf"
fi
if test x$enable_utils != xyes ; then
	RPMBINARGS="$RPMBINARGS --without lustre_utils"
fi
if test x$enable_server != xyes ; then
	RPMBINARGS="$RPMBINARGS --without servers"
fi
if test x$enable_ldiskfs != xyes ; then
	RPMBINARGS="$RPMBINARGS --without ldiskfs"
fi
if test x$enable_zfs = xyes ; then
	RPMBINARGS="$RPMBINARGS --with zfs"
fi
if test x$enable_gss_keyring = xyes ; then
	RPMBINARGS="$RPMBINARGS --with gss_keyring --with gss"
fi
if test x$enable_gss = xyes ; then
	RPMBINARGS="$RPMBINARGS --with gss"
	AC_SUBST(ENABLE_GSS, yes)
elif test x$enable_gss = xno ; then
	RPMBINARGS="$RPMBINARGS --without gss"
	AC_SUBST(ENABLE_GSS, no)
fi
if test x$enable_crypto = xyes ; then
	RPMBINARGS="$RPMBINARGS --with crypto"
	AC_SUBST(ENABLE_CRYPTO, yes)
elif test x$enable_crypto = xno ; then
	RPMBINARGS="$RPMBINARGS --without crypto"
	AC_SUBST(ENABLE_CRYPTO, no)
fi
if test x$enable_multiple_lnds = xyes ; then
	RPMBINARGS="$RPMBINARGS --with multiple_lnds"
else
	RPMBINARGS="$RPMBINARGS --without multiple_lnds"
fi
if test x$EXTERNAL_KO2IBLND = xyes ; then
	RPMBINARGS="$RPMBINARGS --with mofed"
else
	RPMBINARGS="$RPMBINARGS --without mofed"
fi
if test x$BUILT_IN_KO2IBLND = xyes ; then
	RPMBINARGS="$RPMBINARGS --with o2ib"
else
	RPMBINARGS="$RPMBINARGS --without o2ib"
fi
if test x$KFILND = xkfilnd ; then
	RPMBINARGS="$RPMBINARGS --with kfi"
else
	RPMBINARGS="$RPMBINARGS --without kfi"
fi
if test x$ENABLE_GNI = xyes ; then
	RPMBINARGS="$RPMBINARGS --with gni"
else
	RPMBINARGS="$RPMBINARGS --without gni"
fi
if test x$enable_iokit != xyes ; then
	RPMBINARGS="$RPMBINARGS --without lustre_iokit"
fi
if test x$enable_manpages != xyes ; then
	RPMBINARGS="$RPMBINARGS --without manpages"
fi
if test x$enable_shared != xyes ; then
	RPMBINARGS="$RPMBINARGS --without shared"
fi
if test x$enable_static != xyes ; then
	RPMBINARGS="$RPMBINARGS --without static"
fi
if test x$enable_mpitests != xyes ; then
	RPMBINARGS="$RPMBINARGS --without mpi"
fi

RPMBUILD_BINARY_ARGS=$RPMBINARGS

AC_SUBST(RPMBUILD_BINARY_ARGS)
]) # LB_CONFIG_RPMBUILD_OPTIONS

#
# LB_CONFIG_CACHE_OPTIONS
#
# Propagate config cache option
#
AC_DEFUN([LB_CONFIG_CACHE_OPTIONS], [
CONFIG_CACHE_FILE=
if test -f "$cache_file"; then
	CONFIG_CACHE_FILE=$(readlink --canonicalize "$cache_file")
fi
AC_SUBST(CONFIG_CACHE_FILE)
]) # LB_CONFIG_CACHE_OPTIONS

#
# LB_CONFIGURE
#
# main configure steps
#
AC_DEFUN([LB_CONFIGURE], [
AC_MSG_NOTICE([Lustre base checks
==============================================================================])
LB_CANONICAL_SYSTEM

LB_CONFIG_DIST

LB_DOWNSTREAM_RELEASE
LB_USES_DPKG

LB_INCLUDE_RULES

LB_PATH_DEFAULTS

LC_OSD_ADDON

LB_CONFIG_DOCS
LB_CONFIG_MANPAGES
LB_CONFIG_UTILS
LB_CONFIG_TESTS
LB_CONFIG_LUTF
LC_CONFIG_CLIENT
LB_CONFIG_MPITESTS
LB_CONFIG_SERVERS
LC_CONFIG_CRYPTO
LC_GLIBC_SUPPORT_COPY_FILE_RANGE
LC_OPENSSL_SSK

# Tests depends from utils (multiop from liblustreapi)
AS_IF([test "x$enable_utils" = xno], [enable_tests="no"])

AS_IF([test "x$enable_utils" = xyes], [
	LC_OPENSSL_GETSEPOL
	LC_CONFIG_GETSEPOL
	LC_FID2PATH_ANON_UNION
])
AS_IF([test "x$enable_tests" = xyes], [
	LC_HAVE_LIBAIO
	LC_GLIBC_SUPPORT_FHANDLES
])

LIBCFS_CONFIG_CDEBUG
LC_QUOTA

AS_IF([test "x$enable_dist" != xno], [
	AS_IF([test -z $LINUXRELEASE], [LINUXRELEASE="%{nil}"])
	AC_SUBST(LINUXRELEASE)],[LB_LIBMOUNT])
LB_PATH_LUSTREIOKIT

LB_DEFINE_E2FSPROGS_NAMES

LIBCFS_CONFIGURE
LN_CONFIGURE
LC_CONFIGURE

LB_CONDITIONALS
LB_CONFIG_HEADERS

LPLUG_CONFIGURE
LIBCFS_CONFIG_FILES
LB_CONFIG_FILES
LN_CONFIG_FILES
LC_CONFIG_FILES
LPLUG_CONFIG_FILES

AC_SUBST(ac_configure_args)

MOSTLYCLEANFILES='.*.cmd .*.flags *.o *.ko *.mod.c .depend .*.1.* Modules.symvers Module.symvers'
AC_SUBST(MOSTLYCLEANFILES)

LB_CONFIG_RPMBUILD_OPTIONS
LB_CONFIG_CACHE_OPTIONS

AS_IF([test -d $TEST_DIR -a "x${PARALLEL_BUILD_OPT}" != "xdebug"], [
	AC_MSG_NOTICE([remove temporary parallel configure dir $TEST_DIR])
	rm -rf $TEST_DIR
])

AC_OUTPUT
]) # LB_CONFIGURE
