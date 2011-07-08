#
# LB_PATH_LDISKFS
#
# --without-ldiskfs   - Disable ldiskfs support.
# --with-ldiskfs=no
#
# --with-ldiskfs      - Enable ldiskfs support and attempt to autodetect the
# --with-ldiskfs=yes    headers in one of the following places in this order:
#                       * ./ldiskfs
#                       * /usr/src/ldiskfs-*/$LINUXRELEASE
#                       * ../ldiskfs
#
# --with-ldiskfs=path - Enable ldiskfs support and use the headers in the
#                       provided path.  No autodetection is performed.
#
# --with-ldiskfs-obj  - When ldiskfs support is enabled the object directory
#                       will be based on the --with-ldiskfs directory.  If
#                       this is detected incorrectly it can be explicitly
#                       specified using this option.
#
# NOTE: As with all external packages ldiskfs is expected to already be
# configured and built.  However, if the ldiskfs tree is located in-tree
# (./ldiskfs) then it will be configured and built recursively as part of
# the lustre build system.
#
# NOTE: The lustre and in-tree ldiskfs build systems both make use these
# macros.  This is undesirable and confusing at best, it is potentially
# danagerous at worst.  The ldiskfs build system should be entirely stand
# alone without dependency on the lustre build system.
#
AC_DEFUN([LB_PATH_LDISKFS],
[
AC_ARG_WITH([ldiskfs],
	AC_HELP_STRING([--with-ldiskfs=path], [set path to ldiskfs source]),
	[],[
		if test x$enable_server = xyes && test x$enable_dist = xno; then
			with_ldiskfs='yes'
		else
			with_ldiskfs='no'
		fi
	])

case x$with_ldiskfs in
	xno)
		LDISKFS_DIR=
		;;
	xyes)
		LDISKFS_DIR=

		# Check ./ldiskfs
		ldiskfs_src=$PWD/ldiskfs
		if test -e "$ldiskfs_src"; then
			LDISKFS_DIR=$(readlink -f $ldiskfs_src)
		else
			# Check /usr/src/ldiskfs-*/$LINUXRELEASE
			ldiskfs_src=$(ls -1d \
				/usr/src/ldiskfs-*/$LINUXRELEASE \
				2>/dev/null | tail -1)
			if test -e "$ldiskfs_src"; then
				LDISKFS_DIR=$(readlink -f $ldiskfs_src)
			else
				# Check ../ldiskfs
				ldiskfs_src=$PWD/../ldiskfs
				if test -e "$ldiskfs_src"; then
					LDISKFS_DIR=$(readlink -f $ldiskfs_src)
				else
					# Disable ldiskfs failed to detect
					with_ldiskfs='no'
				fi
			fi
		fi

		;;
	*)
		LDISKFS_DIR=$(readlink -f $with_ldiskfs)
		with_ldiskfs='yes'
		;;
esac

AC_MSG_CHECKING([whether to enable ldiskfs])
AC_MSG_RESULT([$with_ldiskfs])

AC_ARG_WITH([ldiskfs-obj],
	AC_HELP_STRING([--with-ldiskfs-obj=path],[set path to ldiskfs objects]),
	[
		if test x$with_ldiskfs = xyes; then
			LDISKFS_OBJ="$withval"
		fi
	],[
		if test x$with_ldiskfs = xyes; then
			LDISKFS_OBJ=$LDISKFS_DIR
		fi
	])

if test x$with_ldiskfs = xyes; then
	AC_MSG_CHECKING([ldiskfs source directory])
	AC_MSG_RESULT([$LDISKFS_DIR])
	AC_SUBST(LDISKFS_DIR)

	AC_MSG_CHECKING([ldiskfs object directory])
	AC_MSG_RESULT([$LDISKFS_OBJ])
	AC_SUBST(LDISKFS_OBJ)

	LB_LDISKFS_SYMVERS
	LB_LDISKFS_RELEASE
	LB_LDISKFS_EXT_RELEASE
	LB_LDISKFS_EXT_DIR
	LB_LDISKFS_BUILD
	LB_LDISKFS_DEFINE_OPTIONS
fi

#
# LDISKFS_DEVEL is required because when using the ldiskfs-devel package the
# ext3/4 source will be fully patched to ldiskfs.  When building with the
# in-tree ldiskfs this patching this will occur after the configure step.
# We needed a way to determine if we should check the patched or unpatched
# source files.
#
# Longer term this could be removed by moving the ldiskfs patching in to
# the configure phase.  Or better yet ldiskfs could be updated to generate
# a ldiskfs_config.h which clearly defines how it was built.  This can
# then be directly included by Lustre to avoid all the autoconf guess work.
# For an example of this behavior consult the lustre/zfs build integration.
#
AM_CONDITIONAL(LDISKFS_DEVEL, \
	test x$LDISKFS_DIR = x$(readlink -f $PWD/ldiskfs) || \
	test x$LDISKFS_DIR = x$(readlink -f $PWD/../ldiskfs))

AM_CONDITIONAL(LDISKFS_BUILD, test x$enable_ldiskfs_build = xyes)
AM_CONDITIONAL(LDISKFS_ENABLED, test x$with_ldiskfs = xyes)

if test -e "$PWD/ldiskfs"; then
	LDISKFS_DIST_SUBDIR="ldiskfs"
	AC_SUBST(LDISKFS_DIST_SUBDIR)
	AC_CONFIG_SUBDIRS("ldiskfs")
fi
])

#
# LB_LDISKFS_EXT_RELEASE
#
# Determine if ext3 or ext4 sources should be used for ldiskfs.
#
AC_DEFUN([LB_LDISKFS_EXT_RELEASE],
[
AC_ARG_ENABLE([ext4],
	 AC_HELP_STRING([--enable-ext4], [enable ldiskfs build using ext4]),
	[],
	[
		if test x$RHEL_KERNEL = xyes; then
			enable_ext4='yes'
		else
			# 2.6.22-2.6.26 ext4 available but unstable
			case x$LINUXRELEASE in
			x2.6.2[[0-6]]*)
				enable_ext4='no' ;;
			*)
				enable_ext4='yes' ;;
			esac
		fi
	])

if test x$enable_ext4 = xyes; then
	LDISKFS_BACKFS='ext4'
else
	LDISKFS_BACKFS='ext3'
fi

AC_MSG_CHECKING([whether to use ext3 or ext4 source])
AC_MSG_RESULT([$LDISKFS_BACKFS])
AC_SUBST(LDISKFS_BACKFS)
])

#
# LB_LDISKFS_EXT_DIR
#
# Determine the location of the ext3/ext4 source code.  It it required
# for several configure tests and to build ldiskfs.
#
AC_DEFUN([LB_LDISKFS_EXT_DIR],
[
# Kernel ext source located with devel headers
linux_src=$LINUX
if test -e "$linux_src/fs/$LDISKFS_BACKFS/super.c"; then
	EXT_DIR=$linux_src/fs/$LDISKFS_BACKFS
else
	# Kernel ext source provided by kernel-debuginfo-common package
	linux_src=$(ls -1d /usr/src/debug/*/linux-$LINUXRELEASE \
		2>/dev/null | tail -1)
	if test -e "$linux_src/fs/$LDISKFS_BACKFS/super.c"; then
		EXT_DIR=$linux_src/fs/$LDISKFS_BACKFS
	else
		EXT_DIR=
	fi
fi

AC_MSG_CHECKING([$LDISKFS_BACKFS source directory])
AC_MSG_RESULT([$EXT_DIR])
AC_SUBST(EXT_DIR)
])

#
# LB_LDISKFS_EXT_SOURCE
#
# Spot check the existance of several source files common to ext3/ext4.
# Detecting this at configure time allows us to avoid a potential build
# failure and provide a useful error message to explain what is wrong.
#
AC_DEFUN([LB_LDISKFS_EXT_SOURCE],
[
if test x$EXT_DIR = x; then
	AC_MSG_ERROR([Complete $LDISKFS_BACKFS source must exist.

If you are building using kernel-devel packages then ensure that the
matching kernel-debuginfo-common and kernel-debuginfo-common-<arch>
packages are installed.])
fi

LB_CHECK_FILE([$EXT_DIR/dir.c], [], [ AC_MSG_ERROR(
	[Complete $LDISKFS_BACKFS source must exist for ldiskfs build])])
LB_CHECK_FILE([$EXT_DIR/file.c], [], [ AC_MSG_ERROR(
	[Complete $LDISKFS_BACKFS source must exist for ldiskfs build])])
LB_CHECK_FILE([$EXT_DIR/inode.c], [], [ AC_MSG_ERROR(
	[Complete $LDISKFS_BACKFS source must exist for ldiskfs build])])
LB_CHECK_FILE([$EXT_DIR/super.c], [], [ AC_MSG_ERROR(
	[Complete $LDISKFS_BACKFS source must exist for ldiskfs build])])
])

#
# LB_LDISKFS_DEFINE_OPTIONS
#
# Enable config options related to ldiskfs.  These are used by ldiskfs,
# lvfs, and the osd-ldiskfs code (which includes ldiskfs headers.)
#
AC_DEFUN([LB_LDISKFS_DEFINE_OPTIONS],
[
AC_DEFINE(HAVE_LDISKFS_OSD, 1, Enable ldiskfs osd)

with_ldiskfs_pdo=no
if test $LDISKFS_BACKFS = 'ext4'; then
	AC_DEFINE(HAVE_EXT4_LDISKFS, 1, [build ext4 based ldiskfs])
	case $LINUXRELEASE in
	2.6.32*)
		if test x$RHEL_KERNEL = xyes; then
			with_ldiskfs_pdo=yes
			AC_DEFINE(HAVE_LDISKFS_PDO, 1, [have ldiskfs PDO patch])
		fi
	esac
fi

LB_LDISKFS_JBD2_JOURNAL_CALLBACK_SET

AC_DEFINE(CONFIG_LDISKFS_FS_XATTR, 1,
	[enable extended attributes for ldiskfs])
AC_DEFINE(CONFIG_LDISKFS_FS_POSIX_ACL, 1,
	[enable posix acls for ldiskfs])
AC_DEFINE(CONFIG_LDISKFS_FS_SECURITY, 1,
	[enable fs security for ldiskfs])
AC_DEFINE(CONFIG_LDISKFSDEV_FS_POSIX_ACL, 1,
	[enable posix acls for ldiskfs])
AC_DEFINE(CONFIG_LDISKFSDEV_FS_XATTR, 1,
	[enable extented attributes for ldiskfs])
AC_DEFINE(CONFIG_LDISKFSDEV_FS_SECURITY, 1,
	[enable fs security for ldiskfs])
])

#
# Check for jbd2_journal_callback_set(), which is needed for commit
# callbacks.  When LU-433 lands jbd2_journal_callback_set() will only
# remain for legacy reasons and AC_MSG_ERROR can be removed.
#
# 2.6.18 with ext3 still uses journal_callback_set() for commit callbacks.
#
AC_DEFUN([LB_LDISKFS_JBD2_JOURNAL_CALLBACK_SET],
[
	LB_CHECK_SYMBOL_EXPORT([jbd2_journal_callback_set],
	[fs/jbd2/journal.c],
	[AC_DEFINE(HAVE_JBD2_JOURNAL_CALLBACK_SET, 1,
		[kernel exports jbd2_journal_callback_set])],
	[LB_CHECK_SYMBOL_EXPORT([journal_callback_set],
		[fs/jbd/journal.c],
		[AC_DEFINE(HAVE_JOURNAL_CALLBACK_SET, 1,
			[kernel exports journal_callback_set])],
		[if test x$with_ldiskfs != xno ; then
			AC_MSG_ERROR([ldiskfs needs jbd2-jcberr patch])
		fi])])
])

#
# Optionally configure/make the ldiskfs sources.  If the sources are
# determined to reside in-tree this feature will automatically be
# enabled.  If the sources are not in-tree it will be disabled.
# Use --enable-ldiskfs-build or --disable-ldiskfs-build if you need
# to override this behavior.
#
AC_DEFUN([LB_LDISKFS_BUILD],
[
AC_ARG_ENABLE([ldiskfs-build],
	AC_HELP_STRING([--enable-ldiskfs-build],
		[enable ldiskfs configure/make]),
	[], [
		LDISKFS_DIR_INTREE=$(readlink -f $PWD/ldiskfs)
		if test x$LDISKFS_DIR = x$LDISKFS_DIR_INTREE; then
			enable_ldiskfs_build='yes'
		else
			enable_ldiskfs_build='no'
		fi
	])

AC_MSG_CHECKING([whether to build ldiskfs])
if test x$enable_ldiskfs_build = xyes; then
	AC_MSG_RESULT([$enable_ldiskfs_build])

	LB_CHECK_FILE([$LDISKFS_DIR/configure], [], [
		AC_MSG_ERROR([Complete ldiskfs build system must exist])])
	LB_LDISKFS_EXT_SOURCE

	LDISKFS_SUBDIR="ldiskfs"
	AC_SUBST(LDISKFS_SUBDIR)
else
	enable_ldiskfs_build='no'
	AC_MSG_RESULT([$enable_ldiskfs_build])
fi
])

AC_DEFUN([LB_LDISKFS_SYMVERS],
[
AC_MSG_CHECKING([ldiskfs module symbols])
if test -r $LDISKFS_OBJ/Module.symvers; then
	LDISKFS_SYMBOLS=Module.symvers
elif test -r $LDISKFS_OBJ/Modules.symvers; then
	LDISKFS_SYMBOLS=Modules.symvers
elif test -r $LDISKFS_OBJ/ldiskfs/Module.symvers; then
	LDISKFS_SYMBOLS=Module.symvers
elif test -r $LDISKFS_OBJ/ldiskfs/Modules.symvers; then
	LDISKFS_SYMBOLS=Modules.symvers
else
	LDISKFS_SYMBOLS=$SYMVERFILE
fi

AC_MSG_RESULT([$LDISKFS_SYMBOLS])
AC_SUBST(LDISKFS_SYMBOLS)
])

AC_DEFUN([LB_LDISKFS_RELEASE],
[
AC_MSG_CHECKING([ldiskfs source release])
if test -r $LDISKFS_OBJ/config.h; then
	tmp_flags="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="-I$LDISKFS_DIR $EXTRA_KCFLAGS"
	LB_LINUX_TRY_MAKE([
		#undef PACKAGE_NAME
		#undef PACKAGE_TARNAME
		#undef PACKAGE_VERSION
		#undef PACKAGE_STRING
		#undef PACKAGE_BUGREPORT
		#undef PACKAGE
		#undef VERSION
		#undef STDC_HEADERS

		#include <$LDISKFS_OBJ/config.h>
	],[
		char *LDISKFS_RELEASE;
		LDISKFS_RELEASE=VERSION;
	],[
		$makerule LUSTRE_KERNEL_TEST=conftest.i
	],[
		test -s build/conftest.i
	],[
		eval $(grep "LDISKFS_RELEASE=" build/conftest.i)
	],[
		AC_MSG_RESULT([unknown])
		AC_MSG_ERROR([Could not preprocess test program.])
	])
	EXTRA_KCFLAGS="$tmp_flags"
	rm build/conftest.i
elif test -r $LDISKFS_DIR/configure.ac; then
	LDISKFS_RELEASE=$(awk '/AC\_INIT/ { print [$]3 }' \
		 $LDISKFS_DIR/configure.ac | tr ',' '\n')
else
	AC_MSG_RESULT([unknown])
	AC_MSG_ERROR([Could not locate config.h, META, or configure.ac to check release.])
fi

if test x$LDISKFS_RELEASE = x; then
	AC_MSG_RESULT([unknown])
	AC_MSG_ERROR([Could not determine ldiskfs release.])
fi

AC_MSG_RESULT([$LDISKFS_RELEASE])
AC_SUBST(LDISKFS_RELEASE)
])

#
# LB_DEFINE_E2FSPROGS_NAMES
#
# Enable the use of alternate naming of ldiskfs-enabled e2fsprogs package.
#
AC_DEFUN([LB_DEFINE_E2FSPROGS_NAMES],
[
AC_ARG_WITH([ldiskfsprogs],
        AC_HELP_STRING([--with-ldiskfsprogs],
                       [use alternate names for ldiskfs-enabled e2fsprogs]),
	[],[withval='no'])

AC_MSG_CHECKING([whether to use alternate names for e2fsprogs])
if test x$withval = xyes ; then
	AC_DEFINE(HAVE_LDISKFSPROGS, 1, [enable use of ldiskfsprogs package])
	E2FSPROGS="ldiskfsprogs"
	MKE2FS="mkfs.ldiskfs"
	DEBUGFS="debugfs.ldiskfs"
	TUNE2FS="tunefs.ldiskfs"
	E2LABEL="label.ldiskfs"
	DUMPE2FS="dumpfs.ldiskfs"
	E2FSCK="fsck.ldiskfs"
	PFSCK="pfsck.ldiskfs"
	AC_MSG_RESULT([enabled])
else
	E2FSPROGS="e2fsprogs"
	MKE2FS="mke2fs"
	DEBUGFS="debugfs"
	TUNE2FS="tune2fs"
	E2LABEL="e2label"
	DUMPE2FS="dumpe2fs"
	E2FSCK="e2fsck"
	PFSCK="fsck"
	AC_MSG_RESULT([disabled])
fi

AC_DEFINE_UNQUOTED(E2FSPROGS, "$E2FSPROGS", [name of ldiskfs e2fsprogs package])
AC_DEFINE_UNQUOTED(MKE2FS, "$MKE2FS", [name of ldiskfs mkfs program])
AC_DEFINE_UNQUOTED(DEBUGFS, "$DEBUGFS", [name of ldiskfs debug program])
AC_DEFINE_UNQUOTED(TUNE2FS, "$TUNE2FS", [name of ldiskfs tune program])
AC_DEFINE_UNQUOTED(E2LABEL, "$E2LABEL", [name of ldiskfs label program])
AC_DEFINE_UNQUOTED(DUMPE2FS,"$DUMPE2FS", [name of ldiskfs dump program])
AC_DEFINE_UNQUOTED(E2FSCK, "$E2FSCK", [name of ldiskfs fsck program])
AC_DEFINE_UNQUOTED(PFSCK, "$PFSCK", [name of parallel fsck program])

AC_SUBST([E2FSPROGS], [$E2FSPROGS])
AC_SUBST([MKE2FS], [$MKE2FS])
AC_SUBST([DEBUGFS], [$DEBUGFS])
AC_SUBST([TUNE2FS], [$TUNE2FS])
AC_SUBST([E2LABEL], [$E2LABEL])
AC_SUBST([DUMPE2FS], [$DUMPE2FS])
AC_SUBST([E2FSCK], [$E2FSCK])
AC_SUBST([PFSCK], [$PFSCK])
])

AC_DEFUN([LB_LDISKFS_SERIES],
[
if $1; then
	AC_MSG_CHECKING([which ldiskfs series to use])
	case $LINUXRELEASE in
	2.6.18*)
		if test x$RHEL_KERNEL = xyes; then
			LDISKFS_SERIES="2.6-rhel5-ext4.series"
		fi
		;;
	2.6.32*)
		if test x$RHEL_KERNEL = xyes; then
			LDISKFS_SERIES="2.6-rhel6.series"
		fi
		;;
	*)
		AC_MSG_WARN([Unknown kernel version $LINUXRELEASE])
		LDISKFS_SERIES=
		;;
	esac
	AC_MSG_RESULT([$LDISKFS_SERIES])
else
	LDISKFS_SERIES=
fi
AC_SUBST(LDISKFS_SERIES)
])
