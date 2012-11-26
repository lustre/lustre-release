
#
# LB_LDISKFS_EXT_DIR
#
# Determine the location of the ext4 source code.  It is required
# for several configure tests and to build ldiskfs.
#
AC_DEFUN([LB_LDISKFS_EXT_DIR],
[
# Kernel ext source located with devel headers
linux_src=$LINUX
if test -e "$linux_src/fs/ext4/super.c"; then
	EXT_DIR=$linux_src/fs/ext4
else
	# Kernel ext source provided by kernel-debuginfo-common package
	linux_src=$(ls -1d /usr/src/debug/*/linux-$LINUXRELEASE \
		2>/dev/null | tail -1)
	if test -e "$linux_src/fs/ext4/super.c"; then
		EXT_DIR=$linux_src/fs/ext4
	else
		EXT_DIR=
	fi
fi

AC_MSG_CHECKING([ext4 source directory])
AC_MSG_RESULT([$EXT_DIR])
AC_SUBST(EXT_DIR)
])

#
# LB_LDISKFS_EXT_SOURCE
#
# Spot check the existance of several source files common to ext4.
# Detecting this at configure time allows us to avoid a potential build
# failure and provide a useful error message to explain what is wrong.
#
AC_DEFUN([LB_LDISKFS_EXT_SOURCE],
[
if test x$EXT_DIR = x; then
	enable_ldiskfs_build='no'
else
	LB_CHECK_FILE([$EXT_DIR/dir.c], [], [
		enable_ldiskfs_build='no'
		AC_MSG_WARN([ext4 must exist for ldiskfs build])])
	LB_CHECK_FILE([$EXT_DIR/file.c], [], [
		enable_ldiskfs_build='no'
		AC_MSG_WARN([ext4 must exist for ldiskfs build])])
	LB_CHECK_FILE([$EXT_DIR/inode.c], [], [
		enable_ldiskfs_build='no'
		AC_MSG_WARN([ext4 must exist for ldiskfs build])])
	LB_CHECK_FILE([$EXT_DIR/super.c], [], [
		enable_ldiskfs_build='no'
		AC_MSG_WARN([ext4 must exist for ldiskfs build])])
fi

if test x$enable_ldiskfs_build = xno; then
	enable_server='no'
	enable_ldiskfs_build='no'
	with_ldiskfs='no'
	LDISKFS_SUBDIR=

	AC_MSG_WARN([

Disabling server because complete ext4 source does not exist.

If you are building using kernel-devel packages and require ldiskfs
server support then ensure that the matching kernel-debuginfo-common
and kernel-debuginfo-common-<arch> packages are installed.

])

fi
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
case $LINUXRELEASE in
2.6.32*)
	if test x$RHEL_KERNEL = xyes; then
		with_ldiskfs_pdo=yes
		AC_DEFINE(HAVE_LDISKFS_PDO, 1, [have ldiskfs PDO patch])
	fi
	if test x$SUSE_KERNEL = xyes; then
		with_ldiskfs_pdo=yes
		AC_DEFINE(HAVE_LDISKFS_PDO, 1, [have ldiskfs PDO patch])
	fi
	;;
esac
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
AC_DEFUN([LB_LDISKFS_JBD2_JOURNAL_CALLBACK_SET],
[
	LB_CHECK_SYMBOL_EXPORT([jbd2_journal_callback_set],
		[fs/jbd2/journal.c],
		[AC_DEFINE(HAVE_JBD2_JOURNAL_CALLBACK_SET, 1,
			[kernel exports jbd2_journal_callback_set])])
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
		if test x$SUSE_KERNEL = xyes; then
			LDISKFS_SERIES="2.6-sles11.series"
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
