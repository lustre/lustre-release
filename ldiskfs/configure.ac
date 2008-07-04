# Process this file with autoconf to produce a configure script.

AC_INIT([Lustre ldiskfs], 3.0.5, [https://bugzilla.lustre.org/])
AC_CONFIG_SRCDIR([lustre-ldiskfs.spec.in])

# Don't look for install-sh, etc. in ..
AC_CONFIG_AUX_DIR([.])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE

AC_PROG_CC

LB_CANONICAL_SYSTEM
LB_INCLUDE_RULES
LB_PROG_CC


#
# LC_TARGET_SUPPORTED
#
# is the target os supported?
#
AC_DEFUN([LC_TARGET_SUPPORTED],
[case $target_os in
	linux* | darwin*)
$1
		;;
	*)
$2
		;;
esac
])


AC_MSG_CHECKING([whether to build kernel modules])
AC_ARG_ENABLE([modules],
	      AC_HELP_STRING([--disable-modules],
			     [disable building of Lustre kernel modules]),[],
			     [LC_TARGET_SUPPORTED([enable_modules='yes'],
			     [enable_modules='no'])])
AC_MSG_RESULT([$enable_modules])

if test x$enable_modules = xyes ; then
	LB_PROG_LINUX
if test x$linux25 = xyes ; then
	LB_LINUX_MODPOST
fi
fi

LB_CONFIG_HEADERS

# These allow Lustre Makefiles and autoMakefiles to be used unchanged.
AM_CONDITIONAL(MODULES, true)
AM_CONDITIONAL(LINUX, true)
AM_CONDITIONAL(DARWIN, true)
AM_CONDITIONAL(LINUX25, true)

LDISKFSDIR="$PWD/ldiskfs"
AC_SUBST(LDISKFSDIR)

AC_MSG_CHECKING([whether to enable quilt for making ldiskfs])
AC_ARG_ENABLE([quilt],
	      AC_HELP_STRING([--disable-quilt],
			     [disable use of quilt for ldiskfs]),[],
			     [enable_quilt='yes'])
AC_MSG_RESULT([$enable_quilt])

AC_PATH_PROG(PATCH, patch, [no])

if test x$enable_quilt = xno ; then
    QUILT="no"
else
    AC_PATH_PROG(QUILT, quilt, [no])
fi

if test x$enable_ldiskfs$PATCH$QUILT = xyesnono ; then
	AC_MSG_ERROR([Quilt or patch are needed to build the ldiskfs module])
fi

AM_CONDITIONAL(USE_QUILT, test x$QUILT != xno)

LB_DEFINE_LDISKFS_OPTIONS

AC_MSG_CHECKING([which ldiskfs series to use])
case $LINUXRELEASE in
2.6.5*) LDISKFS_SERIES="2.6-suse.series" ;;
2.6.9*) LDISKFS_SERIES="2.6-rhel4.series" ;;
2.6.10-ac*) LDISKFS_SERIES="2.6-fc3.series" ;;
2.6.10*) LDISKFS_SERIES="2.6-rhel4.series" ;;
2.6.12*) LDISKFS_SERIES="2.6.12-vanilla.series" ;;
2.6.15*) LDISKFS_SERIES="2.6-fc5.series";;
2.6.16*) LDISKFS_SERIES="2.6-sles10.series";;
2.6.18*)
	if test x$RHEL_KENEL = xyes; then
		LDISKFS_SERIES="2.6-rhel5.series"
	else
		LDISKFS_SERIES="2.6.18-vanilla.series"
	fi
	;;
2.6.22*) LDISKFS_SERIES="2.6.22-vanilla.series";;
*) AC_MSG_WARN([Unknown kernel version $LINUXRELEASE, fix ldiskfs/configure.ac])
esac
AC_MSG_RESULT([$LDISKFS_SERIES])
AC_SUBST(LDISKFS_SERIES)

AC_SUBST(ac_configure_args)

LB_CHECK_SYMBOL_EXPORT([d_rehash_cond],
		       [fs/dcache.c],
		       [AC_DEFINE(HAVE_D_REHASH_COND, 1,
				  [d_rehash_cond is exported by the kernel])],
				  [])

LB_CHECK_SYMBOL_EXPORT([__d_rehash],
		       [fs/dcache.c],
		       [AC_DEFINE(HAVE___D_REHASH, 1,
				  [__d_rehash is exported by the kernel])],
				  [])

LB_CHECK_SYMBOL_EXPORT([d_move_locked],
		       [fs/dcache.c],
		       [AC_DEFINE(HAVE_D_MOVE_LOCKED, 1,
				  [d_move_locked is exported by the kernel])],
				  [])

LB_CHECK_SYMBOL_EXPORT([__d_move],
		       [fs/dcache.c],
		       [AC_DEFINE(HAVE___D_MOVE, 1,
				  [__d_move exported by the kernel])],
				  [])

LB_CONFIG_FILES
AC_CONFIG_FILES([ldiskfs/autoMakefile ldiskfs/Makefile])

MOSTLYCLEANFILES='.*.cmd .*.flags *.o *.ko *.mod.c .depend .*.1.*'
AC_SUBST(MOSTLYCLEANFILES)

AC_OUTPUT
