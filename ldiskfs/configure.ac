# Process this file with autoconf to produce a configure script.

AC_INIT([Lustre ldiskfs], 3.3.0, [http://bugs.whamcloud.com/])
AC_CONFIG_SRCDIR([lustre-ldiskfs.spec.in])

# Don't look for install-sh, etc. in ..
AC_CONFIG_AUX_DIR([.])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([1.9 tar-ustar])

AC_PROG_CC

LB_CANONICAL_SYSTEM

LB_DOWNSTREAM_RELEASE

LB_BUILDID

LB_INCLUDE_RULES
LB_PROG_CC

AC_ARG_ENABLE([dist],
	AC_HELP_STRING([--enable-dist],
			[only configure enough for make dist]),
	[enable_dist='yes'],[enable_dist='no'])
AC_MSG_RESULT([$enable_dist])
if test x$enable_dist != xno; then
	enable_modules='no'
fi

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
	LB_LINUX_MODPOST
fi

LB_LDISKFS_SERIES([test x$enable_dist = xno])

AC_MSG_CHECKING([whether to build Lustre server support])
AC_ARG_ENABLE([server],
	AC_HELP_STRING([--disable-server],
	               [disable Lustre server support]),
	[],[
		if test -n "$LDISKFS_SERIES"; then
			enable_server='yes'
		else
			enable_server='no'
		fi
	])
AC_MSG_RESULT([$enable_server])

LB_CONFIG_HEADERS

# These allow Lustre Makefiles and autoMakefiles to be used unchanged.
AM_CONDITIONAL(MODULES, true)
AM_CONDITIONAL(LINUX, true)
AM_CONDITIONAL(DARWIN, true)

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

if test x$enable_server$PATCH$QUILT = xyesnono ; then
	AC_MSG_ERROR([Quilt or patch are needed to build the ldiskfs module])
fi

AM_CONDITIONAL(USE_QUILT, test x$QUILT != xno)

if test x$enable_server$enable_dist = xyesno ; then
LB_LDISKFS_EXT_DIR
LB_LDISKFS_EXT_SOURCE
LB_LDISKFS_DEFINE_OPTIONS
fi

AM_CONDITIONAL(LDISKFS_PDO, test x$with_ldiskfs_pdo = xyes)

AC_SUBST(ac_configure_args)

LB_CONFIG_FILES
AC_CONFIG_FILES([ldiskfs/autoMakefile ldiskfs/Makefile])

MOSTLYCLEANFILES='.*.cmd .*.flags *.o *.ko *.mod.c .depend .*.1.* Modules.symvers Module.symvers'
AC_SUBST(MOSTLYCLEANFILES)

AC_OUTPUT
