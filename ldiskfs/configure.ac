# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.57])
AC_INIT([Lustre ldiskfs], 4.1.0, [http://bugs.whamcloud.com/])
AC_CONFIG_SRCDIR([lustre-ldiskfs.spec.in])

# Don't look for install-sh, etc. in ..
AC_CONFIG_AUX_DIR([config])

AC_CONFIG_MACRO_DIR([config])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([1.10 tar-ustar -Wno-portability])
AM_MAINTAINER_MODE([enable])

AC_PROG_CC

LB_DOWNSTREAM_RELEASE

LB_BUILDID

LB_PROG_CC

AC_ARG_ENABLE([dist],
	AC_HELP_STRING([--enable-dist],
			[only configure enough for make dist]),
	[enable_dist='yes'],[enable_dist='no'])
AC_MSG_RESULT([$enable_dist])
if test x$enable_dist != xno; then
	enable_modules='no'
fi

AC_MSG_CHECKING([whether to build kernel modules])
AC_ARG_ENABLE([modules],
	      AC_HELP_STRING([--disable-modules],
			     [disable building of Lustre kernel modules]),[],
			     [enable_modules='yes'],
			     [enable_modules='no'])
AC_MSG_RESULT([$enable_modules])

if test x$enable_modules = xyes ; then
	LB_LINUX_PATH
	LB_LINUX_SYMVERFILE
	LB_LINUX_CONFIG([MODULES],[],[
		AC_MSG_ERROR([module support is required to build ldiskfs kernel module.])
	])
	LB_LINUX_CONFIG([MODVERSIONS])
	LB_LINUX_CONFIG([KALLSYMS],[],[
		AC_MSG_ERROR([ldiskfs requires that CONFIG_KALLSYMS is enabled in your kernel.])
	])
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

LDISKFSDIR="$PWD/ldiskfs"
AC_SUBST(LDISKFSDIR)

LDISKFS_AC_PATCH_PROGRAM

if test x$enable_server$enable_dist = xyesno ; then
LB_LDISKFS_EXT_DIR
LB_LDISKFS_EXT_SOURCE
LB_EXT_FREE_BLOCKS_WITH_BUFFER_HEAD
LB_EXT_PBLOCK
fi

LB_CONFIG_HEADERS

AC_SUBST(ac_configure_args)

AC_CONFIG_FILES([Makefile ldiskfs/Makefile]
		AC_PACKAGE_TARNAME[.spec])

MOSTLYCLEANFILES='.*.cmd .*.flags *.o *.ko *.mod.c .depend .*.1.* Modules.symvers Module.symvers'
AC_SUBST(MOSTLYCLEANFILES)

AC_OUTPUT
