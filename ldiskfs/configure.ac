# Process this file with autoconf to produce a configure script.

AC_INIT([Lustre ldiskfs], 3.3.0, [http://bugs.whamcloud.com/])
AC_CONFIG_SRCDIR([lustre-ldiskfs.spec.in])
ldiskfs_is_ext4=yes

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

LB_HAVE_EXT4_ENABLED

if test x$enable_ext4 = xyes ; then
	AC_DEFINE(HAVE_EXT4_LDISKFS, 1, [ldiskfs based on ext4])
	BACKFS=ext4
else
	BACKFS=ext3
fi

AC_SUBST(BACKFS)
BACKFSU=${BACKFS/ext/EXT}
AC_SUBST(BACKFSU) # We need a Upper string

AM_CONDITIONAL(USE_EXT4, test x$enable_ext4 = xyes)

if test x$enable_dist != xyes; then
	# don't need to do this if only configuring for make dist
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
                if test x$enable_ext4 = xyes; then
		        LDISKFS_SERIES="2.6-rhel5-ext4.series"
                else
		        LDISKFS_SERIES="2.6-rhel5.series"
                fi
	else
		LDISKFS_SERIES="2.6.18-vanilla.series"
	fi
	;;
2.6.22*) LDISKFS_SERIES="2.6.22-vanilla.series";;
2.6.27*) LDISKFS_SERIES="2.6-sles11.series";;
2.6.32*) LDISKFS_SERIES="2.6-rhel6.series";;
*) AC_MSG_WARN([Unknown kernel version $LINUXRELEASE, fix ldiskfs/configure.ac])
esac
AC_MSG_RESULT([$LDISKFS_SERIES])
fi
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

LB_CONFIG_FILES
AC_CONFIG_FILES([ldiskfs/autoMakefile ldiskfs/Makefile])

MOSTLYCLEANFILES='.*.cmd .*.flags *.o *.ko *.mod.c .depend .*.1.* Modules.symvers Module.symvers'
AC_SUBST(MOSTLYCLEANFILES)

AC_OUTPUT
