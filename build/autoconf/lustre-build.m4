#
# LB_CHECK_VERSION
#
# Verify that LUSTRE_VERSION was defined properly
#
AC_DEFUN([LB_CHECK_VERSION],
[if test "LUSTRE_VERSION" = "LUSTRE""_VERSION" ; then
	AC_MSG_ERROR([This script was not built with a version number.])
fi
])

#
# LB_CANONICAL_SYSTEM
#
# fixup $target_os for use in other places
#
AC_DEFUN([LB_CANONICAL_SYSTEM],
[case $target_os in
	linux*)
		lb_target_os="linux"
		;;
	darwin*)
		lb_target_os="darwin"
		;;
esac
AC_SUBST(lb_target_os)
])

#
# LB_CHECK_FILE
#
# Check for file existance even when cross compiling
#
AC_DEFUN([LB_CHECK_FILE],
[AS_VAR_PUSHDEF([lb_File], [lb_cv_file_$1])dnl
AC_CACHE_CHECK([for $1], lb_File,
[if test -r "$1"; then
  AS_VAR_SET(lb_File, yes)
else
  AS_VAR_SET(lb_File, no)
fi])
AS_IF([test AS_VAR_GET(lb_File) = yes], [$2], [$3])[]dnl
AS_VAR_POPDEF([lb_File])dnl
])# LB_CHECK_FILE

#
# LB_CHECK_FILES
#
# LB_CHECK_FILE over multiple files
#
AC_DEFUN([LB_CHECK_FILES],
[AC_FOREACH([AC_FILE_NAME], [$1],
  [LB_CHECK_FILE(AC_FILE_NAME,
                 [AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_[]AC_FILE_NAME), 1,
                                    [Define to 1 if you have the
                                     file `]AC_File['.])
$2],
                 [$3])])])

#
# LB_ARG_LIBS_INCLUDES
#
# support for --with-foo, --with-foo-includes, and --with-foo-libs in
# a single magical macro
#
AC_DEFUN([LB_ARG_LIBS_INCLUDES],
[lb_pathvar="m4_bpatsubst([$2], -, _)"
AC_MSG_CHECKING([for $1])
AC_ARG_WITH([$2],
	AC_HELP_STRING([--with-$2=path],
		[path to $1]),
	[],[withval=$4])

if test x$withval = xyes ; then
	eval "$lb_pathvar='$3'"
else
	eval "$lb_pathvar='$withval'"
fi
AC_MSG_RESULT([${!lb_pathvar:-no}])

if test x${!lb_pathvar} != x -a x${!lb_pathvar} != xno ; then
	AC_MSG_CHECKING([for $1 includes])
	AC_ARG_WITH([$2-includes],
		AC_HELP_STRING([--with-$2-includes=path],
			[path to $1 includes]),
		[],[withval='yes'])

	lb_includevar="${lb_pathvar}_includes"
	if test x$withval = xyes ; then
		eval "${lb_includevar}='${!lb_pathvar}/include'"
	else
		eval "${lb_includevar}='$withval'"
	fi
	AC_MSG_RESULT([${!lb_includevar}])

	AC_MSG_CHECKING([for $1 libs])
	AC_ARG_WITH([$2-libs],
		AC_HELP_STRING([--with-$2-libs=path],
			[path to $1 libs]),
		[],[withval='yes'])

	lb_libvar="${lb_pathvar}_libs"
	if test x$withval = xyes ; then
		eval "${lb_libvar}='${!lb_pathvar}/lib'"
	else
		eval "${lb_libvar}='$withval'"
	fi
	AC_MSG_RESULT([${!lb_libvar}])
fi
])
])

#
# LB_PATH_LIBSYSIO
#
# Handle internal/external libsysio
#
AC_DEFUN([LB_PATH_LIBSYSIO],
[AC_ARG_WITH([sysio],
	AC_HELP_STRING([--with-sysio=path],
			[set path to libsysio source (default is included libsysio)]),
	[],[
		case $lb_target_os in
			linux)
				with_sysio='yes'
				;;
			*)
				with_sysio='no'
				;;
		esac
	])
AC_MSG_CHECKING([location of libsysio])
enable_sysio="$with_sysio"
case x$with_sysio in
	xyes)
		AC_MSG_RESULT([internal])
		LB_CHECK_FILE([$srcdir/libsysio/src/rmdir.c],[],[
			AC_MSG_ERROR([A complete internal libsysio was not found.])
		])
		LIBSYSIO_SUBDIR="libsysio"
		SYSIO="$PWD/libsysio"
		;;
	xno)
		AC_MSG_RESULT([disabled])
		;;
	*)
		AC_MSG_RESULT([$with_sysio])
		LB_CHECK_FILE([$with_sysio/lib/libsysio.a],[],[
			AC_MSG_ERROR([A complete (built) external libsysio was not found.])
		])
		SYSIO=$with_sysio
		with_sysio="yes"
		;;
esac

# We have to configure even if we don't build here for make dist to
# work
AC_CONFIG_SUBDIRS(libsysio)
])

#
# LB_CONFIG_CRAY_XT3
#
# Enable Cray XT3 features
#
AC_DEFUN([LB_CONFIG_CRAY_XT3],
[AC_MSG_CHECKING([whether to build Cray XT3 features])
AC_ARG_ENABLE([cray_xt3],
	AC_HELP_STRING([--enable-cray-xt3],
			[enable building of Cray XT3 features]),
	[enable_cray_xt3='yes'],[enable_cray_xt3='no'])
AC_MSG_RESULT([$enable_cray_xt3])
if test x$enable_cray_xt3 != xno; then
        AC_DEFINE(CRAY_XT3, 1, Enable Cray XT3 Features)
fi
])

#
# LB_CONFIG_BGL
#
# Enable BGL features
#
AC_DEFUN([LB_CONFIG_BGL],
[AC_MSG_CHECKING([whether to build BGL features])
AC_ARG_ENABLE([bgl],
	AC_HELP_STRING([--enable-bgl],
			[enable building of BGL features]),
	[enable_bgl='yes'],[enable_bgl='no'])
AC_MSG_RESULT([$enable_bgl])
if test x$enable_bgl != xno; then
        AC_DEFINE(BGL_SUPPORT, 1, Enable BGL Features)
        enable_doc='no'
        enable_tests='no'
        enable_server='no'
        enable_liblustre='no'
        enable_libreadline='no'
fi
])

#
# LB_PATH_SNMP
#
# check for in-tree snmp support
#
AC_DEFUN([LB_PATH_SNMP],
[LB_CHECK_FILE([$srcdir/snmp/lustre-snmp.c],[SNMP_DIST_SUBDIR="snmp"])
AC_SUBST(SNMP_DIST_SUBDIR)
AC_SUBST(SNMP_SUBDIR)
])

#
# LB_CONFIG_MODULES
#
# Build kernel modules?
#
AC_DEFUN([LB_CONFIG_MODULES],
[AC_MSG_CHECKING([whether to build kernel modules])
AC_ARG_ENABLE([modules],
	AC_HELP_STRING([--disable-modules],
			[disable building of Lustre kernel modules]),
	[],[
		LC_TARGET_SUPPORTED([
			enable_modules='yes'
		],[
			enable_modules='no'
		])
	])
AC_MSG_RESULT([$enable_modules ($target_os)])

if test x$enable_modules = xyes ; then
	case $target_os in
		linux*)
			LB_PROG_LINUX
			;;
		darwin*)
			LB_PROG_DARWIN
			;;
		*)
			# This is strange - Lustre supports a target we don't
			AC_MSG_ERROR([Modules are not supported on $target_os])
			;;
	esac
fi
])

#
# LB_CONFIG_UTILS
#
# Build utils?
#
AC_DEFUN([LB_CONFIG_UTILS],
[AC_MSG_CHECKING([whether to build utilities])
AC_ARG_ENABLE([utils],
	AC_HELP_STRING([--disable-utils],
			[disable building of Lustre utility programs]),
	[],[enable_utils='yes'])
AC_MSG_RESULT([$enable_utils])
if test x$enable_utils = xyes ; then 
	LB_CONFIG_INIT_SCRIPTS
fi
])

#
# LB_CONFIG_TESTS
#
# Build tests?
#
AC_DEFUN([LB_CONFIG_TESTS],
[AC_MSG_CHECKING([whether to build Lustre tests])
AC_ARG_ENABLE([tests],
	AC_HELP_STRING([--disable-tests],
			[disable building of Lustre tests]),
	[],
	[
		enable_tests='yes'
	])
AC_MSG_RESULT([$enable_tests])
])

#
# LB_CONFIG_DOCS
#
# Build docs?
#
AC_DEFUN([LB_CONFIG_DOCS],
[AC_MSG_CHECKING([whether to build docs])
AC_ARG_ENABLE(doc,
	AC_HELP_STRING([--disable-doc],
			[skip creation of pdf documentation]),
	[
		if test x$enable_doc = xyes ; then
		    ENABLE_DOC=1	   
		else
		    ENABLE_DOC=0
		fi
	],[
		ENABLE_DOC=0
		enable_doc='no'
	])
AC_MSG_RESULT([$enable_doc])
AC_SUBST(ENABLE_DOC)
])

#
# LB_CONFIG_INIT_SCRIPTS
#
# our init scripts only work on red hat linux
#
AC_DEFUN([LB_CONFIG_INIT_SCRIPTS],
[ENABLE_INIT_SCRIPTS=0
if test x$enable_utils = xyes ; then
        AC_MSG_CHECKING([whether to install init scripts])
        # our scripts only work on red hat systems
        if test -f /etc/init.d/functions -a -f /etc/sysconfig/network ; then
                ENABLE_INIT_SCRIPTS=1
                AC_MSG_RESULT([yes])
        else
                AC_MSG_RESULT([no])
        fi
fi
AC_SUBST(ENABLE_INIT_SCRIPTS)
])

#
# LB_CONFIG_HEADERS
#
# add -include config.h
#
AC_DEFUN([LB_CONFIG_HEADERS],
[AC_CONFIG_HEADERS([config.h])
CPPFLAGS="-include \$(top_builddir)/config.h $CPPFLAGS"
EXTRA_KCFLAGS="-include $PWD/config.h $EXTRA_KCFLAGS"
AC_SUBST(EXTRA_KCFLAGS)
])

#
# LB_INCLUDE_RULES
#
# defines for including the toplevel Rules
#
AC_DEFUN([LB_INCLUDE_RULES],
[INCLUDE_RULES="include $PWD/build/Rules"
AC_SUBST(INCLUDE_RULES)
])

#
# LB_PATH_DEFAULTS
#
# 'fixup' default paths
#
AC_DEFUN([LB_PATH_DEFAULTS],
[# directories for binaries
AC_PREFIX_DEFAULT([/usr])

sysconfdir='/etc'
AC_SUBST(sysconfdir)

# Directories for documentation and demos.
docdir='${datadir}/doc/$(PACKAGE)'
AC_SUBST(docdir)

LN_PATH_DEFAULTS
LC_PATH_DEFAULTS

])

#
# LB_PROG_CC
#
# checks on the C compiler
#
AC_DEFUN([LB_PROG_CC],
[AC_PROG_RANLIB
AC_MSG_CHECKING([for buggy compiler])
CC_VERSION=`$CC -v 2>&1 | grep "^gcc version"`
bad_cc() {
	AC_MSG_RESULT([buggy compiler found!])
	echo
	echo "   '$CC_VERSION'"
	echo "  has been known to generate bad code, "
	echo "  please get an updated compiler."
	AC_MSG_ERROR([sorry])
}
case "$CC_VERSION" in
	"gcc version 2.95"*)
		bad_cc
		;;
	# ost_pack_niobuf putting 64bit NTOH temporaries on the stack
	# without "sub    $0xc,%esp" to protect the stack from being
	# stomped on by interrupts (bug 606)
	"gcc version 2.96 20000731 (Red Hat Linux 7.1 2.96-98)")
		bad_cc
		;;
	# mandrake's similar sub 0xc compiler bug
	# http://marc.theaimsgroup.com/?l=linux-kernel&m=104748366226348&w=2
	"gcc version 2.96 20000731 (Mandrake Linux 8.1 2.96-0.62mdk)")
		bad_cc
		;;
	*)
		AC_MSG_RESULT([no known problems])
		;;
esac

# ---------  unsigned long long sane? -------
AC_CHECK_SIZEOF(unsigned long long, 0)
echo "---> size SIZEOF $SIZEOF_unsigned_long_long"
echo "---> size SIZEOF $ac_cv_sizeof_unsigned_long_long"
if test $ac_cv_sizeof_unsigned_long_long != 8 ; then
        AC_MSG_ERROR([** we assume that sizeof(long long) == 8.  Tell phil@clusterfs.com])
fi

# FIXME
AC_CHECK_DECL([__i386__], [], [

if test x$enable_bgl != xyes; then
AC_MSG_CHECKING([if $CC accepts -m64])
CC_save="$CC"
CC="$CC -m64"
AC_TRY_COMPILE([],[],[
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
	CC="$CC_save"
])
fi

])

CPPFLAGS="-I\$(top_builddir)/lnet/include -I\$(top_srcdir)/lnet/include -I\$(top_builddir)/lustre/include -I\$(top_srcdir)/lustre/include $CPPFLAGS"

LLCPPFLAGS="-D__arch_lib__ -D_LARGEFILE64_SOURCE=1"
AC_SUBST(LLCPPFLAGS)

LLCFLAGS="-g -Wall -fPIC"
AC_SUBST(LLCFLAGS)

# everyone builds against lnet and lustre
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -g -I$PWD/lnet/include -I$PWD/lustre/include"
AC_SUBST(EXTRA_KCFLAGS)
])

#
# LB_CONTITIONALS
#
# AM_CONDITIONAL instances for everything
# (so that portals/lustre can disable some if needed)
AC_DEFUN([LB_CONDITIONALS],
[AM_CONDITIONAL(MODULES, test x$enable_modules = xyes)
AM_CONDITIONAL(UTILS, test x$enable_utils = xyes)
AM_CONDITIONAL(TESTS, test x$enable_tests = xyes)
AM_CONDITIONAL(DOC, test x$ENABLE_DOC = x1)
AM_CONDITIONAL(INIT_SCRIPTS, test x$ENABLE_INIT_SCRIPTS = "x1")
AM_CONDITIONAL(LINUX, test x$lb_target_os = "xlinux")
AM_CONDITIONAL(DARWIN, test x$lb_target_os = "xdarwin")

# this lets lustre cancel libsysio, per-branch or if liblustre is
# disabled
if test "x$LIBSYSIO_SUBDIR" = xlibsysio ; then
	if test "x$with_sysio" != xyes ; then
		SYSIO=""
		LIBSYSIO_SUBDIR=""
	fi
fi
AC_SUBST(LIBSYSIO_SUBDIR)
AC_SUBST(SYSIO)

LB_LINUX_CONDITIONALS
LB_DARWIN_CONDITIONALS

LN_CONDITIONALS
LC_CONDITIONALS
])

#
# LB_CONFIGURE
#
# main configure steps
#
AC_DEFUN([LB_CONFIGURE],
[LB_CANONICAL_SYSTEM

LB_INCLUDE_RULES

LB_CONFIG_CRAY_XT3
LB_CONFIG_BGL
LB_PATH_DEFAULTS

LB_PROG_CC

LB_PATH_LIBSYSIO
LB_PATH_SNMP

LB_CONFIG_DOCS
LB_CONFIG_UTILS
LB_CONFIG_TESTS
LC_CONFIG_CLIENT_SERVER

# two cmd3 macros, please define dummies for other branches 
LC_CONFIG_SPLIT
LC_CONFIG_LDISKFS

LB_CONFIG_MODULES

LC_CONFIG_LIBLUSTRE
LN_CONFIGURE

LC_CONFIGURE

if test "$SNMP_DIST_SUBDIR" ; then
	LS_CONFIGURE
fi

LB_CONDITIONALS
LB_CONFIG_HEADERS

AC_CONFIG_FILES(
[Makefile:build/Makefile.in.toplevel]
[autoMakefile
build/autoMakefile
build/autoconf/Makefile
build/Rules
build/lustre.spec
])

LN_CONFIG_FILES
LC_CONFIG_FILES
if test "$SNMP_DIST_SUBDIR" ; then
	LS_CONFIG_FILES
fi

AC_SUBST(ac_configure_args)

MOSTLYCLEANFILES='.*.cmd .*.flags *.o *.ko *.mod.c .depend .*.1.*'
AC_SUBST(MOSTLYCLEANFILES)

AC_OUTPUT

cat <<_ACEOF

CC:            $CC
LD:            $LD
CPPFLAGS:      $CPPFLAGS
LLCPPFLAGS:    $LLCPPFLAGS
CFLAGS:        $CFLAGS
EXTRA_KCFLAGS: $EXTRA_KCFLAGS
LLCFLAGS:      $LLCFLAGS

Type 'make' to build Lustre.
_ACEOF
])
