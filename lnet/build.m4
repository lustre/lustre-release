# ----------  other tests and settings ---------


# ---------  unsigned long long sane? -------

AC_CHECK_SIZEOF(unsigned long long, 0)
echo "---> size SIZEOF $SIZEOF_unsigned_long_long"
echo "---> size SIZEOF $ac_cv_sizeof_unsigned_long_long"
if test $ac_cv_sizeof_unsigned_long_long != 8 ; then
        AC_MSG_ERROR([** we assume that sizeof(long long) == 8.  Tell phil@clusterfs.com])
fi

# directories for binaries
ac_default_prefix=
bindir='${exec_prefix}/usr/bin'
sbindir='${exec_prefix}/usr/sbin'
includedir='${prefix}/usr/include'

rootsbindir='${exec_prefix}/sbin'
AC_SUBST(rootsbindir)

# Directories for documentation and demos.
docdir='${prefix}/usr/share/doc/$(PACKAGE)'
AC_SUBST(docdir)
demodir='$(docdir)/demo'
AC_SUBST(demodir)
pkgexampledir='${prefix}/usr/lib/$(PACKAGE)/examples'
AC_SUBST(pkgexampledir)
pymoddir='${prefix}/usr/lib/${PACKAGE}/python/Lustre'
AC_SUBST(pymoddir)
# for substitution in lconf
PYMOD_DIR="/usr/lib/$PACKAGE/python"
AC_SUBST(PYMOD_DIR)
modulenetdir='$(moduledir)/net/$(PACKAGE)'
AC_SUBST(modulenetdir)


# ----------  BAD gcc? ------------
AC_PROG_RANLIB
AC_PROG_CC
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
TMP_VERSION=`echo $CC_VERSION | cut -c 1-16`
if test "$TMP_VERSION" = "gcc version 2.95"; then
        bad_cc
fi
case "$CC_VERSION" in 
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
# end ------  BAD gcc? ------------

# --------  Check for required packages  --------------

# this doesn't seem to work on older autoconf
# AC_CHECK_LIB(readline, readline,,)
AC_MSG_CHECKING([for readline support])
AC_ARG_ENABLE(readline,
	AC_HELP_STRING([--disable-readline],
			[do not use readline library]),
	[],[enable_readline='yes'])
AC_MSG_RESULT([$enable_readline]) 
if test x$enable_readline = xyes ; then
	LIBREADLINE="-lreadline -lncurses"
	AC_DEFINE(HAVE_LIBREADLINE, 1, [readline library is available])
else 
	LIBREADLINE=""
fi
AC_SUBST(LIBREADLINE)

AC_MSG_CHECKING([if efence debugging support is requested])
AC_ARG_ENABLE(efence,
	AC_HELP_STRING([--enable-efence],
			[use efence library]),
	[],[enable_efence='no'])
AC_MSG_RESULT([$enable_efence])
if test "$enable_efence" = "yes" ; then
	LIBEFENCE="-lefence"
	AC_DEFINE(HAVE_LIBEFENCE, 1, [libefence support is requested])
else 
	LIBEFENCE=""
fi
AC_SUBST(LIBEFENCE)
