
# ----------  directories ---------


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

# Directories for documentation and demos.
docdir='${prefix}/usr/share/doc/$(PACKAGE)'
AC_SUBST(docdir)
demodir='$(docdir)/demo'
AC_SUBST(demodir)
pkgexampledir='${prefix}/usr/lib/$(PACKAGE)/examples'
AC_SUBST(pkgexampledir)
pymoddir='${prefix}/usr/lib/${PACKAGE}/python/Lustre'
AC_SUBST(pymoddir)
modulenetdir='$(moduledir)/net/$(PACKAGE)'
AC_SUBST(modulenetdir)


# ----------  BAD gcc? ------------
AC_PROG_RANLIB
AC_PROG_CC
AC_MSG_CHECKING(for buggy compiler)
CC_VERSION=`$CC -v 2>&1 | grep "^gcc version"`
bad_cc() {
	echo
	echo "   '$CC_VERSION'"
	echo "  has been known to generate bad code, "
	echo "  please get an updated compiler."
	AC_MSG_ERROR(sorry)
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
		AC_MSG_RESULT(no known problems)
		;;
esac
# end ------  BAD gcc? ------------

# --------  Check for required packages  --------------

# this doesn't seem to work on older autoconf
# AC_CHECK_LIB(readline, readline,,)
AC_ARG_ENABLE(readline,	[  --enable-readline  use readline library],,
			enable_readline="yes")
 
if test "$enable_readline" = "yes" ; then
   LIBREADLINE="-lreadline -lncurses"
   HAVE_LIBREADLINE="-DHAVE_LIBREADLINE=1"
else 
   LIBREADLINE=""
   HAVE_LIBREADLINE=""
fi
AC_SUBST(LIBREADLINE)
AC_SUBST(HAVE_LIBREADLINE)

AC_ARG_ENABLE(efence,  [  --enable-efence  use efence library],,
			enable_efence="no")
 
if test "$enable_efence" = "yes" ; then
   LIBEFENCE="-lefence"
   HAVE_LIBEFENCE="-DHAVE_LIBEFENCE=1"
else 
   LIBEFENCE=""
   HAVE_LIBEFENCE=""
fi
AC_SUBST(LIBEFENCE)
AC_SUBST(HAVE_LIBEFENCE)

# end -------- Kernel build environment. -----------------


