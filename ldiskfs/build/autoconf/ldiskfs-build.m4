#
# LB_DOWNSTREAM_RELEASE
#
AC_DEFUN([LB_DOWNSTREAM_RELEASE],
[AC_ARG_WITH([downstream-release],
	AC_HELP_STRING([--with-downstream-release=string],
		       [set a string in the BUILD_VERSION and RPM Release: (default is nothing)]),
	[DOWNSTREAM_RELEASE=$with_downstream_release],
	[
	# if not specified, see if it's in the META file
	if test -f META; then
		DOWNSTREAM_RELEASE=$(sed -ne '/^LOCAL_VERSION =/s/.*= *//p' META)
	fi
	])
AC_SUBST(DOWNSTREAM_RELEASE)
])

#
# LB_BUILDID
#
# Check if the source is a GA release and if not, set a "BUILDID"
#
# Currently there are at least two ways/modes of/for doing this.  One
# is if we are in a valid git repository, the other is if we are in a
# non-git source tree of some form.  Building the latter from the former
# will be handled here.
AC_DEFUN([LB_BUILDID],
[
AC_MSG_CHECKING([for buildid])
BUILDID=""
if git branch >/dev/null 2>&1; then
	ffw=0
	hash=""
	ver=$(git describe --match v[[0-9]]_*_[[0-9]]* --tags)
	if [[[ $ver = *-*-* ]]]; then
		hash=${ver##*-}
		ffw=${ver#*-}
		ffw=${ffw%-*}
		ver=${ver%%-*}
	fi
	# it's tempting to use [[ $ver =~ ^v([0-9]+_)+([0-9]+|RC[0-9]+)$ ]]
	# here but the portability of the regex on the right is dismal
	# (thanx suse)
	if echo "$ver" | egrep -q "^v([[0-9]]+_)+([[0-9]]+|RC[[0-9]]+)$"; then
		ver=$(echo $ver | sed -e 's/^v\(.*\)/\1/' \
				      -e 's/_RC[[0-9]].*$//' -e 's/_/./g')
	fi

	# a "lustre fix" value of .0 should be truncated
	if [[[ $ver = *.*.*.0 ]]]; then
		ver=${ver%.0}
	fi
	# ditto for a "lustre fix" value of _0
	if [[[ $ver = v*_*_*_0 ]]]; then
		ver=${ver%_0}
	fi
	if [[[ $ver = v*_*_* ]]]; then
		ver=${ver#v}
		ver=${ver//_/.}
	fi

	if test "$ffw" != "0"; then
		BUILDID="$hash"
		msg="$BUILDID (ahead by $ffw commits)"
		AC_MSG_RESULT([$msg])
	else
		AC_MSG_RESULT([none... congratulations, you must be on a tag])
	fi
elif test -f META; then
	BUILDID=$(sed -ne '/^BUILDID =/s/.*= *//p' META)
	msg="$BUILDID (from META file)"
	AC_MSG_RESULT([$msg])
else
	AC_MSG_WARN([FIXME: I don't know how to deal with source trees outside of git that don't have a META file.  Not setting a buildid.])
fi
AC_SUBST(BUILDID)
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
# LB_CONFIG_HEADERS
#
# add -include config.h
#
AC_DEFUN([LB_CONFIG_HEADERS],[
	AC_CONFIG_HEADERS([config.h])
	CPPFLAGS="-include $PWD/config.h $CPPFLAGS"
	EXTRA_KCFLAGS="-include $PWD/config.h $EXTRA_KCFLAGS"
	AC_SUBST(EXTRA_KCFLAGS)
])

#
# LB_INCLUDE_RULES
#
# defines for including the toplevel Rules
#
AC_DEFUN([LB_INCLUDE_RULES],[
	INCLUDE_RULES="include $PWD/Rules"
	AC_SUBST(INCLUDE_RULES)
])

#
# LB_PROG_CC
#
# checks on the C compiler
#
AC_DEFUN([LB_PROG_CC],
[AC_PROG_RANLIB

# ---------  unsigned long long sane? -------
AC_CHECK_SIZEOF(unsigned long long, 0)
echo "---> size SIZEOF $SIZEOF_unsigned_long_long"
echo "---> size SIZEOF $ac_cv_sizeof_unsigned_long_long"
if test $ac_cv_sizeof_unsigned_long_long != 8 ; then
	AC_MSG_ERROR([** we assume that sizeof(long long) == 8.])
fi

if test $target_cpu == "powerpc64"; then
	AC_MSG_WARN([set compiler with -m64])
	CFLAGS="$CFLAGS -m64"
	CC="$CC -m64"
fi

LLCPPFLAGS="-D__arch_lib__ -D_LARGEFILE64_SOURCE=1"
AC_SUBST(LLCPPFLAGS)

# Add _GNU_SOURCE for strnlen on linux
LLCFLAGS="-g -Wall -fPIC -D_GNU_SOURCE"
AC_SUBST(LLCFLAGS)

CCASFLAGS="-Wall -fPIC -D_GNU_SOURCE"
AC_SUBST(CCASFLAGS)
])

#
# LB_CONFIG_FILES
#
# build-specific config files
#
AC_DEFUN([LB_CONFIG_FILES],
[
	AC_CONFIG_FILES([
		Makefile
		autoMakefile]
		[Rules:build/Rules.in]
		AC_PACKAGE_TARNAME[.spec]
	)
])
