dnl Process this file with autoconf to produce a configure script.
AC_INIT([quilt],[0.24],[quilt-dev@nongnu.org])
AC_CONFIG_AUX_DIR(config)
AC_PREREQ(2.53)
AC_REVISION ($Revision: 1.1.2.1 $)

PACKAGE_RELEASE=1
AC_SUBST(PACKAGE_RELEASE)

dnl Setup for backup-files compilation
AC_HEADER_STDC
AC_CHECK_FUNCS([mkdir])
AC_CHECK_FUNCS([rmdir])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strrchr])
AC_C_CONST
AC_FUNC_STAT

AC_PROG_INSTALL

AC_SYS_INTERPRETER
if test "$interpval" != yes ; then
	AC_MSG_WARN([no

bash/perl scripts may not be invoked correctly due to problems with your 
systems implementation of #! being either broken or non-existant.
])
fi

dnl Check for Bourne-Again Shell
AC_ARG_WITH(bash, AC_HELP_STRING(
    [--with-bash], [name of the bash executable to use]),
    [
	BASH="$withval"
	AC_SUBST(BASH)
	AC_MSG_NOTICE([Using bash executable $BASH])
    ],[
	AC_PATH_PROG(BASH, bash)
    ])
if test -z "$BASH" ; then
    AC_MSG_ERROR([Please specify the location of bash with the option '--with-bash'])
fi

# It would be nice not to have to use backticks, but too many retarded sh
# implementations still don't support $( )
# BEWARE:  There is a distinct possibility that we are currently running under
# bash in this configure script (/bin/sh being a symlink to /bin/bash).  Even
# though the result /could/ be available to us directly as $BASH_VERSION we
# don't want to use, or trust it, incase the user is specifying a different
# bash executable.
if `$BASH -c '[[ "$BASH_VERSION" \< "2.04" ]]'` ; then
    AC_MSG_ERROR([
$PACKAGE_NAME requires at least version 2.04 of bash, you can download a current
version of bash from ftp.gnu.org
])
fi

dnl Check for Perl
AC_ARG_WITH(perl, AC_HELP_STRING(
    [--with-perl], [name of the Perl executable to use]),
    [
	PERL="$withval"
	AC_SUBST(PERL)
	AC_MSG_NOTICE([Using Perl executable $PERL])
    ],[
	AC_PATH_PROGS(PERL, [perl perl5])
    ])
if test -z "$PERL" ; then
    AC_MSG_ERROR([Please specify the location of Perl with the option '--with-perl'])
fi

dnl Check for sed
AC_ARG_WITH(sed, AC_HELP_STRING(
    [--with-sed], [name of the sed executable to use]),
    [
	SED="$withval"
	AC_SUBST(SED)
	AC_MSG_NOTICE([Using sed executable $SED])
    ],[
	SED="sed"
	AC_SUBST(SED)
    ])

dnl Check for awk
AC_ARG_WITH(awk, AC_HELP_STRING(
    [--with-awk], [name of the awk executable to use]),
    [
	AWK="$withval"
	AC_SUBST(AWK)
	AC_MSG_NOTICE([Using awk executable $AWK])
    ],[
	AC_PATH_PROGS(AWK, [gawk awk])
    ])

dnl Test for awk features that may be mising?

if test -z "$PERL" ; then
    AC_MSG_ERROR([Please specify the location of Perl with the option '--with-perl'])
fi

dnl Checks for mktemp (for creating temporary files and directories)
AC_ARG_WITH(mktemp, AC_HELP_STRING(
    [--with-mktemp], [name of the mktemp executable to use (or 'none'
		      to use a quilt internal mechanism)]),
    [
	MKTEMP="$withval"
	AC_SUBST(MKTEMP)
	AC_MSG_NOTICE([Using mktemp executable $MKTEMP])
    ],[
	AC_PATH_PROG(MKTEMP, mktemp)
    ])
if test -z "$MKTEMP" -o "$MKTEMP" = "none" ; then
    MKTEMP=internal_mktemp
else
    AC_MSG_CHECKING(whether $MKTEMP -d works)
    if tempdir=`$MKTEMP -d /tmp/$PACKAGE_NAME.XXXXXX 2>/dev/null` && \
       rmdir "$tempdir" ; then
	AC_MSG_RESULT(yes)
    else
	AC_MSG_RESULT(no)
	AC_MSG_ERROR([
'$MKTEMP -d' does not create temporary directories.
If you don't have a version of mktemp that can create directories, you
can specify '--with-mktemp=none' and $PACKAGE_NAME will use its own
internal tempfile generation mechanism.
])
    fi
fi

dnl Check for diff
AC_ARG_WITH(diff, AC_HELP_STRING(
    [--with-diff], [name of the diff executable to use]),
    [
	DIFF="$withval"
	AC_SUBST(DIFF)
	AC_MSG_NOTICE([Using diff executable $DIFF])
    ],[
	AC_PATH_PROG(DIFF, diff)
    ])
if test -z "$DIFF"; then
    AC_MSG_ERROR([Please specify the location of diff with the option '--with-diff'])
fi

dnl Check for patch
AC_ARG_WITH(patch, AC_HELP_STRING(
    [--with-patch], [name of the patch executable to use]),
    [
	PATCH="$withval"
	AC_SUBST(PATCH)
	AC_MSG_NOTICE([Using patch executable $PATCH])
    ],[
	AC_PATH_PROG(PATCH, patch)
    ])
if test -z "$PATCH"; then
    AC_MSG_ERROR([Please specify the location of patch with the option '--with-patch'])
fi

# Sun's patch is a mess, issue a warning.  But we are going to continue with
# the build because you might just be lucky.
AC_MSG_CHECKING([whether $PATCH will work])
if $PATCH -v 2>&1 | grep -q "Sun" >/dev/null 2>&1; then
	AC_MSG_RESULT(no)
	AC_MSG_WARN([
Sorry, you have a Sun version of patch which is notoriously buggy.  $PACKAGE_NAME
may function correctly, or minor errors may occur due to Sun's patch tool.
Please consider upgrading to GNU patch, if you already have GNU patch then you
can supply its path with the '--with-patch=' option.
])
elif $PATCH --version 2>&1 | grep -q "patch 2.0" >/dev/null 2>&1; then
	AC_MSG_RESULT(no)
	AC_MSG_WARN([
Sorry, the version of patch you are using can cause severe problems when a patch
creates a directory.  $PACKAGE_NAME may well function correctly with this version
of patch or small problems could creep in.
Please consider upgrading your patch to a more recent version, if you already 
have a more recent version of patch then you can supply its path with the 
'--with-patch=' option.
])
else
	AC_MSG_RESULT(yes)
fi

dnl Check for diffstat
AC_ARG_WITH(diffstat, AC_HELP_STRING(
    [--with-diffstat], [name of the diffstat executable to use]),
    [
	DIFFSTAT="$withval"
	AC_SUBST(DIFFSTAT)
	AC_MSG_NOTICE([Using diffstat executable $DIFFSTAT])
    ],[
	AC_PATH_PROG(DIFFSTAT, diffstat)
    ])
if test -z "$DIFFSTAT"; then
    AC_MSG_WARN([
diffstat does not appear to be in your path, this is not a fatal error however
$PACKAGE_NAME has increased functionality if diffstat exists.  If you have diffstat
you can specify the location the option '--with-diffstat'.
])
fi

dnl Check for NLS
AC_ARG_ENABLE(nls, AC_HELP_STRING(
    [--enable-nls], [include natural language support]))
if test "$enableval" != "no"; then
    AC_PATH_PROG(MSGFMT, msgfmt)
fi
if test "$enableval" = "yes" -a -z "$MSGFMT" ; then
    AC_MSG_ERROR([
You do not appear to have msgfmt, which is part of the GNU Gettext package.  It
is a required package as you chose the '--enable-nls' option to configure.
You can download GNU Gettext from ftp.gnu.org
])
fi
if test -z "$MSGFMT" ; then
    AC_MSG_NOTICE([Building without natural language support])
fi

AC_CONFIG_FILES(Makefile)
AC_OUTPUT

dnl Print results
AC_MSG_RESULT([])
AC_MSG_RESULT([$PACKAGE_NAME version $PACKAGE_VERSION configured.])
AC_MSG_RESULT([])
AC_MSG_RESULT([Using '$prefix' for installation prefix.])

# we don't need to see this just for the backup-files command
# but we may as well spec it for the future
#AC_MSG_RESULT([Using '$CC' for C compiler.])
#AC_MSG_RESULT([Building with '$CFLAGS' for C compiler flags.])
#AC_MSG_RESULT([Building with '$LIBS' for linker flags.])

AC_MSG_RESULT([])
AC_MSG_RESULT([Report bugs to $PACKAGE_BUGREPORT])
