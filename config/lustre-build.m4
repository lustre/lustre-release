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
	solaris*)
		lb_target_os="SunOS"
		;;
esac
AC_SUBST(lb_target_os)
])

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

	if test "$ver" != "$VERSION"; then
		AC_MSG_WARN([most recent tag found: $ver does not match current version $VERSION.])
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
	AC_MSG_RESULT([none])
	AC_MSG_WARN([

FIXME: I don't know how to deal with source trees outside of git that
don't have a META file. Not setting a buildid.
])
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

# We have to configure even if we don't build here for make dist to work
AC_CONFIG_SUBDIRS([libsysio])
])

#
# LB_PATH_LUSTREIOKIT
#
# We no longer handle external lustre-iokit
#
AC_DEFUN([LB_PATH_LUSTREIOKIT],
[AC_ARG_ENABLE([iokit],
	AC_HELP_STRING([--disable-iokit],
		[disable iokit (default is enable)]),
	[],[
		enable_iokit='yes'
	])
AC_MSG_CHECKING([whether to build iokit])
AC_MSG_RESULT([$enable_iokit])
AS_IF([test "x$enable_iokit" = xyes], [LUSTREIOKIT_SUBDIR="lustre-iokit"], [LUSTREIOKIT_SUBDIR=""])[]dnl
AC_SUBST(LUSTREIOKIT_SUBDIR)
AM_CONDITIONAL(BUILD_LUSTREIOKIT, [test "x$enable_iokit" = xyes])
])

# Define no libcfs by default.
AC_DEFUN([LB_LIBCFS_DIR],
[
case x$libcfs_is_module in
	xyes)
          LIBCFS_INCLUDE_DIR="libcfs/include"
          LIBCFS_SUBDIR="libcfs"
          ;;
        x*)
          LIBCFS_INCLUDE_DIR="lnet/include"
          LIBCFS_SUBDIR=""
          ;;
esac
AC_SUBST(LIBCFS_SUBDIR)
AC_SUBST(LIBCFS_INCLUDE_DIR)
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
			LIBCFS_PROG_LINUX
			LN_PROG_LINUX
			if test x$enable_server != xno; then
				LB_EXT4_SRC_DIR
			fi
			LC_PROG_LINUX
			;;
		darwin*)
			LB_PROG_DARWIN
			LIBCFS_PROG_DARWIN
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
# LB_CONFIG_DIST
#
# Just enough configure so that "make dist" is useful
#
# this simply re-adjusts some defaults, which of course can be overridden
# on the configure line after the --for-dist option
#
AC_DEFUN([LB_CONFIG_DIST],
[AC_MSG_CHECKING([whether to configure just enough for make dist])
AC_ARG_ENABLE([dist],
	AC_HELP_STRING([--enable-dist],
			[only configure enough for make dist]),
	[enable_dist='yes'],[enable_dist='no'])
AC_MSG_RESULT([$enable_dist])
if test x$enable_dist != xno; then
	enable_modules='no'
	enable_utils='no'
        enable_liblustre='no'
        enable_doc='no'
        enable_tests='no'
fi
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
# LB_PATH_DEFAULTS
#
# 'fixup' default paths
#
AC_DEFUN([LB_PATH_DEFAULTS],
[# directories for binaries
AC_PREFIX_DEFAULT([/usr])

sysconfdir='$(CROSS_PATH)/etc'
AC_SUBST(sysconfdir)

# Directories for documentation and demos.
docdir='$(datadir)/doc/$(PACKAGE)'
AC_SUBST(docdir)

LIBCFS_PATH_DEFAULTS
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
AC_CHECK_TOOL(LD, ld, [no])
AC_CHECK_TOOL(OBJDUMP, objdump, [no])
AC_CHECK_TOOL(STRIP, strip, [no])

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

CPPFLAGS="-I$PWD/$LIBCFS_INCLUDE_DIR -I$PWD/lnet/include -I$PWD/lustre/include $CPPFLAGS"

LLCPPFLAGS="-D__arch_lib__ -D_LARGEFILE64_SOURCE=1"
AC_SUBST(LLCPPFLAGS)

# Add _GNU_SOURCE for strnlen on linux
LLCFLAGS="-g -Wall -fPIC -D_GNU_SOURCE"
AC_SUBST(LLCFLAGS)

CCASFLAGS="-Wall -fPIC -D_GNU_SOURCE"
AC_SUBST(CCASFLAGS)

# everyone builds against lnet and lustre
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -g -I$PWD/$LIBCFS_INCLUDE_DIR -I$PWD/lnet/include -I$PWD/lustre/include"
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
AM_CONDITIONAL(SUNOS, test x$lb_target_os = "xSunOS")
AM_CONDITIONAL(USES_DPKG, test x$uses_dpkg = "xyes")
AM_CONDITIONAL([USE_QUILT], [test x$use_quilt = xyes])

# Sanity check for PCLMULQDQ instruction availability
# PCLMULQDQ instruction is a new instruction available beginning with
# the all new Core processor family based on the 32nm microarchitecture
# codename Westmere. So, $target_cpu = x86_64 should have this instruction
# except MIC microarchitecture (k1om).
AM_CONDITIONAL(HAVE_PCLMULQDQ, test x$target_cpu = "xx86_64" -a x$target_vendor != "xk1om")
if test x$target_cpu = "xx86_64" -a x$target_vendor != "xk1om" ; then
	AC_DEFINE(HAVE_PCLMULQDQ, 1, [have PCLMULQDQ instruction])
fi

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

LB_DARWIN_CONDITIONALS

LIBCFS_CONDITIONALS
LN_CONDITIONALS
LC_CONDITIONALS
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
		config/Makefile
		[Rules:build/Rules.in]
		AC_PACKAGE_TARNAME[.spec]
		AC_PACKAGE_TARNAME[-dkms.spec]
		contrib/Makefile
		contrib/lbuild/Makefile
		contrib/scripts/Makefile
		ldiskfs/Makefile
		ldiskfs/autoMakefile
		lustre-iokit/Makefile
		lustre-iokit/obdfilter-survey/Makefile
		lustre-iokit/ost-survey/Makefile
		lustre-iokit/sgpdd-survey/Makefile
		lustre-iokit/mds-survey/Makefile
		lustre-iokit/ior-survey/Makefile
		lustre-iokit/stats-collect/Makefile
	)
])

#
# LB_CONFIG_SERVERS
#
AC_DEFUN([LB_CONFIG_SERVERS],
[
AC_ARG_ENABLE([server],
	AC_HELP_STRING([--disable-server],
			[disable Lustre server support]),
	[AS_IF([test x$enable_server != xyes -a x$enable_server != xno],
		[AC_MSG_ERROR([server valid options are "yes" or "no"])])
	AS_IF([test x$enable_server = xyes -a x$enable_dist = xyes],
		[AC_MSG_ERROR([--enable-server cannot be used with --enable-dist])])
	],
	[AS_IF([test x$enable_dist = xyes],
		     [enable_server=no],
		     [enable_server=maybe])
	]
)

# There are at least two good reasons why we should really run
# LB_CONFIG_MODULES elsewhere before the call to LB_CONFIG_SERVERS:
# LB_CONFIG_MODULES needs to be run for client support even when
# servers are disabled, and because module support is actually a
# prerequisite of server support.  However, some things under
# LB_CONFIG_MODULES need us to already have checked for --disable-server,
# before running, so until LB_CONFIG_MODULES can be reorganized, we
# call it here.
LB_CONFIG_MODULES
AS_IF([test x$enable_modules = xno],[enable_server=no])
LB_CONFIG_LDISKFS
LB_CONFIG_ZFS

# If no backends were configured, and the user did not explicitly
# require servers to be enabled, we just disable servers.
AS_IF([test x$enable_ldiskfs = xno -a x$enable_zfs = xno],
	[AS_CASE([$enable_server],
		[maybe], [enable_server=no],
		[yes], [AC_MSG_ERROR([cannot enable servers, no backends were configured])])
	],
	[AS_IF([test x$enable_server = xmaybe], [enable_server=yes])]
)

AC_MSG_CHECKING([whether to build Lustre server support])
AC_MSG_RESULT([$enable_server])
AS_IF([test x$enable_server = xyes],
	[AC_DEFINE(HAVE_SERVER_SUPPORT, 1, [support server])]
)
])


#
# LB_CONFIG_RPMBUILD_OPTIONS
#
# The purpose of this function is to assemble command line options
# for the rpmbuild command based on the options passed to the configure
# script, and also upon the descisions that configure makes based on
# the tests that it runs.
# These strings can be passed to rpmbuild on the command line
# in the Make targets named "rpms" and "srpm".
#
AC_DEFUN([LB_CONFIG_RPMBUILD_OPTIONS],[
	RPMBINARGS=
	RPMSRCARGS=
	CONFIGURE_ARGS=
	eval set -- $ac_configure_args
	for arg; do
		case $arg in
			--with-release=* ) ;;
			--with-kmp-moddir=* ) ;;
			--with-linux=* | --with-linux-obj=* ) ;;
			--enable-tests | --disable-tests ) ;;
			--enable-modules | --disable-modules ) ;;
			* ) CONFIGURE_ARGS="$CONFIGURE_ARGS '$arg'" ;;
		esac
	done
	if test -n "$CONFIGURE_ARGS" ; then
		RPMBINARGS="$RPMBINARGS --define \"configure_args $CONFIGURE_ARGS\""
	fi
	if test -n "$LINUX" ; then
		RPMBINARGS="$RPMBINARGS --define \"kdir $LINUX\""
		if test -n "$LINUX_OBJ" -a "$LINUX_OBJ" != x"$LINUX" ; then
			RPMBINARGS="$RPMBINARGS --define \"kobjdir $LINUX_OBJ\""
		fi
	fi
	if test -n "$KMP_MODDIR" ; then
		RPMBINARGS="$RPMBINARGS --define \"kmoddir $KMP_MODDIR\""
	fi
	if test -n "$CROSS_PATH" ; then
		if test x$enable_server = xyes ; then
			echo -e "\n"
			"*** Don't support cross compilation for the Intel(R) Xeon Phi(TM) card.\n"
			exit 1
		fi
		CROSS_SUFFIX="-mic"
		RPMBINARGS="$RPMBINARGS --define \"post_script build/gen_filelist.sh\""
		RPMBINARGS="$RPMBINARGS --define \"cross_path $CROSS_PATH\""
		RPMBINARGS="$RPMBINARGS --define \"rootdir %{cross_path}\""
		RPMBINARGS="$RPMBINARGS --define \"_prefix %{cross_path}/usr\""
		RPMBINARGS="$RPMBINARGS --define \"_mandir %{_prefix}/share/man\""
		RPMBINARGS="$RPMBINARGS --define \"_sysconfdir %{cross_path}/etc\""
		RPMBINARGS="$RPMBINARGS --define \"make_args $CROSS_VARS\""
		if test x$CC_TARGET_ARCH = x"x86_64-k1om-linux" ; then
			RPMBINARGS="$RPMBINARGS --define \"cross_requires intel-mic-gpl\""
		fi
	fi
	if test x$enable_modules != xyes ; then
		RPMBINARGS="$RPMBINARGS --without lustre_modules"
	fi
	if test x$enable_tests != xyes ; then
		RPMBINARGS="$RPMBINARGS --without lustre_tests"
		RPMSRCARGS="$RPMSRCARGS --without lustre_tests"
	fi
	if test x$enable_server != xyes ; then
		RPMBINARGS="$RPMBINARGS --without servers"
		if test -n "$CROSS_SUFFIX" ; then
			RPMBINARGS="$RPMBINARGS --define \"lustre_name lustre-client$CROSS_SUFFIX\""
		fi
	fi
	if test x$enable_ldiskfs != xyes ; then
		RPMBINARGS="$RPMBINARGS --without ldiskfs"
	fi
	if test x$enable_zfs = xyes ; then
		RPMBINARGS="$RPMBINARGS --with zfs"
	fi
	if test x$enable_iokit != xyes ; then
		RPMBINARGS="$RPMBINARGS --without lustre_iokit"
		RPMSRCARGS="$RPMSRCARGS --without lustre_iokit"
	fi

	RPMBUILD_BINARY_ARGS=$RPMBINARGS
	RPMBUILD_SOURCE_ARGS=$RPMSRCARGS

	AC_SUBST(RPMBUILD_BINARY_ARGS)
	AC_SUBST(RPMBUILD_SOURCE_ARGS)
])

#
# LB_CONFIGURE
#
# main configure steps
#
AC_DEFUN([LB_CONFIGURE],
[LB_CANONICAL_SYSTEM

LB_CONFIG_DIST

LB_DOWNSTREAM_RELEASE
LB_USES_DPKG
LB_BUILDID

LB_LIBCFS_DIR

LB_INCLUDE_RULES

LB_PATH_DEFAULTS

LB_PROG_CC

LC_OSD_ADDON

LB_CONFIG_DOCS
LB_CONFIG_UTILS
LB_CONFIG_TESTS
LC_CONFIG_CLIENT
LB_CONFIG_SERVERS

# two macros for cmd3
m4_ifdef([LC_CONFIG_SPLIT], [LC_CONFIG_SPLIT])
m4_ifdef([LC_NODEMAP_PROC_DEBUG], [LC_NODEMAP_PROC_DEBUG])
LN_CONFIG_CDEBUG
LC_QUOTA

LN_CONFIG_USERSPACE

LB_PATH_LIBSYSIO
LB_PATH_SNMP
LB_PATH_LUSTREIOKIT

LB_DEFINE_E2FSPROGS_NAMES

LC_CONFIG_LIBLUSTRE
LIBCFS_CONFIGURE
LN_CONFIGURE

LC_CONFIGURE

if test "$SNMP_DIST_SUBDIR" ; then
	LS_CONFIGURE
fi


LB_CONDITIONALS
LB_CONFIG_HEADERS

LIBCFS_CONFIG_FILES
LB_CONFIG_FILES
LN_CONFIG_FILES
LC_CONFIG_FILES
if test "$SNMP_DIST_SUBDIR" ; then
	LS_CONFIG_FILES
fi

AC_SUBST(ac_configure_args)

MOSTLYCLEANFILES='.*.cmd .*.flags *.o *.ko *.mod.c .depend .*.1.* Modules.symvers Module.symvers'
AC_SUBST(MOSTLYCLEANFILES)

LB_CONFIG_RPMBUILD_OPTIONS

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
