sinclude(lustre/version.m4)

AC_INIT([Lustre], [LUSTRE_VERSION], [http://bugzilla.lustre.org/], [lustre])

if test "LUSTRE_VERSION" = "LUSTRE""_VERSION" ; then
	cat >&2 <<-EOF
	This script was not built with a version number.

	This is likely due to an incorrect checkout, or a broken
	tarball.

	Please see README.lustrecvs, or contact your Lustre vendor.
	EOF
	exit 1
fi

AC_CONFIG_SRCDIR(lustre/obdclass/obdo.c)
AM_INIT_AUTOMAKE
# AM_MAINTAINER_MODE

sinclude(build/build.ac)
sinclude(portals/portals.ac)
sinclude(lustre/lustre.ac)

AC_CONFIG_HEADERS([config.h])

CPPFLAGS="-include \$(top_builddir)/config.h $CPPFLAGS"
EXTRA_KCFLAGS="-include $PWD/config.h $EXTRA_KCFLAGS"
AC_SUBST(EXTRA_KCFLAGS)

AC_OUTPUT([
Makefile
autoMakefile
])

cat <<EOF

CPPFLAGS: $CPPFLAGS
LLCPPFLAGS: $LLCPPFLAGS
CFLAGS: $CFLAGS
EXTRA_KCFLAGS: $EXTRA_KCFLAGS
LLCFLAGS: $LLCFLAGS

Type 'make' to build Lustre.
EOF
