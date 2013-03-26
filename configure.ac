AC_PREREQ([2.57])
AC_INIT([Lustre], [LUSTRE_VERSION], [http://bugs.whamcloud.com/], [lustre])
sinclude(lustre/autoconf/lustre-version.ac)

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])

# Overridden by --without-ldiskfs/--with-zfs configure options
AM_CONDITIONAL(LDISKFS_ENABLED, true)
AM_CONDITIONAL(ZFS_ENABLED, false)

LB_CHECK_VERSION

LC_CONFIG_SRCDIR

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([1.10 tar-ustar -Wno-portability])
AM_MAINTAINER_MODE([enable])

AC_PROG_CC

AM_PROG_AS

AC_CHECK_TOOLS(AR, ar)

LB_CONFIGURE
