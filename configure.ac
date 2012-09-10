
AC_INIT([Lustre], [LUSTRE_VERSION], [http://bugs.whamcloud.com/], [lustre])
sinclude(lustre/autoconf/lustre-version.ac)

# Overridden in LB_PATH_LDISKFS on certain branches
AM_CONDITIONAL(LDISKFS_ENABLED, false)

LB_CHECK_VERSION

LC_CONFIG_SRCDIR

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([1.9 tar-ustar])
# AM_MAINTAINER_MODE

AC_PROG_CC

AM_PROG_AS

AC_CHECK_TOOLS(AR, ar)

LB_CONFIGURE
