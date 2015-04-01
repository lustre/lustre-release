AC_PREREQ([2.57])
AC_INIT([Lustre], [LUSTRE_VERSION], [https://jira.hpdd.intel.com/], [lustre])
sinclude(lustre/autoconf/lustre-version.ac)

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])

LB_CHECK_VERSION

LC_CONFIG_SRCDIR

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([1.10 tar-ustar -Wno-portability])
AM_MAINTAINER_MODE([enable])

AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_MKDIR_P
AM_PROG_AS

AC_PATH_PROG(RPMBUILD, rpmbuild)
AC_CHECK_TOOLS(AR, ar)

LB_CONFIGURE
