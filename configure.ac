AC_PREREQ([2.57])
AC_INIT([Lustre], m4_esyscmd([sh -c "./LUSTRE-VERSION-GEN | tr -d '\n'"]),
        [https://jira.hpdd.intel.com/], [lustre])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])

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

LUSTRE_VERSION_CPP_MACROS
LB_CONFIGURE
