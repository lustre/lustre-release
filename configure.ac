# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# configure.ac
#
# Used by autoconf to create the configure script
#

AC_PREREQ([2.57])
AC_INIT([Lustre], m4_esyscmd_s([./LUSTRE-VERSION-GEN]),
	[https://jira.whamcloud.com/], [lustre])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])

LC_CONFIG_SRCDIR

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([1.10 tar-pax -Wno-portability subdir-objects])
AM_MAINTAINER_MODE([enable])

LTC_TOOLCHAIN_CONFIGURE
LT_INIT
AC_PROG_MKDIR_P

AC_PATH_PROG(FLEX, flex)
AC_PATH_PROG(BISON, bison)
AC_PATH_PROG(RPMBUILD, rpmbuild)
AC_PATH_PROG(PKGCONF, pkg-config)

LUSTRE_VERSION_CPP_MACROS
LB_CONFIGURE
LTC_TOOLCHAIN_STATUS
