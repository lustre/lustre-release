# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# config/lustre-compiler-plugins.m4
#
# Configure compliler plugin settings
#

#
# LPLUG_ENABLE
#
# Simple flag to enable compiler plugins.
#
AC_DEFUN([LPLUG_ENABLE], [
AC_ARG_ENABLE([compiler-plugins],
    AS_HELP_STRING([--enable-compiler-plugins], [Enable compiler plugins]))

AS_IF([test "x$enable_compiler_plugins" == "xyes"], [
CFLAGS="$CFLAGS -fplugin=$(pwd)/cc-plugins/.libs/libfindstatic.so"
], [])
AM_CONDITIONAL([CC_PLUGINS], [test x$enable_compiler_plugins = xyes])
]) # LPLUG_ENABLE

#
# LPLUG_CONFIGURE
#
# main configure steps
#
AC_DEFUN([LPLUG_CONFIGURE], [
LPLUG_ENABLE
]) # LPLUG_CONFIGURE

#
# LPLUG_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LPLUG_CONFIG_FILES], [
	AC_CONFIG_FILES([
		cc-plugins/Makefile
	])
]) # LPLUG_CONFIG_FILES
