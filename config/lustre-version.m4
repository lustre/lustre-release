# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# config/lustre-version.m4
#
# Defines variables for Lustre version number
#

#
# LUSTRE_VERSION_CPP_MACROS
#
AC_DEFUN([LUSTRE_VERSION_CPP_MACROS], [
LUSTRE_MAJOR=`echo AC_PACKAGE_VERSION | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\1/']`
LUSTRE_MINOR=`echo AC_PACKAGE_VERSION | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\2/']`
LUSTRE_PATCH=`echo AC_PACKAGE_VERSION | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\3/']`
LUSTRE_FIX=`echo AC_PACKAGE_VERSION | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)([-\._][a-z]*([0-9]+))?.*/\5/']`
AS_IF([test -z "$LUSTRE_FIX"], [LUSTRE_FIX="0"])

AC_DEFINE_UNQUOTED([LUSTRE_MAJOR], [$LUSTRE_MAJOR], [First number in the Lustre version])
AC_DEFINE_UNQUOTED([LUSTRE_MINOR], [$LUSTRE_MINOR], [Second number in the Lustre version])
AC_DEFINE_UNQUOTED([LUSTRE_PATCH], [$LUSTRE_PATCH], [Third number in the Lustre version])
AC_DEFINE_UNQUOTED([LUSTRE_FIX], [$LUSTRE_FIX], [Fourth number in the Lustre version])
# Even though the code could just use VERSION or PACKAGE_VERSION directly,
# we use this copy named LUSTRE_VERSION_STRING instead to maintain less
# divergence from the Lustre client code in the upstream Linux kernel code.
AC_DEFINE_UNQUOTED([LUSTRE_VERSION_STRING], ["$PACKAGE_VERSION"], [A copy of PACKAGE_VERSION])

# Enable only for version before 2.20.53
AS_IF([test "$LUSTRE_MAJOR" -lt 2 ||
       (test "$LUSTRE_MAJOR" -eq 2 && test "$LUSTRE_MINOR" -lt 20) ||
       (test "$LUSTRE_MAJOR" -eq 2 && test "$LUSTRE_MINOR" -eq 20 &&
        test "$LUSTRE_PATCH" -lt 53)],
      [ENABLE_LFS_MIGRATE=yes])

AM_CONDITIONAL([ENABLE_LFS_MIGRATE], [test "x$ENABLE_LFS_MIGRATE" = "xyes"])

]) # LUSTRE_VERSION_CPP_MACROS
