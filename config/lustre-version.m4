#
# LUSTRE_VERSION_VARIABLES
#
AC_DEFUN([LUSTRE_VERSION_VARIABLES], [

LUSTRE_MAJOR=`echo AC_PACKAGE_VERSION | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\1/']`
LUSTRE_MINOR=`echo AC_PACKAGE_VERSION | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\2/']`
LUSTRE_PATCH=`echo AC_PACKAGE_VERSION | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\3/']`
LUSTRE_FIX=`echo AC_PACKAGE_VERSION | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\5/']`
AS_IF([test -z "$LUSTRE_FIX"], [LUSTRE_FIX="0"])

m4_pattern_allow(AC_LUSTRE)
[AC_LUSTRE_MAJOR]=$LUSTRE_MAJOR
[AC_LUSTRE_MINOR]=$LUSTRE_MINOR
[AC_LUSTRE_PATCH]=$LUSTRE_PATCH
[AC_LUSTRE_FIX]=$LUSTRE_FIX

AC_SUBST([AC_LUSTRE_MAJOR])
AC_SUBST([AC_LUSTRE_MINOR])
AC_SUBST([AC_LUSTRE_PATCH])
AC_SUBST([AC_LUSTRE_FIX])

])
