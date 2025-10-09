dnl Use plain C version of ISA-L erasure code
AC_DEFUN([EC_ISA_L_SUPPORT],[
  isa_l_library="../../erasurecode/libec.a"

  AC_SUBST([ISA_L_LIBRARY], $isa_l_library)
])

#
# EC_CONFIGURE
#
# other configure checks
#
AC_DEFUN([EC_CONFIGURE], [
AC_MSG_NOTICE([Erasurecode core checks
==============================================================================])
EC_ISA_L_SUPPORT
]) # EC_CONFIGURE

#
# EC_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([EC_CONFIG_FILES], [
AC_CONFIG_FILES([
lustre/utils/erasurecode/Makefile
lustre/utils/erasurecode/autoMakefile
lustre/ec/Makefile
lustre/ec/autoMakefile
])
]) # EC_CONFIG_FILES
