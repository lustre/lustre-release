AC_INIT
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE(lustre-iokit,1.2)
AC_PATH_PROGS(BASH, bash)
AC_PATH_PROGS(PERL, perl)
RELEASE="`date +%Y%m%d%H%M`"
AC_SUBST(RELEASE)

AC_OUTPUT(
lustre-iokit.spec
Makefile
sgpdd-survey/Makefile
obdfilter-survey/Makefile
ost-survey/Makefile
ior-survey/Makefile
stats-collect/Makefile
)
