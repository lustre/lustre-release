#
# LS_CONFIGURE
#
# configure bits for lustre-snmp
#
AC_DEFUN([LS_CONFIGURE], [
AC_MSG_CHECKING([whether to try to build SNMP support])
AC_ARG_ENABLE([snmp],
	AC_HELP_STRING([--enable-snmp],
		[require SNMP support (default=auto)]),
	[], [enable_snmp="auto"])
AC_MSG_RESULT([$enable_snmp])

if test x$enable_snmp != xno ; then
	AC_CHECK_PROG([NET_SNMP_CONFIG], [net-snmp-config], [net-snmp-config])
	if test "$NET_SNMP_CONFIG" ; then
		NET_SNMP_CFLAGS=$($NET_SNMP_CONFIG --base-cflags)
		NET_SNMP_LIBS=$($NET_SNMP_CONFIG --agent-libs)

		CPPFLAGS_save="$CPPFLAGS"
		CPPFLAGS="$CPPFLAGS $NET_SNMP_CFLAGS"

		LIBS_save="$LIBS"
		LIBS="$LIBS $NET_SNMP_LIBS"

		AC_CHECK_HEADER([net-snmp/net-snmp-config.h],[
			AC_CHECK_FUNC([register_mib],[SNMP_SUBDIR="snmp"],[
				LIBS="$LIBS -lwrap"
				NET_SNMP_LISB="$NET_SNMP_LIBS -lwrap"
				# fail autoconf's cache
				unset ac_cv_func_register_mib
				AC_CHECK_FUNC([register_mib],[SNMP_SUBDIR="snmp"])
			])
		])

		LIBS="$LIBS_save"
		CPPFLAGS="$CPPFLAGS_save"
	fi
	AC_MSG_CHECKING([for SNMP support])
	if test "$SNMP_SUBDIR" ; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no (see config.log for errors)])
		if test x$enable_snmp = xyes ; then
			AC_MSG_ERROR([SNMP support was requested, but unavailable])
		fi
	fi
fi

agentdir='${pkglibdir}/snmp'
mibdir='${pkgdatadir}/snmp/mibs'

AC_SUBST(NET_SNMP_CFLAGS)
AC_SUBST(NET_SNMP_LIBS)
AC_SUBST(agentdir)
AC_SUBST(mibdir)
]) # LS_CONFIGURE

#
# LS_CONFIG_FILE
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LS_CONFIG_FILES], [
AC_CONFIG_FILES([
snmp/Makefile
snmp/autoconf/Makefile
])
]) # LS_CONFIG_FILES
