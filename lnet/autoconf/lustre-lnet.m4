#
# LP_CONFIG_ZEROCOPY
#
# check if zerocopy is available/wanted
#
AC_DEFUN([LP_CONFIG_ZEROCOPY],
[AC_MSG_CHECKING([for zero-copy TCP support])
AC_ARG_ENABLE([zerocopy],
	AC_HELP_STRING([--disable-zerocopy],
		       [disable socknal zerocopy]),
	[],[enable_zerocopy='yes'])
if test x$enable_zerocopy = xno ; then
	AC_MSG_RESULT([no (by request)])
else
	ZCCD="`grep -c zccd $LINUX/include/linux/skbuff.h`"
	if test "$ZCCD" != 0 ; then
		AC_DEFINE(SOCKNAL_ZC, 1, [use zero-copy TCP])
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT([no (no kernel support)])
	fi
fi
])

#
# LP_CONFIG_AFFINITY
#
# check if cpu affinity is available/wanted
#
AC_DEFUN([LP_CONFIG_AFFINITY],
[AC_ARG_ENABLE([affinity],
	AC_HELP_STRING([--disable-affinity],
		       [disable process/irq affinity]),
	[],[enable_affinity='yes'])

AC_MSG_CHECKING([for CPU affinity support])
if test x$enable_affinity = xno ; then
	AC_MSG_RESULT([no (by request)])
else
	LB_LINUX_TRY_COMPILE([
		#include <linux/sched.h>
	],[
		struct task_struct t;
		#ifdef CPU_ARRAY_SIZE
		cpumask_t m;
		#else
		unsigned long m;
		#endif
		set_cpus_allowed(&t, m);
	],[
		AC_DEFINE(CPU_AFFINITY, 1, [kernel has cpu affinity support])
		AC_MSG_RESULT([yes])
	],[
		AC_MSG_RESULT([no (no kernel support)])
	])
fi
])

#
# LP_CONFIG_QUADRICS
#
# check if quadrics support is in this kernel
#
AC_DEFUN([LP_CONFIG_QUADRICS],
[AC_MSG_CHECKING([if quadrics kernel headers are present])
if test -d $LINUX/drivers/net/qsnet ; then
	AC_MSG_RESULT([yes])
	QSWNAL="qswnal"
	AC_MSG_CHECKING([for multirail EKC])
	if test -f $LINUX/include/elan/epcomms.h; then
		AC_MSG_RESULT([supported])
		QSWCPPFLAGS="-DMULTIRAIL_EKC=1"
	else
		AC_MSG_RESULT([not supported])
		if test -d $LINUX/drivers/net/qsnet/include; then
			QSWCPPFLAGS="-I$LINUX/drivers/net/qsnet/include"
		else
			QSWCPPFLAGS="-I$LINUX/include/linux"
		fi
	fi
else
	AC_MSG_RESULT([no])
	QSWNAL=""
	QSWCPPFLAGS=""
fi
AC_SUBST(QSWCPPFLAGS)
AC_SUBST(QSWNAL)
])

#
# LP_CONFIG_GM
#
# check if GM support is available
#
AC_DEFUN([LP_CONFIG_GM],
[AC_MSG_CHECKING([if gm support was requested])
AC_ARG_WITH([gm],
	AC_HELP_STRING([--with-gm=path],
		       [build gmnal against path]),
	[
		case $with_gm in 
			yes)
				AC_MSG_RESULT([yes])
				GMCPPFLAGS="-I/usr/local/gm/include"
				GMNAL="gmnal"
				;;
			no)
				AC_MSG_RESULT([no])
				GMCPPFLAGS=""
				GMNAL=""
				;;
			*)
				AC_MSG_RESULT([yes])
				GMCPPFLAGS="-I$with_gm/include -I$with_gm/drivers -I$with_gm/drivers/linux/gm"
				GMNAL="gmnal"
				;;
		esac
	],[
		AC_MSG_RESULT([no])
		GMCPPFLAGS=""
		GMNAL=""
	])
AC_SUBST(GMCPPFLAGS)
AC_SUBST(GMNAL)
])

#
# LP_CONFIG_OPENIB
#
# check for OpenIB in the kernel
AC_DEFUN([LP_CONFIG_OPENIB],[
AC_MSG_CHECKING([whether to enable OpenIB support])
# set default
DFLTOPENIBCPPFLAGS="-I$LINUX/drivers/infiniband/include -DIN_TREE_BUILD"
AC_ARG_WITH([openib],
	AC_HELP_STRING([--with-openib=path],
	               [build openibnal against path]),
	[
		case $with_openib in
		yes)    OPENIBCPPFLAGS="$DFLTOPENIBCPPFLAGS"
			ENABLEOPENIB=2
			;;
		no)     ENABLEOPENIB=0
			;;
		*)      OPENIBCPPFLAGS="-I$with_openib/include"
			ENABLEOPENIB=3
			;;
		esac
	],[
                OPENIBCPPFLAGS="$DFLTOPENIBCPPFLAGS"
		ENABLEOPENIB=1
	])
if test $ENABLEOPENIB -eq 0; then
	AC_MSG_RESULT([disabled])
else
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $OPENIBCPPFLAGS"
	LB_LINUX_TRY_COMPILE([
		#include <ts_ib_core.h>
	],[
       	        struct ib_device_properties props;
		return 0;
	],[
		AC_MSG_RESULT([yes])
		OPENIBNAL="openibnal"
	],[
		AC_MSG_RESULT([no])
		case $ENABLEOPENIB in
		1) ;;
		2) AC_MSG_ERROR([default openib headers not present]);;
		3) AC_MSG_ERROR([bad --with-openib path]);;
		*) AC_MSG_ERROR([internal error]);;
		esac
		OPENIBNAL=""
		OPENIBCPPFLAGS=""
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(OPENIBCPPFLAGS)
AC_SUBST(OPENIBNAL)
])

#
# LP_CONFIG_IIB
#
# check for infinicon infiniband support
#
AC_DEFUN([LP_CONFIG_IIB],
[AC_MSG_CHECKING([if Infinicon IB kernel headers are present])
# for how the only infinicon ib build has headers in /usr/include/iba
IIBCPPFLAGS="-I/usr/include -DIN_TREE_BUILD"
EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS $IIBCPPFLAGS"
LB_LINUX_TRY_COMPILE([
	#include <linux/iba/ibt.h>
],[
        IBT_INTERFACE_UNION interfaces;
        FSTATUS             rc;

         rc = IbtGetInterfaceByVersion(IBT_INTERFACE_VERSION_2,
				       &interfaces);

	return rc == FSUCCESS ? 0 : 1;
],[
	AC_MSG_RESULT([yes])
	IIBNAL="iibnal"
],[
	AC_MSG_RESULT([no])
	IIBNAL=""
	IIBCPPFLAGS=""
])
EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
AC_SUBST(IIBCPPFLAGS)
AC_SUBST(IIBNAL)
])

#
# LP_CONFIG_VIB
#
# check for Voltaire infiniband support
#
AC_DEFUN([LP_CONFIG_VIB],
[AC_MSG_CHECKING([if Voltaire IB kernel headers are present])
VIBCPPFLAGS="-I/usr/local/include/ibhost-kdevel -DCPU_BE=0 -DCPU_LE=1 -DGSI_PASS_PORT_NUM"
EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS $VIBCPPFLAGS"
LB_LINUX_TRY_COMPILE([
        #include <linux/list.h>
 	#include <vverbs.h>
],[
        vv_hca_h_t     kib_hca;
	vv_return_t    retval;

	retval = vv_hca_open("ANY_HCA", NULL, &kib_hca);

	return retval == vv_return_ok ? 0 : 1;
],[
	AC_MSG_RESULT([yes])
	VIBNAL="vibnal"
],[
	AC_MSG_RESULT([no])
	VIBNAL=""
	VIBCPPFLAGS=""
])
EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
AC_SUBST(VIBCPPFLAGS)
AC_SUBST(VIBNAL)
])

#
# LP_CONFIG_RANAL
#
# check whether to use the RapidArray nal
#
AC_DEFUN([LP_CONFIG_RANAL],
[#### Rapid Array
AC_MSG_CHECKING([if RapidArray kernel headers are present])
# placeholder
RACPPFLAGS="-I/tmp"
EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS $RACPPFLAGS"
LB_LINUX_TRY_COMPILE([
	#include <linux/types.h>
	#include <rapl.h>
],[
        RAP_RETURN          rc;
	RAP_PVOID           dev_handle;

        rc = RapkGetDeviceByIndex(0, NULL, &dev_handle);

	return rc == RAP_SUCCESS ? 0 : 1;
],[
	AC_MSG_RESULT([yes])
	RANAL="ranal"
],[
	AC_MSG_RESULT([no])
	RANAL=""
	RACPPFLAGS=""
])
EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
AC_SUBST(RACPPFLAGS)
AC_SUBST(RANAL)
])

#
# LP_STRUCT_PAGE_LIST
#
# 2.6.4 no longer has page->list
#
AC_DEFUN([LP_STRUCT_PAGE_LIST],
[AC_MSG_CHECKING([if struct page has a list field])
LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
],[
	struct page page;
	&page.list;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_PAGE_LIST, 1, [struct page has a list field])
],[
	AC_MSG_RESULT([no])
])
])

#
# LP_STRUCT_SIGHAND
#
# red hat 2.4 adds sighand to struct task_struct
#
AC_DEFUN([LP_STRUCT_SIGHAND],
[AC_MSG_CHECKING([if task_struct has a sighand field])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	struct task_struct p;
	p.sighand = NULL;
],[
	AC_DEFINE(CONFIG_RH_2_4_20, 1, [this kernel contains Red Hat 2.4.20 patches])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# LP_FUNC_CPU_ONLINE
#
# cpu_online is different in rh 2.4, vanilla 2.4, and 2.6
#
AC_DEFUN([LP_FUNC_CPU_ONLINE],
[AC_MSG_CHECKING([if kernel defines cpu_online()])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	cpu_online(0);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_CPU_ONLINE, 1, [cpu_online found])
],[
	AC_MSG_RESULT([no])
])
])

#
# LP_TYPE_CPUMASK_T
#
# same goes for cpumask_t
#
AC_DEFUN([LP_TYPE_CPUMASK_T],
[AC_MSG_CHECKING([if kernel defines cpumask_t])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	return sizeof (cpumask_t);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_CPUMASK_T, 1, [cpumask_t found])
],[
	AC_MSG_RESULT([no])
])
])

#
# LP_FUNC_SHOW_TASK
#
# we export show_task(), but not all kernels have it (yet)
#
AC_DEFUN([LP_FUNC_SHOW_TASK],
[AC_MSG_CHECKING([if kernel exports show_task])
have_show_task=0
for file in ksyms sched ; do
	if grep -q "EXPORT_SYMBOL(show_task)" \
		 "$LINUX/kernel/$file.c" 2>/dev/null ; then
		have_show_task=1
		break
	fi
done
if test x$have_show_task = x1 ; then
	AC_DEFINE(HAVE_SHOW_TASK, 1, [show_task is exported])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
])

#
# LP_PROG_LINUX
#
# Portals linux kernel checks
#
AC_DEFUN([LP_PROG_LINUX],
[LP_CONFIG_ZEROCOPY
LP_CONFIG_AFFINITY
LP_CONFIG_QUADRICS
LP_CONFIG_GM
if test $linux25 = 'no' ; then
	LP_CONFIG_OPENIB
fi
LP_CONFIG_IIB
LP_CONFIG_VIB
LP_CONFIG_RANAL

LP_STRUCT_PAGE_LIST
LP_STRUCT_SIGHAND
LP_FUNC_CPU_ONLINE
LP_TYPE_CPUMASK_T
LP_FUNC_SHOW_TASK
])

#
# LP_PATH_DEFAULTS
#
# default paths for installed files
#
AC_DEFUN([LP_PATH_DEFAULTS],
[
])

#
# LP_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LP_CONFIGURE],
[# portals/utils/portals.c
AC_CHECK_HEADERS([netdb.h netinet/tcp.h asm/types.h])
AC_CHECK_FUNCS([gethostbyname socket connect])

# portals/utils/debug.c
AC_CHECK_HEADERS([linux/version.h])

AC_CHECK_TYPE([spinlock_t],
	[AC_DEFINE(HAVE_SPINLOCK_T, 1, [spinlock_t is defined])],
	[],
	[#include <linux/spinlock.h>])

# --------  Check for required packages  --------------

# this doesn't seem to work on older autoconf
# AC_CHECK_LIB(readline, readline,,)
AC_MSG_CHECKING([for readline support])
AC_ARG_ENABLE(readline,
	AC_HELP_STRING([--disable-readline],
			[do not use readline library]),
	[],[enable_readline='yes'])
AC_MSG_RESULT([$enable_readline]) 
if test x$enable_readline = xyes ; then
	LIBREADLINE="-lreadline -lncurses"
	AC_DEFINE(HAVE_LIBREADLINE, 1, [readline library is available])
else 
	LIBREADLINE=""
fi
AC_SUBST(LIBREADLINE)

AC_MSG_CHECKING([if efence debugging support is requested])
AC_ARG_ENABLE(efence,
	AC_HELP_STRING([--enable-efence],
			[use efence library]),
	[],[enable_efence='no'])
AC_MSG_RESULT([$enable_efence])
if test "$enable_efence" = "yes" ; then
	LIBEFENCE="-lefence"
	AC_DEFINE(HAVE_LIBEFENCE, 1, [libefence support is requested])
else 
	LIBEFENCE=""
fi
AC_SUBST(LIBEFENCE)

# -------- enable acceptor libwrap (TCP wrappers) support? -------
AC_MSG_CHECKING([if libwrap support is requested])
AC_ARG_ENABLE([libwrap],
	AC_HELP_STRING([--enable-libwrap], [use TCP wrappers]),
	[case "${enableval}" in
		yes) enable_libwrap=yes ;;
		no) enable_libwrap=no ;;
		*) AC_MSG_ERROR(bad value ${enableval} for --enable-libwrap) ;;
	esac],[enable_libwrap=no])
AC_MSG_RESULT([$enable_libwrap])
if test x$enable_libwrap = xyes ; then
	LIBWRAP="-lwrap"
	AC_DEFINE(HAVE_LIBWRAP, 1, [libwrap support is requested])
else
	LIBWRAP=""
fi
AC_SUBST(LIBWRAP)

# ----------------------------------------
# some tests for catamount-like systems
# ----------------------------------------
AC_ARG_ENABLE([sysio_init],
	AC_HELP_STRING([--disable-sysio-init],
		[call sysio init functions when initializing liblustre]),
	[],[enable_sysio_init=yes])
AC_MSG_CHECKING([whether to initialize libsysio])
AC_MSG_RESULT([$enable_sysio_init])
if test x$enable_sysio_init != xno ; then
	AC_DEFINE([INIT_SYSIO], 1, [call sysio init functions])
fi

AC_ARG_ENABLE([urandom],
	AC_HELP_STRING([--disable-urandom],
		[disable use of /dev/urandom for liblustre]),
	[],[enable_urandom=yes])
AC_MSG_CHECKING([whether to use /dev/urandom for liblustre])
AC_MSG_RESULT([$enable_urandom])
if test x$enable_urandom != xno ; then
	AC_DEFINE([LIBLUSTRE_USE_URANDOM], 1, [use /dev/urandom for random data])
fi

# -------- check for -lcap and -lpthread ----
if test x$enable_liblustre = xyes ; then
	AC_CHECK_LIB([cap], [cap_get_proc],
		[
			CAP_LIBS="-lcap"
			AC_DEFINE([HAVE_LIBCAP], 1, [use libcap])
		],
		[CAP_LIBS=""])
	AC_SUBST(CAP_LIBS)
	AC_CHECK_LIB([pthread], [pthread_create],
		[
			PTHREAD_LIBS="-lpthread"
			AC_DEFINE([HAVE_LIBPTHREAD], 1, [use libpthread])
		],
		[PTHREAD_LIBS=""])
	AC_SUBST(PTHREAD_LIBS)
fi
])

#
# LP_CONDITIONALS
#
# AM_CONDITOINAL defines for portals
#
AC_DEFUN([LP_CONDITIONALS],
[AM_CONDITIONAL(BUILD_QSWNAL, test x$QSWNAL = "xqswnal")
AM_CONDITIONAL(BUILD_GMNAL, test x$GMNAL = "xgmnal")
AM_CONDITIONAL(BUILD_OPENIBNAL, test x$OPENIBNAL = "xopenibnal")
AM_CONDITIONAL(BUILD_IIBNAL, test x$IIBNAL = "xiibnal")
AM_CONDITIONAL(BUILD_VIBNAL, test x$VIBNAL = "xvibnal")
AM_CONDITIONAL(BUILD_RANAL, test x$RANAL = "xranal")
])

#
# LP_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LP_CONFIG_FILES],
[AC_CONFIG_FILES([
portals/Kernelenv
portals/Makefile
portals/autoMakefile
portals/autoconf/Makefile
portals/doc/Makefile
portals/include/Makefile
portals/include/linux/Makefile
portals/include/portals/Makefile
portals/knals/Makefile
portals/knals/autoMakefile
portals/knals/gmnal/Makefile
portals/knals/gmnal/autoMakefile
portals/knals/openibnal/Makefile
portals/knals/openibnal/autoMakefile
portals/knals/iibnal/Makefile
portals/knals/iibnal/autoMakefile
portals/knals/vibnal/Makefile
portals/knals/vibnal/autoMakefile
portals/knals/lonal/Makefile
portals/knals/lonal/autoMakefile
portals/knals/qswnal/Makefile
portals/knals/qswnal/autoMakefile
portals/knals/ranal/Makefile
portals/knals/ranal/autoMakefile
portals/knals/socknal/Makefile
portals/knals/socknal/autoMakefile
portals/libcfs/Makefile
portals/libcfs/autoMakefile
portals/portals/Makefile
portals/portals/autoMakefile
portals/router/Makefile
portals/router/autoMakefile
portals/tests/Makefile
portals/tests/autoMakefile
portals/unals/Makefile
portals/utils/Makefile
])
])
