#
# LP_CHECK_GCC_VERSION
#
# Check compiler version
#
AC_DEFUN([LP_CHECK_GCC_VERSION],
[AC_MSG_CHECKING([compiler version])
PTL_CC_VERSION=`$CC --version | awk '/^gcc/{print $ 3}'`
PTL_MIN_CC_VERSION="3.2.2"
v2n() {
	awk -F. '{printf "%d\n", (($ 1)*100+($ 2))*100+($ 3)}'
}
if test -z "$PTL_CC_VERSION" -o \
        `echo $PTL_CC_VERSION | v2n` -ge `echo $PTL_MIN_CC_VERSION | v2n`; then
	AC_MSG_RESULT([ok])
else
	AC_MSG_RESULT([Buggy compiler found])
	AC_MSG_ERROR([Need gcc version >= $PTL_MIN_CC_VERSION])
fi
])

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
[AC_MSG_CHECKING([for QsNet sources])
AC_ARG_WITH([qsnet],
	AC_HELP_STRING([--with-qsnet=path],
		       [set path to qsnet source (default=$LINUX)]),
	[QSNET=$with_qsnet],
	[QSNET=$LINUX])
AC_MSG_RESULT([$QSNET])

AC_MSG_CHECKING([if quadrics kernel headers are present])
if test -d $QSNET/drivers/net/qsnet ; then
	AC_MSG_RESULT([yes])
	QSWNAL="qswnal"
	AC_MSG_CHECKING([for multirail EKC])
	if test -f $QSNET/include/elan/epcomms.h; then
		AC_MSG_RESULT([supported])
		QSWCPPFLAGS="-I$QSNET/include -DMULTIRAIL_EKC=1"
	else
		AC_MSG_RESULT([not supported])
		if test -d $QSNET/drivers/net/qsnet/include; then
			QSWCPPFLAGS="-I$QSNET/drivers/net/qsnet/include"
		else
			QSWCPPFLAGS="-I$QSNET/include/linux"
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
[LB_ARG_LIBS_INCLUDES([Myrinet],[gm])
if test x$gm_includes != x ; then
	GMCPPFLAGS="-I$gm_includes"
	if test -d "$gm/drivers" ; then
		GMCPPFLAGS="$GMCPPFLAGS -I$gm/drivers -I$gm/drivers/linux/gm"
	fi
fi
AC_SUBST(GMCPPFLAGS)

if test x$gm_libs != x ; then
	GMLIBS="-L$gm_libs"
fi
AC_SUBST(GMLIBS)

ENABLE_GM=0
if test x$gm != x ; then
	GMNAL="gmnal"
	ENABLE_GM=1
fi
AC_SUBST(GMNAL)
AC_SUBST(ENABLE_GM)
])

#
# LP_CONFIG_OPENIB
#
# check for OpenIB in the kernel
AC_DEFUN([LP_CONFIG_OPENIB],[
AC_MSG_CHECKING([whether to enable OpenIB support])
# set default
OPENIBPATH="$LINUX/drivers/infiniband"
AC_ARG_WITH([openib],
	AC_HELP_STRING([--with-openib=path],
	               [build openibnal against path]),
	[
		case $with_openib in
		yes)    ENABLEOPENIB=2
			;;
		no)     ENABLEOPENIB=0
			;;
		*)      OPENIBPATH="$with_openib"
			ENABLEOPENIB=3
			;;
		esac
	],[
		ENABLEOPENIB=1
	])
if test $ENABLEOPENIB -eq 0; then
	AC_MSG_RESULT([disabled])
elif test ! \( -f ${OPENIBPATH}/include/ts_ib_core.h -a \
               -f ${OPENIBPATH}/include/ts_ib_cm.h -a\
	       -f ${OPENIBPATH}/include/ts_ib_sa_client.h \); then
	AC_MSG_RESULT([no])
	case $ENABLEOPENIB in
	1) ;;
	2) AC_MSG_ERROR([kernel OpenIB headers not present]);;
	3) AC_MSG_ERROR([bad --with-openib path]);;
	*) AC_MSG_ERROR([internal error]);;
	esac
else
    	case $ENABLEOPENIB in
	1|2) OPENIBCPPFLAGS="-I$OPENIBPATH/include -DIN_TREE_BUILD";;
	3)   OPENIBCPPFLAGS="-I$OPENIBPATH/include";;
	*)   AC_MSG_RESULT([no])
	     AC_MSG_ERROR([internal error]);;
	esac
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $OPENIBCPPFLAGS"
	LB_LINUX_TRY_COMPILE([
		#include <ts_ib_core.h>
		#include <ts_ib_cm.h>
	        #include <ts_ib_sa_client.h>
	],[
       	        struct ib_device_properties dev_props;
	        struct ib_cm_active_param   cm_active_params;
	        tTS_IB_CLIENT_QUERY_TID     tid;
	        int                         enum1 = IB_QP_ATTRIBUTE_STATE;
		int                         enum2 = IB_ACCESS_LOCAL_WRITE;
		int                         enum3 = IB_CQ_CALLBACK_INTERRUPT;
		int                         enum4 = IB_CQ_PROVIDER_REARM;
		return 0;
	],[
		AC_MSG_RESULT([yes])
		OPENIBNAL="openibnal"
	],[
		AC_MSG_RESULT([no])
		case $ENABLEOPENIB in
		1) ;;
		2) AC_MSG_ERROR([can't compile with kernel OpenIB headers]);;
		3) AC_MSG_ERROR([can't compile with OpenIB headers under $OPENIBPATH]);;
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
#
# LP_CONFIG_IIB
#
# check for infinicon infiniband support
#
AC_DEFUN([LP_CONFIG_IIB],[
AC_MSG_CHECKING([whether to enable Infinicon support])
# set default
IIBPATH="/usr/include"
AC_ARG_WITH([iib],
	AC_HELP_STRING([--with-iib=path],
	               [build iibnal against path]),
	[
		case $with_iib in
		yes)    ENABLEIIB=2
			;;
		no)     ENABLEIIB=0
			;;
		*)      IIBPATH="${with_iib}/include"
			ENABLEIIB=3
			;;
		esac
	],[
		ENABLEIIB=1
	])
if test $ENABLEIIB -eq 0; then
	AC_MSG_RESULT([disabled])
elif test ! \( -f ${IIBPATH}/linux/iba/ibt.h \); then
	AC_MSG_RESULT([no])
	case $ENABLEIIB in
	1) ;;
	2) AC_MSG_ERROR([default Infinicon headers not present]);;
	3) AC_MSG_ERROR([bad --with-iib path]);;
	*) AC_MSG_ERROR([internal error]);;
	esac
else
	IIBCPPFLAGS="-I$IIBPATH"
	if test $IIBPATH != "/usr/include"; then
		# we need /usr/include come what may
		IIBCPPFLAGS="$IIBCPPFLAGS -I/usr/include"
        fi
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
		case $ENABLEIIB in
		1) ;;
		2) AC_MSG_ERROR([can't compile with default Infinicon headers]);;
		3) AC_MSG_ERROR([can't compile with Infinicon headers under $IIBPATH]);;
		*) AC_MSG_ERROR([internal error]);;
		esac
		IIBNAL=""
		IIBCPPFLAGS=""
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(IIBCPPFLAGS)
AC_SUBST(IIBNAL)
])

#
# LP_CONFIG_VIB
#
# check for Voltaire infiniband support
#
AC_DEFUN([LP_CONFIG_VIB],
[AC_MSG_CHECKING([whether to enable Voltaire IB support])
VIBPATH=""
AC_ARG_WITH([vib],
	AC_HELP_STRING([--with-vib=path],
		       [build vibnal against path]),
	[
		case $with_vib in
		no)     AC_MSG_RESULT([no]);;
		*)	VIBPATH="${with_vib}/src/nvigor/ib-code"
			if test -d "$with_vib" -a -d "$VIBPATH"; then
	                        AC_MSG_RESULT([yes])
			else
				AC_MSG_RESULT([no])
				AC_MSG_ERROR([No directory $VIBPATH])
                        fi;;
		esac
	],[
		AC_MSG_RESULT([no])
	])
if test -z "$VIBPATH"; then
	VIBNAL=""
else
	VIBCPPFLAGS="-I${VIBPATH}/include -I${VIBPATH}/cm"
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $VIBCPPFLAGS"
	LB_LINUX_TRY_COMPILE([
        	#include <linux/list.h>
		#include <asm/byteorder.h>
		#ifdef __BIG_ENDIAN
		# define CPU_BE 1
                # define CPU_LE 0
		#endif
		#ifdef __LITTLE_ENDIAN
		# define CPU_BE 0
		# define CPU_LE 1
		#endif
	 	#include <vverbs.h>
	        #include <ib-cm.h>
	        #include <ibat.h>
	],[
	        vv_hca_h_t       kib_hca;
		vv_return_t      vvrc;
	        cm_cep_handle_t  cep;
	        ibat_arp_data_t  arp_data;
		ibat_stat_t      ibatrc;

		vvrc = vv_hca_open("ANY_HCA", NULL, &kib_hca);
	        cep = cm_create_cep(cm_cep_transp_rc);
	        ibatrc = ibat_get_ib_data((uint32_t)0, (uint32_t)0,
                                          ibat_paths_primary, &arp_data,
					  (ibat_get_ib_data_reply_fn_t)NULL,
                                          NULL, 0);
		return 0;
	],[
		VIBNAL="vibnal"
	],[
	        AC_MSG_ERROR([can't compile vibnal with given path])
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
if test -n "$VIBNAL"; then
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $VIBCPPFLAGS"
	AC_MSG_CHECKING([if Voltaire still uses void * sg addresses])
	LB_LINUX_TRY_COMPILE([
        	#include <linux/list.h>
		#include <asm/byteorder.h>
		#ifdef __BIG_ENDIAN
		# define CPU_BE 1
                # define CPU_LE 0
		#endif
		#ifdef __LITTLE_ENDIAN
		# define CPU_BE 0
		# define CPU_LE 1
		#endif
	 	#include <vverbs.h>
	        #include <ib-cm.h>
	        #include <ibat.h>
	],[
	        vv_scatgat_t  sg;

	        return &sg.v_address[3] == NULL;
	],[
	        AC_MSG_RESULT([yes])
	        VIBCPPFLAGS="$VIBCPPFLAGS -DIBNAL_VOIDSTAR_SGADDR=1"
	],[
	        AC_MSG_RESULT([no])
	])
	AC_MSG_CHECKING([if page_to_phys() must avoid sign extension])
	LB_LINUX_TRY_COMPILE([
		#include <linux/kernel.h>
		#include <linux/mm.h>
		#include <linux/unistd.h>
		#include <asm/system.h>
		#include <asm/io.h>
	],[
	        struct page p;

		switch (42) {
		case 0:
		case (sizeof(typeof(page_to_phys(&p))) < 8):
			break;
		}
	],[
		AC_MSG_RESULT([yes])
		VIBCPPFLAGS="$VIBCPPFLAGS -DIBNAL_32BIT_PAGE2PHYS=1"
	],[
		AC_MSG_RESULT([no])
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
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
RACPPFLAGS="-I${LINUX}/drivers/xd1/include"
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
LP_CONFIG_OPENIB
LP_CONFIG_VIB
LP_CONFIG_IIB
LP_CONFIG_RANAL

LP_STRUCT_PAGE_LIST
LP_STRUCT_SIGHAND
LP_FUNC_CPU_ONLINE
LP_TYPE_CPUMASK_T
LP_FUNC_SHOW_TASK
])

#
# LP_PROG_DARWIN
#
# Darwin checks
#
AC_DEFUN([LP_PROG_DARWIN],
[LB_DARWIN_CHECK_FUNCS([get_preemption_level])
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
AC_CHECK_HEADERS([netdb.h netinet/tcp.h asm/types.h endian.h sys/ioctl.h])
AC_CHECK_FUNCS([gethostbyname socket connect])

# portals/utils/debug.c
AC_CHECK_HEADERS([linux/version.h])

AC_CHECK_TYPE([spinlock_t],
	[AC_DEFINE(HAVE_SPINLOCK_T, 1, [spinlock_t is defined])],
	[],
	[#include <linux/spinlock.h>])

# portals/utils/wirecheck.c
AC_CHECK_FUNCS([strnlen])

# --------  Check for required packages  --------------

LIBS_save="$LIBS"
LIBS="-lncurses $LIBS"
AC_CHECK_LIB([readline],[readline],[
	LIBREADLINE="-lreadline -lncurses"
	AC_DEFINE(HAVE_LIBREADLINE, 1, [readline library is available])
],[
	LIBREADLINE=""
])
LIBS="$LIBS_save"
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
portals/include/libcfs/Makefile
portals/include/libcfs/linux/Makefile
portals/include/portals/Makefile
portals/include/portals/linux/Makefile
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
portals/libcfs/linux/Makefile
portals/portals/Makefile
portals/portals/autoMakefile
portals/router/Makefile
portals/router/autoMakefile
portals/tests/Makefile
portals/tests/autoMakefile
portals/unals/Makefile
portals/utils/Makefile
])
case $lb_target_os in
	darwin)
		AC_CONFIG_FILES([
portals/include/libcfs/darwin/Makefile
portals/include/portals/darwin/Makefile
portals/libcfs/darwin/Makefile
])
		;;
esac
])
