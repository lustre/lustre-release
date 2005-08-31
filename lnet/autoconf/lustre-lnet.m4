#
# LN_CHECK_GCC_VERSION
#
# Check compiler version
#
AC_DEFUN([LN_CHECK_GCC_VERSION],
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
# LN_CONFIG_ZEROCOPY
#
# check if zerocopy is available/wanted
#
AC_DEFUN([LN_CONFIG_ZEROCOPY],
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
# LN_CONFIG_AFFINITY
#
# check if cpu affinity is available/wanted
#
AC_DEFUN([LN_CONFIG_AFFINITY],
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
# LN_CONFIG_QUADRICS
#
# check if quadrics support is in this kernel
#
AC_DEFUN([LN_CONFIG_QUADRICS],
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

	if test x$QSNET = x$LINUX ; then
		LB_LINUX_CONFIG([QSNET],[],[
			LB_LINUX_CONFIG([QSNET_MODULE],[],[
				AC_MSG_WARN([QSNET is not enabled in this kernel; not building qswnal.])
				QSWNAL=""
				QSWCPPFLAGS=""
			])
		])
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
# LN_CONFIG_GM
#
# check if GM support is available
#
AC_DEFUN([LN_CONFIG_GM],[
AC_MSG_CHECKING([whether to enable GM support])
AC_ARG_WITH([gm],
        AC_HELP_STRING([--with-gm=path-to-gm-source-tree],
	               [build gmnal against path]),
	[
	        case $with_gm in
                no)    ENABLE_GM=0
	               ;;
                *)     ENABLE_GM=1
                       GM_SRC="$with_gm"
		       ;;
                esac
        ],[
                ENABLE_GM=0
        ])
AC_ARG_WITH([gm-install],
        AC_HELP_STRING([--with-gm-install=path-to-gm-install-tree],
	               [say where GM has been installed]),
	[
	        GM_INSTALL=$with_gm_install
        ],[
                GM_INSTALL="/opt/gm"
        ])
if test $ENABLE_GM -eq 0; then
        AC_MSG_RESULT([no])
else
        AC_MSG_RESULT([yes])

	GMNAL="gmnal"
        GMCPPFLAGS="-I$GM_SRC/include -I$GM_SRC/drivers -I$GM_SRC/drivers/linux/gm"

	if test -f $GM_INSTALL/lib/libgm.a -o \
                -f $GM_INSTALL/lib64/libgm.a; then
	        GMLIBS="-L$GM_INSTALL/lib -L$GM_INSTALL/lib64"
        else
	        AC_MSG_ERROR([Cant find GM libraries under $GM_INSTALL])
        fi

	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$GMCPPFLAGS -DGM_KERNEL $EXTRA_KCFLAGS"

        AC_MSG_CHECKING([that code using GM compiles with given path])
	LB_LINUX_TRY_COMPILE([
		#define GM_STRONG_TYPES 1
		#ifdef VERSION
		#undef VERSION
		#endif
	        #include "gm.h"
		#include "gm_internal.h"
        ],[
	        struct gm_port *port = NULL;
		gm_recv_event_t *rxevent = gm_blocking_receive_no_spin(port);
                return 0;
        ],[
		AC_MSG_RESULT([yes])
        ],[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Bad --with-gm path])
        ])

	AC_MSG_CHECKING([that GM has gm_register_memory_ex_phys()])
	LB_LINUX_TRY_COMPILE([
		#define GM_STRONG_TYPES 1
		#ifdef VERSION
		#undef VERSION
		#endif
	        #include "gm.h"
		#include "gm_internal.h"
	],[
		gm_status_t     gmrc;
		struct gm_port *port = NULL;
		gm_u64_t        phys = 0;
		gm_up_t         pvma = 0;

		gmrc = gm_register_memory_ex_phys(port, phys, 100, pvma);
		return 0;
	],[
		AC_MSG_RESULT([yes])
	],[
		AC_MSG_RESULT([no.
Please patch the GM sources as follows... 
    cd $GM_SRC
    patch -p0 < $PWD/lnet/knals/gmnal/gm-reg-phys.patch
...then rebuild and re-install them])
                AC_MSG_ERROR([Can't build GM without gm_register_memory_ex_phys()])
        ])

	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(GMCPPFLAGS)
AC_SUBST(GMLIBS)
AC_SUBST(GMNAL)
])

#
# LN_CONFIG_OPENIB
#
# check for OpenIB in the kernel
AC_DEFUN([LN_CONFIG_OPENIB],[
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
# LN_CONFIG_IIB
#
# check for infinicon infiniband support
#
AC_DEFUN([LN_CONFIG_IIB],[
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
# LN_CONFIG_VIB
#
# check for Voltaire infiniband support
#
AC_DEFUN([LN_CONFIG_VIB],
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
# LN_CONFIG_RANAL
#
# check whether to use the RapidArray nal
#
AC_DEFUN([LN_CONFIG_RANAL],
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
# LN_STRUCT_PAGE_LIST
#
# 2.6.4 no longer has page->list
#
AC_DEFUN([LN_STRUCT_PAGE_LIST],
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
# LN_STRUCT_SIGHAND
#
# red hat 2.4 adds sighand to struct task_struct
#
AC_DEFUN([LN_STRUCT_SIGHAND],
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
# LN_FUNC_CPU_ONLINE
#
# cpu_online is different in rh 2.4, vanilla 2.4, and 2.6
#
AC_DEFUN([LN_FUNC_CPU_ONLINE],
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
# LN_TYPE_CPUMASK_T
#
# same goes for cpumask_t
#
AC_DEFUN([LN_TYPE_CPUMASK_T],
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
# LN_FUNC_SHOW_TASK
#
# we export show_task(), but not all kernels have it (yet)
#
AC_DEFUN([LN_FUNC_SHOW_TASK],
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
# LN_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LN_PROG_LINUX],
[LN_CONFIG_ZEROCOPY
LN_CONFIG_AFFINITY
LN_CONFIG_QUADRICS
LN_CONFIG_GM
LN_CONFIG_OPENIB
LN_CONFIG_VIB
LN_CONFIG_IIB
LN_CONFIG_RANAL

LN_STRUCT_PAGE_LIST
LN_STRUCT_SIGHAND
LN_FUNC_CPU_ONLINE
LN_TYPE_CPUMASK_T
LN_FUNC_SHOW_TASK
])

#
# LN_PROG_DARWIN
#
# Darwin checks
#
AC_DEFUN([LN_PROG_DARWIN],
[LB_DARWIN_CHECK_FUNCS([get_preemption_level])
])

#
# LN_PATH_DEFAULTS
#
# default paths for installed files
#
AC_DEFUN([LN_PATH_DEFAULTS],
[
])

#
# LN_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LN_CONFIGURE],
[# lnet/utils/portals.c
AC_CHECK_HEADERS([netdb.h netinet/tcp.h asm/types.h endian.h sys/ioctl.h])
AC_CHECK_FUNCS([gethostbyname socket connect])

# lnet/utils/debug.c
AC_CHECK_HEADERS([linux/version.h])

AC_CHECK_TYPE([spinlock_t],
	[AC_DEFINE(HAVE_SPINLOCK_T, 1, [spinlock_t is defined])],
	[],
	[#include <linux/spinlock.h>])

# lnet/utils/wirecheck.c
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
# LN_CONDITIONALS
#
# AM_CONDITOINAL defines for lnet
#
AC_DEFUN([LN_CONDITIONALS],
[AM_CONDITIONAL(BUILD_QSWNAL, test x$QSWNAL = "xqswnal")
AM_CONDITIONAL(BUILD_GMNAL, test x$GMNAL = "xgmnal")
AM_CONDITIONAL(BUILD_OPENIBNAL, test x$OPENIBNAL = "xopenibnal")
AM_CONDITIONAL(BUILD_IIBNAL, test x$IIBNAL = "xiibnal")
AM_CONDITIONAL(BUILD_VIBNAL, test x$VIBNAL = "xvibnal")
AM_CONDITIONAL(BUILD_RANAL, test x$RANAL = "xranal")
])

#
# LN_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LN_CONFIG_FILES],
[AC_CONFIG_FILES([
lnet/Kernelenv
lnet/Makefile
lnet/autoMakefile
lnet/autoconf/Makefile
lnet/doc/Makefile
lnet/include/Makefile
lnet/include/libcfs/Makefile
lnet/include/libcfs/linux/Makefile
lnet/include/lnet/Makefile
lnet/include/lnet/linux/Makefile
lnet/knals/Makefile
lnet/knals/autoMakefile
lnet/knals/gmnal/Makefile
lnet/knals/gmnal/autoMakefile
lnet/knals/openibnal/Makefile
lnet/knals/openibnal/autoMakefile
lnet/knals/iibnal/Makefile
lnet/knals/iibnal/autoMakefile
lnet/knals/vibnal/Makefile
lnet/knals/vibnal/autoMakefile
lnet/knals/qswnal/Makefile
lnet/knals/qswnal/autoMakefile
lnet/knals/ranal/Makefile
lnet/knals/ranal/autoMakefile
lnet/knals/socknal/Makefile
lnet/knals/socknal/autoMakefile
lnet/libcfs/Makefile
lnet/libcfs/autoMakefile
lnet/libcfs/linux/Makefile
lnet/lnet/Makefile
lnet/lnet/autoMakefile
lnet/tests/Makefile
lnet/tests/autoMakefile
lnet/unals/Makefile
lnet/utils/Makefile
])
case $lb_target_os in
	darwin)
		AC_CONFIG_FILES([
lnet/include/libcfs/darwin/Makefile
lnet/include/lnet/darwin/Makefile
lnet/libcfs/darwin/Makefile
])
		;;
esac
])
