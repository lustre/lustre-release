#
# LN_CONFIG_MAX_PAYLOAD
#
# configure maximum payload
#
AC_DEFUN([LN_CONFIG_MAX_PAYLOAD],
[AC_MSG_CHECKING([for non-default maximum LNET payload])
AC_ARG_WITH([max-payload-mb],
	AC_HELP_STRING([--with-max-payload-mb=MBytes],
                       [set maximum lnet payload in MBytes]),
        [
		AC_MSG_RESULT([$with_max_payload_mb])
	        LNET_MAX_PAYLOAD_MB=$with_max_payload_mb
		LNET_MAX_PAYLOAD="(($with_max_payload_mb)<<20)"
	], [
		AC_MSG_RESULT([no])
		LNET_MAX_PAYLOAD="LNET_MTU"
	])
        AC_DEFINE_UNQUOTED(LNET_MAX_PAYLOAD, $LNET_MAX_PAYLOAD,
			   [Max LNET payload])
])

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
		#if HAVE_CPUMASK_T
		cpumask_t     m;
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
# LN_CONFIG_PORTALS
#
# configure support for Portals
#
AC_DEFUN([LN_CONFIG_PORTALS],
[AC_MSG_CHECKING([for portals])
AC_ARG_WITH([portals],
	AC_HELP_STRING([--with-portals=path],
                       [set path to portals]),
        [
		case $with_portals in
			no)     ENABLEPORTALS=0
				;;
			*)	PORTALS="${with_portals}"
				ENABLEPORTALS=1
				;;
		esac
	], [
		ENABLEPORTALS=0
	])
PTLLNDCPPFLAGS=""
if test $ENABLEPORTALS -eq 0; then
	AC_MSG_RESULT([no])
elif test ! \( -f ${PORTALS}/include/portals/p30.h \); then
        AC_MSG_RESULT([no])
	AC_MSG_ERROR([bad --with-portals path])
else
        AC_MSG_RESULT([$PORTALS])
        PTLLNDCPPFLAGS="-I${PORTALS}/include"
fi
AC_SUBST(PTLLNDCPPFLAGS)
])

#
# LN_CONFIG_BACKOFF
#
# check if tunable tcp backoff is available/wanted
#
AC_DEFUN([LN_CONFIG_BACKOFF],
[AC_MSG_CHECKING([for tunable backoff TCP support])
AC_ARG_ENABLE([backoff],
       AC_HELP_STRING([--disable-backoff],
                      [disable socknal tunable backoff]),
       [],[enable_backoff='yes'])
if test x$enable_backoff = xno ; then
       AC_MSG_RESULT([no (by request)])
else
       BOCD="`grep -c TCP_BACKOFF $LINUX/include/linux/tcp.h`"
       if test "$BOCD" != 0 ; then
               AC_DEFINE(SOCKNAL_BACKOFF, 1, [use tunable backoff TCP])
               AC_MSG_RESULT(yes)
       else
               AC_MSG_RESULT([no (no kernel support)])
       fi
fi
])


#
# LN_CONFIG_PTLLND
#
# configure support for Portals LND
#
AC_DEFUN([LN_CONFIG_PTLLND],
[
if test -z "$ENABLEPORTALS"; then
	LN_CONFIG_PORTALS
fi

AC_MSG_CHECKING([whether to build the kernel portals LND])

PTLLND=""
if test $ENABLEPORTALS -ne 0; then
	AC_MSG_RESULT([yes])
	PTLLND="ptllnd"
else
	AC_MSG_RESULT([no])
fi
AC_SUBST(PTLLND)
])

#
# LN_CONFIG_UPTLLND
#
# configure support for Portals LND
#
AC_DEFUN([LN_CONFIG_UPTLLND],
[
if test -z "$ENABLEPORTALS"; then
	LN_CONFIG_PORTALS
fi

AC_MSG_CHECKING([whether to build the userspace portals LND])

UPTLLND=""
if test $ENABLEPORTALS -ne 0; then
	AC_MSG_RESULT([yes])
	UPTLLND="ptllnd"
else
	AC_MSG_RESULT([no])
fi
AC_SUBST(UPTLLND)
])

#
# LN_CONFIG_USOCKLND
#
# configure support for userspace TCP/IP LND
#
AC_DEFUN([LN_CONFIG_USOCKLND],
[AC_MSG_CHECKING([whether to build usocklnd])
AC_ARG_ENABLE([usocklnd],
       	AC_HELP_STRING([--disable-usocklnd],
                      	[disable usocklnd]),
       	[],[enable_usocklnd='yes'])

if test x$enable_usocklnd = xyes ; then
	if test "$ENABLE_LIBPTHREAD" = "yes" ; then
		AC_MSG_RESULT([yes])
      		USOCKLND="usocklnd"
	else
		AC_MSG_RESULT([no (libpthread not present or disabled)])
		USOCKLND=""
	fi
else
	AC_MSG_RESULT([no (disabled explicitly)])
     	USOCKLND=""
fi
AC_SUBST(USOCKLND)
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
	QSWLND="qswlnd"
	AC_MSG_CHECKING([for multirail EKC])
	if test -f $QSNET/include/elan/epcomms.h; then
		AC_MSG_RESULT([supported])
		QSWCPPFLAGS="-I$QSNET/include -DMULTIRAIL_EKC=1"
	else
		AC_MSG_RESULT([not supported])
		AC_MSG_ERROR([Need multirail EKC])
	fi

	if test x$QSNET = x$LINUX ; then
		LB_LINUX_CONFIG([QSNET],[],[
			LB_LINUX_CONFIG([QSNET_MODULE],[],[
				AC_MSG_WARN([QSNET is not enabled in this kernel; not building qswlnd.])
				QSWLND=""
				QSWCPPFLAGS=""
			])
		])
	fi
else
	AC_MSG_RESULT([no])
	QSWLND=""
	QSWCPPFLAGS=""
fi
AC_SUBST(QSWCPPFLAGS)
AC_SUBST(QSWLND)
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
	               [build gmlnd against path]),
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

	GMLND="gmlnd"
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
    patch -p0 < $PWD/lnet/klnds/gmlnd/gm-reg-phys.patch
...then rebuild and re-install them])
                AC_MSG_ERROR([Can't build GM without gm_register_memory_ex_phys()])
        ])

	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(GMCPPFLAGS)
AC_SUBST(GMLIBS)
AC_SUBST(GMLND)
])


#
# LN_CONFIG_MX
#
AC_DEFUN([LN_CONFIG_MX],
[AC_MSG_CHECKING([whether to enable Myrinet MX support])
# set default
MXPATH="/opt/mx"
AC_ARG_WITH([mx],
       AC_HELP_STRING([--with-mx=path],
                      [build mxlnd against path]),
       [
               case $with_mx in
               yes)    ENABLEMX=2
                       ;;
               no)     ENABLEMX=0
                       ;;
               *)      MXPATH=$with_mx
                       ENABLEMX=3
                       ;;
               esac
       ],[
               ENABLEMX=1
       ])
if test $ENABLEMX -eq 0; then
       AC_MSG_RESULT([disabled])
elif test ! \( -f ${MXPATH}/include/myriexpress.h -a \
              -f ${MXPATH}/include/mx_kernel_api.h -a \
              -f ${MXPATH}/include/mx_pin.h \); then
       AC_MSG_RESULT([no])
       case $ENABLEMX in
       1) ;;
       2) AC_MSG_ERROR([Myrinet MX kernel headers not present]);;
       3) AC_MSG_ERROR([bad --with-mx path]);;
       *) AC_MSG_ERROR([internal error]);;
       esac
else
       MXCPPFLAGS="-I$MXPATH/include"
       EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
       EXTRA_KCFLAGS="$EXTRA_KCFLAGS $MXCPPFLAGS"
       MXLIBS="-L$MXPATH/lib"
       LB_LINUX_TRY_COMPILE([
               #define MX_KERNEL 1
               #include <mx_extensions.h>
               #include <myriexpress.h>
       ],[
               mx_endpoint_t   end;
               mx_status_t     status;
               mx_request_t    request;
               int             result;

               mx_init();
               mx_open_endpoint(MX_ANY_NIC, MX_ANY_ENDPOINT, 0, NULL, 0, &end);
	       mx_register_unexp_handler(end, (mx_unexp_handler_t) NULL, NULL);
               mx_wait_any(end, MX_INFINITE, 0LL, 0LL, &status, &result);
               mx_iconnect(end, 0LL, 0, 0, 0, NULL, &request);
               return 0;
       ],[
               AC_MSG_RESULT([yes])
               MXLND="mxlnd"
       ],[
               AC_MSG_RESULT([no])
               case $ENABLEMX in
               1) ;;
               2) AC_MSG_ERROR([can't compile with Myrinet MX kernel headers]);;
               3) AC_MSG_ERROR([can't compile with Myrinet MX headers under $MXPATH]);;
               *) AC_MSG_ERROR([internal error]);;
               esac
               MXLND=""
               MXCPPFLAGS=""
       ])
       EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(MXCPPFLAGS)
AC_SUBST(MXLIBS)
AC_SUBST(MXLND)
])



#
# LN_CONFIG_O2IB
#
AC_DEFUN([LN_CONFIG_O2IB],[
AC_MSG_CHECKING([whether to enable OpenIB gen2 support])
# set default
AC_ARG_WITH([o2ib],
	AC_HELP_STRING([--with-o2ib=path],
	               [build o2iblnd against path]),
	[
		case $with_o2ib in
		yes)    O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
			ENABLEO2IB=2
			;;
		no)     ENABLEO2IB=0
			;;
		*)      O2IBPATHS=$with_o2ib
			ENABLEO2IB=3
			;;
		esac
	],[
		O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
		ENABLEO2IB=1
	])
if test $ENABLEO2IB -eq 0; then
	AC_MSG_RESULT([disabled])
else
	o2ib_found=false
	for O2IBPATH in $O2IBPATHS; do
		if test \( -f ${O2IBPATH}/include/rdma/rdma_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_verbs.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_fmr_pool.h \); then
			o2ib_found=true
			break
 		fi
	done
	if ! $o2ib_found; then
		AC_MSG_RESULT([no])
		case $ENABLEO2IB in
			1) ;;
			2) AC_MSG_ERROR([kernel OpenIB gen2 headers not present]);;
			3) AC_MSG_ERROR([bad --with-o2ib path]);;
			*) AC_MSG_ERROR([internal error]);;
		esac
	else
		O2IBCPPFLAGS="-I$O2IBPATH/include"
		EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
		EXTRA_KCFLAGS="$EXTRA_KCFLAGS $O2IBCPPFLAGS"
		EXTRA_LNET_INCLUDE="$O2IBCPPFLAGS $EXTRA_LNET_INCLUDE"
		LB_LINUX_TRY_COMPILE([
		        #include <linux/version.h>
		        #include <linux/pci.h>
		        #if !HAVE_GFP_T
		        typedef int gfp_t;
		        #endif
		        #include <rdma/rdma_cm.h>
		        #include <rdma/ib_cm.h>
		        #include <rdma/ib_verbs.h>
		        #include <rdma/ib_fmr_pool.h>
		],[
		        struct rdma_cm_id          *cm_id;
		        struct rdma_conn_param      conn_param;
		        struct ib_device_attr       device_attr;
		        struct ib_qp_attr           qp_attr;
		        struct ib_pool_fmr          pool_fmr;
		        enum   ib_cm_rej_reason     rej_reason;

		        cm_id = rdma_create_id(NULL, NULL, RDMA_PS_TCP);
		        return PTR_ERR(cm_id);
		],[
		        AC_MSG_RESULT([yes])
		        O2IBLND="o2iblnd"
		],[
		        AC_MSG_RESULT([no])
		        case $ENABLEO2IB in
		        1) ;;
		        2) AC_MSG_ERROR([can't compile with kernel OpenIB gen2 headers]);;
		        3) AC_MSG_ERROR([can't compile with OpenIB gen2 headers under $O2IBPATH]);;
		        *) AC_MSG_ERROR([internal error]);;
		        esac
		        O2IBLND=""
		        O2IBCPPFLAGS=""
		])

		# we know at this point that the found OFED source is good
		if test \( $ENABLEO2IB = 3 \); then
			if test \( -f $O2IBPATH/Module.symvers \); then
				AC_MSG_NOTICE([adding $O2IBPATH/Module.symvers to $PWD/Module.symvers])
				cat $O2IBPATH/Module.symvers >> $PWD/Module.symvers
			else
				AC_MSG_ERROR([an external source tree was specified for o2iblnd however I could not find a $O2IBPATH/Module.symvers there])
			fi
		fi

		# version checking is a hack and isn't reliable,
		# we need verify it with each new ofed release

		if grep -q ib_dma_map_single \
			${O2IBPATH}/include/rdma/ib_verbs.h; then
			if grep -q comp_vector \
				${O2IBPATH}/include/rdma/ib_verbs.h; then
				IBLND_OFED_VERSION="1025"
			else
				IBLND_OFED_VERSION="1020"
			fi
		else
			IBLND_OFED_VERSION="1010"
		fi

		AC_DEFINE_UNQUOTED(IBLND_OFED_VERSION, $IBLND_OFED_VERSION,
				   [OFED version])

		EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
	fi
fi

AC_SUBST(EXTRA_LNET_INCLUDE)
AC_SUBST(O2IBCPPFLAGS)
AC_SUBST(O2IBLND)
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
	               [build openiblnd against path]),
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
               -f ${OPENIBPATH}/include/ts_ib_cm.h -a \
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
	OPENIBCPPFLAGS="$OPENIBCPPFLAGS -DIB_NTXRXPARAMS=4"
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
		OPENIBLND="openiblnd"
	],[
		AC_MSG_RESULT([no])
		case $ENABLEOPENIB in
		1) ;;
		2) AC_MSG_ERROR([can't compile with kernel OpenIB headers]);;
		3) AC_MSG_ERROR([can't compile with OpenIB headers under $OPENIBPATH]);;
		*) AC_MSG_ERROR([internal error]);;
		esac
		OPENIBLND=""
		OPENIBCPPFLAGS=""
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(OPENIBCPPFLAGS)
AC_SUBST(OPENIBLND)
])

#
# LN_CONFIG_CIBLND
#
AC_DEFUN([LN_CONFIG_CIB],[
AC_MSG_CHECKING([whether to enable Cisco/TopSpin IB support])
# set default
CIBPATH=""
CIBLND=""
AC_ARG_WITH([cib],
	AC_HELP_STRING([--with-cib=path],
	               [build ciblnd against path]),
	[
		case $with_cib in
		no)     AC_MSG_RESULT([no]);;
		*)      CIBPATH="$with_cib"
	                if test -d "$CIBPATH"; then
	                 	AC_MSG_RESULT([yes])
                        else
				AC_MSG_RESULT([no])
				AC_MSG_ERROR([No directory $CIBPATH])
			fi;;
		esac
	],[
		AC_MSG_RESULT([no])
	])
if test -n "$CIBPATH"; then
	CIBCPPFLAGS="-I${CIBPATH}/ib/ts_api_ng/include -I${CIBPATH}/all/kernel_services/include -DUSING_TSAPI"
	CIBCPPFLAGS="$CIBCPPFLAGS -DIB_NTXRXPARAMS=3"
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $CIBCPPFLAGS"
	LB_LINUX_TRY_COMPILE([
		#include <ts_ib_core.h>
		#include <ts_ib_cm.h>
	        #include <ts_ib_sa_client.h>
	],[
	        struct ib_device_properties dev_props;
	        struct ib_cm_active_param   cm_active_params;
	        tTS_IB_CLIENT_QUERY_TID     tid;
	        int                         enum1 = TS_IB_QP_ATTRIBUTE_STATE;
		int                         enum2 = TS_IB_ACCESS_LOCAL_WRITE;
		int                         enum3 = TS_IB_CQ_CALLBACK_INTERRUPT;
		int                         enum4 = TS_IB_CQ_PROVIDER_REARM;
		return 0;
	],[
		CIBLND="ciblnd"
	],[
		AC_MSG_ERROR([can't compile ciblnd with given path])
	        CIBCPPFLAGS=""
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(CIBCPPFLAGS)
AC_SUBST(CIBLND)
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
	               [build iiblnd against path]),
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
		IIBLND="iiblnd"
	],[
		AC_MSG_RESULT([no])
		case $ENABLEIIB in
		1) ;;
		2) AC_MSG_ERROR([can't compile with default Infinicon headers]);;
		3) AC_MSG_ERROR([can't compile with Infinicon headers under $IIBPATH]);;
		*) AC_MSG_ERROR([internal error]);;
		esac
		IIBLND=""
		IIBCPPFLAGS=""
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(IIBCPPFLAGS)
AC_SUBST(IIBLND)
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
		       [build viblnd against path]),
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
	VIBLND=""
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
		VIBLND="viblnd"
	],[
	        AC_MSG_ERROR([can't compile viblnd with given path])
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
if test -n "$VIBLND"; then
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
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(VIBCPPFLAGS)
AC_SUBST(VIBLND)
])

#
# LN_CONFIG_RALND
#
# check whether to use the RapidArray lnd
#
AC_DEFUN([LN_CONFIG_RALND],
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
	RALND="ralnd"
],[
	AC_MSG_RESULT([no])
	RALND=""
	RACPPFLAGS=""
])
EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
AC_SUBST(RACPPFLAGS)
AC_SUBST(RALND)
])



#
# LN_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LN_PROG_LINUX],
[
LN_CONFIG_AFFINITY
LN_CONFIG_BACKOFF
LN_CONFIG_QUADRICS
LN_CONFIG_GM
LN_CONFIG_OPENIB
LN_CONFIG_CIB
LN_CONFIG_VIB
LN_CONFIG_IIB
LN_CONFIG_O2IB
LN_CONFIG_RALND
LN_CONFIG_PTLLND
LN_CONFIG_MX
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

#
# LC_CONFIG_READLINE
#
# Build with readline
#
AC_MSG_CHECKING([whether to enable readline support])
AC_ARG_ENABLE(readline,
        AC_HELP_STRING([--disable-readline],
                        [disable readline support]),
        [],[enable_readline='yes'])
AC_MSG_RESULT([$enable_readline])

# -------- check for readline if enabled ----
if test x$enable_readline = xyes ; then
	LIBS_save="$LIBS"
	LIBS="-lncurses $LIBS"
	AC_CHECK_LIB([readline],[readline],[
	LIBREADLINE="-lreadline -lncurses"
	AC_DEFINE(HAVE_LIBREADLINE, 1, [readline library is available])
	],[
	LIBREADLINE=""
	])
	LIBS="$LIBS_save"
else
	LIBREADLINE=""
fi
AC_SUBST(LIBREADLINE)

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

# -------- check for -lcap support ----
if test x$enable_liblustre = xyes ; then
	AC_CHECK_LIB([cap], [cap_get_proc],
		[
			CAP_LIBS="-lcap"
			AC_DEFINE([HAVE_LIBCAP], 1, [use libcap])
		],
		[
			CAP_LIBS=""
		])
	AC_SUBST(CAP_LIBS)

fi

LN_CONFIG_MAX_PAYLOAD
LN_CONFIG_UPTLLND
LN_CONFIG_USOCKLND
])

#
# LN_CONDITIONALS
#
# AM_CONDITOINAL defines for lnet
#
AC_DEFUN([LN_CONDITIONALS],
[AM_CONDITIONAL(BUILD_QSWLND, test x$QSWLND = "xqswlnd")
AM_CONDITIONAL(BUILD_GMLND, test x$GMLND = "xgmlnd")
AM_CONDITIONAL(BUILD_MXLND, test x$MXLND = "xmxlnd")
AM_CONDITIONAL(BUILD_O2IBLND, test x$O2IBLND = "xo2iblnd")
AM_CONDITIONAL(BUILD_OPENIBLND, test x$OPENIBLND = "xopeniblnd")
AM_CONDITIONAL(BUILD_CIBLND, test x$CIBLND = "xciblnd")
AM_CONDITIONAL(BUILD_IIBLND, test x$IIBLND = "xiiblnd")
AM_CONDITIONAL(BUILD_VIBLND, test x$VIBLND = "xviblnd")
AM_CONDITIONAL(BUILD_RALND, test x$RALND = "xralnd")
AM_CONDITIONAL(BUILD_PTLLND, test x$PTLLND = "xptllnd")
AM_CONDITIONAL(BUILD_UPTLLND, test x$UPTLLND = "xptllnd")
AM_CONDITIONAL(BUILD_USOCKLND, test x$USOCKLND = "xusocklnd")
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
lnet/include/lnet/Makefile
lnet/include/lnet/linux/Makefile
lnet/klnds/Makefile
lnet/klnds/autoMakefile
lnet/klnds/gmlnd/Makefile
lnet/klnds/mxlnd/autoMakefile
lnet/klnds/mxlnd/Makefile
lnet/klnds/gmlnd/autoMakefile
lnet/klnds/openiblnd/Makefile
lnet/klnds/openiblnd/autoMakefile
lnet/klnds/o2iblnd/Makefile
lnet/klnds/o2iblnd/autoMakefile
lnet/klnds/ciblnd/Makefile
lnet/klnds/ciblnd/autoMakefile
lnet/klnds/iiblnd/Makefile
lnet/klnds/iiblnd/autoMakefile
lnet/klnds/viblnd/Makefile
lnet/klnds/viblnd/autoMakefile
lnet/klnds/qswlnd/Makefile
lnet/klnds/qswlnd/autoMakefile
lnet/klnds/ralnd/Makefile
lnet/klnds/ralnd/autoMakefile
lnet/klnds/socklnd/Makefile
lnet/klnds/socklnd/autoMakefile
lnet/klnds/ptllnd/Makefile
lnet/klnds/ptllnd/autoMakefile
lnet/lnet/Makefile
lnet/lnet/autoMakefile
lnet/selftest/Makefile
lnet/selftest/autoMakefile
lnet/ulnds/Makefile
lnet/ulnds/autoMakefile
lnet/ulnds/socklnd/Makefile
lnet/ulnds/ptllnd/Makefile
lnet/utils/Makefile
])
case $lb_target_os in
	darwin)
		AC_CONFIG_FILES([
lnet/include/lnet/darwin/Makefile
])
		;;
esac
])
