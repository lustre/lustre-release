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
# LN_CONFIG_CDEBUG
#
# whether to enable various libcfs debugs (CDEBUG, ENTRY/EXIT, LASSERT, etc.)
#
AC_DEFUN([LN_CONFIG_CDEBUG],
[
AC_MSG_CHECKING([whether to enable CDEBUG, CWARN])
AC_ARG_ENABLE([libcfs_cdebug],
	AC_HELP_STRING([--disable-libcfs-cdebug],
			[disable libcfs CDEBUG, CWARN]),
	[],[enable_libcfs_cdebug='yes'])
AC_MSG_RESULT([$enable_libcfs_cdebug])
if test x$enable_libcfs_cdebug = xyes; then
   AC_DEFINE(CDEBUG_ENABLED, 1, [enable libcfs CDEBUG, CWARN])
else
   AC_DEFINE(CDEBUG_ENABLED, 0, [disable libcfs CDEBUG, CWARN])
fi

AC_MSG_CHECKING([whether to enable ENTRY/EXIT])
AC_ARG_ENABLE([libcfs_trace],
	AC_HELP_STRING([--disable-libcfs-trace],
			[disable libcfs ENTRY/EXIT]),
	[],[enable_libcfs_trace='yes'])
AC_MSG_RESULT([$enable_libcfs_trace])
if test x$enable_libcfs_trace = xyes; then
   AC_DEFINE(CDEBUG_ENTRY_EXIT, 1, [enable libcfs ENTRY/EXIT])
else
   AC_DEFINE(CDEBUG_ENTRY_EXIT, 0, [disable libcfs ENTRY/EXIT])
fi

AC_MSG_CHECKING([whether to enable LASSERT, LASSERTF])
AC_ARG_ENABLE([libcfs_assert],
	AC_HELP_STRING([--disable-libcfs-assert],
			[disable libcfs LASSERT, LASSERTF]),
	[],[enable_libcfs_assert='yes'])
AC_MSG_RESULT([$enable_libcfs_assert])
if test x$enable_libcfs_assert = xyes; then
   AC_DEFINE(LIBCFS_DEBUG, 1, [enable libcfs LASSERT, LASSERTF])
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
               if grep rto_max $LINUX/include/linux/tcp.h|grep -q __u16; then
                   AC_DEFINE(SOCKNAL_BACKOFF_MS, 1, [tunable backoff TCP in ms])
               fi
       else
               AC_MSG_RESULT([no (no kernel support)])
       fi
fi
])

#
# LN_CONFIG_PANIC_DUMPLOG
#
# check if tunable panic_dumplog is wanted
#
AC_DEFUN([LN_CONFIG_PANIC_DUMPLOG],
[AC_MSG_CHECKING([for tunable panic_dumplog support])
AC_ARG_ENABLE([panic_dumplog],
       AC_HELP_STRING([--enable-panic_dumplog],
                      [enable panic_dumplog]),
       [],[enable_panic_dumplog='no'])
if test x$enable_panic_dumplog = xyes ; then
       AC_DEFINE(LNET_DUMP_ON_PANIC, 1, [use dumplog on panic])
       AC_MSG_RESULT([yes (by request)])
else
       AC_MSG_RESULT([no])
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


# check if kenrel has scsi/fc_compat.h
AC_DEFUN([LN_HAVE_SCSI_FC_COMPAT_H],
[LB_CHECK_FILE([$LINUX/include/scsi/fc_compat.h], [
	AC_DEFINE(HAVE_SCSI_FC_COMPAT_H, 1,
		[kernel has include/scsi/fc_compat.h])
])
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
			if test \( -d ${O2IBPATH}/kernel_patches -a \
				   -f ${O2IBPATH}/Makefile \); then
				AC_MSG_RESULT([no])
				AC_MSG_ERROR([you appear to be trying to use the OFED distribution's source directory (${O2IBPATH}) rather than the "development/headers" directory which is likely in ${O2IBPATH%-*}])
			fi
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
		EXTRA_LNET_INCLUDE="$EXTRA_LNET_INCLUDE $O2IBCPPFLAGS"

		LB_LINUX_TRY_COMPILE([
		        #include <linux/version.h>
		        #include <linux/pci.h>
		        #if !HAVE_GFP_T
		        typedef int gfp_t;
		        #endif
			#if !defined(HAVE_OFED_BACKPORT_H) && defined(HAVE_SCSI_FC_COMPAT_H)
		        #include <scsi/fc_compat.h>
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

			rdma_destroy_id(NULL);
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
		O2IB_SYMVER=""
		if test $ENABLEO2IB -eq 3 ; then
			# OFED default rpm not handle sles10 Modules.symvers name
			for name in Module.symvers Modules.symvers; do
				if test -f $O2IBPATH/$name; then
					O2IB_SYMVER=$name;
					break;
				fi
			done
			if test -n "$O2IB_SYMVER"; then
				AC_MSG_NOTICE([adding $O2IBPATH/Module.symvers to $PWD/$SYMVERFILE])
				# strip out the existing symbols versions first
				if test -f $PWD/$SYMVERFILE; then
				    egrep -v $(echo $(awk '{ print $2 }' $O2IBPATH/$O2IB_SYMVER) | tr ' ' '|') $PWD/$SYMVERFILE > $PWD/$SYMVERFILE.old
				else
				    touch $PWD/$SYMVERFILE.old
				fi
				cat $PWD/$SYMVERFILE.old $O2IBPATH/$O2IB_SYMVER > $PWD/$SYMVERFILE
				rm $PWD/$SYMVERFILE.old
			else
				AC_MSG_ERROR([an external source tree was specified for o2iblnd however I could not find a $O2IBPATH/Module.symvers there])
			fi
		fi

		LN_CONFIG_OFED_SPEC
		EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
	fi
fi

AC_SUBST(EXTRA_LNET_INCLUDE)
AC_SUBST(O2IBCPPFLAGS)
AC_SUBST(O2IBLND)

# In RHEL 6.2, rdma_create_id() takes the queue-pair type as a fourth argument
if test $ENABLEO2IB -ne 0; then
	AC_MSG_CHECKING([if rdma_create_id wants four args])
	LB_LINUX_TRY_COMPILE([
		#include <rdma/rdma_cm.h>
	],[
		rdma_create_id(NULL, NULL, 0, 0);
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_RDMA_CREATE_ID_4ARG, 1,
			[rdma_create_id wants 4 args])
	],[
		AC_MSG_RESULT([no])
	])
fi
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
# LN_TYPE_GFP_T
#
# check if gfp_t is typedef-ed
#
AC_DEFUN([LN_TYPE_GFP_T],
[AC_MSG_CHECKING([if kernel defines gfp_t])
LB_LINUX_TRY_COMPILE([
        #include <linux/gfp.h>
],[
	return sizeof(gfp_t);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_GFP_T, 1, [gfp_t found])
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
# also check sched_show_task() in here, since 2.6.27.
#
AC_DEFUN([LN_FUNC_SHOW_TASK],
[LB_CHECK_SYMBOL_EXPORT([show_task],
[kernel/ksyms.c kernel/sched.c],[
AC_DEFINE(HAVE_SHOW_TASK, 1, [show_task is exported])
],[
        LB_CHECK_SYMBOL_EXPORT([sched_show_task],
        [kernel/ksyms.c kernel/sched.c],[
        AC_DEFINE(HAVE_SCHED_SHOW_TASK, 1, [sched_show_task is exported])
        ],[])
])
])

# check kernel __u64 type
AC_DEFUN([LN_KERN__U64_LONG_LONG],
[AC_MSG_CHECKING([kernel __u64 is long long type])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/types.h>
	#include <linux/stddef.h>
],[
	unsigned long long *data1;
	__u64 *data2 = NULL;
		
	data1 = data2;
],[
	AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_KERN__U64_LONG_LONG, 1,
                  [kernel __u64 is long long type])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

# check userland __u64 type
AC_DEFUN([LN_USER__U64_LONG_LONG],
[AC_MSG_CHECKING([userspace __u64 is long long type])
tmp_flags="$CFLAGS"
CFLAGS="$CFLAGS -Werror"
AC_COMPILE_IFELSE([
	#include <stdio.h>
	#include <linux/types.h>
	#include <linux/stddef.h>
	int main(void) {
		unsigned long long *data1;
		__u64 *data2 = NULL;
		
		data1 = data2;
		return 0;
	}
],[
	AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_USER__U64_LONG_LONG, 1,
                  [userspace __u64 is long long type])
],[
	AC_MSG_RESULT([no])
])
CFLAGS="$tmp_flags"
])

# check kernel __le16, __le32 types
AC_DEFUN([LN_LE_TYPES],
[AC_MSG_CHECKING([__le16 and __le32 types are defined])
LB_LINUX_TRY_COMPILE([
	#include <linux/types.h>
],[
	__le16 a;
	__le32 b;
],[
	AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_LE_TYPES, 1,
                  [__le16 and __le32 types are defined])
],[
	AC_MSG_RESULT([no])
])
])


# check if task_struct with rcu memeber
AC_DEFUN([LN_TASK_RCU],
[AC_MSG_CHECKING([if task_struct has a rcu field])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
        struct task_struct tsk;

        tsk.rcu.next = NULL;
],[
	AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_TASK_RCU, 1,
                  [task_struct has rcu field])
],[
	AC_MSG_RESULT([no])
])
])

# LN_TASKLIST_LOCK
# 2.6.18 remove tasklist_lock export
AC_DEFUN([LN_TASKLIST_LOCK],
[LB_CHECK_SYMBOL_EXPORT([tasklist_lock],
[kernel/fork.c],[
AC_DEFINE(HAVE_TASKLIST_LOCK, 1,
         [tasklist_lock exported])
],[
])
])

# 2.6.19 API changes
# kmem_cache_destroy(cachep) return void instead of
# int
AC_DEFUN([LN_KMEM_CACHE_DESTROY_INT],
[AC_MSG_CHECKING([kmem_cache_destroy(cachep) return int])
LB_LINUX_TRY_COMPILE([
        #include <linux/slab.h>
],[
	int i = kmem_cache_destroy(NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_KMEM_CACHE_DESTROY_INT, 1,
                [kmem_cache_destroy(cachep) return int])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.19 API change
#panic_notifier_list use atomic_notifier operations
#
AC_DEFUN([LN_ATOMIC_PANIC_NOTIFIER],
[AC_MSG_CHECKING([panic_notifier_list is atomic])
LB_LINUX_TRY_COMPILE([
	#include <linux/notifier.h>
	#include <linux/kernel.h>
],[
	struct atomic_notifier_head panic_notifier_list;
],[
        AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_ATOMIC_PANIC_NOTIFIER, 1,
		[panic_notifier_list is atomic_notifier_head])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.20 API change INIT_WORK use 2 args and not
# store data inside
AC_DEFUN([LN_3ARGS_INIT_WORK],
[AC_MSG_CHECKING([check INIT_WORK want 3 args])
LB_LINUX_TRY_COMPILE([
	#include <linux/workqueue.h>
],[
	struct work_struct work;

	INIT_WORK(&work, NULL, NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_3ARGS_INIT_WORK, 1,
                  [INIT_WORK use 3 args and store data inside])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.21 api change. 'register_sysctl_table' use only one argument,
# instead of more old which need two.
AC_DEFUN([LN_2ARGS_REGISTER_SYSCTL],
[AC_MSG_CHECKING([check register_sysctl_table want 2 args])
LB_LINUX_TRY_COMPILE([
        #include <linux/sysctl.h>
],[
	return register_sysctl_table(NULL,0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_2ARGS_REGISTER_SYSCTL, 1,
                  [register_sysctl_table want 2 args])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.21 marks kmem_cache_t deprecated and uses struct kmem_cache
# instead
AC_DEFUN([LN_KMEM_CACHE],
[AC_MSG_CHECKING([check kernel has struct kmem_cache])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
        #include <linux/slab.h>
        typedef struct kmem_cache cache_t;
],[
	cache_t *cachep = NULL;

	kmem_cache_alloc(cachep, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_KMEM_CACHE, 1,
                  [kernel has struct kmem_cache])
],[
        AC_MSG_RESULT(no)
])
EXTRA_KCFLAGS="$tmp_flags"
])

# 2.6.23 lost dtor argument
AC_DEFUN([LN_KMEM_CACHE_CREATE_DTOR],
[AC_MSG_CHECKING([check kmem_cache_create has dtor argument])
LB_LINUX_TRY_COMPILE([
        #include <linux/slab.h>
],[
	kmem_cache_create(NULL, 0, 0, 0, NULL, NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_KMEM_CACHE_CREATE_DTOR, 1,
                  [kmem_cache_create has dtor argument])
],[
        AC_MSG_RESULT(no)
])
])

#
# LN_FUNC_DUMP_TRACE
#
# 2.6.23 exports dump_trace() so we can dump_stack() on any task
# 2.6.24 has stacktrace_ops.address with "reliable" parameter
#
AC_DEFUN([LN_FUNC_DUMP_TRACE],
[LB_CHECK_SYMBOL_EXPORT([dump_trace],
[kernel/ksyms.c arch/${LINUX_ARCH%_64}/kernel/traps_64.c arch/x86/kernel/dumpstack_32.c arch/x86/kernel/dumpstack_64.c],[
	tmp_flags="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="-Werror"
	AC_MSG_CHECKING([whether we can really use dump_trace])
	LB_LINUX_TRY_COMPILE([
		struct task_struct;
		struct pt_regs;
		#include <asm/stacktrace.h>
	],[
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_DUMP_TRACE, 1, [dump_trace is exported])
	],[
		AC_MSG_RESULT(no)
	],[
	])
	AC_MSG_CHECKING([whether print_trace_address has reliable argument])
	LB_LINUX_TRY_COMPILE([
		struct task_struct;
		struct pt_regs;
		void print_addr(void *data, unsigned long addr, int reliable);
		#include <asm/stacktrace.h>
	],[
		struct stacktrace_ops ops;

		ops.address = print_addr;
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_TRACE_ADDRESS_RELIABLE, 1,
			  [print_trace_address has reliable argument])
	],[
		AC_MSG_RESULT(no)
	],[
	])
	AC_MSG_CHECKING([dump_trace want address])
	LB_LINUX_TRY_COMPILE([
		struct task_struct;
		struct pt_regs;
		#include <asm/stacktrace.h>
	],[
		dump_trace(NULL, NULL, NULL, 0, NULL, NULL);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_DUMP_TRACE_ADDRESS, 1,
			  [dump_trace want address argument])
	],[
		AC_MSG_RESULT(no)
	],[
	])
EXTRA_KCFLAGS="$tmp_flags"
])
])

# 2.6.24 request not use real numbers for ctl_name
AC_DEFUN([LN_SYSCTL_UNNUMBERED],
[AC_MSG_CHECKING([for CTL_UNNUMBERED])
LB_LINUX_TRY_COMPILE([
        #include <linux/sysctl.h>
],[
	#ifndef CTL_UNNUMBERED
	#error CTL_UNNUMBERED not exist in kernel
	#endif
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SYSCTL_UNNUMBERED, 1,
                  [sysctl has CTL_UNNUMBERED])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.24 lost scatterlist->page
AC_DEFUN([LN_SCATTERLIST_SETPAGE],
[AC_MSG_CHECKING([for exist sg_set_page])
LB_LINUX_TRY_COMPILE([
        #include <asm/types.h>
        #include <linux/scatterlist.h>
],[
	sg_set_page(NULL,NULL,0,0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SCATTERLIST_SETPAGE, 1,
                  [struct scatterlist has page member])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.26 use int instead of atomic for sem.count
AC_DEFUN([LN_SEM_COUNT],
[AC_MSG_CHECKING([atomic sem.count])
LB_LINUX_TRY_COMPILE([
        #include <asm/semaphore.h>
],[
	struct semaphore s;
	
	atomic_read(&s.count);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SEM_COUNT_ATOMIC, 1,
                  [semaphore counter is atomic])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.27 have second argument to sock_map_fd
AC_DEFUN([LN_SOCK_MAP_FD_2ARG],
[AC_MSG_CHECKING([sock_map_fd have second argument])
LB_LINUX_TRY_COMPILE([
	#include <linux/net.h>
],[
        sock_map_fd(NULL, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SOCK_MAP_FD_2ARG, 1,
                  [sock_map_fd have second argument])
],[
        AC_MSG_RESULT(no)
])
])

# since 2.6.27 have linux/cred.h defined current_* macro
AC_DEFUN([LN_HAVE_LINUX_CRED_H],
[LB_CHECK_FILE([$LINUX/include/linux/cred.h],[
        AC_DEFINE(HAVE_LINUX_CRED_H, 1,
                [kernel has include/linux/cred.h])
],[
        AC_MSG_RESULT([no])
])
])

#
#
# LN_CONFIG_USERSPACE
#
#
AC_DEFUN([LN_CONFIG_USERSPACE],
[
LN_USER__U64_LONG_LONG
])

#
# LN_STRUCT_CRED_IN_TASK
#
# struct cred was introduced in 2.6.29 to streamline credentials in task struct
#
AC_DEFUN([LN_STRUCT_CRED_IN_TASK],
[AC_MSG_CHECKING([if kernel has struct cred])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	struct task_struct *tsk = NULL;
	tsk->real_cred = NULL;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_STRUCT_CRED, 1, [struct cred found])
],[
	AC_MSG_RESULT([no])
])
])

#
# LN_FUNC_UNSHARE_FS_STRUCT
#
# unshare_fs_struct was introduced in 2.6.30 to prevent others to directly
# mess with copy_fs_struct
#
AC_DEFUN([LN_FUNC_UNSHARE_FS_STRUCT],
[AC_MSG_CHECKING([if kernel defines unshare_fs_struct()])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
	#include <linux/fs_struct.h>
],[
	unshare_fs_struct();
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_UNSHARE_FS_STRUCT, 1, [unshare_fs_struct found])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

# See if sysctl proc_handler wants only 5 arguments (since 2.6.32)
AC_DEFUN([LN_5ARGS_SYSCTL_PROC_HANDLER],
[AC_MSG_CHECKING([if sysctl proc_handler wants 5 args])
LB_LINUX_TRY_COMPILE([
	#include <linux/sysctl.h>
],[
        struct ctl_table *table = NULL;
	int write = 1;
	void __user *buffer = NULL;
	size_t *lenp = NULL;
	loff_t *ppos = NULL;

	proc_handler *proc_handler;
	proc_handler(table, write, buffer, lenp, ppos);

],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_5ARGS_SYSCTL_PROC_HANDLER, 1,
                  [sysctl proc_handler wants 5 args])
],[
        AC_MSG_RESULT(no)
])
])

#
# LN_HAVE_IS_COMPAT_TASK
#
# Added in 2.6.17, it wasn't until 2.6.29 that all
# Linux architectures have is_compat_task()
#
AC_DEFUN([LN_HAVE_IS_COMPAT_TASK],
[AC_MSG_CHECKING([if is_compat_task() is declared])
LB_LINUX_TRY_COMPILE([
        #include <linux/compat.h>
],[
        int i = is_compat_task();
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_IS_COMPAT_TASK, 1, [is_compat_task() is available])
],[
        AC_MSG_RESULT([no])
])
])

#
# LN_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LN_PROG_LINUX],
[
LN_HAVE_SCSI_FC_COMPAT_H
LN_FUNC_CPU_ONLINE
LN_TYPE_GFP_T
LN_TYPE_CPUMASK_T
LN_CONFIG_AFFINITY
LN_CONFIG_BACKOFF
LN_CONFIG_PANIC_DUMPLOG
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

LN_STRUCT_PAGE_LIST
LN_STRUCT_SIGHAND
LN_FUNC_SHOW_TASK
LN_KERN__U64_LONG_LONG
LN_LE_TYPES
LN_TASK_RCU
# 2.6.18
LN_TASKLIST_LOCK
LN_HAVE_IS_COMPAT_TASK
# 2.6.19
LN_KMEM_CACHE_DESTROY_INT
LN_ATOMIC_PANIC_NOTIFIER
# 2.6.20
LN_3ARGS_INIT_WORK
# 2.6.21
LN_2ARGS_REGISTER_SYSCTL
LN_KMEM_CACHE
# 2.6.23
LN_KMEM_CACHE_CREATE_DTOR
# 2.6.24
LN_SYSCTL_UNNUMBERED
LN_SCATTERLIST_SETPAGE
# 2.6.26
LN_SEM_COUNT
# 2.6.27
LN_SOCK_MAP_FD_2ARG
LN_FUNC_DUMP_TRACE
LN_HAVE_LINUX_CRED_H
#2.6.29
LN_STRUCT_CRED_IN_TASK
# 2.6.30
LN_FUNC_UNSHARE_FS_STRUCT
# 2.6.32
LN_5ARGS_SYSCTL_PROC_HANDLER
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

# -------- check for -lpthread support ----
AC_MSG_CHECKING([whether to use libpthread for lnet library])
AC_ARG_ENABLE([libpthread],
       	AC_HELP_STRING([--disable-libpthread],
               	[disable libpthread]),
       	[],[enable_libpthread=yes])
if test "$enable_libpthread" = "yes" ; then
	AC_CHECK_LIB([pthread], [pthread_create],
		[ENABLE_LIBPTHREAD="yes"],
		[ENABLE_LIBPTHREAD="no"])
	if test "$ENABLE_LIBPTHREAD" = "yes" ; then
		AC_MSG_RESULT([$ENABLE_LIBPTHREAD])
		PTHREAD_LIBS="-lpthread"
		AC_DEFINE([HAVE_LIBPTHREAD], 1, [use libpthread])
	else
		PTHREAD_LIBS=""
		AC_MSG_RESULT([no libpthread is found])
	fi
	AC_SUBST(PTHREAD_LIBS)
else
	AC_MSG_RESULT([no (disabled explicitly)])
	ENABLE_LIBPTHREAD="no"
fi
AC_SUBST(ENABLE_LIBPTHREAD)

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
lnet/include/libcfs/Makefile
lnet/include/libcfs/linux/Makefile
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
lnet/libcfs/Makefile
lnet/libcfs/autoMakefile
lnet/libcfs/linux/Makefile
lnet/lnet/Makefile
lnet/lnet/autoMakefile
lnet/selftest/Makefile
lnet/selftest/autoMakefile
lnet/ulnds/Makefile
lnet/ulnds/autoMakefile
lnet/ulnds/socklnd/Makefile
lnet/ulnds/ptllnd/Makefile
lnet/utils/Makefile
lnet/include/libcfs/darwin/Makefile
lnet/include/libcfs/winnt/Makefile
lnet/include/lnet/darwin/Makefile
lnet/libcfs/darwin/Makefile
])
])

#
# LIBCFS stub macros. (These are defined in the libcfs module on HEAD))
#
AC_DEFUN([LIBCFS_PATH_DEFAULTS], [])
AC_DEFUN([LIBCFS_PROG_LINUX], [])
AC_DEFUN([LIBCFS_CONDITIONALS], [])
AC_DEFUN([LIBCFS_CONFIGURE], [])
AC_DEFUN([LIBCFS_CONFIG_FILES], [])
