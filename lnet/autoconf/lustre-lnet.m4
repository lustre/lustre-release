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
		CONFIG_LNET_MAX_PAYLOAD_MB=$with_max_payload_mb
		CONFIG_LNET_MAX_PAYLOAD="(($with_max_payload_mb)<<20)"
	], [
		AC_MSG_RESULT([no])
		CONFIG_LNET_MAX_PAYLOAD="LNET_MTU"
	])
	AC_DEFINE_UNQUOTED(CONFIG_LNET_MAX_PAYLOAD, $CONFIG_LNET_MAX_PAYLOAD,
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
# LN_FUNC_DEV_GET_BY_NAME_2ARG
#
AC_DEFUN([LN_FUNC_DEV_GET_BY_NAME_2ARG],
[AC_MSG_CHECKING([if dev_get_by_name has two args])
LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
],[
        dev_get_by_name(NULL, NULL);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_DEV_GET_BY_NAME_2ARG, 1, [dev_get_by_name has 2 args])
],[
	AC_MSG_RESULT([no])
])
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
		struct task_struct *t;
		#if HAVE_CPUMASK_T
		cpumask_t     m;
	        #else
	        unsigned long m;
		#endif
		set_cpus_allowed_ptr(t, &m);
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
	PORTALS=$(readlink --canonicalize $PORTALS)
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
		QSNET=$(readlink --canonicalize $QSNET)
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
       MXPATH=$(readlink --canonicalize $MXPATH)
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
AC_DEFUN([LN_CONFIG_O2IB],
[AC_MSG_CHECKING([whether to use Compat RDMA])
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
	AC_MSG_RESULT([no])
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
		compatrdma_found=false
		if test -f ${O2IBPATH}/include/linux/compat-2.6.h; then
			compatrdma_found=true
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_COMPAT_RDMA, 1, [compat rdma found])
		else
			AC_MSG_RESULT([no])
		fi
		if ! $compatrdma_found; then
			if test -f $O2IBPATH/config.mk; then
				. $O2IBPATH/config.mk
			elif test -f $O2IBPATH/ofed_patch.mk; then
				. $O2IBPATH/ofed_patch.mk
			fi
		else
			if test x$RHEL_KERNEL = xyes; then
				case $RHEL_KERNEL_VERSION in
					2.6.32-358*)
						EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -DCONFIG_COMPAT_RHEL_6_4";;
					2.6.32-431*)
						EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -DCONFIG_COMPAT_RHEL_6_4 -DCONFIG_COMPAT_RHEL_6_5";;
				esac
			elif test x$SUSE_KERNEL = xyes; then
				SP=$(grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= *//')
				EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -DCONFIG_COMPAT_SLES_11_$SP"
			fi
		fi
		AC_MSG_CHECKING([whether to use any OFED backport headers])
		if test -n "$BACKPORT_INCLUDES"; then
			OFED_BACKPORT_PATH="$O2IBPATH/${BACKPORT_INCLUDES/*\/kernel_addons/kernel_addons}/"
			EXTRA_OFED_INCLUDE="-I$OFED_BACKPORT_PATH $EXTRA_OFED_INCLUDE"
			AC_MSG_RESULT([yes])
		else
			AC_MSG_RESULT([no])
		fi

		AC_MSG_CHECKING([whether to enable OpenIB gen2 support])
		O2IBPATH=$(readlink --canonicalize $O2IBPATH)
		EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -I$O2IBPATH/include"

		LB_LINUX_TRY_COMPILE([
		        #include <linux/version.h>
		        #include <linux/pci.h>
			#include <linux/gfp.h>
			#ifdef HAVE_COMPAT_RDMA
			#include <linux/compat-2.6.h>
			#endif
		        #include <rdma/rdma_cm.h>
		        #include <rdma/ib_cm.h>
		        #include <rdma/ib_verbs.h>
		        #include <rdma/ib_fmr_pool.h>
		],[
		        struct rdma_cm_id      *cm_idi __attribute__ ((unused));
		        struct rdma_conn_param  conn_param __attribute__ ((unused));
		        struct ib_device_attr   device_attr __attribute__ ((unused));
		        struct ib_qp_attr       qp_attr __attribute__ ((unused));
		        struct ib_pool_fmr      pool_fmr __attribute__ ((unused));
		        enum   ib_cm_rej_reason rej_reason __attribute__ ((unused));

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
				AC_MSG_NOTICE([adding $O2IBPATH/$O2IB_SYMVER to $PWD/$SYMVERFILE])
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
	fi
fi

AC_SUBST(EXTRA_OFED_INCLUDE)
AC_SUBST(O2IBLND)

# In RHEL 6.2, rdma_create_id() takes the queue-pair type as a fourth argument
if test $ENABLEO2IB -ne 0; then
	AC_MSG_CHECKING([if rdma_create_id wants four args])
	LB_LINUX_TRY_COMPILE([
		#ifdef HAVE_COMPAT_RDMA
		#include <linux/compat-2.6.h>
		#endif
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
# LN_CONFIG_GNILND
#
# check whether to use the Gemini Network Interface lnd
#
AC_DEFUN([LN_CONFIG_GNILND],
[#### Gemini Network Interface
AC_MSG_CHECKING([whether to enable GNI lnd])
AC_ARG_ENABLE([gni],
	AC_HELP_STRING([--enable-gni],
			[enable GNI lnd]),
	[],[enable_gni='no'])
AC_MSG_RESULT([$enable_gni])

if test x$enable_gni = xyes ; then
	AC_MSG_CHECKING([if GNI kernel headers are present])
	# placeholder
	# GNICPPFLAGS was set in spec file
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $GNICPPFLAGS"
	LB_LINUX_TRY_COMPILE([
		#include <linux/types.h>
		#include <gni_pub.h>
	],[
		gni_cdm_handle_t	kgni_domain;
		gni_return_t		rc;
		int			rrc;

		rc = gni_cdm_create(0, 1, 1, 0, &kgni_domain);

		rrc = (rc == GNI_RC_SUCCESS) ? 0 : 1;

		return rrc;
	],[
		AC_MSG_RESULT([yes])
		GNILND="gnilnd"
	],[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([can't compile gnilnd with given GNICPPFLAGS: $GNICPPFLAGS])
	])
	# at this point, we have gnilnd basic support, now check for extra features
	AC_MSG_CHECKING([to use RCA in gnilnd])
	LB_LINUX_TRY_COMPILE([
		#include <linux/types.h>
		#include <gni_pub.h>
		#include <krca_lib.h>
	],[
		gni_cdm_handle_t	kgni_domain;
		gni_return_t		rc;
		krca_ticket_t		ticket = KRCA_NULL_TICKET;
		int			rrc;
		__u32			nid = 0, nic_addr;

		rc = gni_cdm_create(0, 1, 1, 0, &kgni_domain);

		rrc = (rc == GNI_RC_SUCCESS) ? 0 : 1;

		rrc += krca_nid_to_nicaddrs(nid, 1, &nic_addr);

		rrc += krca_register(&ticket, RCA_MAKE_SERVICE_INDEX(RCA_IO_CLASS, 9), 99, 0);

		return rrc;
	],[
		AC_MSG_RESULT([yes])
		GNICPPFLAGS="$GNICPPFLAGS -DGNILND_USE_RCA=1"
		GNILNDRCA="gnilndrca"
	],[
		AC_MSG_RESULT([no])
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
fi
AC_SUBST(GNICPPFLAGS)
AC_SUBST(GNILNDRCA)
AC_SUBST(GNILND)
])


#
#
# LN_CONFIG_USERSPACE
#
# This is defined but empty because it is called from
# build/autconf/lustre-build.m4 which is shared by all branches.
#
AC_DEFUN([LN_CONFIG_USERSPACE],
[
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

        proc_handler *proc_handler = NULL;
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
# 2.6.36 tcp_sendpage() first parameter is 'struct sock' instead of 'struct socket'.
#
AC_DEFUN([LN_CONFIG_TCP_SENDPAGE],
[AC_MSG_CHECKING([if tcp_sendpage first parameter is socket])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
        #include <linux/net.h>
        #include <net/tcp.h>
],[
        tcp_sendpage((struct socket*)0, NULL, 0, 0, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_TCP_SENDPAGE_USE_SOCKET, 1,
                  [tcp_sendpage use socket as first parameter])
],[
        AC_MSG_RESULT(no)
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# LN_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LN_PROG_LINUX],
[
LN_FUNC_DEV_GET_BY_NAME_2ARG
LN_CONFIG_AFFINITY
LN_CONFIG_BACKOFF
LN_CONFIG_QUADRICS
LN_CONFIG_O2IB
LN_CONFIG_RALND
LN_CONFIG_GNILND
LN_CONFIG_PTLLND
LN_CONFIG_MX
# 2.6.32
LN_5ARGS_SYSCTL_PROC_HANDLER
# 2.6.36
LN_CONFIG_TCP_SENDPAGE
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
AM_CONDITIONAL(BUILD_MXLND, test x$MXLND = "xmxlnd")
AM_CONDITIONAL(BUILD_O2IBLND, test x$O2IBLND = "xo2iblnd")
AM_CONDITIONAL(BUILD_RALND, test x$RALND = "xralnd")
AM_CONDITIONAL(BUILD_GNILND, test x$GNILND = "xgnilnd")
AM_CONDITIONAL(BUILD_GNILND_RCA, test x$GNILNDRCA = "xgnilndrca")
AM_CONDITIONAL(BUILD_PTLLND, test x$PTLLND = "xptllnd")
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
lnet/klnds/mxlnd/autoMakefile
lnet/klnds/mxlnd/Makefile
lnet/klnds/o2iblnd/Makefile
lnet/klnds/o2iblnd/autoMakefile
lnet/klnds/qswlnd/Makefile
lnet/klnds/qswlnd/autoMakefile
lnet/klnds/ralnd/Makefile
lnet/klnds/ralnd/autoMakefile
lnet/klnds/gnilnd/Makefile
lnet/klnds/gnilnd/autoMakefile
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
lnet/utils/Makefile
lnet/include/lnet/darwin/Makefile
])
])
