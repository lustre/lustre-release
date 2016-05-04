#
# LN_CONFIG_MAX_PAYLOAD
#
# configure maximum payload
#
AC_DEFUN([LN_CONFIG_MAX_PAYLOAD], [
AC_MSG_CHECKING([for non-default maximum LNET payload])
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
]) # LN_CONFIG_MAX_PAYLOAD

#
# LN_CHECK_GCC_VERSION
#
# Check compiler version
#
AC_DEFUN([LN_CHECK_GCC_VERSION], [
AC_MSG_CHECKING([compiler version])
PTL_CC_VERSION=`$CC --version | awk '/^gcc/{print $ 3}'`
PTL_MIN_CC_VERSION="3.2.2"
v2n() {
	awk -F. '{printf "%d\n", (($ 1)*100+($ 2))*100+($ 3)}'
}
if test -z "$PTL_CC_VERSION" -o \
	$(echo $PTL_CC_VERSION | v2n) -ge $(echo $PTL_MIN_CC_VERSION | v2n); then
	AC_MSG_RESULT([ok])
else
	AC_MSG_RESULT([Buggy compiler found])
	AC_MSG_ERROR([Need gcc version >= $PTL_MIN_CC_VERSION])
fi
]) # LN_CHECK_GCC_VERSION

#
# LN_CONFIG_AFFINITY
#
# check if cpu affinity is available/wanted
#
AC_DEFUN([LN_CONFIG_AFFINITY], [
AC_MSG_CHECKING([whether to enable CPU affinity support])
AC_ARG_ENABLE([affinity],
	AC_HELP_STRING([--disable-affinity],
		[disable process/irq affinity]),
	[], [enable_affinity="yes"])
AC_MSG_RESULT([$enable_affinity])
AS_IF([test "x$enable_affinity" = xyes], [
	LB_CHECK_COMPILE([if Linux kernel has cpu affinity support],
	set_cpus_allowed_ptr, [
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
		AC_DEFINE(CPU_AFFINITY, 1,
			[kernel has cpu affinity support])
	])
])
]) # LN_CONFIG_AFFINITY

#
# LN_CONFIG_BACKOFF
#
# check if tunable tcp backoff is available/wanted
#
AC_DEFUN([LN_CONFIG_BACKOFF], [
AC_MSG_CHECKING([whether to enable tunable backoff TCP support])
AC_ARG_ENABLE([backoff],
	AC_HELP_STRING([--disable-backoff],
		[disable socknal tunable backoff]),
	[], [enable_backoff="yes"])
AC_MSG_RESULT([$enable_backoff])
AS_IF([test "x$enable_backoff" = xyes], [
	AC_MSG_CHECKING([if Linux kernel has tunable backoff TCP support])
	AS_IF([grep -c TCP_BACKOFF $LINUX/include/linux/tcp.h >/dev/null], [
		AC_MSG_RESULT([yes])
		AC_DEFINE(SOCKNAL_BACKOFF, 1, [use tunable backoff TCP])
		AS_IF([grep rto_max $LINUX/include/linux/tcp.h | grep -q __u16 >/dev/null],
			[AC_DEFINE(SOCKNAL_BACKOFF_MS, 1,
				[tunable backoff TCP in ms])])
	], [
		AC_MSG_RESULT([no])
	])
])
]) # LN_CONFIG_BACKOFF

#
# LN_CONFIG_DLC
#
# Configure dlc if enabled
#
# if libyaml is set (IE libyaml installed) and enable_dlc = yes then build
# dlc other wise (IE if libyaml is not set or enable_dlc = no) then don't
# build dlc.
#
AC_DEFUN([LN_CONFIG_DLC], [
	AC_CHECK_LIB([yaml],  [yaml_parser_initialize],[
		LIBYAML="libyaml"],[
		LIBYAML=""],[-lm])
	AC_MSG_CHECKING([whether to enable dlc])
	AC_ARG_ENABLE([dlc],
		AC_HELP_STRING([--disable-dlc],
			[disable building dlc]),
			[], [enable_dlc="yes"])
	USE_DLC=""
	AS_IF([test "x$enable_dlc" = xyes],
		[AS_IF([test "x$LIBYAML" = xlibyaml], [
			USE_DLC="yes"
			AC_MSG_RESULT([yes])
		], [
			AC_MSG_RESULT([no (libyaml not present)])
		])
	], [
		AC_MSG_RESULT([no])
	])
	AC_SUBST(USE_DLC)
])

#
# LN_CONFIG_O2IB
#
# If current OFED installed (assume with "ofed_info") and devel
# headers are not found, error because we assume OFED infiniband
# driver needs to be used and we must configure/build with it.
# Current OFED headers detection mechanism allow for non-standard
# prefix but relies on "ofed_info" command and on "%prefix/openib"
# link (both are ok for 1.5.x and 3.x versions), and should work
# for both source and DKMS builds.
#
AC_DEFUN([LN_CONFIG_O2IB], [
AC_MSG_CHECKING([whether to use Compat RDMA])
AC_ARG_WITH([o2ib],
	AC_HELP_STRING([--with-o2ib=[yes|no|<path>]],
		[build o2iblnd against path]),
	[], [with_o2ib="yes"])

case $with_o2ib in
	yes)    AS_IF([which ofed_info 2>/dev/null], [
			O2IBPATHS=$(ofed_info | egrep -w 'compat-rdma-devel|kernel-ib-devel|ofa_kernel-devel' | xargs rpm -ql | grep '/openib$')
			AS_IF([test -z "$O2IBPATHS"], [
				AC_MSG_ERROR([
You seem to have an OFED installed but have not installed it's devel package.
If you still want to build Lustre for your OFED I/B stack, you need to install its devel headers RPM.
Instead, if you want to build Lustre for your kernel's built-in I/B stack rather than your installed OFED stack, either remove the OFED package(s) or use --with-o2ib=no.
					     ])
			])
			AS_IF([test $(echo $O2IBPATHS | wc -w) -ge 2], [
				AC_MSG_ERROR([
It appears that you have multiple OFED versions installed.
If you still want to build Lustre for your OFED I/B stack, you need to install a single version with its devel headers RPM.
Instead, if you want to build Lustre for your kernel's built-in I/B stack rather than your installed OFED stack, either remove the OFED package(s) or use --with-o2ib=no.
					     ])
			])
			OFED="yes"
		], [
			O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
		])
		ENABLEO2IB="yes"
		;;
	no)     ENABLEO2IB="no"
		;;
	*)      O2IBPATHS=$with_o2ib
		ENABLEO2IB="withpath"
		OFED="yes"
		;;
esac

AS_IF([test $ENABLEO2IB = "no"], [
	AC_MSG_RESULT([no])
], [
	o2ib_found=false
	for O2IBPATH in $O2IBPATHS; do
		AS_IF([test \( -f ${O2IBPATH}/include/rdma/rdma_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_verbs.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_fmr_pool.h \)], [
			o2ib_found=true
			break
		])
	done
	if ! $o2ib_found; then
		AC_MSG_RESULT([no])
		case $ENABLEO2IB in
			"yes") AC_MSG_ERROR([no OFED nor kernel OpenIB gen2 headers present]) ;;
			"withpath") AC_MSG_ERROR([bad --with-o2ib path]) ;;
			*) AC_MSG_ERROR([internal error]) ;;
		esac
	else
		COMPAT_AUTOCONF=""
		compatrdma_found=false
		if test -f ${O2IBPATH}/include/linux/compat-2.6.h; then
			AC_MSG_RESULT([yes])
			compatrdma_found=true
			AC_DEFINE(HAVE_COMPAT_RDMA, 1, [compat rdma found])
			EXTRA_OFED_CONFIG="$EXTRA_OFED_CONFIG -include ${O2IBPATH}/include/linux/compat-2.6.h"
			if test -f "$O2IBPATH/include/linux/compat_autoconf.h"; then
				COMPAT_AUTOCONF="$O2IBPATH/include/linux/compat_autoconf.h"
			fi
		else
			AC_MSG_RESULT([no])
		fi
		if ! $compatrdma_found; then
			if test -f "$O2IBPATH/config.mk"; then
				. "$O2IBPATH/config.mk"
			elif test -f "$O2IBPATH/ofed_patch.mk"; then
				. "$O2IBPATH/ofed_patch.mk"
			fi
		elif test -z "$COMPAT_AUTOCONF"; then
			# Depreciated checks
			if test "x$RHEL_KERNEL" = xyes; then
				RHEL_MAJOR=$(awk '/ RHEL_MAJOR / { print [$]3 }' $LINUX_OBJ/include/$VERSION_HDIR/version.h)
				I=$(awk '/ RHEL_MINOR / { print [$]3 }' $LINUX_OBJ/include/$VERSION_HDIR/version.h)
				while test "$I" -ge 0; do
					EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -DCONFIG_COMPAT_RHEL_${RHEL_MAJOR}_$I"
					I=$(($I-1))
				done
			elif test "x$SUSE_KERNEL" = xyes; then
				SP=$(grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= *//')
				EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -DCONFIG_COMPAT_SLES_11_$SP"
			fi
		fi

		AC_MSG_CHECKING([whether to use any OFED backport headers])
		if test -n "$BACKPORT_INCLUDES"; then
			AC_MSG_RESULT([yes])
			OFED_BACKPORT_PATH="$O2IBPATH/${BACKPORT_INCLUDES/*\/kernel_addons/kernel_addons}/"
			EXTRA_OFED_INCLUDE="-I$OFED_BACKPORT_PATH $EXTRA_OFED_INCLUDE"
		else
			AC_MSG_RESULT([no])
		fi

		O2IBLND=""
		O2IBPATH=$(readlink --canonicalize $O2IBPATH)
		EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -I$O2IBPATH/include"
		LB_CHECK_COMPILE([whether to enable OpenIB gen2 support],
		openib_gen2_support, [
			#ifdef HAVE_COMPAT_RDMA
			#undef PACKAGE_NAME
			#undef PACKAGE_TARNAME
			#undef PACKAGE_VERSION
			#undef PACKAGE_STRING
			#undef PACKAGE_BUGREPORT
			#undef PACKAGE_URL
			#include <linux/compat-2.6.h>
			#endif
			#include <linux/version.h>
			#include <linux/pci.h>
			#include <linux/gfp.h>
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
			O2IBLND="o2iblnd"
		],[
			case $ENABLEO2IB in
			"yes") AC_MSG_ERROR([can't compile with OpenIB gen2 headers]) ;;
			"withpath") AC_MSG_ERROR([can't compile with OpenIB gen2 headers under $O2IBPATH]) ;;
			*) AC_MSG_ERROR([internal error]) ;;
			esac
		])
		# we know at this point that the found OFED source is good
		O2IB_SYMVER=""
		if test $ENABLEO2IB = "withpath" -o "x$OFED" = "xyes" ; then
			# OFED default rpm not handle sles10 Modules.symvers name
			for name in Module.symvers Modules.symvers; do
				if test -f $O2IBPATH/$name; then
					O2IB_SYMVER=$name;
					break;
				fi
			done
			if test -n "$O2IB_SYMVER"; then
				AC_MSG_NOTICE([adding $O2IBPATH/$O2IB_SYMVER to Symbol Path])
				EXTRA_SYMBOLS="$EXTRA_SYMBOLS $O2IBPATH/$O2IB_SYMVER"
				AC_SUBST(EXTRA_SYMBOLS)
			else
				AC_MSG_ERROR([an external source tree was, either specified or detected, for o2iblnd however I could not find a $O2IBPATH/Module.symvers there])
			fi
		fi

		LB_CHECK_COMPILE([if Linux kernel has kthread_worker],
		linux_kthread_worker, [
			#ifdef HAVE_COMPAT_RDMA
			#undef PACKAGE_NAME
			#undef PACKAGE_TARNAME
			#undef PACKAGE_VERSION
			#undef PACKAGE_STRING
			#undef PACKAGE_BUGREPORT
			#undef PACKAGE_URL
			#include <linux/compat-2.6.h>
			#endif
			#include <linux/kthread.h>
		],[
			struct kthread_work	*kth_wrk __attribute__ ((unused));
			flush_kthread_work(kth_wrk);
		],[
			AC_DEFINE(HAVE_KTHREAD_WORK, 1, [kthread_worker found])
			if test -z "$COMPAT_AUTOCONF"; then
				EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -DCONFIG_COMPAT_IS_KTHREAD"
			fi
		])
	fi
])
AC_SUBST(EXTRA_OFED_CONFIG)
AC_SUBST(EXTRA_OFED_INCLUDE)
AC_SUBST(O2IBLND)
AC_SUBST(O2IBPATH)
AC_SUBST(ENABLEO2IB)

# In RHEL 6.2, rdma_create_id() takes the queue-pair type as a fourth argument
AS_IF([test $ENABLEO2IB != "no"], [
	LB_CHECK_COMPILE([if 'rdma_create_id' wants four args],
	rdma_create_id_4args, [
		#ifdef HAVE_COMPAT_RDMA
		#undef PACKAGE_NAME
		#undef PACKAGE_TARNAME
		#undef PACKAGE_VERSION
		#undef PACKAGE_STRING
		#undef PACKAGE_BUGREPORT
		#undef PACKAGE_URL
		#include <linux/compat-2.6.h>
		#endif
		#include <rdma/rdma_cm.h>
	],[
		rdma_create_id(NULL, NULL, 0, 0);
	],[
		AC_DEFINE(HAVE_RDMA_CREATE_ID_4ARG, 1,
			[rdma_create_id wants 4 args])
	])
])
#
# 4.2 introduced struct ib_cq_init_attr which is used
# by ib_create_cq(). Note some OFED stacks only keep
# their headers in sync with latest kernels but not
# the functionality which means for infiniband testing
# we need to always test functionality testings.
#
AS_IF([test $ENABLEO2IB != "no"], [
	LB_CHECK_COMPILE([if 'struct ib_cq_init_attr' is used],
	ib_cq_init_attr, [
		#ifdef HAVE_COMPAT_RDMA
		#undef PACKAGE_NAME
		#undef PACKAGE_TARNAME
		#undef PACKAGE_VERSION
		#undef PACKAGE_STRING
		#undef PACKAGE_BUGREPORT
		#undef PACKAGE_URL
		#include <linux/compat-2.6.h>
		#endif
		#include <rdma/ib_verbs.h>
	],[
		struct ib_cq_init_attr cq_attr;

		ib_create_cq(NULL, NULL, NULL, NULL, &cq_attr);
	],[
		AC_DEFINE(HAVE_IB_CQ_INIT_ATTR, 1,
			[struct ib_cq_init_attr is used by ib_create_cq])
	])
])

# 4.3 removed ib_alloc_fast_reg_mr()
AS_IF([test $ENABLEO2IB != "no"], [
	LB_CHECK_COMPILE([if 'ib_alloc_fast_reg_mr' exists],
	ib_alloc_fast_reg_mr, [
		#ifdef HAVE_COMPAT_RDMA
		#undef PACKAGE_NAME
		#undef PACKAGE_TARNAME
		#undef PACKAGE_VERSION
		#undef PACKAGE_STRING
		#undef PACKAGE_BUGREPORT
		#undef PACKAGE_URL
		#include <linux/compat-2.6.h>
		#endif
		#include <rdma/ib_verbs.h>
	],[
		ib_alloc_fast_reg_mr(NULL, 0);
	],[
		AC_DEFINE(HAVE_IB_ALLOC_FAST_REG_MR, 1,
			[ib_alloc_fast_reg_mr is defined])
	])
])

# 4.4 added network namespace parameter for rdma_create_id()
AS_IF([test $ENABLEO2IB != "no"], [
	LB_CHECK_COMPILE([if 'rdma_create_id' wants five args],
	rdma_create_id_5args, [
		#ifdef HAVE_COMPAT_RDMA
		#undef PACKAGE_NAME
		#undef PACKAGE_TARNAME
		#undef PACKAGE_VERSION
		#undef PACKAGE_STRING
		#undef PACKAGE_BUGREPORT
		#undef PACKAGE_URL
		#include <linux/compat-2.6.h>
		#endif
		#include <rdma/rdma_cm.h>
	],[
		rdma_create_id(NULL, NULL, NULL, 0, 0);
	],[
		AC_DEFINE(HAVE_RDMA_CREATE_ID_5ARG, 1,
			[rdma_create_id wants 5 args])
	])
])

# new fast registration API introduced in 4.4
AS_IF([test $ENABLEO2IB != "no"], [
	LB_CHECK_COMPILE([if 'ib_map_mr_sg' exists],
	ib_map_mr_sg, [
		#ifdef HAVE_COMPAT_RDMA
		#undef PACKAGE_NAME
		#undef PACKAGE_TARNAME
		#undef PACKAGE_VERSION
		#undef PACKAGE_STRING
		#undef PACKAGE_BUGREPORT
		#undef PACKAGE_URL
		#include <linux/compat-2.6.h>
		#endif
		#include <rdma/ib_verbs.h>
	],[
		ib_map_mr_sg(NULL, NULL, 0, 0);
	],[
		AC_DEFINE(HAVE_IB_MAP_MR_SG, 1,
			[ib_map_mr_sg exists])
	])
])
]) # LN_CONFIG_O2IB

#
# LN_CONFIG_GNILND
#
# check whether to use the Gemini Network Interface lnd
#
AC_DEFUN([LN_CONFIG_GNILND], [
AC_MSG_CHECKING([whether to enable GNI lnd])
AC_ARG_ENABLE([gni],
	AC_HELP_STRING([--enable-gni],
		[enable GNI lnd]),
	[], [enable_gni="no"])
AC_MSG_RESULT([$enable_gni])

AS_IF([test "x$enable_gni" = xyes], [
	# GNICPPFLAGS was set in spec file
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $GNICPPFLAGS"
	LB_CHECK_COMPILE([if GNI kernel headers are present],
	GNI_header, [
		#include <linux/types.h>
		#include <gni_pub.h>
	],[
		gni_cdm_handle_t kgni_domain;
		gni_return_t	 rc;
		int		 rrc;
		rc = gni_cdm_create(0, 1, 1, 0, &kgni_domain);
		rrc = (rc == GNI_RC_SUCCESS) ? 0 : 1;
		return rrc;
	],[
		GNILND="gnilnd"
	],[
		AC_MSG_ERROR([can't compile gnilnd with given GNICPPFLAGS: $GNICPPFLAGS])
	])
	# at this point, we have gnilnd basic support,
	# now check for extra features
	LB_CHECK_COMPILE([to use RCA in gnilnd],
	RCA_gnilnd, [
		#include <linux/types.h>
		#include <gni_pub.h>
		#include <krca_lib.h>
	],[
		gni_cdm_handle_t kgni_domain;
		gni_return_t	 rc;
		krca_ticket_t	 ticket = KRCA_NULL_TICKET;
		int		 rrc;
		__u32		 nid = 0, nic_addr;
		rc = gni_cdm_create(0, 1, 1, 0, &kgni_domain);
		rrc = (rc == GNI_RC_SUCCESS) ? 0 : 1;
		rrc += krca_nid_to_nicaddrs(nid, 1, &nic_addr);
		rrc += krca_register(&ticket, RCA_MAKE_SERVICE_INDEX(RCA_IO_CLASS, 9), 99, 0);
		return rrc;
	],[
		GNICPPFLAGS="$GNICPPFLAGS -DGNILND_USE_RCA=1"
	])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
])
AC_SUBST(GNICPPFLAGS)
AC_SUBST(GNILND)
]) # LN_CONFIG_GNILND

#
# LN_CONFIG_SK_SLEEP
#
# 2.6.35 kernel has sk_sleep function
#
AC_DEFUN([LN_CONFIG_SK_SLEEP], [
LB_CHECK_COMPILE([if Linux kernel has 'sk_sleep'],
sk_sleep, [
	#ifdef HAVE_COMPAT_RDMA
	#undef PACKAGE_NAME
	#undef PACKAGE_TARNAME
	#undef PACKAGE_VERSION
	#undef PACKAGE_STRING
	#undef PACKAGE_BUGREPORT
	#undef PACKAGE_URL
	#include <linux/compat-2.6.h>
	#endif
	#include <net/sock.h>
],[
	sk_sleep(NULL);
],[
	AC_DEFINE(HAVE_SK_SLEEP, 1,
		  [kernel has sk_sleep])
])
]) # LN_CONFIG_SK_SLEEP

#
# LN_CONFIG_TCP_SENDPAGE
#
# 2.6.36 tcp_sendpage() first parameter is 'struct sock' instead of 'struct socket'.
#
AC_DEFUN([LN_CONFIG_TCP_SENDPAGE], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'tcp_sendpage' first parameter is socket],
tcp_sendpage_socket, [
	#ifdef HAVE_COMPAT_RDMA
	#undef PACKAGE_NAME
	#undef PACKAGE_TARNAME
	#undef PACKAGE_VERSION
	#undef PACKAGE_STRING
	#undef PACKAGE_BUGREPORT
	#undef PACKAGE_URL
	#include <linux/compat-2.6.h>
	#endif
	#include <linux/net.h>
	#include <net/tcp.h>
],[
	tcp_sendpage((struct socket*)0, NULL, 0, 0, 0);
],[
	AC_DEFINE(HAVE_TCP_SENDPAGE_USE_SOCKET, 1,
		[tcp_sendpage use socket as first parameter])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_CONFIG_TCP_SENDPAGE

#
# LN_CONFIG_SK_DATA_READY
#
# 3.15 for struct sock the *sk_data_ready() field only takes one argument now
#
AC_DEFUN([LN_CONFIG_SK_DATA_READY], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'sk_data_ready' takes only one argument],
sk_data_ready, [
	#ifdef HAVE_COMPAT_RDMA
	#undef PACKAGE_NAME
	#undef PACKAGE_TARNAME
	#undef PACKAGE_VERSION
	#undef PACKAGE_STRING
	#undef PACKAGE_BUGREPORT
	#undef PACKAGE_URL
	#include <linux/compat-2.6.h>
	#endif
	#include <linux/net.h>
	#include <net/sock.h>
],[
	((struct sock *)0)->sk_data_ready(NULL);
],[
	AC_DEFINE(HAVE_SK_DATA_READY_ONE_ARG, 1,
		[sk_data_ready uses only one argument])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_CONFIG_SK_DATA_READY

#
# LN_CONFIG_IB_INC_RKEY
#
AC_DEFUN([LN_CONFIG_IB_INC_RKEY], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if function 'ib_inc_rkey' is defined],
ib_inc_rkey, [
	#ifdef HAVE_COMPAT_RDMA
	#undef PACKAGE_NAME
	#undef PACKAGE_TARNAME
	#undef PACKAGE_VERSION
	#undef PACKAGE_STRING
	#undef PACKAGE_BUGREPORT
	#undef PACKAGE_URL
	#include <linux/compat-2.6.h>
	#endif
	#include <rdma/ib_verbs.h>
],[
	(void)ib_inc_rkey(0);
],[
	AC_DEFINE(HAVE_IB_INC_RKEY, 1,
		  [function ib_inc_rkey exist])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_CONFIG_IB_INC_RKEY

#
# LN_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LN_PROG_LINUX], [
AC_MSG_NOTICE([LNet kernel checks
==============================================================================])

LN_CONFIG_AFFINITY
LN_CONFIG_BACKOFF
LN_CONFIG_O2IB
LN_CONFIG_GNILND
LN_CONFIG_IB_INC_RKEY
# 2.6.35
LN_CONFIG_SK_SLEEP
# 2.6.36
LN_CONFIG_TCP_SENDPAGE
# 3.15
LN_CONFIG_SK_DATA_READY
]) # LN_PROG_LINUX

#
# LN_PATH_DEFAULTS
#
# default paths for installed files
#
AC_DEFUN([LN_PATH_DEFAULTS], [
]) # LN_PATH_DEFAULTS

#
# LN_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LN_CONFIGURE], [
AC_MSG_NOTICE([LNet core checks
==============================================================================])

# lnet/utils/portals.c
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_FUNCS([gethostbyname])

# lnet/utils/wirecheck.c
AC_CHECK_FUNCS([strnlen])

# --------  Check for required packages  --------------

AC_MSG_CHECKING([whether to enable 'efence' debugging support])
AC_ARG_ENABLE(efence,
	AC_HELP_STRING([--enable-efence],
		[use efence library]),
	[], [enable_efence="no"])
AC_MSG_RESULT([$enable_efence])

LIBEFENCE=""
AS_IF([test "$enable_efence" = yes], [
	LIBEFENCE="-lefence"
	AC_DEFINE(HAVE_LIBEFENCE, 1,
		[libefence support is requested])
])
AC_SUBST(LIBEFENCE)

LN_CONFIG_MAX_PAYLOAD
LN_CONFIG_DLC
]) # LN_CONFIGURE

#
# LN_CONDITIONALS
#
# AM_CONDITIONAL defines for lnet
#
AC_DEFUN([LN_CONDITIONALS], [
AM_CONDITIONAL(BUILD_O2IBLND,    test x$O2IBLND = "xo2iblnd")
AM_CONDITIONAL(BUILD_GNILND,     test x$GNILND  = "xgnilnd")
AM_CONDITIONAL(BUILD_DLC,        test x$USE_DLC = "xyes")
]) # LN_CONDITIONALS

#
# LN_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LN_CONFIG_FILES], [
AC_CONFIG_FILES([
lnet/Makefile
lnet/autoMakefile
lnet/autoconf/Makefile
lnet/doc/Makefile
lnet/include/Makefile
lnet/include/lnet/Makefile
lnet/klnds/Makefile
lnet/klnds/autoMakefile
lnet/klnds/o2iblnd/Makefile
lnet/klnds/o2iblnd/autoMakefile
lnet/klnds/gnilnd/Makefile
lnet/klnds/gnilnd/autoMakefile
lnet/klnds/socklnd/Makefile
lnet/klnds/socklnd/autoMakefile
lnet/lnet/Makefile
lnet/lnet/autoMakefile
lnet/selftest/Makefile
lnet/selftest/autoMakefile
lnet/utils/Makefile
lnet/utils/lnetconfig/Makefile
])
]) # LN_CONFIG_FILES
