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
# Configure dlc
#
# fail to build if libyaml is not installed
#
AC_DEFUN([LN_CONFIG_DLC], [
	AS_IF([test "x$enable_dist" = xno], [
		AC_CHECK_LIB([yaml], [yaml_parser_initialize],
			     [LIBYAML="libyaml"],
			     [AC_MSG_ERROR([YAML development libraries not not installed])],
			     [-lm])
	])
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
			AS_IF([test x$uses_dpkg = xyes], [
				OFED_INFO="ofed_info | awk '{print \[$]2}'"
				LSPKG="dpkg --listfiles"
			], [
				OFED_INFO="ofed_info"
				LSPKG="rpm -ql"
			])
			O2IBPATHS=$(eval $OFED_INFO | egrep -w 'mlnx-ofed-kernel-dkms|mlnx-ofa_kernel-devel|compat-rdma-devel|kernel-ib-devel|ofa_kernel-devel' | xargs $LSPKG | grep '\(/openib\|/ofa_kernel/default\|/ofa_kernel\)$' | head -n1)
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
			if test -e $O2IBPATHS/${LINUXRELEASE}; then
			    O2IBPATHS=$O2IBPATHS/${LINUXRELEASE}
			elif test -e $O2IBPATHS/default; then
			    O2IBPATHS=$O2IBPATHS/default
			fi
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
	AC_DEFUN([LN_CONFIG_O2IB_SRC], [])
	AC_DEFUN([LN_CONFIG_O2IB_RESULTS], [])
], [
	o2ib_found=false
	for O2IBPATH in $O2IBPATHS; do
		AS_IF([test \( -f ${O2IBPATH}/include/rdma/rdma_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_verbs.h \)], [
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
		EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -I$O2IBPATH/include -I$O2IBPATH/include/uapi"
		EXTRA_CHECK_INCLUDE="$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE"
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
		],[
			struct rdma_cm_id      *cm_idi __attribute__ ((unused));
			struct rdma_conn_param  conn_param __attribute__ ((unused));
			struct ib_device_attr   device_attr __attribute__ ((unused));
			struct ib_qp_attr       qp_attr __attribute__ ((unused));
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
			if test -f $O2IBPATH/Module.symvers; then
				O2IB_SYMVER=$O2IBPATH/Module.symvers;
				break;
			fi
			if test -n "$O2IB_SYMVER"; then
				AC_MSG_NOTICE([adding $O2IB_SYMVER to Symbol Path])
				EXTRA_SYMBOLS="$EXTRA_SYMBOLS $O2IB_SYMVER"
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
			struct kthread_work *kth_wrk = NULL;
			flush_kthread_work(kth_wrk);
		],[
			AC_DEFINE(HAVE_KTHREAD_WORK, 1, [kthread_worker found])
			if test -z "$COMPAT_AUTOCONF"; then
				EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -DCONFIG_COMPAT_IS_KTHREAD"
			fi
		])
		EXTRA_CHECK_INCLUDE=""
	fi
])
AC_SUBST(EXTRA_OFED_CONFIG)
AC_SUBST(EXTRA_OFED_INCLUDE)
AC_SUBST(O2IBLND)
AC_SUBST(O2IBPATH)
AC_SUBST(ENABLEO2IB)

AS_IF([test $ENABLEO2IB != "no"], [
	EXTRA_CHECK_INCLUDE="$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE"
	KBUILD_EXTRA_SYMBOLS="$KBUILD_EXTRA_SYMBOLS $O2IBPATH/Module.symvers"

	# In RHEL 6.2, rdma_create_id() takes the queue-pair type as a fourth argument
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

	# 4.4 added network namespace parameter for rdma_create_id()
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

	# 4.2 introduced struct ib_cq_init_attr which is used
	# by ib_create_cq(). Note some OFED stacks only keep
	# their headers in sync with latest kernels but not
	# the functionality which means for infiniband testing
	# we need to always test functionality testings.
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

	# 4.3 removed ib_alloc_fast_reg_mr()
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

	# 4.9 must stop using ib_get_dma_mr and the global MR
	# We then have to use FMR/Fastreg for all RDMA.
	LB_CHECK_COMPILE([if 'ib_get_dma_mr' exists],
	ib_get_dma_mr, [
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
		ib_get_dma_mr(NULL, 0);
	],[
		AC_DEFINE(HAVE_IB_GET_DMA_MR, 1,
			[ib_get_dma_mr is defined])
	])

	# In v4.4 Linux kernel,
	# commit e622f2f4ad2142d2a613a57fb85f8cf737935ef5
	# split up struct ib_send_wr so that all non-trivial verbs
	# use their own structure which embedds struct ib_send_wr.
	LB_CHECK_COMPILE([if 'struct ib_rdma_wr' is defined],
	ib_rdma_wr, [
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
		struct ib_rdma_wr *wr __attribute__ ((unused));

		wr = rdma_wr(NULL);
	],[
		AC_DEFINE(HAVE_IB_RDMA_WR, 1,
			[struct ib_rdma_wr is defined])
	])

	# new fast registration API introduced in 4.4
	LB_CHECK_COMPILE([if 4arg 'ib_map_mr_sg' exists],
	ib_map_mr_sg_4args, [
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

	# ib_map_mr_sg changes from 4 to 5 args (adding sg_offset_p)
	# in kernel 4.7 (and RHEL 7.3)
	LB_CHECK_COMPILE([if 5arg 'ib_map_mr_sg' exists],
	ib_map_mr_sg_5args, [
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
		ib_map_mr_sg(NULL, NULL, 0, NULL, 0);
	],[
		AC_DEFINE(HAVE_IB_MAP_MR_SG, 1,
			[ib_map_mr_sg exists])
		AC_DEFINE(HAVE_IB_MAP_MR_SG_5ARGS, 1,
			[ib_map_mr_sg has 5 arguments])
	])

	# ib_query_device() removed in 4.5
	LB_CHECK_COMPILE([if 'struct ib_device' has member 'attrs'],
	ib_device.attrs, [
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
		struct ib_device dev;
		struct ib_device_attr dev_attr = {};
		dev.attrs = dev_attr;
	],[
		AC_DEFINE(HAVE_IB_DEVICE_ATTRS, 1,
			[struct ib_device.attrs is defined])
	])

	# A flags argument was added to ib_alloc_pd() in Linux 4.9,
	# commit ed082d36a7b2c27d1cda55fdfb28af18040c4a89
	LB_CHECK_COMPILE([if 2arg 'ib_alloc_pd' exists],
	ib_alloc_pd, [
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
		ib_alloc_pd(NULL, 0);
	],[
		AC_DEFINE(HAVE_IB_ALLOC_PD_2ARGS, 1,
			[ib_alloc_pd has 2 arguments])
	])

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

	# In MOFED 4.6, the second and third parameters for
	# ib_post_send() and ib_post_recv() are declared with
	# 'const'.
	tmp_flags="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="-Werror"
	LB_CHECK_COMPILE([if 'ib_post_send() and ib_post_recv()' have const parameters],
	ib_post_send_recv_const, [
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
		ib_post_send(NULL, (const struct ib_send_wr *)NULL,
			     (const struct ib_send_wr **)NULL);
	],[
		AC_DEFINE(HAVE_IB_POST_SEND_RECV_CONST, 1,
			[ib_post_send and ib_post_recv have const parameters])
	])
	EXTRA_KCFLAGS="$tmp_flags"

	# 5.0
	LN_IB_DEVICE_OPS_EXISTS
	# 5.1
	LN_IB_SG_DMA_ADDRESS_EXISTS

	# A reason argument was added to rdma_reject() in Linux 5.8,
	# commit 8094ba0ace7f6cd1e31ea8b151fba3594cadfa9a
	LB_CHECK_COMPILE([if 4arg 'rdma_reject' exists],
	rdma_reject, [
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
		#include <rdma/ib_cm.h>
		#include <rdma/rdma_cm.h>
	],[
		rdma_reject(NULL, NULL, 0, 0);
	],[
		AC_DEFINE(HAVE_RDMA_REJECT_4ARGS, 1,
			[rdma_reject has 4 arguments])
	])

	# The FMR pool API was removed in Linux 5.8,
	# commit 4e373d5417ecbb4f438a8500f0379a2fc29c2643
	LB_CHECK_COMPILE([if FMR pools API available],
	ib_fmr, [
		#include <rdma/ib_verbs.h>
	],[
		struct ib_fmr fmr = {};
	],[
		AC_DEFINE(HAVE_FMR_POOL_API, 1,
			[FMR pool API is available])
	])

	# rdma_connect_locked() was added in Linux 5.10,
	# commit 071ba4cc559de47160761b9500b72e8fa09d923d
	# and in MOFED-5.2-2. rdma_connect_locked() must
	# be called instead of rdma_connect() in
	# RDMA_CM_EVENT_ROUTE_RESOLVED handler.
	LB_CHECK_COMPILE([if 'rdma_connect_locked' exists],
	rdma_connect_locked, [
		#include <rdma/rdma_cm.h>
	],[
		rdma_connect_locked(NULL, NULL);
	],[
		AC_DEFINE(HAVE_RDMA_CONNECT_LOCKED, 1,
			[rdma_connect_locked is defined])
	])

	EXTRA_CHECK_INCLUDE=""
	AC_DEFUN([LN_CONFIG_O2IB_SRC], [])
	AC_DEFUN([LN_CONFIG_O2IB_RESULTS], [])
]) # ENABLEO2IB != "no"
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

# LN_CONFIG_SOCK_CREATE_KERN
#
# 4.x sock_create_kern() added a first parameter as 'struct net *'
# instead of int.
#
AC_DEFUN([LN_CONFIG_SOCK_CREATE_KERN], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'sock_create_kern' first parameter is net],
sock_create_kern_net, [
	#include <linux/net.h>
	#include <net/net_namespace.h>
],[
	sock_create_kern((struct net*)0, 0, 0, 0, NULL);
],[
	AC_DEFINE(HAVE_SOCK_CREATE_KERN_USE_NET, 1,
		[sock_create_kern use net as first parameter])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_CONFIG_SOCK_CREATE_KERN

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
# LN_EXPORT_KMAP_TO_PAGE
#
# 3.10 Export kmap_to_page
#
AC_DEFUN([LN_EXPORT_KMAP_TO_PAGE], [
LB_CHECK_EXPORT([kmap_to_page], [mm/highmem.c],
	[AC_DEFINE(HAVE_KMAP_TO_PAGE, 1,
		[kmap_to_page is exported by the kernel])])
]) # LN_EXPORT_KMAP_TO_PAG

#
# LN_HAVE_HYPERVISOR_IS_TYPE
#
# 4.14 commit 79cc74155218316b9a5d28577c7077b2adba8e58
# x86/paravirt: Provide a way to check for hypervisors
#
AC_DEFUN([LN_HAVE_HYPERVISOR_IS_TYPE], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if hypervisor_is_type function is available],
hypervisor_is_type_exists, [
	#include <asm/hypervisor.h>
],[
	(void)hypervisor_is_type(X86_HYPER_NATIVE);
],[
	AC_DEFINE(HAVE_HYPERVISOR_IS_TYPE, 1,
		[hypervisor_is_type function exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_HAVE_HYPERVISOR_IS_TYPE

#
# LN_HAVE_ORACLE_OFED_EXTENSIONS
#
# Oracle UEK 5
#
AC_DEFUN([LN_HAVE_ORACLE_OFED_EXTENSIONS], [
LB_CHECK_COMPILE([if Oracle OFED Extensions are enabled],
oracle_ofed_ext, [
	#include <rdma/ib_fmr_pool.h>
],[
	struct ib_fmr_pool_param param = {
		.relaxed           = 0
	};
	(void)param;
],[
	AC_DEFINE(HAVE_ORACLE_OFED_EXTENSIONS, 1,
		[if Oracle OFED Extensions are enabled])
])
]) # LN_HAVE_ORACLE_OFED_EXTENSIONS

#
# LN_CONFIG_SOCK_GETNAME
#
# 4.17 commit 9b2c45d479d0fb8647c9e83359df69162b5fbe5f getname()
# does not take the length *int argument and returns the length
#
AC_DEFUN([LN_CONFIG_SOCK_GETNAME], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'getname' has two args],
kern_sock_getname_2args, [
	#include <linux/net.h>
],[
	kernel_getsockname(NULL, NULL);
],[
	AC_DEFINE(HAVE_KERN_SOCK_GETNAME_2ARGS, 1,
		['getname' has two args])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_CONFIG_SOCK_GETNAME

#
# LN_HAVE_IN_DEV_FOR_EACH_IFA_RTNL
#
# kernel 5.3 commit ef11db3310e272d3d8dbe8739e0770820dd20e52
# and kernel 4.18.0-193.el8:
# added in_dev_for_each_ifa_rtnl and in_dev_for_each_ifa_rcu
# and removed for_ifa and endfor_ifa.
# Use the _rntl variant as the current locking is rtnl.
#
AC_DEFUN([LN_HAVE_IN_DEV_FOR_EACH_IFA_RTNL], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'in_dev_for_each_ifa_rtnl' is defined],
in_dev_for_each_ifa_rtnl_test, [
	#include <linux/inetdevice.h>
],[
	const struct in_ifaddr *ifa = NULL;
	struct in_device *in_dev = NULL;

	in_dev_for_each_ifa_rtnl(ifa, in_dev) {}
],[
	AC_DEFINE(HAVE_IN_DEV_FOR_EACH_IFA_RTNL, 1,
		['in_dev_for_each_ifa_rtnl' is defined])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_HAVE_IN_DEV_FOR_EACH_IFA_RTNL

#
# LN_IB_DEVICE_OPS_EXISTS
#
# kernel 5.0 commit 521ed0d92ab0db3edd17a5f4716b7f698f4fce61
# RDMA/core: Introduce ib_device_ops
# ... introduces the ib_device_ops structure that defines all the
# InfiniBand device operations in one place ...
#
AC_DEFUN([LN_IB_DEVICE_OPS_EXISTS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if struct ib_device_ops is defined],
ib_device_ops_test, [
	#include <rdma/ib_verbs.h>
],[
	int x = offsetof(struct ib_device_ops, unmap_fmr);
	x = x;
	(void)x;
],[
	AC_DEFINE(HAVE_IB_DEVICE_OPS, 1,
		[if struct ib_device_ops is defined])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_IB_DEVICE_OPS_EXISTS

#
# LN_IB_SG_DMA_ADDRESS_EXISTS
#
# kernel 5.1 commit a163afc88556e099271a7b423295bc5176fcecce
# IB/core: Remove ib_sg_dma_address() and ib_sg_dma_len()
# ... when dma_ops existed (3.6) ib_sg_dma_address() was not trivial ...
#
AC_DEFUN([LN_IB_SG_DMA_ADDRESS_EXISTS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if ib_sg_dma_address wrapper exists],
ib_sg_dma_address_test, [
	#include <rdma/ib_verbs.h>
],[
	u64 x = ib_sg_dma_address(NULL, NULL);
	x = x;
	(void)x;
],[
	AC_DEFINE(HAVE_IB_SG_DMA_ADDRESS, 1,
		[if ib_sg_dma_address wrapper exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LN_IB_SG_DMA_ADDRESS_EXISTS

#
# LN_USR_RDMA
#
#
AC_DEFUN([LN_USR_RDMA], [
AC_MSG_CHECKING([if RDMA_PS_TCP exists])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
	#include <rdma/rdma_user_cm.h>

	int main(void) {
		int x = (int)RDMA_PS_TCP;
		return x;
	}
])],[
	AC_DEFINE(HAVE_USRSPC_RDMA_PS_TCP, 1,
		[RDMA_PS_TCP exists])
])
]) # LN_USR_RDMA


AC_DEFUN([LN_PROG_LINUX_SRC], [])
AC_DEFUN([LN_PROG_LINUX_RESULTS], [])

#
# LN_PROG_LINUX
#
# LNet linux kernel checks
#
AC_DEFUN([LN_PROG_LINUX], [
AC_MSG_NOTICE([LNet kernel checks
==============================================================================])

LN_CONFIG_BACKOFF
LN_CONFIG_O2IB
LN_CONFIG_GNILND
# 3.10
LN_EXPORT_KMAP_TO_PAGE
# 3.15
LN_CONFIG_SK_DATA_READY
# 4.x
LN_CONFIG_SOCK_CREATE_KERN
# 4.14
LN_HAVE_HYPERVISOR_IS_TYPE
LN_HAVE_ORACLE_OFED_EXTENSIONS
# 4.17
LN_CONFIG_SOCK_GETNAME
# 5.3 and 4.18.0-193.el8
LN_HAVE_IN_DEV_FOR_EACH_IFA_RTNL
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

LN_CONFIG_DLC
LN_USR_RDMA
]) # LN_CONFIGURE

#
# LN_CONDITIONALS
#
# AM_CONDITIONAL defines for lnet
#
AC_DEFUN([LN_CONDITIONALS], [
AM_CONDITIONAL(BUILD_O2IBLND,    test x$O2IBLND = "xo2iblnd")
AM_CONDITIONAL(BUILD_GNILND,     test x$GNILND  = "xgnilnd")
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
lnet/include/uapi/linux/lnet/Makefile
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
