# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

# LN_CONFIG_BACKOFF
#
# check if tunable tcp backoff is available/wanted
#
AC_DEFUN([LN_CONFIG_BACKOFF], [
AC_MSG_CHECKING([whether to enable tunable backoff TCP support])
AC_ARG_ENABLE([backoff],
	AS_HELP_STRING([--disable-backoff],
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

	AC_SUBST(ENABLE_BACKOFF, yes)
], [
	AC_SUBST(ENABLE_BACKOFF, no)

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
]) # LN_CONFIG_DLC

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
AC_ARG_ENABLE([multiple-lnds],
	[AS_HELP_STRING([--enable-multiple-lnds],
		[enable multiple lnds to build in-kernel and external o2iblnd])],
	[AS_IF([test x$enable_multiple_lnds != xyes -a x$enable_multiple_lnds != xno],
		[AC_MSG_ERROR([multiple-lnds valid options are "yes" or "no"])])],
	[enable_multiple_lnds="no"])
	ENABLE_MULTIPLE_LNDS="$enable_multiple_lnds"

AC_MSG_CHECKING([if external o2iblnd needs to use Compat RDMA])
AC_ARG_WITH([o2ib],
	AS_HELP_STRING([--with-o2ib=[yes|no|<path>]],
		[build o2iblnd against path]),
	[], [with_o2ib="yes"])

case $with_o2ib in
	yes)	INT_O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
		BUILT_IN_KO2IBLND="yes"
		# Use ofed_info to find external driver
		AS_IF([which ofed_info 2>/dev/null], [
			AS_IF([test x$uses_dpkg = xyes], [
				LSPKG="dpkg --listfiles"
			], [
				LSPKG="rpm -ql"
			])

			O2IBPKG="mlnx-ofed-kernel-dkms"
			O2IBPKG+=" mlnx-ofed-kernel-modules"
			O2IBPKG+=" mlnx-ofa_kernel-devel"
			O2IBPKG+=" compat-rdma-devel"
			O2IBPKG+=" kernel-ib-devel"
			O2IBPKG+=" ofa_kernel-devel"

			O2IBDIR="/ofa_kernel"
			O2IBDIR+="|/ofa_kernel/default"
			O2IBDIR+="|/openib"

			O2IBDIR_PATH=$(eval $LSPKG $O2IBPKG 2>/dev/null |
				       egrep "${O2IBDIR}$" |
				       grep -v /ofed_scripts/ | head -n1)

			# Nowadays, path should always be
			# /usr/src/ofa_kernel/$ARCH/${LINUXRELEASE}
			# and we could clean all that complexity
			# but I don't know how far we should be retro-compatible.

			if test -n "$O2IBDIR_PATH"; then
				if test -d $O2IBDIR_PATH/${target_cpu}/${LINUXRELEASE}; then
					O2IBDIR_PATH=$O2IBDIR_PATH/${target_cpu}/${LINUXRELEASE}
				fi
				EXT_O2IBPATHS=$(find $O2IBDIR_PATH -name rdma_cm.h |
					sed -e 's/\/include\/rdma\/rdma_cm.h//')
			fi

			# When ofed-scripts are installed and either the devel
			# package is missing or multiple devel packages are
			# installed. Give the user a warning
			# The in-kernel ofed stack can be built .. so we can
			# proceed.

			EXTERNAL_KO2IBLND="yes"
			AS_IF([test -z "$EXT_O2IBPATHS"], [
				EXTERNAL_KO2IBLND="no"
				AC_MSG_WARN([
* You seem to have an OFED installed but have not installed the associated
* devel package.
* If you still want to build Lustre for your External OFED I/B stack,
* you need to install its devel headers RPM.
* Only the kernel built-in I/B stack support will be built.
					     ])
			])
			AS_IF([test $(echo $EXT_O2IBPATHS | wc -w) -ge 2], [
				BUILT_IN_KO2IBLND="no"
				AC_MSG_WARN([
* It appears that you have multiple OFED versions installed.
* If you still want to build Lustre for your External OFED I/B stack, you
* need to install a single version with the associated devel package.
* Only the kernel built-in I/B stack support will be built.
				     ])
			])
			if test x$EXTERNAL_KO2IBLND != "xno" ; then
				if test -e $EXT_O2IBPATHS/${LINUXRELEASE}; then
				    EXT_O2IBPATHS=$EXT_O2IBPATHS/${LINUXRELEASE}
				elif test -e $EXT_O2IBPATHS/default; then
				    EXT_O2IBPATHS=$EXT_O2IBPATHS/default
				fi
			fi
		])
		ENABLEO2IB="yes"
		;;
	no)	ENABLEO2IB="no"
		EXTERNAL_KO2IBLND="no"
		BUILT_IN_KO2IBLND="no"
		;;
	*)	ENABLEO2IB="withpath"
		EXT_O2IBPATHS=$with_o2ib
		EXTERNAL_KO2IBLND="yes"
		INT_O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
		BUILT_IN_KO2IBLND="yes"
		;;
esac

AS_IF([test $ENABLEO2IB = "no"], [
	AC_MSG_RESULT([no])
	AC_DEFUN([LN_CONFIG_O2IB_SRC], [])
	AC_DEFUN([LN_CONFIG_O2IB_RESULTS], [])
	EXT_O2IB_SYMBOLS=""
	INT_O2IB_SYMBOLS=""
], [
	# Verify in-kernel O2IB can be built (headers exist) ... or disable it.
	int_o2ib_found=false
	for INT_O2IBPATH in $INT_O2IBPATHS; do
		AS_IF([test \( -f ${INT_O2IBPATH}/include/rdma/rdma_cm.h -a \
			   -f ${INT_O2IBPATH}/include/rdma/ib_cm.h -a \
			   -f ${INT_O2IBPATH}/include/rdma/ib_verbs.h \)], [
			int_o2ib_found=true
			break
		])
	done
	if ! $int_o2ib_found; then
		AC_MSG_WARN([kernel does not support in-kernel o2ib, it will not be built])
		BUILT_IN_KO2IBLND="no"
	fi

	# Verify external O2IB can be built (headers exist), or abort
	ext_o2ib_found=false
	for EXT_O2IBPATH in $EXT_O2IBPATHS; do
		AS_IF([test \( -f ${EXT_O2IBPATH}/include/rdma/rdma_cm.h -a \
			   -f ${EXT_O2IBPATH}/include/rdma/ib_cm.h -a \
			   -f ${EXT_O2IBPATH}/include/rdma/ib_verbs.h \)], [
			ext_o2ib_found=true
			break
		])
	done
	if ! $ext_o2ib_found; then
		case $EXT_ENABLEO2IB in
			"withpath") AC_MSG_ERROR([bad --with-o2ib path]) ;;
			*) 	AC_MSG_WARN([
Auto detection of external O2IB failed. Build of external o2ib disabled.])
				EXTERNAL_KO2IBLND="no"
				;;
		esac
	fi

	if test "x$EXTERNAL_KO2IBLND" != no ; then
		# Additional checks for external O2IB
		COMPAT_AUTOCONF=""
		compatrdma_found=false
		if test -f ${EXT_O2IBPATH}/include/linux/compat-2.6.h; then
			AC_MSG_RESULT([yes])
			compatrdma_found=true
			AC_DEFINE(HAVE_OFED_COMPAT_RDMA, 1, [compat rdma found])
			EXTRA_OFED_CONFIG="$EXTRA_OFED_CONFIG -include ${EXT_O2IBPATH}/include/linux/compat-2.6.h"
			if test -f "$EXT_O2IBPATH/include/linux/compat_autoconf.h"; then
				COMPAT_AUTOCONF="$EXT_O2IBPATH/include/linux/compat_autoconf.h"
			fi
		else
			AC_MSG_RESULT([no])
		fi
		if ! $compatrdma_found; then
			if test -f "$EXT_O2IBPATH/config.mk"; then
				. "$EXT_O2IBPATH/config.mk"
			elif test -f "$EXT_O2IBPATH/ofed_patch.mk"; then
				. "$EXT_O2IBPATH/ofed_patch.mk"
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
			OFED_BACKPORT_PATH="$EXT_O2IBPATH/${BACKPORT_INCLUDES/*\/kernel_addons/kernel_addons}/"
			EXTRA_OFED_INCLUDE="-I$OFED_BACKPORT_PATH $EXTRA_OFED_INCLUDE"
		else
			AC_MSG_RESULT([no])
		fi

		EXT_O2IBLND=""
		EXT_O2IBPATH=$(readlink --canonicalize $EXT_O2IBPATH)
		EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -I$EXT_O2IBPATH/include"
		EXTRA_OFED_INCLUDE="$EXTRA_OFED_INCLUDE -I$EXT_O2IBPATH/include/uapi"
		EXTRA_CHECK_INCLUDE="$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE"
		LB_CHECK_COMPILE([whether to enable OpenIB gen2 support],
		openib_gen2_support, [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
			struct rdma_cm_id *cm_idi __attribute__ ((unused));
			struct rdma_conn_param conn_param __attribute__ ((unused));
			struct ib_device_attr device_attr __attribute__ ((unused));
			struct ib_qp_attr qp_attr __attribute__ ((unused));
			enum ib_cm_rej_reason rej_reason __attribute__ ((unused));

			rdma_destroy_id(NULL);
		],[
			EXT_O2IBLND="o2iblnd"
		],[
			case $ENABLEO2IB in
			"yes") AC_MSG_ERROR([cannot compile with OpenIB gen2 headers]) ;;
			"withpath") AC_MSG_ERROR([cannot compile with OpenIB gen2 headers under $EXT_O2IBPATH]) ;;
			*) AC_MSG_ERROR([internal error]) ;;
			esac
		])
		# we know that the found external OFED source+headers are good
		EXT_O2IB_SYMBOLS=""
		CHECK_SYMBOLS=""
		if test -f $EXT_O2IBPATH/Module.symvers ; then
			CHECK_SYMBOLS=$EXT_O2IBPATH/Module.symvers
		fi
		if test -n "$CHECK_SYMBOLS"; then
			if test ! "$CHECK_SYMBOLS" -ef "$LINUX_OBJ/Module.symvers"; then
				AC_MSG_NOTICE([adding $CHECK_SYMBOLS to external o2ib symbols])
				EXT_O2IB_SYMBOLS="${CHECK_SYMBOLS}"
			else
				EXTERNAL_KO2IBLND="no"
			fi
		elif test "x$EXTERNAL_KO2IBLND" != "xno" ; then
			AC_MSG_WARN([
	* Module.symvers for external o2iblnd was not found.
	* Expected: $EXT_O2IBPATH/Module.symvers
	* ko2iblnd.ko for external OFED will not be built.
				    ])
			EXTERNAL_KO2IBLND="no"
		fi
	fi

	# we expect that the found in-kernel OFED source+headers are good
	INT_O2IB_SYMBOLS=""
	CHECK_SYMBOLS=""
	if test -f $LINUX_OBJ/Module.symvers; then
		# Debian symvers is in the arch tree
		# SUSE symvers is in the OBJ tree [KVER-obj/<arch>/<flavor>/]
		CHECK_SYMBOLS=$LINUX_OBJ/Module.symvers
	elif test -f $INT_O2IBPATH/Module.symvers; then
		CHECK_SYMBOLS=$INT_O2IBPATH/Module.symvers
	fi

	if test -n "$CHECK_SYMBOLS"; then
		if test ! "$CHECK_SYMBOLS" -ef "$LINUX_OBJ/Module.symvers"; then
			AC_MSG_NOTICE([adding $CHECK_SYMBOLS to o2ib in-kernel symbols])
			INT_O2IB_SYMBOLS="${CHECK_SYMBOLS}"
		fi
	else
		AC_MSG_WARN([Module.symvers for in-kernel o2iblnd was not found])
	fi

	if test "x$EXTERNAL_KO2IBLND" = "xno" -a "x$BUILT_IN_KO2IBLND" = "xno" ; then
		AC_MSG_WARN([No o2iblnd can be built])
	elif test "x$ENABLE_MULTIPLE_LNDS" = "xno" -a \
		  "x$EXTERNAL_KO2IBLND" != "xno" -a "x$BUILT_IN_KO2IBLND" != "xno"; then
		AC_MSG_WARN([
NOTE: --enable-multiple-lnds is needed to enable both o2iblnd drivers.
* Disabling in-kernel o2iblnd in favor of external o2iblnd driver.
* There can be only one in this configuration
			    ])
		BUILT_IN_KO2IBLND="no"
	fi

	LB_CHECK_COMPILE([if Linux kernel has kthread_worker],
	linux_kthread_worker, [
		#ifdef HAVE_OFED_COMPAT_RDMA
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
])
AC_SUBST(EXTRA_OFED_CONFIG)
AC_SUBST(EXTRA_OFED_INCLUDE)
AC_SUBST(EXT_O2IBLND)
AC_SUBST(EXT_O2IB_SYMBOLS)
AC_SUBST(INT_O2IB_SYMBOLS)

# Passed down to deb packaging via autoMakefile.am
AC_SUBST(EXT_O2IBPATH)
AC_SUBST(ENABLEO2IB)
AC_SUBST(ENABLE_MULTIPLE_LNDS)

AS_IF([test $ENABLEO2IB != "no"], [
	EXTRA_CHECK_INCLUDE="$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE"
	if test ! $EXT_O2IBPATH -ef $LINUX_OBJ; then
		EXTERNAL_KO2IBLND="yes"
	fi

	# In RHEL 6.2, rdma_create_id() takes the queue-pair type as a fourth argument
	AC_DEFUN([LN_SRC_O2IB_RDMA_CREATE_ID_4A], [
		LB2_OFED_TEST_SRC([rdma_create_id_4args], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_RDMA_CREATE_ID_4A], [
		LB2_OFED_TEST_RESULTS(
			['rdma_create_id' wants four args],
			[rdma_create_id_4args],
			[HAVE_OFED_RDMA_CREATE_ID_4ARG])
	])

	# 4.4 added network namespace parameter for rdma_create_id()
	AC_DEFUN([LN_SRC_O2IB_RDMA_CREATE_ID_5A], [
		LB2_OFED_TEST_SRC([rdma_create_id_5args], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_RDMA_CREATE_ID_5A], [
		LB2_OFED_TEST_RESULTS(
			['rdma_create_id' wants five args],
			[rdma_create_id_5args],
			[HAVE_OFED_RDMA_CREATE_ID_5ARG])
	])

	# 4.2 introduced struct ib_cq_init_attr which is used
	# by ib_create_cq(). Note some OFED stacks only keep
	# their headers in sync with latest kernels but not
	# the functionality which means for infiniband testing
	# we need to always test functionality testings.
	AC_DEFUN([LN_SRC_O2IB_IB_CQ_INIT_ATTR], [
		LB2_OFED_TEST_SRC([ib_cq_init_attr], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_CQ_INIT_ATTR], [
		LB2_OFED_TEST_RESULTS(
			['struct ib_cq_init_attr' is used by ib_create_cq],
			[ib_cq_init_attr],
			[HAVE_OFED_IB_CQ_INIT_ATTR])
	])

	# 4.3 removed ib_alloc_fast_reg_mr()
	AC_DEFUN([LN_SRC_O2IB_IB_ALLOC_FAST_REG_MR], [
		LB2_OFED_TEST_SRC([ib_alloc_fast_reg_mr], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_ALLOC_FAST_REG_MR], [
		LB2_OFED_TEST_RESULTS(
			['ib_alloc_fast_reg_mr' exists],
			[ib_alloc_fast_reg_mr],
			[HAVE_OFED_IB_ALLOC_FAST_REG_MR])
	])

	# 4.9 must stop using ib_get_dma_mr and the global MR
	# We then have to use FMR/Fastreg for all RDMA.
	AC_DEFUN([LN_SRC_O2IB_IB_GET_DMA_MR], [
		LB2_OFED_TEST_SRC([ib_get_dma_mr], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_GET_DMA_MR], [
		LB2_OFED_TEST_RESULTS(
			['ib_get_dma_mr' exists],
			[ib_get_dma_mr],
			[HAVE_OFED_IB_GET_DMA_MR])
	])

	# In v4.4 Linux kernel,
	# commit e622f2f4ad2142d2a613a57fb85f8cf737935ef5
	# split up struct ib_send_wr so that all non-trivial verbs
	# use their own structure which embedds struct ib_send_wr.
	AC_DEFUN([LN_SRC_O2IB_IB_RDMA_WR], [
		LB2_OFED_TEST_SRC([ib_rdma_wr], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
			const struct ib_rdma_wr *wr __attribute__ ((unused));

			wr = rdma_wr(NULL);
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_RDMA_WR], [
		LB2_OFED_TEST_RESULTS(
			['struct ib_rdma_wr' is defined],
			[ib_rdma_wr],
			[HAVE_OFED_IB_RDMA_WR])
	])

	# new fast registration API introduced in 4.4
	AC_DEFUN([LN_SRC_O2IB_IB_MAP_MR_SG_4A], [
		LB2_OFED_TEST_SRC([ib_map_mr_sg_4args], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	# new fast registration API introduced in 4.4
	AC_DEFUN([LN_O2IB_IB_MAP_MR_SG_4A], [
		LB2_OFED_TEST_RESULTS(
			['ib_map_mr_sg' with 4 args exists],
			[ib_map_mr_sg_4args],
			[HAVE_OFED_IB_MAP_MR_SG])
	])

	# ib_map_mr_sg changes from 4 to 5 args (adding sg_offset_p)
	# in kernel 4.7 (and RHEL 7.3)
	AC_DEFUN([LN_SRC_O2IB_IB_MAP_MR_SG_5A], [
		LB2_OFED_TEST_SRC([ib_map_mr_sg_5args], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_MAP_MR_SG_5A], [
		LB2_OFED_TEST_RESULTS(
			[struct ib_reg_wr exists],
			[ib_map_mr_sg_5args],
			[HAVE_OFED_IB_MAP_MR_SG])
		LB2_OFED_TEST_RESULTS(
			['ib_map_mr_sg()' with 5 args exists],
			[ib_map_mr_sg_5args],
			[HAVE_OFED_IB_MAP_MR_SG_5ARGS])
	])

	# ib_query_device() removed in 4.5
	AC_DEFUN([LN_SRC_O2IB_IB_DEVICE_ATTRS], [
		LB2_OFED_TEST_SRC([ib_device_attrs], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_DEVICE_ATTRS], [
		LB2_OFED_TEST_RESULTS(
			['struct ib_device' has member 'attrs'],
			[ib_device_attrs],
			[HAVE_OFED_IB_DEVICE_ATTRS])
	])

	# A flags argument was added to ib_alloc_pd() in Linux 4.9,
	# commit ed082d36a7b2c27d1cda55fdfb28af18040c4a89
	AC_DEFUN([LN_SRC_O2IB_IB_ALLOC_PD], [
		LB2_OFED_TEST_SRC([ib_alloc_pd], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_ALLOC_PD], [
		LB2_OFED_TEST_RESULTS(
			[2arg 'ib_alloc_pd' exists],
			[ib_alloc_pd],
			[HAVE_OFED_IB_ALLOC_PD_2ARGS])
	])

	AC_DEFUN([LN_SRC_O2IB_IB_INC_RKEY], [
		LB2_OFED_TEST_SRC([ib_inc_rkey], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_INC_RKEY], [
		LB2_OFED_TEST_RESULTS(
			[function 'ib_inc_rkey' is defined],
			[ib_inc_rkey],
			[HAVE_OFED_IB_INC_RKEY])
	])

	# In MOFED 4.6, the second and third parameters for
	# ib_post_send() and ib_post_recv() are declared with
	# 'const'.
	AC_DEFUN([LN_SRC_O2IB_IB_POST_SEND_CONST], [
		LB2_OFED_TEST_SRC([ib_post_send_recv_const], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[-Werror],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_POST_SEND_CONST], [
		LB2_OFED_TEST_RESULTS(
			['ib_post_send() and ib_post_recv()' have const parameters],
			[ib_post_send_recv_const],
			[HAVE_OFED_IB_POST_SEND_RECV_CONST])
	])

	# MOFED 5.5 fails with:
	#   ERROR: "ib_dma_virt_map_sg" [.../ko2iblnd.ko] undefined!
	# See if we have a broken ib_dma_map_sg()
	AC_DEFUN([LN_SRC_SANE_IB_DMA_MAP_SG], [
		LB2_OFED_TEST_SRC([sane_ib_dma_map_sg], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
			ib_dma_map_sg((struct ib_device *)NULL,
				      (struct scatterlist *)NULL, 1, 0);
		],[-Werror],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_SANE_IB_DMA_MAP_SG], [
		LB2_OFED_TEST_RESULTS(
			[if ib_dma_map_sg() is sane],
			[sane_ib_dma_map_sg],
			[HAVE_OFED_IB_DMA_MAP_SG_SANE],[module])
	])

	#
	# LN_IB_DEVICE_OPS_EXISTS
	#
	# kernel 5.0 commit 521ed0d92ab0db3edd17a5f4716b7f698f4fce61
	# RDMA/core: Introduce ib_device_ops
	# ... introduces the ib_device_ops structure that defines all the
	# InfiniBand device operations in one place ...
	#
	AC_DEFUN([LN_SRC_O2IB_IB_DEVICE_OPS_EXISTS], [
		LB2_OFED_TEST_SRC([ib_device_ops_test], [
			#include <rdma/ib_verbs.h>
		],[
			int x = offsetof(struct ib_device_ops, unmap_fmr);
			x = x;
			(void)x;
		],[-Werror],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_DEVICE_OPS_EXISTS], [
		LB2_OFED_TEST_RESULTS(
			[struct ib_device_ops is defined],
			[ib_device_ops_test],
			[HAVE_OFED_IB_DEVICE_OPS])
	]) # LN_IB_DEVICE_OPS_EXISTS

	#
	# LN_O2IB_IB_SG_DMA_ADDRESS_EXISTS
	#
	# kernel 5.1 commit a163afc88556e099271a7b423295bc5176fcecce
	# IB/core: Remove ib_sg_dma_address() and ib_sg_dma_len()
	# ... when dma_ops existed (3.6) ib_sg_dma_address() was not trivial ...
	#
	AC_DEFUN([LN_SRC_O2IB_IB_SG_DMA_ADDRESS_EXISTS], [
		LB2_OFED_TEST_SRC([ib_sg_dma_address_test], [
			#include <rdma/ib_verbs.h>
		],[
			u64 x = ib_sg_dma_address(NULL, NULL);
			x = x;
			(void)x;
		],[-Werror],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_SG_DMA_ADDRESS_EXISTS], [
		LB2_OFED_TEST_RESULTS(
			[ib_sg_dma_address wrapper exists],
			[ib_sg_dma_address_test],
			[HAVE_OFED_IB_SG_DMA_ADDRESS])
	]) # LN_O2IB_IB_SG_DMA_ADDRESS_EXISTS

	#
	# LN_O2IB_RDMA_REJECT
	#
	# A reason argument was added to rdma_reject() in Linux 5.8,
	# commit 8094ba0ace7f6cd1e31ea8b151fba3594cadfa9a
	AC_DEFUN([LN_SRC_O2IB_RDMA_REJECT], [
		LB2_OFED_TEST_SRC([rdma_reject], [
			#ifdef HAVE_OFED_COMPAT_RDMA
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
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_RDMA_REJECT], [
		LB2_OFED_TEST_RESULTS(
			[4arg 'rdma_reject' exists],
			[rdma_reject],
			[HAVE_OFED_RDMA_REJECT_4ARGS])
	]) # LN_O2IB_RDMA_REJECT

	#
	# LN_O2IB_IB_FMR
	#
	# The FMR pool API was removed in Linux 5.8,
	# commit 4e373d5417ecbb4f438a8500f0379a2fc29c2643
	AC_DEFUN([LN_SRC_O2IB_IB_FMR], [
		LB2_OFED_TEST_SRC([ib_fmr], [
			#include <rdma/ib_verbs.h>
		],[
			struct ib_fmr fmr = {};
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_IB_FMR], [
		LB2_OFED_TEST_RESULTS(
			[FMR pools API available],
			[ib_fmr],
			[HAVE_OFED_FMR_POOL_API])
	]) # LN_O2IB_IB_FMR

	#
	# LN_O2IB_RDMA_CONNECT_LOCKED
	#
	# rdma_connect_locked() was added in Linux 5.10,
	# commit 071ba4cc559de47160761b9500b72e8fa09d923d
	# and in MOFED-5.2-2. rdma_connect_locked() must
	# be called instead of rdma_connect() in
	# RDMA_CM_EVENT_ROUTE_RESOLVED handler.
	AC_DEFUN([LN_SRC_O2IB_RDMA_CONNECT_LOCKED], [
		LB2_OFED_TEST_SRC([rdma_connect_locked], [
			#include <rdma/rdma_cm.h>
		],[
			rdma_connect_locked(NULL, NULL);
		],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
	])
	AC_DEFUN([LN_O2IB_RDMA_CONNECT_LOCKED], [
		LB2_OFED_TEST_RESULTS(
			['rdma_connect_locked' exists],
			[rdma_connect_locked],
			[HAVE_OFED_RDMA_CONNECT_LOCKED])
	]) # LN_O2IB_RDMA_CONNECT_LOCKED

	EXTRA_CHECK_INCLUDE=""

	AC_DEFUN([LN_CONFIG_O2IB_SRC], [
		LN_SRC_O2IB_RDMA_CREATE_ID_4A
		LN_SRC_O2IB_RDMA_CREATE_ID_5A
		LN_SRC_O2IB_IB_CQ_INIT_ATTR
		LN_SRC_O2IB_IB_ALLOC_FAST_REG_MR
		LN_SRC_O2IB_IB_GET_DMA_MR
		LN_SRC_O2IB_IB_RDMA_WR
		LN_SRC_O2IB_IB_MAP_MR_SG_4A
		LN_SRC_O2IB_IB_MAP_MR_SG_5A
		LN_SRC_O2IB_IB_DEVICE_ATTRS
		LN_SRC_O2IB_IB_ALLOC_PD
		LN_SRC_O2IB_IB_INC_RKEY
		LN_SRC_O2IB_IB_POST_SEND_CONST
		LN_SRC_SANE_IB_DMA_MAP_SG
		LN_SRC_O2IB_IB_DEVICE_OPS_EXISTS
		LN_SRC_O2IB_IB_SG_DMA_ADDRESS_EXISTS
		LN_SRC_O2IB_RDMA_REJECT
		LN_SRC_O2IB_IB_FMR
		LN_SRC_O2IB_RDMA_CONNECT_LOCKED
	])
	AC_DEFUN([LN_CONFIG_O2IB_RESULTS], [
		LN_O2IB_RDMA_CREATE_ID_4A
		LN_O2IB_RDMA_CREATE_ID_5A
		LN_O2IB_IB_CQ_INIT_ATTR
		LN_O2IB_IB_ALLOC_FAST_REG_MR
		LN_O2IB_IB_GET_DMA_MR
		LN_O2IB_IB_RDMA_WR
		LN_O2IB_IB_MAP_MR_SG_4A
		LN_O2IB_IB_MAP_MR_SG_5A
		LN_O2IB_IB_DEVICE_ATTRS
		LN_O2IB_IB_ALLOC_PD
		LN_O2IB_IB_INC_RKEY
		LN_O2IB_IB_POST_SEND_CONST
		LN_SANE_IB_DMA_MAP_SG
		LN_O2IB_IB_DEVICE_OPS_EXISTS
		LN_O2IB_IB_SG_DMA_ADDRESS_EXISTS
		LN_O2IB_RDMA_REJECT
		LN_O2IB_IB_FMR
		LN_O2IB_RDMA_CONNECT_LOCKED
	])
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
	AS_HELP_STRING([--enable-gni],
		[enable GNI lnd]),
	[], [enable_gni="no"])
AC_MSG_RESULT([$enable_gni])

AS_IF([test "x$enable_gni" = xyes], [
	# GNICPPFLAGS and KBUILD_EXTRA_SYMBOLS were set in spec file
	# to include the additional module dependancies of gni kernel driver
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
		AC_MSG_ERROR([cannot compile gnilnd with given GNICPPFLAGS: $GNICPPFLAGS])
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

	AC_SUBST(ENABLE_GNI, yes)
], [
	AC_SUBST(ENABLE_GNI, no)
])
AC_SUBST(GNICPPFLAGS)
AC_SUBST(GNILND)
]) # LN_CONFIG_GNILND

#
# LN_CONFIG_KFILND
#
# check whether to use the kfabric Network Interface lnd
#
AC_DEFUN([LN_CONFIG_KFILND], [
AC_ARG_WITH([kfi],
	AS_HELP_STRING([--with-kfi=<path>], [Kfabric build path for kfilnd]),
	[
		AC_CHECK_FILE([$with_kfi/Module.symvers],
		[
			# KFICPPFLAGS was set in spec file
			KFICPPFLAGS="-I$with_kfi/include"
			EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
			EXTRA_KCFLAGS="$EXTRA_KCFLAGS $KFICPPFLAGS"
			KBUILD_EXTRA_SYMBOLS="$KBUILD_EXTRA_SYMBOLS $with_kfi/Module.symvers"
			LB_CHECK_COMPILE([if kfabric headers are present], KFI_header,
			[
				#include <kfi_endpoint.h>
			],[
				struct kfi_info *hints;
				hints = kfi_allocinfo();
			],[
				KFILND="kfilnd"
				AC_MSG_NOTICE([adding $with_kfi/Module.symvers to Symbol Path])
				EXTRA_SYMBOLS="$EXTRA_SYMBOLS $with_kfi/Module.symvers"
			],[
				AC_MSG_ERROR([cannot compile kfilnd with given KFICPPFLAGS: $KFICPPFLAGS])
			])
		],[
			AC_MSG_ERROR(["$with_kfi/Module.symvers does not exist"])
		])
		# at this point, we have kfilnd basic support,
		# now check for extra features
		LB_CHECK_COMPILE([if kfi_cxi domain ops are available],
		KFI_CXI_dom_ops, [
			#include <kfi_endpoint.h>
			#include <kfi_cxi_ext.h>
		],[
			struct kfid *fid;
			struct kfi_cxi_domain_ops *dom_ops;
			kfi_open_ops(fid, KFI_CXI_DOM_OPS_1, 0,
				(void **)&dom_ops, NULL);
		],[
			AC_DEFINE(HAVE_KFI_CXI_DOM_OPS, 1,
				[kfi_cxi domain ops are available])
		])
	],[])
AC_DEFINE(HAVE_KFILND, 1, [support kfabric LND])
AC_SUBST(KFICPPFLAGS)
AC_SUBST(KFILND)
AC_SUBST(EXTRA_SYMBOLS)
]) # LN_CONFIG_KFILND

#
# LN_CONFIG_SOCK_CREATE_KERN
#
# 4.x sock_create_kern() added a first parameter as 'struct net *'
# instead of int.
#
AC_DEFUN([LN_SRC_CONFIG_SOCK_CREATE_KERN], [
	LB2_LINUX_TEST_SRC([sock_create_kern_net], [
		#include <linux/net.h>
		#include <net/net_namespace.h>
	],[
		sock_create_kern((struct net*)0, 0, 0, 0, NULL);
	],[-Werror])
])
AC_DEFUN([LN_CONFIG_SOCK_CREATE_KERN], [
	LB2_MSG_LINUX_TEST_RESULT([if 'sock_create_kern' first parameter is net],
	[sock_create_kern_net], [
		AC_DEFINE(HAVE_SOCK_CREATE_KERN_USE_NET, 1,
			[sock_create_kern use net as first parameter])
	])
]) # LN_CONFIG_SOCK_CREATE_KERN

#
# LN_CONFIG_SOCK_NOT_OWNED_BY_ME
#
# Linux upstream v6.11-rc3-g151c9c724d05d5b0d changes TCP socket orphan
# cleanup, requiring a change in ksocklnd if present. This has been back-ported
# to 4.* and 5.* Linux distributions.
#
AC_DEFUN([LN_SRC_CONFIG_SOCK_NOT_OWNED_BY_ME], [
	LB2_LINUX_TEST_SRC([sock_not_owned_by_me], [
		#include <net/sock.h>
	],[
		sock_not_owned_by_me((const struct sock *)0);
	],[-Werror])
])
AC_DEFUN([LN_CONFIG_SOCK_NOT_OWNED_BY_ME], [
	LB2_MSG_LINUX_TEST_RESULT([if Linux kernel has 'sock_not_owned_by_me'],
	[sock_not_owned_by_me], [
		AC_DEFINE(HAVE_SOCK_NOT_OWNED_BY_ME, 1,
			[sock_not_owned_by_me is defined in sock.h])
	])
]) # LN_CONFIG_SOCK_NOT_OWNED_BY_ME

#
# LN_CONFIG_SK_DATA_READY
#
# 3.15 for struct sock the *sk_data_ready() field only takes one argument now
#
AC_DEFUN([LN_SRC_CONFIG_SK_DATA_READY], [
	LB2_LINUX_TEST_SRC([sk_data_ready], [
		#include <linux/net.h>
		#include <net/sock.h>
	],[
		((struct sock *)0)->sk_data_ready(NULL);
	],[-Werror])
])
AC_DEFUN([LN_CONFIG_SK_DATA_READY], [
	LB2_MSG_LINUX_TEST_RESULT([if 'sk_data_ready' takes only one argument],
	[sk_data_ready], [
	AC_DEFINE(HAVE_SK_DATA_READY_ONE_ARG, 1,
		[sk_data_ready uses only one argument])
	])
]) # LN_CONFIG_SK_DATA_READY

#
# LN_ETHTOOL_LINK_SETTINGS
#
# ethtool_link_settings was added in Linux 4.6
#
AC_DEFUN([LN_SRC_ETHTOOL_LINK_SETTINGS], [
	LB2_LINUX_TEST_SRC([ethtool_link_settings], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_link_ksettings cmd;
	],[],[$EXTRA_OFED_CONFIG $EXTRA_OFED_INCLUDE])
])
AC_DEFUN([LN_ETHTOOL_LINK_SETTINGS], [
	LB2_MSG_LINUX_TEST_RESULT([if 'ethtool_link_settings' exists],
	[ethtool_link_settings], [
		AC_DEFINE(HAVE_ETHTOOL_LINK_SETTINGS, 1,
			[ethtool_link_settings is defined])
	])
]) # LN_ETHTOOL_LINK_SETTINGS

#
# LN_HAVE_HYPERVISOR_IS_TYPE
#
# 4.14 commit 79cc74155218316b9a5d28577c7077b2adba8e58
# x86/paravirt: Provide a way to check for hypervisors
#
AC_DEFUN([LN_SRC_HAVE_HYPERVISOR_IS_TYPE], [
	LB2_LINUX_TEST_SRC([hypervisor_is_type_exists], [
		#include <asm/hypervisor.h>
	],[
		(void)hypervisor_is_type(X86_HYPER_NATIVE);
	],[-Werror])
])
AC_DEFUN([LN_HAVE_HYPERVISOR_IS_TYPE], [
	LB2_MSG_LINUX_TEST_RESULT([if hypervisor_is_type function is available],
	[hypervisor_is_type_exists], [
		AC_DEFINE(HAVE_HYPERVISOR_IS_TYPE, 1,
			[hypervisor_is_type function exists])
	])
]) # LN_HAVE_HYPERVISOR_IS_TYPE

#
# LN_HAVE_ORACLE_OFED_EXTENSIONS
#
# Oracle UEK 5
#
AC_DEFUN([LN_SRC_HAVE_ORACLE_OFED_EXTENSIONS], [
	LB2_LINUX_TEST_SRC([oracle_ofed_ext], [
		#include <rdma/ib_fmr_pool.h>
	],[
		struct ib_fmr_pool_param param = {
			.relaxed           = 0
		};
		(void)param;
	])
])
AC_DEFUN([LN_HAVE_ORACLE_OFED_EXTENSIONS], [
	LB2_MSG_LINUX_TEST_RESULT([if Oracle OFED Extensions are enabled],
	[oracle_ofed_ext], [
		AC_DEFINE(HAVE_ORACLE_OFED_EXTENSIONS, 1,
			[if Oracle OFED Extensions are enabled])
	])
]) # LN_HAVE_ORACLE_OFED_EXTENSIONS

#
# LN_SRC_HAVE_NETDEV_CMD_TO_NAME
#
# 4.16-rc6 commit ede2762d93ff16e0974f7446516b46b1022db213
# created netdev_cmd_to_name() to map NETDEV events to char names
#
AC_DEFUN([LN_SRC_HAVE_NETDEV_CMD_TO_NAME], [
	LB2_LINUX_TEST_SRC([netdev_cmd_to_name], [
		#include <linux/netdevice.h>
	],[
		netdev_cmd_to_name(NETDEV_UP);
	],[-Werror])
])
AC_DEFUN([LN_HAVE_NETDEV_CMD_TO_NAME], [
	LB2_MSG_LINUX_TEST_RESULT([if 'netdev_cmd_to_name' exist],
	[netdev_cmd_to_name], [
		AC_DEFINE(HAVE_NETDEV_CMD_TO_NAME, 1,
			['netdev_cmd_to_name' is present])
	])
]) # LN_SRC_HAVE_NETDEV_CMD_TO_NAME

#
# LN_CONFIG_SOCK_GETNAME
#
# 4.17 commit 9b2c45d479d0fb8647c9e83359df69162b5fbe5f getname()
# does not take the length *int argument and returns the length
#
AC_DEFUN([LN_SRC_CONFIG_SOCK_GETNAME], [
	LB2_LINUX_TEST_SRC([kern_sock_getname_2args], [
		#include <linux/net.h>
	],[
		kernel_getsockname(NULL, NULL);
	],[-Werror])
])
AC_DEFUN([LN_CONFIG_SOCK_GETNAME], [
	LB2_MSG_LINUX_TEST_RESULT([if 'getname' has two args],
	[kern_sock_getname_2args], [
		AC_DEFINE(HAVE_KERN_SOCK_GETNAME_2ARGS, 1,
			['getname' has two args])
	])
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
AC_DEFUN([LN_SRC_HAVE_IN_DEV_FOR_EACH_IFA_RTNL], [
	LB2_LINUX_TEST_SRC([in_dev_for_each_ifa_rtnl_test], [
		#include <linux/inetdevice.h>
	],[
		const struct in_ifaddr *ifa = NULL;
		struct in_device *in_dev = NULL;

		in_dev_for_each_ifa_rtnl(ifa, in_dev) {}
	],[-Werror])
])
AC_DEFUN([LN_HAVE_IN_DEV_FOR_EACH_IFA_RTNL], [
	LB2_MSG_LINUX_TEST_RESULT([if 'in_dev_for_each_ifa_rtnl' is defined],
	[in_dev_for_each_ifa_rtnl_test], [
		AC_DEFINE(HAVE_IN_DEV_FOR_EACH_IFA_RTNL, 1,
			['in_dev_for_each_ifa_rtnl' is defined])
	])
]) # LN_HAVE_IN_DEV_FOR_EACH_IFA_RTNL

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

AC_DEFUN([LN_PROG_LINUX_SRC], [
	LN_CONFIG_O2IB_SRC
	# 3.15
	LN_SRC_CONFIG_SK_DATA_READY
	# 4.x
	LN_SRC_CONFIG_SOCK_CREATE_KERN
	LN_SRC_CONFIG_SOCK_NOT_OWNED_BY_ME
	# 4.6
	LN_SRC_ETHTOOL_LINK_SETTINGS
	# 4.14
	LN_SRC_HAVE_HYPERVISOR_IS_TYPE
	LN_SRC_HAVE_ORACLE_OFED_EXTENSIONS
	# 4.16
	LN_SRC_HAVE_NETDEV_CMD_TO_NAME
	# 4.17
	LN_SRC_CONFIG_SOCK_GETNAME
	# 5.3 and 4.18.0-193.el8
	LN_SRC_HAVE_IN_DEV_FOR_EACH_IFA_RTNL
])

AC_DEFUN([LN_PROG_LINUX_RESULTS], [
	LN_CONFIG_O2IB_RESULTS
	# 3.15
	LN_CONFIG_SK_DATA_READY
	# 4.x
	LN_CONFIG_SOCK_CREATE_KERN
	LN_CONFIG_SOCK_NOT_OWNED_BY_ME
	# 4.6
	LN_ETHTOOL_LINK_SETTINGS
	# 4.14
	LN_HAVE_HYPERVISOR_IS_TYPE
	LN_HAVE_ORACLE_OFED_EXTENSIONS
	# 4.16
	LN_HAVE_NETDEV_CMD_TO_NAME
	# 4.17
	LN_CONFIG_SOCK_GETNAME
	# 5.3 and 4.18.0-193.el8
	LN_HAVE_IN_DEV_FOR_EACH_IFA_RTNL
])

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
LN_CONFIG_KFILND
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

AC_ARG_WITH([cuda],
	AS_HELP_STRING([--with-cuda=path],
			[Path to the CUDA sources. Set to 'no' to disable.]),
			[cudapath="$withval"],
			[cudapath1=`ls -d1 /usr/src/nvidia-*/nvidia/ 2>/dev/null | tail -1`])

AC_ARG_WITH([gds],
	AS_HELP_STRING([--with-gds=path],
			[Path to the GDS sources. Set to 'no' to disable.]),
			[gdspath="$withval"],
			[gdspath1=`ls -d1 /usr/src/nvidia-fs*/ 2>/dev/null | tail -1`])

AC_MSG_CHECKING([cuda source directory])
	AS_IF([test -z "${cudapath}"], [
		AS_IF([test -e "${cudapath1}/nv-p2p.h"], [
			cudapath=${cudapath1}
		], [
			cudapath="[Not found]"
		])
	])
AC_MSG_RESULT([$cudapath])

AC_MSG_CHECKING([gds source directory])
	AS_IF([test -z "${gdspath}"], [
		AS_IF([test -e "${gdspath1}/nvfs-dma.h"], [
			gdspath=${gdspath1}
		], [
			gdspath="[Not found]"
		])
	])
AC_MSG_RESULT([$gdspath])

AS_IF([test -e "${cudapath}" && test -e "${gdspath}"],[
	LB_CHECK_FILE([$cudapath/nv-p2p.h], [
		AC_MSG_RESULT([CUDA path is $cudapath])
		[CUDA_PATH=${cudapath}]
		AC_SUBST(CUDA_PATH)
	],[
		AC_MSG_RESULT([CUDA sources not found: nv-p2p.h does not exist])
	])

	LB_CHECK_FILE([$gdspath/nvfs-dma.h], [
		LB_CHECK_FILE([$gdspath/config-host.h], [
			AC_MSG_RESULT([GDS path is ${gdspath}])
			[GDS_PATH=${gdspath}]
			AC_SUBST(GDS_PATH)
			AC_DEFINE(WITH_GDS, 1, "GDS build enabled")
		], [
		    AC_MSG_RESULT([GDS sources not found: config-host.h does not exist])
        ])
	], [
		AC_MSG_RESULT([GDS sources not found: nvfs-dma.h does not exist])
    ])
],[
	AC_MSG_WARN([CUDA or GDS sources not found. GDS support disabled])
])

# lnet/utils/lnetconfig/liblnetconfig_netlink.c
AS_IF([test "x$PKGCONF" = "x"],
	[AC_MSG_ERROR([pkg-config package is required to configure Lustre])])

AS_IF([test "x$enable_dist" = xno], [
	PKG_CHECK_MODULES(LIBNL3, [libnl-genl-3.0 >= 3.1])
])

AC_CHECK_LIB([nl-3], [nla_get_s32], [
	AC_DEFINE(HAVE_NLA_GET_S32, 1,
		[libnl3 supports nla_get_s32])
	], [
])

AC_CHECK_LIB([nl-3], [nla_get_s64], [
	AC_DEFINE(HAVE_NLA_GET_S64, 1,
		[libnl3 supports nla_get_s64])
	], [
])

#
# LN_USR_NLMSGERR
#
AC_DEFUN([LN_USR_NLMSGERR], [
AC_MSG_CHECKING([if 'enum nlmsgerr_attrs' exists])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
	#include <linux/netlink.h>

	int main(void) {
		int x = (int)NLMSGERR_ATTR_MAX;
		return x;
	}
])],[
	AC_DEFINE(HAVE_USRSPC_NLMSGERR, 1,
		['enum nlmsgerr_attrs' exists])
])
]) # LN_USR_NLMGSERR

# lnet/utils/portals.c
AC_CHECK_HEADERS([netdb.h])

# lnet/utils/wirecheck.c
AC_CHECK_FUNCS([strnlen])

# --------  Check for required packages  --------------

AC_MSG_CHECKING([whether to enable 'efence' debugging support])
AC_ARG_ENABLE(efence,
	AS_HELP_STRING([--enable-efence],
		[use efence library]),
	[], [enable_efence="no"])
AC_MSG_RESULT([$enable_efence])

LIBEFENCE=""
AS_IF([test "$enable_efence" = yes], [
	LIBEFENCE="-lefence"
	AC_DEFINE(HAVE_LIBEFENCE, 1,
		[libefence support is requested])
	AC_SUBST(ENABLE_EFENCE, yes)
], [
	AC_SUBST(ENABLE_EFENCE, no)
])
AC_SUBST(LIBEFENCE)

LN_CONFIG_DLC
LN_USR_RDMA
LN_USR_NLMSGERR
]) # LN_CONFIGURE

#
# LN_CONDITIONALS
#
# AM_CONDITIONAL defines for lnet
#
AC_DEFUN([LN_CONDITIONALS], [
AM_CONDITIONAL(EXTERNAL_KO2IBLND,  test x$EXTERNAL_KO2IBLND = "xyes")
AM_CONDITIONAL(BUILT_IN_KO2IBLND,  test x$BUILT_IN_KO2IBLND = "xyes")
AM_CONDITIONAL(BUILD_GNILND,       test x$GNILND  = "xgnilnd")
AM_CONDITIONAL(BUILD_KFILND,       test x$KFILND  = "xkfilnd")
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
lnet/klnds/in-kernel-o2iblnd/Makefile
lnet/klnds/in-kernel-o2iblnd/autoMakefile
lnet/klnds/gnilnd/Makefile
lnet/klnds/gnilnd/autoMakefile
lnet/klnds/socklnd/Makefile
lnet/klnds/socklnd/autoMakefile
lnet/klnds/kfilnd/Makefile
lnet/klnds/kfilnd/autoMakefile
lnet/lnet/Makefile
lnet/lnet/autoMakefile
lnet/selftest/Makefile
lnet/selftest/autoMakefile
lnet/utils/Makefile
lnet/utils/lnetconfig/Makefile
])
]) # LN_CONFIG_FILES
