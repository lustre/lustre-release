dnl Checks for OFED
AC_DEFUN([LN_CONFIG_OFED_SPEC], [
	AC_MSG_NOTICE([OFED checks
==============================================================================])

	LB_CHECK_COMPILE([if OFED has 'ib_dma_map_single'],
	ib_dma_map_single, [
		#include <linux/version.h>
		#include <linux/pci.h>
		#include <linux/gfp.h>
		#include <rdma/ib_verbs.h>
	],[
		ib_dma_map_single(NULL, NULL, 0, 0);
		return 0;
	],[
		AC_DEFINE(HAVE_OFED_IB_DMA_MAP, 1,
			[ib_dma_map_single defined])
	])

	LB_CHECK_COMPILE([if OFED 'ib_create_cq' wants 'comp_vector'],
	ib_create_cq_comp_vector, [
		#include <linux/version.h>
		#include <linux/pci.h>
		#include <linux/gfp.h>
		#include <rdma/ib_verbs.h>
	],[
		ib_create_cq(NULL, NULL, NULL, NULL, 0, 0);
		return 0;
	],[
		AC_DEFINE(HAVE_OFED_IB_COMP_VECTOR, 1,
			[has completion vector])
	])

	LB_CHECK_COMPILE([if OFED has 'RDMA_CM_EVENT_ADDR_CHANGE'],
	RDMA_CM_EVENT_ADDR_CHANGE, [
		#include <linux/version.h>
		#include <linux/pci.h>
		#include <linux/gfp.h>
		#ifdef HAVE_COMPAT_RDMA
		#include <linux/compat-2.6.h>
		#endif
		#include <rdma/rdma_cm.h>
	],[
		return (RDMA_CM_EVENT_ADDR_CHANGE == 0);
	],[
		AC_DEFINE(HAVE_OFED_RDMA_CMEV_ADDRCHANGE, 1,
			[has completion vector])
	])

	LB_CHECK_COMPILE([if OFED has 'RDMA_CM_EVENT_TIMEWAIT_EXIT'],
	RDMA_CM_EVENT_TIMEWAIT_EXIT, [
		#include <linux/version.h>
		#include <linux/pci.h>
		#include <linux/gfp.h>
		#ifdef HAVE_COMPAT_RDMA
		#include <linux/compat-2.6.h>
		#endif
		#include <rdma/rdma_cm.h>
	],[
		return (RDMA_CM_EVENT_TIMEWAIT_EXIT == 0);
	],[
		AC_DEFINE(HAVE_OFED_RDMA_CMEV_TIMEWAIT_EXIT, 1,
			[has completion vector])
	])

	LB_CHECK_COMPILE([if OFED has 'rdma_set_reuseaddr'],
	rdma_set_reuseaddr, [
		#include <linux/version.h>
		#include <linux/pci.h>
		#include <linux/gfp.h>
		#ifdef HAVE_COMPAT_RDMA
		#include <linux/compat-2.6.h>
		#endif
		#include <rdma/rdma_cm.h>
	],[
		rdma_set_reuseaddr(NULL, 1);
		return 0;
	],[
		AC_DEFINE(HAVE_OFED_RDMA_SET_REUSEADDR, 1,
			[rdma_set_reuse defined])
	])
])
