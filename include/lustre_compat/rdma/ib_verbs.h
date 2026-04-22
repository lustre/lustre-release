/* SPDX-License-Identifier: GPL-2.0 */

/* This file is part of Lustre, http://www.lustre.org/ */

#ifndef __LIBCFS_RDMA_IB_VERBS_H__
#define __LIBCFS_RDMA_IB_VERBS_H__

#include <rdma/ib_verbs.h>

#if !defined(HAVE_IBK_SG_GAPS_REG) && !defined(IN_KERNEL_HAVE_IBK_SG_GAPS_REG)
#define IBK_SG_GAPS_REG	IB_DEVICE_SG_GAPS_REG
#endif

#endif
