/* SPDX-License-Identifier: GPL-2.0 */

/* This file is part of Lustre, http://www.lustre.org/ */

#ifndef __LIBCFS_RDMA_IB_VERBS_H__
#define __LIBCFS_RDMA_IB_VERBS_H__

#include <rdma/ib_verbs.h>

/* Linux 5.15 commit e945c653c8e97 ("RDMA: Split kernel-only global device
 * caps from uverbs device caps") moved SG_GAPS registration support out of
 * ib_device_attr::device_cap_flags (IB_DEVICE_SG_GAPS_REG) and into the
 * kernel-only ib_device_attr::kernel_cap_flags (IBK_SG_GAPS_REG). The bit
 * value is reused by IB_DEVICE_RAW_MULTI in device_cap_flags, so the field
 * must be selected along with the flag.
 */
#if defined(HAVE_IBK_SG_GAPS_REG) || defined(IN_KERNEL_HAVE_IBK_SG_GAPS_REG)
#define ib_sg_gaps_reg_supported(dev_attr) \
	(!!((dev_attr)->kernel_cap_flags & IBK_SG_GAPS_REG))
#else
#define ib_sg_gaps_reg_supported(dev_attr) \
	(!!((dev_attr)->device_cap_flags & IB_DEVICE_SG_GAPS_REG))
#endif

#endif
