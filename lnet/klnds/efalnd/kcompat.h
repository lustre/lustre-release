/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2024-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Michael Margolin <mrgolin@amazon.com>
 */

#include <rdma/ib_verbs.h>

#ifndef HAVE_IBDEV_TO_NODE
/**
 * ibdev_to_node - return the NUMA node for a given ib_device
 * @dev:	device to get the NUMA node for.
 */
static inline int ibdev_to_node(struct ib_device *ibdev)
{
	struct device *parent = ibdev->dev.parent;

	if (!parent)
		return NUMA_NO_NODE;
	return dev_to_node(parent);
}
#endif
