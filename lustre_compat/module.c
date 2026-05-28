// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/module.h>
#include <linux/kernel.h>

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/libcfs/libcfs.h>
#include <linux/lnet/lib-cpt.h>

int cpu_npartitions;
EXPORT_SYMBOL(cpu_npartitions);
module_param(cpu_npartitions, int, 0444);
MODULE_PARM_DESC(cpu_npartitions, "# of CPU partitions");

char *cpu_pattern = "N";
EXPORT_SYMBOL(cpu_pattern);
module_param(cpu_pattern, charp, 0444);
MODULE_PARM_DESC(cpu_pattern, "CPU partitions pattern");
