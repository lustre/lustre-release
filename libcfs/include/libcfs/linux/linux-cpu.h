/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/linux/linux-mem.h
 *
 * Basic library routines.
 *
 * Author: liang@whamcloud.com
 */

#ifndef __LIBCFS_LINUX_CPU_H__
#define __LIBCFS_LINUX_CPU_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifndef __KERNEL__
#error This include is only for kernel use.
#endif

#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/topology.h>
#include <linux/version.h>

#ifdef CONFIG_SMP

#define HAVE_LIBCFS_CPT

/** virtual processing unit */
struct cfs_cpu_partition {
	/* CPUs mask for this partition */
	cpumask_t			*cpt_cpumask;
	/* nodes mask for this partition */
	nodemask_t			*cpt_nodemask;
	/* NUMA distance between CPTs */
	unsigned			*cpt_distance;
	/* spread rotor for NUMA allocator */
	int				 cpt_spread_rotor;
	/* NUMA node if cpt_nodemask is empty */
	int				 cpt_node;
};

/** descriptor for CPU partitions */
struct cfs_cpt_table {
	/* spread rotor for NUMA allocator */
	int				ctb_spread_rotor;
	/* maximum NUMA distance between all nodes in table */
	unsigned			ctb_distance;
	/* # of CPU partitions */
	int				 ctb_nparts;
	/* partitions tables */
	struct cfs_cpu_partition	*ctb_parts;
	/* shadow HW CPU to CPU partition ID */
	int				*ctb_cpu2cpt;
	/* all cpus in this partition table */
	cpumask_t			*ctb_cpumask;
	/* shadow HW node to CPU partition ID */
	int				*ctb_node2cpt;
	/* all nodes in this partition table */
	nodemask_t			*ctb_nodemask;
};

void cfs_cpu_core_siblings(int cpu, cpumask_t *mask);

#endif /* CONFIG_SMP */

#ifndef HAVE_TOPOLOGY_SIBLING_CPUMASK
# define topology_sibling_cpumask(cpu)	topology_thread_cpumask(cpu)
#endif /* HAVE_TOPOLOGY_SIBLING_CPUMASK */

#endif /* __LIBCFS_LINUX_CPU_H__ */
