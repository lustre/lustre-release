// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Helper routines for dumping data structs for debugging.
 */

#define DEBUG_SUBSYSTEM D_OTHER


#include <obd_support.h>
#include "echo_internal.h"
#include <lustre_net.h>

#define LPDS sizeof(__u64)
int block_debug_setup(void *addr, int len, __u64 off, __u64 id)
{
	LASSERT(addr);

	off = cpu_to_le64 (off);
	id = cpu_to_le64 (id);
	memcpy(addr, (char *)&off, LPDS);
	memcpy(addr + LPDS, (char *)&id, LPDS);

	addr += len - LPDS - LPDS;
	memcpy(addr, (char *)&off, LPDS);
	memcpy(addr + LPDS, (char *)&id, LPDS);

	return 0;
}
EXPORT_SYMBOL(block_debug_setup);

int block_debug_check(char *who, void *addr, int end, __u64 off, __u64 id)
{
	__u64 ne_off;
	int err = 0;

	LASSERT(addr);

	ne_off = le64_to_cpu(off);
	id = le64_to_cpu(id);
	if (memcmp(addr, (char *)&ne_off, LPDS)) {
		CDEBUG(D_ERROR,
		       "%s: id %#llx offset %llu off: %#llx != %#llx\n",
		       who, id, off, *(__u64 *)addr, ne_off);
		err = -EINVAL;
	}
	if (memcmp(addr + LPDS, (char *)&id, LPDS)) {
		CDEBUG(D_ERROR, "%s: id %#llx offset %llu id: %#llx != %#llx\n",
		       who, id, off, *(__u64 *)(addr + LPDS), id);
		err = -EINVAL;
	}

	addr += end - LPDS - LPDS;
	if (memcmp(addr, (char *)&ne_off, LPDS)) {
		CDEBUG(D_ERROR,
		       "%s: id %#llx offset %llu end off: %#llx != %#llx\n",
		       who, id, off, *(__u64 *)addr, ne_off);
		err = -EINVAL;
	}
	if (memcmp(addr + LPDS, (char *)&id, LPDS)) {
		CDEBUG(D_ERROR,
		       "%s: id %#llx offset %llu end id: %#llx != %#llx\n",
		       who, id, off, *(__u64 *)(addr + LPDS), id);
		err = -EINVAL;
	}

	return err;
}
EXPORT_SYMBOL(block_debug_check);
#undef LPDS
