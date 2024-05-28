/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * FIEMAP data structures and flags. This header file will be used until
 * fiemap.h is available in the upstream kernel.
 *
 * Author: Kalpak Shah <kalpak.shah@sun.com>
 * Author: Andreas Dilger <adilger@sun.com>
 */

#ifndef _LUSTRE_FIEMAP_H
#define _LUSTRE_FIEMAP_H

#ifdef __KERNEL__
# include <linux/stddef.h>
#else
# include <stddef.h>
#endif
#include <linux/fiemap.h>
#include <linux/types.h>

/**
 * XXX: We use fiemap_extent::fe_reserved[0], notice the high 16bits of it
 * is used to locate the stripe number starting from the very beginning to
 * resume the fiemap call.
 */
#define fe_device	fe_reserved[0]

static inline int get_fe_device(struct fiemap_extent *fe)
{
	return fe->fe_device & 0x1ffff;
}
static inline void set_fe_device(struct fiemap_extent *fe, int devno)
{
	fe->fe_device = (fe->fe_device & 0xfffe0000) | (devno & 0x1ffff);
}
static inline int get_fe_stripenr(struct fiemap_extent *fe)
{
	return fe->fe_device >> 17;
}
static inline void set_fe_stripenr(struct fiemap_extent *fe, int nr)
{
	fe->fe_device = (fe->fe_device & 0x1ffff) | (nr << 17);
}
static inline void set_fe_device_stripenr(struct fiemap_extent *fe, int devno,
					  int nr)
{
	fe->fe_device = (nr << 17) | (devno & 0x1ffff);
}

static inline __kernel_size_t fiemap_count_to_size(__kernel_size_t extent_count)
{
	return sizeof(struct fiemap) + extent_count *
				       sizeof(struct fiemap_extent);
}

static inline unsigned int fiemap_size_to_count(__kernel_size_t array_size)
{
	return (array_size - sizeof(struct fiemap)) /
	       sizeof(struct fiemap_extent);
}

#define FIEMAP_FLAG_DEVICE_ORDER 0x40000000 /* return device ordered mapping */

#ifdef FIEMAP_FLAGS_COMPAT
#undef FIEMAP_FLAGS_COMPAT
#endif

#define FIEMAP_EXTENT_NET       0x80000000 /* Data stored remotely.
					    * Sets NO_DIRECT flag
					    */

#endif /* _LUSTRE_FIEMAP_H */
