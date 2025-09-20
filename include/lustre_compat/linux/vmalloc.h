/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_LINUX_VMALLOC_H
#define __LIBCFS_LINUX_VMALLOC_H

#include <linux/vmalloc.h>

#ifdef HAVE_VMALLOC_2ARGS
#define __compat_vmalloc(size, flags) __vmalloc(size, flags)
#else
#define __compat_vmalloc(size, flags) __vmalloc(size, flags, PAGE_KERNEL)
#endif

extern void compat_vfree_atomic(const void *addr);

#endif /* __LICBFS_LINUX_VMALLOC_H */
