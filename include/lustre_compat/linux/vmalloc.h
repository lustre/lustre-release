/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_LINUX_VMALLOC_H
#define __LIBCFS_LINUX_VMALLOC_H

#include <linux/vmalloc.h>

#ifndef HAVE_VMALLOC_2ARGS
#define __vmalloc(size, flags) __vmalloc(size, flags, PAGE_KERNEL)
#endif

#ifndef HAVE_KVFREE_ATOMIC_EXPORTED

extern void compat_vfree_atomic(const void *addr);

static inline void kvfree_atomic(const void *addr)
{
	compat_vfree_atomic(addr);
}

void init_compat_vfree_atomic(void);
void exit_compat_vfree_atomic(void);

#else /* !HAVE_KVFREE_ATOMIC_EXPORTED */

static inline void init_compat_vfree_atomic(void) {}
static inline void exit_compat_vfree_atomic(void) {}

#endif /* HAVE_KVFREE_ATOMIC_EXPORTED */

#endif /* __LICBFS_LINUX_VMALLOC_H */
