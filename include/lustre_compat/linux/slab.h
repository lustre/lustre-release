/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef _LINUX_SLAB_LUSTRE_H
#define _LINUX_SLAB_LUSTRE_H

#include_next <linux/slab.h>

#ifndef HAVE_KFREE_SENSITIVE
#define kfree_sensitive(x)      kzfree(x)
#endif

/*
 * linux commit v6.8-5277-gf88c3fb81c4ba
 *  v6.8-5277-gf88c3fb81c4ba
 */
#ifndef SLAB_MEM_SPREAD
#define SLAB_MEM_SPREAD		0
#endif

#endif /* _LINUX_SLAB_LUSTRE_H */
