/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SHRINKER_LUSTRE_H
#define _LINUX_SHRINKER_LUSTRE_H

#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/shrinker.h>
#include <linux/types.h>
#include <libcfs/libcfs.h>

#if !defined(CONFIG_SHRINKER_DEBUG) || defined(HAVE_REGISTER_SHRINKER_FORMAT_NAMED)
struct ll_shrinker {
	struct shrinker ll_shrinker;

  #ifndef CONFIG_SHRINKER_DEBUG
	int debugfs_id;
	const char *name;
	struct dentry *debugfs_entry;
  #endif
  #ifdef HAVE_REGISTER_SHRINKER_FORMAT_NAMED
	struct va_format vaf;
  #endif
};
#else
#define ll_shrinker	shrinker
#endif

struct shrinker *ll_shrinker_alloc(unsigned int flags,
				   const char *fmt, ...);
void ll_shrinker_register(struct shrinker *shrinker);
void ll_shrinker_free(struct shrinker *shrinker);

#endif /* _LINUX_SHRINKER_LUSTRE_H */
