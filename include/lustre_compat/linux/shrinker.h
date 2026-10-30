/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SHRINKER_LUSTRE_H
#define _LINUX_SHRINKER_LUSTRE_H

/*
 * <linux/shrinker.h> is included from deep inside other kernel headers
 * (fs.h -> list_lru.h), so do not pull in heavy headers such as mm.h here.
 * The RHEL8 header is not self-contained: supply its prerequisites first.
 */
#include <linux/types.h>
#include <linux/atomic.h>
/* gcc 8 macro-expands "linux" in __has_include(<...>), so use "" */
#if defined(__has_include)
#if __has_include("linux/rh_kabi.h")
#include <linux/rh_kabi.h>
#endif
#endif
#include_next <linux/shrinker.h>
#include <linux/printk.h>

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

#if !defined(CONFIG_SHRINKER_DEBUG)
void shrinker_debugfs_fini(void);
int shrinker_debugfs_init(void);
#else

static inline void shrinker_debugfs_fini(void) {};
static inline int shrinker_debugfs_init(void) { return 0; };
#endif

struct shrinker *ll_shrinker_alloc(unsigned int flags,
				   const char *fmt, ...);
void ll_shrinker_register(struct shrinker *shrinker);
void ll_shrinker_free(struct shrinker *shrinker);
const char *shrinker_debugfs_path(struct shrinker *shrinker);

#endif /* _LINUX_SHRINKER_LUSTRE_H */
