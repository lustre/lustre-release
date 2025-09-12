/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SHRINKER_LUSTRE_H
#define _LINUX_SHRINKER_LUSTRE_H

#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/shrinker.h>
#include <linux/types.h>

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

void shrinker_debugfs_fini(void);
int shrinker_debugfs_init(void);
#else
#define ll_shrinker	shrinker

static inline void shrinker_debugfs_fini(void) {};
static inline int shrinker_debugfs_init(void) { return 0; };
#endif

struct shrinker *ll_shrinker_alloc(unsigned int flags,
				   const char *fmt, ...);
void ll_shrinker_register(struct shrinker *shrinker);
void ll_shrinker_free(struct shrinker *shrinker);

#endif /* _LINUX_SHRINKER_LUSTRE_H */
