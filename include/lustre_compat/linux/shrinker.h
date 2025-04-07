/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SHRINKER_LUSTRE_H
#define _LINUX_SHRINKER_LUSTRE_H

#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/shrinker.h>
#include <linux/types.h>
#include <libcfs/libcfs.h>

struct ll_shrinker_ops {
#ifdef HAVE_SHRINKER_COUNT
	unsigned long (*count_objects)(struct shrinker *shrinker,
				       struct shrink_control *sc);
	unsigned long (*scan_objects)(struct shrinker *shrinker,
				      struct shrink_control *sc);
#else
	int (*shrink)(struct shrinker *shrinker, struct shrink_control *sc);
#endif
	int seeks;      /* seeks to recreate an obj */
};

#ifndef CONFIG_SHRINKER_DEBUG
struct ll_shrinker {
	struct shrinker ll_shrinker;

	void *private_data;

	int debugfs_id;
	const char *name;
	struct dentry *debugfs_entry;
};
#endif

void ll_shrinker_free(struct shrinker *shrinker);

/* allocate and register a shrinker, return should be checked with IS_ERR() */
struct shrinker *ll_shrinker_create(struct ll_shrinker_ops *ops,
				    unsigned int flags,
				    const char *fmt, ...);

#endif /* _LINUX_SHRINKER_LUSTRE_H */
