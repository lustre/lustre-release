/*  
 *  snapfs/cache.c
 */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>
#include <portals/list.h>
#include "snapfs_internal.h" 
/*
 * XXX - Not sure for snapfs that the cache functions are even needed.
 * Can't all lookups be done by an inode->superblock->u.generic_sbp
 * lookup?
 */

extern struct snap_table snap_tables[SNAP_MAX_TABLES];

/* the intent of this hash is to have collision chains of length 1 */
#define CACHES_BITS 8
#define CACHES_SIZE (1 << CACHES_BITS)
#define CACHES_MASK CACHES_SIZE - 1

static struct list_head snap_caches[CACHES_SIZE];


static inline int snap_cache_hash(kdev_t dev)
{
	return (CACHES_MASK) & ((0x000F & (dev)) + ((0x0F00 & (dev)) >>8));
}

inline void snap_cache_add(struct snap_cache *cache, kdev_t dev)
{
	list_add(&cache->cache_chain,
		 &snap_caches[snap_cache_hash(dev)]);
	cache->cache_dev = dev;
}

inline void snap_init_cache_hash(void)
{
	int i;
	for ( i = 0; i < CACHES_SIZE; i++ ) {
		INIT_LIST_HEAD(&snap_caches[i]);
	}
}

/* map a device to a cache */
struct snap_cache *snap_find_cache(kdev_t dev)
{
	struct snap_cache *cache;
	struct list_head *lh;

	lh = &(snap_caches[snap_cache_hash(dev)]);
        list_for_each_entry(cache, lh, cache_chain) { 
		if ( cache->cache_dev == dev )
			return cache;
	}
	return NULL;
}

/* setup a cache structure when we need one */
struct snap_cache *snap_init_cache(void)
{
	struct snap_cache *cache;

	/* make a snap_cache structure for the hash */
	SNAP_ALLOC(cache,  sizeof(struct snap_cache));
	if ( cache ) {
                memset(cache, 0, sizeof(struct snap_cache));
		INIT_LIST_HEAD(&cache->cache_chain);
		INIT_LIST_HEAD(&cache->cache_clone_list);
        }
	return cache;
}
/*walk through the cache structure*/
int snap_cache_process(snap_cache_cb_t cb, void* in, unsigned long* out)
{
	int i = 0;

	for (i = 0; i < CACHES_SIZE; i++) {
		struct snap_cache *cache;
		struct list_head *lh = &(snap_caches[i]);
		list_for_each_entry(cache, lh, cache_chain) {	
			if (cb(cache, in, out))
				goto exit;
		}
	}
exit:
	return 0;
}


/* free a cache structure and all of the memory it is pointing to */
inline void snap_free_cache(struct snap_cache *cache)
{
	if (!cache)
		return;
	SNAP_FREE(cache, sizeof(struct snap_cache));
}

