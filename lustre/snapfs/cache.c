/*
 *
 *
 *  Copyright (C) 2000 Stelias Computing, Inc.
 *  Copyright (C) 2000 Red Hat, Inc.
 *
 *
 */


#include <stdarg.h>

#include <asm/bitops.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/malloc.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/locks.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#define __NO_VERSION__
#include <linux/module.h>

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

/*
 * XXX - Not sure for snapfs that the cache functions are even needed.
 * Can't all lookups be done by an inode->superblock->u.generic_sbp
 * lookup?
 */

/*
   This file contains the routines associated with managing a
   cache of files .  These caches need to be found
   fast so they are hashed by the device, with an attempt to have
   collision chains of length 1.
*/

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
	struct list_head *lh, *tmp;

	lh = tmp = &(snap_caches[snap_cache_hash(dev)]);
	while ( (tmp = lh->next) != lh ) {
		cache = list_entry(tmp, struct snap_cache, cache_chain);
		if ( cache->cache_dev == dev )
			return cache;
	}
	return NULL;
}


/* map an inode to a cache */
struct snap_cache *snap_get_cache(struct inode *inode)
{
	struct snap_cache *cache;

	/* find the correct snap_cache here, based on the device */
	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) {
		printk("WARNING: no  cache for dev %d, ino %ld\n",
		       inode->i_dev, inode->i_ino);
		return NULL;
	}

	return cache;
}


/* another debugging routine: check fs is InterMezzo fs */
int snap_ispresto(struct inode *inode)
{
	struct snap_cache *cache;

	if ( !inode )
		return 0;
	cache = snap_get_cache(inode);
	if ( !cache )
		return 0;
	return (inode->i_dev == cache->cache_dev);
}

/* setup a cache structure when we need one */
struct snap_cache *snap_init_cache(void)
{
	struct snap_cache *cache;

	/* make a snap_cache structure for the hash */
	SNAP_ALLOC(cache, struct snap_cache *, sizeof(struct snap_cache));
	if ( cache ) {
		memset(cache, 0, sizeof(struct snap_cache));
		INIT_LIST_HEAD(&cache->cache_chain);
		INIT_LIST_HEAD(&cache->cache_clone_list);
	}
	return cache;
}


/* free a cache structure and all of the memory it is pointing to */
inline void snap_free_cache(struct snap_cache *cache)
{
	if (!cache)
		return;


	SNAP_FREE(cache, sizeof(struct snap_cache));
}

