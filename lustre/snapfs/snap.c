
/*
 *  fs/snap/snap.c
 *
 *  A snap shot file system.
 *
 */

#define EXPORT_SYMTAB


#define __NO_VERSION__
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/locks.h>
#include <linux/quotaops.h>
#include <linux/list.h>
#include <linux/file.h>
#include <asm/bitops.h>
#include <asm/byteorder.h>

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

/*
 * Return true if the inode is a redirector inode.
 */
int snap_is_redirector(struct inode *cache_inode)
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	cache = snap_find_cache(cache_inode->i_dev);
	if (!cache) {
		EXIT;
		return 0;
	}
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->is_redirector) {
                EXIT;
                return 0;
        }

	CDEBUG(D_SNAP, "ino %ld\n", cache_inode->i_ino);
	return snapops->is_redirector(cache_inode);
}

/*
 * Using a cache inode and clone super block find the real one.
 */
struct inode *snap_redirect(struct inode *cache_inode, 
			    struct super_block *clone_sb)
{
	struct snap_clone_info *clone_info;
	struct snap_table *table;
	struct inode *redirected;
	struct snap_cache *cache;
        struct snapshot_operations *snapops;
	int slot = 0;
	int my_table[SNAP_MAX];
	int clone_slot;

	ENTRY;

        cache = snap_find_cache(cache_inode->i_dev);
        if (!cache) {
                EXIT;
                return NULL;
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->get_indirect) {
                EXIT;
                return NULL;
        }

	CDEBUG(D_SNAP, "cache ino %ld\n", cache_inode->i_ino);
	clone_info = (struct snap_clone_info *)&clone_sb->u.generic_sbp;

	table = &snap_tables[clone_info->clone_cache->cache_snap_tableno];

	/* first find if there are indirected at the clone_index */
	redirected = snapops->get_indirect(cache_inode, NULL, 
					clone_info->clone_index);
	/* if not found, get the FIRST index after this and before NOW */
 	/* XXX fix this later, now use tbl_count, not NOW */
	if(!redirected) {
		clone_slot = snap_index2slot(table, clone_info->clone_index);
		for(slot = table->tbl_count; slot >= clone_slot; slot --)
		{
			my_table[slot-clone_slot+1] = table->tbl_index[slot];
		}
		redirected = snapops->get_indirect 
		(cache_inode, my_table, table->tbl_count - clone_slot + 1);
	}
        /* old version
	redirected = snapops->get_indirect 
			(cache_inode, table->tbl_index,
		 	snap_index2slot(table, clone_info->clone_index));
	*/
	if(redirected) CDEBUG(D_SNAP,"redirected ino %ld\n",redirected->i_ino);
	EXIT;
	return redirected;
}

/*
 * Make a copy of the data and plug a redirector in between if there
 * is no redirector yet.
 */
int snap_do_cow(struct inode *inode, ino_t parent_ino, int del)
{
	struct snap_cache *cache;
	struct snap snap;
	struct inode *ind = NULL;
	struct snapshot_operations *snapops;

	ENTRY;
	CDEBUG(D_SNAP, "snap_do_cow, ino %ld\n", inode->i_ino);

	cache = snap_find_cache(inode->i_dev);
	if (!cache) {
		EXIT;
		return -EINVAL;
	}
	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->create_indirect) {
		EXIT;
		return -EINVAL;
	}
	snap_last(cache, &snap);
	ind = snapops->create_indirect(inode, parent_ino, snap.index, del);
	EXIT;
	if(ind)	{
		iput(ind);
		return	0;
	}
	else
		return -EINVAL;
}

int snap_iterate(struct super_block *sb,
		int (*repeat)(struct inode *inode, void *priv),
		struct inode **start, void *priv, int flag)
{
	struct inode *inode = sb->s_root->d_inode;
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;

        cache = snap_find_cache(inode->i_dev);
        if (!cache) {
                EXIT;
                return 0;
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->iterate) {
                EXIT;
                return 0;
        }

	EXIT;
	return snapops->iterate(sb, repeat, start, priv, flag);
}

int snap_destroy_indirect(struct inode *pri, int index, struct inode *next_ind )
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;
        cache = snap_find_cache(pri->i_dev);
        if (!cache) {
                EXIT;
                return 0;
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->destroy_indirect) {
                EXIT;
                return 0;
        }

	EXIT;
	return snapops->destroy_indirect(pri, index, next_ind);
}

int snap_restore_indirect(struct inode *pri, int index )
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;

        cache = snap_find_cache(pri->i_dev);
        if (!cache) {
                EXIT;
                return 0;
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->restore_indirect) {
                EXIT;
                return 0;
        }

	EXIT;
	return snapops->restore_indirect(pri, index);
}

struct inode *snap_get_indirect(struct inode *pri, int *table, int slot)
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;

        cache = snap_find_cache(pri->i_dev);
        if (!cache) {
                EXIT;
                return NULL;
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->get_indirect) {
                EXIT;
                return NULL;
        }

	EXIT;
	return snapops->get_indirect(pri, table, slot);
}

int snap_migrate_data(struct inode *dst, struct inode *src)
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;

        cache = snap_find_cache(src->i_dev);
        if (!cache) {
                EXIT;
                return 0;
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->migrate_data) {
                EXIT;
                return 0;
        }

	EXIT;
	return snapops->migrate_data(dst, src);
}

int snap_set_indirect(struct inode *pri, ino_t ind_ino, int index, ino_t parent_ino)
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;

        cache = snap_find_cache(pri->i_dev);
        if (!cache) {
                EXIT;
                return -EINVAL;
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->set_indirect) {
                EXIT;
                return -EINVAL;
        }

	EXIT;
	return snapops->set_indirect(pri, ind_ino, index, parent_ino);
}


