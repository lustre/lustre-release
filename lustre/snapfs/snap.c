
/*
 *  fs/snap/snap.c
 *
 *  A snap shot file system.
 *
 */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/snap.h>
#include "snapfs_internal.h" 

/*
 * Return true if the inode is a redirector inode.
 */
int snap_is_redirector(struct inode *cache_inode)
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	cache = snap_find_cache(cache_inode->i_dev);
	if (!cache) {
		return 0;
	}
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->is_redirector) {
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
                RETURN(NULL);
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->get_indirect) {
                RETURN(NULL);
        }

	CDEBUG(D_SNAP, "cache ino %ld\n", cache_inode->i_ino);
	clone_info = (struct snap_clone_info *)&clone_sb->u.generic_sbp;

	table = &snap_tables[clone_info->clone_cache->cache_snap_tableno];

	/* first find if there are indirected at the clone_index */
	redirected = snapops->get_indirect(cache_inode, NULL, 
					clone_info->clone_index);
	/* if not found, get the FIRST index after this and before NOW */
 	/* XXX fix this later, now use tbl_count, not NOW */
	if (!redirected) {
		int index;
		clone_slot = snap_index2slot(table, clone_info->clone_index);
		for (slot = table->tbl_count-1; slot >= clone_slot; slot --) {
			my_table[slot-clone_slot+1] = table->snap_items[slot].index;
		}
		index = table->tbl_count - clone_slot + 1;
		redirected = snapops->get_indirect(cache_inode, my_table, index);
	}

	if (redirected) 
		CDEBUG(D_SNAP,"redirected ino %ld\n",redirected->i_ino);

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
		RETURN(-EINVAL);
	}
	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->create_indirect) {
		RETURN(-EINVAL);
	}

	snap_last(cache, &snap);
	ind = snapops->create_indirect(inode, snap.index, snap.gen, parent_ino, del);
	if(!ind)
		RETURN(-EINVAL);		
	init_filter_data(ind, 0);
	set_filter_ops(cache, ind);		
	iput(ind);
	RETURN(0);
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
                RETURN(0);
        }
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->iterate) {
                RETURN(0);
        }

	return snapops->iterate(sb, repeat, start, priv, flag);
}

int snap_destroy_indirect(struct inode *pri, int index, struct inode *next_ind )
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;
        cache = snap_find_cache(pri->i_dev);
        if (!cache) 
        	RETURN(0);
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->destroy_indirect) 
                RETURN(0);

	return snapops->destroy_indirect(pri, index, next_ind);
}

int snap_restore_indirect(struct inode *pri, int index )
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;

        cache = snap_find_cache(pri->i_dev);
        if (!cache) 
                RETURN(0);

        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->restore_indirect) 
                RETURN(0);

	return snapops->restore_indirect(pri, index);
}

struct inode *snap_get_indirect(struct inode *pri, int *table, int slot)
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;

        cache = snap_find_cache(pri->i_dev);
        if (!cache) 
                RETURN(NULL);
        
        snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->get_indirect) 
                RETURN(NULL);

	return snapops->get_indirect(pri, table, slot);
}

int snap_set_indirect(struct inode *pri, ino_t ind_ino, int index, ino_t parent_ino)
{
	struct snap_cache *cache;
        struct snapshot_operations *snapops;

	ENTRY;

        cache = snap_find_cache(pri->i_dev);
        if (!cache) 
                RETURN(-EINVAL);
        
	snapops = filter_c2csnapops(cache->cache_filter);
        if (!snapops || !snapops->set_indirect) 
                RETURN(-EINVAL);

	EXIT;
	return snapops->set_indirect(pri, ind_ino, index, parent_ino);
}


