/*
 * dotsnap.c - support for .snap directories
 */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>

#include "snapfs_internal.h" 

struct inode_operations dotsnap_inode_operations;
struct file_operations dotsnap_file_operations;

int currentfs_is_under_dotsnap(struct dentry *de) 
{
	int index = 0;

	while(de && de->d_parent != de) {
		if ( de->d_inode && de->d_inode->i_ino & 0xF0000000 ) {
			EXIT;
			return index;
		}
		index = (int)de->d_fsdata;
		de = de->d_parent;
	}

	RETURN(0);
}

void currentfs_dotsnap_read_inode(struct snap_cache *cache, 
				  struct inode *inode)
{
	int tableno = cache->cache_snap_tableno; 
	struct snap_table *table; 
	ENTRY;

	table = &snap_tables[tableno];

	inode->i_mode = S_IFDIR | 0755 ;
	inode->i_op = &dotsnap_inode_operations;
	inode->i_size = table->tbl_count - 1; 
	/* all except current form a subdirectory and . and .. */
	inode->i_nlink = table->tbl_count -1 + 2;
	inode->i_uid = 0;
	inode->i_gid = 0;
	EXIT;
}

struct dentry *dotsnap_lookup(struct inode *dir,  struct dentry *dentry)
{
	struct snap_table       *table;
	struct snap_cache       *cache;
	int i;
	int index;
	int tableno; 
	ino_t ino;
	struct inode *inode;
	struct snapshot_operations *snapops;

	ENTRY;

	cache = snap_find_cache(dir->i_dev);
	if ( !cache ) {
		CERROR("dotsnap_readdir: cannot find cache\n");
		make_bad_inode(dir);
		RETURN(ERR_PTR(-EINVAL));
	}

	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->get_indirect_ino) {
                RETURN(ERR_PTR(-EINVAL));
        }

	tableno = cache->cache_snap_tableno; 
	table = &snap_tables[tableno];

	if( table->tbl_count <= 1 )
		RETURN(NULL);
	
	index = table->snap_items[0].index;; 
	for ( i = 1 ; i < table->tbl_count ; i++ ) {
		if ( (dentry->d_name.len == strlen(table->snap_items[i].name)) &&
		     (memcmp(&dentry->d_name.name[0], &table->snap_items[i].name[0], 
			     dentry->d_name.len) == 0) ) {
			index = table->snap_items[i].index; 
			break;
		}
	}
	
	if( i >= table->tbl_count )
		RETURN(ERR_PTR(-ENOENT));

	inode = iget(dir->i_sb, dir->i_ino & (~0xF0000000));

        if ( !inode ) 
                RETURN(ERR_PTR(-EINVAL));

	ino =  snapops->get_indirect_ino(inode, index);
	iput(inode); 

	if ( ino == -ENOATTR || ino == 0 ) {
		ino = dir->i_ino & (~0xF0000000);
	}

	if ( ino == -EINVAL ) {
		RETURN(ERR_PTR(-EINVAL));
	}
	CDEBUG(D_INODE, "index %d, ino is %lu\n",index, ino);

	inode = iget(dir->i_sb, ino);
	d_add(dentry, inode); 
	dentry->d_fsdata = (void*)index;
	inode->i_op = dentry->d_parent->d_parent->d_inode->i_op;
	RETURN(NULL);
}


static int dotsnap_readdir(struct file * filp,
			   void * dirent, filldir_t filldir)
{
	unsigned int i;
	int tableno;
	struct snap_cache *cache;
	struct snap_table *table; 
	struct snapshot_operations *snapops;

	ENTRY; 

	cache = snap_find_cache(filp->f_dentry->d_inode->i_dev);
	if ( !cache ) {
		CDEBUG(D_INODE, "dotsnap_readdir: cannot find cache\n");
		make_bad_inode(filp->f_dentry->d_inode);
		RETURN(-EINVAL);
	}

	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->get_indirect_ino) {
                RETURN(-EINVAL);
        }

	tableno = cache->cache_snap_tableno; 
	table = &snap_tables[tableno];
	for (i = filp->f_pos ; i < table->tbl_count -1 ; i++) {
		int index;
		struct inode *inode;
		ino_t ino;


		inode = filp->f_dentry->d_inode;
		index = table->snap_items[i+1].index;
		ino =  snapops->get_indirect_ino 
			(filp->f_dentry->d_inode, index);

		if ( ino == -ENOATTR || ino == 0 ) {
			ino = filp->f_dentry->d_parent->d_inode->i_ino;
		}
		
		if ( ino == -EINVAL ) {
			return -EINVAL;
		}

		CDEBUG(D_INODE, "Listing %s\n", &table->snap_items[i+1].name[0]);	
		if (filldir(dirent, &table->snap_items[i+1].name[0],
			    strlen(&table->snap_items[i+1].name[0]),
			    filp->f_pos, ino, 0) < 0){
			CDEBUG(D_INODE, "\n");
			break;
		}
		filp->f_pos++;
	}
	RETURN(0);
}


struct file_operations dotsnap_file_operations = {
        readdir: dotsnap_readdir,        /* readdir */
};

struct inode_operations dotsnap_inode_operations =
{
	lookup: dotsnap_lookup
};
