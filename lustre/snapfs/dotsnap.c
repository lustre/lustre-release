/*
 * dotsnap.c - support for .snap directories
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

	EXIT;
	return 0;
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
		printk("dotsnap_readdir: cannot find cache\n");
		make_bad_inode(dir);
		EXIT;
		return ERR_PTR(-EINVAL);
	}

	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->get_indirect_ino) {
                EXIT;
                return ERR_PTR(-EINVAL);
        }

	tableno = cache->cache_snap_tableno; 
	table = &snap_tables[tableno];

	if( table->tbl_count <= 1 )
		return NULL;
	
	index = table->tbl_index[0]; 
	for ( i = 1 ; i < table->tbl_count ; i++ ) {
		if ( (dentry->d_name.len == strlen(table->tbl_name[i])) &&
		     (memcmp(dentry->d_name.name, table->tbl_name[i], 
			     dentry->d_name.len) == 0) ) {
			index = table->tbl_index[i]; 
			break;
		}
	}
	
	if( i >= table->tbl_count )
		return ERR_PTR(-ENOENT);

	inode = iget(dir->i_sb, dir->i_ino & (~0xF0000000));

        if ( !inode ) 
                return ERR_PTR(-EINVAL);

	ino =  snapops->get_indirect_ino(inode, index);
	iput(inode); 

	if ( ino == -ENOATTR || ino == 0 ) {
		ino = dir->i_ino & (~0xF0000000);
	}

	if ( ino == -EINVAL ) {
		return ERR_PTR(-EINVAL);
	}
CDEBUG(D_INODE, "index %d, ino is %lu\n",index, ino);

	inode = iget(dir->i_sb, ino);
	d_add(dentry, inode); 
	dentry->d_fsdata = (void*)index;
	inode->i_op = dentry->d_parent->d_parent->d_inode->i_op;
	return NULL;
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
		printk("dotsnap_readdir: cannot find cache\n");
		make_bad_inode(filp->f_dentry->d_inode);
		EXIT;
		return -EINVAL;
	}

	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->get_indirect_ino) {
                EXIT;
                return -EINVAL;
        }

	tableno = cache->cache_snap_tableno; 
	table = &snap_tables[tableno];
	CDEBUG(D_INODE, "\n");	
	for (i = filp->f_pos ; i < table->tbl_count -1 ; i++) {
		int index;
		struct inode *inode;
		ino_t ino;

		CDEBUG(D_INODE, "%d\n",i);	

		inode = filp->f_dentry->d_inode;
		index = table->tbl_index[i+1];
		ino =  snapops->get_indirect_ino 
			(filp->f_dentry->d_inode, index);

		CDEBUG(D_INODE, "\n");	

		if ( ino == -ENOATTR || ino == 0 ) {
			ino = filp->f_dentry->d_parent->d_inode->i_ino;
		}

		CDEBUG(D_INODE, "\n");	
		if ( ino == -EINVAL ) {
			return -EINVAL;
		}

		CDEBUG(D_INODE, "Listing %s\n", table->tbl_name[i+1]);	
		if (filldir(dirent, table->tbl_name[i+1],
			    strlen(table->tbl_name[i+1]),
			    filp->f_pos, ino) < 0){
			CDEBUG(D_INODE, "\n");
			break;
		}
		filp->f_pos++;
	}
	EXIT;
	return 0;
}


struct file_operations dotsnap_file_operations = {
        readdir: dotsnap_readdir,        /* readdir */
};

struct inode_operations dotsnap_inode_operations =
{
	default_file_ops: &dotsnap_file_operations,
	lookup: dotsnap_lookup
};
