
/*
 *  snaptable.c
 *
 *  Manipulate snapshot tables
 *
 */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/snap.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include "snapfs_internal.h" 


struct snap_table snap_tables[SNAP_MAX_TABLES];

#if 0
static void snap_lock_table(int table_no)
{

	spin_lock(snap_tables[table_no].tbl_lock);

}

static void snap_unlock_table(int table_no)
{

	spin_unlock(snap_tables[table_no].tbl_lock);

}
#endif

int snap_index2slot(struct snap_table *snap_table, int snap_index)
{
	int slot;

	for ( slot=0 ; slot < snap_table->tbl_count ; slot++ )
		if ( snap_table->snap_items[slot].index == snap_index )
			return slot;
	return -1;
}



/* latest snap: returns 
   -  the index of the latest snapshot before NOW
   -  hence it returns 0 in case all the volume snapshots lie in the future
   -  this is the index where a COW will land (will be created) 
*/

void snap_last(struct snap_cache *info, struct snap *snap)
{
	int i ;
	time_t now = CURRENT_TIME;
	struct snap_table *table;
	int tableno = info->cache_snap_tableno;

	ENTRY;
	if ( tableno < 0 || tableno > SNAP_MAX_TABLES ) {
		CERROR("invalid table no %d\n", tableno);
		snap->index = -1;
	}
	
	table = &snap_tables[tableno];

	/* start at the highest index in the superblock 
	   snaptime array */ 
	i = table->tbl_count - 1;

	/* NOTE: i>0 is an unnecessary check */
	snap->index = table->snap_items[i].index;
	snap->time = table->snap_items[i].time;
	snap->gen = table->snap_items[i].gen;
	CDEBUG(D_SNAP, "index: %d, time[i]: %ld, now: %ld\n",
	       snap->index, snap->time, now);
	return;
}

/* return -1 if no COW is needed, otherwise the index of the 
   clone to COW to is returned
*/

int snap_needs_cow(struct inode *inode)
{
	struct snap snap;
	struct snap_cache *cache;
	struct filter_inode_info   *filter_info; 
	int index = -1;
	ENTRY;

	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) {
		RETURN(index);
	}
	filter_info = (struct filter_inode_info *) inode->i_filterdata;
	/* here we find the time of the last snap to compare with */

	snap_last(cache, &snap);
	/* decision .... if the snapshot is more recent than the object,
	 * then any change to the object should cause a COW.
	 */
	if (filter_info && filter_info->generation < snap.gen ) {
		index = snap.index;
	}

	CDEBUG(D_SNAP, "snap_needs_cow, ino %lu , get index %d\n",
	       inode->i_ino, index);

	RETURN(index);
} /* snap_needs_cow */

int snap_print_table(struct ioc_snap_tbl_data *data, char *buf, int *buflen)
{
	struct snap_table *table;
	struct ioc_snap_tbl_data *stbl_out;
	int tableno = data->no;
	int i, rc = 0, nleft = (*buflen);

	char *buf_ptr;

	if (tableno < 0 || tableno > SNAP_MAX_TABLES) {
		CERROR("invalid table number %d\n", tableno);
		RETURN(-EINVAL);
	}
	
	table = &snap_tables[tableno];
	stbl_out = (struct ioc_snap_tbl_data *)buf;
	stbl_out->count = table->tbl_count - 1;
	stbl_out->no = tableno;	
	buf_ptr = (char*)stbl_out->snaps; 
	nleft -= buf_ptr - buf; 
	for (i = 1; i < table->tbl_count; i++) {
		memcpy(buf_ptr, &table->snap_items[i], sizeof(struct snap));
		
		nleft -= sizeof(struct snap);
		if(nleft < 0) { 
			CERROR("can not get enough space to print snaptable\n");
			rc = -ERANGE;
			goto exit; 
		} else {
			buf_ptr += sizeof(struct snap);
		}	
	}
exit:
	if(nleft > 0) 
		(*buflen) = (*buflen) - nleft;
	return 0;
}
static int inline get_index_of_item(struct snap_table *table, char *name)
{
	int count = table->tbl_count;
	int i, j;
	
	for (i = 0; i < SNAP_MAX; i++) { 
		if (!strcmp(name, table->snap_items[i].name)) 
			return -EINVAL;	
	}
	for (i = 0; i < SNAP_MAX; i++) {
		int found = 0;
		for (j = 0; j < (count + 1); j++) {
			if (table->snap_items[j].index == i) {
				found = 1;
				break;	
			}
                }
		if (!found)
			return i;
	}
	return -EINVAL;
}
/* This function will write one item(a snapshot) to snaptable  
 * and will also write to disk.
 */
static int snaptable_add_item(struct ioc_snap_tbl_data *data)
{
	struct snap_table 		*table;
	struct snap_disk_table 		*disk_snap_table;
	struct snapshot_operations 	*snapops;
	struct snap_cache 		*cache;
	int 				tableno , index, i, count, rc;
	
	if (!(cache = snap_find_cache((kdev_t)data->dev)))
		RETURN(-ENODEV);

	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->set_meta_attr)
		RETURN(-EINVAL);

	tableno = data->no;
	if (tableno < 0 || tableno > SNAP_MAX_TABLES) {
		CERROR("invalid table number %d\n", tableno);
		RETURN(-EINVAL);
	}
	table = &snap_tables[tableno];	
	count = table->tbl_count;

	/* XXX Is down this sema necessary*/
	down_interruptible(&table->tbl_sema);

	/*add item in snap_table set generation*/
	table->snap_items[count].gen = table->generation + 1;
	table->snap_items[count].time = CURRENT_TIME;
	/* find table index */
	index = get_index_of_item(table, data->snaps[0].name);
	if (index < 0)
		GOTO(exit, rc = -EINVAL);
	
	table->snap_items[count].index = index;
	table->snap_items[count].flags = 0;
	memcpy(&table->snap_items[count].name[0], 
	       data->snaps[0].name, SNAP_MAX_NAMELEN);
	/* we will write the whole snap_table to disk */
	SNAP_ALLOC(disk_snap_table, sizeof(struct snap_disk_table));
	if (!disk_snap_table)
		GOTO(exit, rc = -ENOMEM);
	disk_snap_table->magic = cpu_to_le32((__u32)DISK_SNAP_TABLE_MAGIC);
	disk_snap_table->count = cpu_to_le32((__u32)table->tbl_count) - 1;
	disk_snap_table->generation = cpu_to_le32((__u32)table->generation);
	memset(&disk_snap_table->snap_items[0], 0, 
	       SNAP_MAX * sizeof(struct snap_disk));
	
	for (i = 1; i <= count; i++) {
		struct snap *item = &table->snap_items[i];
		disk_snap_table->snap_items[i-1].time = cpu_to_le64((__u64)item->time);
		disk_snap_table->snap_items[i-1].gen = cpu_to_le32((__u32)item->gen);
		disk_snap_table->snap_items[i-1].flags = cpu_to_le32((__u32)item->flags);
		disk_snap_table->snap_items[i-1].index = cpu_to_le32((__u32)item->index);
		memcpy(&disk_snap_table->snap_items[i-1].name , item->name, SNAP_MAX_NAMELEN);
	}
	rc = snapops->set_meta_attr(cache->cache_sb, DISK_SNAPTABLE_ATTR,
				    (char*)disk_snap_table, sizeof(struct snap_disk_table));

	SNAP_FREE(disk_snap_table, sizeof(struct snap_disk_table));
	table->tbl_count++;
	table->generation++;
exit:
	up(&table->tbl_sema);
	RETURN(rc);
}

static int delete_inode(struct inode *primary, void *param)
{
	struct snap_iterdata * data;
	int tableno = 0;
	int index = 0;
	int rc = 0;

	struct inode *redirect;
	ino_t old_ind = 0;
	struct snap_table *table;
	int slot;
	int delete_slot;
	int this_index;
	struct inode *next_ind = NULL;
	int my_table[SNAP_MAX];

	if(!primary) return 0;

	data = (struct snap_iterdata*) param;

	if(data) {
		index = data->index;
		tableno = data->tableno;
	}

	CDEBUG(D_INODE, "delete_inode ino %lu, index %d\n", primary->i_ino, index);

	table = &snap_tables[tableno];

	redirect = snap_get_indirect(primary, NULL, index);

	if(!redirect)	
		return 0;

	old_ind = redirect->i_ino;
	iput(redirect);
	slot = snap_index2slot(table, index) - 1;
	if( slot > 0 ) {
		this_index = table->snap_items[slot].index;
		redirect = snap_get_indirect(primary, NULL, this_index);
		if(redirect)	
			iput(redirect);
		else  {
			snap_set_indirect(primary, old_ind, this_index, 0);
			snap_set_indirect(primary, 0, index, 0);
			return 0;
		}
	}

	/* get the FIRST index after this and before NOW */
	/* used for destroy_indirect and block level cow */
 	/* XXX fix this later, now use tbl_count, not NOW */
	delete_slot = snap_index2slot(table, index);
	for(slot = table->tbl_count; slot > delete_slot; slot --)
	{
		my_table[slot - delete_slot] = table->snap_items[slot].index;
	}
	next_ind = snap_get_indirect 
		(primary, my_table, table->tbl_count - delete_slot );
	if( next_ind && (next_ind->i_ino == primary->i_ino) ) {
		iput(next_ind);
		next_ind = NULL;
	}

	if( next_ind && (next_ind->i_ino == old_ind) ) {
		iput(next_ind);
		next_ind = NULL;
	}

	rc = snap_destroy_indirect(primary, index, next_ind);

	if(next_ind)	iput(next_ind);

	if(rc != 0)	
		CERROR("snap_destroy_indirect(ino %lu,index %d),ret %d\n",
			primary->i_ino, index, rc);
	return 0;
}

static int snap_delete(struct super_block *sb, struct snap_iterdata *data)
{
	CDEBUG(D_SNAP, "dev %d, tableno %d, index %d, time %lu\n",
		data->dev, data->tableno, data->index, data->time );

	snap_iterate(sb, &delete_inode, NULL, data, SNAP_ITERATE_COWED_INODE);
	
	return 0;
}

/* This function will delete one item(a snapshot) in the snaptable  
 * and will also delete the item in the disk.
 */
int snaptable_delete_item(struct super_block *sb, struct snap_iterdata *data)
{
	struct snap_table 		*table;
	struct snap_disk_table 		*disk_snap_table;
	struct snapshot_operations 	*snapops;
	struct snap_cache 		*cache;
	int 				tableno = data->tableno, index, i, slot, rc, count;
	
	if (!(cache = snap_find_cache((kdev_t)data->dev)))
		RETURN(-ENODEV);

	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->set_meta_attr)
		RETURN(-EINVAL);

	if (tableno < 0 || tableno > SNAP_MAX_TABLES) {
		CERROR("invalid table number %d\n", tableno);
		RETURN(-EINVAL);
	}
	/*first delete the snapshot
	 * FIXME if snap delete error, how to handle this error*/
	rc = snap_delete(sb, data);
	if (rc) 
		RETURN(-EINVAL);
	/*delete item in snaptable */
	table = &snap_tables[tableno];
	index = data->index;

	slot = snap_index2slot(table, index);
	if (slot < 0)
		RETURN(-EINVAL);

	down_interruptible(&table->tbl_sema);
	while(slot < table->tbl_count) {
		struct snap *item = &table->snap_items[slot];
		item->time = table->snap_items[slot + 1].time;
		item->flags = table->snap_items[slot + 1].flags;
		item->gen = table->snap_items[slot + 1].gen;
		item->index = table->snap_items[slot + 1].index;
		memcpy(&item->name[0], &table->snap_items[slot + 1].name[0],
			SNAP_MAX_NAMELEN);
	}

	table->tbl_count --;
	
	SNAP_ALLOC(disk_snap_table, sizeof(struct snap_disk_table));

	if (!disk_snap_table)
		RETURN(-ENOMEM);
	/* we will delete the item  snap_table to disk */
	
	disk_snap_table->magic = cpu_to_le32((__u32)DISK_SNAP_TABLE_MAGIC);
	disk_snap_table->count = cpu_to_le32((__u32)table->tbl_count);
	disk_snap_table->generation = cpu_to_le32((__u32)table->generation);
	memset(&disk_snap_table->snap_items[0], 0, 
	       SNAP_MAX * sizeof(struct snap_disk));

	count = table->tbl_count;

	for (i = 1; i <= count; i++) {
		struct snap *item = &table->snap_items[i];
		disk_snap_table->snap_items[i].time = cpu_to_le64((__u64)item->time);
		disk_snap_table->snap_items[i].gen = cpu_to_le32((__u32)item->gen);
		disk_snap_table->snap_items[i].flags = cpu_to_le32((__u32)item->flags);
		disk_snap_table->snap_items[i].index = cpu_to_le32((__u32)item->index);
		memcpy(&disk_snap_table->snap_items[i].name , item->name, SNAP_MAX_NAMELEN);
	}
	rc = snapops->set_meta_attr(cache->cache_sb, DISK_SNAPTABLE_ATTR,
				    (char*)disk_snap_table, sizeof(struct snap_disk_table));

	SNAP_FREE(disk_snap_table, sizeof(struct snap_disk_table));
	
	up(&table->tbl_sema);
	
	RETURN(0);
}

int snapfs_read_snaptable(struct snap_cache *cache, int tableno)
{
	struct snap_table 		*table;
	struct snap_disk_table 		*disk_snap_table;
	struct snapshot_operations 	*snapops;
	int 				i, rc;
	int				size = 0;

	
	snapops = filter_c2csnapops(cache->cache_filter);
	if (!snapops || !snapops->get_meta_attr)
		RETURN(-EINVAL);
	
	SNAP_ALLOC(disk_snap_table, sizeof(struct snap_disk_table));

	size = sizeof(struct snap_disk_table);

	
	table = &snap_tables[tableno];

	memset(table, 0, sizeof(struct snap_table));
        init_MUTEX(&table->tbl_sema); 

	/*Initialized table */
	table->tbl_count = 1;
	rc = snapops->get_meta_attr(cache->cache_sb, DISK_SNAPTABLE_ATTR,
			       (char*)disk_snap_table, &size);
	if (rc < 0) {
		SNAP_FREE(disk_snap_table, sizeof(struct snap_disk_table));
		RETURN(rc);
	}
	
	if (le32_to_cpu(disk_snap_table->magic) != DISK_SNAP_TABLE_MAGIC) {
		CERROR("On disk snaptable is not right \n");
		RETURN(rc);
	}
	table->generation = le32_to_cpu(disk_snap_table->generation);
	table->tbl_count += le32_to_cpu(disk_snap_table->count);
	for ( i = 0; i < disk_snap_table->count; i++) {
		struct snap *item = &table->snap_items[i + 1];
		item->time = le64_to_cpu(disk_snap_table->snap_items[i].time);
		item->gen = le32_to_cpu(disk_snap_table->snap_items[i].gen);
		item->flags = le32_to_cpu(disk_snap_table->snap_items[i].flags);
		item->index = le32_to_cpu(disk_snap_table->snap_items[i].index);
		memcpy(&item->name[0], &disk_snap_table->snap_items[i].name[0],
		       SNAP_MAX_NAMELEN);
	}
	SNAP_FREE(disk_snap_table, sizeof(struct snap_disk_table));
	return 0;
}

static int getdata(struct ioc_data *input, void **karg)
{
	void *tmp = NULL;

	if (!input->ioc_inlen || !input->ioc_inbuf) 
		return 0;

	SNAP_ALLOC(tmp, input->ioc_inlen);
	if (!tmp)
		RETURN(-ENOMEM);

	CDEBUG(D_SNAP, "snap_alloc:len %d, add %p\n", input->ioc_inlen, tmp);

	memset(tmp, 0, input->ioc_inlen);
	if (copy_from_user(tmp, input->ioc_inbuf, input->ioc_inlen)) {
		CERROR("get inbuf data error \n");
		SNAP_FREE(tmp, input->ioc_inlen);
		RETURN(-EFAULT);
	}
	*karg = tmp;

	return 0;
}

static inline void freedata(void *data, struct ioc_data *input) 
{
	SNAP_FREE(data, input->ioc_inlen);
	CDEBUG(D_SNAP, "snap_free:len %d, add %p\n", input->ioc_inlen, data);
}

static int get_next_inode(struct inode *pri, void *ino)
{
	static ino_t prev_ino = -1 ;	
        ino_t this_ino = pri->i_ino;
	ino_t find_ino = *(ino_t *)ino;
	ino_t *found = ino; 

	if( find_ino == 0) {
		(*found) = this_ino;
		return -1;
	}

	if( find_ino == prev_ino ) {
		(*found) = this_ino;
		return -1;
	}
	else {
		prev_ino = this_ino; 
	} 	
	return 0;
}


static int snap_get_next_inode(struct snap_ino_list_data *data, ino_t *found_ino, ino_t *parent_ino)
{
	kdev_t dev = data->dev;
	ino_t this_ino = data->ino; 

	struct snap_cache *cache;

	struct inode *inode;
	struct dentry * dentry;

	ENTRY;

	cache = snap_find_cache(dev); 
	if ( !cache ) {
                EXIT;
                return -EINVAL;
        }

	snap_iterate( cache->cache_sb, &get_next_inode, NULL, &(data->ino), 
			SNAP_ITERATE_COWED_INODE);

	if( data->ino == this_ino ) {
		data->ino = 0;
	}

	*found_ino = data->ino;

	if( !(*found_ino) )	return 0;

	*parent_ino = 0;
	inode = iget (cache->cache_sb, *found_ino);
	if (list_empty(&inode->i_dentry)) {
		CERROR("No dentry for ino %lu, Error(XXX)! \n", inode->i_ino);
		iput(inode);	
       		return 0;
	}
	else {
		dentry = dget(list_entry(inode->i_dentry.next, struct dentry, d_alias));
	}
	if( dentry->d_parent->d_inode)	
		*parent_ino = dentry->d_parent->d_inode->i_ino;
	else	
		*parent_ino = 0;

	dput(dentry);
	iput(inode);

	return 0;
}

static int print_inode(struct inode *pri,void *param)
{
	CDEBUG(D_SNAP, "cowed inode list: ino %lu \n", pri->i_ino);
	return 0;
}

static int snap_print(struct super_block *sb, void *data)
{
	snap_iterate(sb, &print_inode, NULL, data, SNAP_ITERATE_COWED_INODE);
	return 0;
}

static int delete_new_inode(struct inode *pri, void *param)
{
	struct snap_iterdata * data;

	int index = 1;
	time_t restore_time = 0xFFFFFFFF;

	ENTRY; 

	if(!pri) return 0;

	if(snap_is_redirector(pri)){
		EXIT;
		return 0;
	}

	data = (struct snap_iterdata*) param;

	if(data) {
		index = data->index;
		restore_time = data->time;
	}

	CDEBUG(D_SNAP, "ino %lu, index=%d, time=%lu\n", 
			pri->i_ino, index, restore_time);


	if( pri->i_mtime > restore_time || pri->i_ctime > restore_time ) {
		struct list_head *head = &pri->i_dentry, *pos;

		CDEBUG(D_SNAP, "snap_restore ino %lu is newer, delete \n",pri->i_ino);
		for( pos = head->next; pos != head; pos = pos->next ){
			d_drop( list_entry(pos, struct dentry, d_alias) );
		}
		pri->i_nlink = 0;
	}
	return 0;

}

static int restore_inode(struct inode *pri, void *param)
{
	struct snap_iterdata * data;
//	struct snap_cache *cache;
	int tableno = 0;

	int index = 1;
	time_t restore_time = 0xFFFFFFFF;

	struct inode *ind = NULL;
	int slot;
	int restore_slot;
	struct snap_table *table;
	int restore_index;
	
	ENTRY; 

	if(!pri) return 0;

	data = (struct snap_iterdata*) param;

	if(data) {
		index = data->index;
		tableno  = data->tableno;
		restore_time = data->time;
	}

	CDEBUG(D_SNAP, "ino %lu, index=%d, time=%lu, tableno %d\n", 
			pri->i_ino, index, restore_time, tableno);

       	/* XXX: should we have = here? */	
	if(pri->i_mtime > restore_time || pri->i_ctime > restore_time) {
		restore_index = index;
		table = &snap_tables[tableno];
		/* first find if there are indirected at the index */
		ind = snap_get_indirect(pri, NULL, index);
		/* if not found, get the FIRST index after this and before NOW*/
 		/* XXX fix this later, now use tbl_count, not NOW */
		if(!ind) {
			restore_slot = snap_index2slot(table, index);
			for(slot = restore_slot; slot <= table->tbl_count; 
			    slot++) {
				ind = snap_get_indirect (pri, NULL, 
					table->snap_items[slot].index);
				if(ind)	{
					restore_index = table->snap_items[slot].index;
					break;
				}
			}
		}

		if(ind) {
			CDEBUG(D_SNAP, "restore ino %lu with index %d\n",
					pri->i_ino, restore_index);
			iput(ind);
			snap_restore_indirect(pri, restore_index);
			/* XXX */
			//delete_inode(pri, param);
			snap_destroy_indirect(pri, restore_index, NULL);
		}
		else {	
			CDEBUG(D_SNAP, "ERROR:restore ino %lu\n", pri->i_ino);	
		}
	}
	else {
		CDEBUG(D_SNAP, "ino %lu is older, don't restore\n", pri->i_ino);
	}
	EXIT;
	return 0;
}

//int snap_restore(struct super_block *sb, void *data)
static int snap_restore(struct super_block *sb, struct snap_iterdata *data)
{	
	CDEBUG(D_SNAP, "dev %d, tableno %d, index %d, time %lu\n",
		data->dev, data->tableno, data->index, data->time );

	snap_iterate(sb, &delete_new_inode, NULL, data, SNAP_ITERATE_ALL_INODE);
	snap_iterate(sb, &restore_inode, NULL, data, SNAP_ITERATE_COWED_INODE );
	return 0;
}

/* return the index number of a name in a table */
int snap_get_index_from_name(int tableno, char *name)
{
	struct snap_table *table;
	int slot;

	if ( tableno < 0 || tableno > SNAP_MAX_TABLES ) {
		CERROR("invalid table number %d\n", tableno);
		return -EINVAL;
	}

	table = &snap_tables[tableno];

	for ( slot = 0 ; slot < SNAP_MAX ; slot++ ) {
		if(strncmp (&table->snap_items[slot].name[0], name, 
			SNAP_MAX_NAMELEN) == 0 ) {
			return table->snap_items[slot].index;
		}
	}
	return -EINVAL;
}

int snap_iterate_func(int len, struct snap_ioc_data *ioc_data, unsigned int cmd)
{
	struct snap_iterdata data;
	struct super_block *sb;
	struct snap_cache *cache;
	struct snap_table *table;
	char name[SNAP_MAX_NAMELEN];
	int index, tableno, name_len, slot, rc;
	
	kdev_t dev ;

	ENTRY;

	dev = ioc_data->dev;
	cache = snap_find_cache(dev); 
	if ( !cache ) 
                RETURN(-EINVAL);

	sb = cache->cache_sb;
	tableno = cache->cache_snap_tableno;
	table = &snap_tables[tableno];

	name_len = len - sizeof(kdev_t);	
	memset(name, 0, SNAP_MAX_NAMELEN);	
	if(name_len > SNAP_MAX_NAMELEN)
		name_len = SNAP_MAX_NAMELEN;
	if(name_len < 0 ) 
		name_len = 0;
	memcpy(name, ioc_data->name, name_len);
	
	if ((index = snap_get_index_from_name (tableno, name)) < 0) 
		RETURN(-EINVAL);
	
	data.dev = dev;
	data.index = index;
	data.tableno = tableno;
	slot = snap_index2slot (table, index);
	if( slot < 0 ) 
		RETURN(-EINVAL);
	
	data.time = table->snap_items[slot].time;
	CDEBUG(D_SNAP, "dev %d, tableno %d, index %d, time %lu\n",
		data.dev, data.tableno, data.index, data.time );

	switch (cmd) {
		case IOC_SNAP_DEBUG:
			rc = snap_print(sb, &data);	
			break;
		case IOC_SNAP_DELETE:
			rc = snaptable_delete_item(sb, &data);	
			break;
		case IOC_SNAP_RESTORE:
			rc = snap_restore(sb, &data);	
			break;
		default:
			CERROR("unrecognized cmd %d \n", cmd);
			rc = -EINVAL;
			break;
	}
	RETURN(0);
}

#define BUF_SIZE 1024
int snap_ioctl (struct inode * inode, struct file * filp, 
                            unsigned int cmd, unsigned long arg)
{
	struct ioc_data input; 
	void *karg = NULL;
	int rc = 0;
	kdev_t dev;

	ENTRY; 	

        dev = MINOR(inode->i_rdev);
        if (dev != SNAP_PSDEV_MINOR)
                RETURN(-ENODEV);

        if (!inode) {
                CDEBUG(D_IOCTL, "invalid inode\n");
                RETURN(-EINVAL);
        }

        if ( _IOC_TYPE(cmd) != IOC_SNAP_TYPE || 
             _IOC_NR(cmd) < IOC_SNAP_MIN_NR  || 
             _IOC_NR(cmd) > IOC_SNAP_MAX_NR ) {
                /*FIXME: Sometimes Gettimeof the day will come here
		 * still do not know the reason*/
		CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
                                _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
                RETURN(0);
        }

	/* get data structures */
	rc = copy_from_user(&input, (void *)arg, sizeof(input));
	if (rc) RETURN(rc);

	/* get data from the input data*/
	rc = getdata(&input, &karg);
	if (rc) RETURN(rc);

	switch (cmd) {
	case IOC_SNAP_ADD: {
		rc = snaptable_add_item(karg);
		break;
	}
	case IOC_SNAP_PRINTTABLE: {
		struct ioc_data *output;
		char   *tmp;
		
		SNAP_ALLOC(tmp, BUF_SIZE);
		output=(struct ioc_data*)tmp;
		output->ioc_inbuf = output->ioc_bulk;
		output->ioc_inlen = BUF_SIZE - sizeof(int) - sizeof(unsigned long);
		snap_print_table(karg, output->ioc_inbuf, &(output->ioc_inlen));
		
		rc = copy_to_user((char *)arg, output, 
				  (output->ioc_inlen + sizeof(int) + sizeof(unsigned long)));
		SNAP_FREE(tmp, BUF_SIZE);

		break;
	}
	case IOC_SNAP_GETINDEXFROMNAME: {
		int index = 0;
		char name[SNAP_MAX_NAMELEN];
		int tableno = 0; 
		struct snap_cache *cache;
		kdev_t dev;
		int name_len;

		struct get_index_struct {
			kdev_t dev;
			char name[SNAP_MAX_NAMELEN];
		};

		struct get_index_struct *data = karg;
	
		name_len = input.ioc_inlen - sizeof(kdev_t);	
		dev = data->dev;
		memset(name, 0, SNAP_MAX_NAMELEN);	
		if(name_len > SNAP_MAX_NAMELEN)
			name_len = SNAP_MAX_NAMELEN;
		if(name_len < 0 ) 
			name_len = 0;
		/*for(i=0 ; i< name_len; i++) {
			name[i] = data->name[i];
		}
		*/
		memcpy(name, data->name, name_len);
		printk("dev %d , len %d, name_len %d, find name is [%s]\n", dev, input.ioc_inlen, name_len, name);
		cache = snap_find_cache(dev); 
		if ( !cache ) {
        	        EXIT;
         	       	rc = -EINVAL;
			break;
   		}
		tableno = cache->cache_snap_tableno;

		index = snap_get_index_from_name(tableno, name);
		rc = copy_to_user((char *)arg, &index, sizeof(index));
		break;
	}
	case IOC_SNAP_GET_NEXT_INO: { 
		struct get_ino_struct{
			ino_t found_ino;
			ino_t parent_ino;
		}get_ino;
		get_ino.found_ino = 0;
		get_ino.parent_ino = 0;
		rc = snap_get_next_inode(karg,  &get_ino.found_ino, &get_ino.parent_ino);
		rc = copy_to_user((char *)arg, &get_ino, sizeof(get_ino));
		break;
	}
	case IOC_SNAP_GET_INO_INFO: { 
		struct ioc_ino_info{
			kdev_t dev;
			ino_t ino;
			int index;
		};
		struct snap_cache *cache;
		struct inode *pri;
		struct inode *ind;
		struct ioc_ino_info *data = karg;
		ino_t ind_ino = 0;
	
		cache = snap_find_cache(data->dev); 
		if ( !cache ) {
        	        EXIT;
         	       	rc = -EINVAL;
			break;
   		}
		printk("get_ino_info, dev %d, ino %lu, index %d\n",
			 data->dev, data->ino, data->index);	
		pri = iget(cache->cache_sb, data->ino);
		ind = snap_get_indirect(pri, NULL, data->index);
		if(ind)	{
			ind_ino = ind->i_ino;
			iput(ind);
		}
		iput(pri);
		printk("get_ino_info, get ind %lu\n", ind_ino);
		rc = copy_to_user((char *)arg, &ind_ino, sizeof(ino_t));
		break;
	}
	case IOC_SNAP_DELETE: 
	case IOC_SNAP_RESTORE:
	case IOC_SNAP_DEBUG:
		rc = snap_iterate_func(input.ioc_inlen, karg, cmd);
		break;
#ifdef SNAP_DEBUG
	case IOC_SNAP_DEVFAIL:
		snap_debug_failcode = (unsigned int)arg;
		break;
#endif
	case IOC_SNAP_SHOW_DOTSNAP: {
		struct ioc_show_info{
			kdev_t dev;
			int show;
		};
		struct snap_cache *cache;
		struct ioc_show_info *data = karg;

		cache = snap_find_cache(data->dev);
		if( !cache ) {
			EXIT;
			rc = -EINVAL;
			break;
		}
		cache->cache_show_dotsnap = (char)data->show;
		CDEBUG(D_IOCTL, "Set show dotsnap: %s\n",
			data->show ? "Yes" : "No");
		
		break;
	}
	default:
		rc = -EINVAL;
		break;
	}

	freedata(karg, &input);
	RETURN(rc);
}
