
/*
 *  snaptable.c
 *
 *  Manipulate snapshot tables
 *
 */

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/malloc.h>
#include <linux/locks.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <linux/sysrq.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/quotaops.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/bitops.h>
#include <asm/mmu_context.h>

#include <linux/filter.h>
#include <linux/snapsupport.h>
#include <linux/snapfs.h>

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

	for ( slot=0 ; slot<snap_table->tbl_count ; slot++ )
		if ( snap_table->tbl_index[slot] == snap_index )
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
		printk(__FUNCTION__ ": invalid table no %d\n", tableno);
		snap->index = -1;
	}
	table = &snap_tables[tableno];

	/* start at the highest index in the superblock 
	   snaptime array */ 
	i = table->tbl_count - 1;

	/* NOTE: i>0 is an unnecessary check */
	while ( table->tbl_times[i] > now && i > 0) {
		CDEBUG(D_SNAP, "time: %ld, i: %d\n", table->tbl_times[i], i);
		i--;
	}

	snap->index = table->tbl_index[i];
	snap->time = table->tbl_times[i];
	CDEBUG(D_SNAP, "index: %d, time[i]: %ld, now: %ld\n",
	       snap->index, snap->time, now);
	EXIT;
	return;
}

/* return -1 if no COW is needed, otherwise the index of the 
   clone to COW to is returned
*/

int snap_needs_cow(struct inode *inode)
{
	struct snap snap;
	struct snap_cache *cache;
	int index = -1;
	ENTRY;

	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) {
		EXIT;
		return -1;
	}

	/* here we find the time of the last snap to compare with */
	snap_last(cache, &snap);

	/* decision .... if the snapshot is more recent than the object,
	 * then any change to the object should cause a COW.
	 */
	if (inode->i_mtime <= snap.time && inode->i_ctime <= snap.time) {
		index = snap.index;
	}
	printk("snap_needs_cow, ino %lu , get index %d\n",inode->i_ino, index);

	EXIT;
	return index;
} /* snap_needs_cow */

#if 0
int  snap_obd2snap(struct snap_clone_info *info, struct snap *snap)
{
	struct snap_table *table;
	int tableno = info->clone_cache->cache_snap_tableno;
	int index =  info->clone_index;
	int slot;

	ENTRY;
	if ( tableno < 0 || tableno > SNAP_MAX_TABLES ) {
		printk(__FUNCTION__ ": invalid table no %d\n", tableno);
		snap->index = -1;
	}
	table = &snap_tables[tableno];
	slot = snap_index2slot(table, index);

	snap->index = index;
	snap->time = table->tbl_times[slot];
	EXIT;
	return slot;
}
#endif

/* at what index is the current snapshot located */
int snap_current(struct snap_cache *cache)
{
	int tableno = cache->cache_snap_tableno;

	return snap_tables[tableno].tbl_index[0];
}

int snap_is_used(int table_no, int snap_index) 

{
	/* ENTRY; */
	if ( snap_index < 0 || snap_index >= SNAP_MAX ) {
		printk(__FUNCTION__ ": invalid snapno %d,table %d\n",
		       snap_index, table_no);
		EXIT;
		return -1;
	}
	if ( table_no < 0 || table_no > SNAP_MAX_TABLES ) {
		printk(__FUNCTION__ ": invalid snapno %d,table %d\n",
		       snap_index, table_no);
		EXIT;
		return -1;
	}

	/* EXIT; */
	return snap_tables[table_no].tbl_used & (1<<snap_index);
}

void snap_use(int table_no, int snap_index) 
{
	if ( snap_index < 0 || snap_index >= SNAP_MAX ) {
		printk(__FUNCTION__ ": invalid snapno %d,table %d\n",
		       snap_index, table_no);
		return;
	}
	if ( table_no < 0 || table_no > SNAP_MAX_TABLES ) {
		printk(__FUNCTION__ ": invalid snapno %d,table %d\n",
		       snap_index, table_no);
		return;
	}
	if ( snap_index2slot(&snap_tables[table_no], snap_index) < 0 ) 
		return;

	snap_tables[table_no].tbl_used |=  (1<<snap_index);
}

void snap_unuse(int table_no, int snap_index) 
{
	if ( snap_index < 0 || snap_index >= SNAP_MAX ) {
		printk(__FUNCTION__ ": invalid snapno %d,table %d\n",
		       snap_index, table_no);
		return;
	}
	if ( table_no < 0 || table_no > SNAP_MAX_TABLES ) {
		printk(__FUNCTION__ ": invalid snapno %d,table %d\n",
		       snap_index, table_no);
		return;
	}
	if ( snap_index2slot(&snap_tables[table_no], snap_index) < 0 ) 
		return;

	snap_tables[table_no].tbl_used &=  ~(1<<snap_index);
}

static int nprint_buf(char *buf, int buflen, char *fmt, ...)
{
        va_list args;
        int n;
	char local_buf[1024];

        va_start(args, fmt);
        n = vsprintf(local_buf, fmt, args);
        va_end(args);
	
	if( n > buflen ) {
		if( buflen > 1024)	buflen=1024;
		memcpy(buf, local_buf, buflen);
		return buflen;
	}
	else {
		memcpy(buf, local_buf, n);
		return n;
	}
}
	
int snap_print_table(struct snap_table_data *data, char *buf, int *buflen)
{
	int tableno = data->tblcmd_no;
	int i;
	struct snap_table *table;
	char *buf_ptr;
	int nleft = (*buflen);
	int nprint = 0;

	if ( tableno < 0 || tableno > SNAP_MAX_TABLES ) {
		printk(__FUNCTION__ ": invalid table number %d\n", tableno);
		EXIT;
		return -EINVAL;
	}

	table = &snap_tables[tableno];

	printk("------- snap table %d\n", tableno);
	printk("     -- snap count %d\n", table->tbl_count);
	printk("     -- snap used  0x%x\n", table->tbl_used);
	for ( i = 0 ; i < SNAP_MAX ; i++ ) {
		printk("     -- slot %d, idx %d, time %ld, name %s\n",
		       i, table->tbl_index[i], table->tbl_times[i], 
			table->tbl_name[i]);
	}

	buf_ptr = buf;
	nprint= nprint_buf(buf_ptr, nleft, "------- snap table %d\n", tableno);
	nleft -= nprint;
	if( nleft > 0 )  buf_ptr += nprint;
	else goto exit; 
	nprint = nprint_buf(buf_ptr, nleft, "     -- snap count %d\n", table->tbl_count);
	nleft -= nprint;
	if( nleft > 0 )  buf_ptr += nprint;
	else goto exit;
	nprint = nprint_buf(buf_ptr, nleft, "     -- snap used  0x%x\n", table->tbl_used);
	nleft -= nprint;
	if( nleft > 0 )  buf_ptr += nprint;
	else goto exit;
	for ( i = 0 ; i < SNAP_MAX ; i++ ) {
		nprint = nprint_buf( buf_ptr, nleft,
			"     -- slot %d, idx %d, time %ld, name %s\n",
		       i, table->tbl_index[i], table->tbl_times[i], 
			table->tbl_name[i]);
		nleft -= nprint;
		if( nleft > 0 )  buf_ptr += nprint;
		else goto exit;
	}

exit:
	if(nleft > 0) (*buflen) = (*buflen) - nleft;

	return 0;
}

int snap_install_table(int len, struct snap_table_data *data)
{
	int i, j;
	int tableno = data->tblcmd_no;
//	int found_current;
	struct snap_table *table;

	if ( tableno < 0 || tableno > SNAP_MAX_TABLES ) {
		printk(__FUNCTION__ ": invalid table number %d\n", tableno);
		EXIT;
		return -EINVAL;
	}
	table = &snap_tables[tableno];	

	/* for each index that is used by the current table
	   we need to make sure that the new table we are about
	   to put in contains that index too 
	*/
	for ( i = 0; i < SNAP_MAX ; i++ ) {
		int foundit;
		int err;

		if ((err = snap_is_used(tableno, i)) < 0 ) {
			printk(__FUNCTION__  ": table %d not used\n", tableno);
			EXIT;
			return -EINVAL;
		} else if (err == 0) {
			continue;
		}

		foundit = 0;
		for (j = 0 ; j<= data->tblcmd_count ; j++) {
			if ( i == data->tblcmd_snaps[j].index ) {
				foundit = 1;
				break;
			}
		}
		if ( !foundit ) {
			printk(__FUNCTION__ ": index %d not in table %d\n", 
			       i, tableno);
			return -EINVAL;
		}
	}

	/* we must have:
           - valid indices 
	   - a current snapshot in the table 
	   - increasing snapshot times 
	*/
//	found_current = 0;
	CDEBUG(D_SNAP, "snaplist: tblcmd_count %d\n", data->tblcmd_count);
	for (i = 0 ; i < data->tblcmd_count ; i++) {

		if ( (data->tblcmd_snaps[i].index < 0) ||
		     (data->tblcmd_snaps[i].index >= SNAP_MAX) ) {
			printk(__FUNCTION__ ": snap_index out of range!\n");
			return -EINVAL;
		}

		if (i>0 && data->tblcmd_snaps[i].time <= 
		    data->tblcmd_snaps[i-1].time) {
			printk(__FUNCTION__ ": times not increasing\n");
			return -EINVAL;
		}

//		if ( 0 == data->tblcmd_snaps[i].time ) {
//			found_current = 1;
//			break;
//		}
	}
//	if ( !found_current ) {
//		printk(__FUNCTION__ "no current snapshot in table\n");
//		return -EINVAL;
//	}

	/* ready to go: over write the table */
/*	
	for (i = 0 ; i < data->tblcmd_count ; i++) {

		table->tbl_times[i] = data->tblcmd_snaps[i].time;
		table->tbl_index[i] = data->tblcmd_snaps[i].index;
		memcpy(table->tbl_name[i], data->tblcmd_snaps[i].name, 
			SNAP_MAX_NAMELEN);
		table->tbl_name[i][SNAP_MAX_NAMELEN - 1] = '\0';

		CDEBUG(D_SNAP, "snaplist: i %d, time %ld, idx %d, name %s\n",
		       i, table->tbl_times[i], table->tbl_index[i], 
			table->tbl_name[i]);
	}
*/
	/* below : new, we don't need current snapshot for data
	 * current snapshot always has slot 0, index 0, name "current" 
	 */
	table->tbl_times[0] = 0;
	table->tbl_index[0] = 0;
	strcpy(table->tbl_name[0], "current");

	i=0;	
	CDEBUG(D_SNAP, "snaplist: i %d, time %ld, idx %d, name %s\n",
	       i, table->tbl_times[i], table->tbl_index[i], 
		table->tbl_name[i]);

	for (i = 0 ; i < data->tblcmd_count ; i++) {

		table->tbl_times[i+1] = data->tblcmd_snaps[i].time;
		table->tbl_index[i+1] = data->tblcmd_snaps[i].index;
		memcpy(table->tbl_name[i+1], data->tblcmd_snaps[i].name, 
			SNAP_MAX_NAMELEN);
		table->tbl_name[i+1][SNAP_MAX_NAMELEN - 1] = '\0';

		CDEBUG(D_SNAP, "snaplist: i %d, time %ld, idx %d, name %s\n",
		       i+1, table->tbl_times[i+1], table->tbl_index[i+1], 
			table->tbl_name[i+1]);
	}

	for ( i = data->tblcmd_count + 1 ; i < SNAP_MAX ; i++ ) {
		table->tbl_times[i] = 0;
		table->tbl_index[i] = 0;
		memset(table->tbl_name[i], 0, SNAP_MAX_NAMELEN);
	}

	/* set the table count */
//	table->tbl_count = data->tblcmd_count;
	table->tbl_count = data->tblcmd_count + 1;
	return 0;
}


int snap_table_attach(int tableno, int snap_index) 
{
	struct snap_table *table;

	if ( tableno < 0 || tableno > SNAP_MAX_TABLES ) {
		printk(__FUNCTION__ ": invalid table number %d\n", tableno);
		EXIT;
		return -EINVAL;
	}
	table = &snap_tables[tableno];	
	
	if ( snap_index2slot(table, snap_index) < 0 ) {
		printk(__FUNCTION__ ": snap index %d not present in table %d\n",
		       snap_index, tableno);
		return -EINVAL;
	}

	snap_use(tableno, snap_index);
	return 0;
}

static int getdata(int len, void **data)
{
	void *tmp = NULL;

	if (!len) {
		*data = NULL;
		return 0;
	}

	SNAP_ALLOC(tmp, void *, len);
	if ( !tmp )
		return -ENOMEM;

	CDEBUG(D_MALLOC, "snap_alloc:len %d, add %p\n", len, tmp);

	memset(tmp, 0, len);
	if ( copy_from_user(tmp, *data, len)) {
		SNAP_FREE(tmp, len);
		CDEBUG(D_MALLOC, "snap_free:len %d, add %p\n", len, tmp);
		return -EFAULT;
	}
	*data = tmp;

	return 0;
}

static void freedata(void *data, int len) {
	SNAP_FREE(data, len);
	CDEBUG(D_MALLOC, "snap_free:len %d, add %p\n", len, data);
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
		printk("No dentry for ino %lu, Error(XXX)! \n", inode->i_ino);
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
/*
static int snap_get_inode_info(struct snap_ino_list_data *data,  int index)
{
	kdev_t dev = data->dev;
	ino_t pri = data->ino; 
	int index = data->index;

	struct snap_cache *cache;

	struct inode *pri;
	struct inode *ind;
	ino_t ind_ino = 0;

	ENTRY;

	cache = snap_find_cache(dev); 
	if ( !cache ) {
                EXIT;
                return -EINVAL;
        }
	pri = iget(cache->cache->sb, pri_ino);
	ind = snap_get_indirect(pri, NULL, index);
	if(ind)	{
		ind_ino = ind->i_ino;	
		iput(ind);
	}
	return ind_ino;
}
*/

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

	printk("delete_inode ino %lu, index %d\n", primary->i_ino, index);

	table = &snap_tables[tableno];

	redirect = snap_get_indirect(primary, NULL, index);

	if(!redirect)	
		return 0;

	old_ind = redirect->i_ino;
	iput(redirect);
	slot = snap_index2slot(table, index) - 1;
	if( slot > 0 ) {
		this_index = table->tbl_index[slot];
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
		my_table[slot - delete_slot] = table->tbl_index[slot];
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
		printk("ERROR:snap_destroy_indirect(ino %lu,index %d),ret %d\n", 			primary->i_ino, index, rc);
	return 0;
}

static int snap_delete(struct super_block *sb, struct snap_iterdata *data)
//static int snap_delete(struct super_block *sb, void *data)
{
	CDEBUG(D_SNAP, "dev %d, tableno %d, index %d, time %lu\n",
		data->dev, data->tableno, data->index, data->time );

	snap_iterate(sb,&delete_inode,NULL, data, SNAP_ITERATE_COWED_INODE);
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
//			d_invalidate( list_entry(pos, struct dentry, d_alias) );
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
//	int my_table[SNAP_MAX];
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
	if( pri->i_mtime > restore_time || pri->i_ctime > restore_time )
	{
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
					table->tbl_index[slot]);
				if(ind)	{
					restore_index = table->tbl_index[slot];
					break;
				}
			}
/*			for(slot = table->tbl_count; slot >= restore_slot; 
				slot --)
			{
				my_table[slot - restore_slot + 1] = 
					table->tbl_index[slot];
			}
			ind = snap_get_indirect (pri, my_table, 
					table->tbl_count - restore_slot + 1);

			if( ind && (ind->i_ino == pri->i_ino) )	{
				iput(ind);
				ind =  NULL;
			}
*/
		}

		if(ind) {
			CDEBUG(D_SNAP, "restore ino %lu with index %d\n",
					pri->i_ino, restore_index);
			iput(ind);
//			snap_restore_indirect(pri, index);
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
		printk("ino %lu is older, don't restore\n",pri->i_ino);
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
		printk(__FUNCTION__ ": invalid table number %d\n", tableno);
		return -EINVAL;
	}

	table = &snap_tables[tableno];

	for ( slot = 0 ; slot < SNAP_MAX ; slot++ ) {
/*		if(memcmp (table->tbl_name[slot], name, 
			strlen(table->tbl_name[slot]) ) == 0 ) {
			return table->tbl_index[slot];
		}
*/
		if(strncmp (table->tbl_name[slot], name, 
			SNAP_MAX_NAMELEN) == 0 ) {
			return table->tbl_index[slot];
		}
	}
	return -EINVAL;
}

int snap_iterate_func(int len, struct snap_ioc_data *ioc_data, unsigned int cmd)
{
	struct snap_iterdata data;

	kdev_t dev ;
	char name[SNAP_MAX_NAMELEN];

	int index ;
	int tableno; 
	int name_len;
	int slot;

	struct super_block *sb;
	struct snap_cache *cache;
	struct snap_table *table;

	ENTRY;

	dev = ioc_data->dev;
	cache = snap_find_cache(dev); 
	if ( !cache ) {
                EXIT;
                return -EINVAL;
        }

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
	if ( (index = snap_get_index_from_name (tableno, name)) < 0 ) {
		EXIT;
		return -EINVAL;
	}
	
	data.dev = dev;
	data.index = index;
	data.tableno = tableno;
	slot = snap_index2slot (table, index);
	if( slot < 0 ) {
		EXIT;
		return -EINVAL;
	}
	data.time = table->tbl_times[slot];

	CDEBUG(D_SNAP, "dev %d, tableno %d, index %d, time %lu\n",
		data.dev, data.tableno, data.index, data.time );

	switch (cmd) {
		case IOC_SNAP_DEBUG:
			snap_print(sb, &data);	
			break;
		case IOC_SNAP_DELETE:
			snap_delete(sb, &data);	
			break;
		case IOC_SNAP_RESTORE:
			snap_restore(sb, &data);	
			break;
		default:
			return -EINVAL;
	}
	
	EXIT;

	return 0;
}

int snap_ioctl (struct inode * inode, struct file * filp, 
                            unsigned int cmd, unsigned long arg)
{
	void *uarg, *karg;
	int len;
	int err;
	kdev_t dev;
	struct  {
		int len;
		char *data;
	}input;
	int rc = 0;

	ENTRY; 	

        dev = MINOR(inode->i_rdev);
        if (dev != SNAP_PSDEV_MINOR)
                return -ENODEV;

        if (!inode) {
                CDEBUG(D_IOCTL, "invalid inode\n");
                return -EINVAL;
        }

        if ( _IOC_TYPE(cmd) != IOC_SNAP_TYPE || 
             _IOC_NR(cmd) < IOC_SNAP_MIN_NR  || 
             _IOC_NR(cmd) > IOC_SNAP_MAX_NR ) {
                CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
                                _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
                EXIT;
                return -EINVAL;
        }

	/* get data structures */
	err = copy_from_user(&input, (void *)arg, sizeof(input));
	if ( err ) {
		EXIT;
		return err;
	}
	uarg = input.data;
	len = input.len;

	karg = input.data;
	err = getdata(input.len, &karg);
	if ( err ) {
		EXIT;
		return err;
	}
	
	switch (cmd) {
	case IOC_SNAP_SETTABLE:
		rc = snap_install_table(len, karg);
		break;
	case IOC_SNAP_PRINTTABLE: {
		struct output_data{
			int len;
			char buf[1024];
		}output;
		output.len = sizeof(output.buf);
		snap_print_table(karg, output.buf, &(output.len));
		rc = copy_to_user((char *)arg, &output, output.len+sizeof(int));
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
	
		name_len = len - sizeof(kdev_t);	
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
		printk("dev %d , len %d, name_len %d, find name is [%s]\n", dev, len, name_len, name);
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
		rc = snap_iterate_func(len, karg, cmd);
		break;
	case IOC_SNAP_DEVFAIL:
		snap_debug_failcode = (unsigned int)arg;
		break;
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

	freedata(karg, input.len);
	EXIT;
	return rc;
}
