#ifndef _OBD_SNAP
#define _OBD_SNAP

#define OBD_SNAP_MAGIC 0xfffffff3   /* an unlikely block number */

/* maximum number of snapshot tables we maintain in the kernel */
#define SNAP_MAX_TABLES 8


/* maximum number of snapshots per device 
   must fit in "u" area of struct inode */
#define SNAP_MAX  (EXT2_N_BLOCKS-1)


/* ioctls for manipulating snapshots 40 - 60 */
#define OBD_SNAP_SETTABLE	_IOWR('f', 40, long)
#define OBD_SNAP_PRINTTABLE	_IOWR('f', 41, long)
#define OBD_SNAP_DELETE	_IOWR('f', 42, long)
#define OBD_SNAP_RESTORE	_IOWR('f', 43, long)



/* if time is 0 this designates the "current" snapshot, i.e.
   the head of the tree 
*/
struct snap {
	time_t time;
	int index;
};

/* snap ioctl data for attach: current always in first slot of this array */
struct snap_obd_data {
	int 	     snap_dev;	/* which device contains the data */
	unsigned int snap_index;/* which snapshot is ours */
	unsigned int snap_table;/* which table do we use */
};


/* snap ioctl data for table fiddling */
struct snap_table_data {
	int 		tblcmd_no;	/* which table */
	unsigned int 	tblcmd_count;	/* how many snaps */
	struct snap 	tblcmd_snaps[SNAP_MAX];	/* sorted times! */
};


struct snap_table {
	spinlock_t          tbl_lock;
	unsigned int tbl_count; /* how many snapshots exist in this table*/
	int tbl_used;  /* bitmap of snaps in use by a device */
	time_t tbl_times[SNAP_MAX];
	int tbl_index[SNAP_MAX];
};


/* this is the obd device descriptor: 
   - current snapshot ends up in first slot of this array
 */
struct snap_obd {
	unsigned int snap_index;  /* which snapshot index are we accessing */
	int snap_tableno;
};


/* stored as inline data in the objects */
struct snap_object_data {
	int od_magic;
	/* id of snaps of object; slot 0 has the current data */
	unsigned long od_ids[SNAP_MAX];
};

void snap_use(int table_no, int snap_index) ;
void snap_unuse(int table_no, int snap_index) ;
int snap_is_used(int table_no, int snap_index) ;
int snap_table_attach(int tableno, int snap_index);

#endif
