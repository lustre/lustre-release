#ifndef _OBD_SNAP
#define _OBD_SNAP

#define OBD_SNAP_MAGIC 0x47224722

#define SNAP_MAX  8 /* must fit in "u" area of struct inode */

/* if time is 0 this designates the "current" snapshot, i.e.
   the head of the tree 
*/

struct snap {
	time_t time;
	int index;
};

/* snap ioctl data for attach */
struct snap_obd_data {
	int snap_dev;             /* which device contains the data */
	unsigned int snap_no;     /* which snapshot are we accessing */
	unsigned int snap_count;  /* how many snapshots exist */
	struct snap snap_snaps[SNAP_MAX]; /* times must be incr or attach will fail */
};


/* this is the obd device descriptor */
struct snap_obd {
	unsigned int snap_no;    /* which snapshot index are we accessing */
	unsigned int snap_current;
	unsigned int snap_count; /* how many snapshots exist */
	time_t snap_times[SNAP_MAX];
	int snap_index[SNAP_MAX];
};


/* stored as inline data in the objects */
struct snap_object_data {
	int od_magic;
	/* id of snaps of object; slot 0 has the current data */
	unsigned long od_ids[SNAP_MAX + 1]; 
};



#endif
