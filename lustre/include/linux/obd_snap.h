#ifndef _OBD_SIM
#define _OBD_SIM

#define OBD_SNAP_MAGIC 0x47224722

#define SNAP_MAX  8 /* must fit in "u" area of struct inode */
struct snap_obd_data {
	int snap_dev;             /* which device contains the data */
	unsigned int snap_no;    /* which snapshot are we accessing */
	unsigned int snap_count; /* how many snapshots exist */
	time_t snap_times[SNAP_MAX];
};

struct snap_obd {
	unsigned int snap_no;    /* which snapshot are we accessing */
	unsigned int snap_count; /* how many snapshots exist */
	time_t snap_times[SNAP_MAX];
};

struct snap_object_data {
	int od_magic;
	/* id of snaps of object; slot 0 has the current data */
	unsigned long od_ids[SNAP_MAX + 1]; 
}



#endif
