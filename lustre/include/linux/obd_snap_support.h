#ifndef __OBD_SNAP_SUPP_H
#define __OBD_SNAP_SUPP_H
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

/* What we use to point to IDs in the obdmd data for snapshots.  If we use
 * obd_id (8 bytes) instead of ino_t (4 bytes), we halve the number of
 * available snapshot slots (14 in 56 bytes vs. 7 in 56 bytes until we
 * increase the size of OBD_OBDMDSZ).
 */
typedef obd_id	snap_id;

/* maximum number of snapshot tables we maintain in the kernel */
#define SNAP_MAX_TABLES 8

/* maximum number of snapshots per device 
   must fit in "o_obdmd" area of struct obdo */
#define SNAP_MAX ((OBD_OBDMDSZ - sizeof(uint32_t))/sizeof(snap_id))

struct snap_md {
	uint32_t m_magic;
	snap_id	 m_ids[SNAP_MAX];	/* id of snaps; slot 0 has current id */
};


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

struct snap_iterdata {
	struct lustre_handle *conn;
	struct lustre_handle *ch_conn;
	int index;
	int previndex;
	int currentindex;
	int prevslot;
	time_t prevtime;
};

inline struct lustre_handle *child_conn(struct lustre_handle *conn);
int snap_deleteobj(obd_id id, obd_gr group, void *data);
int snap_restoreobj(obd_id id, obd_gr group, void *data);
int snap_printobj(obd_id id, obd_gr group, void *data);
int snap_iocontrol(int cmd, struct lustre_handle *conn, int len, void *karg, void *uarg);

/* In the future, this function may have to deal with offsets into the obdmd.
 * Currently, we assume we have the whole obdmd struct.
 */
static __inline__ struct snap_md *snap_obdmd(struct obdo *oa)
{
	return ((struct snap_md *)(&oa->o_obdmd));
}
#endif
