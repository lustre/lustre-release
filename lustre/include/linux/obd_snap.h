#ifndef _OBD_SNAP
#define _OBD_SNAP

#define OBD_SNAP_MAGIC 0xfffffff3   /* an unlikely block number */

#ifndef OBD_SNAP_DEVICENAME
#define OBD_SNAP_DEVICENAME "obdsnap"
#endif

/* ioctls for manipulating snapshots 40 - 60 */
#define OBD_SNAP_SETTABLE	_IOWR('f', 40, long)
#define OBD_SNAP_PRINTTABLE	_IOWR('f', 41, long)
#define OBD_SNAP_DELETE	_IOWR('f', 42, long)
#define OBD_SNAP_RESTORE	_IOWR('f', 43, long)

/* this is the obd device descriptor: 
 * - current snapshot ends up in first slot of this array
 */
struct snap_obd {
	unsigned int snap_index;  /* which snapshot index are we accessing */
	int snap_tableno;
};

void snap_use(int table_no, int snap_index) ;
void snap_unuse(int table_no, int snap_index) ;
int snap_is_used(int table_no, int snap_index) ;
int snap_table_attach(int tableno, int snap_index);

#endif
