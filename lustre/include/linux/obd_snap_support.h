#ifndef __OBD_SNAP_SUPP_H
#define __OBD_SNAP_SUPP_H

struct snap_iterdata {
	struct obd_conn *conn;
	struct obd_conn *ch_conn;
	int index;
	int previndex;
	int currentindex;
	int prevslot;
	time_t prevtime;
};


inline struct obd_conn *child_conn(struct obd_conn *conn);
int snap_deleteino(objid id, void *data);
int snap_restoreino(objid id, void *data);
int snap_iocontrol(int cmd, struct obd_conn *conn, int len, void *karg, void *uarg);

#endif
