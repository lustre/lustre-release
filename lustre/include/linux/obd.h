#ifndef __OBD_H
#define __OBD_H


struct obd_conn_info {
	unsigned int conn_id;     /* handle */
};

struct obd_type {
	struct list_head typ_chain;
	struct obd_ops *typ_ops;
	char *typ_name;
	int  typ_refcnt;
};




#endif
