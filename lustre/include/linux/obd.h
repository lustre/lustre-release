#ifndef __OBD_H
#define __OBD_H
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

struct obd_conn_info {
        unsigned int conn_id;     /* handle */
};

struct obd_type {
        struct list_head typ_chain;
        struct obd_ops *typ_ops;
        char *typ_name;
        int  typ_refcnt;
};

#define OBD_MAGIC       0xffff0000
#define OBD_MAGIC_MASK  0xffff0000



#endif
