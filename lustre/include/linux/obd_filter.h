#ifndef _OBD_FILTER_H
#define _OBD_FILTER_H
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#include <linux/obd_class.h>

#ifndef OBD_FILTER_DEVICENAME
#define OBD_FILTER_DEVICENAME "obdfilter"
#endif

extern struct obd_ops filter_obd_ops;

#endif
