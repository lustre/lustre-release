#ifndef _OBD_RAID1
#define _OBD_RAID1
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#include <linux/obd_class.h>

#define MAX_RAID1 16

#ifndef OBD_RAID1_DEVICENAME
#define OBD_RAID1_DEVICENAME "obdraid1"
#endif

/* development definitions */
extern struct obdfs_sb_info *obd_sbi;
extern struct file_operations *obd_fso;

/* obd_raid1.c */
extern struct obd_ops raid1_obd_ops;
inline long ext2_block_map (struct inode * inode, long block);

#endif
