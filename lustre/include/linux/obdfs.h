/* object based disk file system
 * 
 * This software is licensed under the GPL.  See the file COPYING in the
 * top directory of this distribution for details.
 * 
 * Copyright (C), 1999, Stelias Computing Inc
 *
 *
 */


#ifndef _OBDFS_H
#define OBDFS_H
#include <../obd/linux/sim_obd.h>


struct obdfs_sb_info {
	struct obd_conn_info osi_conn_info;
	struct super_block *osi_super;
	int osi_obd_minor;
};



void obdfs_sysctl_init(void);
void obdfs_sysctl_clean(void);

struct obdfs_inode_info;

#define OBDFS_SUPER_MAGIC 0x4711

#endif

