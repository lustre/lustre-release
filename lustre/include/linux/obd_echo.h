#ifndef _OBD_ECHO_H
#define _OBD_ECHO_H
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */


#ifndef OBD_ECHO_DEVICENAME
#define OBD_ECHO_DEVICENAME "obdecho"
#endif

struct echo_obd {
	char *eo_fstype;
        struct super_block *eo_sb;
	struct vfsmount *eo_vfsmnt;
	struct run_ctxt  eo_ctxt;
	spinlock_t eo_lock;
	__u64 eo_lastino;
	struct file_operations *eo_fop; 
	struct inode_operations *eo_iop;
	struct address_space_operations *eo_aops;
};


extern struct obd_ops echo_obd_ops;

#endif

