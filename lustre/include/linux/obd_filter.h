#ifndef _OBD_FILTER_H
#define _OBD_FILTER_H
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */


#ifndef OBD_FILTER_DEVICENAME
#define OBD_FILTER_DEVICENAME "obdfilter"
#endif

struct run_ctxt { 
	struct vfsmount *pwdmnt;
	struct dentry   *pwd;
	mm_segment_t     fs;
};

struct filter_obd {
	char *fo_fstype;
        struct super_block * fo_sb;
	struct vfsmount *fo_vfsmnt;
	struct run_ctxt  fo_ctxt;
	__u64 fo_lastino;
	struct file_operations *fo_fop; 
	struct inode_operations *fo_iop;
	struct address_space_operations *fo_aops;
};


extern struct obd_ops filter_obd_ops;

#endif
