/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LINUX_LUSTRE_MDS_H
#define _LINUX_LUSTRE_MDS_H

#ifndef _LUSTRE_MDS_H
#error Do not #include this file directly. #include <lustre_mds.h> instead
#endif

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/dcache.h>
# include <linux/xattr_acl.h>
#endif

struct mds_obd;
struct ptlrpc_request;
struct obd_device;
struct ll_file_data;

/* mds/handler.c */
#ifdef __KERNEL__
struct dentry *mds_fid2locked_dentry(struct obd_device *obd, struct ll_fid *fid,
                                     struct vfsmount **mnt, int lock_mode,
                                     struct lustre_handle *lockh,
                                     __u64 lockpart);
struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid,
                              struct vfsmount **mnt);
int mds_update_server_data(struct obd_device *, int force_sync);

/* mds/mds_fs.c */
int mds_fs_setup(struct obd_device *obddev, struct vfsmount *mnt);
int mds_fs_cleanup(struct obd_device *obddev);
#endif

#endif
