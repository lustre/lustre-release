/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <info@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 *
 */

#ifndef _LUSTRE_MDS_H
#define _LUSTRE_MDS_H

#ifdef __KERNEL__

#include <linux/fs.h>
#include <linux/lustre_idl.h>

struct ldlm_lock_desc;
struct mds_obd;
struct ptlrpc_connection;
struct ptlrpc_client;
struct obd_export;
struct ptlrpc_request;
struct obd_device;

#define LUSTRE_MDS_NAME "mds"
#define LUSTRE_MDT_NAME "mdt"
#define LUSTRE_MDC_NAME "mdc"

struct mds_update_record {
        __u32 ur_fsuid;
        __u32 ur_fsgid;
        __u32 ur_cap;
        __u32 ur_opcode;
        struct ll_fid *ur_fid1;
        struct ll_fid *ur_fid2;
        int ur_namelen;
        char *ur_name;
        int ur_tgtlen;
        char *ur_tgt;
        struct iattr ur_iattr;
        __u64 ur_rdev;
        __u32 ur_mode;
        __u32 ur_uid;
        __u32 ur_gid;
        __u64 ur_time;
};

#define MDS_LR_CLIENT  8192
#define MDS_LR_SIZE     128

#define MDS_CLIENT_SLOTS 17

#define MDS_MOUNT_RECOV 2

/* Data stored per server at the head of the last_rcvd file.  In le32 order. */
struct mds_server_data {
        __u8 msd_uuid[37];      /* server UUID */
        __u8 uuid_padding[3];   /* unused */
        __u64 msd_last_rcvd;    /* last completed transaction ID */
        __u64 msd_mount_count;  /* MDS incarnation number */
        __u8 padding[512 - 56];
};

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct mds_client_data {
        __u8 mcd_uuid[37];      /* client UUID */
        __u8 uuid_padding[3];   /* unused */
        __u64 mcd_last_rcvd;    /* last completed transaction ID */
        __u64 mcd_mount_count;  /* MDS incarnation number */
        __u64 mcd_last_xid;     /* client RPC xid for the last transaction */
        __u8 padding[MDS_LR_SIZE - 64];
};

/* In-memory access to client data from MDS struct */
struct mds_export_data {
        struct list_head        med_open_head;
        spinlock_t              med_open_lock;
        struct mds_client_data *med_mcd;
        int                     med_off;
};

/* file data for open files on MDS */
struct mds_file_data {
        struct list_head     mfd_list;
        struct lustre_handle mfd_clienthandle;
        __u64                mfd_servercookie;
        struct file         *mfd_file;
};

/* mds/mds_reint.c  */
int mds_reint_rec(struct mds_update_record *r, int offset,
                  struct ptlrpc_request *req);

/* lib/mds_updates.c */
void mds_unpack_body(struct mds_body *b);
void mds_unpack_fid(struct ll_fid *fid);
void mds_pack_fid(struct ll_fid *fid);
void mds_pack_req_body(struct ptlrpc_request *);
void mds_pack_rep_body(struct ptlrpc_request *);
int mds_update_unpack(struct ptlrpc_request *, int offset,
                      struct mds_update_record *);

void mds_readdir_pack(struct ptlrpc_request *req, int offset,
                      obd_id ino, int type);
void mds_getattr_pack(struct ptlrpc_request *req, int offset,
                      struct inode *inode, const char *name, int namelen);
void mds_setattr_pack(struct ptlrpc_request *, int offset, struct inode *,
                      struct iattr *, const char *name, int namelen);
void mds_create_pack(struct ptlrpc_request *, int offset, struct inode *dir,
                     __u32 mode, __u64 rdev, __u32 uid, __u32 gid, __u64 time,
                     const char *name, int namelen, const void *data,
                     int datalen);
void mds_unlink_pack(struct ptlrpc_request *, int offset, struct inode *inode,
                     struct inode *child, __u32 mode, const char *name,
                     int namelen);
void mds_link_pack(struct ptlrpc_request *, int offset, struct inode *ino,
                   struct inode *dir, const char *name, int namelen);
void mds_rename_pack(struct ptlrpc_request *, int offset, struct inode *srcdir,
                     struct inode *tgtdir, const char *name, int namelen,
                     const char *tgt, int tgtlen);
void mds_pack_inode2fid(struct ll_fid *fid, struct inode *inode);
void mds_pack_inode2body(struct mds_body *body, struct inode *inode);

/* mds/handler.c */
struct dentry *mds_name2locked_dentry(struct obd_device *, struct dentry *dir,
                                      struct vfsmount **mnt, char *name,
                                      int namelen, int lock_mode,
                                      struct lustre_handle *lockh,
                                      int dir_lock_mode);
struct dentry *mds_fid2locked_dentry(struct obd_device *obd, struct ll_fid *fid,
                                     struct vfsmount **mnt, int lock_mode,
                                     struct lustre_handle *lockh);
struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid,
                              struct vfsmount **mnt);
int mds_reint(struct ptlrpc_request *req, int offset);
int mds_pack_md(struct mds_obd *mds, struct ptlrpc_request *req,
                int offset, struct mds_body *body, struct inode *inode);

/* mdc/mdc_request.c */
int mdc_enqueue(struct lustre_handle *conn, int lock_type,
                struct lookup_intent *it, int lock_mode, struct inode *dir,
                struct dentry *de, struct lustre_handle *lockh, char *tgt,
                int tgtlen, void *data, int datalen);
int mdc_cancel_unused(struct lustre_handle *conn, struct inode *, int flags);
int mdc_getlovinfo(struct obd_device *obd, struct lustre_handle *mdc_connh,
                   struct ptlrpc_request **request);
int mdc_getstatus(struct lustre_handle *conn, struct ll_fid *rootfid);
int mdc_getattr(struct lustre_handle *conn,
                obd_id ino, int type, unsigned long valid, size_t ea_size,
                struct ptlrpc_request **request);
int mdc_setattr(struct lustre_handle *conn,
                struct inode *, struct iattr *iattr, struct ptlrpc_request **);
int mdc_open(struct lustre_handle *conn, obd_id ino, int type, int flags,
             struct lov_mds_md *lmm, int lmm_size, struct lustre_handle *fh,
             struct ptlrpc_request **);
int mdc_close(struct lustre_handle *conn, obd_id ino, int type,
              struct lustre_handle *fh,  struct ptlrpc_request **req);
int mdc_readpage(struct lustre_handle *conn, obd_id ino,
                 int type, __u64 offset, char *addr, struct ptlrpc_request **);
int mdc_create(struct lustre_handle *conn,
               struct inode *dir, const char *name, int namelen,
               const void *data, int datalen, int mode, __u32 uid, __u32 gid,
               __u64 time, __u64 rdev, struct ptlrpc_request **);
int mdc_unlink(struct lustre_handle *, struct inode *dir, struct inode *child,
               __u32 mode, const char *name, int namelen,
               struct ptlrpc_request **);
int mdc_link(struct lustre_handle *conn,
             struct dentry *src, struct inode *dir, const char *name,
             int namelen, struct ptlrpc_request **);
int mdc_rename(struct lustre_handle *conn,
               struct inode *src, struct inode *tgt, const char *old,
               int oldlen, const char *new, int newlen,
               struct ptlrpc_request **);
int mdc_create_client(obd_uuid_t uuid, struct ptlrpc_client *cl);

/* Store the generation of a newly-created inode in |req| for replay. */
void mdc_store_inode_generation(struct ptlrpc_request *req, int reqoff,
                                int repoff);

int mds_client_add(struct mds_obd *mds, struct mds_export_data *med,
                   int cl_off);
int mds_client_free(struct obd_export *exp);

/* mds/mds_fs.c */
struct mds_fs_operations {
        struct module *fs_owner;
        void   *(* fs_start)(struct inode *inode, int op);
        int     (* fs_commit)(struct inode *inode, void *handle);
        int     (* fs_setattr)(struct dentry *dentry, void *handle,
                               struct iattr *iattr);
        int     (* fs_set_md)(struct inode *inode, void *handle,
                              struct lov_mds_md *md, int size);
        int     (* fs_get_md)(struct inode *inode, struct lov_mds_md *md,
                              int size);
        ssize_t (* fs_readpage)(struct file *file, char *buf, size_t count,
                                loff_t *offset);
        void    (* fs_delete_inode)(struct inode *inode);
        void    (* cl_delete_inode)(struct inode *inode);
        int     (* fs_journal_data)(struct file *file);
        int     (* fs_set_last_rcvd)(struct mds_obd *mds, void *handle);
        int     (* fs_statfs)(struct super_block *sb, struct statfs *sfs);
};

extern int mds_register_fs_type(struct mds_fs_operations *op, const char *name);
extern void mds_unregister_fs_type(const char *name);
extern int mds_fs_setup(struct obd_device *obddev, struct vfsmount *mnt);
extern void mds_fs_cleanup(struct obd_device *obddev);

#define MDS_FSOP_UNLINK         1
#define MDS_FSOP_RMDIR          2
#define MDS_FSOP_RENAME         3
#define MDS_FSOP_CREATE         4
#define MDS_FSOP_MKDIR          5
#define MDS_FSOP_SYMLINK        6
#define MDS_FSOP_MKNOD          7
#define MDS_FSOP_SETATTR        8
#define MDS_FSOP_LINK           9

#endif /* __KERNEL__ */

/* ioctls for trying requests */
#define IOC_REQUEST_TYPE                   'f'
#define IOC_REQUEST_MIN_NR                 30

#define IOC_REQUEST_GETATTR             _IOWR('f', 30, long)
#define IOC_REQUEST_READPAGE            _IOWR('f', 31, long)
#define IOC_REQUEST_SETATTR             _IOWR('f', 32, long)
#define IOC_REQUEST_CREATE              _IOWR('f', 33, long)
#define IOC_REQUEST_OPEN                _IOWR('f', 34, long)
#define IOC_REQUEST_CLOSE               _IOWR('f', 35, long)
#define IOC_REQUEST_MAX_NR               35

#endif
