/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc. <info@clusterfs.com>
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
# include <linux/fs.h>
# include <linux/dcache.h>
#endif
#include <linux/lustre_handles.h>
#include <linux/kp30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_dlm.h>

struct ldlm_lock_desc;
struct mds_obd;
struct ptlrpc_connection;
struct ptlrpc_client;
struct obd_export;
struct ptlrpc_request;
struct obd_device;
struct ll_file_data;

#define LUSTRE_MDS_NAME "mds"
#define LUSTRE_MDT_NAME "mdt"
#define LUSTRE_MDC_NAME "mdc"

struct mdc_rpc_lock {
        struct semaphore rpcl_sem;
        struct lookup_intent *rpcl_it;
};
extern struct mdc_rpc_lock mdc_rpc_lock;
extern struct mdc_rpc_lock mdc_setattr_lock;

static inline void mdc_init_rpc_lock(struct mdc_rpc_lock *lck)
{
        sema_init(&lck->rpcl_sem, 1);
        lck->rpcl_it = NULL;
}

#ifdef __KERNEL__
/* Compat code for kernel patch v18 users, can be removed when everyone has
 * upgraded --phik 02 June 2003 */
#ifdef IT_FL_LOCKED
static inline void mdc_get_rpc_lock(struct mdc_rpc_lock *lck, 
                                    struct lookup_intent *it)
{
        down(&lck->rpcl_sem);
        if (it) { 
                lck->rpcl_it = it;
                it->it_int_flags |= IT_FL_LOCKED;
        }
}

static inline void mdc_put_rpc_lock(struct mdc_rpc_lock *lck, 
                                    struct lookup_intent *it)
{
        if (it == NULL) {
                LASSERT(it == lck->rpcl_it);
                up(&lck->rpcl_sem);
                return;
        }
        if (it != NULL && (it->it_int_flags & IT_FL_LOCKED)) {
                it->it_int_flags &= ~IT_FL_LOCKED;
                LASSERT(it == lck->rpcl_it);
                lck->rpcl_it = NULL;
                up(&lck->rpcl_sem);
        }
}
#else
static inline void mdc_get_rpc_lock(struct mdc_rpc_lock *lck, 
                                    struct lookup_intent *it)
{
        down(&lck->rpcl_sem);
        if (it) { 
                lck->rpcl_it = it;
                it->it_iattr = (void *)1;
        }
}

static inline void mdc_put_rpc_lock(struct mdc_rpc_lock *lck, 
                                    struct lookup_intent *it)
{
        if (it == NULL) {
                LASSERT(it == lck->rpcl_it);
                up(&lck->rpcl_sem);
                return;
        }
        if (it && it->it_iattr) {
                it->it_iattr = NULL;
                LASSERT(it == lck->rpcl_it);
                lck->rpcl_it = NULL;
                up(&lck->rpcl_sem);
        }
}
#endif
#endif

struct mdc_op_data {
        __u64   ino1;
        __u32   gen1;
        __u32   typ1;
        __u32   gid1;
        __u64   ino2;
        __u32   gen2;
        __u32   typ2;
        __u32   gid2;
        const char *name;
        int     namelen;
        int     mode;
};

struct mds_update_record {
        __u32 ur_opcode;
        struct ll_fid *ur_fid1;
        struct ll_fid *ur_fid2;
        int ur_namelen;
        char *ur_name;
        int ur_tgtlen;
        char *ur_tgt;
        int ur_eadatalen;
        void *ur_eadata;
        struct iattr ur_iattr;
        struct obd_ucred ur_uc;
        __u64 ur_rdev;
        __u32 ur_mode;
        __u32 ur_uid;
        __u32 ur_gid;
        __u64 ur_time;
        __u32 ur_flags;
};

#define ur_fsuid    ur_uc.ouc_fsuid
#define ur_fsgid    ur_uc.ouc_fsgid
#define ur_cap      ur_uc.ouc_cap
#define ur_suppgid1 ur_uc.ouc_suppgid1
#define ur_suppgid2 ur_uc.ouc_suppgid2

#define MDS_LR_CLIENT  8192
#define MDS_LR_SIZE     128

#define MDS_CLIENT_SLOTS 17

#define MDS_MOUNT_RECOV 2

/* Data stored per server at the head of the last_rcvd file.  In le32 order. */
struct mds_server_data {
        __u8 msd_uuid[37];      /* server UUID */
        __u8 uuid_padding[3];   /* unused */
        __u64 msd_last_transno; /* last completed transaction ID */
        __u64 msd_mount_count;  /* MDS incarnation number */
        __u8 padding[512 - 56];
};

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct mds_client_data {
        __u8 mcd_uuid[37];      /* client UUID */
        __u8 uuid_padding[3];   /* unused */
        __u64 mcd_mount_count;  /* MDS incarnation number */
        __u64 mcd_last_transno; /* last completed transaction ID */
        __u64 mcd_last_xid;     /* xid for the last transaction */
        __u32 mcd_last_result;  /* result from last RPC */
        __u32 mcd_last_data;    /* per-op data (disposition for open &c.) */
        __u8 padding[MDS_LR_SIZE - 74];
};

/* file data for open files on MDS */
struct mds_file_data {
        struct portals_handle mfd_handle; /* must be first */
        atomic_t              mfd_refcount;
        struct list_head      mfd_list;
        __u64                 mfd_xid;
        int                   mfd_mode;
        struct dentry        *mfd_dentry;
};

/* mds/mds_reint.c  */
int mds_reint_rec(struct mds_update_record *r, int offset,
                  struct ptlrpc_request *req, struct lustre_handle *);

/* mds/mds_open.c */
int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req, struct lustre_handle *);

/* mds/handler.c */
#ifdef __KERNEL__
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
int mds_reint(struct ptlrpc_request *req, int offset, struct lustre_handle *);
int mds_pack_md(struct obd_device *mds, struct lustre_msg *msg,
                int offset, struct mds_body *body, struct inode *inode);
void mds_steal_ack_locks(struct obd_export *exp,
                         struct ptlrpc_request *req);

/* mds/mds_fs.c */
int mds_fs_setup(struct obd_device *obddev, struct vfsmount *mnt);
int mds_fs_cleanup(struct obd_device *obddev, int failover);
#endif

/* mdc/mdc_request.c */
int mdc_enqueue(struct lustre_handle *conn, int lock_type,
                struct lookup_intent *it, int lock_mode,
                struct mdc_op_data *enq_data,
                struct lustre_handle *lockh, char *tgt, int tgtlen,
                ldlm_completion_callback cb_completion,
                ldlm_blocking_callback cb_blocking,
                void *cb_data);
int mdc_getlovinfo(struct obd_device *obd, struct lustre_handle *mdc_connh,
                   struct ptlrpc_request **request);
int mdc_getstatus(struct lustre_handle *conn, struct ll_fid *rootfid);
int mdc_getattr(struct lustre_handle *conn, struct ll_fid *fid,
                unsigned long valid, unsigned int ea_size,
                struct ptlrpc_request **request);
int mdc_getattr_name(struct lustre_handle *conn, struct ll_fid *fid,
                     char *filename, int namelen, unsigned long valid,
                     unsigned int ea_size, struct ptlrpc_request **request);
int mdc_setattr(struct lustre_handle *conn,
                struct mdc_op_data *data,
                struct iattr *iattr, void *ea, int ealen,
                struct ptlrpc_request **request);
int mdc_open(struct lustre_handle *conn, obd_id ino, int type, int flags,
             struct lov_mds_md *lmm, int lmm_size, struct lustre_handle *fh,
             struct ptlrpc_request **);
struct obd_client_handle;
void mdc_set_open_replay_data(struct obd_client_handle *och);
int mdc_close(struct lustre_handle *conn, obd_id ino, int type,
              struct lustre_handle *fh,  struct ptlrpc_request **req);
int mdc_readpage(struct lustre_handle *conn, obd_id ino, int type, __u64 offset,
                 struct page *, struct ptlrpc_request **);
int mdc_create(struct lustre_handle *conn, struct mdc_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid, __u32 gid,
               __u64 time, __u64 rdev, struct ptlrpc_request **request);
int mdc_unlink(struct lustre_handle *conn, struct mdc_op_data *data,
               struct ptlrpc_request **request);
int mdc_link(struct lustre_handle *conn, struct mdc_op_data *data,
             struct ptlrpc_request **);
int mdc_rename(struct lustre_handle *conn, struct mdc_op_data *data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request);
int mdc_create_client(struct obd_uuid uuid, struct ptlrpc_client *cl);

/* Store the generation of a newly-created inode in |req| for replay. */
void mdc_store_inode_generation(struct ptlrpc_request *req, int reqoff,
                                int repoff);


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

#define MDS_CHECK_RESENT(req, reconstruct)                                     \
{                                                                              \
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {               \
                struct mds_client_data *mcd =                                  \
                        req->rq_export->exp_mds_data.med_mcd;                  \
                if (mcd->mcd_last_xid == req->rq_xid) {                        \
                        reconstruct;                                           \
                        RETURN(0);                                             \
                }                                                              \
                DEBUG_REQ(D_HA, req, "no reply for RESENT req (have "LPD64")", \
                          mcd->mcd_last_xid);                                  \
        }                                                                      \
}

#endif
