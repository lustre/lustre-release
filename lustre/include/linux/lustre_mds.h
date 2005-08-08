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
#include <libcfs/kp30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_export.h>
#include <linux/lustre_ucache.h>

struct ldlm_lock_desc;
struct mds_obd;
struct ptlrpc_connection;
struct ptlrpc_client;
struct obd_export;
struct ptlrpc_request;
struct obd_device;
struct ll_file_data;

struct mds_update_record {
        __u32               ur_opcode;
        struct lustre_id   *ur_id1;
        struct lustre_id   *ur_id2;
        int                 ur_namelen;
        char               *ur_name;
        int                 ur_tgtlen;
        char               *ur_tgt;
        int                 ur_eadatalen;
        void               *ur_eadata;
        int                 ur_ea2datalen;
        void               *ur_ea2data;
        int                 ur_ea3datalen;
        void               *ur_ea3data;
        int                 ur_cookielen;       /* obsolete? */
        struct llog_cookie *ur_logcookies;      /* obsolete? */
        struct iattr        ur_iattr;
        struct lvfs_ucred   ur_uc;
        __u64               ur_rdev;
        __u32               ur_mode;
        __u64               ur_time;
        __u32               ur_flags;
};

#define ur_fsuid    ur_uc.luc_fsuid
#define ur_fsgid    ur_uc.luc_fsgid
#define ur_cap      ur_uc.luc_cap
#define ur_uid      ur_uc.luc_uid


#define MDS_LR_SERVER_SIZE    512

#define MDS_LR_CLIENT_START  8192
#define MDS_LR_CLIENT_SIZE    128
#if MDS_LR_CLIENT_START < MDS_LR_SERVER_SIZE
#error "Can't have MDS_LR_CLIENT_START < MDS_LR_SERVER_SIZE"
#endif

#define MDS_CLIENT_SLOTS 17

#define MDS_ROCOMPAT_LOVOBJID   0x00000001
#define MDS_ROCOMPAT_SUPP       (MDS_ROCOMPAT_LOVOBJID)

#define MDS_INCOMPAT_SUPP       (0)

#define MDS_MASTER_OBD           1
#define MDS_CACHE_OBD            0

/*flags for indicate the record are come from cmobd reint or 
  mdc create */
#define REC_REINT_CREATE        0x0001

/* Data stored per server at the head of the last_rcvd file.  In le32 order.
 * Try to keep this the same as fsd_server_data so we might one day merge. */
struct mds_server_data {
        __u8  msd_uuid[40];        /* server UUID */
        __u64 msd_last_transno;    /* last completed transaction ID */
        __u64 msd_mount_count;     /* MDS incarnation number */
        __u64 msd_unused;
        __u32 msd_feature_compat;  /* compatible feature flags */
        __u32 msd_feature_rocompat;/* read-only compatible feature flags */
        __u32 msd_feature_incompat;/* incompatible feature flags */
        __u32 msd_server_size;     /* size of server data area */
        __u32 msd_client_start;    /* start of per-client data area */
        __u16 msd_client_size;     /* size of per-client data area */
        __u16 msd_subdir_count;    /* number of subdirectories for objects */
        __u64 msd_catalog_oid;     /* recovery catalog object id */
        __u32 msd_catalog_ogen;    /* recovery catalog inode generation */
        __u8  msd_peeruuid[40];    /* UUID of LOV/OSC associated with MDS */
        __u8  msd_padding[MDS_LR_SERVER_SIZE - 140];
};

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct mds_client_data {
        __u8 mcd_uuid[40];      /* client UUID */
        __u64 mcd_last_transno; /* last completed transaction ID */
        __u64 mcd_last_xid;     /* xid for the last transaction */
        __u32 mcd_last_result;  /* result from last RPC */
        __u32 mcd_last_data;    /* per-op data (disposition for open &c.) */
        /* for MDS_CLOSE requests */
        __u64 mcd_last_close_transno; /* last completed transaction ID */
        __u64 mcd_last_close_xid;     /* xid for the last transaction */
        __u32 mcd_last_close_result;  /* result from last RPC */
        __u32 mcd_last_close_data;  /* per-op data (disposition for open &c.) */
        __u8 mcd_padding[MDS_LR_CLIENT_SIZE - 88];
};

/* uid/gid mapping support for remote client, some of them
 * probably consume too much space??
 */
#define MDS_IDMAP_HASHSIZE      (32)
#define MDS_IDMAP_HASHFUNC(id)  ((id) & (MDS_IDMAP_HASHSIZE - 1))

#define MDS_RMT_UIDMAP_IDX      (0)
#define MDS_LCL_UIDMAP_IDX      (1)
#define MDS_RMT_GIDMAP_IDX      (2)
#define MDS_LCL_GIDMAP_IDX      (3)
#define MDS_IDMAP_N_HASHES      (4)

#define MDS_IDMAP_NOTFOUND      (-1)

struct mds_idmap_entry {
        struct list_head rmt_hash; /* hashed as rmt_id; */
        struct list_head lcl_hash; /* hashed as lcl_id; */
        atomic_t         refcount;
        uid_t            rmt_id;   /* remote uid/gid */
        uid_t            lcl_id;   /* local uid/gid */
};

struct mds_idmap_table {
        spinlock_t       mit_lock;
        struct list_head mit_idmaps[MDS_IDMAP_N_HASHES][MDS_IDMAP_HASHSIZE];
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

/* group hash table */
struct mds_grp_hash_entry {
        struct list_head        ge_hash;
        struct group_info      *ge_group_info;
        uid_t                   ge_uid;
        int                     ge_flags;
        atomic_t                ge_refcount;
        wait_queue_head_t       ge_waitq;
        long                    ge_acquisition_time;
        unsigned long           ge_acquire_expire;
        unsigned long           ge_expire;
};

#define MDSGRP_HASH_SIZE        (128)
#define MDSGRP_HASH_INDEX(id)   ((id) & (MDSGRP_HASH_SIZE - 1))
#define MDSGRP_UPCALL_MAXPATH   (1024)

struct mds_grp_hash {
        struct list_head        gh_table[MDSGRP_HASH_SIZE];
        spinlock_t              gh_lock;
        char                    gh_upcall[MDSGRP_UPCALL_MAXPATH];
        int                     gh_entry_expire;
        int                     gh_acquire_expire;
        unsigned int            gh_allow_setgroups:1;
};

#ifdef PTL_NETID_ANY
#error "remove this"
#endif
#define PTL_NETID_ANY   ((ptl_netid_t) -1)

#define LSD_PERM_SETUID         0x00000001
#define LSD_PERM_SETGID         0x00000002
#define LSD_PERM_SETGRP         0x00000004

struct lsd_permission {
        ptl_nid_t       nid;
        ptl_netid_t     netid;
        __u32           perm;
};

/* lustre security descriptor */
struct lustre_sec_desc {
        unsigned int            lsd_invalid:1;
        uid_t                   lsd_uid;
        gid_t                   lsd_gid;
        struct group_info      *lsd_ginfo;
        __u32                   lsd_nperms;
        struct lsd_permission  *lsd_perms;
};

struct lsd_cache_entry {
        struct upcall_cache_entry     base;
        struct lustre_sec_desc        lsd;
};

struct lsd_downcall_args {
        int                     err;
        uid_t                   uid;
        gid_t                   gid;
        __u32                   ngroups;
        gid_t                  *groups;
        __u32                   nperms;
        struct lsd_permission  *perms;       
};

/* remote acl upcall */
struct rmtacl_upcall_desc {
        int     status;         /* helper execution status */
        int     upcall_status;  /* error in upcall itself */
        int     get;            /* is getfacl */
        char   *cmd;            /* cmdline (up) */
        __u32   cmdlen;         /* cmdline length (up) */
        char   *res;            /* output (down) */
        __u32   reslen;         /* output length (down) */
        /* upcall internal use */
        uid_t   uid;
        char   *root;
};

struct rmtacl_upcall_entry {
        struct upcall_cache_entry   base;
        struct rmtacl_upcall_desc  *desc;
};

struct rmtacl_downcall_args {
        __u64   key;
        char   *res;            /* output text */
        __u32   reslen;         /* output text length */
        int     status;         /* helper exit code */
};

/* mds/mds_reint.c  */
int mds_reint_rec(struct mds_update_record *r, int offset,
                  struct ptlrpc_request *req, struct lustre_handle *);

/* mds/mds_lsd.c */
__u32 mds_lsd_get_perms(struct lustre_sec_desc *lsd, __u32 is_remote,
                        ptl_netid_t netid, ptl_nid_t nid);

/* mds/handler.c */
#ifdef __KERNEL__
struct dentry *
mds_id2dentry(struct obd_device *obd, struct lustre_id *id,
              struct vfsmount **mnt);

struct dentry *
mds_id2locked_dentry(struct obd_device *obd, struct lustre_id *id,
                     struct vfsmount **mnt, int lock_mode,
                     struct lustre_handle *lockh, int *pmode,
                     char *name, int namelen, __u64 lockpart);
		     
int mds_update_server_data(struct obd_device *, int force_sync);
int mds_update_last_fid(struct obd_device *obd, void *handle, 
			int force_sync);

/* mds/mds_fs.c */
int mds_fs_setup(struct obd_device *obddev, struct vfsmount *mnt);
int mds_fs_cleanup(struct obd_device *obddev, int failover);
#endif

/* mds/mds_lov.c */

/* mdc/mdc_locks.c */
int it_disposition(struct lookup_intent *it, int flag);
void it_set_disposition(struct lookup_intent *it, int flag);
int it_open_error(int phase, struct lookup_intent *it);
int mdc_set_lock_data(struct obd_export *exp, __u64 *lockh, void *data);
int mdc_change_cbdata(struct obd_export *exp, struct lustre_id *id, 
                      ldlm_iterator_t it, void *data);
int mdc_intent_lock(struct obd_export *exp, struct lustre_id *parent, 
                    const char *name, int len, void *lmm, int lmmsize, 
                    struct lustre_id *child, struct lookup_intent *, int, 
                    struct ptlrpc_request **reqp, 
                    ldlm_blocking_callback cb_blocking);
int mdc_enqueue(struct obd_export *exp,
                int lock_type,
                struct lookup_intent *it,
                int lock_mode,
                struct mdc_op_data *data,
                struct lustre_handle *lockh,
                void *lmm,
                int lmmlen,
                ldlm_completion_callback cb_completion,
                ldlm_blocking_callback cb_blocking,
                void *cb_data);

/* mdc/mdc_request.c */
int mdc_req2lustre_md(struct obd_export *exp_lmv, struct ptlrpc_request *req, 
                      unsigned int offset, struct obd_export *exp_lov, 
                      struct lustre_md *md);
int mdc_getstatus(struct obd_export *exp, struct lustre_id *rootid);
int mdc_getattr(struct obd_export *exp, struct lustre_id *id,
                __u64 valid, const char *xattr_name,
                const void *xattr_data, unsigned int xattr_datalen,
                unsigned int ea_size, struct ptlrpc_request **request);
int mdc_getattr_lock(struct obd_export *exp, struct lustre_id *id,
                     char *filename, int namelen, __u64 valid,
                     unsigned int ea_size, struct ptlrpc_request **request);
int mdc_setattr(struct obd_export *exp, struct mdc_op_data *data,
                struct iattr *iattr, void *ea, int ealen, void *ea2, int ea2len,
                void *ea3, int ea3len, struct ptlrpc_request **request);
int mdc_open(struct obd_export *exp, obd_id ino, int type, int flags,
             struct lov_mds_md *lmm, int lmm_size, struct lustre_handle *fh,
             struct ptlrpc_request **);

struct obd_client_handle;

int mdc_set_open_replay_data(struct obd_export *exp, 
                             struct obd_client_handle *och,
                             struct ptlrpc_request *open_req);
int mdc_clear_open_replay_data(struct obd_export *exp, 
                               struct obd_client_handle *och);
int mdc_close(struct obd_export *, struct obdo *, struct obd_client_handle *,
              struct ptlrpc_request **);
int mdc_readpage(struct obd_export *exp, struct lustre_id *id,
                 __u64, struct page *, struct ptlrpc_request **);
int mdc_create(struct obd_export *exp, struct mdc_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid, __u32 gid,
               __u64 rdev, struct ptlrpc_request **request);
int mdc_unlink(struct obd_export *exp, struct mdc_op_data *data,
               struct ptlrpc_request **request);
int mdc_link(struct obd_export *exp, struct mdc_op_data *data,
             struct ptlrpc_request **);
int mdc_rename(struct obd_export *exp, struct mdc_op_data *data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request);
int mdc_sync(struct obd_export *exp, struct lustre_id *id,
             struct ptlrpc_request **);
int mdc_create_client(struct obd_uuid uuid, struct ptlrpc_client *cl);

/* store the generation of a newly-created inode in |req| for replay. */
int mdc_store_inode_generation(struct obd_export *exp,
                               struct ptlrpc_request *req, 
                               int reqoff, int repoff);

int mdc_llog_process(struct obd_export *, char *, llog_cb_t,
                     void *);

int mdc_done_writing(struct obd_export *, struct obdo *);

/* mds_audit_path.c */
int mds_audit_id2name(struct obd_device *obd, char **name, int *namelen, 
                      struct lustre_id *id);

/* ioctls for trying requests */
#define IOC_REQUEST_TYPE                 'f'
#define IOC_REQUEST_MIN_NR               30

#define IOC_REQUEST_GETATTR             _IOWR('f', 30, long)
#define IOC_REQUEST_READPAGE            _IOWR('f', 31, long)
#define IOC_REQUEST_SETATTR             _IOWR('f', 32, long)
#define IOC_REQUEST_CREATE              _IOWR('f', 33, long)
#define IOC_REQUEST_OPEN                _IOWR('f', 34, long)
#define IOC_REQUEST_CLOSE               _IOWR('f', 35, long)
#define IOC_REQUEST_MAX_NR               35

#define MDS_CHECK_RESENT(req, reconstruct)                              \
{                                                                       \
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {        \
                struct mds_client_data *mcd =                           \
                        req->rq_export->exp_mds_data.med_mcd;           \
                                                                        \
                if (le64_to_cpu(mcd->mcd_last_xid) == req->rq_xid) {    \
                        reconstruct;                                    \
                        RETURN(le32_to_cpu(mcd->mcd_last_result));      \
                }                                                       \
                if (le64_to_cpu(mcd->mcd_last_close_xid) == req->rq_xid) { \
                        reconstruct;                                    \
                        RETURN(le32_to_cpu(mcd->mcd_last_close_result));\
                }                                                       \
                DEBUG_REQ(D_HA, req, "no reply for RESENT req"          \
                          "(have "LPD64", and "LPD64")",                \
                          mcd->mcd_last_xid, mcd->mcd_last_close_xid);  \
        }                                                               \
}

#endif
