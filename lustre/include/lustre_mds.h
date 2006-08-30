/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_MDS_H
#define _LUSTRE_MDS_H

#include <lustre_handles.h>
#include <libcfs/kp30.h>
#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_dlm.h>
#include <lustre_log.h>
#include <lustre_export.h>

#if defined(__linux__)
#include <linux/lustre_mds.h>
#elif defined(__APPLE__)
#include <darwin/lustre_mds.h>
#elif defined(__WINNT__)
#include <winnt/lustre_mds.h>
#else
#error Unsupported operating system.
#endif

struct ldlm_lock_desc;
struct mds_obd;
struct ptlrpc_connection;
struct ptlrpc_client;
struct obd_export;
struct ptlrpc_request;
struct obd_device;
struct ll_file_data;

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
        int ur_cookielen;
        struct llog_cookie *ur_logcookies;
        struct iattr ur_iattr;
        struct lvfs_ucred ur_uc;
        __u64 ur_rdev;
        __u64 ur_time;
        __u32 ur_mode;
        __u32 ur_flags;
        struct lvfs_grp_hash_entry *ur_grp_entry;
};

/* file data for open files on MDS */
struct mds_file_data {
        struct portals_handle mfd_handle; /* must be first */
        atomic_t              mfd_refcount;
        struct list_head      mfd_list; /* protected by med_open_lock */
        __u64                 mfd_xid;
        int                   mfd_mode;
        struct dentry        *mfd_dentry;
};

/* mds/mds_reint.c */
struct inode;

int mds_reint_rec(struct mds_update_record *r, int offset,
                  struct ptlrpc_request *req, struct lustre_handle *);

int mds_osc_setattr_async(struct obd_device *obd, __u32 uid, __u32 gid,
                          struct lov_mds_md *lmm, int lmm_size,
                          struct llog_cookie *logcookies, __u64 id, __u32 gen);

int mds_log_op_unlink(struct obd_device *obd,
                      struct lov_mds_md *lmm, int lmm_size,
                      struct llog_cookie *logcookies, int cookies_size);
int mds_log_op_setattr(struct obd_device *obd, struct inode *inode,
                      struct lov_mds_md *lmm, int lmm_size,
                      struct llog_cookie *logcookies, int cookies_size);

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

#define MDS_LOV_MD_NAME "trusted.lov"
#define MDS_LMV_MD_NAME "trusted.lmv"
#define MDD_OBD_NAME    "mdd_obd"
#define MDD_OBD_UUID    "mdd_obd_uuid"
#define MDD_OBD_TYPE    "mds"
#define MDD_OBD_PROFILE "lustre-MDT0000"

#endif
