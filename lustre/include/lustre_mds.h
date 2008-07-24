/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre_mds.h
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

struct lustre_md {
        struct mds_body         *body;
        struct lov_stripe_md    *lsm;
#ifdef CONFIG_FS_POSIX_ACL
        struct posix_acl        *posix_acl;
#endif
};

struct mdc_op_data {
        struct ll_fid    fid1;
        struct ll_fid    fid2;
        struct ll_fid    fid3;
        struct ll_fid    fid4;
        __u64            mod_time;
        const char      *name;
        int              namelen;
        __u32            create_mode;
        __u32            suppgids[2];
        void            *data;
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
        int ur_cookielen;
        struct llog_cookie *ur_logcookies;
        struct iattr ur_iattr;
        struct lvfs_ucred ur_uc;
        __u64 ur_rdev;
        __u64 ur_time;
        __u32 ur_mode;
        __u32 ur_flags;
        struct lvfs_grp_hash_entry *ur_grp_entry;
        struct ldlm_request *ur_dlm;
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

/* ACL */
#ifdef CONFIG_FS_POSIX_ACL
# ifdef HAVE_XATTR_ACL
#  define MDS_XATTR_NAME_ACL_ACCESS XATTR_NAME_ACL_ACCESS
#  define mds_xattr_acl_size(entry) xattr_acl_size(entry)
# else /* HAVE_XATTR_ACL */
#  define MDS_XATTR_NAME_ACL_ACCESS POSIX_ACL_XATTR_ACCESS
#  define mds_xattr_acl_size(entry) posix_acl_xattr_size(entry)
# endif /* HAVE_XATTR_ACL */

# define LUSTRE_POSIX_ACL_MAX_ENTRIES   (32)
#  define LUSTRE_POSIX_ACL_MAX_SIZE      \
                (mds_xattr_acl_size(LUSTRE_POSIX_ACL_MAX_ENTRIES))
#else /* CONFIG_FS_POSIX_ACL */
# define LUSTRE_POSIX_ACL_MAX_SIZE      0
#endif /* CONFIG_FS_POSIX_ACL */

/* mds/mds_reint.c */
int mds_reint_rec(struct mds_update_record *r, int offset,
                  struct ptlrpc_request *req, struct lustre_handle *);

/* mds/mds_lov.c */

/* mdc/mdc_locks.c */
struct md_enqueue_info;

int it_disposition(struct lookup_intent *it, int flag);
void it_set_disposition(struct lookup_intent *it, int flag);
void it_clear_disposition(struct lookup_intent *it, int flag);
int it_open_error(int phase, struct lookup_intent *it);
void mdc_set_lock_data(__u64 *lockh, void *data);
int mdc_change_cbdata(struct obd_export *exp, struct ll_fid *fid,
                      ldlm_iterator_t it, void *data);
int mdc_revalidate_lock(struct obd_export *exp,
                        struct lookup_intent *it,
                        struct ll_fid *fid);
int mdc_intent_lock(struct obd_export *exp,
                    struct mdc_op_data *,
                    void *lmm, int lmmsize,
                    struct lookup_intent *, int,
                    struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking, int extra_lock_flags);
int mdc_enqueue(struct obd_export *exp, struct ldlm_enqueue_info *einfo,
                struct lookup_intent *it, struct mdc_op_data *data,
                struct lustre_handle *lockh, void *lmm, int lmmlen,
                int extra_lock_flags);
int mdc_intent_getattr_async(struct obd_export *exp,
                             struct md_enqueue_info *minfo,
                             struct ldlm_enqueue_info *einfo);

/* mdc/mdc_request.c */
int mdc_init_ea_size(struct obd_export *mdc_exp, struct obd_export *lov_exp);
int mdc_req2lustre_md(struct ptlrpc_request *req, int offset,
                      struct obd_export *exp, struct lustre_md *md);
void mdc_free_lustre_md(struct obd_export *exp, struct lustre_md *md);
int mdc_getstatus(struct obd_export *exp, struct ll_fid *rootfid);
int mdc_getattr(struct obd_export *exp, struct ll_fid *fid,
                obd_valid valid, unsigned int ea_size,
                struct ptlrpc_request **request);
int mdc_getattr_name(struct obd_export *exp, struct ll_fid *fid,
                     const char *filename, int namelen, unsigned long valid,
                     unsigned int ea_size, struct ptlrpc_request **request);
int mdc_setattr(struct obd_export *exp, struct mdc_op_data *data,
                struct iattr *iattr, void *ea, int ealen, void *ea2, int ea2len,
                struct ptlrpc_request **request);
int mdc_setxattr(struct obd_export *exp, struct ll_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, int flags,
                 struct ptlrpc_request **request);
int mdc_getxattr(struct obd_export *exp, struct ll_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, struct ptlrpc_request **request);
int mdc_open(struct obd_export *exp, obd_id ino, int type, int flags,
             struct lov_mds_md *lmm, int lmm_size, struct lustre_handle *fh,
             struct ptlrpc_request **);
struct obd_client_handle;
void mdc_set_open_replay_data(struct obd_client_handle *och,
                              struct ptlrpc_request *open_req);
void mdc_clear_open_replay_data(struct obd_client_handle *och);
int mdc_close(struct obd_export *, struct obdo *, struct obd_client_handle *,
              struct ptlrpc_request **);
int mdc_readpage(struct obd_export *exp, struct ll_fid *mdc_fid, __u64 offset,
                 struct page *, struct ptlrpc_request **);
int mdc_create(struct obd_export *exp, struct mdc_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid, __u32 gid,
               __u32 cap_effective, __u64 rdev,struct ptlrpc_request **request);
int mdc_unlink(struct obd_export *exp, struct mdc_op_data *data,
               struct ptlrpc_request **request);
int mdc_link(struct obd_export *exp, struct mdc_op_data *data,
             struct ptlrpc_request **);
int mdc_rename(struct obd_export *exp, struct mdc_op_data *data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request);
int mdc_sync(struct obd_export *exp, struct ll_fid *fid,
             struct ptlrpc_request **);
int mdc_create_client(struct obd_uuid uuid, struct ptlrpc_client *cl);
int mdc_resource_get_unused(struct obd_export *exp, struct ll_fid *fid,
                            struct list_head *cancels, ldlm_mode_t mode,
                            __u64 bits);

/* Store the generation of a newly-created inode in |req| for replay. */
void mdc_store_inode_generation(struct ptlrpc_request *req, int reqoff,
                                int repoff);
int mdc_llog_process(struct obd_export *, char *logname, llog_cb_t, void *data);
int mdc_done_writing(struct obd_export *exp, struct obdo *);

static inline void mdc_pack_fid(struct ll_fid *fid, obd_id ino, __u32 gen,
                                int type)
{
        fid->id = ino;
        fid->generation = gen;
        fid->f_type = type;
}

static inline int it_to_lock_mode(struct lookup_intent *it)
{
        /* CREAT needs to be tested before open (both could be set) */
        if (it->it_op & IT_CREAT)
                return LCK_CW;
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_LOOKUP))
                return LCK_CR;

        LBUG();
        return -EINVAL;
}

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

/* metadata stat-ahead */
typedef int (* md_enqueue_cb_t)(struct obd_export *exp,
                                struct ptlrpc_request *req,
                                struct md_enqueue_info *minfo,
                                int rc);

struct md_enqueue_info {
        struct mdc_op_data      mi_data;
        struct lookup_intent    mi_it;
        struct lustre_handle    mi_lockh;
        struct dentry          *mi_dentry;
        md_enqueue_cb_t         mi_cb;
        unsigned int            mi_generation;
        void                   *mi_cbdata;
};

#endif
