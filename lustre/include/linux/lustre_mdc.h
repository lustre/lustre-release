/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_MDC_H
#define _LUSTRE_MDC_H

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/dcache.h>
# ifdef CONFIG_FS_POSIX_ACL
# include <linux/xattr_acl.h>
# endif
#endif
#include <linux/lustre_handles.h>
#include <libcfs/kp30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_export.h>

struct ptlrpc_client;
struct obd_export;
struct ptlrpc_request;
struct obd_device;

struct lustre_md {
        struct mdt_body         *body;
        struct lov_stripe_md    *lsm;
#ifdef CONFIG_FS_POSIX_ACL
        struct posix_acl        *posix_acl;
#endif
};

struct md_op_data {
        struct lu_fid    fid1;
        struct lu_fid    fid2;
        __u64            mod_time;
        const char      *name;
        int              namelen;
        __u32            create_mode;
        __u32            suppgids[2];
        
        obd_valid        valid;
        obd_size         size;
        obd_blocks       blocks;
        obd_flag         flags;
        obd_time         mtime;
        obd_time         atime;
        obd_time         ctime;
};

/* mdc/mdc_locks.c */
int it_disposition(struct lookup_intent *it, int flag);
void it_set_disposition(struct lookup_intent *it, int flag);
int it_open_error(int phase, struct lookup_intent *it);
void mdc_set_lock_data(__u64 *lockh, void *data);
int mdc_change_cbdata(struct obd_export *exp, struct lu_fid *fid,
                      ldlm_iterator_t it, void *data);
int mdc_intent_lock(struct obd_export *exp,
                    struct md_op_data *,
                    void *lmm, int lmmsize,
                    struct lookup_intent *, int,
                    struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking, int extra_lock_flags);
int mdc_enqueue(struct obd_export *exp,
                int lock_type,
                struct lookup_intent *it,
                int lock_mode,
                struct md_op_data *op_data,
                struct lustre_handle *lockh,
                void *lmm,
                int lmmlen,
                ldlm_completion_callback cb_completion,
                ldlm_blocking_callback cb_blocking,
                void *cb_data, int extra_lock_flags);

/* mdc/mdc_request.c */
int mdc_init_ea_size(struct obd_export *mdc_exp, struct obd_export *lov_exp);

int mdc_req2lustre_md(struct ptlrpc_request *req, int offset,
                      struct obd_export *exp, struct lustre_md *md);
void mdc_free_lustre_md(struct obd_export *exp, struct lustre_md *md);

int mdc_getstatus(struct obd_export *exp, struct lu_fid *rootfid);
int mdc_getattr(struct obd_export *exp, struct lu_fid *fid,
                obd_valid valid, unsigned int ea_size,
                struct ptlrpc_request **request);
int mdc_getattr_name(struct obd_export *exp, struct lu_fid *fid,
                     const char *filename, int namelen, unsigned long valid,
                     unsigned int ea_size, struct ptlrpc_request **request);
int mdc_setattr(struct obd_export *exp, struct md_op_data *op_data,
                struct iattr *iattr, void *ea, int ealen, void *ea2, int ea2len,
                struct ptlrpc_request **request);
int mdc_setxattr(struct obd_export *exp, struct lu_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, int flags,
                 struct ptlrpc_request **request);
int mdc_getxattr(struct obd_export *exp, struct lu_fid *fid,
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
int mdc_close(struct obd_export *, struct md_op_data *, struct obd_client_handle *,
              struct ptlrpc_request **);
int mdc_readpage(struct obd_export *exp, struct lu_fid *mdc_fid, __u64 offset,
                 struct page *, struct ptlrpc_request **);
int mdc_create(struct obd_export *exp, struct md_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid, __u32 gid,
               __u32 cap_effective, __u64 rdev,struct ptlrpc_request **request);
int mdc_unlink(struct obd_export *exp, struct md_op_data *op_data,
               struct ptlrpc_request **request);
int mdc_link(struct obd_export *exp, struct md_op_data *op_data,
             struct ptlrpc_request **);
int mdc_rename(struct obd_export *exp, struct md_op_data *op_data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request);
int mdc_sync(struct obd_export *exp, struct lu_fid *fid,
             struct ptlrpc_request **);
int mdc_create_client(struct obd_uuid uuid, struct ptlrpc_client *cl);

int mdc_llog_process(struct obd_export *, char *logname, llog_cb_t, void *data);
int mdc_done_writing(struct obd_export *exp, struct md_op_data *op_data);

#endif
