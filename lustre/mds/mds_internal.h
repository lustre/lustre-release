/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _MDS_INTERNAL_H
#define _MDS_INTERNAL_H

#include <linux/lustre_mds.h>

#define MAX_ATIME_DIFF 60

struct mds_filter_data {
        __u64 io_epoch;
};

#define MDS_FILTERDATA(inode) ((struct mds_filter_data *)(inode)->i_filterdata)
#define DENTRY_VALID(dentry)    \
        ((dentry)->d_inode || ((dentry)->d_flags & DCACHE_CROSS_REF))

#define MDS_NO_SPLIT_EXPECTED   0
#define MDS_EXPECT_SPLIT        1
#define MDS_NO_SPLITTABLE       2

static inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mds;
}
static inline struct obd_device *req2obd(struct ptlrpc_request *req)
{
        return req->rq_export->exp_obd;
}

typedef enum {
        MDS_OPEN_COUNT         = 0,
        MDS_CREATE_COUNT       = 1,
        MDS_CLOSE_COUNT        = 2,
        MDS_LINK_COUNT         = 3,
        MDS_UNLINK_COUNT       = 4,
        MDS_GETATTR_COUNT      = 5,
        MDS_GETATTR_NAME_COUNT = 6,
        MDS_SETATTR_COUNT      = 7,
        MDS_RENAME_COUNT       = 8,
        MDS_STATFS_COUNT       = 9,
        MDS_LAST_OPC_COUNT     = 10
} mds_counters_t;

struct lprocfs_stats * lprocfs_alloc_mds_counters(void);
void lprocfs_free_mds_counters(struct lprocfs_stats *ptr);

#ifndef LPROCFS
#define MDS_UPDATE_COUNTER(mds, opcode) do {} while (0)
#else

#define MDS_UPDATE_COUNTER(mds, opcode) \
        LASSERT( opcode < MDS_LAST_OPC_COUNT); \
        LASSERT( mds->mds_counters != NULL); \
        lprocfs_counter_incr(mds->mds_counters, opcode);
#endif

/* mds/mds_reint.c */
int enqueue_ordered_locks(struct obd_device *obd, struct ldlm_res_id *p1_res_id,
                          struct lustre_handle *p1_lockh, int p1_lock_mode,
                          ldlm_policy_data_t *p1_policy,
                          struct ldlm_res_id *p2_res_id,
                          struct lustre_handle *p2_lockh, int p2_lock_mode,
                          ldlm_policy_data_t *p2_policy);
void mds_commit_cb(struct obd_device *, __u64 last_rcvd, void *data, int error);
int mds_finish_transno(struct mds_obd *mds, struct inode *inode, void *handle,
                       struct ptlrpc_request *req, int rc, __u32 op_data);
void mds_reconstruct_generic(struct ptlrpc_request *req);
void mds_req_from_mcd(struct ptlrpc_request *req, struct mds_client_data *mcd);
int mds_get_parent_child_locked(struct obd_device *obd, struct mds_obd *mds,
                                struct ll_fid *fid,
                                struct lustre_handle *parent_lockh,
                                struct dentry **dparentp, int parent_mode,
                                __u64 parent_lockpart, int *update_mode,
                                char *name, int namelen,
                                struct lustre_handle *child_lockh,
                                struct dentry **dchildp, int child_mode,
                                __u64 child_lockpart, void* clone_info);
int mds_lock_new_child(struct obd_device *obd, struct inode *inode,
                       struct lustre_handle *child_lockh);

/* mds/mds_lib.c */
int mds_update_unpack(struct ptlrpc_request *, int offset,
                      struct mds_update_record *);

/* mds/mds_unlink_open.c */
int mds_open_unlink_rename(struct mds_update_record *rec,
                           struct obd_device *obd, struct dentry *dparent,
                           struct dentry *dchild, void **handle);
int mds_cleanup_orphans(struct obd_device *obd);


/* mds/mds_log.c */
int mds_log_op_unlink(struct obd_device *obd, struct inode *inode,
                      struct lov_mds_md *lmm, int lmm_size,
                      struct llog_cookie *logcookies, int cookies_size,
                      struct llog_create_locks **res);
int mds_llog_init(struct obd_device *obd, struct obd_llogs *,
                  struct obd_device *tgt, int count, struct llog_catid *logid);
int mds_llog_finish(struct obd_device *obd, struct obd_llogs *, int count);

/* mds/mds_lov.c */
int mds_lov_connect(struct obd_device *obd, char * lov_name);
int mds_lov_disconnect(struct obd_device *obd, int flags);
int mds_lov_set_info(struct obd_export *exp, obd_count keylen,
                     void *key, obd_count vallen, void *val);
int mds_get_lovtgts(struct obd_device *, int tgt_count, struct obd_uuid *);
int mds_lov_write_objids(struct obd_device *obd);
void mds_lov_update_objids(struct obd_device *obd, obd_id *ids);
int mds_lov_set_growth(struct mds_obd *mds, int count);
int mds_lov_set_nextid(struct obd_device *obd);
int mds_lov_clearorphans(struct mds_obd *mds, struct obd_uuid *ost_uuid);
int mds_post_mds_lovconf(struct obd_device *obd);
int mds_notify(struct obd_device *obd, struct obd_device *watched,
               int active, void *data);
int mds_lov_update_config(struct obd_device *obd, int transno);
int mds_convert_lov_ea(struct obd_device *obd, struct inode *inode,
                       struct lov_mds_md *lmm, int lmm_size);
int mds_revalidate_lov_ea(struct obd_device *obd, struct inode *inode,
                          struct lustre_msg *msg, int offset);

/* mds/mds_open.c */
int mds_query_write_access(struct inode *inode);
int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req, struct lustre_handle *);
int mds_pin(struct ptlrpc_request *req);
int mds_mfd_close(struct ptlrpc_request *req, struct obd_device *obd,
                  struct mds_file_data *mfd, int unlink_orphan);
int mds_close(struct ptlrpc_request *req);
int mds_done_writing(struct ptlrpc_request *req);


/* mds/mds_fs.c */
int mds_client_add(struct obd_device *obd, struct mds_obd *mds,
                   struct mds_export_data *med, int cl_off);
int mds_client_free(struct obd_export *exp, int clear_client);
int mds_obd_create(struct obd_export *exp, struct obdo *oa,
                      struct lov_stripe_md **ea, struct obd_trans_info *oti);
int mds_obd_destroy(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *ea, struct obd_trans_info *oti);

/* mds/handler.c */
int mds_handle(struct ptlrpc_request *req);
extern struct lvfs_callback_ops mds_lvfs_ops;
int mds_lov_clean(struct obd_device *obd);
extern int mds_iocontrol(unsigned int cmd, struct obd_export *exp,
                         int len, void *karg, void *uarg);
extern int mds_lock_mode_for_dir(struct obd_device *, struct dentry *, int);
int mds_postrecov(struct obd_device *obd);

#ifdef __KERNEL__
int mds_get_md(struct obd_device *, struct inode *, void *md, int *size, 
               int lock);
int mds_pack_md(struct obd_device *, struct lustre_msg *, int offset,
                struct mds_body *, struct inode *, int lock);
void mds_pack_dentry2fid(struct ll_fid *, struct dentry *);
void mds_pack_dentry2body(struct mds_body *b, struct dentry *dentry);
void mds_pack_inode2fid(struct obd_device *, struct ll_fid *, struct inode *);
void mds_pack_inode2body(struct obd_device *, struct mds_body *, struct inode *);
#endif

/* mds/mds_lmv.c */
int mds_lmv_postsetup(struct obd_device *obd);
int mds_lmv_connect(struct obd_device *obd, char * lov_name);
int mds_lmv_disconnect(struct obd_device *obd, int flags);
int mds_try_to_split_dir(struct obd_device *, struct dentry *, struct mea **,
                         int, int);
int mds_get_lmv_attr(struct obd_device *, struct inode *, struct mea **, int *);
int mds_choose_mdsnum(struct obd_device *, const char *, int, int);
int mds_lmv_postsetup(struct obd_device *);
int mds_splitting_expected(struct obd_device *, struct dentry *);
int mds_lock_slave_objs(struct obd_device *, struct dentry *,
                        struct lustre_handle **);
int mds_unlink_slave_objs(struct obd_device *, struct dentry *);
void mds_unlock_slave_objs(struct obd_device *, struct dentry *,
                           struct lustre_handle *);
int mds_lock_and_check_slave(int, struct ptlrpc_request *, struct lustre_handle *);
int mds_convert_mea_ea(struct obd_device *, struct inode *, struct lov_mds_md *, int);


#endif /* _MDS_INTERNAL_H */
