#ifndef _MDS_INTERNAL_H
#define _MDS_INTERNAL_H
static inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mds;
}

/* mds/handler.c */
struct mds_file_data *mds_mfd_new(void);
void mds_mfd_put(struct mds_file_data *mfd);
void mds_mfd_destroy(struct mds_file_data *mfd);

/* mds/mds_reint.c */
void mds_commit_cb(struct obd_device *obd, __u64 last_rcvd, int error);
int mds_finish_transno(struct mds_obd *mds, struct inode *inode, void *handle,
                       struct ptlrpc_request *req, int rc, __u32 op_data,
                       fsfilt_cb_t cb_fn);

/* mds/mds_lib.c */
int mds_update_unpack(struct ptlrpc_request *, int offset,
                      struct mds_update_record *);

/* mds/mds_lov.c */
int mds_get_lovtgts(struct mds_obd *mds, int tgt_count,
                    struct obd_uuid *uuidarray);

/* mds/mds_open.c */
int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req, struct lustre_handle *);
int mds_pin(struct ptlrpc_request *req);

/* mds/mds_fs.c */
int mds_client_add(struct obd_device *obd, struct mds_obd *mds,
		   struct mds_export_data *med, int cl_off);
int mds_client_free(struct obd_export *exp);

#ifdef __KERNEL__
void mds_pack_inode2fid(struct ll_fid *fid, struct inode *inode);
void mds_pack_inode2body(struct mds_body *body, struct inode *inode);
#endif

#endif /* _MDS_INTERNAL_H */
