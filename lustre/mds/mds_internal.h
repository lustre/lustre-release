static inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mds;
}

/* mds/handler.c */
struct mds_file_data *mds_mfd_new(void);
void mds_mfd_put(struct mds_file_data *mfd);
void mds_mfd_destroy(struct mds_file_data *mfd);

/* mds/mds_reint.c */
void mds_commit_cb(struct obd_device *obd, __u64 last_rcvd,
		   void *cb_data, int error);
int mds_finish_transno(struct mds_obd *mds, struct inode *inode, void *handle,
                       struct ptlrpc_request *req, int rc, __u32 op_data,
                       fsfilt_cb_t cb_fn, void *cb_data);

