static inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mds;
}

/* mds/mds_fs.c */
struct llog_handle *mds_log_create(struct obd_device *obd);
int mds_log_close(struct llog_handle *cathandle, struct llog_handle *loghandle);
struct llog_handle *mds_log_open(struct obd_device *obd,
                                 struct llog_cookie *logcookie);
struct llog_handle *mds_get_catalog(struct obd_device *obd);
void mds_put_catalog(struct llog_handle *cathandle);

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


