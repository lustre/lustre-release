void mds_pack_req_body(struct ptlrpc_request *);
void mds_pack_rep_body(struct ptlrpc_request *);
void mds_readdir_pack(struct ptlrpc_request *req, __u64 offset, __u32 size,
                      obd_id ino, int type);
void mds_getattr_pack(struct ptlrpc_request *req, int valid, int offset,
                      int flags, struct mdc_op_data *data);
void mds_setattr_pack(struct ptlrpc_request *req,
                      struct mdc_op_data *data,
                      struct iattr *iattr, void *ea, int ealen);
void mds_create_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *op_data,
                     __u32 mode, __u64 rdev, __u32 uid, __u32 gid, __u64 time,
                     const void *data, int datalen);
void mds_open_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *op_data,
                   __u32 mode, __u64 rdev, __u32 uid, __u32 gid, __u64 time,
                   __u32 flags, const void *data, int datalen);
void mds_unlink_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *data);
void mds_link_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *data);
void mds_rename_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *data,
                     const char *old, int oldlen, const char *new, int newlen);
