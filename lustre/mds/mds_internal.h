struct mds_file_data *mds_mfd_new(void);
void mds_mfd_put(struct mds_file_data *mfd);
void mds_mfd_destroy(struct mds_file_data *mfd);
int mds_update_unpack(struct ptlrpc_request *, int offset,
                      struct mds_update_record *);

/* mds/mds_fs.c */
int mds_client_add(struct obd_device *obd, struct mds_export_data *med,
                   int cl_off);
int mds_client_free(struct obd_export *exp);

#ifdef __KERNEL__
void mds_pack_inode2fid(struct ll_fid *fid, struct inode *inode);
void mds_pack_inode2body(struct mds_body *body, struct inode *inode);
#endif
