#include <linux/lustre_mds.h>
void mdc_pack_req_body(struct ptlrpc_request *);
void mdc_pack_rep_body(struct ptlrpc_request *);
void mdc_readdir_pack(struct ptlrpc_request *req, __u64 offset, __u32 size,
                      struct ll_fid *mdc_fid);
void mdc_getattr_pack(struct ptlrpc_request *req, int valid, int offset,
                      int flags, struct mdc_op_data *data);
void mdc_setattr_pack(struct ptlrpc_request *req,
                      struct mdc_op_data *data,
                      struct iattr *iattr, void *ea, int ealen,
		      void *ea2, int ea2len);
void mdc_create_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *op_data, const void *data, int datalen,
		     __u32 mode, __u32 uid, __u32 gid, __u32 cap_effective,
		     __u64 rdev);
void mdc_open_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *op_data, __u32 mode, __u64 rdev,
                   __u32 flags, const void *data, int datalen);
void mdc_unlink_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *data);
void mdc_link_pack(struct ptlrpc_request *req, int offset,
                   struct mdc_op_data *data);
void mdc_rename_pack(struct ptlrpc_request *req, int offset,
                     struct mdc_op_data *data,
                     const char *old, int oldlen, const char *new, int newlen);
void mdc_close_pack(struct ptlrpc_request *req, int offset, struct obdo *oa,
		    int valid, struct obd_client_handle *och);

struct mdc_open_data {
        struct obd_client_handle *mod_och;
        struct ptlrpc_request    *mod_open_req;
        struct ptlrpc_request    *mod_close_req;
};

struct mdc_rpc_lock {
        struct semaphore rpcl_sem;
        struct lookup_intent *rpcl_it;
};

static inline void mdc_init_rpc_lock(struct mdc_rpc_lock *lck)
{
        sema_init(&lck->rpcl_sem, 1);
        lck->rpcl_it = NULL;
}

static inline void mdc_get_rpc_lock(struct mdc_rpc_lock *lck, 
                                    struct lookup_intent *it)
{
        ENTRY;
        down(&lck->rpcl_sem);
        if (it) { 
                lck->rpcl_it = it;
        }
}

static inline void mdc_put_rpc_lock(struct mdc_rpc_lock *lck, 
                                    struct lookup_intent *it)
{
        EXIT;
        if (it == NULL) {
                LASSERT(it == lck->rpcl_it);
                up(&lck->rpcl_sem);
                return;
        }
        if (it) {
                LASSERT(it == lck->rpcl_it);
                lck->rpcl_it = NULL;
                up(&lck->rpcl_sem);
        }
}

/* Quota stuff */
#ifdef HAVE_QUOTA_SUPPORT
int mdc_quotacheck(struct obd_export *exp, struct obd_quotactl *oqctl);
int mdc_poll_quotacheck(struct obd_export *exp, struct if_quotacheck *qchk);
int mdc_quotactl(struct obd_export *exp, struct obd_quotactl *oqctl);
#else
static inline int mdc_quotacheck(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        return -ENOTSUPP;
}

static inline int mdc_poll_quotacheck(struct obd_export *exp, struct if_quotacheck *qchk)
{
        return -ENOTSUPP;
}

static inline int mdc_quotactl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        return -ENOTSUPP;
}
#endif


