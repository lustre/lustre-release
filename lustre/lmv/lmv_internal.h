#ifndef _LMV_INTERNAL_H_
#define _LMV_INTERNAL_H_

#define LL_IT2STR(it) ((it) ? ldlm_it2str((it)->it_op) : "0")
#define MEA_SIZE_LMV(lmv)       \
        ((lmv)->desc.ld_tgt_count * sizeof(struct ll_fid) + sizeof(struct mea))
        
struct lmv_inode {
        struct ll_fid   fid;            /* fid of dirobj */
        unsigned long   size;
        int             flags;
};

struct lmv_obj {
        struct list_head        list;
	struct semaphore        guard;
	int                     freeing;        /* object ig freeing. */
        atomic_t                count;
        struct ll_fid           fid;            /* master fid of dir */
        void                    *update;        /* bitmap of status (uptodate) */
        int                     objcount;
        struct lmv_inode        *objs;          /* array of dirobjs */
        struct obd_device       *obd;           /* pointer to LMV itself */
};

int lmv_setup_mgr(struct obd_device *obd);
void lmv_cleanup_mgr(struct obd_device *obd);
int lmv_check_connect(struct obd_device *obd);

void lmv_put_obj(struct lmv_obj *obj);
struct lmv_obj *lmv_get_obj(struct lmv_obj *obj);

struct lmv_obj *lmv_grab_obj(struct obd_device *obd,
			     struct ll_fid *fid);

void lmv_free_obj(struct lmv_obj *obj);
void lmv_add_obj(struct lmv_obj *obj);
void lmv_del_obj(struct lmv_obj *obj);

struct lmv_obj *lmv_alloc_obj(struct obd_device *obd,
			      struct ll_fid *fid,
			      struct mea *mea);

int lmv_create_obj(struct obd_export *exp, struct ll_fid *fid,
		   struct mea *mea);

int lmv_destroy_obj(struct obd_export *exp, struct ll_fid *fid);

int lmv_intent_lock(struct obd_export *, struct ll_uctxt *,
                    struct ll_fid *, const char *, int, void *, int,
		    struct ll_fid *, struct lookup_intent *, int,
		    struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_lookup(struct obd_export *, struct ll_uctxt *,
                      struct ll_fid *, const char *, int, void *, int,
		      struct ll_fid *, struct lookup_intent *, int,
		      struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_getattr(struct obd_export *, struct ll_uctxt *,
                       struct ll_fid *, const char *, int, void *, int,
		       struct ll_fid *, struct lookup_intent *, int,
		       struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_intent_open(struct obd_export *, struct ll_uctxt *,
                    struct ll_fid *, const char *, int, void *, int,
		    struct ll_fid *, struct lookup_intent *, int,
		    struct ptlrpc_request **, ldlm_blocking_callback);

int lmv_revalidate_slaves(struct obd_export *, struct ptlrpc_request **,
                          struct ll_fid *, struct lookup_intent *, int,
			  ldlm_blocking_callback cb_blocking);

int lmv_get_mea_and_update_object(struct obd_export *, struct ll_fid *);

int lmv_dirobj_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
			    void *, int);

static inline struct mea * 
is_body_of_splitted_dir(struct ptlrpc_request *req, int offset)
{
	struct mds_body *body;
	struct mea *mea;

	LASSERT(req);

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));

	if (!body || !S_ISDIR(body->mode) || !body->eadatasize)
		return NULL;

        mea = lustre_msg_buf(req->rq_repmsg, offset + 1, body->eadatasize);
	LASSERT(mea);

	if (mea->mea_count == 0)
		return NULL;
	
	return mea;
}

static inline int fid_equal(struct ll_fid *fid1, struct ll_fid *fid2)
{
        if (fid1->mds != fid2->mds)
                return 0;
        if (fid1->id != fid2->id)
                return 0;
        if (fid1->generation != fid2->generation)
                return 0;
        return 1;
}

#endif

