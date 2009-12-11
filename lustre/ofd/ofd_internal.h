/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _FILTER_INTERNAL_H
#define _FILTER_INTERNAL_H

#ifdef __KERNEL__
# include <linux/spinlock.h>
#endif
#include <lustre/lustre_idl.h>
#include <lustre_disk.h>
#include <lustre_handles.h>
#include <obd.h>
#include <lustre_debug.h>
#include <obd_cksum.h>
#include <lprocfs_status.h>
#include <lustre_fsfilt.h>


#define FILTER_GROUPS_FILE "groups"

#define FILTER_LAYOUT_VERSION "2"

#define FILTER_INIT_OBJID 0

#define FILTER_SUBDIR_COUNT 32 /* set to zero for no subdirs */

#define FILTER_ROCOMPAT_SUPP (0)

#define FILTER_INCOMPAT_SUPP (OBD_INCOMPAT_GROUPS | OBD_INCOMPAT_OST | \
                              OBD_INCOMPAT_COMMON_LR)

#define FILTER_GRANT_CHUNK (2ULL * PTLRPC_MAX_BRW_SIZE)
#define FILTER_GRANT_SHRINK_LIMIT (16ULL * FILTER_GRANT_CHUNK)
#define GRANT_FOR_LLOG      16

#define FILTER_RECOVERY_TIMEOUT (obd_timeout * 5 * HZ / 2) /* *waves hands* */

extern struct file_operations filter_per_export_stats_fops;

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct filter_client_data {
        __u8  fcd_uuid[40];        /* client UUID */
        __u64 fcd_last_rcvd;       /* last completed transaction ID */
        __u64 fcd_last_xid;        /* client RPC xid for the last transaction */
        __u32 fcd_group;           /* mds group */
        __u8  fcd_padding[LR_CLIENT_SIZE - 60];
};

/* Limit the returned fields marked valid to those that we actually might set */
#define FILTER_VALID_FLAGS (LA_TYPE | LA_MODE | LA_SIZE | LA_BLOCKS | \
                            LA_BLKSIZE | LA_ATIME | LA_MTIME | LA_CTIME)

/* per-client-per-object persistent state (LRU) */
struct filter_mod_data {
        struct list_head fmd_list;      /* linked to fed_mod_list */
        struct lu_fid    fmd_fid;       /* FID being written to */
        __u64            fmd_mactime_xid;/* xid highest {m,a,c}time setattr */
        cfs_time_t       fmd_expire;    /* time when the fmd should expire */
        int              fmd_refcount;  /* reference counter - list holds 1 */
};

#ifdef BGL_SUPPORT
#define FILTER_FMD_MAX_NUM_DEFAULT 128 /* many active files per client on BGL */
#else
#define FILTER_FMD_MAX_NUM_DEFAULT  32
#endif
#define FILTER_FMD_MAX_AGE_DEFAULT ((obd_timeout + 10) * HZ)

int ofd_fmd_init(void);
void ofd_fmd_exit(void);
struct filter_mod_data *filter_fmd_find(struct obd_export *exp,
                                        struct lu_fid *fid);
struct filter_mod_data *filter_fmd_get(struct obd_export *exp,
                                       struct lu_fid *fid);
void filter_fmd_put(struct obd_export *exp, struct filter_mod_data *fmd);
void filter_fmd_expire(struct obd_export *exp);
void filter_fmd_cleanup(struct obd_export *exp);
#ifdef DO_FMD_DROP
void filter_fmd_drop(struct obd_export *exp, struct lu_fid *fid);
#else
#define filter_fmd_drop(exp, fid)
#endif

enum {
        LPROC_FILTER_READ_BYTES = 0,
        LPROC_FILTER_WRITE_BYTES = 1,
        LPROC_FILTER_LAST,
};

//#define FILTER_MAX_CACHE_SIZE (32 * 1024 * 1024) /* was OBD_OBJECT_EOF */
#define FILTER_MAX_CACHE_SIZE OBD_OBJECT_EOF

#ifdef LPROCFS
void filter_tally(struct obd_export *exp, struct page **pages, int nr_pages,
                  unsigned long *blocks, int blocks_per_page, int wr);
int lproc_filter_attach_seqstat(struct obd_device *dev);
void lprocfs_filter_init_vars(struct lprocfs_static_vars *lvars);
#else
static inline void filter_tally(struct obd_export *exp, struct page **pages,
                                int nr_pages, unsigned long *blocks,
                                int blocks_per_page, int wr) {}
static inline int lproc_filter_attach_seqstat(struct obd_device *dev)
{
        return 0;
}
static inline void lprocfs_filter_init_vars(struct lprocfs_static_vars *lvars)
{
        memset(lvars, 0, sizeof(*lvars));
}
#endif

/* Quota stuff */
extern quota_interface_t *filter_quota_interface_ref;

/* Capability */

void blacklist_add(uid_t uid);
void blacklist_del(uid_t uid);
int blacklist_display(char *buf, int bufsize);

#define FILTER_MAX_GROUPS       256

struct filter_device {
        struct dt_device         ofd_dt_dev;
        struct dt_device        *ofd_osd;
        struct dt_device_param   ofd_dt_conf;
        /* DLM name-space for meta-data locks maintained by this server */
        struct ldlm_namespace   *ofd_namespace;
        /* ptlrpc handle for OST->client connections (for lock ASTs). */
        struct ptlrpc_client    *ofd_ldlm_client;

        /* transaction callbacks */
        struct dt_txn_callback   ofd_txn_cb;
        spinlock_t               ofd_transno_lock;
        __u64                    ofd_last_transno;

        /* last_rcvd file */
        struct lu_target         ofd_lut;
        struct dt_object        *ofd_last_group_file;
        unsigned long           *ofd_last_rcvd_slots;

        int                      ofd_subdir_count;

        struct list_head         ofd_llog_list;
        spinlock_t               ofd_llog_list_lock;
        void                    *ofd_lcm;

        /* XXX: make the following dynamic */
        int                      ofd_max_group;
        obd_id                   ofd_last_objids[FILTER_MAX_GROUPS];
        struct semaphore         ofd_create_locks[FILTER_MAX_GROUPS];
        struct dt_object        *ofd_lastid_obj[FILTER_MAX_GROUPS];
        spinlock_t               ofd_objid_lock;
        unsigned long            ofd_destroys_in_progress;

        /* grants: all values in bytes */
        spinlock_t               ofd_grant_lock;
        obd_size                 ofd_tot_dirty;
        obd_size                 ofd_tot_granted;
        obd_size                 ofd_tot_pending;
        int                      ofd_tot_granted_clients;
        struct semaphore         ofd_grant_sem;

        /* filter mod data: filter_device wide values */
        int                      ofd_fmd_max_num; /* per ofd filter_mod_data */
        cfs_duration_t           ofd_fmd_max_age; /* time to fmd expiry */

        /* sptlrpc stuff */
        rwlock_t                 ofd_sptlrpc_lock;
        struct sptlrpc_rule_set  ofd_sptlrpc_rset;

        /* capability related */
        unsigned int             ofd_fl_oss_capa;
        struct list_head         ofd_capa_keys;
        struct hlist_head       *ofd_capa_hash;
};

#define ofd_last_rcvd ofd_lut.lut_last_rcvd
#define ofd_fsd       ofd_lut.lut_lsd

static inline struct filter_device *filter_dev(struct lu_device *d)
{
        return container_of0(d, struct filter_device, ofd_dt_dev.dd_lu_dev);
}

static inline struct obd_device *filter_obd(struct filter_device *ofd)
{
        return ofd->ofd_dt_dev.dd_lu_dev.ld_obd;
}

static inline struct filter_device *filter_exp(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        return filter_dev(obd->obd_lu_dev);
}

struct filter_object {
        struct lu_object_header ofo_header;
        struct dt_object        ofo_obj;
};

static inline struct filter_object *filter_obj(struct lu_object *o)
{
        return container_of0(o, struct filter_object, ofo_obj.do_lu);
}

static inline int filter_object_exists(struct filter_object *obj)
{
        LASSERT(obj != NULL);
        return lu_object_exists(&obj->ofo_obj.do_lu);
}

static inline struct dt_object * fo2dt(struct filter_object *obj)
{
        return &obj->ofo_obj;
}

static inline struct dt_object *filter_object_child(struct filter_object *_obj)
{
        struct lu_object *lu = &(_obj)->ofo_obj.do_lu;
        return container_of0(lu_object_next(lu), struct dt_object, do_lu);
}

static inline
struct filter_device *filter_obj2dev(const struct filter_object *fo)
{
        return filter_dev(fo->ofo_obj.do_lu.lo_dev);
}

static inline
struct lustre_capa *filter_object_capa(const struct lu_env *env,
                                       const struct filter_object *obj)
{
        /* TODO: see mdd_object_capa() */
        return BYPASS_CAPA;
}

static inline void filter_write_lock(const struct lu_env *env,
                                     struct filter_object *fo, int role)
{
        struct dt_object  *next = filter_object_child(fo);
        next->do_ops->do_write_lock(env, next, role);
}

static inline void filter_write_unlock(const struct lu_env *env,
                                       struct filter_object *fo)
{
        struct dt_object  *next = filter_object_child(fo);
        next->do_ops->do_write_unlock(env, next);
}

/*
 * Common data shared by obdfilter-level handlers. This is allocated per-thread
 * to reduce stack consumption.
 */
struct filter_thread_info {
        const struct lu_env       *fti_env;

        /* request related data */
        struct obd_export         *fti_exp;
        __u64                      fti_xid;
        __u64                      fti_transno;
        __u32                      fti_has_trans:1, /* has txn already? */
                                   fti_no_need_trans:1;

        struct lu_fid              fti_fid;
        struct lu_attr             fti_attr;
        struct ldlm_res_id         fti_resid;

        union {
                char               ns_name[48];   /* for obdfilter_init0()     */
                struct lustre_cfg_bufs bufs;      /* for obdfilter_stack_fini()*/
                struct kstatfs     ksfs;          /* for obdfilter_statfs()    */
        } fti_u;

        /* server and client data buffers */
        struct lr_server_data      fti_fsd;
        struct lsd_client_data     fti_fcd;

        /* Ops object filename */
        struct lu_name             fti_name;
};

extern struct lu_context_key filter_txn_thread_key;
extern struct lu_context_key filter_thread_key;

static inline struct filter_thread_info * filter_info(const struct lu_env *env)
{
        struct filter_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &filter_thread_key);
        LASSERT(info);
        LASSERT(info->fti_env);
        LASSERT(info->fti_env == env);
        return info;
}

static inline
struct filter_thread_info * filter_info_init(const struct lu_env *env,
                                             struct obd_export *exp)
{
        struct filter_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &filter_thread_key);
        LASSERT(info);
#if 0
        LASSERT(info->fti_exp == 0);
        LASSERT(info->fti_env == 0);
        LASSERT(info->fti_attr.la_valid == 0);
#endif

        info->fti_env = env;
        info->fti_exp = exp;
        return info;
}

typedef void (*filter_cb_t)(const struct filter_device *mdt, __u64 transno,
                         void *data, int err);
struct filter_commit_cb {
        filter_cb_t  filter_cb_func;
        void     *filter_cb_data;
};

/*
 * Info allocated per-transaction.
 */
#define OFD_MAX_COMMIT_CB       4
struct filter_txn_info {
        __u64                 txi_transno;
        unsigned int          txi_cb_count;
        struct filter_commit_cb  txi_cb[OFD_MAX_COMMIT_CB];
};

static inline void filter_trans_add_cb(const struct thandle *th,
                                       filter_cb_t cb_func, void *cb_data)
{
        struct filter_txn_info *txi;

        txi = lu_context_key_get(&th->th_ctx, &filter_txn_thread_key);
        LASSERT(txi->txi_cb_count < ARRAY_SIZE(txi->txi_cb));

        /* add new callback */
        txi->txi_cb[txi->txi_cb_count].filter_cb_func = cb_func;
        txi->txi_cb[txi->txi_cb_count].filter_cb_data = cb_data;
        txi->txi_cb_count++;
}


extern void target_recovery_fini(struct obd_device *obd);
extern void target_recovery_init(struct lu_target *lut,
                                 svc_handler_t handler);

static inline int filter_export_stats_init(struct filter_device *ofd,
                                           struct obd_export *exp, void *data)
{
        return 0;
}

/* filter_capa.c */
int filter_update_capa_key(struct filter_device *, struct lustre_capa_key *);
int filter_auth_capa(struct filter_device *, struct lu_fid *, __u64,
                     struct lustre_capa *, __u64);
void filter_free_capa_keys(struct filter_device *ofd);

/* filter_obd.c */
int filter_setattr(struct obd_export *exp,
                   struct obd_info *oinfo, struct obd_trans_info *oti);
int filter_destroy(struct obd_export *exp,
                   struct obdo *oa, struct lov_stripe_md *md,
                   struct obd_trans_info *oti, struct obd_export *md_exp,
                   void *capa);

/* filter_lvb.c */
extern struct ldlm_valblock_ops filter_lvbo;


/* filter_io.c */
int filter_preprw(int cmd, struct obd_export *exp,
                  struct obdo *oa, int objcount, struct obd_ioobj *obj,
                  struct niobuf_remote *nb, int *nr_local, struct niobuf_local *res,
                  struct obd_trans_info *oti, struct lustre_capa *capa);
int filter_commitrw(int cmd, struct obd_export *exp,
                    struct obdo *oa, int objcount, struct obd_ioobj *obj,
                    struct niobuf_remote *nb, int npages, struct niobuf_local *res,
                    struct obd_trans_info *oti, int rc);
int filter_brw(int cmd, struct obd_export *, struct obd_info *oinfo,
               obd_count oa_bufs, struct brw_page *pga, struct obd_trans_info *);
void flip_into_page_cache(struct inode *inode, struct page *new_page);

/* filter_io_*.c */
struct filter_iobuf;
struct filter_iobuf *filter_alloc_iobuf(struct filter_obd *, int rw,
                                        int num_pages);
void filter_free_iobuf(struct filter_iobuf *iobuf);
int filter_iobuf_add_page(struct obd_device *obd, struct filter_iobuf *iobuf,
                          struct inode *inode, struct page *page);
void *filter_iobuf_get(struct filter_obd *filter, struct obd_trans_info *oti);
void filter_iobuf_put(struct filter_obd *filter, struct filter_iobuf *iobuf,
                      struct obd_trans_info *oti);
int filter_direct_io(int rw, struct dentry *dchild, struct filter_iobuf *iobuf,
                     struct obd_export *exp, struct iattr *attr,
                     struct obd_trans_info *oti, void **wait_handle);
int filter_clear_truncated_page(struct inode *inode);

/* filter_log.c */

struct ost_filterdata {
        __u32  ofd_epoch;
};
int filter_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                     struct obd_device *tgt, int *idx);
int filter_llog_finish(struct obd_device *obd, int count);
int filter_log_sz_change(struct llog_handle *cathandle,
                         struct ll_fid *mds_fid,
                         __u32 ioepoch,
                         struct llog_cookie *logcookie,
                         struct inode *inode);
void filter_cancel_cookies_cb(struct obd_device *obd, __u64 transno,
                              void *cb_data, int error);
int filter_recov_log_mds_ost_cb(struct llog_handle *llh,
                                struct llog_rec_hdr *rec, void *data);
struct obd_llog_group *filter_find_create_olg(struct obd_device *obd, int group);
struct obd_llog_group *filter_find_olg(struct obd_device *obd, int group);

extern struct ldlm_valblock_ops filter_lvbo;

/* filter_recovery.c */
struct thandle *filter_trans_create0(const struct lu_env *env,
                                     struct filter_device *ofd);
struct thandle *filter_trans_create(const struct lu_env *env,
                                    struct filter_device *ofd);
int filter_trans_start(const struct lu_env *env,
                       struct filter_device *ofd, struct thandle *th);
void filter_trans_stop(const struct lu_env *env,
                       struct filter_device *ofd, struct thandle *th);
int filter_client_free(struct lu_env *env, struct obd_export *exp);
int filter_client_new(const struct lu_env *env, struct filter_device *ofd,
                      struct filter_export_data *fed);
int filter_client_add(const struct lu_env *env, struct filter_device *ofd,
                      struct filter_export_data *fed, int cl_idx);
int filter_fs_setup(const struct lu_env *env, struct filter_device *ofd,
                    struct obd_device *obd);
void filter_fs_cleanup(const struct lu_env *env, struct filter_device *ofd);

/* filter_fs.c */
obd_id filter_last_id(struct filter_device *ofd, obd_gr group);
void filter_last_id_set(struct filter_device *ofd, obd_id id, obd_gr group);
int filter_last_id_write(const struct lu_env *env, struct filter_device *ofd,
                         obd_gr group, struct thandle *th);
int filter_last_id_read(const struct lu_env *env, struct filter_device *ofd,
                        obd_gr group);
int filter_groups_init(const struct lu_env *env, struct filter_device *ofd);
int filter_last_rcvd_header_write(const struct lu_env *env,
                                  struct filter_device *ofd,
                                  struct thandle *th);
int filter_last_rcvd_write(const struct lu_env *env,
                           struct filter_device *ofd,
                           struct lsd_client_data *lcd,
                           loff_t *off, struct thandle *th);
int filter_server_data_init(const struct lu_env *env,
                            struct filter_device *ofd);
int filter_server_data_update(const struct lu_env *env,
                              struct filter_device *ofd);
int filter_group_load(const struct lu_env *env,
                      struct filter_device *ofd, int group);
int filter_last_group_write(const struct lu_env *env, struct filter_device *ofd);

/* filter_objects.c */
struct filter_object *filter_object_find(const struct lu_env *env,
                                         struct filter_device *ofd,
                                         const struct lu_fid *fid);
struct
filter_object *filter_object_find_or_create(const struct lu_env *env,
                                            struct filter_device *ofd,
                                            const struct lu_fid *fid,
                                            struct lu_attr *attr);
int filter_precreate_object(const struct lu_env *env, struct filter_device *ofd,
                            obd_id id, obd_gr group);

void filter_object_put(const struct lu_env *env, struct filter_object *fo);
int filter_attr_set(const struct lu_env *env, struct filter_object *fo,
                    const struct lu_attr *la);
int filter_object_punch(const struct lu_env *env, struct filter_object *fo,
                         __u64 start, __u64 end, struct obdo *oa);
int filter_object_destroy(const struct lu_env *env, struct filter_object *fo);
int filter_attr_get(const struct lu_env *env, struct filter_object *fo,
                    struct lu_attr *la);

/* filter_grants.c */
void filter_grant_discard(struct obd_export *exp);
void filter_grant_sanity_check(struct obd_device *obd, const char *func);
void filter_grant_incoming(const struct lu_env *env, struct obd_export *exp,
                           struct obdo *oa);
obd_size filter_grant_space_left(const struct lu_env *env,
                                 struct obd_export *exp);
int filter_grant_client_calc(struct obd_export *exp, obd_size *left,
                             unsigned long *used, unsigned long *ungranted);
int filter_grant_check(const struct lu_env *env, struct obd_export *exp, 
                       struct obdo *oa, struct niobuf_local *lnb, int nrpages,
                       obd_size *left, unsigned long *used, unsigned long *ungranted);
long filter_grant(const struct lu_env *env, struct obd_export *exp,
                  obd_size current_grant, obd_size want,
                  obd_size fs_space_left);
void filter_grant_commit(struct obd_export *exp, int niocount,
                         struct niobuf_local *res);

/* IDIF stuff */
#include <lustre_fid.h>
static inline void lu_idif_build(struct lu_fid *fid, obd_id id, obd_gr gr)
{
        LASSERT((id >> 48) == 0);
        fid->f_seq = (IDIF_SEQ_START| id >> 32);
        fid->f_oid = (__u32)(id & 0xffffffff);
        fid->f_ver = gr;
}

static inline obd_id lu_idif_id(const struct lu_fid *fid)
{
        return ((fid->f_seq & 0xffff) << 32) | fid->f_oid;
}

static inline obd_gr lu_idif_gr(const struct lu_fid * fid)
{
        return fid->f_ver;
}

static inline struct ldlm_res_id * lu_idif_resid(const struct lu_fid *fid,
                                                 struct ldlm_res_id *name)
{
        name->name[LUSTRE_RES_ID_SEQ_OFF] = lu_idif_id(fid);
        name->name[LUSTRE_RES_ID_OID_OFF] = 0;
        name->name[LUSTRE_RES_ID_VER_OFF] = lu_idif_gr(fid);
        name->name[LUSTRE_RES_ID_HSH_OFF] = 0;
        return name;
}

static inline void lu_idif_from_resid(struct lu_fid *fid,
                                      const struct ldlm_res_id *name)
{
        lu_idif_build(fid, name->name[LUSTRE_RES_ID_SEQ_OFF],
                      name->name[LUSTRE_RES_ID_VER_OFF]);
}

#endif /* _FILTER_INTERNAL_H */
