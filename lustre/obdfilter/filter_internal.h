/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _FILTER_INTERNAL_H
#define _FILTER_INTERNAL_H

#ifdef __KERNEL__
# include <linux/spinlock.h>
#endif
#include <lustre_disk.h>
#include <lustre_handles.h>
#include <lustre_debug.h>
#include <obd.h>
#include <lprocfs_status.h>

#define FILTER_LAYOUT_VERSION "2"

#define FILTER_INIT_OBJID 0

#define FILTER_SUBDIR_COUNT 32 /* set to zero for no subdirs */
#define FILTER_GROUPS        3 /* must be at least 3; not dynamic yet */

#define FILTER_ROCOMPAT_SUPP (0)

#define FILTER_INCOMPAT_SUPP (OBD_INCOMPAT_GROUPS | OBD_INCOMPAT_OST | \
                              OBD_INCOMPAT_COMMON_LR)

#define FILTER_GRANT_CHUNK (2ULL * PTLRPC_MAX_BRW_SIZE)
#define GRANT_FOR_LLOG(obd) 16

#define FILTER_RECOVERY_TIMEOUT (obd_timeout * 5 * HZ / 2) /* *waves hands* */

extern struct file_operations filter_per_export_stats_fops;
extern struct file_operations filter_per_nid_stats_fops;

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct filter_client_data {
        __u8  fcd_uuid[40];        /* client UUID */
        __u64 fcd_last_rcvd;       /* last completed transaction ID */
        __u64 fcd_last_xid;        /* client RPC xid for the last transaction */
        __u32 fcd_group;           /* mds group */
        __u8  fcd_padding[LR_CLIENT_SIZE - 60];
};

/* Limit the returned fields marked valid to those that we actually might set */
#define FILTER_VALID_FLAGS (OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLGENER  |\
                            OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ|\
                            OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME)

struct filter_fid {
        struct ll_fid   ff_fid;         /* ff_fid.f_type == file stripe number */
        __u64           ff_objid;
        __u64           ff_group;
};

/* per-client-per-object persistent state (LRU) */
struct filter_mod_data {
        struct list_head fmd_list;      /* linked to fed_mod_list */
        __u64            fmd_id;        /* object being written to */
        __u64            fmd_gr;        /* group being written to */
        __u64            fmd_mactime_xid;/* xid highest {m,a,c}time setattr */
        unsigned long    fmd_expire;    /* jiffies when it should expire */
        int              fmd_refcount;  /* reference counter - list holds 1 */
};

#ifdef BGL_SUPPORT
#define FILTER_FMD_MAX_NUM_DEFAULT 128 /* many active files per client on BGL */
#else
#define FILTER_FMD_MAX_NUM_DEFAULT  32
#endif
#define FILTER_FMD_MAX_AGE_DEFAULT ((obd_timeout + 10) * HZ)

struct filter_mod_data *filter_fmd_find(struct obd_export *exp,
                                        obd_id objid, obd_gr group);
struct filter_mod_data *filter_fmd_get(struct obd_export *exp,
                                       obd_id objid, obd_gr group);
void filter_fmd_put(struct obd_export *exp, struct filter_mod_data *fmd);
void filter_fmd_expire(struct obd_export *exp);

enum {
        LPROC_FILTER_READ_BYTES = 0,
        LPROC_FILTER_WRITE_BYTES = 1,
        LPROC_FILTER_LAST,
};

//#define FILTER_MAX_CACHE_SIZE (32 * 1024 * 1024) /* was OBD_OBJECT_EOF */
#define FILTER_MAX_CACHE_SIZE OBD_OBJECT_EOF

/* We have to pass a 'created' array to fsfilt_map_inode_pages() which we
 * then ignore.  So we pre-allocate one that everyone can use... */
#define OBDFILTER_CREATED_SCRATCHPAD_ENTRIES 1024
extern int *obdfilter_created_scratchpad;

extern void target_recovery_fini(struct obd_device *obd);
extern void target_recovery_init(struct obd_device *obd,
                                 svc_handler_t handler);

/* filter.c */
void f_dput(struct dentry *);
struct dentry *filter_fid2dentry(struct obd_device *, struct dentry *dir,
                                 obd_gr group, obd_id id);
struct dentry *__filter_oa2dentry(struct obd_device *obd, struct obdo *oa,
                                  const char *what, int quiet);
#define filter_oa2dentry(obd, oa) __filter_oa2dentry(obd, oa, __FUNCTION__, 0)

int filter_finish_transno(struct obd_export *, struct obd_trans_info *, int rc,
                          int force_sync);
__u64 filter_next_id(struct filter_obd *, struct obdo *);
__u64 filter_last_id(struct filter_obd *, obd_gr group);
int filter_update_fidea(struct obd_export *exp, struct inode *inode,
                        void *handle, struct obdo *oa);
int filter_update_server_data(struct obd_device *, struct file *,
                              struct lr_server_data *, int force_sync);
int filter_update_last_objid(struct obd_device *, obd_gr, int force_sync);
int filter_common_setup(struct obd_device *, struct lustre_cfg *lcfg,
                        void *option);
int filter_destroy(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md *md, struct obd_trans_info *,
                   struct obd_export *);
int filter_setattr_internal(struct obd_export *exp, struct dentry *dentry,
                            struct obdo *oa, struct obd_trans_info *oti);
int filter_setattr(struct obd_export *exp, struct obd_info *oinfo,
                   struct obd_trans_info *oti);

struct dentry *filter_create_object(struct obd_device *obd, struct obdo *oa);

struct obd_llog_group *filter_find_olg(struct obd_device *obd, int group);

/* filter_lvb.c */
extern struct ldlm_valblock_ops filter_lvbo;


/* filter_io.c */
int filter_preprw(int cmd, struct obd_export *, struct obdo *, int objcount,
                  struct obd_ioobj *, int niocount, struct niobuf_remote *,
                  struct niobuf_local *, struct obd_trans_info *,
                  struct lustre_capa *);
int filter_commitrw(int cmd, struct obd_export *, struct obdo *, int objcount,
                    struct obd_ioobj *, int niocount, struct niobuf_local *,
                    struct obd_trans_info *, int rc);
int filter_brw(int cmd, struct obd_export *, struct obd_info *oinfo,
               obd_count oa_bufs, struct brw_page *pga, struct obd_trans_info *);
void flip_into_page_cache(struct inode *inode, struct page *new_page);

/* filter_io_*.c */
struct filter_iobuf;
int filter_commitrw_write(struct obd_export *exp, struct obdo *oa, int objcount,
                          struct obd_ioobj *obj, int niocount,
                          struct niobuf_local *res, struct obd_trans_info *oti,
                          int rc);
obd_size filter_grant_space_left(struct obd_export *exp);
long filter_grant(struct obd_export *exp, obd_size current_grant,
                  obd_size want, obd_size fs_space_left);
void filter_grant_commit(struct obd_export *exp, int niocount,
                         struct niobuf_local *res);
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
int filter_log_sz_change(struct llog_handle *cathandle,
                         struct ll_fid *mds_fid,
                         __u32 ioepoch,
                         struct llog_cookie *logcookie,
                         struct inode *inode);
//int filter_get_catalog(struct obd_device *);
void filter_cancel_cookies_cb(struct obd_device *obd, __u64 transno,
                              void *cb_data, int error);
int filter_recov_log_mds_ost_cb(struct llog_handle *llh,
                               struct llog_rec_hdr *rec, void *data);

#ifdef LPROCFS
void filter_tally(struct obd_export *exp, struct page **pages, int nr_pages,
                  unsigned long *blocks, int blocks_per_page, int wr);
int lproc_filter_attach_seqstat(struct obd_device *dev);
void lprocfs_filter_init_vars(struct lprocfs_static_vars *lvars);
#else
static inline void filter_tally(struct obd_export *exp, struct page **pages,
                                int nr_pages, unsigned long *blocks,
                                int blocks_per_page, int wr) {}
static inline int lproc_filter_attach_seqstat(struct obd_device *dev) {}
static void lprocfs_filter_init_vars(struct lprocfs_static_vars *lvars)
{
        memset(lvars, 0, sizeof(*lvars));
}
#endif

/* Quota stuff */
extern quota_interface_t *filter_quota_interface_ref;

/* Capability */
static inline __u64 obdo_mdsno(struct obdo *oa)
{
        return oa->o_gr - FILTER_GROUP_MDS0;
}

int filter_update_capa_key(struct obd_device *obd, struct lustre_capa_key *key);
int filter_auth_capa(struct obd_export *exp, struct lu_fid *fid, __u64 mdsid,
                     struct lustre_capa *capa, __u64 opc);
void filter_free_capa_keys(struct filter_obd *filter);

void blacklist_add(uid_t uid);
void blacklist_del(uid_t uid);
int blacklist_display(char *buf, int bufsize);

#endif /* _FILTER_INTERNAL_H */
