/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2003 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef _FILTER_INTERNAL_H
#define _FILTER_INTERNAL_H

#ifdef __KERNEL__
# include <linux/spinlock.h>
#endif
#include <linux/lustre_handles.h>
#include <linux/obd.h>

#define FILTER_LAYOUT_VERSION "2"

#ifndef OBD_FILTER_DEVICENAME
# define OBD_FILTER_DEVICENAME "obdfilter"
#endif

#ifndef OBD_FILTER_SAN_DEVICENAME
# define OBD_FILTER_SAN_DEVICENAME "sanobdfilter"
#endif

#define LAST_RCVD "last_rcvd"
#define FILTER_INIT_OBJID 0

#define FILTER_LR_SERVER_SIZE    512

#define FILTER_LR_CLIENT_START   8192
#define FILTER_LR_CLIENT_SIZE    128

/* This limit is arbitrary, but for now we fit it in 1 page (32k clients) */
#define FILTER_LR_MAX_CLIENTS (PAGE_SIZE * 8)
#define FILTER_LR_MAX_CLIENT_WORDS (FILTER_LR_MAX_CLIENTS/sizeof(unsigned long))

#define FILTER_SUBDIR_COUNT      32            /* set to zero for no subdirs */
#define FILTER_GROUPS 2 /* must be at least 2; not dynamic yet */

#define FILTER_MOUNT_RECOV 2
#define FILTER_RECOVERY_TIMEOUT (obd_timeout * 5 * HZ / 2) /* *waves hands* */

/* Data stored per server at the head of the last_rcvd file.  In le32 order. */
struct filter_server_data {
        __u8  fsd_uuid[37];        /* server UUID */
        __u8  fsd_uuid_padding[3]; /* unused */
        __u64 fsd_unused;
        __u64 fsd_last_transno;    /* last completed transaction ID */
        __u64 fsd_mount_count;     /* FILTER incarnation number */
        __u32 fsd_feature_compat;  /* compatible feature flags */
        __u32 fsd_feature_rocompat;/* read-only compatible feature flags */
        __u32 fsd_feature_incompat;/* incompatible feature flags */
        __u32 fsd_server_size;     /* size of server data area */
        __u32 fsd_client_start;    /* start of per-client data area */
        __u16 fsd_client_size;     /* size of per-client data area */
        __u16 fsd_subdir_count;    /* number of subdirectories for objects */
        __u64 fsd_catalog_oid;     /* recovery catalog object id */
        __u32 fsd_catalog_ogen;    /* recovery catalog inode generation */
        __u8  fsd_peeruuid[37];    /* UUID of MDS associated with this OST */
        __u8  peer_padding[3];     /* unused */
        __u8  fsd_padding[FILTER_LR_SERVER_SIZE - 140];
};

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct filter_client_data {
        __u8  fcd_uuid[37];        /* client UUID */
        __u8  fcd_uuid_padding[3]; /* unused */
        __u64 fcd_last_rcvd;       /* last completed transaction ID */
        __u64 fcd_mount_count;     /* FILTER incarnation number */
        __u64 fcd_last_xid;        /* client RPC xid for the last transaction */
        __u8  fcd_padding[FILTER_LR_CLIENT_SIZE - 64];
};

#define FILTER_DENTRY_MAGIC 0x9efba101
#define FILTER_FLAG_DESTROY 0x0001      /* destroy dentry on last file close */

/* Limit the returned fields marked valid to those that we actually might set */
#define FILTER_VALID_FLAGS (OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLGENER  |\
                            OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ|\
                            OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME)

enum {
        LPROC_FILTER_READ_BYTES = 0,
        LPROC_FILTER_WRITE_BYTES = 1,
        LPROC_FILTER_LAST,
};

/* filter.c */
struct dentry *filter_parent(struct obd_device *, obd_gr group, obd_id objid);
struct dentry *filter_parent_lock(struct obd_device *, obd_gr, obd_id,
                                  ldlm_mode_t, struct lustre_handle *);
void f_dput(struct dentry *);
struct dentry *filter_fid2dentry(struct obd_device *, struct dentry *dir,
                                 obd_gr group, obd_id id);
struct dentry *__filter_oa2dentry(struct obd_device *obd, struct obdo *oa,
                                  const char *what);
#define filter_oa2dentry(obd, oa) __filter_oa2dentry(obd, oa, __FUNCTION__)

int filter_finish_transno(struct obd_export *, struct obd_trans_info *, int rc);
__u64 filter_next_id(struct filter_obd *, struct obdo *);
int filter_update_server_data(struct obd_device *, struct file *,
                              struct filter_server_data *, int force_sync);
int filter_update_last_objid(struct obd_device *, obd_gr, int force_sync);
int filter_common_setup(struct obd_device *, obd_count len, void *buf,
                        char *option);

/* filter_io.c */
int filter_preprw(int cmd, struct obd_export *, struct obdo *, int objcount,
                  struct obd_ioobj *, int niocount, struct niobuf_remote *,
                  struct niobuf_local *, struct obd_trans_info *);
int filter_commitrw(int cmd, struct obd_export *, struct obdo *, int objcount,
                    struct obd_ioobj *, int niocount, struct niobuf_local *,
                    struct obd_trans_info *);
int filter_brw(int cmd, struct obd_export *, struct obdo *,
	       struct lov_stripe_md *, obd_count oa_bufs, struct brw_page *,
	       struct obd_trans_info *);
void flip_into_page_cache(struct inode *inode, struct page *new_page);

/* filter_io_*.c */
int filter_commitrw_write(struct obd_export *exp, int objcount,
                          struct obd_ioobj *obj, int niocount,
                          struct niobuf_local *res,
                          struct obd_trans_info *oti);

/* filter_log.c */
int filter_log_cancel(struct obd_export *, struct lov_stripe_md *,
                      int num_cookies, struct llog_cookie *, int flags);
int filter_log_op_create(struct llog_handle *cathandle, struct ll_fid *mds_fid,
                         obd_id oid, obd_count ogen, struct llog_cookie *);
int filter_log_op_orphan(struct llog_handle *cathandle, obd_id oid,
                         obd_count ogen, struct llog_cookie *);
struct llog_handle *filter_get_catalog(struct obd_device *);
void filter_put_catalog(struct llog_handle *cathandle);

/* filter_san.c */
int filter_san_setup(struct obd_device *obd, obd_count len, void *buf);
int filter_san_preprw(int cmd, struct obd_export *, struct obdo *, int objcount,
                      struct obd_ioobj *, int niocount, struct niobuf_remote *);


#endif
