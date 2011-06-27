/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _FILTER_INTERNAL_H
#define _FILTER_INTERNAL_H

#ifdef __KERNEL__
# include <linux/spinlock.h>
#endif
#include <lustre_handles.h>
#include <lustre_debug.h>
#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>

#define FILTER_LAYOUT_VERSION "2"

#define FILTER_INIT_OBJID 0

#define FILTER_SUBDIR_COUNT 32 /* set to zero for no subdirs */
#define FILTER_GROUPS        3 /* must be at least 3; not dynamic yet */

#define FILTER_ROCOMPAT_SUPP (0)

#define FILTER_INCOMPAT_SUPP (OBD_INCOMPAT_GROUPS | OBD_INCOMPAT_OST | \
                              OBD_INCOMPAT_COMMON_LR)

#define FILTER_GRANT_CHUNK (2ULL * PTLRPC_MAX_BRW_SIZE)
#define FILTER_GRANT_SHRINK_LIMIT (16ULL * FILTER_GRANT_CHUNK)
#define GRANT_FOR_LLOG(obd) 16

extern struct file_operations filter_per_export_stats_fops;
extern struct file_operations filter_per_nid_stats_fops;

/* Limit the returned fields marked valid to those that we actually might set */
#define FILTER_VALID_FLAGS (OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLGENER  |\
                            OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ|\
                            OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME)

/* per-client-per-object persistent state (LRU) */
struct filter_mod_data {
        cfs_list_t       fmd_list;       /* linked to fed_mod_list */
        __u64            fmd_id;         /* object being written to */
        __u64            fmd_gr;         /* group being written to */
        __u64            fmd_mactime_xid;/* xid highest {m,a,c}time
                                              * setattr */
        unsigned long    fmd_expire;   /* jiffies when it should expire */
        int              fmd_refcount; /* reference counter, list holds 1 */
};

#ifdef HAVE_BGL_SUPPORT
#define FILTER_FMD_MAX_NUM_DEFAULT 128 /* many active files per client on BGL */
#else
#define FILTER_FMD_MAX_NUM_DEFAULT  32
#endif
/* Client cache seconds */
#define FILTER_FMD_MAX_AGE_DEFAULT ((obd_timeout + 10) * CFS_HZ)

#ifndef HAVE_PAGE_CONSTANT
#define mapping_cap_page_constant_write(mapping) 0
#define SetPageConstant(page) do {} while (0)
#define ClearPageConstant(page) do {} while (0)
#endif

struct filter_mod_data *filter_fmd_find(struct obd_export *exp,
                                        obd_id objid, obd_seq seq);
struct filter_mod_data *filter_fmd_get(struct obd_export *exp,
                                       obd_id objid, obd_seq seq);
void filter_fmd_put(struct obd_export *exp, struct filter_mod_data *fmd);
void filter_fmd_expire(struct obd_export *exp);

enum {
        LPROC_FILTER_READ_BYTES = 0,
        LPROC_FILTER_WRITE_BYTES = 1,
        LPROC_FILTER_GET_PAGE = 2,
        LPROC_FILTER_NO_PAGE = 3,
        LPROC_FILTER_CACHE_ACCESS = 4,
        LPROC_FILTER_CACHE_HIT = 5,
        LPROC_FILTER_CACHE_MISS = 6,
        LPROC_FILTER_LAST,
};

//#define FILTER_MAX_CACHE_SIZE (32 * 1024 * 1024) /* was OBD_OBJECT_EOF */
#define FILTER_MAX_CACHE_SIZE OBD_OBJECT_EOF

/* We have to pass a 'created' array to fsfilt_map_inode_pages() which we
 * then ignore.  So we pre-allocate one that everyone can use... */
#define OBDFILTER_CREATED_SCRATCHPAD_ENTRIES 1024
extern int *obdfilter_created_scratchpad;

extern void target_recovery_fini(struct obd_device *obd);
extern void target_recovery_init(struct lu_target *lut,
                                 svc_handler_t handler);

/* filter.c */
void f_dput(struct dentry *);
struct dentry *filter_fid2dentry(struct obd_device *, struct dentry *dir,
                                 obd_seq seq, obd_id id);
struct dentry *__filter_oa2dentry(struct obd_device *obd, struct ost_id *ostid,
                                  const char *what, int quiet);
#define filter_oa2dentry(obd, ostid) __filter_oa2dentry(obd, ostid,     \
                                                        __func__, 0)

int filter_finish_transno(struct obd_export *, struct inode *,
                          struct obd_trans_info *, int rc, int force_sync);
__u64 filter_next_id(struct filter_obd *, struct obdo *);
__u64 filter_last_id(struct filter_obd *, obd_seq seq);
int filter_update_fidea(struct obd_export *exp, struct inode *inode,
                        void *handle, struct obdo *oa);
int filter_update_server_data(struct obd_device *);
int filter_update_last_objid(struct obd_device *, obd_seq, int force_sync);
int filter_common_setup(struct obd_device *, struct lustre_cfg *lcfg,
                        void *option);
int filter_destroy(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md *md, struct obd_trans_info *,
                   struct obd_export *, void *);
int filter_setattr_internal(struct obd_export *exp, struct dentry *dentry,
                            struct obdo *oa, struct obd_trans_info *oti);
int filter_setattr(struct obd_export *exp, struct obd_info *oinfo,
                   struct obd_trans_info *oti);

int filter_create(struct obd_export *exp, struct obdo *oa,
                  struct lov_stripe_md **ea, struct obd_trans_info *oti);

struct obd_llog_group *filter_find_olg(struct obd_device *obd, int seq);

/* filter_lvb.c */
extern struct ldlm_valblock_ops filter_lvbo;


/* filter_io.c */
int filter_preprw(int cmd, struct obd_export *, struct obdo *, int objcount,
                  struct obd_ioobj *, struct niobuf_remote *,
                  int *, struct niobuf_local *, struct obd_trans_info *,
                  struct lustre_capa *);
int filter_commitrw(int cmd, struct obd_export *, struct obdo *, int objcount,
                    struct obd_ioobj *, struct niobuf_remote *,  int,
                    struct niobuf_local *, struct obd_trans_info *, int rc);
int filter_brw(int cmd, struct obd_export *, struct obd_info *oinfo,
               obd_count oa_bufs, struct brw_page *pga, struct obd_trans_info *);
void filter_release_cache(struct obd_device *, struct obd_ioobj *,
                          struct niobuf_remote *, struct inode *);

/* filter_io_*.c */
struct filter_iobuf;
int filter_commitrw_write(struct obd_export *exp, struct obdo *oa, int objcount,
                          struct obd_ioobj *obj, struct niobuf_remote *, int,
                          struct niobuf_local *res, struct obd_trans_info *oti,
                          int rc);
obd_size filter_grant_space_left(struct obd_export *exp);
long filter_grant(struct obd_export *exp, obd_size current_grant,
                  obd_size want, obd_size fs_space_left, int conservative);
void filter_grant_commit(struct obd_export *exp, int niocount,
                         struct niobuf_local *res);
void filter_grant_incoming(struct obd_export *exp, struct obdo *oa);
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

int filter_update_capa_key(struct obd_device *obd, struct lustre_capa_key *key);
int filter_auth_capa(struct obd_export *exp, struct lu_fid *fid, obd_seq seq,
                     struct lustre_capa *capa, __u64 opc);
int filter_capa_fixoa(struct obd_export *exp, struct obdo *oa, obd_seq seq,
                      struct lustre_capa *capa);
void filter_free_capa_keys(struct filter_obd *filter);

void blacklist_add(uid_t uid);
void blacklist_del(uid_t uid);
int blacklist_display(char *buf, int bufsize);

/* sync on lock cancel is useless when we force a journal flush,
 * and if we enable async journal commit, we should also turn on
 * sync on lock cancel if it is not enabled already. */
static inline void filter_slc_set(struct filter_obd *filter)
{
        if (filter->fo_syncjournal == 1)
                filter->fo_sync_lock_cancel = NEVER_SYNC_ON_CANCEL;
        else if (filter->fo_sync_lock_cancel == NEVER_SYNC_ON_CANCEL)
                filter->fo_sync_lock_cancel = ALWAYS_SYNC_ON_CANCEL;
}

#endif /* _FILTER_INTERNAL_H */
