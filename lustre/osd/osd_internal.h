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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_internal.h
 *
 * Shared definitions and declarations for osd module
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H

#if defined(__KERNEL__)

/* struct rw_semaphore */
#include <linux/rwsem.h>
/* handle_t, journal_start(), journal_stop() */
#include <linux/jbd.h>
/* struct dx_hash_info */
#include <linux/ldiskfs_fs.h>
/* struct dentry */
#include <linux/dcache.h>
#include <linux/lustre_iam.h>
/* struct dirent64 */
#include <linux/dirent.h>

/* LUSTRE_OSD_NAME */
#include <obd.h>
/* class_register_type(), class_unregister_type(), class_get_type() */
#include <obd_class.h>
#include <lustre_disk.h>

#include <lustre_fsfilt.h>

#include <dt_object.h>
#include "osd_oi.h"

struct inode;

#define OSD_OII_NOGEN (0)
#define OSD_COUNTERS (0)

#ifdef HAVE_QUOTA_SUPPORT
struct osd_ctxt {
        __u32 oc_uid;
        __u32 oc_gid;
        __u32 oc_cap;
};
#endif

#define OSD_TRACK_DECLARES
#ifdef OSD_TRACK_DECLARES
#define OSD_DECLARE_OP(oh,op)    {                               \
        LASSERT(oh->ot_handle == NULL);                          \
        ((oh)->ot_declare_ ##op)++;}
#define OSD_EXEC_OP(handle,op)      {                            \
        struct osd_thandle *oh;                                  \
        oh = container_of0(handle, struct osd_thandle, ot_super);\
        LASSERT((oh)->ot_declare_ ##op > 0);                     \
        ((oh)->ot_declare_ ##op)--;}
#else
#define OSD_DECLARE_OP(oh,op)
#define OSD_EXEC_OP(oh,op)
#endif

struct osd_thandle {
        struct thandle          ot_super;
        handle_t               *ot_handle;
        struct journal_callback ot_jcb;
        /* Link to the device, for debugging. */
        struct lu_ref_link     *ot_dev_link;
        int                     ot_credits;
        struct osd_object      *ot_alloc_sem_obj;
#ifdef OSD_TRACK_DECLARES
        int                     ot_declare_attr_set;
        int                     ot_declare_punch;
        int                     ot_declare_xattr_set;
        int                     ot_declare_xattr_del;
        int                     ot_declare_create;
        int                     ot_declare_ref_add;
        int                     ot_declare_ref_del;
        int                     ot_declare_write;
        int                     ot_declare_insert;
        int                     ot_declare_delete;
#endif
};

/**
 * Basic transaction credit op
 */
enum dt_txn_op {
        DTO_INDEX_INSERT,
        DTO_INDEX_DELETE,
        DTO_IDNEX_UPDATE,
        DTO_OBJECT_CREATE,
        DTO_OBJECT_DELETE,
        DTO_ATTR_SET_BASE,
        DTO_XATTR_SET,
        DTO_LOG_REC, /**< XXX temporary: dt layer knows nothing about llog. */
        DTO_WRITE_BASE,
        DTO_WRITE_BLOCK,
        DTO_ATTR_SET_CHOWN,

        DTO_NR
};

extern const int osd_dto_credits_noquota[DTO_NR];

struct osd_directory {
        struct iam_container od_container;
        struct iam_descr     od_descr;
};

struct osd_object {
        struct dt_object       oo_dt;
        /**
         * Inode for file system object represented by this osd_object. This
         * inode is pinned for the whole duration of lu_object life.
         *
         * Not modified concurrently (either setup early during object
         * creation, or assigned by osd_object_create() under write lock).
         */
        struct inode          *oo_inode;
        /**
         * to protect index ops.
         */
        struct rw_semaphore    oo_ext_idx_sem;
        struct rw_semaphore    oo_sem;
        struct osd_directory  *oo_dir;
        /** protects inode attributes. */
        spinlock_t             oo_guard;
        /**
         * Following two members are used to indicate the presence of dot and
         * dotdot in the given directory. This is required for interop mode
         * (b11826).
         */
        int oo_compat_dot_created;
        int oo_compat_dotdot_created;

        const struct lu_env   *oo_owner;
#ifdef CONFIG_LOCKDEP
        struct lockdep_map     oo_dep_map;
#endif
};

struct osd_compat_objid;

/*
 * osd device.
 */
struct osd_device {
        /* super-class */
        struct dt_device          od_dt_dev;
        /* information about underlying file system */
        //struct lustre_mount_info *od_mount;
        struct vfsmount          *od_mnt;
        /* object index */
        struct osd_oi             od_oi;
        /*
         * XXX temporary stuff for object index: directory where every object
         * is named by its fid.
         */
        struct dt_object         *od_obj_area;

        /* Environment for transaction commit callback.
         * Currently, OSD is based on ext3/JBD. Transaction commit in ext3/JBD
         * is serialized, that is there is no more than one transaction commit
         * at a time (JBD journal_commit_transaction() is serialized).
         * This means that it's enough to have _one_ lu_context.
         */
        struct lu_env             od_env_for_commit;

        /*
         * Fid Capability
         */
        unsigned int              od_fl_capa:1;
        unsigned long             od_capa_timeout;
        __u32                     od_capa_alg;
        struct lustre_capa_key   *od_capa_keys;
        struct hlist_head        *od_capa_hash;

        cfs_proc_dir_entry_t     *od_proc_entry;
        struct lprocfs_stats     *od_stats;
        /*
         * statfs optimization: we cache a bit.
         */
        cfs_time_t                od_osfs_age;
        struct kstatfs            od_kstatfs;
        spinlock_t                od_osfs_lock;

        /**
         * The following flag indicates, if it is interop mode or not.
         * It will be initialized, using mount param.
         */
        __u32                     od_iop_mode;

        struct fsfilt_operations *od_fsops;

        struct osd_compat_objid  *od_ost_map;
};

struct osd_it_ea_dirent {
        __u64           oied_ino;
        __u64           oied_off;
        unsigned short  oied_namelen;
        char            oied_name[0];
} __attribute__((packed));

#define OSD_IT_EA_BUFSIZE       CFS_PAGE_SIZE

/**
 * This is iterator's in-memory data structure in interoperability
 * mode (i.e. iterator over ldiskfs style directory)
 */
struct osd_it_ea {
        struct osd_object   *oie_obj;
        /** used in ldiskfs iterator, to stored file pointer */
        struct file          oie_file;
        /** current file position */
        __u64                oie_curr_pos;
        /** next file position */
        __u64                oie_next_pos;
        /** how many entries have been read-cached from storage */
        int                  oie_rd_dirent;
        /** current entry is being iterated by caller */
        int                  oie_it_dirent;
        /** current processing entry */
        struct osd_it_ea_dirent *oie_dirent;
        /** buffer to hold entries, size == OSD_IT_EA_BUFSIZE */
        void                *oie_buf;
};

/**
 * Iterator's in-memory data structure for IAM mode.
 */
struct osd_it_iam {
        struct osd_object     *oi_obj;
        struct iam_path_descr *oi_ipd;
        struct iam_iterator    oi_it;
};

#define MAX_BLOCKS_PER_PAGE (CFS_PAGE_SIZE / 512)

struct filter_iobuf {
        atomic_t          dr_numreqs;  /* number of reqs being processed */
        wait_queue_head_t dr_wait;
        int               dr_max_pages;
        int               dr_npages;
        int               dr_error;
        struct page      *dr_pages[PTLRPC_MAX_BRW_PAGES];
        unsigned long     dr_blocks[PTLRPC_MAX_BRW_PAGES*MAX_BLOCKS_PER_PAGE];
        unsigned int      dr_ignore_quota:1;
};

struct osd_thread_info {
        const struct lu_env   *oti_env;
        /**
         * used for index operations.
         */
        struct dentry          oti_obj_dentry;
        struct dentry          oti_child_dentry;

        /** dentry for Iterator context. */
        struct dentry          oti_it_dentry;

        struct lu_fid          oti_fid;
        struct osd_inode_id    oti_id;
        /*
         * XXX temporary: for ->i_op calls.
         */
        struct timespec        oti_time;
        struct timespec        oti_time2;
        /*
         * XXX temporary: fake struct file for osd_object_sync
         */
        struct file            oti_file;
        /*
         * XXX temporary: for capa operations.
         */
        struct lustre_capa_key oti_capa_key;
        struct lustre_capa     oti_capa;

        struct lu_fid_pack     oti_pack;

        /**
         * following ipd and it structures are used for osd_index_iam_lookup()
         * these are defined separately as we might do index operation
         * in open iterator session.
         */

        /** osd iterator context used for iterator session */

        union {
                struct osd_it_iam      oti_it;
                /** ldiskfs iterator data structure, see osd_it_ea_{init, fini} */
                struct osd_it_ea       oti_it_ea;
        };

        /** pre-allocated buffer used by oti_it_ea, size OSD_IT_EA_BUFSIZE */
        void                  *oti_it_ea_buf;

        /** IAM iterator for index operation. */
        struct iam_iterator    oti_idx_it;

        /** union to guarantee that ->oti_ipd[] has proper alignment. */
        union {
                char           oti_it_ipd[DX_IPD_MAX_SIZE];
                long long      oti_alignment_lieutenant;
        };

        union {
                char           oti_idx_ipd[DX_IPD_MAX_SIZE];
                long long      oti_alignment_lieutenant_colonel;
        };


        int                    oti_r_locks;
        int                    oti_w_locks;
        int                    oti_txns;
        /** used in osd_fid_set() to put xattr */
        struct lu_buf          oti_buf;
        /** used in osd_ea_fid_set() to set fid into common ea */
        struct lustre_mdt_attrs oti_mdt_attrs;
#ifdef HAVE_QUOTA_SUPPORT
        struct osd_ctxt        oti_ctxt;
#endif

        /** 0-copy IO */
        struct filter_iobuf    oti_iobuf;

        /** used by compat stuff */
        struct inode           oti_inode;
};

#ifdef LPROCFS
/* osd_lproc.c */
void lprocfs_osd_init_vars(struct lprocfs_static_vars *lvars);
int osd_procfs_init(struct osd_device *osd, const char *name);
int osd_procfs_fini(struct osd_device *osd);
void osd_lprocfs_time_start(const struct lu_env *env);
void osd_lprocfs_time_end(const struct lu_env *env,
                          struct osd_device *osd, int op);
#endif
int osd_statfs(const struct lu_env *env, struct dt_device *dev,
               struct kstatfs *sfs);

struct inode *osd_iget(struct osd_thread_info *info, struct osd_device *dev,
                       const struct osd_inode_id *id);
extern struct inode *ldiskfs_create_inode(handle_t *handle,
                                          struct inode * dir, int mode);
extern int iam_lvar_create(struct inode *obj, int keysize, int ptrsize,
                           int recsize, handle_t *handle);

extern int iam_lfix_create(struct inode *obj, int keysize, int ptrsize,
                           int recsize, handle_t *handle);
extern int ldiskfs_add_entry(handle_t *handle, struct dentry *dentry,
                             struct inode *inode);
extern int ldiskfs_delete_entry(handle_t *handle,
                                struct inode * dir,
                                struct ldiskfs_dir_entry_2 * de_del,
                                struct buffer_head * bh);
extern struct buffer_head * ldiskfs_find_entry(struct dentry *dentry,
                                               struct ldiskfs_dir_entry_2
                                               ** res_dir);

int osd_compat_init(struct osd_device *osd);
void osd_compat_fini(const struct osd_device *dev);
int osd_compat_objid_lookup(struct osd_thread_info *info, struct osd_device *osd,
                            const struct lu_fid *fid, struct osd_inode_id *id);
int osd_compat_objid_insert(struct osd_thread_info *info, struct osd_device *osd,
                            const struct lu_fid *fid, const struct osd_inode_id *id,
                            struct thandle *th);
int osd_compat_objid_delete(struct osd_thread_info *info, struct osd_device *osd,
                            const struct lu_fid *fid, struct thandle *th);
int osd_compat_spec_lookup(struct osd_thread_info *info, struct osd_device *osd,
                           const struct lu_fid *fid, struct osd_inode_id *id);
int osd_compat_spec_insert(struct osd_thread_info *info, struct osd_device *osd,
                           const struct lu_fid *fid, const struct osd_inode_id *id,
                           struct thandle *th);

#endif /* __KERNEL__ */
#endif /* _OSD_INTERNAL_H */
