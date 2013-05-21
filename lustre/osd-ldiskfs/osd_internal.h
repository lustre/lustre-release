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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
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
/* struct dentry */
#include <linux/dcache.h>
/* struct dirent64 */
#include <linux/dirent.h>

#ifdef HAVE_EXT4_LDISKFS
#include <ldiskfs/ldiskfs.h>
#include <ldiskfs/ldiskfs_jbd2.h>
#define osd_journal_callback_set(handle, func, jcb) jbd2_journal_callback_set(handle, func, jcb)
#else
#include <linux/jbd.h>
#include <linux/ldiskfs_fs.h>
#include <linux/ldiskfs_jbd.h>
#define osd_journal_callback_set(handle, func, jcb) journal_callback_set(handle, func, jcb)
#endif


/* LUSTRE_OSD_NAME */
#include <obd.h>
/* class_register_type(), class_unregister_type(), class_get_type() */
#include <obd_class.h>
#include <lustre_disk.h>

#include <dt_object.h>
#include "osd_oi.h"
#include "osd_iam.h"

struct inode;

#define OSD_COUNTERS (0)

/** Enable thandle usage statistics */
#define OSD_THANDLE_STATS (0)

#ifdef HAVE_QUOTA_SUPPORT
struct osd_ctxt {
        __u32 oc_uid;
        __u32 oc_gid;
        cfs_kernel_cap_t oc_cap;
};
#endif

struct osd_directory {
        struct iam_container od_container;
        struct iam_descr     od_descr;
};

/*
 * Object Index (oi) instance.
 */
struct osd_oi {
	/*
	 * underlying index object, where fid->id mapping in stored.
	 */
	struct inode		*oi_inode;
	struct osd_directory	oi_dir;
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
        cfs_rw_semaphore_t     oo_ext_idx_sem;
        cfs_rw_semaphore_t     oo_sem;
        struct osd_directory  *oo_dir;
        /** protects inode attributes. */
        cfs_spinlock_t         oo_guard;
        /**
         * Following two members are used to indicate the presence of dot and
         * dotdot in the given directory. This is required for interop mode
         * (b11826).
         */
        int                    oo_compat_dot_created;
        int                    oo_compat_dotdot_created;

        const struct lu_env   *oo_owner;
#ifdef CONFIG_LOCKDEP
        struct lockdep_map     oo_dep_map;
#endif
};

/*
 * osd device.
 */
struct osd_device {
        /* super-class */
        struct dt_device          od_dt_dev;
        /* information about underlying file system */
        struct lustre_mount_info *od_mount;
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
        cfs_hlist_head_t         *od_capa_hash;

        cfs_proc_dir_entry_t     *od_proc_entry;
        struct lprocfs_stats     *od_stats;
        /*
         * statfs optimization: we cache a bit.
         */
        cfs_time_t                od_osfs_age;
        cfs_kstatfs_t             od_kstatfs;
        cfs_spinlock_t            od_osfs_lock;

        /**
         * The following flag indicates, if it is interop mode or not.
         * It will be initialized, using mount param.
         */
        __u32                     od_iop_mode;
};

/*
 * osd dev stats
 */

struct osd_thandle {
        struct thandle          ot_super;
        handle_t               *ot_handle;
        struct journal_callback ot_jcb;
        /* Link to the device, for debugging. */
        struct lu_ref_link     *ot_dev_link;

#if OSD_THANDLE_STATS
        /** time when this handle was allocated */
        cfs_time_t oth_alloced;

        /** time when this thanle was started */
        cfs_time_t oth_started;
#endif
};

#ifdef LPROCFS
enum {
#if OSD_THANDLE_STATS
        LPROC_OSD_THANDLE_STARTING,
        LPROC_OSD_THANDLE_OPEN,
        LPROC_OSD_THANDLE_CLOSING,
#endif
        LPROC_OSD_NR
};
#endif

/**
 * Storage representation for fids.
 *
 * Variable size, first byte contains the length of the whole record.
 */
struct osd_fid_pack {
        unsigned char fp_len;
        char fp_area[sizeof(struct lu_fid)];
};

struct osd_it_ea_dirent {
        struct lu_fid   oied_fid;
        __u64           oied_ino;
        __u64           oied_off;
        unsigned short  oied_namelen;
        unsigned int    oied_type;
        char            oied_name[0];
} __attribute__((packed));

/**
 * as osd_it_ea_dirent (in memory dirent struct for osd) is greater
 * than lu_dirent struct. osd readdir reads less number of dirent than
 * required for mdd dir page. so buffer size need to be increased so that
 * there  would be one ext3 readdir for every mdd readdir page.
 */

#define OSD_IT_EA_BUFSIZE       (CFS_PAGE_SIZE + CFS_PAGE_SIZE/4)

/**
 * This is iterator's in-memory data structure in interoperability
 * mode (i.e. iterator over ldiskfs style directory)
 */
struct osd_it_ea {
        struct osd_object   *oie_obj;
        /** used in ldiskfs iterator, to stored file pointer */
        struct file          oie_file;
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
	struct lu_fid          oti_fid2;
        struct osd_inode_id    oti_id;
        struct osd_inode_id    oti_id2;
        /*
         * XXX temporary: for ->i_op calls.
         */
        struct txn_param       oti_txn;
        struct timespec        oti_time;
        /*
         * XXX temporary: fake struct file for osd_object_sync
         */
        struct file            oti_file;
        /*
         * XXX temporary: for capa operations.
         */
        struct lustre_capa_key oti_capa_key;
        struct lustre_capa     oti_capa;

        /** osd_device reference, initialized in osd_trans_start() and
            used in osd_trans_stop() */
        struct osd_device     *oti_dev;

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
        struct lu_env          oti_obj_delete_tx_env;
#define OSD_FID_REC_SZ 32
        char                   oti_ldp[OSD_FID_REC_SZ];
        char                   oti_ldp2[OSD_FID_REC_SZ];
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
               cfs_kstatfs_t *sfs);
struct inode *osd_iget(struct osd_thread_info *info,
		       struct osd_device *dev,
		       const struct osd_inode_id *id);
int osd_get_lma(struct osd_thread_info *info, struct inode *inode,
		struct dentry *dentry, struct lustre_mdt_attrs *lma);

/*
 * Invariants, assertions.
 */

/*
 * XXX: do not enable this, until invariant checking code is made thread safe
 * in the face of pdirops locking.
 */
#define OSD_INVARIANT_CHECKS (0)

#if OSD_INVARIANT_CHECKS
static inline int osd_invariant(const struct osd_object *obj)
{
        return
                obj != NULL &&
                ergo(obj->oo_inode != NULL,
                     obj->oo_inode->i_sb == osd_sb(osd_obj2dev(obj)) &&
                     atomic_read(&obj->oo_inode->i_count) > 0) &&
                ergo(obj->oo_dir != NULL &&
                     obj->oo_dir->od_conationer.ic_object != NULL,
                     obj->oo_dir->od_conationer.ic_object == obj->oo_inode);
}
#else
#define osd_invariant(obj) (1)
#endif

/* The on-disk extN format reserves inodes 0-11 for internal filesystem
 * use, and these inodes will be invisible on client side, so the valid
 * sequence for IGIF fid is 12-0xffffffff. But root inode (2#) will be seen
 * on server side (osd), and it should be valid too here.
 */
#define OSD_ROOT_SEQ            2
static inline int osd_fid_is_root(const struct lu_fid *fid)
{
        return fid_seq(fid) == OSD_ROOT_SEQ;
}

static inline int osd_fid_is_igif(const struct lu_fid *fid)
{
        return fid_is_igif(fid) || osd_fid_is_root(fid);
}

/* copy from fs/ext4/dir.c */
static inline int is_32bit_api(void)
{
#ifdef CONFIG_COMPAT
	return is_compat_task();
#else
	return (BITS_PER_LONG == 32);
#endif
}

static inline loff_t ldiskfs_get_htree_eof(struct file *filp)
{
	if ((filp->f_mode & FMODE_32BITHASH) ||
	    (!(filp->f_mode & FMODE_64BITHASH) && is_32bit_api()))
		return LDISKFS_HTREE_EOF_32BIT;
	else
		return LDISKFS_HTREE_EOF_64BIT;
}

#define osd_ldiskfs_find_entry(dir, dentry, de)   \
	        ll_ldiskfs_find_entry(dir, dentry, de)
#define osd_ldiskfs_add_entry(handle, child, cinode) \
	        ldiskfs_add_entry(handle, child, cinode)

extern struct lu_context_key osd_key;

static inline struct osd_thread_info *osd_oti_get(const struct lu_env *env)
{
        return lu_context_key_get(&env->le_ctx, &osd_key);
}

static inline struct super_block *osd_sb(const struct osd_device *dev)
{
        return dev->od_mount->lmi_mnt->mnt_sb;
}

/**
 * IAM Iterator
 */
static inline
struct iam_path_descr *osd_it_ipd_get(const struct lu_env *env,
				      const struct iam_container *bag)
{
	return bag->ic_descr->id_ops->id_ipd_alloc(bag,
					   osd_oti_get(env)->oti_it_ipd);
}

static inline
struct iam_path_descr *osd_idx_ipd_get(const struct lu_env *env,
				       const struct iam_container *bag)
{
	return bag->ic_descr->id_ops->id_ipd_alloc(bag,
					   osd_oti_get(env)->oti_idx_ipd);
}

static inline
void osd_ipd_put(const struct lu_env *env, const struct iam_container *bag,
		 struct iam_path_descr *ipd)
{
	bag->ic_descr->id_ops->id_ipd_free(ipd);
}

static inline
struct dentry *osd_child_dentry_by_inode(const struct lu_env *env,
					 struct inode *inode,
					 const char *name, const int namelen)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct dentry *child_dentry = &info->oti_child_dentry;
	struct dentry *obj_dentry = &info->oti_obj_dentry;

	obj_dentry->d_inode = inode;
	obj_dentry->d_sb = inode->i_sb;
	obj_dentry->d_name.hash = 0;

	child_dentry->d_name.hash = 0;
	child_dentry->d_parent = obj_dentry;
	child_dentry->d_name.name = name;
	child_dentry->d_name.len = namelen;
	return child_dentry;
}

/**
 * Helper function to pack the fid, ldiskfs stores fid in packed format.
 */
static inline
void osd_fid_pack(struct osd_fid_pack *pack, const struct dt_rec *fid,
                  struct lu_fid *befider)
{
        fid_cpu_to_be(befider, (struct lu_fid *)fid);
        memcpy(pack->fp_area, befider, sizeof(*befider));
        pack->fp_len =  sizeof(*befider) + 1;
}

static inline
int osd_fid_unpack(struct lu_fid *fid, const struct osd_fid_pack *pack)
{
        int result;

        result = 0;
        switch (pack->fp_len) {
        case sizeof *fid + 1:
                memcpy(fid, pack->fp_area, sizeof *fid);
                fid_be_to_cpu(fid, fid);
                break;
        default:
                CERROR("Unexpected packed fid size: %d\n", pack->fp_len);
                result = -EIO;
        }
        return result;
}

#endif /* __KERNEL__ */
#endif /* _OSD_INTERNAL_H */
