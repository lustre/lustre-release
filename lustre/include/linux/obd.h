/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef __OBD_H
#define __OBD_H
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/smp_lock.h>
#include <linux/proc_fs.h>

#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_export.h>

struct obd_type {
        struct list_head typ_chain;
        struct obd_ops *typ_ops;
        struct proc_dir_entry *typ_procroot;
        char *typ_name;
        int  typ_refcnt;
};

struct brw_page {
        struct page *pg;
        obd_size count;
        obd_off  off;
        obd_flag flag;
};

struct lov_oinfo { /* per-child structure */
        __u64 loi_id;              /* object ID on the target OST */
        struct lustre_handle *loi_handle; /* handle for object on OST */
        int loi_ost_idx;           /* OST stripe index in lmd_objects array */
};

struct lov_stripe_md {
        __u32 lsm_magic;
        __u64 lsm_object_id;       /* lov object id */
        __u64 lsm_stripe_size;     /* size of the stripe */
        __u32 lsm_stripe_pattern;  /* per-lov object stripe pattern */
        int   lsm_stripe_offset;   /* offset of first stripe in lmd_objects */
        int   lsm_stripe_count;    /* how many objects are being striped on */
        struct lov_oinfo lsm_oinfo[0];
};

/* Individual type definitions */

struct ext2_obd {
        struct super_block *e2_sb;
        struct vfsmount *e2_vfsmnt;
};

struct obd_ucred {
        __u32 ouc_fsuid;
        __u32 ouc_fsgid;
        __u32 ouc_cap;
};

#define OBD_RUN_CTXT_MAGIC      0xC0FFEEAA
#define OBD_CTXT_DEBUG          /* development-only debugging */
struct obd_run_ctxt {
        struct vfsmount *pwdmnt;
        struct dentry   *pwd;
        mm_segment_t     fs;
        __u32            fsuid;
        __u32            fsgid;
        __u32            cap;
#ifdef OBD_CTXT_DEBUG
        __u32            magic;
#endif
};


#ifdef OBD_CTXT_DEBUG
#define OBD_SET_CTXT_MAGIC(ctxt) (ctxt)->magic = OBD_RUN_CTXT_MAGIC
#else
#define OBD_SET_CTXT_MAGIC(ctxt) do {} while(0)
#endif

struct filter_obd {
        char *fo_fstype;
        struct super_block *fo_sb;
        struct vfsmount *fo_vfsmnt;
        struct obd_run_ctxt fo_ctxt;
        struct dentry *fo_dentry_O;
        struct dentry *fo_dentry_O_mode[16];
        spinlock_t fo_objidlock;        /* protects fo_lastobjid increment */
        __u64 fo_lastobjid;
        struct file_operations *fo_fop;
        struct inode_operations *fo_iop;
        struct address_space_operations *fo_aops;
        struct list_head fo_export_list;
        spinlock_t fo_fddlock;          /* protects setting dentry->d_fsdata */
};

struct mds_server_data;

struct client_obd {
        struct obd_import    cl_import;
        struct semaphore     cl_sem;
        int                  cl_conn_count;
        obd_uuid_t           cl_target_uuid; /* XXX -> lustre_name */
        /* max_mds_easize is purely a performance thing so we don't have to
         * call obd_size_wiremd() all the time. */
        int                  cl_max_mds_easize;
        struct obd_device   *cl_containing_lov;
};

#define IOC_OSC_TYPE         'h'
#define IOC_OSC_MIN_NR       20
#define IOC_OSC_REGISTER_LOV _IOWR('h', 20, struct obd_device *)
#define IOC_OSC_MAX_NR       50

struct mds_obd {
        struct ptlrpc_service *mds_service;

        char *mds_fstype;
        struct super_block *mds_sb;
        struct super_operations *mds_sop;
        struct vfsmount *mds_vfsmnt;
        struct obd_run_ctxt mds_ctxt;
        struct file_operations *mds_fop;
        struct inode_operations *mds_iop;
        struct address_space_operations *mds_aops;
        struct mds_fs_operations *mds_fsops;
        int mds_max_mdsize;
        struct file *mds_rcvd_filp;
        spinlock_t mds_last_lock;
        __u64 mds_last_committed;
        __u64 mds_last_rcvd;
        __u64 mds_mount_count;
        struct ll_fid mds_rootfid;
        struct mds_server_data *mds_server_data;
};

struct ldlm_obd {
        struct ptlrpc_service *ldlm_cb_service;
        struct ptlrpc_service *ldlm_cancel_service;
        struct ptlrpc_client *ldlm_client;
        struct ptlrpc_connection *ldlm_server_conn;
};

struct echo_obd {
        char *eo_fstype;
        struct obdo oa;
        spinlock_t eo_lock;
        __u64 eo_lastino;
        atomic_t eo_getattr;
        atomic_t eo_setattr;
        atomic_t eo_create;
        atomic_t eo_destroy;
        atomic_t eo_prep;
        atomic_t eo_read;
        atomic_t eo_write;
};

struct recovd_obd {
        spinlock_t            recovd_lock;
        struct list_head      recovd_managed_items; /* items managed  */
        struct list_head      recovd_troubled_items; /* items in recovery */

        wait_queue_head_t     recovd_recovery_waitq;
        wait_queue_head_t     recovd_ctl_waitq;
        wait_queue_head_t     recovd_waitq;
        struct task_struct   *recovd_thread;
        __u32                 recovd_state;
};

struct trace_obd {
        struct obdtrace_opstats *stats;
};

#if 0
struct snap_obd {
        unsigned int snap_index;  /* which snapshot index are we accessing */
        int snap_tableno;
};

#endif

struct ost_obd {
        struct ptlrpc_service *ost_service;
        struct lustre_handle ost_conn;   /* the local connection to the OBD */
};

struct echo_client_obd {
        struct lustre_handle conn;   /* the local connection to osc/lov */
};

struct lov_tgt_desc {
        obd_uuid_t uuid;
        struct lustre_handle conn;
        int active; /* is this target available for requests, etc */
};

struct lov_obd {
        spinlock_t lov_lock;
        struct obd_device *mdcobd;
        struct lov_desc desc;
        int bufsize;
        int refcount;
        struct lov_tgt_desc *tgts;
};

struct niobuf_local {
        __u64 offset;
        __u32 len;
        __u32 xid;
        __u32 flags;
        void *addr;
        struct page *page;
        void *target_private;
        struct dentry *dentry;
};

#define N_LOCAL_TEMP_PAGE 0x00000001

/* corresponds to one of the obd's */
struct obd_device {
        struct obd_type *obd_type;

        /* common and UUID name of this device */
        char *obd_name;
        obd_uuid_t obd_uuid;

        int obd_minor;
        int obd_flags;
        struct proc_dir_entry *obd_proc_entry;
        struct list_head       obd_exports;
        struct list_head       obd_imports;
        struct ldlm_namespace *obd_namespace;
        struct ptlrpc_client   obd_ldlm_client; /* XXX OST/MDS only */
        /* a spinlock is OK for what we do now, may need a semaphore later */
        spinlock_t obd_dev_lock;
        union {
                struct ext2_obd ext2;
                struct filter_obd filter;
                struct mds_obd mds;
                struct client_obd cli;
                struct ost_obd ost;
                struct echo_client_obd echo_client;;
                //                struct osc_obd osc;
                struct ldlm_obd ldlm;
                struct echo_obd echo;
                struct recovd_obd recovd;
                struct trace_obd trace;
                struct lov_obd lov;
#if 0
                struct snap_obd snap;
#endif
        } u;
       /* Fields used by LProcFS */
        unsigned int cntr_mem_size;
        void* counters;
};

struct obd_ops {
        int (*o_iocontrol)(long cmd, struct lustre_handle *, int len,
                           void *karg, void *uarg);
        int (*o_get_info)(struct lustre_handle *, obd_count keylen, void *key,
                          obd_count *vallen, void **val);
        int (*o_set_info)(struct lustre_handle *, obd_count keylen, void *key,
                          obd_count vallen, void *val);
        int (*o_attach)(struct obd_device *dev, obd_count len, void *data);
        int (*o_detach)(struct obd_device *dev);
        int (*o_setup) (struct obd_device *dev, obd_count len, void *data);
        int (*o_cleanup)(struct obd_device *dev);
        int (*o_connect)(struct lustre_handle *conn, struct obd_device *src,
                         obd_uuid_t cluuid, struct recovd_obd *recovd,
                         ptlrpc_recovery_cb_t recover);
        int (*o_disconnect)(struct lustre_handle *conn);


        int (*o_statfs)(struct lustre_handle *conn, struct obd_statfs *osfs);
        int (*o_packmd)(struct lustre_handle *, struct lov_mds_md **wire_tgt,
                        struct lov_stripe_md *mem_src);
        int (*o_unpackmd)(struct lustre_handle *,
                          struct lov_stripe_md **mem_tgt,
                          struct lov_mds_md *wire_src);
        int (*o_preallocate)(struct lustre_handle *, obd_count *req,
                             obd_id *ids);
        int (*o_create)(struct lustre_handle *conn,  struct obdo *oa,
                        struct lov_stripe_md **ea);
        int (*o_destroy)(struct lustre_handle *conn, struct obdo *oa,
                         struct lov_stripe_md *ea);
        int (*o_setattr)(struct lustre_handle *conn, struct obdo *oa,
                         struct lov_stripe_md *ea);
        int (*o_getattr)(struct lustre_handle *conn, struct obdo *oa,
                         struct lov_stripe_md *ea);
        int (*o_open)(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md *ea);
        int (*o_close)(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *ea);
        int (*o_brw)(int rw, struct lustre_handle *conn,
                     struct lov_stripe_md *ea, obd_count oa_bufs,
                     struct brw_page *pgarr, struct obd_brw_set *);
        int (*o_punch)(struct lustre_handle *conn, struct obdo *tgt,
                       struct lov_stripe_md *ea, obd_size count,
                       obd_off offset);
        int (*o_sync)(struct lustre_handle *conn, struct obdo *tgt,
                      obd_size count, obd_off offset);
        int (*o_migrate)(struct lustre_handle *conn, struct obdo *dst,
                         struct obdo *src, obd_size count, obd_off offset);
        int (*o_copy)(struct lustre_handle *dstconn, struct obdo *dst,
                      struct lustre_handle *srconn, struct obdo *src,
                      obd_size count, obd_off offset);
        int (*o_iterate)(struct lustre_handle *conn,
                         int (*)(obd_id, obd_gr, void *),
                         obd_id *startid, obd_gr group, void *data);
        int (*o_preprw)(int cmd, struct lustre_handle *conn,
                        int objcount, struct obd_ioobj *obj,
                        int niocount, struct niobuf_remote *remote,
                        struct niobuf_local *local, void **desc_private);
        int (*o_commitrw)(int cmd, struct lustre_handle *conn,
                          int objcount, struct obd_ioobj *obj,
                          int niocount, struct niobuf_local *local,
                          void *desc_private);
        int (*o_enqueue)(struct lustre_handle *conn, struct lov_stripe_md *md,
                         struct lustre_handle *parent_lock,
                         __u32 type, void *cookie, int cookielen, __u32 mode,
                         int *flags, void *cb, void *data, int datalen,
                         struct lustre_handle *lockh);
        int (*o_cancel)(struct lustre_handle *, struct lov_stripe_md *md,
                        __u32 mode, struct lustre_handle *);
        int (*o_cancel_unused)(struct lustre_handle *, struct lov_stripe_md *,
                               int local_only);
        
};

static inline void *mds_fs_start(struct mds_obd *mds, struct inode *inode,
                                 int op)
{
        return mds->mds_fsops->fs_start(inode, op);
}

static inline int mds_fs_commit(struct mds_obd *mds, struct inode *inode,
                                void *handle)
{
        return mds->mds_fsops->fs_commit(inode, handle);
}

static inline int mds_fs_setattr(struct mds_obd *mds, struct dentry *dentry,
                                 void *handle, struct iattr *iattr)
{
        int rc;
        /*
         * NOTE: we probably don't need to take i_sem here when changing
         *       ATTR_SIZE because the MDS never needs to truncate a file.
         *       The ext2/ext3 code never truncates a directory, and files
         *       stored on the MDS are entirely sparse (no data blocks).
         *       If we do need to get it, we can do it here.
         */
        lock_kernel();
        rc = mds->mds_fsops->fs_setattr(dentry, handle, iattr);
        unlock_kernel();

        return rc;
}

static inline int mds_fs_set_md(struct mds_obd *mds, struct inode *inode,
                                void *handle, struct lov_mds_md *md,
                                int size)
{
        return mds->mds_fsops->fs_set_md(inode, handle, md, size);
}

static inline int mds_fs_get_md(struct mds_obd *mds, struct inode *inode,
                                struct lov_mds_md *md, int size)
{
        return mds->mds_fsops->fs_get_md(inode, md, size);
}

static inline ssize_t mds_fs_readpage(struct mds_obd *mds, struct file *file,
                                      char *buf, size_t count, loff_t *offset)
{
        return mds->mds_fsops->fs_readpage(file, buf, count, offset);
}

/* Set up callback to update mds->mds_last_committed with the current
 * value of mds->mds_last_recieved when this transaction is on disk.
 */
static inline int mds_fs_set_last_rcvd(struct mds_obd *mds, void *handle)
{
        return mds->mds_fsops->fs_set_last_rcvd(mds, handle);
}

/* Enable data journaling on the given file */
static inline ssize_t mds_fs_journal_data(struct mds_obd *mds,
                                          struct file *file)
{
        return mds->mds_fsops->fs_journal_data(file);
}

static inline int mds_fs_statfs(struct mds_obd *mds, struct statfs *sfs)
{
        if (mds->mds_fsops->fs_statfs)
                return mds->mds_fsops->fs_statfs(mds->mds_sb, sfs);

        return vfs_statfs(mds->mds_sb, sfs);
}

#endif
