/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef __OBD_H
#define __OBD_H
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/smp_lock.h>

#include <linux/lustre_idl.h>

struct obd_conn_info {
        unsigned int conn_id;     /* handle */
};

struct obd_type {
        struct list_head typ_chain;
        struct obd_ops *typ_ops;
        char *typ_name;
        int  typ_refcnt;
};

struct obd_run_ctxt {
        struct vfsmount *pwdmnt;
        struct dentry   *pwd;
        mm_segment_t     fs;
};

struct obd_conn {
        struct obd_device *oc_dev;
        uint32_t oc_id;
};

struct obd_devicename {
        uint32_t len;
        char *name;
        struct dentry *dentry;   /* file system obd device names */
        __u8 _uuid[16];          /* uuid obd device names */
};


/* Individual type definitions */

struct ext2_obd {
        struct super_block *e2_sb;
        struct vfsmount *e2_vfsmnt;
};

struct filter_obd {
        char *fo_fstype;
        struct super_block *fo_sb;
        struct vfsmount *fo_vfsmnt;
        struct obd_run_ctxt fo_ctxt;
        spinlock_t fo_lock;
        __u64 fo_lastino;
        struct file_operations *fo_fop;
        struct inode_operations *fo_iop;
        struct address_space_operations *fo_aops;
};

struct mds_client_info;
struct mds_server_data;

struct mds_obd {
        struct ptlrpc_service *mds_service;

        char *mds_fstype;
        struct super_block *mds_sb;
        struct vfsmount *mds_vfsmnt;
        struct obd_run_ctxt mds_ctxt;
        struct file_operations *mds_fop;
        struct inode_operations *mds_iop;
        struct address_space_operations *mds_aops;
        struct mds_fs_operations *mds_fsops;
        struct file *mds_rcvd_filp;
        __u64 mds_last_committed;
        __u64 mds_last_rcvd;
        __u64 mds_mount_count;
        struct ll_fid mds_rootfid;
        int mds_client_count;
        struct list_head mds_client_info;
        struct mds_server_data *mds_server_data;
};

struct ldlm_obd {
        struct ptlrpc_service *ldlm_service;
        struct ptlrpc_client *ldlm_client;
        struct ptlrpc_connection *ldlm_server_conn;
};

struct echo_obd {
        char *eo_fstype;
        struct super_block *eo_sb;
        struct vfsmount *eo_vfsmnt;
        struct obd_run_ctxt eo_ctxt;
        spinlock_t eo_lock;
        __u64 eo_lastino;
        struct file_operations *eo_fop;
        struct inode_operations *eo_iop;
        struct address_space_operations *eo_aops;
};

struct recovd_obd {
        time_t                recovd_waketime;
        time_t                recovd_timeout;
        struct ptlrpc_service *recovd_service;
        struct ptlrpc_client  *recovd_client;
        __u32                  recovd_flags; 
        __u32                  recovd_wakeup_flag; 
        spinlock_t             recovd_lock;
        struct list_head      recovd_clients_lh; /* clients managed  */
        struct list_head      recovd_troubled_lh; /* clients in trouble */
        wait_queue_head_t     recovd_recovery_waitq;
        wait_queue_head_t     recovd_ctl_waitq;
        wait_queue_head_t     recovd_waitq;
        struct task_struct    *recovd_thread;
};

struct trace_obd {
        struct obdtrace_opstats *stats;
};

#if 0
struct snap_obd {
        unsigned int snap_index;  /* which snapshot index are we accessing */
        int snap_tableno;
};

struct raid1_obd {
        unsigned int raid1_count; /* how many replicas */
        /* devices to replicate on */
        struct obd_device *raid1_devlist[MAX_RAID1];
        /* connections we make */
        struct obd_conn_info raid1_connections[MAX_RAID1];
        struct list_head raid1_clients;  /* clients we have */
};
#endif

struct ost_obd {
        struct ptlrpc_service *ost_service;

        struct obd_device *ost_tgt;
        struct obd_conn ost_conn;
};

struct osc_obd {
        struct obd_device *osc_tgt;
        struct ptlrpc_client *osc_client;
        struct ptlrpc_client *osc_ldlm_client;
        struct ptlrpc_connection *osc_conn;
};

/* corresponds to one of the obd's */
#define MAX_MULTI       16
struct obd_device {
        struct obd_type *obd_type;
        char *obd_name;
        __u8 obd_uuid[37];

        int obd_minor;
        int obd_flags;
        int obd_refcnt;
        struct obd_devicename obd_fsname;
        struct proc_dir_entry *obd_proc_entry;
        int obd_multi_count;
        struct obd_conn obd_multi_conn[MAX_MULTI];
        unsigned int obd_gen_last_id;
        unsigned long obd_gen_prealloc_quota;
        struct list_head obd_gen_clients;
        struct list_head obd_req_list;
        wait_queue_head_t obd_req_waitq;
        union {
                struct ext2_obd ext2;
                struct filter_obd filter;
                struct mds_obd mds;
                struct ost_obd ost;
                struct osc_obd osc;
                struct ldlm_obd ldlm;
                struct echo_obd echo;
                struct recovd_obd recovd;
                struct trace_obd trace;
#if 0
                struct raid1_obd raid1;
                struct snap_obd snap;
#endif
        } u;
};

struct obd_ops {
        int (*o_iocontrol)(int cmd, struct obd_conn *, int len, void *karg,
                           void *uarg);
        int (*o_get_info)(struct obd_conn *, obd_count keylen, void *key,
                          obd_count *vallen, void **val);
        int (*o_set_info)(struct obd_conn *, obd_count keylen, void *key,
                          obd_count vallen, void *val);
        int (*o_attach)(struct obd_device *dev, obd_count len, void *data);
        int (*o_detach)(struct obd_device *dev);
        int (*o_setup) (struct obd_device *dev, obd_count len, void *data);
        int (*o_cleanup)(struct obd_device *dev);
        int (*o_connect)(struct obd_conn *conn);
        int (*o_disconnect)(struct obd_conn *conn);


        int (*o_statfs)(struct obd_conn *conn, struct statfs *statfs);
        int (*o_preallocate)(struct obd_conn *, obd_count *req, obd_id *ids);
        int (*o_create)(struct obd_conn *conn,  struct obdo *oa);
        int (*o_destroy)(struct obd_conn *conn, struct obdo *oa);
        int (*o_setattr)(struct obd_conn *conn, struct obdo *oa);
        int (*o_getattr)(struct obd_conn *conn, struct obdo *oa);
        int (*o_open)(struct obd_conn *conn, struct obdo *oa);
        int (*o_close)(struct obd_conn *conn, struct obdo *oa);
        int (*o_read)(struct obd_conn *conn, struct obdo *oa, char *buf,
                      obd_size *count, obd_off offset);
        int (*o_write)(struct obd_conn *conn, struct obdo *oa, char *buf,
                       obd_size *count, obd_off offset);
        int (*o_brw)(int rw, struct obd_conn *conn, obd_count num_oa,
                     struct obdo **oa, obd_count *oa_bufs, struct page **buf,
                     obd_size *count, obd_off *offset, obd_flag *flags);
        int (*o_punch)(struct obd_conn *conn, struct obdo *tgt, obd_size count,
                       obd_off offset);
        int (*o_sync)(struct obd_conn *conn, struct obdo *tgt, obd_size count,
                      obd_off offset);
        int (*o_migrate)(struct obd_conn *conn, struct obdo *dst,
                         struct obdo *src, obd_size count, obd_off offset);
        int (*o_copy)(struct obd_conn *dstconn, struct obdo *dst,
                      struct obd_conn *srconn, struct obdo *src,
                      obd_size count, obd_off offset);
        int (*o_iterate)(struct obd_conn *conn, int (*)(obd_id, obd_gr, void *),
                         obd_id *startid, obd_gr group, void *data);
        int (*o_preprw)(int cmd, struct obd_conn *conn,
                        int objcount, struct obd_ioobj *obj,
                        int niocount, struct niobuf *nb,
                        struct niobuf *res);
        int (*o_commitrw)(int cmd, struct obd_conn *conn,
                          int objcount, struct obd_ioobj *obj,
                          int niocount, struct niobuf *res);
};

#endif
