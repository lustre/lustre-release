/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lustre lite cluster file system
 * 
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 * 
 * Copyright (C) 2002 Cluster File Systems, Inc. <info@clusterfs.com>
 */



#ifndef _LL_H
#define _LL_H

#include <linux/fs.h>
#include <linux/ext2_fs.h>

#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_ha.h>

extern kmem_cache_t *ll_file_data_slab;
struct ll_file_data {
        __u64 fd_mdshandle;
        struct ptlrpc_request *fd_req;
        __u32 fd_flags;
};


struct ll_read_inode2_cookie {
        struct mds_body *lic_body;
        struct lov_mds_md *lic_lmm;
};

#define LL_IOC_GETFLAGS                 _IOR ('f', 151, long)
#define LL_IOC_SETFLAGS                 _IOW ('f', 152, long)
#define LL_IOC_CLRFLAGS                 _IOW ('f', 153, long)

#define LL_FILE_IGNORE_LOCK             0x00000001

#define LL_INLINESZ      60
struct ll_inode_info {
        struct lov_stripe_md *lli_smd;
        char                 *lli_symlink_name;
        struct lustre_handle  lli_intent_lock_handle;
        struct semaphore      lli_open_sem;
};

#define LL_SUPER_MAGIC 0x0BD00BD0

#define LL_COMMITCBD_STOPPING  0x1
#define LL_COMMITCBD_STOPPED   0x2
#define LL_COMMITCBD_RUNNING   0x4

#define LL_SBI_NOLCK   0x1

struct ll_sb_info {
        unsigned char             ll_sb_uuid[37];
        struct lustre_handle      ll_mdc_conn;
        struct lustre_handle      ll_osc_conn;
        obd_id                    ll_rootino; /* number of root inode */
        
        int                       ll_flags;
        wait_queue_head_t         ll_commitcbd_waitq;
        wait_queue_head_t         ll_commitcbd_ctl_waitq;
        int                       ll_commitcbd_flags;
        struct task_struct       *ll_commitcbd_thread;
        time_t                    ll_commitcbd_waketime;
        time_t                    ll_commitcbd_timeout;
        spinlock_t                ll_commitcbd_lock;
};


static inline struct ll_sb_info *ll_s2sbi(struct super_block *sb)
{
        return (struct ll_sb_info *)(sb->u.generic_sbp);
}

static inline struct lustre_handle *ll_s2obdconn(struct super_block *sb)
{
        return &(ll_s2sbi(sb))->ll_osc_conn;
}

static inline struct client_obd *sbi2mdc(struct ll_sb_info *sbi)
{
        struct obd_device *obd = class_conn2obd(&sbi->ll_mdc_conn);
        if (obd == NULL)
                LBUG();
        return &obd->u.cli;
}

static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return ll_s2sbi(inode->i_sb);
}

static inline struct ll_inode_info *ll_i2info(struct inode *inode)
{
        return (struct ll_inode_info *)&(inode->u.generic_ip);
}

static inline struct lustre_handle *ll_i2obdconn(struct inode *inode)
{
        return ll_s2obdconn(inode->i_sb);
}

static inline void ll_ino2fid(struct ll_fid *fid, obd_id ino, __u32 generation,
                              int type)
{
        fid->id = ino;
        fid->generation = generation;
        fid->f_type = type;
}

static inline void ll_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        ll_ino2fid(fid, inode->i_ino, inode->i_generation,
                   inode->i_mode & S_IFMT);
}

static inline int ll_mds_easize(struct super_block *sb)
{
        return sbi2mdc(ll_s2sbi(sb))->cl_max_mds_easize;
}

static inline int ll_ost_easize(struct super_block *sb)
{
        return sbi2mdc(ll_s2sbi(sb))->cl_max_ost_easize;
}

/* namei.c */
int ll_lock(struct inode *dir, struct dentry *dentry,
            struct lookup_intent *it, struct lustre_handle *lockh);
int ll_unlock(__u32 mode, struct lustre_handle *lockh);

/* dcache.c */
void ll_intent_release(struct dentry *de);

/* dir.c */
extern struct file_operations ll_dir_operations;
extern struct inode_operations ll_dir_inode_operations;

/* file.c */
extern struct file_operations ll_file_operations;
extern struct inode_operations ll_file_inode_operations;
struct ldlm_lock;
int ll_lock_callback(struct ldlm_lock *, struct ldlm_lock_desc *, void *data,
                     __u32 data_len);
int ll_size_lock(struct inode *, struct lov_stripe_md *, __u64 start, int mode,
                 struct lustre_handle **);
int ll_size_unlock(struct inode *, struct lov_stripe_md *, int mode,
                   struct lustre_handle *);
int ll_file_size(struct inode *inode, struct lov_stripe_md *md);

/* rw.c */
struct page *ll_getpage(struct inode *inode, unsigned long offset,
                           int create, int locked);
void ll_truncate(struct inode *inode);

/* symlink.c */
extern struct inode_operations ll_fast_symlink_inode_operations;
extern struct inode_operations ll_symlink_inode_operations;

/* sysctl.c */
void ll_sysctl_init(void);
void ll_sysctl_clean(void);

#endif
