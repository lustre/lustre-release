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

#ifdef __KERNEL__

#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>

#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_ha.h>

#include <linux/rbtree.h>
#include <linux/lustre_compat25.h>
#include <linux/pagemap.h>

/* careful, this is easy to screw up */
#define PAGE_CACHE_MAXBYTES ((__u64)(~0UL) << PAGE_CACHE_SHIFT)

extern kmem_cache_t *ll_file_data_slab;
struct ll_file_data {
        struct obd_client_handle fd_mds_och;
        struct obd_client_handle fd_ost_och;
        __u32 fd_flags;
};

struct lustre_intent_data {
        __u64 it_lock_handle[2];
        __u32 it_disposition;
        __u32 it_status;
        __u32 it_lock_mode;
};

#define LL_IT2STR(it) ((it) ? ldlm_it2str((it)->it_op) : "0")

static inline struct lookup_intent *ll_nd2it(struct nameidata *nd)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        return &nd->it;
#else
        return nd->it;
#endif
}

struct ll_dentry_data {
        int                      lld_cwd_count;
        int                      lld_mnt_count;
        struct obd_client_handle lld_cwd_och;
        struct obd_client_handle lld_mnt_och;
};

#define ll_d2d(de) ((struct ll_dentry_data*) de->d_fsdata)

extern struct file_operations ll_pgcache_seq_fops;

/* 
 * XXX used in obdecho/echo_client.c  must move (pjb)
 *'p' list as its a list of pages linked together
 * by ->private.. 
 */
struct plist {
        struct page *pl_head;
        struct page *pl_tail;
        int pl_num;
};

struct ll_dirty_offsets {
        rb_root_t       do_root;
        spinlock_t      do_lock;
        unsigned long   do_num_dirty;
};

struct ll_writeback_pages {
        obd_count npgs, max;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        int rw;
        struct inode *inode;
        struct brw_page pga[0];
#else
        struct brw_page *pga;
#endif
};

struct ll_inode_info {
        struct lov_stripe_md   *lli_smd;
        char                   *lli_symlink_name;
        struct semaphore        lli_open_sem;
        struct list_head        lli_read_extents;
        __u64                   lli_maxbytes;
        spinlock_t              lli_read_extent_lock;
        unsigned long           lli_flags;
#define LLI_F_HAVE_SIZE_LOCK    0

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        struct inode            lli_vfs_inode;
#endif
};

/*
 * this lets ll_file_read tell ll_readpages how far ahead it can read
 * and still be covered by ll_file_read's lock.  2.5 won't need this, but
 * we have the other problem of other readpage callers making sure that
 * they're covered by a lock..  
 */
struct ll_read_extent {
        struct list_head re_lli_item;
        struct task_struct *re_task;
        struct ldlm_extent re_extent;
};

#define LL_SUPER_MAGIC 0x0BD00BD0

#define LL_COMMITCBD_STOPPING  0x1
#define LL_COMMITCBD_STOPPED   0x2
#define LL_COMMITCBD_RUNNING   0x4

#define LL_SBI_NOLCK   0x1

struct ll_sb_info {
        struct obd_uuid           ll_sb_uuid;
        struct lustre_handle      ll_mdc_conn;
        struct lustre_handle      ll_osc_conn;
        struct proc_dir_entry*    ll_proc_root;
        obd_id                    ll_rootino; /* number of root inode */

        int                       ll_flags;
        wait_queue_head_t         ll_commitcbd_waitq;
        wait_queue_head_t         ll_commitcbd_ctl_waitq;
        int                       ll_commitcbd_flags;
        struct task_struct       *ll_commitcbd_thread;
        time_t                    ll_commitcbd_waketime;
        time_t                    ll_commitcbd_timeout;
        spinlock_t                ll_commitcbd_lock;
        struct list_head          ll_conn_chain; /* per-conn chain of SBs */

        struct list_head          ll_orphan_dentry_list; /*please don't ask -p*/

        struct lprocfs_stats     *ll_stats; /* lprocfs stats counter */
};


#if  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#define    ll_s2sbi(sb)     ((struct ll_sb_info *)((sb)->s_fs_info))
void __d_rehash(struct dentry * entry, int lock);
static inline __u64 ll_ts2u64(struct timespec *time)
{
        __u64 t = time->tv_sec;
        return t;
}
#else  /* 2.4 here */
#define    ll_s2sbi(sb)     ((struct ll_sb_info *)((sb)->u.generic_sbp))
static inline __u64 ll_ts2u64(time_t *time)
{
        return *time;
}
#endif 

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

// FIXME: replace the name of this with LL_SB to conform to kernel stuff
static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return ll_s2sbi(inode->i_sb);
}

// FIXME: replace the name of this with LL_I to conform to kernel stuff
// static inline struct ll_inode_info *LL_I(struct inode *inode)
static inline struct ll_inode_info *ll_i2info(struct inode *inode)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        return container_of(inode, struct ll_inode_info, lli_vfs_inode);
#else
        return (struct ll_inode_info *)&(inode->u.generic_ip);
#endif
}

static inline struct lustre_handle *ll_i2obdconn(struct inode *inode)
{
        return ll_s2obdconn(inode->i_sb);
}

static inline void ll_ino2fid(struct ll_fid *fid, obd_id ino, __u32 generation,
                              int type);

static inline void ll_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        ll_ino2fid(fid, inode->i_ino, inode->i_generation,
                   inode->i_mode & S_IFMT);
}

static inline int ll_mds_max_easize(struct super_block *sb)
{
        return sbi2mdc(ll_s2sbi(sb))->cl_max_mds_easize;
}

static inline __u64 ll_file_maxbytes(struct inode *inode)
{
        return ll_i2info(inode)->lli_maxbytes;
}

/* namei.c */
typedef int (*intent_finish_cb)(struct ptlrpc_request *,
                                struct inode *parent, struct dentry **, 
                                struct lookup_intent *, int offset, obd_id ino);
int ll_intent_lock(struct inode *parent, struct dentry **,
                   struct lookup_intent *, int, intent_finish_cb);
int ll_mdc_blocking_ast(struct ldlm_lock *lock,
                        struct ldlm_lock_desc *desc,
                        void *data, int flag);
void ll_mdc_lock_set_inode(struct lustre_handle *lock, struct inode *inode);
void ll_prepare_mdc_op_data(struct mdc_op_data *data,
                            struct inode *i1, struct inode *i2,
                            const char *name, int namelen, int mode);

/* lprocfs.c */
enum {
         LPROC_LL_DIRTY_HITS = 0,
         LPROC_LL_DIRTY_MISSES,
         LPROC_LL_WB_WRITEPAGE,
         LPROC_LL_WB_PRESSURE,
         LPROC_LL_WB_OK,
         LPROC_LL_WB_FAIL,
         LPROC_LL_READ_BYTES,
         LPROC_LL_WRITE_BYTES,
         LPROC_LL_BRW_READ,
         LPROC_LL_BRW_WRITE,
         LPROC_LL_IOCTL,
         LPROC_LL_OPEN,
         LPROC_LL_RELEASE,
         LPROC_LL_MAP,
         LPROC_LL_LLSEEK,
         LPROC_LL_FSYNC,
         LPROC_LL_SETATTR_RAW,
         LPROC_LL_SETATTR,
         LPROC_LL_TRUNC,

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
         LPROC_LL_GETATTR,
#else
         LPROC_LL_REVALIDATE,
#endif
         LPROC_LL_STAFS,
         LPROC_LL_ALLOC_INODE,

         LPROC_LL_DIRECT_READ,
         LPROC_LL_DIRECT_WRITE,
         LPROC_LL_FILE_OPCODES
};
/* dcache.c */
int ll_have_md_lock(struct dentry *de);

/* dir.c */
extern struct file_operations ll_dir_operations;
extern struct inode_operations ll_dir_inode_operations;

/* file.c */
extern struct file_operations ll_file_operations;
extern struct inode_operations ll_file_inode_operations;
extern struct inode_operations ll_special_inode_operations;
struct ldlm_lock;
int ll_extent_lock_no_validate(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm, int mode,
                   struct ldlm_extent *extent, struct lustre_handle *lockh);
int ll_extent_lock(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm, int mode,
                   struct ldlm_extent *extent, struct lustre_handle *lockh);
int ll_extent_unlock(struct ll_file_data *fd, struct inode *inode,
                     struct lov_stripe_md *lsm, int mode,
                     struct lustre_handle *lockh);
int ll_create_objects(struct super_block *sb, obd_id id, uid_t uid,
                      gid_t gid, struct lov_stripe_md **lsmp);
int ll_file_open(struct inode *inode, struct file *file);
int ll_file_release(struct inode *inode, struct file *file);



/* super.c */
void ll_update_inode(struct inode *, struct mds_body *, struct lov_stripe_md *);
int ll_setattr_raw(struct inode *inode, struct iattr *attr);
int ll_statfs_internal(struct super_block *sb, struct obd_statfs *osfs,
                       unsigned long maxage);

/* symlink.c */
extern struct inode_operations ll_fast_symlink_inode_operations;
extern struct inode_operations ll_symlink_inode_operations;

#else
#include <linux/lustre_idl.h>
#endif /* __KERNEL__ */

static inline void ll_ino2fid(struct ll_fid *fid, obd_id ino, __u32 generation,
                              int type)
{
        fid->id = ino;
        fid->generation = generation;
        fid->f_type = type;
}

#include <asm/types.h>

#define LL_IOC_GETFLAGS                 _IOR ('f', 151, long)
#define LL_IOC_SETFLAGS                 _IOW ('f', 152, long)
#define LL_IOC_CLRFLAGS                 _IOW ('f', 153, long)
#define LL_IOC_LOV_SETSTRIPE            _IOW ('f', 154, long)
#define LL_IOC_LOV_GETSTRIPE            _IOW ('f', 155, long)

#define O_LOV_DELAY_CREATE 0100000000  /* hopefully this does not conflict */

#define LL_FILE_IGNORE_LOCK             0x00000001

#endif
