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

#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>

#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_ha.h>

extern kmem_cache_t *ll_file_data_slab;
struct ll_file_data {
        struct lustre_handle fd_mdshandle;
        struct lustre_handle fd_osthandle;
        struct ptlrpc_request *fd_req;
        __u32 fd_flags;
};

struct lustre_intent_data {
        __u64 it_lock_handle[2];
        __u32 it_disposition;
        __u32 it_status;
        __u32 it_lock_mode;
};

struct ll_dentry_data {
        struct semaphore      lld_it_sem;
};

#define ll_d2d(dentry) ((struct ll_dentry_data*) dentry->d_fsdata)

struct ll_read_inode2_cookie {
        struct mds_body *lic_body;
        struct lov_mds_md *lic_lmm;
};

#define LL_INLINESZ      60
struct ll_inode_info {
        struct lov_stripe_md *lli_smd;
        char                 *lli_symlink_name;
        struct semaphore      lli_open_sem;
        atomic_t              lli_open_count; /* see ll_file_release */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        struct inode          lli_vfs_inode;
#endif
};



#define LL_SUPER_MAGIC 0x0BD00BD0

#define LL_COMMITCBD_STOPPING  0x1
#define LL_COMMITCBD_STOPPED   0x2
#define LL_COMMITCBD_RUNNING   0x4

#define LL_SBI_NOLCK   0x1

struct ll_sb_info {
        obd_uuid_t                ll_sb_uuid;
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
};

static inline struct ll_sb_info *ll_s2sbi(struct super_block *sb)
{
#if  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        return (struct ll_sb_info *)(sb->s_fs_info);
#else
        return (struct ll_sb_info *)(sb->u.generic_sbp);
#endif
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

static inline int ll_mds_max_easize(struct super_block *sb)
{
        return sbi2mdc(ll_s2sbi(sb))->cl_max_mds_easize;
}

/* namei.c */
int ll_lock(struct inode *dir, struct dentry *dentry,
            struct lookup_intent *it, struct lustre_handle *lockh);
int ll_unlock(__u32 mode, struct lustre_handle *lockh);

typedef int (*intent_finish_cb)(int flag, struct ptlrpc_request *,
                                struct dentry **, struct lookup_intent *,
                                int offset, obd_id ino);
int ll_intent_lock(struct inode *parent, struct dentry **,
                   struct lookup_intent *, intent_finish_cb);

/* dcache.c */
void ll_intent_release(struct dentry *, struct lookup_intent *);
int ll_set_dd(struct dentry *de);

/****

I originally implmented these as functions, then realized a macro
would be more helpful for debugging, so the CDEBUG messages show
the current calling function.  The orignal functions are in llite/dcache.c

int ll_save_intent(struct dentry * de, struct lookup_intent * it);
struct lookup_intent * ll_get_intent(struct dentry * de);
****/

#define IT_RELEASED_MAGIC 0xDEADCAFE

#define LL_SAVE_INTENT(de, it)                                                 \
do {                                                                           \
        LASSERT(ll_d2d(de) != NULL);                                           \
                                                                               \
        down(&ll_d2d(de)->lld_it_sem);                                         \
        LASSERT(de->d_it == NULL);                                             \
        de->d_it = it;                                                         \
        CDEBUG(D_DENTRY, "D_IT DOWN dentry %p fsdata %p intent: %s sem %d\n",  \
               de, ll_d2d(de), ldlm_it2str(de->d_it->it_op),                   \
               atomic_read(&(ll_d2d(de)->lld_it_sem.count)));                  \
} while(0)

#define LL_GET_INTENT(de, it)                                                  \
do {                                                                           \
        it = de->d_it;                                                         \
                                                                               \
        LASSERT(ll_d2d(de) != NULL);                                           \
        LASSERT(it);                                                           \
        LASSERT(it->it_op != IT_RELEASED_MAGIC);                               \
                                                                               \
        CDEBUG(D_DENTRY, "D_IT UP dentry %p fsdata %p intent: %s\n",           \
               de, ll_d2d(de), ldlm_it2str(de->d_it->it_op));                  \
        de->d_it = NULL;                                                       \
        it->it_op = IT_RELEASED_MAGIC;                                         \
        up(&ll_d2d(de)->lld_it_sem);                                           \
} while(0)

/* dcache.c */
int ll_have_md_lock(struct dentry *de);

/* dir.c */
extern struct file_operations ll_dir_operations;
extern struct inode_operations ll_dir_inode_operations;

/* file.c */
extern struct file_operations ll_file_operations;
extern struct inode_operations ll_file_inode_operations;
struct ldlm_lock;
int ll_lock_callback(struct ldlm_lock *, struct ldlm_lock_desc *, void *data,
                     __u32 data_len, int flag);
int ll_size_lock(struct inode *, struct lov_stripe_md *, obd_off start,
                 int mode, struct lustre_handle *);
int ll_size_unlock(struct inode *, struct lov_stripe_md *, int mode,
                   struct lustre_handle *);
int ll_file_size(struct inode *inode, struct lov_stripe_md *md);
int ll_create_objects(struct super_block *sb, obd_id id, uid_t uid,
                      gid_t gid, struct lov_stripe_md **lsmp);

/* rw.c */
struct page *ll_getpage(struct inode *inode, unsigned long offset,
                        int create, int locked);
void ll_truncate(struct inode *inode);

/* super.c */
void ll_update_inode(struct inode *, struct mds_body *);

/* symlink.c */
extern struct inode_operations ll_fast_symlink_inode_operations;
extern struct inode_operations ll_symlink_inode_operations;

/* sysctl.c */
void ll_sysctl_init(void);
void ll_sysctl_clean(void);

#endif /* __KERNEL__ */

#include <asm/types.h>

#define LL_IOC_GETFLAGS                 _IOR ('f', 151, long)
#define LL_IOC_SETFLAGS                 _IOW ('f', 152, long)
#define LL_IOC_CLRFLAGS                 _IOW ('f', 153, long)
#define LL_IOC_LOV_SETSTRIPE            _IOW ('f', 154, long)
#define LL_IOC_LOV_GETSTRIPE            _IOW ('f', 155, long)

#define O_LOV_DELAY_CREATE 0100000000  /* hopefully this does not conflict */

#define LL_FILE_IGNORE_LOCK             0x00000001

#endif
