/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * object based disk file system
 * 
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 * 
 *
 *



#ifndef _LL_H
#define _LL_H

#include <linux/fs.h>
#include <linux/ext2_fs.h>

#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_ha.h>
#include <linux/obdo.h>

extern kmem_cache_t *ll_file_data_slab;
struct ll_file_data { 
        __u64 fd_mdshandle; 
};

#define LL_INLINESZ      60
struct ll_inode_info {
        int              lli_flags;
        __u64            lli_objid; 
        char             lli_inline[LL_INLINESZ];
};

#define LL_SUPER_MAGIC 0x0BD00BD0;

#define LL_COMMITCBD_STOPPING  0x1
#define LL_COMMITCBD_STOPPED   0x2
#define LL_COMMITCBD_RUNNING   0x4

struct ll_sb_info {
        struct obd_conn           ll_conn;
        ino_t                     ll_rootino; /* number of root inode */
        struct ptlrpc_client      ll_mds_client;
        struct ptlrpc_connection *ll_mds_conn;
        struct ptlrpc_client      ll_ost_client;
        struct ptlrpc_connection *ll_ost_conn;

        struct list_head          ll_commitcbd_not_committed;
        wait_queue_head_t         ll_commitcbd_waitq;
        wait_queue_head_t         ll_commitcbd_ctl_waitq;
        int                       ll_commitcbd_flags;
        struct task_struct        *ll_commitcbd_thread;
        time_t                    ll_commitcbd_waketime;
        time_t                    ll_commitcbd_timeout;
        spinlock_t                ll_commitcbd_lock;
};


static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return (struct ll_sb_info *) (inode->i_sb->u.generic_sbp);
}

static inline struct ll_inode_info *ll_i2info(struct inode *inode)
{
        return (struct ll_inode_info *)&(inode->u.generic_ip);
}

static inline int ll_has_inline(struct inode *inode)
{
        return (ll_i2info(inode)->lli_flags & OBD_FL_INLINEDATA);
}


static inline struct obd_conn *ll_i2obdconn(struct inode *inode)
{
        return &(ll_i2sbi(inode))->ll_conn;
}

/* dir.c */
extern struct file_operations ll_dir_operations;
extern struct inode_operations ll_dir_inode_operations;

/* file.c */
extern struct file_operations ll_file_operations;
extern struct inode_operations ll_file_inode_operations;

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
