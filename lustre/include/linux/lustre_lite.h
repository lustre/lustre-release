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
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
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


/*
struct lustre_intent_data {
        __u64 it_lock_handle[2];
        __u32 it_disposition;
        __u32 it_status;
        __u32 it_lock_mode;
        }; */

#define LL_IT2STR(it) ((it) ? ldlm_it2str((it)->it_op) : "0")

static inline struct lookup_intent *ll_nd2it(struct nameidata *nd)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        return &nd->intent;
#else
        return nd->intent;
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

#define LLI_INODE_MAGIC                 0x111d0de5
#define LLI_INODE_DEAD                  0xdeadd00d
#define LLI_F_HAVE_OST_SIZE_LOCK        0
#define LLI_F_HAVE_MDS_SIZE_LOCK        1
#define LLI_F_PREFER_EXTENDED_SIZE      2
struct ll_inode_info {
        int                     lli_inode_magic;
        struct lov_stripe_md   *lli_smd;
        struct mea             *lli_mea;
        char                   *lli_symlink_name;
        struct semaphore        lli_open_sem;
        __u64                   lli_maxbytes;
        __u64                   lli_io_epoch;
        unsigned long           lli_flags;
        __u32                   lli_mds;

        /* this lock protects s_d_w and p_w_ll */
        spinlock_t              lli_lock;
        int                     lli_send_done_writing;
        
        int                     lli_snap_index;
        
        struct list_head        lli_pending_write_llaps;

        struct list_head        lli_close_item;

        struct file_operations *ll_save_ifop;
        struct file_operations *ll_save_ffop;
        struct file_operations *ll_save_wfop;
        struct file_operations *ll_save_wrfop;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        struct inode            lli_vfs_inode;
#endif
};

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

static inline void ll_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        mdc_pack_fid(fid, inode->i_ino, inode->i_generation,
                     inode->i_mode & S_IFMT);
        LASSERT(ll_i2info(inode));
        fid->mds = ll_i2info(inode)->lli_mds;
}

static inline void ll_i2uctxt(struct ll_uctxt *ctxt, struct inode *i1,
                              struct inode *i2)
{
        LASSERT(i1);
        LASSERT(ctxt);

        if (in_group_p(i1->i_gid))
                ctxt->gid1 = i1->i_gid;
        else
                ctxt->gid1 = -1;

        if (i2) {
                if (in_group_p(i2->i_gid))
                        ctxt->gid2 = i2->i_gid;
                else
                        ctxt->gid2 = -1;
        } else
                ctxt->gid2 = 0;
}

static inline void 
ll_prepare_mdc_op_data(struct mdc_op_data *data, struct inode *i1,
                       struct inode *i2, const char *name, int namelen,
                       int mode)
{
        LASSERT(i1);

        ll_i2uctxt(&data->ctxt, i1, i2);
        ll_inode2fid(&data->fid1, i1);

        /* it could be directory with mea */
        data->mea1 = ll_i2info(i1)->lli_mea;

        if (i2) {
                ll_inode2fid(&data->fid2, i2);
                data->mea2 = ll_i2info(i2)->lli_mea;
        }

        data->name = name;
        data->namelen = namelen;
        data->create_mode = mode;
        data->mod_time = LTIME_S(CURRENT_TIME);
}

#else
#include <linux/lustre_idl.h>
#endif /* __KERNEL__ */

#include <lustre/lustre_user.h>

#endif
