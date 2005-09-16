/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/smfs_internal.h
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef __LINUX_SMFS_H
#define __LINUX_SMFS_H

#include "smfs_api.h"
#define SMFSDEV_NAME "/dev/smfsconf"
#define SMFS_PSDEV_MINOR 250
#define SMFS_PSDEV_MAJOR 10

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10))
#define FC3_KERNEL
#endif

struct option {
        char *opt;
        char *value;
        struct list_head list;
};

struct smfs_control_device {
        struct list_head smfs_dev_list;
};

#define SMFS_TYPE                "smfs"
#define IOC_SMFS_START           _IOWR('s', 41, long)
#define IOC_SMFS_STOP            _IOWR('s', 42, long)
#define IOC_SMFS_REINT           _IOWR('s', 43, long)
#define IOC_SMFS_UNDO            _IOWR('s', 44, long)

#ifdef __KERNEL__

#define SB_OPS_CHECK             0x1
#define INODE_OPS_CHECK          0x2
#define FILE_OPS_CHECK           0x4
#define DENTRY_OPS_CHECK         0x8
#define SPECIAL_OPS_CHECK        0x10
#define SYMLINK_OPS_CHECK        0x20
#define DIR_OPS_CHECK            0x40

#define MYPATHLEN(buffer, path) ((buffer) + PAGE_SIZE - (path))

#define PACK_KML_REC_INIT(buffer, op_code)          \
do{                                                 \
        int opcode = op_code;                       \
        memcpy(buffer, &opcode, sizeof(opcode));    \
        buffer += sizeof(opcode);                   \
} while (0)

#define SMFS_IOPEN_INO  1
#define KEY_IS(str, key) (strcmp(str,key) == 0)

extern int init_smfs_proc_sys(void);
/*cache.c*/
extern void sm_set_inode_ops(struct inode *);
extern void sm_set_sb_ops(struct super_block *cache_sb, struct super_block *sb);
//extern void init_smfs_cache(void);
//extern void cleanup_smfs_cache(void);
//extern void sm_set_journal_ops(struct super_block *sb, char *cache_type);
extern int smfs_init_sm_ops(struct smfs_super_info *smb);
extern void smfs_cleanup_sm_ops(struct smfs_super_info *smb);

/*smfs_lib.c*/
void smfs_put_super(struct super_block *sb);
int smfs_fill_super(struct super_block *sb, void *data, int silent);
int smfs_post_setup(struct obd_device *, struct vfsmount *, struct dentry *);
void smfs_post_cleanup(struct super_block *);
void * smfs_get_plg_priv(struct smfs_super_info *, int);
/*sysctl.c*/
extern int sm_debug_level;
extern int sm_inodes;
extern long sm_kmemory;
extern int sm_stack;
/*dir.c*/
extern struct inode_operations smfs_dir_iops;
extern struct file_operations smfs_dir_fops;
extern struct inode_operations smfs_iopen_iops;
extern struct file_operations smfs_iopen_fops;

/*file.c*/
extern struct inode_operations smfs_file_iops;
extern struct file_operations  smfs_file_fops;
extern struct inode_operations smfs_special_iops;
extern int smfs_ioctl(struct inode * inode, struct file * filp,
                      unsigned int cmd, unsigned long arg);
extern int smfs_fsync(struct file * file, struct dentry *dentry, int datasync);
extern int smfs_setattr(struct dentry *dentry, struct iattr *attr);
extern int smfs_setxattr(struct dentry *dentry, const char *name,
                         const void *value, size_t size, int flags);
extern int smfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
                         size_t size);
extern ssize_t smfs_listxattr(struct dentry *dentry, char *buffer, size_t size);
extern int smfs_removexattr(struct dentry *dentry, const char *name);
extern int smfs_permission(struct inode *inode, int mask, struct nameidata *nd);
extern int smfs_open(struct inode * inode, struct file * filp);
extern int smfs_release(struct inode * inode, struct file * filp);
/*inode.c*/
struct inode *smfs_get_inode(struct super_block *, struct inode*,  
                             struct smfs_inode_info *, int);

extern struct super_operations smfs_super_ops;

struct smfs_iget_args {
        struct inode            *s_inode;
        struct smfs_inode_info  *s_info;
        int                      s_index;
};

/*symlink.c*/
extern struct inode_operations smfs_sym_iops;
extern struct file_operations smfs_sym_fops;

void *smfs_trans_start(struct inode *inode, int op, void *desc_private);
void smfs_trans_commit(struct inode *inode, void *handle, int force_sync);

extern int smfs_post_rec_write(struct inode *dir, struct dentry *dentry,
                               void   *data1, void *data2);
extern int smfs_post_rec_setattr(struct inode *dir, struct dentry *dentry,
                                 void   *data1, void *data2);
extern int smfs_post_rec_create(struct inode *dir, struct dentry *dentry,
                                void   *data1, void   *data2);
/*kml.c*/
int smfs_do_rec(struct inode *inode);
int smfs_rec_cleanup(struct smfs_super_info *sb);
int smfs_rec_init(struct super_block *sb);

extern int smfs_rec_unpack(struct smfs_proc_args *args, char *record,
                           char **pbuf, int *opcode);
extern int smfs_process_rec(struct super_block *sb, int count,
                            char *dir, int flags);

extern int mds_rec_pack(int, char *, struct dentry *, struct inode *,
                        void *, void *);
extern int ost_rec_pack(int, char *, struct dentry *, struct inode *,
                        void *, void *);

/*smfs_llog.c*/
extern int smfs_llog_setup(struct dentry **, struct dentry **);
extern int smfs_llog_cleanup(struct smfs_super_info *);
extern int smfs_llog_add_rec(struct smfs_super_info *, void *, int);
/*ioctl.c*/
extern int init_smfs_psdev(void);
extern void smfs_cleanup_psdev(void);
/*smfs_cow.c */

/* audit_transfer.c */
int audit_notify(struct llog_handle *llh, void*, int);
int audit_start_transferd(void);
int audit_stop_transferd(void);

/* cache_space.c */
extern int do_cache_manage;
struct cache_purge_queue {
        wait_queue_head_t       cpq_waitq;
        struct super_block     *cpq_sb;
        struct llog_handle     *cpq_loghandle;
        __u32                   cpq_flags;
        struct completion       cpq_comp;
};
/* opcodes */
#define CACHE_SPACE_INSERT 0x1
#define CACHE_SPACE_DELETE 0x2
#define CACHE_SPACE_COMMIT 0x4

#define CACHE_LRU_LOG "CACHE_LRU_LIST"

extern int smfs_cache_hook(struct inode *inode);
extern void cache_space_pre(struct inode *inode, int op);
extern int cache_space_post(int op, void *handle, struct inode *old_dir,
                            struct dentry *old_dentry, struct inode *new_dir,
                            struct dentry *new_dentry);

int cache_space_hook_setup(struct super_block *);
int cache_space_hook_cleanup(void);
int cache_space_hook_init(struct super_block *sb);
int cache_space_hook_exit(struct smfs_super_info *smfs_info);

#define XATTR_SMFS_HOARD_MARK           "hoard"
#define XATTR_SMFS_CACHE_LOGCOOKIE      "cache"
#define XATTR_SMFS_ACTIVE_ENTRY         "entry"


static inline int set_hoard_priority(struct inode *inode, void *handle,
                                     __u32 *hoard)
{
        struct fsfilt_operations *fsops = I2CSB(inode)->sm_fsfilt;
        int rc;

        rc = fsops->fs_set_xattr(inode, handle, XATTR_SMFS_HOARD_MARK,
                                 hoard, sizeof(__u32));
        RETURN(rc);
}

static inline int get_hoard_priority(struct inode *inode, __u32 *hoard)
{
        struct fsfilt_operations *fsops = I2CSB(inode)->sm_fsfilt;
        int rc;

        rc = fsops->fs_get_xattr(inode, XATTR_SMFS_HOARD_MARK,
                                 hoard, sizeof(__u32));
        RETURN(rc);
}

static inline int set_active_entry(struct inode *dir, __u64 *active_entry,
                                   void *handle)
{
        struct fsfilt_operations *fsops = I2CSB(dir)->sm_fsfilt;
        int rc;
        *active_entry = cpu_to_le64(*active_entry);
        rc = fsops->fs_set_xattr(dir, handle, XATTR_SMFS_ACTIVE_ENTRY,
                                 active_entry, sizeof(__u64));
        RETURN(rc);
}
static inline int get_active_entry(struct inode *dir, __u64 *active_entry)
{
        struct fsfilt_operations *fsops = I2CSB(dir)->sm_fsfilt;
        int rc = fsops->fs_get_xattr(dir, XATTR_SMFS_ACTIVE_ENTRY,
                                     active_entry, sizeof(__u64));
        *active_entry = le64_to_cpu(*active_entry);
        if (rc >= 0)
                rc = 0;
        RETURN(rc);
}

struct kml_buffer {
        char *buf;
        int   buf_size;
}; 

#ifdef __KERNEL__
static inline void
smfs_inode2id(struct lustre_id *id, struct inode *inode)
{
        mdc_pack_id(id, inode->i_ino, inode->i_generation,
                    (inode->i_mode & S_IFMT), 0, 0);
}

static inline void 
smfs_prepare_mdc_data(struct mdc_op_data *data, struct inode *i1,
                      struct inode *i2, const char *name, int namelen,
                      int mode)
{
        LASSERT(i1);

        smfs_inode2id(&data->id1, i1);
        if (i2)
                smfs_inode2id(&data->id2, i2);
        else
                memset(&data->id2, 0, sizeof(data->id2));

	data->valid = 0;
        data->name = name;
        data->namelen = namelen;
        data->create_mode = mode;
        data->mod_time = LTIME_S(CURRENT_TIME);
}
#endif

#if CONFIG_SNAPFS
int smfs_cow_init(struct super_block *sb);
int smfs_cow_cleanup(struct smfs_super_info *smb);
int smfs_snap_test_inode(struct inode *inode, void *args);
#else
#define SMFS_PRE_COW(dir, dentry, new_dir, new_dentry, op, name, rc, label)                 
#endif 
#endif /*__KERNEL*/
#endif /* __LINUX_SMFS_H */
