#ifndef __LINUX_SMFS_H
#define __LINUX_SMFS_H

#include <linux/lustre_fsfilt.h>
#define SMFSDEV_NAME "/dev/smfsconf"
#define SMFS_PSDEV_MINOR 250
#define SMFS_PSDEV_MAJOR 10

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

struct smfs_proc_args {
        struct super_block *sr_sb;
        int                 sr_count;
        int                 sr_flags;
        void               *sr_data;
};


#define SB_OPS_CHECK            0x1
#define INODE_OPS_CHECK         0x2
#define FILE_OPS_CHECK          0x4
#define DENTRY_OPS_CHECK        0x8
#define DEV_OPS_CHECK           0x10
#define SYMLINK_OPS_CHECK       0x20
#define DIR_OPS_CHECK           0x40

#define KML_LOG_NAME "kml_rec"

#define MYPATHLEN(buffer, path) ((buffer) + PAGE_SIZE - (path))

#define SMFS_KML_POST(dir, dentry, data1, data2, op, name, rc, label)   \
do {                                                                    \
        if(smfs_do_rec(dir) && !rc) {                                   \
                CDEBUG(D_INODE, "Do %s kml post for dir %lu \n",        \
                              name, dir->i_ino);                        \
                rc = smfs_post_kml_rec(dir, dentry, data1, data2, op);  \
                if (rc)                                                 \
                        GOTO(label, rc);                                \
        }                                                               \
} while(0)

extern int init_smfs_proc_sys(void);
/*options.c*/
extern int get_opt(struct option **option, char **pos);
extern void cleanup_option(void);
extern int init_option(char *data);
/*cache.c*/
extern void sm_set_inode_ops(struct inode *cache_inode, struct inode *inode);
extern void sm_set_sb_ops(struct super_block *cache_sb, struct super_block *sb);
extern void init_smfs_cache(void);
extern void cleanup_smfs_cache(void);
extern void sm_set_journal_ops(struct super_block *sb, char *cache_type);
extern int smfs_init_sm_ops(struct smfs_super_info *smb);
extern void smfs_cleanup_sm_ops(struct smfs_super_info *smb);
static inline struct super_operations *cache_sops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_sb_ops;
}
static inline struct inode_operations *cache_diops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_dir_iops;
}
static inline struct inode_operations *cache_fiops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_file_iops;
}
static inline struct inode_operations *cache_siops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_sym_iops;
}
static inline struct file_operations *cache_dfops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_dir_fops;
}
static inline struct file_operations *cache_ffops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_file_fops;
}
static inline struct file_operations *cache_sfops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_sym_fops;
}
static inline struct dentry_operations *cache_dops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_dentry_ops;
}
static inline struct journal_operations *journal_ops(struct smfs_super_info *smb)
{
        return &smb->sm_ops->sm_journal_ops;
}
/*super.c*/
extern int init_smfs(void);
extern int cleanup_smfs(void);
extern void smfs_put_super(struct super_block *sb);
extern struct super_block *smfs_get_sb_by_path(char *path, int len);
extern struct vfsmount* get_vfsmount(struct super_block *sb);
/*sysctl.c*/
extern int sm_debug_level;
extern int sm_inodes;
extern long sm_kmemory;
extern int sm_stack;
/*dir.c*/
extern struct inode_operations smfs_dir_iops;
extern struct file_operations smfs_dir_fops;
/*file.c*/
extern struct inode_operations smfs_file_iops;
extern struct file_operations  smfs_file_fops;
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
extern int smfs_open(struct inode * inode, struct file * filp);
extern int smfs_release(struct inode * inode, struct file * filp);
/*inode.c*/
extern struct super_operations smfs_super_ops;
/*symlink.c*/
extern struct inode_operations smfs_sym_iops;
extern struct file_operations smfs_sym_fops;
/*journal.c */
extern void *smfs_trans_start(struct inode *inode, int op, void *desc_private);
extern void smfs_trans_commit(struct inode *inode, void *handle,
                              int force_sync);
extern int  smfs_post_kml_rec(struct inode *dir, struct dentry *dst_dentry,
                              void *data1, void *data2, int op);
/*kml.c*/
extern int smfs_kml_init(struct super_block *sb);
extern int smfs_do_rec(struct inode *inode);
extern int smfs_rec_cleanup(struct super_block *sb);
extern int smfs_rec_init(struct super_block *sb);
extern int smfs_rec_unpack(struct smfs_proc_args *args,
                           struct reint_record *u_rec, char *rec_buf);
extern int smfs_start_rec(struct super_block *sb);
extern int smfs_stop_rec(struct super_block *sb);
extern int smfs_process_rec(struct super_block *sb, int count, char *dir,
                            int flags);
void reint_rec_free(struct reint_record *reint_rec);

extern void smfs_rec_pack(struct update_record *rec, struct inode *dst,
                          void *data, int op);
/*smfs_llog.c*/
extern int smfs_llog_setup(struct super_block *sb);
extern int smfs_llog_cleanup(struct super_block *sb);
extern int smfs_llog_add_rec(struct smfs_super_info * sinfo, void *data,
                             int data_size);
/*ioctl.c*/
extern int init_smfs_psdev(void);
extern void smfs_cleanup_psdev(void);

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

extern int cache_space_hook_setup(struct super_block *);
extern int cache_space_hook_cleanup(void);
extern int cache_space_hook_init(struct super_block *);
extern int cache_space_hook_exit(struct super_block *);

#define XATTR_SMFS_HOARD_MARK           "hoard"
#define XATTR_SMFS_CACHE_LOGCOOKIE      "cache"
#define XATTR_SMFS_ACTIVE_ENTRY         "entry"

#define SMFS_TRANS_OP(inode, op)                \
{                                               \
        if (smfs_do_rec(inode))                 \
                op = op | 0x10;                 \
        if (smfs_cache_hook(inode))             \
                op = op | 0x20;                 \
}

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

#define CACHE_HOOK_CREATE       1
#define CACHE_HOOK_LOOKUP       2
#define CACHE_HOOK_LINK         3
#define CACHE_HOOK_UNLINK       4
#define CACHE_HOOK_SYMLINK      5
#define CACHE_HOOK_MKDIR        6
#define CACHE_HOOK_RMDIR        7
#define CACHE_HOOK_MKNOD        8
#define CACHE_HOOK_RENAME       9

#define CACHE_HOOK_MAX          9

#define SMFS_CACHE_HOOK_PRE(op, handle, dir)                            \
{                                                                       \
        if (smfs_cache_hook(dir)) {                                     \
                LASSERT(handle != NULL);                                \
                CDEBUG(D_INODE, "cache hook pre: op %d, dir %lu\n",     \
                       op, dir->i_ino);                                 \
                cache_space_pre(dir, op);                               \
        }                                                               \
}

#define SMFS_CACHE_HOOK_POST(op, handle, old_dir, old_dentry,           \
                             new_dir, new_dentry, rc, label)            \
{                                                                       \
        if (!rc && smfs_cache_hook(old_dir)) {                          \
                LASSERT(handle != NULL);                                \
                CDEBUG(D_INODE, "cache hook post: op %d, dir %lu\n",    \
                       op, old_dir->i_ino);                             \
                rc = cache_space_post(op, handle, old_dir, old_dentry,  \
                                         new_dir, new_dentry);          \
                if (rc)                                                 \
                        GOTO(label, rc);                                \
        }                                                               \
}

#endif /*__KERNEL*/
#endif /* __LINUX_SMFS_H */
