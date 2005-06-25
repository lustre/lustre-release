/* SMFS plugin stuff */
#define SMFS_PLG_KML    0x0001L
#define SMFS_PLG_LRU    0x0004L
#define SMFS_PLG_COW    0x0020L
#define SMFS_PLG_UNDO   0x0100L
#define SMFS_PLG_DUMMY  0x1000L
#define SMFS_PLG_ALL    (~0L)

#define SMFS_SET(flags, mask) (flags |= mask)
#define SMFS_IS(flags, mask) (flags & mask)
#define SMFS_CLEAR(flags, mask) (flags &= ~mask)

typedef int (*smfs_plg_hook)(int hook_code, struct inode *,
                             void *arg, int rc, void * priv);
typedef int (*smfs_plg_func)(int help_code, struct super_block *,
                             void *arg, void * priv);

struct smfs_plugin {
        struct list_head plg_list;
        int              plg_type;

        smfs_plg_hook    plg_pre_op;
        smfs_plg_hook    plg_post_op;
        smfs_plg_func    plg_helper;
        void *           plg_private;
};

#define KML_LOG_NAME    "smfs_kml"

struct kml_priv {
        /* llog pack function */
        int (* pack_fn)(int, char *, struct dentry*,
                        struct inode *, void *, void *);
};

#define UNDO_LOG_NAME   "smfs_undo"
struct undo_priv {
        struct llog_ctxt *undo_ctxt;
};

#define HOOK_CREATE       1
#define HOOK_LOOKUP       2
#define HOOK_LINK         3
#define HOOK_UNLINK       4
#define HOOK_SYMLINK      5
#define HOOK_MKDIR        6
#define HOOK_RMDIR        7
#define HOOK_MKNOD        8
#define HOOK_RENAME       9
#define HOOK_SETATTR      10
#define HOOK_WRITE        11
#define HOOK_READDIR      12
#define HOOK_F_SETATTR    13
#define HOOK_SETXATTR     14
#define HOOK_F_SETXATTR   15
#define HOOK_MAX          16

struct hook_msg {
        struct dentry * dentry;

};

struct hook_link_msg {
        struct dentry * dentry;
        struct dentry * new_dentry;
};
struct hook_unlink_msg {
        struct dentry * dentry;
        int mode;
};

struct hook_symlink_msg {
        struct dentry * dentry;
        int tgt_len;
        char * symname;
};

struct hook_rename_msg {
        struct dentry * dentry;
        struct inode * new_dir;
        struct dentry * new_dentry;
};

struct hook_readdir_msg {
        struct dentry * dentry;
        struct file * filp;
        void * dirent;
        filldir_t filldir;
};

struct hook_write_msg {
        struct dentry * dentry;
        size_t count;
        loff_t pos;
};

struct hook_setattr_msg {
        struct dentry * dentry;
        struct iattr *attr;
};

void smfs_pre_hook (struct inode*, int, void*);
void smfs_post_hook(struct inode*,int, void*, int);

#define SMFS_PRE_HOOK(inode, op, msg) smfs_pre_hook (inode, op, msg)
#define SMFS_POST_HOOK(inode, op, msg, rc) smfs_post_hook(inode, op, msg, rc)

#define PLG_EXIT        0
#define PLG_TRANS_SIZE  1
#define PLG_TEST_INODE  2
#define PLG_SET_INODE   3
#define PLG_START       4
#define PLG_STOP        5
#define PLG_HELPER_MAX  6

struct plg_hmsg {
        __u32 data;
        __u32 result;        
};

int smfs_helper (struct super_block *, int, void *);
#define SMFS_PLG_HELP(sb, op, data)  smfs_helper(sb, op, data)

int smfs_register_plugin(struct super_block *, struct smfs_plugin *);
struct smfs_plugin * smfs_deregister_plugin(struct super_block *, int);

int smfs_init_dummy(struct super_block *);
int smfs_init_kml(struct super_block *);
int smfs_init_lru(struct super_block *);
int smfs_init_cow(struct super_block *);

