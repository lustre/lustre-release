/* SMFS plugin stuff */
#define SMFS_PLG_DUMMY  0x0001L
#define SMFS_PLG_KML    0x0002L
#define SMFS_PLG_LRU    0x0004L
#define SMFS_PLG_COW    0x0008L

#define SMFS_SET_PLG(flags, mask) (flags |= mask)
#define SMFS_IS_PLG(flags, mask) (flags & mask)
#define SMFS_CLEAR_PLG(flags, mask) (flags &= ~mask)

typedef int (*smfs_plg_hook)(int hook_code, void *arg, int, void * priv);
typedef int (*smfs_plg_func)(int help_code, void *arg, void * priv);

struct smfs_plugin {
        struct list_head plg_list;
        int              plg_type;

        smfs_plg_hook    plg_pre_op;
        smfs_plg_hook    plg_post_op;
        smfs_plg_func    plg_helper;
        void *           plg_private;
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
#define HOOK_MAX          13

struct hook_msg {
        struct inode * dir;
        struct dentry * dentry;
};

struct hook_unlink_msg {
        struct inode * dir;
        struct dentry * dentry;
        int mode;
};

struct hook_symlink_msg {
        struct inode * dir;
        struct dentry * dentry;
        int tgt_len;
        char * symname;
};

struct hook_rename_msg {
        struct inode * dir;
        struct dentry * dentry;
        struct inode * new_dir;
        struct dentry * new_dentry;
};

struct hook_readdir_msg {
        struct inode * dir;
        struct dentry * dentry;
        struct file * filp;
        void * dirent;
        filldir_t filldir;
};

struct hook_write_msg {
        struct inode * inode;
        struct dentry * dentry;
        size_t count;
        loff_t pos;
};

struct hook_setattr_msg {
        struct inode * inode;
        struct dentry * dentry;
        struct iattr *attr;
};
#define SMFS_HOOK(sb, op, msg, a,b,c,d,e,f)                  \
do {                                                         \
} while(0)

#define SMFS_PRE_HOOK(sb, op, msg)                           \
do {                                                         \
        struct smfs_super_info *smb = S2SMI(sb);             \
        struct list_head *hlist = &smb->smsi_plg_list;       \
        struct smfs_plugin *plg;                             \
                                                             \
        list_for_each_entry(plg, hlist, plg_list) {          \
                if (plg->plg_pre_op)                         \
                        plg->plg_pre_op(op, msg, 0,          \
                                        plg->plg_private);   \
        }                                                    \
} while(0)

#define SMFS_POST_HOOK(sb, op, msg, rc)                      \
do {                                                         \
        struct smfs_super_info *smb = S2SMI(sb);             \
        struct list_head *hlist = &smb->smsi_plg_list;       \
        struct smfs_plugin *plg;                             \
                                                             \
        list_for_each_entry(plg, hlist, plg_list) {          \
                if (plg->plg_post_op)                        \
                        plg->plg_post_op(op, msg, rc,        \
                                         plg->plg_private);  \
        }                                                    \
} while(0)

#define PLG_EXIT        0
#define PLG_TRANS_SIZE  1
#define PLG_TEST_INODE  2
#define PLG_SET_INODE   3
#define PLG_HELPER_MAX  4

#define SMFS_PLG_HELP(sb, op, data)                              \
do {                                                             \
        struct list_head *hlist = &S2SMI(sb)->smsi_plg_list;     \
        struct smfs_plugin *plugin, *tmp;                        \
                                                                 \
        list_for_each_entry_safe(plugin, tmp, hlist, plg_list) { \
                if (plugin->plg_helper)                          \
                        plugin->plg_helper(op, data,             \
                                           plugin->plg_private); \
        }                                                        \
} while(0)

int smfs_register_plugin(struct super_block *, struct smfs_plugin *);
void * smfs_deregister_plugin(struct super_block *, int);

int smfs_init_dummy(struct super_block *);
int smfs_init_kml(struct super_block *);
int smfs_init_lru(struct super_block *);
int smfs_init_cow(struct super_block *);





