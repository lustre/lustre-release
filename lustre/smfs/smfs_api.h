/* SMFS plugin stuff */
#define SMFS_PLG_DUMMY  0
#define SMFS_PLG_KML    1
#define SMFS_PLG_LRU    2
#define SMFS_PLG_COW    3
#define SMFS_PLG_MAX    4

typedef int (*smfs_plg_hook)(int hook_code, void *arg, void * priv);
typedef int (*smfs_plg_func) (int help_code, void *arg, void * priv);

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

struct hook_data {
        struct inode * dir;
        struct dentry * dentry;
        int ret_code;
};

struct hook_data_rename {
        struct hook_data data;
        struct inode * new_dir;
        struct inode * new_dentry;
};

struct hook_data_readdir {
        struct hook_data data;
        struct file * filp;
        void * dirent;
        filldir_t filldir;
};

struct hook_data_setattr {
        struct hook_data data;
        struct iattr *attr;
};


#define SMFS_PRE_HOOK (op, data)                               \
do {                                                           \
        struct list_head *hlist = &smfs_plg_list;              \
        struct smfs_plugin *plugin;                            \
                                                               \
        list_for_each_entry(plugin, hlist, plg_list) {         \
                if (plugin->plg_pre_op)                        \
                        plugin->plg_pre_op(op, data,           \
                                           plg->plg_private);  \
        }                                                      \
} while(0)

#define SMFS_POST_HOOK (op, data, rc)                          \
do {                                                           \
        struct list_head *hlist = &smfs_plg_list;              \
        struct smfs_plugin *plugin;                            \
                                                               \
        list_for_each_entry(plugin, hlist, plg_list) {         \
                if (plugin->plg_post_op)                       \
                        plugin->plg_post_op(op, data,          \
                                            plg->plg_private); \
        }                                                      \
} while(0)

#define PLG_EXIT        0
#define PLG_TRANS_SIZE  1
#define PLG_TEST_INODE  2
#define PLG_SET_INODE   3
#define PLG_HELPER_MAX  4

#define SMFS_PLG_HELP (op, data)                              \
do {                                                          \
        struct list_head *hlist = &smfs_plg_list;             \
        struct smfs_plugin *plugin;                           \
                                                              \
        list_for_each_entry(plugin, hlist, plg_list) {        \
                if (plugin->plg_helper)                       \
                        plugin->plg_helper(op, data,          \
                                           plg->plg_private); \
        }                                                     \
} while(0)

int smfs_register_plugin(struct smfs_plugin *);
void * smfs_deregister_plugin(int);







