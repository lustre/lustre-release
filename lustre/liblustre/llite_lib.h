/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef __LLU_H_
#define __LLU_H_

#include <liblustre.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_mds.h>
#include <lustre_lite.h>
#include <lustre_ver.h>

#include <sys/types.h>
#include <sys/stat.h>

/* This should not be "optimized" use ~0ULL because page->index is a long and 
 * 32-bit systems are therefore limited to 16TB in a mapping */
#define PAGE_CACHE_MAXBYTES ((__u64)(~0UL) << CFS_PAGE_SHIFT)

struct ll_file_data {
        struct obd_client_handle fd_mds_och;
        __u32 fd_flags;
        struct lustre_handle fd_cwlockh;
        unsigned long fd_gid;
};

struct llu_sb_info
{
        struct obd_uuid          ll_sb_uuid;
        struct obd_export       *ll_mdc_exp;
        struct obd_export       *ll_osc_exp;
        obd_id                   ll_rootino;
        int                      ll_flags;
        struct lustre_client_ocd ll_lco;
        struct list_head         ll_conn_chain;

        struct obd_uuid          ll_mds_uuid;
        struct obd_uuid          ll_mds_peer_uuid;
        char                    *ll_instance;
};

#define LL_SBI_NOLCK            0x1

#define LLI_F_HAVE_OST_SIZE_LOCK        0
#define LLI_F_HAVE_MDS_SIZE_LOCK        1

struct llu_inode_info {
        struct llu_sb_info     *lli_sbi;
        struct ll_fid           lli_fid;

        struct lov_stripe_md   *lli_smd;
        char                   *lli_symlink_name;
        struct semaphore        lli_open_sem;
        __u64                   lli_maxbytes;
        unsigned long           lli_flags;

        /* for libsysio */
        struct file_identifier  lli_sysio_fid;

        struct lookup_intent   *lli_it;

        /* XXX workaround for libsysio readdir */
        loff_t                  lli_dir_pos;

        /* in libsysio we have no chance to store data in file,
         * so place it here. since it's possible that an file
         * was opened several times without close, we track an
         * open_count here */
        struct ll_file_data    *lli_file_data;
        int                     lli_open_flags;
        int                     lli_open_count;

        /* not for stat, change it later */
        int                     lli_st_flags;
        unsigned long           lli_st_generation;
};

static inline struct llu_sb_info *llu_fs2sbi(struct filesys *fs)
{
        return (struct llu_sb_info*)(fs->fs_private);
}

static inline struct llu_inode_info *llu_i2info(struct inode *inode)
{
        return (struct llu_inode_info*)(inode->i_private);
}

static inline struct intnl_stat *llu_i2stat(struct inode *inode)
{
        return &inode->i_stbuf;
}

static inline struct llu_sb_info *llu_i2sbi(struct inode *inode)
{
        return llu_i2info(inode)->lli_sbi;
}

static inline struct obd_export *llu_i2obdexp(struct inode *inode)
{
        return llu_i2info(inode)->lli_sbi->ll_osc_exp;
}

static inline struct obd_export *llu_i2mdcexp(struct inode *inode)
{
        return llu_i2info(inode)->lli_sbi->ll_mdc_exp;
}

static inline int llu_is_root_inode(struct inode *inode)
{
        return (llu_i2info(inode)->lli_fid.id ==
                llu_i2info(inode)->lli_sbi->ll_rootino);
}

#define LL_SAVE_INTENT(inode, it)                                              \
do {                                                                           \
        struct lookup_intent *temp;                                            \
        LASSERT(llu_i2info(inode)->lli_it == NULL);                            \
        OBD_ALLOC(temp, sizeof(*temp));                                        \
        memcpy(temp, it, sizeof(*temp));                                       \
        llu_i2info(inode)->lli_it = temp;                                      \
        CDEBUG(D_DENTRY, "alloc intent %p to inode %p(ino %llu)\n",            \
                        temp, inode, (long long)llu_i2stat(inode)->st_ino);    \
} while(0)


#define LL_GET_INTENT(inode, it)                                               \
do {                                                                           \
        it = llu_i2info(inode)->lli_it;                                        \
                                                                               \
        LASSERT(it);                                                           \
        llu_i2info(inode)->lli_it = NULL;                                      \
        CDEBUG(D_DENTRY, "dettach intent %p from inode %p(ino %llu)\n",        \
                        it, inode, (long long)llu_i2stat(inode)->st_ino);      \
} while(0)

/* interpet return codes from intent lookup */
#define LL_LOOKUP_POSITIVE 1
#define LL_LOOKUP_NEGATIVE 2

static inline void ll_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        *fid = llu_i2info(inode)->lli_fid;
}

struct it_cb_data {
        struct inode *icbd_parent;
        struct pnode *icbd_child;
        obd_id hash;
};

void ll_i2gids(__u32 *suppgids, struct inode *i1,struct inode *i2);

typedef int (*intent_finish_cb)(struct ptlrpc_request *,
                                struct inode *parent, struct pnode *pnode,
                                struct lookup_intent *, int offset, obd_id ino);
int llu_intent_lock(struct inode *parent, struct pnode *pnode,
                    struct lookup_intent *, int flags, intent_finish_cb);

static inline __u64 ll_file_maxbytes(struct inode *inode)
{
        return llu_i2info(inode)->lli_maxbytes;
}

struct mount_option_s
{
        char *mdc_uuid;
        char *osc_uuid;
};

#define IS_BAD_PTR(ptr)         \
        ((unsigned long)(ptr) == 0 || (unsigned long)(ptr) > -1000UL)

/* llite_lib.c */
int liblustre_process_log(struct config_llog_instance *cfg, char *mgsnid,
                          char *profile, int allow_recov);
int ll_parse_mount_target(const char *target, char **mgsnid,
                          char **fsname);

extern struct mount_option_s mount_option;

/* super.c */
void llu_update_inode(struct inode *inode, struct mds_body *body,
                      struct lov_stripe_md *lmm);
void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid);
void obdo_from_inode(struct obdo *dst, struct inode *src, obd_flag valid);
int ll_it_open_error(int phase, struct lookup_intent *it);
struct inode *llu_iget(struct filesys *fs, struct lustre_md *md);
int llu_inode_getattr(struct inode *inode, struct lov_stripe_md *lsm);
int llu_setattr_raw(struct inode *inode, struct iattr *attr);
int llu_file_flock(struct inode *ino, int cmd, struct file_lock *file_lock);

extern struct fssw_ops llu_fssw_ops;

/* file.c */
void llu_prepare_mdc_op_data(struct mdc_op_data *data,
                             struct inode *i1,
                             struct inode *i2,
                             const char *name,
                             int namelen,
                             int mode);
int llu_create(struct inode *dir, struct pnode_base *pnode, int mode);
int llu_local_open(struct llu_inode_info *lli, struct lookup_intent *it);
int llu_iop_open(struct pnode *pnode, int flags, mode_t mode);
int llu_mdc_close(struct obd_export *mdc_exp, struct inode *inode);
int llu_file_release(struct inode *inode);
int llu_iop_close(struct inode *inode);
_SYSIO_OFF_T llu_iop_pos(struct inode *ino, _SYSIO_OFF_T off);
int llu_vmtruncate(struct inode * inode, loff_t offset, obd_flag obd_flags);
void obdo_refresh_inode(struct inode *dst, struct obdo *src, obd_flag valid);
int llu_objects_destroy(struct ptlrpc_request *request, struct inode *dir);

/* rw.c */
int llu_iop_read(struct inode *ino, struct ioctx *ioctxp);
int llu_iop_write(struct inode *ino, struct ioctx *ioctxp);
int llu_iop_iodone(struct ioctx *ioctxp);
int llu_glimpse_size(struct inode *inode);
int llu_extent_lock_cancel_cb(struct ldlm_lock *lock,
                                    struct ldlm_lock_desc *new, void *data,
                                    int flag);
int llu_extent_lock(struct ll_file_data *fd, struct inode *inode,
                    struct lov_stripe_md *lsm, int mode,
                    ldlm_policy_data_t *policy, struct lustre_handle *lockh,
                    int ast_flags);
int llu_extent_unlock(struct ll_file_data *fd, struct inode *inode,
                      struct lov_stripe_md *lsm, int mode,
                      struct lustre_handle *lockh);

/* namei.c */
int llu_iop_lookup(struct pnode *pnode,
                   struct inode **inop,
                   struct intent *intnt,
                   const char *path);
void unhook_stale_inode(struct pnode *pno);
struct inode *llu_inode_from_lock(struct ldlm_lock *lock);
int llu_mdc_blocking_ast(struct ldlm_lock *lock,
                         struct ldlm_lock_desc *desc,
                         void *data, int flag);

/* dir.c */
ssize_t llu_iop_filldirentries(struct inode *ino, _SYSIO_OFF_T *basep, 
                               char *buf, size_t nbytes);

/* ext2 related */
#define EXT2_NAME_LEN (255)

struct ext2_dirent {
        __u32   inode;
        __u16   rec_len;
        __u8    name_len;
        __u8    file_type;
        char    name[EXT2_NAME_LEN];
};

#define EXT2_DIR_PAD                    4
#define EXT2_DIR_ROUND                  (EXT2_DIR_PAD - 1)
#define EXT2_DIR_REC_LEN(name_len)      (((name_len) + 8 + EXT2_DIR_ROUND) & \
                                         ~EXT2_DIR_ROUND)

static inline struct ext2_dirent *ext2_next_entry(struct ext2_dirent *p)
{
        return (struct ext2_dirent*)((char*) p + le16_to_cpu(p->rec_len));
}

static inline void inode_init_lvb(struct inode *inode, struct ost_lvb *lvb)
{
        struct intnl_stat *st = llu_i2stat(inode);
        lvb->lvb_size = st->st_size;
        lvb->lvb_blocks = st->st_blocks;
        lvb->lvb_mtime = st->st_mtime;
        lvb->lvb_atime = st->st_atime;
        lvb->lvb_ctime = st->st_ctime;
}

#endif
