/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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

#ifndef __LLU_H_
#define __LLU_H_

#include <liblustre.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>

#include <sys/types.h>
#include <sys/stat.h>

#define PAGE_CACHE_MAXBYTES ((__u64)(~0UL) << PAGE_CACHE_SHIFT)

struct ll_file_data {
        struct obd_client_handle fd_mds_och;
        __u32 fd_flags;
        struct lustre_handle fd_cwlockh;
        unsigned long fd_gid;
};

struct llu_sb_info
{
        struct obd_uuid         ll_sb_uuid;
        struct obd_export      *ll_mdc_exp;
        struct obd_export      *ll_osc_exp;
        obd_id                  ll_rootino;
        int                     ll_flags;
        struct list_head        ll_conn_chain;

        struct obd_uuid         ll_mds_uuid;
        struct obd_uuid         ll_mds_peer_uuid;
        char                   *ll_instance; 
};

#define LL_SBI_NOLCK            0x1
#define LL_SBI_READAHEAD        0x2

#define LLI_F_HAVE_OST_SIZE_LOCK        0
#define LLI_F_HAVE_MDS_SIZE_LOCK        1
#define LLI_F_PREFER_EXTENDED_SIZE      2

struct llu_inode_info {
        struct llu_sb_info     *lli_sbi;
        struct ll_fid           lli_fid;

        struct lov_stripe_md   *lli_smd;
        char                   *lli_symlink_name;
        struct semaphore        lli_open_sem;
        __u64                   lli_maxbytes;
        unsigned long        	lli_flags;

        /* for libsysio */
        struct file_identifier  lli_sysio_fid;

        struct lookup_intent   *lli_it;

        /* XXX workaround for libsysio unlink */
        int                     lli_stale_flag;
        /* XXX workaround for libsysio readdir */
        loff_t                  lli_dir_pos;

        /* in libsysio we have no chance to store data in file,
         * so place it here. since it's possible that an file
         * was opened several times without close, we track an
         * open_count here */
        struct ll_file_data    *lli_file_data;
        int                     lli_open_flags;
        int                     lli_open_count;

        /* stat FIXME not 64 bit clean */
        dev_t                   lli_st_dev;
        ino_t                   lli_st_ino;
        mode_t                  lli_st_mode;
        nlink_t                 lli_st_nlink;
        uid_t                   lli_st_uid;
        gid_t                   lli_st_gid;
        dev_t                   lli_st_rdev;
        loff_t                  lli_st_size;
        unsigned int            lli_st_blksize;
        unsigned int            lli_st_blocks;
        time_t                  lli_st_atime;
        time_t                  lli_st_mtime;
        time_t                  lli_st_ctime;

        /* not for stat, change it later */
        int			lli_st_flags;
        unsigned long 		lli_st_generation;
};

#define LLU_SYSIO_COOKIE_SIZE(x) \
        (sizeof(struct llu_sysio_cookie) + \
         sizeof(struct ll_async_page) * (x) + \
         sizeof(struct page) * (x))

struct llu_sysio_cookie {
        struct obd_io_group    *lsc_oig;
        struct inode           *lsc_inode;
        int                     lsc_maxpages;
        int                     lsc_npages;
        struct ll_async_page   *lsc_llap;
        struct page            *lsc_pages;
        __u64                   lsc_rwcount;
};

/* XXX why uio.h haven't the definition? */
#define MAX_IOVEC 32

struct llu_sysio_callback_args
{
        int ncookies;
        struct llu_sysio_cookie *cookies[MAX_IOVEC];
};

static inline struct llu_sb_info *llu_fs2sbi(struct filesys *fs)
{
        return (struct llu_sb_info*)(fs->fs_private);
}

static inline struct llu_inode_info *llu_i2info(struct inode *inode)
{
        return (struct llu_inode_info*)(inode->i_private);
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
       	OBD_ALLOC(temp, sizeof(*temp));					       \
        memcpy(temp, it, sizeof(*temp));                                       \
        llu_i2info(inode)->lli_it = temp;                                      \
        CDEBUG(D_DENTRY, "alloc intent %p to inode %p(ino %lu)\n",             \
                        temp, inode, llu_i2info(inode)->lli_st_ino);           \
} while(0)


#define LL_GET_INTENT(inode, it)                                               \
do {                                                                           \
        it = llu_i2info(inode)->lli_it;                                        \
                                                                               \
        LASSERT(it);                                                           \
        llu_i2info(inode)->lli_it = NULL;                                      \
        CDEBUG(D_DENTRY, "dettach intent %p from inode %p(ino %lu)\n",         \
                        it, inode, llu_i2info(inode)->lli_st_ino);             \
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

static inline void ll_i2uctxt(struct ll_uctxt *ctxt, struct inode *i1,
                              struct inode *i2)
{
        struct llu_inode_info *lli1 = llu_i2info(i1);
        struct llu_inode_info *lli2;

        LASSERT(i1);
        LASSERT(ctxt);

        if (in_group_p(lli1->lli_st_gid))
                ctxt->gid1 = lli1->lli_st_gid;
        else
                ctxt->gid1 = -1;

        if (i2) {
        	lli2 = llu_i2info(i2);
                if (in_group_p(lli2->lli_st_gid))
                        ctxt->gid2 = lli2->lli_st_gid;
                else
                        ctxt->gid2 = -1;
        } else 
                ctxt->gid2 = 0;
}


typedef int (*intent_finish_cb)(struct ptlrpc_request *,
                                struct inode *parent, struct pnode *pnode, 
                                struct lookup_intent *, int offset, obd_id ino);
int llu_intent_lock(struct inode *parent, struct pnode *pnode,
                    struct lookup_intent *, int flags, intent_finish_cb);

/* FIXME */
static inline int ll_permission(struct inode *inode, int flag, void * unused)
{
        return 0;
}

static inline __u64 ll_file_maxbytes(struct inode *inode)
{
        return llu_i2info(inode)->lli_maxbytes;
}

struct mount_option_s
{
        char *mdc_uuid;
        char *osc_uuid;
};

/* llite_lib.c */
void generate_random_uuid(unsigned char uuid_out[16]);
int liblustre_process_log(struct config_llog_instance *cfg, int allow_recov);
int ll_parse_mount_target(const char *target, char **mdsnid,
                          char **mdsname, char **profile);

extern int     g_zconf;
extern char   *g_zconf_mdsnid;
extern char   *g_zconf_mdsname;
extern char   *g_zconf_profile;
extern struct mount_option_s mount_option;

/* super.c */
void llu_update_inode(struct inode *inode, struct mds_body *body,
                      struct lov_stripe_md *lmm);
void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid);
void obdo_from_inode(struct obdo *dst, struct inode *src, obd_flag valid);
int ll_it_open_error(int phase, struct lookup_intent *it);
struct inode *llu_iget(struct filesys *fs, struct lustre_md *md);
int llu_inode_getattr(struct inode *inode, struct lov_stripe_md *lsm);

extern struct fssw_ops llu_fssw_ops;

/* file.c */
void llu_prepare_mdc_op_data(struct mdc_op_data *data,
                             struct inode *i1,
                             struct inode *i2,
                             const char *name,
                             int namelen,
                             int mode);
int llu_create(struct inode *dir, struct pnode_base *pnode, int mode);
int llu_iop_open(struct pnode *pnode, int flags, mode_t mode);
int llu_mdc_close(struct obd_export *mdc_exp, struct inode *inode);
int llu_iop_close(struct inode *inode);
int llu_iop_ipreadv(struct inode *ino, struct ioctx *ioctxp);
int llu_iop_ipwritev(struct inode *ino, struct ioctx *ioctxp);
int llu_vmtruncate(struct inode * inode, loff_t offset);
void obdo_refresh_inode(struct inode *dst, struct obdo *src, obd_flag valid);
int llu_objects_destroy(struct ptlrpc_request *request, struct inode *dir);

/* rw.c */
int llu_iop_iodone(struct ioctx *ioctxp __IS_UNUSED);
struct llu_sysio_callback_args*
llu_file_write(struct inode *inode, const struct iovec *iovec,
        	       size_t iovlen, loff_t pos);
struct llu_sysio_callback_args*
llu_file_read(struct inode *inode, const struct iovec *iovec,
              size_t iovlen, loff_t pos);
int llu_glimpse_size(struct inode *inode, struct ost_lvb *lvb);
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
ssize_t llu_iop_getdirentries(struct inode *ino, char *buf, size_t nbytes,
                              _SYSIO_OFF_T *basep);

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

#endif
