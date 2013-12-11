/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LLU_H_
#define __LLU_H_
#include <fcntl.h>
#include <sys/queue.h>
#include <sysio.h>
#ifdef HAVE_XTIO_H
#include <xtio.h>
#endif
#include <fs.h>
#include <mount.h>
#include <inode.h>
#ifdef HAVE_FILE_H
#include <file.h>
#endif

#include <liblustre.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_mdc.h>
#include <lustre_lite.h>
#include <lustre_ver.h>

#include <sys/types.h>
#include <sys/stat.h>

/* for struct cl_lock_descr and struct cl_io */
#include <cl_object.h>
#include <lclient.h>

/* This should not be "optimized" use ~0ULL because page->index is a long and
 * 32-bit systems are therefore limited to 16TB in a mapping */
#define MAX_LFS_FILESIZE ((__u64)(~0UL) << PAGE_CACHE_SHIFT)
struct ll_file_data {
        struct obd_client_handle fd_mds_och;
        __u32 fd_flags;
        struct ccc_grouplock fd_grouplock;
};

struct llu_sb_info {
        struct obd_uuid          ll_sb_uuid;
        struct obd_export       *ll_md_exp;
        struct obd_export       *ll_dt_exp;
        struct lu_fid            ll_root_fid;
        int                      ll_flags;
        struct lustre_client_ocd ll_lco;
        cfs_list_t               ll_conn_chain;

        struct obd_uuid          ll_mds_uuid;
        struct obd_uuid          ll_mds_peer_uuid;
        char                    *ll_instance;
        struct lu_site           *ll_site;
        struct cl_device         *ll_cl;
};

#define LL_SBI_NOLCK            0x1

enum lli_flags {
        /* MDS has an authority for the Size-on-MDS attributes. */
        LLIF_MDS_SIZE_LOCK      = (1 << 0),
};

struct llu_inode_info {
        struct llu_sb_info     *lli_sbi;
        struct lu_fid           lli_fid;

        char                   *lli_symlink_name;
        __u64                   lli_maxbytes;
        unsigned long           lli_flags;
        __u64                   lli_ioepoch;

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
	/* checking lli_has_smd is reliable only inside an IO
	 * i.e, lov stripe has been held. */
	bool                    lli_has_smd;
        int                     lli_open_flags;
        int                     lli_open_count;

        /* not for stat, change it later */
        int                     lli_st_flags;
        unsigned long           lli_st_generation;
        struct cl_object       *lli_clob;
        /* the most recent timestamps obtained from mds */
        struct ost_lvb          lli_lvb;
};

static inline struct llu_sb_info *llu_fs2sbi(struct filesys *fs)
{
        return (struct llu_sb_info*)(fs->fs_private);
}

static inline struct llu_inode_info *llu_i2info(struct inode *inode)
{
        return (struct llu_inode_info*)(inode->i_private);
}

static inline int ll_inode_flags(struct inode *inode)
{
        return llu_i2info(inode)->lli_st_flags;
}

static inline struct intnl_stat *llu_i2stat(struct inode *inode)
{
        return &inode->i_stbuf;
}

#define ll_inode_blksize(inode)     (llu_i2stat(inode)->st_blksize)

static inline struct llu_sb_info *llu_i2sbi(struct inode *inode)
{
        return llu_i2info(inode)->lli_sbi;
}

static inline struct obd_export *llu_i2obdexp(struct inode *inode)
{
        return llu_i2info(inode)->lli_sbi->ll_dt_exp;
}

static inline struct obd_export *llu_i2mdexp(struct inode *inode)
{
        return llu_i2info(inode)->lli_sbi->ll_md_exp;
}

static inline int llu_is_root_inode(struct inode *inode)
{
        return (fid_seq(&llu_i2info(inode)->lli_fid) ==
                fid_seq(&llu_i2info(inode)->lli_sbi->ll_root_fid) &&
                fid_oid(&llu_i2info(inode)->lli_fid) ==
                fid_oid(&llu_i2info(inode)->lli_sbi->ll_root_fid));
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

static inline struct lu_fid *ll_inode2fid(struct inode *inode)
{
        LASSERT(inode != NULL);
        return &llu_i2info(inode)->lli_fid;
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

static inline __u64 ll_file_maxbytes(struct inode *inode)
{
        return llu_i2info(inode)->lli_maxbytes;
}

struct mount_option_s
{
        char *md_uuid;
        char *dt_uuid;
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
void llu_update_inode(struct inode *inode, struct lustre_md *md);
void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid);
int ll_it_open_error(int phase, struct lookup_intent *it);
struct inode *llu_iget(struct filesys *fs, struct lustre_md *md);
int llu_inode_getattr(struct inode *inode, struct obdo *obdo,
                      __u64 ioepoch, int sync);
int llu_md_setattr(struct inode *inode, struct md_op_data *op_data,
                   struct md_open_data **mod);
int llu_setattr_raw(struct inode *inode, struct iattr *attr);
int llu_put_grouplock(struct inode *inode, unsigned long arg);

extern struct fssw_ops llu_fssw_ops;

/* file.c */
void llu_prep_md_op_data(struct md_op_data *op_data, struct inode *i1,
                         struct inode *i2, const char *name, int namelen,
                         int mode, __u32 opc);
int llu_create(struct inode *dir, struct pnode_base *pnode, int mode);
int llu_local_open(struct llu_inode_info *lli, struct lookup_intent *it);
int llu_iop_open(struct pnode *pnode, int flags, mode_t mode);
void llu_done_writing_attr(struct inode *inode, struct md_op_data *op_data);
int llu_md_close(struct obd_export *md_exp, struct inode *inode);
void llu_pack_inode2opdata(struct inode *inode, struct md_op_data *op_data,
                           struct lustre_handle *fh);
int llu_file_release(struct inode *inode);
int llu_som_update(struct inode *inode, struct md_op_data *op_data);
int llu_iop_close(struct inode *inode);
_SYSIO_OFF_T llu_iop_pos(struct inode *ino, _SYSIO_OFF_T off);
int llu_vmtruncate(struct inode * inode, loff_t offset, obd_flag obd_flags);
void obdo_refresh_inode(struct inode *dst, struct obdo *src, obd_flag valid);
int llu_objects_destroy(struct ptlrpc_request *request, struct inode *dir);
void llu_ioepoch_open(struct llu_inode_info *lli, __u64 ioepoch);

/* rw.c */
int llu_iop_read(struct inode *ino, struct ioctx *ioctxp);
int llu_iop_write(struct inode *ino, struct ioctx *ioctxp);
int llu_iop_iodone(struct ioctx *ioctxp);

/* namei.c */
int llu_iop_lookup(struct pnode *pnode,
                   struct inode **inop,
                   struct intent *intnt,
                   const char *path);
void unhook_stale_inode(struct pnode *pno);
struct inode *llu_inode_from_resource_lock(struct ldlm_lock *lock);
struct inode *llu_inode_from_lock(struct ldlm_lock *lock);
int llu_md_blocking_ast(struct ldlm_lock *lock,
                        struct ldlm_lock_desc *desc,
                        void *data, int flag);

/* dir.c */
ssize_t llu_iop_filldirentries(struct inode *ino, _SYSIO_OFF_T *basep,
                               char *buf, size_t nbytes);

/* liblustre/llite_fid.c*/
unsigned long llu_fid_build_ino(struct llu_sb_info *sbi,
                                struct lu_fid *fid);

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

int llu_merge_lvb(const struct lu_env *env, struct inode *inode);

static inline void inode_init_lvb(struct inode *inode, struct ost_lvb *lvb)
{
        struct intnl_stat *st = llu_i2stat(inode);
        lvb->lvb_size = st->st_size;
        lvb->lvb_blocks = st->st_blocks;
        lvb->lvb_mtime = st->st_mtime;
        lvb->lvb_atime = st->st_atime;
        lvb->lvb_ctime = st->st_ctime;
}

#define LLU_IO_GROUP_SIZE(x) \
        (sizeof(struct llu_io_group) + \
         (sizeof(struct ll_async_page) + \
	  sizeof(struct page) + \
          llap_cookie_size) * (x))

struct llu_io_session {
        struct inode           *lis_inode;
        int                     lis_cmd;
        int                     lis_max_groups;
        int                     lis_ngroups;
        int                     lis_rc;
        __u64                   lis_rwcount;
};

struct llu_io_group
{
        struct lustre_rw_params *lig_params;
        int                     lig_rc;
        __u64                   lig_rwcount;
};

struct llu_io_session;
void put_io_group(struct llu_io_group *group);

int cl_sb_init(struct llu_sb_info *sbi);
int cl_sb_fini(struct llu_sb_info *sbi);

void llu_io_init(struct cl_io *io, struct inode *inode, int write);

struct slp_io {
        struct llu_io_session *sio_session;
};

struct slp_session {
        struct slp_io ss_ios;
};

static inline struct slp_session *slp_env_session(const struct lu_env *env)
{
        extern struct lu_context_key slp_session_key;
        struct slp_session *ses;
        ses = lu_context_key_get(env->le_ses, &slp_session_key);
        LASSERT(ses != NULL);
        return ses;
}
static inline struct slp_io *slp_env_io(const struct lu_env *env)
{
        return &slp_env_session(env)->ss_ios;
}

/* lclient compat stuff */
#define cl_inode_info llu_inode_info
#define cl_i2info(info) llu_i2info(info)
#define cl_inode_mode(inode) (llu_i2stat(inode)->st_mode)
#define cl_i2sbi llu_i2sbi
#define cl_isize_read(inode)             (llu_i2stat(inode)->st_size)
#define cl_isize_write(inode,kms)        do{llu_i2stat(inode)->st_size = kms;}while(0)
#define cl_isize_write_nolock(inode,kms) cl_isize_write(inode,kms)

static inline struct ll_file_data *cl_iattr2fd(struct inode *inode,
                                               const struct iattr *attr)
{
        return llu_i2info(inode)->lli_file_data;
}

static inline void cl_isize_lock(struct inode *inode)
{
}

static inline void cl_isize_unlock(struct inode *inode)
{
}

static inline int cl_merge_lvb(const struct lu_env *env, struct inode *inode)
{
	return llu_merge_lvb(env, inode);
}

#define cl_inode_atime(inode) (llu_i2stat(inode)->st_atime)
#define cl_inode_ctime(inode) (llu_i2stat(inode)->st_ctime)
#define cl_inode_mtime(inode) (llu_i2stat(inode)->st_mtime)

static inline struct obd_capa *cl_capa_lookup(struct inode *inode,
                                              enum cl_req_type crt)
{
        return NULL;
}

static inline void cl_stats_tally(struct cl_device *dev, enum cl_req_type crt,
                                  int rc)
{
}

static inline loff_t i_size_read(struct inode *inode)
{
        return inode->i_stbuf.st_size;
}

static inline void i_size_write(struct inode *inode, loff_t i_sz)
{
        inode->i_stbuf.st_size = i_sz;
}

static inline __u64 hash_x_index(__u64 hash, int hash64)
{
	if (BITS_PER_LONG == 32 && hash64)
		hash >>= 32;
	/* save hash 0 as index 0 because otherwise we'll save it at
	 * page index end (~0UL) and it causes truncate_inode_pages_range()
	 * to loop forever. */
	return ~0ULL - (hash + !hash);
}
#endif
