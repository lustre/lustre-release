/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2003 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef LLITE_INTERNAL_H
#define LLITE_INTERNAL_H

struct ll_sb_info {
        struct obd_uuid           ll_sb_uuid;
//        struct lustre_handle      ll_mdc_conn;
        struct obd_export        *ll_mdc_exp;
        struct obd_export        *ll_osc_exp;
        struct proc_dir_entry*    ll_proc_root;
        obd_id                    ll_rootino; /* number of root inode */

        struct obd_uuid           ll_mds_uuid;
        struct obd_uuid           ll_mds_peer_uuid;
        struct lustre_mount_data *ll_lmd;
        char                     *ll_instance; 

        int                       ll_flags;
        wait_queue_head_t         ll_commitcbd_waitq;
        wait_queue_head_t         ll_commitcbd_ctl_waitq;
        int                       ll_commitcbd_flags;
        struct task_struct       *ll_commitcbd_thread;
        time_t                    ll_commitcbd_waketime;
        time_t                    ll_commitcbd_timeout;
        spinlock_t                ll_commitcbd_lock;
        struct list_head          ll_conn_chain; /* per-conn chain of SBs */

        struct hlist_head         ll_orphan_dentry_list; /*please don't ask -p*/
        struct ll_close_queue    *ll_lcq;

        struct lprocfs_stats     *ll_stats; /* lprocfs stats counter */

        spinlock_t                ll_pglist_lock; 
        unsigned long             ll_pglist_gen;
        struct list_head          ll_pglist;
};

struct ll_readahead_state {
        spinlock_t      ras_lock;
        unsigned long   ras_last, ras_window, ras_next_index;
};

extern kmem_cache_t *ll_file_data_slab;
struct ll_file_data {
        struct obd_client_handle fd_mds_och;
        struct ll_readahead_state fd_ras;
        __u32 fd_flags;
};

struct lustre_handle;
struct lov_stripe_md;

extern spinlock_t inode_lock;

extern void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi);
extern struct proc_dir_entry *proc_lustre_fs_root;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
# define hlist_del_init list_del_init
#endif 

static inline struct inode *ll_info2i(struct ll_inode_info *lli)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        return &lli->lli_vfs_inode;
#else
        return list_entry(lli, struct inode, u.generic_ip);
#endif
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

struct it_cb_data {
	struct inode *icbd_parent;
	struct dentry **icbd_childp;
	obd_id hash;
};

#define LLAP_MAGIC 98764321

struct ll_async_page {
        int             llap_magic;
        void            *llap_cookie;
        struct page     *llap_page;
        struct list_head llap_pending_write;
         /* only trust these if the page lock is providing exclusion */
         int             llap_write_queued:1,
                         llap_defer_uptodate:1;
        struct list_head llap_proc_item;
};

#define LL_CDEBUG_PAGE(page, STR)                                       \
        CDEBUG(D_PAGE, "page %p map %p ind %lu priv %0lx: " STR,        \
               page, page->mapping, page->index, page->private)

/* llite/lproc_llite.c */
int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block *sb, char *osc, char *mdc);
void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi);

/* llite/dir.c */
extern struct file_operations ll_dir_operations;
extern struct inode_operations ll_dir_inode_operations;

/* llite/namei.c */
int ll_objects_destroy(struct ptlrpc_request *request, struct inode *dir);
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *lic);
struct dentry *ll_find_alias(struct inode *, struct dentry *);
int ll_mdc_cancel_unused(struct lustre_handle *, struct inode *, int flags,
                         void *opaque);
int ll_mdc_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
                        void *data, int flag);
void ll_prepare_mdc_op_data(struct mdc_op_data *,
                            struct inode *i1, struct inode *i2,
                            const char *name, int namelen, int mode);

/* llite/rw.c */
int ll_prepare_write(struct file *, struct page *, unsigned from, unsigned to);
int ll_commit_write(struct file *, struct page *, unsigned from, unsigned to);
void ll_inode_fill_obdo(struct inode *inode, int cmd, struct obdo *oa);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define ll_ap_completion ll_ap_completion_24
void ll_ap_completion_24(void *data, int cmd, int rc);
#else 
#define ll_ap_completion ll_ap_completion_26
void ll_ap_completion_26(void *data, int cmd, int rc);
#endif
int ll_ocp_update_obdo(struct obd_client_page *ocp, int cmd, struct obdo *oa);
int ll_ocp_set_io_ready(struct obd_client_page *ocp, int cmd);
int ll_ocp_update_io_args(struct obd_client_page *ocp, int cmd);
void ll_removepage(struct page *page);
int ll_sync_page(struct page *page);
int ll_readpage(struct file *file, struct page *page);
struct ll_async_page *llap_from_cookie(void *cookie);
struct ll_async_page *llap_from_page(struct page *page);
void ll_readahead_init(struct ll_readahead_state *ras);

void ll_truncate(struct inode *inode);

/* llite/file.c */
extern struct file_operations ll_file_operations;
extern struct inode_operations ll_file_inode_operations;
extern struct inode_operations ll_special_inode_operations;
extern int ll_inode_revalidate_it(struct dentry *, struct lookup_intent *);
int ll_extent_lock(struct ll_file_data *, struct inode *,
                   struct lov_stripe_md *, int mode, struct ldlm_extent *,
                   struct lustre_handle *);
int ll_extent_unlock(struct ll_file_data *, struct inode *,
                     struct lov_stripe_md *, int mode, struct lustre_handle *);
int ll_file_open(struct inode *inode, struct file *file);
int ll_file_release(struct inode *inode, struct file *file);
int ll_lsm_getattr(struct obd_export *, struct lov_stripe_md *, struct obdo *);
int ll_extent_lock_no_validate(struct ll_file_data *, struct inode *,
                               struct lov_stripe_md *, int mode,
                               struct ldlm_extent *, struct lustre_handle *,
                               int ast_flags);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
int ll_getattr(struct vfsmount *mnt, struct dentry *de,
               struct lookup_intent *it, struct kstat *stat);
#endif

/* llite/dcache.c */
void ll_intent_drop_lock(struct lookup_intent *);
void ll_intent_release(struct lookup_intent *);
extern void ll_set_dd(struct dentry *de);
void ll_unhash_aliases(struct inode *);
void ll_frob_intent(struct lookup_intent **itp, struct lookup_intent *deft);
void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry);

/* llite/llite_lib.c */

extern struct super_operations ll_super_operations;
extern struct super_operations lustre_super_operations;

char *ll_read_opt(const char *opt, char *data);
int ll_set_opt(const char *opt, char *data, int fl);
void ll_options(char *options, char **ost, char **mds, int *flags);
void ll_lli_init(struct ll_inode_info *lli);
int ll_fill_super(struct super_block *sb, void *data, int silent);
int lustre_fill_super(struct super_block *sb, void *data, int silent);
void lustre_put_super(struct super_block *sb);
void ll_put_super(struct super_block *sb);
struct inode *ll_inode_from_lock(struct ldlm_lock *lock);
void ll_clear_inode(struct inode *inode);
int ll_attr2inode(struct inode *inode, struct iattr *attr, int trunc);
int ll_setattr_raw(struct inode *inode, struct iattr *attr);
int ll_setattr(struct dentry *de, struct iattr *attr);
int ll_statfs(struct super_block *sb, struct kstatfs *sfs);
int ll_statfs_internal(struct super_block *sb, struct obd_statfs *osfs,
                       unsigned long maxage);
void ll_update_inode(struct inode *inode, struct mds_body *body,
                     struct lov_stripe_md *lsm);
int it_disposition(struct lookup_intent *it, int flag);
void it_set_disposition(struct lookup_intent *it, int flag);
void ll_read_inode2(struct inode *inode, void *opaque);
int ll_iocontrol(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg);
void ll_umount_begin(struct super_block *sb);
int ll_prep_inode(struct obd_export *exp, struct inode **inode, 
                  struct ptlrpc_request *req, int offset, struct super_block *);
__u32 get_uuid2int(const char *name, int len);
struct dentry *ll_fh_to_dentry(struct super_block *sb, __u32 *data, int len,
                               int fhtype, int parent);
int ll_dentry_to_fh(struct dentry *, __u32 *datap, int *lenp, int need_parent);
/* llite/symlink.c */
extern struct inode_operations ll_fast_symlink_inode_operations;

/* llite/llite_close.c */
struct ll_close_queue {
        spinlock_t              lcq_lock;
        struct list_head        lcq_list;
        wait_queue_head_t       lcq_waitq;
        struct completion       lcq_comp;
};

void llap_write_pending(struct inode *inode, struct ll_async_page *llap);
void llap_write_complete(struct inode *inode, struct ll_async_page *llap);
void ll_open_complete(struct inode *inode);
int ll_is_inode_dirty(struct inode *inode);
void ll_try_done_writing(struct inode *inode);
void ll_queue_done_writing(struct inode *inode);
void ll_close_thread_shutdown(struct ll_close_queue *lcq);
int ll_close_thread_start(struct ll_close_queue **lcq_ret);

/* generic */
#define LL_SUPER_MAGIC 0x0BD00BD0

#define LL_SBI_NOLCK            0x1
#define LL_SBI_READAHEAD        0x2

#if  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#define    ll_s2sbi(sb)     ((struct ll_sb_info *)((sb)->s_fs_info))
void __d_rehash(struct dentry * entry, int lock);
static inline __u64 ll_ts2u64(struct timespec *time)
{
        __u64 t = time->tv_sec;
        return t;
}
#else  /* 2.4 here */
#define    ll_s2sbi(sb)     ((struct ll_sb_info *)((sb)->u.generic_sbp))
static inline __u64 ll_ts2u64(time_t *time)
{
        return *time;
}
#endif 

/* don't need an addref as the sb_info should be holding one */
static inline struct obd_export *ll_s2obdexp(struct super_block *sb)
{
        return ll_s2sbi(sb)->ll_osc_exp;
}

/* don't need an addref as the sb_info should be holding one */
static inline struct obd_export *ll_s2mdcexp(struct super_block *sb)
{
        return ll_s2sbi(sb)->ll_mdc_exp;
}

static inline struct client_obd *sbi2mdc(struct ll_sb_info *sbi)
{
        struct obd_device *obd = sbi->ll_mdc_exp->exp_obd;
        if (obd == NULL)
                LBUG();
        return &obd->u.cli;
}

// FIXME: replace the name of this with LL_SB to conform to kernel stuff
static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return ll_s2sbi(inode->i_sb);
}

static inline struct obd_export *ll_i2obdexp(struct inode *inode)
{
        return ll_s2obdexp(inode->i_sb);
}

static inline struct obd_export *ll_i2mdcexp(struct inode *inode)
{
        return ll_s2mdcexp(inode->i_sb);
}

static inline void ll_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        mdc_pack_fid(fid, inode->i_ino, inode->i_generation,
                     inode->i_mode & S_IFMT);
}

static inline int ll_mds_max_easize(struct super_block *sb)
{
        return sbi2mdc(ll_s2sbi(sb))->cl_max_mds_easize;
}

static inline __u64 ll_file_maxbytes(struct inode *inode)
{
        return ll_i2info(inode)->lli_maxbytes;
}

#endif /* LLITE_INTERNAL_H */
