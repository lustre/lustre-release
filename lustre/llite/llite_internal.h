/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef LLITE_INTERNAL_H
#define LLITE_INTERNAL_H

#include <linux/lustre_debug.h>

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
struct ll_inode_info {
        int                     lli_inode_magic;
        int                     lli_size_pid;
        struct semaphore        lli_size_sem;
        struct semaphore        lli_open_sem;
        struct lov_stripe_md   *lli_smd;
        char                   *lli_symlink_name;
        __u64                   lli_maxbytes;
        __u64                   lli_io_epoch;
        unsigned long           lli_flags;

        /* this lock protects s_d_w and p_w_ll and mmap_cnt */
        spinlock_t              lli_lock;
        struct list_head        lli_pending_write_llaps;
        int                     lli_send_done_writing;
        atomic_t                lli_mmap_cnt;

        struct list_head        lli_close_item;

        /* for writepage() only to communicate to fsync */
        int                     lli_async_rc;

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


/* default to about 40meg of readahead on a given system.  That much tied
 * up in 512k readahead requests serviced at 40ms each is about 1GB/s. */
#define SBI_DEFAULT_READAHEAD_MAX (40UL << (20 - PAGE_CACHE_SHIFT))
enum ra_stat {
        RA_STAT_HIT = 0,
        RA_STAT_MISS,
        RA_STAT_DISTANT_READPAGE,
        RA_STAT_MISS_IN_WINDOW,
        RA_STAT_FAILED_MATCH,
        RA_STAT_DISCARDED,
        RA_STAT_ZERO_LEN,
        RA_STAT_ZERO_WINDOW,
        RA_STAT_EOF,
        RA_STAT_MAX_IN_FLIGHT,
        _NR_RA_STAT,
};

struct ll_ra_info {
        unsigned long             ra_cur_pages;
        unsigned long             ra_max_pages;
        unsigned long             ra_stats[_NR_RA_STAT];
};

struct ll_sb_info {
        struct list_head          ll_list;
        /* this protects pglist and ra_info.  It isn't safe to
         * grab from interrupt contexts */
        spinlock_t                ll_lock;
        struct obd_uuid           ll_sb_uuid;
        struct obd_export        *ll_mdc_exp;
        struct obd_export        *ll_osc_exp;
        struct proc_dir_entry*    ll_proc_root;
        obd_id                    ll_rootino; /* number of root inode */

        struct lustre_mount_data *ll_lmd;
        char                     *ll_instance;

        int                       ll_flags;
        struct list_head          ll_conn_chain; /* per-conn chain of SBs */

        struct hlist_head         ll_orphan_dentry_list; /*please don't ask -p*/
        struct ll_close_queue    *ll_lcq;

        struct lprocfs_stats     *ll_stats; /* lprocfs stats counter */

        unsigned long             ll_async_page_max;
        unsigned long             ll_async_page_count;
        unsigned long             ll_pglist_gen;
        struct list_head          ll_pglist; /* all pages (llap_pglist_item) */

        struct ll_ra_info         ll_ra_info;
        unsigned int              ll_namelen;
};

struct ll_readahead_state {
        spinlock_t      ras_lock;
        unsigned long   ras_last_readpage, ras_consecutive;
        unsigned long   ras_window_start, ras_window_len;
        unsigned long   ras_next_readahead;

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

extern kmem_cache_t *ll_async_page_slab;
extern size_t ll_async_page_slab_size;
struct ll_async_page {
        int             llap_magic;
        void            *llap_cookie;
        struct page     *llap_page;
        struct list_head llap_pending_write;
         /* only trust these if the page lock is providing exclusion */
        unsigned int     llap_write_queued:1,
                         llap_defer_uptodate:1,
                         llap_origin:3,
                         llap_ra_used:1;
        struct list_head llap_pglist_item;
};

enum {
        LLAP_ORIGIN_UNKNOWN = 0,
        LLAP_ORIGIN_READPAGE,
        LLAP_ORIGIN_READAHEAD,
        LLAP_ORIGIN_COMMIT_WRITE,
        LLAP_ORIGIN_WRITEPAGE,
        LLAP__ORIGIN_MAX,
};
extern char *llap_origins[];

#ifdef HAVE_REGISTER_CACHE
#define ll_register_cache(cache) register_cache(cache)
#define ll_unregister_cache(cache) unregister_cache(cache)
#else
#define ll_register_cache(cache) do {} while (0)
#define ll_unregister_cache(cache) do {} while (0)
#endif

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
int ll_writepage(struct page *page);
void ll_inode_fill_obdo(struct inode *inode, int cmd, struct obdo *oa);
void ll_ap_completion(void *data, int cmd, struct obdo *oa, int rc);
int llap_shrink_cache(struct ll_sb_info *sbi, int shrink_fraction);
extern struct cache_definition ll_cache_definition;
void ll_removepage(struct page *page);
int ll_readpage(struct file *file, struct page *page);
struct ll_async_page *llap_from_cookie(void *cookie);
struct ll_async_page *llap_from_page(struct page *page, unsigned origin);
struct ll_async_page *llap_cast_private(struct page *page);
void ll_readahead_init(struct inode *inode, struct ll_readahead_state *ras);
void ll_ra_accounting(struct page *page, struct address_space *mapping);
void ll_truncate(struct inode *inode);

/* llite/file.c */
extern struct file_operations ll_file_operations;
extern struct inode_operations ll_file_inode_operations;
extern int ll_inode_revalidate_it(struct dentry *, struct lookup_intent *);
int ll_extent_lock(struct ll_file_data *, struct inode *,
                   struct lov_stripe_md *, int mode, ldlm_policy_data_t *,
                   struct lustre_handle *, int ast_flags);
int ll_extent_unlock(struct ll_file_data *, struct inode *,
                     struct lov_stripe_md *, int mode, struct lustre_handle *);
int ll_file_open(struct inode *inode, struct file *file);
int ll_file_release(struct inode *inode, struct file *file);
int ll_lsm_getattr(struct obd_export *, struct lov_stripe_md *, struct obdo *);
int ll_glimpse_size(struct inode *inode);
int ll_local_open(struct file *file, struct lookup_intent *it);
int ll_mdc_close(struct obd_export *mdc_exp, struct inode *inode,
                 struct file *file);
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

extern struct super_operations lustre_super_operations;

char *ll_read_opt(const char *opt, char *data);
int ll_set_opt(const char *opt, char *data, int fl);
void ll_options(char *options, char **ost, char **mds, int *flags);
void ll_lli_init(struct ll_inode_info *lli);
int ll_fill_super(struct super_block *sb, void *data, int silent);
int lustre_fill_super(struct super_block *sb, void *data, int silent);
void lustre_put_super(struct super_block *sb);
struct inode *ll_inode_from_lock(struct ldlm_lock *lock);
void ll_clear_inode(struct inode *inode);
int ll_setattr_raw(struct inode *inode, struct iattr *attr);
int ll_setattr(struct dentry *de, struct iattr *attr);
int ll_statfs(struct super_block *sb, struct kstatfs *sfs);
int ll_statfs_internal(struct super_block *sb, struct obd_statfs *osfs,
                       unsigned long maxage);
void ll_update_inode(struct inode *inode, struct mds_body *body,
                     struct lov_stripe_md *lsm);
void ll_read_inode2(struct inode *inode, void *opaque);
int ll_iocontrol(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg);
void ll_umount_begin(struct super_block *sb);
int lustre_remount_fs(struct super_block *sb, int *flags, char *data);
int ll_prep_inode(struct obd_export *exp, struct inode **inode,
                  struct ptlrpc_request *req, int offset, struct super_block *);
void lustre_dump_dentry(struct dentry *, int recur);
void lustre_dump_inode(struct inode *);
struct ll_async_page *llite_pglist_next_llap(struct ll_sb_info *sbi,
                                             struct list_head *list);

/* llite/llite_nfs.c */
__u32 get_uuid2int(const char *name, int len);
struct dentry *ll_fh_to_dentry(struct super_block *sb, __u32 *data, int len,
                               int fhtype, int parent);
int ll_dentry_to_fh(struct dentry *, __u32 *datap, int *lenp, int need_parent);

/* llite/special.c */
extern struct inode_operations ll_special_inode_operations;
extern struct file_operations ll_special_chr_inode_fops;
extern struct file_operations ll_special_chr_file_fops;
extern struct file_operations ll_special_blk_inode_fops;
extern struct file_operations ll_special_fifo_inode_fops;
extern struct file_operations ll_special_fifo_file_fops;
extern struct file_operations ll_special_sock_inode_fops;

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

/* llite/llite_mmap.c */
#if  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
typedef struct rb_root  rb_root_t;
typedef struct rb_node  rb_node_t;
#endif

struct ll_lock_tree_node;
struct ll_lock_tree {
        rb_root_t                       lt_root;
        struct list_head                lt_locked_list;
        struct ll_file_data             *lt_fd;
};

int ll_teardown_mmaps(struct address_space *mapping, __u64 first, __u64 last);
int ll_file_mmap(struct file * file, struct vm_area_struct * vma);
struct ll_lock_tree_node * ll_node_from_inode(struct inode *inode, __u64 start,
                                              __u64 end, ldlm_mode_t mode);
int ll_tree_lock(struct ll_lock_tree *tree, 
                 struct ll_lock_tree_node *first_node,
                 const char *buf, size_t count, int ast_flags);
int ll_tree_unlock(struct ll_lock_tree *tree);


#define LL_SBI_NOLCK            0x1

#define LL_MAX_BLKSIZE          (4UL * 1024 * 1024)

#if  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#define    ll_s2sbi(sb)        ((struct ll_sb_info *)((sb)->s_fs_info))
#define    ll_s2sbi_nocast(sb) ((sb)->s_fs_info)
void __d_rehash(struct dentry * entry, int lock);
static inline __u64 ll_ts2u64(struct timespec *time)
{
        __u64 t = time->tv_sec;
        return t;
}
#else  /* 2.4 here */
#define    ll_s2sbi(sb)     ((struct ll_sb_info *)((sb)->u.generic_sbp))
#define    ll_s2sbi_nocast(sb) ((sb)->u.generic_sbp)
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
