/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef LLITE_INTERNAL_H
#define LLITE_INTERNAL_H

# include <linux/lustre_acl.h>

#ifdef CONFIG_FS_POSIX_ACL
# include <linux/fs.h>
#ifdef HAVE_XATTR_ACL
# include <linux/xattr_acl.h>
#endif
#ifdef HAVE_LINUX_POSIX_ACL_XATTR_H
# include <linux/posix_acl_xattr.h>
#endif
#endif

#include <lustre_debug.h>
#include <lustre_ver.h>
#include <lustre_disk.h>  /* for s2sbi */

/* If there is no FMODE_EXEC defined, make it to match nothing */
#ifndef FMODE_EXEC
#define FMODE_EXEC 0
#endif

#define LL_IT2STR(it) ((it) ? ldlm_it2str((it)->it_op) : "0")
#define LUSTRE_FPRIVATE(file) ((file)->private_data)

#ifdef LUSTRE_KERNEL_VERSION
static inline struct lookup_intent *ll_nd2it(struct nameidata *nd)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        return &nd->intent;
#else
        return nd->intent;
#endif
}
#endif

struct ll_dentry_data {
        int                      lld_cwd_count;
        int                      lld_mnt_count;
        struct obd_client_handle lld_cwd_och;
        struct obd_client_handle lld_mnt_och;
#ifndef LUSTRE_KERNEL_VERSION
        struct lookup_intent     *lld_it;
#endif
};

#define ll_d2d(de) ((struct ll_dentry_data*) de->d_fsdata)

extern struct file_operations ll_pgcache_seq_fops;

#define LLI_INODE_MAGIC                 0x111d0de5
#define LLI_INODE_DEAD                  0xdeadd00d

/* remote client permission cache */
#define REMOTE_PERM_HASHSIZE 16

/* llite setxid/access permission for user on remote client */
struct ll_remote_perm {
        struct hlist_node       lrp_list;
        uid_t                   lrp_uid;
        gid_t                   lrp_gid;
        uid_t                   lrp_fsuid;
        gid_t                   lrp_fsgid;
        int                     lrp_access_perm; /* MAY_READ/WRITE/EXEC, this
                                                    is access permission with
                                                    lrp_fsuid/lrp_fsgid. */
};

enum lli_flags {
        /* MDS has an authority for the Size-on-MDS attributes. */
        LLIF_MDS_SIZE_LOCK      = (1 << 0),
        /* Epoch close is postponed. */
        LLIF_EPOCH_PENDING      = (1 << 1),
        /* DONE WRITING is allowed. */
        LLIF_DONE_WRITING       = (1 << 2),
        /* Sizeon-on-MDS attributes are changed. An attribute update needs to
         * be sent to MDS. */
        LLIF_SOM_DIRTY          = (1 << 3),
};

struct ll_inode_info {
        int                     lli_inode_magic;
        struct semaphore        lli_size_sem;
        void                   *lli_size_sem_owner;
        struct semaphore        lli_open_sem;
        struct semaphore        lli_write_sem;
        char                   *lli_symlink_name;
        __u64                   lli_maxbytes;
        __u64                   lli_ioepoch;
        unsigned long           lli_flags;

        /* this lock protects posix_acl, pending_write_llaps, mmap_cnt */
        spinlock_t              lli_lock;
        struct list_head        lli_pending_write_llaps;
        struct list_head        lli_close_list;
        /* handle is to be sent to MDS later on done_writing and setattr.
         * Open handle data are needed for the recovery to reconstruct
         * the inode state on the MDS. XXX: recovery is not ready yet. */
        struct obd_client_handle *lli_pending_och;

        atomic_t                lli_mmap_cnt;

        /* for writepage() only to communicate to fsync */
        int                     lli_async_rc;

        struct posix_acl       *lli_posix_acl;

        /* remote permission hash */
        struct hlist_head      *lli_remote_perms;
        unsigned long           lli_rmtperm_utime;
        struct semaphore        lli_rmtperm_sem;

        struct list_head        lli_dead_list;

        struct semaphore        lli_och_sem; /* Protects access to och pointers
                                                and their usage counters */
        /* We need all three because every inode may be opened in different
           modes */
        struct obd_client_handle *lli_mds_read_och;
        __u64                   lli_open_fd_read_count;
        struct obd_client_handle *lli_mds_write_och;
        __u64                   lli_open_fd_write_count;
        struct obd_client_handle *lli_mds_exec_och;
        __u64                   lli_open_fd_exec_count;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        struct inode            lli_vfs_inode;
#endif

        /* identifying fields for both metadata and data stacks. */
        struct lu_fid           lli_fid;
        struct lov_stripe_md   *lli_smd;

        /* fid capability */
        /* open count currently used by capability only, indicate whether
         * capability needs renewal */
        atomic_t                lli_open_count;
        struct obd_capa        *lli_mds_capa;
        struct list_head        lli_oss_capas;
};

/*
 * Locking to guarantee consistency of non-atomic updates to long long i_size,
 * consistency between file size and KMS, and consistency within
 * ->lli_smd->lsm_oinfo[]'s.
 *
 * Implemented by ->lli_size_sem and ->lsm_sem, nested in that order.
 */

void ll_inode_size_lock(struct inode *inode, int lock_lsm);
void ll_inode_size_unlock(struct inode *inode, int unlock_lsm);

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

/* default to read-ahead full files smaller than 2MB on the second read */
#define SBI_DEFAULT_READAHEAD_WHOLE_MAX (2UL << (20 - PAGE_CACHE_SHIFT))

enum ra_stat {
        RA_STAT_HIT = 0,
        RA_STAT_MISS,
        RA_STAT_DISTANT_READPAGE,
        RA_STAT_MISS_IN_WINDOW,
        RA_STAT_FAILED_GRAB_PAGE,
        RA_STAT_FAILED_MATCH,
        RA_STAT_DISCARDED,
        RA_STAT_ZERO_LEN,
        RA_STAT_ZERO_WINDOW,
        RA_STAT_EOF,
        RA_STAT_MAX_IN_FLIGHT,
        RA_STAT_WRONG_GRAB_PAGE,
        _NR_RA_STAT,
};

struct ll_ra_info {
        unsigned long             ra_cur_pages;
        unsigned long             ra_max_pages;
        unsigned long             ra_max_read_ahead_whole_pages;
        unsigned long             ra_stats[_NR_RA_STAT];
};

/* LL_HIST_MAX=32 causes an overflow */
#define LL_HIST_MAX 28
#define LL_HIST_START 12 /* buckets start at 2^12 = 4k */
#define LL_PROCESS_HIST_MAX 10
struct per_process_info {
        pid_t pid;
        struct obd_histogram pp_r_hist;
        struct obd_histogram pp_w_hist;
};

/* pp_extents[LL_PROCESS_HIST_MAX] will hold the combined process info */
struct ll_rw_extents_info {
        struct per_process_info pp_extents[LL_PROCESS_HIST_MAX + 1];
};

#define LL_OFFSET_HIST_MAX 100
struct ll_rw_process_info {
        pid_t                     rw_pid;
        int                       rw_op;
        loff_t                    rw_range_start;
        loff_t                    rw_range_end;
        loff_t                    rw_last_file_pos;
        loff_t                    rw_offset;
        size_t                    rw_smallest_extent;
        size_t                    rw_largest_extent;
        struct file               *rw_last_file;
};

/* flags for sbi->ll_flags */
#define LL_SBI_NOLCK             0x01 /* DLM locking disabled (directio-only) */
#define LL_SBI_CHECKSUM          0x02 /* checksum each page as it's written */
#define LL_SBI_FLOCK             0x04
#define LL_SBI_USER_XATTR        0x08 /* support user xattr */
#define LL_SBI_ACL               0x10 /* support ACL */
#define LL_SBI_JOIN              0x20 /* support JOIN */
#define LL_SBI_RMT_CLIENT        0x40 /* remote client */
#define LL_SBI_MDS_CAPA          0x80 /* support mds capa */
#define LL_SBI_OSS_CAPA         0x100 /* support oss capa */

struct ll_sb_info {
        struct list_head          ll_list;
        /* this protects pglist and ra_info.  It isn't safe to
         * grab from interrupt contexts */
        spinlock_t                ll_lock;
        struct obd_uuid           ll_sb_uuid;
        struct obd_export        *ll_md_exp;
        struct obd_export        *ll_dt_exp;
        struct proc_dir_entry*    ll_proc_root;
        struct lu_fid             ll_root_fid; /* root object fid */

        int                       ll_flags;
        struct list_head          ll_conn_chain; /* per-conn chain of SBs */
        struct lustre_client_ocd  ll_lco;

        struct list_head          ll_orphan_dentry_list; /*please don't ask -p*/
        struct ll_close_queue    *ll_lcq;

        struct lprocfs_stats     *ll_stats; /* lprocfs stats counter */

        unsigned long             ll_async_page_max;
        unsigned long             ll_async_page_count;
        unsigned long             ll_pglist_gen;
        struct list_head          ll_pglist; /* all pages (llap_pglist_item) */

        struct ll_ra_info         ll_ra_info;
        unsigned int              ll_namelen;
        struct file_operations   *ll_fop;

        struct list_head          ll_deathrow; /* inodes to be destroyed (b1443) */
        spinlock_t                ll_deathrow_lock;
        /* =0 - hold lock over whole read/write
         * >0 - max. chunk to be read/written w/o lock re-acquiring */
        unsigned long             ll_max_rw_chunk;
        struct ll_rw_extents_info ll_rw_extents_info;
        int                       ll_extent_process_count;
        struct ll_rw_process_info ll_rw_process_info[LL_PROCESS_HIST_MAX];
        unsigned int              ll_offset_process_count;
        struct ll_rw_process_info ll_rw_offset_info[LL_OFFSET_HIST_MAX];
        unsigned int              ll_rw_offset_entry_count;
};

#define LL_DEFAULT_MAX_RW_CHUNK         (32 * 1024 * 1024)

struct ll_ra_read {
        pgoff_t             lrr_start;
        pgoff_t             lrr_count;
        struct task_struct *lrr_reader;
        struct list_head    lrr_linkage;
};

/*
 * per file-descriptor read-ahead data.
 */
struct ll_readahead_state {
        spinlock_t      ras_lock;
        /*
         * index of the last page that read(2) needed and that wasn't in the
         * cache. Used by ras_update() to detect seeks.
         *
         * XXX nikita: if access seeks into cached region, Lustre doesn't see
         * this.
         */
        unsigned long   ras_last_readpage;
        /*
         * number of pages read after last read-ahead window reset. As window
         * is reset on each seek, this is effectively a number of consecutive
         * accesses. Maybe ->ras_accessed_in_window is better name.
         *
         * XXX nikita: window is also reset (by ras_update()) when Lustre
         * believes that memory pressure evicts read-ahead pages. In that
         * case, it probably doesn't make sense to expand window to
         * PTLRPC_MAX_BRW_PAGES on the third access.
         */
        unsigned long   ras_consecutive_pages;
        /*
         * number of read requests after the last read-ahead window reset
         * As window is reset on each seek, this is effectively the number
         * on consecutive read request and is used to trigger read-ahead.
         */
        unsigned long   ras_consecutive_requests;
        /*
         * Parameters of current read-ahead window. Handled by
         * ras_update(). On the initial access to the file or after a seek,
         * window is reset to 0. After 3 consecutive accesses, window is
         * expanded to PTLRPC_MAX_BRW_PAGES. Afterwards, window is enlarged by
         * PTLRPC_MAX_BRW_PAGES chunks up to ->ra_max_pages.
         */
        unsigned long   ras_window_start, ras_window_len;
        /*
         * Where next read-ahead should start at. This lies within read-ahead
         * window. Read-ahead window is read in pieces rather than at once
         * because: 1. lustre limits total number of pages under read-ahead by
         * ->ra_max_pages (see ll_ra_count_get()), 2. client cannot read pages
         * not covered by DLM lock.
         */
        unsigned long   ras_next_readahead;
        /*
         * Total number of ll_file_read requests issued, reads originating
         * due to mmap are not counted in this total.  This value is used to
         * trigger full file read-ahead after multiple reads to a small file.
         */
        unsigned long   ras_requests;
        /*
         * Page index with respect to the current request, these value
         * will not be accurate when dealing with reads issued via mmap.
         */
        unsigned long   ras_request_index;
        /*
         * list of struct ll_ra_read's one per read(2) call current in
         * progress against this file descriptor. Used by read-ahead code,
         * protected by ->ras_lock.
         */
        struct list_head ras_read_beads;
};

struct ll_file_dir {
};

extern kmem_cache_t *ll_file_data_slab;
struct lustre_handle;
struct ll_file_data {
        struct ll_readahead_state fd_ras;
        int fd_omode;
        struct lustre_handle fd_cwlockh;
        unsigned long fd_gid;
        struct ll_file_dir fd_dir;
        __u32 fd_flags;
};

struct lov_stripe_md;

extern spinlock_t inode_lock;

extern struct proc_dir_entry *proc_lustre_fs_root;

static inline struct inode *ll_info2i(struct ll_inode_info *lli)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        return &lli->lli_vfs_inode;
#else
        return list_entry(lli, struct inode, u.generic_ip);
#endif
}

struct it_cb_data {
        struct inode *icbd_parent;
        struct dentry **icbd_childp;
        obd_id hash;
};

void ll_i2gids(__u32 *suppgids, struct inode *i1,struct inode *i2);

#define LLAP_MAGIC 98764321

extern kmem_cache_t *ll_async_page_slab;
extern size_t ll_async_page_slab_size;
struct ll_async_page {
        int              llap_magic;
         /* only trust these if the page lock is providing exclusion */
        unsigned int     llap_write_queued:1,
                         llap_defer_uptodate:1,
                         llap_origin:3,
                         llap_ra_used:1,
                         llap_ignore_quota:1;
        void            *llap_cookie;
        struct page     *llap_page;
        struct list_head llap_pending_write;
        struct list_head llap_pglist_item;
        /* checksum for paranoid I/O debugging */
        __u32 llap_checksum;
};

/*
 * enumeration of llap_from_page() call-sites. Used to export statistics in
 * /proc/fs/lustre/llite/fsN/dump_page_cache.
 */
enum {
        LLAP_ORIGIN_UNKNOWN = 0,
        LLAP_ORIGIN_READPAGE,
        LLAP_ORIGIN_READAHEAD,
        LLAP_ORIGIN_COMMIT_WRITE,
        LLAP_ORIGIN_WRITEPAGE,
        LLAP_ORIGIN_REMOVEPAGE,
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

void ll_ra_read_in(struct file *f, struct ll_ra_read *rar);
void ll_ra_read_ex(struct file *f, struct ll_ra_read *rar);
struct ll_ra_read *ll_ra_read_get(struct file *f);

/* llite/lproc_llite.c */
#ifdef LPROCFS
int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block *sb, char *osc, char *mdc);
void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi);
#else
static inline int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                        struct super_block *sb, char *osc, char *mdc){return 0;}
static inline void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi) {}
#endif


/* llite/dir.c */
extern struct file_operations ll_dir_operations;
extern struct inode_operations ll_dir_inode_operations;

/* llite/namei.c */
int ll_objects_destroy(struct ptlrpc_request *request, struct inode *dir);
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *lic);
struct dentry *ll_find_alias(struct inode *, struct dentry *);
int ll_md_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
                       void *data, int flag);
int ll_md_cancel_unused(struct lustre_handle *, struct inode *, int flags,
                        void *opaque);
#ifndef LUSTRE_KERNEL_VERSION
struct lookup_intent *ll_convert_intent(struct open_intent *oit,
                                        int lookup_flags);
#endif

/* llite/rw.c */
int ll_prepare_write(struct file *, struct page *, unsigned from, unsigned to);
int ll_commit_write(struct file *, struct page *, unsigned from, unsigned to);
int ll_writepage(struct page *page);
void ll_inode_fill_obdo(struct inode *inode, int cmd, struct obdo *oa);
int ll_ap_completion(void *data, int cmd, struct obdo *oa, int rc);
int llap_shrink_cache(struct ll_sb_info *sbi, int shrink_fraction);
struct ll_async_page *llap_from_page(struct page *page, unsigned origin);
extern struct cache_definition ll_cache_definition;
void ll_removepage(struct page *page);
int ll_readpage(struct file *file, struct page *page);
struct ll_async_page *llap_from_cookie(void *cookie);
struct ll_async_page *llap_cast_private(struct page *page);
void ll_readahead_init(struct inode *inode, struct ll_readahead_state *ras);
void ll_ra_accounting(struct ll_async_page *llap,struct address_space *mapping);
void ll_truncate(struct inode *inode);

/* llite/file.c */
extern struct file_operations ll_file_operations;
extern struct file_operations ll_file_operations_flock;
extern struct inode_operations ll_file_inode_operations;
extern int ll_inode_revalidate_it(struct dentry *, struct lookup_intent *);
extern int ll_have_md_lock(struct inode *inode, __u64 bits);
int ll_extent_lock(struct ll_file_data *, struct inode *,
                   struct lov_stripe_md *, int mode, ldlm_policy_data_t *,
                   struct lustre_handle *, int ast_flags);
int ll_extent_unlock(struct ll_file_data *, struct inode *,
                     struct lov_stripe_md *, int mode, struct lustre_handle *);
int ll_file_open(struct inode *inode, struct file *file);
int ll_file_release(struct inode *inode, struct file *file);
int ll_lsm_getattr(struct obd_export *, struct lov_stripe_md *, struct obdo *);
int ll_local_size(struct inode *inode);
int ll_glimpse_ioctl(struct ll_sb_info *sbi, 
                     struct lov_stripe_md *lsm, lstat_t *st);
int ll_glimpse_size(struct inode *inode, int ast_flags);
int ll_local_open(struct file *file,
                  struct lookup_intent *it, struct ll_file_data *fd,
                  struct obd_client_handle *och);
int ll_release_openhandle(struct dentry *, struct lookup_intent *);
int ll_md_close(struct obd_export *md_exp, struct inode *inode,
                struct file *file);
int ll_md_real_close(struct inode *inode, int flags);
void ll_epoch_close(struct inode *inode, struct md_op_data *op_data,
                    struct obd_client_handle **och, unsigned long flags);
int ll_sizeonmds_update(struct inode *inode, struct lustre_handle *fh);
int ll_inode_getattr(struct inode *inode, struct obdo *obdo);
int ll_md_setattr(struct inode *inode, struct md_op_data *op_data);
void ll_pack_inode2opdata(struct inode *inode, struct md_op_data *op_data,
                          struct lustre_handle *fh);
extern void ll_rw_stats_tally(struct ll_sb_info *sbi, pid_t pid, struct file
                               *file, size_t count, int rw);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
int ll_getattr_it(struct vfsmount *mnt, struct dentry *de,
               struct lookup_intent *it, struct kstat *stat);
int ll_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat);
#endif
struct ll_file_data *ll_file_data_get(void);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd);
#else
int ll_inode_permission(struct inode *inode, int mask);
#endif

/* llite/dcache.c */
void ll_intent_drop_lock(struct lookup_intent *);
void ll_intent_release(struct lookup_intent *);
int ll_drop_dentry(struct dentry *dentry);
extern void ll_set_dd(struct dentry *de);
int ll_drop_dentry(struct dentry *dentry);
void ll_unhash_aliases(struct inode *);
void ll_frob_intent(struct lookup_intent **itp, struct lookup_intent *deft);
void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry);
int ll_dcompare(struct dentry *parent, struct qstr *d_name, struct qstr *name);
int ll_revalidate_it_finish(struct ptlrpc_request *request, int offset,
                            struct lookup_intent *it, struct dentry *de);

/* llite/llite_lib.c */
extern struct super_operations lustre_super_operations;

char *ll_read_opt(const char *opt, char *data);
void ll_lli_init(struct ll_inode_info *lli);
int ll_fill_super(struct super_block *sb);
void ll_put_super(struct super_block *sb);
struct inode *ll_inode_from_lock(struct ldlm_lock *lock);
void ll_clear_inode(struct inode *inode);
int ll_setattr_raw(struct inode *inode, struct iattr *attr);
int ll_setattr(struct dentry *de, struct iattr *attr);
int ll_statfs(struct super_block *sb, struct kstatfs *sfs);
int ll_statfs_internal(struct super_block *sb, struct obd_statfs *osfs,
                       __u64 max_age);
void ll_update_inode(struct inode *inode, struct lustre_md *md);
void ll_read_inode2(struct inode *inode, void *opaque);
void ll_delete_inode(struct inode *inode);
int ll_iocontrol(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg);
int ll_flush_ctx(struct inode *inode);
void ll_umount_begin(struct super_block *sb);
int ll_remount_fs(struct super_block *sb, int *flags, char *data);
int ll_prep_inode(struct inode **inode, struct ptlrpc_request *req,
                  int offset, struct super_block *);
void lustre_dump_dentry(struct dentry *, int recur);
void lustre_dump_inode(struct inode *);
struct ll_async_page *llite_pglist_next_llap(struct ll_sb_info *sbi,
                                             struct list_head *list);
int ll_obd_statfs(struct inode *inode, void *arg);
int ll_get_max_mdsize(struct ll_sb_info *sbi, int *max_mdsize);
int ll_process_config(struct lustre_cfg *lcfg);
int ll_ioctl_getfacl(struct inode *inode, struct rmtacl_ioctl_data *ioc);
int ll_ioctl_setfacl(struct inode *inode, struct rmtacl_ioctl_data *ioc);
struct md_op_data *ll_prep_md_op_data(struct md_op_data *op_data,
                                      struct inode *i1, struct inode *i2,
                                      const char *name, int namelen,
                                      int mode, __u32 opc);
void ll_finish_md_op_data(struct md_op_data *op_data);

/* llite/llite_nfs.c */
extern struct export_operations lustre_export_operations;
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
        struct list_head        lcq_head;
        wait_queue_head_t       lcq_waitq;
        struct completion       lcq_comp;
        atomic_t                lcq_stop;
};

void llap_write_pending(struct inode *inode, struct ll_async_page *llap);
int llap_write_complete(struct inode *inode, struct ll_async_page *llap);
int ll_inode_dirty(struct inode *inode, unsigned long flags);
void ll_queue_done_writing(struct inode *inode, unsigned long flags);
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


#define LL_MAX_BLKSIZE          (4UL * 1024 * 1024)

#define    ll_s2sbi(sb)        (s2lsi(sb)->lsi_llsbi)

#if  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
void __d_rehash(struct dentry * entry, int lock);
static inline __u64 ll_ts2u64(struct timespec *time)
{
        __u64 t = time->tv_sec;
        return t;
}
#else  /* 2.4 here */
static inline __u64 ll_ts2u64(time_t *time)
{
        return *time;
}
#endif

/* don't need an addref as the sb_info should be holding one */
static inline struct obd_export *ll_s2dtexp(struct super_block *sb)
{
        return ll_s2sbi(sb)->ll_dt_exp;
}

/* don't need an addref as the sb_info should be holding one */
static inline struct obd_export *ll_s2mdexp(struct super_block *sb)
{
        return ll_s2sbi(sb)->ll_md_exp;
}

static inline struct client_obd *sbi2mdc(struct ll_sb_info *sbi)
{
        struct obd_device *obd = sbi->ll_md_exp->exp_obd;
        if (obd == NULL)
                LBUG();
        return &obd->u.cli;
}

// FIXME: replace the name of this with LL_SB to conform to kernel stuff
static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return ll_s2sbi(inode->i_sb);
}

static inline struct obd_export *ll_i2dtexp(struct inode *inode)
{
        return ll_s2dtexp(inode->i_sb);
}

static inline struct obd_export *ll_i2mdexp(struct inode *inode)
{
        return ll_s2mdexp(inode->i_sb);
}

static inline struct lu_fid *ll_inode2fid(struct inode *inode)
{
        LASSERT(inode != NULL);
        return &ll_i2info(inode)->lli_fid;
}

static inline int ll_mds_max_easize(struct super_block *sb)
{
        return sbi2mdc(ll_s2sbi(sb))->cl_max_mds_easize;
}

static inline __u64 ll_file_maxbytes(struct inode *inode)
{
        return ll_i2info(inode)->lli_maxbytes;
}

/* llite/xattr.c */
int ll_setxattr(struct dentry *dentry, const char *name,
                const void *value, size_t size, int flags);
ssize_t ll_getxattr(struct dentry *dentry, const char *name,
                    void *buffer, size_t size);
ssize_t ll_listxattr(struct dentry *dentry, char *buffer, size_t size);
int ll_removexattr(struct dentry *dentry, const char *name);

/* llite/remote_perm.c */
extern kmem_cache_t *ll_remote_perm_cachep;
extern kmem_cache_t *ll_rmtperm_hash_cachep;

struct hlist_head *alloc_rmtperm_hash(void);
void free_rmtperm_hash(struct hlist_head *hash);
int ll_update_remote_perm(struct inode *inode, struct mdt_remote_perm *perm);
int lustre_check_remote_perm(struct inode *inode, int mask);

/* llite/llite_fid.c */
ino_t ll_fid_build_ino(struct ll_sb_info *sbi, struct lu_fid *fid);

/* llite/llite_capa.c */
extern cfs_timer_t ll_capa_timer;

int ll_capa_thread_start(void);
void ll_capa_thread_stop(void);
void ll_capa_timer_callback(unsigned long unused);

struct obd_capa *ll_add_capa(struct inode *inode, struct obd_capa *ocapa);
int ll_update_capa(struct obd_capa *ocapa, struct lustre_capa *capa);

void ll_capa_open(struct inode *inode);
void ll_capa_close(struct inode *inode);

struct obd_capa *ll_mdscapa_get(struct inode *inode);
struct obd_capa *ll_osscapa_get(struct inode *inode, __u64 opc);

void ll_truncate_free_capa(struct obd_capa *ocapa);
void ll_clear_inode_capas(struct inode *inode);

#endif /* LLITE_INTERNAL_H */
