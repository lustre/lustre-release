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


struct ll_sb_info;
struct lustre_handle;
struct lov_stripe_md;

extern void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi);
extern struct proc_dir_entry *proc_lustre_fs_root;

struct ll_read_inode2_cookie {
        struct mds_body      *lic_body;
        struct lov_stripe_md *lic_lsm;
};


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

/* llite/commit_callback.c */
int ll_commitcbd_setup(struct ll_sb_info *);
int ll_commitcbd_cleanup(struct ll_sb_info *);

/* lproc_llite.c */
int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block *sb, char *osc, char *mdc);
void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi);

/* llite/namei.c */
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct ll_read_inode2_cookie *lic);
struct dentry *ll_find_alias(struct inode *, struct dentry *);
int ll_it_open_error(int phase, struct lookup_intent *it);
int ll_mdc_cancel_unused(struct lustre_handle *conn, struct inode *inode,
                         int flags, void *opaque);

/* llite/rw.c */
void ll_end_writeback(struct inode *, struct page *);

void ll_remove_dirty(struct inode *inode, unsigned long start,
                     unsigned long end);
int ll_rd_dirty_pages(char *page, char **start, off_t off, int count,
                      int *eof, void *data);
int ll_rd_max_dirty_pages(char *page, char **start, off_t off, int count,
                          int *eof, void *data);
int ll_wr_max_dirty_pages(struct file *file, const char *buffer,
                          unsigned long count, void *data);
int ll_clear_dirty_pages(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                         unsigned long start, unsigned long end);
int ll_mark_dirty_page(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                       unsigned long index);

/* llite/file.c */
extern int ll_inode_revalidate_it(struct dentry *dentry, struct lookup_intent *);

/* llite/super.c */
int ll_inode_setattr(struct inode *inode, struct iattr *attr, int do_trunc);
int ll_setattr(struct dentry *de, struct iattr *attr);

/* iod.c */
#define IO_STAT_ADD(FIS, STAT, VAL) do {        \
        struct file_io_stats *_fis_ = (FIS);    \
        spin_lock(&_fis_->fis_lock);            \
        _fis_->fis_##STAT += VAL;               \
        spin_unlock(&_fis_->fis_lock);          \
} while (0)

#define INODE_IO_STAT_ADD(INODE, STAT, VAL)        \
        IO_STAT_ADD(&ll_i2sbi(INODE)->ll_iostats, STAT, VAL)

#define PAGE_IO_STAT_ADD(PAGE, STAT, VAL)               \
        INODE_IO_STAT_ADD((PAGE)->mapping, STAT, VAL)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
/* XXX lliod needs more work in 2.5 before being proven and brought back
 * to 2.4, it'll at least require a patch to introduce page->private */
int lliod_start(struct ll_sb_info *sbi, struct inode *inode);
void lliod_stop(struct ll_sb_info *sbi);
#else
#define lliod_start(sbi, inode) ({int _ret = 0; (void)sbi, (void)inode; _ret;})
#define lliod_stop(sbi) do { (void)sbi; } while (0)
#endif
void lliod_wakeup(struct inode *inode);
void lliod_give_plist(struct inode *inode, struct plist *plist, int rw);
void lliod_give_page(struct inode *inode, struct page *page, int rw);
void plist_init(struct plist *plist); /* for lli initialization.. */

void ll_lldo_init(struct ll_dirty_offsets *lldo);
void ll_record_dirty(struct inode *inode, unsigned long offset);
void ll_remove_dirty(struct inode *inode, unsigned long start,
                     unsigned long end);
int ll_find_dirty(struct ll_dirty_offsets *lldo, unsigned long *start,
                  unsigned long *end);
int ll_farthest_dirty(struct ll_dirty_offsets *lldo, unsigned long *farthest);


/* llite/super25.c */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
int ll_getattr(struct vfsmount *mnt, struct dentry *de,
               struct lookup_intent *it, 
               struct kstat *stat);
#endif


/* llite/dcache.c */
void ll_intent_release(struct lookup_intent *);
extern void ll_set_dd(struct dentry *de);

/* llite/rw.c */
void ll_truncate(struct inode *inode);
void ll_end_writeback(struct inode *inode, struct page *page);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
int ll_check_dirty( struct super_block *sb );
int ll_batch_writepage( struct inode *inode, struct page *page );
#else
#define ll_check_dirty(SB) do { (void)SB; } while (0)
#endif

/* llite/llite_lib.c */

extern struct super_operations ll_super_operations;

char *ll_read_opt(const char *opt, char *data);
int ll_set_opt(const char *opt, char *data, int fl);
void ll_options(char *options, char **ost, char **mds, int *flags);
void ll_lli_init(struct ll_inode_info *lli);
int ll_fill_super(struct super_block *sb, void *data, int silent);
void ll_put_super(struct super_block *sb);
void ll_clear_inode(struct inode *inode);
int ll_attr2inode(struct inode *inode, struct iattr *attr, int trunc);
int ll_inode_setattr(struct inode *inode, struct iattr *attr, int do_trunc);
int ll_setattr_raw(struct inode *inode, struct iattr *attr);
int ll_setattr(struct dentry *de, struct iattr *attr);
int ll_statfs(struct super_block *sb, struct kstatfs *sfs);
void ll_update_inode(struct inode *inode, struct mds_body *body,
                     struct lov_stripe_md *lsm);
void ll_read_inode2(struct inode *inode, void *opaque);
void ll_umount_begin(struct super_block *sb);

#endif /* LLITE_INTERNAL_H */
