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
int ll_prepare_write(struct file *file, struct page *page, unsigned from,
                            unsigned to);
int ll_commit_write(struct file *file, struct page *page, unsigned from,
                    unsigned to);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define ll_complete_writeback ll_complete_writepage_24
void ll_complete_writepage_24(struct obd_client_page *ocp, int rc);
#else 
#define ll_complete_writeback ll_complete_writepage_26
void ll_complete_writepage_26(struct obd_client_page *ocp, int rc);
#endif
int ll_sync_page(struct page *page);
int ll_ocp_update_obdo(struct obd_client_page *ocp, int cmd, struct obdo *oa);
void ll_removepage(struct page *page);
int ll_readpage(struct file *file, struct page *page);

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
int ll_extent_lock_no_validate(struct ll_file_data *, struct inode *,
                               struct lov_stripe_md *, int mode,
                               struct ldlm_extent *, struct lustre_handle *,
                               int ast_flags);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
int ll_getattr(struct vfsmount *mnt, struct dentry *de,
               struct lookup_intent *it, struct kstat *stat);
#endif

/* llite/dcache.c */
void ll_intent_release(struct lookup_intent *);
extern void ll_set_dd(struct dentry *de);
void ll_unhash_aliases(struct inode *);
void ll_frob_intent(struct lookup_intent **itp, struct lookup_intent *deft);
void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry);

/* llite/llite_lib.c */

extern struct super_operations ll_super_operations;

char *ll_read_opt(const char *opt, char *data);
int ll_set_opt(const char *opt, char *data, int fl);
void ll_options(char *options, char **ost, char **mds, int *flags);
void ll_lli_init(struct ll_inode_info *lli);
int ll_fill_super(struct super_block *sb, void *data, int silent);
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
void ll_umount_begin(struct super_block *sb);
int ll_prep_inode(struct obd_export *exp, struct inode **inode, 
                struct ptlrpc_request *req, int offset, struct super_block *sb);

/* llite/symlink.c */
extern struct inode_operations ll_fast_symlink_inode_operations;

#endif /* LLITE_INTERNAL_H */
