/* llite_lib.c */
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

