/*  
 *  snapfs/cache.c
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <portals/list.h>
#include "smfs_internal.h" 
struct sm_ops smfs_operations;
 
extern struct inode_operations smfs_file_iops;
extern struct file_operations  smfs_file_fops;
extern struct address_space_operations smfs_file_aops;
extern struct inode_operations smfs_sym_iops; 
extern struct file_operations smfs_sym_fops;
extern struct super_operations smfs_super_ops;

inline struct super_operations *cache_sops(struct sm_ops *smfs_ops)
{
	return &smfs_ops->sm_sb_ops;
}

inline struct inode_operations *cache_diops(struct sm_ops *smfs_ops)
{
	return &smfs_ops->sm_dir_iops;
}

inline struct inode_operations *cache_fiops(struct sm_ops *smfs_ops)
{
	return &smfs_ops->sm_file_iops;
}

inline struct inode_operations *cache_siops(struct sm_ops *smfs_ops)
{
	return &smfs_ops->sm_sym_iops;
}

inline struct file_operations *cache_dfops(struct sm_ops *smfs_ops) 
{
	return &smfs_ops->sm_dir_fops;
}

inline struct file_operations *cache_ffops(struct sm_ops *smfs_ops)
{
	return &smfs_ops->sm_file_fops;
}

inline struct address_space_operations *cache_faops(struct sm_ops *smfs_ops) 
{
	return &smfs_ops->sm_file_aops;
}

inline struct file_operations *cache_sfops(struct sm_ops *smfs_ops)
{
	return &smfs_ops->sm_sym_fops;
}

inline struct dentry_operations *cache_dops(struct sm_ops *smfs_ops)
{
	return &smfs_ops->sm_dentry_ops;
}

void init_smfs_cache()
{
	memset(&smfs_operations, 0, sizeof(struct sm_ops)); 
}
void cleanup_smfs_cache()
{
	return;
}

static void setup_iops(struct inode *cache_inode, 
		       struct inode_operations *iops,
		       struct inode_operations *cache_iops)
{

	if (cache_inode->i_op && cache_iops && iops) {
		if (cache_inode->i_op->create) 
			iops->create = cache_iops->create;
		if (cache_inode->i_op->create_it) 
			iops->create_it = cache_iops->create_it;
		if (cache_inode->i_op->lookup)
			iops->lookup = cache_iops->lookup;
		if (cache_inode->i_op->lookup_raw)
			iops->lookup_raw = cache_iops->lookup_raw;
		if (cache_inode->i_op->lookup_it)
			iops->lookup_it = cache_iops->lookup_it;
		if (cache_inode->i_op->link)
			iops->link = cache_iops->link;
		if (cache_inode->i_op->link_raw)
			iops->link_raw = cache_iops->link_raw;
		if (cache_inode->i_op->unlink)
			iops->unlink = cache_iops->unlink;
		if (cache_inode->i_op->unlink_raw)
			iops->unlink_raw = cache_iops->unlink_raw;
		if (cache_inode->i_op->symlink)
			iops->symlink = cache_iops->symlink;
		if (cache_inode->i_op->symlink_raw)
			iops->symlink_raw = cache_iops->symlink_raw;
		if (cache_inode->i_op->mkdir)
			iops->mkdir = cache_iops->mkdir;
		if (cache_inode->i_op->mkdir_raw)
			iops->mkdir_raw = cache_iops->mkdir_raw;
		if (cache_inode->i_op->rmdir)
			iops->rmdir = cache_iops->rmdir;
		if (cache_inode->i_op->rmdir_raw)
			iops->rmdir_raw = cache_iops->rmdir_raw;
		if (cache_inode->i_op->mknod)
			iops->mknod = cache_iops->mknod;
		if (cache_inode->i_op->mknod_raw)
			iops->mknod_raw = cache_iops->mknod_raw;
		if (cache_inode->i_op->rename)
			iops->rename = cache_iops->rename;
		if (cache_inode->i_op->rename_raw)
			iops->rename_raw = cache_iops->rename_raw;
		if (cache_inode->i_op->readlink)
			iops->readlink = cache_iops->readlink;
		if (cache_inode->i_op->follow_link)
			iops->follow_link = cache_iops->follow_link;
		if (cache_inode->i_op->truncate)
			iops->truncate = cache_iops->truncate;
		if (cache_inode->i_op->permission)
			iops->permission = cache_iops->permission;
		if (cache_inode->i_op->revalidate)
			iops->revalidate = cache_iops->revalidate;
		if (cache_inode->i_op->revalidate_it)
			iops->revalidate_it = cache_iops->revalidate_it;
		if (cache_inode->i_op->setattr)
			iops->setattr = cache_iops->setattr;
		if (cache_inode->i_op->setattr_raw)
			iops->setattr_raw = cache_iops->setattr_raw;
		if (cache_inode->i_op->getattr)
			iops->getattr = cache_iops->getattr;
		if (cache_inode->i_op->setxattr)
			iops->setxattr = cache_iops->setxattr;
		if (cache_inode->i_op->getxattr)
			iops->getxattr = cache_iops->getxattr;
		if (cache_inode->i_op->listxattr)
			iops->listxattr = cache_iops->listxattr;
		if (cache_inode->i_op->removexattr)
			iops->removexattr = cache_iops->removexattr;
	}
}
static void setup_fops(struct inode *cache_inode,
		       struct file_operations *fops,
		       struct file_operations *cache_fops)
{
	if (cache_inode->i_fop && cache_fops && fops) {
		if (cache_inode->i_fop->llseek)
			fops->llseek = cache_fops->llseek;
		if (cache_inode->i_fop->read)
			fops->read = cache_fops->read;
		if (cache_inode->i_fop->write)
			fops->write = cache_fops->write;
		if (cache_inode->i_fop->readdir)
			fops->readdir = cache_fops->readdir;
		if (cache_inode->i_fop->poll)
			fops->poll = cache_fops->poll;
		if (cache_inode->i_fop->ioctl)
			fops->ioctl = cache_fops->ioctl;
		if (cache_inode->i_fop->mmap)
			fops->mmap = cache_fops->mmap;
		if (cache_inode->i_fop->open)
			fops->open = cache_fops->open;
		if (cache_inode->i_fop->flush)
			fops->flush = cache_fops->flush;
		if (cache_inode->i_fop->release)
			fops->release = cache_fops->release;
		if (cache_inode->i_fop->fsync)
			fops->fsync = cache_fops->fsync;
		if (cache_inode->i_fop->fasync)
			fops->fasync = cache_fops->fasync;
		if (cache_inode->i_fop->lock)
			fops->lock = cache_fops->lock;
		if (cache_inode->i_fop->readv)
			fops->readv = cache_fops->readv;
		if (cache_inode->i_fop->writev)
			fops->writev = cache_fops->writev;
		if (cache_inode->i_fop->sendpage)
			fops->sendpage = cache_fops->sendpage;
		if (cache_inode->i_fop->get_unmapped_area)
			fops->get_unmapped_area = cache_fops->get_unmapped_area;										 	
	}
}
static void setup_aops(struct inode *cache_inode,
		       struct address_space_operations *aops,
		       struct address_space_operations *cache_aops)
{
	if (cache_inode && cache_inode->i_mapping && 
	    aops && cache_aops) {
		struct address_space_operations *caops = cache_inode->i_mapping->a_ops;

		if (caops->writepage) 
			aops->writepage = cache_aops->writepage;
		if (caops->readpage)
			aops->readpage = cache_aops->readpage;
		if (caops->sync_page)
			aops->sync_page = cache_aops->sync_page;
		if (caops->prepare_write)
			aops->prepare_write = cache_aops->prepare_write;
		if (caops->commit_write)
			aops->commit_write = cache_aops->commit_write;
		if (caops->bmap)
			aops->bmap = cache_aops->bmap;
		if (caops->flushpage)
			aops->flushpage = cache_aops->flushpage;
		if (caops->releasepage)
			aops->releasepage = cache_aops->releasepage;
		if (caops->direct_IO)
			aops->direct_IO = cache_aops->direct_IO;
		if (caops->removepage)
			aops->removepage = cache_aops->removepage;
	}									
};
		
static void setup_sm_file_ops(struct inode *cache_inode, 
		       	      struct inode *inode,
		       	      struct inode_operations *cache_iops,
		              struct file_operations *cache_fops,
		              struct address_space_operations *cache_aops)
{
	
	struct smfs_super_info *smb;
	struct inode_operations *iops;
	struct file_operations *fops;
        struct address_space_operations *aops;

	smb = S2SMI(inode->i_sb); 
	
	if (smb->ops_check & FILE_OPS_CHECK) 
		return; 
	smb->ops_check |= FILE_OPS_CHECK;

	iops = cache_fiops(&smfs_operations);
	fops = cache_ffops(&smfs_operations);
	aops = cache_faops(&smfs_operations);

	memset(iops , 0 , sizeof (struct inode_operations));	
	memset(fops , 0 , sizeof (struct file_operations));	
	memset(aops , 0 , sizeof (struct address_space_operations));	

	setup_iops(cache_inode, iops, cache_iops); 	
	setup_fops(cache_inode, fops, cache_fops);
	setup_aops(cache_inode, aops, cache_aops);

	return;
}

static void setup_sm_dir_ops(struct inode *cache_inode, 
			     struct  inode *inode,
		       	     struct inode_operations *cache_dir_iops,
			     struct file_operations *cache_dir_fops)
{
	struct smfs_super_info *smb;
	struct inode_operations *iops;
	struct file_operations *fops;

	smb = S2SMI(inode->i_sb); 
	
	if (smb->ops_check & DIR_OPS_CHECK) 
		return; 
	smb->ops_check |= DIR_OPS_CHECK;

	iops = cache_diops(&smfs_operations);
	fops = cache_dfops(&smfs_operations);

	memset(iops, 0, sizeof (struct inode_operations));	
	memset(fops, 0, sizeof (struct file_operations));	

	setup_iops(cache_inode, iops, cache_dir_iops); 	
	setup_fops(cache_inode, fops, cache_dir_fops);

	return;
}

static void setup_sm_symlink_ops(struct inode *cache_inode, 
				 struct  inode *inode,
		       		 struct inode_operations *cache_sym_iops,
				 struct file_operations *cache_sym_fops)
{
	struct smfs_super_info *smb;
	struct inode_operations *iops;
	struct file_operations *fops;

	smb = S2SMI(inode->i_sb); 
	
	if (smb->ops_check & SYMLINK_OPS_CHECK) 
		return; 
	smb->ops_check |= SYMLINK_OPS_CHECK;

	iops = cache_siops(&smfs_operations);
	fops = cache_sfops(&smfs_operations);

	memset(iops , 0 , sizeof (struct inode_operations));	
	memset(fops , 0 , sizeof (struct file_operations));	

	setup_iops(cache_inode, iops, cache_sym_iops); 	
	setup_fops(cache_inode, fops, cache_sym_fops);

	return;
}

static void setup_sm_sb_ops(struct super_block *cache_sb, 
			    struct super_block *sb, 
			    struct super_operations *smfs_sops)	
{
	struct smfs_super_info *smb;
        struct super_operations *sops;

	ENTRY;

	smb = S2SMI(sb); 
	
	if (smb->ops_check & SB_OPS_CHECK) 
		return; 
	smb->ops_check |= SB_OPS_CHECK;
	sops = cache_sops(&smfs_operations);
	memset(sops, 0, sizeof (struct super_operations));	

	if (cache_sb->s_op) {
		if (cache_sb->s_op->read_inode) 
			sops->read_inode = smfs_sops->read_inode;
		if (cache_sb->s_op->read_inode2)
			sops->read_inode2 = smfs_sops->read_inode2;
		if (cache_sb->s_op->dirty_inode)
			sops->dirty_inode = smfs_sops->dirty_inode;
		if (cache_sb->s_op->write_inode)
			sops->write_inode = smfs_sops->write_inode;
		if (cache_sb->s_op->put_inode)
			sops->put_inode = smfs_sops->put_inode;
		if (cache_sb->s_op->delete_inode)
			sops->delete_inode = smfs_sops->delete_inode;
		if (cache_sb->s_op->put_super)
			sops->put_super = smfs_sops->put_super;
		if (cache_sb->s_op->write_super)
			sops->write_super = smfs_sops->write_super;
		if (cache_sb->s_op->write_super_lockfs)
			sops->write_super_lockfs = smfs_sops->write_super_lockfs;
		if (cache_sb->s_op->unlockfs)
			sops->unlockfs = smfs_sops->unlockfs;
		if (cache_sb->s_op->statfs)
			sops->statfs = smfs_sops->statfs;
		if (cache_sb->s_op->remount_fs)
			sops->remount_fs = smfs_sops->remount_fs;
		if (cache_sb->s_op->clear_inode)
			sops->clear_inode = smfs_sops->clear_inode;
		if (cache_sb->s_op->umount_begin)
			sops->umount_begin = smfs_sops->umount_begin;
		if (cache_sb->s_op->fh_to_dentry)
			sops->fh_to_dentry = smfs_sops->fh_to_dentry;
		if (cache_sb->s_op->dentry_to_fh)
			sops->dentry_to_fh = smfs_sops->dentry_to_fh;
		if (cache_sb->s_op->show_options)
			sops->show_options = smfs_sops->show_options;
	}
					
	return;
}	
void sm_set_inode_ops(struct inode *cache_inode, struct inode *inode)
{
        /* XXX now set the correct snap_{file,dir,sym}_iops */
        if (S_ISDIR(inode->i_mode)) {
       	        setup_sm_dir_ops(cache_inode, inode,
                                 &smfs_dir_iops,
                                 &smfs_dir_fops);
	        inode->i_op = cache_diops(&smfs_operations);
                inode->i_fop = cache_dfops(&smfs_operations);
        } else if (S_ISREG(inode->i_mode)) {
	        setup_sm_file_ops(cache_inode, inode,
                                  &smfs_file_iops,
                                  &smfs_file_fops,
                                  &smfs_file_aops);
                CDEBUG(D_INODE, "inode %lu, i_op at %p\n",
                       inode->i_ino, inode->i_op);
                inode->i_fop = cache_ffops(&smfs_operations);
                inode->i_op = cache_fiops(&smfs_operations);
                if (inode->i_mapping)
                        inode->i_mapping->a_ops = cache_faops(&smfs_operations);
        
	} else if (S_ISLNK(inode->i_mode)) {
                setup_sm_symlink_ops(cache_inode, inode,
                                     &smfs_sym_iops, 
				     &smfs_sym_fops);
                inode->i_op = cache_siops(&smfs_operations);
                inode->i_fop = cache_sfops(&smfs_operations);
                CDEBUG(D_INODE, "inode %lu, i_op at %p\n",
                       inode->i_ino, inode->i_op);
        }
}
void sm_set_sb_ops (struct super_block *cache_sb,
		      struct super_block *sb)
{
	struct smfs_super_info *smb;

	smb = S2SMI(sb); 
	
	setup_sm_sb_ops(cache_sb, sb, &smfs_super_ops);	
	
	sb->s_op = cache_sops(&smfs_operations);
	return;	
}

