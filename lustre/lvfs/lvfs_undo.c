/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include <linux/jbd.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/version.h>
#include <linux/kp30.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/lustre_compat25.h>
#include <linux/lvfs.h>
#include <linux/lustre_smfs.h>
#include "lvfs_internal.h"

#include <linux/obd.h>
#include <linux/lustre_lib.h>

static int lvfs_undo_create(struct super_block *sb, 
                            struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char *path = r_rec->rec_data1;
        int type = r_rec->u_rec.ur_iattr.ia_mode & S_IFMT;
       	struct nameidata nd;
	struct dentry *dparent = NULL;
	struct dentry *dentry = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        int rc = 0;

	rc = lookup_by_path(path, LOOKUP_PARENT, &nd); 
        if (rc)
                RETURN(rc); 
       
        dparent = nd.dentry; 
        dir = dparent->d_inode;
        
        down(&dir->i_sem);
        dentry = lookup_one_len(nd.last.name, dparent, nd.last.len);    
        
	if (!dentry->d_inode || is_bad_inode(dentry->d_inode)) {
		up(&dir->i_sem);
                if (dentry)
                        l_dput(dentry);
                path_release(&nd);
        	RETURN(-ENODEV);
        } 
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);
        
        switch(type) {  
        case S_IFREG:
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                handle = fsfilt->fs_start(dir, FSFILT_OP_UNLINK, NULL, 0);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = vfs_unlink(dir, dentry);
                if (rc)
                        CERROR("unlink in error path: %d\n", rc);
                break;
        case S_IFDIR:
                handle = fsfilt->fs_start(dir, FSFILT_OP_RMDIR, NULL, 0);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                
                rc = vfs_rmdir(dir, dentry);
                if (rc)
                        CERROR("rmdir in error path: %d\n", rc);
                break;
        default:
                CERROR("Error type %d in create\n", type);
                rc = -EINVAL;
                break;
        }  
       
        if (rc) {
                CERROR("Error for undo node %s\n", path);
                GOTO(cleanup, 0); 
        } else {
                /*restore time attr of dir inode*/
                struct iattr *iattr = &r_rec->u_rec.ur_pattr;
                
                iattr->ia_valid = ATTR_MTIME | ATTR_CTIME;
                rc = fsfilt->fs_setattr(dparent, handle, iattr, 0);
                if (rc) {
                        CERROR("error on parent setattr: rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }
        }
cleanup:
        if (handle) 
                rc = fsfilt->fs_commit(dparent->d_inode, handle, 0);
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        if (dentry)
                l_dput(dentry);
        up(&dir->i_sem);
        path_release(&nd);
        RETURN(0);
};

static int lvfs_undo_link(struct super_block *sb, 
                          struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char   *new_path = r_rec->rec_data2;
       	struct nameidata nd;
	struct dentry *dparent = NULL;
	struct dentry *dentry = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        int rc = 0;

	rc = lookup_by_path(new_path, LOOKUP_PARENT, &nd); 
        if (rc)
                RETURN(rc); 
       
        dparent = nd.dentry; 
        dir = dparent->d_inode;
        
        down(&dir->i_sem);
        dentry = lookup_one_len(nd.last.name, dparent, nd.last.len);    
        
	if (!dentry->d_inode || is_bad_inode(dentry->d_inode)) {
		up(&dir->i_sem);
                path_release(&nd);
        	RETURN(-ENODEV);
        } 
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);
        
        handle = fsfilt->fs_start(dir, FSFILT_OP_UNLINK, NULL, 0);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));
        rc = vfs_unlink(dir, dentry);
        if (rc)
                CERROR("unlink in error path: %d\n", rc);

        if (rc) {
                CERROR("Error for undo node %s\n", new_path);
                GOTO(cleanup, 0); 
        } else {
                /*restore time attr of dir inode*/
                struct iattr *iattr = &r_rec->u_rec.ur_pattr;
                
                iattr->ia_valid = ATTR_MTIME | ATTR_CTIME;
                rc = fsfilt->fs_setattr(dparent, handle, iattr, 0);
                if (rc) {
                        CERROR("error on parent setattr: rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }
        }
cleanup:
        if (handle) 
                rc = fsfilt->fs_commit(dir, handle, 0);
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        if (dentry)
                l_dput(dentry);
        up(&dir->i_sem);
        path_release(&nd);
        RETURN(0);
}       

static int lvfs_undo_unlink(struct super_block *sb, 
                             struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char   *path = r_rec->rec_data1;
        struct nameidata nd;
        struct dentry *dparent;
	struct dentry *dentry = NULL;
        struct nameidata del_nd;
        struct dentry *del_dparent = NULL;
	struct dentry *del_dentry = NULL;
        void   *handle = NULL;
        struct inode *dir = NULL;
        int    rc = 0;
        
        /*get parent dentry*/	
        rc = lookup_by_path(path, LOOKUP_PARENT, &nd); 
        if (rc)
                RETURN(rc); 
       
        dparent = nd.dentry;
        dir = dparent->d_inode;
        
        dentry = lookup_create(&nd, 0);
        
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);
        if (SMFS_DO_DEC_LINK(r_rec->u_rec.ur_flags)) {
                ino_t ino = *((ino_t *)r_rec->rec_data2);
                struct inode* inode = iget(dir->i_sb, ino);
                if (!inode) 
                        GOTO(cleanup1, rc = -EINVAL);        
                handle = fsfilt->fs_start(dir, FSFILT_OP_LINK, NULL, 0);
                if (IS_ERR(handle))
                        GOTO(cleanup1, rc = PTR_ERR(handle));
                
                del_dentry = pre_smfs_dentry(NULL, inode, dentry);
                rc = vfs_link(del_dentry, dir, dentry); 
cleanup1:
                post_smfs_dentry(del_dentry);
                iput(inode);
        } else {
                char   *del_path = r_rec->rec_data2;
                             
                rc = lookup_by_path(del_path, LOOKUP_PARENT, &del_nd);
                if (rc) 
                        GOTO(cleanup, rc = -ENODEV);
                del_dparent = del_nd.dentry;
                del_dentry = lookup_one_len(del_nd.last.name, del_dparent, 
                                    del_nd.last.len);    

                if (! del_dentry || !del_dentry->d_inode 
                    || is_bad_inode(del_dentry->d_inode)) 
                        GOTO(cleanup2, rc = -ENODEV);

                handle = fsfilt->fs_start(dir, FSFILT_OP_RENAME, NULL, 0);
                if (IS_ERR(handle))
                        GOTO(cleanup2, rc = PTR_ERR(handle));

                lock_kernel();
                /*move the del dentry back to the original palace*/
                rc = vfs_rename(del_dparent->d_inode, del_dentry, dir, dentry);
                unlock_kernel();
                if (!rc && S_ISDIR(del_dentry->d_inode->i_mode))
                        del_dentry->d_inode->i_flags &=~S_DEAD;
cleanup2:
                if (del_dentry)
                        l_dput(del_dentry);
                path_release(&del_nd);
        }
        if (!rc) {
               /*restore time attr of dir inode*/
                struct iattr *iattr = &r_rec->u_rec.ur_pattr;
                
                iattr->ia_valid = ATTR_MTIME | ATTR_CTIME;
                rc = fsfilt->fs_setattr(dparent, handle, iattr, 0);
                if (rc) {
                        CERROR("error on parent setattr: rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }
        } 
cleanup:
        if (handle) 
                fsfilt->fs_commit(dir, handle, 0);
        if (dentry);
                l_dput(dentry);
        path_release(&nd);
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        RETURN(rc);
}

static int lvfs_undo_rename(struct super_block *sb, 
                             struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char   *path = r_rec->rec_data1;
        char   *new_path = r_rec->rec_data2;
        struct nameidata nd;
        struct nameidata new_nd;
        struct dentry *dparent;
        struct dentry *new_dparent;
	struct dentry *dentry = NULL;
	struct dentry *new_dentry = NULL;
        void   *handle = NULL;
        struct inode *dir = NULL;
        struct inode *new_dir = NULL;
        int    rc = 0;
        
        /*get parent dentry*/	
        rc = lookup_by_path(path, LOOKUP_PARENT, &nd); 
        if (rc)
                RETURN(rc); 
       
        dparent = nd.dentry;
        dir = dparent->d_inode;
        dentry = lookup_create(&nd, 0);
        
        rc = lookup_by_path(new_path, LOOKUP_PARENT, &new_nd);
        if (rc) {
                path_release(&nd); 
                RETURN(rc);
        }
        new_dparent = new_nd.dentry;
        new_dir = new_dparent->d_inode;
        new_dentry = lookup_one_len(new_nd.last.name, new_dparent, 
                                    new_nd.last.len);    
        
        if (! new_dentry || !new_dentry->d_inode 
            || is_bad_inode(new_dentry->d_inode)) {
                GOTO(cleanup, rc = -ENODEV);
        }       
        
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(new_dir);
	 
        handle = fsfilt->fs_start(new_dir, FSFILT_OP_RENAME, NULL, 0);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        lock_kernel();
        /*move the del dentry back to the original palace*/
        rc = vfs_rename(new_dir, new_dentry, dir, dentry);
        unlock_kernel();
        if (rc) {
                CERROR("Error for undo node %s\n", new_path);
                GOTO(cleanup, 0); 
        } else {
                /*restore time attr of dir inode*/
                struct iattr *iattr = &r_rec->u_rec.ur_pattr;
                
                iattr->ia_valid = ATTR_MTIME | ATTR_CTIME;
                rc = fsfilt->fs_setattr(dparent, handle, iattr, 0);
                if (rc) {
                        CERROR("error on parent setattr: rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }
        }
cleanup:
        if (handle) 
                rc = fsfilt->fs_commit(new_dir, handle, 0);
        if (dentry);
		l_dput(dentry);
        if (new_dentry)
                l_dput(new_dentry);
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(new_dir);
        path_release(&nd);
        path_release(&new_nd);
        RETURN(rc);
};

static int lvfs_undo_setattr(struct super_block *sb, 
                             struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char *path = r_rec->rec_data1;
       	struct nameidata nd;
	struct dentry *dparent = NULL;
	struct dentry *dentry = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        int rc = 0;

        rc = lookup_by_path(path, LOOKUP_PARENT, &nd); 
        if (rc)
                RETURN(rc); 
        
        dparent = nd.dentry;
        dir = dparent->d_inode;
        dentry = lookup_one_len(nd.last.name, dparent, nd.last.len);
 
        if (!dentry || !dentry->d_inode 
            || is_bad_inode(dentry->d_inode)) {
                path_release(&nd);
                RETURN(rc);
        }       
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags)) 
                SMFS_CLEAN_INODE_REC(dir);
        handle = fsfilt->fs_start(dir, FSFILT_OP_SETATTR, NULL, 0);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));
        
        /*FIXME later, did not set parent attr*/
        r_rec->u_rec.ur_iattr.ia_valid = r_rec->u_rec.ur_pattr.ia_valid;
        rc = fsfilt->fs_setattr(dentry, handle, &r_rec->u_rec.ur_iattr, 0);
cleanup:  
        if (handle)
                fsfilt->fs_commit(dir, handle, 0); 
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        if (dentry)
                l_dput(dentry);
        path_release(&nd);
        RETURN(0);
       
        RETURN(0);
}; 


typedef int (*lvfs_undoer)(struct super_block *sb, struct reint_record *);

static lvfs_undoer undoers[REINT_MAX + 1] = {
        [REINT_SETATTR] lvfs_undo_setattr,
        [REINT_CREATE] lvfs_undo_create,
        [REINT_LINK] lvfs_undo_link,
        [REINT_UNLINK] lvfs_undo_unlink,
        [REINT_RENAME] lvfs_undo_rename,
};

int lvfs_undo(struct super_block *sb, 
              void *r_rec)
{
        return  undoers[((struct reint_record*)r_rec)->u_rec.ur_opcode](sb, 
                         (struct reint_record *)r_rec);     
};

EXPORT_SYMBOL(lvfs_undo);
