/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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

int lookup_by_path(char *path, int flags, struct nameidata *nd)
{
	struct dentry *dentry = NULL;
        int rc = 0;
        
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (path_init(path, flags, nd)) {
#else
        if (path_lookup(path, flags, nd)) {
#endif
		rc = path_walk(path, nd);
		if (rc)
			RETURN(rc);
	} else
		RETURN(-EINVAL);

	dentry = nd->dentry;

	if (!dentry->d_inode || is_bad_inode(dentry->d_inode) || 
	    (!S_ISDIR(dentry->d_inode->i_mode))) { 
		path_release(nd);
		RETURN(-ENODEV);
	}
        RETURN(rc); 
}  

struct dentry *lookup_create(struct nameidata *nd, int is_dir)
{
        struct dentry *dentry;

        dentry = ERR_PTR(-EEXIST);
        if (nd->last_type != LAST_NORM)
                goto fail;
        dentry = lookup_hash(&nd->last, nd->dentry);
        if (IS_ERR(dentry))
                goto fail;
        if (!is_dir && nd->last.name[nd->last.len] && !dentry->d_inode)
                goto enoent;
        return dentry;
enoent:
        dput(dentry);
        dentry = ERR_PTR(-ENOENT);
fail:
        return dentry;
}

static int lvfs_reint_create(struct super_block *sb, struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char *path = r_rec->name.path_name;
        int type = r_rec->u_rec.ur_iattr.ia_mode & S_IFMT;
        struct nameidata nd;
        struct dentry *dparent = NULL;
        struct dentry *dentry = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        int rc = 0, created = 0, err = 0;
        ENTRY;

        rc = lookup_by_path(path, LOOKUP_PARENT, &nd);
        if (rc)
                RETURN(rc);

        dparent = nd.dentry;

        down(&dparent->d_inode->i_sem);
        /*create a new dentry*/
        dentry = lookup_create(&nd, 0);
        dir = dparent->d_inode;

        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);

        switch(type) {
        case S_IFREG:
                handle = fsfilt->fs_start(dir, FSFILT_OP_CREATE, NULL, 0);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = ll_vfs_create(dir, dentry, r_rec->u_rec.ur_iattr.ia_mode,
                                   NULL);
                break;
        case S_IFDIR:
                handle = fsfilt->fs_start(dir, FSFILT_OP_MKDIR, NULL, 0);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = vfs_mkdir(dir, dentry, r_rec->u_rec.ur_iattr.ia_mode);
                break;
        case S_IFLNK: {
                char *new_path = r_rec->u.re_name.path_name;
                handle = fsfilt->fs_start(dir, FSFILT_OP_SYMLINK, NULL, 0);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = vfs_symlink(dir, dentry, new_path);
                break;
        }
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK: {
                int rdev = r_rec->u_rec.ur_rdev;
                handle = fsfilt->fs_start(dir, FSFILT_OP_MKNOD, NULL, 0);
                if (IS_ERR(handle))
                        GOTO(cleanup, (handle = NULL, rc = PTR_ERR(handle)));
                rc = vfs_mknod(dir, dentry, r_rec->u_rec.ur_iattr.ia_mode,
                               rdev);
                break;
        }
        default:
                CERROR("Error type %d in create\n", type);
                rc = -EINVAL;
                break;
        }

        if (rc) {
                CERROR("Error for creating mkdir %s\n", path);
                GOTO(cleanup, 0);
        } else {
                struct iattr iattr;

                created = 1;

                LTIME_S(iattr.ia_atime) =
                        LTIME_S(r_rec->u_rec.ur_iattr.ia_atime);
                LTIME_S(iattr.ia_ctime) =
                        LTIME_S(r_rec->u_rec.ur_iattr.ia_ctime);
                LTIME_S(iattr.ia_mtime) =
                        LTIME_S(r_rec->u_rec.ur_iattr.ia_mtime);

                iattr.ia_uid = r_rec->u_rec.ur_fsuid;
                if (dir->i_mode & S_ISGID)
                        iattr.ia_gid = dir->i_gid;
                else
                        iattr.ia_gid = r_rec->u_rec.ur_fsgid;
                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                rc = fsfilt->fs_setattr(dentry, handle, &iattr, 0);
                if (rc) {
                        CERROR("error on child setattr: rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }

                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                rc = fsfilt->fs_setattr(dparent, handle, &iattr, 0);
                if (rc) {
                        CERROR("error on parent setattr: rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }
        }
cleanup:
        if (rc && created) {
                /* Destroy the file we just created.  This should not need
                 * extra journal credits, as we have already modified all of
                 * the blocks needed in order to create the file in the first
                 * place.
                 */
                switch (type) {
                case S_IFDIR:
                        err = vfs_rmdir(dir, dentry);
                        if (err)
                                CERROR("rmdir in error path: %d\n", err);
                        break;
                default:
                        err = vfs_unlink(dir, dentry);
                        if (err)
                                CERROR("unlink in error path: %d\n", err);
                        break;
                }
        } else {
                rc = err;
        }
        if (handle)
                rc = fsfilt->fs_commit(dentry->d_inode, handle, 0);

        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        up(&dparent->d_inode->i_sem);
        path_release(&nd);
        if (dentry)
                l_dput(dentry);

        RETURN(0);
};

static int lvfs_reint_link(struct super_block *sb, struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char   *old_path = r_rec->name.path_name;
        char   *new_path = r_rec->u.re_name.path_name;
        struct nameidata old_nd;
        struct nameidata new_nd;
        struct dentry *old_dparent;
        struct dentry *new_dparent;
        struct dentry *old_dentry = NULL;
        struct dentry *new_dentry = NULL;
        void   *handle = NULL;
        struct inode *dir = NULL;
        int    rc = 0;
        ENTRY;

        /*get parent dentry*/
        rc = lookup_by_path(new_path, LOOKUP_PARENT, &new_nd);
        if (rc)
                RETURN(rc);

        new_dparent = new_nd.dentry;

        dir = new_dparent->d_inode;

        new_dentry = lookup_create(&new_nd, 0);

        rc = lookup_by_path(old_path, LOOKUP_PARENT, &old_nd);
        if (rc) {
                path_release(&new_nd);
                RETURN(rc);
        }
        old_dparent = old_nd.dentry;
        old_dentry = lookup_one_len(old_nd.last.name, old_dparent,
                                    old_nd.last.len);

        if (!old_dentry || !old_dentry->d_inode ||
            is_bad_inode(old_dentry->d_inode))
                GOTO(cleanup, rc = -ENODEV);
        if (dir->i_rdev != old_dentry->d_inode->i_rdev)
                GOTO(cleanup, rc = -EINVAL);

        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);

        handle = fsfilt->fs_start(dir, FSFILT_OP_LINK, NULL, 0);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        rc = vfs_link(old_dentry, dir, new_dentry);
        if (rc) {
                CERROR("replay error: vfs_link error rc=%d", rc);
                GOTO(cleanup, rc);
        }
cleanup:
        if (handle)
                rc = fsfilt->fs_commit(dir, handle, 0);
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        if (old_dentry)
                l_dput(old_dentry);
        if (new_dentry)
                l_dput(new_dentry);
        path_release(&new_nd);
        path_release(&old_nd);
        RETURN(rc);
};

static int lvfs_reint_unlink(struct super_block *sb, struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        int type = r_rec->u_rec.ur_iattr.ia_mode & S_IFMT;
        char *path = r_rec->name.path_name;
        struct nameidata nd;
        struct dentry *dparent = NULL;
        struct dentry *dentry = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        int rc = 0;
        ENTRY;

        rc = lookup_by_path(path, LOOKUP_PARENT, &nd);
        if (rc)
                RETURN(rc);

        dparent = nd.dentry;

        dir = dparent->d_inode;

        dentry = lookup_one_len(nd.last.name, dparent, nd.last.len);
        if (!dentry || !dentry->d_inode || is_bad_inode(dentry->d_inode))
                GOTO(cleanup, rc = -ENODEV);

        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);

        handle = fsfilt->fs_start(dir, FSFILT_OP_UNLINK, NULL, 0);

        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        switch (type) {
        case S_IFDIR:
                rc = vfs_rmdir(dir, dentry);
                if (rc)
                        CERROR("rmdir in error path: %d\n", rc);
                break;
        default:
                rc = vfs_unlink(dir, dentry);
                if (rc)
                        CERROR("unlink in error path: %d\n", rc);
                break;
        }
        if (!rc) {
                /*time attr of dir inode*/
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
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        if (dentry)
                l_dput(dentry);
        path_release(&nd);
        RETURN(rc);
};

static int lvfs_reint_rename(struct super_block *sb, struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char *path = r_rec->name.path_name;
        char *new_path = r_rec->u.re_name.path_name;
        struct nameidata nd, new_nd;
        struct dentry *dparent = NULL;
        struct dentry *new_dparent = NULL;
        struct dentry *dentry = NULL;
        struct dentry *new_dentry = NULL;
        struct inode *dir = NULL;
        struct inode *new_dir = NULL;
        void *handle = NULL;
        int rc = 0;
        ENTRY;

        rc = lookup_by_path(path, LOOKUP_PARENT, &nd);
        if (rc)
                RETURN(rc);

        dparent = nd.dentry;
        dir = dparent->d_inode;
        dentry = lookup_one_len(nd.last.name, dparent, nd.last.len);

        if (!dentry || !dentry->d_inode || is_bad_inode(dentry->d_inode)) {
                path_release(&nd);
                RETURN(rc);
        }
        rc = lookup_by_path(new_path, LOOKUP_PARENT, &new_nd);
        if (rc) {
                path_release(&nd);
                path_release(&new_nd);
                RETURN(rc);
        }
        new_dparent = new_nd.dentry;
        new_dir = new_dparent->d_inode;
        new_dentry = lookup_create(&new_nd, 0);

        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);

        handle = fsfilt->fs_start(dir, FSFILT_OP_RENAME, NULL, 0);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        rc = vfs_rename(dir, dentry, new_dir, new_dentry);
        if (rc) {
                CERROR("unlink in error path: %d\n", rc);
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
                rc = fsfilt->fs_setattr(new_dparent, handle, iattr, 0);
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
        if (new_dentry)
                l_dput(new_dentry);
        path_release(&nd);
        path_release(&new_nd);
        RETURN(0);
};

static int lvfs_reint_setattr(struct super_block *sb,
                              struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char *path = r_rec->name.path_name;
        struct nameidata nd;
        struct dentry *dparent = NULL;
        struct dentry *dentry = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        int rc = 0;
        ENTRY;

        rc = lookup_by_path(path, LOOKUP_PARENT, &nd);
        if (rc)
                RETURN(rc);

        dparent = nd.dentry;
        dir = dparent->d_inode;
        dentry = lookup_one_len(nd.last.name, dparent, nd.last.len);

        if (!dentry || !dentry->d_inode || is_bad_inode(dentry->d_inode)) {
                path_release(&nd);
                RETURN(rc);
        }
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);
        handle = fsfilt->fs_start(dir, FSFILT_OP_SETATTR, NULL, 0);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));
        rc = fsfilt->fs_setattr(dentry, handle, &r_rec->u_rec.ur_pattr, 0);
cleanup:
        if (handle)
                fsfilt->fs_commit(dir, handle, 0);
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        if (dentry)
                l_dput(dentry);
        path_release(&nd);
        RETURN(0);
};

static int lvfs_reint_close(struct super_block *sb, struct reint_record *r_rec)
{
        struct fsfilt_operations *fsfilt = S2SMI(sb)->sm_fsfilt;
        char   *path = r_rec->name.path_name;
        struct nameidata nd;
        struct dentry *dparent = NULL;
        struct dentry *dentry = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        struct iattr *iattr = &r_rec->u_rec.ur_iattr;
        int rc = 0;
        ENTRY;

        rc = lookup_by_path(path, LOOKUP_PARENT, &nd);
        if (rc)
                RETURN(rc);

        dparent = nd.dentry;
        dir = dparent->d_inode;
        dentry = lookup_one_len(nd.last.name, dparent, nd.last.len);

        if (!dentry || !dentry->d_inode || is_bad_inode(dentry->d_inode)) {
                path_release(&nd);
                RETURN(rc);
        }
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_CLEAN_INODE_REC(dir);
        handle = fsfilt->fs_start(dir, FSFILT_OP_CREATE, NULL, 0);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        iattr->ia_valid = ATTR_MTIME | ATTR_CTIME | ATTR_SIZE;
        rc = fsfilt->fs_setattr(dentry, handle, iattr, 0);
        if (rc) {
                CERROR("error on parent setattr: rc = %d\n", rc);
                GOTO(cleanup, rc);
        }
cleanup:
        if (handle)
                fsfilt->fs_commit(dir, handle, 0);
        if (!SMFS_DO_WRITE_KML(r_rec->u_rec.ur_flags))
                SMFS_SET_INODE_REC(dir);
        if (dentry)
                l_dput(dentry);
        path_release(&nd);
        RETURN(0);
};

typedef int (*lvfs_reinter)(struct super_block *sb, struct reint_record *);
static lvfs_reinter reinters[REINT_MAX + 1] = {
        [REINT_SETATTR] lvfs_reint_setattr,
        [REINT_CREATE] lvfs_reint_create,
        [REINT_LINK] lvfs_reint_link,
        [REINT_UNLINK] lvfs_reint_unlink,
        [REINT_RENAME] lvfs_reint_rename,
        [REINT_CLOSE] lvfs_reint_close,
};
int lvfs_reint(struct super_block *sb, void *r_rec)
{
        return reinters[((struct reint_record*)r_rec)->u_rec.ur_opcode](sb,
                        (struct reint_record *)r_rec);
};

EXPORT_SYMBOL(lvfs_reint);
