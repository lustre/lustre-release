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
 *
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/lvfs.h>
#include "smfs_internal.h"

#define size_round(x)  (((x)+3) & ~0x3)

void *smfs_trans_start(struct inode *inode, int op, void *desc_private)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;

        CDEBUG(D_INFO, "trans start %p\n", fsfilt->fs_start);

        SMFS_TRANS_OP(inode, op);

        /* There are some problem here. fs_start in fsfilt is used by lustre
         * the journal blocks of write rec are not counted in FIXME later */
        if (fsfilt->fs_start)
                return fsfilt->fs_start(inode, op, desc_private, 0);
        return NULL;
}

void smfs_trans_commit(struct inode *inode, void *handle, int force_sync)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;

        CDEBUG(D_INFO, "trans commit %p\n", fsfilt->fs_commit);

        if (fsfilt->fs_commit)
                fsfilt->fs_commit(inode, handle, force_sync);
}

/*smfs_path is gotten from intermezzo*/
static char* smfs_path(struct dentry *dentry, struct dentry *root, char *buffer,
                       int buflen)
{
        char * end = buffer+buflen;
        char * name = buffer;
        char * buf_end = buffer + buflen;
        char * retval;

        *--end = '\0';
        buflen--;
        /* Get '/' right */
        retval = end-1;
        *retval = '/';

        for (;;) {
                struct dentry * parent;
                int namelen;

                if (dentry == root)
                        break;
                parent = dentry->d_parent;
                if (dentry == parent)
                        break;
                namelen = dentry->d_name.len;
                buflen -= namelen + 1;
                if (buflen < 0)
                        break;
                end -= namelen;
                memcpy(end, dentry->d_name.name, namelen);
                *--end = '/';
                retval = end;
                dentry = parent;
        }

        while (end != buf_end)
                *name++ = *end++;
        *name = '\0';
        return retval;
}
static int smfs_log_path(struct dentry *root, struct dentry *dentry,
                         char *buffer, int buffer_len)
{
        char *p_name = buffer + sizeof(int);
        char *name = NULL;
        int namelen = 0;

        name = smfs_path(dentry, root, p_name, buffer_len);
        namelen = cpu_to_le32(strlen(p_name));
        memcpy(buffer, &namelen, sizeof(int));

        namelen += sizeof(int);
        RETURN(namelen);
}

static inline int log_it(char *buffer, void *data, int length)
{
        memcpy(buffer, &length, sizeof(int));
        memcpy(buffer + sizeof(int), data, length);
        return (sizeof(int) + length);
}

static int smfs_post_rec_create(struct inode *dir, struct dentry *dentry,
                                void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        struct dentry *root;
        struct update_record *rec = NULL;
        char *buffer = NULL, *p_name;
        int rc = 0, buffer_length = 0;
        ENTRY;

        sinfo = S2SMI(dentry->d_inode->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);

        OBD_ALLOC(buffer, PAGE_SIZE + sizeof(struct update_record));
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        rec = (struct update_record*)buffer;

        smfs_rec_pack(rec, dentry->d_inode, dir, REINT_CREATE);

        p_name = buffer + sizeof(struct update_record);

        root = dir->i_sb->s_root;

        rc = smfs_log_path(root, dentry, p_name, PAGE_SIZE);
        if (rc < 0) {
                GOTO(exit, rc);
        } else {
                buffer_length += rc;
                rc = 0;
        }
        if (data1) {
                /*for symlink data is the path of the symname*/
                int data_len = strlen(data1);

                buffer_length += log_it(p_name + buffer_length,
                                        data1, data_len);
        }
        rec->ur_len = sizeof(struct update_record) + buffer_length;
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, rec->ur_len);
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE + sizeof(struct update_record));

        RETURN(rc);
}

static int smfs_post_rec_link(struct inode *dir, struct dentry *dentry,
                              void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        struct dentry *root;
        struct dentry *new_dentry = (struct dentry *)data1;
        struct update_record *rec = NULL;
        char *buffer = NULL, *p_name = NULL;
        int rc = 0, buffer_length = 0;
        ENTRY;

        sinfo = S2SMI(dir->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);
        OBD_ALLOC(buffer, PAGE_SIZE + sizeof(struct update_record));
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);

        rec = (struct update_record*)buffer;

        smfs_rec_pack(rec, dentry->d_inode, NULL, REINT_LINK);

        root = dir->i_sb->s_root;
        /*record old_dentry path*/
        p_name = buffer + sizeof(struct update_record);
        rc = smfs_log_path(root, dentry, p_name, PAGE_SIZE);
        if (rc < 0)
                GOTO(exit, rc);

        buffer_length += rc;
        p_name += buffer_length;

        /*record new_dentry path*/
        rc = smfs_log_path(root, new_dentry, p_name,
                           PAGE_SIZE - rc - sizeof(int));
        if (rc < 0) {
                GOTO(exit, rc);
        } else {
                buffer_length += rc;
                rc = 0;
        }
        rec->ur_len = sizeof(struct update_record) + buffer_length;
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, rec->ur_len);

exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE + sizeof(struct update_record));
        RETURN(rc);
}

static int smfs_post_rec_unlink(struct inode *dir, struct dentry *dentry,
                                void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        struct dentry *root;
        int flag = *((int*)data1);
        struct update_record *rec = NULL;
        char *buffer = NULL, *p_name;
        int rc = 0, buffer_length = 0;
        char fidname[LL_FID_NAMELEN];
        struct dentry *new_child = NULL;
        int namelen;
        ENTRY;

        sinfo = S2SMI(dentry->d_inode->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);

        OBD_ALLOC(buffer, PAGE_SIZE + sizeof(struct update_record));
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        rec = (struct update_record*)buffer;

        smfs_rec_pack(rec, dentry->d_inode, dir, REINT_UNLINK);

        p_name = buffer + sizeof(struct update_record);

        root = dir->i_sb->s_root;
        rc = smfs_log_path(root, dentry, p_name, PAGE_SIZE);
        if (rc < 0)
                GOTO(exit, rc);

        buffer_length += rc;
        p_name += rc;

        if (!flag) {
                /*unlink the inode*/
                namelen = ll_fid2str(fidname, dentry->d_inode->i_ino,
                                     dentry->d_inode->i_generation);

                down(&sinfo->smsi_delete_dir->d_inode->i_sem);
                new_child = lookup_one_len(fidname, sinfo->smsi_delete_dir, namelen);
                if (new_child->d_inode != NULL) {
                        CERROR("has been deleted obj dentry %lu:%u!\n",
                               dentry->d_inode->i_ino,
                               dentry->d_inode->i_generation);
                        LBUG();
                }

                /* FIXME-WANGDI: this is ugly, but I do not know how to resolve
                 * it. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                up(&dir->i_zombie);
#endif
                lock_kernel();
                SMFS_CLEAN_INODE_REC(dir);
                rc = vfs_rename(dir, dentry, sinfo->smsi_delete_dir->d_inode,
                                new_child);
                SMFS_SET_INODE_REC(dir);
                unlock_kernel();
                
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                down(&dir->i_zombie);
#endif
                up(&sinfo->smsi_delete_dir->d_inode->i_sem);
                if (rc)
                        GOTO(exit, rc);
                /* in vfs_unlink the inode on the dentry will be deleted, so we
                 * should delete it from dentry hash. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                list_del_init(&dentry->d_hash);
#else
                hlist_del_init(&dentry->d_hash);
#endif
                
                /* put the new_file_name to the log. */
                rc = smfs_log_path(root, dentry, p_name,
                                   PAGE_SIZE - buffer_length);
                if (rc < 0)
                        GOTO(exit, rc);
                buffer_length += rc;
                rc = 0;
        } else {
                /*only decrease the link count*/
                namelen = sizeof(ino_t);

                buffer_length += log_it(p_name + buffer_length,
                                        &(dentry->d_inode->i_ino), namelen);
                SET_REC_DEC_LINK_FLAGS(rec->ur_flags, SMFS_DEC_LINK);
        }
        rec->ur_len = sizeof(struct update_record) + buffer_length;
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, rec->ur_len);
exit:
        if (new_child);
                dput(new_child);
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE + sizeof(struct update_record));

        RETURN(rc);
}

static int smfs_post_rec_rename(struct inode *dir, struct dentry *dentry,
                                void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        struct dentry *root;
        struct inode *new_dir = (struct inode *)data1;
        struct dentry *new_dentry = (struct dentry *)data2;
        struct update_record *rec = NULL;
        char *buffer = NULL, *p_name = NULL;
        int rc = 0, buffer_length = 0;
        ENTRY;

        sinfo = S2SMI(dir->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);

        OBD_ALLOC(buffer, PAGE_SIZE + sizeof(struct update_record));
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);

        rec = (struct update_record*)buffer;

        smfs_rec_pack(rec, dentry->d_inode, dir, REINT_RENAME);

        root = dir->i_sb->s_root;
        /*record old_dentry path*/
        p_name = buffer + sizeof(struct update_record);
        rc = smfs_log_path(root, dentry, p_name, PAGE_SIZE);
        if (rc < 0)
                GOTO(exit, rc);

        buffer_length += rc;
        p_name += rc;

        root = new_dir->i_sb->s_root;
        /*record new_dentry path*/
        rc = smfs_log_path(root, new_dentry, p_name,
                           PAGE_SIZE - rc - sizeof(int));
        if (rc < 0) {
                GOTO(exit, rc);
        } else {
                buffer_length += rc;
                rc = 0;
        }
        rec->ur_len = sizeof(struct update_record) + buffer_length;
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, rec->ur_len);
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE + sizeof(struct update_record));
        RETURN(rc);
}

static int smfs_post_rec_setattr(struct inode *dir, struct dentry *dentry,
                                 void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        struct dentry *root;
        struct iattr *attr = (struct iattr *)data1;
        struct update_record *rec = NULL;
        char *buffer = NULL, *p_name;
        int rc = 0, buffer_length = 0;
        ENTRY;

        sinfo = S2SMI(dentry->d_inode->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);

        OBD_ALLOC(buffer, PAGE_SIZE + sizeof(struct update_record));
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        rec = (struct update_record*)buffer;

        smfs_rec_pack(rec, dentry->d_inode, attr, REINT_SETATTR);

        root = dentry->d_inode->i_sb->s_root;
        /*record old_dentry path*/
        p_name = buffer + sizeof(struct update_record);
        rc = smfs_log_path(root, dentry, p_name, PAGE_SIZE);

        if (rc < 0) {
                GOTO(exit, rc);
        } else {
                buffer_length += rc;
                rc = 0;
        }
        rec->ur_len = sizeof(struct update_record) + buffer_length;
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, rec->ur_len);
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE + sizeof(struct update_record));
        RETURN(rc);
}
static int smfs_post_rec_open_close(struct inode *dir, struct dentry *dentry,
                                    void *data1, void *data2)
{
        struct smfs_super_info *sinfo;
        struct dentry *root;
        int open = *(int*)data1;
        struct update_record *rec = NULL;
        char *buffer = NULL, *p_name;
        int rc = 0, buffer_length = 0;
        ENTRY;

        sinfo = S2SMI(dentry->d_inode->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);

        OBD_ALLOC(buffer, PAGE_SIZE + sizeof(struct update_record));
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        rec = (struct update_record*)buffer;
        if (open)
                smfs_rec_pack(rec, dentry->d_inode, NULL, REINT_OPEN);
        else
                smfs_rec_pack(rec, dentry->d_inode, NULL, REINT_CLOSE);
        root = dentry->d_inode->i_sb->s_root;
        /*record old_dentry path*/
        p_name = buffer + sizeof(struct update_record);
        rc = smfs_log_path(root, dentry, p_name, PAGE_SIZE);

        if (rc < 0) {
                GOTO(exit, rc);
        } else {
                buffer_length += rc;
                rc = 0;
        }
        rec->ur_len = sizeof(struct update_record) + buffer_length;
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, rec->ur_len);
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE + sizeof(struct update_record));
        RETURN(rc);
}

static int smfs_post_rec_write(struct inode *dir, struct dentry *dentry,
                               void *data1, void *data2)
{
        struct smfs_record_extents extents;
        struct smfs_super_info *sinfo;
        struct dentry *root;
        struct update_record *rec = NULL;
        char *buffer = NULL, *p_name;
        int extents_length = 0;
        int rc = 0, buffer_length = 0;
        ENTRY;

        sinfo = S2SMI(dentry->d_inode->i_sb);
        if (!sinfo)
                RETURN(-EINVAL);

        OBD_ALLOC(buffer, PAGE_SIZE + sizeof(struct update_record));
        if (!buffer)
                GOTO(exit, rc = -ENOMEM);
        rec = (struct update_record*)buffer;

        smfs_rec_pack(rec, dentry->d_inode, NULL, REINT_OPEN);

        root = dentry->d_inode->i_sb->s_root;
        /*record old_dentry path*/
        p_name = buffer + sizeof(struct update_record);
        rc = smfs_log_path(root, dentry, p_name, PAGE_SIZE);

        if (rc < 0) {
                GOTO(exit, rc);
        } else {
                buffer_length += rc;
                rc = 0;
        }
        /*record the extents of this write*/
        extents.sre_count = *((size_t*)data1);
        extents.sre_off = *((loff_t*)data2);
        extents_length = sizeof(struct smfs_record_extents);

        buffer_length += log_it(p_name + buffer_length,
                                &extents, extents_length);
        rec->ur_len = sizeof(struct update_record) + buffer_length;
        rc = smfs_llog_add_rec(sinfo, (void*)buffer, rec->ur_len);
exit:
        if (buffer)
                OBD_FREE(buffer, PAGE_SIZE + sizeof(struct update_record));
        RETURN(rc);
}

typedef int (*post_kml_rec)(struct inode *dir, struct dentry *dentry,
                            void *data1, void *data2);

static post_kml_rec smfs_kml_post[REINT_MAX + 1] = {
        [REINT_SETATTR] smfs_post_rec_setattr,
        [REINT_CREATE]  smfs_post_rec_create,
        [REINT_LINK]    smfs_post_rec_link,
        [REINT_UNLINK]  smfs_post_rec_unlink,
        [REINT_RENAME]  smfs_post_rec_rename,
        [REINT_OPEN]    smfs_post_rec_open_close,
        [REINT_CLOSE]   smfs_post_rec_open_close,
        [REINT_WRITE]   smfs_post_rec_write,
};

int smfs_post_kml_rec(struct inode *dir, struct dentry *dst_dentry,
                      void *data1, void *data2, int op)
{
        return smfs_kml_post[op](dir, dst_dentry, data1, data2);
}
