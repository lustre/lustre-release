/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc.
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

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/smp_lock.h>
#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>

static int ll_readlink_internal(struct inode *inode,
                                struct ptlrpc_request **request, char **symname)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc, symlen = inode->i_size + 1;
        ENTRY;

        *request = NULL;

        if (lli->lli_symlink_name) {
                *symname = lli->lli_symlink_name;
                CDEBUG(D_INODE, "using cached symlink %s\n", *symname);
                RETURN(0);
        }

        rc = mdc_getattr(&sbi->ll_mdc_conn, inode->i_ino, S_IFLNK,
                         OBD_MD_LINKNAME, symlen, request);
        if (rc) {
                CERROR("inode %lu: rc = %d\n", inode->i_ino, rc);
                RETURN(rc);
        }

        *symname = lustre_msg_buf((*request)->rq_repmsg, 1);

        OBD_ALLOC(lli->lli_symlink_name, symlen);
        /* do not return an error if we cannot cache the symlink locally */
        if (lli->lli_symlink_name)
                memcpy(lli->lli_symlink_name, *symname, symlen);

        RETURN(0);
}

static int ll_readlink(struct dentry *dentry, char *buffer, int buflen)
{
        struct inode *inode = dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ptlrpc_request *request;
        char *symname;
        int rc;
        ENTRY;

        /* on symlinks lli_open_sem protects lli_symlink_name allocation/data */
        down(&lli->lli_open_sem);
        rc = ll_readlink_internal(inode, &request, &symname);
        if (rc)
                GOTO(out, rc);

        rc = vfs_readlink(dentry, buffer, buflen, symname);
 out:
        up(&lli->lli_open_sem);
        ptlrpc_req_finished(request);

        RETURN(rc);
}

static int ll_follow_link(struct dentry *dentry, struct nameidata *nd,
                          struct lookup_intent *it)
{
        struct inode *inode = dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ptlrpc_request *request;
        int op = 0, mode = 0, rc;
        char *symname;
        ENTRY;

        if (it != NULL) {
                op = it->it_op;
                mode = it->it_mode;

                ll_intent_release(dentry, it);
        }

        down(&lli->lli_open_sem);
        rc = ll_readlink_internal(inode, &request, &symname);
        up(&lli->lli_open_sem);
        if (rc)
                GOTO(out, rc);

        if (it != NULL) {
                it->it_op = op;
                it->it_mode = mode;
        }

        rc = vfs_follow_link_it(nd, symname, it);
 out:
        ptlrpc_req_finished(request);

        RETURN(rc);
}

extern int ll_inode_revalidate(struct dentry *dentry);
extern int ll_setattr(struct dentry *de, struct iattr *attr);
struct inode_operations ll_fast_symlink_inode_operations = {
        readlink:       ll_readlink,
        setattr:        ll_setattr,
        follow_link2:   ll_follow_link,
        revalidate:     ll_inode_revalidate
};
