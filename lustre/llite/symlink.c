/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *  linux/fs/ext2/symlink.c
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 symlink handling code
 *
 * Modified for OBDFS:
 *  Copyright (C) 1999 Seagate Technology Inc. (author: braam@stelias.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/locks.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h> /* for ENTRY and EXIT only */
#include <linux/lustre_lite.h>

static int ll_readlink(struct dentry *dentry, char *buffer, int buflen)
{
        struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
        struct ptlrpc_request *request = NULL;
        struct inode *inode = dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        int len = inode->i_size + 1;
        char *symname;
        int rc;
        ENTRY;

        /* on symlinks lli_open_sem protects lli_symlink_name allocation/data */
        down(&lli->lli_open_sem);
        if (lli->lli_symlink_name) {
                symname = lli->lli_symlink_name;
                CDEBUG(D_INODE, "using cached symlink %s\n", symname);
                GOTO(out_readlink, rc = 0);
        }

        rc = mdc_getattr(&sbi->ll_mdc_conn, inode->i_ino, S_IFLNK,
                         OBD_MD_LINKNAME, len, &request);

        if (rc) {
                CERROR("inode %d readlink: rc = %ld\n", rc, inode->i_ino);
                GOTO(out_readlink_sem, rc);
        }

        symname = lustre_msg_buf(request->rq_repmsg, 1);

        OBD_ALLOC(lli->lli_symlink_name, len);
        /* do not return an error if we cannot cache the symlink locally */
        if (lli->lli_symlink_name)
                memcpy(lli->lli_symlink_name, symname, len);

out_readlink:
        rc = vfs_readlink(dentry, buffer, buflen, symname);

out_readlink_sem:
        up(&lli->lli_open_sem);
        ptlrpc_free_req(request);

        RETURN(rc);
}

extern int ll_setattr(struct dentry *de, struct iattr *attr);
struct inode_operations ll_fast_symlink_inode_operations = {
        readlink:       ll_readlink,
        setattr:        ll_setattr
};
