/*
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
        struct ptlrpc_request *request;
        char *tmp;
        int rc, size;
        ENTRY;

        rc = mdc_getattr(&sbi->ll_mds_client, sbi->ll_mds_conn,
                         dentry->d_inode->i_ino, S_IFLNK,
                         OBD_MD_LINKNAME, dentry->d_inode->i_size, &request);
        if (rc) {
                CERROR("failure %d inode %ld\n", rc,
                       (long)dentry->d_inode->i_ino);
                ptlrpc_free_req(request);
                RETURN(rc);
        }

        tmp = lustre_msg_buf(request->rq_repmsg, 1);
        size = MIN(request->rq_repmsg->buflens[1], buflen);
        rc = copy_to_user(buffer, tmp, size);
        if (rc == 0)
                rc = size;

        ptlrpc_free_req(request);
        RETURN(rc);
}

extern int ll_setattr(struct dentry *de, struct iattr *attr);
struct inode_operations ll_fast_symlink_inode_operations = {
        readlink:       ll_readlink,
        setattr:        ll_setattr
};
