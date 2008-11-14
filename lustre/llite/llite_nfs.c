/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/llite_nfs.c
 *
 * NFS export of Lustre Light File System
 */

#define DEBUG_SUBSYSTEM S_LLITE
#include <lustre_lite.h>
#include "llite_internal.h"
#ifdef HAVE_LINUX_EXPORTFS_H
#include <linux/exportfs.h>
#endif

__u32 get_uuid2int(const char *name, int len)
{
        __u32 key0 = 0x12a3fe2d, key1 = 0x37abe8f9;
        while (len--) {
                __u32 key = key1 + (key0 ^ (*name++ * 7152373));
                if (key & 0x80000000) key -= 0x7fffffff;
                key1 = key0;
                key0 = key;
        }
        return (key0 << 1);
}

static int ll_nfs_test_inode(struct inode *inode, void *opaque)
{
        struct ll_fid *iid = opaque;

        if (inode->i_ino == iid->id && inode->i_generation == iid->generation)
                return 1;

        return 0;
}

static struct inode * search_inode_for_lustre(struct super_block *sb,
                                              unsigned long ino,
                                              unsigned long generation,
                                              int mode)
{
        struct ptlrpc_request *req = NULL;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct ll_fid fid;
        unsigned long valid = 0;
        int eadatalen = 0, rc;
        struct inode *inode = NULL;
        struct ll_fid iid = { .id = ino, .generation = generation };
        ENTRY;

        inode = ILOOKUP(sb, ino, ll_nfs_test_inode, &iid);

        if (inode)
                RETURN(inode);
        if (S_ISREG(mode)) {
                rc = ll_get_max_mdsize(sbi, &eadatalen);
                if (rc) 
                        RETURN(ERR_PTR(rc));
                valid |= OBD_MD_FLEASIZE;
        }
        fid.id = (__u64)ino;
        fid.generation = generation;
        fid.f_type = mode;

        rc = mdc_getattr(sbi->ll_mdc_exp, &fid, valid, eadatalen, &req);
        if (rc) {
                CERROR("failure %d inode %lu\n", rc, ino);
                RETURN(ERR_PTR(rc));
        }

        rc = ll_prep_inode(sbi->ll_osc_exp, &inode, req, REPLY_REC_OFF, sb);
        if (rc) {
                ptlrpc_req_finished(req);
                RETURN(ERR_PTR(rc));
        }
        ptlrpc_req_finished(req);

        RETURN(inode);
}

static struct dentry *ll_iget_for_nfs(struct super_block *sb, unsigned long ino,
                                      __u32 generation, umode_t mode)
{
        struct inode *inode;
        struct dentry *result;
        ENTRY;

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));

        inode = search_inode_for_lustre(sb, ino, generation, mode);
        if (IS_ERR(inode)) {
                RETURN(ERR_PTR(PTR_ERR(inode)));
        }
        if (is_bad_inode(inode) ||
            (generation && inode->i_generation != generation)){
                /* we didn't find the right inode.. */
                CERROR("Inode %lu, Bad count: %lu %d or version  %u %u\n",
                       inode->i_ino, (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       generation);
                iput(inode);
                RETURN(ERR_PTR(-ESTALE));
        }

        result = d_alloc_anon(inode);
        if (!result) {
                iput(inode);
                RETURN(ERR_PTR(-ENOMEM));
        }
        ll_dops_init(result, 1);

        RETURN(result);
}

struct dentry *ll_fh_to_dentry(struct super_block *sb, __u32 *data, int len,
                               int fhtype, int parent)
{
        switch (fhtype) {
                case 2:
                        if (len < 5)
                                break;
                        if (parent)
                                return ll_iget_for_nfs(sb, data[3], 0, data[4]);
                case 1:
                        if (len < 3)
                                break;
                        if (parent)
                                break;
                        return ll_iget_for_nfs(sb, data[0], data[1], data[2]);
                default: break;
        }
        return ERR_PTR(-EINVAL);
}

int ll_dentry_to_fh(struct dentry *dentry, __u32 *datap, int *lenp,
                    int need_parent)
{
        if (*lenp < 3)
                return 255;
        *datap++ = dentry->d_inode->i_ino;
        *datap++ = dentry->d_inode->i_generation;
        *datap++ = (__u32)(S_IFMT & dentry->d_inode->i_mode);

        if (*lenp == 3 || S_ISDIR(dentry->d_inode->i_mode)) {
                *lenp = 3;
                return 1;
        }
        if (dentry->d_parent) {
                *datap++ = dentry->d_parent->d_inode->i_ino;
                *datap++ = (__u32)(S_IFMT & dentry->d_parent->d_inode->i_mode);

                *lenp = 5;
                return 2;
        }
        *lenp = 3;
        return 1;
}

struct dentry *ll_get_dentry(struct super_block *sb, void *data)
{
        __u32 *inump = (__u32*)data;
        return ll_iget_for_nfs(sb, inump[0], inump[1], S_IFREG);
}

struct dentry *ll_get_parent(struct dentry *dchild)
{
        struct ptlrpc_request *req = NULL;
        struct inode *dir = dchild->d_inode;
        struct ll_sb_info *sbi;
        struct dentry *result = NULL;
        struct ll_fid fid;
        struct mds_body *body;
        char dotdot[] = "..";
        int  rc = 0;
        ENTRY;
        
        LASSERT(dir && S_ISDIR(dir->i_mode));
        
        sbi = ll_s2sbi(dir->i_sb);       
 
        fid.id = (__u64)dir->i_ino;
        fid.generation = dir->i_generation;
        fid.f_type = S_IFDIR;

        rc = mdc_getattr_name(sbi->ll_mdc_exp, &fid, dotdot, strlen(dotdot) + 1,
                              0, 0, &req);
        if (rc) {
                CERROR("failure %d inode %lu get parent\n", rc, dir->i_ino);
                return ERR_PTR(rc);
        }
        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof (*body)); 
       
        LASSERT((body->valid & OBD_MD_FLGENER) && (body->valid & OBD_MD_FLID));
        
        result = ll_iget_for_nfs(dir->i_sb, body->ino, body->generation, S_IFDIR);

        if (IS_ERR(result))
                rc = PTR_ERR(result);

        ptlrpc_req_finished(req);
        if (rc)
                return ERR_PTR(rc);
        RETURN(result);
} 

struct export_operations lustre_export_operations = {
       .get_parent = ll_get_parent,
       .get_dentry = ll_get_dentry, 
};
