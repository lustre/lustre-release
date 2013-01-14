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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
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

#if THREAD_SIZE >= 8192 /* see bug 17630 */

static int ll_nfs_test_inode(struct inode *inode, void *opaque)
{
        struct ll_fid *iid = opaque;

        if (inode->i_ino == iid->id && inode->i_generation == iid->generation)
                return 1;

        return 0;
}

static struct inode * search_inode_for_lustre(struct super_block *sb,
                                              struct ll_fid *iid)
{
        struct ptlrpc_request *req = NULL;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        unsigned long valid = 0;
        int eadatalen = 0, rc;
        struct inode *inode = NULL;
        struct ll_fid *fid = iid;
        ENTRY;

        if (!fid_is_igif((struct lu_fid*)iid)) {
                OBD_ALLOC_PTR(fid);
                if (!fid)
                        RETURN(ERR_PTR(-ENOMEM));
                fid->id = ll_fid_build_ino(iid, 0);
                fid->generation = ll_fid_build_gen(sbi, iid);
        }

        inode = ILOOKUP(sb, fid->id, ll_nfs_test_inode, fid);

        if (fid != iid)
                OBD_FREE_PTR(fid);

        if (inode)
                RETURN(inode);

        rc = ll_get_max_mdsize(sbi, &eadatalen);
        if (rc)
                RETURN(ERR_PTR(rc));

        valid |= OBD_MD_FLEASIZE;

        /* mds_fid2dentry is ignore f_type */
        rc = mdc_getattr(sbi->ll_mdc_exp, iid, valid, eadatalen, &req);
        if (rc) {
                CERROR("failure %d inode "LPU64"\n", rc, iid->id);
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

static struct dentry *ll_iget_for_nfs(struct super_block *sb,
                                      struct ll_fid *iid)
{
        struct inode *inode;
        struct dentry *result;
        ENTRY;

        if (iid->id == 0)
                RETURN(ERR_PTR(-ESTALE));

        inode = search_inode_for_lustre(sb, iid);
        if (IS_ERR(inode))
                RETURN(ERR_PTR(PTR_ERR(inode)));

        if (is_bad_inode(inode) ||
            ((fid_is_igif((struct lu_fid*)iid) && iid->generation) &&
             inode->i_generation != iid->generation)) {
                /* we didn't find the right inode.. */
                CERROR("Inode %lu, Bad count: %lu %d or version  %u %u\n",
                       inode->i_ino, (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       iid->generation);
                iput(inode);
                RETURN(ERR_PTR(-ESTALE));
        }

        result = d_obtain_alias(inode);
        if (!result)
                RETURN(ERR_PTR(-ENOMEM));
        ll_dops_init(result, 1, 0);

        RETURN(result);
}

#define LUSTRE_NFS_FID                0x94

struct lustre_nfs_fid {
        struct ll_fid   child;
        struct ll_fid   parent;
        umode_t         mode;
};

/* plen is in 32 bit units!
 * The return value is file handle type:
 * 1 -- contains child file handle;
 * 2 -- contains child file handle and parent file handle;
 * 255 -- error.
 */
static int ll_encode_fh(struct dentry *de, __u32 *fh, int *plen,
                        int connectable)
{
        struct inode *inode = de->d_inode;
        struct inode *parent = de->d_parent->d_inode;
        struct lustre_nfs_fid *nfs_fid = (void *)fh;
        ENTRY;

        CDEBUG(D_INFO, "encoding for (%lu) maxlen=%d minlen=%u\n",
              inode->i_ino, *plen*4,
              (int)sizeof(struct lustre_nfs_fid));

        if (*plen*4 < sizeof(struct lustre_nfs_fid))
                RETURN(255);

        ll_inode2fid(&nfs_fid->child, inode);
        ll_inode2fid(&nfs_fid->parent, parent);

        nfs_fid->mode = (S_IFMT & inode->i_mode);
        *plen = sizeof(struct lustre_nfs_fid)/4;

        RETURN(LUSTRE_NFS_FID);
}

#ifdef HAVE_FH_TO_DENTRY
static struct dentry *ll_fh_to_dentry(struct super_block *sb, struct fid *fid,
                                      int fh_len, int fh_type)
{
        struct lustre_nfs_fid *nfs_fid = (struct lustre_nfs_fid *)fid;

        if (fh_type != LUSTRE_NFS_FID)
                RETURN(ERR_PTR(-EINVAL));

        RETURN(ll_iget_for_nfs(sb, &nfs_fid->child));
}
static struct dentry *ll_fh_to_parent(struct super_block *sb, struct fid *fid,
                                      int fh_len, int fh_type)
{
        struct lustre_nfs_fid *nfs_fid = (struct lustre_nfs_fid *)fid;

        if (fh_type != LUSTRE_NFS_FID)
                RETURN(ERR_PTR(-EINVAL));
        RETURN(ll_iget_for_nfs(sb, &nfs_fid->parent));
}

#else
/*
 * This length is counted as amount of __u32,
 *  It is composed of a fid and a mode
 */
static struct dentry *ll_decode_fh(struct super_block *sb, __u32 *fh, int fh_len,
                                     int fh_type,
                                     int (*acceptable)(void *, struct dentry *),
                                     void *context)
{
        struct lustre_nfs_fid *nfs_fid = (void *)fh;
        struct dentry *entry;
        ENTRY;

        CDEBUG(D_INFO, "decoding for "LPU64" fh_len=%d fh_type=%x\n",
                nfs_fid->child.id, fh_len, fh_type);

        if (fh_type != LUSTRE_NFS_FID)
                  RETURN(ERR_PTR(-ESTALE));

        entry = sb->s_export_op->find_exported_dentry(sb, &nfs_fid->child,
                                                      &nfs_fid->parent,
                                                      acceptable, context);
        RETURN(entry);
}


struct dentry *ll_get_dentry(struct super_block *sb, void *data)
{
        struct lustre_nfs_fid *fid = data;
        ENTRY;

        RETURN(ll_iget_for_nfs(sb, &fid->child));

}

#endif

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

        ll_inode2fid(&fid, dir);

        rc = mdc_getattr_name(sbi->ll_mdc_exp, &fid, dotdot, strlen(dotdot) + 1,
                              0, 0, &req);
        if (rc) {
                CERROR("failure %d inode %lu get parent\n", rc, dir->i_ino);
                return ERR_PTR(rc);
        }
        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof (*body));

        LASSERT(body->valid & OBD_MD_FLID);

        fid = body->fid1;
        result = ll_iget_for_nfs(dir->i_sb, &fid);

        if (IS_ERR(result))
                rc = PTR_ERR(result);

        ptlrpc_req_finished(req);
        if (rc)
                return ERR_PTR(rc);
        RETURN(result);
}

struct export_operations lustre_export_operations = {
        .encode_fh  = ll_encode_fh,
        .get_parent = ll_get_parent,
#ifdef HAVE_FH_TO_DENTRY
        .fh_to_dentry = ll_fh_to_dentry,
        .fh_to_parent = ll_fh_to_parent,
#else
        .get_dentry = ll_get_dentry,
        .decode_fh  = ll_decode_fh,
#endif
};
#endif /* THREAD_SIZE >= 8192 */
