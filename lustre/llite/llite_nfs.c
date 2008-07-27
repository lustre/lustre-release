/*
 * -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lustre/lustre/llite/llite_nfs.c
 *
 * NFS export of Lustre Light File System
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 * Author: Huang Hua <huanghua@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE
#include <lustre_lite.h>
#include "llite_internal.h"
#ifdef HAVE_LINUX_EXPORTFS_H
#include <linux/exportfs.h>
#endif

static int ll_nfs_test_inode(struct inode *inode, void *opaque)
{
        return lu_fid_eq(&ll_i2info(inode)->lli_fid,
                         (struct lu_fid *)opaque);
}

static struct inode *search_inode_for_lustre(struct super_block *sb,
                                             struct lu_fid *fid,
                                             int mode)
{
        struct ll_sb_info     *sbi = ll_s2sbi(sb);
        struct ptlrpc_request *req = NULL;
        struct inode          *inode = NULL;
        unsigned long         valid = 0;
        int                   eadatalen = 0;
        ino_t                 ino = ll_fid_build_ino(sbi, fid);
        int                   rc;
        ENTRY;

        CDEBUG(D_INFO, "searching inode for:(%lu,"DFID")\n", ino, PFID(fid));

        inode = ILOOKUP(sb, ino, ll_nfs_test_inode, fid);
        if (inode)
                RETURN(inode);

        if (S_ISREG(mode)) {
                rc = ll_get_max_mdsize(sbi, &eadatalen);
                if (rc) 
                        RETURN(ERR_PTR(rc)); 
                valid |= OBD_MD_FLEASIZE;
        }

        rc = md_getattr(sbi->ll_md_exp, fid, NULL, valid, eadatalen, &req);
        if (rc) {
                CERROR("can't get object attrs, fid "DFID", rc %d\n",
                       PFID(fid), rc);
                RETURN(ERR_PTR(rc));
        }

        rc = ll_prep_inode(&inode, req, sb);
        ptlrpc_req_finished(req);
        if (rc)
                RETURN(ERR_PTR(rc));

        RETURN(inode);
}

static struct dentry *ll_iget_for_nfs(struct super_block *sb,
                                      struct lu_fid *fid,
                                      umode_t mode)
{
        struct inode  *inode;
        struct dentry *result;
        ENTRY;

        CDEBUG(D_INFO, "Get dentry for fid: "DFID"\n", PFID(fid));
        if (!fid_is_sane(fid))
                RETURN(ERR_PTR(-ESTALE));

        inode = search_inode_for_lustre(sb, fid, mode);
        if (IS_ERR(inode))
                RETURN(ERR_PTR(PTR_ERR(inode)));

        if (is_bad_inode(inode)) {
                /* we didn't find the right inode.. */
                CERROR("can't get inode by fid "DFID"\n",
                       PFID(fid));
                iput(inode);
                RETURN(ERR_PTR(-ESTALE));
        }

        result = d_alloc_anon(inode);
        if (!result) {
                iput(inode);
                RETURN(ERR_PTR(-ENOMEM));
        }

        ll_set_dd(result);

        lock_dentry(result);
        if (unlikely(result->d_op == &ll_init_d_ops)) {
                result->d_op = &ll_d_ops;
                unlock_dentry(result);
                smp_wmb();
                ll_d_wakeup(result);
        } else {
                result->d_op = &ll_d_ops;
                unlock_dentry(result);
        }

        RETURN(result);
}

/*
 * This length is counted as amount of __u32,
 *  It is composed of a fid and a mode 
 */
#define ONE_FH_LEN (sizeof(struct lu_fid)/4 + 1)

static struct dentry *ll_decode_fh(struct super_block *sb, __u32 *fh, int fh_len,
                                   int fh_type,
                                   int (*acceptable)(void *, struct dentry *),
                                   void *context)
{
        struct lu_fid *parent = NULL;
        struct lu_fid *child;
        struct dentry *entry;
        ENTRY;

        CDEBUG(D_INFO, "decoding for "DFID" fh_len=%d fh_type=%d\n", 
                PFID((struct lu_fid*)fh), fh_len, fh_type);

        if (fh_type != 1 && fh_type != 2)
                RETURN(ERR_PTR(-ESTALE));
        if (fh_len < ONE_FH_LEN * fh_type)
                RETURN(ERR_PTR(-ESTALE));

        child = (struct lu_fid*)fh;
        if (fh_type == 2)
                parent = (struct lu_fid*)(fh + ONE_FH_LEN);
                
        entry = sb->s_export_op->find_exported_dentry(sb, child, parent,
                                                      acceptable, context);
        RETURN(entry);
}

/* The return value is file handle type:
 * 1 -- contains child file handle;
 * 2 -- contains child file handle and parent file handle;
 * 255 -- error.
 */
static int ll_encode_fh(struct dentry *de, __u32 *fh, int *plen, int connectable)
{
        struct inode    *inode = de->d_inode;
        struct lu_fid   *fid = ll_inode2fid(inode);
        ENTRY;

        CDEBUG(D_INFO, "encoding for (%lu,"DFID") maxlen=%d minlen=%d\n",
                       inode->i_ino, PFID(fid), *plen, (int)ONE_FH_LEN);

        if (*plen < ONE_FH_LEN)
                RETURN(255);

        memcpy((char*)fh, fid, sizeof(*fid));
        *(fh + ONE_FH_LEN - 1) = (__u32)(S_IFMT & inode->i_mode);

        if (de->d_parent && *plen >= ONE_FH_LEN * 2) {
                struct inode *parent = de->d_parent->d_inode;
                fh += ONE_FH_LEN;
                memcpy((char*)fh, &ll_i2info(parent)->lli_fid, sizeof(*fid));
                *(fh + ONE_FH_LEN - 1) = (__u32)(S_IFMT & parent->i_mode);
                *plen = ONE_FH_LEN * 2;
                RETURN(2);
        } else {
                *plen = ONE_FH_LEN;
                RETURN(1);
        }
}

static struct dentry *ll_get_dentry(struct super_block *sb, void *data)
{
        struct lu_fid      *fid;
        struct dentry      *entry;
        __u32               mode;
        ENTRY;

        fid = (struct lu_fid *)data;
        mode = *((__u32*)data + ONE_FH_LEN - 1);
        
        entry = ll_iget_for_nfs(sb, fid, mode);
        RETURN(entry);
}

static struct dentry *ll_get_parent(struct dentry *dchild)
{
        struct ptlrpc_request *req = NULL;
        struct inode          *dir = dchild->d_inode;
        struct ll_sb_info     *sbi;
        struct dentry         *result = NULL;
        struct mdt_body       *body;
        static char           dotdot[] = "..";
        int                   rc;
        ENTRY;
        
        LASSERT(dir && S_ISDIR(dir->i_mode));
        
        sbi = ll_s2sbi(dir->i_sb);
 
        CDEBUG(D_INFO, "getting parent for (%lu,"DFID")\n", 
                        dir->i_ino, PFID(ll_inode2fid(dir)));

        rc = md_getattr_name(sbi->ll_md_exp, ll_inode2fid(dir), NULL,
                             dotdot, strlen(dotdot) + 1, 0, 0,
                             ll_i2suppgid(dir), &req);
        if (rc) {
                CERROR("failure %d inode %lu get parent\n", rc, dir->i_ino);
                RETURN(ERR_PTR(rc));
        }
        body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
        LASSERT(body->valid & OBD_MD_FLID);
        
        CDEBUG(D_INFO, "parent for "DFID" is "DFID"\n", 
                PFID(ll_inode2fid(dir)), PFID(&body->fid1));

        result = ll_iget_for_nfs(dir->i_sb, &body->fid1, S_IFDIR);

        ptlrpc_req_finished(req);
        RETURN(result);
} 

struct export_operations lustre_export_operations = {
       .get_parent = ll_get_parent,
       .get_dentry = ll_get_dentry,
       .encode_fh  = ll_encode_fh,
       .decode_fh  = ll_decode_fh,
};
