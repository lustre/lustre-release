/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   NFS export of Lustre Light File System 
 *
 *   Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_LLITE
#include <linux/lustre_lite.h>
#include "llite_internal.h"

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

        inode = ilookup4(sb, ino, NULL, NULL);
        if (inode)
                return inode;
        if (S_ISREG(mode)) {
                eadatalen = obd_size_diskmd(sbi->ll_osc_exp, NULL);
                valid |= OBD_MD_FLEASIZE;
        }
        fid.id = (__u64)ino;
        fid.generation = generation;
        fid.f_type = mode;

        rc = mdc_getattr(sbi->ll_mdc_exp, &fid, valid, eadatalen, &req);
        if (rc) {
                CERROR("failure %d inode %lu\n", rc, ino);
                return ERR_PTR(rc);
        }

        rc = ll_prep_inode(sbi->ll_osc_exp, &inode, req, 0, sb);
        if (rc) {
                ptlrpc_req_finished(req);
                return ERR_PTR(rc);
        }
        ptlrpc_req_finished(req);

        return inode;
}

extern struct dentry_operations ll_d_ops;

static struct dentry *ll_iget_for_nfs(struct super_block *sb, unsigned long ino,
                                      __u32 generation, umode_t mode)
{                                      
        struct inode *inode;      
        struct dentry *result;
        struct list_head *lp;

        if (ino == 0)
                return ERR_PTR(-ESTALE);

        inode = search_inode_for_lustre(sb, ino, generation, mode);
        if (IS_ERR(inode)) {
                return ERR_PTR(PTR_ERR(inode));
        }
        if (is_bad_inode(inode) 
            || (generation && inode->i_generation != generation)
            ){
                /* we didn't find the right inode.. */
              CERROR(" Inode %lu, Bad count: %d %d or version  %u %u\n",
                        inode->i_ino, 
                        inode->i_nlink, 
                        atomic_read(&inode->i_count), 
                        inode->i_generation, 
                        generation);
                iput(inode);
                return ERR_PTR(-ESTALE);
        }
        
        /* now to find a dentry.
         * If possible, get a well-connected one
         */
        spin_lock(&dcache_lock);
        for (lp = inode->i_dentry.next; lp != &inode->i_dentry ; lp=lp->next) {
                result = list_entry(lp,struct dentry, d_alias);
                if (!(result->d_flags & DCACHE_NFSD_DISCONNECTED)) {
                        dget_locked(result);
                        result->d_vfs_flags |= DCACHE_REFERENCED;
                        spin_unlock(&dcache_lock);
                        iput(inode);
                        return result;
                }
        }
        spin_unlock(&dcache_lock);
        result = d_alloc_root(inode);
        if (result == NULL) {
                iput(inode);
                return ERR_PTR(-ENOMEM);
        }
        result->d_flags |= DCACHE_NFSD_DISCONNECTED;
        ll_set_dd(result);
        result->d_op = &ll_d_ops;
        return result;
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
