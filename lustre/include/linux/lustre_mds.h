/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 * MDS data structures.  
 * See also lustre_idl.h for wire formats of requests.
 *
 */

#ifndef _LUSTRE_MDS_H
#define _LUSTRE_MDS_H


#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_idl.h>

static inline void l_dput(struct dentry *de) 
{
        if (!de || IS_ERR(de)) 
                return; 
        dput(de); 
}

struct mds_run_ctxt { 
	struct vfsmount *pwdmnt;
	struct dentry   *pwd;
	mm_segment_t     fs;
};

#define LUSTRE_MDS_NAME "mds"

struct mds_obd {
        struct ptlrpc_service *mds_service;

	char *mds_fstype;
        struct super_block * mds_sb;
	struct vfsmount *mds_vfsmnt;
	struct mds_run_ctxt  mds_ctxt;
	struct file_operations *mds_fop; 
	struct inode_operations *mds_iop;
	struct address_space_operations *mds_aops;

};

struct mds_update_record { 
        __u32 ur_reclen;
        __u32 ur_opcode;
        struct ll_fid *ur_fid1;
        struct ll_fid *ur_fid2;
        int ur_namelen;
        char *ur_name;
        int ur_tgtlen;
        char *ur_tgt;
        struct iattr ur_iattr;
        __u64 ur_id;
        __u32 ur_mode;
        __u32 ur_uid;
        __u32 ur_gid;
        __u64 ur_time;
}; 

/* mds/mds_pack.c */
void *mds_req_tgt(struct mds_req *req);
int mds_pack_req(char *name, int namelen, char *tgt, int tgtlen, struct ptlreq_hdr **hdr, union ptl_req *req, int *len, char **buf);
int mds_unpack_req(char *buf, int len, struct ptlreq_hdr **hdr, union ptl_req *);
int mds_pack_rep(char *name, int namelen, char *tgt, int tgtlen, struct ptlrep_hdr **hdr, union ptl_rep *rep, int *len, char **buf);
int mds_unpack_rep(char *buf, int len, struct ptlrep_hdr **hdr, union ptl_rep *rep);

/* mds/mds_reint.c  */
int mds_reint_rec(struct mds_update_record *r, struct ptlrpc_request *req); 

/* lib/mds_updates.c */
int mds_update_unpack(char *buf, int len, struct mds_update_record *r); 

void mds_setattr_pack(struct mds_rec_setattr *rec, struct inode *inode, struct iattr *iattr);
void mds_create_pack(struct mds_rec_create *rec, struct inode *inode, const char *name, int namelen, __u32 mode, __u64 id, __u32 uid, __u32 gid, __u64 time, const char *tgt, int tgtlen);
void mds_unlink_pack(struct mds_rec_unlink *rec, struct inode *inode, const char *name, int namelen);
void mds_link_pack(struct mds_rec_link *rec, struct inode *inode, struct inode *dir, const char *name, int namelen);
void mds_rename_pack(struct mds_rec_rename *rec, struct inode *srcdir, struct inode *tgtdir, const char *name, int namelen, const char *tgt, int tgtlen);

/* mds/handler.c */
struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid, struct vfsmount **mnt);

/* llight/request.c */
int mdc_getattr(struct ptlrpc_client *peer, ino_t ino, int type, int valid, 
		struct ptlrpc_request **);
int mdc_setattr(struct ptlrpc_client *peer, struct inode *inode,
                struct iattr *iattr, struct ptlrpc_request **);
int mdc_open(struct ptlrpc_client *cl, ino_t ino, int type, int flags,
             __u64 *fh, struct ptlrpc_request **req);
int mdc_close(struct ptlrpc_client *cl, ino_t ino, int type, __u64 fh, 
              struct ptlrpc_request **req);
int mdc_readpage(struct ptlrpc_client *peer, ino_t ino, int type, __u64 offset,
                 char *addr, struct ptlrpc_request **);
int mdc_create(struct ptlrpc_client *peer, 
	       struct inode *dir, const char *name, int namelen, 
	       const char *tgt, int tgtlen, 
	       int mode, __u64 id, __u32 uid, __u32 gid, __u64 time, 
               struct ptlrpc_request **);
int mdc_unlink(struct ptlrpc_client *peer, 
	       struct inode *dir, const char *name, int namelen, 
               struct ptlrpc_request **);
int mdc_link(struct ptlrpc_client *peer, struct dentry *src, 
	       struct inode *dir, const char *name, int namelen, 
               struct ptlrpc_request **);
int mdc_rename(struct ptlrpc_client *peer, struct inode *src, 
	       struct inode *tgt, const char *old, int oldlen, 
	       const char *new, int newlen, 
               struct ptlrpc_request **);
int mdc_create_client(char *uuid, struct ptlrpc_client *cl);

/* ioctls for trying requests */
#define IOC_REQUEST_TYPE                   'f'
#define IOC_REQUEST_MIN_NR                 30

#define IOC_REQUEST_GETATTR		_IOWR('f', 30, long)
#define IOC_REQUEST_READPAGE		_IOWR('f', 31, long)
#define IOC_REQUEST_SETATTR		_IOWR('f', 32, long)
#define IOC_REQUEST_CREATE		_IOWR('f', 33, long)
#define IOC_REQUEST_MAX_NR               33

#endif
