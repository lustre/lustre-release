/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite Update Records
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/locks.h>   // for wait_on_buffer
#else
#include <linux/buffer_head.h>   // for wait_on_buffer
#endif
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <asm/segment.h>

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>

void mds_pack_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        fid->id = HTON__u64(inode->i_ino);
        fid->generation = HTON__u32(inode->i_generation);
        fid->f_type = HTON__u32(S_IFMT & inode->i_mode);
}

void mds_pack_inode2body(struct mds_body *b, struct inode *inode)
{
        b->valid = OBD_MD_FLID | OBD_MD_FLATIME | OBD_MD_FLMTIME |
                OBD_MD_FLCTIME | OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLTYPE | OBD_MD_FLMODE |
                OBD_MD_FLNLINK | OBD_MD_FLGENER;

        /* The MDS file size isn't authoritative for regular files, so don't
         * even pretend. */
        if (S_ISREG(inode->i_mode))
                b->valid &= ~(OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);

        b->ino = HTON__u32(inode->i_ino);
        b->atime = HTON__u32(LTIME_S(inode->i_atime));
        b->mtime = HTON__u32(LTIME_S(inode->i_mtime));
        b->ctime = HTON__u32(LTIME_S(inode->i_ctime));
        b->mode = HTON__u32(inode->i_mode);
        b->size = HTON__u64(inode->i_size);
        b->blocks = HTON__u64(inode->i_blocks);
        b->uid = HTON__u32(inode->i_uid);
        b->gid = HTON__u32(inode->i_gid);
        b->flags = HTON__u32(inode->i_flags);
        b->rdev = HTON__u32(b->rdev);
        b->nlink = HTON__u32(inode->i_nlink);
        b->generation = HTON__u32(inode->i_generation);
        b->suppgid = HTON__u32(-1);
}


void mds_pack_fid(struct ll_fid *fid)
{
        fid->id = HTON__u64(fid->id);
        fid->generation = HTON__u32(fid->generation);
        fid->f_type = HTON__u32(fid->f_type);
}

static void mds_pack_body(struct mds_body *b)
{
        if (b == NULL)
                LBUG();

        b->fsuid = HTON__u32(current->fsuid);
        b->fsgid = HTON__u32(current->fsgid);
        b->capability = HTON__u32(current->cap_effective);

        mds_pack_fid(&b->fid1);
        mds_pack_fid(&b->fid2);
        b->size = HTON__u64(b->size);
        b->ino = HTON__u32(b->ino);
        b->valid = HTON__u32(b->valid);
        b->mode = HTON__u32(b->mode);
        b->uid = HTON__u32(b->uid);
        b->gid = HTON__u32(b->gid);
        b->mtime = HTON__u32(b->mtime);
        b->ctime = HTON__u32(b->ctime);
        b->atime = HTON__u32(b->atime);
        b->flags = HTON__u32(b->flags);
        b->rdev = HTON__u32(b->rdev);
        b->nlink = HTON__u32(b->nlink);
        b->generation = HTON__u32(b->generation);
        b->suppgid = HTON__u32(b->suppgid);
}

void mds_getattr_pack(struct ptlrpc_request *req, int valid, int offset,
                      int flags,
                      struct inode *inode, const char *name, int namelen)
{
        struct mds_body *b;
        b = lustre_msg_buf(req->rq_reqmsg, offset);

        b->fsuid = HTON__u32(current->fsuid);
        b->fsgid = HTON__u32(current->fsgid);
        b->capability = HTON__u32(current->cap_effective);
        b->valid = HTON__u32(valid);
        b->flags = HTON__u32(flags);
        if (in_group_p(inode->i_gid))
                b->suppgid = HTON__u32(inode->i_gid);
        else
                b->suppgid = HTON__u32(-1);

        ll_inode2fid(&b->fid1, inode);
        if (name) {
                char *tmp;
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1);
                LOGL0(name, namelen, tmp);
        }
}

void mds_readdir_pack(struct ptlrpc_request *req, __u64 offset,
                      obd_id ino, int type, __u64 xid)
{
        struct mds_body *b;

        b = lustre_msg_buf(req->rq_reqmsg, 0);
        b->fsuid = HTON__u32(current->fsuid);
        b->fsgid = HTON__u32(current->fsgid);
        b->capability = HTON__u32(current->cap_effective);
        b->fid1.id = HTON__u64(ino);
        b->fid1.f_type = HTON__u32(type);
        b->size = HTON__u64(offset);
        b->suppgid = HTON__u32(-1);
        b->blocks = HTON__u64(xid);
}


void mds_pack_req_body(struct ptlrpc_request *req)
{
        struct mds_body *b = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_pack_body(b);
}

void mds_pack_rep_body(struct ptlrpc_request *req)
{
        struct mds_body *b = lustre_msg_buf(req->rq_repmsg, 0);
        mds_pack_body(b);
}


/* packing of MDS records */
void mds_create_pack(struct ptlrpc_request *req, int offset, struct inode *dir,
                     __u32 mode, __u64 rdev, __u32 uid, __u32 gid, __u64 time,
                     const char *name, int namelen,
                     const void *data, int datalen)
{
        struct mds_rec_create *rec;
        char *tmp;
        rec = lustre_msg_buf(req->rq_reqmsg, offset);

        rec->cr_opcode = HTON__u32(REINT_CREATE);
        rec->cr_fsuid = HTON__u32(current->fsuid);
        rec->cr_fsgid = HTON__u32(current->fsgid);
        rec->cr_cap = HTON__u32(current->cap_effective);
        ll_inode2fid(&rec->cr_fid, dir);
        memset(&rec->cr_replayfid, 0, sizeof(rec->cr_replayfid));
        rec->cr_mode = HTON__u32(mode);
        rec->cr_rdev = HTON__u64(rdev);
        rec->cr_uid = HTON__u32(uid);
        rec->cr_gid = HTON__u32(gid);
        rec->cr_time = HTON__u64(time);
        if (in_group_p(dir->i_gid))
                rec->cr_suppgid = HTON__u32(dir->i_gid);
        else
                rec->cr_suppgid = HTON__u32(-1);

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        LOGL0(name, namelen, tmp);

        if (data) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2);
                LOGL0(data, datalen, tmp);
        }
}
/* packing of MDS records */
void mds_open_pack(struct ptlrpc_request *req, int offset, struct inode *dir,
                     __u32 mode, __u64 rdev, __u32 uid, __u32 gid, __u64 time,
                     __u32 flags,
                     const char *name, int namelen,
                     const void *data, int datalen)
{
        struct mds_rec_create *rec;
        char *tmp;
        rec = lustre_msg_buf(req->rq_reqmsg, offset);

        /* XXX do something about time, uid, gid */
        rec->cr_opcode = HTON__u32(REINT_OPEN);
        rec->cr_fsuid = HTON__u32(current->fsuid);
        rec->cr_fsgid = HTON__u32(current->fsgid);
        rec->cr_cap = HTON__u32(current->cap_effective);
        ll_inode2fid(&rec->cr_fid, dir);
        memset(&rec->cr_replayfid, 0, sizeof(rec->cr_replayfid));
        rec->cr_mode = HTON__u32(mode);
        rec->cr_flags = HTON__u32(flags);
        rec->cr_rdev = HTON__u64(rdev);
        rec->cr_uid = HTON__u32(uid);
        rec->cr_gid = HTON__u32(gid);
        rec->cr_time = HTON__u64(time);
        if (in_group_p(dir->i_gid))
                rec->cr_suppgid = HTON__u32(dir->i_gid);
        else
                rec->cr_suppgid = HTON__u32(-1);

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        LOGL0(name, namelen, tmp);

        if (data) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2);
                LOGL0(data, datalen, tmp);
        }
}

void mds_setattr_pack(struct ptlrpc_request *req,
                      struct inode *inode, struct iattr *iattr,
                      void *ea, int ealen)
{
        struct mds_rec_setattr *rec = lustre_msg_buf(req->rq_reqmsg, 0);

        rec->sa_opcode = HTON__u32(REINT_SETATTR);
        rec->sa_fsuid = HTON__u32(current->fsuid);
        rec->sa_fsgid = HTON__u32(current->fsgid);
        rec->sa_cap = HTON__u32(current->cap_effective);
        ll_inode2fid(&rec->sa_fid, inode);

        if (iattr) {
                rec->sa_valid = HTON__u32(iattr->ia_valid);
                rec->sa_mode = HTON__u32(iattr->ia_mode);
                rec->sa_uid = HTON__u32(iattr->ia_uid);
                rec->sa_gid = HTON__u32(iattr->ia_gid);
                rec->sa_size = HTON__u64(iattr->ia_size);
                rec->sa_atime = HTON__u64(LTIME_S(iattr->ia_atime));
                rec->sa_mtime = HTON__u64(LTIME_S(iattr->ia_mtime));
                rec->sa_ctime = HTON__u64(LTIME_S(iattr->ia_ctime));
                rec->sa_attr_flags = HTON__u32(iattr->ia_attr_flags);

                if ((iattr->ia_valid & ATTR_GID) && in_group_p(iattr->ia_gid))
                        rec->sa_suppgid = HTON__u32(iattr->ia_gid);
                else if ((iattr->ia_valid & ATTR_MODE) &&
                         in_group_p(inode->i_gid))
                        rec->sa_suppgid = HTON__u32(inode->i_gid);
                else
                        rec->sa_suppgid = HTON__u32(-1);
        }

        if (ealen)
                memcpy(lustre_msg_buf(req->rq_reqmsg, 1), ea, ealen);
}

void mds_unlink_pack(struct ptlrpc_request *req, int offset,
                     struct inode *inode, struct inode *child, __u32 mode,
                     const char *name, int namelen)
{
        struct mds_rec_unlink *rec;
        char *tmp;

        rec = lustre_msg_buf(req->rq_reqmsg, offset);

        rec->ul_opcode = HTON__u32(REINT_UNLINK);
        rec->ul_fsuid = HTON__u32(current->fsuid);
        rec->ul_fsgid = HTON__u32(current->fsgid);
        rec->ul_cap = HTON__u32(current->cap_effective);
        rec->ul_mode = HTON__u32(mode);
        if (in_group_p(inode->i_gid))
                rec->ul_suppgid = HTON__u32(inode->i_gid);
        else
                rec->ul_suppgid = HTON__u32(-1);
        ll_inode2fid(&rec->ul_fid1, inode);
        if (child)
                ll_inode2fid(&rec->ul_fid2, child);

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        LOGL0(name, namelen, tmp);
}

void mds_link_pack(struct ptlrpc_request *req, int offset,
                   struct inode *inode, struct inode *dir,
                   const char *name, int namelen)
{
        struct mds_rec_link *rec;
        char *tmp;

        rec = lustre_msg_buf(req->rq_reqmsg, offset);

        rec->lk_opcode = HTON__u32(REINT_LINK);
        rec->lk_fsuid = HTON__u32(current->fsuid);
        rec->lk_fsgid = HTON__u32(current->fsgid);
        rec->lk_cap = HTON__u32(current->cap_effective);
        if (in_group_p(dir->i_gid))
                rec->lk_suppgid = HTON__u32(dir->i_gid);
        else
                rec->lk_suppgid = HTON__u32(-1);
        ll_inode2fid(&rec->lk_fid1, inode);
        ll_inode2fid(&rec->lk_fid2, dir);

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        LOGL0(name, namelen, tmp);
}

void mds_rename_pack(struct ptlrpc_request *req, int offset,
                     struct inode *srcdir, struct inode *tgtdir,
                     const char *old, int oldlen, const char *new, int newlen)
{
        struct mds_rec_rename *rec;
        char *tmp;

        rec = lustre_msg_buf(req->rq_reqmsg, offset);

        /* XXX do something about time, uid, gid */
        rec->rn_opcode = HTON__u32(REINT_RENAME);
        rec->rn_fsuid = HTON__u32(current->fsuid);
        rec->rn_fsgid = HTON__u32(current->fsgid);
        rec->rn_cap = HTON__u32(current->cap_effective);
        if (in_group_p(srcdir->i_gid))
                rec->rn_suppgid1 = HTON__u32(srcdir->i_gid);
        else
                rec->rn_suppgid1 = HTON__u32(-1);
        if (in_group_p(tgtdir->i_gid))
                rec->rn_suppgid2 = HTON__u32(tgtdir->i_gid);
        else
                rec->rn_suppgid2 = HTON__u32(-1);
        ll_inode2fid(&rec->rn_fid1, srcdir);
        ll_inode2fid(&rec->rn_fid2, tgtdir);

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        LOGL0(old, oldlen, tmp);

        if (new) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2);
                LOGL0(new, newlen, tmp);
        }
}

/* unpacking */
void mds_unpack_fid(struct ll_fid *fid)
{
        fid->id = NTOH__u64(fid->id);
        fid->generation = NTOH__u32(fid->generation);
        fid->f_type = NTOH__u32(fid->f_type);
}

void mds_unpack_body(struct mds_body *b)
{
        if (b == NULL)
                LBUG();

        mds_unpack_fid(&b->fid1);
        mds_unpack_fid(&b->fid2);
        b->size = NTOH__u64(b->size);
        b->blocks = NTOH__u64(b->blocks);
        b->valid = NTOH__u32(b->valid);
        b->fsuid = NTOH__u32(b->fsuid);
        b->fsgid = NTOH__u32(b->fsgid);
        b->capability = NTOH__u32(b->capability);
        b->ino = NTOH__u32(b->ino);
        b->mode = NTOH__u32(b->mode);
        b->uid = NTOH__u32(b->uid);
        b->gid = NTOH__u32(b->gid);
        b->mtime = NTOH__u32(b->mtime);
        b->ctime = NTOH__u32(b->ctime);
        b->atime = NTOH__u32(b->atime);
        b->flags = NTOH__u32(b->flags);
        b->rdev = NTOH__u32(b->rdev);
        b->nlink = NTOH__u32(b->nlink);
        b->generation = NTOH__u32(b->generation);
        b->suppgid = NTOH__u32(b->suppgid);
}

static int mds_setattr_unpack(struct ptlrpc_request *req, int offset,
                              struct mds_update_record *r)
{
        struct iattr *attr = &r->ur_iattr;
        struct mds_rec_setattr *rec = lustre_msg_buf(req->rq_reqmsg, offset);
        ENTRY;

        if (req->rq_reqmsg->bufcount < offset + 1 ||
            req->rq_reqmsg->buflens[offset] != sizeof(*rec))
                RETURN(-EFAULT);

        r->ur_fsuid = NTOH__u32(rec->sa_fsuid);
        r->ur_fsgid = NTOH__u32(rec->sa_fsgid);
        r->ur_cap = NTOH__u32(rec->sa_cap);
        r->ur_suppgid1 = NTOH__u32(rec->sa_suppgid);
        r->ur_suppgid2 = NTOH__u32(-1);
        r->ur_fid1 = &rec->sa_fid;
        attr->ia_valid = NTOH__u32(rec->sa_valid);
        attr->ia_mode = NTOH__u32(rec->sa_mode);
        attr->ia_uid = NTOH__u32(rec->sa_uid);
        attr->ia_gid = NTOH__u32(rec->sa_gid);
        attr->ia_size = NTOH__u64(rec->sa_size);
        LTIME_S(attr->ia_atime) = NTOH__u64(rec->sa_atime);
        LTIME_S(attr->ia_mtime) = NTOH__u64(rec->sa_mtime);
        LTIME_S(attr->ia_ctime) = NTOH__u64(rec->sa_ctime);
        attr->ia_attr_flags = NTOH__u32(rec->sa_attr_flags);

        if (req->rq_reqmsg->bufcount == offset + 2) {
                r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];
                r->ur_name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        } else {
                r->ur_namelen = 0;
        }

        RETURN(0);
}

static int mds_create_unpack(struct ptlrpc_request *req, int offset,
                             struct mds_update_record *r)
{
        struct mds_rec_create *rec = lustre_msg_buf(req->rq_reqmsg, offset);
        ENTRY;

        if (req->rq_reqmsg->bufcount < offset + 2 ||
            req->rq_reqmsg->buflens[offset] != sizeof(*rec))
                RETURN(-EFAULT);

        r->ur_fsuid = NTOH__u32(rec->cr_fsuid);
        r->ur_fsgid = NTOH__u32(rec->cr_fsgid);
        r->ur_cap = NTOH__u32(rec->cr_cap);
        r->ur_fid1 = &rec->cr_fid;
        r->ur_fid2 = &rec->cr_replayfid;
        r->ur_mode = NTOH__u32(rec->cr_mode);
        r->ur_rdev = NTOH__u64(rec->cr_rdev);
        r->ur_uid = NTOH__u32(rec->cr_uid);
        r->ur_gid = NTOH__u32(rec->cr_gid);
        r->ur_time = NTOH__u64(rec->cr_time);
        r->ur_flags = NTOH__u32(rec->cr_flags);
        r->ur_suppgid1 = NTOH__u32(rec->cr_suppgid);
        r->ur_suppgid2 = NTOH__u32(-1);

        r->ur_name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        if (req->rq_reqmsg->bufcount == offset + 3) {
                r->ur_tgt = lustre_msg_buf(req->rq_reqmsg, offset + 2);
                r->ur_tgtlen = req->rq_reqmsg->buflens[offset + 2];
        } else {
                r->ur_tgt = NULL;
                r->ur_tgtlen = 0;
        }
        RETURN(0);
}

static int mds_link_unpack(struct ptlrpc_request *req, int offset,
                           struct mds_update_record *r)
{
        struct mds_rec_link *rec = lustre_msg_buf(req->rq_reqmsg, offset);
        ENTRY;

        if (req->rq_reqmsg->bufcount != offset + 2 ||
            req->rq_reqmsg->buflens[offset] != sizeof(*rec))
                RETURN(-EFAULT);

        r->ur_fsuid = NTOH__u32(rec->lk_fsuid);
        r->ur_fsgid = NTOH__u32(rec->lk_fsgid);
        r->ur_cap = NTOH__u32(rec->lk_cap);
        r->ur_suppgid1 = NTOH__u32(rec->lk_suppgid);
        r->ur_suppgid2 = NTOH__u32(-1);
        r->ur_fid1 = &rec->lk_fid1;
        r->ur_fid2 = &rec->lk_fid2;

        r->ur_name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];
        RETURN(0);
}

static int mds_unlink_unpack(struct ptlrpc_request *req, int offset,
                             struct mds_update_record *r)
{
        struct mds_rec_unlink *rec = lustre_msg_buf(req->rq_reqmsg, offset);
        ENTRY;

        if (req->rq_reqmsg->bufcount != offset + 2 ||
            req->rq_reqmsg->buflens[offset] != sizeof(*rec))
                RETURN(-EFAULT);

        r->ur_fsuid = NTOH__u32(rec->ul_fsuid);
        r->ur_fsgid = NTOH__u32(rec->ul_fsgid);
        r->ur_cap = NTOH__u32(rec->ul_cap);
        r->ur_mode = NTOH__u32(rec->ul_mode);
        r->ur_suppgid1 = NTOH__u32(rec->ul_suppgid);
        r->ur_suppgid2 = NTOH__u32(-1);
        r->ur_fid1 = &rec->ul_fid1;
        r->ur_fid2 = &rec->ul_fid2;

        r->ur_name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];
        RETURN(0);
}

static int mds_rename_unpack(struct ptlrpc_request *req, int offset,
                             struct mds_update_record *r)
{
        struct mds_rec_rename *rec = lustre_msg_buf(req->rq_reqmsg, offset);
        ENTRY;

        if (req->rq_reqmsg->bufcount != offset + 3 ||
            req->rq_reqmsg->buflens[offset] != sizeof(*rec))
                RETURN(-EFAULT);

        r->ur_fsuid = NTOH__u32(rec->rn_fsuid);
        r->ur_fsgid = NTOH__u32(rec->rn_fsgid);
        r->ur_cap = NTOH__u32(rec->rn_cap);
        r->ur_suppgid1 = NTOH__u32(rec->rn_suppgid1);
        r->ur_suppgid2 = NTOH__u32(rec->rn_suppgid2);
        r->ur_fid1 = &rec->rn_fid1;
        r->ur_fid2 = &rec->rn_fid2;

        r->ur_name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        r->ur_tgt = lustre_msg_buf(req->rq_reqmsg, offset + 2);
        r->ur_tgtlen = req->rq_reqmsg->buflens[offset + 2];
        RETURN(0);
}

typedef int (*update_unpacker)(struct ptlrpc_request *req, int offset,
                               struct mds_update_record *r);

static update_unpacker mds_unpackers[REINT_MAX + 1] = {
        [REINT_SETATTR] mds_setattr_unpack,
        [REINT_CREATE] mds_create_unpack,
        [REINT_LINK] mds_link_unpack,
        [REINT_UNLINK] mds_unlink_unpack,
        [REINT_RENAME] mds_rename_unpack,
        [REINT_OPEN] mds_create_unpack,
};

int mds_update_unpack(struct ptlrpc_request *req, int offset,
                      struct mds_update_record *rec)
{
        __u32 *opcode = lustre_msg_buf(req->rq_reqmsg, offset);
        int rc;
        ENTRY;

        if (!opcode || req->rq_reqmsg->buflens[offset] < sizeof(*opcode))
                RETURN(-EFAULT);

        rec->ur_opcode = NTOH__u32(*opcode);

        if (*opcode < 0 || *opcode > REINT_MAX) {
                LBUG();
                RETURN(-EFAULT);
        }

        rc = mds_unpackers[*opcode](req, offset, rec);
        RETURN(rc);
}
