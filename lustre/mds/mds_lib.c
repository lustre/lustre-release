/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
# include <linux/locks.h>   // for wait_on_buffer
#else
# include <linux/buffer_head.h>   // for wait_on_buffer
#endif
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <asm/segment.h>

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>

void mds_pack_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        fid->id = inode->i_ino;
        fid->generation = inode->i_generation;
        fid->f_type = (S_IFMT & inode->i_mode);
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

        b->ino = inode->i_ino;
        b->atime = LTIME_S(inode->i_atime);
        b->mtime = LTIME_S(inode->i_mtime);
        b->ctime = LTIME_S(inode->i_ctime);
        b->mode = inode->i_mode;
        b->size = inode->i_size;
        b->blocks = inode->i_blocks;
        b->uid = inode->i_uid;
        b->gid = inode->i_gid;
        b->flags = inode->i_flags;
        b->rdev = b->rdev;
        b->nlink = inode->i_nlink;
        b->generation = inode->i_generation;
        b->suppgid = -1;
}
/* unpacking */
static int mds_setattr_unpack(struct ptlrpc_request *req, int offset,
                              struct mds_update_record *r)
{
        struct iattr *attr = &r->ur_iattr;
        struct mds_rec_setattr *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mds_rec_setattr);
        if (rec == NULL)
                RETURN (-EFAULT);

        r->ur_fsuid = rec->sa_fsuid;
        r->ur_fsgid = rec->sa_fsgid;
        r->ur_cap = rec->sa_cap;
        r->ur_suppgid1 = rec->sa_suppgid;
        r->ur_suppgid2 = -1;
        r->ur_fid1 = &rec->sa_fid;
        attr->ia_valid = rec->sa_valid;
        attr->ia_mode = rec->sa_mode;
        attr->ia_uid = rec->sa_uid;
        attr->ia_gid = rec->sa_gid;
        attr->ia_size = rec->sa_size;
        LTIME_S(attr->ia_atime) = rec->sa_atime;
        LTIME_S(attr->ia_mtime) = rec->sa_mtime;
        LTIME_S(attr->ia_ctime) = rec->sa_ctime;
        attr->ia_attr_flags = rec->sa_attr_flags;

        LASSERT_REQSWAB (req, offset + 1);
        if (req->rq_reqmsg->bufcount > offset + 1) {
                r->ur_eadata = lustre_msg_buf (req->rq_reqmsg,
                                               offset + 1, 0);
                if (r->ur_eadata == NULL)
                        RETURN (-EFAULT);
                r->ur_eadatalen = req->rq_reqmsg->buflens[offset + 1];
        } else {
                r->ur_eadata = NULL;
                r->ur_eadatalen = 0;
        }

        RETURN(0);
}

static int mds_create_unpack(struct ptlrpc_request *req, int offset,
                             struct mds_update_record *r)
{
        struct mds_rec_create *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mds_rec_create);
        if (rec == NULL)
                RETURN (-EFAULT);

        r->ur_fsuid = rec->cr_fsuid;
        r->ur_fsgid = rec->cr_fsgid;
        r->ur_cap = rec->cr_cap;
        r->ur_fid1 = &rec->cr_fid;
        r->ur_fid2 = &rec->cr_replayfid;
        r->ur_mode = rec->cr_mode;
        r->ur_rdev = rec->cr_rdev;
        r->ur_uid = rec->cr_uid;
        r->ur_gid = rec->cr_gid;
        r->ur_time = rec->cr_time;
        r->ur_flags = rec->cr_flags;
        r->ur_suppgid1 = rec->cr_suppgid;
        r->ur_suppgid2 = -1;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN (-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        if (req->rq_reqmsg->bufcount > offset + 2) {
                /* NB for now, we only seem to pass NULL terminated symlink
                 * target strings here.  If this ever changes, we'll have
                 * to stop checking for a buffer filled completely with a
                 * NULL terminated string here, and make the callers check
                 * depending on what they expect.  We should probably stash
                 * it in r->ur_eadata in that case, so it's obvious... -eeb
                 */
                r->ur_tgt = lustre_msg_string(req->rq_reqmsg, offset + 2, 0);
                if (r->ur_tgt == NULL)
                        RETURN (-EFAULT);
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
        struct mds_rec_link *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mds_rec_link);
        if (rec == NULL)
                RETURN (-EFAULT);

        r->ur_fsuid = rec->lk_fsuid;
        r->ur_fsgid = rec->lk_fsgid;
        r->ur_cap = rec->lk_cap;
        r->ur_suppgid1 = rec->lk_suppgid1;
        r->ur_suppgid2 = rec->lk_suppgid2;
        r->ur_fid1 = &rec->lk_fid1;
        r->ur_fid2 = &rec->lk_fid2;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN (-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];
        RETURN(0);
}

static int mds_unlink_unpack(struct ptlrpc_request *req, int offset,
                             struct mds_update_record *r)
{
        struct mds_rec_unlink *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mds_rec_unlink);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->ur_fsuid = rec->ul_fsuid;
        r->ur_fsgid = rec->ul_fsgid;
        r->ur_cap = rec->ul_cap;
        r->ur_mode = rec->ul_mode;
        r->ur_suppgid1 = rec->ul_suppgid;
        r->ur_suppgid2 = -1;
        r->ur_fid1 = &rec->ul_fid1;
        r->ur_fid2 = &rec->ul_fid2;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN(-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];
        RETURN(0);
}

static int mds_rename_unpack(struct ptlrpc_request *req, int offset,
                             struct mds_update_record *r)
{
        struct mds_rec_rename *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mds_rec_unlink);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->ur_fsuid = rec->rn_fsuid;
        r->ur_fsgid = rec->rn_fsgid;
        r->ur_cap = rec->rn_cap;
        r->ur_suppgid1 = rec->rn_suppgid1;
        r->ur_suppgid2 = rec->rn_suppgid2;
        r->ur_fid1 = &rec->rn_fid1;
        r->ur_fid2 = &rec->rn_fid2;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN(-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        r->ur_tgt = lustre_msg_string(req->rq_reqmsg, offset + 2, 0);
        if (r->ur_tgt == NULL)
                RETURN(-EFAULT);
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
        __u32 *opcodep;
        __u32  opcode;
        int rc;
        ENTRY;

        /* NB don't lustre_swab_reqbuf() here.  We're just taking a peek
         * and we want to leave it to the specific unpacker once we've
         * identified the message type */
        opcodep = lustre_msg_buf (req->rq_reqmsg, offset, sizeof (*opcodep));
        if (opcodep == NULL)
                RETURN(-EFAULT);

        opcode = *opcodep;
        if (lustre_msg_swabbed (req->rq_reqmsg))
                __swab32s (&opcode);

        if (opcode > REINT_MAX ||
            mds_unpackers[opcode] == NULL) {
                CERROR ("Unexpected opcode %d\n", opcode);
                RETURN(-EFAULT);
        }

        rec->ur_opcode = opcode;
        rc = mds_unpackers[opcode](req, offset, rec);
        RETURN(rc);
}
