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
#include "mds_internal.h"

#include "mds_internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4)
struct group_info *groups_alloc(int ngroups)
{
        struct group_info *ginfo;

        LASSERT(ngroups <= NGROUPS_SMALL);

        OBD_ALLOC(ginfo, sizeof(*ginfo) + 1 * sizeof(gid_t *));
        if (!ginfo)
                return NULL;
        ginfo->ngroups = ngroups;
        ginfo->nblocks = 1;
        ginfo->blocks[0] = ginfo->small_block;
        atomic_set(&ginfo->usage, 1);

        return ginfo;
}

void groups_free(struct group_info *ginfo)
{
        LASSERT(ginfo->ngroups <= NGROUPS_SMALL);
        LASSERT(ginfo->nblocks == 1);
        LASSERT(ginfo->blocks[0] == ginfo->small_block);

        OBD_FREE(ginfo, sizeof(*ginfo) + 1 * sizeof(gid_t *));
}

/* for 2.4 the group number is small, so simply search the
 * whole array.
 */
int groups_search(struct group_info *ginfo, gid_t grp)
{
        int i;

        if (!ginfo)
                return 0;

        for (i = 0; i < ginfo->ngroups; i++)
                if (GROUP_AT(ginfo, i) == grp)
                        return 1;
        return 0;
}

#else /* >= 2.6.4 */

void groups_sort(struct group_info *ginfo)
{
        int base, max, stride;
        int gidsetsize = ginfo->ngroups;

        for (stride = 1; stride < gidsetsize; stride = 3 * stride + 1)
                ; /* nothing */
        stride /= 3;

        while (stride) {
                max = gidsetsize - stride;
                for (base = 0; base < max; base++) {
                        int left = base;
                        int right = left + stride;
                        gid_t tmp = GROUP_AT(ginfo, right);
                                                                                                    
                        while (left >= 0 && GROUP_AT(ginfo, left) > tmp) {
                                GROUP_AT(ginfo, right) =
                                    GROUP_AT(ginfo, left);
                                right = left;
                                left -= stride;
                        }
                        GROUP_AT(ginfo, right) = tmp;
                }
                stride /= 3;
        }
}

int groups_search(struct group_info *ginfo, gid_t grp)
{
        int left, right;

        if (!ginfo)
                return 0;

        left = 0;
        right = ginfo->ngroups;
        while (left < right) {
                int mid = (left + right) / 2;
                int cmp = grp - GROUP_AT(ginfo, mid);
                if (cmp > 0)
                        left = mid + 1;
                else if (cmp < 0)
                        right = mid;
                else
                        return 1;
        }
        return 0;
}

#endif

void groups_from_buffer(struct group_info *ginfo, __u32 *gids)
{
        int i, ngroups = ginfo->ngroups;

        for (i = 0; i < ginfo->nblocks; i++) {
                int count = min(NGROUPS_PER_BLOCK, ngroups);

                memcpy(ginfo->blocks[i], gids, count * sizeof(__u32));
                gids += NGROUPS_PER_BLOCK;
                ngroups -= count;
        }
}

void mds_pack_dentry2fid(struct ll_fid *fid, struct dentry *dentry)
{
        fid->id = dentry->d_inum;
        fid->generation = dentry->d_generation;
        fid->mds = dentry->d_mdsnum;
}

void mds_pack_dentry2body(struct mds_body *b, struct dentry *dentry)
{
        b->valid |= OBD_MD_FLID | OBD_MD_FLGENER;
        b->ino = dentry->d_inum;
        b->generation = dentry->d_generation;
        b->mds = dentry->d_mdsnum;
}

void mds_pack_inode2fid(struct obd_device *obd, struct ll_fid *fid,
                                struct inode *inode)
{
        if (!obd || !fid || !inode) {
                printk("obd %p, fid %p, inode %p\n", obd, fid, inode);
                LBUG();
        }
        fid->id = inode->i_ino;
        fid->generation = inode->i_generation;
        fid->f_type = (S_IFMT & inode->i_mode);
        fid->mds = obd->u.mds.mds_num;
}

/* Note that we can copy all of the fields, just some will not be "valid" */
void mds_pack_inode2body(struct obd_device *obd, struct mds_body *b,
                                struct inode *inode)
{
        b->valid |= OBD_MD_FLID | OBD_MD_FLCTIME | OBD_MD_FLUID |
                    OBD_MD_FLGID | OBD_MD_FLFLAGS | OBD_MD_FLTYPE |
                    OBD_MD_FLMODE | OBD_MD_FLNLINK | OBD_MD_FLGENER |
                    OBD_MD_FLATIME | OBD_MD_FLMTIME; /* bug 2020 */

        if (!S_ISREG(inode->i_mode))
                b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLATIME |
                            OBD_MD_FLMTIME | OBD_MD_FLRDEV;

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
        b->rdev = inode->i_rdev;
        /* Return the correct link count for orphan inodes */
        if (mds_inode_is_orphan(inode)) {
                b->nlink = 0;
        } else if (S_ISDIR(inode->i_mode)) {
                b->nlink = 1;
        } else {
                b->nlink = inode->i_nlink;
        }
        b->generation = inode->i_generation;
        b->mds = obd->u.mds.mds_num;
}

/* unpacking */
static int mds_setattr_unpack(struct ptlrpc_request *req, int offset,
                              struct mds_update_record *r)
{
        struct iattr *attr = &r->ur_iattr;
        struct mds_rec_setattr *rec;
        ENTRY;

        rec = lustre_swab_reqbuf(req, offset, sizeof(*rec),
                                 lustre_swab_mds_rec_setattr);
        if (rec == NULL)
                RETURN (-EFAULT);

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
        }

        if (req->rq_reqmsg->bufcount > offset + 2) {
                r->ur_logcookies = lustre_msg_buf(req->rq_reqmsg, offset + 2,0);
                if (r->ur_eadata == NULL)
                        RETURN (-EFAULT);

                r->ur_cookielen = req->rq_reqmsg->buflens[offset + 2];
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

        r->ur_fid1 = &rec->cr_fid;
        r->ur_fid2 = &rec->cr_replayfid;
        r->ur_mode = rec->cr_mode;
        r->ur_rdev = rec->cr_rdev;
        r->ur_time = rec->cr_time;
        r->ur_flags = rec->cr_flags;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN (-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        if (req->rq_reqmsg->bufcount > offset + 2) {
                if (S_ISLNK(r->ur_mode)) {
                        r->ur_tgt = lustre_msg_string(req->rq_reqmsg,
                                                      offset + 2, 0);
                        if (r->ur_tgt == NULL)
                                RETURN (-EFAULT);
                        r->ur_tgtlen = req->rq_reqmsg->buflens[offset + 2];
                } else if (S_ISDIR(r->ur_mode)) {
                        /* Stripe info for mkdir - just a 16bit integer */
                        if (req->rq_reqmsg->buflens[offset + 2] != 2) {
                                CERROR("mkdir stripe info does not match "
                                       "expected size %d vs 2\n",
                                       req->rq_reqmsg->buflens[offset + 2]);
                                RETURN (-EINVAL);
                        }
                        r->ur_eadata = lustre_swab_buf (req->rq_reqmsg,
                                               offset + 2, 2, __swab16s);
                        r->ur_eadatalen = req->rq_reqmsg->buflens[offset + 2];
                } else {
                        /* Hm, no other users so far? */
                        LBUG();
                }
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

        r->ur_fid1 = &rec->lk_fid1;
        r->ur_fid2 = &rec->lk_fid2;
        r->ur_time = rec->lk_time;

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

        r->ur_mode = rec->ul_mode;
        r->ur_fid1 = &rec->ul_fid1;
        r->ur_fid2 = &rec->ul_fid2;
        r->ur_time = rec->ul_time;

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
                                  lustre_swab_mds_rec_rename);
        if (rec == NULL)
                RETURN(-EFAULT);

        r->ur_fid1 = &rec->rn_fid1;
        r->ur_fid2 = &rec->rn_fid2;
        r->ur_time = rec->rn_time;

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

static int mds_open_unpack(struct ptlrpc_request *req, int offset,
                           struct mds_update_record *r)
{
        struct mds_rec_create *rec;
        ENTRY;

        rec = lustre_swab_reqbuf (req, offset, sizeof (*rec),
                                  lustre_swab_mds_rec_create);
        if (rec == NULL)
                RETURN (-EFAULT);

        r->ur_fid1 = &rec->cr_fid;
        r->ur_fid2 = &rec->cr_replayfid;
        r->ur_mode = rec->cr_mode;
        r->ur_rdev = rec->cr_rdev;
        r->ur_time = rec->cr_time;
        r->ur_flags = rec->cr_flags;

        LASSERT_REQSWAB (req, offset + 1);
        r->ur_name = lustre_msg_string (req->rq_reqmsg, offset + 1, 0);
        if (r->ur_name == NULL)
                RETURN (-EFAULT);
        r->ur_namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT_REQSWAB (req, offset + 2);
        if (req->rq_reqmsg->bufcount > offset + 2) {
                r->ur_eadata = lustre_msg_buf(req->rq_reqmsg, offset + 2, 0);
                if (r->ur_eadata == NULL)
                        RETURN (-EFAULT);
                r->ur_eadatalen = req->rq_reqmsg->buflens[offset + 2];
        }
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
        [REINT_OPEN] mds_open_unpack,
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

static inline void drop_ucred_ginfo(struct lvfs_ucred *ucred)
{
        if (ucred->luc_ginfo) {
                put_group_info(ucred->luc_ginfo);
                ucred->luc_ginfo = NULL;
        }
}

/*
 * root could set any group_info if we allowed setgroups, while
 * normal user only could 'reduce' their group members -- which
 * is somewhat expensive.
 */
int mds_init_ucred(struct lvfs_ucred *ucred, struct mds_req_sec_desc *rsd)
{
        struct group_info *gnew;

        ENTRY;
        LASSERT(ucred);
        LASSERT(rsd);

        ucred->luc_fsuid = rsd->rsd_fsuid;
        ucred->luc_fsgid = rsd->rsd_fsgid;
        ucred->luc_cap = rsd->rsd_cap;
        ucred->luc_uid = rsd->rsd_uid;
        ucred->luc_ghash = mds_get_group_entry(NULL, rsd->rsd_uid);
        ucred->luc_ginfo = NULL;

        if (ucred->luc_ghash && ucred->luc_ghash->ge_group_info) {
                ucred->luc_ginfo = ucred->luc_ghash->ge_group_info;
                get_group_info(ucred->luc_ginfo);
        }

        /* everything is done if we don't allow setgroups */
        if (!mds_allow_setgroups())
                RETURN(0);

        if (rsd->rsd_ngroups > LUSTRE_MAX_GROUPS) {
                CERROR("client provide too many groups: %d\n",
                rsd->rsd_ngroups);
                drop_ucred_ginfo(ucred);
                mds_put_group_entry(NULL, ucred->luc_ghash);
                RETURN(-EFAULT);
        }

        if (ucred->luc_uid == 0) {
                if (rsd->rsd_ngroups == 0) {
                        drop_ucred_ginfo(ucred);
                        RETURN(0);
                }

                gnew = groups_alloc(rsd->rsd_ngroups);
                if (!gnew) {
                        CERROR("out of memory\n");
                        drop_ucred_ginfo(ucred);
                        mds_put_group_entry(NULL, ucred->luc_ghash);
                        RETURN(-ENOMEM);
                }
                groups_from_buffer(gnew, rsd->rsd_groups);
                /* can't rely on client to sort them */
                groups_sort(gnew);

                drop_ucred_ginfo(ucred);
                ucred->luc_ginfo = gnew;
        } else {
                struct group_info *ginfo;
                __u32 set = 0, cur = 0;

                /* if no group info in hash, we don't
                 * bother createing new
                 */
                if (!ucred->luc_ginfo)
                        RETURN(0);

                /* Note: freeing a group_info count on 'nblocks' instead of
                 * 'ngroups', thus we can safely alloc enough buffer and reduce
                 * and ngroups number later.
                 */
                gnew = groups_alloc(rsd->rsd_ngroups);
                if (!gnew) {
                        CERROR("out of memory\n");
                        drop_ucred_ginfo(ucred);
                        mds_put_group_entry(NULL, ucred->luc_ghash);
                        RETURN(-ENOMEM);
                }

                ginfo = ucred->luc_ginfo;
                while (cur < rsd->rsd_ngroups) {
                        if (groups_search(ginfo, rsd->rsd_groups[cur])) {
                                GROUP_AT(gnew, set) = rsd->rsd_groups[cur];
				set++;
			}
                        cur++;
                }
                gnew->ngroups = set;

                put_group_info(ucred->luc_ginfo);
                ucred->luc_ginfo = gnew;
        }
        RETURN(0);
}

void mds_exit_ucred(struct lvfs_ucred *ucred)
{
        ENTRY;

        if (ucred->luc_ginfo)
                put_group_info(ucred->luc_ginfo);
        if (ucred->luc_ghash)
                mds_put_group_entry(NULL, ucred->luc_ghash);

        EXIT;
}
