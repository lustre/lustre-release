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
#include <linux/lustre_ucache.h>
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

void mds_pack_dentry2id(struct obd_device *obd,
                        struct lustre_id *id,
                        struct dentry *dentry,
                        int fid)
{
        id_ino(id) = dentry->d_inum;
        id_gen(id) = dentry->d_generation;
        
        if (fid) {
                id_fid(id) = dentry->d_fid;
                id_group(id) = dentry->d_mdsnum;
        }
}

void mds_pack_dentry2body(struct obd_device *obd,
                          struct mds_body *b,
                          struct dentry *dentry,
                          int fid)
{
        b->valid |= OBD_MD_FLID | OBD_MD_FLGENER |
                OBD_MD_MDS;

        if (fid)
                b->valid |= OBD_MD_FID;
        
        mds_pack_dentry2id(obd, &b->id1, dentry, fid);
}

int mds_pack_inode2id(struct obd_device *obd,
                      struct lustre_id *id,
                      struct inode *inode,
                      int fid)
{
        int rc = 0;
        ENTRY;

        if (fid) {
                /* we have to avoid deadlock. */
                if (!down_trylock(&inode->i_sem)) {
                        rc = mds_read_inode_sid(obd, inode, id);
                        up(&inode->i_sem);
                } else {
                        rc = mds_read_inode_sid(obd, inode, id);
                }
        }

        if (rc == 0) {
                id_ino(id) = inode->i_ino;
                id_gen(id) = inode->i_generation;
                id_type(id) = (S_IFMT & inode->i_mode);
        }
        RETURN(rc);
}

/* Note that we can copy all of the fields, just some will not be "valid" */
void mds_pack_inode2body(struct obd_device *obd, struct mds_body *b,
                         struct inode *inode, int fid)
{
        b->valid |= OBD_MD_FLID | OBD_MD_FLCTIME | OBD_MD_FLUID |
                OBD_MD_FLGID | OBD_MD_FLFLAGS | OBD_MD_FLTYPE |
                OBD_MD_FLMODE | OBD_MD_FLNLINK | OBD_MD_FLGENER |
                OBD_MD_FLATIME | OBD_MD_FLMTIME; /* bug 2020 */

        if (!S_ISREG(inode->i_mode)) {
                b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                        OBD_MD_FLATIME | OBD_MD_FLMTIME |
                        OBD_MD_FLRDEV;
        }
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

        if (fid)
                b->valid |= OBD_MD_FID;
        
        mds_pack_inode2id(obd, &b->id1, inode, fid);
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

        r->ur_id1 = &rec->sa_id;
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
                r->ur_ea2data = lustre_msg_buf(req->rq_reqmsg, offset + 2, 0);
                if (r->ur_ea2data == NULL)
                        RETURN (-EFAULT);

                r->ur_ea2datalen = req->rq_reqmsg->buflens[offset + 2];
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

        r->ur_id1 = &rec->cr_id;
        r->ur_id2 = &rec->cr_replayid;
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
                } else if (S_ISDIR(r->ur_mode) ) {
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
                } else if (S_ISREG(r->ur_mode)){
                        r->ur_eadata = lustre_msg_buf (req->rq_reqmsg, 
                                                       offset + 2, 0);
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

        r->ur_id1 = &rec->lk_id1;
        r->ur_id2 = &rec->lk_id2;
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
        r->ur_id1 = &rec->ul_id1;
        r->ur_id2 = &rec->ul_id2;
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

        r->ur_id1 = &rec->rn_id1;
        r->ur_id2 = &rec->rn_id2;
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
                RETURN(-EFAULT);

        r->ur_id1 = &rec->cr_id;
        r->ur_id2 = &rec->cr_replayid;
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
                        RETURN(-EFAULT);
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

        /*
         * NB don't lustre_swab_reqbuf() here. We're just taking a peek and we
         * want to leave it to the specific unpacker once we've identified the
         * message type.
         */
        opcodep = lustre_msg_buf (req->rq_reqmsg, offset, sizeof(*opcodep));
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

        rec->ur_id1 = NULL;
        rec->ur_id2 = NULL;
        rec->ur_opcode = opcode;

        rc = mds_unpackers[opcode](req, offset, rec);
	
#if CRAY_PORTALS
        rec->ur_fsuid = req->rq_uid;
#endif
        RETURN(rc);
}

/********************************
 * MDS uid/gid mapping handling *
 ********************************/

static
struct mds_idmap_entry* idmap_alloc_entry(__u32 rmt_id, __u32 lcl_id)
{
        struct mds_idmap_entry *e;

        OBD_ALLOC(e, sizeof(*e));
        if (!e)
                return NULL;

        INIT_LIST_HEAD(&e->rmt_hash);
        INIT_LIST_HEAD(&e->lcl_hash);
        atomic_set(&e->refcount, 1);
        e->rmt_id = rmt_id;
        e->lcl_id = lcl_id;

        return e;
}

void idmap_free_entry(struct mds_idmap_entry *e)
{
        if (!list_empty(&e->rmt_hash))
                list_del(&e->rmt_hash);
        if (!list_empty(&e->lcl_hash))
                list_del(&e->lcl_hash);
        OBD_FREE(e, sizeof(*e));
}

static
int idmap_insert_entry(struct list_head *rmt_hash, struct list_head *lcl_hash,
                       struct mds_idmap_entry *new, const char *warn_msg)
{
        struct list_head *rmt_head = &rmt_hash[MDS_IDMAP_HASHFUNC(new->rmt_id)];
        struct list_head *lcl_head = &lcl_hash[MDS_IDMAP_HASHFUNC(new->lcl_id)];
        struct mds_idmap_entry *e;

        list_for_each_entry(e, rmt_head, rmt_hash) {
                if (e->rmt_id == new->rmt_id &&
                    e->lcl_id == new->lcl_id) {
                        atomic_inc(&e->refcount);
                        return 1;
                }
                if (e->rmt_id == new->rmt_id && warn_msg)
                        CWARN("%s: rmt id %u already map to %u (new %u)\n",
                              warn_msg, e->rmt_id, e->lcl_id, new->lcl_id);
                if (e->lcl_id == new->lcl_id && warn_msg)
                        CWARN("%s: lcl id %u already be mapped from %u "
                              "(new %u)\n", warn_msg,
                              e->lcl_id, e->rmt_id, new->rmt_id);
        }

        list_add_tail(rmt_head, &new->rmt_hash);
        list_add_tail(lcl_head, &new->lcl_hash);
        return 0;
}

static
int idmap_remove_entry(struct list_head *rmt_hash, struct list_head *lcl_hash,
                       __u32 rmt_id, __u32 lcl_id)
{
        struct list_head *rmt_head = &rmt_hash[MDS_IDMAP_HASHFUNC(rmt_id)];
        struct mds_idmap_entry *e;

        list_for_each_entry(e, rmt_head, rmt_hash) {
                if (e->rmt_id == rmt_id && e->lcl_id == lcl_id) {
                        if (atomic_dec_and_test(&e->refcount)) {
                                list_del(&e->rmt_hash);
                                list_del(&e->lcl_hash);
                                OBD_FREE(e, sizeof(*e));
                                return 0;
                        } else
                                return 1;
                }
        }
        return -ENOENT;
}

int mds_idmap_add(struct mds_idmap_table *tbl,
                  uid_t rmt_uid, uid_t lcl_uid,
                  gid_t rmt_gid, gid_t lcl_gid)
{
        struct mds_idmap_entry *ue, *ge;
        ENTRY;

        if (!tbl)
                RETURN(-EPERM);

        ue = idmap_alloc_entry(rmt_uid, lcl_uid);
        if (!ue)
                RETURN(-ENOMEM);
        ge = idmap_alloc_entry(rmt_gid, lcl_gid);
        if (!ge) {
                idmap_free_entry(ue);
                RETURN(-ENOMEM);
        }

        spin_lock(&tbl->mit_lock);

        if (idmap_insert_entry(tbl->mit_idmaps[MDS_RMT_UIDMAP_IDX],
                               tbl->mit_idmaps[MDS_LCL_UIDMAP_IDX],
                               ue, "UID mapping")) {
                idmap_free_entry(ue);
        }

        if (idmap_insert_entry(tbl->mit_idmaps[MDS_RMT_GIDMAP_IDX],
                               tbl->mit_idmaps[MDS_LCL_GIDMAP_IDX],
                               ge, "GID mapping")) {
                idmap_free_entry(ge);
        }

        spin_unlock(&tbl->mit_lock);
        RETURN(0);
}

int mds_idmap_del(struct mds_idmap_table *tbl,
                  uid_t rmt_uid, uid_t lcl_uid,
                  gid_t rmt_gid, gid_t lcl_gid)
{
        ENTRY;

        if (!tbl)
                RETURN(0);

        spin_lock(&tbl->mit_lock);
        idmap_remove_entry(tbl->mit_idmaps[MDS_RMT_UIDMAP_IDX],
                           tbl->mit_idmaps[MDS_LCL_UIDMAP_IDX],
                           rmt_uid, lcl_uid);
        idmap_remove_entry(tbl->mit_idmaps[MDS_RMT_GIDMAP_IDX],
                           tbl->mit_idmaps[MDS_LCL_GIDMAP_IDX],
                           rmt_gid, lcl_gid);
        spin_unlock(&tbl->mit_lock);
        RETURN(0);
}

static
__u32 idmap_lookup_id(struct list_head *hash, int reverse, __u32 id)
{
        struct list_head *head = &hash[MDS_IDMAP_HASHFUNC(id)];
        struct mds_idmap_entry *e;

        if (!reverse) {
                list_for_each_entry(e, head, rmt_hash) {
                        if (e->rmt_id == id)
                                return e->lcl_id;
                }
                return MDS_IDMAP_NOTFOUND;
        } else {
                list_for_each_entry(e, head, lcl_hash) {
                        if (e->lcl_id == id)
                                return e->rmt_id;
                }
                return MDS_IDMAP_NOTFOUND;
        }
}

int mds_idmap_lookup_uid(struct mds_idmap_table *tbl, int reverse, uid_t uid)
{
        struct list_head *hash;

        if (!tbl)
                return MDS_IDMAP_NOTFOUND;

        if (!reverse)
                hash = tbl->mit_idmaps[MDS_RMT_UIDMAP_IDX];
        else
                hash = tbl->mit_idmaps[MDS_LCL_UIDMAP_IDX];

        spin_lock(&tbl->mit_lock);
        uid = idmap_lookup_id(hash, reverse, uid);
        spin_unlock(&tbl->mit_lock);

        return uid;
}

int mds_idmap_lookup_gid(struct mds_idmap_table *tbl, int reverse, gid_t gid)
{
        struct list_head *hash;

        if (!tbl)
                return MDS_IDMAP_NOTFOUND;

        if (!reverse)
                hash = tbl->mit_idmaps[MDS_RMT_GIDMAP_IDX];
        else
                hash = tbl->mit_idmaps[MDS_LCL_GIDMAP_IDX];

        spin_lock(&tbl->mit_lock);
        gid = idmap_lookup_id(hash, reverse, gid);
        spin_unlock(&tbl->mit_lock);

        return gid;
}

struct mds_idmap_table *mds_idmap_alloc()
{
        struct mds_idmap_table *tbl;
        int i, j;

        OBD_ALLOC(tbl, sizeof(*tbl));
        if (!tbl)
                return NULL;

        spin_lock_init(&tbl->mit_lock);
        for (i = 0; i < MDS_IDMAP_N_HASHES; i++)
                for (j = 0; j < MDS_IDMAP_HASHSIZE; j++)
                        INIT_LIST_HEAD(&tbl->mit_idmaps[i][j]);

        return tbl;
}

static void idmap_clear_rmt_hash(struct list_head *list)
{
        struct mds_idmap_entry *e;
        int i;

        for (i = 0; i < MDS_IDMAP_HASHSIZE; i++) {
                while (!list_empty(&list[i])) {
                        e = list_entry(list[i].next, struct mds_idmap_entry,
                                       rmt_hash);
                        idmap_free_entry(e);
                }
        }
}

void mds_idmap_free(struct mds_idmap_table *tbl)
{
        int i;

        spin_lock(&tbl->mit_lock);
        idmap_clear_rmt_hash(tbl->mit_idmaps[MDS_RMT_UIDMAP_IDX]);
        idmap_clear_rmt_hash(tbl->mit_idmaps[MDS_RMT_GIDMAP_IDX]);

        /* paranoid checking */
        for (i = 0; i < MDS_IDMAP_HASHSIZE; i++) {
                LASSERT(list_empty(&tbl->mit_idmaps[MDS_LCL_UIDMAP_IDX][i]));
                LASSERT(list_empty(&tbl->mit_idmaps[MDS_LCL_GIDMAP_IDX][i]));
        }
        spin_unlock(&tbl->mit_lock);

        OBD_FREE(tbl, sizeof(*tbl));
}

/*********************************
 * helpers doing mapping for MDS *
 *********************************/

/*
 * we allow remote setuid/setgid to an "authencated" one,
 * this policy probably change later.
 */
static
int mds_req_secdesc_do_map(struct mds_export_data *med,
                           struct mds_req_sec_desc *rsd)
{
        struct mds_idmap_table *idmap = med->med_idmap;
        uid_t uid, fsuid;
        gid_t gid, fsgid;

        uid = mds_idmap_lookup_uid(idmap, 0, rsd->rsd_uid);
        if (uid == MDS_IDMAP_NOTFOUND) {
                CERROR("can't find map for uid %u\n", rsd->rsd_uid);
                return -EPERM;
        }

        if (rsd->rsd_uid == rsd->rsd_fsuid)
                fsuid = uid;
        else {
                fsuid = mds_idmap_lookup_uid(idmap, 0, rsd->rsd_fsuid);
                if (fsuid == MDS_IDMAP_NOTFOUND) {
                        CERROR("can't find map for fsuid %u\n", rsd->rsd_fsuid);
                        return -EPERM;
                }
        }

        gid = mds_idmap_lookup_gid(idmap, 0, rsd->rsd_gid);
        if (gid == MDS_IDMAP_NOTFOUND) {
                CERROR("can't find map for gid %u\n", rsd->rsd_gid);
                return -EPERM;
        }

        if (rsd->rsd_gid == rsd->rsd_fsgid)
                fsgid = gid;
        else {
                fsgid = mds_idmap_lookup_gid(idmap, 0, rsd->rsd_fsgid);
                if (fsgid == MDS_IDMAP_NOTFOUND) {
                        CERROR("can't find map for fsgid %u\n", rsd->rsd_fsgid);
                        return -EPERM;
                }
        }

        rsd->rsd_uid = uid;
        rsd->rsd_gid = gid;
        rsd->rsd_fsuid = fsuid;
        rsd->rsd_fsgid = fsgid;

        return 0;
}

void mds_body_do_reverse_map(struct mds_export_data *med,
                             struct mds_body *body)
{
        uid_t uid;
        gid_t gid;

        if (!med->med_remote)
                return;

        ENTRY;
        if (body->valid & OBD_MD_FLUID) {
                uid = mds_idmap_lookup_uid(med->med_idmap, 1, body->uid);
                if (uid == MDS_IDMAP_NOTFOUND) {
                        uid = med->med_nllu;
                        if (body->valid & OBD_MD_FLMODE) {
                                body->mode = (body->mode & ~S_IRWXU) |
                                             ((body->mode & S_IRWXO) << 6);
                        }
                }
                body->uid = uid;
        }
        if (body->valid & OBD_MD_FLGID) {
                gid = mds_idmap_lookup_gid(med->med_idmap, 1, body->gid);
                if (gid == MDS_IDMAP_NOTFOUND) {
                        gid = med->med_nllg;
                        if (body->valid & OBD_MD_FLMODE) {
                                body->mode = (body->mode & ~S_IRWXG) |
                                             ((body->mode & S_IRWXO) << 3);
                        }
                }
                body->gid = gid;
        }

        EXIT;
}

/**********************
 * MDS ucred handling *
 **********************/

static inline void drop_ucred_ginfo(struct lvfs_ucred *ucred)
{
        if (ucred->luc_ginfo) {
                put_group_info(ucred->luc_ginfo);
                ucred->luc_ginfo = NULL;
        }
}

static inline void drop_ucred_lsd(struct lvfs_ucred *ucred)
{
        if (ucred->luc_lsd) {
                mds_put_lsd(ucred->luc_lsd);
                ucred->luc_lsd = NULL;
        }
}

/*
 * the heart of the uid/gid handling and security checking.
 *
 * root could set any group_info if we allowed setgroups, while
 * normal user only could 'reduce' their group members -- which
 * is somewhat expensive.
 */
int mds_init_ucred(struct lvfs_ucred *ucred,
                   struct ptlrpc_request *req,
                   struct mds_req_sec_desc *rsd)
{
        struct mds_obd *mds = &req->rq_export->exp_obd->u.mds;
        struct mds_export_data *med = &req->rq_export->u.eu_mds_data;
        struct lustre_sec_desc *lsd;
        ptl_nid_t peernid = req->rq_peer.peer_id.nid;
        struct group_info *gnew;
        unsigned int setuid, setgid, strong_sec, root_squashed;
        __u32 lsd_perms;
        ENTRY;

        LASSERT(ucred);
        LASSERT(rsd);
        LASSERT(rsd->rsd_ngroups <= LUSTRE_MAX_GROUPS);

        /* XXX We'v no dedicated bits indicating whether GSS is used,
         * and authenticated/mapped uid is valid. currently we suppose
         * gss must initialize rq_sec_svcdata.
         */
        if (req->rq_sec_svcdata && req->rq_auth_uid == -1) {
                CWARN("user not authenticated, deny access\n");
                RETURN(-EPERM);
        }

        strong_sec = (req->rq_auth_uid != -1);
        LASSERT(!(req->rq_remote_realm && !strong_sec));

        /* if we use strong authentication for a local client, we
         * expect the uid which client claimed is true.
         */
        if (!med->med_remote && strong_sec &&
            req->rq_auth_uid != rsd->rsd_uid) {
                CWARN("nid "LPX64": UID %u was authenticated while client "
                      "claimed %u, enforce to be %u\n",
                      peernid, req->rq_auth_uid, rsd->rsd_uid,
                      req->rq_auth_uid);
                if (rsd->rsd_uid != rsd->rsd_fsuid)
                        rsd->rsd_uid = req->rq_auth_uid;
                else
                        rsd->rsd_uid = rsd->rsd_fsuid = req->rq_auth_uid;
        }

        if (med->med_remote) {
                int rc;

                if (req->rq_mapped_uid == MDS_IDMAP_NOTFOUND) {
                        CWARN("no mapping found, deny\n");
                        RETURN(-EPERM);
                }

                rc = mds_req_secdesc_do_map(med, rsd);
                if (rc)
                        RETURN(rc);
        }

        /* now lsd come into play */
        ucred->luc_ginfo = NULL;
        ucred->luc_lsd = lsd = mds_get_lsd(rsd->rsd_uid);

        if (!lsd) {
                CERROR("Deny access without LSD: uid %d\n", rsd->rsd_uid);
                RETURN(-EPERM);
        }

        /* find out the setuid/setgid attempt */
        setuid = (rsd->rsd_uid != rsd->rsd_fsuid);
        setgid = (rsd->rsd_gid != rsd->rsd_fsgid ||
                  rsd->rsd_gid != lsd->lsd_gid);

        lsd_perms = mds_lsd_get_perms(lsd, med->med_remote, 0, peernid);

        /* check permission of setuid */
        if (setuid && !(lsd_perms & LSD_PERM_SETUID)) {
                CWARN("mds blocked setuid attempt (%u -> %u) from "LPU64"\n",
                      rsd->rsd_uid, rsd->rsd_fsuid, peernid);
                RETURN(-EPERM);
        }

        /* check permission of setgid */
        if (setgid && !(lsd_perms & LSD_PERM_SETGID)) {
                CWARN("mds blocked setgid attempt (%u/%u -> %u) from "LPU64"\n",
                      rsd->rsd_gid, rsd->rsd_fsgid, lsd->lsd_gid, peernid);
                RETURN(-EPERM);
        }

        root_squashed = mds_squash_root(mds, rsd, &peernid); 

        /* remove privilege for non-root user */
        if (rsd->rsd_fsuid)
                rsd->rsd_cap &= ~CAP_FS_MASK;

        /* by now every fields other than groups in rsd have been granted */
        ucred->luc_uid = rsd->rsd_uid;
        ucred->luc_gid = rsd->rsd_gid;
        ucred->luc_fsuid = rsd->rsd_fsuid;
        ucred->luc_fsgid = rsd->rsd_fsgid;
        ucred->luc_cap = rsd->rsd_cap;

        /* don't use any supplementary group for remote client or
         * we squashed root */
        if (med->med_remote || root_squashed)
                RETURN(0);

        /* install groups from LSD */
        if (lsd->lsd_ginfo) {
                ucred->luc_ginfo = lsd->lsd_ginfo;
                get_group_info(ucred->luc_ginfo);
        }

        /* everything is done if we don't allow setgroups */
        if (!(lsd_perms & LSD_PERM_SETGRP))
                RETURN(0);

        /* root could set any groups as he want (if allowed), normal
         * users only could reduce his group array.
         */
        if (ucred->luc_uid == 0) {
                drop_ucred_ginfo(ucred);

                if (rsd->rsd_ngroups == 0)
                        RETURN(0);

                gnew = groups_alloc(rsd->rsd_ngroups);
                if (!gnew) {
                        CERROR("out of memory\n");
                        drop_ucred_lsd(ucred);
                        RETURN(-ENOMEM);
                }
                groups_from_buffer(gnew, rsd->rsd_groups);
                groups_sort(gnew); /* don't rely on client doing this */

                ucred->luc_ginfo = gnew;
        } else {
                __u32 set = 0, cur = 0;
                struct group_info *ginfo = ucred->luc_ginfo;

                if (!ginfo)
                        RETURN(0);

                /* Note: freeing a group_info count on 'nblocks' instead of
                 * 'ngroups', thus we can safely alloc enough buffer and reduce
                 * and ngroups number later.
                 */
                gnew = groups_alloc(rsd->rsd_ngroups);
                if (!gnew) {
                        CERROR("out of memory\n");
                        drop_ucred_ginfo(ucred);
                        drop_ucred_lsd(ucred);
                        RETURN(-ENOMEM);
                }

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
        drop_ucred_ginfo(ucred);
        drop_ucred_lsd(ucred);
        EXIT;
}
