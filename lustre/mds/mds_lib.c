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

static
struct mds_idmap_table *__get_idmap_table(struct mds_export_data *med,
                                          int create)
{
        struct mds_idmap_table *new;
        int i;

        if (!create || med->med_idmap)
                return med->med_idmap;

        spin_unlock(&med->med_idmap_lock);
        OBD_ALLOC(new, sizeof(*new));
        spin_lock(&med->med_idmap_lock);

        if (!new) {
                CERROR("fail to alloc %d\n", sizeof(*new));
                return NULL;
        }

        if (med->med_idmap) {
                OBD_FREE(new, sizeof(*new));
                return med->med_idmap;
        }

        for (i = 0; i < MDS_IDMAP_HASHSIZE; i++) {
                INIT_LIST_HEAD(&new->uidmap[i]);
                INIT_LIST_HEAD(&new->gidmap[i]);
        }

        CDEBUG(D_SEC, "allocate idmap table for med %p\n", med);
        med->med_idmap = new;
        return new;
}

static void __flush_mapping_table(struct list_head *table)
{
        struct mds_idmap_item *item;
        int i;

        for (i = 0; i < MDS_IDMAP_HASHSIZE; i++) {
                while (!list_empty(&table[i])) {
                        item = list_entry(table[i].next, struct mds_idmap_item,
                                          hash);
                        list_del(&item->hash);
                        OBD_FREE(item, sizeof(*item));
                }
        }
}

void mds_idmap_cleanup(struct mds_export_data *med)
{
        ENTRY;

        if (!med->med_idmap) {
                EXIT;
                return;
        }

        spin_lock(&med->med_idmap_lock);
        __flush_mapping_table(med->med_idmap->uidmap);
        __flush_mapping_table(med->med_idmap->gidmap);
        OBD_FREE(med->med_idmap, sizeof(struct mds_idmap_table));
        spin_unlock(&med->med_idmap_lock);
}

static inline int idmap_hash(__u32 id)
{
        return (id & (MDS_IDMAP_HASHSIZE - 1));
}

static
int __idmap_set_item(struct mds_export_data *med,
                     struct list_head *table,
                     __u32 id1, __u32 id2)
{
        struct list_head *head;
        struct mds_idmap_item *item, *new = NULL;
        int found = 0;

        head = table + idmap_hash(id1);
again:
        list_for_each_entry(item, head, hash) {
                if (item->id1 == id1) {
                        found = 1;
                        break;
                }
        }

        if (!found) {
                if (new == NULL) {
                        spin_unlock(&med->med_idmap_lock);
                        OBD_ALLOC(new, sizeof(*new));
                        spin_lock(&med->med_idmap_lock);
                        if (!new) {
                                CERROR("fail to alloc %d\n", sizeof(*new));
                                return -ENOMEM;
                        }
                        goto again;
                }
                new->id1 = id1;
                new->id2 = id2;
                list_add(&new->hash, head);
        } else {
                if (new)
                        OBD_FREE(new, sizeof(*new));
                if (item->id2 != id2) {
                        CWARN("mapping changed: %u ==> (%u -> %u)\n",
                               id1, item->id2, id2);
                        item->id2 = id2;
                }
                list_move(&item->hash, head);
        }

        return 0;
}

int mds_idmap_set(struct mds_export_data *med, __u32 id1, __u32 id2,
                  int is_uid_mapping)
{
        struct mds_idmap_table *idmap;
        int rc;
        ENTRY;

        spin_lock(&med->med_idmap_lock);

        idmap = __get_idmap_table(med, 1);
        if (!idmap)
                GOTO(out, rc = -ENOMEM);

        if (is_uid_mapping)
                rc = __idmap_set_item(med, idmap->uidmap, id1, id2);
        else
                rc = __idmap_set_item(med, idmap->gidmap, id1, id2);

out:
        spin_unlock(&med->med_idmap_lock);
        RETURN(rc);
}

__u32 mds_idmap_get(struct mds_export_data *med, __u32 id,
                    int is_uid_mapping)
{
        struct mds_idmap_table *idmap;
        struct list_head *table;
        struct list_head *head;
        struct mds_idmap_item *item;
        int found = 0;
        __u32 res;

        spin_lock(&med->med_idmap_lock);
        idmap = __get_idmap_table(med, 0);
        if (!idmap)
                goto nllu;

        table = is_uid_mapping ? idmap->uidmap : idmap->gidmap;
        head = table + idmap_hash(id);

        list_for_each_entry(item, head, hash) {
                if (item->id1 == id) {
                        found = 1;
                        break;
                }
        }
        if (!found)
                goto nllu;

        res = item->id2;
out:
        spin_unlock(&med->med_idmap_lock);
        return res;
nllu:
        res = is_uid_mapping ? med->med_nllu : med->med_nllg;
        goto out;
}

void mds_reverse_map_ugid(struct ptlrpc_request *req,
                          struct mds_body *body)
{
        struct mds_export_data *med = &req->rq_export->u.eu_mds_data;

        LASSERT(req->rq_remote);

        if (body->valid & OBD_MD_FLUID)
                body->uid = mds_idmap_get(med, body->uid, 1);

        if (body->valid & OBD_MD_FLGID)
                body->gid = mds_idmap_get(med, body->gid, 0);
}

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
        unsigned int setuid, setgid, strong_sec;
        ENTRY;

        LASSERT(ucred);
        LASSERT(rsd);
        LASSERT(rsd->rsd_ngroups <= LUSTRE_MAX_GROUPS);

        strong_sec = (req->rq_auth_uid != -1);
        LASSERT(!(req->rq_remote && !strong_sec));

        /* sanity check & set local/remote flag */
        if (req->rq_remote) {
                if (med->med_local) {
                        CWARN("exp %p: client on nid "LPX64" was local, "
                              "set to remote\n", req->rq_export, peernid);
                        med->med_local = 0;
                }
        } else {
                if (!med->med_local) {
                        CWARN("exp %p: client on nid "LPX64" was remote, "
                              "set to local\n", req->rq_export, peernid);
                        med->med_local = 1;
                }
        }

        setuid = (rsd->rsd_fsuid != rsd->rsd_uid);
        setgid = (rsd->rsd_fsgid != rsd->rsd_gid);

        /* deny setuid/setgid for remote client */
        if ((setuid || setgid) && !med->med_local) {
                CWARN("deny setxid (%u/%u) from remote client "LPX64"\n",
                      setuid, setgid, peernid);
                RETURN(-EPERM);
        }

        /* take care of uid/gid mapping for client in remote realm */
        if (req->rq_remote) {
                /* record the uid mapping here */
                mds_idmap_set(med, req->rq_auth_uid, rsd->rsd_uid, 1);

                /* now we act as the authenticated user */
                rsd->rsd_uid = rsd->rsd_fsuid = req->rq_auth_uid;
        } else if (strong_sec && req->rq_auth_uid != rsd->rsd_uid) {
                /* if we use strong authentication on this request, we
                 * expect the uid which client claimed is true.
                 *
                 * FIXME root's machine_credential in krb5 will be interpret
                 * as "nobody", which is not good for mds-mds and mds-ost
                 * connection.
                 */
                CWARN("nid "LPX64": UID %u was authenticated while client "
                      "claimed %u, set %u by force\n",
                      peernid, req->rq_auth_uid, rsd->rsd_uid,
                      req->rq_auth_uid);
                rsd->rsd_uid = req->rq_auth_uid;
        }

        /* now lsd come into play */
        ucred->luc_ginfo = NULL;
        ucred->luc_lsd = lsd = mds_get_lsd(rsd->rsd_uid);

#if CRAY_PORTALS
        ucred->luc_fsuid = req->rq_uid;
#else
        ucred->luc_fsuid = rsd->rsd_fsuid;
#endif
        if (lsd) {
                if (req->rq_remote) {
                        /* record the gid mapping here */
                        mds_idmap_set(med, lsd->lsd_gid, rsd->rsd_gid, 0);
                        /* now we act as the authenticated group */
                        rsd->rsd_gid = rsd->rsd_fsgid = lsd->lsd_gid;
                } else if (rsd->rsd_gid != lsd->lsd_gid) {
                        /* verify gid which client declared is true */
                        CWARN("GID: %u while client declare %u, "
                              "set %u by force\n",
                              lsd->lsd_gid, rsd->rsd_gid,
                              lsd->lsd_gid);
                        rsd->rsd_gid = lsd->lsd_gid;
                }

                if (lsd->lsd_ginfo) {
                        ucred->luc_ginfo = lsd->lsd_ginfo;
                        get_group_info(ucred->luc_ginfo);
                }

                /* check permission of setuid */
                if (setuid) {
                        if (!lsd->lsd_allow_setuid) {
                                CWARN("mds blocked setuid attempt: %u -> %u\n",
                                      rsd->rsd_uid, rsd->rsd_fsuid);
                                RETURN(-EPERM);
                        }
                }

                /* check permission of setgid */
                if (setgid) {
                        if (!lsd->lsd_allow_setgid) {
                                CWARN("mds blocked setgid attempt: %u -> %u\n",
                                      rsd->rsd_gid, rsd->rsd_fsgid);
                                RETURN(-EPERM);
                        }
                }
        } else {
                /* failed to get lsd, right now we simply deny any access
                 * if strong authentication is used,
                 */
                if (strong_sec) {
                        CWARN("mds deny access without LSD\n");
                        RETURN(-EPERM);
                }

                /* and otherwise deny setuid/setgid attempt */
                if (setuid || setgid) {
                        CWARN("mds deny setuid/setgid without LSD\n");
                        RETURN(-EPERM);
                }
        }

        /* NOTE: we have already obtained supplementary groups,
         * it will be retained across root_squash. will it be a
         * security problem??
         */
        mds_squash_root(mds, rsd, &peernid); 

        /* remove privilege for non-root user */
        if (rsd->rsd_fsuid)
                rsd->rsd_cap &= ~CAP_FS_MASK;

        /* by now every fields in rsd have been granted */
        ucred->luc_fsgid = rsd->rsd_fsgid;
        ucred->luc_cap = rsd->rsd_cap;
        ucred->luc_uid = rsd->rsd_uid;

        /* everything is done if we don't allow setgroups */
        if (!lsd || !lsd->lsd_allow_setgrp)
                RETURN(0);

        if (ucred->luc_uid == 0) {
                if (rsd->rsd_ngroups == 0) {
                        drop_ucred_ginfo(ucred);
                        RETURN(0);
                }

                gnew = groups_alloc(rsd->rsd_ngroups);
                if (!gnew) {
                        CERROR("out of memory\n");
                        drop_ucred_ginfo(ucred);
                        drop_ucred_lsd(ucred);
                        RETURN(-ENOMEM);
                }
                groups_from_buffer(gnew, rsd->rsd_groups);
                groups_sort(gnew); /* can't rely on client */

                drop_ucred_ginfo(ucred);
                ucred->luc_ginfo = gnew;
        } else {
                __u32 set = 0, cur = 0;
                struct group_info *ginfo;

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
                        drop_ucred_lsd(ucred);
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
        drop_ucred_ginfo(ucred);
        drop_ucred_lsd(ucred);
        EXIT;
}
