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
 * (Un)packing of OST requests
 *
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifndef __KERNEL__
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_net.h>

int lustre_pack_msg(int count, int *lens, char **bufs, int *len,
                    struct lustre_msg **msg)
{
        char *ptr;
        struct lustre_msg *m;
        int size = 0, i;

        for (i = 0; i < count; i++)
                size += size_round(lens[i]);

        *len = size_round(sizeof(*m) + count * sizeof(__u32)) + size;

        OBD_ALLOC(*msg, *len);
        if (!*msg)
                RETURN(-ENOMEM);

        m = *msg;
        m->magic = PTLRPC_MSG_MAGIC;
        m->version = PTLRPC_MSG_VERSION;
        m->bufcount = count;
        for (i = 0; i < count; i++)
                m->buflens[i] = lens[i];

        ptr = (char *)m + size_round(sizeof(*m) + count * sizeof(__u32));
        for (i = 0; i < count; i++) {
                char *tmp = NULL;
                if (bufs)
                        tmp = bufs[i];
                LOGL(tmp, lens[i], ptr);
        }

        return 0;
}

/* This returns the size of the buffer that is required to hold a lustre_msg
 * with the given sub-buffer lengths. */
int lustre_msg_size(int count, int *lengths)
{
        int size = 0, i;

        for (i = 0; i < count; i++)
                size += size_round(lengths[i]);

        size += size_round(sizeof(struct lustre_msg) + count * sizeof(__u32));

        return size;
}

int lustre_unpack_msg(struct lustre_msg *m, int len)
{
        int   flipped;
        int   required_len;
        int   i;
        ENTRY;

        /* We can provide a slightly better error log, if we check the
         * message magic and version first.  In the future, struct
         * lustre_msg may grow, and we'd like to log a version mismatch,
         * rather than a short message.
         *
         */
        required_len = MAX (offsetof (struct lustre_msg, version) + sizeof (m->version),
                            offsetof (struct lustre_msg, magic) + sizeof (m->magic));
        if (len < required_len) {
                /* can't even look inside the message */
                CERROR ("message length %d too small for magic/version check\n", len);
                RETURN (-EINVAL);
        }

        flipped = (m->magic == __swab32 (PTLRPC_MSG_MAGIC));
        if (flipped)
                __swab32s (&m->version);
        else if (m->magic != PTLRPC_MSG_MAGIC) {
                CERROR("wrong lustre_msg magic %#08x\n", m->magic);
                RETURN (-EINVAL);
        }

        if (m->version != PTLRPC_MSG_VERSION) {
                CERROR("wrong lustre_msg version %#08x\n", m->version);
                RETURN (-EINVAL);
        }

        /* Now we know the sender speaks my language (but possibly flipped)... */
        required_len = size_round(sizeof(*m));
        if (len < required_len) {
                /* can't even look inside the message */
                CERROR ("message length %d too small for lustre_msg\n", len);
                RETURN (-EINVAL);
        }

        if (flipped) {
                __swab32s (&m->type);
                __swab32s (&m->opc);
                __swab64s (&m->last_xid);
                __swab64s (&m->last_committed);
                __swab64s (&m->transno);
                __swab32s (&m->status);
                __swab32s (&m->bufcount);
                __swab32s (&m->flags);
        }
        
        required_len = size_round (offsetof (struct lustre_msg, buflens[m->bufcount]));
        if (len < required_len) {
                /* didn't receive all the buffer lengths */
                CERROR ("message length %d too small for %d buflens\n", 
                        len, m->bufcount);
                RETURN(-EINVAL);
        }

        for (i = 0; i < m->bufcount; i++) {
                if (flipped)
                        __swab32s (&m->buflens[i]);
                required_len += size_round(m->buflens[i]);
        }
        
        if (len < required_len) {
                CERROR("len: %d, required_len %d\n", len, required_len);
                CERROR("bufcount: %d\n", m->bufcount);
                for (i = 0; i < m->bufcount; i++)
                        CERROR("buffer %d length %d\n", i, m->buflens[i]);
                RETURN(-EINVAL);
        }

        RETURN(0);
}

void *lustre_msg_buf(struct lustre_msg *m, int n, int min_size)
{
        int i;
        int offset;
        int buflen;
        int bufcount;
        
        LASSERT (m != NULL);
        LASSERT (n >= 0);
        
        bufcount = m->bufcount;
        if (n >= bufcount) {
                CERROR("msg %p buffer[%d] not present (count %d)\n",
                       m, n, bufcount);
                return NULL;
        }

        buflen = m->buflens[n];
        if (buflen == 0) {
                CERROR("msg %p buffer[%d] is zero length\n", m, n);
                return NULL;
        }

        if (buflen < min_size) {
                CERROR("msg %p buffer[%d] size %d too small (required %d)\n",
                        m, n, buflen, min_size);
                return NULL;
        }
        
        offset = size_round (offsetof (struct lustre_msg, buflens[bufcount]));
        for (i = 0; i < n; i++)
                offset += size_round(m->buflens[i]);

        return (char *)m + offset;
}

char *lustre_msg_string (struct lustre_msg *m, int index, int max_len)
{
        /* max_len == 0 means the string should fill the buffer */
        char *str = lustre_msg_buf (m, index, 0);
        int   slen;
        int   blen;
        
        if (str == NULL) {
                CERROR ("can't unpack string in msg %p buffer[%d]\n", m, index);
                return (NULL);
        }

        blen = m->buflens[index];
        slen = strnlen (str, blen);
        
        if (slen == blen) {                     /* not NULL terminated */
                CERROR ("can't unpack non-NULL terminated string in "
                        "msg %p buffer[%d] len %d\n", m, index, blen);
                return (NULL);
        }
        
        if (max_len == 0) {
                if (slen != blen - 1) {
                        CERROR ("can't unpack short string in msg %p "
                                "buffer[%d] len %d: strlen %d\n",
                                m, index, blen, slen);
                        return (NULL);
                }
        } else if (slen > max_len) {
                CERROR ("can't unpack oversized string in msg %p "
                        "buffer[%d] len %d strlen %d: max %d expected\n", 
                        m, index, blen, slen, max_len);
                return (NULL);
        }

        return (str);
}

/* Wrap up the normal fixed length case */
void *lustre_swab_reqbuf (struct ptlrpc_request *req, int index, int min_size, void *swabber)
{
        void *ptr;
        
        LASSERT_REQSWAB (req, index);

        ptr = lustre_msg_buf (req->rq_reqmsg, index, min_size);
        if (ptr == NULL)
                return (NULL);
        
        if (swabber != NULL &&
            lustre_msg_swabbed (req->rq_reqmsg))
                ((void (*)(void *))swabber)(ptr);
        
        return (ptr);
}

/* Wrap up the normal fixed length case */
void *lustre_swab_repbuf (struct ptlrpc_request *req, int index, int min_size, void *swabber)
{
        void *ptr;
        
        LASSERT_REPSWAB (req, index);

        ptr = lustre_msg_buf (req->rq_repmsg, index, min_size);
        if (ptr == NULL)
                return (NULL);
        
        if (swabber != NULL &&
            lustre_msg_swabbed (req->rq_repmsg))
                ((void (*)(void *))swabber)(ptr);
        
        return (ptr);
}

/* byte flipping routines for all wire types declared in
 * lustre_idl.h implemented here.
 */

void lustre_swab_obdo (struct obdo  *o)
{
        __swab64s (&o->o_id);
        __swab64s (&o->o_gr);
        __swab64s (&o->o_atime);
        __swab64s (&o->o_mtime);
        __swab64s (&o->o_ctime);
        __swab64s (&o->o_size);
        __swab64s (&o->o_blocks);
        __swab64s (&o->o_rdev);
        __swab32s (&o->o_blksize);
        __swab32s (&o->o_mode);
        __swab32s (&o->o_uid);
        __swab32s (&o->o_gid);
        __swab32s (&o->o_flags);
        __swab32s (&o->o_nlink);
        __swab32s (&o->o_generation);
        __swab32s (&o->o_valid);
        __swab32s (&o->o_obdflags);
        __swab32s (&o->o_easize);
        /* o_inline is opaque */
}

void lustre_swab_obd_statfs (struct obd_statfs *os)
{
        __swab64s (&os->os_type);
        __swab64s (&os->os_blocks);
        __swab64s (&os->os_bfree);
        __swab64s (&os->os_bavail);
        __swab64s (&os->os_ffree);
        /* no need to swap os_fsid */
        __swab32s (&os->os_bsize);
        __swab32s (&os->os_namelen);
        /* no need to swap os_spare */
}

void lustre_swab_obd_ioobj (struct obd_ioobj *ioo)
{
        __swab64s (&ioo->ioo_id);
        __swab64s (&ioo->ioo_gr);
        __swab32s (&ioo->ioo_type);
        __swab32s (&ioo->ioo_bufcnt);
}

void lustre_swab_niobuf_remote (struct niobuf_remote *nbr)
{
        __swab64s (&nbr->offset);
        __swab32s (&nbr->len);
        __swab32s (&nbr->xid);
        __swab32s (&nbr->flags);
}

void lustre_swab_ost_body (struct ost_body *b)
{
        lustre_swab_obdo (&b->oa);
}

void lustre_swab_ll_fid (struct ll_fid *fid) 
{
        __swab64s (&fid->id);
        __swab32s (&fid->generation);
        __swab32s (&fid->f_type);
}

void lustre_swab_mds_status_req (struct mds_status_req *r)
{
        __swab32s (&r->flags);
        __swab32s (&r->repbuf);
}

void lustre_swab_mds_fileh_body (struct mds_fileh_body *f)
{
        lustre_swab_ll_fid (&f->f_fid);
}

void lustre_swab_mds_body (struct mds_body *b)
{
        lustre_swab_ll_fid (&b->fid1);
        lustre_swab_ll_fid (&b->fid2);
        /* handle is opaque */
        __swab64s (&b->size);
        __swab64s (&b->blocks);
        __swab32s (&b->ino);
        __swab32s (&b->valid);
        __swab32s (&b->fsuid);
        __swab32s (&b->fsgid);
        __swab32s (&b->capability);
        __swab32s (&b->mode);
        __swab32s (&b->uid);
        __swab32s (&b->gid);
        __swab32s (&b->mtime);
        __swab32s (&b->ctime);
        __swab32s (&b->atime);
        __swab32s (&b->flags);
        __swab32s (&b->rdev);
        __swab32s (&b->nlink);
        __swab32s (&b->generation);
        __swab32s (&b->suppgid);
        __swab32s (&b->eadatasize);
}

void lustre_swab_mds_rec_setattr (struct mds_rec_setattr *sa)
{
        __swab32s (&sa->sa_opcode);
        __swab32s (&sa->sa_fsuid);
        __swab32s (&sa->sa_fsgid);
        __swab32s (&sa->sa_cap);
        __swab32s (&sa->sa_reserved);
        __swab32s (&sa->sa_valid);
        lustre_swab_ll_fid (&sa->sa_fid);
        __swab32s (&sa->sa_mode);
        __swab32s (&sa->sa_uid);
        __swab32s (&sa->sa_gid);
        __swab32s (&sa->sa_attr_flags);
        __swab64s (&sa->sa_size);
        __swab64s (&sa->sa_atime);
        __swab64s (&sa->sa_mtime);
        __swab64s (&sa->sa_ctime);
        __swab32s (&sa->sa_suppgid);
}

void lustre_swab_mds_rec_create (struct mds_rec_create *cr)
{
        __swab32s (&cr->cr_opcode);
        __swab32s (&cr->cr_fsuid);
        __swab32s (&cr->cr_fsgid);
        __swab32s (&cr->cr_cap);
        __swab32s (&cr->cr_flags); /* for use with open */
        __swab32s (&cr->cr_mode);
        lustre_swab_ll_fid (&cr->cr_fid);
        lustre_swab_ll_fid (&cr->cr_replayfid);
        __swab32s (&cr->cr_uid);
        __swab32s (&cr->cr_gid);
        __swab64s (&cr->cr_time);
        __swab64s (&cr->cr_rdev);
        __swab32s (&cr->cr_suppgid);
}

void lustre_swab_mds_rec_link (struct mds_rec_link *lk)
{
        __swab32s (&lk->lk_opcode);
        __swab32s (&lk->lk_fsuid);
        __swab32s (&lk->lk_fsgid);
        __swab32s (&lk->lk_cap);
        __swab32s (&lk->lk_suppgid);
        lustre_swab_ll_fid (&lk->lk_fid1);
        lustre_swab_ll_fid (&lk->lk_fid2);
}

void lustre_swab_mds_rec_unlink (struct mds_rec_unlink *ul)
{
        __swab32s (&ul->ul_opcode);
        __swab32s (&ul->ul_fsuid);
        __swab32s (&ul->ul_fsgid);
        __swab32s (&ul->ul_cap);
        __swab32s (&ul->ul_reserved);
        __swab32s (&ul->ul_mode);
        __swab32s (&ul->ul_suppgid);
        lustre_swab_ll_fid (&ul->ul_fid1);
        lustre_swab_ll_fid (&ul->ul_fid2);
}

void lustre_swab_mdx_rec_rename (struct mds_rec_rename *rn)
{
        __swab32s (&rn->rn_opcode);
        __swab32s (&rn->rn_fsuid);
        __swab32s (&rn->rn_fsgid);
        __swab32s (&rn->rn_cap);
        __swab32s (&rn->rn_suppgid1);
        __swab32s (&rn->rn_suppgid2);
        lustre_swab_ll_fid (&rn->rn_fid1);
        lustre_swab_ll_fid (&rn->rn_fid2);
}

void lustre_swab_lov_desc (struct lov_desc *ld)
{
        __swab32s (&ld->ld_tgt_count);
        __swab32s (&ld->ld_active_tgt_count);
        __swab32s (&ld->ld_default_stripe_count);
        __swab64s (&ld->ld_default_stripe_size);
        __swab64s (&ld->ld_default_stripe_offset);
        __swab32s (&ld->ld_pattern);
        /* uuid endian insensitive */
}

void lustre_swab_ldlm_res_id (struct ldlm_res_id *id)
{
        int  i;
        
        for (i = 0; i < RES_NAME_SIZE; i++)
                __swab64s (&id->name[i]);
}

void lustre_swab_ldlm_extent (struct ldlm_extent *e)
{
        __swab64s (&e->start);
        __swab64s (&e->end);
}

void lustre_swab_ldlm_intent (struct ldlm_intent *i)
{
        __swab64s (&i->opc);
}

void lustre_swab_ldlm_resource_desc (struct ldlm_resource_desc *r)
{
        int   i;
        
        __swab32s (&r->lr_type);
        lustre_swab_ldlm_res_id (&r->lr_name);
        for (i = 0; i < RES_VERSION_SIZE; i++)
                __swab32s (&r->lr_version[i]);
}

void lustre_swab_ldlm_lock_desc (struct ldlm_lock_desc *l)
{
        int   i;
        
        lustre_swab_ldlm_resource_desc (&l->l_resource);
        __swab32s (&l->l_req_mode);
        __swab32s (&l->l_granted_mode);
        lustre_swab_ldlm_extent (&l->l_extent);
        for (i = 0; i < RES_VERSION_SIZE; i++)
                __swab32s (&l->l_version[i]);
}

void lustre_swab_ldlm_request (struct ldlm_request *rq)
{
        __swab32s (&rq->lock_flags);
        lustre_swab_ldlm_lock_desc (&rq->lock_desc);
        /* lock_handle1 opaque */
        /* lock_handle2 opaque */
}

void lustre_swab_ldlm_reply (struct ldlm_reply *r)
{
        __swab32s (&r->lock_flags);
        __swab32s (&r->lock_mode);
        lustre_swab_ldlm_res_id (&r->lock_resource_name);
        /* lock_handle opaque */
        lustre_swab_ldlm_extent (&r->lock_extent);
        __swab64s (&r->lock_policy_res1);
        __swab64s (&r->lock_policy_res2);
}

void lustre_swab_ptlbd_op (struct ptlbd_op *op)
{
        __swab16s (&op->op_cmd);
        __swab16s (&op->op_lun);
        __swab16s (&op->op_niob_cnt);
        /* ignore op__padding */
        __swab32s (&op->op_block_cnt);
}

void lustre_swab_ptlbd_niob (struct ptlbd_niob *n)
{
        __swab64s (&n->n_xid);
        __swab64s (&n->n_block_nr);
        __swab32s (&n->n_offset);
        __swab32s (&n->n_length);
}

void lustre_swab_ptlbd_rsp (struct ptlbd_rsp *r)
{
        __swab16s (&r->r_status);
        __swab16s (&r->r_error_cnt);
}
