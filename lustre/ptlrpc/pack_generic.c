/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eeb@clusterfs.com>
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
#include <linux/obd_class.h>
#include <linux/lustre_net.h>


#define HDR_SIZE(count) \
    size_round(offsetof (struct lustre_msg, buflens[(count)]))

int lustre_msg_swabbed(struct lustre_msg *msg)
{
        return (msg->magic == __swab32(PTLRPC_MSG_MAGIC));
}

static void
lustre_init_msg (struct lustre_msg *msg, int count, int *lens, char **bufs)
{
        char *ptr;
        int   i;
        
        msg->magic = PTLRPC_MSG_MAGIC;
        msg->version = PTLRPC_MSG_VERSION;
        msg->bufcount = count;
        for (i = 0; i < count; i++)
                msg->buflens[i] = lens[i];

        if (bufs == NULL)
                return;

        ptr = (char *)msg + HDR_SIZE(count);
        for (i = 0; i < count; i++) {
                char *tmp = bufs[i];
                LOGL(tmp, lens[i], ptr);
        }
}

int lustre_pack_request (struct ptlrpc_request *req, 
                         int count, int *lens, char **bufs)
{
        ENTRY;
        
        req->rq_reqlen = lustre_msg_size (count, lens);
        OBD_ALLOC(req->rq_reqmsg, req->rq_reqlen);
        if (req->rq_reqmsg == NULL)
                RETURN(-ENOMEM);

        lustre_init_msg (req->rq_reqmsg, count, lens, bufs);
        RETURN (0);
}

#if RS_DEBUG
LIST_HEAD(ptlrpc_rs_debug_lru);
spinlock_t ptlrpc_rs_debug_lock = SPIN_LOCK_UNLOCKED;

#define PTLRPC_RS_DEBUG_LRU_ADD(rs)                                     \
do {                                                                    \
        unsigned long __flags;                                          \
                                                                        \
        spin_lock_irqsave(&ptlrpc_rs_debug_lock, __flags);              \
        list_add_tail(&(rs)->rs_debug_list, &ptlrpc_rs_debug_lru);      \
        spin_unlock_irqrestore(&ptlrpc_rs_debug_lock, __flags);         \
} while (0)

#define PTLRPC_RS_DEBUG_LRU_DEL(rs)                                     \
do {                                                                    \
        unsigned long __flags;                                          \
                                                                        \
        spin_lock_irqsave(&ptlrpc_rs_debug_lock, __flags);              \
        list_del(&(rs)->rs_debug_list);                                 \
        spin_unlock_irqrestore(&ptlrpc_rs_debug_lock, __flags);         \
} while (0)
#else
# define PTLRPC_RS_DEBUG_LRU_ADD(rs) do {} while(0)
# define PTLRPC_RS_DEBUG_LRU_DEL(rs) do {} while(0)
#endif

int lustre_pack_reply (struct ptlrpc_request *req,
                       int count, int *lens, char **bufs)
{
        struct ptlrpc_reply_state *rs;
        int                        msg_len;
        int                        size;
        ENTRY;

        LASSERT (req->rq_reply_state == NULL);

        msg_len = lustre_msg_size (count, lens);
        size = offsetof (struct ptlrpc_reply_state, rs_msg) + msg_len;
        OBD_ALLOC (rs, size);
        if (rs == NULL)
                RETURN (-ENOMEM);

        rs->rs_cb_id.cbid_fn = reply_out_callback;
        rs->rs_cb_id.cbid_arg = rs;
        rs->rs_srv_ni = req->rq_rqbd->rqbd_srv_ni;
        rs->rs_size = size;
        INIT_LIST_HEAD(&rs->rs_exp_list);
        INIT_LIST_HEAD(&rs->rs_obd_list);

        req->rq_replen = msg_len;
        req->rq_reply_state = rs;
        req->rq_repmsg = &rs->rs_msg;
        lustre_init_msg (&rs->rs_msg, count, lens, bufs);

        PTLRPC_RS_DEBUG_LRU_ADD(rs);

        RETURN (0);
}

void lustre_free_reply_state (struct ptlrpc_reply_state *rs)
{
        PTLRPC_RS_DEBUG_LRU_DEL(rs);

        LASSERT (!rs->rs_difficult || rs->rs_handled);
        LASSERT (!rs->rs_on_net);
        LASSERT (!rs->rs_scheduled);
        LASSERT (rs->rs_export == NULL);
        LASSERT (rs->rs_nlocks == 0);
        LASSERT (list_empty(&rs->rs_exp_list));
        LASSERT (list_empty(&rs->rs_obd_list));

        OBD_FREE (rs, rs->rs_size);
}

/* This returns the size of the buffer that is required to hold a lustre_msg
 * with the given sub-buffer lengths. */
int lustre_msg_size(int count, int *lengths)
{
        int size;
        int i;

        size = HDR_SIZE (count);
        for (i = 0; i < count; i++)
                size += size_round(lengths[i]);

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
        required_len = MAX (offsetof (struct lustre_msg, version) +
                            sizeof (m->version),
                            offsetof (struct lustre_msg, magic) +
                            sizeof (m->magic));
        if (len < required_len) {
                /* can't even look inside the message */
                CERROR ("message length %d too small for magic/version check\n",
                        len);
                RETURN (-EINVAL);
        }

        flipped = lustre_msg_swabbed(m);
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

        /* Now we know the sender speaks my language (but possibly flipped)...*/
        required_len = HDR_SIZE(0);
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

        required_len = HDR_SIZE(m->bufcount);

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
                CDEBUG(D_INFO, "msg %p buffer[%d] not present (count %d)\n",
                       m, n, bufcount);
                return NULL;
        }

        buflen = m->buflens[n];
        if (buflen < min_size) {
                CERROR("msg %p buffer[%d] size %d too small (required %d)\n",
                       m, n, buflen, min_size);
                return NULL;
        }

        offset = HDR_SIZE(bufcount);
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
void *lustre_swab_reqbuf (struct ptlrpc_request *req, int index, int min_size,
                          void *swabber)
{
        void *ptr;

        LASSERT_REQSWAB(req, index);

        ptr = lustre_msg_buf(req->rq_reqmsg, index, min_size);
        if (ptr == NULL)
                return NULL;

        if (swabber != NULL && lustre_msg_swabbed(req->rq_reqmsg))
                ((void (*)(void *))swabber)(ptr);

        return ptr;
}

/* Wrap up the normal fixed length case */
void *lustre_swab_repbuf (struct ptlrpc_request *req, int index, int min_size,
                          void *swabber)
{
        void *ptr;

        LASSERT_REPSWAB(req, index);

        ptr = lustre_msg_buf(req->rq_repmsg, index, min_size);
        if (ptr == NULL)
                return NULL;

        if (swabber != NULL && lustre_msg_swabbed(req->rq_repmsg))
                ((void (*)(void *))swabber)(ptr);

        return ptr;
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
        __swab64s (&o->o_grant);
        __swab32s (&o->o_blksize);
        __swab32s (&o->o_mode);
        __swab32s (&o->o_uid);
        __swab32s (&o->o_gid);
        __swab32s (&o->o_flags);
        __swab32s (&o->o_nlink);
        __swab32s (&o->o_generation);
        __swab32s (&o->o_valid);
        __swab32s (&o->o_misc);
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
        __swab32s (&nbr->flags);
}

void lustre_swab_ost_body (struct ost_body *b)
{
        lustre_swab_obdo (&b->oa);
}

void lustre_swab_ost_last_id(obd_id *id)
{
        __swab64s(id);
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
        __swab32s (&sa->sa_suppgid);
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
        __swab32s (&lk->lk_suppgid1);
        __swab32s (&lk->lk_suppgid2);
        lustre_swab_ll_fid (&lk->lk_fid1);
        lustre_swab_ll_fid (&lk->lk_fid2);
}

void lustre_swab_mds_rec_unlink (struct mds_rec_unlink *ul)
{
        __swab32s (&ul->ul_opcode);
        __swab32s (&ul->ul_fsuid);
        __swab32s (&ul->ul_fsgid);
        __swab32s (&ul->ul_cap);
        __swab32s (&ul->ul_suppgid);
        __swab32s (&ul->ul_mode);
        lustre_swab_ll_fid (&ul->ul_fid1);
        lustre_swab_ll_fid (&ul->ul_fid2);
}

void lustre_swab_mds_rec_rename (struct mds_rec_rename *rn)
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

void lustre_swab_ldlm_policy_data (ldlm_policy_data_t *d)
{
        /* the lock data is a union and the first two fields are always an
         * extent so it's ok to process an LDLM_EXTENT and LDLM_FLOCK lock
         * data the same way. */
        __swab64s (&d->l_flock.start);
        __swab64s (&d->l_flock.end);
        __swab32s (&d->l_flock.pid);
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
        lustre_swab_ldlm_policy_data (&l->l_policy_data);
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
        lustre_swab_ldlm_policy_data (&r->lock_policy_data);
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

/* no one calls this */
int llog_log_swabbed(struct llog_log_hdr *hdr)
{
        if (hdr->llh_hdr.lrh_type == __swab32(LLOG_HDR_MAGIC))
                return 1;
        if (hdr->llh_hdr.lrh_type == LLOG_HDR_MAGIC)
                return 0;
        return -1;
}

void lustre_swab_llogd_body (struct llogd_body *d)
{
        __swab64s (&d->lgd_logid.lgl_oid);
        __swab64s (&d->lgd_logid.lgl_ogr);
        __swab32s (&d->lgd_logid.lgl_ogen);
        __swab32s (&d->lgd_ctxt_idx);
        __swab32s (&d->lgd_llh_flags);
        __swab32s (&d->lgd_index);
        __swab32s (&d->lgd_saved_index);
        __swab32s (&d->lgd_len);
        __swab64s (&d->lgd_cur_offset);
}

void lustre_swab_llog_hdr (struct llog_log_hdr *h)
{
        __swab32s (&h->llh_hdr.lrh_index);
        __swab32s (&h->llh_hdr.lrh_len);
        __swab32s (&h->llh_hdr.lrh_type);
        __swab64s (&h->llh_timestamp);
        __swab32s (&h->llh_count);
        __swab32s (&h->llh_bitmap_offset);
        __swab32s (&h->llh_flags);
        __swab32s (&h->llh_tail.lrt_index);
        __swab32s (&h->llh_tail.lrt_len);
}

void lustre_swab_llogd_conn_body (struct llogd_conn_body *d)
{
        __swab64s (&d->lgdc_gen.mnt_cnt);
        __swab64s (&d->lgdc_gen.conn_cnt);
        __swab64s (&d->lgdc_logid.lgl_oid);
        __swab64s (&d->lgdc_logid.lgl_ogr);
        __swab32s (&d->lgdc_logid.lgl_ogen);
        __swab32s (&d->lgdc_ctxt_idx);
}

#ifdef BUG_1343
void lustre_assert_wire_constants(void)
{
        /* Wire protocol assertions generated by 'wirecheck'
         * running on Linux schnapps.adilger.int 2.4.22-l32 #4 Thu Jan 8 14:32:57 MST 2004 i686 i686 
         * with gcc version 3.2.2 20030222 (Red Hat Linux 3.2.2-5) */


        /* Constants... */
        LASSERT(PTLRPC_MSG_MAGIC == 0x0BD00BD0);
        LASSERT(PTLRPC_MSG_VERSION == 0x00000003);
        LASSERT(PTL_RPC_MSG_REQUEST == 4711);
        LASSERT(PTL_RPC_MSG_ERR == 4712);
        LASSERT(PTL_RPC_MSG_REPLY == 4713);
        LASSERT(MSG_LAST_REPLAY == 1);
        LASSERT(MSG_RESENT == 2);
        LASSERT(MSG_CONNECT_RECOVERING == 1);
        LASSERT(MSG_CONNECT_RECONNECT == 2);
        LASSERT(MSG_CONNECT_REPLAYABLE == 4);
        LASSERT(OST_REPLY == 0);
        LASSERT(OST_GETATTR == 1);
        LASSERT(OST_SETATTR == 2);
        LASSERT(OST_READ == 3);
        LASSERT(OST_WRITE == 4);
        LASSERT(OST_CREATE == 5);
        LASSERT(OST_DESTROY == 6);
        LASSERT(OST_GET_INFO == 7);
        LASSERT(OST_CONNECT == 8);
        LASSERT(OST_DISCONNECT == 9);
        LASSERT(OST_PUNCH == 10);
        LASSERT(OST_OPEN == 11);
        LASSERT(OST_CLOSE == 12);
        LASSERT(OST_STATFS == 13);
        LASSERT(OST_SAN_READ == 14);
        LASSERT(OST_SAN_WRITE == 15);
        LASSERT(OST_SYNC == 16);
        LASSERT(OST_LAST_OPC == 18);
        LASSERT(OBD_OBJECT_EOF == 0xffffffffffffffffULL);
        LASSERT(OST_REQ_HAS_OA1 == 1);
        LASSERT(MDS_GETATTR == 33);
        LASSERT(MDS_GETATTR_NAME == 34);
        LASSERT(MDS_CLOSE == 35);
        LASSERT(MDS_REINT == 36);
        LASSERT(MDS_READPAGE == 37);
        LASSERT(MDS_CONNECT == 38);
        LASSERT(MDS_DISCONNECT == 39);
        LASSERT(MDS_GETSTATUS == 40);
        LASSERT(MDS_STATFS == 41);
        LASSERT(MDS_PIN == 42);
        LASSERT(MDS_UNPIN == 43);
        LASSERT(MDS_SYNC == 44);
        LASSERT(MDS_DONE_WRITING == 45);
        LASSERT(MDS_LAST_OPC == 46);
        LASSERT(REINT_SETATTR == 1);
        LASSERT(REINT_CREATE == 2);
        LASSERT(REINT_LINK == 3);
        LASSERT(REINT_UNLINK == 4);
        LASSERT(REINT_RENAME == 5);
        LASSERT(REINT_OPEN == 6);
        LASSERT(REINT_MAX == 6);
        LASSERT(DISP_IT_EXECD == 1);
        LASSERT(DISP_LOOKUP_EXECD == 2);
        LASSERT(DISP_LOOKUP_NEG == 4);
        LASSERT(DISP_LOOKUP_POS == 8);
        LASSERT(DISP_OPEN_CREATE == 16);
        LASSERT(DISP_OPEN_OPEN == 32);
        LASSERT(MDS_STATUS_CONN == 1);
        LASSERT(MDS_STATUS_LOV == 2);
        LASSERT(MDS_OPEN_HAS_EA == 1073741824);
        LASSERT(LDLM_ENQUEUE == 101);
        LASSERT(LDLM_CONVERT == 102);
        LASSERT(LDLM_CANCEL == 103);
        LASSERT(LDLM_BL_CALLBACK == 104);
        LASSERT(LDLM_CP_CALLBACK == 105);
        LASSERT(LDLM_LAST_OPC == 106);
        LASSERT(LCK_EX == 1);
        LASSERT(LCK_PW == 2);
        LASSERT(LCK_PR == 3);
        LASSERT(LCK_CW == 4);
        LASSERT(LCK_CR == 5);
        LASSERT(LCK_NL == 6);
        LASSERT(PTLBD_QUERY == 200);
        LASSERT(PTLBD_READ == 201);
        LASSERT(PTLBD_WRITE == 202);
        LASSERT(PTLBD_FLUSH == 203);
        LASSERT(PTLBD_CONNECT == 204);
        LASSERT(PTLBD_DISCONNECT == 205);
        LASSERT(PTLBD_LAST_OPC == 206);
        LASSERT(MGMT_CONNECT == 250);
        LASSERT(MGMT_DISCONNECT == 251);
        LASSERT(MGMT_EXCEPTION == 252);
        LASSERT(OBD_PING == 400);
        LASSERT(OBD_LOG_CANCEL == 401);
        LASSERT(OBD_LAST_OPC == 402);
        /* Sizes and Offsets */


        /* Checks for struct lustre_handle */
        LASSERT((int)sizeof(struct lustre_handle) == 8);
        LASSERT(offsetof(struct lustre_handle, cookie) == 0);
        LASSERT((int)sizeof(((struct lustre_handle *)0)->cookie) == 8);

        /* Checks for struct lustre_msg */
        LASSERT((int)sizeof(struct lustre_msg) == 64);
        LASSERT(offsetof(struct lustre_msg, handle) == 0);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->handle) == 8);
        LASSERT(offsetof(struct lustre_msg, magic) == 8);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->magic) == 4);
        LASSERT(offsetof(struct lustre_msg, type) == 12);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->type) == 4);
        LASSERT(offsetof(struct lustre_msg, version) == 16);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->version) == 4);
        LASSERT(offsetof(struct lustre_msg, opc) == 20);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->opc) == 4);
        LASSERT(offsetof(struct lustre_msg, last_xid) == 24);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->last_xid) == 8);
        LASSERT(offsetof(struct lustre_msg, last_committed) == 32);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->last_committed) == 8);
        LASSERT(offsetof(struct lustre_msg, transno) == 40);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->transno) == 8);
        LASSERT(offsetof(struct lustre_msg, status) == 48);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->status) == 4);
        LASSERT(offsetof(struct lustre_msg, flags) == 52);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->flags) == 4);
        LASSERT(offsetof(struct lustre_msg, bufcount) == 60);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->bufcount) == 4);
        LASSERT(offsetof(struct lustre_msg, buflens[7]) == 92);
        LASSERT((int)sizeof(((struct lustre_msg *)0)->buflens[7]) == 4);

        /* Checks for struct obdo */
        LASSERT((int)sizeof(struct obdo) == 168);
        LASSERT(offsetof(struct obdo, o_id) == 0);
        LASSERT((int)sizeof(((struct obdo *)0)->o_id) == 8);
        LASSERT(offsetof(struct obdo, o_gr) == 8);
        LASSERT((int)sizeof(((struct obdo *)0)->o_gr) == 8);
        LASSERT(offsetof(struct obdo, o_atime) == 16);
        LASSERT((int)sizeof(((struct obdo *)0)->o_atime) == 8);
        LASSERT(offsetof(struct obdo, o_mtime) == 24);
        LASSERT((int)sizeof(((struct obdo *)0)->o_mtime) == 8);
        LASSERT(offsetof(struct obdo, o_ctime) == 32);
        LASSERT((int)sizeof(((struct obdo *)0)->o_ctime) == 8);
        LASSERT(offsetof(struct obdo, o_size) == 40);
        LASSERT((int)sizeof(((struct obdo *)0)->o_size) == 8);
        LASSERT(offsetof(struct obdo, o_blocks) == 48);
        LASSERT((int)sizeof(((struct obdo *)0)->o_blocks) == 8);
        LASSERT(offsetof(struct obdo, o_grant) == 56);
        LASSERT((int)sizeof(((struct obdo *)0)->o_grant) == 8);
        LASSERT(offsetof(struct obdo, o_blksize) == 64);
        LASSERT((int)sizeof(((struct obdo *)0)->o_blksize) == 4);
        LASSERT(offsetof(struct obdo, o_mode) == 68);
        LASSERT((int)sizeof(((struct obdo *)0)->o_mode) == 4);
        LASSERT(offsetof(struct obdo, o_uid) == 72);
        LASSERT((int)sizeof(((struct obdo *)0)->o_uid) == 4);
        LASSERT(offsetof(struct obdo, o_gid) == 76);
        LASSERT((int)sizeof(((struct obdo *)0)->o_gid) == 4);
        LASSERT(offsetof(struct obdo, o_flags) == 80);
        LASSERT((int)sizeof(((struct obdo *)0)->o_flags) == 4);
        LASSERT(offsetof(struct obdo, o_nlink) == 84);
        LASSERT((int)sizeof(((struct obdo *)0)->o_nlink) == 4);
        LASSERT(offsetof(struct obdo, o_generation) == 88);
        LASSERT((int)sizeof(((struct obdo *)0)->o_generation) == 4);
        LASSERT(offsetof(struct obdo, o_valid) == 92);
        LASSERT((int)sizeof(((struct obdo *)0)->o_valid) == 4);
        LASSERT(offsetof(struct obdo, o_misc) == 96);
        LASSERT((int)sizeof(((struct obdo *)0)->o_misc) == 4);
        LASSERT(offsetof(struct obdo, o_easize) == 100);
        LASSERT((int)sizeof(((struct obdo *)0)->o_easize) == 4);
        LASSERT(offsetof(struct obdo, o_inline) == 104);
        LASSERT((int)sizeof(((struct obdo *)0)->o_inline) == 64);
        LASSERT(OBD_MD_FLID == 1);
        LASSERT(OBD_MD_FLATIME == 2);
        LASSERT(OBD_MD_FLMTIME == 4);
        LASSERT(OBD_MD_FLCTIME == 8);
        LASSERT(OBD_MD_FLSIZE == 16);
        LASSERT(OBD_MD_FLBLOCKS == 32);
        LASSERT(OBD_MD_FLBLKSZ == 64);
        LASSERT(OBD_MD_FLMODE == 128);
        LASSERT(OBD_MD_FLTYPE == 256);
        LASSERT(OBD_MD_FLUID == 512);
        LASSERT(OBD_MD_FLGID == 1024);
        LASSERT(OBD_MD_FLFLAGS == 2048);
        LASSERT(OBD_MD_FLNLINK == 8192);
        LASSERT(OBD_MD_FLGENER == 16384);
        LASSERT(OBD_MD_FLINLINE == 32768);
        LASSERT(OBD_MD_FLRDEV == 65536);
        LASSERT(OBD_MD_FLEASIZE == 131072);
        LASSERT(OBD_MD_LINKNAME == 262144);
        LASSERT(OBD_MD_FLHANDLE == 524288);
        LASSERT(OBD_MD_FLCKSUM == 1048576);
        LASSERT(OBD_MD_FLQOS == 2097152);
        LASSERT(OBD_MD_FLOSCOPQ == 4194304);
        LASSERT(OBD_MD_FLCOOKIE == 8388608);
        LASSERT(OBD_MD_FLGROUP == 16777216);
        LASSERT(OBD_FL_INLINEDATA == 1);
        LASSERT(OBD_FL_OBDMDEXISTS == 2);
        LASSERT(OBD_FL_DELORPHAN == 4);
        LASSERT(OBD_FL_NORPC == 8);
        LASSERT(OBD_FL_IDONLY == 16);
        LASSERT(OBD_FL_RECREATE_OBJS == 32);

        /* Checks for struct lov_mds_md_v1 */
        LASSERT((int)sizeof(struct lov_mds_md_v1) == 32);
        LASSERT(offsetof(struct lov_mds_md_v1, lmm_magic) == 0);
        LASSERT((int)sizeof(((struct lov_mds_md_v1 *)0)->lmm_magic) == 4);
        LASSERT(offsetof(struct lov_mds_md_v1, lmm_pattern) == 4);
        LASSERT((int)sizeof(((struct lov_mds_md_v1 *)0)->lmm_pattern) == 4);
        LASSERT(offsetof(struct lov_mds_md_v1, lmm_object_id) == 8);
        LASSERT((int)sizeof(((struct lov_mds_md_v1 *)0)->lmm_object_id) == 8);
        LASSERT(offsetof(struct lov_mds_md_v1, lmm_object_gr) == 16);
        LASSERT((int)sizeof(((struct lov_mds_md_v1 *)0)->lmm_object_gr) == 8);
        LASSERT(offsetof(struct lov_mds_md_v1, lmm_stripe_size) == 24);
        LASSERT((int)sizeof(((struct lov_mds_md_v1 *)0)->lmm_stripe_size) == 4);
        LASSERT(offsetof(struct lov_mds_md_v1, lmm_stripe_count) == 28);
        LASSERT((int)sizeof(((struct lov_mds_md_v1 *)0)->lmm_stripe_count) == 4);
        LASSERT(offsetof(struct lov_mds_md_v1, lmm_objects) == 32);
        LASSERT((int)sizeof(((struct lov_mds_md_v1 *)0)->lmm_objects) == 0);

        /* Checks for struct lov_ost_data_v1 */
        LASSERT((int)sizeof(struct lov_ost_data_v1) == 24);
        LASSERT(offsetof(struct lov_ost_data_v1, l_object_id) == 0);
        LASSERT((int)sizeof(((struct lov_ost_data_v1 *)0)->l_object_id) == 8);
        LASSERT(offsetof(struct lov_ost_data_v1, l_object_gr) == 8);
        LASSERT((int)sizeof(((struct lov_ost_data_v1 *)0)->l_object_gr) == 8);
        LASSERT(offsetof(struct lov_ost_data_v1, l_ost_gen) == 16);
        LASSERT((int)sizeof(((struct lov_ost_data_v1 *)0)->l_ost_gen) == 4);
        LASSERT(offsetof(struct lov_ost_data_v1, l_ost_idx) == 20);
        LASSERT((int)sizeof(((struct lov_ost_data_v1 *)0)->l_ost_idx) == 4);
        LASSERT(LOV_MAGIC_V0 == 198183888);
        LASSERT(LOV_MAGIC_V1 == 198249424);
        LASSERT(LOV_PATTERN_RAID0 == 1);
        LASSERT(LOV_PATTERN_RAID1 == 2);

        /* Checks for struct obd_statfs */
        LASSERT((int)sizeof(struct obd_statfs) == 144);
        LASSERT(offsetof(struct obd_statfs, os_type) == 0);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_type) == 8);
        LASSERT(offsetof(struct obd_statfs, os_blocks) == 8);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_blocks) == 8);
        LASSERT(offsetof(struct obd_statfs, os_bfree) == 16);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_bfree) == 8);
        LASSERT(offsetof(struct obd_statfs, os_bavail) == 24);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_bavail) == 8);
        LASSERT(offsetof(struct obd_statfs, os_ffree) == 40);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_ffree) == 8);
        LASSERT(offsetof(struct obd_statfs, os_fsid) == 48);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_fsid) == 40);
        LASSERT(offsetof(struct obd_statfs, os_bsize) == 88);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_bsize) == 4);
        LASSERT(offsetof(struct obd_statfs, os_namelen) == 92);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_namelen) == 4);
        LASSERT(offsetof(struct obd_statfs, os_spare) == 104);
        LASSERT((int)sizeof(((struct obd_statfs *)0)->os_spare) == 40);

        /* Checks for struct obd_ioobj */
        LASSERT((int)sizeof(struct obd_ioobj) == 24);
        LASSERT(offsetof(struct obd_ioobj, ioo_id) == 0);
        LASSERT((int)sizeof(((struct obd_ioobj *)0)->ioo_id) == 8);
        LASSERT(offsetof(struct obd_ioobj, ioo_gr) == 8);
        LASSERT((int)sizeof(((struct obd_ioobj *)0)->ioo_gr) == 8);
        LASSERT(offsetof(struct obd_ioobj, ioo_type) == 16);
        LASSERT((int)sizeof(((struct obd_ioobj *)0)->ioo_type) == 4);
        LASSERT(offsetof(struct obd_ioobj, ioo_bufcnt) == 20);
        LASSERT((int)sizeof(((struct obd_ioobj *)0)->ioo_bufcnt) == 4);

        /* Checks for struct niobuf_remote */
        LASSERT((int)sizeof(struct niobuf_remote) == 16);
        LASSERT(offsetof(struct niobuf_remote, offset) == 0);
        LASSERT((int)sizeof(((struct niobuf_remote *)0)->offset) == 8);
        LASSERT(offsetof(struct niobuf_remote, len) == 8);
        LASSERT((int)sizeof(((struct niobuf_remote *)0)->len) == 4);
        LASSERT(offsetof(struct niobuf_remote, flags) == 12);
        LASSERT((int)sizeof(((struct niobuf_remote *)0)->flags) == 4);
        LASSERT(OBD_BRW_READ == 1);
        LASSERT(OBD_BRW_WRITE == 2);
        LASSERT(OBD_BRW_SYNC == 8);
        LASSERT(OBD_BRW_FROM_GRANT == 32);

        /* Checks for struct ost_body */
        LASSERT((int)sizeof(struct ost_body) == 168);
        LASSERT(offsetof(struct ost_body, oa) == 0);
        LASSERT((int)sizeof(((struct ost_body *)0)->oa) == 168);

        /* Checks for struct ll_fid */
        LASSERT((int)sizeof(struct ll_fid) == 16);
        LASSERT(offsetof(struct ll_fid, id) == 0);
        LASSERT((int)sizeof(((struct ll_fid *)0)->id) == 8);
        LASSERT(offsetof(struct ll_fid, generation) == 8);
        LASSERT((int)sizeof(((struct ll_fid *)0)->generation) == 4);
        LASSERT(offsetof(struct ll_fid, f_type) == 12);
        LASSERT((int)sizeof(((struct ll_fid *)0)->f_type) == 4);

        /* Checks for struct mds_status_req */
        LASSERT((int)sizeof(struct mds_status_req) == 8);
        LASSERT(offsetof(struct mds_status_req, flags) == 0);
        LASSERT((int)sizeof(((struct mds_status_req *)0)->flags) == 4);
        LASSERT(offsetof(struct mds_status_req, repbuf) == 4);
        LASSERT((int)sizeof(((struct mds_status_req *)0)->repbuf) == 4);

        /* Checks for struct mds_body */
        LASSERT((int)sizeof(struct mds_body) == 136);
        LASSERT(offsetof(struct mds_body, fid1) == 0);
        LASSERT((int)sizeof(((struct mds_body *)0)->fid1) == 16);
        LASSERT(offsetof(struct mds_body, fid2) == 16);
        LASSERT((int)sizeof(((struct mds_body *)0)->fid2) == 16);
        LASSERT(offsetof(struct mds_body, handle) == 32);
        LASSERT((int)sizeof(((struct mds_body *)0)->handle) == 8);
        LASSERT(offsetof(struct mds_body, size) == 40);
        LASSERT((int)sizeof(((struct mds_body *)0)->size) == 8);
        LASSERT(offsetof(struct mds_body, blocks) == 48);
        LASSERT((int)sizeof(((struct mds_body *)0)->blocks) == 8);
        LASSERT(offsetof(struct mds_body, io_epoch) == 56);
        LASSERT((int)sizeof(((struct mds_body *)0)->io_epoch) == 8);
        LASSERT(offsetof(struct mds_body, ino) == 64);
        LASSERT((int)sizeof(((struct mds_body *)0)->ino) == 4);
        LASSERT(offsetof(struct mds_body, valid) == 68);
        LASSERT((int)sizeof(((struct mds_body *)0)->valid) == 4);
        LASSERT(offsetof(struct mds_body, fsuid) == 72);
        LASSERT((int)sizeof(((struct mds_body *)0)->fsuid) == 4);
        LASSERT(offsetof(struct mds_body, fsgid) == 76);
        LASSERT((int)sizeof(((struct mds_body *)0)->fsgid) == 4);
        LASSERT(offsetof(struct mds_body, capability) == 80);
        LASSERT((int)sizeof(((struct mds_body *)0)->capability) == 4);
        LASSERT(offsetof(struct mds_body, mode) == 84);
        LASSERT((int)sizeof(((struct mds_body *)0)->mode) == 4);
        LASSERT(offsetof(struct mds_body, uid) == 88);
        LASSERT((int)sizeof(((struct mds_body *)0)->uid) == 4);
        LASSERT(offsetof(struct mds_body, gid) == 92);
        LASSERT((int)sizeof(((struct mds_body *)0)->gid) == 4);
        LASSERT(offsetof(struct mds_body, mtime) == 96);
        LASSERT((int)sizeof(((struct mds_body *)0)->mtime) == 4);
        LASSERT(offsetof(struct mds_body, ctime) == 100);
        LASSERT((int)sizeof(((struct mds_body *)0)->ctime) == 4);
        LASSERT(offsetof(struct mds_body, atime) == 104);
        LASSERT((int)sizeof(((struct mds_body *)0)->atime) == 4);
        LASSERT(offsetof(struct mds_body, flags) == 108);
        LASSERT((int)sizeof(((struct mds_body *)0)->flags) == 4);
        LASSERT(offsetof(struct mds_body, rdev) == 112);
        LASSERT((int)sizeof(((struct mds_body *)0)->rdev) == 4);
        LASSERT(offsetof(struct mds_body, nlink) == 116);
        LASSERT((int)sizeof(((struct mds_body *)0)->nlink) == 4);
        LASSERT(offsetof(struct mds_body, generation) == 120);
        LASSERT((int)sizeof(((struct mds_body *)0)->generation) == 4);
        LASSERT(offsetof(struct mds_body, suppgid) == 124);
        LASSERT((int)sizeof(((struct mds_body *)0)->suppgid) == 4);
        LASSERT(offsetof(struct mds_body, eadatasize) == 128);
        LASSERT((int)sizeof(((struct mds_body *)0)->eadatasize) == 4);
        LASSERT(FMODE_READ == 1);
        LASSERT(FMODE_WRITE == 2);
        LASSERT(FMODE_EXEC == 4);
        LASSERT(MDS_OPEN_CREAT == 64);
        LASSERT(MDS_OPEN_EXCL == 128);
        LASSERT(MDS_OPEN_TRUNC == 512);
        LASSERT(MDS_OPEN_APPEND == 1024);
        LASSERT(MDS_OPEN_SYNC == 4096);
        LASSERT(MDS_OPEN_DIRECTORY == 65536);
        LASSERT(MDS_OPEN_DELAY_CREATE == 16777216);
        LASSERT(MDS_OPEN_HAS_EA == 1073741824);

        /* Checks for struct mds_rec_setattr */
        LASSERT((int)sizeof(struct mds_rec_setattr) == 88);
        LASSERT(offsetof(struct mds_rec_setattr, sa_opcode) == 0);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_opcode) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_fsuid) == 4);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_fsuid) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_fsgid) == 8);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_fsgid) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_cap) == 12);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_cap) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_suppgid) == 16);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_suppgid) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_valid) == 20);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_valid) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_fid) == 24);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_fid) == 16);
        LASSERT(offsetof(struct mds_rec_setattr, sa_mode) == 40);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_mode) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_uid) == 44);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_uid) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_gid) == 48);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_gid) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_attr_flags) == 52);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_attr_flags) == 4);
        LASSERT(offsetof(struct mds_rec_setattr, sa_size) == 56);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_size) == 8);
        LASSERT(offsetof(struct mds_rec_setattr, sa_atime) == 64);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_atime) == 8);
        LASSERT(offsetof(struct mds_rec_setattr, sa_mtime) == 72);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_mtime) == 8);
        LASSERT(offsetof(struct mds_rec_setattr, sa_ctime) == 80);
        LASSERT((int)sizeof(((struct mds_rec_setattr *)0)->sa_ctime) == 8);

        /* Checks for struct mds_rec_create */
        LASSERT((int)sizeof(struct mds_rec_create) == 80);
        LASSERT(offsetof(struct mds_rec_create, cr_opcode) == 0);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_opcode) == 4);
        LASSERT(offsetof(struct mds_rec_create, cr_fsuid) == 4);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_fsuid) == 4);
        LASSERT(offsetof(struct mds_rec_create, cr_fsgid) == 8);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_fsgid) == 4);
        LASSERT(offsetof(struct mds_rec_create, cr_cap) == 12);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_cap) == 4);
        LASSERT(offsetof(struct mds_rec_create, cr_flags) == 16);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_flags) == 4);
        LASSERT(offsetof(struct mds_rec_create, cr_mode) == 20);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_mode) == 4);
        LASSERT(offsetof(struct mds_rec_create, cr_fid) == 24);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_fid) == 16);
        LASSERT(offsetof(struct mds_rec_create, cr_replayfid) == 40);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_replayfid) == 16);
        LASSERT(offsetof(struct mds_rec_create, cr_time) == 56);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_time) == 8);
        LASSERT(offsetof(struct mds_rec_create, cr_rdev) == 64);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_rdev) == 8);
        LASSERT(offsetof(struct mds_rec_create, cr_suppgid) == 72);
        LASSERT((int)sizeof(((struct mds_rec_create *)0)->cr_suppgid) == 4);

        /* Checks for struct mds_rec_link */
        LASSERT((int)sizeof(struct mds_rec_link) == 64);
        LASSERT(offsetof(struct mds_rec_link, lk_opcode) == 0);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_opcode) == 4);
        LASSERT(offsetof(struct mds_rec_link, lk_fsuid) == 4);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_fsuid) == 4);
        LASSERT(offsetof(struct mds_rec_link, lk_fsgid) == 8);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_fsgid) == 4);
        LASSERT(offsetof(struct mds_rec_link, lk_cap) == 12);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_cap) == 4);
        LASSERT(offsetof(struct mds_rec_link, lk_suppgid1) == 16);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_suppgid1) == 4);
        LASSERT(offsetof(struct mds_rec_link, lk_suppgid2) == 20);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_suppgid2) == 4);
        LASSERT(offsetof(struct mds_rec_link, lk_fid1) == 24);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_fid1) == 16);
        LASSERT(offsetof(struct mds_rec_link, lk_fid2) == 40);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_fid2) == 16);
        LASSERT(offsetof(struct mds_rec_link, lk_time) == 56);
        LASSERT((int)sizeof(((struct mds_rec_link *)0)->lk_time) == 8);

        /* Checks for struct mds_rec_unlink */
        LASSERT((int)sizeof(struct mds_rec_unlink) == 64);
        LASSERT(offsetof(struct mds_rec_unlink, ul_opcode) == 0);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_opcode) == 4);
        LASSERT(offsetof(struct mds_rec_unlink, ul_fsuid) == 4);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_fsuid) == 4);
        LASSERT(offsetof(struct mds_rec_unlink, ul_fsgid) == 8);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_fsgid) == 4);
        LASSERT(offsetof(struct mds_rec_unlink, ul_cap) == 12);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_cap) == 4);
        LASSERT(offsetof(struct mds_rec_unlink, ul_suppgid) == 16);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_suppgid) == 4);
        LASSERT(offsetof(struct mds_rec_unlink, ul_mode) == 20);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_mode) == 4);
        LASSERT(offsetof(struct mds_rec_unlink, ul_fid1) == 24);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_fid1) == 16);
        LASSERT(offsetof(struct mds_rec_unlink, ul_fid2) == 40);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_fid2) == 16);
        LASSERT(offsetof(struct mds_rec_unlink, ul_time) == 56);
        LASSERT((int)sizeof(((struct mds_rec_unlink *)0)->ul_time) == 8);

        /* Checks for struct mds_rec_rename */
        LASSERT((int)sizeof(struct mds_rec_rename) == 64);
        LASSERT(offsetof(struct mds_rec_rename, rn_opcode) == 0);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_opcode) == 4);
        LASSERT(offsetof(struct mds_rec_rename, rn_fsuid) == 4);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_fsuid) == 4);
        LASSERT(offsetof(struct mds_rec_rename, rn_fsgid) == 8);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_fsgid) == 4);
        LASSERT(offsetof(struct mds_rec_rename, rn_cap) == 12);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_cap) == 4);
        LASSERT(offsetof(struct mds_rec_rename, rn_suppgid1) == 16);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_suppgid1) == 4);
        LASSERT(offsetof(struct mds_rec_rename, rn_suppgid2) == 20);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_suppgid2) == 4);
        LASSERT(offsetof(struct mds_rec_rename, rn_fid1) == 24);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_fid1) == 16);
        LASSERT(offsetof(struct mds_rec_rename, rn_fid2) == 40);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_fid2) == 16);
        LASSERT(offsetof(struct mds_rec_rename, rn_time) == 56);
        LASSERT((int)sizeof(((struct mds_rec_rename *)0)->rn_time) == 8);

        /* Checks for struct lov_desc */
        LASSERT((int)sizeof(struct lov_desc) == 72);
        LASSERT(offsetof(struct lov_desc, ld_tgt_count) == 0);
        LASSERT((int)sizeof(((struct lov_desc *)0)->ld_tgt_count) == 4);
        LASSERT(offsetof(struct lov_desc, ld_active_tgt_count) == 4);
        LASSERT((int)sizeof(((struct lov_desc *)0)->ld_active_tgt_count) == 4);
        LASSERT(offsetof(struct lov_desc, ld_default_stripe_count) == 8);
        LASSERT((int)sizeof(((struct lov_desc *)0)->ld_default_stripe_count) == 4);
        LASSERT(offsetof(struct lov_desc, ld_pattern) == 12);
        LASSERT((int)sizeof(((struct lov_desc *)0)->ld_pattern) == 4);
        LASSERT(offsetof(struct lov_desc, ld_default_stripe_size) == 16);
        LASSERT((int)sizeof(((struct lov_desc *)0)->ld_default_stripe_size) == 8);
        LASSERT(offsetof(struct lov_desc, ld_default_stripe_offset) == 24);
        LASSERT((int)sizeof(((struct lov_desc *)0)->ld_default_stripe_offset) == 8);
        LASSERT(offsetof(struct lov_desc, ld_uuid) == 32);
        LASSERT((int)sizeof(((struct lov_desc *)0)->ld_uuid) == 40);

        /* Checks for struct ldlm_res_id */
        LASSERT((int)sizeof(struct ldlm_res_id) == 32);
        LASSERT(offsetof(struct ldlm_res_id, name[4]) == 32);
        LASSERT((int)sizeof(((struct ldlm_res_id *)0)->name[4]) == 8);

        /* Checks for struct ldlm_extent */
        LASSERT((int)sizeof(struct ldlm_extent) == 16);
        LASSERT(offsetof(struct ldlm_extent, start) == 0);
        LASSERT((int)sizeof(((struct ldlm_extent *)0)->start) == 8);
        LASSERT(offsetof(struct ldlm_extent, end) == 8);
        LASSERT((int)sizeof(((struct ldlm_extent *)0)->end) == 8);

        /* Checks for struct ldlm_flock */
        LASSERT((int)sizeof(struct ldlm_flock) == 32);
        LASSERT(offsetof(struct ldlm_flock, start) == 0);
        LASSERT((int)sizeof(((struct ldlm_flock *)0)->start) == 8);
        LASSERT(offsetof(struct ldlm_flock, end) == 8);
        LASSERT((int)sizeof(((struct ldlm_flock *)0)->end) == 8);
        LASSERT(offsetof(struct ldlm_flock, blocking_export) == 16);
        LASSERT((int)sizeof(((struct ldlm_flock *)0)->blocking_export) == 8);
        LASSERT(offsetof(struct ldlm_flock, blocking_pid) == 24);
        LASSERT((int)sizeof(((struct ldlm_flock *)0)->blocking_pid) == 4);
        LASSERT(offsetof(struct ldlm_flock, pid) == 28);
        LASSERT((int)sizeof(((struct ldlm_flock *)0)->pid) == 4);

        /* Checks for struct ldlm_intent */
        LASSERT((int)sizeof(struct ldlm_intent) == 8);
        LASSERT(offsetof(struct ldlm_intent, opc) == 0);
        LASSERT((int)sizeof(((struct ldlm_intent *)0)->opc) == 8);

        /* Checks for struct ldlm_resource_desc */
        LASSERT((int)sizeof(struct ldlm_resource_desc) == 52);
        LASSERT(offsetof(struct ldlm_resource_desc, lr_type) == 0);
        LASSERT((int)sizeof(((struct ldlm_resource_desc *)0)->lr_type) == 4);
        LASSERT(offsetof(struct ldlm_resource_desc, lr_name) == 4);
        LASSERT((int)sizeof(((struct ldlm_resource_desc *)0)->lr_name) == 32);
        LASSERT(offsetof(struct ldlm_resource_desc, lr_version[4]) == 52);
        LASSERT((int)sizeof(((struct ldlm_resource_desc *)0)->lr_version[4]) == 4);

        /* Checks for struct ldlm_lock_desc */
        LASSERT((int)sizeof(struct ldlm_lock_desc) == 108);
        LASSERT(offsetof(struct ldlm_lock_desc, l_resource) == 0);
        LASSERT((int)sizeof(((struct ldlm_lock_desc *)0)->l_resource) == 52);
        LASSERT(offsetof(struct ldlm_lock_desc, l_req_mode) == 52);
        LASSERT((int)sizeof(((struct ldlm_lock_desc *)0)->l_req_mode) == 4);
        LASSERT(offsetof(struct ldlm_lock_desc, l_granted_mode) == 56);
        LASSERT((int)sizeof(((struct ldlm_lock_desc *)0)->l_granted_mode) == 4);
        LASSERT(offsetof(struct ldlm_lock_desc, l_policy_data) == 60);
        LASSERT((int)sizeof(((struct ldlm_lock_desc *)0)->l_policy_data) == 32);
        LASSERT(offsetof(struct ldlm_lock_desc, l_version[4]) == 108);
        LASSERT((int)sizeof(((struct ldlm_lock_desc *)0)->l_version[4]) == 4);

        /* Checks for struct ldlm_request */
        LASSERT((int)sizeof(struct ldlm_request) == 128);
        LASSERT(offsetof(struct ldlm_request, lock_flags) == 0);
        LASSERT((int)sizeof(((struct ldlm_request *)0)->lock_flags) == 4);
        LASSERT(offsetof(struct ldlm_request, lock_desc) == 4);
        LASSERT((int)sizeof(((struct ldlm_request *)0)->lock_desc) == 108);
        LASSERT(offsetof(struct ldlm_request, lock_handle1) == 112);
        LASSERT((int)sizeof(((struct ldlm_request *)0)->lock_handle1) == 8);
        LASSERT(offsetof(struct ldlm_request, lock_handle2) == 120);
        LASSERT((int)sizeof(((struct ldlm_request *)0)->lock_handle2) == 8);

        /* Checks for struct ldlm_reply */
        LASSERT((int)sizeof(struct ldlm_reply) == 96);
        LASSERT(offsetof(struct ldlm_reply, lock_flags) == 0);
        LASSERT((int)sizeof(((struct ldlm_reply *)0)->lock_flags) == 4);
        LASSERT(offsetof(struct ldlm_reply, lock_mode) == 4);
        LASSERT((int)sizeof(((struct ldlm_reply *)0)->lock_mode) == 4);
        LASSERT(offsetof(struct ldlm_reply, lock_resource_name) == 8);
        LASSERT((int)sizeof(((struct ldlm_reply *)0)->lock_resource_name) == 32);
        LASSERT(offsetof(struct ldlm_reply, lock_handle) == 40);
        LASSERT((int)sizeof(((struct ldlm_reply *)0)->lock_handle) == 8);
        LASSERT(offsetof(struct ldlm_reply, lock_policy_data) == 48);
        LASSERT((int)sizeof(((struct ldlm_reply *)0)->lock_policy_data) == 32);
        LASSERT(offsetof(struct ldlm_reply, lock_policy_res1) == 80);
        LASSERT((int)sizeof(((struct ldlm_reply *)0)->lock_policy_res1) == 8);
        LASSERT(offsetof(struct ldlm_reply, lock_policy_res2) == 88);
        LASSERT((int)sizeof(((struct ldlm_reply *)0)->lock_policy_res2) == 8);

        /* Checks for struct ptlbd_op */
        LASSERT((int)sizeof(struct ptlbd_op) == 12);
        LASSERT(offsetof(struct ptlbd_op, op_cmd) == 0);
        LASSERT((int)sizeof(((struct ptlbd_op *)0)->op_cmd) == 2);
        LASSERT(offsetof(struct ptlbd_op, op_lun) == 2);
        LASSERT((int)sizeof(((struct ptlbd_op *)0)->op_lun) == 2);
        LASSERT(offsetof(struct ptlbd_op, op_niob_cnt) == 4);
        LASSERT((int)sizeof(((struct ptlbd_op *)0)->op_niob_cnt) == 2);
        LASSERT(offsetof(struct ptlbd_op, op__padding) == 6);
        LASSERT((int)sizeof(((struct ptlbd_op *)0)->op__padding) == 2);
        LASSERT(offsetof(struct ptlbd_op, op_block_cnt) == 8);
        LASSERT((int)sizeof(((struct ptlbd_op *)0)->op_block_cnt) == 4);

        /* Checks for struct ptlbd_niob */
        LASSERT((int)sizeof(struct ptlbd_niob) == 24);
        LASSERT(offsetof(struct ptlbd_niob, n_xid) == 0);
        LASSERT((int)sizeof(((struct ptlbd_niob *)0)->n_xid) == 8);
        LASSERT(offsetof(struct ptlbd_niob, n_block_nr) == 8);
        LASSERT((int)sizeof(((struct ptlbd_niob *)0)->n_block_nr) == 8);
        LASSERT(offsetof(struct ptlbd_niob, n_offset) == 16);
        LASSERT((int)sizeof(((struct ptlbd_niob *)0)->n_offset) == 4);
        LASSERT(offsetof(struct ptlbd_niob, n_length) == 20);
        LASSERT((int)sizeof(((struct ptlbd_niob *)0)->n_length) == 4);

        /* Checks for struct ptlbd_rsp */
        LASSERT((int)sizeof(struct ptlbd_rsp) == 4);
        LASSERT(offsetof(struct ptlbd_rsp, r_status) == 0);
        LASSERT((int)sizeof(((struct ptlbd_rsp *)0)->r_status) == 2);
        LASSERT(offsetof(struct ptlbd_rsp, r_error_cnt) == 2);
        LASSERT((int)sizeof(((struct ptlbd_rsp *)0)->r_error_cnt) == 2);

        /* Checks for struct llog_logid */
        LASSERT((int)sizeof(struct llog_logid) == 20);
        LASSERT(offsetof(struct llog_logid, lgl_oid) == 0);
        LASSERT((int)sizeof(((struct llog_logid *)0)->lgl_oid) == 8);
        LASSERT(offsetof(struct llog_logid, lgl_ogr) == 8);
        LASSERT((int)sizeof(((struct llog_logid *)0)->lgl_ogr) == 8);
        LASSERT(offsetof(struct llog_logid, lgl_ogen) == 16);
        LASSERT((int)sizeof(((struct llog_logid *)0)->lgl_ogen) == 4);
        LASSERT(OST_SZ_REC == 274730752);
        LASSERT(OST_RAID1_REC == 274731008);
        LASSERT(MDS_UNLINK_REC == 274801668);
        LASSERT(OBD_CFG_REC == 274857984);
        LASSERT(PTL_CFG_REC == 274923520);
        LASSERT(LLOG_GEN_REC == 274989056);
        LASSERT(LLOG_HDR_MAGIC == 275010873);
        LASSERT(LLOG_LOGID_MAGIC == 275010874);

        /* Checks for struct llog_rec_hdr */
        LASSERT((int)sizeof(struct llog_rec_hdr) == 16);
        LASSERT(offsetof(struct llog_rec_hdr, lrh_len) == 0);
        LASSERT((int)sizeof(((struct llog_rec_hdr *)0)->lrh_len) == 4);
        LASSERT(offsetof(struct llog_rec_hdr, lrh_index) == 4);
        LASSERT((int)sizeof(((struct llog_rec_hdr *)0)->lrh_index) == 4);
        LASSERT(offsetof(struct llog_rec_hdr, lrh_type) == 8);
        LASSERT((int)sizeof(((struct llog_rec_hdr *)0)->lrh_type) == 4);

        /* Checks for struct llog_rec_tail */
        LASSERT((int)sizeof(struct llog_rec_tail) == 8);
        LASSERT(offsetof(struct llog_rec_tail, lrt_len) == 0);
        LASSERT((int)sizeof(((struct llog_rec_tail *)0)->lrt_len) == 4);
        LASSERT(offsetof(struct llog_rec_tail, lrt_index) == 4);
        LASSERT((int)sizeof(((struct llog_rec_tail *)0)->lrt_index) == 4);

        /* Checks for struct llog_logid_rec */
        LASSERT((int)sizeof(struct llog_logid_rec) == 48);
        LASSERT(offsetof(struct llog_logid_rec, lid_hdr) == 0);
        LASSERT((int)sizeof(((struct llog_logid_rec *)0)->lid_hdr) == 16);
        LASSERT(offsetof(struct llog_logid_rec, lid_id) == 16);
        LASSERT((int)sizeof(((struct llog_logid_rec *)0)->lid_id) == 20);
        LASSERT(offsetof(struct llog_logid_rec, lid_tail) == 40);
        LASSERT((int)sizeof(((struct llog_logid_rec *)0)->lid_tail) == 8);

        /* Checks for struct llog_create_rec */
        LASSERT((int)sizeof(struct llog_create_rec) == 56);
        LASSERT(offsetof(struct llog_create_rec, lcr_hdr) == 0);
        LASSERT((int)sizeof(((struct llog_create_rec *)0)->lcr_hdr) == 16);
        LASSERT(offsetof(struct llog_create_rec, lcr_fid) == 16);
        LASSERT((int)sizeof(((struct llog_create_rec *)0)->lcr_fid) == 16);
        LASSERT(offsetof(struct llog_create_rec, lcr_oid) == 32);
        LASSERT((int)sizeof(((struct llog_create_rec *)0)->lcr_oid) == 8);
        LASSERT(offsetof(struct llog_create_rec, lcr_ogen) == 40);
        LASSERT((int)sizeof(((struct llog_create_rec *)0)->lcr_ogen) == 4);

        /* Checks for struct llog_orphan_rec */
        LASSERT((int)sizeof(struct llog_orphan_rec) == 40);
        LASSERT(offsetof(struct llog_orphan_rec, lor_hdr) == 0);
        LASSERT((int)sizeof(((struct llog_orphan_rec *)0)->lor_hdr) == 16);
        LASSERT(offsetof(struct llog_orphan_rec, lor_oid) == 16);
        LASSERT((int)sizeof(((struct llog_orphan_rec *)0)->lor_oid) == 8);
        LASSERT(offsetof(struct llog_orphan_rec, lor_ogen) == 24);
        LASSERT((int)sizeof(((struct llog_orphan_rec *)0)->lor_ogen) == 4);
        LASSERT(offsetof(struct llog_orphan_rec, lor_tail) == 32);
        LASSERT((int)sizeof(((struct llog_orphan_rec *)0)->lor_tail) == 8);

        /* Checks for struct llog_unlink_rec */
        LASSERT((int)sizeof(struct llog_unlink_rec) == 40);
        LASSERT(offsetof(struct llog_unlink_rec, lur_hdr) == 0);
        LASSERT((int)sizeof(((struct llog_unlink_rec *)0)->lur_hdr) == 16);
        LASSERT(offsetof(struct llog_unlink_rec, lur_oid) == 16);
        LASSERT((int)sizeof(((struct llog_unlink_rec *)0)->lur_oid) == 8);
        LASSERT(offsetof(struct llog_unlink_rec, lur_ogen) == 24);
        LASSERT((int)sizeof(((struct llog_unlink_rec *)0)->lur_ogen) == 4);
        LASSERT(offsetof(struct llog_unlink_rec, lur_tail) == 32);
        LASSERT((int)sizeof(((struct llog_unlink_rec *)0)->lur_tail) == 8);

        /* Checks for struct llog_size_change_rec */
        LASSERT((int)sizeof(struct llog_size_change_rec) == 48);
        LASSERT(offsetof(struct llog_size_change_rec, lsc_hdr) == 0);
        LASSERT((int)sizeof(((struct llog_size_change_rec *)0)->lsc_hdr) == 16);
        LASSERT(offsetof(struct llog_size_change_rec, lsc_fid) == 16);
        LASSERT((int)sizeof(((struct llog_size_change_rec *)0)->lsc_fid) == 16);
        LASSERT(offsetof(struct llog_size_change_rec, lsc_io_epoch) == 32);
        LASSERT((int)sizeof(((struct llog_size_change_rec *)0)->lsc_io_epoch) == 4);
        LASSERT(offsetof(struct llog_size_change_rec, lsc_tail) == 40);
        LASSERT((int)sizeof(((struct llog_size_change_rec *)0)->lsc_tail) == 8);

        /* Checks for struct llog_gen */
        LASSERT((int)sizeof(struct llog_gen) == 16);
        LASSERT(offsetof(struct llog_gen, mnt_cnt) == 0);
        LASSERT((int)sizeof(((struct llog_gen *)0)->mnt_cnt) == 8);
        LASSERT(offsetof(struct llog_gen, conn_cnt) == 8);
        LASSERT((int)sizeof(((struct llog_gen *)0)->conn_cnt) == 8);

        /* Checks for struct llog_gen_rec */
        LASSERT((int)sizeof(struct llog_gen_rec) == 40);
        LASSERT(offsetof(struct llog_gen_rec, lgr_hdr) == 0);
        LASSERT((int)sizeof(((struct llog_gen_rec *)0)->lgr_hdr) == 16);
        LASSERT(offsetof(struct llog_gen_rec, lgr_gen) == 16);
        LASSERT((int)sizeof(((struct llog_gen_rec *)0)->lgr_gen) == 16);
        LASSERT(offsetof(struct llog_gen_rec, lgr_tail) == 32);
        LASSERT((int)sizeof(((struct llog_gen_rec *)0)->lgr_tail) == 8);

        /* Checks for struct llog_log_hdr */
        LASSERT((int)sizeof(struct llog_log_hdr) == 4096);
        LASSERT(offsetof(struct llog_log_hdr, llh_hdr) == 0);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_hdr) == 16);
        LASSERT(offsetof(struct llog_log_hdr, llh_timestamp) == 16);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_timestamp) == 8);
        LASSERT(offsetof(struct llog_log_hdr, llh_count) == 24);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_count) == 4);
        LASSERT(offsetof(struct llog_log_hdr, llh_bitmap_offset) == 28);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_bitmap_offset) == 4);
        LASSERT(offsetof(struct llog_log_hdr, llh_size) == 32);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_size) == 4);
        LASSERT(offsetof(struct llog_log_hdr, llh_flags) == 36);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_flags) == 4);
        LASSERT(offsetof(struct llog_log_hdr, llh_cat_idx) == 40);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_cat_idx) == 4);
        LASSERT(offsetof(struct llog_log_hdr, llh_tgtuuid) == 44);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_tgtuuid) == 40);
        LASSERT(offsetof(struct llog_log_hdr, llh_reserved) == 84);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_reserved) == 4);
        LASSERT(offsetof(struct llog_log_hdr, llh_bitmap) == 88);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_bitmap) == 4000);
        LASSERT(offsetof(struct llog_log_hdr, llh_tail) == 4088);
        LASSERT((int)sizeof(((struct llog_log_hdr *)0)->llh_tail) == 8);

        /* Checks for struct llog_cookie */
        LASSERT((int)sizeof(struct llog_cookie) == 32);
        LASSERT(offsetof(struct llog_cookie, lgc_lgl) == 0);
        LASSERT((int)sizeof(((struct llog_cookie *)0)->lgc_lgl) == 20);
        LASSERT(offsetof(struct llog_cookie, lgc_subsys) == 20);
        LASSERT((int)sizeof(((struct llog_cookie *)0)->lgc_subsys) == 4);
        LASSERT(offsetof(struct llog_cookie, lgc_index) == 24);
        LASSERT((int)sizeof(((struct llog_cookie *)0)->lgc_index) == 4);

        /* Checks for struct llogd_body */
        LASSERT((int)sizeof(struct llogd_body) == 48);
        LASSERT(offsetof(struct llogd_body, lgd_logid) == 0);
        LASSERT((int)sizeof(((struct llogd_body *)0)->lgd_logid) == 20);
        LASSERT(offsetof(struct llogd_body, lgd_ctxt_idx) == 20);
        LASSERT((int)sizeof(((struct llogd_body *)0)->lgd_ctxt_idx) == 4);
        LASSERT(offsetof(struct llogd_body, lgd_llh_flags) == 24);
        LASSERT((int)sizeof(((struct llogd_body *)0)->lgd_llh_flags) == 4);
        LASSERT(offsetof(struct llogd_body, lgd_index) == 28);
        LASSERT((int)sizeof(((struct llogd_body *)0)->lgd_index) == 4);
        LASSERT(offsetof(struct llogd_body, lgd_saved_index) == 32);
        LASSERT((int)sizeof(((struct llogd_body *)0)->lgd_saved_index) == 4);
        LASSERT(offsetof(struct llogd_body, lgd_len) == 36);
        LASSERT((int)sizeof(((struct llogd_body *)0)->lgd_len) == 4);
        LASSERT(offsetof(struct llogd_body, lgd_cur_offset) == 40);
        LASSERT((int)sizeof(((struct llogd_body *)0)->lgd_cur_offset) == 8);
        LASSERT(LLOG_ORIGIN_HANDLE_CREATE == 501);
        LASSERT(LLOG_ORIGIN_HANDLE_NEXT_BLOCK == 502);
        LASSERT(LLOG_ORIGIN_HANDLE_READ_HEADER == 503);
        LASSERT(LLOG_ORIGIN_HANDLE_WRITE_REC == 504);
        LASSERT(LLOG_ORIGIN_HANDLE_CLOSE == 505);
        LASSERT(LLOG_ORIGIN_CONNECT == 506);
        LASSERT(LLOG_CATINFO == 507);

        /* Checks for struct llogd_conn_body */
        LASSERT((int)sizeof(struct llogd_conn_body) == 40);
        LASSERT(offsetof(struct llogd_conn_body, lgdc_gen) == 0);
        LASSERT((int)sizeof(((struct llogd_conn_body *)0)->lgdc_gen) == 16);
        LASSERT(offsetof(struct llogd_conn_body, lgdc_logid) == 16);
        LASSERT((int)sizeof(((struct llogd_conn_body *)0)->lgdc_logid) == 20);
        LASSERT(offsetof(struct llogd_conn_body, lgdc_ctxt_idx) == 36);
        LASSERT((int)sizeof(((struct llogd_conn_body *)0)->lgdc_ctxt_idx) == 4);
}
#else
void lustre_assert_wire_constants(void)
{
        return;
}
#endif

