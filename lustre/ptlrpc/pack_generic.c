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
#include <linux/lustre_net.h>


#define HDR_SIZE(count) \
    size_round(offsetof (struct lustre_msg, buflens[(count)]))

int lustre_pack_msg(int count, int *lens, char **bufs, int *len,
                    struct lustre_msg **msg)
{
        char *ptr;
        struct lustre_msg *m;
        int size = 0, i;

        size = HDR_SIZE (count);
        for (i = 0; i < count; i++)
                size += size_round(lens[i]);

        *len = size;

        OBD_ALLOC(*msg, *len);
        if (!*msg)
                RETURN(-ENOMEM);

        m = *msg;
        m->magic = PTLRPC_MSG_MAGIC;
        m->version = PTLRPC_MSG_VERSION;
        m->bufcount = count;
        for (i = 0; i < count; i++)
                m->buflens[i] = lens[i];

        ptr = (char *)m + HDR_SIZE(count);
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
        __swab32s (&ul->ul_reserved);
        __swab32s (&ul->ul_mode);
        __swab32s (&ul->ul_suppgid);
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

void lustre_assert_wire_constants (void)
{
#if BUG_1343
        /* Wire protocol assertions generated by 'wirecheck' */

        /* Constants... */
        LASSERT (PTLRPC_MSG_MAGIC == 0x0BD00BD0);
        LASSERT (PTLRPC_MSG_VERSION == 0x00040002);
        LASSERT (PTL_RPC_MSG_REQUEST == 4711);
        LASSERT (PTL_RPC_MSG_ERR == 4712);
        LASSERT (PTL_RPC_MSG_REPLY == 4713);
        LASSERT (MSG_LAST_REPLAY == 1);
        LASSERT (MSG_RESENT == 2);
        LASSERT (MSG_CONNECT_RECOVERING == 1);
        LASSERT (MSG_CONNECT_RECONNECT == 2);
        LASSERT (MSG_CONNECT_REPLAYABLE == 4);
        LASSERT (OST_REPLY == 0);
        LASSERT (OST_GETATTR == 1);
        LASSERT (OST_SETATTR == 2);
        LASSERT (OST_READ == 3);
        LASSERT (OST_WRITE == 4);
        LASSERT (OST_CREATE == 5);
        LASSERT (OST_DESTROY == 6);
        LASSERT (OST_GET_INFO == 7);
        LASSERT (OST_CONNECT == 8);
        LASSERT (OST_DISCONNECT == 9);
        LASSERT (OST_PUNCH == 10);
        LASSERT (OST_OPEN == 11);
        LASSERT (OST_CLOSE == 12);
        LASSERT (OST_STATFS == 13);
        LASSERT (OST_SAN_READ == 14);
        LASSERT (OST_SAN_WRITE == 15);
        LASSERT (OST_SYNCFS == 16);
        LASSERT (OST_LAST_OPC == 17);
        LASSERT (OST_FIRST_OPC == 0);
        LASSERT (OBD_FL_INLINEDATA == 1);
        LASSERT (OBD_FL_OBDMDEXISTS == 2);
        LASSERT (LOV_MAGIC == 198183888);
        LASSERT (OBD_MD_FLALL == -1);
        LASSERT (OBD_MD_FLID == 1);
        LASSERT (OBD_MD_FLATIME == 2);
        LASSERT (OBD_MD_FLMTIME == 4);
        LASSERT (OBD_MD_FLCTIME == 8);
        LASSERT (OBD_MD_FLSIZE == 16);
        LASSERT (OBD_MD_FLBLOCKS == 32);
        LASSERT (OBD_MD_FLBLKSZ == 64);
        LASSERT (OBD_MD_FLMODE == 128);
        LASSERT (OBD_MD_FLTYPE == 256);
        LASSERT (OBD_MD_FLUID == 512);
        LASSERT (OBD_MD_FLGID == 1024);
        LASSERT (OBD_MD_FLFLAGS == 2048);
        LASSERT (OBD_MD_FLOBDFLG == 4096);
        LASSERT (OBD_MD_FLNLINK == 8192);
        LASSERT (OBD_MD_FLGENER == 16384);
        LASSERT (OBD_MD_FLINLINE == 32768);
        LASSERT (OBD_MD_FLRDEV == 65536);
        LASSERT (OBD_MD_FLEASIZE == 131072);
        LASSERT (OBD_MD_LINKNAME == 262144);
        LASSERT (OBD_MD_FLHANDLE == 524288);
        LASSERT (OBD_MD_FLCKSUM == 1048576);
        LASSERT (OBD_BRW_READ == 1);
        LASSERT (OBD_BRW_WRITE == 2);
        LASSERT (OBD_BRW_CREATE == 4);
        LASSERT (OBD_BRW_SYNC == 8);
        LASSERT (OBD_OBJECT_EOF == 0xffffffffffffffffULL);
        LASSERT (OST_REQ_HAS_OA1 == 1);
        LASSERT (MDS_GETATTR == 33);
        LASSERT (MDS_GETATTR_NAME == 34);
        LASSERT (MDS_CLOSE == 35);
        LASSERT (MDS_REINT == 36);
        LASSERT (MDS_READPAGE == 37);
        LASSERT (MDS_CONNECT == 38);
        LASSERT (MDS_DISCONNECT == 39);
        LASSERT (MDS_GETSTATUS == 40);
        LASSERT (MDS_STATFS == 41);
        LASSERT (MDS_GETLOVINFO == 42);
        LASSERT (MDS_LAST_OPC == 43);
        LASSERT (MDS_FIRST_OPC == 33);
        LASSERT (REINT_SETATTR == 1);
        LASSERT (REINT_CREATE == 2);
        LASSERT (REINT_LINK == 3);
        LASSERT (REINT_UNLINK == 4);
        LASSERT (REINT_RENAME == 5);
        LASSERT (REINT_OPEN == 6);
        LASSERT (REINT_MAX == 6);
        LASSERT (DISP_IT_EXECD == 1);
        LASSERT (DISP_LOOKUP_EXECD == 2);
        LASSERT (DISP_LOOKUP_NEG == 4);
        LASSERT (DISP_LOOKUP_POS == 8);
        LASSERT (DISP_OPEN_CREATE == 16);
        LASSERT (DISP_OPEN_OPEN == 32);
        LASSERT (MDS_STATUS_CONN == 1);
        LASSERT (MDS_STATUS_LOV == 2);
        LASSERT (MDS_OPEN_HAS_EA == 1);
        LASSERT (LOV_RAID0 == 0);
        LASSERT (LOV_RAIDRR == 1);
        LASSERT (LDLM_ENQUEUE == 101);
        LASSERT (LDLM_CONVERT == 102);
        LASSERT (LDLM_CANCEL == 103);
        LASSERT (LDLM_BL_CALLBACK == 104);
        LASSERT (LDLM_CP_CALLBACK == 105);
        LASSERT (LDLM_LAST_OPC == 106);
        LASSERT (LDLM_FIRST_OPC == 101);
        LASSERT (PTLBD_QUERY == 200);
        LASSERT (PTLBD_READ == 201);
        LASSERT (PTLBD_WRITE == 202);
        LASSERT (PTLBD_FLUSH == 203);
        LASSERT (PTLBD_CONNECT == 204);
        LASSERT (PTLBD_DISCONNECT == 205);
        LASSERT (PTLBD_LAST_OPC == 204);
        LASSERT (PTLBD_FIRST_OPC == 200);
        LASSERT (OBD_PING == 400);
        /* Sizes and Offsets */


        /* Checks for struct lustre_handle */
        LASSERT (sizeof (struct lustre_handle) == 8);
        LASSERT (offsetof (struct lustre_handle, cookie) == 0);
        LASSERT (sizeof (((struct lustre_handle *)0)->cookie) == 8);

        /* Checks for struct lustre_msg */
        LASSERT (sizeof (struct lustre_msg) == 60);
        LASSERT (offsetof (struct lustre_msg, handle) == 0);
        LASSERT (sizeof (((struct lustre_msg *)0)->handle) == 8);
        LASSERT (offsetof (struct lustre_msg, magic) == 8);
        LASSERT (sizeof (((struct lustre_msg *)0)->magic) == 4);
        LASSERT (offsetof (struct lustre_msg, type) == 12);
        LASSERT (sizeof (((struct lustre_msg *)0)->type) == 4);
        LASSERT (offsetof (struct lustre_msg, version) == 16);
        LASSERT (sizeof (((struct lustre_msg *)0)->version) == 4);
        LASSERT (offsetof (struct lustre_msg, opc) == 20);
        LASSERT (sizeof (((struct lustre_msg *)0)->opc) == 4);
        LASSERT (offsetof (struct lustre_msg, last_xid) == 24);
        LASSERT (sizeof (((struct lustre_msg *)0)->last_xid) == 8);
        LASSERT (offsetof (struct lustre_msg, last_committed) == 32);
        LASSERT (sizeof (((struct lustre_msg *)0)->last_committed) == 8);
        LASSERT (offsetof (struct lustre_msg, transno) == 40);
        LASSERT (sizeof (((struct lustre_msg *)0)->transno) == 8);
        LASSERT (offsetof (struct lustre_msg, status) == 48);
        LASSERT (sizeof (((struct lustre_msg *)0)->status) == 4);
        LASSERT (offsetof (struct lustre_msg, flags) == 52);
        LASSERT (sizeof (((struct lustre_msg *)0)->flags) == 4);
        LASSERT (offsetof (struct lustre_msg, bufcount) == 56);
        LASSERT (sizeof (((struct lustre_msg *)0)->bufcount) == 4);
        LASSERT (offsetof (struct lustre_msg, buflens[7]) == 88);
        LASSERT (sizeof (((struct lustre_msg *)0)->buflens[7]) == 4);

        /* Checks for struct obdo */
        LASSERT (sizeof (struct obdo) == 164);
        LASSERT (offsetof (struct obdo, o_id) == 0);
        LASSERT (sizeof (((struct obdo *)0)->o_id) == 8);
        LASSERT (offsetof (struct obdo, o_gr) == 8);
        LASSERT (sizeof (((struct obdo *)0)->o_gr) == 8);
        LASSERT (offsetof (struct obdo, o_atime) == 16);
        LASSERT (sizeof (((struct obdo *)0)->o_atime) == 8);
        LASSERT (offsetof (struct obdo, o_mtime) == 24);
        LASSERT (sizeof (((struct obdo *)0)->o_mtime) == 8);
        LASSERT (offsetof (struct obdo, o_ctime) == 32);
        LASSERT (sizeof (((struct obdo *)0)->o_ctime) == 8);
        LASSERT (offsetof (struct obdo, o_size) == 40);
        LASSERT (sizeof (((struct obdo *)0)->o_size) == 8);
        LASSERT (offsetof (struct obdo, o_blocks) == 48);
        LASSERT (sizeof (((struct obdo *)0)->o_blocks) == 8);
        LASSERT (offsetof (struct obdo, o_rdev) == 56);
        LASSERT (sizeof (((struct obdo *)0)->o_rdev) == 8);
        LASSERT (offsetof (struct obdo, o_blksize) == 64);
        LASSERT (sizeof (((struct obdo *)0)->o_blksize) == 4);
        LASSERT (offsetof (struct obdo, o_mode) == 68);
        LASSERT (sizeof (((struct obdo *)0)->o_mode) == 4);
        LASSERT (offsetof (struct obdo, o_uid) == 72);
        LASSERT (sizeof (((struct obdo *)0)->o_uid) == 4);
        LASSERT (offsetof (struct obdo, o_gid) == 76);
        LASSERT (sizeof (((struct obdo *)0)->o_gid) == 4);
        LASSERT (offsetof (struct obdo, o_flags) == 80);
        LASSERT (sizeof (((struct obdo *)0)->o_flags) == 4);
        LASSERT (offsetof (struct obdo, o_nlink) == 84);
        LASSERT (sizeof (((struct obdo *)0)->o_nlink) == 4);
        LASSERT (offsetof (struct obdo, o_generation) == 88);
        LASSERT (sizeof (((struct obdo *)0)->o_generation) == 4);
        LASSERT (offsetof (struct obdo, o_valid) == 92);
        LASSERT (sizeof (((struct obdo *)0)->o_valid) == 4);
        LASSERT (offsetof (struct obdo, o_obdflags) == 96);
        LASSERT (sizeof (((struct obdo *)0)->o_obdflags) == 4);
        LASSERT (offsetof (struct obdo, o_easize) == 100);
        LASSERT (sizeof (((struct obdo *)0)->o_easize) == 4);
        LASSERT (offsetof (struct obdo, o_inline) == 104);
        LASSERT (sizeof (((struct obdo *)0)->o_inline) == 60);

        /* Checks for struct obd_statfs */
        LASSERT (sizeof (struct obd_statfs) == 144);
        LASSERT (offsetof (struct obd_statfs, os_type) == 0);
        LASSERT (sizeof (((struct obd_statfs *)0)->os_type) == 8);
        LASSERT (offsetof (struct obd_statfs, os_blocks) == 8);
        LASSERT (sizeof (((struct obd_statfs *)0)->os_blocks) == 8);
        LASSERT (offsetof (struct obd_statfs, os_bfree) == 16);
        LASSERT (sizeof (((struct obd_statfs *)0)->os_bfree) == 8);
        LASSERT (offsetof (struct obd_statfs, os_bavail) == 24);
        LASSERT (sizeof (((struct obd_statfs *)0)->os_bavail) == 8);
        LASSERT (offsetof (struct obd_statfs, os_ffree) == 40);
        LASSERT (sizeof (((struct obd_statfs *)0)->os_ffree) == 8);
        LASSERT (offsetof (struct obd_statfs, os_fsid) == 48);
        LASSERT (sizeof (((struct obd_statfs *)0)->os_fsid) == 40);
        LASSERT (offsetof (struct obd_statfs, os_bsize) == 88);
        LASSERT (sizeof (((struct obd_statfs *)0)->os_bsize) == 4);
        LASSERT (offsetof (struct obd_statfs, os_namelen) == 92);
        LASSERT (sizeof (((struct obd_statfs *)0)->os_namelen) == 4);

        /* Checks for struct obd_ioobj */
        LASSERT (sizeof (struct obd_ioobj) == 24);
        LASSERT (offsetof (struct obd_ioobj, ioo_id) == 0);
        LASSERT (sizeof (((struct obd_ioobj *)0)->ioo_id) == 8);
        LASSERT (offsetof (struct obd_ioobj, ioo_gr) == 8);
        LASSERT (sizeof (((struct obd_ioobj *)0)->ioo_gr) == 8);
        LASSERT (offsetof (struct obd_ioobj, ioo_type) == 16);
        LASSERT (sizeof (((struct obd_ioobj *)0)->ioo_type) == 4);
        LASSERT (offsetof (struct obd_ioobj, ioo_bufcnt) == 20);
        LASSERT (sizeof (((struct obd_ioobj *)0)->ioo_bufcnt) == 4);

        /* Checks for struct niobuf_remote */
        LASSERT (sizeof (struct niobuf_remote) == 16);
        LASSERT (offsetof (struct niobuf_remote, offset) == 0);
        LASSERT (sizeof (((struct niobuf_remote *)0)->offset) == 8);
        LASSERT (offsetof (struct niobuf_remote, len) == 8);
        LASSERT (sizeof (((struct niobuf_remote *)0)->len) == 4);
        LASSERT (offsetof (struct niobuf_remote, flags) == 12);
        LASSERT (sizeof (((struct niobuf_remote *)0)->flags) == 4);

        /* Checks for struct ost_body */
        LASSERT (sizeof (struct ost_body) == 164);
        LASSERT (offsetof (struct ost_body, oa) == 0);
        LASSERT (sizeof (((struct ost_body *)0)->oa) == 164);

        /* Checks for struct ll_fid */
        LASSERT (sizeof (struct ll_fid) == 16);
        LASSERT (offsetof (struct ll_fid, id) == 0);
        LASSERT (sizeof (((struct ll_fid *)0)->id) == 8);
        LASSERT (offsetof (struct ll_fid, generation) == 8);
        LASSERT (sizeof (((struct ll_fid *)0)->generation) == 4);
        LASSERT (offsetof (struct ll_fid, f_type) == 12);
        LASSERT (sizeof (((struct ll_fid *)0)->f_type) == 4);

        /* Checks for struct mds_status_req */
        LASSERT (sizeof (struct mds_status_req) == 8);
        LASSERT (offsetof (struct mds_status_req, flags) == 0);
        LASSERT (sizeof (((struct mds_status_req *)0)->flags) == 4);
        LASSERT (offsetof (struct mds_status_req, repbuf) == 4);
        LASSERT (sizeof (((struct mds_status_req *)0)->repbuf) == 4);

        /* Checks for struct mds_fileh_body */
        LASSERT (sizeof (struct mds_fileh_body) == 24);
        LASSERT (offsetof (struct mds_fileh_body, f_fid) == 0);
        LASSERT (sizeof (((struct mds_fileh_body *)0)->f_fid) == 16);

        /* Checks for struct mds_body */
        LASSERT (sizeof (struct mds_body) == 124);
        LASSERT (offsetof (struct mds_body, fid1) == 0);
        LASSERT (sizeof (((struct mds_body *)0)->fid1) == 16);
        LASSERT (offsetof (struct mds_body, fid2) == 16);
        LASSERT (sizeof (((struct mds_body *)0)->fid2) == 16);
        LASSERT (offsetof (struct mds_body, handle) == 32);
        LASSERT (sizeof (((struct mds_body *)0)->handle) == 8);
        LASSERT (offsetof (struct mds_body, size) == 40);
        LASSERT (sizeof (((struct mds_body *)0)->size) == 8);
        LASSERT (offsetof (struct mds_body, blocks) == 48);
        LASSERT (sizeof (((struct mds_body *)0)->blocks) == 8);
        LASSERT (offsetof (struct mds_body, ino) == 56);
        LASSERT (sizeof (((struct mds_body *)0)->ino) == 4);
        LASSERT (offsetof (struct mds_body, valid) == 60);
        LASSERT (sizeof (((struct mds_body *)0)->valid) == 4);
        LASSERT (offsetof (struct mds_body, fsuid) == 64);
        LASSERT (sizeof (((struct mds_body *)0)->fsuid) == 4);
        LASSERT (offsetof (struct mds_body, fsgid) == 68);
        LASSERT (sizeof (((struct mds_body *)0)->fsgid) == 4);
        LASSERT (offsetof (struct mds_body, capability) == 72);
        LASSERT (sizeof (((struct mds_body *)0)->capability) == 4);
        LASSERT (offsetof (struct mds_body, mode) == 76);
        LASSERT (sizeof (((struct mds_body *)0)->mode) == 4);
        LASSERT (offsetof (struct mds_body, uid) == 80);
        LASSERT (sizeof (((struct mds_body *)0)->uid) == 4);
        LASSERT (offsetof (struct mds_body, gid) == 84);
        LASSERT (sizeof (((struct mds_body *)0)->gid) == 4);
        LASSERT (offsetof (struct mds_body, mtime) == 88);
        LASSERT (sizeof (((struct mds_body *)0)->mtime) == 4);
        LASSERT (offsetof (struct mds_body, ctime) == 92);
        LASSERT (sizeof (((struct mds_body *)0)->ctime) == 4);
        LASSERT (offsetof (struct mds_body, atime) == 96);
        LASSERT (sizeof (((struct mds_body *)0)->atime) == 4);
        LASSERT (offsetof (struct mds_body, flags) == 100);
        LASSERT (sizeof (((struct mds_body *)0)->flags) == 4);
        LASSERT (offsetof (struct mds_body, rdev) == 104);
        LASSERT (sizeof (((struct mds_body *)0)->rdev) == 4);
        LASSERT (offsetof (struct mds_body, nlink) == 108);
        LASSERT (sizeof (((struct mds_body *)0)->nlink) == 4);
        LASSERT (offsetof (struct mds_body, generation) == 112);
        LASSERT (sizeof (((struct mds_body *)0)->generation) == 4);
        LASSERT (offsetof (struct mds_body, suppgid) == 116);
        LASSERT (sizeof (((struct mds_body *)0)->suppgid) == 4);

        /* Checks for struct mds_rec_setattr */
        LASSERT (sizeof (struct mds_rec_setattr) == 92);
        LASSERT (offsetof (struct mds_rec_setattr, sa_opcode) == 0);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_opcode) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_fsuid) == 4);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_fsuid) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_fsgid) == 8);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_fsgid) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_cap) == 12);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_cap) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_reserved) == 16);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_reserved) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_valid) == 20);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_valid) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_fid) == 24);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_fid) == 16);
        LASSERT (offsetof (struct mds_rec_setattr, sa_mode) == 40);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_mode) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_uid) == 44);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_uid) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_gid) == 48);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_gid) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_attr_flags) == 52);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_attr_flags) == 4);
        LASSERT (offsetof (struct mds_rec_setattr, sa_size) == 56);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_size) == 8);
        LASSERT (offsetof (struct mds_rec_setattr, sa_atime) == 64);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_atime) == 8);
        LASSERT (offsetof (struct mds_rec_setattr, sa_mtime) == 72);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_mtime) == 8);
        LASSERT (offsetof (struct mds_rec_setattr, sa_ctime) == 80);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_ctime) == 8);
        LASSERT (offsetof (struct mds_rec_setattr, sa_suppgid) == 88);
        LASSERT (sizeof (((struct mds_rec_setattr *)0)->sa_suppgid) == 4);

        /* Checks for struct mds_rec_create */
        LASSERT (sizeof (struct mds_rec_create) == 84);
        LASSERT (offsetof (struct mds_rec_create, cr_opcode) == 0);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_opcode) == 4);
        LASSERT (offsetof (struct mds_rec_create, cr_fsuid) == 4);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_fsuid) == 4);
        LASSERT (offsetof (struct mds_rec_create, cr_fsgid) == 8);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_fsgid) == 4);
        LASSERT (offsetof (struct mds_rec_create, cr_cap) == 12);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_cap) == 4);
        LASSERT (offsetof (struct mds_rec_create, cr_flags) == 16);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_flags) == 4);
        LASSERT (offsetof (struct mds_rec_create, cr_mode) == 20);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_mode) == 4);
        LASSERT (offsetof (struct mds_rec_create, cr_fid) == 24);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_fid) == 16);
        LASSERT (offsetof (struct mds_rec_create, cr_replayfid) == 40);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_replayfid) == 16);
        LASSERT (offsetof (struct mds_rec_create, cr_uid) == 56);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_uid) == 4);
        LASSERT (offsetof (struct mds_rec_create, cr_gid) == 60);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_gid) == 4);
        LASSERT (offsetof (struct mds_rec_create, cr_time) == 64);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_time) == 8);
        LASSERT (offsetof (struct mds_rec_create, cr_rdev) == 72);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_rdev) == 8);
        LASSERT (offsetof (struct mds_rec_create, cr_suppgid) == 80);
        LASSERT (sizeof (((struct mds_rec_create *)0)->cr_suppgid) == 4);

        /* Checks for struct mds_rec_link */
        LASSERT (sizeof (struct mds_rec_link) == 56);
        LASSERT (offsetof (struct mds_rec_link, lk_opcode) == 0);
        LASSERT (sizeof (((struct mds_rec_link *)0)->lk_opcode) == 4);
        LASSERT (offsetof (struct mds_rec_link, lk_fsuid) == 4);
        LASSERT (sizeof (((struct mds_rec_link *)0)->lk_fsuid) == 4);
        LASSERT (offsetof (struct mds_rec_link, lk_fsgid) == 8);
        LASSERT (sizeof (((struct mds_rec_link *)0)->lk_fsgid) == 4);
        LASSERT (offsetof (struct mds_rec_link, lk_cap) == 12);
        LASSERT (sizeof (((struct mds_rec_link *)0)->lk_cap) == 4);
        LASSERT (offsetof (struct mds_rec_link, lk_suppgid1) == 16);
        LASSERT (sizeof (((struct mds_rec_link *)0)->lk_suppgid1) == 4);
        LASSERT (offsetof (struct mds_rec_link, lk_suppgid2) == 20);
        LASSERT (sizeof (((struct mds_rec_link *)0)->lk_suppgid2) == 4);
        LASSERT (offsetof (struct mds_rec_link, lk_fid1) == 24);
        LASSERT (sizeof (((struct mds_rec_link *)0)->lk_fid1) == 16);
        LASSERT (offsetof (struct mds_rec_link, lk_fid2) == 40);
        LASSERT (sizeof (((struct mds_rec_link *)0)->lk_fid2) == 16);

        /* Checks for struct mds_rec_unlink */
        LASSERT (sizeof (struct mds_rec_unlink) == 60);
        LASSERT (offsetof (struct mds_rec_unlink, ul_opcode) == 0);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_opcode) == 4);
        LASSERT (offsetof (struct mds_rec_unlink, ul_fsuid) == 4);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_fsuid) == 4);
        LASSERT (offsetof (struct mds_rec_unlink, ul_fsgid) == 8);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_fsgid) == 4);
        LASSERT (offsetof (struct mds_rec_unlink, ul_cap) == 12);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_cap) == 4);
        LASSERT (offsetof (struct mds_rec_unlink, ul_reserved) == 16);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_reserved) == 4);
        LASSERT (offsetof (struct mds_rec_unlink, ul_mode) == 20);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_mode) == 4);
        LASSERT (offsetof (struct mds_rec_unlink, ul_suppgid) == 24);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_suppgid) == 4);
        LASSERT (offsetof (struct mds_rec_unlink, ul_fid1) == 28);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_fid1) == 16);
        LASSERT (offsetof (struct mds_rec_unlink, ul_fid2) == 44);
        LASSERT (sizeof (((struct mds_rec_unlink *)0)->ul_fid2) == 16);

        /* Checks for struct mds_rec_rename */
        LASSERT (sizeof (struct mds_rec_rename) == 56);
        LASSERT (offsetof (struct mds_rec_rename, rn_opcode) == 0);
        LASSERT (sizeof (((struct mds_rec_rename *)0)->rn_opcode) == 4);
        LASSERT (offsetof (struct mds_rec_rename, rn_fsuid) == 4);
        LASSERT (sizeof (((struct mds_rec_rename *)0)->rn_fsuid) == 4);
        LASSERT (offsetof (struct mds_rec_rename, rn_fsgid) == 8);
        LASSERT (sizeof (((struct mds_rec_rename *)0)->rn_fsgid) == 4);
        LASSERT (offsetof (struct mds_rec_rename, rn_cap) == 12);
        LASSERT (sizeof (((struct mds_rec_rename *)0)->rn_cap) == 4);
        LASSERT (offsetof (struct mds_rec_rename, rn_suppgid1) == 16);
        LASSERT (sizeof (((struct mds_rec_rename *)0)->rn_suppgid1) == 4);
        LASSERT (offsetof (struct mds_rec_rename, rn_suppgid2) == 20);
        LASSERT (sizeof (((struct mds_rec_rename *)0)->rn_suppgid2) == 4);
        LASSERT (offsetof (struct mds_rec_rename, rn_fid1) == 24);
        LASSERT (sizeof (((struct mds_rec_rename *)0)->rn_fid1) == 16);
        LASSERT (offsetof (struct mds_rec_rename, rn_fid2) == 40);
        LASSERT (sizeof (((struct mds_rec_rename *)0)->rn_fid2) == 16);

        /* Checks for struct lov_desc */
        LASSERT (sizeof (struct lov_desc) == 72);
        LASSERT (offsetof (struct lov_desc, ld_tgt_count) == 0);
        LASSERT (sizeof (((struct lov_desc *)0)->ld_tgt_count) == 4);
        LASSERT (offsetof (struct lov_desc, ld_active_tgt_count) == 4);
        LASSERT (sizeof (((struct lov_desc *)0)->ld_active_tgt_count) == 4);
        LASSERT (offsetof (struct lov_desc, ld_default_stripe_count) == 8);
        LASSERT (sizeof (((struct lov_desc *)0)->ld_default_stripe_count) == 4);
        LASSERT (offsetof (struct lov_desc, ld_default_stripe_size) == 12);
        LASSERT (sizeof (((struct lov_desc *)0)->ld_default_stripe_size) == 8);
        LASSERT (offsetof (struct lov_desc, ld_default_stripe_offset) == 20);
        LASSERT (sizeof (((struct lov_desc *)0)->ld_default_stripe_offset) == 8);
        LASSERT (offsetof (struct lov_desc, ld_pattern) == 28);
        LASSERT (sizeof (((struct lov_desc *)0)->ld_pattern) == 4);
        LASSERT (offsetof (struct lov_desc, ld_uuid) == 32);
        LASSERT (sizeof (((struct lov_desc *)0)->ld_uuid) == 37);

        /* Checks for struct ldlm_res_id */
        LASSERT (sizeof (struct ldlm_res_id) == 24);
        LASSERT (offsetof (struct ldlm_res_id, name[3]) == 24);
        LASSERT (sizeof (((struct ldlm_res_id *)0)->name[3]) == 8);

        /* Checks for struct ldlm_extent */
        LASSERT (sizeof (struct ldlm_extent) == 16);
        LASSERT (offsetof (struct ldlm_extent, start) == 0);
        LASSERT (sizeof (((struct ldlm_extent *)0)->start) == 8);
        LASSERT (offsetof (struct ldlm_extent, end) == 8);
        LASSERT (sizeof (((struct ldlm_extent *)0)->end) == 8);

        /* Checks for struct ldlm_intent */
        LASSERT (sizeof (struct ldlm_intent) == 8);
        LASSERT (offsetof (struct ldlm_intent, opc) == 0);
        LASSERT (sizeof (((struct ldlm_intent *)0)->opc) == 8);

        /* Checks for struct ldlm_resource_desc */
        LASSERT (sizeof (struct ldlm_resource_desc) == 44);
        LASSERT (offsetof (struct ldlm_resource_desc, lr_type) == 0);
        LASSERT (sizeof (((struct ldlm_resource_desc *)0)->lr_type) == 4);
        LASSERT (offsetof (struct ldlm_resource_desc, lr_name) == 4);
        LASSERT (sizeof (((struct ldlm_resource_desc *)0)->lr_name) == 24);
        LASSERT (offsetof (struct ldlm_resource_desc, lr_version[4]) == 44);
        LASSERT (sizeof (((struct ldlm_resource_desc *)0)->lr_version[4]) == 4);

        /* Checks for struct ldlm_lock_desc */
        LASSERT (sizeof (struct ldlm_lock_desc) == 84);
        LASSERT (offsetof (struct ldlm_lock_desc, l_resource) == 0);
        LASSERT (sizeof (((struct ldlm_lock_desc *)0)->l_resource) == 44);
        LASSERT (offsetof (struct ldlm_lock_desc, l_req_mode) == 44);
        LASSERT (sizeof (((struct ldlm_lock_desc *)0)->l_req_mode) == 4);
        LASSERT (offsetof (struct ldlm_lock_desc, l_granted_mode) == 48);
        LASSERT (sizeof (((struct ldlm_lock_desc *)0)->l_granted_mode) == 4);
        LASSERT (offsetof (struct ldlm_lock_desc, l_extent) == 52);
        LASSERT (sizeof (((struct ldlm_lock_desc *)0)->l_extent) == 16);
        LASSERT (offsetof (struct ldlm_lock_desc, l_version[4]) == 84);
        LASSERT (sizeof (((struct ldlm_lock_desc *)0)->l_version[4]) == 4);

        /* Checks for struct ldlm_request */
        LASSERT (sizeof (struct ldlm_request) == 104);
        LASSERT (offsetof (struct ldlm_request, lock_flags) == 0);
        LASSERT (sizeof (((struct ldlm_request *)0)->lock_flags) == 4);
        LASSERT (offsetof (struct ldlm_request, lock_desc) == 4);
        LASSERT (sizeof (((struct ldlm_request *)0)->lock_desc) == 84);
        LASSERT (offsetof (struct ldlm_request, lock_handle1) == 88);
        LASSERT (sizeof (((struct ldlm_request *)0)->lock_handle1) == 8);
        LASSERT (offsetof (struct ldlm_request, lock_handle2) == 96);
        LASSERT (sizeof (((struct ldlm_request *)0)->lock_handle2) == 8);

        /* Checks for struct ldlm_reply */
        LASSERT (sizeof (struct ldlm_reply) == 72);
        LASSERT (offsetof (struct ldlm_reply, lock_flags) == 0);
        LASSERT (sizeof (((struct ldlm_reply *)0)->lock_flags) == 4);
        LASSERT (offsetof (struct ldlm_reply, lock_mode) == 4);
        LASSERT (sizeof (((struct ldlm_reply *)0)->lock_mode) == 4);
        LASSERT (offsetof (struct ldlm_reply, lock_resource_name) == 8);
        LASSERT (sizeof (((struct ldlm_reply *)0)->lock_resource_name) == 24);
        LASSERT (offsetof (struct ldlm_reply, lock_handle) == 32);
        LASSERT (sizeof (((struct ldlm_reply *)0)->lock_handle) == 8);
        LASSERT (offsetof (struct ldlm_reply, lock_extent) == 40);
        LASSERT (sizeof (((struct ldlm_reply *)0)->lock_extent) == 16);
        LASSERT (offsetof (struct ldlm_reply, lock_policy_res1) == 56);
        LASSERT (sizeof (((struct ldlm_reply *)0)->lock_policy_res1) == 8);
        LASSERT (offsetof (struct ldlm_reply, lock_policy_res2) == 64);
        LASSERT (sizeof (((struct ldlm_reply *)0)->lock_policy_res2) == 8);

        /* Checks for struct ptlbd_op */
        LASSERT (sizeof (struct ptlbd_op) == 12);
        LASSERT (offsetof (struct ptlbd_op, op_cmd) == 0);
        LASSERT (sizeof (((struct ptlbd_op *)0)->op_cmd) == 2);
        LASSERT (offsetof (struct ptlbd_op, op_lun) == 2);
        LASSERT (sizeof (((struct ptlbd_op *)0)->op_lun) == 2);
        LASSERT (offsetof (struct ptlbd_op, op_niob_cnt) == 4);
        LASSERT (sizeof (((struct ptlbd_op *)0)->op_niob_cnt) == 2);
        LASSERT (offsetof (struct ptlbd_op, op__padding) == 6);
        LASSERT (sizeof (((struct ptlbd_op *)0)->op__padding) == 2);
        LASSERT (offsetof (struct ptlbd_op, op_block_cnt) == 8);
        LASSERT (sizeof (((struct ptlbd_op *)0)->op_block_cnt) == 4);

        /* Checks for struct ptlbd_niob */
        LASSERT (sizeof (struct ptlbd_niob) == 24);
        LASSERT (offsetof (struct ptlbd_niob, n_xid) == 0);
        LASSERT (sizeof (((struct ptlbd_niob *)0)->n_xid) == 8);
        LASSERT (offsetof (struct ptlbd_niob, n_block_nr) == 8);
        LASSERT (sizeof (((struct ptlbd_niob *)0)->n_block_nr) == 8);
        LASSERT (offsetof (struct ptlbd_niob, n_offset) == 16);
        LASSERT (sizeof (((struct ptlbd_niob *)0)->n_offset) == 4);
        LASSERT (offsetof (struct ptlbd_niob, n_length) == 20);
        LASSERT (sizeof (((struct ptlbd_niob *)0)->n_length) == 4);

        /* Checks for struct ptlbd_rsp */
        LASSERT (sizeof (struct ptlbd_rsp) == 4);
        LASSERT (offsetof (struct ptlbd_rsp, r_status) == 0);
        LASSERT (sizeof (((struct ptlbd_rsp *)0)->r_status) == 2);
        LASSERT (offsetof (struct ptlbd_rsp, r_error_cnt) == 2);
        LASSERT (sizeof (((struct ptlbd_rsp *)0)->r_error_cnt) == 2);
#endif
}
