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
# include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <linux/lustre_sec.h>
#include <linux/fcntl.h>


#define HDR_SIZE(count) \
    size_round(offsetof (struct lustre_msg, buflens[(count)]))

int lustre_msg_swabbed(struct lustre_msg *msg)
{
        return (msg->magic == __swab32(PTLRPC_MSG_MAGIC));
}

int lustre_msg_check_version(struct lustre_msg *msg, __u32 version)
{
        if (!lustre_msg_swabbed(msg))
                return (msg->version & LUSTRE_VERSION_MASK) != version;

        return (__swab32(msg->version) & LUSTRE_VERSION_MASK) != version;
}

void lustre_init_msg (struct lustre_msg *msg, int count, int *lens, char **bufs)
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

int lustre_secdesc_size(void)
{
#ifdef __KERNEL__
        int ngroups = current_ngroups;

        if (ngroups > LUSTRE_MAX_GROUPS)
                ngroups = LUSTRE_MAX_GROUPS;

        return sizeof(struct mds_req_sec_desc) +
                sizeof(__u32) * ngroups;
#else
        return 0;
#endif
}

/*
 * because group info might have changed since last time we call
 * secdesc_size(), so here we did more sanity check to prevent garbage gids
 */
void lustre_pack_secdesc(struct ptlrpc_request *req, int size)
{
#ifdef __KERNEL__
        struct mds_req_sec_desc *rsd;
        
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
        struct group_info *ginfo;
#endif

        rsd = lustre_msg_buf(req->rq_reqmsg,
                             MDS_REQ_SECDESC_OFF, size);
        
        rsd->rsd_uid = current->uid;
        rsd->rsd_gid = current->gid;
        rsd->rsd_fsuid = current->fsuid;
        rsd->rsd_fsgid = current->fsgid;
        rsd->rsd_cap = current->cap_effective;
        rsd->rsd_ngroups = (size - sizeof(*rsd)) / sizeof(__u32);
        LASSERT(rsd->rsd_ngroups <= LUSTRE_MAX_GROUPS);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
        task_lock(current);
        get_group_info(current->group_info);
        ginfo = current->group_info;
        task_unlock(current);
        if (rsd->rsd_ngroups > ginfo->ngroups)
                rsd->rsd_ngroups = ginfo->ngroups;
        memcpy(rsd->rsd_groups, ginfo->blocks[0],
               rsd->rsd_ngroups * sizeof(__u32));
#else
        LASSERT(rsd->rsd_ngroups <= NGROUPS);
        if (rsd->rsd_ngroups > current->ngroups)
                rsd->rsd_ngroups = current->ngroups;
        memcpy(rsd->rsd_groups, current->groups,
               rsd->rsd_ngroups * sizeof(__u32));
#endif
#endif
}

int lustre_pack_request (struct ptlrpc_request *req,
                         int count, int *lens, char **bufs)
{
        int rc;
        ENTRY;

        req->rq_reqlen = lustre_msg_size(count, lens);
        rc = ptlrpcs_cli_alloc_reqbuf(req, req->rq_reqlen);
        if (rc)
                RETURN(rc);

        lustre_init_msg(req->rq_reqmsg, count, lens, bufs);
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
        int                        rc;
        ENTRY;

        LASSERT(req->rq_reply_state == NULL);
        LASSERT(req->rq_svcsec);
        LASSERT(req->rq_repmsg == NULL);

        req->rq_replen = lustre_msg_size(count, lens);
        rc = svcsec_alloc_repbuf(req->rq_svcsec, req, req->rq_replen);
        if (rc)
                RETURN(rc);
        LASSERT(req->rq_reply_state);
        LASSERT(req->rq_repmsg == req->rq_reply_state->rs_msg);
                                                                                                    
        rs = req->rq_reply_state;
        rs->rs_svcsec = svcsec_get(req->rq_svcsec);
        rs->rs_cb_id.cbid_fn = reply_out_callback;
        rs->rs_cb_id.cbid_arg = rs;
        rs->rs_srv_ni = req->rq_rqbd->rqbd_srv_ni;
        INIT_LIST_HEAD(&rs->rs_exp_list);
        INIT_LIST_HEAD(&rs->rs_obd_list);

        lustre_init_msg(rs->rs_msg, count, lens, bufs);

        PTLRPC_RS_DEBUG_LRU_ADD(rs);

        RETURN (0);
}

void lustre_free_reply_state (struct ptlrpc_reply_state *rs)
{
        struct ptlrpc_svcsec *svcsec = rs->rs_svcsec;

        PTLRPC_RS_DEBUG_LRU_DEL(rs);

        LASSERT (!rs->rs_difficult || rs->rs_handled);
        LASSERT (!rs->rs_on_net);
        LASSERT (!rs->rs_scheduled);
        LASSERT (rs->rs_export == NULL);
        LASSERT (rs->rs_nlocks == 0);
        LASSERT (list_empty(&rs->rs_exp_list));
        LASSERT (list_empty(&rs->rs_obd_list));
        LASSERT (svcsec);

        if (svcsec->free_repbuf)
                svcsec->free_repbuf(svcsec, rs);
        else
                svcsec_free_reply_state(rs);

        svcsec_put(svcsec);
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

        if ((m->version & ~LUSTRE_VERSION_MASK) != PTLRPC_MSG_VERSION) {
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

/* Wrap up the normal fixed length cases */
void *lustre_swab_buf(struct lustre_msg *msg, int index, int min_size,
                      void *swabber)
{
        void *ptr;

        ptr = lustre_msg_buf(msg, index, min_size);
        if (ptr == NULL)
                return NULL;

        if (swabber != NULL && lustre_msg_swabbed(msg))
                ((void (*)(void *))swabber)(ptr);

        return ptr;
}

void *lustre_swab_reqbuf(struct ptlrpc_request *req, int index, int min_size,
                         void *swabber)
{
        LASSERT_REQSWAB(req, index);
        return lustre_swab_buf(req->rq_reqmsg, index, min_size, swabber);
}

void *lustre_swab_repbuf(struct ptlrpc_request *req, int index, int min_size,
                         void *swabber)
{
        LASSERT_REPSWAB(req, index);
        return lustre_swab_buf(req->rq_repmsg, index, min_size, swabber);
}

/* byte flipping routines for all wire types declared in
 * lustre_idl.h implemented here.
 */

void lustre_swab_connect(struct obd_connect_data *ocd)
{
        __swab64s (&ocd->ocd_connect_flags);
        __swab32s (&ocd->ocd_nllu[0]);
        __swab32s (&ocd->ocd_nllu[1]);
}

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
        __swab64s (&o->o_valid);
        __swab32s (&o->o_misc);
        __swab32s (&o->o_easize);
        __swab32s (&o->o_mds);
        __swab64s (&o->o_fid);
        /* o_inline is opaque */
}

/* mdc pack methods used by mdc and smfs*/
void *mdc_create_pack(struct lustre_msg *msg, int offset,
                      struct mdc_op_data *op_data, __u32 mode,
                      __u64 rdev, const void *data, int datalen)
{
        struct mds_rec_create *rec;
        char *tmp;
        rec = lustre_msg_buf(msg, offset, sizeof (*rec));

        rec->cr_opcode = REINT_CREATE;
        rec->cr_id = op_data->id1;
        memset(&rec->cr_replayid, 0, sizeof(rec->cr_replayid));
        rec->cr_mode = mode;
        rec->cr_rdev = rdev;
        rec->cr_time = op_data->mod_time;

        tmp = lustre_msg_buf(msg, offset + 1, op_data->namelen + 1);
        LOGL0(op_data->name, op_data->namelen, tmp);

        if (data) {
                tmp = lustre_msg_buf(msg, offset + 2, datalen);
                memcpy (tmp, data, datalen);
        }
        return ((void*)tmp + size_round(datalen));
}

void *mdc_setattr_pack(struct lustre_msg *msg, int offset,
                       struct mdc_op_data *data, struct iattr *iattr,
                       void *ea, int ealen, void *ea2, int ea2len)
{
        struct mds_rec_setattr *rec = lustre_msg_buf(msg, offset, sizeof(*rec));
        char *tmp = NULL;

        rec->sa_opcode = REINT_SETATTR;
        rec->sa_id = data->id1;

        if (iattr) {
                rec->sa_valid = iattr->ia_valid;
                rec->sa_mode = iattr->ia_mode;
                rec->sa_uid = iattr->ia_uid;
                rec->sa_gid = iattr->ia_gid;
                rec->sa_size = iattr->ia_size;
                rec->sa_atime = LTIME_S(iattr->ia_atime);
                rec->sa_mtime = LTIME_S(iattr->ia_mtime);
                rec->sa_ctime = LTIME_S(iattr->ia_ctime);
                rec->sa_attr_flags = iattr->ia_attr_flags;
        }
        tmp = (char*)rec + size_round(sizeof(*rec));
                
        if (ealen == 0)
                return (void*)tmp;

        memcpy(lustre_msg_buf(msg, offset + 1, ealen), ea, ealen);
        tmp += size_round(ealen);

        if (ea2len == 0)
                return (void*)tmp;

        memcpy(lustre_msg_buf(msg, offset + 2, ea2len), ea2, ea2len);
        tmp += size_round(ea2len);
        return (void*)tmp;
}

void *mdc_unlink_pack(struct lustre_msg *msg, int offset,
                      struct mdc_op_data *data)
{
        struct mds_rec_unlink *rec;
        char *tmp;

        rec = lustre_msg_buf(msg, offset, sizeof (*rec));
        LASSERT (rec != NULL);

        rec->ul_opcode = REINT_UNLINK;
        rec->ul_mode = data->create_mode;
        rec->ul_id1 = data->id1;
        rec->ul_id2 = data->id2;
        rec->ul_time = data->mod_time;

        tmp = lustre_msg_buf(msg, offset + 1, data->namelen + 1);
        LASSERT (tmp != NULL);
        LOGL0(data->name, data->namelen, tmp);
        return (void*)tmp;        
}

void *mdc_link_pack(struct lustre_msg *msg, int offset,
                    struct mdc_op_data *data)
{
        struct mds_rec_link *rec;
        char *tmp;

        rec = lustre_msg_buf(msg, offset, sizeof (*rec));

        rec->lk_opcode = REINT_LINK;
        rec->lk_id1 = data->id1;
        rec->lk_id2 = data->id2;
        rec->lk_time = data->mod_time;

        tmp = lustre_msg_buf(msg, offset + 1, data->namelen + 1);
        LOGL0(data->name, data->namelen, tmp);
        
        return (void*)tmp; 
}

void *mdc_rename_pack(struct lustre_msg *msg, int offset,
                      struct mdc_op_data *data,
                      const char *old, int oldlen,
                      const char *new, int newlen)
{
        struct mds_rec_rename *rec;
        char *tmp;

        rec = lustre_msg_buf(msg, offset, sizeof (*rec));

        /* XXX do something about time, uid, gid */
        rec->rn_opcode = REINT_RENAME;
        rec->rn_id1 = data->id1;
        rec->rn_id2 = data->id2;
        rec->rn_time = data->mod_time;

        tmp = lustre_msg_buf(msg, offset + 1, oldlen + 1);
        LOGL0(old, oldlen, tmp);

        if (new) {
                tmp = lustre_msg_buf(msg, offset + 2, newlen + 1);
                LOGL0(new, newlen, tmp);
        }
        return (void*)tmp;
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

void lustre_swab_generic_32s(__u32 *val)
{
        __swab32s(val);
}

void lustre_swab_ost_lvb(struct ost_lvb *lvb)
{
        __swab64s(&lvb->lvb_size);
        __swab64s(&lvb->lvb_mtime);
        __swab64s(&lvb->lvb_atime);
        __swab64s(&lvb->lvb_ctime);
        __swab64s(&lvb->lvb_blocks);
}

void lustre_swab_lustre_stc (struct lustre_stc *stc)
{
        __swab64s (&stc->u.e3s.l3s_ino);
        __swab32s (&stc->u.e3s.l3s_gen);
        __swab32s (&stc->u.e3s.l3s_type);
}

void lustre_swab_lustre_fid(struct lustre_fid *fid)
{
        __swab64s (&fid->lf_id);
        __swab64s (&fid->lf_group);
        __swab32s (&fid->lf_version);
}

void lustre_swab_lustre_id (struct lustre_id *id)
{
        lustre_swab_lustre_stc(&id->li_stc);
        lustre_swab_lustre_fid(&id->li_fid);
}

void lustre_swab_mds_status_req (struct mds_status_req *r)
{
        __swab32s (&r->flags);
        __swab32s (&r->repbuf);
}

/* 
 * because sec_desc is variable buffer, we must check it by hand
 */
struct mds_req_sec_desc *lustre_swab_mds_secdesc(struct ptlrpc_request *req,
                                                 int offset)
{
        struct mds_req_sec_desc *rsd;
        struct lustre_msg *m;
        __u32 i;

        LASSERT_REQSWAB(req, offset);

        m = req->rq_reqmsg;
        rsd = lustre_msg_buf(m, offset, sizeof(*rsd));
        if (!rsd)
                return NULL;

        if (lustre_msg_swabbed(m)) {
                __swab32s(&rsd->rsd_uid);
                __swab32s(&rsd->rsd_gid);
                __swab32s(&rsd->rsd_fsuid);
                __swab32s(&rsd->rsd_fsgid);
                __swab32s(&rsd->rsd_cap);
                __swab32s(&rsd->rsd_ngroups);
        }

        if (rsd->rsd_ngroups > LUSTRE_MAX_GROUPS) {
                CERROR("%u groups is not allowed\n", rsd->rsd_ngroups);
                return NULL;
        }

        if (m->buflens[offset] !=
            sizeof(*rsd) + rsd->rsd_ngroups * sizeof(__u32)) {
                CERROR("bufflen %u while contains %u groups\n",
                        m->buflens[offset], rsd->rsd_ngroups);
                return NULL;
        }

        if (lustre_msg_swabbed(m)) {
                for (i = 0; i < rsd->rsd_ngroups; i++)
                        __swab32s(&rsd->rsd_groups[i]);
        }

        return rsd;
}

void lustre_swab_mds_body (struct mds_body *b)
{
        lustre_swab_lustre_id (&b->id1);
        lustre_swab_lustre_id (&b->id2);
        /* handle is opaque */
        __swab64s (&b->size);
        __swab64s (&b->blocks);
        __swab64s (&b->valid);
        __swab32s (&b->mode);
        __swab32s (&b->uid);
        __swab32s (&b->gid);
        __swab32s (&b->mtime);
        __swab32s (&b->ctime);
        __swab32s (&b->atime);
        __swab32s (&b->flags);
        __swab32s (&b->rdev);
        __swab32s (&b->nlink);
        __swab32s (&b->eadatasize);
}
void lustre_swab_mds_rec_setattr (struct mds_rec_setattr *sa)
{
        __swab32s (&sa->sa_opcode);
        __swab32s (&sa->sa_valid);
        lustre_swab_lustre_id (&sa->sa_id);
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
        __swab32s (&cr->cr_flags); /* for use with open */
        __swab32s (&cr->cr_mode);
        lustre_swab_lustre_id (&cr->cr_id);
        lustre_swab_lustre_id (&cr->cr_replayid);
        __swab64s (&cr->cr_time);
        __swab64s (&cr->cr_rdev);
}

void lustre_swab_mds_rec_link (struct mds_rec_link *lk)
{
        __swab32s (&lk->lk_opcode);
        lustre_swab_lustre_id (&lk->lk_id1);
        lustre_swab_lustre_id (&lk->lk_id2);
}

void lustre_swab_mds_rec_unlink (struct mds_rec_unlink *ul)
{
        __swab32s (&ul->ul_opcode);
        __swab32s (&ul->ul_mode);
        lustre_swab_lustre_id (&ul->ul_id1);
        lustre_swab_lustre_id (&ul->ul_id2);
}

void lustre_swab_mds_rec_rename (struct mds_rec_rename *rn)
{
        __swab32s (&rn->rn_opcode);
        lustre_swab_lustre_id (&rn->rn_id1);
        lustre_swab_lustre_id (&rn->rn_id2);
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
        /* the lock data is a union and the first three fields of both EXTENT
         * and FLOCK types are __u64, so it's ok to swab them in the same way */
        __swab64s (&d->l_flock.start);
        __swab64s (&d->l_flock.end);
        __swab64s (&d->l_flock.pid);
        __swab64s (&d->l_flock.blocking_pid);
}

void lustre_swab_ldlm_intent (struct ldlm_intent *i)
{
        __swab64s (&i->opc);
}

void lustre_swab_ldlm_resource_desc (struct ldlm_resource_desc *r)
{
        __swab32s (&r->lr_type);
        lustre_swab_ldlm_res_id (&r->lr_name);
}

void lustre_swab_ldlm_lock_desc (struct ldlm_lock_desc *l)
{
        lustre_swab_ldlm_resource_desc (&l->l_resource);
        __swab32s (&l->l_req_mode);
        __swab32s (&l->l_granted_mode);
        lustre_swab_ldlm_policy_data (&l->l_policy_data);
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
        lustre_swab_ldlm_lock_desc (&r->lock_desc);
        /* lock_handle opaque */
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

void lustre_assert_wire_constants(void)
{
}

