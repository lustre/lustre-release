/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/pack_generic.c
 *
 * (Un)packing of OST requests
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Eric Barton <eeb@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <libcfs/libcfs.h>

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <obd_cksum.h>

static inline int lustre_msg_hdr_size_v2(int count)
{
        return size_round(offsetof(struct lustre_msg_v2, lm_buflens[count]));
}

int lustre_msg_hdr_size(__u32 magic, int count)
{
        switch (magic) {
        case LUSTRE_MSG_MAGIC_V2:
                return lustre_msg_hdr_size_v2(count);
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", magic);
                return -EINVAL;
        }
}
EXPORT_SYMBOL(lustre_msg_hdr_size);

int lustre_msg_swabbed(struct lustre_msg *msg)
{
        return (msg->lm_magic == LUSTRE_MSG_MAGIC_V2_SWABBED);
}

static inline int
lustre_msg_check_version_v2(struct lustre_msg_v2 *msg, __u32 version)
{
        __u32 ver = lustre_msg_get_version(msg);
        return (ver & LUSTRE_VERSION_MASK) != version;
}

int lustre_msg_check_version(struct lustre_msg *msg, __u32 version)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
        case LUSTRE_MSG_MAGIC_V1_SWABBED:
                CERROR("msg v1 not supported - please upgrade you system\n");
                return -EINVAL; 
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                return lustre_msg_check_version_v2(msg, version);
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

/* early reply size */
int lustre_msg_early_size() {
        static int size = 0;
        if (!size)
                size = lustre_msg_size(LUSTRE_MSG_MAGIC_V2, 1, NULL);
        return size;
}
EXPORT_SYMBOL(lustre_msg_early_size);

int lustre_msg_size_v2(int count, __u32 *lengths)
{
        int size;
        int i;

        size = lustre_msg_hdr_size_v2(count);
        for (i = 0; i < count; i++)
                size += size_round(lengths[i]);

        return size;
}
EXPORT_SYMBOL(lustre_msg_size_v2);

/* This returns the size of the buffer that is required to hold a lustre_msg
 * with the given sub-buffer lengths.
 * NOTE: this should only be used for NEW requests, and should always be
 *       in the form of a v2 request.  If this is a connection to a v1
 *       target then the first buffer will be stripped because the ptlrpc
 *       data is part of the lustre_msg_v1 header. b=14043 */
int lustre_msg_size(__u32 magic, int count, __u32 *lens)
{
        __u32 size[] = { sizeof(struct ptlrpc_body) };

        if (!lens) {
                LASSERT(count == 1);
                lens = size;
        }

        LASSERT(count > 0);
        LASSERT(lens[MSG_PTLRPC_BODY_OFF] == sizeof(struct ptlrpc_body));

        switch (magic) {
        case LUSTRE_MSG_MAGIC_V2:
                return lustre_msg_size_v2(count, lens);
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", magic);
                return -EINVAL;
        }
}

/* This is used to determine the size of a buffer that was already packed
 * and will correctly handle the different message formats. */
int lustre_packed_msg_size(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
                return lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

void lustre_init_msg_v2(struct lustre_msg_v2 *msg, int count, __u32 *lens,
                        char **bufs)
{
        char *ptr;
        int i;

        msg->lm_bufcount = count;
        /* XXX: lm_secflvr uninitialized here */
        msg->lm_magic = LUSTRE_MSG_MAGIC_V2;

        for (i = 0; i < count; i++)
                msg->lm_buflens[i] = lens[i];

        if (bufs == NULL)
                return;

        ptr = (char *)msg + lustre_msg_hdr_size_v2(count);
        for (i = 0; i < count; i++) {
                char *tmp = bufs[i];
                LOGL(tmp, lens[i], ptr);
        }
}
EXPORT_SYMBOL(lustre_init_msg_v2);

static int lustre_pack_request_v2(struct ptlrpc_request *req,
                                  int count, __u32 *lens, char **bufs)
{
        int reqlen, rc;

        reqlen = lustre_msg_size_v2(count, lens);

        rc = sptlrpc_cli_alloc_reqbuf(req, reqlen);
        if (rc)
                return rc;

        req->rq_reqlen = reqlen;

        lustre_init_msg_v2(req->rq_reqmsg, count, lens, bufs);
        lustre_msg_add_version(req->rq_reqmsg, PTLRPC_MSG_VERSION);
        lustre_set_req_swabbed(req, MSG_PTLRPC_BODY_OFF);
        return 0;
}

int lustre_pack_request(struct ptlrpc_request *req, __u32 magic, int count,
                        __u32 *lens, char **bufs)
{
        __u32 size[] = { sizeof(struct ptlrpc_body) };

        if (!lens) {
                LASSERT(count == 1);
                lens = size;
        }

        LASSERT(count > 0);
        LASSERT(lens[MSG_PTLRPC_BODY_OFF] == sizeof(struct ptlrpc_body));

        /* only use new format, we don't need to be compatible with 1.4 */
        magic = LUSTRE_MSG_MAGIC_V2;

        switch (magic) {
        case LUSTRE_MSG_MAGIC_V2:
                return lustre_pack_request_v2(req, count, lens, bufs);
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", magic);
                return -EINVAL;
        }
}

#if RS_DEBUG
CFS_LIST_HEAD(ptlrpc_rs_debug_lru);
spinlock_t ptlrpc_rs_debug_lock;

#define PTLRPC_RS_DEBUG_LRU_ADD(rs)                                     \
do {                                                                    \
        spin_lock(&ptlrpc_rs_debug_lock);                               \
        list_add_tail(&(rs)->rs_debug_list, &ptlrpc_rs_debug_lru);      \
        spin_unlock(&ptlrpc_rs_debug_lock);                             \
} while (0)

#define PTLRPC_RS_DEBUG_LRU_DEL(rs)             \
do {                                            \
        spin_lock(&ptlrpc_rs_debug_lock);       \
        list_del(&(rs)->rs_debug_list);         \
        spin_unlock(&ptlrpc_rs_debug_lock);     \
} while (0)
#else
# define PTLRPC_RS_DEBUG_LRU_ADD(rs) do {} while(0)
# define PTLRPC_RS_DEBUG_LRU_DEL(rs) do {} while(0)
#endif

struct ptlrpc_reply_state *lustre_get_emerg_rs(struct ptlrpc_service *svc)
{
        struct ptlrpc_reply_state *rs = NULL;

        spin_lock(&svc->srv_lock);
        /* See if we have anything in a pool, and wait if nothing */
        while (list_empty(&svc->srv_free_rs_list)) {
                struct l_wait_info lwi;
                int rc;
                spin_unlock(&svc->srv_lock);
                /* If we cannot get anything for some long time, we better
                   bail out instead of waiting infinitely */
                lwi = LWI_TIMEOUT(cfs_time_seconds(10), NULL, NULL);
                rc = l_wait_event(svc->srv_free_rs_waitq,
                                  !list_empty(&svc->srv_free_rs_list), &lwi);
                if (rc)
                        goto out;
                spin_lock(&svc->srv_lock);
        }

        rs = list_entry(svc->srv_free_rs_list.next, struct ptlrpc_reply_state,
                        rs_list);
        list_del(&rs->rs_list);
        spin_unlock(&svc->srv_lock);
        LASSERT(rs);
        memset(rs, 0, svc->srv_max_reply_size);
        rs->rs_service = svc;
        rs->rs_prealloc = 1;
out:
        return rs;
}

void lustre_put_emerg_rs(struct ptlrpc_reply_state *rs)
{
        struct ptlrpc_service *svc = rs->rs_service;

        LASSERT(svc);

        spin_lock(&svc->srv_lock);
        list_add(&rs->rs_list, &svc->srv_free_rs_list);
        spin_unlock(&svc->srv_lock);
        cfs_waitq_signal(&svc->srv_free_rs_waitq);
}

int lustre_pack_reply_v2(struct ptlrpc_request *req, int count,
                         __u32 *lens, char **bufs, int flags)
{
        struct ptlrpc_reply_state *rs;
        int                        msg_len, rc;
        ENTRY;

        LASSERT(req->rq_reply_state == NULL);

        if ((flags & LPRFL_EARLY_REPLY) == 0)
                req->rq_packed_final = 1;

        msg_len = lustre_msg_size_v2(count, lens);
        rc = sptlrpc_svc_alloc_rs(req, msg_len);
        if (rc)
                RETURN(rc);

        rs = req->rq_reply_state;
        atomic_set(&rs->rs_refcount, 1);        /* 1 ref for rq_reply_state */
        rs->rs_cb_id.cbid_fn = reply_out_callback;
        rs->rs_cb_id.cbid_arg = rs;
        rs->rs_service = req->rq_rqbd->rqbd_service;
        CFS_INIT_LIST_HEAD(&rs->rs_exp_list);
        CFS_INIT_LIST_HEAD(&rs->rs_obd_list);

        req->rq_replen = msg_len;
        req->rq_reply_state = rs;
        req->rq_repmsg = rs->rs_msg;

        lustre_init_msg_v2(rs->rs_msg, count, lens, bufs);
        lustre_msg_add_version(rs->rs_msg, PTLRPC_MSG_VERSION);
        lustre_set_rep_swabbed(req, MSG_PTLRPC_BODY_OFF);

        PTLRPC_RS_DEBUG_LRU_ADD(rs);

        RETURN(0);
}
EXPORT_SYMBOL(lustre_pack_reply_v2);

int lustre_pack_reply_flags(struct ptlrpc_request *req, int count, __u32 *lens,
                            char **bufs, int flags)
{
        int rc = 0;
        __u32 size[] = { sizeof(struct ptlrpc_body) };

        if (!lens) {
                LASSERT(count == 1);
                lens = size;
        }

        LASSERT(count > 0);
        LASSERT(lens[MSG_PTLRPC_BODY_OFF] == sizeof(struct ptlrpc_body));

        switch (req->rq_reqmsg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                rc = lustre_pack_reply_v2(req, count, lens, bufs, flags);
                break;
        default:
                LASSERTF(0, "incorrect message magic: %08x\n",
                         req->rq_reqmsg->lm_magic);
                rc = -EINVAL;
        }
        if (rc != 0)
                CERROR("lustre_pack_reply failed: rc=%d size=%d\n", rc,
                       lustre_msg_size(req->rq_reqmsg->lm_magic, count, lens));
        return rc;
}

int lustre_pack_reply(struct ptlrpc_request *req, int count, __u32 *lens,
                      char **bufs)
{
        return lustre_pack_reply_flags(req, count, lens, bufs, 0);
}

void *lustre_msg_buf_v2(struct lustre_msg_v2 *m, int n, int min_size)
{
        int i, offset, buflen, bufcount;

        LASSERT(m != NULL);
        LASSERT(n >= 0);

        bufcount = m->lm_bufcount;
        if (unlikely(n >= bufcount)) {
                CDEBUG(D_INFO, "msg %p buffer[%d] not present (count %d)\n",
                       m, n, bufcount);
                return NULL;
        }

        buflen = m->lm_buflens[n];
        if (unlikely(buflen < min_size)) {
                CERROR("msg %p buffer[%d] size %d too small (required %d)\n",
                       m, n, buflen, min_size);
                return NULL;
        }

        offset = lustre_msg_hdr_size_v2(bufcount);
        for (i = 0; i < n; i++)
                offset += size_round(m->lm_buflens[i]);

        return (char *)m + offset;
}

void *lustre_msg_buf(struct lustre_msg *m, int n, int min_size)
{
        switch (m->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                return lustre_msg_buf_v2(m, n, min_size);
        default:
                LASSERTF(0, "incorrect message magic: %08x(msg:%p)\n", m->lm_magic, m);
                return NULL;
        }
}

int lustre_shrink_msg_v2(struct lustre_msg_v2 *msg, int segment,
                         unsigned int newlen, int move_data)
{
        char   *tail = NULL, *newpos;
        int     tail_len = 0, n;

        LASSERT(msg);
        LASSERT(msg->lm_bufcount > segment);
        LASSERT(msg->lm_buflens[segment] >= newlen);

        if (msg->lm_buflens[segment] == newlen)
                goto out;

        if (move_data && msg->lm_bufcount > segment + 1) {
                tail = lustre_msg_buf_v2(msg, segment + 1, 0);
                for (n = segment + 1; n < msg->lm_bufcount; n++)
                        tail_len += size_round(msg->lm_buflens[n]);
        }

        msg->lm_buflens[segment] = newlen;

        if (tail && tail_len) {
                newpos = lustre_msg_buf_v2(msg, segment + 1, 0);
                LASSERT(newpos <= tail);
                if (newpos != tail)
                        memcpy(newpos, tail, tail_len);
        }
out:
        return lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);
}

/*
 * for @msg, shrink @segment to size @newlen. if @move_data is non-zero,
 * we also move data forward from @segment + 1.
 *
 * if @newlen == 0, we remove the segment completely, but we still keep the
 * totally bufcount the same to save possible data moving. this will leave a
 * unused segment with size 0 at the tail, but that's ok.
 *
 * return new msg size after shrinking.
 *
 * CAUTION:
 * + if any buffers higher than @segment has been filled in, must call shrink
 *   with non-zero @move_data.
 * + caller should NOT keep pointers to msg buffers which higher than @segment
 *   after call shrink.
 */
int lustre_shrink_msg(struct lustre_msg *msg, int segment,
                      unsigned int newlen, int move_data)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
                return lustre_shrink_msg_v2(msg, segment, newlen, move_data);
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_free_reply_state(struct ptlrpc_reply_state *rs)
{
        PTLRPC_RS_DEBUG_LRU_DEL(rs);

        LASSERT (atomic_read(&rs->rs_refcount) == 0);
        LASSERT (!rs->rs_difficult || rs->rs_handled);
        LASSERT (!rs->rs_on_net);
        LASSERT (!rs->rs_scheduled);
        LASSERT (rs->rs_export == NULL);
        LASSERT (rs->rs_nlocks == 0);
        LASSERT (list_empty(&rs->rs_exp_list));
        LASSERT (list_empty(&rs->rs_obd_list));

        sptlrpc_svc_free_rs(rs);
}

static int lustre_unpack_msg_v2(struct lustre_msg_v2 *m, int len)
{
        int flipped, required_len, i;

        /* Now we know the sender speaks my language. */
        required_len = lustre_msg_hdr_size_v2(0);
        if (len < required_len) {
                /* can't even look inside the message */
                CERROR("message length %d too small for lustre_msg\n", len);
                return -EINVAL;
        }

        flipped = lustre_msg_swabbed(m);

        if (flipped) {
                __swab32s(&m->lm_bufcount);
                __swab32s(&m->lm_secflvr);
                __swab32s(&m->lm_repsize);
                __swab32s(&m->lm_cksum);
                __swab32s(&m->lm_flags);
                CLASSERT(offsetof(typeof(*m), lm_padding_2) != 0);
                CLASSERT(offsetof(typeof(*m), lm_padding_3) != 0);
        }

        required_len = lustre_msg_hdr_size_v2(m->lm_bufcount);
        if (len < required_len) {
                /* didn't receive all the buffer lengths */
                CERROR ("message length %d too small for %d buflens\n",
                        len, m->lm_bufcount);
                return -EINVAL;
        }
        
        for (i = 0; i < m->lm_bufcount; i++) {
                if (flipped)
                        __swab32s(&m->lm_buflens[i]);
                required_len += size_round(m->lm_buflens[i]);
        }

        if (len < required_len) {
                CERROR("len: %d, required_len %d\n", len, required_len);
                CERROR("bufcount: %d\n", m->lm_bufcount);
                for (i = 0; i < m->lm_bufcount; i++)
                        CERROR("buffer %d length %d\n", i, m->lm_buflens[i]);
                return -EINVAL;
        }

        return 0;
}

int lustre_unpack_msg(struct lustre_msg *m, int len)
{
        int required_len, rc;
        ENTRY;

        /* We can provide a slightly better error log, if we check the
         * message magic and version first.  In the future, struct
         * lustre_msg may grow, and we'd like to log a version mismatch,
         * rather than a short message.
         *
         */
        required_len = offsetof(struct lustre_msg, lm_magic) +
                       sizeof(m->lm_magic);
        if (len < required_len) {
                /* can't even look inside the message */
                CERROR("message length %d too small for magic/version check\n",
                       len);
                RETURN(-EINVAL);
        }

        switch (m->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                rc = lustre_unpack_msg_v2(m, len);
                break;
        default:
                CERROR("bad lustre msg magic: %#08X\n", m->lm_magic);
                return -EINVAL;
        }

        RETURN(rc);
}

static inline int lustre_unpack_ptlrpc_body_v2(struct lustre_msg_v2 *m,
                                               int offset)
{
        struct ptlrpc_body *pb;

        pb = lustre_msg_buf_v2(m, offset, sizeof(*pb));
        if (!pb) {
                CERROR("error unpacking ptlrpc body\n");
                return -EFAULT;
        }
        if (lustre_msg_swabbed(m))
                lustre_swab_ptlrpc_body(pb);

        if ((pb->pb_version & ~LUSTRE_VERSION_MASK) != PTLRPC_MSG_VERSION) {
                 CERROR("wrong lustre_msg version %08x\n", pb->pb_version);
                 return -EINVAL;
        }

        return 0;
}

int lustre_unpack_req_ptlrpc_body(struct ptlrpc_request *req, int offset)
{
        switch (req->rq_reqmsg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                lustre_set_req_swabbed(req, offset);
                return lustre_unpack_ptlrpc_body_v2(req->rq_reqmsg, offset);
        default:
                CERROR("bad lustre msg magic: %#08X\n",
                       req->rq_reqmsg->lm_magic);
                return -EINVAL;
        }
}

int lustre_unpack_rep_ptlrpc_body(struct ptlrpc_request *req, int offset)
{
        switch (req->rq_repmsg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                lustre_set_rep_swabbed(req, offset);
                return lustre_unpack_ptlrpc_body_v2(req->rq_repmsg, offset);
        default:
                CERROR("bad lustre msg magic: %#08X\n",
                       req->rq_repmsg->lm_magic);
                return -EINVAL;
        }
}

static inline int lustre_msg_buflen_v2(struct lustre_msg_v2 *m, int n)
{
        if (n >= m->lm_bufcount)
                return 0;

        return m->lm_buflens[n];
}

/**
 * lustre_msg_buflen - return the length of buffer @n in message @m
 * @m - lustre_msg (request or reply) to look at
 * @n - message index (base 0)
 *
 * returns zero for non-existent message indices
 */
int lustre_msg_buflen(struct lustre_msg *m, int n)
{
        switch (m->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                return lustre_msg_buflen_v2(m, n);
        default:
                CERROR("incorrect message magic: %08x\n", m->lm_magic);
                return -EINVAL;
        }
}
EXPORT_SYMBOL(lustre_msg_buflen);

static inline void
lustre_msg_set_buflen_v2(struct lustre_msg_v2 *m, int n, int len)
{
        if (n >= m->lm_bufcount)
                LBUG();

        m->lm_buflens[n] = len;
}

void lustre_msg_set_buflen(struct lustre_msg *m, int n, int len)
{
        switch (m->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
                lustre_msg_set_buflen_v2(m, n, len);
                return;
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", m->lm_magic);
        }
}

EXPORT_SYMBOL(lustre_msg_set_buflen);

/* NB return the bufcount for lustre_msg_v2 format, so if message is packed
 * in V1 format, the result is one bigger. (add struct ptlrpc_body). */
int lustre_msg_bufcount(struct lustre_msg *m)
{
        switch (m->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                return m->lm_bufcount;
        default:
                CERROR("incorrect message magic: %08x\n", m->lm_magic);
                return -EINVAL;
        }
}
EXPORT_SYMBOL(lustre_msg_bufcount);

char *lustre_msg_string(struct lustre_msg *m, int index, int max_len)
{
        /* max_len == 0 means the string should fill the buffer */
        char *str;
        int slen, blen;

        switch (m->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                str = lustre_msg_buf_v2(m, index, 0);
                blen = lustre_msg_buflen_v2(m, index);
                break;
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", m->lm_magic);
        }

        if (str == NULL) {
                CERROR ("can't unpack string in msg %p buffer[%d]\n", m, index);
                return NULL;
        }

        slen = strnlen(str, blen);

        if (slen == blen) {                     /* not NULL terminated */
                CERROR("can't unpack non-NULL terminated string in "
                        "msg %p buffer[%d] len %d\n", m, index, blen);
                return NULL;
        }

        if (max_len == 0) {
                if (slen != blen - 1) {
                        CERROR("can't unpack short string in msg %p "
                               "buffer[%d] len %d: strlen %d\n",
                               m, index, blen, slen);
                        return NULL;
                }
        } else if (slen > max_len) {
                CERROR("can't unpack oversized string in msg %p "
                       "buffer[%d] len %d strlen %d: max %d expected\n",
                       m, index, blen, slen, max_len);
                return NULL;
        }

        return str;
}

/* Wrap up the normal fixed length cases */
void *lustre_swab_buf(struct lustre_msg *msg, int index, int min_size,
                      void *swabber)
{
        void *ptr = NULL;

        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                ptr = lustre_msg_buf_v2(msg, index, min_size);
                break;
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
        }
        if (ptr == NULL)
                return NULL;

        if (swabber != NULL && lustre_msg_swabbed(msg))
                ((void (*)(void *))swabber)(ptr);

        return ptr;
}

void *lustre_swab_reqbuf(struct ptlrpc_request *req, int index, int min_size,
                         void *swabber)
{
        lustre_set_req_swabbed(req, index);
        return lustre_swab_buf(req->rq_reqmsg, index, min_size, swabber);
}

void *lustre_swab_repbuf(struct ptlrpc_request *req, int index, int min_size,
                         void *swabber)
{
        lustre_set_rep_swabbed(req, index);
        return lustre_swab_buf(req->rq_repmsg, index, min_size, swabber);
}

__u32 lustre_msghdr_get_flags(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
        case LUSTRE_MSG_MAGIC_V1_SWABBED:
                return 0;
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                /* already in host endian */
                return msg->lm_flags;
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

void lustre_msghdr_set_flags(struct lustre_msg *msg, __u32 flags)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
                return;
        case LUSTRE_MSG_MAGIC_V2:
                msg->lm_flags = flags;
                return;
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

__u32 lustre_msg_get_flags(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;
                }
                return pb->pb_flags;
        }
        default:
                /* flags might be printed in debug code while message
                 * uninitialized */
                return 0;
        }
}

void lustre_msg_add_flags(struct lustre_msg *msg, int flags)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_flags |= flags;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_flags(struct lustre_msg *msg, int flags)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_flags = flags;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_clear_flags(struct lustre_msg *msg, int flags)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_flags &= ~(MSG_GEN_FLAG_MASK & flags);
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

__u32 lustre_msg_get_op_flags(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;
                }
                return pb->pb_op_flags;
        }
        default:
                return 0;
        }
}

void lustre_msg_add_op_flags(struct lustre_msg *msg, int flags)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_op_flags |= flags;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_op_flags(struct lustre_msg *msg, int flags)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_op_flags |= flags;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

struct lustre_handle *lustre_msg_get_handle(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return NULL;
                }
                return &pb->pb_handle;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return NULL;
        }
}

__u32 lustre_msg_get_type(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return PTL_RPC_MSG_ERR;
                }
                return pb->pb_type;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return PTL_RPC_MSG_ERR;
        }
}

__u32 lustre_msg_get_version(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;
                }
                return pb->pb_version;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

void lustre_msg_add_version(struct lustre_msg *msg, int version)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_version |= version;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

__u32 lustre_msg_get_opc(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;
                }
                return pb->pb_opc;
        }
        default:
                CERROR("incorrect message magic: %08x(msg:%p)\n", msg->lm_magic, msg);
                return 0;
        }
}

__u64 lustre_msg_get_last_xid(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;
                }
                return pb->pb_last_xid;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

__u64 lustre_msg_get_last_committed(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;
                }
                return pb->pb_last_committed;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

__u64 lustre_msg_get_transno(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;
                }
                return pb->pb_transno;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

int lustre_msg_get_status(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return -EINVAL;
                }
                return pb->pb_status;
        }
        default:
                /* status might be printed in debug code while message
                 * uninitialized */
                return -EINVAL;
        }
}

__u64 lustre_msg_get_slv(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return -EINVAL;
                }
                return pb->pb_slv;
        }
        default:
                CERROR("invalid msg magic %x\n", msg->lm_magic);
                return -EINVAL;
        }
}


void lustre_msg_set_slv(struct lustre_msg *msg, __u64 slv)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return;
                }
                pb->pb_slv = slv;
                return;
        }
        default:
                CERROR("invalid msg magic %x\n", msg->lm_magic);
                return;
        }
}

__u32 lustre_msg_get_limit(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return -EINVAL;
                }
                return pb->pb_limit;
        }
        default:
                CERROR("invalid msg magic %x\n", msg->lm_magic);
                return -EINVAL;
        }
}


void lustre_msg_set_limit(struct lustre_msg *msg, __u64 limit)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return;
                }
                pb->pb_limit = limit;
                return;
        }
        default:
                CERROR("invalid msg magic %x\n", msg->lm_magic);
                return;
        }
}

__u32 lustre_msg_get_conn_cnt(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;
                }
                return pb->pb_conn_cnt;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

int lustre_msg_is_v1(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
        case LUSTRE_MSG_MAGIC_V1_SWABBED:
                return 1;
        default:
                return 0;
        }
}

__u32 lustre_msg_get_magic(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                return msg->lm_magic;
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

__u32 lustre_msg_get_timeout(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
        case LUSTRE_MSG_MAGIC_V1_SWABBED:
                return 0;
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;

                }
                return pb->pb_timeout;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

__u32 lustre_msg_get_service_time(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
        case LUSTRE_MSG_MAGIC_V1_SWABBED:
                return 0;
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                if (!pb) {
                        CERROR("invalid msg %p: no ptlrpc body!\n", msg);
                        return 0;

                }
                return pb->pb_service_time;
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

__u32 lustre_msg_get_cksum(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
        case LUSTRE_MSG_MAGIC_V1_SWABBED:
                return 0;
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                return msg->lm_cksum;
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

__u32 lustre_msg_calc_cksum(struct lustre_msg *msg)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
        case LUSTRE_MSG_MAGIC_V1_SWABBED:
                return 0;
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED: {
                struct ptlrpc_body *pb;
                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                return crc32_le(~(__u32)0, (unsigned char *)pb, sizeof(*pb));
        }
        default:
                CERROR("incorrect message magic: %08x\n", msg->lm_magic);
                return 0;
        }
}

void lustre_msg_set_handle(struct lustre_msg *msg, struct lustre_handle *handle)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_handle = *handle;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_type(struct lustre_msg *msg, __u32 type)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_type = type;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_opc(struct lustre_msg *msg, __u32 opc)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_opc = opc;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_last_xid(struct lustre_msg *msg, __u64 last_xid)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_last_xid = last_xid;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_last_committed(struct lustre_msg *msg, __u64 last_committed)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_last_committed = last_committed;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_transno(struct lustre_msg *msg, __u64 transno)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_transno = transno;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_status(struct lustre_msg *msg, __u32 status)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_status = status;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_conn_cnt(struct lustre_msg *msg, __u32 conn_cnt)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_conn_cnt = conn_cnt;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_timeout(struct lustre_msg *msg, __u32 timeout)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
                return;
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_timeout = timeout;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_service_time(struct lustre_msg *msg, __u32 service_time)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
                return;
        case LUSTRE_MSG_MAGIC_V2: {
                struct ptlrpc_body *pb;

                pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF, sizeof(*pb));
                LASSERTF(pb, "invalid msg %p: no ptlrpc body!\n", msg);
                pb->pb_service_time = service_time;
                return;
        }
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}

void lustre_msg_set_cksum(struct lustre_msg *msg, __u32 cksum)
{
        switch (msg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V1:
                return;
        case LUSTRE_MSG_MAGIC_V2:
                msg->lm_cksum = cksum;
                return;
        default:
                LASSERTF(0, "incorrect message magic: %08x\n", msg->lm_magic);
        }
}


void ptlrpc_request_set_replen(struct ptlrpc_request *req)
{
        int count = req_capsule_filled_sizes(&req->rq_pill, RCL_SERVER);

        req->rq_replen = lustre_msg_size(req->rq_reqmsg->lm_magic, count,
                                         req->rq_pill.rc_area[RCL_SERVER]);
        if (req->rq_reqmsg->lm_magic == LUSTRE_MSG_MAGIC_V2)
                req->rq_reqmsg->lm_repsize = req->rq_replen;
}

void ptlrpc_req_set_repsize(struct ptlrpc_request *req, int count, __u32 *lens)
{
        req->rq_replen = lustre_msg_size(req->rq_reqmsg->lm_magic, count, lens);
        if (req->rq_reqmsg->lm_magic == LUSTRE_MSG_MAGIC_V2)
                req->rq_reqmsg->lm_repsize = req->rq_replen;
}

/* byte flipping routines for all wire types declared in
 * lustre_idl.h implemented here.
 */
void lustre_swab_ptlrpc_body(struct ptlrpc_body *b)
{
        __swab32s (&b->pb_type);
        __swab32s (&b->pb_version);
        __swab32s (&b->pb_opc);
        __swab32s (&b->pb_status);
        __swab64s (&b->pb_last_xid);
        __swab64s (&b->pb_last_seen);
        __swab64s (&b->pb_last_committed);
        __swab64s (&b->pb_transno);
        __swab32s (&b->pb_flags);
        __swab32s (&b->pb_op_flags);
        __swab32s (&b->pb_conn_cnt);
        __swab32s (&b->pb_timeout);
        __swab32s (&b->pb_service_time);
        __swab32s (&b->pb_limit);
        __swab64s (&b->pb_slv);
        __swab64s (&b->pb_pre_versions[0]);
        __swab64s (&b->pb_pre_versions[1]);
        __swab64s (&b->pb_pre_versions[2]);
        __swab64s (&b->pb_pre_versions[3]);
        CLASSERT(offsetof(typeof(*b), pb_padding) != 0);
}

void lustre_swab_connect(struct obd_connect_data *ocd)
{
        __swab64s(&ocd->ocd_connect_flags);
        __swab32s(&ocd->ocd_version);
        __swab32s(&ocd->ocd_grant);
        __swab64s(&ocd->ocd_ibits_known);
        __swab32s(&ocd->ocd_index);
        __swab32s(&ocd->ocd_brw_size);
        __swab32s(&ocd->ocd_nllu);
        __swab32s(&ocd->ocd_nllg);
        __swab64s(&ocd->ocd_transno);
        __swab32s(&ocd->ocd_group);
        __swab32s(&ocd->ocd_cksum_types);
        CLASSERT(offsetof(typeof(*ocd), padding1) != 0);
        CLASSERT(offsetof(typeof(*ocd), padding2) != 0);
}

void lustre_swab_obdo (struct obdo  *o)
{
        __swab64s (&o->o_valid);
        __swab64s (&o->o_id);
        __swab64s (&o->o_gr);
        __swab64s (&o->o_fid);
        __swab64s (&o->o_size);
        __swab64s (&o->o_mtime);
        __swab64s (&o->o_atime);
        __swab64s (&o->o_ctime);
        __swab64s (&o->o_blocks);
        __swab64s (&o->o_grant);
        __swab32s (&o->o_blksize);
        __swab32s (&o->o_mode);
        __swab32s (&o->o_uid);
        __swab32s (&o->o_gid);
        __swab32s (&o->o_flags);
        __swab32s (&o->o_nlink);
        __swab32s (&o->o_generation);
        __swab32s (&o->o_misc);
        __swab32s (&o->o_easize);
        __swab32s (&o->o_mds);
        __swab32s (&o->o_stripe_idx);
        __swab32s (&o->o_padding_1);
        /* o_inline is opaque */
}

void lustre_swab_obd_statfs (struct obd_statfs *os)
{
        __swab64s (&os->os_type);
        __swab64s (&os->os_blocks);
        __swab64s (&os->os_bfree);
        __swab64s (&os->os_bavail);
        __swab64s (&os->os_files);
        __swab64s (&os->os_ffree);
        /* no need to swab os_fsid */
        __swab32s (&os->os_bsize);
        __swab32s (&os->os_namelen);
        __swab64s (&os->os_maxbytes);
        __swab32s (&os->os_state);
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
        __swab64s (&b->valid);
        __swab64s (&b->size);
        __swab64s (&b->mtime);
        __swab64s (&b->atime);
        __swab64s (&b->ctime);
        __swab64s (&b->blocks);
        __swab64s (&b->io_epoch);
        __swab64s (&b->ino);
        __swab32s (&b->fsuid);
        __swab32s (&b->fsgid);
        __swab32s (&b->capability);
        __swab32s (&b->mode);
        __swab32s (&b->uid);
        __swab32s (&b->gid);
        __swab32s (&b->flags);
        __swab32s (&b->rdev);
        __swab32s (&b->nlink);
        __swab32s (&b->generation);
        __swab32s (&b->suppgid);
        __swab32s (&b->eadatasize);
        __swab32s (&b->aclsize);
        __swab32s (&b->max_mdsize);
        __swab32s (&b->max_cookiesize);
        __swab32s (&b->padding_4);
}

void lustre_swab_mdt_body (struct mdt_body *b)
{
        lustre_swab_lu_fid (&b->fid1);
        lustre_swab_lu_fid (&b->fid2);
        /* handle is opaque */
        __swab64s (&b->valid);
        __swab64s (&b->size);
        __swab64s (&b->mtime);
        __swab64s (&b->atime);
        __swab64s (&b->ctime);
        __swab64s (&b->blocks);
        __swab64s (&b->ioepoch);
        __swab64s (&b->ino);
        __swab32s (&b->fsuid);
        __swab32s (&b->fsgid);
        __swab32s (&b->capability);
        __swab32s (&b->mode);
        __swab32s (&b->uid);
        __swab32s (&b->gid);
        __swab32s (&b->flags);
        __swab32s (&b->rdev);
        __swab32s (&b->nlink);
        __swab32s (&b->generation);
        __swab32s (&b->suppgid);
        __swab32s (&b->eadatasize);
        __swab32s (&b->aclsize);
        __swab32s (&b->max_mdsize);
        __swab32s (&b->max_cookiesize);
        __swab32s (&b->padding_4);
}

void lustre_swab_mdt_epoch (struct mdt_epoch *b)
{
        /* handle is opaque */
         __swab64s (&b->ioepoch);
         __swab32s (&b->flags);
         CLASSERT(offsetof(typeof(*b), padding) != 0);
}

void lustre_swab_mgs_target_info(struct mgs_target_info *mti)
{
        int i;
        __swab32s(&mti->mti_lustre_ver);
        __swab32s(&mti->mti_stripe_index);
        __swab32s(&mti->mti_config_ver);
        __swab32s(&mti->mti_flags);
        __swab32s(&mti->mti_nid_count);
        CLASSERT(sizeof(lnet_nid_t) == sizeof(__u64));
        for (i = 0; i < MTI_NIDS_MAX; i++)
                __swab64s(&mti->mti_nids[i]);
}

static void lustre_swab_obd_dqinfo (struct obd_dqinfo *i)
{
        __swab64s (&i->dqi_bgrace);
        __swab64s (&i->dqi_igrace);
        __swab32s (&i->dqi_flags);
        __swab32s (&i->dqi_valid);
}

static void lustre_swab_obd_dqblk (struct obd_dqblk *b)
{
        __swab64s (&b->dqb_ihardlimit);
        __swab64s (&b->dqb_isoftlimit);
        __swab64s (&b->dqb_curinodes);
        __swab64s (&b->dqb_bhardlimit);
        __swab64s (&b->dqb_bsoftlimit);
        __swab64s (&b->dqb_curspace);
        __swab64s (&b->dqb_btime);
        __swab64s (&b->dqb_itime);
        __swab32s (&b->dqb_valid);
        CLASSERT(offsetof(typeof(*b), padding) != 0);
}

void lustre_swab_obd_quotactl (struct obd_quotactl *q)
{
        __swab32s (&q->qc_cmd);
        __swab32s (&q->qc_type);
        __swab32s (&q->qc_id);
        __swab32s (&q->qc_stat);
        lustre_swab_obd_dqinfo (&q->qc_dqinfo);
        lustre_swab_obd_dqblk (&q->qc_dqblk);
}

void lustre_swab_mds_remote_perm (struct mds_remote_perm *p)
{
        __swab32s (&p->rp_uid);
        __swab32s (&p->rp_gid);
        __swab32s (&p->rp_fsuid);
        __swab32s (&p->rp_fsgid);
        __swab32s (&p->rp_access_perm);
};

void lustre_swab_mdt_remote_perm (struct mdt_remote_perm *p)
{
        __swab32s (&p->rp_uid);
        __swab32s (&p->rp_gid);
        __swab32s (&p->rp_fsuid);
        __swab32s (&p->rp_fsgid);
        __swab32s (&p->rp_access_perm);
};

void lustre_swab_mds_rec_setattr (struct mds_rec_setattr *sa)
{
        __swab32s (&sa->sa_opcode);
        __swab32s (&sa->sa_fsuid);
        __swab32s (&sa->sa_fsgid);
        __swab32s (&sa->sa_cap);
        __swab32s (&sa->sa_suppgid);
        __swab32s (&sa->sa_mode);
        lustre_swab_ll_fid (&sa->sa_fid);
        __swab64s (&sa->sa_valid);
        __swab64s (&sa->sa_size);
        __swab64s (&sa->sa_mtime);
        __swab64s (&sa->sa_atime);
        __swab64s (&sa->sa_ctime);
        __swab32s (&sa->sa_uid);
        __swab32s (&sa->sa_gid);
        __swab32s (&sa->sa_attr_flags);
        CLASSERT(offsetof(typeof(*sa), sa_padding) != 0);
}

void lustre_swab_mds_rec_join (struct mds_rec_join *jr)
{
        __swab64s(&jr->jr_headsize);
        lustre_swab_ll_fid(&jr->jr_fid);
}

void lustre_swab_mdt_rec_join (struct mdt_rec_join *jr)
{
        __swab64s(&jr->jr_headsize);
        lustre_swab_lu_fid(&jr->jr_fid);
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
        CLASSERT(offsetof(typeof(*cr), cr_padding_1) != 0);
        CLASSERT(offsetof(typeof(*cr), cr_padding_2) != 0);
        CLASSERT(offsetof(typeof(*cr), cr_padding_3) != 0);
        CLASSERT(offsetof(typeof(*cr), cr_padding_4) != 0);
        CLASSERT(offsetof(typeof(*cr), cr_padding_5) != 0);
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
        __swab64s (&lk->lk_time);
        CLASSERT(offsetof(typeof(*lk), lk_padding_1) != 0);
        CLASSERT(offsetof(typeof(*lk), lk_padding_2) != 0);
        CLASSERT(offsetof(typeof(*lk), lk_padding_3) != 0);
        CLASSERT(offsetof(typeof(*lk), lk_padding_4) != 0);
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
        __swab64s (&ul->ul_time);
        CLASSERT(offsetof(typeof(*ul), ul_padding_1) != 0);
        CLASSERT(offsetof(typeof(*ul), ul_padding_2) != 0);
        CLASSERT(offsetof(typeof(*ul), ul_padding_3) != 0);
        CLASSERT(offsetof(typeof(*ul), ul_padding_4) != 0);
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
        __swab64s (&rn->rn_time);
        CLASSERT(offsetof(typeof(*rn), rn_padding_1) != 0);
        CLASSERT(offsetof(typeof(*rn), rn_padding_2) != 0);
        CLASSERT(offsetof(typeof(*rn), rn_padding_3) != 0);
        CLASSERT(offsetof(typeof(*rn), rn_padding_4) != 0);
}

void lustre_swab_mdt_rec_reint (struct mdt_rec_reint *rr)
{
        __swab32s (&rr->rr_opcode);
        __swab32s (&rr->rr_fsuid);
        __swab32s (&rr->rr_fsgid);
        __swab32s (&rr->rr_cap);
        __swab32s (&rr->rr_suppgid1);
        __swab32s (&rr->rr_suppgid2);
        /* handle is opaque */
        lustre_swab_lu_fid (&rr->rr_fid1);
        lustre_swab_lu_fid (&rr->rr_fid2);
        __swab64s (&rr->rr_mtime);
        __swab64s (&rr->rr_atime);
        __swab64s (&rr->rr_ctime);
        __swab64s (&rr->rr_size);
        __swab64s (&rr->rr_blocks);
        __swab32s (&rr->rr_bias);
        __swab32s (&rr->rr_mode);
        __swab32s (&rr->rr_padding_1);
        __swab32s (&rr->rr_padding_2);
        __swab32s (&rr->rr_padding_3);
        __swab32s (&rr->rr_padding_4);

        CLASSERT(offsetof(typeof(*rr), rr_padding_1) != 0);
        CLASSERT(offsetof(typeof(*rr), rr_padding_2) != 0);
        CLASSERT(offsetof(typeof(*rr), rr_padding_3) != 0);
        CLASSERT(offsetof(typeof(*rr), rr_padding_4) != 0);
};

void lustre_swab_lov_desc (struct lov_desc *ld)
{
        __swab32s (&ld->ld_tgt_count);
        __swab32s (&ld->ld_active_tgt_count);
        __swab32s (&ld->ld_default_stripe_count);
        __swab64s (&ld->ld_default_stripe_size);
        __swab64s (&ld->ld_default_stripe_offset);
        __swab32s (&ld->ld_pattern);
        __swab32s (&ld->ld_qos_maxage);
        /* uuid endian insensitive */
}

/*begin adding MDT by huanghua@clusterfs.com*/
void lustre_swab_lmv_desc (struct lmv_desc *ld)
{
        __swab32s (&ld->ld_tgt_count);
        __swab32s (&ld->ld_active_tgt_count);
        /* uuid endian insensitive */
}
/*end adding MDT by huanghua@clusterfs.com*/
void lustre_swab_md_fld (struct md_fld *mf)
{
        __swab64s(&mf->mf_seq);
        __swab64s(&mf->mf_mds);
}

static void print_lum (struct lov_user_md *lum)
{
        CDEBUG(D_OTHER, "lov_user_md %p:\n", lum);
        CDEBUG(D_OTHER, "\tlmm_magic: %#x\n", lum->lmm_magic);
        CDEBUG(D_OTHER, "\tlmm_pattern: %#x\n", lum->lmm_pattern);
        CDEBUG(D_OTHER, "\tlmm_object_id: "LPU64"\n", lum->lmm_object_id);
        CDEBUG(D_OTHER, "\tlmm_object_gr: "LPU64"\n", lum->lmm_object_gr);
        CDEBUG(D_OTHER, "\tlmm_stripe_size: %#x\n", lum->lmm_stripe_size);
        CDEBUG(D_OTHER, "\tlmm_stripe_count: %#x\n", lum->lmm_stripe_count);
        CDEBUG(D_OTHER, "\tlmm_stripe_offset: %#x\n", lum->lmm_stripe_offset);
}

void lustre_swab_lov_user_md(struct lov_user_md *lum)
{
        ENTRY;
        CDEBUG(D_IOCTL, "swabbing lov_user_md\n");
        __swab32s(&lum->lmm_magic);
        __swab32s(&lum->lmm_pattern);
        __swab64s(&lum->lmm_object_id);
        __swab64s(&lum->lmm_object_gr);
        __swab32s(&lum->lmm_stripe_size);
        __swab16s(&lum->lmm_stripe_count);
        __swab16s(&lum->lmm_stripe_offset);
        print_lum(lum);
        EXIT;
}

static void print_lumj (struct lov_user_md_join *lumj)
{
        CDEBUG(D_OTHER, "lov_user_md %p:\n", lumj);
        CDEBUG(D_OTHER, "\tlmm_magic: %#x\n", lumj->lmm_magic);
        CDEBUG(D_OTHER, "\tlmm_pattern: %#x\n", lumj->lmm_pattern);
        CDEBUG(D_OTHER, "\tlmm_object_id: "LPU64"\n", lumj->lmm_object_id);
        CDEBUG(D_OTHER, "\tlmm_object_gr: "LPU64"\n", lumj->lmm_object_gr);
        CDEBUG(D_OTHER, "\tlmm_stripe_size: %#x\n", lumj->lmm_stripe_size);
        CDEBUG(D_OTHER, "\tlmm_stripe_count: %#x\n", lumj->lmm_stripe_count);
        CDEBUG(D_OTHER, "\tlmm_extent_count: %#x\n", lumj->lmm_extent_count);
}

void lustre_swab_lov_user_md_join(struct lov_user_md_join *lumj)
{
        ENTRY;
        CDEBUG(D_IOCTL, "swabbing lov_user_md_join\n");
        __swab32s(&lumj->lmm_magic);
        __swab32s(&lumj->lmm_pattern);
        __swab64s(&lumj->lmm_object_id);
        __swab64s(&lumj->lmm_object_gr);
        __swab32s(&lumj->lmm_stripe_size);
        __swab32s(&lumj->lmm_stripe_count);
        __swab32s(&lumj->lmm_extent_count);
        print_lumj(lumj);
        EXIT;
}

static void print_lum_objs(struct lov_user_md *lum)
{
        struct lov_user_ost_data *lod;
        int i;
        ENTRY;
        if (!(libcfs_debug & D_OTHER)) /* don't loop on nothing */
                return;
        CDEBUG(D_OTHER, "lov_user_md_objects: %p\n", lum);
        for (i = 0; i < lum->lmm_stripe_count; i++) {
                lod = &lum->lmm_objects[i];
                CDEBUG(D_OTHER, "(%i) lod->l_object_id: "LPX64"\n", i, lod->l_object_id);
                CDEBUG(D_OTHER, "(%i) lod->l_object_gr: "LPX64"\n", i, lod->l_object_gr);
                CDEBUG(D_OTHER, "(%i) lod->l_ost_gen: %#x\n", i, lod->l_ost_gen);
                CDEBUG(D_OTHER, "(%i) lod->l_ost_idx: %#x\n", i, lod->l_ost_idx);
        }
        EXIT;
}

void lustre_swab_lov_user_md_objects(struct lov_user_md *lum)
{
        struct lov_user_ost_data *lod;
        int i;
        ENTRY;
        for (i = 0; i < lum->lmm_stripe_count; i++) {
                lod = &lum->lmm_objects[i];
                __swab64s(&lod->l_object_id);
                __swab64s(&lod->l_object_gr);
                __swab32s(&lod->l_ost_gen);
                __swab32s(&lod->l_ost_idx);
        }
        print_lum_objs(lum);
        EXIT;
}


void lustre_swab_lov_mds_md(struct lov_mds_md *lmm)
{
        struct lov_ost_data *lod;
        int i;
        ENTRY;
        for (i = 0; i < lmm->lmm_stripe_count; i++) {
                lod = &lmm->lmm_objects[i];
                __swab64s(&lod->l_object_id);
                __swab64s(&lod->l_object_gr);
                __swab32s(&lod->l_ost_gen);
                __swab32s(&lod->l_ost_idx);
        }
        __swab32s(&lmm->lmm_magic);
        __swab32s(&lmm->lmm_pattern);
        __swab64s(&lmm->lmm_object_id);
        __swab64s(&lmm->lmm_object_gr);
        __swab32s(&lmm->lmm_stripe_size);
        __swab32s(&lmm->lmm_stripe_count);

        EXIT;
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
        __swab64s(&d->l_extent.start);
        __swab64s(&d->l_extent.end);
        __swab64s(&d->l_extent.gid);
        __swab32s(&d->l_flock.pid);
}

void lustre_swab_ldlm_intent (struct ldlm_intent *i)
{
        __swab64s (&i->opc);
}

void lustre_swab_ldlm_resource_desc (struct ldlm_resource_desc *r)
{
        __swab32s (&r->lr_type);
        CLASSERT(offsetof(typeof(*r), lr_padding) != 0);
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
        __swab32s (&rq->lock_count);
        /* lock_handle[] opaque */
}

void lustre_swab_ldlm_reply (struct ldlm_reply *r)
{
        __swab32s (&r->lock_flags);
        CLASSERT(offsetof(typeof(*r), lock_padding) != 0);
        lustre_swab_ldlm_lock_desc (&r->lock_desc);
        /* lock_handle opaque */
        __swab64s (&r->lock_policy_res1);
        __swab64s (&r->lock_policy_res2);
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

void lustre_swab_qdata(struct qunit_data *d)
{
        __swab32s (&d->qd_id);
        __swab32s (&d->qd_flags);
        __swab64s (&d->qd_count);
}

void lustre_swab_qdata_old(struct qunit_data_old *d)
{
        __swab32s (&d->qd_id);
        __swab32s (&d->qd_type);
        __swab32s (&d->qd_count);
        __swab32s (&d->qd_isblk);
}

#ifdef __KERNEL__
struct qunit_data *lustre_quota_old_to_new(struct qunit_data_old *d)
{
        struct qunit_data_old tmp;
        struct qunit_data *ret;
        ENTRY;

        if (!d)
                return NULL;

        tmp = *d;
        ret = (struct qunit_data *)d;
        ret->qd_id = tmp.qd_id;
        ret->qd_flags = (tmp.qd_type ? QUOTA_IS_GRP : 0) | (tmp.qd_isblk ? QUOTA_IS_BLOCK : 0);
        ret->qd_count = tmp.qd_count;
        RETURN(ret);

}
EXPORT_SYMBOL(lustre_quota_old_to_new);

struct qunit_data_old *lustre_quota_new_to_old(struct qunit_data *d)
{
        struct qunit_data tmp;
        struct qunit_data_old *ret;
        ENTRY;

        if (!d)
                return NULL;

        tmp = *d;
        ret = (struct qunit_data_old *)d;
        ret->qd_id = tmp.qd_id;
        ret->qd_type = ((tmp.qd_flags & QUOTA_IS_GRP) ? GRPQUOTA : USRQUOTA);
        ret->qd_count = (__u32)tmp.qd_count;
        ret->qd_isblk = ((tmp.qd_flags & QUOTA_IS_BLOCK) ? 1 : 0);
        RETURN(ret);
}
EXPORT_SYMBOL(lustre_quota_new_to_old);
#endif /* __KERNEL__ */

static inline int req_ptlrpc_body_swabbed(struct ptlrpc_request *req)
{
        LASSERT(req->rq_reqmsg);

        switch (req->rq_reqmsg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                return lustre_req_swabbed(req, MSG_PTLRPC_BODY_OFF);
        default:
                CERROR("bad lustre msg magic: %#08X\n",
                       req->rq_reqmsg->lm_magic);
        }
        return 0;
}

static inline int rep_ptlrpc_body_swabbed(struct ptlrpc_request *req)
{
        LASSERT(req->rq_repmsg);

        switch (req->rq_repmsg->lm_magic) {
        case LUSTRE_MSG_MAGIC_V2:
        case LUSTRE_MSG_MAGIC_V2_SWABBED:
                return lustre_rep_swabbed(req, MSG_PTLRPC_BODY_OFF);
        default:
                /* uninitialized yet */
                return 0;
        }
}

void _debug_req(struct ptlrpc_request *req, __u32 mask,
                struct libcfs_debug_msg_data *data, const char *fmt, ... )
{
        va_list args;

        va_start(args, fmt);
        libcfs_debug_vmsg2(data->msg_cdls, data->msg_subsys, mask, data->msg_file,
                           data->msg_fn, data->msg_line, fmt, args,
                           " req@%p x"LPD64"/t"LPD64"("LPD64") o%d->%s@%s:%d/%d"
                           " lens %d/%d e %d to %d dl "CFS_TIME_T" ref %d "
                           "fl "REQ_FLAGS_FMT"/%x/%x rc %d/%d\n",
                           req, req->rq_xid, req->rq_transno,
                           req->rq_reqmsg ? lustre_msg_get_transno(req->rq_reqmsg) : 0,
                           req->rq_reqmsg ? lustre_msg_get_opc(req->rq_reqmsg) : -1,
                           req->rq_import ? obd2cli_tgt(req->rq_import->imp_obd) :
                           req->rq_export ?
                           (char*)req->rq_export->exp_client_uuid.uuid : "<?>",
                           req->rq_import ?
                           (char *)req->rq_import->imp_connection->c_remote_uuid.uuid :
                           req->rq_export ?
                           (char *)req->rq_export->exp_connection->c_remote_uuid.uuid : "<?>",
                           req->rq_request_portal, req->rq_reply_portal,
                           req->rq_reqlen, req->rq_replen,
                           req->rq_early_count, req->rq_timeout, req->rq_deadline,
                           atomic_read(&req->rq_refcount), DEBUG_REQ_FLAGS(req),
                           req->rq_reqmsg && req_ptlrpc_body_swabbed(req) ?
                           lustre_msg_get_flags(req->rq_reqmsg) : -1,
                           req->rq_repmsg && rep_ptlrpc_body_swabbed(req) ?
                           lustre_msg_get_flags(req->rq_repmsg) : -1,
                           req->rq_status,
                           req->rq_repmsg && rep_ptlrpc_body_swabbed(req) ?
                           lustre_msg_get_status(req->rq_repmsg) : -1);
}
EXPORT_SYMBOL(_debug_req);

void lustre_swab_lustre_capa(struct lustre_capa *c)
{
        lustre_swab_lu_fid(&c->lc_fid);
        __swab64s (&c->lc_opc);
        __swab32s (&c->lc_uid);
        __swab32s (&c->lc_flags);
        __swab32s (&c->lc_keyid);
        __swab32s (&c->lc_timeout);
        __swab64s (&c->lc_expiry);
}

void lustre_swab_lustre_capa_key (struct lustre_capa_key *k)
{
        __swab64s (&k->lk_mdsid);
        __swab32s (&k->lk_keyid);
        __swab32s (&k->lk_padding);
}
