/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC
#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#else
#include <liblustre.h>
#endif

#include <libcfs/kp30.h>
#include <linux/obd_support.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_net.h>
#include <linux/lustre_sec.h>

static spinlock_t svcsecs_lock = SPIN_LOCK_UNLOCKED;
static struct ptlrpc_svcsec *svcsecs[PTLRPC_SEC_MAX_FLAVORS] = {
        NULL,
};

int svcsec_register(struct ptlrpc_svcsec *sec)
{
        __u32 flavor = sec->pss_flavor.flavor;

        if (flavor >= PTLRPC_SEC_MAX_FLAVORS)
                return -EINVAL;

        spin_lock(&svcsecs_lock);
        if (svcsecs[flavor]) {
                spin_unlock(&svcsecs_lock);
                return -EALREADY;
        }
        svcsecs[flavor] = sec;
        spin_unlock(&svcsecs_lock);

        CDEBUG(D_SEC, "Registered svc security module %s\n", sec->pss_name);
        return 0;
}

int svcsec_unregister(struct ptlrpc_svcsec *sec)
{
        __u32 flavor = sec->pss_flavor.flavor;

        if (flavor >= PTLRPC_SEC_MAX_FLAVORS)
                return -EINVAL;

        spin_lock(&svcsecs_lock);
        if (!svcsecs[flavor]) {
                spin_unlock(&svcsecs_lock);
                return -EINVAL;
        }

        LASSERT(svcsecs[flavor] == sec);

        CDEBUG(D_SEC, "Unregistered svc security module %s\n", sec->pss_name);
        svcsecs[flavor] = NULL;
        spin_unlock(&svcsecs_lock);

        return 0;
}

static
struct ptlrpc_svcsec * flavor2svcsec(__u32 flavor)
{
        struct ptlrpc_svcsec *sec;

        if (flavor >= PTLRPC_SEC_MAX_FLAVORS)
                return NULL;

        spin_lock(&svcsecs_lock);
        sec = svcsecs[flavor];
        if (sec && !try_module_get(sec->pss_owner))
                sec = NULL;
        spin_unlock(&svcsecs_lock);
        return sec;
}

struct ptlrpc_svcsec * svcsec_get(struct ptlrpc_svcsec *sec)
{
        int rc;

        spin_lock(&svcsecs_lock);
        rc = try_module_get(sec->pss_owner);
        spin_unlock(&svcsecs_lock);
        LASSERT(rc);
        return sec;
}

void svcsec_put(struct ptlrpc_svcsec *sec)
{
        spin_lock(&svcsecs_lock);
        module_put(sec->pss_owner);
        spin_unlock(&svcsecs_lock);
}

/*
 * common code to allocate reply_state buffer.
 */
int svcsec_alloc_reply_state(struct ptlrpc_request *req,
                             int msgsize, int secsize)
{
        struct ptlrpc_reply_state *rs;
        char *buf;
        int repsize, bufsize;
        ENTRY;

        LASSERT(msgsize % 8 == 0);
        LASSERT(secsize % 8 == 0);

        repsize = sizeof(struct ptlrpcs_wire_hdr) + msgsize + secsize;
        bufsize = repsize + sizeof(struct ptlrpc_reply_state);

        OBD_ALLOC(buf, bufsize);
        if (!buf) {
                CERROR("can't alloc %d\n", bufsize);
                RETURN(-ENOMEM);
        }

        /* req->rq_repbuf is not used on server side */
        rs = (struct ptlrpc_reply_state *) (buf + repsize);
        rs->rs_buf = buf;
        rs->rs_buf_len = bufsize;
        rs->rs_repbuf = buf;
        rs->rs_repbuf_len = repsize;
        /* current known data length is hdr + msg, security payload
         * will be added on later.
         */
        rs->rs_repdata_len = sizeof(struct ptlrpcs_wire_hdr) + msgsize;
        req->rq_repmsg = rs->rs_msg = (struct lustre_msg *)
                         (rs->rs_repbuf + sizeof(struct ptlrpcs_wire_hdr));

        req->rq_reply_state = rs;

        CDEBUG(D_SEC, "alloc rs buf at %p, len %d; repbuf at %p, len %d\n",
               rs->rs_buf, rs->rs_buf_len, rs->rs_repbuf, rs->rs_repbuf_len);

        RETURN(0);
}

void svcsec_free_reply_state(struct ptlrpc_reply_state *rs)
{
        char *p;
        ENTRY;

        /* for work around memory-alloc debug poison */
        LASSERT(rs);
        p = rs->rs_buf;
        OBD_FREE(p, rs->rs_buf_len);
        EXIT;
}

int svcsec_alloc_repbuf(struct ptlrpc_svcsec *svcsec,
                        struct ptlrpc_request *req,
                        int msgsize)
{
        LASSERT(svcsec);
        LASSERT(msgsize % 8 == 0);

        if (svcsec->alloc_repbuf)
                return svcsec->alloc_repbuf(svcsec, req, msgsize);
        else
                return svcsec_alloc_reply_state(req, msgsize, 0);
}

int svcsec_accept(struct ptlrpc_request *req, enum ptlrpcs_error *res)
{
        struct ptlrpc_svcsec           *sec;
        struct ptlrpcs_wire_hdr        *sec_hdr;
        int                             rc;
        ENTRY;

        LASSERT(req->rq_reqbuf);
        LASSERT(!req->rq_reqmsg);
        LASSERT(!req->rq_svcsec);

        *res = PTLRPCS_BADCRED;
        if (req->rq_reqbuf_len < sizeof(*sec_hdr)) {
                CERROR("drop too short msg (length: %d)\n", req->rq_reqbuf_len);
                RETURN(SVC_DROP);
        }

        sec_hdr = (struct ptlrpcs_wire_hdr *) req->rq_reqbuf;
        sec_hdr->flavor = le32_to_cpu(sec_hdr->flavor);
        sec_hdr->sectype = le32_to_cpu(sec_hdr->sectype);
        sec_hdr->msg_len = le32_to_cpu(sec_hdr->msg_len);
        sec_hdr->sec_len = le32_to_cpu(sec_hdr->sec_len);

        /* sanity check */
        switch (sec_hdr->sectype) {
        case PTLRPC_SEC_TYPE_NONE:
        case PTLRPC_SEC_TYPE_AUTH:
        case PTLRPC_SEC_TYPE_PRIV:
                break;
        default:
                CERROR("unknown security type %d\n", sec_hdr->sectype);
                RETURN(SVC_DROP);
        }

        if (sizeof(*sec_hdr) + sec_hdr->msg_len + sec_hdr->sec_len >
            req->rq_reqbuf_len) {
                CERROR("received %d, msg %d, sec %d\n",
                        req->rq_reqbuf_len, sec_hdr->msg_len, sec_hdr->sec_len);
                RETURN(SVC_DROP);
        }

        req->rq_svcsec = sec = flavor2svcsec(sec_hdr->flavor);
        if (!sec) {
                CERROR("drop msg: unsupported flavor %d\n", sec_hdr->flavor);
                RETURN(SVC_DROP);
        }
        LASSERT(sec->accept);

        rc = sec->accept(req, res);

        switch (rc) {
        case SVC_DROP:
                svcsec_put(sec);
                req->rq_svcsec = NULL;
                break;
        case SVC_OK:
        case SVC_LOGIN:
        case SVC_LOGOUT:
                LASSERT(req->rq_reqmsg);
                break;
        }

        RETURN(rc);
}

int svcsec_authorize(struct ptlrpc_request *req)
{
        LASSERT(req->rq_svcsec);
        LASSERT(req->rq_svcsec->authorize);

        return (req->rq_svcsec->authorize(req));
}

void svcsec_cleanup_req(struct ptlrpc_request *req)
{
        struct ptlrpc_svcsec *svcsec = req->rq_svcsec;
        ENTRY;

        LASSERT(svcsec);
        LASSERT(svcsec->cleanup_req || !req->rq_sec_svcdata);

        if (svcsec->cleanup_req)
                svcsec->cleanup_req(svcsec, req);
        EXIT;
}
