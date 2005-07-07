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

static
int null_svcsec_accept(struct ptlrpc_request *req, enum ptlrpcs_error *res)
{
        struct ptlrpcs_wire_hdr *hdr = buf_to_sec_hdr(req->rq_reqbuf);
        ENTRY;

        LASSERT(SEC_FLAVOR_MAJOR(hdr->flavor) == PTLRPCS_FLVR_MAJOR_NULL);

        if (hdr->sec_len != 0) {
                CERROR("security payload %d not zero\n", hdr->sec_len);
                *res = PTLRPCS_REJECTEDCRED;
                RETURN(SVC_DROP);
        }

        req->rq_req_secflvr = PTLRPCS_FLVR_NULL;

        req->rq_reqmsg = (struct lustre_msg *)(hdr + 1);
        req->rq_reqlen = hdr->msg_len;
        *res = PTLRPCS_OK;
        CDEBUG(D_SEC, "req %p: set reqmsg at %p, len %d\n",
               req, req->rq_reqmsg, req->rq_reqlen);
        RETURN(SVC_OK);
}

static
int null_svcsec_authorize(struct ptlrpc_request *req)
{
        struct ptlrpc_reply_state *rs = req->rq_reply_state;
        struct ptlrpcs_wire_hdr *hdr;
        ENTRY;

        LASSERT(rs);
        LASSERT(rs->rs_repbuf_len >= 4 * 4);

        hdr = buf_to_sec_hdr(rs->rs_repbuf);
        hdr->flavor = cpu_to_le32(PTLRPCS_FLVR_NULL);
        hdr->msg_len = cpu_to_le32(req->rq_replen);
        hdr->sec_len = cpu_to_le32(0);

        CDEBUG(D_SEC, "fill in datasize %d\n", rs->rs_repdata_len);
        RETURN(0);
}

static struct ptlrpc_svcsec null_svcsec = {
        .pss_owner      = THIS_MODULE,
        .pss_name       = "svcsec.null",
        .pss_flavor     = PTLRPCS_FLVR_MAJOR_NULL,
        .accept         = null_svcsec_accept,
        .authorize      = null_svcsec_authorize,
};

int svcsec_null_init()
{
        int rc;

        rc = svcsec_register(&null_svcsec);
        if (rc)
                CERROR("failed to register SVCNULL security: %d\n", rc);

        return rc;
}

int svcsec_null_exit()
{
        int rc;

        rc = svcsec_unregister(&null_svcsec);
        if (rc)
                CERROR("cannot unregister SVCNULL security: %d\n", rc);

        return rc;
}

