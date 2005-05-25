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
#include <linux/lustre_net.h>
#include <linux/lustre_sec.h>

static int null_cred_refresh(struct ptlrpc_cred *cred)
{
        ENTRY;
        LASSERT(cred->pc_flags & PTLRPC_CRED_UPTODATE);
        RETURN(0);
}

static int null_cred_match(struct ptlrpc_cred *cred,
                           struct vfs_cred *vcred)
{
        ENTRY;
        RETURN(1);
}

static int null_cred_sign(struct ptlrpc_cred *cred,
                          struct ptlrpc_request *req)
{
        struct ptlrpcs_wire_hdr *hdr = buf_to_sec_hdr(req->rq_reqbuf);
        ENTRY;

        hdr->sec_len = cpu_to_le32(0);

        RETURN(0);
}

static int null_cred_verify(struct ptlrpc_cred *cred,
                            struct ptlrpc_request *req)
{
        struct ptlrpcs_wire_hdr *hdr = buf_to_sec_hdr(req->rq_repbuf);

        if (hdr->sec_len != 0) {
                CERROR("security payload %u not zero\n", hdr->sec_len);
                RETURN(-EPROTO);
        }

        req->rq_repmsg = (struct lustre_msg *)(hdr + 1);
        req->rq_replen = hdr->msg_len;
        CDEBUG(D_SEC, "set repmsg at %p, len %d\n",
               req->rq_repmsg, req->rq_replen);

        RETURN(0);
}

static void null_cred_destroy(struct ptlrpc_cred *cred)
{
        LASSERT(!atomic_read(&cred->pc_refcount));

        CDEBUG(D_SEC, "NULL_SEC: destroy cred %p\n", cred);
        OBD_FREE(cred, sizeof(*cred));
}

static struct ptlrpc_credops null_credops = {
        .refresh        = null_cred_refresh,
        .match          = null_cred_match,
        .sign           = null_cred_sign,
        .verify         = null_cred_verify,
        .destroy        = null_cred_destroy,
};

static
struct ptlrpc_sec* null_create_sec(ptlrpcs_flavor_t *flavor,
                                   const char *pipe_dir,
                                   void *pipe_data)
{
        struct ptlrpc_sec *sec;
        ENTRY;

        LASSERT(flavor->flavor == PTLRPC_SEC_NULL);

        OBD_ALLOC(sec, sizeof(*sec));
        if (!sec)
                RETURN(ERR_PTR(-ENOMEM));

        sec->ps_sectype = PTLRPC_SEC_TYPE_NONE;
        sec->ps_expire = (-1UL >> 1); /* never expire */
        sec->ps_nextgc = (-1UL >> 1);
        sec->ps_flags = 0;

        CDEBUG(D_SEC, "Create NULL security module at %p\n", sec);
        RETURN(sec);
}

static
void null_destroy_sec(struct ptlrpc_sec *sec)
{
        ENTRY;

        CDEBUG(D_SEC, "Destroy NULL security module at %p\n", sec);

        LASSERT(!atomic_read(&sec->ps_refcount));
        OBD_FREE(sec, sizeof(*sec));
        EXIT;
}

static
struct ptlrpc_cred* null_create_cred(struct ptlrpc_sec *sec,
                                     struct vfs_cred *vcred)
{
        struct ptlrpc_cred *cred;
        ENTRY;

        OBD_ALLOC(cred, sizeof(*cred));
        if (!cred)
                RETURN(NULL);

        INIT_LIST_HEAD(&cred->pc_hash);
        atomic_set(&cred->pc_refcount, 0);
        cred->pc_sec = sec;
        cred->pc_ops = &null_credops;
        cred->pc_expire = (-1UL >> 1); /* never expire */
        cred->pc_flags = PTLRPC_CRED_UPTODATE;
        cred->pc_pag = vcred->vc_pag;
        cred->pc_uid = vcred->vc_uid;
        CDEBUG(D_SEC, "create a null cred at %p("LPU64"/%u)\n",
               cred, vcred->vc_pag, vcred->vc_uid);

        RETURN(cred);
}

static struct ptlrpc_secops null_secops = {
        .create_sec     = null_create_sec,
        .destroy_sec    = null_destroy_sec,
        .create_cred    = null_create_cred,
};

static struct ptlrpc_sec_type null_type = {
        .pst_owner      = THIS_MODULE,
        .pst_name       = "NULL_SEC",
        .pst_inst       = ATOMIC_INIT(0),
        .pst_flavor     = {PTLRPC_SEC_NULL, 0},
        .pst_ops        = &null_secops,
};

int ptlrpcs_null_init(void)
{
        int rc;

        rc = ptlrpcs_register(&null_type);
        if (rc)
                CERROR("failed to register NULL security: %d\n", rc);

        return rc;
}

int ptlrpcs_null_exit(void)
{
        int rc;

        rc = ptlrpcs_unregister(&null_type);
        if (rc)
                CERROR("cannot unregister NULL security: %d\n", rc);

        return rc;
}
