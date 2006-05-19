/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/fid_seq.c
 *  Lustre File Id (fid)
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#include <linux/module.h>

#include <lustre/lustre_idl.h>
#include <obd.h>
#include <lustre_fid.h>

/* sequence manager initialization/finalization stuff */
struct lu_seq_mgr *seq_mgr_init(struct lu_seq_mgr_ops *ops,
                                void *opaque)
{
        struct lu_seq_mgr *mgr;
        ENTRY;

        OBD_ALLOC_PTR(mgr);
        if (!mgr)
                RETURN(NULL);

        sema_init(&mgr->m_seq_sem, 1);
        mgr->m_opaque = opaque;
        mgr->m_ops = ops;

        RETURN(mgr);
}
EXPORT_SYMBOL(seq_mgr_init);

void seq_mgr_fini(struct lu_seq_mgr *mgr)
{
        OBD_FREE_PTR(mgr);
}
EXPORT_SYMBOL(seq_mgr_fini);

int seq_mgr_write(const struct lu_context *ctx, struct lu_seq_mgr *mgr)
{
        ENTRY;
        RETURN(mgr->m_ops->smo_write(ctx, mgr->m_opaque, &mgr->m_seq));
}
EXPORT_SYMBOL(seq_mgr_write);

int seq_mgr_read(const struct lu_context *ctx, struct lu_seq_mgr *mgr)
{
        ENTRY;
        RETURN(mgr->m_ops->smo_read(ctx, mgr->m_opaque, &mgr->m_seq));
}
EXPORT_SYMBOL(seq_mgr_read);

/* manager functionality stuff */
int seq_mgr_alloc(const struct lu_context *ctx, struct lu_seq_mgr *mgr,
                  __u64 *seq)
{
        int rc = 0;
        ENTRY;

        LASSERT(mgr != NULL);
        LASSERT(seq != NULL);

        down(&mgr->m_seq_sem);
        if (mgr->m_seq > mgr->m_seq_last) {
                /* new range of seqs should be got from master */
                rc = -EOPNOTSUPP;
        } else {
                *seq = mgr->m_seq;
                mgr->m_seq++;

                rc = seq_mgr_write(ctx, mgr);
        }
        up(&mgr->m_seq_sem);
        RETURN(rc);
}
EXPORT_SYMBOL(seq_mgr_alloc);

/* initialize meta-sequence. First of all try to get it from lower layer,
 * falling down to back store one. In the case this is first run and there is
 * not meta-sequence initialized yet - store it to backstore. */
int seq_mgr_setup(const struct lu_context *ctx, struct lu_seq_mgr *mgr)
{
        int rc = 0;
        ENTRY;

        /* set seq range */
        mgr->m_seq_last = mgr->m_seq + LUSTRE_SEQ_RANGE;
        /* allocate next seq after root one */
        mgr->m_seq += LUSTRE_ROOT_FID_SEQ + 1;

        rc = seq_mgr_read(ctx, mgr);
        if (rc == -ENODATA) {
                CWARN("initialize sequence by defaut ["LPU64"]\n", mgr->m_seq);

                /* initialize new sequence config as it is not yet created. */
                rc = seq_mgr_write(ctx, mgr);
        }

        EXIT;
        if (rc == 0)
                CWARN("using start sequence: ["LPU64"]\n", mgr->m_seq);
        return rc;
}
EXPORT_SYMBOL(seq_mgr_setup);

static int __init fid_mod_init(void)
{
        /* some stuff will be here (cache initializing, etc.) */
	return 0;
}

static void __exit fid_mod_exit(void)
{
        /* some stuff will be here */
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre FID Module");
MODULE_LICENSE("GPL");

cfs_module(fid, "0.0.2", fid_mod_init, fid_mod_exit);
