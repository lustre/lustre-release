/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/fid_store.c
 *  Lustre Sequence Manager
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_FID

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>
#include <md_object.h>
#include <obd_support.h>
#include <lustre_req_layout.h>
#include <lustre_fid.h>
#include "fid_internal.h"

#ifdef __KERNEL__
struct seq_store_capsule {
        struct lu_range ssc_space;
        struct lu_range ssc_super;
};

enum {
        SEQ_TXN_STORE_CREDITS = 20
};

/* this function implies that caller takes care about locking */
int seq_store_write(struct lu_server_seq *seq,
                    const struct lu_context *ctx)
{
        struct dt_object *dt_obj = seq->seq_obj;
        struct dt_device *dt_dev = seq->seq_dev;
        struct seq_store_capsule capsule;
        loff_t pos = 0;
        struct txn_param txn;
        struct thandle *th;
	int rc;
	ENTRY;

        /* stub here, will fix it later */
        txn.tp_credits = SEQ_TXN_STORE_CREDITS;

        th = dt_dev->dd_ops->dt_trans_start(ctx, dt_dev, &txn);
        if (!IS_ERR(th)) {
                rc = dt_obj->do_body_ops->dbo_write(ctx, dt_obj,
                                                    (char *)&capsule,
                                                    sizeof(capsule),
                                                    &pos, th);
                if (rc == sizeof(capsule)) {
                        rc = 0;
                } else if (rc >= 0) {
                        rc = -EIO;
                }
                
                dt_dev->dd_ops->dt_trans_stop(ctx, th);
        } else {
                rc = PTR_ERR(th);
        }
	
	RETURN(rc);
}

/* this function implies that caller takes care about locking or locking is not
 * needed (init time). */
int seq_store_read(struct lu_server_seq *seq,
                   const struct lu_context *ctx)
{
        struct dt_object *dt_obj = seq->seq_obj;
        struct seq_store_capsule capsule;
        loff_t pos = 0;
	int rc;
	ENTRY;

        rc = dt_obj->do_body_ops->dbo_read(ctx, dt_obj,
                                           (char *)&capsule,
                                           sizeof(capsule), &pos);
        if (rc == sizeof(capsule)) {
                seq->seq_space = capsule.ssc_space;
                seq->seq_super = capsule.ssc_super;
                rc = 0;
        } else if (rc == 0) {
                rc = -ENODATA;
        } else if (rc >= 0) {
                CERROR("read only %d bytes of %d\n",
                       rc, sizeof(capsule));
                rc = -EIO;
        }
	
	RETURN(rc);
}

int seq_store_init(struct lu_server_seq *seq,
                   const struct lu_context *ctx)
{
        struct dt_device *dt = seq->seq_dev;
        struct dt_object *dt_obj;
        int rc;
        ENTRY;

        LASSERT(seq->seq_service == NULL);

        dt_obj = dt_store_open(ctx, dt, "seq", &seq->seq_fid);
        if (!IS_ERR(dt_obj)) {
                seq->seq_obj = dt_obj;
		rc = 0;
        } else {
                CERROR("cannot find \"seq\" obj %d\n",
		       (int)PTR_ERR(dt_obj));
                rc = PTR_ERR(dt_obj);
        }

        RETURN(rc);
}

void seq_store_fini(struct lu_server_seq *seq,
                    const struct lu_context *ctx)
{
        ENTRY;
        if (seq->seq_obj != NULL) {
                lu_object_put(ctx, &seq->seq_obj->do_lu);
                seq->seq_obj = NULL;
        }
        EXIT;
}
#endif
