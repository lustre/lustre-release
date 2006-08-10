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
enum {
        SEQ_TXN_STORE_CREDITS = 20
};

/* this function implies that caller takes care about locking */
int seq_store_write(struct lu_server_seq *seq,
                    const struct lu_context *ctx)
{
        struct dt_object *dt_obj = seq->lss_obj;
        struct dt_device *dt_dev = seq->lss_dev;
        struct seq_thread_info *info;
        struct thandle *th;
        loff_t pos = 0;
	int rc;
	ENTRY;

        info = lu_context_key_get(ctx, &seq_thread_key);
        LASSERT(info != NULL);

        /* stub here, will fix it later */
        info->sti_txn.tp_credits = SEQ_TXN_STORE_CREDITS;

        th = dt_dev->dd_ops->dt_trans_start(ctx, dt_dev, &info->sti_txn);
        if (!IS_ERR(th)) {
                /* store ranges in le format */
                range_to_le(&info->sti_record.ssr_space, &seq->lss_space);
                range_to_le(&info->sti_record.ssr_super, &seq->lss_super);

                rc = dt_obj->do_body_ops->dbo_write(ctx, dt_obj,
                                                    (char *)&info->sti_record,
                                                    sizeof(info->sti_record),
                                                    &pos, th);
                if (rc == sizeof(info->sti_record)) {
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
        struct dt_object *dt_obj = seq->lss_obj;
        struct seq_thread_info *info;
        loff_t pos = 0;
	int rc;
	ENTRY;

        info = lu_context_key_get(ctx, &seq_thread_key);
        LASSERT(info != NULL);

        rc = dt_obj->do_body_ops->dbo_read(ctx, dt_obj,
                                           (char *)&info->sti_record,
                                           sizeof(info->sti_record), &pos);
        if (rc == sizeof(info->sti_record)) {
                seq->lss_space = info->sti_record.ssr_space;
                lustre_swab_lu_range(&seq->lss_space);
                
                seq->lss_super = info->sti_record.ssr_super;
                lustre_swab_lu_range(&seq->lss_super);
                rc = 0;
        } else if (rc == 0) {
                rc = -ENODATA;
        } else if (rc >= 0) {
                CERROR("read only %d bytes of %d\n",
                       rc, sizeof(info->sti_record));
                rc = -EIO;
        }
	
	RETURN(rc);
}

int seq_store_init(struct lu_server_seq *seq,
                   const struct lu_context *ctx)
{
        struct dt_device *dt = seq->lss_dev;
        struct dt_object *dt_obj;
        struct lu_fid fid;
        int rc;
        ENTRY;

        LASSERT(seq->lss_service == NULL);

        dt_obj = dt_store_open(ctx, dt, "seq", &fid);
        if (!IS_ERR(dt_obj)) {
                seq->lss_obj = dt_obj;
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
        if (seq->lss_obj != NULL) {
                lu_object_put(ctx, &seq->lss_obj->do_lu);
                seq->lss_obj = NULL;
        }
        EXIT;
}
#endif
