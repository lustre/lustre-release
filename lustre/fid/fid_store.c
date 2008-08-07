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
 * lustre/fid/fid_store.c
 *
 * Lustre Sequence Manager
 *
 * Author: Yury Umanets <umka@clusterfs.com>
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

static struct lu_buf *seq_store_buf(struct seq_thread_info *info)
{
        struct lu_buf *buf;

        buf = &info->sti_buf;
        buf->lb_buf = &info->sti_space;
        buf->lb_len = sizeof(info->sti_space);
        return buf;
}

/* This function implies that caller takes care about locking. */
int seq_store_write(struct lu_server_seq *seq,
                    const struct lu_env *env)
{
        struct dt_object *dt_obj = seq->lss_obj;
        struct seq_thread_info *info;
        struct dt_device *dt_dev;
        struct thandle *th;
        loff_t pos = 0;
	int rc;
	ENTRY;

        dt_dev = lu2dt_dev(seq->lss_obj->do_lu.lo_dev);
        info = lu_context_key_get(&env->le_ctx, &seq_thread_key);
        LASSERT(info != NULL);

        /* Stub here, will fix it later. */
        txn_param_init(&info->sti_txn, SEQ_TXN_STORE_CREDITS);

        th = dt_dev->dd_ops->dt_trans_start(env, dt_dev, &info->sti_txn);
        if (!IS_ERR(th)) {
                /* Store ranges in le format. */
                range_cpu_to_le(&info->sti_space, &seq->lss_space);

                rc = dt_obj->do_body_ops->dbo_write(env, dt_obj,
                                                    seq_store_buf(info),
                                                    &pos, th, BYPASS_CAPA);
                if (rc == sizeof(info->sti_space)) {
                        CDEBUG(D_INFO, "%s: Space - "DRANGE"\n",
                               seq->lss_name, PRANGE(&seq->lss_space));
                        rc = 0;
                } else if (rc >= 0) {
                        rc = -EIO;
                }

                dt_dev->dd_ops->dt_trans_stop(env, th);
        } else {
                rc = PTR_ERR(th);
        }
	
	RETURN(rc);
}

/*
 * This function implies that caller takes care about locking or locking is not
 * needed (init time).
 */
int seq_store_read(struct lu_server_seq *seq,
                   const struct lu_env *env)
{
        struct dt_object *dt_obj = seq->lss_obj;
        struct seq_thread_info *info;
        loff_t pos = 0;
	int rc;
	ENTRY;

        info = lu_context_key_get(&env->le_ctx, &seq_thread_key);
        LASSERT(info != NULL);

        rc = dt_obj->do_body_ops->dbo_read(env, dt_obj, seq_store_buf(info),
                                           &pos, BYPASS_CAPA);

        if (rc == sizeof(info->sti_space)) {
                range_le_to_cpu(&seq->lss_space, &info->sti_space);
                CDEBUG(D_INFO, "%s: Space - "DRANGE"\n",
                       seq->lss_name, PRANGE(&seq->lss_space));
                rc = 0;
        } else if (rc == 0) {
                rc = -ENODATA;
        } else if (rc >= 0) {
                CERROR("%s: Read only %d bytes of %d\n", seq->lss_name,
                       rc, (int)sizeof(info->sti_space));
                rc = -EIO;
        }

	RETURN(rc);
}

int seq_store_init(struct lu_server_seq *seq,
                   const struct lu_env *env,
                   struct dt_device *dt)
{
        struct dt_object *dt_obj;
        struct lu_fid fid;
        const char *name;
        int rc;
        ENTRY;

        name = seq->lss_type == LUSTRE_SEQ_SERVER ?
                LUSTRE_SEQ_SRV_NAME : LUSTRE_SEQ_CTL_NAME;

        dt_obj = dt_store_open(env, dt, name, &fid);
        if (!IS_ERR(dt_obj)) {
                seq->lss_obj = dt_obj;
		rc = 0;
        } else {
                CERROR("%s: Can't find \"%s\" obj %d\n",
		       seq->lss_name, name, (int)PTR_ERR(dt_obj));
                rc = PTR_ERR(dt_obj);
        }

        RETURN(rc);
}

void seq_store_fini(struct lu_server_seq *seq,
                    const struct lu_env *env)
{
        ENTRY;

        if (seq->lss_obj != NULL) {
                if (!IS_ERR(seq->lss_obj))
                        lu_object_put(env, &seq->lss_obj->do_lu);
                seq->lss_obj = NULL;
        }

        EXIT;
}
#endif
