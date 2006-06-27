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
int
seq_store_write(struct lu_server_seq *seq,
		const struct lu_context *ctx)
{
	int rc = 0;
	ENTRY;

	RETURN(rc);
}

int
seq_store_read(struct lu_server_seq *seq,
	       const struct lu_context *ctx)
{
	int rc = -ENODATA;
	ENTRY;
	
	RETURN(rc);
}

int
seq_store_init(struct lu_server_seq *seq,
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

void
seq_store_fini(struct lu_server_seq *seq,
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
