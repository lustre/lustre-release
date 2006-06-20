/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2006 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_LMV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/div64.h>
#include <linux/seq_file.h>
#else
#include <liblustre.h>
#endif

#include <lustre/lustre_idl.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "lmv_internal.h"

int lmv_fld_lookup(struct obd_device *obd, const struct lu_fid *fid)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        __u64 mds;
        int rc;
        ENTRY;

        LASSERT(fid_is_sane(fid));
        rc = fld_client_lookup(&lmv->lmv_fld, fid_seq(fid), &mds);
        if (rc) {
                CERROR("can't find mds by seq "LPU64", rc %d\n",
                       fid_seq(fid), rc);
                RETURN(rc);
        }
        CWARN("LMV: got MDS "LPU64" for sequence: "LPU64"\n",
              mds, fid_seq(fid));
        if (mds >= lmv->desc.ld_tgt_count || mds < 0) {
                CERROR("Got invalid mdsno: %llu (max: %d)\n",
                       mds, lmv->desc.ld_tgt_count);
                mds = (__u64)-EINVAL;
        }
        RETURN((int)mds);
}
