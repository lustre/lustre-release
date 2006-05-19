/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/version.h>

#include <lustre_lite.h>
#include <lustre_ha.h>
#include <lustre_ver.h>
#include <lustre_dlm.h>
#include <lustre_disk.h>
#include "llite_internal.h"

static int ll_fid_alloc(struct obd_export *exp, struct lu_fid *fid,
                        struct placement_hint *hint)
{
        int rc;
        ENTRY;

        rc = obd_fid_alloc(exp, fid, hint);
        if (rc) {
                CERROR("cannot allocate new fid, rc %d\n", rc);
                RETURN(rc);
        }

        LASSERT(fid_seq(fid) != 0 && fid_num(fid) != 0);
        RETURN(rc);
}

/* allocates passed fid, that is assigns f_num and f_seq to the @fid */
int ll_fid_md_alloc(struct ll_sb_info *sbi, struct lu_fid *fid,
                    struct placement_hint *hint)
{
        ENTRY;
        RETURN(ll_fid_alloc(sbi->ll_md_exp, fid, hint));
}

/* allocates passed fid, that is assigns f_num and f_seq to the @fid */
int ll_fid_dt_alloc(struct ll_sb_info *sbi, struct lu_fid *fid,
                    struct placement_hint *hint)
{
        ENTRY;
        RETURN(ll_fid_alloc(sbi->ll_dt_exp, fid, hint));
}

/* build inode number on passed @fid */
ino_t ll_fid_build_ino(struct ll_sb_info *sbi, struct lu_fid *fid)
{
        ino_t ino;
        ENTRY;

        /* very stupid and having many downsides inode allocation algorithm
         * based on fid. */
        ino = (fid_seq(fid) - 1) * LUSTRE_FID_SEQ_WIDTH + fid_oid(fid);
        RETURN(ino);
}
