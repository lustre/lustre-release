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

#include <lustre_fid.h>
#include <lustre_lite.h>
#include <lustre_ha.h>
#include <lustre_ver.h>
#include <lustre_dlm.h>
#include <lustre_disk.h>
#include "llite_internal.h"

static int ll_fid_alloc(struct obd_export *exp, struct lu_fid *fid,
                        struct lu_placement_hint *hint)
{
        int rc;
        ENTRY;

        rc = obd_fid_alloc(exp, fid, hint);
        if (rc) {
                CERROR("cannot allocate new fid, rc %d\n", rc);
                RETURN(rc);
        }

        LASSERT(fid_is_sane(fid));
        RETURN(rc);
}

/* allocates passed fid, that is assigns f_num and f_seq to the @fid */
int ll_fid_md_alloc(struct ll_sb_info *sbi, struct lu_fid *fid,
                    struct lu_placement_hint *hint)
{
        ENTRY;
        RETURN(ll_fid_alloc(sbi->ll_md_exp, fid, hint));
}

/* allocates passed fid, that is assigns f_num and f_seq to the @fid */
int ll_fid_dt_alloc(struct ll_sb_info *sbi, struct lu_fid *fid,
                    struct lu_placement_hint *hint)
{
        ENTRY;
        RETURN(ll_fid_alloc(sbi->ll_dt_exp, fid, hint));
}

static int ll_fid_init(struct obd_export *exp)
{
        int rc;
        ENTRY;

        rc = obd_fid_init(exp);
        if (rc) {
                CERROR("cannot initialize FIDs framework, "
                       "rc %d\n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}

int ll_fid_md_init(struct ll_sb_info *sbi)
{
        ENTRY;
        RETURN(ll_fid_init(sbi->ll_md_exp));
}

int ll_fid_dt_init(struct ll_sb_info *sbi)
{
#if 0
        ENTRY;
        RETURN(ll_fid_init(sbi->ll_dt_exp));
#endif
        /* XXX: enable this again when OSD is starting sequence-management
         * service. */
        ENTRY;
        RETURN(0);
}

static int ll_fid_fini(struct obd_export *exp)
{
        int rc;
        ENTRY;

        rc = obd_fid_fini(exp);
        if (rc) {
                CERROR("cannot finalize FIDs framework, "
                       "rc %d\n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}

int ll_fid_md_fini(struct ll_sb_info *sbi)
{
        ENTRY;
        RETURN(ll_fid_fini(sbi->ll_md_exp));
}

int ll_fid_dt_fini(struct ll_sb_info *sbi)
{
        ENTRY;
        RETURN(ll_fid_fini(sbi->ll_dt_exp));
}

/* build inode number on passed @fid */
ino_t ll_fid_build_ino(struct ll_sb_info *sbi,
                       struct lu_fid *fid)
{
        ino_t ino;
        ENTRY;

        /* very stupid and having many downsides inode allocation algorithm
         * based on fid. */
        ino = (fid_seq(fid) - 1) * LUSTRE_SEQ_WIDTH + fid_oid(fid);
        RETURN(ino);
}
