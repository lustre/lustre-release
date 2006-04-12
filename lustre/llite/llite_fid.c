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

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_ver.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_disk.h>
#include "llite_internal.h"

/* allocates passed fid, that is assigns f_num and f_seq to the @fid */
int ll_fid_alloc(struct ll_sb_info *sbi, struct lu_fid *fid)
{
        ENTRY;

        spin_lock(&sbi->ll_fid_lock);
        if (sbi->ll_md_fid.f_oid < LUSTRE_FID_SEQ_WIDTH) {
                sbi->ll_md_fid.f_oid += 1;
                *fid = sbi->ll_md_fid;
        } else {
                CERROR("sequence is exhausted. Switching to "
                       "new one is not yet implemented\n");
                LBUG();
        }
        spin_unlock(&sbi->ll_fid_lock);
        
        RETURN(0);
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
