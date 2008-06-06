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

/* Build inode number on passed @fid */
ino_t ll_fid_build_ino(struct ll_sb_info *sbi,
                       struct lu_fid *fid)
{
        ino_t ino;
        ENTRY;

        if (fid_is_igif(fid)) {
                ino = lu_igif_ino(fid);
                RETURN(ino);
        }

        /*
         * Very stupid and having many downsides inode allocation algorithm
         * based on fid.
         */
        ino = fid_flatten(fid);
        ino = ino & 0x7fffffff;

        if (unlikely(ino == 0))
                /* the first result ino is 0xFFC001, so this is rarely used */
                ino = 0xffbcde; 
        RETURN(ino);
}
