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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lustre/llite/llite_fid.c
 *
 * Lustre Light Super operations
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

        if (unlikely(ino == 0))
                /* the first result ino is 0xFFC001, so this is rarely used */
                ino = 0xffbcde; 
        ino = ino | 0x80000000;
        RETURN(ino);
}
