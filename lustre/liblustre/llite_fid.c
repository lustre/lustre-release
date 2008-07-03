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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#ifdef HAVE_XTIO_H
#include <xtio.h>
#endif
#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#ifdef HAVE_FILE_H
#include <file.h>
#endif

/* both sys/queue.h (libsysio require it) and portals/lists.h have definition
 * of 'LIST_HEAD'. undef it to suppress warnings
 */
#undef LIST_HEAD
#include <lnet/lnetctl.h>     /* needed for parse_dump */

#include "lutil.h"
#include "llite_lib.h"
#include <lustre_ver.h>
#include <lustre_fid.h>

/* build inode number on passed @fid */
unsigned long llu_fid_build_ino(struct llu_sb_info *sbi,
                                struct lu_fid *fid)
{
        unsigned long ino;
        ENTRY;

        if (fid_is_igif(fid)) {
                ino = lu_igif_ino(fid);
                RETURN(ino);
        }

        ino = fid_flatten(fid);

        if (unlikely(ino == 0))
                /* the first result ino is 0xFFC001, so this is rarely used */
                ino = 0xffbcde;
        ino = ino | 0x80000000;
        RETURN(ino);
}
