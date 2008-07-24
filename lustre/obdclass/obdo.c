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
 * lustre/obdclass/obdo.c
 *
 * Object Devices Class Driver
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#ifndef __KERNEL__
#include <liblustre.h>
#else
#include <obd_class.h>
#include <lustre/lustre_idl.h>
#endif

void obdo_cpy_md(struct obdo *dst, struct obdo *src, obd_flag valid)
{
#ifdef __KERNEL__
        CDEBUG(D_INODE, "src obdo "LPX64" valid "LPX64", dst obdo "LPX64"\n",
               src->o_id, src->o_valid, dst->o_id);
#endif
        if (valid & OBD_MD_FLATIME)
                dst->o_atime = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                dst->o_mtime = src->o_mtime;
        if (valid & OBD_MD_FLCTIME)
                dst->o_ctime = src->o_ctime;
        if (valid & OBD_MD_FLSIZE)
                dst->o_size = src->o_size;
        if (valid & OBD_MD_FLBLOCKS) /* allocation of space */
                dst->o_blocks = src->o_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                dst->o_blksize = src->o_blksize;
        if (valid & OBD_MD_FLTYPE)
                dst->o_mode = (dst->o_mode & ~S_IFMT) | (src->o_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                dst->o_mode = (dst->o_mode & S_IFMT) | (src->o_mode & ~S_IFMT);
        if (valid & OBD_MD_FLUID)
                dst->o_uid = src->o_uid;
        if (valid & OBD_MD_FLGID)
                dst->o_gid = src->o_gid;
        if (valid & OBD_MD_FLFLAGS)
                dst->o_flags = src->o_flags;
        if (valid & OBD_MD_FLGENER)
                dst->o_generation = src->o_generation;

        dst->o_valid |= valid;
}
EXPORT_SYMBOL(obdo_cpy_md);

void obdo_to_ioobj(struct obdo *oa, struct obd_ioobj *ioobj)
{
        ioobj->ioo_id = oa->o_id;
        if (oa->o_valid & OBD_MD_FLGROUP)
                ioobj->ioo_gr = oa->o_gr;
        else 
                ioobj->ioo_gr = 0;
        ioobj->ioo_type = oa->o_mode;
}
EXPORT_SYMBOL(obdo_to_ioobj);
