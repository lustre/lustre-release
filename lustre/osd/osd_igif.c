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
 * lustre/osd/osd_igif.c
 *
 * igif (compatibility fids) support
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/* fid stuff */
#include <lustre/lustre_idl.h>

/* struct osd_inode_id */
#include "osd_oi.h"
#include "osd_igif.h"

void lu_igif_to_id(const struct lu_fid *fid, struct osd_inode_id *id)
{
        LASSERT(fid_is_igif(fid));
        id->oii_ino = lu_igif_ino(fid);
        id->oii_gen = lu_igif_gen(fid);
}

void lu_igif_build(struct lu_fid *fid, __u32 ino, __u32 gen)
{
        fid->f_seq = ino;
        fid->f_oid = gen;
        fid->f_ver = 0;
        LASSERT(fid_is_igif(fid));
}
