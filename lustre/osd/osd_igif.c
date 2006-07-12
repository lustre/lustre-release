/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/osd/osd_igif.c
 *  igif (compatibility fids) support
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/* fid stuff */
#include <lustre/lustre_idl.h>

/* struct osd_inode_id */
#include "osd_oi.h"
#include "osd_igif.h"

int lu_fid_is_igif(const struct lu_fid *fid)
{
        return fid_seq(fid) == LUSTRE_ROOT_FID_SEQ;
}

void lu_igif_to_id(const struct lu_fid *fid, struct osd_inode_id *id)
{
        LASSERT(lu_fid_is_igif(fid));
        id->oii_ino = lu_igif_ino(fid);
        id->oii_gen = lu_igif_gen(fid);
}

__u32 lu_igif_ino(const struct lu_fid *fid)
{
        LASSERT(lu_fid_is_igif(fid));
        return fid_oid(fid);
}

__u32 lu_igif_gen(const struct lu_fid *fid)
{
        LASSERT(lu_fid_is_igif(fid));
        return fid_ver(fid);
}

void lu_igif_build(struct lu_fid *fid, __u32 ino, __u32 gen)
{
        fid->f_seq = LUSTRE_ROOT_FID_SEQ;
        fid->f_oid = ino;
        fid->f_ver = gen;
        LASSERT(lu_fid_is_igif(fid));
}
