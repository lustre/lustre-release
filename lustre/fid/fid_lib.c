/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/fid_lib.c
 *  Miscellaneous fid functions.
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
#define DEBUG_SUBSYSTEM S_FID

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd.h>
#include <lu_object.h>
#include <lustre_fid.h>

void fid_cpu_to_le(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = cpu_to_le64(fid_seq(src));
        dst->f_oid = cpu_to_le32(fid_oid(src));
        dst->f_ver = cpu_to_le32(fid_ver(src));
}
EXPORT_SYMBOL(fid_cpu_to_le);

void fid_le_to_cpu(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = le64_to_cpu(fid_seq(src));
        dst->f_oid = le32_to_cpu(fid_oid(src));
        dst->f_ver = le32_to_cpu(fid_ver(src));
}
EXPORT_SYMBOL(fid_le_to_cpu);

void range_cpu_to_le(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = cpu_to_le64(src->lr_start);
        dst->lr_end = cpu_to_le64(src->lr_end);
}
EXPORT_SYMBOL(range_cpu_to_le);

void range_le_to_cpu(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = le64_to_cpu(src->lr_start);
        dst->lr_end = le64_to_cpu(src->lr_end);
}
EXPORT_SYMBOL(range_le_to_cpu);
