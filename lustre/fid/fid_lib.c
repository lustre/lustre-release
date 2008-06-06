/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/fid_lib.c
 *  Miscellaneous fid functions.
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *           Yury Umanets <umka@clusterfs.com>
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

/**
 * A cluster-wide range from which fid-sequences are granted to servers and
 * then clients.
 *
 * Fid namespace:
 * <pre>
 * Normal FID:        seq:64 [2^32,2^64-1]      oid:32          ver:32
 * IGIF      :        0:33, ino:31              gen:32          0:32
 * IDIF      :        0:32, 1:1, ost-index:15,  objd:48         0:32
 * </pre>
 *
 * The first 0x400 sequences of normal FID are reserved for special purpose.
 */
const struct lu_range LUSTRE_SEQ_SPACE_RANGE = {
        FID_SEQ_START + 0x400ULL,
        (__u64)~0ULL
};
EXPORT_SYMBOL(LUSTRE_SEQ_SPACE_RANGE);

/* Zero range, used for init and other purposes. */
const struct lu_range LUSTRE_SEQ_ZERO_RANGE = {
        0,
        0
};
EXPORT_SYMBOL(LUSTRE_SEQ_ZERO_RANGE);

/* Lustre Big Fs Lock fid. */
const struct lu_fid LUSTRE_BFL_FID = { .f_seq = 0x0000000000000003,
                                       .f_oid = 0x0000000000000001,
                                       .f_ver = 0x0000000000000000 };
EXPORT_SYMBOL(LUSTRE_BFL_FID);

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

#ifdef __KERNEL__
void range_cpu_to_be(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = cpu_to_be64(src->lr_start);
        dst->lr_end = cpu_to_be64(src->lr_end);
}
EXPORT_SYMBOL(range_cpu_to_be);

void range_be_to_cpu(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = be64_to_cpu(src->lr_start);
        dst->lr_end = be64_to_cpu(src->lr_end);
}
EXPORT_SYMBOL(range_be_to_cpu);

#endif
