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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
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
 * lustre/fid/fid_lib.c
 *
 * Miscellaneous fid functions.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
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
 * Normal FID:        seq:64 [2^33,2^64-1]      oid:32          ver:32
 * IGIF      :        0:32, ino:32              gen:32          0:32
 * IDIF      :        0:31, 1:1, ost-index:16,  objd:48         0:32
 * </pre>
 *
 * The first 0x400 sequences of normal FID are reserved for special purpose.
 * FID_SEQ_START + 1 is for local file id generation.
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
        CLASSERT(sizeof(*src) ==
                 sizeof(src->lr_start) +
                 sizeof(src->lr_end) +
                 sizeof(src->lr_padding));
        dst->lr_start = cpu_to_le64(src->lr_start);
        dst->lr_end = cpu_to_le64(src->lr_end);
}
EXPORT_SYMBOL(range_cpu_to_le);

void range_le_to_cpu(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof(*src) ==
                 sizeof(src->lr_start) +
                 sizeof(src->lr_end) +
                 sizeof(src->lr_padding));
        dst->lr_start = le64_to_cpu(src->lr_start);
        dst->lr_end = le64_to_cpu(src->lr_end);
}
EXPORT_SYMBOL(range_le_to_cpu);

#ifdef __KERNEL__
void range_cpu_to_be(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof(*src) ==
                 sizeof(src->lr_start) +
                 sizeof(src->lr_end) +
                 sizeof(src->lr_padding));
        dst->lr_start = cpu_to_be64(src->lr_start);
        dst->lr_end = cpu_to_be64(src->lr_end);
}
EXPORT_SYMBOL(range_cpu_to_be);

void range_be_to_cpu(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof(*src) ==
                 sizeof(src->lr_start) +
                 sizeof(src->lr_end) +
                 sizeof(src->lr_padding));
        dst->lr_start = be64_to_cpu(src->lr_start);
        dst->lr_end = be64_to_cpu(src->lr_end);
}
EXPORT_SYMBOL(range_be_to_cpu);

#endif
