/*
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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 */

#include <obd.h>
#include <lquota.h>

#ifndef _LQUOTA_INTERNAL_H
#define _LQUOTA_INTERNAL_H

#define QTYPE_NAME(qtype) ((qtype) == USRQUOTA ? "usr" : "grp")

/* lquota_lib.c */
struct dt_object *acct_obj_lookup(const struct lu_env *, struct dt_device *,
                                  __u32);

/* lproc_quota.c */
extern struct file_operations lprocfs_quota_seq_fops;

#endif /* _LQUOTA_INTERNAL_H */
