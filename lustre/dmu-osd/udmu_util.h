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
 * lustre/dmu/udmu.c
 * Module that interacts with the ZFS DMU and provides an abstraction
 * to the rest of Lustre.
 *
 * Author: Manoj Joseph <manoj.joseph@sun.com>
 */

#ifndef _DMU_UTIL_H
#define _DMU_UTIL_H

#ifdef DMU_OSD

#ifdef __cplusplus
extern "C" {
#endif

int udmu_util_lookup(udmu_objset_t *uos, dmu_buf_t *parent_db,
                     const char *name, dmu_buf_t **new_dbp, void *tag);

int udmu_util_create(udmu_objset_t *uos, dmu_buf_t *parent_db,
                     const char *name, dmu_buf_t **new_db, void *tag);

int udmu_util_mkdir(udmu_objset_t *uos, dmu_buf_t *parent_db,
                    const char *name, dmu_buf_t **new_db, void *tag);

int udmu_util_setattr(udmu_objset_t *uos, dmu_buf_t *db, vnattr_t *va);

int udmu_util_write(udmu_objset_t *uos, dmu_buf_t *db,
                    uint64_t offset, uint64_t len, void *buf);

#ifdef __cplusplus
}
#endif

#endif /* DMU_OSD */

#endif /* _DMU_UTIL_H */
