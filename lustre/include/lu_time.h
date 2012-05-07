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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lu_time.h
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LUSTRE_LU_TIME_H
#define __LUSTRE_LU_TIME_H

struct lprocfs_stats;
struct lu_env;

int  lu_time_global_init(void);
void lu_time_global_fini(void);

int  lu_time_named_init(struct lprocfs_stats **stats, const char *name,
                        cfs_proc_dir_entry_t *entry,
                        const char **names, int nr);
int  lu_time_init(struct lprocfs_stats **stats,
                  cfs_proc_dir_entry_t *entry,
                  const char **names, int nr);
void lu_time_fini(struct lprocfs_stats **stats);

void lu_lprocfs_time_start(const struct lu_env *env);
void lu_lprocfs_time_end(const struct lu_env *env,
                         struct lprocfs_stats *stats, int idx);

int lu_time_is_clean(const struct lu_env *env);

#endif /* __LUSTRE_LU_TIME_H */
