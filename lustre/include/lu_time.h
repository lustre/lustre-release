/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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
 *
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
