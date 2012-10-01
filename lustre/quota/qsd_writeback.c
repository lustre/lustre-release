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
 * Copyright (c) 2011, 2012, Intel, Inc.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "qsd_internal.h"

/* Bump version of global or slave index copy
 *
 * \param qqi    - qsd_qtype_info
 * \param ver    - version to be bumped to
 * \param global - global or slave index copy?
 */
void qsd_bump_version(struct qsd_qtype_info *qqi, __u64 ver, bool global)
{
}

/*
 * Schedule a commit of a lquota entry
 *
 * \param  qqi   - qsd_qtype_info
 * \param  lqe   - lquota_entry
 * \param  qid   - quota id
 * \param  rec   - global or slave record to be updated to disk
 * \param  ver   - new index file version
 * \param  global- ture : master record; false : slave record
 */
void qsd_upd_schedule(struct qsd_qtype_info *qqi, struct lquota_entry *lqe,
		      union lquota_id *qid, union lquota_rec *rec, __u64 ver,
		      bool global)
{
}
