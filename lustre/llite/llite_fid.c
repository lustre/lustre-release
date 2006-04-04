/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2002-2005 Cluster File Systems, Inc.
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
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/version.h>

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_ver.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_disk.h>
#include "llite_internal.h"

/* allocates passed fid, that is assigns f_num and f_seq to the @fid */
int ll_fid_alloc(struct ll_sb_info *sbi, struct lu_fid *fid)
{
    ENTRY;
    RETURN(0);
}

