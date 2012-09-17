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
 * Copyright (c) 2012, Intel, Inc.
 * Use is subject to license terms.
 *
 * lustre/mdt/mdt_lvb.c
 *
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

/* Called with res->lr_lvb_sem held */
static int mdt_lvbo_init(struct ldlm_resource *res)
{
	return 0;
}

static int mdt_lvbo_size(struct ldlm_lock *lock)
{
	return 0;
}

static int mdt_lvbo_fill(struct ldlm_lock *lock, void *lvb, int lvblen)
{
	return 0;
}

struct ldlm_valblock_ops mdt_lvbo = {
	lvbo_init:	mdt_lvbo_init,
	lvbo_size: 	mdt_lvbo_size,
	lvbo_fill: 	mdt_lvbo_fill
};
