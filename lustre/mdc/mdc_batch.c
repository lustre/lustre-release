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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2020, 2022, DDN Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustre/mdc/mdc_batch.c
 *
 * Batch Metadata Updating on the client (MDC)
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/module.h>
#include <lustre_acl.h>

#include "mdc_internal.h"


static md_update_pack_t mdc_update_packers[MD_OP_MAX];

static object_update_interpret_t mdc_update_interpreters[MD_OP_MAX];

int mdc_batch_add(struct obd_export *exp, struct lu_batch *bh,
		  struct md_op_item *item)
{
	enum md_item_opcode opc = item->mop_opc;

	ENTRY;

	if (opc >= MD_OP_MAX || mdc_update_packers[opc] == NULL ||
	    mdc_update_interpreters[opc] == NULL) {
		CERROR("%s: unexpected opcode %d\n",
		       exp->exp_obd->obd_name, opc);
		RETURN(-EFAULT);
	}

	RETURN(cli_batch_add(exp, bh, item, mdc_update_packers[opc],
			     mdc_update_interpreters[opc]));
}
