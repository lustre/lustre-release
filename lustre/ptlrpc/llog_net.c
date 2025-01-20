// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <libcfs/libcfs.h>
#include <obd_class.h>
#include <lustre_log.h>

int llog_initiator_connect(struct llog_ctxt *ctxt)
{
	struct obd_import *new_imp;

	ENTRY;

	LASSERT(ctxt);
	new_imp = ctxt->loc_obd->u.cli.cl_import;
	LASSERTF(!ctxt->loc_imp || ctxt->loc_imp == new_imp,
		 "%px - %px\n", ctxt->loc_imp, new_imp);
	mutex_lock(&ctxt->loc_mutex);
	if (ctxt->loc_imp != new_imp) {
		if (ctxt->loc_imp)
			class_import_put(ctxt->loc_imp);
		ctxt->loc_imp = class_import_get(new_imp);
	}
	mutex_unlock(&ctxt->loc_mutex);
	RETURN(0);
}
EXPORT_SYMBOL(llog_initiator_connect);
