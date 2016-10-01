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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_RPC


#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_req_layout.h>

#include "ptlrpc_internal.h"

extern spinlock_t ptlrpc_last_xid_lock;
#if RS_DEBUG
extern spinlock_t ptlrpc_rs_debug_lock;
#endif

static __init int ptlrpc_init(void)
{
	int rc;

	ENTRY;

	lustre_assert_wire_constants();
#if RS_DEBUG
	spin_lock_init(&ptlrpc_rs_debug_lock);
#endif
	INIT_LIST_HEAD(&ptlrpc_all_services);
	mutex_init(&ptlrpc_all_services_mutex);
	mutex_init(&pinger_mutex);
	mutex_init(&ptlrpcd_mutex);
	ptlrpc_init_xid();

	rc = req_layout_init();
	if (rc)
		RETURN(rc);

	rc = tgt_mod_init();
	if (rc)
		GOTO(err_layout, rc);

	rc = ptlrpc_hr_init();
	if (rc)
		GOTO(err_tgt, rc);

	rc = ptlrpc_request_cache_init();
	if (rc)
		GOTO(err_hr, rc);

	rc = ptlrpc_init_portals();
	if (rc)
		GOTO(err_cache, rc);

	rc = ptlrpc_connection_init();
	if (rc)
		GOTO(err_portals, rc);

	ptlrpc_put_connection_superhack = ptlrpc_connection_put;

	rc = ptlrpc_start_pinger();
	if (rc)
		GOTO(err_conn, rc);

	rc = ldlm_init();
	if (rc)
		GOTO(err_pinger, rc);

	rc = sptlrpc_init();
	if (rc)
		GOTO(err_ldlm, rc);

	rc = ptlrpc_nrs_init();
	if (rc)
		GOTO(err_sptlrpc, rc);

	rc = nodemap_mod_init();
	if (rc)
		GOTO(err_nrs, rc);

	RETURN(0);
err_nrs:
	ptlrpc_nrs_fini();
err_sptlrpc:
	sptlrpc_fini();
err_ldlm:
	ldlm_exit();
err_pinger:
	ptlrpc_stop_pinger();
err_conn:
	ptlrpc_connection_fini();
err_portals:
	ptlrpc_exit_portals();
err_cache:
	ptlrpc_request_cache_fini();
err_hr:
	ptlrpc_hr_fini();
err_tgt:
	tgt_mod_exit();
err_layout:
	req_layout_fini();
	return rc;
}

static void __exit ptlrpc_exit(void)
{
	nodemap_mod_exit();
	ptlrpc_nrs_fini();
	sptlrpc_fini();
	ldlm_exit();
	ptlrpc_stop_pinger();
	ptlrpc_exit_portals();
	ptlrpc_request_cache_fini();
	ptlrpc_hr_fini();
	ptlrpc_connection_fini();
	tgt_mod_exit();
	req_layout_fini();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Request Processor and Lock Management");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);
