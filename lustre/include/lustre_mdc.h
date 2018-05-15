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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre_mdc.h
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_MDC_H
#define _LUSTRE_MDC_H

/** \defgroup mdc mdc
 *
 * @{
 */

#include <linux/fs.h>
#include <linux/dcache.h>
#ifdef CONFIG_FS_POSIX_ACL
# include <linux/posix_acl_xattr.h>
#endif /* CONFIG_FS_POSIX_ACL */
#include <lustre_handles.h>
#include <lustre_intent.h>
#include <libcfs/libcfs.h>
#include <obd_class.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_dlm.h>
#include <lustre_export.h>

struct ptlrpc_client;
struct obd_export;
struct ptlrpc_request;
struct obd_device;

static inline void mdc_get_mod_rpc_slot(struct ptlrpc_request *req,
					struct lookup_intent *it)
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	__u32 opc;
	__u16 tag;

	opc = lustre_msg_get_opc(req->rq_reqmsg);
	tag = obd_get_mod_rpc_slot(cli, opc, it);
	lustre_msg_set_tag(req->rq_reqmsg, tag);
}

static inline void mdc_put_mod_rpc_slot(struct ptlrpc_request *req,
					struct lookup_intent *it)
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	__u32 opc;
	__u16 tag;

	opc = lustre_msg_get_opc(req->rq_reqmsg);
	tag = lustre_msg_get_tag(req->rq_reqmsg);
	obd_put_mod_rpc_slot(cli, opc, it, tag);
}


/**
 * Update the maximum possible easize.
 *
 * This value is learned from ptlrpc replies sent by the MDT.  The
 * default easize is initialized to the minimum value but allowed to
 * grow up to a single page in size if required to handle the common
 * case.
 *
 * \see client_obd::cl_default_mds_easize
 *
 * \param[in] exp	export for MDC device
 * \param[in] body	body of ptlrpc reply from MDT
 *
 */
static inline void mdc_update_max_ea_from_body(struct obd_export *exp,
					       struct mdt_body *body)
{
	if (body->mbo_valid & OBD_MD_FLMODEASIZE) {
		struct client_obd *cli = &exp->exp_obd->u.cli;
		__u32 def_easize;

		if (cli->cl_max_mds_easize < body->mbo_max_mdsize)
			cli->cl_max_mds_easize = body->mbo_max_mdsize;

		def_easize = min_t(__u32, body->mbo_max_mdsize,
				   OBD_MAX_DEFAULT_EA_SIZE);
		cli->cl_default_mds_easize = def_easize;
	}
}


/* mdc/mdc_locks.c */
int it_open_error(int phase, struct lookup_intent *it);

static inline bool cl_is_lov_delay_create(unsigned int flags)
{
	return  (flags & O_LOV_DELAY_CREATE_1_8) != 0 ||
		(flags & O_LOV_DELAY_CREATE_MASK) == O_LOV_DELAY_CREATE_MASK;
}

static inline void cl_lov_delay_create_clear(unsigned int *flags)
{
	if ((*flags & O_LOV_DELAY_CREATE_1_8) != 0)
		*flags &= ~O_LOV_DELAY_CREATE_1_8;
	if ((*flags & O_LOV_DELAY_CREATE_MASK) == O_LOV_DELAY_CREATE_MASK)
		*flags &= ~O_LOV_DELAY_CREATE_MASK;
}

/** @} mdc */

#endif
