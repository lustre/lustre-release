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
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 *
 * Copyright 2015 Cray Inc, all rights reserved.
 * Author: Ben Evans.
 *
 * Define obdo associated functions
 *   obdo:  OBject Device o...
 */

#ifndef _LUSTRE_OBDO_H_
#define _LUSTRE_OBDO_H_

#include <lustre/lustre_idl.h>

/**
 * Dumper for struct obdo
 */
void dump_obdo(struct obdo *oa);

/**
 * Create an obdo to send over the wire
 */
static inline void lustre_set_wire_obdo(const struct obd_connect_data *ocd,
					struct obdo *wobdo,
					const struct obdo *lobdo)
{
	*wobdo = *lobdo;
	wobdo->o_flags &= ~OBD_FL_LOCAL_MASK;
	if (ocd == NULL)
		return;

	if (unlikely(!(ocd->ocd_connect_flags & OBD_CONNECT_FID)) &&
	    fid_seq_is_echo(ostid_seq(&lobdo->o_oi))) {
		/* Currently OBD_FL_OSTID will only be used when 2.4 echo
		 * client communicate with pre-2.4 server */
		wobdo->o_oi.oi.oi_id = fid_oid(&lobdo->o_oi.oi_fid);
		wobdo->o_oi.oi.oi_seq = fid_seq(&lobdo->o_oi.oi_fid);
	}
}

/**
 * Create a local obdo from a wire based odbo
 */
static inline void lustre_get_wire_obdo(const struct obd_connect_data *ocd,
					struct obdo *lobdo,
					const struct obdo *wobdo)
{
	__u32 local_flags = 0;

	if (lobdo->o_valid & OBD_MD_FLFLAGS)
		local_flags = lobdo->o_flags & OBD_FL_LOCAL_MASK;

	*lobdo = *wobdo;
	if (local_flags != 0) {
		lobdo->o_valid |= OBD_MD_FLFLAGS;
		lobdo->o_flags &= ~OBD_FL_LOCAL_MASK;
		lobdo->o_flags |= local_flags;
	}
	if (ocd == NULL)
		return;

	if (unlikely(!(ocd->ocd_connect_flags & OBD_CONNECT_FID)) &&
	    fid_seq_is_echo(wobdo->o_oi.oi.oi_seq)) {
		/* see above */
		lobdo->o_oi.oi_fid.f_seq = wobdo->o_oi.oi.oi_seq;
		lobdo->o_oi.oi_fid.f_oid = wobdo->o_oi.oi.oi_id;
		lobdo->o_oi.oi_fid.f_ver = 0;
	}
}

#endif
