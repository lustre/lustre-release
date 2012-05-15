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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_obd.c
 *
 * Author: Andreas Dilger <adilger@whamcloud.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

static int ofd_obd_notify(struct obd_device *obd, struct obd_device *unused,
			  enum obd_notify_event ev, void *data)
{
	switch (ev) {
	case OBD_NOTIFY_CONFIG:
		LASSERT(obd->obd_no_conn);
		cfs_spin_lock(&obd->obd_dev_lock);
		obd->obd_no_conn = 0;
		cfs_spin_unlock(&obd->obd_dev_lock);
		break;
	default:
		CDEBUG(D_INFO, "%s: Unhandled notification %#x\n",
		       obd->obd_name, ev);
	}
	return 0;
}

struct obd_ops ofd_obd_ops = {
	.o_owner	  = THIS_MODULE,
	.o_notify	  = ofd_obd_notify,
};
