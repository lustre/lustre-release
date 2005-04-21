/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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

#include "lonal.h"

ptl_nal_t klonal_nal = {
        .nal_name       = "lo",
        .nal_type       = LONAL,
        .nal_startup    = klonal_startup,
        .nal_shutdown   = klonal_shutdown,
        .nal_send       = klonal_send,
        .nal_send_pages = klonal_send_pages,
        .nal_recv       = klonal_recv,
        .nal_recv_pages = klonal_recv_pages,
};

int     klonal_instanced;

void
klonal_shutdown(ptl_ni_t *ni)
{
	CDEBUG (D_NET, "shutdown\n");
	LASSERT (ni->ni_nal == &klonal_nal);
        LASSERT (klonal_instanced);
        
        klonal_instanced = 0;
	PORTAL_MODULE_UNUSE;
}

ptl_err_t
klonal_startup (ptl_ni_t *ni, char **interfaces)
{
	LASSERT (ni->ni_nal == &klonal_nal);

        if (klonal_instanced)  {
                /* Multiple instances of the loopback NI is never right */
                CERROR ("Only 1 instance supported\n");
                return PTL_FAIL;
        }

	CDEBUG (D_NET, "start\n");

#warning fixme
        ni->ni_nid = 0;
        klonal_instanced = 1;

	PORTAL_MODULE_USE;
	return (PTL_OK);
}

void __exit
klonal_finalise (void)
{
	ptl_unregister_nal(&klonal_nal);
}

static int __init
klonal_initialise (void)
{
	int   rc;

	rc = ptl_register_nal(&klonal_nal);
	if (rc != PTL_OK) {
		CERROR("Can't register LONAL: %d\n", rc);
		return (-ENOMEM);		/* or something... */
	}

	return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Loopback NAL v0.01");
MODULE_LICENSE("GPL");

module_init (klonal_initialise);
module_exit (klonal_finalise);
