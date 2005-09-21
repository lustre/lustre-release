/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
 *   Author: Eric Barton <eeb@bartonsoftware.com>
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
 *
 */

#include "ptllnd.h"

lnd_t               the_ptllnd = {
        .lnd_type       = PTLLND,
        .lnd_startup    = ptllnd_startup,
        .lnd_shutdown   = ptllnd_shutdown,
        .lnd_send       = ptllnd_send,
        .lnd_recv       = ptllnd_recv,
        .lnd_eager_recv = ptllnd_eager_recv,
};


void ptllnd_shutdown(struct lnet_ni *ni)
{
}

int ptllnd_startup(struct lnet_ni *ni)
{
	/* could get limits from portals I guess... */
	ni->ni_maxtxcredits = 
	ni->ni_peertxcredits = 1000;

	return 0;
}

