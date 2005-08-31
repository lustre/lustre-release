/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 * Author: Phil Schwan <phil@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Lustre; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * miscellaneous libcfs stuff
 */
#define DEBUG_SUBSYSTEM S_PORTALS
#include <lnet/types.h>

/*
 * Convert server error code to client format. Error codes are from
 * Linux errno.h, so for Linux client---identity.
 */
int convert_server_error(__u64 ecode)
{
	return ecode;
}

/*
 * convert <fcntl.h> flag from client to server.
 */
int convert_client_oflag(int cflag)
{
	return cflag;
}


