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
#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/types.h>

/*
 * Convert server error code to client format. Error codes are from
 * Linux errno.h, so for Linux client---identity.
 */
int convert_server_error(__u64 ecode)
{
	return ecode;
}
EXPORT_SYMBOL(convert_server_error);

/*
 * convert <fcntl.h> flag from client to server.
 */
int convert_client_oflag(int cflag, int *result)
{
        *result = cflag;
	return 0;
}
EXPORT_SYMBOL(convert_client_oflag);

void cfs_stack_trace_fill(struct cfs_stack_trace *trace)
{}

EXPORT_SYMBOL(cfs_stack_trace_fill);

void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no)
{
        return NULL;
}
EXPORT_SYMBOL(cfs_stack_trace_frame);

