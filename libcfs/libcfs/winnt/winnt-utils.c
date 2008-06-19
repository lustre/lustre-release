/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or modify it under
 *   the terms of version 2 of the GNU General Public License as published by
 *   the Free Software Foundation. Lustre is distributed in the hope that it
 *   will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details. You should have received a
 *   copy of the GNU General Public License along with Lustre; if not, write
 *   to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
 *   USA.
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
	return cfs_error_code((NTSTATUS)ecode);
}

/*
 * convert <fcntl.h> flag from client to server.
 * 
 * nt kernel uses several members to describe the open flags
 * such as DesiredAccess/ShareAccess/CreateDisposition/CreateOptions
 * so it's better to convert when using, not here.
 */

int convert_client_oflag(int cflag, int *result)
{
    *result = 0;
	return 0;
}


int cfs_error_code(NTSTATUS Status)
{
    switch (Status) {

        case STATUS_ACCESS_DENIED:
            return (-EACCES);

        case STATUS_ACCESS_VIOLATION:
            return (-EFAULT);
    
        case STATUS_BUFFER_TOO_SMALL:
            return (-ETOOSMALL);

        case STATUS_INVALID_PARAMETER:
            return (-EINVAL);

        case STATUS_NOT_IMPLEMENTED:
        case STATUS_NOT_SUPPORTED:
            return (-EOPNOTSUPP);

        case STATUS_INVALID_ADDRESS:
        case STATUS_INVALID_ADDRESS_COMPONENT:
            return (-EADDRNOTAVAIL);

        case STATUS_NO_SUCH_DEVICE:
        case STATUS_NO_SUCH_FILE:
        case STATUS_OBJECT_NAME_NOT_FOUND:
        case STATUS_OBJECT_PATH_NOT_FOUND:  
        case STATUS_NETWORK_BUSY:
        case STATUS_INVALID_NETWORK_RESPONSE:
        case STATUS_UNEXPECTED_NETWORK_ERROR:
            return (-ENETDOWN);

        case STATUS_BAD_NETWORK_PATH:
        case STATUS_NETWORK_UNREACHABLE:
        case STATUS_PROTOCOL_UNREACHABLE:     
            return (-ENETUNREACH);

        case STATUS_LOCAL_DISCONNECT:
        case STATUS_TRANSACTION_ABORTED:
        case STATUS_CONNECTION_ABORTED:
            return (-ECONNABORTED);

        case STATUS_REMOTE_DISCONNECT:
        case STATUS_LINK_FAILED:
        case STATUS_CONNECTION_DISCONNECTED:
        case STATUS_CONNECTION_RESET:
        case STATUS_PORT_UNREACHABLE:
            return (-ECONNRESET);

        case STATUS_PAGEFILE_QUOTA:
        case STATUS_NO_MEMORY:
        case STATUS_CONFLICTING_ADDRESSES:
        case STATUS_QUOTA_EXCEEDED:
        case STATUS_TOO_MANY_PAGING_FILES:
        case STATUS_INSUFFICIENT_RESOURCES:
        case STATUS_WORKING_SET_QUOTA:
        case STATUS_COMMITMENT_LIMIT:
        case STATUS_TOO_MANY_ADDRESSES:
        case STATUS_REMOTE_RESOURCES:
            return (-ENOBUFS);

        case STATUS_INVALID_CONNECTION:
            return (-ENOTCONN);

        case STATUS_PIPE_DISCONNECTED:
            return (-ESHUTDOWN);

        case STATUS_TIMEOUT:
        case STATUS_IO_TIMEOUT:
        case STATUS_LINK_TIMEOUT:
            return (-ETIMEDOUT);

        case STATUS_REMOTE_NOT_LISTENING:
        case STATUS_CONNECTION_REFUSED:
            return (-ECONNREFUSED);

        case STATUS_HOST_UNREACHABLE:
            return (-EHOSTUNREACH);

        case STATUS_PENDING:
        case STATUS_DEVICE_NOT_READY:
            return (-EAGAIN);

        case STATUS_CANCELLED:
        case STATUS_REQUEST_ABORTED:
            return (-EINTR);

        case STATUS_BUFFER_OVERFLOW:
        case STATUS_INVALID_BUFFER_SIZE:
            return (-EMSGSIZE);

    }

    if (NT_SUCCESS(Status)) 
        return 0;

    return (-EINVAL);
}


void cfs_stack_trace_fill(struct cfs_stack_trace *trace)
{
}

void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no)
{
    return NULL;
}
