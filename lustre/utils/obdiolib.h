/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2003 Cluster File Systems, Inc.
 *   Author: Eric Barton <eeb@clusterfs.com> 
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
#ifndef _OBDIOLIB_H_
#define _OBDIOLIB_H_

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>

struct obdio_conn {
        int	               oc_fd;
        uint64_t               oc_conn_addr;
        uint64_t               oc_conn_cookie;
        struct obd_ioctl_data  oc_data;
        char                   oc_buffer[8192];
};

struct obdio_barrier {
        uint64_t               ob_id;
	uint64_t               ob_oid;
        uint64_t               ob_npeers;
        uint64_t               ob_ordinal;
        uint64_t               ob_count;
};
	
extern struct obdio_conn * obdio_connect (int device);
extern void obdio_disconnect (struct obdio_conn *conn);
extern int obdio_open (struct obdio_conn *conn, uint64_t oid, 
		       struct lustre_handle *fh);
extern int obdio_close (struct obdio_conn *conn, uint64_t oid, 
			struct lustre_handle *fh);
extern int obdio_pread (struct obdio_conn *conn, uint64_t oid, 
			char *buffer, uint32_t count, uint64_t offset);
extern int obdio_pwrite (struct obdio_conn *conn, uint64_t oid, 
			 char *buffer, uint32_t count, uint64_t offset);
extern int obdio_enqueue (struct obdio_conn *conn, uint64_t oid,
			  int mode, uint64_t offset, uint32_t count,
			  struct lustre_handle *lh);
extern int obdio_cancel (struct obdio_conn *conn, struct lustre_handle *lh);
extern void *obdio_alloc_aligned_buffer (void **spacep, int size);
extern struct obdio_barrier *obdio_new_barrier (uint64_t oid, uint64_t id, int npeers) ;
extern int obdio_setup_barrier (struct obdio_conn *conn, struct obdio_barrier *b);
extern int obdio_barrier (struct obdio_conn *conn, struct obdio_barrier *b);

#endif
