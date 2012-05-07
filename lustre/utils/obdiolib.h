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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _OBDIOLIB_H_
#define _OBDIOLIB_H_

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <obd_class.h>

struct obdio_conn {
        int                    oc_fd;
        __u32                  oc_device;
        struct obd_ioctl_data  oc_data;
        char                   oc_buffer[8192];
};

struct obdio_barrier {
        __u64                  ob_id;
        __u64                  ob_oid;
        __u64                  ob_npeers;
        __u64                  ob_ordinal;
        __u64                  ob_count;
};

extern struct obdio_conn *obdio_connect(int device);
extern void obdio_disconnect(struct obdio_conn *conn, int flags);
extern int obdio_open(struct obdio_conn *conn, __u64 oid,
                      struct lustre_handle *fh);
extern int obdio_close(struct obdio_conn *conn, __u64 oid,
                       struct lustre_handle *fh);
extern int obdio_pread(struct obdio_conn *conn, __u64 oid,
                       void *buffer, __u32 count, __u64 offset);
extern int obdio_pwrite(struct obdio_conn *conn, __u64 oid,
                        void *buffer, __u32 count, __u64 offset);
extern int obdio_enqueue(struct obdio_conn *conn, __u64 oid,
                         int mode, __u64 offset, __u32 count,
                         struct lustre_handle *lh);
extern int obdio_cancel(struct obdio_conn *conn, struct lustre_handle *lh);
extern void *obdio_alloc_aligned_buffer(void **spacep, int size);
extern struct obdio_barrier *obdio_new_barrier(__u64 oid, __u64 id,
                                               int npeers);
extern int obdio_setup_barrier(struct obdio_conn *conn,struct obdio_barrier *b);
extern int obdio_barrier(struct obdio_conn *conn, struct obdio_barrier *b);

#endif
