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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LNET_LINUX_LNET_H__
#define __LNET_LINUX_LNET_H__

#ifndef __LNET_H__
#error Do not #include this file directly. #include <lnet/lnet.h> instead
#endif

#ifdef __KERNEL__
#include <lnet/types.h>

int
ks_query_iovs_length(struct iovec  *iov, int niov);

int
ks_query_kiovs_length(lnet_kiov_t *kiov, int nkiov);

int
ks_send_buf(ks_tconn_t *, char *, int, int, int);

int
ks_recv_buf(ks_tconn_t *, char *, int, int, int);

int
ks_send_iovs(ks_tconn_t *, struct iovec *, int, int, int);

int
ks_recv_iovs(ks_tconn_t *, struct iovec *, int, int, int);

int
ks_send_kiovs(ks_tconn_t *, lnet_kiov_t *, int, int, int);

int
ks_recv_kiovs(ks_tconn_t *, lnet_kiov_t *, int, int, int);

#endif /* __KERNEL__ */
#endif
