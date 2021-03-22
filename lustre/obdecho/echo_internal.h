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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014 Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdecho/echo_internal.h
 */

#ifndef _ECHO_INTERNAL_H
#define _ECHO_INTERNAL_H

/* The persistent object (i.e. actually stores stuff!) */
#define ECHO_PERSISTENT_OBJID    1ULL
#define ECHO_PERSISTENT_SIZE     ((__u64)(1<<20))

/* block size to use for data verification */
#define OBD_ECHO_BLOCK_SIZE	(4<<10)

#ifdef HAVE_SERVER_SUPPORT
extern const struct obd_ops echo_obd_ops;
extern struct lu_device_type echo_srv_type;
int echo_persistent_pages_init(void);
void echo_persistent_pages_fini(void);
#endif /* HAVE_SERVER_SUPPORT */

/* mapping value to tell page is not encrypted */
#define ECHO_MAPPING_UNENCRYPTED ((void *)1)

/* debug.c */
int block_debug_setup(void *addr, int len, u64 off, u64 id);
int block_debug_check(char *who, void *addr, int len, u64 off, u64 id);

#endif
