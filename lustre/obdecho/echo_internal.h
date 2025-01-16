/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014 Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
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
