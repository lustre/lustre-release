/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/* Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/* This file is part of Lustre, http://www.lustre.org/
 *
 * #defines shared between socknal implementation and utilities
 */

#ifndef __UAPI_LNET_SOCKLND_H__
#define __UAPI_LNET_SOCKLND_H__

#define SOCKLND_CONN_NONE     (-1)
#define SOCKLND_CONN_ANY	0
#define SOCKLND_CONN_CONTROL	1
#define SOCKLND_CONN_BULK_IN	2
#define SOCKLND_CONN_BULK_OUT	3
#define SOCKLND_CONN_NTYPES	4

#define SOCKLND_CONN_ACK	SOCKLND_CONN_BULK_IN

#endif
