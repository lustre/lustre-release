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
 * http://www.gnu.org/licenses/gpl-2.0.htm
 *
 * GPL HEADER END
 */
/*
 * libcfs/libcfs/posix/posix-tracefile.h
 *
 * Userspace debugging-tracing
 */

#ifndef __LIBCFS_POSIX_TRACEFILE_H__
#define __LIBCFS_POSIX_TRACEFILE_H__

/**
 * three types of trace_data in linux
 * posix need to max of available types to have 
 * type checking happy.
 */
typedef enum {
	CFS_TCD_TYPE_PROC = 0,
	CFS_TCD_TYPE_SOFTIRQ,
	CFS_TCD_TYPE_IRQ,
	CFS_TCD_TYPE_MAX
} cfs_trace_buf_type_t;

#endif
