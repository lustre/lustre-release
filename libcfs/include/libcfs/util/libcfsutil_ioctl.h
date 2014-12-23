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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/util/libcfsutil_ioctl.h
 *
 * Utility functions for calling ioctls.
 *
 */

/* FIXME - rename these to libcfs_ */

int libcfs_ioctl_pack(struct libcfs_ioctl_data *data, char **pbuf, int max);
void libcfs_ioctl_unpack(struct libcfs_ioctl_data *data, char *pbuf);
typedef int (ioc_handler_t)(int dev_id, unsigned int opc, void *buf);
void set_ioc_handler(ioc_handler_t *handler);
int register_ioc_dev(int dev_id, const char * dev_name, int major, int minor);
void unregister_ioc_dev(int dev_id);
int set_ioctl_dump(char * file);
int l_ioctl(int dev_id, unsigned int opc, void *buf);
int parse_dump(char * dump_file, ioc_handler_t ioc_func);
int jt_ioc_dump(int argc, char **argv);
extern char *dump_filename;
int dump(int dev_id, unsigned int opc, void *buf);
