/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/linux/lprocfs_status.h
 *
 * Top level header file for LProc SNMP
 *
 * Author: Hariharan Thantry thantry@users.sourceforge.net
 */
#ifndef _LINUX_LPROCFS_SNMP_H
#define _LINUX_LPROCFS_SNMP_H

#ifndef _LPROCFS_SNMP_H
#error Do not #include this file directly. #include <lprocfs_status.h> instead
#endif

#ifdef __KERNEL__
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/autoconf.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/smp.h>
#include <linux/rwsem.h>
#include <libcfs/kp30.h>

# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/statfs.h>
# else 
#  define kstatfs statfs
# endif

#else 
#  define kstatfs statfs
#endif

#endif /* LPROCFS_SNMP_H */
