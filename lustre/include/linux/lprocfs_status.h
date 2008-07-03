/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 *   Top level header file for LProc SNMP
 *   Author: Hariharan Thantry thantry@users.sourceforge.net
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
#include <libcfs/libcfs.h>
#include <linux/statfs.h>

#else 
#  define kstatfs statfs
#endif

#endif /* LPROCFS_SNMP_H */
