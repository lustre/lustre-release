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
#ifndef _DARWIN_LPROCFS_SNMP_H
#define _DARWIN_LPROCFS_SNMP_H

#ifndef _LPROCFS_SNMP_H
#error Do not #include this file directly. #include <lprocfs_status.h> instead
#endif

#ifdef LPROCFS
#undef LPROCFS
#endif

#include <libcfs/libcfs.h>
#define kstatfs statfs

/*
 * XXX nikita: temporary! Stubs for naked procfs calls made by Lustre
 * code. Should be replaced with our own procfs-like API.
 */

static inline cfs_proc_dir_entry_t *proc_symlink(const char *name,
                                                 cfs_proc_dir_entry_t *parent,
                                                 const char *dest)
{
        return NULL;
}

static inline cfs_proc_dir_entry_t *create_proc_entry(const char *name,
                                                      mode_t mode,
                                                      cfs_proc_dir_entry_t *p)
{
        return NULL;
}

#endif /* XNU_LPROCFS_SNMP_H */
