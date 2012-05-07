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
 *
 * lustre/include/darwin/lprocfs_status.h
 *
 * Author: Hariharan Thantry thantry@users.sourceforge.net
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
