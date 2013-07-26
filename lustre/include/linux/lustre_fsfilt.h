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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/linux/lustre_fsfilt.h
 *
 * Filesystem interface helper.
 */

#ifndef _LINUX_LUSTRE_FSFILT_H
#define _LINUX_LUSTRE_FSFILT_H

#ifndef _LUSTRE_FSFILT_H
#error Do not #include this file directly. #include <lustre_fsfilt.h> instead
#endif

#ifdef __KERNEL__

#include <obd.h>
#include <obd_class.h>

struct fsfilt_operations {
        cfs_list_t fs_list;
        cfs_module_t *fs_owner;
        char   *fs_type;
        int     (* fs_map_inode_pages)(struct inode *inode, struct page **page,
				       int pages, unsigned long *blocks,
				       int create, struct mutex *sem);
};

extern int fsfilt_register_ops(struct fsfilt_operations *fs_ops);
extern void fsfilt_unregister_ops(struct fsfilt_operations *fs_ops);
extern struct fsfilt_operations *fsfilt_get_ops(const char *type);
extern void fsfilt_put_ops(struct fsfilt_operations *fs_ops);

#define __fsfilt_check_slow(obd, start, msg)                              \
do {                                                                      \
        if (cfs_time_before(jiffies, start + 15 * CFS_HZ))                \
                break;                                                    \
        else if (cfs_time_before(jiffies, start + 30 * CFS_HZ))           \
                CDEBUG(D_VFSTRACE, "%s: slow %s %lus\n", obd->obd_name,   \
                       msg, (jiffies-start) / CFS_HZ);                    \
        else if (cfs_time_before(jiffies, start + DISK_TIMEOUT * CFS_HZ)) \
                CWARN("%s: slow %s %lus\n", obd->obd_name, msg,           \
                      (jiffies - start) / CFS_HZ);                        \
        else                                                              \
                CERROR("%s: slow %s %lus\n", obd->obd_name, msg,          \
                       (jiffies - start) / CFS_HZ);                       \
} while (0)

#define fsfilt_check_slow(obd, start, msg)              \
do {                                                    \
        __fsfilt_check_slow(obd, start, msg);           \
        start = jiffies;                                \
} while (0)

#endif /* __KERNEL__ */

#endif
