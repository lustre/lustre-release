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
 */

#ifndef __LINUX_OBD_H
#define __LINUX_OBD_H

#ifndef __OBD_H
#error Do not #include this file directly. #include <obd.h> instead
#endif

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/list.h>
# include <linux/sched.h>  /* for struct task_struct, for current.h */
# include <asm/current.h>  /* for smp_lock.h */
# include <linux/smp_lock.h>
# include <linux/proc_fs.h>
# include <linux/mount.h>
# ifndef HAVE_VFS_INTENT_PATCHES
#  include <linux/lustre_intent.h>
# endif
#endif

typedef spinlock_t client_obd_lock_t;

static inline void client_obd_list_lock_init(client_obd_lock_t *lock)
{
        spin_lock_init(lock);
}

static inline void client_obd_list_lock_done(client_obd_lock_t *lock)
{}

static inline void client_obd_list_lock(client_obd_lock_t *lock)
{
        spin_lock(lock);
}

static inline void client_obd_list_unlock(client_obd_lock_t *lock)
{
        spin_unlock(lock);
}

#if defined(__KERNEL__) && !defined(HAVE_ADLER)
/* zlib_adler() is an inline function defined in zutil.h */
#define HAVE_ADLER
#endif
#endif /* __LINUX_OBD_H */
