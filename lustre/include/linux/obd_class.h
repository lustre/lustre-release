/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
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
 */

#ifndef __LINUX_CLASS_OBD_H
#define __LINUX_CLASS_OBD_H

#ifndef __CLASS_OBD_H
#error Do not #include this file directly. #include <obd_class.h> instead
#endif

#ifndef __KERNEL__
#include <sys/types.h>
#include <libcfs/list.h>
#else
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/timer.h>
#endif

#ifdef __KERNEL__
# ifndef HAVE_SERVER_SUPPORT

/* hash info structure used by the directory hash */
#  define LDISKFS_DX_HASH_LEGACY        0
#  define LDISKFS_DX_HASH_HALF_MD4      1
#  define LDISKFS_DX_HASH_TEA           2
#  define LDISKFS_DX_HASH_R5            3
#  define LDISKFS_DX_HASH_SAME          4
#  define LDISKFS_DX_HASH_MAX           4

/* hash info structure used by the directory hash */
struct ldiskfs_dx_hash_info
{
        u32     hash;
        u32     minor_hash;
        int     hash_version;
        u32     *seed;
};

#  define LDISKFS_HTREE_EOF     0x7fffffff

int ldiskfsfs_dirhash(const char *name, int len, struct ldiskfs_dx_hash_info *hinfo);

# endif /* HAVE_SERVER_SUPPORT */
#endif /* __KERNEL__ */

/* obdo.c */
#ifdef __KERNEL__
void obdo_from_inode(struct obdo *dst, struct inode *src, obd_flag valid);
void obdo_from_la(struct obdo *dst, struct lu_attr *la, obd_flag valid);
void obdo_refresh_inode(struct inode *dst, struct obdo *src, obd_flag valid);
void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid);
#endif

#if !defined(__KERNEL__)
#define to_kdev_t(dev) dev
#define kdev_t_to_nr(dev) dev
#endif

#endif /* __LINUX_OBD_CLASS_H */
