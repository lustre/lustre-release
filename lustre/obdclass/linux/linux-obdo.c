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
 * lustre/obdclass/linux/linux-obdo.c
 *
 * Object Devices Class Driver
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#ifndef __KERNEL__
#include <liblustre.h>
#else
#include <linux/module.h>
#include <obd_class.h>
#include <lustre/lustre_idl.h>
#endif

#ifdef __KERNEL__
#include <linux/fs.h>
#include <linux/pagemap.h> /* for PAGE_CACHE_SIZE */

void obdo_from_iattr(struct obdo *oa, struct iattr *attr, unsigned int ia_valid)
{
        if (ia_valid & ATTR_ATIME) {
                oa->o_atime = LTIME_S(attr->ia_atime);
                oa->o_valid |= OBD_MD_FLATIME;
        }
        if (ia_valid & ATTR_MTIME) {
                oa->o_mtime = LTIME_S(attr->ia_mtime);
                oa->o_valid |= OBD_MD_FLMTIME;
        }
        if (ia_valid & ATTR_CTIME) {
                oa->o_ctime = LTIME_S(attr->ia_ctime);
                oa->o_valid |= OBD_MD_FLCTIME;
        }
        if (ia_valid & ATTR_SIZE) {
                oa->o_size = attr->ia_size;
                oa->o_valid |= OBD_MD_FLSIZE;
        }
        if (ia_valid & ATTR_MODE) {
                oa->o_mode = attr->ia_mode;
                oa->o_valid |= OBD_MD_FLTYPE | OBD_MD_FLMODE;
                if (!in_group_p(oa->o_gid) && !cfs_capable(CFS_CAP_FSETID))
                        oa->o_mode &= ~S_ISGID;
        }
        if (ia_valid & ATTR_UID) {
                oa->o_uid = attr->ia_uid;
                oa->o_valid |= OBD_MD_FLUID;
        }
        if (ia_valid & ATTR_GID) {
                oa->o_gid = attr->ia_gid;
                oa->o_valid |= OBD_MD_FLGID;
        }
}
EXPORT_SYMBOL(obdo_from_iattr);

void iattr_from_obdo(struct iattr *attr, struct obdo *oa, obd_flag valid)
{
        valid &= oa->o_valid;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE, "valid "LPX64", new time "LPU64"/"LPU64"\n",
                       oa->o_valid, oa->o_mtime, oa->o_ctime);

        attr->ia_valid = 0;
        if (valid & OBD_MD_FLATIME) {
                LTIME_S(attr->ia_atime) = oa->o_atime;
                attr->ia_valid |= ATTR_ATIME;
        }
        if (valid & OBD_MD_FLMTIME) {
                LTIME_S(attr->ia_mtime) = oa->o_mtime;
                attr->ia_valid |= ATTR_MTIME;
        }
        if (valid & OBD_MD_FLCTIME) {
                LTIME_S(attr->ia_ctime) = oa->o_ctime;
                attr->ia_valid |= ATTR_CTIME;
        }
        if (valid & OBD_MD_FLSIZE) {
                attr->ia_size = oa->o_size;
                attr->ia_valid |= ATTR_SIZE;
        }
#if 0   /* you shouldn't be able to change a file's type with setattr */
        if (valid & OBD_MD_FLTYPE) {
                attr->ia_mode = (attr->ia_mode & ~S_IFMT)|(oa->o_mode & S_IFMT);
                attr->ia_valid |= ATTR_MODE;
        }
#endif
        if (valid & OBD_MD_FLMODE) {
                attr->ia_mode = (attr->ia_mode & S_IFMT)|(oa->o_mode & ~S_IFMT);
                attr->ia_valid |= ATTR_MODE;
                if (!in_group_p(oa->o_gid) && !cfs_capable(CFS_CAP_FSETID))
                        attr->ia_mode &= ~S_ISGID;
        }
        if (valid & OBD_MD_FLUID) {
                attr->ia_uid = oa->o_uid;
                attr->ia_valid |= ATTR_UID;
        }
        if (valid & OBD_MD_FLGID) {
                attr->ia_gid = oa->o_gid;
                attr->ia_valid |= ATTR_GID;
        }
}
EXPORT_SYMBOL(iattr_from_obdo);

/* WARNING: the file systems must take care not to tinker with
   attributes they don't manage (such as blocks). */
void obdo_from_inode(struct obdo *dst, struct inode *src, obd_flag valid)
{
        obd_flag newvalid = 0;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE, "valid %x, new time %lu/%lu\n",
                       valid, LTIME_S(src->i_mtime), 
                       LTIME_S(src->i_ctime));

        if (valid & OBD_MD_FLATIME) {
                dst->o_atime = LTIME_S(src->i_atime);
                newvalid |= OBD_MD_FLATIME;
        }
        if (valid & OBD_MD_FLMTIME) {
                dst->o_mtime = LTIME_S(src->i_mtime);
                newvalid |= OBD_MD_FLMTIME;
        }
        if (valid & OBD_MD_FLCTIME) {
                dst->o_ctime = LTIME_S(src->i_ctime);
                newvalid |= OBD_MD_FLCTIME;
        }
        if (valid & OBD_MD_FLSIZE) {
                dst->o_size = i_size_read(src);
                newvalid |= OBD_MD_FLSIZE;
        }
        if (valid & OBD_MD_FLBLOCKS) {  /* allocation of space (x512 bytes) */
                dst->o_blocks = src->i_blocks;
                newvalid |= OBD_MD_FLBLOCKS;
        }
        if (valid & OBD_MD_FLBLKSZ) {   /* optimal block size */
                dst->o_blksize = 1<<src->i_blkbits;
                newvalid |= OBD_MD_FLBLKSZ;
        }
        if (valid & OBD_MD_FLTYPE) {
                dst->o_mode = (dst->o_mode & S_IALLUGO)|(src->i_mode & S_IFMT);
                newvalid |= OBD_MD_FLTYPE;
        }
        if (valid & OBD_MD_FLMODE) {
                dst->o_mode = (dst->o_mode & S_IFMT)|(src->i_mode & S_IALLUGO);
                newvalid |= OBD_MD_FLMODE;
        }
        if (valid & OBD_MD_FLUID) {
                dst->o_uid = src->i_uid;
                newvalid |= OBD_MD_FLUID;
        }
        if (valid & OBD_MD_FLGID) {
                dst->o_gid = src->i_gid;
                newvalid |= OBD_MD_FLGID;
        }
        if (valid & OBD_MD_FLFLAGS) {
                dst->o_flags = src->i_flags;
                newvalid |= OBD_MD_FLFLAGS;
        }
        if (valid & OBD_MD_FLGENER) {
                dst->o_generation = src->i_generation;
                newvalid |= OBD_MD_FLGENER;
        }
        if (valid & OBD_MD_FLFID) {
                dst->o_fid = src->i_ino;
                newvalid |= OBD_MD_FLFID;
        }

        dst->o_valid |= newvalid;
}
EXPORT_SYMBOL(obdo_from_inode);

void obdo_refresh_inode(struct inode *dst, struct obdo *src, obd_flag valid)
{
        valid &= src->o_valid;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE,
                       "valid "LPX64", cur time %lu/%lu, new "LPU64"/"LPU64"\n",
                       src->o_valid, LTIME_S(dst->i_mtime),
                       LTIME_S(dst->i_ctime), src->o_mtime, src->o_ctime);

        if (valid & OBD_MD_FLATIME && src->o_atime > LTIME_S(dst->i_atime))
                LTIME_S(dst->i_atime) = src->o_atime;
        if (valid & OBD_MD_FLMTIME && src->o_mtime > LTIME_S(dst->i_mtime))
                LTIME_S(dst->i_mtime) = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > LTIME_S(dst->i_ctime))
                LTIME_S(dst->i_ctime) = src->o_ctime;
        if (valid & OBD_MD_FLSIZE)
                i_size_write(dst, src->o_size);
        /* optimum IO size */
        if (valid & OBD_MD_FLBLKSZ && src->o_blksize > (1<<dst->i_blkbits)) {
                dst->i_blkbits = ffs(src->o_blksize)-1;
#ifdef HAVE_INODE_BLKSIZE
                dst->i_blksize = src->o_blksize;
#endif
        }

        if (dst->i_blkbits < CFS_PAGE_SHIFT) {
#ifdef HAVE_INODE_BLKSIZE
                dst->i_blksize = CFS_PAGE_SIZE;
#endif
                dst->i_blkbits = CFS_PAGE_SHIFT;
        }

        /* allocation of space */
        if (valid & OBD_MD_FLBLOCKS && src->o_blocks > dst->i_blocks)
                dst->i_blocks = src->o_blocks;
}
EXPORT_SYMBOL(obdo_refresh_inode);

void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid)
{
        valid &= src->o_valid;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE,
                       "valid "LPX64", cur time %lu/%lu, new "LPU64"/"LPU64"\n",
                       src->o_valid, LTIME_S(dst->i_mtime),
                       LTIME_S(dst->i_ctime), src->o_mtime, src->o_ctime);

        if (valid & OBD_MD_FLATIME)
                LTIME_S(dst->i_atime) = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                LTIME_S(dst->i_mtime) = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > LTIME_S(dst->i_ctime))
                LTIME_S(dst->i_ctime) = src->o_ctime;
        if (valid & OBD_MD_FLSIZE)
                i_size_write(dst, src->o_size);
        if (valid & OBD_MD_FLBLOCKS) { /* allocation of space */
                dst->i_blocks = src->o_blocks;
                if (dst->i_blocks < src->o_blocks) /* overflow */
                        dst->i_blocks = -1;

        }
        if (valid & OBD_MD_FLBLKSZ) {
                dst->i_blkbits = ffs(src->o_blksize)-1;
#ifdef HAVE_INODE_BLKSIZE
                dst->i_blksize = src->o_blksize;
#endif
        }
        if (valid & OBD_MD_FLTYPE)
                dst->i_mode = (dst->i_mode & ~S_IFMT) | (src->o_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                dst->i_mode = (dst->i_mode & S_IFMT) | (src->o_mode & ~S_IFMT);
        if (valid & OBD_MD_FLUID)
                dst->i_uid = src->o_uid;
        if (valid & OBD_MD_FLGID)
                dst->i_gid = src->o_gid;
        if (valid & OBD_MD_FLFLAGS)
                dst->i_flags = src->o_flags;
        if (valid & OBD_MD_FLGENER)
                dst->i_generation = src->o_generation;
}
EXPORT_SYMBOL(obdo_to_inode);
#endif
