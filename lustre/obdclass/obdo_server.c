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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/linux/linux-obdo.c
 *
 * Object Devices Class Driver
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/pagemap.h> /* for PAGE_SIZE */
#include <obd_class.h>

/*FIXME: Just copy from obdo_from_inode*/
void obdo_from_la(struct obdo *dst, const struct lu_attr *la, u64 valid)
{
	u64 newvalid = 0;

	if (valid & LA_ATIME) {
		dst->o_atime = la->la_atime;
		newvalid |= OBD_MD_FLATIME;
	}
	if (valid & LA_MTIME) {
		dst->o_mtime = la->la_mtime;
		newvalid |= OBD_MD_FLMTIME;
	}
	if (valid & LA_CTIME) {
		dst->o_ctime = la->la_ctime;
		newvalid |= OBD_MD_FLCTIME;
	}
	if (valid & LA_SIZE) {
		dst->o_size = la->la_size;
		newvalid |= OBD_MD_FLSIZE;
	}
	if (valid & LA_BLOCKS) {  /* allocation of space (x512 bytes) */
		dst->o_blocks = la->la_blocks;
		newvalid |= OBD_MD_FLBLOCKS;
	}
	if (valid & LA_TYPE) {
		dst->o_mode = (dst->o_mode & S_IALLUGO) |
			(la->la_mode & S_IFMT);
		newvalid |= OBD_MD_FLTYPE;
	}
	if (valid & LA_MODE) {
		dst->o_mode = (dst->o_mode & S_IFMT) |
			(la->la_mode & S_IALLUGO);
		newvalid |= OBD_MD_FLMODE;
	}
	if (valid & LA_UID) {
		dst->o_uid = la->la_uid;
		newvalid |= OBD_MD_FLUID;
	}
	if (valid & LA_GID) {
		dst->o_gid = la->la_gid;
		newvalid |= OBD_MD_FLGID;
	}
	if (valid & LA_PROJID) {
		dst->o_projid = la->la_projid;
		newvalid |= OBD_MD_FLPROJID;
	}
	if (valid & LA_FLAGS) {
		dst->o_flags = la->la_flags;
		newvalid |= OBD_MD_FLFLAGS;
	}
	if (valid & LA_NLINK) {
		dst->o_nlink = la->la_nlink;
		newvalid |= OBD_MD_FLNLINK;
	}
	dst->o_valid |= newvalid;
}
EXPORT_SYMBOL(obdo_from_la);

/*FIXME: Just copy from obdo_from_inode*/
void la_from_obdo(struct lu_attr *dst, const struct obdo *obdo, u64 valid)
{
	u64 newvalid = 0;

	valid &= obdo->o_valid;

	if (valid & OBD_MD_FLATIME) {
		dst->la_atime = obdo->o_atime;
		newvalid |= LA_ATIME;
	}
	if (valid & OBD_MD_FLMTIME) {
		dst->la_mtime = obdo->o_mtime;
		newvalid |= LA_MTIME;
	}
	if (valid & OBD_MD_FLCTIME) {
		dst->la_ctime = obdo->o_ctime;
		newvalid |= LA_CTIME;
	}
	if (valid & OBD_MD_FLSIZE) {
		dst->la_size = obdo->o_size;
		newvalid |= LA_SIZE;
	}
	if (valid & OBD_MD_FLBLOCKS) {
		dst->la_blocks = obdo->o_blocks;
		newvalid |= LA_BLOCKS;
	}
	if (valid & OBD_MD_FLTYPE) {
		dst->la_mode = (dst->la_mode & S_IALLUGO) |
			(obdo->o_mode & S_IFMT);
		newvalid |= LA_TYPE;
	}
	if (valid & OBD_MD_FLMODE) {
		dst->la_mode = (dst->la_mode & S_IFMT) |
			(obdo->o_mode & S_IALLUGO);
		newvalid |= LA_MODE;
	}
	if (valid & OBD_MD_FLUID) {
		dst->la_uid = obdo->o_uid;
		newvalid |= LA_UID;
	}
	if (valid & OBD_MD_FLGID) {
		dst->la_gid = obdo->o_gid;
		newvalid |= LA_GID;
	}
	if (valid & OBD_MD_FLPROJID) {
		dst->la_projid = obdo->o_projid;
		newvalid |= LA_PROJID;
	}
	if (valid & OBD_MD_FLFLAGS) {
		dst->la_flags = obdo->o_flags;
		newvalid |= LA_FLAGS;
	}
	if (valid & OBD_MD_FLNLINK) {
		dst->la_nlink = obdo->o_nlink;
		newvalid |= LA_NLINK;
	}
	dst->la_valid = newvalid;
}
EXPORT_SYMBOL(la_from_obdo);
