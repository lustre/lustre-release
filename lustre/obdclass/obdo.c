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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/obdo.c
 *
 * Object Devices Class Driver
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/user_namespace.h>
#include <linux/uidgid.h>

#include <obd_class.h>
#include <lustre_obdo.h>

void obdo_set_parent_fid(struct obdo *dst, const struct lu_fid *parent)
{
	dst->o_parent_oid = fid_oid(parent);
	dst->o_parent_seq = fid_seq(parent);
	dst->o_parent_ver = fid_ver(parent);
	dst->o_valid |= OBD_MD_FLPARENT | OBD_MD_FLFID;
}
EXPORT_SYMBOL(obdo_set_parent_fid);

void obdo_set_o_projid(struct obdo *dst, u32 projid)
{
	dst->o_projid = projid;
	dst->o_valid |= OBD_MD_FLPROJID;
}
EXPORT_SYMBOL(obdo_set_o_projid);

/*
 * WARNING: the file systems must take care not to tinker with
 * attributes they don't manage (such as blocks).
 */
void obdo_from_inode(struct obdo *dst, struct inode *src, u64 valid)
{
	u64 newvalid = 0;

	if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
		CDEBUG(D_INODE, "valid %#llx, new time %lld/%lld\n",
		       valid, (s64) src->i_mtime.tv_sec,
		       (s64) src->i_ctime.tv_sec);

	if (valid & OBD_MD_FLATIME) {
		dst->o_atime = src->i_atime.tv_sec;
		newvalid |= OBD_MD_FLATIME;
	}
	if (valid & OBD_MD_FLMTIME) {
		dst->o_mtime = src->i_mtime.tv_sec;
		newvalid |= OBD_MD_FLMTIME;
	}
	if (valid & OBD_MD_FLCTIME) {
		dst->o_ctime = src->i_ctime.tv_sec;
		newvalid |= OBD_MD_FLCTIME;
	}
	if (valid & OBD_MD_FLSIZE) {
		dst->o_size = i_size_read(src);
		newvalid |= OBD_MD_FLSIZE;
	}
	if (valid & OBD_MD_FLBLOCKS) { /* allocation of space (x512 bytes) */
		dst->o_blocks = src->i_blocks;
		newvalid |= OBD_MD_FLBLOCKS;
	}
	if (valid & OBD_MD_FLBLKSZ) { /* optimal block size */
		dst->o_blksize = 1U << src->i_blkbits;
		newvalid |= OBD_MD_FLBLKSZ;
	}
	if (valid & OBD_MD_FLTYPE) {
		dst->o_mode = (dst->o_mode & S_IALLUGO) |
			      (src->i_mode & S_IFMT);
		newvalid |= OBD_MD_FLTYPE;
	}
	if (valid & OBD_MD_FLMODE) {
		dst->o_mode = (dst->o_mode & S_IFMT) |
			      (src->i_mode & S_IALLUGO);
		newvalid |= OBD_MD_FLMODE;
	}
	if (valid & OBD_MD_FLUID) {
		dst->o_uid = from_kuid(&init_user_ns, src->i_uid);
		newvalid |= OBD_MD_FLUID;
	}
	if (valid & OBD_MD_FLGID) {
		dst->o_gid = from_kgid(&init_user_ns, src->i_gid);
		newvalid |= OBD_MD_FLGID;
	}
	if (valid & OBD_MD_FLFLAGS) {
		dst->o_flags = src->i_flags;
		newvalid |= OBD_MD_FLFLAGS;
	}
	dst->o_valid |= newvalid;
}
EXPORT_SYMBOL(obdo_from_inode);

void obdo_cpy_md(struct obdo *dst, const struct obdo *src, u64 valid)
{
	CDEBUG(D_INODE, "src obdo "DOSTID" valid %#llx, dst obdo "DOSTID"\n",
	       POSTID(&src->o_oi), src->o_valid, POSTID(&dst->o_oi));
	if (valid & OBD_MD_FLATIME)
		dst->o_atime = src->o_atime;
	if (valid & OBD_MD_FLMTIME)
		dst->o_mtime = src->o_mtime;
	if (valid & OBD_MD_FLCTIME)
		dst->o_ctime = src->o_ctime;
	if (valid & OBD_MD_FLSIZE)
		dst->o_size = src->o_size;
	if (valid & OBD_MD_FLBLOCKS) /* allocation of space */
		dst->o_blocks = src->o_blocks;
	if (valid & OBD_MD_FLBLKSZ)
		dst->o_blksize = src->o_blksize;
	if (valid & OBD_MD_FLTYPE)
		dst->o_mode = (dst->o_mode & ~S_IFMT) | (src->o_mode & S_IFMT);
	if (valid & OBD_MD_FLMODE)
		dst->o_mode = (dst->o_mode & S_IFMT) | (src->o_mode & ~S_IFMT);
	if (valid & OBD_MD_FLUID)
		dst->o_uid = src->o_uid;
	if (valid & OBD_MD_FLGID)
		dst->o_gid = src->o_gid;
	if (valid & OBD_MD_FLFLAGS)
		dst->o_flags = src->o_flags;
	if (valid & OBD_MD_FLFID) {
		dst->o_parent_seq = src->o_parent_seq;
		dst->o_parent_ver = src->o_parent_ver;
	}
	if (valid & OBD_MD_FLPARENT)
		dst->o_parent_oid = src->o_parent_oid;
	if (valid & OBD_MD_FLHANDLE)
		dst->o_handle = src->o_handle;

	dst->o_valid |= valid;
}
EXPORT_SYMBOL(obdo_cpy_md);

void obdo_to_ioobj(const struct obdo *oa, struct obd_ioobj *ioobj)
{
	ioobj->ioo_oid = oa->o_oi;
	if (unlikely(!(oa->o_valid & OBD_MD_FLGROUP)))
		ostid_set_seq_mdt0(&ioobj->ioo_oid);

	/*
	 * Since 2.4 this does not contain o_mode in the low 16 bits.
	 * Instead, it holds (bd_md_max_brw - 1) for multi-bulk BRW RPCs
	 */
	ioobj->ioo_max_brw = 0;
}
EXPORT_SYMBOL(obdo_to_ioobj);

/*
 * Create an obdo to send over the wire
 */
void lustre_set_wire_obdo(const struct obd_connect_data *ocd,
			  struct obdo *wobdo,
			  const struct obdo *lobdo)
{
	*wobdo = *lobdo;
	if (ocd == NULL)
		return;

	if (!(wobdo->o_valid & OBD_MD_FLUID))
		wobdo->o_uid = from_kuid(&init_user_ns, current_uid());
	if (!(wobdo->o_valid & OBD_MD_FLGID))
		wobdo->o_gid = from_kgid(&init_user_ns, current_gid());

	if (unlikely(!(ocd->ocd_connect_flags & OBD_CONNECT_FID)) &&
	    fid_seq_is_echo(ostid_seq(&lobdo->o_oi))) {
		/*
		 * Currently OBD_FL_OSTID will only be used when 2.4 echo
		 * client communicate with pre-2.4 server
		 */
		wobdo->o_oi.oi.oi_id = fid_oid(&lobdo->o_oi.oi_fid);
		wobdo->o_oi.oi.oi_seq = fid_seq(&lobdo->o_oi.oi_fid);
	}
}
EXPORT_SYMBOL(lustre_set_wire_obdo);

/*
 * Create a local obdo from a wire based odbo
 */
void lustre_get_wire_obdo(const struct obd_connect_data *ocd,
			  struct obdo *lobdo,
			  const struct obdo *wobdo)
{
	*lobdo = *wobdo;
	if (ocd == NULL)
		return;

	if (unlikely(!(ocd->ocd_connect_flags & OBD_CONNECT_FID)) &&
	    fid_seq_is_echo(wobdo->o_oi.oi.oi_seq)) {
		/* see above */
		lobdo->o_oi.oi_fid.f_seq = wobdo->o_oi.oi.oi_seq;
		lobdo->o_oi.oi_fid.f_oid = wobdo->o_oi.oi.oi_id;
		lobdo->o_oi.oi_fid.f_ver = 0;
	}
}
EXPORT_SYMBOL(lustre_get_wire_obdo);
