/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * OSD Object Index
 *
 * Object Index (oi) service runs in the bottom layer of server stack. In
 * translates fid local to this service to the storage cookie that uniquely
 * and efficiently identifies object (inode) of the underlying file system.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef _OSD_OI_H
#define _OSD_OI_H

/* struct rw_semaphore */
#include <linux/rwsem.h>
#include <linux/jbd2.h>
#include <lustre_fid.h>
#include <lu_object.h>
#include <md_object.h>

#define OSD_OI_FID_OID_BITS	6
#define OSD_OI_FID_NR		(1UL << OSD_OI_FID_OID_BITS)
#define OSD_OII_NOGEN		(0)

struct lu_fid;
struct osd_thread_info;
struct lu_site;

struct dt_device;
struct osd_device;
struct osd_oi;

/*
 * Storage cookie. Datum uniquely identifying inode on the underlying file
 * system.
 *
 * osd_inode_id is the internal ldiskfs identifier for an object. It should
 * not be visible outside of the osd-ldiskfs. Other OSDs may have different
 * identifiers, so this cannot form any part of the OSD API.
 */
struct osd_inode_id {
	__u32 oii_ino; /* inode number */
	__u32 oii_gen; /* inode generation */
};

/* OI cache entry */
struct osd_idmap_cache {
	struct lu_fid		oic_fid;
	struct osd_inode_id	oic_lid;
	struct osd_device	*oic_dev;
	__u16			oic_remote:1;	/* FID isn't local */
};

static inline void osd_id_pack(struct osd_inode_id *tgt,
			       const struct osd_inode_id *src)
{
	tgt->oii_ino = cpu_to_be32(src->oii_ino);
	tgt->oii_gen = cpu_to_be32(src->oii_gen);
}

static inline void osd_id_unpack(struct osd_inode_id *tgt,
				 struct osd_inode_id *src)
{
	tgt->oii_ino = be32_to_cpu(src->oii_ino);
	tgt->oii_gen = be32_to_cpu(src->oii_gen);
}

static inline void osd_id_gen(struct osd_inode_id *id, __u32 ino, __u32 gen)
{
	id->oii_ino = ino;
	id->oii_gen = gen;
}

static inline void osd_id_to_inode(struct inode *inode,
				   const struct osd_inode_id *id)
{
	inode->i_ino        = id->oii_ino;
	inode->i_generation = id->oii_gen;
}

static inline int osd_id_eq(const struct osd_inode_id *id0,
			    const struct osd_inode_id *id1)
{
	return (id0->oii_ino == id1->oii_ino) &&
	       (id0->oii_gen == id1->oii_gen ||
		id0->oii_gen == OSD_OII_NOGEN ||
		id1->oii_gen == OSD_OII_NOGEN);
}

static inline int osd_id_eq_strict(const struct osd_inode_id *id0,
				   const struct osd_inode_id *id1)
{
	return (id0->oii_ino == id1->oii_ino && id0->oii_gen == id1->oii_gen);
}

enum oi_check_flags {
	OI_CHECK_FLD	= 0x00000001,
	OI_KNOWN_ON_OST	= 0x00000002,
	OI_LOCKED	= 0x00000004,
};

extern unsigned int osd_oi_count;

int osd_oi_mod_init(void);
int osd_oi_init(struct osd_thread_info *info, struct osd_device *osd,
		bool restored);
void osd_oi_fini(struct osd_thread_info *info, struct osd_device *osd);
int  osd_oi_lookup(struct osd_thread_info *info, struct osd_device *osd,
		   const struct lu_fid *fid, struct osd_inode_id *id,
		   enum oi_check_flags flags);
int  osd_oi_insert(struct osd_thread_info *info, struct osd_device *osd,
		   const struct lu_fid *fid, const struct osd_inode_id *id,
		   handle_t *th, enum oi_check_flags flags, bool *exist);
int  osd_oi_delete(struct osd_thread_info *info,
		   struct osd_device *osd, const struct lu_fid *fid,
		   handle_t *th, enum oi_check_flags flags);
int  osd_oi_update(struct osd_thread_info *info, struct osd_device *osd,
		   const struct lu_fid *fid, const struct osd_inode_id *id,
		   handle_t *th, enum oi_check_flags flags);

int fid_is_on_ost(struct osd_thread_info *info, struct osd_device *osd,
		  const struct lu_fid *fid, enum oi_check_flags flags);
#endif /* _OSD_OI_H */
