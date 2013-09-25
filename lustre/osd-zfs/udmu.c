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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/udmu.c
 * Module that interacts with the ZFS DMU and provides an abstraction
 * to the rest of Lustre.
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Atul Vidwansa <atul.vidwansa@sun.com>
 * Author: Manoj Joseph <manoj.joseph@sun.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#include <lustre/lustre_idl.h>  /* OBD_OBJECT_EOF */
#include <lustre/lustre_user.h> /* struct obd_statfs */

#include <sys/dnode.h>
#include <sys/dbuf.h>
#include <sys/spa.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa_impl.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_tx.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_prop.h>
#include <sys/sa_impl.h>
#include <sys/txg.h>

#include "udmu.h"

int udmu_blk_insert_cost(void)
{
	int max_blockshift, nr_blkptrshift;

	/* max_blockshift is the log2 of the number of blocks needed to reach
	 * the maximum filesize (that's to say 2^64) */
	max_blockshift = DN_MAX_OFFSET_SHIFT - SPA_MAXBLOCKSHIFT;

	/* nr_blkptrshift is the log2 of the number of block pointers that can
	 * be stored in an indirect block */
	CLASSERT(DN_MAX_INDBLKSHIFT > SPA_BLKPTRSHIFT);
	nr_blkptrshift = DN_MAX_INDBLKSHIFT - SPA_BLKPTRSHIFT;

	/* max_blockshift / nr_blkptrshift is thus the maximum depth of the
	 * tree. We add +1 for rounding purpose.
	 * The tree depth times the indirect block size gives us the maximum
	 * cost of inserting a block in the tree */
	return (max_blockshift / nr_blkptrshift + 1) * (1 << DN_MAX_INDBLKSHIFT);
}

int udmu_objset_open(char *osname, udmu_objset_t *uos)
{
	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	uint64_t version = ZPL_VERSION;
	uint64_t sa_obj;
	int      error;

	memset(uos, 0, sizeof(udmu_objset_t));

	error = dmu_objset_own(osname, DMU_OST_ZFS, B_FALSE, uos, &uos->os);
	if (error) {
		uos->os = NULL;
		goto out;
	}

	/* Check ZFS version */
	error = zap_lookup(uos->os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1,
			   &version);
	if (error) {
		CERROR("%s: Error looking up ZPL VERSION\n", osname);
		/*
		 * We can't return ENOENT because that would mean the objset
		 * didn't exist.
		 */
		error = EIO;
		goto out;
	}

	error = zap_lookup(uos->os, MASTER_NODE_OBJ, ZFS_SA_ATTRS, 8, 1,
			   &sa_obj);
	if (error)
		goto out;

	error = sa_setup(uos->os, sa_obj, zfs_attr_table, ZPL_END,
			 &uos->z_attr_table);
	if (error)
		goto out;

	error = zap_lookup(uos->os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1,
			   &uos->root);
	if (error) {
		CERROR("%s: Error looking up ZFS root object.\n", osname);
		error = EIO;
		goto out;
	}
	ASSERT(uos->root != 0);

	/* Check that user/group usage tracking is supported */
	if (!dmu_objset_userused_enabled(uos->os) ||
		DMU_USERUSED_DNODE(uos->os)->dn_type != DMU_OT_USERGROUP_USED ||
		DMU_GROUPUSED_DNODE(uos->os)->dn_type != DMU_OT_USERGROUP_USED) {
		CERROR("%s: Space accounting not supported by this target, "
			"aborting\n", osname);
		error = ENOTSUPP;
		goto out;
	}

	/*
	 * as DMU doesn't maintain f_files absolutely actual (it's updated
	 * at flush, not when object is create/destroyed) we've implemented
	 * own counter which is initialized from on-disk at mount, then is
	 * being maintained by DMU OSD
	 */
	dmu_objset_space(uos->os, &refdbytes, &availbytes, &usedobjs,
			 &availobjs);
	uos->objects = usedobjs;
	spin_lock_init(&uos->lock);

out:
	if (error && uos->os != NULL)
		dmu_objset_disown(uos->os, uos);

	return error;
}

void udmu_objset_close(udmu_objset_t *uos)
{
	ASSERT(uos->os != NULL);

	/*
	 * Force a txg sync.  This should not be needed, neither for
	 * correctness nor safety.  Presumably, we are only doing
	 * this to force commit callbacks to be called sooner.
	 */
	txg_wait_synced(dmu_objset_pool(uos->os), 0ULL);

	/* close the object set */
	dmu_objset_disown(uos->os, uos);

	uos->os = NULL;
}

/* Estimate the number of objects from a number of blocks */
static uint64_t udmu_objs_count_estimate(uint64_t refdbytes,
					uint64_t usedobjs,
					uint64_t nrblocks)
{
	uint64_t est_objs, est_refdblocks, est_usedobjs;

	/* Compute an nrblocks estimate based on the actual number of
	 * dnodes that could fit in the space.  Since we don't know the
	 * overhead associated with each dnode (xattrs, SAs, VDEV overhead,
	 * etc) just using DNODE_SHIFT isn't going to give a good estimate.
	 * Instead, compute an estimate based on the average space usage per
	 * dnode, with an upper and lower cap.
	 *
	 * In case there aren't many dnodes or blocks used yet, add a small
	 * correction factor using OSD_DNODE_EST_SHIFT.  This correction
	 * factor gradually disappears as the number of real dnodes grows.
	 * This also avoids the need to check for divide-by-zero later.
	 */
	CLASSERT(OSD_DNODE_MIN_BLKSHIFT > 0);
	CLASSERT(OSD_DNODE_EST_BLKSHIFT > 0);

	est_refdblocks = (refdbytes >> SPA_MAXBLOCKSHIFT) +
			 (OSD_DNODE_EST_COUNT >> OSD_DNODE_EST_BLKSHIFT);
	est_usedobjs   = usedobjs + OSD_DNODE_EST_COUNT;

	/* Average space/dnode more than maximum dnode size, use max dnode
	 * size to estimate free dnodes from adjusted free blocks count.
	 * OSTs typically use more than one block dnode so this case applies. */
	if (est_usedobjs <= est_refdblocks * 2) {
		est_objs = nrblocks;

	/* Average space/dnode smaller than min dnode size (probably due to
	 * metadnode compression), use min dnode size to estimate the number of
	 * objects.
	 * An MDT typically uses below 512 bytes/dnode so this case applies. */
	} else if (est_usedobjs >= (est_refdblocks << OSD_DNODE_MIN_BLKSHIFT)) {
		est_objs = nrblocks << OSD_DNODE_MIN_BLKSHIFT;

		/* Between the extremes, we try to use the average size of
		 * existing dnodes to compute the number of dnodes that fit
		 * into nrblocks:
		 *
		 * est_objs = nrblocks * (est_usedobjs / est_refblocks);
		 *
		 * but this may overflow 64 bits or become 0 if not handled well
		 *
		 * We know nrblocks is below (64 - 17 = 47) bits from
		 * SPA_MAXBLKSHIFT, and est_usedobjs is under 48 bits due to
		 * DN_MAX_OBJECT_SHIFT, which means that multiplying them may
		 * get as large as 2 ^ 95.
		 *
		 * We also know (est_usedobjs / est_refdblocks) is between 2 and
		 * 256, due to above checks, so we can safely compute this first.
		 * We care more about accuracy on the MDT (many dnodes/block)
		 * which is good because this is where truncation errors are
		 * smallest.  This adds 8 bits to nrblocks so we can use 7 bits
		 * to compute a fixed-point fraction and nrblocks can still fit
		 * in 64 bits. */
	} else {
		unsigned dnodes_per_block = (est_usedobjs << 7)/est_refdblocks;

		est_objs = (nrblocks * dnodes_per_block) >> 7;
	}
	return est_objs;
}

int udmu_objset_statfs(udmu_objset_t *uos, struct obd_statfs *osfs)
{
	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	uint64_t est_availobjs;
	uint64_t reserved;

	dmu_objset_space(uos->os, &refdbytes, &availbytes, &usedobjs,
			&availobjs);

	/*
	 * ZFS allows multiple block sizes.  For statfs, Linux makes no
	 * proper distinction between bsize and frsize.  For calculations
	 * of free and used blocks incorrectly uses bsize instead of frsize,
	 * but bsize is also used as the optimal blocksize.  We return the
	 * largest possible block size as IO size for the optimum performance
	 * and scale the free and used blocks count appropriately.
	 */
	osfs->os_bsize = 1ULL << SPA_MAXBLOCKSHIFT;

	osfs->os_blocks = (refdbytes + availbytes) >> SPA_MAXBLOCKSHIFT;
	osfs->os_bfree = availbytes >> SPA_MAXBLOCKSHIFT;
	osfs->os_bavail = osfs->os_bfree; /* no extra root reservation */

	/* Take replication (i.e. number of copies) into account */
	osfs->os_bavail /= uos->os->os_copies;

	/*
	 * Reserve some space so we don't run into ENOSPC due to grants not
	 * accounting for metadata overhead in ZFS, and to avoid fragmentation.
	 * Rather than report this via os_bavail (which makes users unhappy if
	 * they can't fill the filesystem 100%), reduce os_blocks as well.
	 *
	 * Reserve 0.78% of total space, at least 4MB for small filesystems,
	 * for internal files to be created/unlinked when space is tight.
	 */
	CLASSERT(OSD_STATFS_RESERVED_BLKS > 0);
	if (likely(osfs->os_blocks >=
			OSD_STATFS_RESERVED_BLKS << OSD_STATFS_RESERVED_SHIFT))
		reserved = osfs->os_blocks >> OSD_STATFS_RESERVED_SHIFT;
	else
		reserved = OSD_STATFS_RESERVED_BLKS;

	osfs->os_blocks -= reserved;
	osfs->os_bfree  -= MIN(reserved, osfs->os_bfree);
	osfs->os_bavail -= MIN(reserved, osfs->os_bavail);

	/*
	 * The availobjs value returned from dmu_objset_space() is largely
	 * useless, since it reports the number of objects that might
	 * theoretically still fit into the dataset, independent of minor
	 * issues like how much space is actually available in the pool.
	 * Compute a better estimate in udmu_objs_count_estimate().
	 */
	est_availobjs = udmu_objs_count_estimate(refdbytes, usedobjs,
						osfs->os_bfree);

	osfs->os_ffree = min(availobjs, est_availobjs);
	osfs->os_files = osfs->os_ffree + uos->objects;

	/* ZFS XXX: fill in backing dataset FSID/UUID
	   memcpy(osfs->os_fsid, .... );*/

	/* We're a zfs filesystem. */
	osfs->os_type = UBERBLOCK_MAGIC;

	/* ZFS XXX: fill in appropriate OS_STATE_{DEGRADED,READONLY} flags
	   osfs->os_state = vf_to_stf(vfsp->vfs_flag);
	   if (sb->s_flags & MS_RDONLY)
	   osfs->os_state = OS_STATE_READONLY;
	 */

	osfs->os_namelen = MAXNAMELEN;
	osfs->os_maxbytes = OBD_OBJECT_EOF;

	return 0;
}

/**
 * Helper function to estimate the number of inodes in use for a give uid/gid
 * from the block usage
 */
uint64_t udmu_objset_user_iused(udmu_objset_t *uos, uint64_t uidbytes)
{
	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	uint64_t uidobjs;

	/* get fresh statfs info */
	dmu_objset_space(uos->os, &refdbytes, &availbytes, &usedobjs,
			&availobjs);

	/* estimate the number of objects based on the disk usage */
	uidobjs = udmu_objs_count_estimate(refdbytes, usedobjs,
					uidbytes >> SPA_MAXBLOCKSHIFT);
	if (uidbytes > 0)
		/* if we have at least 1 byte, we have at least one dnode ... */
		uidobjs = max_t(uint64_t, uidobjs, 1);
	return uidobjs;
}

/* We don't actually have direct access to the zap_hashbits() function
 * so just pretend like we do for now.  If this ever breaks we can look at
 * it at that time. */
#define zap_hashbits(zc) 48
/*
 * ZFS hash format:
 * | cd (16 bits) | hash (48 bits) |
 * we need it in other form:
 * |0| hash (48 bit) | cd (15 bit) |
 * to be a full 64-bit ordered hash so that Lustre readdir can use it to merge
 * the readdir hashes from multiple directory stripes uniformly on the client.
 * Another point is sign bit, the hash range should be in [0, 2^63-1] because
 * loff_t (for llseek) needs to be a positive value.  This means the "cd" field
 * should only be the low 15 bits.
 */
uint64_t udmu_zap_cursor_serialize(zap_cursor_t *zc)
{
	uint64_t zfs_hash = zap_cursor_serialize(zc) & (~0ULL >> 1);

	return (zfs_hash >> zap_hashbits(zc)) |
		(zfs_hash << (63 - zap_hashbits(zc)));
}

void udmu_zap_cursor_init_serialized(zap_cursor_t *zc, udmu_objset_t *uos,
		uint64_t zapobj, uint64_t dirhash)
{
	uint64_t zfs_hash = ((dirhash << zap_hashbits(zc)) & (~0ULL >> 1)) |
		(dirhash >> (63 - zap_hashbits(zc)));
	zap_cursor_init_serialized(zc, uos->os, zapobj, zfs_hash);
}

/*
 * Zap cursor APIs
 */
int udmu_zap_cursor_init(zap_cursor_t **zc, udmu_objset_t *uos,
		uint64_t zapobj, uint64_t dirhash)
{
	zap_cursor_t *t;

	t = kmem_alloc(sizeof(*t), KM_NOSLEEP);
	if (t) {
		udmu_zap_cursor_init_serialized(t, uos, zapobj, dirhash);
		*zc = t;
		return 0;
	}
	return (ENOMEM);
}

void udmu_zap_cursor_fini(zap_cursor_t *zc)
{
	zap_cursor_fini(zc);
	kmem_free(zc, sizeof(*zc));
}

/*
 * Get the object id from dmu_buf_t
 */
int udmu_object_is_zap(dmu_buf_t *db)
{
	dmu_buf_impl_t *dbi = (dmu_buf_impl_t *) db;
	dnode_t *dn;
	int rc;

	DB_DNODE_ENTER(dbi);

	dn = DB_DNODE(dbi);
	rc = (dn->dn_type == DMU_OT_DIRECTORY_CONTENTS ||
			dn->dn_type == DMU_OT_USERGROUP_USED);

	DB_DNODE_EXIT(dbi);

	return rc;
}

