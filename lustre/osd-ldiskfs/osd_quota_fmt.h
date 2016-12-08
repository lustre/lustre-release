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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2015, Intel Corporation.
 * Use is subject to license terms.
 *
 * Lustre ldiskfs quota format
 * from include/linux/quotaio_v2.h
 */
#ifndef _OSD_QUOTA_FMT_H
#define _OSD_QUOTA_FMT_H

#include <linux/types.h>
#include <linux/quota.h>

/*
 * The following structure defines the format of the disk quota file
 * (as it appears on disk) - the file is a radix tree whose leaves point
 * to blocks of these structures. for the version 2.
 */
struct lustre_disk_dqblk_v2 {
	__u32 dqb_id;         /**< id this quota applies to */
	__u32 padding;
	__u64 dqb_ihardlimit; /**< absolute limit on allocated inodes */
	__u64 dqb_isoftlimit; /**< preferred inode limit */
	__u64 dqb_curinodes;  /**< current # allocated inodes */
	/**< absolute limit on disk space (in QUOTABLOCK_SIZE) */
	__u64 dqb_bhardlimit;
	/**< preferred limit on disk space (in QUOTABLOCK_SIZE) */
	__u64 dqb_bsoftlimit;
	__u64 dqb_curspace;   /**< current space occupied (in bytes) */
	s64	dqb_btime;	/**< time limit for excessive disk use */
	s64	dqb_itime;	/**< time limit for excessive inode use */
};

/* Number of entries in one blocks(14 entries) */
#define LUSTRE_DQSTRINBLK \
		((LUSTRE_DQBLKSIZE - sizeof(struct lustre_disk_dqdbheader)) \
		 / sizeof(struct lustre_disk_dqblk_v2))
#define GETENTRIES(buf) (((char *)buf)+sizeof(struct lustre_disk_dqdbheader))

/*
 * Here are header structures as written on disk and their in-memory copies
 */
/* First generic header */
struct lustre_disk_dqheader {
	__u32 dqh_magic; /* Magic number identifying file */
	__u32 dqh_version; /* File version */
};

/* Header with type and version specific information */
struct lustre_disk_dqinfo {
	/* Time before block soft limit becomes hard limit */
	__u32 dqi_bgrace;
	/* Time before inode soft limit becomes hard limit */
	__u32 dqi_igrace;
	/* Flags for quotafile (DQF_*) */
	__u32 dqi_flags;
	/* Number of blocks in file */
	__u32 dqi_blocks;
	/* Number of first free block in the list */
	__u32 dqi_free_blk;
	/* Number of block with at least one free entry */
	__u32 dqi_free_entry;
};

/*
 *  Structure of header of block with quota structures. It is padded to
 *  16 bytes so there will be space for exactly 21 quota-entries in a block
 */
struct lustre_disk_dqdbheader {
	__u32 dqdh_next_free; /* Number of next block with free entry */
	__u32 dqdh_prev_free; /* Number of previous block with free entry */
	__u16 dqdh_entries;   /* Number of valid entries in block */
	__u16 dqdh_pad1;
	__u32 dqdh_pad2;
};

/* Offset of info header in file */
#define LUSTRE_DQINFOOFF	sizeof(struct lustre_disk_dqheader)
#define LUSTRE_DQBLKSIZE_BITS	10
/* Size of block with quota structures */
#define LUSTRE_DQBLKSIZE	(1 << LUSTRE_DQBLKSIZE_BITS)
/* Offset of tree in file in blocks */
#define LUSTRE_DQTREEOFF	1
/* Depth of quota tree */
#define LUSTRE_DQTREEDEPTH	4

#define GETIDINDEX(id, depth)	(((id) >> \
				((LUSTRE_DQTREEDEPTH - (depth) - 1) * 8)) & \
				0xff)
#endif /* osd_quota_fmt.h */
