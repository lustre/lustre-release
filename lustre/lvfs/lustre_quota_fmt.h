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
 * lustre/lvfs/lustre_quota_fmt.h
 *
 * Lustre administrative quota format
 * from include/linux/quotaio_v2.h
 */
#ifndef _LUSTRE_QUOTA_FMT_H
#define _LUSTRE_QUOTA_FMT_H

#include <linux/types.h>
#include <linux/quota.h>

/*
 * Definitions of magics and versions of current quota files
 * Same with quota v2's magic
 */
#define LUSTRE_INITQMAGICS {\
        0xd9c01f11,     /** USRQUOTA */\
        0xd9c01927      /** GRPQUOTA */\
}

/* Invalid magics that mark quota file as inconsistent */
#define LUSTRE_BADQMAGICS {\
        0xbadbadba,     /** USRQUOTA */\
        0xbadbadba      /** GRPQUOTA */\
}

/* for the verson 2 of lustre_disk_dqblk*/
#define LUSTRE_INITQVERSIONS_V2 {\
        1,		/* USRQUOTA */\
        1		/* GRPQUOTA */\
}

/*
 * The following structure defines the format of the disk quota file
 * (as it appears on disk) - the file is a radix tree whose leaves point
 * to blocks of these structures. for the version 2.
 */
struct lustre_disk_dqblk_v2 {
        __u32 dqb_id;           /**< id this quota applies to */
        __u32 padding;
        __u64 dqb_ihardlimit;   /**< absolute limit on allocated inodes */
        __u64 dqb_isoftlimit;   /**< preferred inode limit */
        __u64 dqb_curinodes;    /**< current # allocated inodes */
        __u64 dqb_bhardlimit;   /**< absolute limit on disk space (in QUOTABLOCK_SIZE) */
        __u64 dqb_bsoftlimit;   /**< preferred limit on disk space (in QUOTABLOCK_SIZE) */
        __u64 dqb_curspace;     /**< current space occupied (in bytes) */
        obd_time dqb_btime;        /**< time limit for excessive disk use */
        obd_time dqb_itime;        /**< time limit for excessive inode use */
};

/* Number of entries in one blocks(14 entries) */
#define LUSTRE_DQSTRINBLK_V2 \
                ((LUSTRE_DQBLKSIZE - sizeof(struct lustre_disk_dqdbheader)) \
		/ sizeof(struct lustre_disk_dqblk_v2)) 
#define GETENTRIES_V2(buf) (((char *)buf)+sizeof(struct lustre_disk_dqdbheader))

#define GETENTRIES(buf,version) ((version == LUSTRE_QUOTA_V2) ? \
                                GETENTRIES_V2(buf) : 0)

/*
 * Here are header structures as written on disk and their in-memory copies
 */
/* First generic header */
struct lustre_disk_dqheader {
        __u32 dqh_magic;        /* Magic number identifying file */
        __u32 dqh_version;      /* File version */
};

/* Header with type and version specific information */
struct lustre_disk_dqinfo {
        __u32 dqi_bgrace;       /* Time before block soft limit becomes hard limit */
        __u32 dqi_igrace;       /* Time before inode soft limit becomes hard limit */
        __u32 dqi_flags;        /* Flags for quotafile (DQF_*) */
        __u32 dqi_blocks;       /* Number of blocks in file */
        __u32 dqi_free_blk;     /* Number of first free block in the list */
        __u32 dqi_free_entry;   /* Number of block with at least one free entry */
};

/*
 *  Structure of header of block with quota structures. It is padded to 16 bytes so
 *  there will be space for exactly 21 quota-entries in a block
 */
struct lustre_disk_dqdbheader {
        __u32 dqdh_next_free;   /* Number of next block with free entry */
        __u32 dqdh_prev_free;   /* Number of previous block with free entry */
        __u16 dqdh_entries;     /* Number of valid entries in block */
        __u16 dqdh_pad1;
        __u32 dqdh_pad2;
};

#ifdef LPROCFS
void lprocfs_quotfmt_test_init_vars(struct lprocfs_static_vars *lvars);
#else
static void lprocfs_quotfmt_test_init_vars(struct lprocfs_static_vars *lvars) {}
#endif

#define LUSTRE_DQINFOOFF	sizeof(struct lustre_disk_dqheader)     /* Offset of info header in file */
#define LUSTRE_DQBLKSIZE_BITS	10
#define LUSTRE_DQBLKSIZE	(1 << LUSTRE_DQBLKSIZE_BITS)    /* Size of block with quota structures */
#define LUSTRE_DQTREEOFF	1       /* Offset of tree in file in blocks */
#define LUSTRE_DQTREEDEPTH	4       /* Depth of quota tree */

typedef char *dqbuf_t;

#define GETIDINDEX(id, depth) (((id) >> ((LUSTRE_DQTREEDEPTH-(depth)-1)*8)) & 0xff)

#define MAX_UL (0xffffffffUL)

#define lustre_info_dirty(info) \
        cfs_test_bit(DQF_INFO_DIRTY_B, &(info)->dqi_flags)

struct dqblk {
        cfs_list_t link;
        uint blk;
};

/* come from lustre_fmt_common.c */
dqbuf_t getdqbuf(void);
void freedqbuf(dqbuf_t buf);
void disk2memdqb(struct lustre_mem_dqblk *m, void *d,
                        enum lustre_quota_version version);
void lustre_mark_info_dirty(struct lustre_mem_dqinfo *info);
int lustre_init_quota_header(struct lustre_quota_info *lqi, int type, 
                             int fakemagics);
int lustre_init_quota_info_generic(struct lustre_quota_info *lqi, int type,
                                   int fakemagics);
int lustre_read_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_read_quota_file_info(struct file* f, struct lustre_mem_dqinfo* info);
int lustre_write_quota_info(struct lustre_quota_info *lqi, int type);
int get_free_dqblk(struct file *filp, struct lustre_mem_dqinfo *info);
int put_free_dqblk(struct file *filp, struct lustre_mem_dqinfo *info,
                          dqbuf_t buf, uint blk);
int remove_free_dqentry(struct file *filp,
                               struct lustre_mem_dqinfo *info, dqbuf_t buf,
                               uint blk);
int insert_free_dqentry(struct file *filp,
                               struct lustre_mem_dqinfo *info, dqbuf_t buf,
                               uint blk);
ssize_t quota_read(struct file *file, struct inode *inode, int type,
                   uint blk, dqbuf_t buf);
int walk_tree_dqentry(struct file *filp, struct inode *inode, int type,
                      uint blk, int depth, cfs_list_t *list);
int check_quota_file(struct file *f, struct inode *inode, int type,
                     lustre_quota_version_t version);
int lustre_check_quota_file(struct lustre_quota_info *lqi, int type);
int lustre_read_dquot(struct lustre_dquot *dquot);
int lustre_commit_dquot(struct lustre_dquot *dquot);
int lustre_init_quota_info(struct lustre_quota_info *lqi, int type);
int lustre_get_qids(struct file *fp, struct inode *inode, int type,
                    cfs_list_t *list);
ssize_t lustre_read_quota(struct file *f, struct inode *inode, int type,
                          char *buf, int count, loff_t pos);

#define LUSTRE_ADMIN_QUOTAFILES_V2 {\
        "admin_quotafile_v2.usr",       /* user admin quotafile */\
        "admin_quotafile_v2.grp"        /* group admin quotafile */\
}

#define LUSTRE_OPQFILES_NAMES_V2 { "lquota_v2.user", "lquota_v2.group" }
#endif                          /* lustre_quota_fmt.h */
