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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/include/lustre/libiam.h
 *
 * iam user level library
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Fan Yong <fanyong@clusterfs.com>
 */

/* lustre/libiam.h */
#ifndef __IAM_ULIB_H__
#define __IAM_ULIB_H__

#define DX_FMT_NAME_LEN 16

#define IAM_LFIX_ROOT_MAGIC  0xbedabb1edULL
#define IAM_LVAR_ROOT_MAGIC  0xb01dfaceULL

enum {
	IAM_LEAF_HEADER_MAGIC = 0x1976,
	IAM_LVAR_LEAF_MAGIC   = 0x1973,
	IAM_IDLE_HEADER_MAGIC = 0x7903
};

enum iam_fmt_t {
	FMT_LFIX = 0,
	FMT_LVAR = 1,
};

struct dx_countlimit {
	u_int16_t limit;
	u_int16_t count;
} __attribute__((packed));

struct iam_lfix_root {
	u_int64_t  ilr_magic;
	u_int16_t  ilr_keysize;
	u_int16_t  ilr_recsize;
	u_int16_t  ilr_ptrsize;
	u_int8_t   ilr_indirect_levels;
	u_int8_t   ilr_padding;
	struct dx_countlimit limit;
	u_int32_t idle_blocks;
	u_int8_t  ilr_paddingdd2[12];
	unsigned char entries[];
} __attribute__((packed));

struct iam_leaf_head {
	u_int16_t ill_magic;
	u_int16_t ill_count;
} __attribute__((packed));

struct lvar_leaf_header {
	u_int16_t vlh_magic; /* magic number IAM_LVAR_LEAF_MAGIC */
	u_int16_t vlh_used;  /* used bytes, including header */
} __attribute__((packed));

/*
 * Header structure to record idle blocks.
 */
struct iam_idle_head {
	__le16 iih_magic;
	__le16 iih_count; /* how many idle blocks in this head */
	__le32 iih_next; /* next head for idle blocks */
	__le32 iih_blks[];
} __attribute__((packed));

struct iam_index_head {
	struct dx_countlimit limit;
	u_int8_t  paddingdd[16];
	unsigned char entries[];
} __attribute__((packed));

struct lvar_root {
	u_int32_t vr_magic;
	u_int16_t vr_recsize;
	u_int16_t vr_ptrsize;
	u_int8_t  vr_indirect_levels;
	u_int8_t  vr_padding0;
	u_int16_t vr_padding1;
} __attribute__((packed));


struct lvar_leaf_entry {
	u_int32_t vle_hash;
	u_int16_t vle_keysize;
	u_int8_t  vle_key[];
} __attribute__((packed));

struct osd_inode_id {
	__u32 oii_ino;
	__u32 oii_gen;
} __attribute__ ((packed));


enum {
	LVAR_PAD   = 4,
	LVAR_ROUND = LVAR_PAD - 1
};

static inline unsigned int node_limit(unsigned int node_gap,
				      unsigned int block_size,
				      unsigned int size)
{
	return (block_size - node_gap) / size;
}

static inline unsigned int root_limit(unsigned int root_gap,
				      unsigned int node_gap,
				      unsigned int block_size,
				      unsigned int size)
{
	unsigned int limit;

	limit = (block_size - root_gap) / size;
	if (limit == node_limit(node_gap, block_size, size))
		limit--;
	return limit;
}

struct iam_uapi_info {
	__u16 iui_keysize;
	__u16 iui_recsize;
	__u16 iui_ptrsize;
	__u16 iui_height;
	char  iui_fmt_name[DX_FMT_NAME_LEN];
};

/*
 * Creat an iam file, but do NOT open it.
 * Return 0 if success, else -1.
 */
int iam_creat(char *filename, enum iam_fmt_t fmt,
	      int blocksize, int keysize, int recsize, int ptrsize);

/*
 * Open an iam file, but do NOT creat it if the file doesn't exist.
 * Please use iam_creat for creating the file before use iam_open.
 * Return file id (fd) if success, else -1.
 */
int iam_open(char *filename, struct iam_uapi_info *ua);

/*
 * Close file opened by iam_open.
 */
int iam_close(int fd);

/*
 * Please use iam_open before use this function.
 */
int iam_insert(int fd, struct iam_uapi_info *ua, int key_need_convert,
	       char *keybuf, int rec_need_convert, char *recbuf);

/*
 * Please use iam_open before use this function.
 */
int iam_lookup(int fd, struct iam_uapi_info *ua,
	       int key_need_convert, char *key_buf, int *keysize,
	       char *save_key, int rec_need_convert, char *rec_buf,
	       int *recsize, char *save_rec);

/*
 * Please use iam_open before use this function.
 */
int iam_delete(int fd, struct iam_uapi_info *ua, int key_need_convert,
	       char *keybuf, int rec_need_convert, char *recbuf);

/*
 * Please use iam_open before use this function.
 */
int iam_it_start(int fd, struct iam_uapi_info *ua, int key_need_convert,
		 char *key_buf, int *keysize, char *save_key,
		 int rec_need_convert, char *rec_buf, int *recsize,
		 char *save_rec);

/*
 * Please use iam_open before use this function.
 */
int iam_it_next(int fd, struct iam_uapi_info *ua, int key_need_convert,
		char *key_buf, int *keysize, char *save_key,
		int rec_need_convert, char *rec_buf, int *recsize,
		char *save_rec);

/*
 * Please use iam_open before use this function.
 */
int iam_it_stop(int fd, struct iam_uapi_info *ua, int key_need_convert,
		char *keybuf, int rec_need_convert, char *recbuf);

/*
 * Change iam file mode.
 */
int iam_polymorph(char *filename, unsigned long mode);

#endif
