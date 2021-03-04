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
 * lustre/utils/create_iam.c
 *
 * User-level tool for creation of iam files.
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <endian.h>
#include <errno.h>

#include <sys/types.h>

void usage(void)
{
	printf(
	       "usage: create_iam [-h] [-k <keysize>] [-r recsize] [-b <blocksize] [-p <ptrsize>] [-v]\n");
}

enum {
	IAM_LFIX_ROOT_MAGIC = 0xbedabb1edULL,
	IAM_LVAR_ROOT_MAGIC = 0xb01dface
};

struct iam_lfix_root {
	u_int64_t  ilr_magic;
	u_int16_t  ilr_keysize;
	u_int16_t  ilr_recsize;
	u_int16_t  ilr_ptrsize;
	u_int16_t  ilr_indirect_levels;
};

enum {
	IAM_LEAF_HEADER_MAGIC = 0x1976,
	IAM_LVAR_LEAF_MAGIC   = 0x1973
};

struct iam_leaf_head {
	u_int16_t ill_magic;
	u_int16_t ill_count;
};

struct dx_countlimit {
	u_int16_t limit;
	u_int16_t count;
};

typedef __u32 lvar_hash_t;

struct lvar_leaf_header {
	u_int16_t vlh_magic; /* magic number IAM_LVAR_LEAF_MAGIC */
	u_int16_t vlh_used;  /* used bytes, including header */
};

struct lvar_root {
	u_int32_t vr_magic;
	u_int16_t vr_recsize;
	u_int16_t vr_ptrsize;
	u_int8_t  vr_indirect_levels;
	u_int8_t  vr_padding0;
	u_int16_t vr_padding1;
};

struct lvar_leaf_entry {
	u_int32_t vle_hash;
	u_int16_t vle_keysize;
	u_int8_t  vle_key[0];
};

enum {
	LVAR_PAD   = 4,
	LVAR_ROUND = LVAR_PAD - 1
};

/**
 * Stores \a val at \a dst, where the latter is possibly unaligned. Uses
 * memcpy(). This macro is needed to avoid dependency of user level tools on
 * the kernel headers.
 */
#define STORE_UNALIGNED(val, dst)			\
({							\
	typeof(val) __val = (val);			\
							\
	BUILD_BUG_ON(sizeof(val) != sizeof(*(dst)));	\
	memcpy(dst, &__val, sizeof(*(dst)));		\
})

static void lfix_root(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct iam_lfix_root *root;
	struct dx_countlimit *limit;
	void *entry;

	root = buf;
	*root = (typeof(*root)) {
		.ilr_magic           = cpu_to_le64(IAM_LFIX_ROOT_MAGIC),
		.ilr_keysize         = cpu_to_le16(keysize),
		.ilr_recsize         = cpu_to_le16(recsize),
		.ilr_ptrsize         = cpu_to_le16(ptrsize),
		.ilr_indirect_levels = 0
	};

	limit = (void *)(root + 1);
	*limit = (typeof(*limit)){
		/*
		 * limit itself + one pointer to the leaf.
		 */
		.count = cpu_to_le16(2),
		.limit = (blocksize - sizeof(*root)) / (keysize + ptrsize)
	};

	entry = root + 1;
	/*
	 * Skip over @limit.
	 */
	entry += keysize + ptrsize;

	/*
	 * Entry format is <key> followed by <ptr>. In the minimal tree
	 * consisting of a root and single node, <key> is a minimal possible
	 * key.
	 *
	 * XXX: this key is hard-coded to be a sequence of 0's.
	 */
	entry += keysize;
	/* now @entry points to <ptr> */
	if (ptrsize == 4)
		STORE_UNALIGNED(cpu_to_le32(1), (u_int32_t *)entry);
	else
		STORE_UNALIGNED(cpu_to_le64(1), (u_int64_t *)entry);
}

static void lfix_leaf(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct iam_leaf_head *head;

	/* form leaf */
	head = buf;
	*head = (struct iam_leaf_head) {
		.ill_magic = cpu_to_le16(IAM_LEAF_HEADER_MAGIC),
		/*
		 * Leaf contains an entry with the smallest possible key
		 * (created by zeroing).
		 */
		.ill_count = cpu_to_le16(1),
	};
}

static void lvar_root(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct lvar_root *root;
	struct dx_countlimit *limit;
	void *entry;
	int isize;

	isize = sizeof(lvar_hash_t) + ptrsize;
	root = buf;
	*root = (typeof(*root)) {
		.vr_magic            = cpu_to_le32(IAM_LVAR_ROOT_MAGIC),
		.vr_recsize          = cpu_to_le16(recsize),
		.vr_ptrsize          = cpu_to_le16(ptrsize),
		.vr_indirect_levels  = 0
	};

	limit = (void *)(root + 1);
	*limit = (typeof(*limit)){
		/*
		 * limit itself + one pointer to the leaf.
		 */
		.count = cpu_to_le16(2),
		.limit = (blocksize - sizeof(*root)) / isize
	};

	entry = root + 1;
	/*
	 * Skip over @limit.
	 */
	entry += isize;

	/*
	 * Entry format is <key> followed by <ptr>. In the minimal tree
	 * consisting of a root and single node, <key> is a minimal possible
	 * key.
	 *
	 * XXX: this key is hard-coded to be a sequence of 0's.
	 */
	entry += sizeof(lvar_hash_t);
	/* now @entry points to <ptr> */
	if (ptrsize == 4)
		STORE_UNALIGNED(cpu_to_le32(1), (u_int32_t *)entry);
	else
		STORE_UNALIGNED(cpu_to_le64(1), (u_int64_t *)entry);
}

static int lvar_esize(int namelen, int recsize)
{
	return (offsetof(struct lvar_leaf_entry, vle_key) +
		namelen + recsize + LVAR_ROUND) & ~LVAR_ROUND;
}

static void lvar_leaf(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct lvar_leaf_header *head;

	/* form leaf */
	head = buf;
	*head = (typeof(*head)) {
		.vlh_magic = cpu_to_le16(IAM_LVAR_LEAF_MAGIC),
		.vlh_used  = cpu_to_le16(sizeof(*head) + lvar_esize(0, recsize))
	};
}

enum iam_fmt_t {
	FMT_LFIX,
	FMT_LVAR
};

int main(int argc, char **argv)
{
	int rc;
	int opt;
	int blocksize = 4096;
	int keysize   = 8;
	int recsize   = 8;
	int ptrsize   = 4;
	int verbose   = 0;
	void *buf;
	char *fmtstr = "lfix";
	enum iam_fmt_t fmt;

	do {
		opt = getopt(argc, argv, "hb:k:r:p:vf:");
		switch (opt) {
		case 'v':
			verbose++;
		case -1:
			break;
		case 'b':
			blocksize = atoi(optarg);
			break;
		case 'k':
			keysize = atoi(optarg);
			break;
		case 'r':
			recsize = atoi(optarg);
			break;
		case 'p':
			ptrsize = atoi(optarg);
			break;
		case 'f':
			fmtstr = optarg;
			break;
		case '?':
		default:
			fprintf(stderr, "Unable to parse options.");
		case 'h':
			usage();
			return 0;
		}
	} while (opt != -1);

	if (ptrsize != 4 && ptrsize != 8) {
		fprintf(stderr,
			"Invalid ptrsize (%i). Only 4 and 8 are supported\n",
			ptrsize);
		return 1;
	}

	if (blocksize <= 100 || keysize < 1 || recsize < 0) {
		fprintf(stderr, "Too small record, key or block block\n");
		return 1;
	}

	if (keysize + recsize + sizeof(struct iam_leaf_head) > blocksize / 3) {
		fprintf(stderr, "Too large (record, key) or too small block\n");
		return 1;
	}

	if (!strcmp(fmtstr, "lfix")) {
		fmt = FMT_LFIX;
	} else if (!strcmp(fmtstr, "lvar")) {
		fmt = FMT_LVAR;
	} else {
		fprintf(stderr, "Wrong format `%s'\n", fmtstr);
		return 1;
	}

	if (verbose > 0) {
		fprintf(stderr,
			"fmt: %s, key: %i, rec: %i, ptr: %i, block: %i\n",
			fmtstr, keysize, recsize, ptrsize, blocksize);
	}
	buf = malloc(blocksize);
	if (!buf) {
		fprintf(stderr, "Unable to allocate %i bytes\n", blocksize);
		return 1;
	}

	memset(buf, 0, blocksize);

	if (fmt == FMT_LFIX)
		lfix_root(buf, blocksize, keysize, ptrsize, recsize);
	else
		lvar_root(buf, blocksize, keysize, ptrsize, recsize);

	rc = write(1, buf, blocksize);
	if (rc != blocksize) {
		fprintf(stderr, "Unable to write root node: %m (%i)\n", rc);
		free(buf);
		return 1;
	}

	/* form leaf */
	memset(buf, 0, blocksize);

	if (fmt == FMT_LFIX)
		lfix_leaf(buf, blocksize, keysize, ptrsize, recsize);
	else
		lvar_leaf(buf, blocksize, keysize, ptrsize, recsize);

	rc = write(1, buf, blocksize);
	free(buf);
	if (rc != blocksize) {
		fprintf(stderr, "Unable to write leaf node: %m (%i)\n", rc);
		return 1;
	}
	if (verbose > 0)
		fprintf(stderr,
			"Don't forget to umount/mount before accessing iam from the kernel!\n");
	return 0;
}
