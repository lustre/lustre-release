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
 * Copyright (c) 2014, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/libiam.c
 *
 * iam user level library
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Fan Yong <fanyong@clusterfs.com>
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <endian.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <libcfs/util/string.h>
#include <lustre/libiam.h>

typedef __u32 lvar_hash_t;

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
#define STORE_UNALIGNED(val, dst)               \
({                                              \
	typeof(*(dst)) __val = (val);           \
						\
	memcpy(dst, &__val, sizeof *(dst));     \
})

static int root_limit(int rootgap, int blocksize, int size)
{
	int limit;
	int nlimit;

	limit = (blocksize - rootgap) / size;
	nlimit = blocksize / size;
	if (limit == nlimit)
		limit--;
	return limit;
}

static int lfix_root_limit(int blocksize, int size)
{
	return root_limit(sizeof(struct iam_lfix_root), blocksize, size);
}

static void lfix_root(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct iam_lfix_root *root;
	struct dx_countlimit *limit;
	void *entry;

	root = buf;
	*root = (typeof(*root)) {
		.ilr_magic           = htole64(IAM_LFIX_ROOT_MAGIC),
		.ilr_keysize         = htole16(keysize),
		.ilr_recsize         = htole16(recsize),
		.ilr_ptrsize         = htole16(ptrsize),
		.ilr_indirect_levels = 0
	};

	limit = (void *)(root + 1);
	*limit = (typeof(*limit)){
		/*
		 * limit itself + one pointer to the leaf.
		 */
		.count = htole16(2),
		.limit = lfix_root_limit(blocksize, keysize + ptrsize)
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
		STORE_UNALIGNED(htole32(1), (u_int32_t *)entry);
	else
		STORE_UNALIGNED(htole64(1), (u_int64_t *)entry);
}

static void lfix_leaf(void *buf,
		      int blocksize, int keysize, int ptrsize, int recsize)
{
	struct iam_leaf_head *head;

	/* form leaf */
	head = buf;
	*head = (typeof(*head)) {
		.ill_magic = htole16(IAM_LEAF_HEADER_MAGIC),
		/*
		 * Leaf contains an entry with the smallest possible key
		 * (created by zeroing).
		 */
		.ill_count = htole16(1),
	};
}

static int lvar_root_limit(int blocksize, int size)
{
	return root_limit(sizeof(struct lvar_root), blocksize, size);
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
		.vr_magic            = htole32(IAM_LVAR_ROOT_MAGIC),
		.vr_recsize          = htole16(recsize),
		.vr_ptrsize          = htole16(ptrsize),
		.vr_indirect_levels  = 0
	};

	limit = (void *)(root + 1);
	*limit = (typeof(*limit)) {
		/*
		 * limit itself + one pointer to the leaf.
		 */
		.count = htole16(2),
		.limit = lvar_root_limit(blocksize, keysize + ptrsize)
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
		STORE_UNALIGNED(htole32(1), (u_int32_t *)entry);
	else
		STORE_UNALIGNED(htole64(1), (u_int64_t *)entry);
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
	char *rec;

	/* form leaf */
	head = buf;
	*head = (typeof(*head)) {
		.vlh_magic = htole16(IAM_LVAR_LEAF_MAGIC),
		.vlh_used  = htole16(sizeof(*head) + lvar_esize(0, recsize))
	};
	rec = (void *)(head + 1);
	rec[offsetof(struct lvar_leaf_entry, vle_key)] = recsize;
}

struct iam_uapi_op {
	void *iul_key;
	void *iul_rec;
};

struct iam_uapi_it {
	struct iam_uapi_op iui_op;
	__u16 iui_state;
};

enum iam_ioctl_cmd {
	IAM_IOC_INIT      = _IOW('i', 1, struct iam_uapi_info),
	IAM_IOC_GETINFO   = _IOR('i', 2, struct iam_uapi_info),
	IAM_IOC_INSERT    = _IOR('i', 3, struct iam_uapi_op),
	IAM_IOC_LOOKUP    = _IOWR('i', 4, struct iam_uapi_op),
	IAM_IOC_DELETE    = _IOR('i', 5, struct iam_uapi_op),
	IAM_IOC_IT_START  = _IOR('i', 6, struct iam_uapi_it),
	IAM_IOC_IT_NEXT   = _IOW('i', 7, struct iam_uapi_it),
	IAM_IOC_IT_STOP   = _IOR('i', 8, struct iam_uapi_it),
	IAM_IOC_POLYMORPH = _IOR('i', 9, unsigned long)
};

static unsigned char hex2dec(unsigned char hex)
{
	if (('0' <= hex) && (hex <= '9'))
		return hex - '0';
	else if (('a' <= hex) && (hex <= 'f'))
		return hex - 'a' + 10;
	else if (('A' <= hex) && (hex <= 'F'))
		return hex - 'A' + 10;
	exit(1);
}

static unsigned char *packdigit(unsigned char *number)
{
	unsigned char *area;
	unsigned char *scan;

	area = calloc(strlen((char *)number) / 2 + 2, sizeof(char));
	if (area) {
		for (scan = area; *number; number += 2, scan++)
			*scan = (hex2dec(number[0]) << 4) | hex2dec(number[1]);
	}
	return area;
}

static char *iam_convert(int size, int need_convert, char *source)
{
	char *ptr;
	unsigned char *opt;

	if (!source)
		return NULL;

	if (need_convert) {
		ptr = calloc(size + 1, sizeof(char));
		if (!ptr)
			return NULL;

		opt = packdigit((unsigned char *)source);
		if (!opt) {
			free(ptr);
			return NULL;
		}
		memcpy(ptr, opt, size + 1);
		free(opt);
	} else {
		ptr = strdup(source);
	}

	return ptr;
}

static int iam_doop(int fd, struct iam_uapi_info *ua, int cmd,
		    int key_need_convert, char *key_buf,
		    int *keysize, char *save_key,
		    int rec_need_convert, char *rec_buf,
		    int *recsize, char *save_rec)
{
	int ret;
	char *key;
	char *rec;
	struct iam_uapi_op op;

	key = iam_convert(ua->iui_keysize, key_need_convert, key_buf);
	if (!key)
		return -1;

	rec = iam_convert(ua->iui_recsize, rec_need_convert, rec_buf);
	if (!rec) {
		free(key);
		return -1;
	}

	op.iul_key = key;
	op.iul_rec = rec;
	ret = ioctl(fd, cmd, &op);
	if (ret == 0) {
		if ((keysize) && (*keysize > 0) && (save_key)) {
			if (*keysize > ua->iui_keysize)
				*keysize = ua->iui_keysize;
			memcpy(save_key, key, *keysize);
		}
		if ((recsize) && (*recsize > 0) && (save_rec)) {
			if (*recsize > ua->iui_recsize)
				*recsize = ua->iui_recsize;
			memcpy(save_rec, rec, *recsize);
		}
	}
	free(key);
	free(rec);
	return ret;
}

/*
 * Creat an iam file, but do NOT open it.
 * Return 0 if success, else -1.
 */
int iam_creat(char *filename, enum iam_fmt_t fmt,
	      int blocksize, int keysize, int recsize, int ptrsize)
{
	int fd;
	char *buf;

	if (!filename) {
		errno = EINVAL;
		return -1;
	}

	if ((fmt != FMT_LFIX) && (fmt != FMT_LVAR)) {
		errno = EOPNOTSUPP;
		return -1;
	}

	if (blocksize <= 100) {
		errno = EINVAL;
		return -1;
	}

	if (keysize < 1) {
		errno = EINVAL;
		return -1;
	}

	if (recsize < 0) {
		errno = EINVAL;
		return -1;
	}

	if (ptrsize != 4 && ptrsize != 8) {
		errno = EINVAL;
		return -1;
	}

	if (keysize + recsize + sizeof(struct iam_leaf_head) > blocksize / 3) {
		errno = EINVAL;
		return -1;
	}

	fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0600);
	if (fd < 0)
		return -1;

	buf = malloc(blocksize);
	if (!buf) {
		close(fd);
		return -1;
	}

	memset(buf, 0, blocksize);
	if (fmt == FMT_LFIX)
		lfix_root(buf, blocksize, keysize, ptrsize, recsize);
	else
		lvar_root(buf, blocksize, keysize, ptrsize, recsize);

	if (write(fd, buf, blocksize) != blocksize) {
		close(fd);
		free(buf);
		return -1;
	}

	memset(buf, 0, blocksize);
	if (fmt == FMT_LFIX)
		lfix_leaf(buf, blocksize, keysize, ptrsize, recsize);
	else
		lvar_leaf(buf, blocksize, keysize, ptrsize, recsize);

	if (write(fd, buf, blocksize) != blocksize) {
		close(fd);
		free(buf);
		return -1;
	}

	close(fd);
	free(buf);
	return 0;
}

/*
 * Open an iam file, but do NOT creat it if the file doesn't exist.
 * Please use iam_creat for creating the file before use iam_open.
 * Return file id (fd) if success, else -1.
 */
int iam_open(char *filename, struct iam_uapi_info *ua)
{
	int fd;

	if (!filename) {
		errno = EINVAL;
		return -1;
	}

	if (!ua) {
		errno = EINVAL;
		return -1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;

	if (ioctl(fd, IAM_IOC_INIT, ua) != 0) {
		close(fd);
		return -1;
	}

	if (ioctl(fd, IAM_IOC_GETINFO, ua) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Close file opened by iam_open.
 */
int iam_close(int fd)
{
	return close(fd);
}

/*
 * Please use iam_open before use this function.
 */
int iam_insert(int fd, struct iam_uapi_info *ua,
	       int key_need_convert, char *key_buf,
	       int rec_need_convert, char *rec_buf)
{
	return iam_doop(fd, ua, IAM_IOC_INSERT,
			key_need_convert, key_buf, NULL, NULL,
			rec_need_convert, rec_buf, NULL, NULL);
}

/*
 * Please use iam_open before use this function.
 */
int iam_lookup(int fd, struct iam_uapi_info *ua,
	       int key_need_convert, char *key_buf,
	       int *keysize, char *save_key,
	       int rec_need_convert, char *rec_buf,
	       int *recsize, char *save_rec)
{
	return iam_doop(fd, ua, IAM_IOC_LOOKUP,
			key_need_convert, key_buf, keysize, save_key,
			rec_need_convert, rec_buf, recsize, save_rec);
}

/*
 * Please use iam_open before use this function.
 */
int iam_delete(int fd, struct iam_uapi_info *ua,
	       int key_need_convert, char *key_buf,
	       int rec_need_convert, char *rec_buf)
{
	return iam_doop(fd, ua, IAM_IOC_DELETE,
			key_need_convert, key_buf, NULL, NULL,
			rec_need_convert, rec_buf, NULL, NULL);
}

/*
 * Please use iam_open before use this function.
 */
int iam_it_start(int fd, struct iam_uapi_info *ua,
		 int key_need_convert, char *key_buf,
		 int *keysize, char *save_key,
		 int rec_need_convert, char *rec_buf,
		 int *recsize, char *save_rec)
{
	return iam_doop(fd, ua, IAM_IOC_IT_START,
			key_need_convert, key_buf, keysize, save_key,
			rec_need_convert, rec_buf, recsize, save_rec);
}

/*
 * Please use iam_open before use this function.
 */
int iam_it_next(int fd, struct iam_uapi_info *ua,
		int key_need_convert, char *key_buf,
		int *keysize, char *save_key,
		int rec_need_convert, char *rec_buf,
		int *recsize, char *save_rec)
{
	return iam_doop(fd, ua, IAM_IOC_IT_NEXT,
			key_need_convert, key_buf, keysize, save_key,
			rec_need_convert, rec_buf, recsize, save_rec);
}

/*
 * Please use iam_open before use this function.
 */
int iam_it_stop(int fd, struct iam_uapi_info *ua,
		int key_need_convert, char *key_buf,
		int rec_need_convert, char *rec_buf)
{
	return iam_doop(fd, ua, IAM_IOC_IT_STOP,
			key_need_convert, key_buf, NULL, NULL,
			rec_need_convert, rec_buf, NULL, NULL);
}

/*
 * Change iam file mode.
 */
int iam_polymorph(char *filename, unsigned long mode)
{
	int fd;
	int ret;

	if (!filename) {
		errno = EINVAL;
		return -1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = ioctl(fd, IAM_IOC_POLYMORPH, mode);
	close(fd);
	return ret;
}
