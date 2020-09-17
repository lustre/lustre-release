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
 *
 * Copyright 2020, DataDirect Networks Storage.
 *
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: John L. Hammond <jhammond@whamcloud.com>
 *
 * lustre/utils/ofd_access_batch.c
 *
 * Access log entry batching for ofd_access_log_reader.
 */
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/lustre/lustre_access_log.h>
#include <linux/lustre/lustre_fid.h>
#include <linux/lustre/lustre_idl.h>
#include <libcfs/util/hash.h>
#include <libcfs/util/list.h>
#include "lstddef.h"
#include "ofd_access_batch.h"

/* XXX Weird param order to be consistent with list_replace_init(). */
static inline void list_replace_init(struct list_head *old_node,
				struct list_head *new_node)
{
	list_add(new_node, old_node);
	list_del_init(old_node);
}

struct fid_hash_node {
	struct list_head fhn_node;
	struct lu_fid fhn_fid;
};

static inline bool fid_eq(const struct lu_fid *f1, const struct lu_fid *f2)
{
	return f1->f_seq == f2->f_seq && f1->f_oid == f2->f_oid &&
	       f1->f_ver == f2->f_ver;
}

static inline __u64 fid_flatten(const struct lu_fid *fid)
{
	__u64 ino;
	__u64 seq;

	if (fid_is_igif(fid)) {
		ino = lu_igif_ino(fid);
		return ino;
	}

	seq = fid_seq(fid);

	ino = (seq << 24) + ((seq >> 24) & 0xffffff0000ULL) + fid_oid(fid);

	return ino != 0 ? ino : fid_oid(fid);
}

/**
 * map fid to 32 bit value for ino on 32bit systems.
 */
static inline __u32 fid_flatten32(const struct lu_fid *fid)
{
	__u32 ino;
	__u64 seq;

	if (fid_is_igif(fid)) {
		ino = lu_igif_ino(fid);
		return ino;
	}

	seq = fid_seq(fid) - FID_SEQ_START;

	/* Map the high bits of the OID into higher bits of the inode number so
	 * that inodes generated at about the same time have a reduced chance
	 * of collisions. This will give a period of 2^12 = 1024 unique clients
	 * (from SEQ) and up to min(LUSTRE_SEQ_MAX_WIDTH, 2^20) = 128k objects
	 * (from OID), or up to 128M inodes without collisions for new files.
	 */
	ino = ((seq & 0x000fffffULL) << 12) + ((seq >> 8) & 0xfffff000) +
	      (seq >> (64 - (40-8)) & 0xffffff00) +
	      (fid_oid(fid) & 0xff000fff) + ((fid_oid(fid) & 0x00fff000) << 8);

	return ino != 0 ? ino : fid_oid(fid);
}

static unsigned long fid_hash(const struct lu_fid *f, unsigned int shift)
{
#if __BITS_PER_LONG == 32
	return hash_long(fid_flatten32(f), shift);
#elif __BITS_PER_LONG == 64
	return hash_long(fid_flatten(f), shift);
#else
# error "Wordsize not 32 or 64"
#endif
}

static void fhn_init(struct fid_hash_node *fhn, const struct lu_fid *fid)
{
	INIT_LIST_HEAD(&fhn->fhn_node);
	fhn->fhn_fid = *fid;
}

static bool fhn_is_hashed(struct fid_hash_node *fhn)
{
	return !list_empty(&fhn->fhn_node);
}

static void fhn_del_init(struct fid_hash_node *fhn)
{
	if (fhn_is_hashed(fhn))
		list_del_init(&fhn->fhn_node);
}

static inline void fhn_replace_init(struct fid_hash_node *old_fhn,
				struct fid_hash_node *new_fhn)
{
	list_add(&new_fhn->fhn_node, &old_fhn->fhn_node);
	list_del_init(&old_fhn->fhn_node);
}

void fid_hash_add(struct list_head *head, unsigned int shift,
		struct fid_hash_node *fhn)
{
	assert(!fhn_is_hashed(fhn));

	list_add(&fhn->fhn_node, &head[fid_hash(&fhn->fhn_fid, shift)]);
}

struct fid_hash_node *
fid_hash_find(struct list_head *head, unsigned int shift, const struct lu_fid *fid)
{
	struct list_head *hash_list;
	struct fid_hash_node *fhn, *next;

	hash_list = &head[fid_hash(fid, shift)];
	list_for_each_entry_safe(fhn, next, hash_list, fhn_node) {
		assert(fhn_is_hashed(fhn));

		if (fid_eq(fid, &fhn->fhn_fid))
			return fhn;
	}

	return NULL;
}

struct fid_hash_node *
fid_hash_insert(struct list_head *head, unsigned int shift, struct fid_hash_node *new_fhn)
{
	struct list_head *list;
	struct fid_hash_node *old_fhn, *next;

	list = &head[fid_hash(&new_fhn->fhn_fid, shift)];
	list_for_each_entry_safe(old_fhn, next, list, fhn_node) {
		assert(fhn_is_hashed(old_fhn));

		if (fid_eq(&old_fhn->fhn_fid, &new_fhn->fhn_fid))
			return old_fhn;
	}

	list_add(&new_fhn->fhn_node, list);

	return new_fhn;
}

int fid_hash_init(struct list_head **phead, unsigned int *pshift, unsigned int shift)
{
	struct list_head *new_head;
	unsigned int i;

	new_head = malloc(sizeof(*new_head) << shift);
	if (new_head == NULL)
		return -1;

	for (i = 0; i < (1 << shift); i++)
		INIT_LIST_HEAD(&new_head[i]);

	*phead = new_head;
	*pshift = shift;

	return 0;
}

int fid_hash_resize(struct list_head **phead, unsigned int *pshift, unsigned int new_shift)
{
	struct list_head *new_head;
	unsigned int i;
	int rc;

	if (*pshift == new_shift)
		return 0;

	rc = fid_hash_init(&new_head, &new_shift, new_shift);
	if (rc < 0)
		return rc;

	for (i = 0; i < (1 << *pshift); i++) {
		struct list_head *list = &(*phead)[i];
		struct fid_hash_node *fhn, *next;

		list_for_each_entry_safe(fhn, next, list, fhn_node) {
			fhn_del_init(fhn);
			fid_hash_add(new_head, new_shift, fhn);
		}
	}

	free(*phead);
	*phead = new_head;
	*pshift = new_shift;

	return 0;
}

enum {
	ALR_READ = 0,
	ALR_WRITE = 1,
};

/* Entry in the batching hash. */
struct alr_entry {
	struct fid_hash_node alre_fid_hash_node;
	time_t alre_time[2]; /* Not strictly needed. */
	__u64 alre_begin[2];
	__u64 alre_end[2];
	__u64 alre_size[2];
	__u64 alre_segment_count[2];
	__u64 alre_count[2];
	char alre_obd_name[];
};

enum {
	ALR_BATCH_HASH_SHIFT_DEFAULT = 10,
	ALR_BATCH_HASH_SHIFT_MAX = 30,
};

struct alr_batch {
	struct list_head *alrb_hash;
	unsigned int alrb_hash_shift;
	unsigned int alrb_count;
};

static void alre_del_init(struct alr_entry *alre)
{
	fhn_del_init(&alre->alre_fid_hash_node);
}

static void alre_update(struct alr_entry *alre, time_t time, __u64 begin,
			__u64 end, __u32 size, __u32 segment_count, __u32 flags)
{
	unsigned int d = (flags & OFD_ACCESS_READ) ? ALR_READ : ALR_WRITE;

	alre->alre_time[d] = max_t(time_t, alre->alre_time[d], time);
	alre->alre_begin[d] = min_t(__u64, alre->alre_begin[d], begin);
	alre->alre_end[d] = max_t(__u64, alre->alre_end[d], end);
	alre->alre_size[d] += size;
	alre->alre_segment_count[d] += segment_count;
	alre->alre_count[d] += 1;
}

int alr_batch_add(struct alr_batch *alrb, const char *obd_name,
		const struct lu_fid *pfid, time_t time, __u64 begin, __u64 end,
		__u32 size, __u32 segment_count, __u32 flags)
{
	struct fid_hash_node fhn, *p;
	struct alr_entry *alre;
	int rc;

	if (alrb == NULL)
		return 0;

	assert(sizeof(time_t) == sizeof(__u64));

	fhn_init(&fhn, pfid);

	/* Find old or insert sentinel (fhn). Replace sentinel if returned. */
	p = fid_hash_insert(alrb->alrb_hash, alrb->alrb_hash_shift, &fhn);
	if (p == &fhn) {
		size_t alre_size = sizeof(*alre) + strlen(obd_name) + 1;

		alre = calloc(1, alre_size);
		if (alre == NULL) {
			rc = -1;
			goto out;
		}

		fhn_init(&alre->alre_fid_hash_node, pfid);
		strcpy(alre->alre_obd_name, obd_name);
		fhn_replace_init(&fhn, &alre->alre_fid_hash_node);
		alrb->alrb_count++;
	} else {
		alre = container_of(p, struct alr_entry, alre_fid_hash_node);
	}

	alre_update(alre, time, begin, end, size, segment_count, flags);
	rc = 0;
out:
	fhn_del_init(&fhn);

	return rc;
}

int sort_compare(const void *a1, const void *a2)
{
	int l = *(const int*)a1;
	int r = *(const int *)a2;
	if (l > r) return -1;
	if (l < r) return  1;
	return 0;
}

static void alre_printf(FILE *f, struct alr_entry *alre, int d)
{
	fprintf(f, "o=%s f="DFID" t=%lld b=%llu e=%llu s=%llu g=%llu n=%llu d=%c\n",
		alre->alre_obd_name,
		PFID(&alre->alre_fid_hash_node.fhn_fid),
		(long long)alre->alre_time[d],
		(unsigned long long)alre->alre_begin[d],
		(unsigned long long)alre->alre_end[d],
		(unsigned long long)alre->alre_size[d],
		(unsigned long long)alre->alre_segment_count[d],
		(unsigned long long)alre->alre_count[d],
		(d == ALR_READ) ? 'r' : 'w');
}

struct alr_thread_arg {
	struct list_head list;
	int fraction;
	FILE *file;
	pthread_mutex_t *file_mutex;
};

void *alr_sort_and_print_thread(void *arg)
{
	struct alr_entry *alre, *next;
	struct alr_thread_arg *aa = arg;
	struct list_head *tmp = &aa->list;
	int *sa = NULL;
	int rc, d, i, nr = 0;
	unsigned long cut;

	list_for_each_entry(alre, tmp, alre_fid_hash_node.fhn_node) {
		if (alre->alre_count[0] > 0)
			nr++;
		if (alre->alre_count[1] > 0)
			nr++;
	}

	if (nr == 0)
		goto out;

	sa = calloc(nr, sizeof(*sa));
	if (!sa) {
		fprintf(stderr, "cannot allocate memory for sorting\n");
		exit(1);
	}

	i = 0;
	list_for_each_entry(alre, tmp, alre_fid_hash_node.fhn_node) {
		if (alre->alre_count[0] > 0)
			sa[i++] = alre->alre_count[0];
		if (alre->alre_count[1] > 0)
			sa[i++] = alre->alre_count[1];
	}

	qsort(sa, nr, sizeof(*sa), sort_compare);
	i = nr * aa->fraction / 100;
	cut = sa[i];
	if (cut < 1)
		cut = 1;
	free(sa);

	/* Prevent jumbled output from multiple concurrent sort and
	 * print threads. */
	rc = pthread_mutex_lock(aa->file_mutex);
	if (rc != 0) {
		fprintf(stderr, "cannot lock batch file: %s\n",
			strerror(rc));
		exit(1);
	}

	/* there might be lots of items at @cut, but we want to limit total
	 * output. so the first loop dumps all items > @cut and the second
	 * loop dumps items=@cut so that total number (@i) is not exceeeded.
	 * XXX: possible optimization - move items=@cut to another list, so
	 * that 2nd pass takes < O(n) */
	list_for_each_entry(alre, tmp, alre_fid_hash_node.fhn_node) {
		for (d = 0; d < 2; d++) {
			if (alre->alre_count[d] <= cut)
				continue;
			alre_printf(aa->file, alre, d);
			i--;
		}
	}

	list_for_each_entry(alre, tmp, alre_fid_hash_node.fhn_node) {
		for (d = 0; d < 2 && i > 0; d++) {
			if (alre->alre_count[d] != cut)
				continue;
			alre_printf(aa->file, alre, d);
			i--;
		}
	}

	rc = pthread_mutex_unlock(aa->file_mutex);
	if (rc != 0) {
		fprintf(stderr, "cannot unlock batch file: %s\n",
			strerror(rc));
		exit(1);
	}

out:
	fflush(aa->file);

	list_for_each_entry_safe(alre, next, tmp, alre_fid_hash_node.fhn_node) {
		alre_del_init(alre);
		free(alre);
	}

	free(aa);

	return NULL;
}

/* Print, clear, and resize the batch. */
int alr_batch_print(struct alr_batch *alrb, FILE *file,
		    pthread_mutex_t *file_mutex, int fraction)
{
	unsigned int new_hash_shift;
	pthread_attr_t attr, *pattr = NULL;
	struct alr_thread_arg *aa = NULL;
	pthread_t pid;
	int i, rc;

	if (alrb == NULL)
		return 0;

	aa = calloc(1, sizeof(*aa));
	if (aa == NULL)
		return -ENOMEM;

	/* move all collected items to the temp list */
	INIT_LIST_HEAD(&aa->list);
	for (i = 0; i < (1 << alrb->alrb_hash_shift); i++) {
		if (list_empty(&alrb->alrb_hash[i]))
			continue;
		list_splice(&alrb->alrb_hash[i], &aa->list);
		INIT_LIST_HEAD(&alrb->alrb_hash[i]);
	}
	aa->file = file;
	aa->file_mutex = file_mutex;
	aa->fraction = fraction;

	rc = pthread_attr_init(&attr);
	if (rc != 0)
		goto out;

	pattr = &attr;

	rc = pthread_attr_setdetachstate(pattr, PTHREAD_CREATE_DETACHED);
	if (rc != 0)
		goto out;

	/* as sorting may take time and we don't want to lose access
	 * records we better do sorting and printing in a different thread */
	rc = pthread_create(&pid, pattr, &alr_sort_and_print_thread, aa);
	if (rc != 0)
		goto out;

	aa = NULL; /* Sort and print thread owns it now. */
out:
	/* Resize hash based on previous count. */
	new_hash_shift = alrb->alrb_hash_shift;

	while (new_hash_shift < ALR_BATCH_HASH_SHIFT_MAX &&
	       (1 << new_hash_shift) < alrb->alrb_count)
		new_hash_shift++;

	fid_hash_resize(&alrb->alrb_hash, &alrb->alrb_hash_shift,
			new_hash_shift);

	alrb->alrb_count = 0;

	if (pattr != NULL)
		pthread_attr_destroy(pattr);

	if (aa != NULL) {
		struct alr_entry *alre, *next;

		list_for_each_entry_safe(alre, next, &aa->list,
					 alre_fid_hash_node.fhn_node) {
			alre_del_init(alre);
			free(alre);
		}
	}

	free(aa);

	if (rc > 0)
		rc = -rc; /* Fixup pthread return conventions. */

	return rc;
}

struct alr_batch *alr_batch_create(unsigned int shift)
{
	struct alr_batch *alrb;
	int rc;

	if (shift == -1U)
		shift = ALR_BATCH_HASH_SHIFT_DEFAULT;

	alrb = calloc(1, sizeof(*alrb));
	if (alrb == NULL)
		return NULL;

	rc = fid_hash_init(&alrb->alrb_hash, &alrb->alrb_hash_shift, shift);
	if (rc < 0) {
		free(alrb);
		return NULL;
	}

	return alrb;
}

void alr_batch_destroy(struct alr_batch *alrb)
{
	unsigned int i;

	if (alrb == NULL)
		return;

	for (i = 0; i < (1 << alrb->alrb_hash_shift); i++) {
		struct list_head *list = &alrb->alrb_hash[i];
		struct alr_entry *alre, *next;

		list_for_each_entry_safe(alre, next, list, alre_fid_hash_node.fhn_node) {
			alre_del_init(alre);
			free(alre);
		}
	}

	free(alrb->alrb_hash);
	free(alrb);
}
