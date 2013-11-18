/* GPL HEADER START
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
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * Please  visit http://www.xyratex.com/contact if you need additional
 * information or have any questions.
 *
 * GPL HEADER END
 */

/*
 * Copyright 2012 Xyratex Technology Limited
 */

/*
 * Libcfs crypto hash interfaces for user mode.
 */

#include <libcfs/libcfs.h>
#include <libcfs/libcfs_crypto.h>
#include <libcfs/posix/posix-crypto.h>
#include <libcfs/user-crypto.h>

/**
 *  Array of hash algorithm speed in MByte per second
 */
static int cfs_crypto_hash_speeds[CFS_HASH_ALG_MAX];

struct __hash_alg {
	/**
	 * Initialization of algorithm
	 */
	int (*init)(void);
	/**
	 * Start function for the hash instance
	 */
	int (*start)(void *ctx, unsigned char *p, unsigned int len);
	/**
	 * Partial update checksum
	 */
	int (*update)(void *ctx, const unsigned char *p, unsigned int len);
	/**
	 * Final function for the instance destroy context and copy digest
	 */
	int (*final)(void *ctx, unsigned char *p, unsigned int len);
	/**
	 * Destroy algorithm
	 */
	void (*fini)(void);
	unsigned int    ha_ctx_size;    /**< size of context */
	unsigned int    ha_priority;    /**< implementation priority
					     defined by developer
					     to get one from equal algorithm */
	unsigned char   ha_id;	  /**< algorithm identifier */
};

struct hash_desc {
	const struct __hash_alg *hd_hash;
	unsigned char   hd_ctx[0];
};

static int crc32_update_wrapper(void *ctx, const unsigned char *p,
				unsigned int len)
{
	unsigned int crc = *(unsigned int *)ctx;

	crc = crc32_le(crc, p, len);

	*(unsigned int *)ctx = crc;
	return 0;
}

static int adler_wrapper(void *ctx, const unsigned char *p,
				unsigned int len)
{
	unsigned int cksum = *(unsigned int *)ctx;

	cksum = zlib_adler32(cksum, p, len);

	*(unsigned int *)ctx = cksum;
	return 0;
}

#if defined(HAVE_PCLMULQDQ) && defined(NEED_CRC32_ACCEL)
static int crc32_pclmul_wrapper(void *ctx, const unsigned char *p,
				unsigned int len)
{
	unsigned int cksum = *(unsigned int *)ctx;

	cksum = crc32_pclmul_le(cksum, p, len);

	*(unsigned int *)ctx = cksum;
	return 0;
}
#endif

static int start_generic(void *ctx, unsigned char *key,
			 unsigned int key_len)
{
	const struct cfs_crypto_hash_type       *type;
	struct hash_desc	*hd = container_of(ctx, struct hash_desc,
						   hd_ctx);
	type = cfs_crypto_hash_type(hd->hd_hash->ha_id);
	LASSERT(type != NULL);

	/* copy key to context */
	if (key && key_len == hd->hd_hash->ha_ctx_size) {
		memcpy(ctx, key, key_len);
	} else if (type->cht_key != 0) {
		memcpy(ctx, &type->cht_key, type->cht_size);
	} else {
		CWARN("Invalid key or key_len, zero context\n");
		memset(ctx, 0, hd->hd_hash->ha_ctx_size);
	}
	return 0;
}

static int final_generic(void *ctx, unsigned char *hash,
			 unsigned int hash_len)
{
	const struct cfs_crypto_hash_type       *type;
	struct hash_desc	*hd = container_of(ctx, struct hash_desc,
						   hd_ctx);
	type = cfs_crypto_hash_type(hd->hd_hash->ha_id);
	LASSERT(type != NULL);
	 /* copy context to out hash */
	LASSERT(hd->hd_hash->ha_ctx_size == type->cht_size);
	memcpy(hash, ctx, hd->hd_hash->ha_ctx_size);


	return 0;
}

static struct __hash_alg crypto_hash[] = {
					  {.ha_id = CFS_HASH_ALG_CRC32,
					   .ha_ctx_size = sizeof(unsigned int),
					   .ha_priority = 10,
					   .init = crc32init_le,
					   .update = crc32_update_wrapper,
					   .start = start_generic,
					   .final = final_generic,
					   .fini = NULL},
					  {.ha_id = CFS_HASH_ALG_ADLER32,
					   .ha_ctx_size = sizeof(unsigned int),
					   .ha_priority = 10,
					   .init = NULL,
					   .update = adler_wrapper,
					   .start = start_generic,
					   .final = final_generic,
					   .fini = NULL},
#if defined(HAVE_PCLMULQDQ) && defined(NEED_CRC32_ACCEL)
					  {.ha_id = CFS_HASH_ALG_CRC32,
					   .ha_ctx_size = sizeof(unsigned int),
					   .ha_priority = 100,
					   .init = crc32_pclmul_init,
					   .update = crc32_pclmul_wrapper,
					   .start = start_generic,
					   .final = final_generic,
					   .fini = NULL},
#endif
					};

/**
 * Go through hashes to find the hash with max priority for the hash_alg
 * algorithm. This is done for different implementation of the same
 * algorithm. Priority is staticaly defined by developer, and can be zeroed
 * if initialization of algo is unsuccessful.
 */
static const struct __hash_alg
*cfs_crypto_hash_best_alg(enum cfs_crypto_hash_alg hash_alg)
{
	int max_priority = 0;
	const struct __hash_alg *alg = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(crypto_hash); i++) {
		if (hash_alg == crypto_hash[i].ha_id &&
		    max_priority < crypto_hash[i].ha_priority) {
			max_priority = crypto_hash[i].ha_priority;
			alg = &crypto_hash[i];
		}
	}

	return alg;
}

struct cfs_crypto_hash_desc
*cfs_crypto_hash_init(enum cfs_crypto_hash_alg hash_alg,
		      unsigned char *key, unsigned int key_len)
{
	struct hash_desc			*hdesc = NULL;
	const struct cfs_crypto_hash_type	*type;
	const struct __hash_alg			*ha = NULL;
	int					err;

	type = cfs_crypto_hash_type(hash_alg);
	if (type == NULL) {
		CWARN("Unsupported hash algorithm id = %d, max id is %d\n",
		      hash_alg, CFS_HASH_ALG_MAX);
		return ERR_PTR(-EINVAL);
	}

	ha = cfs_crypto_hash_best_alg(hash_alg);
	if (ha == NULL) {
		CERROR("Failed to get hash algorithm\n");
		return ERR_PTR(-ENODEV);
	}

	hdesc = kmalloc(sizeof(*hdesc) + ha->ha_ctx_size, 0);
	if (hdesc == NULL)
		return ERR_PTR(-ENOMEM);

	hdesc->hd_hash = ha;

	if (ha->start != NULL) {
		err = ha->start(hdesc->hd_ctx, key, key_len);
		if (err == 0) {
			return (struct cfs_crypto_hash_desc *) hdesc;
		} else {
			kfree(hdesc);
			return ERR_PTR(err);
		}
	}

	return (struct cfs_crypto_hash_desc *) hdesc;
}

int cfs_crypto_hash_update(struct cfs_crypto_hash_desc *desc, const void *buf,
			   unsigned int buf_len)
{
	struct hash_desc *d = (struct hash_desc *)desc;
	return d->hd_hash->update(d->hd_ctx, buf, buf_len);
}

int cfs_crypto_hash_update_page(struct cfs_crypto_hash_desc *desc,
				struct page *page, unsigned int offset,
				unsigned int len)
{
	const void *p = page->addr + offset;

	return cfs_crypto_hash_update(desc, p, len);
}

/**
 *      To get final hash and destroy cfs_crypto_hash_desc, caller
 *      should use valid hash buffer with enougth len for hash.
 *      If hash_len pointer is NULL - destroy descriptor.
 */
int cfs_crypto_hash_final(struct cfs_crypto_hash_desc *desc,
			  unsigned char *hash, unsigned int *hash_len)
{
	const struct cfs_crypto_hash_type *type;
	struct hash_desc	*d = (struct hash_desc *)desc;
	int			size;
	int			err;

	LASSERT(d != NULL);
	type = cfs_crypto_hash_type(d->hd_hash->ha_id);
	LASSERT(type != NULL);
	size = type->cht_size;

	if (hash_len == NULL) {
		err = 0;
		goto free;
	}
	if (hash == NULL || *hash_len < size) {
		err = -ENOMEM;
		goto free;
	}

	LASSERT(d->hd_hash->final != NULL);
	err = d->hd_hash->final(d->hd_ctx, hash, *hash_len);
free:
	kfree(d);

	return err;
}

int cfs_crypto_hash_digest(enum cfs_crypto_hash_alg hash_alg,
			   const void *buf, unsigned int buf_len,
			   unsigned char *key, unsigned int key_len,
			   unsigned char *hash, unsigned int *hash_len)
{
	struct cfs_crypto_hash_desc      *desc;
	int			     err, err2;

	desc = cfs_crypto_hash_init(hash_alg, key, key_len);

	if (IS_ERR(desc))
		return PTR_ERR(desc);

	err = cfs_crypto_hash_update(desc, buf, buf_len);
	if (err != 0)
		hash_len = NULL;

	err2 = cfs_crypto_hash_final(desc, hash, hash_len);
	if (err2 != 0 && err == 0)
		err = err2;

	return err;
}


static void cfs_crypto_start_timer(struct timeval *start)
{
	gettimeofday(start, NULL);
	return;
}

/** return usec */
static long cfs_crypto_get_sec(struct timeval *start)
{
	struct timeval  end;

	gettimeofday(&end, NULL);

	return cfs_timeval_sub(&end, start, NULL);
}

static void cfs_crypto_performance_test(enum cfs_crypto_hash_alg hash_alg,
					const unsigned char *buf,
					unsigned int buf_len)
{
	struct timeval		  start;
	int			     bcount, err, msec;
	int			     iteration = 400; /* do test 400 times */
	unsigned char		   hash[64];
	unsigned int		    hash_len = 64;

	cfs_crypto_start_timer(&start);
	for (bcount = 0; bcount < iteration; bcount++) {
		err = cfs_crypto_hash_digest(hash_alg, buf, buf_len, NULL, 0,
					     hash, &hash_len);
		if (err)
			break;

	}

	msec = (int)(cfs_crypto_get_sec(&start) / 1000.0);
	if (err) {
		cfs_crypto_hash_speeds[hash_alg] =  -1;
		CDEBUG(D_INFO, "Crypto hash algorithm err = %d\n", err);
	} else {
		long tmp;
		tmp =  ((bcount * buf_len / msec) * 1000) / (1024 * 1024);
		cfs_crypto_hash_speeds[hash_alg] = (int)tmp;
	}
	CDEBUG(D_CONFIG, "Crypto hash algorithm %s speed = %d MB/s\n",
	       cfs_crypto_hash_name(hash_alg),
	       cfs_crypto_hash_speeds[hash_alg]);
}

int cfs_crypto_hash_speed(enum cfs_crypto_hash_alg hash_alg)
{
	if (hash_alg < CFS_HASH_ALG_MAX)
		return cfs_crypto_hash_speeds[hash_alg];
	else
		return -1;
}

/**
 * Do performance test for all hash algorithms.
 */
static int cfs_crypto_test_hashes(void)
{
	unsigned char	   i;
	unsigned char	   *data;
	unsigned int	    j, data_len = 1024 * 1024;

	data = kmalloc(data_len, 0);
	if (data == NULL) {
		CERROR("Failed to allocate mem\n");
		return -ENOMEM;
	}
	for (j = 0; j < data_len; j++)
		data[j] = j & 0xff;

	for (i = 0; i < CFS_HASH_ALG_MAX; i++)
		cfs_crypto_performance_test(i, data, data_len);

	kfree(data);
	return 0;
}

/**
 *      Register crypto hash algorithms
 */
int cfs_crypto_register(void)
{
	int i, err;
	for (i = 0; i < ARRAY_SIZE(crypto_hash); i++) {
		if (crypto_hash[i].init == NULL)
			continue;
		err = crypto_hash[i].init();
		if (err < 0) {
			crypto_hash[i].ha_priority = 0;
			CWARN("Failed to initialize hash %s, error %d\n",
			      cfs_crypto_hash_name(crypto_hash[i].ha_id), err);
		}
	}

	cfs_crypto_test_hashes();
	return 0;
}

/**
 *      Unregister
 */
void cfs_crypto_unregister(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(crypto_hash); i++) {
		if (crypto_hash[i].fini == NULL)
			continue;
		if (crypto_hash[i].ha_priority > 0)
			crypto_hash[i].fini();
	}
}
