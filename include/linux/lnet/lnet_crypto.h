/* SPDX-License-Identifier: GPL-2.0 */

/* Copyright 2012 Xyratex Technology Limited
 *
 * Copyright (c) 2014, Intel Corporation.
 */

#ifndef _LNET_CRYPTO_H
#define _LNET_CRYPTO_H

#include <asm/page.h>
#include <uapi/linux/lnet/lnet-crypto.h>

/* cfs crypto hash descriptor */
struct ahash_request *
	cfs_crypto_hash_init(enum cfs_crypto_hash_alg hash_alg,
			     unsigned char *key, unsigned int key_len);
int cfs_crypto_hash_update_page(struct ahash_request *req,
				struct page *page, unsigned int offset,
				unsigned int len);
int cfs_crypto_hash_update(struct ahash_request *req, const void *buf,
			   unsigned int buf_len);
int cfs_crypto_hash_final(struct ahash_request *req,
			  unsigned char *hash, unsigned int *hash_len);
int cfs_crypto_register(void);
void cfs_crypto_unregister(void);
int cfs_crypto_hash_speed(enum cfs_crypto_hash_alg hash_alg);

#endif
