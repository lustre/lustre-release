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
