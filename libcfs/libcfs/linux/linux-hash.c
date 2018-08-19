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

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/module.h>
#ifdef HAVE_STRINGHASH
#include <linux/stringhash.h>
#else
#include <linux/dcache.h>
#endif
#include <linux/hash.h>

#include <libcfs/linux/linux-hash.h>

/* Return the "hash_len" (hash and length) of a null-terminated string */
/* The kernel equivalent is in fs/namei.c but for some strange reason
 * RHEL7.5 stuck it in dax/super.c instead. This placement never existed
 * upstream so to make life easier we just have the equavilent
 */
u64 cfs_hashlen_string(const void *salt, const char *name)
{
#ifdef HAVE_FULL_NAME_HASH_3ARGS
	unsigned long hash = init_name_hash(salt);
#else
	unsigned long hash = init_name_hash();
#endif
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	while (c) {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	}
	return hashlen_create(end_name_hash(hash), len);
}
EXPORT_SYMBOL(cfs_hashlen_string);
