// SPDX-License-Identifier: GPL-2.0

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
