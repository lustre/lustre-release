/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_STRINGHASH_LUSTRE_H
#define __LINUX_STRINGHASH_LUSTRE_H

#include <linux/dcache.h>
#include <linux/types.h>

#ifndef HAVE_STRINGHASH

u64 hashlen_string(const void *salt, const char *name);

#ifndef hashlen_hash
#define hashlen_hash(hashlen) ((u32)(hashlen))
#endif

#ifndef hashlen_create
#define hashlen_create(hash, len) ((u64)(len)<<32 | (u32)(hash))
#endif

#else
#include <linux/stringhash.h>
#endif /* !HAVE_STRINGHASH */

#endif /* !__LINUX_STRINGHASH_LUSTRE_H */
