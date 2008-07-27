/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_CLASS
#include <obd_class.h>
#ifdef __KERNEL__
#include <linux/kmod.h>   /* for request_module() */
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#else
#include <liblustre.h>
#include <obd.h>
#endif
#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>

#ifdef __KERNEL__
#include <linux/jbd.h>
#ifdef HAVE_SERVER_SUPPORT
/* LDISKFS_SB() */
#include <linux/ldiskfs_fs.h>
#endif
#endif
static int mea_last_char_hash(int count, char *name, int namelen)
{
        unsigned int c;

        c = name[namelen - 1];
        if (c == 0)
                CWARN("looks like wrong len is passed\n");
        c = c % count;
        return c;
}

static int mea_all_chars_hash(int count, char *name, int namelen)
{
        unsigned int c = 0;

        while (--namelen >= 0)
                c += name[namelen];
        c = c % count;
        return c;
}

#ifdef __KERNEL__
/* This hash calculate method must be same as the lvar hash method */

#define LVAR_HASH_SANDWICH  (0)
#define LVAR_HASH_TEA       (1)
#define LVAR_HASH_R5        (0)
#define LVAR_HASH_PREFIX    (0)

static __u32 hash_build0(const char *name, int namelen)
{
        __u32 result;

        if (namelen == 0)
                return 0;
        if (strncmp(name, ".", 1) == 0 && namelen == 1)
                return 1;
        if (strncmp(name, "..", 2) == 0 && namelen == 2)
                return 2;

        if (LVAR_HASH_PREFIX) {
                result = 0;
                strncpy((void *)&result,
                        name, min(namelen, (int)sizeof result));
        } else {
                struct ldiskfs_dx_hash_info hinfo;

                if (LVAR_HASH_TEA)
                        hinfo.hash_version = LDISKFS_DX_HASH_TEA;
                else
                        hinfo.hash_version = LDISKFS_DX_HASH_R5;
                hinfo.seed = 0;
                ldiskfsfs_dirhash(name, namelen, &hinfo);
                result = hinfo.hash;
                if (LVAR_HASH_SANDWICH) {
                        __u32 result2;

                        hinfo.hash_version = LDISKFS_DX_HASH_TEA;
                        hinfo.seed = 0;
                        ldiskfsfs_dirhash(name, namelen, &hinfo);
                        result2 = hinfo.hash;
                        result = (0xfc000000 & result2) | (0x03ffffff & result);
                }
        }

        return result;
}

enum {
        HASH_GRAY_AREA = 1024
};

static __u32 hash_build(const char *name, int namelen)
{
        __u32 hash;

        hash = (hash_build0(name, namelen) << 1) & MAX_HASH_SIZE_32;
        if (hash > MAX_HASH_SIZE_32 - HASH_GRAY_AREA)
                hash &= HASH_GRAY_AREA - 1;
        return hash;
}

static int mea_hash_segment(int count, const char *name, int namelen)
{
        __u32 hash;

        LASSERT(IS_PO2(MAX_HASH_SIZE_32 + 1));

        hash = hash_build(name, namelen) / (MAX_HASH_SIZE_32 / count);
        LASSERTF(hash < count, "hash %x count %d \n", hash, count);

        return hash;
}
#else
static int mea_hash_segment(int count, char *name, int namelen)
{
        return 0;
}
#endif
int raw_name2idx(int hashtype, int count, const char *name, int namelen)
{
        unsigned int c = 0;

        LASSERT(namelen > 0);
        if (count <= 1)
                return 0;

        switch (hashtype) {
                case MEA_MAGIC_LAST_CHAR:
                        c = mea_last_char_hash(count, (char *)name, namelen);
                        break;
                case MEA_MAGIC_ALL_CHARS:
                        c = mea_all_chars_hash(count, (char *)name, namelen);
                        break;
                case MEA_MAGIC_HASH_SEGMENT:
                        c = mea_hash_segment(count, (char *)name, namelen);
                        break;
                default:
                        CERROR("Unknown hash type 0x%x\n", hashtype);
        }
	
        LASSERT(c < count);
        return c;
}

int mea_name2idx(struct lmv_stripe_md *mea, const char *name, int namelen)
{
        unsigned int c;

        LASSERT(mea && mea->mea_count);

	c = raw_name2idx(mea->mea_magic, mea->mea_count, name, namelen);

        LASSERT(c < mea->mea_count);
        return c;
}
