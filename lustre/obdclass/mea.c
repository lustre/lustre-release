/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifdef __KERNEL__
#include <linux/kmod.h>   /* for request_module() */
#include <linux/module.h>
#include <obd_class.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#else 
#include <liblustre.h>
#include <obd_class.h>
#include <obd.h>
#endif
#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>

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

/* This hash calculate method must be same as the lvar hash method */
static int mea_hash_segment(int count, char *name, int namelen)
{
        __u32 result = 0;
        __u32 hash_segment = MAX_HASH_SIZE / count;
        
        strncpy((void *)&result, name, min(namelen, (int)sizeof result));

        result = (result << 1) & 0x7fffffff;

        return result / hash_segment;
}

int raw_name2idx(int hashtype, int count, const char *name, int namelen)
{
        unsigned int c = 0;

        LASSERT(namelen > 0);
        if (count <= 1)
                return 0;

        switch (hashtype) {
                case MEA_MAGIC_LAST_CHAR:
                        c = mea_last_char_hash(count, (char *) name, namelen);
                        break;
                case MEA_MAGIC_ALL_CHARS:
                        c = mea_all_chars_hash(count, (char *) name, namelen);
                        break;
                case MEA_MAGIC_HASH_SEGMENT:
                        c = mea_hash_segment(count, (char *) name, namelen);
                        break;
                default:
                        CERROR("unknown hash type 0x%x\n", hashtype);
        }
	
        return c;
}

int mea_name2idx(struct lmv_stripe_md *mea, char *name, int namelen)
{
        unsigned int c;
        
        LASSERT(mea && mea->mea_count);

	c = raw_name2idx(mea->mea_magic, mea->mea_count, name, namelen);

        LASSERT(c < mea->mea_count);
        return c;
}

